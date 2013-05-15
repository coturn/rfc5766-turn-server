/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "apputils.h"

#include "dtls_listener.h"
#include "ns_ioalib_impl.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* #define REQUEST_CLIENT_CERT */

///////////////////////////////////////////////////

typedef struct {
  ioa_addr local_addr;
  ioa_addr remote_addr;
  ioa_socket_raw fd;
  SSL *ssl;
} ur_conn_info;

///////////////////////////////////////////////////

#define FUNCSTART if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

#define COOKIE_SECRET_LENGTH (32)

struct dtls_listener_relay_server_info {
  char ifname[1025];
  ioa_addr addr;
  ioa_engine_handle e;
  int verbose;
  SSL_CTX *dtls_ctx;
  struct event *udp_listen_ev;
  evutil_socket_t udp_listen_fd;
  uint32_t *stats;
  ioa_engine_new_connection_event_handler connect_cb;
};

enum {
	NDC_LISTENING,
	NDC_ACCEPTING,
	NDC_READY
};

typedef struct _new_dtls_conn {
	int state;
	ur_conn_info info;
	struct event *ev;
	struct event *to_ev;
	dtls_listener_relay_server_type *server;
} new_dtls_conn;

///////////// dtls message types //////////

int is_dtls_handshake_message(const unsigned char* buf, int len);
int is_dtls_data_message(const unsigned char* buf, int len);
int is_dtls_alert_message(const unsigned char* buf, int len);
int is_dtls_cipher_change_message(const unsigned char* buf, int len);

int is_dtls_handshake_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x16 && buf[1]==0xfe && buf[2]==0xff);
}

int is_dtls_data_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x17 && buf[1]==0xfe && buf[2]==0xff);
}

int is_dtls_alert_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x15 && buf[1]==0xfe && buf[2]==0xff);
}

int is_dtls_cipher_change_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x14 && buf[1]==0xfe && buf[2]==0xff);
}

///////////// utils /////////////////////

#if !defined(TURN_NO_DTLS)

static void calculate_cookie(SSL* ssl, unsigned char *cookie_secret, unsigned int cookie_length) {
  long rv=(long)ssl;
  long inum=(cookie_length-(((long)cookie_secret)%sizeof(long)))/sizeof(long);
  long i=0;
  long *ip=(long*)cookie_secret;
  for(i=0;i<inum;++i,++ip) *ip=rv;
}

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  ioa_addr peer;

  unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
  calculate_cookie(ssl, cookie_secret, sizeof(cookie_secret));
  
  /* Read peer information */
  (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
  
  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
  case AF_INET:
    length += sizeof(struct in_addr);
    break;
  case AF_INET6:
    length += sizeof(struct in6_addr);
    break;
  default:
    OPENSSL_assert(0);
    break;
  }
  length += sizeof(in_port_t);
  buffer = (unsigned char*) OPENSSL_malloc(length);
  
  if (buffer == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"out of memory\n");
    return 0;
  }
  
  switch (peer.ss.ss_family) {
  case AF_INET:
    memcpy(buffer,
	   &peer.s4.sin_port,
	   sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.s4.sin_port),
	   &peer.s4.sin_addr,
	   sizeof(struct in_addr));
    break;
  case AF_INET6:
    memcpy(buffer,
	   &peer.s6.sin6_port,
	   sizeof(in_port_t));
    memcpy(buffer + sizeof(in_port_t),
	   &peer.s6.sin6_addr,
	   sizeof(struct in6_addr));
    break;
  default:
    OPENSSL_assert(0);
    break;
  }
  
  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char*) buffer, length, result, &resultlength);
  OPENSSL_free(buffer);
  
  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;
  
  return 1;
}

static int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
  unsigned int resultlength=0;
  unsigned char result[COOKIE_SECRET_LENGTH];

  generate_cookie(ssl, result, &resultlength);
  
  if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) {
    //TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: cookies are OK, length=%u\n",__FUNCTION__,cookie_len);
    return 1;
  }
  
  return 0;
}

/* NDC free */

static void free_ndc(new_dtls_conn *ndc)
{
	if (ndc) {
		EVENT_DEL(ndc->ev);
		EVENT_DEL(ndc->to_ev);
		//We use UDP only sockets here
		if (ndc->info.ssl) {
			if (!(SSL_get_shutdown(ndc->info.ssl) & SSL_SENT_SHUTDOWN)) {
				SSL_set_shutdown(ndc->info.ssl, SSL_RECEIVED_SHUTDOWN);
				SSL_shutdown(ndc->info.ssl);
			}
			SSL_free(ndc->info.ssl);
			ndc->info.ssl = NULL;
			ndc->info.fd = -1;
		} else if(ndc->info.fd>=0) {
			evutil_closesocket(ndc->info.fd);
			ndc->info.fd = -1;
		}
		free(ndc);
	}
}

/////////////// io handlers ///////////////////

static int dtls_accept(int verbose, SSL* ssl)
{

	if (!ssl)
		return -1;

	/* handshake */
	int rc = SSL_accept(ssl);
	int err = errno;

	if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_SYSCALL && errno == EMSGSIZE) {
		int new_mtu = decrease_mtu(ssl, SOSO_MTU, verbose);
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: mtu=%d\n", __FUNCTION__, new_mtu);
	}

	if (verbose)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Accept: rc=%d, errno=%d\n", rc, err);

	switch (SSL_get_error(ssl, rc)){
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
		return 0;
	case SSL_ERROR_WANT_WRITE:
		return 0;
	case SSL_ERROR_ZERO_RETURN:
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "accept: SSL_ERROR_ZERO_RETURN\n");
		return 0;
	case SSL_ERROR_SYSCALL:
		if (verbose) {
			char buf[65536];
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "accept: SSL_ERROR_SYSCALL: %d (%s)\n", err,
							ERR_error_string(ERR_get_error(), buf));
		}
		return 0;
	case SSL_ERROR_SSL:
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "accept: SSL_ERROR_SSL\n");
		return 0;
	default:
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "accept: UNKNOWN ERROR\n");
		return 0;
	}

	struct timeval timeout;
	/* Set and activate timeouts */
	timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	return 1;
}

static int accept_client_connection(dtls_listener_relay_server_type* server, new_dtls_conn **ndc)
{

	FUNCSTART;

	if (!ndc || !(*ndc) || (*ndc)->state != NDC_ACCEPTING)
		return -1;

	SSL* ssl = (*ndc)->info.ssl;

	if(!ssl)
		return -1;

	int rc = dtls_accept(server->verbose, (*ndc)->info.ssl);
	if (rc < 0)
		return -1;
	if (!rc)
		return rc;

	(*ndc)->state = NDC_READY;

	addr_debug_print(server->verbose, &((*ndc)->info.remote_addr), "Accepted connection from");

	if (server->verbose && SSL_get_peer_certificate(ssl)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1,
						XN_FLAG_MULTILINE);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n------------------------------------------------------------\n\n");
	}

	{
		ioa_socket_handle ioas = create_ioa_socket_from_ssl(server->e, (*ndc)->info.fd, ssl, DTLS_SOCKET, CLIENT_SOCKET, &((*ndc)->info.remote_addr), &((*ndc)->info.local_addr));
		if(ioas) {
			ioa_net_data nd;

			ns_bzero(&nd,sizeof(nd));
			addr_cpy(&(nd.src_addr),&((*ndc)->info.remote_addr));
			nd.nbh = NULL;
			nd.chnum = 0;
			nd.recv_ttl = TTL_IGNORE;
			nd.recv_tos = TOS_IGNORE;

			server->connect_cb(server->e, ioas, &nd);
			(*ndc)->info.ssl = NULL;
			(*ndc)->info.fd = -1;
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from SSL\n");
		}
	}

	free_ndc(*ndc);
	*ndc = NULL;

	FUNCEND	;

	return 0;
}

static int dtls_listen(int verbose, SSL* ssl, ioa_addr *client_addr)
{
	/* handshake */
	int rc = DTLSv1_listen(ssl, client_addr);

	if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_SYSCALL && errno == EMSGSIZE) {
		int new_mtu = decrease_mtu(ssl, SOSO_MTU, verbose);
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: mtu=%d\n", __FUNCTION__, new_mtu);
	}

	switch (SSL_get_error(ssl, rc)){
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
		return 0;
	case SSL_ERROR_WANT_WRITE:
		return 0;
	case SSL_ERROR_ZERO_RETURN:
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "listen: SSL_ERROR_ZERO_RETURN\n");
		return 0;
	case SSL_ERROR_SYSCALL:
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "listen: SSL_ERROR_SYSCALL\n");
		return 0;
	case SSL_ERROR_SSL:
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "listen: SSL_ERROR_SSL\n");
		return 0;
	default:
		if (verbose)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "listen: UNKNOWN ERROR\n");
		return 0;
	}

	return 1;
}

static int listen_client_connection(dtls_listener_relay_server_type* server, new_dtls_conn **ndc) {

	FUNCSTART;

	if(!ndc || !(*ndc) || (*ndc)->state!=NDC_LISTENING) return -1;

	ioa_addr client_addr;

	int rc = dtls_listen(server->verbose,(*ndc)->info.ssl,&client_addr);

	if(server->verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Listen: rc=%d\n",rc);

	if(rc<0) return -1;
	if(!rc) return rc;

	(*ndc)->state=NDC_ACCEPTING;
	addr_cpy(&((*ndc)->info.remote_addr),&client_addr);
	accept_client_connection(server,ndc);

	FUNCEND;
	return 0;
}

static void ndc_input_handler(ioa_socket_raw fd, short what, void* arg)
{

	if (!(what & EV_READ))
		return;

	if(!arg) {
		read_spare_buffer(fd);
		return;
	}

	UNUSED_ARG(fd);

	new_dtls_conn *ndc = (new_dtls_conn *)arg;

	dtls_listener_relay_server_type *server = (dtls_listener_relay_server_type *) (ndc->server);

	if (!server) {
		read_spare_buffer(fd);
		return;
	}

	if (ndc->info.fd < 0) {
		read_spare_buffer(fd);
		return;
	}

	if (!(ndc->info.ssl)) {
		read_spare_buffer(fd);
		return;
	}

	int ret = 0;

	switch (ndc->state){
	case NDC_ACCEPTING:
		ret = accept_client_connection(server, &ndc);
		break;
	case NDC_LISTENING:
		ret = listen_client_connection(server, &ndc);
		break;
	default:
		ret = -1;
	}

	if(ndc) {
		if (ret < 0 || (ndc->info.ssl && SSL_get_shutdown(ndc->info.ssl))) {
			free_ndc(ndc);
		}
	}
}

static void client_connecting_timeout_handler(ioa_socket_raw fd, short what, void* arg) {

  if(!arg) return;

  new_dtls_conn *ndc = (new_dtls_conn *)arg;

  dtls_listener_relay_server_type *server = ndc->server;

  FUNCSTART;

  UNUSED_ARG(fd);

  if(!(what&EV_TIMEOUT)) return;

  free_ndc(ndc);

  FUNCEND;
}

#endif

static evutil_socket_t open_client_connection_socket(dtls_listener_relay_server_type* server, ur_conn_info *pinfo);

static void udp_server_input_handler(evutil_socket_t fd, short what, void* arg)
{

	dtls_listener_relay_server_type* server = (dtls_listener_relay_server_type*) arg;

	if(!(server->connect_cb)) {
		return;
	}

	FUNCSTART;

	if (!server)
		return;

	if (!(what & EV_READ))
		return;

	if (server->stats)
		++(*(server->stats));

	ioa_addr client_addr;

	ioa_network_buffer_handle *elem = (ioa_network_buffer_handle *)
	  ioa_network_buffer_allocate(server->e);

	ioa_net_data nd;;

	ns_bzero(&nd,sizeof(nd));
	addr_cpy(&(nd.src_addr),&client_addr);
	nd.nbh = elem;
	nd.chnum = 0;
	nd.recv_ttl = TTL_IGNORE;
	nd.recv_tos = TOS_IGNORE;

	ioa_addr si_other;
	int slen = get_ioa_addr_len(&(server->addr));
	ssize_t bsize = 0;

	int flags = MSG_DONTWAIT;

	do {
		bsize = recvfrom(fd, ioa_network_buffer_data(elem), ioa_network_buffer_get_capacity(), flags, (struct sockaddr*) &si_other, (socklen_t*) &slen);
	} while (bsize < 0 && (errno == EINTR));

	if (bsize > 0) {

		ioa_network_buffer_set_size(elem, (size_t)bsize);

		if (stun_is_request_str(ioa_network_buffer_data(elem), ioa_network_buffer_get_size(elem))) {

			addr_cpy(&client_addr, &si_other);

			ur_conn_info info;

			memset(&info, 0, sizeof(info));
			info.fd = -1;
			addr_cpy(&(info.remote_addr), &client_addr);
			addr_cpy(&(info.local_addr), &(server->addr));

			if (open_client_connection_socket(server, &info) >= 0) {

				ioa_socket_handle ioas = create_ioa_socket_from_fd(server->e,
								info.fd, UDP_SOCKET, CLIENT_SOCKET,
								&info.remote_addr, &info.local_addr);

				if (ioas) {

					int rc = server->connect_cb(server->e, ioas, &nd);

					if(rc < 0) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create UDP session\n");
						IOA_CLOSE_SOCKET(ioas);
					}
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from FD\n");
					close(info.fd);
				}
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open socket from FD\n");
			}

		}

	}

	ioa_network_buffer_delete(server->e, nd.nbh);

	FUNCEND	;
}

static void server_input_handler(evutil_socket_t fd, short what, void* arg)
{
	dtls_listener_relay_server_type* server = (dtls_listener_relay_server_type*) arg;

	FUNCSTART;

	if (!server) {
		if(what & EV_READ) {
			read_spare_buffer(fd);
		}
		return;
	}

	if (!(what & EV_READ)) {
		return;
	}

	if (server->stats)
		++(*(server->stats));

	ioa_addr client_addr;

	int rc = 0;

	unsigned char buf[0xFFFF + 1];
	ioa_addr si_other;
	int slen = get_ioa_addr_len(&(server->addr));

	int flags = MSG_DONTWAIT | MSG_PEEK;

	do {
		rc = recvfrom(fd, buf, sizeof(buf), flags, (struct sockaddr*) &si_other, (socklen_t*) &slen);
	} while (rc < 0 && (errno == EINTR));

	addr_cpy(&client_addr, &si_other);

#if !defined(TURN_NO_DTLS)

	if (!no_dtls && is_dtls_handshake_message(buf, rc)) {

		SSL* connecting_ssl = NULL;

		BIO *bio = NULL;
		struct timeval timeout;

		/* Create BIO */
		bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		/* Set and activate timeouts */
		timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		connecting_ssl = SSL_new(server->dtls_ctx);

		SSL_set_bio(connecting_ssl, bio, bio);
		SSL_set_options(connecting_ssl, SSL_OP_COOKIE_EXCHANGE);

		SSL_set_max_cert_list(connecting_ssl, 655350);

		ur_conn_info info;

		memset(&info, 0, sizeof(info));
		info.fd = -1;
		addr_cpy(&(info.remote_addr), &client_addr);
		addr_cpy(&(info.local_addr), &(server->addr));
		info.ssl = connecting_ssl;

		if (open_client_connection_socket(server, &info) >= 0) {

		  new_dtls_conn *ndc = (new_dtls_conn *)malloc(sizeof(new_dtls_conn));
			memset(ndc, 0, sizeof(new_dtls_conn));

			memcpy(&(ndc->info), &info, sizeof(info));

			ndc->state = NDC_LISTENING;

			ndc->ev = event_new(server->e->event_base, info.fd, EV_READ | EV_PERSIST, ndc_input_handler, ndc);

			ndc->server = server;

			event_add(ndc->ev, NULL);

			set_mtu_df(ndc->info.ssl, ndc->info.fd, ndc->info.local_addr.ss.ss_family, SOSO_MTU, 1,
							server->verbose);

			{
				struct timeval tv;

				tv.tv_sec = DTLS_MAX_CONNECT_TIMEOUT;
				tv.tv_usec = 0;
				ndc->to_ev = evtimer_new(server->e->event_base,
								client_connecting_timeout_handler,
								ndc);
				evtimer_add(ndc->to_ev,&tv);
			}

			rc = listen_client_connection(server, &ndc);

			if (rc >= 0) {
				BIO_set_fd(SSL_get_rbio(connecting_ssl), ndc->info.fd, BIO_CLOSE);
				BIO_ctrl(SSL_get_rbio(connecting_ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0,
								&(ndc->info.remote_addr.ss));
			} else {
				free_ndc(ndc);
			}
		}
	} else if(!no_udp) {

#endif

		udp_server_input_handler(fd, what, arg);

#if !defined(TURN_NO_DTLS)
	} else {

		flags = MSG_DONTWAIT;

		do {
			rc = recvfrom(fd, buf, sizeof(buf), flags, (struct sockaddr*) &si_other, (socklen_t*) &slen);
		} while (rc < 0 && (errno == EINTR));
	}
#endif

	if (server->stats)
		--(*(server->stats));

	FUNCEND;
}

///////////////////// operations //////////////////////////

static evutil_socket_t open_client_connection_socket(dtls_listener_relay_server_type* server, ur_conn_info *pinfo) {

  FUNCSTART;

  if(!server) return -1;

  if(!pinfo) return -1;

  if(server->verbose) 
  {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: AF: %d:%d\n",__FUNCTION__,
	   (int)pinfo->remote_addr.ss.ss_family,(int)server->addr.ss.ss_family);
  }

  OPENSSL_assert(pinfo->remote_addr.ss.ss_family == server->addr.ss.ss_family);

  pinfo->fd = socket(pinfo->remote_addr.ss.ss_family, SOCK_DGRAM, 0);
  if (pinfo->fd < 0) {
    perror("socket");
    return -1;
  }

  if(sock_bind_to_device(pinfo->fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind client socket to device %s\n",server->ifname);
  }

  set_sock_buf_size(pinfo->fd,UR_CLIENT_SOCK_BUF_SIZE);
  
  socket_set_reusable(pinfo->fd);

  if(server->verbose) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Binding socket %d to addr\n",pinfo->fd);
	  addr_debug_print(server->verbose,&server->addr,"Bind to");
  }

  if(addr_bind(pinfo->fd,&server->addr)<0) {
    evutil_closesocket(pinfo->fd);
    pinfo->fd=-1;
    return -1;
  }

  if(addr_connect(pinfo->fd,&pinfo->remote_addr,NULL)<0) {
    evutil_closesocket(pinfo->fd);
    pinfo->fd=-1;
    return -1;
  }

  addr_debug_print(server->verbose, &pinfo->remote_addr,"UDP connected to");
  
  evutil_make_socket_nonblocking(pinfo->fd);

  set_socket_df(pinfo->fd, pinfo->remote_addr.ss.ss_family, 1);

  FUNCEND;

  return pinfo->fd;
}

static int create_server_socket(dtls_listener_relay_server_type* server) {

  FUNCSTART;

  if(!server) return -1;

  server->udp_listen_fd = -1;

  server->udp_listen_fd = socket(server->addr.ss.ss_family, SOCK_DGRAM, 0);
  if (server->udp_listen_fd < 0) {
    perror("socket");
    return -1;
  }

  set_sock_buf_size(server->udp_listen_fd,UR_SERVER_SOCK_BUF_SIZE);

  socket_set_reusable(server->udp_listen_fd);

  if(sock_bind_to_device(server->udp_listen_fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to device %s\n",server->ifname);
  }

  addr_bind(server->udp_listen_fd,&server->addr);

  set_socket_df(server->udp_listen_fd, server->addr.ss.ss_family, 1);

  evutil_make_socket_nonblocking(server->udp_listen_fd);

  server->udp_listen_ev = event_new(server->e->event_base,server->udp_listen_fd,
				    EV_READ|EV_PERSIST,server_input_handler,server);

  event_add(server->udp_listen_ev,NULL);

  if(addr_get_from_sock(server->udp_listen_fd, &(server->addr))) {
    perror("Cannot get local socket addr");
    return -1;
  }

  if(!no_udp && !no_dtls)
	  addr_debug_print(server->verbose, &server->addr,"UDP/DTLS listener opened on ");
  else if(!no_dtls)
	  addr_debug_print(server->verbose, &server->addr,"DTLS listener opened on ");
  else if(!no_udp)
	  addr_debug_print(server->verbose, &server->addr,"UDP listener opened on ");

  FUNCEND;
  
  return 0;
}

#if defined(REQUEST_CLIENT_CERT)

static int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
  /* This function should ask the user
   * if he trusts the received certificate.
   * Here we always trust.
   */
  if(ok && ctx) return 1;
  return -1;
}

#endif

static int init_server(dtls_listener_relay_server_type* server,
		       const char* ifname,
		       const char *local_address, 
		       int port, 
		       int verbose,
		       ioa_engine_handle e,
		       uint32_t *stats,
		       ioa_engine_new_connection_event_handler send_socket) {

  if(!server) return -1;

  server->dtls_ctx = e->dtls_ctx;
  server->stats=stats;
  server->connect_cb = send_socket;

  if(ifname) STRCPY(server->ifname,ifname);

  if(make_ioa_addr((const u08bits*)local_address, port, &server->addr)<0) {
    return -1;
  }

  server->verbose=verbose;
  
  server->e = e;
  
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method: %s\n",event_base_get_method(server->e->event_base));
  
  if(server->dtls_ctx) {

#if defined(REQUEST_CLIENT_CERT)
	  /* If client has to authenticate, then  */
	  SSL_CTX_set_verify(server->dtls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
#endif
  
	  SSL_CTX_set_read_ahead(server->dtls_ctx, 1);

#if !defined(TURN_NO_DTLS)
	  SSL_CTX_set_cookie_generate_cb(server->dtls_ctx, generate_cookie);
	  SSL_CTX_set_cookie_verify_cb(server->dtls_ctx, verify_cookie);
#endif
  }

  return create_server_socket(server);
}

static int clean_server(dtls_listener_relay_server_type* server) {
  if(server) {
    EVENT_DEL(server->udp_listen_ev);
    if(server->udp_listen_fd>=0) {
      evutil_closesocket(server->udp_listen_fd);
      server->udp_listen_fd=-1;
    }
  }
  return 0;
}

///////////////////////////////////////////////////////////


dtls_listener_relay_server_type* create_dtls_listener_server(const char* ifname,
							     const char *local_address, 
							     int port, 
							     int verbose,
							     ioa_engine_handle e,
							     uint32_t *stats,
							     ioa_engine_new_connection_event_handler send_socket) {
  
  dtls_listener_relay_server_type* server=(dtls_listener_relay_server_type*)
    malloc(sizeof(dtls_listener_relay_server_type));

  memset(server,0,sizeof(dtls_listener_relay_server_type));

  if(init_server(server,
		 ifname, local_address, port,
		 verbose,
		 e,
		 stats,
		 send_socket)<0) {
    free(server);
    return NULL;
  } else {
    return server;
  }
}

void udp_send_message(dtls_listener_relay_server_type *server, ioa_network_buffer_handle nbh, ioa_addr *dest)
{
	if(server && dest && nbh && (server->udp_listen_fd > -1)) {
		udp_send(server->udp_listen_fd, dest, (s08bits*)ioa_network_buffer_data(nbh), (int)ioa_network_buffer_get_size(nbh));
	}
}

void delete_dtls_listener_server(dtls_listener_relay_server_type* server, int delete_engine) {
  if(server) {
    clean_server(server);
    if(delete_engine)
    	close_ioa_engine(server->e);
    free(server);
  }
}

//////////////////////////////////////////////////////////////////
