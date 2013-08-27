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

#define MAX_SINGLE_UDP_BATCH (16)

struct dtls_listener_relay_server_info {
  char ifname[1025];
  ioa_addr addr;
  ioa_engine_handle e;
  int verbose;
  SSL_CTX *dtls_ctx;
  struct event *udp_listen_ev;
  ioa_socket_handle udp_listen_s;
  struct message_to_relay sm;
  int slen0;
  relay_server_handle rs;
  ioa_engine_new_connection_event_handler connect_cb;
  ioa_engine_udp_event_handler udp_eh;

};

///////////// forward declarations ////////

static int create_server_socket(dtls_listener_relay_server_type* server);
static int clean_server(dtls_listener_relay_server_type* server);
static int reopen_server_socket(dtls_listener_relay_server_type* server);

///////////// dtls message types //////////

int is_dtls_handshake_message(const unsigned char* buf, int len);
int is_dtls_data_message(const unsigned char* buf, int len);
int is_dtls_alert_message(const unsigned char* buf, int len);
int is_dtls_cipher_change_message(const unsigned char* buf, int len);

int is_dtls_message(const unsigned char* buf, int len);

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

int is_dtls_message(const unsigned char* buf, int len) {
  if(buf && (len>3) && (buf[1])==0xfe && (buf[2]==0xff)) {
	  switch (buf[0]) {
	  case 0x14:
	  case 0x15:
	  case 0x16:
	  case 0x17:
		  return 1;
	  default:
		  ;
	  }
  }
  return 0;
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
  (void) BIO_dgram_get_peer(SSL_get_wbio(ssl), &peer);
  
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

/////////////// io handlers ///////////////////

static int dtls_accept_client_connection(dtls_listener_relay_server_type* server,
				SSL *ssl,
				ioa_addr *remote_addr, ioa_addr *local_addr,
				int fd,
				u08bits *s, int len)
{

	FUNCSTART;

	if (!ssl)
		return -1;

	int rc = ssl_read(ssl, (s08bits*)s, ioa_network_buffer_get_capacity(), server->verbose, &len);

	if (rc < 0)
		return -1;

	addr_debug_print(server->verbose, remote_addr, "Accepted connection from");

	{
		ioa_socket_handle ioas = create_ioa_socket_from_ssl(server->e, fd, NULL, ssl, DTLS_SOCKET, CLIENT_SOCKET, remote_addr, local_addr);
		if(ioas) {

			ioas->listener_server = server;

			addr_cpy(&(server->sm.m.sm.nd.src_addr),remote_addr);
			server->sm.m.sm.nd.nbh = NULL;
			server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
			server->sm.m.sm.nd.recv_tos = TOS_IGNORE;
			server->sm.m.sm.s = ioas;

			server->connect_cb(server->e, &(server->sm));
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from SSL\n");
		}
	}

	FUNCEND	;

	return 0;
}

static evutil_socket_t dtls_open_client_connection_socket(dtls_listener_relay_server_type* server, ur_conn_info *pinfo);

static void dtls_server_input_handler(evutil_socket_t fd, short what, void* arg, u08bits *buf, int len)
{
	dtls_listener_relay_server_type* server = (dtls_listener_relay_server_type*) arg;

	FUNCSTART;

	if (!server || !buf || len<1) {
		return;
	}

	if (!(what & EV_READ)) {
		return;
	}

	SSL* connecting_ssl = NULL;

	BIO *wbio = NULL;
	struct timeval timeout;

	/* Create BIO */
	wbio = BIO_new_dgram(fd, BIO_NOCLOSE);
	(void)BIO_dgram_set_peer(wbio, (struct sockaddr*) &(server->sm.m.sm.nd.src_addr));

	/* Set and activate timeouts */
	timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
	timeout.tv_usec = 0;
	BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	connecting_ssl = SSL_new(server->dtls_ctx);

	SSL_set_accept_state(connecting_ssl);

	SSL_set_bio(connecting_ssl, NULL, wbio);
	SSL_set_options(connecting_ssl, SSL_OP_COOKIE_EXCHANGE);

	SSL_set_max_cert_list(connecting_ssl, 655350);

	ur_conn_info info;

	ns_bzero(&info, sizeof(ur_conn_info));
	info.fd = -1;
	addr_cpy(&(info.remote_addr), &(server->sm.m.sm.nd.src_addr));
	addr_cpy(&(info.local_addr), &(server->addr));
	info.ssl = connecting_ssl;

	if ((dtls_open_client_connection_socket(server, &info) >= 0) && info.ssl) {

		set_mtu_df(info.ssl, info.fd, info.local_addr.ss.ss_family, SOSO_MTU, 1,
			server->verbose);

		int rc = dtls_accept_client_connection(server, info.ssl,
						&info.remote_addr, &info.local_addr,
						info.fd,
						buf, len);

		if (rc < 0) {
			if (!(SSL_get_shutdown(info.ssl) & SSL_SENT_SHUTDOWN)) {
				SSL_set_shutdown(info.ssl, SSL_RECEIVED_SHUTDOWN);
				SSL_shutdown(info.ssl);
			}
			SSL_free(info.ssl);

			if(info.fd>=0)
				socket_closesocket(info.fd);
		}
	} else {
		if(connecting_ssl)
			SSL_free(connecting_ssl);
	}
}

#endif


static void udp_server_input_handler(evutil_socket_t fd, short what, void* arg)
{
	int cycle = 0;

	dtls_listener_relay_server_type* server = (dtls_listener_relay_server_type*) arg;

	FUNCSTART;

	if (!(what & EV_READ)) {
		return;
	}

	ioa_network_buffer_handle *elem = NULL;

	start_udp_cycle:

	elem = (ioa_network_buffer_handle *)ioa_network_buffer_allocate(server->e);

	server->sm.m.sm.nd.nbh = elem;
	server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
	server->sm.m.sm.nd.recv_tos = TOS_IGNORE;

	int slen = server->slen0;
	ssize_t bsize = 0;

	int flags = 0;

	do {
		bsize = recvfrom(fd, ioa_network_buffer_data(elem), ioa_network_buffer_get_capacity(), flags, (struct sockaddr*) &(server->sm.m.sm.nd.src_addr), (socklen_t*) &slen);
	} while (bsize < 0 && (errno == EINTR));

	int conn_reset = is_connreset();
	int to_block = would_block();

	if (bsize < 0) {

		if(to_block) {
			ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
			server->sm.m.sm.nd.nbh = NULL;
			FUNCEND;
			return;
		}

	#if defined(MSG_ERRQUEUE)

		//Linux
		int eflags = MSG_ERRQUEUE | MSG_DONTWAIT;
		static s08bits buffer[65535];
		u32bits errcode = 0;
		ioa_addr orig_addr;
		int ttl = 0;
		int tos = 0;
		udp_recvfrom(fd, &orig_addr, &(server->addr), buffer,
					(int) sizeof(buffer), &ttl, &tos, server->e->cmsg, eflags,
					&errcode);
		//try again...
		do {
			bsize = recvfrom(fd, ioa_network_buffer_data(elem), ioa_network_buffer_get_capacity(), flags, (struct sockaddr*) &(server->sm.m.sm.nd.src_addr), (socklen_t*) &slen);
		} while (bsize < 0 && (errno == EINTR));

		conn_reset = is_connreset();
		to_block = would_block();

	#endif

		if(conn_reset) {
			ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
			server->sm.m.sm.nd.nbh = NULL;
			reopen_server_socket(server);
			FUNCEND;
			return;
		}
	}

	if(bsize<0) {
		if(!to_block && !conn_reset) {
			int ern=errno;
			perror(__FUNCTION__);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: recvfrom error %d\n",__FUNCTION__,ern);
		}
		ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
		server->sm.m.sm.nd.nbh = NULL;
		FUNCEND;
		return;
	}

	if (bsize > 0) {

		ioa_network_buffer_set_size(elem, (size_t)bsize);
		server->sm.m.sm.s = server->udp_listen_s;
		server->sm.t = RMT_SOCKET;

		int rc = 0;

#if !defined(TURN_NO_DTLS)
		if (!no_dtls && is_dtls_handshake_message(ioa_network_buffer_data(elem),
						(int)ioa_network_buffer_get_size(elem))) {
			dtls_server_input_handler(fd, what, arg,
				ioa_network_buffer_data(elem),
				(int)ioa_network_buffer_get_size(elem));
			rc = 1;
		}
#endif

		if(!rc) {
			rc = server->udp_eh(server->rs, &(server->sm));

			if(rc < 0) {
				if(eve(server->e->verbose)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot handle UDP event\n");
				}
			}
		}
	}

	ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
	server->sm.m.sm.nd.nbh = NULL;

	if(cycle++<MAX_SINGLE_UDP_BATCH)
		goto start_udp_cycle;

	FUNCEND;
}

///////////////////// operations //////////////////////////

#if !defined(TURN_NO_DTLS)

static evutil_socket_t dtls_open_client_connection_socket(dtls_listener_relay_server_type* server, ur_conn_info *pinfo) {

  FUNCSTART;

  if(!server) return -1;

  if(!pinfo) return -1;

  if(server->verbose)
  {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: AF: %d:%d\n",__FUNCTION__,
	   (int)pinfo->remote_addr.ss.ss_family,(int)server->addr.ss.ss_family);
  }

  if(pinfo->remote_addr.ss.ss_family != server->addr.ss.ss_family)
	  return -1;

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
	  socket_closesocket(pinfo->fd);
    pinfo->fd=-1;
    return -1;
  }

  if(addr_connect(pinfo->fd,&pinfo->remote_addr,NULL)<0) {
	  socket_closesocket(pinfo->fd);
    pinfo->fd=-1;
    return -1;
  }

  addr_debug_print(server->verbose, &pinfo->remote_addr,"UDP connected to");

  socket_set_nonblocking(pinfo->fd);

  set_socket_df(pinfo->fd, pinfo->remote_addr.ss.ss_family, 1);

  FUNCEND;

  return pinfo->fd;
}

#endif

static int create_server_socket(dtls_listener_relay_server_type* server) {

  FUNCSTART;

  if(!server) return -1;

  clean_server(server);

  ioa_socket_raw udp_listen_fd = -1;

  udp_listen_fd = socket(server->addr.ss.ss_family, SOCK_DGRAM, 0);
  if (udp_listen_fd < 0) {
    perror("socket");
    return -1;
  }

  server->udp_listen_s = create_ioa_socket_from_fd(server->e, udp_listen_fd, NULL, UDP_SOCKET, LISTENER_SOCKET, NULL, &(server->addr));

  server->udp_listen_s->listener_server = server;

  set_sock_buf_size(udp_listen_fd,UR_SERVER_SOCK_BUF_SIZE);

  if(sock_bind_to_device(udp_listen_fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to device %s\n",server->ifname);
  }

  if(addr_bind(udp_listen_fd,&server->addr)<0) {
	  perror("Cannot bind local socket to addr");
	  char saddr[129];
	  addr_to_string(&server->addr,(u08bits*)saddr);
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind UDP/DTLS listener socket to addr %s\n",saddr);
	  return -1;
  }

  server->udp_listen_ev = event_new(server->e->event_base,udp_listen_fd,
				    EV_READ|EV_PERSIST,udp_server_input_handler,server);

  event_add(server->udp_listen_ev,NULL);

  if(addr_get_from_sock(udp_listen_fd, &(server->addr))) {
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

static int reopen_server_socket(dtls_listener_relay_server_type* server)
{
	if(!server)
		return 0;

	FUNCSTART;

	EVENT_DEL(server->udp_listen_ev);

	if(server->udp_listen_s->fd>=0) {
		socket_closesocket(server->udp_listen_s->fd);
		server->udp_listen_s->fd = -1;
	}

	if (!(server->udp_listen_s)) {
		return create_server_socket(server);
	}

	ioa_socket_raw udp_listen_fd = socket(server->addr.ss.ss_family, SOCK_DGRAM, 0);
	if (udp_listen_fd < 0) {
		perror("socket");
		FUNCEND;
		return -1;
	}

	server->udp_listen_s->fd = udp_listen_fd;

	/* some UDP sessions may fail due to the race condition here */

	set_socket_options(server->udp_listen_s);

	set_sock_buf_size(udp_listen_fd, UR_SERVER_SOCK_BUF_SIZE);

	if (sock_bind_to_device(udp_listen_fd, (unsigned char*) server->ifname) < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
			"Cannot bind listener socket to device %s\n",
			server->ifname);
	}

	if(addr_bind(udp_listen_fd,&server->addr)<0) {
		  perror("Cannot bind local socket to addr");
		  char saddr[129];
		  addr_to_string(&server->addr,(u08bits*)saddr);
		  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to addr %s\n",saddr);
		  return -1;
	}

	server->udp_listen_ev = event_new(server->e->event_base, udp_listen_fd,
				EV_READ | EV_PERSIST, udp_server_input_handler, server);

	event_add(server->udp_listen_ev, NULL );

	if (!no_udp && !no_dtls)
		addr_debug_print(server->verbose, &server->addr,
					"UDP/DTLS listener opened on ");
	else if (!no_dtls)
		addr_debug_print(server->verbose, &server->addr,
					"DTLS listener opened on ");
	else if (!no_udp)
		addr_debug_print(server->verbose, &server->addr,
				"UDP listener opened on ");

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
		       relay_server_handle rs,
		       ioa_engine_new_connection_event_handler send_socket,
		       ioa_engine_udp_event_handler udp_eh) {

  if(!server) return -1;

  server->dtls_ctx = e->dtls_ctx;
  server->connect_cb = send_socket;
  server->udp_eh = udp_eh;

  if(ifname) STRCPY(server->ifname,ifname);

  if(make_ioa_addr((const u08bits*)local_address, port, &server->addr)<0) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot create a UDP/DTLS listener for address: %s\n",local_address);
	  return -1;
  }

  server->slen0 = get_ioa_addr_len(&(server->addr));

  server->verbose=verbose;
  
  server->e = e;
  server->rs = rs;
  
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
    close_ioa_socket(server->udp_listen_s);
    server->udp_listen_s = NULL;
  }
  return 0;
}

///////////////////////////////////////////////////////////

dtls_listener_relay_server_type* create_dtls_listener_server(const char* ifname,
							     const char *local_address, 
							     int port, 
							     int verbose,
							     ioa_engine_handle e,
							     relay_server_handle rs,
							     ioa_engine_new_connection_event_handler send_socket,
							     ioa_engine_udp_event_handler udp_eh) {
  
  dtls_listener_relay_server_type* server=(dtls_listener_relay_server_type*)
    turn_malloc(sizeof(dtls_listener_relay_server_type));

  ns_bzero(server,sizeof(dtls_listener_relay_server_type));

  if(init_server(server,
		 ifname, local_address, port,
		 verbose,
		 e,
		 rs,
		 send_socket,
		 udp_eh)<0) {
    turn_free(server,sizeof(dtls_listener_relay_server_type));
    return NULL;
  } else {
    return server;
  }
}

ioa_engine_handle get_engine(dtls_listener_relay_server_type* server)
{
	if(server)
		return server->e;
	return NULL;
}

//////////// UDP send ////////////////

void udp_send_message(dtls_listener_relay_server_type *server, ioa_network_buffer_handle nbh, ioa_addr *dest)
{
	if(server && dest && nbh && (server->udp_listen_s))
		udp_send(server->udp_listen_s, dest, (s08bits*)ioa_network_buffer_data(nbh), (int)ioa_network_buffer_get_size(nbh));
}

//////////////////////////////////////////////////////////////////
