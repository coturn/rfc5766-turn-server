/*
 * Copyright (C) 2012 Citrix Systems
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

#include "ns_turn_utils.h"

#include "tls_listener.h"
#include "ns_ioalib_impl.h"

#include <event2/listener.h>

///////////////////////////////////////////////////

typedef struct {
  ioa_addr local_addr;
  ioa_addr remote_addr;
  ioa_socket_raw fd;
} ur_conn_info;

///////////////////////////////////////////////////

#define FUNCSTART if(server && server->verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && server->verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

struct tls_listener_relay_server_info
{
	char ifname[1025];
	ioa_addr addr;
	ioa_addr relay_addr;
	ioa_engine_handle e;
	int verbose;
	struct evconnlistener *l;
	uint32_t *stats;
};

/////////////// io handlers ///////////////////

static void server_input_handler(struct evconnlistener *l, evutil_socket_t fd,
				struct sockaddr *sa, int socklen, void *arg)
{

	UNUSED_ARG(l);

	tls_listener_relay_server_type * server = (tls_listener_relay_server_type*) arg;

	if(!(server->e->connect_cb)) {
		close(fd);
		return;
	}

	FUNCSTART;

	if (!server)
		return;

	if (server->stats)
		++(*(server->stats));

	ioa_addr client_addr;
	ns_bcopy(sa,&client_addr,socklen);

	set_sock_buf_size(fd,UR_CLIENT_SOCK_BUF_SIZE);

	addr_debug_print(server->verbose, &client_addr,"tls connected to");

	ioa_socket_handle ioas =
				create_ioa_socket_from_fd(
							server->e,
							fd,
							TLS_SOCKET,
							CLIENT_SOCKET,
							&client_addr,
							&(server->addr));

	if (ioas) {
		ioa_net_data nd = { &client_addr, NULL, 0 };
		int rc = server->e->connect_cb(server->e, ioas, &nd);

		if (rc < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"Cannot create tls session\n");
			IOA_CLOSE_SOCKET(ioas);
		}
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"Cannot create ioa_socket from FD\n");
		close(fd);
	}

	FUNCEND	;
}

///////////////////// operations //////////////////////////

static int create_server_listener(tls_listener_relay_server_type* server) {

  FUNCSTART;

  if(!server) return -1;

  evutil_socket_t tls_listen_fd = -1;

  tls_listen_fd = socket(server->addr.ss.ss_family, SOCK_STREAM, 0);
  if (tls_listen_fd < 0) {
      perror("socket");
      return -1;
  }

  socket_set_reusable(tls_listen_fd);

  if(sock_bind_to_device(tls_listen_fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to device %s\n",server->ifname);
  }

  addr_bind(tls_listen_fd,&server->addr);

  evutil_make_socket_nonblocking(tls_listen_fd);

  server->l = evconnlistener_new(server->e->event_base,
		  server_input_handler, server,
		  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
		  1024, tls_listen_fd);

  if(!(server->l)) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot create TLS listener\n");
	  evutil_closesocket(tls_listen_fd);
	  return -1;
  }

  if(addr_get_from_sock(tls_listen_fd, &(server->addr))) {
    perror("Cannot get local socket addr");
    return -1;
  }

  addr_debug_print(server->verbose, &server->addr,"Listener opened on ");

  FUNCEND;
  
  return 0;
}

static int init_server(tls_listener_relay_server_type* server,
		       const char* ifname,
		       const char *local_address, 
		       int port, 
		       int verbose,
		       ioa_engine_handle e,
		       uint32_t *stats) {

  if(!server) return -1;

  server->stats=stats;

  if(ifname) strncpy(server->ifname,ifname,sizeof(server->ifname)-1);

  if(make_ioa_addr((const u08bits*)local_address, port, &server->addr)<0) {
    return -1;
  }

  server->verbose=verbose;
  
  server->e = e;
  
  return create_server_listener(server);
}

static int clean_server(tls_listener_relay_server_type* server) {
  if(server) {
	  if(server->l) {
		  evconnlistener_free(server->l);
		  server->l = NULL;
	  }
  }
  return 0;
}

///////////////////////////////////////////////////////////


tls_listener_relay_server_type* create_tls_listener_server(const char* ifname,
				const char *local_address, int port, int verbose,
				ioa_engine_handle e, uint32_t *stats)
{

	tls_listener_relay_server_type* server = malloc(sizeof(tls_listener_relay_server_type));

	memset(server, 0, sizeof(tls_listener_relay_server_type));

	if (init_server(server, ifname, local_address, port, verbose, e, stats) < 0) {
		free(server);
		return NULL;
	} else {
		return server;
	}
}

void delete_tls_listener_server(tls_listener_relay_server_type* server, int delete_engine) {
  if(server) {
    clean_server(server);
    if(delete_engine && (server->e))
    	close_ioa_engine(server->e);
    free(server);
  }
}

//////////////////////////////////////////////////////////////////
