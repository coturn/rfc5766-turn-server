/*
 * Copyright (C) 2011, 2012 Citrix Systems
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

#include "ns_turn_utils.h"
#include "stunservice.h"
#include "apputils.h"
#include "ns_turn_buffer.h"

//////////////////////////////////////////

#define FUNCSTART if(server && server->verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && server->verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

///////////////////////////////////////////

struct _stunserver {
  int verbose;
  char relay_ifname[1025];
  struct event_base *event_base;
  int stun_port;
  ioa_socket_raw stun_fd;
  struct event *stun_listen_ev;
  ioa_addr stun_i_addr;
};

//////////////// PLAIN NET ////////////////////////////

static int UDPNET_sendto(ioa_socket_raw fd, ioa_addr* dest_addr, const char* buffer, int len) {

  if(fd>=0 && dest_addr && buffer) {
    int slen=get_ioa_addr_len(dest_addr);
    int rc = 0;
    do {
      rc = sendto(fd,buffer,len,0,
		  (struct sockaddr*)dest_addr,
		  (socklen_t)slen);
    } while(rc<0 && ((errno==EINTR)||(errno==ENOBUFS)||(errno==EAGAIN)));

    return rc;
  }

  return -1;
}

static int UDPNET_recvfrom(ioa_socket_raw fd, ioa_addr* orig_addr, const ioa_addr *like_addr, char* buffer, int buf_size) {

  if(fd<0 || !orig_addr || !like_addr || !buffer) return -1;

  int len = 0;
  int slen=get_ioa_addr_len(like_addr);

  do {
    len = recvfrom(fd, buffer,
		   buf_size, 0,
		   (struct sockaddr*)orig_addr,(socklen_t*)&slen);
  } while(len<0 && ((errno==EINTR)||(errno==EAGAIN)));

  return len;
}

///////////////////////////////////////////

static int send_binding_OK(ioa_socket_raw fd, stun_buffer* request,
		    ioa_addr *reflexive_addr, int success) {

  if(fd>=0 && request) {
    
    stun_buffer response;
    stun_tid tid;
    
    stun_tid_from_message(request, &tid);
    
    int error_code=0;

    if(!success) error_code=403;
    
    stun_set_binding_response(&response, &tid, reflexive_addr, error_code, NULL);

    int rc = UDPNET_sendto(fd, reflexive_addr, (char*)response.buf,response.len);

    if(rc>0) {
      return 0;
    }
  }
  
  return -1;
}

///////////////////////////////////////////////////////////////////////////////////////////

static void stun_server_input_handler(ioa_socket_raw fd, short what, void* arg) {

  if(!(what&EV_READ) || !arg) return;

  UNUSED_ARG(fd);
  
  stunserver *server=(stunserver*)arg;

  ioa_addr remote_addr;  
  stun_buffer buffer;

  int len = UDPNET_recvfrom(fd, &remote_addr, &(server->stun_i_addr), (char*)buffer.buf, sizeof(buffer.buf));

  if(len>=0) {

    buffer.len=len;

    if(stun_is_binding_request(&buffer, 0)) {      
      send_binding_OK(fd,&buffer,&remote_addr,1);
    }
  }
}

static int create_internal_stun_socket(stunserver* server) {

  FUNCSTART;

  if(!server) return -1;

  server->stun_fd = socket(server->stun_i_addr.ss.ss_family, SOCK_DGRAM, 0);
  if (server->stun_fd < 0) {
    perror("socket");
    return -1;
  }

  set_sock_buf_size(server->stun_fd,UR_SERVER_SOCK_BUF_SIZE);

  socket_set_reusable(server->stun_fd);

  if(sock_bind_to_device(server->stun_fd, (unsigned char*)server->relay_ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind socket to device %s\n",server->relay_ifname);
  }

  addr_bind(server->stun_fd,&(server->stun_i_addr));

  evutil_make_socket_nonblocking(server->stun_fd);

  server->stun_listen_ev = event_new(server->event_base,server->stun_fd,
				     EV_READ|EV_PERSIST,stun_server_input_handler,server);

  event_add(server->stun_listen_ev,NULL);

  addr_debug_print(server->verbose, &(server->stun_i_addr),"STUN server opened on ");

  FUNCEND;
  
  return 0;
}

stunserver* start_internal_stun_server(int verbose, const char* relay_ifname, const char* relay_address, int stun_port,
				struct event_base *event_base)
{

	stunserver* server = (stunserver*) malloc(sizeof(stunserver));
	memset(server, 0, sizeof(stunserver));

	server->verbose = verbose;
	server->stun_fd = -1;
	server->event_base = event_base;

	if (stun_port < 1)
		stun_port = DEFAULT_STUN_PORT;

	if (make_ioa_addr((const u08bits*) (relay_address), 0, &(server->stun_i_addr)) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: Cannot create relay address %s\n", __FUNCTION__,
						relay_address);
		free(server);
		return NULL;
	}
	addr_set_port(&(server->stun_i_addr), stun_port);

	if (relay_ifname)
		strncpy(server->relay_ifname, relay_ifname, sizeof(server->relay_ifname));

	if (create_internal_stun_socket(server) < 0 || ((server->stun_fd) < 0)) {
		free(server);
		return NULL;
	}

	return server;
}

void clean_internal_stun_server(stunserver **server) {

  if(server && *server) {

    EVENT_DEL((*server)->stun_listen_ev);

    if((*server)->stun_fd>=0) {
      evutil_closesocket((*server)->stun_fd);
      (*server)->stun_fd=-1;
    }

    free(*server);
    *server=NULL;
  }
}

//////////////////////////////////////////////////////////////////
