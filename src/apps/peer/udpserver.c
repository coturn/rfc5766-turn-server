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

#include "apputils.h"
#include "udpserver.h"
#include "stun_buffer.h"

/////////////// io handlers ///////////////////

static void udp_server_input_handler(evutil_socket_t fd, short what, void* arg) {

  if(!(what&EV_READ)) return;

  server_type *server=(server_type*)arg;

  FUNCSTART;

  int len = 0;
  int slen = get_ioa_addr_len(&(server->addr));
  stun_buffer buffer;
  ioa_addr remote_addr;

  do {
    len = recvfrom(fd, buffer.buf, sizeof(buffer.buf)-1, 0, (struct sockaddr*) &remote_addr, (socklen_t*) &slen);
  } while(len<0 && ((errno==EINTR)||(errno==EAGAIN)));
  
  buffer.len=len;

  if(len>=0) {
    do {
      len = sendto(fd, buffer.buf, len, 0, (const struct sockaddr*) &remote_addr, (socklen_t) slen);
    } while (len < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));
  }

  FUNCEND;
}

///////////////////// operations //////////////////////////

static int udp_create_server_socket(server_type* server, 
				    const char* ifname, const char *local_address, int port) {

  FUNCSTART;

  if(!server) return -1;

  server->udp_fd = -1;

  strncpy(server->ifname,ifname,sizeof(server->ifname)-1);

  if(make_ioa_addr((const u08bits*)local_address, port, &server->addr)<0) return -1;
  
  server->udp_fd = socket(server->addr.ss.ss_family, SOCK_DGRAM, 0);
  if (server->udp_fd < 0) {
    perror("socket");
    return -1;
  }

  if(sock_bind_to_device(server->udp_fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind udp server socket to device %s\n",server->ifname);
  }

  set_sock_buf_size(server->udp_fd,UR_SERVER_SOCK_BUF_SIZE);
  
  socket_set_reusable(server->udp_fd);
  if(addr_bind(server->udp_fd,&server->addr)<0) return -1;
  
  evutil_make_socket_nonblocking(server->udp_fd);

  server->udp_ev = event_new(server->event_base,server->udp_fd,EV_READ|EV_PERSIST,
			     udp_server_input_handler,server);
  
  event_add(server->udp_ev,NULL);
  
  FUNCEND;
  
  return 0;
}

static server_type* init_server(int verbose, const char* ifname, const char *local_address, int port) {

  server_type* server=(server_type*)malloc(sizeof(server_type));

  if(!server) return server;

  memset(server,0,sizeof(server_type));

  server->verbose=verbose;

  server->event_base = event_base_new();

  server->udp_fd=-1;

  udp_create_server_socket(server, ifname, local_address, port);

  return server;
}

static int clean_server(server_type* server) {
  if(server) {
    EVENT_DEL(server->udp_ev);
    if(server->event_base) event_base_free(server->event_base);
    if(server->udp_fd>=0) {
      evutil_closesocket(server->udp_fd);
      server->udp_fd=-1;
    }
    free(server);
  }
  return 0;
}

///////////////////////////////////////////////////////////

static void run_events(server_type* server) {

  if(!server) return;

  struct timeval timeout;

  timeout.tv_sec=0;
  timeout.tv_usec=100000;

  event_base_loopexit(server->event_base, &timeout);
  event_base_dispatch(server->event_base);
}

/////////////////////////////////////////////////////////////


server_type* start_udp_server(int verbose, const char* ifname, const char *local_address, int port) {
  return init_server(verbose, ifname, local_address, port);
}

void run_udp_server(server_type* server) {
  
  if(server) {
    
    unsigned int cycle=0;
    
    while (1) {
      
      cycle++;
      
      run_events(server);
    }
  }  
}

void clean_udp_server(server_type* server) {
  if(server) clean_server(server);
}

//////////////////////////////////////////////////////////////////
