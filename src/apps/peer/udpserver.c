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

////////////// SS ///////////////

static app_ur_super_session* init_super_session(app_ur_super_session *ss) {
  if(ss) {
    memset(ss,0,sizeof(app_ur_super_session));
    ss->session.pinfo.fd=-1;
    ss->tcp_session.pinfo.fd=-1;
  }
  return ss;
}

app_ur_super_session* create_new_ss(void) {
  return init_super_session((app_ur_super_session*)malloc(sizeof(app_ur_super_session)));
}

/////////////// clean all //////////////////////

static void us_delete_ur_map_session_elem_data(app_ur_session* cdi) {
  if(cdi) {
    EVENT_DEL(cdi->input_ev);
    if(cdi->pinfo.fd>=0) {
      evutil_closesocket(cdi->pinfo.fd);
    }
    cdi->pinfo.fd=-1;
  }
}

static void delete_ur_map_ss(void *p) {
  if(p) {
    app_ur_super_session* ss = (app_ur_super_session*)p;
    us_delete_ur_map_session_elem_data(&(ss->session));
    us_delete_ur_map_session_elem_data(&(ss->tcp_session));
    free(p);
  }
}

int remove_all_from_ur_map_ss(ur_map* map, app_ur_super_session* ss)
{
	if (!map || !ss)
		return 0;
	else {

		int ret = 0;

		if (ss->session.pinfo.fd >= 0) {
			ret |= ur_map_del(map, (ur_map_key_type)ss->session.pinfo.fd, NULL);
		}
		if (ss->tcp_session.pinfo.fd >= 0) {
			ret |= ur_map_del(map, (ur_map_key_type)ss->tcp_session.pinfo.fd, NULL);
		}
		delete_ur_map_ss(ss);

		return ret;
	}
}

/////////////// Client actions /////////////////

static int shutdown_client_connection(server_type *server, app_ur_session *elem) {

  FUNCSTART;

  if(!elem) return -1;
  
  elem->state=UR_STATE_SHUTTING_DOWN;
  
  app_ur_super_session* ss = get_from_ur_map_ss(server->client_map,elem->pinfo.fd);
  if(!ss) return -1;

  remove_all_from_ur_map_ss(server->client_map,ss);
  
  if (server->verbose)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"done, connection closed.\n");

  FUNCEND;
  
  return 0;
}

static int write_client_connection(server_type *server, app_ur_session *elem) {

  FUNCSTART;

  if(!elem) return -1;

  if(elem->state!=UR_STATE_READY) return -1;

  int ret=0;

  if(elem->pinfo.fd>=0) {
    int rc = 0;
    do {
      rc = send(elem->pinfo.fd,elem->in_buffer.buf,elem->in_buffer.len,0);
    } while(rc<0 && ((errno==EINTR)||(errno==ENOBUFS)||(errno==EAGAIN)));
    
    if (server->verbose) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"wrote %d bytes\n", (int)rc);
    }
  }

  elem->state=UR_STATE_READY;

  FUNCEND;

  return ret;
}

static int udp_read_client_connection(server_type *server,
				  app_ur_session *elem) {

  FUNCSTART;

  if(!elem) return -1;
  
  if(elem->state!=UR_STATE_READY && elem->state!=UR_STATE_WAITING_FOR_VERIFICATION) return -1;

  int len = 0;

  do {
    len = recv(elem->pinfo.fd, elem->in_buffer.buf, sizeof(elem->in_buffer.buf)-1, 0);
  } while(len<0 && ((errno==EINTR)||(errno==EAGAIN)));
  
  elem->in_buffer.len=len;

  if(len>=0) {

    if(stun_is_command_message(&(elem->in_buffer))) {

      if(stun_is_binding_response(&(elem->in_buffer))) {

	app_ur_super_session* ss = get_from_ur_map_ss(server->client_map,elem->pinfo.fd);
	
	if(ss) {
	  
	  if(elem->state==UR_STATE_WAITING_FOR_VERIFICATION) {
	    
	    if(stun_is_success_response(&(elem->in_buffer))) {
	      
	      elem->state=UR_STATE_READY;
	      ioa_addr reflexive_addr;
	      addr_set_any(&reflexive_addr);
	      if(stun_attr_get_first_addr(&(elem->in_buffer), STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, 
					  &reflexive_addr,NULL)>=0) {

		addr_debug_print(server->verbose, &reflexive_addr,"UDP reflexive addr");

		app_ur_conn_info* pinfo=&(ss->session.pinfo);

		if(addr_connect(pinfo->fd,&pinfo->remote_addr)<0) {
		  FUNCEND;
		  return -1;
		}

		addr_debug_print(server->verbose, &pinfo->remote_addr,"UDP connected to");
		
		FUNCEND;
		return 0;
	      }
	      FUNCEND;
	      return 0;
	    }
	  }
	}
      }
      FUNCEND;
      return 0;
    } else {
      elem->in_buffer.buf[len]=0;
      if(len==1 && elem->in_buffer.buf[0] == 'x') {
	elem->state=UR_STATE_SHUTTING_DOWN;
	return shutdown_client_connection(server,elem);
      }
      
      FUNCEND;
      return write_client_connection(server,elem);
    }
  } 

  FUNCEND;
  return -1;
}

/////////////// io handlers ///////////////////

static void client_input_handler(evutil_socket_t fd, short what, void* arg) {

  if(!(what&EV_READ)) return;

  server_type *server=(server_type*)arg;

  app_ur_super_session* ss = get_from_ur_map_ss(server->client_map, fd);
  if(!ss) {
    return;
  }
  app_ur_session* elem = &(ss->session);
  
  int ret = 0;
  
  switch(elem->state) {
  case UR_STATE_SHUTTING_DOWN:
    shutdown_client_connection(server,elem);
    return;
  case UR_STATE_WAITING_FOR_VERIFICATION:
  case UR_STATE_READY:
    ret = udp_read_client_connection(server,elem);
    break;
  default:
    ret = -1;
  }

}

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

static int udp_open_client_connection_worker(server_type* server, 
					     app_ur_super_session *ss, 
					     ioa_addr *remote_addr) {

  FUNCSTART;
  
  if(!server) return -1;
  
  if(!ss) return -1;
    
  if(server->verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: AF: %d:%d\n",__FUNCTION__,
	   (int)remote_addr->ss.ss_family,(int)server->addr.ss.ss_family);
  }
  
  app_ur_conn_info* pinfo=&(ss->session.pinfo);
  addr_cpy(&(pinfo->remote_addr),remote_addr);
  
  pinfo->fd = socket(pinfo->remote_addr.ss.ss_family, SOCK_DGRAM, 0);
  if (pinfo->fd < 0) {
    perror("socket");
    FUNCEND;
    return -1;
  }

  if(sock_bind_to_device(pinfo->fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind udp client socket to device %s\n",server->ifname);
  }

  set_sock_buf_size(pinfo->fd,UR_SERVER_SOCK_BUF_SIZE);
  
  socket_set_reusable(pinfo->fd);

  ioa_addr addr;
  addr_cpy(&addr,&(server->addr));
  addr_set_port(&addr,0);

  if(addr_bind(pinfo->fd,&addr)<0) {
    evutil_closesocket(pinfo->fd);
    pinfo->fd=-1;
    FUNCEND;
    return -1;
  }

  addr_get_from_sock(pinfo->fd, &(pinfo->local_addr));

  addr_debug_print(server->verbose, &addr,"UDP bound to");
  
  evutil_make_socket_nonblocking(pinfo->fd);
  
  app_ur_session* newelem=&(ss->session);

  newelem->input_ev = event_new(server->event_base,pinfo->fd,
			       EV_READ|EV_PERSIST,client_input_handler,server);

  event_add(newelem->input_ev,NULL);

  newelem->state=UR_STATE_READY;

  add_all_to_ur_map_ss(server->client_map,ss);
  
  FUNCEND;

  return 0;
}

int udp_open_client_connection(server_type* server, app_ur_super_session *ss, 
			       ioa_addr *remote_addr) {

  FUNCSTART;

  if(udp_open_client_connection_worker(server, ss, remote_addr)<0) {
    
    FUNCEND;
    return -1;
    
  } else {
      
    app_ur_session* udp_elem=&(ss->session);
    
    if(udp_elem->pinfo.fd>=0) {

      stun_prepare_binding_request(&(udp_elem->in_buffer));

      int len=0;

      ioa_addr stun_i_addr;
      addr_cpy(&stun_i_addr,remote_addr);
      addr_set_port(&stun_i_addr,DEFAULT_STUN_PORT);

      int slen=get_ioa_addr_len(&stun_i_addr);
      
      do {
	len = sendto(udp_elem->pinfo.fd, udp_elem->in_buffer.buf, udp_elem->in_buffer.len, 0, 
		     (struct sockaddr*)&stun_i_addr,(socklen_t)slen);
      } while(len<0 && ((errno==EINTR)||(errno==ENOBUFS)||(errno==EAGAIN)));

      if(server->verbose) {
	addr_debug_print(server->verbose, &stun_i_addr,"To addr:");
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: sent %d bytes\n",__FUNCTION__,len);
      }
	
      if(len>0) {
	udp_elem->state = UR_STATE_WAITING_FOR_VERIFICATION;
      } else {
	perror("send");
	FUNCEND;
	return -1;
      }
    }
  }

  FUNCEND;

  return 0;
}

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

  server->client_map = ur_map_create();

  server->udp_fd=-1;

  udp_create_server_socket(server, ifname, local_address, port);

  return server;
}

static int clean_server(server_type* server) {
  if(server) {
    ur_map_free(&server->client_map);
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
      if((cycle & 15) == 0) {
	if (1 || server->verbose) {
	  int msz=ur_map_size(server->client_map);
	  if(server->verbose) 
	    {
	      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: cycle=%u, msz=%d\n",__FUNCTION__,cycle,msz);
	    }
	}
      }
      
      run_events(server);
    }
  }  
}

void run_server_to(server_type* server, struct timeval *timeout);

void run_server_to(server_type* server, struct timeval *timeout) {

  if(!server) return;
  
  event_base_loopexit(server->event_base, timeout);
  event_base_dispatch(server->event_base);
}

void clean_udp_server(server_type* server) {
  if(server) clean_server(server);
}

//////////////////////////////////////////////////////////////////
