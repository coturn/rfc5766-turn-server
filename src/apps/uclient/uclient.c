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
#include "uclient.h"
#include "startuclient.h"
#include "ns_turn_utils.h"

#include <unistd.h>

static const int verbose_packets=0;

static size_t current_clients_number = 0;

static ev_uint32_t tot_send_messages=0;
static ev_uint32_t tot_recv_messages=0;

static struct event_base* client_event_base=NULL;

static int client_write(app_ur_session *elem);
static int client_shutdown(app_ur_session *elem);

static unsigned int current_time = 0;

static char buffer_to_send[65536]="\0";

#define MAX_CLIENTS (1024)

static app_ur_session* elems[MAX_CLIENTS];

#define SLEEP_INTERVAL (2345)

///////////////////////////////////////////////////////////////////////////////

static unsigned int __turn_getSTime(void) {
  struct timeval tv={0,0};
  evutil_gettimeofday(&tv,NULL);
  return (unsigned int)(tv.tv_sec);
}

////////////////////////////////////////////////////////////////////

static int refresh_channel(app_ur_session* elem);

//////////////////////// SS ////////////////////////////////////////

static app_ur_session* init_app_session(app_ur_session *ss) {
  if(ss) {
    memset(ss,0,sizeof(app_ur_session));
    ss->pinfo.fd=-1;
  }
  return ss;
}

static app_ur_session* create_new_ss(void)
{
	++current_clients_number;
	return init_app_session((app_ur_session*) malloc(sizeof(app_ur_session)));
}

static void uc_delete_session_elem_data(app_ur_session* cdi) {
  if(cdi) {
    EVENT_DEL(cdi->timer_ev);
    EVENT_DEL(cdi->input_ev);
    if(cdi->pinfo.fd>=0) {
      evutil_closesocket(cdi->pinfo.fd);
    }
    cdi->pinfo.fd=-1;
  }
}

static int remove_all_from_ss(app_ur_session* ss)
{
	if (ss) {
		uc_delete_session_elem_data(ss);

		free(ss);
		--current_clients_number;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

int send_buffer(int fd, stun_buffer* message)
{

	int rc = 0;
	do {
		rc = send(fd, message->buf, message->len, 0);
	} while (rc < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));

	if (rc < 0)
		return -1;

	return rc;
}

int recv_buffer(int fd, const ioa_addr *like_addr, stun_buffer* message) {

	int rc = 0;
	int slen = get_ioa_addr_len(like_addr);
	ioa_addr raddr;
	do {
		rc = recvfrom(fd, message->buf, sizeof(message->buf) - 1, 0,
				(struct sockaddr*) &raddr, (socklen_t*) &slen);
	} while (rc < 0 && ((errno == EINTR) || (errno == EAGAIN)));

	if (rc < 0)
		return -1;

	message->len = rc;

	return rc;
}

static int client_read(app_ur_session *elem) {

	if (!elem)
		return -1;

	if (elem->state != UR_STATE_READY)
		return -1;

	elem->ctime = current_time;

	int fd = elem->pinfo.fd;

	int rc = 0;

	if (udp_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before read ...\n");
	}

	rc = recv_buffer(fd, &(elem->pinfo.local_addr), &(elem->in_buffer));

	if (udp_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "read %d bytes\n", (int) rc);
	}

	if (rc >= 0) {

		elem->in_buffer.len = rc;

		uint16_t chnumber = 0;

		if (stun_is_indication(&(elem->in_buffer))) {

			uint16_t method = stun_get_method(&elem->in_buffer);
			if (method != STUN_METHOD_DATA) {
				TURN_LOG_FUNC(
						TURN_LOG_LEVEL_INFO,
						"ERROR: received indication message has wrong method: 0x%x\n",
						(int) method);
				return 0;
			}

			stun_attr_ref sar = stun_attr_get_first_by_type(&(elem->in_buffer),
					STUN_ATTRIBUTE_DATA);
			if (!sar) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"ERROR: received DATA message has no data\n");
				return 0;
			}

			int rlen = stun_attr_get_len(sar);
			if (rlen != clmessage_length) {
				TURN_LOG_FUNC(
						TURN_LOG_LEVEL_INFO,
						"ERROR: received DATA message has wrong len: %d, must be %d\n",
						rlen, clmessage_length);
				return 0;
			}

			const u08bits* data = stun_attr_get_value(sar);

			if (memcmp(data, buffer_to_send, clmessage_length)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"ERROR: received buffer have wrong content\n");
				return 0;
			}

		} else if (stun_is_success_response(&(elem->in_buffer))) {
			return 0;
		} else if (stun_is_error_response(&(elem->in_buffer), NULL,NULL,0)) {
			return 0;
		} else if (stun_is_channel_message(&(elem->in_buffer), &chnumber)) {

			if (elem->chnum != chnumber) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"ERROR: received message has wrong channel: %d\n",
						(int) chnumber);
				return 0;
			}

			if (elem->in_buffer.len >= 0) {
				if (elem->in_buffer.len != clmessage_length + 4) {
					TURN_LOG_FUNC(
							TURN_LOG_LEVEL_INFO,
							"ERROR: received buffer have wrong length: %d, must be %d\n",
							rc, clmessage_length + 4);
					return 0;
				}
				if (memcmp(elem->in_buffer.buf + 4, buffer_to_send,
						clmessage_length)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"ERROR: received buffer have wrong content\n");
					return 0;
				}
			}
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"ERROR: Unknown message received\n");
			return 0;
		}

		elem->rmsgnum += 1;
		elem->wait_cycles = 0;
		tot_recv_messages++;

	} else {

		if (handle_socket_error())
			return 0;

		return -1;
	}

	return 0;
}

static int client_shutdown(app_ur_session *elem) {

  if(!elem) return -1;

  elem->state=UR_STATE_DONE;

  elem->ctime=current_time;
  elems[elem->clnum]=NULL;

  remove_all_from_ss(elem);
  
  if (udp_verbose)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"done, connection 0x%lx closed.\n",(long)elem);
  
  return 0;
}

static int client_write(app_ur_session *elem) {

  if(!elem) return -1;

  if(elem->state!=UR_STATE_READY) return -1;

  elem->ctime=current_time;

  if(!use_send_method) {
    stun_init_channel_message(elem->chnum, &(elem->out_buffer), clmessage_length);
    memcpy(elem->out_buffer.buf+4,buffer_to_send,clmessage_length);
  } else {
    stun_init_indication(STUN_METHOD_SEND, &(elem->out_buffer));
    stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DATA, buffer_to_send, clmessage_length);
    stun_attr_add_addr(&(elem->out_buffer),STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
    if(dont_fragment)
	    stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);
    stun_attr_add_fingerprint_str(elem->out_buffer.buf,(size_t*)&(elem->out_buffer.len));
  }

  if (elem->out_buffer.len > 0) {

    int fd=elem->pinfo.fd;
    
    if (udp_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before write ...\n");
	}

    int rc=send_buffer(fd,&(elem->out_buffer));

    if(rc<0 && handle_socket_error()) return 0;

    elem->wmsgnum--;
    
    if(rc >= 0) {
      if (udp_verbose && verbose_packets) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "wrote %d bytes\n", (int) rc);
	  }
      tot_send_messages++;
    } else {
    	perror("send");
    	return -1;
    }
  }

  return 0;
}

static void client_input_handler(evutil_socket_t fd, short what, void* arg) {

  if(!(what&EV_READ)||!arg) return;

  UNUSED_ARG(fd);

  app_ur_session* elem = arg;
  if(!elem) {
    return;
  }
  
  switch(elem->state) {
  case UR_STATE_SHUTTING_DOWN:
    client_shutdown(elem);
    return;
  case UR_STATE_READY:
    client_read(elem);
    break;
  default:
    ;
  }
}

static void run_events(void) {

  struct timeval timeout;

  timeout.tv_sec=1;
  timeout.tv_usec=0;

  event_base_loopexit(client_event_base, &timeout);
  event_base_dispatch(client_event_base);
}

////////////////////// main method /////////////////

static int start_client(const char *remote_address, int port,
			const unsigned char* ifname, const char *local_address, 
			int messagenumber, 
			int i) {

  app_ur_session* ss=create_new_ss();
  app_ur_session* ss_rtcp=NULL;

  if(!no_rtcp)
    ss_rtcp = create_new_ss();

  app_ur_conn_info *udp_info=&(ss->pinfo);
  app_ur_conn_info *udp_info_rtcp=NULL;

  if(!no_rtcp) 
    udp_info_rtcp = &(ss_rtcp->pinfo);

  uint16_t chnum=0;
  uint16_t chnum_rtcp=0;

  start_connection(port, remote_address, 
		   ifname, local_address, 
		   udp_verbose,
		   udp_info, &chnum,
		   udp_info_rtcp, &chnum_rtcp);
  
  evutil_make_socket_nonblocking(udp_info->fd);
  
  if(!no_rtcp) 
    evutil_make_socket_nonblocking(udp_info_rtcp->fd);
  
  struct event* ev = event_new(client_event_base,udp_info->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss);

  event_add(ev,NULL);
  
  struct event* ev_rtcp = NULL;

  if(!no_rtcp) {
    ev_rtcp = event_new(client_event_base,udp_info_rtcp->fd,
			EV_READ|EV_PERSIST,client_input_handler,
			ss_rtcp);
  
    event_add(ev_rtcp,NULL);
  }
  
  ss->state=UR_STATE_READY;
  
  ss->input_ev=ev;
  ss->tot_msgnum=messagenumber;
  ss->wmsgnum=ss->tot_msgnum;
  ss->rmsgnum=0;
  ss->wait_cycles=0;
  ss->clnum=i;
  ss->chnum=chnum;

  if(!no_rtcp) {

    ss_rtcp->state=UR_STATE_READY;
    
    ss_rtcp->input_ev=ev_rtcp;
    ss_rtcp->tot_msgnum=ss->tot_msgnum;
    if(ss_rtcp->tot_msgnum<1) ss_rtcp->tot_msgnum=1;
    ss_rtcp->wmsgnum=ss_rtcp->tot_msgnum;
    ss_rtcp->rmsgnum=0;
    ss_rtcp->wait_cycles=0;
    ss_rtcp->clnum=i+1;
    ss_rtcp->chnum=chnum_rtcp;
  }
  
  elems[i]=ss;

  refresh_channel(ss);

  if(!no_rtcp)
    elems[i+1]=ss_rtcp;

  return 0;
}

static int start_c2c(const char *remote_address, int port,
			    const unsigned char* ifname, const char *local_address, 
			    int messagenumber, 
			    int i) {

  app_ur_session* ss1=create_new_ss();
  app_ur_session* ss1_rtcp=NULL;

  if(!no_rtcp)
    ss1_rtcp = create_new_ss();

  app_ur_session* ss2=create_new_ss();
  app_ur_session* ss2_rtcp=NULL;

  if(!no_rtcp)
    ss2_rtcp = create_new_ss();

  app_ur_conn_info *udp_info1=&(ss1->pinfo);
  app_ur_conn_info *udp_info1_rtcp=NULL;

  if(!no_rtcp)
    udp_info1_rtcp = &(ss1_rtcp->pinfo);

  app_ur_conn_info *udp_info2=&(ss2->pinfo);
  app_ur_conn_info *udp_info2_rtcp=NULL;

  if(!no_rtcp)
    udp_info2_rtcp = &(ss2_rtcp->pinfo);

  uint16_t chnum1=0;
  uint16_t chnum1_rtcp=0;
  uint16_t chnum2=0;
  uint16_t chnum2_rtcp=0;

  start_c2c_connection(port, remote_address, 
		       ifname, local_address, 
		       udp_verbose,
		       udp_info1, &chnum1,
		       udp_info1_rtcp, &chnum1_rtcp,
		       udp_info2, &chnum2,
		       udp_info2_rtcp, &chnum2_rtcp);
  
  evutil_make_socket_nonblocking(udp_info1->fd);
  
  if(!no_rtcp)
    evutil_make_socket_nonblocking(udp_info1_rtcp->fd);
  
  evutil_make_socket_nonblocking(udp_info2->fd);
  
  if(!no_rtcp)
    evutil_make_socket_nonblocking(udp_info2_rtcp->fd);
  
  struct event* ev1 = event_new(client_event_base,udp_info1->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss1);

  event_add(ev1,NULL);
  
  struct event* ev1_rtcp = NULL;

  if(!no_rtcp) {
    ev1_rtcp = event_new(client_event_base,udp_info1_rtcp->fd,
			 EV_READ|EV_PERSIST,client_input_handler,
			 ss1_rtcp);
    
    event_add(ev1_rtcp,NULL);
  }

  struct event* ev2 = event_new(client_event_base,udp_info2->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss2);

  event_add(ev2,NULL);
  
  struct event* ev2_rtcp = NULL;

  if(!no_rtcp) {
    ev2_rtcp = event_new(client_event_base,udp_info2_rtcp->fd,
			 EV_READ|EV_PERSIST,client_input_handler,
			 ss2_rtcp);
    
    event_add(ev2_rtcp,NULL);
  }

  ss1->state=UR_STATE_READY;
  
  ss1->input_ev=ev1;
  ss1->tot_msgnum=messagenumber;
  ss1->wmsgnum=ss1->tot_msgnum;
  ss1->rmsgnum=0;
  ss1->wait_cycles=0;
  ss1->clnum=i;
  ss1->chnum=chnum1;

  if(!no_rtcp) {

    ss1_rtcp->state=UR_STATE_READY;
    
    ss1_rtcp->input_ev=ev1_rtcp;
    ss1_rtcp->tot_msgnum=ss1->tot_msgnum;
    if(ss1_rtcp->tot_msgnum<1) ss1_rtcp->tot_msgnum=1;
    ss1_rtcp->wmsgnum=ss1_rtcp->tot_msgnum;
    ss1_rtcp->rmsgnum=0;
    ss1_rtcp->wait_cycles=0;
    ss1_rtcp->clnum=i+1;
    ss1_rtcp->chnum=chnum1_rtcp;
  }

  ss2->state=UR_STATE_READY;
  
  ss2->input_ev=ev2;
  ss2->tot_msgnum=ss1->tot_msgnum;
  ss2->wmsgnum=ss2->tot_msgnum;
  ss2->rmsgnum=0;
  ss2->wait_cycles=0;
  ss2->clnum=i+2;
  ss2->chnum=chnum2;


  if(!no_rtcp) {
    ss2_rtcp->state=UR_STATE_READY;
  
    ss2_rtcp->input_ev=ev2_rtcp;
    ss2_rtcp->tot_msgnum=ss1_rtcp->tot_msgnum;
    ss2_rtcp->wmsgnum=ss2_rtcp->tot_msgnum;
    ss2_rtcp->rmsgnum=0;
    ss2_rtcp->wait_cycles=0;
    ss2_rtcp->clnum=i+3;
    ss2_rtcp->chnum=chnum2_rtcp;
  }
  
  elems[i++]=ss1;
  if(!no_rtcp)
    elems[i++]=ss1_rtcp;
  elems[i++]=ss2;
  if(!no_rtcp)
    elems[i++]=ss2_rtcp;

  return 0;
}

static int refresh_channel(app_ur_session* elem) {

  stun_buffer message;

  {
    stun_init_request(STUN_METHOD_REFRESH, &message);
    uint32_t lt=htonl(600);
    stun_attr_add(&message, STUN_ATTRIBUTE_LIFETIME, (const char*)&lt, 4);
    stun_attr_add_fingerprint_str(message.buf,(size_t*)&(message.len));
    send_buffer(elem->pinfo.fd, &message);
  }

  if(!addr_any(&(elem->pinfo.peer_addr))) {

    {
      stun_init_request(STUN_METHOD_CREATE_PERMISSION,&message);
      stun_attr_add_addr(&message,STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
      stun_attr_add_fingerprint_str(message.buf,(size_t*)&(message.len));
      send_buffer(elem->pinfo.fd, &message);
    }

    if(STUN_VALID_CHANNEL(elem->chnum)) {
      stun_set_channel_bind_request(&message,&(elem->pinfo.peer_addr),elem->chnum);
      stun_attr_add_fingerprint_str(message.buf,(size_t*)&(message.len));
      send_buffer(elem->pinfo.fd, &message);
    }
  }

  return 0;
}

static void client_timer_handler(evutil_socket_t fd, short what, void* arg) {

  fd=what;

  if(!arg) return;
  app_ur_session* elem = (app_ur_session*)arg;

  if(((elem->timer_cycle++) & (4096-1)) == (4096-1)) {
    refresh_channel(elem);
  }

  if(elem->wmsgnum<1) {
    ++(elem->wait_cycles);
    if((elem->wait_cycles>50) || (elem->tot_msgnum-elem->rmsgnum)<1) {
      //TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: 111.111: c=%d, w=%d, r=%d\n",__FUNCTION__,elem->wait_cycles,elem->tot_msgnum,elem->rmsgnum);
      if(!hang_on)
	client_shutdown(elem);
    }
  } else {
    client_write(elem);
  }
}

void start_mclient(const char *remote_address, int port,
		const unsigned char* ifname, const char *local_address, int length,
		int messagenumber, int mclient) {

	//sleep(20);

	if (mclient < 1)
		mclient = 1;

	if(c2c) {
	  //mclient must be a multiple of 4:
	  if(!no_rtcp)
	    mclient += ((4 - (mclient & 0x00000003)) & 0x00000003);
	  else if(mclient & 0x1)
	    ++mclient;
	} else {
	  if(!no_rtcp)
	    if(mclient & 0x1)
	      ++mclient;
	}

	unsigned int stime = __turn_getSTime();
	current_time = __turn_getSTime();

	if (length >= (int) sizeof(int)) {
		memset(buffer_to_send, random(), length);
	}

	clmessage_length = length;

	client_event_base = event_base_new();

	int i = 0;
	int tot_clients = 0;

	if(c2c) {
	  if(!no_rtcp)
	    for (i = 0; i < (mclient >> 2); i++) {
	      usleep(SLEEP_INTERVAL);
	      if (start_c2c(remote_address, port, ifname, local_address,
			    messagenumber, i << 2) < 0) {
		exit(-1);
	      }
	      tot_clients+=4;
	    }
	  else
	    for (i = 0; i < (mclient >> 1); i++) {
	      usleep(SLEEP_INTERVAL);
	      if (start_c2c(remote_address, port, ifname, local_address,
			    messagenumber, i << 1) < 0) {
		exit(-1);
	      }
	      tot_clients+=2;
	    }
	} else {
	  if(!no_rtcp)
	    for (i = 0; i < (mclient >> 1); i++) {
	      usleep(SLEEP_INTERVAL);
	      if (start_client(remote_address, port, ifname, local_address,
			       messagenumber, i << 1) < 0) {
		exit(-1);
	      }
	      tot_clients+=2;
	    }
	  else 
	    for (i = 0; i < mclient; i++) {
	      usleep(SLEEP_INTERVAL);
	      if (start_client(remote_address, port, ifname, local_address,
			       messagenumber, i) < 0) {
		exit(-1);
	      }
	      tot_clients++;
	    }
	}

	for (i = 0; i < tot_clients; i++) {

		usleep(SLEEP_INTERVAL);

		int chn = i;

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 20 * 1000;
		elems[chn]->timer_ev = event_new(client_event_base, -1, EV_TIMEOUT
				| EV_PERSIST, client_timer_handler, elems[chn]);
		event_add(elems[chn]->timer_ev, &tv);

		if (udp_verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Connection 0x%lx open\n",
					(long) (elems[chn]));
		}
	}

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total connect time is %u\n",
			((unsigned int) __turn_getSTime() - stime));

	stime = __turn_getSTime();

	static ev_uint32_t prev_tot_send_messages = 0;
	static ev_uint32_t prev_tot_recv_messages = 0;

	while (1) {

		current_time = __turn_getSTime();

		run_events();

		int msz = (int)current_clients_number;
		if (msz < 1) {
			break;
		}

		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"%s: msz=%d, tot_send_messages=%lu, tot_recv_messages=%lu\n",
				__FUNCTION__, msz, (unsigned long) tot_send_messages,
				(unsigned long) tot_recv_messages);

		prev_tot_send_messages = tot_send_messages;
		prev_tot_recv_messages = tot_recv_messages;
	}

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
			"%s: tot_send_messages=%lu, tot_recv_messages=%lu\n", __FUNCTION__,
			(unsigned long) tot_send_messages,
			(unsigned long) tot_recv_messages);

	if (client_event_base)
		event_base_free(client_event_base);

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total transmit time is %u\n",
			((unsigned int) __turn_getSTime() - stime));
}


