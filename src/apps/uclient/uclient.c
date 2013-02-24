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
#include "uclient.h"
#include "startuclient.h"
#include "ns_turn_utils.h"
#include "session.h"

#include <unistd.h>
#include <time.h>

#include <openssl/err.h>

static const int verbose_packets=0;

static size_t current_clients_number = 0;

static u32bits tot_send_messages=0;
static u32bits tot_recv_messages=0;

static struct event_base* client_event_base=NULL;

static int client_write(app_ur_session *elem);
static int client_shutdown(app_ur_session *elem);

static u64bits current_time = 0;
static u64bits current_mstime = 0;

static char buffer_to_send[65536]="\0";

#define MAX_CLIENTS (1024)
static int total_clients = 0;

static app_ur_session* elems[MAX_CLIENTS];

#define SLEEP_INTERVAL (2345)

int RTP_PACKET_INTERVAL = 20;

static inline s64bits time_minus(u64bits t1, u64bits t2) {
	return ( (s64bits)t1 - (s64bits)t2 );
}

static u64bits total_loss = 0;
static u64bits total_jitter = 0;
static u64bits total_latency = 0;

static u64bits min_latency = 0xFFFFFFFF;
static u64bits max_latency = 0;
static u64bits min_jitter = 0xFFFFFFFF;
static u64bits max_jitter = 0;


static int show_statistics = 0;

///////////////////////////////////////////////////////////////////////////////

static void __turn_getMSTime(void) {
  static u64bits start_sec = 0;
  struct timespec tp={0,0};
#if defined(CLOCK_REALTIME)
  clock_gettime(CLOCK_REALTIME, &tp);
#else
  tp.tv_sec = time(NULL);
#endif
  if(!start_sec)
    start_sec = tp.tv_sec;
  if(current_time != (u64bits)((u64bits)(tp.tv_sec)-start_sec))
    show_statistics = 1;
  current_time = (u64bits)((u64bits)(tp.tv_sec)-start_sec);
  current_mstime = (u64bits)((current_time * 1000) + (tp.tv_nsec/1000000));
}

////////////////////////////////////////////////////////////////////

static int refresh_channel(app_ur_session* elem, u16bits method);

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
    EVENT_DEL(cdi->input_ev);
    if(cdi->pinfo.ssl && !(cdi->pinfo.broken)) {
	    if(!(SSL_get_shutdown(cdi->pinfo.ssl) & SSL_SENT_SHUTDOWN)) {
		    SSL_set_shutdown(cdi->pinfo.ssl, SSL_RECEIVED_SHUTDOWN);
		    SSL_shutdown(cdi->pinfo.ssl);
	    }
    }
    if(cdi->pinfo.fd>=0) {
      evutil_closesocket(cdi->pinfo.fd);
    }
    cdi->pinfo.fd=-1;
    if(cdi->pinfo.ssl) {
	    SSL_free(cdi->pinfo.ssl);
	    cdi->pinfo.ssl = NULL;
    }
  }
}

static int remove_all_from_ss(app_ur_session* ss)
{
	if (ss) {
		uc_delete_session_elem_data(ss);

		--current_clients_number;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer* message)
{

	int rc = 0;
	int ret = -1;

	char *buffer = (char*) (message->buf);

	if (clnet_info->ssl) {

		int message_sent = 0;
		while (!message_sent) {

			if (SSL_get_shutdown(clnet_info->ssl)) {
				return -1;
			}

			int len = 0;
			do {
				len = SSL_write(clnet_info->ssl, buffer, message->len);
			} while (len < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));

			if(len == message->len) {
				if (clnet_verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"buffer sent: size=%d\n",len);
				}

				message_sent = 1;
				ret = len;
			} else {
				switch (SSL_get_error(clnet_info->ssl, len)){
				case SSL_ERROR_NONE:
					/* Try again ? */
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Just try again later */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* Try again */
					break;
				case SSL_ERROR_SYSCALL:
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Socket write error 111.666: \n");
					if (handle_socket_error())
						break;
				case SSL_ERROR_SSL:
				{
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: \n");
					char buf[1024];
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"%s (%d)\n",
						ERR_error_string(ERR_get_error(),buf),
						SSL_get_error(clnet_info->ssl, len));
				}
				default:
					clnet_info->broken = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Unexpected error while writing!\n");
					return -1;
				}
			}
		}

	} else if (clnet_info->fd >= 0) {

		size_t left = (size_t) (message->len);

		while (left > 0) {
			do {
				rc = send(clnet_info->fd, buffer, left, 0);
			} while (rc < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno
							== EAGAIN)));
			if (rc > 0) {
				left -= (size_t) rc;
				buffer += rc;
			} else {
				break;
			}
		}

		if (left > 0)
			return -1;

		ret = (int) message->len;
	}

	return ret;
}

int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer* message) {

	int rc = 0;

	if(!use_secure && !use_tcp && clnet_info->fd>=0) {

		/* Plain UDP */

		do {
			rc = recv(clnet_info->fd, message->buf, sizeof(message->buf) - 1, 0);
		} while (rc < 0 && ((errno == EINTR) || (errno == EAGAIN)));

		if (rc < 0)
			return -1;

		message->len = rc;

	} else if(use_secure && clnet_info->ssl && !(clnet_info->broken)) {

		/* TLS/DTLS */

		int message_received = 0;
		while (!message_received) {

			if (SSL_get_shutdown(clnet_info->ssl))
				return -1;

			rc = 0;
			do {
				rc = SSL_read(clnet_info->ssl, message->buf,
								sizeof(message->buf) - 1);
			} while (rc < 0 && ((errno == EINTR) || (errno == EAGAIN)));

			if (rc > 0) {

				if (clnet_verbose) {
					TURN_LOG_FUNC(
									TURN_LOG_LEVEL_INFO,
									"response received: size=%d\n",
									rc);
				}
				message->len = rc;
				message_received = 1;

			} else {

				int sslerr = SSL_get_error(clnet_info->ssl, rc);

				switch (sslerr){
				case SSL_ERROR_NONE:
					/* Try again ? */
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Just try again later */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* Try again */
					break;
				case SSL_ERROR_SYSCALL:
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"Socket read error 111.999: \n");
					if (handle_socket_error())
						break;
				case SSL_ERROR_SSL:
				{
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"SSL write error: \n");
					char buf[1024];
					TURN_LOG_FUNC(
									TURN_LOG_LEVEL_INFO,
									"%s (%d)\n",
									ERR_error_string(
													ERR_get_error(),
													buf),
									SSL_get_error(
													clnet_info->ssl,
													rc));
				}
				default:
					clnet_info->broken = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"Unexpected error while reading: rc=%d, sslerr=%d\n",rc,sslerr);
					return -1;
				}
			}
		}

	} else if(!use_secure && use_tcp && clnet_info->fd>=0){

		/* Plain TCP */

		do {
			rc = recv(clnet_info->fd, message->buf, sizeof(message->buf) - 1, MSG_PEEK);
		} while (rc < 0 && ((errno == EINTR) || (errno == EAGAIN)));
		if(rc>0) {
			int mlen = stun_get_message_len_str(message->buf, rc);
			if(mlen>0 && mlen<=rc) {
				do {
					rc = recv(clnet_info->fd, message->buf, (size_t)mlen, 0);
				} while (rc < 0 && ((errno == EINTR) || (errno == EAGAIN)));

				if (rc < 0)
					return -1;

				message->len = rc;
			} else {
				rc = 0;
			}
		}
	}

	return rc;
}

static int client_read(app_ur_session *elem) {

	if (!elem)
		return -1;

	if (elem->state != UR_STATE_READY)
		return -1;

	elem->ctime = current_time;

	app_ur_conn_info *clnet_info = &(elem->pinfo);
	int err_code = 0;
	u08bits err_msg[129];
	int rc = 0;

	if (clnet_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before read ...\n");
	}

	rc = recv_buffer(clnet_info, &(elem->in_buffer));

	if (clnet_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "read %d bytes\n", (int) rc);
	}

	if (rc > 0) {

		elem->in_buffer.len = rc;

		uint16_t chnumber = 0;

		const message_info *mi = NULL;

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
						"ERROR: received DATA message has no data, size=%d\n",rc);
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

			mi = (const message_info*)data;

		} else if (stun_is_success_response(&(elem->in_buffer))) {
			return 0;
		} else if (stun_is_challenge_response_str(elem->in_buffer.buf, (size_t)elem->in_buffer.len,
							&err_code,err_msg,sizeof(err_msg),
							clnet_info->realm,clnet_info->nonce)) {
			return refresh_channel(elem, stun_get_method(&elem->in_buffer));
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

				mi = (message_info*)(elem->in_buffer.buf + 4);
			}
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"ERROR: Unknown message received of size: %d\n",(int)(elem->in_buffer.len));
			return 0;
		}

		if(mi) {
			/*
			printf("%s: 111.111: msgnum=%d, rmsgnum=%d, sent=%lu, recv=%lu\n",__FUNCTION__,
				mi->msgnum,elem->recvmsgnum,(unsigned long)mi->mstime,(unsigned long)current_mstime);
				*/
			if(mi->msgnum != elem->recvmsgnum+1)
				++(elem->loss);
			else {
			  u64bits clatency = (u64bits)time_minus(current_mstime,mi->mstime);
			  if(clatency>max_latency)
			    max_latency = clatency;
			  if(clatency<min_latency)
			    min_latency = clatency;
			  elem->latency += clatency;
			  if(elem->rmsgnum>0) {
			    u64bits cjitter = abs((int)(current_mstime-elem->recvtimems)-RTP_PACKET_INTERVAL);
			    
			    if(cjitter>max_jitter)
			      max_jitter = cjitter;
			    if(cjitter<min_jitter)
			      min_jitter = cjitter;
			    
			    elem->jitter += cjitter;
			  }
			}

			elem->recvmsgnum = mi->msgnum;
		}

		++elem->rmsgnum;
		++tot_recv_messages;
		elem->recvtimems=current_mstime;
		elem->wait_cycles = 0;

	} else if(rc == 0) {
		return 0;
	} else {
		return -1;
	}

	return 0;
}

static int client_shutdown(app_ur_session *elem) {

  if(!elem) return -1;

  elem->state=UR_STATE_DONE;

  elem->ctime=current_time;

  remove_all_from_ss(elem);
  
  if (clnet_verbose)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"done, connection 0x%lx closed.\n",(long)elem);
  
  return 0;
}

static int client_write(app_ur_session *elem) {

  if(!elem) return -1;

  if(elem->state!=UR_STATE_READY) return -1;

  elem->ctime=current_time;

  message_info *mi = (message_info*)buffer_to_send;
  mi->msgnum=elem->wmsgnum;
  mi->mstime=current_mstime;

  if(!use_send_method) {
    stun_init_channel_message(elem->chnum, &(elem->out_buffer), clmessage_length);
    memcpy(elem->out_buffer.buf+4,buffer_to_send,clmessage_length);
  } else {
    stun_init_indication(STUN_METHOD_SEND, &(elem->out_buffer));
    stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DATA, buffer_to_send, clmessage_length);
    stun_attr_add_addr(&(elem->out_buffer),STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
    if(dont_fragment)
	    stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);
    if(use_fingerprints)
	    stun_attr_add_fingerprint_str(elem->out_buffer.buf,(size_t*)&(elem->out_buffer.len));
  }

  if (elem->out_buffer.len > 0) {
    
    if (clnet_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before write ...\n");
    }

    int rc=send_buffer(&(elem->pinfo),&(elem->out_buffer));

    ++elem->wmsgnum;
    elem->to_send_timems += RTP_PACKET_INTERVAL;
    
    if(rc >= 0) {
      if (clnet_verbose && verbose_packets) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "wrote %d bytes\n", (int) rc);
	  }
      tot_send_messages++;
    } else {
    	return -1;
    }
  }

  return 0;
}

static void client_input_handler(evutil_socket_t fd, short what, void* arg) {

  if(!(what&EV_READ)||!arg) return;

  UNUSED_ARG(fd);

  app_ur_session* elem = (app_ur_session*)arg;
  if(!elem) {
    return;
  }
  
  switch(elem->state) {
  case UR_STATE_READY:
    client_read(elem);
    break;
  default:
    ;
  }
}

static void run_events(void) {
	event_base_loop(client_event_base,EVLOOP_NONBLOCK);
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

  app_ur_conn_info *clnet_info=&(ss->pinfo);
  app_ur_conn_info *clnet_info_rtcp=NULL;

  if(!no_rtcp) 
    clnet_info_rtcp = &(ss_rtcp->pinfo);

  uint16_t chnum=0;
  uint16_t chnum_rtcp=0;

  start_connection(port, remote_address, 
		   ifname, local_address, 
		   clnet_verbose,
		   clnet_info, &chnum,
		   clnet_info_rtcp, &chnum_rtcp);
  
  evutil_make_socket_nonblocking(clnet_info->fd);
  
  if(!no_rtcp) 
    evutil_make_socket_nonblocking(clnet_info_rtcp->fd);
  
  struct event* ev = event_new(client_event_base,clnet_info->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss);

  event_add(ev,NULL);
  
  struct event* ev_rtcp = NULL;

  if(!no_rtcp) {
    ev_rtcp = event_new(client_event_base,clnet_info_rtcp->fd,
			EV_READ|EV_PERSIST,client_input_handler,
			ss_rtcp);
  
    event_add(ev_rtcp,NULL);
  }
  
  ss->state=UR_STATE_READY;
  
  ss->input_ev=ev;
  ss->tot_msgnum=messagenumber;
  ss->recvmsgnum=-1;
  ss->chnum=chnum;

  if(!no_rtcp) {

    ss_rtcp->state=UR_STATE_READY;
    
    ss_rtcp->input_ev=ev_rtcp;
    ss_rtcp->tot_msgnum=ss->tot_msgnum;
    if(ss_rtcp->tot_msgnum<1) ss_rtcp->tot_msgnum=1;
    ss_rtcp->recvmsgnum=-1;
    ss_rtcp->chnum=chnum_rtcp;
  }
  
  elems[i]=ss;

  refresh_channel(ss,0);

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

  app_ur_conn_info *clnet_info1=&(ss1->pinfo);
  app_ur_conn_info *clnet_info1_rtcp=NULL;

  if(!no_rtcp)
    clnet_info1_rtcp = &(ss1_rtcp->pinfo);

  app_ur_conn_info *clnet_info2=&(ss2->pinfo);
  app_ur_conn_info *clnet_info2_rtcp=NULL;

  if(!no_rtcp)
    clnet_info2_rtcp = &(ss2_rtcp->pinfo);

  uint16_t chnum1=0;
  uint16_t chnum1_rtcp=0;
  uint16_t chnum2=0;
  uint16_t chnum2_rtcp=0;

  start_c2c_connection(port, remote_address, 
		       ifname, local_address, 
		       clnet_verbose,
		       clnet_info1, &chnum1,
		       clnet_info1_rtcp, &chnum1_rtcp,
		       clnet_info2, &chnum2,
		       clnet_info2_rtcp, &chnum2_rtcp);
  
  evutil_make_socket_nonblocking(clnet_info1->fd);
  
  if(!no_rtcp)
    evutil_make_socket_nonblocking(clnet_info1_rtcp->fd);
  
  evutil_make_socket_nonblocking(clnet_info2->fd);
  
  if(!no_rtcp)
    evutil_make_socket_nonblocking(clnet_info2_rtcp->fd);
  
  struct event* ev1 = event_new(client_event_base,clnet_info1->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss1);

  event_add(ev1,NULL);
  
  struct event* ev1_rtcp = NULL;

  if(!no_rtcp) {
    ev1_rtcp = event_new(client_event_base,clnet_info1_rtcp->fd,
			 EV_READ|EV_PERSIST,client_input_handler,
			 ss1_rtcp);
    
    event_add(ev1_rtcp,NULL);
  }

  struct event* ev2 = event_new(client_event_base,clnet_info2->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss2);

  event_add(ev2,NULL);
  
  struct event* ev2_rtcp = NULL;

  if(!no_rtcp) {
    ev2_rtcp = event_new(client_event_base,clnet_info2_rtcp->fd,
			 EV_READ|EV_PERSIST,client_input_handler,
			 ss2_rtcp);
    
    event_add(ev2_rtcp,NULL);
  }

  ss1->state=UR_STATE_READY;
  
  ss1->input_ev=ev1;
  ss1->tot_msgnum=messagenumber;
  ss1->recvmsgnum=-1;
  ss1->chnum=chnum1;

  if(!no_rtcp) {

    ss1_rtcp->state=UR_STATE_READY;
    
    ss1_rtcp->input_ev=ev1_rtcp;
    ss1_rtcp->tot_msgnum=ss1->tot_msgnum;
    if(ss1_rtcp->tot_msgnum<1) ss1_rtcp->tot_msgnum=1;
    ss1_rtcp->recvmsgnum=-1;
    ss1_rtcp->chnum=chnum1_rtcp;
  }

  ss2->state=UR_STATE_READY;
  
  ss2->input_ev=ev2;
  ss2->tot_msgnum=ss1->tot_msgnum;
  ss2->recvmsgnum=-1;
  ss2->chnum=chnum2;


  if(!no_rtcp) {
    ss2_rtcp->state=UR_STATE_READY;
  
    ss2_rtcp->input_ev=ev2_rtcp;
    ss2_rtcp->tot_msgnum=ss1_rtcp->tot_msgnum;
    ss2_rtcp->recvmsgnum=-1;
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

static int refresh_channel(app_ur_session* elem, u16bits method)
{

	stun_buffer message;
	app_ur_conn_info *clnet_info = &(elem->pinfo);

	if (!method || (method == STUN_METHOD_REFRESH)) {
		stun_init_request(STUN_METHOD_REFRESH, &message);
		uint32_t lt = htonl(600);
		stun_attr_add(&message, STUN_ATTRIBUTE_LIFETIME, (const char*) &lt, 4);
		if (clnet_info->nonce[0]) {
			if (stun_attr_add_integrity_by_user_str(message.buf, (size_t*) &(message.len), g_uname,
							clnet_info->realm, g_upwd, clnet_info->nonce) < 0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, " Cannot add integrity to the message\n");
				return -1;
			}
		}
		if(use_fingerprints)
			    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
		send_buffer(clnet_info, &message);
	}

	if (!addr_any(&(elem->pinfo.peer_addr))) {

		if (!method || (method == STUN_METHOD_CREATE_PERMISSION)) {
			stun_init_request(STUN_METHOD_CREATE_PERMISSION, &message);
			stun_attr_add_addr(&message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
			if (clnet_info->nonce[0]) {
				if (stun_attr_add_integrity_by_user_str(message.buf, (size_t*) &(message.len), g_uname,
								clnet_info->realm, g_upwd, clnet_info->nonce) < 0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, " Cannot add integrity to the message\n");
					return -1;
				}
			}
			if(use_fingerprints)
				    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
			send_buffer(&(elem->pinfo), &message);
		}

		if (!method || (method == STUN_METHOD_CHANNEL_BIND)) {
			if (STUN_VALID_CHANNEL(elem->chnum)) {
				stun_set_channel_bind_request(&message, &(elem->pinfo.peer_addr), elem->chnum);
				if (clnet_info->nonce[0]) {
					if (stun_attr_add_integrity_by_user_str(message.buf, (size_t*) &(message.len),
									g_uname, clnet_info->realm, g_upwd,
									clnet_info->nonce) < 0) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										" Cannot add integrity to the message\n");
						return -1;
					}
				}
				if(use_fingerprints)
					    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
				send_buffer(&(elem->pinfo), &message);
			}
		}
	}

	elem->refresh_time = current_mstime + 30*1000;

	return 0;
}

static inline int client_timer_handler(app_ur_session* elem)
{

	if (elem) {

		if (!turn_time_before(current_mstime, elem->refresh_time)) {
			refresh_channel(elem, 0);
		}

		if (!turn_time_before(current_mstime, elem->to_send_timems)) {

			if (elem->wmsgnum >= elem->tot_msgnum) {
				if (!turn_time_before(current_mstime, elem->finished_time) ||
					(elem->tot_msgnum - elem->rmsgnum) < 1) {
					/*
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: elem=0x%x: 111.111: c=%d, t=%d, r=%d, w=%d\n",__FUNCTION__,(int)elem,elem->wait_cycles,elem->tot_msgnum,elem->rmsgnum,elem->wmsgnum);
					*/
					/*
					 TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: 111.222: ly=%llu, ls=%llu, j=%llu\n",__FUNCTION__,
					 (unsigned long long)elem->latency,
					 (unsigned long long)elem->loss,
					 (unsigned long long)elem->jitter);
					*/
					total_loss += elem->loss;
					elem->loss=0;
					total_latency += elem->latency;
					elem->latency=0;
					total_jitter += elem->jitter;
					elem->jitter=0;
					if (!hang_on)
						client_shutdown(elem);
					return 1;
				}
			} else {
				client_write(elem);
				elem->finished_time = current_mstime + 1*1000;
			}
		}
	}

	return 0;
}

static void timer_handler(void)
{

	int i = 0;

	__turn_getMSTime();

	for (i = 0; i < total_clients; ++i) {
	  int finished = client_timer_handler(elems[i]);
	  if(finished) {
		  elems[i]=NULL;
	  }
	}
}

void start_mclient(const char *remote_address, int port,
		const unsigned char* ifname, const char *local_address,
		int messagenumber, int mclient) {

	if (mclient < 1)
		mclient = 1;

	total_clients = mclient;

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

	__turn_getMSTime();
	u32bits stime = current_time;

	memset(buffer_to_send, random(), clmessage_length);

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

	total_clients = tot_clients;

	for(i=0;i<total_clients;i++) {
		__turn_getMSTime();
		elems[i]->to_send_timems = current_mstime + ((u32bits)random())%500;
	}

	__turn_getMSTime();

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total connect time is %u\n",
			((unsigned int) (current_time - stime)));

	stime = current_time;

	while (1) {

		timer_handler();
		run_events();

		int msz = (int)current_clients_number;
		if (msz < 1) {
			break;
		}

		if(show_statistics) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				      "%s: msz=%d, tot_send_messages=%lu, tot_recv_messages=%lu\n",
				      __FUNCTION__, msz, (unsigned long) tot_send_messages,
				      (unsigned long) tot_recv_messages);
			show_statistics=0;
		}
	}

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
		      "%s: tot_send_messages=%lu, tot_recv_messages=%lu\n", 
		      __FUNCTION__,
		      (unsigned long) tot_send_messages,
		      (unsigned long) tot_recv_messages);

	if (client_event_base)
		event_base_free(client_event_base);

	if(tot_send_messages<tot_recv_messages)
		tot_recv_messages=tot_send_messages;

	total_loss = tot_send_messages-tot_recv_messages;

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total transmit time is %u\n",
			((unsigned int)(current_time - stime)));
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total lost packets %llu (%f%c)\n",
				(unsigned long long)total_loss, (((double)total_loss/(double)tot_send_messages)*100.00),'%');
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Average round trip delay %f ms; min = %lu ms, max = %lu ms\n",
				((double)total_latency/(double)((tot_recv_messages<1) ? 1 : tot_recv_messages)),
				(unsigned long)min_latency,
				(unsigned long)max_latency);
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Average jitter %f ms; min = %lu ms, max = %lu ms\n",
				((double)total_jitter/(double)tot_recv_messages),
				(unsigned long)min_jitter,
				(unsigned long)max_jitter);
}


