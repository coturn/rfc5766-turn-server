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

#include "ns_turn_utils.h"
#include "ns_turn_session.h"
#include "ns_turn_server.h"

#include "stun_buffer.h"
#include "apputils.h"

#include "ns_ioalib_impl.h"

#include <pthread.h>

#include <event2/bufferevent_ssl.h>

/************** Forward function declarations ******/

static void socket_input_handler(evutil_socket_t fd, short what, void* arg);
static void socket_input_handler_bev(struct bufferevent *bev, void* arg);
static void eventcb_bev(struct bufferevent *bev, short events, void *arg);

/************** Utils **************************/

#if !defined(min)
#define min(a,b) ((a)<=(b) ? (a) : (b))
#endif

int set_df_on_ioa_socket(ioa_socket_handle s, int value)
{
	if (s->do_not_use_df)
		value = 0;

	if (s->current_df_relay_flag != value) {
		s->current_df_relay_flag = value;
		return set_socket_df(s->fd, s->family, value);
	}

	return 0;
}

void set_do_not_use_df(ioa_socket_handle s)
{
	s->do_not_use_df = 1;
	s->current_df_relay_flag = 1;
	set_socket_df(s->fd, s->family, 0);
}

/************** Buffer List ********************/

static stun_buffer_list_elem *new_blist_elem(ioa_engine_handle e)
{
	stun_buffer_list_elem *ret = NULL;

	if(e && e->bufs) {
		ret=e->bufs;
		e->bufs=ret->next;
	} else {
		ret = malloc(sizeof(stun_buffer_list_elem));
	}

	ret->next=NULL;
	ret->tsz=0;

	return ret;
}

static void free_blist_elem(ioa_engine_handle e, stun_buffer_list_elem *elem)
{
	if(elem) {
		if(e) {
			if(e->bufs) {
				if(e->bufs->tsz<MAX_BUFFER_QUEUE_SIZE_PER_ENGINE) {
					elem->next = e->bufs;
					e->bufs = elem;
					elem->tsz = elem->next->tsz + 1;
				} else {
					free(elem);
				}
			} else {
				e->bufs=elem;
				elem->tsz = 0;
				elem->next= NULL;
			}
		} else {
			free(elem);
		}
	}
}

/************** ENGINE *************************/

ioa_engine_handle create_ioa_engine(struct event_base *eb, turnipports *tp, const s08bits* relay_ifname,
				size_t relays_number, s08bits **relay_addrs, int verbose)
{

	if (!relays_number || !relay_addrs || !tp) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create TURN engine\n", __FUNCTION__);
		return NULL;
	} else {
		ioa_engine_handle e = malloc(sizeof(ioa_engine));
		ns_bzero(e,sizeof(ioa_engine));
		e->verbose = verbose;
		e->tp = tp;
		if (eb) {
			e->event_base = eb;
			e->deallocate_eb = 0;
		} else {
			e->event_base = event_base_new();
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (engine own thread): %s\n",event_base_get_method(e->event_base));
			e->deallocate_eb = 1;
		}
		if (relay_ifname)
			strncpy(e->relay_ifname, relay_ifname, sizeof(e->relay_ifname) - 1);
		if (relay_addrs) {
			size_t i = 0;
			e->relay_addrs = malloc(relays_number * sizeof(ioa_addr));
			for (i = 0; i < relays_number; i++)
				make_ioa_addr((u08bits*) relay_addrs[i], 0, &(e->relay_addrs[i]));
			e->relays_number = relays_number;
		}
		e->relay_addr_counter = (size_t) random() % relays_number;
		return e;
	}
}

void set_ssl_ctx(ioa_engine_handle e, SSL_CTX *ctx)
{
	e->tls_ctx = ctx;
}

void close_ioa_engine(ioa_engine_handle e)
{
	if (e) {
	  if (e->deallocate_eb && e->event_base)
	    event_base_free(e->event_base);

	  stun_buffer_list_elem *elem=e->bufs;
	  while(elem) {
		  stun_buffer_list_elem *next=elem->next;
		  free(elem);
		  elem=next;
	  }

	  if(e->relay_addrs)
		  free(e->relay_addrs);

	  free(e);
	}
}

void ioa_engine_set_rtcp_map(ioa_engine_handle e, rtcp_map *rtcpmap)
{
	if(e)
		e->rtcp_map = rtcpmap;
}

int register_callback_on_ioa_engine_new_connection(ioa_engine_handle e, ioa_engine_new_connection_event_handler cb)
{
	e->connect_cb = cb;
	return 0;
}

static const ioa_addr* ioa_engine_get_relay_addr(ioa_engine_handle e, int address_family, int *err_code)
{
	if (e && e->relays_number) {

		size_t i = 0;

		for(i=0; i<e->relays_number; i++) {

			e->relay_addr_counter = e->relay_addr_counter % e->relays_number;
			const ioa_addr *relay_addr = &(e->relay_addrs[e->relay_addr_counter++]);

			switch (address_family){
			case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT:
			case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
				if (relay_addr->ss.ss_family == AF_INET)
					return relay_addr;
				break;
			case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
				if (relay_addr->ss.ss_family == AF_INET6)
					return relay_addr;
				break;
			default:
				*err_code = 440;
				return NULL;
			};
		}

		*err_code = 440;
	}
	return NULL;
}

/******************** Timers ****************************/

static void timer_event_handler(evutil_socket_t fd, short what, void* arg)
{
	timer_event* te = arg;

	if(!te)
		return;

	UNUSED_ARG(fd);

	if (!(what & EV_TIMEOUT))
		return;

	if(te->e->verbose)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: timeout 0x%lx: %s\n", __FUNCTION__,(long)te, te->txt);

	ioa_timer_event_handler cb = te->cb;
	ioa_engine_handle e = te->e;
	void *ctx = te->ctx;

	cb(e, ctx);
}

ioa_timer_handle set_ioa_timer(ioa_engine_handle e, int secs, int ms, ioa_timer_event_handler cb, void* ctx, int persist, const s08bits *txt)
{
	ioa_timer_handle ret = NULL;

	if (e && cb && secs > 0) {

		timer_event *te = malloc(sizeof(timer_event));
		int flags = EV_TIMEOUT;
		if (persist)
			flags |= EV_PERSIST;
		struct event *ev = event_new(e->event_base, -1, flags, timer_event_handler, te);
		struct timeval tv;

		tv.tv_sec = secs;
		tv.tv_usec = ms * 1000;

		te->ctx = ctx;
		te->e = e;
		te->ev = ev;
		te->cb = cb;
		te->txt=strdup(txt);

		evtimer_add(ev,&tv);

		ret = te;
	}

	return ret;
}

void stop_ioa_timer(ioa_timer_handle th)
{
	if (th) {
		timer_event *te = th;
		EVENT_DEL(te->ev);
	}
}

void delete_ioa_timer(ioa_timer_handle th)
{
	if (th) {
		stop_ioa_timer(th);
		timer_event *te = th;
		if(te->txt) {
			free(te->txt);
			te->txt = NULL;
		}
		free(th);
	}
}

/************** SOCKETS HELPERS ***********************/

int get_ioa_socket_from_reservation(ioa_engine_handle e, u64bits in_reservation_token, ioa_socket_handle *s)
{
  if (e && in_reservation_token && s) {
    *s = rtcp_map_get(e->rtcp_map, in_reservation_token);
    if (*s) {
      rtcp_map_del_savefd(e->rtcp_map, in_reservation_token);
      return 0;
    }
  }
  return -1;
}

static ioa_socket_handle create_unbound_ioa_socket(ioa_engine_handle e, int family, SOCKET_TYPE st)
{
	evutil_socket_t fd = -1;
	ioa_socket_handle ret = NULL;

	switch (st){
	case UDP_SOCKET:
		fd = socket(family, SOCK_DGRAM, 0);
		if (fd < 0) {
			perror("socket");
			return NULL;
		}
		set_sock_buf_size(fd, UR_CLIENT_SOCK_BUF_SIZE);
		break;
	default:
		/* we do not support TCP sockets in the relay position */
		return NULL;
	}

	socket_set_reusable(fd);
	evutil_make_socket_nonblocking(fd);

	ret = malloc(sizeof(ioa_socket));
	ns_bzero(ret,sizeof(ioa_socket));

	ret->fd = fd;
	ret->family = family;
	ret->st = st;
	ret->e = e;

	return ret;
}

static int bind_ioa_socket(ioa_socket_handle s, const ioa_addr* local_addr)
{
	if (s && s->fd >= 0 && s->e && local_addr) {
		int res = addr_bind(s->fd, local_addr);
		if (res >= 0) {
			s->bound = 1;
			addr_cpy(&(s->local_addr), local_addr);
			return 0;
		}
	}
	return -1;
}

int create_relay_ioa_sockets(ioa_engine_handle e, int address_family, int even_port, ioa_socket_handle *rtp_s,
				ioa_socket_handle *rtcp_s, uint64_t *out_reservation_token, int *err_code,
				const u08bits **reason)
{

	*rtp_s = NULL;
	if (rtcp_s)
		*rtcp_s = NULL;

	turnipports* tp = e->tp;

	size_t iip = 0;

	for (iip = 0; iip < e->relays_number; ++iip) {

		ioa_addr relay_addr;
		const ioa_addr *ra = ioa_engine_get_relay_addr(e, address_family, err_code);
		if(ra)
			addr_cpy(&relay_addr, ra);

		if(*err_code) {
			if(*err_code == 440)
				*reason = (const u08bits *) "Unsupported address family";
			return -1;
		}

		int rtcp_port = -1;

		*rtp_s = create_unbound_ioa_socket(e, relay_addr.ss.ss_family, UDP_SOCKET);
		if (*rtp_s == NULL) {
			perror("socket");
			return -1;
		}

		sock_bind_to_device((*rtp_s)->fd, (unsigned char*)e->relay_ifname);

		ioa_addr rtcp_local_addr;
		addr_cpy(&rtcp_local_addr, &relay_addr);

		if (even_port > 0) {
			*rtcp_s = create_unbound_ioa_socket(e, relay_addr.ss.ss_family, UDP_SOCKET);
			if (*rtcp_s == NULL) {
				perror("socket");
				IOA_CLOSE_SOCKET(*rtp_s);
				return -1;
			}

			sock_bind_to_device((*rtcp_s)->fd, (unsigned char*)e->relay_ifname);
		}

		addr_debug_print(e->verbose, &relay_addr, "Server relay addr");

		int i = 0;
		ioa_addr local_addr;
		addr_cpy(&local_addr, &relay_addr);
		for (i = 0; i < 0xFFFF; i++) {
			int port = 0;
			rtcp_port = -1;
			if (even_port < 0) {
				port = turnipports_allocate(tp, &relay_addr);
			} else {
				port = turnipports_allocate_even(tp, &relay_addr, even_port, out_reservation_token);
				if (port >= 0 && even_port > 0) {
					rtcp_port = port + 1;
					addr_set_port(&rtcp_local_addr, rtcp_port);
					if (bind_ioa_socket(*rtcp_s, &rtcp_local_addr) < 0) {
						addr_set_port(&local_addr, port);
						turnipports_release(tp, &local_addr);
						turnipports_release(tp, &rtcp_local_addr);
						rtcp_port = -1;
						continue;
					}
				}
			}
			if (port < 0) {
				IOA_CLOSE_SOCKET(*rtp_s);
				if (rtcp_s && *rtcp_s)
					IOA_CLOSE_SOCKET(*rtcp_s);
				rtcp_port = -1;
				break;
			}
			addr_set_port(&local_addr, port);
			if (bind_ioa_socket(*rtp_s, &local_addr) >= 0) {
				break;
			} else {
				turnipports_release(tp, &local_addr);
				if (rtcp_port >= 0)
					turnipports_release(tp, &rtcp_local_addr);
				rtcp_port = -1;
			}
		}

		if (*rtp_s)
			break;

		addr_debug_print(e->verbose, &local_addr, "Local relay addr");
	}

	if (!(*rtp_s)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: no available ports 3\n", __FUNCTION__);
		IOA_CLOSE_SOCKET(*rtp_s);
		IOA_CLOSE_SOCKET(*rtcp_s);
		return -1;
	}

	if (rtcp_s && *rtcp_s && out_reservation_token && *out_reservation_token) {
		if (rtcp_map_put(e->rtcp_map, *out_reservation_token, *rtcp_s) < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot update RTCP map\n", __FUNCTION__);
			IOA_CLOSE_SOCKET(*rtp_s);
			IOA_CLOSE_SOCKET(*rtcp_s);
			return -1;
		}
	}

	return 0;
}

ioa_socket_handle create_ioa_socket_from_fd(ioa_engine_handle e,
				ioa_socket_raw fd, SOCKET_TYPE st,
				const ioa_addr *remote_addr, const ioa_addr *local_addr)
{
	ioa_socket_handle ret = NULL;

	if (fd < 0) {
		return NULL;
	}

	ret = malloc(sizeof(ioa_socket));
	ns_bzero(ret,sizeof(ioa_socket));

	evutil_make_socket_nonblocking(fd);

	ret->fd = fd;
	ret->family = local_addr->ss.ss_family;
	ret->st = st;
	ret->e = e;

	if (local_addr) {
		ret->bound = 1;
		addr_cpy(&(ret->local_addr), local_addr);
	}

	if (remote_addr) {
		ret->connected = 1;
		addr_cpy(&(ret->remote_addr), remote_addr);
	}

	return ret;
}

static void channel_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *in_buffer, void *arg) {

	if (!(event_type & IOA_EV_READ) || !arg)
		return;

	ch_info* chn = arg;

	ts_ur_super_session* ss = s->session;

	if(!ss) return;

	turn_turnserver *server = ss->server;

	if (!server) {
		return;
	}

	int offset = STUN_CHANNEL_HEADER_LENGTH;

	int ilen = min((int)ioa_network_buffer_get_size(in_buffer->nbh),
					(int)(ioa_network_buffer_get_capacity() - offset));

	if (ilen >= 0) {

		size_t len = (size_t)(ilen);

		u16bits chnum = chn->chnum;

		if (chnum) {

			ioa_network_buffer_handle nbh = in_buffer->nbh;
			ns_bcopy(ioa_network_buffer_data(in_buffer->nbh), (s08bits*)(ioa_network_buffer_data(nbh)+offset), len);
			ioa_network_buffer_header_init(nbh);
			stun_init_channel_message_str(chnum, ioa_network_buffer_data(nbh), &len, len);
			ioa_network_buffer_set_size(nbh,len);
			in_buffer->nbh = NULL;
			if (s->e->verbose) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"%s: send channel 0x%x\n", __FUNCTION__,
						(int) (chnum));
			}

			send_data_from_ioa_socket_nbh(ss->client_session.s, NULL, nbh, 0, NULL);
		}
	}
}

void refresh_ioa_socket_channel(void *socket_channel)
{
	UNUSED_ARG(socket_channel);
}

void *create_ioa_socket_channel(ioa_socket_handle s, void *channel_info)
{
	ch_info *chn = channel_info;

	ioa_socket_handle cs = create_unbound_ioa_socket(s->e, s->local_addr.ss.ss_family, UDP_SOCKET);
	if (cs == NULL) {
		perror("socket");
		return NULL;
	}

	sock_bind_to_device(cs->fd, (unsigned char*)cs->e->relay_ifname);

	if(bind_ioa_socket(cs, &(s->local_addr))<0) {
		IOA_CLOSE_SOCKET(cs);
		return NULL;
	}

	if (addr_connect(cs->fd, &(chn->peer_addr)) < 0) {
		IOA_CLOSE_SOCKET(cs);
		return NULL;
	}

	addr_cpy(&(cs->remote_addr),&(chn->peer_addr));
	cs->connected = 1;

	set_ioa_socket_session(cs, s->session);

	cs->do_not_use_df = s->do_not_use_df;

	if(s->current_df_relay_flag)
		set_df_on_ioa_socket(cs,s->current_df_relay_flag);

	register_callback_on_ioa_socket(cs->e, cs, IOA_EV_READ, channel_input_handler, chn);

	return cs;
}

void delete_ioa_socket_channel(void *socket_channel)
{
	ioa_socket_handle cs = socket_channel;
	IOA_CLOSE_SOCKET(cs);
}

static void close_socket_net_data(ioa_socket_handle s)
{
	if(s) {
		if(s->bev) {
			if (!s->broken) {
				SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
				if (!(SSL_get_shutdown(ctx) & SSL_SENT_SHUTDOWN)) {
					/*
					 * SSL_RECEIVED_SHUTDOWN tells SSL_shutdown to act as if we had already
					 * received a close notify from the other end.  SSL_shutdown will then
					 * send the final close notify in reply.  The other end will receive the
					 * close notify and send theirs.  By this time, we will have already
					 * closed the socket and the other end's real close notify will never be
					 * received.  In effect, both sides will think that they have completed a
					 * clean shutdown and keep their sessions valid.  This strategy will fail
					 * if the socket is not ready for writing, in which case this hack will
					 * lead to an unclean shutdown and lost session on the other end.
					 */
					SSL_set_shutdown(ctx, SSL_RECEIVED_SHUTDOWN);
					SSL_shutdown(ctx);
				}
			}
			bufferevent_free(s->bev);
			s->bev=NULL;
			s->fd=-1;
		}
		if (s->fd >= 0) {
			evutil_closesocket(s->fd);
			s->fd = -1;
		}
	}
}

void close_ioa_socket(ioa_socket_handle s)
{
	if (s) {
		if(s->done) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!double free on socket: 0x%lx\n", (long)s);
			return;
		}
		s->done = 1;

		ioa_network_buffer_delete(s->e, s->defer_nbh);

		EVENT_DEL(s->read_event);
		if(s->bound && s->e && s->e->tp) {
			turnipports_release(s->e->tp,&(s->local_addr));
		}

		close_socket_net_data(s);

		free(s);
	}
}

void *get_ioa_socket_session(ioa_socket_handle s)
{
	return s->session;
}

void set_ioa_socket_session(ioa_socket_handle s, void *ss)
{
	if(s)
		s->session = ss;
}

ioa_addr* get_local_addr_from_ioa_socket(ioa_socket_handle s)
{
	if (s) {

		if (s->local_addr_known) {
			return &(s->local_addr);
		} else if (s->bound && (addr_get_port(&(s->local_addr)) > 0)) {
			s->local_addr_known = 1;
			return &(s->local_addr);
		} else if (addr_get_from_sock(s->fd, &(s->local_addr)) == 0) {
			s->local_addr_known = 1;
			return &(s->local_addr);
		}
	}
	return NULL;
}

ioa_addr* get_remote_addr_from_ioa_socket(ioa_socket_handle s)
{
	if (s) {

		if (s->connected) {
			return &(s->remote_addr);
		}
	}
	return NULL;
}

static int udp_recvfrom(evutil_socket_t fd, ioa_addr* orig_addr, const ioa_addr *like_addr, s08bits* buffer, int buf_size)
{

	if (fd < 0 || !orig_addr || !like_addr || !buffer)
		return -1;

	int len = 0;
	int slen = get_ioa_addr_len(like_addr);

	do {
		len = recvfrom(fd, buffer, buf_size, 0, (struct sockaddr*) orig_addr, (socklen_t*) &slen);
	} while (len < 0 && ((errno == EINTR) || (errno == EAGAIN)));

	return len;
}

static int socket_input_worker(evutil_socket_t fd, ioa_socket_handle s)
{
	int len;
	ioa_addr remote_addr;

	if(s->done)
		goto do_flush;

	stun_buffer_list_elem *elem = new_blist_elem(s->e);
	len = -1;

	if(s->bev) {
		struct evbuffer *inbuf = bufferevent_get_input(s->bev);
		if(inbuf) {
			ev_ssize_t blen = evbuffer_copyout(inbuf, elem->buf.buf, sizeof(elem->buf.buf));
			if(blen>0) {
				int mlen = stun_get_message_len_str(elem->buf.buf, blen);
				if(mlen>0 && mlen<=(int)blen) {
					len = (int)bufferevent_read(s->bev, elem->buf.buf, mlen);
				} else if(blen>=TOO_BIG_BAD_TCP_MESSAGE) {
					s->tobeclosed = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: bad TCP message, session to be closed.\n",
							__FUNCTION__);
				}
			}
		}
	} else if(s->fd>=0){
		len = udp_recvfrom(s->fd, &remote_addr, &(s->local_addr), (s08bits*)(elem->buf.buf), sizeof(elem->buf.buf));
	} else {
		free_blist_elem(s->e,elem);
		s->tobeclosed = 1;
		goto do_flush;
	}

	if (len >= 0) {
		elem->buf.len = len;
		if(s->read_cb) {
			ioa_net_data event_data = {&remote_addr, elem, 0 };
			ioa_net_event_handler cb = s->read_cb;
			void* ctx = s->read_ctx;

			cb(s, IOA_EV_READ, &event_data, ctx);

			if(event_data.nbh)
				free_blist_elem(s->e,elem);

			elem = NULL;

		} else {
			ioa_network_buffer_delete(s->e, s->defer_nbh);
			s->defer_nbh = elem;
			elem = NULL;
		}
	}

	if(elem) {
		free_blist_elem(s->e,elem);
		elem = NULL;
	}

	return len;

	do_flush:
	if(fd>=0 && !(s->bev)) {
		char buffer[1024];
		recv(fd, buffer, sizeof(buffer),0);
	}
	return 0;
}

static void socket_input_handler(evutil_socket_t fd, short what, void* arg)
{

	if (!(what & EV_READ) || !arg)
		return;

	ioa_socket_handle s = arg;

	if (!ioa_socket_tobeclosed(s))
		socket_input_worker(fd, s);

	if (ioa_socket_tobeclosed(s)) {
		ts_ur_super_session *ss = s->session;
		if (ss) {
			turn_turnserver *server = ss->server;
			if (server)
				shutdown_client_connection(server, ss);
		}
	}
}

static void socket_input_handler_bev(struct bufferevent *bev, void* arg)
{

	if (bev && arg) {
		ioa_socket_handle s = arg;

		while (!ioa_socket_tobeclosed(s)) {
			if(socket_input_worker(s->fd, s)<=0)
				break;
		}

		if (ioa_socket_tobeclosed(s)) {
			ts_ur_super_session *ss = s->session;
			if (ss) {
				turn_turnserver *server = ss->server;
				if (server)
					shutdown_client_connection(server, ss);
			}
			return;
		}
	}
}

static void eventcb_bev(struct bufferevent *bev, short events, void *arg)
{
	UNUSED_ARG(bev);

	if (events & BEV_EVENT_CONNECTED) {
		// Connect okay
	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		if (arg) {
			ioa_socket_handle s = arg;
			s->broken = 1;
			ts_ur_super_session *ss = s->session;
			if (ss) {
				turn_turnserver *server = ss->server;
				if (server)
					shutdown_client_connection(server, ss);
			}
		}
	}
}

static inline int udp_send(evutil_socket_t fd, const ioa_addr* dest_addr, const s08bits* buffer, int len)
{
	int rc = 0;
	if (dest_addr) {
		int slen = get_ioa_addr_len(dest_addr);
		do {
			rc = sendto(fd, buffer, len, 0, (const struct sockaddr*) dest_addr, (socklen_t) slen);
		} while (rc < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));
	} else {
		do {
			rc = send(fd, buffer, len, 0);
		} while (rc < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));
	}

	return rc;
}

int send_data_from_ioa_socket_nbh(ioa_socket_handle s, ioa_addr* dest_addr,
				ioa_network_buffer_handle nbh, int to_peer,
				void *socket_channel)
{
	int ret = -1;
	if (s->done || (s->fd == -1)) {

		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"!!! Trying to send data from closed socket: 0x%lx (1): done=%d, fd=%d\n",(long) s, (int)s->done, (int)s->fd);

	} else if (nbh) {

		if (!ioa_socket_tobeclosed(s) && s->e) {

			if (to_peer && socket_channel)
				s = socket_channel; //Use dedicated socket

			if (s->done || (s->fd == -1)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"!!! Trying to send data from closed socket: 0x%lx (2): done=%d, fd=%d\n",(long) s, (int)s->done, (int)s->fd);
			} else {
				if (s->connected && s->bev) {
					if (bufferevent_write(s->bev,ioa_network_buffer_data(nbh),ioa_network_buffer_get_size(nbh))< 0) {
						ret = -1;
						perror("bufev send");
					} else {
						bufferevent_flush(s->bev, EV_WRITE, BEV_FLUSH);
						ret = (int) ioa_network_buffer_get_size(nbh);
					}
				} else if (s->fd >= 0) {
					if (s->connected)
						dest_addr = NULL; /* ignore dest_addr */
					else if (!dest_addr)
						dest_addr = &(s->remote_addr);
					ret = udp_send(s->fd, dest_addr, (s08bits*) ioa_network_buffer_data(nbh),ioa_network_buffer_get_size(nbh));
					if (ret < 0)
						perror("udp send");
				}
			}
		}
	}

	ioa_network_buffer_delete(s->e, nbh);

	return ret;
}

int register_callback_on_ioa_socket(ioa_engine_handle e, ioa_socket_handle s, int event_type, ioa_net_event_handler cb, void* ctx)
{

	if (cb) {
		if ((event_type & IOA_EV_READ) && s) {

			if(e)
				s->e = e;

			if(s->e) {
				switch(s->st) {
				case UDP_SOCKET:
					if(s->read_event) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 1\n", __FUNCTION__);
						return -1;
					} else {
						s->read_event = event_new(s->e->event_base,s->fd, EV_READ|EV_PERSIST, socket_input_handler, s);
						event_add(s->read_event,NULL);
					}
					break;
				case TCP_SOCKET:
					if(s->bev) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 2\n", __FUNCTION__);
						return -1;
					} else {
						s->bev = bufferevent_socket_new(s->e->event_base,
										s->fd,
										BEV_OPT_CLOSE_ON_FREE);
						bufferevent_setcb(s->bev, socket_input_handler_bev, NULL,
							eventcb_bev, s);
						bufferevent_setwatermark(s->bev, EV_READ, 1, 1024000);
						bufferevent_enable(s->bev, EV_READ); /* Start reading. */
					}
					break;
				case TLS_SOCKET:
					if(s->bev) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 2\n", __FUNCTION__);
						return -1;
					} else {
						SSL *tls_ssl = SSL_new(e->tls_ctx);
						s->bev = bufferevent_openssl_socket_new(s->e->event_base,
											s->fd,
											tls_ssl,
											BUFFEREVENT_SSL_ACCEPTING,
											BEV_OPT_CLOSE_ON_FREE);
						bufferevent_setcb(s->bev, socket_input_handler_bev, NULL,
							eventcb_bev, s);
						bufferevent_setwatermark(s->bev, EV_READ, 1, 1024000);
						bufferevent_enable(s->bev, EV_READ); /* Start reading. */
					}
					break;
				default:
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
							"%s: software error: unknown socket type: %d\n", __FUNCTION__,(int)(s->st));
					return -1;
				}
			}

			s->read_cb = cb;
			s->read_ctx = ctx;
			return 0;
		}
	}
	/* unsupported event */
	return -1;
}

int ioa_socket_tobeclosed(ioa_socket_handle s)
{
	if(s) {
		if(s->tobeclosed)
			return 1;
		if(s->done) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: check on already closed socket: 0x%lx\n",__FUNCTION__,(long)s);
			return 1;
		}
		if(s->fd < 0) {
			return 1;
		}
	}
	return 0;
}

void set_ioa_socket_tobeclosed(ioa_socket_handle s)
{
	s->tobeclosed = 1;
}

/*
 * Network buffer functions
 */
ioa_network_buffer_handle ioa_network_buffer_allocate(ioa_engine_handle e)
{
	stun_buffer_list_elem *elem = new_blist_elem(e);
	ns_bzero(&(elem->buf),sizeof(stun_buffer));
	return elem;
}

/* We do not use special header in this simple implementation */
void ioa_network_buffer_header_init(ioa_network_buffer_handle nbh)
{
	UNUSED_ARG(nbh);
}

u08bits *ioa_network_buffer_data(ioa_network_buffer_handle nbh)
{
	stun_buffer_list_elem *elem = nbh;
	return elem->buf.buf;
}

size_t ioa_network_buffer_get_size(ioa_network_buffer_handle nbh)
{
	if(!nbh)
		return 0;
	else {
		stun_buffer_list_elem *elem = nbh;
		return (size_t)(elem->buf.len);
	}
}

size_t ioa_network_buffer_get_capacity(void)
{
	return STUN_BUFFER_SIZE;
}

void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len)
{
	stun_buffer_list_elem *elem = nbh;
	elem->buf.len=(ssize_t)len;
}
void ioa_network_buffer_delete(ioa_engine_handle e, ioa_network_buffer_handle nbh) {
	stun_buffer_list_elem *elem = nbh;
	free_blist_elem(e,elem);
}

/******* debug ************/

static FILE* _rtpfile = NULL;

void rtpprintf(const char *format, ...)
{
	if(!_rtpfile) {
		char fn[129];
		sprintf(fn,"/var/rtp_%d.log",(int)getpid());
		_rtpfile = fopen(fn,"w");
	}
	va_list args;
	va_start (args, format);
	vfprintf(_rtpfile,format, args);
	fflush(_rtpfile);
	va_end (args);
}
