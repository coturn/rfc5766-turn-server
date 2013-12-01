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

#include "ns_turn_utils.h"
#include "ns_turn_session.h"
#include "ns_turn_server.h"
#include "ns_turn_khash.h"

#include "stun_buffer.h"
#include "apputils.h"

#include "ns_ioalib_impl.h"

#if !defined(TURN_NO_TLS)
#include <event2/bufferevent_ssl.h>
#endif

#include <event2/listener.h>

#include <openssl/err.h>

#if !defined(TURN_NO_HIREDIS)
#include "hiredis_libevent2.h"
#endif

/* Compilation test:
#if defined(IP_RECVTTL)
#undef IP_RECVTTL
#endif
#if defined(IPV6_RECVHOPLIMIT)
#undef IPV6_RECVHOPLIMIT
#endif
#if defined(IP_RECVTOS)
#undef IP_RECVTOS
#endif
#if defined(IPV6_RECVTCLASS)
#undef IPV6_RECVTCLASS
#endif
*/

#define MAX_ERRORS_IN_UDP_BATCH (1024)

struct turn_sock_extended_err {
	uint32_t ee_errno; /* error number */
	uint8_t ee_origin; /* where the error originated */
	uint8_t ee_type; /* type */
	uint8_t ee_code; /* code */
	uint8_t ee_pad; /* padding */
	uint32_t ee_info; /* additional information */
	uint32_t ee_data; /* other data */
/* More data may follow */
};

#define TRIAL_EFFORTS_TO_SEND (2)

/************** Forward function declarations ******/

static int socket_readerr(evutil_socket_t fd, ioa_addr *orig_addr);

static void socket_input_handler(evutil_socket_t fd, short what, void* arg);
static void socket_input_handler_bev(struct bufferevent *bev, void* arg);
static void eventcb_bev(struct bufferevent *bev, short events, void *arg);

static int send_ssl_backlog_buffers(ioa_socket_handle s);

static int set_accept_cb(ioa_socket_handle s, accept_cb acb, void *arg);

static void close_socket_net_data(ioa_socket_handle s);

/************** Utils **************************/

int set_df_on_ioa_socket(ioa_socket_handle s, int value)
{
	if(s->parent_s)
		return 0;

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
	if(s->parent_s)
		return;

	s->do_not_use_df = 1;
	s->current_df_relay_flag = 1;
	set_socket_df(s->fd, s->family, 0);
}

/************** Buffer List ********************/

static int buffer_list_empty(stun_buffer_list *bufs)
{
	if(bufs && bufs->head && bufs->tsz)
		return 0;
	return 1;
}

static stun_buffer_list_elem *get_elem_from_buffer_list(stun_buffer_list *bufs)
{
	stun_buffer_list_elem *ret = NULL;

	if(bufs && bufs->head && bufs->tsz) {

		ret=bufs->head;
		bufs->head=ret->next;
		if(bufs->head)
			bufs->head->prev = NULL;
		if(ret == bufs->tail)
			bufs->tail = NULL;
		--bufs->tsz;

		ret->next=NULL;
		ret->prev = NULL;
		ret->buf.len = 0;
	}

	return ret;
}

static void pop_elem_from_buffer_list(stun_buffer_list *bufs)
{
	if(bufs && bufs->head && bufs->tsz) {

		if(bufs->head == bufs->tail) {
			turn_free(bufs->head,sizeof(stun_buffer_list_elem));
			bufs->head = NULL;
			bufs->tail = NULL;
			bufs->tsz = 0;
		} else {
			stun_buffer_list_elem *ret = bufs->head;
			bufs->head=ret->next;
			if(bufs->head)
				bufs->head->prev = NULL;
			--bufs->tsz;
			turn_free(ret,sizeof(stun_buffer_list_elem));
		}
	}
}



static stun_buffer_list_elem *new_blist_elem(ioa_engine_handle e)
{
	stun_buffer_list_elem *ret = get_elem_from_buffer_list(&(e->bufs));

	if(!ret) {
	  ret = (stun_buffer_list_elem *)turn_malloc(sizeof(stun_buffer_list_elem));
	  ret->buf.len = 0;
	  ret->next = NULL;
	  ret->prev = NULL;
	}

	return ret;
}

static void add_elem_to_buffer_list(stun_buffer_list *bufs, stun_buffer_list_elem *elem)
{
	if (bufs && elem) {
		if (bufs->tail && bufs->tsz) {
			elem->next = NULL;
			elem->prev = bufs->tail;
			bufs->tail->next = elem;
			bufs->tail = elem;
			++bufs->tsz;
		} else {
			bufs->head = elem;
			bufs->tail = elem;
			bufs->tsz = 1;
			elem->next = NULL;
			elem->prev = NULL;
		}
	}
}

static void add_buffer_to_buffer_list(stun_buffer_list *bufs, s08bits *buf, size_t len)
{
	if(bufs && buf && (bufs->tsz<MAX_SOCKET_BUFFER_BACKLOG)) {
	  stun_buffer_list_elem *elem = (stun_buffer_list_elem *)turn_malloc(sizeof(stun_buffer_list_elem));
	  elem->next = NULL;
	  elem->prev = NULL;
	  ns_bcopy(buf,elem->buf.buf,len);
	  elem->buf.len = (ssize_t)len;
	  add_elem_to_buffer_list(bufs,elem);
	}
}

static void free_blist_elem(ioa_engine_handle e, stun_buffer_list_elem *elem)
{
	if(elem) {

		if(e) {
			if(e->bufs.tsz<MAX_BUFFER_QUEUE_SIZE_PER_ENGINE) {
				add_elem_to_buffer_list(&(e->bufs), elem);
				elem=NULL;
			}
		}

		if(elem) {
			turn_free(elem,sizeof(stun_buffer_list_elem));
		}
	}
}

/************** ENGINE *************************/

static void timer_handler(ioa_engine_handle e, void* arg) {

  UNUSED_ARG(arg);

  e->jiffie = turn_time();

  _log_time_value = e->jiffie;
  _log_time_value_set = 1;
}

ioa_engine_handle create_ioa_engine(struct event_base *eb, turnipports *tp, const s08bits* relay_ifname,
				size_t relays_number, s08bits **relay_addrs, int verbose, band_limit_t max_bps)
{
	static int capabilities_checked = 0;

	if(!capabilities_checked) {
		capabilities_checked = 1;
#if !defined(CMSG_SPACE)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "On this platform, I am using alternative behavior of TTL/TOS according to RFC 5766.\n");
#endif
#if !defined(IP_RECVTTL)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv4: On this platform, I am using alternative behavior of TTL according to RFC 5766.\n");
#endif
#if !defined(IPV6_RECVHOPLIMIT)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv6: On this platform, I am using alternative behavior of TTL (HOPLIMIT) according to RFC 6156.\n");
#endif
#if !defined(IP_RECVTOS)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv4: On this platform, I am using alternative behavior of TOS according to RFC 5766.\n");
#endif
#if !defined(IPV6_RECVTCLASS)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv6: On this platform, I am using alternative behavior of TRAFFIC CLASS according to RFC 6156.\n");
#endif
	}

	if (!relays_number || !relay_addrs || !tp) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create TURN engine\n", __FUNCTION__);
		return NULL;
	} else {
		ioa_engine_handle e = (ioa_engine_handle)turn_malloc(sizeof(ioa_engine));

		ns_bzero(e,sizeof(ioa_engine));

		e->max_bpj = max_bps * SECS_PER_JIFFIE;
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
			STRCPY(e->relay_ifname, relay_ifname);
		if (relay_addrs) {
			size_t i = 0;
			e->relay_addrs = (ioa_addr*)turn_malloc(relays_number * sizeof(ioa_addr));
			for (i = 0; i < relays_number; i++) {
				if(make_ioa_addr((u08bits*) relay_addrs[i], 0, &(e->relay_addrs[i]))<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot add a relay address: %s\n",relay_addrs[i]);
				}
			}
			e->relays_number = relays_number;
		}
		e->relay_addr_counter = (size_t) random() % relays_number;
		timer_handler(e,e);
		e->timer_ev = set_ioa_timer(e, SECS_PER_JIFFIE, 0, timer_handler, e, 1, "timer_handler");
		return e;
	}
}

void set_ssl_ctx(ioa_engine_handle e,
		SSL_CTX *tls_ctx_ssl23,
		SSL_CTX *tls_ctx_v1_0,
#if defined(SSL_TXT_TLSV1_1)
		SSL_CTX *tls_ctx_v1_1,
#if defined(SSL_TXT_TLSV1_2)
		SSL_CTX *tls_ctx_v1_2,
#endif
#endif
		SSL_CTX *dtls_ctx)
{
	e->tls_ctx_ssl23 = tls_ctx_ssl23;
	e->tls_ctx_v1_0 = tls_ctx_v1_0;
#if defined(SSL_TXT_TLSV1_1)
	e->tls_ctx_v1_1 = tls_ctx_v1_1;
#if defined(SSL_TXT_TLSV1_2)
	e->tls_ctx_v1_2 = tls_ctx_v1_2;
#endif
#endif
	e->dtls_ctx = dtls_ctx;
}

void ioa_engine_set_rtcp_map(ioa_engine_handle e, rtcp_map *rtcpmap)
{
	if(e)
		e->map_rtcp = rtcpmap;
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
  timer_event* te = (timer_event*)arg;

	if(!te)
		return;

	UNUSED_ARG(fd);

	if (!(what & EV_TIMEOUT))
		return;

	if(eve(te->e->verbose))
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

		timer_event * te = (timer_event*) turn_malloc(sizeof(timer_event));
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
		te->txt = strdup(txt);

		evtimer_add(ev,&tv);

		ret = te;
	}

	return ret;
}

void stop_ioa_timer(ioa_timer_handle th)
{
	if (th) {
	  timer_event *te = (timer_event *)th;
	  EVENT_DEL(te->ev);
	}
}

void delete_ioa_timer(ioa_timer_handle th)
{
	if (th) {
		stop_ioa_timer(th);
		timer_event *te = (timer_event *)th;
		if(te->txt) {
			turn_free(te->txt,strlen(te->txt)+1);
			te->txt = NULL;
		}
		turn_free(th,sizeof(timer_event));
	}
}

/************** SOCKETS HELPERS ***********************/

static int ioa_socket_check_bandwidth(ioa_socket_handle s, size_t sz)
{
	if((s->e->max_bpj == 0) || (s->sat != CLIENT_SOCKET)) {
		return 1;
	} else {
		band_limit_t bsz = (band_limit_t)sz;
		if(s->jiffie != s->e->jiffie) {
			s->jiffie = s->e->jiffie;
			if(bsz > s->e->max_bpj) {
				s->jiffie_bytes = 0;
				return 0;
			} else {
				s->jiffie_bytes = bsz;
				return 1;
			}
		} else {
			band_limit_t nsz = s->jiffie_bytes + bsz;
			if(nsz > s->e->max_bpj)
				return 0;
			else {
				s->jiffie_bytes = nsz;
				return 1;
			}
		}
	}
}

int get_ioa_socket_from_reservation(ioa_engine_handle e, u64bits in_reservation_token, ioa_socket_handle *s)
{
  if (e && in_reservation_token && s) {
    *s = rtcp_map_get(e->map_rtcp, in_reservation_token);
    if (*s) {
      rtcp_map_del_savefd(e->map_rtcp, in_reservation_token);
      return 0;
    }
  }
  return -1;
}

/* Socket options helpers ==>> */

#define CORRECT_RAW_TTL(ttl) do { if(ttl<0 || ttl>255) ttl=TTL_DEFAULT; } while(0)
#define CORRECT_RAW_TOS(tos) do { if(tos<0 || tos>255) tos=TOS_DEFAULT; } while(0)

static int get_raw_socket_ttl(evutil_socket_t fd, int family)
{
	int ttl = 0;

	if(family == AF_INET6) {
#if !defined(IPV6_RECVHOPLIMIT)
		UNUSED_ARG(fd);
		do { return TTL_IGNORE; } while(0);
#else
		socklen_t slen = (socklen_t)sizeof(ttl);
		if(getsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl,&slen)<0) {
			perror("get HOPLIMIT on socket");
			return TTL_IGNORE;
		}
#endif
	} else {
#if !defined(IP_RECVTTL)
		UNUSED_ARG(fd);
		do { return TTL_IGNORE; } while(0);
#else
		socklen_t slen = (socklen_t)sizeof(ttl);
		if(getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl,&slen)<0) {
			perror("get TTL on socket");
			return TTL_IGNORE;
		}
#endif
	}

	CORRECT_RAW_TTL(ttl);

	return ttl;
}

static int get_raw_socket_tos(evutil_socket_t fd, int family)
{
	int tos = 0;

	if(family == AF_INET6) {
#if !defined(IPV6_RECVTCLASS)
		UNUSED_ARG(fd);
		do { return TOS_IGNORE; } while(0);
#else
		socklen_t slen = (socklen_t)sizeof(tos);
		if(getsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos,&slen)<0) {
			perror("get TCLASS on socket");
			return -1;
		}
#endif
	} else {
#if !defined(IP_RECVTOS)
		UNUSED_ARG(fd);
		do { return TOS_IGNORE; } while(0);
#else
		socklen_t slen = (socklen_t)sizeof(tos);
		if(getsockopt(fd, IPPROTO_IP, IP_TOS, &tos,&slen)<0) {
			perror("get TOS on socket");
			return -1;
		}
#endif
	}

	CORRECT_RAW_TOS(tos);

	return tos;
}

static int set_raw_socket_ttl(evutil_socket_t fd, int family, int ttl)
{

	if(family == AF_INET6) {
#if !defined(IPV6_RECVHOPLIMIT)
		UNUSED_ARG(fd);
		UNUSED_ARG(ttl);
#else
		CORRECT_RAW_TTL(ttl);
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl,sizeof(ttl))<0) {
			perror("set HOPLIMIT on socket");
			return -1;
		}
#endif
	} else {
#if !defined(IP_RECVTTL)
		UNUSED_ARG(fd);
		UNUSED_ARG(ttl);
#else
		CORRECT_RAW_TTL(ttl);
		if(setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl,sizeof(ttl))<0) {
			perror("set TTL on socket");
			return -1;
		}
#endif
	}

	return 0;
}

static int set_raw_socket_tos(evutil_socket_t fd, int family, int tos)
{

	if(family == AF_INET6) {
#if !defined(IPV6_RECVTCLASS)
		UNUSED_ARG(fd);
		UNUSED_ARG(tos);
#else
		CORRECT_RAW_TOS(tos);
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos,sizeof(tos))<0) {
			perror("set TCLASS on socket");
			return -1;
		}
#endif
	} else {
#if !defined(IPV6_RECVTOS)
		UNUSED_ARG(fd);
		UNUSED_ARG(tos);
#else
		if(setsockopt(fd, IPPROTO_IP, IP_TOS, &tos,sizeof(tos))<0) {
			perror("set TOS on socket");
			return -1;
		}
#endif
	}

	return 0;
}

static int set_socket_ttl(ioa_socket_handle s, int ttl)
{
	if(s->default_ttl < 0) //Unsupported
		return -1;

	if(ttl < 0)
		ttl = s->default_ttl;

	CORRECT_RAW_TTL(ttl);

	if(ttl > s->default_ttl)
		ttl=s->default_ttl;

	if(s->current_ttl != ttl) {
		int ret = set_raw_socket_ttl(s->fd, s->family, ttl);
		s->current_ttl = ttl;
		return ret;
	}

	return 0;
}

static int set_socket_tos(ioa_socket_handle s, int tos)
{
	if(s->default_tos < 0) //Unsupported
		return -1;

	if(tos < 0)
		tos = s->default_tos;

	CORRECT_RAW_TOS(tos);

	if(s->current_tos != tos) {
		int ret = set_raw_socket_tos(s->fd, s->family, tos);
		s->current_tos = tos;
		return ret;
	}

	return 0;
}

int set_raw_socket_ttl_options(evutil_socket_t fd, int family)
{
	if (family == AF_INET6) {
#if !defined(IPV6_RECVHOPLIMIT)
		UNUSED_ARG(fd);
#else
		int recv_ttl_on = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &recv_ttl_on,
						sizeof(recv_ttl_on)) < 0) {
			perror("cannot set recvhoplimit\n");
		}
#endif
	} else {
#if !defined(IP_RECVTTL)
		UNUSED_ARG(fd);
#else
		int recv_ttl_on = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &recv_ttl_on,
						sizeof(recv_ttl_on)) < 0) {
			perror("cannot set recvttl\n");
		}
#endif
	}

	return 0;
}

int set_raw_socket_tos_options(evutil_socket_t fd, int family)
{
	if (family == AF_INET6) {
#if !defined(IPV6_RECVTCLASS)
		UNUSED_ARG(fd);
#else
		int recv_tos_on = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &recv_tos_on,
						sizeof(recv_tos_on)) < 0) {
			perror("cannot set recvtclass\n");
		}
#endif
	} else {
#if !defined(IP_RECVTOS)
		UNUSED_ARG(fd);
#else
		int recv_tos_on = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &recv_tos_on,
						sizeof(recv_tos_on)) < 0) {
			perror("cannot set recvtos\n");
		}
#endif
	}

	return 0;
}

int set_socket_options(ioa_socket_handle s)
{

	if(!s || (s->parent_s))
		return 0;

	set_sock_buf_size(s->fd,UR_CLIENT_SOCK_BUF_SIZE);

	if ((s->st == TCP_SOCKET) || (s->st == TLS_SOCKET)) {
		struct linger so_linger;
		so_linger.l_onoff = 1;
		so_linger.l_linger = 0;
		if(setsockopt(s->fd,
		    SOL_SOCKET,
		    SO_LINGER,
		    &so_linger,
		    sizeof(so_linger))<1) {
			//perror("setsolinger")
			;
		}
	}

	socket_set_nonblocking(s->fd);
	socket_set_reusable(s->fd);

	if ((s->st == UDP_SOCKET) || (s->st == DTLS_SOCKET)) {
		set_raw_socket_ttl_options(s->fd, s->family);
		set_raw_socket_tos_options(s->fd, s->family);

#ifdef SO_BSDCOMPAT
		//Linux. Option may be obsolete,
		{
			int on = 1;
			if(setsockopt(s->fd, SOL_SOCKET, SO_BSDCOMPAT, (void *)&on, sizeof(on))<0)
			perror("SO_BSDCOMPAT");
		}
#endif

#ifdef IP_RECVERR
		if (s->family != AF_INET6) {
			int on = 0;
#ifdef TURN_IP_RECVERR
			on = 1;
#endif
			if(setsockopt(s->fd, IPPROTO_IP, IP_RECVERR, (void *)&on, sizeof(on))<0)
				perror("IP_RECVERR");
		}
#endif

#ifdef IPV6_RECVERR
		if (s->family == AF_INET6) {
			int on = 0;
#ifdef TURN_IP_RECVERR
			on = 1;
#endif
			if(setsockopt(s->fd, IPPROTO_IPV6, IPV6_RECVERR, (void *)&on, sizeof(on))<0)
				perror("IPV6_RECVERR");
		}
#endif

	} else {
		int flag = 1;
		int result = setsockopt(s->fd, /* socket affected */
					IPPROTO_TCP, /* set option at TCP level */
					TCP_NODELAY, /* name of option */
					(char*)&flag, /* value */
					sizeof(int)); /* length of option value */
		if (result < 0)
			perror("TCP_NODELAY");
		socket_tcp_set_keepalive(s->fd);
	}

	s->default_ttl = get_raw_socket_ttl(s->fd, s->family);
	s->current_ttl = s->default_ttl;

	s->default_tos = get_raw_socket_tos(s->fd, s->family);
	s->current_tos = s->default_tos;

	return 0;
}

/* <<== Socket options helpers */

ioa_socket_handle create_unbound_ioa_socket(ioa_engine_handle e, ioa_socket_handle parent_s, int family, SOCKET_TYPE st, SOCKET_APP_TYPE sat)
{
	evutil_socket_t fd = -1;
	ioa_socket_handle ret = NULL;

	if(!parent_s) {
		switch (st){
		case UDP_SOCKET:
			fd = socket(family, SOCK_DGRAM, 0);
			if (fd < 0) {
				perror("UDP socket");
				return NULL;
			}
			set_sock_buf_size(fd, UR_CLIENT_SOCK_BUF_SIZE);
			break;
		case TCP_SOCKET:
			fd = socket(family, SOCK_STREAM, 0);
			if (fd < 0) {
				perror("TCP socket");
				return NULL;
			}
			set_sock_buf_size(fd, UR_CLIENT_SOCK_BUF_SIZE);
			break;
		default:
			/* we do not support other sockets in the relay position */
			return NULL;
		}
	}

	ret = (ioa_socket*)turn_malloc(sizeof(ioa_socket));
	ns_bzero(ret,sizeof(ioa_socket));

	ret->magic = SOCKET_MAGIC;

	ret->fd = fd;
	ret->family = family;
	ret->st = st;
	ret->sat = sat;
	ret->e = e;

	if(parent_s) {
		add_socket_to_parent(parent_s, ret);
	} else {
		set_socket_options(ret);
	}

	return ret;
}

static int bind_ioa_socket_func(ioa_socket_handle s, const ioa_addr* local_addr, const char* file, const char *func, int line)
{
	if(!s || (s->parent_s))
		return 0;

	if (s && s->fd >= 0 && s->e && local_addr) {

		int res = addr_bind_func(s->fd, local_addr, file, func, line);
		if (res >= 0) {
			s->bound = 1;
			addr_cpy(&(s->local_addr), local_addr);
			addr_get_from_sock(s->fd, &(s->local_addr));
			return 0;
		}
	}
	return -1;
}

#define bind_ioa_socket(s,addr) bind_ioa_socket_func((s),(addr),__FILE__,__FUNCTION__,__LINE__)

int create_relay_ioa_sockets(ioa_engine_handle e,
				int address_family, u08bits transport,
				int even_port, ioa_socket_handle *rtp_s,
				ioa_socket_handle *rtcp_s, uint64_t *out_reservation_token,
				int *err_code, const u08bits **reason,
				accept_cb acb, void *acbarg)
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

		IOA_CLOSE_SOCKET(*rtp_s);
		if(rtcp_s)
			IOA_CLOSE_SOCKET(*rtcp_s);

		ioa_addr rtcp_local_addr;
		addr_cpy(&rtcp_local_addr, &relay_addr);

		addr_debug_print(e->verbose, &relay_addr, "Server relay addr");

		int i = 0;
		int port = 0;
		ioa_addr local_addr;
		addr_cpy(&local_addr, &relay_addr);
		for (i = 0; i < 0xFFFF; i++) {
			port = 0;
			rtcp_port = -1;
			if (even_port < 0) {
				port = turnipports_allocate(tp, transport, &relay_addr);
			} else {

				port = turnipports_allocate_even(tp, &relay_addr, even_port, out_reservation_token);
				if (port >= 0 && even_port > 0) {

					IOA_CLOSE_SOCKET(*rtcp_s);
					*rtcp_s = create_unbound_ioa_socket(e, NULL, relay_addr.ss.ss_family, UDP_SOCKET, RELAY_RTCP_SOCKET);
					if (*rtcp_s == NULL) {
						perror("socket");
						IOA_CLOSE_SOCKET(*rtp_s);
						addr_set_port(&local_addr, port);
						turnipports_release(tp, transport, &local_addr);
						rtcp_port = port + 1;
						addr_set_port(&rtcp_local_addr, rtcp_port);
						turnipports_release(tp, transport, &rtcp_local_addr);
						return -1;
					}
					sock_bind_to_device((*rtcp_s)->fd, (unsigned char*)e->relay_ifname);

					rtcp_port = port + 1;
					addr_set_port(&rtcp_local_addr, rtcp_port);
					if (bind_ioa_socket(*rtcp_s, &rtcp_local_addr) < 0) {
						addr_set_port(&local_addr, port);
						turnipports_release(tp, transport, &local_addr);
						turnipports_release(tp, transport, &rtcp_local_addr);
						rtcp_port = -1;
						IOA_CLOSE_SOCKET(*rtcp_s);
						continue;
					}
				}
			}
			if (port < 0) {
				IOA_CLOSE_SOCKET(*rtp_s);
				if (rtcp_s)
					IOA_CLOSE_SOCKET(*rtcp_s);
				rtcp_port = -1;
				break;
			} else {

				IOA_CLOSE_SOCKET(*rtp_s);

				*rtp_s = create_unbound_ioa_socket(e, NULL, relay_addr.ss.ss_family,
										(transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) ? TCP_SOCKET : UDP_SOCKET,
										RELAY_SOCKET);
				if (*rtp_s == NULL) {
					if (rtcp_s)
						IOA_CLOSE_SOCKET(*rtcp_s);
					addr_set_port(&local_addr, port);
					turnipports_release(tp, transport, &local_addr);
					if (rtcp_port >= 0)
						turnipports_release(tp, transport, &rtcp_local_addr);
					perror("socket");
					return -1;
				}

				sock_bind_to_device((*rtp_s)->fd, (unsigned char*)e->relay_ifname);

				addr_set_port(&local_addr, port);
				if (bind_ioa_socket(*rtp_s, &local_addr) >= 0) {
					break;
				} else {
					IOA_CLOSE_SOCKET(*rtp_s);
					if (rtcp_s)
						IOA_CLOSE_SOCKET(*rtcp_s);
					addr_set_port(&local_addr, port);
					turnipports_release(tp, transport, &local_addr);
					if (rtcp_port >= 0)
						turnipports_release(tp, transport, &rtcp_local_addr);
					rtcp_port = -1;
				}
			}
		}

		if(i>=0xFFFF) {
			IOA_CLOSE_SOCKET(*rtp_s);
			if (rtcp_s)
				IOA_CLOSE_SOCKET(*rtcp_s);
		}

		if (*rtp_s) {
			addr_set_port(&local_addr, port);
			addr_debug_print(e->verbose, &local_addr, "Local relay addr");
			break;
		}
	}

	if (!(*rtp_s)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: no available ports 3\n", __FUNCTION__);
		IOA_CLOSE_SOCKET(*rtp_s);
		if (rtcp_s)
			IOA_CLOSE_SOCKET(*rtcp_s);
		return -1;
	}

	set_accept_cb(*rtp_s, acb, acbarg);

	if (rtcp_s && *rtcp_s && out_reservation_token && *out_reservation_token) {
		if (rtcp_map_put(e->map_rtcp, *out_reservation_token, *rtcp_s) < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot update RTCP map\n", __FUNCTION__);
			IOA_CLOSE_SOCKET(*rtp_s);
			if (rtcp_s)
				IOA_CLOSE_SOCKET(*rtcp_s);
			return -1;
		}
	}

	return 0;
}

/* RFC 6062 ==>> */

static void tcp_listener_input_handler(struct evconnlistener *l, evutil_socket_t fd,
				struct sockaddr *sa, int socklen, void *arg)
{
	UNUSED_ARG(l);

	ioa_socket_handle list_s = (ioa_socket_handle) arg;

	ioa_addr client_addr;
	ns_bcopy(sa,&client_addr,socklen);

	addr_debug_print(list_s->e->verbose, &client_addr,"tcp accepted from");

	ioa_socket_handle s =
				create_ioa_socket_from_fd(
							list_s->e,
							fd,
							NULL,
							TCP_SOCKET,
							TCP_RELAY_DATA_SOCKET,
							&client_addr,
							&(list_s->local_addr));

	if (s) {
		if(list_s->acb) {
			list_s->acb(s,list_s->acbarg);
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"Do not know what to do with accepted TCP socket\n");
			close_ioa_socket(s);
		}
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"Cannot create ioa_socket from FD\n");
		socket_closesocket(fd);
	}
}

static int set_accept_cb(ioa_socket_handle s, accept_cb acb, void *arg)
{
	if(!s || s->parent_s)
		return -1;

	if(s->st == TCP_SOCKET) {
		s->list_ev = evconnlistener_new(s->e->event_base,
			  tcp_listener_input_handler, s,
			  LEV_OPT_REUSEABLE,
			  1024, s->fd);
		if(!(s->list_ev)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot start TCP listener\n", __FUNCTION__);
			return -1;
		}
		s->acb = acb;
		s->acbarg = arg;
	}
	return 0;
}

static void connect_eventcb(struct bufferevent *bev, short events, void *ptr)
{
	UNUSED_ARG(bev);

	ioa_socket_handle ret = (ioa_socket_handle) ptr;
	if (ret) {
		connect_cb cb = ret->conn_cb;
		void *arg = ret->conn_arg;
		if (events & BEV_EVENT_CONNECTED) {
			ret->conn_cb = NULL;
			ret->conn_arg = NULL;
			if(ret->conn_bev) {
				bufferevent_disable(ret->conn_bev,EV_READ|EV_WRITE);
				bufferevent_free(ret->conn_bev);
				ret->conn_bev=NULL;
			}
			ret->connected = 1;
			if(cb) {
				cb(1,arg);
			}
		} else if (events & BEV_EVENT_ERROR) {
			/* An error occured while connecting. */
			ret->conn_cb = NULL;
			ret->conn_arg = NULL;
			if(ret->conn_bev) {
				bufferevent_disable(ret->conn_bev,EV_READ|EV_WRITE);
				bufferevent_free(ret->conn_bev);
				ret->conn_bev=NULL;
			}
			if(cb) {
				cb(0,arg);
			}
		}
	}
}

ioa_socket_handle ioa_create_connecting_tcp_relay_socket(ioa_socket_handle s, ioa_addr *peer_addr, connect_cb cb, void *arg)
{
	ioa_socket_handle ret = create_unbound_ioa_socket(s->e, NULL, s->family, s->st, TCP_RELAY_DATA_SOCKET);

	if(!ret) {
		return NULL;
	}

	ioa_addr new_local_addr;
	addr_cpy(&new_local_addr, &(s->local_addr));

#if !defined(SO_REUSEPORT)
	/*
	 * trick for OSes which do not support SO_REUSEPORT.
	 * Section 5.2 of RFC 6062 will not work correctly
	 * for those OSes (for example, Linux pre-3.9 kernel).
	 */
#if !defined(__CYGWIN__) && !defined(__CYGWIN32__) && !defined(__CYGWIN64__)
	close_socket_net_data(s);
#else
	addr_set_port(&new_local_addr,0);
#endif
#endif

	if(bind_ioa_socket(ret, &new_local_addr)<0) {
		IOA_CLOSE_SOCKET(ret);
		ret = NULL;
		goto ccs_end;
	}

	addr_cpy(&(ret->remote_addr), peer_addr);

	set_ioa_socket_session(ret, s->session);

	if(ret->conn_bev) {
		bufferevent_disable(ret->conn_bev,EV_READ|EV_WRITE);
		bufferevent_free(ret->conn_bev);
		ret->conn_bev=NULL;
	}

	ret->conn_bev = bufferevent_socket_new(ret->e->event_base,
					ret->fd,
					BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
	bufferevent_setcb(ret->conn_bev, NULL, NULL, connect_eventcb, ret);

	ret->conn_arg = arg;
	ret->conn_cb = cb;

	if (bufferevent_socket_connect(ret->conn_bev, (struct sockaddr *) peer_addr, get_ioa_addr_len(peer_addr)) < 0) {
		/* Error starting connection */
		set_ioa_socket_session(ret, NULL);
		IOA_CLOSE_SOCKET(ret);
		ret = NULL;
		goto ccs_end;
	}

	ccs_end:

#if !defined(SO_REUSEPORT)
#if !defined(__CYGWIN__) && !defined(__CYGWIN32__) && !defined(__CYGWIN64__)
		/*
		 * trick for OSes which do not support SO_REUSEPORT.
		 * Section 5.2 of RFC 6062 will not work correctly
		 * for those OSes (for example, Linux pre-3.9 kernel).
		 */
	s->fd = socket(s->family, SOCK_STREAM, 0);
	if (s->fd < 0) {
		perror("TCP socket");
		if(ret) {
			set_ioa_socket_session(ret, NULL);
			IOA_CLOSE_SOCKET(ret);
			ret = NULL;
		}
	} else {
		set_socket_options(s);
		sock_bind_to_device(s->fd, (unsigned char*)s->e->relay_ifname);
		if(bind_ioa_socket(s, &new_local_addr)<0) {
			if(ret) {
				set_ioa_socket_session(ret, NULL);
				IOA_CLOSE_SOCKET(ret);
				ret = NULL;
			}
		} else {
			set_accept_cb(s, s->acb, s->acbarg);
		}
	}
#endif
#endif

	return ret;
}

/* <<== RFC 6062 */

void add_socket_to_parent(ioa_socket_handle parent_s, ioa_socket_handle s)
{
	if(parent_s && s) {
		delete_socket_from_parent(s);
		s->parent_s = parent_s;
		s->fd = parent_s->fd;
	}
}

void delete_socket_from_parent(ioa_socket_handle s)
{
	if(s && s->parent_s) {
		s->parent_s = NULL;
		s->fd = -1;
	}
}

void add_socket_to_map(ioa_socket_handle s, ur_addr_map *amap)
{
	if(amap && s && (s->sockets_container != amap)) {
		delete_socket_from_map(s);
		ur_addr_map_del(amap, &(s->remote_addr),NULL);
		ur_addr_map_put(amap,
				&(s->remote_addr),
				(ur_addr_map_value_type)s);
		s->sockets_container = amap;
	}
}

void delete_socket_from_map(ioa_socket_handle s)
{
	if(s && s->sockets_container) {
		ur_addr_map_del(s->sockets_container,
				&(s->remote_addr),
				NULL);
		s->sockets_container = NULL;
	}
}

ioa_socket_handle create_ioa_socket_from_fd(ioa_engine_handle e,
				ioa_socket_raw fd, ioa_socket_handle parent_s,
				SOCKET_TYPE st, SOCKET_APP_TYPE sat,
				const ioa_addr *remote_addr, const ioa_addr *local_addr)
{
	ioa_socket_handle ret = NULL;

	if ((fd < 0) && !parent_s) {
		return NULL;
	}

	ret = (ioa_socket*)turn_malloc(sizeof(ioa_socket));
	ns_bzero(ret,sizeof(ioa_socket));

	ret->magic = SOCKET_MAGIC;

	ret->fd = fd;
	ret->family = local_addr->ss.ss_family;
	ret->st = st;
	ret->sat = sat;
	ret->e = e;

	if (local_addr) {
		ret->bound = 1;
		addr_cpy(&(ret->local_addr), local_addr);
	}

	if (remote_addr) {
		ret->connected = 1;
		addr_cpy(&(ret->remote_addr), remote_addr);
	}

	if(parent_s) {
		add_socket_to_parent(parent_s, ret);
	} else {
		set_socket_options(ret);
	}

	return ret;
}

/* Only must be called for DTLS_SOCKET */
ioa_socket_handle create_ioa_socket_from_ssl(ioa_engine_handle e, ioa_socket_handle parent_s, SSL* ssl, SOCKET_TYPE st, SOCKET_APP_TYPE sat, const ioa_addr *remote_addr, const ioa_addr *local_addr)
{
	ioa_socket_handle ret = create_ioa_socket_from_fd(e, parent_s->fd, parent_s, st, sat, remote_addr, local_addr);

	if(ret) {
		ret->ssl = ssl;
		if(st == DTLS_SOCKET)
			STRCPY(ret->orig_ctx_type,"DTLSv1.0");
	}

	return ret;
}

static void close_socket_net_data(ioa_socket_handle s)
{
	if(s) {

		EVENT_DEL(s->read_event);
		if(s->list_ev) {
			evconnlistener_free(s->list_ev);
			s->list_ev = NULL;
		}
		if(s->conn_bev) {
			bufferevent_disable(s->conn_bev,EV_READ|EV_WRITE);
			bufferevent_free(s->conn_bev);
			s->conn_bev=NULL;
		}
		if(s->bev) {
			bufferevent_disable(s->bev,EV_READ|EV_WRITE);
			bufferevent_free(s->bev);
			s->bev=NULL;
		}

		if (s->ssl) {
			if (!s->broken) {
				if(!(SSL_get_shutdown(s->ssl) & SSL_SENT_SHUTDOWN)) {
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
					SSL_set_shutdown(s->ssl, SSL_RECEIVED_SHUTDOWN);
					SSL_shutdown(s->ssl);
				}
			}
			SSL_free(s->ssl);
			s->ssl = NULL;
		}

		if (s->fd >= 0) {
			socket_closesocket(s->fd);
			s->fd = -1;
		}
	}
}

void detach_socket_net_data(ioa_socket_handle s)
{
	if(s) {
		EVENT_DEL(s->read_event);
		s->read_cb = NULL;
		s->read_ctx = NULL;
		if(s->list_ev) {
			evconnlistener_free(s->list_ev);
			s->list_ev = NULL;
			s->acb = NULL;
			s->acbarg = NULL;
		}
		if(s->conn_bev) {
			bufferevent_disable(s->conn_bev,EV_READ|EV_WRITE);
			bufferevent_free(s->conn_bev);
			s->conn_bev=NULL;
			s->conn_arg=NULL;
			s->conn_cb=NULL;
		}
		if(s->bev) {
			bufferevent_disable(s->bev,EV_READ|EV_WRITE);
			bufferevent_free(s->bev);
			s->bev=NULL;
		}
	}
}

void close_ioa_socket_func(ioa_socket_handle s, const char *func, const char *file, int line)
{
	if (s) {
		if(s->magic != SOCKET_MAGIC) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s wrong magic on socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, s->st, s->sat);
			return;
		}

		if(s->done) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s double free on socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, s->st, s->sat);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
			return;
		}

		s->done = 1;

		s->func = func;
		s->file = file;
		s->line = line;

		while(!buffer_list_empty(&(s->bufs)))
			pop_elem_from_buffer_list(&(s->bufs));

		ioa_network_buffer_delete(s->e, s->defer_nbh);

		if(s->bound && s->e && s->e->tp) {
			turnipports_release(s->e->tp,
					((s->st == TCP_SOCKET) ? STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE : STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE),
					&(s->local_addr));
		}

		delete_socket_from_map(s);
		delete_socket_from_parent(s);

		close_socket_net_data(s);

		turn_free(s,sizeof(ioa_socket));
	}
}

ioa_socket_handle detach_ioa_socket(ioa_socket_handle s, int full_detach)
{
	ioa_socket_handle ret = NULL;

	if (!s) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Detaching NULL socket\n");
	} else {
		if(s->done) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on done socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, s->st, s->sat);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
			return ret;
		}
		if(s->tobeclosed) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on tobeclosed socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, s->st, s->sat);
			return ret;
		}
		if(!(s->e)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on socket without engine: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, s->st, s->sat);
			return ret;
		}

		s->tobeclosed = 1;

		if(s->parent_s) {
			if((s->st != UDP_SOCKET) && (s->st != DTLS_SOCKET)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on non-UDP child socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, s->st, s->sat);
				return ret;
			}
		}

		evutil_socket_t udp_fd = -1;

		if(full_detach && s->parent_s) {

			udp_fd = socket(s->local_addr.ss.ss_family, SOCK_DGRAM, 0);
			if (udp_fd < 0) {
				perror("socket");
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Cannot allocate new socket\n",__FUNCTION__);
				return ret;
			}
		}

		detach_socket_net_data(s);

		while(!buffer_list_empty(&(s->bufs)))
					pop_elem_from_buffer_list(&(s->bufs));

		ioa_network_buffer_delete(s->e, s->defer_nbh);

		ret = (ioa_socket*)turn_malloc(sizeof(ioa_socket));
		if(!ret) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Cannot allocate new socket structure\n",__FUNCTION__);
			if(udp_fd>=0)
				close(udp_fd);
			return ret;
		}

		ns_bzero(ret,sizeof(ioa_socket));

		ret->magic = SOCKET_MAGIC;

		ret->ssl = s->ssl;
		ret->fd = s->fd;

		ret->family = s->family;
		ret->st = s->st;
		ret->sat = s->sat;
		ret->bound = s->bound;
		ret->local_addr_known = s->local_addr_known;
		addr_cpy(&(ret->local_addr),&(s->local_addr));
		ret->connected = s->connected;
		ioa_socket_handle parent_s = s->parent_s;
		addr_cpy(&(ret->remote_addr),&(s->remote_addr));

		ur_addr_map *sockets_container = s->sockets_container;

		delete_socket_from_map(s);
		delete_socket_from_parent(s);

		if(full_detach && parent_s) {

			ret->fd = udp_fd;

			if(sock_bind_to_device(udp_fd, (unsigned char*)(s->e->relay_ifname))<0) {
			    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot bind udp server socket to device %s\n",(char*)(s->e->relay_ifname));
			}

			if(addr_bind(udp_fd,&(s->local_addr))<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot bind new detached udp server socket to local addr\n");
				IOA_CLOSE_SOCKET(ret);
				return ret;
			}

			int connect_err=0;
			if(addr_connect(udp_fd, &(s->remote_addr), &connect_err)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot connect new detached udp server socket to remote addr\n");
				IOA_CLOSE_SOCKET(ret);
				return ret;
			}

			set_socket_options(ret);

		} else {
			add_socket_to_parent(parent_s, ret);
			add_socket_to_map(ret,sockets_container);
		}

		ret->current_ttl = s->current_ttl;
		ret->default_ttl = s->default_ttl;

		ret->current_tos = s->current_tos;
		ret->default_tos = s->default_tos;

		s->ssl = NULL;
		s->fd = -1;
	}

	return ret;
}

void *get_ioa_socket_session(ioa_socket_handle s)
{
	if(s)
		return s->session;
	return NULL;
}

void set_ioa_socket_session(ioa_socket_handle s, void *ss)
{
	if(s)
		s->session = ss;
}

void clear_ioa_socket_session_if(ioa_socket_handle s, void *ss)
{
	if(s && s->session==ss) {
		s->session=NULL;
	}
}

void *get_ioa_socket_sub_session(ioa_socket_handle s)
{
	if(s)
		return s->sub_session;
	return NULL;
}

void set_ioa_socket_sub_session(ioa_socket_handle s, void *tc)
{
	if(s)
		s->sub_session = tc;
}

int get_ioa_socket_address_family(ioa_socket_handle s) {
	if(!s) {
		return AF_INET;
	} else if(s->parent_s) {
		return s->parent_s->family;
	} else {
		return s->family;
	}
}

SOCKET_TYPE get_ioa_socket_type(ioa_socket_handle s)
{
	if(s)
		return s->st;

	return UNKNOWN_SOCKET;
}

SOCKET_APP_TYPE get_ioa_socket_app_type(ioa_socket_handle s)
{
	if(s)
		return s->sat;
	return UNKNOWN_APP_SOCKET;
}

void set_ioa_socket_app_type(ioa_socket_handle s, SOCKET_APP_TYPE sat) {
	if(s)
		s->sat = sat;
}

ioa_addr* get_local_addr_from_ioa_socket(ioa_socket_handle s)
{
	if (s) {

		if(s->parent_s) {
			return get_local_addr_from_ioa_socket(s->parent_s);
		} else if (s->local_addr_known) {
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

int get_local_mtu_ioa_socket(ioa_socket_handle s)
{
	if(s) {
		if(s->parent_s)
			return get_local_mtu_ioa_socket(s->parent_s);

		return get_socket_mtu(s->fd, s->family, eve(s->e->verbose));
	}
	return -1;
}

/*
 * Return: -1 - error, 0 or >0 - OK
 * *read_len -1 - no data, >=0 - data available
 */
int ssl_read(evutil_socket_t fd, SSL* ssl, s08bits* buffer, int buf_size, int verbose, int *read_len)
{
	int ret = 0;

	if (!ssl || !buffer || (*read_len < 1)) {
		return -1;
	}

	stun_buffer buf;
	ns_bcopy(buffer,buf.buf,*read_len);
	buf.len = *read_len;

	*read_len = -1;
	int len = 0;

	if (eve(verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: before read...\n", __FUNCTION__);
	}

	BIO *wbio = SSL_get_wbio(ssl);
	if(wbio) {
		BIO_set_fd(wbio,fd,BIO_NOCLOSE);
	}

	BIO* rbio = BIO_new_mem_buf(buf.buf, (int) buf.len);
	BIO_set_mem_eof_return(rbio, -1);

	ssl->rbio = rbio;

	int if1 = SSL_is_init_finished(ssl);

	do {
		len = SSL_read(ssl, buffer, buf_size);
	} while (len < 0 && (errno == EINTR));

	int if2 = SSL_is_init_finished(ssl);

	if (eve(verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: after read: %d\n", __FUNCTION__, len);
	}

	if(SSL_get_shutdown(ssl)) {

		ret = -1;

	} else if (!if1 && if2) {

		if(verbose && SSL_get_peer_certificate(ssl)) {
		  printf("\n------------------------------------------------------------\n");
		  X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1,
					XN_FLAG_MULTILINE);
		  printf("\n\n Cipher: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		  printf("\n------------------------------------------------------------\n\n");
		}

		ret = 0;

	} else if (len < 0 && ((errno == ENOBUFS) || (errno == EAGAIN))) {
		if (eve(verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: ENOBUFS/EAGAIN\n", __FUNCTION__);
		}
		ret = 0;
	} else {

		if (eve(verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: read %d bytes\n", __FUNCTION__, (int) len);
		}

		if (len >= 0) {
			*read_len = len;
			ret = len;
		} else {
			switch (SSL_get_error(ssl, len)){
			case SSL_ERROR_NONE:
				//???
				ret = 0;
				break;
			case SSL_ERROR_WANT_READ:
				ret = 0;
				break;
			case SSL_ERROR_WANT_WRITE:
				ret = 0;
				break;
			case SSL_ERROR_ZERO_RETURN:
				ret = 0;
				break;
			case SSL_ERROR_SYSCALL:
			{
				int err = errno;
				if (handle_socket_error()) {
					ret = 0;
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS Socket read error: %d\n", err);
					ret = -1;
				}
				break;
			}
			case SSL_ERROR_SSL:
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL read error: ");
					s08bits buf[65536];
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
				}
				if (verbose)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL connection closed.\n");
				ret = -1;
				break;
			default:
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error while reading!\n");
				}
				ret = -1;
			}
		}
	}

	BIO_free(rbio);
	ssl->rbio = NULL;

	return ret;
}

static int socket_readerr(evutil_socket_t fd, ioa_addr *orig_addr)
{
	if ((fd < 0) || !orig_addr)
		return -1;

#if defined(CMSG_SPACE) && defined(MSG_ERRQUEUE) && defined(IP_RECVERR)

	u08bits ecmsg[TURN_CMSG_SZ+1];
	int flags = MSG_ERRQUEUE;
	int len = 0;

	struct msghdr msg;
	struct iovec iov;
	char buffer[65536];

	char *cmsg = (char*)ecmsg;

	msg.msg_control = cmsg;
	msg.msg_controllen = TURN_CMSG_SZ;
	/* CMSG_SPACE(sizeof(recv_ttl)+sizeof(recv_tos)) */

	msg.msg_name = orig_addr;
	msg.msg_namelen = (socklen_t)get_ioa_addr_len(orig_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_iov->iov_base = buffer;
	msg.msg_iov->iov_len = sizeof(buffer);
	msg.msg_flags = 0;

	int try_cycle = 0;

	do {

		do {
			len = recvmsg(fd,&msg,flags);
		} while (len < 0 && (errno == EINTR));

	} while((len>0)&&(try_cycle++<MAX_ERRORS_IN_UDP_BATCH));

#endif

	return 0;
}

typedef unsigned char recv_ttl_t;
typedef unsigned char recv_tos_t;

int udp_recvfrom(evutil_socket_t fd, ioa_addr* orig_addr, const ioa_addr *like_addr, s08bits* buffer, int buf_size, int *ttl, int *tos, s08bits *ecmsg, int flags, u32bits *errcode)
{
	int len = 0;

	if (fd < 0 || !orig_addr || !like_addr || !buffer)
		return -1;

	if(errcode)
		*errcode = 0;

	int slen = get_ioa_addr_len(like_addr);
	recv_ttl_t recv_ttl = TTL_DEFAULT;
	recv_tos_t recv_tos = TOS_DEFAULT;

#if !defined(CMSG_SPACE)
	do {
	  len = recvfrom(fd, buffer, buf_size, flags, (struct sockaddr*) orig_addr, (socklen_t*) &slen);
	} while (len < 0 && (errno == EINTR));
	if(len<0 && errcode)
		*errcode = (u32bits)errno;
#else
	struct msghdr msg;
	struct iovec iov;

	char *cmsg = (char*)ecmsg;

	msg.msg_control = cmsg;
	msg.msg_controllen = TURN_CMSG_SZ;
	/* CMSG_SPACE(sizeof(recv_ttl)+sizeof(recv_tos)) */

	msg.msg_name = orig_addr;
	msg.msg_namelen = (socklen_t)slen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_iov->iov_base = buffer;
	msg.msg_iov->iov_len = (size_t)buf_size;
	msg.msg_flags = 0;

#if defined(MSG_ERRQUEUE)
	int try_cycle = 0;
	try_again:
#endif

	do {
		len = recvmsg(fd,&msg,flags);
	} while (len < 0 && (errno == EINTR));

#if defined(MSG_ERRQUEUE)

	if(flags & MSG_ERRQUEUE) {
			if((len>0)&&(try_cycle++<MAX_ERRORS_IN_UDP_BATCH)) goto try_again;
	}

	if((len<0) && (!(flags & MSG_ERRQUEUE))) {
		//Linux
		int eflags = MSG_ERRQUEUE | MSG_DONTWAIT;
		u32bits errcode1 = 0;
		udp_recvfrom(fd, orig_addr, like_addr, buffer, buf_size, ttl, tos, ecmsg, eflags, &errcode1);
		//try again...
		do {
			len = recvmsg(fd,&msg,flags);
		} while (len < 0 && (errno == EINTR));
	}
#endif

	if (len >= 0) {

		struct cmsghdr *cmsgh;

		// Receive auxiliary data in msg
		for (cmsgh = CMSG_FIRSTHDR(&msg); cmsgh != NULL; cmsgh
						= CMSG_NXTHDR(&msg,cmsgh)) {
			int l = cmsgh->cmsg_level;
			int t = cmsgh->cmsg_type;

			switch(l) {
			case IPPROTO_IP:
				switch(t) {
#if defined(IP_RECVTTL)
				case IP_RECVTTL:
				case IP_TTL:
					recv_ttl = *((recv_ttl_t *) CMSG_DATA(cmsgh));
					break;
#endif
#if defined(IP_RECVTOS)
				case IP_RECVTOS:
				case IP_TOS:
					recv_tos = *((recv_tos_t *) CMSG_DATA(cmsgh));
					break;
#endif
#if defined(IP_RECVERR)
				case IP_RECVERR:
				{
					struct turn_sock_extended_err *e=(struct turn_sock_extended_err*) CMSG_DATA(cmsgh);
					if(errcode)
						*errcode = e->ee_errno;
				}
					break;
#endif
				default:
					;
					/* no break */
				};
				break;
			case IPPROTO_IPV6:
				switch(t) {
#if defined(IPV6_RECVHOPLIMIT)
				case IPV6_RECVHOPLIMIT:
				case IPV6_HOPLIMIT:
					recv_ttl = *((recv_ttl_t *) CMSG_DATA(cmsgh));
					break;
#endif
#if defined(IPV6_RECVTCLASS)
				case IPV6_RECVTCLASS:
				case IPV6_TCLASS:
					recv_tos = *((recv_tos_t *) CMSG_DATA(cmsgh));
					break;
#endif
#if defined(IPV6_RECVERR)
				case IPV6_RECVERR:
				{
					struct turn_sock_extended_err *e=(struct turn_sock_extended_err*) CMSG_DATA(cmsgh);
					if(errcode)
						*errcode = e->ee_errno;
				}
					break;
#endif
				default:
					;
					/* no break */
				};
				break;
			default:
				;
				/* no break */
			};
		}
	}

#endif

	*ttl = recv_ttl;

	CORRECT_RAW_TTL(*ttl);

	*tos = recv_tos;

	CORRECT_RAW_TOS(*tos);

	return len;
}

#if !defined(TURN_NO_TLS)
static TURN_TLS_TYPE check_tentative_tls(ioa_socket_raw fd)
{
	TURN_TLS_TYPE ret = TURN_TLS_NO;

	char s[12];
	int len = 0;

	do {
		len = (int)recv(fd, s, sizeof(s), MSG_PEEK);
	} while (len < 0 && (errno == EINTR));

	if(len>0 && ((size_t)len == sizeof(s))) {
		if((s[0]==22)&&(s[1]==3)&&(s[5]==1)&&(s[9]==3)) {
			char max_supported = (char)(TURN_TLS_TOTAL-2);
			if(s[10] >= max_supported)
				ret = (TURN_TLS_TYPE)((((int)TURN_TLS_TOTAL)-1));
			else
				ret = (TURN_TLS_TYPE)(s[10]+1);
		} else if((s[2]==1)&&(s[3]==3)) {
			ret = TURN_TLS_SSL23; /* compatibility mode */
		}
	}

	return ret;
}
#endif

static int socket_input_worker(ioa_socket_handle s)
{
	int len = 0;
	int ret = 0;
	size_t app_msg_len = 0;
	int ttl = TTL_IGNORE;
	int tos = TOS_IGNORE;
	ioa_addr remote_addr;

	int try_again = 0;
	int try_ok = 0;
	int try_cycle = 0;
	const int MAX_TRIES = 16;

	if(!s)
		return 0;

	if(s->done) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, s->st, s->sat);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
		return -1;
	}

	if(!(s->e))
		return 0;

	if(s->tobeclosed)
		return 0;

	if(s->connected)
		addr_cpy(&remote_addr,&(s->remote_addr));

	if(s->st == TLS_SOCKET) {
#if !defined(TURN_NO_TLS)
		SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
		if(!ctx || SSL_get_shutdown(ctx)) {
			s->tobeclosed = 1;
			return 0;
		}
#endif
	} else if(s->st == DTLS_SOCKET) {
		if(!(s->ssl) || SSL_get_shutdown(s->ssl)) {
			s->tobeclosed = 1;
			return 0;
		}
	}

	if(!(s->e))
		return 0;

	if(s->st == TENTATIVE_TCP_SOCKET) {
		EVENT_DEL(s->read_event);
#if !defined(TURN_NO_TLS)
		TURN_TLS_TYPE tls_type = check_tentative_tls(s->fd);
		if(tls_type) {
			s->st = TLS_SOCKET;
			if(s->ssl) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: 0x%lx, st=%d, sat=%d: ssl already exist\n", __FUNCTION__,(long)s, s->st, s->sat);
			}
			if(s->bev) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: 0x%lx, st=%d, sat=%d: bev already exist\n", __FUNCTION__,(long)s, s->st, s->sat);
			}
			switch(tls_type) {
			case TURN_TLS_v1_0:
				s->ssl = SSL_new(s->e->tls_ctx_v1_0);
				STRCPY(s->orig_ctx_type,"TLSv1.0");
				break;
#if defined(SSL_TXT_TLSV1_1)
			case TURN_TLS_v1_1:
				s->ssl = SSL_new(s->e->tls_ctx_v1_1);
				STRCPY(s->orig_ctx_type,"TLSv1.1");
				break;
#if defined(SSL_TXT_TLSV1_2)
			case TURN_TLS_v1_2:
				s->ssl = SSL_new(s->e->tls_ctx_v1_2);
				STRCPY(s->orig_ctx_type,"TLSv1.2");
				break;
#endif
#endif
			default:
				s->ssl = SSL_new(s->e->tls_ctx_ssl23);
				STRCPY(s->orig_ctx_type,"SSLv23");
			};
			s->bev = bufferevent_openssl_socket_new(s->e->event_base,
								s->fd,
								s->ssl,
								BUFFEREVENT_SSL_ACCEPTING,
								BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
			bufferevent_setcb(s->bev, socket_input_handler_bev, NULL,
					eventcb_bev, s);
			bufferevent_setwatermark(s->bev, EV_READ, 1, BUFFEREVENT_HIGH_WATERMARK);
			bufferevent_enable(s->bev, EV_READ); /* Start reading. */
		} else
#endif //TURN_NO_TLS
		{
			s->st = TCP_SOCKET;
			if(s->bev) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: 0x%lx, st=%d, sat=%d: bev already exist\n", __FUNCTION__,(long)s, s->st, s->sat);
			}
			s->bev = bufferevent_socket_new(s->e->event_base,
							s->fd,
							BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
			bufferevent_setcb(s->bev, socket_input_handler_bev, NULL,
					eventcb_bev, s);
			bufferevent_setwatermark(s->bev, EV_READ, 1, BUFFEREVENT_HIGH_WATERMARK);
			bufferevent_enable(s->bev, EV_READ); /* Start reading. */
		}
	}

	try_start:

	if(!(s->e))
		return 0;

	try_again=0;
	try_ok=0;

	stun_buffer_list_elem *elem = new_blist_elem(s->e);
	len = -1;

	if(s->bev) { /* TCP & TLS */
		struct evbuffer *inbuf = bufferevent_get_input(s->bev);
		if(inbuf) {
			ev_ssize_t blen = evbuffer_copyout(inbuf, elem->buf.buf, STUN_BUFFER_SIZE);
			if(blen>0) {
				int mlen = 0;

				if(blen>(ev_ssize_t)STUN_BUFFER_SIZE)
				  blen=(ev_ssize_t)STUN_BUFFER_SIZE;

				if(((s->st == TCP_SOCKET)||(s->st == TLS_SOCKET)) && ((s->sat == TCP_CLIENT_DATA_SOCKET)||(s->sat==TCP_RELAY_DATA_SOCKET))) {
					mlen = blen;
				} else {
					mlen = stun_get_message_len_str(elem->buf.buf, blen, 1, &app_msg_len);
				}

				if(mlen>0 && mlen<=(int)blen) {
					len = (int)bufferevent_read(s->bev, elem->buf.buf, mlen);
					if(len < 0) {
						ret = -1;
						s->tobeclosed = 1;
						s->broken = 1;
					} else if(s->st == TLS_SOCKET) {
#if !defined(TURN_NO_TLS)
						SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
						if(!ctx || SSL_get_shutdown(ctx)) {
							ret = -1;
							s->tobeclosed = 1;
						}
#endif
					}
					if(ret != -1) {
						ret = len;
					}
				}

			} else if(blen<0) {
				s->tobeclosed = 1;
				s->broken = 1;
				ret = -1;
			}
		} else {
			s->tobeclosed = 1;
			s->broken = 1;
			ret = -1;
		}

		if(len == 0)
			len = -1;
	} else if(s->fd>=0){ /* UDP and DTLS */
		ret = udp_recvfrom(s->fd, &remote_addr, &(s->local_addr), (s08bits*)(elem->buf.buf), STUN_BUFFER_SIZE, &ttl, &tos, s->e->cmsg, 0, NULL);
		len = ret;
		if(s->ssl && (len>0)) { /* DTLS */
			send_ssl_backlog_buffers(s);
			ret = ssl_read(s->fd, s->ssl, (s08bits*)(elem->buf.buf), STUN_BUFFER_SIZE, s->e->verbose, &len);
			addr_cpy(&remote_addr,&(s->remote_addr));
			if(ret < 0) {
				s->tobeclosed = 1;
				s->broken = 1;
			}
			if((ret!=-1)&&(len>0))
				try_again = 1;
		} else { /* UDP */
			if(ret>=0)
				try_again = 1;
		}
	} else {
		s->tobeclosed = 1;
		s->broken = 1;
		ret = -1;
	}

	if ((ret!=-1) && (len >= 0)) {
		if(ioa_socket_check_bandwidth(s,(size_t)len)) {
			if(app_msg_len)
				elem->buf.len = app_msg_len;
			else
				elem->buf.len = len;

			if(s->read_cb) {
				ioa_net_data nd;

				ns_bzero(&nd,sizeof(ioa_net_data));
				addr_cpy(&(nd.src_addr),&remote_addr);
				nd.nbh = elem;
				nd.recv_ttl = ttl;
				nd.recv_tos = tos;

				s->read_cb(s, IOA_EV_READ, &nd, s->read_ctx);

				if(nd.nbh)
					free_blist_elem(s->e,elem);

				elem = NULL;

				try_ok = 1;

			} else {
				ioa_network_buffer_delete(s->e, s->defer_nbh);
				s->defer_nbh = elem;
				elem = NULL;
			}
		}
	}

	if(elem) {
		free_blist_elem(s->e,elem);
		elem = NULL;
	}

	if(try_again && try_ok && !(s->done) &&
		!(s->tobeclosed) && ((++try_cycle)<MAX_TRIES) &&
		!(s->parent_s)) {
		goto try_start;
	}

	return len;
}

static void socket_input_handler(evutil_socket_t fd, short what, void* arg)
{

	if (!(what & EV_READ))
		return;

	if(!arg) {
		read_spare_buffer(fd);
		return;
	}

	ioa_socket_handle s = (ioa_socket_handle)arg;

	if(!s)
		return;

	if(s->done) {
		read_spare_buffer(fd);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket, ev=%d: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(int)what,(long)s, s->st, s->sat);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
		return;
	}

	if(fd != s->fd) {
		read_spare_buffer(fd);
		return;
	}

	if (!ioa_socket_tobeclosed(s))
		socket_input_worker(s);

	if(s->done) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s (1) on socket, ev=%d: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(int)what,(long)s, s->st, s->sat);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
		return;
	}

	close_ioa_socket_after_processing_if_necessary(s);
}

void close_ioa_socket_after_processing_if_necessary(ioa_socket_handle s)
{
	if (s && ioa_socket_tobeclosed(s)) {
		switch (s->sat){
		case TCP_CLIENT_DATA_SOCKET:
		case TCP_RELAY_DATA_SOCKET:
		{
			tcp_connection *tc = (tcp_connection *) (s->sub_session);
			if (tc) {
				s->sub_session = NULL;
				s->session = NULL;
				delete_tcp_connection(tc);
			}
		}
			break;
		default:
		{
			ts_ur_super_session *ss = (ts_ur_super_session *) (s->session);
			if (ss) {
				turn_turnserver *server = (turn_turnserver *) ss->server;
				if (server) {
					s->session = NULL;
					s->sub_session = NULL;
					shutdown_client_connection(server, ss, 0);
				}
			}
		}
		}
	}
}

static void socket_input_handler_bev(struct bufferevent *bev, void* arg)
{

	if (bev && arg) {

		ioa_socket_handle s = (ioa_socket_handle) arg;

		if (s->done) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__, (long) s, s->st, s->sat);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
			return;
		}

		while (!ioa_socket_tobeclosed(s)) {
			if (socket_input_worker(s) <= 0)
				break;
		}

		if (s->done) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s (1) on socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__, (long) s, s->st, s->sat);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
			return;
		}

		if (ioa_socket_tobeclosed(s)) {
			switch(s->sat) {
			case TCP_CLIENT_DATA_SOCKET:
			case TCP_RELAY_DATA_SOCKET:
			{
				tcp_connection *tc = (tcp_connection *)(s->sub_session);
				if(tc) {
					s->sub_session = NULL;
					s->session = NULL;
					delete_tcp_connection(tc);
				}
			}
			break;
			default:
			{
				ts_ur_super_session *ss = (ts_ur_super_session *)(s->session);
				if (ss) {
					turn_turnserver *server = (turn_turnserver *)ss->server;
					if (server) {
						s->session=NULL;
						s->sub_session=NULL;
						shutdown_client_connection(server, ss, 0);
					}
				}
			}
			}
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
			ioa_socket_handle s = (ioa_socket_handle) arg;

			if (s->done) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: closed socket: 0x%lx (1): done=%d, fd=%d, br=%d, st=%d, sat=%d, tbc=%d\n", __FUNCTION__, (long) s, (int) s->done,
								(int) s->fd, s->broken, s->st, s->sat, s->tobeclosed);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
				return;
			}

			if (events == BEV_EVENT_ERROR)
				s->broken = 1;

			switch (s->sat){
			case TCP_CLIENT_DATA_SOCKET:
			case TCP_RELAY_DATA_SOCKET:
			{
				tcp_connection *tc = (tcp_connection *) (s->sub_session);
				if (tc) {
					s->sub_session = NULL;
					s->session = NULL;
					delete_tcp_connection(tc);
				}
			}
				break;
			default:
			{
				ts_ur_super_session *ss = (ts_ur_super_session *) (s->session);
				if (ss) {
					turn_turnserver *server = (turn_turnserver *) ss->server;
					if (server) {
						s->session = NULL;
						s->sub_session = NULL;
						shutdown_client_connection(server, ss, 0);
					}
				}
			}
			}
		}
	}
}

static int ssl_send(ioa_socket_handle s, const s08bits* buffer, int len, int verbose)
{

	if (!s || !(s->ssl) || !buffer)
		return -1;

	SSL *ssl = s->ssl;

	if (eve(verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: before write: buffer=0x%lx, len=%d\n", __FUNCTION__,(long)buffer,len);
	}

	if(s->parent_s) {
		/* Trick only for "children" sockets: */
		BIO *wbio = SSL_get_wbio(ssl);
		if(!wbio)
			return -1;
		int fd = BIO_get_fd(wbio,0);
		int sfd = s->parent_s->fd;
		if(sfd >= 0) {
			if(fd != sfd) {
				BIO_set_fd(wbio,sfd,BIO_NOCLOSE);
			}
		}
	}

	int rc = 0;
	int try_again = 1;

#if !defined(TURN_IP_RECVERR)
	try_again = 0;
#endif

	try_start:

	do {
		rc = SSL_write(ssl, buffer, len);
	} while (rc < 0 && errno == EINTR);

	if (eve(verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: after write: %d\n", __FUNCTION__,rc);
	}

	if (rc < 0 && ((errno == ENOBUFS) || (errno == EAGAIN))) {
		if (eve(verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: ENOBUFS/EAGAIN\n", __FUNCTION__);
		}
		return 0;
	}

	if (rc >= 0) {

		if (eve(verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrote %d bytes\n", __FUNCTION__, (int) rc);
		}

		return rc;

	} else {

		if (eve(verbose)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: failure: rc=%d, err=%d\n", __FUNCTION__, (int)rc,(int)SSL_get_error(ssl, rc));
		}

		switch (SSL_get_error(ssl, rc)){
		case SSL_ERROR_NONE:
			//???
			if (eve(verbose)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "wrote %d bytes\n", (int) rc);
			}
			return 0;
		case SSL_ERROR_WANT_WRITE:
			return 0;
		case SSL_ERROR_WANT_READ:
			return 0;
		case SSL_ERROR_SYSCALL:
		{
			int err = errno;
			if (!handle_socket_error()) {
				if(s->st == DTLS_SOCKET) {
					if(is_connreset()) {
						if(try_again) {
							BIO *wbio = SSL_get_wbio(ssl);
							if(wbio) {
								int fd = BIO_get_fd(wbio,0);
								if(fd>=0) {
									try_again = 0;
									TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket, tring to recover write operation...\n");
									socket_readerr(fd, &(s->local_addr));
									goto try_start;
								}
							}
						}
					}
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket lost packet... fine\n");
					return 0;
				}
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket write error unrecoverable: %d; buffer=0x%lx, len=%d, ssl=0x%lx\n", err, (long)buffer, (int)len, (long)ssl);
				return -1;
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket write error recoverable: %d\n", err);
				return 0;
			}
		}
		case SSL_ERROR_SSL:
			if (verbose) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: ");
				s08bits buf[65536];
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n", ERR_error_string(ERR_get_error(), buf),
								SSL_get_error(ssl, rc));
			}
			return -1;
		default:
			if (verbose) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error while writing!\n");
			}
			return -1;
		}
	}
}

static int send_ssl_backlog_buffers(ioa_socket_handle s)
{
	int ret = 0;
	if(s) {
		stun_buffer_list_elem *elem = s->bufs.head;
		while(elem) {
			int rc = ssl_send(s, (s08bits*)elem->buf.buf, (size_t)elem->buf.len, s->e->verbose);
			if(rc<1)
				break;
			++ret;
			pop_elem_from_buffer_list(&(s->bufs));
			elem = s->bufs.head;
		}
	}

	return ret;
}

int is_connreset(void) {
	switch (errno) {
	case ECONNRESET:
	case ECONNREFUSED:
		return 1;
	default:
		;
	}
	return 0;
}

int would_block(void) {
#if defined(EWOULDBLOCK)
	if(errno == EWOULDBLOCK)
		return 1;
#endif
	return (errno == EAGAIN);
}

int udp_send(ioa_socket_handle s, const ioa_addr* dest_addr, const s08bits* buffer, int len)
{
	int rc = 0;
	evutil_socket_t fd = -1;

	if(!s)
		return -1;

	if(s->parent_s)
		fd = s->parent_s->fd;
	else
		fd = s->fd;

	if(fd>=0) {

		int try_again = 1;

		int cycle;

#if !defined(TURN_IP_RECVERR)
		try_again = 0;
#endif

		try_start:

		cycle = 0;

		if (dest_addr) {

			int slen = get_ioa_addr_len(dest_addr);

			do {
				rc = sendto(fd, buffer, len, 0, (const struct sockaddr*) dest_addr, (socklen_t) slen);
			} while (
					((rc < 0) && (errno == EINTR)) ||
					((rc<0) && is_connreset() && (++cycle<TRIAL_EFFORTS_TO_SEND))
					);

		} else {
			do {
				rc = send(fd, buffer, len, 0);
			} while (
					((rc < 0) && (errno == EINTR)) ||
					((rc<0) && is_connreset() && (++cycle<TRIAL_EFFORTS_TO_SEND))
					);
		}

		if(rc<0) {
			if((errno == ENOBUFS) || (errno == EAGAIN)) {
				//Lost packet due to overload ... fine.
				rc = len;
			} else if(is_connreset()) {
				if(try_again) {
					try_again = 0;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "UDP Socket, tring to recover write operation...\n");
					socket_readerr(fd, &(s->local_addr));
					goto try_start;
				}
				//Lost packet - sent to nowhere... fine.
				rc = len;
			}
		}
	}

	return rc;
}

int send_data_from_ioa_socket_nbh(ioa_socket_handle s, ioa_addr* dest_addr,
				ioa_network_buffer_handle nbh,
				int ttl, int tos)
{
	int ret = -1;

	if(!s)
		return -1;

	if (s->done || (s->fd == -1)) {
		TURN_LOG_FUNC(
				TURN_LOG_LEVEL_INFO,
				"!!! %s: (1) Trying to send data from closed socket: 0x%lx (1): done=%d, fd=%d, st=%d, sat=%d\n",
				__FUNCTION__, (long) s, (int) s->done,
				(int) s->fd, s->st, s->sat);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);

	} else if (nbh) {
		if(!ioa_socket_check_bandwidth(s,ioa_network_buffer_get_size(nbh))) {
			/* Bandwidth exhausted, we pretend everything is fine: */
			ret = (int)(ioa_network_buffer_get_size(nbh));
		} else {
			if (!ioa_socket_tobeclosed(s) && s->e) {

				if (!(s->done || (s->fd == -1))) {
					set_socket_ttl(s, ttl);
					set_socket_tos(s, tos);

					if (s->connected && s->bev) {
						if (s->st == TLS_SOCKET) {
#if !defined(TURN_NO_TLS)
							SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
							if (!ctx || SSL_get_shutdown(ctx)) {
								s->tobeclosed = 1;
								ret = 0;
							}
#endif
						}

						if (!(s->tobeclosed)) {
							if (bufferevent_write(
										s->bev,
										ioa_network_buffer_data(nbh),
										ioa_network_buffer_get_size(nbh))
											< 0) {
								ret = -1;
								perror("bufev send");
								s->tobeclosed = 1;
								s->broken = 1;
							} else {
								ret = (int) ioa_network_buffer_get_size(nbh);
							}
						}
					} else if (s->ssl) {
						send_ssl_backlog_buffers(s);
						ret = ssl_send(
								s,
								(s08bits*) ioa_network_buffer_data(nbh),
								ioa_network_buffer_get_size(nbh),
								s->e->verbose);
						if (ret < 0)
							s->tobeclosed = 1;
						else if (ret == 0)
							add_buffer_to_buffer_list(
									&(s->bufs),
									(s08bits*) ioa_network_buffer_data(nbh),
									ioa_network_buffer_get_size(nbh));
					} else if (s->fd >= 0) {

						if (s->connected && !(s->parent_s)) {
							dest_addr = NULL; /* ignore dest_addr */
						} else if (!dest_addr) {
							dest_addr = &(s->remote_addr);
						}

						ret = udp_send(s,
									dest_addr,
									(s08bits*) ioa_network_buffer_data(nbh),ioa_network_buffer_get_size(nbh));
						if (ret < 0) {
							s->tobeclosed = 1;
#if defined(EADDRNOTAVAIL)
							int perr=errno;
#endif
							perror("udp send");
#if defined(EADDRNOTAVAIL)
							if(dest_addr && (perr==EADDRNOTAVAIL)) {
							  char sfrom[129];
							  addr_to_string(&(s->local_addr), (u08bits*)sfrom);
							  char sto[129];
							  addr_to_string(dest_addr, (u08bits*)sto);
							  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
									"%s: network error: address unreachable from %s to %s\n", 
									__FUNCTION__,sfrom,sto);
							}
#endif
						}
					}
				}
			}
		}
	}

	ioa_network_buffer_delete(s->e, nbh);

	return ret;
}

int register_callback_on_ioa_socket(ioa_engine_handle e, ioa_socket_handle s, int event_type, ioa_net_event_handler cb, void* ctx, int clean_preexisting)
{
	if(s) {

		if (event_type & IOA_EV_READ) {

			if(e)
				s->e = e;

			if(s->e && !(s->parent_s)) {

				switch(s->st) {
				case DTLS_SOCKET:
				case UDP_SOCKET:
					if(s->read_event) {
						if(!clean_preexisting) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 1\n", __FUNCTION__);
							return -1;
						}
					} else {
						s->read_event = event_new(s->e->event_base,s->fd, EV_READ|EV_PERSIST, socket_input_handler, s);
						event_add(s->read_event,NULL);
					}
					break;
				case TENTATIVE_TCP_SOCKET:
					if(s->bev) {
						if(!clean_preexisting) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 2\n", __FUNCTION__);
							return -1;
						}
					} else if(s->read_event) {
						if(!clean_preexisting) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 3\n", __FUNCTION__);
							return -1;
						}
					} else {
						s->read_event = event_new(s->e->event_base,s->fd, EV_READ|EV_PERSIST, socket_input_handler, s);
						event_add(s->read_event,NULL);
					}
					break;
				case TCP_SOCKET:
					if(s->bev) {
						if(!clean_preexisting) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 4\n", __FUNCTION__);
							return -1;
						}
					} else {
						s->bev = bufferevent_socket_new(s->e->event_base,
										s->fd,
										BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
						bufferevent_setcb(s->bev, socket_input_handler_bev, NULL,
							eventcb_bev, s);
						bufferevent_setwatermark(s->bev, EV_READ, 1, BUFFEREVENT_HIGH_WATERMARK);
						bufferevent_enable(s->bev, EV_READ); /* Start reading. */
					}
					break;
				case TLS_SOCKET:
					if(s->bev) {
						if(!clean_preexisting) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
								"%s: software error: buffer preset 5\n", __FUNCTION__);
							return -1;
						}
					} else {
#if !defined(TURN_NO_TLS)
						if(!(s->ssl)) {
							//??? how we can get to this point ???
							s->ssl = SSL_new(e->tls_ctx_ssl23);
							STRCPY(s->orig_ctx_type,"SSLv23");
							s->bev = bufferevent_openssl_socket_new(s->e->event_base,
											s->fd,
											s->ssl,
											BUFFEREVENT_SSL_ACCEPTING,
											BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
						} else {
							s->bev = bufferevent_openssl_socket_new(s->e->event_base,
											s->fd,
											s->ssl,
											BUFFEREVENT_SSL_OPEN,
											BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
						}
						bufferevent_setcb(s->bev, socket_input_handler_bev, NULL,
							eventcb_bev, s);
						bufferevent_setwatermark(s->bev, EV_READ, 1, BUFFEREVENT_HIGH_WATERMARK);
						bufferevent_enable(s->bev, EV_READ); /* Start reading. */
#endif
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

	/* unsupported event or else */
	return -1;
}

int ioa_socket_tobeclosed_func(ioa_socket_handle s, const char *func, const char *file, int line)
{
	if(s) {
		if(s->magic != SOCKET_MAGIC) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: from %s:%s:%d: magic is wrong on the socket: 0x%lx, st=%d, sat=%d\n",__FUNCTION__,func,file,line,(long)s,s->st,s->sat);
			return 1;
		}

		if(s->done) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: from %s:%s:%d: check on already closed socket: 0x%lx, st=%d, sat=%d\n",__FUNCTION__,func,file,line,(long)s,s->st,s->sat);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: 0x%lx was closed at %s;%s:%d\n", __FUNCTION__,(long)s, s->func,s->file,s->line);
			return 1;
		}
		if(s->broken)
			return 1;
		if(s->tobeclosed)
			return 1;
		if(s->fd < 0) {
			return 1;
		}
		if(s->ssl) {
			if(SSL_get_shutdown(s->ssl))
				return 1;
		}
	}
	return 0;
}

void set_ioa_socket_tobeclosed(ioa_socket_handle s)
{
	if(s)
		s->tobeclosed = 1;
}

/*
 * Network buffer functions
 */
ioa_network_buffer_handle ioa_network_buffer_allocate(ioa_engine_handle e)
{
	stun_buffer_list_elem *elem = new_blist_elem(e);
	elem->buf.len = 0;
	return elem;
}

/* We do not use special header in this simple implementation */
void ioa_network_buffer_header_init(ioa_network_buffer_handle nbh)
{
	UNUSED_ARG(nbh);
}

u08bits *ioa_network_buffer_data(ioa_network_buffer_handle nbh)
{
  stun_buffer_list_elem *elem = (stun_buffer_list_elem *)nbh;
	return elem->buf.buf;
}

size_t ioa_network_buffer_get_size(ioa_network_buffer_handle nbh)
{
	if(!nbh)
		return 0;
	else {
	  stun_buffer_list_elem *elem = (stun_buffer_list_elem *)nbh;
		return (size_t)(elem->buf.len);
	}
}

size_t ioa_network_buffer_get_capacity(void)
{
	return STUN_BUFFER_SIZE;
}

void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len)
{
  stun_buffer_list_elem *elem = (stun_buffer_list_elem *)nbh;
  elem->buf.len=(ssize_t)len;
}
void ioa_network_buffer_delete(ioa_engine_handle e, ioa_network_buffer_handle nbh) {
  stun_buffer_list_elem *elem = (stun_buffer_list_elem *)nbh;
  free_blist_elem(e,elem);
}

/////////// REPORTING STATUS /////////////////////

static inline u32bits get_allocation_id(allocation *a)
{
	return (u32bits)(kh_int64_hash_func((u64bits)((unsigned long)a)));
}

void turn_report_allocation_set(void *a, turn_time_t lifetime, int refresh)
{
	if(a) {
		ts_ur_super_session *ss = (ts_ur_super_session*)(((allocation*)a)->owner);
		if(ss) {
			const char* status="new";
			if(refresh)
				status="refreshed";
			turn_turnserver *server = (turn_turnserver*)ss->server;
			if(server) {
				ioa_engine_handle e = turn_server_get_engine(server);
				if(e && e->verbose) {
					if(ss->client_session.s->ssl) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s Allocation: id=0x%lx, username=<%s>, lifetime=%lu, cipher=%s, method=%s (%s)\n", status, get_allocation_id((allocation*)a), (char*)ss->username, (unsigned long)lifetime, SSL_get_cipher(ss->client_session.s->ssl), turn_get_ssl_method(ss->client_session.s->ssl),ss->client_session.s->orig_ctx_type);
					} else {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s Allocation: id=0x%lx, username=<%s>, lifetime=%lu\n", status, get_allocation_id((allocation*)a), (char*)ss->username, (unsigned long)lifetime);
					}
				}
			}
#if !defined(TURN_NO_HIREDIS)
			if(default_async_context_is_not_empty()) {
				char key[1024];
				snprintf(key,sizeof(key),"turn/user/%s/allocation/0x%lx/status",(char*)ss->username, (unsigned long)get_allocation_id((allocation*)a));
				send_message_to_redis(NULL, "set", key, "%s lifetime=%lu", status, (unsigned long)lifetime);
				send_message_to_redis(NULL, "publish", key, "%s lifetime=%lu", status, (unsigned long)lifetime);
			}
#endif
		}
	}
}

void turn_report_allocation_delete(void *a)
{
	if(a) {
		ts_ur_super_session *ss = (ts_ur_super_session*)(((allocation*)a)->owner);
		if(ss) {
			turn_turnserver *server = (turn_turnserver*)ss->server;
			if(server) {
				ioa_engine_handle e = turn_server_get_engine(server);
				if(e && e->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Delete Allocation: id=0x%lx, username=<%s>\n", get_allocation_id((allocation*)a), (char*)ss->username);
				}
			}
#if !defined(TURN_NO_HIREDIS)
			if(default_async_context_is_not_empty()) {
				char key[1024];
				snprintf(key,sizeof(key),"turn/user/%s/allocation/0x%lx/status",(char*)ss->username, (unsigned long)get_allocation_id((allocation*)a));
				send_message_to_redis(NULL, "del", key, "");
				send_message_to_redis(NULL, "publish", key, "deleted");
			}
#endif
		}
	}
}

void turn_report_allocation_delete_all(void)
{
#if !defined(TURN_NO_HIREDIS)
	delete_redis_keys("turn/user/*/allocation/*/status");
#endif
}

void turn_report_session_usage(void *session)
{
	if(session) {
		ts_ur_super_session *ss = (ts_ur_super_session *)session;
		turn_turnserver *server = (turn_turnserver*)ss->server;
		if(server && (ss->received_packets || ss->sent_packets)) {
			ioa_engine_handle e = turn_server_get_engine(server);
			allocation *a = &(ss->alloc);
			if(((ss->received_packets+ss->sent_packets)&2047)==0) {
				if(e && e->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Session allocation id=0x%lx, username=<%s>, rp=%lu, rb=%lu, sp=%lu, sb=%lu\n", get_allocation_id(a), (char*)ss->username, (unsigned long)(ss->received_packets), (unsigned long)(ss->received_bytes),(unsigned long)(ss->sent_packets),(unsigned long)(ss->sent_bytes));
				}
#if !defined(TURN_NO_HIREDIS)
				if(default_async_context_is_not_empty()) {
					char key[1024];
					snprintf(key,sizeof(key),"turn/user/%s/allocation/0x%lx/traffic",(char*)ss->username, (unsigned long)get_allocation_id((allocation*)a));
					send_message_to_redis(NULL, "publish", key, "rcvp=%lu, rcvb=%lu, sentp=%lu, sentb=%lu",(unsigned long)(ss->received_packets), (unsigned long)(ss->received_bytes),(unsigned long)(ss->sent_packets),(unsigned long)(ss->sent_bytes));
				}
#endif
				ss->received_packets=0;
				ss->received_bytes=0;
				ss->sent_packets=0;
				ss->sent_bytes=0;
			}
		}
	}
}

//////////////////////////////////////////////////
