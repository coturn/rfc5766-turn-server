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

#include "mainrelay.h"

//////////// Barrier for the threads //////////////

#if !defined(TURN_NO_THREAD_BARRIERS)
static unsigned int barrier_count = 0;
static pthread_barrier_t barrier;
#endif

//////////////////////////////////////////////

#define get_real_general_relay_servers_number() (general_relay_servers_number > 1 ? general_relay_servers_number : 1)
#define get_real_udp_relay_servers_number() (udp_relay_servers_number > 1 ? udp_relay_servers_number : 1)

struct relay_server {
	turnserver_id id;
	struct event_base* event_base;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	struct bufferevent *auth_in_buf;
	struct bufferevent *auth_out_buf;
	ioa_engine_handle ioa_eng;
	turn_turnserver *server;
	pthread_t thr;
};

static struct relay_server **general_relay_servers = NULL;
static struct relay_server **udp_relay_servers = NULL;

//////////////////////////////////////////////

static void run_events(struct event_base *eb);
static void setup_relay_server(struct relay_server *rs, ioa_engine_handle e, int to_set_rfc5780);

/////////////// AUX SERVERS ////////////////

static void add_aux_server_list(const char *saddr, turn_server_addrs_list_t *list)
{
	if(saddr && list) {
		ioa_addr addr;
		if(make_ioa_addr_from_full_string((const u08bits*)saddr, 0, &addr)!=0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong full address format: %s\n",saddr);
		} else {
			list->addrs = (ioa_addr*)realloc(list->addrs,sizeof(ioa_addr)*(list->size+1));
			addr_cpy(&(list->addrs[(list->size)++]),&addr);
			{
				u08bits s[1025];
				addr_to_string(&addr, s);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Aux server: %s\n",s);
			}
		}
	}
}

void add_aux_server(const char *saddr)
{
	add_aux_server_list(saddr,&aux_servers_list);
}

/////////////// ALTERNATE SERVERS ////////////////

static void add_alt_server(const char *saddr, int default_port, turn_server_addrs_list_t *list)
{
	if(saddr && list) {
		ioa_addr addr;
		if(make_ioa_addr_from_full_string((const u08bits*)saddr, default_port, &addr)!=0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong full address format: %s\n",saddr);
		} else {
			list->addrs = (ioa_addr*)realloc(list->addrs,sizeof(ioa_addr)*(list->size+1));
			addr_cpy(&(list->addrs[(list->size)++]),&addr);
			{
				u08bits s[1025];
				addr_to_string(&addr, s);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Alternate server: %s\n",s);
			}
		}
	}
}

void add_alternate_server(const char *saddr)
{
	add_alt_server(saddr,DEFAULT_STUN_PORT,&alternate_servers_list);
}

void add_tls_alternate_server(const char *saddr)
{
	add_alt_server(saddr,DEFAULT_STUN_TLS_PORT,&tls_alternate_servers_list);
}

//////////////////////////////////////////////////

void add_listener_addr(const char* addr) {
	ioa_addr baddr;
	if(make_ioa_addr((const u08bits*)addr,0,&baddr)<0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot add a listener address: %s\n",addr);
	} else {
		++listener.addrs_number;
		++listener.services_number;
		listener.addrs = (char**)realloc(listener.addrs, sizeof(char*)*listener.addrs_number);
		listener.addrs[listener.addrs_number-1]=strdup(addr);
		listener.encaddrs = (ioa_addr**)realloc(listener.encaddrs, sizeof(ioa_addr*)*listener.addrs_number);
		listener.encaddrs[listener.addrs_number-1]=(ioa_addr*)turn_malloc(sizeof(ioa_addr));
		addr_cpy(listener.encaddrs[listener.addrs_number-1],&baddr);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Listener address to use: %s\n",addr);
	}
}

void add_relay_addr(const char* addr) {
	ioa_addr baddr;
	if(make_ioa_addr((const u08bits*)addr,0,&baddr)<0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot add a relay address: %s\n",addr);
	} else {
		++relays_number;
		relay_addrs = (char**)realloc(relay_addrs, sizeof(char*)*relays_number);
		relay_addrs[relays_number-1]=strdup(addr);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Relay address to use: %s\n",addr);
	}
}

//////////////////////////////////////////////////

// communications between listener and relays ==>>

static int handle_relay_message(relay_server_handle rs, struct message_to_relay *sm);

void send_auth_message_to_auth_server(struct auth_message *am)
{
	struct evbuffer *output = bufferevent_get_output(authserver.out_buf);
	if(evbuffer_add(output,am,sizeof(struct auth_message))<0) {
		fprintf(stderr,"%s: Weird buffer error\n",__FUNCTION__);
	}
}

static void auth_server_receive_message(struct bufferevent *bev, void *ptr)
{
	UNUSED_ARG(ptr);

	struct auth_message am;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);

	while ((n = evbuffer_remove(input, &am, sizeof(struct auth_message))) > 0) {
		if (n != sizeof(struct auth_message)) {
			fprintf(stderr,"%s: Weird buffer error: size=%d\n",__FUNCTION__,n);
			continue;
		}

		if(use_st_credentials) {
			st_password_t pwd;
			if(get_user_pwd(am.username,pwd)<0) {
				am.success = 0;
			} else {
				ns_bcopy(pwd,am.pwd,sizeof(st_password_t));
				am.success = 1;
			}
		} else {
			hmackey_t key;
			if(get_user_key(am.username,key,am.in_buffer.nbh)<0) {
				am.success = 0;
			} else {
				ns_bcopy(key,am.key,sizeof(hmackey_t));
				am.success = 1;
			}
		}

		size_t dest = am.id;

		struct evbuffer *output = NULL;

		if(dest>=TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP) {
			dest -= TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP;
			if(dest >= get_real_udp_relay_servers_number()) {
					TURN_LOG_FUNC(
								TURN_LOG_LEVEL_ERROR,
								"%s: Too large UDP relay number: %d\n",
									__FUNCTION__,(int)dest);
			} else {
				output = bufferevent_get_output(udp_relay_servers[dest]->auth_out_buf);
			}
		} else {
			if(dest >= get_real_general_relay_servers_number()) {
					TURN_LOG_FUNC(
							TURN_LOG_LEVEL_ERROR,
							"%s: Too large general relay number: %d\n",
										__FUNCTION__,(int)dest);
			} else {
				output = bufferevent_get_output(general_relay_servers[dest]->auth_out_buf);
			}
		}

		if(output)
			evbuffer_add(output,&am,sizeof(struct auth_message));
	}
}

static int send_socket_to_general_relay(ioa_engine_handle e, struct message_to_relay *sm)
{
	size_t dest = (hash_int32(addr_get_port(&(sm->m.sm.nd.src_addr)))) % get_real_general_relay_servers_number();

	struct message_to_relay *smptr = sm;

	smptr->t = RMT_SOCKET;

	{
		struct evbuffer *output = NULL;
		int success = 0;

		output = bufferevent_get_output(general_relay_servers[dest]->out_buf);

		if(output) {

			if(evbuffer_add(output,smptr,sizeof(struct message_to_relay))<0) {
				TURN_LOG_FUNC(
					TURN_LOG_LEVEL_ERROR,
					"%s: Cannot add message to relay output buffer\n",
					__FUNCTION__);
			} else {

				success = 1;
				smptr->m.sm.nd.nbh=NULL;
			}

		}

		if(!success) {
			ioa_network_buffer_delete(e, smptr->m.sm.nd.nbh);
			smptr->m.sm.nd.nbh=NULL;

			if(get_ioa_socket_type(smptr->m.sm.s) != UDP_SOCKET) {
				IOA_CLOSE_SOCKET(smptr->m.sm.s);
			}

			return -1;
		}
	}

	return 0;
}

static int send_socket_to_relay(turnserver_id id, u64bits cid, stun_tid *tid, ioa_socket_handle s, int message_integrity, MESSAGE_TO_RELAY_TYPE rmt, ioa_net_data *nd)
{
	int ret = 0;

	struct message_to_relay sm;
	ns_bzero(&sm,sizeof(struct message_to_relay));
	sm.t = rmt;

	struct relay_server *rs = NULL;
	if(id>=TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP) {
		size_t dest = id-TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP;
		if(dest >= get_real_udp_relay_servers_number()) {
			TURN_LOG_FUNC(
					TURN_LOG_LEVEL_ERROR,
					"%s: Too large UDP relay number: %d, rmt=%d\n",
					__FUNCTION__,(int)dest,(int)rmt);
			dest=0;
		}
		rs = udp_relay_servers[dest];
	} else {
		size_t dest = id;
		if(dest >= get_real_general_relay_servers_number()) {
			TURN_LOG_FUNC(
					TURN_LOG_LEVEL_ERROR,
					"%s: Too large general relay number: %d, rmt=%d\n",
					__FUNCTION__,(int)dest,(int)rmt);
			dest=0;
		}
		rs = general_relay_servers[dest];
	}

	switch (rmt) {
	case(RMT_CB_SOCKET): {

		sm.m.cb_sm.id = id;
		sm.m.cb_sm.connection_id = (tcp_connection_id)cid;
		stun_tid_cpy(&(sm.m.cb_sm.tid),tid);
		sm.m.cb_sm.s = s;
		sm.m.cb_sm.message_integrity = message_integrity;

		break;
	}
	case (RMT_MOBILE_SOCKET): {

		if(nd && nd->nbh) {
			sm.m.sm.s = s;
			addr_cpy(&(sm.m.sm.nd.src_addr),&(nd->src_addr));
			sm.m.sm.nd.recv_tos = nd->recv_tos;
			sm.m.sm.nd.recv_ttl = nd->recv_ttl;
			sm.m.sm.nd.nbh = nd->nbh;
			nd->nbh = NULL;
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Empty buffer with mobile socket\n",__FUNCTION__);
			ret = -1;
		}

		break;
	}
	default: {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: UNKNOWN RMT message: %d\n",__FUNCTION__,(int)rmt);
		ret = -1;
	}
	}

	if(ret == 0) {

		struct evbuffer *output = bufferevent_get_output(rs->out_buf);
		if(output) {
			evbuffer_add(output,&sm,sizeof(struct message_to_relay));
		} else {
			TURN_LOG_FUNC(
					TURN_LOG_LEVEL_ERROR,
					"%s: Empty output buffer\n",
					__FUNCTION__);
			ret = -1;
		}
	}

	if(ret != 0) {
		IOA_CLOSE_SOCKET(s);
		ioa_network_buffer_delete(rs->ioa_eng, sm.m.sm.nd.nbh);
		sm.m.sm.nd.nbh = NULL;
	}

	return ret;
}

static int handle_relay_message(relay_server_handle rs, struct message_to_relay *sm)
{
	if(rs && sm) {

		switch (sm->t) {

		case RMT_SOCKET: {

			if (sm->m.sm.s->defer_nbh) {
				if (!sm->m.sm.nd.nbh) {
					sm->m.sm.nd.nbh = sm->m.sm.s->defer_nbh;
					sm->m.sm.s->defer_nbh = NULL;
				} else {
					ioa_network_buffer_delete(rs->ioa_eng, sm->m.sm.s->defer_nbh);
					sm->m.sm.s->defer_nbh = NULL;
				}
			}

			ioa_socket_handle s = sm->m.sm.s;

			/* Special case: UDP socket */
			if (get_ioa_socket_type(s) == UDP_SOCKET) {

				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"%s: UDP socket wrongly sent over relay messaging channel: 0x%lx : 0x%lx\n",
					__FUNCTION__, (long) s->read_event, (long) s->bev);
				IOA_CLOSE_SOCKET(s);

			} else if (get_ioa_socket_type(s) == DTLS_SOCKET) {

				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"%s: DTLS socket wrongly sent over relay messaging channel: 0x%lx : 0x%lx\n",
					__FUNCTION__, (long) s->read_event, (long) s->bev);
				IOA_CLOSE_SOCKET(s);

			} else {

				if (!s) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
						"%s: socket EMPTY\n",__FUNCTION__);
				} else if (s->read_event || s->bev) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
						"%s: socket wrongly preset: 0x%lx : 0x%lx\n",
						__FUNCTION__, (long) s->read_event, (long) s->bev);
					IOA_CLOSE_SOCKET(s);
				} else {
					s->e = rs->ioa_eng;
					open_client_connection_session(rs->server, &(sm->m.sm));
				}
			}

			ioa_network_buffer_delete(rs->ioa_eng, sm->m.sm.nd.nbh);
			sm->m.sm.nd.nbh = NULL;
		}
			break;
		case RMT_CB_SOCKET:

			turnserver_accept_tcp_client_data_connection(rs->server, sm->m.cb_sm.connection_id,
				&(sm->m.cb_sm.tid), sm->m.cb_sm.s, sm->m.cb_sm.message_integrity);

			break;
		case RMT_MOBILE_SOCKET: {

			ioa_socket_handle s = sm->m.sm.s;

			if (!s) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
							"%s: mobile socket EMPTY\n",__FUNCTION__);
			} else if (s->read_event || s->bev) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
									"%s: mobile socket wrongly preset: 0x%lx : 0x%lx\n",
									__FUNCTION__, (long) s->read_event, (long) s->bev);
				IOA_CLOSE_SOCKET(s);
			} else {
				s->e = rs->ioa_eng;
				open_client_connection_session(rs->server, &(sm->m.sm));
			}

			ioa_network_buffer_delete(rs->ioa_eng, sm->m.sm.nd.nbh);
			sm->m.sm.nd.nbh = NULL;
			break;
		}
		default: {
			perror("Weird buffer type\n");
		}
		}
	}

	return 0;
}

static void handle_relay_auth_message(struct relay_server *rs, struct auth_message *am)
{
	am->resume_func(am->success, am->key, am->pwd,
				rs->server, am->ctxkey, &(am->in_buffer));
	if (am->in_buffer.nbh) {
		ioa_network_buffer_delete(rs->ioa_eng, am->in_buffer.nbh);
		am->in_buffer.nbh = NULL;
	}
}

static void relay_receive_message(struct bufferevent *bev, void *ptr)
{
	struct message_to_relay sm;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	struct relay_server *rs = (struct relay_server *)ptr;

	while ((n = evbuffer_remove(input, &sm, sizeof(struct message_to_relay))) > 0) {

		if (n != sizeof(struct message_to_relay)) {
			perror("Weird buffer error\n");
			continue;
		}

		handle_relay_message(rs, &sm);
	}
}

static void relay_receive_auth_message(struct bufferevent *bev, void *ptr)
{
	struct auth_message am;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	struct relay_server *rs = (struct relay_server *)ptr;

	while ((n = evbuffer_remove(input, &am, sizeof(struct auth_message))) > 0) {

		if (n != sizeof(struct auth_message)) {
			perror("Weird auth_buffer error\n");
			continue;
		}

		handle_relay_auth_message(rs, &am);
	}
}

static int send_message_from_listener_to_client(ioa_engine_handle e, ioa_network_buffer_handle nbh, ioa_addr *origin, ioa_addr *destination)
{

	struct message_to_listener mm;
	mm.t = LMT_TO_CLIENT;
	addr_cpy(&(mm.m.tc.origin),origin);
	addr_cpy(&(mm.m.tc.destination),destination);
	mm.m.tc.nbh = ioa_network_buffer_allocate(e);
	ioa_network_buffer_header_init(mm.m.tc.nbh);
	ns_bcopy(ioa_network_buffer_data(nbh),ioa_network_buffer_data(mm.m.tc.nbh),ioa_network_buffer_get_size(nbh));
	ioa_network_buffer_set_size(mm.m.tc.nbh,ioa_network_buffer_get_size(nbh));

	struct evbuffer *output = bufferevent_get_output(listener.out_buf);

	evbuffer_add(output,&mm,sizeof(struct message_to_listener));

	return 0;
}

static void listener_receive_message(struct bufferevent *bev, void *ptr)
{
	UNUSED_ARG(ptr);

	struct message_to_listener mm;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);

	while ((n = evbuffer_remove(input, &mm, sizeof(struct message_to_listener))) > 0) {
		if (n != sizeof(struct message_to_listener)) {
			perror("Weird buffer error\n");
			continue;
		}

		if (mm.t != LMT_TO_CLIENT) {
			perror("Weird buffer type\n");
			continue;
		}

		size_t relay_thread_index = 0;

		if(new_net_engine) {
			size_t ri;
			for(ri=0;ri<get_real_general_relay_servers_number();ri++) {
				if(general_relay_servers[ri]->thr == pthread_self()) {
					relay_thread_index=ri;
					break;
				}
			}
		}

		size_t i;
		int found = 0;
		for(i=0;i<listener.addrs_number;i++) {
			if(addr_eq_no_port(listener.encaddrs[i],&mm.m.tc.origin)) {
				int o_port = addr_get_port(&mm.m.tc.origin);
				if(listener.addrs_number == listener.services_number) {
					if(o_port == listener_port) {
						if(listener.udp_services && listener.udp_services[i] && listener.udp_services[i][relay_thread_index]) {
							found = 1;
							udp_send_message(listener.udp_services[i][relay_thread_index], mm.m.tc.nbh, &mm.m.tc.destination);
						}
					} else {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Wrong origin port(1): %d\n",__FUNCTION__,o_port);
					}
				} else if((listener.addrs_number * 2) == listener.services_number) {
					if(o_port == listener_port) {
						if(listener.udp_services && listener.udp_services[i*2] && listener.udp_services[i*2][relay_thread_index]) {
							found = 1;
							udp_send_message(listener.udp_services[i*2][relay_thread_index], mm.m.tc.nbh, &mm.m.tc.destination);
						}
					} else if(o_port == get_alt_listener_port()) {
						if(listener.udp_services && listener.udp_services[i*2+1] && listener.udp_services[i*2+1][relay_thread_index]) {
							found = 1;
							udp_send_message(listener.udp_services[i*2+1][relay_thread_index], mm.m.tc.nbh, &mm.m.tc.destination);
						}
					} else {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Wrong origin port(2): %d\n",__FUNCTION__,o_port);
					}
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Wrong listener setup\n",__FUNCTION__);
				}
				break;
			}
		}

		if(!found) {
			u08bits saddr[129];
			addr_to_string(&mm.m.tc.origin, saddr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Cannot find local source %s\n",__FUNCTION__,saddr);
		}

		ioa_network_buffer_delete(listener.ioa_eng, mm.m.tc.nbh);
		 mm.m.tc.nbh = NULL;
	}
}

// <<== communications between listener and relays

static ioa_engine_handle create_new_listener_engine(void)
{
	struct event_base *eb = event_base_new();
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (udp listener/relay thread): %s\n",event_base_get_method(eb));
	ioa_engine_handle e = create_ioa_engine(eb, listener.tp, relay_ifname, relays_number, relay_addrs, verbose, max_bps);
	set_ssl_ctx(e, tls_ctx_ssl23, tls_ctx_v1_0,
#if defined(SSL_TXT_TLSV1_1)
		tls_ctx_v1_1,
#if defined(SSL_TXT_TLSV1_2)
		tls_ctx_v1_2,
#endif
#endif
					dtls_ctx);
	ioa_engine_set_rtcp_map(e, listener.rtcpmap);
	return e;
}

static void *run_udp_listener_thread(void *arg)
{
  static int always_true = 1;

  ignore_sigpipe();

#if !defined(TURN_NO_THREAD_BARRIERS)
  if((pthread_barrier_wait(&barrier)<0) && errno)
	  perror("barrier wait");
#else
  sleep(5);
#endif

  dtls_listener_relay_server_type *server = (dtls_listener_relay_server_type *)arg;

  while(always_true && server) {
    run_events(get_engine(server)->event_base);
  }

  return arg;
}

static void setup_listener(void)
{
	listener.tp = turnipports_create(min_port, max_port);

	listener.event_base = event_base_new();

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (main listener thread): %s\n",event_base_get_method(listener.event_base));

	listener.ioa_eng = create_ioa_engine(listener.event_base, listener.tp, relay_ifname, relays_number, relay_addrs, verbose, max_bps);

	if(!listener.ioa_eng)
		exit(-1);

	set_ssl_ctx(listener.ioa_eng, tls_ctx_ssl23, tls_ctx_v1_0,
#if defined(SSL_TXT_TLSV1_1)
		tls_ctx_v1_1,
#if defined(SSL_TXT_TLSV1_2)
		tls_ctx_v1_2,
#endif
#endif
					dtls_ctx);

	listener.rtcpmap = rtcp_map_create(listener.ioa_eng);

#if !defined(TURN_NO_HIREDIS)
	if(use_redis_statsdb) {
		listener.rch = get_redis_async_connection(listener.event_base, redis_statsdb);
		set_default_async_context(listener.rch);
		turn_report_allocation_delete_all();
	}
#endif

	ioa_engine_set_rtcp_map(listener.ioa_eng, listener.rtcpmap);

	{
		struct bufferevent *pair[2];
		int opts = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS;

		opts |= BEV_OPT_THREADSAFE;

		bufferevent_pair_new(listener.event_base, opts, pair);
		listener.in_buf = pair[0];
		listener.out_buf = pair[1];
		bufferevent_setcb(listener.in_buf, listener_receive_message, NULL, NULL, &listener);
		bufferevent_enable(listener.in_buf, EV_READ);
	}

	if(listener.addrs_number<2) {
		rfc5780 = 0;
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: I cannot support STUN CHANGE_REQUEST functionality because only one IP address is provided\n");
	} else {
		listener.services_number = listener.services_number * 2;
	}

	listener.udp_services = (dtls_listener_relay_server_type***)realloc(listener.udp_services, sizeof(dtls_listener_relay_server_type**)*listener.services_number);
	listener.dtls_services = (dtls_listener_relay_server_type***)realloc(listener.dtls_services, sizeof(dtls_listener_relay_server_type**)*listener.services_number);

	listener.aux_udp_services = (dtls_listener_relay_server_type***)realloc(listener.aux_udp_services, sizeof(dtls_listener_relay_server_type**)*aux_servers_list.size+1);
}

static void setup_barriers(void)
{
	/* Adjust barriers: */

#if !defined(TURN_NO_THREAD_BARRIERS)

	if(!new_net_engine && general_relay_servers_number>1) {

		/* UDP: */
		if(!no_udp) {

			barrier_count += listener.addrs_number;

			if(rfc5780) {
				barrier_count += listener.addrs_number;
			}
		}

		if(!no_dtls && (no_udp || (listener_port != tls_listener_port))) {

			barrier_count += listener.addrs_number;

			if(rfc5780) {
				barrier_count += listener.addrs_number;
			}
		}

		if(!no_udp || !no_dtls) {
			barrier_count += (unsigned int)aux_servers_list.size;
		}
	}
#endif

#if !defined(TURN_NO_THREAD_BARRIERS)
	if(pthread_barrier_init(&barrier,NULL,barrier_count)<0)
		perror("barrier init");

#endif
}

static void setup_udp_listener_servers(void)
{
	size_t i = 0;

	/* Adjust udp relay number */

	if(general_relay_servers_number>1) {

		if (!no_udp) {

			udp_relay_servers_number += listener.addrs_number;

			if (rfc5780) {
				udp_relay_servers_number += listener.addrs_number;
			}
		}

		if (!no_dtls && (no_udp || (listener_port != tls_listener_port))) {

			udp_relay_servers_number += listener.addrs_number;

			if (rfc5780) {
				udp_relay_servers_number += listener.addrs_number;
			}
		}

		if (!no_udp || !no_dtls) {
			udp_relay_servers_number += (unsigned int) aux_servers_list.size;
		}
	}

	{
		if (!no_udp || !no_dtls) {
			udp_relay_servers = (struct relay_server**) turn_malloc(sizeof(struct relay_server *)*get_real_udp_relay_servers_number());
			ns_bzero(udp_relay_servers,sizeof(struct relay_server *)*get_real_udp_relay_servers_number());

			for (i = 0; i < get_real_udp_relay_servers_number(); i++) {

				ioa_engine_handle e = listener.ioa_eng;
				int is_5780 = rfc5780;

				if(general_relay_servers_number<=1) {
					while(!(general_relay_servers[0]->ioa_eng))
						sched_yield();
					udp_relay_servers[i] = general_relay_servers[0];
					continue;
				} else if(general_relay_servers_number>1) {
					e = create_new_listener_engine();
					is_5780 = is_5780 && (i >= (size_t) (aux_servers_list.size));
				}

				struct relay_server* udp_rs = (struct relay_server*) turn_malloc(sizeof(struct relay_server));
				ns_bzero(udp_rs, sizeof(struct relay_server));
				udp_rs->id = (turnserver_id) i + TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP;
				setup_relay_server(udp_rs, e, is_5780);
				udp_relay_servers[i] = udp_rs;
			}
		}
	}

	int udp_relay_server_index = 0;

	/* Create listeners */

	/* Aux UDP servers */
	for(i=0; i<aux_servers_list.size; i++) {

		int index = i;

		if(!no_udp || !no_dtls) {

			ioa_addr addr;
			char saddr[129];
			addr_cpy(&addr,&aux_servers_list.addrs[i]);
			int port = (int)addr_get_port(&addr);
			addr_to_string_no_port(&addr,(u08bits*)saddr);

			listener.aux_udp_services[index] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**));
			listener.aux_udp_services[index][0] = create_dtls_listener_server(listener_ifname, saddr, port, verbose, udp_relay_servers[udp_relay_server_index]->ioa_eng, udp_relay_servers[udp_relay_server_index]->server, 1);

			if(general_relay_servers_number>1) {
				++udp_relay_server_index;
				pthread_t thr;
				if(pthread_create(&thr, NULL, run_udp_listener_thread, listener.aux_udp_services[index][0])<0) {
					perror("Cannot create aux listener thread\n");
					exit(-1);
				}
				pthread_detach(thr);
			}
		}
	}

	/* Main servers */
	for(i=0; i<listener.addrs_number; i++) {

		int index = rfc5780 ? i*2 : i;

		/* UDP: */
		if(!no_udp) {

			listener.udp_services[index] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**));
			listener.udp_services[index][0] = create_dtls_listener_server(listener_ifname, listener.addrs[i], listener_port, verbose, udp_relay_servers[udp_relay_server_index]->ioa_eng, udp_relay_servers[udp_relay_server_index]->server, 1);

			if(general_relay_servers_number>1) {
				++udp_relay_server_index;
				pthread_t thr;
				if(pthread_create(&thr, NULL, run_udp_listener_thread, listener.udp_services[index][0])<0) {
					perror("Cannot create listener thread\n");
					exit(-1);
				}
				pthread_detach(thr);
			}

			if(rfc5780) {

				listener.udp_services[index+1] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**));
				listener.udp_services[index+1][0] = create_dtls_listener_server(listener_ifname, listener.addrs[i], get_alt_listener_port(), verbose, udp_relay_servers[udp_relay_server_index]->ioa_eng, udp_relay_servers[udp_relay_server_index]->server, 1);

				if(general_relay_servers_number>1) {
					++udp_relay_server_index;
					pthread_t thr;
					if(pthread_create(&thr, NULL, run_udp_listener_thread, listener.udp_services[index+1][0])<0) {
						perror("Cannot create listener thread\n");
						exit(-1);
					}
					pthread_detach(thr);
				}
			}
		} else {
			listener.udp_services[index] = NULL;
			if(rfc5780)
				listener.udp_services[index+1] = NULL;
		}
		if(!no_dtls && (no_udp || (listener_port != tls_listener_port))) {

			listener.dtls_services[index] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**));
			listener.dtls_services[index][0] = create_dtls_listener_server(listener_ifname, listener.addrs[i], tls_listener_port, verbose, udp_relay_servers[udp_relay_server_index]->ioa_eng, udp_relay_servers[udp_relay_server_index]->server, 1);

			if(general_relay_servers_number>1) {
				++udp_relay_server_index;
				pthread_t thr;
				if(pthread_create(&thr, NULL, run_udp_listener_thread, listener.dtls_services[index][0])<0) {
					perror("Cannot create listener thread\n");
					exit(-1);
				}
				pthread_detach(thr);
			}

			if(rfc5780) {

				listener.dtls_services[index+1] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**));
				listener.dtls_services[index+1][0] = create_dtls_listener_server(listener_ifname, listener.addrs[i], get_alt_tls_listener_port(), verbose, udp_relay_servers[udp_relay_server_index]->ioa_eng, udp_relay_servers[udp_relay_server_index]->server, 1);

				if(general_relay_servers_number>1) {
					++udp_relay_server_index;
					pthread_t thr;
					if(pthread_create(&thr, NULL, run_udp_listener_thread, listener.dtls_services[index+1][0])<0) {
						perror("Cannot create listener thread\n");
						exit(-1);
					}
					pthread_detach(thr);
				}
			}
		} else {
			listener.dtls_services[index] = NULL;
			if(rfc5780)
				listener.dtls_services[index+1] = NULL;
		}
	}
}

static void setup_new_udp_listener_servers(void)
{
	size_t i = 0;
	size_t relayindex = 0;

	/* Create listeners */

	for(relayindex=0;relayindex<get_real_general_relay_servers_number();relayindex++) {
		while(!(general_relay_servers[relayindex]->ioa_eng) || !(general_relay_servers[relayindex]->server))
			sched_yield();
	}

	/* Aux UDP servers */
	for(i=0; i<aux_servers_list.size; i++) {

		int index = i;

		if(!no_udp || !no_dtls) {

			ioa_addr addr;
			char saddr[129];
			addr_cpy(&addr,&aux_servers_list.addrs[i]);
			int port = (int)addr_get_port(&addr);
			addr_to_string_no_port(&addr,(u08bits*)saddr);

			listener.aux_udp_services[index] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**) * get_real_general_relay_servers_number());

			for(relayindex=0;relayindex<get_real_general_relay_servers_number();relayindex++) {
				listener.aux_udp_services[index][relayindex] = create_dtls_listener_server(listener_ifname, saddr, port, verbose,
						general_relay_servers[relayindex]->ioa_eng, general_relay_servers[relayindex]->server, !relayindex);
			}
		}
	}

	/* Main servers */
	for(i=0; i<listener.addrs_number; i++) {

		int index = rfc5780 ? i*2 : i;

		/* UDP: */
		if(!no_udp) {

			listener.udp_services[index] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**) * get_real_general_relay_servers_number());

			for(relayindex=0;relayindex<get_real_general_relay_servers_number();relayindex++) {
				listener.udp_services[index][relayindex] = create_dtls_listener_server(listener_ifname, listener.addrs[i], listener_port, verbose,
						general_relay_servers[relayindex]->ioa_eng, general_relay_servers[relayindex]->server, !relayindex);
			}

			if(rfc5780) {

				listener.udp_services[index+1] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**) * get_real_general_relay_servers_number());

				for(relayindex=0;relayindex<get_real_general_relay_servers_number();relayindex++) {
					listener.udp_services[index+1][relayindex] = create_dtls_listener_server(listener_ifname, listener.addrs[i], get_alt_listener_port(), verbose,
							general_relay_servers[relayindex]->ioa_eng, general_relay_servers[relayindex]->server, !relayindex);
				}
			}
		} else {
			listener.udp_services[index] = NULL;
			if(rfc5780)
				listener.udp_services[index+1] = NULL;
		}
		if(!no_dtls && (no_udp || (listener_port != tls_listener_port))) {

			listener.dtls_services[index] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**) * get_real_general_relay_servers_number());

			for(relayindex=0;relayindex<get_real_general_relay_servers_number();relayindex++) {
				listener.dtls_services[index][relayindex] = create_dtls_listener_server(listener_ifname, listener.addrs[i], tls_listener_port, verbose,
						general_relay_servers[relayindex]->ioa_eng, general_relay_servers[relayindex]->server, !relayindex);
			}

			if(rfc5780) {

				listener.dtls_services[index+1] = (dtls_listener_relay_server_type**)malloc(sizeof(dtls_listener_relay_server_type**) * get_real_general_relay_servers_number());

				for(relayindex=0;relayindex<get_real_general_relay_servers_number();relayindex++) {
					listener.dtls_services[index+1][relayindex] = create_dtls_listener_server(listener_ifname, listener.addrs[i], get_alt_tls_listener_port(), verbose,
							general_relay_servers[relayindex]->ioa_eng, general_relay_servers[relayindex]->server, !relayindex);
				}
			}
		} else {
			listener.dtls_services[index] = NULL;
			if(rfc5780)
				listener.dtls_services[index+1] = NULL;
		}
	}
}

static void setup_tcp_listener_servers(void)
{
	size_t i = 0;

	listener.tcp_services = (tls_listener_relay_server_type**)realloc(listener.tcp_services, sizeof(tls_listener_relay_server_type*)*listener.services_number);
	listener.tls_services = (tls_listener_relay_server_type**)realloc(listener.tls_services, sizeof(tls_listener_relay_server_type*)*listener.services_number);

	listener.aux_tcp_services = (tls_listener_relay_server_type**)realloc(listener.aux_tcp_services, sizeof(tls_listener_relay_server_type*)*aux_servers_list.size+1);

	/* Create listeners */

	/* Aux TCP servers */
	if(!no_tls || !no_tcp) {

		for(i=0; i<aux_servers_list.size; i++) {

			ioa_addr addr;
			char saddr[129];
			addr_cpy(&addr,&aux_servers_list.addrs[i]);
			int port = (int)addr_get_port(&addr);
			addr_to_string_no_port(&addr,(u08bits*)saddr);

			listener.aux_tcp_services[i] = create_tls_listener_server(listener_ifname, saddr, port, verbose, listener.ioa_eng, send_socket_to_general_relay);
		}
	}

	/* Main servers */
	for(i=0; i<listener.addrs_number; i++) {

		int index = rfc5780 ? i*2 : i;

		/* TCP: */
		if(!no_tcp) {
			listener.tcp_services[index] = create_tls_listener_server(listener_ifname, listener.addrs[i], listener_port, verbose, listener.ioa_eng, send_socket_to_general_relay);
			if(rfc5780)
				listener.tcp_services[index+1] = create_tls_listener_server(listener_ifname, listener.addrs[i], get_alt_listener_port(), verbose, listener.ioa_eng, send_socket_to_general_relay);
		} else {
			listener.tcp_services[index] = NULL;
			if(rfc5780)
				listener.tcp_services[index+1] = NULL;
		}
		if(!no_tls && (no_tcp || (listener_port != tls_listener_port))) {
			listener.tls_services[index] = create_tls_listener_server(listener_ifname, listener.addrs[i], tls_listener_port, verbose, listener.ioa_eng, send_socket_to_general_relay);
			if(rfc5780)
				listener.tls_services[index+1] = create_tls_listener_server(listener_ifname, listener.addrs[i], get_alt_tls_listener_port(), verbose, listener.ioa_eng, send_socket_to_general_relay);
		} else {
			listener.tls_services[index] = NULL;
			if(rfc5780)
				listener.tls_services[index+1] = NULL;
		}
	}
}

static int get_alt_addr(ioa_addr *addr, ioa_addr *alt_addr)
{
	if(!addr || !rfc5780 || (listener.addrs_number<2))
		return -1;
	else {
		size_t index = 0xffff;
		size_t i = 0;
		int alt_port = -1;
		int port = addr_get_port(addr);

		if(port == listener_port)
			alt_port = get_alt_listener_port();
		else if(port == get_alt_listener_port())
			alt_port = listener_port;
		else if(port == tls_listener_port)
			alt_port = get_alt_tls_listener_port();
		else if(port == get_alt_tls_listener_port())
			alt_port = tls_listener_port;
		else
			return -1;

		for(i=0;i<listener.addrs_number;i++) {
			if(listener.encaddrs && listener.encaddrs[i]) {
				if(addr->ss.ss_family == listener.encaddrs[i]->ss.ss_family) {
					index=i;
					break;
				}
			}
		}
		if(index!=0xffff) {
			for(i=0;i<listener.addrs_number;i++) {
				size_t ind = (index+i+1) % listener.addrs_number;
				if(listener.encaddrs && listener.encaddrs[ind]) {
					ioa_addr *caddr = listener.encaddrs[ind];
					if(caddr->ss.ss_family == addr->ss.ss_family) {
						addr_cpy(alt_addr,caddr);
						addr_set_port(alt_addr, alt_port);
						return 0;
					}
				}
			}
		}

		return -1;
	}
}

static void run_events(struct event_base *eb)
{

	if (!eb)
		return;

	struct timeval timeout;

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	event_base_loopexit(eb, &timeout);

	event_base_dispatch(eb);
}

void run_listener_server(struct event_base *eb)
{
	unsigned int cycle = 0;
	for (;;) {

		if (eve(verbose)) {
			if ((cycle++ & 15) == 0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cycle=%u\n", __FUNCTION__, cycle);
			}
		}

		run_events(eb);

		rollover_logfile();
	}
}

static void setup_relay_server(struct relay_server *rs, ioa_engine_handle e, int to_set_rfc5780)
{
	struct bufferevent *pair[2];
	int opts = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS;

	if(e) {
		rs->event_base = e->event_base;
		rs->ioa_eng = e;
	} else {
		rs->event_base = event_base_new();
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (general relay thread): %s\n",event_base_get_method(rs->event_base));
		rs->ioa_eng = create_ioa_engine(rs->event_base, listener.tp, relay_ifname, relays_number, relay_addrs, verbose, max_bps);
		set_ssl_ctx(rs->ioa_eng, tls_ctx_ssl23, tls_ctx_v1_0,
#if defined(SSL_TXT_TLSV1_1)
		tls_ctx_v1_1,
#if defined(SSL_TXT_TLSV1_2)
		tls_ctx_v1_2,
#endif
#endif
					dtls_ctx);
		ioa_engine_set_rtcp_map(rs->ioa_eng, listener.rtcpmap);
	}

	opts |= BEV_OPT_THREADSAFE;

	bufferevent_pair_new(rs->event_base, opts, pair);
	rs->in_buf = pair[0];
	rs->out_buf = pair[1];
	bufferevent_setcb(rs->in_buf, relay_receive_message, NULL, NULL, rs);
	bufferevent_enable(rs->in_buf, EV_READ);

	bufferevent_pair_new(rs->event_base, opts, pair);
	rs->auth_in_buf = pair[0];
	rs->auth_out_buf = pair[1];
	bufferevent_setcb(rs->auth_in_buf, relay_receive_auth_message, NULL, NULL, rs);
	bufferevent_enable(rs->auth_in_buf, EV_READ);

	rs->server = create_turn_server(rs->id, verbose,
					rs->ioa_eng, 0,
					fingerprint, DONT_FRAGMENT_SUPPORTED,
					users->ct,
					(u08bits*)global_realm,
					start_user_check,
					check_new_allocation_quota,
					release_allocation_quota,
					external_ip,
					&no_tcp_relay,
					&no_udp_relay,
					&stale_nonce,
					&stun_only,
					&no_stun,
					&alternate_servers_list,
					&tls_alternate_servers_list,
					&aux_servers_list,
					udp_self_balance,
					&no_multicast_peers, &no_loopback_peers,
					&ip_whitelist, &ip_blacklist,
					send_socket_to_relay,
					&secure_stun, shatype, &mobility, &server_relay,
					send_turn_session_info);

	if(to_set_rfc5780) {
		set_rfc5780(rs->server, get_alt_addr, send_message_from_listener_to_client);
	}
}

static void *run_general_relay_thread(void *arg)
{
  static int always_true = 1;
  struct relay_server *rs = (struct relay_server *)arg;
  
  int udp_reuses_the_same_relay_server = (general_relay_servers_number<=1) || new_net_engine;

  int we_need_rfc5780 = udp_reuses_the_same_relay_server && rfc5780;

  ignore_sigpipe();

  setup_relay_server(rs, NULL, we_need_rfc5780);

#if !defined(TURN_NO_THREAD_BARRIERS)
  if((pthread_barrier_wait(&barrier)<0) && errno)
	  perror("barrier wait");
#endif

  while(always_true) {
    run_events(rs->event_base);
  }
  
  return arg;
}

static void setup_general_relay_servers(void)
{
	size_t i = 0;

	general_relay_servers = (struct relay_server**)turn_malloc(sizeof(struct relay_server *)*get_real_general_relay_servers_number());
	ns_bzero(general_relay_servers,sizeof(struct relay_server *)*get_real_general_relay_servers_number());

	for(i=0;i<get_real_general_relay_servers_number();i++) {

		general_relay_servers[i] = (struct relay_server*)turn_malloc(sizeof(struct relay_server));
		ns_bzero(general_relay_servers[i], sizeof(struct relay_server));
		general_relay_servers[i]->id = (turnserver_id)i;

		if(general_relay_servers_number == 0) {
			setup_relay_server(general_relay_servers[i], listener.ioa_eng, new_net_engine && rfc5780);
			general_relay_servers[i]->thr = pthread_self();
		} else {
			if(pthread_create(&(general_relay_servers[i]->thr), NULL, run_general_relay_thread, general_relay_servers[i])<0) {
				perror("Cannot create relay thread\n");
				exit(-1);
			}
			pthread_detach(general_relay_servers[i]->thr);
		}
	}
}

static int run_auth_server_flag = 1;

static void* run_auth_server_thread(void *arg)
{
	struct event_base *eb = (struct event_base*)arg;

#if !defined(TURN_NO_THREAD_BARRIERS)
	if((pthread_barrier_wait(&barrier)<0) && errno)
		perror("barrier wait");
#endif

	ignore_sigpipe();

	while(run_auth_server_flag) {
		run_events(eb);
		read_userdb_file(0);
		update_white_and_black_lists();
		auth_ping();
#if !defined(TURN_NO_HIREDIS)
		send_message_to_redis(NULL, "publish", "__XXX__", "__YYY__");
#endif
	}

	return arg;
}

static void setup_auth_server(void)
{
	ns_bzero(&authserver,sizeof(struct auth_server));

	authserver.event_base = event_base_new();
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (auth thread): %s\n",event_base_get_method(authserver.event_base));

	struct bufferevent *pair[2];
	int opts = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS;

	opts |= BEV_OPT_THREADSAFE;

	bufferevent_pair_new(authserver.event_base, opts, pair);
	authserver.in_buf = pair[0];
	authserver.out_buf = pair[1];
	bufferevent_setcb(authserver.in_buf, auth_server_receive_message, NULL, NULL, &authserver);
	bufferevent_enable(authserver.in_buf, EV_READ);

	if(pthread_create(&(authserver.thr), NULL, run_auth_server_thread, authserver.event_base)<0) {
		perror("Cannot create auth thread\n");
		exit(-1);
	}
	pthread_detach(authserver.thr);
}

static void* run_cli_server_thread(void *arg)
{
	ignore_sigpipe();

	setup_cli_thread();

#if !defined(TURN_NO_THREAD_BARRIERS)
	if((pthread_barrier_wait(&barrier)<0) && errno)
		perror("barrier wait");
#endif

	while(cliserver.event_base) {
		run_events(cliserver.event_base);
	}

	return arg;
}

static void setup_cli_server(void)
{
	ns_bzero(&cliserver,sizeof(struct cli_server));
	cliserver.listen_fd = -1;
	cliserver.verbose = verbose;

	if(pthread_create(&(cliserver.thr), NULL, run_cli_server_thread, &cliserver)<0) {
		perror("Cannot create cli thread\n");
		exit(-1);
	}

	pthread_detach(cliserver.thr);
}

void setup_server(void)
{
	evthread_use_pthreads();

#if !defined(TURN_NO_THREAD_BARRIERS)

	/* relay threads plus auth thread plus main listener thread */
	/* udp address listener thread(s) will start later */
	barrier_count = general_relay_servers_number+2;

	if(use_cli)
		barrier_count += 1;

#endif

	setup_listener();
	setup_barriers();
	setup_general_relay_servers();

	if(new_net_engine)
		setup_new_udp_listener_servers();
	else
		setup_udp_listener_servers();

	setup_tcp_listener_servers();
	setup_auth_server();
	if(use_cli)
		setup_cli_server();

#if !defined(TURN_NO_THREAD_BARRIERS)
	if((pthread_barrier_wait(&barrier)<0) && errno)
		perror("barrier wait");
#endif
}

void init_listener(void)
{
	ns_bzero(&listener,sizeof(struct listener_server));
}

///////////////////////////////
