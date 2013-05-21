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

#include "ns_turn_server.h"

#include "ns_turn_utils.h"
#include "ns_turn_allocation.h"
#include "ns_turn_msg_addr.h"

///////////////////////////////////////////

#define FUNCSTART if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

////////////////////////////////////////////////

#define MAX_NUMBER_OF_UNKNOWN_ATTRS (128)

int TURN_MAX_TO_ALLOCATE_TIMEOUT = 60;

///////////////////////////////////////////

struct _turn_turnserver {

	turnserver_id id;
	ioa_engine_handle e;
	int verbose;
	int fingerprint;
	int rfc5780;
	int stale_nonce;
	int stun_only;
	get_alt_addr_cb alt_addr_cb;
	send_message_cb sm_cb;
	dont_fragment_option_t dont_fragment;
	u32bits *stats;
	int (*disconnect)(ts_ur_super_session*);
	turn_credential_type ct;
	u08bits realm[STUN_MAX_REALM_SIZE+1];
	get_user_key_cb userkeycb;
	check_new_allocation_quota_cb chquoatacb;
	release_allocation_quota_cb raqcb;
	ioa_addr **encaddrs;
	ioa_addr *external_ip;
	size_t addrs_number;
	int no_loopback_peers;
	int no_multicast_peers;

	/* RFC 6062 ==>> */
	int no_udp_relay;
	int no_tcp_relay;
	ur_map *tcp_relay_connections;
	/* <<== RFC 6062 */

	/* Alternate servers ==>> */
	alternate_servers_list_t *alternate_servers_list;
	size_t as_counter;
	alternate_servers_list_t *tls_alternate_servers_list;
	size_t tls_as_counter;

	/* White/black listing of address ranges */
	ip_range_list_t* ip_whitelist;
	ip_range_list_t* ip_blacklist;
};

///////////////////////////////////////////

static int create_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime,
		int address_family, u08bits transport,
		int even_port, u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code, const u08bits **reason, accept_cb acb);

static int refresh_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime, int even_port,
		u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code);

static int write_client_connection(turn_turnserver *server, ts_ur_super_session* ss, ioa_network_buffer_handle nbh, int ttl, int tos);

static void accept_tcp_connection(ioa_socket_handle s, void *arg);

static int read_client_connection(turn_turnserver *server, ts_ur_session *elem,
				  ts_ur_super_session *ss, ioa_net_data *in_buffer,
				  int can_resume);

static int need_stun_authentication(turn_turnserver *server);

/////////////////// RFC 5780 ///////////////////////

void set_rfc5780(turn_turnserver *server, get_alt_addr_cb cb, send_message_cb smcb)
{
	if(server) {
		if(!cb || !smcb) {
			server->rfc5780 = 0;
			server->alt_addr_cb = NULL;
			server->sm_cb = NULL;
		} else {
			server->rfc5780 = 1;
			server->alt_addr_cb = cb;
			server->sm_cb = smcb;
		}
	}
}

static int is_rfc5780(turn_turnserver *server)
{
	if(!server)
		return 0;

	return ((server->rfc5780) && (server->alt_addr_cb));
}

static int get_other_address(turn_turnserver *server, ts_ur_super_session *ss, ioa_addr *alt_addr)
{
	if(is_rfc5780(server) && ss) {
		int ret = server->alt_addr_cb(get_local_addr_from_ioa_socket(ss->client_session.s), alt_addr);
		return ret;
	}

	return -1;
}

static int send_turn_message_to(turn_turnserver *server, ioa_network_buffer_handle nbh, ioa_addr *response_origin, ioa_addr *response_destination)
{
	if(is_rfc5780(server) && nbh && response_origin && response_destination) {
		return server->sm_cb(server->e, nbh, response_origin, response_destination);
	}

	return -1;
}

/////////////////// Peer addr check /////////////////////////////

static int good_peer_addr(turn_turnserver *server, ioa_addr *peer_addr)
{
	if(server && peer_addr) {
		if(server->no_multicast_peers && ioa_addr_is_multicast(peer_addr))
			return 0;
		if(server->no_loopback_peers && ioa_addr_is_loopback(peer_addr))
			return 0;

		{
			int i;

			// White/black listing of addr ranges
			for (i = server->ip_whitelist->ranges_number - 1; i >= 0; --i) {
				if (ioa_addr_in_range(server->ip_whitelist->encaddrsranges[i], peer_addr))
					return 1;
			}

			for (i = server->ip_blacklist->ranges_number - 1; i >= 0; --i) {
				if (ioa_addr_in_range(server->ip_blacklist->encaddrsranges[i], peer_addr)) {
					if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "A peer IP denied in the range: %s\n",server->ip_blacklist->ranges[i]);
					}
					return 0;
				}
			}
		}

		return 1;
	}
	return 0;
}

/////////////////// Allocation //////////////////////////////////

allocation* get_allocation_ss(ts_ur_super_session *ss) {
	return &(ss->alloc);
}

static inline ts_ur_session *get_relay_session_ss(ts_ur_super_session *ss)
{
	return &(ss->alloc.relay_session);
}

static inline ioa_socket_handle get_relay_socket_ss(ts_ur_super_session *ss)
{
	return ss->alloc.relay_session.s;
}

/////////// SS /////////////////

static ts_ur_super_session* create_new_ss(turn_turnserver* server) {
	ts_ur_super_session *ss = (ts_ur_super_session*)turn_malloc(sizeof(ts_ur_super_session));
	ns_bzero(ss,sizeof(ts_ur_super_session));
	ss->server = server;
	init_allocation(ss,&(ss->alloc), server->tcp_relay_connections);
	return ss;
}

static void delete_ur_map_ss(void *p) {
	if (p) {
		ts_ur_super_session* ss = (ts_ur_super_session*) p;
		delete_ur_map_session_elem_data(&(ss->client_session));
		clean_allocation(get_allocation_ss(ss));
		IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);
		turn_free(p,sizeof(ts_ur_super_session));
	}
}

/////////// clean all /////////////////////

static int turn_server_remove_all_from_ur_map_ss(ts_ur_super_session* ss) {
	if (!ss)
		return 0;
	else {
		int ret = 0;
		(((turn_turnserver*)ss->server)->raqcb)(ss->username);
		if (ss->client_session.s) {
			clear_ioa_socket_session_if(ss->client_session.s, ss);
		}
		if (get_relay_socket_ss(ss)) {
			clear_ioa_socket_session_if(get_relay_socket_ss(ss), ss);
		}
		delete_ur_map_ss(ss);
		return ret;
	}
}

/////////////////////////////////////////////////////////////////

static void client_ss_channel_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);

	if (!arg)
		return;

	ch_info* chn = (ch_info*) arg;

	turn_channel_delete(chn);
}

static void client_ss_perm_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);

	if (!arg)
		return;

	turn_permission_info* tinfo = (turn_permission_info*) arg;

	allocation* a = (allocation*) (tinfo->owner);

	if (!a)
		return;

	allocation_remove_turn_permission(a, tinfo);
}

///////////////////////////////////////////////////////////////////

static int update_turn_permission_lifetime(ts_ur_super_session *ss, turn_permission_info *tinfo, turn_time_t time_delta) {

	if (ss && tinfo && tinfo->owner) {

		turn_turnserver *server = (turn_turnserver *) (ss->server);

		if (server) {

			if(!time_delta) time_delta = STUN_PERMISSION_LIFETIME;
			turn_time_t newtime = turn_time() + time_delta;
			if (tinfo->expiration_time < newtime) {

				IOA_EVENT_DEL(tinfo->lifetime_ev);
				tinfo->expiration_time = newtime;
				tinfo->lifetime_ev = set_ioa_timer(server->e, time_delta, 0,
								client_ss_perm_timeout_handler, tinfo, 0,
								"client_ss_channel_timeout_handler");
			}

			return 0;
		}
	}
	return -1;
}

static int update_channel_lifetime(ts_ur_super_session *ss, ch_info* chn)
{

	if (chn) {

		turn_permission_info* tinfo = (turn_permission_info*) (chn->owner);

		if (tinfo && tinfo->owner) {

			turn_turnserver *server = (turn_turnserver *) (ss->server);

			if (server) {

				if (update_turn_permission_lifetime(ss, tinfo, STUN_CHANNEL_LIFETIME) < 0)
					return -1;

				turn_time_t newtime = turn_time() + STUN_CHANNEL_LIFETIME;
				if (chn->expiration_time < newtime) {

					IOA_EVENT_DEL(chn->lifetime_ev);
					chn->expiration_time = newtime;
					chn->lifetime_ev = set_ioa_timer(server->e, STUN_CHANNEL_LIFETIME, 0,
									client_ss_channel_timeout_handler,
									chn, 0,
									"client_ss_channel_timeout_handler");
				}

				refresh_ioa_socket_channel(chn->socket_channel);

				return 0;
			}
		}
	}
	return -1;
}

/////////////// TURN ///////////////////////////

#define SKIP_ATTRIBUTES case STUN_ATTRIBUTE_PRIORITY: case STUN_ATTRIBUTE_FINGERPRINT: case STUN_ATTRIBUTE_MESSAGE_INTEGRITY: break; \
	case STUN_ATTRIBUTE_USERNAME: case STUN_ATTRIBUTE_REALM: case STUN_ATTRIBUTE_NONCE: \
	sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),\
		ioa_network_buffer_get_size(in_buffer->nbh), sar); \
	continue

static u08bits get_transport_value(const u08bits *value) {
	if((value[0] == STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE)||
	   (value[0] == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)) {
		return value[0];
	}
	return 0;
}

static int handle_turn_allocate(turn_turnserver *server,
				ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				int *err_code, 	const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	allocation* a = get_allocation_ss(ss);

	ts_ur_session* elem = &(ss->client_session);

	if (is_allocation_valid(a)) {

		if (!stun_tid_equals(tid, &(a->tid))) {
			*err_code = 437;
			*reason = (const u08bits *)"Wrong TID";
		} else {
			size_t len = ioa_network_buffer_get_size(nbh);
			ioa_addr xor_relayed_addr;
			ioa_addr *relayed_addr = get_local_addr_from_ioa_socket(get_relay_socket_ss(ss));
			if(server->external_ip) {
				addr_cpy(&xor_relayed_addr, server->external_ip);
				addr_set_port(&xor_relayed_addr,addr_get_port(relayed_addr));
			} else {
				addr_cpy(&xor_relayed_addr, relayed_addr);
			}
			stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len,
							tid,
					&xor_relayed_addr,
					get_remote_addr_from_ioa_socket(elem->s),
					(a->expiration_time - turn_time()), 0, NULL, 0);
			ioa_network_buffer_set_size(nbh,len);
			*resp_constructed = 1;
		}

	} else {

		a = NULL;

		u08bits transport = 0;
		u32bits lifetime = 0;
		int even_port = -1;
		int dont_fragment = 0;
		u64bits in_reservation_token = 0;
		int af = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
		u08bits username[STUN_MAX_USERNAME_SIZE+1]="\0";
		size_t ulen = 0;

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);

			if(attr_type == STUN_ATTRIBUTE_USERNAME) {
				const u08bits* value = stun_attr_get_value(sar);
				if (value) {
					ulen = stun_attr_get_len(sar);
					if(ulen>=sizeof(username)) {
						*err_code = 400;
						*reason = (const u08bits *)"User name is too long";
						break;
					}
					ns_bcopy(value,username,ulen);
					username[ulen]=0;
				}
			}

			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_REQUESTED_TRANSPORT: {
				if (stun_attr_get_len(sar) != 4) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Transport Field";
				} else if(transport) {
					*err_code = 400;
					*reason = (const u08bits *)"Duplicate Transport Fields";
				} else {
					const u08bits* value = stun_attr_get_value(sar);
					if (value) {
						transport = get_transport_value(value);
						if (!transport || value[1] || value[2] || value[3]) {
							*err_code = 442;
							*reason = (const u08bits *)"Unsupported Transport Protocol";
						}
						if((transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) && server->no_tcp_relay) {
							*err_code = 403;
							*reason = (const u08bits *)"TCP Transport is not allowed by the TURN Server configuration";
						} else if((transport == STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE) && server->no_udp_relay) {
							*err_code = 403;
							*reason = (const u08bits *)"UDP Transport is not allowed by the TURN Server configuration";
						} else {
							SOCKET_TYPE cst = get_ioa_socket_type(ss->client_session.s);
							if((transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) &&
											(cst!=TCP_SOCKET) && (cst!=TLS_SOCKET)) {
								*err_code = 400;
								*reason = (const u08bits *)"Wrong Transport Data";
							} else {
								ss->is_tcp_relay = (transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE);
							}
						}
					} else {
						*err_code = 400;
						*reason = (const u08bits *)"Wrong Transport Data";
					}
				}
			}
				break;
			case STUN_ATTRIBUTE_DONT_FRAGMENT:
				dont_fragment = 1;
				if(!(server->dont_fragment))
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
				break;
			case STUN_ATTRIBUTE_LIFETIME: {
			  if (stun_attr_get_len(sar) != 4) {
			    *err_code = 400;
			    *reason = (const u08bits *)"Wrong Lifetime Field";
			  } else {
			    const u08bits* value = stun_attr_get_value(sar);
			    if (!value) {
			      *err_code = 400;
			      *reason = (const u08bits *)"Wrong Lifetime Data";
			    } else {
			      lifetime = nswap32(*((const u32bits*)value));
			    }
			  }
			}
			  break;
			case STUN_ATTRIBUTE_EVEN_PORT: {
			  if (in_reservation_token) {
			    *err_code = 400;
			    *reason = (const u08bits *)"Even Port and Reservation Token cannot be used together";
			  } else if (even_port >= 0) {
			    *err_code = 400;
			    *reason = (const u08bits *)"Even Port cannot be used in this request";
			  } else {
			    even_port = stun_attr_get_even_port(sar);
			  }
			}
			  break;
			case STUN_ATTRIBUTE_RESERVATION_TOKEN: {
			  int len = stun_attr_get_len(sar);
			  if (len != 8) {
			    *err_code = 400;
			    *reason = (const u08bits *)"Wrong Format of Reservation Token";
			  } else if(af != STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT) {
				  *err_code = 400;
				  *reason = (const u08bits *)"Address family attribute can not be used with reservation token request";
			  } else {
			    if (even_port >= 0) {
			      *err_code = 400;
			      *reason = (const u08bits *)"Reservation Token cannot be used in this request with even port";
			    } else if (in_reservation_token) {
			      *err_code = 400;
			      *reason = (const u08bits *)"Reservation Token cannot be used in this request";
			    } else {
			      in_reservation_token = stun_attr_get_reservation_token_value(sar);
			    }
			  }
			}
			  break;
			case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY: {
				if(in_reservation_token) {
					*err_code = 400;
					*reason = (const u08bits *)"Address family attribute can not be used with reservation token request";
				} else {
					int af_req = stun_get_requested_address_family(sar);
					if(af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT) {
						switch (af_req) {
						case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
						case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
							af = af_req;
							break;
						default:
							*err_code = 440;
							*reason = (const u08bits *)"Unsupported address family requested";
						}
					} else {
						*err_code = 400;
						*reason = (const u08bits *)"Only one address family attribute can be used in a request";
					}
				}
			}
			  break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
		}

		if (!transport) {

		  *err_code = 400;
		  if(!(*reason))
		    *reason = (const u08bits *)"Transport field missed or wrong";
		  
		} else if (*ua_num > 0) {

		  *err_code = 420;
		  if(!(*reason))
		    *reason = (const u08bits *)"Unknown attribute";

		} else if (*err_code) {

			;

		} else if((transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) && (dont_fragment || in_reservation_token || (even_port!=-1))) {

			*err_code = 400;
			if(!(*reason))
			    *reason = (const u08bits *)"Request parameters are incompatible with TCP transport";

		} else {

			lifetime = stun_adjust_allocate_lifetime(lifetime);
			u64bits out_reservation_token = 0;

			if((server->chquoatacb)(username)<0) {

				*err_code = 486;
				*reason = (const u08bits *)"Allocation Quota Reached";

			} else if (create_relay_connection(server, ss, lifetime,
							af, transport,
							even_port, in_reservation_token, &out_reservation_token,
							err_code, reason,
							accept_tcp_connection) < 0) {

				(server->raqcb)(username);

				if (!*err_code) {
				  *err_code = 437;
				  if(!(*reason))
				    *reason = (const u08bits *)"Cannot create relay endpoint";
				}

			} else {

				a = get_allocation_ss(ss);
				set_allocation_valid(a,1);

				STRCPY(ss->username,username);

				stun_tid_cpy(&(a->tid), tid);

				size_t len = ioa_network_buffer_get_size(nbh);

				ioa_addr xor_relayed_addr;
				ioa_addr *relayed_addr = get_local_addr_from_ioa_socket(get_relay_socket_ss(ss));
				if(server->external_ip) {
					addr_cpy(&xor_relayed_addr, server->external_ip);
					addr_set_port(&xor_relayed_addr,addr_get_port(relayed_addr));
				} else {
					addr_cpy(&xor_relayed_addr, relayed_addr);
				}

				stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len, tid,
							   &xor_relayed_addr,
							   get_remote_addr_from_ioa_socket(elem->s), lifetime, 
							   0,NULL,
							   out_reservation_token);
				ioa_network_buffer_set_size(nbh,len);
				*resp_constructed = 1;

				turn_report_allocation_set(&(ss->alloc), lifetime, 0);
			}
		}
	}

	if (!(*resp_constructed)) {

		if (!(*err_code)) {
			*err_code = 437;
		}

		size_t len = ioa_network_buffer_get_size(nbh);
		stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len, tid, NULL, NULL, 0, *err_code, *reason, 0);
		ioa_network_buffer_set_size(nbh,len);
		*resp_constructed = 1;
	}

	return 0;
}

static int handle_turn_refresh(turn_turnserver *server,
			       ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			       int *err_code, 	const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
			       ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	allocation* a = get_allocation_ss(ss);

	u16bits method = STUN_METHOD_REFRESH;

	if (!is_allocation_valid(a)) {

		*err_code = 437;
		*reason = (const u08bits *)"Invalid allocation";

	} else {
		u32bits lifetime = 0;
		int to_delete = 0;

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_LIFETIME: {
				if (stun_attr_get_len(sar) != 4) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Lifetime field format";
				} else {
					const u08bits* value = stun_attr_get_value(sar);
					if (!value) {
						*err_code = 400;
						*reason = (const u08bits *)"Wrong lifetime field data";
					} else {
						lifetime = nswap32(*((const u32bits*)value));
						if (!lifetime)
							to_delete = 1;
					}
				}
			}
				break;
			case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY: {
				int af_req = stun_get_requested_address_family(sar);
				ioa_addr *addr = get_local_addr_from_ioa_socket(a->relay_session.s);
				int is_err = 0;
				switch (af_req) {
				case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
					if(addr->ss.ss_family != AF_INET) {
						is_err = 1;
					}
					break;
				case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
					if(addr->ss.ss_family != AF_INET6) {
						is_err = 1;
					}
					break;
				default:
					is_err = 1;
				}

				if(is_err) {
					*err_code = 443;
					*reason = (const u08bits *)"Peer Address Family Mismatch";
				}
			}
				break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;
			*reason = (const u08bits *)"Unknown attribute";

		} else if (*err_code) {

			;

		} else {

			if (to_delete)
				lifetime = 0;
			else
				lifetime = stun_adjust_allocate_lifetime(lifetime);

			if (refresh_relay_connection(server, ss, lifetime, 0, 0, 0,
					err_code) < 0) {

				if (!(*err_code)) {
					*err_code = 437;
					*reason = (const u08bits *)"Cannot refresh relay connection (internal error)";
				}

			} else {

				turn_report_allocation_set(&(ss->alloc), lifetime, 1);

				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_success_response_str(method, ioa_network_buffer_data(nbh), &len, tid);
				u32bits lt = nswap32(lifetime);

				stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_LIFETIME,
						(const u08bits*) &lt, 4);
				ioa_network_buffer_set_size(nbh,len);

				*resp_constructed = 1;
			}
		}
	}

	if (!(*resp_constructed)) {

		if (!(*err_code)) {
			*err_code = 437;
		}

		size_t len = ioa_network_buffer_get_size(nbh);
		stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
		ioa_network_buffer_set_size(nbh,len);

		*resp_constructed = 1;
	}

	return 0;
}

/* RFC 6062 ==>> */

static void tcp_peer_data_input_handler(ioa_socket_handle s, int event_type, ioa_net_data *in_buffer, void *arg)
{
	if (!(event_type & IOA_EV_READ) || !arg)
		return;

	UNUSED_ARG(s);

	tcp_connection *tc = (tcp_connection*)arg;

	if(tc->state != TC_STATE_READY)
		return;

	if(!(tc->client_s))
		return;

	ioa_network_buffer_handle nbh = in_buffer->nbh;
	in_buffer->nbh = NULL;

	int ret = send_data_from_ioa_socket_nbh(tc->client_s, NULL, nbh, 0, NULL, TTL_IGNORE, TOS_IGNORE);
	if (ret < 0) {
		set_ioa_socket_tobeclosed(s);
	}
}

static void tcp_client_data_input_handler(ioa_socket_handle s, int event_type, ioa_net_data *in_buffer, void *arg)
{
	if (!(event_type & IOA_EV_READ) || !arg)
		return;

	UNUSED_ARG(s);

	tcp_connection *tc = (tcp_connection*)arg;

	if(tc->state != TC_STATE_READY)
		return;

	if(!(tc->peer_s))
		return;

	ioa_network_buffer_handle nbh = in_buffer->nbh;
	in_buffer->nbh = NULL;

	int ret = send_data_from_ioa_socket_nbh(tc->peer_s, NULL, nbh, 0, NULL, TTL_IGNORE, TOS_IGNORE);
	if (ret < 0) {
		set_ioa_socket_tobeclosed(s);
	}
}

static void conn_bind_timeout_handler(ioa_engine_handle e, void *arg)
{
	UNUSED_ARG(e);
	if(arg) {
		tcp_connection *tc = (tcp_connection *)arg;
		delete_tcp_connection(tc);
	}
}

static void client_to_peer_connect_callback(int success, void *arg)
{
	if(arg) {
		tcp_connection *tc = (tcp_connection *)arg;
		allocation *a = (allocation*)(tc->owner);
		ts_ur_super_session *ss = (ts_ur_super_session*)(a->owner);
		turn_turnserver *server=(turn_turnserver*)(ss->server);
		int err_code = 0;

		IOA_EVENT_DEL(tc->peer_conn_timeout);

		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		size_t len = ioa_network_buffer_get_size(nbh);

		if(success) {
			if(register_callback_on_ioa_socket(server->e, tc->peer_s, IOA_EV_READ, tcp_peer_data_input_handler, tc, 1)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot set TCP peer data input callback\n", __FUNCTION__);
				success=0;
				err_code = 500;
			}
		}

		if(success) {
			tc->state = TC_STATE_PEER_CONNECTED;
			stun_init_success_response_str(STUN_METHOD_CONNECT, ioa_network_buffer_data(nbh), &len, &(tc->tid));
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_CONNECTION_ID,
									(const u08bits*)&(tc->id), 4);

			IOA_EVENT_DEL(tc->conn_bind_timeout);
			tc->conn_bind_timeout = set_ioa_timer(server->e, TCP_CONN_BIND_TIMEOUT, 0,
									conn_bind_timeout_handler, tc, 0,
									"conn_bind_timeout_handler");

		} else {
			tc->state = TC_STATE_FAILED;
			if(!err_code)
				err_code = 447;
			const u08bits *reason = (const u08bits *)"Connection Timeout or Failure";
			stun_init_error_response_str(STUN_METHOD_CONNECT, ioa_network_buffer_data(nbh), &len, err_code, reason, &(tc->tid));
		}

		ioa_network_buffer_set_size(nbh,len);

		if(need_stun_authentication(server)) {
			stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd);
			ioa_network_buffer_set_size(nbh,len);
		}

		write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);

		if(!success) {
			delete_tcp_connection(tc);
		}
	}
}

static void peer_conn_timeout_handler(ioa_engine_handle e, void *arg)
{
	UNUSED_ARG(e);

	client_to_peer_connect_callback(0,arg);
}

static int start_tcp_connection_to_peer(turn_turnserver *server, ts_ur_super_session *ss, stun_tid *tid,
				allocation *a, ioa_addr *peer_addr,
				int *err_code, const u08bits **reason)
{
	FUNCSTART;

	if(!ss || !(a->relay_session.s)) {
		*err_code = 500;
		FUNCEND;
		return -1;
	}

	tcp_connection *tc = get_tcp_connection_by_peer(a, peer_addr);
	if(tc) {
		*err_code = 446;
		*reason = (const u08bits *)"Connection Already Exists";
		FUNCEND;
		return -1;
	}

	tc = create_tcp_connection(a, tid, peer_addr, err_code);
	if(!tc) {
		if(!(*err_code)) {
			*err_code = 500;
		}
		FUNCEND;
		return -1;
	} else if(*err_code) {
		delete_tcp_connection(tc);
		FUNCEND;
		return -1;
	}

	IOA_EVENT_DEL(tc->peer_conn_timeout);
	tc->peer_conn_timeout = set_ioa_timer(server->e, TCP_PEER_CONN_TIMEOUT, 0,
						peer_conn_timeout_handler, tc, 0,
						"peer_conn_timeout_handler");

	ioa_socket_handle tcs = ioa_create_connecting_tcp_relay_socket(a->relay_session.s, peer_addr, client_to_peer_connect_callback, tc);
	if(!tcs) {
		delete_tcp_connection(tc);
		*err_code = 500;
		FUNCEND;
		return -1;
	}

	tc->state = TC_STATE_CLIENT_TO_PEER_CONNECTING;
	tc->peer_s = tcs;
	set_ioa_socket_sub_session(tc->peer_s,tc);

	FUNCEND;
	return 0;
}

static void accept_tcp_connection(ioa_socket_handle s, void *arg)
{
	if(s) {
		if(arg) {
			ts_ur_super_session *ss = (ts_ur_super_session*)arg;
			turn_turnserver *server=(turn_turnserver*)(ss->server);

			FUNCSTART;

			allocation *a = &(ss->alloc);
			ioa_addr *peer_addr = get_remote_addr_from_ioa_socket(s);
			if(!good_peer_addr(server, peer_addr)) {
				u08bits saddr[256];
				addr_to_string(peer_addr, saddr);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: an attempt to connect from a peer with forbidden address: %s\n", __FUNCTION__,saddr);
				close_ioa_socket(s);
				FUNCEND;
				return;
			}
			tcp_connection *tc = get_tcp_connection_by_peer(a, peer_addr);
			if(tc) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: peer data socket with this address already exist\n", __FUNCTION__);
				close_ioa_socket(s);
				FUNCEND;
				return;
			}

			if(!can_accept_tcp_connection_from_peer(a,peer_addr)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: peer has no permission to connect\n", __FUNCTION__);
				close_ioa_socket(s);
				FUNCEND;
				return;
			}

			stun_tid tid;
			ns_bzero(&tid,sizeof(tid));
			int err_code=0;
			tc = create_tcp_connection(a, &tid, peer_addr, &err_code);
			if(!tc) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot create TCP connection\n", __FUNCTION__);
				close_ioa_socket(s);
				FUNCEND;
				return;
			}

			tc->state = TC_STATE_PEER_CONNECTED;
			tc->peer_s = s;

			set_ioa_socket_session(s,ss);
			set_ioa_socket_sub_session(s,tc);

			if(register_callback_on_ioa_socket(server->e, s, IOA_EV_READ, tcp_peer_data_input_handler, tc, 1)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot set TCP peer data input callback\n", __FUNCTION__);
				close_ioa_socket(s);
				FUNCEND;
				return;
			}

			IOA_EVENT_DEL(tc->conn_bind_timeout);
			tc->conn_bind_timeout = set_ioa_timer(server->e, TCP_CONN_BIND_TIMEOUT, 0,
								conn_bind_timeout_handler, tc, 0,
								"conn_bind_timeout_handler");

			ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
			size_t len = ioa_network_buffer_get_size(nbh);

			stun_init_indication_str(STUN_METHOD_CONNECTION_ATTEMPT, ioa_network_buffer_data(nbh), &len);
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_CONNECTION_ID,
						(const u08bits*)&(tc->id), 4);
			stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr);

			ioa_network_buffer_set_size(nbh,len);

			if(server->ct == TURN_CREDENTIALS_SHORT_TERM) {
				stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd);
				ioa_network_buffer_set_size(nbh,len);
			}

			write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);

			FUNCEND;

		} else {
			close_ioa_socket(s);
		}
	}
}

static int handle_turn_connect(turn_turnserver *server,
				    ts_ur_super_session *ss, stun_tid *tid,
				    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				    ioa_net_data *in_buffer) {

	FUNCSTART;
	ioa_addr peer_addr;
	int peer_found = 0;
	addr_set_any(&peer_addr);
	allocation* a = get_allocation_ss(ss);

	if(!(ss->is_tcp_relay)) {
		*err_code = 403;
		*reason = (const u08bits *)"Connect cannot be used with UDP relay";
	} else if (!is_allocation_valid(a)) {
		*err_code = 437;
		*reason = (const u08bits *)"Allocation mismatch";
	} else {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
			  {
				if(stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh),
						       ioa_network_buffer_get_size(in_buffer->nbh),
						       sar, &peer_addr,
						       &(ss->default_peer_addr)) == -1) {
					*err_code = 400;
					*reason = (const u08bits *)"Bad Peer Address";
				} else {
					ioa_addr *relay_addr = get_local_addr_from_ioa_socket(a->relay_session.s);

					if(relay_addr->ss.ss_family != peer_addr.ss.ss_family) {
						*err_code = 443;
						*reason = (const u08bits *)"Peer Address Family Mismatch";
					}

					peer_found = 1;
				}
				break;
			  }
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
						     ioa_network_buffer_get_size(in_buffer->nbh),
						     sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;
			*reason = (const u08bits *)"Unknown attribute";

		} else if (*err_code) {

			;

		} else if (!peer_found) {

			*err_code = 400;
			*reason = (const u08bits *)"Where is Peer Address ?";

		} else {
			if(!good_peer_addr(server,&peer_addr)) {
				*err_code = 403;
				*reason = (const u08bits *) "Forbidden IP";
			} else {
				start_tcp_connection_to_peer(server, ss, tid, a, &peer_addr, err_code, reason);
			}
		}
	}

	FUNCEND;
	return 0;
}

static int bind_tcp_connection(turn_turnserver *server, ts_ur_super_session *ss, u32bits id, int *err_code)
{
	tcp_connection *tc = get_tcp_connection_by_id(server->tcp_relay_connections, id);
	if(!tc) {
		*err_code = 404;
		return -1;
	} else if(tc->state == TC_STATE_READY) {
		*err_code = 404;
		return -1;
	} else if(tc->client_s) {
		*err_code = 500;
		return -1;
	} else {
		allocation *a = (allocation*)(tc->owner);
		ts_ur_super_session *ss_orig = (ts_ur_super_session*)(a->owner);
		tc->state = TC_STATE_READY;
		tc->client_s = ss->client_session.s;
		inc_ioa_socket_ref_counter(ss->client_session.s);
		set_ioa_socket_session(tc->client_s,ss_orig);
		set_ioa_socket_sub_session(tc->client_s,tc);
		set_ioa_socket_app_type(tc->client_s,TCP_CLIENT_DATA_SOCKET);
		if(register_callback_on_ioa_socket(server->e, tc->client_s, IOA_EV_READ, tcp_client_data_input_handler, tc, 1)<0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot set TCP client data input callback\n", __FUNCTION__);
			*err_code = 500;
			return -1;
		}
		IOA_EVENT_DEL(tc->conn_bind_timeout);
	}

	return 0;
}

static int handle_turn_connection_bind(turn_turnserver *server,
			       ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			       int *err_code, 	const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
			       ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	allocation* a = get_allocation_ss(ss);

	u16bits method = STUN_METHOD_CONNECTION_BIND;

	if (is_allocation_valid(a)) {

		*err_code = 400;
		*reason = (const u08bits *)"Bad request: CONNECTION_BIND cannot be issued after allocation";

	} else if((get_ioa_socket_type(ss->client_session.s)!=TCP_SOCKET) && (get_ioa_socket_type(ss->client_session.s)!=TLS_SOCKET)) {

		*err_code = 400;
		*reason = (const u08bits *)"Bad request: CONNECTION_BIND only possible with TCP/TLS";

	} else {
		u32bits id = 0;

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_CONNECTION_ID: {
				if (stun_attr_get_len(sar) != 4) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Connection ID field format";
				} else {
					const u08bits* value = stun_attr_get_value(sar);
					if (!value) {
						*err_code = 400;
						*reason = (const u08bits *)"Wrong Connection ID field data";
					} else {
						id = *((const u32bits*)value); //AS-IS encoding, no conversion to/from network byte order
					}
				}
			}
				break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
						     ioa_network_buffer_get_size(in_buffer->nbh), sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;
			*reason = (const u08bits *)"Unknown attribute";

		} else if (*err_code) {

			;

		} else {

			if (bind_tcp_connection(server, ss, id, err_code) < 0) {

				if (!(*err_code)) {
					*err_code = 437;
					*reason = (const u08bits *)"Cannot bind TCP relay connection (internal error)";
				}

			} else {

				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_success_response_str(method, ioa_network_buffer_data(nbh), &len, tid);
				ioa_network_buffer_set_size(nbh,len);

				*resp_constructed = 1;
			}
		}
	}

	if (!(*resp_constructed)) {

		if (!(*err_code)) {
			*err_code = 437;
		}

		size_t len = ioa_network_buffer_get_size(nbh);
		stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
		ioa_network_buffer_set_size(nbh,len);

		*resp_constructed = 1;
	}

	return 0;
}

/* <<== RFC 6062 */

static int handle_turn_channel_bind(turn_turnserver *server,
				    ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				    ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	FUNCSTART;
	u16bits chnum = 0;
	ioa_addr peer_addr;
	addr_set_any(&peer_addr);
	allocation* a = get_allocation_ss(ss);

	if(ss->is_tcp_relay) {
		*err_code = 403;
		*reason = (const u08bits *)"Channel bind cannot be used with TCP relay";
	} else if (is_allocation_valid(a)) {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_CHANNEL_NUMBER: {
				if (chnum) {
					chnum = 0;
					*err_code = 400;
					*reason = (const u08bits *)"Channel number cannot be duplicated in this request";
					break;
				}
				chnum = stun_attr_get_channel_number(sar);
				if (!chnum) {
					*err_code = 400;
					*reason = (const u08bits *)"Channel number cannot be zero in this request";
					break;
				}
			}
				break;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
			  {
				stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh), 
						       ioa_network_buffer_get_size(in_buffer->nbh), 
						       sar, &peer_addr,
						       &(ss->default_peer_addr));

				ioa_addr *relay_addr = get_local_addr_from_ioa_socket(a->relay_session.s);

				if(relay_addr->ss.ss_family != peer_addr.ss.ss_family) {
					*err_code = 443;
					*reason = (const u08bits *)"Peer Address Family Mismatch";
				}

				break;
			  }
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;
			*reason = (const u08bits *)"Unknown attribute";

		} else if (*err_code) {

			;

		} else if (!chnum || addr_any(&peer_addr)) {

			*err_code = 400;
			*reason = (const u08bits *)"Bad channel bind request";

		} else if(!STUN_VALID_CHANNEL(chnum)) {

			*err_code = 400;
			*reason = (const u08bits *)"Bad channel number";

		} else {

			ch_info* chn = allocation_get_ch_info(a, chnum);
			turn_permission_info* tinfo = NULL;

			if (chn) {
				if (!addr_eq(&peer_addr, &(chn->peer_addr))) {
					*err_code = 400;
					*reason = (const u08bits *)"You cannot use the same channel number with different peer";
				} else {
					tinfo = (turn_permission_info*) (chn->owner);
					if (!tinfo) {
						*err_code = 500;
						*reason = (const u08bits *)"Wrong permission info";
					} else {
						if (!addr_eq_no_port(&peer_addr, &(tinfo->addr))) {
							*err_code = 500;
							*reason = (const u08bits *)"Wrong permission info and peer addr conbination";
						} else if (chn->port != addr_get_port(&peer_addr)) {
							*err_code = 500;
							*reason = (const u08bits *)"Wrong port number";
						}
					}
				}

			} else {

				chn = allocation_get_ch_info_by_peer_addr(a, &peer_addr);
				if(chn) {
					*err_code = 400;
					*reason = (const u08bits *)"You cannot use the same peer with different channel number";
				} else {
					if(!good_peer_addr(server,&peer_addr)) {
						*err_code = 403;
						*reason = (const u08bits *) "Forbidden IP";
					} else {
						chn = allocation_get_new_ch_info(a, chnum, &peer_addr);
						if (!chn) {
							*err_code = 500;
							*reason = (const u08bits *) "Cannot find channel data";
						} else {
							tinfo = (turn_permission_info*) (chn->owner);
							if (!tinfo) {
								*err_code = 500;
								*reason
									= (const u08bits *) "Wrong turn permission info";
							}
							if (!(chn->socket_channel)) {
								chn->socket_channel = create_ioa_socket_channel(
									get_relay_socket(a), chn);
								if(!(chn->socket_channel)) {
									*err_code = 500;
									*reason = (const u08bits *) "Cannot create channel socket";
									turn_channel_delete(chn);
								}
							}
						}
					}
				}
			}

			if (!(*err_code) && chn && tinfo) {

			  if (update_channel_lifetime(ss,chn) < 0) {
			    *err_code = 500;
			    *reason = (const u08bits *)"Cannot update channel lifetime (internal error)";
			  } else {
				  size_t len = ioa_network_buffer_get_size(nbh);
				  stun_set_channel_bind_response_str(ioa_network_buffer_data(nbh), &len, tid, 0, NULL);
				  ioa_network_buffer_set_size(nbh,len);
				  *resp_constructed = 1;
			  }
			}
		}
	}

	FUNCEND;
	return 0;
}

static int handle_turn_binding(turn_turnserver *server,
				    ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				    ioa_net_data *in_buffer, ioa_network_buffer_handle nbh,
				    int *origin_changed, ioa_addr *response_origin,
				    int *dest_changed, ioa_addr *response_destination) {

	FUNCSTART;
	ts_ur_session* elem = &(ss->client_session);
	int change_ip = 0;
	int change_port = 0;
	int padding = 0;
	int response_port_present = 0;
	u16bits response_port = 0;
	SOCKET_TYPE st = get_ioa_socket_type(ss->client_session.s);

	*origin_changed = 0;
	*dest_changed = 0;

	stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
						    ioa_network_buffer_get_size(in_buffer->nbh));
	while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
		int attr_type = stun_attr_get_type(sar);
		switch (attr_type) {
		SKIP_ATTRIBUTES;
		case STUN_ATTRIBUTE_CHANGE_REQUEST:
/*
 * This fix allows the client program from the Stuntman source to make STUN binding requests
 * to this server.
 *
 * It was provided by  John Selbie, from STUNTMAN project:
 *
 * "Here's the gist of the change. Stuntman comes with a STUN client library
 * and client program. The client program displays the mapped IP address and
 * port if it gets back a successful binding response.
 * It also interops with JSTUN, a Java implementation of STUN.
 * However, the JSTUN server refuses to respond to any binding request that
 * doesn't have a CHANGE-REQUEST attribute in it.
 * ... workaround is for the client to make a request with an empty CHANGE-REQUEST
 * attribute (neither the ip or port bit are set)."
 *
 */
			stun_attr_get_change_request_str(sar, &change_ip, &change_port);
			if( (!is_rfc5780(server)) && (change_ip || change_port)) {
				*err_code = 420;
				*reason = (const u08bits *)"Unknown attribute: TURN server was configured without RFC 5780 support";
				break;
			}
			if(change_ip || change_port) {
				if(st != UDP_SOCKET) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong request: applicable only to UDP protocol";
				}
			}
			break;
		case STUN_ATTRIBUTE_PADDING:
			if(response_port_present) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request format: you cannot use PADDING and RESPONSE_PORT together";
			} else if((st != UDP_SOCKET) && (st != DTLS_SOCKET)) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request: padding applicable only to UDP and DTLS protocols";
			} else {
				padding = 1;
			}
			break;
		case STUN_ATTRIBUTE_RESPONSE_PORT:
			if(padding) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request format: you cannot use PADDING and RESPONSE_PORT together";
			} else if(st != UDP_SOCKET) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request: applicable only to UDP protocol";
			} else {
				int rp = stun_attr_get_response_port_str(sar);
				if(rp>=0) {
					response_port_present = 1;
					response_port = (u16bits)rp;
				} else {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong response port format";
				}
			}
			break;
		default:
			if(attr_type>=0x0000 && attr_type<=0x7FFF)
				unknown_attrs[(*ua_num)++] = nswap16(attr_type);
		};
		sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
					     ioa_network_buffer_get_size(in_buffer->nbh),
					     sar);
	}

	if (*ua_num > 0) {

		*err_code = 420;
		*reason = (const u08bits *)"Unknown attribute";

	} else if (*err_code) {

		;

	} else {

		size_t len = ioa_network_buffer_get_size(nbh);
		if (stun_set_binding_response_str(ioa_network_buffer_data(nbh), &len, tid,
					get_remote_addr_from_ioa_socket(elem->s), 0, NULL) >= 0) {

			addr_cpy(response_origin, get_local_addr_from_ioa_socket(ss->client_session.s));

			*resp_constructed = 1;

			if(!is_rfc5780(server)) {

				stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
							STUN_ATTRIBUTE_RESPONSE_ORIGIN, response_origin);

			} else {

				ioa_addr other_address;

				if(get_other_address(server,ss,&other_address) == 0) {

					addr_cpy(response_destination, get_remote_addr_from_ioa_socket(ss->client_session.s));

					if(change_ip) {
						*origin_changed = 1;
						if(change_port) {
							addr_cpy(response_origin,&other_address);
						} else {
							int old_port = addr_get_port(response_origin);
							addr_cpy(response_origin,&other_address);
							addr_set_port(response_origin,old_port);
						}
					} else if(change_port) {
						*origin_changed = 1;
						addr_set_port(response_origin,addr_get_port(&other_address));
					}

					stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
									STUN_ATTRIBUTE_RESPONSE_ORIGIN, response_origin);
					stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
									STUN_ATTRIBUTE_OTHER_ADDRESS, &other_address);

					if(response_port_present) {
						*dest_changed = 1;
						addr_set_port(response_destination, (int)response_port);
					}

					if(padding) {
						int mtu = get_local_mtu_ioa_socket(ss->client_session.s);
						if(mtu<68)
							mtu=1500; /* must be more than enough to test fragmentation in real networks */

						mtu = (mtu >> 2) << 2;
						stun_attr_add_padding_str(ioa_network_buffer_data(nbh), &len, (u16bits)mtu);
					}
				}
			}
		}
		ioa_network_buffer_set_size(nbh, len);
	}

	FUNCEND;
	return 0;
}

static int handle_turn_send(turn_turnserver *server, ts_ur_super_session *ss,
			    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
			    ioa_net_data *in_buffer) {

	FUNCSTART;

	ioa_addr peer_addr;
	const u08bits* value = NULL;
	int len = -1;
	int addr_found = 0;
	int set_df = 0;

	addr_set_any(&peer_addr);
	allocation* a = get_allocation_ss(ss);

	if(ss->is_tcp_relay) {
		*err_code = 403;
		*reason = (const u08bits *)"Send cannot be used with TCP relay";
	} else if (is_allocation_valid(a) && (in_buffer->recv_ttl != 0)) {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_DONT_FRAGMENT:
				if(!(server->dont_fragment))
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
				else
					set_df = 1;
				break;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS: {
				if (addr_found) {
					*err_code = 400;
					*reason = (const u08bits *)"Address duplication";
				} else {
					stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh), 
							       ioa_network_buffer_get_size(in_buffer->nbh),
							       sar, &peer_addr,
							       &(ss->default_peer_addr));
				}
			}
				break;
			case STUN_ATTRIBUTE_DATA: {
				if (len >= 0) {
					*err_code = 400;
					*reason = (const u08bits *)"Data duplication";
				} else {
					len = stun_attr_get_len(sar);
					value = stun_attr_get_value(sar);
				}
			}
				break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
		}

		if (*err_code) {
			;
		} else if (*ua_num > 0) {

			*err_code = 420;

		} else if (!addr_any(&peer_addr) && len >= 0) {

			turn_permission_info* tinfo = get_from_turn_permission_map(
					a->addr_to_perm, &peer_addr);
			if (tinfo) {

				set_df_on_ioa_socket(get_relay_socket_ss(ss), set_df);

				ioa_network_buffer_handle nbh = in_buffer->nbh;
				ns_bcopy(value,ioa_network_buffer_data(nbh),len);
				ioa_network_buffer_header_init(nbh);
				ioa_network_buffer_set_size(nbh,len);
				send_data_from_ioa_socket_nbh(get_relay_socket_ss(ss), &peer_addr, nbh, 1, NULL, in_buffer->recv_ttl-1, in_buffer->recv_tos);
				in_buffer->nbh = NULL;
			}

		} else {
			*err_code = 400;
			*reason = (const u08bits *)"No address found";
		}
	}

	FUNCEND;
	return 0;
}

static int update_permission(ts_ur_super_session *ss, ioa_addr *peer_addr) {

	if (!ss || !peer_addr)
		return -1;

	allocation* a = get_allocation_ss(ss);

	turn_permission_info* tinfo = get_from_turn_permission_map(a->addr_to_perm,
			peer_addr);

	if (!tinfo)
		tinfo = allocation_add_permission(a, peer_addr);

	if (!tinfo)
		return -1;

	if (update_turn_permission_lifetime(ss, tinfo, 0) < 0)
		return -1;

	ch_info *chn = get_turn_channel(tinfo, peer_addr);
	if(chn) {
		if (update_channel_lifetime(ss, chn) < 0)
			return -1;
	}

	return 0;
}

static int handle_turn_create_permission(turn_turnserver *server,
					 ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
					 int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
					 ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	int ret = -1;

	ioa_addr peer_addr;
	addr_set_any(&peer_addr);

	int addr_found = 0;

	UNUSED_ARG(server);

	allocation* a = get_allocation_ss(ss);

	if (is_allocation_valid(a)) {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS: {
				stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh), 
						       ioa_network_buffer_get_size(in_buffer->nbh),
						       sar, &peer_addr,
						       &(ss->default_peer_addr));

				ioa_addr *relay_addr = get_local_addr_from_ioa_socket(a->relay_session.s);

				if(relay_addr->ss.ss_family != peer_addr.ss.ss_family) {
					*err_code = 443;
					*reason = (const u08bits *)"Peer Address Family Mismatch";
				} else if(!good_peer_addr(server, &peer_addr)) {
					*err_code = 403;
					*reason = (const u08bits *) "Forbidden IP";
				} else {
					addr_found = 1;
					addr_set_port(&peer_addr, 0);
					if (update_permission(ss, &peer_addr) < 0) {
						*err_code = 500;
						*reason = (const u08bits *)"Cannot update permission (internal error)";
					}
				}
			}
				break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;

		} else if (*err_code) {

			;

		} else if (!addr_found) {

			*err_code = 400;
			*reason = (const u08bits *)"No address found";

		} else {

			size_t len = ioa_network_buffer_get_size(nbh);
			stun_init_success_response_str(STUN_METHOD_CREATE_PERMISSION,
							ioa_network_buffer_data(nbh), &len, tid);
			ioa_network_buffer_set_size(nbh,len);

			ret = 0;
			*resp_constructed = 1;
		}
	}

	return ret;
}

// AUTH ==>>

static int need_stun_authentication(turn_turnserver *server)
{
	switch(server->ct) {
	case TURN_CREDENTIALS_LONG_TERM:
		return 1;
	case TURN_CREDENTIALS_SHORT_TERM:
		return 1;
	default:
		return 0;
	};
}

static int create_challenge_response(turn_turnserver *server,
				ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				int *err_code, 	const u08bits **reason,
				ioa_network_buffer_handle nbh,
				u16bits method)
{
	size_t len = ioa_network_buffer_get_size(nbh);
	stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
	*resp_constructed = 1;
	stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_NONCE,
					ss->nonce, (int)(sizeof(ss->nonce)-1));
	stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_REALM,
					server->realm, (int)(strlen((s08bits*)(server->realm))));
	ioa_network_buffer_set_size(nbh,len);
	return 0;
}

#if !defined(min)
#define min(a,b) ((a)<=(b) ? (a) : (b))
#endif

static void resume_processing_after_username_check(int success,  hmackey_t hmackey, st_password_t pwd, void *ctx, ioa_net_data *in_buffer)
{

	if(ctx && in_buffer && in_buffer->nbh) {

		ts_ur_super_session *ss = (ts_ur_super_session*)ctx;
		turn_turnserver *server = (turn_turnserver *)ss->server;
		ts_ur_session *elem = &(ss->client_session);

		if(success) {
			ns_bcopy(hmackey,ss->hmackey,sizeof(hmackey_t));
			ns_bcopy(pwd,ss->pwd,sizeof(st_password_t));
		}

		read_client_connection(server,elem,ss,in_buffer,0);

		ioa_network_buffer_delete(server->e, in_buffer->nbh);
		in_buffer->nbh=NULL;
	}
}

static int check_stun_auth(turn_turnserver *server,
			ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			int *err_code, 	const u08bits **reason,
			ioa_net_data *in_buffer, ioa_network_buffer_handle nbh,
			u16bits method, int *message_integrity,
			int *postpone_reply,
			int can_resume)
{
	u08bits uname[STUN_MAX_USERNAME_SIZE+1];
	u08bits realm[STUN_MAX_REALM_SIZE+1];
	u08bits nonce[STUN_MAX_NONCE_SIZE+1];
	size_t alen = 0;

	if(!need_stun_authentication(server))
		return 0;

	int new_nonce = 0;

	if(ss->nonce[0]==0) {
		int i = 0;
		for(i=0;i<NONCE_LENGTH_32BITS;i++) {
			u08bits *s = ss->nonce + 8*i;
			snprintf((s08bits*)s, sizeof(ss->nonce)-8*i-1, "%08x",(u32bits)random());
		}
		ss->nonce_expiration_time = turn_time() + STUN_NONCE_EXPIRATION_TIME;
		new_nonce = 1;
	}

	if(server->stale_nonce) {
		if(turn_time_before(ss->nonce_expiration_time,turn_time())) {
			int i = 0;
			for(i=0;i<NONCE_LENGTH_32BITS;i++) {
				u08bits *s = ss->nonce + 8*i;
				snprintf((s08bits*)s, sizeof(ss->nonce)-8*i-1, "%08x",(u32bits)random());
			}
			ss->nonce_expiration_time = turn_time() + STUN_NONCE_EXPIRATION_TIME;
		}
	}

	/* MESSAGE_INTEGRITY ATTR: */

	stun_attr_ref sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh),
							    STUN_ATTRIBUTE_MESSAGE_INTEGRITY);

	if(!sar) {
		*err_code = 401;
		*reason = (u08bits*)"Unauthorised";
		if(server->ct != TURN_CREDENTIALS_SHORT_TERM) {
			return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method);
		} else {
			return -1;
		}

	}

	if(server->ct != TURN_CREDENTIALS_SHORT_TERM) {

		/* REALM ATTR: */

		sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  STUN_ATTRIBUTE_REALM);

		if(!sar) {
			*err_code = 400;
			*reason = (u08bits*)"Bad request";
			return -1;
		}

		alen = min((size_t)stun_attr_get_len(sar),sizeof(realm)-1);
		ns_bcopy(stun_attr_get_value(sar),realm,alen);
		realm[alen]=0;
	}

	/* USERNAME ATTR: */

	sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  STUN_ATTRIBUTE_USERNAME);

	if(!sar) {
		*err_code = 400;
		*reason = (u08bits*)"Bad request";
		return -1;
	}

	alen = min((size_t)stun_attr_get_len(sar),sizeof(uname)-1);
	ns_bcopy(stun_attr_get_value(sar),uname,alen);
	uname[alen]=0;

	if(server->ct != TURN_CREDENTIALS_SHORT_TERM) {
		/* NONCE ATTR: */

		sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  STUN_ATTRIBUTE_NONCE);

		if(!sar) {
			*err_code = 400;
			*reason = (u08bits*)"Bad request";
			return -1;
		}

		alen = min((size_t)stun_attr_get_len(sar),sizeof(nonce)-1);
		ns_bcopy(stun_attr_get_value(sar),nonce,alen);
		nonce[alen]=0;

		/* Stale Nonce check: */

		if(new_nonce) {
			*err_code = 401;
			*reason = (u08bits*)"Unauthorized";
			return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method);
		}

		if(strcmp((s08bits*)ss->nonce,(s08bits*)nonce)) {
			*err_code = 438;
			*reason = (u08bits*)"Stale nonce";
			return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method);
		}
	}

	/* Password */
	if((ss->hmackey[0] == 0) && (ss->pwd[0] == 0)) {
		ur_string_map_value_type ukey = NULL;
		if(can_resume) {
			ukey = (server->userkeycb)(server->id, uname, resume_processing_after_username_check, in_buffer, ss, postpone_reply);
			if(*postpone_reply) {
				return 0;
			}
		}
		/* we always return NULL for short-term credentials here */
		if(!ukey) {
			/* direct user pattern is supported only for long-term credentials */
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"%s: Cannot find credentials of user <%s>\n",
					__FUNCTION__, (char*)uname);
			*err_code = 401;
			*reason = (u08bits*)"Unauthorised";
			if(server->ct != TURN_CREDENTIALS_SHORT_TERM) {
				return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method);
			} else {
				return -1;
			}
		}
		ns_bcopy(ukey,ss->hmackey,16);
	}

	/* Check integrity */
	if(stun_check_message_integrity_by_key_str(server->ct,ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  ss->hmackey,
					  ss->pwd)<1) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"%s: user %s credentials are incorrect\n",
				__FUNCTION__, (char*)uname);
		*err_code = 401;
		*reason = (u08bits*)"Unauthorised";
		if(server->ct != TURN_CREDENTIALS_SHORT_TERM) {
			return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method);
		} else {
			return -1;
		}
	}

	*message_integrity = 1;

	return 0;
}

//<<== AUTH

static void set_alternate_server(alternate_servers_list_t *asl, int af, size_t *counter, u16bits method, stun_tid *tid, int *resp_constructed, int *err_code, const u08bits **reason, ioa_network_buffer_handle nbh)
{
	if(asl && asl->size) {
		size_t i ;
		for(i=0;i<asl->size;++i) {
			if(*counter>=asl->size)
				*counter = 0;
			ioa_addr *addr = &(asl->addrs[*counter]);
			*counter +=1;
			if(addr->ss.ss_family == af) {

				*err_code = 300;
				*reason = (const u08bits *)"Redirect";

				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
				*resp_constructed = 1;
				stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_ALTERNATE_SERVER, addr);
				ioa_network_buffer_set_size(nbh,len);

				return;
			}
		}
	}
}

static int handle_turn_command(turn_turnserver *server, ts_ur_super_session *ss, ioa_net_data *in_buffer, ioa_network_buffer_handle nbh, int *resp_constructed, int can_resume)
{

	stun_tid tid;
	int err_code = 0;
	const u08bits *reason = NULL;
	int no_response = 0;
	int message_integrity = 0;

	u16bits unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
	u16bits ua_num = 0;
	u16bits method = stun_get_method_str(ioa_network_buffer_data(in_buffer->nbh), 
					     ioa_network_buffer_get_size(in_buffer->nbh));

	*resp_constructed = 0;

	stun_tid_from_message_str(ioa_network_buffer_data(in_buffer->nbh), 
				  ioa_network_buffer_get_size(in_buffer->nbh), 
				  &tid);

	if (stun_is_request_str(ioa_network_buffer_data(in_buffer->nbh), 
				ioa_network_buffer_get_size(in_buffer->nbh))) {

		if(method != STUN_METHOD_BINDING) {
			if(server->stun_only) {
				no_response = 1;
				if(server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: STUN method 0x%x ignored\n",
										__FUNCTION__, (unsigned int)method);
				}
			} else {
				int postpone_reply = 0;
				check_stun_auth(server, ss, &tid, resp_constructed, &err_code, &reason, in_buffer, nbh, method, &message_integrity, &postpone_reply, can_resume);
				if(postpone_reply)
					no_response = 1;
			}
		}

		if (!err_code && !(*resp_constructed) && !no_response) {

			switch (method){

			case STUN_METHOD_ALLOCATE:

				if((server->ct == TURN_CREDENTIALS_LONG_TERM)||
					 (server->ct == TURN_CREDENTIALS_SHORT_TERM)) {

					SOCKET_TYPE cst = get_ioa_socket_type(ss->client_session.s);
					int af = get_ioa_socket_address_family(ss->client_session.s);
					alternate_servers_list_t *asl = server->alternate_servers_list;

					if(cst == TLS_SOCKET || cst == DTLS_SOCKET) {
						asl = server->tls_alternate_servers_list;
					}

					set_alternate_server(asl,af,&(server->as_counter),method,&tid,resp_constructed,&err_code,&reason,nbh);
				}

				if(!err_code && !(*resp_constructed) && !no_response) {
					handle_turn_allocate(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);
				}

				if(server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"%s: user <%s>: request ALLOCATE processed, error %d\n",
									__FUNCTION__, (char*)ss->username, err_code);
				}

				break;

			case STUN_METHOD_CONNECT:

				handle_turn_connect(server, ss, &tid, &err_code, &reason,
							unknown_attrs, &ua_num, in_buffer);

				if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: request CONNECT processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}

				if(!err_code)
					no_response = 1;

				break;

			case STUN_METHOD_CONNECTION_BIND:

				handle_turn_connection_bind(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);

				if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: request CONNECTION_BIND processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}

				break;

			case STUN_METHOD_REFRESH:

				handle_turn_refresh(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);

				if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: request REFRESH processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}
				break;

			case STUN_METHOD_CHANNEL_BIND:

				handle_turn_channel_bind(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);

				if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: request CHANNEL_BIND processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}
				break;

			case STUN_METHOD_CREATE_PERMISSION:

				handle_turn_create_permission(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);

				if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: request CREATE_PERMISSION processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}
				break;

			case STUN_METHOD_BINDING:

			{
				int origin_changed=0;
				ioa_addr response_origin;
				int dest_changed=0;
				ioa_addr response_destination;

				handle_turn_binding(server, ss, &tid, resp_constructed, &err_code, &reason,
							unknown_attrs, &ua_num, in_buffer, nbh,
							&origin_changed, &response_origin,
							&dest_changed, &response_destination);

				if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: request BINDING processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}

				if(*resp_constructed && !err_code && (origin_changed || dest_changed)) {

					if (server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "RFC 5780 request successfully processed\n");
					}

					{
						static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
						static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
						size_t len = ioa_network_buffer_get_size(nbh);
						stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
						ioa_network_buffer_set_size(nbh, len);
					}

					send_turn_message_to(server, nbh, &response_origin, &response_destination);

					no_response = 1;
				}

				break;
			}
			default:
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unsupported STUN request received, method 0x%x\n",(unsigned int)method);
			};
		}

	} else if (stun_is_indication_str(ioa_network_buffer_data(in_buffer->nbh), 
					  ioa_network_buffer_get_size(in_buffer->nbh))) {

		no_response = 1;
		int postpone = 0;

		if(server->ct == TURN_CREDENTIALS_SHORT_TERM) {
			check_stun_auth(server, ss, &tid, resp_constructed, &err_code, &reason, in_buffer, nbh, method, &message_integrity, &postpone, can_resume);
		}

		if (!postpone && !err_code) {

			switch (method){

			case STUN_METHOD_SEND:

				handle_turn_send(server, ss, &err_code, &reason, unknown_attrs, &ua_num, in_buffer);

				if(eve(server->verbose)) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: indication SEND processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}

				break;

			case STUN_METHOD_DATA:

				err_code = 403;

				if(eve(server->verbose)) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: user <%s>: indication SEND processed, error %d\n",
										__FUNCTION__, (char*)ss->username, err_code);
				}

				break;

			default:
				if (server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unsupported STUN indication received: method 0x%x\n",(unsigned int)method);
				}
			}
		};

	} else {

		no_response = 1;

		if (server->verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Wrong STUN message received\n");
		}
	}

	if (ua_num > 0) {

		err_code = 420;

		size_t len = ioa_network_buffer_get_size(nbh);
		stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, NULL, &tid);

		stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES, (const u08bits*) unknown_attrs, (ua_num
						* 2));

		ioa_network_buffer_set_size(nbh,len);

		*resp_constructed = 1;
	}

	if (!no_response) {

		if (!(*resp_constructed)) {

			if (!err_code)
				err_code = 400;

			size_t len = ioa_network_buffer_get_size(nbh);
			stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, reason, &tid);
			ioa_network_buffer_set_size(nbh,len);
			*resp_constructed = 1;
		}

		{
			static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
			static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
			ioa_network_buffer_set_size(nbh, len);
		}

		if(message_integrity) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd);
			ioa_network_buffer_set_size(nbh,len);
		}

		if(err_code) {
			if(server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
								"%s: user <%s>: message processed, error %d\n",
								__FUNCTION__, (char*)ss->username, err_code);
			}
		}

	} else {
		*resp_constructed = 0;
	}

	return 0;
}

//////////////////////////////////////////////////////////////////

static int write_to_peerchannel(ts_ur_super_session* ss, u16bits chnum, ioa_net_data *in_buffer) {

	int rc = 0;

	if (ss && get_relay_socket_ss(ss) && (in_buffer->recv_ttl!=0)) {

		allocation* a = get_allocation_ss(ss);

		if (is_allocation_valid(a)) {

			ch_info* chn = allocation_get_ch_info(a, chnum);

			if (!chn)
				return -1;

			/* Channel packets are always sent with DF=0: */
			set_df_on_ioa_socket(get_relay_socket_ss(ss), 0);

			ioa_network_buffer_handle nbh = in_buffer->nbh;
			ns_bcopy((ioa_network_buffer_data(in_buffer->nbh)+STUN_CHANNEL_HEADER_LENGTH),
				  ioa_network_buffer_data(nbh),
				  ioa_network_buffer_get_size(in_buffer->nbh)-STUN_CHANNEL_HEADER_LENGTH);
			ioa_network_buffer_header_init(nbh);
			ioa_network_buffer_set_size(nbh,ioa_network_buffer_get_size(in_buffer->nbh)-STUN_CHANNEL_HEADER_LENGTH);
			rc = send_data_from_ioa_socket_nbh(get_relay_socket_ss(ss), &(chn->peer_addr), nbh, 1, chn->socket_channel, in_buffer->recv_ttl-1, in_buffer->recv_tos);
			in_buffer->nbh = NULL;
		}
	}

	return rc;
}

static void client_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *data, void *arg);
static void peer_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *data, void *arg);

/////////////// Client actions /////////////////

int shutdown_client_connection(turn_turnserver *server, ts_ur_super_session *ss) {

	FUNCSTART;

	if (!ss)
		return -1;

	ts_ur_session* elem = &(ss->client_session);

	if (eve(server->verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"closing session 0x%lx, client socket 0x%lx in state %ld (socket session=0x%lx)\n",
				(long) ss,
				(long) elem->s,
				(long) (elem->state),
				(long)get_ioa_socket_session(elem->s));
	}

	if (elem->state == UR_STATE_DONE) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"!!! closing session 0x%lx, socket 0x%lx in DONE state %ld\n",
				(long)ss, (long) elem->s, (long) (elem->state));
		return -1;
	}

	elem->state = UR_STATE_DONE;

	if (server->disconnect)
		server->disconnect(ss);

	clear_ioa_socket_session_if(elem->s,ss);
	IOA_CLOSE_SOCKET(elem->s);

	if (server->verbose) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TURN connection closed, user <%s>\n",(char*)ss->username);
	}

	turn_server_remove_all_from_ur_map_ss(ss);

	FUNCEND;

	return 0;
}

int shutdown_client_connection_ss(ts_ur_super_session *ss)
{
  return shutdown_client_connection((turn_turnserver*)ss->server, ss);
}

static void client_to_be_allocated_timeout_handler(ioa_engine_handle e,
		void *arg) {

	if (!arg)
		return;

	UNUSED_ARG(e);

	ts_ur_super_session* ss = (ts_ur_super_session*) arg;

	turn_turnserver* server = (turn_turnserver*) (ss->server);

	if (!server)
		return;

	FUNCSTART;

	IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);

	shutdown_client_connection(server, ss);

	FUNCEND;
}

static int write_client_connection(turn_turnserver *server, ts_ur_super_session* ss, ioa_network_buffer_handle nbh, int ttl, int tos) {

	FUNCSTART;

	ts_ur_session* elem = &(ss->client_session);

	if (elem->state != UR_STATE_READY) {
		ioa_network_buffer_delete(server->e, nbh);
		FUNCEND;
		return -1;
	} else {

		++(ss->sent_packets);
		ss->sent_bytes += (u32bits)ioa_network_buffer_get_size(nbh);
		turn_report_session_usage(ss);

		if (eve(server->verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"%s: prepare to write to s 0x%lx\n", __FUNCTION__,
				(long) (elem->s));
		}

		int ret = send_data_from_ioa_socket_nbh(elem->s, NULL, nbh, 0, NULL, ttl, tos);

		FUNCEND;
		return ret;
	}
}

static void client_ss_allocation_timeout_handler(ioa_engine_handle e, void *arg) {

	UNUSED_ARG(e);

	if (!arg)
		return;

	ts_ur_super_session* ss = (ts_ur_super_session*)arg;

	if (!ss)
		return;

	allocation* a =  get_allocation_ss(ss);

	turn_turnserver* server = (turn_turnserver*) (ss->server);

	if (!server) {
		clean_allocation(a);
		return;
	}

	FUNCSTART;

	shutdown_client_connection(server, ss);

	FUNCEND;
}

static int create_relay_connection(turn_turnserver* server,
				   ts_ur_super_session *ss, u32bits lifetime,
				   int address_family, u08bits transport,
				   int even_port, u64bits in_reservation_token, u64bits *out_reservation_token,
				   int *err_code, const u08bits **reason,
				   accept_cb acb) {

	if (server && ss) {

		allocation* a = get_allocation_ss(ss);
		ts_ur_session* newelem = get_relay_session_ss(ss);

		ns_bzero(newelem, sizeof(ts_ur_session));
		newelem->s = NULL;

		ioa_socket_handle rtcp_s = NULL;

		if (in_reservation_token) {

			if (get_ioa_socket_from_reservation(server->e, in_reservation_token,
					&newelem->s) < 0) {
				*err_code = 508;
				*reason = (const u08bits *)"Cannot find reserved socket";
				return -1;
			}

		} else {

			int res = create_relay_ioa_sockets(server->e,
							address_family, transport,
							even_port, &(newelem->s), &rtcp_s, out_reservation_token,
							err_code, reason, acb, ss);
			if (res < 0) {
				if(!(*err_code))
					*err_code = 508;
				if(!(*reason))
					*reason = (const u08bits *)"Cannot create socket";
				return -1;
			}
		}

		if (newelem->s == NULL) {
			*err_code = 508;
			*reason = (const u08bits *)"Cannot create relay socket";
			return -1;
		}

		if (rtcp_s) {
			if (out_reservation_token && *out_reservation_token) {
				/* OK */
			} else {
				IOA_CLOSE_SOCKET(rtcp_s);
				*err_code = 508;
				*reason = (const u08bits *)"Wrong reservation tokens (internal error)";
				return -1;
			}
		}

		newelem->state = UR_STATE_READY;

		/* RFC6156: do not use DF when IPv6 is involved: */
		if((get_local_addr_from_ioa_socket(newelem->s)->ss.ss_family == AF_INET6) ||
		   (get_local_addr_from_ioa_socket(ss->client_session.s)->ss.ss_family == AF_INET6))
			set_do_not_use_df(newelem->s);

		if(get_ioa_socket_type(newelem->s) != TCP_SOCKET) {
			register_callback_on_ioa_socket(server->e, newelem->s, IOA_EV_READ,
				peer_input_handler, ss, 0);
		}

		IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);

		if (lifetime > 0 && a) {

			ioa_timer_handle ev = set_ioa_timer(server->e, lifetime, 0,
					client_ss_allocation_timeout_handler, ss, 0,
					"client_ss_allocation_timeout_handler");
			set_allocation_lifetime_ev(a, lifetime, ev);
		}

		set_ioa_socket_session(newelem->s, ss);
	}

	return 0;
}

static int refresh_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime, int even_port,
		u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code) {

	UNUSED_ARG(even_port);
	UNUSED_ARG(in_reservation_token);
	UNUSED_ARG(out_reservation_token);
	UNUSED_ARG(err_code);

	allocation* a = get_allocation_ss(ss);

	if (server && ss && is_allocation_valid(a)) {

		if (lifetime < 1) {
			set_allocation_valid(a, 0);
			lifetime = 1;
		}

		ioa_timer_handle ev = set_ioa_timer(server->e, lifetime, 0,
				client_ss_allocation_timeout_handler, ss, 0,
				"refresh_client_ss_allocation_timeout_handler");

		set_allocation_lifetime_ev(a, lifetime, ev);

		return 0;

	} else {
		return -1;
	}
}

static int read_client_connection(turn_turnserver *server, ts_ur_session *elem,
				  ts_ur_super_session *ss, ioa_net_data *in_buffer,
				  int can_resume) {

	FUNCSTART;

	if (!server || !elem || !ss || !in_buffer) {
		FUNCEND;
		return -1;
	}

	if (elem->state != UR_STATE_READY) {
		FUNCEND;
		return -1;
	}

	int ret = (int)ioa_network_buffer_get_size(in_buffer->nbh);
	if (ret < 0) {
		FUNCEND;
		return -1;
	}

	++(ss->received_packets);
	ss->received_bytes += (u32bits)ioa_network_buffer_get_size(in_buffer->nbh);
	turn_report_session_usage(ss);

	if (eve(server->verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
			      "%s: data.buffer=0x%lx, data.len=%ld\n", __FUNCTION__,
			      (long)ioa_network_buffer_data(in_buffer->nbh), 
			      (long)ioa_network_buffer_get_size(in_buffer->nbh));
	}

	u16bits chnum = 0;

	if (stun_is_channel_message_str(ioa_network_buffer_data(in_buffer->nbh), 
					ioa_network_buffer_get_size(in_buffer->nbh), 
					&chnum)) {

		if(ss->is_tcp_relay) {
			//Forbidden
			FUNCEND;
			return -1;
		}
		int rc = write_to_peerchannel(ss, chnum, in_buffer);

		if (eve(server->verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrote to peer %d bytes\n",
					__FUNCTION__, (int) rc);
		}

		FUNCEND;
		return 0;

	} else if (stun_is_command_message_full_check_str(ioa_network_buffer_data(in_buffer->nbh),
			ioa_network_buffer_get_size(in_buffer->nbh), 0, &(ss->enforce_fingerprints))) {

		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		int resp_constructed = 0;

		handle_turn_command(server, ss, in_buffer, nbh, &resp_constructed, can_resume);

		if(resp_constructed) {

			if(server->fingerprint || ss->enforce_fingerprints) {
				size_t len = ioa_network_buffer_get_size(nbh);
				if(stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh),&len)<0) {
					FUNCEND;
					ioa_network_buffer_delete(server->e, nbh);
					return -1;
				}
				ioa_network_buffer_set_size(nbh,len);
			}

			int ret = write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);

			FUNCEND;
			return ret;
		} else {
			ioa_network_buffer_delete(server->e, nbh);
			return 0;
		}

	}

	//Unrecognised message received

	FUNCEND;
	return -1;
}

int open_client_connection_session(turn_turnserver* server,
				struct socket_message *sm) {

	FUNCSTART;
	if (!server)
		return -1;

	if (!(sm->s))
		return -1;

	ts_ur_super_session* ss = create_new_ss(server);

	ts_ur_session *newelem = &(ss->client_session);

	newelem->s = sm->s;

	register_callback_on_ioa_socket(server->e, newelem->s, IOA_EV_READ,
			client_input_handler, ss, 0);

	newelem->state = UR_STATE_READY;

	set_ioa_socket_session(ss->client_session.s, ss);

	newelem->state = UR_STATE_READY;
	if (server->stats)
		++(*(server->stats));

	IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);
	ss->to_be_allocated_timeout_ev = set_ioa_timer(server->e,
			TURN_MAX_TO_ALLOCATE_TIMEOUT, 0,
			client_to_be_allocated_timeout_handler, ss, 0,
			"client_to_be_allocated_timeout_handler");

	if(sm->nbh) {
		ioa_net_data nd;

		ns_bzero(&nd,sizeof(nd));
		addr_cpy(&(nd.src_addr),&(sm->remote_addr));
		nd.nbh = sm->nbh;
		nd.chnum = sm->chnum;
		nd.recv_ttl = TTL_IGNORE;
		nd.recv_tos = TOS_IGNORE;

		sm->nbh=NULL;

		client_input_handler(newelem->s,IOA_EV_READ,&nd,ss);
		ioa_network_buffer_delete(server->e, nd.nbh);
	}

	FUNCEND;

	return 0;
}

/////////////// io handlers ///////////////////

static void peer_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *in_buffer, void *arg) {

	if (!(event_type & IOA_EV_READ) || !arg)
		return;

	if(in_buffer->recv_ttl==0)
		return;

	UNUSED_ARG(s);

	ts_ur_super_session* ss = (ts_ur_super_session*) arg;

	if(!ss) return;

	turn_turnserver *server = (turn_turnserver*) (ss->server);

	if (!server) {
		return;
	}

	ts_ur_session* elem = get_relay_session_ss(ss);
	if (elem->s == NULL) {
		return;
	}

	int offset = STUN_CHANNEL_HEADER_LENGTH;

	int ilen = min((int)ioa_network_buffer_get_size(in_buffer->nbh),
					(int)(ioa_network_buffer_get_capacity() - offset));

	if (ilen >= 0) {

		size_t len = (size_t)(ilen);

		allocation* a = get_allocation_ss(ss);
		if (is_allocation_valid(a)) {

			u16bits chnum = in_buffer->chnum;

			ioa_network_buffer_handle nbh = NULL;

			if(!chnum) {
				/*
				 * If chnum hint is provided, then
				 * we do not need to go through this expensive block.
				 */
				turn_permission_info* tinfo = allocation_get_permission(a,
								&(in_buffer->src_addr));
					if (tinfo)
					chnum = get_turn_channel_number(tinfo, &(in_buffer->src_addr));
			}

			if (chnum) {
				nbh = in_buffer->nbh;
				ns_bcopy(ioa_network_buffer_data(in_buffer->nbh), (s08bits*)(ioa_network_buffer_data(nbh)+offset), len);
				ioa_network_buffer_header_init(nbh);
				stun_init_channel_message_str(chnum, ioa_network_buffer_data(nbh), &len, len);
				ioa_network_buffer_set_size(nbh,len);
				in_buffer->nbh = NULL;
				if (eve(server->verbose)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"%s: send channel 0x%x\n", __FUNCTION__,
							(int) (chnum));
				}
			} else {
				nbh = ioa_network_buffer_allocate(server->e);
				stun_init_indication_str(STUN_METHOD_DATA, ioa_network_buffer_data(nbh), &len);
				stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_DATA,
								ioa_network_buffer_data(in_buffer->nbh), (size_t)ilen);
				stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
						STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
						&(in_buffer->src_addr));
				ioa_network_buffer_set_size(nbh,len);

				if(server->ct == TURN_CREDENTIALS_SHORT_TERM) {
					stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd);
					ioa_network_buffer_set_size(nbh,len);
				}
			}
			if (eve(server->verbose)) {
				u16bits* t = (u16bits*) ioa_network_buffer_data(nbh);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Send data: 0x%x\n",
						(int) (nswap16(t[0])));
			}

			int ret = write_client_connection(server, ss, nbh, in_buffer->recv_ttl-1, in_buffer->recv_tos);
			if (ret < 0)
				set_ioa_socket_tobeclosed(s);
		}
	}
}

static void client_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *data, void *arg) {

	if (!arg)
		return;

	UNUSED_ARG(s);
	UNUSED_ARG(event_type);

	ts_ur_super_session* ss = (ts_ur_super_session*)arg;

	turn_turnserver *server = (turn_turnserver*)ss->server;

	if (!server) {
		return;
	}

	ts_ur_session* elem = &(ss->client_session);

	if (elem->s == NULL) {
		return;
	}

	int ret = 0;

	switch (elem->state) {
	case UR_STATE_READY:
		read_client_connection(server, elem, ss, data, 1);
		break;
	case UR_STATE_DONE:
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"!!! %s: Trying to read from closed socket: s=0x%lx\n",
				__FUNCTION__, (long) (elem->s));
		return;
	default:
		ret = -1;
	}

	if (ret < 0 && server->verbose) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"Error on client handler: s=0x%lx\n", (long) (elem->s));
		set_ioa_socket_tobeclosed(s);
	}
}

///////////////////////////////////////////////////////

static int init_server(turn_turnserver* server) {

	if (!server)
		return -1;

	return 0;
}

static int clean_server(turn_turnserver* server) {

	if (!server)
		return -1;
 
	return 0;
}

///////////////////////////////////////////////////////////

turn_turnserver* create_turn_server(turnserver_id id, int verbose, ioa_engine_handle e,
		u32bits *stats,
		int stun_port, int fingerprint, dont_fragment_option_t dont_fragment,
		turn_credential_type ct,
		u08bits *realm,
		get_user_key_cb userkeycb,
		check_new_allocation_quota_cb chquotacb,
		release_allocation_quota_cb raqcb,
		ioa_addr *external_ip,
		int no_tcp_relay,
		int no_udp_relay,
		int stale_nonce,
		int stun_only,
		alternate_servers_list_t *alternate_servers_list,
		alternate_servers_list_t *tls_alternate_servers_list,
		int no_multicast_peers, int no_loopback_peers,
		ip_range_list_t* ip_whitelist, ip_range_list_t* ip_blacklist) {

	turn_turnserver* server =
			(turn_turnserver*) turn_malloc(sizeof(turn_turnserver));

	if (!server)
		return server;

	ns_bzero(server,sizeof(turn_turnserver));

	server->id = id;
	server->tcp_relay_connections = ur_map_create();
	server->ct = ct;
	STRCPY(server->realm,realm);
	server->userkeycb = userkeycb;
	server->chquoatacb = chquotacb;
	server->raqcb = raqcb;
	server->no_multicast_peers = no_multicast_peers;
	server->no_loopback_peers = no_loopback_peers;

	server->no_tcp_relay = no_tcp_relay;
	server->no_udp_relay = no_udp_relay;

	server->alternate_servers_list = alternate_servers_list;
	server->tls_alternate_servers_list = tls_alternate_servers_list;

	server->stale_nonce = stale_nonce;
	server->stun_only = stun_only;

	server->dont_fragment = dont_fragment;
	server->fingerprint = fingerprint;
	server->stats = stats;
	server->external_ip = external_ip;
	if (stun_port < 1)
		stun_port = DEFAULT_STUN_PORT;

	server->verbose = verbose;

	server->e = e;

	server->ip_whitelist = ip_whitelist;
	server->ip_blacklist = ip_blacklist;

	if (init_server(server) < 0) {
	  turn_free(server,sizeof(turn_turnserver));
	  return NULL;
	}

	return server;
}

void delete_turn_server(turn_turnserver* server) {
	if (server) {
		clean_server(server);
		turn_free(server,sizeof(turn_turnserver));
	}
}

ioa_engine_handle turn_server_get_engine(turn_turnserver *s) {
	if(s)
		return s->e;
	return NULL;
}

void set_disconnect_cb(turn_turnserver* server, int(*disconnect)(
		ts_ur_super_session*)) {
	server->disconnect = disconnect;
}

//////////////////////////////////////////////////////////////////
