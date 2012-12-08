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

#include "ns_turn_server.h"

#include "ns_turn_utils.h"
#include "ns_turn_allocation.h"
#include "ns_turn_msg_addr.h"

///////////////////////////////////////////

#define FUNCSTART if(server && server->verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && server->verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

////////////////////////////////////////////////

#define MAX_NUMBER_OF_UNKNOWN_ATTRS (128)

#define TURN_MAX_TO_ALLOCATE_TIMEOUT (30)

///////////////////////////////////////////

struct _turn_turnserver {

	ioa_engine_handle e;
	int verbose;
	int fingerprint;
	dont_fragment_option_t dont_fragment;
	u32bits *stats;
	int (*disconnect)(ts_ur_super_session*);
	turn_user_db *users;
};

///////////////////////////////////////////

static int create_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime, int address_family,
		int even_port, u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code, const u08bits **reason);

static int refresh_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime, int even_port,
		u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code);

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

static ts_ur_super_session* init_super_session(ts_ur_super_session *ss) {
	if (ss) {
		ns_bzero(ss,sizeof(ts_ur_super_session));
		init_allocation(&(ss->alloc));
	}
	return ss;
}

static ts_ur_super_session* create_new_ss(void) {
	return init_super_session((ts_ur_super_session*) turn_malloc(
			sizeof(ts_ur_super_session)));
}

static int check_new_allocation_quota(turn_turnserver *server, u08bits *username)
{
	int ret = 0;
	if (server && username) {
		ur_string_map_lock(server->users->alloc_counters);
		if (server->users->total_quota && (server->users->total_current_allocs >= server->users->total_quota)) {
			ret = -1;
		} else {
			ur_string_map_value_type value = 0;
			if (!ur_string_map_get(server->users->alloc_counters, (ur_string_map_key_type) username, &value)) {
				value = (ur_string_map_value_type) 1;
				ur_string_map_put(server->users->alloc_counters, (ur_string_map_key_type) username, value);
				++(server->users->total_current_allocs);
			} else {
				if ((server->users->user_quota) && ((size_t) value >= server->users->user_quota)) {
					ret = -1;
				} else {
					value = (ur_string_map_value_type)(((size_t)value) + 1);
					ur_string_map_put(server->users->alloc_counters, (ur_string_map_key_type) username, value);
					++(server->users->total_current_allocs);
				}
			}
		}
		ur_string_map_unlock(server->users->alloc_counters);
	}
	return ret;
}

static void release_allocation_quota(turn_turnserver *server, u08bits *username)
{
	if (server && username) {
		ur_string_map_lock(server->users->alloc_counters);
		ur_string_map_value_type value = 0;
		ur_string_map_get(server->users->alloc_counters, (ur_string_map_key_type) username, &value);
		if (value) {
			value = (ur_string_map_value_type)(((size_t)value) - 1);
			ur_string_map_put(server->users->alloc_counters, (ur_string_map_key_type) username, value);
		}
		if (server->users->total_current_allocs)
			--(server->users->total_current_allocs);
		ur_string_map_unlock(server->users->alloc_counters);
	}
}

/////////// clean all /////////////////////

static void delete_ur_map_ss(void *p) {
	if (p) {
		ts_ur_super_session* ss = (ts_ur_super_session*) p;
		delete_ur_map_session_elem_data(&(ss->client_session));
		free_allocation(get_allocation_ss(ss));
		IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);
		turn_free(p,sizeof(ts_ur_super_session));
	}
}

static int turn_server_remove_all_from_ur_map_ss(ts_ur_super_session* ss) {
	if (!ss)
		return 0;
	else {
		int ret = 0;
		release_allocation_quota(ss->server,ss->username);
		if (ss->client_session.s) {
			set_ioa_socket_session(ss->client_session.s, NULL);
		}
		if (get_relay_socket_ss(ss)) {
			set_ioa_socket_session(get_relay_socket_ss(ss), NULL);
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

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s\n", __FUNCTION__);

	ch_info* chn = (ch_info*) arg;

	turn_channel_delete(chn);
}

static void client_ss_perm_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);

	if (!arg)
		return;

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s\n", __FUNCTION__);

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

#define SKIP_AUTH_ATTRIBUTES case STUN_ATTRIBUTE_FINGERPRINT: case STUN_ATTRIBUTE_MESSAGE_INTEGRITY: break; \
	case STUN_ATTRIBUTE_USERNAME: case STUN_ATTRIBUTE_REALM: case STUN_ATTRIBUTE_NONCE: \
	sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),\
		ioa_network_buffer_get_size(in_buffer->nbh), sar); \
	continue

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
			stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len,
							tid,
					get_local_addr_from_ioa_socket(get_relay_socket_ss(ss)),
					get_remote_addr_from_ioa_socket(elem->s),
					(a->expiration_time - turn_time()), 0, NULL, 0);
			ioa_network_buffer_set_size(nbh,len);
			*resp_constructed = 1;
		}

	} else {

		a = NULL;

		int valid_transport_included = 0;
		u32bits lifetime = 0;
		int even_port = -1;
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
			SKIP_AUTH_ATTRIBUTES;
			case STUN_ATTRIBUTE_REQUESTED_TRANSPORT: {
				if (stun_attr_get_len(sar) != 4) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Transport Field";
				} else {
					const u08bits* value = stun_attr_get_value(sar);
					if (value) {
						if (value[0] != 17 || value[1] || value[2] || value[3]) {
							*err_code = 442;
							*reason = (const u08bits *)"Wrong Transport"; 
						} else {
							valid_transport_included = 1;
						}
					} else {
						*err_code = 400;
						*reason = (const u08bits *)"Wrong Transport Data";
					}
				}
			}
				break;
			case STUN_ATTRIBUTE_DONT_FRAGMENT:
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

		if (!valid_transport_included) {

		  *err_code = 400;
		  if(!(*reason))
		    *reason = (const u08bits *)"Transport field missed";
		  
		} else if (*ua_num > 0) {

		  *err_code = 420;
		  if(!(*reason))
		    *reason = (const u08bits *)"Unknown attribute";

		} else if (*err_code) {

			;

		} else {

			lifetime = stun_adjust_allocate_lifetime(lifetime);
			u64bits out_reservation_token = 0;

			if(check_new_allocation_quota(server,username)<0) {

				*err_code = 486;
				*reason = (const u08bits *)"Allocation Quota Reached";

			} else if (create_relay_connection(server, ss, lifetime, af, even_port,
						    in_reservation_token, &out_reservation_token, err_code, reason) < 0) {

				release_allocation_quota(server,username);

				if (!*err_code) {
				  *err_code = 437;
				  if(!(*reason))
				    *reason = (const u08bits *)"Cannot create relay endpoint";
				}

			} else {

				a = get_allocation_ss(ss);
				set_allocation_valid(a,1);

				strcpy((char*)ss->username,(char*)username);

				stun_tid_cpy(&(a->tid), tid);

				size_t len = ioa_network_buffer_get_size(nbh);

				stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len, tid,
							   get_local_addr_from_ioa_socket(get_relay_socket_ss(ss)),
							   get_remote_addr_from_ioa_socket(elem->s), lifetime, 
							   0,NULL,
							   out_reservation_token);
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
			SKIP_AUTH_ATTRIBUTES;
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

static int handle_turn_channel_bind(turn_turnserver *server,
				    ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				    ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	FUNCSTART;
	u16bits chnum = 0;
	ioa_addr peer_addr;
	addr_set_any(&peer_addr);
	allocation* a = get_allocation_ss(ss);

	if (is_allocation_valid(a)) {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_AUTH_ATTRIBUTES;
			case STUN_ATTRIBUTE_CHANNEL_NUMBER: {
				if (chnum) {
					chnum = 0;
					*err_code = 400;
					*reason = (const u08bits *)"Channel number cannot be used in this request";
					break;
				}
				chnum = stun_attr_get_channel_number(sar);
			}
				break;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
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

		} else if (chnum && !addr_any(&peer_addr)) {

			ch_info* chn = allocation_get_ch_info(a, chnum);
			turn_permission_info* tinfo = NULL;

			if (chn) {
				if (!addr_eq(&peer_addr, &(chn->peer_addr))) {
					*err_code = 403;
					*reason = (const u08bits *)"Wrong Peer Addr";
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
				if(chn)
					turn_channel_delete(chn);

				chn = allocation_get_new_ch_info(a, chnum, &peer_addr);
				if (!chn) {
				  *err_code = 500;
				  *reason = (const u08bits *)"Cannot find channel data";
				} else {
				  tinfo = (turn_permission_info*) (chn->owner);
				  if (!tinfo) {
				    *err_code = 500;
				    *reason = (const u08bits *)"Wrong turn permission info";
				  }
				  if(!(chn->socket_channel))
				  	chn->socket_channel = create_ioa_socket_channel(get_relay_socket(a), chn);
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

	if (is_allocation_valid(a) && (in_buffer->recv_ttl != 0)) {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_AUTH_ATTRIBUTES;
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
			SKIP_AUTH_ATTRIBUTES;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS: {
				stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh), 
						       ioa_network_buffer_get_size(in_buffer->nbh),
						       sar, &peer_addr,
						       &(ss->default_peer_addr));

				ioa_addr *relay_addr = get_local_addr_from_ioa_socket(a->relay_session.s);

				if(relay_addr->ss.ss_family != peer_addr.ss.ss_family) {
					*err_code = 443;
					*reason = (const u08bits *)"Peer Address Family Mismatch";
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
	switch(server->users->ct) {
	case TURN_CREDENTIALS_LONG_TERM:
		return 1;
	case TURN_CREDENTIALS_NONE:
		return 0;
	default:
		fprintf(stderr,"Wrong credential mechanism used\n");
		exit(-1);
	};
}

static int create_challenge_response(turn_turnserver *server,
				ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				int *err_code, 	const u08bits **reason,
				ioa_network_buffer_handle nbh,
				u16bits method, int regenerate_nonce)
{
	int i = 0;
	size_t len = ioa_network_buffer_get_size(nbh);
	stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
	*resp_constructed = 1;
	if(regenerate_nonce) {
		for(i=0;i<NONCE_LENGTH_32BITS;i++) {
			u08bits *s = ss->nonce + 8*i;
			sprintf((s08bits*)s,"%08x",(u32bits)random());
		}
		ss->nonce_expiration_time = turn_time() + STUN_NONCE_EXPIRATION_TIME;
	}
	stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_NONCE,
					ss->nonce, (int)(sizeof(ss->nonce)-1));
	stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_REALM,
					server->users->realm, (int)(strlen((s08bits*)(server->users->realm))));
	ioa_network_buffer_set_size(nbh,len);
	return 0;
}

#if !defined(min)
#define min(a,b) ((a)<=(b) ? (a) : (b))
#endif

static int check_stun_auth(turn_turnserver *server,
			ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			int *err_code, 	const u08bits **reason,
			ioa_net_data *in_buffer, ioa_network_buffer_handle nbh,
			u16bits method, int *message_integrity)
{
	u08bits uname[STUN_MAX_USERNAME_SIZE+1];
	u08bits realm[STUN_MAX_REALM_SIZE+1];
	u08bits nonce[STUN_MAX_NONCE_SIZE+1];
	size_t alen = 0;

	if(!need_stun_authentication(server))
		return 0;

	int regenerate_nonce = turn_time_before(ss->nonce_expiration_time,turn_time()) || (ss->nonce[0]==0);

	/* MESSAGE_INTEGRITY ATTR: */

	stun_attr_ref sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh),
							    STUN_ATTRIBUTE_MESSAGE_INTEGRITY);

	if(!sar) {
		*err_code = 401;
		*reason = (u08bits*)"Unauthorised";
		return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method,regenerate_nonce);
	}

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

	if(regenerate_nonce || strcmp((s08bits*)ss->nonce,(s08bits*)nonce)) {
		*err_code = 438;
		*reason = (u08bits*)"Stale Nonce";
		return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method,regenerate_nonce);
	}

	/* Password */
	if(ss->hmackey[0] == 0) {
		ur_string_map_value_type ukey;
		ur_string_map_lock(server->users->accounts);
		if(!ur_string_map_get(server->users->accounts, (ur_string_map_key_type)uname, &ukey)) {
			ur_string_map_unlock(server->users->accounts);
			*err_code = 401;
			*reason = (u08bits*)"Unauthorised";
			return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method,regenerate_nonce);
		}
		ns_bcopy(ukey,ss->hmackey,16);
		ur_string_map_unlock(server->users->accounts);
	}

	/* Check integrity */
	if(stun_check_message_integrity_by_key_str(ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  ss->hmackey)<1) {
		*err_code = 401;
		*reason = (u08bits*)"Unauthorised";
		return create_challenge_response(server,ss,tid,resp_constructed,err_code,reason,nbh,method,regenerate_nonce);
	}

	*message_integrity = 1;

	return 0;
}

//<<== AUTH

static int handle_turn_command(turn_turnserver *server, ts_ur_super_session *ss, ioa_net_data *in_buffer, ioa_network_buffer_handle nbh, int *resp_constructed)
{

	stun_tid tid;
	int err_code = 0;
	const u08bits *reason = NULL;
	int no_response = 0;
	int message_integrity = 0;

	ts_ur_session* elem = &(ss->client_session);
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

		check_stun_auth(server, ss, &tid, resp_constructed, &err_code, &reason, in_buffer, nbh, method, &message_integrity);

		if (!err_code && !(*resp_constructed)) {

			switch (method){

			case STUN_METHOD_ALLOCATE:

				handle_turn_allocate(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);
				break;

			case STUN_METHOD_REFRESH:

				handle_turn_refresh(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);
				break;

			case STUN_METHOD_CHANNEL_BIND:

				handle_turn_channel_bind(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);
				break;

			case STUN_METHOD_CREATE_PERMISSION:

				handle_turn_create_permission(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);
				break;

			case STUN_METHOD_BINDING:
			{
				size_t len = ioa_network_buffer_get_size(nbh);
				if (stun_set_binding_response_str(ioa_network_buffer_data(nbh), &len, &tid,
								get_remote_addr_from_ioa_socket(elem->s), 0, NULL) >= 0) {
					*resp_constructed = 1;
				}
				ioa_network_buffer_set_size(nbh, len);
			}
				break;

			default:
				if (server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unsupported STUN request received\n");
				}
			};
		}

	} else if (stun_is_indication_str(ioa_network_buffer_data(in_buffer->nbh), 
					  ioa_network_buffer_get_size(in_buffer->nbh))) {

		no_response = 1;

		switch (method){

		case STUN_METHOD_SEND:

		  handle_turn_send(server, ss, &err_code, &reason, unknown_attrs, &ua_num, in_buffer);

			break;

		case STUN_METHOD_DATA:

			err_code = 403;

			break;

		default:
			if (server->verbose) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unsupported STUN indication received\n");
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

		if(message_integrity) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_integrity_str(ioa_network_buffer_data(nbh),&len,ss->hmackey);
			ioa_network_buffer_set_size(nbh,len);
		}
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

	if (server->verbose) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"closing connection 0x%lx in state %ld\n", (long) elem->s,
				(long) (elem->state));
	}

	if (elem->state == UR_STATE_DONE) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"!!! closing connection 0x%lx in DONE state %ld\n",
				(long) elem->s, (long) (elem->state));
		return -1;
	}

	elem->state = UR_STATE_DONE;

	if (server->disconnect)
		server->disconnect(ss);

	IOA_CLOSE_SOCKET(elem->s);

	turn_server_remove_all_from_ur_map_ss(ss);

	if (server->verbose) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TURN connection closed.\n");
	}

	FUNCEND;

	return 0;
}

int shutdown_client_connection_ss(ts_ur_super_session *ss)
{
	return shutdown_client_connection(ss->server, ss);
}

static void client_to_be_allocated_timeout_handler(ioa_engine_handle e,
		void *arg) {

	if (!arg)
		return;

	UNUSED_ARG(e);

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s\n", __FUNCTION__);

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

		if (server->verbose) {
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

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s\n", __FUNCTION__);

	ts_ur_super_session* ss = (ts_ur_super_session*)arg;

	if (!ss)
		return;

	allocation* a =  get_allocation_ss(ss);

	turn_turnserver* server = (turn_turnserver*) (ss->server);

	if (!server) {
		free_allocation(a);
		return;
	}

	FUNCSTART;

	shutdown_client_connection(server, ss);

	FUNCEND;
}

static int create_relay_connection(turn_turnserver* server,
				   ts_ur_super_session *ss, u32bits lifetime, int address_family,
				   int even_port, u64bits in_reservation_token, u64bits *out_reservation_token,
				   int *err_code, const u08bits **reason) {

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

			int res = create_relay_ioa_sockets(server->e, address_family, even_port,
					&(newelem->s), &rtcp_s, out_reservation_token,
					err_code, reason);
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

		register_callback_on_ioa_socket(server->e, newelem->s, IOA_EV_READ,
				peer_input_handler, ss);

		IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);

		if (lifetime > 0 && a) {

			ioa_timer_handle ev = set_ioa_timer(server->e, lifetime, 0,
					client_ss_allocation_timeout_handler, ss, 0,
					"client_ss_allocation_timeout_handler");
			set_allocation_lifetime_ev(a, turn_time() + lifetime, ev);
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

		set_allocation_lifetime_ev(a, turn_time() + lifetime, ev);

		return 0;

	} else {
		return -1;
	}
}

static int read_client_connection(turn_turnserver *server, ts_ur_session *elem,
				  ts_ur_super_session *ss, ioa_net_data *in_buffer) {

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

	if (server->verbose) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
			      "%s: data.buffer=0x%lx, data.len=%ld\n", __FUNCTION__,
			      (long)ioa_network_buffer_data(in_buffer->nbh), 
			      (long)ioa_network_buffer_get_size(in_buffer->nbh));
	}

	u16bits chnum = 0;

	if (stun_is_channel_message_str(ioa_network_buffer_data(in_buffer->nbh), 
					ioa_network_buffer_get_size(in_buffer->nbh), 
					&chnum)) {

		int rc = write_to_peerchannel(ss, chnum, in_buffer);

		if (server->verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrote to peer %d bytes\n",
					__FUNCTION__, (int) rc);
		}

		FUNCEND;
		return 0;

	} else if (stun_is_command_message_full_check_str(ioa_network_buffer_data(in_buffer->nbh),
					       ioa_network_buffer_get_size(in_buffer->nbh), 0)) {

		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		int resp_constructed = 0;

		handle_turn_command(server, ss, in_buffer, nbh, &resp_constructed);

		if(resp_constructed) {

			if(server->fingerprint) {
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

	ts_ur_super_session* ss = create_new_ss();
	ss->server = server;

	ts_ur_session *newelem = &(ss->client_session);

	newelem->s = sm->s;

	register_callback_on_ioa_socket(server->e, newelem->s, IOA_EV_READ,
			client_input_handler, ss);

	newelem->state = UR_STATE_READY;

	set_ioa_socket_session(ss->client_session.s, ss);

	newelem->state = UR_STATE_READY;
	if (server->stats)
		++(*(server->stats));

	ss->to_be_allocated_timeout_ev = set_ioa_timer(server->e,
			TURN_MAX_TO_ALLOCATE_TIMEOUT, 0,
			client_to_be_allocated_timeout_handler, ss, 0,
			"client_to_be_allocated_timeout_handler");

	if(sm->nbh) {
		ioa_net_data nd = { &(sm->remote_addr), sm->nbh, sm->chnum, TTL_IGNORE, TOS_IGNORE };
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
								in_buffer->remote_addr);
					if (tinfo)
					chnum = get_turn_channel_number(tinfo, in_buffer->remote_addr);
			}

			if (chnum) {
				nbh = in_buffer->nbh;
				ns_bcopy(ioa_network_buffer_data(in_buffer->nbh), (s08bits*)(ioa_network_buffer_data(nbh)+offset), len);
				ioa_network_buffer_header_init(nbh);
				stun_init_channel_message_str(chnum, ioa_network_buffer_data(nbh), &len, len);
				ioa_network_buffer_set_size(nbh,len);
				in_buffer->nbh = NULL;
				if (server->verbose) {
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
						in_buffer->remote_addr);
				ioa_network_buffer_set_size(nbh,len);
			}
			if (server->verbose) {
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

	ts_ur_super_session* ss = arg;

	turn_turnserver *server = ss->server;

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
		read_client_connection(server, elem, ss, data);
		break;
	case UR_STATE_DONE:
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"!!! %s: Trying to read from closed socket: s=0x%lx\n",
				__FUNCTION__, (long) (elem->s));
		return;
	default:
		ret = -1;
	}

	if (ret < 0 && server->verbose) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
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


turn_turnserver* create_turn_server(int verbose, ioa_engine_handle e,
		u32bits *stats,
		int stun_port, int fingerprint, dont_fragment_option_t dont_fragment,
		turn_user_db *users) {

	turn_turnserver* server =
			(turn_turnserver*) turn_malloc(sizeof(turn_turnserver));

	if (!server)
		return server;

	ns_bzero(server,sizeof(turn_turnserver));

	server->users = users;
	server->dont_fragment = dont_fragment;
	server->fingerprint = fingerprint;
	server->stats = stats;
	if (stun_port < 1)
		stun_port = DEFAULT_STUN_PORT;

	server->verbose = verbose;

	server->e = e;

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

void set_disconnect_cb(turn_turnserver* server, int(*disconnect)(
		ts_ur_super_session*)) {
	server->disconnect = disconnect;
}

//////////////////////////////////////////////////////////////////
