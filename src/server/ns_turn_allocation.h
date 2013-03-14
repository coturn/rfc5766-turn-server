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

#ifndef __TURN_TURN_A_LIB__
#define __TURN_TURN_A_LIB__

#include "ns_turn_utils.h"
#include "ns_turn_msg.h"
#include "ns_turn_ioalib.h"
#include "ns_turn_maps.h"

#ifdef __cplusplus
extern "C" {
#endif

///////// Defines //////////

#define TCP_PEER_CONN_TIMEOUT (30)
#define TCP_CONN_BIND_TIMEOUT (30)

///////// types ////////////

enum _UR_STATE {
  UR_STATE_UNKNOWN=0,
  UR_STATE_READY,
  UR_STATE_DONE
};

typedef enum _UR_STATE UR_STATE;

////////////// Network session ////////////////

typedef struct
{
	UR_STATE state;
	ioa_socket_handle s;
	unsigned int ctime;
	int known_mtu;
} ts_ur_session;

static inline void delete_ur_map_session_elem_data(ts_ur_session* cdi)
{
	if (cdi)
		IOA_CLOSE_SOCKET(cdi->s);
}

////////// RFC 6062 TCP connection ////////

enum _TC_STATE {
	TC_STATE_UNKNOWN=0,
	TC_STATE_CLIENT_TO_PEER_CONNECTING,
	TC_STATE_PEER_CONNECTING,
	TC_STATE_PEER_CONNECTED,
	TC_STATE_READY,
	TC_STATE_FAILED
};

typedef enum _TC_STATE TC_STATE;

typedef struct _tcp_connection_list {
  struct _tcp_connection_list *next;
} tcp_connection_list;

typedef struct
{
	tcp_connection_list list;
	TC_STATE state;
	u32bits id;
	ioa_addr peer_addr;
	ioa_socket_handle client_s;
	ioa_socket_handle peer_s;
	ioa_timer_handle peer_conn_timeout;
	ioa_timer_handle conn_bind_timeout;
	stun_tid tid;
	void *owner; //a
	int done;
} tcp_connection;

////////////////////////////////

typedef struct _ch_info {
  u16bits chnum;
  u16bits port;
  ioa_addr peer_addr;
  turn_time_t expiration_time;
  ioa_timer_handle lifetime_ev;
  void *owner; //perm
  void *socket_channel; //optimization
} ch_info;

typedef struct _perm_list {
  struct _perm_list *next;
} perm_list;

typedef struct _turn_permission_info {
  perm_list list;
  ur_map *channels;
  ioa_addr addr;
  turn_time_t expiration_time;
  ioa_timer_handle lifetime_ev;
  void* owner; //a
} turn_permission_info;

typedef turn_permission_info** turn_permission_map;

//////////////// ALLOCATION //////////////////////

typedef struct _allocation {
  int is_valid;
  turn_time_t expiration_time;
  stun_tid tid;
  ioa_timer_handle lifetime_ev;
  turn_permission_map addr_to_perm;
  ts_ur_session relay_session;
  ur_map *channel_to_ch_info;
  void *owner; //ss
  ur_map *tcp_connections; //global reference
  tcp_connection_list tcl; //local reference
} allocation;

//////////// PERMISSION AND CHANNELS ////////////////////

void init_turn_permission_map(turn_permission_map *map);
void free_turn_permission_map(turn_permission_map *map);
turn_permission_info* get_from_turn_permission_map(const turn_permission_map map, const ioa_addr *addr);
void remove_from_turn_permission_map(turn_permission_map map, const ioa_addr *addr);
int turn_permission_map_size(const turn_permission_map map);

void turn_permission_clean(ur_map_value_type value);

u16bits get_turn_channel_number(turn_permission_info* tinfo, ioa_addr *addr);
ch_info *get_turn_channel(turn_permission_info* tinfo, ioa_addr *addr);

void turn_channel_delete(ch_info* chn);

/////////// ALLOCATION ////////////

void init_allocation(void *owner, allocation* a, ur_map *tcp_connections);
void clean_allocation(allocation *a);

void set_allocation_lifetime_ev(allocation *a, turn_time_t exp_time, ioa_timer_handle ev);
int is_allocation_valid(const allocation* a);
void set_allocation_valid(allocation* a, int value);
turn_permission_info* allocation_get_permission(const allocation* a, const ioa_addr *addr);
turn_permission_map allocation_get_turn_permission_map(const allocation *a);
turn_permission_info* allocation_add_permission(allocation *a, const ioa_addr* addr);
void allocation_remove_turn_permission(allocation* a, turn_permission_info* tinfo);

ch_info* allocation_get_new_ch_info(allocation* a, u16bits chnum, ioa_addr* peer_addr);
ch_info* allocation_get_ch_info(allocation* a, u16bits chnum);
ch_info* allocation_get_ch_info_by_peer_addr(allocation* a, ioa_addr* peer_addr);

ts_ur_session *get_relay_session(allocation *a);
ioa_socket_handle get_relay_socket(allocation *a);

tcp_connection *get_tcp_connection_by_id(ur_map *map, u32bits id);
tcp_connection *get_tcp_connection_by_peer(allocation *a, ioa_addr *peer_addr);
int can_accept_tcp_connection_from_peer(allocation *a, ioa_addr *peer_addr);
tcp_connection *create_tcp_connection(allocation *a, stun_tid *tid, ioa_addr *peer_addr, int *err_code);
void delete_tcp_connection(tcp_connection *tc);

///////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_TURN_A_LIB__
