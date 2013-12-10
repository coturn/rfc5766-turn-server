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

#ifndef __TURN_SESSION__
#define __TURN_SESSION__

#include "ns_turn_utils.h"
#include "ns_turn_maps.h"
#include "ns_turn_ioalib.h"
#include "ns_turn_allocation.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////////// session info //////////////////////

typedef u64bits turnsession_id;

#define NONCE_MAX_SIZE (NONCE_LENGTH_32BITS*4+1)

typedef u64bits mobile_id_t;

typedef struct {
  void* server; 
  turnsession_id id;
  ts_ur_session client_session;
  ioa_addr default_peer_addr;
  allocation alloc;
  ioa_timer_handle to_be_allocated_timeout_ev;
  u08bits nonce[NONCE_MAX_SIZE];
  turn_time_t nonce_expiration_time;
  u08bits username[STUN_MAX_USERNAME_SIZE+1];
  hmackey_t hmackey;
  st_password_t pwd;
  int enforce_fingerprints;
  int is_tcp_relay;
  int to_be_closed;
  SHATYPE shatype;
  /* Stats */
  u32bits received_packets;
  u32bits sent_packets;
  u32bits received_bytes;
  u32bits sent_bytes;
  size_t t_received_packets;
  size_t t_sent_packets;
  size_t t_received_bytes;
  size_t t_sent_bytes;
  /* Mobile */
  int is_mobile;
  mobile_id_t mobile_id;
  char s_mobile_id[33];
} ts_ur_super_session;

////// Session info for statistics //////

#define TURN_ADDR_STR_SIZE (101)

typedef struct _addr_data {
	ioa_addr addr;
	char saddr[TURN_ADDR_STR_SIZE];
} addr_data;

struct turn_session_info {
	turnsession_id id;
	int valid;
	turn_time_t expiration_time;
	SOCKET_TYPE client_protocol;
	SOCKET_TYPE peer_protocol;
	char tls_method[17];
	char tls_cipher[65];
	addr_data local_addr_data;
	addr_data remote_addr_data;
	addr_data relay_addr_data;
	addr_data *peers_data;
	size_t peers_size;
	u08bits username[STUN_MAX_USERNAME_SIZE+1];
	int enforce_fingerprints;
	SHATYPE shatype;
/* Stats */
	size_t received_packets;
	size_t sent_packets;
	size_t received_bytes;
	size_t sent_bytes;
/* Mobile */
	int is_mobile;
};

void turn_session_info_init(struct turn_session_info* tsi);
void turn_session_info_clean(struct turn_session_info* tsi);
void turn_session_info_add_peer(struct turn_session_info* tsi, ioa_addr *peer);

int turn_session_info_copy_from(struct turn_session_info* tsi, ts_ur_super_session *ss);

////////////// ss /////////////////////

allocation* get_allocation_ss(ts_ur_super_session *ss);

///////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_SESSION__
