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

#define STUN_NONCE_EXPIRATION_TIME (600)

typedef struct {
  void* server; 
  ts_ur_session client_session;
  ioa_addr default_peer_addr;
  allocation alloc;
  ioa_timer_handle to_be_allocated_timeout_ev;
  u08bits nonce[NONCE_LENGTH_32BITS*8+1];
  turn_time_t nonce_expiration_time;
  u08bits username[STUN_MAX_USERNAME_SIZE+1];
  u08bits hmackey[16];
  int enforce_fingerprints;
  int is_tcp_relay;
} ts_ur_super_session;

////////////// ss /////////////////////

allocation* get_allocation_ss(ts_ur_super_session *ss);
int shutdown_client_connection_ss(ts_ur_super_session *ss);

///////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_SESSION__
