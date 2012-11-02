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

#ifndef __SESSION__
#define __SESSION__

#include <stdint.h>

#include <event2/event.h>

#include "ns_turn_ioaddr.h"
#include "ns_turn_utils.h"

#include "stun_buffer.h"
#include "apputils.h"

///////// types ////////////

enum _UR_STATE {
  UR_STATE_UNKNOWN=0,
  UR_STATE_READY,
  UR_STATE_SHUTTING_DOWN,
  UR_STATE_WAITING_FOR_VERIFICATION,
  UR_STATE_DONE
};

typedef enum _UR_STATE UR_STATE;

//////////////// session info //////////////////////

typedef struct {
  ioa_addr local_addr;
  ioa_addr remote_addr;
  ioa_addr peer_addr;
  ioa_socket_raw fd;
} app_ur_conn_info;

typedef struct {
  UR_STATE state;
  app_ur_conn_info pinfo;
  unsigned int ctime;
  uint16_t chnum;
  int tot_msgnum;
  int wmsgnum;
  int rmsgnum;
  int wait_cycles;
  int clnum;
  struct event *timer_ev;
  int timer_cycle;
  int known_mtu;
  struct event *input_ev; 
  stun_buffer in_buffer;
  stun_buffer out_buffer;
} app_ur_session;

///////////////////////////////////////////////////////

#endif //__SESSION__
