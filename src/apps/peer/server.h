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

#ifndef __SERVER_LIB__
#define __SERVER_LIB__

//////////////////////////////

#include "ns_turn_utils.h"
#include "session.h"

#include <event2/event.h>

//////////////////////////////

struct server_info;
typedef struct server_info server_type;

///////////////////////////////////////////////////

#define FUNCSTART if(server && server->verbose) turn_log_func_default(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && server->verbose) turn_log_func_default(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

///////////////////////////////////////////////////////

struct server_info {
  char ifname[1025];
  ioa_addr addr;
  struct event_base* event_base;
  struct event *udp_ev;
  struct event *tcp_ev;
  evutil_socket_t udp_fd;
  evutil_socket_t tcp_fd;
  int verbose;
  ur_map *client_map;
};

///////////////////////////////////////////

int udp_open_client_connection(server_type* server, app_ur_super_session *ss, 
			       ioa_addr *remote_addr);

app_ur_super_session* create_new_ss(void);
int remove_all_from_ur_map_ss(ur_map* map, app_ur_super_session* ss);

///////////////////////////////////////////

#endif //__SERVER_LIB__
