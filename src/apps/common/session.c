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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/tcp.h>

#include "session.h"

/////////// SS ///////////////////////////

app_ur_super_session* get_from_ur_map_ss(ur_map* map, ioa_socket_raw fd) {
  if(!map) return NULL;
  else {
    void* result;
    if(!ur_map_get(map, (ur_map_key_type)fd, &result)) {
      return NULL;
    }
    return (app_ur_super_session*)result;
  }
}

int add_to_ur_map_ss(ur_map* map, ioa_socket_raw fd, app_ur_super_session* value) {
  if(!map) return -1;
  else {
    return ur_map_put(map, (ur_map_key_type)fd, value);
  }
}

int add_all_to_ur_map_ss(ur_map* map, app_ur_super_session* ss) {
  if(!map || !ss) return -1;
  else {
    int ret = 0;
    if(ss->session.pinfo.fd>=0) add_to_ur_map_ss(map, ss->session.pinfo.fd, ss);
#if defined(TURN_CLIENT) || defined(TURN_PEER)
    if(ss->tcp_session.pinfo.fd>=0) add_to_ur_map_ss(map, ss->tcp_session.pinfo.fd, ss);
#else
    if(ss->relay_session.pinfo.fd>=0) add_to_ur_map_ss(map, ss->relay_session.pinfo.fd, ss);
#endif
    return ret;
  }
}

//////////////////////////////////////////////////////////////
