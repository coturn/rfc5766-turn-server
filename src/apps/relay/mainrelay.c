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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ns_turn_utils.h"

#include "udp_listener.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"
#include "stunservice.h"

#include "apputils.h"

#include "ns_ioalib_impl.h"

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: turnserver [options]\n"
  "Options:\n"
  "	-p      local port (Default: 3478)\n"
  "	-d	local \"external\" interface device (optional)\n"
  "	-L      local address\n"
  "	-i	local \"internal\" interface device for relay sockets (optional)\n"
  "	-E      local relay address\n"
  "	-v      verbose\n"
  "	-f      set fingerprints\n";

//////////////////////////////////////////////////

static struct event_base* event_base = NULL;
static ioa_engine_handle ioa_eng = NULL;

static size_t listeners_number = 0;
static char **listener_addrs = NULL;
static udp_listener_relay_server_type **listener_servers = NULL;

static turn_turnserver* turn_server = NULL;

static stunserver *stunservice = NULL;

static uint32_t stats=0;

//////////////////////////////////////////////////

static int port = RELAY_DEFAULT_PORT;

static char relay_addr[256];
static int verbose=0;

static rtcp_map* rtcpmap;
static turnipports* tp;
static char ifname[1025]="\0";
static char relay_ifname[1025]="\0";
static int fingerprint = 0;

//////////////////////////////////////////////////

static void add_listener_addr(const char* addr) {
	++listeners_number;
	listener_addrs = realloc(listener_addrs, sizeof(char*)*listeners_number);
	listener_addrs[listeners_number-1]=strdup(addr);
	listener_servers = realloc(listener_servers, sizeof(udp_listener_relay_server_type*)*listeners_number);
	listener_servers[listeners_number-1] = NULL;
}

//////////////////////////////////////////////////

static int send_socket(ioa_engine_handle e, ioa_socket_handle s, ioa_net_data *nd)
{
	UNUSED_ARG(e);
	return open_client_connection_session(turn_server, s, 0, NULL, nd);
}

static int we_need_extra_stun_service(void)
{
	size_t i = 0;
	ioa_addr ra, la;
	make_ioa_addr((const u08bits*)relay_addr,0,&ra);

	for(i=0;i<listeners_number;i++) {
		make_ioa_addr((const u08bits*)(listener_addrs[i]),0,&la);
		if(addr_eq_no_port(&la,&ra))
			return 0;
	}

	return 1;
}

static void setup_relay_server(void)
{
	size_t i = 0;

	event_base = event_base_new();

	tp = turnipports_create(LOW_DEFAULT_PORTS_BOUNDARY, HIGH_DEFAULT_PORTS_BOUNDARY);

	ioa_eng = create_ioa_engine(event_base, tp, relay_ifname, relay_addr, verbose);

	register_callback_on_ioa_engine_new_connection(ioa_eng, send_socket);

	rtcpmap = rtcp_map_create(ioa_eng);

	ioa_engine_set_rtcp_map(ioa_eng, rtcpmap);

	turn_server = create_turn_server(verbose, ioa_eng, &stats, 0, fingerprint, DONT_FRAGMENT_SUPPORTED);

	if (we_need_extra_stun_service())
		stunservice = start_internal_stun_server(verbose, relay_ifname, relay_addr, 0, event_base);

	for(i=0;i<listeners_number;i++)
		listener_servers[i] = create_udp_listener_server(ifname, listener_addrs[i], port, verbose, ioa_eng, &stats);
}

///////////////////////////////////////////////////////////////

static void clean_relay_server(void)
{
	size_t i = 0;

	if (stunservice) {
		clean_internal_stun_server(&stunservice);
	}

	if(listener_servers) {
		for(i=0;i<listeners_number; i++) {
			if (listener_servers[i]) {
				delete_udp_listener_server(listener_servers[i],0);
				listener_servers[i] = NULL;
			}
		}
		free(listener_servers);
	}

	if(listener_addrs) {
		for(i=0;i<listeners_number; i++) {
			if (listener_addrs[i]) {
				free(listener_addrs[i]);
				listener_addrs[i] = NULL;
			}
		}
		free(listener_addrs);
	}

	if (turn_server) {
		delete_turn_server(turn_server);
		turn_server = NULL;
	}

	if (rtcpmap) {
		rtcp_map_free(&rtcpmap);
	}

	if (ioa_eng) {
		close_ioa_engine(ioa_eng);
	} else if (event_base) {
		event_base_free(event_base);
		event_base = NULL;
	}

	if (tp) {
	  turnipports_destroy(&tp);
	}
}

//////////////////////////////////////////////////

static void run_events(void) {

  if(!event_base) return;

  struct timeval timeout;

  timeout.tv_sec=0;
  timeout.tv_usec=1000000;

  event_base_loopexit(event_base, &timeout);
  event_base_dispatch(event_base);
}

/////////////////////////////////////////////////////////////

static void run_relay_server(void) {

  unsigned int cycle=0;
  
  while (1) {
    
    cycle++;
    if((cycle & 15) == 0) {
      if (1 || verbose) {
	if(verbose) 
	  {
	    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: cycle=%u, stats=%lu\n",
				  __FUNCTION__,cycle,(unsigned long)stats);
	  }
      }
    }
      
    run_events();
  }
}

//////////////////////////////////////////////////

int main(int argc, char **argv)
{
  char c=0;

  srandom((unsigned int)time(NULL));
  
  relay_addr[0]=0;
    
  while ((c = getopt(argc, argv, "i:d:p:L:E:R:r:w:vf")) != -1) {
    switch(c) {
    case 'i':
      strcpy(relay_ifname,optarg);
      break;
    case 'd':
      strcpy(ifname,optarg);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'L':
      add_listener_addr(optarg);
      break;
    case 'E':
      strncpy(relay_addr, optarg, sizeof(relay_addr)-1);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'f':
      fingerprint = 1;
      break;
    default:
      fprintf(stderr, "%s\n", Usage);
      exit(1);
    }
  }

  setup_relay_server();

  run_relay_server();

  clean_relay_server();

  return 0;
}

