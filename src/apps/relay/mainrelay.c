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
#include <pthread.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "ns_turn_utils.h"

#include "udp_listener.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "ns_ioalib_impl.h"

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: turnserver [options]\n"
  "Options:\n"
  "	-p      TURN listener port (Default: 3478)\n"
  "	-d	Listener interface device (optional)\n"
  "	-L      Listener IP address of relay server. Multiple listeners can be specified\n"
  "	-i	Relay interface device for relay sockets (optional)\n"
  "	-E      Relay address (the local IP address that will be used to relay the packets to the peer)\n"
  "	-f      set TURN fingerprints\n"
  "	-m	number of extra threads to handle established connections (default is 0)\n"
  "	-v      verbose\n";

//////////////////////////////////////////////////

struct listener_server {
	size_t number;
	rtcp_map* rtcpmap;
	turnipports* tp;
	struct event_base* event_base;
	ioa_engine_handle ioa_eng;
	char **addrs;
	udp_listener_relay_server_type **services;
};

struct listener_server listener = {0, NULL, NULL, NULL, NULL, NULL, NULL};

static uint32_t stats=0;

//////////////////////////////////////////////////

static int port = RELAY_DEFAULT_PORT;

static size_t relays_number = 0;
static char **relay_addrs = NULL;

static size_t relay_servers_number = 1;
struct relay_server {
	struct event_base* event_base;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	ioa_engine_handle ioa_eng;
	turn_turnserver *server;
	pthread_t thr;
};
static struct relay_server **relay_servers = NULL;

/////////////////////////////////////////////////

static int verbose=0;

static char ifname[1025]="\0";
static char relay_ifname[1025]="\0";
static int fingerprint = 0;

//////////////////////////////////////////////////

static void add_listener_addr(const char* addr) {
	++listener.number;
	listener.addrs = realloc(listener.addrs, sizeof(char*)*listener.number);
	listener.addrs[listener.number-1]=strdup(addr);
	listener.services = realloc(listener.services, sizeof(udp_listener_relay_server_type*)*listener.number);
	listener.services[listener.number-1] = NULL;
}

static void add_relay_addr(const char* addr) {
	++relays_number;
	relay_addrs = realloc(relay_addrs, sizeof(char*)*relays_number);
	relay_addrs[relays_number-1]=strdup(addr);
}

//////////////////////////////////////////////////

static int send_socket(ioa_engine_handle e, ioa_socket_handle s, ioa_net_data *nd)
{
	static size_t current_relay_server = 0;

	UNUSED_ARG(e);

	current_relay_server = current_relay_server % relay_servers_number;

	struct socket_message sm;
	addr_cpy(&(sm.remote_addr),nd->remote_addr);
	sm.nbh = nd->nbh;
	nd->nbh = NULL;
	sm.s = s;
	size_t dest = current_relay_server++;
	sm.chnum = nd->chnum;

	struct evbuffer *output = bufferevent_get_output(relay_servers[dest]->out_buf);
	evbuffer_add(output,&sm,sizeof(sm));
	bufferevent_flush(relay_servers[dest]->out_buf, EV_READ|EV_WRITE, BEV_FLUSH);

	return 0;
}

static void acceptsocket(struct bufferevent *bev, void *ptr)
{
	struct socket_message sm;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	while ((n = evbuffer_remove(input, &sm, sizeof(sm))) > 0) {
		if(n != sizeof(sm)) {
			perror("Weird buffer error\n");
			exit(-1);
		}
		struct relay_server *rs = ptr;
		open_client_connection_session(rs->server, &sm);
	}
}


static void setup_listener_servers(void)
{
	size_t i = 0;

	listener.tp = turnipports_create(LOW_DEFAULT_PORTS_BOUNDARY, HIGH_DEFAULT_PORTS_BOUNDARY);

	listener.event_base = event_base_new();

	listener.ioa_eng = create_ioa_engine(listener.event_base, listener.tp, relay_ifname, relays_number, relay_addrs, verbose);

	register_callback_on_ioa_engine_new_connection(listener.ioa_eng, send_socket);

	listener.rtcpmap = rtcp_map_create(listener.ioa_eng);

	ioa_engine_set_rtcp_map(listener.ioa_eng, listener.rtcpmap);

	for(i=0;i<listener.number;i++)
		listener.services[i] = create_udp_listener_server(ifname, listener.addrs[i], port, verbose, listener.ioa_eng, &stats);
}

static void run_events(struct event_base *eb)
{

	if (!eb)
		return;

	struct timeval timeout;

	timeout.tv_sec = 0;
	timeout.tv_usec = 1000000;

	event_base_loopexit(eb, &timeout);

	event_base_dispatch(eb);
}

static void run_server(struct event_base *eb)
{
	unsigned int cycle = 0;
	while (1) {

		if (verbose) {
			if ((cycle++ & 15) == 0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cycle=%u, stats=%lu\n", __FUNCTION__, cycle,
								(unsigned long) stats);
			}
		}

		run_events(eb);
	}
}

static void *run_relay_thread(void *arg)
{
	struct relay_server *rs = arg;

	run_server(rs->event_base);

	return arg;
}

static void setup_relay_servers(void)
{
	size_t i = 0;

	relay_servers = malloc(sizeof(struct relay_server *)*relay_servers_number);

	for(i=0;i<relay_servers_number;i++) {

		struct bufferevent *pair[2];
		relay_servers[i] = malloc(sizeof(struct relay_server));

		if(relay_servers_number<2) {
			relay_servers[i]->event_base = listener.event_base;
			relay_servers[i]->ioa_eng = listener.ioa_eng;
		} else {
			relay_servers[i]->event_base = event_base_new();
			relay_servers[i]->ioa_eng = create_ioa_engine(relay_servers[i]->event_base, listener.tp, relay_ifname, relays_number, relay_addrs, verbose);
			register_callback_on_ioa_engine_new_connection(relay_servers[i]->ioa_eng, send_socket);
			ioa_engine_set_rtcp_map(relay_servers[i]->ioa_eng, listener.rtcpmap);
		}

		bufferevent_pair_new(relay_servers[i]->event_base, BEV_OPT_THREADSAFE, pair);
		relay_servers[i]->in_buf = pair[0];
		relay_servers[i]->out_buf = pair[1];
		bufferevent_setcb(relay_servers[i]->in_buf, acceptsocket, NULL, NULL, relay_servers[i]);
		bufferevent_enable(relay_servers[i]->in_buf, EV_READ);
		relay_servers[i]->server = create_turn_server(verbose, relay_servers[i]->ioa_eng, &stats, 0, fingerprint, DONT_FRAGMENT_SUPPORTED);

		if(relay_servers_number<2) {
			relay_servers[i]->thr = pthread_self();
		} else {
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_DETACHED);
			if(pthread_create(&(relay_servers[i]->thr), &attr, run_relay_thread, relay_servers[i])<0) {
				perror("Cannot create relay thread\n");
				exit(-1);
			}
			pthread_attr_destroy(&attr);
		}
	}
}

static void setup_server(void)
{
	evthread_use_pthreads();

	setup_listener_servers();

	setup_relay_servers();
}

///////////////////////////////////////////////////////////////

static void clean_server(void)
{
	size_t i = 0;

	if (relay_servers) {
		for(i=0;i<relay_servers_number;i++) {
			if(relay_servers[i]) {
				delete_turn_server(relay_servers[i]->server);
				if(relay_servers[i]->ioa_eng != listener.ioa_eng)
					close_ioa_engine(relay_servers[i]->ioa_eng);
				if(relay_servers[i]->in_buf)
					bufferevent_free(relay_servers[i]->in_buf);
				if(relay_servers[i]->out_buf)
					bufferevent_free(relay_servers[i]->out_buf);
				if(relay_servers[i]->event_base != listener.event_base)
					event_base_free(relay_servers[i]->event_base);
				free(relay_servers[i]);
				relay_servers[i] = NULL;
			}
		}
		free(relay_servers);
	}

	if(listener.services) {
		for(i=0;i<listener.number; i++) {
			if (listener.services[i]) {
				delete_udp_listener_server(listener.services[i],0);
				listener.services[i] = NULL;
			}
		}
		free(listener.services);
		listener.services = NULL;
	}

	if (listener.ioa_eng) {
		close_ioa_engine(listener.ioa_eng);
		listener.ioa_eng = NULL;
	}

	if (listener.event_base) {
		event_base_free(listener.event_base);
		listener.event_base = NULL;
	}

	if (listener.rtcpmap) {
		rtcp_map_free(&(listener.rtcpmap));
	}

	if (listener.tp) {
	  turnipports_destroy(&(listener.tp));
	}

	if (relay_addrs) {
		for (i = 0; i < relays_number; i++) {
			if (relay_addrs[i]) {
				free(relay_addrs[i]);
				relay_addrs[i] = NULL;
			}
		}
		free(relay_addrs);
	}

	if(listener.addrs) {
		for(i=0;i<listener.number; i++) {
			if (listener.addrs[i]) {
				free(listener.addrs[i]);
				listener.addrs[i] = NULL;
			}
		}
		free(listener.addrs);
		listener.addrs = NULL;
	}

	listener.number = 0;
}

//////////////////////////////////////////////////

int main(int argc, char **argv)
{
  char c=0;

  srandom((unsigned int)time(NULL));
    
  while ((c = getopt(argc, argv, "i:d:p:L:E:R:r:w:m:vf")) != -1) {
    switch(c) {
    case 'i':
      strcpy(relay_ifname,optarg);
      break;
    case 'm':
      relay_servers_number = atoi(optarg)+1;
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
      add_relay_addr(optarg);
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

  setup_server();

  run_server(listener.event_base);

  clean_server();

  return 0;
}

