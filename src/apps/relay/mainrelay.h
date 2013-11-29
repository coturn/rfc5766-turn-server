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

#if !defined(__MAIN_RELAY__)
#define __MAIN_RELAY__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>

#include <pthread.h>
#include <sched.h>

#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <pwd.h>
#include <grp.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include <sys/utsname.h>

#include "ns_turn_utils.h"
#include "ns_turn_khash.h"

#include "userdb.h"

#include "tls_listener.h"
#include "dtls_listener.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "ns_ioalib_impl.h"

#if !defined(TURN_NO_HIREDIS)
#include "hiredis_libevent2.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

//////////////// OpenSSL Init //////////////////////

extern SSL_CTX *tls_ctx_ssl23;
extern SSL_CTX *tls_ctx_v1_0;

#if defined(SSL_TXT_TLSV1_1)
extern SSL_CTX *tls_ctx_v1_1;
#if defined(SSL_TXT_TLSV1_2)
extern SSL_CTX *tls_ctx_v1_2;
#endif
#endif

extern SSL_CTX *dtls_ctx;

extern SHATYPE shatype;

//////////////// Common params ////////////////////

extern int verbose;
extern int turn_daemon;
extern int stale_nonce;
extern int stun_only;
extern int no_stun;
extern int secure_stun;

extern int do_not_use_config_file;

#define DEFAULT_CONFIG_FILE "turnserver.conf"

////////////////  Listener server /////////////////

extern int listener_port;
extern int tls_listener_port;
extern int alt_listener_port;
extern int alt_tls_listener_port;
extern int rfc5780;

static inline int get_alt_listener_port(void) {
	if(alt_listener_port<1)
		return listener_port + 1;
	return alt_listener_port;
}

static inline int get_alt_tls_listener_port(void) {
	if(alt_tls_listener_port<1)
		return tls_listener_port + 1;
	return alt_tls_listener_port;
}

extern int no_udp;
extern int no_tcp;
extern int no_tls;

#if defined(TURN_NO_DTLS)
extern int no_dtls;
#else
extern int no_dtls;
#endif


extern int no_tcp_relay;
extern int no_udp_relay;

extern char listener_ifname[1025];

#if !defined(TURN_NO_HIREDIS)
extern char redis_statsdb[1025];
extern int use_redis_statsdb;
#endif

struct message_to_listener_to_client {
	ioa_addr origin;
	ioa_addr destination;
	ioa_network_buffer_handle nbh;
};

enum _MESSAGE_TO_LISTENER_TYPE {
	LMT_UNKNOWN,
	LMT_TO_CLIENT
};
typedef enum _MESSAGE_TO_LISTENER_TYPE MESSAGE_TO_LISTENER_TYPE;

struct message_to_listener {
	MESSAGE_TO_LISTENER_TYPE t;
	union {
		struct message_to_listener_to_client tc;
	} m;
};

struct listener_server {
	rtcp_map* rtcpmap;
	turnipports* tp;
	struct event_base* event_base;
	ioa_engine_handle ioa_eng;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	char **addrs;
	ioa_addr **encaddrs;
	size_t addrs_number;
	size_t services_number;
	dtls_listener_relay_server_type ***udp_services;
	dtls_listener_relay_server_type ***dtls_services;
	dtls_listener_relay_server_type ***aux_udp_services;
	tls_listener_relay_server_type **tcp_services;
	tls_listener_relay_server_type **tls_services;
	tls_listener_relay_server_type **aux_tcp_services;
#if !defined(TURN_NO_HIREDIS)
	redis_context_handle rch;
#endif
};

extern struct listener_server listener;

extern ip_range_list_t ip_whitelist;
extern ip_range_list_t ip_blacklist;

extern int new_net_engine;

//////////////// Relay servers //////////////////////////////////

#define MAX_NUMBER_OF_GENERAL_RELAY_SERVERS ((u08bits)(128))

#define TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP ((u08bits)(0x01FF))
#define TURNSERVER_ID_BOUNDARY_BETWEEN_UDP_AND_TCP TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP

extern band_limit_t max_bps;

extern u16bits min_port;
extern u16bits max_port;

extern int no_multicast_peers;
extern int no_loopback_peers;

extern char relay_ifname[1025];

extern size_t relays_number;
extern char **relay_addrs;

// Single global public IP.
// If multiple public IPs are used
// then ioa_addr mapping must be used.
extern ioa_addr *external_ip;

extern int fingerprint;

extern turnserver_id general_relay_servers_number;
extern turnserver_id udp_relay_servers_number;

extern int mobility;

////////////// Auth server ////////////////////////////////////////////////

struct auth_server {
	struct event_base* event_base;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	pthread_t thr;
};

extern struct auth_server authserver;

/////////////// AUX SERVERS ////////////////

extern turn_server_addrs_list_t aux_servers_list;
extern int udp_self_balance;

void add_aux_server(const char *saddr);

/////////////// ALTERNATE SERVERS ////////////////

extern turn_server_addrs_list_t alternate_servers_list;
extern turn_server_addrs_list_t tls_alternate_servers_list;

void add_alternate_server(const char *saddr);
void add_tls_alternate_server(const char *saddr);

////////// Addrs ////////////////////

void add_listener_addr(const char* addr);
void add_relay_addr(const char* addr);

///////// Auth ////////////////

void send_auth_message_to_auth_server(struct auth_message *am);

/////////// Setup server ////////

void init_listener(void);
void setup_server(void);
void run_listener_server(struct event_base *eb);

///////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__MAIN_RELAY__
