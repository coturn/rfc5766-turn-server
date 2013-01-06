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
#include <limits.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>

#if !defined(TURN_NO_THREADS)
#include <pthread.h>
#endif

#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include "ns_turn_utils.h"

#include "udp_listener.h"
#include "tcp_listener.h"
#include "tls_listener.h"
#include "dtls_listener.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "ns_ioalib_impl.h"

//////////////// OpenSSL Init //////////////////////

static void openssl_setup(void);
static void openssl_cleanup(void);

//////////////// Common params ////////////////////

static int verbose=0;
static int turn_daemon = 0;

#define DEFAULT_CONFIG_FILE "turnserver.conf"
#define DEFAULT_USERDB_FILE "turnuserdb.conf"

////////////////  Listener server /////////////////

static int listener_port = DEFAULT_STUN_PORT;
static int tls_listener_port = DEFAULT_STUN_TLS_PORT;

static int no_udp = 0;
static int no_tcp = 0;
static int no_tls = 0;
static int no_dtls = 0;

static SSL_CTX *tls_ctx = NULL;
static SSL_CTX *dtls_ctx = NULL;

static char listener_ifname[1025]="\0";

/*
 * openssl genrsa -out pkey 2048
 * openssl req -new -key pkey -out cert.req
 * openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert
 *
*/
static char cert_file[1025]="\0";
static char pkey_file[1025]="\0";

struct listener_server {
	size_t number;
	rtcp_map* rtcpmap;
	turnipports* tp;
	struct event_base* event_base;
	ioa_engine_handle ioa_eng;
	char **addrs;
	udp_listener_relay_server_type **udp_services;
	tcp_listener_relay_server_type **tcp_services;
	tls_listener_relay_server_type **tls_services;
	dtls_listener_relay_server_type **dtls_services;
};

struct listener_server listener = {0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

static uint32_t stats=0;

//////////////// Relay servers //////////////////////////////////

static u16bits min_port = LOW_DEFAULT_PORTS_BOUNDARY;
static u16bits max_port = HIGH_DEFAULT_PORTS_BOUNDARY;

static char relay_ifname[1025]="\0";

static size_t relays_number = 0;
static char **relay_addrs = NULL;

static int fingerprint = 0;

static char userdb_file[1025]="\0";
static turn_user_db *users = NULL;
static s08bits global_realm[1025];

static size_t relay_servers_number = 0;
#define get_real_relay_servers_number() (relay_servers_number > 1 ? relay_servers_number : 1)

struct relay_server {
	struct event_base* event_base;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	ioa_engine_handle ioa_eng;
	turn_turnserver *server;
#if !defined(TURN_NO_THREADS)
	pthread_t thr;
#endif
};
static struct relay_server **relay_servers = NULL;

////////////// Configuration functionality ////////////////////////////////

static void read_config_file(int argc, char **argv);
static void read_userdb_file(void);

//////////////////////////////////////////////////

static void add_listener_addr(const char* addr) {
	++listener.number;
	listener.addrs = realloc(listener.addrs, sizeof(char*)*listener.number);
	listener.addrs[listener.number-1]=strdup(addr);
	listener.udp_services = realloc(listener.udp_services, sizeof(udp_listener_relay_server_type*)*listener.number);
	listener.udp_services[listener.number-1] = NULL;
	listener.tcp_services = realloc(listener.tcp_services, sizeof(tcp_listener_relay_server_type*)*listener.number);
	listener.tcp_services[listener.number-1] = NULL;
	listener.tls_services = realloc(listener.tls_services, sizeof(tls_listener_relay_server_type*)*listener.number);
	listener.tls_services[listener.number-1] = NULL;
	listener.dtls_services = realloc(listener.dtls_services, sizeof(dtls_listener_relay_server_type*)*listener.number);
	listener.dtls_services[listener.number-1] = NULL;
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

	current_relay_server = current_relay_server % get_real_relay_servers_number();

	struct socket_message sm;
	addr_cpy(&(sm.remote_addr),nd->remote_addr);
	sm.nbh = nd->nbh;
	nd->nbh = NULL;
	sm.s = s;
	size_t dest = current_relay_server++;
	sm.chnum = nd->chnum;

	struct evbuffer *output = bufferevent_get_output(relay_servers[dest]->out_buf);
	evbuffer_add(output,&sm,sizeof(sm));
	bufferevent_flush(relay_servers[dest]->out_buf, EV_WRITE, BEV_FLUSH);

	return 0;
}

static void acceptsocket(struct bufferevent *bev, void *ptr)
{
	struct socket_message sm;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	while ((n = evbuffer_remove(input, &sm, sizeof(sm))) > 0) {
		if (n != sizeof(sm)) {
			perror("Weird buffer error\n");
			exit(-1);
		}
		struct relay_server *rs = ptr;
		if (sm.s->defer_nbh) {
			if (!sm.nbh) {
				sm.nbh = sm.s->defer_nbh;
				sm.s->defer_nbh = NULL;
			} else {
				ioa_network_buffer_delete(rs->ioa_eng, sm.s->defer_nbh);
				sm.s->defer_nbh = NULL;
			}
		}

		ioa_socket_handle s = sm.s;

		if (s->read_event || s->bev) {
			TURN_LOG_FUNC(
				TURN_LOG_LEVEL_ERROR,
				"%s: socket wrongly preset: 0x%lx : 0x%lx\n",
				__FUNCTION__, (long) s->read_event,
				(long) s->bev);
			IOA_CLOSE_SOCKET(sm.s);
			return;
		}

		s->e = rs->ioa_eng;

		open_client_connection_session(rs->server, &sm);
		ioa_network_buffer_delete(rs->ioa_eng, sm.nbh);

		if (ioa_socket_tobeclosed(s)) {
			ts_ur_super_session *ss = s->session;
			if (ss) {
				turn_turnserver *server = ss->server;
				if (server)
					shutdown_client_connection(server, ss);
			}
		}
	}
}

static void setup_listener_servers(void)
{
	size_t i = 0;

	listener.tp = turnipports_create(min_port, max_port);

	listener.event_base = event_base_new();

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (listener thread): %s\n",event_base_get_method(listener.event_base));

	listener.ioa_eng = create_ioa_engine(listener.event_base, listener.tp, relay_ifname, relays_number, relay_addrs, verbose);

	if(!listener.ioa_eng)
		exit(-1);

	set_ssl_ctx(listener.ioa_eng, tls_ctx, dtls_ctx);

	register_callback_on_ioa_engine_new_connection(listener.ioa_eng, send_socket);

	listener.rtcpmap = rtcp_map_create(listener.ioa_eng);

	ioa_engine_set_rtcp_map(listener.ioa_eng, listener.rtcpmap);

	for(i=0;i<listener.number;i++) {
		if(!no_udp)
			listener.udp_services[i] = create_udp_listener_server(listener_ifname, listener.addrs[i], listener_port, verbose, listener.ioa_eng, &stats);
		if(!no_tcp)
			listener.tcp_services[i] = create_tcp_listener_server(listener_ifname, listener.addrs[i], listener_port, verbose, listener.ioa_eng, &stats);
		if(!no_tls)
			listener.tls_services[i] = create_tls_listener_server(listener_ifname, listener.addrs[i], tls_listener_port, verbose, listener.ioa_eng, &stats);
		if(!no_dtls)
			listener.dtls_services[i] = create_dtls_listener_server(listener_ifname, listener.addrs[i], tls_listener_port, verbose, listener.ioa_eng, &stats);
	}
}

static void run_events(struct event_base *eb)
{

	if (!eb)
		return;

	struct timeval timeout;

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	event_base_loopexit(eb, &timeout);

	event_base_dispatch(eb);
}

static void run_listener_server(struct event_base *eb)
{
	unsigned int cycle = 0;
	for (;;) {

		if (verbose) {
			if ((cycle++ & 15) == 0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cycle=%u, stats=%lu\n", __FUNCTION__, cycle,
								(unsigned long) stats);
			}
		}

		run_events(eb);

		read_userdb_file();
	}
}

static void setup_relay_server(struct relay_server *rs, ioa_engine_handle e)
{
	struct bufferevent *pair[2];
	int opts = 0;

	if(e) {
		rs->event_base = e->event_base;
		rs->ioa_eng = e;
	} else {
		rs->event_base = event_base_new();
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (relay thread): %s\n",event_base_get_method(rs->event_base));
		rs->ioa_eng = create_ioa_engine(rs->event_base, listener.tp, relay_ifname, relays_number, relay_addrs, verbose);
		set_ssl_ctx(rs->ioa_eng, tls_ctx, dtls_ctx);
		ioa_engine_set_rtcp_map(rs->ioa_eng, listener.rtcpmap);
	}

#if !defined(TURN_NO_THREADS)
	opts = BEV_OPT_THREADSAFE;
#endif

	bufferevent_pair_new(rs->event_base, opts, pair);
	rs->in_buf = pair[0];
	rs->out_buf = pair[1];
	bufferevent_setcb(rs->in_buf, acceptsocket, NULL, NULL, rs);
	bufferevent_enable(rs->in_buf, EV_READ);
	rs->server = create_turn_server(verbose, rs->ioa_eng, &stats, 0, fingerprint, DONT_FRAGMENT_SUPPORTED, users);
}

#if !defined(TURN_NO_THREADS)
static void *run_relay_thread(void *arg)
{
  static int always_true = 1;
  struct relay_server *rs = arg;
  
  setup_relay_server(rs, NULL);

  while(always_true)
    run_events(rs->event_base);
  
  return arg;
}
#endif

static void setup_relay_servers(void)
{
	size_t i = 0;

#if defined(TURN_NO_THREADS)
	relay_servers_number = 0;
#endif

	relay_servers = malloc(sizeof(struct relay_server *)*get_real_relay_servers_number());

	for(i=0;i<get_real_relay_servers_number();i++) {

		relay_servers[i] = malloc(sizeof(struct relay_server));

#if defined(TURN_NO_THREADS)
		setup_relay_server(relay_servers[i], listener.ioa_eng);
#else
		if(relay_servers_number == 0) {
			setup_relay_server(relay_servers[i], listener.ioa_eng);
			relay_servers[i]->thr = pthread_self();
		} else {
			if(pthread_create(&(relay_servers[i]->thr), NULL, run_relay_thread, relay_servers[i])<0) {
				perror("Cannot create relay thread\n");
				exit(-1);
			}
			pthread_detach(relay_servers[i]->thr);
		}
#endif
	}
}

static void setup_server(void)
{
#if !defined(TURN_NO_THREADS)
	evthread_use_pthreads();
#endif

	setup_listener_servers();

	setup_relay_servers();
}

///////////////////////////////////////////////////////////////

static void clean_server(void)
{
	size_t i = 0;

	if (relay_servers) {
		for(i=0;i<get_real_relay_servers_number();i++) {
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

	if(listener.udp_services) {
		for(i=0;i<listener.number; i++) {
			if (listener.udp_services[i]) {
				delete_udp_listener_server(listener.udp_services[i],0);
				listener.udp_services[i] = NULL;
			}
		}
		free(listener.udp_services);
		listener.udp_services = NULL;
	}

	if(listener.tcp_services) {
		for(i=0;i<listener.number; i++) {
			if (listener.tcp_services[i]) {
				delete_tcp_listener_server(listener.tcp_services[i],0);
				listener.tcp_services[i] = NULL;
			}
		}
		free(listener.tcp_services);
		listener.tcp_services = NULL;
	}

	if(listener.tls_services) {
		for(i=0;i<listener.number; i++) {
			if (listener.tls_services[i]) {
				delete_tls_listener_server(listener.tls_services[i],0);
				listener.tls_services[i] = NULL;
			}
		}
		free(listener.tls_services);
		listener.tls_services = NULL;
	}

	if(listener.dtls_services) {
		for(i=0;i<listener.number; i++) {
			if (listener.dtls_services[i]) {
				delete_dtls_listener_server(listener.dtls_services[i],0);
				listener.dtls_services[i] = NULL;
			}
		}
		free(listener.dtls_services);
		listener.dtls_services = NULL;
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

	if(users) {
		ur_string_map_free(&(users->static_accounts));
		ur_string_map_free(&(users->dynamic_accounts));
		ur_string_map_free(&(users->alloc_counters));
		free(users);
	}
}

//////////////////////////////////////////////////

static int make_local_listeners_list(void)
{
	struct ifaddrs * ifs = NULL;
	struct ifaddrs * ifa = NULL;

	char saddr[INET6_ADDRSTRLEN] = "\0";

	getifaddrs(&ifs);

	if (ifs) {
		for (ifa = ifs; ifa != NULL; ifa = ifa->ifa_next) {

			if (ifa ->ifa_addr->sa_family == AF_INET) {
				if(!inet_ntop(AF_INET, &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr, saddr,
								INET_ADDRSTRLEN))
					continue;
			} else if (ifa->ifa_addr->sa_family == AF_INET6) {
				if(!inet_ntop(AF_INET6, &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr, saddr,
								INET6_ADDRSTRLEN))
					continue;
				if(strstr(saddr,"fe80") == saddr)
					continue;
			} else
				continue;

			add_listener_addr(saddr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Added listener address %s (%s)\n",saddr,ifa->ifa_name);
		}
		freeifaddrs(ifs);
	}

	return 0;
}

static int make_local_relays_list(int allow_local)
{
	struct ifaddrs * ifs = NULL;
	struct ifaddrs * ifa = NULL;

	char saddr[INET6_ADDRSTRLEN] = "\0";

	getifaddrs(&ifs);

	if (ifs) {
		for (ifa = ifs; ifa != NULL; ifa = ifa->ifa_next) {

			if(!allow_local && (strstr(ifa->ifa_name,"lo") == ifa->ifa_name))
				continue;

			if (ifa ->ifa_addr->sa_family == AF_INET) {
				if(!inet_ntop(AF_INET, &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr, saddr,
								INET_ADDRSTRLEN))
					continue;
			} else if (ifa->ifa_addr->sa_family == AF_INET6) {
				if(!inet_ntop(AF_INET6, &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr, saddr,
								INET6_ADDRSTRLEN))
					continue;
				if(strstr(saddr,"fe80") == saddr)
					continue;
			} else
				continue;

			add_relay_addr(saddr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Added relay address %s (%s)\n",saddr,ifa->ifa_name);
		}
		freeifaddrs(ifs);
	}

	return 0;
}

//////////////////////////////////////////////////

static char Usage[] = "Usage: turnserver [options]\n"
	"Options:\n"
	"	-d, --listening-device		Listener interface device (optional, Linux only).\n"
	"	-p, --listening-port		TURN listener port (Default: 3478).\n"
	"	    --tls-listening-port	TURN listener port for TLS and DTLS listeners\n"
	"					(Default: 5349).\n"
	"	-L, --listening-ip		Listener IP address of relay server. Multiple listeners can be specified.\n"
	"	-i, --relay-device		Relay interface device for relay sockets (optional, Linux only).\n"
	"	-E, --relay-ip			Relay address (the local IP address that will be used to relay the packets to the peer).\n"
	"	-m, --relay-threads		Number of extra threads to handle established connections (default is 0).\n"
	"	    --min-port			Lower bound of the UDP port range for relay endpoints allocation.\n"
	"					Default value is 49152, according to RFC 5766.\n"
	"	    --max-port			Upper bound of the UDP port range for relay endpoints allocation.\n"
	"					Default value is 65535, according to RFC 5766.\n"
	"	-v, --verbose			Verbose.\n"
	"	-o, --daemon			Start process as daemon (detach from current shell).\n"
	"	-f, --fingerprint		Use fingerprints in the TURN messages.\n"
	"	-a, --lt-cred-mech		Use long-term credential mechanism. Default - no authentication.\n"
	"	-u, --user			User account, in form 'username:password'.\n"
	"	-r, --realm			Realm.\n"
	"	-q, --user-quota		per-user allocation quota.\n"
	"	-Q, --total-quota		total allocation quota.\n"
	"	-c				Configuration file name (default - turnserver.conf).\n"
	"	-b, --userdb			'Dynamic' user database file name (default - turnuserdb.conf).\n"
	"	-n				Do not use configuration file.\n"
	"	    --cert			Certificate file, PEM format. Same file search rules\n"
	"					applied as for the configuration file.\n"
	"					If both --no-tls and --no_dtls options\n"
	"					are specified, then this parameter is not needed.\n"
	"	    --pkey			Private key file, PEM format. Same file search rules\n"
	"					applied as for the configuration file.\n"
	"					If both --no-tls and --no-dtls options\n"
	"					are specified, then this parameter is not needed.\n"
	"	    --no-udp			Do not start UDP listeners.\n"
	"	    --no-tcp			Do not start TCP listeners.\n"
	"	    --no-tls			Do not start TLS listeners.\n"
	"	    --no-dtls			Do not start DTLS listeners.\n"
	"	-h				Help\n";

static char AdminUsage[] = "Usage: turnadmin [command] [options]\n"
	"Commands:\n"
	"	-k, --key		generate key for a user\n"
	"	-a, --add		add/update a user\n"
	"	-d, --delete		delete a user\n"
	"Options:\n"
	"	-b, --user-db-file	Dynamic user database file\n"
	"	-u, --user		Username\n"
	"	-r, --realm		Realm\n"
	"	-p, --password		Password\n"
	"	-h, --help		Help\n";

#define OPTIONS "c:d:p:L:E:i:m:l:r:u:b:q:Q:vofha"

#define ADMIN_OPTIONS "kadb:u:r:p:h"

enum EXTRA_OPTS {
	NO_UDP_OPT=256,
	NO_TCP_OPT,
	NO_TLS_OPT,
	NO_DTLS_OPT,
	TLS_PORT_OPT,
	CERT_FILE_OPT,
	PKEY_FILE_OPT,
	MIN_PORT_OPT,
	MAX_PORT_OPT
};

static struct option long_options[] = {
				{ "listening-device", required_argument, NULL, 'd' },
				{ "listening-port", required_argument, NULL, 'p' },
				{ "tls-listening-port", required_argument, NULL, TLS_PORT_OPT },
				{ "listening-ip", required_argument, NULL, 'L' },
				{ "relay-device", required_argument, NULL, 'i' },
				{ "relay-ip", required_argument, NULL, 'E' },
				{ "relay-threads", required_argument, NULL, 'm' },
				{ "min-port", required_argument, NULL, MIN_PORT_OPT },
				{ "max-port", required_argument, NULL, MAX_PORT_OPT },
				{ "lt-cred-mech", optional_argument, NULL, 'a' },
				{ "user", required_argument, NULL, 'u' },
				{ "realm", required_argument, NULL, 'r' },
				{ "user-quota", required_argument, NULL, 'q' },
				{ "total-quota", required_argument, NULL, 'Q' },
				{ "verbose", optional_argument, NULL, 'v' },
				{ "daemon", optional_argument, NULL, 'o' },
				{ "fingerprint", optional_argument, NULL, 'f' },
				{ "no-udp", optional_argument, NULL, NO_UDP_OPT },
				{ "no-tcp", optional_argument, NULL, NO_TCP_OPT },
				{ "no-tls", optional_argument, NULL, NO_TLS_OPT },
				{ "no-dtls", optional_argument, NULL, NO_DTLS_OPT },
				{ "cert", required_argument, NULL, CERT_FILE_OPT },
				{ "pkey", required_argument, NULL, PKEY_FILE_OPT },
				{ NULL, no_argument, NULL, 0 }
};

static struct option admin_long_options[] = {
				{ "key", no_argument, NULL, 'k' },
				{ "add", no_argument, NULL, 'a' },
				{ "delete", no_argument, NULL, 'd' },
				{ "userdb", required_argument, NULL, 'b' },
				{ "user", required_argument, NULL, 'u' },
				{ "realm", required_argument, NULL, 'r' },
				{ "password", required_argument, NULL, 'p' },
				{ "help", no_argument, NULL, 'h' },
				{ NULL, no_argument, NULL, 0 }
};

static char *skip_blanks(char* s)
{
	while(*s==' ' || *s=='\t' || *s=='\n')
		++s;

	return s;
}

static int get_bool_value(const char* s)
{
	if(!s || !(s[0])) return 1;
	if(s[0]=='0' || s[0]=='n' || s[0]=='N' || s[0]=='f' || s[0]=='F') return 0;
	if(s[0]=='y' || s[0]=='Y' || s[0]=='t' || s[0]=='T') return 1;
	if(s[0]>'0' && s[0]<='9') return 1;
	if(!strcmp(s,"off") || !strcmp(s,"OFF") || !strcmp(s,"Off")) return 0;
	if(!strcmp(s,"on") || !strcmp(s,"ON") || !strcmp(s,"On")) return 1;
	TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown boolean value: %s. You can use on/off, yes/no, 1/0, true/false.\n",s);
	exit(-1);
}

static int add_user_account(const char *user, int dynamic)
{
	if(user) {
		char *s = strstr(user,":");
		if(!s || (s==user) || (strlen(s)<2)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user account: %s\n",user);
		} else {
			size_t ulen = s-user;
			char *uname = malloc(sizeof(char)*(ulen+1));
			strncpy(uname,user,ulen);
			uname[ulen]=0;
			if(SASLprep((u08bits*)uname)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user name: %s\n",user);
				free(uname);
				return -1;
			}
			s = skip_blanks(s+1);
			unsigned char *key = malloc(16);
			if(strstr(s,"0x")==s) {
				char *keysource = s + 2;
				if(strlen(keysource)!=32) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s\n",s);
					free(uname);
					free(key);
					return -1;
				}
				char is[3];
				int i;
				unsigned int v;
				is[2]=0;
				for(i=0;i<16;i++) {
					is[0]=keysource[i*2];
					is[1]=keysource[i*2+1];
					sscanf(is,"%02x",&v);
					key[i]=(unsigned char)v;
				}
			} else {
				stun_produce_integrity_key_str((u08bits*)uname, (u08bits*)global_realm, (u08bits*)s, key);
			}
			if(dynamic) {
				ur_string_map_lock(users->dynamic_accounts);
				ur_string_map_put(users->dynamic_accounts, (ur_string_map_key_type)uname, (ur_string_map_value_type)key);
				ur_string_map_unlock(users->dynamic_accounts);
			} else {
				ur_string_map_lock(users->static_accounts);
				ur_string_map_put(users->static_accounts, (ur_string_map_key_type)uname, (ur_string_map_value_type)key);
				ur_string_map_unlock(users->static_accounts);
			}
			free(uname);
			return 0;
		}
	}

	return -1;
}

static void set_option(int c, const char *value)
{
	switch (c){
	case 'i':
		strcpy(relay_ifname, value);
		break;
	case 'm':
#if defined(TURN_NO_THREADS)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: threading is not supported,\n I am using single thread.\n");
#elif defined(OPENSSL_THREADS)
		relay_servers_number = atoi(value);
#else
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: OpenSSL version is too old OR does not support threading,\n I am using single thread.\n");
#endif
		break;
	case 'd':
		strcpy(listener_ifname, value);
		break;
	case 'p':
		listener_port = atoi(value);
		break;
	case TLS_PORT_OPT:
		tls_listener_port = atoi(value);
		break;
	case MIN_PORT_OPT:
		min_port = atoi(value);
		break;
	case MAX_PORT_OPT:
		max_port = atoi(value);
		break;
	case 'L':
		add_listener_addr(value);
		break;
	case 'E':
		add_relay_addr(value);
		break;
	case 'v':
		verbose = get_bool_value(value);
		break;
	case 'o':
		turn_daemon = get_bool_value(value);
		break;
	case 'a':
		if (get_bool_value(value))
			users->ct = TURN_CREDENTIALS_LONG_TERM;
		break;
	case 'f':
		fingerprint = get_bool_value(value);
		break;
	case 'u':
		add_user_account(value,0);
		break;
	case 'b':
		strcpy(userdb_file, value);
		break;
	case 'r':
		strcpy(global_realm,value);
		strcpy((s08bits*) users->realm, value);
		break;
	case 'q':
		users->user_quota = atoi(value);
		break;
	case 'Q':
		users->total_quota = atoi(value);
		break;
	case NO_UDP_OPT:
		no_udp = get_bool_value(value);
		break;
	case NO_TCP_OPT:
		no_tcp = get_bool_value(value);
		break;
	case NO_TLS_OPT:
#if defined(TURN_NO_TLS)
		no_tls = 1;
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: TLS is not supported\n");
#else
		no_tls = get_bool_value(value);
#endif
		break;
	case NO_DTLS_OPT:
#if defined(BIO_CTRL_DGRAM_QUERY_MTU)
		no_dtls = get_bool_value(value);
#else
		no_dtls = 1;
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: DTLS is not supported\n");
#endif
		break;
	case CERT_FILE_OPT:
		strcpy(cert_file,value);
		break;
	case PKEY_FILE_OPT:
		strcpy(pkey_file,value);
		break;
	/* these options have been already taken care of before: */
	case 'c':
	case 'n':
	case 'h':
		break;
	default:
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "%s\n", Usage);
		exit(-1);
	}
}

static int parse_arg_string(char *sarg, int *c, char **value)
{
	int i = 0;
	char *name = sarg;
	while(*sarg) {
		if((*sarg==' ') || (*sarg=='=')) {
			*sarg=0;
			do {
				++sarg;
			} while((*sarg==' ') || (*sarg=='='));
			*value = sarg;
			break;
		}
		++sarg;
		*value=sarg;
	}

	while(long_options[i].name) {
		if(strcmp(long_options[i].name,name)) {
			++i;
			continue;
		}
		*c=long_options[i].val;
		return 0;
	}

	return -1;
}

static void read_userdb_file(void)
{
	static char *full_path_to_userdb_file = NULL;
	static int first_read = 1;
	static turn_time_t mtime = 0;

	FILE *f = NULL;

	if(full_path_to_userdb_file) {
		struct stat sb;
		if(stat(full_path_to_userdb_file,&sb)<0) {
			perror("File statistics");
		} else {
			turn_time_t newmtime = (turn_time_t)(sb.st_mtime);
			if(mtime == newmtime)
				return;
			mtime = newmtime;

		}
	}

	if (!full_path_to_userdb_file)
		full_path_to_userdb_file = find_config_file(userdb_file, first_read);

	if (full_path_to_userdb_file)
		f = fopen(full_path_to_userdb_file, "r");

	if (f) {

		char sbuf[1025];

		ur_string_map_lock(users->dynamic_accounts);
		ur_string_map_clean(users->dynamic_accounts);

		for (;;) {
			char *s = fgets(sbuf, sizeof(sbuf) - 1, f);
			if (!s)
				break;
			s = skip_blanks(s);
			if (s[0] == '#')
				continue;
			if (!s[0])
				continue;
			size_t slen = strlen(s);
			while (slen && (s[slen - 1] == 10 || s[slen - 1] == 13))
				s[--slen] = 0;
			if (slen)
				add_user_account(s,1);
		}

		ur_string_map_unlock(users->dynamic_accounts);

		fclose(f);

	} else if (first_read)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Cannot find userdb file: %s: going without dynamic user database.\n", userdb_file);

	first_read = 0;
}

static void read_config_file(int argc, char **argv)
{
	char config_file[1025] = DEFAULT_CONFIG_FILE;

	strcpy(userdb_file,DEFAULT_USERDB_FILE);

	if (argv) {
		int i = 0;
		for (i = 0; i < argc; i++) {
			if (!strcmp(argv[i], "-c")) {
				if (i < argc - 1) {
					strncpy(config_file, argv[i + 1], sizeof(config_file)
									- 1);
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Wrong usage of -c option\n");
				}
			} else if (!strcmp(argv[i], "-n")) {
				return;
			} else if (!strcmp(argv[i], "-h")) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s\n", Usage);
				exit(0);
			}
		}
	}

	if (config_file[0]) {

		FILE *f = NULL;
		char *full_path_to_config_file = NULL;

		full_path_to_config_file = find_config_file(config_file, 1);
		if (full_path_to_config_file)
			f = fopen(full_path_to_config_file, "r");

		if (f && full_path_to_config_file) {

			char sbuf[1025];
			char sarg[1035];

			for (;;) {
				char *s = fgets(sbuf, sizeof(sbuf) - 1, f);
				if (!s)
					break;
				s = skip_blanks(s);
				if (s[0] == '#')
					continue;
				if (!s[0])
					continue;
				size_t slen = strlen(s);
				while (slen && (s[slen - 1] == 10 || s[slen - 1] == 13))
					s[--slen] = 0;
				if (slen) {
					int c = 0;
					char *value = NULL;
					strcpy(sarg, s);
					if (parse_arg_string(sarg, &c, &value) < 0) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Bad configuration format: %s\n",
							sarg);
					} else
						set_option(c, value);
				}
			}

			fclose(f);

		} else
			TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Cannot find config file: %s. Default settings will be used.\n",
				config_file);
	}
}

static int adminmain(int argc, char **argv)
{
	int c = 0;

	int kcommand = 0;
	int acommand = 0;
	int dcommand = 0;

	u08bits user[STUN_MAX_USERNAME_SIZE+1]="\0";
	u08bits realm[STUN_MAX_REALM_SIZE+1]="\0";
	u08bits pwd[STUN_MAX_PWD_SIZE+1]="\0";

	strcpy(userdb_file,DEFAULT_USERDB_FILE);

	while (((c = getopt_long(argc, argv, ADMIN_OPTIONS, admin_long_options, NULL)) != -1)) {
		switch (c){
		case 'k':
			kcommand = 1;
			break;
		case 'a':
			acommand = 1;
			break;
		case 'd':
			dcommand = 1;
			break;
		case 'b':
			strcpy(userdb_file,optarg);
			break;
		case 'u':
			strcpy((char*)user,optarg);
			if(SASLprep((u08bits*)user)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user name: %s\n",user);
				exit(-1);
			}
			break;
		case 'r':
			strcpy((char*)realm,optarg);
			if(SASLprep((u08bits*)realm)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong realm: %s\n",realm);
				exit(-1);
			}
			break;
		case 'p':
			strcpy((char*)pwd,optarg);
			if(SASLprep((u08bits*)pwd)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong password: %s\n",pwd);
				exit(-1);
			}
			break;
		case 'h':
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s\n", AdminUsage);
			exit(0);
			break;
		default:
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s\n", AdminUsage);
			exit(-1);
		}
	}

	if(!user[0] || (kcommand + acommand + dcommand != 1)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s\n", AdminUsage);
		exit(-1);
	}

	if(kcommand) {
		u08bits key[16];
		size_t i = 0;
		stun_produce_integrity_key_str(user, realm, pwd, key);
		printf("0x");
		for(i=0;i<sizeof(key);i++) {
			printf("%02x",(unsigned int)key[i]);
		}
		printf("\n");
	} else {

		char *full_path_to_userdb_file = find_config_file(userdb_file, 1);
		FILE *f = full_path_to_userdb_file ? fopen(full_path_to_userdb_file,"r") : NULL;
		int found = 0;
		char us[1025];
		size_t i = 0;
		u08bits key[16];
		char **content = NULL;
		size_t csz = 0;

		stun_produce_integrity_key_str(user, realm, pwd, key);

		strcpy(us, (char*) user);
		strcpy(us + strlen(us), ":");

		if (f) {

			char sarg[1025];
			char sbuf[1025];

			for (;;) {
				char *s0 = fgets(sbuf, sizeof(sbuf) - 1, f);
				if (!s0)
					break;

				size_t slen = strlen(s0);
				while (slen && (s0[slen - 1] == 10 || s0[slen - 1] == 13))
					s0[--slen] = 0;

				char *s = skip_blanks(s0);

				if (s[0] == '#')
					goto add_and_cont;
				if (!s[0])
					goto add_and_cont;

				strcpy(sarg, s);
				if (strstr(sarg, us) == sarg) {
					if (dcommand)
						continue;

					if (found)
						continue;
					found = 1;
					strcpy(us, (char*) user);
					strcpy(us + strlen(us), ":0x");
					for (i = 0; i < sizeof(key); i++) {
						sprintf(
										us + strlen(us),
										"%02x",
										(unsigned int) key[i]);
					}

					s0 = us;
				}

				add_and_cont: content = realloc(content, sizeof(char*)
									* (++csz));
				content[csz - 1] = strdup(s0);
			}

			fclose(f);
		}

		if(!found && acommand) {
			strcpy(us,(char*)user);
			strcpy(us+strlen(us),":0x");
			for(i=0;i<sizeof(key);i++) {
				sprintf(us+strlen(us),"%02x",(unsigned int)key[i]);
			}
			content = realloc(content,sizeof(char*)*(++csz));
			content[csz-1]=strdup(us);
		}

		if(!full_path_to_userdb_file)
			full_path_to_userdb_file=strdup(userdb_file);

		char *dir = malloc(strlen(full_path_to_userdb_file)+21);
		strcpy(dir,full_path_to_userdb_file);
		size_t dlen = strlen(dir);
		while(dlen) {
			if(dir[dlen-1]=='/')
				break;
			dir[--dlen]=0;
		}
		strcpy(dir+strlen(dir),".tmp_userdb");

		f = fopen(dir,"w");
		if(!f) {
			perror("file open");
			exit(-1);
		}

		for(i=0;i<csz;i++)
			fprintf(f,"%s\n",content[i]);

		fclose(f);

		rename(dir,full_path_to_userdb_file);
	}

	return 0;
}

static void set_system_parameters(void)
{
	srandom((unsigned int) time(NULL));
	setlocale(LC_ALL, "C");

	/* Ignore SIGPIPE from TCP sockets */
	signal(SIGPIPE, SIG_IGN);

	{
		struct rlimit rlim;
		if(getrlimit(RLIMIT_NOFILE, &rlim)<0) {
			perror("Cannot get system limit");
		} else {
			rlim.rlim_cur = rlim.rlim_max;
			if(setrlimit(RLIMIT_NOFILE, &rlim)<0) {
				perror("Cannot set system limit");
			}
		}
	}
}

int main(int argc, char **argv)
{
	int c = 0;

	{
	  /* On some systems, it may give us the execution path */
		char *_var = getenv("_");
		if(_var && *_var)
			set_execdir(dirname(_var));
	}

#if defined(TURN_NO_TLS)
	no_tls = 1;
	TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "WARNING: TLS is not supported\n");
#endif

#if !defined(BIO_CTRL_DGRAM_QUERY_MTU)
	no_dtls = 1;
	TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "WARNING: OpenSSL version is too old, DTLS is not supported\n");
#endif

	set_system_parameters();

	if(strstr(argv[0],"turnadmin"))
		return adminmain(argc,argv);

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "RFC 5389/5766/6156 STUN/TURN Server, version number %s '%s'\n",TURN_SERVER_VERSION,TURN_SERVER_VERSION_NAME);

	users = malloc(sizeof(turn_user_db));
	ns_bzero(users,sizeof(turn_user_db));
	users->ct = TURN_CREDENTIALS_NONE;
	users->static_accounts = ur_string_map_create(free);
	users->dynamic_accounts = ur_string_map_create(free);
	users->alloc_counters = ur_string_map_create(NULL);

	read_config_file(argc,argv);

	while (((c = getopt_long(argc, argv, OPTIONS, long_options, NULL)) != -1)) {
		if(c != 'u')
			set_option(c,optarg);
	}

	optind = 0;

	while (((c = getopt_long(argc, argv, OPTIONS, long_options, NULL)) != -1)) {
		if(c == 'u')
			set_option(c,optarg);
	}

	read_userdb_file();

	argc -= optind;
	argv += optind;

	if(argc>0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown argument: %s\n",argv[argc-1]);
		exit(-1);
	}

	openssl_setup();

	if (!listener.number) {
		make_local_listeners_list();
		if (!listener.number) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "You must specify the listener address(es)\n", __FUNCTION__);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s\n", Usage);
			exit(-1);
		}
	}

	if (!relays_number) {
		make_local_relays_list(0);
		if (!relays_number) {
			make_local_relays_list(1);
			if (!relays_number) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "You must specify the relay address(es)\n",
								__FUNCTION__);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s\n", Usage);
				exit(-1);
			}
		}
	}

	if(turn_daemon) {
#if !defined(HAS_DAEMON)
		pid_t pid = fork();
		if(pid>0)
			exit(0);
		if(pid<0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot start daemon process\n");
			exit(-1);
		}
#else
		if(daemon(1,0)<0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot start daemon process\n");
			exit(-1);
		}
		reset_rtpprintf();
#endif
	}

	setup_server();

	run_listener_server(listener.event_base);

	clean_server();

	openssl_cleanup();

	return 0;
}

////////// OpenSSL locking ////////////////////////////////////////

#if defined(OPENSSL_THREADS) && !defined(TURN_NO_THREADS)

static pthread_mutex_t* mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line) {
  UNUSED_ARG(file);
  UNUSED_ARG(line);
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
static void id_function(CRYPTO_THREADID *ctid)
{
    CRYPTO_THREADID_set_numeric(ctid, (unsigned long)pthread_self());
}
#else
static unsigned long id_function(void)
{
    return (unsigned long)pthread_self();
}
#endif

#endif

static int THREAD_setup(void) {

#if defined(OPENSSL_THREADS) && !defined(TURN_NO_THREADS)

	int i;

	mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks()
			* sizeof(pthread_mutex_t));
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&mutex_buf[i], NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	CRYPTO_THREADID_set_callback(id_function);
#else
	CRYPTO_set_id_callback(id_function);
#endif

	CRYPTO_set_locking_callback(locking_function);
#endif

	return 1;
}

static int THREAD_cleanup(void) {

#if defined(OPENSSL_THREADS) && !defined(TURN_NO_THREADS)

  int i;

  if (!mutex_buf)
    return 0;

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	CRYPTO_THREADID_set_callback(NULL);
#else
	CRYPTO_set_id_callback(NULL);
#endif

  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;

#endif

  return 1;
}

static void set_ctx(SSL_CTX* ctx, const char *protocol)
{

	SSL_CTX_set_cipher_list(ctx, "DEFAULT");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: no certificate found\n",protocol);
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: Certificate file %s found\n",protocol,cert_file);
	}

	if (!SSL_CTX_use_PrivateKey_file(ctx, pkey_file, SSL_FILETYPE_PEM)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: no private key found\n",protocol);
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: Private key file %s found\n",protocol,pkey_file);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: invalid private key\n",protocol);
	}
}

static void adjust_key_file_name(char *fn, const char* file_title)
{
	char *full_path_to_file = NULL;

	if(!fn[0]) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: you must set the %s file parameter\n",file_title);
		goto keyerr;
	}

	full_path_to_file = find_config_file(fn, 1);
	FILE *f = full_path_to_file ? fopen(full_path_to_file,"r") : NULL;
	if(!f) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: cannot find %s file: %s (1)\n",file_title,fn);
		goto keyerr;
	}

	if(!full_path_to_file) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: cannot find %s file: %s (2)\n",file_title,fn);
		goto keyerr;
	}

	strcpy(fn,full_path_to_file);

	if(full_path_to_file)
		free(full_path_to_file);
	return;

	keyerr:
	no_tls = 1;
	no_dtls = 1;
	if(full_path_to_file)
		free(full_path_to_file);
	TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: cannot start TLS and DTLS listeners because %s file is not set properly\n",file_title);
	return;
}

static void adjust_key_file_names(void)
{
	adjust_key_file_name(cert_file,"certificate");
	adjust_key_file_name(pkey_file,"private key");
}

static void openssl_setup(void)
{
	THREAD_setup();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

#if defined(TURN_NO_TLS)
	if(!no_tls) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "WARNING: TLS is not supported\n");
		no_tls = 1;
	}
#endif

	if(!(no_tls && no_dtls) && !cert_file[0]) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,"\nWARNING: certificate file is not specified, I cannot start TLS/DTLS services.\nOnly 'plain' UDP/TCP listeners can be started.\n");
		no_tls = 1;
		no_dtls = 1;
	}

	if(!(no_tls && no_dtls) && !pkey_file[0]) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,"\nWARNING: private key file is not specified, I cannot start TLS/DTLS services.\nOnly 'plain' UDP/TCP listeners can be started.\n");
		no_tls = 1;
		no_dtls = 1;
	}

	if(!(no_tls && no_dtls)) {
		adjust_key_file_names();
	}

	if(!no_tls) {
		tls_ctx = SSL_CTX_new(TLSv1_server_method());
		set_ctx(tls_ctx,"TLS");
	}

	if(!no_dtls) {
#if !defined(BIO_CTRL_DGRAM_QUERY_MTU)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "ERROR: DTLS is not supported.\n");
#else
		if(OPENSSL_VERSION_NUMBER < 0x10000000L) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: OpenSSL version is rather old, DTLS may not be working correctly.\n");
		}
		dtls_ctx = SSL_CTX_new(DTLSv1_server_method());
		set_ctx(dtls_ctx,"DTLS");
#endif
	}
}

static void openssl_cleanup(void)
{
	if(tls_ctx) {
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;
	}

	if(dtls_ctx) {
		SSL_CTX_free(dtls_ctx);
		dtls_ctx = NULL;
	}

	THREAD_cleanup();
}

///////////////////////////////
