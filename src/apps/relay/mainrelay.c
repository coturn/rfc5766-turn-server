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
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "ns_turn_utils.h"

#include "udp_listener.h"
#include "tcp_listener.h"
#include "tls_listener.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "ns_ioalib_impl.h"

//////////////// OpenSSL Init //////////////////////

static void openssl_setup(void);
static void openssl_cleanup(void);

//////////////// Common params ////////////////////

static int verbose=0;

#define DEFAULT_CONFIG_FILE "turn.conf"
const char* config_file_search_dirs[] = {"", "etc/", "/etc/", "/usr/local/etc/", NULL };

////////////////  Listener server /////////////////

static int listener_port = DEFAULT_STUN_PORT;
static int tls_listener_port = DEFAULT_STUN_TLS_PORT;

static int no_udp = 0;
static int no_tcp = 0;
static int no_tls = 0;

static SSL_CTX *tls_ctx = NULL;

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
};

struct listener_server listener = {0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

static uint32_t stats=0;

//////////////// Relay servers //////////////////////////////////

static u16bits min_port = LOW_DEFAULT_PORTS_BOUNDARY;
static u16bits max_port = HIGH_DEFAULT_PORTS_BOUNDARY;

static char relay_ifname[1025]="\0";

static size_t relays_number = 0;
static char **relay_addrs = NULL;

static int fingerprint = 0;

static turn_user_db *users = NULL;

static size_t relay_servers_number = 0;
#define get_real_relay_servers_number() (relay_servers_number > 1 ? relay_servers_number : 1)

struct relay_server {
	struct event_base* event_base;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	ioa_engine_handle ioa_eng;
	turn_turnserver *server;
	pthread_t thr;
};
static struct relay_server **relay_servers = NULL;

////////////// Configuration functionality ////////////////////////////////

static int read_config_file(int argc, char **argv, int users_only);
static void reread_users(void) ;

static int orig_argc = 0;
static char **orig_argv = NULL;

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
			close_ioa_socket(s);
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

	set_ssl_ctx(listener.ioa_eng, tls_ctx);

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

		reread_users();
	}
}

static void setup_relay_server(struct relay_server *rs, ioa_engine_handle e)
{
	struct bufferevent *pair[2];

	if(e) {
		rs->event_base = e->event_base;
		rs->ioa_eng = e;
	} else {
		rs->event_base = event_base_new();
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (relay thread): %s\n",event_base_get_method(rs->event_base));
		rs->ioa_eng = create_ioa_engine(rs->event_base, listener.tp, relay_ifname, relays_number, relay_addrs, verbose);
		set_ssl_ctx(rs->ioa_eng, tls_ctx);
		ioa_engine_set_rtcp_map(rs->ioa_eng, listener.rtcpmap);
	}

	bufferevent_pair_new(rs->event_base, BEV_OPT_THREADSAFE, pair);
	rs->in_buf = pair[0];
	rs->out_buf = pair[1];
	bufferevent_setcb(rs->in_buf, acceptsocket, NULL, NULL, rs);
	bufferevent_enable(rs->in_buf, EV_READ);
	rs->server = create_turn_server(verbose, rs->ioa_eng, &stats, 0, fingerprint, DONT_FRAGMENT_SUPPORTED, users);
}

static void *run_relay_thread(void *arg)
{
  static int always_true = 1;
  struct relay_server *rs = arg;
  
  setup_relay_server(rs, NULL);

  while(always_true)
    run_events(rs->event_base);
  
  return arg;
}

static void setup_relay_servers(void)
{
	size_t i = 0;

	relay_servers = malloc(sizeof(struct relay_server *)*get_real_relay_servers_number());

	for(i=0;i<get_real_relay_servers_number();i++) {

		relay_servers[i] = malloc(sizeof(struct relay_server));

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
		ur_string_map_free(&(users->accounts));
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
			printf("Added listener address %s (%s)\n",saddr,ifa->ifa_name);
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
			printf("Added relay address %s (%s)\n",saddr,ifa->ifa_name);
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
	"	    --tls-listening-port	TURN listener port for TLS listeners\n"
	"					(Default: 5349).\n"
	"	-L, --listening-ip		Listener IP address of relay server. Multiple listeners can be specified.\n"
	"	-i, --relay-device		Relay interface device for relay sockets (optional, Linux only).\n"
	"	-E, --relay-ip			Relay address (the local IP address that will be used to relay the packets to the peer).\n"
	"	-m, --relay-threads		Number of extra threads to handle established connections (default is 0).\n"
	"	-l, --min-port			Lower bound of the UDP port range for relay endpoints allocation.\n"
	"					Default value is 49152, according to RFC 5766.\n"
	"	-r, --max-port			Upper bound of the UDP port range for relay endpoints allocation.\n"
	"					Default value is 65535, according to RFC 5766.\n"
	"	-v, --verbose			Verbose.\n"
	"	-f, --fingerprint		Use fingerprints in the TURN messages.\n"
	"	-a, --lt-cred-mech		Use long-term credential mechanism.\n"
	"	-u, --user			User account, in form 'username:password'.\n"
	"	-e, --realm			Realm.\n"
	"	-q, --user-quota		per-user allocation quota.\n"
	"	-Q, --total-quota		total allocation quota.\n"
	"	-c				Configuration file name (default - turn.conf).\n"
	"	-n				Do not use configuration file.\n"
	"	    --cert			Certificate file, PEM format. Same file search rules\n"
	"					applied as for the configuration file.\n"
	"					If --no-tls option\n"
	"					is specified, then this parameter is not needed.\n"
	"	    --pkey			Private key file, PEM format. Same file search rules\n"
	"					applied as for the configuration file.\n"
	"					If --no-tls option\n"
	"					is specified, then this parameter is not needed.\n"
	"	    --no-udp			Do not start UDP listeners.\n"
	"	    --no-tcp			Do not start TCP listeners.\n"
	"	    --no-tls			Do not start TLS listeners.\n"
	"	-h				Help\n";

static char AdminUsage[] = "Usage: turnadmin [command] [options]\n"
	"Options:\n"
	"	-k, --key		Command: generate key for a user\n"
	"	-a, --add		Command: add/update a user\n"
	"	-d, --delete		Command: delete a user\n"
	"	-c, --config-file	configuration file\n"
	"	-u, --user		Username\n"
	"	-r, --realm		Realm\n"
	"	-p, --password		Password\n"
	"	-h, --help		Help\n";

#define OPTIONS "d:p:L:E:i:m:l:r:u:e:q:Q:vfha"

#define ADMIN_OPTIONS "kadc:u:r:p:h"

enum EXTRA_OPTS {
	NO_UDP_OPT=256,
	NO_TCP_OPT,
	NO_TLS_OPT,
	TLS_PORT_OPT,
	CERT_FILE_OPT,
	PKEY_FILE_OPT
};

static struct option long_options[] = {
				{ "listening-device", required_argument, NULL, 'd' },
				{ "listening-port", required_argument, NULL, 'p' },
				{ "tls-listening-port", required_argument, NULL, TLS_PORT_OPT },
				{ "listening-ip", required_argument, NULL, 'L' },
				{ "relay-device", required_argument, NULL, 'i' },
				{ "relay-ip", required_argument, NULL, 'E' },
				{ "relay-threads", required_argument, NULL, 'm' },
				{ "min-port", required_argument, NULL, 'l' },
				{ "max-port", required_argument, NULL, 'r' },
				{ "lt-cred-mech", optional_argument, NULL, 'a' },
				{ "user", required_argument, NULL, 'u' },
				{ "realm", required_argument, NULL, 'e' },
				{ "user-quota", required_argument, NULL, 'q' },
				{ "total-quota", required_argument, NULL, 'Q' },
				{ "verbose", optional_argument, NULL, 'v' },
				{ "fingerprint", optional_argument, NULL, 'f' },
				{ "no-udp", optional_argument, NULL, NO_UDP_OPT },
				{ "no-tcp", optional_argument, NULL, NO_TCP_OPT },
				{ "no-tls", optional_argument, NULL, NO_TLS_OPT },
				{ "cert", required_argument, NULL, CERT_FILE_OPT },
				{ "pkey", required_argument, NULL, PKEY_FILE_OPT },
				{ NULL, no_argument, NULL, 0 }
};

static struct option admin_long_options[] = {
				{ "key", no_argument, NULL, 'k' },
				{ "add", no_argument, NULL, 'a' },
				{ "delete", no_argument, NULL, 'd' },
				{ "config-file", required_argument, NULL, 'c' },
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

static FILE *find_config_file(const char *config_file, int print_file_name, char **full_path_to_config_file)
{
	if (config_file && config_file[0]) {
		if (config_file[0] == '/') {
			*full_path_to_config_file = strdup(config_file);
			FILE *f = fopen(config_file, "r");
			if (f)
				return f;
		} else {
			int i = 0;
			size_t cflen = strlen(config_file);

			while (config_file_search_dirs[i]) {
				size_t dirlen = strlen(config_file_search_dirs[i]);
				char *fn = malloc(sizeof(char) * (dirlen + cflen + 1));
				strcpy(fn, config_file_search_dirs[i]);
				strcpy(fn + dirlen, config_file);
				FILE *f = fopen(fn, "r");
				if (f) {
					if (print_file_name)
						fprintf(stdout, "File found: %s\n", fn);
					*full_path_to_config_file = fn;
					return f;
				}
				free(fn);
				++i;
			}
		}
	}
	return NULL;
}

static int get_bool_value(const char* s)
{
	if(!s || !(s[0])) return 1;
	if(s[0]=='0' || s[0]=='n' || s[0]=='N' || s[0]=='f' || s[0]=='F') return 0;
	if(s[0]=='y' || s[0]=='Y' || s[0]=='t' || s[0]=='T') return 1;
	if(s[0]>'0' && s[0]<='9') return 1;
	if(!strcmp(s,"off") || !strcmp(s,"OFF") || !strcmp(s,"Off")) return 0;
	if(!strcmp(s,"on") || !strcmp(s,"ON") || !strcmp(s,"On")) return 1;
	fprintf(stderr,"Unknown boolean value: %s. You can use on/off, yes/no, 1/0, true/false.\n",s);
	exit(-1);
}

static int add_user_account(const char *user)
{
	if(user) {
		char *s = strstr(user,":");
		if(!s || (s==user) || (strlen(s)<2)) {
			fprintf(stderr,"Wrong user account: %s\n",user);
		} else {
			size_t ulen = s-user;
			char *uname = malloc(sizeof(char)*(ulen+1));
			strncpy(uname,user,ulen);
			uname[ulen]=0;
			if(SASLprep((u08bits*)uname)<0) {
				fprintf(stderr,"Wrong user name: %s\n",user);
				free(uname);
				return -1;
			}
			s = skip_blanks(s+1);
			if(strstr(s,"0x")==s)
				s+=2;
			if(strlen(s)!=32) {
				fprintf(stderr,"Wrong key: %s\n",s);
				free(uname);
				return -1;
			}
			unsigned char *key = malloc(16);
			char is[3];
			int i;
			unsigned int v;
			is[2]=0;
			for(i=0;i<16;i++) {
				is[0]=s[i*2];
				is[1]=s[i*2+1];
				sscanf(is,"%02x",&v);
				key[i]=(unsigned char)v;
			}
			ur_string_map_lock(users->accounts);
			ur_string_map_put(users->accounts, (ur_string_map_key_type)uname, (ur_string_map_value_type)key);
			ur_string_map_unlock(users->accounts);
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
		relay_servers_number = atoi(value);
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
	case 'l':
		min_port = atoi(value);
		break;
	case 'r':
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
	case 'a':
		if (get_bool_value(value))
			users->ct = TURN_CREDENTIALS_LONG_TERM;
		break;
	case 'f':
		fingerprint = get_bool_value(value);
		break;
	case 'u':
		add_user_account(value);
		break;
	case 'e':
		strcpy((s08bits*) users->realm, value);
		break;
	case 'q':
		users->user_quota = atoi(optarg);
		break;
	case 'Q':
		users->total_quota = atoi(optarg);
		break;
	case NO_UDP_OPT:
		no_udp = get_bool_value(value);
		break;
	case NO_TCP_OPT:
		no_tcp = get_bool_value(value);
		break;
	case NO_TLS_OPT:
		no_tls = get_bool_value(value);
		break;
	case CERT_FILE_OPT:
		strcpy(cert_file,optarg);
		break;
	case PKEY_FILE_OPT:
		strcpy(pkey_file,optarg);
		break;
	/* these options have been already taken care of before: */
	case 'c':
	case 'n':
	case 'h':
		break;
	default:
		fprintf(stderr, "%s\n", Usage);
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

static int read_config_file(int argc, char **argv, int users_only)
{
	static char config_file[1025] = DEFAULT_CONFIG_FILE;
	static char *full_path_to_config_file = NULL;
	static turn_time_t mtime = 0;

	int i = 0;
	FILE *f = NULL;

	if(users_only && full_path_to_config_file) {
		struct stat sb;
		if(stat(full_path_to_config_file,&sb)<0) {
			perror("File statistics");
		} else {
			turn_time_t newmtime = (turn_time_t)(sb.st_mtime);
			if(mtime == newmtime)
				return 0;

		}
	}

	if (full_path_to_config_file)
		f = fopen(full_path_to_config_file, "r");
	else {
		if (argv) {

			for (i = 0; i < argc; i++) {
				if (!strcmp(argv[i], "-c")) {
					if (i < argc - 1) {
						strncpy(config_file, argv[i + 1], sizeof(config_file) - 1);
					} else {
						fprintf(stderr, "Wrong usage of -c option\n");
					}
				} else if (!strcmp(argv[i], "-n")) {
					config_file[0] = 0;
				} else if (!strcmp(argv[i], "-h")) {
					fprintf(stdout, "%s\n", Usage);
					exit(0);
				}
			}
		}

		f = find_config_file(config_file, !users_only, &full_path_to_config_file);
	}

	if (f && full_path_to_config_file) {

		char sbuf[1025];
		char sarg[1035];

		struct stat sb;
		if(stat(full_path_to_config_file,&sb)<0)
			perror("File statistics");
		else
			mtime = (turn_time_t)(sb.st_mtime);


		ur_string_map_lock(users->accounts);
		ur_string_map_clean(users->accounts);

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
				strcpy(sarg, s);
				int c = 0;
				char *value = NULL;
				if (parse_arg_string(sarg, &c, &value) < 0) {
					fprintf(stderr, "Bad configuration format: %s\n", sarg);
				} else {
					if (c == 'u' || (users_only == 0))
						set_option(c, value);
				}
			}
		}

		fclose(f);

		return 1;

	} else if (!users_only) {
		fprintf(stderr, "Cannot find config file: %s\n", config_file);
		exit(-1);
	} else
		return 0;
}

static void reread_users(void)
{
	int c = 0;
	if(read_config_file(0,NULL,1)) {
		optind=0;
		while (((c = getopt_long(orig_argc, orig_argv, OPTIONS, long_options, NULL)) != -1)) {
			if(c == 'u')
				set_option(c,optarg);
		}
		ur_string_map_unlock(users->accounts);
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

	char config_file[1025] = DEFAULT_CONFIG_FILE;

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
		case 'c':
			strcpy(config_file,optarg);
			break;
		case 'u':
			strcpy((char*)user,optarg);
			if(SASLprep((u08bits*)user)<0) {
				fprintf(stderr,"Wrong user name: %s\n",user);
				exit(-1);
			}
			break;
		case 'r':
			strcpy((char*)realm,optarg);
			if(SASLprep((u08bits*)realm)<0) {
				fprintf(stderr,"Wrong realm: %s\n",realm);
				exit(-1);
			}
			break;
		case 'p':
			strcpy((char*)pwd,optarg);
			if(SASLprep((u08bits*)pwd)<0) {
				fprintf(stderr,"Wrong password: %s\n",pwd);
				exit(-1);
			}
			break;
		case 'h':
			fprintf(stdout, "%s\n", AdminUsage);
			exit(0);
			break;
		default:
			fprintf(stderr, "%s\n", AdminUsage);
			exit(-1);
		}
	}

	if(!user[0] || (kcommand + acommand + dcommand != 1)) {
		fprintf(stderr, "%s\n", AdminUsage);
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

		char *full_path_to_config_file = NULL;
		FILE *f = find_config_file(config_file, 1, &full_path_to_config_file);
		if(!f || !full_path_to_config_file) {
			fprintf(stderr,"Cannot file %s file.\n",config_file);
			exit(-1);
		}

		char **content = NULL;
		size_t csz = 0;
		char sarg[1025];
		char sbuf[1025];
		char us[1025];
		int found = 0;
		int realm_found = 0;
		size_t i = 0;
		u08bits key[16];

		stun_produce_integrity_key_str(user, realm, pwd, key);

		strcpy(us,(char*)user);
		strcpy(us+strlen(us),":");

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
			int c = 0;
			char *value = NULL;
			if (parse_arg_string(sarg, &c, &value) >= 0) {
				if (c == 'u') {
					if(strstr(value,us)==value) {
						if(dcommand)
							continue;

						if(found)
							continue;
						found = 1;
						strcpy(us,"user=");
						strcpy(us+strlen(us),(char*)user);
						strcpy(us+strlen(us),":0x");
						for(i=0;i<sizeof(key);i++) {
							sprintf(us+strlen(us),"%02x",(unsigned int)key[i]);
						}
						s0 = us;
					}
				} else if(c == 'e') {
					if(!realm_found) {
						realm_found = 1;
						strcpy(us,"realm=");
						strcpy(us+strlen(us),(char*)realm);
						s0 = us;
					} else
						continue;
				}
			}

			add_and_cont:
			content = realloc(content,sizeof(char*)*(++csz));
			content[csz-1]=strdup(s0);
		}

		fclose(f);

		if(!found && acommand) {
			strcpy(us,"user=");
			strcpy(us+strlen(us),(char*)user);
			strcpy(us+strlen(us),":0x");
			for(i=0;i<sizeof(key);i++) {
				sprintf(us+strlen(us),"%02x",(unsigned int)key[i]);
			}
			content = realloc(content,sizeof(char*)*(++csz));
			content[csz-1]=strdup(us);
		}

		if(!realm_found && acommand) {
			strcpy(us,"realm=");
			strcpy(us+strlen(us),(char*)realm);
			content = realloc(content,sizeof(char*)*(++csz));
			content[csz-1]=strdup(us);
		}

		char *dir = malloc(strlen(full_path_to_config_file)+21);
		strcpy(dir,full_path_to_config_file);
		size_t dlen = strlen(dir);
		while(dlen) {
			if(dir[dlen-1]=='/')
				break;
			dir[--dlen]=0;
		}
		strcpy(dir+strlen(dir),".tmp_config");

		f = fopen(dir,"w");
		if(!f) {
			perror("file open");
			exit(-1);
		}

		for(i=0;i<csz;i++)
			fprintf(f,"%s\n",content[i]);

		fclose(f);

		rename(dir,full_path_to_config_file);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int c = 0;

	srandom((unsigned int) time(NULL));
	setlocale(LC_ALL, "C");

	if(strstr(argv[0],"turnadmin"))
		return adminmain(argc,argv);

	users = malloc(sizeof(turn_user_db));
	ns_bzero(users,sizeof(turn_user_db));
	users->ct = TURN_CREDENTIALS_NONE;
	users->accounts = ur_string_map_create(free);
	users->alloc_counters = ur_string_map_create(NULL);

	if(read_config_file(argc,argv,0))
		ur_string_map_unlock(users->accounts);

	orig_argc = argc;
	orig_argv = argv;

	while (((c = getopt_long(argc, argv, OPTIONS, long_options, NULL)) != -1)) {
		set_option(c,optarg);
	}

	argc -= optind;
	argv += optind;

	if(argc>0) {
		fprintf(stderr,"Unknown argument: %s\n",argv[argc-1]);
		exit(-1);
	}

	openssl_setup();

	if (!listener.number) {
		make_local_listeners_list();
		if (!listener.number) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "You must specify the listener address(es)\n", __FUNCTION__);
			fprintf(stderr, "%s\n", Usage);
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
				fprintf(stderr, "%s\n", Usage);
				exit(-1);
			}
		}
	}

	setup_server();

	run_listener_server(listener.event_base);

	clean_server();

	openssl_cleanup();

	return 0;
}

////////// OpenSSL locking ////////////////////////////////////////

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

static int THREAD_setup(void) {

#ifdef OPENSSL_THREADS

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

#ifdef OPENSSL_THREADS

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

static void set_ctx(SSL_CTX* ctx) {

  SSL_CTX_set_cipher_list(ctx, "DEFAULT");
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

  if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)) {
    if (verbose) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: no certificate found!");
      exit(-1);
    }
  }

  if (!SSL_CTX_use_PrivateKey_file(ctx, pkey_file, SSL_FILETYPE_PEM)) {
    if (verbose) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: no private key found!");
      exit(-1);
    }
  }

  if (!SSL_CTX_check_private_key (ctx)) {
    if (verbose) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: invalid private key!");
      exit(-1);
    }
  }
}

static void adjust_key_file_name(char *fn, const char* file_title)
{
	char *full_path_to_file = NULL;

	if(!fn[0]) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: you must set the %s file parameter\n",file_title);
		exit(-1);
	}

	FILE *f = find_config_file(fn, 1, &full_path_to_file);
	if(!f) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: cannot find %s file: %s (1)\n",file_title,fn);
		exit(-1);
	}

	if(!full_path_to_file) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"\nERROR: cannot find %s file: %s (2)\n",file_title,fn);
		exit(-1);
	}

	strcpy(fn,full_path_to_file);

	free(full_path_to_file);
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

	if(!no_tls && !cert_file[0]) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,"\nWARNING: certificate file is not specified, I cannot start TLS services.\n");
		no_tls = 1;
	}

	if(!no_tls && !pkey_file[0]) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,"\nWARNING: private key file is not specified, I cannot start TLS services.\n");
		no_tls = 1;
	}

	if(!no_tls) {
		adjust_key_file_names();

		tls_ctx = SSL_CTX_new(TLSv1_server_method());

		set_ctx(tls_ctx);
	}
}

static void openssl_cleanup(void)
{
	if(tls_ctx)
		SSL_CTX_free(tls_ctx);

	THREAD_cleanup();
}

///////////////////////////////
