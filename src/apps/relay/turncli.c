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

#include <signal.h>

#include "libtelnet.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>

#include "userdb.h"
#include "mainrelay.h"

#include "ns_turn_utils.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "turncli.h"

///////////////////////////////

struct cli_server cliserver;

int use_cli = 1;

ioa_addr cli_addr;
int cli_addr_set = 0;

int cli_port = CLI_DEFAULT_PORT;

char cli_password[CLI_PASSWORD_LENGTH] = "";

///////////////////////////////

struct cli_session {
	//TODO
	evutil_socket_t fd;
	int auth_completed;
	size_t cmds;
	struct bufferevent *bev;
	ioa_addr addr;
	telnet_t *ts;
};

///////////////////////////////

#define CLI_PASSWORD_TRY_NUMBER (5)

static char CLI_HELP_STR[] =
" ?,h,help - help text\n"
" quit, exit, bye - end CLI session\n"
" stop, shutdown, halt - shutdown TURN Server\n";

static char CLI_GREETING_STR[] =
"TURN Server\n"
"rfc5766-turn-server\n"
TURN_SOFTWARE
"\nType ? for help\n";

static char CLI_CURSOR[] = "> ";

static const telnet_telopt_t cli_telopts[] = {
    { TELNET_TELOPT_ECHO,      TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_TTYPE,     TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_COMPRESS2, TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_ZMP,       TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_MSSP,      TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_BINARY,    TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_NAWS,      TELNET_WONT, TELNET_DONT },
    { -1, 0, 0 }
  };

///////////////////////////////

static void close_cli_session(struct cli_session* cs);

static int run_cli_output(struct cli_session* cs, const char *buf, unsigned int len)
{
	if(cs && buf && len) {
		if(bufferevent_write(cs->bev, buf, len)< 0) {
			return -1;
		}
		return 0;
	}
	return -1;
}

static void close_cli_session(struct cli_session* cs)
{
	if(cs) {

		addr_debug_print(cliserver.verbose, &(cs->addr),"CLI session disconnected from");

		if(cs->ts) {
			telnet_free(cs->ts);
			cs->ts = NULL;
		}

		if(cs->bev) {
			bufferevent_flush(cs->bev,EV_WRITE,BEV_FLUSH);
			bufferevent_disable(cs->bev,EV_READ|EV_WRITE);
			bufferevent_free(cs->bev);
			cs->bev=NULL;
		}

		if(cs->fd>=0) {
			close(cs->fd);
			cs->fd = -1;
		}

		turn_free(cs,sizeof(struct cli_session));
	}
}

static void type_cli_cursor(struct cli_session* cs)
{
	if(cs && (cs->bev)) {
		telnet_send(cs->ts, CLI_CURSOR, strlen(CLI_CURSOR));
	}
}

static int run_cli_input(struct cli_session* cs, const char *buf0, unsigned int len)
{
	int ret = 0;

	if(cs && buf0 && cs->ts && cs->bev) {

		char *buf = strdup(buf0);

		char *cmd = buf;

		while((cmd[0]==' ') || (cmd[0]=='\t')) ++cmd;

		size_t sl = len;

		sl = strlen(cmd);

		while(sl) {
			char c = cmd[sl-1];
			if((c==10)||(c==13)) {
				cmd[sl-1]=0;
				--sl;
			} else {
				break;
			}
		}

		if(sl) {
			cs->cmds += 1;
			if(cli_password[0] && !(cs->auth_completed)) {
				if(strcmp(cmd,cli_password)) {
					if(cs->cmds>=CLI_PASSWORD_TRY_NUMBER) {
						addr_debug_print(1, &(cs->addr),"CLI authentication error");
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"CLI authentication error\n");
						close_cli_session(cs);
					} else {
						const char* ipwd="Enter password: ";
						telnet_send(cs->ts,ipwd,strlen(ipwd));
					}
				} else {
					cs->auth_completed = 1;
					addr_debug_print(1, &(cs->addr),"CLI authentication success");
					type_cli_cursor(cs);
				}
			} else if((strcmp(cmd,"bye") == 0)||(strcmp(cmd,"quit") == 0)||(strcmp(cmd,"exit") == 0)) {
				const char* str="Bye !";
				telnet_send(cs->ts,str,strlen(str));
				close_cli_session(cs);
				ret = -1;
			} else if((strcmp(cmd,"halt") == 0)||(strcmp(cmd,"shutdown") == 0)||(strcmp(cmd,"stop") == 0)) {
				addr_debug_print(1, &(cs->addr),"CLI user sent shutdown command");
				const char* str="TURN server is shutting down";
				telnet_send(cs->ts,str,strlen(str));
				close_cli_session(cs);
				exit(0);
			} else if((strcmp(cmd,"?") == 0)||(strcmp(cmd,"h") == 0)||(strcmp(cmd,"help") == 0)) {
				telnet_send(cs->ts,CLI_HELP_STR,strlen(CLI_HELP_STR));
				type_cli_cursor(cs);
			} else {
				const char* str="Unknown command\n";
				telnet_send(cs->ts,str,strlen(str));
				type_cli_cursor(cs);
			}
		} else {
			type_cli_cursor(cs);
		}

		free(buf);
	}

	return ret;
}

static void cli_socket_input_handler_bev(struct bufferevent *bev, void* arg)
{
	if (bev && arg) {

		struct cli_session* cs = (struct cli_session*) arg;

		if(!(cs->ts))
			return;

		stun_buffer buf;

		while(cs->bev) {

			int len = (int)bufferevent_read(cs->bev, buf.buf, STUN_BUFFER_SIZE-1);
			if(len < 0) {
				close_cli_session(cs);
				return;
			} else if(len == 0) {
				return;
			}

			buf.len = len;
			buf.buf[len]=0;

			telnet_recv(cs->ts, (const char *)buf.buf, (unsigned int)(buf.len));
		}
	}
}

static void cli_eventcb_bev(struct bufferevent *bev, short events, void *arg)
{
	UNUSED_ARG(bev);

	if (events & BEV_EVENT_CONNECTED) {
		// Connect okay
	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		if (arg) {

			struct cli_session* cs = (struct cli_session*) arg;

			close_cli_session(cs);
		}
	}
}

static void cli_telnet_event_handler(telnet_t *telnet, telnet_event_t *event, void *user_data)
{
	if (user_data && telnet) {

		struct cli_session *cs = (struct cli_session *) user_data;

		switch (event->type){
		case TELNET_EV_DATA:
			run_cli_input(cs, event->data.buffer, event->data.size);
			break;
		case TELNET_EV_SEND:
			run_cli_output(cs, event->data.buffer, event->data.size);
			break;
		case TELNET_EV_ERROR:
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TELNET error: %s", event->error.msg);
			break;
		default:
			;
		};
	}
}

static void cliserver_input_handler(struct evconnlistener *l, evutil_socket_t fd,
				struct sockaddr *sa, int socklen, void *arg)
{
	UNUSED_ARG(l);
	UNUSED_ARG(arg);
	UNUSED_ARG(socklen);

	addr_debug_print(cliserver.verbose, (ioa_addr*)sa,"CLI connected to");

	struct cli_session *clisession = (struct cli_session*)turn_malloc(sizeof(struct cli_session));
	ns_bzero(clisession,sizeof(struct cli_session));

	set_socket_options_fd(fd, 1, sa->sa_family);

	clisession->fd = fd;

	addr_cpy(&(clisession->addr),(ioa_addr*)sa);

	clisession->bev = bufferevent_socket_new(cliserver.event_base,
					fd,
					BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
	bufferevent_setcb(clisession->bev, cli_socket_input_handler_bev, NULL,
			cli_eventcb_bev, clisession);
	bufferevent_setwatermark(clisession->bev, EV_READ, 1, BUFFEREVENT_HIGH_WATERMARK);
	bufferevent_enable(clisession->bev, EV_READ); /* Start reading. */

	clisession->ts = telnet_init(cli_telopts, cli_telnet_event_handler, 0, clisession);

	if(!(clisession->ts)) {
		const char *str = "Cannot open telnet session\n";
		addr_debug_print(cliserver.verbose, (ioa_addr*)sa,str);
		close_cli_session(clisession);
	} else {
		telnet_send(clisession->ts, CLI_GREETING_STR, strlen(CLI_GREETING_STR));
		if(cli_password[0]) {
			const char* ipwd="Enter password: ";
			telnet_send(clisession->ts,ipwd,strlen(ipwd));
		} else {
			type_cli_cursor(clisession);
		}
	}
}

void setup_cli_thread(void)
{
	cliserver.event_base = event_base_new();
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (cli thread): %s\n",event_base_get_method(cliserver.event_base));

	struct bufferevent *pair[2];
	int opts = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS;

	opts |= BEV_OPT_THREADSAFE;

	bufferevent_pair_new(cliserver.event_base, opts, pair);
	cliserver.in_buf = pair[0];
	cliserver.out_buf = pair[1];
	bufferevent_setcb(cliserver.in_buf, cli_server_receive_message, NULL, NULL, &cliserver);
	bufferevent_enable(cliserver.in_buf, EV_READ);

	if(!cli_addr_set) {
		if(make_ioa_addr((const u08bits*)CLI_DEFAULT_IP,0,&cli_addr)<0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot set cli address %s\n",CLI_DEFAULT_IP);
			return;
		}
	}

	addr_set_port(&cli_addr,cli_port);

	cliserver.listen_fd = socket(cli_addr.ss.ss_family, SOCK_STREAM, 0);
	if (cliserver.listen_fd < 0) {
	    perror("socket");
	    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot open CLI socket\n");
	    return;
	}

	if(addr_bind(cliserver.listen_fd,&cli_addr)<0) {
	  perror("Cannot bind CLI socket to addr");
	  char saddr[129];
	  addr_to_string(&cli_addr,(u08bits*)saddr);
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot bind CLI listener socket to addr %s\n",saddr);
	  socket_closesocket(cliserver.listen_fd);
	  return;
	}

	socket_tcp_set_keepalive(cliserver.listen_fd);

	socket_set_nonblocking(cliserver.listen_fd);

	cliserver.l = evconnlistener_new(cliserver.event_base,
			  cliserver_input_handler, &cliserver,
			  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
			  1024, cliserver.listen_fd);

	if(!(cliserver.l)) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot create CLI listener\n");
	  socket_closesocket(cliserver.listen_fd);
	  return;
	}

	if(addr_get_from_sock(cliserver.listen_fd, &cli_addr)) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot get local socket addr\n");
	  socket_closesocket(cliserver.listen_fd);
	  return;
	}

	addr_debug_print(cliserver.verbose, &cli_addr,"CLI listener opened on ");
}

void cli_server_receive_message(struct bufferevent *bev, void *ptr)
{
	UNUSED_ARG(ptr);

	//TODO

	struct cli_message cm;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);

	while ((n = evbuffer_remove(input, &cm, sizeof(struct cli_message))) > 0) {
		if (n != sizeof(struct cli_message)) {
			fprintf(stderr,"%s: Weird CLI buffer error: size=%d\n",__FUNCTION__,n);
			continue;
		}
	}
}

///////////////////////////////
