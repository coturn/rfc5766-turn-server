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
#include <stdarg.h>

#if !defined(TURN_NO_HIREDIS)

#include "hiredis_libevent2.h"
#include "ns_turn_utils.h"

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

//////////////// Libevent context ///////////////////////

struct redisLibeventEvents
{
	redisAsyncContext *context;
	int allocated;
	struct event_base *base;
	struct event *rev, *wev;
	int rev_set, wev_set;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
};

static redisAsyncContext *defaultAsyncContext = NULL;

///////////// Messages ////////////////////////////

struct redis_message
{
	char format[513];
	char arg[513];
};

/////////////////// Callbacks ////////////////////////////


static void redisLibeventReadEvent(int fd, short event, void *arg) {
  ((void)fd); ((void)event);
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)arg;
  if(e) {
    redisAsyncHandleRead(e->context);
  }
}

static void redisLibeventWriteEvent(int fd, short event, void *arg) {
  ((void)fd); ((void)event);
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)arg;
  if(e) {
    redisAsyncHandleWrite(e->context);
  }
}

static void redisLibeventAddRead(void *privdata) {
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
  if(e && (e->rev)) {
    event_add(e->rev,NULL);
    e->rev_set = 1;
  }
}

static void redisLibeventDelRead(void *privdata) {
    struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
    if(e && e->rev) {
      event_del(e->rev);
      e->rev_set = 0;
    }
}

static void redisLibeventAddWrite(void *privdata) {
    struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
    if(e && (e->wev)) {
      event_add(e->wev,NULL);
      e->wev_set = 1;
    }
}

static void redisLibeventDelWrite(void *privdata) {
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
  if(e && e->wev) {
    event_del(e->wev);
    e->wev_set = 0;
  }
}

static void redisLibeventCleanup(void *privdata)
{

	if (privdata) {

		struct redisLibeventEvents *e = (struct redisLibeventEvents *) privdata;
		if (e->allocated) {
			e->allocated = 0;
			if (e->rev) {
				if(e->rev_set)
					event_del(e->rev);
				event_free(e->rev);
				e->rev = NULL;
			}
			if (e->wev) {
				if(e->wev_set)
					event_del(e->wev);
				event_free(e->wev);
				e->wev = NULL;
			}
			turn_free(privdata, sizeof(struct redisLibeventEvents));
		}
	}
}

///////////////////////// Send-receive ///////////////////////////

static void send_message_for_redis(redisAsyncContext *ac, const struct redis_message *rm)
{

	if(!ac)
		return;

	struct redisLibeventEvents *e = (struct redisLibeventEvents *)(ac->ev.data);

	if(e && rm) {
		struct evbuffer *output = bufferevent_get_output(e->out_buf);
		if(evbuffer_add(output,rm,sizeof(*rm))<0) {
			fprintf(stderr,"%s: Weird buffer error\n",__FUNCTION__);
		}
	}
}

static void receive_message_for_redis(struct bufferevent *bev, void *ptr)
{
	if(!ptr)
		return;

	struct redisLibeventEvents *e = (struct redisLibeventEvents*)ptr;
	redisAsyncContext *ac = e->context;

	struct redis_message rm;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	while ((n = evbuffer_remove(input, &rm, sizeof(rm))) > 0) {
		if (n != sizeof(rm)) {
			fprintf(stderr,"%s: Weird buffer error: size=%d\n",__FUNCTION__,n);
			continue;
		}

		if(ac) {
			redisAsyncCommand(ac, NULL, e, rm.format, rm.arg);
		}
	}
}

void send_message_to_redis(redis_context_handle rch, const char *command, const char *key, const char *format,...)
{
	redisAsyncContext *ac=(redisAsyncContext *)rch;
	if(!ac)
		ac = defaultAsyncContext;

	if(ac) {
		struct redis_message rm;

		snprintf(rm.format,sizeof(rm.format)-3,"%s %s ", command, key);
		strcpy(rm.format+strlen(rm.format),"%s");

		va_list args;
		va_start (args, format);
		vsnprintf(rm.arg, sizeof(rm.arg)-1, format, args);
		va_end (args);

		send_message_for_redis(ac, &rm);
	}
}

static void deleteKeysCallback(redisAsyncContext *c, void *reply0, void *privdata)
{
	redisReply *reply = (redisReply*) reply0;

	if (reply) {

		if (reply->type == REDIS_REPLY_ERROR)
			printf("Error: %s\n", reply->str);
		else if (reply->type != REDIS_REPLY_ARRAY)
			printf("Unexpected type: %d\n", reply->type);
		else {
			size_t i;
			for (i = 0; i < reply->elements; ++i) {
				redisAsyncCommand(c, NULL, privdata, "del %s", reply->element[i]->str);
			}
		}
	}
}

void delete_redis_keys(const char *key_pattern)
{
	redisAsyncContext *ac = defaultAsyncContext;
	if(ac) {
		redisAsyncCommand(ac, deleteKeysCallback, ac->ev.data, "keys %s", key_pattern);
	}
}

void set_default_async_context(redis_context_handle rch)
{
	defaultAsyncContext = (redisAsyncContext*)rch;
}

int default_async_context_is_not_empty(void)
{
	return (defaultAsyncContext != NULL);
}

///////////////////////// Attach /////////////////////////////////

redis_context_handle redisLibeventAttach(struct event_base *base, char *ip0, int port0, char *pwd, int db)
{

  struct redisLibeventEvents *e = NULL;
  redisAsyncContext *ac = NULL;

  char ip[256];
  if(ip0 && ip0[0])
	  STRCPY(ip,ip0);
  else
	  STRCPY(ip,"127.0.0.1");

  int port = DEFAULT_REDIS_PORT;
  if(port0>0)
	  port=port0;
  
  ac = redisAsyncConnect(ip, port);
  if (ac->err) {
  	fprintf(stderr,"Error: %s\n", ac->errstr);
  	return NULL;
  }

  /* Create container for context and r/w events */
  e = (struct redisLibeventEvents*)turn_malloc(sizeof(struct redisLibeventEvents));
  ns_bzero(e,sizeof(struct redisLibeventEvents));

  e->allocated = 1;
  e->context = ac;
  e->base = base;

  /* Register functions to start/stop listening for events */
  ac->ev.addRead = redisLibeventAddRead;
  ac->ev.delRead = redisLibeventDelRead;
  ac->ev.addWrite = redisLibeventAddWrite;
  ac->ev.delWrite = redisLibeventDelWrite;
  ac->ev.cleanup = redisLibeventCleanup;

  ac->ev.data = e;

  /* Initialize and install read/write events */
  e->rev = event_new(e->base,e->context->c.fd,
  		     EV_READ,redisLibeventReadEvent,
  		     e);

  e->wev = event_new(e->base,e->context->c.fd,
		     EV_WRITE,redisLibeventWriteEvent,
  		     e);

  if (e->rev == NULL || e->wev == NULL) {
	  turn_free(e, sizeof(struct redisLibeventEvents));
	  return NULL;
  }
  
  event_add(e->wev, NULL);
  e->wev_set = 1;

  struct bufferevent *pair[2];
  int opts = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS;

  opts |= BEV_OPT_THREADSAFE;

  bufferevent_pair_new(base, opts, pair);
  e->in_buf = pair[0];
  e->out_buf = pair[1];
  bufferevent_setcb(e->in_buf, receive_message_for_redis, NULL, NULL, e);
  bufferevent_enable(e->in_buf, EV_READ);

  //Authentication
  if(pwd)
	  redisAsyncCommand(ac, NULL, e, "AUTH %s", pwd);

  if(db>0)
	  redisAsyncCommand(ac, NULL, e, "SELECT %d", db);

  return ac;
}

/////////////////////////////////////////////////////////

#endif
/* TURN_NO_HIREDIS */

