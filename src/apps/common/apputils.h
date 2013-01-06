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

#ifndef __APP_LIB__
#define __APP_LIB__

#include <event2/event.h>

#include <openssl/ssl.h>

#include "ns_turn_ioaddr.h"

//////////// Common defines ///////////////////////////

#define PEER_DEFAULT_PORT (DEFAULT_STUN_PORT+1)

#define DTLS_MAX_RECV_TIMEOUT (5)
#define DTLS_MAX_CONNECT_TIMEOUT (5)

#define UR_CLIENT_SOCK_BUF_SIZE (65536)
#define UR_SERVER_SOCK_BUF_SIZE (UR_CLIENT_SOCK_BUF_SIZE*2)

//////////////////////////////////////////

#define EVENT_DEL(ev) if(ev) { event_del(ev); event_free(ev); ev=NULL; }

//////////////////////////////////////////

#define ioa_socket_raw int

///////////////////////// Sockets ///////////////////////////////

int set_sock_buf_size(evutil_socket_t fd, int sz);
int socket_set_reusable(evutil_socket_t fd);
int sock_bind_to_device(evutil_socket_t fd, const unsigned char* ifname);

int addr_connect(evutil_socket_t fd, const ioa_addr* addr);
int addr_bind(evutil_socket_t fd, const ioa_addr* addr);
int addr_get_from_sock(evutil_socket_t fd, ioa_addr *addr);

int handle_socket_error(void);

///////////////////////// MTU //////////////////////////

#define MAX_MTU (1500 - 20 - 8)
#define MIN_MTU (576 - 20 - 8)
#define SOSO_MTU (1300)

#define MTU_STEP (68)

int set_socket_df(evutil_socket_t fd, int family, int value);
int set_mtu_df(SSL* ssl, evutil_socket_t fd, int family, int mtu, int verbose);
int decrease_mtu(SSL* ssl, int mtu, int verbose);

////////////////// File search ////////////////////////

char* find_config_file(const char *config_file, int print_file_name);
void set_execdir(const char *dir);

///////////////////////////////////////////////////////

#endif //__APP_LIB__
