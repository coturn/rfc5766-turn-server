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

#ifndef __UCLIENT_ECHO__
#define __UCLIENT_ECHO__

#include "ns_turn_utils.h"
#include "stun_buffer.h"
#include "session.h"

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////

extern int clmessage_length;
extern int use_send_method;
extern int clnet_verbose;
extern int use_tcp;
extern int use_secure;
extern char cert_file[1025];
extern char pkey_file[1025];
extern int hang_on;
extern int c2c;
extern ioa_addr peer_addr;
extern int no_rtcp;
extern int default_address_family;
extern int dont_fragment;
extern u08bits g_uname[STUN_MAX_USERNAME_SIZE+1];
extern u08bits g_upwd[STUN_MAX_PWD_SIZE+1];
extern int use_fingerprints;
extern SSL_CTX *root_tls_ctx;

void start_mclient(const char *remote_address, int port,
		   const unsigned char* ifname, const char *local_address,
		   int messagenumber, int mclient);

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer* message);
int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer* message);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__UCLIENT_ECHO__

