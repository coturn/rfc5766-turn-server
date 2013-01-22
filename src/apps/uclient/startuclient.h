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

#ifndef __STARTCLIENT_TURN__
#define __STARTCLIENT_TURN__

#include "ns_turn_utils.h"
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

/////////////////////////////////////////////////////////

int start_c2c_connection(uint16_t clnet_remote_port,
			 const char *remote_address, 
			 const unsigned char* ifname, const char *local_address,
			 int verbose,
			 app_ur_conn_info *clnet_info1,
			 uint16_t *chn1,
			 app_ur_conn_info *clnet_info1_rtcp,
			 uint16_t *chn1_rtcp,
			 app_ur_conn_info *clnet_info2,
			 uint16_t *chn2,
			 app_ur_conn_info *clnet_info2_rtcp,
			 uint16_t *chn2_rtcp);

int start_connection(uint16_t clnet_remote_port,
		     const char *remote_address, 
		     const unsigned char* ifname, const char *local_address,
		     int verbose,
		     app_ur_conn_info *clnet_info,
		     uint16_t *chn,
		     app_ur_conn_info *clnet_info_rtcp,
		     uint16_t *chn_rtcp);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__STARTCLIENT_TURN__

