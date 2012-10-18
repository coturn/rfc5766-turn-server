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

/*
 * IO Abstraction library
 */

#ifndef __IOA_LIB__
#define __IOA_LIB__

#include "ns_turn_ioaddr.h"

enum _SOCKET_TYPE {
	UDP_SOCKET,
	TCP_SOCKET
};

#define IOA_EV_TIMEOUT	0x01
#define IOA_EV_READ	0x02
#define IOA_EV_WRITE	0x04
#define IOA_EV_SIGNAL	0x08
#define IOA_EV_CLOSE	0x10

typedef enum _SOCKET_TYPE SOCKET_TYPE;

struct _ioa_socket;
typedef struct _ioa_socket ioa_socket;
typedef ioa_socket *ioa_socket_handle;

struct _ioa_engine;
typedef struct _ioa_engine ioa_engine;
typedef ioa_engine *ioa_engine_handle;

typedef void *ioa_timer_handle;

/* event data for net event */
typedef struct _ioa_net_data {
	ioa_addr	*remote_addr;
	s08bits		*buffer;
	int		 len;
	u16bits		 chnum;
} ioa_net_data;

/*
 * Network event handler callback
 * chnum parameter is just an optimisation hint -
 * the function must work correctly when chnum=0
 * (when no hint information is available).
 */
typedef void (*ioa_net_event_handler)(ioa_socket_handle s, int event_type, ioa_net_data *data, void *ctx);

/*
 * New connection callback
 */
typedef int (*ioa_engine_new_connection_event_handler)(ioa_engine_handle e, ioa_socket_handle s, u08bits *buf, int len);

/*
 * Timer callback
 */
typedef void (*ioa_timer_event_handler)(ioa_engine_handle e, void *ctx);

/* timers */

ioa_timer_handle set_ioa_timer(ioa_engine_handle e, int secs, int ms, ioa_timer_event_handler cb, void *ctx, int persist, const s08bits *txt);
void stop_ioa_timer(ioa_timer_handle th);
void delete_ioa_timer(ioa_timer_handle th);
#define IOA_EVENT_DEL(E) do { if(E) { delete_ioa_timer(E); E = NULL; } } while(0)

/* RTP socket handling */
/*
 * event_port == -1: no rtcp;
 * event_port == 0: reserve rtcp;
 * even_port == +1: reserve and bind rtcp.
 */
int create_relay_ioa_sockets(ioa_engine_handle e, int even_port, ioa_socket_handle *rtp_s, ioa_socket_handle *rtcp_s, u64bits *out_reservation_token);
int get_ioa_socket_from_reservation(ioa_engine_handle e, u64bits in_reservation_token, u32bits lifetime, ioa_socket_handle *s);

ioa_addr* get_local_addr_from_ioa_socket(ioa_socket_handle s);
ioa_addr* get_remote_addr_from_ioa_socket(ioa_socket_handle s);
void *get_ioa_socket_session(ioa_socket_handle s);
void set_ioa_socket_session(ioa_socket_handle s, void *ss);
int register_callback_on_ioa_socket(ioa_engine_handle e, ioa_socket_handle s, int event_type, ioa_net_event_handler cb, void *ctx);
int send_data_from_ioa_socket(ioa_socket_handle s, ioa_addr* dest_addr, const s08bits* buffer, int len, int to_peer, void *socket_channel);
void close_ioa_socket(ioa_socket_handle s);
#define IOA_CLOSE_SOCKET(S) do { if(S) { close_ioa_socket(S); S = NULL; } } while(0)
int set_df_on_ioa_socket(ioa_socket_handle s, int value);
int ioa_socket_tobeclosed(ioa_socket_handle s);

void* create_ioa_socket_channel(ioa_socket_handle s, ioa_addr* peer_addr, u16bits chnum);
void refresh_ioa_socket_channel(void *socket_channel);
void delete_ioa_socket_channel(void *socket_channel);

#endif /* __IOA_LIB__ */
