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

#ifdef __cplusplus
extern "C" {
#endif

////////////// Mutexes /////////////////////

struct _turn_mutex {
  u32bits data;
  void* mutex;
};

typedef struct _turn_mutex turn_mutex;

int turn_mutex_init(turn_mutex* mutex);
int turn_mutex_init_recursive(turn_mutex* mutex);

int turn_mutex_lock(const turn_mutex *mutex);
int turn_mutex_unlock(const turn_mutex *mutex);

int turn_mutex_destroy(turn_mutex* mutex);

#define TURN_MUTEX_DECLARE(mutex) turn_mutex mutex;
#define TURN_MUTEX_INIT(mutex) turn_mutex_init(mutex)
#define TURN_MUTEX_INIT_RECURSIVE(mutex) turn_mutex_init_recursive(mutex)
#define TURN_MUTEX_LOCK(mutex) turn_mutex_lock(mutex)
#define TURN_MUTEX_UNLOCK(mutex) turn_mutex_unlock(mutex)
#define TURN_MUTEX_DESTROY(mutex) turn_mutex_destroy(mutex)

/////// Sockets //////////////////////////////

#define IOA_EV_TIMEOUT	0x01
#define IOA_EV_READ	0x02
#define IOA_EV_WRITE	0x04
#define IOA_EV_SIGNAL	0x08
#define IOA_EV_CLOSE	0x10

enum _SOCKET_TYPE {
	UNKNOWN_SOCKET=0,
	TCP_SOCKET=6,
	UDP_SOCKET=17,
	TLS_SOCKET=56,
	DTLS_SOCKET=250,
	TENTATIVE_TCP_SOCKET=255
};

typedef enum _SOCKET_TYPE SOCKET_TYPE;

enum _SOCKET_APP_TYPE {
	UNKNOWN_APP_SOCKET,
	CLIENT_SOCKET,
	RELAY_SOCKET,
	RELAY_RTCP_SOCKET,
	CHANNEL_SOCKET,
	TCP_CLIENT_DATA_SOCKET,
	TCP_RELAY_DATA_SOCKET
};

typedef enum _SOCKET_APP_TYPE SOCKET_APP_TYPE;

struct _ioa_socket;
typedef struct _ioa_socket ioa_socket;
typedef ioa_socket *ioa_socket_handle;

struct _ioa_engine;
typedef struct _ioa_engine ioa_engine;
typedef ioa_engine *ioa_engine_handle;

typedef void *ioa_timer_handle;

typedef void *ioa_network_buffer_handle;

/* event data for net event */
typedef struct _ioa_net_data {
	ioa_addr			src_addr;
	ioa_network_buffer_handle	nbh;
	u16bits				chnum;
	int				recv_ttl;
	int				recv_tos;
} ioa_net_data;

/* Callback on TCP connection completion */
typedef void (*connect_cb)(int success, void *arg);
/* Callback on accepted socket from TCP relay endpoint */
typedef void (*accept_cb)(ioa_socket_handle s, void *arg);

/*
 * Network buffer functions
 */
ioa_network_buffer_handle ioa_network_buffer_allocate(ioa_engine_handle e);
void ioa_network_buffer_header_init(ioa_network_buffer_handle nbh);
u08bits *ioa_network_buffer_data(ioa_network_buffer_handle nbh);
size_t ioa_network_buffer_get_size(ioa_network_buffer_handle nbh);
size_t ioa_network_buffer_get_capacity(void);
void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len);
void ioa_network_buffer_delete(ioa_engine_handle e, ioa_network_buffer_handle nbh);

/*
 * Status reporting functions
 */
void turn_report_allocation_set(void *a, turn_time_t lifetime, int refresh);
void turn_report_allocation_delete(void *a);
void turn_report_session_usage(void *session);
void turn_report_allocation_delete_all(void);

/*
 * Network event handler callback
 * chnum parameter is just an optimisation hint -
 * the function must work correctly when chnum=0
 * (when no hint information is available).
 */
typedef void (*ioa_net_event_handler)(ioa_socket_handle s, int event_type, ioa_net_data *data, void *ctx);

/*
 * Timer callback
 */
typedef void (*ioa_timer_event_handler)(ioa_engine_handle e, void *ctx);

/* timers */

ioa_timer_handle set_ioa_timer(ioa_engine_handle e, int secs, int ms, ioa_timer_event_handler cb, void *ctx, int persist, const s08bits *txt);
void stop_ioa_timer(ioa_timer_handle th);
void delete_ioa_timer(ioa_timer_handle th);
#define IOA_EVENT_DEL(E) do { if(E) { delete_ioa_timer(E); E = NULL; } } while(0)

ioa_socket_handle create_unbound_ioa_socket(ioa_engine_handle e, int family, SOCKET_TYPE st, SOCKET_APP_TYPE sat);

void inc_ioa_socket_ref_counter(ioa_socket_handle s);

/* Relay socket handling */
/*
 * event_port == -1: no rtcp;
 * event_port == 0: reserve rtcp;
 * even_port == +1: reserve and bind rtcp.
 */
int create_relay_ioa_sockets(ioa_engine_handle e, int address_family, u08bits transport,
				int even_port, ioa_socket_handle *rtp_s, ioa_socket_handle *rtcp_s,
				u64bits *out_reservation_token, int *err_code, const u08bits **reason,
				accept_cb acb, void *acbarg);

ioa_socket_handle  ioa_create_connecting_tcp_relay_socket(ioa_socket_handle s, ioa_addr *peer_addr, connect_cb cb, void *arg);

int get_ioa_socket_from_reservation(ioa_engine_handle e, u64bits in_reservation_token, ioa_socket_handle *s);

int get_ioa_socket_address_family(ioa_socket_handle s);
SOCKET_TYPE get_ioa_socket_type(ioa_socket_handle s);
SOCKET_APP_TYPE get_ioa_socket_app_type(ioa_socket_handle s);
void set_ioa_socket_app_type(ioa_socket_handle s, SOCKET_APP_TYPE sat);
ioa_addr* get_local_addr_from_ioa_socket(ioa_socket_handle s);
ioa_addr* get_remote_addr_from_ioa_socket(ioa_socket_handle s);
int get_local_mtu_ioa_socket(ioa_socket_handle s);
void *get_ioa_socket_session(ioa_socket_handle s);
void set_ioa_socket_session(ioa_socket_handle s, void *ss);
void clear_ioa_socket_session_if(ioa_socket_handle s, void *ss);
void *get_ioa_socket_sub_session(ioa_socket_handle s);
void set_ioa_socket_sub_session(ioa_socket_handle s, void *tc);
int register_callback_on_ioa_socket(ioa_engine_handle e, ioa_socket_handle s, int event_type, ioa_net_event_handler cb, void *ctx, int clean_preexisting);
int send_data_from_ioa_socket_nbh(ioa_socket_handle s, ioa_addr* dest_addr, ioa_network_buffer_handle nbh, int to_peer, void *socket_channel, int ttl, int tos);
void close_ioa_socket(ioa_socket_handle s);
#define IOA_CLOSE_SOCKET(S) do { if(S) { close_ioa_socket(S); S = NULL; } } while(0)
int set_df_on_ioa_socket(ioa_socket_handle s, int value);
void set_do_not_use_df(ioa_socket_handle s);
int ioa_socket_tobeclosed(ioa_socket_handle s);
void set_ioa_socket_tobeclosed(ioa_socket_handle s);

void* create_ioa_socket_channel(ioa_socket_handle s, void *channel_info);
void refresh_ioa_socket_channel(void *socket_channel);
void delete_ioa_socket_channel(void **socket_channel);

///////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif /* __IOA_LIB__ */
