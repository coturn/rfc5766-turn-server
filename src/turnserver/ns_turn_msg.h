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

#ifndef __LIB_TURN_MSG__
#define __LIB_TURN_MSG__

#include "ns_turn_ioaddr.h"

#define STUN_BUFFER_SIZE (65536)

#define DEFAULT_STUN_PORT (3478)

#if BYTE_ORDER == LITTLE_ENDIAN
#define DEFAULT_STUN_PORT_NBO (0x960D)
#elif BYTE_ORDER == BIG_ENDIAN
#define DEFAULT_STUN_PORT_NBO (0x0D96)
#else
#error WRONG BYTE_ORDER SETTING
#endif

#define STUN_HEADER_LENGTH (20)
#define STUN_CHANNEL_HEADER_LENGTH (4)

#define STUN_MAGIC_COOKIE (0x2112A442)

#define IS_STUN_REQUEST(msg_type)       (((msg_type) & 0x0110) == 0x0000)
#define IS_STUN_INDICATION(msg_type)    (((msg_type) & 0x0110) == 0x0010)
#define IS_STUN_SUCCESS_RESP(msg_type)  (((msg_type) & 0x0110) == 0x0100)
#define IS_STUN_ERR_RESP(msg_type)      (((msg_type) & 0x0110) == 0x0110)

#define GET_STUN_REQUEST(msg_type)      (msg_type & 0xFEEF)
#define GET_STUN_INDICATION(msg_type)   ((msg_type & 0xFEEF)|0x0010)
#define GET_STUN_SUCCESS_RESP(msg_type)  ((msg_type & 0xFEEF)|0x0100)
#define GET_STUN_ERR_RESP(msg_type)      (msg_type | 0x0110)

#define STUN_DEFAULT_ALLOCATE_LIFETIME (600)
#define STUN_MIN_ALLOCATE_LIFETIME STUN_DEFAULT_ALLOCATE_LIFETIME
#define STUN_MAX_ALLOCATE_LIFETIME (3600)
#define STUN_CHANNEL_LIFETIME (600)
#define STUN_PERMISSION_LIFETIME (300)

#define STUN_METHOD_BINDING (0x001)
#define STUN_METHOD_ALLOCATE (0x003)
#define STUN_METHOD_REFRESH (0x004)
#define STUN_METHOD_SEND (0x006)
#define STUN_METHOD_DATA (0x007)
#define STUN_METHOD_CREATE_PERMISSION (0x008)
#define STUN_METHOD_CHANNEL_BIND (0x009)

#define STUN_ATTRIBUTE_MAPPED_ADDRESS (0x0001)
#define STUN_ATTRIBUTE_RESPONSE_ADDRESS (0x0002)
#define STUN_ATTRIBUTE_CHANGE_ADDRESS (0x0003)
#define STUN_ATTRIBUTE_SOURCE_ADDRESS (0x0004)
#define STUN_ATTRIBUTE_CHANGED_ADDRESS (0x0005)
#define STUN_ATTRIBUTE_USERNAME (0x0006)
#define STUN_ATTRIBUTE_PASSWORD (0x0007)
#define STUN_ATTRIBUTE_MESSAGE_INTEGRITY (0x0008)
#define STUN_ATTRIBUTE_ERROR_CODE (0x0009)
#define STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES (0x000A)
#define STUN_ATTRIBUTE_REFLECTED_FROM (0x000B)
#define STUN_ATTRIBUTE_REALM (0x0014)
#define STUN_ATTRIBUTE_NONCE (0x0015)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY (0x0017)
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS (0x0020)

#define STUN_ATTRIBUTE_SOFTWARE (0x8022)
#define STUN_ATTRIBUTE_ALTERNATE_SERVER (0x8023)
#define STUN_ATTRIBUTE_FINGERPRINT (0x8028)

#define STUN_ATTRIBUTE_CHANNEL_NUMBER (0x000C)
#define STUN_ATTRIBUTE_LIFETIME (0x000D)
#define STUN_ATTRIBUTE_BANDWIDTH (0x0010)
#define STUN_ATTRIBUTE_XOR_PEER_ADDRESS (0x0012)
#define STUN_ATTRIBUTE_DATA (0x0013)
#define STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS (0x0016)
#define STUN_ATTRIBUTE_EVEN_PORT (0x0018)
#define STUN_ATTRIBUTE_REQUESTED_TRANSPORT (0x0019)
#define STUN_ATTRIBUTE_DONT_FRAGMENT (0x001A)
#define STUN_ATTRIBUTE_TIMER_VAL (0x0021)
#define STUN_ATTRIBUTE_RESERVATION_TOKEN (0x0022)

#define STUN_VALID_CHANNEL(chn) ((chn)>=0x4000 && (chn)<=0x7FFF)

///////// values //////////////////

#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 (0x01)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6 (0x02)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT (0x00)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID (-1)

///////////////////////////////////

typedef struct {
  uint8_t tsx_id[12];
} stun_tid;

///////////////////////////////////

typedef const void* stun_attr_ref;

//////////////////////////////////////////////////////////////

int stun_tid_equals(const stun_tid *id1, const stun_tid *id2);
void stun_tid_cpy(stun_tid *id1, const stun_tid *id2);
void stun_tid_generate(stun_tid* id);

///////////////////////////////////////////////////////////////

u16bits stun_make_type(u16bits method);
u16bits stun_make_request(u16bits method);
u16bits stun_make_indication(u16bits method);
u16bits stun_make_success_response(u16bits method);
u16bits stun_make_error_response(u16bits method);

///////////////////////////////////////////////////////////////

u32bits stun_adjust_allocate_lifetime(u32bits lifetime);

///////////// STR ////////////////////////////////////////////////

void stun_init_buffer_str(u08bits *buf, size_t *len);
void stun_init_command_str(u16bits message_type, u08bits* buf, size_t *len);
void stun_init_request_str(u16bits method, u08bits* buf, size_t *len);
void stun_init_indication_str(u16bits method, u08bits* buf, size_t *len);
void stun_init_success_response_str(u16bits method, u08bits* buf, size_t *len, stun_tid* id);
void stun_init_error_response_str(u16bits method, u08bits* buf, size_t *len, u16bits error_code, const u08bits *reason, stun_tid* id);
int stun_init_channel_message_str(u16bits chnumber, u08bits* buf, size_t *len, int length);

u08bits* stun_get_app_data_ptr_str(u08bits* buf, int *olength);

int stun_is_command_message_str(const u08bits* buf, size_t blen);
int stun_is_command_message_offset_str(const u08bits* buf, size_t blen, int offset);
int stun_is_request_str(const u08bits* buf, size_t len);
int stun_is_success_response_str(const u08bits* buf, size_t len);
int stun_is_error_response_str(const u08bits* buf, size_t len, int *err_code, u08bits *err_msg, size_t err_msg_size);
int stun_is_response_str(const u08bits* buf, size_t len);
int stun_is_indication_str(const u08bits* buf, size_t len);
u16bits stun_get_method_str(const u08bits *buf, size_t len);
u16bits stun_get_msg_type_str(const u08bits *buf, size_t len);
int stun_is_channel_message_str(const u08bits *buf, size_t len, u16bits* chnumber);
int is_channel_msg_str(const u08bits* buf, size_t blen);

void stun_set_binding_request_str(u08bits* buf, size_t *len);
int stun_set_binding_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				  const ioa_addr *reflexive_addr, int error_code, const u08bits *reason);
int stun_is_binding_request_str(const u08bits* buf, size_t len, size_t offset);
int stun_is_binding_response_str(const u08bits* buf, size_t len);

void stun_tid_from_message_str(const u08bits* buf, size_t len, stun_tid* id);
void stun_tid_message_cpy(u08bits *buf, const stun_tid* id);
void stun_tid_generate_in_message_str(u08bits* buf, stun_tid* id);

int stun_get_command_message_len_str(const u08bits* buf, size_t len);

int stun_attr_is_addr(stun_attr_ref attr);
int stun_attr_get_type(stun_attr_ref attr);
int stun_attr_get_len(stun_attr_ref attr);
const u08bits* stun_attr_get_value(stun_attr_ref attr);
u16bits stun_attr_get_channel_number(stun_attr_ref attr);
uint8_t stun_attr_get_even_port(stun_attr_ref attr);
u64bits stun_attr_get_reservation_token_value(stun_attr_ref attr);
stun_attr_ref stun_attr_get_first_by_type_str(const u08bits* buf, size_t len, u16bits attr_type);
stun_attr_ref stun_attr_get_first_str(const u08bits* buf, size_t len);
stun_attr_ref stun_attr_get_next_str(const u08bits* buf, size_t len, stun_attr_ref prev);
int stun_attr_add_str(u08bits* buf, size_t *len, u16bits attr, const u08bits* avalue, int alen);
int stun_attr_add_addr_str(u08bits *buf, size_t *len, u16bits attr_type, const ioa_addr* ca);
int stun_attr_get_addr_str(const u08bits *buf, size_t len, stun_attr_ref attr, ioa_addr* ca, const ioa_addr *default_addr);
int stun_attr_get_first_addr_str(const u08bits *buf, size_t len, u16bits attr_type, ioa_addr* ca, const ioa_addr *default_addr);
int stun_attr_add_channel_number_str(u08bits* buf, size_t *len, u16bits chnumber);
u16bits stun_attr_get_first_channel_number_str(const u08bits *buf, size_t len);

int stun_get_channel_message_len_str(const u08bits* buf);
int stun_is_specific_channel_message_str(const u08bits* buf, size_t len, u16bits chnumber);

int stun_set_allocate_request_str(u08bits* buf, size_t *len, u32bits lifetime, int address_family);
int stun_set_allocate_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				   const ioa_addr *relayed_addr,
				   const ioa_addr *reflexive_addr,
				   u32bits lifetime, int error_code, const u08bits *reason,
				   u64bits reservation_token);

u16bits stun_set_channel_bind_request_str(u08bits* buf, size_t *len,
					  const ioa_addr* peer_addr, u16bits channel_number);
void stun_set_channel_bind_response_str(u08bits* buf, size_t *len, stun_tid* tid, int error_code, const u08bits *reason);

int stun_get_requested_address_family(stun_attr_ref attr);

///////////////////////////////////////////////////////////////

#endif //__LIB_TURN_MSG__
