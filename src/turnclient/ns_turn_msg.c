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

#include "ns_turn_msg.h"
#include "ns_turn_msg_addr.h"

/////////////////////////////////////////////////////////////////

static u32bits ns_crc32(const u08bits *buffer, u32bits len);

/////////////////////////////////////////////////////////////////

int stun_get_command_message_len_str(const u08bits* buf, size_t len) {
  if(!stun_is_command_message_str(buf,len)) return -1;
  return (int)(nswap16(((const u16bits*)(buf))[1])+STUN_HEADER_LENGTH);
}

static int stun_set_command_message_len_str(u08bits* buf, int len) {
  if(len<STUN_HEADER_LENGTH) return -1;
  ((u16bits*)buf)[1]=nswap16((u16bits)(len-STUN_HEADER_LENGTH));
  return 0;
}

///////////  Low-level binary //////////////////////////////////////////////

u16bits stun_make_type(u16bits method) {
  method = method & 0x0FFF;
  return ((method & 0x000F) | ((method & 0x0070)<<1) | 
	  ((method & 0x0380)<<2) | ((method & 0x0C00)<<2));
}

u16bits stun_get_method_str(const u08bits *buf, size_t len) {
  if(!buf || len<2) return (u16bits)-1;

  u16bits tt = nswap16(((const u16bits*)buf)[0]);
  
  return (tt & 0x000F) | ((tt & 0x00E0)>>1) | 
    ((tt & 0x0E00)>>2) | ((tt & 0x3000)>>2);
}

u16bits stun_get_msg_type_str(const u08bits *buf, size_t len) {
  if(!buf || len<2) return (u16bits)-1;
  return ((nswap16(((const u16bits*)buf)[0])) & 0x3FFF);
}

int is_channel_msg_str(const u08bits* buf, size_t blen) {
  return (buf && blen>=4 && STUN_VALID_CHANNEL(nswap16(((const u16bits*)buf)[0])));
}

/////////////// message types /////////////////////////////////

int stun_is_command_message_str(const u08bits* buf, size_t blen) {
  if(buf && blen>=STUN_HEADER_LENGTH) {
    if(!STUN_VALID_CHANNEL(nswap16(((const u16bits*)buf)[0]))) {
      if((((u08bits)buf[0]) & ((u08bits)(0xC0)))==0) {
	if(nswap32(((const u32bits*)(buf))[1]) == STUN_MAGIC_COOKIE) {
	  u16bits len=nswap16(((const u16bits*)(buf))[1]);
	  if((len & 0x0003) == 0) {
	    if((size_t)(len+STUN_HEADER_LENGTH) == blen) {
	      return 1;
	    }
	  }
	}
      }
    }
  }
  return 0;
}

int stun_is_command_message_full_check_str(const u08bits* buf, size_t blen, int must_check_fingerprint) {
	if(!stun_is_command_message_str(buf,blen))
		return 0;
	stun_attr_ref sar = stun_attr_get_first_by_type_str(buf, blen, STUN_ATTRIBUTE_FINGERPRINT);
	if(!sar)
		return !must_check_fingerprint;
	const u32bits* fingerprint = (const u32bits*)stun_attr_get_value(sar);
	if(!fingerprint)
		return !must_check_fingerprint;
	return (*fingerprint == nswap32(ns_crc32(buf,blen-8) ^ ((u32bits)0x5354554e)));
}

int stun_is_command_message_offset_str(const u08bits* buf, size_t blen, int offset) {
  return stun_is_command_message_str(buf + offset, blen);
}

int stun_is_request_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  return IS_STUN_REQUEST(stun_get_msg_type_str(buf,len));
}

int stun_is_success_response_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  return IS_STUN_SUCCESS_RESP(stun_get_msg_type_str(buf,len));
}

int stun_is_error_response_str(const u08bits* buf, size_t len, int *err_code, u08bits *err_msg, size_t err_msg_size) {
  if(is_channel_msg_str(buf,len)) return 0;
  if(IS_STUN_ERR_RESP(stun_get_msg_type_str(buf,len))) {
    if(err_code) {
      stun_attr_ref sar = stun_attr_get_first_by_type_str(buf, len, STUN_ATTRIBUTE_ERROR_CODE);
      if(sar) {
	if(stun_attr_get_len(sar)>=4) {
	  const u08bits* val = (const u08bits*)stun_attr_get_value(sar);
	  *err_code=(int)(val[2]*100 + val[3]);
	  if(err_msg && err_msg_size>0) {
	    err_msg[0]=0;
	    if(stun_attr_get_len(sar)>4) { 
	      size_t msg_len = stun_attr_get_len(sar) - 4;
	      if(msg_len>(err_msg_size-1))
		msg_len=err_msg_size - 1;
	      ns_bcopy(val+4, err_msg, msg_len);
	      err_msg[msg_len]=0;
	    }
	  }
	}
      }
    }
    return 1;
  }
  return 0;
}

int stun_is_response_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  if(IS_STUN_SUCCESS_RESP(stun_get_msg_type_str(buf,len))) return 1;
  if(IS_STUN_ERR_RESP(stun_get_msg_type_str(buf,len))) return 1;
  return 0;
}

int stun_is_indication_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  return IS_STUN_INDICATION(stun_get_msg_type_str(buf,len));
}

u16bits stun_make_request(u16bits method) {
  return GET_STUN_REQUEST(stun_make_type(method));
}

u16bits stun_make_indication(u16bits method) {
  return GET_STUN_INDICATION(stun_make_type(method));
}

u16bits stun_make_success_response(u16bits method) {
  return GET_STUN_SUCCESS_RESP(stun_make_type(method));
}

u16bits stun_make_error_response(u16bits method) {
  return GET_STUN_ERR_RESP(stun_make_type(method));
}

//////////////// INIT ////////////////////////////////////////////

void stun_init_buffer_str(u08bits *buf, size_t *len) {
  *len=STUN_HEADER_LENGTH;
  ns_bzero(buf,*len);
}

void stun_init_command_str(u16bits message_type, u08bits* buf, size_t *len) {
  stun_init_buffer_str(buf,len);
  message_type &= (u16bits)(0x3FFF);
  ((u16bits*)buf)[0]=nswap16(message_type);
  ((u16bits*)buf)[1]=0;
  ((u32bits*)buf)[1]=nswap32(STUN_MAGIC_COOKIE);
  stun_tid_generate_in_message_str(buf,NULL);
  {
    static const u08bits *field = (const u08bits *)"Citrix-AG";
    static const size_t fsz = 9;
    stun_attr_add_str(buf,len,STUN_ATTRIBUTE_SOFTWARE,field,fsz);
  }
}

void stun_init_request_str(u16bits method, u08bits* buf, size_t *len) {
  stun_init_command_str(stun_make_request(method), buf, len);
}

void stun_init_indication_str(u16bits method, u08bits* buf, size_t *len) {
  stun_init_command_str(stun_make_indication(method), buf, len);
}

void stun_init_success_response_str(u16bits method, u08bits* buf, size_t *len, stun_tid* id) {
  stun_init_command_str(stun_make_success_response(method), buf, len);
  if(id) {
    stun_tid_message_cpy(buf, id);
  }
}

void stun_init_error_response_str(u16bits method, u08bits* buf, size_t *len,
				u16bits error_code, const u08bits *reason,
				stun_tid* id)
{

	stun_init_command_str(stun_make_error_response(method), buf, len);

	if (!reason) {

		switch (error_code){
		case 300:
			reason = (const u08bits *) "Try Alternate";
			break;
		case 400:
			reason = (const u08bits *) "Bad Request";
			break;
		case 401:
			reason = (const u08bits *) "Unauthorized";
			break;
		case 404:
			reason = (const u08bits *) "Not Found";
			break;
		case 420:
			reason = (const u08bits *) "Unknown Attribute";
			break;
		case 438:
			reason = (const u08bits *) "Stale Nonce";
			break;
		case 500:
			reason = (const u08bits *) "Server Error";
			break;
		default:
			reason = (const u08bits *) "Unknown Error";
			break;
		};
	}

	u08bits avalue[129];
	avalue[0] = 0;
	avalue[1] = 0;
	avalue[2] = (u08bits) (error_code / 100);
	avalue[3] = (u08bits) (error_code % 100);
	strcpy((s08bits*) (avalue + 4), (const s08bits*) reason);
	int alen = 4 + strlen((const s08bits*) reason);

	stun_attr_add_str(buf, len, STUN_ATTRIBUTE_ERROR_CODE, (u08bits*) avalue, alen);
	if (id) {
		stun_tid_message_cpy(buf, id);
	}
}

int stun_init_channel_message_str(u16bits chnumber, u08bits* buf, size_t *len, int length) {
  if(length<0 || (STUN_BUFFER_SIZE<(4+length))) return -1;
  ((u16bits*)(buf))[0]=nswap16(chnumber);
  ((u16bits*)(buf))[1]=nswap16((u16bits)length);
  *len=4+length;
  return 0;
}

/////////// CHANNEL ////////////////////////////////////////////////

u08bits* stun_get_app_data_ptr_str(u08bits* buf, int *olength) {
  u16bits length=nswap16(((u16bits*)(buf))[1]);
  if(STUN_BUFFER_SIZE<(4+length)) return NULL;
  if(olength) *olength=(int)length;
  return buf+4;
}

int stun_get_channel_message_len_str(const u08bits* buf) {
  u16bits length=nswap16(((const u16bits*)buf)[1]);
  if(STUN_BUFFER_SIZE<(4+length)) return -1;
  return (4+length);
}

int stun_is_channel_message_str(const u08bits *buf, size_t blen, u16bits* chnumber) {
  if(blen<4) return 0;
  u16bits chn=nswap16(((const u16bits*)(buf))[0]);
  if(!STUN_VALID_CHANNEL(chn)) return 0;
  if((size_t)(4+(nswap16(((const u16bits*)(buf))[1])))!=blen) return 0;
  if(chnumber) *chnumber=chn;
  return 1;
}

int stun_is_specific_channel_message_str(const u08bits* buf, size_t len, u16bits chnumber) {
  if(len<4) return 0;
  if(((u08bits)(buf[0]) & 0xc0) != 0x40) return 0;
  u16bits chn=nswap16(((const u16bits*)(buf))[0]);
  if(!STUN_VALID_CHANNEL(chn)) return 0;
  if(chn!=chnumber) return 0;
  if(4+(size_t)(nswap16(((const u16bits*)(buf))[1]))!=len) return 0;
  return 1;
}

////////// ALLOCATE ///////////////////////////////////

int stun_set_allocate_request_str(u08bits* buf, size_t *len, u32bits lifetime, int address_family) {

  stun_init_request_str(STUN_METHOD_ALLOCATE, buf, len);

  //REQUESTED-TRANSPORT
  {
    u08bits field[4];
    field[0]=17;
    field[1]=0;
    field[2]=0;
    field[3]=0;
    if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_REQUESTED_TRANSPORT,field,sizeof(field))<0) return -1;
  }

  //LIFETIME
  {
    if(lifetime<1) lifetime=STUN_DEFAULT_ALLOCATE_LIFETIME;
    u32bits field=nswap32(lifetime);
    if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_LIFETIME,(u08bits*)(&field),sizeof(field))<0) return -1;
  }

  //ADRESS-FAMILY
  switch (address_family) {
  case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
  case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
  {
	  u08bits field[4];
	  field[0] = (u08bits)address_family;
	  field[1]=0;
	  field[2]=0;
	  field[3]=0;
	  if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY,field,sizeof(field))<0) return -1;
	  break;
  }
  case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT:
	  /* ignore */
	  break;
  default:
	  return -1;
  };

  return 0;
}

int stun_set_allocate_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				   const ioa_addr *relayed_addr, const ioa_addr *reflexive_addr,
				   u32bits lifetime, int error_code, const u08bits *reason,
				   u64bits reservation_token) {

  if(!error_code) {

    stun_init_success_response_str(STUN_METHOD_ALLOCATE, buf, len, tid);
    
    if(relayed_addr) {
      if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,relayed_addr)<0) return -1;
    }
    
    if(reflexive_addr) {
      if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,reflexive_addr)<0) return -1;
    }

    if(reservation_token) {
      reservation_token=nswap64(reservation_token);
      stun_attr_add_str(buf,len,STUN_ATTRIBUTE_RESERVATION_TOKEN,(u08bits*)(&reservation_token),8);
    }

    {
      if(lifetime<1) lifetime=STUN_DEFAULT_ALLOCATE_LIFETIME;
      u32bits field=nswap32(lifetime);
      if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_LIFETIME,(u08bits*)(&field),sizeof(field))<0) return -1;
    }

  } else {
    stun_init_error_response_str(STUN_METHOD_ALLOCATE, buf, len, error_code, reason, tid);
  }

  return 0;
}

/////////////// CHANNEL BIND ///////////////////////////////////////

u16bits stun_set_channel_bind_request_str(u08bits* buf, size_t *len,
					   const ioa_addr* peer_addr, u16bits channel_number) {

  if(!STUN_VALID_CHANNEL(channel_number)) {
    channel_number = 0x4000 + ((u16bits)(((u32bits)random())%(0x7FFF-0x4000+1)));
  }
  
  stun_init_request_str(STUN_METHOD_CHANNEL_BIND, buf, len);
  
  if(stun_attr_add_channel_number_str(buf, len, channel_number)<0) return 0;
  
  if(!peer_addr) {
    ioa_addr ca;
    ns_bzero(&ca,sizeof(ca));
    
    if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &ca)<0) return 0;
  } else {
    if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr)<0) return 0;
  }

  return channel_number;
}

void stun_set_channel_bind_response_str(u08bits* buf, size_t *len, stun_tid* tid, int error_code, const u08bits *reason) {
  if(!error_code) {
    stun_init_success_response_str(STUN_METHOD_CHANNEL_BIND, buf, len, tid);
  } else {
    stun_init_error_response_str(STUN_METHOD_CHANNEL_BIND, buf, len, error_code, reason, tid);
  }
}

/////////////// BINDING ///////////////////////////////////////

void stun_set_binding_request_str(u08bits* buf, size_t *len) {
  stun_init_request_str(STUN_METHOD_BINDING, buf, len);
}

int stun_set_binding_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				  const ioa_addr *reflexive_addr, int error_code, const u08bits *reason) {

  if(!error_code) {
    stun_init_success_response_str(STUN_METHOD_BINDING, buf, len, tid);
    if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,reflexive_addr)<0) return -1;
  } else {
    stun_init_error_response_str(STUN_METHOD_BINDING, buf, len, error_code, reason, tid);
  }

  return 0;
}

int stun_is_binding_request_str(const u08bits* buf, size_t len, size_t offset)
{
  if(offset < len) {
    buf += offset;
    len -= offset;
    if (stun_is_command_message_str(buf, len)) {
      if (stun_is_request_str(buf, len) && (stun_get_method_str(buf, len) == STUN_METHOD_BINDING)) {
	return 1;
      }
    }
  }
  return 0;
}

int stun_is_binding_response_str(const u08bits* buf, size_t len) {
  if(stun_is_command_message_str(buf,len) &&
     (stun_get_method_str(buf,len)==STUN_METHOD_BINDING)) {
    if(stun_is_response_str(buf,len)) {
      return 1;
    }
  }
  return 0;
}

/////////////////////////////// TID ///////////////////////////////


int stun_tid_equals(const stun_tid *id1, const stun_tid *id2) {
  if(id1==id2) return 1;
  if(!id1) return 0;
  if(!id2) return 0;
  {
    unsigned int i=0;
    for(i=0;i<sizeof(id1->tsx_id);++i) {
      if(id1->tsx_id[i]!=id2->tsx_id[i]) return 0;
    }
  }
  return 1;
}

void stun_tid_cpy(stun_tid *id1, const stun_tid *id2) {
  if(!id1) return;
  if(!id2) return;
  ns_bcopy((const void*)(id2->tsx_id),(void*)(id1->tsx_id),sizeof(id1->tsx_id));
}

static void stun_tid_string_cpy(u08bits* s, const stun_tid* id) {
  if(s && id) {
    ns_bcopy((const void*)(id->tsx_id),s,sizeof(id->tsx_id));
  }
}

static void stun_tid_from_string(const u08bits* s, stun_tid* id) {
  if(s && id) {
    ns_bcopy(s,(void*)(id->tsx_id),sizeof(id->tsx_id));
  }
}

void stun_tid_from_message_str(const u08bits* buf, size_t len, stun_tid* id) {
  if(stun_is_command_message_str(buf,len)) {
    stun_tid_from_string(buf+8, id);
  }
}

void stun_tid_message_cpy(u08bits* buf, const stun_tid* id) {
  if(buf && id) {
    stun_tid_string_cpy(buf+8, id);
  }
}

void stun_tid_generate(stun_tid* id) {
  if(id) {
    u32bits *w=(u32bits*)(id->tsx_id);
    w[0]=(u32bits)random();
    w[1]=(u32bits)random();
    w[2]=(u32bits)random();
  }
}

void stun_tid_generate_in_message_str(u08bits* buf, stun_tid* id) {
  stun_tid tmp;
  if(!id) id=&tmp;
  stun_tid_generate(id);
  stun_tid_message_cpy(buf, id);
}

/////////////////// TIME ////////////////////////////////////////////////////////

u32bits stun_adjust_allocate_lifetime(u32bits lifetime) {
  if(!lifetime) return STUN_DEFAULT_ALLOCATE_LIFETIME;
  else if(lifetime<STUN_MIN_ALLOCATE_LIFETIME) return STUN_MIN_ALLOCATE_LIFETIME;
  else if(lifetime>STUN_MAX_ALLOCATE_LIFETIME) return STUN_MAX_ALLOCATE_LIFETIME;
  return lifetime;
}

////////////// ATTR /////////////////////////////////////////////////////////////

int stun_attr_get_type(stun_attr_ref attr) {
  if(attr)
    return (int)(nswap16(((const u16bits*)attr)[0]));
  return -1;
}

int stun_attr_get_len(stun_attr_ref attr) {
  if(attr)
    return (int)(nswap16(((const u16bits*)attr)[1]));
  return -1;
}

const u08bits* stun_attr_get_value(stun_attr_ref attr) {
  if(attr) {
    int len = (int)(nswap16(((const u16bits*)attr)[1]));
    if(len<1) return NULL;
    return ((const u08bits*)attr)+4;
  }
  return NULL;
}

int stun_get_requested_address_family(stun_attr_ref attr)
{
	if (attr) {
		int len = (int) (nswap16(((const u16bits*)attr)[1]));
		if (len != 4)
			return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID;
		int val = ((const u08bits*) attr)[4];
		switch (val){
		case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
			return val;
		case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
			return val;
		default:
			return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID;
		};
	}
	return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
}

u16bits stun_attr_get_channel_number(stun_attr_ref attr) {
  if(attr) {
    const u08bits* value = stun_attr_get_value(attr);
    if(value) {
      u16bits cn=nswap16(((const u16bits*)value)[0]);
      if(STUN_VALID_CHANNEL(cn)) return cn;
    }
  }
  return 0;
}

u64bits stun_attr_get_reservation_token_value(stun_attr_ref attr)  {
  if(attr) {
    const u08bits* value = stun_attr_get_value(attr);
    if(value) {
      return nswap64(((const u64bits*)value)[0]);
    }
  }
  return 0;
}

int stun_attr_is_addr(stun_attr_ref attr) {

  if(attr) {
    switch(stun_attr_get_type(attr)) {
    case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
    case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
    case STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:
    case STUN_ATTRIBUTE_MAPPED_ADDRESS:
    case STUN_ATTRIBUTE_RESPONSE_ADDRESS:
    case STUN_ATTRIBUTE_CHANGE_ADDRESS:
    case STUN_ATTRIBUTE_SOURCE_ADDRESS:
    case STUN_ATTRIBUTE_CHANGED_ADDRESS:
      return 1;
      break;
    default:
      ;
    };
  }
  return 0;
}

u08bits stun_attr_get_even_port(stun_attr_ref attr) {
  if(attr) {
    const u08bits* value=stun_attr_get_value(attr);
    if(value) {
      if((u08bits)(value[0]) > 0x7F) return 1;
    }
  }
  return 0;
}

stun_attr_ref stun_attr_get_first_by_type_str(const u08bits* buf, size_t len, u16bits attr_type) {

  stun_attr_ref attr=stun_attr_get_first_str(buf,len);
  while(attr) {
    if(stun_attr_get_type(attr) == attr_type) {
      return attr;
    }
    attr=stun_attr_get_next_str(buf,len,attr);
  }

  return NULL;
}

stun_attr_ref stun_attr_get_first_str(const u08bits* buf, size_t len) {

  if(stun_get_command_message_len_str(buf,len)>STUN_HEADER_LENGTH) {
    return (stun_attr_ref)(buf+STUN_HEADER_LENGTH);
  }

  return NULL;
}

stun_attr_ref stun_attr_get_next_str(const u08bits* buf, size_t len, stun_attr_ref prev) {

  if(!prev) return stun_attr_get_first_str(buf,len);
  else {
    const u08bits* end = buf + stun_get_command_message_len_str(buf,len);
    int attrlen=stun_attr_get_len(prev);
    u16bits rem4 = ((u16bits)attrlen) & 0x0003;
    if(rem4) {
      attrlen = attrlen+4-(int)rem4;
    }
    const u08bits* attr_end=(const u08bits*)prev+4+attrlen;
    if(attr_end<end) return attr_end;
    return NULL;
  }
}

int stun_attr_add_str(u08bits* buf, size_t *len, u16bits attr, const u08bits* avalue, int alen) {
  if(alen<0) alen=0;
  u08bits tmp[1];
  if(!avalue) {
    alen=0;
    avalue=tmp;
  }
  int clen = stun_get_command_message_len_str(buf,*len);
  int newlen = clen + 4 + alen;
  int newlenrem4=newlen%4;
  if(newlenrem4) {
    newlen=newlen+(4-newlenrem4);
  }
  if(newlen>=STUN_BUFFER_SIZE) return -1;
  else {
    u08bits* attr_start=buf+clen;
    
    u16bits *attr_start_16t=(u16bits*)attr_start;
    
    stun_set_command_message_len_str(buf,newlen);
    *len = newlen;
    
    attr_start_16t[0]=nswap16(attr);
    attr_start_16t[1]=nswap16(alen);
    if(alen>0) ns_bcopy(avalue,attr_start+4,alen);
    return 0;
  }
}

int stun_attr_add_addr_str(u08bits *buf, size_t *len, u16bits attr_type, const ioa_addr* ca) {

  stun_tid tid;
  stun_tid_from_message_str(buf, *len, &tid);

  int xor_ed=0;
  switch(attr_type) {
  case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
  case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
  case STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:
    xor_ed=1;
    break;
  default:
    ;
  };

  u08bits cfield[64];
  int clen=0;
  if(stun_addr_encode(ca, cfield, &clen, xor_ed, STUN_MAGIC_COOKIE, tid.tsx_id)<0) {
    return -1;
  }

  if(stun_attr_add_str(buf,len,attr_type,(u08bits*)(&cfield),clen)<0) return -1;

  return 0;
}

int stun_attr_get_addr_str(const u08bits *buf, size_t len, stun_attr_ref attr, ioa_addr* ca, const ioa_addr *default_addr) {

  stun_tid tid;
  stun_tid_from_message_str(buf, len, &tid);

  ns_bzero(ca,sizeof(ioa_addr));

  int attr_type = stun_attr_get_type(attr);
  if(attr_type<0) return -1;

  int xor_ed=0;
  switch(attr_type) {
  case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
  case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
  case STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:
    xor_ed=1;
    break;
  default:
    ;
  };

  const u08bits *cfield=stun_attr_get_value(attr);
  if(!cfield) return -1;

  if(stun_addr_decode(ca, cfield, stun_attr_get_len(attr), xor_ed, STUN_MAGIC_COOKIE, tid.tsx_id)<0) {
    return -1;
  }

  if(default_addr && addr_any_no_port(ca)) {
    int port = addr_get_port(ca);
    addr_cpy(ca,default_addr);
    addr_set_port(ca,port);
  }

  return 0;
}

int stun_attr_get_first_addr_str(const u08bits *buf, size_t len, u16bits attr_type, ioa_addr* ca, const ioa_addr *default_addr) {

  stun_attr_ref attr=stun_attr_get_first_str(buf,len);

  while(attr) {
    if(stun_attr_is_addr(attr) && (attr_type == stun_attr_get_type(attr))) {
      if(stun_attr_get_addr_str(buf,len,attr,ca,default_addr)==0) {
	return 0;
      }
    }
    attr=stun_attr_get_next_str(buf,len,attr);
  }

  return -1;
}

int stun_attr_add_channel_number_str(u08bits* buf, size_t *len, u16bits chnumber) {

  u16bits field[2];
  field[0]=nswap16(chnumber);
  field[1]=0;
  
  return stun_attr_add_str(buf,len,STUN_ATTRIBUTE_CHANNEL_NUMBER,(u08bits*)(field),sizeof(field));
}

u16bits stun_attr_get_first_channel_number_str(const u08bits *buf, size_t len) {

  stun_attr_ref attr=stun_attr_get_first_str(buf,len);
  while(attr) {
    if(stun_attr_get_type(attr) == STUN_ATTRIBUTE_CHANNEL_NUMBER) {
      u16bits ret = stun_attr_get_channel_number(attr);
      if(STUN_VALID_CHANNEL(ret)) {
	return ret;
      }
    }
    attr=stun_attr_get_next_str(buf,len,attr);
  }

  return 0;
}

////////////// FINGERPRINT ////////////////////////////

int stun_attr_add_fingerprint_str(u08bits *buf, size_t *len)
{
	u32bits crc32 = 0;
	stun_attr_add_str(buf, len, STUN_ATTRIBUTE_FINGERPRINT, (u08bits*)&crc32, 4);
	crc32 = ns_crc32(buf,*len-8);
	*((u32bits*)(buf+*len-4)) = nswap32(crc32 ^ ((u32bits)0x5354554e));
	return 0;
}
////////////// CRC ///////////////////////////////////////////////

#define CRC_MASK    0xFFFFFFFFUL

#define UPDATE_CRC(crc, c)  crc = crctable[(u08bits)crc ^ (u08bits)(c)] ^ (crc >> 8)

static const u32bits crctable[256] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
  0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
  0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
  0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
  0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
  0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
  0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
  0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
  0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
  0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
  0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
  0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
  0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
  0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
  0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
  0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
  0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
  0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
  0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
  0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
  0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
  0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
  0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
  0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
  0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
  0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
  0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
  0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
  0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
  0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
  0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
  0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
  0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
  0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
  0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
  0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
  0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
  0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
  0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
  0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

/*

#define CRCPOLY     0xEDB88320UL
reversed 0x04C11DB7
1110 1101 1001 1000 1000 0011 0010 0000

static void make_crctable(void)
{
	uint i, j;
	u32bits r;

	for (i = 0; i < 256; ++i) {
		r = i;
		for (j = 8; j > 0; --j) {
			if (r & 1)
				r = (r >> 1) ^ CRCPOLY;
			else
				r >>= 1;
		}
		crctable[i] = r;
	}
}
*/

static u32bits ns_crc32(const u08bits *buffer, u32bits len)
{
	u32bits crc = CRC_MASK;
	while ( len-- ) UPDATE_CRC( crc, *buffer++ );
	return (~crc);
}

///////////////////////////////////////////////////////
