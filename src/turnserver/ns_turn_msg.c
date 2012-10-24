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
  ioa_addr ca_real;
  ioa_addr_map_to_real(ca,&ca_real);
  if(stun_addr_encode(&ca_real, cfield, &clen, xor_ed, STUN_MAGIC_COOKIE, tid.tsx_id)<0) {
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

  ioa_addr ca_real;

  if(stun_addr_decode(&ca_real, cfield, stun_attr_get_len(attr), xor_ed, STUN_MAGIC_COOKIE, tid.tsx_id)<0) {
    return -1;
  }

  ioa_addr_map_from_real(&ca_real,ca);

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

///////////////////////////////////////////////////////
