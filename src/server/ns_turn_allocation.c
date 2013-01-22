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

#include "ns_turn_allocation.h"

////////// DATA //////////////////////////////////////////////////

#define TURN_PERMISSION_MAP_SIZE (17)

/////////////// ALLOCATION ///////////////////////////////////////

void init_allocation(allocation* a) {
  if(a) {
    ns_bzero(a,sizeof(allocation));
    a->channel_to_ch_info=ur_map_create();
    init_turn_permission_map(&(a->addr_to_perm));
  }
}

void free_allocation(allocation *a)
{
	if (a) {

		delete_ur_map_session_elem_data(&(a->relay_session));

		IOA_EVENT_DEL(a->lifetime_ev);

		/* The order is important here: */
		free_turn_permission_map(&(a->addr_to_perm));
		ur_map_free(&(a->channel_to_ch_info));

		a->is_valid=0;
	}
}

ts_ur_session *get_relay_session(allocation *a)
{
	return &(a->relay_session);
}

ioa_socket_handle get_relay_socket(allocation *a)
{
	return a->relay_session.s;
}

void set_allocation_lifetime_ev(allocation *a, turn_time_t exp_time, ioa_timer_handle ev) {
  if(a) {
    IOA_EVENT_DEL(a->lifetime_ev);
    a->expiration_time=exp_time;
    a->lifetime_ev=ev;
  }
}

int is_allocation_valid(const allocation* a) {
  if(a) return a->is_valid;
  else return 0;
}

void set_allocation_valid(allocation* a, int value) {
  if(a) a->is_valid=value;
}

turn_permission_info* allocation_get_permission(const allocation* a, const ioa_addr *addr) {
  if(a && a->addr_to_perm) {
    return get_from_turn_permission_map(a->addr_to_perm, addr);
  }
  return NULL;
}

///////////////////////////// TURN_PERMISSION /////////////////////////////////

static void set_cilist_head(turn_permission_info *cdi) {
  if(cdi) {
    cdi->list.next=NULL;
  }
}

static void free_cilist_elem(turn_permission_info *cdi) {
  if(cdi) {
    turn_permission_clean(cdi);
    turn_free(cdi,sizeof(turn_permission_info));
  }
}

static void free_cilist(turn_permission_info *cdi) {
  if(cdi) {
    free_cilist((turn_permission_info *)cdi->list.next);
    free_cilist_elem(cdi);
  }
}

static turn_permission_info* push_back_cilist(turn_permission_info *cdi, turn_permission_info *elem) {
  if(!elem) return cdi;
  if(!cdi) {
    set_cilist_head(elem);
    return elem;
  } else {
    cdi->list.next=(perm_list *)push_back_cilist((turn_permission_info*)cdi->list.next,elem);
    return cdi;
  }
}

static turn_permission_info* remove_from_cilist(const ioa_addr *addr,turn_permission_info *cdi) {
  if(!cdi || !addr) return cdi;
  if(addr_eq_no_port(addr,&(cdi->addr))) {
    turn_permission_info* ret=(turn_permission_info*)cdi->list.next;
    free_cilist_elem(cdi);
    return ret;
  }
  cdi->list.next=(perm_list*)remove_from_cilist(addr,(turn_permission_info*)cdi->list.next);
  return cdi;
}

static int cilist_size(turn_permission_info* cdi) {
  if(!cdi) return 0;
  return 1+cilist_size((turn_permission_info*)(cdi->list.next));
}

void init_turn_permission_map(turn_permission_map *map) {
  int i=0;
  (*map)=(turn_permission_map)turn_malloc(sizeof(turn_permission_info*)*TURN_PERMISSION_MAP_SIZE);
  for(i=0;i<TURN_PERMISSION_MAP_SIZE;i++) {
    (*map)[i]=NULL;
  }
}

void free_turn_permission_map(turn_permission_map *map) {
  int i=0;
  for(i=0;i<TURN_PERMISSION_MAP_SIZE;i++) {
    if((*map)[i]) {
      free_cilist((*map)[i]);
      (*map)[i]=NULL;
    }
  }
  turn_free(*map,sizeof(turn_permission_map));
  *map=NULL;
}

int turn_permission_map_size(turn_permission_map map) {
  int sz=0;
  if(map) {
    int i=0;
    for(i=0;i<TURN_PERMISSION_MAP_SIZE;i++) {
      sz+=cilist_size(map[i]);
    }
  }
  return sz;
}

turn_permission_info* get_from_turn_permission_map(const turn_permission_map map, const ioa_addr *addr) {
  if(!addr) return NULL;
  u32bits hash=addr_hash_no_port(addr);
  turn_permission_info* ret=map[hash%TURN_PERMISSION_MAP_SIZE];
  int found = 0;
  while(ret) {
    if(addr_eq_no_port(&ret->addr,addr)) {
      found=1;
      break;
    } else {
      ret=(turn_permission_info*)(ret->list.next);
    }
  }

  if(!found)
    ret = NULL;

  return ret;
}

void remove_from_turn_permission_map(turn_permission_map map, const ioa_addr* addr) {
  if(map && addr) {
    u32bits hash=addr_hash_no_port(addr);
    int fds=(int)(hash%TURN_PERMISSION_MAP_SIZE);
    map[fds]=remove_from_cilist(addr,map[fds]);
  }
}

static void ch_info_clean(ur_map_value_type value) {
  if(value) {
    ch_info* c = (ch_info*)value;
    IOA_EVENT_DEL(c->lifetime_ev);
    ns_bzero(c,sizeof(ch_info));
  }
}

static int delete_channel_info_from_allocation_map(ur_map_key_type key, ur_map_value_type value)
{
	UNUSED_ARG(key);

	if(value) {
		ch_info* chn = (ch_info*)value;
		turn_permission_info* tinfo = (turn_permission_info*)chn->owner;
		if(tinfo) {
			allocation* a = (allocation*)tinfo->owner;
			if(a) {
				delete_ioa_socket_channel(&(chn->socket_channel));
				ur_map_del(a->channel_to_ch_info, chn->chnum, ch_info_clean);
			}
		}
		turn_free(chn,sizeof(ch_info));
	}

	return 0;
}

void turn_channel_delete(ch_info* chn)
{
	if(chn) {
	  turn_permission_info* tinfo = (turn_permission_info*)chn->owner;
		if(tinfo) {
			ur_map_del(tinfo->channels, (ur_map_key_type)addr_get_port(&(chn->peer_addr)),NULL);
			delete_channel_info_from_allocation_map((ur_map_key_type)addr_get_port(&(chn->peer_addr)),(ur_map_value_type)chn);
		}
	}
}

void turn_permission_clean(ur_map_value_type value) {
  if(value) {
    turn_permission_info* tinfo = (turn_permission_info*)value;
    ur_map_foreach(tinfo->channels, (foreachcb_type)delete_channel_info_from_allocation_map);
    ur_map_free(&(tinfo->channels));
    IOA_EVENT_DEL(tinfo->lifetime_ev);
    ns_bzero(tinfo,sizeof(turn_permission_info));
  }
}

void allocation_remove_turn_permission(allocation* a, turn_permission_info* tinfo)
{
	if (a && tinfo) {
		remove_from_turn_permission_map(a->addr_to_perm, &(tinfo->addr));
	}
}

ch_info* allocation_get_new_ch_info(allocation* a, u16bits chnum, ioa_addr* peer_addr)
{

	turn_permission_info* tinfo = get_from_turn_permission_map(a->addr_to_perm, peer_addr);

	if (!tinfo)
		tinfo = allocation_add_permission(a, peer_addr);

	ch_info* chn = (ch_info*)turn_malloc(sizeof(ch_info));

	ns_bzero(chn,sizeof(ch_info));

	chn->chnum = chnum;
	chn->port = addr_get_port(peer_addr);
	addr_cpy(&(chn->peer_addr), peer_addr);
	chn->owner = tinfo;
	ur_map_put(a->channel_to_ch_info, chnum, chn);

	ur_map_put(tinfo->channels, (ur_map_key_type) addr_get_port(peer_addr), (ur_map_value_type) chn);

	return chn;
}

ch_info* allocation_get_ch_info(allocation* a, u16bits chnum) {
	void* vchn = NULL;
	if (ur_map_get(a->channel_to_ch_info, chnum, &vchn) && vchn) {
		return (ch_info*) vchn;
	}
	return NULL;
}

ch_info* allocation_get_ch_info_by_peer_addr(allocation* a, ioa_addr* peer_addr) {
	turn_permission_info* tinfo = get_from_turn_permission_map(a->addr_to_perm, peer_addr);
	if(tinfo) {
		return get_turn_channel(tinfo,peer_addr);
	}
	return NULL;
}

u16bits get_turn_channel_number(turn_permission_info* tinfo, ioa_addr *addr)
{
	if (tinfo) {
		ur_map_value_type t = 0;
		if (ur_map_get(tinfo->channels, (ur_map_key_type)addr_get_port(addr), &t) && t) {
			ch_info* chn = (ch_info*) t;
			if (STUN_VALID_CHANNEL(chn->chnum)) {
				return chn->chnum;
			}
		}
	}

	return 0;
}

ch_info *get_turn_channel(turn_permission_info* tinfo, ioa_addr *addr)
{
	if (tinfo) {
		ur_map_value_type t = 0;
		if (ur_map_get(tinfo->channels, (ur_map_key_type)addr_get_port(addr), &t) && t) {
			ch_info* chn = (ch_info*) t;
			if (STUN_VALID_CHANNEL(chn->chnum)) {
				return chn;
			}
		}
	}

	return NULL;
}

turn_permission_map allocation_get_turn_permission_map(const allocation *a) {
  return a->addr_to_perm;
}

turn_permission_info* allocation_add_permission(allocation *a, const ioa_addr* addr) {
  if(a && addr) {
    turn_permission_map map = a->addr_to_perm;
    turn_permission_info *elem=(turn_permission_info *)turn_malloc(sizeof(turn_permission_info));
    ns_bzero(elem,sizeof(turn_permission_info));
    elem->channels = ur_map_create();
    addr_cpy(&elem->addr,addr);
    u32bits hash=addr_hash_no_port(addr);
    int fds=(int)(hash%TURN_PERMISSION_MAP_SIZE);
    elem->list.next=NULL;
    map[fds]=push_back_cilist(map[fds],elem);
    elem->owner = a;
    return elem;
  } else {
    return NULL;
  }
}

//////////////////////////////////////////////////////////////////

