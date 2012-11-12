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

#include "ns_turn_maps.h"

#include "ns_turn_ioalib.h"

#include "ns_turn_khash.h"

KHASH_MAP_INIT_INT64(3, ur_map_value_type)

#define MAGIC_HASH ((u64bits)(0x90ABCDEFL))

struct _ur_map {
  khash_t(3) *h;
  u64bits magic;
  TURN_MUTEX_DECLARE(mutex)
};

static int ur_map_init(ur_map* map) {
  if(map) {
    map->h=kh_init(3);
    if(map->h) {
      map->magic=MAGIC_HASH;
      TURN_MUTEX_INIT_RECURSIVE(&(map->mutex));
      return 0;
    }
  }
  return -1;
}

static int ur_map_valid(const ur_map *map) {
  return (map && map->h && map->magic==MAGIC_HASH);
}

ur_map* ur_map_create() {
  ur_map *map=(ur_map*)turn_malloc(sizeof(ur_map));
  if(ur_map_init(map)<0) {
    turn_free(map,sizeof(ur_map));
    return NULL;
  }
  return map;
}

/**
 * @ret:
 * 0 - success
 * -1 - error
 */
int ur_map_put(ur_map* map, ur_map_key_type key, ur_map_value_type value) {
  if(!ur_map_valid(map)) return -1;
  else {

    int ret=0;
    khiter_t k;

    k = kh_get(3, map->h, key);
    if(k != kh_end(map->h)) {
      kh_del(3, map->h, k);
    }
    
    k = kh_put(3,map->h,key,&ret);

    if (!ret) {
      kh_del(3, map->h, k);
      return -1;
    }

    kh_value(map->h, k) = value;

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_map_get(const ur_map* map, ur_map_key_type key, ur_map_value_type *value) {
  if(!ur_map_valid(map)) return 0;
  else {

    khiter_t k;

    k = kh_get(3, map->h, key);
    if((k != kh_end(map->h)) && kh_exist(map->h,k)) {
      if(value) *value=kh_value(map->h,k);
      return 1;
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_map_del(ur_map* map, ur_map_key_type key,ur_map_del_func delfunc) {
  if(!ur_map_valid(map)) return 0;
  else {

    khiter_t k;

    k = kh_get(3, map->h, key);
    if((k != kh_end(map->h)) && kh_exist(map->h,k)) {
      if(delfunc) {
	delfunc(kh_value(map->h,k));
      }
      kh_del(3,map->h,k);
      return 1;
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_map_exist(const ur_map* map, ur_map_key_type key) {
  if(!ur_map_valid(map)) return 0;
  else {

    khiter_t k;

    k = kh_get(3, map->h, key);
    if((k != kh_end(map->h)) && kh_exist(map->h,k)) {
      return 1;
    }

    return 0;
  }
}

void ur_map_free(ur_map** map) {
  if(map && ur_map_valid(*map)) {
    kh_destroy(3,(*map)->h);
    (*map)->h=NULL;
    (*map)->magic=0;
    TURN_MUTEX_DESTROY(&((*map)->mutex));
    turn_free(*map,sizeof(ur_map));
    *map=NULL;
  }
}

size_t ur_map_size(const ur_map* map) {
  if(ur_map_valid(map)) {
    return kh_size(map->h);
  } else {
    return 0;
  }
}

int ur_map_foreach(ur_map* map, foreachcb_type func) {
  if(map && func && ur_map_valid(map)) {
    khiter_t k;
    for (k = kh_begin((*map)->h); k != kh_end(map->h); ++k) {
      if (kh_exist(map->h, k)) {
	if(func((ur_map_key_type)(kh_key(map->h, k)),
		(ur_map_value_type)(kh_value(map->h, k)))) {
	  return 1;
	}
      }
    }
  }
  return 0;
}

int ur_map_foreach_arg(ur_map* map, foreachcb_arg_type func, void* arg) {
  if(map && func && ur_map_valid(map)) {
    khiter_t k;
    for (k = kh_begin((*map)->h); k != kh_end(map->h); ++k) {
      if (kh_exist(map->h, k)) {
	if(func((ur_map_key_type)(kh_key(map->h, k)),
		(ur_map_value_type)(kh_value(map->h, k)),
		arg)
	   ) {
	  return 1;
	}
      }
    }
  }
  return 0;
}

int ur_map_lock(const ur_map* map) {
  if(ur_map_valid(map)) {
    TURN_MUTEX_LOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

int ur_map_unlock(const ur_map* map) {
  if(ur_map_valid(map)) {
    TURN_MUTEX_UNLOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

////////////////////  ADDR LISTS ///////////////////////////////////

typedef struct _addr_list {
  struct _addr_list* next;
} addr_list;

typedef struct _addr_elem {
  addr_list list;
  ur_addr_map_key_base_type key;
  ur_addr_map_value_type value;
} addr_elem;

typedef struct _addr_list_header {
  addr_list *list;
} addr_list_header;

static size_t addr_list_size(const addr_list *sl) {
  if(!sl) return 0;
  return 1+addr_list_size(sl->next);
}

static void addr_list_free(addr_list_header* slh) {
  if(slh) {
    addr_list* list=slh->list;
    while(list) {
      addr_elem *elem=(addr_elem*)list;
      addr_list* tail=elem->list.next;
      turn_free(elem,sizeof(addr_elem));
      list=tail;
    }
  }
}
    
static addr_list* addr_list_add(addr_list* sl, const ur_addr_map_key_type key,  ur_addr_map_value_type value) {
  if(!key) return sl;
  addr_elem *elem=(addr_elem*)turn_malloc(sizeof(addr_elem));
  elem->list.next=sl;
  addr_cpy(&(elem->key),key);
  elem->value=value;
  return &(elem->list);
}

static addr_list* addr_list_remove(addr_list* sl, const ur_addr_map_key_type key, 
				   ur_addr_map_func delfunc, int *counter) {
  if(!sl || !key) return sl;
  addr_elem *elem=(addr_elem*)sl;
  addr_list* tail=elem->list.next;
  if(addr_eq(&(elem->key),key)) {
    if(delfunc && elem->value) delfunc(elem->value);
    turn_free(elem,sizeof(addr_elem));
    if(counter) *counter+=1;
    sl=addr_list_remove(tail, key, delfunc, counter);
  } else {
    elem->list.next=addr_list_remove(tail,key,delfunc,counter);
  }
  return sl;
}

static addr_list* addr_list_remove_by_ip(addr_list* sl, const ur_addr_map_key_type key,
					   ur_addr_map_func delfunc, int *counter) {
  if(!sl || !key) return sl;
  addr_elem *elem=(addr_elem*)sl;
  addr_list* tail=elem->list.next;
  if(addr_eq_no_port(&(elem->key),key)) {
    if(delfunc && elem->value) delfunc(elem->value);
    turn_free(elem,sizeof(addr_elem));
    if(counter) *counter+=1;
    sl=addr_list_remove_by_ip(tail, key, delfunc, counter);
  } else {
    elem->list.next=addr_list_remove_by_ip(tail,key,delfunc,counter);
  }
  return sl;
}

static void addr_list_foreach(addr_list* sl,  ur_addr_map_func func) {
  if(sl && func) {
	  addr_elem *elem=(addr_elem*)sl;
	  addr_list* tail=elem->list.next;
	  func(elem->value);
	  addr_list_foreach(tail, func);
  }
}

static void addr_list_foreach_arg(addr_list* sl,  ur_addr_map_func_arg func, void *arg) {
  if(sl && func) {
	  addr_elem *elem=(addr_elem*)sl;
	  addr_list* tail=elem->list.next;
	  func(&(elem->key), elem->value, arg);
	  addr_list_foreach_arg(tail, func, arg);
  }
}

static addr_elem* addr_list_get(addr_list* sl, const ur_addr_map_key_type key) {

  if(!sl || !key) return NULL;

  addr_elem *elem=(addr_elem*)sl;
  if(addr_eq(&(elem->key),key)) {
    return elem;
  } else {
    addr_list* tail=elem->list.next;
    return addr_list_get(tail, key);
  }
}

////////// ADDR MAPS ////////////////////////////////////////////

#define DEFAULT_ADDR_MAP_SIZE (1021)

struct _ur_addr_map {
  addr_list_header *lists;
  u32bits size;
  u64bits magic;
  TURN_MUTEX_DECLARE(mutex)
};

static int addr_map_index(const ur_addr_map *map, ur_addr_map_key_type key) {
  u32bits hash = addr_hash(key);
  if(map->size)
	  hash = hash % map->size;
  return (int)hash;
}

static addr_list_header* get_addr_list_header(ur_addr_map *map, ur_addr_map_key_type key) {
  return &(map->lists[addr_map_index(map,key)]);
}

static const addr_list_header* get_addr_list_header_const(const ur_addr_map *map, ur_addr_map_key_type key) {
  return &(map->lists[addr_map_index(map,key)]);
}

static int ur_addr_map_init(ur_addr_map* map, u32bits size) {
  if(map) {
    ns_bzero(map,sizeof(ur_addr_map));
    map->magic=MAGIC_HASH;
    if(size)
	    map->size = size;
    else
	    map->size = DEFAULT_ADDR_MAP_SIZE;

    map->lists = turn_malloc(sizeof(addr_list_header) * map->size);
    ns_bzero(map->lists,sizeof(addr_list_header) * map->size);

    TURN_MUTEX_INIT_RECURSIVE(&(map->mutex));
    return 0;
  }
  return -1;
}

static int ur_addr_map_valid(const ur_addr_map *map) {
  return (map && map->magic==MAGIC_HASH);
}

ur_addr_map* ur_addr_map_create(u32bits size) {
  ur_addr_map *map=(ur_addr_map*)turn_malloc(sizeof(ur_addr_map));
  if(ur_addr_map_init(map,size)<0) {
    turn_free(map,sizeof(ur_addr_map));
    return NULL;
  }
  return map;
}

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the addr key exists, the value is updated.
 */
int ur_addr_map_put(ur_addr_map* map, ur_addr_map_key_type key, ur_addr_map_value_type value) {

  if(!ur_addr_map_valid(map)) return -1;

  else {

    addr_list_header* slh = get_addr_list_header(map, key);

    addr_elem* elem = addr_list_get(slh->list, key);
    if(elem) {
      elem->value=value;
    } else {
      slh->list=addr_list_add(slh->list,key,value);
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_get(const ur_addr_map* map, ur_addr_map_key_type key, ur_addr_map_value_type *value) {

  if(!ur_addr_map_valid(map)) return 0;

  else {

    const addr_list_header* slh = get_addr_list_header_const(map, key);

    const addr_elem *elem = addr_list_get(slh->list, key);
    if(elem) {
      if(value) *value=elem->value;
      return 1;
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_del(ur_addr_map* map, ur_addr_map_key_type key,ur_addr_map_func delfunc) {

  if(!ur_addr_map_valid(map)) return 0;

  else {

    addr_list_header* slh = get_addr_list_header(map, key);

    int counter=0;

    slh->list=addr_list_remove(slh->list, key, delfunc, &counter);

    return (counter>0);
  }
}

int ur_addr_map_del_by_ip(ur_addr_map* map, ur_addr_map_key_type key, ur_addr_map_func delfunc)
{

	if (!ur_addr_map_valid(map))
		return 0;
	else {

		int counter = 0;
		u32bits i = 0;
		for (i = 0; i < map->size; ++i) {

			addr_list_header* slh = &(map->lists[i]);

			slh->list = addr_list_remove_by_ip(slh->list, key, delfunc, &counter);
		}

		return (counter > 0);
	}
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
void ur_addr_map_foreach(ur_addr_map* map, ur_addr_map_func func) {

  if(ur_addr_map_valid(map)) {

    u32bits i=0;
    for(i=0;i<map->size;i++) {
      
      addr_list_header* slh = &(map->lists[i]);
      
      addr_list_foreach(slh->list, func);
    }
  }
}

void ur_addr_map_foreach_arg(ur_addr_map* map, ur_addr_map_func_arg func, void *arg) {

  if(ur_addr_map_valid(map)) {

    u32bits i=0;
    for(i=0;i<map->size;i++) {

      addr_list_header* slh = &(map->lists[i]);

      addr_list_foreach_arg(slh->list, func, arg);
    }
  }
}

void ur_addr_map_free(ur_addr_map** map) {
  if(map && ur_addr_map_valid(*map)) {
    u32bits i=0;
    for(i=0;i<(*map)->size;i++) {
      addr_list_free(&((*map)->lists[i]));
    }
    (*map)->magic=0;
    turn_free((*map)->lists,sizeof(addr_list_header) * (*map)->size);
    (*map)->lists = NULL;
    (*map)->size=0;
    TURN_MUTEX_DESTROY(&((*map)->mutex));
    turn_free(*map,sizeof(ur_addr_map));
    *map=NULL;
  }
}

size_t ur_addr_map_size(const ur_addr_map* map) {
  if(ur_addr_map_valid(map)) {
    size_t ret=0;
    u32bits i=0;
    for(i=0;i<map->size;i++) {
      ret+=addr_list_size(map->lists[i].list);
    }
    return ret;
  } else {
    return 0;
  }
}

int ur_addr_map_lock(const ur_addr_map* map) {
  if(ur_addr_map_valid(map)) {
    TURN_MUTEX_LOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

int ur_addr_map_unlock(const ur_addr_map* map) {
  if(ur_addr_map_valid(map)) {
    TURN_MUTEX_UNLOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

////////////////////  STRING LISTS ///////////////////////////////////

typedef struct _string_list {
  struct _string_list* next;
} string_list;

typedef struct _string_elem {
  string_list list;
  ur_string_map_key_type key;
  u32bits key_size;
  ur_string_map_value_type value;
} string_elem;

typedef struct _string_list_header {
  string_list *list;
} string_list_header;

static size_t string_list_size(const string_list *sl) {
  if(!sl) return 0;
  return 1+string_list_size(sl->next);
}

static void string_list_free(string_list_header* slh, ur_string_map_func del_value_func) {
  if(slh) {
    string_list* list=slh->list;
    while(list) {
      string_elem *elem=(string_elem*)list;
      string_list* tail=elem->list.next;
      if(elem->key) turn_free(elem->key,elem->key_size);
      if(del_value_func && elem->value)
	      del_value_func(elem->value);
      turn_free(elem,sizeof(string_elem));
      list=tail;
    }
    slh->list=NULL;
  }
}

static string_list* string_list_add(string_list* sl, const ur_string_map_key_type key, ur_string_map_value_type value) {
  if(!key) return sl;
  string_elem *elem=(string_elem*)turn_malloc(sizeof(string_elem));
  elem->list.next=sl;
  elem->key_size = strlen(key)+1;
  elem->key=turn_malloc(elem->key_size);
  ns_bcopy(key,elem->key,elem->key_size);
  elem->value=value;
  return &(elem->list);
}

static string_list* string_list_remove(string_list* sl, const ur_string_map_key_type key,
					ur_string_map_func del_value_func, int *counter) {
  if(!sl || !key) return sl;
  string_elem *elem=(string_elem*)sl;
  string_list* tail=elem->list.next;
  if(strcmp(elem->key,key)==0) {
    turn_free(elem->key,elem->key_size);
    if(del_value_func)
	    del_value_func(elem->value);
    turn_free(elem,sizeof(string_elem));
    if(counter) *counter+=1;
    sl=string_list_remove(tail, key, del_value_func, counter);
  } else {
    elem->list.next=string_list_remove(tail,key,del_value_func,counter);
  }
  return sl;
}

static string_elem* string_list_get(string_list* sl, const ur_string_map_key_type key) {

  if(!sl || !key) return NULL;

  string_elem *elem=(string_elem*)sl;
  if(strcmp(elem->key,key)==0) {
    return elem;
  } else {
    return string_list_get(elem->list.next, key);
  }
}

////////// STRING MAPS ////////////////////////////////////////////

#define STRING_MAP_SIZE (1024)

struct _ur_string_map {
  string_list_header lists[STRING_MAP_SIZE];
  u64bits magic;
  ur_string_map_func del_value_func;
  TURN_MUTEX_DECLARE(mutex)
};

static unsigned long string_hash(const ur_string_map_key_type key) {

  u08bits *str=(u08bits*)key;

  unsigned long hash = 0;
  int c = 0;

  while ((c = *str++))
    hash = c + (hash << 6) + (hash << 16) - hash;

  return hash;
}

static int string_map_index(const ur_string_map_key_type key) {
  return (int)(string_hash(key) % STRING_MAP_SIZE);
}

static string_list_header* get_string_list_header(ur_string_map *map, const ur_string_map_key_type key) {
  return &(map->lists[string_map_index(key)]);
}

static int ur_string_map_init(ur_string_map* map) {
  if(map) {
    ns_bzero(map,sizeof(ur_string_map));
    map->magic=MAGIC_HASH;

    TURN_MUTEX_INIT_RECURSIVE(&(map->mutex));

    return 0;
  }
  return -1;
}

static int ur_string_map_valid(const ur_string_map *map) {
  return (map && map->magic==MAGIC_HASH);
}

ur_string_map* ur_string_map_create(ur_string_map_func del_value_func) {
  ur_string_map *map=(ur_string_map*)turn_malloc(sizeof(ur_string_map));
  if(ur_string_map_init(map)<0) {
    turn_free(map,sizeof(ur_string_map));
    return NULL;
  }
  map->del_value_func = del_value_func;
  return map;
}

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the string key exists, and the value is different, return error.
 */
int ur_string_map_put(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type value) {

  if(!ur_string_map_valid(map)) return -1;

  else {

    string_list_header* slh = get_string_list_header(map, key);

    string_elem *elem = string_list_get(slh->list, key);
    if(elem) {
      if(elem->value != value) {
	      if(map->del_value_func)
		      map->del_value_func(elem->value);
	      elem->value = value;
      }
      return 0;
    }

    slh->list=string_list_add(slh->list,key,value);

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_get(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type *value) {

  if(!ur_string_map_valid(map)) return 0;

  else {

    string_list_header* slh = get_string_list_header(map, key);
    string_elem *elem = string_list_get(slh->list, key);
    if(elem) {
      if(value) *value=elem->value;
      return 1;
    } else {
      return 0;
    }
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_del(ur_string_map* map, const ur_string_map_key_type key) {

  if(!ur_string_map_valid(map)) return 0;

  else {

    string_list_header* slh = get_string_list_header(map, key);

    int counter=0;

    slh->list=string_list_remove(slh->list, key, map->del_value_func, &counter);

    return (counter>0);
  }
}

void ur_string_map_clean(ur_string_map* map) {
	if (ur_string_map_valid(map)) {
		int i = 0;
		for (i = 0; i < STRING_MAP_SIZE; i++) {
			string_list_free(&(map->lists[i]), map->del_value_func);
		}
	}
}

void ur_string_map_free(ur_string_map** map) {
  if(map && ur_string_map_valid(*map)) {
    int i=0;
    for(i=0;i<STRING_MAP_SIZE;i++) {
      string_list_free(&((*map)->lists[i]),(*map)->del_value_func);
    }
    (*map)->magic=0;
    TURN_MUTEX_DESTROY(&((*map)->mutex));
    turn_free(*map,sizeof(ur_string_map));
    *map=NULL;
  }
}

size_t ur_string_map_size(const ur_string_map* map) {
  if(ur_string_map_valid(map)) {
    size_t ret=0;
    int i=0;
    for(i=0;i<STRING_MAP_SIZE;i++) {
      ret+=string_list_size(map->lists[i].list);
    }
    return ret;
  } else {
    return 0;
  }
}

int ur_string_map_lock(const ur_string_map* map) {
  if(ur_string_map_valid(map)) {
    TURN_MUTEX_LOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

int ur_string_map_unlock(const ur_string_map* map) {
  if(ur_string_map_valid(map)) {
    TURN_MUTEX_UNLOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

////////////////////////////////////////////////////////////////
