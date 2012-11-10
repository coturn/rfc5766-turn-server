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

#ifndef __TURN_MAPS__
#define __TURN_MAPS__

#include "ns_turn_ioaddr.h"

//////////////// UR MAP //////////////////

typedef u64bits ur_map_key_type;
typedef void* ur_map_value_type;
struct _ur_map;
typedef struct _ur_map ur_map;

typedef void (*ur_map_del_func)(ur_map_value_type);

typedef int (*foreachcb_type)(ur_map_key_type key, ur_map_value_type value);
typedef int (*foreachcb_arg_type)(ur_map_key_type key, 
				  ur_map_value_type value, 
				  void *arg);

ur_map* ur_map_create(void);

/**
 * @ret:
 * 0 - success
 * -1 - error
 */

int ur_map_put(ur_map* map, ur_map_key_type key, ur_map_value_type value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int ur_map_get(const ur_map* map, ur_map_key_type key, ur_map_value_type *value);
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int ur_map_del(ur_map* map, ur_map_key_type key,ur_map_del_func delfunc);
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int ur_map_exist(const ur_map* map, ur_map_key_type key);

void ur_map_free(ur_map** map);

size_t ur_map_size(const ur_map* map);

int ur_map_foreach(ur_map* map, foreachcb_type func);

int ur_map_foreach_arg(ur_map* map, foreachcb_arg_type func, void* arg);

int ur_map_lock(const ur_map* map);
int ur_map_unlock(const ur_map* map);

//////////////// UR ADDR MAP //////////////////

typedef ioa_addr ur_addr_map_key_base_type;
typedef ur_addr_map_key_base_type* ur_addr_map_key_type;
typedef unsigned long ur_addr_map_value_type;
struct _ur_addr_map;
typedef struct _ur_addr_map ur_addr_map;

typedef void (*ur_addr_map_func)(ur_addr_map_value_type);
typedef void (*ur_addr_map_func_arg)(ur_addr_map_key_type key,
				ur_addr_map_value_type value,
				void *arg);

ur_addr_map* ur_addr_map_create(u32bits size);

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the addr key exists, the value is updated.
 */
int ur_addr_map_put(ur_addr_map* map, ur_addr_map_key_type key, ur_addr_map_value_type value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_get(const ur_addr_map* map, ur_addr_map_key_type key, ur_addr_map_value_type *value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_del(ur_addr_map* map, ur_addr_map_key_type key,ur_addr_map_func func);
int ur_addr_map_del_by_ip(ur_addr_map* map, ur_addr_map_key_type key,ur_addr_map_func func);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
void ur_addr_map_foreach(ur_addr_map* map, ur_addr_map_func func);
void ur_addr_map_foreach_arg(ur_addr_map* map, ur_addr_map_func_arg func, void *arg);

void ur_addr_map_free(ur_addr_map** map);

size_t ur_addr_map_size(const ur_addr_map* map);

int ur_addr_map_lock(const ur_addr_map* map);
int ur_addr_map_unlock(const ur_addr_map* map);

//////////////// UR STRING MAP //////////////////

typedef s08bits* ur_string_map_key_type;
typedef void* ur_string_map_value_type;
struct _ur_string_map;
typedef struct _ur_string_map ur_string_map;

typedef void (*ur_string_map_func)(ur_string_map_value_type);

ur_string_map* ur_string_map_create(ur_string_map_func del_value_func);

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the string key exists, and the value is different, return error.
 */
int ur_string_map_put(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_get(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type *value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_del(ur_string_map* map, const ur_string_map_key_type key);

void ur_string_map_free(ur_string_map** map);

size_t ur_string_map_size(const ur_string_map* map);

int ur_string_map_lock(const ur_string_map* map);
int ur_string_map_unlock(const ur_string_map* map);

////////////////////////////////////////////

#endif //__TURN_MAPS__
