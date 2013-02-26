/*
 * Copyright (C) 2013 Citrix Systems
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>

#if !defined(TURN_NO_THREADS)
#include <pthread.h>
#endif

#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "userdb.h"

#include "ns_turn_utils.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

//////////// USER DB //////////////////////////////

char userdb_file[1025]="\0";
size_t users_number = 0;
int use_lt_credentials = 0;
int auth_credentials = 0;
turn_user_db *users = NULL;
s08bits global_realm[1025];

/////////// USER DB CHECK //////////////////

u08bits *get_user_key(u08bits *uname)
{
	ur_string_map_value_type ukey = NULL;
	ur_string_map_lock(users->static_accounts);
	if(!ur_string_map_get(users->static_accounts, (ur_string_map_key_type)uname, &ukey)) {
		ur_string_map_unlock(users->static_accounts);
		ur_string_map_lock(users->dynamic_accounts);
		if(!ur_string_map_get(users->dynamic_accounts, (ur_string_map_key_type)uname, &ukey)) {
			ur_string_map_unlock(users->dynamic_accounts);
			return (u08bits*)NULL;
		}
		ur_string_map_unlock(users->dynamic_accounts);
	} else {
		ur_string_map_unlock(users->static_accounts);
	}

	return (u08bits*)ukey;
}

int check_new_allocation_quota(u08bits *username)
{
	int ret = 0;
	if (username) {
		ur_string_map_lock(users->alloc_counters);
		if (users->total_quota && (users->total_current_allocs >= users->total_quota)) {
			ret = -1;
		} else {
			ur_string_map_value_type value = 0;
			if (!ur_string_map_get(users->alloc_counters, (ur_string_map_key_type) username, &value)) {
				value = (ur_string_map_value_type) 1;
				ur_string_map_put(users->alloc_counters, (ur_string_map_key_type) username, value);
				++(users->total_current_allocs);
			} else {
				if ((users->user_quota) && ((size_t) value >= users->user_quota)) {
					ret = -1;
				} else {
					value = (ur_string_map_value_type)(((size_t)value) + 1);
					ur_string_map_put(users->alloc_counters, (ur_string_map_key_type) username, value);
					++(users->total_current_allocs);
				}
			}
		}
		ur_string_map_unlock(users->alloc_counters);
	}
	return ret;
}

void release_allocation_quota(u08bits *username)
{
	if (username) {
		ur_string_map_lock(users->alloc_counters);
		ur_string_map_value_type value = 0;
		ur_string_map_get(users->alloc_counters, (ur_string_map_key_type) username, &value);
		if (value) {
			value = (ur_string_map_value_type)(((size_t)value) - 1);
			ur_string_map_put(users->alloc_counters, (ur_string_map_key_type) username, value);
		}
		if (users->total_current_allocs)
			--(users->total_current_allocs);
		ur_string_map_unlock(users->alloc_counters);
	}
}

///////////////////////////////
