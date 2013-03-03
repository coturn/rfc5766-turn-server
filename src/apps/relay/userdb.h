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

#ifndef __USERDB__
#define __USERDB__

#include <stdlib.h>
#include <stdio.h>

#include "ns_turn_utils.h"
#include "ns_turn_maps.h"
#include "ns_turn_server.h"

#include "apputils.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////// Defines //////////////////////////////

#define DEFAULT_USERDB_FILE "turnuserdb.conf"

//////////// USER DB //////////////////////////////

struct _turn_user_db {
	turn_credential_type ct;
	u08bits realm[STUN_MAX_REALM_SIZE+1];
	size_t total_quota;
	size_t user_quota;
	size_t total_current_allocs;
	ur_string_map *static_accounts;
	ur_string_map *dynamic_accounts;
	ur_string_map *alloc_counters;
};
typedef struct _turn_user_db turn_user_db;

extern char userdb_file[1025];
extern size_t users_number;
extern int use_lt_credentials;
extern int auth_credentials;
extern turn_user_db *users;
extern s08bits global_realm[1025];

/////////// USER DB CHECK //////////////////

u08bits *get_user_key(u08bits *uname);
int check_new_allocation_quota(u08bits *username);
void release_allocation_quota(u08bits *username);

/////////// Handle user DB /////////////////

void read_userdb_file(void);
int add_user_account(char *user, int dynamic);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __USERDB__///

