/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
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

#define AUTH_SECRET_SIZE (512)

//////////// USER DB //////////////////////////////

struct auth_message {
	turnserver_id id;
	u08bits username[1025];
	hmackey_t key;
	st_password_t pwd;
	get_username_resume_cb resume_func;
	ioa_net_data in_buffer;
	u64bits ctxkey;
	int success;
};

struct _turn_user_db {
	turn_credential_type ct;
	vint total_quota;
	vint user_quota;
	vint total_current_allocs;
	ur_string_map *static_accounts;
	ur_string_map *dynamic_accounts;
	ur_string_map *alloc_counters;
};
typedef struct _turn_user_db turn_user_db;

enum _TURN_USERDB_TYPE {
	TURN_USERDB_TYPE_FILE=0
#if !defined(TURN_NO_PQ)
	,TURN_USERDB_TYPE_PQ
#endif
#if !defined(TURN_NO_MYSQL)
	,TURN_USERDB_TYPE_MYSQL
#endif
#if !defined(TURN_NO_HIREDIS)
	,TURN_USERDB_TYPE_REDIS
#endif
};

typedef enum _TURN_USERDB_TYPE TURN_USERDB_TYPE;

enum _TURNADMIN_COMMAND_TYPE {
	TA_COMMAND_UNKNOWN,
	TA_PRINT_KEY,
	TA_UPDATE_USER,
	TA_DELETE_USER,
	TA_LIST_USERS,
	TA_SET_SECRET,
	TA_SHOW_SECRET,
	TA_DEL_SECRET
};

typedef enum _TURNADMIN_COMMAND_TYPE TURNADMIN_COMMAND_TYPE;

/////////// SHARED SECRETS //////////////////

struct _secrets_list {
	char **secrets;
	size_t sz;
};
typedef struct _secrets_list secrets_list_t;

/////////// USERS PARAM /////////////////////

#define TURN_LONG_STRING_SIZE (1025)

typedef struct _users_params_t {

  TURN_USERDB_TYPE userdb_type;
  char userdb[TURN_LONG_STRING_SIZE];

  size_t users_number;
  int use_lt_credentials;
  int use_st_credentials;
  int anon_credentials;

  turn_user_db users;

  s08bits global_realm[STUN_MAX_REALM_SIZE+1];

  int use_auth_secret_with_timestamp;
  char rest_api_separator;
  secrets_list_t static_auth_secrets;
} users_params_t;

/////////////////////////////////////////////

void init_secrets_list(secrets_list_t *sl);
void init_dynamic_ip_lists(void);
void update_white_and_black_lists(void);
void clean_secrets_list(secrets_list_t *sl);
size_t get_secrets_list_size(secrets_list_t *sl);
const char* get_secrets_list_elem(secrets_list_t *sl, size_t i);
void add_to_secrets_list(secrets_list_t *sl, const char* elem);

/////////// USER DB CHECK //////////////////

int get_user_key(u08bits *uname, hmackey_t key, ioa_network_buffer_handle nbh);
int get_user_pwd(u08bits *uname, st_password_t pwd);
u08bits *start_user_check(turnserver_id id, u08bits *uname, get_username_resume_cb resume, ioa_net_data *in_buffer, u64bits ctxkey, int *postpone_reply);
int check_new_allocation_quota(u08bits *username);
void release_allocation_quota(u08bits *username);

/////////// Handle user DB /////////////////

void read_userdb_file(int to_print);
void auth_ping(void);
int add_user_account(char *user, int dynamic);
int adminuser(u08bits *user, u08bits *realm, u08bits *pwd, u08bits *secret, TURNADMIN_COMMAND_TYPE ct, int is_st);

int add_ip_list_range(char* range, ip_range_list_t * list);

///////////// Redis //////////////////////

#if !defined(TURN_NO_HIREDIS)
#include "hiredis_libevent2.h"
redis_context_handle get_redis_async_connection(struct event_base *base, char* connection_string);
#endif

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __USERDB__///

