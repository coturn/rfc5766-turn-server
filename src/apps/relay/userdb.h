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

#define DEFAULT_AUTH_SECRET_EXPIRATION_TIME (3600*24)

//////////// USER DB //////////////////////////////

struct auth_message {
	turnserver_id id;
	u08bits username[1025];
	hmackey_t key;
	st_password_t pwd;
	get_username_resume_cb resume_func;
	ioa_net_data in_buffer;
	void *ctx;
	int success;
};

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

enum _TURN_USERDB_TYPE {
	TURN_USERDB_TYPE_FILE=0
#if !defined(TURN_NO_PQ)
	,TURN_USERDB_TYPE_PQ
#endif
#if !defined(TURN_NO_MYSQL)
	,TURN_USERDB_TYPE_MYSQL
#endif
};

typedef enum _TURN_USERDB_TYPE TURN_USERDB_TYPE;

extern TURN_USERDB_TYPE userdb_type;
extern char userdb[1025];

extern size_t users_number;
extern int use_lt_credentials;
extern int use_st_credentials;
extern int anon_credentials;

extern int use_auth_secret_with_timestamp;
extern char static_auth_secret[1025];
extern turn_time_t auth_secret_timestamp_expiration_time;

extern turn_user_db *users;

extern s08bits global_realm[1025];

extern void send_auth_message_to_auth_server(struct auth_message *am);

/////////// USER DB CHECK //////////////////

int get_user_key(u08bits *uname, hmackey_t key);
int get_user_pwd(u08bits *uname, st_password_t pwd);
u08bits *start_user_check(turnserver_id id, u08bits *uname, get_username_resume_cb resume, ioa_net_data *in_buffer, void *ctx, int *postpone_reply);
int check_new_allocation_quota(u08bits *username);
void release_allocation_quota(u08bits *username);

/////////// Handle user DB /////////////////

void read_userdb_file(void);
int add_user_account(char *user, int dynamic);
int adminuser(u08bits *user, u08bits *realm, u08bits *pwd, int kcommand, int acommand , int dcommand, int lcommand, int is_st);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __USERDB__///

