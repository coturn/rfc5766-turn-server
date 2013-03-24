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

#if !defined(TURN_NO_PQ)
#include <libpq-fe.h>
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

char userdb_uri[1025]="\0";

#if !defined(TURN_NO_THREADS)
char sql_userdb_uri[1025]="\0";
#endif

size_t users_number = 0;
int use_lt_credentials = 0;
int anon_credentials = 0;
turn_user_db *users = NULL;
s08bits global_realm[1025];

#if !defined(TURN_NO_PQ)
static PGconn *dbconnection = NULL;
#endif

/////////// USER DB CHECK //////////////////

static int convert_string_key_to_binary(char* keysource, hmackey_t key) {
	if(strlen(keysource)!=(2*sizeof(hmackey_t))) {
		return -1;
	} else {
		char is[3];
		size_t i;
		unsigned int v;
		is[2]=0;
		for(i=0;i<sizeof(hmackey_t);i++) {
			is[0]=keysource[i*2];
			is[1]=keysource[i*2+1];
			sscanf(is,"%02x",&v);
			key[i]=(unsigned char)v;
		}
		return 0;
	}
}


int is_sql_userdb(void)
{
#if !defined(TURN_NO_PQ)
	return (sql_userdb_uri[0]!=0);
#else
	return 0;
#endif
}

#if !defined(TURN_NO_PQ)
static PGconn *get_db_connection(void)
{
	if(dbconnection) {
		ConnStatusType status = PQstatus(dbconnection);
		if(status != CONNECTION_OK) {
			PQfinish(dbconnection);
			dbconnection = NULL;
		}
	}
	if(!dbconnection && is_sql_userdb()) {
		char *errmsg=NULL;
		PQconninfoOption *co = PQconninfoParse(sql_userdb_uri, &errmsg);
		if(!co) {
			if(errmsg) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open DB connection %s, connection string format error: %s\n",sql_userdb_uri,errmsg);
				free(errmsg);
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open DB connection: %s, unknown connection string format error\n",sql_userdb_uri);
			}
		} else {
			PQconninfoFree(co);
			dbconnection = PQconnectdb(sql_userdb_uri);
			if(!dbconnection) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open DB connection: %s, runtime error\n",sql_userdb_uri);
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DB connection success: %s\n",sql_userdb_uri);
			}
		}
	}
	return dbconnection;
}
#endif

int get_user_key(u08bits *uname, hmackey_t key)
{
	int ret = -1;
	ur_string_map_value_type ukey = NULL;
	ur_string_map_lock(users->static_accounts);
	if(ur_string_map_get(users->static_accounts, (ur_string_map_key_type)uname, &ukey)) {
		ret = 0;
	} else {
		ur_string_map_lock(users->dynamic_accounts);
		if(ur_string_map_get(users->dynamic_accounts, (ur_string_map_key_type)uname, &ukey)) {
			ret = 0;
		}
		ur_string_map_unlock(users->dynamic_accounts);
	}
	ur_string_map_unlock(users->static_accounts);

	if(ret==0) {
		ns_bcopy(ukey,key,sizeof(hmackey_t));
		return 0;
	} else {
#if !defined(TURN_NO_PQ)
	if(get_db_connection()) {
		char statement[1025];
		sprintf(statement,"select hmackey from turnusers_lt where name='%s'",uname);
		PGresult *res = PQexec(get_db_connection(), statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK) || (PQntuples(res)!=1)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving DB information: %s\n",PQerrorMessage(get_db_connection()));
		} else {
			char *kval = PQgetvalue(res,0,0);
			if(kval) {
				if(convert_string_key_to_binary(kval, key)<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s, user %s\n",kval,uname);
				} else {
					ret = 0;
				}
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong hmackey data for user %s: %s\n",uname,kval);
			}
		}

		if(res) {
			PQclear(res);
		}
	}
#endif
	}

	return ret;
}

u08bits *start_user_check(turnserver_id id, u08bits *uname, get_username_resume_cb resume, ioa_net_data *in_buffer, void *ctx, int *postpone_reply)
{
	UNUSED_ARG(uname);
	UNUSED_ARG(resume);
	UNUSED_ARG(in_buffer);
	UNUSED_ARG(ctx);

	*postpone_reply = 1;

	struct auth_message am;
	ns_bzero(&am,sizeof(am));
	am.id = id;
	STRCPY(am.username,uname);
	am.resume_func = resume;
	memcpy(&(am.in_buffer),in_buffer,sizeof(am.in_buffer));
	in_buffer->nbh = NULL;
	am.ctx = ctx;

	send_auth_message_to_auth_server(&am);

	return NULL;
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

//////////////////////////////////

void read_userdb_file(void)
{
	static char *full_path_to_userdb_file = NULL;
	static int first_read = 1;
	static turn_time_t mtime = 0;

	if(is_sql_userdb())
		return;

	FILE *f = NULL;

	if(full_path_to_userdb_file) {
		struct stat sb;
		if(stat(full_path_to_userdb_file,&sb)<0) {
			perror("File statistics");
		} else {
			turn_time_t newmtime = (turn_time_t)(sb.st_mtime);
			if(mtime == newmtime)
				return;
			mtime = newmtime;

		}
	}

	if (!full_path_to_userdb_file)
		full_path_to_userdb_file = find_config_file(userdb_uri, first_read);

	if (full_path_to_userdb_file)
		f = fopen(full_path_to_userdb_file, "r");

	if (f) {

		char sbuf[1025];

		ur_string_map_lock(users->dynamic_accounts);
		ur_string_map_clean(users->dynamic_accounts);

		for (;;) {
			char *s = fgets(sbuf, sizeof(sbuf) - 1, f);
			if (!s)
				break;
			s = skip_blanks(s);
			if (s[0] == '#')
				continue;
			if (!s[0])
				continue;
			size_t slen = strlen(s);
			while (slen && (s[slen - 1] == 10 || s[slen - 1] == 13))
				s[--slen] = 0;
			if (slen)
				add_user_account(s,1);
		}

		ur_string_map_unlock(users->dynamic_accounts);

		fclose(f);

	} else if (first_read)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: Cannot find userdb file: %s: going without dynamic user database.\n", userdb_uri);

	first_read = 0;
}

int add_user_account(char *user, int dynamic)
{
	if(user) {
		char *s = strstr(user, ":");
		if(!s || (s==user) || (strlen(s)<2)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user account: %s\n",user);
		} else {
			size_t ulen = s-user;
			char *uname = (char*)malloc(sizeof(char)*(ulen+1));
			strncpy(uname,user,ulen);
			uname[ulen]=0;
			if(SASLprep((u08bits*)uname)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user name: %s\n",user);
				free(uname);
				return -1;
			}
			s = skip_blanks(s+1);
			hmackey_t *key = (hmackey_t*)malloc(sizeof(hmackey_t));
			if(strstr(s,"0x")==s) {
				char *keysource = s + 2;
				if(convert_string_key_to_binary(keysource, *key)<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s\n",s);
					free(uname);
					free(key);
					return -1;
				}
			} else {
				stun_produce_integrity_key_str((u08bits*)uname, (u08bits*)global_realm, (u08bits*)s, *key);
			}
			if(dynamic) {
				ur_string_map_lock(users->dynamic_accounts);
				ur_string_map_put(users->dynamic_accounts, (ur_string_map_key_type)uname, (ur_string_map_value_type)*key);
				ur_string_map_unlock(users->dynamic_accounts);
			} else {
				ur_string_map_lock(users->static_accounts);
				ur_string_map_put(users->static_accounts, (ur_string_map_key_type)uname, (ur_string_map_value_type)*key);
				ur_string_map_unlock(users->static_accounts);
			}
			users_number++;
			free(uname);
			return 0;
		}
	}

	return -1;
}

////////////////// Admin /////////////////////////

int adminuser(u08bits *user, u08bits *realm, u08bits *pwd, int kcommand, int acommand , int dcommand)
{
	hmackey_t key;
	char skey[sizeof(hmackey_t)*2+1];

	if(!dcommand) {
		stun_produce_integrity_key_str(user, realm, pwd, key);
		size_t i = 0;
		char *s=skey;
		for(i=0;i<sizeof(hmackey_t);i++) {
			sprintf(s,"%02x",(unsigned int)key[i]);
			s+=2;
		}
	}

	if(kcommand) {

		printf("0x%s\n",skey);

	} else if(is_sql_userdb()){
#if !defined(TURN_NO_PQ)
		char statement[1025];

		if(dcommand) {
			sprintf(statement,"delete from turnusers_lt where name='%s'",user);
			PGresult *res = PQexec(get_db_connection(), statement);
			if(res) {
				PQclear(res);
			}
		}

		if(acommand) {
			sprintf(statement,"insert into turnusers_lt values('%s','%s')",user,skey);
			PGresult *res = PQexec(get_db_connection(), statement);
			if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
				if(res) {
					PQclear(res);
				}
				sprintf(statement,"update turnusers_lt set hmackey='%s' where name='%s'",skey,user);
				PGresult *res = PQexec(get_db_connection(), statement);
				if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user key information: %s\n",PQerrorMessage(get_db_connection()));
				}
			}
			if(res) {
				PQclear(res);
			}
		}
#endif
	} else {

		char *full_path_to_userdb_file = find_config_file(userdb_uri, 1);
		FILE *f = full_path_to_userdb_file ? fopen(full_path_to_userdb_file,"r") : NULL;
		int found = 0;
		char us[1025];
		size_t i = 0;
		char **content = NULL;
		size_t csz = 0;

		strcpy(us, (char*) user);
		strcpy(us + strlen(us), ":");

		if (!f) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "File %s not found, will be created.\n",userdb_uri);
		} else {

			char sarg[1025];
			char sbuf[1025];

			for (;;) {
				char *s0 = fgets(sbuf, sizeof(sbuf) - 1, f);
				if (!s0)
					break;

				size_t slen = strlen(s0);
				while (slen && (s0[slen - 1] == 10 || s0[slen - 1] == 13))
					s0[--slen] = 0;

				char *s = skip_blanks(s0);

				if (s[0] == '#')
					goto add_and_cont;
				if (!s[0])
					goto add_and_cont;

				strcpy(sarg, s);
				if (strstr(sarg, us) == sarg) {
					if (dcommand)
						continue;

					if (found)
						continue;
					found = 1;
					strcpy(us, (char*) user);
					strcpy(us + strlen(us), ":0x");
					for (i = 0; i < sizeof(key); i++) {
						sprintf(
										us + strlen(us),
										"%02x",
										(unsigned int) key[i]);
					}

					s0 = us;
				}

				add_and_cont:
				content = (char**)realloc(content, sizeof(char*) * (++csz));
				content[csz - 1] = strdup(s0);
			}

			fclose(f);
		}

		if(!found && acommand) {
			strcpy(us,(char*)user);
			strcpy(us+strlen(us),":0x");
			for(i=0;i<sizeof(key);i++) {
				sprintf(us+strlen(us),"%02x",(unsigned int)key[i]);
			}
			content = (char**)realloc(content,sizeof(char*)*(++csz));
			content[csz-1]=strdup(us);
		}

		if(!full_path_to_userdb_file)
			full_path_to_userdb_file=strdup(userdb_uri);

		char *dir = (char*)malloc(strlen(full_path_to_userdb_file)+21);
		strcpy(dir,full_path_to_userdb_file);
		size_t dlen = strlen(dir);
		while(dlen) {
			if(dir[dlen-1]=='/')
				break;
			dir[--dlen]=0;
		}
		strcpy(dir+strlen(dir),".tmp_userdb");

		f = fopen(dir,"w");
		if(!f) {
			perror("file open");
			exit(-1);
		}

		for(i=0;i<csz;i++)
			fprintf(f,"%s\n",content[i]);

		fclose(f);

		rename(dir,full_path_to_userdb_file);
	}

	return 0;
}


///////////////////////////////
