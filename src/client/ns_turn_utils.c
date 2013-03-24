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

#include "ns_turn_utils.h"

///////////////////////// LOG ///////////////////////////////////

#if defined(TURN_LOG_FUNC_IMPL)
extern void TURN_LOG_FUNC_IMPL(TURN_LOG_LEVEL level, const s08bits* format, va_list args);
#endif

void turn_log_func_default(TURN_LOG_LEVEL level, const s08bits* format, ...)
{
	{
		va_list args;
		va_start(args,format);
#if defined(TURN_LOG_FUNC_IMPL)
		TURN_LOG_FUNC_IMPL(level,format,args);
#else
		if (level == TURN_LOG_LEVEL_ERROR)
			vfprintf(stderr, format, args);
		else
			vprintf(format, args);
#endif
		va_end(args);
	}
#if !defined(TURN_LOG_FUNC_IMPL)
	{
		va_list args;
		va_start(args,format);
		vrtpprintf(format, args);
		va_end(args);
	}
#endif
}

void addr_debug_print(int verbose, const ioa_addr *addr, const s08bits* s)
{
	if (verbose) {
		if (!addr) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n%s: EMPTY\n", s);
		} else {
			s08bits addrbuf[INET6_ADDRSTRLEN];
			if (!s)
				s = "";
			if (addr->ss.ss_family == AF_INET) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\nIPv4. %s: %s:%d\n", s, inet_ntop(AF_INET,
								&addr->s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
								nswap16(addr->s4.sin_port));
			} else if (addr->ss.ss_family == AF_INET6) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\nIPv6. %s: %s:%d\n", s, inet_ntop(AF_INET6,
								&addr->s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
								nswap16(addr->s6.sin6_port));
			} else {
				if (addr_any_no_port(addr)) {
					TURN_LOG_FUNC(
									TURN_LOG_LEVEL_INFO,
									"\nIP. %s: 0.0.0.0:%d\n",
									s,
									nswap16(addr->s4.sin_port));
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrong IP address family: %d\n", s,
									(int) (addr->ss.ss_family));
				}
			}
		}
	}
}

#if defined(__USE_OPENSSL__)

///////////// Security functions implementation from ns_turn_msg.h ///////////

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

#include "ns_turn_msg.h"

int stun_calculate_hmac(u08bits *buf, size_t len, hmackey_t key, u08bits *hmac)
{
	if (!HMAC(EVP_sha1(), key, sizeof(hmackey_t), buf, len, hmac, NULL)) {
		return -1;
	} else {
		return 0;
	}
}

int stun_produce_integrity_key_str(u08bits *uname, u08bits *realm, u08bits *upwd, hmackey_t key)
{
	MD5_CTX ctx;
	size_t ulen = strlen((s08bits*)uname);
	size_t rlen = strlen((s08bits*)realm);
	size_t plen = strlen((s08bits*)upwd);
	u08bits *str = (u08bits*)malloc(ulen+1+rlen+1+plen+1);

	strcpy((s08bits*)str,(s08bits*)uname);
	str[ulen]=':';
	strcpy((s08bits*)str+ulen+1,(s08bits*)realm);
	str[ulen+1+rlen]=':';
	strcpy((s08bits*)str+ulen+1+rlen+1,(s08bits*)upwd);

	MD5_Init(&ctx);
	MD5_Update(&ctx,str,ulen+1+rlen+1+plen);
	MD5_Final(key,&ctx);
	free(str);

	return 0;
}

#endif

/******* Log ************/

static FILE* _rtpfile = NULL;

void reset_rtpprintf(void)
{
	if(_rtpfile) {
		fclose(_rtpfile);
		_rtpfile = NULL;
	}
}

static void set_rtpfile(void)
{
	if (!_rtpfile) {
		char fn[129];
		sprintf(fn, "/var/log/turn_%d.log", (int) getpid());
		_rtpfile = fopen(fn, "w");
		if (!_rtpfile) {
			sprintf(fn, "/var/tmp/turn_%d.log", (int) getpid());
			_rtpfile = fopen(fn, "w");
			if (!_rtpfile) {
				sprintf(fn, "/tmp/turn_%d.log", (int) getpid());
				_rtpfile = fopen(fn, "w");
				if (!_rtpfile) {
					sprintf(fn, "turn_%d.log", (int) getpid());
					_rtpfile = fopen(fn, "w");
					if (!_rtpfile)
						_rtpfile = stdout;
				}
			}
		}
	}
}

void rtpprintf(const char *format, ...)
{
	set_rtpfile();
	va_list args;
	va_start (args, format);
	vfprintf(_rtpfile,format, args);
	fflush(_rtpfile);
	va_end (args);
}

int vrtpprintf(const char *format, va_list args)
{
	set_rtpfile();
	vfprintf(_rtpfile,format, args);
	fflush(_rtpfile);
	return 0;
}

//////////////////////////////////////////////////////////////////
