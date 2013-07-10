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

#include "ns_turn_utils.h"
#include "ns_turn_msg.h"

#include "apputils.h"

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

/*********************** Sockets *********************************/

void read_spare_buffer(evutil_socket_t fd)
{
	if(fd >= 0) {
		static char buffer[65536];
		recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
	}
}

int set_sock_buf_size(evutil_socket_t fd, int sz)
{
  while(sz>0) {
	  if(setsockopt(fd,SOL_SOCKET,SO_RCVBUF,(const void*)(&sz),(socklen_t)sizeof(sz))<0) {
		  sz = sz / 2;
	  } else {
		  break;
	  }
  }

  if(sz<1) {
	  perror("Cannot set socket size");
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot set sock size %d on fd %d\n",sz,fd);
	  return -1;
  }

  return 0;
}

int socket_tcp_set_keepalive(evutil_socket_t fd)
{
#ifdef SO_KEEPALIVE
    /* Set the keepalive option active */
    {
	    const int on = 1;
	    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const void*)&on, (socklen_t) sizeof(on));
    }
#else
    UNUSED_ARG(fd);
#endif

#ifdef SO_NOSIGPIPE
    {
    	 const int on = 1;
    	 setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const void*)&on, (socklen_t) sizeof(on));
    }
#endif

    return 0;
}

int socket_set_reusable(evutil_socket_t fd) {
  if(fd<0) return -1;
  else {
    evutil_make_listen_socket_reuseable(fd);

#ifdef SO_REUSEPORT
    {
      const int on = 1;
      setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
    }
#endif

#ifdef SO_REUSEADDR
    {
      const int on = 1;
      int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
      if(ret<0)
	perror("SO_REUSEADDR");
    }
#endif

    return 0;
  }
}

int sock_bind_to_device(evutil_socket_t fd, const unsigned char* ifname) {

	if (fd >= 0 && ifname && ifname[0]) {

		socket_set_reusable(fd);

#if defined(SO_BINDTODEVICE)

		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));

		strncpy(ifr.ifr_name, (const char*) ifname, sizeof(ifr.ifr_name));

		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
			if (errno == EPERM)
				perror("You must obtain superuser privileges to bind a socket to device");
			else
				perror("Cannot bind socket to device");

			return -1;
		}

		return 0;

#endif

	}

	return 0;
}

int addr_connect(evutil_socket_t fd, const ioa_addr* addr, int *out_errno)
{
	if (!addr || fd < 0)
		return -1;
	else {
		int err = 0;
		do {
			if (addr->ss.ss_family == AF_INET) {
				err = connect(fd, (const struct sockaddr *) addr, sizeof(struct sockaddr_in));
			} else if (addr->ss.ss_family == AF_INET6) {
				err = connect(fd, (const struct sockaddr *) addr, sizeof(struct sockaddr_in6));
			} else {
				return -1;
			}
		} while (err < 0 && errno == EINTR);

		if(out_errno)
		  *out_errno = errno;

		if (err < 0 && errno != EINPROGRESS)
			perror("Connect");

		return err;
	}
}

int addr_bind(evutil_socket_t fd, const ioa_addr* addr)
{
	if (!addr || fd < 0)
		return -1;
	else {
		int ret = -1;

		socket_set_reusable(fd);

		if (addr->ss.ss_family == AF_INET) {
			do {
				ret = bind(fd, (const struct sockaddr *) addr, sizeof(struct sockaddr_in));
			} while (ret < 0 && errno == EINTR);
		} else if (addr->ss.ss_family == AF_INET6) {
			const int off = 0;
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *) &off, sizeof(off));
			do {
				ret = bind(fd, (const struct sockaddr *) addr, sizeof(struct sockaddr_in6));
			} while (ret < 0 && errno == EINTR);
		} else {
			return -1;
		}
		return ret;
	}
}

int addr_get_from_sock(evutil_socket_t fd, ioa_addr *addr)
{

	if (fd < 0 || !addr)
		return -1;
	else {

		ioa_addr a;
		a.ss.ss_family = AF_INET6;
		socklen_t socklen = get_ioa_addr_len(&a);
		if (getsockname(fd, (struct sockaddr*) &a, &socklen) < 0) {
			a.ss.ss_family = AF_INET;
			socklen = get_ioa_addr_len(&a);
			if (getsockname(fd, (struct sockaddr*) &a, &socklen) < 0) {
				return -1;
			}
		}

		addr_cpy(addr, &a);

		return 0;
	}
}

/////////////////// MTU /////////////////////////////////////////

int set_socket_df(evutil_socket_t fd, int family, int value)
{

  int ret=0;

#if defined(IP_DONTFRAG) && defined(IPPROTO_IP) //BSD
  {
    const int val=value;
    /* kernel sets DF bit on outgoing IP packets */
    if(family==AF_INET) {
      ret = setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val));
    } else {
#if defined(IPV6_DONTFRAG) && defined(IPPROTO_IPV6)
      ret = setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &val, sizeof(val));
#else
#error CANNOT SET IPV6 SOCKET DF FLAG (1)
#endif
    }
    if(ret<0) {
      int err=errno;
      perror("set socket df:");
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: set sockopt failed: fd=%d, err=%d, family=%d\n",__FUNCTION__,fd,err,family);
    }
  }
#elif defined(IPPROTO_IP) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO) && defined(IP_PMTUDISC_DONT) //LINUX
  {
    /* kernel sets DF bit on outgoing IP packets */
    if(family==AF_INET) {
      int val=IP_PMTUDISC_DO;
      if(!value) val=IP_PMTUDISC_DONT;
      ret = setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
    } else {
#if defined(IPPROTO_IPV6) && defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO) && defined(IPV6_PMTUDISC_DONT)
      int val=IPV6_PMTUDISC_DO;
      if(!value) val=IPV6_PMTUDISC_DONT;
      ret = setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val, sizeof(val));
#else
#error CANNOT SET IPV6 SOCKET DF FLAG (2)
#endif
    }
    if(ret<0) {
      perror("set DF");
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: set sockopt failed\n",__FUNCTION__);
    }
  }
#else
//CANNOT SET SOCKET DF FLAG (3) : UNKNOWN PLATFORM
  UNUSED_ARG(fd);
  UNUSED_ARG(family);
  UNUSED_ARG(value);
#endif

  return ret;
}

static int get_mtu_from_ssl(SSL* ssl)
{
  int ret = SOSO_MTU;
#if !defined(TURN_NO_DTLS)
  if(ssl)
	  ret = BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);
#else
  UNUSED_ARG(ssl);
#endif
  return ret;
}

static void set_query_mtu(SSL* ssl) {
  if(ssl) {
#if defined(SSL_OP_NO_QUERY_MTU)
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
#else
    ;
#endif
  }
}

int decrease_mtu(SSL* ssl, int mtu, int verbose)
{

	if (!ssl)
		return mtu;

	int new_mtu = get_mtu_from_ssl(ssl);

	if (new_mtu < 1)
		new_mtu = mtu;

	if (new_mtu > MAX_MTU)
		mtu = MAX_MTU;
	if (new_mtu > 0 && new_mtu < MIN_MTU)
		mtu = MIN_MTU;
	else if (new_mtu < mtu)
		mtu = new_mtu;
	else
		mtu -= MTU_STEP;

	if (mtu < MIN_MTU)
		mtu = MIN_MTU;

	set_query_mtu(ssl);
	if (verbose)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "1. mtu to use: %d\n", mtu);

#if !defined(TURN_NO_DTLS)
	SSL_set_mtu(ssl,mtu);
	BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_SET_MTU, mtu, NULL);
#endif

	return mtu;
}

int set_mtu_df(SSL* ssl, evutil_socket_t fd, int family, int mtu, int df_value, int verbose) {

  if(!ssl || fd<0) return 0;

  int ret=set_socket_df(fd, family, df_value);

  if(!mtu) mtu=SOSO_MTU;
  else if(mtu<MIN_MTU) mtu=MIN_MTU;
  else if(mtu>MAX_MTU) mtu=MAX_MTU;

  set_query_mtu(ssl);
  if(verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"3. mtu to use: %d\n",mtu);

#if !defined(TURN_NO_DTLS)

  SSL_set_mtu(ssl,mtu);

  BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_SET_MTU, mtu, NULL);

#endif

  if(verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"4. new mtu: %d\n",get_mtu_from_ssl(ssl));

  return ret;
}

int get_socket_mtu(evutil_socket_t fd, int family, int verbose)
{

	int ret = 0;

	UNUSED_ARG(fd);
	UNUSED_ARG(family);
	UNUSED_ARG(verbose);

#if defined(IP_MTU)
	int val = 0;
	socklen_t slen=sizeof(val);
	if(family==AF_INET) {
		ret = getsockopt(fd, IPPROTO_IP, IP_MTU, &val, &slen);
	} else {
#if defined(IPPROTO_IPV6) && defined(IPV6_MTU)
		ret = getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &val, &slen);
#endif
		;
	}
	if(ret<0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: get IP_MTU sockopt failed\n",__FUNCTION__);
	} else {
		if(verbose) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: IP_MTU=%d\n",__FUNCTION__,val);
	}

	ret = val;
#endif

	if (verbose)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: final=%d\n", __FUNCTION__, ret);

	return ret;
}

//////////////////// socket error handle ////////////////////

int handle_socket_error() {
  switch (errno) {
  case EINTR:
    /* Interrupted system call.
     * Just ignore.
     */
    return 1;
  case ENOBUFS:
    /* No buffers, temporary condition.
     * Just ignore and try later.
     */
    return 1;
  case EAGAIN:
#if defined(EWOULDBLOCK)
#if (EWOULDBLOCK != EAGAIN)
  case EWOULDBLOCK:
#endif
#endif
    return 1;
  case EMSGSIZE:
    return 1;
  case EBADF:
    /* Invalid socket.
     * Must close connection.
     */
    return 0;
  case EHOSTDOWN:
    /* Host is down.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    return 1;
  case ECONNRESET:
  case ECONNREFUSED:
    /* Connection reset by peer. */
    return 0;
  case ENOMEM:
    /* Out of memory.
     * Must close connection.
     */
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Out of memory!\n");
    return 0;
  case EACCES:
    /* Permission denied.
     * Just ignore, we might be blocked
     * by some firewall policy. Try again
     * and hope for the best.
     */
    return 1;
  default:
    /* Something unexpected happened */
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Unexpected error! (errno = %d)\n", errno);
    return 0;
  }
}

//////////////////// Misc utils //////////////////////////////

char *skip_blanks(char* s)
{
	while(*s==' ' || *s=='\t' || *s=='\n')
		++s;

	return s;
}

//////////////////// Config file search //////////////////////

#define Q(x) #x
#define QUOTE(x) Q(x)

#define ETCDIR INSTALL_PREFIX/etc/
#define QETCDIR QUOTE(ETCDIR)

static const char *config_file_search_dirs[] = {"./", "./etc/", "../etc/", "/etc/", "/usr/local/etc/", QETCDIR, NULL };
static char *c_execdir=NULL;

void set_execdir(void)
{
  /* On some systems, this may give us the execution path */
  char *_var = getenv("_");
  if(_var && *_var) {
    _var = strdup(_var);
    char *edir=_var;
    if(edir[0]!='.') 
      edir = strstr(edir,"/");
    if(edir && *edir)
      edir = dirname(edir);
    else
      edir = dirname(_var);
    if(c_execdir)
      free(c_execdir);
    c_execdir = strdup(edir);
    free(_var);
  }
}

void print_abs_file_name(const char *msg1, const char *msg2, const char *fn) 
{
  char absfn[1025];
  absfn[0]=0;

  if(fn) {
    while(fn[0] && fn[0]==' ') ++fn;
    if(fn[0]) {
      if(fn[0]=='/') {
	STRCPY(absfn,fn);
      } else {
	if(fn[0]=='.' && fn[1]=='/')
	  fn+=2;
	if(!getcwd(absfn,sizeof(absfn)-1))
	  absfn[0]=0;
	size_t blen=strlen(absfn);
	if(blen<sizeof(absfn)-1) {
	  strncpy(absfn+blen,"/",sizeof(absfn)-blen);
	  strncpy(absfn+blen+1,fn,sizeof(absfn)-blen-1);
	} else {
	  STRCPY(absfn,fn);
	}
	absfn[sizeof(absfn)-1]=0;
      }
    }
  }
  if(absfn[0]) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s%s file found: %s\n", msg1, msg2, absfn);
  }
}

char* find_config_file(const char *config_file, int print_file_name)
{
	char *full_path_to_config_file = NULL;

	if (config_file && config_file[0]) {
		if (config_file[0] == '/') {
			FILE *f = fopen(config_file, "r");
			if (f) {
				fclose(f);
				full_path_to_config_file = strdup(config_file);
			}
		} else {
			int i = 0;
			size_t cflen = strlen(config_file);

			while (config_file_search_dirs[i]) {
				size_t dirlen = strlen(config_file_search_dirs[i]);
				size_t fnsz = sizeof(char) * (dirlen + cflen + 10);
				char *fn = (char*)malloc(fnsz+1);
				strncpy(fn, config_file_search_dirs[i], fnsz);
				strncpy(fn + dirlen, config_file, fnsz-dirlen);
				fn[fnsz]=0;
				FILE *f = fopen(fn, "r");
				if (f) {
					fclose(f);
					if (print_file_name)
					  print_abs_file_name("","Config",fn);
					full_path_to_config_file = fn;
					break;
				}
				free(fn);
				if(config_file_search_dirs[i][0]!='/' && 
				   config_file_search_dirs[i][0]!='.' &&
				   c_execdir && c_execdir[0]) {
					size_t celen = strlen(c_execdir);
					fnsz = sizeof(char) * (dirlen + cflen + celen + 10);
					fn = (char*)malloc(fnsz+1);
					strncpy(fn,c_execdir,fnsz);
					size_t fnlen=strlen(fn);
					if(fnlen<fnsz) {
					  strncpy(fn+fnlen,"/",fnsz-fnlen);
					  fnlen=strlen(fn);
					  if(fnlen<fnsz) {
					    strncpy(fn+fnlen, config_file_search_dirs[i], fnsz-fnlen);
					    fnlen=strlen(fn);
					    if(fnlen<fnsz) {
					      strncpy(fn+fnlen, config_file, fnsz-fnlen);
					    }
					  }
					}
					fn[fnsz]=0;
					if(strstr(fn,"//")!=fn) {
					  f = fopen(fn, "r");
					  if (f) {
					    fclose(f);
					    if (print_file_name)
					      print_abs_file_name("","Config",fn);
					    full_path_to_config_file = fn;
					    break;
					  }
					}
					free(fn);
				}
				++i;
			}
		}

		if(!full_path_to_config_file) {
			if(strstr(config_file,"etc/")==config_file) {
				return find_config_file(config_file+4, print_file_name);
			}
		}
	}

	return full_path_to_config_file;
}

/////////////////// SYS SETTINGS ///////////////////////

void set_system_parameters(int max_resources)
{
	srandom((unsigned int) time(NULL));
	setlocale(LC_ALL, "C");

	build_base64_decoding_table();

	/* Ignore SIGPIPE from TCP sockets */
	signal(SIGPIPE, SIG_IGN);

	if(max_resources) {
		struct rlimit rlim;
		if(getrlimit(RLIMIT_NOFILE, &rlim)<0) {
			perror("Cannot get system limit");
		} else {
			rlim.rlim_cur = rlim.rlim_max;
			while((setrlimit(RLIMIT_NOFILE, &rlim)<0) && (rlim.rlim_cur>0)) {
				rlim.rlim_cur = rlim.rlim_cur>>1;
			}
		}
	}
}

////////////////////// Base 64 ////////////////////////////

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static size_t mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char*)malloc(*output_length+1);
    if (encoded_data == NULL) return NULL;

    size_t i,j;
    for (i = 0, j = 0; i < input_length;) {

        u32bits octet_a = i < input_length ? data[i++] : 0;
        u32bits octet_b = i < input_length ? data[i++] : 0;
        u32bits octet_c = i < input_length ? data[i++] : 0;

        u32bits triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    encoded_data[*output_length]=0;

    return encoded_data;
}

void build_base64_decoding_table() {

    decoding_table = (char*)malloc(256);

    int i;
    for (i = 0; i < 256; i++)
        decoding_table[(unsigned char) encoding_table[i]] = (char)i;
}

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_base64_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    size_t i,j;
    for (i = 0, j = 0; i < input_length;) {

        u32bits sextet_a = 0;
        if(data[i] != '=')
        	sextet_a = (u32bits)decoding_table[(int)data[i]];
        ++i;
        u32bits sextet_b = 0;
        if(data[i] != '=')
        	sextet_b = (u32bits)decoding_table[(int)data[i]];
        ++i;
        u32bits sextet_c = 0;
        if(data[i] != '=')
        	sextet_c = (u32bits)decoding_table[(int)data[i]];
        ++i;
        u32bits sextet_d = 0;
        if(data[i] != '=')
        	sextet_c = (u32bits)decoding_table[(int)data[i]];

        ++i;

        u32bits triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

/////////////////////////// HMAC ////////////////////////////

#if defined(__USE_OPENSSL__)

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

int calculate_hmac(u08bits *buf, size_t len, const void *key, int key_len, u08bits *hmac, unsigned int *hmac_len)
{
	if (!HMAC(EVP_sha1(), key, key_len, buf, len, hmac, hmac_len)) {
		return -1;
	} else {
		return 0;
	}
}

#else

int calculate_hmac(u08bits *buf, size_t len, const void *key, int key_len, u08bits *hmac, unsigned int *hmac_len)
{
	UNUSED_ARG(buf);
	UNUSED_ARG(len);
	UNUSED_ARG(key);
	UNUSED_ARG(key_len);
	UNUSED_ARG(hmac);
	UNUSED_ARG(hmac_len);

	return -1;
}

#endif

//////////////////////////////////////////////////////////////
