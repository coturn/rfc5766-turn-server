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
#include "ns_turn_msg_addr.h"
#include "apputils.h"

#include <pthread.h>

/////////////////////////////////////////////////////////////////

int addr_to_buffer(const ioa_addr* addr, unsigned char* saddr8) {
  uint16_t *saddr16=(uint16_t*)(saddr8);
  saddr8[0]=0;
  if(addr->ss.ss_family==AF_INET) {
    saddr8[1]=0;
    uint32_t *saddr32=(uint32_t*)(saddr8);
    saddr8[0]=8;
    saddr16[1]=addr->s4.sin_port;
    saddr32[1]=addr->s4.sin_addr.s_addr;
  } else if(addr->ss.ss_family==AF_INET6) {
    saddr8[1]=1;
    saddr8[0]=20;
    saddr16[1]=addr->s6.sin6_port;
    memcpy(saddr8+4,&(addr->s6.sin6_addr),16);
  }
  return saddr8[0];
}

int addr_from_buffer(ioa_addr* addr, const unsigned char* saddr8) {
  int ret=-1;
  if(addr && saddr8) {
    addr_set_any(addr);
    if(saddr8[0]) {
      const uint16_t *saddr16=(const uint16_t*)(saddr8);
      if(saddr8[0]==8 && saddr8[1]==0) {
	addr->ss.ss_family=AF_INET;
	const uint32_t *saddr32=(const uint32_t*)(saddr8);
	addr->s4.sin_port=saddr16[1];
	addr->s4.sin_addr.s_addr=saddr32[1];
	ret=0;
      } else if(saddr8[0]==20 && saddr8[1]==1) {
	addr->ss.ss_family=AF_INET6;
	addr->s6.sin6_port=saddr16[1];
	memcpy(&(addr->s6.sin6_addr),saddr8+4,16);
	ret=0;
      }
    }
  }
  return ret;
}

/*********************** Sockets *********************************/

int set_sock_buf_size(evutil_socket_t fd, int sz) {

  if(setsockopt(fd,SOL_SOCKET,SO_RCVBUF,(const void*)(&sz),(socklen_t)sizeof(sz))<0) {
    perror("Cannot set socket size");
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot set sock size on %d\n",fd);
    return -1;
  }
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

    return 0;
  }
}

int sock_bind_to_device(evutil_socket_t fd, const unsigned char* ifname) {

  if(fd>=0 && ifname && ifname[0]) {

#if defined(SO_BINDTODEVICE)

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, (const char*)ifname, sizeof(ifr.ifr_name));

    if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
      perror("cannot bind socket to device");
      return -1;
    }

#endif

    return 0;
  }

  return 0;
}

int addr_connect(evutil_socket_t fd, const ioa_addr* addr)
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

int set_socket_df(evutil_socket_t fd, int family, int value) {

  UNUSED_ARG(fd);
  UNUSED_ARG(family);

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
#error CANNOT SET SOCKET DF FLAG (3) : UNKNOWN PLATFORM
#endif

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
    return 1;
  case EMSGSIZE:
    return 1;
  case EBADF:
    /* Invalid socket.
     * Must close connection.
     */
    return 0;
    break;
  case EHOSTDOWN:
    /* Host is down.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    return 1;
  case ECONNRESET:
  case ECONNREFUSED:
    /* Connection reset by peer.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    return 1;
    break;
  case ENOMEM:
    /* Out of memory.
     * Must close connection.
     */
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Out of memory!\n");
    return 0;
    break;
  case EACCES:
    /* Permission denied.
     * Just ignore, we might be blocked
     * by some firewall policy. Try again
     * and hope for the best.
     */
    return 1;
    break;
  default:
    /* Something unexpected happened */
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Unexpected error! (errno = %d)\n", errno);
    return 0;
    break;
  }
  return 0;
}

//////////////// trivial  address mapping /////////////////////

int ioa_addr_map_to_real(const ioa_addr *ca, ioa_addr *ca_real) {
  addr_cpy(ca_real,ca);
  return 0;
}

int ioa_addr_map_from_real(const ioa_addr *ca_real, ioa_addr *ca) {
  addr_cpy(ca,ca_real);
  return 0;
}

//////////////////////////////////////////////////////////////
