/*
 * Copyright (C) 2012 Citrix Systems
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

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ns_turn_utils.h"
#include "apputils.h"
#include "stun_buffer.h"

////////////////////////////////////////////////////

static int run_stunclient(const char* rip, int rport, const char* lip) {

  int udp_fd = -1;
  ioa_addr local_addr;
  ioa_addr remote_addr;

  stun_buffer buf;

  memset((void *) &remote_addr, 0, sizeof(struct sockaddr_storage));
  if(make_ioa_addr((const u08bits*)rip, rport, &remote_addr)<0)
    err(-1,NULL);

  memset((void *) &local_addr, 0, sizeof(struct sockaddr_storage));

  if(*lip) {
    if(make_ioa_addr((const u08bits*)lip, 0, &local_addr)<0)
      err(-1,NULL);
  }

  udp_fd = socket(remote_addr.ss.ss_family, SOCK_DGRAM, 0);
  if (udp_fd < 0)
    err(-1,NULL);

  if(*lip) {
    if(addr_bind(udp_fd,&local_addr)<0)
      err(-1,NULL);
  }

  stun_prepare_binding_request(&buf);

  {
    int len=0;
    int slen=get_ioa_addr_len(&remote_addr);
      
    do {
      len = sendto(udp_fd, buf.buf, buf.len, 0, 
		   (struct sockaddr*)&remote_addr,(socklen_t)slen);
    } while(len<0 && ((errno==EINTR)||(errno==ENOBUFS)||(errno==EAGAIN)));

    if(len<0)
      err(-1,NULL);

  }

  {
    int len = 0;
    u08bits *ptr=buf.buf;
    int recvd=0;
    const int to_recv=sizeof(buf.buf);

    do {
      len = recv(udp_fd, ptr, to_recv-recvd, 0);
      if(len>0) {
	recvd+=len;
	ptr+=len;
	break;
      }
    } while(len<0 && ((errno==EINTR)||(errno==EAGAIN)));

    if(recvd>0) len=recvd;
    buf.len=len;

    if(stun_is_command_message(&buf)) {

      if(stun_is_response(&buf)) {

	if(stun_is_success_response(&buf)) {
	  
	  if(stun_is_binding_response(&buf)) {
	    
	    ioa_addr reflexive_addr;
	    addr_set_any(&reflexive_addr);
	    if(stun_attr_get_first_addr(&buf, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, 
					&reflexive_addr,NULL)>=0) {
	      addr_debug_print(1, &reflexive_addr,"UDP reflexive addr");
	    } else {
	      printf("Cannot read the response\n");
	    }
	  } else {
	    printf("Wrong type of response\n");
	  }
	} else {
	  printf("The response is an error\n");
	}
      } else {
	printf("The response is not a reponse message\n");
      }
    } else {
      printf("The response is not a STUN message\n");
    }
  }

  close(udp_fd);

  return 0;
}

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: stunclient [options] address\n"
  "Options:\n"
  "        -p      remote port (Default: 3478)\n"
  "        -L      local address\n";

//////////////////////////////////////////////////

int main(int argc, char **argv)
{
  int port = DEFAULT_STUN_PORT;
  char local_addr[256];
  char c=0;

  srandom((unsigned int)time(NULL));
  
  memset(local_addr, 0, sizeof(local_addr));
  
  while ((c = getopt(argc, argv, "p:L:")) != -1) {
    switch(c) {
    case 'p':
      port = atoi(optarg);
      break;
    case 'L':
      strncpy(local_addr, optarg, sizeof(local_addr)-1);
      break;
    default:
      fprintf(stderr,"%s\n", Usage);
      exit(1);
    }
  }

  if(optind>=argc) {
    fprintf(stderr, "%s\n", Usage);
    exit(-1);
  }

  run_stunclient(argv[optind], port, local_addr);

  return 0;
}
