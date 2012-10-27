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

#include "uclient.h"
#include "ns_turn_utils.h"
#include "apputils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/////////////// extern definitions /////////////////////

int clmessage_length=0;
int use_send_method=0;
int c2c=0;
int udp_verbose=0;
int hang_on=0;
ioa_addr peer_addr;
int no_rtcp = 0;
int default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
int dont_fragment = 0;

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: uclient [options] address\n"
  "Options:\n"
  "        -l      message length (Default: 100 Bytes)\n"
  "        -p      remote port (Default: 3478)\n"
  "        -n      number of messages to send (Default: 5)\n"
  "        -L      local address\n"
  "        -v      verbose\n"
  "        -m      number of clients (default is 1)\n"
  "        -s      use send method\n"
  "        -y      use client-to-client connections\n"
  "        -h      hang on indefinitely after the last sent packet\n"
  "        -e      peer address\n"
  "        -r      peer port (default 3479)\n"
  "        -c      no rtcp connections\n"
  "        -x      IPv6 relayed address requested\n"
  "        -g      include DONT_FRAGMENT option\n";

//////////////////////////////////////////////////

int main(int argc, char **argv)
{
  int port = RELAY_DEFAULT_PORT;
  int length = 100;
  int messagenumber = 5;
  char local_addr[256];
  char c;
  int mclient=1;
  unsigned char ifname[1025]="\0";
  char peer_address[129]="\0";
  int peer_port = PEER_DEFAULT_PORT;
    
  srandom((unsigned int)time(NULL));
  
  memset(local_addr, 0, sizeof(local_addr));
  
  while ((c = getopt(argc, argv, "d:p:l:n:L:m:e:r:vsyhcxg")) != -1) {
    switch(c) {
    case 'g':
      dont_fragment = 1;
      break;
    case 'd':
      strcpy((char*)ifname,optarg);
      break;
    case 'x':
	    default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
	    break;
    case 'l':
      length = atoi(optarg);
      break;
    case 's':
      use_send_method=1;
      break;
    case 'n':
      messagenumber = atoi(optarg);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'L':
      strncpy(local_addr, optarg, sizeof(local_addr)-1);
      break;
    case 'e':
      strncpy(peer_address, optarg, sizeof(peer_address)-1);
      break;
    case 'r':
      peer_port = atoi(optarg);
      break;
    case 'v':
      udp_verbose = 1;
      break;
    case 'h':
      hang_on = 1;
      break;
    case 'c':
      no_rtcp = 1;
      break;
    case 'm':
      mclient = atoi(optarg);
      break;
    case 'y':
      c2c=1;
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

  if(!c2c) {
    if (make_ioa_addr((const u08bits*) peer_address, peer_port,
		      &peer_addr) < 0)
      return -1;
  }

  start_mclient(argv[optind], port, ifname, local_addr, length, messagenumber, mclient);

  return 0;
}
