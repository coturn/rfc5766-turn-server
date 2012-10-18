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
#include "udpserver.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: server [options]\n"
  "Options:\n"
  "        -p      port (Default: 3479)\n"
  "        -L      local address\n"
  "        -v      verbose\n";


//////////////////////////////////////////////////

int main(int argc, char **argv)
{
  int port = PEER_DEFAULT_PORT;
  char local_addr[256];
  int verbose=0;
  char c;
  char ifname[1025]="\0";

  srandom((unsigned int)time(NULL));
  
  local_addr[0]=0;
  
  while ((c = getopt(argc, argv, "d:p:L:v")) != -1)
    switch(c) {
    case 'd':
      strcpy(ifname,optarg);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'L':
      strncpy(local_addr, optarg, sizeof(local_addr)-1);
      break;
    case 'v':
      verbose = 1;
      break;
    default:
      fprintf(stderr, "%s\n", Usage);
      exit(1);
    }
  
  server_type* server = start_udp_server(verbose, ifname, local_addr, port);
  run_udp_server(server);
  clean_udp_server(server);
  
  return 0;
}

