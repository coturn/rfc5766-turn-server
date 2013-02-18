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

#include "uclient.h"
#include "ns_turn_utils.h"
#include "apputils.h"
#include "session.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/opensslv.h>

/////////////// extern definitions /////////////////////

int clmessage_length=100;
int use_send_method=0;
int c2c=0;
int clnet_verbose=0;
int use_tcp=0;
int use_secure=0;
char cert_file[1025]="\0";
char pkey_file[1025]="\0";
int hang_on=0;
ioa_addr peer_addr;
int no_rtcp = 0;
int default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
int dont_fragment = 0;
u08bits g_uname[STUN_MAX_USERNAME_SIZE+1];
u08bits g_upwd[STUN_MAX_PWD_SIZE+1];
int use_fingerprints = 1;
SSL_CTX *root_tls_ctx = NULL;

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: uclient [options] address\n"
  "Options:\n"
  "	-l	Message length (Default: 100 Bytes).\n"
  "	-t	TCP (default - UDP).\n"
  "	-S	Secure connection: TLS for TCP, DTLS for UDP.\n"
  "	-i	Certificate file (for secure connections only).\n"
  "	-k	Private key file (for secure connections only).\n"
  "	-p	TURN server port (Default: 3478 unsecure, 5349 secure).\n"
  "	-n	Number of messages to send (Default: 5).\n"
  "	-d	Local interface device (optional).\n"
  "	-L	Local address.\n"
  "	-v	Verbose.\n"
  "	-m	Number of clients (default is 1).\n"
  "	-s	Use send method.\n"
  "	-y	Use client-to-client connections.\n"
  "	-h	Hang on indefinitely after the last sent packet.\n"
  "	-e	Peer address.\n"
  "	-r	Peer port (default 3480).\n"
  "	-c	No rtcp connections.\n"
  "	-x	IPv6 relayed address requested.\n"
  "	-g	Include DONT_FRAGMENT option\n."
  "	-z	Per-session packet interval in milliseconds (default is 20 ms).\n"
  "	-u	STUN/TURN user name.\n"
  "	-w	STUN/TURN user password.\n";

//////////////////////////////////////////////////

int main(int argc, char **argv)
{
	int port = 0;
	int messagenumber = 5;
	char local_addr[256];
	char c;
	int mclient = 1;
	unsigned char ifname[1025] = "\0";
	char peer_address[129] = "\0";
	int peer_port = PEER_DEFAULT_PORT;

	set_execdir();

	srandom((unsigned int) time(NULL));

	memset(local_addr, 0, sizeof(local_addr));

	while ((c = getopt(argc, argv, "d:p:l:n:L:m:e:r:u:w:i:k:z:vsyhcxgtS")) != -1) {
		switch (c){
		case 'z':
			RTP_PACKET_INTERVAL = atoi(optarg);
			break;
		case 'u':
			STRCPY(g_uname, optarg);
			break;
		case 'w':
			STRCPY(g_upwd, optarg);
			break;
		case 'g':
			dont_fragment = 1;
			break;
		case 'd':
			STRCPY(ifname, optarg);
			break;
		case 'x':
			default_address_family
							= STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
			break;
		case 'l':
			clmessage_length = atoi(optarg);
			break;
		case 's':
			use_send_method = 1;
			break;
		case 'n':
			messagenumber = atoi(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'L':
			STRCPY(local_addr, optarg);
			break;
		case 'e':
			STRCPY(peer_address, optarg);
			break;
		case 'r':
			peer_port = atoi(optarg);
			break;
		case 'v':
			clnet_verbose = 1;
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
			c2c = 1;
			break;
		case 't':
			use_tcp = 1;
			break;
		case 'S':
			use_secure = 1;
			break;
		case 'i':
		{
			char* fn = find_config_file(optarg,1);
			if(!fn) {
				fprintf(stderr,"ERROR: file %s not found\n",optarg);
				exit(-1);
			}
			strcpy(cert_file,fn);
			free(fn);
			break;
		}
		case 'k':
		{
			char* fn = find_config_file(optarg,1);
			if(!fn) {
				fprintf(stderr,"ERROR: file %s not found\n",optarg);
				exit(-1);
			}
			STRCPY(pkey_file,fn);
			free(fn);
			break;
		}
		default:
			fprintf(stderr, "%s\n", Usage);
			exit(1);
		}
	}

	if(port == 0) {
		if(use_secure)
			port = DEFAULT_STUN_TLS_PORT;
		else
			port = DEFAULT_STUN_PORT;
	}

	if (clmessage_length < (int) sizeof(message_info))
		clmessage_length = (int) sizeof(message_info);

	if (optind >= argc) {
		fprintf(stderr, "%s\n", Usage);
		exit(-1);
	}

	if (!c2c) {
		if (make_ioa_addr((const u08bits*) peer_address, peer_port, &peer_addr) < 0)
			return -1;
	}

	/* SSL Init ==>> */

	if(use_secure) {

		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();

		if(use_tcp) {
			root_tls_ctx = SSL_CTX_new(TLSv1_client_method());
		} else {
#if !defined(BIO_CTRL_DGRAM_QUERY_MTU)
		  fprintf(stderr,"ERROR: DTLS is not supported.\n");
		  exit(-1);
#else
		  if(OPENSSL_VERSION_NUMBER < 0x10000000L) {
		  	TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: OpenSSL version is rather old, DTLS may not be working correctly.\n");
		  }
		  root_tls_ctx = SSL_CTX_new(DTLSv1_client_method());
#endif
		}
		SSL_CTX_set_cipher_list(root_tls_ctx, "DEFAULT");

		if (!SSL_CTX_use_certificate_file(root_tls_ctx, cert_file,
			SSL_FILETYPE_PEM)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\nERROR: no certificate found!\n");
			exit(-1);
		}

		if (!SSL_CTX_use_PrivateKey_file(root_tls_ctx, pkey_file,
						SSL_FILETYPE_PEM)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\nERROR: no private key found!\n");
			exit(-1);
		}

		if (!SSL_CTX_check_private_key(root_tls_ctx)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\nERROR: invalid private key!\n");
			exit(-1);
		}

		SSL_CTX_set_verify_depth(root_tls_ctx, 2);
		SSL_CTX_set_read_ahead(root_tls_ctx, 1);
	}

	start_mclient(argv[optind], port, ifname, local_addr, messagenumber, mclient);

	return 0;
}
