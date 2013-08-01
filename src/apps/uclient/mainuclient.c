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
#include "stun_buffer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/opensslv.h>

/////////////// extern definitions /////////////////////

int clmessage_length=100;
int do_not_use_channel=0;
int c2c=0;
int clnet_verbose=TURN_VERBOSE_NONE;
int use_tcp=0;
int use_secure=0;
int use_short_term=0;
char cert_file[1025]="\0";
char pkey_file[1025]="\0";
int hang_on=0;
ioa_addr peer_addr;
int no_rtcp = 0;
int default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
int dont_fragment = 0;
u08bits g_uname[STUN_MAX_USERNAME_SIZE+1];
st_password_t g_upwd;
int use_fingerprints = 1;
SSL_CTX *root_tls_ctx[4];
int root_tls_ctx_num = 0;
u08bits relay_transport = STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE;
unsigned char client_ifname[1025] = "\0";
int passive_tcp = 0;
int mandatory_channel_padding = 0;
int negative_test = 0;
int dos = 0;

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: uclient [flags] [options] turn-server-ip-address\n"
  "Flags:\n"
  "	-t	TCP (default - UDP).\n"
  "	-T	TCP relay transport (default - UDP). Implies options -t, -y, -c, and ignores \n"
  "		options -s, -e, -r and -g.\n"
  "	-P	Passive TCP (RFC6062 with active peer). Implies -T.\n"
  "	-S	Secure connection: TLS for TCP, DTLS for UDP.\n"
  "	-v	Verbose.\n"
  "	-s	Use send method.\n"
  "	-y	Use client-to-client connections.\n"
  "	-h	Hang on indefinitely after the last sent packet.\n"
  "	-c	No rtcp connections.\n"
  "	-x	IPv6 relayed address requested.\n"
  "	-g	Include DONT_FRAGMENT option.\n"
  "	-A	Use short-term credentials mechanism. By default, the program uses\n"
  "		the long-term credentials mechanism if authentication is required.\n"
  "	-D	Mandatory channel padding (like in pjnath).\n"
  "	-N	Negative tests (some limited cases only).\n"
  "	-O	DOS attack mode (quick connect and exit).\n"
  "Options:\n"
  "	-l	Message length (Default: 100 Bytes).\n"
  "	-i	Certificate file (for secure connections only).\n"
  "	-k	Private key file (for secure connections only).\n"
  "	-p	TURN server port (Default: 3478 unsecure, 5349 secure).\n"
  "	-n	Number of messages to send (Default: 5).\n"
  "	-d	Local interface device (optional).\n"
  "	-L	Local address.\n"
  "	-m	Number of clients (default is 1).\n"
  "	-e	Peer address.\n"
  "	-r	Peer port (default 3480).\n"
  "	-z	Per-session packet interval in milliseconds (default is 20 ms).\n"
  "	-u	STUN/TURN user name.\n"
  "	-w	STUN/TURN user password.\n"
  "	-W	TURN REST API authentication secret. Is not compatible with -A option.\n"
  "	-C	TURN REST API username/timestamp separator symbol (character). The default value is ':'.\n";

//////////////////////////////////////////////////

#if !defined(SHA_DIGEST_LENGTH)
#define SHA_DIGEST_LENGTH (20)
#endif

int main(int argc, char **argv)
{
	int port = 0;
	int messagenumber = 5;
	char local_addr[256];
	int c;
	int mclient = 1;
	char peer_address[129] = "\0";
	int peer_port = PEER_DEFAULT_PORT;

	int use_auth_secret_with_timestamp = 0;
	char rest_api_separator = ':';
	char auth_secret[1025]="\0";

	set_logfile("stdout");

	set_execdir();

	set_system_parameters(0);

	ns_bzero(local_addr, sizeof(local_addr));

	while ((c = getopt(argc, argv, "d:p:l:n:L:m:e:r:u:w:i:k:z:W:C:vsyhcxgtTSAPDNO")) != -1) {
		switch (c){
		case 'O':
			dos = 1;
			break;
		case 'C':
			rest_api_separator=*optarg;
			break;
		case 'D':
			mandatory_channel_padding = 1;
			break;
		case 'N':
			negative_test = 1;
			break;
		case 'z':
			RTP_PACKET_INTERVAL = atoi(optarg);
			break;
		case 'A':
			use_short_term = 1;
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
			STRCPY(client_ifname, optarg);
			break;
		case 'x':
			default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
			break;
		case 'l':
			clmessage_length = atoi(optarg);
			break;
		case 's':
			do_not_use_channel = 1;
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
			clnet_verbose = TURN_VERBOSE_NORMAL;
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
		case 'P':
			passive_tcp = 1;
			/* implies 'T': */
		case 'T':
			relay_transport = STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE;
			break;
		case 'S':
			use_secure = 1;
			break;
		case 'W':
			use_auth_secret_with_timestamp = 1;
			STRCPY(auth_secret,optarg);
			break;
		case 'i':
		{
			char* fn = find_config_file(optarg,1);
			if(!fn) {
				fprintf(stderr,"ERROR: file %s not found\n",optarg);
				exit(-1);
			}
			STRCPY(cert_file,fn);
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

	if(use_auth_secret_with_timestamp) {

		if(use_short_term) {
			fprintf(stderr,"ERROR: You cannot use authentication secret (REST API) with short-term credentials mechanism.\n");
			exit(-1);
		}
		{
			char new_uname[1025];
			if(g_uname[0]) {
			  snprintf(new_uname,sizeof(new_uname),"%lu%c%s",(unsigned long)time(NULL),rest_api_separator, (char*)g_uname);
			} else {
			  snprintf(new_uname,sizeof(new_uname),"%lu", (unsigned long)time(NULL));
			}
			STRCPY(g_uname,new_uname);
		}
		{
			u08bits hmac[1025]="\0";
			unsigned int hmac_len = SHA_DIGEST_LENGTH;

			if(calculate_hmac(g_uname, strlen((char*)g_uname), auth_secret, strlen(auth_secret), hmac, &hmac_len)>=0) {
				size_t pwd_length = 0;
				char *pwd = base64_encode(hmac,hmac_len,&pwd_length);

				if(pwd) {
					if(pwd_length>0) {
						ns_bcopy(pwd,g_upwd,pwd_length);
						g_upwd[pwd_length]=0;
					}
				}
				free(pwd);
			}
		}
	}

	if(is_TCP_relay()) {
		dont_fragment = 0;
		no_rtcp = 1;
		c2c = 1;
		use_tcp = 1;
		do_not_use_channel = 1;
	}

	if(port == 0) {
		if(use_secure)
			port = DEFAULT_STUN_TLS_PORT;
		else
			port = DEFAULT_STUN_PORT;
	}

	if (clmessage_length < (int) sizeof(message_info))
		clmessage_length = (int) sizeof(message_info);

	const int max_header = 100;
	if(clmessage_length > (int)(STUN_BUFFER_SIZE-max_header)) {
		fprintf(stderr,"Message length was corrected to %d\n",(STUN_BUFFER_SIZE-max_header));
		clmessage_length = (int)(STUN_BUFFER_SIZE-max_header);
	}

	if (optind >= argc) {
		fprintf(stderr, "%s\n", Usage);
		exit(-1);
	}

	if (!c2c) {
		if (make_ioa_addr((const u08bits*) peer_address, peer_port, &peer_addr) < 0)
			return -1;
		if(peer_addr.ss.ss_family == AF_INET6)
			default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;

	}

	/* SSL Init ==>> */

	if(use_secure) {

		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();

		if(use_tcp) {
			root_tls_ctx[0] = SSL_CTX_new(SSLv3_client_method());
			root_tls_ctx_num++;
			root_tls_ctx[1] = SSL_CTX_new(TLSv1_client_method());
			root_tls_ctx_num++;
#if defined(SSL_TXT_TLSV1_1)
			root_tls_ctx[2] = SSL_CTX_new(TLSv1_1_client_method());
			root_tls_ctx_num++;
#if defined(SSL_TXT_TLSV1_2)
			root_tls_ctx[3] = SSL_CTX_new(TLSv1_2_client_method());
			root_tls_ctx_num++;
#endif
#endif
		} else {
#if defined(TURN_NO_DTLS)
		  fprintf(stderr,"ERROR: DTLS is not supported.\n");
		  exit(-1);
#else
		  if(OPENSSL_VERSION_NUMBER < 0x10000000L) {
		  	TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: OpenSSL version is rather old, DTLS may not be working correctly.\n");
		  }
		  root_tls_ctx[0] = SSL_CTX_new(DTLSv1_client_method());
		  root_tls_ctx_num++;
#endif
		}

		int sslind = 0;
		for(sslind = 0; sslind<root_tls_ctx_num; sslind++) {
			if (!SSL_CTX_use_certificate_file(root_tls_ctx[sslind], cert_file,
							SSL_FILETYPE_PEM)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\nERROR: no certificate found!\n");
				exit(-1);
			}

			if (!SSL_CTX_use_PrivateKey_file(root_tls_ctx[sslind], pkey_file,
						SSL_FILETYPE_PEM)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\nERROR: no private key found!\n");
				exit(-1);
			}

			if (!SSL_CTX_check_private_key(root_tls_ctx[sslind])) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\nERROR: invalid private key!\n");
				exit(-1);
			}

			SSL_CTX_set_verify_depth(root_tls_ctx[sslind], 2);
			SSL_CTX_set_read_ahead(root_tls_ctx[sslind], 1);
		}
	}

	start_mclient(argv[optind], port, client_ifname, local_addr, messagenumber, mclient);

	return 0;
}
