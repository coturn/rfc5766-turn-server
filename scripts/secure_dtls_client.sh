#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

testapps/bin/uclient -S -i etc/test_client_cert.pem -k etc/test_client_pkey.pem -n 1000 -m 10 -l 170 -e ::1 -g -u ninefingers -w youhavetoberealistic 127.0.0.1

