#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=turn.examples/bin/:../turn.examples/bin:${PATH} uclient -S -i example_turn_client_cert.pem -k example_turn_client_pkey.pem -n 1000 -m 10 -l 170 -e 127.0.0.1 -g -u ninefingers -w youhavetoberealistic -s ::1

