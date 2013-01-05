#!/bin/sh
#
# This is a script for the peer application,
# for testing only purposes. It opens UDP echo-like socket
# on IP address 127.0.0.1 and default port 3479. 
#

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=turn.examples/bin/:../turn.examples/bin:${PATH} peer -L 127.0.0.1
