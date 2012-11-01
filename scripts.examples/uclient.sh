#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

#testapps/bin/uclient -y -z -n 1000 -m 100 -l 172 127.0.0.1
testapps/bin/uclient -n 1000 -m 10 -l 170 -e ::1 -g 127.0.0.1

