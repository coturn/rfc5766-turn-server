#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

#bin/peer -L 127.0.0.1
bin/peer -L ::1
#bin/peer -d lo -L ::1
