#!/bin/sh
#
# This is an example of a script for DOS attack emulation

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

while [ 0 ] ; do

PATH=examples/bin/:../bin/:bin/:${PATH} turnutils_uclient -O -D -n 1 -m 12 -e 127.0.0.1 -g $@ ::1

PATH=examples/bin/:../bin/:bin/:${PATH} turnutils_uclient -O -n 1 -m 12 -y -s $@ 127.0.0.1

PATH=examples/bin/:../bin:bin/:${PATH} turnutils_uclient -O -t -n 1 -m 12 -e 127.0.0.1 -g $@ ::1

PATH=examples/bin/:../bin:bin/:${PATH} turnutils_uclient -O -T -n 1 -m 12 -y -s $@ 127.0.0.1

done
