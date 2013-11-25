#!/bin/sh
#
# This is an example of a script to run a DOS attack 
# in a "secure" environment on a server with 
# self-load-balancing option 
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

export SLEEP_TIME=3

while [ 0 ] ; do 

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -g -u ninefingers -w youhavetoberealistic -y $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u ninefingers -w youhavetoberealistic $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e ::1 -g -u ninefingers -w youhavetoberealistic -s $@ 127.0.0.1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -t -n 30 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -T -n 10 -m 10 -l 170 -y -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -T -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -y -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -t -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero $@ ::1 &

sleep ${SLEEP_TIME}

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -g -u ninefingers -w youhavetoberealistic -y -p 12345 $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u ninefingers -w youhavetoberealistic -p 12345 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e ::1 -g -u ninefingers -w youhavetoberealistic -s -p 12345 $@ 127.0.0.1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -t -n 30 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero -p 12345 $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -T -n 10 -m 10 -l 170 -y -g -u gorst -w hero -p 12345 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -T -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -y -g -u gorst -w hero -p 12345 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -t -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero -p 12345 $@ ::1 &

sleep ${SLEEP_TIME}

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -g -u ninefingers -w youhavetoberealistic -y -p 12346 $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u ninefingers -w youhavetoberealistic -p 12346 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e ::1 -g -u ninefingers -w youhavetoberealistic -s -p 12346 $@ 127.0.0.1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -t -n 30 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero -p 12346 $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -T -n 10 -m 10 -l 170 -y -g -u gorst -w hero -p 12346 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -T -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -y -g -u gorst -w hero -p 12346 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -t -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero -p 12346 $@ ::1 &

sleep ${SLEEP_TIME}

type killall >>/dev/null 2>>/dev/null
ER=$?
if [ ${ER} -eq 0 ] ; then
  killall turnutils_uclient >>/dev/null 2>>/dev/null
else
  type pkill >>/dev/null 2>>/dev/null
  ER=$?
  if [ ${ER} -eq 0 ] ; then
    pkill turnutils_u >>/dev/null 2>>/dev/null
  else
    sleep 10
  fi
fi

done


