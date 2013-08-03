#!/bin/sh
#
# This is an example of a script to run a "secure" TURN DTLS client
# with the long-term credentials mechanism.
#
# Options:
#
# 1) -t is absent, it means that UDP networking is used.
# 2) -S means "secure protocol", that is DTLS in the case of UDP.
# 3) -i sets certificate file for DTLS.
# 4) -k sets private key file for DTLS.
# 5) -n 1000 means 1000 messages per single emulated client. Messages
# are sent with interval of 20 milliseconds, to emulate an RTP stream.
# 6) -m 10 means that 10 clients are emulated.
# 7) -l 170 means that the payload size of the packets is 170 bytes 
# (like average audio RTP packet).
# 8) -e ::1 means that the clients will use peer IPv6 address ::1.
# 9) -g means "set DONT_FRAGMENT parameter in TURN requests".
# 10) -u ninefingers means that if the server challenges the client with 
# authentication challenge, then we use account "ninefingers".
# 11) -w youhavetoberealistic sets the password for the account.
# 12) -s option means that the client will be using "send" mechanism for data.
# 13) 127.0.0.1 (the last parameter) is the TURN Server IP address. 
# We use IPv6 - to - IPv4 here to illustrate how the TURN Server 
# converts the traffic from IPv6 to IPv4 and back.
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

while [ 0 ] ; do 

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -g -u ninefingers -w youhavetoberealistic -y $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u ninefingers -w youhavetoberealistic $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e ::1 -g -u ninefingers -w youhavetoberealistic -s $@ 127.0.0.1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -t -n 30 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -T -n 10 -m 10 -l 170 -y -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -T -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -y -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -t -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero $@ ::1 &

sleep 1

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -g -u ninefingers -w youhavetoberealistic -y -p 12345 $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u ninefingers -w youhavetoberealistic -p 12345 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e ::1 -g -u ninefingers -w youhavetoberealistic -s -p 12345 $@ 127.0.0.1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -t -n 30 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero -p 12345 $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -O -T -n 10 -m 10 -l 170 -y -g -u gorst -w hero -p 12345 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -T -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -y -g -u gorst -w hero -p 12345 $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -O -t -S -i turn_client_cert.pem -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero -p 12345 $@ ::1 &

sleep 2

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


