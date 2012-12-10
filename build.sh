#!/bin/sh

testlib() {
    ${CC} ${TMPCPROGC} -o ${TMPCPROGB} ${OSLIBS} -l${1} 2>/dev/null
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	echo "Do not use -l${1}"
	return 0
    else
	OSLIBS="${OSLIBS} -l${1}"
	return 1
    fi
}

#########################
# To be set:
OSCFLAGS=
OSLIBS="-L/usr/local/lib/event2/ -L/usr/local/lib/ -Llib"
#########################

TMPDIR="."

if [ -d /var/tmp ] ; then
  TMPDIR="/var/tmp"
elif [ -d /tmp ] ; then
  TMPDIR=/tmp
fi

echo Use TMP dir ${TMPDIR}

TMPCPROG=test
TMPCPROGC=${TMPDIR}/${TMPCPROG}.c
TMPCPROGB=${TMPDIR}/${TMPCPROG}

cat > ${TMPCPROGC} <<!
int main() {
    return 0;
}
!

if [ -z "${CC}" ] ; then
    CC=cc
fi

echo "Compiler: ${CC}"

${CC} ${TMPCPROGC} -o ${TMPCPROGB}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "ERROR: cannot use compiler ${CC} properly"
    exit
fi

GNUOSCFLAGS="-Wall -Wextra -Wformat-security -Wnested-externs -Wstrict-prototypes  -Wmissing-prototypes -Wpointer-arith -Wcast-qual -Wredundant-decls"

${CC} ${GNUOSCFLAGS} ${TMPCPROGC} -o ${TMPCPROGB} 2>/dev/null
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Not an ordinary GNU or Clang compiler"
else
    OSCFLAGS="${OSCFLAGS} ${GNUOSCFLAGS}"
fi

testlib socket
testlib nsl
testlib dl
testlib pthread

testlib ssl
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "SSL lib installed."
else
    echo "ERROR: OpenSSL development libraries are not installed properly in /usr/local."
    echo "Abort."
    exit
fi

testlib crypto
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Crypto SSL lib installed."
else
    echo "ERROR: OpenSSL development libraries are not installed properly in /usr/local."
    echo "Abort."
    exit
fi

testlib event
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Libevent2 installed."
else
    echo "ERROR: Libevent2 development libraries are not installed properly in /usr/local."
    echo "See the INSTALL file."
    echo "Abort."
    exit
fi

testlib event_pthreads
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Libevent2 pthreads installed."
else
    echo "ERROR: Libevent2 development libraries are not compiled with threads support."
    echo "See the INSTALL file."
    echo "Abort."
    exit
fi

testlib event_openssl
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Libevent2-openssl installed."
else
    echo "ERROR: Libevent2 development libraries are not compiled with OpenSSL support."
    echo "See the INSTALL file."
    echo "Abort."
    exit
fi

SYSTEM=`uname`

if [ "${SYSTEM}" = "SunOS" ] ; then
# Solaris
    OSCFLAGS=${OSCFLAGS}" -D__EXTENSIONS__ -D_XOPEN_SOURCE=500"
fi

echo make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" $@

make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" $@ -f Makefile.all

