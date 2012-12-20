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

pthread_testlib() {
    ${CC} ${TH_TMPCPROGC} -o ${TH_TMPCPROGB} ${OSLIBS} 2>/dev/null
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	echo "Do not use pthreads"
	return 0
    else
	return 1
    fi
}

#########################
# To be set:
#########################
OSCFLAGS=
OSLIBS="-L/usr/local/lib/event2/ -L/usr/local/lib/ -Llib"
TURN_NO_THREADS=
TURN_NO_TLS=

#########################
# Temporary DIR location:
#########################

TMPDIR="."

if [ -d /var/tmp ] ; then
  TMPDIR="/var/tmp"
elif [ -d /tmp ] ; then
  TMPDIR=/tmp
fi

echo Use TMP dir ${TMPDIR}

#########################
# Basic C test programs
#########################

TMPCPROG=__test__ccomp__$$
TMPCPROGC=${TMPDIR}/${TMPCPROG}.c
TMPCPROGB=${TMPDIR}/${TMPCPROG}

cat > ${TMPCPROGC} <<!
int main() {
    return 0;
}
!

TH_TMPCPROG=__test__ccomp__pthread__$$
TH_TMPCPROGC=${TMPDIR}/${TH_TMPCPROG}.c
TH_TMPCPROGB=${TMPDIR}/${TH_TMPCPROG}

cat > ${TH_TMPCPROGC} <<!
#include <pthread.h>
int main() {
    return (int)pthread_create(NULL,NULL,NULL,NULL);
}
!

##########################
# What is out compiler ?
##########################

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

###########################
# Check if we can use GNU
# or Clang compiler flags
###########################

GNUOSCFLAGS="-Wall -Wextra -Wformat-security -Wnested-externs -Wstrict-prototypes  -Wmissing-prototypes -Wpointer-arith -Wcast-qual -Wredundant-decls"

${CC} ${GNUOSCFLAGS} ${TMPCPROGC} -o ${TMPCPROGB} 2>/dev/null
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Not an ordinary GNU or Clang compiler"
else
    OSCFLAGS="${OSCFLAGS} ${GNUOSCFLAGS}"
fi

###########################
# Test some general-purpose
# libraries 
###########################

testlib socket
testlib nsl
testlib dl

###########################
# Can we use multi-threading ?
###########################

testlib pthread

pthread_testlib
ER=$?
if [ ${ER} -eq 0 ] ; then
	echo "WARNING: Cannot find pthread library functions."
	echo "Using single-thread mode."
	TURN_NO_THREADS="-DTURN_NO_THREADS"
fi

###########################
# Test OpenSSL installation
###########################

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
    echo "ERROR: OpenSSL Crypto development libraries are not installed properly in /usr/local."
    echo "Abort."
    exit
fi

###########################
# Test Libevent2 setup
###########################

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

testlib event_openssl
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Libevent2-openssl installed."
else
    echo "ERROR: Libevent2 development libraries are not compiled with OpenSSL support."
    echo "TLS will be disabled."
    TURN_NO_TLS="-DTURN_NO_TLS"
fi

if [ -z "${TURN_NO_THREADS}" ] ; then
	testlib event_pthreads
	ER=$?
	if ! [ ${ER} -eq 0 ] ; then
    	echo "Libevent2 pthreads installed."
	else
    	echo "WARNING: Libevent2 development libraries are not compiled with threads support."
    	echo "Using single-thread mode."
		TURN_NO_THREADS="-DTURN_NO_THREADS"
	fi
fi

#############################
# Adjustments for Solaris
#############################

SYSTEM=`uname`

if [ "${SYSTEM}" = "SunOS" ] ; then
# Solaris ? is this you ?!
    OSCFLAGS="${OSCFLAGS} -D__EXTENSIONS__ -D_XOPEN_SOURCE=500"
fi

###############################
# So, what we have now:
###############################

OSCFLAGS="${OSCFLAGS} ${TURN_NO_THREADS} ${TURN_NO_TLS}"

echo make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" $@

###############################
# Run make:
###############################

make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" $@ -f Makefile.all

