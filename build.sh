#!/bin/sh

testlibraw() {
    ${CC} ${TMPCPROGC} -o ${TMPCPROGB} ${OSCFLAGS} ${OSLIBS} -${1} 2>/dev/null
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	echo "Do not use -${1}"
	return 0
    else
	OSLIBS="${OSLIBS} -${1}"
	return 1
    fi
}

testlib() {
    testlibraw l${1}
}

pthread_testlib() {

    testlibraw pthread
    ER=$?
    if [ ${ER} -eq 0 ] ; then
    	testlib pthread
    fi

    ${CC} ${TH_TMPCPROGC} -o ${TH_TMPCPROGB} ${OSCFLAGS} ${OSLIBS} 2>/dev/null
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	${CC} ${TH_TMPCPROGC} -o ${TH_TMPCPROGB} ${OSCFLAGS} ${OSLIBS} -D_GNU_SOURCE 2>/dev/null
	ER=$?
	if ! [ ${ER} -eq 0 ] ; then
	    echo "Do not use pthreads"
	    return 0
	else 
	    echo "Older GNU pthread library found"
	    OSCFLAGS="${OSCFLAGS} -D_GNU_SOURCE"
	    return 1
	fi
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

#############################
# Adjustments for Solaris
#############################

SYSTEM=`uname`

if [ "${SYSTEM}" = "SunOS" ] ; then
# Solaris ? is this you ?!
    OSCFLAGS="${OSCFLAGS} -D__EXTENSIONS__ -D_XOPEN_SOURCE=500"
fi

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
    pthread_mutexattr_settype(0,PTHREAD_MUTEX_RECURSIVE);
    return (int)pthread_create(0,0,0,0);
}
!

##########################
# What is our compiler ?
##########################

if [ -z "${CC}" ] ; then
    CC=cc
    ${CC} ${TMPCPROGC} ${OSCFLAGS} -o ${TMPCPROGB}
	ER=$?
	if ! [ ${ER} -eq 0 ] ; then
		CC=gcc
    	${CC} ${TMPCPROGC} ${OSCFLAGS} -o ${TMPCPROGB}
		ER=$?
		if ! [ ${ER} -eq 0 ] ; then
			CC=clang
    		${CC} ${TMPCPROGC} ${OSCFLAGS} -o ${TMPCPROGB}
			ER=$?
			if ! [ ${ER} -eq 0 ] ; then
				CC=unknown
			fi
		fi
	fi
fi

echo "Compiler: ${CC}"

${CC} ${TMPCPROGC} ${OSCFLAGS} -o ${TMPCPROGB}
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

${CC} ${GNUOSCFLAGS} ${TMPCPROGC} ${OSCFLAGS} -o ${TMPCPROGB} 2>/dev/null
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
    echo "SSL lib found."
else
    echo "ERROR: OpenSSL development libraries are not installed properly in /usr/local."
    echo "Abort."
    exit
fi

testlib crypto
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Crypto SSL lib found."
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
    echo "Libevent2 found."
else
    echo "ERROR: Libevent2 development libraries are not installed properly in /usr/local."
    echo "See the INSTALL file."
    echo "Abort."
    exit
fi

testlib event_openssl
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Libevent2-openssl found."
else
    echo "ERROR: Libevent2 development libraries are not compiled with OpenSSL support."
    echo "TLS will be disabled."
    TURN_NO_TLS="-DTURN_NO_TLS"
fi

if [ -z "${TURN_NO_THREADS}" ] ; then
	testlib event_pthreads
	ER=$?
	if ! [ ${ER} -eq 0 ] ; then
    	echo "Libevent2 pthreads found."
	else
    	echo "WARNING: Libevent2 development libraries are not compiled with threads support."
    	echo "Using single-thread mode."
		TURN_NO_THREADS="-DTURN_NO_THREADS"
	fi
fi

###############################
# So, what we have now:
###############################

OSCFLAGS="${OSCFLAGS} ${TURN_NO_THREADS} ${TURN_NO_TLS} -D__USE_OPENSSL__"

echo make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" $@

###############################
# Run make:
###############################

make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" -f Makefile.all $@

