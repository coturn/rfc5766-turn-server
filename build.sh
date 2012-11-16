#!/bin/sh

SYSTEM=`uname`

if [ "${SYSTEM}" = "SunOS" ] ; then
# Solaris
    OSLIBS+="-lsocket -lnsl"
fi

GNUOSCFLAGS="-Werror -Wall -Wextra -Wformat-security -Wnested-externs -Wstrict-prototypes  -Wmissing-prototypes -Wpointer-arith -Winline -Wcast-qual -Wredundant-decls"

OSCFLAGS=

if [ -z "${CC}" ] ; then
    CC=cc
else
    if [ "${CC}" = "gcc" ] ; then
	OSCFLAGS="${GNUOSCFLAGS}"
    else
	if [ "${CC}" = "clang" ] ; then
	    OSCFLAGS="${GNUOSCFLAGS}"
	fi
    fi
fi

if [ -z "${OSCFLAGS}" ] ; then  
    COMPSIGN=`${CC} --version 2>/dev/null | grep -i gcc | cut -b 1`
    RETRES=$?
    if [ ${RETRES} -eq 0 ] ; then
	if [ ${COMPSIGN} ] ; then
	    OSCFLAGS="${GNUOSCFLAGS}"
	fi
    fi
fi

if [ -z "${OSCFLAGS}" ] ; then  
    COMPSIGN=`${CC} --version 2>/dev/null | grep -i clang | cut -b 1`
    RETRES=$?
    if [ ${RETRES} -eq 0 ] ; then
	if [ ${COMPSIGN} ] ; then
	    OSCFLAGS="${GNUOSCFLAGS}"
	fi
    fi
fi

if [ -z "${OSCFLAGS}" ] ; then  
    COMPSIGN=`${CC} --version 2>/dev/null | grep -i "Free Software Foundation" | cut -b 1`
    RETRES=$?
    if [ ${RETRES} -eq 0 ] ; then
	if [ ${COMPSIGN} ] ; then
	    OSCFLAGS="${GNUOSCFLAGS}"
	fi
    fi
fi

make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" $@
