#!/bin/sh

SYSTEM=`uname`

if [ "${SYSTEM}" = "SunOS" ] ; then
# Solaris
    OSLIBS+="-lsocket -lnsl"
fi

GNUCFLAGS="-Werror -Wall -Wextra -Wformat-security -Wnested-externs -Wstrict-prototypes  -Wmissing-prototypes -Wpointer-arith -Winline -Wcast-qual -Wredundant-decls"

CFLAGS=

if [ -z "${CC}" ] ; then
    CC=cc
else
    if [ "${CC}" = "gcc" ] ; then
	CFLAGS="${GNUCFLAGS}"
    else
	if [ "${CC}" = "clang" ] ; then
	    CFLAGS="${GNUCFLAGS}"
	fi
    fi
fi

if [ -z "${CFLAGS}" ] ; then  
    COMPSIGN=`${CC} --version 2>/dev/null | grep -i gcc | cut -b 1`
    RETRES=$?
    if [ ${RETRES} -eq 0 ] ; then
	if [ ${COMPSIGN} ] ; then
	    CFLAGS="${GNUCFLAGS}"
	fi
    fi
fi

if [ -z "${CFLAGS}" ] ; then  
    COMPSIGN=`${CC} --version 2>/dev/null | grep -i clang | cut -b 1`
    RETRES=$?
    if [ ${RETRES} -eq 0 ] ; then
	if [ ${COMPSIGN} ] ; then
	    CFLAGS="${GNUCFLAGS}"
	fi
    fi
fi

if [ -z "${CFLAGS}" ] ; then  
    COMPSIGN=`${CC} --version 2>/dev/null | grep -i "Free Software Foundation" | cut -b 1`
    RETRES=$?
    if [ ${RETRES} -eq 0 ] ; then
	if [ ${COMPSIGN} ] ; then
	    CFLAGS="${GNUCFLAGS}"
	fi
    fi
fi

make OSLIBS="${OSLIBS}" CFLAGS="${CFLAGS}" $@
