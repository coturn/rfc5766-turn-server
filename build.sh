#!/bin/sh

SYSTEM=`uname`

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

if [ "${SYSTEM}" = "SunOS" ] ; then
# Solaris
    OSLIBS="-lsocket -lnsl -ldl"
    if [ -z "${OSCFLAGS}" ] ; then
	#SolStudio compiler
        OSCFLAGS=${OSCFLAGS}" -xc99"
    else
	#GCC/CLANG compilers
	OSCFLAGS=${OSCFLAGS}" --std=c99"
    fi
    OSCFLAGS=${OSCFLAGS}" -D__EXTENSIONS__ -D_XOPEN_SOURCE=600"
fi

ISLINUX=`echo ${SYSTEM} | grep -i linux | cut -b 1`
if [ ${ISLINUX} ] ; then
#Linux
  OSLIBS="-ldl"
fi

ISBSD=`echo ${SYSTEM} | grep -i bsd | cut -b 1`
if [ ${ISBSD} ] ; then
#BSD
  OSLIBS=
fi

make OSLIBS="${OSLIBS}" OSCFLAGS="${OSCFLAGS}" $@
