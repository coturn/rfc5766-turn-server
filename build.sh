#!/bin/sh

if [ -e /lib/libsocket.so ] ; then
  OSLIBS+=" -lsocket"
fi

if [ -e /lib/libnsl.so ] ; then
  OSLIBS+=" -lnsl"
fi

make OSLIBS="${OSLIBS}" $@
