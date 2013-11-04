#!/bin/bash

# Fedora preparation script.

. ./common.pre.build.sh

PACKS="mariadb-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
    exit -1
fi

echo "CentOS6" > ${BUILDDIR}/platform
