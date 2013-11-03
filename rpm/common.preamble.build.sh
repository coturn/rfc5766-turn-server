#!/bin/bash

# Common preparation script.

. ./common.build.sh

# Common packs

PACKS="make gcc redhat-rpm-config rpm-build doxygen openssl-devel svn"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACKS}"
    exit -1
fi

