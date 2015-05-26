#!/bin/bash

# CentOS7 preparation script.

CPWD=`pwd`

. ./common.pre.build.sh

cd ${CPWD}

# Common packs

PACKS="libevent-devel mariadb-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
    cd ${CPWD}
    exit -1
fi

# EPEL (for hiredis)

sudo yum -y install epel
 
# Platform file

cd ${CPWD}
echo "CentOS7" > ${BUILDDIR}/platform

echo "#!/bin/sh" > ${BUILDDIR}/install.sh
echo "sudo yum -y install epel" > ${BUILDDIR}/install.sh

cd ${CPWD}
