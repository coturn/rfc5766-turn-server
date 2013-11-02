#!/bin/bash

TURNVERSION=2.6.6.2

BUILDDIR=~/rpmbuild
ARCH=`uname -i`
LIBEVENTVERSION=2.0.21

# Libevent2:

sudo yum install make
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install gcc
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install redhat-rpm-config
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install rpm-build
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install doxygen
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install openssl-devel
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install wget
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

rm -rf ${BUILDDIR}
mkdir ${BUILDDIR}
mkdir ${BUILDDIR}/SOURCES
mkdir ${BUILDDIR}/SPECS

cd ${BUILDDIR}/SOURCES
wget https://github.com/downloads/libevent/libevent/libevent-${LIBEVENTVERSION}-stable.tar.gz
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

cd ${BUILDDIR}/SPECS
wget https://raw.github.com/crocodilertc/libevent/master/libevent.spec
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

rpmbuild -ba ${BUILDDIR}/SPECS/libevent.spec
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi


# TURN

sudo rpm -i ${BUILDDIR}/RPMS/${ARCH}/libevent-${LIBEVENTVERSION}-1.el6.${ARCH}.rpm

sudo rpm -i ${BUILDDIR}/RPMS/${ARCH}/libevent-devel-${LIBEVENTVERSION}-1.el6.${ARCH}.rpm

sudo rpm -Uvh http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm

sudo yum install mysql-devel
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install postgresql-devel
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

sudo yum install hiredis-devel
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

mkdir ${BUILDDIR}/tmp
cd ${BUILDDIR}/tmp
svn export http://rfc5766-turn-server.googlecode.com/svn/trunk/ turnserver-${TURNVERSION}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

tar zcf ${BUILDDIR}/SOURCES/turnserver-${TURNVERSION}.tar.gz turnserver-${TURNVERSION}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

rpmbuild -ta ${BUILDDIR}/SOURCES/turnserver-${TURNVERSION}.tar.gz
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

 