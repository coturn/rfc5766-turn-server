#!/bin/bash

TURNVERSION=2.6.6.2

BUILDDIR=~/rpmbuild
ARCH=`uname -i`
LIBEVENT2VERSION=2.0.21
LIBEVENT2DISTRO=libevent-${LIBEVENT2VERSION}-stable.tar.gz
EPELRPM=epel-release-6-8.noarch.rpm

# DIRS

mkdir -p ${BUILDDIR}
mkdir -p ${BUILDDIR}/SOURCES
mkdir -p ${BUILDDIR}/SPECS
mkdir -p ${BUILDDIR}/RPMS
mkdir -p ${BUILDDIR}/tmp

# Common packs

PACKS="make gcc redhat-rpm-config rpm-build doxygen openssl-devel wget svn"
sudo yum install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACKS}"
    exit -1
fi

# Libevent2:

cd ${BUILDDIR}/SOURCES
if ! [ -f  ${LIBEVENT2DISTRO} ] ; then
    wget https://github.com/downloads/libevent/libevent/${LIBEVENT2DISTRO}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	exit -1
    fi
fi

cd ${BUILDDIR}/SPECS
if ! [ -f libevent.spec ] ; then
    wget https://raw.github.com/crocodilertc/libevent/master/libevent.spec
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	exit -1
    fi
fi

rpmbuild -ba ${BUILDDIR}/SPECS/libevent.spec
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-${LIBEVENT2VERSION}-1.el6.${ARCH}.rpm
sudo rpm -i --force ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-devel-${LIBEVENT2VERSION}-1.el6.${ARCH}.rpm
sudo rpm -i --force ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    exit -1
fi

# TURN

cd ${BUILDDIR}/RPMS
if ! [ -f ${EPELRPM} ] ; then
    wget http://download.fedoraproject.org/pub/epel/6/i386/${EPELRPM}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	exit -1
    fi
fi

PACK=epel-release-6-8.noarch.rpm
sudo yum install ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    sudo yum update ${PACK}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	echo "Cannot install package ${PACK}"
	exit -1
    fi
fi

PACKS="mysql-devel postgresql-devel hiredis-devel"
sudo yum install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACKS}"
    exit -1
fi

cd ${BUILDDIR}/tmp
rm -rf turnserver-${TURNVERSION}
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

 
