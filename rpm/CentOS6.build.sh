#!/bin/bash

TURNVERSION=2.6.6.2

BUILDDIR=~/rpmbuild
ARCH=`uname -p`
LIBEVENT_MAJOR_VERSION=2
LIBEVENT_VERSION=${LIBEVENT_MAJOR_VERSION}.0.21
LIBEVENT_DISTRO=libevent-${LIBEVENT_VERSION}-stable.tar.gz
EPELRPM=epel-release-6-8.noarch.rpm
TURNSERVER_SVN_URL=http://rfc5766-turn-server.googlecode.com/svn/trunk/
LIBEVENT_SPEC_DIR=libevent.rpm
LIBEVENTSPEC_SVN_URL=http://rfc5766-turn-server.googlecode.com/svn/${LIBEVENT_SPEC_DIR}/
LIBEVENT_SPEC_FILE=libevent.spec

WGETOPTIONS="-r --no-check-certificate"

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
if ! [ -f  ${LIBEVENT_DISTRO} ] ; then
    wget ${WGETOPTIONS} https://github.com/downloads/libevent/libevent/${LIBEVENT_DISTRO}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	exit -1
    fi
fi

if ! [ -f ${BUILDDIR}/SPECS/${LIBEVENT_SPEC_FILE} ] ; then 
    cd ${BUILDDIR}/tmp
    rm -rf ${LIBEVENT_SPEC_DIR}
    svn export ${LIBEVENTSPEC_SVN_URL} ${LIBEVENT_SPEC_DIR}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	exit -1
    fi
    
    if ! [ -f ${LIBEVENT_SPEC_DIR}/${LIBEVENT_SPEC_FILE} ] ; then
	echo "ERROR: cannot download ${LIBEVENT_SPEC_FILE} file"
	exit -1
    fi

    cp ${LIBEVENT_SPEC_DIR}/${LIBEVENT_SPEC_FILE} ${BUILDDIR}/SPECS
fi

cd ${BUILDDIR}/SPECS
rpmbuild -ba ${BUILDDIR}/SPECS/${LIBEVENT_SPEC_FILE}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-${LIBEVENT_MAJOR_VERSION}*.rpm
sudo rpm -i --force ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-devel*.rpm
sudo rpm -i --force ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    exit -1
fi

# TURN

cd ${BUILDDIR}/RPMS
if ! [ -f ${EPELRPM} ] ; then
    wget ${WGETOPTIONS} http://download.fedoraproject.org/pub/epel/6/i386/${EPELRPM}
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
svn export ${TURNSERVER_SVN_URL} turnserver-${TURNVERSION}
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

 
