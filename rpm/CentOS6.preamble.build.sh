#!/bin/bash

# CentOS6 preparation script.

. ./common.preamble.build.sh

EPELRPM=epel-release-6-8.noarch.rpm
LIBEVENT_MAJOR_VERSION=2
LIBEVENT_VERSION=${LIBEVENT_MAJOR_VERSION}.0.21
LIBEVENT_DISTRO=libevent-${LIBEVENT_VERSION}-stable.tar.gz
LIBEVENT_SPEC_DIR=libevent.rpm
LIBEVENTSPEC_SVN_URL=${TURNSERVER_SVN_URL}/${LIBEVENT_SPEC_DIR}/
LIBEVENT_SPEC_FILE=libevent.spec

# Common packs

PACKS="mysql-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
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

!cd ${BUILDDIR}/SPECS
rpmbuild -ba ${BUILDDIR}/SPECS/${LIBEVENT_SPEC_FILE}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-${LIBEVENT_MAJOR_VERSION}*.rpm
sudo rpm ${RPMOPTIONS} ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-devel*.rpm
sudo rpm ${RPMOPTIONS} ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    exit -1
fi

# EPEL (for hiredis)

cd ${BUILDDIR}/RPMS
if ! [ -f ${EPELRPM} ] ; then
    wget ${WGETOPTIONS} http://download.fedoraproject.org/pub/epel/6/i386/${EPELRPM}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	exit -1
    fi
fi

PACK=epel-release-6-8.noarch.rpm
sudo rpm ${RPMOPTIONS} ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package ${PACK}"
    exit -1
fi
 
