#!/bin/bash

# Fedora preparation script.

BUILDDIR=~/rpmbuild

# DIRS

mkdir -p ${BUILDDIR}
mkdir -p ${BUILDDIR}/SOURCES
mkdir -p ${BUILDDIR}/SPECS
mkdir -p ${BUILDDIR}/RPMS
mkdir -p ${BUILDDIR}/tmp

# Common packs

PACKS="make gcc redhat-rpm-config rpm-build doxygen openssl-devel svn mariadb-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACKS}"
    exit -1
fi

