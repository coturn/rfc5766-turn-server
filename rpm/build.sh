#!/bin/bash

TURNVERSION=2.6.7.0

BUILDDIR=~/rpmbuild
ARCH=`uname -p`
TURNSERVER_SVN_URL=http://rfc5766-turn-server.googlecode.com/svn/trunk/

# Required packages

PACKS="postgresql-devel hiredis-devel"

sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACKS}"
    exit -1
fi

# TURN

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

# Make binary tarball

cd ${BUILDDIR}/RPMS/${ARCH}
mkdir -p di
mv *debuginfo* di
mv *devel* di

cat <<EOF >install.sh
#!/bin/sh
sudo rpm -i --force *.rpm
EOF

chmod a+x install.sh

tar cvfz turnserver-${TURNVERSION}-rpms-${ARCH}.tar.gz *.rpm install.sh
