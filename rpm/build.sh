#!/bin/bash

. ./build.settings.sh

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
svn export ${TURNSERVER_SVN_URL}/trunk turnserver-${TURNVERSION}
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
rm -rf turnserver-${TURNVERSION}
mkdir turnserver-${TURNVERSION}
mv *.rpm turnserver-${TURNVERSION}/

cat <<EOF >turnserver-${TURNVERSION}/install.sh
#!/bin/sh
for i in *.rpm ; do
  sudo rpm -Uvh \${i}
  ER=\$?
  if ! [ \${ER} -eq 0 ] ; then
    sudo rpm -ivh --force \${i}
    ER=\$?
    if ! [ \${ER} -eq 0 ] ; then
      echo "ERROR: cannot install package \${i}"
      exit -1
    fi
  fi
done
EOF

chmod a+x turnserver-${TURNVERSION}/install.sh

PLATFORM=`cat ${BUILDDIR}/platform`

tar cvfz turnserver-${TURNVERSION}-${PLATFORM}-${ARCH}.tar.gz turnserver-${TURNVERSION}
