#!/bin/bash

# Common settings script.

TURNVERSION=3.2.3.8
BUILDDIR=~/rpmbuild
ARCH=`uname -p`
TURNSERVER_SVN_URL=http://rfc5766-turn-server.googlecode.com/svn
TURNSERVER_SVN_URL_VER=branches/v3.2

WGETOPTIONS="--no-check-certificate"
RPMOPTIONS="-ivh --force"


