#!/bin/bash
#
# Startup script for TURN Server
#
# chkconfig: 345 85 15
# description: RFC 5766 TURN Server
#
# processname: turnserver
# pidfile: /var/run/turnserver.pid
# config: /etc/turnserver/turnserver.conf
#
### BEGIN INIT INFO
# Provides: turnserver
# Required-Start: $local_fs $network
# Short-Description: RFC 5766 TURN Server
# Description: RFC 5766 TURN Server
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

turn=/usr/bin/turnserver
prog=turnserver
pidfile=/var/run/$prog.pid
lockfile=/var/lock/subsys/$prog
user=turnserver
RETVAL=0

[ -f /etc/sysconfig/$prog ] && . /etc/sysconfig/$prog

start() {
	echo -n $"Starting $prog: "
	# there is something at end of this output which is needed to
	# report proper [ OK ] status in CentOS scripts
	daemon --pidfile=$pidfile --user=$user $turn $OPTIONS
	RETVAL=$?
	echo
	[ $RETVAL = 0 ] && touch $lockfile
}

stop() {
	echo -n $"Stopping $prog: "
	killproc $turn
	RETVAL=$?
	echo
	[ $RETVAL = 0 ] && rm -f $lockfile $pidfile
}

[ -z "$OPTIONS" ] && OPTIONS="-c /etc/turnserver/turnserver.conf -o --no-stdout-log"

# See how we were called.
case "$1" in
	start)
		start
		;;
	stop)
		stop
		;;
	status)
		status $turn
		RETVAL=$?
		;;
	restart)
		stop
		start
		;;
	condrestart)
		if [ -f /var/run/$prog.pid ] ; then
			stop
			start
		fi
		;;
	*)
		echo $"Usage: $prog {start|stop|restart|condrestart|status|help}"
		exit 1
esac

exit $RETVAL
