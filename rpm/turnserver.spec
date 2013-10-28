Name:		turnserver
Version:	2.6.6.1
Release:	0%{dist}
Summary:	RFC5766 TURN Server

Group:		System Environment/Libraries
License:	BSD
URL:		https://code.google.com/p/rfc5766-turn-server/ 
Source0:	https://rfc5766-turn-server.googlecode.com/files/%{name}-%{version}.tar.gz

BuildRequires:	gcc, make, redhat-rpm-config
BuildRequires:	openssl-devel, libevent-devel >= 2.0.0, mysql-devel
BuildRequires:	postgresql-devel epel-release hiredis-devel
Requires:	openssl, libevent >= 2.0.0, mysql-libs, postgresql-libs
Requires:	epel-release hiredis perl-DBI perl-libwww-perl


%description
The TURN Server is a VoIP media traffic NAT traversal server and gateway. It
can be used as a general-purpose network traffic TURN server/gateway, too.

This implementation also includes some extra features. Supported RFCs:

TURN specs:
- RFC 5766 - base TURN specs
- RFC 6062 - TCP relaying TURN extension
- RFC 6156 - IPv6 extension for TURN
- Experimental DTLS support as client protocol.

STUN specs:
- RFC 3489 - "classic" STUN
- RFC 5389 - base "new" STUN specs
- RFC 5769 - test vectors for STUN protocol testing
- RFC 5780 - NAT behavior discovery support

The implementation fully supports the following client-to-TURN-server protocols:
- UDP (per RFC 5766)
- TCP (per RFC 5766 and RFC 6062)
- TLS (per RFC 5766 and RFC 6062); SSL3/TLS1.0/TLS1.1/TLS1.2; SSL2 wrapping
  supported
- DTLS (experimental non-standard feature)

Supported relay protocols:
- UDP (per RFC 5766)
- TCP (per RFC 6062)

Supported user databases (for user repository, with passwords or keys, if
authentication is required):
- Flat files
- MySQL
- PostgreSQL
- Redis

Redis can also be used for status and statistics storage and notification.

Supported TURN authentication mechanisms:
- short-term
- long-term
- TURN REST API (a modification of the long-term mechanism, for time-limited
  secret-based authentication, for WebRTC applications)

The load balancing can be implemented with the following tools (either one or a
combination of them):
- network load-balancer server
- DNS-based load balancing
- built-in ALTERNATE-SERVER mechanism.


%package 	utils
Summary:	TURN client utils
Group:		System Environment/Libraries
Requires:	turnserver-client-libs = %{version}-%{release}

%description 	utils
This package contains the TURN client utils.

%package 	client-libs
Summary:	TURN client library
Group:		System Environment/Libraries
Requires:	openssl, libevent >= 2.0.0

%description	client-libs
This package contains the TURN client library.

%package 	client-devel
Summary:	TURN client development headers.
Group:		Development/Libraries
Requires:	turnserver-client-libs = %{version}-%{release}

%description 	client-devel
This package contains the TURN client development headers.

%prep
%setup -q -n %{name}-%{version}

%build
PREFIX=%{_prefix} CONFDIR=%{_sysconfdir}/%{name} EXAMPLESDIR=%{_datadir}/%{name} \
	MANPREFIX=%{_datadir} LIBDIR=%{_libdir} MORECMD=cat ./configure
make

%install
rm -rf $RPM_BUILD_ROOT
DESTDIR=$RPM_BUILD_ROOT make install
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/rc.d/init.d
install -m755 rpm/turnserver.init.el \
		$RPM_BUILD_ROOT/%{_sysconfdir}/rc.d/init.d/turnserver
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig
install -m644 rpm/turnserver.sysconfig \
		$RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/turnserver
mv $RPM_BUILD_ROOT/%{_sysconfdir}/%{name}/turnserver.conf.default \
	$RPM_BUILD_ROOT/%{_sysconfdir}/%{name}/turnserver.conf
mv $RPM_BUILD_ROOT/%{_sysconfdir}/%{name}/turnuserdb.conf.default \
	$RPM_BUILD_ROOT/%{_sysconfdir}/%{name}/turnuserdb.conf

%clean
rm -rf "$RPM_BUILD_ROOT"

%pre
%{_sbindir}/groupadd -r turnserver 2> /dev/null || :
%{_sbindir}/useradd -r -g turnserver -s /bin/false -c "TURN Server daemon" -d \
		%{_datadir}/%{name} turnserver 2> /dev/null || :

%post
/sbin/chkconfig --add turnserver

%preun
/sbin/service turnserver stop > /dev/null 2>&1
/sbin/chkconfig --del turnserver

%files
%defattr(-,root,root)
%{_bindir}/turnserver
%{_bindir}/turnadmin
%{_mandir}/man1/rfc5766-turn-server.1.gz
%{_mandir}/man1/turnserver.1.gz
%{_mandir}/man1/turnadmin.1.gz
%dir %attr(-,turnserver,turnserver) %{_sysconfdir}/%{name}
%config(noreplace) %attr(0644,turnserver,turnserver) %{_sysconfdir}/%{name}/turnserver.conf
%config(noreplace) %attr(0644,turnserver,turnserver) %{_sysconfdir}/%{name}/turnuserdb.conf
%config(noreplace) %{_sysconfdir}/sysconfig/turnserver
%config %{_sysconfdir}/rc.d/init.d/turnserver
%dir %{_docdir}/%{name}
%{_docdir}/%{name}/INSTALL
%{_docdir}/%{name}/postinstall.txt
%{_docdir}/%{name}/README.turnadmin
%{_docdir}/%{name}/README.turnserver
%{_docdir}/%{name}/schema.sql
%{_docdir}/%{name}/schema.stats.redis
%{_docdir}/%{name}/schema.userdb.redis
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/schema.sql
%{_datadir}/%{name}/schema.stats.redis
%{_datadir}/%{name}/schema.userdb.redis
%{_datadir}/%{name}/testredisdbsetup.sh
%dir %{_datadir}/%{name}/etc
%{_datadir}/%{name}/etc/turn_server_cert.pem
%{_datadir}/%{name}/etc/turn_server_pkey.pem
%{_datadir}/%{name}/etc/turnserver.conf
%{_datadir}/%{name}/etc/turnuserdb.conf
%dir %{_datadir}/%{name}/scripts
%{_datadir}/%{name}/scripts/peer.sh
%{_datadir}/%{name}/scripts/readme.txt
%dir %{_datadir}/%{name}/scripts/basic
%{_datadir}/%{name}/scripts/basic/dos_attack.sh
%{_datadir}/%{name}/scripts/basic/relay.sh
%{_datadir}/%{name}/scripts/basic/tcp_client.sh
%{_datadir}/%{name}/scripts/basic/tcp_client_c2c_tcp_relay.sh
%{_datadir}/%{name}/scripts/basic/udp_c2c_client.sh
%{_datadir}/%{name}/scripts/basic/udp_client.sh
%dir %{_datadir}/%{name}/scripts/loadbalance
%{_datadir}/%{name}/scripts/loadbalance/master_relay.sh
%{_datadir}/%{name}/scripts/loadbalance/slave_relay_1.sh
%{_datadir}/%{name}/scripts/loadbalance/slave_relay_2.sh
%{_datadir}/%{name}/scripts/loadbalance/tcp_c2c_tcp_relay.sh
%{_datadir}/%{name}/scripts/loadbalance/udp_c2c.sh
%dir %{_datadir}/%{name}/scripts/longtermsecure
%{_datadir}/%{name}/scripts/longtermsecure/secure_dos_attack.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_dtls_client.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_dtls_client_cert.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_relay.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_relay_cert.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_tcp_client.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_tcp_client_c2c_tcp_relay.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_tls_client.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_tls_client_c2c_tcp_relay.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_udp_c2c.sh
%{_datadir}/%{name}/scripts/longtermsecure/secure_udp_client.sh
%dir %{_datadir}/%{name}/scripts/longtermsecuredb
%{_datadir}/%{name}/scripts/longtermsecuredb/secure_relay_with_db_mysql.sh
%{_datadir}/%{name}/scripts/longtermsecuredb/secure_relay_with_db_psql.sh
%{_datadir}/%{name}/scripts/longtermsecuredb/secure_relay_with_db_redis.sh
%dir %{_datadir}/%{name}/scripts/restapi
%{_datadir}/%{name}/scripts/restapi/secure_relay_secret.sh
%{_datadir}/%{name}/scripts/restapi/secure_relay_secret_with_db_mysql.sh
%{_datadir}/%{name}/scripts/restapi/secure_relay_secret_with_db_psql.sh
%{_datadir}/%{name}/scripts/restapi/secure_relay_secret_with_db_redis.sh
%{_datadir}/%{name}/scripts/restapi/secure_udp_client_with_secret.sh
%{_datadir}/%{name}/scripts/restapi/shared_secret_maintainer.pl
%dir %{_datadir}/%{name}/scripts/selfloadbalance
%{_datadir}/%{name}/scripts/selfloadbalance/secure_dos_attack.sh
%{_datadir}/%{name}/scripts/selfloadbalance/secure_relay.sh
%dir %{_datadir}/%{name}/scripts/shorttermsecure
%{_datadir}/%{name}/scripts/shorttermsecure/secure_relay_short_term_mech.sh
%{_datadir}/%{name}/scripts/shorttermsecure/secure_tcp_client_c2c_tcp_relay_short_term.sh
%{_datadir}/%{name}/scripts/shorttermsecure/secure_udp_client_short_term.sh


%files 		utils
%defattr(-,root,root)
%{_bindir}/turnutils_peer
%{_bindir}/turnutils_stunclient
%{_bindir}/turnutils_uclient
%{_mandir}/man1/turnutils.1.gz
%{_mandir}/man1/turnutils_peer.1.gz
%{_mandir}/man1/turnutils_stunclient.1.gz
%{_mandir}/man1/turnutils_uclient.1.gz
%dir %{_docdir}/%{name}
%{_docdir}/%{name}/README.turnutils
%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/etc
%{_datadir}/%{name}/etc/turn_client_cert.pem
%{_datadir}/%{name}/etc/turn_client_pkey.pem

%files		client-libs
%{_libdir}/libturnclient.a

%files		client-devel
%dir %{_includedir}/turn
%{_includedir}/turn/ns_turn_defs.h
%dir %{_includedir}/turn/client
%{_includedir}/turn/client/ns_turn_ioaddr.h
%{_includedir}/turn/client/ns_turn_msg_addr.h
%{_includedir}/turn/client/ns_turn_msg_defs.h
%{_includedir}/turn/client/ns_turn_msg.h
%{_includedir}/turn/client/TurnMsgLib.h

%changelog
* Sun Oct 27 2013
  - Updated for version 2.6.6.1
* Sun Oct 27 2013
  - Updated for version 2.6.6.0
* Fri May 3 2013 Peter Dunkley <peter.dunkley@crocodilertc.net>
  - First version
