#!/bin/sh

txt2man -t TURN -I turnserver -I turnadmin -I turnutils -I turnutils_uclient -I turnutils_stunclient -I turnutils_rfc5769check -I turnutils_peer -B "TURN Server" README.turnserver > man/man1/turnserver.1

txt2man -t TURN -I turnserver -I turnadmin -I turnutils -I turnutils_uclient -I turnutils_stunclient -I turnutils_rfc5769check -I turnutils_peer -B "TURN Server" README.turnadmin > man/man1/turnadmin.1

txt2man -t TURN -I turnserver -I turnadmin -I turnutils -I turnutils_uclient -I turnutils_stunclient -I turnutils_rfc5769check -I turnutils_peer -B "TURN Server" README.turnutils > man/man1/turnutils.1
