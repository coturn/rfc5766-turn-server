#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

bin/turnserver -L 127.0.0.1 -L ::1 -E 127.0.0.1 -E ::1 -f -m 3 --min-port=32355 --max-port=65535 --no-tls




