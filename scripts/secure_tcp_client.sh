#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=turn.examples/bin/:../turn.examples/bin:${PATH} uclient -t -n 1000 -m 10 -l 170 -e 127.0.0.1 -g -u gorst -w hero -s ::1

