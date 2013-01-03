#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=turn.apps.examples/bin/:../turn.apps.examples/bin:${PATH} uclient -n 1000 -m 10 -l 170 -e 127.0.0.1 -g -u ninefingers -w youhavetoberealistic ::1

