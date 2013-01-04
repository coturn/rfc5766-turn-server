#!/bin/sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=turn.examples/bin/:../turn.examples/bin:${PATH} peer -L 127.0.0.1
