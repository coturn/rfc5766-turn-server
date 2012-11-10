CC ?= cc

AR := ar -r

OSLIBS :=

CFLAGS += -O2 -Werror -Wall -Wextra -Wformat-security -Wnested-externs -Wstrict-prototypes  -Wmissing-prototypes -Wpointer-arith -Winline -Wcast-qual -Wredundant-decls 

LIBEVENT_INCLUDE := /usr/local/include/
LIBEVENT_LIB := -L/usr/local/lib/event2/ -levent -levent_pthreads -lpthread -lmd -lssl

include common.mk
