AR = ar -r

CFLAGS+="-O2"

LIBEVENT_INCLUDE += /usr/local/include/
LIBEVENT_LIB += -L/usr/local/lib/event2/ -L/usr/local/lib/ -levent -levent_pthreads -lpthread -lssl -lcrypto

INCFLAGS += -Isrc/apps/common -Isrc/server -Isrc/client -I${LIBEVENT_INCLUDE} 
LIBFLAGS += ${LIBEVENT_LIB} -Llib
LINKFLAGS += ${LIBFLAGS} ${OSLIBS}

CFLAGS += ${INCFLAGS}

MAKE_DEPS += Makefile build.sh

LIBCLIENTTURN_HEADERS = src/ns_turn_defs.h src/client/ns_turn_ioaddr.h src/client/ns_turn_msg.h src/client/ns_turn_msg_addr.h src/client/ns_turn_msg.h src/client/ns_turn_utils.h
LIBCLIENTTURN_DEPS = ${LIBCLIENTTURN_HEADERS} ${MAKE_DEPS} 
LIBCLIENTTURN_OBJS = build/obj/ns_turn_ioaddr.o build/obj/ns_turn_msg_addr.o build/obj/ns_turn_msg.o build/obj/ns_turn_utils.o

LIBSERVERTURN_HEADERS = ${LIBCLIENTTURN_HEADERS} src/server/ns_turn_allocation.h src/server/ns_turn_ioalib.h src/server/ns_turn_khash.h src/server/ns_turn_maps_rtcp.h src/server/ns_turn_maps.h src/server/ns_turn_server.h src/server/ns_turn_session.h 
LIBSERVERTURN_DEPS = ${LIBSERVERTURN_HEADERS} ${MAKE_DEPS} 
LIBSERVERTURN_OBJS = ${LIBCLIENTTURN_OBJS} build/obj/ns_turn_allocation.o build/obj/ns_turn_maps_rtcp.o build/obj/ns_turn_maps.o build/obj/ns_turn_server.o

COMMON_DEPS = ${LIBCLIENTTURN_DEPS} src/apps/common/apputils.c src/apps/common/apputils.h src/apps/common/stun_buffer.c src/apps/common/stun_buffer.h
COMMON_MODS = src/apps/common/apputils.c src/apps/common/stun_buffer.c

IMPL_DEPS = src/apps/relay/ns_ioalib_impl.h src/apps/relay/ns_ioalib_engine_impl.c src/apps/relay/turn_ports.h src/apps/relay/turn_ports.c
IMPL_MODS = src/apps/relay/ns_ioalib_engine_impl.c src/apps/relay/turn_ports.c src/apps/relay/turnmutex.c 

all	:	testapps/bin/stunclient testapps/bin/uclient bin/turnserver testapps/bin/peer lib/libturnclient.a
	rm -rf include
	mkdir -p include/turn/client
	cp -r src/client/*.h include/turn/client/
	cp src/ns_turn_defs.h include/turn/ 

testapps/bin/uclient	:	${COMMON_DEPS} src/apps/uclient/session.h lib/libturnclient.a src/apps/uclient/mainuclient.c src/apps/uclient/uclient.c src/apps/uclient/uclient.h src/apps/uclient/startuclient.c src/apps/uclient/startuclient.h 
	mkdir -p testapps/bin
	${CC} ${CFLAGS} ${INCFLAGS} src/apps/uclient/uclient.c src/apps/uclient/startuclient.c src/apps/uclient/mainuclient.c ${COMMON_MODS} -o $@ ${LINKFLAGS} -lturnclient 

testapps/bin/stunclient	:	${COMMON_DEPS} lib/libturnclient.a src/apps/stunclient/stunclient.c 
	mkdir -p testapps/bin
	${CC} ${CFLAGS} ${INCFLAGS} src/apps/stunclient/stunclient.c ${COMMON_MODS} -o $@ ${LINKFLAGS} -lturnclient  

bin/turnserver	:	${COMMON_DEPS} ${IMPL_DEPS} ${LIBSERVERTURN_OBJS} ${LIBSERVERTURN_DEPS} src/apps/relay/mainrelay.c src/apps/relay/udp_listener.h src/apps/relay/udp_listener.c  
	mkdir -p bin
	rm -rf bin/turnadmin
	${CC} ${CFLAGS} ${INCFLAGS} ${IMPL_MODS} -Ilib src/apps/relay/mainrelay.c src/apps/relay/udp_listener.c ${COMMON_MODS} ${LIBSERVERTURN_OBJS} -o $@ ${LINKFLAGS}
	cd bin; ln -s turnserver turnadmin  

testapps/bin/peer	:	${COMMON_DEPS} ${LIBCLIENTTURN_OBJS} ${LIBCLIENTTURN_DEPS} src/apps/peer/mainudpserver.c src/apps/peer/udpserver.h src/apps/peer/udpserver.c
	mkdir -p testapps/bin
	${CC} ${CFLAGS} ${INCFLAGS} src/apps/peer/mainudpserver.c src/apps/peer/udpserver.c ${COMMON_MODS} -o $@ ${LINKFLAGS} -lturnclient 

### Client Library:

lib/libturnclient.a	:	${LIBCLIENTTURN_OBJS} ${LIBCLIENTTURN_DEPS}
	mkdir -p lib
	${AR} $@ ${LIBCLIENTTURN_OBJS}

build/obj/ns_turn_ioaddr.o	:	src/client/ns_turn_ioaddr.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/client/ns_turn_ioaddr.c -o $@

build/obj/ns_turn_msg_addr.o	:	src/client/ns_turn_msg_addr.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/client/ns_turn_msg_addr.c -o $@

build/obj/ns_turn_msg.o	:	src/client/ns_turn_msg.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/client/ns_turn_msg.c -o $@

build/obj/ns_turn_utils.o	:	src/client/ns_turn_utils.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/client/ns_turn_utils.c -o $@

### Server Obj:

build/obj/ns_turn_server.o	:	src/server/ns_turn_server.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/server/ns_turn_server.c -o $@

build/obj/ns_turn_maps_rtcp.o	:	src/server/ns_turn_maps_rtcp.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/server/ns_turn_maps_rtcp.c -o $@

build/obj/ns_turn_maps.o	:	src/server/ns_turn_maps.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/server/ns_turn_maps.c -o $@

build/obj/ns_turn_allocation.o	:	src/server/ns_turn_allocation.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} ${INCFLAGS} -c src/server/ns_turn_allocation.c -o $@

### Clean all:

clean	:	
	rm -rf bin testapps build lib obj *~ */*~ */*/*~ */*/*/*~ *core include 


