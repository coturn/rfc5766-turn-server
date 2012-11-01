
INCFLAGS:=-Isrc/apps/common -Isrc/turnserver -Isrc/turnclient -I${LIBEVENT_INCLUDE} 
LIBFLAGS:=${LIBEVENT_LIB} -Llib -Lbuild
LINKFLAGS:=${LIBFLAGS} ${OSLIBS}

CFLAGS += ${INCFLAGS}

CLIENT_CFLAGS:=-DTURN_CLIENT
PEER_CFLAGS:=-DTURN_PEER

MAKE_DEPS := Makefile common.mk 

LIBCLIENTTURN_HEADERS := src/turnclient/ns_turn_defs.h src/turnclient/ns_turn_ioaddr.h src/turnclient/ns_turn_msg.h src/turnclient/ns_turn_msg_addr.h src/turnclient/ns_turn_msg.h src/turnclient/ns_turn_utils.h
LIBCLIENTTURN_DEPS := ${LIBCLIENTTURN_HEADERS} ${MAKE_DEPS} 
LIBCLIENTTURN_OBJS := build/obj/ns_turn_ioaddr.o build/obj/ns_turn_msg_addr.o build/obj/ns_turn_msg.o build/obj/ns_turn_utils.o

LIBSERVERTURN_HEADERS := ${LIBCLIENTTURN_HEADERS} src/turnserver/ns_turn_allocation.h src/turnserver/ns_turn_ioalib.h src/turnserver/ns_turn_khash.h src/turnserver/ns_turn_maps_rtcp.h src/turnserver/ns_turn_maps.h src/turnserver/ns_turn_server.h src/turnserver/ns_turn_session.h 
LIBSERVERTURN_DEPS := ${LIBSERVERTURN_HEADERS} ${MAKE_DEPS} 
LIBSERVERTURN_OBJS := ${LIBCLIENTTURN_OBJS} build/obj/ns_turn_allocation.o build/obj/ns_turn_maps_rtcp.o build/obj/ns_turn_maps.o build/obj/ns_turn_server.o

COMMON_DEPS := ${LIBCLIENTTURN_DEPS} src/apps/common/apputils.c src/apps/common/apputils.h src/apps/common/stun_buffer.c src/apps/common/stun_buffer.h
COMMON_MODS := src/apps/common/apputils.c src/apps/common/stun_buffer.c src/apps/common/turnmutex.c

IMPL_DEPS := src/apps/common/ns_ioalib_impl.h src/apps/common/ns_ioalib_engine_impl.c src/apps/common/turn_ports.h src/apps/common/turn_ports.c
IMPL_MODS := src/apps/common/ns_ioalib_engine_impl.c src/apps/common/turn_ports.c 

NONRELAY_DEPS := src/apps/common/session.c src/apps/common/session.h
NONRELAY_MODS := src/apps/common/session.c

all	:	testapps/bin/stunclient testapps/bin/uclient bin/turnserver testapps/bin/peer lib/libturnclient.a
	rm -rf include
	mkdir -p include/turn/client
	cp -r src/turnclient/*.h include/turn/client/  

testapps/bin/uclient	:	${COMMON_DEPS} ${NONRELAY_DEPS} src/turnserver/ns_turn_khash.h build/obj/ns_turn_maps.o lib/libturnclient.a src/apps/uclient/mainuclient.c src/apps/uclient/uclient.c src/apps/uclient/uclient.h src/apps/uclient/startuclient.c src/apps/uclient/startuclient.h 
	mkdir -p testapps/bin
	${CC} ${CLIENT_CFLAGS} ${CFLAGS} ${NONRELAY_MODS} src/apps/uclient/uclient.c src/apps/uclient/startuclient.c src/apps/uclient/mainuclient.c build/obj/ns_turn_maps.o ${COMMON_MODS} -o $@ ${LINKFLAGS} -lturnclient 

testapps/bin/stunclient	:	${COMMON_DEPS} lib/libturnclient.a src/apps/stunclient/stunclient.c 
	mkdir -p testapps/bin
	${CC} ${CLIENT_CFLAGS} ${CFLAGS} src/apps/stunclient/stunclient.c ${COMMON_MODS} -o $@ ${LINKFLAGS} -lturnclient  

bin/turnserver	:	${COMMON_DEPS} ${IMPL_DEPS} ${LIBSERVERTURN_OBJS} ${LIBSERVERTURN_DEPS} src/apps/relay/mainrelay.c src/apps/relay/udp_listener.h src/apps/relay/udp_listener.c  
	mkdir -p bin
	${CC} ${CFLAGS} ${IMPL_MODS} -Ilib src/apps/relay/mainrelay.c src/apps/relay/udp_listener.c ${COMMON_MODS} ${LIBSERVERTURN_OBJS} -o $@ ${LINKFLAGS}  

testapps/bin/peer	:	${COMMON_DEPS} ${NONRELAY_DEPS} ${IMPL_DEPS} ${LIBSERVERTURN_OBJS} ${LIBSERVERTURN_DEPS} src/apps/peer/mainudpserver.c src/apps/peer/udpserver.h src/apps/peer/udpserver.c src/apps/peer/server.h
	mkdir -p testapps/bin
	${CC} ${PEER_CFLAGS} ${CFLAGS} ${NONRELAY_MODS} ${IMPL_MODS} src/apps/peer/mainudpserver.c src/apps/peer/udpserver.c ${COMMON_MODS} ${LIBSERVERTURN_OBJS} -o $@ ${LINKFLAGS} 
	
### Client Library:
	
lib/libturnclient.a	:	${LIBCLIENTTURN_OBJS} ${LIBCLIENTTURN_DEPS}
	mkdir -p lib
	${AR} $@ ${LIBCLIENTTURN_OBJS}

build/obj/ns_turn_ioaddr.o	:	src/turnclient/ns_turn_ioaddr.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnclient/ns_turn_ioaddr.c -o $@

build/obj/ns_turn_msg_addr.o	:	src/turnclient/ns_turn_msg_addr.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnclient/ns_turn_msg_addr.c -o $@

build/obj/ns_turn_msg.o	:	src/turnclient/ns_turn_msg.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnclient/ns_turn_msg.c -o $@

build/obj/ns_turn_utils.o	:	src/turnclient/ns_turn_utils.c ${LUBCLIENTTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnclient/ns_turn_utils.c -o $@

### Server Obj:

build/obj/ns_turn_server.o	:	src/turnserver/ns_turn_server.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_server.c -o $@

build/obj/ns_turn_maps_rtcp.o	:	src/turnserver/ns_turn_maps_rtcp.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_maps_rtcp.c -o $@

build/obj/ns_turn_maps.o	:	src/turnserver/ns_turn_maps.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_maps.c -o $@

build/obj/ns_turn_allocation.o	:	src/turnserver/ns_turn_allocation.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_allocation.c -o $@

### Clean all:

clean	:	
	rm -rf bin testapps build lib obj *~ */*~ */*/*~ */*/*/*~ *core include 


