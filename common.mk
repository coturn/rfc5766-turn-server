
INCFLAGS:=-Isrc/apps/common -Isrc/turnserver -I${LIBEVENT_INCLUDE} 
LIBFLAGS:=-L${LIBEVENT_LIB} -Llib -levent -lturn
LINKFLAGS:=${LIBFLAGS} ${OSLIBS}

CFLAGS += ${INCFLAGS}

CLIENT_CFLAGS:=-DTURN_CLIENT
PEER_CFLAGS:=-DTURN_PEER

MAKE_DEPS := Makefile common.mk 

LIBTURN_HEADERS := src/turnserver/ns_turn_allocation.h src/turnserver/ns_turn_ioaddr.h src/turnserver/ns_turn_ioalib.h src/apps/common/ns_turn_defs.h src/turnserver/ns_turn_khash.h src/turnserver/ns_turn_maps_rtcp.h src/turnserver/ns_turn_maps.h src/turnserver/ns_turn_msg.h src/turnserver/ns_turn_msg_addr.h src/turnserver/ns_turn_msg.h src/turnserver/ns_turn_server.h src/turnserver/ns_turn_session.h src/turnserver/ns_turn_utils.h
LIBTURN_DEPS := ${LIBTURN_HEADERS} ${MAKE_DEPS} 
LIBTURN_OBJS := build/obj/ns_turn_allocation.o build/obj/ns_turn_ioaddr.o build/obj/ns_turn_maps_rtcp.o build/obj/ns_turn_maps.o build/obj/ns_turn_msg_addr.o build/obj/ns_turn_msg.o build/obj/ns_turn_server.o build/obj/ns_turn_utils.o

COMMON_DEPS := ${LIBTURN_DEPS} lib/libturn.a src/apps/common/ns_ioalib_impl.h src/apps/common/ns_ioalib_engine_impl.c src/apps/common/apputils.c src/apps/common/apputils.h src/apps/common/turn_ports.h src/apps/common/turn_ports.c src/apps/common/stun_buffer.c src/apps/common/stun_buffer.h
COMMON_MODS := src/apps/common/turnmutex.c src/apps/common/ns_ioalib_engine_impl.c src/apps/common/apputils.c src/apps/common/turn_ports.c src/apps/common/stun_buffer.c

NONRELAY_DEPS := src/apps/common/session.c src/apps/common/session.h
NONRELAY_MODS := src/apps/common/session.c

all	:	bin/stunclient bin/uclient bin/turnserver bin/peer lib/libturn.a 

bin/uclient	:	${COMMON_DEPS} ${NONRELAY_DEPS} src/apps/uclient/mainuclient.c src/apps/uclient/uclient.c src/apps/uclient/uclient.h src/apps/uclient/startuclient.c src/apps/uclient/startuclient.h 
	mkdir -p bin
	${CC} ${CLIENT_CFLAGS} ${CFLAGS} ${NONRELAY_MODS} src/apps/uclient/uclient.c src/apps/uclient/startuclient.c src/apps/uclient/mainuclient.c ${COMMON_MODS} -o $@ ${LINKFLAGS}

bin/stunclient	:	${COMMON_DEPS} src/apps/stunclient/stunclient.c 
	mkdir -p bin
	${CC} ${CLIENT_CFLAGS} ${CFLAGS} src/apps/stunclient/stunclient.c ${COMMON_MODS} -o $@ ${LINKFLAGS} 

bin/turnserver	:	${COMMON_DEPS} src/apps/relay/mainrelay.c src/apps/relay/udp_listener.h src/apps/relay/stunservice.h src/apps/relay/udp_listener.c src/apps/relay/stunservice.c  
	mkdir -p bin
	${CC} ${CFLAGS} -Ilib src/apps/relay/mainrelay.c src/apps/relay/udp_listener.c src/apps/relay/stunservice.c ${COMMON_MODS} -o $@ ${LINKFLAGS} 

bin/peer	:	${COMMON_DEPS} ${NONRELAY_DEPS} src/apps/peer/mainudpserver.c src/apps/peer/udpserver.h src/apps/peer/udpserver.c src/apps/peer/server.h
	mkdir -p bin
	${CC} ${PEER_CFLAGS} ${CFLAGS} ${NONRELAY_MODS} src/apps/peer/mainudpserver.c src/apps/peer/udpserver.c ${COMMON_MODS} -o $@ ${LINKFLAGS} 

lib/libturn.a	:	${LIBTURN_OBJS} ${LIBTURN_DEPS}
	mkdir -p lib
	${AR} $@ ${LIBTURN_OBJS}

build/obj/ns_turn_allocation.o	:	src/turnserver/ns_turn_allocation.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_allocation.c -o $@

build/obj/ns_turn_ioaddr.o	:	src/turnserver/ns_turn_ioaddr.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_ioaddr.c -o $@

build/obj/ns_turn_maps_rtcp.o	:	src/turnserver/ns_turn_maps_rtcp.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_maps_rtcp.c -o $@

build/obj/ns_turn_maps.o	:	src/turnserver/ns_turn_maps.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_maps.c -o $@

build/obj/ns_turn_msg_addr.o	:	src/turnserver/ns_turn_msg_addr.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_msg_addr.c -o $@

build/obj/ns_turn_msg.o	:	src/turnserver/ns_turn_msg.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_msg.c -o $@

build/obj/ns_turn_server.o	:	src/turnserver/ns_turn_server.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_server.c -o $@

build/obj/ns_turn_utils.o	:	src/turnserver/ns_turn_utils.c ${LUBTURN_DEPS}
	mkdir -p build/obj
	${CC} ${CFLAGS} -c src/turnserver/ns_turn_utils.c -o $@

clean	:	
	rm -rf bin build lib obj *~ */*~ */*/*~ */*/*/*~ *core 


