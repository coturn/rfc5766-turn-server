/*
 * Copyright (C) 2011, 2012 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ns_turn_maps.h"

#include "ns_turn_ioalib.h"

#include "turn_ports.h"

////////// DATA ////////////////////////////////////////////

#define PORTS_SIZE (0xFFFF+1)
#define TPS_OUT_OF_RANGE ((u64bits)(-1))
#define TPS_TAKEN_SINGLE ((u64bits)(-2))
#define TPS_TAKEN_EVEN ((u64bits)(-3))
#define TPS_TAKEN_ODD ((u64bits)(-4))

struct _turnports {
  u64bits status[PORTS_SIZE];
  u64bits low;
  u64bits high;
  u16bits range_start;
  u16bits range_stop;
  int ports[PORTS_SIZE];
  TURN_MUTEX_DECLARE(mutex)
};
typedef struct _turnports turnports;

/////////////// TURNPORTS statics //////////////////////////

static turnports* turnports_create(u16bits start, u16bits end);
static void turnports_destroy(turnports** tp);
static u16bits turnports_size(turnports* tp);

static int turnports_allocate(turnports* tp);
static int turnports_allocate_even(turnports* tp, int allocate_rtcp, u64bits *reservation_token);

static void turnports_release(turnports* tp, u16bits port);

static int turnports_is_allocated(turnports* tp, u16bits port);
static int turnports_is_available(turnports* tp, u16bits port);

/////////////// UTILS //////////////////////////////////////

static int is_taken(u64bits status) {
  switch(status) {
  case TPS_TAKEN_SINGLE:
  case TPS_TAKEN_EVEN:
  case TPS_TAKEN_ODD:
    return 1;
  default:
    return 0;
  };
}

static void turnports_randomize(turnports* tp) {
  if(tp) {
    srandom((unsigned long)tp);
    unsigned int size=(unsigned int)(tp->high-tp->low);
    unsigned int i=0;
    unsigned int cycles=size*10;
    for(i=0;i<cycles;i++) {
      u16bits port1 = (u16bits)(tp->low + (u16bits)(((unsigned long)random())%((unsigned long)size)));
      u16bits port2 = (u16bits)(tp->low + (u16bits)(((unsigned long)random())%((unsigned long)size)));
      if(port1!=port2) {
	int pos1=tp->status[port1];
	int pos2=tp->status[port2];
	int tmp=tp->status[port1];
	tp->status[port1]=tp->status[port2];
	tp->status[port2]=tmp;
	tmp=tp->ports[pos1];
	tp->ports[pos1]=tp->ports[pos2];
	tp->ports[pos2]=tmp;
      }
    }
  }
}   

static void turnports_init(turnports* tp, u16bits start, u16bits end) {

  tp->low=start;
  tp->high=((u64bits)end)+1;

  tp->range_start=start;
  tp->range_stop=end;
  
  int i=0;
  for(i=0;i<start;i++) {
    tp->status[i]=TPS_OUT_OF_RANGE;
    tp->ports[i]=i;
  }
  for(i=start;i<=end;i++) {
    tp->status[i]=i;
    tp->ports[i]=i;
  }
  for(i=((int)end)+1;i<PORTS_SIZE;i++) {
    tp->status[i]=TPS_OUT_OF_RANGE;
    tp->ports[i]=i;
  }

  turnports_randomize(tp);

  TURN_MUTEX_INIT_RECURSIVE(&(tp->mutex));
}

/////////////// FUNC ///////////////////////////////////////

turnports* turnports_create(u16bits start, u16bits end) {

  if(start>end) return NULL;

  turnports* ret=(turnports*)turn_malloc(sizeof(turnports));
  turnports_init(ret,start,end);

  return ret;
}

void turnports_destroy(turnports** tp) {
  if(tp && *tp) {
    TURN_MUTEX_DESTROY(&((*tp)->mutex));
    turn_free(*tp,sizeof(turnports));
    *tp=NULL;
  }
}

u16bits turnports_size(turnports* tp) {
  if(!tp) return 0;
  else {
    TURN_MUTEX_LOCK(&tp->mutex);
    u16bits ret = (u16bits)((tp->high-tp->low));
    TURN_MUTEX_UNLOCK(&tp->mutex);
    return ret;
  }
}

int turnports_allocate(turnports* tp) {

  int port=-1;

  TURN_MUTEX_LOCK(&tp->mutex);

  if(tp) {

    while(1) {
      
      if(tp->high <= tp->low) {
	TURN_MUTEX_UNLOCK(&tp->mutex);
	return -1;
      }
      
      int position=(u16bits)(tp->low & 0x0000FFFF);
      
      port=tp->ports[position];
      if(port<(int)(tp->range_start) || port>((int)(tp->range_stop))) {
	TURN_MUTEX_UNLOCK(&tp->mutex);
	return -1;
      }
      if(is_taken(tp->status[port])) {
	++(tp->low);
	continue;
      } 
      if(tp->status[port]!=tp->low) {
	++(tp->low);
	continue;
      }
      tp->status[port]=TPS_TAKEN_SINGLE;
      ++(tp->low);
      break;
    }
  }

  TURN_MUTEX_UNLOCK(&tp->mutex);

  return port;
}

void turnports_release(turnports* tp, u16bits port) {
  TURN_MUTEX_LOCK(&tp->mutex);
  if(tp && port>=tp->range_start && port<=tp->range_stop) {
    u16bits position=(u16bits)(tp->high & 0x0000FFFF);
    if(is_taken(tp->status[port])) {
      tp->status[port]=tp->high;
      tp->ports[position]=port;
      ++(tp->high);
    }
  }
  TURN_MUTEX_UNLOCK(&tp->mutex);
}

int turnports_allocate_even(turnports* tp, int allocate_rtcp, u64bits *reservation_token) {
  if(tp) {
    TURN_MUTEX_LOCK(&tp->mutex);
    u16bits size = turnports_size(tp);
    if(size>1) {
      u16bits i=0;
      for(i=0;i<size;i++) {
	int port=turnports_allocate(tp);
	if(port & 0x00000001) {
	  turnports_release(tp,port);
	} else {
	  if(!allocate_rtcp) {
	    TURN_MUTEX_UNLOCK(&tp->mutex);
	    return port;
	  } else {
	    int rtcp_port=port+1;
	    if(rtcp_port>tp->range_stop) {
	      turnports_release(tp,port);
	    } else if(!turnports_is_available(tp,rtcp_port)) {
	      turnports_release(tp,port);
	    } else {
	      tp->status[port]=TPS_TAKEN_EVEN;
	      tp->status[rtcp_port]=TPS_TAKEN_ODD;
	      if(reservation_token) {
		u16bits *v16=(u16bits*)reservation_token;
		u32bits *v32=(u32bits*)reservation_token;
		v16[0]=(u16bits)(tp->ports[(u16bits)(tp->low & 0x0000FFFF)]);
		v16[1]=(u16bits)(tp->ports[(u16bits)(tp->high & 0x0000FFFF)]);
		v32[1]=(u32bits)random();
	      }
	      TURN_MUTEX_UNLOCK(&tp->mutex);
	      return port;
	    }
	  }
	}
      }
    }
    TURN_MUTEX_UNLOCK(&tp->mutex);
  }
  return -1;
}

int turnports_is_allocated(turnports* tp, u16bits port) {
  if(!tp) return 0;
  else {
    TURN_MUTEX_LOCK(&tp->mutex);
    int ret = is_taken(tp->status[port]);
    TURN_MUTEX_UNLOCK(&tp->mutex);
    return ret;
  }
}

int turnports_is_available(turnports* tp, u16bits port) {
  if(tp) {
    TURN_MUTEX_LOCK(&tp->mutex);
    u64bits status = tp->status[port];
    if((status!=TPS_OUT_OF_RANGE) && !is_taken(status)) {
      u16bits position=(u16bits)(status & 0x0000FFFF);
      if((int)(tp->ports[position])==(int)port) {
	TURN_MUTEX_UNLOCK(&tp->mutex);
	return 1;
      }
    }
    TURN_MUTEX_UNLOCK(&tp->mutex);
  }
  return 0;
}

/////////////////// IP-mapped PORTS /////////////////////////////////////

struct _turnipports
{
	u16bits start;
	u16bits end;
	ur_addr_map* ip_to_turnports;
	TURN_MUTEX_DECLARE(mutex)
};

//////////////////////////////////////////////////

turnipports* turnipports_create(u16bits start, u16bits end)
{
	turnipports *ret = (turnipports*) turn_malloc(sizeof(turnipports));
	ret->ip_to_turnports = ur_addr_map_create(0);
	ret->start = start;
	ret->end = end;
	TURN_MUTEX_INIT_RECURSIVE(&(ret->mutex));
	return ret;
}

static void turnipports_del_func(ur_addr_map_value_type val)
{
	turnports *tp = (turnports*) val;
	turnports_destroy(&tp);
}

void turnipports_destroy(turnipports** tp)
{
	if (tp && *tp) {
		ur_addr_map_foreach((*tp)->ip_to_turnports, turnipports_del_func);
		ur_addr_map_free(&((*tp)->ip_to_turnports));
		TURN_MUTEX_DESTROY(&((*tp)->mutex));
		turn_free(*tp,sizeof(turnipports));
		*tp = NULL;
	}
}

static turnports* turnipports_add(turnipports* tp, const ioa_addr *backend_addr)
{
	ur_addr_map_value_type t = 0;
	if (tp && backend_addr) {
		ioa_addr ba;
		addr_cpy(&ba, backend_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (!ur_addr_map_get(tp->ip_to_turnports, &ba, &t)) {
			t = (ur_addr_map_value_type) turnports_create(tp->start, tp->end);
			ur_addr_map_put(tp->ip_to_turnports, &ba, t);
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return (turnports*) t;
}

void turnipports_remove(turnipports* tp, const ioa_addr *backend_addr)
{
	if (tp && backend_addr) {
		ioa_addr ba;
		addr_cpy(&ba, backend_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		ur_addr_map_del(tp->ip_to_turnports, &ba, turnipports_del_func);
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
}

int turnipports_allocate(turnipports* tp, const ioa_addr *backend_addr)
{
	int ret = -1;
	if (tp && backend_addr) {
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		turnports *t = turnipports_add(tp, backend_addr);
		ret = turnports_allocate(t);
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

int turnipports_allocate_even(turnipports* tp, const ioa_addr *backend_addr, int allocate_rtcp,
				u64bits *reservation_token)
{
	int ret = -1;
	if (tp && backend_addr) {
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		turnports *t = turnipports_add(tp, backend_addr);
		ret = turnports_allocate_even(t, allocate_rtcp, reservation_token);
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

void turnipports_release(turnipports* tp, const ioa_addr *socket_addr)
{
	if (tp && socket_addr) {
		ioa_addr ba;
		ur_addr_map_value_type t;
		addr_cpy(&ba, socket_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (ur_addr_map_get(tp->ip_to_turnports, &ba, &t)) {
			turnports_release((turnports*) t, addr_get_port(socket_addr));
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
}

int turnipports_is_allocated(turnipports* tp, const ioa_addr *backend_addr, u16bits port)
{
	int ret = 0;
	if (tp && backend_addr) {
		ioa_addr ba;
		ur_addr_map_value_type t;
		addr_cpy(&ba, backend_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (ur_addr_map_get(tp->ip_to_turnports, &ba, &t)) {
			ret = turnports_is_allocated((turnports*) t, port);
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

int turnipports_is_available(turnipports* tp, const ioa_addr *backend_addr, u16bits port)
{
	int ret = 0;
	if (tp && backend_addr) {
		ioa_addr ba;
		ur_addr_map_value_type t;
		addr_cpy(&ba, backend_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (!ur_addr_map_get(tp->ip_to_turnports, &ba, &t)) {
			ret = 1;
		} else {
			ret = turnports_is_available((turnports*) t, port);
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

//////////////////////////////////////////////////////////////////


