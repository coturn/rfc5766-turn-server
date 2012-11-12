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

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "ns_turn_ioalib.h"

/////// defines ///////////

#define MAGIC_CODE (0xEFCD1983)

int turn_mutex_lock(const turn_mutex *mutex) {
  if(mutex && mutex->mutex && (mutex->data == MAGIC_CODE)) {
    int ret = pthread_mutex_lock((pthread_mutex_t*)mutex->mutex);
    if(ret<0) {
      perror("Mutex lock");
    }
    return ret;
  } else {
    printf("Uninitialized mutex\n");
    return -1;
  }
}

int turn_mutex_unlock(const turn_mutex *mutex) {
  if(mutex && mutex->mutex && (mutex->data == MAGIC_CODE)) {
    int ret = pthread_mutex_unlock((pthread_mutex_t*)mutex->mutex);
    if(ret<0) {
      perror("Mutex unlock");
    }
    return ret;
  } else {
    printf("Uninitialized mutex\n");
    return -1;
  }
}

int turn_mutex_init(turn_mutex* mutex) {
  if(mutex) {
    mutex->mutex=malloc(sizeof(pthread_mutex_t));
    mutex->data=MAGIC_CODE;
    int ret = pthread_mutex_init((pthread_mutex_t*)mutex->mutex,NULL);
    if(ret<0) {
      perror("Mutex init");
      mutex->data=0;
      free(mutex->mutex);
      mutex->mutex=NULL;
    }
    return ret;
  } else {
    return -1;
  }
}

int turn_mutex_init_recursive(turn_mutex* mutex) {
  int ret=-1;
  if(mutex) {
    pthread_mutexattr_t attr;
    if(pthread_mutexattr_init(&attr)<0) {
      perror("Cannot init mutex attr");
    } else {
      if(pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE)<0) {
	perror("Cannot set type on mutex attr");
      } else {
	mutex->mutex=malloc(sizeof(pthread_mutex_t));
	mutex->data=MAGIC_CODE;
	if((ret=pthread_mutex_init((pthread_mutex_t*)mutex->mutex,&attr))<0) {
	  perror("Cannot init mutex");
	  mutex->data=0;
	  free(mutex->mutex);
	  mutex->mutex=NULL;
	}
      }
      pthread_mutexattr_destroy(&attr);
    }
  }
  return ret;
}

int turn_mutex_destroy(turn_mutex* mutex) {
  if(mutex && mutex->mutex && mutex->data == MAGIC_CODE) {
    int ret = pthread_mutex_destroy((pthread_mutex_t*)(mutex->mutex));
    mutex->data=0;
    free(mutex->mutex);
    mutex->mutex=NULL;
    return ret;
  } else {
    return 0;
  }
}

////////////////////////////////////////////

