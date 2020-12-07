/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#ifndef LWIP_ARCH_SYS_ARCH_H_
#define LWIP_ARCH_SYS_ARCH_H_

#include <errno.h>

#define SYS_MBOX_NULL NULL
#define SYS_SEM_NULL  NULL

typedef unsigned int sys_prot_t;

struct sys_sem;
typedef struct sys_sem * sys_sem_t;
#define sys_sem_valid(sem) (((sem) != NULL) && (*(sem) != NULL))
#define sys_sem_set_invalid(sem) do { if((sem) != NULL) { *(sem) = NULL; }}while(0)


#define mem_clib_malloc sys_arch_malloc
#define mem_clib_free sys_arch_free
#define mem_clib_calloc sys_arch_calloc

void * sys_arch_malloc(size_t nbytes);
void sys_arch_free(void  * mem);
void * sys_arch_calloc(size_t n, size_t nbytes);

pthread_t sys_arch_get_first_thread();



/* let sys.h use binary semaphores for mutexes */
#define LWIP_COMPAT_MUTEX 0
typedef pthread_mutex_t sys_mutex_t;

struct sys_mbox;
typedef struct sys_mbox * sys_mbox_t;

typedef pthread_t sys_thread_t;


#endif /* LWIP_ARCH_SYS_ARCH_H_ */
