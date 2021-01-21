/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
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
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/*
 * Wed Apr 17 16:05:29 EDT 2002 (James Roth)
 *
 *  - Fixed an unlikely sys_thread_new() race condition.
 *
 *  - Made current_thread() work with threads which where
 *    not created with sys_thread_new().  This includes
 *    the main thread and threads made with pthread_create().
 *
 *  - Catch overflows where more than SYS_MBOX_SIZE messages
 *    are waiting to be read.  The sys_mbox_post() routine
 *    will block until there is more room instead of just
 *    leaking messages.
 */
#include "lwip/debug.h"

#include <pthread.h>
#include <semaphore.h>
#include <sos/debug.h>
#include <sos/sos.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwip/opt.h"
#include "lwip/stats.h"
#include "lwip/sys.h"

#define UMAX(a, b) ((a) > (b) ? (a) : (b))

#if !NO_SYS

static pthread_t m_first_thread = 0;
static pthread_mutex_t threads_mutex;

struct sys_mbox_msg {
  struct sys_mbox_msg *next;
  void *msg;
};

#define SYS_MBOX_SIZE 16

struct sys_mbox {
  int first, last;
  void *msgs[SYS_MBOX_SIZE];
  struct sys_sem *not_empty;
  struct sys_sem *not_full;
  pthread_mutex_t mutex;
  int wait_send;
};

struct sys_sem {
  sem_t *sem;
};

#if SYS_LIGHTWEIGHT_PROT
static pthread_mutex_t lwprot_mutex;
static pthread_t lwprot_thread = (pthread_t)0xDEAD;
static int lwprot_count = 0;
#endif /* SYS_LIGHTWEIGHT_PROT */

static struct sys_sem *sys_sem_new_internal(u8_t count);
static void sys_sem_free_internal(struct sys_sem *sem);
static void initialize_mutex(pthread_mutex_t *mutex);
static void sys_lock_mbox(struct sys_mbox *mbox);
static void sys_unlock_mbox(struct sys_mbox *mbox);

void initialize_mutex(pthread_mutex_t *mutex) {
  pthread_mutexattr_t mutex_attr;
  pthread_mutexattr_init(&mutex_attr);
  pthread_mutexattr_setpshared(&mutex_attr, 1);
  pthread_mutexattr_setprioceiling(&mutex_attr, 20);
  pthread_mutex_init(mutex, &mutex_attr);
}

void sys_lock_mbox(struct sys_mbox *mbox) { pthread_mutex_lock(&mbox->mutex); }
void sys_unlock_mbox(struct sys_mbox *mbox) {
  pthread_mutex_unlock(&mbox->mutex);
}

void *sys_arch_malloc(size_t nbytes) {
  return _malloc_r(sos_task_table[0].global_reent, nbytes);
}

void sys_arch_free(void *mem) { _free_r(sos_task_table[0].global_reent, mem); }

void *sys_arch_calloc(size_t n, size_t nbytes) {
  return sys_arch_malloc(n * nbytes);
}

pthread_t sys_arch_get_first_thread() { return m_first_thread; }

/*-----------------------------------------------------------------------------------*/
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn function,
                            void *arg, int stacksize, int prio) {
  int result;
  pthread_t tmp;
  LWIP_UNUSED_ARG(name);
  LWIP_UNUSED_ARG(stacksize);
  LWIP_UNUSED_ARG(prio);

  pthread_attr_t attr;

  pthread_attr_init(&attr);

  if (pthread_attr_setstacksize(&attr, stacksize) < 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET, "Failed to set stack size");
  }

#if 1
  if (pthread_attr_setschedpolicy(&attr, SCHED_FIFO) < 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET, "Failed to set policy");
  }

  struct sched_param param;
  param.sched_priority = prio;

  if (pthread_attr_setschedparam(&attr, &param) < 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET, "Failed to set priority");
  }
#endif

  result = pthread_create(&tmp, &attr, (void *(*)(void *))function, arg);

  if (result < 0) {
    sos_debug_log_info(SOS_DEBUG_SOCKET, "Failed to create thread");
    abort();
  }

  if (m_first_thread == 0) {
    m_first_thread = tmp;
  }

  return tmp;
}
/*-----------------------------------------------------------------------------------*/
err_t sys_mbox_new(struct sys_mbox **mb, int size) {
  struct sys_mbox *mbox;
  LWIP_UNUSED_ARG(size);

  mbox = (struct sys_mbox *)sys_arch_malloc(sizeof(struct sys_mbox));
  if (mbox == NULL) {
    return ERR_MEM;
  }
  mbox->first = mbox->last = 0;
  mbox->not_empty = sys_sem_new_internal(0);
  mbox->not_full = sys_sem_new_internal(0);

  initialize_mutex(&mbox->mutex);

  mbox->wait_send = 0;

  SYS_STATS_INC_USED(mbox);
  *mb = mbox;
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
void sys_mbox_free(struct sys_mbox **mb) {
  if ((mb != NULL) && (*mb != SYS_MBOX_NULL)) {
    struct sys_mbox *mbox = *mb;
    SYS_STATS_DEC(mbox.used);

    sys_lock_mbox(mbox);

    sys_sem_free_internal(mbox->not_empty);
    sys_sem_free_internal(mbox->not_full);

    sys_unlock_mbox(mbox);

    pthread_mutex_destroy(&mbox->mutex);

    mbox->not_empty = mbox->not_full = NULL;
    /*  LWIP_DEBUGF("sys_mbox_free: mbox 0x%lx\n", mbox); */
    sys_arch_free(mbox);
  }
}
/*-----------------------------------------------------------------------------------*/
err_t sys_mbox_trypost(struct sys_mbox **mb, void *msg) {
  u8_t first;
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  sys_lock_mbox(mbox);

  LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_trypost: mbox %p msg %p\n", (void *)mbox,
                          (void *)msg));

  if ((mbox->last + 1) >= (mbox->first + SYS_MBOX_SIZE)) {
    sys_unlock_mbox(mbox);
    sos_debug_printf("can't post now\n");
    return ERR_MEM;
  }

  mbox->msgs[mbox->last % SYS_MBOX_SIZE] = msg;

  if (mbox->last == mbox->first) {
    first = 1;
  } else {
    first = 0;
  }

  mbox->last++;

  if (first) {
    sys_sem_signal(&mbox->not_empty);
  }

  // sys_sem_signal(&mbox->mutex);
  sys_unlock_mbox(mbox);

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
void sys_mbox_post(struct sys_mbox **mb, void *msg) {

  // this is posting (adding) msg to the mailbox

  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  sys_lock_mbox(mbox);

  LWIP_DEBUGF(SYS_DEBUG,
              ("sys_mbox_post: mbox %p msg %p\n", (void *)mbox, (void *)msg));

  while ((mbox->last + 1) >= (mbox->first + SYS_MBOX_SIZE)) {
    mbox->wait_send++;

    sys_unlock_mbox(mbox);
    sys_arch_sem_wait(&mbox->not_full, 0);
    sys_lock_mbox(mbox);
    mbox->wait_send--;
  }

  mbox->msgs[mbox->last % SYS_MBOX_SIZE] = msg;

  if (mbox->last == mbox->first) {
    sys_sem_signal(&mbox->not_empty);
  }

  sys_unlock_mbox(mbox);
  // sys_sem_signal(&mbox->mutex);
}
/*-----------------------------------------------------------------------------------*/
u32_t sys_arch_mbox_tryfetch(struct sys_mbox **mb, void **msg) {

  // this is trying to fetch msg from the mailbox

  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  sys_lock_mbox(mbox);

  if (mbox->first == mbox->last) {
    sys_unlock_mbox(mbox);
    return SYS_MBOX_EMPTY;
  }

  if (msg != NULL) {
    LWIP_DEBUGF(SYS_DEBUG,
                ("sys_mbox_tryfetch: mbox %p msg %p\n", (void *)mbox, *msg));
    *msg = mbox->msgs[mbox->first % SYS_MBOX_SIZE];
  } else {
    LWIP_DEBUGF(SYS_DEBUG,
                ("sys_mbox_tryfetch: mbox %p, null msg\n", (void *)mbox));
  }

  mbox->first++;

  if (mbox->wait_send) {
    sys_sem_signal(&mbox->not_full);
  }

  sys_unlock_mbox(mbox);

  return 0;
}
/*-----------------------------------------------------------------------------------*/
u32_t sys_arch_mbox_fetch(struct sys_mbox **mb, void **msg, u32_t timeout) {
  u32_t time_needed = 0;
  struct sys_mbox *mbox;

  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  /* The mutex lock is quick so we don't bother with the timeout
   stuff here. */
  // sys_arch_sem_wait(&mbox->mutex, 0);
  sys_lock_mbox(mbox);

  while (mbox->first == mbox->last) {
    sys_unlock_mbox(mbox);

    /* We block while waiting for a mail to arrive in the mailbox. We
   must be prepared to timeout. */
    time_needed = sys_arch_sem_wait(&mbox->not_empty, timeout);

    if (time_needed == SYS_ARCH_TIMEOUT) {
      return SYS_ARCH_TIMEOUT;
    }

    sys_lock_mbox(mbox);
  }

  if (msg != NULL) {
    LWIP_DEBUGF(SYS_DEBUG,
                ("sys_mbox_fetch: mbox %p msg %p\n", (void *)mbox, *msg));
    *msg = mbox->msgs[mbox->first % SYS_MBOX_SIZE];
  } else {
    LWIP_DEBUGF(SYS_DEBUG,
                ("sys_mbox_fetch: mbox %p, null msg\n", (void *)mbox));
  }

  // pop the mbox from the circ buffer
  mbox->first++;

  if (mbox->wait_send) {
    sys_sem_signal(&mbox->not_full);
  }

  sys_unlock_mbox(mbox);

  return time_needed;
}
/*-----------------------------------------------------------------------------------*/
static struct sys_sem *sys_sem_new_internal(u8_t count) {
  struct sys_sem *sem;

  sem = (struct sys_sem *)sys_arch_malloc(sizeof(struct sys_sem));
  if (sem != NULL) {
    sem->sem = (sem_t *)sys_arch_malloc(sizeof(sem_t));
    if (sem->sem == 0) {
      sys_arch_free(sem);
      return 0;
    }
    // this will be sem_init()
    // sos_debug_log_info(SOS_DEBUG_SOCKET, "SEM Init %p %p", sem, sem->sem);
    sem_init(sem->sem, 1, count);
  }
  return sem;
}
/*-----------------------------------------------------------------------------------*/
err_t sys_sem_new(struct sys_sem **sem, u8_t count) {
  SYS_STATS_INC_USED(sem);
  *sem = sys_sem_new_internal(count);
  if (*sem == NULL) {
    return ERR_MEM;
  }
  return ERR_OK;
}

/*-----------------------------------------------------------------------------------*/
u32_t sys_arch_sem_wait(struct sys_sem **s, u32_t timeout) {

  // this will be sem_timedwait()
  struct sys_sem *sem = *s;

  u64 start = sos_realtime();
  if (timeout > 0) {
    struct timespec now;
    struct timespec abs_timeout;
    clock_gettime(CLOCK_REALTIME, &now);
    u32 seconds = timeout / 1000;
    u32 milliseconds = timeout % 1000;
    abs_timeout.tv_nsec = now.tv_nsec + milliseconds * 1000000UL;
    abs_timeout.tv_sec = now.tv_sec + seconds;

    if (abs_timeout.tv_nsec > 1000000000UL) {
      abs_timeout.tv_nsec -= 1000000000UL;
      abs_timeout.tv_sec++;
    }

    int result = sem_timedwait(sem->sem, &abs_timeout);
    if (result < 0) {
      // did not get the semaphore in time
      return SYS_ARCH_TIMEOUT;
    }
  } else {
    if (sem_wait(sem->sem) < 0) {
      sos_debug_log_error(SOS_DEBUG_SOCKET, "Failed to wait semaphore %d",
                          errno);
    }
  }
  u64 end = sos_realtime();
  return ((u32)(start - end)) / 1000UL;
}
/*-----------------------------------------------------------------------------------*/
void sys_sem_signal(struct sys_sem **s) {
  struct sys_sem *sem = *s;
  if (sem_post(sem->sem) < 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET, "Failed to post semaphore %d", errno);
  }
}
/*-----------------------------------------------------------------------------------*/
static void sys_sem_free_internal(struct sys_sem *sem) {
  if (sem && sem->sem) {
    sem_destroy(sem->sem);
    sys_arch_free(sem->sem);
    sys_arch_free(sem);
  } else {
    sos_debug_log_warning(SOS_DEBUG_SOCKET, "Freeing invalid sem");
  }
}
/*-----------------------------------------------------------------------------------*/
void sys_sem_free(struct sys_sem **sem) {
  if ((sem != NULL) && (*sem != SYS_SEM_NULL)) {
    SYS_STATS_DEC(sem.used);
    sys_sem_free_internal(*sem);
  }
}
#endif /* !NO_SYS */
/*-----------------------------------------------------------------------------------*/
u32_t sys_now(void) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return now.tv_sec * 1000 + now.tv_nsec / 1000000UL;
}
/*-----------------------------------------------------------------------------------*/
void sys_init(void) {
  sos_debug_log_info(SOS_DEBUG_SOCKET, "Sys Init %p", &threads_mutex);
  initialize_mutex(&threads_mutex);
}

void sys_arch_msleep(u32_t ms) {
  if (ms < 1000) {
    usleep(ms * 1000);
  } else {
    sleep(ms / 1000);
  }
}

/*-----------------------------------------------------------------------------------*/
#if SYS_LIGHTWEIGHT_PROT
/** sys_prot_t sys_arch_protect(void)
This optional function does a "fast" critical region protection and returns
the previous protection level. This function is only called during very short
critical regions. An embedded system which supports ISR-based drivers might
want to implement this function by disabling interrupts. Task-based systems
might want to implement this by using a mutex or disabling tasking. This
function should support recursive calls from the same task or interrupt. In
other words, sys_arch_protect() could be called while already protected. In
that case the return value indicates that it is already protected.
sys_arch_protect() is only required if your port is supporting an operating
system.
*/
sys_prot_t sys_arch_protect(void) {
  /* Note that for the UNIX port, we are using a lightweight mutex, and our
   * own counter (which is locked by the mutex). The return code is not actually
   * used. */
  if (lwprot_thread != pthread_self()) {
    /* We are locking the mutex where it has not been locked before *
     * or is being locked by another thread */
    pthread_mutex_lock(&lwprot_mutex);
    lwprot_thread = pthread_self();
    lwprot_count = 1;
  } else
    /* It is already locked by THIS thread */
    lwprot_count++;
  return 0;
}
/*-----------------------------------------------------------------------------------*/
/** void sys_arch_unprotect(sys_prot_t pval)
This optional function does a "fast" set of critical region protection to the
value specified by pval. See the documentation for sys_arch_protect() for
more information. This function is only required if your port is supporting
an operating system.
*/
void sys_arch_unprotect(sys_prot_t pval) {
  LWIP_UNUSED_ARG(pval);
  if (lwprot_thread == pthread_self()) {
    if (--lwprot_count == 0) {
      lwprot_thread = (pthread_t)0xDEAD;
      pthread_mutex_unlock(&lwprot_mutex);
    }
  }
}
#endif /* SYS_LIGHTWEIGHT_PROT */

/*-----------------------------------------------------------------------------------*/

#ifndef MAX_JIFFY_OFFSET
#define MAX_JIFFY_OFFSET ((~0U >> 1) - 1)
#endif

#ifndef HZ
#define HZ 100
#endif

u32_t sys_jiffies(void) { return sys_now(); }

#if PPP_DEBUG

#include <stdarg.h>

void ppp_trace(int level, const char *format, ...) {
  va_list args;

  (void)level;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}
#endif

err_t sys_mutex_new(sys_mutex_t *mutex) {
  initialize_mutex(mutex);
  return ERR_OK;
}

void sys_mutex_lock(sys_mutex_t *mutex) { pthread_mutex_lock(mutex); }

void sys_mutex_unlock(sys_mutex_t *mutex) { pthread_mutex_unlock(mutex); }

void sys_mutex_free(sys_mutex_t *mutex) { pthread_mutex_destroy(mutex); }

int sys_mutex_valid(sys_mutex_t *mutex) {
  int prio_ceiling;
  if (pthread_mutex_getprioceiling(mutex, &prio_ceiling) < 0) {
    return 0;
  }
  return 1;
}

void sys_mutex_set_invalid(sys_mutex_t *mutex) { pthread_mutex_destroy(mutex); }

int sys_mbox_valid(sys_mbox_t *mbox) { return (mbox != 0) && (*mbox != 0); }

void sys_mbox_set_invalid(sys_mbox_t *mbox) { *mbox = 0; }
