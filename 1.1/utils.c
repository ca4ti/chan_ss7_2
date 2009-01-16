/* utils.c - Handling of timers, locks, threads and stuff
 *
 * Copyright (C) 2006, Sifira A/S.
 *
 * Author: Anders Baekgaard <ab@sifira.dk>
 *         Anders Baekgaard <ab@dicea.dk>
 *
 * This file is part of chan_ss7.
 *
 * chan_ss7 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * chan_ss7 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with chan_ss7; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef MTP_STANDALONE
#include "aststubs.h"
#else
#include "asterisk/sched.h"
#include "asterisk/lock.h"
#define mtp_sched_add ast_sched_add
#define mtp_sched_del ast_sched_del
#define mtp_sched_runq ast_sched_runq
#define mtp_sched_wait ast_sched_wait
#define mtp_sched_context_create sched_context_create
#define mtp_sched_context_destroy sched_context_destroy
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/module.h"


#endif
#include "asterisk/utils.h"

struct sched_context *mtp_sched_context_create(void);
void mtp_sched_context_destroy(struct sched_context *con);


#include "astversion.h"
#include "config.h"
#include "mtp.h"
#include "utils.h"

#ifdef MTP_STANDALONE
#undef ast_pthread_create
#undef pthread_create
#define ast_pthread_create pthread_create
#endif

static inline const char *mtp_inet_ntoa(char *buf, int bufsiz, struct in_addr ia)
{
	return inet_ntop(AF_INET, &ia, buf, bufsiz);
}


AST_MUTEX_DEFINE_STATIC(glock);

/* Delay between monitor wakeups. */
#define MONITOR_FREQ 500

static void wakeup_monitor(void) {
  write(get_receive_pipe(), "", 1);
}

static struct sched_context *monitor_sched = NULL;

int timers_wait(void)
{
  int timeout = mtp_sched_wait(monitor_sched);
  if(timeout <= 0 || timeout > MONITOR_FREQ) {
    timeout = MONITOR_FREQ;
  }
  return timeout;
}


int start_timer(int msec, int (*cb)(void *), void *data)
{
  int id = mtp_sched_add(monitor_sched, msec, cb, data);
  if(msec < MONITOR_FREQ) {
    wakeup_monitor();
  }
  return id;
}

void stop_timer(int tid)
{
  mtp_sched_del(monitor_sched, tid);
}


int timers_init(void)
{
  /* Start the monitor thread. */
  monitor_sched = mtp_sched_context_create();
  if(monitor_sched == NULL) {
    ast_log(LOG_ERROR, "Unable to create monitor scheduling context.\n");
    return -1;
  }
  return 0;
}

int timers_cleanup(void)
{
  if(monitor_sched) {
    mtp_sched_context_destroy(monitor_sched);
    monitor_sched = NULL;
  }
  return 0;
}

void run_timers(void)
{
  ast_mutex_lock(&glock);
  mtp_sched_runq(monitor_sched);
  ast_mutex_unlock(&glock);
}

void lock_global(void)
{
  ast_mutex_lock(&glock);
}

void unlock_global(void)
{
  ast_mutex_unlock(&glock);
}


int start_thread(pthread_t* t, void* (*thread_main)(void*data), int* running, int prio)
{
  struct sched_param sp;
  int res;

  res = ast_pthread_create(t, NULL, thread_main, NULL);
  if(res != 0) {
    ast_log(LOG_ERROR, "Failed to create thread: %s.\n", strerror(res));
    return -1;
  }

  memset(&sp, 0, sizeof(sp));
  sp.sched_priority = prio;
  res = pthread_setschedparam(*t, SCHED_RR, &sp);
  if(res != 0) {
    ast_log(LOG_WARNING, "Failed to set thread to realtime priority: %s.\n",
            strerror(res));
  }

  *running = 1;

  return 0;
}

void stop_thread(pthread_t *t, int* running) {
  if(*running) {
    pthread_join(*t, NULL);
    *running = 0;
  }
}


const char* inaddr2s(struct in_addr addr)
{
  static char buf[20];

  return mtp_inet_ntoa(buf, sizeof(buf), addr);
}

