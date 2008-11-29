/* chan_ss7.c - Implementation of SS7 (MTP2, MTP3, and ISUP) for Asterisk.
 *
 * Copyright (C) 2005-2006, Sifira A/S.
 *
 * Author: Kristian Nielsen <kn@sifira.dk>,
 *         Anders Baekgaard <ab@sifira.dk>
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
#include <sys/poll.h>
#include <netinet/in.h>

#include "asterisk/channel.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/sched.h"
#include "asterisk/cli.h"
#include "asterisk/lock.h"

#include "astversion.h"
#include "config.h"
#include "lffifo.h"
#include "utils.h"
#include "mtp.h"
#include "transport.h"
#include "isup.h"
#include "l4isup.h"
#include "cluster.h"
#include "mtp3io.h"

#ifdef USE_ASTERISK_1_2
#define AST_MODULE_LOAD_SUCCESS  0
#define AST_MODULE_LOAD_DECLINE  1
#define AST_MODULE_LOAD_FAILURE -1
#endif

/* Send fifo for sending control requests to the MTP thread.
   The fifo is lock-free (one thread may put and another get simultaneously),
   but multiple threads doing put must be serialized with this mutex. */
AST_MUTEX_DEFINE_STATIC(mtp_control_mutex);
static struct lffifo *mtp_control_fifo = NULL;

/* This is the MTP2/MTP3 thread, which runs at high real-time priority
   and is careful not to wait for locks in order not to loose MTP
   frames. */
static pthread_t mtp_thread = AST_PTHREADT_NULL;
static int mtp_thread_running = 0;


/* This is the monitor thread which mainly handles scheduling/timeouts. */
static pthread_t monitor_thread = AST_PTHREADT_NULL;
static int monitor_running = 0;



/* State for dumps. */
AST_MUTEX_DEFINE_STATIC(dump_mutex);
static FILE *dump_in_fh = NULL;
static FILE *dump_out_fh = NULL;
static int dump_do_fisu, dump_do_lssu, dump_do_msu;


static const char desc[] = "SS7 Protocol Support";
static const char config[] = "ss7.conf";




static int cmd_version(int fd, int argc, char *argv[]);
static int cmd_dump_status(int fd, int argc, char *argv[]);
static int cmd_dump_stop(int fd, int argc, char *argv[]);
static int cmd_dump_start(int fd, int argc, char *argv[]);
static char *complete_dump_stop(const char *line, const char *word, int pos, int state);
static char *complete_dump_start(const char *line, const char *word, int pos, int state);
static int cmd_link_up(int fd, int argc, char *argv[]);
static int cmd_link_down(int fd, int argc, char *argv[]);
static int cmd_link_status(int fd, int argc, char *argv[]);
static int cmd_ss7_status(int fd, int argc, char *argv[]);

static struct ast_cli_entry my_clis[] = {
  { {"ss7", "version", NULL}, cmd_version,
    "Show current version of chan_ss7",
    "Usage: ss7 version\n",
    NULL
  },

  { { "ss7", "dump", "start", NULL}, cmd_dump_start,
    "Start MTP2 dump to a file",
    "Usage: ss7 dump start <file> [in|out|both] [fisu] [lssu] [msu]\n"
    "       Start mtp2 dump to file. Either incoming, outgoing, or both(default).\n"
    "       Optinally specify which of fisu, lssu, and msu should be dumped.\n"
    "       The output is in PCAP format (can be read by wireshark).\n",
    complete_dump_start
  },

  { {"ss7", "dump", "stop", NULL}, cmd_dump_stop,
    "Stop a running MTP2 dump",
    "Usage: ss7 dump stop [in|out|both]\n"
    "       Stop mtp2 dump started with \"ss7 start dump\". Either incoming,\n"
    "       outgoing, or both(default).\n",
    complete_dump_stop
  },

  { {"ss7", "dump", "status", NULL}, cmd_dump_status,
    "Stop what dumps are running",
    "Usage: ss7 dump status\n",
    NULL
  },

#ifndef MODULETEST
  { {"ss7", "link", "down", NULL}, cmd_link_down,
    "Stop the MTP2 link(s) [logical-link-no]...",
    "Usage: ss7 link down [logical-link-no]\n"
    "       Take the link(s) down; it will be down until started explicitly with\n"
    "       'ss7 link up'.\n"
    "       Until then, it will continuously transmit LSSU 'OS' (out-of-service)\n"
    "       frames.\n"
    "       If no logical-link-no argument is given, all links are affected.\n",
    NULL
  },

  { {"ss7", "link", "up", NULL}, cmd_link_up,
    "Start the MTP2 link(s) [logical-link-no]...",
    "Usage: ss7 link up\n"
    "       Attempt to take the MTP2 link(s) up with the initial alignment procedure.\n"
    "       If no logical-link-no argument is given, all links are affected.\n",
    NULL
  },

  { {"ss7", "link", "status", NULL}, cmd_link_status,
    "Show status of the MTP2 links",
    "Usage: ss7 link status\n"
    "       Show the status of the MTP2 links.\n",
    NULL
  },
#endif

  { {"ss7", "block", NULL}, cmd_block,
    "Set circuits in local maintenance blocked mode",
    "Usage: ss7 block <first> <count> [<linksetname>]\n"
    "       Set <count> lines into local maintenance blocked mode, starting at circuit <first>on linkset <linksetname>\n",
    NULL
  },

  { {"ss7", "unblock", NULL}, cmd_unblock,
    "Remove local maintenance blocked mode from circuits",
    "Usage: ss7 unblock <first> <count> [<linksetname>]\n"
    "       Remove <count> lines from local maintenance blocked mode, starting at circuit <first> on linkset <linksetname>.\n",
    NULL
  },

  { {"ss7", "linestat", NULL}, cmd_linestat,
    "Show line states",
    "Usage: ss7 linestat\n"
    "       Show status for all circuits.\n",
    NULL
  },

  { {"ss7", "show", "channels", NULL}, cmd_linestat,
    "Show channel states",
    "Usage: ss7 show channels\n"
    "       Show status for all channels.\n",
    NULL
  },

  { {"ss7", "cluster", "start", NULL}, cmd_cluster_start,
    "Start cluster",
    "Usage: ss7 cluster start\n"
    "       Start the cluster.\n",
    NULL
  },

  { {"ss7", "cluster", "stop", NULL}, cmd_cluster_stop,
    "Stop cluster",
    "Usage: ss7 cluster stop\n"
    "       Stop the cluster.\n",
    NULL
  },

  { {"ss7", "cluster", "status", NULL}, cmd_cluster_status,
    "Show status of the cluster",
    "Usage: ss7 cluster status\n"
    "       Show the status of the cluster.\n",
    NULL
  },

  { {"ss7", "reset", NULL}, cmd_reset,
    "Reset all circuits",
    "Usage: ss7 reset\n"
    "       Reset all circuits.\n",
    NULL
  },

  { { "ss7", "mtp", "data", NULL}, mtp_cmd_data,
    "Copy hex encoded string to MTP",
    "Usage: ss7 mtp data string\n"
    "       Copy hex encoded string to MTP",
    NULL,
  },

  { { "ss7", "status", NULL}, cmd_ss7_status,
    "Show status of ss7",
    "Usage: ss7 status\n"
    "       Show status/statistics of ss7",
    NULL,
  },

#ifdef MODULETEST
  { {"ss7", "testfailover", NULL}, cmd_testfailover,
    "Test the failover mechanism",
    "Usage: ss7 testfailover"
    "       Test the failover mechanism.\n",
    NULL
  },
  { {"ss7", "moduletest", NULL}, cmd_moduletest,
    "Run a moduletest",
    "Usage: ss7 moduletest <no>"
    "       Run moduletest <no>.\n",
    NULL
  },
#endif
};


static void dump_pcap(FILE *f, struct mtp_event *event)
{
  unsigned int usec  = event->dump.stamp.tv_usec - (event->dump.stamp.tv_usec % 1000) +
    event->dump.slinkno*2 + /* encode link number in usecs */
    event->dump.out /* encode direction in/out */;

  fwrite(&event->dump.stamp.tv_sec, sizeof(event->dump.stamp.tv_sec), 1, f);
  fwrite(&usec, sizeof(usec), 1, f);
  fwrite(&event->len, sizeof(event->len), 1, f); /* number of bytes of packet in file */
  fwrite(&event->len, sizeof(event->len), 1, f); /* actual length of packet */
  fwrite(event->buf, 1, event->len, f);
  fflush(f);
}

static void init_pcap_file(FILE *f)
{
  unsigned int magic = 0xa1b2c3d4;  /* text2pcap does this */
  unsigned short version_major = 2;
  unsigned short version_minor = 4;
  unsigned int thiszone = 0;
  unsigned int sigfigs = 0;
  unsigned int snaplen = 102400;
  unsigned int linktype = 140;

  fwrite(&magic, sizeof(magic), 1, f);
  fwrite(&version_major, sizeof(version_major), 1, f);
  fwrite(&version_minor, sizeof(version_minor), 1, f);
  fwrite(&thiszone, sizeof(thiszone), 1, f);
  fwrite(&sigfigs, sizeof(sigfigs), 1, f);
  fwrite(&snaplen, sizeof(snaplen), 1, f);
  fwrite(&linktype, sizeof(linktype), 1, f);
}

/* Queue a request to the MTP thread. */
static void mtp_enqueue_control(struct mtp_req *req) {
  int res;

  ast_mutex_lock(&mtp_control_mutex);
  res = lffifo_put(mtp_control_fifo, (unsigned char *)req, sizeof(struct mtp_req) + req->len);
  ast_mutex_unlock(&mtp_control_mutex);
  if(res != 0) {
    ast_log(LOG_WARNING, "MTP control fifo full (MTP thread hanging?).\n");
  }
}


static int start_mtp_thread(void)
{
  return start_thread(&mtp_thread, mtp_thread_main, &mtp_thread_running, 15);
}

static void stop_mtp_thread(void)
{
    mtp_thread_signal_stop();
    stop_thread(&mtp_thread, &mtp_thread_running);
}

static int cmd_link_up_down(int fd, int argc, char *argv[], int updown) {
  static unsigned char buf[sizeof(struct mtp_req)];
  struct mtp_req *req = (struct mtp_req *)buf;
  int i;

  req->typ = updown;
  req->len = sizeof(req->link);
  if(argc > 3) {
    for (i = 3; i < argc; i++) {
      int link_ix = atoi(argv[i]);
      ast_log(LOG_DEBUG, "MTP control link %s %d\n", updown == MTP_REQ_LINK_UP ? "up" : "down", link_ix);
      if (link_ix >= this_host->n_schannels) {
	ast_log(LOG_ERROR, "Link index out of range %d, max %d.\n", link_ix, this_host->n_schannels);
	return RESULT_FAILURE;
      }
      req->link.link_ix = link_ix;
      mtp_enqueue_control(req);
    }
  }
  else {
    for (i=0; i < this_host->n_schannels; i++) {
      ast_log(LOG_DEBUG, "MTP control link %s %d\n", updown == MTP_REQ_LINK_UP ? "up" : "down", i);
      req->link.link_ix = i;
      mtp_enqueue_control(req);
    }
  }
  return RESULT_SUCCESS;
}


static int cmd_link_down(int fd, int argc, char *argv[]) {
  return cmd_link_up_down(fd, argc, argv, MTP_REQ_LINK_DOWN);
}


static int cmd_link_up(int fd, int argc, char *argv[]) {
  return cmd_link_up_down(fd, argc, argv, MTP_REQ_LINK_UP);
}


static int cmd_link_status(int fd, int argc, char *argv[]) {
  char buff[256];
  int i;

  for (i = 0; i < this_host->n_schannels; i++) {
    if (mtp_cmd_linkstatus(buff, i) == 0)
      ast_cli(fd, buff);
  }
  return RESULT_SUCCESS;
}


static char *complete_generic(const char *word, int state, char **options, int entries) {
  int which = 0;
  int i;

  for(i = 0; i < entries; i++) {
    if(0 == strncasecmp(word, options[i], strlen(word))) {
      if(++which > state) {
        return strdup(options[i]);
      }
    }
  }
  return NULL;
}

static char *dir_options[] = { "in", "out", "both", };
static char *filter_options[] = { "fisu", "lssu", "msu", };

static char *complete_dump_start(const char *line, const char *word, int pos, int state)
{
  if(pos == 4) {
    return complete_generic(word, state, dir_options,
                            sizeof(dir_options)/sizeof(dir_options[0]));
  } else if(pos > 4) {
    return complete_generic(word, state, filter_options,
                            sizeof(filter_options)/sizeof(filter_options[0]));
  } else {
    /* We won't attempt to complete file names, that's not worth it. */
    return NULL;
  }
}

static char *complete_dump_stop(const char *line, const char *word, int pos, int state)
{
  if(pos == 3) {
    return complete_generic(word, state, dir_options,
                            sizeof(dir_options)/sizeof(dir_options[0]));
  } else {
    return NULL;
  }
}

static int cmd_dump_start(int fd, int argc, char *argv[]) {
  int in, out;
  int i;
  int fisu,lssu,msu;
  FILE *fh;

  if(argc < 4) {
    return RESULT_SHOWUSAGE;
  }

  if(argc == 4) {
    in = 1;
    out = 1;
  } else {
    if(0 == strcasecmp(argv[4], "in")) {
      in = 1;
      out = 0;
    } else if(0 == strcasecmp(argv[4], "out")) {
      in = 0;
      out = 1;
    } else if(0 == strcasecmp(argv[4], "both")) {
      in = 1;
      out = 1;
    } else {
      return RESULT_SHOWUSAGE;
    }
  }

  ast_mutex_lock(&dump_mutex);
  if((in && dump_in_fh != NULL) || (out && dump_out_fh != NULL)) {
    ast_cli(fd, "Dump already running, must be stopped (with 'ss7 stop dump') "
            "before new can be started.\n");
    ast_mutex_unlock(&dump_mutex);
    return RESULT_FAILURE;
  }

  if(argc <= 5) {
    fisu = 0;
    lssu = 0;
    msu = 1;
  } else {
    fisu = 0;
    lssu = 0;
    msu = 0;
    for(i = 5; i < argc; i++) {
      if(0 == strcasecmp(argv[i], "fisu")) {
        fisu = 1;
      } else if(0 == strcasecmp(argv[i], "lssu")) {
        lssu = 1;
      } else if(0 == strcasecmp(argv[i], "msu")) {
        msu = 1;
      } else {
        ast_mutex_unlock(&dump_mutex);
        return RESULT_SHOWUSAGE;
      }
    }
  }

  fh = fopen(argv[3], "w");
  if(fh == NULL) {
    ast_cli(fd, "Error opening file '%s': %s.\n", argv[3], strerror(errno));
    ast_mutex_unlock(&dump_mutex);
    return RESULT_FAILURE;
  }

  if(in) {
    dump_in_fh = fh;
  }
  if(out) {
    dump_out_fh = fh;
  }
  dump_do_fisu = fisu;
  dump_do_lssu = lssu;
  dump_do_msu = msu;
  init_pcap_file(fh);

  ast_mutex_unlock(&dump_mutex);
  return RESULT_SUCCESS;
}

static int cmd_dump_stop(int fd, int argc, char *argv[]) {
  int in, out;

  if(argc == 3) {
    in = 1;
    out = 1;
  } else if(argc == 4) {
    if(0 == strcasecmp(argv[3], "in")) {
      in = 1;
      out = 0;
    } else if(0 == strcasecmp(argv[3], "out")) {
      in = 0;
      out = 1;
    } else if(0 == strcasecmp(argv[3], "both")) {
      in = 1;
      out = 1;
    } else {
      return RESULT_SHOWUSAGE;
    }
  } else {
    return RESULT_SHOWUSAGE;
  }

  ast_mutex_lock(&dump_mutex);

  if((in && !out && dump_in_fh == NULL) ||
     (out && !in && dump_out_fh == NULL) ||
     (in && out && dump_in_fh == NULL && dump_out_fh == NULL)) {
    ast_cli(fd, "No dump running.\n");
    ast_mutex_unlock(&dump_mutex);
    return RESULT_SUCCESS;
  }

  if(in && dump_in_fh != NULL) {
    if(dump_out_fh == dump_in_fh) {
      /* Avoid closing it twice. */
      dump_out_fh = NULL;
    }
    fclose(dump_in_fh);
    dump_in_fh = NULL;
  }
  if(out && dump_out_fh != NULL) {
    fclose(dump_out_fh);
    dump_out_fh = NULL;
  }

  ast_mutex_unlock(&dump_mutex);
  return RESULT_SUCCESS;
}

static int cmd_dump_status(int fd, int argc, char *argv[]) {
  ast_mutex_lock(&dump_mutex);

  /* ToDo: This doesn't seem to work, the output is getting lost somehow.
     Not sure why, but could be related to ast_carefulwrite() called in
     ast_cli(). */
  ast_cli(fd, "Yuck! what is going on here?!?\n");
  if(dump_in_fh != NULL) {
    ast_cli(fd, "Dump of incoming frames is running.\n");
  }
  if(dump_out_fh != NULL) {
    ast_cli(fd, "Dump of outgoing frames is running.\n");
  }
  if(dump_in_fh != NULL || dump_out_fh != NULL) {
    ast_cli(fd, "Filter:%s%s%s.\n",
            (dump_do_fisu ? " fisu" : ""),
            (dump_do_lssu ? " lssu" : ""),
            (dump_do_msu ? " msu" : ""));
  }

  ast_mutex_unlock(&dump_mutex);
  return RESULT_SUCCESS;
}


static int cmd_version(int fd, int argc, char *argv[])
{
  ast_cli(fd, "chan_ss7 version %s\n", CHAN_SS7_VERSION);

  return RESULT_SUCCESS;
}


static int cmd_ss7_status(int fd, int argc, char *argv[])
{
  cmd_linkset_status(fd, argc, argv);
  return RESULT_SUCCESS;
}


static void process_event(struct mtp_event* event)
{
  FILE *dump_fh;

  switch(event->typ) {
  case MTP_EVENT_ISUP:
    l4isup_event(event);
    break;
  case MTP_EVENT_SCCP:
    break;
  case MTP_EVENT_REQ_REGISTER:
    if (event->regist.ss7_protocol == 5) {
      struct link* link = &links[event->regist.isup.slinkix];
      mtp3_register_isup(link->mtp3fd, link->linkix);
    }
    break;
  case MTP_EVENT_LOG:
    ast_log(event->log.level, event->log.file, event->log.line,
	    event->log.function, "%s", event->buf);
    break;

  case MTP_EVENT_DUMP:
    ast_mutex_lock(&dump_mutex);

    if(event->dump.out) {
      dump_fh = dump_out_fh;
    } else {
      dump_fh = dump_in_fh;
    }
    if(dump_fh != NULL) {
      if(event->len < 3 ||
	 ( !(event->buf[2] == 0 && !dump_do_fisu) &&
	   !((event->buf[2] == 1 || event->buf[2] == 2) && !dump_do_lssu) &&
	   !(event->buf[2] > 2 && !dump_do_msu)))
	dump_pcap(dump_fh, event);
    }

    ast_mutex_unlock(&dump_mutex);
    break;

  case MTP_EVENT_STATUS:
    {
      struct link* link = event->status.link;
      char* name = link ? link->name : "(peer)";
      switch(event->status.link_state) {
      case MTP_EVENT_STATUS_LINK_UP:
	l4isup_link_status_change(link, 1);
	ast_log(LOG_WARNING, "MTP is now UP on link '%s'.\n", name);
	break;
      case MTP_EVENT_STATUS_LINK_DOWN:
	l4isup_link_status_change(link, 0);
	ast_log(LOG_WARNING, "MTP is now DOWN on link '%s'.\n", name);
	break;
      case MTP_EVENT_STATUS_INSERVICE:
	ast_log(LOG_WARNING, "Signaling ready for linkset '%s'.\n", link->linkset->name);
	l4isup_inservice(link);
	break;
      default:
	ast_log(LOG_NOTICE, "Unknown event type STATUS (%d), "
		"not processed.\n", event->status.link_state);
      }
    }
    break;

  default:
    ast_log(LOG_NOTICE, "Unexpected mtp event type %d.\n", event->typ);
  }
}

/* Monitor thread main loop.
   Monitor reads events from the realtime MTP thread, and processes them at
   non-realtime priority. It also handles timers for ISUP etc.
*/
static void *monitor_main(void *data) {
  int res, nres;
  struct pollfd fds[(MAX_LINKS+1)];
  int i, n_fds;
  int rebuild_fds = 1;
  struct lffifo *receive_fifo = mtp_get_receive_fifo();

  ast_verbose(VERBOSE_PREFIX_3 "Starting monitor thread, pid=%d.\n", getpid());

  fds[0].fd = get_receive_pipe();
  fds[0].events = POLLIN;
  while(monitor_running) {
    if (rebuild_fds) {
      if (rebuild_fds > 1)
	poll(fds, 0, 200); /* sleep */
      rebuild_fds = 0;
      n_fds = 1;
      for (i = 0; i < n_linksets; i++) {
	struct linkset* linkset = &linksets[i];
	int j;
	for (j = 0; j < linkset->n_links; j++) {
	  int k;
	  struct link* link = linkset->links[j];
	  for (k = 0; k < this_host->n_spans; k++) {
	    if (this_host->spans[k].link == link)
	      break;
	    if ((this_host->spans[k].link->linkset == link->linkset) ||
		(is_combined_linkset(this_host->spans[k].link->linkset, link->linkset)))
	      break;
	  }
	  if (k < this_host->n_spans) {
	    if (link->remote) {
	      if (link->mtp3fd == -1) {
		link->mtp3fd = mtp3_connect_socket(link->mtp3server_host, link->mtp3server_port);
		if (link->mtp3fd != -1)
		  res = mtp3_register_isup(link->mtp3fd, link->linkix);
		if ((link->mtp3fd == -1) || (res == -1))
		  rebuild_fds += 2;
	      }
	      fds[n_fds].fd = link->mtp3fd;
	      fds[n_fds++].events = POLLIN|POLLERR|POLLNVAL|POLLHUP;
	    }
	  }
	}
      }
    }
    int timeout = timers_wait();

    nres = poll(fds, n_fds, timeout);
    if(nres < 0) {
      if(errno == EINTR) {
        /* Just try again. */
      } else {
        ast_log(LOG_ERROR, "poll() failure, errno=%d: %s\n",
                errno, strerror(errno));
      }
    } else if(nres > 0) {
      for (i = 0; (i < n_fds) && (nres > 0); i++) {
	unsigned char eventbuf[MTP_EVENT_MAX_SIZE];
	struct mtp_event *event = (struct mtp_event*) eventbuf;
	struct link* link = NULL;
	if(fds[i].revents) {
	  int j;
	  for (j = 0; j < n_links; j++) {
	    link = &links[j];
	    if (link->remote && (link->mtp3fd == fds[i].fd))
	      break;
	  }
	  if (j == n_links)
	    link = NULL;
	}
	else
	  continue;
	if(fds[i].revents & (POLLERR|POLLNVAL|POLLHUP)) {
	  close(fds[i].fd);
	  if (link)
	    link->mtp3fd = -1;
	  rebuild_fds++; rebuild_fds++; /* when > 1, use short sleep */
	  nres--;
	  continue;
	}
	if(!fds[i].revents & POLLIN)
	  continue;
	if (i == 0) {
	  /* Events waiting in the receive buffer. */
	  unsigned char dummy[512];

	  /* Empty the pipe before pulling from fifo. This way the race
	     condition between mtp and monitor threads may cause spurious
	     wakeups, but not loss/delay of messages. */
	  read(fds[i].fd, dummy, sizeof(dummy));

	  /* Process all available events. */
	  while((res = lffifo_get(receive_fifo, eventbuf, sizeof(eventbuf))) != 0) {
	    if(res < 0) {
	      ast_log(LOG_ERROR, "Yuck! oversized frame in receive fifo, bailing out.\n");
	      return NULL;
	    }
	    process_event(event);
	  }
	}
	else {
#if MTP3_SOCKET == SOCK_STREAM
	  res = read(fds[i].fd, eventbuf, sizeof(struct mtp_event));
	  if ((res > 0) && (event->len > 0)) {
	    int p = res;
	    int len = event->len;
	    if (sizeof(struct mtp_event) + event->len > MTP_EVENT_MAX_SIZE) {
	      ast_log(LOG_NOTICE, "Got too large packet: len %d, max %d, discarded", sizeof(struct mtp_event) + event->len, MTP_EVENT_MAX_SIZE);
	      len = 0;
	      res = 0;
	    }
	    do {
	      res = read(fds[i].fd, &eventbuf[p], len);
	      if (res > 0) {
		p += res;
		len -= res;
	      }
	      else if ((res < 0) && (errno != EINTR)) {
		len = 0;
	      }
	      else {
		len = 0;
	      }
	    } while (len > 0);
	  }
#else
	  res = read(fds[i].fd, eventbuf, sizeof(eventbuf)+MTP_MAX_PCK_SIZE);
#endif
	  if (res > 0) {
	    if (event->typ == MTP_EVENT_ISUP) {
	      event->isup.link = NULL;
	      event->isup.slink = &links[event->isup.slinkix];
	    }
	    process_event(event);
	  }
	  else if (res == 0) {
	    int j;
	    for (j = 0; j < n_links; j++) {
	      struct link* link = &links[j];
	      if (link->remote && (link->mtp3fd == fds[i].fd)) {
		close(fds[i].fd);
		link->mtp3fd = -1;
		rebuild_fds++;
	      }
	    }
	  }
	}
	nres--;
      }
    }

    /* We need to lock the global glock mutex around ast_sched_runq() so that
       we avoid a race with ss7_hangup. With the lock, invalidating the
       channel in ss7_hangup() and removing associated monitor_sched entries
       is an atomic operation, so that we avoid calling timer handlers with
       references to invalidated channels. */
    run_timers();
  }
  return NULL;
}


static void stop_monitor(void) {
  int i;

  if(monitor_running) {
    monitor_running = 0;
    /* Monitor wakes up every 1/2 sec, so no need to signal it explicitly. */
    pthread_join(monitor_thread, NULL);
  }
  for (i = 0; i < n_links; i++) {
    struct link* link = &links[i];
    if (link->remote && (link->mtp3fd > -1))
      close(link->mtp3fd);
  }
}


static int ss7_reload_module(void) {
  ast_log(LOG_NOTICE, "SS7 reload not implemented.\n");
  return AST_MODULE_LOAD_SUCCESS;
}


static int ss7_load_module(void)
{
  if(load_config(0)) {
    return AST_MODULE_LOAD_FAILURE;
  }

  if (timers_init()) {
    ast_log(LOG_ERROR, "Unable to initialize timers.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
  if (isup_init()) {
    ast_log(LOG_ERROR, "Unable to initialize ISUP.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
#ifdef SCCP
  if (sccp_init()) {
    ast_log(LOG_ERROR, "Unable to initialize SCCP.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
#endif

  if(mtp_init()) {
    ast_log(LOG_ERROR, "Unable to initialize MTP.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
  if(start_mtp_thread()) {
    ast_log(LOG_ERROR, "Unable to start MTP thread.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
  mtp_control_fifo = mtp_get_control_fifo();

  monitor_running = 1;          /* Otherwise there is a race, and
                                   monitor may exit immediately */
  if(ast_pthread_create(&monitor_thread, NULL, monitor_main, NULL) < 0) {
    ast_log(LOG_ERROR, "Unable to start monitor thread.\n");
    monitor_running = 0;
    return AST_MODULE_LOAD_FAILURE;
  }


  ast_cli_register_multiple(my_clis, sizeof(my_clis)/ sizeof(my_clis[0]));

  ast_verbose(VERBOSE_PREFIX_3 "SS7 channel loaded successfully.\n");
  return AST_MODULE_LOAD_SUCCESS;
}


static int ss7_unload_module(void)
{
  ast_cli_unregister_multiple(my_clis, sizeof(my_clis)/ sizeof(my_clis[0]));

#ifdef SCCP
  sccp_cleanup();
#endif
  isup_cleanup();

  ast_mutex_lock(&dump_mutex);
  if(dump_in_fh != NULL) {
    if(dump_in_fh == dump_out_fh) {
      dump_out_fh = NULL;
    }
    fclose(dump_in_fh);
    dump_in_fh = NULL;
  }
  if(dump_out_fh != NULL) {
    fclose(dump_out_fh);
    dump_out_fh = NULL;
  }
  ast_mutex_unlock(&dump_mutex);

  if(monitor_running) {
    stop_monitor();
  }
  stop_mtp_thread();
  mtp_cleanup();
  timers_cleanup();


  destroy_config();
  ast_verbose(VERBOSE_PREFIX_3 "SS7 channel unloaded.\n");
  return AST_MODULE_LOAD_SUCCESS;
}


#ifdef USE_ASTERISK_1_2
int reload(void)
{
  return ss7_reload_module();
}
int load_module(void)
{
  return ss7_load_module();
}
int unload_module(void)
{
  return ss7_unload_module();
}
char *description() {
  return (char *) desc;
}

char *key() {
  return ASTERISK_GPL_KEY;
}
#else
#define AST_MODULE "chan_ss7"
AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, desc,
                .load = ss7_load_module,
                .unload = ss7_unload_module,
                .reload = ss7_reload_module,
);
#endif
