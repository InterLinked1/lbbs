/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief I/O Logging for Debugging
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note This module is similar in function to the tee utility or tcpflow for TCP,
 *       (except we operate on pipes). This I/O transform module does no actual
 *       transformation of the data that flows through it, it simply
 *       logs the session to disk, for debugging analysis.
 *       This is only enabled on-demand.
 */

#include "include/bbs.h"

#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>

#include "include/module.h"
#include "include/node.h"
#include "include/linkedlists.h"
#include "include/alertpipe.h"
#include "include/utils.h"

/* Extra correctness checks */
#define VERIFY_INTEGRITY

struct log_data {
	int rpfd[2];
	int wpfd[2];
	int orig_rfd;
	int orig_wfd;
	size_t sentbytes;
	size_t recvbytes;
	pthread_t thread;
	FILE *fp;
	unsigned int done:1;
	RWLIST_ENTRY(log_data) entry;
};

static RWLIST_HEAD_STATIC(loggers, log_data);

static void flowlog(FILE *fp, char *restrict buf, size_t len, char dirchr)
{
	size_t i, j;
	char *s = buf;

	/* Generate timestamp */
	char datestr[20];
	time_t lognow;
	struct tm logdate;
	struct timeval now;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waggregate-return"
	now = bbs_tvnow();
#pragma GCC diagnostic pop
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);

	fprintf(fp, "%c %s.%06d\n", dirchr, datestr, (int) now.tv_usec);

#define LINE_LENGTH 32

	/* The output here is designed to be formatted similar to tcpflow's output with the -C and -D options. */
	for (i = 0; len > 0; i += LINE_LENGTH) {
		char hexbuf[81]; /* 80 cols, so 81 with NUL */
		char asciibuf[LINE_LENGTH + 1]; /* 32 cols, so 33 with NUL */
		char *hexpos = hexbuf, *asciipos = asciibuf;
		size_t bytes_this_line = MIN((size_t) LINE_LENGTH, len);
#ifdef VERIFY_INTEGRITY
		bbs_assert(bytes_this_line <= LINE_LENGTH); /* If this fails, some hanky panky has gone on with the types */
#endif
		/* For all characters available for this line: */
		for (j = 0; j < bytes_this_line; j++, s++) {
#undef sprintf
			hexpos += sprintf(hexpos, "%02x%s", *s, j % 2 ? " " : "");
			*(asciipos++) = isprint(*s) ? *s : '.';
		}
		/* *hexpos is already NUL due to sprintf */
		*asciipos = '\0';
		/* Line of output in log file */
		fprintf(fp, "%c %04x: %-80s %-32s\n", dirchr, (int) i, hexbuf, asciibuf);
		if (len >= LINE_LENGTH) {
			len -= LINE_LENGTH;
		} else {
			len = 0;
		}
	}
	fprintf(fp, "\n");
}

static ssize_t deliver(struct log_data *l, char *restrict buf, size_t len, int destfd, int is_write)
{
	/* Write to destination, unmodified */
	ssize_t res = bbs_write(destfd, buf, len);
	if (res != (ssize_t) len) {
		return -1;
	}

	/* Also duplicate to log file. */
	flowlog(l->fp, buf, len, is_write ? '<' : '>'); /* Use < for write, > for read */
	/* Resist the urge to flush every time... otherwise, the performance benefit of using a FILE* vaporizes */
	return res;
}

static void *log_thread(void *varg)
{
	struct log_data *l = varg;
	struct pollfd pfds[2];

	pfds[0].fd = l->wpfd[0]; /* Data that we need to compress and send along */
	pfds[1].fd = l->orig_rfd; /* Data that we received that needs to be decompressed */
	pfds[0].events = pfds[1].events = POLLIN | POLLPRI | POLLERR | POLLNVAL;
	pfds[0].revents = pfds[1].revents = 0;

	for (;;) {
		ssize_t rres;
		ssize_t res = poll(pfds, 2, -1);
		if (res < 0) {
			bbs_debug(3, "poll returned %ld: %s\n", res, strerror(errno));
			if (errno == EINTR && !l->done) {
				continue;
			}
			break;
		}

		/* Since we want to "tee" the data, by
		 * reading some data and then writing it to two separate places,
		 * we can't use any kernel-level copy techniques for this,
		 * we have to read into userspace and copy it back.
		 * Since we're already doing that, it also makes sense to use
		 * buffer writes (using FILE*), rather than writing directly. */
		if (pfds[0].revents & POLLIN) {
			/* Node writing towards socket */
			char input[BUFSIZ];
			rres = read(l->wpfd[0], input, sizeof(input));
			if (rres <= 0) {
				break;
			}
			res = deliver(l, input, (size_t) rres, l->orig_wfd, 1);
			if (rres <= 0) {
				break;
			}
			l->sentbytes += (size_t) res;
			pfds[0].revents = 0;
		}
		if (pfds[1].revents & POLLIN) {
			/* Got data from socket for node */
			char input[BUFSIZ];
			rres = read(l->orig_rfd, input, sizeof(input));
			if (rres <= 0) {
				break;
			}
			res = deliver(l, input, (size_t) rres, l->rpfd[1], 0);
			if (rres <= 0) {
				break;
			}
			l->recvbytes += (size_t) res;
			pfds[1].revents = 0;
		}
		if (pfds[0].revents || pfds[1].revents) {
			bbs_debug(3, "poll returned %s\n", poll_revent_name(pfds[0].revents ? pfds[0].revents : pfds[1].revents));
			break;
		}
	}
	bbs_debug(4, "Log thread exiting\n");
	PIPE_CLOSE(l->wpfd);
	PIPE_CLOSE(l->rpfd);
	return NULL;
}

/* I/O transformation callback functions */

static int setup(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg)
{
	struct log_data *l;
	char template[64] = "/tmp/iolog_XXXXXX";

	/* Since we generally want to log the data without encryption or compression, etc.
	 * (we want to log the application layer data, without any presentation layer stuff),
	 * this transformation should be added last.
	 * That works out, because since it's added manually, it'll be added
	 * during the session, after the other stuff has already been set up. */

	UNUSED(dir);
	UNUSED(arg);

	l = calloc(1, sizeof(*l));
	if (ALLOC_FAILURE(l)) {
		return -1;
	}

	l->fp = bbs_mkftemp(template, 0600);
	if (!l->fp) {
		goto fail;
	}

	if (pipe(l->rpfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		goto fail;
	} else if (pipe(l->wpfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		goto fail;
	}

	/* Spawn a separate thread to handle the new intermediate layer and the compression/decompression */
	if (bbs_pthread_create(&l->thread, NULL, log_thread, l)) {
		goto fail;
	}

	/* Fiddle the file descriptors around */
	l->orig_rfd = *rfd;
	l->orig_wfd = *wfd;
	*rfd = l->rpfd[0]; /* Application now reads from the read end of this pipe */
	*wfd = l->wpfd[1]; /* Application now writes to the write end of the other pipe */

	/* For example (assuming this is for a node):
	 *
	 *    Layer 7 (Application)                                         Layer 6 (Presentation Layer)
	 *                                          io_log           
	 *
	 * -----   <--- read(l->rpfd[0])  <---  write(l->rpfd[1]) <--- read(l->orig_rfd)  <-- ... other I/O transformations ...  ------------
	 * NODE |                                                                                                               | TCP socket |
	 * -----   ---> write(l->wpfd[1]) ----> read(l->wpfd[0])  ---> write(l->orig_wfd) --> ... other I/O transformations ...  ------------
	 */

	RWLIST_WRLOCK(&loggers);
	RWLIST_INSERT_HEAD(&loggers, l, entry);
	RWLIST_UNLOCK(&loggers);

	bbs_verb(6, "Started I/O logging session to %s\n", template);

	*data = l; /* Store as transform callback data */
	return 0;

fail:
	PIPE_CLOSE(l->rpfd);
	PIPE_CLOSE(l->wpfd);
	if (l->fp) {
		fclose(l->fp);
	}
	free(l);
	return -1;
}

static void cleanup(struct bbs_io_transformation *tran)
{
	struct log_data *l = tran->data;
	bbs_assert_exists(l);

	RWLIST_WRLOCK(&loggers);
	RWLIST_REMOVE(&loggers, l, entry);
	RWLIST_UNLOCK(&loggers);

	l->done = 1;
	pthread_kill(l->thread, SIGUSR1); /* Signal log_thread (shutdown(l->wpfd[1], SHUT_RDWR) does not work) */
	PIPE_CLOSE(l->rpfd);
	PIPE_CLOSE(l->wpfd);
	bbs_pthread_join(l->thread, NULL);
	if (l->fp) {
		fclose(l->fp);
	}
	free(l);
}

static int load_module(void)
{
	return bbs_io_transformer_register("X-LOG", setup, NULL, cleanup, TRANSFORM_SESSION_LOGGING, TRANSFORM_SERVER_CLIENT_TX_RX);
}

static int unload_module(void)
{
	return bbs_io_transformer_unregister("X-LOG");
}

BBS_MODULE_INFO_STANDARD("I/O Logging Module");
