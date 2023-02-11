/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief BBS Logging
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h> /* use opendir, closedir */
#include <time.h>
#include <unistd.h> /* use gettid */
#include <sys/time.h> /* use gettimeofday */
#include <unistd.h> /* use write */
#include <linux/limits.h> /* use PATH_MAX */
#include <sys/stat.h> /* use mkdir */
#include <sys/types.h>
#include <pthread.h>

#include "include/utils.h" /* use bbs_gettid */
#include "include/linkedlists.h"

/* bbs.c */
extern int option_debug;
extern int option_verbose;

static FILE *logfp = NULL;
static int logstdout = 0;
static int stdoutavailable = 0;

/*! \brief Mutexes to force serialization of logging to both log file and foreground console.
 * In theory, fprintf should be capable of handling multiple threads interleaving writes,
 * but if nothing else, this cleans up helgrind whining about it a bit. */
static pthread_mutex_t loglock, termlock;

/*! \brief Pretty printing for verbose log level */
static int verbose_special_formatting = 1;

int bbs_set_verbose(int newlevel)
{
	int old = option_verbose;
	if (newlevel < 0 || newlevel > MAX_VERBOSE) {
		bbs_warning("Invalid verbose level: %d\n", newlevel);
		return -1;
	}
	option_verbose = newlevel;
	/* Only log if logger is initialized */
	if (logfp) {
		bbs_verb(1, "Verbose level changed from %d to %d\n", old, newlevel);
	}
	return old;
}

int bbs_set_debug(int newlevel)
{
	int old = option_debug;
	if (newlevel < 0 || newlevel > MAX_DEBUG) {
		bbs_warning("Invalid debug level: %d\n", newlevel);
		return -1;
	}
	option_debug = newlevel;
	/* Only log if logger is initialized */
	if (logfp) {
		bbs_verb(1, "Debug level changed from %d to %d\n", old, newlevel);
	}
	return old;
}

int bbs_log_init(int nofork)
{
	static char logfile[PATH_MAX];
	DIR *dir;

	/* If BBS_LOG_DIR doesn't exist, create it first. */
	dir = opendir(BBS_LOG_DIR);
	if (dir) {
		closedir(dir);
	} else if (errno == ENOENT) {
		/* Shouldn't happen since bbs.c creates if needed */
		if (mkdir(BBS_LOG_DIR, 0744)) { /* Directory must be executable to be able to create files in it */
			fprintf(stderr, "Unable to create log directory: %s\n", strerror(errno));
			return -1;
		}
	} else {
		fprintf(stderr, "Unable to open log directory: %s\n", strerror(errno));
		return -1;
	}

	snprintf(logfile, sizeof(logfile), "%s/%s", BBS_LOG_DIR, "bbs.log");
	logstdout = nofork;
	stdoutavailable = nofork;

	if (!(logfp = fopen(logfile, "a"))) {
		fprintf(stderr, "Unable to open log file: %s (%s)\n", logfile, strerror(errno));
		return -1;
	}
	fprintf(logfp, "=== BBS logger initialization (pid %d) ===\n", bbs_gettid());
	if (logstdout) {
		fflush(stdout);
	}
	pthread_mutex_init(&loglock, NULL);
	pthread_mutex_init(&termlock, NULL);
	return 0;
}

int bbs_set_stdout_logging(int enabled)
{
	if (enabled && !stdoutavailable) {
		bbs_debug(1, "Can't enable logging to stdout when daemonized\n");
		return -1;
	}
	pthread_mutex_lock(&termlock);
	logstdout = enabled;
	pthread_mutex_unlock(&termlock);
	return 0;
}

/*! \note int lists, anyone? */
struct remote_log_fd {
	int fd;
	RWLIST_ENTRY(remote_log_fd) entry; /* Next entry */
};

static RWLIST_HEAD_STATIC(remote_log_fds, remote_log_fd);

/*! \note Assumes all remote consoles are going to use a fd within the first 1024 */
static int fd_logging[1024]; /* Array for constant time access instead of a linked list. Even though we traverse the list for writing, to set logging on/off, we don't need to. */

int bbs_set_fd_logging(int fd, int enabled)
{
	if (!IN_BOUNDS(fd, 0, (int) ARRAY_LEN(fd_logging))) {
		bbs_error("Cannot set logging for fd %d: out of bounds\n", fd);
		return -1;
	}
	RWLIST_RDLOCK(&remote_log_fds); /* We're not modifying the list itself. */
	fd_logging[fd] = enabled;
	RWLIST_UNLOCK(&remote_log_fds);
	return 0;
}

int bbs_add_logging_fd(int fd)
{
	struct remote_log_fd *rfd;

	if (fd >= (int) ARRAY_LEN(fd_logging)) {
		bbs_error("Cannot register file descriptors greater than %lu\n", ARRAY_LEN(fd_logging));
		return -1;
	}

	RWLIST_WRLOCK(&remote_log_fds);
	RWLIST_TRAVERSE(&remote_log_fds, rfd, entry) {
		if (rfd->fd == fd) {
			break;
		}
	}
	if (rfd) {
		bbs_error("File descriptor %d already has logging\n", fd);
		RWLIST_UNLOCK(&remote_log_fds);
		return -1;
	}
	rfd = calloc(1, sizeof(*rfd));
	if (!fd) {
		bbs_error("calloc failed\n");
		RWLIST_UNLOCK(&remote_log_fds);
		return -1;
	}
	rfd->fd = fd;
	RWLIST_INSERT_HEAD(&remote_log_fds, rfd, entry);
	fd_logging[fd] = 1; /* Initialize to enabled */
	RWLIST_UNLOCK(&remote_log_fds);
	bbs_debug(5, "Registered file descriptor %d for logging\n", fd);
	return 0;
}

int bbs_remove_logging_fd(int fd)
{
	struct remote_log_fd *rfd;

	RWLIST_WRLOCK(&remote_log_fds);
	RWLIST_TRAVERSE_SAFE_BEGIN(&remote_log_fds, rfd, entry) {
		if (rfd->fd == fd) {
			RWLIST_REMOVE_CURRENT(entry);
			free(rfd);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&remote_log_fds);
	if (!rfd) {
		bbs_error("File descriptor %d did not have logging\n", fd);
	} else {
		bbs_debug(5, "Unregistered file descriptor %d from logging\n", fd);
	}
	return rfd ? 0 : -1;
}

int bbs_log_close(void)
{
	bbs_assert(logfp != NULL);
	bbs_debug(1, "Shutting down BBS logger\n");

	pthread_mutex_lock(&loglock);
	pthread_mutex_lock(&termlock);
	fclose(logfp);
	logfp = NULL;
	logstdout = 0;
	pthread_mutex_unlock(&loglock);
	pthread_mutex_unlock(&termlock);

	pthread_mutex_destroy(&loglock);
	pthread_mutex_destroy(&termlock);
	return 0;
}

#define COLOR_LOG(name, color) (COLOR_START color COLOR_BEGIN name COLOR_RESET)
#define COLOR_LOG_OR(name, color, term) term ? COLOR_LOG(name, color) : name

static const char *loglevel2str(enum bbs_log_level level, int term)
{
	/* WARNING/VERBOSE are the longest names, so make them all that long by left-padding with spaces, for visual alignment. */
	switch (level) {
		case LOG_ERROR:
			return COLOR_LOG_OR(" ERROR", COLOR_RED, term);
		case LOG_WARNING:
			return COLOR_LOG_OR("WARNING", COLOR_RED, term);
		case LOG_NOTICE:
			return COLOR_LOG_OR(" NOTICE", COLOR_MAGENTA, term);
		case LOG_AUTH:
			return COLOR_LOG_OR("   AUTH", COLOR_BROWN, term);
		case LOG_VERBOSE:
			return COLOR_LOG_OR("VERBOSE", COLOR_CYAN, term);
		case LOG_DEBUG:
			return COLOR_LOG_OR("  DEBUG", COLOR_GREEN, term);
	}
	bbs_assert(0);
	return NULL;
}

static const char *verbose_prefix(int level)
{
	switch (level) {
		case 0:
		case 1:
			return "";
		case 2:
			return " === ";
		case 3:
			return "  == ";
		case 4:
			return "  -- ";
		case 5:
			return "   -- ";
		case 6:
			return "    ** ";
		case 7:
		case 8:
		case 9:
		case 10:
			return "     > ";
		default:
			bbs_assert(0);
	}
	return NULL;
}

static struct timeval tvnow(void)
{
	struct timeval t;
	gettimeofday(&t, NULL);
	return t;
}

#define log_puts(msg) pthread_mutex_lock(&loglock); fprintf(logfp, "%s", msg); fflush(logfp); pthread_mutex_unlock(&loglock);
#define term_puts(msg) pthread_mutex_lock(&termlock); fprintf(stdout, "%s", msg); fflush(stdout); pthread_mutex_unlock(&termlock);

void __attribute__ ((format (gnu_printf, 1, 2))) bbs_printf(const char *fmt, ...)
{
	va_list ap;

	pthread_mutex_lock(&termlock);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fflush(stdout);
	pthread_mutex_unlock(&termlock);
}

void __attribute__ ((format (gnu_printf, 2, 3))) bbs_dprintf(int fd, const char *fmt, ...)
{
	va_list ap;

	if (fd == STDOUT_FILENO) {
		/* Provide the illusion to the caller of bbs_dprintf of using dprintf,
		 * but actually use serialized printf under the hood.
		 * We do this to surround any writes to STDOUT_FILENO with mutexes,
		 * and if the fd were changed to not STDOUT_FILENO, we would fall back
		 * to normal dprintf below.
		 */
		pthread_mutex_lock(&termlock);
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		fflush(stdout);
		pthread_mutex_unlock(&termlock);
	} else {
		va_start(ap, fmt);
		vdprintf(fd, fmt, ap);
		va_end(ap);
	}
}

/* from bbs.c */
extern int shutdown_finished;

void __attribute__ ((format (gnu_printf, 6, 7))) __bbs_log(enum bbs_log_level loglevel, int level, const char *file, int lineno, const char *func, const char *fmt, ...)
{
	char *buf;
	int len;
	va_list ap;
	time_t lognow;
	struct tm logdate;
	struct timeval now;
	char datestr[20];
	int thread_id;

	switch (loglevel) {
		case LOG_DEBUG:
			if (level > option_debug) {
				return;
			}
			break;
		case LOG_VERBOSE:
			if (level > option_verbose) {
				return;
			}
			break;
		default:
			break;
	}

	if (!logfp && (!strcmp(file, "config.c"))) {
#if 0
		/* If you need to debug config parsing (of bbs.conf) prior to startup, send to STDOUT
		 * We haven't forked yet so this is okay. */
		va_start(ap, fmt);
		len = vprintf(fmt, ap);
		va_end(ap);
#endif
		return; /* Logger isn't yet initialized - config.c has some log calls prior to logger initializing, abort. */
	} else if (!logfp && shutdown_finished) {
		/* Alternately, an attempt to log something after bbs_log_close, specifically after cleanup() has finished.
		 * We can't just keep track if the logger has closed because it's a bug if we call bbs_log with a closed logger.
		 * However, if not all modules unregister before shutdown, then bbs_module_unregister will get called
		 * automatically on exit. So if shutdown has actually finished, make an exception (the fact that the module
		 * was still registered is a bug, but don't assert just because of that). Instead, just use STDOUT if not a daemon. */
		if (stdoutavailable) {
			va_start(ap, fmt);
			len = vprintf(fmt, ap);
			va_end(ap);
		}
		return;
	}

	bbs_assert(logfp != NULL);

	now = tvnow();
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);

	thread_id = bbs_gettid();

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		log_puts("ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
	} else {
		char *fullbuf;
		int bytes;
		int log_stdout;
		int need_reset = 0;

		need_reset = strchr(buf, 27) ? 1 : 0; /* If contains ESC, this could contain a color escape sequence. Reset afterwards. */

		pthread_mutex_lock(&termlock);
		log_stdout = logstdout;
		pthread_mutex_unlock(&termlock);

		if (log_stdout) {
			if (loglevel == LOG_VERBOSE && verbose_special_formatting) {
				const char *verbprefix = verbose_prefix(level);
				bytes = asprintf(&fullbuf, "[%s.%03d] %s%s%s", datestr, (int) now.tv_usec / 1000, verbprefix, buf, need_reset ? COLOR_RESET : "");
			} else {
				bytes = asprintf(&fullbuf, "[%s.%03d] %s[%d]: %s%s:%d %s%s: %s%s", datestr, (int) now.tv_usec / 1000, loglevel2str(loglevel, 1), thread_id, COLOR_START COLOR_WHITE COLOR_BEGIN, file, lineno, func, COLOR_RESET, buf, need_reset ? COLOR_RESET : "");
			}
			if (bytes < 0) {
				term_puts("ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
				term_puts(buf); /* Just put what we had */
			} else {
				struct remote_log_fd *rfd;
				term_puts(fullbuf);
				RWLIST_RDLOCK(&remote_log_fds);
				RWLIST_TRAVERSE(&remote_log_fds, rfd, entry) {
					if (fd_logging[rfd->fd]) {
#undef dprintf
						dprintf(rfd->fd, "%s", fullbuf);
					}
				}
				RWLIST_UNLOCK(&remote_log_fds);
				free(fullbuf);
			}
		}
		bytes = asprintf(&fullbuf, "[%s.%03d] %s[%d]: %s:%d %s: %s%s", datestr, (int) now.tv_usec / 1000, loglevel2str(loglevel, 0), thread_id, file, lineno, func, buf, need_reset ? COLOR_RESET : "");
		if (bytes < 0) {
			log_puts("ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
			log_puts(buf); /* Just put what we had */
		} else {
			log_puts(fullbuf);
			free(fullbuf);
		}
		free(buf);
	}

	return;
}
