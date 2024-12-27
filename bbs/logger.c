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
#include <unistd.h>
#include <sys/time.h> /* use gettimeofday */
#include <unistd.h> /* use write */
#include <sys/stat.h> /* use mkdir */
#include <sys/types.h>
#include <poll.h>
#include <limits.h> /* use PATH_MAX */

#include "include/utils.h" /* use bbs_gettid, bbs_tvnow */
#include "include/linkedlists.h"
#include "include/cli.h"

/* Log messages to STDERR when we fail to write log messages to remote consoles */
#define DEBUG_LOGGING_FAILURES

/* bbs.c */
extern int option_debug;
extern int option_verbose;
extern int max_logfile_debug_level;

static FILE *logfp = NULL;
static int logstdout = 0;
static int stdoutavailable = 0;

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

static int cli_verbose(struct bbs_cli_args *a)
{
	int res;

	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */
	res = bbs_set_verbose(atoi(a->argv[1]));
	return res < 0 ? res : 0;
}

static int cli_debug(struct bbs_cli_args *a)
{
	int res;

	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */
	res = bbs_set_debug(atoi(a->argv[1]));
	return res < 0 ? res : 0;
}

static int cli_maxdebug(struct bbs_cli_args *a)
{
	int oldmax, newmax;

	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */
	newmax = atoi(a->argv[1]);
	if (newmax < 0 || newmax > MAX_DEBUG) {
		return -1;
	}
	oldmax = max_logfile_debug_level;
	max_logfile_debug_level = newmax;
	bbs_debug(1, "Max file debug level changed from %d to %d\n", oldmax, newmax);
	return 0;
}

static int cli_localdebug(struct bbs_cli_args *a);

static struct bbs_cli_entry cli_commands_logger[] = {
	BBS_CLI_COMMAND(cli_verbose, "verbose", 2, "Set verbose log level", "verbose <newlevel>"),
	BBS_CLI_COMMAND(cli_debug, "debug", 2, "Set debug log level", "debug <newlevel>"),
	BBS_CLI_COMMAND(cli_maxdebug, "maxdebug", 2, "Set max file debug log level", "maxdebug <newlevel>"),
	BBS_CLI_COMMAND(cli_localdebug, "localdebug", 2, "Set max debug log level for current console session", "localdebug <newlevel>"),
};

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
	if (bbs_cli_register_multiple(cli_commands_logger)) {
		return -1;
	}
	return 0;
}

int bbs_set_stdout_logging(int enabled)
{
	if (enabled && !stdoutavailable) {
		bbs_debug(1, "Can't enable logging to stdout when daemonized\n");
		return -1;
	}
	logstdout = enabled;
	return 0;
}

/*! \note int lists, anyone? */
struct remote_log_fd {
	int fd;			/* File descriptor for this console */
	int maxdebug;	/* Max debug level for this console */
	unsigned int skipped:1;
	unsigned int enabled:1;
	bbs_mutex_t lock;
	RWLIST_ENTRY(remote_log_fd) entry; /* Next entry */
};

static RWLIST_HEAD_STATIC(remote_log_fds, remote_log_fd);

/* Local debug setting for foreground console, since it doesn't have a struct remote_log_fd */
static int fg_maxdebug = MAX_DEBUG;

static int active_remote_consoles = 0;

int bbs_set_fd_logging(int fd, int enabled)
{
	struct remote_log_fd *rfd;
	RWLIST_RDLOCK(&remote_log_fds); /* We're not modifying the list itself. */
	RWLIST_TRAVERSE(&remote_log_fds, rfd, entry) {
		if (rfd->fd == fd) {
			SET_BITFIELD(rfd->enabled, enabled);
			break;
		}
	}
	RWLIST_UNLOCK(&remote_log_fds);
	return rfd ? 0 : -1;
}

static int set_fd_logging_max_debug(int fd, int maxdebug)
{
	int oldmax;
	struct remote_log_fd *rfd;
	RWLIST_WRLOCK(&remote_log_fds);
	RWLIST_TRAVERSE(&remote_log_fds, rfd, entry) {
		if (rfd->fd == fd) {
			oldmax = rfd->maxdebug;
			rfd->maxdebug = maxdebug;
			break;
		}
	}
	RWLIST_UNLOCK(&remote_log_fds);
	return rfd ? oldmax : -1;
}

static int cli_localdebug(struct bbs_cli_args *a)
{
	int oldmax, newmax;

	newmax = atoi(a->argv[1]);
	if (newmax < 0 || newmax > MAX_DEBUG) {
		return -1;
	}

	if (a->fdout == STDOUT_FILENO) {
		oldmax = fg_maxdebug;
		fg_maxdebug = newmax;
	} else {
		oldmax = set_fd_logging_max_debug(a->fdout, newmax);
		if (oldmax == -1) {
			return -1;
		}
	}
	bbs_debug(1, "Max local debug level for fd %d changed from %d to %d\n", a->fdout, oldmax, newmax);
	return 0;
}

int bbs_add_logging_fd(int fd)
{
	struct remote_log_fd *rfd;

	RWLIST_WRLOCK(&remote_log_fds);
	RWLIST_TRAVERSE(&remote_log_fds, rfd, entry) {
		if (rfd->fd == fd) {
			break;
		}
	}
	if (unlikely(rfd != NULL)) {
		bbs_error("File descriptor %d already has logging\n", fd);
		RWLIST_UNLOCK(&remote_log_fds);
		return -1;
	}
	rfd = calloc(1, sizeof(*rfd));
	if (ALLOC_FAILURE(rfd)) {
		RWLIST_UNLOCK(&remote_log_fds);
		return -1;
	}
	rfd->fd = fd;
	rfd->enabled = 1; /* Initialize to enabled */
	rfd->maxdebug = MAX_DEBUG; /* By default, there is no local restriction on the max debug level */
	bbs_mutex_init(&rfd->lock, NULL);
	RWLIST_INSERT_HEAD(&remote_log_fds, rfd, entry);
	active_remote_consoles++;
	RWLIST_UNLOCK(&remote_log_fds);
	bbs_debug(5, "Registered file descriptor %d for logging\n", fd);
	return 0;
}

int bbs_remove_logging_fd(int fd)
{
	struct remote_log_fd *rfd;

	RWLIST_WRLOCK(&remote_log_fds);
	rfd = RWLIST_REMOVE_BY_FIELD(&remote_log_fds, fd, fd, entry);
	active_remote_consoles--;
	RWLIST_UNLOCK(&remote_log_fds);
	if (unlikely(!rfd)) {
		bbs_error("File descriptor %d did not have logging\n", fd);
	} else {
		bbs_mutex_destroy(&rfd->lock);
		free(rfd);
		bbs_debug(5, "Unregistered file descriptor %d from logging\n", fd);
	}
	return rfd ? 0 : -1;
}

int bbs_log_close(void)
{
	bbs_assert(logfp != NULL);
	bbs_debug(1, "Shutting down BBS logger\n");

	/* The CLI shuts down before logging, so the logging CLI commands have already been removed at this point */

	fclose(logfp);
	logfp = NULL;
	logstdout = 0;
	return 0;
}

#define COLOR_LOG(name, color) (COLOR_START color COLOR_BEGIN name COLOR_RESET)
#define COLOR_LOG_OR(name, color, term) term ? COLOR_LOG(name, color) : name

static const char *loglevel2str(enum bbs_log_level level, int term)
{
	/* WARNING/VERBOSE are the longest names, so make them all that long by left-padding with spaces, for visual alignment. */
	switch (level) {
		case LOG_ERROR:
			return COLOR_LOG_OR("  ERROR", TERM_COLOR_RED, term);
		case LOG_WARNING:
			return COLOR_LOG_OR("WARNING", TERM_COLOR_RED, term);
		case LOG_NOTICE:
			return COLOR_LOG_OR(" NOTICE", TERM_COLOR_MAGENTA, term);
		case LOG_AUTH:
			return COLOR_LOG_OR("   AUTH", TERM_COLOR_BROWN, term);
		case LOG_VERBOSE:
			return COLOR_LOG_OR("VERBOSE", TERM_COLOR_CYAN, term);
		case LOG_DEBUG:
			return COLOR_LOG_OR("  DEBUG", TERM_COLOR_GREEN, term);
	}
	__builtin_unreachable();
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
	__builtin_unreachable();
}

#define log_puts(msg) fprintf(logfp, "%s", msg); fflush(logfp);
#define term_puts(msg) fprintf(stdout, "%s", msg); fflush(stdout);

void __attribute__ ((format (gnu_printf, 1, 2))) bbs_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fflush(stdout);
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
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		fflush(stdout);
	} else {
		va_start(ap, fmt);
		vdprintf(fd, fmt, ap);
		va_end(ap);
	}
}

/* from bbs.c */
extern int shutdown_finished;

static unsigned short int logid_counter; /* Can roll over, only used for local diagnostics */

void __attribute__ ((format (gnu_printf, 6, 7))) __bbs_log(enum bbs_log_level loglevel, int level, const char *file, int lineno, const char *func, const char *fmt, ...)
{
	int len;
	va_list ap;
	time_t lognow;
	struct tm logdate;
	struct timeval now;
	char datestr[20];
	char logminibuf[512];
	char logfullbuf[768];
	char *buf = logminibuf;
	char *fullbuf = logfullbuf;
	int thread_id;
	int dynamic = 0, fulldynamic = 0;
	int bytes;
	int log_stdout, log_remote;
	int need_reset = 0;
	int skip_logfile = 0;
	short unsigned int logid;

	switch (loglevel) {
		case LOG_DEBUG:
			if (level > option_debug) {
				return;
			}
			skip_logfile = level > max_logfile_debug_level;
			break;
		case LOG_VERBOSE:
			if (level > option_verbose) {
				return;
			}
			/* Fall through */
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
	} else if (!logfp) {
		/* Attempt to call logger before it's even initialized. e.g. allocation failure during startup. */
		if (stdoutavailable) {
			va_start(ap, fmt);
			len = vprintf(fmt, ap);
			va_end(ap);
		}
		return;
	}

	bbs_assert(logfp != NULL);

#pragma GCC diagnostic ignored "-Waggregate-return"
	now = bbs_tvnow();
#pragma GCC diagnostic pop
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);

	thread_id = bbs_gettid();
	logid = bbs_atomic_fetchadd_int(&logid_counter, +1);

	va_start(ap, fmt);
	len = vsnprintf(logminibuf, sizeof(logminibuf), fmt, ap);
	va_end(ap);

	if (len >= (int) sizeof(logminibuf)) {
		/* Too large for stack allocated buffer. Dynamically allocate it. */
		dynamic = 1;
		buf = malloc((size_t) len + 1);
		if (ALLOC_FAILURE(buf)) {
			va_list ap2;
			/* Fall back to simple logging. */
			va_start(ap, fmt);
			va_copy(ap2, ap);
			if (stdoutavailable) {
				vfprintf(stderr, fmt, ap);
			}
			va_end(ap);
			if (logfp) {
				vfprintf(logfp, fmt, ap2);
			}
			va_end(ap2);
			return;
		}
		va_start(ap, fmt);
#undef vsprintf
		vsprintf(buf, fmt, ap); /* vsprintf is safe, vsnprintf is unnecessary here */
		va_end(ap);
	}

	need_reset = strchr(buf, 27) ? 1 : 0; /* If contains ESC, this could contain a color escape sequence. Reset afterwards. */

	/* Race condition here is fine, but helgrind won't like it: */
	log_stdout = logstdout;
	log_remote = active_remote_consoles > 0; /* Small chance a brand new console could register between this check and traversing the remote consoles... but not a big deal. */

	/* If the foreground or any remote consoles are active, prepare a log message for any connected consoles. */
	if (log_stdout || log_remote) {
		int delays = 0;
		struct remote_log_fd *rfd;
		if (loglevel == LOG_VERBOSE && verbose_special_formatting) {
			const char *verbprefix = verbose_prefix(level);
			bytes = snprintf(logfullbuf, sizeof(logfullbuf), "[%s.%03d] %s%s%s", datestr, (int) now.tv_usec / 1000, verbprefix, buf, need_reset ? COLOR_RESET : "");
			if (bytes >= (int) sizeof(logfullbuf)) {
				fulldynamic = 1;
				fullbuf = malloc((size_t) bytes + 1);
				if (ALLOC_FAILURE(fullbuf)) {
					term_puts("ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
					term_puts(buf); /* Just put what we had */
					goto stdoutdone;
				}
				/* Safe */
#undef sprintf
				sprintf(fullbuf, "[%s.%03d] %s%s%s", datestr, (int) now.tv_usec / 1000, verbprefix, buf, need_reset ? COLOR_RESET : "");
			}
		} else {
			bytes = snprintf(logfullbuf, sizeof(logfullbuf), "[%s.%03d] %s[%d]: %s%s:%d %s%s: %s%s", datestr, (int) now.tv_usec / 1000, loglevel2str(loglevel, 1), thread_id, COLOR_START TERM_COLOR_WHITE COLOR_BEGIN, file, lineno, func, COLOR_RESET, buf, need_reset ? COLOR_RESET : "");
			if (bytes >= (int) sizeof(logfullbuf)) {
				fullbuf = malloc((size_t) bytes + 1);
				if (ALLOC_FAILURE(fullbuf)) {
					term_puts("ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
					term_puts(buf); /* Just put what we had */
					goto stdoutdone;
				}
				fulldynamic = 1;
				/* Safe */
				bytes = sprintf(fullbuf, "[%s.%03d] %s[%d]: %s%s:%d %s%s: %s%s", datestr, (int) now.tv_usec / 1000, loglevel2str(loglevel, 1), thread_id, COLOR_START TERM_COLOR_WHITE COLOR_BEGIN, file, lineno, func, COLOR_RESET, buf, need_reset ? COLOR_RESET : "");
			}
		}

		/* Log to foreground console, if there is one */
		if (log_stdout && (loglevel != LOG_DEBUG || level <= fg_maxdebug)) {
			term_puts(fullbuf);
		}

		/* Log to remote consoles */
		RWLIST_RDLOCK(&remote_log_fds); /* Each console has its own lock, so a read lock is perfectly fine and allows more logging throughput */
		RWLIST_TRAVERSE(&remote_log_fds, rfd, entry) {
			char *bufstart = fullbuf;
			size_t bytesleft = (size_t) bytes;
			ssize_t wres;

			if (loglevel == LOG_DEBUG && level > rfd->maxdebug) {
				/* Skip consoles that don't want debug messages of this debug level */
				continue;
			} else if (!rfd->enabled) {
				continue; /* Logging disabled for this console */
			}

			/* Although acquiring a lock for every log message to every remote console is not ideal,
			 * it is necessary because otherwise, concurrent writes could result
			 * in messages being split up when logged, and we need to ensure messages are logged atomically. */
			bbs_mutex_lock(&rfd->lock);

			/* Prevent libc_write from blocking if there's a ton of logging going on. */
			bbs_unblock_fd(rfd->fd);

			/* Can't use bbs_timed_write, since that can log additional messages. */
			wres = write(rfd->fd, bufstart, bytesleft);
			/* Failed or partial write. Retry if we have time.
			 * Introduce no more than a 10 ms delay max, even that might be too much. The 10 ms is for all consoles, not just this one.
			 * In practice, since we have a mutex for each remote console, this is rarely needed. */
			while (((wres == -1 && errno == EAGAIN) || (wres > 0 && (size_t) wres < bytesleft)) && delays < 10) {
				/* Since we don't have a log queue, it is possible that multiple threads
				 * could try logging to the same terminals concurrently,
				 * after all, this traversal only uses a RDLOCK.
				 * If this happens, try again after a small instant. That will usually succeed. */
				struct pollfd pfd;
				memset(&pfd, 0, sizeof(pfd));
				pfd.fd = rfd->fd;
				pfd.events = POLLOUT;
				/* Do not wait more than 1 millisecond. Even that is already a lot,
				 * since this could add a delay of up to 1 ms per remote console,
				 * and this log operation is blocking a thread that is doing actual work!
				 * select() would give us more granularity, but it's unsafe. */
				delays++;
				if (wres > 0) {
					bufstart += wres;
					bytesleft -= (size_t) wres;
#ifdef DEBUG_LOGGING_FAILURES
					fprintf(stderr, "%5u [%d <%d>] Retrying partial write\n", logid, thread_id, rfd->fd);
				} else {
					fprintf(stderr, "%5u [%d <%d>] Retrying failed write\n", logid, thread_id, rfd->fd);
#endif
				}
				/* If we can make progress now, try again. Otherwise, give up immediately.
				 * (And if poll returns 1, we probably can make progress, since we are still holding the console lock,
				 *  nobody else can write to it in the meantime.) */
				if (poll(&pfd, 1, 1) > 0) {
					wres = write(rfd->fd, bufstart, bytesleft);
				} else {
					/* Release console lock ASAP */
					bbs_block_fd(rfd->fd);
					bbs_mutex_unlock(&rfd->lock);
					fprintf(stderr, "%5u [%d <%d>] Failed to log %lu bytes: Resource temporarily unavailable\n", logid, thread_id, rfd->fd, bytesleft);
					goto nextiteration; /* Can't continue since we're in a double loop. We want to continue the outer loop. */
				}
#ifdef DEBUG_LOGGING_FAILURES
				if (wres == (ssize_t) bytesleft) {
					fprintf(stderr, "%5u [%d <%d>] Succeeded after retry\n", logid, thread_id, rfd->fd);
				}
#endif
			}
			if (wres != (ssize_t) bytesleft) {
				int saved_errno = errno;
				/* Release console lock ASAP */
				bbs_block_fd(rfd->fd);
				bbs_mutex_unlock(&rfd->lock);
				/* Well, we can't log a message if we failed to log a message.
				 * That would probably not work out well. */
				fprintf(stderr, "%5u [%d <%d>] Failed to log %lu bytes (wrote %ld): %s\n", logid, thread_id, rfd->fd, bytesleft, wres, strerror(saved_errno));
			} else {
				bbs_block_fd(rfd->fd);
				bbs_mutex_unlock(&rfd->lock);
			}
nextiteration:
			;
		}
		RWLIST_UNLOCK(&remote_log_fds);
		if (fulldynamic) {
			free(fullbuf);
		}
stdoutdone:
		/* Reset */
		fulldynamic = 0;
		fullbuf = logfullbuf;
	}

	if (!skip_logfile) {
		/* Log message to file should not include color formatting */
		bytes = snprintf(logfullbuf, sizeof(logfullbuf), "[%s.%03d] %s[%d]: %s:%d %s: %s%s", datestr, (int) now.tv_usec / 1000, loglevel2str(loglevel, 0), thread_id, file, lineno, func, buf, need_reset ? COLOR_RESET : "");
		if (bytes >= (int) sizeof(logfullbuf)) {
			fullbuf = malloc((size_t) bytes + 1);
			if (ALLOC_FAILURE(fullbuf)) {
				log_puts("ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
				log_puts(buf); /* Just put what we had */
				goto almostdone;
			}
			fulldynamic = 1;
			/* Safe */
			sprintf(fullbuf, "[%s.%03d] %s[%d]: %s:%d %s: %s%s", datestr, (int) now.tv_usec / 1000, loglevel2str(loglevel, 0), thread_id, file, lineno, func, buf, need_reset ? COLOR_RESET : "");
		}

		fwrite(fullbuf, 1, (size_t) bytes, logfp);
		fflush(logfp);

		if (fulldynamic) {
			free(fullbuf);
		}
	}

almostdone:
	if (dynamic) {
		free(buf);
	}
}
