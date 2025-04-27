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
 * \brief File descriptor leak wrapper
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h> /* use atoi */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h> /* use getprotobynumber */
#include <sys/resource.h> /* use getrlimit */
#include <dirent.h>

#include "include/utils.h"
#include "include/cli.h"

#define FDLEAKS_NUM_FDS 1024

#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
/* Undefine the overrides in bbs.h to expose the real functions */
#undef open
#undef accept
#undef pipe
#undef socketpair
#undef eventfd
#undef socket
#undef close
#undef fopen
#undef fclose
#undef dup2
#undef dup

static struct fdinfo {
	const char *callname;
	int line;
	unsigned int isopen:1;
	char file[40];
	char function[25];
	char callargs[100];
	time_t now;
} fdinfo[FDLEAKS_NUM_FDS];

/* #define FD_LOGFILE "/var/log/lbbs/fd.log" */

#ifdef FD_LOGFILE
static bbs_mutex_t fd_loglock = BBS_MUTEX_INITIALIZER;
static FILE *fd_logfile = NULL;
#endif

#ifdef FD_LOGFILE
#define FD_LOGF(nowarg, file, line, func, fmt, ...) \
	bbs_mutex_lock(&fd_loglock); \
	if (fd_logfile) { \
		time_t now = nowarg; \
		char datestring[24]; \
		struct tm opendate; \
		localtime_r(&now, &opendate); \
		strftime(datestring, sizeof(datestring), "%F %T", &opendate); \
		fprintf(fd_logfile, "%s: %s:%d (%s) " fmt, datestring, file, line, func, ## __VA_ARGS__); \
	} \
	bbs_mutex_unlock(&fd_loglock);
#else
#define FD_LOGF(now, file, line, func, fmt, ...)
#endif

/*! \brief Get number of file descriptors open by current process */
static int num_open_fds(void)
{
	DIR *dp = opendir("/proc/self/fd");
	struct dirent *de;
	int count = 0;

	if (!dp) {
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		count++;
	}
	closedir(dp);

	return count - 3; /* don't count ., .., self */
}

static int print_fds(int fd)
{
	DIR *dir;
	struct dirent *entry;
	char symlink[256];
	const char *fd_dir;
	ssize_t bytes;

#ifdef __linux__
	fd_dir = "/proc/self/fd";
#else
	fd_dir = "/dev/fd";
#endif

	if (!(dir = opendir(fd_dir))) {
		bbs_error("Error opening directory - %s: %s\n", fd_dir, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_LNK) {
			char path[512];
			int fdnum = atoi(entry->d_name);
			/* Only care about ones we don't know about */
			if (ARRAY_IN_BOUNDS(fdnum, fdinfo) && fdinfo[fdnum].isopen) {
				continue; /* We know about it */
			}
			snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
			bytes = readlink(path, symlink, sizeof(symlink) - 1);
			if (bytes == -1) {
				bbs_error("readlink: %s\n", strerror(errno));
				continue;
			}
			symlink[bytes] = '\0'; /* Safe (readlink does not null terminate) */
			bbs_dprintf(fd, "%5s => %s\n", entry->d_name, symlink);
		}
	}

	closedir(dir);
	return 0;
}

#define fd_log(fd, fmt, ...) \
	if (fd == -1) { \
		bbs_warning(fmt, ## __VA_ARGS__); \
	} else { \
		bbs_dprintf(fd, fmt, ## __VA_ARGS__); \
	}

static int bbs_fd_dump(int fd)
{
#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
	unsigned int i, opened = 0;
	struct rlimit rl;

	getrlimit(RLIMIT_NOFILE, &rl);

	for (i = 0; i < ARRAY_LEN(fdinfo); i++) {
		/* Some of the assigned fds are >= ARRAY_LEN(fdinfo), so not all will show up here */
		if (fdinfo[i].isopen) {
			char datestring[24];
			struct tm opendate;
			localtime_r(&fdinfo[i].now, &opendate);
			strftime(datestring, sizeof(datestring), "%F %T", &opendate);
			fd_log(fd, "%5u [%s] %18s:%-5d %-25s %s(%s)\n", i, datestring, fdinfo[i].file, fdinfo[i].line, fdinfo[i].function, fdinfo[i].callname, fdinfo[i].callargs);
			opened++;
		}
	}
	if (fd != -1) { /* If we're out of file descriptors, we can't do this anyways since it requires one */
		print_fds(fd); /* Print fds we don't know about */
	}
	/* Add 1 because readdir in print_fds will open a FD */
	fd_log(fd, "Open files: %u (%d) / %d\n", opened, num_open_fds() + 1, (int) rl.rlim_cur); /* XXX RLIM_INFINITY? */

#else
	fd_log("%s compiled without DEBUG_FD_LEAKS\n", __FILE__);
#endif
	return 0;
}

/* COPY does safe_strncpy(dst, src, sizeof(dst)), except:
 * - if it doesn't fit, it copies the value after the slash
 *   (possibly truncated)
 * - if there is no slash, it copies the value with the head
 *   truncated */
#define	COPY(dst, src) { \
	size_t dlen = sizeof(dst), slen = strlen(src);                \
	if (slen + 1 > dlen) {                                     \
		const char *slash = strrchr(src, '/');                 \
		if (slash) {                                           \
			safe_strncpy(dst, slash + 1, dlen);             \
		} else {                                               \
			safe_strncpy(dst, src + slen - dlen + 1, dlen); \
		}                                                      \
	} else {                                                   \
		safe_strncpy(dst, src, dlen);                       \
	}                                                          \
}

#define STORE_COMMON(offset, name, ...) { \
	struct fdinfo *tmp = &fdinfo[offset]; \
	tmp->now = time(NULL); \
	COPY(tmp->file, file);      \
	tmp->line = line;           \
	COPY(tmp->function, func);  \
	tmp->callname = name;       \
	snprintf(tmp->callargs, sizeof(tmp->callargs), __VA_ARGS__); \
	tmp->isopen = 1;            \
	FD_LOGF(tmp->now, tmp->file, tmp->line, tmp->function, "%d = %s(%s)\n", offset, tmp->callname, tmp->callargs); \
}

#define LOG_FAILURE() \
	if (errno == EMFILE) { \
		/* Possible file descriptor exhaustion, dump file descriptors to aid in debugging */ \
		bbs_fd_dump(-1); \
	} \

#define STORE_COMMON_HELPER(fd, name, fmt, ...) \
	if (fd > -1) { \
		if (fd < (int) ARRAY_LEN(fdinfo)) { \
			STORE_COMMON(fd, name, fmt, ## __VA_ARGS__); \
		} \
	} else { \
		LOG_FAILURE(); \
	}

#define MARK_OPEN(fd) \
	fdinfo[fd].isopen = 1; \
	COPY(fdinfo[fd].file, file); \
	fdinfo[fd].line = line; \
	fdinfo[fd].now = time(NULL);

#define MARK_CLOSED(fd) \
	fdinfo[fd].isopen = 0; \
	/* Update to where it was closed so we can debug attempts to close previously closed fds */ \
	COPY(fdinfo[fd].file, file); \
	fdinfo[fd].line = line; \
	fdinfo[fd].now = time(NULL);

int __bbs_open(const char *file, int line, const char *func, const char *path, int flags, ...)
{
	int res;
	va_list ap;
	int mode;

/* Proactively ensure we don't inadvertently acquire controlling terminal.
 * Okay to enable in production. */
#define CHECK_FOR_CONTROLLING_TERMINAL

/* Always add the O_NOCTTY flag blindly to every open().
 * While this is correct and harmless, this should not normally be used since it masks bugs,
 * the bugs being not using O_NOCTTY at the appropriate calling site.
 * Only use for debugging when things have already gone wrong. */
/* #define PREVENT_ACCIDENTAL_CONTROLLING_TERMINAL */

#ifdef PREVENT_ACCIDENTAL_CONTROLLING_TERMINAL
#if O_NOCTTY != 0
	/* Since there is really never a scenario in which we want to acquire controlling terminal
	 * by opening something, it is always safe to do this.
	 * In fact, on many non-Linux systems, O_NOCTTY is 0 (which honestly makes more sense).
	 * However, to be semantic, the open call itself should have O_NOCTTY if needed.
	 * Therefore, rather than always blindly adding this flag,
	 * this should only be done for debugging (since doing this will make it work properly). */
	flags |= O_NOCTTY;
#endif
#endif /* PREVENT_ACCIDENTAL_CONTROLLING_TERMINAL */

	if (flags & O_CREAT) {
		char sflags[80];
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
		res = open(path, flags, mode);
		snprintf(sflags, sizeof(sflags), "O_CREAT%s%s%s%s%s%s%s%s",
			flags & O_APPEND ? "|O_APPEND" : "",
			flags & O_EXCL ? "|O_EXCL" : "",
			flags & O_NONBLOCK ? "|O_NONBLOCK" : "",
			flags & O_TRUNC ? "|O_TRUNC" : "",
			flags & O_RDWR ? "|O_RDWR" : "",
#if O_RDONLY == 0
			!(flags & (O_WRONLY | O_RDWR)) ? "|O_RDONLY" : "",
#else
			flags & O_RDONLY ? "|O_RDONLY" : "",
#endif
			flags & O_WRONLY ? "|O_WRONLY" : "",
			"");
		flags &= ~(O_CREAT | O_APPEND | O_EXCL | O_NONBLOCK | O_TRUNC | O_RDWR | O_RDONLY | O_WRONLY);
		if (flags) {
			STORE_COMMON_HELPER(res, "open", "\"%s\",%s|%d,%04o", path, sflags, flags, mode);
		} else {
			STORE_COMMON_HELPER(res, "open", "\"%s\",%s,%04o", path, sflags, mode);
		}
	} else {
		res = open(path, flags);
		STORE_COMMON_HELPER(res, "open", "\"%s\",%d", path, flags);
	}

#ifdef CHECK_FOR_CONTROLLING_TERMINAL
	/* We do not want to ever have any controlling terminal.
	 * Otherwise, when it exits, the BBS receives a SIGHUP.
	 * In the worst case, this could cause the BBS to exit if the signal isn't ignored.
	 * At best, it's wasting a signal that can be used for other purposes. */
	if (res != -1 && isatty(res) && !(flags & O_NOCTTY)) {
		/* We only need to bother checking if the returned file descriptor is a TTY to begin with,
		 * and if the original flags did NOT include O_NOCTTY, since if they did, it wouldn't be. */
		int ctty = open("/dev/tty", 0); /* If it's not -1, that means we're a controlling terminal (BAD!) */
		/* If we got here, this assertion is almost certainly going to fail... but confirm, to be sure */
		if (bbs_assertion_failed(ctty == -1)) {
			/* Technically, just because we happen to have a controlling terminal now,
			 * doesn't mean this open is what actually caused that.
			 * Something else may have happened just prior to the open() call, or just after it.
			 * But there's a good chance this is the offender. */
			__bbs_log(LOG_WARNING, 0, file, line, func, "Yikes, we just acquired a controlling terminal!\n");
			close(ctty);
		}
	}
#endif

	return res;
}

int __bbs_accept(int socket, struct sockaddr *address, socklen_t *address_len,
	const char *file, int line, const char *func)
{
	int res = accept(socket, address, address_len);
	STORE_COMMON_HELPER(res, "accept", "{%d}", socket);
	return res;
}

int __bbs_pipe(int *fds, const char *file, int line, const char *func)
{
	int i, res = pipe(fds);
	if (res) {
		return res;
	}
	for (i = 0; i < 2; i++) {
		STORE_COMMON_HELPER(fds[i], "pipe", "{%d,%d}", fds[0], fds[1]);
	}
	return 0;
}

int __bbs_socketpair(int domain, int type, int protocol, int sv[2],
	const char *file, int line, const char *func)
{
	int i, res = socketpair(domain, type, protocol, sv);
	if (res) {
		return res;
	}
	for (i = 0; i < 2; i++) {
		STORE_COMMON_HELPER(sv[i], "socketpair", "{%d,%d}", sv[0], sv[1]);
	}
	return 0;
}

int __bbs_eventfd(unsigned int initval, int flags, const char *file, int line, const char *func)
{
	int res = eventfd(initval, flags);
	STORE_COMMON_HELPER(res, "eventfd", "{%d}", res);
	return res;
}

int __bbs_socket(int domain, int type, int protocol, const char *file, int line, const char *func)
{
	char sdomain[20], stype[20];
	const char *sproto = NULL;
	struct protoent *pe;
	int res = socket(domain, type, protocol);
	if (res < 0) {
		LOG_FAILURE();
	} else if (res >= (int) ARRAY_LEN(fdinfo)) {
		bbs_warning("File descriptor %d out of logging range\n", res);
	}

	if ((pe = getprotobynumber(protocol))) {
		sproto = pe->p_name;
	}

	if (domain == PF_UNIX) {
		safe_strncpy(sdomain, "PF_UNIX", sizeof(sdomain));
	} else if (domain == PF_INET) {
		safe_strncpy(sdomain, "PF_INET", sizeof(sdomain));
	} else {
		snprintf(sdomain, sizeof(sdomain), "%d", domain);
	}

	if (type == SOCK_DGRAM) {
		safe_strncpy(stype, "SOCK_DGRAM", sizeof(stype));
		if (protocol == 0) {
			sproto = "udp";
		}
	} else if (type == SOCK_STREAM) {
		safe_strncpy(stype, "SOCK_STREAM", sizeof(stype));
		if (protocol == 0) {
			sproto = "tcp";
		}
	} else {
		snprintf(stype, sizeof(stype), "%d", type);
	}

	if (sproto) {
		STORE_COMMON_HELPER(res, "socket", "%s,%s,\"%s\"", sdomain, stype, sproto);
	} else {
		STORE_COMMON_HELPER(res, "socket", "%s,%s,\"%d\"", sdomain, stype, protocol);
	}
	return res;
}

int bbs_std_close(int fd)
{
	return close(fd);
}

int __bbs_close(int fd, const char *file, int line, const char *func)
{
	int res;

	/* Detect attempts to close file descriptors we shouldn't be closing
	 * (e.g. can happen if a file descriptor variable is initialized to 0 instead of -1) */
	if (unlikely(fd <= 2) && (fd < 0 || strcmp(file, "system.c"))) { /* It's legitimate to close file descriptors 0, 1, and 2 when calling exec */
		bbs_warning("Attempting to close file descriptor %d at %s:%d (%s)\n", fd, file, line, func);
		bbs_log_backtrace(); /* Get a backtrace to see what made the invalid close, in case immediate caller isn't enough detail. */
	}
	res = close(fd);
	if (res) {
		int close_errno = errno;
		if (bbs_assertion_failed(close_errno != EBADF) && ARRAY_IN_BOUNDS(fd, fdinfo)) {
			__bbs_log(LOG_ERROR, 0, file, line, func, "Failed to close fd %d: %s (previously %s at %s:%d)\n",
				fd, strerror(close_errno), fdinfo[fd].isopen ? "opened" : "closed", fdinfo[fd].file, fdinfo[fd].line);
		} else {
			__bbs_log(LOG_ERROR, 0, file, line, func, "Failed to close fd %d: %s\n", fd, strerror(close_errno));
		}
	} else if (ARRAY_IN_BOUNDS(fd, fdinfo)) { /* && !res (implicit) */
		MARK_CLOSED(fd);
	}
	FD_LOGF(time(NULL), file, line, func, "close(%d)\n", fd);
	return res;
}

int __bbs_mark_opened(int fd, const char *file, int line, const char *func)
{
	if (!bbs_fd_valid(fd)) {
		__bbs_log(LOG_WARNING, 0, file, line, func, "File descriptor %d is not valid\n", fd);
		return 1;
	}
	bbs_debug(5, "Marking file descriptor %d as open\n", fd);
	if (ARRAY_IN_BOUNDS(fd, fdinfo)) {
		if (bbs_assertion_failed(!fdinfo[fd].isopen)) {
			char datestring[24];
			struct tm opendate;
			localtime_r(&fdinfo[fd].now, &opendate);
			strftime(datestring, sizeof(datestring), "%F %T", &opendate);
			__bbs_log(LOG_WARNING, 0, file, line, func, "File descriptor %d marked open, but was already opened at %s:%d at %s?\n", fd, fdinfo[fd].file, fdinfo[fd].line, datestring);
		}
		MARK_OPEN(fd);
		/* Since we don't have a function or call args, blank them out so a previous one doesn't linger */
		strcpy(fdinfo[fd].function, "");
		fdinfo[fd].callname = "";
		strcpy(fdinfo[fd].callargs, "");
	}
	FD_LOGF(time(NULL), file, line, func, "mark_opened(%d)\n", fd);
	return 0;
}

int __bbs_mark_closed(int fd, const char *file, int line, const char *func)
{
	/* Don't attempt to close the file descriptor, if it's already closed.
	 * Something else may reuse it in the meantime and we could close something else.
	 * Of course, if that's the case, we'll mess up our state array below,
	 * but that's lower stakes than actually messing up program behavior. */
	if (bbs_fd_valid(fd)) {
		/* Only a warning, not an error, because race conditions are possible with file descriptors.
		 * It's possible it really was closed, but got opened by the time we got here.
		 * That said, it is unlikely, so log a warning just in case something really is wrong. */
		__bbs_log(LOG_WARNING, 0, file, line, func, "File descriptor %d is still valid\n", fd);
		return 1;
	}
	bbs_debug(5, "Marking file descriptor %d as closed\n", fd);
	if (ARRAY_IN_BOUNDS(fd, fdinfo)) {
		if (bbs_assertion_failed(fdinfo[fd].isopen)) {
			char datestring[24];
			struct tm opendate;
			localtime_r(&fdinfo[fd].now, &opendate);
			strftime(datestring, sizeof(datestring), "%F %T", &opendate);
			__bbs_log(LOG_WARNING, 0, file, line, func, "File descriptor %d marked closed, but was already closed at %s:%d at %s?\n", fd, fdinfo[fd].file, fdinfo[fd].line, datestring);
		}
		MARK_CLOSED(fd);
	}
	FD_LOGF(time(NULL), file, line, func, "mark_closed(%d)\n", fd);
	return 0;
}

FILE *__bbs_fopen(const char *path, const char *mode, const char *file, int line, const char *func)
{
	FILE *res = fopen(path, mode);
	int fd;
	if (!res) {
		return res;
	}
	fd = fileno(res);
	STORE_COMMON_HELPER(fd, "fopen", "\"%s\",\"%s\"", path, mode);
	return res;
}

FILE *bbs_std_fopen(const char *path, const char *mode)
{
	return fopen(path, mode);
}

int bbs_std_fclose(FILE *ptr)
{
	return fclose(ptr);
}

int __bbs_fclose(FILE *ptr, const char *file, int line, const char *func)
{
	int fd, res;

#ifndef FD_LOGFILE
	UNUSED(func);
#endif

	bbs_assert_exists(ptr);
	fd = fileno(ptr);
	if ((res = fclose(ptr) || !ARRAY_IN_BOUNDS(fd, fdinfo))) {
		return res;
	}
	MARK_CLOSED(fd);
	FD_LOGF(time(NULL), file, line, func, "fclose(%d)\n", fd);
	return res;
}

int __bbs_dup2(int oldfd, int newfd, const char *file, int line, const char *func)
{
	int res = dup2(oldfd, newfd);
	/* On success, newfd will be closed automatically if it was already
	 * open. We don't need to mention anything about that, we're updating
	 * the value anyway. */
	STORE_COMMON_HELPER(res, "dup2", "%d,%d", oldfd, newfd); /* res == newfd */
	return res;
}

int __bbs_dup(int oldfd, const char *file, int line, const char *func)
{
	int res = dup(oldfd);
	STORE_COMMON_HELPER(res, "dup2", "%d", oldfd);
	return res;
}

#endif /* DEBUG_FD_LEAKS */

static int cli_fds(struct bbs_cli_args *a)
{
	return bbs_fd_dump(a->fdout);
}

BBS_CLI_COMMAND_SINGLE(cli_fds, "fds", 1, "View list of open file descriptors", NULL);

void bbs_fd_shutdown(void)
{
#ifdef FD_LOGFILE
	bbs_mutex_lock(&fd_loglock);
	if (fd_logfile) {
		bbs_debug(5, "Closing fd logfile\n");
		fclose(fd_logfile);
		fd_logfile = NULL;
		/*! \note It is technically possible during shutdown that some other threads
		 * still have file descriptors to close and thus, at this point,
		 * those won't get logged. */
	}
	bbs_mutex_unlock(&fd_loglock);
#endif
	bbs_fd_dump(STDOUT_FILENO);
}

int bbs_fd_init(void)
{
#ifdef FD_LOGFILE
	bbs_mutex_lock(&fd_loglock);
	fd_logfile = fopen(FD_LOGFILE, "w"); /* Start fresh each run */
	if (!fd_logfile) {
		bbs_error("Failed to open %s for writing: %s\n", FD_LOGFILE, strerror(errno));
	}
	bbs_mutex_unlock(&fd_loglock);
#endif
	return bbs_cli_register(&cli_command); /* Automatically unregistered at shutdown */
}
