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
 *
 * \note Mostly borrowed from astfd.c from Asterisk (GPLv2)
 */

#include "include/bbs.h"

#include <stdlib.h> /* use atoi */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h> /* use getprotobynumber */
#include <sys/resource.h> /* use getrlimit */
#include <dirent.h>

#include "include/utils.h"

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

static struct fdleaks {
	const char *callname;
	int line;
	unsigned int isopen:1;
	char file[40];
	char function[25];
	char callargs[100];
	time_t now;
} fdleaks[FDLEAKS_NUM_FDS];

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
	struct fdleaks *tmp = &fdleaks[offset]; \
	tmp->now = (int) time(NULL); \
	COPY(tmp->file, file);      \
	tmp->line = line;           \
	COPY(tmp->function, func);  \
	tmp->callname = name;       \
	snprintf(tmp->callargs, sizeof(tmp->callargs), __VA_ARGS__); \
	tmp->isopen = 1;            \
}

int __fdleak_open(const char *file, int line, const char *func, const char *path, int flags, ...)
{
	int res;
	va_list ap;
	int mode;

	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
		res = open(path, flags, mode);
		if (res > -1 && res < (int) ARRAY_LEN(fdleaks)) {
			char sflags[80];
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
				STORE_COMMON(res, "open", "\"%s\",%s|%d,%04o", path, sflags, flags, mode);
			} else {
				STORE_COMMON(res, "open", "\"%s\",%s,%04o", path, sflags, mode);
			}
		}
	} else {
		res = open(path, flags);
		if (res > -1 && res < (int) ARRAY_LEN(fdleaks)) {
			STORE_COMMON(res, "open", "\"%s\",%d", path, flags);
		}
	}
	return res;
}

int __fdleak_accept(int socket, struct sockaddr *address, socklen_t *address_len,
	const char *file, int line, const char *func)
{
	int res = accept(socket, address, address_len);

	if (res >= 0) {
		STORE_COMMON(res, "accept", "{%d}", socket);
	}

	return res;
}

int __fdleak_pipe(int *fds, const char *file, int line, const char *func)
{
	int i, res = pipe(fds);
	if (res) {
		return res;
	}
	for (i = 0; i < 2; i++) {
		if (fds[i] > -1 && fds[i] < (int) ARRAY_LEN(fdleaks)) {
			STORE_COMMON(fds[i], "pipe", "{%d,%d}", fds[0], fds[1]);
		}
	}
	return 0;
}

int __fdleak_socketpair(int domain, int type, int protocol, int sv[2],
	const char *file, int line, const char *func)
{
	int i, res = socketpair(domain, type, protocol, sv);
	if (res) {
		return res;
	}
	for (i = 0; i < 2; i++) {
		if (sv[i] > -1 && sv[i] < (int) ARRAY_LEN(fdleaks)) {
			STORE_COMMON(sv[i], "socketpair", "{%d,%d}", sv[0], sv[1]);
		}
	}
	return 0;
}

int __fdleak_eventfd(unsigned int initval, int flags, const char *file, int line, const char *func)
{
	int res = eventfd(initval, flags);

	if (res >= 0) {
		STORE_COMMON(res, "eventfd", "{%d}", res);
	}

	return res;
}

int __fdleak_socket(int domain, int type, int protocol, const char *file, int line, const char *func)
{
	char sdomain[20], stype[20];
	const char *sproto = NULL;
	struct protoent *pe;
	int res = socket(domain, type, protocol);
	if (res < 0 || res >= (int) ARRAY_LEN(fdleaks)) {
		return res;
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
		STORE_COMMON(res, "socket", "%s,%s,\"%s\"", sdomain, stype, sproto);
	} else {
		STORE_COMMON(res, "socket", "%s,%s,\"%d\"", sdomain, stype, protocol);
	}
	return res;
}

int __fdleak_close(int fd, const char *file, int line, const char *func)
{
	int res;

	/* Detect attempts to close file descriptors we shouldn't be closing
	 * (e.g. can happen if a file descriptor variable is initialized to 0 instead of -1) */
	if (fd <= 2 && (fd < 0 || strcmp(file, "system.c"))) { /* It's legitimate to close file descriptors 0, 1, and 2 when calling exec */
		bbs_warning("Attempting to close file descriptor %d at %s:%d (%s)\n", fd, file, line, func);
		bbs_log_backtrace(); /* Get a backtrace to see what made the invalid close, in case immediate caller isn't enough detail. */
	}
	res = close(fd);
	if (!res && IN_BOUNDS(fd, 0, (int) ARRAY_LEN(fdleaks))) {
		fdleaks[fd].isopen = 0;
	}
	return res;
}

FILE *__fdleak_fopen(const char *path, const char *mode, const char *file, int line, const char *func)
{
	FILE *res = fopen(path, mode);
	int fd;
	if (!res) {
		return res;
	}
	fd = fileno(res);
	if (fd > -1 && fd < (int) ARRAY_LEN(fdleaks)) {
		STORE_COMMON(fd, "fopen", "\"%s\",\"%s\"", path, mode);
	}
	return res;
}

int __fdleak_fclose(FILE *ptr)
{
	int fd, res;

	bbs_assert_exists(ptr);
	fd = fileno(ptr);
	if ((res = fclose(ptr)) || fd < 0 || fd >= (int) ARRAY_LEN(fdleaks)) {
		return res;
	}
	fdleaks[fd].isopen = 0;
	return res;
}

int __fdleak_dup2(int oldfd, int newfd, const char *file, int line, const char *func)
{
	int res = dup2(oldfd, newfd);
	if (res < 0 || res >= (int) ARRAY_LEN(fdleaks)) {
		return res;
	}
	/* On success, newfd will be closed automatically if it was already
	 * open. We don't need to mention anything about that, we're updating
	 * the value anyway. */
	STORE_COMMON(res, "dup2", "%d,%d", oldfd, newfd); /* res == newfd */
	return res;
}

int __fdleak_dup(int oldfd, const char *file, int line, const char *func)
{
	int res = dup(oldfd);
	if (res < 0 || res >= (int) ARRAY_LEN(fdleaks)) {
		return res;
	}
	STORE_COMMON(res, "dup2", "%d", oldfd);
	return res;
}

#endif /* DEBUG_FD_LEAKS */

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
	char path[512];
	char symlink[256];
	ssize_t bytes;

	if (!(dir = opendir("/proc/self/fd"))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_LNK) {
			int fdnum = atoi(entry->d_name);
			/* Only care about ones we don't know about */
			if (IN_BOUNDS(fdnum, 0, (int) ARRAY_LEN(fdleaks) - 1) && fdleaks[fdnum].isopen) {
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

int bbs_fd_dump(int fd)
{
#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
	unsigned int i, opened = 0;
	struct rlimit rl;
	char datestring[256];

	getrlimit(RLIMIT_NOFILE, &rl);

	for (i = 0; i < ARRAY_LEN(fdleaks); i++) {
		/* Some of the assigned fds are >= ARRAY_LEN(fdleaks), so not all will show up here */
		if (fdleaks[i].isopen) {
			struct tm opendate;
			localtime_r(&fdleaks[i].now, &opendate);
			strftime(datestring, sizeof(datestring), "%F %T", &opendate);
			bbs_dprintf(fd, "%5u [%s] %18s:%-5d %-25s %s(%s)\n", i, datestring, fdleaks[i].file, fdleaks[i].line, fdleaks[i].function, fdleaks[i].callname, fdleaks[i].callargs);
			opened++;
		}
	}
	print_fds(fd); /* Print fds we don't know about */
	/* Add 1 because readdir in print_fds will open a FD */
	bbs_dprintf(fd, "Open files: %u (%d) / %d\n", opened, num_open_fds() + 1, (int) rl.rlim_cur); /* XXX RLIM_INFINITY? */

#else
	bbs_dprintf("%s compiled without DEBUG_FD_LEAKS\n", __FILE__);
#endif
	return 0;
}
