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
 * \brief General utility functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h> /* use isprint, isspace */
#include <unistd.h>
#include <dirent.h>
#include <time.h> /* use time */
#include <sys/time.h> /* use gettimeofday */
#include <uuid/uuid.h> /* use uuid_generate, uuid_unparse */
#include <syscall.h>
#include <sys/sendfile.h>

#include "include/utils.h"
#include "include/node.h" /* use bbs_fd_poll_read */
#include "include/base64.h"

char *bbs_uuid(void)
{
	char *uuid;
	uuid_t binary_uuid;

	uuid_generate_random(binary_uuid);
	uuid = malloc(UUID_STR_LEN + 1);
	if (!uuid) {
		return NULL;
	}
	uuid_unparse_lower(binary_uuid, uuid);
	return uuid;
}

int dyn_str_append(struct dyn_str *dynstr, const char *s, size_t len)
{
	int newlen;

	if (!dynstr->buf) {
		dynstr->buf = strdup(s);
		if (!dynstr->buf) {
			bbs_error("strdup failed\n");
			return -1;
		}
		dynstr->len = len;
		dynstr->used = len;
		return len;
	}

	/* Do we have enough room in the existing buffer? */
	newlen = dynstr->used + len;
	if (newlen >= dynstr->len) {
		char *newbuf = realloc(dynstr->buf, newlen);
		if (!newbuf) {
			bbs_error("realloc failed\n");
			return -1;
		}
		dynstr->buf = newbuf;
		dynstr->len = newlen;
	}
	memcpy(dynstr->buf + dynstr->used, s, len);
	dynstr->used = newlen;
	return newlen;
}

void bbs_readline_init(struct readline_data *rldata, char *buf, int len)
{
	memset(rldata, 0, sizeof(*rldata));
	rldata->buf = buf;
	rldata->len = len;
	/* Initialize internals: start at the beginning */
	rldata->pos = rldata->buf;
	rldata->left = rldata->len;
	rldata->leftover = 0;
}

/*! \brief Helper function to read a single line from a file descriptor, with a timeout (for any single read) */
int bbs_fd_readline(int fd, struct readline_data *rldata, const char *delim, int timeout)
{
	int res;
	char *firstdelim = NULL;
	int delimlen;
	int used;

	if (rldata->leftover) { /* Data from previous read still in the buffer */
		/* Shift contents of buffer back to beginning, which simplifies some things over potentially circling around until we wrap. */
		memmove(rldata->buf, rldata->pos, rldata->leftover);
		res = rldata->leftover; /* Pretend like we just read this many bytes, just now. */
		rldata->buf[res] = '\0';
#if 0
		bbs_debug(8, "Shifted buffer now contains: %s\n", rldata->buf);
#endif
		/* Update our position to where we need to be. */
		rldata->pos = rldata->buf + res;
		rldata->left = rldata->len - res;
		/* If we already have a delimiter, no need to proceed further. */
		firstdelim = strstr(rldata->buf, delim); /* Use buf, not pos, since pos is the beginning of the buffer that remains at this point. */
		res = rldata->leftover = 0;
	} else {
		rldata->pos = rldata->buf;
		rldata->left = rldata->len;
	}

	while (!firstdelim) {
#ifdef EXTRA_CHECKS
		bbs_assert(rldata->pos + rldata->left - 1 <= rldata->buf + rldata->len); /* If we're going to corrupt the stack and crash anyways, might as well assert. */
#endif
		res = bbs_fd_poll_read(fd, timeout, rldata->pos, rldata->left - 1); /* Subtract 1 for NUL */
		if (res <= 0) {
			bbs_debug(3, "read returned %d\n", res);
			return res - 1; /* see the doxygen notes: we should return 0 only if we read just the delimiter. */
		}
		rldata->pos[res] = '\0'; /* Safe. Null terminate so we can use string functions. */
		firstdelim = strstr(rldata->pos, delim); /* Find the first occurence of the delimiter, if present. */
		/* Update our position */
		rldata->pos += res;
		rldata->left -= res;
	}

	delimlen = strlen(delim);

	/* We have at least 1 complete command, and maybe more. */
	*firstdelim = '\0'; /* Null terminate here so the caller can just read from the buffer and get a full line (up to and not including the delimiter). */
	used = firstdelim - rldata->buf; /* Number of bytes, NOT including the trimmed delimiter. */
	firstdelim += delimlen; /* There is the beginning of the rest of the buffer. No, we do not need to add 1 here. */
	rldata->leftover = rldata->pos - firstdelim; /* Number of bytes leftover. */
	bbs_debug(6, "Read %lu bytes (%d just now), processing %d and leaving %d leftover\n", rldata->pos - rldata->buf, res, used, rldata->leftover);
	rldata->pos = firstdelim; /* Update pos to point to the beginning, not the end, of the remaining data in the buffer. leftover tells us how much is left, we don't need a pointer to it directly. */

	firstdelim += 2; /* There is no guarantee that this doesn't contain garbage, but this is our next position. */
	return used; /* Return number of bytes that we're actually returning, not however many are really in the buffer, since the caller won't care about that anyways. */
}

unsigned char *bbs_sasl_decode(const char *s, char **authorization, char **authentication, char **passwd)
{
	int outlen;
	unsigned char *decoded;
	int runlen = 0;
	char *authorization_id, *authentication_id, *password;

	decoded = base64_decode((unsigned char*) s, strlen(s), &outlen);
	/* If you were to dump decoded here using a printf-style function, you would just see the username, since the string is separated by NULs. We need the outlen. */
	if (!decoded) {
		return NULL;
	}
	authorization_id = (char*) decoded;
	runlen += strlen(authorization_id) + 1;
	if (runlen >= outlen) {
		bbs_warning("No data after nickname?\n");
		free(decoded);
		return NULL;
	}
	authentication_id = (char*) decoded + runlen;
	runlen += strlen(authentication_id) + 1;
	if (runlen >= outlen) {
		bbs_warning("No data after username?\n");
		free(decoded);
		return NULL;
	}
	password = (char*) decoded + runlen;

	*authorization = authorization_id;
	*authentication = authentication_id;
	*passwd = password;
	return decoded;
}

int bbs_dir_traverse_items(const char *path, int (*on_file)(const char *dir_name, const char *filename, int dir, void *obj), void *obj)
{
	DIR *dir;
	struct dirent *entry;
	int res;

	/* Since we'll be using errno to check for problems, zero it out now. That said, a module we load could set it while we're loading modules. */
	if (errno) {
		bbs_debug(10, "errno was %s, ignoring\n", strerror(errno));
		errno = 0;
	}

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	res = 0;

	while ((entry = readdir(dir)) != NULL) { /* Don't just bail out if errno becomes set, modules could set errno when we load them. */
		int is_file = 0;
		int is_dir = 0;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		/* If the dirent structure has a d_type use it to determine if we are dealing with
		 * a file or directory. Unfortunately if it doesn't have it, or if the type is
		 * unknown, or a link then we'll need to use the stat function instead. */
		if (entry->d_type != DT_UNKNOWN && entry->d_type != DT_LNK) {
			is_file = entry->d_type == DT_REG;
			is_dir = entry->d_type == DT_DIR;
		} else {
			continue; /* Something else? Skip it */
		}

		if (is_file || is_dir) {
			/* If the handler returns non-zero then stop */
			if ((res = on_file(path, entry->d_name , is_dir, obj))) {
				break;
			}
			/* Otherwise move on to next item in directory */
		}
	}

	closedir(dir);

	if (res && errno) {
		bbs_error("Error while reading directories (%d) - %s: %s\n", res, path, strerror(errno));
		res = -1;
	}

	return res;
}

/*! \note This function is used by autoload_modules */
static int __bbs_dir_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, void *obj), void *obj, int max_depth, int dironly)
{
	DIR *dir;
	struct dirent *entry;
	int res;
	int isroot;

	/* Since we'll be using errno to check for problems, zero it out now. That said, a module we load could set it while we're loading modules. */
	if (errno) {
		bbs_debug(10, "errno was %s, ignoring\n", strerror(errno));
		errno = 0;
	}

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	--max_depth;
	res = 0;
	isroot = !strcmp(path, "/") ? 1 : 0;

	while ((entry = readdir(dir)) != NULL) { /* Don't just bail out if errno becomes set, modules could set errno when we load them. */
		int is_file = 0;
		int is_dir = 0;
		char *full_path = NULL;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		/* If the dirent structure has a d_type use it to determine if we are dealing with
		 * a file or directory. Unfortunately if it doesn't have it, or if the type is
		 * unknown, or a link then we'll need to use the stat function instead. */
		if (entry->d_type != DT_UNKNOWN && entry->d_type != DT_LNK) {
			is_file = entry->d_type == DT_REG;
			is_dir = entry->d_type == DT_DIR;
		} else {
			continue; /* Something else? Skip it */
		}

		if (is_file && !dironly) {
			/* If the handler returns non-zero then stop */
			if ((res = on_file(path, entry->d_name, obj))) {
				break;
			}
			/* Otherwise move on to next item in directory */
			continue;
		}

		if (!is_dir) {
			bbs_debug(6, "Skipping %s: not a regular file or directory\n", entry->d_name);
			continue;
		}

		/* Only recurse into sub-directories if not at the max depth */
		if (max_depth != 0) {
			if (!full_path) {
				/* Don't use alloca or allocate on the stack, because we're in a loop */
				full_path = malloc(strlen(path) + strlen(entry->d_name) + 2);
				if (!full_path) {
					return -1;
				}
#undef sprintf /* This is safe */
				sprintf(full_path, "%s/%s", isroot ? "" : path, entry->d_name);
			}
			bbs_debug(4, "Recursing into %s\n", full_path);
			if ((res = __bbs_dir_traverse(full_path, on_file, obj, max_depth, dironly))) {
				free(full_path);
				break;
			}
		} else {
			bbs_error("Recursion depth maxed out for recursive directory traversal\n");
		}
		free(full_path);
	}

	closedir(dir);

	if (res && errno) {
		bbs_error("Error while reading directories (%d) - %s: %s\n", res, path, strerror(errno));
		res = -1;
	}

	return res;
}

int bbs_dir_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, void *obj), void *obj, int max_depth)
{
	return __bbs_dir_traverse(path, on_file, obj, max_depth, 0);
}

int bbs_dir_traverse_dirs(const char *path, int (*on_file)(const char *dir_name, const char *filename, void *obj), void *obj, int max_depth)
{
	return __bbs_dir_traverse(path, on_file, obj, max_depth, 1);
}

int bbs_dir_has_file_prefix(const char *path, const char *prefix)
{
	DIR *dir;
	struct dirent *entry;
	int res;
	int prefixlen = strlen(prefix);

	/* Since we'll be using errno to check for problems, zero it out now. */
	if (errno) {
		errno = 0;
	}

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	res = 0;

	while ((entry = readdir(dir)) != NULL) { /* Don't just bail out if errno becomes set, modules could set errno when we load them. */
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		} else if (entry->d_type == DT_REG) {
			if (!strncmp(entry->d_name, prefix, prefixlen)) {
				res = 1;
				break;
			}
		}
	}

	closedir(dir);

	if (res < 0 && errno) {
		bbs_error("Error while reading directories (%d) - %s: %s\n", res, path, strerror(errno));
		res = -1;
	}

	return res;
}

int bbs_dir_has_subdirs(const char *path)
{
	DIR *dir;
	struct dirent *entry;
	int res;

	/* Since we'll be using errno to check for problems, zero it out now. */
	if (errno) {
		errno = 0;
	}

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	res = 0;

	while ((entry = readdir(dir)) != NULL) { /* Don't just bail out if errno becomes set, modules could set errno when we load them. */
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		} else if (entry->d_type == DT_DIR) {
			res = 1;
			break;
		}
	}

	closedir(dir);

	if (res < 0 && errno) {
		bbs_error("Error while reading directories (%d) - %s: %s\n", res, path, strerror(errno));
		res = -1;
	}

	return res;
}

/*! \note Skips using bbs_dir_traverse and does it directly since executing a callback for every single file is an expensive way to calculate the quota */
static int __bbs_dir_size(const char *path, long *size, int max_depth)
{
	DIR *dir;
	struct dirent *entry;
	int res;
	int isroot;
	struct stat st;

	/* Since we'll be using errno to check for problems, zero it out now. */
	if (errno) {
		errno = 0;
	}

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	--max_depth;
	res = 0;
	isroot = !strcmp(path, "/") ? 1 : 0;

	/* Include the directory itself. */
#if 0
	if (stat(path, &st)) {
		bbs_error("stat(%s) failed: %s\n", path, strerror(errno));
	} else {
		*size = *size + st.st_size;
	}
#else
	*size += 4096; /* Each directory should add 4096 bytes */
#endif

	while ((entry = readdir(dir)) != NULL) { /* Don't just bail out if errno becomes set, modules could set errno when we load them. */
		int is_file = 0;
		int is_dir = 0;
		char *full_path = NULL;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		/* If the dirent structure has a d_type use it to determine if we are dealing with
		 * a file or directory. Unfortunately if it doesn't have it, or if the type is
		 * unknown, or a link then we'll need to use the stat function instead. */
		if (entry->d_type != DT_UNKNOWN && entry->d_type != DT_LNK) {
			is_file = entry->d_type == DT_REG;
			is_dir = entry->d_type == DT_DIR;
		} else {
			continue; /* Something else? Skip it */
		}

		if (is_file) {
			char fullname[512];
			snprintf(fullname, sizeof(fullname), "%s/%s", path, entry->d_name);
			if (stat(fullname, &st)) {
				bbs_error("stat(%s) failed: %s\n", fullname, strerror(errno));
			} else {
#ifdef EXTRA_DEBUG
				bbs_debug(10, "File %s is %ld bytes\n", fullname, st.st_size);
#endif
				*size = *size + st.st_size;
			}
			continue;
		} else if (!is_dir) { /* Not a regular file or directory */
			bbs_debug(7, "Skipping non-regular file/directory: %s\n", entry->d_name);
			continue;
		}

		/* Only recurse into sub-directories if not at the max depth */
		if (max_depth != 0) {
			if (!full_path) {
				/* Don't use alloca or allocate on the stack, because we're in a loop */
				full_path = malloc(strlen(path) + strlen(entry->d_name) + 2);
				if (!full_path) {
					return -1;
				}
				sprintf(full_path, "%s/%s", isroot ? "" : path, entry->d_name); /* Safe */
			}
			bbs_debug(4, "Recursing into %s\n", full_path);
			res = __bbs_dir_size(full_path, size, max_depth);
			if (res) {
				free(full_path);
				break;
			}
		} else {
			bbs_error("Recursion depth maxed out for recursive directory traversal\n");
		}
		free(full_path);
	}

	closedir(dir);

	if (res && errno) {
		bbs_error("Error while reading directories (%d) - %s: %s\n", res, path, strerror(errno));
		res = -1;
	}

	return res;
}

long bbs_dir_size(const char *path)
{
	int res;
	long size = 0;
	res = __bbs_dir_size(path, &size, 32);
	if (res) {
		return res;
	}
	bbs_debug(6, "Directory %s size is %ld bytes\n", path, size);
	return size;
}

FILE *bbs_mkftemp(char *template, mode_t mode)
{
	FILE *p;
	int pfd;

	pfd = mkstemp(template); /* template will get updated to contain the actual filename */
	chmod(template, mode);

	if (pfd == -1) {
		/* It's not specified if mkstemp sets errno, but check it anyways */
		bbs_error("mkstemp failed: %s\n", strerror(errno));
		return NULL;
	}

	p = fdopen(pfd, "w+");
	if (!p) {
		bbs_error("Failed to open file %s: %s\n", template, strerror(errno));
		close(pfd);
		return NULL;
	}
	return p;
}

int bbs_copy_file(int srcfd, int destfd, int start, int bytes)
{
	int copied;
	off_t offset;

	if (!bytes) { /* Something's not right. */
		bbs_warning("Wanted to copy 0 bytes from file descriptor %d?\n", srcfd);
		return -1;
	}

	offset = start;
	/* This is not a POSIX function, it exists only in Linux.
	 * Like sendfile, it's more efficient than moving data between kernel and userspace,
	 * since the kernel can do the copy directly.
	 * Closest we can get to a system call that will copy a file for us. */
	copied = copy_file_range(srcfd, &offset, destfd, NULL, bytes, 0);
	/* If copy_file_range fails, the syscall probably isn't available on this system. */
#if 0
	if (copied == -1 && errno == ENOSYS) {
		/* copy_file_range glibc function doesn't exist on this function. */
		bbs_debug(5, "copy_file_range glibc wrapper doesn't exist?\n");
		copied = syscall(__NR_copy_file_range, srcfd, &offset, destfd, NULL, bytes, 0);
	}
#endif
	if (copied == -1 && errno == ENOSYS) {
		/* Okay, the actual syscall doesn't even exist. Fall back to sendfile. */
		copied = sendfile(destfd, srcfd, &offset, bytes);
	}
	if (copied == -1) {
		bbs_error("copy %d -> %d failed: %s\n", srcfd, destfd, strerror(errno));
		return -1;
	} else if (copied != bytes) {
		bbs_error("Wanted to copy %d bytes but only copied %d?\n", bytes, copied);
		return -1;
	}
	close(srcfd);
	close(destfd);
	return copied;
}

struct timeval bbs_tvnow(void)
{
	struct timeval t;
	gettimeofday(&t, NULL);
	return t;
}

/*! \note This is ast_tvdiff_ms from Asterisk (GPLv2) */
int64_t bbs_tvdiff_ms(struct timeval end, struct timeval start)
{
	/* the offset by 1,000,000 below is intentional...
	it avoids differences in the way that division
	is handled for positive and negative numbers, by ensuring
	that the divisor is always positive
	*/
	int64_t sec_dif = (int64_t)(end.tv_sec - start.tv_sec) * 1000;
	int64_t usec_dif = (1000000 + end.tv_usec - start.tv_usec) / 1000 - 1000;
	return sec_dif + usec_dif;
}

int bbs_time_friendly_short_now(char *buf, size_t len)
{
	time_t lognow;
    struct tm logdate;

	lognow = time(NULL);
    localtime_r(&lognow, &logdate);
	/* 01/01 01:01pm = 13 chars */
	return strftime(buf, len, "%m/%d %I:%M%P", &logdate);
}

int bbs_time_friendly_now(char *buf, size_t len)
{
	time_t lognow;
    struct tm logdate;

	lognow = time(NULL);
    localtime_r(&lognow, &logdate);
	/* Sat Dec 31 2000 09:45 am EST =  29 chars */
	return strftime(buf, len, "%a %b %e %Y %I:%M %P %Z", &logdate);
}

int bbs_time_friendly(int epoch, char *buf, size_t len)
{
	time_t lognow;
    struct tm logdate;
	/* Accept an int and cast internally for ease of usage: callers can directly provide int timestamps
	 * without having to manually cast to time_t on the stack and provide a pointer */
	time_t epocht = (time_t) epoch;

	lognow = time(&epocht);
    localtime_r(&lognow, &logdate);
	/* Sat Dec 31 2000 09:45 am EST =  29 chars */
	return strftime(buf, len, "%a %b %e %Y %I:%M %P %Z", &logdate);
}

void print_time_elapsed(int start, int end, char *buf, size_t len)
{
	int diff;
	int hr, min, sec;

	if (!end) {
		end = time(NULL);
	}

	diff = end - start;
	hr = diff / 3600;
	diff -= (hr * 3600);
	min = diff / 60;
	diff -= (min * 60);
	sec = diff;
	snprintf(buf, len, "%d:%02d:%02d", hr, min, sec);
}

void print_days_elapsed(int start, int end, char *buf, size_t len)
{
	int diff;
	int days, hr, min, sec;

	if (!end) {
		end = time(NULL);
	}

	diff = end - start;
	days = diff / (3600 * 24);
	diff -= (days * (3600 * 24));
	hr = diff / 3600;
	diff -= (hr * 3600);
	min = diff / 60;
	diff -= (min * 60);
	sec = diff;
	snprintf(buf, len, "%d day%s, %d hr%s, %d min%s, %d sec%s", days, ESS(days), hr, ESS(hr), min, ESS(min), sec, ESS(sec));
}

int bbs_printable_strlen(const char *s)
{
	int c = 0;
	while (*s) {
		if (*s == 27) {
			/* Escape sequences include printable characters, so we need to process them as an entire unit */
			if (*(s + 1) == '[') {
				/* Control Sequence Introducer: Begins an (ANSI) escape sequence.
				 * These are variable length, ugh...
				 * XXX This is far from complete, in fact it's close to incomplete.
				 * Because bbs_printable_strlen is mainly used to deal with color,
				 * that's the main thing we handle here.
				 */
				if (*(s + 2) == '1' && *(s + 3) == ';' && isdigit(*(s + 4)) && isdigit(*(s + 5)) && *(s + 6) == 'm') {
					/* Color */
					s += 7; /* Skip the whole escape sequence */
					continue;
				}
			}
		} else if (isprint(*s)) {
			s++;
			c++;
		} else if (*s == '\t') {
			/* Oh boy. This is impossible to say. It depends on WHERE the tab is on the page. We have no context here. */
			/* Fortunately, this shouldn't happen. The automatic menu screen generator doesn't use tabs.
			 * Users may use tabs if they manually make the screen using display= in menus.conf,
			 * but in that case, we don't call print_strlen on that. */
			bbs_warning("Printable string length calculation may be inaccurate: string contains TAB\n");
			s++;
			c += 4; /* Assume 4 characters, but this is kinda arbitrary. But for the purposes we care about, overestimate is safer than underestimate. */
		} else {
			s++; /* Some other non printable thing, just ignore it */
		}
	}
	return c;
}

int bbs_str_process_backspaces(const char *s, char *buf, size_t len)
{
	int i = 0;
	while (*s) {
		if (len <= 1) {
			bbs_error("Truncation occured\n");
			return -1;
		}
		if (*s == 8 || *s == 127) { /* BACKSPACE or DELETE character */
			if (i > 0) {
				*--buf = '\0';
				len++;
				i--;
			} /* else, ignore backspaces at beginning of line */
			s++;
		} else {
			*buf++ = *s++;
			i++;
			len--;
		}
	}
	*buf = '\0';
	return 0;
}

int bbs_str_safe_print(const char *s, char *buf, size_t len)
{
	char ascii_num[7];

	while (*s) {
		if (len <= 1) {
			bbs_error("Truncation occurred when building string\n");
			return -1;
		}
		/* isprint doesn't include LF, but we don't want to.
		 * It does include TAB, which we don't want either. */
		if (isprint(*s) && *s != '\t') {
			*buf = *s; /* Just copy */
			buf++;
			len--;
		} else {
			/* Make a representation */
			size_t replen = snprintf(ascii_num, sizeof(ascii_num), "<%d>", *s);
			if (replen >= len - 1) {
				bbs_error("Truncation occurred when building string\n");
				return -1;
			}
			safe_strncpy(buf, ascii_num, len - 1);
			buf += replen;
			len -= replen;
		}
		s++;
	}
	*buf = '\0';
	return 0;
}

void bbs_dump_string(const char *s)
{
	char buf[1024];
	char *pos = buf;
	int len = sizeof(buf) - 4;

	while (*s) {
		if (len <= 6) {
			break;
		}
		if (isprint(*s)) {
			*pos++ = *s;
			len--;
		} else {
			if (*s == '\r') {
				strcpy(pos, "<CR>"); /* Safe */
				pos += 4;
				len -= 4;
			} else if (*s == '\n') {
				strcpy(pos, "<LF>");
				pos += 4;
				len -= 4;
			} else {
				int b = snprintf(pos, len, "<%d>", *s);
				pos += b;
				len -= b;
			}
		}
		s++;
	}

	*pos = '\0';
	bbs_debug(8, "String Dump: '%s'\n", buf);
}

int bbs_strcpy_nospaces(const char *s, char *buf, size_t len)
{
	/* Copy the username, not including spaces */
	while (*s && --len > 1) {
		if (isprint(*s) && !isspace(*s)) {
			*buf++ = *s;
		}
		s++;
	}
	*buf = '\0'; /* Null terminate */
	return len > 1 ? 0 : -1;
}

void bbs_strreplace(char *s, char find, char repl)
{
	while (*s) {
		if (*s == find) {
			*s = repl;
		}
		s++;
	}
}

int bbs_str_isprint(const char *s)
{
	while (*s) {
		/* isprint doesn't include LF */
		if (!isprint(*s) && !isspace(*s)) {
			bbs_debug(3, "Character %d is not printable\n", *s);
			return 0;
		}
		s++;
	}
	return 1;
}

int bbs_str_anyprint(const char *s)
{
	while (*s) {
		if (isprint(*s) && !isspace(*s)) {
			return 1;
		}
		s++;
	}
	return 0;
}
