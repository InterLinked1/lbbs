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

#include "include/utils.h"

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
