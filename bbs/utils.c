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
#include <stdarg.h>
#include <string.h>
#include <ctype.h> /* use isprint, isspace */
#include <unistd.h>
#include <dirent.h>
#include <ftw.h>
#include <time.h> /* use time */
#include <sys/time.h> /* use gettimeofday */
#include <libgen.h> /* use dirname, basename (FreeBSD) */

#ifdef __linux__
#include <uuid/uuid.h> /* use uuid_generate, uuid_unparse */
#include <syscall.h>
#endif

#include "include/utils.h"
#include "include/node.h" /* use bbs_poll_read */
#include "include/user.h"
#include "include/base64.h"

char *bbs_uuid(void)
{
#ifdef UUID_STR_LEN
	char *uuid;
	uuid_t binary_uuid;

	uuid_generate_random(binary_uuid);
	uuid = malloc(UUID_STR_LEN + 1);
	if (ALLOC_FAILURE(uuid)) {
		return NULL;
	}
	uuid_unparse_lower(binary_uuid, uuid);
	return uuid;
#else
	bbs_error("uuid not supported on this platform\n");
	return NULL;
#endif
}

void dyn_str_reset(struct dyn_str *dynstr)
{
	free_if(dynstr->buf);
	dynstr->len = 0;
	dynstr->used = 0;
}

int dyn_str_append(struct dyn_str *dynstr, const char *s, size_t len)
{
	size_t requiredlen, newlen;

	if (!dynstr->buf) {
		dynstr->buf = malloc(len + 1); /* use malloc, not strdup, in case the buffer contains data after what we want to copy */
		if (ALLOC_FAILURE(dynstr->buf)) {
			return -1;
		}
		memcpy(dynstr->buf, s, len);
		dynstr->buf[len] = '\0';
		dynstr->len = len;
		dynstr->used = len;
		return (int) len;
	}

	/* Do we have enough room in the existing buffer? */
	requiredlen = dynstr->used + len;
	/* Double memory allocation as needed, rather than linear increase, to make reallocations amortized constant time */
	/* In the strange case that newlen is 0, multiplying by 2 is still 0, so add 1 so doubling works.
	 * This could happen if the first call to dyn_str_append has a length of 0. */
	newlen = dynstr->len ? dynstr->len : 1;
	while (newlen < requiredlen) {
		newlen *= 2;
	}

	if (newlen >= dynstr->len) {
		char *newbuf = realloc(dynstr->buf, newlen + 1); /* Add NULL terminator */
		if (ALLOC_FAILURE(newbuf)) {
			return -1;
		}
		dynstr->buf = newbuf;
		dynstr->len = requiredlen;
		dynstr->buf[requiredlen] = '\0';
	}
	memcpy(dynstr->buf + dynstr->used, s, len);
	dynstr->used = requiredlen;
	return (int) requiredlen;
}

int __attribute__ ((format (gnu_printf, 2, 3))) dyn_str_append_fmt(struct dyn_str *dynstr, const char *fmt, ...)
{
	char *buf;
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	len = dyn_str_append(dynstr, buf, (size_t) len);
	free(buf);
	return len;
}

int bbs_parse_url(struct bbs_url *url, char *restrict s)
{
	char *tmp;

	/* Example URLs:
	 * imap://user:password@imap.example.com:993/mailbox
	 * ftp://user@localhost/
	 * ftp://localhost
	 */

	url->prot = s;
	tmp = strstr(s, "://");
	if (!tmp) {
		return -1;
	}

	*tmp = '\0';
	tmp += STRLEN("://");
	s = tmp;

	/* There may be 1 or 2 @ symbols.
	 * If there is only 1, it's a little ambiguous, but we'll assume it's the hostname.
	 */
	tmp = strrchr(s, '@'); /* Username could contain @ symbol, so be tolerant of that */
	if (!tmp) {
		url->host = s;
	} else {
		*tmp++ = '\0';
		url->host = tmp;
		url->user = s;
		tmp = strchr(s, ':');
		if (tmp) {
			*tmp++ = '\0';
			url->pass = tmp;
		}
	}
	tmp = strchr(url->host, '/');
	if (tmp) {
		*tmp++ = '\0';
		url->resource = tmp;
	}
	tmp = strchr(url->host, ':');
	if (tmp) {
		*tmp++ = '\0';
		url->port = atoi(S_IF(tmp));
	}
	return 0;
}

#define char_to_int(x) (x >= 'a' ? x - 'a' - 'A' : x >= 'A' ? x - 'A' + 10 : x - '0')

void bbs_url_decode(char *restrict s)
{
	char *o;

	for (o = s; *s; s++, o++) {
		if (*s == '+') {
			/* A lot of URL decoders don't do this. Convert + to space. */
			*o = ' ';
		} else if (*s == '%' && isxdigit(s[1]) && isxdigit(s[2])) {
			/* It's simply %xx where xx is the hex code for the ASCII char.
			 * Doing it this way is probably faster than sprintf/sscanf */
			char h;
			int a, b;
			a = char_to_int(s[1]);
			b = char_to_int(s[2]);
			h = (char) (b + 16 * a);
			*o = h;
			s += 2; /* Needs to skip 3 characters, but the for loop will do the last one */
		} else {
			*o = *s;
		}
	}
	*o = '\0';
}

#undef char_to_int

unsigned char *bbs_sasl_decode(const char *s, char **authorization, char **authentication, char **passwd)
{
	int outlen;
	unsigned char *decoded;
	int runlen = 0;
	char *authorization_id, *authentication_id, *password;

	decoded = base64_decode((const unsigned char*) s, (int) strlen(s), &outlen);
	/* If you were to dump decoded here using a printf-style function, you would just see the username, since the string is separated by NULs. We need the outlen. */
	if (!decoded) {
		return NULL;
	}
	authorization_id = (char*) decoded;
	runlen += (int) strlen(authorization_id) + 1;
	if (runlen >= outlen) {
		bbs_warning("No data after nickname?\n");
		free(decoded);
		return NULL;
	}
	authentication_id = (char*) decoded + runlen;
	runlen += (int) strlen(authentication_id) + 1;
	if (runlen >= outlen) {
		bbs_warning("No data after username?\n");
		free(decoded);
		return NULL;
	}
	password = (char*) decoded + runlen;
	if (strlen_zero(password)) {
		bbs_warning("No password provided\n");
		free(decoded);
		return NULL;
	}

	*authorization = authorization_id;
	*authentication = authentication_id;
	*passwd = password;
	return decoded;
}

char *bbs_sasl_encode(const char *nickname, const char *username, const char *password)
{
	char *encoded;
	int len;
	int outlen;
	char decoded[256];
	len = snprintf(decoded, sizeof(decoded), "%s%c%s%c%s", nickname, '\0', username, '\0', password);
	if (len >= (int) sizeof(decoded)) {
		bbs_error("Truncation occured (arguments too long!)\n");
		return NULL;
	}
	encoded = base64_encode(decoded, len, &outlen);
	if (!encoded) {
		bbs_error("base64 encoding failed\n");
		return NULL;
	}
	return encoded;
}

int bbs_parse_email_address(char *addr, char **name, char **user, char **host)
{
	char address_buf[256]; /* Our mailbox names are definitely not super long, so using a small buffer is okay. */
	char *start, *domain;

	if (!name && !user && !host) { /* If we don't want to keep the parsed result, make a stack copy and leave the original intact. */
		safe_strncpy(address_buf, addr, sizeof(address_buf));
		addr = address_buf;
	}

	start = strchr(addr, '<');
	if (start++ && !strlen_zero(start)) {
		char *end;
		end = strchr(start, '>');
		if (!end) {
			return -1; /* Email address must be enclosed in <> */
		}
		*end = '\0'; /* Now start refers to just the portion in the <> */
	} else {
		start = addr; /* Not enclosed in <> */
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	domain = (char*) bbs_strcnext(start, '@'); /* else, no domain, it's just a username */
#pragma GCC diagnostic pop

	if (!user && !host) {
		return 0; /* We only confirmed that this was a valid address. */
	}

	if (name) {
		if (addr != start) {
			*name = addr;
		} else {
			*name = NULL;
		}
	}
	if (user) {
		if (start > addr) {
			*(start - 1) = '\0';
		}
		ltrim(start);
		*user = start;
		if (name) {
			rtrim(*name);
		}
	}
	if (host) {
#pragma GCC diagnostic ignored "-Wstringop-overflow"
		/* avoid warning: writing 1 byte into a region of size 0 */
		/* XXX Requires adding -Wno-stringop-overflow to bbs Makefile with -flto */
		if (domain) {
			*(domain - 1) = '\0';
#pragma GCC diagnostic pop
			*host = domain;
		} else {
			*host = NULL;
		}
	}
	return 0;
}

int bbs_user_identity_mismatch(struct bbs_user *user, const char *from)
{
	char matchstr[32];

	if (!user) {
		return -1;
	}

	ltrim(from);
	/* Skip name, if present. */
	while (*from) {
		if (*from != '<') {
			from++;
		} else {
			from++;
			break;
		}
	}

	snprintf(matchstr, sizeof(matchstr), "%s@%s>", bbs_username(user), bbs_hostname());

	if (strlen_zero(from) || (bbs_user_is_registered(user) && strcasecmp(from, matchstr))) {
		return 1;
	}

	return 0;
}

int bbs_append_stuffed_line_message(FILE *fp, const char *line, size_t len)
{
	size_t res;
	/* Compiler could maybe optimize fprintf to fwrite, but just use it directly */
	if (*line == '.') { /* RFC 5321 4.5.2: If line starts with a ., it's byte stuffed, and really starts at the character after. */
		line++;
		len--;
	}
	res = fwrite(line, sizeof(char), len, fp);
	if (res != len) {
		bbs_error("Failed to append %lu bytes (appended %lu)\n", len, res);
		return -1;
	}
	res = fwrite("\r\n", sizeof(char), STRLEN("\r\n"), fp);
	if (res != STRLEN("\r\n")) {
		bbs_error("Failed to append %d bytes (appended %lu)\n", 2, res);
		return -1;
	}
	return (int) len + 2;
}

const char *bbs_basename(const char *s)
{
	/* basename(2) might modify its argument,
	 * so don't bother using that. */
	const char *a = s;
	/* Don't modify the input argument */
	while (*s) {
		if (*s == '/') {
			s++;
			a = s;
		} else {
			s++;
		}
	}
	return a;
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
				if (ALLOC_FAILURE(full_path)) {
					closedir(dir);
					return -1;
				}
#undef sprintf /* This is safe */
				sprintf(full_path, "%s/%s", isroot ? "" : path, entry->d_name);
			}
#ifdef EXTRA_DEBUG
			bbs_debug(4, "Recursing into %s\n", full_path);
#endif
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

void bbs_free_scandir_entries(struct dirent **entries, int numfiles)
{
	int fno = 0;
	struct dirent *entry;

	while (fno < numfiles && (entry = entries[fno++])) {
		free(entry);
	}
}

int bbs_dir_has_file_prefix(const char *path, const char *prefix)
{
	DIR *dir;
	struct dirent *entry;
	int res;
	size_t prefixlen = strlen(prefix);

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
					closedir(dir);
					return -1;
				}
				sprintf(full_path, "%s/%s", isroot ? "" : path, entry->d_name); /* Safe */
			}
#ifdef EXTRA_DEBUG
			bbs_debug(4, "Recursing into %s\n", full_path);
#endif
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

int bbs_dir_num_files(const char *path)
{
	DIR *dir;
	struct dirent *entry;
	int num = 0;

	/* Order doesn't matter here, we just want the total number of messages, so fine (and faster) to use opendir instead of scandir */
	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		num++;
	}

	closedir(dir);
	return num;
}

int bbs_file_exists(const char *path)
{
	struct stat st;

	/* stat() is supposedly the most efficient way to check existence,
	 * faster than access or other functions. */

	return stat(path, &st) ? 0 : 1;
}

int bbs_ensure_directory_exists(const char *path)
{
	if (eaccess(path, R_OK | X_OK)) {
		int derr = errno;
		if (mkdir(path, 0700)) {
			/* The directory probably already exists, but we can't access it for some reason. */
			bbs_warning("mkdir(%s) failed: %s\n", path, strerror(errno));
			bbs_error("Can't access directory %s: %s\n", path, strerror(derr));
			return -1;
		}
	}
	return 0;
}

int bbs_ensure_directory_exists_recursive(const char *path)
{
	if (eaccess(path, R_OK | X_OK)) {
		int derr = errno;
		/* Recursively create parents as needed */
		if (bbs_str_count(path, '/') > 2) {
			char parent[PATH_MAX];
			safe_strncpy(parent, path, sizeof(parent));
			bbs_ensure_directory_exists_recursive(dirname(parent));
		}
		if (mkdir(path, 0700)) {
			/* The directory probably already exists, but we can't access it for some reason. */
			bbs_warning("mkdir(%s) failed: %s\n", path, strerror(errno));
			bbs_error("Can't access directory %s: %s\n", path, strerror(derr));
			return -1;
		}
	}
	return 0;
}

static int nftw_rm(const char *path, const struct stat *st, int flag, struct FTW *f)
{
	int res;

	UNUSED(st);
	UNUSED(f);

	if (flag == FTW_DP) { /* directory */
		res = rmdir(path);
	} else {
		res = unlink(path);
	}
	if (res) {
		bbs_error("Failed to remove %s: %s\n", path, strerror(errno));
	}
	return res;
}

int bbs_delete_directory(const char *path)
{
	/* can't use rmdir, since that's only good for empty directories.
	 * A maildir will NEVER be empty, so use nftw instead. */
	if (nftw(path, nftw_rm, 2, FTW_MOUNT | FTW_PHYS | FTW_DEPTH)) {
		bbs_error("nftw(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_delete_file(const char *path)
{
	/* Could use either remove(2) or unlink(2),
	 * but since we know it's a file, unlink is more appropriate. */
	if (unlink(path)) {
		bbs_error("unlink(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

FILE *bbs_mkftemp(char *template, mode_t mode)
{
	FILE *p;
	int pfd;

	pfd = mkstemp(template); /* template will get updated to contain the actual filename */
	if (chmod(template, mode)) {
		bbs_warning("Failed to set permissions for %s: %s\n", template, strerror(errno));
	}

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
	int fellback = 0;

	if (bytes <= 0) { /* Something's not right. */
		bbs_warning("Wanted to copy %d bytes from file descriptor %d?\n", bytes, srcfd);
		return -1;
	}

	bbs_assert(srcfd != destfd);

	offset = start;
	/* This is not a POSIX function, it exists only in Linux.
	 * Like sendfile, it's more efficient than moving data between kernel and userspace,
	 * since the kernel can do the copy directly.
	 * Closest we can get to a system call that will copy a file for us. */
	copied = (int) copy_file_range(srcfd, &offset, destfd, NULL, (size_t) bytes, 0);
	/* If copy_file_range fails, the syscall probably isn't available on this system. */
#if 0
	if (copied == -1 && errno == ENOSYS) {
		/* copy_file_range glibc function doesn't exist on this system. */
		bbs_debug(5, "copy_file_range glibc wrapper doesn't exist?\n");
		copied = (int) syscall(__NR_copy_file_range, srcfd, &offset, destfd, NULL, (size_t) bytes, 0);
	}
#endif
	if (copied == -1 && errno == ENOSYS) {
		/* Okay, the actual syscall doesn't even exist. Fall back to sendfile. */
		fellback = 1;
		copied = (int) bbs_sendfile(destfd, srcfd, &offset, (size_t) bytes);
	}
	if (copied == -1) {
		bbs_error("%s %d -> %d failed: %s\n", fellback ? "sendfile" : "copy_file_range", srcfd, destfd, strerror(errno));
		return -1;
	} else if (copied != bytes) {
		bbs_error("Wanted to copy %d bytes but only copied %d?\n", bytes, copied);
		return -1;
	}
	return copied;
}

ssize_t bbs_splice(int fd_in, int fd_out, size_t len)
{
	/* Use splice(2) if available, otherwise fall back to sendfile(2) */
#ifdef __linux__
	off64_t off_in = 0;
	/* off_in must be NULL if fd_in is a pipe */
	ssize_t res, written = 0;
	while (len > 0) {
		res = splice(fd_in, &off_in, fd_out, NULL, len, 0);
		if (res < 0) {
			bbs_error("splice failed: %s\n", strerror(errno));
			return -1;
		}
		len -= (size_t) res;
		off_in += (off64_t) res;
	}
	return written;
#else
	off_t offset = 0;
	return bbs_sendfile(fd_out, fd_in, &offset, len);
#endif
}

ssize_t bbs_send_file(const char *filepath, int wfd)
{
	int fd;
	ssize_t sent;
	off_t size, offset;

	fd = open(filepath, O_RDONLY, 0600);
	if (fd < 0) {
		bbs_error("open(%s) failed: %s\n", filepath, strerror(errno));
		return -1;
	}
	size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	offset = 0;
	sent = bbs_sendfile(wfd, fd, &offset, (size_t) size);
	close(fd);
	if (sent != size) {
		bbs_error("Wanted to write %lu bytes but only wrote %ld?\n", size, sent);
		return -1;
	}
	bbs_debug(6, "Sent %ld bytes to fd %d\n", sent, wfd);
	return sent;
}

char *bbs_file_to_string(const char *filename, size_t maxsize, int *restrict length)
{
	char *s = NULL;
	FILE *fp;
	size_t size;
	size_t res;

	fp = fopen(filename, "rb");
	if (!fp) {
		bbs_error("fopen(%s) failed: %s\n", filename, strerror(errno));
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	size = (size_t) ftell(fp);
	rewind(fp); /* Be kind, rewind. */

	if (maxsize && size > maxsize) {
		bbs_warning("File %s is %lu bytes (only wanted max %lu)\n", filename, size, maxsize);
		goto cleanup;
	}

	s = malloc(size + 1); /* Add 1 for NUL */
	if (ALLOC_FAILURE(s)) {
		goto cleanup;
	}
	if (length) {
		*length = (int) size;
	}
	res = fread(s, 1, size, fp);
	if (res != size) {
		bbs_error("Wanted to read %lu bytes but only read %lu\n", size, res);
		free(s);
		return NULL;
	}
	s[res] = '\0'; /* Safe */

cleanup:
	fclose(fp);
	return s;
}

/* XXX Have to pass -Wno-aggregate-return to the linker for this function, with -flto */
#pragma GCC diagnostic ignored "-Waggregate-return"
struct timeval bbs_tvnow(void)
{
	struct timeval t;
	gettimeofday(&t, NULL);
	return t;
}
#pragma GCC diagnostic pop

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
	return (int) strftime(buf, len, "%m/%d %I:%M%P", &logdate);
}

int bbs_time_friendly_now(char *buf, size_t len)
{
	time_t lognow;
	struct tm logdate;

	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	/* Sat Dec 31 2000 09:45 am EST =  29 chars */
	return (int) strftime(buf, len, "%a %b %e %Y %I:%M %P %Z", &logdate);
}

int bbs_time_friendly(time_t epoch, char *buf, size_t len)
{
	struct tm logdate;

	localtime_r(&epoch, &logdate);
	/* Sat Dec 31 2000 09:45 am EST =  29 chars */
	return (int) strftime(buf, len, "%a %b %e %Y %I:%M %P %Z", &logdate);
}

void print_time_elapsed(time_t start, time_t end, char *buf, size_t len)
{
	time_t diff;
	time_t hr, min, sec;

	if (!end) {
		end = time(NULL);
	}

	diff = end - start;
	hr = diff / 3600;
	diff -= (hr * 3600);
	min = diff / 60;
	diff -= (min * 60);
	sec = diff;
	snprintf(buf, len, "%" TIME_T_FMT ":%02" TIME_T_FMT ":%02" TIME_T_FMT, hr, min, sec);
}

void print_days_elapsed(time_t start, time_t end, char *buf, size_t len)
{
	time_t diff;
	time_t days, hr, min, sec;

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
	snprintf(buf, len, "%" TIME_T_FMT " day%s, %" TIME_T_FMT " hr%s, %" TIME_T_FMT " min%s, %" TIME_T_FMT " sec%s", days, ESS(days), hr, ESS(hr), min, ESS(min), sec, ESS(sec));
}

int bbs_parse_rfc822_date(const char *s, struct tm *tm)
{
	char *t;

	/* Multiple possible date formats:
	 * 15 Oct 2002 23:57:35 +0300
	 * Tues, 15 Oct 2002 23:57:35 +0300
	 *  Mon, 3 Jul 2023 22:01:33 GMT */
	if ((t = strptime(s, "%a, %d %b %Y %H:%M:%S %z", tm)) || (t = strptime(s, "%d %b %Y %H:%M:%S %z", tm))) {
		return 0;
	}

	/* I've encountered some emails where the date is something like this:
	 * Mon, 3 Jul 2023 22:01:33 GMT
	 * Note that instead of an offset, you just have a TZ abbreviation.
	 * Valid according to RFC 822 5.1, but not according to RFC 2822 3.3, and not very common. */
	if ((t = strptime(s, "%a, %d %b %Y %H:%M:%S %Z", tm))) {
		bbs_debug(1, "Non-RFC2822 compliant date: %s (%s)\n", s, t);
		return 0;
	}

	bbs_warning("Failed to parse as date: %s\n", s);
	return -1;
}
