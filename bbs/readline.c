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
 * \brief Delimited read helper
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#ifdef BBS_IN_CORE
#include <stdio.h> /* use BUFSIZ */
#endif

#ifdef BBS_IN_CORE
#include "include/node.h"
#include "include/utils.h" /* This includes readline.h */
#else
#include "include/readline.h"
#endif

static inline void readline_buffer_reset(struct readline_data *restrict rldata)
{
	rldata->pos = rldata->buf;
	rldata->left = rldata->len;
}

void bbs_readline_init(struct readline_data *rldata, char *buf, size_t len)
{
	memset(rldata, 0, sizeof(*rldata));
	rldata->buf = buf;
	rldata->len = len;
	/* Initialize internals: start at the beginning */
	readline_buffer_reset(rldata);
	rldata->leftover = 0;
}

void bbs_readline_flush(struct readline_data *rldata)
{
	readline_buffer_reset(rldata);
	rldata->leftover = 0;
}

static char *readline_pre_read(struct readline_data *restrict rldata, const char *delim, ssize_t *resptr)
{
	char *firstdelim = NULL;

	if (rldata->leftover) { /* Data from previous read still in the buffer */
		size_t res;
		/* Shift contents of buffer back to beginning, which simplifies some things over potentially circling around until we wrap. */
#ifdef EXTRA_DEBUG
		bbs_debug(8, "Shifting by %ld bytes at pos %ld\n", rldata->leftover, rldata->pos - rldata->buf);
#endif
		memmove(rldata->buf, rldata->pos, (size_t) rldata->leftover);
		res = rldata->leftover; /* Pretend like we just read this many bytes, just now. */
		rldata->buf[res] = '\0';
		/* Update our position to where we need to be. */
		rldata->pos = rldata->buf + res;
		rldata->left = rldata->len - res;
		/* If we already have a delimiter, no need to proceed further. */
		/* Use memmem instead of strstr to accomodate binary data */
		firstdelim = memmem(rldata->buf, res, delim, strlen(delim)); /* Use buf, not pos, since pos is the beginning of the buffer that remains at this point. */
		res = rldata->leftover = 0;
		rldata->leftover = 0;
		*resptr = (ssize_t) res;
	} else {
		if (!rldata->waiting) {
			/* bbs_readline never returns without reading a full line,
			 * but bbs_readline_append can return without calling readline_post_read,
			 * so we should not reset pos to buf if the next chunk is incomplete. */
#ifdef EXTRA_DEBUG
			bbs_debug(8," Resetting buffer\n");
#endif
			readline_buffer_reset(rldata);
		}
	}
	rldata->waiting = 0;
	return firstdelim;
}

int readline_bytes_available(struct readline_data *restrict rldata, int process)
{
	if (process) {
		/* Shift leftover to beginning */
		int ready; /* We're discarding this, so delimiter doesn't matter */
		bbs_readline_append(rldata, "\n", NULL, 0, &ready);
	}
	return (int) (rldata->pos - rldata->buf);
}

static int readline_post_read(struct readline_data *restrict rldata, const char *delim, char *restrict firstdelim, ssize_t res)
{
	int used, delimlen;

	delimlen = (int) strlen(delim);

	/* We have at least 1 complete command, and maybe more. */
	*firstdelim = '\0'; /* Null terminate here so the caller can just read from the buffer and get a full line (up to and not including the delimiter). */
	used = (int) (firstdelim - rldata->buf); /* Number of bytes, NOT including the trimmed delimiter. */
	firstdelim += delimlen; /* There is the beginning of the rest of the buffer. No, we do not need to add 1 here. */
	rldata->leftover = (size_t) (rldata->pos - firstdelim); /* Number of bytes leftover. */
#ifdef EXTRA_DEBUG
	bbs_debug(8, "Read %lu bytes (%ld just now), processing %d and leaving %lu leftover\n", rldata->pos - rldata->buf, res, used, rldata->leftover);
#else
	UNUSED(res);
#endif
	rldata->pos = firstdelim; /* Update pos to point to the beginning, not the end, of the remaining data in the buffer. leftover tells us how much is left, we don't need a pointer to it directly. */

	return used; /* Return number of bytes that we're actually returning, not however many are really in the buffer, since the caller won't care about that anyways. */
}

#ifdef BBS_IN_CORE
/*! \brief Helper function to read a single line from a file descriptor, with a timeout (for any single read) */
ssize_t bbs_readline(int fd, struct readline_data *restrict rldata, const char *restrict delim, int timeout)
{
	ssize_t res;
	char *firstdelim;

	firstdelim = readline_pre_read(rldata, delim, &res);

	while (!firstdelim) {
#ifdef EXTRA_CHECKS
		bbs_assert(rldata->pos + rldata->left - 1 <= rldata->buf + rldata->len); /* If we're going to corrupt the stack and crash anyways, might as well assert. */
#endif
		if (rldata->left - 1 < 2) {
			bbs_warning("Buffer (size %lu) has been exhausted\n", rldata->len); /* The using application needs to allocate a larger buffer */
			return -3;
		}
		res = bbs_poll_read(fd, timeout, rldata->pos, (size_t) rldata->left - 1); /* Subtract 1 for NUL */
		if (res <= 0) {
			bbs_debug(3, "bbs_poll_read returned %ld\n", res);
			return res - 1; /* see the doxygen notes: we should return 0 only if we read just the delimiter. */
		}
		rldata->pos[res] = '\0'; /* Safe. Null terminate so we can use string functions. */
		firstdelim = strstr(rldata->pos, delim); /* Find the first occurence of the delimiter, if present. */
		/* Update our position */
		rldata->pos += (size_t) res;
		rldata->left -= (size_t) res;
	}

	return readline_post_read(rldata, delim, firstdelim, res);
}

static ssize_t __bbs_readline_getn(int fd, int destfd, struct dyn_str *restrict dynstr, struct readline_data *restrict rldata, int timeout, size_t n)
{
	ssize_t wres;
	ssize_t res;
	size_t left_in_buffer, written = 0, remaining = n;

	/* First, use anything that's already in the buffer from a previous read.
	 * The actual delimiter we provide to readline_pre_read doesn't matter here, it can be anything,
	 * since we don't use the result.
	 * We only check rldata->pos afterwards to determine how much data is already in the buffer. */
	readline_pre_read(rldata, "\n", &res);
	left_in_buffer = (size_t) (rldata->pos - rldata->buf);
#ifdef EXTRA_DEBUG
	bbs_debug(8, "Up to %lu/%lu bytes can be satisfied from existing buffer\n", left_in_buffer, n);
#endif

	if (left_in_buffer) {
		/* XXX Similar to below, we need to retry this section in a loop until either the buffer is empty or remaining == 0
		 * This is to handle the case that write doesn't succeed in writing all the bytes we told it to do (wres < bytes)*/
		size_t bytes = MIN(left_in_buffer, n); /* Minimum of # bytes available or # bytes we want to read */
		if (destfd != -1) {
			wres = bbs_write(destfd, rldata->buf, bytes);
			if (wres < 0) {
				return wres;
			}
		} else if (dynstr) {
			dyn_str_append(dynstr, rldata->buf, bytes);
			wres = (int) bytes;
		} else {
			/* Somebody is just discarding this data without saving it */
			wres = (int) bytes;
		}
		written += (size_t) wres;
		remaining -= (size_t) wres;
		/* Update (shift) the rldata buffer for the next time it gets used. */
		memmove(rldata->buf, rldata->buf + bytes, left_in_buffer - bytes);
		left_in_buffer -= bytes;
		rldata->buf[left_in_buffer] = '\0';
		/* Update our position to where we need to be. */
		rldata->pos = rldata->buf + left_in_buffer;
		rldata->left = rldata->len - left_in_buffer;
	}

	/* In case there's more data still left than we read. It's currently at the beginning of the buffer already (rldata->buf)
	 * In readline_pre_read we'll end up shifting by 0 bytes in memmove, but the delimiter should get set right. */
	if (left_in_buffer) {
#ifdef EXTRA_DEBUG
		bbs_debug(6, "%lu bytes remain in buffer\n", left_in_buffer);
#endif
		rldata->pos = rldata->buf;
		rldata->leftover = left_in_buffer;
	}

	/* For the remainder of this function, we don't use the rldata buffer.
	 * Since we know the exact number of bytes we want, we can use a temporary buffer
	 * and write them directly to the destination, no persistent bookkeeping is required. */
	while (remaining) {
		char readbuf[BUFSIZ];
		size_t readsize = MIN(sizeof(readbuf), remaining); /* Don't read more than we want, or can */
		res = bbs_poll_read(fd, timeout, readbuf, readsize);
		if (res <= 0) {
			return (int) written;
		}
		if (destfd != -1) {
			/* XXX If copying from fd to fd, could use copy_file_range or sendfile for efficiency? (unless source can't be a socket) */
			wres = bbs_write(destfd, readbuf, (size_t) res);
			if (wres <= 0) {
				return (int) written;
			}
		} else if (dynstr) {
			dyn_str_append(dynstr, readbuf, (size_t) res);
			wres = (int) res;
		} else {
			/* Somebody is just discarding this data without saving it */
			wres = (int) res;
		}
		written += (size_t) wres;
		remaining -= (size_t) wres;
	}
	return (int) written;
}

ssize_t bbs_readline_getn(int fd, int destfd, struct readline_data *restrict rldata, int timeout, size_t n)
{
	return __bbs_readline_getn(fd, destfd, NULL, rldata, timeout, n);
}

ssize_t bbs_readline_getn_dynstr(int fd, struct dyn_str *restrict dynstr, struct readline_data *restrict rldata, int timeout, size_t n)
{
	return __bbs_readline_getn(fd, -1, dynstr, rldata, timeout, n);
}

char *bbs_readline_getn_str(int fd, struct readline_data *restrict rldata, int timeout, size_t n)
{
	struct dyn_str dynstr;

	memset(&dynstr, 0, sizeof(dynstr));
	if (__bbs_readline_getn(fd, -1, &dynstr, rldata, timeout, n) != (int) n) {
		free_if(dynstr.buf);
	}
	return dynstr.buf;
}

ssize_t bbs_readline_discard_n(int fd, struct readline_data *restrict rldata, int timeout, size_t n)
{
	return bbs_readline_getn(fd, -1, rldata, timeout, n); /* Read the bytes and throw them away */
}

void bbs_readline_set_boundary(struct readline_data *restrict rldata, const char *separator)
{
	rldata->boundary = separator;
	rldata->boundarylen = strlen(separator);
}

static int readline_get_until_process(struct dyn_str *dynstr, struct readline_data *restrict rldata, size_t left_in_buffer, size_t maxlen)
{
	size_t i;

	for (i = 0; i < left_in_buffer; i++) {
		if (rldata->buf[i] == rldata->boundary[rldata->boundarypos]) {
			/* Up to the boundarypos'th character of the boundary has been read */
			rldata->boundarypos++;
			if (rldata->boundarypos == rldata->boundarylen) {
				size_t n;
				i++; /* Skip the last char of the boundary itself */
				/* We've read the entire boundary.
				 * We want to REMOVE the boundary from the string.
				 * Since we haven't yet appended to dynstr, we
				 * may need to copy some number of bytes first,
				 * and we may also need to remove the last X bytes from it,
				 * where X <= boundarylen. */
				bbs_debug(4, "Parsed full content until boundary, length is %lu\n", rldata->segmentlen);
				if (i > rldata->boundarylen) {
					/* There was data at the beginning of the buffer that
					 * wasn't part of the boundary that we need to append. */
					n = i - rldata->boundarylen;
					dyn_str_append(dynstr, rldata->buf, n);
					rldata->segmentlen += n;
				} else {
					/* If i <= boundarylen, left_in_buffer[0] was already part of the boundary.
					 * We need to remove some number of characters. */
					size_t curlen;
					n = rldata->boundarylen - i;
					curlen = dyn_str_len(dynstr);
					dynstr->buf[curlen - n] = '\0';
					dynstr->used = curlen - n - 1;
					rldata->segmentlen -= n;
				}
				bbs_assert(rldata->segmentlen == dyn_str_len(dynstr));
				bbs_debug(4, "Parsed full content until boundary, length is %lu\n", rldata->segmentlen);
				/* No need to copy the boundary itself. Discard that, and shift in everything after it, if any */
				memmove(rldata->buf, rldata->buf + i, left_in_buffer - i);
				left_in_buffer -= i;
				/* Update our position to where we need to be. */
				rldata->pos = rldata->buf + i;
				rldata->left = rldata->len - i;
				rldata->buf[left_in_buffer] = '\0';
				rldata->leftover = left_in_buffer;
				rldata->segmentlen = 0; /* Reset */
				rldata->boundarypos = 0;
				return 0;
			}
		} else {
			rldata->boundarypos = 0; /* Any match we had is gone now. */
		}
	}

	/* If we got this far, we didn't read the entire boundary. Copy everything over. */
	bbs_debug(8, "Chunk of length %lu is incomplete\n", left_in_buffer);
	rldata->segmentlen += left_in_buffer;
	if (rldata->segmentlen > maxlen) { /* Too much! */
		bbs_warning("Maximum segment length (%lu) exceeded (would be >= %lu)\n", maxlen, rldata->segmentlen);
	} else {
		dyn_str_append(dynstr, rldata->buf, left_in_buffer);
	}
	readline_buffer_reset(rldata);
	return 1; /* We're incomplete */
}

int bbs_readline_get_until(int fd, struct dyn_str *dynstr, struct readline_data *restrict rldata, int timeout, size_t maxlen)
{
	ssize_t res;
	size_t left_in_buffer;

	bbs_assert_exists(rldata->boundary); /* Boundary must be initialized first */

	/* First, use anything that's already in the buffer from a previous read.
	 * The actual delimiter we provide to readline_pre_read doesn't matter here, it can be anything,
	 * since we don't use the result.
	 * We only check rldata->pos afterwards to determine how much data is already in the buffer. */
	readline_pre_read(rldata, "\n", &res);

	left_in_buffer = (size_t) (rldata->pos - rldata->buf);
	if (left_in_buffer && !readline_get_until_process(dynstr, rldata, left_in_buffer, maxlen)) {
		return 0;
	}

	/* Read as much data as is available, for efficiency */
	for (;;) {
		bbs_assert(rldata->pos == rldata->buf);
		res = bbs_poll_read(fd, timeout, rldata->pos, rldata->left);
		if (res <= 0) {
			return -1;
		}
		rldata->pos += (size_t) res;
		rldata->left -= (size_t) res;
		if (res && !readline_get_until_process(dynstr, rldata, (size_t) res, maxlen)) {
			return 0;
		}
	}
	return 0;
}
#endif /* BBS_IN_CORE */

int bbs_readline_append(struct readline_data *restrict rldata, const char *restrict delim, char *restrict buf, size_t len, int *restrict ready)
{
	char *firstdelim;
	size_t res;
	ssize_t unused;
	int drain = 0;

	firstdelim = readline_pre_read(rldata, delim, &unused);
	if (firstdelim) {
		*ready = 1;
		drain = 1;
		/* Force the caller to use the previous chunk before appending */
	} else {
		*ready = 0; /* Reset */
	}

	/* If there's data to append, do that as well */
	if (len) {
		if (len >= rldata->left - 1) {
			bbs_warning("Insufficient space in buffer to fully write %lu bytes (have %lu)\n", len, rldata->left - 1);
			return -1; /* Don't write past the end of the buffer. Don't even bother storing a partial append. */
		}

		/* buf is not (necessarily) null terminated, so can't just blindly use safe_strncpy */
		res = MIN(len, rldata->left - 1);
		memcpy(rldata->pos, buf, res);

		rldata->pos[res] = '\0'; /* Safe. Null terminate so we can use string functions. */
		if (!drain) { /* If we're draining the buffer, firstdelim is already set and we want to use that */
			firstdelim = strstr(rldata->pos, delim); /* Find the first occurence of the delimiter, if present. */
		}
		/* Update our position */
		rldata->pos += res;
		rldata->left -= res;
		*ready = firstdelim ? 1 : 0;
	} else {
		res = 0;
	}

	if (*ready) {
		char *nextbegin, *origpos = rldata->pos;

		readline_post_read(rldata, delim, firstdelim, (int) res);
		nextbegin = rldata->pos;
		rldata->leftover = (size_t) (origpos - nextbegin); /* Amount leftover is whatever we'll need to shift after the caller uses the available chunk */

		/* Still return the original value */
	} else {
		/* Don't shift anything in the buffer just yet. We will once we get a complete chunk. */
		rldata->waiting = 1;
	}

	return (int) res;
}
