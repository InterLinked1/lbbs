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

#include "include/readline.h"

#ifdef BBS_IN_CORE
#include "include/node.h"
#endif

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

static char *readline_pre_read(struct readline_data *restrict rldata, const char *delim, int *resptr)
{
	char *firstdelim = NULL;

	if (rldata->leftover) { /* Data from previous read still in the buffer */
		int res;
		/* Shift contents of buffer back to beginning, which simplifies some things over potentially circling around until we wrap. */
		memmove(rldata->buf, rldata->pos, (size_t) rldata->leftover);
		res = rldata->leftover; /* Pretend like we just read this many bytes, just now. */
		rldata->buf[res] = '\0';
		/* Update our position to where we need to be. */
		rldata->pos = rldata->buf + res;
		rldata->left = rldata->len - res;
		/* If we already have a delimiter, no need to proceed further. */
		firstdelim = strstr(rldata->buf, delim); /* Use buf, not pos, since pos is the beginning of the buffer that remains at this point. */
		res = rldata->leftover = 0;
		rldata->leftover = 0;
		*resptr = res;
	} else {
		if (!rldata->waiting) {
			/* bbs_readline never returns without reading a full line,
			 * but bbs_readline_append can return without calling readline_post_read,
			 * so we should not reset pos to buf if the next chunk is incomplete. */
			rldata->pos = rldata->buf;
			rldata->left = rldata->len;
		}
	}
	rldata->waiting = 0;
	return firstdelim;
}

static int readline_post_read(struct readline_data *restrict rldata, const char *delim, char *restrict firstdelim, int res)
{
	int used, delimlen;

	delimlen = (int) strlen(delim);

	/* We have at least 1 complete command, and maybe more. */
	*firstdelim = '\0'; /* Null terminate here so the caller can just read from the buffer and get a full line (up to and not including the delimiter). */
	used = (int) (firstdelim - rldata->buf); /* Number of bytes, NOT including the trimmed delimiter. */
	firstdelim += delimlen; /* There is the beginning of the rest of the buffer. No, we do not need to add 1 here. */
	rldata->leftover = (int) (rldata->pos - firstdelim); /* Number of bytes leftover. */
#ifdef EXTRA_DEBUG
	bbs_debug(8, "Read %lu bytes (%d just now), processing %d and leaving %d leftover\n", rldata->pos - rldata->buf, res, used, rldata->leftover);
#else
	UNUSED(res);
#endif
	rldata->pos = firstdelim; /* Update pos to point to the beginning, not the end, of the remaining data in the buffer. leftover tells us how much is left, we don't need a pointer to it directly. */

	return used; /* Return number of bytes that we're actually returning, not however many are really in the buffer, since the caller won't care about that anyways. */
}

#ifdef BBS_IN_CORE
/*! \brief Helper function to read a single line from a file descriptor, with a timeout (for any single read) */
int bbs_readline(int fd, struct readline_data *restrict rldata, const char *restrict delim, int timeout)
{
	int res;
	char *firstdelim;

	firstdelim = readline_pre_read(rldata, delim, &res);

	while (!firstdelim) {
#ifdef EXTRA_CHECKS
		bbs_assert(rldata->pos + rldata->left - 1 <= rldata->buf + rldata->len); /* If we're going to corrupt the stack and crash anyways, might as well assert. */
#endif
		if (rldata->left - 1 < 2) {
			bbs_warning("Buffer (size %d) has been exhausted\n", rldata->len); /* The using application needs to allocate a larger buffer */
			return -1;
		}
		res = bbs_poll_read(fd, timeout, rldata->pos, (size_t) rldata->left - 1); /* Subtract 1 for NUL */
		if (res <= 0) {
			bbs_debug(3, "read returned %d (%s)\n", res, res < 0 ? strerror(errno) : "");
			return res - 1; /* see the doxygen notes: we should return 0 only if we read just the delimiter. */
		}
		rldata->pos[res] = '\0'; /* Safe. Null terminate so we can use string functions. */
		firstdelim = strstr(rldata->pos, delim); /* Find the first occurence of the delimiter, if present. */
		/* Update our position */
		rldata->pos += res;
		rldata->left -= res;
	}

	return readline_post_read(rldata, delim, firstdelim, res);
}

int bbs_readline_getn(int fd, int destfd, struct readline_data *restrict rldata, int timeout, int n)
{
	int res, wres;
	unsigned int left_in_buffer;
	int written = 0, remaining = n;

	/* First, use anything that's already in the buffer from a previous read.
	 * The actual delimiter we provide to readline_pre_read doesn't matter here, it can be anything,
	 * since we don't use the result.
	 * We only check rldata->pos afterwards to determine how much data is already in the buffer. */
	readline_pre_read(rldata, "\n", &res);
	left_in_buffer = (unsigned int) (rldata->pos - rldata->buf);
#ifdef EXTRA_DEBUG
	bbs_debug(8, "Up to %d/%d bytes can be satisfied from existing buffer\n", left_in_buffer, n);
#endif
	if (left_in_buffer) {
		unsigned int bytes = (unsigned int) MIN(left_in_buffer, (unsigned int) n); /* Minimum of # bytes available or # bytes we want to read */
		wres = bbs_write(destfd, rldata->buf, bytes);
		if (wres < 0) {
			return wres;
		}
		written += wres;
		remaining -= wres;
		/* Update (shift) the rldata buffer for the next time it gets used. */
		memmove(rldata->buf, rldata->buf + bytes, left_in_buffer - bytes);
		left_in_buffer -= bytes;
		rldata->buf[left_in_buffer] = '\0';
		/* Update our position to where we need to be. */
		rldata->pos = rldata->buf + left_in_buffer;
		rldata->left = rldata->len - (int) left_in_buffer;
	}
	/* For the remainder of this function, we don't use the rldata buffer.
	 * Since we know the exact number of bytes we want, we can use a temporary buffer
	 * and write them directly to the destination, no persistent bookkeeping is required. */
	while (remaining) {
		char readbuf[BUFSIZ];
		int readsize = MIN((int) sizeof(readbuf), remaining); /* Don't read more than we want, or can */
		res = bbs_poll_read(fd, timeout, readbuf, (size_t) readsize);
		if (res <= 0) {
			return written;
		}
		wres = bbs_write(destfd, readbuf, (unsigned int) res);
		if (wres <= 0) {
			return written;
		}
		written += wres;
		remaining -= wres;
	}
	return written;
}
#endif /* BBS_IN_CORE */

int bbs_readline_append(struct readline_data *restrict rldata, const char *restrict delim, char *restrict buf, size_t len, int *restrict ready)
{
	char *firstdelim;
	int res, drain = 0;

	firstdelim = readline_pre_read(rldata, delim, &res);
	if (firstdelim) {
		*ready = 1;
		drain = 1;
		/* Force the caller to use the previous chunk before appending */
	} else {
		*ready = 0; /* Reset */
	}

	/* If there's data to append, do that as well */
	if (len) {
		if ((int) len >= rldata->left - 1) {
			bbs_warning("Insufficient space in buffer to fully write %lu bytes (have %d)\n", len, rldata->left - 1);
			return -1; /* Don't write past the end of the buffer. Don't even bother storing a partial append. */
		}

		/* buf is not (necessarily) null terminated, so can't just blindly use safe_strncpy */
		res = MIN((int) len, rldata->left - 1);
		memcpy(rldata->pos, buf, (size_t) res);

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

		readline_post_read(rldata, delim, firstdelim, res);
		nextbegin = rldata->pos;
		rldata->leftover = (int) (origpos - nextbegin); /* Amount leftover is whatever we'll need to shift after the caller uses the available chunk */

		/* Still return the original value */
	} else {
		/* Don't shift anything in the buffer just yet. We will once we get a complete chunk. */
		rldata->waiting = 1;
	}

	return res;
}
