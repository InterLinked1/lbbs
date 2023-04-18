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

static char *readline_pre_read(struct readline_data *rldata, const char *delim, int *resptr)
{
	char *firstdelim = NULL;

	if (rldata->leftover) { /* Data from previous read still in the buffer */
		int res;
		/* Shift contents of buffer back to beginning, which simplifies some things over potentially circling around until we wrap. */
		memmove(rldata->buf, rldata->pos, rldata->leftover);
		res = rldata->leftover; /* Pretend like we just read this many bytes, just now. */
		rldata->buf[res] = '\0';
		/* Update our position to where we need to be. */
		rldata->pos = rldata->buf + res;
		rldata->left = rldata->len - res;
		/* If we already have a delimiter, no need to proceed further. */
		firstdelim = strstr(rldata->buf, delim); /* Use buf, not pos, since pos is the beginning of the buffer that remains at this point. */
		res = rldata->leftover = 0;
		*resptr = res;
	} else {
		rldata->pos = rldata->buf;
		rldata->left = rldata->len;
	}
	return firstdelim;
}

static int readline_post_read(struct readline_data *rldata, const char *delim, char *firstdelim, int res)
{
	int used, delimlen;

	delimlen = strlen(delim);

	/* We have at least 1 complete command, and maybe more. */
	*firstdelim = '\0'; /* Null terminate here so the caller can just read from the buffer and get a full line (up to and not including the delimiter). */
	used = firstdelim - rldata->buf; /* Number of bytes, NOT including the trimmed delimiter. */
	firstdelim += delimlen; /* There is the beginning of the rest of the buffer. No, we do not need to add 1 here. */
	rldata->leftover = rldata->pos - firstdelim; /* Number of bytes leftover. */
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
int bbs_fd_readline(int fd, struct readline_data *rldata, const char *delim, int timeout)
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
		}
		res = bbs_fd_poll_read(fd, timeout, rldata->pos, rldata->left - 1); /* Subtract 1 for NUL */
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
#endif

int bbs_fd_readline_append(struct readline_data *rldata, const char *delim, char *buf, size_t len, int *ready)
{
	char *firstdelim;
	int res;

	firstdelim = readline_pre_read(rldata, delim, &res);

	if (firstdelim) {
		*ready = 1;
		return 0; /* Force the caller to use the previous chunk before appending */
	}
	if ((int) len >= rldata->left - 1) {
		bbs_warning("Insufficient space in buffer to fully write %lu bytes (have %d)\n", len, rldata->left - 1);
	}

	/* buf is not (necessarily) null terminated, so can't just blindly use safe_strncpy */
	res = MIN((int) len, rldata->left - 1);
	memcpy(rldata->pos, buf, res);

	rldata->pos[res] = '\0'; /* Safe. Null terminate so we can use string functions. */
	firstdelim = strstr(rldata->pos, delim); /* Find the first occurence of the delimiter, if present. */
	/* Update our position */
	rldata->pos += res;
	rldata->left -= res;
	*ready = firstdelim ? 1 : 0;

	if (*ready) {
		readline_post_read(rldata, delim, firstdelim, res);
		/* Still return the original value */
	}

	return res;
}
