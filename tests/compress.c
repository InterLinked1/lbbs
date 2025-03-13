/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Compression Functions for Test Suite
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "compress.h"

#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <string.h>

#include <zlib.h>

#define DEFAULT_COMPRESSION_LEVEL 6

struct z_data {
	z_stream compressor_s;
	z_stream decompressor_s;
	z_streamp compressor;
	z_streamp decompressor;
	int fd; /* For convenience, also store the file descriptor here so we can pass everything in this struct */
};

struct z_data *z_client_new(int fd)
{
	int res;
	struct z_data *z;

	z = calloc(1, sizeof(*z));
	if (!z) {
		return NULL;
	}
	z->compressor = &z->compressor_s;
	z->decompressor = &z->decompressor_s;
	z->compressor->zalloc = Z_NULL;
	z->compressor->zfree = Z_NULL;
	z->compressor->opaque = Z_NULL;
	res = deflateInit2(z->compressor, DEFAULT_COMPRESSION_LEVEL, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
	if (res != Z_OK) {
		free(z);
		return NULL;
	}
	z->compressor->avail_in = 0;
	z->compressor->avail_out = 0;

	z->decompressor->zalloc = Z_NULL;
	z->decompressor->zfree = Z_NULL;
	z->decompressor->opaque = Z_NULL;
	res = inflateInit2(z->decompressor, -15);
	if (res != Z_OK) {
		free(z);
		return NULL;
	}
	z->fd = fd;
	return z;
}

void z_client_free(struct z_data *z)
{
	deflateEnd(z->compressor);
	inflateEnd(z->decompressor);
	free(z);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
ssize_t zlib_write(struct z_data *z, int line, const char *buf, size_t len)
{
	char output[BUFSIZ];

	z->compressor->next_in = (Bytef*) buf;
	z->compressor->avail_in = (uInt) len;

	do {
		size_t comp_len;
		int res;
		ssize_t wres;

		z->compressor->avail_out = sizeof(output);
		z->compressor->next_out = (Bytef*) output;

		res = deflate(z->compressor, Z_PARTIAL_FLUSH);
		if (res < 0) {
			bbs_error("deflate failed: %s\n", zError(res));
			return -1;
		}
		comp_len = sizeof(output) - z->compressor->avail_out;
		bbs_debug(10, "Deflated to %lu bytes at line %d\n", comp_len, line);
		wres = write(z->fd, output, comp_len);
		if (wres <= 0) {
			bbs_error("write returned %ld at line %d\n", wres, line);
			return -1;
		}
		/* We filled up the buffer, so need to keep looping to flush out */
	} while (z->compressor->avail_out == 0);
	return (ssize_t) len;
}
#pragma GCC diagnostic pop

ssize_t zlib_read(struct z_data *z, int line, char *buf, size_t len)
{
	char input[BUFSIZ / 10]; /* Hopefully the compression doesn't reduce the size by more than 90%... */
	char output[BUFSIZ];
	int zres;
	ssize_t rres;
	size_t bytes = 0;

	rres = read(z->fd, input, sizeof(input));
	if (rres <= 0) {
		bbs_error("read returned %ld at line %d\n", rres, line);
		return -1;
	}

	z->decompressor->next_in = (Bytef*) input;
	z->decompressor->avail_in = (uInt) rres;

	do {
		size_t decomp_len;

		z->decompressor->avail_out = sizeof(output);
		z->decompressor->next_out = (Bytef*) output;

		zres = inflate(z->decompressor, Z_NO_FLUSH);
		if (zres < 0) {
			bbs_error("inflate failed: %s\n", zError(zres));
			return -1;
		}
		decomp_len = sizeof(output) - z->decompressor->avail_out;
		bbs_debug(9, "Inflated to %lu bytes at line %d\n", decomp_len, line);
		if (decomp_len == 0) {
			bbs_debug(7, "Couldn't decompress anything with received input\n");
			continue;
		}
		if (decomp_len >= len) {
			bbs_error("Buffer overflow occured!\n");
			return -1;
		}
		memcpy(buf, output, decomp_len);
		buf += decomp_len;
		bytes += decomp_len;
		len -= decomp_len;
	} while (z->decompressor->avail_out == 0);
	buf[0] = '\0';
	return (ssize_t) bytes;
}

int test_z_client_expect(struct z_data *z, int ms, const char *restrict s, int line)
{
	char buf[4096];
	return test_z_client_expect_buf(z, ms, s, line, buf, sizeof(buf));
}

int test_z_client_expect_buf(struct z_data *z, int ms, const char *s, int line, char *buf, size_t len)
{
	int res;
	struct pollfd pfd;

	pfd.fd = z->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	assert(pfd.fd != -1);

	res = poll(&pfd, 1, ms);
	if (res < 0) {
		return -1;
	}
	if (res > 0 && pfd.revents) {
		ssize_t bytes;
		bytes = zlib_read(z, line, buf, len - 1);
		if (bytes <= 0) {
			return -1;
		}
		buf[bytes] = '\0'; /* Safe */
		if (!strstr(buf, s)) {
			bbs_warning("Failed to receive expected output at line %d: %s (got %s)\n", line, s, buf);
			return -1;
		}
		bbs_debug(10, "Contains output expected at line %d: %s", line, buf); /* Probably already ends in LF */
		return 0;
	}
	bbs_warning("Failed to receive expected output at line %d: %s\n", line, s);
	return -1;
}

int test_z_client_expect_eventually(struct z_data *z, int ms, const char *restrict s, int line)
{
	char buf[4096];
	return test_z_client_expect_eventually_buf(z, ms, s, line, buf, sizeof(buf));
}

int test_z_client_expect_eventually_buf(struct z_data *z, int ms, const char *restrict s, int line, char *restrict buf, size_t len)
{
	struct pollfd pfd;

	pfd.fd = z->fd;
	pfd.events = POLLIN;
	assert(pfd.fd != -1);

	for (;;) {
		int res;
		pfd.revents = 0;
		res = poll(&pfd, 1, ms);
		if (res < 0) {
			return -1;
		} else if (!res) {
			break;
		}
		if (res > 0 && pfd.revents) {
			ssize_t bytes;
			bytes = zlib_read(z, line, buf, len - 1);
			if (bytes <= 0) {
				return -1;
			}
			buf[bytes] = '\0'; /* Safe */
			/* Probably ends in LF, so skip one here */
			bbs_debug(10, "Analyzing output(%d): %s", line, buf); /* Particularly under valgrind, we'll end up reading individual lines more than chunks, so using CLIENT_DRAIN is especially important */
			/* XXX Should use bbs_readline_append for reliability */
			if (strstr(buf, s)) {
				return 0;
			}
		}
	}
	bbs_warning("Failed to receive expected output at line %d: %s\n", line, s);
	return -1;
}
