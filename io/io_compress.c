/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief RFC 1951 DEFLATE compression
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>

#include <zlib.h>

#include "include/module.h"
#include "include/node.h"
#include "include/linkedlists.h"
#include "include/alertpipe.h"
#include "include/utils.h"
#include "include/cli.h"

/* See https://www.zlib.net/manual.html#Constants */
#define DEFAULT_COMPRESSION_LEVEL 6

struct compress_data {
	z_stream compressor_s; /* Stack allocated */
	z_stream decompressor_s; /* Stack allocated */
	z_streamp compressor; /* Pointer to the stack allocated variable */
	z_streamp decompressor; /* Pointer to the stack allocated variable */
	int rpfd[2];
	int wpfd[2];
	int level; /* Current compression level */
	int orig_rfd;
	int orig_wfd;
	size_t sentbytes;
	size_t sentbytes_comp;
	size_t recvbytes;
	size_t recvbytes_comp;
	pthread_t thread;
	RWLIST_ENTRY(compress_data) entry;
};

static RWLIST_HEAD_STATIC(compressors, compress_data);

static ssize_t compress_and_send(struct compress_data *z, char *buf, size_t len)
{
	char output[BUFSIZ];

	z->compressor->next_in = (Bytef*) buf;
	z->compressor->avail_in = (uInt) len;

#ifdef DEBUG_COMPRESSION
	bbs_debug(9, "Compressing %lu bytes\n", len);
#endif

	do {
		size_t comp_len;
		int res;
		ssize_t wres;

		z->compressor->avail_out = sizeof(output);
		z->compressor->next_out = (Bytef*) output;

		res = deflate(z->compressor, Z_PARTIAL_FLUSH);
		if (res < 0) {
			bbs_error("deflate failed: %s\n", zError(res));
			bbs_soft_assert(res != Z_STREAM_ERROR);
			return -1;
		}
		comp_len = sizeof(output) - z->compressor->avail_out;
		bbs_debug(10, "Deflated to %lu bytes\n", comp_len);
		wres = bbs_write(z->orig_wfd, output, comp_len);
		if (wres <= 0) {
			return -1;
		}

		z->sentbytes_comp += comp_len;
		/* We filled up the buffer, so need to keep looping to flush out */
	} while (z->compressor->avail_out == 0);
	bbs_assert(z->compressor->avail_in == 0);
	z->sentbytes += len;
	return (ssize_t) len;
}

static ssize_t decompress_and_deliver(struct compress_data *z, char *buf, size_t len)
{
	char output[BUFSIZ];
	int zres;
	size_t bytes = 0;

#ifdef DEBUG_COMPRESSION
	bbs_debug(9, "Deflating %lu bytes\n", len);
#endif

	z->decompressor->next_in = (Bytef*) buf;
	z->decompressor->avail_in = (uInt) len;

	do {
		ssize_t wres;
		size_t decomp_len;

		z->decompressor->avail_out = sizeof(output);
		z->decompressor->next_out = (Bytef*) output;

		zres = inflate(z->decompressor, Z_NO_FLUSH);
		if (zres < 0) {
			bbs_error("inflate failed: %s\n", zError(zres));
			bbs_soft_assert(zres != Z_STREAM_ERROR);
			return -1;
		}
		decomp_len = sizeof(output) - z->decompressor->avail_out;
		bbs_debug(9, "Inflated to %lu bytes\n", decomp_len);
		if (decomp_len == 0) {
			bbs_debug(7, "Couldn't decompress anything with received input\n");
			/* XXX Hopefully don't get stuck by looping again if nothing follows */
			continue;
		}
		wres = bbs_write(z->rpfd[1], output, decomp_len);
		if (wres <= 0) {
			return -1;
		}
		z->recvbytes += decomp_len;
		bytes += decomp_len;
		/* If we couldn't decompress all the data received into the output buffer,
		 * keep processing */
	} while (z->decompressor->avail_out == 0);
	z->recvbytes_comp += len;
	return (ssize_t) bytes;
}

static void *zlib_thread(void *varg)
{
	struct compress_data *z = varg;
	struct pollfd pfds[2];

	pfds[0].fd = z->wpfd[0]; /* Data that we need to compress and send along */
	pfds[1].fd = z->orig_rfd; /* Data that we received that needs to be decompressed */
	pfds[0].events = pfds[1].events = POLLIN | POLLPRI | POLLERR | POLLNVAL;
	pfds[0].revents = pfds[1].revents = 0;

	for (;;) {
		ssize_t rres;
		ssize_t res = poll(pfds, 2, -1);
		if (res < 0) {
			bbs_debug(3, "poll returned %ld: %s\n", res, strerror(errno));
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (pfds[0].revents & POLLIN) {
			char input[BUFSIZ];
			rres = read(z->wpfd[0], input, sizeof(input));
			if (rres <= 0) {
				break;
			}
			/* Compress it */
			res = compress_and_send(z, input, (size_t) rres);
			if (rres <= 0) {
				break;
			}
			pfds[0].revents = 0;
		}
		if (pfds[1].revents & POLLIN) {
			char input[BUFSIZ];
			rres = read(z->orig_rfd, input, sizeof(input));
			if (rres <= 0) {
				break;
			}
			/* Decompress it */
			res = decompress_and_deliver(z, input, (size_t) rres);
			if (rres <= 0) {
				break;
			}
			pfds[1].revents = 0;
		}
		if (pfds[0].revents || pfds[1].revents) {
			bbs_debug(3, "poll returned %s\n", poll_revent_name(pfds[0].revents ? pfds[0].revents : pfds[1].revents));
			break;
		}
	}
	bbs_debug(4, "zlib thread exiting\n");
	PIPE_CLOSE(z->wpfd);
	PIPE_CLOSE(z->rpfd);
	return NULL;
}

/* I/O transformation callback functions */

static int setup(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg)
{
	int res;
	struct compress_data *z;

	/* Regardless of whether we are the server or the client, we
	 * compress data that we write, and decompress data that we receive.
	 * So data written to wfd will be read by this module,
	 * compressed, and written to the original wfd,
	 * and data to the current rfd will be read by this module,
	 * decompressed, and written to the original rfd.
	 *
	 * Compression must always happen FURTHER from the network socket than TLS,
	 * so due to the architecture in play here (fiddling file descriptors around),
	 * that means that compression is not compatible with encryption unless setup AFTERWARDS,
	 * which is the most common flow, but is not guaranteed. */
	UNUSED(dir);
	UNUSED(arg);

	z = calloc(1, sizeof(*z));
	if (ALLOC_FAILURE(z)) {
		return -1;
	}

	z->compressor = &z->compressor_s;
	z->decompressor = &z->decompressor_s;
	z->level = DEFAULT_COMPRESSION_LEVEL;

	/* Some of the parameters (e.g. -15) are adapted in particular for the IMAP COMPRESS=DEFLATE extension,
	 * as specified in RFC 4978 Section 4. */
	z->compressor->zalloc = Z_NULL;
	z->compressor->zfree = Z_NULL;
	z->compressor->opaque = Z_NULL;
	res = deflateInit2(z->compressor, z->level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
	if (res != Z_OK) {
		bbs_error("Failed to initialize deflator\n");
		free(z);
		return -1;
	}
	z->compressor->avail_in = 0;
	z->compressor->avail_out = 0;

	z->decompressor->zalloc = Z_NULL;
	z->decompressor->zfree = Z_NULL;
	z->decompressor->opaque = Z_NULL;
	res = inflateInit2(z->decompressor, -15);
	if (res != Z_OK) {
		bbs_error("Failed to initialize inflator\n");
		deflateEnd(z->compressor);
		free(z);
		return -1;
	}

	if (pipe(z->rpfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		goto fail;
	} else if (pipe(z->wpfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		goto fail;
	}

	/* Spawn a separate thread to handle the new intermediate layer and the compression/decompression */
	if (bbs_pthread_create(&z->thread, NULL, zlib_thread, z)) {
		goto fail;
	}

	/* Fiddle the file descriptors around */
	z->orig_rfd = *rfd;
	z->orig_wfd = *wfd;
	*rfd = z->rpfd[0]; /* Application now reads from the read end of this pipe */
	*wfd = z->wpfd[1]; /* Application now writes to the write end of the other pipe */

	RWLIST_WRLOCK(&compressors);
	RWLIST_INSERT_HEAD(&compressors, z, entry);
	RWLIST_UNLOCK(&compressors);

	*data = z; /* Store as transform callback data */
	return 0;

fail:
	deflateEnd(z->compressor);
	inflateEnd(z->decompressor);
	PIPE_CLOSE(z->rpfd);
	PIPE_CLOSE(z->wpfd);
	free(z);
	return -1;
}

static void cleanup(struct bbs_io_transformation *tran)
{
	struct compress_data *z = tran->data;
	bbs_assert_exists(z);

	RWLIST_WRLOCK(&compressors);
	RWLIST_REMOVE(&compressors, z, entry);
	RWLIST_UNLOCK(&compressors);

	close_if(z->wpfd[1]); /* Close write end since we're done writing, but don't close other file descriptors since we may need to finish flushing pending data */
	bbs_pthread_join(z->thread, NULL); /* Wait for I/O to finish */

	deflateEnd(z->compressor);
	inflateEnd(z->decompressor);
	free(z);
}

static int query(struct bbs_io_transformation *tran, int query, void *data)
{
	struct compress_data *z = tran->data;
	int *result, comp_level;

	switch (query) {
	case TRANSFORM_QUERY_COMPRESSION_FLUSH:
		bbs_debug(3, "Flushing compression dictionary\n");
		return deflate(z->compressor, Z_FULL_FLUSH);
	case TRANSFORM_QUERY_SET_COMPRESSION_LEVEL:
		result = data;
		comp_level = *result;
		/* Valid compression level is 0 through 9 */
		if (comp_level < Z_NO_COMPRESSION || comp_level > Z_BEST_COMPRESSION) {
			bbs_error("Invalid compression level requested: %d\n", comp_level);
			return -1;
		}
		if (z->level == comp_level) {
			bbs_debug(5, "Compression level has not changed (%d)\n", z->level);
			return 0;
		}
		z->level = comp_level;
		bbs_debug(3, "Setting compression level to %d\n", z->level);
		return deflateParams(z->compressor, z->level, Z_DEFLATED);
	default:
		bbs_warning("Unknown query type: %d\n", query);
		return -1;
	}
	__builtin_unreachable();
}

static int cli_compression(struct bbs_cli_args *a)
{
	struct compress_data *z;

	bbs_dprintf(a->fdout, "%3s %3s %8s %8s %5s %11s %11s %11s %11s %6s %6s %s\n", "RFD", "WFD", "Orig RFD", "Orig WFD", "Level", "Sent Data", "Sent (Comp)", "Recv Data", "Recv (Comp)", "Send %", "Recv %", "Thread");
	RWLIST_RDLOCK(&compressors);
	RWLIST_TRAVERSE(&compressors, z, entry) {
		char send_pct[13], recv_pct[13];
		snprintf(send_pct, sizeof(send_pct), "%d%%", (int) (100.0 * (double) z->sentbytes_comp / (double) z->sentbytes));
		snprintf(recv_pct, sizeof(recv_pct), "%d%%", (int) (100.0 * (double) z->recvbytes_comp / (double) z->recvbytes));
#if defined(__linux__) && defined(__GLIBC__)
		bbs_dprintf(a->fdout, "%3d %3d %8d %8d %5d %11lu %11lu %11lu %11lu %6s %6s %lu\n",
			z->rpfd[0], z->wpfd[1], z->orig_rfd, z->orig_wfd, z->level, z->sentbytes, z->sentbytes_comp, z->recvbytes, z->recvbytes_comp, send_pct, recv_pct, z->thread);
#else
		bbs_dprintf(a->fdout, "%3d %3d %8d %8d %5d %11lu %11lu %11lu %11lu %6s %6s\n",
			z->rpfd[0], z->wpfd[1], z->orig_rfd, z->orig_wfd, z->level, z->sentbytes, z->sentbytes_comp, z->recvbytes, z->recvbytes_comp, send_pct, recv_pct);
#endif
	}
	RWLIST_UNLOCK(&compressors);
	return 0;
}

static struct bbs_cli_entry cli_commands_compress[] = {
	BBS_CLI_COMMAND(cli_compression, "compressions", 1, "List all compression sessions", NULL),
};

static int load_module(void)
{
	int res = bbs_io_transformer_register("DEFLATE", setup, query, cleanup, TRANSFORM_DEFLATE_COMPRESSION, TRANSFORM_SERVER_CLIENT_TX_RX);
	if (res) {
		return res;
	}
	bbs_cli_register_multiple(cli_commands_compress);
	return 0;
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_compress);
	return bbs_io_transformer_unregister("DEFLATE");
}

BBS_MODULE_INFO_STANDARD("RFC 1951 DEFLATE Compression");
