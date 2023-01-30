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
 * \brief Base64 encoding
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note base64 encoding functions from Asterisk (GPLv2)
 */

#include "include/bbs.h"

#include <stdlib.h> /* use malloc */
#include <string.h> /* use memset */

#include "include/base64.h"

#define BASELINELEN    72  /*!< Line length for Base 64 encoded messages */
#define BASEMAXINLINE  256 /*!< Buffer size for Base 64 attachment encoding */

/*! \brief Structure used for base64 encoding */
struct baseio {
	int iocp;
	int iolen;
	int linelength;
	int ateof;
	unsigned char iobuf[BASEMAXINLINE];
};

/*!
 * \brief utility used by inchar(), for base_encode()
 */
static int inbuf(struct baseio *bio, FILE *fi)
{
	int l;

	if (bio->ateof) {
		return 0;
	}

	if ((l = fread(bio->iobuf, 1, BASEMAXINLINE, fi)) != BASEMAXINLINE) {
		bio->ateof = 1;
		if (l == 0) {
			/* Assume EOF */
			return 0;
		}
	}

	bio->iolen = l;
	bio->iocp = 0;

	return 1;
}

/*!
 * \brief utility used by base_encode()
 */
static int inchar(struct baseio *bio, FILE *fi)
{
	if (bio->iocp >= bio->iolen) {
		if (!inbuf(bio, fi)) {
			return EOF;
		}
	}

	return bio->iobuf[bio->iocp++];
}

/*!
 * \brief utility used by base_encode()
 */
static int ochar(struct baseio *bio, int c, FILE *so, const char *endl)
{
	if (bio->linelength >= BASELINELEN) {
		if (fputs(endl, so) == EOF) {
			return -1;
		}

		bio->linelength = 0;
	}

	if (putc(((unsigned char) c), so) == EOF) {
		return -1;
	}

	bio->linelength++;

	return 1;
}

static int __base64_encode_file(FILE *inputfile, FILE *outputfile, const char *endl)
{
	static const unsigned char dtable[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
		'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0',
		'1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
	int i, hiteof = 0;
	struct baseio bio;

	memset(&bio, 0, sizeof(bio));
	bio.iocp = BASEMAXINLINE;

	while (!hiteof){
		unsigned char igroup[3], ogroup[4];
		int c, n;

		memset(igroup, 0, sizeof(igroup));

		for (n = 0; n < 3; n++) {
			if ((c = inchar(&bio, inputfile)) == EOF) {
				hiteof = 1;
				break;
			}

			igroup[n] = (unsigned char) c;
		}

		if (n > 0) {
			ogroup[0]= dtable[igroup[0] >> 2];
			ogroup[1]= dtable[((igroup[0] & 3) << 4) | (igroup[1] >> 4)];
			ogroup[2]= dtable[((igroup[1] & 0xF) << 2) | (igroup[2] >> 6)];
			ogroup[3]= dtable[igroup[2] & 0x3F];

			if (n < 3) {
				ogroup[3] = '=';

				if (n < 2) {
					ogroup[2] = '=';
				}
			}

			for (i = 0; i < 4; i++) {
				ochar(&bio, ogroup[i], outputfile, endl);
			}
		}
	}

	if (fputs(endl, outputfile) == EOF) {
		return -1;
	}

	return 0;
}

int base64_encode_file(const char *filename, FILE *outputfile, const char *endl)
{
	FILE *fi;
	int res;

	if (!(fi = fopen(filename, "rb"))) {
		bbs_error("Failed to open file: %s: %s\n", filename, strerror(errno));
		return -1;
	}

	res = __base64_encode_file(fi, outputfile, endl);

	fclose(fi);
	return res;
}

static const unsigned char decoding_table[256] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,
0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*! \note Modified and amalgamated from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c/64856489 */
unsigned char *base64_decode(const unsigned char *data, int input_length, int *outlen)
{
	int i, j;
	int output_length;
	unsigned char *decoded_data;

	if (input_length % 4 != 0) {
		bbs_warning("Input length %d is invalid\n", input_length);
		return NULL;
	}

	output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') {
		(output_length)--;
	}
	if (data[input_length - 2] == '=') {
		(output_length)--;
	}

	decoded_data = (unsigned char*) malloc(output_length + 1);
	if (!decoded_data) {
		bbs_error("malloc failed\n");
		return NULL;
	}

	for (i = 0, j = 0; i < input_length;) {
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

		if (j < output_length) {
			decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		}
		if (j < output_length) {
			decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		}
		if (j < output_length) {
			decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
		}
	}

	*outlen = output_length;
	decoded_data[output_length] = '\0';
	return decoded_data;
}
