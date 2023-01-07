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
