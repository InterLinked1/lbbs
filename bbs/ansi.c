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
 * \brief ANSI escape sequences
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h> /* use malloc, free */

#include "include/ansi.h"
#include "include/utils.h" /* use bbs_str_safe_print */

int bbs_ansi_strip(const char *restrict in, size_t inlen, char *restrict out, size_t outlen, int *restrict strippedlen)
{
	int outindex = 0;

	/* We're stripping characters. The output can never be larger than the input. */
	if (outlen < inlen + 1) { /* Add 1 since we need to null terminate the buffer */
		/* If outlen > inlen, it's just unnecessarily long.
		 * If outlen < inlen, there could be truncation. */
		bbs_warning("ANSI-stripped output could be truncated (%lu < %lu + 1)\n", outlen, inlen);
	}

	*out = '\0'; /* In case everything is stripped, null terminate now */

	if (!*in) {
		bbs_debug(6, "Input string is empty?\n");
		return -1;
	}

	/* Rules based on ansi2txt */
	while (*in) {
		char c = *(in++);

		switch (c) {
			case 0:
				bbs_error("Malformed ANSI escape sequence\n");
				return -1;
			case 27:
				c = *(in++); /* Eat ESC */
				switch (c) {
					case 0:
						bbs_error("Malformed ANSI escape sequence\n");
						return -1;
					case '7': /* Cursor save */
					case '8': /* Cursor restore */
						break;
					case '#':
						c = *(++in);
						switch (c) {
						case 0:
							bbs_error("Malformed ANSI escape sequence\n");
							return -1;
#pragma GCC diagnostic ignored "-Wpedantic"
						case '3' ... '6': /* Double height top, bottom line; single, double width line */
#pragma GCC diagnostic pop
							/* Fall through */
						default:
							break;
						}
						break;
					case 'P': /* Device control string, eat until ESC */
						while (*in++ && *in == 27);
						break;
					case '\\': /* Termination code form a device control string */
						break;
					case '(': /* Choose character set */
						break;
					case '[':
						c = ';';
						while (*in && c == ';') {
							while (*in && (c = *in++) && c <= '9');
							if (c == '?') {
								c = ';';
								continue;
							}
						}
						break;
					default:
						break;
				}
				break;
#pragma GCC diagnostic ignored "-Wpedantic"
			case 32 ... 126:
#pragma GCC diagnostic pop
				/* Fall through */
			default:
				*out++ = c;
				outindex++;
				break;
		}
	}

#ifdef ANSI_DEBUG
	bbs_debug(7, "insize: %lu, outsize: %lu, outlen: %d\n", inlen, outlen, outindex);
#endif

	if (outindex >= (int) outlen) {
		bbs_error("Truncation occured\n");
		return -1;
	}

	if (strippedlen) {
		*strippedlen = outindex; /* Don't include null terminator in length here */
	}

	*out = '\0';
	return 0;
}
