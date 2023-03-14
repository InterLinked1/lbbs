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
 * \brief RFC 4616 PLAIN SASL Encoder
 *
 * \note Creates a base64 encoded PLAIN SASL authentication string from identity
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static char encoding_table[] =
{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
'w', 'x', 'y', 'z', '0', '1', '2', '3',
'4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

/*! \brief Based on https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c/6782480#6782480 */
static char *base64_encode(const char *data, int input_length, int *outlen)
{
	char *encoded_data;
	int i, j, output_len;

	output_len = 4 * ((input_length + 2) / 3);
	encoded_data = malloc(output_len);
	if (!encoded_data) {
		return NULL;
	}

    for (i = 0, j = 0; i < input_length; ) {
        uint32_t octet_a = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[output_len - 1 - i] = '=';
	}

	*outlen = output_len;
    return encoded_data;
}

int main(int argc, char *argv[])
{
	char *encoded;
	int outlen;
	char decoded[1024];
	unsigned long len;

	if (argc != 4) {
		fprintf(stderr, "Usage: saslencode <nickname> <username> <password>\n");
		exit(EXIT_FAILURE);
	}

	len = snprintf(decoded, sizeof(decoded), "%s%c%s%c%s", argv[1], '\0', argv[2], '\0', argv[3]);
	if (len >= sizeof(decoded)) {
		fprintf(stderr, "Truncation occured (arguments too long!)\n");
		return -1;
	}
	encoded = base64_encode(decoded, len, &outlen);
	if (!encoded) {
		fprintf(stderr, "base64 encoding failed\n");
		return -1;
	}
	printf("Base64: %s\n", encoded);
	free(encoded);
	return 0;
}
