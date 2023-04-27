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
 * \brief Modification Sequence file (.modseqs) decoder
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	FILE *fp;
	int res;
	unsigned int uid;
	unsigned long modseq;

	if (argc != 2) {
		fprintf(stderr, "Usage: modseqdecode <filename>\n");
		exit(EXIT_FAILURE);
	}

	fp = fopen(argv[1], "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open %s\n", argv[1]);
		exit(errno);
	}

	res = fread(&modseq, sizeof(unsigned long), 1, fp);
	if (res != 1) {
		fprintf(stderr, "File corrupted: failed to read HIGHESTMODSEQ\n");
		exit(EXIT_FAILURE);
	}

	printf("HIGHESTMODSEQ: %lu\n", modseq);

	for (;;) {
		res = fread(&uid, sizeof(unsigned int), 1, fp);
		if (res != 1) {
			break;
		}
		res = fread(&modseq, sizeof(unsigned long), 1, fp);
		if (res != 1) {
			break;
		}
		printf("UID - %8u => MODSEQ %12lu\n", uid, modseq);
	}

	fclose(fp);
	return 0;
}
