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
 * \brief Memory leaker
 *
 * \note Create a perpetually growing memory leak until stopped (for testing resource limits)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	size_t allocated = 0;

	(void) argc;
	(void) argv;

	for (;;) {
		char *s = malloc(1024 * 1024); /* 1 MB at a time */
		if (!s) {
			printf("Allocation failed\n");
			break;
		}
		allocated++;
		printf("%6lu MB now allocated\n", allocated);
		usleep(50000); /* Pause 50ms for every MB allocated */
	}
	return 0;
}
