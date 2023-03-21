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
 * \brief Allocation Recovery Test
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>

extern int test_autorun;
extern int rand_alloc_fails;

static int pre(void)
{
	test_autorun = 0;
	rand_alloc_fails = 1; /* Randomly fail some allocations */
	test_autoload_all();
	return 0;
}

static int run(void)
{
	int i;
	unsigned long f = 0;
	int ports[] = { 23, 25, 80, 110, 143 };
	int clientfds[ARRAY_LEN(ports)];

	/* The purpose of this test is not to ensure correctness of any particular functionality,
	 * since memory allocation failures will likely lead to things NOT working correctly.
	 * Rather, the goal is to stress test the BBS, cause some allocation failures, and ensure that
	 * a) we don't crash
	 * b) memory leaks don't ensue as a result of the allocation failures.
	 *
	 */

	/* At least a few allocation errors should happen in this case */
	for (i = 0; i < 75; i++) {
		for (f = 0; f < ARRAY_LEN(ports); f++) {
			clientfds[f] = test_make_socket(ports[f]);
		}
		for (f = 0; f < ARRAY_LEN(ports); f++) {
			close_if(clientfds[f]);
		}
	}

	usleep(1000);

	return 0;
}

TEST_MODULE_INFO_STANDARD("Allocation Tests");
