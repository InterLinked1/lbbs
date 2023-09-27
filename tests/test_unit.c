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
 * \brief Unit Test Executions
 *
 * This simply executes the unit tests from a test framework module,
 * useful since the test framework is run by the CI easily,
 * but the unit tests don't lend themselves as easily to that
 * on their own.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

extern int startup_run_unit_tests;

static int pre(void)
{
	startup_run_unit_tests = 1;
	test_autoload_all(); /* Load everything since multiple modules contain unit tests */
	return 0;
}

static int run(void)
{
	int res = test_bbs_expect(COLOR(COLOR_SUCCESS) "100%" COLOR_RESET, SEC_MS(20)); /* Unit tests are fast, so shouldn't take very long to execute them all */
	if (res) {
		bbs_error("Failed to receive expected output\n");
	}
	return res;
}

TEST_MODULE_INFO_STANDARD("Unit Tests");
