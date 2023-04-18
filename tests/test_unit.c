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

/* from mod_sysop.c */
#define BBS_SYSOP_SOCKET DIRCAT(DIRCAT("/var/run", BBS_NAME), "sysop.sock")

static int run(void)
{
	return test_bbs_expect("100%", SEC_MS(5)); /* Unit tests are fast, so shouldn't take very long to execute them all */
}

TEST_MODULE_INFO_STANDARD("Unit Tests");