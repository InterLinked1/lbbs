/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Backtrace Test
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/test.h"

static int test_backtrace(void)
{
	/* This test is mainly used to help determine if we have a buggy version of libbfd,
	 * i.e. one that leaks memory on every backtrace. */
	bbs_log_backtrace();
	return 0;
}

static struct bbs_unit_test tests[] =
{
	{ "Backtrace Test", test_backtrace },
};

static int unload_module(void)
{
	return bbs_unregister_tests(tests);
}

static int load_module(void)
{
	int res = bbs_register_tests(tests);
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_STANDARD("Backtrace Unit Tests");
