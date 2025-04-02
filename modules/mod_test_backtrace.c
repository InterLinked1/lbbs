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
#include "include/cli.h"

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

static int cli_abort(struct bbs_cli_args *a)
{
	/* Test CLI command to manually abort to test if we can dump core successfully
	 * This can be used to confirm a core would be dumped if the BBS were to crash for another reason. */
	UNUSED(a);
	abort();
	return -1; /* Never reached */
}

static struct bbs_cli_entry cli_commands_backtrace[] = {
	BBS_CLI_COMMAND(cli_abort, "abort", 1, "Abort BBS and dump core", NULL),
};

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_backtrace);
	return bbs_unregister_tests(tests);
}

static int load_module(void)
{
	int res = bbs_register_tests(tests);
	if (!res) {
		bbs_cli_register_multiple(cli_commands_backtrace);
	}
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_STANDARD("Backtrace Unit Tests");
