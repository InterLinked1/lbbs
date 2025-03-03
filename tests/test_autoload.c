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
 * \brief Module Autoload Test
 *
 * This simply autoloads all the modules for a test
 * and then shuts everything back down again
 * after a brief delay.
 *
 * Since we autoload as many modules as possible,
 * this can be useful for narrowing the scope of
 * any issues that may arise just from a module
 * loading, since this test does nothing else.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

static int pre(void)
{
	test_autoload_all(); /* Load everything since multiple modules contain unit tests */
	return 0;
}

static int run(void)
{
	/* After the BBS starts, wait a few seconds, then shut it down again
	 * This gives enough time for the mod_irc_client -> net_irc connection
	 * to be established. */
	sleep(4);
	return 0;
}

TEST_MODULE_INFO_STANDARD("Autoload Tests");
