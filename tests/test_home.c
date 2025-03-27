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
 * \brief Home Directory Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_load_module("net_imap.so");

	/* If 'make templates' (run by 'make samples') has never been run on this system,
	 * the templates won't exist at runtime to copy. */
	TEST_REQUIRE_FILE("/var/lib/lbbs/templates/.config/.imapremote.sample");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_imap.conf");
	TEST_ADD_CONFIG("transfers.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	return 0;
}

static int run(void)
{
	int client1 = -1;
	int res = -1;

	client1 = test_make_socket(143);
	REQUIRE_FD(client1);

	CLIENT_EXPECT(client1, "OK");
	SWRITE(client1, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(client1, "a1 OK");

	/* Logging in to the IMAP server will trigger a check for .imapremote (when doing LIST),
	 * which will autocreate a user's home directory, if needed,
	 * copying any template files. */

	SWRITE(client1, "a2 LIST \"\" \"*\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a2 OK");

	if (eaccess(TEST_HOME_DIR_ROOT "/1/.config/.imapremote.sample", R_OK)) {
		bbs_error("eaccess(%s) failed: %s\n", TEST_HOME_DIR_ROOT "/1/.config/.imapremote.sample", strerror(errno));
		goto cleanup;
	}

	res = 0;

cleanup:
	close_if(client1);
	return res;
}

TEST_MODULE_INFO_STANDARD("Home Directory Tests");
