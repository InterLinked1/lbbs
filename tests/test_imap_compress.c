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
 * \brief IMAP COMPRESS Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "compress.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

static int pre(void)
{
	test_preload_module("io_compress.so");
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

static int run(void)
{
	struct z_data *z = NULL;
	int clientfd = -1;
	int res = -1;

	clientfd = test_make_socket(143);
	if (clientfd < 0) {
		return -1;
	}

	/* Connect and log in */
	CLIENT_EXPECT(clientfd, "OK");
	SWRITE(clientfd, "1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(clientfd, "1 OK");

	SWRITE(clientfd, "2 COMPRESS DEFLATE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "2 OK"); /* The tagged response is without compress. After this, we use compression for the remainder of the session. */

	z = z_client_new(clientfd);
	REQUIRE_ZLIB_CLIENT(z);

	ZLIB_SWRITE(z, "3 ID (\"name\" \"LBBS Tester\" \"version\" \"123\")" ENDL);
	ZLIB_CLIENT_EXPECT_EVENTUALLY(z, "3 OK");

	ZLIB_SWRITE(z, "4 select \"INBOX\"" ENDL);
	ZLIB_CLIENT_EXPECT_EVENTUALLY(z, "4 OK");

	/* LOGOUT */
	ZLIB_SWRITE(z, "5 LOGOUT" ENDL);
	ZLIB_CLIENT_EXPECT_EVENTUALLY(z, "* BYE");
	res = 0;

cleanup:
	ZLIB_CLIENT_SHUTDOWN(z);
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP COMPRESS Tests");
