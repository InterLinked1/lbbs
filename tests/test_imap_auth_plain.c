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
 * \brief IMAP AUTH PLAIN Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

static int pre(void)
{
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
	int clientfd = -1;
	int res = -1;

	clientfd = test_make_socket(143);
	REQUIRE_FD(clientfd);

	/* Connect and log in */
	CLIENT_EXPECT(clientfd, "* OK [CAPABILITY");

	SWRITE(clientfd, "1 authenticate PLAIN" ENDL);
	CLIENT_EXPECT(clientfd, "+");

	SWRITE(clientfd, TEST_SASL ENDL);
	CLIENT_EXPECT(clientfd, "1 OK [CAPABILITY");

	SWRITE(clientfd, "2 ID (\"name\" \"MailNews\" \"version\" \"52.9.8629a1\")" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "2 OK");

	SWRITE(clientfd, "3 select \"INBOX\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "3 OK");

	/* LOGOUT */
	SWRITE(clientfd, "4 LOGOUT" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* BYE");
	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP AUTHENTICATE PLAIN Tests");
