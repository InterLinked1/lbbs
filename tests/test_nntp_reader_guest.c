/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief NNTP Guest Reader Tests
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
	test_load_module("net_nntp.so");
	test_load_module("mod_sysop.so"); /* For creating newsgroups */

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_SUBCONFIG("nntp_guest", "net_nntp.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	TEST_RESET_MKDIR(TEST_NEWS_DIR);
	return 0;
}

static int create_groups(void)
{
	int sockfd;

	OPEN_CLI_SOCKET(sockfd);

	NEW_NEWSGROUP(sockfd, "misc.test", "A miscellaneous test group", "Sysop", "y");
	NEW_NEWSGROUP(sockfd, "misc.empty", "A miscellaneous empty group", "Sysop", "y");
	NEW_NEWSGROUP(sockfd, "misc.restricted", "A miscellaneous restricted group", "Sysop", "y");

	close(sockfd);
	return 0;

cleanup:
	return -1; /* No need to close_if(sockfd) first, the only failure path is from REQUIRE_FD in OPEN_CLI_SOCKET */
}

static int run(void)
{
	const char *s;
	int client1 = -1;
	int guest = -1;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	/* This is a separate test from test_nntp_reader, because it requires setting checkidentity=no in net_nntp.conf,
	 * but in test_nntp_reader, we want that left to 'yes' to test certain behavior. */

	/* Have client 1 post an article */
	client1 = test_make_socket(119);
	REQUIRE_FD(client1);
	CLIENT_EXPECT(client1, "200 " TEST_HOSTNAME);

	SWRITE(client1, "AUTHINFO USER " TEST_USER "@" TEST_HOSTNAME "\r\n");
	CLIENT_EXPECT(client1, "381");
	SWRITE(client1, "AUTHINFO PASS " TEST_PASS "\r\n");
	CLIENT_EXPECT(client1, "281");

	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "340");
	POST_NEWS_ARTICLE(s, client1, TEST_EMAIL, "misc.test");
	CLIENT_EXPECT(client1, "240");

	/* Unauthenticated users should be able to read misc.test, but not post there */
	guest = test_make_socket(119);
	REQUIRE_FD(guest);
	CLIENT_EXPECT(guest, "200 " TEST_HOSTNAME);

	SWRITE(guest, "LIST ACTIVE\r\n");
	CLIENT_EXPECT_EVENTUALLY(guest, "misc.test");

	SWRITE(guest, "GROUP misc.test\r\n");
	CLIENT_EXPECT_EVENTUALLY(guest, "211 1 1 1 misc.test");

	SWRITE(guest, "ARTICLE 1\r\n");
	CLIENT_EXPECT_EVENTUALLY(guest, ".\r\n");

	SWRITE(guest, "POST\r\n");
	CLIENT_EXPECT(guest, "340");
	POST_NEWS_ARTICLE(s, guest, TEST_EMAIL, "misc.test");
	CLIENT_EXPECT(guest, "440");

	res = 0;

cleanup:
	close_if(client1);
	close_if(guest);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Guest Reader Tests");
