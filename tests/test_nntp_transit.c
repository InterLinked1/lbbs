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
 * \brief NNTP Transit Tests
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
	TEST_ADD_CONFIG("net_nntp.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	TEST_RESET_MKDIR(TEST_NEWS_DIR);
	return 0;
}

static int create_groups(void)
{
	int sockfd;

	OPEN_CLI_SOCKET(sockfd);

#define NEW_GROUP(name, desc, creator, posting) \
	CLI_SWRITE(sockfd, "/news newgroup" CLI_EOL); \
	CLI_SWRITE(sockfd, name CLI_EOL); \
	CLI_SWRITE(sockfd, desc CLI_EOL); \
	CLI_SWRITE(sockfd, creator CLI_EOL); \
	CLI_SWRITE(sockfd, posting CLI_EOL);

	NEW_GROUP("misc.test", "A miscellaneous test group", "Sysop", "y");
	NEW_GROUP("misc.empty", "A miscellaneous empty group", "Sysop", "y");

	close(sockfd);
	return 0;

cleanup:
	return -1; /* No need to close_if(sockfd) first, the only failure path is from REQUIRE_FD in OPEN_CLI_SOCKET */
}

static int run(void)
{
	const char *s;
	int clientfd;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	s = "From: \"Demo User\" <" TEST_EMAIL_UNAUTHORIZED ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;

	clientfd = test_make_socket(433);
	REQUIRE_FD(clientfd);

#define TEST_MESSAGE_ID "test.message@" TEST_HOSTNAME

	/* Initial connection */
	CLIENT_EXPECT(clientfd, "200 " TEST_HOSTNAME);
	SWRITE(clientfd, "CAPABILITIES\r\n");
	CLIENT_EXPECT(clientfd, "101");
	CLIENT_EXPECT_EVENTUALLY(clientfd, ".\r\n");

	/* Offer new article that we don't currently have. */
	SWRITE(clientfd, "IHAVE <" TEST_MESSAGE_ID ">\r\n");
	CLIENT_EXPECT(clientfd, "335");
	write(clientfd, s, strlen(s));
	CLIENT_EXPECT_EVENTUALLY(clientfd, "235");

	/* Offer the same article again, it should be rejected. */
	SWRITE(clientfd, "IHAVE <" TEST_MESSAGE_ID ">\r\n");
	CLIENT_EXPECT(clientfd, "435");

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Transit Tests");
