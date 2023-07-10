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
	test_load_module("net_nntp.so");

	TEST_ADD_CONFIG("net_nntp.conf");
	system("rm -rf /tmp/test_lbbs/newsdir"); /* Yuck */
	mkdir(TEST_NEWS_DIR, 0700); /* Make directory if it doesn't exist already */
	mkdir(TEST_NEWS_DIR "/misc.test", 0700);
	mkdir(TEST_NEWS_DIR "/misc.empty", 0700);
	return 0;
}

static int run(void)
{
	const char *s;
	int clientfd;
	int res = -1;

	s = "From: \"Demo User\" <" TEST_EMAIL_UNAUTHORIZED ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;

	clientfd = test_make_socket(433);
	if (clientfd < 0) {
		return -1;
	}

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
