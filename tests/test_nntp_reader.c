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
 * \brief NNTP Reader Tests
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

	TEST_RESET_MKDIR(TEST_NEWS_DIR);
	TEST_MKDIR(TEST_NEWS_DIR "/misc.test");
	TEST_MKDIR(TEST_NEWS_DIR "/misc.empty");
	return 0;
}

static int run(void)
{
	const char *s;
	int clientfd;
	int res = -1;

	clientfd = test_make_socket(119);
	REQUIRE_FD(clientfd);

	/* Initial connection */
	CLIENT_EXPECT(clientfd, "200 " TEST_HOSTNAME);
	SWRITE(clientfd, "CAPABILITIES\r\n");
	CLIENT_EXPECT(clientfd, "101");
	CLIENT_EXPECT_EVENTUALLY(clientfd, ".\r\n");

	/* Posting without logging in should fail */
	SWRITE(clientfd, "POST\r\n");
	CLIENT_EXPECT(clientfd, "480");

	/* Log in now */
	SWRITE(clientfd, "AUTHINFO USER " TEST_USER "@" TEST_HOSTNAME "\r\n");
	CLIENT_EXPECT(clientfd, "381");
	SWRITE(clientfd, "AUTHINFO PASS " TEST_PASS "\r\n");
	CLIENT_EXPECT(clientfd, "281");

	/* Try posting an article under an unauthorized identity */
	SWRITE(clientfd, "POST\r\n");
	CLIENT_EXPECT(clientfd, "340");
	s = "From: \"Demo User\" <" TEST_EMAIL_UNAUTHORIZED ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;
	write(clientfd, s, strlen(s)); /* This message is from RFC 3977 6.3.1.3 */
	CLIENT_EXPECT(clientfd, "441");

	/* Ensure the article wasn't accepted and stored */
	SWRITE(clientfd, "ARTICLE 1\r\n");
	CLIENT_EXPECT(clientfd, "412"); /* No group currently selected */
	SWRITE(clientfd, "GROUP misc.test\r\n"); /* Select a group */
	CLIENT_EXPECT(clientfd, "211 0 0 0 misc.test");

	/* Attempts to fetch nonexistent articles should fail */
	SWRITE(clientfd, "ARTICLE 1\r\n");
	CLIENT_EXPECT(clientfd, "423");

	/* Try again with an authorized identity */
	SWRITE(clientfd, "POST\r\n");
	CLIENT_EXPECT(clientfd, "340");
	s = "From: \"Demo User\" <" TEST_EMAIL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;
	write(clientfd, s, strlen(s)); /* This message is from RFC 3977 6.3.1.3 */
	CLIENT_EXPECT(clientfd, "240");

	/* Try querying all the newsgroups */
	SWRITE(clientfd, "LIST\r\n");
	CLIENT_EXPECT(clientfd, "215");
	/* Should be sorted, so misc.empty should be in the first line. */
	CLIENT_EXPECT(clientfd, "misc.empty"); /* Don't also wait for misc.test, etc. since it's probably part of the same read() output and we don't chunk per line */

	/* Try reading that article: it should now exist. */
	SWRITE(clientfd, "GROUP misc.test\r\n");
	CLIENT_EXPECT(clientfd, "211 1 1 1 misc.test");
	SWRITE(clientfd, "HEAD 1\r\n");
	CLIENT_EXPECT(clientfd, "221");
	CLIENT_EXPECT(clientfd, TEST_EMAIL); /* Our email should be in the response data */
	SWRITE(clientfd, "ARTICLE 1\r\n");
	CLIENT_EXPECT_EVENTUALLY(clientfd, ".\r\n");

	/* No previous */
	SWRITE(clientfd, "LAST\r\n");
	CLIENT_EXPECT(clientfd, "422");

	/* No next */
	SWRITE(clientfd, "NEXT\r\n");
	CLIENT_EXPECT(clientfd, "421");

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Reader Tests");
