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
	int client1 = -1, client3 = -1;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	client1 = test_make_socket(119);
	REQUIRE_FD(client1);

	/* Initial connection */
	CLIENT_EXPECT(client1, "200 " TEST_HOSTNAME);
	SWRITE(client1, "CAPABILITIES\r\n");
	CLIENT_EXPECT(client1, "101");
	CLIENT_EXPECT_EVENTUALLY(client1, ".\r\n");

	/* Posting without logging in should fail */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "480");

	/* Log in now */
	SWRITE(client1, "AUTHINFO USER " TEST_USER "@" TEST_HOSTNAME "\r\n");
	CLIENT_EXPECT(client1, "381");
	SWRITE(client1, "AUTHINFO PASS " TEST_PASS "\r\n");
	CLIENT_EXPECT(client1, "281");

	/* Try posting an article under an unauthorized identity */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "340");
	POST_NEWS_ARTICLE(s, client1, TEST_EMAIL_UNAUTHORIZED, "misc.test"); /* This message is from RFC 3977 6.3.1.3 */
	CLIENT_EXPECT(client1, "441");

	/* Ensure the article wasn't accepted and stored */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT(client1, "412"); /* No group currently selected */
	SWRITE(client1, "GROUP misc.test\r\n"); /* Select a group */
	CLIENT_EXPECT(client1, "211 0 0 0 misc.test");

	/* Attempts to fetch nonexistent articles should fail */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT(client1, "423");

	/* Try again with an authorized identity */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "340");
	POST_NEWS_ARTICLE(s, client1, TEST_EMAIL, "misc.test");
	CLIENT_EXPECT(client1, "240");

	/* Try querying all the newsgroups */
	SWRITE(client1, "LIST\r\n");
	CLIENT_EXPECT(client1, "215");
	/* Should be sorted, so misc.empty should be in the first line. */
	CLIENT_EXPECT(client1, "misc.empty 0 0 y"); /* Don't also wait for misc.test, etc. since it's probably part of the same read() output and we don't chunk per line */

	/* Ask for different LIST variants */
	SWRITE(client1, "LIST ACTIVE\r\n");
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test 1 1 y"); /* Should appear last alphabetically */

	SWRITE(client1, "LIST ACTIVE.TIMES *test\r\n"); /* specify wildmat that will only match one group */
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT(client1, "Sysop");

	SWRITE(client1, "LIST NEWSGROUPS\r\n");
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test A miscellaneous test group");

	SWRITE(client1, "LIST DISTRIB.PATS\r\n");
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT_EVENTUALLY(client1, ".");

	/* Try reading that article: it should now exist. */
	SWRITE(client1, "GROUP misc.test\r\n");
	CLIENT_EXPECT(client1, "211 1 1 1 misc.test");
	SWRITE(client1, "HEAD 1\r\n");
	CLIENT_EXPECT(client1, "221");
	CLIENT_EXPECT(client1, TEST_EMAIL); /* Our email should be in the response data */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ".\r\n");

	/* No previous */
	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, "422");

	/* No next */
	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, "421");

	/* Post again, using a different From identity that is an alias of our mailbox,
	 * so we should be allowed to post using it. */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "340");
	POST_NEWS_ARTICLE(s, client1, "nntpalias@" TEST_HOSTNAME, "misc.test");
	CLIENT_EXPECT(client1, "240");

	/* Try some things that should be denied by ACL */

	/* Can't post to misc.restricted */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "340");
	POST_NEWS_ARTICLE(s, client1, TEST_EMAIL, "misc.restricted");
	CLIENT_EXPECT(client1, "440");

	/* User 3 isn't allowed to do anything, since he has no matching ACL */
	client3 = test_make_socket(119);
	REQUIRE_FD(client3);
	CLIENT_EXPECT(client3, "200 " TEST_HOSTNAME);

	SWRITE(client3, "AUTHINFO USER " TEST_USER3 "@" TEST_HOSTNAME "\r\n");
	CLIENT_EXPECT(client3, "381");
	SWRITE(client3, "AUTHINFO PASS " TEST_PASS3 "\r\n");
	CLIENT_EXPECT(client3, "281");

	SWRITE(client3, "LIST ACTIVE misc.test\r\n");
	CLIENT_EXPECT(client3, "215");
	CLIENT_EXPECT(client3, ".");

	SWRITE(client3, "GROUP misc.test\r\n");
	CLIENT_EXPECT(client3, "502");

	res = 0;

cleanup:
	close_if(client1);
	close_if(client3);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Reader Tests");
