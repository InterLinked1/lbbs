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
	int clientfd;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	clientfd = test_make_socket(433);
	REQUIRE_FD(clientfd);

#define TEST_MESSAGE_ID "<test.message@" TEST_NEWS_HOSTNAME ">"

	/* Initial connection */
	CLIENT_EXPECT(clientfd, "200 " TEST_NEWS_HOSTNAME);
	SWRITE(clientfd, "CAPABILITIES\r\n");
	CLIENT_EXPECT(clientfd, "101");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "IHAVE");

	/* Offer new article that we don't currently have. */
	SWRITE(clientfd, "IHAVE " TEST_MESSAGE_ID "\r\n");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "335");
	IHAVE_NEWS_ARTICLE(s, clientfd, TEST_MESSAGE_ID, TEST_EMAIL_UNAUTHORIZED, "misc.test"); /* This message is from RFC 3977 6.3.1.3 */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "235");

	/* Offer the same article again, it should be rejected. */
	SWRITE(clientfd, "IHAVE " TEST_MESSAGE_ID "\r\n");
	CLIENT_EXPECT(clientfd, "435");

	/* Offer an article in a newsgroup for which peering is not authorized */
	SWRITE(clientfd, "IHAVE <restricted.message@" TEST_HOSTNAME ">\r\n");
	CLIENT_EXPECT(clientfd, "335");
	IHAVE_NEWS_ARTICLE(s, clientfd, TEST_MESSAGE_ID, TEST_EMAIL_UNAUTHORIZED, "misc.restricted");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "437");

	/* Shouldn't be able to read any articles from this group either */
	SWRITE(clientfd, "GROUP misc.restricted\r\n");
	CLIENT_EXPECT(clientfd, "502");

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Transit Tests");
