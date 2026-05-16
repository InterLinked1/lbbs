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

#define SEND_ARTICLE_RESPONSE(fd, messageid, email, group, respcode) \
	SWRITE(clientfd, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_EVENTUALLY(clientfd, "335"); \
	IHAVE_NEWS_ARTICLE(s, fd, messageid, email, group); \
	CLIENT_EXPECT_EVENTUALLY(fd, #respcode);

#define SEND_ARTICLE_REFUSED(fd, messageid, email, group) \
	SWRITE(clientfd, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_EVENTUALLY(clientfd, "435"); \

#define SEND_ARTICLE(fd, messageid, email, group) SEND_ARTICLE_RESPONSE(fd, messageid, email, group, 235)

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

	NEW_NEWSGROUP(sockfd, "test.moderated", "A moderated group", "Sysop", "m");
	NEW_NEWSGROUP(sockfd, "test.closed", "A closed group", "Sysop", "x");
	NEW_NEWSGROUP(sockfd, "test.junk", "A junk group", "Sysop", "j");
	NEW_NEWSGROUP(sockfd, "test.nolocal", "A nolocal group", "Sysop", "n");
	NEW_NEWSGROUP(sockfd, "test.aliased", "An aliased group", "Sysop", "=misc.test");

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

	/* Initial connection */
	CLIENT_EXPECT(clientfd, "200 " TEST_NEWS_HOSTNAME);
	SWRITE(clientfd, "CAPABILITIES\r\n");
	CLIENT_EXPECT(clientfd, "101");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "IHAVE");

	SEND_ARTICLE(clientfd, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer new article that we don't currently have. */
	SEND_ARTICLE_REFUSED(clientfd, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer the same article again, it should be rejected. */
	SEND_ARTICLE_RESPONSE(clientfd, "<restricted.message@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.restricted", 437); /* Offer an article in a newsgroup for which peering is not authorized */

	/* Shouldn't be able to read any articles from this group either */
	SWRITE(clientfd, "GROUP misc.restricted\r\n");
	CLIENT_EXPECT(clientfd, "502");

	SEND_ARTICLE_RESPONSE(clientfd, "<testmessage.101@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.closed", 437); /* Can't post to closed group with status 'x' */
	SEND_ARTICLE(clientfd, "<testmessage.102@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.junk"); /* Can post to a group that gets filed into junk (i.e. peered but not carried locally) */
	SEND_ARTICLE(clientfd, "<testmessage.103@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.nolocal"); /* Can post to group with 'n' status */

	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 2); /* Group has 1 article + overview file */
	SEND_ARTICLE(clientfd, "<testmessage.104@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.aliased"); /* Can post to aliased group, should get filed into misc.test instead */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 3);

	SEND_ARTICLE_RESPONSE(clientfd, "<testmessage.105@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated", 437); /* Messages to moderated group should be rejected without Approved header */
	SEND_ARTICLE(clientfd, "<testmessage.106@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated\r\nApproved: moderator@bbs.example.com"); /* Add Approved header, and now it should work */

	/* Attempt to create a new group, the message should get filed into control.newgroup. Not a properly formed newgroup cmsg, but it suffices for now. */
	SEND_ARTICLE(clientfd, "<testmessage.ctl1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.newgroup\r\nControl: newgroup test.newgroup\r\nApproved: newsmaster@bbs.example.com");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/control/newgroup", 2); /* Control message + overview file */

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Transit Tests");
