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

#include "../nets/net_nntp/nntp.h"

#define IHAVE_ADDITIONAL_RESPONSE(fd, messageid, email, group, addl, respcode) \
	SWRITE(clientfd, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_CODE(clientfd, NNTP_CONT_IHAVE); \
	IHAVE_NEWS_ARTICLE(s, fd, messageid, email, group, addl); \
	CLIENT_EXPECT_CODE(fd, respcode);

#define IHAVE_RESPONSE(fd, messageid, email, group, respcode) \
	IHAVE_ADDITIONAL_RESPONSE(fd, messageid, email, group, "", respcode)

#define IHAVE_REFUSED(fd, messageid, email, group) \
	SWRITE(clientfd, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_CODE(clientfd, NNTP_FAIL_IHAVE_REFUSE); \

#define IHAVE(fd, messageid, email, group) IHAVE_RESPONSE(fd, messageid, email, group, NNTP_OK_IHAVE)

#define IHAVE_ADDITIONAL(fd, messageid, email, group, addl) IHAVE_ADDITIONAL_RESPONSE(fd, messageid, email, group, addl, NNTP_OK_IHAVE)

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
	CLIENT_EXPECT(clientfd, XSTR(NNTP_OK_BANNER_POST) " " TEST_NEWS_HOSTNAME);
	SWRITE(clientfd, "CAPABILITIES\r\n");
	CLIENT_EXPECT_CODE(clientfd, NNTP_INFO_CAPABILITIES);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "IHAVE");

	IHAVE(clientfd, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer new article that we don't currently have. */
	IHAVE_REFUSED(clientfd, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer the same article again, it should be rejected. */
	IHAVE_RESPONSE(clientfd, "<restricted.message@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.restricted", 437); /* Offer an article in a newsgroup for which peering is not authorized */

	/* Shouldn't be able to read any articles from this group either */
	SWRITE(clientfd, "GROUP misc.restricted\r\n");
	CLIENT_EXPECT_CODE(clientfd, NNTP_ERR_ACCESS);

	IHAVE_RESPONSE(clientfd, "<testmessage.101@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.closed", 437); /* Can't post to closed group with status 'x' */
	IHAVE(clientfd, "<testmessage.102@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.junk"); /* Can post to a group that gets filed into junk (i.e. peered but not carried locally) */
	IHAVE(clientfd, "<testmessage.103@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.nolocal"); /* Can post to group with 'n' status */

	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 2); /* Group has 1 article + overview file */
	IHAVE(clientfd, "<testmessage.104@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.aliased"); /* Can post to aliased group, should get filed into misc.test instead */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 3);

	IHAVE_RESPONSE(clientfd, "<testmessage.105@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated", 437); /* Messages to moderated group should be rejected without Approved header */
	IHAVE_ADDITIONAL(clientfd, "<testmessage.106@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated", "Approved: moderator@bbs.example.com\r\n"); /* Add Approved header, and now it should work */

	/* Attempt to create a new group, the message should get filed into control.newgroup. Not a properly formed newgroup cmsg, but it suffices for now. */
	IHAVE_ADDITIONAL(clientfd, "<testmessage.ctl1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.newgroup", "Control: newgroup test.newgroup\r\nApproved: newsmaster@bbs.example.com\r\n");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/control/newgroup", 2); /* Control message + overview file */

	/* Send an article with distributions. First, we include one that is accepted, but the second one time, we include only an unwanted distribution. */

	/* Because dist1a is wanted, even though dist2a is not, article is accepted */
	IHAVE_ADDITIONAL(clientfd, "<testmessage.dist1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test", "Distribution: dist1a,dist1b\r\n");

	/* Because dist2a is not wanted by any of the matching inpeer entries, article is rejected */
	IHAVE_ADDITIONAL_RESPONSE(clientfd, "<testmessage.dist2@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test", "Distribution: dist1b\r\n", 437);

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Transit Tests");
