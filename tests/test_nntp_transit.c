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
	SWRITE(peer1, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_CODE(peer1, NNTP_CONT_IHAVE); \
	SEND_NEWS_ARTICLE(s, fd, messageid, email, group, addl); \
	CLIENT_EXPECT_CODE(fd, respcode);

#define IHAVE_RESPONSE(fd, messageid, email, group, respcode) \
	IHAVE_ADDITIONAL_RESPONSE(fd, messageid, email, group, "", respcode)

#define IHAVE_REFUSED(fd, messageid, email, group) \
	SWRITE(peer1, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_CODE(peer1, NNTP_FAIL_IHAVE_REFUSE); \

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
	int peer1, peer2 = -1;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	peer1 = test_make_socket(433);
	REQUIRE_FD(peer1);

	/* Initial connection */
	CLIENT_EXPECT(peer1, XSTR(NNTP_OK_BANNER_POST) " " TEST_NEWS_HOSTNAME);
	SWRITE(peer1, "CAPABILITIES\r\n");
	CLIENT_EXPECT_CODE(peer1, NNTP_INFO_CAPABILITIES);
	CLIENT_EXPECT_EVENTUALLY(peer1, "IHAVE");

	IHAVE(peer1, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer new article that we don't currently have. */
	IHAVE_REFUSED(peer1, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer the same article again, it should be rejected. */
	IHAVE_RESPONSE(peer1, "<restricted.message@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.restricted", 437); /* Offer an article in a newsgroup for which peering is not authorized */

	/* Shouldn't be able to read any articles from this group either */
	SWRITE(peer1, "GROUP misc.restricted\r\n");
	CLIENT_EXPECT_CODE(peer1, NNTP_ERR_ACCESS);

	IHAVE_RESPONSE(peer1, "<testmessage.101@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.closed", 437); /* Can't post to closed group with status 'x' */
	IHAVE(peer1, "<testmessage.102@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.junk"); /* Can post to a group that gets filed into junk (i.e. peered but not carried locally) */
	IHAVE(peer1, "<testmessage.103@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.nolocal"); /* Can post to group with 'n' status */

	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 2); /* Group has 1 article + overview file */
	IHAVE(peer1, "<testmessage.104@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.aliased"); /* Can post to aliased group, should get filed into misc.test instead */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 3);

	IHAVE_RESPONSE(peer1, "<testmessage.105@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated", 437); /* Messages to moderated group should be rejected without Approved header */
	IHAVE_ADDITIONAL(peer1, "<testmessage.106@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated", "Approved: moderator@bbs.example.com\r\n"); /* Add Approved header, and now it should work */

	/* Attempt to create a new group, the message should get filed into control.newgroup. Not a properly formed newgroup cmsg, but it suffices for now. */
	IHAVE_ADDITIONAL(peer1, "<testmessage.ctl1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.newgroup", "Control: newgroup test.newgroup\r\nApproved: newsmaster@bbs.example.com\r\n");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/control/newgroup", 2); /* Control message + overview file */

	/* Send an article with distributions. First, we include one that is accepted, but the second one time, we include only an unwanted distribution. */

	/* Because dist1a is wanted, even though dist2a is not, article is accepted */
	IHAVE_ADDITIONAL(peer1, "<testmessage.dist1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test", "Distribution: dist1a,dist1b\r\n");

	/* Because dist2a is not wanted by any of the matching inpeer entries, article is rejected */
	IHAVE_ADDITIONAL_RESPONSE(peer1, "<testmessage.dist2@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test", "Distribution: dist1b\r\n", 437);

	/* Test article deferral for in-progress articles */
	peer2 = test_make_socket(433);
	REQUIRE_FD(peer2);
	CLIENT_EXPECT_CODE(peer2, NNTP_OK_BANNER_POST);

	SWRITE(peer2, "MODE STREAM" ENDL);
	CLIENT_EXPECT_CODE(peer2, NNTP_OK_STREAM);

	SWRITE(peer1, "CHECK <concurrently.delivered>" ENDL);
	CLIENT_EXPECT(peer1, XSTR(NNTP_OK_CHECK) " <concurrently.delivered>");
	SWRITE(peer2, "CHECK <concurrently.delivered>" ENDL);
	CLIENT_EXPECT(peer2, XSTR(NNTP_OK_CHECK) " <concurrently.delivered>");
	SWRITE(peer1, "IHAVE <concurrently.delivered>" ENDL);
	CLIENT_EXPECT_CODE(peer1, NNTP_CONT_IHAVE); /* At this point, article delivery is now in progress */
	SWRITE(peer2, "CHECK <concurrently.delivered>" ENDL);
	CLIENT_EXPECT_CODE(peer2, NNTP_FAIL_CHECK_DEFER); /* Article should be deferred */
	SEND_NEWS_ARTICLE(s, peer1, "<concurrently.delivered>", TEST_EMAIL_EXTERNAL, "misc.test", "");
	CLIENT_EXPECT_CODE(peer1, NNTP_OK_IHAVE);
	SWRITE(peer2, "CHECK <concurrently.delivered>" ENDL);
	CLIENT_EXPECT_CODE(peer2, NNTP_FAIL_CHECK_REFUSE); /* Article should be now be rejected outright */

	/* Peer 2 now sends the same article again anyways, should be rejected */
	SWRITE(peer2, "TAKETHIS <concurrently.delivered>" ENDL);
	SEND_NEWS_ARTICLE(s, peer2, "<concurrently.delivered>", TEST_EMAIL_EXTERNAL, "misc.test", "");
	CLIENT_EXPECT(peer2, XSTR(NNTP_FAIL_TAKETHIS_REJECT) " <concurrently.delivered>");

	/* A different article using TAKETHIS should succeed (not yet received) */
	SWRITE(peer2, "TAKETHIS <nonconcurrently.delivered>" ENDL);
	SEND_NEWS_ARTICLE(s, peer2, "<nonconcurrently.delivered>", TEST_EMAIL_EXTERNAL, "misc.test", "");
	CLIENT_EXPECT(peer2, XSTR(NNTP_OK_TAKETHIS) " <nonconcurrently.delivered>");

	/* Send malformed article, which will be rejected */
	SWRITE(peer2, "TAKETHIS <malformed.message>" ENDL);
	SWRITE(peer2, "Newsgroups: misc.test\r\n.\r\n");
	CLIENT_EXPECT(peer2, XSTR(NNTP_FAIL_TAKETHIS_REJECT) " <malformed.message>");

	/* Send article for a group we don't want */
	SWRITE(peer2, "TAKETHIS <unwanted.article>" ENDL);
	SEND_NEWS_ARTICLE(s, peer2, "<unwanted.article>", TEST_EMAIL_EXTERNAL, "misc.test,local.poison", "");
	CLIENT_EXPECT(peer2, XSTR(NNTP_FAIL_TAKETHIS_REJECT) " <unwanted.article>");

	res = 0;

cleanup:
	close(peer1);
	close_if(peer2);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Transit Tests");
