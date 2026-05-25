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

#include "../include/test.h" /* use bbs_test_assert macros */

#include "netnews.h"

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
	NEW_NEWSGROUP(sockfd, "feed.test", "An group fed to peers", "Sysop", "y");

	close(sockfd);
	return 0;

cleanup:
	return -1; /* No need to close_if(sockfd) first, the only failure path is from REQUIRE_FD in OPEN_CLI_SOCKET */
}

static int run(void)
{
	const char *s;
	int client1 = -1;
	int peer1, peer2 = -1;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	peer1 = test_make_socket(433);
	REQUIRE_FD(peer1);

	/* Also open a client to verify certain things */
	client1 = test_make_socket(119);
	REQUIRE_FD(client1);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_BANNER_POST) " " TEST_NEWS_HOSTNAME);
	SWRITE(client1, "AUTHINFO USER " TEST_USER "@" TEST_NEWS_HOSTNAME "\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_CONT_AUTHINFO);
	SWRITE(client1, "AUTHINFO PASS " TEST_PASS "\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_AUTHINFO);

	/* Initial connection */
	CLIENT_EXPECT(peer1, XSTR(NNTP_OK_BANNER_POST) " " TEST_NEWS_HOSTNAME);
	SWRITE(peer1, "CAPABILITIES\r\n");
	CLIENT_EXPECT_EVENTUALLY(peer1, "IHAVE");

	/* We do this only to finish reading the rest of the response and ensure that there is no unread output */
	SWRITE(peer1, "DATE\r\n");
	CLIENT_EXPECT_EVENTUALLY(peer1, "111");

	IHAVE(peer1, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer new article that we don't currently have. */
	IHAVE_REFUSED(peer1, "<test.message@" TEST_NEWS_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test"); /* Offer the same article again, it should be rejected. */
	IHAVE_RESPONSE(peer1, "<restricted.message@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.restricted", NNTP_FAIL_IHAVE_REJECT); /* Offer an article in a newsgroup for which peering is not authorized */

	/* Shouldn't be able to read any articles from this group either */
	SWRITE(peer1, "GROUP misc.restricted\r\n");
	CLIENT_EXPECT_CODE(peer1, NNTP_ERR_ACCESS);

	IHAVE_RESPONSE(peer1, "<testmessage.101@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.closed", NNTP_FAIL_IHAVE_REJECT); /* Can't post to closed group with status 'x' */
	IHAVE(peer1, "<testmessage.102@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.junk"); /* Can post to a group that gets filed into junk (i.e. peered but not carried locally) */
	IHAVE(peer1, "<testmessage.103@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.nolocal"); /* Can post to group with 'n' status */

	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 2); /* Group has 1 article + overview file */
	IHAVE(peer1, "<testmessage.104@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.aliased"); /* Can post to aliased group, should get filed into misc.test instead */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/misc/test", 3);

	IHAVE_RESPONSE(peer1, "<testmessage.105@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated", NNTP_FAIL_IHAVE_REJECT); /* Messages to moderated group should be rejected without Approved header */
	IHAVE_ADDITIONAL(peer1, "<testmessage.106@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.moderated", "Approved: moderator@bbs.example.com\r\n"); /* Add Approved header, and now it should work */

	/* Attempt to create a new group, the message should get filed into control.newgroup. Not a properly formed newgroup cmsg, but it suffices for now. */
	IHAVE_ADDITIONAL(peer1, "<testmessage.ctl1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "test.newgroup", "Control: newgroup test.newgroup\r\nApproved: newsmaster@bbs.example.com\r\n");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_NEWS_DIR "/control/newgroup", 2); /* Control message + overview file */

	/* Send an article with distributions. First, we include one that is accepted, but the second one time, we include only an unwanted distribution. */

	/* Because dist1a is wanted, even though dist2a is not, article is accepted */
	IHAVE_ADDITIONAL(peer1, "<testmessage.dist1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test", "Distribution: dist1a,dist1b\r\n");

	/* Because rejdist is not wanted by any of the matching inpeer entries, article is rejected */
	IHAVE_ADDITIONAL_RESPONSE(peer1, "<testmessage.rejdist@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test", "Distribution: rejdist\r\n", NNTP_FAIL_IHAVE_REJECT);

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
	SEND_PEER_NEWS_ARTICLE(s, peer1, "<concurrently.delivered>", TEST_EMAIL_EXTERNAL, "misc.test", "");
	CLIENT_EXPECT_CODE(peer1, NNTP_OK_IHAVE);
	SWRITE(peer2, "CHECK <concurrently.delivered>" ENDL);
	CLIENT_EXPECT_CODE(peer2, NNTP_FAIL_CHECK_REFUSE); /* Article should be now be rejected outright */

	/* Peer 2 now sends the same article again anyways, should be rejected */
	SWRITE(peer2, "TAKETHIS <concurrently.delivered>" ENDL);
	SEND_PEER_NEWS_ARTICLE(s, peer2, "<concurrently.delivered>", TEST_EMAIL_EXTERNAL, "misc.test", "");
	CLIENT_EXPECT(peer2, XSTR(NNTP_FAIL_TAKETHIS_REJECT) " <concurrently.delivered>");

	/* A different article using TAKETHIS should succeed (not yet received) */
	SWRITE(peer2, "TAKETHIS <nonconcurrently.delivered>" ENDL);
	SEND_PEER_NEWS_ARTICLE(s, peer2, "<nonconcurrently.delivered>", TEST_EMAIL_EXTERNAL, "misc.test", "");
	CLIENT_EXPECT(peer2, XSTR(NNTP_OK_TAKETHIS) " <nonconcurrently.delivered>");

	/* Send malformed article, which will be rejected */
	SWRITE(peer2, "TAKETHIS <malformed.message>" ENDL);
	SWRITE(peer2, "Newsgroups: misc.test\r\n.\r\n");
	CLIENT_EXPECT(peer2, XSTR(NNTP_FAIL_TAKETHIS_REJECT) " <malformed.message>");

	/* Send article for a group we don't want */
	SWRITE(peer2, "TAKETHIS <unwanted.article>" ENDL);
	SEND_PEER_NEWS_ARTICLE(s, peer2, "<unwanted.article>", TEST_EMAIL_EXTERNAL, "misc.test,local.poison", "");
	CLIENT_EXPECT(peer2, XSTR(NNTP_FAIL_TAKETHIS_REJECT) " <unwanted.article>");

	/* Send article with a site we don't want */
	SWRITE(peer1, "TAKETHIS <unwanted.site>" ENDL);
	s = "Path: foo!verybadsite!.POSTED!not-for-mail" ENDL
		"Date: " NNTP_TEST_DATE_HEADER ENDL
		"From: \"Demo User\" <" TEST_EMAIL_EXTERNAL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Message-ID: <unwanted.site>" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;
	write(peer1, s, strlen(s));
	CLIENT_EXPECT_CODE(peer1, NNTP_FAIL_TAKETHIS_REJECT);

	/* Send article with malformed header */
	SWRITE(peer2, "TAKETHIS <malformed.article>" ENDL);
	SEND_PEER_NEWS_ARTICLE(s, peer2, "<malformed.article>", TEST_EMAIL_EXTERNAL, "misc.test,,misc.foo", "");
	CLIENT_EXPECT(peer2, XSTR(NNTP_FAIL_TAKETHIS_REJECT) " <malformed.article>");

	/* Send article with Xref header, which should be ignored and replaced */
	TAKETHIS_ADDITIONAL_RESPONSE(peer1, "<testmessage.xref@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "misc.test", NNTP_OK_TAKETHIS,
		"Xref: news.example.com misc.test:9832\r\n"
	);
	GROUP_EXPECT(client1, "misc.test", 1, 6, 6);
	SWRITE(client1, "HDR Xref 6\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "6 Xref: news.example.com misc.test:6" ENDL);

	/* Test receiving article with long Path header that will get wrapped (and a few <diag-match>'s (e.g. "!!") */
	SWRITE(peer1, "TAKETHIS <long.path>" ENDL);
	s = "Path: foo!foo1!foo2!foo3!foo4!foo5!foo6!foo7!foo8!foo9!!foo10!foo11!foo12!foo13!foo14!foo15!foo16!foo17!foo18!foo19!!foo20!foo21!foo22!foo23!foo24!foo25!"
		"foo26!foo27!foo28!foo29!foo30!foo31!foo32!foo33!foo34!foo35!foo36!foo37!foo38!foo39!foo40!foo41!foo42!foo43!foo44!.POSTED!not-for-mail" ENDL
		"Date: " NNTP_TEST_DATE_HEADER ENDL
		"From: \"Demo User\" <" TEST_EMAIL_EXTERNAL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Message-ID: <long.path>" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;
	write(peer1, s, strlen(s));
	CLIENT_EXPECT_CODE(peer1, NNTP_OK_TAKETHIS);

	/* Article without mandatory headers should be rejected, here we check Date, Path, and Message-ID in particular since those are not required for proto-articles. */
	/* Missing Date */
	SWRITE(peer1, "TAKETHIS <missing.date>" ENDL);
	s = "From: \"Demo User\" <" TEST_EMAIL_EXTERNAL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Message-ID: <missing.date>" ENDL
		"Subject: I am just a test article" ENDL
		"Path: !foosite!.POSTED" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;
	write(peer1, s, strlen(s));
	CLIENT_EXPECT_CODE(peer1, NNTP_FAIL_TAKETHIS_REJECT);

	/* Missing Path */
	SWRITE(peer1, "TAKETHIS <missing.path>" ENDL);
	s = "From: \"Demo User\" <" TEST_EMAIL_EXTERNAL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Message-ID: <missing.path>" ENDL
		"Date: " NNTP_TEST_DATE_HEADER ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;
	write(peer1, s, strlen(s));
	CLIENT_EXPECT_CODE(peer1, NNTP_FAIL_TAKETHIS_REJECT);

	/* Missing Message-ID */
	SWRITE(peer1, "TAKETHIS <missing.messageid>" ENDL);
	s = "From: \"Demo User\" <" TEST_EMAIL_EXTERNAL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Date: " NNTP_TEST_DATE_HEADER ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This is just a test article." ENDL
		"." ENDL;
	write(peer1, s, strlen(s));
	CLIENT_EXPECT_CODE(peer1, NNTP_FAIL_TAKETHIS_REJECT);

	/* Now, test sending received articles to other peers (which are actually ourself, so these articles will all be refused) */
	TAKETHIS(peer1, "<feedmessage.1@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "feed.test");
	TAKETHIS(peer1, "<feedmessage.2@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "feed.test");
	TAKETHIS(peer1, "<feedmessage.3@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "feed.test");
	TAKETHIS(peer1, "<feedmessage.4@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "feed.test");
	TAKETHIS_ADDITIONAL(peer1, "<feedmessage.5@" TEST_HOSTNAME ">", TEST_EMAIL_EXTERNAL, "feed.test",
		"Distribution: dist1a\r\n" /* this will cause the article to get fed to multiple sites */
	);
	TAKETHIS_ADDITIONAL(peer1, "<feedmessage.6@" TEST_HOSTNAME ">", TEST_EMAIL, "feed.test", /* Use a local email so it will be authorized to post */
		"Distribution: post\r\n" /* this will cause the article to get fed using a reading connection */
	);

	TEST_CLI_COMMAND("news feedstats"); /* If running tests manually, inspect the stats and backlogs */
	TEST_CLI_COMMAND("news feedflush queueflush"); /* Flush articles that were queued for site 'queueflush' */

	/* Pause briefly or the last article might not get processed and will remain in the backlog file (esp. under valgrind) */
	if (running_under_valgrind()) { /* An awful kludge, I know */
		usleep(2500000);
	} else {
		usleep(500000);
	}

	TEST_CLI_COMMAND("news feedstats"); /* Backlog for that site should clear */

	res = 0;

cleanup:
	close(peer1);
	close_if(peer2);
	close_if(client1);
	return res;
}

static int post(void)
{
	struct stat st_loopback1, st_loopback2, st_loopback3, st_queueonly, st_queueflush;

	/* After the BBS has exited, make sure the backlogs for the peers loopback1 and loopback2 are as expected: */
	if (stat(TEST_NEWS_DIR "/.backlog/loopback1", &st_loopback1)) {
		bbs_error("stat failed: %s\n", strerror(errno));
		goto cleanup;
	} else if (stat(TEST_NEWS_DIR "/.backlog/loopback2", &st_loopback2)) {
		bbs_error("stat failed: %s\n", strerror(errno));
		goto cleanup;
	} else if (stat(TEST_NEWS_DIR "/.backlog/loopback3", &st_loopback3)) {
		bbs_error("stat failed: %s\n", strerror(errno));
		goto cleanup;
	} else if (stat(TEST_NEWS_DIR "/.backlog/queueonly", &st_queueonly)) {
		bbs_error("stat failed: %s\n", strerror(errno));
		goto cleanup;
	} else if (stat(TEST_NEWS_DIR "/.backlog/queueflush", &st_queueflush)) {
		bbs_error("stat failed: %s\n", strerror(errno));
		goto cleanup;
	}

	bbs_test_assert_long_equals(0L, st_loopback1.st_size);
	bbs_test_assert_long_equals(67L, st_loopback2.st_size); /* Actual size was verified experimentally and doesn't matter, we just need it to be > 0 */
	bbs_test_assert_long_equals(0L, st_loopback3.st_size);
	bbs_test_assert_long_equals(67L, st_queueonly.st_size); /* All articles to this site are queued (and not flushed during the tests) */
	bbs_test_assert_long_equals(0L, st_queueflush.st_size); /* Even though this site has identical configuration to the previous one, backlog should've been cleared by explicit flush */

	return 0;

cleanup:
	return -1;
}

TEST_MODULE_INFO_POST("NNTP Transit Tests");
