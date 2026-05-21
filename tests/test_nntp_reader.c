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

#include "netnews.h"

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_load_module("net_nntp.so");
	test_load_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("mod_sysop.so"); /* For creating newsgroups */

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
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
	NEW_NEWSGROUP(sockfd, "misc.crossposts", "A miscellaneous group of crossposts", "Sysop", "y");

	NEW_NEWSGROUP(sockfd, "test.moderated", "A moderated group", "Sysop", "m");
	NEW_NEWSGROUP(sockfd, "test.closed", "A closed group", "Sysop", "x");
	NEW_NEWSGROUP(sockfd, "test.junk", "A junk group", "Sysop", "j");
	NEW_NEWSGROUP(sockfd, "test.nolocal", "A nolocal group", "Sysop", "n");
	NEW_NEWSGROUP(sockfd, "test.aliased", "An aliased group", "Sysop", "=misc.test");

	NEW_NEWSGROUP(sockfd, "local.restricted", "A local-only group", "Sysop", "y");

	close(sockfd);
	return 0;

cleanup:
	return -1; /* No need to close_if(sockfd) first, the only failure path is from REQUIRE_FD in OPEN_CLI_SOCKET */
}

static int run(void)
{
	const char *s;
	char *xfield, *xfields, *xmsgid;
	char xoverresp[512];
	char sizebuf[512];
	int expectedsize;
	int client1 = -1, client3 = -1;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	client1 = test_make_socket(119);
	REQUIRE_FD(client1);

	/* Initial connection */
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_BANNER_POST) " " TEST_NEWS_HOSTNAME);
	SWRITE(client1, "CAPABILITIES\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_INFO_CAPABILITIES);
	CLIENT_EXPECT_EVENTUALLY(client1, "POST");

	/* Posting without logging in should fail */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_FAIL_AUTH_NEEDED);

	/* Log in now */
	SWRITE(client1, "AUTHINFO USER " TEST_USER "@" TEST_HOSTNAME "\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_CONT_AUTHINFO);
	SWRITE(client1, "AUTHINFO PASS " TEST_PASS "\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_AUTHINFO);

	/* LISTGROUP without arguments should fail since no group is selected yet */
	SWRITE(client1, "LISTGROUP\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_NO_GROUP);

	SWRITE(client1, "HELP\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "." ENDL);
	SWRITE(client1, "DATE\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_INFO_DATE) " 2"); /* This test will work until the year 3000... good enough? */
	SWRITE(client1, "NEWGROUPS\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_ERR_SYNTAX);
	SWRITE(client1, "NEWGROUPS 260109 123059\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test");
	SWRITE(client1, "NEWGROUPS 20260109 123059\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test");
	SWRITE(client1, "NEWGROUPS 20260109 123059 GMT\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test");
	SWRITE(client1, "NEWGROUPS 20260109 123059 GMT\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "." ENDL); /* 231 response with several groups */
	SWRITE(client1, "NEWGROUPS 30000109 123059 GMT\r\n"); /* Some date far in the future */
	CLIENT_EXPECT_CODE(client1, NNTP_OK_NEWGROUPS);
	CLIENT_EXPECT(client1, "." ENDL);

	SWRITE(client1, "NEWNEWS * 19990101 123059 GMT\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_NEWNEWS);
	CLIENT_EXPECT(client1, "." ENDL); /* no articles yet, so no new news */

	/* Try posting an article under an unauthorized identity */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL_UNAUTHORIZED, "misc.test", NNTP_FAIL_POST_REJECT);

	/* Ensure the article wasn't accepted and stored */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_NO_GROUP); /* No group currently selected */
	GROUP_EXPECT(client1, "misc.test", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0); /* Select a group. Group is empty and this server responds with all 0s since it has never had articles */

	/* Attempts to fetch nonexistent articles should fail */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);

	/* Try again with an authorized identity */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test");

	/* Try to a non-existent group */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "misc.nonexistent", NNTP_FAIL_POST_REJECT);

	/* Try querying all the newsgroups */
	SWRITE(client1, "LIST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_LIST);
	/* Should be sorted, so misc.empty should be in the first line. */
	CLIENT_EXPECT(client1, "misc.empty 0 " XSTR(ALWAYS_EMPTY_LOW_WATERMARK) " y"); /* Don't also wait for misc.test, etc. since it's probably part of the same read() output and we don't chunk per line */

	/* Ask for different LIST variants */
	SWRITE(client1, "LIST ACTIVE\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_LIST);
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test 1 1 y"); /* Should appear last alphabetically */

	SWRITE(client1, "LIST COUNTS\r\n");
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_OK_LIST);
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test 1 1 1 y"); /* Should appear last alphabetically */

	SWRITE(client1, "LIST ACTIVE.TIMES *test\r\n"); /* specify wildmat that will only match one group */
	CLIENT_EXPECT_CODE(client1, NNTP_OK_LIST);
	CLIENT_EXPECT(client1, "Sysop");

	SWRITE(client1, "LIST NEWSGROUPS\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_LIST);
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test\tA miscellaneous test group");

	SWRITE(client1, "LIST DISTRIB.PATS\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_LIST);
	CLIENT_EXPECT_EVENTUALLY(client1, "local.*");

	SWRITE(client1, "LIST DISTRIBUTIONS\r\n");
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_OK_LIST);
	CLIENT_EXPECT_EVENTUALLY(client1, "local\t");

	SWRITE(client1, "LIST MODERATORS\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "*:newsmoderator");

	SWRITE(client1, "LIST MOTD\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "that happens to be multiline.");

	SWRITE(client1, "LIST SUBSCRIPTIONS\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test");

	/* Try reading that article: it should now exist. */
	GROUP_EXPECT(client1, "misc.test", 1, 1, 1);
	SWRITE(client1, "HEAD 1\r\n");
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_OK_HEAD);
	CLIENT_EXPECT(client1, TEST_EMAIL); /* Our email should be in the response data */

	SWRITE(client1, "NEWNEWS misc.* 29990101 123059 GMT\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_NEWNEWS);
	CLIENT_EXPECT(client1, "."); /* No articles newer than the provided timestamp */

	SWRITE(client1, "NEWNEWS misc.* 19990101 123059 GMT\r\n"); /* Repeat, but now it should include the article */
	CLIENT_EXPECT_EVENTUALLY(client1, TEST_NEWS_HOSTNAME ">"); /* Should have some message ID */

	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ".\r\n");
	SWRITE(client1, "STAT 1\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_STAT);

	/* No previous */
	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_PREV);

	/* No next */
	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_NEXT);

	/* Post again, using a different From identity that is an alias of our mailbox,
	 * so we should be allowed to post using it. */
	POST_ARTICLE_TO_GROUP(client1, "nntpalias@" TEST_HOSTNAME, "misc.test");

	SWRITE(client1, "LIST ACTIVE misc.test\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_LIST);
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test 2 1 y");

	/* Delete articles and confirm LIST ACTIVE and GROUP report what we expect for low, high, and count
	 * We start out with two articles, 1 and 2. */
	DELETE_ARTICLE("misc.test", 1);
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 2, 2, 1);
	DELETE_ARTICLE("misc.test", 2);
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", EMPTY_LOW_WATERMARK(3), EMPTY_HIGH_WATERMARK(2), 0);

	/* Post and delete articles to ensure the water marks are always correct */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 3 */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 3, 3, 1);
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 4 */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 3, 4, 2);
	DELETE_ARTICLE("misc.test", 4); /* Delete the newest article */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 3, 3, 1); /* High water mark should decrease */
	DELETE_ARTICLE("misc.test", 3); /* Delete the remaining article */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", EMPTY_LOW_WATERMARK(5), EMPTY_HIGH_WATERMARK(4), 0); /* Low water mark should jump up as high as is legal if MAXIMIZE_LOW_WATERMARK is defined */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 5 */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 5, 5, 1);
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 5 */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 5, 6, 2);
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 7 */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 5, 7, 3);
	DELETE_ARTICLE("misc.test", 6); /* Delete an article in the middle */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 5, 7, 2); /* Water marks should stay the same, but count should update */
	DELETE_ARTICLE("misc.test", 6); /* Delete the same article again, nothing should change */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 5, 7, 2);
	DELETE_ARTICLE("misc.test", 7);
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 5, 5, 1);
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 8 */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 5, 8, 2);
	DELETE_ARTICLE("misc.test", 5);
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.test", 8, 8, 1);

	/* Test LAST and NEXT more exhaustively
	 * The GROUP command that was run last would have made "8" the current article. */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 9 */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 10 */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 11 */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 12 */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test"); /* Post article 13 */

	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_PREV);

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 9");

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 10");

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 11");

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 12");

	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 11");

	SWRITE(client1, "XOVER 11\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, TEST_EMAIL);

	DELETE_ARTICLE("misc.test", 10);

	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 9"); /* Should jump right back to 9 */

	SWRITE(client1, "HEAD\r\n"); /* HEAD 9 (without args) */
	CLIENT_EXPECT_EVENTUALLY(client1, "." ENDL);

	/* Article doesn't exist anymore, all these commands should fail: */
	SWRITE(client1, "XOVER 10\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_INVALID); /* Article shouldn't be in overview anymore */
	SWRITE(client1, "ARTICLE 10\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);
	SWRITE(client1, "HEAD 10\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);
	SWRITE(client1, "BODY 10\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);
	SWRITE(client1, "STAT 10\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);

	/* Check format of overview */
	SWRITE(client1, "LIST OVERVIEW.FMT\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "Xref:full"); /* should be near the end */

	SWRITE(client1, "LIST HEADERS\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "Xref" ENDL);
	SWRITE(client1, "LIST HEADERS MSGID\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "Xref" ENDL);

	SWRITE(client1, "XOVER 9\r\n");
	/* Ensure overview for remaining articles is still intact
	 * Save the response into a custom buffer so we can use it later. */
	if (test_client_expect_eventually_buf(client1, SEC_MS(2), TEST_EMAIL, __LINE__, xoverresp, sizeof(xoverresp))) {
		goto cleanup;
	}

	/* Request articles by article number. This should also change the current article number. */
	SWRITE(client1, "BODY 13\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_BODY);
	CLIENT_EXPECT(client1, "This is just a test article");
	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 12");
	SWRITE(client1, "STAT 13\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 13");
	SWRITE(client1, "STAT\r\n"); /* Repeat without arguments, for current article (13) */
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 13");
	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, "12");

	/* We already did XOVER 9 above, extract the Message-ID from that.
	 * While we're here, check the fields in the XOVER response are as we'd expect */
	xfields = xoverresp;
	xfield = strsep(&xfields, "\t"); /* Field 1 = article number */
	TEST_EXPECT_STRING(xfield, "9");
	xfield = strsep(&xfields, "\t"); /* Field 2 = Subject */
	TEST_EXPECT_STRING(xfield, "I am just a test article");
	xfield = strsep(&xfields, "\t"); /* Field 3 = From */
	TEST_EXPECT_STRING(xfield, "Demo User");
	xfield = strsep(&xfields, "\t"); /* Field 4 = Date */
	TEST_EXPECT_STRING(xfield, ","); /* Date varies, so don't test that */
	xmsgid = strsep(&xfields, "\t"); /* Field 5 = Message-ID - we didn't know what this was, since the server assigns it, so save it */
	xfield = strsep(&xfields, "\t"); /* Field 6 = References - this is empty */
	TEST_EXPECT(strlen_zero(xfield));
	xfield = strsep(&xfields, "\t"); /* Field 7 = Bytes */
	TEST_EXPECT(atoi(xfield) > 50); /* Has to be at least 50 bytes! Probably more */
	xfield = strsep(&xfields, "\t"); /* Field 8 = Lines */
	TEST_EXPECT(atoi(xfield) == 1);
	xfield = strsep(&xfields, "\t"); /* Field 9 = Xref */
	TEST_EXPECT_STRING(xfield, "Xref: news.example.com misc.test:9");

	/* Request article by Message-ID in the current group */
	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_ARTICLE) " 9 <"); /* We know this is article number 9 in the current group, and although the RFC allows this to be 0, it should fill in the article number in this case */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article."); /* Read the rest of the response */

	FMT_WRITE(client1, "STAT %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 9 <");

	/* Change groups and re-issue the command, the article number should be 0 since the article isn't in that group */
	GROUP_EXPECT(client1, "misc.empty", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0);
	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_ARTICLE)  " 0 <");
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article."); /* Read the rest of the response */

	FMT_WRITE(client1, "STAT %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_STAT) " 0 <");

	/* Test behavior of cross-posted articles */
	GROUP_EXPECT(client1, "misc.test", 8, 13, 5); /* 11 was deleted, rest are still there */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test,misc.test"); /* Group duplicated should only result in one post to it */
	GROUP_EXPECT(client1, "misc.test", 8, 14, 6);

	GROUP_EXPECT(client1, "misc.crossposts", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0);
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test,misc.crossposts");
	GROUP_EXPECT(client1, "misc.crossposts", 1, 1, 1);
	GROUP_EXPECT(client1, "misc.test", 8, 15, 7);

	/* NEWNEWS should contain articles in the response (many articles, but we don't have a good way to test for that here)
	 * At least the last message-ID we knew about should be present */
	SWRITE(client1, "NEWNEWS * 19990101 123059 GMT\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, xmsgid);

	SWRITE(client1, "LISTGROUP\r\n"); /* List articles for current group */
	CLIENT_EXPECT_EVENTUALLY(client1, "13"); /* This is one of them */

	SWRITE(client1, "LISTGROUP misc.test\r\n"); /* Repeat for same group, explicitly specified this time */
	CLIENT_EXPECT_EVENTUALLY(client1, "12");

	/* Ensure Xref header is correct: */
	SWRITE(client1, "HEAD 15\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "Xref: news.example.com misc.test:15 misc.crossposts:1");

	/* Use OVER to get overview for a range of articles */
	SWRITE(client1, "OVER <nonexistent.message>\r\n");
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_FAIL_MSGID_NOTFOUND);

	SWRITE(client1, "HDR Subject <nonexistent.message>\r\n");
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_FAIL_MSGID_NOTFOUND);

	SWRITE(client1, "OVER 13-12\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);

	FMT_WRITE(client1, "OVER %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "9\t");

	FMT_WRITE(client1, "HDR Content-Type %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_ERR_UNAVAILABLE); /* Not supported for HDR */

	FMT_WRITE(client1, "HDR :bytes %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE(client1, NNTP_OK_HDR);
	FMT_WRITE(client1, "HDR Subject %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_OK_HDR);
	FMT_WRITE(client1, "XHDR :bytes %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_ERR_UNAVAILABLE); /* XHDR doesn't support metadata */
	FMT_WRITE(client1, "XHDR Subject %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE(client1, NNTP_OK_HEAD); /* Both HDR and XHDR should work, but response codes are different */
	FMT_WRITE(client1, "XPAT :bytes %s 1\r\n", xmsgid);
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_ERR_UNAVAILABLE);
	FMT_WRITE(client1, "XPAT Subject %s *test art*\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "test article");
	SWRITE(client1, "XPAT Subject 10-12 *test art*\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "12 I am just a test article" ENDL);
	SWRITE(client1, "XPAT Subject 10-12 test art\r\n");
	CLIENT_EXPECT_CODE_EVENTUALLY(client1, NNTP_OK_HEAD);
	CLIENT_EXPECT(client1, "." ENDL); /* No matches */

	/* The articles don't have a References header (but should still appear in HDR response) */
	FMT_WRITE(client1, "HDR References 8-15\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "11 " ENDL);

	FMT_WRITE(client1, "HDR Subject %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "9 I am just a test article" ENDL);

	SWRITE(client1, "HDR Subject 8-9\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "9 I am just a test article" ENDL);

	SWRITE(client1, "OVER 13-\r\n"); /* 13-15 */
	CLIENT_EXPECT_EVENTUALLY(client1, "15\t");

	/* Ask for the cross-posted article by article ID */
	SWRITE(client1, "XOVER 15\r\n");
	if (test_client_expect_eventually_buf(client1, SEC_MS(2), TEST_EMAIL, __LINE__, xoverresp, sizeof(xoverresp))) {
		goto cleanup;
	}
	xfields = xoverresp;
	xfield = strsep(&xfields, "\t"); /* Field 1 = article number */
	TEST_EXPECT_STRING(xfield, "15");
	xfield = strsep(&xfields, "\t"); /* Field 2 = Subject */
	xfield = strsep(&xfields, "\t"); /* Field 3 = From */
	xfield = strsep(&xfields, "\t"); /* Field 4 = Date */
	xmsgid = strsep(&xfields, "\t"); /* Field 5 = Message-ID */

	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_ARTICLE) " 15 <"); /* The server will say it's article 15 because the first link created was in this group */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	GROUP_EXPECT(client1, "misc.crossposts", 1, 1, 1); /* Switch groups to misc.crossposts */
	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_ARTICLE) " 1 <"); /* The same article is article 1 in this group (not required by the RFC, could've returned 0, but the server tries to be as helpful as possible) */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	SWRITE(client1, "ARTICLE 1\r\n"); /* Should work with article number as well */
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_ARTICLE) " 1 <");
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	GROUP_EXPECT(client1, "misc.empty", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0); /* Switch groups to misc.crossposts */
	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_ARTICLE) " 0 <"); /* The article isn't in this group, so article number MUST be 0 */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	FMT_WRITE(client1, "OVER %s\r\n", xmsgid); /* Ditto with OVER MSGID */
	CLIENT_EXPECT_EVENTUALLY(client1, "0\t");

	/* Now, delete the article from one group. It should still remain in the other. */
	DELETE_ARTICLE("misc.test", 15);
	GROUP_EXPECT(client1, "misc.crossposts", 1, 1, 1); /* Article should still be here! */

	/* Actually request the article to make sure we still have it and not just the metadata */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT(client1, XSTR(NNTP_OK_ARTICLE) " 1 <");
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	/* But article shouldn't exist here anymore, at least if we request it by article number */
	GROUP_EXPECT(client1, "misc.test", 8, 14, 6);
	SWRITE(client1, "ARTICLE 15\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);

	/* Now delete it in the other group as well */
	DELETE_ARTICLE("misc.crossposts", 1);
	GROUP_EXPECT(client1, "misc.crossposts", EMPTY_LOW_WATERMARK(2), EMPTY_HIGH_WATERMARK(1), 0);
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_ARTNUM_NOTFOUND);

	/* Test dot-stuffing */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test");
	GROUP_EXPECT(client1, "misc.test", 8, 16, 7);
	SWRITE(client1, "HDR :bytes 16\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_OK_HDR);
	/* We don't know exactly how many bytes are going to be in the message, but extract it */
	if (test_client_expect_buf(client1, SEC_MS(2), "16 ", __LINE__, sizebuf, sizeof(sizebuf))) {
		goto cleanup;
	}

	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_CONT_POST);
	s = "Newsgroups: misc.test" ENDL
		"From: \"Demo User\" <" TEST_EMAIL ">" ENDL
		NNTP_DEFAULT_ARTICLE_BASE
		/* These lines are new (and all dot-stuffed): */
		".." ENDL
		".." ENDL
		".." ENDL
		".." ENDL
		".." ENDL
		".." ENDL
		"." ENDL; /* EOM */
	write(client1, s, strlen(s));
	CLIENT_EXPECT_CODE(client1, NNTP_OK_POST);
	GROUP_EXPECT(client1, "misc.test", 8, 17, 8);
	SWRITE(client1, "HDR :bytes 17\r\n");
	/* Same as previous message but with 6 extra lines that are dot-stuffed. 6 lines, 3 bytes each (. CR LF, but not including leading dot for dot-stuffing).
	 * So, +18 bytes. */
	CLIENT_EXPECT_CODE(client1, NNTP_OK_HDR);
	expectedsize = atoi(sizebuf + STRLEN("16 ")) + 18;
	if (test_client_expect_buf(client1, SEC_MS(2), "17 ", __LINE__, sizebuf, sizeof(sizebuf))) {
		goto cleanup;
	}
	if (atoi(sizebuf + STRLEN("17 ")) != expectedsize) {
		bbs_error("Expected %d bytes but got %s\n", expectedsize, sizebuf + STRLEN("17 "));
		goto cleanup;
	}

	/* When requesting the article back, the lines with a '.' by themselves must be dot-stuffed back again */
	SWRITE(client1, "BODY 17\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ".." ENDL);

	/* Test messages with multi-line headers */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_OK_POST,
		"References: <ancestor1.foo>" ENDL
		"\t<ancestor2.foo> <ancestor3.foo>" ENDL
		" <ancestor4.foo>" ENDL
	);

	/* Ensure that we unfolded the multi-line References header and saved it properly: */
	SWRITE(client1, "HDR References 18\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "18 <ancestor1.foo> <ancestor2.foo> <ancestor3.foo> <ancestor4.foo>" ENDL);

	/* Test that the client-provided Xref header is rejected */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Xref: misc.example.org misc.test:321" ENDL
	);

	/* See if the correct Distribution header gets added (and we also include our own Message-ID) */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.crossposts", NNTP_OK_POST,
		"Message-ID: <unique.messageid>" ENDL
		"References: <ancestor1.foo>" ENDL
		"\t<ancestor2.foo> <ancestor3.foo>" ENDL
		" <ancestor4.foo>" ENDL
	);

	/* Our Message-ID should have been preserved */
	SWRITE(client1, "HDR Message-ID <unique.messageid>\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "0 <unique.messageid>" ENDL);

	/* Check that the correct Distribution header was added */
	SWRITE(client1, "HEAD <unique.messageid>\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "Distribution: cp4" ENDL);

	/* Check that the Organization header was added */
	SWRITE(client1, "HEAD <unique.messageid>\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "Organization: Society of BBS Sysops" ENDL);

	/* Repeat, should be rejected since server should reject message with duplicate Message-ID, even from a reader */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.crossposts", NNTP_FAIL_POST_REJECT,
		"Message-ID: <unique.messageid>" ENDL
		"References: <ancestor1.foo>" ENDL
		"\t<ancestor2.foo> <ancestor3.foo>" ENDL
		" <ancestor4.foo>" ENDL
		"Xref: news.example.net misc.test:12" ENDL
	);

	/* Inject message without Date header, it should get added for us.
	 * We provide our own Organization, which should be preserved.
	 * Additionally, Injection-Date header should get added if not already present and if either Date or Message-ID is missing */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_CONT_POST);
	s = "From: \"Demo User\" <" TEST_EMAIL ">" ENDL
		"Organization: My Organization" ENDL
		"Newsgroups: misc.test" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This article did not originally have a Date header." ENDL
		"." ENDL; \
	write(client1, s, strlen(s));
	CLIENT_EXPECT_CODE(client1, NNTP_OK_POST);

	GROUP_EXPECT(client1, "misc.test", 8, 19, 10);
	SWRITE(client1, "HEAD 19\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ENDL "Date: ");
	SWRITE(client1, "HEAD 19\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ENDL "Injection-Date: ");
	SWRITE(client1, "HEAD 19\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ENDL "Organization: My Organization");

	/* But if we have a Date header and it's invalid, should get rejected */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_CONT_POST);
	s = "From: \"Demo User\" <" TEST_EMAIL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Date: foobar" ENDL
		"Subject: I am just a test article" ENDL
		ENDL
		"This article did not originally have a Date header." ENDL
		"." ENDL; \
	write(client1, s, strlen(s));
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_POST_REJECT);

	/* Articles dated too far in the future should get rejected */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_CONT_POST);
	s = "From: \"Demo User\" <" TEST_EMAIL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Date: Thu, 31 Dec 2099 05:33:29 -0700" ENDL \
		"Subject: I am just a test article" ENDL
		ENDL
		"This article is too far in the future." ENDL
		"." ENDL; \
	write(client1, s, strlen(s));
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_POST_REJECT);

	/* Same with articles too far in the past, they should get rejected
	 * (normally, this would be a small value, but to allow the tests to age well
	 *  without maintenance, maxacceptage has been set to a very large value,
	 *  so we need to use an old enough date.) */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_CODE(client1, NNTP_CONT_POST);
	s = "From: \"Demo User\" <" TEST_EMAIL ">" ENDL
		"Newsgroups: misc.test" ENDL
		"Date: Sat, 28 Feb 1970 05:33:29 -0700" ENDL \
		"Subject: I am just a test article" ENDL
		ENDL
		"This article is too far in the past." ENDL
		"." ENDL; \
	write(client1, s, strlen(s));
	CLIENT_EXPECT_CODE(client1, NNTP_FAIL_POST_REJECT);

	/* Path is allowed as long as not yet posted */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_OK_POST,
		"Path: foo!client!not-for-mail" ENDL
	);
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_OK_POST,
		"Path: POSTED!not-for-mail" ENDL
	);
	GROUP_EXPECT(client1, "misc.test", 8, 21, 12);
	SWRITE(client1, "HEAD 21\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "!.POSTED!"); /* .POSTED should've been added */

	/* If article already has .POSTED in its path, should get rejected */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Path: foo\r\n\t!.POSTED" ENDL
	);
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Path: .POSTED!not-for-mail" ENDL
	);
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Path: foo!.POSTED" ENDL
	);
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Path: foo!.POSTED!not-for-mail" ENDL
	);
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Path: foo!.POSTED.client.local!not-for-mail" ENDL
	);
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Path: foo!something.POSTED!not-for-mail" ENDL
	);

	/* Try some posts that should be rejected */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "misc.restricted", NNTP_FAIL_POST_AUTH); /* Disallowed by post wildmat */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "test.closed", NNTP_FAIL_POST_REJECT); /* Denied by 'x' status */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "test.junk", NNTP_FAIL_POST_REJECT); /* Denied by 'j' status */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "test.nolocal", NNTP_FAIL_POST_REJECT); /* Denied by 'n' status */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "test.aliased", NNTP_FAIL_POST_REJECT); /* Denied by '=' status */
	GROUP_EXPECT(client1, "test.moderated", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", -1); /* doesn't exist yet */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "test.moderated"); /* Will be accepted but not posted to the group, but should appear in "moderator's" inbox */
	GROUP_EXPECT(client1, "test.moderated", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);

	/* Can't add "Approved" headers to messages */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Approved: moderator@news.example.com" ENDL
	);

	/* Can't add "Control" headers to messages */
	POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(client1, TEST_EMAIL, "misc.test", NNTP_FAIL_POST_REJECT,
		"Control: cmsg newgroup foo.baz" ENDL
	);

	/* User 3 isn't allowed to do anything, since he has no matching ACL */
	client3 = test_make_socket(119);
	REQUIRE_FD(client3);
	CLIENT_EXPECT(client3, XSTR(NNTP_OK_BANNER_POST) " " TEST_NEWS_HOSTNAME);

	SWRITE(client3, "AUTHINFO USER " TEST_USER3 "@" TEST_NEWS_HOSTNAME "\r\n");
	CLIENT_EXPECT_CODE(client3, NNTP_CONT_AUTHINFO);
	SWRITE(client3, "AUTHINFO PASS " TEST_PASS3 "\r\n");
	CLIENT_EXPECT_CODE(client3, NNTP_OK_AUTHINFO);

	SWRITE(client3, "LIST ACTIVE misc.test\r\n");
	CLIENT_EXPECT_CODE(client3, NNTP_OK_LIST);
	CLIENT_EXPECT(client3, ".");

	SWRITE(client3, "GROUP misc.test\r\n");
	CLIENT_EXPECT_CODE(client3, NNTP_ERR_ACCESS);

	/* Permission should be denied if performing operations directly with Message-ID since not authorized for containing group */
	FMT_WRITE(client3, "OVER %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE_EVENTUALLY(client3, NNTP_FAIL_MSGID_NOTFOUND);
	FMT_WRITE(client3, "STAT %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE_EVENTUALLY(client3, NNTP_FAIL_MSGID_NOTFOUND);
	FMT_WRITE(client3, "HDR Subject %s\r\n", xmsgid);
	CLIENT_EXPECT_CODE_EVENTUALLY(client3, NNTP_FAIL_MSGID_NOTFOUND);

	/* Lastly, "spoof" an almost full group so we can test its behavior.
	 * Here, we use misc.empty since it has thus far been empty so we know what to replace. */

	/* XXX To do this, we directly modify the active file at runtime, which
	 * which we can do at the moment because it isn't open persistently
	 * (and this will probably change in the future, and this will need to be updated;
	 * likely by adding an article to the group with an explicitly high article number,
	 * then deleting it.) */
	system("sed -i 's/misc.empty\t0000000000\t0000000000\t0000000000/misc.empty\t2147483645\t2147483644\t2147483645/' " TEST_NEWS_DIR "/active");

	/* Now, fill up the group and check that the water marks behave correctly. */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.empty", EMPTY_LOW_WATERMARK(2147483646), EMPTY_HIGH_WATERMARK(2147483645), 0);
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.empty");
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.empty", 2147483646, 2147483646, 1);
	DELETE_ARTICLE("misc.empty", 2147483646);
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.empty", EMPTY_LOW_WATERMARK(2147483647), EMPTY_HIGH_WATERMARK(2147483646), 0);
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.empty");
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.empty", 2147483647, 2147483647, 1);
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "misc.empty", 441); /* Henceforth, any further posting should fail since group is now full */
	DELETE_ARTICLE("misc.empty", 2147483647);
	/* This response doesn't vary, regardless of compilation settings for low water mark.
	 * But if MAXIMIZE_LOW_WATERMARK is defined, this check ensures we never exceed NNTP_MAX_ARTICLE_NUMBER (2147483647) in our response (as that would overflow). */
	GROUP_AND_LIST_ACTIVE_EXPECT(client1, "misc.empty", 2147483647, 2147483646, 0);

	res = 0;

cleanup:
	close_if(client1);
	close_if(client3);
	return res;
}

TEST_MODULE_INFO_STANDARD("NNTP Reader Tests");
