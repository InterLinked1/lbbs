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

/* Use the same definitions (or lack thereof) of MAXIMIZE_LOW_WATERMARK and EMPTY_LOW_WATERMARK_IS_ZERO from nntp.h
 * There's nothing else we need from this header file (besides NNTP_MAX_ARTICLE_NUMBER); this just avoids having to duplicate the macro definitions here.
 * tests/Makefile ensures we get recompiled if nntp.h changes, since it's included here. */
#include "../nets/net_nntp/nntp.h"

/* These macros are a bit tricky. The C preprocessor wasn't really designed to evaluate expression,
 * but we need to do that here BEFORE stringifying for the EXPECT macros.
 * This is a kludge to do that by having a "lookup table" of macros to do literal replacements.
 * Note that compilation will not fail if the required SUB1_X defines are not available;
 * however, the tests will as SUB1_X will appear in the expect search string literally, rather than the intended "evaluated" argument.
 * Ugly, but that way the "test logic" doesn't need to do any math at runtime. */
#ifndef MAXIMIZE_LOW_WATERMARK
#define SUB1(x) SUB1_##x
#define SUB1_1 0
#define SUB1_2 1
#define SUB1_3 2
#define SUB1_4 3
#define SUB1_5 4
#define SUB1_2147483645 2147483644
#define SUB1_2147483646 2147483645
#define SUB1_2147483647 2147483646
#endif

/* We start high and subtract, rather than start low and add, so we don't have to worry about exceeding the max article number */
#ifdef MAXIMIZE_LOW_WATERMARK
#define EMPTY_LOW_WATERMARK(nominal) nominal
#define EMPTY_HIGH_WATERMARK(nominal) nominal
#else
/* Subtract 1 from whatever would have been the expected value if MAXIMIZE_LOW_WATERMARK were defined */
#define EMPTY_LOW_WATERMARK(nominal) SUB1(nominal)
#define EMPTY_HIGH_WATERMARK(nominal) SUB1(nominal)
#endif

#ifdef EMPTY_LOW_WATERMARK_IS_ZERO
#define ALWAYS_EMPTY_LOW_WATERMARK 0
#else
#define ALWAYS_EMPTY_LOW_WATERMARK 1
#endif

#define DELETE_ARTICLE(group, article) TEST_CLI_COMMAND("news delarticle " group " " #article)

/* We have to use XSTR instead of just #var since two levels of macros are required to eval the macro before converting to string */
#define LIST_ACTIVE_EXPECT(fd, group, low, high) \
	SWRITE(fd, "LIST ACTIVE " group ENDL); \
	CLIENT_EXPECT_EVENTUALLY(fd, group " " XSTR(high) " " XSTR(low));

#define GROUP_EXPECT(fd, group, low, high, count) \
	SWRITE(fd, "GROUP " group ENDL); \
	CLIENT_EXPECT(fd, "211 " #count " " XSTR(low) " " XSTR(high) " " group)

#define GROUP_AND_LIST_ACTIVE_EXPECT(fd, group, low, high, count) \
	GROUP_EXPECT(fd, group, low, high, count); \
	LIST_ACTIVE_EXPECT(fd, group, low, high);

#define POST_ARTICLE_TO_GROUP_RESPONSE(fd, email, group, respcode) \
	SWRITE(client1, "POST\r\n"); \
	CLIENT_EXPECT(client1, "340"); \
	POST_NEWS_ARTICLE(s, client1, email, group); \
	CLIENT_EXPECT(client1, #respcode);

#define POST_ARTICLE_TO_GROUP(fd, email, group) POST_ARTICLE_TO_GROUP_RESPONSE(fd, email, group, 240)

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
	NEW_NEWSGROUP(sockfd, "misc.crossposts", "A miscellaneous group of crossposts", "Sysop", "y");

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
	int client1 = -1, client3 = -1;
	int res = -1;

	if (create_groups()) {
		return -1;
	}

	client1 = test_make_socket(119);
	REQUIRE_FD(client1);

	/* Initial connection */
	CLIENT_EXPECT(client1, "200 " TEST_NEWS_HOSTNAME);
	SWRITE(client1, "CAPABILITIES\r\n");
	CLIENT_EXPECT(client1, "101");
	CLIENT_EXPECT_EVENTUALLY(client1, "POST");

	/* Posting without logging in should fail */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "480");

	/* Log in now */
	SWRITE(client1, "AUTHINFO USER " TEST_USER "@" TEST_HOSTNAME "\r\n");
	CLIENT_EXPECT(client1, "381");
	SWRITE(client1, "AUTHINFO PASS " TEST_PASS "\r\n");
	CLIENT_EXPECT(client1, "281");

	/* LISTGROUP without arguments should fail since no group is selected yet */
	SWRITE(client1, "LISTGROUP\r\n");
	CLIENT_EXPECT(client1, "412");

	SWRITE(client1, "HELP\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "." ENDL);
	SWRITE(client1, "DATE\r\n");
	CLIENT_EXPECT(client1, "111 2"); /* This test will work until the year 3000... good enough? */
	SWRITE(client1, "NEWGROUPS\r\n");
	CLIENT_EXPECT(client1, "501");
	SWRITE(client1, "NEWGROUPS 260109 123059\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test");
	SWRITE(client1, "NEWGROUPS 20260109 123059\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test");
	SWRITE(client1, "NEWGROUPS 20260109 123059 GMT\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test");
	SWRITE(client1, "NEWGROUPS 20260109 123059 GMT\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "." ENDL); /* 231 response with several groups */
	SWRITE(client1, "NEWGROUPS 30000109 123059 GMT\r\n"); /* Some date far in the future */
	CLIENT_EXPECT(client1, "231");
	CLIENT_EXPECT(client1, "." ENDL);

	SWRITE(client1, "NEWNEWS * 19990101 123059 GMT\r\n");
	CLIENT_EXPECT(client1, "230");
	CLIENT_EXPECT(client1, "." ENDL); /* no articles yet, so no new news */

	/* Try posting an article under an unauthorized identity */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL_UNAUTHORIZED, "misc.test", 441);

	/* Ensure the article wasn't accepted and stored */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT(client1, "412"); /* No group currently selected */
	GROUP_EXPECT(client1, "misc.test", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0); /* Select a group. Group is empty and this server responds with all 0s since it has never had articles */

	/* Attempts to fetch nonexistent articles should fail */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT(client1, "423");

	/* Try again with an authorized identity */
	POST_ARTICLE_TO_GROUP(client1, TEST_EMAIL, "misc.test");

	/* Try to a non-existent group */
	POST_ARTICLE_TO_GROUP_RESPONSE(client1, TEST_EMAIL, "misc.nonexistent", 441);

	/* Try querying all the newsgroups */
	SWRITE(client1, "LIST\r\n");
	CLIENT_EXPECT(client1, "215");
	/* Should be sorted, so misc.empty should be in the first line. */
	CLIENT_EXPECT(client1, "misc.empty 0 " XSTR(ALWAYS_EMPTY_LOW_WATERMARK) " y"); /* Don't also wait for misc.test, etc. since it's probably part of the same read() output and we don't chunk per line */

	/* Ask for different LIST variants */
	SWRITE(client1, "LIST ACTIVE\r\n");
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test 1 1 y"); /* Should appear last alphabetically */

	SWRITE(client1, "LIST ACTIVE.TIMES *test\r\n"); /* specify wildmat that will only match one group */
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT(client1, "Sysop");

	SWRITE(client1, "LIST NEWSGROUPS\r\n");
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT_EVENTUALLY(client1, "misc.test\tA miscellaneous test group");

	SWRITE(client1, "LIST DISTRIB.PATS\r\n");
	CLIENT_EXPECT(client1, "215");
	CLIENT_EXPECT_EVENTUALLY(client1, ".");

	/* Try reading that article: it should now exist. */
	GROUP_EXPECT(client1, "misc.test", 1, 1, 1);
	SWRITE(client1, "HEAD 1\r\n");
	CLIENT_EXPECT(client1, "221");
	CLIENT_EXPECT(client1, TEST_EMAIL); /* Our email should be in the response data */

	SWRITE(client1, "NEWNEWS misc.* 29990101 123059 GMT\r\n");
	CLIENT_EXPECT(client1, "230");
	CLIENT_EXPECT(client1, "."); /* No articles newer than the provided timestamp */

	SWRITE(client1, "NEWNEWS misc.* 19990101 123059 GMT\r\n"); /* Repeat, but now it should include the article */
	CLIENT_EXPECT_EVENTUALLY(client1, TEST_NEWS_HOSTNAME ">"); /* Should have some message ID */

	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ".\r\n");
	SWRITE(client1, "STAT 1\r\n");
	CLIENT_EXPECT(client1, "223");

	/* No previous */
	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, "422");

	/* No next */
	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, "421");

	/* Post again, using a different From identity that is an alias of our mailbox,
	 * so we should be allowed to post using it. */
	POST_ARTICLE_TO_GROUP(client1, "nntpalias@" TEST_HOSTNAME, "misc.test");

	SWRITE(client1, "LIST ACTIVE misc.test\r\n");
	CLIENT_EXPECT(client1, "215");
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
	CLIENT_EXPECT(client1, "422");

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, "223 9");

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, "223 10");

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, "223 11");

	SWRITE(client1, "NEXT\r\n");
	CLIENT_EXPECT(client1, "223 12");

	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, "223 11");

	SWRITE(client1, "XOVER 11\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, TEST_EMAIL);

	DELETE_ARTICLE("misc.test", 10);

	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, "223 9"); /* Should jump right back to 9 */

	SWRITE(client1, "HEAD\r\n"); /* HEAD 9 (without args) */
	CLIENT_EXPECT_EVENTUALLY(client1, "." ENDL);

	/* Article doesn't exist anymore, all these commands should fail: */
	SWRITE(client1, "XOVER 10\r\n");
	CLIENT_EXPECT(client1, "420"); /* Article shouldn't be in overview anymore */
	SWRITE(client1, "ARTICLE 10\r\n");
	CLIENT_EXPECT(client1, "423");
	SWRITE(client1, "HEAD 10\r\n");
	CLIENT_EXPECT(client1, "423");
	SWRITE(client1, "BODY 10\r\n");
	CLIENT_EXPECT(client1, "423");
	SWRITE(client1, "STAT 10\r\n");
	CLIENT_EXPECT(client1, "423");

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
	CLIENT_EXPECT(client1, "220");
	CLIENT_EXPECT(client1, "This is just a test article");
	SWRITE(client1, "LAST\r\n");
	CLIENT_EXPECT(client1, "12");
	SWRITE(client1, "STAT 13\r\n");
	CLIENT_EXPECT(client1, "223 13");
	SWRITE(client1, "STAT\r\n"); /* Repeat without arguments, for current article (13) */
	CLIENT_EXPECT(client1, "223 13");
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
	CLIENT_EXPECT(client1, "220 9 <"); /* We know this is article number 9 in the current group, and although the RFC allows this to be 0, it should fill in the article number in this case */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article."); /* Read the rest of the response */

	FMT_WRITE(client1, "STAT %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, "223 9 <");

	/* Change groups and re-issue the command, the article number should be 0 since the article isn't in that group */
	GROUP_EXPECT(client1, "misc.empty", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0);
	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, "220 0 <");
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article."); /* Read the rest of the response */

	FMT_WRITE(client1, "STAT %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, "223 0 <");

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
	CLIENT_EXPECT_EVENTUALLY(client1, "430");

	SWRITE(client1, "HDR Subject <nonexistent.message>\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "430");

	SWRITE(client1, "OVER 13-12\r\n");
	CLIENT_EXPECT(client1, "423");

	FMT_WRITE(client1, "OVER %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "9\t");

	FMT_WRITE(client1, "HDR Content-Type %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "503"); /* Not supported for HDR */

	FMT_WRITE(client1, "HDR :bytes %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, "225");
	FMT_WRITE(client1, "HDR Subject %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "225");
	FMT_WRITE(client1, "XHDR :bytes %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "503"); /* XHDR doesn't support metadata */
	FMT_WRITE(client1, "XHDR Subject %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, "221"); /* Both HDR and XHDR should work, but response codes are different */
	FMT_WRITE(client1, "XPAT :bytes %s 1\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "503");
	FMT_WRITE(client1, "XPAT Subject %s *test art*\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client1, "test article");
	SWRITE(client1, "XPAT Subject 10-12 *test art*\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "12 I am just a test article" ENDL);
	SWRITE(client1, "XPAT Subject 10-12 test art\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "221");
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
	CLIENT_EXPECT(client1, "220 15 <"); /* The server will say it's article 15 because the first link created was in this group */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	GROUP_EXPECT(client1, "misc.crossposts", 1, 1, 1); /* Switch groups to misc.crossposts */
	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, "220 1 <"); /* The same article is article 1 in this group (not required by the RFC, could've returned 0, but the server tries to be as helpful as possible) */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	SWRITE(client1, "ARTICLE 1\r\n"); /* Should work with article number as well */
	CLIENT_EXPECT(client1, "220 1 <");
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	GROUP_EXPECT(client1, "misc.empty", ALWAYS_EMPTY_LOW_WATERMARK, 0, 0); /* Switch groups to misc.crossposts */
	FMT_WRITE(client1, "ARTICLE %s\r\n", xmsgid);
	CLIENT_EXPECT(client1, "220 0 <"); /* The article isn't in this group, so article number MUST be 0 */
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	FMT_WRITE(client1, "OVER %s\r\n", xmsgid); /* Ditto with OVER MSGID */
	CLIENT_EXPECT_EVENTUALLY(client1, "0\t");

	/* Now, delete the article from one group. It should still remain in the other. */
	DELETE_ARTICLE("misc.test", 15);
	GROUP_EXPECT(client1, "misc.crossposts", 1, 1, 1); /* Article should still be here! */

	/* Actually request the article to make sure we still have it and not just the metadata */
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT(client1, "220 1 <");
	CLIENT_EXPECT_EVENTUALLY(client1, "This is just a test article.");

	/* But article shouldn't exist here anymore, at least if we request it by article number */
	GROUP_EXPECT(client1, "misc.test", 8, 14, 6);
	SWRITE(client1, "ARTICLE 15\r\n");
	CLIENT_EXPECT(client1, "423");

	/* Now delete it in the other group as well */
	DELETE_ARTICLE("misc.crossposts", 1);
	GROUP_EXPECT(client1, "misc.crossposts", EMPTY_LOW_WATERMARK(2), EMPTY_HIGH_WATERMARK(1), 0);
	SWRITE(client1, "ARTICLE 1\r\n");
	CLIENT_EXPECT(client1, "423");

	/* Test dot-stuffing */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "340");
	s = "From: \"Demo User\" <" TEST_EMAIL ">" ENDL \
		"Newsgroups: misc.test" ENDL \
		"Date: Thu, 21 May 1998 05:33:29 -0700" ENDL \
		"Subject: I am just a test article" ENDL \
		ENDL \
		"This article tests dot-stuffing." ENDL \
		"." ENDL; \
	write(client1, s, strlen(s));
	CLIENT_EXPECT(client1, "240");
	GROUP_EXPECT(client1, "misc.test", 8, 16, 7);
	SWRITE(client1, "HDR :bytes 16\r\n");
	CLIENT_EXPECT(client1, "225");
	CLIENT_EXPECT(client1, "16 216");

	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT(client1, "340");
	s = "From: \"Demo User\" <" TEST_EMAIL ">" ENDL \
		"Newsgroups: misc.test" ENDL \
		"Date: Thu, 21 May 1998 05:33:29 -0700" ENDL \
		"Subject: I am just a test article" ENDL \
		ENDL \
		"This article tests dot-stuffing." ENDL \

		/* These lines are new (and all dot-stuffed): */
		".." ENDL \
		".." ENDL \
		".." ENDL \
		".." ENDL \
		".." ENDL \
		".." ENDL \

		"." ENDL; \
	write(client1, s, strlen(s));
	CLIENT_EXPECT(client1, "240");
	GROUP_EXPECT(client1, "misc.test", 8, 17, 8);
	SWRITE(client1, "HDR :bytes 17\r\n");
	/* Same as previous message but with 6 extra lines that are dot-stuffed. 6 lines, 3 bytes each (. CR LF, but not including leading dot for dot-stuffing).
	 * So, +18 bytes. */
	CLIENT_EXPECT(client1, "225");
	CLIENT_EXPECT(client1, "17 234");

	/* When requesting the article back, the lines with a '.' by themselves must be dot-stuffed back again */
	SWRITE(client1, "BODY 17\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ".." ENDL);

	/* Try some things that should be denied by ACL */

	/* Can't post to misc.restricted */
	SWRITE(client1, "POST\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "340");
	POST_NEWS_ARTICLE(s, client1, TEST_EMAIL, "misc.restricted");
	CLIENT_EXPECT(client1, "440");

	/* User 3 isn't allowed to do anything, since he has no matching ACL */
	client3 = test_make_socket(119);
	REQUIRE_FD(client3);
	CLIENT_EXPECT(client3, "200 " TEST_NEWS_HOSTNAME);

	SWRITE(client3, "AUTHINFO USER " TEST_USER3 "@" TEST_NEWS_HOSTNAME "\r\n");
	CLIENT_EXPECT(client3, "381");
	SWRITE(client3, "AUTHINFO PASS " TEST_PASS3 "\r\n");
	CLIENT_EXPECT(client3, "281");

	SWRITE(client3, "LIST ACTIVE misc.test\r\n");
	CLIENT_EXPECT(client3, "215");
	CLIENT_EXPECT(client3, ".");

	SWRITE(client3, "GROUP misc.test\r\n");
	CLIENT_EXPECT(client3, "502");

	/* Permission should be denied if performing operations directly with Message-ID since not authorized for containing group */
	FMT_WRITE(client3, "OVER %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client3, "430");
	FMT_WRITE(client3, "STAT %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client3, "430");
	FMT_WRITE(client3, "HDR Subject %s\r\n", xmsgid);
	CLIENT_EXPECT_EVENTUALLY(client3, "430");

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
