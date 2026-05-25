/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief Network News Transfer Protocol tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define TEST_NEWS_HOSTNAME "news.example.com"

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
	CLIENT_EXPECT(fd, XSTR(NNTP_OK_GROUP) " " #count " " XSTR(low) " " XSTR(high) " " group)

#define GROUP_AND_LIST_ACTIVE_EXPECT(fd, group, low, high, count) \
	GROUP_EXPECT(fd, group, low, high, count); \
	LIST_ACTIVE_EXPECT(fd, group, low, high);

#define POST_ARTICLE_TO_GROUP_RESPONSE(fd, email, group, respcode) \
	SWRITE(fd, "POST\r\n"); \
	CLIENT_EXPECT_CODE(fd, NNTP_CONT_POST); \
	POST_NEWS_ARTICLE(s, fd, email, group); \
	CLIENT_EXPECT_CODE(fd, respcode);

#define POST_ARTICLE_TO_GROUP_ADDITIONAL_RESPONSE(fd, email, group, respcode, addl) \
	SWRITE(fd, "POST\r\n"); \
	CLIENT_EXPECT_CODE(fd, NNTP_CONT_POST); \
	POST_NEWS_ARTICLE_ADDITIONAL(s, fd, email, group, addl); \
	CLIENT_EXPECT_CODE(fd, respcode);

#define POST_ARTICLE_TO_GROUP(fd, email, group) POST_ARTICLE_TO_GROUP_RESPONSE(fd, email, group, NNTP_OK_POST)

#define IHAVE_ADDITIONAL_RESPONSE(fd, messageid, email, group, addl, respcode) \
	SWRITE(fd, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_CODE(fd, NNTP_CONT_IHAVE); \
	SEND_PEER_NEWS_ARTICLE(s, fd, messageid, email, group, addl); \
	CLIENT_EXPECT_CODE(fd, respcode);

#define IHAVE_RESPONSE(fd, messageid, email, group, respcode) \
	IHAVE_ADDITIONAL_RESPONSE(fd, messageid, email, group, "", respcode)

#define IHAVE_REFUSED(fd, messageid, email, group) \
	SWRITE(fd, "IHAVE " messageid "\r\n"); \
	CLIENT_EXPECT_CODE(fd, NNTP_FAIL_IHAVE_REFUSE); \

#define IHAVE(fd, messageid, email, group) IHAVE_RESPONSE(fd, messageid, email, group, NNTP_OK_IHAVE)

#define IHAVE_ADDITIONAL(fd, messageid, email, group, addl) IHAVE_ADDITIONAL_RESPONSE(fd, messageid, email, group, addl, NNTP_OK_IHAVE)

#define TAKETHIS(fd, messageid, email, group) \
	SWRITE(fd, "TAKETHIS " messageid "\r\n"); \
	SEND_PEER_NEWS_ARTICLE(s, fd, messageid, email, group, ""); \
	CLIENT_EXPECT_CODE(fd, NNTP_OK_TAKETHIS);

#define TAKETHIS_ADDITIONAL(fd, messageid, email, group, addl) \
	SWRITE(fd, "TAKETHIS " messageid "\r\n"); \
	SEND_PEER_NEWS_ARTICLE(s, fd, messageid, email, group, addl); \
	CLIENT_EXPECT_CODE(fd, NNTP_OK_TAKETHIS);

#define TAKETHIS_RESPONSE(fd, messageid, email, group, respcode) \
	SWRITE(fd, "TAKETHIS " messageid "\r\n"); \
	SEND_PEER_NEWS_ARTICLE(s, fd, messageid, email, group, ""); \
	CLIENT_EXPECT_CODE(fd, respcode);

#define TAKETHIS_ADDITIONAL_RESPONSE(fd, messageid, email, group, respcode, addl) \
	SWRITE(fd, "TAKETHIS " messageid "\r\n"); \
	SEND_PEER_NEWS_ARTICLE(s, fd, messageid, email, group, addl); \
	CLIENT_EXPECT_CODE(fd, respcode);

#define NEW_NEWSGROUP(sockfd, name, desc, creator, posting) \
	usleep(10000); \
	CLI_SWRITE(sockfd, "/news newgroup" CLI_EOL); \
	CLI_SWRITE(sockfd, name CLI_EOL); \
	CLI_SWRITE(sockfd, desc CLI_EOL); \
	CLI_SWRITE(sockfd, creator CLI_EOL); \
	CLI_SWRITE(sockfd, posting CLI_EOL);

/* Date chosen so that we can test articles with Date headers that are both too old and too new,
 * with a large enough value for maxacceptage in net_nntp.conf */
#define NNTP_TEST_DATE_HEADER "Thu, 1 Jan 2026 05:33:29 -0700"

#define NNTP_DEFAULT_ARTICLE_BASE \
	"Date: " NNTP_TEST_DATE_HEADER ENDL \
	"Subject: I am just a test article" ENDL \
	ENDL \
	"This is just a test article." ENDL \

/* This message is based on RFC 3977 6.3.1.3 */
#define SEND_NEWS_ARTICLE(s, fd, messageid, from, newsgroup, addl) \
	s = "From: \"Demo User\" <" from ">" ENDL \
		"Newsgroups: " newsgroup ENDL \
		addl \
		"Message-ID: " messageid ENDL \
		NNTP_DEFAULT_ARTICLE_BASE \
		"." ENDL; \
	write(fd, s, strlen(s));

#define SEND_PEER_NEWS_ARTICLE(s, fd, messageid, from, newsgroup, addl) SEND_NEWS_ARTICLE(s, fd, messageid, from, newsgroup, addl "Path: !foosite!.POSTED\r\n")

#define POST_NEWS_ARTICLE(s, fd, from, newsgroup) POST_NEWS_ARTICLE_ADDITIONAL(s, fd, from, newsgroup, "")
#define POST_NEWS_ARTICLE_ADDITIONAL(s, fd, from, newsgroup, addl) \
	s = "From: \"Demo User\" <" from ">" ENDL \
		"Newsgroups: " newsgroup ENDL \
		addl \
		NNTP_DEFAULT_ARTICLE_BASE \
		"." ENDL; \
	write(fd, s, strlen(s));
