/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Paging Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Things this test module tests (to some extent):
 * - Inbound SNPP
 * - Inbound SMTP
 * - Outbound SNPP
 * - Outbound SMTP
 * - Delivery to IRC
 * - Command Execution
 */

/* This needs to match the #define in mod_paging_smtp (if it's defined there, it should be here, and if not, it shouldn't be) */
#define ALWAYS_HAVE_A_SUBJECT

static int pre(void)
{
	/* This test module mostly tests SNPP as far as the paging protocols go,
	 * but the main goal is really to excercise the paging core and mod_paging. */
	test_preload_module("mod_mail.so");
	test_load_module("mod_paging.so");
	test_load_module("mod_paging_snpp.so");
	test_load_module("mod_paging_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("mod_smtp_filter.so"); /* So we can test Return-Path */
	test_load_module("net_snpp.so");
	test_load_module("net_smtp.so");
	test_load_module("net_irc.so");
	/* For IMAP: */
	test_preload_module("mod_mimeparse.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("transfers.conf"); /* So we can use home directory configs */
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_irc.conf");
	TEST_ADD_CONFIG("mod_paging.conf");
	TEST_ADD_CONFIG("net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);

	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	TEST_MKDIR(TEST_HOME_DIR_ROOT);
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1/.config");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/2");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/2/.config");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/3");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/3/.config");
	TEST_ADD_CONFIG_INTO_DIR("paging/.paging.1", TEST_HOME_DIR_ROOT "/1/.config/.paging");
	TEST_ADD_CONFIG_INTO_DIR("paging/.paging.2", TEST_HOME_DIR_ROOT "/2/.config/.paging");
	TEST_ADD_CONFIG_INTO_DIR("paging/.paging.3", TEST_HOME_DIR_ROOT "/3/.config/.paging");

	return 0;
}

/* Store message tag, terminating at 2nd space (so we store just tag + password) */
#define STORE_MSGTAG() \
	msgtagtmp = strchr(buf, ' '); \
	if (msgtagtmp) { \
		msgtagtmp++; \
		strncpy(msgtagbuf, msgtagtmp, sizeof(msgtagbuf) - 1); \
		msgtagbuf[sizeof(msgtagbuf) - 1] = '\0'; \
		tmp = strchr(msgtagbuf, ' '); \
		if (tmp) { \
			tmp++; \
			tmp = strchr(tmp, ' '); \
			if (tmp) *tmp = '\0'; \
		} \
	}

#define FMT_WRITE(fd, fmt, ...) { \
	char _scratch_buf[1024]; \
	int _len; \
	_len = snprintf(_scratch_buf, sizeof(_scratch_buf), fmt, ## __VA_ARGS__); \
	write(fd, _scratch_buf, (size_t) _len); \
}

static int run(void)
{
	int clientfd = -1, ircfd = -1, smtpfd = -1, imapfd = -1;
	int res = -1;
	char buf[512];
	char msgtagbuf[sizeof(buf) + 1]; /* Was 32, but this avoids a stringop-truncation warning */
	char *msgtagtmp, *tmp;

	/* Set up IRC connection */
	ircfd = test_make_socket(6667);
	REQUIRE_FD(ircfd);

	/* SASL negotiation */
	SWRITE(ircfd, "CAP LS 302\r\n");
	SWRITE(ircfd, "NICK " TEST_USER ENDL);
	SWRITE(ircfd, "USER " TEST_USER ENDL);
	CLIENT_EXPECT_EVENTUALLY(ircfd, "CAP * LS");
	SWRITE(ircfd, "CAP REQ :sasl\r\n");
	CLIENT_EXPECT(ircfd, "CAP * ACK");
	SWRITE(ircfd, "AUTHENTICATE PLAIN\r\n");
	CLIENT_EXPECT(ircfd, "AUTHENTICATE +\r\n");
	SWRITE(ircfd, "AUTHENTICATE " TEST_SASL "\r\n");
	CLIENT_EXPECT(ircfd, "903");
	SWRITE(ircfd, "CAP END\r\n");

	CLIENT_EXPECT_EVENTUALLY(ircfd, "376"); /* End of MOTD */

	/* Set up an SNPP client connection */
	clientfd = test_make_socket(444);
	REQUIRE_FD(clientfd);
	CLIENT_EXPECT(clientfd, "220");

	SWRITE(clientfd, "PAGE 5551001\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "PAGE 5551001\r\n");
	CLIENT_EXPECT(clientfd, "503"); /* Duplicate */
	SWRITE(clientfd, "MESS This is the first test message\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT_BUF(clientfd, "250", buf);
	STORE_MSGTAG(); /* Save message tag and passcode */

	/* Check status afterwards (allowed, even though it isn't 2WAY) */
	FMT_WRITE(clientfd, "MSTA %s\r\n", msgtagbuf);
	CLIENT_EXPECT(clientfd, "960"); /* 960 instead of 880, since it's not 2WAY, we don't know if it was actually delivered */
	FMT_WRITE(clientfd, "KTAG %s\r\n", msgtagbuf);
	CLIENT_EXPECT(clientfd, "250");
	FMT_WRITE(clientfd, "MSTA %s\r\n", msgtagbuf);
	CLIENT_EXPECT(clientfd, "550");

	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1); /* Should get via email, since user 1 specified an email address in [5551001] */
	CLIENT_EXPECT_EVENTUALLY(ircfd, "This is the first test message"); /* Should get via IRC as well */

	/* Delivery should be rejected if PIN required and not provided */
	SWRITE(clientfd, "PAGE 5551002\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This message should not reach the recipient\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "554");

	/* The 5551011 alias has its own PIN, even though the target does not */
	SWRITE(clientfd, "PAGE 5551011\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This message should not reach the recipient either\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "554");

	/* The target of 5551012 has a PIN, but the alias 5551012 has a different PIN, which is the actual one */
	SWRITE(clientfd, "PAGE 5551012\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This message should not reach the recipient either\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "554");

	/* Okay, supply the correct PIN for 5551013 now */
	SWRITE(clientfd, "PAGE 5551013 1234\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This message should be accepted\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "250");

	/* Deliver to 2 recipients, and use DATA */
	SWRITE(clientfd, "PAGE 5551001\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "PAGE 5551002 4321\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");
	SWRITE(clientfd, "This is a multiline page.\r\n");
	SWRITE(clientfd, "But it's not very long.\r\n");
	SWRITE(clientfd, ".\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "250");

	CLIENT_EXPECT(ircfd, "it's not very long"); /* Should have received via IRC due to 5551001 being a recipient */
	usleep(50000); /* Wait for SMTP transaction (since that happens async after the 250 response) to finish before checking maildir */

	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/2/new", 1);
	/* User 1 will get the copy for 5551001, and then the copy for 5551098 (which is an SNPP target of 5551002) */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 3);

	/* Test that page-username successfully delivers a page to a user */
	smtpfd = test_make_socket(25);
	REQUIRE_FD(smtpfd);
	CLIENT_EXPECT_EVENTUALLY(smtpfd, "220 ");
	SWRITE(smtpfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(smtpfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	SWRITE(smtpfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "RCPT TO:<page-" TEST_EMAIL ">" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "DATA" ENDL);
	CLIENT_EXPECT(smtpfd, "354");
	SWRITE(smtpfd, "Date: Sun, 1 Jan 2023 05:33:29 -0700" ENDL);
	SWRITE(smtpfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(smtpfd, "Subject: Test Page" ENDL);
	SWRITE(smtpfd, "To: page-" TEST_EMAIL ENDL);
	SWRITE(smtpfd, ENDL);
	SWRITE(smtpfd, "This is a test page message submitted by email." ENDL);
	SWRITE(smtpfd, "." ENDL); /* EOM */
	CLIENT_EXPECT(smtpfd, "250");
	CLIENT_EXPECT(ircfd, "This is a test page message submitted by email"); /* Should have received message via IRC */

	/* Alphanumeric messages should be rejected if endpoint is numeric only */
	SWRITE(clientfd, "PAGE 5553001\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This message should be rejected because it is not numeric\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "554");

	/* Repeat, but add an additional recipient that is not numeric-only, so it should succeed overall */
	SWRITE(clientfd, "PAGE 5553001\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "PAGE " TEST_USER "\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This message should be not rejected even though not all its recipients can receive alphanumeric pages\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "250");

	/* However, if ALL recipients are numeric only, it should still fail */
	SWRITE(clientfd, "PAGE 5553001\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "PAGE 5553002\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This message should be not rejected even though not all its recipients can receive alphanumeric pages\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "554");

	/* Attempt to page user 3, who is not online and only has IRC configured as a method (with no bouncer).
	 * The recipient should be valid but delivery fail with "retry later". */
	SWRITE(clientfd, "PAGE 5551103\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This is a test\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "554 Temporary Delivery Failure");

	/* Test that we can page aliases that are not numeric and not usernames */
	SWRITE(clientfd, "PAGE testuseralias\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This is a test\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "250");

	/* Test that if we send a page via SNPP, and it gets relayed via SNPP, and then via SMTP to the recipient,
	 * the initial paging subject is still present as the email subject. */
	imapfd = test_make_socket(143);
	REQUIRE_FD(imapfd);
	SWRITE(clientfd, "PAGE 5551201\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SUBJ This is my subject\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "CALL bob@example.com\r\n"); /* "Caller ID", in this case we use an email instead of a phone number */
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This is my message\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "250");
	/* Check via IMAP that the headers are what we expect */
	CLIENT_EXPECT(imapfd, "OK");
	SWRITE(imapfd, "a1 LOGIN \"" TEST_USER2 "\" \"" TEST_PASS2 "\"" ENDL);
	CLIENT_EXPECT(imapfd, "a1 OK");
	SWRITE(imapfd, "a2 SELECT \"INBOX\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "a2 OK");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/2/cur", 2);
	SWRITE(imapfd, "a3 UID FETCH 2 (BODY.PEEK[HEADER.FIELDS (Subject)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Subject: This is my subject" ENDL);
	SWRITE(imapfd, "a4 UID FETCH 2 (BODY.PEEK[HEADER.FIELDS (From)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "From: bob@example.com" ENDL); /* We include CR LF at the end to ensure there isn't anything AFTER in the header, either */

	/* If the page doesn't have a subject, the email should still have one */
	SWRITE(clientfd, "PAGE 5551201\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This is my message\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "250");
#ifdef ALWAYS_HAVE_A_SUBJECT
	SWRITE(imapfd, "a5 UID FETCH 3 (BODY.PEEK[HEADER.FIELDS (Subject)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Subject: New Page" ENDL);
/* even if ALWAYS_HAVE_A_SUBJECT isn't defined, we still do this transaction, so the sequence numbers for later operations will match */
#endif

	/* Repeat with a sender, but no subject (which is reasonable for something submitted via email, though in this case we do so via SNPP) */
	SWRITE(clientfd, "PAGE 5551201\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "CALL bob@example.com\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This is my message\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT(clientfd, "250");
#ifdef ALWAYS_HAVE_A_SUBJECT
	SWRITE(imapfd, "a6 UID FETCH 4 (BODY.PEEK[HEADER.FIELDS (Subject)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Subject: New Page" ENDL);
#endif
	SWRITE(imapfd, "a7 UID FETCH 4 (BODY.PEEK[HEADER.FIELDS (From)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "From: bob@example.com" ENDL); /* We include CR LF at the end to ensure there isn't anything AFTER in the header, either */

	/* Repeat, but via SMTP
	 * This tests sending and receiving an email address in the "CALL" SNPP command */
	SWRITE(smtpfd, "RSET" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "RCPT TO:<page-5551201@" TEST_HOSTNAME ">" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "DATA" ENDL);
	CLIENT_EXPECT(smtpfd, "354");
	SWRITE(smtpfd, "Date: Sun, 1 Jan 2023 05:33:29 -0700" ENDL);
	SWRITE(smtpfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(smtpfd, "Subject: Test Page" ENDL);
	SWRITE(smtpfd, "To: page-5551201@" TEST_HOSTNAME ENDL);
	SWRITE(smtpfd, ENDL);
	SWRITE(smtpfd, "This is a test page message submitted by email." ENDL);
	SWRITE(smtpfd, "." ENDL); /* EOM */
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(imapfd, "a8 UID FETCH 5 (BODY.PEEK[HEADER.FIELDS (Subject)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Subject: Test Page" ENDL);
	SWRITE(imapfd, "a9 UID FETCH 5 (BODY.PEEK[HEADER.FIELDS (From)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "From: " TEST_EMAIL_EXTERNAL ENDL); /* We include CR LF at the end to ensure there isn't anything AFTER in the header, either */
	SWRITE(imapfd, "a10 UID FETCH 4 (BODY.PEEK[HEADER.FIELDS (Return-Path)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Return-Path: page-sender@" TEST_HOSTNAME ENDL);

	/* Can't ping non-2WAY pagers */
	SWRITE(clientfd, "PING 5553001\r\n");
	CLIENT_EXPECT(clientfd, "550");

	SWRITE(clientfd, "2WAY\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "PING 5553001\r\n");
	CLIENT_EXPECT(clientfd, "821"); /* Even though it's not 2WAY, it'll acknowledge it's a valid endpoint, but no location data available */

	/* Should get the same response if pinging an IRC-only endpoint, when user is on IRC */
	SWRITE(clientfd, "2WAY\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "PING testuser\r\n");
	CLIENT_EXPECT(clientfd, "821");

	close_if(ircfd);

	usleep(250000); /* May need to wait momentarily for IRC connection to drop */

	SWRITE(clientfd, "PING testuser\r\n");
	CLIENT_EXPECT(clientfd, "750");

	res = 0;

cleanup:
	close_if(clientfd);
	close_if(ircfd);
	close_if(smtpfd);
	close_if(imapfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Paging Tests");
