/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief SMTP Mail Filter Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "email.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("mod_smtp_filter.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

#define send_body(fd) test_send_sample_body(fd, "John Q. Public <JQP@bar.com>")

static int run(void)
{
	int smtpfd = -1;
	int imapfd = -1;
	int res = -1;

	imapfd = test_make_socket(143);
	CLIENT_EXPECT(imapfd, "OK");
	SWRITE(imapfd, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);

	smtpfd = test_make_socket(25);
	REQUIRE_FD(smtpfd);

	/* As a slight optimization, switch to SMTP stuff while the login is happening */
	CLIENT_EXPECT_EVENTUALLY(smtpfd, "220 ");

	SWRITE(smtpfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(smtpfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */

	/* Send a message to a local recipient */
	SWRITE(smtpfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(smtpfd, "250");

	CLIENT_EXPECT(imapfd, "a1 OK");
	SWRITE(imapfd, "a2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "a2 OK");

	/* Send the body */
	if (send_body(smtpfd)) {
		goto cleanup;
	}
	CLIENT_EXPECT(smtpfd, "250");

	/* Test that the headers are in the order we expect. */
	SWRITE(imapfd, "a3 NOOP" ENDL); /* Discard IDLE updates */
	CLIENT_EXPECT_EVENTUALLY(imapfd, "a3 OK");

	/* Last header added was Delivered-To */
	SWRITE(imapfd, "a4 FETCH 1 BODY.PEEK[HEADER]<0.42>" ENDL); /* First line of headers, including line ending */
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Delivered-To: <" TEST_EMAIL ">");

	/* Before that, Return-Path */
	SWRITE(imapfd, "a5 FETCH 1 BODY.PEEK[HEADER]<42.35>" ENDL); /* Second line of headers, including line ending */
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Return-Path: " TEST_EMAIL_EXTERNAL);

	/* Before that, Received */
	SWRITE(imapfd, "a6 FETCH 1 BODY.PEEK[HEADER]<77.10>" ENDL); /* Beginning of previous line */
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Received: ");

	res = 0;

cleanup:
	close_if(smtpfd);
	close_if(imapfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("SMTP MTA Filter Tests");
