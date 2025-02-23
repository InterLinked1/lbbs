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
 * \brief Misc. filtering-related IMAP tests
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
	test_preload_module("mod_auth_static.so");
	test_preload_module("mod_mail.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("mod_mailscript.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");

	system("rm -rf /tmp/test_lbbs/maildir"); /* Purge the contents of the directory, if it existed. */
	mkdir(TEST_MAIL_DIR, 0700); /* Make directory if it doesn't exist already (of course it won't due to the previous step) */
	system("cp before.rules " TEST_MAIL_DIR); /* Global before MailScript */
	return 0;
}

#define STANDARD_ENVELOPE_BEGIN() \
	SWRITE(smtpfd, "RSET" ENDL); \
	CLIENT_EXPECT(smtpfd, "250"); \
	SWRITE(smtpfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL); \
	CLIENT_EXPECT_EVENTUALLY(smtpfd, "250 "); \
	SWRITE(smtpfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n"); \
	CLIENT_EXPECT(smtpfd, "250"); \
	SWRITE(smtpfd, "RCPT TO:<" TEST_EMAIL ">\r\n"); \
	CLIENT_EXPECT(smtpfd, "250"); \
	SWRITE(smtpfd, "DATA\r\n"); \
	CLIENT_EXPECT(smtpfd, "354"); \
	SWRITE(smtpfd, "Date: Sun, 1 Jan 2023 05:33:29 -0700" ENDL);

#define STANDARD_DATA() \
	SWRITE(smtpfd, ENDL); \
	SWRITE(smtpfd, "This is a test email message." ENDL); \
	SWRITE(smtpfd, "From: Some string here" ENDL); /* This is not a header, but if we missed the EOH, it might think it was one. */ \
	SWRITE(smtpfd, "." ENDL); \

static int run(void)
{
	int smtpfd;
	int imapfd = -1;
	int res = -1;

	smtpfd = test_make_socket(25);
	if (smtpfd < 0) {
		return -1;
	}

	imapfd = test_make_socket(143);
	if (smtpfd < 0) {
		goto cleanup;
	}

	CLIENT_EXPECT_EVENTUALLY(smtpfd, "220 ");

	/* Log in and enable NOTIFY */
	CLIENT_EXPECT(imapfd, "OK");
	SWRITE(imapfd, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(imapfd, "a1 OK");

	/* Enable NOTIFY for all personal mailboxes */
	SWRITE(imapfd, "a2 NOTIFY SET (personal (MessageNew (FLAGS) MessageExpunge))" ENDL);
	CLIENT_EXPECT(imapfd, "a2 OK");

	SWRITE(imapfd, "a3 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "a3 OK");

	SWRITE(imapfd, "a4 IDLE" ENDL);
	CLIENT_EXPECT(imapfd, "+ idling");

	/* Should be moved to .Trash */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(smtpfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(smtpfd, "Subject: Test Subject 1" ENDL);
	SWRITE(smtpfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(smtpfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/new", 1);

	/* We're idling on the INBOX, with NOTIFY enabled.
	 * We should get an untagged STATUS for Junk,
	 * NOT an untagged EXISTS for INBOX. */
	CLIENT_EXPECT(imapfd, "* STATUS");

	SWRITE(smtpfd, "QUIT");
	res = 0;

cleanup:
	close(smtpfd);
	close_if(imapfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Mail Filtering IMAP Interaction Tests");
