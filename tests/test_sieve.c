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
 * \brief Sieve Filtering Engine Tests
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
	test_load_module("mod_sieve.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	TEST_MKDIR(TEST_MAIL_DIR "/1");
	/* Sieve scripts go in the home directory, but the symlink itself to the active script goes in the maildir.
	 * We're just putting an actual file instead of a symlink there, but that's fine. */
	TEST_ADD_CONFIG_INTO_DIR(".sieve", TEST_MAIL_DIR "/1");
	TEST_MKDIR(TEST_MAIL_DIR "/2");
	TEST_ADD_CONFIG_INTO_DIR(".sieve", TEST_MAIL_DIR "/2");
	return 0;
}

#define STANDARD_ENVELOPE_BEGIN() \
	SWRITE(clientfd, "RSET" ENDL); \
	CLIENT_EXPECT(clientfd, "250"); \
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL); \
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); \
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n"); \
	CLIENT_EXPECT(clientfd, "250"); \
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL ">\r\n"); \
	CLIENT_EXPECT(clientfd, "250"); \
	SWRITE(clientfd, "DATA\r\n"); \
	CLIENT_EXPECT(clientfd, "354"); \
	SWRITE(clientfd, "Date: Sun, 1 Jan 2023 05:33:29 -0700" ENDL);

#define STANDARD_DATA() \
	SWRITE(clientfd, ENDL); \
	SWRITE(clientfd, "This is a test email message." ENDL); \
	SWRITE(clientfd, "From: Some string here" ENDL); /* This is not a header, but if we missed the EOH, it might think it was one. */ \
	SWRITE(clientfd, "." ENDL); \

static int run(void)
{
	int clientfd;
	int res = -1;

	clientfd = test_make_socket(25);
	REQUIRE_FD(clientfd);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "220 ");

	/* Test each of the rules in .sieve, one by one */

	/* Note: Everything below here is mostly the same as in test_mailscript
	 * (at least at the time of this coding).
	 * But it just happens to be that way, as it was easy to port the
	 * MailScript rules to Sieve and test for functionality parity that way.
	 */

	/* Should be moved to .Junk */
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");
	/* World's shortest email (really, this is invalid, but SMTP doesn't care) */
	SWRITE(clientfd, "T: " ENDL);
	SWRITE(clientfd, "." ENDL);
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Junk/new", 1);

	/* Should be moved to .Trash */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 1" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/new", 1);

	/* Should NOT be moved to .Trash */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Something" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/new", 1);

	/* Should bounce, and not be delivered at all */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 2" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "554");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/new", 1);

	/* Ditto, but custom bounce message, too */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 3" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "This is a custom bounce message");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/new", 1);

	/* Test conditional rule evaluation */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 4" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Junk/new", 2);

	/* Test contains */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 5" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	SWRITE(clientfd, "Cc: cc@example.org" ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1); /* Message dropped silently */

	/* Test header exists */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 5" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	SWRITE(clientfd, "X-Drop-Message: Foo-Bar" ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1); /* Message dropped silently */

	/* Test envelope */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 7" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1); /* Message dropped silently */

	/* Test redirect and ensure that self mail loops do not occur */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 8" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 2);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/2/new", 1); /* Also forwarded to user 2 */

	/* Test redirect and back-and-forth mail loops and ensure loops do not occur */
	STANDARD_ENVELOPE_BEGIN();
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 9" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 3);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/2/new", 2); /* Also forwarded to user 2 */

#if 0
	SWRITE(clientfd, "RSET" ENDL);
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 ");
	SWRITE(clientfd, "AUTH PLAIN\r\n");
	CLIENT_EXPECT(clientfd, "334");
	SWRITE(clientfd, TEST_SASL "\r\n");
	CLIENT_EXPECT(clientfd, "235");
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL2 ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");
	SWRITE(clientfd, "Date: Sun, 1 Jan 2023 05:33:29 -0700" ENDL);
	SWRITE(clientfd, "From: " TEST_EMAIL ENDL);
	SWRITE(clientfd, "Subject: Test Subject 12" ENDL);
	SWRITE(clientfd, "To: " TEST_EMAIL2 ENDL);
	STANDARD_DATA();
	CLIENT_EXPECT(clientfd, "250");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/2/new", 3); 
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 4); /* Vacation responder auto reply */
#endif

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Sieve Tests");
