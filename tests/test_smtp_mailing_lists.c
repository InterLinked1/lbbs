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
 * \brief SMTP Mailing List Tests
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
	test_preload_module("mod_mail.so");
	test_preload_module("net_smtp.so");
	test_preload_module("mod_mimeparse.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("mod_smtp_mailing_lists.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");
	TEST_ADD_CONFIG("mod_smtp_mailing_lists.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

static int send_body(int clientfd, const char *from, int html)
{
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");
	SWRITE(clientfd, "Date: Thu, 21 May 1998 05:33:29 -0700" ENDL);
	SWRITE(clientfd, "From: ");
	write(clientfd, from, strlen(from));
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "Subject: Next Meeting" ENDL);
	SWRITE(clientfd, "To: list1@" TEST_HOSTNAME ENDL);
	if (html) {
		SWRITE(clientfd, "Content-Type: text/html" ENDL); /* In the real world, would probably be multipart, but tests the same thing */
	}
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "Bill:" ENDL);
	SWRITE(clientfd, "The next meeting of the board of directors will be on Tuesday." ENDL);
	SWRITE(clientfd, "John." ENDL);
	SWRITE(clientfd, "." ENDL); /* EOM */
	return 0;

cleanup:
	return -1;
}

static int handshake(int clientfd, int reset)
{
	if (reset) {
		/* We should be able to reset at any point without losing our authenticated state, or needing to re-HELO/EHLO */
		SWRITE(clientfd, "RSET" ENDL);
		CLIENT_EXPECT(clientfd, "250");
	} else {
		CLIENT_EXPECT_EVENTUALLY(clientfd, "220 ");
		SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
		CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	}
	return 0;
cleanup:
	return -1;
}

static int run(void)
{
	int clientfd, client1 = -1;
	int res = -1;

	clientfd = test_make_socket(587);
	REQUIRE_FD(clientfd);

	if (handshake(clientfd, 0)) {
		goto cleanup;
	}

	/* Log in */
	SWRITE(clientfd, "AUTH PLAIN\r\n");
	CLIENT_EXPECT(clientfd, "334");
	SWRITE(clientfd, TEST_SASL "\r\n");
	CLIENT_EXPECT(clientfd, "235");

	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<list1@" TEST_HOSTNAME ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (send_body(clientfd, TEST_EMAIL, 0)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "250");

	/* Verify that the email message actually exists on disk. Only our mailbox will exist so far (nobody else has logged in). */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);

	/* Check that Subject contains tag.
	 * Ironically, it's easier to do this using the IMAP protocol than it is trying to manually find and parse the file on disk ourselves. */
	client1 = test_make_socket(143);
	REQUIRE_FD(client1);

	/* Connect and log in */
	CLIENT_EXPECT(client1, "OK");
	SWRITE(client1, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(client1, "a1 OK");

	SWRITE(client1, "a2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a2 OK");

	/* This also tests IMAP to some extent... */
	SWRITE(client1, "a3 FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])" ENDL);
	CLIENT_EXPECT(client1, "Subject: [My List] Next Meeting");

	/* Next test, ensure that list size restrictions work */
	if (handshake(clientfd, 1)) {
		goto cleanup;
	}
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<small@" TEST_HOSTNAME ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (send_body(clientfd, TEST_EMAIL, 0)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "552");

	/* HTML emails to plain text only list should be rejected */
	if (handshake(clientfd, 1)) {
		goto cleanup;
	}
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<list1@" TEST_HOSTNAME ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (send_body(clientfd, TEST_EMAIL, 1)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "550");

	res = 0;

cleanup:
	close(clientfd);
	close_if(client1);
	return res;
}

TEST_MODULE_INFO_STANDARD("SMTP Mailing List Tests");
