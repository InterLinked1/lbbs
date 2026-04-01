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

/* Uncomment to test with actual, real DMARC policy lookups. Normally we don't require Internet access for tests, so this is disabled by default.
 * The tests should pass regardless, since failure to lookup DMARC policies fails safe to treating it as restrictive (quarantine/reject). */

/* #define TEST_WITH_REAL_DMARC_POLICIES */

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("net_smtp.so");
	test_preload_module("mod_mimeparse.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("mod_smtp_mailing_lists.so");
	test_load_module("net_imap.so");
#ifdef TEST_WITH_REAL_DMARC_POLICIES
	test_preload_module("mod_curl.so"); /* mod_smtp_filter_dmarc requires mod_curl */
	test_load_module("mod_smtp_filter_dmarc.so");
#endif

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");
	TEST_ADD_CONFIG("mod_smtp_mailing_lists.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

/*! \note This differs from test_send_sample_body in a few ways */
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

#define LIST_RCPT_DATA(list, fromaddr) \
	SWRITE(clientfd, "RCPT TO:" list "\r\n"); \
	CLIENT_EXPECT(clientfd, "250"); \
	SWRITE(clientfd, "DATA\r\n"); \
	CLIENT_EXPECT(clientfd, "354"); \
	SWRITE(clientfd, "Date: Thu, 21 May 1998 05:33:30 -0700" ENDL); \
	SWRITE(clientfd, "From: " fromaddr ENDL); \
	SWRITE(clientfd, ENDL); \
	SWRITE(clientfd, "Test" ENDL); \
	SWRITE(clientfd, "." ENDL); /* EOM */

	/* Ensure only authorized senders can post */
	SWRITE(clientfd, "RSET\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 ");
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	LIST_RCPT_DATA("<limitedsender>", TEST_EMAIL);
	CLIENT_EXPECT(clientfd, "550"); /* Not authorized! */

	/* Send email to multiple mailboxes via a mailing list, one of which fails at delivery time.
	 * In this case, the failure is due to insufficient quota. */
	TEST_MKDIR(TEST_MAIL_DIR "/2");
	TEST_EXEC("echo '32' > " TEST_MAIL_DIR "/2/.quota"); /* Quota of 32 bytes, insufficient for delivery to mailbox 4 */

	SWRITE(clientfd, "RSET\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 ");
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	LIST_RCPT_DATA("<oneandtwo>", TEST_EMAIL);

	/* Delivery to mailbox 1 will succeed, but delivery to mailbox 2 should fail due to insufficient quota.
	 * However, that is handled by a bounce and we still get a 250 at the protocol level. */
	CLIENT_EXPECT(clientfd, "250");

#define POST_TO_LIST(list, mailfrom, fromaddr) \
	SWRITE(clientfd, "RSET\r\n"); \
	CLIENT_EXPECT(clientfd, "250"); \
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL); \
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); \
	SWRITE(clientfd, "MAIL FROM:<" mailfrom ">\r\n"); \
	CLIENT_EXPECT(clientfd, "250"); \
	LIST_RCPT_DATA(list, fromaddr); \
	CLIENT_EXPECT(clientfd, "250");

	/* Test reply behavior of individual lists */
	POST_TO_LIST("<replysender>", TEST_EMAIL, TEST_EMAIL);
	SWRITE(client1, "b1 FETCH 3 (BODY.PEEK[HEADER.FIELDS (Reply-To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Reply-To: " TEST_EMAIL);

	POST_TO_LIST("<replylist>", TEST_EMAIL, TEST_EMAIL);
	SWRITE(client1, "c1 FETCH 4 (BODY.PEEK[HEADER.FIELDS (Reply-To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Reply-To: <replylist@bbs.example.com>");

	POST_TO_LIST("<replyboth>", TEST_EMAIL, TEST_EMAIL);
	SWRITE(client1, "c2 FETCH 5 (BODY.PEEK[HEADER.FIELDS (Reply-To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Reply-To: <replyboth@bbs.example.com>," TEST_EMAIL);

	/* Test that the list name comes through properly */
	POST_TO_LIST("<replysendername>", TEST_EMAIL, TEST_EMAIL);
	SWRITE(client1, "d1 FETCH 6 (BODY.PEEK[HEADER.FIELDS (Reply-To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Reply-To: " TEST_EMAIL);

	/* Past this point, all messages are from an external sender, only the dmarcmungetest list: */

	/* Test an external email address, which should munge the From address
	 * If TEST_WITH_REAL_DMARC_POLICIES isn't defined, mod_smtp_filter_dmarc isn't loaded, so it should fail safe with BBS_DMARC_POLICY_ERROR and munge anyways
	 * (Unless TEST_WITH_REAL_DMARC_POLICIES is defined, no DNS lookup is actually performed, in cases tests are being run offline) */
	close_if(clientfd); /* Reopen so we can pretend to be an MTA instead of MSA */
	clientfd = test_make_socket(25);
	REQUIRE_FD(clientfd);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "220 ");
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 ");

	POST_TO_LIST("<dmarcmungetest>", TEST_EMAIL_EXTERNAL, TEST_EMAIL_EXTERNAL);
	SWRITE(client1, "e1 FETCH 7 (BODY.PEEK[HEADER.FIELDS (Reply-To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Reply-To: " TEST_EMAIL_EXTERNAL);
	SWRITE(client1, "e2 FETCH 7 (BODY.PEEK[HEADER.FIELDS (From)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "From: external=" TEST_EXTERNAL_DOMAIN "@" TEST_HOSTNAME);

	POST_TO_LIST("<dmarcmungetest>", TEST_EMAIL_EXTERNAL, "External Sender <" TEST_EMAIL_EXTERNAL ">");
	SWRITE(client1, "f1 FETCH 8 (BODY.PEEK[HEADER.FIELDS (Reply-To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Reply-To: External Sender <" TEST_EMAIL_EXTERNAL ">");
	/* Ensure that if there was a name in the address, the munged From header still includes it
	 * If TEST_WITH_REAL_DMARC_POLICIES is defined, we'll still munge since TEST_EMAIL_EXTERNAL uses a domain with p=reject and sp=reject */
	SWRITE(client1, "f2 FETCH 8 (BODY.PEEK[HEADER.FIELDS (From)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "From: External Sender <external=" TEST_EXTERNAL_DOMAIN "@" TEST_HOSTNAME ">");

	/* Repeat, with a quoted name */
	POST_TO_LIST("<dmarcmungetest>", TEST_EMAIL_EXTERNAL, "\"External Sender\" <" TEST_EMAIL_EXTERNAL ">");
	SWRITE(client1, "g1 FETCH 9 (BODY.PEEK[HEADER.FIELDS (Reply-To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Reply-To: \"External Sender\" <" TEST_EMAIL_EXTERNAL ">");
	SWRITE(client1, "g2 FETCH 9 (BODY.PEEK[HEADER.FIELDS (From)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "From: \"External Sender\" <external=" TEST_EXTERNAL_DOMAIN "@" TEST_HOSTNAME ">");

	res = 0;

cleanup:
	close(clientfd);
	close_if(client1);
	return res;
}

TEST_MODULE_INFO_STANDARD("SMTP Mailing List Tests");
