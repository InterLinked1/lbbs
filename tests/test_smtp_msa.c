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
 * \brief SMTP Message Submission Agent Tests
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
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
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
	int clientfd;
	int res = -1;

	clientfd = test_make_socket(587);
	REQUIRE_FD(clientfd);

	if (handshake(clientfd, 0)) {
		goto cleanup;
	}

	/* Can't send messages without logging in */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "530"); /* Authentication required */

	/* Log in */
	SWRITE(clientfd, "AUTH PLAIN\r\n");
	CLIENT_EXPECT(clientfd, "334");
	SWRITE(clientfd, TEST_SASL "\r\n");
	CLIENT_EXPECT(clientfd, "235");

	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "503"); /* MAIL first */

	/* Try using identities we're not authorized to */

	/* Unauthorized envelope */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL2 ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL2 ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (test_send_sample_body(clientfd, TEST_EMAIL)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "550");

	/* Unauthorized From: header */
	if (handshake(clientfd, 1)) {
		goto cleanup;
	}
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (test_send_sample_body(clientfd, TEST_EMAIL2)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "550");

	/* Verify that the email message does NOT exist on disk. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", -1); /* Folder not created yet */

	/* Malformed From: header (extraneous trailing '>') */
	if (handshake(clientfd, 1)) {
		goto cleanup;
	}
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (test_send_sample_body(clientfd, "<" TEST_EMAIL ">>")) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "550");

	/* Verify that the email message does NOT exist on disk. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", -1); /* Folder not created yet */

	/* All right, let's get it right this time. */
	if (handshake(clientfd, 1)) {
		goto cleanup;
	}
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (test_send_sample_body(clientfd, TEST_EMAIL)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "250");

	/* Verify that the email message actually exists on disk. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("SMTP MSA Tests");
