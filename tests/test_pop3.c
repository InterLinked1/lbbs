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
 * \brief POP3 Tests
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
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_preload_module("mod_smtp_delivery_local.so");
	test_load_module("net_pop3.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_pop3.conf");

	system("rm -rf " TEST_MAIL_DIR); /* Purge the contents of the directory, if it existed. */
	mkdir(TEST_MAIL_DIR, 0700); /* Make directory if it doesn't exist already (of course it won't due to the previous step) */
	return 0;
}

static int send_count = 0;

static int send_message(int client1)
{
	char subject[32];

	if (!send_count++) {
		CLIENT_EXPECT(client1, "220");
		SWRITE(client1, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
		CLIENT_EXPECT_EVENTUALLY(client1, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	} else {
		SWRITE(client1, "RSET" ENDL);
		CLIENT_EXPECT(client1, "250");
	}

	SWRITE(client1, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(client1, "250");
	SWRITE(client1, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(client1, "250");
	SWRITE(client1, "DATA\r\n");
	CLIENT_EXPECT(client1, "354");

	snprintf(subject, sizeof(subject), "Subject: Message %d" ENDL, send_count);

	SWRITE(client1, "Date: Sun, 1 Jan 2023 05:33:29 -0700" ENDL);
	SWRITE(client1, "From: " TEST_EMAIL_EXTERNAL ENDL);
	write(client1, subject, strlen(subject));
	SWRITE(client1, "To: " TEST_EMAIL ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "This is a test email message." ENDL);
	SWRITE(client1, "....Let's hope it gets delivered properly." ENDL); /* Test byte stuffing */
	SWRITE(client1, "." ENDL); /* EOM */
	CLIENT_EXPECT(client1, "250");
	return 0;

cleanup:
	return -1;
}

static int make_messages(int nummsg)
{
	int clientfd;

	clientfd = test_make_socket(25);
	if (clientfd < 0) {
		return -1;
	}

	/* First, dump some messages into the mailbox for us to retrieve */
	while (send_count < nummsg) {
		send_message(clientfd);
	}
	/* Verify that the email messages were all sent properly. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", send_count);
	close(clientfd); /* Close SMTP connection */

	return 0;
cleanup:
	return -1;
}

#define TARGET_MESSAGES 10

static int run(void)
{
	int client1 = -1, client2 = -1;
	int res = -1;

	if (make_messages(TARGET_MESSAGES)) {
		return -1;
	}

	/* Begin POP3 testing. */
	client1 = test_make_socket(110);
	if (client1 < 0) {
		return -1;
	}

	/* Connect and log in */
	CLIENT_EXPECT(client1, "+OK"); /* Server Ready greeting */
	SWRITE(client1, "CAPA " ENDL);
	CLIENT_EXPECT(client1, "+OK");
	CLIENT_EXPECT_EVENTUALLY(client1, ".");
	CLIENT_DRAIN(client1);
	SWRITE(client1, "USER " TEST_USER ENDL);
	CLIENT_EXPECT(client1, "+OK");
	SWRITE(client1, "PASS " TEST_PASS ENDL);
	CLIENT_EXPECT(client1, "+OK");

	/* Query mailbox */
	SWRITE(client1, "STAT" ENDL);
	CLIENT_EXPECT(client1, "+OK " XSTR(TARGET_MESSAGES)); /* Ensure correct # of messages in response (although we don't check size here) */

	/* Another client should not be able to connect while this client is active. */
	client2 = test_make_socket(110);
	if (client2 < 0) {
		goto cleanup;
	}
	CLIENT_EXPECT(client2, "+OK"); /* Server Ready greeting */
	SWRITE(client2, "USER " TEST_USER ENDL);
	CLIENT_EXPECT(client2, "+OK");
	SWRITE(client2, "PASS " TEST_PASS ENDL);
	CLIENT_EXPECT(client2, "-ERR [IN-USE]"); /* Mailbox is busy */
	close_if(client2);

	/* SMTP connections while a POP3 session is active are okay,
	 * since new messages are delivered to "new",
	 * and the POP3 client will cause messages in "new" to be moved to "cur"
	 * as soon as the session begins, and after that point it will only be concerned with that.
	 * Message retrieval (POP3/IMAP) are the only ways messages can be moved from "new" to "cur".
	 */

	/* Continue the first session */

	SWRITE(client1, "RETR 1" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, ".");
	CLIENT_DRAIN(client1);
	SWRITE(client1, "DELE 1" ENDL);
	CLIENT_EXPECT(client1, "+OK");
	SWRITE(client1, "QUIT" ENDL);
	CLIENT_EXPECT(client1, "+OK"); /* Server will now purge message marked as deleted */
	close_if(client1);

	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/cur", send_count - 1); /* We deleted one message (it should now be in the Trash directory) */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash", 1);

	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	return res;
}

TEST_MODULE_INFO_STANDARD("POP3 Tests");
