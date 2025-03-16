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
	test_preload_module("mod_smtp_delivery_local.so");
	test_load_module("net_pop3.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_pop3.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

/* Do not change this value, as the value is used hardcoded in several places that would need to be updated as well */
#define TARGET_MESSAGES 10

static int run(void)
{
	int client1 = -1, client2 = -1;
	int res = -1;

	if (test_make_messages(TEST_EMAIL, TARGET_MESSAGES)) {
		return -1;
	}

	/* Verify that the email messages were all sent properly. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", send_count);

	/* Begin POP3 testing. */
	client1 = test_make_socket(110);
	REQUIRE_FD(client1);

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
	REQUIRE_FD(client2);

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
