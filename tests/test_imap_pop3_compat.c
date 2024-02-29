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
 * \brief IMAP and POP3 Compatibility Tests
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
	test_load_module("net_imap.so");
	test_load_module("net_pop3.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_imap.conf");
	TEST_ADD_CONFIG("net_pop3.conf");

	system("rm -rf " TEST_MAIL_DIR); /* Purge the contents of the directory, if it existed. */
	mkdir(TEST_MAIL_DIR, 0700); /* Make directory if it doesn't exist already (of course it won't due to the previous step) */
	return 0;
}

static int run(void)
{
	int client1 = -1, client2 = -1;
	int res = -1;

	client1 = test_make_socket(143);
	if (client1 < 0) {
		return -1;
	}

	/* Connect and log in */
	CLIENT_EXPECT(client1, "OK");
	SWRITE(client1, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(client1, "a1 OK");

	/* POP3 sessions are not necessarily rejected entirely while an IMAP session is active.
	 * This is hard to test since the IMAP server does not persistently hold the mailbox lock.
	 * The lock is only grabbed (as a RDLOCK) for as long as an operation needs it.
	 * If an IMAP client is idling, no locks are held, and a POP client would be allowed to connect.
	 * Thus, we use the TESTLOCK command, explicitly added for this purpose.
	 */
	client2 = test_make_socket(110);
	if (client2 < 0) {
		goto cleanup;
	}
	CLIENT_EXPECT(client2, "+OK"); /* Server Ready greeting */
	SWRITE(client2, "USER " TEST_USER ENDL);
	CLIENT_EXPECT(client2, "+OK");

	/* Interleave these writes at the same time to ensure the lock is held when the POP server tries to authenticate */
	SWRITE(client1, "a2 TESTLOCK" ENDL); /* When the INBOX is selected, that should temporarily grab the lock */
	CLIENT_EXPECT(client1, "TESTLOCK in progress"); /* Wait for TESTLOCK command to start processing, so we know the lock's held */

	SWRITE(client2, "PASS " TEST_PASS ENDL);
	CLIENT_EXPECT(client2, "-ERR [IN-USE]"); /* Mailbox is busy */
	close_if(client2); /* POP server will disconnect at this point. We'll need to reconnect. */

	/* But if we wait a moment and try again, it should succeed, since the IMAP server will eventually release the lock. */
	CLIENT_EXPECT(client1, "a2 OK"); /* This will naturally block until the lock is released. So when we try to reconnect to the POP server, it will succeed. */

	/* This POP3 login should succeed. */
	client2 = test_make_socket(110);
	if (client2 < 0) {
		return -1;
	}
	CLIENT_EXPECT(client2, "+OK"); /* Server ready */
	SWRITE(client2, "USER " TEST_USER ENDL);
	CLIENT_EXPECT(client2, "+OK");
	SWRITE(client2, "PASS " TEST_PASS ENDL);
	CLIENT_EXPECT(client2, "+OK");

	/* IMAP connections must not be able to modify the mailbox while a POP3 session is active */
	SWRITE(client1, "a2 SELECT \"INBOX\"" ENDL);
	CLIENT_EXPECT(client1, "a2 NO"); /* Mailbox busy */

	SWRITE(client2, "QUIT" ENDL); /* Make sure we cleanly quit so that the POP3 user doesn't log in and block the IMAP connection */
	CLIENT_EXPECT(client2, "+OK");
	close_if(client2);

	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP/POP3 Compatibility Tests");
