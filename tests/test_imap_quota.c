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
 * \brief IMAP QUOTA Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "email.h"

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;
	int i;

	CREATE_IMAP_CONNECTION(clientfd, TEST_USER, TEST_PASS);
	SELECT_MAILBOX(clientfd, "a2", "INBOX");

	SWRITE(clientfd, "b1 GETQUOTA" ENDL);
	CLIENT_EXPECT(clientfd, "(STORAGE 32 39062)"); /* used, then total */

	/* Send enough messages to make it > 1 KB */
	if (test_make_messages(TEST_EMAIL, 25)) {
		return -1;
	}

	SWRITE(clientfd, "b2 NOOP" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "b2 OK"); /* Flush the untagged EXISTS/RECENT messages from message delivery */

	SWRITE(clientfd, "b3 GETQUOTA" ENDL);
	CLIENT_EXPECT(clientfd, "(STORAGE 37 39062)"); /* Quota usage should've increased */

	SWRITE(clientfd, "c1 COPY 1:25 \"INBOX\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "c1 OK");

	SWRITE(clientfd, "c2 GETQUOTA" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "(STORAGE 48 39062)"); /* Quota usage should've increased */

	SWRITE(clientfd, "d1 MOVE 26:50 \"Trash\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "d1 OK");

	SWRITE(clientfd, "d2 GETQUOTA" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "(STORAGE 53 39062)"); /* Should've been no material change in quota usage, but the move does create some directories and files */

	SELECT_MAILBOX(clientfd, "e1", "Trash");

	SWRITE(clientfd, "e2 STORE 1:* +FLAGS (\\Deleted)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "e2 OK");

	SWRITE(clientfd, "e3 EXPUNGE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "e3 OK");

	SWRITE(clientfd, "e4 GETQUOTA" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "(STORAGE 48 39062)"); /* Quota usage should've decreased */

	/* APPEND enough to guarantee increase in mailbox size by at least 1 KB */
	for (i = 0; i < 4; i++) {
		/* APPEND */
		/* Example from RFC 9051 6.3.12 */
		SWRITE(clientfd, "f1 APPEND INBOX (\\Seen) {326}" ENDL);
		CLIENT_EXPECT_EVENTUALLY(clientfd, "+");
		SWRITE(clientfd, "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)" ENDL);
		SWRITE(clientfd, "From: Fred Foobar <foobar@Blurdybloop.example>" ENDL);
		SWRITE(clientfd, "Subject: afternoon meeting" ENDL);
		SWRITE(clientfd, "To: mooch@owatagu.siam.edu.example" ENDL);
		SWRITE(clientfd, "Message-Id: <B27397-0100000@Blurdybloop.example>" ENDL);
		SWRITE(clientfd, "MIME-Version: 1.0" ENDL);
		SWRITE(clientfd, "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII" ENDL);
		SWRITE(clientfd, ENDL);
		SWRITE(clientfd, "Hello Joe, do you think we can meet at 3:30 tomorrow?" ENDL);
		SWRITE(clientfd, ENDL);
		CLIENT_EXPECT_EVENTUALLY(clientfd, "] APPEND");
	}

	SWRITE(clientfd, "f2 GETQUOTA" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "(STORAGE 49 39062)"); /* Quota usage should've increased */

	/* APPEND enough to exceed quota, using a non-synchronizing literal.
	 * Message will be a 27262976 byte upload (26 MB).
	 * This also tests the bug in [LBBS-149]. */
	SWRITE(clientfd, "h1 APPEND INBOX (\\Seen) {27262976+}" ENDL);
	SWRITE(clientfd, "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)" ENDL);
	SWRITE(clientfd, "From: Fred Foobar <foobar@Blurdybloop.example>" ENDL);
	SWRITE(clientfd, "Subject: afternoon meeting" ENDL);
	SWRITE(clientfd, "To: mooch@owatagu.siam.edu.example" ENDL);
	SWRITE(clientfd, "Message-Id: <B27397-0100000@Blurdybloop.example>" ENDL);
	SWRITE(clientfd, "MIME-Version: 1.0" ENDL);
	SWRITE(clientfd, "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII" ENDL);
	SWRITE(clientfd, ENDL);
	/* Original message is 326 bytes, minus 55 for the original last line = 271 bytes above.
	 * 27262976 - 271 = 27262705 bytes needed
	 * That's 545254 iterations of 50 bytes each, plus 5 bytes leftover. */
	for (i = 0; i < 545254; i++) {
		SWRITE(clientfd, "Hello Joe, do you think we can meet at 3:30 now?" ENDL);
	}
	SWRITE(clientfd, "Bye" ENDL); /* Last 5 bytes */
	SWRITE(clientfd, ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "NO [LIMIT]"); /* APPEND should fail since file is too large */

	/* LOGOUT */
	SWRITE(clientfd, "z1 LOGOUT" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* BYE");
	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP QUOTA Tests");
