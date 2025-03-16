/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief IMAP Message Sequence Number Mapping Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note net_imap currently deviates from IMAP4rev1 in that no mapping of sequence numbers to UIDs is maintained per-connection,
 *       which IMAP servers generally do, since this can differ per connection and we need to know the client's view of the mapping.
 *       If this is eventually changed, then this test module should be updated to ensure this works as expected.
 *       For now, we simply do some checks to verify that if the client gets into a situation where its view of sequence numbers
 *       differs from the default "dumb" view of a message with sequence number X being the X'th UID-ordered message in the maildir,
 *       that the operation is rejected by the IMAP server. This at least prevents a client from doing something it didn't mean to,
 *       and on the whole should be rare these days with modern IMAP clients, since the use of IDLE when not performing an operation,
 *       generally ensures clients are always kept synchronized with the current mailbox.
 *
 *       Put another way, although this IMAP server deviates from the RFC in this fairly fundamental way,
 *       we will not have any incorrect behavior for this reason if we respond OK to a command.
 *       In some cases, we'll end up responding NO, to prevent incorrect behavior due to this limitation,
 *       but we'll avoid something happening that shouldn't happen.
 */

#include "test.h"
#include "email.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_imap.so");
	test_load_module("mod_mail_events.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");
	TEST_ADD_CONFIG("mod_mail_events.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

#define TARGET_MESSAGES 10

static int run(void)
{
	int smtpfd = -1;
	int c1 = -1, c2 = -1, c3 = -1;
	int res = -1;

	smtpfd = test_make_socket(25);
	REQUIRE_FD(smtpfd);

	/* First, dump some messages into the mailbox for us to retrieve */
	while (send_count < TARGET_MESSAGES) {
		test_send_message(smtpfd, TEST_EMAIL);
	}

	/* Verify that the email messages were all sent properly. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", send_count);

	c1 = test_make_socket(143);
	if (c1 < 0) {
		goto cleanup;
	}
	c2 = test_make_socket(143);
	if (c2 < 0) {
		goto cleanup;
	}
	c3 = test_make_socket(143);
	if (c3 < 0) {
		goto cleanup;
	}

	/* Connect and log in */
	CLIENT_EXPECT(c1, "OK");
	SWRITE(c1, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(c1, "a1 OK");

	SWRITE(c1, "a2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c1, "a2 OK");

	CLIENT_EXPECT(c2, "OK");
	SWRITE(c2, "b1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(c2, "b1 OK");

	SWRITE(c2, "b2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c2, "b2 OK");

	CLIENT_EXPECT(c3, "OK");
	SWRITE(c3, "c1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(c3, "c1 OK");

	SWRITE(c3, "c2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c3, "c2 OK");

	/* We now have two IMAP clients that have selected the same mailbox.
	 * The mailbox currently has 10 messages in it. */

	SWRITE(c1, "a3 FETCH 1 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c1, "a3 OK");

	SWRITE(c1, "a4 IDLE" ENDL);
	CLIENT_EXPECT(c1, "+");

	/* Client 1 is now idling. Client 2 is not. */
	test_send_message(smtpfd, TEST_EMAIL);

	/* Client 1 will get informed in realtime, client 2 will need to poll */
	CLIENT_EXPECT(c1, "* 11 EXISTS");
	SWRITE(c2, "b3 NOOP" ENDL);
	CLIENT_EXPECT(c2, "* 11 EXISTS");

	/* Now, an expunge. All of them should get 3, 4, 5, but we can only do one check with CLIENT_EXPECT_EVENTUALLY, so check a different one per connection. */
	SWRITE(c3, "c3 STORE 3:5 +FLAGS (\\Deleted)" ENDL);
	/* CLIENT_EXPECT_EVENTUALLY(c3, "* 3 FETCH"); */
	CLIENT_EXPECT_EVENTUALLY(c3, "c3 OK"); /* This is needed to ensure all messages are deleted before we verify on the other clients */

	CLIENT_EXPECT_EVENTUALLY(c1, "* 4 FETCH");

	SWRITE(c2, "b4 NOOP" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c2, "* 5 FETCH");

	/* Part B: Actually expunge */
	SWRITE(c3, "c4 EXPUNGE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c3, "c4 OK");

	/* Because the sequence numbers shift after each EXPUNGE notification, they are all 3 (for messages 3, 4, and 5) */
	CLIENT_EXPECT_EVENTUALLY(c1, "* 3 EXPUNGE");

	SWRITE(c2, "b5 NOOP" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c2, "* 3 EXPUNGE");

	/* We had 11 messages, and now have 8 */

	/* Do another expunge */
	SWRITE(c3, "c5 STORE 3:5 +FLAGS (\\Deleted)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c3, "c5 OK"); /* This is needed to ensure all messages are deleted before we verify on the other clients */
	CLIENT_EXPECT_EVENTUALLY(c1, "* 4 FETCH");
	SWRITE(c2, "b6 FETCH 8 (FLAGS)" ENDL); /* We can get FETCH updates during a FETCH... just not EXPUNGE updates */
	CLIENT_EXPECT_EVENTUALLY(c2, "* 3 FETCH");

	/* Actual expunge. */
	SWRITE(c3, "c6 EXPUNGE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c3, "* 3 EXPUNGE");
	CLIENT_EXPECT_EVENTUALLY(c1, "* 3 EXPUNGE");

	/* We had 8 messages, and now have 5 */

	/* RFC 9051 7.5.1
	 * An EXPUNGE response MUST NOT be sent when no command is in progress, nor while responding to a FETCH, STORE, or SEARCH command.
	 * This rule is necessary to prevent a loss of synchronization of message sequence numbers between client and server. */

	/* Okay, this is a case in which a "correct" IMAP server would need to know that, as far as this client is concerned,
	 * messages 3 through 5 haven't yet been expunged and still exist, and we can't notify the client about the expunge yet either! */
	SWRITE(c2, "b7 STORE 7 +FLAGS (\\Seen)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c2, "b7 NO"); /* Server should reject the command, because the client's view of the sequence mapping has diverged from reality, and we can't honor it */

	SWRITE(c2, "b8 NOOP" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c2, "* 3 EXPUNGE");

	/* Okay, now client 2 is back in sync and could retry its STORE: */
	SWRITE(c2, "b9 STORE 4 +FLAGS (\\Seen)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c2, "b9 OK"); /* This is needed to ensure all messages are deleted before we verify on the other clients */
	CLIENT_EXPECT_EVENTUALLY(c1, "* 4 FETCH");

	/* This time, client 3 is the one that needs to poll for an update. */
	SWRITE(c3, "c7 FETCH 1 (FLAGS)" ENDL); /* We can get FETCH updates during a FETCH... just not EXPUNGE updates */
	CLIENT_EXPECT_EVENTUALLY(c3, "* 4 FETCH");

	SWRITE(c3, "c8 STORE 3:5 +FLAGS (\\Deleted)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c3, "c8 OK"); /* This is needed to ensure all messages are deleted before we verify on the other clients */
	CLIENT_EXPECT_EVENTUALLY(c1, "* 4 FETCH");
	SWRITE(c2, "b10 FETCH 2 (FLAGS)" ENDL); /* We can get FETCH updates during a FETCH... just not EXPUNGE updates */
	CLIENT_EXPECT_EVENTUALLY(c2, "* 3 FETCH");

	/* Actual expunge. */
	SWRITE(c3, "c9 EXPUNGE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c3, "* 3 EXPUNGE");
	CLIENT_EXPECT_EVENTUALLY(c1, "* 3 EXPUNGE");

	/* RFC 9051 7.5.1
	 * UID FETCH, UID STORE, and UID SEARCH are different commands from FETCH, STORE, and SEARCH.
	 * An EXPUNGE response MAY be sent during a UID command. */
	SWRITE(c2, "b11 UID STORE 1 +FLAGS (\\Seen)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c2, "* 1 FETCH");

	CLIENT_EXPECT_EVENTUALLY(c1, "* 1 FETCH");

	SWRITE(c3, "c10 UID FETCH 2 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c3, "* 1 FETCH");

	/* Stop idling on client 1 */
	SWRITE(c1, "DONE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(c1, "a4 OK");
	res = 0;

cleanup:
	close_if(c1);
	close_if(c2);
	close_if(smtpfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP Message Sequence Number Mapping Tests");
