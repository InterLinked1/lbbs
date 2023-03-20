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
 * \brief IMAP Tests
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
	test_load_module("net_smtp.so");
	test_load_module("net_imap.so");
	test_load_module("net_pop3.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");
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
	} else {
		SWRITE(client1, "RSET" ENDL);
		CLIENT_EXPECT(client1, "250");
	}

	SWRITE(client1, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
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
	close(clientfd); /* Close SMTP connection */

	return 0;
}

/* Do not change this value, as the value is used hardcoded in several places that would need to be updated as well */
#define TARGET_MESSAGES 10

static int run(void)
{
	int client1 = -1, client2 = -1;
	int res = -1;

	if (make_messages(TARGET_MESSAGES)) {
		return -1;
	}
	/* Verify that the email messages were all sent properly. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", send_count);

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
	SWRITE(client2, "PASS " TEST_PASS ENDL);

	/* Interleave these writes at the same time to ensure the lock is held when the POP server tries to authenticate */
	SWRITE(client1, "a2 TESTLOCK" ENDL); /* When the INBOX is selected, that should temporarily grab the lock */
	CLIENT_EXPECT(client2, "-ERR [IN-USE]"); /* Mailbox is busy */
	close_if(client2); /* POP server will disconnect at this point. We'll need to reconnect. */

	/* But if we wait a moment and try again, it should succeed, since the IMAP server will eventually release the lock. */
	CLIENT_EXPECT(client1, "a2 OK"); /* This will naturally block until the lock is released. So when we try to reconnect to the POP server, it will succeed. */

	/* EXAMINE */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", send_count);
	SWRITE(client1, "a2 EXAMINE \"INBOX\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a2 OK [READ-ONLY] EXAMINE completed");
	/* EXAMINE traversal should NOT result in messages being moved */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", send_count);

	/* SELECT */
	SWRITE(client1, "a3 SELECT \"INBOX\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* " XSTR(TARGET_MESSAGES) " EXISTS");
	/* SELECT traversal should have moved all the messages from new to cur */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/cur", send_count);

	/* This POP3 login should succeed. Note that this will result in a maildir traversal. For that reason, we do the EXAMINE/SELECT above so that this traversal here will not move any files. */
	client2 = test_make_socket(110);
	if (client2 < 0) {
		return -1;
	}
	CLIENT_EXPECT(client2, "+OK"); /* Server ready */
	SWRITE(client2, "USER " TEST_USER ENDL);
	CLIENT_EXPECT(client2, "+OK");
	SWRITE(client2, "PASS " TEST_PASS ENDL);
	CLIENT_EXPECT(client2, "+OK");
	SWRITE(client2, "QUIT" ENDL); /* Make sure we cleanly quit so that the POP3 user doesn't log in and block the IMAP connection */
	CLIENT_EXPECT(client2, "+OK");
	close_if(client2);
	usleep(2000); /* Wait a small instant since the mailbox lock is not released until net_pop3 cleans up the POP3 session, and we need to be able to grab the lock */

	/* LIST */
	SWRITE(client1, "a4 LIST \"\" \"\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a4 OK LIST");

	/* CREATE */
	SWRITE(client1, "a5 CREATE foobar" ENDL);
	CLIENT_EXPECT(client1, "a5 OK CREATE");
	/* Make sure the created folder shows up in LIST, and exists on disk. */
	SWRITE(client1, "a6 LIST \"\" \"*\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "foobar");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.foobar", 0); /* This function would return -1 if the directory did not exist, so 0 means it exists */
	CLIENT_DRAIN(client1);

	/* RENAME */
	SWRITE(client1, "a7 RENAME foobar barfoo" ENDL);
	CLIENT_EXPECT(client1, "a7 OK RENAME");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.foobar", -1);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.barfoo", 0);

	/* DELETE */
	SWRITE(client1, "a8 DELETE barfoo" ENDL);
	CLIENT_EXPECT(client1, "a8 OK DELETE"); /* ...and just as soon, it was gone again. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.barfoo", -1); /* See note above */

	/* SUBSCRIBE */
	SWRITE(client1, "a9 SUBSCRIBE foobar" ENDL); /* Doesn't matter whether or not it exists */
	CLIENT_EXPECT(client1, "a9 OK SUBSCRIBE");

	/* NAMESPACE */
	SWRITE(client1, "a10 NAMESPACE" ENDL);
	CLIENT_EXPECT(client1, "* NAMESPACE");

	/* STATUS */
	/* RFC 9051: the STATUS command SHOULD NOT be used on the currently selected mailbox. However, servers MUST be able to execute the STATUS command on the selected mailbox. */
	SWRITE(client1, "a11 STATUS \"INBOX\" (UIDNEXT MESSAGES)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* STATUS INBOX (MESSAGES 10 UIDNEXT 11)");

	/* The main thing we want to test with STATUS is this:
	 * RFC 9051 6.3.11: It does not change the currently selected mailbox, nor does it affect the state of any messages in the queried mailbox.
	 * We can test this by issuing STATUS on a different folder, and then when we try to perform an operation on the originally selected folder, it should be sensible.
	 */
	SWRITE(client1, "a12 STATUS \"Trash\" (UIDNEXT MESSAGES)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* STATUS Trash (MESSAGES 0 UIDNEXT 1)");

	/* This FETCH should apply to INBOX, not Trash */
	SWRITE(client1, "a13 FETCH 1:* (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 10 FETCH"); /* Expect to get info for the 10th message (in the INBOX) */
	CLIENT_DRAIN(client1);

	/* APPEND */
	/* Example from RFC 9051 6.3.12 */
	SWRITE(client1, "a14 APPEND INBOX (\\Seen) {326}" ENDL);
	CLIENT_EXPECT(client1, "+");
	SWRITE(client1, "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)" ENDL);
	SWRITE(client1, "From: Fred Foobar <foobar@Blurdybloop.example>" ENDL);
	SWRITE(client1, "Subject: afternoon meeting" ENDL);
	SWRITE(client1, "To: mooch@owatagu.siam.edu.example" ENDL);
	SWRITE(client1, "Message-Id: <B27397-0100000@Blurdybloop.example>" ENDL);
	SWRITE(client1, "MIME-Version: 1.0" ENDL);
	SWRITE(client1, "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII" ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "Hello Joe, do you think we can meet at 3:30 tomorrow?" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "11] APPEND"); /* The UID of this message should be 11 */
	CLIENT_DRAIN(client1);

	/* STORE */
	SWRITE(client1, "a15 STORE 1:3 +FLAGS (\\Seen)" ENDL); /* Mark messages 1 through 3 as read */
	CLIENT_EXPECT_EVENTUALLY(client1, "* 3 FETCH (FLAGS (\\Seen))"); /* We know taht no other flags have been set yet */
	CLIENT_DRAIN(client1);

	/* Make sure the flags really persisted */
	SWRITE(client1, "a16 FETCH 3:3 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "\\Seen"); /* The response will also contain the UID, so just make sure that it contains "Seen" */
	/* Depending on timing, the end of response could have been read already or may still be pending, so use CLIENT_DRAIN */
	CLIENT_DRAIN(client1);

	/* Set flags silently */
	SWRITE(client1, "a17 STORE 4 +FLAGS.SILENT (\\Seen)" ENDL); /* Mark message 4 as read */
	CLIENT_EXPECT(client1, "a17 OK STORE"); /* Immediate success, with no other untagged responses */

	/* COPY */
	SWRITE(client1, "a18 COPY 3 Trash" ENDL);
	CLIENT_EXPECT(client1, "3 1] COPY");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/cur", 1);

	/* EXPUNGE */
	SWRITE(client1, "a19 EXPUNGE" ENDL);
	CLIENT_EXPECT(client1, "a19 OK EXPUNGE"); /* There are no messages in the currently selected folder with the Deleted flag set */
	/* But we can change that */
	SWRITE(client1, "a20 SELECT \"Trash\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a20 OK");
	/* We copied a message to the Trash in a18. Mark it as deleted. */
	SWRITE(client1, "a21 STORE 1 +FLAGS.SILENT (\\Deleted)" ENDL);
	CLIENT_EXPECT(client1, "a21 OK STORE");
	SWRITE(client1, "a22 EXPUNGE" ENDL);
	CLIENT_EXPECT(client1, "* 1 EXPUNGE");
	CLIENT_EXPECT(client1, "a22 OK EXPUNGE");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/cur", 0);

	/* Test UID-prefixed commands. Granted... the UIDs and sequence numbers are the same in these tests. */
	SWRITE(client1, "a23 SELECT \"INBOX\"" ENDL); /* First, switch back to the INBOX. */
	CLIENT_EXPECT_EVENTUALLY(client1, "a23 OK [READ-WRITE] SELECT");
	SWRITE(client1, "a24 UID FETCH 1 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "UID 1");
	CLIENT_DRAIN(client1);

	/* Test IDLE. Start idling, then send ourselves a message. */
	SWRITE(client1, "a25 IDLE" ENDL);
	CLIENT_EXPECT(client1, "+");
	send_count = 0;
	make_messages(1);
	CLIENT_EXPECT(client1, "* 12 EXISTS"); /* Should receive an untagged EXISTS message. In particular, there are now 12 messages in this folder. */
	SWRITE(client1, "DONE" ENDL);
	CLIENT_EXPECT(client1, "a25 OK IDLE");

	/* LOGOUT */
	SWRITE(client1, "a26 LOGOUT" ENDL);
	CLIENT_EXPECT(client1, "* BYE");

	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP Tests");
