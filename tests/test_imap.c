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
	test_preload_module("mod_mimeparse.so");
	test_load_module("net_smtp.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");

	system("rm -rf " TEST_MAIL_DIR); /* Purge the contents of the directory, if it existed. */
	mkdir(TEST_MAIL_DIR, 0700); /* Make directory if it doesn't exist already (of course it won't due to the previous step) */
	return 0;
}

static int send_count = 0;

static int send_message(int client1, size_t extrabytes)
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
	SWRITE(client1, "Content-Type: text/plain" ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "This is a test email message." ENDL);
	SWRITE(client1, "....Let's hope it gets delivered properly." ENDL); /* Test byte stuffing */
	if (extrabytes) {
		extrabytes = MIN(sizeof(subject), extrabytes);
		memset(subject, 'a', extrabytes);
		write(client1, subject, extrabytes);
		SWRITE(client1, ENDL);
	}
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
		send_message(clientfd, 0);
	}
	close(clientfd); /* Close SMTP connection */

	return 0;
}

/* Do not change this value, as the value is used hardcoded in several places that would need to be updated as well */
#define TARGET_MESSAGES 10

#define SELECT_MAILBOX(fd, tag, name) \
	SWRITE(fd, tag " SELECT \"" name "\"" ENDL); \
	CLIENT_EXPECT_EVENTUALLY(fd, tag " OK");

static unsigned int get_uidvalidity(int fd, const char *mailbox)
{
	char buf[256];
	char *s;
	static int c = 0;

	dprintf(fd, "u%d SELECT %s\r\n", ++c, mailbox);
	if (test_client_expect_eventually_buf(fd, SEC_MS(5), "UIDVALIDITY ", __LINE__, buf, sizeof(buf))) {
		return 0;
	}
	s = strstr(buf, "UIDVALIDITY ");
	if (!s) {
		return 0;
	}
	s += STRLEN("UIDVALIDITY ");
	CLIENT_DRAIN(fd);
	return (unsigned int) atoi(s);
}

static int run(void)
{
	int client1 = -1, client2 = -1, smtpfd;
	int res = -1;
	int i;
	unsigned int uidvalidity;

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

	/* LIST */
	SWRITE(client1, "a4 LIST \"\" \"\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a4 OK LIST");

	/* LIST-EXTENDED and LIST-STATUS extensions */
	SWRITE(client1, "a4a LIST (SUBSCRIBED) \"\" (\"INBOX\") RETURN (STATUS (MESSAGES UNSEEN SIZE))" ENDL);
	/* Dunno the actual size here, but if it's present that's probably correct */
	CLIENT_EXPECT_EVENTUALLY(client1, "* STATUS \"INBOX\" (MESSAGES " XSTR(TARGET_MESSAGES) " UNSEEN " XSTR(TARGET_MESSAGES) " SIZE ");
	CLIENT_DRAIN(client1);

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
	CLIENT_EXPECT_EVENTUALLY(client1, "* STATUS \"INBOX\" (MESSAGES 10 UIDNEXT 11)");

	/* The main thing we want to test with STATUS is this:
	 * RFC 9051 6.3.11: It does not change the currently selected mailbox, nor does it affect the state of any messages in the queried mailbox.
	 * We can test this by issuing STATUS on a different folder, and then when we try to perform an operation on the originally selected folder, it should be sensible.
	 */
	SWRITE(client1, "a12 STATUS \"Trash\" (UIDNEXT MESSAGES)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* STATUS \"Trash\" (MESSAGES 0 UIDNEXT 1)");

	SWRITE(client1, "a12a LIST \"\" \"Trash\" RETURN (STATUS (UIDNEXT MESSAGES))" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "\".\" \"Trash\""); /* Ensure mailbox name is correct (Trash, not .Trash) */

	/* Issue the command again since we can't currently reliably test for presence of multiple lines in one go */
	SWRITE(client1, "a12b LIST \"\" \"Trash\" RETURN (STATUS (UIDNEXT MESSAGES))" ENDL);
	/* We tested LIST-STATUS with INBOX earlier, but that's a special case. This tests the other case (non-INBOX): */
	CLIENT_EXPECT_EVENTUALLY(client1, "* STATUS \"Trash\" (MESSAGES 0 UIDNEXT 1)");

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
	SWRITE(client1, ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "11] APPEND"); /* The UID of this message should be 11 */
	CLIENT_DRAIN(client1);

	/* Repeat with non-synchronizing literal */
	SWRITE(client1, "a14b APPEND INBOX (\\Seen) {326+}" ENDL);
	SWRITE(client1, "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)" ENDL);
	SWRITE(client1, "From: Fred Foobar <foobar@Blurdybloop.example>" ENDL);
	SWRITE(client1, "Subject: afternoon meeting" ENDL);
	SWRITE(client1, "To: mooch@owatagu.siam.edu.example" ENDL);
	SWRITE(client1, "Message-Id: <B27397-0100000@Blurdybloop.example>" ENDL);
	SWRITE(client1, "MIME-Version: 1.0" ENDL);
	SWRITE(client1, "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII" ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "Hello Joe, do you think we can meet at 3:30 tomorrow?" ENDL);
	SWRITE(client1, ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "12] APPEND"); /* The UID of this message should be 12 */
	CLIENT_DRAIN(client1);

	/* MULTIAPPEND */
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
	/* Skip this since we're in the middle of a MULTIAPPEND: SWRITE(client1, ENDL); */
	/* Repeat with non-synchronizing literal */
	SWRITE(client1, "(\\Seen) {326+}" ENDL);
	SWRITE(client1, "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)" ENDL);
	SWRITE(client1, "From: Fred Foobar <foobar@Blurdybloop.example>" ENDL);
	SWRITE(client1, "Subject: afternoon meeting" ENDL);
	SWRITE(client1, "To: mooch@owatagu.siam.edu.example" ENDL);
	SWRITE(client1, "Message-Id: <B27397-0100000@Blurdybloop.example>" ENDL);
	SWRITE(client1, "MIME-Version: 1.0" ENDL);
	SWRITE(client1, "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII" ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "Hello Joe, do you think we can meet at 3:30 tomorrow?" ENDL);
	SWRITE(client1, ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "13:14] APPEND"); /* The UID of these messages should be 13 and 14 */
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
	CLIENT_EXPECT(client1, "a19 OK"); /* There are no messages in the currently selected folder with the Deleted flag set */
	/* But we can change that */
	SELECT_MAILBOX(client1, "a20", "Trash");
	/* We copied a message to the Trash in a18. Mark it as deleted. */
	SWRITE(client1, "a21 STORE 1 +FLAGS.SILENT (\\Deleted)" ENDL);
	CLIENT_EXPECT(client1, "a21 OK STORE");

	/* Test another client at the same time. */
	client2 = test_make_socket(143);
	if (client2 < 0) {
		goto cleanup;
	}
	CLIENT_EXPECT(client2, "OK");
	SWRITE(client2, "b1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(client2, "b1 OK");

	SELECT_MAILBOX(client2, "b2", "Trash");

	SWRITE(client1, "a22 EXPUNGE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 EXPUNGE"); /* Expunger should immediately see this response */
	CLIENT_DRAIN(client1);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/.Trash/cur", 0);

	/* Client 2 should see the EXPUNGE when it does a NOOP */
	SWRITE(client2, "b3 FETCH 111:* (FLAGS)" ENDL); /* FETCH should not trigger the delayed EXPUNGE response... */
	CLIENT_EXPECT(client2, "b3");
	SWRITE(client2, "b4 NOOP" ENDL); /* ...but NOOP should */
	CLIENT_EXPECT(client2, "* 1 EXPUNGE");
	CLIENT_DRAIN(client2);

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
	CLIENT_EXPECT(client1, "* 15 EXISTS"); /* Should receive an untagged EXISTS message. In particular, there are now 15 messages in this folder. */

	/* Change the flags of a message. We should get an untagged response for it. */
	SELECT_MAILBOX(client2, "b3", "INBOX");
	SWRITE(client2, "b4 STORE 1 +FLAGS.SILENT (\\Flagged)" ENDL);
	CLIENT_EXPECT(client2, "b4 OK");
	CLIENT_EXPECT(client1, "\\Flagged"); /* Should get an untagged response when a flag is changed */
	close_if(client2);

	SWRITE(client1, "DONE" ENDL);
	CLIENT_EXPECT(client1, "a25 OK IDLE");

	/* Test FETCH BODYSTRUCTURE */
	/* Since gmime/glib don't free all their memory prior to exiting,
	 * run this multiple times to invoke mod_mimeparse multiple times,
	 * to ensure our suppressions are valid. */
	for (i = 0; i < 3; i++) {
		SWRITE(client1, "a26 UID FETCH 1 (UID BODYSTRUCTURE)" ENDL);
		CLIENT_EXPECT(client1, "plain");
		CLIENT_DRAIN(client1);
	}
	SWRITE(client1, "a27 UID FETCH 11 (FLAGS UID BODYSTRUCTURE)" ENDL);
	CLIENT_EXPECT(client1, "PLAIN");
	CLIENT_DRAIN(client1);

	/* Test FETCH BODY.PEEK[HEADER] */
	SWRITE(client1, "a28 UID FETCH 11 (FLAGS BODY.PEEK[HEADER])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "MIME-Version");
	CLIENT_DRAIN(client1);

	/* Test FETCH ENVELOPE and INTERNALDATE */
	SWRITE(client1, "a29 UID FETCH 11 (FLAGS ENVELOPE INTERNALDATE)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "B27397-0100000@Blurdybloop.example");
	CLIENT_DRAIN(client1);

	/* Using BODY instead of BODY.PEEK should result in the message getting marked as read.
	 * Additionally, the flags should contain \Seen in the response.
	 * First, remove the \Seen flag if it is already present. */
	SWRITE(client1, "a30 UID STORE 11 -FLAGS.SILENT (\\Seen)" ENDL);
	CLIENT_EXPECT(client1, "a30 OK UID STORE"); /* Response should be UID prefixed! */

	SWRITE(client1, "a31 UID FETCH 11 (BODY[TEXT] FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "\\Seen");
	CLIENT_DRAIN(client1);

	/* Independently verify in a subsequent message that the file really was renamed to contain the Seen flag */
	SWRITE(client1, "a32 UID FETCH 11 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "\\Seen");
	CLIENT_DRAIN(client1);

	/* SEARCH */
	SWRITE(client1, "a33 UID SEARCH LARGER 20 SEEN HEADER \"Content-Type\" \"plain\" BODY \"test\" OR OR SMALLER 200000 NOT FROM \"John Smith\" NOT FROM \"Paul Smith\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a33 OK UID SEARCH");
	CLIENT_DRAIN(client1);

	/* Keywords (custom flags) */
	SWRITE(client1, "a34 STORE 1 +FLAGS ($label1)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "$label1");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "a35 FETCH 1 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "$label1");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "a36 STORE 1 +FLAGS ($label2)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "$label2");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "a36 FETCH 1 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "$label1 $label2");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "a37 STORE 1 -FLAGS ($label1)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "$label2");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "a38 STORE 1 FLAGS ($label3)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "$label3");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "a39 FETCH 1 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "$label3");
	CLIENT_DRAIN(client1);

	/* ACLs and shared mailboxes */
	client2 = test_make_socket(143);
	if (client2 < 0) {
		goto cleanup;
	}
	CLIENT_EXPECT(client2, "OK");
	SWRITE(client2, "a1 LOGIN \"" TEST_USER2 "\" \"" TEST_PASS2 "\"" ENDL);
	CLIENT_EXPECT(client2, "a1 OK");

	SWRITE(client2, "a2 CREATE sharedmbox" ENDL);
	CLIENT_EXPECT(client2, "a2 OK");

	SWRITE(client2, "a3 SETACL sharedmbox " TEST_USER " lrswipkxte" ENDL); /* Grant full control, except administration rights */
	CLIENT_EXPECT(client2, "a3 OK");

	/* Shared mailbox should show up */
	SWRITE(client1, "b1 LIST \"\" \"Other Users*\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "sharedmbox");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "b2 SELECT \"Other Users." TEST_USER2 ".sharedmbox\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "b2 OK")

	/* Now remove the permissions */
	SWRITE(client2, "a4 DELETEACL sharedmbox " TEST_USER ENDL);
	CLIENT_EXPECT(client2, "a4 OK");

	SWRITE(client1, "b3 LIST \"\" \"Other Users*\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "b3 OK"); /* Can't really test for negative output... */
	CLIENT_DRAIN(client1);

	close_if(client2);

	/* SORT */
	/* Delete any existing messages so we don't get confused. */
	SELECT_MAILBOX(client1, "c1", "INBOX");

	SWRITE(client1, "c2 STORE 1:* FLAGS.SILENT (\\Deleted)" ENDL);
	CLIENT_EXPECT(client1, "c2 OK");

	SWRITE(client1, "c3 CLOSE" ENDL); /* Expunge but don't send untagged responses */
	CLIENT_EXPECT(client1, "c3 OK");

	smtpfd = test_make_socket(25);
	if (smtpfd < 0) {
		goto cleanup;
	}
	send_count = 0;
	send_message(smtpfd, 10);
	send_message(smtpfd, 12);
	send_message(smtpfd, 16);
	send_message(smtpfd, 7);
	send_message(smtpfd, 15);
	send_message(smtpfd, 2);
	SWRITE(smtpfd, "QUIT" ENDL);
	close_if(smtpfd);

	SELECT_MAILBOX(client1, "c4", "INBOX");

	SWRITE(client1, "c5 SORT (REVERSE SIZE TO REVERSE DATE) UTF-8 ALL" ENDL); /* Use SORT, not UID SORT, so we can exactly predict the correct sequence numbers for response */
	CLIENT_EXPECT(client1, "SORT 3 5 2 1 4 6");
	CLIENT_DRAIN(client1);

	/* Test ESEARCH */
	SWRITE(client1, "c6 SEARCH RETURN (MIN MAX COUNT) 1:10" ENDL);
	CLIENT_EXPECT(client1, "* ESEARCH (TAG \"c6\") MIN 1 MAX 6 COUNT 6");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "c7 SEARCH RETURN () 1:10" ENDL);
	CLIENT_EXPECT(client1, "* ESEARCH (TAG \"c7\") ALL 1:6");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "c8 SEARCH RETURN (MIN ALL) 1:10" ENDL);
	CLIENT_EXPECT(client1, "* ESEARCH (TAG \"c8\") MIN 1 ALL 1:6");
	CLIENT_DRAIN(client1);

	/* Test ESORT */
	SWRITE(client1, "c9 SORT RETURN () (REVERSE SIZE TO REVERSE DATE) UTF-8 UNDELETED" ENDL);
	CLIENT_EXPECT(client1, "* ESEARCH (TAG \"c9\") ALL 3,5,2,1,4,6");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "c10 SORT RETURN (MIN ALL) (REVERSE SIZE TO REVERSE DATE) UTF-8 UNDELETED" ENDL);
	CLIENT_EXPECT(client1, "* ESEARCH (TAG \"c10\") MIN 1 ALL 3,5,2,1,4,6");
	CLIENT_DRAIN(client1);

	/* Test SEARCHRES */
	SWRITE(client1, "c11 SEARCH RETURN (SAVE) 3" ENDL);
	CLIENT_EXPECT(client1, "c11 OK");
	SWRITE(client1, "c12 FETCH $ (FLAGS)" ENDL);
	CLIENT_EXPECT(client1, "* 3 FETCH");
	CLIENT_DRAIN(client1);

	/* Test MOVE */
	SWRITE(client1, "c13 MOVE 5 Trash" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 5 EXPUNGE"); /* Other clients in the same mailbox should also get an EXPUNGE if idling or on next command */
	CLIENT_DRAIN(client1);

	/* Test BURL SMTP + IMAP URLAUTH */
	SWRITE(client1, "d1 APPEND Sent (\\Seen) {310}" ENDL); /* 310 includes the length of TEST_EMAIL */
	CLIENT_EXPECT(client1, "+");
	SWRITE(client1, "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)" ENDL);
	SWRITE(client1, "From: " TEST_EMAIL ENDL); /* Must be from ourself */
	SWRITE(client1, "Subject: afternoon meeting" ENDL);
	SWRITE(client1, "To: mooch@owatagu.siam.edu.example" ENDL);
	SWRITE(client1, "Message-Id: <B27397-0100000@Blurdybloop.example>" ENDL);
	SWRITE(client1, "MIME-Version: 1.0" ENDL);
	SWRITE(client1, "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII" ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "Hello Joe, do you think we can meet at 3:30 tomorrow?" ENDL);
	SWRITE(client1, ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, " 1] APPEND"); /* The UID of this message should be 1; this is the first test that uses the Sent folder. */
	CLIENT_DRAIN(client1);

	/* UIDVALIDITY is not used in the current implementation so we can send some random value,
	 * but ideally should parse from the APPEND response */
#define BURL_URL "imap://" TEST_USER "@" TEST_HOSTNAME "/Sent;UIDVALIDITY=12345/;UID=1;urlauth=submit+" TEST_USER
	SWRITE(client1, "d2 GENURLAUTH " BURL_URL " INTERNAL" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, ":internal"); /* GENURLAUTH should tack on :internal */
	CLIENT_DRAIN(client1);
	SWRITE(client1, "d3 IDLE" ENDL); /* Need to idle to get the unilateral EXISTS without doing a NOOP */
	CLIENT_EXPECT(client1, "+");

	smtpfd = test_make_socket(587);
	if (smtpfd < 0) {
		goto cleanup;
	}
	CLIENT_EXPECT(smtpfd, "220");
	SWRITE(smtpfd, "EHLO myclient" ENDL);
	CLIENT_EXPECT_EVENTUALLY(smtpfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	SWRITE(smtpfd, "AUTH PLAIN\r\n");
	CLIENT_EXPECT(smtpfd, "334");
	SWRITE(smtpfd, TEST_SASL "\r\n");
	CLIENT_EXPECT(smtpfd, "235");
	SWRITE(smtpfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(smtpfd, "250");
	/* Look, ma! We're not sending the message data to the SMTP server! */
	SWRITE(smtpfd, "BURL " BURL_URL ":internal LAST" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	CLIENT_EXPECT_EVENTUALLY(client1, "* 6 EXISTS"); /* Should receive the message we just sent to ourself. INBOX already had 6 messages, but we moved 1. */
	CLIENT_DRAIN(client1);

	SWRITE(client1, "DONE" ENDL);
	CLIENT_EXPECT(client1, "d3 OK");

	/* Test keywords on messages moved between folders */
	SELECT_MAILBOX(client1, "a0", "Sent");

	SWRITE(client1, "e1 STORE 1 +FLAGS.SILENT ($Test1 $Test2)" ENDL);
	CLIENT_EXPECT(client1, "e1 OK");

	SELECT_MAILBOX(client1, "e2", "INBOX");

	/* Ensure the mappings for keywords are different between the two folders, and that flags are copied properly. */
	SWRITE(client1, "e3 STORE 1:2 +FLAGS.SILENT (\\Seen $Test2)" ENDL);
	CLIENT_EXPECT(client1, "e3 OK");

	SWRITE(client1, "e4 COPY 1 Sent" ENDL);
	CLIENT_EXPECT(client1, "e4 OK");

	SELECT_MAILBOX(client1, "e5", "Sent");

	/* Sent already had one message (from the BURL test). It'll be #2 */
	SWRITE(client1, "e6 FETCH 2 (FLAGS)" ENDL);
	CLIENT_EXPECT(client1, "FLAGS (\\Seen $Test2)"); /* Ensure these flags, and no other flags, are present */
	CLIENT_DRAIN(client1);

	/* Test CONDSTORE with STORE: UNCHANGEDSINCE */
	SWRITE(client1, "e7 STORE 1 (UNCHANGEDSINCE 0) +FLAGS.SILENT ($Test2)" ENDL); /* 0 will never match */
	CLIENT_EXPECT(client1, "[MODIFIED 1]");
	CLIENT_DRAIN(client1);

	SWRITE(client1, "e8 STORE 1 (UNCHANGEDSINCE 999) -FLAGS.SILENT ($Test1)" ENDL); /* Some value we know will be higher, and let the STORE proceed */
	CLIENT_EXPECT(client1, "MODSEQ"); /* Even though we said +FLAGS.SILENT, we should get an untagged FETCH response. Should also contain MODSEQ (but not flags if silent). */
	CLIENT_DRAIN(client1);

	/* Test CONDSTORE with FETCH: CHANGEDSINCE */
	SWRITE(client1, "e9 FETCH 1 (FLAGS) (CHANGEDSINCE 999)" ENDL);
	CLIENT_EXPECT(client1, "e9 OK"); /* This shouldn't match any messages */

	SWRITE(client1, "e10 FETCH 1 (FLAGS) (CHANGEDSINCE 0)" ENDL);
	CLIENT_EXPECT(client1, "MODSEQ"); /* Should get an implicit MODSEQ as part of the untagged response */
	CLIENT_DRAIN(client1);

	/* Test CONDSTORE with SEARCH: MODSEQ */
	SWRITE(client1, "e10 SEARCH MODSEQ 1 ALL" ENDL);
	CLIENT_EXPECT(client1, "MODSEQ");
	CLIENT_DRAIN(client1);

	/* Test CONDSTORE with ESEARCH */
	SWRITE(client1, "e11 SEARCH RETURN (MIN) MODSEQ 1" ENDL);
	CLIENT_EXPECT(client1, "MODSEQ"); /* XXX If we knew the modification sequences of all messages in this mailbox, we'd expect to see the modseq of the minimum UID message with MODSEQ >= 1 */
	CLIENT_DRAIN(client1);

	/* Test QRESYNC */
	uidvalidity = get_uidvalidity(client1, "INBOX");
	if (!uidvalidity) {
		goto cleanup;
	}
	dprintf(client1, "e12 SELECT INBOX (QRESYNC (%u 1))" ENDL, uidvalidity); /* Try using QRESYNC without enabling */
	CLIENT_EXPECT(client1, "e12 BAD");
	dprintf(client1, "e13 ENABLE QRESYNC" ENDL);
	CLIENT_EXPECT(client1, "QRESYNC");
	CLIENT_DRAIN(client1);

	dprintf(client1, "e14 SELECT INBOX (QRESYNC (%u 1))" ENDL, uidvalidity);
	CLIENT_EXPECT_EVENTUALLY(client1, "FETCH"); /* Should get all flag changes since MODSEQ 1 */
	CLIENT_DRAIN(client1);

	dprintf(client1, "e15 SELECT INBOX (QRESYNC (%u 1))" ENDL, uidvalidity);
	CLIENT_EXPECT_EVENTUALLY(client1, "VANISHED"); /* Repeat, to make sure we also got a VANISHED response */
	CLIENT_DRAIN(client1);

	SWRITE(client1, "e16 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)" ENDL);
	CLIENT_EXPECT(client1, "VANISHED"); /* Should get a VANISHED response */
	CLIENT_DRAIN(client1);

	SWRITE(client1, "e17 IDLE" ENDL);
	CLIENT_EXPECT(client1, "+");

	/* Now, if another client expunges a message, we should get a VANISHED response, not an EXPUNGE response */
	client2 = test_make_socket(143);
	if (client2 < 0) {
		goto cleanup;
	}
	CLIENT_EXPECT(client2, "OK");
	SWRITE(client2, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(client2, "a1 OK");
	SELECT_MAILBOX(client2, "a2", "INBOX");
	SWRITE(client2, "a3 STORE 1 +FLAGS.SILENT (\\Deleted)" ENDL);
	CLIENT_EXPECT(client1, "\\Deleted"); /* We should get notified about the flag change since we're idling */
	CLIENT_EXPECT(client2, "a3 OK");
	SWRITE(client2, "a4 EXPUNGE" ENDL);
	CLIENT_EXPECT(client2, "* 1 EXPUNGE");
	CLIENT_EXPECT(client1, "* VANISHED"); /* We should get a VANISHED response for the expunged message (containing the UID) */

	SWRITE(client1, "DONE" ENDL);
	CLIENT_EXPECT(client1, "e17 OK");

	CLIENT_DRAIN(client2);
	close_if(client2);

	/* LOGOUT */
	SWRITE(client1, "z999 LOGOUT" ENDL);
	CLIENT_EXPECT(client1, "* BYE");

	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP Tests");
