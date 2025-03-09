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
 * \brief IMAP FETCH Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note There are a handful of basic FETCH tests in test_imap,
 *       this test module specifically focuses on more extensively
 *       testing the various functionality in the FETCH command
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/sendfile.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#else
#error "sendfile API unavailable"
#endif

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

static int write_file_to_socket(int client, const char *filename)
{
	int fd;
	off_t offset, fsize;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
		return -1;
	}
	fsize = lseek(fd, 0, SEEK_END);
	offset = 0;
	bbs_debug(3, "Sending %s (%ld bytes)\n", filename, fsize);
	/* Assuming the file is small enough, it should succeed in one go,
	 * and bbs_sendfile wrapper isn't needed */
#ifdef __linux__
	if (sendfile(client, fd, &offset, (size_t) fsize) != fsize) {
#elif defined(__FreeBSD__)
	if (sendfile(client, fd, offset, (size_t) fsize, NULL, NULL, 0) != fsize) {
#else
#error "Missing sendfile"
#endif
		bbs_error("Failed to write file: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int send_count;

static int send_message(int client1, const char *filename)
{
	if (!send_count++) {
		CLIENT_EXPECT_EVENTUALLY(client1, "220 ");
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

	/* Note: Make sure these files end in CR LF.
	 * Otherwise it might get added when uploading to another IMAP server as a "fix-up"
	 * and that will throw some of the sizes off by 2. */
	if (write_file_to_socket(client1, filename)) {
		goto cleanup;
	}

	/* Messages end in CR LF, so only send . CR LF here */
	SWRITE(client1, "." ENDL); /* EOM */
	CLIENT_EXPECT(client1, "250");
	return 0;

cleanup:
	return -1;
}

static int send_short_message(int client1)
{
	if (!send_count++) {
		CLIENT_EXPECT_EVENTUALLY(client1, "220 ");
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

	/* Lengths include CR LF */
	SWRITE(client1, "Content-Type: text/plain" ENDL); /* 26 bytes */
	SWRITE(client1, "To: user@example.com" ENDL); /* 22 bytes */
	SWRITE(client1, "From: user@example.com" ENDL); /* 24 bytes */
	SWRITE(client1, "Subject: Test message" ENDL); /* 23 bytes */
	SWRITE(client1, "Sun, 10 Nov 2024 19:58:17 -0500" ENDL); /* 33 bytes */
	SWRITE(client1, ENDL); /* 2 bytes */
	SWRITE(client1, "Test" ENDL); /* 6 bytes */

	/* Messages end in CR LF, so only send . CR LF here */
	SWRITE(client1, "." ENDL); /* EOM */
	CLIENT_EXPECT(client1, "250");
	return 0;

cleanup:
	return -1;
}

static int make_messages(void)
{
	int clientfd;
	int res = 0;

	send_count = 0;
	clientfd = test_make_socket(25);
	if (clientfd < 0) {
		return -1;
	}

	res |= send_message(clientfd, "messages/multipart.eml");
	res |= send_message(clientfd, "messages/multipart2.eml");
	res |= send_message(clientfd, "messages/alternative.eml");
	res |= send_short_message(clientfd);

	close(clientfd); /* Close SMTP connection */
	return res;
}

static int run(void)
{
	int client1 = -1;
	int res = -1;

	if (make_messages()) {
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

	SWRITE(client1, "a2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a2 OK");

	SWRITE(client1, "b1 FETCH 1 (BODYSTRUCTURE)" ENDL);
	/* Actual BODYSTRUCTURE format may vary be server since they all do that differently... but certain things should ALWAYS appear verbatim */
	CLIENT_EXPECT_EVENTUALLY(client1, "_Part_17304_1769721302"); /* Hard to test with all the quotes, but just make sure it works at all */

	/* Length is an easy way to validate that the output is as expected.
	 * The lengths are taken from running the same tests against another IMAP server that should be compliant.
	 * Since net_imap prefixes all FETCH responses with the UID, we make sure to include that as well.
	 * We also test that when using BODY.PEEK, the message is never marked as soon,
	 * and that BODY.PEEK is not used in the response (should be BODY).
	 * Since the CR LF sequence might be written later, particularly for larger payloads,
	 * we don't include that in our EXPECT (though it should be there). */

	SWRITE(client1, "b2 FETCH 1 (BODY.PEEK[])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 BODY[] {1835}");

	SWRITE(client1, "b3 FETCH 1 (BODY.PEEK[1])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 BODY[1] {76}");

	SWRITE(client1, "b4 FETCH 1 (BODY.PEEK[2])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 BODY[2] {310}");

	SWRITE(client1, "b5 FETCH 1 (BODY.PEEK[3])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 BODY[3] {522}");

	SWRITE(client1, "b6 FETCH 1 (BODY.PEEK[1.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 BODY[1.MIME] {79}");

	SWRITE(client1, "b7 FETCH 1 (BODY.PEEK[2.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 BODY[2.MIME] {196}" ENDL);

	SWRITE(client1, "b8 FETCH 1 (BODY.PEEK[3.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 BODY[3.MIME] {70}");

	/* Request multiple things at once */
	SWRITE(client1, "c1 FETCH 1 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (Date Subject From To X-Priority Importance X-MSMail-Priority Priority)])" ENDL); /* actual FETCH command used by mod_webmail */

	/* Since we were only peeking, message should not have \Seen flag... it happens that the \Recent flag is set, so we're okay with that */
	SWRITE(client1, "c2 FETCH 1 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 FLAGS (\\Recent))");

	SWRITE(client1, "c3 FETCH 1 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (Date Subject From To X-Priority Importance X-MSMail-Priority Priority)])" ENDL); 
	CLIENT_EXPECT_EVENTUALLY(client1, "Priority)] {119}");

	/* Go ahead and mark it seen now */
	SWRITE(client1, "d1 FETCH 1 (BODY[])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "d1 OK");

	SWRITE(client1, "d2 FETCH 1 (FLAGS)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* 1 FETCH (UID 1 FLAGS (\\Seen \\Recent))" ENDL);

	/* Request multiple BODY things in the same command */
	SWRITE(client1, "d3 FETCH 1 (BODY[2.MIME] BODY[3.MIME])" ENDL);
	/* Since we don't have reliable readline, we can really only check for a single thing in response to a command, so need to check twice */
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[2.MIME] {196}");
	SWRITE(client1, "d4 FETCH 1 (BODY[2.MIME] BODY[3.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3.MIME] {70}");

	SWRITE(client1, "d5 FETCH 1 (BODY[HEADER.FIELDS (TO)] BODY[HEADER.FIELDS (SUBJECT CC)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Subject: Test");

	/* Message 2 contains a message/rfc822, so we can ask for the additional part specifiers that are specific to that: */
	SWRITE(client1, "e1 FETCH 1:2 (BODY.PEEK[1.MIME])" ENDL); /* Do 2 messages at once */
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.MIME] {78}");

	SWRITE(client1, "e2 FETCH 2 (BODY.PEEK[3])" ENDL); /* Part spec 3 is the subpart corresponding to a message/rfc822 */
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3] {429}");

	SWRITE(client1, "e3 FETCH 2 (BODY.PEEK[3.HEADER])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3.HEADER] {417}");

	SWRITE(client1, "e4 FETCH 2 (BODY.PEEK[3.TEXT])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3.TEXT] {8}");

	SWRITE(client1, "e5 FETCH 2 (BODY.PEEK[3.HEADER.FIELDS (TO SUBJECT)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3.HEADER.FIELDS (TO SUBJECT)] {39}");

	SWRITE(client1, "e6 FETCH 2 (FLAGS BODY.PEEK[3.HEADER.FIELDS (TO SUBJECT)] BODY.PEEK[3.HEADER.FIELDS (CC SUBJECT)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3.HEADER.FIELDS (CC SUBJECT)] {17}");
	SWRITE(client1, "e7 FETCH 2 (FLAGS BODY.PEEK[3.HEADER.FIELDS (TO SUBJECT)] BODY.PEEK[3.HEADER.FIELDS (CC SUBJECT)])" ENDL); /* Repeat to capture other one */
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3.HEADER.FIELDS (TO SUBJECT)] {39}");

	SWRITE(client1, "e8 FETCH 2 (BODY.PEEK[3.HEADER.FIELDS.NOT (TO CC SUBJECT)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[3.HEADER.FIELDS.NOT (TO CC SUBJECT)] {380}");

	/* The Received header in this message is multiline, and should all appear on a single line without CR LF inbetween
	 * This is true for HEADER.FIELDS/HEADER.FIELDS.NOT as well as just HEADER */
	SWRITE(client1, "e9 FETCH 2 (BODY.PEEK[3.HEADER.FIELDS.NOT (TO CC SUBJECT)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Received: from [10.1.1.1]\tby example.com");

	SWRITE(client1, "e10 FETCH 2 (BODY.PEEK[3.HEADER.FIELDS (Received To)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Received: from [10.1.1.1]\tby example.com");

	SWRITE(client1, "e11 FETCH 2 (BODY.PEEK[])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[] {1999}");

	SWRITE(client1, "f1 FETCH 3 (BODYSTRUCTURE)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "\"------------B56ACAA1D42503EF82F52166\"");

	SWRITE(client1, "f2 FETCH 3 (BODY.PEEK[])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[] {1671}");

	SWRITE(client1, "f3 FETCH 3 (RFC822.HEADER)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "RFC822.HEADER {494}");

	/* Obsoleted BODY[0] syntax. Defined in RFC 1730 but obsoleted by RFC 3501. Should be equivalent to getting the header. */
	SWRITE(client1, "f4 FETCH 3 (BODY.PEEK[0])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[0] {494}");

	SWRITE(client1, "f5 FETCH 3 (BODY.PEEK[1])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1] {714}");

	SWRITE(client1, "f6 FETCH 3 (BODY.PEEK[1.1])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.1] {101}");

	SWRITE(client1, "f7 FETCH 3 (BODY.PEEK[1.2])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.2] {319}");

	SWRITE(client1, "f8 FETCH 3 (BODY.PEEK[2])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[2] {36}");

	SWRITE(client1, "f9 FETCH 3 (BODY.PEEK[1.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.MIME] {88}");

	SWRITE(client1, "f10 FETCH 3 (BODY.PEEK[1.1.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.1.MIME] {91}");

	SWRITE(client1, "f11 FETCH 3 (BODY.PEEK[1.2.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.2.MIME] {75}");

	SWRITE(client1, "f12 FETCH 3 (BODY.PEEK[2.MIME])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[2.MIME] {161}");

	/* Nonexistent subpart */
	SWRITE(client1, "f13 FETCH 3 (BODY.PEEK[2.1])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[2.1] {0}");

	/* .TEXT isn't legal on non message/rfc822 subparts */
	SWRITE(client1, "g1 FETCH 2 (BODY.PEEK[1.TEXT])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.TEXT] {0}");
	SWRITE(client1, "g2 FETCH 3 (BODY.PEEK[1.TEXT])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[1.TEXT] {0}");

	/* Now, test partial fetches: */
	SWRITE(client1, "g3 FETCH 3 (BODY.PEEK[]<0>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[]<0> {1671}");

	SWRITE(client1, "g4 FETCH 3 (BODY.PEEK[]<2>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[]<2> {1669}"); /* start is 0-indexed, so this should be 2 smaller than entire body */

	SWRITE(client1, "g5 FETCH 3 (BODY.PEEK[]<2.3>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[]<2> {3}");

	SWRITE(client1, "g6 FETCH 3 (BODY.PEEK[]<0.9999>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[]<0> {1671}"); /* Should be truncated to available length */

	SWRITE(client1, "g7 FETCH 3 (BODY.PEEK[]<8.9999>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[]<8> {1663}");

	SWRITE(client1, "g8 FETCH 3 (BODY.PEEK[2]<1.4>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[2]<1> {4}");

	SWRITE(client1, "g9 FETCH 3 (BODY.PEEK[2]<1.4>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "GVzd");

	SWRITE(client1, "g10 FETCH 3 (BODY.PEEK[2]<25.15>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[2]<25> {11}");

	SWRITE(client1, "g11 FETCH 3 (BODY.PEEK[2]<25.15>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "WNobWVudA==");

	SWRITE(client1, "g12 FETCH 3 (BODY.PEEK[HEADER]<1.25>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "BODY[HEADER]<1> {25}");

	/* Use message 2, since it has a message/rfc822 attachment */
	SWRITE(client1, "g13 FETCH 2 (BODY.PEEK[3.HEADER.FIELDS (Content-Type)]<1.12>)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "ontent-Type:");

	/* Request RFC822.HEADER ([LBBS-85] bug fix) */
	CLIENT_DRAIN(client1);
	SWRITE(client1, "h1 FETCH 4 (UID RFC822.HEADER)" ENDL);
	CLIENT_EXPECT(client1, "* 4 FETCH (UID 4 RFC822.HEADER {130}");

	/* Ideally, we would be able to confirm that 130 bytes are actually received here...
	 * Since we can't, repeat, and ensure it's the headers, not the body. */

	CLIENT_DRAIN(client1);
	SWRITE(client1, "h2 FETCH 4 (UID RFC822.HEADER)" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "Content-Type");

	SWRITE(client1, "z999 LOGOUT" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "* BYE");
	res = 0;

cleanup:
	close_if(client1);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP FETCH Tests");
