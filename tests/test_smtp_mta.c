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
 * \brief SMTP Mail Transfer Agent Tests
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

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");

	system("rm -rf " TEST_MAIL_DIR); /* Purge the contents of the directory, if it existed. */
	mkdir(TEST_MAIL_DIR, 0700); /* Make directory if it doesn't exist already (of course it won't due to the previous step) */
	return 0;
}

static int send_body(int clientfd)
{
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");
	/* From RFC 5321. The actual content is completely unimportant. No, it doesn't matter at all that the From address doesn't match the envelope.
	 * Note that messages from localhost are always passed by SPF, so although we don't disable the SPF addon, it's not very meaningful either way for this test. */
	SWRITE(clientfd, "Date: Thu, 21 May 1998 05:33:29 -0700" ENDL);
	SWRITE(clientfd, "From: John Q. Public <JQP@bar.com>" ENDL);
	SWRITE(clientfd, "Subject: The Next Meeting of the Board" ENDL);
	SWRITE(clientfd, "To: Jones@xyz.com" ENDL);
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "Bill:" ENDL);
	SWRITE(clientfd, "The next meeting of the board of directors will be" ENDL);
	SWRITE(clientfd, "on Tuesday." ENDL);
	SWRITE(clientfd, "....See you there!" ENDL); /* Test byte stuffing. This should not end message receipt! */
	SWRITE(clientfd, "John." ENDL);
	SWRITE(clientfd, "." ENDL); /* EOM */
	CLIENT_EXPECT(clientfd, "250");
	return 0;

cleanup:
	return -1;
}

static int run(void)
{
	int clientfd;
	int i, res = -1;

	clientfd = test_make_socket(25);
	if (clientfd < 0) {
		return -1;
	}

	CLIENT_EXPECT(clientfd, "220");

	/* Try doing invalid things */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "503"); /* HELO/EHLO first */
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "503"); /* HELO/EHLO first */

	/* Now stop messing around and start for real */
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */

	/* Try sending a message that's advertised as too big */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL "> SIZE=500001\r\n");
	CLIENT_EXPECT(clientfd, "552");

	/* Try sending from a domain that's blacklisted. */
	SWRITE(clientfd, "MAIL FROM:<test@example.org> SIZE=400000\r\n");
	CLIENT_EXPECT(clientfd, "554"); /* Blacklisted domain */

	/* Start over */
	SWRITE(clientfd, "RSET\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 ");

	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");

	/* Try an external recipient */
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "550"); /* Mail relay denied */

	/* Try a local recipient that doesn't exist. */
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL_NONEXISTENT ">\r\n");
	CLIENT_EXPECT(clientfd, "550"); /* No such user */

	/* Try a local recipient (that exists) this time */
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");

	/* Send the body */
	if (send_body(clientfd)) {
		goto cleanup;
	}

	/* Verify that the email message actually exists on disk. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);

	/* Send another message, but this time to an alias, and with an acceptable size. */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL "> SIZE=100000\r\n"); /* Not the real size but it doesn't matter */
	CLIENT_EXPECT(clientfd, "250");

	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL_ALIAS ">\r\n");
	CLIENT_EXPECT(clientfd, "250");

	/* Send the body */
	if (send_body(clientfd)) {
		goto cleanup;
	}

	/* Verify that the email message actually exists on disk. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 2);

	/* Ensure mail loops are prevented */
	SWRITE(clientfd, "RSET" ENDL);
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 ");
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");
	SWRITE(clientfd, "Date: Thu, 21 May 1998 05:33:29 -0700" ENDL);
	for (i = 0; i < 55; i++) {
		SWRITE(clientfd, "Received: from foobar.example.com" ENDL);
	}
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "Test" ENDL);
	SWRITE(clientfd, "." ENDL); /* EOM */
	CLIENT_EXPECT(clientfd, "554"); /* Mail loop detected */

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("SMTP MTA Tests");
