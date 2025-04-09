/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Email Message Generation
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "email.h"

#include <stdio.h>
#include <string.h>

int send_count = 0;

int test_send_sample_body(int clientfd, const char *from)
{
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");
	/* From RFC 5321. The actual content is completely unimportant. No, it doesn't matter at all that the From address doesn't match the envelope.
	 * Note that messages from localhost are always passed by SPF, so although we don't disable the SPF addon, it's not very meaningful either way for this test. */
	SWRITE(clientfd, "Date: Thu, 21 May 1998 05:33:29 -0700" ENDL);
	SWRITE(clientfd, "From: ");
	write(clientfd, from, strlen(from));
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "Subject: The Next Meeting of the Board" ENDL);
	SWRITE(clientfd, "To: Jones@xyz.com" ENDL);
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "Bill:" ENDL);
	SWRITE(clientfd, "The next meeting of the board of directors will be" ENDL);
	SWRITE(clientfd, "on Tuesday." ENDL);
	SWRITE(clientfd, "....See you there!" ENDL); /* Test byte stuffing. This should not end message receipt! */
	SWRITE(clientfd, "John." ENDL);
	SWRITE(clientfd, "." ENDL); /* EOM */
	return 0;

cleanup:
	return -1;
}

int test_send_message_with_extra_bytes(int clientfd, const char *recipient, size_t extrabytes)
{
	char linebuf[64];
	int len;

	if (!send_count++) {
		CLIENT_EXPECT_EVENTUALLY(clientfd, "220 ");
		SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
		CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	} else {
		SWRITE(clientfd, "RSET" ENDL);
		CLIENT_EXPECT(clientfd, "250");
	}

	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");

	len = snprintf(linebuf, sizeof(linebuf), "RCPT TO:<%s>\r\n", recipient);
	write(clientfd, linebuf, (size_t) len);

	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "DATA\r\n");
	CLIENT_EXPECT(clientfd, "354");

	SWRITE(clientfd, "Date: Sun, 1 Jan 2023 05:33:29 -0700" ENDL);
	SWRITE(clientfd, "From: " TEST_EMAIL_EXTERNAL ENDL);

	len = snprintf(linebuf, sizeof(linebuf), "Subject: Message %d" ENDL, send_count);
	write(clientfd, linebuf, (size_t) len);

	len = snprintf(linebuf, sizeof(linebuf), "To: %s" ENDL, recipient);
	write(clientfd, linebuf, (size_t) len);

	SWRITE(clientfd, "Content-Type: text/plain" ENDL);
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "This is a test email message." ENDL);
	SWRITE(clientfd, "....Let's hope it gets delivered properly." ENDL); /* Test byte stuffing */
	if (extrabytes) {
		extrabytes = MIN(sizeof(linebuf), extrabytes);
		memset(linebuf, 'a', extrabytes);
		write(clientfd, linebuf, extrabytes);
		SWRITE(clientfd, ENDL);
	}
	SWRITE(clientfd, "." ENDL); /* EOM */
	CLIENT_EXPECT(clientfd, "250");
	return 0;

cleanup:
	return -1;
}

int test_make_messages(const char *recipient, int nummsg)
{
	int clientfd;
	int res = 0;

	send_count = 0; /* Reset, if we already sent messages previously, since this will be a new SMTP session */

	clientfd = test_make_socket(25);
	if (clientfd < 0) {
		return -1;
	}

	/* First, dump some messages into the mailbox for us to retrieve */
	while (send_count < nummsg) {
		res |= test_send_message(clientfd, recipient);
	}
	close(clientfd); /* Close SMTP connection */

	return res;
}
