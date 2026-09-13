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
 * \brief IMAP TLS Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "tls.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static int pre(void)
{
	test_preload_module("io_tls.so");
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_imap.so");
	test_load_module("net_smtp.so");

	TEST_ADD_CONFIG("tls.conf");
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_SUBCONFIG("smtp_large", "net_smtp.conf");
	TEST_ADD_SUBCONFIG("tls", "net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);

	/* Not all platforms have it and we don't create it.
	 * On Debian, can run 'apt-get install ssl-cert' if this cert pair is missing. */
	TEST_REQUIRE_FILE("/etc/ssl/private/ssl-cert-snakeoil.key");

	return 0;
}

static int send_message(int client1)
{
	char date[42], subject[32];
	static int send_count = 0;
	int i;

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

	snprintf(date, sizeof(date), "Date: Sun, 1 Jan 2023 01:01:01 -0700" ENDL);
	write(client1, date, strlen(date));
	SWRITE(client1, "From: " TEST_EMAIL_EXTERNAL ENDL);
	snprintf(subject, sizeof(subject), "Subject: Message %d" ENDL, send_count);
	write(client1, subject, strlen(subject));

	SWRITE(client1, "To: " TEST_EMAIL ENDL);
	SWRITE(client1, "Content-Type: text/plain" ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "This is the beginning of a test email message." ENDL);
	for (i = 0; i < 450000; i++) {
		/* Each line is 31 bytes (including CR LF), so 31 * 150,000 = ~4.65 MB */
		SWRITE(client1, "This is a test email message." ENDL);
	}
	SWRITE(client1, "This is the end of a test email message." ENDL);
	SWRITE(client1, "." ENDL); /* EOM */
	CLIENT_EXPECT(client1, "250");
	return 0;

cleanup:
	return -1;
}

static int send_messages(void)
{
	int clientfd = -1;
	int res = 0;
	int num_messages = 2;

	clientfd = test_make_socket(25);
	REQUIRE_FD_RETURN(clientfd);

	while (num_messages--) {
		res |= send_message(clientfd);
		if (res) {
			break;
		}
	}

	close(clientfd);
	return res;
}

static int run(void)
{
	SSL *ssl = NULL;
	int clientfd = -1;
	int res = -1;

	if (send_messages()) {
		goto cleanup;
	}

	clientfd = test_make_socket(993);
	REQUIRE_FD(clientfd);

	/* Connect and immediately set up TLS */
	ssl = tls_client_new(clientfd);
	REQUIRE_SSL(ssl);

	/* Log in */
	TLS_CLIENT_EXPECT(ssl, "* OK [CAPABILITY");
	TLS_SWRITE(ssl, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a1 OK");

	TLS_SWRITE(ssl, "a2 ID (\"name\" \"lbbs.test.client\" \"version\" \"" BBS_VERSION "\" NIL)" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a2 OK");

	TLS_SWRITE(ssl, "a3 SELECT INBOX" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a3 OK");

	TLS_SWRITE(ssl, "a4 FETCH 1 (BODY[])" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "This is the end of a test email message.");

	TLS_SWRITE(ssl, "a5 FETCH 1 (RFC822.SIZE INTERNALDATE BODY[])" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a5 OK");

	TLS_SWRITE(ssl, "a6 FETCH 1 (BODY[])" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "This is the beginning of a test email message.");
	/* Stop reading here, which should lead to the I/O pipes for TLS getting filled with the remainder of the (large) message */

	usleep(1000 * SEC_MS(2));

	/* Test passes as long as we get here and exit, without any errors (e.g. soft assertions) */
	res = 0;

cleanup:
	if (res) {
		test_get_live_backtrace();
	}
	SSL_SHUTDOWN(ssl);
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP TLS Tests");
