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
 * \brief SMTP Delivery Status Notification (DSN) Tests
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
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("mod_smtp_delivery_external.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_SUBCONFIG("dsn", "net_smtp.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	ADD_TO_HOSTS_FILE(TEST_EMAIL_EXTERNAL_OUTGOING_BOUNCE_DOMAIN, "127.0.0.1");
	return 0;
}

static int handshake(int clientfd, int reset)
{
	if (reset) {
		/* We should be able to reset at any point without losing our authenticated state, or needing to re-HELO/EHLO */
		SWRITE(clientfd, "RSET" ENDL);
		CLIENT_EXPECT(clientfd, "250");
	} else {
		CLIENT_EXPECT_EVENTUALLY(clientfd, "220 ");
		SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
		CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	}
	return 0;
cleanup:
	return -1;
}

static int run(void)
{
	int clientfd;
	int res = -1;
	int attempts;

	clientfd = test_make_socket(587);
	REQUIRE_FD(clientfd);

	if (handshake(clientfd, 0)) {
		goto cleanup;
	}

	/* Log in */
	SWRITE(clientfd, "AUTH PLAIN\r\n");
	CLIENT_EXPECT(clientfd, "334");
	SWRITE(clientfd, TEST_SASL "\r\n");
	CLIENT_EXPECT(clientfd, "235");
	if (handshake(clientfd, 1)) {
		goto cleanup;
	}

	/* Send email to a domain that is not defined in mod_mail.conf, so it should result in
	 * a permanent bounce since mail for that domain isn't accepted here.
	 * We don't use static_relays in net_smtp.conf, since otherwise when we try sending it,
	 * it will just use the static route in a loop. Instead, the domain is added to the hosts file. */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL_EXTERNAL_OUTGOING_BOUNCE ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (test_send_sample_body(clientfd, TEST_EMAIL)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "250"); /* Outgoing messages are queued so we'll get a 250 response, even though delivery will eventually fail */

	/* Verify that we received the bounce. */
	for (attempts = 0; attempts < 40 && test_dir_file_count(TEST_MAIL_DIR "/1/new") != 1; attempts++) {
		usleep(25000); /* Rather than needing an IMAP connection to see we received the DSN message, just poll mailbox for new message count on disk */
	}
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1);

	res = 0;

cleanup:
	close(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("SMTP DSN Tests");
