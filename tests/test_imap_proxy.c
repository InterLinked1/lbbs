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
 * \brief IMAP Client Proxy Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "email.h"
#include "tls.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

/* Note: This test really tests three things at once:
 * 1. First and foremost, client proxy functionality works as expected.
 * 2. The bbs_tcp_client behavior (which is not used by any of the other tests at this time)
 * 3. TLS clients (via bbs_tcp_client) (test_ftps, for example, only tests TLS server behavior in the BBS)
 */

static int pre(void)
{
	test_preload_module("io_tls.so");
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_imap.so");
	test_load_module("mod_mail_events.so");

	TEST_REQUIRE_FILE("/etc/ssl/private/ssl-cert-snakeoil.key"); /* Not all platforms have it and we don't create it */

	TEST_ADD_CONFIG("tls.conf");
	TEST_ADD_CONFIG("transfers.conf"); /* So we can use home directory configs */
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_SUBCONFIG("tls", "net_imap.conf"); /* Enable IMAPS */
	TEST_ADD_CONFIG("mod_mail_events.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);

	/* Install the sample .imapremote file in user 1's config directory */
	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	TEST_MKDIR(TEST_HOME_DIR_ROOT);
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1/.config");
	TEST_ADD_CONFIG_INTO_DIR(".imapremote", TEST_HOME_DIR_ROOT "/1/.config");
	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;
	SSL *ssl = NULL;

	if (test_make_messages(TEST_EMAIL2, 2)) {
		return -1;
	}

	/* Verify that the email messages were all sent properly. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/2/new", send_count);

	clientfd = test_make_socket(993); /* Use IMAPS port */
	REQUIRE_FD(clientfd);

	/* Implicit TLS */
	ssl = tls_client_new(clientfd);
	REQUIRE_SSL(ssl);

	/* Connect and log in */
	TLS_CLIENT_EXPECT(ssl, "OK");
	TLS_SWRITE(ssl, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	TLS_CLIENT_EXPECT(ssl, "a1 OK");

	/* Yes... it's a bit silly, using the proxy functionality to access a local mailbox, rather than a remote one.
	 * In real life, this mailbox's ACL would just allow direct access.
	 * But, hey, it works, and it's great for testing! */
	TLS_SWRITE(ssl, "a2 LIST \"\" \"*\"" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "Other Users.testuser2.INBOX");

	TLS_SWRITE(ssl, "a3 SELECT \"Other Users.testuser2.INBOX\"" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a3 OK");

	/* There should be two messages here
	 * We use STORE since FETCH will return OK even if no messages were fetched */
	TLS_SWRITE(ssl, "a4 STORE 2 +FLAGS ($Important)" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a4 OK");

	/* Test a COPY operation */
	TLS_SWRITE(ssl, "a5 COPY 1 \"Other Users.testuser2.Trash\"" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a5 OK");

	/* Now, that message should exist there as well... */
	TLS_SWRITE(ssl, "a6 SELECT \"Other Users.testuser2.Trash\"" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a6 OK");

	TLS_SWRITE(ssl, "a7 STORE 1 +FLAGS ($Important)" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a7 OK");

	/* Now, do a STATUS */
	TLS_SWRITE(ssl, "a8 STATUS \"Other Users.testuser2.INBOX\" (UNSEEN)" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "* STATUS \"Other Users.testuser2.INBOX\" (UNSEEN 2)"); /* The returned name should be in the pre-proxy format */

	/* Test a case that previously had a bug.
	 * If we SELECT the INBOX, then SELECT a proxied folder,
	 * and a new message is delivered to the local INBOX,
	 * that would previously be triggered as if the currently selected mailbox had a new message,
	 * even though at most, it should trigger a STATUS with NOTIFY enabled. */
	TLS_SWRITE(ssl, "a9 NOTIFY SET (SELECTED-DELAYED (MessageNew MessageExpunge FlagChange)) (personal (MessageNew MessageExpunge)) (subtree \"Other Users\" (MessageNew (FLAGS) MessageExpunge MailboxName FlagChange))" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a9 OK");

	TLS_SWRITE(ssl, "a10 SELECT INBOX" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a10 OK");

	TLS_SWRITE(ssl, "a11 SELECT \"Other Users.testuser2.INBOX\"" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a11 OK");

	TLS_SWRITE(ssl, "a12 IDLE" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "+");

	if (test_make_messages(TEST_EMAIL, 1)) {
		goto cleanup;
	}

	/* We should get notified about this, but with a STATUS, not an EXISTS */
	TLS_CLIENT_EXPECT(ssl, "* STATUS \"INBOX\"");

	TLS_SWRITE(ssl, "DONE" ENDL);

	TLS_SWRITE(ssl, "z999 LOGOUT" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "* BYE");
	res = 0;

cleanup:
	if (ssl) {
		SSL_SHUTDOWN(ssl);
	}
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP Proxy Tests");
