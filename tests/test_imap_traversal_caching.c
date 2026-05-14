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
 * \brief IMAP Traversal Caching Tests
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
	test_preload_module("mod_lmdb.so");
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

	CREATE_IMAP_CONNECTION(clientfd, TEST_USER, TEST_PASS);
	SELECT_MAILBOX(clientfd, "a2", "INBOX");

	if (test_make_messages(TEST_EMAIL, 5)) { /* Now have 5 messages in INBOX */
		return -1;
	}

	/* Note that none of these tests here actually verify that caching is used,
	 * i.e. the tests will (should) still pass if mod_lmdb is not loaded.
	 * However, if caching *is* used, they do ensure it works correctly,
	 * as if no caching were used. */

	SWRITE(clientfd, "b1 NOOP" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "b1 OK"); /* Flush the untagged EXISTS/RECENT messages from message delivery */

	SWRITE(clientfd, "c1 COPY 1:5 \"Trash\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "c1 OK"); /* Now have 5 messages in Trash */

	SWRITE(clientfd, "c2 COPY 1:5 \"Trash\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "c2 OK"); /* Now have 10 messages in Trash */

	SWRITE(clientfd, "c3 COPY 1:5 \"Trash\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "c3 OK"); /* Now have 15 messages in Trash */

	SELECT_MAILBOX(clientfd, "d1", "Trash");

	SWRITE(clientfd, "d2 SELECT \"INBOX\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "5 EXISTS");

	/* This traversal should be cached */
	SWRITE(clientfd, "d3 SELECT \"Trash\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "15 EXISTS");

	SWRITE(clientfd, "d4 STORE 1 +FLAGS \\Seen" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "d4 OK"); /* Still have 15 messages in Trash, but only 14 unread */

	/* This traversal should not be cached */
	SWRITE(clientfd, "d5 LIST (SUBSCRIBED) \"\" (\"Trash\") RETURN (STATUS (MESSAGES UNSEEN RECENT SIZE))" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* STATUS \"Trash\" (MESSAGES 15 RECENT 0 UNSEEN 14 SIZE 3270");

	/* This traversal should be cached */
	SWRITE(clientfd, "d6 SELECT \"Trash\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "15 EXISTS");

	/* As should this one */
	SWRITE(clientfd, "d7 LIST (SUBSCRIBED) \"\" (\"INBOX\") RETURN (STATUS (MESSAGES UNSEEN RECENT SIZE))" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* STATUS \"INBOX\" (MESSAGES 5 RECENT 0 UNSEEN 5 SIZE 1090");

	if (test_make_messages(TEST_EMAIL, 1)) {
		return -1;
	}

	/* This traversal is still cached, since there are only new messages (cur is unchanged) */
	SWRITE(clientfd, "e1 LIST (SUBSCRIBED) \"\" (\"INBOX\") RETURN (STATUS (MESSAGES UNSEEN RECENT SIZE))" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* STATUS \"INBOX\" (MESSAGES 6 RECENT 1 UNSEEN 6 SIZE 1308");

	/* Delete a message in the trash, which will increment MODSEQ. */
	SWRITE(clientfd, "e2 STORE 1:2 +FLAGS \\Deleted" ENDL);
	SWRITE(clientfd, "e3 EXPUNGE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* 1 EXPUNGE");

	/* ... so this traversal should not be cached. */
	SWRITE(clientfd, "e4 LIST (SUBSCRIBED) \"\" (\"Trash\") RETURN (STATUS (MESSAGES UNSEEN RECENT SIZE))" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* STATUS \"Trash\" (MESSAGES 13 RECENT 0 UNSEEN 13 SIZE 2834");

	/* LOGOUT */
	SWRITE(clientfd, "z1 LOGOUT" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "* BYE");
	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP Traversal Caching Tests");
