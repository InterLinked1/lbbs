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
 * \brief IRC Bouncer Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/* This should match whether this is defined in mod_irc_bouncer */
#define USE_REAL_NICK_WHEN_POSSIBLE

static int pre(void)
{
	/* Don't load mod_chanserv.so since we don't want to muck with any channel registrations on this server */
	test_preload_module("net_irc.so");
	test_preload_module("mod_mail.so");
	test_load_module("mod_irc_bouncer.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_smtp.so");

	TEST_ADD_CONFIG("transfers.conf");
	TEST_ADD_CONFIG("net_irc.conf");
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);

	/* Install .bouncer in user 1's config directory */
	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	TEST_MKDIR(TEST_HOME_DIR_ROOT);
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1/.config");
	TEST_ADD_CONFIG_INTO_DIR(".bouncer", TEST_HOME_DIR_ROOT "/1/.config");

	return 0;
}

#define TEST_DELIMIT(ms, title) \
	usleep(1000 * ms); \
	bbs_debug(1, "--------------------- %s ---------------------\n", title);

static int run(void)
{
	int client1 = -1, client2 = -1;
	int res = -1;

	client1 = test_make_socket(6667);
	REQUIRE_FD(client1);

	client2 = test_make_socket(6667);
	REQUIRE_FD(client2);

	/* SASL negotiation */
	SWRITE(client2, "CAP LS 302\r\n");
	SWRITE(client2, "NICK " TEST_USER2 ENDL);
	SWRITE(client2, "USER " TEST_USER2 ENDL);
	CLIENT_EXPECT_EVENTUALLY(client2, "CAP * LS");
	SWRITE(client2, "CAP REQ :sasl\r\n");
	CLIENT_EXPECT(client2, "CAP * ACK");
	SWRITE(client2, "AUTHENTICATE PLAIN\r\n");
	CLIENT_EXPECT(client2, "AUTHENTICATE +\r\n");
	SWRITE(client2, "AUTHENTICATE " TEST_SASL2 "\r\n");
	CLIENT_EXPECT(client2, "903");
	SWRITE(client2, "CAP END\r\n");

	CLIENT_EXPECT_EVENTUALLY(client2, "376"); /* End of MOTD */

	TEST_DELIMIT(1, "User 2 messages user 1, who is not yet connected");
#ifdef USE_REAL_NICK_WHEN_POSSIBLE
	SWRITE(client2, "PRIVMSG " TEST_USER " :Are you around?\r\n"); /* Bouncer should save message */
#else
	SWRITE(client2, "PRIVMSG " TEST_USER "_ :Are you around?\r\n"); /* Bouncer should save message */
#endif

	TEST_DELIMIT(1, "User 1 connects");

	/* SASL negotiation */
	SWRITE(client1, "CAP LS 302\r\n");
	SWRITE(client1, "NICK " TEST_USER ENDL);
	SWRITE(client1, "USER " TEST_USER ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "CAP * LS");
	SWRITE(client1, "CAP REQ :sasl\r\n");
	CLIENT_EXPECT(client1, "CAP * ACK");
	SWRITE(client1, "AUTHENTICATE PLAIN\r\n");
	CLIENT_EXPECT(client1, "AUTHENTICATE +\r\n");
	SWRITE(client1, "AUTHENTICATE " TEST_SASL "\r\n");
	CLIENT_EXPECT(client1, "903");
	SWRITE(client1, "CAP END\r\n");

	/* Now, without doing anything, the message user 2 sent earlier should get replayed */
	CLIENT_EXPECT_EVENTUALLY(client1, "Are you around?");

	TEST_DELIMIT(1, "Users join channels");
	SWRITE(client1, "JOIN #bouncer-test\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #bouncer-test");

	SWRITE(client2, "JOIN #bouncer-test\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #bouncer-test");
	CLIENT_EXPECT_EVENTUALLY(client2, "JOIN #bouncer-test");

	/* Okay, user 1 and user 2 are now both in #bouncer-test,
	 * a channel for which the bouncer is enabled for user 1. */

	/* Messages within a channel should reach the other guy */
	SWRITE(client1, "PRIVMSG #bouncer-test :Hello world!\r\n");
	CLIENT_EXPECT_EVENTUALLY(client2, "PRIVMSG #bouncer-test :Hello world!");

	/* Now, user 1 drops, which will active his bouncer */
	TEST_DELIMIT(1, "User 1 drops, triggering bouncer to join");

	SWRITE(client1, "PART #bouncer-test\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "PART #bouncer-test");
#ifndef USE_REAL_NICK_WHEN_POSSIBLE
	CLIENT_EXPECT_EVENTUALLY(client2, "PART #bouncer-test");
#endif

	TEST_DELIMIT(5, "Bouncer now in the channel"); /* Give time for the bouncer to join the channel */

	/* Bouncer should now be running */
	SWRITE(client2, "PRIVMSG #bouncer-test :Hello there!\r\n");
	usleep(2500);
	SWRITE(client2, "PRIVMSG #bouncer-test :Where did you go?\r\n");
	usleep(2500);
	SWRITE(client2, "PRIVMSG #bouncer-test :Come back!\r\n");

	TEST_DELIMIT(3, "User 1 rejoins"); /* Wait for the message to process so user 1 won't receive a message that, just by luck, was still being processed */

	/* Now, user 1 rejoins, and the message he missed should get replayed */
	SWRITE(client1, "JOIN #bouncer-test\r\n");
#ifndef USE_REAL_NICK_WHEN_POSSIBLE
	CLIENT_EXPECT_EVENTUALLY(client2, "JOIN #bouncer-test");
#endif
	CLIENT_EXPECT_EVENTUALLY(client1, "Where did you go?"); /* Timestamp will be prepended so just look for the message itself */

	/* Drop and rejoin, logs shouldn't be flushed back to us.
	 * We should, moreover, get a JOIN (just to us, if USE_REAL_NICK_WHEN_POSSIBLE is defined, or to everyone otherwise, but to us nonetheless). */
	TEST_DELIMIT(3, "User 1 leaves #bouncer-test again");
	SWRITE(client1, "PART #bouncer-test\r\n");
	CLIENT_EXPECT(client1, "PART #bouncer-test");

	/* User 2 does a WHOIS on the bouncer user */
	TEST_DELIMIT(3, "User 2 does a WHOIS on user 1's bouncer user");
	SWRITE(client2, "WHO #bouncer-test\r\n");
	CLIENT_EXPECT_EVENTUALLY(client2, "315");

	SWRITE(client2, "WHOIS " TEST_USER "_\r\n");
	CLIENT_EXPECT_EVENTUALLY(client2, "318");

	TEST_DELIMIT(1, "User 1 rejoins again");
	SWRITE(client1, "JOIN #bouncer-test\r\n");
	CLIENT_EXPECT(client1, "JOIN #bouncer-test");
#ifndef USE_REAL_NICK_WHEN_POSSIBLE
	CLIENT_EXPECT_EVENTUALLY(client2, "JOIN #bouncer-test");
#endif
	CLIENT_EXPECT_EVENTUALLY(client1, "366 " TEST_USER);

	TEST_DELIMIT(5, "User 1 leaves #bouncer-test for good");
	SWRITE(client1, "PART #bouncer-test\r\n");
	CLIENT_EXPECT(client1, "PART #bouncer-test"); /* Shouldn't have received any queued messages, they should have been deleted when flushed before */

	TEST_DELIMIT(1, "User 2 joins #bouncer-test2 and sends a message");
	SWRITE(client2, "JOIN #bouncer-test2\r\n");
	CLIENT_EXPECT_EVENTUALLY(client2, "JOIN #bouncer-test2");

	SWRITE(client2, "PRIVMSG #bouncer-test2 :This message is going to get emailed. It will get emailed to user 1 upon joining the channel, "
		"since interactive mode is disabled. It's longer than 72 characters, so it will get wrapped as well.\r\n");

	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", -1); /* Shouldn't be any messages yet, in fact, the maildir doesn't even exist yet */

	TEST_DELIMIT(10, "User 1 joins #bouncer-test2, triggering email of missed message");
	SWRITE(client1, "JOIN #bouncer-test2\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #bouncer-test2");

	usleep(100000); /* We need to wait a good bit for the message to get delivered */

	/* Now, we should have received an email... (here, we cheat and just check the maildir, so we don't need to establish an IMAP or POP3 connection) */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", 1); /* Should now have a message */

	SWRITE(client1, "QUIT :Hanging up\r\n");
	SWRITE(client2, "QUIT :Hanging up\r\n");
	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	return res;
}

TEST_MODULE_INFO_STANDARD("IRC Bouncer Tests");
