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
 * \brief IRC Relay Tests
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
	/* Don't load mod_chanserv.so since we don't want to muck with any channel registrations on this server */
	test_preload_module("net_irc.so");
	test_preload_module("door_irc.so");
	test_load_module("mod_relay_irc.so");

	TEST_ADD_CONFIG("net_irc.conf");
	TEST_ADD_CONFIG("door_irc.conf");
	TEST_ADD_CONFIG("mod_relay_irc.conf");
	return 0;
}

static int run(void)
{
	int client1, client2 = -1;
	int res = -1;

	client1 = test_make_socket(6667);
	if (client1 < 0) {
		return -1;
	}

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

	CLIENT_EXPECT_EVENTUALLY(client1, "376"); /* End of MOTD */

	SWRITE(client1, "JOIN #test1\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #test1");

	client2 = test_make_socket(6667);
	if (client2 < 0) {
		goto cleanup;
	}

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

	SWRITE(client2, "JOIN #test2\r\n");
	CLIENT_EXPECT_EVENTUALLY(client2, "JOIN #test2");

	/* Okay, user 1 is now connected to #test1 and user 2 is connected to #test2
	 * Per mod_relay_irc.conf, these channels are set up as a relay pair.
	 * So messages sent to one channel should be received by users in the other. */

	/* Messages within a channel should reach the other guy */
	SWRITE(client1, "PRIVMSG #test1 :Hello world!\r\n");
	CLIENT_EXPECT_EVENTUALLY(client2, ":" TEST_USER "!" "IRC@IRC/" TEST_USER " PRIVMSG #test2 :Hello world!");

	/* Test the other direction as well */
	SWRITE(client2, "PRIVMSG #test2 :Hello there!\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, ":" TEST_USER2 "!" "IRC@IRC/" TEST_USER2 " PRIVMSG #test1 :Hello there!");

	SWRITE(client1, "QUIT :Hanging up\r\n");
	SWRITE(client2, "QUIT :Hanging up\r\n");
	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	return res;
}

TEST_MODULE_INFO_STANDARD("IRC Relay Tests");
