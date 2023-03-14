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
 * \brief IRC Server Tests
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
	test_add_module("net_irc.so");

	TEST_ADD_CONFIG("net_irc.conf");
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

	/* Join some channels */
	SWRITE(client1, "JOIN #test1,#test2,#test3\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "MODE #test3 +oq testuser"); /* Nobody else was in these channels */

	/* All right, now for some real fun... multi-user */
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

	/* Join some channels */
	SWRITE(client2, "JOIN #test1,#test2,#test4\r\n"); /* Some shared channels, some not */
	CLIENT_EXPECT_EVENTUALLY(client2, "MODE #test4 +oq testuser"); /* Nobody else was in that last channel */

	/* Messages within a channel should reach the other guy */
	SWRITE(client1, "PRIVMSG #test1 :Hello world!\r\n");
	CLIENT_EXPECT(client2, ":" TEST_USER "!" TEST_USER "@node/1 PRIVMSG #test1 :Hello world!");

	/* Send message to a channel we're not in (or rather more, doesn't exist). */
	SWRITE(client1, "PRIVMSG #test4 :This is a message that will not be delivered.\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "442"); /* Not on that channel */

	/* Channel operators can kick users */
	SWRITE(client1, "KICK #test1 " TEST_USER2 ENDL);
	CLIENT_EXPECT(client1, "KICK");

	/* But not the other way around */
	SWRITE(client2, "KICK #test2 " TEST_USER ENDL);
	CLIENT_EXPECT_EVENTUALLY(client2, "482"); /* Not a channel operator */

	/* On the other hand, if somebody OPERs, it's a totally different ballgame. */
	SWRITE(client2, "OPER " TEST_USER2 " " TEST_PASS2 ENDL);
	CLIENT_EXPECT(client2, "381"); /* Now an IRC operator, bwahaha */

	/* IRC operators can kick ANYONE */
	SWRITE(client2, "KICK #test2 " TEST_USER ENDL);
	CLIENT_EXPECT(client2, "482"); /* Well, not yet. We can make ourselves an operator though and THEN kick anyone. */
	SWRITE(client2, "MODE #test2 +o " TEST_USER2 ENDL);
	CLIENT_EXPECT(client2, "MODE #test2 +o " TEST_USER2);
	SWRITE(client2, "KICK #test2 " TEST_USER ENDL);
	CLIENT_EXPECT(client2, "KICK"); /* Now the kick should work */

	/* Client 1 joins #test1 again, so that both users have at least one common channel */
	SWRITE(client1, "JOIN #test2\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #test2");

	/* Leave a channel */
	SWRITE(client2, "PART #test2\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "PART #test2"); /* Other guy should get the part message */

	/* These tests below are not very robust... they basically just ensure that something happens and the server doesn't crash. */
	SWRITE(client1, "LIST\r\n"); /* Get channel list */
	CLIENT_EXPECT_EVENTUALLY(client1, "323");
	SWRITE(client2, "ISON " TEST_USER "\r\n"); /* Check if another user is online */
	CLIENT_EXPECT_EVENTUALLY(client2, "303");

	/*! \note These tests are meant to run quite fast, so there is no handling for server PINGs.
	 * since we wouldn't get a ping while the tests are running anyways.
	 * However, we can certainly test sending a PING from *OUR* side, as we should get a PONG reply in return. */
	SWRITE(client1, "PING :hello\r\n");
	CLIENT_EXPECT(client1, "PONG :hello");

	/* Client 2 joins channel so there's a common channel to see the quit message following */
	SWRITE(client2, "JOIN #test1\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #test1");

	/* Client 1 quits for good. */
	SWRITE(client1, "QUIT :Hanging up\r\n");
	CLIENT_EXPECT_EVENTUALLY(client2, "QUIT"); /* Other guy should get the quit since there's a channel in common. */

	res = 0;

cleanup:
	close(client1);
	close_if(client2);
	return res;
}

TEST_MODULE_INFO_STANDARD("IRC Server Tests");
