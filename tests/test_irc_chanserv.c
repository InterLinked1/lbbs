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
 * \brief IRC ChanServ Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static int pre(void)
{
	test_preload_module("mod_mysql.so");
	test_preload_module("net_irc.so");
	test_load_module("mod_chanserv.so");

	test_use_mysql(); /* Run the database for this test */

	TEST_ADD_CONFIG("mod_mysql.conf");
	TEST_ADD_CONFIG("mod_chanserv.conf");
	TEST_ADD_CONFIG("net_irc.conf");
	return 0;
}

static int irc_connect(void)
{
	int clientfd = test_make_socket(6667);
	REQUIRE_FD(clientfd);

	/* SASL negotiation */
	SWRITE(clientfd, "CAP LS 302\r\n");
	SWRITE(clientfd, "NICK " TEST_USER ENDL);
	SWRITE(clientfd, "USER " TEST_USER ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "CAP * LS");
	SWRITE(clientfd, "CAP REQ :sasl\r\n");
	CLIENT_EXPECT(clientfd, "CAP * ACK");
	SWRITE(clientfd, "AUTHENTICATE PLAIN\r\n");
	CLIENT_EXPECT(clientfd, "AUTHENTICATE +\r\n");
	SWRITE(clientfd, "AUTHENTICATE " TEST_SASL "\r\n");
	CLIENT_EXPECT(clientfd, "903");
	SWRITE(clientfd, "CAP END\r\n");

	CLIENT_EXPECT_EVENTUALLY(clientfd, "376"); /* End of MOTD */
	return clientfd;

cleanup:
	close_if(clientfd);
	return -1;
}

static int run(void)
{
	int client1;
	int res = -1;

	client1 = irc_connect();
	REQUIRE_FD(client1);

	SWRITE(client1, "JOIN #test1" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #test1");

	/* Register the channel with ChanServ */
	SWRITE(client1, "PRIVMSG ChanServ INFO #test1" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "#test1 is not registered");

	SWRITE(client1, "PRIVMSG ChanServ REGISTER #test1" ENDL);
	CLIENT_EXPECT(client1, "#test1 is now registered");

	SWRITE(client1, "PRIVMSG ChanServ HELP SET" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "End of Help");

	SWRITE(client1, "TOPIC #test1 :This is a test channel" ENDL);
	CLIENT_EXPECT(client1, "This is a test channel");

	/* Enable GUARD so the channel persists with no regular users in it */
	SWRITE(client1, "PRIVMSG ChanServ SET #test1 GUARD ON" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "The GUARD flag has been set for channel #test1");

	/* Reconnect and try to OP ourselves */
	close(client1);

	usleep(1000); /* Wait a moment */

	client1 = irc_connect();
	REQUIRE_FD(client1);

	/* Topic should have persisted */
	SWRITE(client1, "TOPIC #test1" ENDL);
	CLIENT_EXPECT(client1, "This is a test channel");

	SWRITE(client1, "JOIN #test1" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #test1");

	SWRITE(client1, "PRIVMSG ChanServ OP #test1" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "MODE #test1 +o");

	SWRITE(client1, "QUIT :Hanging up\r\n");
	res = 0;

cleanup:
	close_if(client1);
	return res;
}

TEST_MODULE_INFO_STANDARD("IRC ChanServ Tests");
