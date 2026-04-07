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
	test_preload_module("mod_mimeparse.so");
	test_load_module("mod_irc_bouncer.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_smtp.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("transfers.conf");
	TEST_ADD_CONFIG("net_irc.conf");
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");

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
	int client1 = -1, client2 = -1, client3 = -1, clientfd = -1;
	int imapfd = -1;
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

	/* If there are trailing spaces in the message, they shouldn't appear in the bouncer log file / email */
	/* Should be in log something like:
	 * '2000-01-01 00:00:00 :testuser2!testuser2@node/2 PRIVMSG #bouncer-test2 :Test message ending in spaces<LF>' */
	SWRITE(client2, "PRIVMSG #bouncer-test2 :Test message ending in spaces         \r\n");

	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", -1); /* Shouldn't be any messages yet, in fact, the maildir doesn't even exist yet */

	imapfd = test_make_socket(143);
	REQUIRE_FD(imapfd);
	CLIENT_EXPECT(imapfd, "OK");
	SWRITE(imapfd, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT(imapfd, "a1 OK");
	SWRITE(imapfd, "a2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "a2 OK");

	TEST_DELIMIT(10, "User 1 joins #bouncer-test2, triggering email of missed message");
	SWRITE(client1, "JOIN #bouncer-test2\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #bouncer-test2");

	/* Now, we should have received an email... */
	SWRITE(imapfd, "a3 IDLE" ENDL);
	CLIENT_EXPECT(imapfd, "+");
	CLIENT_EXPECT(imapfd, "* 1 EXISTS");
	SWRITE(imapfd, "DONE" ENDL);

	SWRITE(imapfd, "a4 FETCH 1 (BODY[])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "ending in spaces" ENDL); /* Shouldn't be any spaces between "ending in spaces" and CR LF */

	SWRITE(client1, "QUIT :Hanging up\r\n");

	/* Now, reply to the message via email */
	clientfd = test_make_socket(587);
	REQUIRE_FD(clientfd);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "220 ");
	SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */

	/* Log in */
	SWRITE(clientfd, "AUTH PLAIN\r\n");
	CLIENT_EXPECT(clientfd, "334");
	SWRITE(clientfd, TEST_SASL "\r\n");
	CLIENT_EXPECT(clientfd, "235");

/* From mod_irc_bouncer */
#define IRC_BOUNCER_EMAIL_USER "ircbouncer"

	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">" ENDL);
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" IRC_BOUNCER_EMAIL_USER "@" TEST_HOSTNAME ">" ENDL);
	CLIENT_EXPECT(clientfd, "250");

	SWRITE(clientfd, "DATA" ENDL);
	CLIENT_EXPECT(clientfd, "354");

	SWRITE(clientfd, "Date: Thu, 21 May 1998 05:33:29 -0700" ENDL);
	SWRITE(clientfd, "From: <" TEST_EMAIL ">" ENDL);
	SWRITE(clientfd, "Subject: Re: You missed messages in #bouncertest2" ENDL);
	SWRITE(clientfd, "To: " IRC_BOUNCER_EMAIL_USER "@" TEST_HOSTNAME ENDL);
	SWRITE(clientfd, "Content-Type: text/plain; format=flowed" ENDL);
	SWRITE(clientfd, "In-Reply-To: <ircbouncer-0-0-#bouncer-test2@" TEST_HOSTNAME ">" ENDL); /* The only important piece is the channel name */
	SWRITE(clientfd, ENDL);
	SWRITE(clientfd, "This is a test reply via SMTP. This line is long enough that it should " ENDL);
	SWRITE(clientfd, "get unwrapped by the format=flowed line wrapping logic. " ENDL);
	SWRITE(clientfd, "The line continuations go on and on. " ENDL);
	SWRITE(clientfd, "We wrap even earlier than 72 characters, " ENDL);
	SWRITE(clientfd, "so the message needn't be as long." ENDL); /* Full message is under 512 */
	SWRITE(clientfd, "Now this, this is a second message!" ENDL);
	SWRITE(clientfd, "." ENDL); /* EOM */

	CLIENT_EXPECT(clientfd, "250");
	CLIENT_EXPECT(client2, "so the message needn't be as long"); /* Both lines should be part of one message */

	SWRITE(client2, "QUIT :Hanging up\r\n");

	/* Ensure we get our own PART notice if leaving channel */
	close_if(client1);
	TEST_DELIMIT(1, "User 1 connects again");
	client1 = test_make_socket(6667);
	REQUIRE_FD(client1);
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

	TEST_DELIMIT(2, "User 1 joins and leaves");
	SWRITE(client1, "JOIN #joinleave-test\r\n");
	CLIENT_EXPECT_EVENTUALLY(client1, "JOIN #joinleave-test");

	SWRITE(client1, "PART #joinleave-test\r\n");
	CLIENT_EXPECT(client1, "PART #joinleave-test");

	TEST_DELIMIT(1, "User 1 quits");
	close_if(client1);

	/* Using a real client, message a bouncer user (which is a programmatic user) and ensure that the bouncer user picks up the message
	 * This needs to work even if the user was in no channels at the time of quitting IRC */
	client3 = test_make_socket(6667);
	REQUIRE_FD(client3);

	SWRITE(client3, "CAP LS 302\r\n");
	SWRITE(client3, "NICK " TEST_USER3 ENDL);
	SWRITE(client3, "USER " TEST_USER3 ENDL);
	CLIENT_EXPECT_EVENTUALLY(client3, "CAP * LS");
	SWRITE(client3, "CAP REQ :sasl\r\n");
	CLIENT_EXPECT(client3, "CAP * ACK");
	SWRITE(client3, "AUTHENTICATE PLAIN\r\n");
	CLIENT_EXPECT(client3, "AUTHENTICATE +\r\n");
	SWRITE(client3, "AUTHENTICATE " TEST_SASL3 "\r\n");
	CLIENT_EXPECT(client3, "903");
	SWRITE(client3, "CAP END\r\n");

	CLIENT_EXPECT_EVENTUALLY(client3, "376 " TEST_USER3);

	TEST_DELIMIT(5, "User 3 sends a message to user 1");
	SWRITE(client3, "PRIVMSG " TEST_USER " :This is a delayed message\r\n");

	/* Rejoin as user 1, we should get the PM */
	client1 = test_make_socket(6667);
	REQUIRE_FD(client1);
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
	CLIENT_EXPECT_EVENTUALLY(client1, "This is a delayed message");

	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	close_if(client3);
	close_if(imapfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IRC Bouncer Tests");
