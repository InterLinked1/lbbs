/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Terminal Emulator Compatibility Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <arpa/telnet.h>

static int pre(void)
{
	test_load_module("mod_node_callbacks.so"); /* To consume EVENT_NODE_INTERACTIVE_START, prompt for ENTER */
	test_load_module("mod_menu_handlers.so");
	test_load_module("net_rlogin.so");
	test_load_module("net_telnet.so");

	TEST_ADD_CONFIG("menus.conf");
	TEST_ADD_CONFIG("nodes.conf");
	TEST_ADD_CONFIG("net_telnet.conf");

	return 0;
}

#define SETUP_TEST(port) \
	clientfd = test_make_socket(port); \
	REQUIRE_FD(clientfd);

#define FINALIZE_TEST() \
	close_if(clientfd);

#define FMT_EXPECT(fmt, ...) \
	sprintf(tmpbuf, fmt, ## __VA_ARGS__); \
	CLIENT_EXPECT_EVENTUALLY(clientfd, tmpbuf);

#define FMT_SEND(fmt, ...) \
	bytes = sprintf(tmpbuf, fmt, ## __VA_ARGS__); \
	write(clientfd, tmpbuf, (size_t) bytes);

#define SEND_CURSOR_POS(n, m) \
	bytes = sprintf(tmpbuf, "\e[%d;%dR", n, m); \
	write(clientfd, tmpbuf, (size_t) bytes);

#define TELNET_EOL "\r\0" /* CR NUL */
#define CRLF "\r\n"
#define EOL "\r"

#define TDD_EOL() \
	SWRITE(clientfd, "\r"); \
	SWRITE(clientfd, "\n"); \
	SWRITE(clientfd, "\r");

#define RLOGIN_HANDSHAKE(clientuser, serveruser, termtype_speed) \
	bytes = sprintf(tmpbuf, "%c%s%c%s%c%s%c", 0, clientuser, 0, serveruser, 0, termtype_speed, 0); \
	write(clientfd, tmpbuf, (size_t) bytes);

static char tmpbuf[64];
static int bytes;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-contains-nul"

static int ansi_handshake(int clientfd)
{
	FMT_EXPECT(TERM_CURSOR_POS_QUERY);
	SEND_CURSOR_POS(3, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_RESET_LINE */
	SEND_CURSOR_POS(6, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_UP_ONE_LINE */
	SEND_CURSOR_POS(5, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_COLOR_GREEN */
	SEND_CURSOR_POS(5, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_TITLE_FMT */
	SEND_CURSOR_POS(5, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_CURSOR_POS_SET_FMT */
	SEND_CURSOR_POS(4, 6);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_CLEAR */
	SEND_CURSOR_POS(1, 1);

	return 0;

cleanup:
	return -1;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;

	clientfd = test_make_socket(23);
	REQUIRE_FD(clientfd);

	/* This test aims to emulate a variety of popular terminal emulators
	 * with the various terminal protocols, to ensure basic compatibility
	 * for line endings and other things that vary by both of these dimensions.
	 *
	 * For example, for telnet, several combinations of line endings are used:
	 * - SyncTERM uses CR NUL
	 * - KiTTY uses CR LF
	 * - qodem uses just CR
	 *
	 * In all of these tests, we log in and go to the 'u' submenu and look for 'Test Token' in the output.
	 *
	 * To capture what is received at the PTY layer, define DUMP_PTY_INPUT in pty.c,
	 * capture the outputs to a logfile, and then dump them using 'hexdump -C'.
	 * Note that this dump output does not include protocol-specific negotiation. */

	/* KiTTY, Telnet */
	SETUP_TEST(23);
	FMT_EXPECT("%c%c%c", IAC, WONT, TELOPT_LINEMODE);
	FMT_SEND("%c%c%c", IAC, WILL, TELOPT_NAWS); /* Offer to send dimensions, before responding to anything */
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_NAWS);
	/* KiTTY doesn't respond with dimensions at this point */
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_NAWS); /* Server asks again */
	FMT_SEND("%c%c%c%c%c%d%d%c%c", IAC, SB, TELOPT_NAWS, 0, 80, 0, 24, IAC, SE);
	FMT_EXPECT("%c%c%c", IAC, DONT, TELOPT_NAWS);
	FMT_SEND("%c%c%c", IAC, WONT, TELOPT_NAWS);
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_TTYPE);
	/* KiTTY doesn't respond to term type request */
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_TSPEED);
	/* KiTTY doesn't respond to speed request */
	/* KiTTY never acknowledged echo settings, so retry now: */
	FMT_EXPECT("%c%c%c", IAC, WILL, TELOPT_ECHO); /* WONT then WILL */
	FMT_SEND("%c%c%c", IAC, DONT, TELOPT_ECHO);
	FMT_SEND("%c%c%c", IAC, DO, TELOPT_ECHO);

	if (ansi_handshake(clientfd)) {
		goto cleanup;
	}

	/* KiTTY uses CR LF line endings */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, CRLF); /* Press a key */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login:");
	SWRITE(clientfd, TEST_USER4);
	SWRITE(clientfd, CRLF); /* CR NUL -> CR logic in pty.c only handles if the sequence is by itself */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password:");
	SWRITE(clientfd, TEST_PASS4);
	SWRITE(clientfd, CRLF);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, CRLF);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu U");
	SWRITE(clientfd, "u");
	FMT_EXPECT("Test Token");
	SWRITE(clientfd, "qqy"); /* Logout cleanly for fast test exit */
	FINALIZE_TEST();

	/* SyncTERM, Telnet */
	SETUP_TEST(23);
	FMT_EXPECT("%c%c%c", IAC, WONT, TELOPT_LINEMODE);
	FMT_SEND("%c%c%c", IAC, DO, TELOPT_ECHO); /* Acknowledge local echo disable */
	FMT_SEND("%c%c%c", IAC, DO, TELOPT_SGA); /* Acknowledge suppress go ahead */
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_TTYPE);
	FMT_SEND("%c%c%c", IAC, WILL, TELOPT_TTYPE);
	FMT_EXPECT("%c%c%c%c%c%c", IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE);
	FMT_SEND("%c%c%c%c%s%c%c", IAC, SB, TELOPT_TTYPE, TELQUAL_IS, "syncterm", IAC, SE);
	FMT_SEND("%c%c%c", IAC, WILL, TELOPT_NAWS); /* Proactive offer to send terminal dimensions */
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_NAWS);
	FMT_SEND("%c%c%c%c%c%d%d%c%c", IAC, SB, TELOPT_NAWS, 0, 80, 0, 24, IAC, SE);
	FMT_EXPECT("%c%c%c", IAC, DONT, TELOPT_NAWS);
	FMT_SEND("%c%c%c", IAC, WONT, TELOPT_NAWS);
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_TSPEED);
	FMT_SEND("%c%c%c", IAC, WONT, TELOPT_TSPEED);

	if (ansi_handshake(clientfd)) {
		goto cleanup;
	}

	/* SyncTERM uses CR NUL line endings */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, TELNET_EOL); /* Press a key */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login:");
	SWRITE(clientfd, TEST_USER4);
	SWRITE(clientfd, TELNET_EOL); /* CR NUL -> CR logic in pty.c only handles if the sequence is by itself */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password:");
	SWRITE(clientfd, TEST_PASS4);
	SWRITE(clientfd, TELNET_EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, TELNET_EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu U");
	SWRITE(clientfd, "u");
	FMT_EXPECT("Test Token");
	SWRITE(clientfd, "qqy"); /* Logout cleanly for fast test exit */
	FINALIZE_TEST();

	/* qodem, Telnet */
	SETUP_TEST(23);
	FMT_EXPECT("%c%c%c", IAC, WONT, TELOPT_LINEMODE);
	FMT_SEND("%c%c%c", IAC, DO, TELOPT_BINARY); /* qodem offers binary with both DO and WILL, strange... */
	FMT_SEND("%c%c%c", IAC, WILL, TELOPT_BINARY);
	/* Server ignores binary option */
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_TTYPE);
	FMT_SEND("%c%c%c", IAC, WILL, TELOPT_TTYPE);
	FMT_EXPECT("%c%c%c%c%c%c", IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE);
	FMT_SEND("%c%c%c%c%s%c%c", IAC, SB, TELOPT_TTYPE, TELQUAL_IS, "xterm", IAC, SE);
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_NAWS);
	FMT_SEND("%c%c%c%c%c%d%d%c%c", IAC, SB, TELOPT_NAWS, 0, 80, 0, 24, IAC, SE);
	FMT_EXPECT("%c%c%c", IAC, DONT, TELOPT_NAWS);
	/* Client does not acknowledge */
	FMT_EXPECT("%c%c%c", IAC, DO, TELOPT_TSPEED);
	FMT_SEND("%c%c%c", IAC, WILL, TELOPT_TSPEED);
	FMT_EXPECT("%c%c%c%c%c%c", IAC, SB, TELOPT_TSPEED, TELQUAL_SEND, IAC, SE);
	FMT_SEND("%c%c%c%c%s%c%c", IAC, SB, TELOPT_TSPEED, TELQUAL_IS, "38400,38400", IAC, SE);

	if (ansi_handshake(clientfd)) {
		goto cleanup;
	}

	/* qodem uses CR line endings */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL); /* Press a key */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login:");
	SWRITE(clientfd, TEST_USER4 EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password:");
	SWRITE(clientfd, TEST_PASS4 EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu U");
	SWRITE(clientfd, "u");
	FMT_EXPECT("Test Token");
	SWRITE(clientfd, "qqy"); /* Logout cleanly for fast test exit */
	FINALIZE_TEST();

	/* KiTTY, RLogin */
	SETUP_TEST(513);
	RLOGIN_HANDSHAKE("", TEST_USER4, "xterm/38400");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "\0");

	if (ansi_handshake(clientfd)) {
		goto cleanup;
	}

	SWRITE(clientfd, "80" EOL "24" EOL); /* Since net_rlogin currently fails to get window dimensions, enter manually */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL); /* Press a key */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login:");
	SWRITE(clientfd, TEST_USER4 EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password:");
	SWRITE(clientfd, TEST_PASS4 EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu U");
	SWRITE(clientfd, "u");
	FMT_EXPECT("Test Token");
	SWRITE(clientfd, "qqy"); /* Logout cleanly for fast test exit */
	FINALIZE_TEST();

	/* SyncTERM, RLogin, without password preconfigured */
	SETUP_TEST(513);
	RLOGIN_HANDSHAKE("", TEST_USER4, "syncterm/115200");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "\0");

	if (ansi_handshake(clientfd)) {
		goto cleanup;
	}

	SWRITE(clientfd, "80" EOL "24" EOL); /* Since net_rlogin currently fails to get window dimensions, enter manually */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL); /* Press a key */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login:");
	SWRITE(clientfd, TEST_USER4 EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password:");
	SWRITE(clientfd, TEST_PASS4 EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu U");
	SWRITE(clientfd, "u");
	FMT_EXPECT("Test Token");
	SWRITE(clientfd, "qqy"); /* Logout cleanly for fast test exit */
	FINALIZE_TEST();

	/* SyncTERM, RLogin, with password preconfigured */
	SETUP_TEST(513);
	RLOGIN_HANDSHAKE(TEST_PASS4, TEST_USER4, "syncterm/115200");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "\0");

	if (ansi_handshake(clientfd)) {
		goto cleanup;
	}

	/* Since net_rlogin currently fails to get window dimensions, send here: */
	SWRITE(clientfd, "80" EOL "24" EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL); /* Press a key */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, EOL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu U");
	SWRITE(clientfd, "u");
	FMT_EXPECT("Test Token");
	SWRITE(clientfd, "qqy"); /* Logout cleanly for fast test exit */
	FINALIZE_TEST();

	/* TDD test */
	SETUP_TEST(2245);
	FMT_EXPECT("key");
	SWRITE(clientfd, " "); /* Press a key */
	FMT_EXPECT("Login");
	SWRITE(clientfd, "TERMTEST"); /* TDDs only send all caps... */
	TDD_EOL();
	FMT_EXPECT("Password");
	SWRITE(clientfd, TEST_PASS4); /* ... which is why the password is intentionally all caps */
	TDD_EOL();
	FMT_EXPECT("key");
	SWRITE(clientfd, " "); /* Hit a key */
	FMT_EXPECT("Opt");
	SWRITE(clientfd, "u");
	FMT_EXPECT("Opt"); /* TDD options aren't printed, so won't see it, but should be there */
	SWRITE(clientfd, "qqy"); /* Logout cleanly for fast test exit */
	close_if(clientfd);

#pragma GCC diagnostic pop

/*
Raw logs with DUMP_PTY_INPUT:

SyncTERM, telnet

00000000  1b 5b 33 3b 31 52 1b 5b  36 3b 31 52 1b 5b 35 3b  |.[3;1R.[6;1R.[5;|
00000010  31 52 1b 5b 35 3b 31 52  1b 5b 35 3b 31 52 1b 5b  |1R.[5;1R.[5;1R.[|
00000020  34 3b 36 52 1b 5b 31 3b  31 52 0d 00 74 65 72 6d  |4;6R.[1;1R..term|
00000030  74 65 73 74 0d 00 54 45  52 4d 50 41 53 53 0d 00  |test..TERMPASS..|
00000040  0d 00 75                                          |..u|
00000043

SyncTERM, rlogin

00000000  1b 5b 33 3b 31 52 1b 5b  36 3b 31 52 1b 5b 35 3b  |.[3;1R.[6;1R.[5;|
00000010  31 52 1b 5b 35 3b 31 52  1b 5b 35 3b 31 52 1b 5b  |1R.[5;1R.[5;1R.[|
00000020  34 3b 36 52 1b 5b 31 3b  31 52 38 30 0d 32 34 0d  |4;6R.[1;1R80.24.|
00000030  0d 74 65 72 6d 74 65 73  74 0d 54 45 52 4d 50 41  |.termtest.TERMPA|
00000040  53 53 0d 0d 75                                    |SS..u|
00000045

KiTTY, telnet

00000000  1b 5b 33 3b 31 52 1b 5b  36 3b 31 52 1b 5b 35 3b  |.[3;1R.[6;1R.[5;|
00000010  31 52 1b 5b 35 3b 31 52  1b 5b 35 3b 31 52 1b 5b  |1R.[5;1R.[5;1R.[|
00000020  34 3b 36 52 1b 5b 31 3b  31 52 0d 0a 74 65 72 6d  |4;6R.[1;1R..term|
00000030  74 65 73 74 0d 0a 54 45  52 4d 50 41 53 53 0d 0a  |test..TERMPASS..|
00000040  0d 0a 75                                          |..u|
00000043

KiTTY, rlogin

00000000  1b 5b 33 3b 31 52 1b 5b  36 3b 31 52 1b 5b 35 3b  |.[3;1R.[6;1R.[5;|
00000010  31 52 1b 5b 35 3b 31 52  1b 5b 35 3b 31 52 1b 5b  |1R.[5;1R.[5;1R.[|
00000020  34 3b 36 52 1b 5b 31 3b  31 52 38 30 0d 32 34 0d  |4;6R.[1;1R80.24.|
00000030  0d 74 65 72 6d 74 65 73  74 0d 54 45 52 4d 50 41  |.termtest.TERMPA|
00000040  53 53 0d 0d 75                                    |SS..u|
00000045

KiTTY, SSH (authenticate as part of protocol)

00000000  1b 5b 33 3b 31 52 1b 5b  36 3b 31 52 1b 5b 35 3b  |.[3;1R.[6;1R.[5;|
00000010  31 52 1b 5b 35 3b 31 52  1b 5b 35 3b 31 52 1b 5b  |1R.[5;1R.[5;1R.[|
00000020  34 3b 36 52 1b 5b 31 3b  31 52 0d 0d 75           |4;6R.[1;1R..u|
0000002d

qodem, telnet

00000000  1b 5b 33 3b 31 52 1b 5b  36 3b 31 52 1b 5b 35 3b  |.[3;1R.[6;1R.[5;|
00000010  31 52 1b 5b 35 3b 31 52  1b 5b 35 3b 31 52 1b 5b  |1R.[5;1R.[5;1R.[|
00000020  34 3b 36 52 1b 5b 31 3b  31 52 0d 74 65 72 6d 74  |4;6R.[1;1R.termt|
00000030  65 73 74 0d 54 45 52 4d  50 41 53 53 0d 0d 75     |est.TERMPASS..u|
0000003f

Superprint 4425 TDD, telnet (TDD mode)
2 spaces (x20) are at "press a key" prompts

Each time we hit ENTER, we receive CR LF CR

00000000  20 54 45 52 4d 54 45 53  54 0d 0a 0d 54 45 52 4d  | TERMTEST...TERM|
00000010  50 41 53 53 0d 0a 0d 20  55                       |PASS... U|
00000019
*/

	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Terminal Emulator Tests");
