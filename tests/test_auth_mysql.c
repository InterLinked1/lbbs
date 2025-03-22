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
 * \brief MySQL User Registration/Authentication Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "ansi.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

extern int use_static_auth;

static int pre(void)
{
	test_preload_module("mod_mysql.so");
	test_load_module("mod_auth_mysql.so");
	test_load_module("mod_menu_handlers.so");
	test_load_module("mod_node_callbacks.so");
	test_load_module("net_telnet.so");

	test_use_mysql(); /* Run the database for this test */
	use_static_auth = 0; /* Use database for authentication, don't load mod_auth_static */

	/* no net_telnet.conf needed, defaults are sufficient */
	TEST_ADD_CONFIG("menus.conf");
	TEST_ADD_CONFIG("mod_mysql.conf");
	TEST_ADD_CONFIG("mod_auth_mysql.conf");
	return 0;
}

static int run(void)
{
	int clientfd;
	int res = -1;

	clientfd = test_make_socket(23);
	REQUIRE_FD(clientfd);

	if (test_ansi_handshake(clientfd)) {
		goto cleanup;
	}

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, " "); /* Hit a key */

#define CRLF "\r\n"

	/* New User */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login:");
	SWRITE(clientfd, "New");
	SWRITE(clientfd, CRLF); /* CR NUL -> CR logic in pty.c only handles if the sequence is by itself */

	CLIENT_EXPECT_EVENTUALLY(clientfd, "full real name");
	SWRITE(clientfd, "John Smith");
	SWRITE(clientfd, CRLF);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "username");
	SWRITE(clientfd, TEST_USER);
	SWRITE(clientfd, CRLF);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password");
	SWRITE(clientfd, TEST_PASS);
	SWRITE(clientfd, CRLF);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Confirm Password");
	SWRITE(clientfd, TEST_PASS);
	SWRITE(clientfd, CRLF);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Network mail address");
	SWRITE(clientfd, TEST_EMAIL);
	SWRITE(clientfd, CRLF);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "City");
	SWRITE(clientfd, "Anytown");
	SWRITE(clientfd, CRLF);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "State");
	SWRITE(clientfd, "NY");
	SWRITE(clientfd, CRLF);

	CLIENT_EXPECT_EVENTUALLY(clientfd, "information correct?");
	SWRITE(clientfd, "y");

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Registration successful");
	SWRITE(clientfd, " ");

	/* Now, log in fresh */
	close(clientfd);
	clientfd = test_make_socket(23);
	REQUIRE_FD(clientfd);

	if (test_ansi_handshake(clientfd)) {
		goto cleanup;
	}

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, " "); /* Hit a key */

	/* Must always use CLIENT_EXPECT_EVENTUALLY since our input is also echoed back to us */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login");
	SWRITE(clientfd, TEST_USER "\n");

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password");
	SWRITE(clientfd, TEST_PASS "\n");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "at welcome menu via T");

	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("MySQL User Authentication Tests");
