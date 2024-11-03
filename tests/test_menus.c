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
 * \brief Menu Tests
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
	test_load_module("mod_menu_handlers.so");
	test_load_module("mod_node_callbacks.so");
	test_load_module("net_telnet.so");

	/* no net_telnet.conf needed, defaults are sufficient */
	TEST_ADD_CONFIG("menus.conf");
	TEST_ADD_CONFIG("nodes.conf");

	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;

	clientfd = test_make_socket(23);
	REQUIRE_FD(clientfd);

	/* We do not support ANSI, so wait out the ANSI handshake */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "ENTER");
	SWRITE(clientfd, "\r\n");

	if (test_client_expect_eventually(clientfd, SEC_MS(7), "ENTER", __LINE__)) {
		goto cleanup;
	}
	SWRITE(clientfd, "\r\n");

	/* Enter 'no', we do not support ANSI, nor are we slow */
	if (test_client_expect_eventually(clientfd, SEC_MS(7), "?", __LINE__)) {
		goto cleanup;
	}
	SWRITE(clientfd, "y");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "?");
	SWRITE(clientfd, "y");

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, " "); /* Hit a key */

	/* Must always use CLIENT_EXPECT_EVENTUALLY since our input is also echoed back to us */

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login");
	SWRITE(clientfd, TEST_USER "\n");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password");
	SWRITE(clientfd, TEST_PASS "\n");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "at welcome menu via T");
	CLIENT_DRAIN(clientfd);
	SWRITE(clientfd, " "); /* Hit a key */

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Main Menu");
	SWRITE(clientfd, "a"); /* Choose option 'a' */

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu A1");
	SWRITE(clientfd, "q"); /* Go back to main menu */

	/* Test submenu skip navigation */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Main Menu");
	SWRITE(clientfd, "/aa\n"); /* Go to the same submenu, and into the submenu A2 */

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Menu A2");
	SWRITE(clientfd, "qq"); /* Go back to main menu */

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Main Menu");

	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Menu Tests");
