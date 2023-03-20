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
 * \brief Finger Tests
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
	test_preload_module("mod_mail.so");
	test_load_module("net_finger.so");

	TEST_ADD_CONFIG("net_finger.conf");

	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;

	/* List all users */
	clientfd = test_make_socket(79);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, TEST_USER);
	close_if(clientfd);

	/* List a specific user */
	clientfd = test_make_socket(79);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, TEST_USER ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, TEST_USER);
	close_if(clientfd);

	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Finger Tests");
