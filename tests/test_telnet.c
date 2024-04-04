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
 * \brief Telnet Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int pre(void)
{
	test_load_module("net_telnet.so");
	/* no net_telnet.conf needed, defaults are sufficient */
	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;
	unsigned int i = 0;

	/* Fuzz the Telnet server with arbitrary data and ensure it doesn't crash */
	/* Try invalid commands */
	for (i = 0; i < 255; i++) {
		unsigned char data[] = { (unsigned char) i, 250, (unsigned char) i };
		clientfd = test_make_socket(23);
		REQUIRE_FD(clientfd);
		write(clientfd, data, 3);
		close_if(clientfd);
	}
	/* Try invalid options */
	for (i = 0; i < 255; i++) {
		unsigned char data[] = { 255, 250, (unsigned char) i };
		clientfd = test_make_socket(23);
		REQUIRE_FD(clientfd);
		write(clientfd, data, 3);
		close_if(clientfd);
	}

	res = 0;

	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Telnet Tests");
