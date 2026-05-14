/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief HTTP Proxy Server Tests
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
	test_preload_module("mod_http.so");
	test_load_module("mod_http_proxy.so");
	test_load_module("net_http.so");

	TEST_ADD_CONFIG("net_http.conf");
	TEST_ADD_CONFIG("mod_http_proxy.conf");

	TEST_RESET_MKDIR(TEST_WWW_DIR);

	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;

	/* Test open proxy functionality.
	 * Use HTTP/1.0 to make sure we handle that properly. */
	clientfd = test_make_socket(8080);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, "GET http://127.0.0.1:80/test.txt HTTP/1.0" ENDL);
	SWRITE(clientfd, ENDL); /* End of headers */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "404");
	close_if(clientfd);

	/* Test an actual proxy connection.
	 * Nobody is authorized to proxy, so we should get a 403 */
	clientfd = test_make_socket(8080);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, "CONNECT http://127.0.0.1:80/test.txt HTTP/1.0" ENDL);
	SWRITE(clientfd, ENDL); /* End of headers */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "403");

	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("HTTP Proxy Server Tests");
