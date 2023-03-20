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
 * \brief HTTP Server Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#define TEST_WWW_DIR "/tmp/test_lbbs_www"

static int pre(void)
{
	test_load_module("net_http.so");

	TEST_ADD_CONFIG("net_http.conf");

	system("rm -rf " TEST_WWW_DIR); /* Purge the contents of the directory, if it existed. */
	mkdir(TEST_WWW_DIR, 0700); /* Make directory if it doesn't exist already (of course it won't due to the previous step) */
	mkdir(TEST_WWW_DIR "/testdir", 0700);
	/* Not efficient, but I feel lazy right now */
	system("echo 'This is a test page' > " TEST_WWW_DIR "/file1.txt");
	system("echo 'This is another test page' > " TEST_WWW_DIR "/file2.txt");
	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;

	/* The HTTP server is running on (non standard) port 8080.
	 * In a clean testing environment, it should be okay to bind on port 80,
	 * but Apache is already listening on port 80 on this machine here, so avoid conflicting with that. */

	clientfd = test_make_socket(8080);
	REQUIRE_FD(clientfd);

	SWRITE(clientfd, "GET / HTTP/1.1" ENDL);
	SWRITE(clientfd, ENDL); /* End of headers */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "file2.txt");
	CLIENT_DRAIN(clientfd);
	close_if(clientfd);

	clientfd = test_make_socket(8080);
	REQUIRE_FD(clientfd);

	/* XXX It would be significantly more rigorous to read the response line by line and, after the headers, make an exact comparison of the entire body */

	SWRITE(clientfd, "GET /file1.txt HTTP/1.1" ENDL);
	SWRITE(clientfd, "Connection: keep-alive" ENDL);
	SWRITE(clientfd, ENDL); /* End of headers */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "This is a test page");
	CLIENT_DRAIN(clientfd);

	/* Test connection reuse */
	SWRITE(clientfd, "GET /file2.txt HTTP/1.1" ENDL);
	SWRITE(clientfd, "Connection: keep-alive" ENDL);
	SWRITE(clientfd, ENDL); /* End of headers */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "This is another test page");
	CLIENT_DRAIN(clientfd);

	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("HTTP Server Tests");
