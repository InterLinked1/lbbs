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
 * \brief Gopher Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#define TEST_GOPHER_DIR "/tmp/test_lbbs_gopherdir"

static int pre(void)
{
	test_load_module("net_gopher.so");

	TEST_ADD_CONFIG("net_gopher.conf");

	system("rm -rf " TEST_GOPHER_DIR); /* Purge the contents of the directory, if it existed. */
	mkdir(TEST_GOPHER_DIR, 0700); /* Make directory if it doesn't exist already (of course it won't due to the previous step) */
	mkdir(TEST_GOPHER_DIR "/testdir", 0700);
	/* Not efficient, but I feel lazy right now */
	system("echo 'This is a test page' > " TEST_GOPHER_DIR "/file1.txt");
	system("echo 'This is another test page' > " TEST_GOPHER_DIR "/file2.txt");
	return 0;
}

static int run(void)
{
	int clientfd = -1;
	int res = -1;

	clientfd = test_make_socket(70);
	REQUIRE_FD(clientfd);

	SWRITE(clientfd, ENDL); /* "List what you have" */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "1testdir");
	close_if(clientfd);

	clientfd = test_make_socket(70);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, ENDL); /* "List what you have" */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "0file1.txt");
	close_if(clientfd);

	clientfd = test_make_socket(70);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, ENDL); /* "List what you have" */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "0file2.txt");

	/* Try retrieving a file */
	clientfd = test_make_socket(70);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, "/file2.txt" ENDL);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "This is another test page");

	res = 0;

cleanup:
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Gopher Tests");
