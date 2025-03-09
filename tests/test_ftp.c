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
 * \brief FTP Tests
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
	test_load_module("net_ftp.so");

	TEST_ADD_CONFIG("transfers.conf");
	TEST_ADD_CONFIG("net_ftp.conf");

	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	return 0;
}

static int new_pasv(int client1)
{
	char buf[256];
	char *h1, *h2, *h3, *h4, *p1, *p2;
	int port;
	int client2;

	SWRITE(client1, "PASV" ENDL);
	CLIENT_EXPECT_BUF(client1, "227", buf);
	p2 = buf;
	h1 = strsep(&p2, ",");
	h2 = strsep(&p2, ",");
	h3 = strsep(&p2, ",");
	h4 = strsep(&p2, ",");
	p1 = strsep(&p2, ",");
	if (strlen_zero(h1) || strlen_zero(h2) || strlen_zero(h3) || strlen_zero(h4) || strlen_zero(p1) || strlen_zero(p2)) {
		bbs_error("Failed to get valid data connection info\n");
		goto cleanup;
	}

	/* Ignore the hostname and just use the port */
	port = atoi(p1) * 256 + atoi(p2);
	client2 = test_make_socket(port);
	return client2;

cleanup:
	return -1;
}

static int run(void)
{
	int client1 = -1, client2 = -1;
	int pasv = -1;
	int res = -1;

	/* Open control connection */
	client1 = test_make_socket(21);
	REQUIRE_FD(client1);

	CLIENT_EXPECT(client1, "220");
	SWRITE(client1, "USER " TEST_USER ENDL);
	CLIENT_EXPECT(client1, "331");
	SWRITE(client1, "PASS " TEST_PASS ENDL);
	CLIENT_EXPECT(client1, "230");

	/* By default, should be in home directory after authenticating */
	SWRITE(client1, "PWD" ENDL);
	CLIENT_EXPECT(client1, "/home/" TEST_USER);

	/* Explicitly set current directory to root */
	SWRITE(client1, "CWD /" ENDL);
	CLIENT_EXPECT(client1, "250");

	SWRITE(client1, "PWD" ENDL);
	CLIENT_EXPECT(client1, "257 \"/\"");

	SWRITE(client1, "MKD test" ENDL);
	CLIENT_EXPECT(client1, "250");
	SWRITE(client1, "MKD test" ENDL);
	CLIENT_EXPECT(client1, "450"); /* Directory already exists */
	SWRITE(client1, "CWD test" ENDL);
	CLIENT_EXPECT(client1, "250");

	SWRITE(client1, "NOOP" ENDL);
	CLIENT_EXPECT(client1, "200");

	SWRITE(client1, "HELP" ENDL);
	CLIENT_EXPECT(client1, "211");
	CLIENT_DRAIN(client1);

	client2 = new_pasv(client1); /* Open a data connection */
	REQUIRE_FD(client2);
	SWRITE(client1, "STOR foobar.txt" ENDL);
	CLIENT_EXPECT(client1, "150");
	SWRITE(client2, "Hello world\r\nGoodbye world\r\n");
	close_if(client2);
	CLIENT_EXPECT(client1, "226");

	client2 = new_pasv(client1);
	REQUIRE_FD(client2);
	SWRITE(client1, "LIST" ENDL);
	CLIENT_EXPECT(client1, "125");
	CLIENT_EXPECT_EVENTUALLY(client2, "foobar");
	CLIENT_DRAIN(client1);
	CLIENT_DRAIN(client2);
	close_if(client2);

	/* STOR should truncate... */
	client2 = new_pasv(client1); /* Open a data connection */
	REQUIRE_FD(client2);
	SWRITE(client1, "STOR foobar.txt" ENDL);
	CLIENT_EXPECT(client1, "150");
	SWRITE(client2, "Goodbye world\r\nHello world\r\n");
	close_if(client2);
	CLIENT_EXPECT(client1, "226");

	/* ...Read back the file we put. */
	client2 = new_pasv(client1);
	REQUIRE_FD(client2);
	SWRITE(client1, "RETR foobar.txt" ENDL);
	CLIENT_EXPECT(client1, "150");
	CLIENT_EXPECT(client2, "Goodbye world\r\nHello world\r\n");
	close_if(client2);
	CLIENT_EXPECT(client1, "226");

	/* Append to the same file... */
	client2 = new_pasv(client1);
	REQUIRE_FD(client2);
	SWRITE(client1, "APPE foobar.txt" ENDL);
	CLIENT_EXPECT(client1, "150");
	SWRITE(client2, "You say hello, I say goodbye\r\n");
	close_if(client2);
	CLIENT_EXPECT(client1, "226");

	/* ...Read it back */
	client2 = new_pasv(client1);
	REQUIRE_FD(client2);
	SWRITE(client1, "TYPE I" ENDL); /* Binary mode */
	CLIENT_EXPECT(client1, "200");
	SWRITE(client1, "RETR foobar.txt" ENDL);
	CLIENT_EXPECT(client1, "150");
	CLIENT_EXPECT(client2, "Goodbye world\r\nHello world\r\nYou say hello, I say goodbye\r\n");
	close_if(client2);
	CLIENT_EXPECT(client1, "226");

	/* Rename the file */
	SWRITE(client1, "RNFR foobar.txt" ENDL);
	CLIENT_EXPECT(client1, "226");
	SWRITE(client1, "RNTO foobar2.txt" ENDL);
	CLIENT_EXPECT(client1, "226");

	/* Delete the file */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_TRANSFER_DIR "/test", 1);
	SWRITE(client1, "DELE foobar2.txt" ENDL);
	CLIENT_EXPECT(client1, "226");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_TRANSFER_DIR "/test", 0);

	SWRITE(client1, "CWD /" ENDL);
	CLIENT_EXPECT(client1, "250");
	SWRITE(client1, "RMD test" ENDL);
	CLIENT_EXPECT(client1, "250");

	/* User 2 logs in, to create its home directory */
	client2 = test_make_socket(21);
	REQUIRE_FD(client2);
	CLIENT_EXPECT(client2, "220");
	SWRITE(client2, "USER " TEST_USER2 ENDL);
	CLIENT_EXPECT(client2, "331");
	SWRITE(client2, "PASS " TEST_PASS2 ENDL);
	CLIENT_EXPECT(client2, "230");
	close(client2);

	/* Ensure we can't access other users' home directories */
	SWRITE(client1, "CWD /home" ENDL);
	CLIENT_EXPECT(client1, "250");

	/* Directory listing is fine, since show_all_home_dirs=yes */
	client2 = new_pasv(client1);
	REQUIRE_FD(client2);
	SWRITE(client1, "LIST" ENDL);
	CLIENT_EXPECT(client1, "125");
	/* We should at least see our own home directory,
	 * and even others, unless HIDE_OTHER_HOME_DIRECTORIES is defined  */
	CLIENT_EXPECT_EVENTUALLY(client2, TEST_USER);
	CLIENT_DRAIN(client1);
	CLIENT_DRAIN(client2);
	close_if(client2);

	/* Can't access user 2's home dir */
	SWRITE(client1, "CWD " TEST_USER2 ENDL);
	CLIENT_EXPECT(client1, "431");

	/* Same if we try by absolute path */
	SWRITE(client1, "CWD /home/" TEST_USER2 ENDL);
	CLIENT_EXPECT(client1, "431");

	SWRITE(client1, "REIN" ENDL); /* Log out */
	CLIENT_EXPECT(client1, "220");

	SWRITE(client1, "QUIT" ENDL);
	CLIENT_EXPECT(client1, "231");

	/* Same if we try as anonymous user */
	client2 = test_make_socket(21);
	REQUIRE_FD(client2);
	CLIENT_EXPECT(client2, "220");
	SWRITE(client2, "USER anonymous" ENDL);
	CLIENT_EXPECT(client2, "331");
	SWRITE(client2, "PASS anonymous@example.com" ENDL);
	CLIENT_EXPECT(client2, "230");
	SWRITE(client2, "CWD /home" ENDL);
	CLIENT_EXPECT(client2, "250");
	SWRITE(client2, "CWD " TEST_USER2 ENDL);
	CLIENT_EXPECT(client2, "431");

	/* Try modifying stuff in public files */
	SWRITE(client2, "CWD /home/public" ENDL);
	CLIENT_EXPECT(client2, "250");
	SWRITE(client2, "MKD test" ENDL);
	CLIENT_EXPECT(client2, "250");

	/* We should see "public" in the directory listing of /home */
	SWRITE(client2, "CWD /home" ENDL);
	CLIENT_EXPECT(client2, "250");
	pasv = new_pasv(client2);
	REQUIRE_FD(pasv);
	SWRITE(client2, "LIST" ENDL);
	CLIENT_EXPECT(client2, "125");
	/* We should at least see our own home directory,
	 * and even others, unless HIDE_OTHER_HOME_DIRECTORIES is defined  */
	CLIENT_EXPECT_EVENTUALLY(pasv, "public");

	res = 0;

cleanup:
	close_if(client1);
	close_if(client2);
	close_if(pasv);
	return res;
}

TEST_MODULE_INFO_STANDARD("FTP Tests");
