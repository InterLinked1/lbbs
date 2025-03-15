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
 * \brief FTPS Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "tls.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

static int pre(void)
{
	test_preload_module("io_tls.so");
	test_load_module("net_ftp.so");

	TEST_ADD_CONFIG("transfers.conf");
	TEST_ADD_CONFIG("tls.conf");
	TEST_ADD_SUBCONFIG("tls", "net_ftp.conf");

	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	return 0;
}

static int new_pasv(SSL *ssl)
{
	char buf[256];
	char *h1, *h2, *h3, *h4, *p1, *p2;
	int port;

	TLS_SWRITE(ssl, "PASV" ENDL);
	TLS_CLIENT_EXPECT_BUF(ssl, "227", buf);
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
	return test_make_socket(port);

cleanup:
	return -1;
}

static int run(void)
{
	int client1 = -1, client2 = -1;
	int pasv = -1;
	int res = -1;
	SSL *ssl = NULL, *ssl2 = NULL;

	/* Test FTPES (Explicit TLS) */
	client1 = test_make_socket(21);
	REQUIRE_FD(client1);

	CLIENT_EXPECT(client1, "220 Welcome");

	/* Use Explicit TLS to upgrade to secure connection */
	SWRITE(client1, "AUTH TLS" ENDL);
	CLIENT_EXPECT(client1, "234 Begin TLS negotiation");
	CLIENT_DRAIN(client1);

	ssl = tls_client_new(client1);
	REQUIRE_SSL(ssl);

	TLS_SWRITE(ssl, "USER " TEST_USER ENDL);
	TLS_CLIENT_EXPECT(ssl, "331");
	TLS_SWRITE(ssl, "PASS " TEST_PASS ENDL);
	TLS_CLIENT_EXPECT(ssl, "230");

	/* Enable encryption for data channels in the future */
	TLS_SWRITE(ssl, "PBSZ 0" ENDL);
	TLS_CLIENT_EXPECT(ssl, "200 ");
	TLS_SWRITE(ssl, "PROT P" ENDL);
	TLS_CLIENT_EXPECT(ssl, "200 ");

	client2 = new_pasv(ssl); /* Open a data connection */
	REQUIRE_FD(client2);

	TLS_SWRITE(ssl, "STOR foobar.txt" ENDL);
	TLS_CLIENT_EXPECT(ssl, "150");
	ssl2 = tls_client_new_reuse_session(client2, ssl);
	REQUIRE_SSL(ssl2);

#define TEST_FILE_STRING "Hello world\r\nGoodbye world\r\n"
#define TEST_FILE_LENGTH XSTR(28) /* Would be nice to not hardcode this, but XSTR(STRLEN(...)) doesn't seem to work */

	TLS_SWRITE(ssl2, TEST_FILE_STRING);
	SSL_SHUTDOWN(ssl2);
	close_if(client2);
	TLS_CLIENT_EXPECT(ssl, "226");

	/* Even before downloading, verify the file we put has the right size. */
	TLS_SWRITE(ssl, "SIZE foobar.txt" ENDL);
	TLS_CLIENT_EXPECT(ssl, "213 " TEST_FILE_LENGTH);

	/* ...Read back the file we put. */
	client2 = new_pasv(ssl);
	REQUIRE_FD(client2);

	TLS_SWRITE(ssl, "RETR foobar.txt" ENDL);
	TLS_CLIENT_EXPECT(ssl, "150");
	ssl2 = tls_client_new_reuse_session(client2, ssl);
	REQUIRE_SSL(ssl2);

	TLS_CLIENT_EXPECT(ssl2, TEST_FILE_STRING);
	SSL_SHUTDOWN(ssl2);
	close_if(client2);
	TLS_CLIENT_EXPECT(ssl, "226");

	res = 0;

cleanup:
	SSL_SHUTDOWN(ssl);
	SSL_SHUTDOWN(ssl2);
	close_if(client1);
	close_if(client2);
	close_if(pasv);
	return res;
}

TEST_MODULE_INFO_STANDARD("FTPS Tests");
