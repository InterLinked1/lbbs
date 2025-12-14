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
 * \brief TLS Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "tls.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static int pre(void)
{
	test_preload_module("io_tls.so");
	test_load_module("mod_sysop.so"); /* So we can reload the certs using CLI command */
	test_load_module("net_ftp.so");

	/* Not all platforms have it and we don't create it.
	 * On Debian, can run 'apt-get install ssl-cert' if this cert pair is missing. */
	TEST_REQUIRE_FILE("/etc/ssl/private/ssl-cert-snakeoil.key");

	TEST_ADD_CONFIG("tls.conf");
	TEST_ADD_CONFIG("transfers.conf");
	TEST_ADD_SUBCONFIG("tls", "net_ftp.conf");

	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	return 0;
}

#define NUM_INITIAL_CONNECTIONS 3
#define NUM_CONNECTIONS (NUM_INITIAL_CONNECTIONS + 3)

static int run(void)
{
	int clientfd[NUM_CONNECTIONS];
	SSL *ssl[NUM_CONNECTIONS];
	int i, res = -1;

	/* Initialize clients */
	for (i = 0; i < NUM_CONNECTIONS; i++) {
		clientfd[i] = -1;
		ssl[i] = NULL;
	}

	for (i = 0; i < NUM_INITIAL_CONNECTIONS; i++) {
		clientfd[i] = test_make_socket(21);
		REQUIRE_FD(clientfd[i]);
		CLIENT_EXPECT(clientfd[i], "220 Welcome");

		/* Use Explicit TLS to upgrade to secure connection */
		SWRITE(clientfd[i], "AUTH TLS" ENDL);
	}
	for (i = 0; i < NUM_INITIAL_CONNECTIONS; i++) {
		CLIENT_EXPECT(clientfd[i], "234 Begin TLS negotiation");
		CLIENT_DRAIN(clientfd[i]);
		ssl[i] = tls_client_new(clientfd[i]);
		REQUIRE_SSL(ssl[i]);
	}
	for (i = 0; i < NUM_INITIAL_CONNECTIONS; i++) {
		TLS_SWRITE(ssl[i], "USER " TEST_USER ENDL);
		TLS_CLIENT_EXPECT(ssl[i], "331");
	}

	/* Reload the TLS certificates, which means the server will have new SSL_CTX's to use,
	 * but this connection will still be using the old one. */
	TEST_CLI_COMMAND("tlsreload");

	/* Create the remaining clients *after* we've reloaded */
	for (i = NUM_INITIAL_CONNECTIONS; i < NUM_CONNECTIONS; i++) {
		clientfd[i] = test_make_socket(21);
		REQUIRE_FD(clientfd[i]);
		CLIENT_EXPECT(clientfd[i], "220 Welcome");
		SWRITE(clientfd[i], "AUTH TLS" ENDL);
		CLIENT_EXPECT(clientfd[i], "234 Begin TLS negotiation");
		CLIENT_DRAIN(clientfd[i]);
		ssl[i] = tls_client_new(clientfd[i]);
		REQUIRE_SSL(ssl[i]);
		TLS_SWRITE(ssl[i], "USER " TEST_USER ENDL);
		TLS_CLIENT_EXPECT(ssl[i], "331");
	}

	for (i = 0; i < NUM_CONNECTIONS; i++) {
		TLS_SWRITE(ssl[i], "HELP" ENDL);
		TLS_CLIENT_EXPECT(ssl[i], "211");
	}

	/* Reload again */
	TEST_CLI_COMMAND("tlsreload");

	for (i = 0; i < NUM_CONNECTIONS; i++) {
		TLS_SWRITE(ssl[i], "HELP" ENDL);
		TLS_CLIENT_EXPECT(ssl[i], "211");
	}

	for (i = 0; i < NUM_CONNECTIONS; i++) {
		TLS_SWRITE(ssl[i], "QUIT" ENDL);
		TLS_CLIENT_EXPECT(ssl[i], "231");
	}

	/* Test passes if no memory leaks occur. */
	res = 0;

cleanup:
	for (i = 0; i < NUM_CONNECTIONS; i++) {
		SSL_SHUTDOWN(ssl[i]);
		close_if(clientfd[i]);
	}
	return res;
}

TEST_MODULE_INFO_STANDARD("TLS Tests");
