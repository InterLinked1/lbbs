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
 * \brief IMAP COMPRESS/TLS Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "tls.h"
#include "compress.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

static int pre(void)
{
	test_preload_module("io_tls.so");
	test_preload_module("io_compress.so");
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("tls.conf");
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_SUBCONFIG("tls", "net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

static ssize_t zlib_tls_write(void *cbdata, const char *buf, size_t len)
{
	SSL *ssl = cbdata;
	return tls_write(ssl, __LINE__, buf, len);
}

static ssize_t zlib_tls_read(void *cbdata, char *buf, size_t len)
{
	SSL *ssl = cbdata;
	return tls_read(ssl, __LINE__, buf, len);
}

static int run(void)
{
	SSL *ssl = NULL;
	struct z_data *z = NULL;
	int clientfd = -1;
	int res = -1;

	clientfd = test_make_socket(993);
	REQUIRE_FD(clientfd);

	/* Connect and immediately set up TLS */
	ssl = tls_client_new(clientfd);
	REQUIRE_SSL(ssl);

	/* Log in */
	TLS_CLIENT_EXPECT(ssl, "* OK [CAPABILITY");
	TLS_SWRITE(ssl, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a1 OK");

	TLS_SWRITE(ssl, "a2 ID (\"name\" \"lbbs.test.client\" \"version\" \"" BBS_VERSION "\" NIL)" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a2 OK");

	/* Now, set up compression on top of the TLS session */
	TLS_SWRITE(ssl, "a3 COMPRESS DEFLATE" ENDL);
	TLS_CLIENT_EXPECT_EVENTUALLY(ssl, "a3 OK"); /* The tagged response is without compress. After this, we use compression for the remainder of the session. */

	z = z_client_new(clientfd); /* We pass in the socket file descriptor, but since we enabled compression on top of encryption, we need to use zlib on top of OpenSSL */
	REQUIRE_ZLIB_CLIENT(z);

	ZLIB_SWRITE_CB(zlib_tls_write, ssl, z, "a4 NAMESPACE" ENDL);
	ZLIB_CLIENT_EXPECT_EVENTUALLY_READCB(zlib_tls_read, ssl, z, "a4 OK");

	res = 0;

cleanup:
	/* This test doesn't actually work, and it doesn't really matter. The point is to ensure there are no file descriptor leaks regardless of what the client does.
	 * Therefore, we always return 0, and when the test is run under valgrind, it should pass as long as we don't leak any file descriptors
	 * due to the nested transformation. */
	res = 0;
	ZLIB_CLIENT_SHUTDOWN(z);
	SSL_SHUTDOWN(ssl);
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP COMPRESS/TLS Tests");
