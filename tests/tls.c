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
 * \brief TLS Functions for Test Suite
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "tls.h"

#include <string.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/*!
 * \note All OpenSSL functions should be called
 * only from within this file.
 * This way, none of the test modules that do TLS stuff
 * needs linkage to OpenSSL. */

static const char *ssl_strerror(int err)
{
	switch (err) {
	case SSL_ERROR_NONE:
		return "SSL_ERROR_NONE";
	case SSL_ERROR_ZERO_RETURN:
		return "SSL_ERROR_ZERO_RETURN";
	case SSL_ERROR_WANT_READ:
		return "SSL_ERROR_WANT_READ";
	case SSL_ERROR_WANT_WRITE:
		return "SSL_ERROR_WANT_WRITE";
	case SSL_ERROR_WANT_CONNECT:
		return "SSL_ERROR_WANT_CONNECT";
	case SSL_ERROR_WANT_ACCEPT:
		return "SSL_ERROR_WANT_ACCEPT";
	case SSL_ERROR_WANT_X509_LOOKUP:
		return "SSL_ERROR_WANT_X509_LOOKUP";
	case SSL_ERROR_SYSCALL:
		return "SSL_ERROR_SYSCALL";
	case SSL_ERROR_SSL:
		return "SSL_ERROR_SSL";
	default:
		break;
	}
	return "Undefined";
}

static SSL_SESSION *master_session = NULL;

static SSL_SESSION *get_session_cb(SSL *ssl, const unsigned char *arg1, int arg2, int *arg3)
{
	UNUSED(ssl);
	UNUSED(arg1);
	UNUSED(arg2);
	UNUSED(arg3);
	return master_session;
}

SSL *__tls_client_new(int fd, SSL *ssl_master, int line)
{
	SSL *ssl;
	SSL_CTX *ctx;

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		bbs_error("Failed to setup new SSL context\n");
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION); /* Only use TLS, disable compression */
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
	if (ssl_master) {
		/* We want to reuse this session */
		SSL_SESSION *session = SSL_get_session(ssl_master);
		master_session = session;
		SSL_CTX_sess_set_get_cb(ctx, get_session_cb);
	}
	ssl = SSL_new(ctx);
	if (!ssl) {
		bbs_error("Failed to create new SSL\n");
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) == -1) {
		bbs_error("Failed to connect SSL at line %d: %s\n", line, ERR_error_string(ERR_get_error(), NULL));
		SSL_CTX_free(ctx);
		SSL_free(ssl);
		ctx = NULL;
		ssl = NULL;
		return NULL;
	}

	/* Since we are using the snake oil cert, we explicitly do NOT verify the TLS cert here */

	SSL_CTX_free(ctx);
	bbs_debug(3, "Connected TLS client at line %d (fd %d)\n", line, fd);
	return ssl;
}

void __tls_free(SSL *ssl, int line)
{
	int fd, sres, status;
	fd = SSL_get_fd(ssl);

#define SHUTDOWN_STATUS(s) (s & SSL_RECEIVED_SHUTDOWN ? s & SSL_SENT_SHUTDOWN ? "sent/received" : "received" : "none")
	status = SSL_get_shutdown(ssl);
	bbs_debug(6, "Shutdown status is %s\n", SHUTDOWN_STATUS(status));

	sres = SSL_shutdown(ssl);
	if (sres == 0) {
		status = SSL_get_shutdown(ssl);
		bbs_debug(6, "Shutdown status is %s\n", SHUTDOWN_STATUS(status));
		/* Bidirectional shutdown (required for TLS 1.3) */
		sres = SSL_shutdown(ssl);
		status = SSL_get_shutdown(ssl);
		bbs_debug(6, "Shutdown status is %s\n", SHUTDOWN_STATUS(status));
	}
	if (sres != 1) {
		int err = SSL_get_error(ssl, sres);
		bbs_debug(1, "SSL shutdown failed %p (%d): %s\n", ssl, sres, ssl_strerror(err));
	}
	SSL_free(ssl);
	bbs_debug(3, "Destroyed TLS client at line %d (fd %d)\n", line, fd);
}

ssize_t tls_write(SSL *ssl, int line, const char *buf, size_t len)
{
	ssize_t wres = SSL_write(ssl, buf, (int) len);
	if (wres != (ssize_t) len) {
		if (wres <= 0) {
			int err = SSL_get_error(ssl, (int) wres);
			bbs_error("SSL_write error at line %d: %s\n", line, ssl_strerror(err));
		} else {
			bbs_error("SSL_write failed at line %d (%ld != %lu)\n", line, wres, len);
		}
		return -1;
	}
	bbs_debug(5, "Sent %ld B via fd %d\n", wres, SSL_get_wfd(ssl));
	return wres;
}

ssize_t tls_read(SSL *ssl, int line, char *buf, size_t len)
{
	ssize_t rres = SSL_read(ssl, buf, (int) len);
	if (rres <= 0) {
		int err = SSL_get_error(ssl, (int) rres);
		bbs_error("SSL_read error at line %d: %s\n", line, ssl_strerror(err));
		return -1;
	}
	bbs_debug(5, "Received %ld B via fd %d\n", rres, SSL_get_rfd(ssl));
	return rres;
}

int test_tls_client_expect(SSL *ssl, int ms, const char *restrict s, int line)
{
	char buf[4096];
	return test_tls_client_expect_buf(ssl, ms, s, line, buf, sizeof(buf));
}

int test_tls_client_expect_buf(SSL *ssl, int ms, const char *s, int line, char *buf, size_t len)
{
	int res;
	struct pollfd pfd;

	/* There is finally an SSL_poll(), but only as of OpenSSL 3.3, so hold off on using that just yet */
	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = SSL_get_rfd(ssl);
	pfd.events = POLLIN;
	pfd.revents = 0;
	assert(pfd.fd != -1);

	res = poll(&pfd, 1, ms);
	if (res < 0) {
		return -1;
	}
	if (res > 0 && pfd.revents) {
		ssize_t bytes;
		bytes = tls_read(ssl, line, buf, len - 1);
		if (bytes <= 0) {
			return -1;
		}
		buf[bytes] = '\0'; /* Safe */
		if (!strstr(buf, s)) {
			bbs_warning("Failed to receive expected output at line %d: %s (got %s)\n", line, s, buf);
			return -1;
		}
		bbs_debug(10, "Contains output expected at line %d: %s", line, buf); /* Probably already ends in LF */
		return 0;
	}
	bbs_warning("Failed to receive expected output at line %d: %s\n", line, s);
	return -1;
}

int test_tls_client_expect_eventually(SSL *ssl, int ms, const char *restrict s, int line)
{
	char buf[4096];
	return test_tls_client_expect_eventually_buf(ssl, ms, s, line, buf, sizeof(buf));
}

int test_tls_client_expect_eventually_buf(SSL *ssl, int ms, const char *restrict s, int line, char *restrict buf, size_t len)
{
	struct pollfd pfd;

	/* There is finally an SSL_poll(), but only as of OpenSSL 3.3, so hold off on using that just yet */
	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = SSL_get_rfd(ssl);
	pfd.events = POLLIN;
	assert(pfd.fd != -1);

	for (;;) {
		int res;
		pfd.revents = 0;
		res = poll(&pfd, 1, ms);
		if (res < 0) {
			return -1;
		} else if (!res) {
			break;
		}
		if (res > 0 && pfd.revents) {
			ssize_t bytes;
			bytes = tls_read(ssl, line, buf, len - 1);
			if (bytes <= 0) {
				return -1;
			}
			buf[bytes] = '\0'; /* Safe */
			/* Probably ends in LF, so skip one here */
			bbs_debug(10, "Analyzing output(%d): %s", line, buf); /* Particularly under valgrind, we'll end up reading individual lines more than chunks, so using CLIENT_DRAIN is especially important */
			/* XXX Should use bbs_readline_append for reliability */
			if (strstr(buf, s)) {
				return 0;
			}
		}
	}
	bbs_warning("Failed to receive expected output at line %d: %s\n", line, s);
	return -1;
}
