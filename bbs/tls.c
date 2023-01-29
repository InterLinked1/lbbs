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
 * \brief Transport Layer Security (TLS)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/tls.h"

/* For hashing: */
#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#include "include/config.h"

static char ssl_cert[256] = "";
static char ssl_key[256] = "";

#ifdef HAVE_OPENSSL
SSL_CTX *ssl_ctx = NULL;
#endif

static int ssl_is_available = 0;

int hash_sha256(const char *s, char buf[SHA256_BUFSIZE])
{
#ifdef HAVE_OPENSSL
	int i;
    unsigned char hash[SHA256_DIGEST_LENGTH];

	/* We already use OpenSSL, just use that */
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, s, strlen(s));
	SHA256_Final(hash, &sha256);

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
#undef sprintf
        sprintf(buf + (i * 2), "%02x", hash[i]); /* Safe */
    }
    buf[SHA256_BUFSIZE - 1] = '\0';
	return 0;
#else
	UNUSED(s);
	UNUSED(buf);
	UNUSED(len);
	return -1;
#endif
}

/*! \todo is there an OpenSSL function for this? */
const char *ssl_strerror(int err)
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

SSL *ssl_new_accept(int fd)
{
	int res;
	SSL *ssl;

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		bbs_error("Failed to create SSL\n");
		return NULL;
	}
	SSL_set_fd(ssl, fd);
	res = SSL_accept(ssl);
	if (res != 1) {
		int sslerr = SSL_get_error(ssl, res);
		bbs_error("SSL error %d: %d (%s = %s)\n", res, sslerr, ssl_strerror(sslerr), ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	return ssl;
}

int ssl_available(void)
{
	return ssl_is_available;
}

static int ssl_load_config(void)
{
	int res = 0;
	struct bbs_config *cfg;

	cfg = bbs_config_load("tls.conf", 0);

	if (!cfg) {
		bbs_warning("SSL/TLS will be unavailable since tls.conf is missing\n");
		return -1; /* Impossible to do TLS if we don't know what the server key/cert are */
	}

	res |= bbs_config_val_set_str(cfg, "tls", "cert", ssl_cert, sizeof(ssl_cert));
	res |= bbs_config_val_set_str(cfg, "tls", "key", ssl_key, sizeof(ssl_key));

	if (!res && (s_strlen_zero(ssl_cert) || s_strlen_zero(ssl_key))) {
		bbs_error("An SSL certificate and private key must be provided to use TLS\n");
		return -1;
	}

	bbs_config_free(cfg);
	return res;
}

int ssl_server_init(void)
{
#ifdef HAVE_OPENSSL
	const SSL_METHOD *method;

	if (ssl_load_config()) {
		return -1;
	}

	method = TLS_server_method(); /* Server method, not client method! */
	ssl_ctx = SSL_CTX_new(method);

	if (!ssl_ctx) {
		bbs_error("Failed to create SSL context\n");
		return -1;
	}

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL); /* Server is not verifying the client, the client will verify the server */

	if (SSL_CTX_use_certificate_file(ssl_ctx, ssl_cert, SSL_FILETYPE_PEM) <= 0) {
        bbs_error("Could not load certificate file %s: %s\n", ssl_cert, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_key, SSL_FILETYPE_PEM) <= 0) {
        bbs_error("Could not load private key file %s: %s\n", ssl_key, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        bbs_error("Private key does not match public certificate\n");
        return -1;
    }

	ssl_is_available = 1;
	return 0;
#else
	bbs_error("BBS compiled with OpenSSL support?\n");
	return -1; /* Won't happen */
#endif
}

void ssl_server_shutdown(void)
{
	ssl_is_available = 0;
#ifdef HAVE_OPENSSL
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
#endif
}
