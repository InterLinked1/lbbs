/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief TLS Functions for Test Suite
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/* For SSL* */
#include <openssl/ssl.h>

/*!
 * \brief Start a TLS client session on the provided file descriptor
 * \param fd File descriptor of the socket that will be doing encrypted communications
 * \note The server certificate is NOT verified
 * \retval NULL on failure
 * \return SSL session on success
 */
SSL *__tls_client_new(int fd, SSL *ssl, int line);

#define tls_client_new(fd) __tls_client_new(fd, NULL, __LINE__)
#define tls_client_new_reuse_session(fd, ssl) __tls_client_new(fd, ssl, __LINE__)

/*! \brief Destroy a TLS session */
void __tls_free(SSL *ssl, int line);

#define tls_free(ssl) __tls_free(ssl, __LINE__)

#define SSL_SHUTDOWN(ssl) if (ssl) { tls_free(ssl); ssl = NULL; }

#define REQUIRE_SSL(ssl) if (!ssl) { goto cleanup; }

ssize_t tls_write(SSL *ssl, int line, const char *buf, size_t len);

ssize_t tls_read(SSL *ssl, int line, char *buf, size_t len);

int test_tls_client_expect(SSL *ssl, int ms, const char *s, int line);
int test_tls_client_expect_buf(SSL *ssl, int ms, const char *s, int line, char *buf, size_t len);
int test_tls_client_expect_eventually(SSL *ssl, int ms, const char *s, int line);
int test_tls_client_expect_eventually_buf(SSL *ssl, int ms, const char *s, int line, char *buf, size_t len);

#define TLS_CLIENT_EXPECT(ssl, s) if (test_tls_client_expect(ssl, SEC_MS(5), s, __LINE__)) { goto cleanup; }
#define TLS_CLIENT_EXPECT_BUF(ssl, s, buf) if (test_tls_client_expect_buf(ssl, SEC_MS(5), s, __LINE__, buf, sizeof(buf))) { goto cleanup; }
#define TLS_CLIENT_EXPECT_EVENTUALLY(ssl, s) if (test_tls_client_expect_eventually(ssl, SEC_MS(5), s, __LINE__)) { goto cleanup; }

#define TLS_SWRITE(ssl, s) if (tls_write(ssl, __LINE__, s, STRLEN(s)) < 0) { goto cleanup; }
