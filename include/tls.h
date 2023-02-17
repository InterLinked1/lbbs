/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Transport Layer Security (TLS)
 *
 */

/* I know we link with -lssl statically in the main binary, this is just for semantics, mainly */
#define HAVE_OPENSSL

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define SHA256_BUFSIZE 65

/*!
 * \brief Hash a string using SHA256
 * \param s String to hash
 * \param buf Buffer that is at least 65 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
 */
int hash_sha256(const char *s, char buf[SHA256_BUFSIZE]);

/*! \brief Get the string version of an OpenSSL error */
const char *ssl_strerror(int err);

/*!
 * \brief Create a new SSL structure for a file descriptor for a server TLS session
 * \param fd Server file descriptor returned previously by accept()
 * \param[out] rfd File descriptor for reading from connection (data has been decrypted)
 * \param[out] wfd File descriptor for writing to connection (data will be encrypted)
 * \retval ssl on success, NULL on failure
 * \note This may be used immediately after accept or later in the session (e.g. STARTTLS)
 */
SSL *ssl_new_accept(int fd, int *rfd, int *wfd);

/*!
 * \brief Create a new SSL structure for a file descriptor for a client TLS session
 * \param fd Client file descriptor
 * \param[out] rfd File descriptor for reading from connection (data has been decrypted)
 * \param[out] wfd File descriptor for writing to connection (data will be encrypted)
 * \retval ssl on success, NULL on failure
 */
SSL *ssl_client_new(int fd, int *rfd, int *wfd);

/*!
 * \brief Close and free an OpenSSL connection
 * \retval 0 on success, -1 on failure
 */
int ssl_close(SSL *ssl);

/*!
 * \brief Whether SSL is available. Modules requiring SSL/TLS functionality should ensure this returns true
 * \retval 1 if available, 0 if not
 */
int ssl_available(void);

/*! \brief Load SSL config on startup */
int ssl_server_init(void);

/*! \brief Clean up SSL on shutdown */
void ssl_server_shutdown(void);
