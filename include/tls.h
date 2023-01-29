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
 * \brief Create a new SSL structure for a file descriptor
 * \param fd File descriptor returned previously by accept()
 * \retval ssl on success, NULL on failure
 */
SSL *ssl_new_accept(int fd);

/*!
 * \brief Whether SSL is available. Modules requiring SSL/TLS functionality should ensure this returns true
 * \retval 1 if available, 0 if not
 */
int ssl_available(void);

/*! \brief Load SSL config on startup */
int ssl_server_init(void);

/*! \brief Clean up SSL on shutdown */
void ssl_server_shutdown(void);
