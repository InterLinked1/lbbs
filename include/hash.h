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
 * \brief Hashing functions
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
#define SHA1_LEN 20
#define SHA1_BUFSIZE 41 /* 160 bits = 20 bytes = 40 hex digits + NUL */

/*!
 * \brief Hash a string using SHA256
 * \param s String to hash
 * \param buf Buffer that is at least 65 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
 */
int hash_sha256(const char *s, char buf[SHA256_BUFSIZE]);

/*!
 * \brief Hash a string using SHA1
 * \param s String to hash
 * \param buf Buffer that is at least 41 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
 */
int hash_sha1(const char *s, char buf[SHA1_BUFSIZE]);

/*!
 * \brief Hash a string using SHA1, but get the actual bytes in return
 * \param s String to hash
 * \param buf Buffer that is at least 20 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
*/
int hash_sha1_bytes(const char *s, char buf[SHA1_LEN]);
