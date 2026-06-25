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

#define SHA256_BUFSIZE 65
#define SHA1_LEN 20
#define SHA1_BUFSIZE 41 /* 160 bits = 20 bytes = 40 hex digits + NUL */
#define MD5_LEN 16

/*!
 * \brief Hash a string using SHA256 and get the digest as hexadecimal
 * \param s String or buffer to hash
 * \param bytes Number of bytes to hash
 * \param buf Buffer that is at least 65 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
 */
int hash_sha256_hex(const unsigned char *s, size_t bytes, char buf[SHA256_BUFSIZE]);

/*!
 * \brief Hash a string using SHA1 and get the digest as hexadecimal
 * \param s String or buffer to hash
 * \param bytes Number of bytes to hash
 * \param buf Buffer that is at least 41 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
 */
int hash_sha1_hex(const unsigned char *s, size_t bytes, char buf[SHA1_BUFSIZE]);

/*!
 * \brief Hash a string using SHA1 and get the raw digest bytes
 * \param s String or buffer to hash
 * \param bytes Number of bytes to hash
 * \param buf Buffer that is at least 20 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
*/
int hash_sha1_bytes(const unsigned char *s, size_t bytes, unsigned char buf[SHA1_LEN]);

/*!
 * \brief Hash a string using SHA1 and get the raw digest bytes
 * \param s String or buffer to hash
 * \param bytes Number of bytes to hash
 * \param buf Buffer that is at least 20 bytes (larger is unnecessary)
 * \retval 0 on success, -1 on failure
*/
int hash_md5_bytes(const unsigned char *s, size_t bytes, unsigned char buf[MD5_LEN]);
