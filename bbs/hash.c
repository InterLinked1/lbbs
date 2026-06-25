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
 * \brief Hashing functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/hash.h"

/* For hashing: */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#undef sprintf

/* We already use OpenSSL, so just use its functions */

/*! \todo Migrate to EVP functions or newer wrappers */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* SHA256_Init, SHA256_Update, SHA256_Final deprecated in OpenSSL 3.0 */
int hash_sha256_hex(const unsigned char *s, size_t bytes, char buf[SHA256_BUFSIZE])
{
	int i;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256(s, (unsigned long) bytes, hash);

	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(buf + (i * 2), "%02x", hash[i]); /* Safe */
	}
	buf[SHA256_BUFSIZE - 1] = '\0';
	return 0;
}

int hash_sha1_hex(const unsigned char *s, size_t bytes, char buf[SHA1_BUFSIZE])
{
	int i;
	unsigned char hash[SHA_DIGEST_LENGTH];

	SHA1(s, (unsigned long) bytes, hash);

	for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(buf + (i * 2), "%02x", hash[i]); /* Safe */
	}
	buf[SHA1_BUFSIZE - 1] = '\0';
	return 0;
}

int hash_sha1_bytes(const unsigned char *s, size_t bytes, unsigned char buf[SHA1_LEN])
{
	SHA1(s, (unsigned long) bytes, buf);
	return 0;
}

int hash_md5_bytes(const unsigned char *s, size_t bytes, unsigned char buf[MD5_LEN])
{
	MD5(s, (unsigned long) bytes, buf);
	return 0;
}
#pragma GCC diagnostic pop /* -Wdeprecated-declarations */
