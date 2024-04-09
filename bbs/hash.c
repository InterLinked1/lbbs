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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#undef sprintf

/*! \todo Migrate to EVP functions or newer wrappers */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* SHA256_Init, SHA256_Update, SHA256_Final deprecated in OpenSSL 3.0 */
int hash_sha256(const char *s, char buf[SHA256_BUFSIZE])
{
	int i;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	/* We already use OpenSSL, just use that */
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, s, strlen(s));
	SHA256_Final(hash, &sha256);

	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(buf + (i * 2), "%02x", hash[i]); /* Safe */
	}
	buf[SHA256_BUFSIZE - 1] = '\0';
	return 0;
}

int hash_sha1(const char *s, char buf[SHA1_BUFSIZE])
{
	int i;
	unsigned char hash[SHA_DIGEST_LENGTH];

	/* We already use OpenSSL, just use that */
	SHA_CTX sha1;
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, s, strlen(s));
	SHA1_Final(hash, &sha1);

	for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(buf + (i * 2), "%02x", hash[i]); /* Safe */
	}
	buf[SHA1_BUFSIZE - 1] = '\0';
	return 0;
}

int hash_sha1_bytes(const char *s, char buf[SHA1_LEN])
{
	unsigned char hash[SHA_DIGEST_LENGTH];

	/* We already use OpenSSL, just use that */
	SHA_CTX sha1;
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, s, strlen(s));
	SHA1_Final(hash, &sha1);

	memcpy(buf, hash, SHA1_LEN);
	return 0;
}
#pragma GCC diagnostic pop /* -Wdeprecated-declarations */
