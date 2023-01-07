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
 * \brief Password cryptography functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h> /* use strdup */
#include <ctype.h> /* use isprint */

#ifdef __GLIBC__
#include <gnu/libc-version.h>
#endif

#if !(defined __GLIBC__ && __GLIBC_MINOR__ >= 31)
/* crypt with blowfish, from Openwall, since
 * Debian 10's glibc's crypt doesn't have blowfish support, unlike Debian 11's.
 * blowfish isn't available in Debian 10: https://github.com/NigelCunningham/pam-MySQL/issues/55
 *
 * XXX crypt_blowfish.c is only needed if NEED_CRYPTO_IMPL is defined.
 */
#define NEED_CRYPTO_IMPL
#endif

#ifdef NEED_CRYPTO_IMPL
#include <sys/random.h>
extern int _crypt_output_magic(const char *setting, char *output, int size);
extern char *_crypt_blowfish_rn(const char *key, const char *setting,
	char *output, int size);
extern char *_crypt_gensalt_blowfish_rn(const char *prefix,
	unsigned long count,
	const char *input, int size, char *output, int output_size);
#endif

#include <openssl/rand.h>

#include "include/crypt.h"

#ifdef NEED_CRYPTO_IMPL
/*! \note Thank you, PHP */
static int php_bin2hex(const unsigned char *old, size_t oldlen, char *result, size_t newlen)
{
	static char hexconvtab[] = "0123456789abcdef";
    size_t i, j;

	if (newlen < (2 * oldlen + 1)) {
		return -1;
	}

    for (i = j = 0; i < oldlen; i++) {
        result[j++] = hexconvtab[old[i] >> 4];
        result[j++] = hexconvtab[old[i] & 15];
    }
    result[j] = '\0';
    return 0;
}
#endif

/*
 * We use crypt(3) here. There are better ways to do this,
 * so a future improvement might be to figure out the OpenSSL
 * functions and use those, but this is "good enough" for now.
 */

char *bbs_password_salt(void)
{
#ifndef NEED_CRYPTO_IMPL
	/* cost can be 4-31: https://manpages.debian.org/unstable/libcrypt-dev/crypt.5.en.html */
	return crypt_gensalt_ra("$2b$", 11, NULL, 0); /* 2b = bcrypt */
#else
#define SALT_LENGTH 16
	char result[SALT_LENGTH * 2 + 1];
	unsigned char stream[SALT_LENGTH + 1];
	int res;
	res = getrandom(stream, SALT_LENGTH, 0);
	if (res < 0) {
		bbs_error("getrandom failed: %s\n", strerror(errno));
		return NULL;
	} else if (res != SALT_LENGTH) {
		bbs_error("getrandom returned %d bytes (wanted %d)\n", res, SALT_LENGTH);
		return NULL;
	}
	if (php_bin2hex(stream, SALT_LENGTH, result, sizeof(result))) {
		bbs_error("bin2hex failed\n");
		return NULL;
	}
	result[0] = '$';
	result[1] = '2';
	result[2] = 'a';
	result[3] = '$';
	/* Cost parameter / Number of rounds of hashing (10) */
	result[4] = '1';
	result[5] = '0';
	result[6] = '$';
	/* Blowfish hashing with a salt as follows: "$2a$", "$2x$" or "$2y$",
	 * a two digit cost parameter, "$", and 22 characters from the alphabet "./0-9A-Za-z"
	 * https://stackoverflow.com/questions/28099229/php-crypt-returns-0-failure-string-in-version-5-6-4-but-not-5-4
	 */
	result[7 + 22] = '\0';
	return strdup(result);
#endif
}

#ifdef NEED_CRYPTO_IMPL
static char *_crypt_retval_magic(char *retval, const char *setting, char *output, int size) {
	if (retval) {
		return retval;
	}
	if (_crypt_output_magic(setting, output, size)) {
		bbs_error("Shouldn't happen...\n");
		return NULL; /* shouldn't happen */
	}
	return output;
}

static char *__crypt_rn(__const char *key, __const char *setting, void *data, int size)
{
	if (setting[0] == '$' && setting[1] == '2') {
		return _crypt_blowfish_rn(key, setting, (char *)data, size);
	}
	bbs_warning("Falling back to crypt_r (setting: %s)\n", setting); /* Whole point of using this functions if crypt_r is not supported, so this won't be good... */
	return crypt_r(key, setting, data); /* If it's not blowfish, just fall back, since that's all we care about adding support for. */
}

static char *__crypt_r(__const char *key, __const char *setting, struct crypt_data *data)
{
	return _crypt_retval_magic(__crypt_rn(key, setting, data, sizeof(*data)), setting, (char *)data, sizeof(*data));
}
#endif

char *bbs_password_hash(const char *password, const char *salt)
{
	char *hash;
	struct crypt_data data;
	int len;

	memset(&data, 0, sizeof(data)); /* Not necessary, but whatever... */
	data.initialized = 0; /* This must be done. */

	/* We do not use crypt, as it's not thread-safe. Use crypt_r instead. */
#ifndef NEED_CRYPTO_IMPL
	bbs_debug(9, "Using real crypt_r\n");
	hash = crypt_r(password, salt, &data); /* Use the real crypt_r */
#else
	bbs_debug(9, "Using alternate crypt_r\n");
	data.current_salt[0] = '$';
	data.current_salt[1] = '2';
	hash = __crypt_r(password, salt, &data); /* Use our custom implementation of crypt_r */
#endif

	if (strlen_zero(hash)) {
		bbs_error("Failed to compute hash: %s\n", strerror(errno));
		return NULL;
	} else if (!strcmp(hash, "*0")) {
		bbs_error("Failed to compute hash (invalid salt?): %s (salt: %s)\n", strerror(errno), salt);
		return NULL;
	}

	len = strlen(hash);
	if (len != 59 && len != 60) {
		/* XXX This is only for bcrypt */
		/* https://stackoverflow.com/questions/5881169/what-column-type-length-should-i-use-for-storing-a-bcrypt-hashed-password-in-a-d */
		bbs_error("%s failed: password hash length should be 59-60 but was %d? (%s)\n", __FUNCTION__, len, hash);
		return NULL;
	}

	return strdup(hash);
}

int bbs_password_salt_and_hash(const char *password, char *buf, size_t len)
{
	char *hash, *salt = bbs_password_salt();
	if (!salt) {
		return -1;
	}
	hash = bbs_password_hash(password, salt);
	free(salt);
	if (!hash) {
		return -1;
	}
	if (strlen(hash) >= len) {
		bbs_error("Truncation with buffer of size %lu\n", len);
		return -1;
	}
	safe_strncpy(buf, hash, len);
	free(hash);
	return 0;
}

int bbs_password_verify(const char *password, const char *salt, const char *hash)
{
	int a, b, res;
	char *uhash = bbs_password_hash(password, salt);

	if (!uhash) {
		return -1;
	}

	a = strlen(uhash);
	b = strlen(hash);

	if (!a || !b || a != b) {
		free(uhash);
		return -1;
	}

	res = 0; /* innocent until proven guilty */

	/* This is intentionally not an optimal loop.
	 * If we break out of the loop as soon as we find a mismatch,
	 * this can make it possible for an attacker to conduct a "timing attack".
	 * Therefore, we always make every comparison so we don't leak
	 * information about how much of the hash matched.
	 */
	for (b = 0; b < a; b++) {
		if (uhash[b] != hash[b]) {
			res = -1; /* don't leak (time wise) by aborting early! */
		}
	}

	free(uhash);
	return res;
}

int bbs_password_verify_bcrypt(const char *password, char *combined)
{
	int res;
	char *salt;
	char *pos, *ohash;
	char orig;
	int len;

	/* For bcrypt, it's $2b$<COST>$ + 22 char salt + 31 char hash */
	len = strlen(combined);
	/* Length should be 7 + 22 + 31 = 60 */
	if (len != 60) {
		bbs_warning("Expected input length to be 60, but it's %d?\n", len);
		return -1;
	}
	salt = strdupa(combined);
	/* XXX When I originally wrote this code, with NEED_CRYPTO_IMPL, I had pos = salt + len - 1 - 31 here.
	 * When incorporating this code into the BBS, I found that the salt was only 21 characters
	 * with this calculation, as opposed to 22, as it should be.
	 * It works correctly here without subtracting the additional "1", without NEED_CRYPTO_IMPL.
	 * Because the code in this source file is far from the most portable code,
	 * I'm adding a note here in case this causes issues in the future.
	 * Perhaps we do need to subtract 1 if NEED_CRYPTO_IMPL is defined.
	 * Also, we now catch invalid salt length before trying to call crypt_r with an invalid salt,
	 * since that will just confuse everybody.
	 */
	pos = salt + len - 31;
	/* Temporarily terminate the string after the salt, so we don't have to duplicate the string just for that. */
	orig = pos[0];
	pos[0] = '\0';
	if (strlen(salt + 7) != 22) { /* Skip $2b$XX$ - first 7 chars */
		/* Yeah, calling strlen twice isn't efficient, but this is an off nominal path anyways */
		bbs_warning("Salt %s is %lu characters (must be 22)\n", salt, strlen(salt + 7));
		return -1;
	}
	ohash = bbs_password_hash(password, salt);
	pos[0] = orig; /* Unterminate the string to revert it back to what it was originally */
	res = bbs_password_verify(password, salt, combined);
	if (ohash) {
		free(ohash);
	}
	return res;
}
