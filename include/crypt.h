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
 * \brief Password cryptography functions
 *
 */

#define BCRYPT_FULL_HASH_LEN 60

/*!
 * \brief Generate a cryptographically secure random string containing only alphanumeric characters
 * \param[out] buf
 * \param len Size of buffer. The length of the random string will be one less than this, as the string will be NUL terminated.
 * \retval 0 on success, -1 on failure
 */
int bbs_rand_alnum(char *buf, size_t len);

/*!
 * \brief Generate a bcrypt salt
 * \retval salt, which is dynamically allocated and must be freed
 */
char *bbs_password_salt(void);

/*!
 * \brief Generate a hash
 * \param password Password to hash
 * \param salt Salt to use in hash, generated by password_salt
 * \retval hash, which must be freed
 */
char *bbs_password_hash(const char *password, const char *salt);

/*!
 * \brief Generate a salt and hash
 * \param password Password to hash
 * \param buf Buffer
 * \param len Length of buf (at least 61)
 * \retval 0 on success, -1 on failure
 */
int bbs_password_salt_and_hash(const char *password, char *buf, size_t len);

/*!
 * \brief Verify a user-provided password against the correct password hash
 * \param password Password to verify for match against combined salt + hash
 * \param salt The salt used to hash the password
 * \param hash The password hash itself
 * \retval 0 on success (match), -1 on failure (mismatch)
 */
int bbs_password_verify(const char *password, const char *salt, const char *hash);

/*!
 * \brief Provided the stored bcrypt salt + hash of a password, verify an input password
 * \param password Password to verify for match against combined salt + hash
 * \param combined The full hash i.e. salt + hash
 * \retval 0 on success (match), -1 on failure (mismatch)
 */
int bbs_password_verify_bcrypt(const char *password, const char *combined);
