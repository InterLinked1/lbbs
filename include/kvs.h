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
 * \brief Key Value Store
 *
 */

struct kvs_callbacks {
	int (*get)(const char *key, size_t keylen, char *buf, size_t len, char **outbuf, size_t *outlen);
	int (*put)(const char *key, size_t keylen, const char *value, size_t valuelen);
	int (*del)(const char *key, size_t keylen);
};

/*!
 * \brief Register a KVS backend provider
 * \param cb kvs_callbacks structure
 * \param priority Priority (lower priority indicates higher precedence). Not currently used.
 * \retval 0 on success, -1 on failure (another backend already registered)
 * \note Currently only one KVS backend provider may be registered at a time
 */
#define bbs_register_kvs_backend(cb, priority) __bbs_register_kvs_backend(cb, priority, BBS_MODULE_SELF)

int __bbs_register_kvs_backend(struct kvs_callbacks *cb, int priority, void *mod);

/*!
 * \brief Unregister a KVS backend provider, previously registered using bbs_register_kvs_backend
 * \param cb kvs_callbacks structure
 * \retval 0 on success, -1 on failure (backend not currently registered)
 */
int bbs_unregister_kvs_backend(struct kvs_callbacks *cb);

/*!
 * \brief Store a value from the key-value store into a provided buffer
 * \param[in] key Key name
 * \param[in] keylen Length of key
 * \param[out] buf Buffer for value
 * \param[in] len Length of buf
 * \param[out] outlen Length of value
 * \retval 0 on success, -1 on failure
 * \note If a value would be truncated, the operation is failed, but you can get the real length from outlen.
 */
int bbs_kvs_get(const char *key, size_t keylen, char *buf, size_t len, size_t *outlen);

/*!
 * \brief Retrieve a value from the key-value store into an allocated buffer
 * \param[in] key Key name
 * \param[in] keylen Length of key
 * \param[out] outlen Length of value
 * \return Value on success
 * \return NULL on failure
*/
char *bbs_kvs_get_allocated(const char *key, size_t keylen, size_t *outlen);

/*!
 * \brief Store a value into the kvs-value store
 * \param[in] key Key name
 * \param[in] keylen Length of key
 * \param[in] value Value to store
 * \param[in] valuelen Length of value
 * \retval 0 on success, -1 on failure
*/
int bbs_kvs_put(const char *key, size_t keylen, const char *value, size_t valuelen);

/*!
 * \brief Store a value into the kvs-value store
 * \param[in] key Key name
 * \param[in] keylen Length of key
 * \retval 0 on success, -1 on failure (including key didn't exist)
 */
int bbs_kvs_del(const char *key, size_t keylen);
