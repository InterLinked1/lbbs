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
 * \brief LMDB (Lightning Memory-Mapped Database) key-value store
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <lmdb.h>

#include "include/module.h"
#include "include/kvs.h"
#include "include/utils.h" /* use bbs_ensure_directory_exists */

static MDB_env *env = NULL;
static MDB_dbi dbi = 0;

static const char *dbpath = "/var/lib/lbbs/lmdb";

static int lmdb_get(const char *key, size_t keylen, char *buf, size_t len, char **outbuf, size_t *outlen)
{
	MDB_txn *txn;
	MDB_val dbkey, value;
	int res;

	res = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (res) {
		bbs_error("mdb_txn_begin failed: %s\n", mdb_strerror(res));
		return -1;
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	dbkey.mv_data = (char*) key;
#pragma GCC diagnostic pop
	dbkey.mv_size = keylen;
	res = mdb_get(txn, dbi, &dbkey, &value);
	if (res) {
		if (res == MDB_NOTFOUND) {
			bbs_debug(5, "mdb_get failed: %s\n", mdb_strerror(res));
		} else {
			bbs_error("mdb_get failed: %s\n", mdb_strerror(res));
		}
		mdb_txn_commit(txn);
		return -1;
	}
	if (outlen) { /* Do this first, so if truncation occurs, the caller knows how big it was */
		*outlen = value.mv_size;
	}
	if (buf) {
		if (value.mv_size >= len - 1) {
			bbs_warning("Truncation when copying value of size %lu to buffer of size %lu\n", value.mv_size, len);
			mdb_txn_commit(txn);
			return -1;
		}
		memcpy(buf, value.mv_data, value.mv_size);
		buf[value.mv_size] = '\0';
	} else if (outbuf) {
		*outbuf = memdup(value.mv_data, value.mv_size);
	}
	mdb_txn_commit(txn);
	return 0;
}

static int lmdb_put(const char *key, size_t keylen, const char *value, size_t valuelen)
{
	MDB_txn *txn;
	MDB_val dbkey, dbvalue;
	int res;

	res = mdb_txn_begin(env, NULL, 0, &txn);
	if (res) {
		bbs_error("mdb_txn_begin failed: %s\n", mdb_strerror(res));
		return -1;
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	dbkey.mv_data = (char*) key;
	dbkey.mv_size = keylen;
	dbvalue.mv_data = (char*) value;
#pragma GCC diagnostic pop
	dbvalue.mv_size = valuelen;
	res = mdb_put(txn, dbi, &dbkey, &dbvalue, 0);
	if (res) {
		bbs_error("mdb_put failed: %s\n", mdb_strerror(res));
		mdb_txn_abort(txn);
		return -1;
	}
	mdb_txn_commit(txn);
	return 0;
}

static int lmdb_del(const char *key, size_t keylen)
{
	MDB_txn *txn;
	MDB_val dbkey;
	int res;

	res = mdb_txn_begin(env, NULL, 0, &txn);
	if (res) {
		bbs_error("mdb_txn_begin failed: %s\n", mdb_strerror(res));
		return -1;
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	dbkey.mv_data = (char*) key;
#pragma GCC diagnostic pop
	dbkey.mv_size = keylen;
	res = mdb_del(txn, dbi, &dbkey, NULL);
	if (res) {
		bbs_error("mdb_del failed: %s\n", mdb_strerror(res));
		mdb_txn_abort(txn);
		return -1;
	}
	mdb_txn_commit(txn);
	return 0;
}

struct kvs_callbacks cb = {
	.get = lmdb_get,
	.put = lmdb_put,
	.del = lmdb_del,
};

static int load_module(void)
{
	MDB_txn *txn;
	int res;

	if (bbs_ensure_directory_exists(dbpath)) {
		return -1;
	}
	res = mdb_env_create(&env);
	if (res) {
		bbs_error("mdb_env_create failed: %s\n", mdb_strerror(res));
		return -1;
	}
	if (mdb_env_open(env, dbpath, 0, 0600)) {
		bbs_error("mdb_env_open failed: %s\n", mdb_strerror(res));
		goto abort;
	}
	if (mdb_txn_begin(env, NULL, 0, &txn)) {
		bbs_error("mdb_txn_begin failed: %s\n", mdb_strerror(res));
		goto abort;
	}
	/* Only use a single database. Use a dummy transaction to create a reusable DB handle. */
	if (mdb_dbi_open(txn, NULL, 0, &dbi)) {
		bbs_error("mdb_dbi_open failed: %s\n", mdb_strerror(res));
		mdb_txn_abort(txn);
		goto abort;
	}
	mdb_txn_commit(txn);
	bbs_register_kvs_backend(&cb, 5);
	return 0;

abort:
	mdb_env_close(env);
	return -1;
}

static int unload_module(void)
{
	bbs_unregister_kvs_backend(&cb);
	mdb_dbi_close(env, dbi);
	mdb_env_close(env);
	return 0;
}

BBS_MODULE_INFO_STANDARD("LMDB Key Value Store");
