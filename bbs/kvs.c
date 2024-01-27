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
 * \brief Key Value Store
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/kvs.h"
#include "include/callback.h"

/* At this time, there is only support for 1 KVS backend loaded at a time. Because why would we need more? */
BBS_SINGULAR_STRUCT_CALLBACK_DECLARE(callbacks, kvs_callbacks);

int __bbs_register_kvs_backend(struct kvs_callbacks *cb, int priority, void *mod)
{
	UNUSED(priority);
	return bbs_singular_callback_register(&callbacks, cb, mod);
}

int bbs_unregister_kvs_backend(struct kvs_callbacks *cb)
{
	return bbs_singular_callback_unregister(&callbacks, cb);
}

int bbs_kvs_get(const char *key, size_t keylen, char *buf, size_t len, size_t *outlen)
{
	int res;
	size_t outlentmp, *ptr;

	ptr = outlen ? outlen : &outlentmp;
	*ptr = 0;

	if (bbs_singular_callback_execute_pre(&callbacks)) {
		bbs_error("No KVS backend currently registered\n");
		return -1;
	}

	res = BBS_SINGULAR_STRUCT_CALLBACK_EXECUTE(callbacks)->get(key, keylen, buf, len, NULL, ptr);
	bbs_singular_callback_execute_post(&callbacks);

	bbs_debug(6, "KVS GET(%s) => %lu bytes\n", key, *ptr);
	return res;
}

char *bbs_kvs_get_allocated(const char *key, size_t keylen, size_t *outlen)
{
	char *c;
	int res;
	size_t outlentmp, *ptr;

	ptr = outlen ? outlen : &outlentmp;
	*ptr = 0;
	if (bbs_singular_callback_execute_pre(&callbacks)) {
		bbs_error("No KVS backend currently registered\n");
		return NULL;
	}

	res = BBS_SINGULAR_STRUCT_CALLBACK_EXECUTE(callbacks)->get(key, keylen, NULL, 0, &c, ptr);
	bbs_singular_callback_execute_post(&callbacks);

	if (res) {
		return NULL;
	}

	bbs_debug(6, "KVS GET(%s) => %lu bytes\n", key, *ptr);
	return c;
}

int bbs_kvs_put(const char *key, size_t keylen, const char *value, size_t valuelen)
{
	int res;

	if (bbs_singular_callback_execute_pre(&callbacks)) {
		bbs_error("No KVS backend currently registered\n");
		return -1;
	}

	res = BBS_SINGULAR_STRUCT_CALLBACK_EXECUTE(callbacks)->put(key, keylen, value, valuelen);
	bbs_singular_callback_execute_post(&callbacks);

	bbs_debug(6, "KVS PUT(%s) => %lu bytes\n", key, valuelen);
	return res;
}

int bbs_kvs_del(const char *key, size_t keylen)
{
	int res;

	if (bbs_singular_callback_execute_pre(&callbacks)) {
		bbs_error("No KVS backend currently registered\n");
		return -1;
	}

	res = BBS_SINGULAR_STRUCT_CALLBACK_EXECUTE(callbacks)->del(key, keylen);
	bbs_singular_callback_execute_post(&callbacks);

	bbs_debug(6, "KVS DEL(%s)\n", key);
	return res;
}
