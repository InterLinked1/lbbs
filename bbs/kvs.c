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

#include "include/module.h"
#include "include/kvs.h"

/* At this time, there is only support for 1 KVS backend loaded at a time. Because why would we need more? */
static struct kvs_callbacks *callbacks = NULL;
static void *kvsmod = NULL;

int __bbs_register_kvs_backend(struct kvs_callbacks *cb, int priority, void *mod)
{
	/* Unlike auth providers, there is only 1 user registration handler */
	if (callbacks) {
		bbs_error("A KVS backend is already registered.\n");
		return -1;
	}

	UNUSED(priority);

	callbacks = cb;
	kvsmod = mod;
	return 0;
}

int bbs_unregister_kvs_backend(struct kvs_callbacks *cb)
{
	if (cb != callbacks) {
		bbs_error("KVS provider does not match registered provider\n");
		return -1;
	}

	callbacks = NULL;
	kvsmod = NULL;
	return 0;
}

int bbs_kvs_get(const char *key, size_t keylen, char *buf, size_t len, size_t *outlen)
{
	int res;
	size_t outlentmp, *ptr;

	ptr = outlen ? outlen : &outlentmp;
	*ptr = 0;
	if (!callbacks) {
		bbs_error("No KVS backend currently registered\n");
		return -1;
	}

	bbs_module_ref(kvsmod);
	res = callbacks->get(key, keylen, buf, len, NULL, ptr);
	bbs_module_unref(kvsmod);

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
	if (!callbacks) {
		bbs_error("No KVS backend currently registered\n");
		return NULL;
	}

	bbs_module_ref(kvsmod);
	res = callbacks->get(key, keylen, NULL, 0, &c, ptr);
	bbs_module_unref(kvsmod);

	if (res) {
		return NULL;
	}

	bbs_debug(6, "KVS GET(%s) => %lu bytes\n", key, *ptr);
	return c;
}

int bbs_kvs_put(const char *key, size_t keylen, const char *value, size_t valuelen)
{
	int res;

	if (!callbacks) {
		bbs_error("No KVS backend currently registered\n");
		return -1;
	}

	bbs_module_ref(kvsmod);
	res = callbacks->put(key, keylen, value, valuelen);
	bbs_module_unref(kvsmod);

	bbs_debug(6, "KVS PUT(%s) => %lu bytes\n", key, valuelen);
	return res;
}

int bbs_kvs_del(const char *key, size_t keylen)
{
	int res;

	if (!callbacks) {
		bbs_error("No KVS backend currently registered\n");
		return -1;
	}

	bbs_module_ref(kvsmod);
	res = callbacks->del(key, keylen);
	bbs_module_unref(kvsmod);

	bbs_debug(6, "KVS DEL(%s)\n", key);
	return res;
}
