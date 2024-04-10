/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Abstract I/O transformations interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/io.h"

/* Unlike most I/O stream abstractions, such as OpenSSL's BIO,
 * Dovecot's read/write streams, and libetpan's "low" interface,
 * this is not a truly abstract I/O interface.
 * It is an interface that is highly coupled to file descriptors,
 * since much of the I/O in the BBS is currently written to depend on that.
 * While it would be more performant to be able to call I/O callback functions
 * that could, for example, call SSL_write directly under the hood,
 * rather than first writing to a pipe which is then drained in another
 * thread and passed to SSL_write, at this point, it would require
 * substantial work to refactor everything not to use file descriptors directly,
 * since initially it was only needed for TLS and nothing else.
 *
 * This abstraction is still useful, since instead of keeping track
 * of multiple read/write file descriptors, we can continue to only
 * use one and I/O modules will be responsible for setting up their
 * own intermediate layer. This also allows for modularity since
 * dependencies for particular kinds of I/O transformations (e.g. TLS, compression)
 * need not be embedded in the core, but can be implemented in their own modules.
 */

struct bbs_io_transformer {
	const char *name;
	enum bbs_io_transform_type type;
	enum bbs_io_transform_dir dir;
	int (*setup)(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg);
	int (*query)(struct bbs_io_transformation *tran, int query, void *data);
	void (*cleanup)(struct bbs_io_transformation *tran);
	void *module;
	RWLIST_ENTRY(bbs_io_transformer) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(transformers, bbs_io_transformer);

int __bbs_io_transformer_register(const char *name, int (*setup)(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg),
	int (*query)(struct bbs_io_transformation *tran, int query, void *data),
	void (*cleanup)(struct bbs_io_transformation *tran), enum bbs_io_transform_type type, enum bbs_io_transform_dir dir, void *module)
{
	struct bbs_io_transformer *t;

	RWLIST_WRLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (!strcasecmp(name, t->name)) {
			RWLIST_UNLOCK(&transformers);
			bbs_error("I/O transformer '%s' already registered\n", name);
			return -1;
		}
	}
	t = calloc(1, sizeof(*t) + strlen(name) + 1);
	if (ALLOC_FAILURE(t)) {
		RWLIST_UNLOCK(&transformers);
		return -1;
	}
	strcpy(t->data, name); /* Safe */
	t->name = t->data;
	t->module = module;
	t->setup = setup;
	t->query = query;
	t->cleanup = cleanup;
	t->type = type;
	t->dir = dir;
	RWLIST_INSERT_TAIL(&transformers, t, entry);
	RWLIST_UNLOCK(&transformers);

	return 0;
}

int bbs_io_transformer_unregister(const char *name)
{
	struct bbs_io_transformer *t;

	RWLIST_WRLOCK(&transformers);
	RWLIST_TRAVERSE_SAFE_BEGIN(&transformers, t, entry) {
		if (!strcasecmp(name, t->name)) {
			RWLIST_REMOVE_CURRENT(entry);
			free(t);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&transformers);

	return t ? 0 : -1;
}

int bbs_io_named_transformer_available(const char *name)
{
	struct bbs_io_transformer *t;

	RWLIST_RDLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (!strcmp(name, t->name)) {
			break;
		}
	}
	RWLIST_UNLOCK(&transformers);

	if (!t) {
		bbs_debug(3, "No such transformer named '%s'\n", name);
	}

	return t ? 1 : 0;
}

int bbs_io_transformer_available(enum bbs_io_transform_type transform_type)
{
	struct bbs_io_transformer *t;

	RWLIST_RDLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (t->type == transform_type) {
			break;
		}
	}
	RWLIST_UNLOCK(&transformers);

	if (!t) {
		bbs_debug(3, "No such transformer of type %d\n", transform_type);
	}

	return t ? 1 : 0;
}

static int io_transform_slots_free(struct bbs_io_transformations *trans)
{
	int i;

	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (!trans->transformations[i].transformer) {
			/* Not in use */
			return 1;
		}
	}
	return 0;
}

static int io_transform_store(struct bbs_io_transformations *trans, struct bbs_io_transformer *t, void *data)
{
	int i;

	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (!trans->transformations[i].transformer) {
			trans->transformations[i].data = data;
			trans->transformations[i].transformer = t;
			bbs_debug(7, "Set up node I/O transformer at index %d\n", i);
			return 0;
		}
	}
	/* Shouldn't happen since only one thread is really handling a node's I/O at a time */
	bbs_error("Failed to store transformation\n");
	return -1;
}

static int __bbs_io_transform_possible(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, int warn)
{
	if (bbs_io_transform_active(trans, type)) {
		if (warn) {
			bbs_error("Transformation %d already active, declining to set up duplicate transformation\n", type);
		}
		return 0;
	}

	/* TLS compression is disabled, so we don't need to worry about rejecting TRANSFORM_DEFLATE_COMPRESSION
	 * if that were already to be active (as normally, that would conflict). */

	/* XXX Ideally, ordering constraints would be specified in the modules themselves,
	 * but since this involves both of them, just put it here for now: */
	if (type == TRANSFORM_TLS_ENCRYPTION) {
		if (bbs_io_transform_active(trans, TRANSFORM_DEFLATE_COMPRESSION)) {
			/* Since I/O transformations are pushed onto a stack of file descriptors, effectively,
			 * but TLS must happen after compression, it is too late to begin encryption.
			 * The current I/O transformation architecture doesn't really us to add transformations
			 * underneath existing ones. */
			if (warn) {
				bbs_warning("Can't enable encryption after compression has already been enabled, enable encryption prior to compression instead\n");
			}
			return 0;
		}
	}
	return 1;
}

int bbs_io_transform_possible(struct bbs_io_transformations *trans, enum bbs_io_transform_type type)
{
	return __bbs_io_transform_possible(trans, type, 0);
}

int bbs_io_transform_setup(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, enum bbs_io_transform_dir direction, int *rfd, int *wfd, const void *arg)
{
	int res;
	void *data = NULL;
	struct bbs_io_transformer *t;

	if (!__bbs_io_transform_possible(trans, type, 1)) {
		return -1;
	}

	RWLIST_RDLOCK(&transformers);
	if (!io_transform_slots_free(trans)) {
		RWLIST_UNLOCK(&transformers);
		bbs_error("Already at max transformations (%d)\n", MAX_IO_TRANSFORMS);
		return -1;
	}
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (!(t->dir & direction)) {
			continue;
		}
		if (t->type == type) {
			break;
		}
	}

	if (!t) {
		/* Should use bbs_io_transformer_available before to check.
		 * Yes, that is TOCTOU, but this should happen infrequently,
		 * although it is possible, hence a warning, not an error: */
		RWLIST_UNLOCK(&transformers);
		bbs_warning("No suitable transformer found (type %d)\n", type);
		return -1;
	}

	res = t->setup(rfd, wfd, direction, &data, arg);

	/* Store transform private data on node */
	if (!res) {
		if (io_transform_store(trans, t, data)) {
			struct bbs_io_transformation tran;
			tran.transformer = t;
			tran.data = data;
			t->cleanup(&tran);
			res = 1;
		} else {
			bbs_module_ref(t->module, 1);
		}
	}
	RWLIST_UNLOCK(&transformers);

	return res;
}

int bbs_io_transform_active(struct bbs_io_transformations *trans, enum bbs_io_transform_type type)
{
	int i, active = 0;

	RWLIST_RDLOCK(&transformers);
	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (trans->transformations[i].data) {
			struct bbs_io_transformer *t = trans->transformations[i].transformer;
			if (t->type == type) {
				active = 1;
				break;
			}
		}
	}
	RWLIST_UNLOCK(&transformers);

	return active;
}

int bbs_io_transform_query(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, int query, void *data)
{
	int i;
	int res = -1;

	RWLIST_RDLOCK(&transformers);
	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (trans->transformations[i].data) {
			struct bbs_io_transformer *t = trans->transformations[i].transformer;
			if (t->type == type) {
				if (t->query) {
					res = t->query(&trans->transformations[i], query, data);
				} else {
					res = 1;
				}
				break;
			}
		}
	}
	RWLIST_UNLOCK(&transformers);

	return res;
}

static void teardown_transformation(struct bbs_io_transformation *tran)
{
	struct bbs_io_transformer *t = tran->transformer;
	t->cleanup(tran);
	tran->data = NULL;
	tran->transformer = NULL;
	bbs_module_unref(t->module, 1);
}

void bbs_io_teardown_all_transformers(struct bbs_io_transformations *trans)
{
	int i;

	RWLIST_RDLOCK(&transformers);
	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (trans->transformations[i].data) {
			bbs_debug(7, "Removing I/O transformer at index %d\n", i);
			teardown_transformation(&trans->transformations[i]);
		}
	}
	RWLIST_UNLOCK(&transformers);
}
