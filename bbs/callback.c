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
 * \brief Module Callbacks
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/callback.h"
#include "include/module.h"

static inline void set_function_pointer(struct bbs_singular_callback *scb, void *ptr)
{
	/* We can't directly assign to *scb->func_pointer_ptr, since it's a void pointer,
	 * and we can't dereference void pointers in C.
	 * Therefore, cast to some arbitrary but concrete type, so we're allowed
	 * to make the assignment.
	 * This works, since all pointers are the same size. */
	int **ptraddress = scb->func_pointer_ptr;
	*ptraddress = (int*) ptr;
}

static inline int function_pointer_exists(struct bbs_singular_callback *scb)
{
	int **ptraddress = scb->func_pointer_ptr;
	return *ptraddress ? 1 : 0;
}

/*! \brief Dereference a void pointer. Yeah, you read that right. */
static inline void *function_pointer_value(struct bbs_singular_callback *scb)
{
	int **ptraddress = scb->func_pointer_ptr;
	return (void*) *ptraddress;
}

int bbs_singular_callback_destroy(struct bbs_singular_callback *scb)
{
	bbs_rwlock_destroy(&scb->lock);
	return 0;
}

int __bbs_singular_callback_register(struct bbs_singular_callback *scb, void *cbptr, void *mod, const char *file, int line, const char *func)
{
	bbs_rwlock_wrlock(&scb->lock);

	if (function_pointer_exists(scb)) {
		/* Already a callback function registered. */
		__bbs_log(LOG_ERROR, 0, file, line, func, "Could not register callback function %p (already one registered)\n", cbptr);
		bbs_rwlock_unlock(&scb->lock);
		return -1;
	}

	/* Yes, it may seem a bit dangerous that we're using void for a function pointer,
	 * but the idea is that we're being called by a function that accepts that function
	 * as an argument, so it's already passed type checking in that case. */
	set_function_pointer(scb, cbptr);
	scb->mod = mod;

	bbs_rwlock_unlock(&scb->lock);
	return 0;
}

int __bbs_singular_callback_unregister(struct bbs_singular_callback *scb, void *cbptr, const char *file, int line, const char *func)
{
	bbs_rwlock_wrlock(&scb->lock);
	if (cbptr != function_pointer_value(scb)) {
		__bbs_log(LOG_ERROR, 0, file, line, func, "Can't unregister callback function %p (not the one registered)\n", cbptr);
		bbs_rwlock_unlock(&scb->lock);
		return -1;
	}

	/* Locking is needed essentially to prevent TOCTOU (Time of Check, Time of Use) bugs.
	 * Without locking, one thread could check if the callback exists, but that callback
	 * could be unregistered before it actually executes it using the (now NULL) pointer. */
	set_function_pointer(scb, NULL);
	scb->mod = NULL;

	bbs_rwlock_unlock(&scb->lock);
	return 0;
}

int bbs_singular_callback_registered(struct bbs_singular_callback *scb)
{
	return function_pointer_exists(scb);
}

int __bbs_singular_callback_execute_pre(struct bbs_singular_callback *scb, void *refmod, const char *file, int line, const char *func)
{
	bbs_rwlock_rdlock(&scb->lock);
	if (!function_pointer_exists(scb)) {
		bbs_rwlock_unlock(&scb->lock);
		return -1; /* No callback registered */
	}
	if (scb->mod) {
		__bbs_module_ref(scb->mod, 100, refmod, file, line, func);
	}

	/* We don't actually execute the callback here, because
	 * the callbacks allowed by this API are completely arbitrary,
	 * and could have an arbitrary return type and number (and type) of parameters.
	 * We'll let the caller do that. */

	/* We intentionally return without unlocking scb->lock,
	 * since the call to bbs_singular_callback_execute_post will unlock.
	 * If scb->mod could never be NULL, we could technically unlock here,
	 * because the callback cannot be unregistered by the module providing it
	 * as long as that module is in use (has a positive refcount).
	 * However, to support the bbs_singular_callback API within the core,
	 * we just keep holding the read lock. Doesn't hurt anything, since we
	 * we wouldn't be able to unregister anyways while this is held,
	 * and a read lock won't inhibit concurrent invocations of the callback. */
	return 0;
}

int __bbs_singular_callback_execute_post(struct bbs_singular_callback *scb, void *refmod, const char *file, int line, const char *func)
{
	if (scb->mod) {
		__bbs_module_unref(scb->mod, 100, refmod, file, line, func);
	}
	bbs_rwlock_unlock(&scb->lock);
	return 0;
}
