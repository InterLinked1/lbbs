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
 * \brief Startup Callbacks
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>

#include "include/linkedlists.h"
#include "include/startup.h"

struct startup_callback {
	int (*execute)(void);	/*!< Callback function */
	int priority;			/*!< Priority */
	RWLIST_ENTRY(startup_callback) entry; /*!< Next entry */
};

static RWLIST_HEAD_STATIC(callbacks, startup_callback);

static int started = 0;

int bbs_register_startup_callback(int (*execute)(void), int priority)
{
	struct startup_callback *cb;

	RWLIST_WRLOCK(&callbacks);
	if (started) {
		bbs_error("BBS is already fully started: startup callbacks cannot be registered anymore\n");
		RWLIST_UNLOCK(&callbacks);
		return -1;
	}
	cb = calloc(1, sizeof(*cb));
	if (ALLOC_FAILURE(cb)) {
		RWLIST_UNLOCK(&callbacks);
		return -1;
	}
	cb->execute = execute;
	cb->priority = priority;
	/* Tail insert, so they run in the order registered */
	RWLIST_INSERT_SORTED(&callbacks, cb, entry, priority);
	bbs_debug(3, "Registered startup callback %p\n", execute);
	RWLIST_UNLOCK(&callbacks);
	return 0;
}

int bbs_run_when_started(int (*execute)(void), int priority)
{
	if (bbs_is_fully_started()) {
		return execute();
	} else {
		return bbs_register_startup_callback(execute, priority);
	}
}

int bbs_run_startup_callbacks(void)
{
	struct startup_callback *cb;

	RWLIST_WRLOCK(&callbacks);
	while ((cb = RWLIST_REMOVE_HEAD(&callbacks, entry))) {
		cb->execute();
		free(cb);
	}
	started = 1;
	RWLIST_UNLOCK(&callbacks);
	return 0;
}
