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
	/*! Callback function */
	int (*execute)(void);
	/* Next entry */
	RWLIST_ENTRY(startup_callback) entry;
};

static RWLIST_HEAD_STATIC(callbacks, startup_callback);

static int started = 0;

int bbs_register_startup_callback(int (*execute)(void))
{
	struct startup_callback *cb;

	RWLIST_WRLOCK(&callbacks);
	if (started) {
		bbs_error("BBS is already fully started: startup callbacks cannot be registered anymore\n");
		RWLIST_UNLOCK(&callbacks);
		return -1;
	}
	cb = calloc(1, sizeof(*cb));
	if (!cb) {
		RWLIST_UNLOCK(&callbacks);
		return -1;
	}
	cb->execute = execute;
	/* Tail insert, so they run in the order registered */
	RWLIST_INSERT_TAIL(&callbacks, cb, entry);
	bbs_debug(3, "Registered startup callback %p\n", execute);
	RWLIST_UNLOCK(&callbacks);
	return 0;
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
