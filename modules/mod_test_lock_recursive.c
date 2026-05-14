/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Recursive Lock Test
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/test.h"
#include "include/thread.h"

static bbs_rwlock_t rwlock = BBS_RWLOCK_INITIALIZER;
static int test_state = 0;

static void *lock_a(void *varg)
{
	UNUSED(varg);

	bbs_rwlock_rdlock(&rwlock);
	test_state = 1;
	while (test_state != 2) {
		usleep(1000);
	}
	/* Wait long enough after the wrlock attempt that we're
	 * sure the wrlock attempt is already in progress at this point. */
	usleep(SEC_MS(5));
	bbs_rwlock_unlock(&rwlock);
	return NULL;
}

static int test_recursive_rwlock(void)
{
	int res;
	pthread_t a = 0;

	res = bbs_pthread_create(&a, NULL, lock_a, NULL);
	if (res) {
		return -1;
	}

	while (test_state != 1) {
		usleep(1000);
	}

	/* Now, another thread also grabs a rdlock */
	bbs_rwlock_rdlock(&rwlock);
	/* mutex has 2 owners */
	bbs_rwlock_unlock(&rwlock);
	/* mutex is back to just the original owner */

	test_state = 2;

	/* Now, attempt a wrlock */
	bbs_rwlock_wrlock(&rwlock);
#if 0
	/* The test should pass normally as there is no actual recursive locking attempt.
	 * Running this line would actually cause a recursive locking attempt,
	 * which SHOULD cause an assertion (and does if you test this manually, but
	 * for obvious reasons we don't test that an assertion occured normally.) */
	bbs_rwlock_wrlock(&rwlock);
#endif
	bbs_rwlock_unlock(&rwlock);

	bbs_pthread_join(a, NULL);

	/* Test passes if we got here; a false assertion crashing the BBS is implicitly a failure. */
	return 0;
}

static struct bbs_unit_test tests[] =
{
	{ "Recursive RWLOCK Test", test_recursive_rwlock },
};

static int unload_module(void)
{
	return bbs_unregister_tests(tests);
}

static int load_module(void)
{
	return bbs_register_tests(tests);
}

BBS_MODULE_INFO_STANDARD("Recursive Lock Unit Tests");
