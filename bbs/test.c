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
 * \brief Unit Test Framework
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <sys/time.h> /* use gettimeofday */

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/test.h"
#include "include/utils.h" /* use bbs_tvdiff_ms */

struct bbs_test {
	int (*execute)(void);		/*!< Test callback function */
	struct bbs_module *module;	/*!< Module registering test */
	int result;					/*!< Return value from last test run */
	unsigned int time;			/*!< Total time to run test, in ms */
	unsigned int executed:1;	/*!< Whether test has been executed */
	RWLIST_ENTRY(bbs_test) entry;	/*!< Next test */
	char name[0];				/*!< Name */
};

static RWLIST_HEAD_STATIC(tests, bbs_test);

static int test_execute(struct bbs_test *test)
{
	int res;
	struct timeval begin, end;

	bbs_debug(5, "Starting test '%s'\n", test->name);

	bbs_module_ref(test->module);
	gettimeofday(&begin, NULL);
	res = test->result = test->execute();
	gettimeofday(&end, NULL);
	bbs_module_unref(test->module);

	bbs_debug(5, "Test '%s' returned %d\n", test->name, res);
	test->executed = 1;

	test->time = (unsigned int) bbs_tvdiff_ms(end, begin);
	return res;
}

int bbs_run_test(int fd, const char *name)
{
	int res = 0;
	int total = 0, passed = 0;
	struct bbs_test *test;

	RWLIST_RDLOCK(&tests); /* Prevent test from being unregistered while running */
	RWLIST_TRAVERSE(&tests, test, entry) {
		int mres;
		if (name && strcasecmp(name, test->name)) {
			continue;
		}
		total++;
		mres = test_execute(test); /* execute the test and save results */
		res |= mres;
		if (!mres) {
			passed++;
		}
		if (fd != -1) {
			bbs_dprintf(fd, "%s%-7s%s %-32s %1s%4ums\n",
				test->result || !test->executed ? COLOR(COLOR_FAILURE) : COLOR(COLOR_SUCCESS),
				test->executed ? test->result ? "FAIL" : "PASS" : "NOT RUN",
				COLOR_RESET,
				test->name,
				test->time ? "" : "<",
				test->time ? test->time : 1);
		}
	}
	/* Summarize */
	if (fd) {
		if (total) {
			bbs_dprintf(fd, " == Tests Complete == \n");
			RWLIST_TRAVERSE(&tests, test, entry) {
				if (name && strcasecmp(name, test->name)) {
					continue;
				}
				bbs_dprintf(fd, "%s%-7s%s %-32s %1s%4ums\n",
					test->result || !test->executed ? COLOR(COLOR_FAILURE) : COLOR(COLOR_SUCCESS),
					test->executed ? test->result ? "FAIL" : "PASS" : "NOT RUN",
					COLOR_RESET,
					test->name,
					test->time ? "" : "<",
					test->time ? test->time : 1);
			}
			/* Stats */
			bbs_dprintf(fd, "%s%d%%%s of tests passed\n", passed == total ? COLOR(COLOR_SUCCESS) : COLOR(COLOR_FAILURE), (int) (100.0 * passed / total), COLOR_RESET);
		} else if (name) {
			bbs_dprintf(fd, "No such test: %s\n", name);
		}
	}
	RWLIST_UNLOCK(&tests);

	return res;
}

int bbs_run_tests(int fd)
{
	return bbs_run_test(fd, NULL);
}

int __bbs_register_test(const char *name, int (*execute)(void), void *mod)
{
	struct bbs_test *test;

	RWLIST_WRLOCK(&tests);

	RWLIST_TRAVERSE(&tests, test, entry) {
		if (test->execute == execute) {
			break;
		}
	}
	if (test) {
		RWLIST_UNLOCK(&tests);
		bbs_error("Test %s (%p) already registered\n", name, execute);
		return -1;
	}

	test = calloc(1, sizeof(*test) + strlen(name) + 1);
	if (ALLOC_FAILURE(test)) {
		return -1;
	}

	test->execute = execute;
	test->module = mod;
	strcpy(test->name, name); /* Safe */

	RWLIST_INSERT_TAIL(&tests, test, entry);
	RWLIST_UNLOCK(&tests);

	return 0;
}

int bbs_unregister_test(int (*execute)(void))
{
	struct bbs_test *test;

	test = RWLIST_WRLOCK_REMOVE_BY_FIELD(&tests, execute, execute, entry);
	if (!test) {
		bbs_error("Tried to remove test %p that wasn't registered?\n", execute);
		return -1;
	}

	free(test);
	return 0;
}
