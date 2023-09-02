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
 * \brief Numeric Range Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/test.h"
#include "include/range.h"

static int test_sequence_in_range(void)
{
	bbs_test_assert_equals(1, in_range("2:3,6", 2));
	bbs_test_assert_equals(1, in_range("2:3,6", 3));
	bbs_test_assert_equals(1, in_range("2:3,6", 6));
	bbs_test_assert_equals(0, in_range("2:3,6", 4));
	bbs_test_assert_equals(1, in_range("2:3,6,7:9", 8));
	bbs_test_assert_equals(1, in_range("1:*", 8));
	bbs_test_assert_equals(1, in_range("1:*", 6666));
	bbs_test_assert_equals(1, in_range("*", 13));
	bbs_test_assert_equals(1, in_range("1", 1));
	return 0;

cleanup:
	return -1;
}

static int test_range_generation(void)
{
	char *ranges;
	unsigned int a[6] = { 3, 5, 2, 1, 4, 6 };
	unsigned int b[6] = { 1, 2, 3, 5, 7, 8 };
	unsigned int c[6] = { 5, 6, 7, 3, 2, 1 };

	/* Ranges must be ascending only (RFC 5267 3.2) */

	ranges = uintlist_to_ranges(a, 6);
	bbs_test_assert_str_equals(ranges, "3,5,2,1,4,6");
	free_if(ranges);

	ranges = uintlist_to_ranges(b, 6);
	bbs_test_assert_str_equals(ranges, "1:3,5,7:8");
	free_if(ranges);

	ranges = uintlist_to_ranges(c, 6);
	bbs_test_assert_str_equals(ranges, "5:7,3,2,1");
	free_if(ranges);

	return 0;

cleanup:
	free_if(ranges);
	return -1;
}

static int test_copyuid_generation(void)
{
	unsigned int *a = NULL, *b = NULL;
	char *s = NULL;
	int lengths = 0, allocsizes = 0;

	uintlist_append2(&a, &b, &lengths, &allocsizes, 1, 11);
	uintlist_append2(&a, &b, &lengths, &allocsizes, 3, 13);
	uintlist_append2(&a, &b, &lengths, &allocsizes, 4, 14);
	uintlist_append2(&a, &b, &lengths, &allocsizes, 6, 16);

	s = gen_uintlist(a, lengths);
	bbs_test_assert_str_equals(s, "1,3:4,6");
	free_if(s);

	s = gen_uintlist(b, lengths);
	bbs_test_assert_str_equals(s, "11,13:14,16");
	free_if(s);

	free_if(a);
	free_if(b);
	return 0;

cleanup:
	free_if(a);
	free_if(b);
	free_if(s);
	return -1;
}

static struct bbs_unit_test tests[] =
{
	{ "IMAP FETCH Sequence Ranges", test_sequence_in_range },
	{ "IMAP Sequence Range Generation", test_range_generation },
	{ "IMAP COPYUID Generation", test_copyuid_generation },
};

static int unload_module(void)
{
	return bbs_unregister_tests(tests);
}

static int load_module(void)
{
	int res = bbs_register_tests(tests);
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_STANDARD("Range Unit Tests");
