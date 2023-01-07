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
 * \brief Unit Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/module.h"
#include "include/test.h"
#include "include/variables.h"
#include "include/utils.h"

#define bbs_test_assert(x) if (!(x)) { bbs_warning("Test assertion failed: %s\n", #x); goto cleanup; }
#define bbs_test_assert_equals(x, y) if (!((x) == (y))) { bbs_warning("Test assertion failed: %s (%d != %d)\n", #x, (x), (y)); goto cleanup; }
#define bbs_test_assert_str_equals(x, y) if (strcmp(x, y)) { bbs_warning("Test assertion failed: '%s' != '%s'\n", x, y); goto cleanup; }

static int test_substitution(void)
{
	int res = -1;
	char buffer[256];
	/* Use BBS_TEST_ prefixed test vars so we don't conflict with anything */
	const char *orig = "Hello ${BBS_TEST_testvar}";
	const char *novars = "Hello there!";

	bbs_var_set(NULL, "BBS_TEST_testvar", "world");
	bbs_substitute_vars(NULL, orig, buffer, sizeof(buffer));
	bbs_test_assert_str_equals(buffer, "Hello world");

	/* Now reuse the buffer */
	bbs_var_set(NULL, "BBS_TEST_testvar", "!");
	bbs_substitute_vars(NULL, orig, buffer, sizeof(buffer));
	bbs_test_assert_str_equals(buffer, "Hello !");

	/* Substitution with no variables */
	bbs_substitute_vars(NULL, novars, buffer, sizeof(buffer));
	bbs_test_assert_str_equals(buffer, novars);

	res = 0; /* All passed */

cleanup:
	/* Clean up the mess we made */
	bbs_var_set(NULL, "BBS_TEST_testvar", NULL); /* Clean up the dummy global we made */
	return res;
}

static int test_safe_print(void)
{
	int res = -1;
	char buf[12];
	const char *s = "\tabc\n";

	bbs_test_assert(!bbs_str_safe_print(s, buf, sizeof(buf)));
	bbs_test_assert_str_equals(buf, "<9>abc<10>");
	return 0;

cleanup:
	return res;
}

static int test_printable_strlen(void)
{
	int res = -1;
	const char *s = COLOR(COLOR_GREEN) "abc";

	bbs_test_assert_equals(bbs_printable_strlen(s), 3);
	return 0;

cleanup:
	return res;
}

static struct unit_tests {
	const char *name;
	int (*callback)(void);
} tests[] =
{
	{ "Variable Substitution", test_substitution },
	{ "Safe Print", test_safe_print },
	{ "Printable String Length", test_printable_strlen },
};

static int load_module(void)
{
	int res = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_LEN(tests); i++) {
		res |= bbs_register_test(tests[i].name, tests[i].callback);
	}
	return res;
}

static int unload_module(void)
{
	int res = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_LEN(tests); i++) {
		res |= bbs_unregister_test(tests[i].callback);
	}
	return res;
}

BBS_MODULE_INFO_STANDARD("Unit Tests");
