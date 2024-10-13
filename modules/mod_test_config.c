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
 * \brief Config file parsing tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/test.h"
#include "include/config.h"
#include "include/utils.h"

#define START_TEST() \
	char *str1 = NULL, *str2 = NULL; \
	char template[256] = "/tmp/test_config_XXXXXX"; \
	FILE *fp = bbs_mkftemp(template, 0660); \
	if (!fp) { \
		return -1; \
	}

static int test_keyval_create(void)
{
	int mres, res = -1;
	char *tmp;
	int len2;
	START_TEST();

	fprintf(fp, "[general]\n");
	fprintf(fp, "foo = bar\n");
	fprintf(fp, "\n");
	fprintf(fp, "[settings]\n");
	fclose(fp);

	mres = bbs_config_set_keyval(template, "settings", "mykey", "test!"); /* Value same length for easy string replace */
	bbs_test_assert_equals(mres, 0);
	str2 = bbs_file_to_string(template, 0, &len2);
	bbs_test_assert_exists(str2);
	tmp = strstr(str2, "mykey = test!");
	bbs_test_assert_exists(tmp);

	res = 0;

cleanup:
	bbs_delete_file(template);
	free_if(str1);
	free_if(str2);
	return res;
}

static int test_keyval_update(void)
{
	int mres, res = -1;
	char *tmp;
	int len1, len2;
	START_TEST();

	fprintf(fp, "[general]\n");
	fprintf(fp, "foo = bar\n");
	fprintf(fp, "\n");
	fprintf(fp, "[settings]\n");
	fprintf(fp, "mykey = myval\n");
	fclose(fp);

	str1 = bbs_file_to_string(template, 0, &len1);
	bbs_test_assert_exists(str1);
	mres = bbs_config_set_keyval(template, "settings", "mykey", "test!"); /* Value same length for easy string replace */
	bbs_test_assert_equals(mres, 0);
	str2 = bbs_file_to_string(template, 0, &len2);
	bbs_test_assert_exists(str2);
	tmp = strstr(str1, "myval");
	bbs_test_assert_exists(tmp);
	memcpy(tmp, "test!", STRLEN("test!")); /* Don't copy a NUL terminator after */
	bbs_test_assert_str_equals(str1, str2);

	res = 0;

cleanup:
	bbs_delete_file(template);
	free_if(str1);
	free_if(str2);
	return res;
}

static int test_keyval_update_crlf(void)
{
	int mres, res = -1;
	char *tmp;
	int len1, len2;
	START_TEST();

	fprintf(fp, "[general]\r\n");
	fprintf(fp, "foo = bar\r\n");
	fprintf(fp, "\r\n");
	fprintf(fp, "[settings]\r\n");
	fprintf(fp, "mykey = myval\r\n");
	fprintf(fp, "\r\n");
	fprintf(fp, "[settings2]\r\n");
	fclose(fp);

	str1 = bbs_file_to_string(template, 0, &len1);
	bbs_test_assert_exists(str1);
	mres = bbs_config_set_keyval(template, "settings", "mykey", "test!"); /* Value same length for easy string replace */
	bbs_test_assert_equals(mres, 0);
	str2 = bbs_file_to_string(template, 0, &len2);
	bbs_test_assert_exists(str2);
	tmp = strstr(str1, "myval");
	bbs_test_assert_exists(tmp);
	memcpy(tmp, "test!", STRLEN("test!")); /* Don't copy a NUL terminator after */
	bbs_test_assert_str_equals(str1, str2);

	res = 0;

cleanup:
	bbs_delete_file(template);
	free_if(str1);
	free_if(str2);
	return res;
}

static struct bbs_unit_test tests[] =
{
	{ "Config Setting Create", test_keyval_create },
	{ "Config Setting Update", test_keyval_update },
	{ "Config Update Line Endings", test_keyval_update_crlf },
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

BBS_MODULE_INFO_STANDARD("Config File Unit Tests");
