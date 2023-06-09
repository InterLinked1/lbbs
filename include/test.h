/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Unit Test Framework
 *
 */

#define bbs_test_assert(x) if (!(x)) { bbs_warning("Test assertion failed: %s\n", #x); goto cleanup; }
#define bbs_test_assert_equals(x, y) if (!((x) == (y))) { bbs_warning("Test assertion failed: (%d != %d)\n", (x), (y)); goto cleanup; }
#define bbs_test_assert_size_equals(x, y) if (!((x) == (y))) { bbs_warning("Test assertion failed: (%lu != %lu)\n", (x), (y)); goto cleanup; }
#define bbs_test_assert_exists(x) if ((x) == NULL) { bbs_warning("Test assertion failed: (%s != NULL)\n", #x); goto cleanup; }
#define bbs_test_assert_null(x) if (!((x) == NULL)) { bbs_warning("Test assertion failed: (%p == NULL)\n", (x)); goto cleanup; }
#define bbs_test_assert_mem_equals(x, y, sz) if (memcmp(x, y, sz)) { bbs_warning("Test assertion failed: '%s' != '%s'\n", x, y); goto cleanup; }
#define bbs_test_assert_str_equals(x, y) if (strcmp(x, y)) { bbs_warning("Test assertion failed: '%s' != '%s'\n", x, y); goto cleanup; }
#define bbs_test_assert_str_exists_equals(x, y) if (strlen_zero(x) || strcmp(x, y)) { bbs_warning("Test assertion failed: '%s' != '%s'\n", x, y); goto cleanup; }
#define bbs_test_assert_str_exists_contains(x, y) if (strlen_zero(x) || !strstr(x, y)) { bbs_warning("Test assertion failed: '%s' does not contain '%s'\n", x, y); goto cleanup; }

/*! \brief Run all registered unit tests */
int bbs_run_tests(int fd);

/*!
 * \brief Run a specific unit test
 * \param fd
 * \param name Name of test to run
 * \retval 0 on success, -1 on failure
 */
int bbs_run_test(int fd, const char *name);

/*!
 * \brief Registers a unit test
 * \param name Name of unit test
 * \param exec Function
 * \retval 0 on success, non-zero on failure
 */
#define bbs_register_test(name, exec) __bbs_register_test(name, exec, BBS_MODULE_SELF)

int __bbs_register_test(const char *name, int (*execute)(void), void *mod);

/*! \brief Unregister a unit test */
int bbs_unregister_test(int (*execute)(void));

struct bbs_unit_test {
	const char *name;
	int (*callback)(void);
};

int __bbs_register_tests(struct bbs_unit_test tests[], unsigned int len, void *mod);

/*! \brief Register multiple unit tests */
#define bbs_register_tests(tests) __bbs_register_tests(tests, ARRAY_LEN(tests), BBS_MODULE_SELF)

/*! \brief Unregister multiple unit tests */
int __bbs_unregister_tests(struct bbs_unit_test tests[], unsigned int len);

#define bbs_unregister_tests(tests) __bbs_unregister_tests(tests, ARRAY_LEN(tests))
