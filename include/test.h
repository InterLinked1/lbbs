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
#define bbs_test_assert_str_equals(x, y) if (strcmp(x, y)) { bbs_warning("Test assertion failed: '%s' != '%s'\n", x, y); goto cleanup; }

/*! \brief Run all registered unit tests */
int bbs_run_tests(int fd);

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
