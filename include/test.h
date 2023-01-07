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
