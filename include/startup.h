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
 * \brief Startup Callbacks
 *
 */

/*! \brief Urgent startup priority */
#define STARTUP_PRIORITY_URGENT 0

/*! \brief Default priority when it doesn't matter at all */
#define STARTUP_PRIORITY_DEFAULT 10

/*! \brief Dependent startup priority */
#define STARTUP_PRIORITY_DEPENDENT 50

/*!
 * \brief Register a function to execute once the BBS has fully started
 *        This is useful when modules or parts of the core are unable
 *        to complete some initialization or task until all other modules
 *        have finished loading.
 * \param execute Callback function to run
 * \param priority Startup callback priority. Lower number priorities will be run earlier.
 *                 Simple callbacks with no dependencies (especially those that may be dependencies of other callbacks) must be run first.
 * \note This function can only be called during startup.
 * \retval 0 on success, -1 on failure
 */
int bbs_register_startup_callback(int (*execute)(void), int priority);

/*! \brief Run all startup callbacks */
int bbs_run_startup_callbacks(void);
