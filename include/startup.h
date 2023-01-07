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

/*!
 * \brief Register a function to execute once the BBS has fully started
 *        This is useful when modules or parts of the core are unable
 *        to complete some initialization or task until all other modules
 *        have finished loading.
 * \param execute Callback function to run
 * \note This function can only be called during startup.
 * \retval 0 on success, -1 on failure
 */
int bbs_register_startup_callback(int (*execute)(void));

/*! \brief Run all startup callbacks */
int bbs_run_startup_callbacks(void);
