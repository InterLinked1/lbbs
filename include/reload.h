/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief Core reload handlers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*!
 * \brief Register a reload handler
 * \param name Name of reload handler. Must be unique.
 * \param description A description of what this handler reloads.
 * \param reloader Reload callback that should return 0 on success
 * \retval 0 on success, -1 on failure
 * \note This API is for use in the core only. Module CANNOT use this API.
 *       Reload handlers are automatically unregistered only at shutdown.
 */
int bbs_register_reload_handler(const char *name, const char *description, int (*reloader)(int fd));
