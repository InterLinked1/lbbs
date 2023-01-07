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
 * \brief BBS menu handlers
 *
 */

/* Forward declarations */
struct bbs_node;
struct bbs_module;

/*!
 * \brief Registers a menu handler
 * \param name Name of menu handler (must be unique globally)
 * \param exec Function
 * \param needargs Whether this handler requires arguments (1 = yes, 0 = optional). If 1, the handler function will never be called without arguments.
 * \retval 0 on success
 * \retval -1 on failure
 */
#define bbs_register_menu_handler(name, exec, needargs) __bbs_register_menu_handler(name, exec, needargs, BBS_MODULE_SELF)

int __bbs_register_menu_handler(const char *name, int (*execute)(struct bbs_node *node, char *args), int needargs, void *mod);

/*! \brief Unregister a menu handler */
int bbs_unregister_menu_handler(const char *name);

/*! \brief Print list of hmenu andlers */
int bbs_list_menu_handlers(int fd);

/*!
 * \brief Whether a menu handler exists for a given menu action name
 * \param name Menu handler name
 * \param needargs If provided, will be set to whether or not this handler requires arguments.
 * \retval 1 if exists, 0 if doesn't exist
 */
int menu_handler_exists(const char *name, int *needargs);

/*!
 * \brief Execute a named menu handler (for use by menu.c)
 * \param node
 * \param name Name of menu handler to execute
 * \param args Arguments to menu handler. This is intentionally char and not const char
 *        since many handlers need to parse the arguments into chunks and this allows them to do that in place.
 * \retval -3 return from all menus and set res to 0 (will break menu loop in menu.c)
 * \retval -2 return from current menu and set res to 0 (will break menu loop in menu.c)
 * \retval -1 immediately disconnect
 * \retval 0 normal menu item return (success)
 */
int menu_handler_exec(struct bbs_node *node, const char *name, char *args);
