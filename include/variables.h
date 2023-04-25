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
 * \brief BBS variables
 *
 * \note Everything is case-sensitive! (Variable names and values alike)
 *
 */

#include "include/linkedlists.h"

/* Forward declarations */
struct bbs_node;
struct bbs_var;
RWLIST_HEAD(bbs_vars, bbs_var);

/*! \brief Destroy and free a variable list */
void bbs_vars_destroy(struct bbs_vars *vars);

/*! \brief Called during shutdown to free global variables */
void bbs_vars_cleanup(void);

/*! \brief Load variables on startup from variables.conf */
int bbs_vars_init(void);

/*!
 * \brief Set a variable
 * \param node If NULL, variable will be set globally.
 * \param key Name of variable. Case-sensitive.
 * \param value New or updated variable value. To delete a variable already set, use NULL.
 * \retval 0 if variable was successfully added, updated, or deleted, and -1 on failure.
 */
int bbs_var_set(struct bbs_node *node, const char *key, const char *value);

/*!
 * \brief Set a global variable using config input
 * \param key Name of variable. Case-sensitive.
 * \param value New or updated variable value. To delete a variable already set, use NULL.
 * \note This function should not be used by the BBS itself for setting BBS variables, only for setting variables from user configs.
 * \retval 0 if variable was successfully added, updated, or deleted, and -1 on failure.
 */
int bbs_var_set_user(const char *key, const char *value);

/*!
 * \brief Set a variable using a format string
 * \param node If NULL, variable will be set globally.
 * \param key Name of variable. Case-sensitive.
 * \param fmt printf-style format string
 * \retval 0 if variable was successfully added, updated, or deleted, and -1 on failure.
 */
int bbs_var_set_fmt(struct bbs_node *node, const char *key, const char *fmt, ...) __attribute__ ((format (gnu_printf, 3, 4))) ;

/*!
 * \brief Enumerate all variables
 * \param fd File descriptor to which to print
 * \param node Node for which to list variables. If NULL, all global variables will be dumped.
 */
int bbs_vars_dump(int fd, struct bbs_node *node);

/*!
 * \brief Get a variable
 * \param node If provided, the node will also be searched for variables, after global variables.
 * \param key Name of variable. Case-sensitive.
 * \warning The node must be locked while calling this function to ensure race condition safety. This function is not safe for global variables. Avoid if possible.
 * \returns value if found, NULL if not found
 */
const char *bbs_var_get(struct bbs_node *node, const char *key);

/*!
 * \brief Get a variable
 * \param node If provided, the node will also be searched for variables, after global variables.
 * \param key Name of variable. Case-sensitive.
 * \param buf Buffer into which to copy variable value, if it exists. If the variable is not found, the buffer will be null terminated as a courtesy.
 * \param len Size of buf.
 * \retval 0 if found, -1 if not found
 */
int bbs_var_get_buf(struct bbs_node *node, const char *key, char *buf, size_t len);

/*!
 * \brief Substitute variables in a string
 * \param node If provided, the node will also be searched for variables, after global variables.
 * \param sub Original string from which to substitute variables
 * \param buf Buffer into which to copy variable value, if it exists. If the variable is not found, the buffer will be null terminated as a courtesy.
 * \param len Size of buf.
 * \retval 0 if found, -1 if not found
 */
int bbs_substitute_vars(struct bbs_node *node, const char *sub, char *buf, size_t len);
