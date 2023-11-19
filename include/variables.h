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

/*! \brief Remove the first variable in a variable list */
void bbs_vars_remove_first(struct bbs_vars *vars);

/*!
 * \brief Peek at the first variable in a variable list
 * \param vars
 * \param[out] Variable value
 * \return Variable key, or NULL if list is empty
 */
const char *bbs_vars_peek_head(struct bbs_vars *vars, char **value);

/*!
 * \brief Get the next variable in a variable list
 * \param vars
 * \param[out] Next variable for iterator
 * \param[out] Variable key
 * \return Next variable value, or NULL if no next value
 */
const char *bbs_varlist_next(struct bbs_vars *vars, struct bbs_var **v, const char **key);

/*! \brief Called during shutdown to free global variables */
void bbs_vars_cleanup(void);

/*! \brief Load variables on startup from variables.conf */
int bbs_vars_init(void);

/*!
 * \brief Initialize custom user-specific node variables upon user login
 * \param node Authenticated node
 * \retval 0 on success, -1 on failure
 */
int bbs_user_init_vars(struct bbs_node *node);

/*!
 * \brief Append to the variable added most recently to a list
 * \param vars
 * \param s Data to append
 * \retval 0 on success, -1 on failure
 */
int bbs_varlist_last_var_append(struct bbs_vars *vars, const char *s);

/*!
 * \brief Add to or update a variable in a list
 * \param vars
 * \param key Variable name
 * \param value Variable value
 * \retval 0 on success, -1 on failure
 */
int bbs_varlist_append(struct bbs_vars *vars, const char *key, const char *value);

/*!
 * \brief Set a variable
 * \param node If NULL, variable will be set globally.
 * \param key Name of variable. Case-sensitive.
 * \param value New or updated variable value. To delete a variable already set, use NULL.
 * \retval 0 if variable was successfully added, updated, or deleted, and -1 on failure.
 */
int bbs_node_var_set(struct bbs_node *node, const char *key, const char *value);

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
int bbs_node_var_set_fmt(struct bbs_node *node, const char *key, const char *fmt, ...) __attribute__ ((format (gnu_printf, 3, 4))) ;

/*!
 * \brief Get a variable
 * \param vars
 * \param key Name of variable. Case-sensitive.
 * \returns value if found, NULL if not found
 */
const char *bbs_var_find(struct bbs_vars *vars, const char *key);

/*! \brief Same as bbs_var_find, but does a case-insensitive search */
const char *bbs_var_find_case(struct bbs_vars *vars, const char *key);

/*!
 * \brief Enumerate all variables
 * \param fd File descriptor to which to print
 * \param node Node for which to list variables. If NULL, all global variables will be dumped.
 */
int bbs_node_vars_dump(int fd, struct bbs_node *node);

/*!
 * \brief Get a variable
 * \param node If provided, the node will also be searched for variables, after global variables.
 * \param key Name of variable. Case-sensitive.
 * \warning The node must be locked while calling this function to ensure race condition safety. This function is not safe for global variables. Avoid if possible.
 * \returns value if found, NULL if not found
 */
const char *bbs_node_var_get(struct bbs_node *node, const char *key);

/*!
 * \brief Get a variable
 * \param node If provided, the node will also be searched for variables, after global variables.
 * \param key Name of variable. Case-sensitive.
 * \param buf Buffer into which to copy variable value, if it exists. If the variable is not found, the buffer will be null terminated as a courtesy.
 * \param len Size of buf.
 * \retval 0 if found, -1 if not found
 */
int bbs_node_var_get_buf(struct bbs_node *node, const char *key, char *buf, size_t len);

/*!
 * \brief Substitute variables in a string
 * \param node If provided, the node will also be searched for variables, after global variables.
 * \param sub Original string from which to substitute variables
 * \param buf Buffer into which to copy variable value, if it exists. If the variable is not found, the buffer will be null terminated as a courtesy.
 * \param len Size of buf.
 * \retval 0 if found, -1 if not found
 */
int bbs_node_substitute_vars(struct bbs_node *node, const char *sub, char *buf, size_t len);
