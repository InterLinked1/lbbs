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
 * \brief Authentication
 *
 */

/* Forward declarations */
struct bbs_node;
struct bbs_user;

#define AUTH_PROVIDER_PARAMS struct bbs_user *user, const char *username, const char *password

/*!
 * \brief Register a user registration provider
 * \param regprovider Callback function to execute that fully handles user registration.
 * \note Only one user registration provider may be registered system-wide.
 */
#define bbs_register_user_registration_provider(regprovider) __bbs_register_user_registration_provider(regprovider, BBS_MODULE_SELF)

int __bbs_register_user_registration_provider(int (*regprovider)(struct bbs_node *node), void *mod);

/*!
 * \brief Unregister a previously registered user registration provider
 * \param regprovider Callback function to execute that fully handles user registration.
 * \note Only one user registration provider may be registered system-wide.
 */
int bbs_unregister_user_registration_provider(int (*regprovider)(struct bbs_node *node));

/*!
 * \brief Attempt to register a new user
 * \param node
 * \retval 0 if user registered successfully, 1 on failed registration, -1 to disconnect
 */
int bbs_user_register(struct bbs_node *node);

/*!
 * \brief Register a password reset handler
 * \param handler Callback function to execute that will reset a password. The function should return 0 on success and nonzero on failure.
 * \note Only one password reset handler may be registered system-wide.
 */
#define bbs_register_password_reset_handler(handler) __bbs_register_password_reset_handler(handler, BBS_MODULE_SELF)

int __bbs_register_password_reset_handler(int (*handler)(const char *username, const char *password), void *mod);

/*!
 * \brief Unregister a previously registered password reset handler
 * \param handler Callback function to execute that will reset a user's password to the provided one. The function should return 0 on success and nonzero on failure.
 * \note Only one password reset handler may be registered system-wide.
 */
int bbs_unregister_password_reset_handler(int (*handler)(const char *username, const char *password));

/*!
 * \brief Attempt to reset a user's password. This may be used for user password change and sysop/self-service password resets
 * \param username Username of user whose password should be changed
 * \param password The new password
 * \retval 0 if password updated successfully, nonzero on failure.
 * \warning This function assumes that any invocation of it is authorized. This must be properly wrapped.
 */
int bbs_user_reset_password(const char *username, const char *password);

/*!
 * \brief Register a user info handler
 * \param handler Callback function to execute that will return a BBS user with details about the specified user. The callback should return NULL if no such user or failure.
 * \note Only one user info handler may be registered system-wide.
 */
#define bbs_register_user_info_handler(handler) __bbs_register_user_info_handler(handler, BBS_MODULE_SELF)

int __bbs_register_user_info_handler(struct bbs_user* (*handler)(const char *username), void *mod);

/*!
 * \brief Unregister a previously registered user info handler
 * \param handler Callback function to execute that will return a BBS user with details about the specified user. The callback should return NULL if no such user or failure.
 * \note Only one user info handler may be registered system-wide.
 */
int bbs_unregister_user_info_handler(struct bbs_user* (*handler)(const char *username));

/*!
 * \brief Retrieve the bbs_user struct corresponding to a user, e.g. for looking up details of a user that is not currently logged in.
 * \param username
 * \retval user on success, NULL on failure. The returned struct must be freed using bbs_user_destroy.
 */
struct bbs_user *bbs_user_info_by_username(const char *username);

/*!
 * \brief Register a user list handler
 * \param handler Callback function to execute that will return an array of BBS users.
 * \note Only one user list handler may be registered system-wide.
 */
#define bbs_register_user_list_handler(handler) __bbs_register_user_list_handler(handler, BBS_MODULE_SELF)

int __bbs_register_user_list_handler(struct bbs_user** (*handler)(void), void *mod);

/*!
 * \brief Unregister a previously registered user list handler
 * \param handler Callback function to execute that will return an array of BBS users.
 * \note Only one user list handler may be registered system-wide.
 */
int bbs_unregister_user_list_handler(struct bbs_user** (*handler)(void));

/*!
 * \brief Retrieve an array of all registered BBS users. The array is NULL terminated.
 * \retval user list on success, NULL on failure. The user list must be freed using bbs_user_list_destroy (see user.h).
 */
struct bbs_user **bbs_user_list(void);

/*! \brief Clean up any cached logins */
void login_cache_cleanup(void);

/*!
 * \brief Generate a temporary token that can be used to authenticate a user in lieu of a password
 * \param user
 * \param[out] buf
 * \param len Must be at least 48.
 * \retval 0 on success, -1 on failure
*/
int bbs_user_temp_authorization_token(struct bbs_user *user, char *buf, size_t len);

/*!
 * \brief Attempt to authenticate a user
 * \param user
 * \param username User-attempted username. NULL for guest.
 * \param password User-attempted password. NULL for guest.
 * \retval 0 if user authenticated successfully, -1 if wrong credentials or other failure
 * \note This only exists separately because SSH needs to create the user before the node. Use bbs_authenticate if possible.
 *       If you use this function, you must use bbs_user_attach_node to attach the user to the node, once created.
 */
int bbs_user_authenticate(struct bbs_user *user, const char *username, const char *password);

/*!
 * \brief Authenticate a user using an RFC4616 SASL PLAIN response
 * \param node
 * \param s SASL PLAIN response from client
 * \retval 0 on success, -1 on failure
 */
int bbs_sasl_authenticate(struct bbs_node *node, const char *s);

/*!
 * \brief Attach a BBS user to a BBS node
 * \param node
 * \param user
 * \retval 0 on success, -1 on failure
 * \note This function should only be used when user authentication happens before a node is created (currently only in net_ssh). Use bbs_authenticate if possible.
 */
int bbs_node_attach_user(struct bbs_node *node, struct bbs_user *user);

/*!
 * \brief Attempt to authenticate a user and attach the user to a node
 * \param node
 * \param username User-attempted username. NULL for guest.
 * \param password User-attempted password. NULL for guest.
 * \retval 0 if user authenticated successfully, -1 if wrong credentials or other failure
 */
int bbs_authenticate(struct bbs_node *node, const char *username, const char *password);

/*!
 * \brief Register an auth provider that approves user logins
 * \param name Friendly name of auth provider
 * \param provider Callback function to execute that accepts node, username, and password,
 *        and returns 0 on success and -1 on failure.
 *        The provider must set node->user.priv to a positive value as part of approving the login.
 * \note At least one auth provider must be registered for user authentication to be possible
 */
#define bbs_register_auth_provider(name, provider) __bbs_register_auth_provider(name, provider, BBS_MODULE_SELF)

int __bbs_register_auth_provider(const char *name, int (*provider)(AUTH_PROVIDER_PARAMS), void *mod);

/*!
 * \brief Unregister an auth provider
 * \param provider Callback function to unregister
 */
int bbs_unregister_auth_provider(int (*provider)(AUTH_PROVIDER_PARAMS));

/*! \brief Get number of auth providers currently registered */
int bbs_num_auth_providers(void);

int bbs_init_auth(void);
