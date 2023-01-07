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
#define bbs_register_user_registration_provider(name) __bbs_register_user_registration_provider(name, BBS_MODULE_SELF)

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
 * \brief Attempt to authenticate a user
 * \param node
 * \param username User-attempted username. NULL for guest.
 * \param password User-attempted password. NULL for guest.
 * \retval 0 if user authenticated successfully, -1 if wrong credentials or other failure
 * \note This only exists separately because SSH needs to create the user before the node. Use bbs_authenticate if possible.
 *       If you use this function, you must use bbs_user_attach_node to attach the user to the node, once created.
 */
int bbs_user_authenticate(struct bbs_user *user, const char *username, const char *password);

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
 * \provider Callback function to unregister
 */
int bbs_unregister_auth_provider(int (*provider)(AUTH_PROVIDER_PARAMS));

/*! \brief List registered auth providers */
int bbs_list_auth_providers(int fd);

/*! \brief Get number of auth providers currently registered */
int bbs_num_auth_providers(void);
