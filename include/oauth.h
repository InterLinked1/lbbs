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
 * \brief OAuth2 token interface
 *
 */

/* Forward declaration */
struct bbs_user;

#define OAUTH_PROVIDER_PARAMS struct bbs_user *user, const char *name, char *buf, size_t len

/*!
 * \brief Register an OAuth token provider that obtains an OAuth2 token
 * \param provider Callback function to execute that will provide the OAuth2 access token
 *        for a given profile name, restricted to the current user as appropriate.
 * \note At least one OAuth token provider must be registered for user authentication to be possible
 */
#define bbs_register_oauth_provider(provider) __bbs_register_oauth_provider(provider, BBS_MODULE_SELF)

int __bbs_register_oauth_provider(int (*provider)(OAUTH_PROVIDER_PARAMS), void *mod);

/*!
 * \brief Unregister an OAuth token provider
 * \provider Callback function to unregister
 */
int bbs_unregister_oauth_provider(int (*provider)(OAUTH_PROVIDER_PARAMS));

/*!
 * \brief Get the current OAuth token for a given user and profile
 * \param user
 * \param name Profile name
 * \param[out] buf
 * \param len Size of buf. Should be at least 300 (these tokens can be quite long!)
 * \retval 0 on success, -1 if not found or on error
 */
int bbs_get_oauth_token(struct bbs_user *user, const char *name, char *buf, size_t len);
