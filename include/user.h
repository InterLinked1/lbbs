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
 * \brief BBS user
 *
 */

struct bbs_user {
	unsigned int id;			/*!< User ID */
	char *username;				/*!< Username */
	int priv;					/*!< User privilege. -1 if no user, 0 = guest, > 0 = logged in as a registered user. */
	char *email;				/*!< Email Address */
	/* Guest users only */
	char *guestname;			/*!< Guest's real name/alias */
	char *guestemail;			/*!< Guest's email address */
	char *guestlocation;		/*!< Guest's location */
};

/*! \brief Whether a user is logged into a node, either as a registered user or as a guest */
#define bbs_node_logged_in(node) (node->user && node->user->priv >= 0)

/*! \brief Whether a user is logged into a node as a guest */
#define bbs_user_is_guest(user) (user && user->priv == 0)

/*! \brief Whether a user is logged into a node as a registered user */
#define bbs_user_is_registered(user) (user && user->priv > 0)

/*!
 * \brief Get username/alias of a BBS user.
 * \note Unlike bbs_username, this will return user-provided name for guests, rather than just "Guest"
 */
#define bbs_user_alias(user) (bbs_user_is_guest(user) ? user->guestname : user->username)

/*! \brief Email address of registered or guest user */
#define bbs_user_email(user) (bbs_user_is_guest(user) ? user->guestemail : user->email)

/*!
 * \brief Get username of a BBS user.
 * \param user. It is okay if user is NULL, so it is always safe to pass node->user, for example.
 * \note For guests, this will always return Guest, not the guest-provided alias. Use bbs_user_alias for that.
 * \retval Friendly representation of logged in user. Never NULL.
 */
const char *bbs_username(struct bbs_user *user);

/*!
 * \brief Create user struct
 * \retval user on success, NULL on failure
 */
struct bbs_user *bbs_user_request(void);

/*!
 * \brief Set guest user details
 * \param user
 * \param guestname Guest's name or alias
 * \param guestemail Guest's email address
 * \param guestlocation Guest's location
 * \retval 0 on success, -1 on failure
 */
int bbs_user_guest_info_set(struct bbs_user *user, const char *guestname, const char *guestemail, const char *guestlocation);

/*! \brief Free a user */
void bbs_user_destroy(struct bbs_user *user);
