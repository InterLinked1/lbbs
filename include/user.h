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

/* Forward declarations */
struct tm;

struct bbs_user {
	unsigned int id;			/*!< User ID */
	char *username;				/*!< Username */
	int priv;					/*!< User privilege. -1 if no user, 0 = guest, > 0 = logged in as a registered user. */
	char *email;				/*!< Email Address */
	/* Additional info fields */
	char *fullname;
	char *phone;
	char *address;
	char *city;
	char *state;
	char *zip;
	char gender;
	/* Dates */
	/* These are declared as pointers so we can just forward declare struct tm, rather than having
	 * everything that includes user.h be aware of its type. */
	struct tm *dob;
	struct tm *registered;
	struct tm *lastlogin;
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

/*! \brief Privilege level of user */
#define bbs_user_priv(user) (user ? user->priv : 0)

/*!
 * \brief Get username of a BBS user.
 * \param user It is okay if user is NULL, so it is always safe to pass node->user, for example.
 * \note For guests, this will always return Guest, not the guest-provided alias. Use bbs_user_alias for that.
 * \returns Friendly representation of logged in user. Never NULL.
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

/*!
 * \brief Print out information about a user
 * \param fd File descriptor to which to print output
 * \param username Username of user
 * \param verbose Verbosity level of information to dump. 10 for everything (sysops only)
 * \retval 0 on success, -1 on failure (no such user)
 */
int bbs_user_dump(int fd, const char *username, int verbose);

/*!
 * \brief Print out information about all users
 * \param fd File descriptor to which to print output
 * \param verbose Verbosity level of information to dump. 10 for everything (sysops only)
 * \retval 0 on success, -1 on failure (no such user)
*/
int bbs_users_dump(int fd, int verbose);

/*!
 * \brief Whether a user exists or not
 * \param username
 * \retval 1 if exists, 0 if doesn't exist
 */
int bbs_user_exists(const char *username);

/*!
 * \brief Get a user ID from a username
 * \param username Username to query
 * \retval 0 if user does not exist, positive user ID if user exists
 */
unsigned int bbs_userid_from_username(const char *username);

/*!
 * \brief Get a username from a user ID
 * \param userid User ID to query
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on match, -1 if no such user
 */
int bbs_username_from_userid(unsigned int userid, char *buf, size_t len);

/*! \brief Same as bbs_username_from_userid, but username returned is all lowercase */
int bbs_lowercase_username_from_userid(unsigned int userid, char *buf, size_t len);

/*!
 * \brief Get a user's privilege level by username
 * \param userid User ID
 * \retval -1 if user does not exist, user privilege level if user exists
 */
int bbs_user_priv_from_userid(unsigned int userid);

/*!
 * \brief Get a user by user ID
 * \param userid User ID
 * \returns NULL if user does not exist, user otherwise, which must be freed using bbs_user_destroy (or attached to a node)
 */
struct bbs_user *bbs_user_from_userid(unsigned int userid);

/*!
 * \brief Get a user by username
 * \param username
 * \returns NULL if user does not exist, user otherwise, which must be freed using bbs_user_destroy (or attached to a node)
 */
struct bbs_user *bbs_user_from_username(const char *username);

/*! \brief Free a list of BBS users, including all the users in the list */
void bbs_user_list_destroy(struct bbs_user **userlist);

/*! \brief Free a user */
void bbs_user_destroy(struct bbs_user *user);

/*! \brief Invalidate the user ID/username translation cache */
void username_cache_flush(void);
