/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Static config user authentication
 *
 * \note This module is NOT intended for production usage.
 *       Its primary purpose is to mock an authentication provider for ease of automated black box testing.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/config.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/crypt.h" /* use bbs_password_verify_bcrypt */
#include "include/mail.h"

struct static_user {
	char *username;
	char *password;
	int priv;
	unsigned int id;
	RWLIST_ENTRY(static_user) entry;
};

static RWLIST_HEAD_STATIC(users, static_user);

static void free_user(struct static_user *u)
{
	free_if(u->username);
	free_if(u->password);
	free(u);
}

static struct bbs_user *convert_user(struct static_user *u)
{
	struct bbs_user *user = bbs_user_request();
	if (!user) {
		return NULL;
	}
	user->username = strdup(u->username);
	user->id = u->id;
	user->priv = u->priv;
	return user;
}

static int provider(AUTH_PROVIDER_PARAMS)
{
	struct static_user *u;
	int res = -1;

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, u, entry) {
		if (!strcasecmp(username, u->username)) {
			if (!bbs_password_verify_bcrypt(password, u->password)) {
				user->username = strdup(u->username);
				user->id = u->id;
				user->priv = u->priv;
				res = 0;
			}
			break;
		}
	}
	RWLIST_UNLOCK(&users);
	if (!u) {
		/* If we didn't find a user, do a dummy call to bbs_password_verify_bcrypt
		 * to prevent timing attacks (user exists or doesn't exist) */
#define DUMMY_PASSWORD "P@ssw0rd123"
#define DUMMY_PASSWORD_HASH "$2y$10$0uZL6ZrlTFw1Z.pyKPOLXub2cQdrRAPMAuHz0gWsmzwy4W/6oOLt2"
		bbs_password_verify_bcrypt(DUMMY_PASSWORD, DUMMY_PASSWORD_HASH);
#undef DUMMY_PASSWORD
#undef DUMMY_PASSWORD_HASH
	}
	return res;
}

static struct bbs_user *get_user_info(const char *username)
{
	struct static_user *u;
	struct bbs_user *user = NULL;

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, u, entry) {
		if (!strcasecmp(username, u->username)) {
			user = convert_user(u);
			break;
		}
	}
	RWLIST_UNLOCK(&users);
	return user;
}

static struct bbs_user **get_users(void)
{
	struct static_user *u;
	struct bbs_user *user;
	struct bbs_user **userlist;
	int index = 0;

	RWLIST_RDLOCK(&users);
	userlist = malloc((RWLIST_SIZE(&users, u, entry) + 1) * sizeof(*user)); /* The list will be NULL terminated, so add 1 */
	/* Keep list locked here so count can't change on us */
	RWLIST_TRAVERSE(&users, u, entry) {
		user = convert_user(u);
		if (user) {
			userlist[index++] = user;
		}
	}
	RWLIST_UNLOCK(&users);
	userlist[index] = NULL; /* Safe */

	return userlist;
}

static int load_config(void)
{
	int userid = 0;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_auth_static.conf", 0);

	if (!cfg) {
		return -1;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcasecmp(bbs_config_section_name(section), "users")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				struct static_user *u = calloc(1, sizeof(*u));
				if (!u) {
					bbs_error("Failed to allocate user\n");
				}
				u->id = ++userid;
				u->username = strdup(bbs_keyval_key(keyval));
				u->password = strdup(bbs_keyval_val(keyval));
				u->priv = 1;
				RWLIST_INSERT_TAIL(&users, u, entry);
			}
		} else {
			bbs_error("Unknown config section: %s\n", bbs_config_section_name(section));
		}
	}

	bbs_config_free(cfg); /* Destroy the config now, rather than waiting until shutdown, since it will NEVER be used again for anything. */
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	bbs_register_user_info_handler(get_user_info);
	bbs_register_user_list_handler(get_users);
	return bbs_register_auth_provider("Static", provider);
}

static int unload_module(void)
{
	int res = bbs_unregister_auth_provider(provider);
	bbs_unregister_user_info_handler(get_user_info);
	bbs_unregister_user_list_handler(get_users);

	RWLIST_REMOVE_ALL(&users, entry, free_user);

	return res;
}

BBS_MODULE_INFO_STANDARD("Static Config User Authentication");
