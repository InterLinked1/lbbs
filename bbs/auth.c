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
 * \brief Authentication
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/linkedlists.h"
#include "include/auth.h"
#include "include/node.h" /* use bbs_node_logged_in */
#include "include/user.h"
#include "include/notify.h"
#include "include/module.h" /* use bbs_module_name */

/*! \note Even though multiple auth providers are technically allowed, in general only 1 should be registered.
 * The original thinking behind allowing multiple is to allow alternates for authentication
 * in case there are multiple authentication sources or the main was down, but this doesn't really play nicely
 * with the rest of the architecture since it wouldn't be synchronized necessarily.
 */
struct auth_provider {
	/*! Door function */
	int (*execute)(AUTH_PROVIDER_PARAMS);
	/*! Module registering the door */
	struct bbs_module *module;
	/* Next entry */
	RWLIST_ENTRY(auth_provider) entry;
	/* Friendly name, not used internally, since we use the callback function as the unique "key", not the name. Only used in bbs_list_providers */
	char name[0];
};

static RWLIST_HEAD_STATIC(providers, auth_provider);

static int (*registerprovider)(struct bbs_node *node) = NULL;
void *registermod = NULL;

static int (*pwresethandler)(const char *username, const char *password) = NULL;
void *pwresetmod = NULL;

static struct bbs_user* (*userinfohandler)(const char *username) = NULL;
void *userinfomod = NULL;

int __bbs_register_user_registration_provider(int (*regprovider)(struct bbs_node *node), void *mod)
{
	/* Unlike auth providers, there is only 1 user registration handler */
	if (registerprovider) {
		bbs_error("A user registration provider is already registered.\n");
		return -1;
	}

	registerprovider = regprovider;
	registermod = mod;
	return 0;
}

int bbs_unregister_user_registration_provider(int (*regprovider)(struct bbs_node *node))
{
	if (regprovider != registerprovider) {
		bbs_error("User registration provider %p does not match registered provider %p\n", regprovider, registerprovider);
		return -1;
	}

	registerprovider = NULL;
	registermod = NULL;
	return 0;
}

int __bbs_register_password_reset_handler(int (*handler)(const char *username, const char *password), void *mod)
{
	/* Only one password reset handler */
	if (pwresethandler) {
		bbs_error("A password reset handler is already registered.\n");
		return -1;
	}

	pwresethandler = handler;
	pwresetmod = mod;
	return 0;
}

int bbs_unregister_password_reset_handler(int (*handler)(const char *username, const char *password))
{
	if (handler != pwresethandler) {
		bbs_error("Password reset handler %p does not match registered handler %p\n", handler, pwresethandler);
		return -1;
	}

	pwresethandler = NULL;
	pwresetmod = NULL;
	return 0;
}

int __bbs_register_user_info_handler(struct bbs_user* (*handler)(const char *username), void *mod)
{
	/* Only one user info handler */
	if (userinfohandler) {
		bbs_error("A user info handler is already registered.\n");
		return -1;
	}

	userinfohandler = handler;
	userinfomod = mod;
	return 0;
}

int bbs_unregister_user_info_handler(struct bbs_user* (*handler)(const char *username))
{
	if (handler != userinfohandler) {
		bbs_error("User info handler %p does not match registered handler %p\n", handler, userinfohandler);
		return -1;
	}

	userinfohandler = NULL;
	userinfomod = NULL;
	return 0;
}

int __bbs_register_auth_provider(const char *name, int (*provider)(AUTH_PROVIDER_PARAMS), void *mod)
{
	struct auth_provider *p;

	RWLIST_WRLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		if (p->execute == provider) {
			break;
		}
	}
	if (p) {
		bbs_error("Provider is already registered\n");
		RWLIST_UNLOCK(&providers);
		return -1;
	}
	p = calloc(1, sizeof(*p) + strlen(name) + 1);
	if (!p) {
		bbs_error("Failed to calloc auth provider\n");
		RWLIST_UNLOCK(&providers);
		return -1;
	}
	p->execute = provider;
	p->module = mod;
	strcpy(p->name, name); /* Safe */
	RWLIST_INSERT_TAIL(&providers, p, entry);
	RWLIST_UNLOCK(&providers);
	return 0;
}

int bbs_unregister_auth_provider(int (*provider)(AUTH_PROVIDER_PARAMS))
{
	struct auth_provider *p;

	RWLIST_WRLOCK(&providers);
	RWLIST_TRAVERSE_SAFE_BEGIN(&providers, p, entry) {
		if (p->execute == provider) {
			RWLIST_REMOVE_CURRENT(entry);
			free(p);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&providers);
	if (!p) {
		bbs_error("Failed to unregister auth provider: not currently registered\n");
		return -1;
	}
	return 0;
}

int bbs_list_auth_providers(int fd)
{
	int c = 0;
	struct auth_provider *p;

	RWLIST_RDLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		/* Printing out numbers isn't just nice,
		 * since providers are called in this order, it's super important
		 * to make that clear. */
		c++;
		/* A module won't be able to unregister without first unregistering
		 * the provider, which it can't do right now since the list is locked,
		 * so accessing the module is safe. */
		bbs_dprintf(fd, " %d => %-30s (%s)\n", c, p->name, bbs_module_name(p->module));
	}
	RWLIST_UNLOCK(&providers);
	bbs_dprintf(fd, "%d registered auth provider%s\n", c, ESS(c));
	return 0;
}

int bbs_num_auth_providers(void)
{
	int c = 0;
	struct auth_provider *p;

	RWLIST_RDLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		c++;
	}
	RWLIST_UNLOCK(&providers);

	if (!registerprovider) {
		/* This is kind of kludgy way to check this to warn,
		 * but that way we don't need to expose this separately to bbs.c,
		 * since it calls this function to ensure we have auth providers already.
		 */
		bbs_warning("No user registration provider is currently registered.\n");
	}

	return c;
}

static int do_authenticate(struct bbs_user *user, const char *username, const char *password)
{
	int c = 0, res = -1;
	struct auth_provider *p;

	bbs_debug(6, "Attempting password authentication for user '%s'\n", username);

	/* Note that this traversal will proceed in the order that providers were registered,
	 * since we always do a tail-insert.
	 * So the auth providers that should have first dibs need to be registered first.
	 */
	RWLIST_RDLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		bbs_module_ref(p->module);
		res = p->execute(user, username, password);
		bbs_module_unref(p->module);
		c++;
		if (!res) {
			break; /* Somebody granted the login. Stop. */
		}
	}
	RWLIST_UNLOCK(&providers);

	/* If there weren't any providers, well, we have a problem. */
	if (c == 0) {
		bbs_warning("No auth providers are currently registered! Login rejected\n");
		return -1;
	} else if (res) {
		bbs_debug(6, "Login rejected by all (%d) auth provider%s\n", c, ESS(c));
	}
	return res;
}

int bbs_user_authenticate(struct bbs_user *user, const char *username, const char *password)
{
	bbs_assert(user != NULL);

	if (do_authenticate(user, username, password)) {
		/* We don't know the IP address here so we can't log that, but it will be in the logs */
		bbs_auth("Login attempt rejected for user %s (wrong password)\n", username);
		return -1; /* All auth providers rejected the login. */
	}

	/* Successful registered user login */

	/* Some sanity checks on the authentication. */
	if (!user->id) {
		/* This is fatal, we need the user ID and can't make one up */
		bbs_error("Auth provider did not set the user ID\n");
		return -1;
	}
	if (!user->username) {
		bbs_warning("Auth provider did not set the username explicitly\n");
		/* Fall back to duping the user-provided username.
		 * However, since usernames are probably not case-sensitive,
		 * this is not ideal as we might use an "unofficial" casing of the username.
		 * This is why the auth provider should explicitly set the username
		 * with the official casing, so we can be consistent no matter
		 * what casing the user provides at login. */
		user->username = strdup(username);
	}
	if (user->priv < 1) {
		/* The auth provider is supposed to set user->priv with the user's privilege level.
		 * The BBS core doesn't really care what this value is, as long as it's positive.*/
		bbs_warning("Auth provider granted login for '%s', but privilege is %d? Defaulting to 1\n", username, user->priv);
		/* 1 is the lowest possible privilege, so fall back to granting the least permissive access if the module didn't specify.
		 * However, emit a warning above because providers should really set this explicitly. */
		user->priv = 1;
	}
	bbs_auth("User %s successfully authenticated\n", bbs_username(user));
	return 0;
}

int bbs_node_attach_user(struct bbs_node *node, struct bbs_user *user)
{
	bbs_assert_exists(node);
	if (!user) {
		return -1;
	}
	if (bbs_node_logged_in(node)) {
		/* Already logged in ??? */
		bbs_error("Node %d is already logged in as %s\n", node->id, S_IF(node->user->username));
		return -1;
	}
	node->user = user;
	bbs_auth("Node %d now logged in as %s (via %s)\n", node->id, bbs_username(user), node->protname);
	return 0;
}

int bbs_authenticate(struct bbs_node *node, const char *username, const char *password)
{
	/* I thought about making password non-const and zeroing out
	 * its memory here, but some modules receive the password
	 * as const, so we may as well preserve it here
	 * and do that elsewhere if possible.
	 */
	if (bbs_node_logged_in(node)) {
		/* Already logged in ??? */
		bbs_error("Node %d is already logged in as %s\n", node->id, S_IF(node->user->username));
		return -1;
	}

	if (!node->user) {
		/* First time? Allocate. */
		node->user = bbs_user_request();
		if (!node->user) {
			return -1;
		}
	}

	if (!username && !password) {
		/* Guest login */
		if (!bbs_guest_login_allowed()) {
			/* Reject guest login, since not permitted */
			bbs_auth("Guest login rejected for node %d (disabled)\n", node->id);
			return -1;
		}
		bbs_auth("Node %d logged in as Guest\n", node->id);
		node->user->priv = 0; /* Guest */
		return 0;
	}

	/* Not a guest, somebody needs to actual verify the username and password. */
	if (bbs_user_authenticate(node->user, username, password)) {
		return -1;
	}

	/* Do not run any callbacks for user login here, since this function isn't always
	 * called on authentication (SSH for example could call bbs_user_authenticate
	 * and then bbs_node_attach_user).
	 * Any such stuff should be done in node.c after user login */

	bbs_auth("Node %d now logged in as %s\n", node->id, bbs_username(node->user));
	return 0;
}

int bbs_user_register(struct bbs_node *node)
{
	int res;

	if (!registerprovider) {
		bbs_error("No user registration provider is currently registered, registration rejected\n");
		return -1;
	}

	bbs_debug(3, "Handing new user registration off to %p\n", registerprovider);

	node->menu = "Register";
	bbs_assert_exists(registermod);
	bbs_module_ref(registermod);
	res = registerprovider(node);
	bbs_module_unref(registermod);
	node->menu = NULL;

	if (!res) {
		if (!bbs_node_logged_in(node)) {
			bbs_error("User registration callback returned 0, but node %d is not logged in\n", node->id);
			return -1; /* Abort */
		}
		/* If we got here, then the user was able to self-register (or the sysop-enabled registration process completed before the reg provider returned) */
		bbs_auth("New user registration successful for %s\n", bbs_username(node->user));
		/* Relatively speaking, it's a pretty big deal whenever a new user registers.
		 * Notify the sysop. */
		bbs_sysop_email(NULL, "New User Registration", "Greetings, sysop,\r\n\tA new user, %s (#%d), just registered on your BBS from IP %s.",
			bbs_username(node->user), node->user->id, node->ip);
	}
	return res;
}

int bbs_user_reset_password(const char *username, const char *password)
{
	int res;

	if (!pwresethandler) {
		bbs_error("No password reset handler is currently registered\n");
		return -1;
	}

	bbs_assert_exists(pwresetmod);
	bbs_module_ref(pwresetmod);
	res = pwresethandler(username, password);
	bbs_module_unref(pwresetmod);

	if (!res) {
		bbs_auth("Password changed for user '%s'\n", username);
	}

	return res;
}

struct bbs_user *bbs_user_info_by_username(const char *username)
{
	struct bbs_user *user = NULL;

	if (!userinfohandler) {
		bbs_error("No user info handler is currently registered\n");
		return NULL;
	}

	bbs_assert_exists(userinfomod);
	bbs_module_ref(userinfomod);
	user = userinfohandler(username);
	bbs_module_unref(userinfomod);

	return user;
}
