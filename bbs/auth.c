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

#include <openssl/sha.h>

#include "include/linkedlists.h"
#include "include/auth.h"
#include "include/node.h" /* use bbs_node_logged_in */
#include "include/user.h"
#include "include/module.h" /* use bbs_module_name */
#include "include/utils.h"
#include "include/tls.h" /* use hash_sha256 */
#include "include/event.h"
#include "include/crypt.h"

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
static void *registermod = NULL;

static int (*pwresethandler)(const char *username, const char *password) = NULL;
static void *pwresetmod = NULL;

static struct bbs_user* (*userinfohandler)(const char *username) = NULL;
static void *userinfomod = NULL;

static struct bbs_user** (*userlisthandler)(void) = NULL;
static void *userlistmod = NULL;

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

int __bbs_register_user_list_handler(struct bbs_user** (*handler)(void), void *mod)
{
	/* Only one user list handler */
	if (userlisthandler) {
		bbs_error("A user list handler is already registered.\n");
		return -1;
	}

	userlisthandler = handler;
	userlistmod = mod;
	return 0;
}

int bbs_unregister_user_list_handler(struct bbs_user** (*handler)(void))
{
	if (handler != userlisthandler) {
		bbs_error("User list handler %p does not match registered handler %p\n", handler, userlisthandler);
		return -1;
	}

	userlisthandler = NULL;
	userlistmod = NULL;
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

	p = RWLIST_WRLOCK_REMOVE_BY_FIELD(&providers, execute, provider, entry);
	if (!p) {
		bbs_error("Failed to unregister auth provider: not currently registered\n");
		return -1;
	} else {
		free(p);
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

#define MAX_CACHE_SIZE 10
#define MAX_CACHE_AGE 3600

struct cached_login {
	char *username;
	char *ip;
	int added;
	char hash[65];
	RWLIST_ENTRY(cached_login) entry;
};

static RWLIST_HEAD_STATIC(cached_logins, cached_login);

struct pw_auth_token {
	char *username;
	int added;
	char token[48];
	RWLIST_ENTRY(pw_auth_token) entry;
};

static RWLIST_HEAD_STATIC(auth_tokens, pw_auth_token);

static void cached_login_destroy(struct cached_login *l)
{
	free_if(l->username);
	free_if(l->ip);
	free(l);
}

static void auth_token_destory(struct pw_auth_token *t)
{
	free_if(t->username);
	free(t);
}

void login_cache_cleanup(void)
{
	RWLIST_WRLOCK_REMOVE_ALL(&cached_logins, entry, cached_login_destroy);
	RWLIST_WRLOCK_REMOVE_ALL(&auth_tokens, entry, auth_token_destory);
}

#define POSSIBLE_AUTH_TOKEN_CHAR '\\'
#define MAX_TOKEN_AGE 15

int bbs_user_temp_authorization_token(struct bbs_user *user, char *buf, size_t len)
{
	struct pw_auth_token *t;

	if (!bbs_user_is_registered(user)) {
		bbs_warning("Can't generate tokens for non-registered users\n");
		return -1;
	}

	/* Generate a "token" that can be used in lieu of a password
	 * for loopback authentication to the BBS.
	 *
	 * Currently, the only existing use case of this is when the door_irc IRC client
	 * wants to initiate a connection to the IRC server (net_irc).
	 * net_irc doesn't know that the connection is coming from the BBS, from
	 * a user that (maybe) is already logged in. The IP address will be 127.0.0.1,
	 * but that isn't really meaningful since localhost connections are not trusted specially.
	 *
	 * What we do here is generate a one-time token that can be used for the purposes
	 * of authentication. The authorizing module will call bbs_user_authenticate
	 * eventually, and in that code, if there is a token that exists for that user
	 * (and the login attempt is from 127.0.0.1, since that is required but not sufficient),
	 * then we can grant access simply by virtue of the token match.
	 *
	 * Using a random token is necessary because we don't have access to the user's password
	 * at any point besides login.
	 * Using a random token is desirable because if the sysop misconfigures door_irc.conf
	 * and accidentally makes connections elsewhere, the tokens that could leak out
	 * will be meaningless, since these tokens are only good for connections from localhost,
	 * and only for a short period of time (e.g. less than 15 seconds).
	 */

	/* Create a token and insert into the list so we can find it again. */
	RWLIST_WRLOCK(&auth_tokens);
	t = calloc(1, sizeof(*t));
	if (!t) {
		RWLIST_UNLOCK(&auth_tokens);
		return -1;
	}
	if (len < sizeof(t->token)) {
		RWLIST_UNLOCK(&auth_tokens);
		bbs_error("Truncation occured when storing temporary authorization token (need %lu bytes, only %lu available)\n", sizeof(t->token), len);
		free(t);
		return -1;
	}
	t->token[0] = POSSIBLE_AUTH_TOKEN_CHAR; /* Use an uncommon character to indicate possible token */
	if (bbs_rand_alnum(t->token + 1, sizeof(t->token) - 1)) {
		RWLIST_UNLOCK(&auth_tokens);
		free(t);
		return -1;
	}
	t->username = strdup(bbs_username(user));
	t->added = time(NULL);
	RWLIST_INSERT_TAIL(&auth_tokens, t, entry);
	RWLIST_UNLOCK(&auth_tokens);
	safe_strncpy(buf, t->token, len);
	return 0;
}

/*! \retval 1 if valid match, 0 if not */
static int valid_temp_token(const char *username, const char *password)
{
	struct pw_auth_token *t;
	int now, cutoff;
	int match = 0;

	now = time(NULL);
	cutoff = now - MAX_TOKEN_AGE;

	/* Purge any stale tokens. */
	RWLIST_WRLOCK(&auth_tokens);
	RWLIST_TRAVERSE_SAFE_BEGIN(&auth_tokens, t, entry) {
		if (t->added < cutoff) {
			RWLIST_REMOVE_CURRENT(entry);
			auth_token_destory(t);
		} else {
			if (!strcmp(username, t->username) && !strcmp(password, t->token)) {
				match = 1;
			}
			RWLIST_REMOVE_CURRENT(entry);
			auth_token_destory(t); /* What good is a one-time token if we reuse it? */
			/* Don't break, we still want to purge any tokens that may be stale. */
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&auth_tokens);
	return match;
}

/*! \retval 1 if successful, 0 if not found or unsuccessful */
static int login_is_cached(struct bbs_node *node, const char *username, const char *hash)
{
	struct cached_login *l;
	int now, cutoff;
	int remaining = 0;
	int i;

	now = time(NULL);
	cutoff = now - MAX_CACHE_AGE;

	/* Purge any stale cached logins. */
	RWLIST_WRLOCK(&cached_logins);
	RWLIST_TRAVERSE_SAFE_BEGIN(&cached_logins, l, entry) {
		if (l->added < cutoff) {
			RWLIST_REMOVE_CURRENT(entry);
			cached_login_destroy(l);
		} else {
			remaining++;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;

	/* If we still have more than MAX_CACHE_SIZE, purge the oldest ones. */
	if (remaining > MAX_CACHE_SIZE) {
		i = 0;
		RWLIST_TRAVERSE_SAFE_BEGIN(&cached_logins, l, entry) {
			if (i++ < MAX_CACHE_SIZE) { /* Oldest cached logins are all at the end of the list */
				continue;
			}
			RWLIST_REMOVE_CURRENT(entry);
			cached_login_destroy(l);
		}
		RWLIST_TRAVERSE_SAFE_END;
	}

	/* Now, check for a match. */
	RWLIST_TRAVERSE(&cached_logins, l, entry) {
		if (strlen_zero(l->username) || strlen_zero(l->ip)) {
			continue; /* Allocation failure when l was allocated */
		}
		if (strcasecmp(l->username, username)) { /* Usernames are not case sensitive */
			continue;
		}
		if (strcmp(l->ip, node->ip)) { /* Cached logins only good from same IP */
			bbs_debug(3, "Cached login denied (different IP address)\n");
			continue;
		}
		if (strcmp(l->hash, hash)) {
			bbs_debug(3, "Cached login denied (hash mismatch)\n");
			continue; /* Wrong password */
		}
		break;
	}
	RWLIST_UNLOCK(&cached_logins);
	return l ? 1 : 0;
}

static int login_cache(struct bbs_node *node, const char *username, const char *hash)
{
	struct cached_login *l;

	/*
	 * Recent logins are cached for performance reasons, since using bcrypt is expensive and slow.
	 * This is good for security against offline and brute force attacks, but because many
	 * BBS services (e.g. email, web) require frequent reauthentication over many
	 * sessions, this can slow down the user experience noticably for these services.
	 *
	 * This cached login mechanism comes with several security implications that are outlined here.
	 *
	 * Cached logins are stored using the SHA256 of the original password.
	 * The main reason for using SHA256 is to get an irreversible hash so the password
	 * cannot be recovered from memory.
	 * There are a number of problems with this scheme (SHA256 is still secure in some ways, not in others),
	 * but fundamentally you can't get good password security and performance at the same time.
	 *
	 * Therefore:
	 *
	 * Cached logins expire after an hour, regardless of if they are used.
	 * Thus, if a password is changed, any old password hash will expire after at most an hour.
	 * Note that if a password is changed through the BBS, the cached password will expire immediately
	 * as a security measure. However, if the password is changed directly (e.g. direct DB modification),
	 * then we won't know about that. Still, a cached password will persist for at most an hour in this case.
	 *
	 * To limit the scope of any attacks, cached logins may only be used from the same
	 * IP address as the initial login. Therefore, an attacker would need to be at the same
	 * IP address and guess the right password (or generate a collision) within an hour
	 * of a normal, uncached login. This is an unlikely scenario for the typical BBS.
	 *
	 * These offer a reasonable tradeoff between security and performance.
	 */

	if (!strcmp(node->ip, "127.0.0.1")) {
		return -1; /* Don't allow cached logins from localhost, this combines attack surfaces */
	}

	l = calloc(1, sizeof(*l));
	if (!l) {
		return -1;
	}
	l->added = time(NULL);
	l->username = strdup(username);
	safe_strncpy(l->hash, hash, sizeof(l->hash)); /* Could just use strcpy too, if we trust the hash is legitimate. */
	l->ip = strdup(node->ip);
	RWLIST_WRLOCK(&cached_logins);
	RWLIST_INSERT_HEAD(&cached_logins, l, entry);
	RWLIST_UNLOCK(&cached_logins);
	return 0;
}

static int bbs_node_authenticate(struct bbs_node *node, const char *username, const char *password)
{
	int res;
	char sha256_hash[65];

	hash_sha256(password, sha256_hash);

	/* Fast authentication for previously and recently successful logins */
	if (login_is_cached(node, username, sha256_hash)) {
		node->user = bbs_user_info_by_username(username); /* Get the actual user from the DB */
		if (!node->user) {
			bbs_warning("Login cached for nonexistent user %s?\n", username);
		} else {
			bbs_auth("User %s successfully authenticated (cached)\n", bbs_username(node->user));
			return 0;
		}
	}

	if (*password == POSSIBLE_AUTH_TOKEN_CHAR && !strcmp(node->ip, "127.0.0.1") && valid_temp_token(username, password)) { /* Check for possible temp auth token first */
		node->user = bbs_user_info_by_username(username); /* Get the actual user from the DB */
		if (!node->user) {
			bbs_warning("Login cached for nonexistent user %s?\n", username);
		} else {
			bbs_auth("User %s successfully authenticated (temp auth token)\n", bbs_username(node->user));
			return 0;
		}
	}

	/* Normal (full) authentication */
	/* Prevent the node from disappearing while authentication is ongoing (especially since it can take awhile)
	 * Without locking, there is a small chance that the node is destroyed while authentication is in process,
	 * and as part of that the user is destroyed. As a result, the auth provider may attempt to access freed memory.
	 * The locking will prevent a node (and its user) from being destroyed while authentication is running.
	 * The same problem does not exist for bbs_user_authenticate standalone when not called from bbs_node_authenticate,
	 * because users are not globally stored in any container. A user not attached to a node would only be freed
	 * by the thread that called bbs_user_authenticate in the first place.
	 */
	bbs_node_lock(node);
	res = bbs_user_authenticate(node->user, username, password);
	bbs_node_unlock(node);
	if (!res) {
		login_cache(node, username, sha256_hash);
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
	if (bbs_node_authenticate(node, username, password)) {
		bbs_event_dispatch(node, EVENT_NODE_LOGIN_FAILED);
		return -1;
	}

	if (!bbs_user_is_registered(node->user)) {
		bbs_error("Authentication returned success, but no user?\n");
		return -1;
	}

	if (strchr(username, ' ')) {
		/* mod_auth_mysql doesn't allow registration of usernames with spaces,
		 * but that doesn't guarantee there aren't already usernames with spaces, etc. */
		bbs_warning("Username '%s' contains space (may not be compatible with all services)\n", username); /* e.g. IRC */
	}

	/* Do not run any callbacks for user login here, since this function isn't always
	 * called on authentication (SSH for example could call bbs_user_authenticate
	 * and then bbs_node_attach_user).
	 * Any such stuff should be done in node.c after user login */

	bbs_auth("Node %d now logged in as %s\n", node->id, bbs_username(node->user));
	bbs_event_dispatch(node, EVENT_USER_LOGIN); /* XXX If bbs_user_authenticate is called directly, this event isn't emitted */
	return 0;
}

int bbs_sasl_authenticate(struct bbs_node *node, const char *s)
{
	int res;
	unsigned char *decoded;
	char *authorization_id, *authentication_id, *password;

	decoded = bbs_sasl_decode(s, &authorization_id, &authentication_id, &password);
	if (!decoded) {
		return -1;
	}

	res = bbs_authenticate(node, authentication_id, password);
	bbs_memzero(password, strlen(password)); /* Destroy the password from memory before we free it */
	free(decoded);
	return res;
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

	if (bbs_user_is_registered(node->user)) { /* we might have returned -1 after registration succeeded on timeout */
		if (!bbs_node_logged_in(node)) {
			bbs_error("User registration callback returned 0, but node %d is not logged in\n", node->id);
			return -1; /* Abort */
		}
		/* If we got here, then the user was able to self-register (or the sysop-enabled registration process completed before the reg provider returned) */
		bbs_auth("New user registration successful for %s\n", bbs_username(node->user));
		bbs_event_dispatch(node, EVENT_USER_REGISTRATION);
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
		struct bbs_event event;
		login_cache_cleanup(); /* Purge any cached passwords. Here we purge all of them, but could probably just do the relevant user only... */
		bbs_auth("Password changed for user '%s'\n", username);
		memset(&event, 0, sizeof(event));
		event.type = EVENT_USER_PASSWORD_CHANGE;
		safe_strncpy(event.username, username, sizeof(event.username));
		bbs_event_broadcast(&event);
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

struct bbs_user **bbs_user_list(void)
{
	struct bbs_user **userlist = NULL;

	if (!userlisthandler) {
		bbs_error("No user list handler is currently registered\n");
		return NULL;
	}

	bbs_assert_exists(userlistmod);
	bbs_module_ref(userlistmod);
	userlist = userlisthandler();
	bbs_module_unref(userlistmod);

	return userlist;
}
