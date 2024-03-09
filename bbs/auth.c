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
#include "include/stringlist.h"
#include "include/auth.h"
#include "include/node.h" /* use bbs_node_logged_in */
#include "include/user.h"
#include "include/module.h" /* use bbs_module_name */
#include "include/utils.h"
#include "include/hash.h" /* use hash_sha256 */
#include "include/event.h"
#include "include/crypt.h"
#include "include/startup.h"
#include "include/config.h"
#include "include/cli.h"
#include "include/callback.h"
#include "include/reload.h"

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
	char name[];
};

static RWLIST_HEAD_STATIC(providers, auth_provider);

/* Unlike auth providers, there is only 1 user registration handler */
BBS_SINGULAR_CALLBACK_DECLARE(registerprovider, int, struct bbs_node *node);

/* Only one password reset handler */
BBS_SINGULAR_CALLBACK_DECLARE(pwresethandler, int, const char *username, const char *password);

/* Only one user info handler */
BBS_SINGULAR_CALLBACK_DECLARE(userinfohandler, struct bbs_user *, const char *username);

/* Only one user list handler */
BBS_SINGULAR_CALLBACK_DECLARE(userlisthandler, struct bbs_user**, void);

static struct stringlist reserved_usernames;

struct reserved_username_searcher {
	int (*exists)(const char *username);
	void *mod;
	RWLIST_ENTRY(reserved_username_searcher) entry;
};

static RWLIST_HEAD_STATIC(reserved_username_callbacks, reserved_username_searcher);

int __bbs_username_reserved_callback_register(int (*exists)(const char *username), void *mod)
{
	struct reserved_username_searcher *r;

	RWLIST_WRLOCK(&reserved_username_callbacks);
	r = calloc(1, sizeof(*r));
	if (ALLOC_FAILURE(r)) {
		RWLIST_UNLOCK(&reserved_username_callbacks);
		return -1;
	}
	r->exists = exists;
	r->mod = mod;
	RWLIST_INSERT_HEAD(&reserved_username_callbacks, r, entry);
	RWLIST_UNLOCK(&reserved_username_callbacks);

	return 0;
}

int bbs_username_reserved_callback_unregister(int (*exists)(const char *username))
{
	struct reserved_username_searcher *r = RWLIST_WRLOCK_REMOVE_BY_FIELD(&reserved_username_callbacks, exists, exists, entry);
	if (!r) {
		return -1;
	}
	free(r);
	return 0;
}

int bbs_username_reserved(const char *username)
{
	struct reserved_username_searcher *r;
	int exists = 0;

	if (stringlist_case_contains(&reserved_usernames, username)) {
		/* Explicitly reserved */
		return 1;
	}

	RWLIST_WRLOCK(&reserved_username_callbacks);
	RWLIST_TRAVERSE(&reserved_username_callbacks, r, entry) {
		bbs_module_ref(r->mod, 2);
		exists |= r->exists(username);
		bbs_module_unref(r->mod, 2);
		if (exists) {
			/* Some module has reserved it */
			break;
		}
	}
	RWLIST_UNLOCK(&reserved_username_callbacks);

	return exists;
}

int __bbs_register_user_registration_provider(int (*regprovider)(struct bbs_node *node), void *mod)
{
	return bbs_singular_callback_register(&registerprovider, regprovider, mod);
}

int bbs_unregister_user_registration_provider(int (*regprovider)(struct bbs_node *node))
{
	return bbs_singular_callback_unregister(&registerprovider, regprovider);
}

int __bbs_register_password_reset_handler(int (*handler)(const char *username, const char *password), void *mod)
{
	return bbs_singular_callback_register(&pwresethandler, handler, mod);
}

int bbs_unregister_password_reset_handler(int (*handler)(const char *username, const char *password))
{
	return bbs_singular_callback_unregister(&pwresethandler, handler);
}

int __bbs_register_user_info_handler(struct bbs_user* (*handler)(const char *username), void *mod)
{
	return bbs_singular_callback_register(&userinfohandler, handler, mod);
}

int bbs_unregister_user_info_handler(struct bbs_user* (*handler)(const char *username))
{
	return bbs_singular_callback_unregister(&userinfohandler, handler);
}

int __bbs_register_user_list_handler(struct bbs_user** (*handler)(void), void *mod)
{
	return bbs_singular_callback_register(&userlisthandler, handler, mod);
}

int bbs_unregister_user_list_handler(struct bbs_user** (*handler)(void))
{
	return bbs_singular_callback_unregister(&userlisthandler, handler);
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
	if (ALLOC_FAILURE(p)) {
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

int bbs_num_auth_providers(void)
{
	int c = 0;
	struct auth_provider *p;

	RWLIST_RDLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		c++;
	}
	RWLIST_UNLOCK(&providers);

	if (!bbs_singular_callback_registered(&registerprovider)) {
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

	if (!bbs_str_isprint(username)) {
		return -1;
	}

	bbs_debug(6, "Attempting password authentication for user '%s'\n", username);

	/* Note that this traversal will proceed in the order that providers were registered,
	 * since we always do a tail-insert.
	 * So the auth providers that should have first dibs need to be registered first.
	 */
	RWLIST_RDLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		bbs_module_ref(p->module, 1);
		res = p->execute(user, username, password);
		bbs_module_unref(p->module, 1);
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
	time_t added;
	char hash[65];
	RWLIST_ENTRY(cached_login) entry;
};

static RWLIST_HEAD_STATIC(cached_logins, cached_login);

struct pw_auth_token {
	char *username;
	time_t added;
	time_t expires;
	char token[TEMP_PASSWORD_TOKEN_BUFLEN];
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
	bbs_debug(3, "Purging temporary login token for %s\n", t->username);
	bbs_memzero(t->token, sizeof(t->token)); /* This token isn't really sensitive, since it's no longer valid, but scrub it anyways */
	free(t->username);
	free(t);
}

void login_cache_cleanup(void)
{
	RWLIST_WRLOCK_REMOVE_ALL(&cached_logins, entry, cached_login_destroy);
	RWLIST_WRLOCK_REMOVE_ALL(&auth_tokens, entry, auth_token_destory);
}

/* Changed from \\, since libetpan will double the leading \,
 * butchering the password, making such tokens impossible
 * to use with applications using that library. */
#define POSSIBLE_AUTH_TOKEN_CHAR '}'
#define DEFAULT_MAX_TOKEN_AGE 15

static int create_temp_authorization_token(struct bbs_user *user, char *buf, size_t len, time_t expires)
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
	if (ALLOC_FAILURE(t)) {
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
	if (bbs_rand_alnum(t->token + 1, sizeof(t->token) - 2)) {
		RWLIST_UNLOCK(&auth_tokens);
		free(t);
		return -1;
	}
	t->token[TEMP_PASSWORD_TOKEN_BUFLEN - 1] = '\0';
	t->username = strdup(bbs_username(user));
	if (ALLOC_FAILURE(t->username)) {
		RWLIST_UNLOCK(&auth_tokens);
		free(t);
		return -1;
	}
	t->added = time(NULL);
	t->expires = expires;
	RWLIST_INSERT_TAIL(&auth_tokens, t, entry);
	RWLIST_UNLOCK(&auth_tokens);
	safe_strncpy(buf, t->token, len);
	bbs_assert(!strcmp(buf, t->token)); /* Provided buffer must be large enough */
	bbs_verb(5, "Created %s login token for %s\n", expires ? "temporary" : "semi-permanent", bbs_username(user));
	return 0;
}

int bbs_user_temp_authorization_token(struct bbs_user *user, char *buf, size_t len)
{
	return create_temp_authorization_token(user, buf, len, time(NULL) + DEFAULT_MAX_TOKEN_AGE);
}

int bbs_user_semiperm_authorization_token(struct bbs_user *user, char *buf, size_t len)
{
	return create_temp_authorization_token(user, buf, len, 0);
}

int bbs_user_semiperm_authorization_token_purge(const char *buf)
{
	int res = -1;
	struct pw_auth_token *t;

	RWLIST_WRLOCK(&auth_tokens);
	RWLIST_TRAVERSE_SAFE_BEGIN(&auth_tokens, t, entry) {
		if (!strcmp(t->token, buf)) {
			RWLIST_REMOVE_CURRENT(entry);
			auth_token_destory(t);
			res = 0;
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&auth_tokens);
	return res;
}

/*! \retval 1 if valid match, 0 if not */
static int valid_temp_token(const char *username, const char *password)
{
	struct pw_auth_token *t;
	time_t now;
	int total = 0;
	int match = 0;

	now = time(NULL);

	/* Purge any stale tokens. */
	RWLIST_WRLOCK(&auth_tokens);
	RWLIST_TRAVERSE_SAFE_BEGIN(&auth_tokens, t, entry) {
		if (t->expires && t->expires < now) { /* If it has an expiration time and it's already past, purge it */
			RWLIST_REMOVE_CURRENT(entry);
			auth_token_destory(t);
		} else {
			if (!strcasecmp(username, t->username) && !strcmp(password, t->token)) {
				match = 1;
			}
			if (t->expires) {
				RWLIST_REMOVE_CURRENT(entry);
				auth_token_destory(t); /* What good is a one-time token if we reuse it? */
			}
			/* Don't break, we still want to purge any tokens that may be stale. */
		}
		total++;
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&auth_tokens);
	return match;
}

/*! \retval 1 if successful, 0 if not found or unsuccessful */
static int login_is_cached(struct bbs_node *node, const char *username, const char *hash)
{
	struct cached_login *l;
	time_t now, cutoff;
	int remaining = 0;

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
		int i = 0;
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
			bbs_debug(3, "Cached login denied (different IP addresses: %s != %s)\n", l->ip, node->ip);
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

#ifndef TRUST_LOCALHOST
	if (bbs_is_loopback_ipv4(node->ip)) {
		return -1; /* Don't allow cached logins from localhost, this combines attack surfaces */
	}
#endif

	l = calloc(1, sizeof(*l));
	if (ALLOC_FAILURE(l)) {
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

	if (strlen_zero(password)) {
		return -1;
	}

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

	if (*password == POSSIBLE_AUTH_TOKEN_CHAR && bbs_is_loopback_ipv4(node->ip) && valid_temp_token(username, password)) { /* Check for possible temp auth token first */
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
		bbs_auth("Login attempt rejected for user %s (wrong password)\n", bbs_str_isprint(username) ? username : "[non-printable]");
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

static int post_auth(struct bbs_node *node, struct bbs_user *user)
{
	bbs_auth("Node %d now logged in as %s (via %s)\n", node->id, bbs_username(user), node->protname);
	bbs_event_dispatch(node, EVENT_USER_LOGIN);
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
	post_auth(node, user); /* Manually emit event since bbs_authenticate wasn't used */
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

	if (!username) {
		if (!password) {
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
		/* No username, but got a password, huh? */
		bbs_auth("Rejecting password login without username on node %d\n", node->id);
		return -1;
	}

	/* Not a guest, somebody needs to actual verify the username and password. */
	if (bbs_node_authenticate(node, username, password)) {
		bbs_event_dispatch_custom(node, EVENT_NODE_LOGIN_FAILED, username);
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

	post_auth(node, node->user);
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

	if (bbs_singular_callback_execute_pre(&registerprovider)) {
		bbs_error("No user registration provider is currently registered, registration rejected\n");
		return -1;
	}

	node->menu = "Register";
	res = BBS_SINGULAR_CALLBACK_EXECUTE(registerprovider)(node);
	bbs_singular_callback_execute_post(&registerprovider);
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

	if (bbs_singular_callback_execute_pre(&pwresethandler)) {
		bbs_error("No password reset handler is currently registered\n");
		return -1;
	}

	res = BBS_SINGULAR_CALLBACK_EXECUTE(pwresethandler)(username, password);
	bbs_singular_callback_execute_post(&pwresethandler);

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

	if (bbs_singular_callback_execute_pre(&userinfohandler)) {
		bbs_error("No user info handler is currently registered\n");
		return NULL;
	}

	user = BBS_SINGULAR_CALLBACK_EXECUTE(userinfohandler)(username);
	bbs_singular_callback_execute_post(&userinfohandler);

	return user;
}

struct bbs_user **bbs_user_list(void)
{
	struct bbs_user **userlist = NULL;

	if (bbs_singular_callback_execute_pre(&userlisthandler)) {
		bbs_error("No user list handler is currently registered\n");
		return NULL;
	}

	userlist = BBS_SINGULAR_CALLBACK_EXECUTE(userlisthandler)();
	bbs_singular_callback_execute_post(&userlisthandler);

	return userlist;
}

static int cli_authproviders(struct bbs_cli_args *a)
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
		bbs_dprintf(a->fdout, " %d => %-30s (%s)\n", c, p->name, bbs_module_name(p->module));
	}
	RWLIST_UNLOCK(&providers);
	bbs_dprintf(a->fdout, "%d registered auth provider%s\n", c, ESS(c));
	return 0;
}

static int cli_cachedauth_list(struct bbs_cli_args *a)
{
	struct cached_login *l;
	bbs_dprintf(a->fdout, "%-15s %s\n", "Username", "IP");
	RWLIST_TRAVERSE(&cached_logins, l, entry) {
		bbs_dprintf(a->fdout, "%-15s %s\n", S_IF(l->username), S_IF(l->ip));
	}
	return 0;
}

static int cli_cachedauth_clear(struct bbs_cli_args *a)
{
	UNUSED(a);
	RWLIST_WRLOCK_REMOVE_ALL(&cached_logins, entry, cached_login_destroy);
	return 0;
}

static struct bbs_cli_entry cli_commands_auth[] = {
	BBS_CLI_COMMAND(cli_authproviders, "authproviders", 1, "List all auth providers", NULL),
	BBS_CLI_COMMAND(cli_cachedauth_list, "cachedauth list", 2, "List all cached authentication", NULL),
	BBS_CLI_COMMAND(cli_cachedauth_clear, "cachedauth clear", 2, "Clear all cached authentication", NULL),
};

static int check_authproviders(void)
{
	if (!bbs_num_auth_providers()) {
		bbs_warning("There are no auth providers currently registered. User login will fail.\n");
	}
	return 0;
}

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("auth.conf", 1);

	if (!cfg) {
		bbs_warning("No usernames are reserved, leaving BBS vulnerable to name hijacking\n");
		return 0;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "reserved_usernames")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				const char *key = bbs_keyval_key(keyval);
				stringlist_push(&reserved_usernames, key);
			}
		}
	}
	if (stringlist_is_empty(&reserved_usernames)) {
		bbs_warning("No usernames are reserved, leaving BBS vulnerable to name hijacking\n");
	}
	return 0;
}

static int auth_reload(int fd)
{
	RWLIST_WRLOCK(&reserved_usernames);
	stringlist_empty(&reserved_usernames);
	load_config();
	RWLIST_UNLOCK(&reserved_usernames);

	bbs_dprintf(fd, "Reloaded auth settings\n");
	return 0;
}

int bbs_cleanup_auth(void)
{
	stringlist_empty_destroy(&reserved_usernames);
	return 0;
}

int bbs_init_auth(void)
{
	stringlist_init(&reserved_usernames);

	RWLIST_WRLOCK(&reserved_usernames);
	load_config();
	RWLIST_UNLOCK(&reserved_usernames);

	bbs_register_reload_handler("auth", "Reload authentication settings", auth_reload);
	bbs_run_when_started(check_authproviders, STARTUP_PRIORITY_DEFAULT);
	return bbs_cli_register_multiple(cli_commands_auth);
}
