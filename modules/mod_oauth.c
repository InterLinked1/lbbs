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
 * \brief OAuth 2.0 (Open Authorization) interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/config.h"
#include "include/linkedlists.h"
#include "include/utils.h"
#include "include/user.h"
#include "include/oauth.h"
#include "include/json.h"
#include "include/transfer.h"
#include "include/cli.h"

#include "include/mod_curl.h"

struct oauth_client {
	const char *name;
	const char *clientid;
	const char *clientsecret;
	const char *posturl;
	const char *filename;
	char *accesstoken;
	char *refreshtoken;
	RWLIST_ENTRY(oauth_client) entry;
	time_t tokentime;
	time_t expires;
	unsigned int userid;
	unsigned int accesstokeninitiallyempty:1;
	bbs_mutex_t lock;
	char data[0];
};

static RWLIST_HEAD_STATIC(clients, oauth_client);

static void free_client(struct oauth_client *client)
{
	free_if(client->refreshtoken);
	free_if(client->accesstoken);
	bbs_mutex_destroy(&client->lock);
	free(client);
}

#define REQUIRE_SETTING(field) \
	if (strlen_zero(clientid)) { \
		bbs_error("OAuth config profile '%s' missing required setting '%s'\n", name, field); \
		return -1; \
	}

/*! \note clients must be WRLOCK'd when calling */
static int add_oauth_client(const char *name, const char *clientid, const char *clientsecret, const char *refreshtoken, const char *accesstoken,
	const char *posturl, int expires, unsigned int userid, const char *filename)
{
	struct oauth_client *client;
	size_t namelen, idlen, secretlen, urllen, filenamelen;
	char *pos;

	REQUIRE_SETTING(clientid);
	/* clientsecret is optional */
	REQUIRE_SETTING(refreshtoken);
	REQUIRE_SETTING(posturl);

	/* Allocate */
	RWLIST_TRAVERSE_SAFE_BEGIN(&clients, client, entry) {
		if (userid == client->userid && !strcmp(client->name, name)) {
			bbs_debug(3, "Client '%s', user ID %u already defined, replacing\n", name, userid);
			/* If a user updated the .oauth.conf file in his/her home directory,
			 * we'll need to rescan it, and we'll call add_oauth_client again.
			 * We should update the existing config entry, rather than just aborting. */
			RWLIST_REMOVE_CURRENT(entry);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (client) {
		free_client(client);
	}
	namelen = strlen(name);
	idlen = strlen(clientid);
	secretlen = !strlen_zero(clientsecret) ? strlen(clientsecret) : 0;
	urllen = strlen(posturl);
	filenamelen = strlen(filename);
	client = calloc(1, sizeof(*client) + namelen + idlen + secretlen + urllen + filenamelen + 5); /* NULs for each of them */
	if (ALLOC_FAILURE(client)) {
		return -1;
	}
	/* All safe */
	pos = client->data;
	strcpy(pos, name);
	client->name = pos;

	pos += namelen + 1;
	strcpy(pos, clientid);
	client->clientid = pos;

	pos += idlen + 1;
	if (!strlen_zero(clientsecret)) {
		strcpy(pos, clientsecret);
		client->clientsecret = pos;
	} else {
		client->clientsecret = NULL;
	}

	pos += secretlen + 1;
	strcpy(pos, posturl);
	client->posturl = pos;

	pos += urllen + 1;
	strcpy(pos, filename);
	client->filename = pos;

	client->refreshtoken = strdup(refreshtoken);
	if (ALLOC_FAILURE(client->refreshtoken)) {
		free(client);
		return -1;
	}

	/* Access token is optional and will change during runtime */
	if (accesstoken) {
		client->accesstoken = strdup(accesstoken);
		if (ALLOC_FAILURE(client->accesstoken)) {
			free(client->refreshtoken);
			free(client);
			return -1;
		}
		client->tokentime = time(NULL); /* Assumed to be valid as of now. */
	} else {
		client->accesstokeninitiallyempty = 1;
	}

	client->expires = expires;
	client->userid = userid;

	bbs_mutex_init(&client->lock, NULL);

	RWLIST_INSERT_HEAD(&clients, client, entry);
	return 0;
}

static int refresh_token(struct oauth_client *client)
{
	char postdata[1024]; /* Luckily most OAuth providers seem to use the same OAuth parameters, but we could allow for custom POST data */
	struct bbs_curl c = {
		.url = client->posturl,
		.postfields = postdata,
		.forcefail = 0, /* If there's an error, display it */
	};
	const char *newaccesstoken;
	const char *newrefreshtoken;
	json_t *json;
	json_error_t jansson_error = {};
	int expires;
	time_t now = time(NULL);

	/* Get a new token */
	/* Even when client_secret is not required, as long as the argument is empty, the query param being present doesn't hurt anything (at least with Microsoft) */
	snprintf(postdata, sizeof(postdata), "client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s", client->clientid, S_IF(client->clientsecret), client->refreshtoken);
	if (bbs_curl_post(&c) || c.http_code != 200) {
		bbs_warning("Failed to refresh OAuth token '%s': %s\n", client->name, c.response);
		bbs_curl_free(&c);
		return -1;
	}

#ifdef DEBUG_OAUTH
	bbs_debug(5, "cURL response: %s\n", c.response);
#endif

	/* Parse the result if it's valid and get the new token */
	json = json_loads(c.response, 0, &jansson_error);

	if (!json) {
		bbs_warning("Failed to parse as JSON (line %d): %s\n", jansson_error.line, jansson_error.text);
		goto cleanup;
	}

	newaccesstoken = json_object_string_value(json, "access_token");
	newrefreshtoken = json_object_string_value(json, "refresh_token");
	expires = json_object_int_value(json, "expires_in");

	if (!newaccesstoken) {
		bbs_warning("Unable to find access_token\n");
		goto cleanup;
	}

	if (expires) {
		client->expires = expires; /* If they tell us when it'll expire, use that. */
	}

	client->tokentime = now;
	if (!strlen_zero(newrefreshtoken) && strcmp(newrefreshtoken, client->refreshtoken)) {
		/* The authorization server MAY issue a new refresh token, in which case the client
		 * MUST discard the old refresh token and replace it with the new refresh token.
		 * The authorization server MAY revoke the old refresh token after issuing a new refresh token to the client. */
		bbs_debug(2, "OAuth refresh token has changed\n");
		REPLACE(client->refreshtoken, newrefreshtoken);
		/* This is good as long as the BBS is running continously, but we also need to update the static configuration file,
		 * or we'll lose the new refresh token the next time the BBS starts (or mod_oauth is reloaded). */
		if (bbs_config_set_keyval(client->filename, client->name, "refreshtoken", client->refreshtoken)) {
			bbs_warning("OAuth refresh token has changed, but is not persisted to configuration\n");
		}
	}
	if (!strlen_zero(newaccesstoken) && !client->accesstokeninitiallyempty && (strlen_zero(client->accesstoken) || strcmp(newaccesstoken, client->accesstoken))) {
		REPLACE(client->accesstoken, newaccesstoken);
		/* Also update the config with the new access token, so we don't try to use
		 * an old access token in the future.
		 * This way, if there's an access token specified in the config file,
		 * when we write new refresh tokens to the file, we don't leave a stale access token there
		 * and load that back in when it's no longer valid. */
		if (bbs_config_set_keyval(client->filename, client->name, "accesstoken", client->accesstoken)) {
			bbs_warning("OAuth access token has changed, but is not persisted to configuration\n");
		}
	} else {
		/* Just update in memory, we won't pull an old access token from the config in the future since it's not specified there to start with. */
		REPLACE(client->accesstoken, newaccesstoken);
	}

	bbs_verb(4, "Refreshed OAuth token '%s' (good for %ds)\n", client->name, expires);
	json_decref(json);
	bbs_curl_free(&c);
	return 0;

cleanup:
	if (json) {
		json_decref(json);
	}
	bbs_curl_free(&c);
	return -1;
}

static int fetch_token(struct oauth_client *client, char *buf, size_t len)
{
	int res;
	time_t now = time(NULL);
	time_t expiretime;

	bbs_mutex_lock(&client->lock);

	/* tokentime is when the token was acquired.
	 * expires is for how long the token is valid.
	 * So tokentime + expires = when the token expires */
	expiretime = client->tokentime + client->expires;

	if (client->tokentime && now < expiretime) {
		/* We already have a valid token and it hasn't expired yet. */
		safe_strncpy(buf, client->accesstoken, len);
		bbs_mutex_unlock(&client->lock);
		return 0;
	} else if (client->tokentime) {
		time_t ago = now - expiretime;
		bbs_debug(3, "Token refresh required (expired %" TIME_T_FMT " seconds ago)\n", ago);
	} else {
		bbs_debug(3, "Token refresh required (no access token pre-seeded)\n");
	}

	res = refresh_token(client);
	if (!res) {
		size_t accesstokenlen = strlen(client->accesstoken);
		if (accesstokenlen >= len) {
			bbs_warning("Truncation occured when copying access token of length %lu to buffer of size %lu, authentication will fail!\n", accesstokenlen, len);
		}
		safe_strncpy(buf, client->accesstoken, len);
	}
	bbs_mutex_unlock(&client->lock);
	return res;
}

#define MAX_USER_OAUTH_TOKENS 50

static int load_config_file(const char *filename, unsigned int forceuserid, const char *match)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	int namematch = 0;
	int added = 0;

	/*! \note
	 * This module config is a little bit different.
	 * We do read in a general module config file, but in addition to that,
	 * we also read config files in each user's home directory (as needed, not all upfront),
	 * since this is something that users need to be able to configure themselves.
	 * Thus, while it's possible to configure things in the general config file,
	 * it's expected that most configuration will be done by users in their own config files.
	 */

	/* If there are concurrent calls to get a user token, we need to serialize these
	 * to one thread doesn't free a cfg while another thread is still using it. */
	RWLIST_WRLOCK(&clients);
	cfg = bbs_config_load(filename, 1); /* Use cached version if available, if user has updated config, we'll reparse */
	if (!cfg) {
		RWLIST_UNLOCK(&clients);
		return -1;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		int expires = 3600; /* Defaults to 1 hour */
		unsigned int userid = 0;
		const char *clientid = NULL, *clientsecret = NULL, *accesstoken = NULL, *refreshtoken = NULL, *posturl = NULL;
		if (!strcmp(bbs_config_section_name(section), "general")) { /* Not used currently, but reserved */
			continue;
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcasecmp(key, "clientid")) {
				clientid = value;
			} else if (!strcasecmp(key, "clientsecret")) {
				clientsecret = value;
			} else if (!strcasecmp(key, "refreshtoken")) {
				refreshtoken = value;
			} else if (!strcasecmp(key, "accesstoken")) {
				accesstoken = value;
			} else if (!strcasecmp(key, "posturl")) {
				posturl = value;
			} else if (!strcasecmp(key, "expires")) {
				expires = atoi(value);
			} else if (!strcasecmp(key, "userid")) {
				userid = (unsigned int) atoi(value);
			} else {
				bbs_warning("Unknown config directive: %s\n", key);
			}
		}
		if (forceuserid) {
			userid = forceuserid;
		}
		if (match && !strcmp(bbs_config_section_name(section), match)) {
			namematch = 1;
		}
		add_oauth_client(bbs_config_section_name(section), clientid, clientsecret, refreshtoken, accesstoken, posturl, expires, userid, filename);
		if (forceuserid && added++ > MAX_USER_OAUTH_TOKENS) {
			/* Prevent a user from loading an unbounded amount of token mappings into memory. */
			bbs_warning("Maximum user OAuth token mappings exceeded, ignoring remaining mappings\n");
			break;
		}
	}
	RWLIST_UNLOCK(&clients);
	return !match || namematch ? 0 : -1;
}

static int get_oauth_token(struct bbs_user *user, const char *name, char *buf, size_t len)
{
	char useroauthfile[256];
	int res = -1;
	struct oauth_client *client;
	unsigned int userid = bbs_user_is_registered(user) ? user->id : 0;

	if (user && bbs_transfer_home_config_file(userid, ".oauth.conf", useroauthfile, sizeof(useroauthfile))) {
		return -1;
	}

	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		/* Because users can name their token mappings, the name on its own is not unique.
		 * However, the name + user ID should be. So either it's the user's token,
		 * or it's a token that anybody can use. */
		if (!strcmp(client->name, name) && (!client->userid || client->userid == userid)) {
			if (user && bbs_cached_config_outdated(useroauthfile)) {
				/* If the tokens changed, they could be outdated, parse it again. */
				bbs_debug(3, "OAuth config file %s has been modified since last parse, ignoring cached version\n", useroauthfile);
				break;
			}
			res = fetch_token(client, buf, len);
			break;
		}
	}
	RWLIST_UNLOCK(&clients);

	if (!user) {
		return -1;
	}

	if (!client || res) { /* Didn't find a matching token, or it failed the first time */
		/* Didn't find any matching OAuth token. Look in the user's home directory and see if it's there. */
		if (!load_config_file(useroauthfile, userid, name)) { /* Only counts if we specifically loaded a section with the given name */
			/* Repeat, since we just now added a section named that */
			RWLIST_RDLOCK(&clients);
			RWLIST_TRAVERSE(&clients, client, entry) {
				if (!strcmp(client->name, name) && (!client->userid || client->userid == userid)) {
					res = fetch_token(client, buf, len);
					break;
				}
			}
			RWLIST_UNLOCK(&clients);
		}
	}

	return res;
}

static int cli_get_tokens(struct bbs_cli_args *a)
{
	struct oauth_client *client;
	int c = 0;
	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!c++) {
			bbs_dprintf(a->fdout, "%-15s %7s\n", "Name", "User ID");
		}
		bbs_dprintf(a->fdout, "%-15s %7u\n", client->name, client->userid);
	}
	RWLIST_UNLOCK(&clients);
	bbs_dprintf(a->fdout, "%d total token%s\n", c, ESS(c));
	return 0;
}

static int cli_get_token(struct bbs_cli_args *a)
{
	int match = 0;
	time_t now = time(NULL);
	unsigned int userid = a->argc >= 4 ? (unsigned int) atoi(a->argv[3]) : 0;
	struct oauth_client *client;
	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!strcmp(a->argv[2], client->name)) {
			if (!userid || client->userid == userid) {
				time_t diff;
				match++;
				bbs_mutex_lock(&client->lock);
				diff = client->tokentime + client->expires - now;
				bbs_dprintf(a->fdout, "-- %s --\n", client->name);
				if (client->userid) {
					bbs_dprintf(a->fdout, "%-15s %u\n", "User ID:", client->userid);
				}
				bbs_dprintf(a->fdout, "%-15s %s\n", "Client ID:", S_IF(client->clientid));
				bbs_dprintf(a->fdout, "%-15s %s\n", "Client Secret:", S_IF(client->clientsecret));
				bbs_dprintf(a->fdout, "%-15s %s\n", "Post URL:", S_IF(client->posturl));
				bbs_dprintf(a->fdout, "%-15s %s\n", "Access Token:", S_IF(client->accesstoken));
				bbs_dprintf(a->fdout, "%-15s %s\n", "Refresh Token:", S_IF(client->refreshtoken));
				bbs_dprintf(a->fdout, "%-15s %" TIME_T_FMT " (%" TIME_T_FMT "s from now)\n", "Token Expiry:", client->tokentime, diff);
				bbs_mutex_unlock(&client->lock);
				if (userid) {
					break;
				}
			}
		}
	}
	RWLIST_UNLOCK(&clients);
	if (!match) {
		if (userid) {
			bbs_dprintf(a->fdout, "No OAuth2 profiles matched profile name '%s' and user ID %u\n", a->argv[2], userid);
		} else {
			bbs_dprintf(a->fdout, "No OAuth2 profiles matched profile name '%s'\n", a->argv[2]);
		}
		return -1;
	}
	return 0;
}

static int cli_refresh_token(struct bbs_cli_args *a)
{
	int match = 0;
	unsigned int userid = a->argc >= 4 ? (unsigned int) atoi(a->argv[3]) : 0;
	struct oauth_client *client;
	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!strcmp(a->argv[2], client->name)) {
			if (!userid || client->userid == userid) {
				bbs_mutex_lock(&client->lock);
				if (refresh_token(client)) {
					bbs_dprintf(a->fdout, "Failed to refresh OAuth2 token '%s'\n", client->name);
				}
				bbs_mutex_unlock(&client->lock);
			}
		}
	}
	RWLIST_UNLOCK(&clients);
	if (!match) {
		if (userid) {
			bbs_dprintf(a->fdout, "No OAuth2 profiles matched profile name '%s' and user ID %u\n", a->argv[2], userid);
		} else {
			bbs_dprintf(a->fdout, "No OAuth2 profiles matched profile name '%s'\n", a->argv[2]);
		}
		return -1;
	} else {
		bbs_dprintf(a->fdout, "Refreshed %d token%s\n", match, ESS(match));
	}
	return 0;
}

static struct bbs_cli_entry cli_commands_oauth[] = {
	BBS_CLI_COMMAND(cli_get_tokens, "oauth tokens", 2, "List all configured OAuth2 tokens", NULL),
	BBS_CLI_COMMAND(cli_get_token, "oauth token", 3, "Dump information about an OAuth token", "oauth token <profile> <user ID>"),
	BBS_CLI_COMMAND(cli_refresh_token, "oauth refresh", 3, "Manually force refresh of an OAuth token", "oauth refresh <profile> <user ID>"),
};

static int load_config(void)
{
	return load_config_file("mod_oauth.conf", 0, NULL);
}

static int load_module(void)
{
	/* Initially, we only load profiles from mod_oauth.conf,
	 * individual user .oauth.conf configs are parsed just in time,
	 * if/as needed. */
	if (load_config()) {
		return -1;
	}
	bbs_register_oauth_provider(get_oauth_token);
	bbs_cli_register_multiple(cli_commands_oauth);
	return 0;
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_oauth);
	bbs_unregister_oauth_provider(get_oauth_token);
	RWLIST_WRLOCK_REMOVE_ALL(&clients, entry, free_client);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("OAuth 2.0 Client Authentication", "mod_curl.so");
