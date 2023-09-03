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
#include <pthread.h>

#include "include/module.h"
#include "include/config.h"
#include "include/curl.h"
#include "include/linkedlists.h"
#include "include/utils.h"
#include "include/user.h"
#include "include/oauth.h"
#include "include/json.h"
#include "include/transfer.h"

/* Helpful resources:
 * https://github.com/google/gmail-oauth2-tools/wiki/OAuth2DotPyRunThrough
 * This is useful; it doesn't quite work anymore, but it gets you most of the way there.
 */

struct oauth_client {
	const char *name;
	const char *clientid;
	const char *clientsecret;
	const char *refreshtoken;
	const char *posturl;
	char *accesstoken;
	RWLIST_ENTRY(oauth_client) entry;
	time_t tokentime;
	time_t expires;
	unsigned int userid;
	pthread_mutex_t lock;
	char data[0];
};

static RWLIST_HEAD_STATIC(clients, oauth_client);

static void free_client(struct oauth_client *client)
{
	free_if(client->accesstoken);
	pthread_mutex_destroy(&client->lock);
	free(client);
}

static int add_oauth_client(const char *name, const char *clientid, const char *clientsecret, const char *refreshtoken, const char *accesstoken,
	const char *posturl, int expires, unsigned int userid)
{
	struct oauth_client *client;
	size_t namelen, idlen, secretlen, refreshlen, urllen;
	char *pos;

	if (strlen_zero(clientid) || strlen_zero(clientsecret) || strlen_zero(refreshtoken) || strlen_zero(posturl)) {
		bbs_error("Missing required OAuth config information in %s\n", name);
		return -1;
	}

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
	secretlen = strlen(clientsecret);
	refreshlen = strlen(refreshtoken);
	urllen = strlen(posturl);
	client = calloc(1, sizeof(*client) + namelen + idlen + secretlen + refreshlen + urllen + 5); /* NULs for each of them */
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
	strcpy(pos, clientsecret);
	client->clientsecret = pos;

	pos += secretlen + 1;
	strcpy(pos, refreshtoken);
	client->refreshtoken = pos;

	pos += refreshlen + 1;
	strcpy(pos, posturl);
	client->posturl = pos;

	/* Access token is optional */
	if (accesstoken) {
		client->accesstoken = strdup(accesstoken);
		client->tokentime = time(NULL); /* Assumed to be valid as of now. */
	}

	client->expires = expires;
	client->userid = userid;

	pthread_mutex_init(&client->lock, NULL);

	RWLIST_INSERT_HEAD(&clients, client, entry);
	return 0;
}

static int fetch_token(struct oauth_client *client, char *buf, size_t len)
{
	char postdata[512]; /* Luckily most OAuth providers seem to use the same OAuth parameters, but we could allow for custom POST data */
	struct bbs_curl c = {
		.url = client->posturl,
		.postfields = postdata,
		.forcefail = 0, /* If there's an error, display it */
	};
	const char *newtoken;
	json_t *json;
	json_error_t jansson_error = {};
	time_t now = time(NULL);
	int expires;
	time_t expiretime;
	int res = -1;

	pthread_mutex_lock(&client->lock);

	/* tokentime is when the token was acquired.
	 * expires is for how long the token is valid.
	 * So tokentime + expires = when the token expires */
	expiretime = client->tokentime + client->expires;

	if (client->tokentime && now < expiretime) {
		/* We already have a valid token and it hasn't expired yet. */
		safe_strncpy(buf, client->accesstoken, len);
		pthread_mutex_unlock(&client->lock);
		return 0;
	} else if (client->tokentime) {
		time_t ago = now - expiretime;
		bbs_debug(5, "Token refresh required (expired %" TIME_T_FMT " seconds ago)\n", ago);
	}

	/* Get a new token */
	snprintf(postdata, sizeof(postdata), "client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s", client->clientid, client->clientsecret, client->refreshtoken);
	if (bbs_curl_post(&c) || c.http_code != 200) {
		bbs_warning("Failed to refresh OAuth token '%s': %s\n", client->name, c.response);
		pthread_mutex_unlock(&client->lock);
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

	newtoken = json_object_string_value(json, "access_token");
	expires = json_object_int_value(json, "expires_in");

	if (!newtoken) {
		bbs_warning("Unable to find access_token\n");
		goto cleanup;
	}

	if (expires) {
		client->expires = expires; /* If they tell us when it'll expire, use that. */
	}

	client->tokentime = now;
	REPLACE(client->accesstoken, newtoken);
	safe_strncpy(buf, client->accesstoken, len);
	res = 0;

	bbs_verb(4, "Refreshed OAuth token '%s' (good for %ds)\n", client->name, expires);

cleanup:
	pthread_mutex_unlock(&client->lock);
	if (json) {
		json_decref(json);
	}
	bbs_curl_free(&c);
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
		add_oauth_client(bbs_config_section_name(section), clientid, clientsecret, refreshtoken, accesstoken, posturl, expires, userid);
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
	int res = -1;
	struct oauth_client *client;
	unsigned int userid = bbs_user_is_registered(user) ? user->id : 0;

	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		/* Because users can name their token mappings, the name on its own is not unique.
		 * However, the name + user ID should be. So either it's the user's token,
		 * or it's a token that anybody can use. */
		if (!strcmp(client->name, name) && (!client->userid || client->userid == userid)) {
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
		char useroauthfile[256];
		if (bbs_transfer_home_config_file(userid, ".oauth.conf", useroauthfile, sizeof(useroauthfile))) {
			return -1;
		}
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

static int load_config(void)
{
	return load_config_file("mod_oauth.conf", 0, NULL);
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	bbs_register_oauth_provider(get_oauth_token);
	return 0;
}

static int unload_module(void)
{
	bbs_unregister_oauth_provider(get_oauth_token);
	RWLIST_WRLOCK_REMOVE_ALL(&clients, entry, free_client);
	return 0;
}

BBS_MODULE_INFO_STANDARD("OAuth 2.0");
