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
#include "include/user.h"

#include "include/oauth.h"

#include "include/json.h"

/* Helpful resources:
 * https://github.com/google/gmail-oauth2-tools/wiki/OAuth2DotPyRunThrough
 * This is useful, but it doesn't quite work anymore, but it gets you most of the way there.
 */

struct oauth_client {
	const char *name;
	const char *clientid;
	const char *clientsecret;
	const char *refreshtoken;
	const char *posturl;
	char *accesstoken;
	RWLIST_ENTRY(oauth_client) entry;
	int tokentime;
	int expires;
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
	const char *posturl, int expires, int userid)
{
	struct oauth_client *client;
	int namelen, idlen, secretlen, refreshlen, urllen;
	char *pos;

	if (strlen_zero(clientid) || strlen_zero(clientsecret) || strlen_zero(refreshtoken) || strlen_zero(posturl)) {
		bbs_error("Missing required OAuth config information in %s\n", name);
		return -1;
	}

	/* Allocate */
	RWLIST_WRLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!strcmp(client->name, name)) {
			bbs_error("Client '%s' already defined\n", name);
			break;
		}
	}
	if (client) {
		RWLIST_UNLOCK(&clients);
		return -1;
	}
	namelen = strlen(name);
	idlen = strlen(clientid);
	secretlen = strlen(clientsecret);
	refreshlen = strlen(refreshtoken);
	urllen = strlen(posturl);
	client = calloc(1, sizeof(*client) + namelen + idlen + secretlen + refreshlen + urllen + 5); /* NULs for each of them */
	if (ALLOC_FAILURE(client)) {
		RWLIST_UNLOCK(&clients);
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
	RWLIST_UNLOCK(&clients);
	return 0;
}

static int fetch_token(struct oauth_client *client, char *buf, size_t len)
{
	char postdata[512]; /* Luckily most OAuth providers seem to use the same OAuth parameters, but we could allow for custom POST data */
	struct bbs_curl c = {
		.url = client->posturl,
		.postfields = postdata,
		.forcefail = 1,
	};
	const char *newtoken;
	json_t *json;
	json_error_t jansson_error = {};
	int now = time(NULL);
	int expires, expired = now - client->expires;
	int res = -1;

	pthread_mutex_lock(&client->lock);

	if (client->tokentime && expired > client->tokentime) {
		/* We already have a valid token and it hasn't expired yet. */
		safe_strncpy(buf, client->accesstoken, len);
		pthread_mutex_unlock(&client->lock);
		return 0;
	}

	/* Get a new token */
	snprintf(postdata, sizeof(postdata), "client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s", client->clientid, client->clientsecret, client->refreshtoken);
	if (bbs_curl_post(&c)) {
		bbs_warning("Failed to refresh OAuth token '%s'\n", client->name);
		pthread_mutex_unlock(&client->lock);
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

static int get_oauth_token(struct bbs_user *user, const char *name, char *buf, size_t len)
{
	int res = -1;
	struct oauth_client *client;

	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!strcmp(client->name, name)) {
			if (client->userid && (!bbs_user_is_registered(user) || user->id != client->userid)) {
				bbs_warning("OAuth user '%s' restricted to user %u (rejecting %u\n", name, client->userid, user->id);
				continue;
			}
			res = fetch_token(client, buf, len);
			break;
		}
	}
	RWLIST_UNLOCK(&clients);
	return res;
}

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

	cfg = bbs_config_load("mod_oauth.conf", 1);
	if (!cfg) {
		return -1;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		int expires = 3600; /* Defaults to 1 hour */
		int userid = 0;
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
				userid = atoi(value);
			} else {
				bbs_warning("Unknown config directive: %s\n", key);
			}
		}
		add_oauth_client(bbs_config_section_name(section), clientid, clientsecret, refreshtoken, accesstoken, posturl, expires, userid);
	}
	return 0;
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
