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
 * \brief Slack IRC relay integration
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>

#include <curl/curl.h> /* needed for curl_easy_escape */

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/module.h"
#include "include/utils.h"
#include "include/node.h" /* use bbs_hostname */
#include "include/startup.h"
#include "include/cli.h"

#include "include/mod_curl.h"
#include "include/json.h"

/* Needed for presence query/subscribe commands. Requires jansson support, so must come after json.h include. */
#define SLACK_EXPOSE_JSON

/* libslackrtm: https://github.com/InterLinked1/slack-rtm */
#include <slackrtm/slack.h>
#include <slackrtm/slack-client.h>

#define MIN_VERSION_REQUIRED SEMVER_VERSION(0,3,3)
#if SEMVER_VERSION(SLACK_RTM_LIB_VERSION_MAJOR, SLACK_RTM_LIB_VERSION_MINOR, SLACK_RTM_LIB_VERSION_PATCH) < MIN_VERSION_REQUIRED
#error "libslackrtm version too old"
#endif

#include "include/net_irc.h"

static int expose_members = 1;

struct slack_user {
	const char *userid;
	RWLIST_ENTRY(slack_user) entry;
	const char *username;
	const char *realname;
	const char *dispname;
	char *status;
	int tzoffset;
	char ircusername[64];
	char *dmchannel;
	struct slack_relay *relay;
	unsigned int active:1;			/*!< Presence status */
	unsigned int shared:1;			/*!< Whether we share any channels with this user */
	bbs_mutex_t lock;
	char lastmsg[512];
	char data[];
};

RWLIST_HEAD(slack_users, slack_user);

struct member {
	struct slack_user *u;
	RWLIST_ENTRY(member) entry;
};

RWLIST_HEAD(members, member);

struct chan_pair {
	const char *irc;	/*!< IRC channel name */
	const char *slack;	/*!< Slack channel ID */
	struct slack_relay *relay;	/*!< Associated Slack relay, for finding Slack channel from IRC channel name */
	RWLIST_ENTRY(chan_pair) entry;
	bbs_mutex_t sendlock;
	bbs_mutex_t msglock;
	char *name;			/*!< Actual Slack channel name */
	char *topic;		/*!< Slack channel topic */
	struct members members;	/*!< Members of channel (may be incomplete, in large workspaces) */
	unsigned int used:1;	/*!< Whether this channel has been accessed/used */
	char lastmsg[512];
	char data[];
};

RWLIST_HEAD(chan_pairs, chan_pair);

#define SLACK_TS_LENGTH 17

struct slack_relay {
	RWLIST_ENTRY(slack_relay) entry;
	struct slack_client *slack;
	unsigned int relaysystem:1;	/*!< Relay system messages (e.g. JOIN, PART, etc.) */
	unsigned int relayaway:1;	/*!< Relay AWAY status */
	unsigned int relaystatus:1;	/*!< Update status when relaying AWAY status */
	unsigned int started:1;		/*!< Relay started successfully */
	unsigned int error:1;		/*!< Relay in (fatal or problematic) error state */
	unsigned int preservethreading:1;	/*!< Try to preserve threading in replies */
	unsigned int prefixthread:1;	/*!< Whether to prefix messages with the thread ID */
	const char *name;
	const char *ircuser;		/*!< IRC username, if this is a personal relay (i.e. intended for just one IRC user) */
	const char *token;
	const char *gwserver;
	const char *cookie_d;
	const char *enterpriseid;
	const char *cookie_ds;
	struct chan_pairs mappings;
	struct slack_users users;
	pthread_t thread;
	bbs_mutex_t lock;
	char last_ts[SLACK_TS_LENGTH + 1];
	char data[];
};

static RWLIST_HEAD_STATIC(relays, slack_relay);

static void cp_free(struct chan_pair *cp)
{
	RWLIST_WRLOCK_REMOVE_ALL(&cp->members, entry, free);
	RWLIST_HEAD_DESTROY(&cp->members);
	free_if(cp->topic);
	bbs_mutex_destroy(&cp->sendlock);
	bbs_mutex_destroy(&cp->msglock);
	free(cp);
}

static void slack_user_free(struct slack_user *u)
{
	free_if(u->status);
	free_if(u->dmchannel);
	bbs_mutex_destroy(&u->lock);
	free(u);
}

static void relay_free(struct slack_relay *relay)
{
	if (relay->slack) { /* Should always be true except on config parsing early abort */
		if (relay->thread) {
			slack_client_interrupt(relay->slack);
			bbs_pthread_join(relay->thread, NULL);
		}
		slack_client_destroy(relay->slack);
	}
	RWLIST_WRLOCK_REMOVE_ALL(&relay->mappings, entry, cp_free);
	RWLIST_WRLOCK_REMOVE_ALL(&relay->users, entry, slack_user_free);
	RWLIST_HEAD_DESTROY(&relay->mappings);
	RWLIST_HEAD_DESTROY(&relay->users);
	bbs_mutex_destroy(&relay->lock);
	free(relay);
}

static struct chan_pair *find_slack_channel(struct slack_relay *relay, const char *channel)
{
	struct chan_pair *cp;
	RWLIST_TRAVERSE(&relay->mappings, cp, entry) {
		if (!strcmp(cp->slack, channel)) {
			break;
		}
	}
	return cp;
}

static struct chan_pair *find_irc_channel(const char *channel)
{
	struct slack_relay *r;
	/* This is a harder job than find_slack_channel, because find_slack_channel already has a relay.
	 * We don't know the relay, so we have to traverse everything. */
	RWLIST_TRAVERSE(&relays, r, entry) {
		struct chan_pair *cp;
		RWLIST_TRAVERSE(&r->mappings, cp, entry) {
			if (!strcmp(cp->irc, channel)) {
				return cp;
			}
		}
	}
	return NULL;
}

static void add_channel_member(struct chan_pair *cp, struct slack_user *u)
{
	struct member *m = calloc(1, sizeof(*m));
	if (ALLOC_FAILURE(m)) {
		return;
	}
	m->u = u;
	u->shared = 1;
	RWLIST_INSERT_HEAD(&cp->members, m, entry);
}

static json_t *slack_curl_get(struct slack_relay *relay, const char *url)
{
	char cookies[512];
	json_t *json;
	json_error_t jansson_error = {};
	struct bbs_curl c = {
		.url = url,
		.forcefail = 1,
		.cookies = cookies,
	};

	if (relay->cookie_ds) {
		snprintf(cookies, sizeof(cookies), "d=%s; d-s=%s", relay->cookie_d, relay->cookie_ds);
	} else {
		snprintf(cookies, sizeof(cookies), "d=%s", relay->cookie_d);
	}

	if (bbs_curl_get(&c)) {
		return NULL;
	}

	json = json_loads(c.response, 0, &jansson_error);
	if (!json) {
		bbs_warning("Failed to parse as JSON (line %d): %s\n", jansson_error.line, jansson_error.text);
		bbs_curl_free(&c);
		return NULL;
	}
	if (!json_object_bool_value(json, "ok")) {
		bbs_warning("Slack API request failed: %s\n", c.response);
		json_decref(json);
		bbs_curl_free(&c);
		return NULL;
	}
	bbs_curl_free(&c);
	return json;
}

static json_t *slack_curl_post(struct slack_relay *relay, const char *url, const char *postfields)
{
	char cookies[512];
	json_t *json;
	json_error_t jansson_error = {};
	struct bbs_curl c = {
		.url = url,
		.postfields = postfields,
		.forcefail = 1,
		.cookies = cookies,
	};

	if (relay->cookie_ds) {
		snprintf(cookies, sizeof(cookies), "d=%s; d-s=%s", relay->cookie_d, relay->cookie_ds);
	} else {
		snprintf(cookies, sizeof(cookies), "d=%s", relay->cookie_d);
	}

	if (bbs_curl_post(&c)) {
		return NULL;
	}

	json = json_loads(c.response, 0, &jansson_error);
	if (!json) {
		bbs_warning("Failed to parse as JSON (line %d): %s\n", jansson_error.line, jansson_error.text);
		bbs_curl_free(&c);
		return NULL;
	}
	if (!json_object_bool_value(json, "ok")) {
		bbs_warning("Slack API request failed: %s\n", c.response);
		json_decref(json);
		bbs_curl_free(&c);
		return NULL;
	}
	bbs_curl_free(&c);
	return json;
}

static struct slack_user *load_single_user(struct slack_relay *relay, json_t *jsonuser, const char *userid)
{
	json_t *profile;
	struct slack_user *user = NULL;
	const char *realname, *name, *displayname, *status;
	const char *ircusername;
	char baseusername[56];
	size_t useridlen, realnamelen, namelen, displaynamelen;
	int tzoffset;
	char *data;

	if (!userid) {
		bbs_warning("Missing user ID, not loading user\n");
		return NULL;
	}

	/* In practice, most of the time it seems display name is set and real name is not set,
	 * but occasionally it will even be the other way around, so always ask for both. */
	realname = json_object_string_value(jsonuser, "real_name");
	name = json_object_string_value(jsonuser, "name");
	tzoffset = (int) json_object_number_value(jsonuser, "tz_offset");
	profile = json_object_get(jsonuser, "profile");
	displayname = json_object_string_value(profile, "display_name");
	status = json_object_string_value(profile, "status_text");

	if (!name && !realname && !displayname) {
		/* Either something is werid or it's a parsing error */
		bbs_warning("Nameless user %s?\n", userid);
		return NULL;
	}

	bbs_debug(5, "Fetched user %s/%s: %s/%s/%s/%d (%s)\n", relay->name, userid, name, realname, displayname, tzoffset, status);

	/* displayname is likely to be realname (by default). Don't duplicate it if that's the case. */
	if (displayname && realname && !strcmp(displayname, realname)) {
		displayname = NULL;
	}

	useridlen = STRING_ALLOC_SIZE(userid);
	namelen = STRING_ALLOC_SIZE(name);
	realnamelen = STRING_ALLOC_SIZE(realname);
	displaynamelen = STRING_ALLOC_SIZE(displayname);

	user = calloc(1, sizeof(*user) + useridlen + namelen + realnamelen + displaynamelen);
	if (ALLOC_FAILURE(user)) {
		return NULL;
	}

	user->tzoffset = tzoffset;
	if (!strlen_zero(status)) {
		user->status = strdup(status);
	}

	data = user->data;
	SET_FSM_STRING_VAR(user, data, userid, userid, useridlen);
	SET_FSM_STRING_VAR(user, data, username, name, namelen);
	SET_FSM_STRING_VAR(user, data, realname, realname, realnamelen);
	SET_FSM_STRING_VAR(user, data, dispname, displayname, displaynamelen);

	/* Prefer the traditional "name" (now deprecated) if set, since it's the closest to an IRC-style username */
	ircusername = name ? name : displayname ? displayname : realname ? realname : userid;
	bbs_strcpy_nospaces(ircusername, baseusername, sizeof(baseusername));
	/* Even if it's a personal relay, we still need to prepend a prefix to make these
	 * usernames unique from the userspace of regular IRC user.
	 * Since we could have multiple Slack workspaces, with duplicate names between each,
	 * prefix using the configured name of the workspace. */
	snprintf(user->ircusername, sizeof(user->ircusername), "%s/%s", relay->name, baseusername);

	user->relay = relay;
	bbs_mutex_init(&user->lock, NULL);
	RWLIST_INSERT_HEAD(&relay->users, user, entry);
	return user;
}

/*! \note relay->users must be WRLOCK'd when calling */
static struct slack_user *load_user(struct slack_relay *relay, const char *userid)
{
	char url[256];
	json_t *json;
	struct slack_user *user;

	snprintf(url, sizeof(url), "https://slack.com/api/users.info?token=%s&user=%s", relay->token, userid);
	json = slack_curl_get(relay, url);
	if (!json) {
		return NULL;
	}

	user = load_single_user(relay, json_object_get(json, "user"), userid);

	json_decref(json);
	return user;
}

static int load_users(struct slack_relay *relay, int limit)
{
	char url[256];
	size_t index;
	json_t *json, *members, *value;

	snprintf(url, sizeof(url), "https://slack.com/api/users.list?token=%s&limit=%d", relay->token, limit);
	json = slack_curl_get(relay, url);
	if (!json) {
		return -1;
	}

	RWLIST_WRLOCK(&relay->users);
	members = json_object_get(json, "members");
	json_array_foreach(members, index, value) {
		load_single_user(relay, value, json_object_string_value(value, "id"));
	}
	RWLIST_UNLOCK(&relay->users);

	json_decref(json);
	return 0;
}

/* Forward declaration */
static struct slack_user *slack_user_by_userid_locked(struct slack_relay *relay, const char *userid, int reorder);

static void load_members(struct slack_relay *relay, struct chan_pair *cp, const char *channelid, int limit)
{
	char url[256];
	size_t index;
	json_t *json, *members, *value;
	int c = 0;

	/* Get all (or the first N) members in the channel */
	snprintf(url, sizeof(url), "https://slack.com/api/conversations.members?token=%s&channel=%s&limit=%d", relay->token, channelid, limit);
	json = slack_curl_get(relay, url);
	if (!json) {
		return;
	}

	members = json_object_get(json, "members");

	/* relay->users is already WRLOCK'd */
	RWLIST_WRLOCK(&cp->members);
	json_array_foreach(members, index, value) {
		const char *userid = json_string_value(value);
		/* Hopefully already loaded, due to calling load_users previously to fetch members en masse */
		struct slack_user *u = slack_user_by_userid_locked(relay, userid, 0);
		if (!u) {
			bbs_warning("Couldn't load user %s (while loading channel %s)\n", userid, channelid);
			continue;
		}
		/* Keep track of the user:channel relationship that exists here */
		add_channel_member(cp, u);
		c++;
	}
	RWLIST_UNLOCK(&cp->members);

	json_decref(json);
	bbs_debug(5, "Added %d user%s to channel %s\n", c, ESS(c), channelid);
}

static int load_channels(struct slack_relay *relay, int limit)
{
	char url[256];
	size_t index;
	json_t *json, *channels, *value;

	/* Get all the channels we're in (not all in the workspace): https://api.slack.com/methods/users.conversations */
	snprintf(url, sizeof(url), "https://slack.com/api/users.conversations?token=%s&exclude_archived=true&types=public_channel,private_channel", relay->token);
	json = slack_curl_get(relay, url);
	if (!json) {
		return -1;
	}

	channels = json_object_get(json, "channels");

	RWLIST_WRLOCK(&relay->users);
	json_array_foreach(channels, index, value) {
		const char *channelid = json_object_string_value(value, "id");
		const char *name = json_object_string_value(value, "name");
		const char *topic = json_object_string_value(json_object_get(value, "topic"), "value");
		struct chan_pair *cp = find_slack_channel(relay, channelid);
		if (!cp) {
			bbs_debug(6, "Ignoring out of scope channel %s (%s)\n", channelid, name);
			continue; /* This isn't a channel within scope of the relay */
		}
		bbs_mutex_lock(&cp->msglock);
		REPLACE(cp->name, name);
		REPLACE(cp->topic, topic);
		bbs_mutex_unlock(&cp->msglock);
		/* Load all the members of the channel, so we can later answer the question:
		 * If user U in channel C? (without having to make any API calls) */
		load_members(relay, cp, channelid, limit);
	}
	RWLIST_UNLOCK(&relay->users);

	json_decref(json);
	return 0;
}

static int load_presence(struct slack_relay *relay, int limit)
{
	struct slack_user *u;
	int c = 0;
	int res = 0;
	json_t *userids = json_array();
	if (!userids) {
		return -1;
	}

	RWLIST_RDLOCK(&relay->users);
	RWLIST_TRAVERSE(&relay->users, u, entry) {
		if (!u->shared) {
			continue; /* If we don't share any channels with this user, we don't care about his/her presence status */
		}
		if (++c >= limit) {
			bbs_warning("Maximum presence limit reached, results will be incomplete\n");
			break;
		}
		json_array_append_new(userids, json_string(u->userid));
	}
	RWLIST_UNLOCK(&relay->users);

	if (slack_users_presence_query(relay->slack, userids)) {
		bbs_warning("Failed to send presence query request\n");
		res = -1;
	} else if (slack_users_presence_subscribe(relay->slack, userids)) {
		bbs_warning("Failed to send presence subscribe request\n");
		res = -1;
	}
	json_decref(userids);
	return res;
}

static struct slack_user *slack_user_by_irc_username(const char *ircusername)
{
	struct slack_relay *relay;
	struct slack_user *u = NULL;

	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		RWLIST_RDLOCK(&relay->users);
		RWLIST_TRAVERSE(&relay->users, u, entry) {
			if (!strcmp(u->ircusername, ircusername)) {
				/* In a double loop, can't break */
				RWLIST_UNLOCK(&relay->users);
				RWLIST_UNLOCK(&relays);
				return u;
			}
		}
		RWLIST_UNLOCK(&relay->users);
	}
	RWLIST_UNLOCK(&relays);

	/* This operation is used when issuing a WHOIS.
	 * We should not try to lookup a user live if it doesn't exist,
	 * because it most likely doesn't. */

	return NULL;
}

static struct slack_user *slack_user_by_userid_locked(struct slack_relay *relay, const char *userid, int reorder)
{
	struct slack_user *u;
	int index = 0;

	/* Since some workspaces might have a lot of users,
	 * an optimization made here is we move the most recently used users to the front of the linked list,
	 * since they will probably be used again soon (e.g. currently active in a conversation)
	 * This should make this lookup operation amortized constant time for typical activity.
	 */
	RWLIST_TRAVERSE_SAFE_BEGIN(&relay->users, u, entry) {
		if (!strcmp(u->userid, userid)) {
			if (reorder && index > 4) { /* If it's not near the front, move it there. Allow some leeway so we're not constantly reordering. */
				RWLIST_REMOVE_CURRENT(entry);
				RWLIST_INSERT_HEAD(&relay->users, u, entry);
			}
			return u;
		}
		index++;
	}
	RWLIST_TRAVERSE_SAFE_END;

	/* Doesn't exist yet. Ask for this user, specifically.
	 * For large workspaces, we may never be able to store all users (nor should we try to). */
	u = load_user(relay, userid);

	if (!u) {
		bbs_warning("Couldn't fetch user for user ID %s\n", userid);
	}

	return u;
}

static struct slack_user *slack_user_by_userid(struct slack_relay *relay, const char *userid, int reorder)
{
	struct slack_user *u;
	RWLIST_WRLOCK(&relay->users);
	u = slack_user_by_userid_locked(relay, userid, reorder);
	RWLIST_UNLOCK(&relay->users);
	return u;
}

/*! \brief Get the channel ID for a direct message with a user */
static const char *slack_user_dm_id(struct slack_user *u)
{
	char cookies[512];
	char url[128];
	char postdata[128];
	json_t *json;
	const char *chan;
	json_error_t jansson_error = {};
	struct slack_relay *relay;
	struct bbs_curl c = {
		.url = url,
		.forcefail = 1,
		.postfields = postdata,
		.cookies = cookies,
	};

	if (u->dmchannel) {
		return u->dmchannel;
	}

	relay = u->relay;
	if (relay->cookie_ds) {
		snprintf(cookies, sizeof(cookies), "d=%s; d-s=%s", relay->cookie_d, relay->cookie_ds);
	} else {
		snprintf(cookies, sizeof(cookies), "d=%s", relay->cookie_d);
	}

	/* This API is really convoluted. For one, the reference and test pages contradict each other:
	 * https://api.slack.com/methods/conversations.open
	 * https://api.slack.com/methods/conversations.open/test
	 * Even though we make a POST response, the users argument still needs to be sent as a query parameter.
	 */
	snprintf(url, sizeof(url), "https://slack.com/api/conversations.open?users=%s", u->userid);
	snprintf(postdata, sizeof(postdata), "token=%s", relay->token);

	if (bbs_curl_post(&c)) {
		return NULL;
	}

	json = json_loads(c.response, 0, &jansson_error);
	if (!json) {
		bbs_warning("Failed to parse as JSON (line %d): %s\n", jansson_error.line, jansson_error.text);
		bbs_curl_free(&c);
		return NULL;
	}
	if (!json_object_bool_value(json, "ok")) {
		bbs_warning("Slack API request failed for user %s: %s\n", u->userid, c.response);
		bbs_curl_free(&c);
		json_decref(json);
		return NULL;
	}
	bbs_curl_free(&c);

	chan = json_object_string_value(json_object_get(json, "channel"), "id");
	if (!chan) {
		json_decref(json);
		return NULL;
	}

	bbs_mutex_lock(&u->lock);
	REPLACE(u->dmchannel, chan);
	bbs_mutex_unlock(&u->lock);
	json_decref(json);

	return u->dmchannel;
}

static struct slack_user *find_username_all_channels(const char *userid)
{
	struct slack_relay *r;

	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, r, entry) {
		struct slack_user *u;

		RWLIST_RDLOCK(&r->users);
		RWLIST_TRAVERSE(&r->users, u, entry) {
			if (!strcmp(u->userid, userid)) {
				RWLIST_UNLOCK(&r->users);
				RWLIST_UNLOCK(&relays);
				return u;
			}
		}
		RWLIST_UNLOCK(&r->users);
	}
	RWLIST_UNLOCK(&relays);
	return NULL;
}

static int substitute_mentions(const char *line, char *buf, size_t len)
{
	char *pos = buf;
	size_t left = len - 1;
	const char *start = NULL, *c = line;

	/* Need to substitute stuff like <@UA1BCDEF2> to @jsmith
	 * We don't substitute channels for a couple reasons:
	 * - They're more ambiguous, and do we use the Slack name or the IRC name?
	 * - Not everyone has access to all channels. Slack will mask a channel name
	 *   if a recipient of a message doesn't have access to it.
	 *   We can only send one thing to IRC, so decoding channel names
	 *   risks breaching privacy of the channel. */
	while (*c) {
		if (left <= 0) {
			bbs_warning("Buffer exhaustion when substituting nicks\n");
			buf[len - 1] = '\0';
			return -1;
		}
		if (!start && *c == '<' && *(c + 1) == '@' && *(c + 2) && strchr(c + 2, '>')) {
			start = c + 2;
		} else if (start && *c == '>') {
			/* User IDs are 9 characters (excluding the @ symbol) and start with U. */
			char userid[10];
			struct slack_user *u;

			safe_strncpy(userid, start, sizeof(userid));
			bbs_debug(3, "Searching for username to replace '%s'\n", userid);
			/* XXX This is not ideal,
			 * but since this callback function doesn't receive any private callback data,
			 * we don't know which relay this is for, so we have to search them all.
			 * This is still correct, since user IDs are unique across all workspaces,
			 * but it's not as efficient.
			 * To make this faster, we could have irc_relay_send_multiline accept private callback data
			 * (which would be the relay), and then just check the users in that relay here. */
			u = find_username_all_channels(userid);
			bbs_debug(5, "Substituted %s -> %s\n", userid, u ? u->username : "");
			if (u) {
				size_t bytes = (size_t) snprintf(pos, left, "@%s", u->username);
				pos += bytes;
				left -= bytes;
			} else {
				/* Couldn't resolve this, just keep it as was */
				size_t bytes = (size_t) (c - start + 1);
				if (bytes > left) {
					memcpy(pos, start, bytes);
					pos += bytes;
					left -= bytes;
				}
			}
			start = NULL;
		} else if (!start) {
			*pos++ = *c;
			left--;
		}
		c++;
	}
	*pos = '\0';
	return 0;
}

static int on_message(struct slack_event *event, const char *channel, const char *thread_ts, const char *ts, const char *user, const char *text)
{
	char dup[4000];
	char prefixed[4096];
	struct slack_user *u;
	const char *ircusername;
	struct slack_client *slack = slack_event_get_userdata(event);
	struct slack_relay *relay = slack_client_get_userdata(slack);
	const char *destination;

	UNUSED(ts);
	UNUSED(thread_ts);

	if (strlen_zero(text)) {
		bbs_debug(2, "Ignoring message with no text\n"); /* Probably just an attachment */
		return 0;
	}

	/* If it's a direct message, it doesn't need to have an explicit channel mapping,
	 * we'll try to deliver it to the associated (or addressed) user.
	 *
	 * Note that in Slack, only true DMs between two parties have the 'D' prefix.
	 * Multi-party DMs use the 'C' prefix, and these do need to be mapped to channels
	 * explicitly in mod_slack.conf for us to process them. */

	if (*channel == 'D') { /* Direct message */
		u = slack_user_by_userid(relay, user, 1);
		ircusername = u ? u->ircusername : user;
		if (u) {
			/* Don't echo something we just posted */
			bbs_mutex_lock(&u->lock);
			if (!strcmp(u->lastmsg, text)) {
				bbs_mutex_unlock(&u->lock);
				bbs_debug(4, "Not echoing our own direct message post...\n");
				return 0;
			}
			bbs_mutex_unlock(&u->lock);
		}
		if (relay->ircuser) {
			/* Relay direct messages directly to a specific user, if this is a personal relay.
			 * If it's not, then see if the message includes a username at the beginning.
			 * If not, then not really sure what we can do with this... */
			destination = relay->ircuser;
		} else {
			char *message, *recipient, *colon;
			safe_strncpy(dup, text, sizeof(dup));
			message = dup;
			recipient = strsep(&message, " ");
			destination = strsep(&message, " ");
			if (strlen_zero(recipient) || strlen_zero(message)) {
				bbs_debug(8, "Private message is not properly addressed, ignoring\n");
				/* Don't send an autoresponse saying "please use this messaging format", since there may be other consumers */
				return -1;
			}
			colon = strchr(recipient, ':');
			if (!colon) {
				return -1; /* Not a private message */
			}
			destination = recipient;
			text = message;
		}
		bbs_debug(6, "Relaying private message to %s\n", destination);
	} else {
		/* See if there are any mappings for this Slack channel */
		struct chan_pair *cp = find_slack_channel(relay, channel);
		if (!cp) {
			bbs_debug(5, "Ignoring message from Slack channel %s (no mapping for relay %p)\n", channel, relay);
			return 0;
		}
		u = slack_user_by_userid(relay, user, 1);
		ircusername = u ? u->ircusername : user;
		destination = cp->irc;
		/* We use a mutex that is separate from that
		 * used for serializing sent messages,
		 * since the process of sending a message
		 * can cause the on_message callback to be invoked.
		 * If we were to have locked cp->lock before sending
		 * and lock it again here, that will deadlock
		 * the sending thread until it gives up, at which
		 * point it will read the reply confirming the sent message
		 * only after we give up. */
		bbs_mutex_lock(&cp->msglock);
		if (!strcmp(cp->lastmsg, text)) { /* For most messages (except our own posts), this should be near constant time since they'll diverge quickly */
			bbs_mutex_unlock(&cp->msglock);
			bbs_debug(4, "Not echoing our own post...\n");
			return 0;
		}
		bbs_mutex_unlock(&cp->msglock);
		bbs_debug(4, "Relaying message from channel %s by %s (%s) to %s: %s\n", channel, user, ircusername, cp->irc, text);
	}

	/* XXX ircusername is not guaranteed to be unique in the workspace. Only user IDs are unique,
	 * no other attributes are. However, this is what will be most natural to use for the "IRC username".
	 * In most small workspaces, this should not pose an issue; however, if a collision occurs
	 * (and we don't check for this), then unexpected behavior may occur. */
	if (relay->prefixthread) {
		/* If this is the first message in a thread, just include the ts.
		 * If it's a reply to a message in a thread, prefix the ts with a '>',
		 * which allows recipients on IRC to distinguish replies from top-level messages. */
		const char *eff_ts = S_OR(thread_ts, ts);
		if (!strlen_zero(eff_ts)) {
			snprintf(prefixed, sizeof(prefixed), "%s%s: %s", thread_ts ? ">" : "", eff_ts, text);
			text = prefixed;
			/* Also keep track of the last active ts.
			 * on_message can only be called once per relay at a time since there's a single thread dispatching events,
			 * but multiple threads could try sending messages (using this variable) simultaneously,
			 * so this needs to be atomic with that. */
			bbs_mutex_lock(&relay->lock);
			safe_strncpy(relay->last_ts, eff_ts, sizeof(relay->last_ts));
			bbs_mutex_unlock(&relay->lock);
		}
	}
	irc_relay_send_multiline(destination, CHANNEL_USER_MODE_NONE, "Slack", ircusername, user, text, substitute_mentions, relay->ircuser);
	return 0;
}

static void process_presence_change(struct slack_relay *relay, const char *userid, int active)
{
	struct slack_user *u = slack_user_by_userid(relay, userid, 0); /* Do not reorder */
	if (!u) {
		/* Should never happen */
		bbs_warning("Got presence update for user %s we don't have?\n", userid);
		return;
	}
	bbs_debug(5, "Presence change: %s (%s) => %s\n", userid, u->ircusername, active ? "active" : "offline");
	SET_BITFIELD(u->active, active);
}

static int on_presence_change_multi(struct slack_event *event, json_t *userids, const char *presence)
{
	struct slack_client *slack = slack_event_get_userdata(event);
	struct slack_relay *relay = slack_client_get_userdata(slack);
	size_t index;
	json_t *value;

	/* There is only "active" and "away". So we only need the first 2 letters to differentiate. */
	if (!strncmp(presence, "ac", 2)) {
		json_array_foreach(userids, index, value) {
			const char *userid = json_string_value(value);
			process_presence_change(relay, userid, 1);
		}
	} else if (!strncmp(presence, "aw", 2)) {
		json_array_foreach(userids, index, value) {
			const char *userid = json_string_value(value);
			process_presence_change(relay, userid, 0);
		}
	} else {
		bbs_warning("Unexpected presence value: %s\n", presence);
	}
	return 0;
}

static int on_presence_change(struct slack_event *event, const char *userid, const char *presence)
{
	struct slack_client *slack = slack_event_get_userdata(event);
	struct slack_relay *relay = slack_client_get_userdata(slack);

	/* There is only "active" and "away". So we only need the first 2 letters to differentiate. */
	if (!strncmp(presence, "ac", 2)) {
		process_presence_change(relay, userid, 1);
	} else if (!strncmp(presence, "aw", 2)) {
		process_presence_change(relay, userid, 0);
	} else {
		bbs_warning("Unexpected presence value for %s: %s\n", userid, presence);
	}
	return 0;
}

static void notify_unauthorized(const char *sender, const char *channel, const char *ircuser)
{
	/* Right channel, wrong permissions */
	char notice[256];
	/* Could log to either the auth or warning levels... nothing is wrong with the system,
	 * this is just something possibly malicious. */
	bbs_warning("Dropped attempt by %s to access/post to %s, since this is a personal relay for %s\n", sender, channel, ircuser);
	/* Notify the sender, since someone could genuinely join a channel and think they're alone,
	 * and begin posting, because the NAMES reply came back empty.
	 * Privacy is preserved since the message is NOT relayed,
	 * but we need to notify the sender that this is somebody else's relay channel.
	 * Hopefully s/he will leave voluntarily, but if not, things are still good. */
	/* XXX Doesn't really make sense to send as the sender? But we don't have access to MessageServ here... */
	snprintf(notice, sizeof(notice), "You do not have permission to relay messages in %s", channel); /* Don't disclose who does, either */
	irc_relay_send_notice(sender, CHANNEL_USER_MODE_NONE, "Slack", sender, NULL, notice, NULL);
}

static void parse_parent_thread(struct slack_relay *relay, char *restrict ts, const char **restrict thread_ts, char const **restrict msg)
{
	const char *word2;
	long word1len, tsl;

	if (!relay->preservethreading || strlen_zero(*msg)) {
		/* Do nothing */
		return;
	}

	if (*(*msg) == '>') {
		(*msg)++;
		if (strlen_zero(*msg)) {
			return;
		}
		/* If it starts with >,
		 * that's short hand for "reply in thread in the last active thread" */
		bbs_mutex_lock(&relay->lock);
		if (!strlen_zero(relay->last_ts)) {
			safe_strncpy(ts, relay->last_ts, SLACK_TS_LENGTH + 2);
			bbs_mutex_unlock(&relay->lock);
			*thread_ts = ts;
			bbs_debug(5, "Replying to last active thread: %s\n", ts);
		} else {
			bbs_mutex_unlock(&relay->lock);
			bbs_debug(3, "No last ts on file, can't reply in thread\n");
			/* Just post a top level message */
		}
		return;
	}

	safe_strncpy(ts, *msg, SLACK_TS_LENGTH + 2);
	tsl = atol(ts); /* Parse timestamp, at least up until period */
	if (tsl <= 0) {
		return; /* Can't be a valid ts */
	}

	word2 = strchr(*msg, ' ');
	if (!word2) {
		return; /* Only one word? */
	}

	word1len = word2 - *msg;
	/* Accept ts rest of message and ts: rest of message */
	if (word1len != SLACK_TS_LENGTH && (word1len != SLACK_TS_LENGTH + 1 || *(*msg + SLACK_TS_LENGTH) != ':')) {
		bbs_debug(5, "Not prefixed with a ts after all\n");
		return; /* More afterwards, so can't be just a timestamp */
	}

	if (word1len == SLACK_TS_LENGTH + 1) {
		/* Ditch the trailing : */
		*(ts + SLACK_TS_LENGTH) = '\0';
	}

	/* Assume that it's a valid timestamp. */
	bbs_debug(7, "Message seems to be prefixed with a Slack ts (%s)\n", ts);
	*thread_ts = ts;
	*msg = word2 + 1;
}

static int slack_send(struct irc_relay_message *rmsg)
{
	char buf[532];
	char ts[SLACK_TS_LENGTH + 2];
	struct slack_relay *relay;
	const char *thread_ts = NULL;
	const char *channel = rmsg->channel;
	const char *sender = rmsg->sender;
	const char *msg = rmsg->msg;
	struct chan_pair *cp = find_irc_channel(channel);
	if (!cp) {
		return 0; /* No relay exists for this channel */
	}
	relay = cp->relay;

	if (sender && relay->ircuser && strcasecmp(relay->ircuser, sender)) {
		notify_unauthorized(sender, channel, relay->ircuser);
		return 0;
	}

	if (!sender) {
		if (!cp->used) { /* This is the first time anybody on IRC has joined the channel */
			if (!strlen_zero(cp->topic)) { /* The first time anybody joins, set the channel topic */
				cp->used = 1; /* Only need to do this once */
				/* XXX Note: Since anyone can join the channel, the channel topic may "leak" */
				irc_relay_set_topic(channel, cp->topic, relay->ircuser);
			}
		}
		if (!relay->relaysystem) {
			bbs_debug(3, "Dropping system-generated message since relaysystem=no\n");
			return 0;
		}
	}

	parse_parent_thread(relay, ts, &thread_ts, &msg);

	if (!relay->ircuser) {
		/* Many:many relay, identify the user */
		if (sender) {
			/* With Slack, it's *bold*, not **bold** - but we also need to format properly */
			snprintf(buf, sizeof(buf), "*&lt;%s&gt;* %s", sender, msg);
			msg = buf;
		}
	} /* else, it's a personal relay, don't prepend the IRC username */

	bbs_debug(4, "Relaying message to Slack channel %s: %s\n", channel, msg);

	/* Currently, we don't have a better way of preventing us from echoing our own messages back to ourself
	 * (we don't know our Slack user ID, and even if we did, this user could have posted a message
	 * from elsewhere, we don't necessarily know it came from IRC */

	bbs_mutex_lock(&cp->msglock);
	safe_strncpy(cp->lastmsg, msg, sizeof(cp->lastmsg));
	/* We have to unlock msglock before calling slack_channel_post...
	 * since that is not safe to hold. We instead use sendlock
	 * to ensure serialization of sent messages. */
	bbs_mutex_unlock(&cp->msglock);

	/* slack_channel_post_message is not threadsafe, so we surround it with the channel lock */
	bbs_mutex_lock(&cp->sendlock);
	if (slack_channel_post_message(relay->slack, cp->slack, thread_ts, msg)) {
		bbs_error("Failed to post message to channel %s\n", channel);
		relay->error = 1;
		bbs_mutex_unlock(&cp->sendlock);
		return 1;
	}
	bbs_mutex_unlock(&cp->sendlock);
	return 0;
}

static int privmsg(const char *recipient, const char *sender, const char *msg)
{
	char buf[532];
	char ts[SLACK_TS_LENGTH + 2];
	const char *dmchannel;
	struct slack_relay *relay;
	const char *thread_ts = NULL;
	struct slack_user *u = slack_user_by_irc_username(recipient);
	if (!u) {
		return 0;
	}

	dmchannel = slack_user_dm_id(u);
	if (!dmchannel) {
		bbs_warning("Unable to get DM channel for %s\n", u->userid);
		return -1; /* It exists, but we failed */
	}

	relay = u->relay;

	if (sender && relay->ircuser && strcasecmp(relay->ircuser, sender)) {
		notify_unauthorized(sender, recipient, relay->ircuser);
		return 0;
	}

	parse_parent_thread(relay, ts, &thread_ts, &msg);

	if (!relay->ircuser) {
		/* Many:many relay, identify the user */
		if (sender) {
			/* With Slack, it's *bold*, not **bold** - but we also need to format properly */
			snprintf(buf, sizeof(buf), "*&lt;%s&gt;* %s", sender, msg);
			msg = buf;
		}
	} /* else, it's a personal relay, don't prepend the IRC username */

	bbs_debug(4, "Relaying direct message to Slack channel %s: %s\n", dmchannel, msg);

	bbs_mutex_lock(&u->lock);
	safe_strncpy(u->lastmsg, msg, sizeof(u->lastmsg));
	bbs_mutex_unlock(&u->lock);

	/* slack_channel_post_message is not threadsafe, so we surround it with the channel lock normally;
	 * however, we don't have a cp for users, so use the relay lock. */
	bbs_mutex_lock(&relay->lock);
	if (slack_channel_post_message(relay->slack, dmchannel, thread_ts, msg)) {
		bbs_error("Failed to post message to channel %s\n", dmchannel);
		relay->error = 1;
		bbs_mutex_unlock(&relay->lock);
		return -1;
	}
	bbs_mutex_unlock(&relay->lock);
	return 1;
}

static int update_presence(struct slack_relay *relay, int away)
{
	char postdata[256] = "";
	json_t *json;

	/* https://docs.slack.dev/reference/methods/users.setPresence/ */
	snprintf(postdata, sizeof(postdata), "token=%s&presence=%s", relay->token, away ? "away" : "auto");

	json = slack_curl_post(relay, "https://slack.com/api/users.setPresence", postdata);
	if (!json) {
		return -1;
	}
	json_decref(json);
	return 0;
}

/* Not the most efficient approach, but it'll do for its rare usage */
static char *my_urlencode(const char *s)
{
	CURL *curl;
	char *encoded, *copy = NULL;

	curl = curl_easy_init();
	if (!curl) {
		return NULL;
	}
	encoded = curl_easy_escape(curl, s, (int) strlen(s));
	if (encoded) {
		copy = strdup(encoded);
		curl_free(encoded);
	}
	curl_easy_cleanup(curl);
	return copy;
}

static int update_status(struct slack_relay *relay, const char *msg)
{
	char postdata[512] = "";
	json_t *json, *profile;
	char *decoded, *encoded;

	profile = json_object();
	if (!profile) {
		return -1;
	}
	json_object_set_new(profile, "status_text", json_string(msg ? msg : ""));
	json_object_set_new(profile, "status_emoji",json_string("")); /* this is mandatory when clearing status, but not when setting it */
	json_object_set_new(profile, "status_expiration", json_integer(0));
	decoded = json_dumps(profile, 0);
	encoded = my_urlencode(decoded); /* Need to URL encode before including in POST body */
	json_decref(profile);

	/* https://docs.slack.dev/reference/methods/users.profile.set/ */
	snprintf(postdata, sizeof(postdata), "token=%s&profile=%s", relay->token, encoded);

	json = slack_curl_post(relay, "https://slack.com/api/users.profile.set", postdata);
	if (!json) {
		return -1;
	}
	json_decref(json);
	return 0;
}

static int set_status(struct slack_relay *relay, const char *msg)
{
	/* If desired, separately update the status on Slack with the away message */
	if (relay->relaystatus) {
		if (update_status(relay, msg)) {
			bbs_warning("Failed to set status for Slack relay %s to '%s'\n", relay->name, S_IF(msg));
			return -1;
		} else {
			bbs_debug(4, "Set status for Slack relay %s to '%s'\n", relay->name, S_IF(msg));
			return 0;
		}
	}
	return 1;
}

static int away_cb(const char *username, enum irc_user_status userstatus, const char *msg)
{
	struct slack_relay *relay;

	UNUSED(userstatus);

	/* As with mod_irc_relay, there could be multiple Slack workspaces,
	 * so we need to iterate over relays to find all matches. */
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		if (!relay->relayaway) {
			continue;
		}
		if (strlen_zero(relay->ircuser)) {
			continue;
		}
		if (strcasecmp(relay->ircuser, username)) {
			continue;
		}

		if (update_presence(relay, msg ? 1 : 0)) {
			bbs_warning("Failed to set presence for Slack relay %s to %s\n", relay->name, msg ? "away" : "auto");
		} else {
			bbs_debug(4, "Set presence for Slack relay %s to %s\n", relay->name, msg ? "away" : "auto");
		}
		set_status(relay, msg);
	}
	RWLIST_UNLOCK(&relays);

	return 0;
}

/* Similar to away_cb, but called whenever the module loads (typically at startup)
 * to automatically mark as AWAY any users that are not currently online.
 * This way, we don't need to wait for a user to explicitly use the AWAY command
 * for the remote network to accurately reflect whether user is away or not. */
static int autoaway(void)
{
	struct slack_relay *relay;

	/* We don't update status at this time, just presence */
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		int inactive;
		if (!relay->relayaway) {
			continue;
		}
		if (strlen_zero(relay->ircuser)) {
			continue;
		}
		inactive = irc_user_inactive(relay->ircuser);
		if (update_presence(relay, inactive)) {
			bbs_warning("Failed to set presence for Slack relay %s to away\n", relay->name);
		} else {
			bbs_debug(4, "Set presence for Slack relay %s to away (%s not currently active on IRC)\n", relay->name, relay->ircuser);
			/* If active, also clear status */
			if (!inactive) {
				set_status(relay, NULL);
			}
		}
	}
	RWLIST_UNLOCK(&relays);
	return 0;
}

static int channel_contains_user(struct chan_pair *cp, struct slack_user *u)
{
	struct member *m;
	RWLIST_RDLOCK(&cp->members);
	RWLIST_TRAVERSE(&cp->members, m, entry) {
		if (m->u == u) {
			break;
		}
	}
	RWLIST_UNLOCK(&cp->members);
	return m ? 1 : 0;
}

static void dump_user(struct bbs_node *node, int fd, const char *requsername, struct slack_user *u)
{
	irc_relay_who_response(node, fd, "Slack", requsername, u->ircusername, u->userid, u->active);
}

/*!
 * \param fd
 * \param numeric: 318 = WHOIS, 352 = WHO, 353 = NAMES
 * \param requsername
 * \param channel
 * \param user
 */
static int nicklist(struct bbs_node *node, int fd, int numeric, const char *requsername, const char *channel, const char *user)
{
	if (!expose_members) {
		bbs_debug(5, "Ignoring since exposemembers=no\n");
		return 0;
	} else if (channel && (numeric == 352 || numeric == 353)) { /* WHO or NAMES */
		char buf[500];
		int len = 0;
		struct slack_user *u;
		struct slack_relay *relay;
		struct chan_pair *cp = find_irc_channel(channel);
		if (!cp) {
			/* No relay exists for this channel */
			return 0;
		}

		relay = cp->relay;
		if (relay->ircuser && strcasecmp(relay->ircuser, requsername)) {
			notify_unauthorized(requsername, channel, relay->ircuser);
			return 0;
		}

		RWLIST_RDLOCK(&relay->users);
		RWLIST_TRAVERSE(&relay->users, u, entry) {
			if (!channel_contains_user(cp, u)) {
				continue; /* User not in this channel */
			}
			if (numeric == 352) {
				dump_user(node, fd, requsername, u); /* Include in WHO response */
			} else if (numeric == 353) {
				len += snprintf(buf + len, sizeof(buf) - (size_t) len, "%s%s", len ? " " : "", u->ircusername);
				if (len >= 400) { /* Stop well short of the 512 character message limit and clear the buffer */
					len = 0;
					irc_relay_names_response(node, fd, requsername, cp->irc, buf);
				}
			}
		}
		RWLIST_UNLOCK(&relay->users);
		if (len > 0) {
			irc_relay_names_response(node, fd, requsername, cp->irc, buf); /* Last one */
		}
		return 0; /* Other modules could contain matches as well */
	} else if (user && (numeric == 353 || numeric == 318)) { /* Only for WHO and WHOIS, not NAMES */
		struct slack_relay *relay;
		struct slack_user *u = slack_user_by_irc_username(user);
		if (!u) {
			bbs_debug(7, "No such user: %s\n", user);
			return 0;
		}

		relay = u->relay;
		if (relay->ircuser && strcasecmp(relay->ircuser, requsername)) {
			notify_unauthorized(requsername, channel, relay->ircuser);
			return 0;
		}

		if (numeric == 353) {
			dump_user(node, fd, requsername, u);
		} else if (numeric == 318) {
			irc_relay_numeric_response(node, fd, 311, "%s %s %s %s * :%s", requsername, u->ircusername, u->ircusername, u->ircusername, u->userid);
			irc_relay_numeric_response(node, fd, 312, "%s %s %s :%s", requsername, u->ircusername, "Slack", u->relay->name);
			if (!u->active && u->status) {
				/* IRC doesn't have a generic "status message", users can only set if they're /away
				 * But if the user is away and has a status message, no reason not to send that!
				 * (Especially since these *are* often used as "away" messages. */
				irc_relay_numeric_response(node, fd, 301, "%s %s :%s", requsername, u->ircusername, u->status);
			}
		}
		return 1; /* Success, stop traversal, since only one module will have a match, and it's us. */
	}
	return 0;
}

static int cli_slack_relays(struct bbs_cli_args *a)
{
	int i = 0;
	struct slack_relay *r;

	bbs_dprintf(a->fdout, "%-20s %6s %18s %13s (%s)\n", "Name", "Status", "Preserve Threading", "Prefix Thread", "IRC User (Private Relay)");
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, r, entry) {
		bbs_dprintf(a->fdout, "%-20s %6s %18s %13s %s\n", r->name, r->error ? "Error" : "Normal", BBS_YN(r->preservethreading), BBS_YN(r->prefixthread), S_IF(r->ircuser));
		i++;
	}
	RWLIST_UNLOCK(&relays);
	bbs_dprintf(a->fdout, "%d relay%s\n", i, ESS(i));
	return 0;
}

static int cli_slack_channels(struct bbs_cli_args *a)
{
	int i = 0;
	int match = 0;
	struct slack_relay *r;

	bbs_dprintf(a->fdout, "%-20s %-30s %-20s %s\n", "Slack Channel ID", "Slack Channel Name", "IRC Channel", "Status");
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, r, entry) {
		struct chan_pair *cp;

		RWLIST_RDLOCK(&r->mappings);
		RWLIST_TRAVERSE(&r->mappings, cp, entry) {
			i++;
			/* This check could be done in the outer loop, if we didn't want to count all the channels. */
			if (a->argc == 3 && strcasecmp(r->name, a->argv[2])) { /* Optional relay filter */
				continue;
			}
			bbs_dprintf(a->fdout, "%-20s %-30s %-20s %s\n", cp->slack, S_IF(cp->name), cp->irc, r->error ? "Error" : "Normal");
			match++;
		}
		RWLIST_UNLOCK(&r->mappings);
	}
	RWLIST_UNLOCK(&relays);
	bbs_dprintf(a->fdout, "%d/%d relay%s\n", match, i, ESS(i));
	return 0;
}

static int cli_slack_users(struct bbs_cli_args *a)
{
	int i = 0, active = 0;
	int match = 0;
	struct slack_relay *r;

	bbs_dprintf(a->fdout, "%-20s %1s %-30s %-20s\n", "Slack User ID", "A", "Slack Username", "Slack Real Name");
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, r, entry) {
		struct slack_user *u;

		RWLIST_RDLOCK(&r->users);
		RWLIST_TRAVERSE(&r->users, u, entry) {
			i++;
			/* This check could be done in the outer loop, if we didn't want to count all the users. */
			if (a->argc == 3 && strcasecmp(r->name, a->argv[2])) { /* Optional relay filter */
				continue;
			}
			bbs_dprintf(a->fdout, "%-20s %1s %-30s %-20s\n", u->userid, u->active ? "*" : "", u->username, u->realname);
			if (u->active) {
				active++;
			}
			match++;
		}
		RWLIST_UNLOCK(&r->users);
	}
	RWLIST_UNLOCK(&relays);
	bbs_dprintf(a->fdout, "%d/%d user%s (%d active)\n", match, i, ESS(i), active);
	return 0;
}

static int cli_slack_members(struct bbs_cli_args *a)
{
	int i = 0;
	struct slack_relay *r;

	bbs_dprintf(a->fdout, "%-20s %-30s %-20s\n", "Slack Channel ID", "Slack Channel Name", "IRC Channel");
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, r, entry) {
		struct chan_pair *cp;
		RWLIST_RDLOCK(&r->mappings);
		RWLIST_TRAVERSE(&r->mappings, cp, entry) {
			struct member *m;
			if (strcmp(cp->slack, a->argv[2])) {
				continue;
			}
			RWLIST_TRAVERSE(&cp->members, m, entry) {
				struct slack_user *u = m->u;
				bbs_dprintf(a->fdout, "%-20s %1s %-30s %-20s\n", u->userid, u->active ? "*" : "", u->username, u->realname);
				i++;
			}
		}
		RWLIST_UNLOCK(&r->mappings);
	}
	RWLIST_UNLOCK(&relays);
	bbs_dprintf(a->fdout, "%d member%s\n", i, ESS(i));
	return 0;
}

static int cli_slack_debug(struct bbs_cli_args *a)
{
	int level = atoi(a->argv[2]);
	if (level < 0) {
		level = 0;
	}
	slack_set_log_level(level);
	bbs_dprintf(a->fdout, "Set libslackrtm debug level to %d\n", level);
	return 0;
}

static struct bbs_cli_entry cli_commands_slack[] = {
	BBS_CLI_COMMAND(cli_slack_relays, "slack relays", 2, "List all Slack relays", NULL),
	BBS_CLI_COMMAND(cli_slack_channels, "slack chans", 2, "List Slack channels", "slack chans [<relay>]"),
	BBS_CLI_COMMAND(cli_slack_users, "slack users", 2, "List Slack users", "slack users [<relay>]"),
	BBS_CLI_COMMAND(cli_slack_members, "slack members", 3, "List a Slack channel's members", "slack members <channel>"),
	BBS_CLI_COMMAND(cli_slack_debug, "slack debug", 3, "Set Slack library debug level", "slack debug <level> [0=none,1=fatal,2=error,3=warning,4=notice,5+=debug]"),
};

struct slack_callbacks slack_callbacks = {
	.message = on_message,
	.message_changed = on_message, /* Treat edited message the same as a new message */
	.presence_change = on_presence_change,
	.presence_change_multi = on_presence_change_multi,
};

static void slack_log(int level, int len, const char *file, const char *function, int line, const char *buf)
{
	switch (level) {
		case SLACK_LOG_FATAL:
		case SLACK_LOG_ERROR:
			__bbs_log(LOG_ERROR, 0, file, line, function, "%.*s", len, buf);
			break;
		case SLACK_LOG_WARNING:
			__bbs_log(LOG_WARNING, 0, file, line, function, "%.*s", len, buf);
			break;
		case SLACK_LOG_DEBUG:
		default: /* Debug consists of multiple levels */
			__bbs_log(LOG_DEBUG, level - SLACK_LOG_DEBUG, file, line, function, "%.*s", len, buf);
	}
}

#define SLACK_REQUEST_USER_LIMIT 500

static void *slack_relay_run(void *varg)
{
	int res;
	struct slack_relay *relay = varg;
	struct slack_client *slack = relay->slack;

	/* Connect to Slack */
	if (slack_client_connect(slack)) {
		bbs_error("Slack client connection failed for relay %s\n", relay->name);
		return NULL;
	}

	slack_client_set_autoreconnect(slack, 1); /* Enable autoreconnect since this is supposed to be a long lived relay */
	res = load_users(relay, SLACK_REQUEST_USER_LIMIT); /* Load all users (or at least as many as we can) in advance */
	if (res) {
		bbs_error("Failed to load users\n");
	}
	if (!res && strlen_zero(relay->enterpriseid)) { /* This API fails for enterprise workspaces, so skip it for those */
		res = load_channels(relay, SLACK_REQUEST_USER_LIMIT); /* Load channels next, which will also load members (which is why we do load_users first) */
		if (res) {
			bbs_error("Failed to load channels\n");
		}
	}
	if (!res) {
		res = load_presence(relay, SLACK_REQUEST_USER_LIMIT); /* Finally, load presence, for all users that share channels with us */
		if (res) {
			bbs_error("Failed to load presences\n");
		}
	}
	if (!res) {
		relay->started = 1;
		slack_event_loop(slack, &slack_callbacks); /* Run event loop */
	} else {
		bbs_error("Failed to set up Slack relay %s\n", relay->name);
		relay->error = 1;
	}
	return NULL;
}

static int start_clients(void)
{
	struct slack_relay *relay;
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		if (bbs_pthread_create(&relay->thread, NULL, slack_relay_run, relay)) {
			bbs_warning("Failed to start Slack relay %s\n", relay->name);
		}
	}
	RWLIST_UNLOCK(&relays);
	return 0;
}

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct slack_relay *relay = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_slack.conf", 1);

	if (!cfg) {
		bbs_error("File 'mod_slack.conf' is missing, declining to load\n");
		return -1;
	}

	bbs_config_val_set_true(cfg, "slack", "exposemembers", &expose_members);

	RWLIST_WRLOCK(&relays);
	while ((section = bbs_config_walk(cfg, section))) {
		const char *type;
		const char *token = NULL, *gwserver = NULL, *cookie_d = NULL; /* Required */
		const char *enterpriseid = NULL, *cookie_ds = NULL; /* Optional (enterprises only) */
		unsigned int relaysystem = 0, relayaway = 0, relaystatus = 0;
		const char *ircuser = NULL;
		const char *mapname = NULL;
		struct slack_client *slack;
		int preservethreading = 0, prefixthread = 0;
		size_t namelen, tokenlen = 0, gwserverlen = 0, cookie_d_len = 0, entlen = 0, cookie_ds_len = 0, ircuserlen = 0;
		size_t datalen;
		char *data;
		struct bbs_config_section *mapsect;

		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Not a channel mapping section, skip */
		}

		/* Category name is not relevant, only the contents. */
		type = bbs_config_sect_val(section, "type");
		if (strlen_zero(type)) {
			bbs_error("Config section %s missing type\n", bbs_config_section_name(section));
			continue;
		}

		if (strcmp(type, "relay")) {
			continue;
		}

		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcasecmp(key, "token")) {
				token = value;
				tokenlen = strlen(value) + 1;
			} else if (!strcasecmp(key, "gwserver")) {
				gwserver = value;
				gwserverlen = strlen(value) + 1;
			} else if (!strcasecmp(key, "cookie_d")) {
				cookie_d = value;
				cookie_d_len = strlen(value) + 1;
			} else if (!strcasecmp(key, "enterpriseid")) {
				enterpriseid = value;
				entlen = strlen(value) + 1;
			} else if (!strcasecmp(key, "cookie_ds")) {
				cookie_ds = value;
				cookie_ds_len = strlen(value) + 1;
			} else if (!strcasecmp(key, "relaysystem")) {
				relaysystem = S_TRUE(value);
			} else if (!strcasecmp(key, "relayaway")) {
				relayaway = S_TRUE(value);
			} else if (!strcasecmp(key, "relaystatus")) {
				relaystatus = S_TRUE(value);
			} else if (!strcasecmp(key, "ircuser")) {
				ircuser = value;
				ircuserlen = strlen(ircuser) + 1;
			} else if (!strcasecmp(key, "mapping")) {
				mapname = value;
			} else if (!strcasecmp(key, "preservethreading")) {
				preservethreading = S_TRUE(value);
			} else if (!strcasecmp(key, "prefixthread")) {
				prefixthread = S_TRUE(value);
			} else if (!strcasecmp(key, "type")) { /* We know it's type=relay */
				continue;
			} else {
				bbs_warning("Unknown directive: %s\n", key);
			}
		}
		if (!token || !gwserver || !cookie_d) {
			bbs_warning("Section %s is incomplete, ignoring\n", bbs_config_section_name(section));
			continue;
		} else if (!mapname) {
			bbs_warning("Section %s missing mapping, ignoring\n", bbs_config_section_name(section));
			continue;
		}

		/* Ensure mappings exist before we allocate anything */
		mapsect = bbs_config_section_get(cfg, mapname);
		if (!mapsect) {
			bbs_warning("Map section '%s' does not exist\n", mapname);
			continue;
		} else if (!bbs_config_section_walk(mapsect, keyval)) {
			bbs_warning("Map section '%s' is empty\n", mapname);
			continue; /* If it's empty, nothing will be relayed, so what's the point in setting one up? */
		}

		namelen = strlen(bbs_config_section_name(section)) + 1;
		datalen = namelen + tokenlen + gwserverlen + cookie_d_len + entlen + cookie_ds_len + ircuserlen;
		relay = calloc(1, sizeof(*relay) + datalen);
		if (ALLOC_FAILURE(relay)) {
			continue;
		}
		bbs_mutex_init(&relay->lock, NULL);
		SET_BITFIELD(relay->relaysystem, relaysystem);
		SET_BITFIELD(relay->relayaway, relayaway);
		SET_BITFIELD(relay->relaystatus, relaystatus);
		SET_BITFIELD(relay->prefixthread, prefixthread);
		SET_BITFIELD(relay->preservethreading, preservethreading);
		data = relay->data;

		SET_FSM_STRING_VAR(relay, data, name, bbs_config_section_name(section), namelen);
		SET_FSM_STRING_VAR(relay, data, token, token, tokenlen);
		SET_FSM_STRING_VAR(relay, data, gwserver, gwserver, gwserverlen);
		SET_FSM_STRING_VAR(relay, data, cookie_d, cookie_d, cookie_d_len);
		SET_FSM_STRING_VAR(relay, data, enterpriseid, enterpriseid, entlen);
		SET_FSM_STRING_VAR(relay, data, cookie_ds, cookie_ds, cookie_ds_len);
		SET_FSM_STRING_VAR(relay, data, ircuser, ircuser, ircuserlen);

		RWLIST_HEAD_INIT(&relay->mappings);
		RWLIST_HEAD_INIT(&relay->users);

		RWLIST_WRLOCK(&relay->mappings);
		while ((keyval = bbs_config_section_walk(mapsect, keyval))) {
			const char *slackchanid = bbs_keyval_key(keyval);
			const char *ircchanname = bbs_keyval_val(keyval);
			size_t slacklen, irclen;
			struct chan_pair *cp;

			if (!strcasecmp(slackchanid, "type") && !strcasecmp(ircchanname, "mapping")) {
				/* Don't include type=mapping, that's not a mapping */
				continue;
			}

			slacklen = strlen(slackchanid) + 1;
			irclen = strlen(ircchanname) + 1;
			cp = calloc(1, sizeof(*cp) + slacklen + irclen);
			if (ALLOC_FAILURE(cp)) {
				continue;
			}
			data = cp->data;
			SET_FSM_STRING_VAR(cp, data, slack, slackchanid, slacklen);
			SET_FSM_STRING_VAR(cp, data, irc, ircchanname, irclen);
			cp->relay = relay;
			bbs_mutex_init(&cp->msglock, NULL);
			bbs_mutex_init(&cp->sendlock, NULL);
			RWLIST_HEAD_INIT(&cp->members);
			RWLIST_INSERT_TAIL(&relay->mappings, cp, entry);
		}
		RWLIST_UNLOCK(&relay->mappings);

		slack = slack_client_new(relay);
		if (!slack) {
			relay_free(relay);
			continue;
		}

		slack_client_set_token(slack, token);
		slack_client_set_gateway_server(slack, gwserver);
		slack_client_set_cookie(slack, "d", cookie_d);

		/* If these are NULL, it doesn't hurt anything */
		slack_client_set_enterprise_id(slack, enterpriseid);
		slack_client_set_cookie(slack, "d-s", cookie_ds);

		relay->slack = slack;
		if (!slack_client_connect_possible(slack)) {
			bbs_warning("Slack relay '%s' missing required information, ignoring\n", bbs_config_section_name(section));
			relay_free(relay);
			continue;
		}
		RWLIST_INSERT_HEAD(&relays, relay, entry);
	}
	RWLIST_UNLOCK(&relays);

	/* Actually launch each relay in its own thread */
	bbs_config_unlock(cfg);
	bbs_run_when_started(start_clients, STARTUP_PRIORITY_DEPENDENT);
	return 0;
}

struct irc_relay_callbacks relay_callbacks = {
	.relay_send = slack_send,
	.nicklist = nicklist,
	.privmsg = privmsg,
	.away = away_cb,
};

static int load_module(void)
{
	/* Initialize the library */
	slack_set_log_level(SLACK_LOG_WARNING); /* Show up to warnings by default */
	slack_set_logger(slack_log);

	/* Don't enable debug logging by default, but CLI command can be used to enable, if desired */

	if (load_config()) {
		return -1;
	}

	irc_relay_register(&relay_callbacks);
	bbs_cli_register_multiple(cli_commands_slack);
	bbs_run_when_started(autoaway, STARTUP_PRIORITY_DEPENDENT + 1); /* mod_irc_client uses STARTUP_PRIORITY_DEPENDENT priority */
	return 0;
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_slack);
	irc_relay_unregister(&relay_callbacks);
	RWLIST_WRLOCK_REMOVE_ALL(&relays, entry, relay_free);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("Slack/IRC Relay", "net_irc.so,mod_curl.so");
