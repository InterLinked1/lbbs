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

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/module.h"
#include "include/utils.h"
#include "include/node.h" /* use bbs_hostname */
#include "include/startup.h"
#include "include/curl.h"

#include "include/json.h"

/* Needed for presence query/subscribe commands. Requires jansson support, so must come after json.h include. */
#define SLACK_EXPOSE_JSON

/* libslackrtm: https://github.com/InterLinked1/slack-rtm */
#include <slackrtm/slack.h>
#include <slackrtm/slack-client.h>

#define SEMVER_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

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
	pthread_mutex_t lock;
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
	pthread_mutex_t lock;
	char *name;			/*!< Actual Slack channel name */
	char *topic;		/*!< Slack channel topic */
	struct members members;	/*!< Members of channel (may be incomplete, in large workspaces) */
	unsigned int used:1;	/*!< Whether this channel has been accessed/used */
	char lastmsg[512];
	char data[];
};

RWLIST_HEAD(chan_pairs, chan_pair);

struct slack_relay {
	RWLIST_ENTRY(slack_relay) entry;
	struct slack_client *slack;
	unsigned int relaysystem:1;
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
	char data[];
};

static RWLIST_HEAD_STATIC(relays, slack_relay);

static void cp_free(struct chan_pair *cp)
{
	RWLIST_WRLOCK_REMOVE_ALL(&cp->members, entry, free);
	free_if(cp->topic);
	pthread_mutex_destroy(&cp->lock);
	free(cp);
}

static void slack_user_free(struct slack_user *u)
{
	free_if(u->status);
	free_if(u->dmchannel);
	pthread_mutex_destroy(&u->lock);
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

/*!
 * \brief Fill in the appropriate bytes of a flexible struct member for a constant string
 * \param var struct
 * \param dataptr A pointer that is initialized (before any calls to this macro) to the flexible struct member
 * \param field The name of the struct field to set.
 * \param name The name of the field and the name of the variable to copy (must be named the same). Variable must not be uninitialized.
 * \param len The number of bytes required to store this variable (strlen + 1)
 */
#define SET_FSM_STRING_VAR(var, dataptr, field, name, len) \
		if (!strlen_zero(name)) { \
			strcpy(dataptr, name); \
			var->field = dataptr; \
			dataptr += len; \
		}

/*! \brief Get number of bytes needed to store a string */
#define STRING_ALLOC_SIZE(s) (!strlen_zero(s) ? strlen(s) + 1 : 0)

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
	pthread_mutex_init(&user->lock, NULL);
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

static void load_users(struct slack_relay *relay, int limit)
{
	char url[256];
	size_t index;
	json_t *json, *members, *value;

	snprintf(url, sizeof(url), "https://slack.com/api/users.list?token=%s&limit=%d", relay->token, limit);
	json = slack_curl_get(relay, url);
	if (!json) {
		return;
	}

	RWLIST_WRLOCK(&relay->users);
	members = json_object_get(json, "members");
	json_array_foreach(members, index, value) {
		load_single_user(relay, value, json_object_string_value(value, "id"));
	}
	RWLIST_UNLOCK(&relay->users);

	json_decref(json);
}

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
		struct slack_user *u = load_user(relay, userid);
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

static void load_channels(struct slack_relay *relay, int limit)
{
	char url[256];
	size_t index;
	json_t *json, *channels, *value;

	/* Get all the channels we're in (not all in the workspace): https://api.slack.com/methods/users.conversations */
	snprintf(url, sizeof(url), "https://slack.com/api/users.conversations?token=%s&exclude_archived=true&types=public_channel,private_channel", relay->token);
	json = slack_curl_get(relay, url);
	if (!json) {
		return;
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
		pthread_mutex_lock(&cp->lock);
		REPLACE(cp->name, name);
		REPLACE(cp->topic, topic);
		pthread_mutex_unlock(&cp->lock);
		/* Load all the members of the channel, so we can later answer the question:
		 * If user U in channel C? (without having to make any API calls) */
		load_members(relay, cp, channelid, limit);
	}
	RWLIST_UNLOCK(&relay->users);

	json_decref(json);
}

static void load_presence(struct slack_relay *relay, int limit)
{
	struct slack_user *u;
	int c = 0;
	json_t *userids = json_array();
	if (!userids) {
		return;
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
	} else if (slack_users_presence_subscribe(relay->slack, userids)) {
		bbs_warning("Failed to send presence subscribe request\n");
	}
	json_decref(userids);
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

static struct slack_user *slack_user_by_userid(struct slack_relay *relay, const char *userid, int reorder)
{
	struct slack_user *u;
	int index = 0;

	/* Since some workspaces might have a lot of users,
	 * an optimization made here is we move the most recently used users to the front of the linked list,
	 * since they will probably be used again soon (e.g. currently active in a conversation)
	 * This should make this lookup operation amortized constant time for typical activity.
	 */
	RWLIST_WRLOCK(&relay->users);
	RWLIST_TRAVERSE_SAFE_BEGIN(&relay->users, u, entry) {
		if (!strcmp(u->userid, userid)) {
			if (reorder && index > 4) { /* If it's not near the front, move it there. Allow some leeway so we're not constantly reordering. */
				RWLIST_REMOVE_CURRENT(entry);
				RWLIST_INSERT_HEAD(&relay->users, u, entry);
			}
			RWLIST_UNLOCK(&relay->users);
			return u;
		}
		index++;
	}
	RWLIST_TRAVERSE_SAFE_END;

	/* Doesn't exist yet. Ask for this user, specifically.
	 * For large workspaces, we may never be able to store all users (nor should we try to). */
	u = load_user(relay, userid);
	RWLIST_UNLOCK(&relay->users);

	if (!u) {
		bbs_warning("Couldn't fetch user for user ID %s\n", userid);
	}

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

	pthread_mutex_lock(&u->lock);
	REPLACE(u->dmchannel, chan);
	pthread_mutex_unlock(&u->lock);
	json_decref(json);

	return u->dmchannel;
}

static int on_message(struct slack_event *event, const char *channel, const char *thread_ts, const char *ts, const char *user, const char *text)
{
	char dup[4000];
	struct slack_user *u;
	const char *ircusername;
	struct slack_client *slack = slack_event_get_userdata(event);
	struct slack_relay *relay = slack_client_get_userdata(slack);
	struct chan_pair *cp;
	const char *destination;

	UNUSED(ts);
	UNUSED(thread_ts);

	if (strlen_zero(text)) {
		bbs_debug(2, "Ignoring message with no text\n"); /* Probably just an attachment */
		return 0;
	}

	/* See if there are any mappings for this Slack channel */
	cp = find_slack_channel(relay, channel);

	if (!cp) {
		bbs_debug(5, "Ignoring message from Slack channel %s (no mapping for relay %p)\n", channel, relay);
		return 0;
	}

	u = slack_user_by_userid(relay, user, 1);
	ircusername = u ? u->ircusername : user;

	destination = cp->irc;

	/* Don't echo something we just posted */
	if (*channel == 'D') { /* Direct message */
		pthread_mutex_lock(&u->lock);
		if (!strcmp(u->lastmsg, text)) {
			pthread_mutex_unlock(&cp->lock);
			bbs_debug(4, "Not echoing our own direct message post...\n");
			return 0;
		}
		pthread_mutex_unlock(&u->lock);
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
	} else {
		pthread_mutex_lock(&cp->lock);
		if (!strcmp(cp->lastmsg, text)) { /* For most messages (except our own posts), this should be near constant time since they'll diverge quickly */
			pthread_mutex_unlock(&cp->lock);
			bbs_debug(4, "Not echoing our own post...\n");
			return 0;
		}
		pthread_mutex_unlock(&cp->lock);
	}

	bbs_debug(4, "Relaying message from channel %s by %s (%s) to %s: %s\n", channel, user, ircusername, cp->irc, text);

	/* XXX ircusername is not guaranteed to be unique in the workspace. Only user IDs are unique,
	 * no other attributes are. However, this is what will be most natural to use for the "IRC username".
	 * In most small workspaces, this should not pose an issue; however, if a collision occurs
	 * (and we don't check for this), then unexpected behavior may occur. */
	irc_relay_send_multiline(destination, CHANNEL_USER_MODE_NONE, "Slack", ircusername, user, text, NULL, relay->ircuser);
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

static int slack_send(const char *channel, const char *sender, const char *msg)
{
	char buf[532];
	struct slack_relay *relay;
	struct chan_pair *cp = find_irc_channel(channel);
	if (!cp) {
		return 0; /* No relay exists for this channel */
	}
	relay = cp->relay;

	if (sender && relay->ircuser && strcmp(relay->ircuser, sender)) {
		notify_unauthorized(sender, channel, relay->ircuser);
		return 0;
	}

	if (!sender) {
		if (!cp->used) { /* This is the first time anybody on IRC has joined the channel */
			if (!strlen_zero(cp->topic)) { /* The first time anybody joins, set the channel topic */
				cp->used = 1; /* Only need to do this once */
				/* XXX Note: Since anyone can join the channel, the channel topic may "leak" */
				irc_relay_set_topic(channel, cp->topic);
			}
		}
		if (!relay->relaysystem) {
			bbs_debug(3, "Dropping system-generated message since relaysystem=no\n");
			return 0;
		}
	}

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
	pthread_mutex_lock(&cp->lock);
	safe_strncpy(cp->lastmsg, msg, sizeof(cp->lastmsg));
	pthread_mutex_unlock(&cp->lock);

	if (slack_channel_post_message(relay->slack, cp->slack, NULL, msg)) {
		bbs_error("Failed to post message to channel %s\n", channel);
	}
	return 0;
}

static int privmsg(const char *recipient, const char *sender, const char *msg)
{
	char buf[532];
	const char *dmchannel;
	struct slack_relay *relay;
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

	if (sender && relay->ircuser && strcmp(relay->ircuser, sender)) {
		notify_unauthorized(sender, recipient, relay->ircuser);
		return 0;
	}

	if (!relay->ircuser) {
		/* Many:many relay, identify the user */
		if (sender) {
			/* With Slack, it's *bold*, not **bold** - but we also need to format properly */
			snprintf(buf, sizeof(buf), "*&lt;%s&gt;* %s", sender, msg);
			msg = buf;
		}
	} /* else, it's a personal relay, don't prepend the IRC username */

	bbs_debug(4, "Relaying direct message to Slack channel %s: %s\n", dmchannel, msg);

	pthread_mutex_lock(&u->lock);
	safe_strncpy(u->lastmsg, msg, sizeof(u->lastmsg));
	pthread_mutex_unlock(&u->lock);

	if (slack_channel_post_message(relay->slack, dmchannel, NULL, msg)) {
		bbs_error("Failed to post message to channel %s\n", dmchannel);
	}
	return 1;
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

static void dump_user(int fd, const char *requsername, struct slack_user *u)
{
	irc_relay_who_response(fd, "Slack", requsername, u->ircusername, u->userid, u->active);
}

/*!
 * \param fd
 * \param numeric: 318 = WHOIS, 352 = WHO, 353 = NAMES
 * \param requsername
 * \param channel
 * \param user
 */
static int nicklist(int fd, int numeric, const char *requsername, const char *channel, const char *user)
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
		if (relay->ircuser && strcmp(relay->ircuser, requsername)) {
			notify_unauthorized(requsername, channel, relay->ircuser);
			return 0;
		}

		RWLIST_RDLOCK(&relay->users);
		RWLIST_TRAVERSE(&relay->users, u, entry) {
			if (!channel_contains_user(cp, u)) {
				continue; /* User not in this channel */
			}
			if (numeric == 352) {
				dump_user(fd, requsername, u); /* Include in WHO response */
			} else if (numeric == 353) {
				len += snprintf(buf + len, sizeof(buf) - (size_t) len, "%s%s", len ? " " : "", u->ircusername);
				if (len >= 400) { /* Stop well short of the 512 character message limit and clear the buffer */
					len = 0;
					irc_relay_names_response(fd, requsername, cp->irc, buf);
				}
			}
		}
		RWLIST_UNLOCK(&relay->users);
		if (len > 0) {
			irc_relay_names_response(fd, requsername, cp->irc, buf); /* Last one */
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
		if (relay->ircuser && strcmp(relay->ircuser, requsername)) {
			notify_unauthorized(requsername, channel, relay->ircuser);
			return 0;
		}

		if (numeric == 353) {
			dump_user(fd, requsername, u);
		} else if (numeric == 318) {
			irc_relay_numeric_response(fd, 311, "%s %s %s %s * :%s", requsername, u->ircusername, u->ircusername, u->ircusername, u->userid);
			irc_relay_numeric_response(fd, 312, "%s %s %s :%s", requsername, u->ircusername, "Slack", u->relay->name);
			if (!u->active && u->status) {
				/* IRC doesn't have a generic "status message", users can only set if they're /away
				 * But if the user is away and has a status message, no reason not to send that!
				 * (Especially since these *are* often used as "away" messages. */
				irc_relay_numeric_response(fd, 301, "%s %s :%s", requsername, u->ircusername, u->status);
			}
		}
		return 1; /* Success, stop traversal, since only one module will have a match, and it's us. */
	}
	return 0;
}

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

static void *slack_relay(void *varg)
{
	struct slack_relay *relay = varg;
	struct slack_client *slack = relay->slack;

	/* Connect to Slack */
	if (slack_client_connect(slack)) {
		bbs_error("Slack client connection failed\n");
		return NULL;
	}

	slack_client_set_autoreconnect(slack, 1); /* Enable autoreconnect since this is supposed to be a long lived relay */
	load_users(relay, SLACK_REQUEST_USER_LIMIT); /* Load all users (or at least as many as we can) in advance */
	load_channels(relay, SLACK_REQUEST_USER_LIMIT); /* Load channels next, which will also load members (which is why we do load_users first) */
	load_presence(relay, SLACK_REQUEST_USER_LIMIT); /* Finally, load presence, for all users that share channels with us */

	slack_event_loop(slack, &slack_callbacks); /* Run event loop */
	return NULL;
}

static int start_clients(void)
{
	struct slack_relay *relay;
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		bbs_pthread_create(&relay->thread, NULL, slack_relay, relay);
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
		unsigned int relaysystem = 0;
		const char *ircuser = NULL;
		const char *mapname = NULL;
		struct slack_client *slack;
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
			} else if (!strcasecmp(key, "ircuser")) {
				ircuser = value;
				ircuserlen = strlen(ircuser) + 1;
			} else if (!strcasecmp(key, "mapping")) {
				mapname = value;
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
		SET_BITFIELD(relay->relaysystem, relaysystem);
		data = relay->data;

		SET_FSM_STRING_VAR(relay, data, name, bbs_config_section_name(section), namelen);
		SET_FSM_STRING_VAR(relay, data, token, token, tokenlen);
		SET_FSM_STRING_VAR(relay, data, gwserver, gwserver, gwserverlen);
		SET_FSM_STRING_VAR(relay, data, cookie_d, cookie_d, cookie_d_len);
		SET_FSM_STRING_VAR(relay, data, enterpriseid, enterpriseid, entlen);
		SET_FSM_STRING_VAR(relay, data, cookie_ds, cookie_ds, cookie_ds_len);
		SET_FSM_STRING_VAR(relay, data, ircuser, ircuser, ircuserlen);

		RWLIST_WRLOCK(&relay->mappings);
		while ((keyval = bbs_config_section_walk(mapsect, keyval))) {
			const char *slackchanid = bbs_keyval_key(keyval);
			const char *ircchanname = bbs_keyval_val(keyval);
			size_t slacklen, irclen;
			struct chan_pair *cp;

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
			pthread_mutex_init(&cp->lock, NULL);
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
	if (bbs_is_fully_started()) {
		start_clients();
	} else {
		bbs_register_startup_callback(start_clients, STARTUP_PRIORITY_DEPENDENT);
	}

	return 0;
}

#define DEBUG_SLACK

static int load_module(void)
{
	/* Initialize the library */
	slack_set_logger(slack_log);
#ifdef DEBUG_SLACK
	slack_set_log_level(SLACK_LOG_DEBUG + 7);
#endif

	if (load_config()) {
		return -1;
	}

	irc_relay_register(slack_send, nicklist, privmsg, BBS_MODULE_SELF);
	return 0;
}

static int unload_module(void)
{
	irc_relay_unregister(slack_send);
	RWLIST_WRLOCK_REMOVE_ALL(&relays, entry, relay_free);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("Slack/IRC Relay", "net_irc.so");
