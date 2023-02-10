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
 * \brief Discord IRC relay integration
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>

/* libdiscord: https://github.com/Cogmasters/concord */
#include <concord/discord.h>

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/module.h"
#include "include/utils.h"
#include "include/node.h" /* use bbs_hostname */

#include "include/net_irc.h"

static int discord_ready = 0;
static struct discord *discord_client = NULL;
static pthread_t discord_thread;

static int expose_members = 1;
static char token[84];
static char configfile[84];

/* Note: only a single client is supported (multiple guilds and multiple channels within the guild are supported) */

struct u64snowflake_entry {
	u64snowflake id;
	RWLIST_ENTRY(u64snowflake_entry) entry;
};

RWLIST_HEAD(u64snowflake_list, u64snowflake_entry);

struct chan_pair {
	u64snowflake guild_id;
	u64snowflake guild_owner;		/* Not normalized, but we don't keep track of guilds separately */
	u64snowflake channel_id;
	unsigned int relaysystem:1;		/* Whether to relay non PRIVMSGs */
	unsigned int defaultdeny:1;		/* Default denied */
	const char *discord_channel;	/* Should not include leading # */
	const char *irc_channel;		/* Should including leading # (or other prefix) */
	struct u64snowflake_list members;	/* Members with permission to view channel */
	struct u64snowflake_list roles;		/* Roles with permission to view channel */
	RWLIST_ENTRY(chan_pair) entry;
	char data[0];
};

static RWLIST_HEAD_STATIC(mappings, chan_pair);

enum user_status {
	STATUS_NONE = 0, /* Default, since not known by default */
	STATUS_ONLINE,
	STATUS_DND,
	STATUS_IDLE,
	STATUS_OFFLINE,
};

struct user {
	u64snowflake guild_id; /* A user can probably belong to more than one guild ID... store the one we first see */
	u64snowflake user_id;
	u64unix_ms guild_joined; /* Likewise, when the user joined the guild (which applies to "joining" all channels anyways, really) */
	u64snowflake *roles;
	unsigned int admin:1;	/* Guild admin */
	int numroles;
	const char *username;
	const char *discriminator;
	enum user_status status;
	RWLIST_ENTRY(user) entry;
	char data[0];
};

static RWLIST_HEAD_STATIC(users, user);

static void free_user(struct user *user)
{
	free_if(user->roles);
	free(user);
}

static void empty_u64snowflake_list(struct u64snowflake_list *list)
{
	struct u64snowflake_entry *e;

	RWLIST_WRLOCK(list);
	while ((e = RWLIST_REMOVE_HEAD(list, entry))) {
		free(e);
	}
	RWLIST_UNLOCK(list);
}

static void free_cp(struct chan_pair *cp)
{
	empty_u64snowflake_list(&cp->members);
	empty_u64snowflake_list(&cp->roles);
	free(cp);
}

static void list_cleanup(void)
{
	struct chan_pair *cp;
	struct user *u;

	/* Clean up mappings */
	RWLIST_WRLOCK(&mappings);
	while ((cp = RWLIST_REMOVE_HEAD(&mappings, entry))) {
		free_cp(cp);
	}
	RWLIST_UNLOCK(&mappings);
	/* Clean up users */
	RWLIST_WRLOCK(&users);
	while ((u = RWLIST_REMOVE_HEAD(&users, entry))) {
		free_user(u);
	}
	RWLIST_UNLOCK(&users);
}

static int add_pair(u64snowflake guild_id, const char *discord_channel, const char *irc_channel, unsigned int relaysystem)
{
	struct chan_pair *cp;
	int dlen, ilen;

	RWLIST_WRLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		int discord_match, irc_match;
		if (cp->guild_id != guild_id) {
			continue;
		}
		/* Guild IDs match. Does either channel name match? */
		discord_match = !strcmp(cp->discord_channel, discord_channel);
		irc_match = !strcmp(cp->irc_channel, irc_channel);
		if (!discord_match && !irc_match) {
			continue; /* Nope, neither matches. */
		}
		if (!(discord_match && irc_match)) {
			/* One of them matches, but not both of them? */
			bbs_warning("Channel mapping %s <=> %s conflicts with mapping %s <=> %s, ignoring\n", discord_channel, irc_channel, cp->discord_channel, cp->irc_channel);
			break;
		}
		/* Both of them match. */
		bbs_warning("Channel mapping %s <=> %s is duplicated, ignoring\n", discord_channel, irc_channel);
		break;
	}
	if (cp) {
		RWLIST_UNLOCK(&mappings);
		return -1;
	}
	dlen = strlen(discord_channel);
	ilen = strlen(irc_channel);
	cp = calloc(1, sizeof(*cp) + dlen + ilen + 2); /* 2 NULs */
	if (!cp) {
		RWLIST_UNLOCK(&mappings);
		return -1;
	}
	strcpy(cp->data, discord_channel); /* Safe */
	strcpy(cp->data + dlen + 1, irc_channel); /* Safe */
	cp->discord_channel = cp->data;
	cp->irc_channel = cp->data + dlen + 1;
	cp->guild_id = guild_id;
	cp->relaysystem = relaysystem;
	/* channel_id is not yet known. Once we call fetch_channels, we'll be able to get the channel_id if it matches a name. */
	RWLIST_INSERT_HEAD(&mappings, cp, entry);
	RWLIST_UNLOCK(&mappings);
	bbs_debug(2, "Adding 1:1 channel mapping for (%lu) %s <=> %s\n", guild_id, discord_channel, irc_channel);
	return 0;
}

static struct user *find_user(u64snowflake user_id)
{
	struct user *u;

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, u, entry) {
		if (u->user_id == user_id) {
			break;
		}
	}
	RWLIST_UNLOCK(&users);
	return u;
}

static struct user *find_user_by_username(const char *s)
{
	char buf[84];
	struct user *u;

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, u, entry) {
		/* STARTS_WITH uses STRLEN, not strlen, so just use strncmp */
		if (!strncmp(u->username, u->username, strlen(u->username))) { /* If it starts with, it's probably going to be a match, but confirm */
			snprintf(buf, sizeof(buf), "%s#%s", u->username, u->discriminator);
			if (!strcmp(s, buf)) {
				break;
			}
		}
	}
	RWLIST_UNLOCK(&users);
	return u;
}

static enum user_status status_from_str(const char *s)
{
	if (!strcmp(s, "idle")) {
		return STATUS_IDLE;
	} else if (!strcmp(s, "dnd")) {
		return STATUS_DND;
	} else if (!strcmp(s, "online")) {
		return STATUS_ONLINE;
	} else if (!strcmp(s, "offline")) {
		return STATUS_OFFLINE;
	} else {
		return STATUS_NONE;
	}
}

static void remove_user(struct discord_user *user)
{
	struct user *u;

	RWLIST_WRLOCK(&users);
	RWLIST_TRAVERSE_SAFE_BEGIN(&users, u, entry) {
		if (u->user_id == user->id) {
			RWLIST_REMOVE_CURRENT(entry);
			free_user(u);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&users);
	if (!u) {
		bbs_error("Failed to remove user %lu (%s#%s)\n", user->id, user->username, user->discriminator);
	}
}

/*! \brief Add a user, or update (with status) */
static struct user *add_user(struct discord_user *user, u64snowflake guild_id, const char *status, u64unix_ms joined_at)
{
	struct user *u;
	int ulen, dlen;
	char simpleusername[64];
	int new = 0;
	const char *username = user->username;

	if (strchr(username, ' ')) {
		/* Gaa... username contains spaces (not allowed with IRC) */
		if (bbs_strcpy_nospaces(username, simpleusername, sizeof(simpleusername))) {
			return NULL; /* Skip, if we can't make it fit */
		}
		username = simpleusername;
	}

	RWLIST_WRLOCK(&users);
	RWLIST_TRAVERSE(&users, u, entry) {
		if (u->user_id == user->id) {
			break;
		}
	}
	if (u) {
		/* XXX Could happen if in multiple guilds? */
		/* Can also happen if we're updating a user, because we failed to get the presence for this user the first time */
		bbs_debug(6, "User %lu already exists\n", user->id);
	}
	if (!u) {
		new = 1;
		ulen = strlen(user->username);
		dlen = strlen(user->discriminator);
		u = calloc(1, sizeof(*u) + ulen + dlen + 2);
		if (!u) {
			RWLIST_UNLOCK(&users);
			return NULL;
		}
		strcpy(u->data, username); /* Safe */
		strcpy(u->data + ulen + 1, user->discriminator); /* Safe */
		u->username = u->data;
		u->discriminator = u->data + ulen + 1;
		u->user_id = user->id;
		u->guild_id = guild_id;
		u->guild_joined = joined_at;
	}
	if (!strlen_zero(status)) {
		u->status = status_from_str(status);
	}
	if (new) {
		RWLIST_INSERT_HEAD(&users, u, entry);
	}
	RWLIST_UNLOCK(&users);
	return u;
}

static void on_guild_members_chunk(struct discord *client, const struct discord_guild_members_chunk *event)
{
	int i;
	struct discord_guild_members *members = event->members;
	struct discord_presence_updates *presences = event->presences;
	int presencefails = 0;
	struct user *u;

	UNUSED(client);

	bbs_assert_exists(presences);

	bbs_debug(3, "Got chunk for guild %lu: %d members, %d presences\n", event->guild_id, members->size, presences->size);
	/* Add all members currently in the guild */
	for (i = 0; i < members->size; i++) {
		struct discord_guild_member *member = &members->array[i];
		struct discord_user *user = member->user;
		struct discord_presence_update *presence = NULL;
		const char *presencestatus = "none";
		struct snowflakes *roles = member->roles;
		if (i >= presences->size || !(presence = &presences->array[i]) || !presence->status) {
#ifdef EXTRA_DISCORD_DEBUG
			/* We're already going to warn at the end, so don't make too much noise in normal builds */
			bbs_warning("Missing presence information for user %s#%s\n", user->username, user->discriminator);
#endif
			presencefails++;
		} else {
			presencestatus = presence->status;
		}

#define ADMINISTRATOR (1 << 3)

		bbs_debug(8, "User %d/%d: %lu => %s#%s [%s] (%s) - %d role(s)\n", i + 1, members->size, user->id, user->username, user->discriminator, S_IF(member->nick), presencestatus, roles ? roles->size : 0);
		u = add_user(user, event->guild_id, presence ? presence->status : "none", member->joined_at);
#if 0
		{
			int j;
			for (j = 0; j < 40; j++) {
				if (member->permissions & (1 << j)) {
					bbs_debug(8, "User %s#%s has permission %d\n", user->username, user->discriminator, j);
				}
			}
		}
#endif
		if (u && member->permissions & ADMINISTRATOR) {
			bbs_debug(6, "Ooh... %s#%s is an administrator of guild %lu\n", user->username, user->discriminator, u->guild_id);
			u->admin = 1; /* XXX Admin of *THIS GUILD*, but not other guilds... fine for now since we store guild_id as part of the user */
		}
		if (u && roles && roles->size > 0) {
#ifdef EXTRA_DISCORD_DEBUG
			int j;
			for (j = 0; j < roles->size; j++) {
				bbs_debug(10, "User has role %lu\n", roles->array[j]);
			}
#endif
			u->roles = calloc(roles->size, roles->array[0]);
			if (u->roles) {
				u->numroles = roles->size;
				memcpy(u->roles, roles, sizeof(*u->roles));
			}
		}
	}
	if (presencefails) {
		/* XXX For some reason, this happens, and we fail to get the remaining presences */
		static int last_fails = 0;
		int retry_now = presencefails;
		struct snowflakes missed; /* Must be dynamically allocated, not stack allocated, since discord_request_guild_members is async */
		/* Retry to get the missing presences */
		bbs_warning("Guild %lu chunk has %d members, but only %d presences? Failed to fetch %d presence%s\n", event->guild_id, members->size, presences->size, presencefails, ESS(presencefails));
		if (presencefails == last_fails) {
			/* Some presences might never be fetchable, so don't retry forever and ever if that's the case. Stop once
			 * we're not longer decreasing the number of missing presences. */
			bbs_error("Giving up presence retries, %d failure(s) outstanding\n", presencefails);
			return;
		}

		/*! \todo XXX Workaround for libdiscord JSON serialization truncation bug, remove once no longer needed */
		retry_now = MIN(25, presencefails); /* Don't retry more than 25 in a single request */

		missed.array = calloc(retry_now, sizeof(u64snowflake *));
		if (missed.array) {
			struct discord_request_guild_members params = {
				.guild_id = u->guild_id,
				.query = "", /* Empty string to return all members */
				.limit = retry_now, /* All members */
				.user_ids = &missed, /* Filter to only users whose status we failed to get the first time */
				.presences = true, /* Include presences */
			};
			i = 0;
			RWLIST_RDLOCK(&users);
			RWLIST_TRAVERSE(&users, u, entry) {
				if (u->status == STATUS_NONE) {
					if (i >= retry_now) {
						bbs_error("Indexing out of bounds: i=%d, presencefails=%d\n", i, retry_now); /* This is a bug if it happens, should probably be an assertion */
						break;
					}
					missed.array[i++] = u->user_id;
#ifdef EXTRA_DISCORD_DEBUG
					bbs_debug(7, "Retrying to get presence for user %s#%s\n", u->username, u->discriminator);
#endif
				}
			}
			RWLIST_UNLOCK(&users);
			missed.size = i;

			bbs_debug(7, "Retrying %d presence request%s\n", i, ESS(i));

			last_fails = presencefails;
			discord_request_guild_members(client, &params); /* on_guild_members_chunk callback will fire */
			free(missed.array); /* discord_request_guild_members is done using missed by the time it returns (it'll serialize it into JSON before making the request) */
		}
	}
}

static void on_guild_member_add(struct discord *client, const struct discord_guild_member *event)
{
	struct discord_user *user = event->user;

	UNUSED(client);
	bbs_debug(2, "User %lu (%s#%s) has joined guild %lu\n", user->id, user->username, user->discriminator, event->guild_id);
	add_user(user, event->guild_id, "online", time(NULL) * 1000);
}

static void on_guild_member_remove(struct discord *client, const struct discord_guild_member_remove *event)
{
	struct discord_user *user = event->user;

	UNUSED(client);
	bbs_debug(2, "User %lu (%s#%s) has left guild %lu\n", user->id, user->username, user->discriminator, event->guild_id);
	remove_user(user);
}

static void on_presence_update(struct discord *client, const struct discord_presence_update *event)
{
	struct user *u;
	struct discord_user *user = event->user;
	struct discord_client_status *client_status = event->client_status;

	UNUSED(client);

	u = find_user(user->id);
	if (!u) {
		bbs_warning("Presence update for nonexistent user %lu?\n", user->id); /* XXX New member (since module loaded)? Add now? */
		return;
	}

	/* the discord_user struct here doesn't always have username and discriminator set (such as for non-online presence updates.
	 * Thus, refer to our local user struct for this info. */

	bbs_debug(3, "Presence update: guild=%lu, user=%lu (%s#%s), status=%s (desktop: %s, mobile: %s, web: %s)\n",
		event->guild_id, user->id, u->username, u->discriminator, event->status, S_IF(client_status->desktop), S_IF(client_status->mobile), S_IF(client_status->web));

	u->status = status_from_str(event->status);
}

static void fetch_members(struct discord *client, u64snowflake guild_id)
{
	struct discord_request_guild_members params = { 
		.guild_id = guild_id,
		.query = "", /* Empty string to return all members */
		.limit = 0, /* All members */
		.presences = true, /* Include presences */
	};
	discord_request_guild_members(client, &params); /* on_guild_members_chunk callback will fire */
}

static int user_has_role(struct user *u, u64snowflake role_id)
{
	int i;
	if (!u->roles) {
		return 0;
	}
	for (i = 0; i < u->numroles; i++) {
		if (u->roles[i] == role_id) {
			bbs_debug(9, "User %s#%s has role %lu\n", u->username, u->discriminator, role_id);
			return 1;
		}
	}
	return 0;
}

/*! \brief Given a user, a reasonably (but not terribly) efficient way to determine if the channel contains the user */
static int channel_contains_user(struct chan_pair *cp, struct user *u)
{
	struct u64snowflake_entry *e;

	if (cp->guild_id != u->guild_id) {
		return 0; /* Different guild IDs */
	}

	/* We need to check 4 things here:
	 * - Is the user explicitly allowed access to the channel?
	 * - Does the user have a role that is allowed access to the channel?
	 * - Is the user a guild administrator?
	 * - Is the user the guild owner?
	 * The last two are corner caess that are easy to overlook, but would exclude the very people who should most have access!
	 */

	if (!cp->defaultdeny) {
		/* No overwrites. Everyone can view the channel. */
		if (!(RWLIST_EMPTY(&cp->members) && RWLIST_EMPTY(&cp->roles))) {
			bbs_debug(3, "Channel is not private, but there are roles/members added?\n");
		}
		bbs_debug(5, "Channel %lu (%s) is open to everyone\n", cp->channel_id, cp->discord_channel);
		return 1;
	}

	/* Check for explicit permission */
	RWLIST_RDLOCK(&cp->members);
	RWLIST_TRAVERSE(&cp->members, e, entry) {
#ifdef EXTRA_DISCORD_DEBUG
		bbs_debug(10, "Comparing member %lu with %lu\n", u->user_id, e->id);
#endif
		if (e->id == u->user_id) {
			break;
		}
	}
	RWLIST_UNLOCK(&cp->members);
	if (e) {
		bbs_debug(5, "User %s#%s explicitly belongs to %lu (%s)\n", u->username, u->discriminator, cp->channel_id, cp->discord_channel);
		return 1;
	}
	/* Check by role */
	RWLIST_RDLOCK(&cp->roles);
	RWLIST_TRAVERSE(&cp->roles, e, entry) {
#ifdef EXTRA_DISCORD_DEBUG
		bbs_debug(10, "Does user %s#%s have role %lu?\n", u->username, u->discriminator, e->id);
#endif
		if (user_has_role(u, e->id)) {
			break;
		}
	}
	RWLIST_UNLOCK(&cp->roles);
	if (e) {
		bbs_debug(5, "User %s#%s implicitly belongs to %lu (%s)\n", u->username, u->discriminator, cp->channel_id, cp->discord_channel);
		return 1;
	}
	/* Even though it's more efficient to check this immediately, check this last to attempt to match on roles/users explicitly first.
	 * We need to handle this explicitly at some point though, since it's not covered by other cases. */
	if (u->admin) {
		bbs_debug(5, "User %s#%s is an administrator of guild %lu (%s)\n", u->username, u->discriminator, cp->guild_id, cp->discord_channel);
		return 1;
	}
	/* And this is yet another separate case... */
	if (u->user_id == cp->guild_owner) {
		bbs_debug(5, "User %s#%s is the owner of guild %lu (%s)\n", u->username, u->discriminator, cp->guild_id, cp->discord_channel);
		return 1;
	}
	return 0;
}

static void link_permissions(struct chan_pair *cp, struct discord_overwrites *overwrites)
{
	/* We can't directly link permissions to users, since users may not all exist yet.
	 * Just store any users and roles on the channel itself, and at runtime,
	 * we can check if a user is in the channel by seeing if the user
	 * is in cp->users, or if the user has any of the roles in cp->roles */
	int j;
	RWLIST_WRLOCK(&cp->members);
	for (j = 0; j < overwrites->size; j++) {
		struct u64snowflake_entry *e;
		struct discord_overwrite *overwrite = &overwrites->array[j];
		u64bitmask allow, deny;
		/* overwrite->type: 0 = role, 1 = member */
		/* Permissions: https://discord.com/developers/docs/topics/permissions#permissions */
#define VIEW_CHANNEL (1 << 10)
		allow = overwrite->allow;
		deny = overwrite->deny;
		/* This may be a bit simplistic, but should cover most cases */
		bbs_debug(7, "Permission for %s %lu for %s: %s\n", overwrite->type ? "user" : "role", overwrite->id, cp->discord_channel, allow & VIEW_CHANNEL && !(deny & VIEW_CHANNEL) ? "allowed" : "denied");
		if (!(allow & VIEW_CHANNEL && !(deny & VIEW_CHANNEL))) {
			if (overwrite->id == cp->guild_id) {
				/* Deny everyone by default */
				bbs_debug(6, "Default deny for channel %s\n", cp->discord_channel);
				cp->defaultdeny = 1;
			} else {
				bbs_debug(6, "Permission denied for %lu\n", overwrite->id);
			}
			continue;
		}
		e = calloc(1, sizeof(*e));
		if (!e) {
			bbs_error("calloc failed\n");
			continue; /* continue would be fine here, but we already need a label, so use it for consistency */
		}
		e->id = overwrite->id;
		if (overwrite->type == 1) { /* it's a user, explicitly */
			RWLIST_INSERT_HEAD(&cp->members, e, entry);
			bbs_debug(3, "Granted permission for channel %s to user %lu\n", cp->discord_channel, e->id);
		} else { /* 0 = it's a role */
			RWLIST_INSERT_HEAD(&cp->roles, e, entry);
			bbs_debug(3, "Granted permission for channel %s to role %lu\n", cp->discord_channel, e->id);
		}
	}
	RWLIST_UNLOCK(&cp->members);
}

static void fetch_channels(struct discord *client, u64snowflake guild_id, u64snowflake guild_owner)
{
	struct chan_pair *cp;
	int i;
	struct discord_channels channels = { 0 };
	CCORDcode code;
	struct discord_ret_channels ret = { .sync = &channels };

	code = discord_get_guild_channels(client, guild_id, &ret);
	if (code != CCORD_OK) {
		bbs_error("Couldn't fetch channels from guild %lu: %s\n", guild_id, discord_strerror(code, client));
		return;
	}

	RWLIST_WRLOCK(&mappings);
	for (i = 0; i < channels.size; i++) {
		struct discord_channel *channel = &channels.array[i];
		/* channel->member_count is always 0 and channel->recipients is NULL */

		RWLIST_TRAVERSE(&mappings, cp, entry) {
			if (guild_id != cp->guild_id) {
				continue;
			}
			if (!strcmp(cp->discord_channel, channel->name)) {
				break;
			}
		}
		if (!cp) {
			bbs_debug(3, "Ignoring channel %d/%d: %lu => %s\n", i + 1, channels.size, channel->id, channel->name);
		} else {
			struct discord_channel dchannel = { 0 };
			struct discord_ret_channel ret2 = { .sync = &dchannel };
			struct discord_overwrites *overwrites;
			/* Auto fill in channel IDs based on channel name, so users don't need to specify those in the config directly */
			cp->channel_id = channel->id;
			cp->guild_owner = guild_owner;
			bbs_debug(3, "Matching channel %d/%d: %lu => %s\n", i + 1, channels.size, channel->id, channel->name);
			code = discord_get_channel(client, channel->id, &ret2);
			if (code != CCORD_OK) {
				bbs_error("Couldn't fetch channel %lu: %s\n", channel->id, discord_strerror(code, client));
				continue;
			}
			bbs_assert(dchannel.id == channel->id);

			/* Need to store all members of each channel.
			 * Workaround since recipients (and members) are NULL...
			 * Instead of directly obtaining a list of channel members,
			 * determine what members are in what channels using the permissions, and checking roles if necessary
			 * Permissions, in this case, serve as a crude proxy for membership in the channel.
			 */

			/* By default, all members have access to all channels in a guild, if nothing else is specified. */

			overwrites = dchannel.permission_overwrites;
			if (!overwrites) {
				bbs_error("Failed to fetch member permissions for channel %lu (%s)\n", channel->id, cp->discord_channel);
				continue;
			}
			bbs_debug(3, "Channel %s contains %d permissions and is owned by %lu\n", cp->discord_channel, overwrites->size, guild_owner);
			link_permissions(cp, overwrites);
		}
	}
	/* Make sure all channels have a channel ID */
	RWLIST_TRAVERSE_SAFE_BEGIN(&mappings, cp, entry) {
		if (!cp->channel_id) {
			bbs_error("Channel mapping %s <=> %s lacks a channel ID and will be ignored (does %s exist in guild %lu?)\n", cp->discord_channel, cp->irc_channel, cp->discord_channel, cp->guild_id);
			/* May as well remove it, it serves no purpose anyways */
			RWLIST_REMOVE_CURRENT(entry);
			free_cp(cp);
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&mappings);
	discord_channels_cleanup(&channels);
}

static void load_channels(struct discord *client, struct discord_guilds *guilds)
{
	int i, numguilds = guilds->size;
	struct discord_guild *gs = guilds->array;

	for (i = 0; i < numguilds; i++) {
		struct discord_guild *g = &gs[i];
		bbs_debug(3, "Guild %d/%d: %lu\n", i + 1, numguilds, g->id);
		fetch_members(client, g->id); /* The event has a members and channels struct, but they're always NULL, so fetch explicitly. */
		if (!g->owner_id) {
			/*! \todo Possible libdiscord bug, but should work once fixed */
			bbs_error("Owner ID is %lu?\n", g->owner_id);
		}
		fetch_channels(client, g->id, g->owner_id);
	}
}

static void on_ready(struct discord *client, const struct discord_ready *event)
{
	UNUSED(client);
	UNUSED(event);

	discord_ready = 1;
	bbs_debug(1, "Succesfully connected to Discord as %s#%s\n", event->user->username, event->user->discriminator);

	load_channels(client, event->guilds);
}

static struct chan_pair *find_mapping(u64snowflake guild_id, u64snowflake channel_id)
{
	struct chan_pair *cp;

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		/* We're doiong int comparisons, not string comparisons, so this is nice and speedy fast! */
		if (guild_id != cp->guild_id) {
			continue; /* Guild IDs don't even match */
		}
		if (channel_id != cp->channel_id) {
			continue; /* Channel IDs don't match */
		}
		/* Found a match! */
		break;
	}
	RWLIST_UNLOCK(&mappings);
	return cp; /* It's okay to return unlocked since at this point, items can't be removed from the list until the module is unloaded anyways. */
}

static struct chan_pair *find_mapping_irc(const char *channel)
{
	struct chan_pair *cp;

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (!strcmp(channel, cp->irc_channel)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp; /* It's okay to return unlocked since at this point, items can't be removed from the list until the module is unloaded anyways. */
}

#define fdprint_log(fd, fmt, ...) dprintf(fd, fmt, ## __VA_ARGS__); bbs_debug(6, fmt, ## __VA_ARGS__);

static void dump_user(int fd, const char *requsername, struct user *u)
{
	char mask[96];
	char userflags[3];
	char combined[84];
	int hopcount = 2; /* Since we're going through a relay, use an incremented hop count */

	snprintf(combined, sizeof(combined), "%s#%s", u->username, u->discriminator);
	snprintf(mask, sizeof(mask), "%s/%s", "Discord", combined);
	/* We consider users to be active in a channel as long as they're in it, so offline is the equivalent of "away" in IRC */
	snprintf(userflags, sizeof(userflags), "%c%s", u->status == STATUS_OFFLINE ? 'G' : 'H', "");
#undef dprintf
	/* IRC numeric 352: see the 352 numeric in net_irc for more info. */
	fdprint_log(fd, "%03d %s :" "%s %s %s %s %s %s :%d %lu\r\n", 352, requsername, "*", combined, mask, bbs_hostname(), u->username, userflags, hopcount, u->user_id);
}

/*!
 * \param numeric
 * 318 = WHOIS
 * 352 = WHO
 * 353 = NAMES
 */
static int nicklist(int fd, int numeric, const char *requsername, const char *channel, const char *user)
{
	/* We should do absolutely nothing if a user/channel does not exist,
	 * since the relay nicklist callbacks runs for all registered relays,
	 * and likely only one of them will have a match, if any.
	 * However, if we happen to match, return nonzero to stop the traversal.
	 */

#ifdef EXTRA_DISCORD_DEBUG
	bbs_debug(9, "Nicklist callback for %d: %s/%s\n", numeric, S_IF(channel), S_IF(user));
#endif

	if (!discord_ready) {
		bbs_debug(1, "Discord is not yet ready, dropping message\n");
		return 0;
	} else if (!expose_members) {
		bbs_debug(5, "Ignoring since exposemembers=no\n");
		return 0;
	} else if (channel && (numeric == 352 || numeric == 353)) { /* WHO or NAMES */
		struct user *u;
		char buf[500];
		int len = 0;
		struct chan_pair *cp = find_mapping_irc(channel);
		if (!cp) {
			/* No relay exists for this channel */
			bbs_debug(6, "No relay exists for channel %s\n", channel);
			return 0;
		}

		RWLIST_RDLOCK(&users);
		RWLIST_TRAVERSE(&users, u, entry) {
			if (u->guild_id != cp->guild_id) {
				continue; /* Not even the same guild ID */
			}
			if (!channel_contains_user(cp, u)) {
				continue; /* User not in this channel */
			}
			/* User is in the same guild that the channel is in, just assume match for now */
			if (u->status == STATUS_NONE) {
#ifdef EXTRA_DISCORD_DEBUG
				bbs_debug(9, "Skipping user %s#%s (no status information)\n", u->username, u->discriminator);
#endif
				continue;
			}
			if (numeric == 352) {
				dump_user(fd, requsername, u); /* Include in WHO response */
			} else if (numeric == 353) {
				len += snprintf(buf + len, sizeof(buf) - len, "%s%s#%s", len ? " " : "", u->username, u->discriminator);
				if (len >= 400) { /* Stop well short of the 512 character message limit and clear the buffer */
					len = 0;
					fdprint_log(fd, "%03d %s " "%s %s :%s\r\n", numeric, requsername, PUBLIC_CHANNEL_PREFIX, cp->irc_channel, buf);
				}
			}
		}
		RWLIST_UNLOCK(&users);
		if (len > 0) {
			fdprint_log(fd, "%03d %s " "%s %s :%s\r\n", numeric, requsername, PUBLIC_CHANNEL_PREFIX, cp->irc_channel, buf); /* Last one */
		}
		return 1;
	} else if (user && (numeric == 353 || numeric == 318)) { /* Only for WHO and WHOIS, not NAMES */
		struct user *u = find_user_by_username(user);

		if (!u) {
			bbs_debug(7, "No such user: %s\n", user);
			return 0;
		}

		if (numeric == 353) {
			dump_user(fd, requsername, u);
		} else if (numeric == 318) {
			char mask[96];
			char combined[84];
			int idle = 0; /* XXX Arbitrary */
			int signon = u->guild_joined / 1000; /* Probably the most sensical value to use? */
			snprintf(combined, sizeof(combined), "%s#%s", u->username, u->discriminator);
			snprintf(mask, sizeof(mask), "%s/%s", "Discord", combined);
			fdprint_log(fd, "%03d %s " "%s %s %s * :%lu\r\n", 311, requsername, combined, combined, mask, u->user_id);
			fdprint_log(fd, "%03d %s " "%s %s :%s\r\n", 312, requsername, combined, "Discord", "Discord Relay");
			fdprint_log(fd, "%03d %s " "%s %d %u :seconds idle, signon time\r\n", 317, requsername, combined, idle, signon);
		}
		return 1; /* Success, stop traversal */
	}
	return 0;
}

static int discord_send(const char *channel, const char *sender, const char *msg)
{
	struct chan_pair *cp;

	if (!discord_ready) {
		bbs_debug(1, "Discord is not yet ready, dropping message\n");
		return 0;
	} else if (!(cp = find_mapping_irc(channel))) {
		/* No relay exists for this channel */
		return 0;
	} else if (!cp->relaysystem  && !sender) {
		bbs_debug(3, "Dropping system-generated message since relaysystem=no\n");
	} else {
		char mbuf[564]; /* Max allowed is 2000, but IRC message can only be 512. Add some for the sender name */
		struct discord_create_message params = {
			.content = mbuf,
			.message_reference = &(struct discord_message_reference) {
				.message_id = 0, /* Irrelevant, we're not replying to a channel thread (IRC doesn't have the concept of threads anyways) */
				.channel_id = cp->channel_id,
				.guild_id = cp->guild_id,
				.fail_if_not_exists = false, /* Send as a normal message, not an in-thread reply */
			},
			.components = NULL,
		};
		/* Use ** (markdown) to bold the username, just like many IRC clients do. For system messages, italicize them. */
		snprintf(mbuf, sizeof(mbuf), sender ? "**<%s>** %s" : "*%s%s*", S_IF(sender), msg);
		discord_create_message(discord_client, cp->channel_id, &params, NULL);
	}
	return 0;
}

static void on_message_create(struct discord *client, const struct discord_message *event)
{
	struct chan_pair *cp;
	struct discord_user *author;

	UNUSED(client);

	/* If we don't ignore bot messages, if we post a message in response
	 * to a message from the channel, then we'll perpetually bounce messages
	 * back and forth... similar to how NOTICE messages should not be autoresponded
	 * to on IRC (unlike PRIVMSG), bot messages should not be responded to. */
	if (event->author->bot) {
		bbs_debug(3, "Ignoring message from bot: %s\n", event->content);
		return;
	}

	/* Check if there's a channel that matches. */
	cp = find_mapping(event->guild_id, event->channel_id);
	if (!cp) {
		bbs_debug(7, "Ignoring message from channel %lu (no mapping): %s\n", event->channel_id, event->content);
	} else { /* Relay to IRC */
		char sender[84];
		author = event->author;
		snprintf(sender, sizeof(sender), "%s#%s", author->username, author->discriminator);
		bbs_debug(4, "Relaying message from channel %lu by %s to %s: %s\n", event->channel_id, sender, cp->irc_channel, event->content);
		irc_relay_send(cp->irc_channel, CHANNEL_USER_MODE_NONE, "Discord", sender, event->content);
	}
	return;
}

static void on_message_update(struct discord *client, const struct discord_message *event)
{
	struct chan_pair *cp;
	struct discord_user *author;

	UNUSED(client);
	if (!event->author) {
		bbs_error("Event has no author?\n");
		return;
	}
	if (event->author->bot) {
		bbs_debug(3, "Ignoring updated message from bot: %s\n", event->content);
		return;
	}

	/* Check if there's a channel that matches. */
	cp = find_mapping(event->guild_id, event->channel_id);
	if (!cp) {
		bbs_debug(7, "Ignoring updated message from channel %lu (no mapping): %s\n", event->channel_id, event->content);
	} else { /* Relay to IRC */
		char sender[84];
		author = event->author;
		snprintf(sender, sizeof(sender), "%s#%s", author->username, author->discriminator);
		bbs_debug(4, "Relaying updated message from channel %lu by %s to %s: %s\n", event->channel_id, sender, cp->irc_channel, event->content);
		/* If we wanted to be really fancy, we could turn the update into a sed style string, but we'd need the original message for that...
		 * which in theory we could keep track of, but we don't store messages, that would be ridiculous overhead...
		 * so, just pass it on as a new message */
		irc_relay_send(cp->irc_channel, CHANNEL_USER_MODE_NONE, "Discord", sender, event->content);
	}
	return;
}

static void *discord_relay(void *varg)
{
	struct discord *client = varg;
	discord_run(client);
	bbs_debug(3, "Discord relay thread now exiting\n");
	return NULL;
}

static int load_config(void)
{
	int res = 0;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_discord.conf", 1);

	if (!cfg) {
		bbs_error("File 'mod_discord.conf' is missing, declining to load\n");
		return -1;
	}

	res |= !bbs_config_val_set_str(cfg, "discord", "token", token, sizeof(token));
	res |= !bbs_config_val_set_str(cfg, "discord", "concordconfig", configfile, sizeof(configfile));
	if (!res) {
		bbs_error("Missing token in mod_discord.conf, and no JSON config specified, declining to load\n");
		return -1; /* Things won't work without the token */
	}

	bbs_config_val_set_true(cfg, "discord", "exposemembers", &expose_members);

	while ((section = bbs_config_walk(cfg, section))) {
		const char *irc = NULL, *discord = NULL, *guild = NULL;
		unsigned int relaysystem = 1;
		if (!strcmp(bbs_config_section_name(section), "discord")) {
			continue; /* Not a channel mapping section, skip */
		}

		/* Category name is not relevant, only the contents. */

		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcasecmp(key, "irc_channel")) {
				irc = value;
			} else if (!strcasecmp(key, "discord_channel")) {
				discord = value;
			} else if (!strcasecmp(key, "discord_guild")) {
				guild = value;
			} else if (!strcasecmp(key, "relaysystem")) {
				relaysystem = S_TRUE(value);
			} else {
				bbs_warning("Unknown directive: %s\n", key);
			}
		}
		if (!irc || !discord || !guild) {
			bbs_warning("Section %s is incomplete, ignoring\n", bbs_config_section_name(section));
			continue;
		}
		add_pair(atol(guild), discord, irc, relaysystem);
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	ccord_global_init();
	if (!s_strlen_zero(configfile)) {
		discord_client = discord_config_init(configfile);
	} else {
		discord_client = discord_init(token);
	}
	if (!discord_client) {
		bbs_error("Failed to initialize Discord client using %s\n", !s_strlen_zero(configfile) ? "config file" : "token");
		return -1;
	}

	discord_add_intents(discord_client, DISCORD_GATEWAY_MESSAGE_CONTENT | DISCORD_GATEWAY_GUILD_MESSAGES | DISCORD_GATEWAY_GUILD_PRESENCES | DISCORD_GATEWAY_GUILDS | DISCORD_GATEWAY_GUILD_MEMBERS | DISCORD_GATEWAY_DIRECT_MESSAGES | DISCORD_GATEWAY_PRESENCE_UPDATE);

	discord_cache_enable(discord_client, DISCORD_CACHE_GUILDS); /* So we can get the guild owner later */

	discord_set_on_ready(discord_client, &on_ready);
	/* PRIVMSG */
	discord_set_on_message_create(discord_client, &on_message_create);
	discord_set_on_message_update(discord_client, &on_message_update);

	discord_set_on_presence_update(discord_client, &on_presence_update);
	discord_set_on_guild_members_chunk(discord_client, &on_guild_members_chunk);

	/* JOIN, PART/QUIT/KICK */
	discord_set_on_guild_member_add(discord_client, &on_guild_member_add);
	discord_set_on_guild_member_remove(discord_client, &on_guild_member_remove);
	/*! \todo Probably need on_user_update as well, for nick changes */

	if (bbs_pthread_create(&discord_thread, NULL, discord_relay, discord_client)) {
		bbs_error("Unable to create Discord thread.\n");
		discord_shutdown(discord_client);
		discord_cleanup(discord_client);
		ccord_global_cleanup();
		return -1;
	}
	irc_relay_register(discord_send, nicklist, BBS_MODULE_SELF);
	return 0;
}

static int unload_module(void)
{
	discord_ready = 0;
	irc_relay_unregister(discord_send);

	/*! \todo BUGBUG This is not multithread safe. Pending resolution in libdiscord. */
	discord_shutdown(discord_client);
	discord_cleanup(discord_client);
	bbs_pthread_join(discord_thread, NULL);

	ccord_global_cleanup();
	list_cleanup();
	return 0;
}

BBS_MODULE_INFO_STANDARD("Discord/IRC Relay");