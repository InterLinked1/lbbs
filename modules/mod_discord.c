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

#include <concord/discord.h>

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/module.h"
#include "include/utils.h"

#include "include/net_irc.h"

static int discord_ready = 0;
static struct discord *discord_client = NULL;
static pthread_t discord_thread;

static char token[84];

/* Note: only a single client is supported (multiple guilds and multiple channels within the guild are supported) */

struct chan_pair {
	u64snowflake guild_id;
	u64snowflake channel_id;
	const char *discord_channel;	/* Should not include leading # */
	const char *irc_channel;		/* Should including leading # (or other prefix) */
	RWLIST_ENTRY(chan_pair) entry;
	char data[0];
};

static RWLIST_HEAD_STATIC(mappings, chan_pair);

static void cleanup_pairs(void)
{
	struct chan_pair *cp;

	RWLIST_WRLOCK(&mappings);
	while ((cp = RWLIST_REMOVE_HEAD(&mappings, entry))) {
		free(cp);
	}
	RWLIST_UNLOCK(&mappings);
}

static int add_pair(u64snowflake guild_id, const char *discord_channel, const char *irc_channel)
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
	/* channel_id is not yet known. Once we call fetch_channels, we'll be able to get the channel_id if it matches a name. */
	RWLIST_INSERT_HEAD(&mappings, cp, entry);
	RWLIST_UNLOCK(&mappings);
	bbs_debug(3, "Adding 1:1 channel mapping for (%lu) %s <=> %s\n", guild_id, discord_channel, irc_channel);
	return 0;
}

static void on_guild_members_chunk(struct discord *client, const struct discord_guild_members_chunk *event)
{
#if 0
	int i;
#endif
	struct discord_guild_members *members = event->members;

	UNUSED(client);

	bbs_debug(3, "Guild %lu has %d members\n", event->guild_id, members->size);
#if 0
	for (i = 0; i < members->size; i++) {
		struct discord_guild_member *member = &members->array[i];
		struct discord_user *user = member->user;

		bbs_debug(8, "User: %lu => %s#%s [%s]\n", user->id, user->username, user->discriminator, member->nick);
	}
#endif
}

static void fetch_members(struct discord *client, u64snowflake guild_id)
{
	struct discord_request_guild_members params = { 
		.guild_id = guild_id,
		.query = "", /* Empty string to return all members */
		.limit = 0, /* All members */
	};
	discord_request_guild_members(client, &params); /* on_guild_members_chunk callback will fire */
}

static void fetch_channels(struct discord *client, u64snowflake guild_id)
{
	struct chan_pair *cp;
	int i;
	struct discord_channels channels = { 0 };
	CCORDcode code;
	struct discord_ret_channels ret = { .sync = &channels };

	code = discord_get_guild_channels(client, guild_id, &ret);
	if (code != CCORD_OK) {
		bbs_error("Couldn't fetch channels from guild %lu\n", guild_id);
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
			/* Auto fill in channel IDs based on channel name, so users don't need to specify those in the config directly */
			cp->channel_id = channel->id;
			bbs_debug(3, "Matching channel %d/%d: %lu => %s\n", i + 1, channels.size, channel->id, channel->name);
		}
	}
	/* Make sure all channels have a channel ID */
	RWLIST_TRAVERSE_SAFE_BEGIN(&mappings, cp, entry) {
		if (!cp->channel_id) {
			bbs_error("Channel mapping %s <=> %s lacks a channel ID and will be ignored (does %s exist in guild %lu?)\n", cp->discord_channel, cp->irc_channel, cp->discord_channel, cp->guild_id);
			/* May as well remove it, it serves no purpose anyways */
			RWLIST_REMOVE_CURRENT(entry);
			free(cp);
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
		fetch_channels(client, g->id);
		fetch_members(client, g->id); /* The event has a members and channels struct, but they're always NULL, so fetch explicitly. */
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

static int discord_send(const char *channel, const char *sender, const char *msg)
{
	struct chan_pair *cp;

	if (!discord_ready) {
		bbs_debug(1, "Discord is not yet ready, dropping message\n");
		return 0;
	} else if (!(cp = find_mapping_irc(channel))) {
		/* No relay exists for this channel */
		return 0;
	} else {
		char mbuf[564]; /* Max allowed is 2000, but IRC message can only be 512. Add some for the sender name */
		struct discord_create_message params = {
			.content = mbuf,
			.message_reference = &(struct discord_message_reference) {
				.message_id = 0, /* Irrelevant */
				.channel_id = cp->channel_id,
				.guild_id = cp->guild_id,
				.fail_if_not_exists = false, /* Send as a normal message, not an in-thread reply */
			},
			.components = NULL,
		};
		snprintf(mbuf, sizeof(mbuf), sender ? "**<%s>** %s" : "%s%s", S_IF(sender), msg);
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
		author = event->author;
		bbs_debug(4, "Relaying message from channel %lu by %s to %s: %s\n", event->channel_id, author->username, cp->irc_channel, event->content);
		irc_relay_send(cp->irc_channel, CHANNEL_USER_MODE_NONE, "Discord", author->username, event->content);
	}
	return;
}

static void on_message_update(struct discord *client, const struct discord_message *event)
{
	UNUSED(client);
	if (event->author->bot) {
		bbs_debug(3, "Ignoring message from bot: %s\n", event->content);
		return;
	}
	bbs_debug(2, "Updated message from channel %lu: %s\n", event->channel_id, event->content);
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
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_discord.conf", 1);

	if (!cfg) {
		bbs_error("File 'mod_discord.conf' is missing, declining to load\n");
		return -1;
	}

	if (bbs_config_val_set_str(cfg, "discord", "token", token, sizeof(token))) {
		bbs_error("Missing token in mod_discord.conf, declining to load\n");
		return -1; /* Things won't work without the token */
	}

	while ((section = bbs_config_walk(cfg, section))) {
		const char *irc = NULL, *discord = NULL, *guild = NULL;
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
			} else {
				bbs_warning("Unknown directive: %s\n", key);
			}
		}
		if (!irc || !discord || !guild) {
			bbs_warning("Section %s is incomplete, ignoring\n", bbs_config_section_name(section));
			continue;
		}
		add_pair(atol(guild), discord, irc);
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	ccord_global_init();
	discord_client = discord_init(token);
	if (!discord_client) {
		bbs_error("Failed to initialize Discord client\n");
		return -1;
	}

	discord_add_intents(discord_client, DISCORD_GATEWAY_MESSAGE_CONTENT | DISCORD_GATEWAY_GUILD_MESSAGES | DISCORD_GATEWAY_GUILD_MEMBERS);

	discord_set_on_ready(discord_client, &on_ready);
	discord_set_on_message_create(discord_client, &on_message_create);
	discord_set_on_message_update(discord_client, &on_message_update);
	discord_set_on_guild_members_chunk(discord_client, &on_guild_members_chunk);

	if (bbs_pthread_create(&discord_thread, NULL, discord_relay, discord_client)) {
		bbs_error("Unable to create Discord thread.\n");
		discord_shutdown(discord_client);
		discord_cleanup(discord_client);
		ccord_global_cleanup();
		return -1;
	}
	irc_relay_register(discord_send, BBS_MODULE_SELF);
	return 0;
}

static int unload_module(void)
{
	irc_relay_unregister(discord_send);

	discord_shutdown(discord_client);
	discord_cleanup(discord_client);
	bbs_pthread_join(discord_thread, NULL);

	ccord_global_cleanup();
	cleanup_pairs();
	return 0;
}

BBS_MODULE_INFO_STANDARD("Discord/IRC Relay");
