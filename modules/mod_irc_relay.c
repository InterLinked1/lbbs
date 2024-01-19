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
 * \brief IRC-to-IRC relay integration
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>

#ifdef __linux__
#include <bsd/string.h>
#endif

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/module.h"
#include "include/utils.h"
#include "include/node.h" /* use bbs_hostname */
#include "include/cli.h"
#include "include/stringlist.h"

/* Since this is an IRC/IRC relay, we depend on both the server and client modules */
#include "include/net_irc.h"
#include "include/mod_irc_client.h"

static int expose_members = 1;
static unsigned int ignore_join_start = 0;

static time_t modstart;

struct chan_pair {
	const char *client1;
	const char *channel1;
	const char *client2;
	const char *channel2;
	const char *ircuser;
	unsigned int relaysystem:1;
	unsigned int gotnames:2;	/* Have we queried the NAMES for this channel pair at least once? */
	RWLIST_ENTRY(chan_pair) entry;
	struct stringlist members;
	pthread_t names_thread;
	pthread_mutex_t names_query_lock;
	char data[0];
};

static RWLIST_HEAD_STATIC(mappings, chan_pair);

static void chan_pair_cleanup(struct chan_pair *cp)
{
	pthread_mutex_lock(&cp->names_query_lock);
	if (cp->names_thread) {
		bbs_pthread_join(cp->names_thread, NULL);
		cp->names_thread = 0;
	}
	pthread_mutex_unlock(&cp->names_query_lock);

	stringlist_empty(&cp->members);
	pthread_mutex_destroy(&cp->names_query_lock);
	free(cp);
}

static void list_cleanup(void)
{
	/* Clean up mappings */
	RWLIST_WRLOCK_REMOVE_ALL(&mappings, entry, chan_pair_cleanup);
}

static int add_pair(const char *client1, const char *channel1, const char *client2, const char *channel2, const char *ircuser, int relaysystem)
{
	char *pos;
	struct chan_pair *cp;
	size_t client1len, channel1len, client2len, channel2len, userlen;

	if (ircuser && client1 && client2) {
		bbs_error("ircuser may not be specified if both client1 and client2 are provided\n");
		return -1;
	}

	/* Add NULs here if needed */
	client1len = client1 ? strlen(client1) + 1 : 0;
	client2len = client2 ? strlen(client2) + 1 : 0;
	channel1len = strlen(channel1) + 1;
	channel2len = strlen(channel2) + 1;
	userlen = ircuser ? strlen(ircuser) + 1 : 0;

	RWLIST_WRLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (strcmp(S_IF(client1), S_IF(cp->client1))) {
			continue;
		}
		if (strcmp(S_IF(client2), S_IF(cp->client2))) {
			continue;
		}
		if (strcmp(channel1, cp->channel1)) {
			continue;
		}
		if (strcmp(channel2, cp->channel2)) {
			continue;
		}
		if (!strcmp(S_IF(client1), S_IF(client2)) && !strcmp(channel1, channel2)) { /* Source and destination are the same */
			bbs_warning("Channel mapping %s/%s <=> %s/%s is a loopback, ignoring\n", S_IF(client1), channel1, S_IF(client2), channel2);
			break;
		}
		/* Both of them match. */
		bbs_warning("Channel mapping %s/%s <=> %s/%s is duplicated, ignoring\n", S_IF(client1), channel1, S_IF(client2), channel2);
		break;
	}
	if (cp) {
		RWLIST_UNLOCK(&mappings);
		return -1;
	}

	cp = calloc(1, sizeof(*cp) + client1len + client2len + channel1len + channel2len + userlen); /* NULs are included above */
	if (ALLOC_FAILURE(cp)) {
		RWLIST_UNLOCK(&mappings);
		return -1;
	}

	pos = cp->data;

	if (client1) {
		strcpy(pos, client1);
		cp->client1 = pos;
		pos += client1len;
	}
	if (client2) {
		strcpy(pos, client2);
		cp->client2 = pos;
		pos += client2len;
	}

	strcpy(pos, channel1);
	cp->channel1 = pos;
	pos += channel1len;

	strcpy(pos, channel2);
	cp->channel2 = pos;
	pos += channel2len;

	if (ircuser) {
		strcpy(pos, ircuser);
		cp->ircuser = pos;
	}

	SET_BITFIELD(cp->relaysystem, relaysystem);
	pthread_mutex_init(&cp->names_query_lock, NULL);

	RWLIST_INSERT_HEAD(&mappings, cp, entry);
	RWLIST_UNLOCK(&mappings);

	bbs_debug(3, "Added mapping for %s/%s <=> %s/%s (relaysystem: %s)\n", S_IF(cp->client1), cp->channel1, S_IF(cp->client2), cp->channel2, cp->relaysystem ? "yes" : "no");
	return 0;
}

#define MAP1_MATCH(cp, client, channel) (!strcmp(S_IF(cp->client1), S_IF(client)) && !strcmp(channel, cp->channel1))
#define MAP2_MATCH(cp, client, channel) (!strcmp(S_IF(cp->client2), S_IF(client)) && !strcmp(channel, cp->channel2))

static struct chan_pair *find_chanpair(const char *client, const char *channel)
{
	struct chan_pair *cp = NULL;

	if (strlen_zero(channel)) {
		/* Could be NULL where there's no channel from the remote network, e.g. for NICK command, etc. */
		bbs_debug(9, "No channel, no match!\n");
		return NULL;
	}

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (MAP1_MATCH(cp, client, channel) || MAP2_MATCH(cp, client, channel)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

/*! \note c can be NULL, client must not be NULL */
#define CLIENT_MATCH(c, client) (!strlen_zero(c) && !strcmp(c, client))

#define EITHER_CLIENT_MATCH(cp, client) (CLIENT_MATCH(cp->client1, client) || CLIENT_MATCH(cp->client2, client))

static struct chan_pair *find_chanpair_by_client(const char *client)
{
	struct chan_pair *cp = NULL;

	if (!client) {
		return NULL;
	}

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (EITHER_CLIENT_MATCH(cp, client)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

static struct chan_pair *client_exists(const char *client)
{
	struct chan_pair *cp = NULL;

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (EITHER_CLIENT_MATCH(cp, client)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

static struct chan_pair *find_chanpair_reverse(const char *clientname)
{
	struct chan_pair *cp = NULL;

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (!cp->client1 && cp->client2 && !strcmp(cp->client2, clientname)) {
			break;
		}
		if (!cp->client2 && cp->client1 && !strcmp(cp->client1, clientname)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

static pthread_mutex_t nicklock = PTHREAD_MUTEX_INITIALIZER;
static int nickpipe[2] = { -1, -1 };
static const char *numericclient = NULL;

/*! \brief Numeric messages of interest from IRC clients */
static void numeric_cb(const char *clientname, const char *prefix, int numeric, const char *msg)
{
	int len;
	char mybuf[512];

	UNUSED(clientname);

	if (!numericclient) {
		return; /* Weren't waiting for a response, don't care. */
	}
	/* Since we have to format it here anyways, do all the formatting here */
	len = snprintf(mybuf, sizeof(mybuf), ":%s %d %s\n", S_OR(prefix, bbs_hostname()), numeric, msg); /* Use LF to delimit on the other end */
	bbs_debug(9, "Numeric %s: %s\n", prefix, mybuf);
	if (nickpipe[0] == -1) { /* In theory, we could receive this callback at any point. If we didn't call it from wait_response, there's nothing to write to right now */
		bbs_debug(9, "Ignoring numeric since we didn't ask for it\n");
		return;
	}
	bbs_write(nickpipe[1], mybuf, (size_t) len);
}

static void cp_add_member(struct chan_pair *cp, const char *username)
{
	/* This is used to work around a particular limitation that we face.
	 * When a user quits an IRC channel on another network and that gets relayed through here,
	 * we'd like to relay the quit to all the channels that user was in.
	 * However, the QUIT message is not associated with a channel (it's network wide),
	 * so we need to keep track of the channels that a user is in.
	 * More straightforward, we keep track of the users in a channel, which allows us to determine that. */
	/*! \todo BUGBUG FIXME This assumes that only one channel is remote (once client is NULL, i.e. the local BBS IRC network, and the other is a client to some remote IRC network).
	 * However, they could BOTH be remote, in which case we'd need to actually keep track of the members of BOTH sides.
	 * The use case of a remote to remote relay is probably uncommon but is possible so should be handled correctly. */
	if (strlen_zero(username)) {
		bbs_error("NAMES username is empty?\n");
		return;
	}
	stringlist_push(&cp->members, username); /* Keep track of the username without the client name prefixed */
}

static const char *numeric_name(int numeric)
{
	switch (numeric) {
		case 318:
			return "WHOIS";
		case 352:
			return "WHO";
		case 353:
			return "NAMES";
		default:
			return NULL;
	}
	__builtin_unreachable();
}

/*! \todo This info should be cached locally for a while (there could be lots of these requests in a busy channel...) */
static int wait_response(struct bbs_node *node, int fd, const char *requsername, int numeric, struct chan_pair *cp, const char *clientname, const char *channel, const char *origchan, const char *fullnick, const char *nick)
{
	char buf[3092] = "";
	int res = -1;
	char *bufpos, *line;
	size_t buflen = sizeof(buf) - 1;

	/* Only one pipe needed: they write, we read */

	/* To prevent deadlocks, we'll only wait on the pipe for a limited amount of time. */
	pthread_mutex_lock(&nicklock);
	numericclient = clientname;
	if (pipe(nickpipe)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		pthread_mutex_unlock(&nicklock);
		return -1;
	}
	switch (numeric) {
		case 318:
			bbs_irc_client_send(clientname, "%s %s", numeric_name(numeric), nick);
			break;
		case 352:
		case 353:
			bbs_irc_client_send(clientname, "%s %s", numeric_name(numeric), channel);
			break;
		default:
			bbs_error("Numeric %d not supported\n", numeric);
			goto cleanup;
	}
	/* Wait for the response to our request. */
	res = bbs_poll(nickpipe[0], 3000);
	if (res <= 0) {
		bbs_warning("Didn't receive response to %s (%d) query: returned %d (%s/%s/%s)\n", numeric_name(numeric), numeric, res, clientname, origchan, channel);
		res = -1;
		goto cleanup;
	}

	/* Read the full response, until there's no more data for 250ms or we get the END OF LIST numeric. Relay each message as soon as we get it. */
	/*! \todo Rewrite using bbs_readline */
	bufpos = buf;
	do {
		ssize_t readres = read(nickpipe[0], bufpos, buflen);
		if (readres <= 0) {
			break;
		}
		bufpos += (size_t) readres;
		buflen -= (size_t) readres;
	} while (bbs_poll(nickpipe[0], 250) > 0);

	*bufpos = '\0';

#define RELAY_DEBUG
#define PREFIX_NAMES

#ifdef RELAY_DEBUG
#define SEND_RESP(fd, fmt, ...) bbs_debug(9, fmt, ## __VA_ARGS__); bbs_auto_fd_writef(node, fd, fmt, ## __VA_ARGS__);
#else
#define SEND_RESP(fd, fmt, ...) bbs_auto_fd_writef(node, fd, fmt, ## __VA_ARGS__)
#endif

	/* Now, parse the response, and send the results back. */
	bufpos = buf;
	stringlist_empty(&cp->members);
	while ((line = strsep(&bufpos, "\n"))) {
		const char *w1, *w2, *w3, *w4, *w5, *w6, *w7, *w8;
		char *rest;
		int mynumeric;
#ifdef PREFIX_NAMES
		char restbuf[512] = "";
		char *restpos;
		size_t restlen;
		char *restptr;
		char newnick[64];

		SAFE_FAST_BUF_INIT(restbuf, sizeof(restbuf), restpos, restlen);
#endif
		if (strlen_zero(line)) {
			continue; /* It happens... */
		}
		w1 = strsep(&line, " ");
		w2 = strsep(&line, " ");
		w3 = strsep(&line, " ");
		w4 = strsep(&line, " ");
		rest = line;
		mynumeric = atoi(S_IF(w2));
		switch (numeric) {
			case 318:
				/* We need to replace a few things, but can otherwise pass it back intact.
				 * - The third word is to whom we are sending the response. This was the client's username, but should be replaced with requsername.
				 * - The fourth word was the nick on which we did the lookup. We want to replace this nick back with fullnick, which is what the original lookup was for. */
				w3 = requsername;
				w4 = fullnick;
				/* Skip end of */
				if (mynumeric == 318) {
					break;
				} else {
					res = 0;
				}
				SEND_RESP(fd, "%s %s %s %s %s\r\n", w1, w2, w3, w4, rest);
				break;
			case 352:
				/* Pass it on if it matches the numeric (skip end of) */
				if (mynumeric != numeric) {
#ifdef RELAY_DEBUG
					bbs_debug(5, "Skipping numeric %d\n", mynumeric);
#endif
					break;
				}
				w3 = requsername; /* Replace client username with requsername */
				w4 = origchan; /* Replace channel name */
				/* The 8th word contains the nick */
				w5 = strsep(&rest, " ");
				w6 = strsep(&rest, " ");
				w7 = strsep(&rest, " ");
				w8 = strsep(&rest, " ");
				snprintf(newnick, sizeof(newnick), "%s/%s", clientname, w8); /* Add the prefix to the beginning of the nick */
				w8 = newnick;
				res = 0;
				SEND_RESP(fd, "%s %s %s %s %s %s %s %s %s\r\n", w1, w2, w3, w4, w5, w6, w7, w8, rest);
				break;
			case 353: /* NAMES replies are super important: IRC clients use this to construct the nicklist sidebar */
				/* Pass it on if it matches the numeric (skip end of) */
				if (mynumeric != numeric) {
#ifdef RELAY_DEBUG
					bbs_debug(5, "Skipping numeric %d\n", mynumeric);
#endif
					break;
				}
				w3 = requsername; /* Replace client username with requsername */
				w5 = strsep(&rest, " ");
				w5 = origchan; /* Replace channel name */
				res = 0;

#ifdef PREFIX_NAMES
				if (rest && *rest == ':') {
					int n = 0;
					rest++;
					SAFE_FAST_APPEND_NOSPACE(restbuf, sizeof(restbuf), restpos, restlen, ":");

					while ((restptr = strsep(&rest, " "))) {
						/* Use clientname rather than channel name on the other network (channel names could be the same, and are longer)
						 * Benefit of "prefixing" like this is also that any channel prefixes like @ or + will no longer be at the beginning,
						 * so those modes/flags from other channels won't mean anything here (as they don't).
						 * Update: Turns out though that this messes with other things, like being able to directly use these nicknames,
						 * so stip the prefixes anyways, leaving just the username.
						 */
						while (*restptr == PREFIX_FOUNDER[0] || *restptr == PREFIX_ADMIN[0] || *restptr == PREFIX_OP[0] || *restptr == PREFIX_HALFOP[0] || *restptr == PREFIX_VOICE[0]) {
							restptr++;
						}

						cp_add_member(cp, restptr);
						snprintf(newnick, sizeof(newnick), "%s%s/%s", n ? " " : "", clientname, restptr);
						SAFE_FAST_APPEND_NOSPACE(restbuf, sizeof(restbuf), restpos, restlen, "%s", newnick);
						n++;
					}
					rest = restbuf;
					bbs_debug(5, "Translated nicks: %s\n", rest);
				}
#else
				{
					char namescopy[512];
					char *name, *namesdup = namescopy;
					safe_strncpy(namescopy, rest, sizeof(namescopy));
					while ((name = strsep(&namesdup, " "))) {
						cp_add_member(cp, name);
					}
				}
#endif
				SEND_RESP(fd, "%s %s %s %s %s %s\r\n", w1, w2, w3, w4, w5, rest);
				break;
			default:
				bbs_error("Unhandled numeric %d?\n", numeric);
				break;
		}
	}

cleanup:
	numericclient = NULL;
	close(nickpipe[0]);
	close(nickpipe[1]);
	nickpipe[0] = nickpipe[1] = -1;
	pthread_mutex_unlock(&nicklock);
	return res;
}

static int cp_contains_user(struct chan_pair *cp, const char *username)
{
	int res;

	/* XXX This is a global mutex (not even a rwlock), so this is not optimal */
	pthread_mutex_lock(&nicklock);
	res = stringlist_contains(&cp->members, username);
	pthread_mutex_unlock(&nicklock);

	return res;
}

static int cli_irc_relaymembers(struct bbs_cli_args *a)
{
	struct chan_pair *cp;

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		const char *s;
		int c = 0;
		struct stringitem *i = NULL;
		bbs_dprintf(a->fdout, "Client %s/%s - channels %s/%s\n", S_IF(cp->client1), S_IF(cp->client2), cp->channel1, cp->channel2);
		while ((s = stringlist_next(&cp->members, &i))) {
			bbs_dprintf(a->fdout, "- %s\n", s);
			c++;
		}
		if (c) {
			bbs_dprintf(a->fdout, "-- %d member%s\n", c, ESS(c));
		}
	}
	RWLIST_UNLOCK(&mappings);
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
	irc_relay_send_notice(sender, CHANNEL_USER_MODE_NONE, "IRC", sender, NULL, notice, NULL); /* XXX This mask is not meaningful (IRC/sender) */
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
	struct chan_pair *cp;
	char fullnick[84], fullnick2[84];
	char *nick = NULL;
	const char *origchan = NULL;
	const char *clientname = NULL; /* Came from native IRC server. We need a pointer, can't use NULL directly. */

	if (numeric == 318 && !user) {
#ifdef RELAY_DEBUG
		bbs_debug(7, "Ignoring numeric %d\n", numeric);
#endif
		return 0; /* Don't even care. Certainly, don't crash. */
	} else if (numeric != 318 && !channel) {
#ifdef RELAY_DEBUG
		bbs_debug(7, "Ignoring numeric %d\n", numeric);
#endif
		return 0;
	}

	if (user) {
		/* e.g. fullnick now contains clientname/nick */
		/* We can't use find_chanpair directly since we don't actually have a channel (channel == NULL).
		 * The channel name is actually contained in the user portion, so we have to split that first.
		 * Makes sense, since depending on what the channel part is, we may have to use a different client. */
		safe_strncpy(fullnick, user, sizeof(fullnick));
		safe_strncpy(fullnick2, user, sizeof(fullnick2));
		nick = fullnick2;
		clientname = strsep(&nick, "/");
		if (!nick || !clientname) {
			return 0; /* Could happen, for requests that we don't care about. */
		}
		/* The channel of interest is actually associated with a client, i.e. client is NOT NULL.
		 * However, the other end of it, our side, is NULL. Therefore, look for a pair
		 * where one side has a NULL client, and the other side contains a non-NULL client
		 * and the specified client name. */
		cp = find_chanpair_reverse(clientname);
	} else {
		cp = find_chanpair(NULL, channel);
	}

	bbs_debug(8, "Numeric: %d, channel: %s, user: %s, nick: %s, client: %s\n", numeric, S_IF(channel), S_IF(user), S_IF(nick), S_IF(clientname));

	if (!cp) { /* Not something we care about */
		bbs_debug(9, "No nicklist match for channel %s/%s\n", S_IF(clientname), channel);
		return 0;
	}

	if (cp->ircuser && strcasecmp(cp->ircuser, requsername)) {
		notify_unauthorized(requsername, channel, cp->ircuser);
		return 0;
	}

	if (numeric != 318) {
		channel = cp->client1 ? cp->channel1 : cp->channel2;
		origchan = cp->client1 ? cp->channel2 : cp->channel1;
	}

	/* This is IRC, so we can just do pass on the request, then pass back the response. Of course, easier said than done... */
	/* We know that one client is NULL and one is non-NULL, we want the side that isn't NULL. */
	if (!cp->client1) {
		/* It came from channel1, so provide names from channel2 */
		bbs_debug(8, "Relaying nicknames from %s/%s\n", S_IF(cp->client2), cp->channel2);
		if (!cp->client2) {
			/* The requesting channel is on the native server,
			 * and in this case the destination one (from which we want names) is also.
			 * Just bail out, because we shouldn't provide names when relaying between
			 * our own channels, it just doesn't make any sense.
			 *
			 * Furthermore, this case really shouldn't ever occur.
			 * If we're doing lookups for someone on THIS server,
			 * then this callback will never get hit, since we'll find the user on the IRC server.
			 * If the user doesn't exist there, won't exist here either because we'll be checking the same place.
			 *
			 * Only do this across networks. */
			bbs_warning("Both clients are NULL?\n");
			return 0;
		}
		/* Determine who's in the "real" channel using our client */
		/* Only one request at a time, to prevent interleaving of responses */
		wait_response(node, fd, requsername, numeric, cp, cp->client2, channel, origchan, fullnick, nick);
		/*! \todo BUGBUG Regarding the below comment, we need to return 1
		 * to stop the traversal and indicate a user was found, which IS appropriate here.
		 * But in the cases where multiple relay modules could match, we should probably still
		 * return 1, and net_irc can traverse all the callbacks anyways. */
		return 1; /* Even though we matched, there could be matches in other relays */
	} else if (!cp->client2) {
		/* It came from channel1, so provide names from channel1 */
		bbs_debug(8, "Relaying nicknames from %s/%s\n", S_IF(cp->client1), cp->channel1);
		if (!cp->client1) {
			bbs_warning("Both clients are NULL?\n");
			return 0; /* See comments above in first map case */
		}
		wait_response(node, fd, requsername, numeric, cp, cp->client1, channel, origchan, fullnick, nick);
		return 0; /* Even though we matched, there could be matches in other relays */
	} else {
		bbs_debug(8, "Case we don't care about\n");
	}

	return 0;
}

static int privmsg_cb(const char *recipient, const char *sender, const char *msg)
{
	char buf[128];
	char *clientname, *destrecip;
	struct chan_pair *cp;

	safe_strncpy(buf, recipient, sizeof(buf));
	/* Format is clientname/recipient */
	destrecip = buf;
	clientname = strsep(&destrecip, "/");

	cp = client_exists(clientname);
	if (!cp) { /* Not something we care about */
		bbs_debug(9, "No relay match for client %s (%s -> %s)\n", clientname, sender, recipient);
		return 0;
	}

	/* An IRC client with this client name exists, in mod_irc_client. */
	if (cp->ircuser) {
		bbs_irc_client_msg(clientname, destrecip, NULL, "%s", msg); /* Don't prepend username for personal relays */
	} else {
		bbs_irc_client_msg(clientname, destrecip, NULL, "<%s> %s", sender, msg);
	}
	return 1;
}

/* XXX Lots of duplicated code follows */

/*! \brief Callback for messages received on native IRC server (from our server to the channel) */
static int netirc_cb(const char *channel, const char *sender, const char *msg)
{
	char fullmsg[510];
	int ctcp = 0;
	struct chan_pair *cp;
	const char *clientname = NULL; /* Came from native IRC server. We need a pointer, can't use NULL directly. */

	/* Message came from the native IRC server.
	 * This means that either client1 or client2 is NULL, and for the corresponding one,
	 * the channel name matches. */

	cp = find_chanpair(NULL, channel);
	if (!cp) { /* Not something we care about */
		bbs_debug(9, "No relay match for channel %s/%s\n", S_IF(clientname), channel);
		return 0;
	}

	/*! \todo Is there the potential for loops here, currently? If it's a NOTICE, drop it and don't relay?  */

	if (sender && cp->ircuser && strcasecmp(cp->ircuser, sender)) {
		notify_unauthorized(sender, channel, cp->ircuser);
		return 0;
	}

	if (!sender && !cp->relaysystem) {
		bbs_debug(8, "Not relaying system message\n");
		return 0;
	}

	if ((int) ignore_join_start && time(NULL) < modstart + (int) ignore_join_start && strstr(msg, "has joined")) {
		bbs_debug(2, "Not relaying JOIN message '%s' due to startupjoinignore setting.\n", msg);
		return 0;
	}

	/* Account for CTCP messages: need to relay these properly. */
	if (*msg == 0x01) {
		const char *ctcpactionend;
		int ctcpactionbytes;

		msg++; /* CTCP message ends in 0x01 so we don't have to add 0x01 to the end using snprintf */
		ctcpactionend = strchr(msg, ' ');
		if (ctcpactionend) {
			ctcpactionbytes = (int) (ctcpactionend - msg + 1);
			ctcp = 1;
			/* Turn 0x01ACTION action0x01 into 0x01ACTION <sender> action0x01 */
			snprintf(fullmsg, sizeof(fullmsg), "%c%.*s <%s> %s", 0x01, ctcpactionbytes, msg, sender, msg + ctcpactionbytes);
		} else {
			bbs_warning("CTCP message is invalid\n");
		}
	}

	/* Relay it to the other side of the mapping */
	if (MAP1_MATCH(cp, clientname, channel)) {
		/* It came from channel1, so send to channel2 */
		bbs_debug(8, "Relaying from %s/%s => %s/%s: %s\n", S_IF(cp->client1), cp->channel1, S_IF(cp->client2), cp->channel2, msg);
		if (cp->client2) {
			if (sender && !cp->ircuser) { /* We're sending to a real IRC channel using a client, so we need to pack the sender name into the message itself, if present. */
				if (!ctcp) {
					if (snprintf(fullmsg, sizeof(fullmsg), "<%s> %s", sender, msg) >= (int) sizeof(fullmsg)) {
						bbs_warning("Truncation when prefixing sending username to message\n");
					}
				}
				msg = fullmsg;
			}
			bbs_irc_client_msg(cp->client2, cp->channel2, sender, "%s", msg); /* Don't call bbs_irc_client_msg with a NULL client or it will use the default (first) one in mod_irc_client */
		} else { /* Relay to native IRC server */
			irc_relay_send(cp->channel2, CHANNEL_USER_MODE_NONE, S_OR(cp->client1, "IRC"), S_OR(sender, cp->channel1), NULL, msg, cp->ircuser);
		}
	} else {
		/* It came from channel2, so send to channel1 */
		bbs_debug(8, "Relaying from %s/%s => %s/%s: %s\n", S_IF(cp->client2), cp->channel2, S_IF(cp->client1), cp->channel1, msg);
		if (cp->client1) {
			if (sender && !cp->ircuser) { /* We're sending to a real IRC channel using a client, so we need to pack the sender name into the message itself, if present. */
				if (!ctcp) {
					if (snprintf(fullmsg, sizeof(fullmsg), "<%s> %s", sender, msg) >= (int) sizeof(fullmsg)) {
						bbs_warning("Truncation when prefixing sending username to message\n");
					}
				}
				msg = fullmsg;
			}
			bbs_irc_client_msg(cp->client1, cp->channel1, sender, "%s", msg);
		} else {
			irc_relay_send(cp->channel1, CHANNEL_USER_MODE_NONE, S_OR(cp->client2, "IRC"), S_OR(sender, cp->channel2), NULL, msg, cp->ircuser);
		}
	}

	return 0;
}

static void *names_query(void *varg)
{
	const char *channel, *origchan;
	struct chan_pair *cp = varg;

	channel = cp->client1 ? cp->channel1 : cp->channel2;
	origchan = cp->client1 ? cp->channel2 : cp->channel1;
	bbs_debug(3, "First activity for chanpair %s/%s %s/%s, fetching members of channel %s\n", S_IF(cp->client1), S_IF(cp->client2), cp->channel1, cp->channel2, channel);
	wait_response(NULL, -1, NULL, 353, cp, S_OR(cp->client1, cp->client2), channel, origchan, NULL, NULL);

	cp->gotnames = 2; /* Do not lock names_query_lock here or we could deadlock if somebody waiting for us to exit has it locked. */
	return NULL;
}

static void ensure_names_aware(struct chan_pair *cp)
{
	/* If we joined the channel with members already in it,
	 * we're reliant on some user on the local IRC network issuing a "NAMES"
	 * that allows us to piggyback on that and capture the list of channel members.
	 * If that never happens and a user quits, then in our current state,
	 * we're not aware that that user was ever in the channel, so we incorrectly decline to relay it.
	 * To prevent this, this lazily loads the channel members the first time a chan_pair is referenced.
	 * We do it lazily since we can't actually be sure that all IRC clients are ready when this module
	 * loads, since this could load a split instant after mod_irc_client at startup, and if so,
	 * it's not a good time to be making NAMES requests yet...
	 */
	pthread_mutex_lock(&cp->names_query_lock);
	if (cp->gotnames) {
		if (cp->gotnames == 2 && cp->names_thread) {
			/* It's done, join the thread */
			bbs_pthread_join(cp->names_thread, NULL);
			cp->names_thread = 0;
		}
	} else {
		cp->gotnames = 1; /* Don't do it again if one is already in progress, so mark completed when we start, rather than when the job finishes */
		bbs_pthread_create(&cp->names_thread, NULL, names_query, cp);
	}
	pthread_mutex_unlock(&cp->names_query_lock);
}

static void relay_quit(const char *clientname, const char *username, const char *msg)
{
	char sysmsg[512];
	struct chan_pair *cp;

	snprintf(sysmsg, sizeof(sysmsg), ":%s/%s QUIT :%s", clientname, username, S_IF(msg));
	bbs_debug(3, "Intercepting QUIT by %s/%s\n", clientname, username);
	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		/* We're looking for a match on the remote side (the local side could be NULL). */
		ensure_names_aware(cp);
		if (!EITHER_CLIENT_MATCH(cp, clientname)) {
			continue;
		}
		if (!cp->relaysystem) {
			bbs_debug(8, "Not relaying system message for client %s/%s\n", S_IF(cp->client1), S_IF(cp->client2));
			continue;
		}
		if (cp_contains_user(cp, username)) {
			bbs_debug(6, "Client %s, channel %s contains user %s, relaying QUIT...\n", clientname, username, username);
			if (!cp->channel2) { /* We're relaying from the remote client to the native network */
				irc_relay_raw_send(cp->channel2, sysmsg);
			} else {
				irc_relay_raw_send(cp->channel1, sysmsg);
			}
		}
	}
	RWLIST_UNLOCK(&mappings);
}

/*! \brief Callback for messages received on IRC client (from some server to our client) */
static void command_cb(const char *clientname, enum irc_callback_msg_type type, const char *channel, const char *prefix, int ctcp, const char *msg)
{
	char nativenick[64];
	char sysmsg[512];
	const char *ourchan;
	struct chan_pair *cp;

	if (type == CMD_QUIT) {
		/* Client quit messages don't have a channel associated with them (and there could be multiple).
		 * Since relays are per channel, not per network, we need to determine what channels this user was in, and relay to those channels.
		 * For this, we rely on clients on the network doing a periodic NAMES query,
		 * which we then cache in a list for each cp, which we'll consult now.
		 * There could be multiple cp's to which we need to relay, but we only need to check all the chan pairs for this client. */
		relay_quit(clientname, prefix, msg);
		return;
	}

	/* XXX In theory we should only need to do one traversal here. By the name alone, we should know if it's a channel or username */
	cp = find_chanpair(clientname, channel);
	if (!cp) { /* Probably not something we care about. It could be a private message, though. */
		cp = find_chanpair_by_client(clientname); /* If the client exists, then we can relay a private message */

		/* For a private message, channel is our (used for the relay) IRC user's username */
		if (!strlen_zero(msg) && *msg == '<') {
			/* Format is <sender> message.
			 * Our expected format is <sender> <recipient>: message, so we can actually route it the right user on the IRC server.
			 * Message will appear to be sent by clientname/<sender>. */
			char dup[512];
			char sendername[84];
			const char *recipient;
			char *message, *sender;
			safe_strncpy(dup, msg, sizeof(dup));
			message = dup;
			sender = strsep(&message, " ");
			if (cp && cp->ircuser) {
				recipient = cp->ircuser;
			} else { /* Only if not for a private relay */
				char *recipienttmp = strsep(&message, " ");
				if (strlen_zero(recipienttmp) || strlen_zero(message)) {
					bbs_debug(8, "Private message is not properly addressed, ignoring\n");
					/* Don't send an autoresponse saying "please use this messaging format", since there may be other consumers */
					return;
				}
				recipient = recipienttmp;
			}
			/* Strip <> */
			if (*sender == '<') {
				sender++;
			} else {
				return;
			}
			bbs_strterm(sender, '>');
			bbs_strterm(recipient, ':'); /* strip : */
			snprintf(sendername, sizeof(sendername), "%s/%s", clientname, sender);
			bbs_debug(8, "Received private message: %s -> %s: %s\n", sendername, recipient, message);
			irc_relay_send(recipient, CHANNEL_USER_MODE_NONE, clientname, sendername, NULL, message, cp ? cp->ircuser : NULL);
			return;
		}

		bbs_debug(9, "No relay match for channel %s/%s\n", clientname, channel);
		return;
	}

	ensure_names_aware(cp);

	if (strlen_zero(channel)) {
		bbs_debug(9, "No channel for message from %s\n", clientname);
		return;
	}

	/* In the unfortunate event that either configuration or a bug has allowed
	 * some kind of loop to happen, messages might bounce back and forth between
	 * two channels in perpetuity. However, because all the relay modules prefix
	 * nicknames with some identifier (the client name, in this case), we can
	 * easily detect something like this happening since the username will
	 * grow longer and longer when this happens until it is longer than the buffer size
	 * and then stays truncated forever.
	 * Therefore, if we detect an unreasonably long nickname, just drop it.
	 * Since this is coming from IRC, and IRC doesn't allow super long nicks,
	 * this is pretty reliable.
	 * This is done for the interception cases below.
	 */

	switch (type) {
		case CMD_JOIN:
			/* Leave the hostmask (stuff after ~) intact... I guess? */
			/* The channel name to use is not channel, which is what the channel name is on the other side (client side).
			 * We need to use the name on OUR side. */
			/* Tack the client name on as a prefix, so it matches with the nicklist and doesn't cause a mixup
			 * Worst case scenario, the same nick might be in use on both sides, and this will really confuse clients if they're told they did something they didn't. */
			ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
			snprintf(sysmsg, sizeof(sysmsg), ":%s/%s JOIN %s", clientname, prefix, ourchan);
			bbs_debug(3, "Intercepting JOIN by %s/%s (%s -> %s)\n", clientname, prefix, channel, ourchan);
			if (strlen(prefix) >= 64) {
				bbs_warning("Potential IRC loop detected, dropping message\n");
			} else if (!cp->relaysystem) {
				bbs_debug(8, "Not relaying system message\n");
			} else if (ignore_join_start && time(NULL) < modstart + (int) ignore_join_start) {
				bbs_debug(2, "Not relaying JOIN by %s/%s (%s -> %s) due to startupjoinignore setting.\n", clientname, prefix, channel, ourchan);
			} else if (MAP1_MATCH(cp, clientname, channel)) {
				irc_relay_raw_send(cp->channel2, sysmsg);
			} else {
				irc_relay_raw_send(cp->channel1, sysmsg);
			}
			/* To keep our users list up to date, even if nobody on the network is issuing a NAMES query */
			if (!cp_contains_user(cp, prefix)) {
				pthread_mutex_lock(&nicklock);
				stringlist_push(&cp->members, prefix);
				pthread_mutex_unlock(&nicklock);
			}
			break;
		case CMD_PART:
			ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
			snprintf(sysmsg, sizeof(sysmsg), ":%s/%s PART %s", clientname, prefix, ourchan);
			bbs_debug(3, "Intercepting PART by %s/%s (%s -> %s)\n", clientname, prefix, channel, ourchan);
			if (strlen(prefix) >= 64) {
				bbs_warning("Potential IRC loop detected, dropping message\n");
			} else if (!cp->relaysystem) {
				bbs_debug(8, "Not relaying system message\n");
			} else if (MAP1_MATCH(cp, clientname, channel)) {
				irc_relay_raw_send(cp->channel2, sysmsg);
			} else {
				irc_relay_raw_send(cp->channel1, sysmsg);
			}
			/* To keep our users list up to date, even if nobody on the network is issuing a NAMES query */
			if (cp_contains_user(cp, prefix)) {
				pthread_mutex_lock(&nicklock);
				stringlist_remove(&cp->members, prefix);
				pthread_mutex_unlock(&nicklock);
			}
			break;
		case CMD_QUIT: /* This is academic, as QUIT is handled above */
			__builtin_unreachable();
#if 0
			ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
			snprintf(sysmsg, sizeof(sysmsg), ":%s/%s QUIT :%s", clientname, prefix, S_IF(msg));
			bbs_debug(3, "Intercepting QUIT by %s/%s (%s)\n", clientname, prefix, S_IF(msg));
			if (strlen(prefix) >= 64) {
				bbs_warning("Potential IRC loop detected, dropping message\n");
			} else if (!cp->relaysystem) {
				bbs_debug(8, "Not relaying system message\n");
			} else if (MAP1_MATCH(cp, clientname, channel)) {
				irc_relay_raw_send(cp->channel2, sysmsg);
			} else {
				irc_relay_raw_send(cp->channel1, sysmsg);
			}
#endif
			break;
		case CMD_PRIVMSG:
			snprintf(nativenick, sizeof(nativenick), "%s/%s", clientname, prefix);
			if (ctcp) {
				/* Must be an ACTION */
				ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
				bbs_debug(3, "Intercepting CTCP action by %s/%s (%s -> %s) - '%s'\n", clientname, prefix, channel, ourchan, msg);
				snprintf(sysmsg, sizeof(sysmsg), "%cACTION %s%c", 0x01, msg, 0x01);
				bbs_dump_string(sysmsg);
				msg = sysmsg;
			}
			/* Relay it to the other side of the mapping */
			if (MAP1_MATCH(cp, clientname, channel)) {
				/* It came from channel1, so send to channel2 */
				bbs_debug(8, "Relaying from %s/%s => %s/%s\n", S_IF(cp->client1), cp->channel1, S_IF(cp->client2), cp->channel2);
				if (cp->client2) { /* Relay to another (remote) IRC channel */
					bbs_irc_client_msg(cp->client2, cp->channel2, prefix, "%s", msg);
				} else { /* Relay to local IRC network */
					irc_relay_send(cp->channel2, CHANNEL_USER_MODE_NONE, S_OR(cp->client1, clientname), nativenick, NULL, msg, cp->ircuser);
				}
			} else {
				/* It came from channel2, so send to channel1 */
				bbs_debug(8, "Relaying from %s/%s => %s/%s\n", S_IF(cp->client2), cp->channel2, S_IF(cp->client1), cp->channel1);
				if (cp->client1) { /* Relay to another (remote) IRC channel */
					bbs_irc_client_msg(cp->client1, cp->channel1, prefix, "%s", msg);
				} else { /* Relay to local IRC network */
					irc_relay_send(cp->channel1, CHANNEL_USER_MODE_NONE, S_OR(cp->client2, clientname), nativenick, NULL, msg, cp->ircuser);
				}
			}
			break;
		default:
			break;
	}
}

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_irc_relay.conf", 1);

	if (!cfg) {
		bbs_error("File 'mod_irc_relay.conf' is missing, declining to load\n");
		return -1;
	}

	bbs_config_val_set_true(cfg, "general", "exposemembers", &expose_members);
	bbs_config_val_set_uint(cfg, "general", "startupjoinignore", &ignore_join_start);

	while ((section = bbs_config_walk(cfg, section))) {
		const char *client1 = NULL, *client2 = NULL, *channel1 = NULL, *channel2 = NULL;
		const char *ircuser = NULL;
		int relaysystem = 1;
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Not a channel mapping section, skip */
		}

		/* Category name is not relevant, only the contents. */

		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcasecmp(key, "client1")) {
				client1 = value;
			} else if (!strcasecmp(key, "channel1")) {
				channel1 = value;
			} else if (!strcasecmp(key, "client2")) {
				client2 = value;
			} else if (!strcasecmp(key, "channel2")) {
				channel2 = value;
			} else if (!strcasecmp(key, "relaysystem")) {
				relaysystem = S_TRUE(value);
			} else if (!strcasecmp(key, "ircuser")) {
				ircuser = value;
			} else {
				bbs_warning("Unknown directive: %s\n", key);
			}
		}
		if (!channel1 || !channel2) {
			bbs_warning("Section %s is incomplete, ignoring\n", bbs_config_section_name(section));
			continue;
		}
		add_pair(client1, channel1, client2, channel2, ircuser, relaysystem);
	}

	return 0;
}

static int cli_irc_relays(struct bbs_cli_args *a)
{
	struct chan_pair *cp;

	bbs_dprintf(a->fdout, "%-20s %-20s %-20s %-20s %9s %s\n", "Client 1", "Channel 1", "Client 2", "Channel 2", "RelaySys?", "IRC User");
	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		bbs_dprintf(a->fdout, "%-20s %-20s %-20s %-20s %9s %s\n", S_IF(cp->client1), S_IF(cp->channel1), S_IF(cp->client2), S_IF(cp->channel2), BBS_YN(cp->relaysystem), S_IF(cp->ircuser));
	}
	RWLIST_UNLOCK(&mappings);
	return 0;
}

static struct bbs_cli_entry cli_commands_irc[] = {
	BBS_CLI_COMMAND(cli_irc_relays, "irc relays", 2, "List all IRC-IRC relays", NULL),
	BBS_CLI_COMMAND(cli_irc_relaymembers, "irc relaymembers", 2, "List all known users in all remote IRC clients", NULL),
};

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	modstart = time(NULL);
	irc_relay_register(netirc_cb, nicklist, privmsg_cb);
	bbs_irc_client_msg_callback_register(command_cb, numeric_cb);
	bbs_cli_register_multiple(cli_commands_irc);
	return 0;
}

static int unload_module(void)
{
	if (nickpipe[0] != -1) {
		shutdown(nickpipe[0], SHUT_RDWR); /* Make any in-progress NAMES query exit now */
	}
	bbs_cli_unregister_multiple(cli_commands_irc);
	bbs_irc_client_msg_callback_unregister(command_cb);
	irc_relay_unregister(netirc_cb);
	list_cleanup();
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("IRC/IRC Relay", "net_irc.so,mod_irc_client.so");
