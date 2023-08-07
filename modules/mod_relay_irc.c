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
#include <bsd/string.h>

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/module.h"
#include "include/utils.h"
#include "include/node.h" /* use bbs_hostname */

/* Since this is an IRC/IRC relay, we depend on both the server and client modules */
#include "include/net_irc.h"
#include "include/door_irc.h"

static int expose_members = 1;
static unsigned int ignore_join_start = 0;

static int modstart;

struct chan_pair {
	const char *client1;
	const char *channel1;
	const char *client2;
	const char *channel2;
	const char *ircuser;
	unsigned int relaysystem:1;
	RWLIST_ENTRY(chan_pair) entry;
	char data[0];
};

static RWLIST_HEAD_STATIC(mappings, chan_pair);

static void list_cleanup(void)
{
	/* Clean up mappings */
	RWLIST_WRLOCK_REMOVE_ALL(&mappings, entry, free);
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

	bbs_assert_exists(channel);

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (MAP1_MATCH(cp, client, channel) || MAP2_MATCH(cp, client, channel)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

static struct chan_pair *find_chanpair_by_client(const char *client)
{
	struct chan_pair *cp = NULL;

	if (!client) {
		return NULL;
	}

	RWLIST_RDLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (cp->client1 && !strcmp(cp->client1, client)) {
			break;
		} else if (cp->client2 && !strcmp(cp->client2, client)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

static struct chan_pair *client_exists(const char *client)
{
	struct chan_pair *cp = NULL;

	RWLIST_WRLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (!strlen_zero(cp->client1) && !strcmp(client, cp->client1)) {
			break;
		} else if (!strlen_zero(cp->client2) && !strcmp(client, cp->client2)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

static struct chan_pair *find_chanpair_reverse(const char *clientname)
{
	struct chan_pair *cp = NULL;

	RWLIST_WRLOCK(&mappings);
	RWLIST_TRAVERSE(&mappings, cp, entry) {
		if (!cp->client1 && cp->client2 &&  !strcmp(cp->client2, clientname)) {
			break;
		}
		if (!cp->client2 && cp->client1 && !strcmp(cp->client1, clientname)) {
			break;
		}
	}
	RWLIST_UNLOCK(&mappings);
	return cp;
}

static pthread_mutex_t nicklock;
static int nickpipe[2] = { -1, -1 };
static const char *numericclient = NULL;

/*! \brief Numeric messages of interest from door_irc clients */
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
	bbs_debug(9, "Numeric %s\n", prefix);
	write(nickpipe[1], mybuf, (size_t) len);
}

/*! \todo This info should be cached locally for a while (there could be lots of these requests in a busy channel...) */
static int wait_response(int fd, const char *requsername, int numeric, const char *clientname, const char *channel, const char *origchan, const char *fullnick, const char *nick)
{
	char buf[3092];
	int res = -1;
	char *bufpos, *line;
	size_t buflen = sizeof(buf) - 1;

	/* Only one pipe needed: they write, we read */

	/* To prevent deadlocks, we'll only wait on the pipe for a limited amount of time. */
	pthread_mutex_lock(&nicklock);
	numericclient = clientname;
	if (pipe(nickpipe)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	}
	switch (numeric) {
		case 318:
			bbs_irc_client_send(clientname, "WHOIS %s", nick);
			break;
		case 352:
			bbs_irc_client_send(clientname, "WHO %s", channel);
			break;
		case 353:
			bbs_irc_client_send(clientname, "NAMES %s", channel);
			break;
		default:
			bbs_error("Numeric %d not supported\n", numeric);
			goto cleanup;
	}
	/* Wait for the response to our request. */
	res = bbs_poll(nickpipe[0], 3000);
	if (res <= 0) {
		bbs_warning("Didn't receive response to WHO/WHOIS/NAMES (%d) query: returned %d\n", numeric, res);
		res = -1;
		goto cleanup;
	}

	/* Read the full response, until there's no more data for 250ms or we get the END OF LIST numeric. Relay each message as soon as we get it. */
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
#define SEND_RESP(fd, fmt, ...) bbs_debug(9, fmt, ## __VA_ARGS__); dprintf(fd, fmt, ## __VA_ARGS__);
#else
#define SEND_RESP(fd, fmt, ...) dprintf(fd, fmt, ## __VA_ARGS__)
#endif

#undef dprintf
	/* Now, parse the response, and send the results back. */
	bufpos = buf;
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
						snprintf(newnick, sizeof(newnick), "%s%s/%s", n ? " " : "", clientname, restptr);
						SAFE_FAST_APPEND_NOSPACE(restbuf, sizeof(restbuf), restpos, restlen, "%s", newnick);
						n++;
					}
					rest = restbuf;
					bbs_debug(5, "Translated nicks: %s\n", rest);
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
static int nicklist(int fd, int numeric, const char *requsername, const char *channel, const char *user)
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
		wait_response(fd, requsername, numeric, cp->client2, channel, origchan, fullnick, nick);
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
		wait_response(fd, requsername, numeric, cp->client1, channel, origchan, fullnick, nick);
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

	/* Something with this client name exists, in door_irc. */
	if (cp->ircuser) {
		bbs_irc_client_msg(clientname, destrecip, "%s", msg); /* Don't prepend username for personal relays */
	} else {
		bbs_irc_client_msg(clientname, destrecip, "<%s> %s", sender, msg);
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
					snprintf(fullmsg, sizeof(fullmsg), "<%s> %s", sender, msg);
				}
				msg = fullmsg;
			}
			bbs_irc_client_msg(cp->client2, cp->channel2, "%s", msg); /* Don't call bbs_irc_client_msg with a NULL client or it will use the default (first) one in door_irc */
		} else { /* Relay to native IRC server */
			irc_relay_send(cp->channel2, CHANNEL_USER_MODE_NONE, S_OR(cp->client1, "IRC"), S_OR(sender, cp->channel1), NULL, msg, cp->ircuser);
		}
	} else {
		/* It came from channel2, so send to channel1 */
		bbs_debug(8, "Relaying from %s/%s => %s/%s: %s\n", S_IF(cp->client2), cp->channel2, S_IF(cp->client1), cp->channel1, msg);
		if (cp->client1) {
			if (sender && !cp->ircuser) { /* We're sending to a real IRC channel using a client, so we need to pack the sender name into the message itself, if present. */
				if (!ctcp) {
					snprintf(fullmsg, sizeof(fullmsg), "<%s> %s", sender, msg);
				}
				msg = fullmsg;
			}
			bbs_irc_client_msg(cp->client1, cp->channel1, "%s", msg);
		} else {
			irc_relay_send(cp->channel1, CHANNEL_USER_MODE_NONE, S_OR(cp->client2, "IRC"), S_OR(sender, cp->channel2), NULL, msg, cp->ircuser);
		}
	}

	return 0;
}

/*! \brief Callback for messages received on door_irc client (from some server to our client) */
static void doormsg_cb(const char *clientname, const char *channel, const char *msg)
{
	struct chan_pair *cp;
	const char *w;

	if (strlen_zero(channel)) {
		bbs_debug(9, "No channel for message from %s\n", clientname); /* Includes things like nick changes */
		return;
	}

	/* XXX In theory we should only need to do one traversal here. By the name alone, we should know if it's a channel or username */
	cp = find_chanpair(clientname, channel);
	if (!cp) { /* Probably not something we care about. It could be a private message, though. */
		cp = find_chanpair_by_client(clientname); /* If the client exists, then we can relay a private message */

		/* For a private message, channel is our (used for the relay) IRC user's username */
		if (*msg == '<') {
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

	/* XXX This is klunky... we're getting JOIN/PART messages through the PRIVMSG callback, due to how door_irc is structured (which is really an issue there, not here) */
	w = strchr(msg, ' ');
	if (w && !strcmp(w, " has " COLOR(COLOR_GREEN) "joined" COLOR_RESET "\n")) {
		char sysmsg[92];
		char nick[64];
		const char *ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
		safe_strncpy(nick, msg, sizeof(nick));
		bbs_strterm(nick, ' '); /* cut off " has joined" */
		if (strlen(nick) >= sizeof(nick)) {
			bbs_warning("Potential IRC loop detected, dropping message\n");
			return;
		}
		/* Leave the hostmask (stuff after ~) intact... I guess? */
		/* The channel name to use is not channel, which is what the channel name is on the other side (client side).
		 * We need to use the name on OUR side. */
		/* Tack the client name on as a prefix, so it matches with the nicklist and doesn't cause a mixup
		 * Worst case scenario, the same nick might be in use on both sides, and this will really confuse clients if they're told they did something they didn't. */
		snprintf(sysmsg, sizeof(sysmsg), ":%s/%s JOIN %s", clientname, nick, ourchan);
		bbs_debug(3, "Intercepting JOIN by %s/%s (%s -> %s)\n", clientname, nick, channel, ourchan);
		if (!cp->relaysystem) {
			bbs_debug(8, "Not relaying system message\n");
			return;
		} else if (ignore_join_start && time(NULL) < modstart + (int) ignore_join_start) {
			bbs_debug(2, "Not relaying JOIN by %s/%s (%s -> %s) due to startupjoinignore setting.\n", clientname, nick, channel, ourchan);
		} else if (MAP1_MATCH(cp, clientname, channel)) {
			irc_relay_raw_send(cp->channel2, sysmsg);
		} else {
			irc_relay_raw_send(cp->channel1, sysmsg);
		}
		return;
	} else if (w && !strcmp(w, " has " COLOR(COLOR_RED) "left" COLOR_RESET "\n")) {
		char sysmsg[92];
		char nick[64];
		const char *ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
		safe_strncpy(nick, msg, sizeof(nick));
		bbs_strterm(nick, ' '); /* cut off " has left" */
		if (strlen(nick) >= sizeof(nick)) {
			bbs_warning("Potential IRC loop detected, dropping message\n");
			return;
		}
		snprintf(sysmsg, sizeof(sysmsg), ":%s/%s PART %s", clientname, nick, ourchan);
		bbs_debug(3, "Intercepting PART by %s/%s (%s -> %s)\n", clientname, nick, channel, ourchan);
		if (!cp->relaysystem) {
			bbs_debug(8, "Not relaying system message\n");
			return;
		} else if (MAP1_MATCH(cp, clientname, channel)) {
			irc_relay_raw_send(cp->channel2, sysmsg);
		} else {
			irc_relay_raw_send(cp->channel1, sysmsg);
		}
		return;
	} else if (w && STARTS_WITH(w, " has " COLOR(COLOR_RED) "quit" COLOR_RESET "\n")) {
		char sysmsg[92];
		char nick[64];
		const char *ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
		safe_strncpy(nick, msg, sizeof(nick));
		bbs_strterm(nick, ' '); /* cut off " has quit" */
		if (strlen(nick) >= sizeof(nick)) {
			bbs_warning("Potential IRC loop detected, dropping message\n");
			return;
		}
		snprintf(sysmsg, sizeof(sysmsg), ":%s/%s QUIT %s", clientname, nick, ourchan);
		bbs_debug(3, "Intercepting QUIT by %s/%s (%s -> %s)\n", clientname, nick, channel, ourchan);
		if (!cp->relaysystem) {
			bbs_debug(8, "Not relaying system message\n");
			return;
		} else if (MAP1_MATCH(cp, clientname, channel)) {
			irc_relay_raw_send(cp->channel2, sysmsg);
		} else {
			irc_relay_raw_send(cp->channel1, sysmsg);
		}
		return;
	} else if (w && STARTS_WITH(msg, "[ACTION] ")) { /* Hack to detect CTCP messages, since we've lost the 0x01 and all that */
		char sysmsg[512];
		char actionmsg[493];
		char nick[64];
		const char *meaction;
		const char *ourchan = MAP1_MATCH(cp, clientname, channel) ? cp->channel2 : cp->channel1;
		bbs_strncpy_until(nick, msg, sizeof(nick), ' ');
		meaction = strstr(msg, "[ACTION] ");
		if (meaction) {
			meaction += STRLEN("[ACTION] ");
			bbs_strncpy_until(actionmsg, meaction, sizeof(actionmsg), '\n'); /* XXX Seems to be a LF in the message, get rid of it */
			snprintf(sysmsg, sizeof(sysmsg), "PRIVMSG %s :%cACTION %s%c", ourchan, 0x01, actionmsg, 0x01);
			bbs_dump_string(sysmsg);
			bbs_debug(3, "Intercepting CTCP action by %s/%s (%s -> %s) - '%s'\n", clientname, nick, channel, ourchan, actionmsg);
			if (MAP1_MATCH(cp, clientname, channel)) {
				irc_relay_raw_send(cp->channel2, sysmsg);
			} else {
				irc_relay_raw_send(cp->channel1, sysmsg);
			}
			return;
		}
	}

	/* Relay it to the other side of the mapping */
	if (MAP1_MATCH(cp, clientname, channel)) {
		/* It came from channel1, so send to channel2 */
		bbs_debug(8, "Relaying from %s/%s => %s/%s\n", S_IF(cp->client1), cp->channel1, S_IF(cp->client2), cp->channel2);
		if (cp->client2) {
			bbs_irc_client_msg(cp->client2, cp->channel2, "%s", msg);
		} else {
			char nativenick[64];
			char msgbuf[512];
			char *tmp;
			const char *sendnick = cp->channel1;
			/* Message format is something like "<sender> Actual message" */
			if (*msg == '<') {
				safe_strncpy(msgbuf, msg, sizeof(msgbuf));
				tmp = strchr(msgbuf, '>');
				if (msg) {
					*tmp++ = '\0';
					msg = tmp;
					sendnick = msgbuf + 1;
					/* Okay, now the message is just the message, and we have extracted the real sender name */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
					/* Truncation is acceptable since a nickname isn't going to be that long, and I'm not allocating a larger buffer to silence the warning. */
					snprintf(nativenick, sizeof(nativenick), "%s/%s", clientname,  sendnick); /* Use the clientname, not the channel name on the other side */
					sendnick = nativenick;
					/* Now we have a unique nick that doesn't conflict with this same nick on our local IRC server */
				}
			}
			irc_relay_send(cp->channel2, CHANNEL_USER_MODE_NONE, S_OR(cp->client1, clientname), sendnick, NULL, msg, cp->ircuser);
		}
	} else {
		/* It came from channel2, so send to channel1 */
		bbs_debug(8, "Relaying from %s/%s => %s/%s\n", S_IF(cp->client2), cp->channel2, S_IF(cp->client1), cp->channel1);
		if (cp->client1) {
			bbs_irc_client_msg(cp->client1, cp->channel1, "%s", msg);
		} else {
			char nativenick[64];
			char msgbuf[512];
			char *tmp;
			const char *sendnick = cp->channel2;
			/* Message format is something like "<sender> Actual message" */
			if (*msg == '<') {
				safe_strncpy(msgbuf, msg, sizeof(msgbuf));
				tmp = strchr(msgbuf, '>');
				if (msg) {
					*tmp++ = '\0';
					msg = tmp;
					sendnick = msgbuf + 1;
					/* Okay, now the message is just the message, and we have extracted the real sender name */
					snprintf(nativenick, sizeof(nativenick), "%s/%s", clientname,  sendnick);
#pragma GCC diagnostic pop /* -Wformat-truncation */
					sendnick = nativenick;
					/* Now we have a unique nick that doesn't conflict with this same nick on our local IRC server */
				}
			}
			irc_relay_send(cp->channel1, CHANNEL_USER_MODE_NONE, S_OR(cp->client2, clientname), sendnick, NULL, msg, cp->ircuser);
		}
	}
}

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_relay_irc.conf", 1);

	if (!cfg) {
		bbs_error("File 'mod_relay_irc.conf' is missing, declining to load\n");
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

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	pthread_mutex_init(&nicklock, NULL);
	modstart = (int) time(NULL);

	irc_relay_register(netirc_cb, nicklist, privmsg_cb, BBS_MODULE_SELF);
	bbs_irc_client_msg_callback_register(doormsg_cb, numeric_cb, BBS_MODULE_SELF);
	return 0;
}

static int unload_module(void)
{
	bbs_irc_client_msg_callback_unregister(doormsg_cb);
	irc_relay_unregister(netirc_cb);
	list_cleanup();
	pthread_mutex_destroy(&nicklock);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("IRC/IRC Relay", "net_irc.so,door_irc.so");
