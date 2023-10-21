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
 * \brief IRC client
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h> /* use gettimeofday */

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/door.h"
#include "include/term.h"
#include "include/linkedlists.h"
#include "include/utils.h"
#include "include/config.h"
#include "include/auth.h"

#define EXPOSE_IRC_MSG

/* Most IRC client stuff is handled directly in mod_irc_client,
 * but for one-off connections, door_irc still runs a client directly. */
#include <lirc/irc.h>

#include "include/mod_irc_client.h"

struct participant {
	struct bbs_node *node;
	struct client_relay *client;		/* Reference to the underlying client */
	const char *channel;				/* Channel */
	int chatpipe[2];					/* Pipe to store data */
	RWLIST_ENTRY(participant) entry;	/* Next participant */
};

RWLIST_HEAD(participants, participant);

struct client_relay {
	RWLIST_ENTRY(client_relay) entry; 	/* Next client */
	struct participants participants; 	/* List of participants */
	const char *name;					/* Unique client name */
	char data[];
};

static RWLIST_HEAD_STATIC(door_irc_clients, client_relay);

static void leave_client(struct client_relay *client, struct participant *participant)
{
	struct participant *p;

	/* Lock the entire list first */
	RWLIST_WRLOCK(&door_irc_clients);
	RWLIST_WRLOCK(&client->participants);
	p = RWLIST_REMOVE(&client->participants, participant, entry);
	if (p) {
		/* Close the pipe */
		close(p->chatpipe[0]);
		close(p->chatpipe[1]);
		/* Free */
		free(p);
	} else {
		bbs_error("Failed to remove participant %p (node %d) from client %s?\n", participant, participant->node->id, client->name);
	}
	RWLIST_UNLOCK(&client->participants);
	if (RWLIST_EMPTY(&client->participants)) {
		client = RWLIST_REMOVE(&door_irc_clients, client, entry);
		bbs_assert_exists(client);
		free(client);
	}
	RWLIST_UNLOCK(&door_irc_clients);
}

static struct participant *join_client(struct bbs_node *node, const char *name)
{
	struct participant *p;
	struct client_relay *client;

	RWLIST_WRLOCK(&door_irc_clients);
	RWLIST_TRAVERSE(&door_irc_clients, client, entry) {
		if (!strcasecmp(client->name, name)) {
			break;
		}
	}
	if (!client) {
		/* If it doesn't exist yet, dynamically create it
		 * if it's a client that exists in mod_irc_client. */
		if (bbs_irc_client_exists(name)) {
			client = calloc(1, sizeof(*client) + strlen(name) + 1);
		}
		if (!client) {
			bbs_error("IRC client %s doesn't exist\n", name);
			RWLIST_UNLOCK(&door_irc_clients);
			return NULL;
		}
		bbs_assert_exists(name);
		strcpy(client->data, name); /* Safe */
		client->name = client->data;
		bbs_debug(3, "Dynamically created client '%s'\n", client->name);
		bbs_assert_exists(client->name);
		RWLIST_INSERT_HEAD(&door_irc_clients, client, entry);
	}
	/* Okay, we have the client. Add the newcomer to it. */
	p = calloc(1, sizeof(*p));
	if (ALLOC_FAILURE(p)) {
		RWLIST_UNLOCK(&door_irc_clients);
		return NULL;
	}
	p->node = node;
	p->client = client;
	if (pipe(p->chatpipe)) {
		bbs_error("Failed to create pipe\n");
		free(p);
		RWLIST_UNLOCK(&door_irc_clients);
		return NULL;
	}
	RWLIST_INSERT_HEAD(&client->participants, p, entry);
	RWLIST_UNLOCK(&door_irc_clients);
	return p;
}

/* Forward declarations */
static int __attribute__ ((format (gnu_printf, 5, 6))) _chat_send(struct client_relay *client, struct participant *sender, const char *channel, int dorelay, const char *fmt, ...);

#define relay_to_local(client, channel, fmt, ...) _chat_send(client, NULL, channel, 0, fmt, __VA_ARGS__)

static int __chat_send(struct client_relay *client, struct participant *sender, const char *channel, int dorelay, const char *msg, int len)
{
	time_t now;
	struct tm sendtime;
	char datestr[18];
	size_t timelen;
	struct participant *p;

	/* Calculate the current time once, for everyone, using the server's time (sorry if participants are in different time zones) */
	now = time(NULL);
	localtime_r(&now, &sendtime);
	/* So, %P is lowercase and %p is uppercase. Just consult your local strftime(3) man page if you don't believe me. Good grief. */
	strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime); /* mm-dd hh:mm:ssPP + space at end (before message) = 17 chars */
	timelen = strlen(datestr); /* Should be 17 */
	bbs_assert(timelen == 17);

	/* If sender is set, it's safe to use even with no locks, because the sender is a calling function of this one */
	if (sender) {
		bbs_debug(7, "Broadcasting %s to %s,%s (except node %d): %s%.*s\n", dorelay ? "to IRC" : "from IRC", client->name, channel, sender->node->id, datestr, len, msg);
	} else {
		bbs_debug(7, "Broadcasting %s to %s,%s: %s%.*s\n", dorelay ? "to IRC" : "from IRC", client->name, channel, datestr, len, msg);
	}

	/* Relay the message to everyone */
	RWLIST_RDLOCK(&client->participants);
	if (dorelay) {
		bbs_irc_client_send(client->name, channel, msg); /* Actually send to IRC */
	}
	RWLIST_TRAVERSE(&client->participants, p, entry) {
		ssize_t res;
		/* We're intentionally relaying to other BBS nodes ourselves, separately from IRC, rather than
		 * just enabling echo on the IRC client and letting that bounce back for other participants.
		 * This is because we don't want our own messages to echo back to ourselves,
		 * and rather than parse messages to figure out if we should ignore something we just sent,
		 * it's easier to not have to ignore anything in the first place (at least for this purpose, still need to do channel filtering) */
		if (p == sender) {
			continue; /* Don't send a sender's message back to him/herself */
		}
		/* XXX Restricts users to a single channel, currently */
		if (!strlen_zero(channel) && strcmp(p->channel, channel)) {
			continue; /* Channel filter doesn't match for this participant. A participant can only be in 1 channel via this door (unlike IRC in general). */
		}
		if (!NODE_IS_TDD(p->node)) {
			res = write(p->chatpipe[1], datestr, timelen); /* Don't send timestamps to TDDs, for brevity */
			if (res <= 0) {
				bbs_error("write failed: %s\n", strerror(errno));
			}
		}
		res = write(p->chatpipe[1], msg, (size_t) len);
		if (res <= 0) {
			bbs_error("write failed: %s\n", strerror(errno));
			continue; /* Even if one send fails, don't fail all of them */
		}
	}
	RWLIST_UNLOCK(&client->participants);
	return 0;
}

#define chat_send(client, sender, channel, fmt, ...) _chat_send(client, sender, channel, 1, fmt, __VA_ARGS__)

#pragma GCC diagnostic ignored "-Wredundant-decls"
/*
 * Forward declaration needed since __attribute__ can only be used with declarations, not definitions.
 * See http://www.unixwiz.net/techtips/gnu-c-attributes.html#compat
 * We only need the redundant declarations for static functions with attributes.
 */
static int __attribute__ ((format (gnu_printf, 5, 6))) _chat_send(struct client_relay *client, struct participant *sender, const char *channel, int dorelay, const char *fmt, ...);

/*!
 * \param client
 * \param sender If NULL, the message will be sent to the sender, if specified, the message will not be sent to this participant
 * \param channel
 * \param dorelay
 * \param fmt
 */
static int __attribute__ ((format (gnu_printf, 5, 6))) _chat_send(struct client_relay *client, struct participant *sender, const char *channel, int dorelay, const char *fmt, ...)
{
	char *buf;
	int res, len;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* No format specifiers in the format string, just do it directly to avoid an unnecessary allocation. */
		return __chat_send(client, sender, channel, dorelay, fmt, (int) strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	res = __chat_send(client, sender, channel, dorelay, buf, len);
	free(buf);
	return res;
}
#pragma GCC diagnostic pop

static int participant_relay(struct bbs_node *node, struct participant *p, const char *channel)
{
	char buf[384];
	char buf2[sizeof(buf)];
	ssize_t res;
	struct client_relay *c = p->client;

	/* Join the channel */
	bbs_node_clear_screen(node);
	chat_send(c, NULL, channel, "%s@%d has joined %s\n", bbs_username(node->user), p->node->id, channel);

	bbs_node_unbuffer(node); /* Unbuffer so we can receive keys immediately. Otherwise, might print a message while user is typing */

	for (;;) {
		/* We need to poll both the node as well as the participant (chat) pipe */
		res = bbs_node_poll2(node, SEC_MS(10), p->chatpipe[0]);
		if (res < 0) {
			break;
		} else if (res == 1) {
			/* Node has activity: Typed something */
			res = bbs_node_read(node, buf, 1);
			if (res <= 0) {
				break;
			}
			res = 0;
			if (buf[0] == '\n') { /* User just pressed ENTER. Um, okay. */
				continue;
			}
			bbs_node_writef(node, "%c", buf[0]);
			/* Now, buffer input */
			/* XXX The user will be able to use terminal line editing, except for the first char */
			/* XXX ESC should cancel */
			/* XXX All this would be handled once we have a terminal line editor that works with unbuffered input */
			bbs_node_buffer(node);
			res = bbs_node_poll_read(node, MIN_MS(3), buf + 1, sizeof(buf) - 2); /* Leave the first char in the buffer alone, -1 for null termination, and -1 for the first char */
			if (res <= 0) {
				bbs_debug(3, "bbs_node_poll_read returned %ld\n", res);
				if (res == 0) {
					/* User started a message, but didn't finish before timeout */
					bbs_node_writef(node, "\n*** TIMEOUT ***\n");
					bbs_node_flush_input(node); /* Discard any pending input */
					continue;
				}
				break;
			}
			res++; /* Add 1, since we read 1 char prior to the last read */
			buf[res] = '\0'; /* Now we can use strcasecmp, et al. */

			bbs_str_process_backspaces(buf, buf2, sizeof(buf2));

			/* strcasecmp will fail because the buffer has a LF at the end. Use strncasecmp, so anything starting with /help or /quit will technically match too */
			if (STARTS_WITH(buf2, "/quit")) {
				break; /* Quit */
			}
			bbs_node_unbuffer(node);
			chat_send(c, p, channel, "<%s@%d> %s", bbs_username(node->user), node->id, buf2); /* buf2 already contains a newline from the user pressing ENTER, so don't add another one */
		} else if (res == 2) {
			/* Pipe has activity: Received a message */
			res = 0;
			res = (int) read(p->chatpipe[0], buf, sizeof(buf) - 1);
			if (res <= 0) {
				break;
			}
			buf[res] = '\0'; /* Safe */
			/* Don't add a trailing LF, the sent message should already had one. */
			if (bbs_node_writef(node, "%.*s", (int) res, buf) < 0) {
				res = -1;
				break;
			}
			/* Since we null terminated the buffer, we can safely use strstr */
			if (strcasestr(buf, bbs_username(node->user))) {
				bbs_debug(3, "Message contains '%s', alerting user\n", bbs_username(node->user));
				/* If the message contains our username, ring the bell.
				 * (Most IRC door_irc_clients also do this for mentions.) */
				if (bbs_node_ring_bell(node) < 0) {
					res = -1;
					break;
				}
			}
		}
	}

	chat_send(c, NULL, channel, "%s@%d has left %s\n", bbs_username(node->user), node->id, channel);
	return (int) res;
}

/*! \note Must be called locked */
static struct client_relay *find_client(const char *name)
{
	struct client_relay *c = NULL;

	RWLIST_TRAVERSE(&door_irc_clients, c, entry) {
		bbs_assert(!RWLIST_EMPTY(&c->participants)); /* Shouldn't be any non-empty door_irc_clients */
		if (!strcmp(c->name, name)) {
			return c;
		}
	}
	return c;
}

/*! \brief Callback for messages received on IRC client (from some server to our client) */
static void command_cb(const char *clientname, enum irc_callback_msg_type type, const char *channel, const char *prefix, int ctcp, const char *msg)
{
	struct client_relay *client;

	RWLIST_RDLOCK(&door_irc_clients);

	client = find_client(clientname);
	if (!client) {
		RWLIST_UNLOCK(&door_irc_clients);
		return;
	}

	/* Don't release the lock until the callback finishes executing.
	 * Since it's just a read lock, this won't block anything else. */

	switch (type) {
		/* These have a channel */
		case CMD_PRIVMSG:
		case CMD_NOTICE:
			if (ctcp) {
				/* The only CTCP messages that pass through to callbacks are ACTIONs. */
				relay_to_local(client, channel, "[ACTION] <%s> %s\n", prefix, msg);
			} else {
				relay_to_local(client, channel, "<%s> %s\n", prefix, msg);
			}
			break;
		case CMD_JOIN:
			relay_to_local(client, channel, "%s has %sjoined%s\n", prefix, COLOR(COLOR_GREEN), COLOR_RESET);
			break;
		case CMD_PART:
			relay_to_local(client, channel, "%s has %sleft%s\n", prefix, COLOR(COLOR_RED), COLOR_RESET);
			break;
		case CMD_KICK:
			relay_to_local(client, channel, "%s has been %skicked%s\n", prefix, COLOR(COLOR_RED), COLOR_RESET);
			break;
		case CMD_TOPIC:
			relay_to_local(client, channel, "%s has %schanged the topic%s of %s\n", prefix, COLOR_GREEN, COLOR_RESET, msg);
			break;
		case CMD_MODE:
			break; /* Ignore */
		/* These do not have a channel */
		case CMD_QUIT:
			/* We should relay this message to all channels that contain this user,
			 * but we don't currently have a mechanism to do that, so just ignore it... */
#if 0
			relay_to_local(client, NULL, "%s has %squit%s\n", prefix, COLOR(COLOR_RED), COLOR_RESET);
#endif
			break;
		case CMD_NICK:
			/* Same comment as QUIT */
#if 0
			relay_to_local(client, NULL, "%s is %snow known as%s %s\n", prefix, COLOR(COLOR_CYAN), COLOR_RESET, msg);
#endif
			break;
		case CMD_PING:
		case CMD_UNSUPPORTED:
			break;
	}

	RWLIST_UNLOCK(&door_irc_clients);
}

/*! \note channel could be char* and that would be fine, but we don't need to modify it, so const char* works */
static int irc_single_client(struct bbs_node *node, char *constring, const char *channel)
{
	struct irc_client *ircl;
	int res;
	int port = 0; /* Default */
	int secure = 0;
	int flags = 0;
	struct readline_data rldata;
	char usernamebuf[24];
	char passwordbuf[64];
	char buf[2048];
	char *username, *password, *hostname, *portstr;

	/* Parse the arguments.
	 * Format is:
	 * irc:// or ircs://username[:password]@hostname[:port] */
	if (STARTS_WITH(constring, "ircs://")) {
		secure = 1;
		constring += STRLEN("ircs://");
	} else {
		constring += STRLEN("irc://"); /* This is the only other thing it could be */
	}

	portstr = constring;
	password = strsep(&portstr, "@");
	username = strsep(&password, ":");
	hostname = strsep(&portstr, ":");
	if (!strlen_zero(portstr)) {
		port = atoi(portstr);
	}

	if (strlen_zero(hostname)) {
		bbs_warning("Missing IRC hostname\n");
		return 0;
	}

	bbs_node_clear_screen(node);
	bbs_node_writef(node, "Connecting to IRC...\n");

	/* We get our own client, all to ourself! */
	if (strlen_zero(username)) {
		bbs_node_writef(node, "Enter username: ");
		NONPOS_RETURN(bbs_node_readline(node, MIN_MS(1), usernamebuf, sizeof(usernamebuf))); /* Returning -1 anyways, no need to re-enable echo */
		username = usernamebuf;
		if (strlen_zero(username)) {
			bbs_node_writef(node, "No username received. Connection aborted.\n");
			NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
			return 0;
		}
	}
	if (!strlen_zero(password) && !strcmp(password, "*")) {
		if (bbs_user_is_registered(node->user) && !bbs_user_temp_authorization_token(node->user, passwordbuf, sizeof(passwordbuf))) {
			password = passwordbuf;
		} else {
			password = NULL;
		}
	}
	if (strlen_zero(password)) {
		/* Don't know the password.
		 * For connections from a BBS node to the BBS IRC server,
		 * user will probably have to re-enter his/her password here manually,
		 * since we don't have any way of authenticating to the IRC server otherwise.
		 * Kind of clunky, admittedly, in the future we could add a more seamless
		 * mechanism that would allow the IRC server to auto-authenticate connections
		 * like this perhaps (e.g. if username and password are empty).
		 *
		 * Complication is that we don't actually know this connection is to the local
		 * IRC server, it could be to any arbitrary server, so this is at least generic:
		 */
		bbs_node_echo_off(node); /* Don't display password */
		bbs_node_writef(node, "Enter password for %s: ", username);
		NONPOS_RETURN(bbs_node_readline(node, MIN_MS(1), passwordbuf, sizeof(passwordbuf))); /* Returning -1 anyways, no need to re-enable echo */
		/* Hopefully the password is right... only get one shot!
		 * In theory, if we knew the connection was to our own IRC server,
		 * we could actually call bbs_user_authentication here with a dummy user
		 * to check the password, and if it's okay, proceed since we know that
		 * the IRC server will then accept it.
		 */
		bbs_node_echo_on(node);
		password = passwordbuf;
		if (strlen_zero(password)) {
			bbs_node_writef(node, "\nNo password received. Connection aborted.\n");
			NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
			return 0;
		}
	}

	/* Somehow, it actually works that the same user can log into IRC twice
	 * e.g. once directly to IRC and once through here.
	 * Obviously the full masks are different in these cases. */

	ircl = irc_client_new(hostname, (unsigned int) port, username, password);
	if (!ircl) {
		return 0;
	}

	irc_client_autojoin(ircl, channel);
	if (secure) {
		flags |= IRC_CLIENT_USE_TLS;
		/* Require SASL if using TLS, but don't do it otherwise,
		 * since the IRC URI doesn't indicate whether to use SASL or not.
		 * If a server requires SASL, however, it's reasonable to expect that
		 * it supports TLS, so just pair them together. */
		flags |= IRC_CLIENT_USE_SASL;
	}
	irc_client_set_flags(ircl, flags);

	res = irc_client_connect(ircl); /* Actually connect */
	if (!res) {
		res = irc_client_login(ircl); /* Authenticate */
	}
	if (res || !irc_client_connected(ircl)) {
		bbs_node_writef(node, "Connection failed.\n");
		bbs_node_wait_key(node, SEC_MS(75));
		goto cleanup;
	}

	/* Instead of spawning a client_relay thread with a pseudo client and running an event loop,
	 * handle the connection in the current thread.
	 * This does complicate things just a little bit, as can be seen below.
	 * There are several inefficiencies in the loop that could be optimized.
	 */
	bbs_readline_init(&rldata, buf, sizeof(buf)); /* XXX Should probably use a bbs_node_readline in client_relay as well, to simplify message parsing */
	bbs_node_clear_screen(node);
	bbs_node_buffer(node);
	for (;;) {
		time_t now;
		struct tm sendtime;
		char datestr[18] = "";

		/* XXX Known issue: If a message is received while a user is typing,
		 * the message from IRC is printed out immediately and the user continues typing on the next line.
		 * Not super ideal, but since the node is buffered here, we can't easily fix this without unbuffering
		 * the first character and then buffering the rest, and not printing during that time
		 * (this is what door_irc and door_chat do for the shared door_irc_clients normally).
		 */

		/* Client is buffered, so if poll returns, that means we have a full message from it */
		res = irc_poll(ircl, -1, node->slavefd); /* Wait for either something from the server or from the client */
		if (res <= 0) {
			break;
		}

		/* If res == 1, the IRC client had activity, if == 2, the slave had activity */
		if (res == 2) {
			char clientbuf[512]; /* Use a separate buf so that bbs_readline gets its own buf for the server reads */

			/* No need to use a fancy bbs_node_readline struct, since we can reasonably expect to get 1 full line at a time, nothing more, nothing less */
			res = bbs_node_readline(node, 0, clientbuf, sizeof(clientbuf) - 1);
			if (res <= 0) {
				bbs_warning("bbs_readline returned %d\n", res);
				break;
			}
			clientbuf[res] = '\0'; /* Safe */
			bbs_strterm(clientbuf, '\r'); /* If we did get a CR, strip it */

			/* Parse the user's message. Note this isn't IRC syntax, it's just STDIN input.
			 * Unless the user typed /quit, we can basically just build a message and send it to the channel. */
			if (!strcasecmp(clientbuf, "/quit")) {
				break;
			}
			irc_client_msg(ircl, channel, clientbuf); /* Actually send to IRC */

			/* Make our timestamp */
			if (!NODE_IS_TDD(node)) {
				now = time(NULL);
				localtime_r(&now, &sendtime);
				strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime);
			}

			bbs_node_writef(node, "%s<%s> %s\n", datestr, irc_client_username(ircl), clientbuf); /* Echo the user's own message */
		} else { /* Must've been the server. */
			char tmpbuf[2048];
			int ready;
			ssize_t bres;
			/* bbs_readline internally will call poll(), but we already polled inside irc_poll,
			 * and then poll() again to see which file descriptor had activity,
			 * so just pass 0 as poll should always return > 0 anyways, immediately,
			 * since we haven't read any data yet to quell the poll. */

			/* Another clunky thing. Need to get data using irc_read, but we want to buffer it using a bbs_node_readline struct.
			 * So use bbs_readline_append.
			 */
			bres = irc_read(ircl, tmpbuf, sizeof(tmpbuf));
			res = bbs_readline_append(&rldata, "\r\n", tmpbuf, (size_t) res, &ready);
			if (!ready) {
				continue;
			}
			do {
				struct irc_msg msg_stack, *msg = &msg_stack;
				if (res < 0) {
					res += 1; /* Convert the res back to a normal one. */
					if (res == 0) {
						/* No data to read. This shouldn't happen if irc_poll returned > 0 */
						bbs_warning("bbs_readline returned %d\n", res - 1); /* And subtract 1 again to match what it actually returned before we added 1 */
					}
					goto cleanup;
				}
				/* Parse message from server */
				memset(&msg_stack, 0, sizeof(msg_stack));
				if (!irc_parse_msg(msg, buf) && !irc_parse_msg_type(msg)) {
					/* Condensed version of what command_cb does */
					switch (irc_msg_type(msg)) {
						case IRC_NUMERIC:
							bbs_node_writef(node, "%s %d %s\n", NODE_IS_TDD(node) ? "" : S_IF(irc_msg_prefix(msg)), irc_msg_numeric(msg), irc_msg_body(msg));
							break;
						case IRC_CMD_PRIVMSG:
						case IRC_CMD_NOTICE:
							/* NOTICE is same as PRIVMSG, but should never be acknowledged (replied to), to prevent loops, e.g. for use with bots. */
							bbs_strterm(irc_msg_prefix(msg), '!'); /* Strip everything except the nickname from the prefix */
							if (irc_msg_is_ctcp(msg) && !irc_parse_msg_ctcp(msg)) {
								if (irc_msg_type(msg) == IRC_CMD_PRIVMSG) { /* Ignore NOTICE */
									enum irc_ctcp_type ctcp = irc_msg_ctcp_type(msg);
									switch (irc_msg_ctcp_type(msg)) {
										case CTCP_ACTION:
											if (!NODE_IS_TDD(node)) {
												now = time(NULL);
												localtime_r(&now, &sendtime);
												strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime);
											}
											bbs_node_writef(node, "[ACTION] %s<%s> %s\n", datestr, irc_msg_prefix(msg), irc_msg_body(msg));
											break;
										/* Mirrors CTCP handling in mod_irc_client: */
										case CTCP_VERSION:
											irc_client_ctcp_reply(ircl, irc_msg_prefix(msg), ctcp, BBS_SHORTNAME " / LIRC " XSTR(LIRC_MAJOR_VERSION) "." XSTR(LIRC_MINOR_VERSION) "." XSTR(LIRC_PATCH_VERSION));
											break;
										case CTCP_PING:
											irc_client_ctcp_reply(ircl, irc_msg_prefix(msg), ctcp, irc_msg_body(msg)); /* Reply with the data that was sent */
											break;
										case CTCP_TIME:
											{
												char timebuf[32];
												time_t nowtime;
												struct tm nowdate;

												nowtime = time(NULL);
												localtime_r(&nowtime, &nowdate);
												strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M:%S %P %Z", &nowdate);
												irc_client_ctcp_reply(ircl, irc_msg_prefix(msg), ctcp, timebuf);
											}
											break;
										default:
											break;
									}
								}
							} else {
								if (!NODE_IS_TDD(node)) {
									now = time(NULL);
									localtime_r(&now, &sendtime);
									strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime);
								}
								bbs_node_writef(node, "%s<%s> %s\n", datestr, msg->prefix, irc_msg_body(msg));
							}
							break;
						case IRC_CMD_PING:
							/* Reply with the same data that it sent us (some servers may actually require that) */
							irc_client_pong(ircl, msg);
							break;
						case IRC_CMD_JOIN:
							bbs_node_writef(node, "%s has %sjoined%s\n", msg->prefix, COLOR(COLOR_GREEN), COLOR_RESET);
							break;
						case IRC_CMD_PART:
							bbs_node_writef(node, "%s has %sleft%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
							break;
						case IRC_CMD_QUIT:
							/* Since this client is for a single end user, and the server sent us the quit,
							 * we know it must be relevant to us */
							bbs_node_writef(node, "%s has %squit%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
							break;
						case IRC_CMD_KICK:
							bbs_node_writef(node, "%s has been %skicked%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
							break;
						case IRC_CMD_NICK:
							bbs_node_writef(node, "%s is %snow known as%s %s\n", msg->prefix, COLOR(COLOR_CYAN), COLOR_RESET, irc_msg_body(msg));
							break;
						case IRC_CMD_TOPIC:
							bbs_node_writef(node, "%s has %schanged the topic%s of %s\n", irc_msg_prefix(msg), COLOR_GREEN, COLOR_RESET, irc_msg_body(msg));
							break;
						case IRC_CMD_ERROR:
						case IRC_CMD_OTHER:
						case IRC_UNPARSED:
						default:
							break;
					}
				}

				/* Okay, now because bbs_readline might have read MULTIPLE lines from the server,
				 * call it again to make sure there isn't any further input.
				 * We use a timeout of 0, because if there isn't another message ready already,
				 * then we should just go back to the outer poll.
				 */
				bres = bbs_readline(node->slavefd, &rldata, "\r\n", 0);
			} while (bres > 0);
		}
	}

cleanup:
	irc_client_destroy(ircl);
	return 0;
}

static int irc_client_exec(struct bbs_node *node, const char *args)
{
	char buf[84];
	char *channel, *client;
	struct participant *p;
	int res;

	if (strlen_zero(args)) {
		bbs_error("Must specify a client name to use (syntax: client,channel)\n");
		return 0; /* Don't disconnect the node */
	}

	safe_strncpy(buf, args, sizeof(buf));
	channel = buf;
	client = strsep(&channel, ",");

	if (strlen_zero(channel) || strlen_zero(client)) {
		bbs_error("Must specify a client and channel (syntax: client,channel)\n");
		return 0;
	}

	/* Join via a dedicated connection, dynamically. Especially useful if trying to join the local BBS IRC server,
	 * since then we can have a 1:1 connection for each client. */
	if (STARTS_WITH(client, "irc://") || STARTS_WITH(client, "ircs://")) {
		return irc_single_client(node, client, channel);
	}

	/* Join via a preconstructed client. */
	p = join_client(node, client);
	if (!p) {
		return 0;
	}

	p->channel = channel;
	res = participant_relay(node, p, channel);
	leave_client(p->client, p);
	return res;
}

static int unload_module(void)
{
	bbs_irc_client_msg_callback_unregister(command_cb);
	return bbs_unregister_door("irc");
}

static int load_module(void)
{
	if (bbs_irc_client_msg_callback_register(command_cb, NULL)) { /* No numeric callback needed */
		return -1;
	}
	return bbs_register_door("irc", irc_client_exec);
}

BBS_MODULE_INFO_DEPENDENT("Internet Relay Chat Client", "mod_irc_client.so");
