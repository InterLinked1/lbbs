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
 * \brief Standalone realtime chat
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h> /* use close */

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/door.h"
#include "include/term.h"
#include "include/linkedlists.h"
#include "include/utils.h"

struct participant {
	struct bbs_node *node;
	/* Reference to our channel, for speed of finding it again (we can do pointer comparisons instead of string comparisons) */
	struct channel *channel;
	/* Join time */
	int jointime;
	/* Pipe to store data */
	int chatpipe[2];
	/* Next participant */
	RWLIST_ENTRY(participant) entry;
};

RWLIST_HEAD(participants, participant);

struct channel {
	struct participants participants; /* List of participants */
	RWLIST_ENTRY(channel) entry; /* Next channel */
	char name[0]; /* Name of channel */
};

static RWLIST_HEAD_STATIC(channels, channel);

static void leave_channel(struct channel *channel, struct participant *participant)
{
	struct participant *p;

	/* Lock the entire channels list first */
	RWLIST_WRLOCK(&channels);
	RWLIST_WRLOCK(&channel->participants);
	RWLIST_TRAVERSE_SAFE_BEGIN(&channel->participants, p, entry) {
		if (p == participant) {
			RWLIST_REMOVE_CURRENT(entry);
			/* Close the pipe */
			close(p->chatpipe[0]);
			close(p->chatpipe[1]);
			/* Free */
			free(p);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (!p) {
		bbs_error("Failed to remove participant %p (node %d) from channel %s?\n", participant, participant->node->id, channel->name);
	}
	/* The only ways the participants can change is through join or leave.
	 * Both lock the entire channels list, and the channels list is still
	 * locked until the end of the function, so this is safe to do.
	 * We must unlock the list if we're going to destroy it.
	 */
	RWLIST_UNLOCK(&channel->participants);
	if (RWLIST_EMPTY(&channel->participants)) {
		struct channel *c;
		/* Nobody is left in the channel. Destroy it. */
		bbs_debug(3, "Nobody is left in channel %s, destroying\n", channel->name);
		RWLIST_TRAVERSE_SAFE_BEGIN(&channels, c, entry) {
			if (c == channel) {
				RWLIST_REMOVE_CURRENT(entry);
				free(c);
				break;
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
		if (!c) {
			bbs_error("Faled to remove channel %s?\n", channel->name);
		}
	}
	RWLIST_UNLOCK(&channels);
}

static struct participant *join_channel(struct bbs_node *node, const char *name)
{
	struct participant *p;
	struct channel *channel;
	int newchan = 0;

	RWLIST_WRLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (!strcasecmp(channel->name, name)) {
			break;
		}
	}
	if (!channel) {
		/* Doesn't exist yet, make it on the fly */
		bbs_debug(3, "Chat channel %s doesn't exist yet, creating it now\n", name);
		channel = calloc(1, sizeof(*channel) + strlen(name) + 1);
		if (!channel) {
			bbs_error("calloc failure\n");
			RWLIST_UNLOCK(&channels);
			return NULL;
		}
		newchan = 1;
		strcpy(channel->name, name); /* Safe */
	}
	/* Okay, we have the channel. Add the newcomer to it. */
	p = calloc(1, sizeof(*p));
	if (!p) {
		bbs_error("calloc failure\n");
		if (newchan) {
			free(channel); /* If we calloc'd a channel but failed to calloc a participant, discard (free) the channel */
		}
		RWLIST_UNLOCK(&channels);
		return NULL;
	}
	p->node = node;
	p->channel = channel;
	p->jointime = time(NULL);
	if (pipe(p->chatpipe)) {
		bbs_error("Failed to create pipe\n");
		if (newchan) {
			free(channel);
		}
		free(p);
		RWLIST_UNLOCK(&channels);
		return NULL;
	}
	/* Tail insert so participants show up in order */
	RWLIST_INSERT_TAIL(&channel->participants, p, entry);
	if (newchan) {
		RWLIST_INSERT_TAIL(&channels, channel, entry);
	}
	RWLIST_UNLOCK(&channels);
	return p;
}

/*! \note This is only safe to call for threads that are currently in the channel */
static int channel_participant_count(struct channel *channel)
{
	struct participant *p;
	int c;

	RWLIST_RDLOCK(&channel->participants);
	c = RWLIST_SIZE(&channel->participants, p, entry);
	RWLIST_UNLOCK(&channel->participants);

	bbs_assert(c > 0); /* We're at least in it. */
	return c;
}

/*! \note This is only safe to call for threads that are currently in the channel */
static int print_channel_participants(struct bbs_node *node, struct channel *channel)
{
	char elapsed[24];
	int c = 0;
	struct participant *p;
	int now = time(NULL);

	bbs_writef(node, "%4s %9s %s\n", "Node", "Elapsed", "User");
	RWLIST_RDLOCK(&channel->participants);
	RWLIST_TRAVERSE(&channel->participants, p, entry) {
		struct bbs_node *n = p->node;
		print_time_elapsed(p->jointime, now, elapsed, sizeof(elapsed));
		/* Participants can't go away without leaving the channel (which needs a WRLOCK)
		 * So nodes can't go away either. */
		bbs_writef(node, "%4d %9s %s\n", n->id, elapsed, bbs_username(n->user));
		c++;
	}
	RWLIST_UNLOCK(&channel->participants);

	bbs_assert(c > 0); /* We're at least in it. */
	bbs_writef(node, "%d user%s in channel #%s\n", c, ESS(c), channel->name);
	return c;
}

#define INTEGRITY_CHECKS

static int __chat_send(struct channel *channel, struct participant *sender, const char *msg, int len)
{
	time_t now;
    struct tm sendtime;
	char datestr[18];
	int timelen;
	int res;
	struct participant *p;
#ifdef INTEGRITY_CHECKS
	struct channel *c;

	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, c, entry) {
		if (c == channel) {
			break;
		}
	}
	/* channels shouldn't disappear while we're using them
	 * In theory we don't need to traverse (although this ensures the assertion),
	 * we just need RDLOCK the list to prevent the channel from being removed,
	 * although really channels shouldn't be removed if there are participants.
	 * XXX Assuming only participants can remove themselves, since we're in the channel,
	 * it must still exist. So maybe all this locking is kind of unnecessary... */
	bbs_assert(c != NULL);
	RWLIST_UNLOCK(&channels);
#endif

	/* Calculate the current time once, for everyone, using the server's time (sorry if participants are in different time zones) */
	now = time(NULL);
    localtime_r(&now, &sendtime);
	/* So, %P is lowercase and %p is uppercase. Just consult your local strftime(3) man page if you don't believe me. Good grief. */
	strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime); /* mm-dd hh:mm:ssPP + space at end (before message) = 17 chars */
	timelen = strlen(datestr); /* Should be 17 */
	bbs_assert(timelen == 17);

	/* If sender is set, it's safe to use even with no locks, because the sender is a calling function of this one */
	if (sender) {
		bbs_debug(7, "Broadcasting to %s (except node %d): %s%.*s\n", channel->name, sender->node->id, datestr, len, msg);
	} else {
		bbs_debug(7, "Broadcasting to %s: %s%.*s\n", channel->name, datestr, len, msg);
	}

	/* Relay the message to everyone */
	RWLIST_RDLOCK(&channel->participants);
	RWLIST_TRAVERSE(&channel->participants, p, entry) {
		if (p == sender) {
			continue; /* Don't send a sender's message back to him/herself */
		}
		/* A participant can only be in one channel, so we don't have to worry
		 * about multiple people trying to write to the pipe at once.
		 * Only one write can occur to a participant's pipe at any given time.
		 * If participants were allowed to be in multiple channels,
		 * then this would be different, we would need to have a mutex for each participant.
		 * But this module is only single channel, I think the multi-channel stuff
		 * can be reserved for the IRC module. Let's keep it simple here.
		 */
		if (!NODE_IS_TDD(p->node)) {
			res = write(p->chatpipe[1], datestr, timelen); /* Don't send timestamps to TDDs, for brevity */
		}
		if (res > 0) {
			res = write(p->chatpipe[1], msg, len);
		}
		if (res <= 0) {
			bbs_error("write failed: %s\n", strerror(errno));
			continue; /* Even if one send fails, don't fail all of them */
		}
	}
	RWLIST_UNLOCK(&channel->participants);
	return 0;
}

/*! \param sender If NULL, the message will be sent to the sender, if specified, the message will not be sent to this participant */
static int __attribute__ ((format (gnu_printf, 3, 4))) chat_send(struct channel *channel, struct participant *sender, const char *fmt, ...)
{
	char *buf;
	int res, len;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* No format specifiers in the format string, just do it directly to avoid an unnecessary allocation. */
		return __chat_send(channel, sender, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		bbs_error("vasprintf failure\n");
		return -1;
	}
	res = __chat_send(channel, sender, buf, len);
	free(buf);
	return res;
}

static int chat_run(struct bbs_node *node, struct participant *p)
{
	char buf[384];
	char buf2[sizeof(buf)];
	int res;
	int participants;
	struct channel *c = p->channel;

	/* Join the channel */
	bbs_clear_screen(node);
	chat_send(c, NULL, "%s has joined #%s from node %d\n", bbs_username(node->user), c->name, node->id);

	bbs_unbuffer(node); /* Unbuffer so we can receive keys immediately. Otherwise, might print a message while user is typing */

	/* Since q will not quit, explicitly provide instructions to the poor, unsuspecting user */
	participants = channel_participant_count(c);
	bbs_assert(participants >= 1); /* We're in it at least */
	bbs_writef(node, "Welcome to #%s! Type /quit to quit, and /help for help\n", c->name);
	bbs_writef(node, "%d user%s (%d other user%s) in channel #%s\n", participants, ESS(participants), participants - 1, ESS(participants - 1), c->name);

	for (;;) {
		/* We need to poll both the node as well as the participant (chat) pipe */
		res = bbs_poll2(node, SEC_MS(10), p->chatpipe[0]);
		if (res < 0) {
			break;
		} else if (res == 1) {
			/* Node has activity: Typed something */
			res = bbs_read(node, buf, 1);
			if (res <= 0) {
				break;
			}
			res = 0;
			if (buf[0] == '\n') { /* User just pressed ENTER. Um, okay. */
				bbs_writef(node, "%s%s%s\n", COLOR(COLOR_RED), "Empty messages not allowed. Type /help for help.", COLOR_RESET);
				continue;
			}
			bbs_writef(node, "%c", buf[0]);
			/* Now, buffer input */
			/* XXX The user will be able to use terminal line editing, except for the first char */
			/* XXX ESC should cancel */
			/* XXX All this would be handled once we have a terminal line editor that works with unbuffered input */
			bbs_buffer(node);
			res = bbs_poll_read(node, SEC_MS(30), buf + 1, sizeof(buf) - 2); /* Leave the first char in the buffer alone, -1 for null termination, and -1 for the first char */
			if (res <= 0) {
				break;
			}
			res++; /* Add 1, since we read 1 char prior to the last read */
			buf[res] = '\0'; /* Now we can use strcasecmp */

			bbs_str_process_backspaces(buf, buf2, sizeof(buf2));

			/* strcasecmp will fail because the buffer has a LF at the end. Use strncasecmp, so anything starting with /help or /quit will technically match too */
			if (STARTS_WITH(buf2, "/quit")) {
				break; /* Quit */
			} else if (STARTS_WITH(buf2, "/users")) {
				print_channel_participants(node, c);
			} else if (STARTS_WITH(buf2, "/help")) {
				bbs_writef(node, "== LBBS Chat ==\n");
				bbs_writef(node, "/help Help\n");
				bbs_writef(node, "/quit Quit\n");
				bbs_writef(node, "/users List users in channel\n");
				bbs_writef(node, "<message>\n");
			}
			bbs_unbuffer(node);

			/* Message contains non-printable characters. Reject it.
			 * It's not great for security if any user can send arbitrary ASCII characters to anyone else's terminal. */
			if (!bbs_str_anyprint(buf2)) {
				/* For example, reject messages that contain only spaces. */
				bbs_writef(node, "%s%s%s\n", COLOR(COLOR_RED), "Sorry, message is empty.", COLOR_RESET);
				continue;
			} else if (!bbs_str_isprint(buf2)) {
				bbs_writef(node, "%s%s%s\n", COLOR(COLOR_RED), "Sorry, message contains invalid characters.", COLOR_RESET);
				continue;
			}

			/* Provide p so we don't relay the message to ourself. */
			/* The node number is needed to uniquely identify a participant, not just the username.
			 * For example, the same user could be logged into 2 terminals at once.
			 * Or, multiple guest users might be logged in.
			 */
			chat_send(c, p, "%s@%d: %s", bbs_username(node->user), node->id, buf2); /* buf already contains a newline from the user pressing ENTER, so don't add another one */
		} else if (res == 2) {
			/* Pipe has activity: Received a message */
			/* The nice thing is since it's in a pipe, we won't
			 * lose messages if something is sent while we were typing,
			 * they'll just be delayed a bit.
			 * The timestamp is created when the message is sent,
			 * so THAT will be accurate, which is good!
			 */
			res = 0;
			res = read(p->chatpipe[0], buf, sizeof(buf) - 1);
			if (res <= 0) {
				break;
			}
			buf[res] = '\0'; /* Safe */
			/* Don't add a trailing LF, the sent message should already had one.
			 * Even if it doesn't, don't blindly add one. Because we write the time and message in 2 separate calls to write(),
			 * in __chat_send, we could end up doing 2 disjoint reads here, and the first one will only have the timestamp.
			 */
			if (bbs_writef(node, "%.*s", res, buf) < 0) {
				res = -1;
				break;
			}
			/* Since we null terminated the buffer, we can safely use strstr */
			if (strcasestr(buf, bbs_username(node->user))) {
				bbs_debug(3, "Message contains '%s', alerting user\n", bbs_username(node->user));
				/* If the message contains our username, ring the bell.
				 * (Most IRC clients also do this for mentions.) */
				if (bbs_ring_bell(node) < 0) {
					res = -1;
					break;
				}
			}
		}
	}

	chat_send(c, NULL, "%s has left #%s from node %d\n", bbs_username(node->user), c->name, node->id);
	return res;
}

static int module_shutdown = 0;

static int chat_exec(struct bbs_node *node, const char *args)
{
	int res;
	struct participant *p;

	if (module_shutdown) {
		return 0; /* Probably a race condition that would never happen... but it could? */
	}

	if (strlen_zero(args)) {
		bbs_error("Must specify a channel name to join\n");
		return 0; /* Don't disconnect the node */
	}
	p = join_channel(node, args);
	if (!p) {
		return 0;
	}

	res = chat_run(node, p);
	leave_channel(p->channel, p);

	return res;
}

static int load_module(void)
{
	return bbs_register_door("chat", chat_exec);
}

static int unload_module(void)
{
	/* In theory, we should always be OK since if the list is not empty, door.c already bumped this module's ref count,
	 * and module.c should decline to even call unload_module. */
	RWLIST_WRLOCK(&channels);
	module_shutdown = RWLIST_EMPTY(&channels);
	RWLIST_UNLOCK(&channels);

	if (!module_shutdown) {
		bbs_error("Module has ref count 0, but channels are active?\n"); /* Bug! */
		return -1; /* Still active channels. Decline unload. */
	}

	return bbs_unregister_door("chat");
}

BBS_MODULE_INFO_STANDARD("Standalone Realtime Chat");
