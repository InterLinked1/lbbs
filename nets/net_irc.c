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
 * \brief Internet Relay Chat (IRC) Server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h> /* use gettimeofday */
#include <limits.h> /* use PATH_MAX */

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/stringlist.h"
#include "include/ansi.h"
#include "include/notify.h"
#include "include/alertpipe.h"
#include "include/cli.h"
#include "include/ratelimit.h"

#include "include/net_irc.h"

#define DEFAULT_IRC_PORT 6667
#define DEFAULT_IRCS_PORT 6697

#define IRC_SERVER_VERSION BBS_NAME "-" BBS_VERSION "-irc"

/*! \todo There is currently no support for multi-server networks (see RFC 2813) */

/*! \brief Clients will be pinged every 2 minutes, and have 2 minutes to respond. */
#define PING_TIME MIN_MS(2)

#define MAX_TOPIC_LENGTH 390
#define MAX_CHANNEL_LENGTH 50
#define MAX_AWAY_LEN 90
#define MAX_CHANNELS 50

#define MAX_NICKLEN 16
#define MAX_HOSTLEN 128
/*! \todo not yet supported */
#define DEF_MAXLIST "b:1"

/* Hostmask / prefix format (nickname!ident@hostname) */
#define HOSTMASK_FMT "%s!%s@%s"
#define HOSTMASK_ARGS(user) (user)->nickname, (user)->username, (user)->hostname

/*! \note Since not all users have a node (e.g. builtin services) */
#define irc_other_thread_writef(node, fmt, ...) bbs_auto_any_fd_writef(node, node ? node->wfd : -1, fmt, ## __VA_ARGS__)

/* There isn't a bbs_auto_any_fd_write */
#define irc_other_thread_write(node, buf, len) bbs_auto_any_fd_writef(node, node ? node->wfd : -1, "%.*s", (int) len, buf)

#define send_reply(user, fmt, ...) bbs_debug(3, "%p <= " fmt, user, ## __VA_ARGS__); irc_other_thread_writef(user->node, fmt, ## __VA_ARGS__);
#define send_numeric(user, numeric, fmt, ...) send_reply(user, "%03d %s :" fmt, numeric, user->nickname, ## __VA_ARGS__)
#define send_numeric2(user, numeric, fmt, ...) send_reply(user, "%03d %s " fmt, numeric, user->nickname, ## __VA_ARGS__)
#define send_numeric_broadcast(channel, user, numeric, fmt, ...) channel_broadcast(channel, user, "%03d %s " fmt, numeric, irc_hostname, ## __VA_ARGS__)

/*! \note Currently this is a single-server network, so there is no difference in practice between # and & channels. */
/*! \todo Make this IRC network daemon multi-server capable somehow? Perhaps linkable with other servers running the same IRC module? Would also allow sharing state... */

#define VALID_CHANNEL_NAME_PREFIX(c) (c == '#' || c == '&' || c == '+' || c == '!')
#define IS_CHANNEL_NAME(s) (VALID_CHANNEL_NAME_PREFIX(*s))
#define VALID_CHANNEL_NAME(s) (!strlen_zero(s) && IS_CHANNEL_NAME(s))

/*! \todo include irc.h from LIRC, so we can use macro names for numerics, at least */

static int irc_port = DEFAULT_IRC_PORT;
static int ircs_port = DEFAULT_IRCS_PORT;

static pthread_t irc_ping_thread = 0;

static int irc_enabled = 1, ircs_enabled = 1;
static int require_sasl = 1;
static int require_chanserv = 1;
static int log_channels = 0;

static time_t loadtime = 0;
static int need_restart = 0;

static char irc_hostname[84];
static char motd_file[256];
static char *motdstring = NULL;

static int load_config(void);

/* ChatZilla/Ambassador interface guide: http://chatzilla.hacksrus.com/intro */

/* Reference for numeric message strings: https://github.com/solanum-ircd/solanum/blob/main/include/messages.h */
/* Reference for channel modes: https://github.com/solanum-ircd/solanum/blob/main/help/opers/cmode */

static const char *usermodes = "iowZ";
static const char *channelmodes = "cgijklmnprstzCPST";
static const char *paramchannelmodes = "qahov";
/* https://modern.ircdocs.horse/#mode-message */
static const char *chanmodes = ",,jkl,cgimnprstzCPST"; /* I think this is the correct categorization into the A,B,C,D modes... */

/*! \brief Channel "hidden" from queries unless the user is also in it */
#define CHANNEL_HIDDEN (CHANNEL_MODE_PRIVATE | CHANNEL_MODE_SECRET)

/*! \brief An IRC operator */
struct irc_operator {
	const char *name;
	const char *password;
	RWLIST_ENTRY(irc_operator) entry;	/* Next operator */
	char data[];
};

static RWLIST_HEAD_STATIC(operators, irc_operator);	/* Container for all operators */

static int operators_online = 0;

/*! \brief A single IRC user */
struct irc_user {
	struct bbs_node *node;			/* Node that is handling this user. 1:1 mapping. */
	int channelcount;				/* Number of channels currently in, for constant-time count access */
	char *username;					/* Client username. Does not change. */
	char *nickname;					/* Client nickname. Can change. */
	char *realname;					/* "Real name", typically the client name */
	char *hostname;					/* Hostname: defaults to IP, but can use a host mask or "cloak" instead */
	char *password;					/* Password for PASS command */
	enum user_modes modes;			/* User's modes (apply to the user globally, not just a specific channel) */
	time_t joined;					/* Time joined */
	time_t lastactive;				/* Time of last JOIN, PART, PRIVMSG, NOTICE, etc. */
	time_t lastping;				/* Last ping sent */
	time_t lastpong;				/* Last pong received */
	struct timeval lastping_us;		/* Lag timer start (when we sent a PING) */
	int lag;						/* Lag, in ms (how long it took to get a PONG) */
	bbs_mutex_t lock;				/* User lock */
	char *awaymsg;					/* Away message */
	unsigned int away:1;			/* User is currently away (default is 0, i.e. user is here) */
	unsigned int multiprefix:1;		/* Supports multi-prefix */
	unsigned int registered:1;		/* Fully registered */
	unsigned int programmatic:1;	/* Programmatic from another module, as opposed to a real client connection (e.g. for mod_irc_bounder) */
	RWLIST_ENTRY(irc_user) entry;	/* Next user */
	/* Avoid using a flexible struct member since we'll probably strdup both the username and nickname beforehand anyways */
};

/*! \brief An IRC WHOWAS */
struct whowas {
	const char *who;
	time_t joined;
	size_t nicklen;
	RWLIST_ENTRY(whowas) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(whowas_users, whowas);

static void whowas_update(struct irc_user *user, int keep)
{
	char buf[128];
	int len;
	struct whowas *w;

	if (!user->registered || strlen_zero(user->nickname)) {
		return;
	}

	/* If nickname already exists, remove and add again with updated info */
	RWLIST_WRLOCK(&whowas_users);
	RWLIST_TRAVERSE_SAFE_BEGIN(&whowas_users, w, entry) {
		/* If the first word matches, it's the same nickname */
		if (!strncasecmp(user->nickname, w->who, w->nicklen) && w->nicklen == strlen(user->nickname)) {
			RWLIST_REMOVE_CURRENT(entry);
			free(w);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;

	if (keep) {
		/* Format of response RPL_WHOWASUSER (314) */
		len = snprintf(buf, sizeof(buf), "%s %s %s *: %s", user->nickname, S_IF(user->username), S_IF(user->hostname), S_IF(user->realname));

		w = calloc(1, sizeof(*w) + (size_t) len + 1);
		if (ALLOC_SUCCESS(w)) {
			w->joined = user->joined;
			w->nicklen = strlen(user->nickname);
			strcpy(w->data, buf); /* Safe */
			w->who = w->data;
			RWLIST_INSERT_HEAD(&whowas_users, w, entry);
		}
	}
	RWLIST_UNLOCK(&whowas_users);
}

/*! \todo
 * Now that the programmatic user APIs exist,
 * services (ChanServ, MessageServ) could, in the future,
 * potentially be refactored out of net_irc.
 * Unlike mod_irc_bouncer, we would return 0 for
 * the join_leave_suppress callback, since we
 * would never want to suppress JOIN/PART, etc.
 * for services. */

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
/*! \brief Static user struct for ChanServ operations */
static struct irc_user user_chanserv = {
	.node = NULL,
	.channelcount = 0,
	.username = "ChanServ",
	.nickname = "ChanServ",
	.realname = "Channel Services",
	.hostname = "services",
	.modes = USER_MODE_OPERATOR, /* Grant ChanServ permissions to do whatever it wants */
	.programmatic = 1,
	.lock = BBS_MUTEX_INITIALIZER,
};

/*! \brief Static user struct for private messaging operations */
static struct irc_user user_messageserv = {
	.node = NULL,
	.channelcount = 0,
	/* This is kind of the opposite of MemoServ, actually, so let's call it MessageServ */
	.username = "MessageServ",
	.nickname = "MessageServ",
	.realname = "Messaging Services",
	.hostname = "services",
	.modes = 0,
	.programmatic = 1,
	.lock = BBS_MUTEX_INITIALIZER,
};
#pragma GCC diagnostic pop

#define IS_SERVICE(user) (user == &user_chanserv || user == &user_messageserv)

/*! \brief Is this a "real" user? (with a node, coming in via a TCP connection, not part of a BBS module) */
#define IS_REAL_USER(user) (!user->programmatic)

static RWLIST_HEAD_STATIC(users, irc_user);	/* Container for all users */

/*! \brief A user in a channel (1:1) */
struct irc_member {
	struct irc_user *user;			/* Reference to user (must be in the users list) */
	enum channel_user_modes modes;	/* User's channel flags (flags for this channel) */
	bbs_mutex_t lock;			/* Member lock */
	RWLIST_ENTRY(irc_member) entry;	/* Next member */
};

RWLIST_HEAD(channel_members, irc_member);

/* XXX 100% horrible horrible (hopefully temporary) kludge - a total lock hack: In this case, it's to emulate recursive locking for this thread stack:
 *
 * Example of call stacks that would otherwise deadlock:
 *
 * -- Example A (line numbers pretty outdated by now)
 * _irc_relay_send (net_irc.c:937) <--- try to RDLOCK
 * netirc_cb (mod_irc_relay.c:575)
 * relay_broadcast (net_irc.c:793)
 * relay_broadcast (net_irc.c:777)
 * drop_member_if_present (net_irc.c:2522)
 * leave_all_channels.constprop.0 (net_irc.c:2575) <---- initial WRLOCK
 * handle_client (net_irc.c:2979)
 *
 * -- Example B (line numbers less outdated)
 * join_channel (net_irc.c:3189) <---- try to WRLOCK again channels (and even channels->members) again
 * irc_user_exec (net_irc.c:4056)
 * bouncer_send (mod_irc_bouncer.c:226)
 * start_bouncer_for_channel (mod_irc_bouncer.c:573)
 * join_leave (mod_irc_bouncer.c:644)
 * join_leave_suppress (net_irc.c:2990)
 * leave_channel (net_irc.c:2990) <---- initial WRLOCK
 * handle_client (net_irc.c:3872)
 *
 * There are more call sites than just these, and all the known ones have ENABLE_RECURSIVE_LOCKING() in an appropriate place.
 */

enum lock_state {
	LOCK_STATE_UNLOCKED,
	LOCK_STATE_RDLOCK,
	LOCK_STATE_WRLOCK,
};

struct recursive_lock {
	pthread_t thread;
	enum lock_state state;
	int count;
	int line;
	bbs_mutex_t lock;
};

struct recursive_lock channels_recurse = {
	.thread = 0,
	.state = LOCK_STATE_UNLOCKED,
	.count = 0,
	.lock = BBS_MUTEX_INITIALIZER,
};

/* Macros to manage recursive locking for the channels list */
#define DEBUG_RECURSIVE_LOCKING

#ifdef DEBUG_RECURSIVE_LOCKING
#define RECURSIVE_LOCK_DUMP_STATE_TO_STACK(r) \
	pthread_t _recursive_thread = (r)->thread; \
	int _recursive_count = (r)->count; \
	enum lock_state _recursive_state = (r)->state; \
	UNUSED(_recursive_thread); \
	UNUSED(_recursive_count); \
	UNUSED(_recursive_state);
#else
#define RECURSIVE_LOCK_DUMP_STATE_TO_STACK(r)
#endif

#define RECURSIVE_LOCKING_ENABLED(r) ((r)->thread == pthread_self())

#define RECURSIVE_LOCK_COUNT_ADJUST(r, c) \
	(r)->count += c;

/* If we already hold a lock and we're recursing,
 * and we just want a RDLOCK, it doesn't matter
 * whether we hold a RDLOCK or WRLOCK, it's fine... */
#define RWLIST_RDLOCK_RECURSIVE(l, r) \
	if (RECURSIVE_LOCKING_ENABLED((r)) && (r)->state != LOCK_STATE_UNLOCKED) { \
		bbs_mutex_lock(&(r)->lock); \
		RECURSIVE_LOCK_COUNT_ADJUST(r, +1); \
		bbs_mutex_unlock(&(r)->lock); \
	} else { \
		RECURSIVE_LOCK_DUMP_STATE_TO_STACK(r); \
		RWLIST_RDLOCK(l); \
		bbs_mutex_lock(&(r)->lock); \
		(r)->thread = pthread_self(); \
		(r)->state = LOCK_STATE_RDLOCK; \
		(r)->line = __LINE__; \
		RECURSIVE_LOCK_COUNT_ADJUST(r, +1); \
		bbs_mutex_unlock(&(r)->lock); \
	}

/* ... However, if we want to get a WRLOCK and we already locked the list,
 * then we must have initially grabbed a WRLOCK.
 * That won't work, the code needs to grab a WRLOCK from the get go. */
#define RWLIST_WRLOCK_RECURSIVE(l, r) \
	if (RECURSIVE_LOCKING_ENABLED((r)) && (r)->state != LOCK_STATE_UNLOCKED) { \
		if ((r)->state == LOCK_STATE_WRLOCK) { \
			bbs_mutex_lock(&(r)->lock); \
			RECURSIVE_LOCK_COUNT_ADJUST(r, +1); \
			bbs_mutex_unlock(&(r)->lock); \
		} else { \
			bbs_error("List %p was %s at line %d, but now we want a WRLOCK!\n", (r), (r)->state == LOCK_STATE_RDLOCK ? "initially RDLOCK'd" : "unlocked", (r)->line); \
			bbs_log_backtrace(); \
			abort(); \
		} \
	} else { \
		RECURSIVE_LOCK_DUMP_STATE_TO_STACK(r); \
		RWLIST_WRLOCK(l); \
		bbs_mutex_lock(&(r)->lock); \
		(r)->thread = pthread_self(); \
		(r)->state = LOCK_STATE_WRLOCK; \
		(r)->line = __LINE__; \
		RECURSIVE_LOCK_COUNT_ADJUST(r, +1); \
		bbs_mutex_unlock(&(r)->lock); \
	}

#define RWLIST_UNLOCK_RECURSIVE(l, r) \
	bbs_mutex_lock(&(r)->lock); \
	RECURSIVE_LOCK_COUNT_ADJUST(r, -1); \
	if (!(r)->count) { \
		(r)->thread = 0; \
		(r)->state = LOCK_STATE_UNLOCKED; \
		(r)->line = __LINE__; \
		RWLIST_UNLOCK(l); \
	} \
	bbs_mutex_unlock(&(r)->lock);

/* These do nothing, but are merely markers to indicate known code paths
 * that require recursive locking. */
#define ENABLE_RECURSIVE_LOCKING(r)
#define RESET_RECURSIVE_LOCKING(r)

struct irc_channel {
	const char *name;					/* Name of channel */
	const char *username;				/* Username of owner (for private namespace channels) */
	int membercount;					/* Current member count, for constant-time member count access */
	char *password;						/* Channel password */
	char *topic;						/* Channel topic */
	char *topicsetby;					/* Ident of who set the channel topic */
	time_t topicsettime;				/* Epoch time of when the topic was last set */
	struct channel_members members;		/* List of users currently in this channel */
	enum channel_modes modes;			/* Channel modes (non-user specific) */
	unsigned int limit;					/* Limit on number of users in channel (only enforced on joins) */
	unsigned int throttleusers;			/* Users allowed to join per interval */
	unsigned int throttleinterval;		/* Throttle interval duration (s) */
	time_t throttlebegin;				/* When last throttle interval began */
	unsigned int throttlecount;			/* # of users that joined in the last throttle interval */
	struct stringlist invited;			/* String list of invited nicks */
	FILE *fp;							/* Optional log file to which to log all channel activity */
	RWLIST_ENTRY(irc_channel) entry;	/* Next channel */
	struct bbs_rate_limit ratelimit;	/* Time that last relayed message was sent */
	unsigned int relay:1;				/* Enable relaying */
	bbs_mutex_t lock;					/* Channel lock */
	struct recursive_lock recurse;		/* Recursive lock */
	char data[];						/* Flexible struct member for channel name / owner username */
};

static RWLIST_HEAD_STATIC(channels, irc_channel);	/* Container for all channels */

struct irc_relay {
	struct irc_relay_callbacks *relay_callbacks;
	void *mod;
	RWLIST_ENTRY(irc_relay) entry;
};

static RWLIST_HEAD_STATIC(relays, irc_relay); /* Container for all relays */

static int add_operator(const char *name, const char *password)
{
	struct irc_operator *operator;
	size_t namelen, pwlen;

	namelen = strlen(name);
	pwlen = password ? strlen(password) : 0;

	RWLIST_WRLOCK(&operators);
	RWLIST_TRAVERSE(&operators, operator, entry) {
		if (!strcmp(name, operator->name)) {
			break;
		}
	}
	if (operator) {
		RWLIST_UNLOCK(&operators);
		bbs_warning("Operator with name '%s' already exist\n", name);
		return -1;
	}
	operator = calloc(1, sizeof(*operator) + namelen + pwlen + 2);
	if (ALLOC_FAILURE(operator)) {
		RWLIST_UNLOCK(&operators);
		return -1;
	}

	strcpy(operator->data, name); /* Safe */
	operator->name = operator->data;
	if (password) {
		strcpy(operator->data + namelen + 1, password); /* Safe */
		operator->password = operator->data + namelen + 1;
	}
	RWLIST_INSERT_HEAD(&operators, operator, entry);
	RWLIST_UNLOCK(&operators);
	return 0;
}

/*
 * Yes, we really are exporting global symbols, just for a few important functions.
 * I thought about adding a relay.c/relay.h in the core that could then call these instead,
 * but the problem is modules could load before this module anyways and then consequently
 * fail to register their relay functions since this module hasn't loaded yet and registered
 * its callbacks. So, a dependency chain is inevitable and we'll have to preload this module
 * in modules.conf to guarantee things will work properly. So, whatever...
 */

int __irc_relay_register(struct irc_relay_callbacks *relay_callbacks, void *mod)
{
	struct irc_relay *relay;

	RWLIST_WRLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		if (relay_callbacks == relay->relay_callbacks) {
			break;
		}
	}
	if (relay) {
		bbs_error("Relay %p is already registered\n", relay_callbacks);
		RWLIST_UNLOCK(&relays);
		return -1;
	}
	relay = calloc(1, sizeof(*relay));
	if (ALLOC_FAILURE(relay)) {
		RWLIST_UNLOCK(&relays);
		return -1;
	}
	relay->relay_callbacks = relay_callbacks;
	relay->mod = mod;
	RWLIST_INSERT_HEAD(&relays, relay, entry);
	bbs_module_ref(BBS_MODULE_SELF, 1); /* Bump our module ref count */
	RWLIST_UNLOCK(&relays);
	return 0;
}

/* No need for a separate cleanup function since this module cannot be unloaded until all relays have unregistered */

int irc_relay_unregister(struct irc_relay_callbacks *relay_callbacks)
{
	struct irc_relay *relay;

	relay = RWLIST_WRLOCK_REMOVE_BY_FIELD(&relays, relay_callbacks, relay_callbacks, entry);
	if (relay) {
		free(relay);
		bbs_module_unref(BBS_MODULE_SELF, 1); /* And decrement the module ref count back again */
	} else {
		bbs_error("Relay %p was not previously registered\n", relay_callbacks);
		return -1;
	}
	return 0;
}

/* Programmatic user interface, e.g. ChanServ, bouncer users */

struct programmatic_user {
	struct irc_user *user;
	struct irc_event_callbacks *cb;
	enum irc_command_callback_event events;
	void *mod;
	RWLIST_ENTRY(programmatic_user) entry;
};

static RWLIST_HEAD_STATIC(programmatic_users, programmatic_user);

int __irc_register_programmatic_user(struct irc_user *user, struct irc_event_callbacks *cb, enum irc_command_callback_event events, void *mod)
{
	struct programmatic_user *p;

	p = calloc(1, sizeof(*p));
	if (ALLOC_FAILURE(p)) {
		return -1;
	}
	p->user = user;
	p->cb = cb;
	p->events = events;
	p->mod = mod;

	RWLIST_RDLOCK(&programmatic_users);
	if (!strcmp(user->username, "ChanServ")) {
		/* Since ChanServ is frequently used, always insert it at the front of the list.
		 * This way private messaging ChanServ is still constant time,
		 * even with a lot of programmatic users registered. */
		RWLIST_INSERT_HEAD(&programmatic_users, p, entry);
	} else {
		RWLIST_INSERT_TAIL(&programmatic_users, p, entry);
	}
	RWLIST_UNLOCK(&programmatic_users);

	return 0;
}

int irc_unregister_programmatic_user(struct irc_user *user)
{
	struct programmatic_user *p = RWLIST_WRLOCK_REMOVE_BY_FIELD(&programmatic_users, user, user, entry);
	if (p) {
		free(p);
	} else {
		bbs_warning("Couldn't find programmatic user %p\n", user);
	}
	return p ? 0 : -1;
}

static int chanserv_registered = 0;

int __irc_chanserv_register(struct irc_event_callbacks *cb, void *mod)
{
	int res = __irc_register_programmatic_user(&user_chanserv, cb, IRCCMD_EVENT_JOIN | IRCCMD_EVENT_TOPIC, mod); /* mod_chanserv only uses these 2 */
	if (!res) {
		chanserv_registered = 1;
	}
	return res;
}

int irc_chanserv_unregister(struct irc_event_callbacks *cb)
{
	/* We could key registration by both the user and the callback,
	 * but since the user is unique (a primary key of sorts),
	 * we don't need to use the callback at all. */
	UNUSED(cb);
	chanserv_registered = 0;
	return irc_unregister_programmatic_user(&user_chanserv);
}

static void broadcast_channel_event(enum irc_command_callback_event event, const char *channel, const char *hostmask, const char *username, const char *data)
{
	struct programmatic_user *p;
	const char *command = ""; /* Doesn't need to be initialized, but makes gcc happy */

	switch (event) {
		case IRCCMD_EVENT_NONE: command = "NONE"; break;
		case IRCCMD_EVENT_PRIVMSG: command = "PRIVMSG"; break;
		case IRCCMD_EVENT_JOIN: command = "JOIN"; break;
		case IRCCMD_EVENT_PART: command = "PART"; break;
		case IRCCMD_EVENT_QUIT: command = "QUIT"; break;
		case IRCCMD_EVENT_KICK: command = "KICK"; break;
		case IRCCMD_EVENT_TOPIC: command = "TOPIC"; break;
		case IRCCMD_EVENT_MODE: command = "MODE"; break;
		/* No default case, to force us to handle everything */
	}

	RWLIST_RDLOCK(&programmatic_users);
	RWLIST_TRAVERSE(&programmatic_users, p, entry) {
		if (p->events & event) { /* Don't make useless function calls if not subscribed for this event */
			bbs_module_ref(p->mod, 12);
			/* We intentionally use the username here, not the nickname */
			p->cb->command_cb(p->user->username, event, command, channel, hostmask, username, data);
			bbs_module_unref(p->mod, 12);
		}
	}
	RWLIST_UNLOCK(&programmatic_users);
}

static void broadcast_channel_event_external(enum irc_command_callback_event event, struct irc_channel *chan, const char *sender, const char *relayname, const char *hostname, const char *data)
{
	char hostmask[128];
	snprintf(hostmask, sizeof(hostmask), HOSTMASK_FMT, sender, relayname, hostname);
	broadcast_channel_event(event, chan->name, hostmask, sender, data);
}

static void broadcast_channel_event_internal(enum irc_command_callback_event event, struct irc_channel *chan, struct irc_user *user, const char *data)
{
	char hostmask[128];
	snprintf(hostmask, sizeof(hostmask), HOSTMASK_FMT, HOSTMASK_ARGS(user));
	broadcast_channel_event(event, chan->name, hostmask, user->username, data);
}

static int nickserv(struct irc_user *user, char *s);

static int programmatic_privmsg(struct irc_user *user, const char *recipient, char *msg)
{
	/* We only execute one callback at max, if we find a matching one */
	struct programmatic_user *p;
	char hostmask[128];

	/* Special exception for NickServ, ChanServ is handled in the normal list below */
	if (!strcasecmp(recipient, "NickServ")) {
		nickserv(user, msg);
		return 0;
	}

	snprintf(hostmask, sizeof(hostmask), HOSTMASK_FMT, HOSTMASK_ARGS(user));

	/* There is no mechanism here for writing output back to user.
	 * ChanServ and other programmatic users will send a PRIVMSG if needed,
	 * or very well do other things. */
	RWLIST_RDLOCK(&programmatic_users);
	RWLIST_TRAVERSE(&programmatic_users, p, entry) {
		if (!strcmp(p->user->username, recipient)) {
			bbs_module_ref(p->mod, 12);
			p->cb->privmsg_cb(hostmask, user->username, recipient, msg);
			bbs_module_unref(p->mod, 12);
			break;
		}
	}
	RWLIST_UNLOCK(&programmatic_users);
	return p ? 1 : 0;
}

static int chanserv_msg(struct irc_user *user, char *msg)
{
	return programmatic_privmsg(user, "ChanServ", msg);
}

static int authorized_atleast_bymode(enum channel_user_modes modes, int atleast)
{
	unsigned int auth = 0;

	switch (atleast) {
		case CHANNEL_USER_MODE_VOICE:
			auth |= modes & CHANNEL_USER_MODE_VOICE;
			/* Fall through */
		case CHANNEL_USER_MODE_HALFOP:
			auth |= modes & CHANNEL_USER_MODE_HALFOP;
			/* Fall through */
		case CHANNEL_USER_MODE_OP:
			auth |= modes & CHANNEL_USER_MODE_OP;
			/* Fall through */
		case CHANNEL_USER_MODE_ADMIN:
			auth |= modes & CHANNEL_USER_MODE_ADMIN;
			/* Fall through */
		case CHANNEL_USER_MODE_FOUNDER:
			auth |= modes & CHANNEL_USER_MODE_FOUNDER;
			/* Fall through */
		default:
			break;
	}

	return (int) auth;
}

static int authorized_atleast(struct irc_member *member, int atleast)
{
	int auth = 0;

	bbs_mutex_lock(&member->lock);
	auth = authorized_atleast_bymode(member->modes, atleast);
	bbs_mutex_unlock(&member->lock);

	return auth;
}

#define APPEND_MODE(buf, len, modes, mode, letter) if ((modes & mode) && (len-- >= 1)) { buf[pos++] = letter; }

static int get_channel_user_modes(char *buf, size_t len, struct irc_member *member)
{
	int pos = 0;

	bbs_mutex_lock(&member->lock);
	if (!member->modes) {
		bbs_mutex_unlock(&member->lock);
		buf[0] = '\0';
		return -1;
	}
	buf[pos++] = '+';
	APPEND_MODE(buf, len, member->modes, CHANNEL_USER_MODE_ADMIN, 'a');
	APPEND_MODE(buf, len, member->modes, CHANNEL_USER_MODE_HALFOP, 'h');
	APPEND_MODE(buf, len, member->modes, CHANNEL_USER_MODE_OP, 'o');
	APPEND_MODE(buf, len, member->modes, CHANNEL_USER_MODE_FOUNDER, 'q');
	APPEND_MODE(buf, len, member->modes, CHANNEL_USER_MODE_VOICE, 'v');
	(void) len; /* Suppress cppcheck whining about len being unused for the last APPEND_MODE call */
	bbs_mutex_unlock(&member->lock);
	buf[pos] = '\0';
	return 0;
}

static void get_channel_modes(char *buf, size_t len, struct irc_channel *channel)
{
	int pos = 0;
	if (!channel->modes) {
		buf[0] = '\0';
		return;
	}
	buf[pos++] = '+';
	/* Capitals come before lowercase */
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_CTCP_BLOCK, 'C');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_PERMANENT, 'P');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_TLS_ONLY, 'S');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_NOTICE_BLOCK, 'T');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_COLOR_FILTER, 'c');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_FREE_INVITE, 'g');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_INVITE_ONLY, 'i');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_THROTTLED, 'j');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_PASSWORD, 'k');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_LIMIT, 'l');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_MODERATED, 'm');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_NO_EXTERNAL, 'n');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_PRIVATE, 'p');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_REGISTERED_ONLY, 'r');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_SECRET, 's');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_TOPIC_PROTECTED, 't');
	APPEND_MODE(buf, len, channel->modes, CHANNEL_MODE_REDUCED_MODERATION, 'z');
	(void) len; /* Suppress cppcheck whining about len being unused for the last APPEND_MODE call */
	buf[pos] = '\0';
}

static int get_user_modes(char *buf, size_t len, struct irc_user *user)
{
	int pos = 0;

	bbs_mutex_lock(&user->lock);
	if (!user->modes) {
		bbs_mutex_unlock(&user->lock);
		buf[0] = '\0';
		return -1;
	}
	buf[pos++] = '+';
	APPEND_MODE(buf, len, user->modes, USER_MODE_INVISIBLE, 'i');
	APPEND_MODE(buf, len, user->modes, USER_MODE_OPERATOR, 'o');
	APPEND_MODE(buf, len, user->modes, USER_MODE_WALLOPS, 'w');
	APPEND_MODE(buf, len, user->modes, USER_MODE_SECURE, 'Z');
	(void) len; /* Suppress cppcheck whining about len being unused for the last APPEND_MODE call */
	bbs_mutex_unlock(&user->lock);
	buf[pos] = '\0';
	return 0;
}

#define MULTIPREFIX_FMT "%s%s%s%s%s"
#define MULTIPREFIX_ARGS(member) (member->modes & CHANNEL_USER_MODE_FOUNDER) ? PREFIX_FOUNDER : "", (member->modes & CHANNEL_USER_MODE_ADMIN) ? PREFIX_ADMIN : "", (member->modes & CHANNEL_USER_MODE_OP) ? PREFIX_OP : "", (member->modes & CHANNEL_USER_MODE_HALFOP) ? PREFIX_HALFOP : "", (member->modes & CHANNEL_USER_MODE_VOICE) ? PREFIX_VOICE : ""

static const char *top_channel_membership_prefix(struct irc_member *member)
{
	/* https://modern.ircdocs.horse/#channel-membership-prefixes */
	if (member->modes & CHANNEL_USER_MODE_FOUNDER) {
		return PREFIX_FOUNDER;
	} else if (member->modes & CHANNEL_USER_MODE_ADMIN) {
		return PREFIX_ADMIN;
	} else if (member->modes & CHANNEL_USER_MODE_OP) {
		return PREFIX_OP;
	} else if (member->modes & CHANNEL_USER_MODE_HALFOP) {
		return PREFIX_HALFOP;
	} else if (member->modes & CHANNEL_USER_MODE_VOICE) {
		return PREFIX_VOICE;
	}
	return "";
}

static void user_free(struct irc_user *user)
{
	if (user->modes & USER_MODE_OPERATOR) {
		RWLIST_WRLOCK(&operators);
		operators_online--;
		RWLIST_UNLOCK(&operators);
	}
	bbs_mutex_destroy(&user->lock);
	free_if(user->password);
	free_if(user->hostname);
	free_if(user->awaymsg);
	free_if(user->realname);
	free_if(user->username);
	free_if(user->nickname);
	free(user);
}

/* Forward declaration */
static void set_away_via_relays(struct irc_user *user, enum irc_user_status userstatus, const char *awaymsg);

static void unlink_user(struct irc_user *user)
{
	struct irc_user *u;

	RWLIST_WRLOCK(&users);
	u = RWLIST_REMOVE(&users, user, entry);
	RWLIST_UNLOCK(&users);
	if (!u) {
		bbs_error("Didn't find user '%s' in list\n", S_IF(user->nickname));
	}
	/* Caller will free */
}

static struct irc_member *get_member(struct irc_user *user, struct irc_channel *channel)
{
	struct irc_member *member;
	RWLIST_RDLOCK(&channel->members);
	RWLIST_TRAVERSE(&channel->members, member, entry) {
		if (member->user == user) {
			break;
		}
	}
	RWLIST_UNLOCK(&channel->members);
	return member;
}

static inline int priv_channel_owner(struct irc_channel *c, const char *username)
{
	return !strcasecmp(c->username, username);
}

static int user_is_priv_channel_owner(struct irc_channel *c, struct irc_user *u)
{
	return !strcasecmp(c->username, u->username);
}

/*!
 * \brief Find a channel by name
 * \param channel Channel name
 * \param username Owner's username, if a private namespace channel
 * \return Channel or NULL
 * \note Channels list must be locked when calling
 */
static struct irc_channel *find_channel(const char *channel, const char *username)
{
	struct irc_channel *c;

	RWLIST_TRAVERSE(&channels, c, entry) {
		if (!strcmp(c->name, channel)) {
			if (!strlen_zero(c->username)) {
				if (!strlen_zero(username) && priv_channel_owner(c, username)) {
					return c; /* Private namespace channel owned by this user */
				}
			} else {
				/* Non-private (normal) channel */
				return c;
			}
		}
	}
	return NULL;
}

static struct irc_channel *find_channel_by_user(const char *channel, struct irc_user *user)
{
	return find_channel(channel, user->node && bbs_user_is_registered(user->node->user) ? bbs_username(user->node->user) : NULL);
}

/*! \note This returns a user with no locks */
static struct irc_member *get_member_by_channel_name(struct irc_user *user, const char *channame)
{
	struct irc_channel *channel;
	struct irc_member *member;

	RWLIST_RDLOCK(&channels);
	channel = find_channel_by_user(channame, user);
	if (!channel) {
		RWLIST_UNLOCK(&channels);
		bbs_debug(3, "Channel '%s' doesn't exist\n", channame);
		return NULL;
	}
	RWLIST_TRAVERSE(&channel->members, member, entry) {
		if (member->user == user) {
			break;
		}
	}
	RWLIST_UNLOCK(&channels);

	return member;
}

/*! \note This returns a user with no locks */
/*! \todo Replace usage of get_user with get_user_locked, and have caller unlock user when we're done with it */
static struct irc_user *get_user(const char *nickname)
{
	struct irc_user *user;

	if (!strcasecmp(nickname, "ChanServ") && chanserv_registered) {
		return &user_chanserv;
	}

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, user, entry) {
		if (!strcasecmp(user->nickname, nickname)) {
			break;
		}
	}
	RWLIST_UNLOCK(&users);
	return user;
}

/*! \note Returns a non-programmatic user, locked */
static struct irc_user *get_user_return_locked(const char *nickname)
{
	struct irc_user *user;

	if (!strcasecmp(nickname, "ChanServ") && chanserv_registered) {
		return &user_chanserv;
	}

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, user, entry) {
		if (!user->programmatic && !strcasecmp(user->nickname, nickname)) {
			bbs_mutex_lock(&user->lock);
			break;
		}
	}
	RWLIST_UNLOCK(&users);
	return user;
}

int irc_user_inactive(const char *username)
{
	struct irc_user *user;

	if (!strcasecmp(username, "ChanServ") && chanserv_registered) {
		return 1;
	}

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, user, entry) {
		/* Ignore programmatic users (e.g. bouncer clients masquerading as real users),
		 * as those should not cause us to think a user is active. */
		if (!user->programmatic && !strcasecmp(user->username, username)) {
			int res = user->away ? 1 : 0;
			RWLIST_UNLOCK(&users);
			return res;
		}
	}
	RWLIST_UNLOCK(&users);
	return -1;
}

int irc_user_send_single(const char *username, const char *data)
{
	struct irc_user *u = get_user_return_locked(username);
	if (!u) {
		bbs_warning("Can't write data to %s (not online)\n", username);
		return -1;
	}
	irc_other_thread_writef(u->node, "%s", data);
	bbs_mutex_unlock(&u->lock);
	return 0;
}

int irc_user_send_chunk(struct irc_user *user, const char *data)
{
	/* user is already locked */
	return irc_other_thread_writef(user->node, "%s", data) < 0 ? -1 : 0;
}

int irc_user_send_multiple(const char *username, int (*write_cb)(struct irc_user *user, void *obj), void *obj)
{
	int res;
	struct irc_user *user = get_user_return_locked(username);
	if (!user) {
		bbs_warning("Can't write data to %s (not online)\n", username);
		return -1;
	}
	/* Now that we searched for the user once,
	 * give the callback a handle to it,
	 * and let it write stuff out. */
	res = write_cb(user, obj); /* Keep locked so it can't go away while in use */
	bbs_mutex_unlock(&user->lock);
	return res;
}

static struct irc_member *get_member_by_nickname(const char *nickname, const char *channame)
{
	struct irc_user *user = get_user(nickname);
	if (!user) {
		return NULL;
	}
	return get_member_by_channel_name(user, channame);
}

/*! \note Mainly exists so that ChanServ can easily get the modes of channel members */
enum channel_user_modes irc_get_channel_member_modes(const char *channel, const char *nickname)
{
	struct irc_member *member = get_member_by_nickname(nickname, channel);
	if (!member) {
		return CHANNEL_USER_MODE_NONE;
	}
	return member->modes;
}

/*! \note This returns a channel with no locks */
/*! \warning Do not use this function, generally speaking, as it does not support private namespace awareness. Use find_channel or find_channel_by_user */
static struct irc_channel *get_channel(const char *channame)
{
	struct irc_channel *channel;

	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (!strcmp(channel->name, channame)) {
			break;
		}
	}
	RWLIST_UNLOCK(&channels);
	return channel;
}

const char *irc_channel_topic(const char *channel)
{
	struct irc_channel *c = get_channel(channel); /* The only place this is used, this would not be a private namespace channel anyways */
	if (!c) {
		return NULL;
	}
	return c->topic;
}

int irc_valid_channel_name(const char *s)
{
	int i = 0;
	if (!VALID_CHANNEL_NAME(s) || strlen(s) > MAX_CHANNEL_LENGTH) {
		return 0;
	}
	while (*s) {
		if (!isalnum(*s) && *s != '-' && !(!i && VALID_CHANNEL_NAME_PREFIX(*s))) {
			bbs_debug(3, "Character %d is not valid\n", *s);
			return 0;
		}
		s++;
		i = 1;
	}
	return 1;
}

static void channel_free(struct irc_channel *channel)
{
	bbs_assert(channel->membercount == 0);
	stringlist_empty_destroy(&channel->invited);
	bbs_mutex_destroy(&channel->lock);
	bbs_mutex_destroy(&channel->recurse.lock);
	if (channel->fp) {
		fclose(channel->fp);
		channel->fp = NULL;
	}
	free_if(channel->password);
	free_if(channel->topicsetby);
	free_if(channel->topic);
	RWLIST_HEAD_DESTROY(&channel->members);
	free(channel);
}

static void member_free(struct irc_member *member)
{
	bbs_mutex_destroy(&member->lock);
	free(member);
}

#define CHANNEL_MEMBER_COUNT_ADJUST(channel, incr) \
	bbs_mutex_lock(&channel->lock); \
	channel->membercount += incr; \
	bbs_assert(channel->membercount >= 0); \
	bbs_mutex_unlock(&channel->lock);

static void destroy_channels(void)
{
	struct irc_channel *channel;

	RWLIST_WRLOCK(&channels);
	while ((channel = RWLIST_REMOVE_HEAD(&channels, entry))) {
		struct irc_member *member;
		RWLIST_WRLOCK(&channel->members); /* Kick any members still present */
		while ((member = RWLIST_REMOVE_HEAD(&channel->members, entry))) {
			CHANNEL_MEMBER_COUNT_ADJUST(channel, -1);
			member_free(member);
		}
		RWLIST_UNLOCK(&channel->members);
		channel_free(channel);
	}
	RWLIST_UNLOCK(&channels);
}

static void destroy_operators(void)
{
	RWLIST_WRLOCK_REMOVE_ALL(&operators, entry, free);
}

#define channel_broadcast(channel, user, fmt, ...) __channel_broadcast(1, channel, user, 0, fmt, ## __VA_ARGS__)
#define channel_broadcast_nolock(channel, user, fmt, ...) __channel_broadcast(0, channel, user, 0, fmt, ## __VA_ARGS__)
#define channel_broadcast_selective(channel, user, minmode, fmt, ...) __channel_broadcast(1, channel, user, minmode, fmt, ## __VA_ARGS__)

/*
 * Forward declaration needed since __attribute__ can only be used with declarations, not definitions.
 * See http://www.unixwiz.net/techtips/gnu-c-attributes.html#compat
 * We only need the redundant declarations for static functions with attributes.
 */
static int __attribute__ ((format (gnu_printf, 5, 6))) __channel_broadcast(int lock, struct irc_channel *channel, struct irc_user *user, enum channel_user_modes minmode, const char *fmt, ...);

/*!
 * \brief Send a message to everyone (or almost everyone) in a channel
 * \param lock
 * \param channel Channel to which to broadcast
 * \param user A user to which to NOT send the message (typically to prevent echoes of a user's own messages). NULL to really send to everyone.
 * \param minmode The minimum channel user mode required to broadcast the message
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
static int __channel_broadcast(int lock, struct irc_channel *channel, struct irc_user *user, enum channel_user_modes minmode, const char *fmt, ...)
{
	struct irc_member *member;
	char *buf;
	int len;
	int sent = 0, skipped = 0;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	if (lock) {
		RWLIST_RDLOCK(&channel->members);
	}
	RWLIST_TRAVERSE(&channel->members, member, entry) {
		if (user && user == member->user) {
			skipped++;
			continue; /* Skip */
		}
		if (minmode && !authorized_atleast(member, minmode)) {
			skipped++;
			continue; /* Skip those who don't have at least a certain privilege (e.g. for moderating messages only to ops) */
		}
		bbs_assert_exists(member->user);
		/* Careful here... we want member->user, not user */
		irc_other_thread_write(member->user->node, buf, (size_t) len);
		sent++;
	}
	if (lock) {
		RWLIST_UNLOCK(&channel->members);
	}
	bbs_debug(5, "(%d/%d) <= %s", sent, skipped, buf); /* Log it just once, not for every user to whom we send it. Message ends in CR LF, so don't add one here. */
	if (channel->fp) {
		time_t lognow;
		struct tm logdate;
		char datestr[20];
		/* Calculate our current timestamp, for logging sanity */
		lognow = time(NULL);
		localtime_r(&lognow, &logdate);
		strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);
		fprintf(channel->fp, "[%s] %s", datestr, buf); /* Assume it ends in CR LF (it better!) */
	}
	/* It's possible to send to 0 users only if there's only one user in the channel and user is non NULL (don't echo to sender) */
	if (!sent && !user) {
		bbs_warning("Message was broadcast to 0 users in channel %s?\n", channel->name); /* Probably a bug */
	}
	free(buf);
	return 0;
}

static void user_setactive(struct irc_user *user)
{
	bbs_mutex_lock(&user->lock);
	user->lastactive = time(NULL);
	bbs_mutex_unlock(&user->lock);
}

/*!
 * \param channel
 * \param user Should be NULL for "system" generated messages and provided for messages actually sent by that user.
 * \param username
 * \param buf
 * \param sendingmod
 */
static void relay_broadcast(struct irc_channel *channel, struct irc_user *user, const char *username, const char *buf, void *sendingmod)
{
	/* Now, relay it to any other external integrations that may exist. */
	struct irc_relay *relay;
	struct irc_relay_message rmsg;

	memset(&rmsg, 0, sizeof(rmsg));
	rmsg.channel = channel->name;
	rmsg.sender = user ? user->nickname : username ? username : NULL;
	rmsg.msg = buf;
	rmsg.sendingmod = sendingmod;

	if (channel->relay) {
		int res = 0;
		RWLIST_RDLOCK(&relays);
		RWLIST_TRAVERSE(&relays, relay, entry) {
			if (sendingmod == relay->mod) {
				/* Don't relay messages from a module back to itself! */
#ifdef EXTRA_DEBUG
				bbs_debug(8, "Not relaying message back to module %p\n", sendingmod);
#endif
				continue;
			}
			if (relay->relay_callbacks->relay_send) {
				bbs_module_ref(relay->mod, 4);
				res = relay->relay_callbacks->relay_send(&rmsg);
				if (res == 1 && user && bbs_user_is_registered(user->node->user)) {
					/* Delivery of this message failed.
					 * If the sender is a local IRC user, privately notify the sender of this.
					 * Currently, only mod_slack returns an error on failure to deliver message to Slack. */
					send_reply(user, "NOTICE PRIVMSG :*** Your message could not be successfully relayed.\r\n");
				}
				if (res == -1) {
					bbs_module_unref(relay->mod, 4);
					break;
				}
				bbs_module_unref(relay->mod, 4);
			}
		}
		RWLIST_UNLOCK(&relays);
	}
}

int _irc_relay_raw_send(const char *channel, const char *msg, void *mod)
{
	struct irc_channel *c = get_channel(channel); /* mod_irc_relay is the only caller of irc_relay_raw_send, and private namespace awareness isn't supported from other IRC <-> native IRC */
	if (!c) {
		/* If there aren't any members in the channel, it doesn't exist,
		 * so relaying to it will fail.
		 * This includes the case where some non-IRC service A is relaying
		 * to a non-native IRC network C. The relay flow here is:
		 * A -> B -> C (where B is net_irc, the native IRC network)
		 * However, if there are no members of B's channel,
		 * then we stop here.
		 * The solution that allows relaying from A to C even when B does not
		 * exist is to... make it exist, e.g. guard the channel with ChanServ. */
		bbs_warning("Failed to relay to nonexistent channel %s (no members)\n", channel);
		return -1;
	}
	channel_broadcast_nolock(c, NULL, "%s\r\n", msg);
	if (c->relay) {
		relay_broadcast(c, NULL, NULL, msg, mod);
	}
	return 0;
}

static void channel_print_topic(struct irc_user *user, struct irc_channel *channel)
{
	if (channel->topic) {
		if (!user) { /* Broadcast (topic change) */
			send_numeric_broadcast(channel, NULL, 332, "%s :%s\r\n", channel->name, S_IF(channel->topic));
			send_numeric_broadcast(channel, user, 333, "%s %s %" TIME_T_FMT "\r\n", channel->name, channel->topicsetby, channel->topicsettime);
		} else {
			send_numeric2(user, 332, "%s :%s\r\n", channel->name, S_IF(channel->topic));
			send_numeric2(user, 333, "%s %s %" TIME_T_FMT "\r\n", channel->name, channel->topicsetby, channel->topicsettime);
		}
	} else {
		if (!user) {
			send_numeric_broadcast(channel, user, 331, "%s :No topic is set\r\n", channel->name);
		} else {
			send_numeric2(user, 331, "%s :No topic is set\r\n", channel->name);
		}
	}
}

int irc_relay_set_topic(const char *channel, const char *topic, const char *ircuser)
{
	char buf[128];
	struct irc_channel *c = find_channel(channel, ircuser);

	if (!c) {
		bbs_warning("Could not find channel %s?\n", channel);
		return -1;
	}

	bbs_mutex_lock(&c->lock);
	REPLACE(c->topic, topic);
	snprintf(buf, sizeof(buf), HOSTMASK_FMT, HOSTMASK_ARGS(&user_messageserv));
	REPLACE(c->topicsetby, buf);
	c->topicsettime = time(NULL);
	bbs_mutex_unlock(&c->lock);

	channel_print_topic(NULL, c);
	broadcast_channel_event_internal(IRCCMD_EVENT_TOPIC, c, &user_messageserv, topic);
	return 0;
}

static int transform_and_send(const char *channel, enum channel_user_modes modes, const char *relayname, const char *sender, const char *hostsender, const char *restrict msg, int(*transform)(const char *line, char *buf, size_t len), const char *ircuser, void *mod)
{
	/* The maximum length of a single IRC message is 512 characters,
	 * but we use a slightly larger buffer here in case the transform
	 * function replaces substrings with larger substrings.
	 * If we limit the buffer to 512, and we get a message of the maximum
	 * length, expansion will fail since truncation will occur.
	 * This should be good enough to allow reasonable transformation of
	 * a message of any valid length.
	 * If the buffer is still too small, we'll dynamically allocate one.
	 */
	char linebuf[624];
	size_t linelen;
	int res;
	/* We use both final and line, so that we can accept a const argument (msg)
	 * and provide a const argument to _irc_relay_send.
	 * The added complication avoids the need to allocate if the length
	 * of the message is sufficiently small, which is the common case. */
	char *line = NULL;
	const char *final;
	char *dynbuf = NULL;

	if (strlen_zero(msg)) {
		return -1;
	}

	if (transform) {
		size_t origlen = strlen(msg);
		if (origlen >= sizeof(linebuf) - 50) {
			/* Stack allocated buffer is probably too small.
			 * Dynamically allocate. */
			if (origlen >= 4096) {
				bbs_warning("Refusing to relay excessively long message of length %lu\n", origlen);
				return -1;
			}
			dynbuf = malloc(origlen + 50);
			if (ALLOC_FAILURE(dynbuf)) {
				return -1;
			}
			strcpy(dynbuf, msg); /* Safe */
			res = transform(msg, dynbuf, origlen + 50);
		} else {
			res = transform(msg, linebuf, sizeof(linebuf));
		}
		if (res < 0) {
			free_if(dynbuf);
			return -1;
		}
		if (origlen >= sizeof(linebuf) - 50) {
			line = dynbuf;
		} else {
			line = linebuf;
		}
		bbs_strterm(line, '\r');
		final = line;
	} else {
		final = msg;
	}

	linelen = strlen(final);
	if (linelen > 510 || (!line && strchr(final, '\r'))) {
		/* If has a trailing CR, we need to strip it.
		 * Since msg is const, we need to use a buffer to modify if that's the case. */
		if (linelen > sizeof(linebuf)) {
			dynbuf = strdup(final);
			if (ALLOC_FAILURE(dynbuf)) {
				return -1;
			}
			final = line = dynbuf;
		} else {
			strcpy(linebuf, final); /* Safe */
			final = line = linebuf;
		}
	}

	/* Truncation becomes likely beyond this point, so split the message up.
	 * This is because the relay modules may prefix a sender name,
	 * and the raw IRC message itself prefixes the command name and the channel.
	 * Thus, we may add something like:
	 * PRIVMSG #channel :<username>
	 * and this could be 40-50 bytes, potentially.
	 * Being conservative on message length here reduces the chance that
	 * the message will be within bounds within the BBS but exceed 512 when it hits lirc
	 * to actually generate the final message.
	 *
	 * On top of that, libera seems to be truncating messages at 470 characters,
	 * which is far under the 512 character limit. Clients as well attempt to split
	 * messages under the 512 character limit, with Ambassador doing so around 462.
	 * So, we actually want to aim somewhere around 100 fewer characters than the 512 limit,
	 * to be conservative and ensure truncation doesn't occur when relaying to IRC.
	 */

#define MAX_PREFORMATTED_RELAY_MSGLEN 412
	while (linelen > MAX_PREFORMATTED_RELAY_MSGLEN) {
		char c1, c2, c3, c4;
		/* Message is too long to be a single message towards IRC.
		 * Split it up. */
		char *end = line + MAX_PREFORMATTED_RELAY_MSGLEN - 10; /* Leave room for the relay module to prefix a username later. */
		const char *midpoint = line + MAX_PREFORMATTED_RELAY_MSGLEN / 2;
		/* Look for a graceful position to split the message (a space).
		 * In the worst case, there are no spaces, and we should split the
		 * message in the second half no matter what, so we send a maximum
		 * of 2-3 messages per ~512 characters. */
#pragma GCC diagnostic push /* ignore spurious warning */
#pragma GCC diagnostic ignored "-Wstrict-overflow"
		while (end > midpoint && !isspace(*end)) {
			end--;
		}
#pragma GCC diagnostic pop
		/* We are guaranteed here that *end is not the last character in the message. */
		end++; /* Move back forward past the space. */
		c1 = *end; /* Save character at this position. */
		c2 = *(end + 1);
		c3 = *(end + 2);
		c4 = *(end + 3);
		/* Use ... to indicate payload will be continued in another message.
		 * It will be prefixed by a space, which is fine since it likely differentiates from user-added '...',
		 * since user-created messages are likely to end "EOM..." not "EOM ..." */
		*end = '.';
		*(end + 1) = '.';
		*(end + 2) = '.';
		*(end + 3) = '\0'; /* NUL terminate to split message. */
		_irc_relay_send(channel, modes, relayname, sender, hostsender, final, ircuser, 0, mod);
		*end = c1; /* Restore character */
		*(end + 1) = c2;
		*(end + 2) = c3;
		*(end + 3) = c4;
		end -= 3;
		final = line = end; /* This is the beginning of the next chunk to send. */
		linelen = strlen(line);
		/* Since we subtracted 3 from the end, we can use the first 3 characters to put '...' for message continuation indication */
		*end = '.';
		*(end + 1) = '.';
		*(end + 2) = '.';
	}

	/* Send entire message, if less than max message length, or the last chunk, if it was larger. */
	res = _irc_relay_send(channel, modes, relayname, sender, hostsender, final, ircuser, 0, mod);
	free_if(dynbuf);
	return res;
}

int _irc_relay_send_multiline(const char *channel, enum channel_user_modes modes, const char *relayname, const char *sender, const char *hostsender, const char *msg, int(*transform)(const char *line, char *buf, size_t len), const char *ircuser, void *mod)
{
	int res = 0;
	int line_count = 0;
	char *dup, *line, *lines;

	if (!strchr(msg, '\n')) { /* Avoid unnecessarily allocating memory if we don't have to. */
		res |= transform_and_send(channel, modes, relayname, sender, hostsender, msg, transform, ircuser, mod);
	} else {
		dup = strdup(msg);
		if (ALLOC_FAILURE(dup)) {
			return -1;
		}
		lines = dup;
		while ((line = strsep(&lines, "\n"))) {
			if (++line_count > 1) {
				/* Max of 5 messages to IRC per second,
				 * so sleep 200 ms between each message we send.
				 * This should avoid getting rejected by the rate limiter... */
				bbs_debug(1, "Sleeping 200 ms to avoid spamming IRC (line %d)\n", line_count);
				bbs_safe_sleep(200);
				if (line_count > 10) {
					/* Okay, now this is getting ridiculous... abort. */
					free(dup);
					bbs_warning("Truncating excessively long message relayed to IRC\n");
					return 1;
				}
			}
			res |= transform_and_send(channel, modes, relayname, sender, hostsender, line, transform, ircuser, mod);
		}
		free(dup);
	}
	return res;
}

/*! \brief Somewhat condensed version of privmsg, for relay integration */
int _irc_relay_send(const char *channel, enum channel_user_modes modes, const char *relayname, const char *sender, const char *hostsender, const char *msg, const char *ircuser, int notice, void *mod)
{
	char hostname[84];
	struct irc_channel *c;
	
	enum channel_user_modes minmode = CHANNEL_USER_MODE_NONE;

	/*! \todo need to respond with appropriate numerics here */
	if (strlen_zero(msg)) {
		bbs_debug(5, "Ignoring empty message\n");
		return -1;
	}
	if (strlen(msg) >= 510) { /* Include CR LF */
		bbs_debug(5, "Message too long to relay to IRC: %lu bytes\n", strlen(msg));
		return -1;
	}

	/* If something specific specified, use the override, otherwise use the same thing.
	 * This allows relay modules to customize the hostmask if they want. */
	if (!strlen_zero(hostsender)) {
		/* We were provided a hostname/IP address directly for this part that we can use. */
		safe_strncpy(hostname, hostsender, sizeof(hostname));
	} else {
		snprintf(hostname, sizeof(hostname), "%s/%s", relayname, sender);
	}

	/* It's not our job to filter messages, clients can do that. For example, decimal 1 is legitimate for CTCP commands. */

	if (!IS_CHANNEL_NAME(channel)) {
		struct irc_user *user2 = get_user(channel);
		/* Private message to another user. This is super simple, there's no other overhead or anything involved. */
		if (!user2) {
			bbs_debug(7, "No such user: %s\n", channel);
			return -1;
		}
#if 0 /* No longer applies: irc_other_thread_writef handles serialization */
		/* notice is only true when the relay module is sending a message as part of a relay callback,
		 * in which case user is already locked. Don't lock again, or we'll deadlock.
		 * If !notice, this isn't the case. */
		if (!notice) {
			bbs_mutex_lock(&user2->lock); /* Serialize writes to this user */
		}
#endif
		irc_other_thread_writef(user2->node, ":" HOSTMASK_FMT " %s %s :%s\r\n", sender, relayname, hostname, notice ? "NOTICE" : "PRIVMSG", user2->nickname, msg);
#if 0
		if (!notice) {
			bbs_mutex_unlock(&user2->lock);
		}
#endif
		/* Don't care if user is away in this case */
		return 0;
	}

	/*! \todo simplify using get_channel, get_member? But then we may have more locking issues... */
	/* Grab a RDLOCK, unless this thread already has it WRLOCK'ed in a higher stack frame,
	 * which can happen if something is being relayed in response to a callback firing. */
	RWLIST_RDLOCK_RECURSIVE(&channels, &channels_recurse);
	c = find_channel(channel, ircuser);
	RWLIST_UNLOCK_RECURSIVE(&channels, &channels_recurse);

	if (!c) {
		if (ircuser) {
			/* If this is a personal relay, then the channel may not exist currently, because the user hasn't joined it,
			 * but if the user is online, s/he will probably want to join. */
			struct irc_user *u = get_user(ircuser);
			if (!u) {
				/* User is offline, nothing we can do... maybe we could send an email notification about a missed message,
				 * but blindly do this would not be feasible. If the user missed 500 messages while not on IRC,
				 * then that would be 500 emails... */
				bbs_debug(5, "Message not deliverable, %s is not online\n", ircuser);
				return -1;
			}
			/* We cannot deliver the message to the channel, but since it's a private relay,
			 * and the user is online, just send a PM with the message.
			 * Also invite the user to join to receive further messages "normally". */
			send_reply(u, ":" HOSTMASK_FMT " INVITE %s %s\r\n", HOSTMASK_ARGS(&user_messageserv), u->nickname, channel);
			irc_other_thread_writef(u->node, ":" HOSTMASK_FMT " %s %s :%s\r\n", HOSTMASK_ARGS(&user_messageserv), "NOTICE", u->nickname, msg);
		}
		return -1;
	}

	/* If channel doesn't allow relaying, don't do it. */
	if (!c->relay) {
		return -1;
	}

	/* There's no actual irc_user for the relay, but we do get member modes passed in that we can use. */
	if (c->modes & CHANNEL_MODE_MODERATED && !authorized_atleast_bymode(modes, CHANNEL_USER_MODE_VOICE)) {
		if (c->modes & CHANNEL_MODE_REDUCED_MODERATION) {
			minmode = CHANNEL_USER_MODE_HALFOP;
		} else {
			bbs_debug(3, "You're neither voiced nor a channel operator\r\n"); /* Channel moderated, unable to send */
			return -1;
		}
	}

	if (ircuser) {
		/* This channel exists, so that means that there is at least one user in it.
		 * However, we don't actually know that the user (or users) are authorized to receive this message.
		 * So, explicitly check the channel membership. If there is anyone present besides ircuser,
		 * kick the user from the channel. */
		struct irc_member *member;
		RWLIST_WRLOCK(&c->members);
		RWLIST_TRAVERSE_SAFE_BEGIN(&c->members, member, entry) {
			struct irc_user *kicked = member->user;
			if (!strcasecmp(kicked->nickname, ircuser)) {
				/* If using the nickname of the username, must be the user */
				continue;
			}
			if (!IS_REAL_USER(kicked)) {
				continue; /* Programmatic users (including services) do not have a node. */
			}
			if (bbs_user_is_registered(kicked->node->user) && !strcasecmp(bbs_username(kicked->node->user), ircuser)) {
				/* Nicknames are unique but usernames are not, across all sessions.
				 * User could be logged in as something else, but if authenticated as same user, also fine */
				continue;
			}
			bbs_auth("Dropping unauthorized user %s from relayed channel %s\n", kicked->nickname, c->name);
			RWLIST_REMOVE_CURRENT(entry);
			CHANNEL_MEMBER_COUNT_ADJUST(c, -1);
			member_free(member);
			/* Already locked, so don't try to recursively lock: */
			channel_broadcast_nolock(c, NULL, ":" HOSTMASK_FMT " KICK %s %s :%s\r\n", HOSTMASK_ARGS(&user_messageserv), c->name, kicked->nickname, "Not authorized to receive relayed messages");
		}
		RWLIST_TRAVERSE_SAFE_END;
		RWLIST_UNLOCK(&c->members);
	}

	/* One has to be careful when relaying messages from "modern" walled gardens like Slack and Discord to an IRC channel,
	 * since these applications allow users to easily construct messages that are not tolerated on IRC.
	 * Libera, for example, will drop a client if it sends more than 5 messages in the same second.
	 * Therefore, if a relay is providing us with spammy input, we MUST either truncate them or sleep between transmissions.
	 *
	 * There are several places this could be done (going further down the call stack):
	 * - net_irc: in _irc_relay_send_multiline, when processing multiline message
	 * - net_irc: in _irc_relay_send (broader), to handle any transmissions into an IRC relay
	 * - mod_irc_relay: per each individual IRC relay (in mod_irc_relay)
	 * - mod_irc_client: Transmissions towards each IRC client
	 *
	 * The last one is not suitable, since it's too specific to individual IRC clients, and we may not want to rate limit everything.
	 * The first one is not specific enough, since a user could send many individual messages at once that aren't multiline,
	 *   even though this may be the most common way of triggering this issue.
	 * The middle two are more suitable places to have these kinds of guardrails.
	 * The tiebreaker comes down to whether or not we should prevent flooding of all messages to the network IRC server,
	 * or specifically relays as well, and it makes sense that we should do both.
	 *
	 * _irc_relay_send is not ideal for enforcing rate limiting because it doesn't know where the message came from
	 * (specifically, there is no data structure available here where we can keep track of rate limiting by sender / sending module).
	 * However, it is better than nothing considering net_irc could keep track of rate limiting on a per-user basis,
	 * but relayed messages aren't associated with users, so this will just have to do. If we detect a large amount
	 * of traffic coming into the IRC channel from *ALL* sources, we can act upon that.
	 *
	 * Therefore, we take a two-pronged approach:
	 * - _irc_relay_send should ENFORCE rate limiting for ALL relayed-in traffic, since at this point, we don't know where the message came from.
	 *   This won't apply to _irc_relay_raw_send or privmsg (non-relayed PRIVMSG), but it will apply to all messages from "outside" the BBS going through it.
	 * - Individual relay modules (e.g. mod_discord) should DISCOURAGE and RESTRICT flooding but truncating or dropping messages,
	 *   so as to proactively prevent flooding before _irc_relay_send has to drop messages as a last resort, and inform senders about the overload.
	 */
	bbs_mutex_lock(&c->lock);
	/* Atomically check since this this function can be called from multiple threads. */
	if (bbs_rate_limit_exceeded(&c->ratelimit)) {
		bbs_mutex_unlock(&c->lock);
		bbs_warning("Rate limit exceeded, dropping message...\n");
		/* Drop message if rate limit exceeded.
		 * Unlike per-user rate limits,
		 * we can't notify anyone about this. */
		return -1;
	}
	bbs_mutex_unlock(&c->lock);

	channel_broadcast_selective(c, NULL, minmode, ":" HOSTMASK_FMT " %s %s :%s\r\n", sender, relayname, hostname, "PRIVMSG", c->name, msg);
	relay_broadcast(c, NULL, sender, msg, mod);
	broadcast_channel_event_external(IRCCMD_EVENT_PRIVMSG, c, sender, relayname, hostname, msg); /* For messages from relays to go to the bouncer */
	return 0;
}

static int privmsg(struct irc_user *user, const char *channame, int notice, char *message)
{
	struct irc_channel *channel;
	struct irc_member *m;
	char stripbuf[513];
	size_t msglen;
	enum channel_user_modes minmode = CHANNEL_USER_MODE_NONE;

	user_setactive(user);

	if (strlen_zero(message)) {
		send_numeric(user, 412, "No text to send\r\n");
		return -1;
	}

	msglen = strlen(message);
	if (msglen >= 510) { /* Include CR LF */
		send_numeric(user, 416, "Input too large\r\n"); /* XXX Not really the right numeric */
		return -1;
	}

	/*! \todo FIXME Could be multiple channels, comma-separated (not currently supported) */

	if (!notice && programmatic_privmsg(user, channame, message)) {
		return 0;
	} /* else, fall through to IS_CHANNEL_NAME so we can send a 401 response. */

	if (!IS_CHANNEL_NAME(channame)) {
		struct irc_user *user2 = get_user(channame);
		/* Private message to another user. This is super simple, there's no other overhead or anything involved. */
		if (!user2) {
			int res = 0;
			struct irc_relay *relay;
			/* Check if the user exists in any callbacks. */
			RWLIST_RDLOCK(&relays);
			RWLIST_TRAVERSE(&relays, relay, entry) {
				if (!relay->relay_callbacks->privmsg) {
					continue;
				}
				bbs_module_ref(relay->mod, 5);
				res = relay->relay_callbacks->privmsg(channame, user->nickname, message);
				if (res) {
					bbs_module_unref(relay->mod, 5);
					break;
				}
				bbs_module_unref(relay->mod, 5);
			}
			RWLIST_UNLOCK(&relays);
			if (!relay) { /* Didn't exist in a relay either */
				send_numeric2(user, 401, "%s :No such nick/channel\r\n", channame);
				return -1;
			}
			if (res == -1) { /* Relay tried to deliver it but failed */
				send_numeric2(user, 401, "%s :Message delivery failed\r\n", channame);
				return -1;
			}
		} else {
			irc_other_thread_writef(user2->node, ":" HOSTMASK_FMT " %s %s :%s\r\n", HOSTMASK_ARGS(user), notice ? "NOTICE" : "PRIVMSG", user2->nickname, message);
			if (user2->away) {
				send_numeric(user, 301, "%s :%s\r\n", user2->nickname, S_IF(user2->awaymsg));
			}
		}
		return 0;
	}

	RWLIST_RDLOCK(&channels);
	channel = find_channel_by_user(channame, user);
	if (!channel) {
		RWLIST_UNLOCK(&channels);
		send_numeric2(user, 403, "%s :No such channel\r\n", channame);
		return -1;
	}

	/* Check if we're actually in the channel */
	RWLIST_RDLOCK(&channel->members);
	RWLIST_TRAVERSE(&channel->members, m, entry) {
		if (m->user == user) {
			break;
		}
	}
	RWLIST_UNLOCK(&channel->members);
	RWLIST_UNLOCK(&channels);

	if (!m && channel->modes & CHANNEL_MODE_NO_EXTERNAL) {
		send_numeric(user, 442, "You're not on that channel\r\n");
		return -1;
	}

	if (channel->modes & CHANNEL_MODE_MODERATED && (!m || !authorized_atleast(m, CHANNEL_USER_MODE_VOICE))) {
		if (channel->modes & CHANNEL_MODE_REDUCED_MODERATION) {
			minmode = CHANNEL_USER_MODE_HALFOP;
		} else {
			send_numeric(user, 489, "You're neither voiced nor a channel operator\r\n"); /* Channel moderated, unable to send */
			return -1;
		}
	}

	/* It's not our job to filter messages, clients can do that. For example, decimal 1 is legitimate for CTCP commands.
	 * Unless we've specifically been told we should do some filtering. */
	if (channel->modes & CHANNEL_MODE_CTCP_BLOCK) {
		if (*message == 0x01 && !STARTS_WITH(message + 1, "ACTION ")) { /* Denotes beginning of CTCP message */
			send_numeric2(user, 404, "%s :Cannot send to nick/channel\r\n", channame);
			return -1;
		}
	}
	if (channel->modes & CHANNEL_MODE_NOTICE_BLOCK) {
		if (notice && *message != 0x01) { /* Denotes beginning of CTCP reply */
			send_numeric2(user, 404, "%s :Cannot send to nick/channel\r\n", channame);
			return -1;
		}
	}
	if (channel->modes & CHANNEL_MODE_COLOR_FILTER) {
		int newlen;
		if (bbs_ansi_strip(message, msglen, stripbuf, sizeof(stripbuf), &newlen)) {
			/* Our fault */
			send_numeric2(user, 404, "%s :Cannot send to nick/channel\r\n", channame);
			return -1;
		}
		message = stripbuf; /* Send the message, stripped of all color/formatting/etc. */
	}

	/*! \todo By default, don't echo messages to ourself, but could if enabled: https://ircv3.net/specs/extensions/echo-message */
	channel_broadcast_selective(channel, user, minmode, ":" HOSTMASK_FMT " %s %s :%s\r\n", HOSTMASK_ARGS(user), notice ? "NOTICE" : "PRIVMSG", channel->name, message);
	if (channel->relay && !notice) {
		relay_broadcast(channel, user, NULL, message, NULL);
	}
	broadcast_channel_event_internal(IRCCMD_EVENT_PRIVMSG, channel, user, message);
	return 0;
}

static void handle_privmsg(struct irc_user *user, char *s, int notice)
{
	char *channel;
	/* Format for channel messages:
	 * PRIVMSG #channel :my message
	 */
	channel = strsep(&s, " ");
	if (channel) {
		if (s && *s == ':') {
			s++; /* Skip leading : */
		}
		privmsg(user, channel, notice, s);
	}
}

static int print_channel_mode(struct irc_user *user, struct irc_channel *channel)
{
	char chanmode[16];
	if (!channel) {
		send_numeric2(user, 403, "%s :No such channel\r\n", ""); /* Whoops */
		return -1;
	}
	get_channel_modes(chanmode, sizeof(chanmode), channel);
	if (user) {
		send_reply(user, ":%s MODE %s %s\r\n", irc_hostname, channel->name, chanmode);
	} else {
		channel_broadcast(channel, user, ":%s MODE %s %s\r\n", irc_hostname, channel->name, chanmode);
	}
	return 0;
}

#if 0
static int print_member_mode(struct irc_member *member, struct irc_channel *channel)
{
	char chanmode[16];
	if (!channel || !member) {
		return -1;
	}
	get_channel_user_modes(chanmode, sizeof(chanmode), member);
	channel_broadcast(channel, NULL, ":%s MODE %s %s %s\r\n", irc_hostname, channel->name, chanmode, member->user->nickname);
	return 0;
}
#endif

static int print_user_mode(struct irc_user *user)
{
	char usermode[16];
	get_user_modes(usermode, sizeof(usermode), user);
	send_reply(user, ":%s MODE %s :%s\r\n", user->nickname, user->nickname, usermode);
	return 0;
}

#define SET_MODE(modes, set, mode) \
	if (set && !(modes & mode)) { \
		bbs_debug(6, "Set mode %s\n", #mode); \
		modes |= (unsigned int) mode; \
		changed++; \
	} else if (!set && modes & mode) { \
		bbs_debug(6, "Cleared mode %s\n", #mode); \
		modes &= (unsigned int) ~mode; \
		changed++; \
	} else { \
		bbs_debug(6, "Not %sting mode %s (no change)\n", set ? "set" : "unset", #mode); \
	}

#define SET_MODE_FORCE(modes, set, mode) \
	if (set) { \
		bbs_debug(6, "Set mode %s\n", #mode); \
		modes |= (unsigned int) mode; \
		changed++; \
	} else { \
		bbs_debug(6, "Cleared mode %s\n", #mode); \
		modes &= (unsigned int) ~mode; \
		changed++; \
	}

#define MIN_MODE(member, mode, str) \
	if (!authorized_atleast(member, mode)) { \
		send_numeric2(user, 482, "%s: You're not a channel %s\r\n", channel->name, str); \
		continue; \
	}

#define REQUIRE_OPER(user) \
	if (!(user->modes & USER_MODE_OPERATOR)) { \
		send_numeric(user, 481, "You're not an IRC operator\r\n"); \
		continue; \
	}

#define REQUIRE_PARAMETER(user, var) \
	if (!var) { \
		send_numeric(user,  461, "Not enough parameters\r\n"); \
		continue; \
	}

static void handle_modes(struct irc_user *user, char *s)
{
	struct irc_member *member = NULL, *targetmember = NULL;
	struct irc_channel *channel = NULL;

	/* Stuff like this:
	 * MODE #channel
	 * MODE #channel +S
	 * MODE #channel +o jsmith
	 */
	char *modes, *channel_name = strsep(&s, " ");
	channel = find_channel_by_user(channel_name, user);

	if (*channel_name == CHANNEL_NAME_PREFIX_MODELESS_CHAR) {
		send_numeric(user, 502, "Channel does not support modes\r\n"); /* Modeless channel */
		return;
	}

	modes = strsep(&s, " "); /* If there's anything left, it's the usernames to target for a channel mode */
	/* Unless there's a : */
	if (modes && *modes == ':') {
		modes++;
	}
	if (!modes) {
		/* Just get the modes for a channel */
		if (IS_CHANNEL_NAME(channel_name)) {
			print_channel_mode(user, channel); /* NULL OK */
		} else {
			/* XXX Apparently you can't view other users' modes? If it turns out this is fine, then we can just call get_user and call print_user_mode on that. */
			if (strcmp(channel_name, user->username)) {
				send_numeric(user, 502, "Can't change mode for other users\r\n");
				return;
			}
			print_user_mode(user); /* Print our mode */
		}
	} else {
		char *target;
		int set;
		int changed = 0;
		target = s; /* Anything left is the target, e.g. user to op */
		bbs_debug(5, "Modes: '%s'\n", modes);
		if (*modes == '+') {
			set = 1;
		} else if (*modes == '-') {
			set = 0;
		} else { /* Not + or - ? */
			send_numeric(user, 501, "Unknown MODE flag\r\n");
			return;
		}
		bbs_debug(3, "User %p requested %s modes for %s: %s\n", user, set ? "set" : "unset", S_OR(target, "(empty target)"), channel_name);
		/*
		 * User modes: /mode jsmith +i => MODE jsmith +i
		 * Channel modes: /mode #test +S => MODE #test +S
		 * Channel modes for users: /mode #test +o jsmith => MODE #test +o jsmith
		 *
		 * List channel modes: /mode #test => MODE #test
		 */

		/* Find the member for this channel */
		if (IS_CHANNEL_NAME(channel_name)) {
			member = get_member_by_channel_name(user, channel_name);
			if ((!member || !authorized_atleast(member, CHANNEL_USER_MODE_OP)) && !(user->modes & USER_MODE_OPERATOR)) { /* Must be at least an op */
				send_numeric2(user, 482, "%s: You're not a channel operator\r\n", channel_name);
				return;
			}
			if (!channel) {
				send_numeric2(user, 403, "%s :No such channel\r\n", channel_name);
				return;
			}
		} else if (!IS_SERVICE(user) && strcmp(user->nickname, channel_name)) {
			send_numeric(user, 502, "Can't change mode for other users\r\n");
			return;
		}
		if (target) {
			targetmember = get_member_by_nickname(target, channel_name);
		}
		for (modes++; *modes; modes++) { /* Skip the + or - to start */
			char modebuf[128];
			char mode = *modes;
			bbs_debug(5, "Requesting %s mode %c for %s (%s)\n", set ? "set" : "unset", mode, S_OR(target, "(empty target)"), S_IF(channel_name));
			if (IS_CHANNEL_NAME(channel_name)) { /* Channel, and it's a channel operator */
				char *args;
				int broadcast_if_change = 1;
				switch (mode) {
					case 'C':
						SET_MODE(channel->modes, set, CHANNEL_MODE_CTCP_BLOCK);
						break;
					case 'P':
						if (set) {
							REQUIRE_OPER(user);
						}
						SET_MODE(channel->modes, set, CHANNEL_MODE_PERMANENT);
						break;
					case 'S':
						SET_MODE(channel->modes, set, CHANNEL_MODE_TLS_ONLY);
						break;
					case 'T':
						SET_MODE(channel->modes, set, CHANNEL_MODE_NOTICE_BLOCK);
						break;
					case 'q':
					case 'a':
						if (!(user->modes & USER_MODE_OPERATOR)) {
							MIN_MODE(member, CHANNEL_USER_MODE_FOUNDER, "founder"); /* Only founders can change 'a' (whereas ops can deop other ops) */
						}
						/* Fall through */
					case 'o':
					case 'h':
					case 'v':
						broadcast_if_change = 0; /* We'll handle the broadcast within this case itself */
						REQUIRE_PARAMETER(user, target);
						if (!targetmember) {
							send_numeric(user, 441, "They aren't on that channel\r\n");
							continue;
						}
						/* This is written out the long way instead of using the ternary operator so that #mode will print what we want in the macro */
						bbs_mutex_lock(&targetmember->lock);
						if (mode == 'q') {
							SET_MODE(targetmember->modes, set, CHANNEL_USER_MODE_FOUNDER);
						} else if (mode == 'a') {
							SET_MODE(targetmember->modes, set, CHANNEL_USER_MODE_ADMIN);
						} else if (mode == 'o') {
							if (!set && IS_SERVICE(targetmember->user)) {
								send_numeric(user, 484, "%s %s :Cannot kick or deop a network service\r\n", targetmember->user->nickname, channel->name);
								continue;
							}
							SET_MODE(targetmember->modes, set, CHANNEL_USER_MODE_OP);
						} else if (mode == 'h') {
							SET_MODE(targetmember->modes, set, CHANNEL_USER_MODE_HALFOP);
						} else if (mode == 'v') {
							SET_MODE(targetmember->modes, set, CHANNEL_USER_MODE_VOICE);
						}
						bbs_mutex_unlock(&targetmember->lock);
						if (changed) {
							snprintf(modebuf, sizeof(modebuf), "%s %c%c %s", channel->name, set ? '+' : '-', mode, targetmember->user->nickname);
							channel_broadcast(channel, NULL, ":%s MODE %s\r\n", user->nickname, modebuf);
							broadcast_channel_event_internal(IRCCMD_EVENT_MODE, channel, user, s);
						}
						break;
					case 'c':
						SET_MODE(channel->modes, set, CHANNEL_MODE_COLOR_FILTER);
						break;
					case 'g':
						SET_MODE(channel->modes, set, CHANNEL_MODE_FREE_INVITE);
						break;
					case 'i':
						SET_MODE(channel->modes, set, CHANNEL_MODE_INVITE_ONLY);
						break;
					case 'j': /* Throttled */
						if (set && strlen_zero(target)) {
							send_numeric(user, 461, "Not enough parameters\r\n");
							continue;
						}
						args = strchr(target, ':'); /* Must have users:interval */
						REQUIRE_PARAMETER(user, args);
						if (set) {
							*args++ = '\0';
							channel->throttleusers = (unsigned int) atoi(target);
							channel->throttleinterval = (unsigned int) atoi(S_IF(args));
							SET_MODE_FORCE(channel->modes, 1, CHANNEL_MODE_THROTTLED); /* It's possible the arguments changed, even if it wasn't toggled. */
						} else {
							SET_MODE(channel->modes, set, CHANNEL_MODE_THROTTLED);
							channel->throttleusers = channel->throttleinterval = 0;
						}
						break;
					case 'k':
						if (set && strlen_zero(target)) {
							send_numeric(user, 461, "Not enough parameters\r\n");
							continue;
						}
						SET_MODE_FORCE(channel->modes, set, CHANNEL_MODE_PASSWORD); /* Arguments could have changed, even if mode not toggled */
						if (set) {
							channel->password = strdup(target);
							/* Broadcast the new password to the channel. */
							snprintf(modebuf, sizeof(modebuf), "%s %c%c %s", channel->name, '+', mode, target);
							channel_broadcast(channel, NULL, ":%s MODE %s\r\n", user->nickname, modebuf);
							broadcast_channel_event_internal(IRCCMD_EVENT_MODE, channel, user, s);
							broadcast_if_change = 0; /* Don't do it again */
						} else {
							free_if(channel->password);
						}
						break;
					case 'l':
						if (set && strlen_zero(target)) {
							send_numeric(user, 461, "Not enough parameters\r\n");
							continue;
						}
						SET_MODE_FORCE(channel->modes, set, CHANNEL_MODE_LIMIT); /* Arguments could have changed, even if mode not toggled */
						channel->limit = set ? (unsigned int) atoi(target) : 0; /* If this fails, the limit will be 0 (turned off), so not super dangerous... */
						break;
					case 'm':
						SET_MODE(channel->modes, set, CHANNEL_MODE_MODERATED);
						break;
					case 'n':
						SET_MODE(channel->modes, set, CHANNEL_MODE_NO_EXTERNAL);
						break;
					case 'p':
						SET_MODE(channel->modes, set, CHANNEL_MODE_PRIVATE);
						break;
					case 'r':
						SET_MODE(channel->modes, set, CHANNEL_MODE_REGISTERED_ONLY);
						break;
					case 's':
						SET_MODE(channel->modes, set, CHANNEL_MODE_SECRET);
						break;
					case 't':
						SET_MODE(channel->modes, set, CHANNEL_MODE_TOPIC_PROTECTED);
						break;
					case 'z':
						SET_MODE(channel->modes, set, CHANNEL_MODE_REDUCED_MODERATION);
						break;
					default:
						bbs_warning("Unknown channel mode '%c'\n", isprint(mode) ? mode : ' ');
						send_numeric2(user, 472, "%c :is an unknown mode char to me\r\n", mode);
				}
				/*! \todo Improvement would be rather than doing one at a time, broadcast all the changes at once (storing changed modes in a tmp buffer) */
				if (broadcast_if_change && changed) {
					snprintf(modebuf, sizeof(modebuf), "%s %c%c", channel->name, set ? '+' : '-', mode);
					channel_broadcast(channel, NULL, ":%s MODE %s\r\n", user->nickname, modebuf);
					broadcast_channel_event_internal(IRCCMD_EVENT_MODE, channel, user, s);
				}
			} else { /* Same user */
				switch (mode) {
					case 'i':
						SET_MODE(user->modes, set, USER_MODE_INVISIBLE);
						break;
					case 'o': /* Channel operator */
						/* +o cannot be done using MODE, must use the OPER command instead */
						if (set) {
							send_numeric2(user, 472, "%c :is an unknown mode char to me\r\n", mode);
							continue;
						}
						RWLIST_WRLOCK(&operators);
						SET_MODE(user->modes, set, USER_MODE_OPERATOR); /* Operators can do-op themselves using -o, however */
						operators_online--;
						RWLIST_UNLOCK(&operators);
						break;
					case 'w':
						SET_MODE(user->modes, set, USER_MODE_WALLOPS);
						break;
					case 'Z': /* Valid mode but is read only */
					default:
						bbs_warning("Unknown user mode '%c'\n", isprint(mode) ? mode : ' ');
						send_numeric2(user, 472, "%c :is an unknown mode char to me\r\n", mode);
				}
				if (changed) {
					send_reply(user, ":%s MODE %s %c%c\r\n", user->nickname, user->nickname, set ? '+' : '-', mode);
				}
			}
		}
	}
}

/*! \todo this isn't locking safe */
static void handle_topic(struct irc_user *user, char *s)
{
	struct irc_channel *channel;
	char *channame = strsep(&s, " ");
	if (s && *s == ':') {
		s++;
	}

	channel = find_channel_by_user(channame, user);
	if (!channel) {
		send_numeric2(user, 403, "%s :No such channel\r\n", s);
	} else if (!s) { /* Print current channel topic */
		channel_print_topic(user, channel);
	} else {
		struct irc_member *m;
		if (strlen(s) > MAX_TOPIC_LENGTH) {
			send_numeric(user, 416, "Topic is too long\r\n"); /* XXX Not really the right numeric */
			return;
		}
		m = get_member_by_nickname(user->nickname, channel->name);
		if (!m || (channel->modes & CHANNEL_MODE_TOPIC_PROTECTED && !authorized_atleast(m, CHANNEL_USER_MODE_HALFOP))) { /* Need at least half op to set the topic, if protected. */
			send_numeric(user, 482, "You're not a channel operator\r\n");
		} else {
			char buf[128];
			REPLACE(channel->topic, s);
			snprintf(buf, sizeof(buf), HOSTMASK_FMT, HOSTMASK_ARGS(user));
			REPLACE(channel->topicsetby, buf);
			channel->topicsettime = time(NULL);
			channel_print_topic(NULL, channel);
			broadcast_channel_event_internal(IRCCMD_EVENT_TOPIC, channel, user, s);
		}
	}
}

static void handle_invite(struct irc_user *user, char *s)
{
	char *nick, *channame;
	struct irc_member *member, *member2;
	struct irc_channel *channel;
	struct irc_user *inviteduser;
	nick = strsep(&s, " ");
	channame = s;

	if (!nick || !channame) {
		send_numeric(user, 461, "Not enough parameters\r\n");
		return;
	}
	channel = find_channel_by_user(channame, user);
	if (!channel) {
		send_numeric2(user, 403, "%s :No such channel\r\n", channame);
		return;
	}
	member = get_member_by_channel_name(user, channame);
	if (!member) {
		send_numeric(user, 442, "You're not on that channel\r\n");
		return;
	}
	member2 = get_member_by_nickname(nick, channame);
	if (member2) {
		send_numeric2(user, 443, "%s %s :is already on channel\r\n", nick, channame);
		return;
	}
	if (channel->modes & CHANNEL_MODE_INVITE_ONLY) {
		/* Must be at least an op to invite people *or* channel must have free invite enabled */
		if (!authorized_atleast(member, CHANNEL_USER_MODE_OP) && !(channel->modes & CHANNEL_MODE_FREE_INVITE)) {
			send_numeric2(user, 482, "%s: You're not a channel operator\r\n", channame);
			return;
		}
	}
	inviteduser = get_user(nick);
	if (!inviteduser) {
		send_numeric2(user, 401, "%s :No such nick/channel\r\n", nick);
		return;
	}

	RWLIST_WRLOCK(&channel->invited);
	if (!stringlist_contains_locked(&channel->invited, nick)) {
		stringlist_push(&channel->invited, nick); /* Add nick to invite list so we can keep track of the invite */
	}
	RWLIST_UNLOCK(&channel->invited);

	send_reply(inviteduser, ":" HOSTMASK_FMT " INVITE %s %s\r\n", HOSTMASK_ARGS(user), inviteduser->nickname, channame);
	send_numeric2(user, 341, "%s %s\r\n", nick, channame); /* Confirm to inviter */
}

/*! \brief Advance a string one character if the first character matches */
#define SKIP_CHAR(str, c) if (!strlen_zero(str) && *str == c) { str++; }

static void handle_knock(struct irc_user *user, char *s)
{
	char *msg, *channame;
	struct irc_channel *channel;
	struct irc_member *member;

	/* KNOCK <channel> [<message>] */
	channame = strsep(&s, " ");
	msg = s;
	SKIP_CHAR(msg, ':');

	channel = find_channel_by_user(channame, user);
	if (!channel) {
		send_numeric2(user, 403, "%s :No such channel\r\n", channame);
		return;
	}
	member = get_member_by_channel_name(user, channame);
	if (member) {
		send_numeric(user, 714, "You're already on that channel\r\n"); /*! \todo Don't think this is the right format */
		return;
	}
	if (channel->modes & CHANNEL_HIDDEN) {
		send_numeric(user, 715, "KNOCKs are disabled.\r\n");
		return;
	}
	/* Notify ops about the KNOCK */
	channel_broadcast_selective(channel, NULL, CHANNEL_USER_MODE_OP, ":%s %d %s " HOSTMASK_FMT " :has asked for an invite\r\n", irc_hostname, 710, channel->name, HOSTMASK_ARGS(user)); /* XXX msg is not used, seems there's no place for it in this numeric? */
	send_numeric(user, 711, "Your KNOCK has been delivered.\r\n");
}

static void dump_who(struct irc_user *user, struct irc_user *whouser, struct irc_member *member)
{
	const char *chan = "*"; /* https://modern.ircdocs.horse/#rplwhoreply-352 */
	int hopcount = 0;
	char prefixes[6] = "";
	char userflags[3 + sizeof(prefixes)];

	bbs_mutex_lock(&whouser->lock);
	if (member) {
		if (user->multiprefix) {
			snprintf(prefixes, sizeof(prefixes), MULTIPREFIX_FMT, MULTIPREFIX_ARGS(member));
		} else {
			snprintf(prefixes, sizeof(prefixes), "%s", top_channel_membership_prefix(member));
		}
	}
	snprintf(userflags, sizeof(userflags), "%c%s%s", whouser->away ? 'G' : 'H', whouser->modes & USER_MODE_OPERATOR ? "*" : "", prefixes);
	bbs_mutex_unlock(&whouser->lock);

	send_numeric2(user, 352, "%s %s %s %s %s %s :%d %s\r\n", chan, whouser->username, whouser->hostname, irc_hostname, whouser->nickname, userflags, hopcount, whouser->realname);
}

/*!
 * \brief Whether two users share any IRC channels in common
 * \note channel->members must be RDLOCK'd when calling
 */
static int channels_in_common(struct irc_user *u1, struct irc_user *u2)
{
	/* XXX This is not the most efficient algorithm. It's just the easiest implementation that works now.
	 * It's O(n^2), since traversing all members of all channels is expensive.
	 * It would be a lot cheaper to cache the channels of which a user is a member
	 * on the user struct itself, and make comparisons between those,
	 * since users are not generally in many channels. */
	struct irc_channel *channel;

	if (u1 == u2) {
		return 1; /* Same user */
	}

	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		struct irc_member *m1 = NULL, *m2 = NULL, *m;
		/* channel->members is already RDLOCK'd */
		RWLIST_TRAVERSE(&channel->members, m, entry) {
			if (channel->username) {
				/* If private channel for one user,
				 * can't have in common with any other user */
				continue;
			}
			if (m->user == u1) {
				m1 = m;
			} else if (m->user == u2) {
				m2 = m;
			}
		}
		if (m1 && m2) {
			/* Both u1 and u2 are members of this channel. */
			break;
		}
	}
	if (channel) {
		bbs_debug(5, "Users share channel %s in common\n", channel->name);
	} else {
		bbs_debug(5, "Users do not share any common channels\n");
	}
	RWLIST_UNLOCK(&channels);

	/* If channel is not NULL here, then we found a common channel. */
	return channel ? 1 : 0;
}

int __irc_relay_numeric_response(struct bbs_node *node, int fd, const char *fmt, ...)
{
	char buf[512]; /* An IRC message can't be longer than this anyways */
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	bbs_debug(9, "%.*s", len, buf);
	bbs_auto_fd_writef(node, fd, buf, (size_t) len);
	return len;
}

void irc_relay_who_response(struct bbs_node *node, int fd, const char *relayname, const char *ircusername, const char *hostsuffix, const char *uniqueid, int active)
{
	char mask[96];
	char userflags[3];
	int hopcount = 2; /* Since we're going through a relay, use an incremented hop count */

	snprintf(mask, sizeof(mask), "%s/%s", relayname, hostsuffix);

	/* We consider users to be active in a channel as long as they're in it, so offline is the equivalent of "away" in IRC */
	snprintf(userflags, sizeof(userflags), "%c%s", active ? 'H' : 'G', ""); /* H/G = here / gone */
	/* IRC numeric 352 */
	irc_relay_numeric_response(node, fd, 352, "%s %s %s %s %s %s %s :%d %s", ircusername, "*", hostsuffix, mask, bbs_hostname(), hostsuffix, userflags, hopcount, uniqueid);
}

void irc_relay_names_response(struct bbs_node *node, int fd, const char *ircusername, const char *channel, const char *names)
{
	irc_relay_numeric_response(node, fd, 353, "%s %s %s :%s", ircusername, PUBLIC_CHANNEL_PREFIX, channel, names);
}

static void handle_who(struct irc_user *user, char *s)
{
	struct irc_relay *relay;
	int res = 0;
	char *flags;
	int opersonly = 0;

	/* Format is WHO [<name> ["o"]] */
	flags = s;
	s = strsep(&flags, " ");
	if (!strlen_zero(flags) && !strcmp(flags, "o")) {
		opersonly = 1;
	}

	if (IS_CHANNEL_NAME(s)) {
		struct irc_member *member;
		struct irc_channel *channel = find_channel_by_user(s, user);
		if (!channel) {
			send_numeric2(user, 403, "%s :No such channel\r\n", s);
			return;
		}
		RWLIST_RDLOCK(&channel->members);
		RWLIST_TRAVERSE(&channel->members, member, entry) {
			if (member->user->modes & USER_MODE_INVISIBLE && !channels_in_common(member->user, user)) {
				continue;
			}
			dump_who(user, member->user, member);
		}
		RWLIST_UNLOCK(&channel->members);
		if (channel->relay) {
			/* Now, pull in any "unreal" members from other protocols */
			RWLIST_RDLOCK(&relays);
			RWLIST_TRAVERSE(&relays, relay, entry) {
				if (relay->relay_callbacks->nicklist) {
					bbs_module_ref(relay->mod, 6);
					/* Callbacks will return 0 for no match, 1 for match.
					 * However, multiple relay modules could have members in the channel,
					 * so we should not break early if nicklist callback returns 1;
					 * we need to check all the relays for matches.
					 * As long as at least one relay had members, we'll report success. */
					res += relay->relay_callbacks->nicklist(user->node, user->node ? user->node->wfd : -1, 352, user->username, s, NULL);
					bbs_module_unref(relay->mod, 6);
				}
			}
			RWLIST_UNLOCK(&relays);
		}
	} else {
		struct irc_user *whouser = get_user(s);
		if (whouser && (!opersonly || whouser->modes & USER_MODE_OPERATOR)) {
			dump_who(user, whouser, NULL);
		} else if (!opersonly) { /* Relays don't have any operators */
			/* Check relays, we don't have a channel handle so we don't really know if the user exists in a relay */
			RWLIST_RDLOCK(&relays);
			RWLIST_TRAVERSE(&relays, relay, entry) {
				if (relay->relay_callbacks->nicklist) {
					bbs_module_ref(relay->mod, 7);
					/* Unlike the above case, a specific user can only exist in one relay,
					 * so as soon as we find a match, we can break. */
					res = relay->relay_callbacks->nicklist(user->node, user->node ? user->node->wfd : -1, 352, user->username, NULL, s);
					bbs_module_unref(relay->mod, 7);
				}
				if (res) {
					break;
				}
			}
			RWLIST_UNLOCK(&relays);
		}
		if (!whouser && !res) {
			send_numeric2(user, 401, "%s :No such nick/channel\r\n", s);
			return;
		}
	}
	send_numeric(user, 315, "%s: End of WHO list\r\n", s);
}

/*!
 * \brief Assuming channel is a hidden channel, whether this channel should be considered off-limits to a user query
 * \retval 1 if user is not in the channel, 0 if the channel is not hidden or the user is in the channel
 */
static int suppress_channel(struct irc_user *user, struct irc_channel *channel)
{
	struct irc_member *m;
	if (!(channel->modes & CHANNEL_HIDDEN)) {
		return 0; /* It's not private or secret */
	}
	m = get_member(user, channel);
	if (!m) {
		return 1; /* Skip: requesting user isn't in this channel */
	}
	return 0;
}

static void handle_whois(struct irc_user *user, char *s)
{
	time_t now;
	char umodes[15];
	struct irc_channel *channel;
	struct irc_user *u = get_user(s);
	if (!u) {
		int res = 0;
		struct irc_relay *relay;
		RWLIST_RDLOCK(&relays);
		RWLIST_TRAVERSE(&relays, relay, entry) {
			if (relay->relay_callbacks->nicklist) {
				bbs_module_ref(relay->mod, 8);
				res = relay->relay_callbacks->nicklist(user->node, user->node ? user->node->wfd : -1, 318, user->username, NULL, s);
				bbs_module_unref(relay->mod, 8);
			}
			if (res) {
				break;
			}
		}
		RWLIST_UNLOCK(&relays);
		if (!res) {
			send_numeric2(user, 401, "%s :No such nick/channel\r\n", s);
		} else {
			send_numeric2(user, 318, "%s :End of /WHOIS list\r\n", s); /* case must be preserved, so use s instead of u->nickname */
		}
		return;
	}

	now = time(NULL);
	get_user_modes(umodes, sizeof(umodes), u);

	if (!IS_SERVICE(u)) {
		send_numeric2(user, 307, "%s :has identified for this nick\r\n", u->nickname); /* Everyone has, and nicks can't be changed, so... */
	}
	send_numeric2(user, 311, "%s %s %s * :%s\r\n", u->nickname, u->username, u->hostname, u->realname);
	send_numeric2(user, 312, "%s %s :%s\r\n", u->nickname, IS_SERVICE(u) ? "services" : irc_hostname, IS_SERVICE(u) ? "IRC Services" : "Root IRC Server");
	if (user->modes & USER_MODE_OPERATOR) {
		send_numeric2(user, 313, "%s :is an IRC operator\r\n", u->nickname);
	}

	if (IS_SERVICE(u)) {
		send_numeric2(user, 309, "%s :is a Network Service\r\n", u->nickname);
	}

	if (!IS_SERVICE(u)) {
		char buf[256];
		int len = 0;
		/* Channel memberships */
		RWLIST_RDLOCK(&channels);
		RWLIST_TRAVERSE(&channels, channel, entry) {
			struct irc_member *member;
			if (channel->modes & CHANNEL_HIDDEN && suppress_channel(user, channel)) {
				continue;
			}
			if (channel->username && !user_is_priv_channel_owner(channel, user)) {
				continue; /* Private namespace channel */
			}
			RWLIST_RDLOCK(&channel->members);
			RWLIST_TRAVERSE(&channel->members, member, entry) {
				if (member->user == u) {
					if (member->user->modes & USER_MODE_INVISIBLE) {
						/* Include channels only if user is in them too (show only shared channels) */
						if (!get_member(user, channel)) {
							continue;
						}
					}
					if (user->multiprefix) {
						len += snprintf(buf + len, sizeof(buf) - (size_t) len, "%s" MULTIPREFIX_FMT "%s", len ? " " : "", MULTIPREFIX_ARGS(member), channel->name);
					} else {
						len += snprintf(buf + len, sizeof(buf) - (size_t) len, "%s%s%s", len ? " " : "", top_channel_membership_prefix(member), channel->name);
					}
					if (len >= 200) {
						send_numeric2(user, 319, "%s :%s\r\n", u->nickname, buf);
						len = 0;
					}
				}
			}
			RWLIST_UNLOCK(&channel->members);
		}
		RWLIST_UNLOCK(&channels);
		if (len > 0) {
			send_numeric2(user, 319, "%s :%s\r\n", u->nickname, buf);
		}
	}
	if (u->modes) {
		send_numeric2(user, 379, "%s :is using modes %s\r\n", u->nickname, umodes);
	}
	if (!IS_SERVICE(u)) {
		send_numeric2(user, 317, "%s %" TIME_T_FMT " %" TIME_T_FMT " :seconds idle, signon time\r\n", u->nickname, now - u->lastactive, u->joined);
	}
	if (user->modes & USER_MODE_SECURE) {
		send_numeric2(user, 671, "%s :is using a secure connection\r\n", u->nickname);
	}
	send_numeric2(user, 318, "%s :End of /WHOIS list\r\n", s); /* case must be preserved, so use s instead of u->nickname */
}

static void handle_whowas(struct irc_user *user, char *s)
{
	char *username;
	struct whowas *w;

	username = strsep(&s, " ");
	/* s (2nd argument) is now the # sessions back to go
	 * Ambassador will substitute "null" if this is not specified.
	 * Either way, we ignore this parameter, it's always effectively "1". */

	bbs_debug(2, "WHOWAS lookup for '%s'\n", username);

	RWLIST_RDLOCK(&whowas_users);
	RWLIST_TRAVERSE(&whowas_users, w, entry) {
		if (!strncasecmp(w->who, username, w->nicklen)) {
			if (w->who[w->nicklen] == ' ') { /* Must be a complete match. */
				char timebuf[56];
				struct tm logdate;
				send_numeric2(user, 314, "%s\r\n", w->who);
				localtime_r(&w->joined, &logdate);
				strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M %P %Z", &logdate);
				send_numeric2(user, 330, "%.*s %.*s\r\n", (int) w->nicklen, w->who, (int) w->nicklen, w->who);
				send_numeric2(user, 312, "%.*s %s %s\r\n", (int) w->nicklen, w->who, irc_hostname, timebuf);
				break;
			}
		}
	}
	RWLIST_UNLOCK(&whowas_users);

	if (!w) {
		send_numeric2(user, 406, "%s :There was no such nickname\r\n", username);
	}

	send_numeric2(user, 369, "%s :End of WHOWAS\r\n", username); /* case must be preserved, so use s */
}

static void handle_userhost(struct irc_user *user, char *s)
{
	char buf[256];
	struct irc_user *u = get_user(s);
	if (!u) {
		send_numeric2(user, 401, "%s :No such nick/channel\r\n", s);
		return;
	}
	bbs_mutex_lock(&u->lock);
	snprintf(buf, sizeof(buf), "%s %s = %c %s %s", u->nickname, u->modes & USER_MODE_OPERATOR ? "*" : "", u->away ? '-' : '+', S_IF(u->awaymsg), u->hostname);
	bbs_mutex_unlock(&u->lock);
	send_numeric(user, 302, "%s\r\n", buf);
}

static void handle_list(struct irc_user *user, char *s)
{
	struct irc_channel *channel;
	unsigned int minmembers = 0, maxmembers = 0;
	unsigned int mintopicage = 0, maxtopicage = 0;
	time_t now = time(NULL);
	char *elistcond, *conds;

	conds = s;
	while ((elistcond = strsep(&conds, ","))) {
		if (strlen_zero(elistcond) || strlen_zero(elistcond + 1)) {
			continue;
		}
		switch (*elistcond) {
			/* These are not inclusive */
			case '>':
				minmembers = (unsigned int) atoi(elistcond + 1);
				break;
			case '<':
				maxmembers = (unsigned int) atoi(elistcond + 1);
				break;
			case 'T':
				elistcond++;
				if (*elistcond == '<' && *++elistcond) {
					maxtopicage = (unsigned int) atoi(elistcond);
				} else if (*elistcond == '>' && *++elistcond) {
					mintopicage = (unsigned int) atoi(elistcond);
				}
				break;
			default:
				bbs_warning("Unhandled ELIST condition: %s\n", elistcond);
				break;
		}
	}

	send_numeric2(user, 321, "Channel :Users Name\r\n");
	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (channel->username && !user_is_priv_channel_owner(channel, user)) {
			continue; /* Private namespace channel */
		}
		/* Remember, the conditions are NOT inclusive. If they are equal, in other words, that is not a match, skip. */
		if (minmembers && channel->membercount <= (int) minmembers) {
			continue;
		} else if (maxmembers && channel->membercount >= (int) maxmembers) {
			continue;
		} else if (mintopicage && channel->topicsettime && channel->topicsettime >= now - maxtopicage) {
			continue; /* Topic too old */
		} else if (maxtopicage && channel->topicsettime && channel->topicsettime <= now - maxtopicage) {
			continue; /* Topic too new */
		}
		if (channel->modes & CHANNEL_MODE_SECRET && suppress_channel(user, channel)) {
			continue;
		}
		send_numeric2(user, 322, "%s %d :%s\r\n", channel->name, channel->membercount, S_IF(channel->topic));
	}
	RWLIST_UNLOCK(&channels);
	send_numeric(user, 323, "End of /LIST\r\n");
}

static void handle_stats(struct irc_user *user, char *s)
{
	struct irc_operator *operator;
	char *query, *target = s;

	query = strsep(&target, " ");
	switch (*query) {
		/* There's not really any sensitive info here, just a list of operators, so allow anyone to query it */
		case 'o':
			RWLIST_RDLOCK(&operators);
			RWLIST_TRAVERSE(&operators, operator, entry) {
				send_numeric(user, 243, "O %s@%s * %s %d\r\n", operator->name, "*", operator->name, -1);
			}
			RWLIST_UNLOCK(&operators);
			break;
		/*! \todo implement other queries */
		default:
			break;
	}

	send_numeric(user, 219, "%c :End of /STATS report\r\n", *query);
}

static void handle_help(struct irc_user *user, char *s)
{
	if (s && *s == ':') {
		s++;
	}
	if (strlen_zero(s)) {
		send_numeric(user, 704, "index * :** Help System **\r\n");
		/*! \todo add handlers and dynamically generate this? */
		send_numeric(user, 705, "index AWAY HELP INVITE JOIN KICK LIST MOTD NAMES NOTICE PART PING PONG PRIVMSG QUIT TOPIC USERHOST WHO WHOIS WHOWAS\r\n");
		send_numeric(user, 706, "index :End of /HELP\r\n");
		return;
	}
	/*! \todo add individual command help here */
	send_numeric(user, 524, "I don't know anything about that\r\n");
}

static void cloak_user(struct irc_user *user)
{
	char cloak[32];
	/* Replace hostname with a cloak, since nobody actually wants his or her location publicly shared */
	snprintf(cloak, sizeof(cloak), "node/%d", user->node->id);
	bbs_debug(6, "Cloaking node %d's hostname from %s to %s\n", user->node->id, user->hostname, cloak);
	REPLACE(user->hostname, cloak);
}

static void broadcast_nick_change(struct irc_user *user, const char *oldnick)
{
	struct irc_channel *channel;
	struct irc_member *member;

	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (channel->username && !user_is_priv_channel_owner(channel, user)) {
			continue; /* Private namespace channel */
		}
		RWLIST_RDLOCK(&channel->members);
		RWLIST_TRAVERSE(&channel->members, member, entry) {
			if (member->user == user) {
				channel_broadcast_nolock(channel, NULL, ":%s NICK %s\r\n", oldnick, user->nickname);
				break;
			}
		}
		RWLIST_UNLOCK(&channel->members);
	}
	RWLIST_UNLOCK(&channels);
}

/*! \note users must be locked */
static int nickname_in_use(const char *nickname)
{
	struct irc_user *u;
	RWLIST_TRAVERSE(&users, u, entry) {
		if (!strcmp(u->nickname, nickname)) {
			return 1;
		}
	}
	return 0;
}

/*!
 * \brief Atomically set or change nickname, if desired nickname is available
 * \retval 1 Nickname in use
 * \retval -1 Other failure
 * \retval 0 Success
 */
static int set_nickname(struct irc_user *user, const char *nickname, char *oldnick, size_t oldnicklen)
{
	char *newnick;

	/* If we already have the desired nickname, no change needed */
	if (user->nickname && !strcmp(user->nickname, nickname)) {
		bbs_debug(5, "Already have desired nickname '%s', no change needed\n", nickname);
		return 0;
	}

	RWLIST_WRLOCK(&users); /* Since we're changing the nickname, which is kind of a key in the list, write lock */
	if (nickname_in_use(nickname)) {
		RWLIST_UNLOCK(&users);
		return 1;
	}
	if (oldnick) {
		safe_strncpy(oldnick, S_IF(user->nickname), oldnicklen);
	}
	newnick = strdup(nickname);
	if (ALLOC_FAILURE(newnick)) {
		RWLIST_UNLOCK(&users);
		return -1;
	}
	if (user->nickname) {
		bbs_notice("%s (" HOSTMASK_FMT ") changed nickname to %s\n", user->nickname, HOSTMASK_ARGS(user), newnick);
	}
	free_if(user->nickname);
	user->nickname = newnick;
	RWLIST_UNLOCK(&users);
	return 0;
}

/*! \brief Try to set a fallback nickname */
static int autoset_nickname(struct irc_user *user, const char *base_nickname, char *oldnick, size_t oldnicklen)
{
	char buf[MAX_NICKLEN + 1];
	int len;

	/* Keep appending '_' until it succeeds */
	len = snprintf(buf, sizeof(buf), "%s", base_nickname);
	while (len < MAX_NICKLEN) {
		strcpy(buf + len, "_");
		if (!set_nickname(user, buf, oldnick, oldnicklen)) {
			bbs_debug(4, "Autoset nickname to %s\n", buf);
			return 0;
		}
		len++;
	}
	bbs_error("Failed to autoset any nickname for %s\n", base_nickname);
	return -1;
}

static int try_nick_swap(struct irc_user *user, const char *nickname)
{
	struct irc_user *u2;

	/* Have an existing nickname we can use in the swap.
	 * Give real, interactive users precedence over programmatic users. */

	/* Nickname in use.
	 * See if we can swap places with a programmatic user masquerading as us. */
	RWLIST_WRLOCK(&users);
	RWLIST_TRAVERSE(&users, u2, entry) {
		if (!user->programmatic && u2->programmatic && !strcmp(u2->nickname, nickname)) {
			char *nick2;
			/* Swap the allocated references */
			bbs_debug(1, "Swapped desired nickname (%s) from a programmatic user (%s)\n", u2->nickname, user->nickname);
			bbs_notice("%s (" HOSTMASK_FMT ") changed nickname to %s\n", user->nickname, HOSTMASK_ARGS(user), u2->nickname);
			nick2 = user->nickname;
			user->nickname = u2->nickname;
			u2->nickname = nick2;
			break;
		}
	}
	RWLIST_UNLOCK(&users);
	return u2 ? 0 : 1;
}

/*! \brief Automatically try to set the preferred nickname, or try a fallback nickname otherwise */
static int set_or_default_nickname(struct irc_user *user, const char *nickname, char *oldnick, size_t oldnicklen)
{
	int res;

	/* Most of the time, users will get their nick */
	res = set_nickname(user, nickname, oldnick, oldnicklen);
	if (res != 1) {
		return res;
	}

	/* If we already have a unique name, try a swap first. */
	if (!strlen_zero(user->nickname) && !try_nick_swap(user, nickname)) {
		return 0;
	}

	/* Finally, as a last resort, try appending '_' repeatedly */
	return autoset_nickname(user, nickname, oldnick, oldnicklen);
}

static int add_user(struct irc_user *user)
{
	if (user->registered) {
		bbs_error("Trying to add already registered user?\n");
		return -1;
	} else if (strlen_zero(user->username)) {
		bbs_error("User lacks a username\n");
		return -1;
	} else if (strlen_zero(user->nickname)) {
		bbs_error("User lacks a nickname\n");
		return -1;
	}

	if (IS_REAL_USER(user)) {
		cloak_user(user); /* Cloak the user before adding to users list, so our IP doesn't leak on WHO/WHOIS */
	}

	RWLIST_WRLOCK(&users);
	/* This user isn't in the users list yet,
	 * so even though we've assigned the nickname in that field,
	 * if we found the same nickname in the global list,
	 * then another user is already using it. */
	if (nickname_in_use(user->nickname)) {
		char orignick[MAX_NICKLEN + 1];
		/* add_user is only called for non-programmatic users,
		 * so if a programmatic user is using our nickname,
		 * swap them out transparently.
		 * First, we need to pick a different nickname for ourself
		 * that we can use for the swap. */
		RWLIST_UNLOCK(&users);
		safe_strncpy(orignick, user->nickname, sizeof(orignick)); /* Need to copy since user->nickname could change inside autoset_nickname */
		if (autoset_nickname(user, orignick, NULL, 0) || try_nick_swap(user, orignick)) {
			send_numeric(user, 433, "Nickname is already in use\r\n");
			return -1;
		}
		RWLIST_WRLOCK(&users);
	}
	user->registered = 1;
	RWLIST_INSERT_HEAD(&users, user, entry);
	RWLIST_UNLOCK(&users);
	return 0;
}

/*! \brief Callback run once a registered user has connected and logged into IRC, but before the user has joined any channels or done anything else */
static void post_login(struct irc_user *user)
{
	set_away_via_relays(user, IRC_USER_STATUS_JOIN, NULL); /* If we just logged in, we're no longer away */
}

static void do_identity_update(struct irc_user *user)
{
	if (!user->registered) {
		add_user(user);
	} else {
		cloak_user(user);
	}
}

static void handle_nick(struct irc_user *user, char *s)
{
	char oldnick[64] = "";

	if (!IS_REAL_USER(user)) {
		send_numeric(user, 902, "Only real users can use the NICK command\r\n");
		return;
	}

	if (user->node->user && strcasecmp(s, bbs_username(user->node->user))) {
		const char *suffix;
		size_t usernamelen = strlen(bbs_username(user->node->user));
		/* Don't allow changing nick if already logged in, unless it's to our actual username,
		 * or something that starts with it, followed by an underscore. */
		if (strncasecmp(s, bbs_username(user->node->user), usernamelen)) {
			send_numeric(user, 902, "You must use a nick assigned to you\r\n");
			return;
		}
		/* If username is jsmith, allow jsmith_, jsmith__, jsmith_m, etc.
		 * But it has to be jsmith or start with jsmith_ */
		suffix = s + usernamelen;
		/* If the first n characters match but not the whole string the suffix must be non-empty */
		bbs_assert(!strlen_zero(suffix));
		if (*suffix != '_') {
			send_numeric(user, 902, "You must use a nick assigned to you\r\n");
			return;
		}
	}

	if (bbs_user_exists(s)) {
		int inuse;
		/* If not authenticated, can't set nickname to that of a user */
		if (!bbs_user_is_registered(user->node->user)) {
			send_numeric(user, 433, "%s\r\n", s);
			send_reply(user, "NOTICE AUTH :*** This nickname is registered. Please choose a different nickname, or identify using NickServ\r\n");
			/* Client will need to send NS IDENTIFY <password> or PRIVMSG NickServ :IDENTIFY <password> */
			return;
		}
		RWLIST_RDLOCK(&users);
		inuse = nickname_in_use(s);
		RWLIST_UNLOCK(&users);
		if (inuse) {
			/* If we are authenticated, and it's ours, we can steal it, maybe */
			if (autoset_nickname(user, s, oldnick, sizeof(oldnick)) || try_nick_swap(user, s)) {
				send_numeric(user, 433, "%s\r\n", s);
				send_reply(user, "NOTICE AUTH :*** This nickname is registered. Please choose a different nickname, or identify using NickServ\r\n");
				return;
			}
			goto success;
		}
	}

	/* Nickname is not claimed. It's fine. */
	if (set_nickname(user, s, oldnick, sizeof(oldnick))) {
		bbs_notice("%s failed to change nickname to %s\n", user->nickname, s);
		send_numeric(user, 433, "Nickname is already in use\r\n");
		return;
	}

success:
	bbs_debug(5, "Nickname changed from %s to %s\n", oldnick, s);
	do_identity_update(user);
	if (!s_strlen_zero(oldnick)) {
		send_reply(user, ":%s NICK %s\r\n", oldnick, user->nickname);
		broadcast_nick_change(user, oldnick);
	}
}

static int handle_identify(struct irc_user *user, char *s)
{
	int res;
	char *username, *pw;

	if (!IS_REAL_USER(user)) {
		send_numeric(user, 461, "Only real users can use the IDENTIFY command\r\n");
		return -1;
	}

	username = strsep(&s, " ");
	pw = s;
	if (!username) {
		send_numeric(user, 461, "Not enough parameters\r\n");
		return 0;
	}
	/* Format is password or username password */
	if (!pw) {
		pw = username;
		username = user->nickname;
	}
	res = bbs_authenticate(user->node, username, pw);
	memset(pw, 0, strlen(pw));
	if (res) {
		send_numeric(user, 464, "Password incorrect\r\n");
	} else {
		free_if(user->username);
		user->username = strdup(username);
		/* Just in case it was different here. */
		if (strlen_zero(user->nickname) || strcasecmp(username, user->nickname)) {
			if (set_or_default_nickname(user, username, NULL, 0)) {
				return -1; /* If this fails, just abort the client since things will break */
			}
		}
		do_identity_update(user);
		send_numeric(user, 900, HOSTMASK_FMT " %s You are now logged in as %s\r\n", HOSTMASK_ARGS(user), user->username, user->username);
		post_login(user);
	}
	return 0;
}

static int nickserv(struct irc_user *user, char *s)
{
	char *target = strsep(&s, " ");

	if (!IS_REAL_USER(user)) {
		return -1;
	}

	/* This is all we need from NickServ, we don't need "it" to handle registration or anything else */
	if (!strcasecmp(target, "IDENTIFY")) {
		if (!user->registered || !bbs_user_is_registered(user->node->user)) {
			return handle_identify(user, s);
		} else {
			send_reply(user, "NOTICE AUTH :*** Nickname change not supported.\r\n");
		}
	/* LOGOUT is not supported, since we need all users in the users list to have a name */
	} else {
		bbs_debug(3, "Unsupported NickServ command: %s\n", target);
		send_reply(user, "NOTICE AUTH :*** NickServ does not support registration on this server. Please register interactively via a terminal session.\r\n");
	}
	return 0;
}

static void handle_oper(struct irc_user *user, char *s)
{
	struct irc_operator *operator;
	char *name, *pw;

	if (user->modes & USER_MODE_OPERATOR) { /* If already an operator, don't erroneously increment operators_online */
		/* Already an operator */
		send_numeric(user, 381, "You are now an IRC operator\r\n"); /* XXX Shouldn't there be an "You are already an operator"? */
		return;
	}

	if (!IS_REAL_USER(user)) {
		send_numeric(user, 491, "Only real users can become an operator\r\n");
		return;
	}

	if (!s) {
		send_numeric(user, 461, "Not enough parameters\r\n");
		return;
	}
	pw = s;
	name = strsep(&pw, " ");
	if (!name || !pw) {
		send_numeric(user, 461, "Not enough parameters\r\n");
		return;
	}

	RWLIST_WRLOCK(&operators); /* Must be atomic (WRLOCK, not RDLOCK) for incrementing operators_online */
	RWLIST_TRAVERSE(&operators, operator, entry) {
		if (!strcmp(name, operator->name)) {
			if (!operator->password) { /* nativeopers: authenticate "natively" using BBS credentials */
				if (!strcmp(operator->name, bbs_username(user->node->user))) {
					int res;
					struct bbs_user *u = bbs_user_request();
					if (!u) {
						RWLIST_UNLOCK(&operators);
						return; /* Not much we can do... */
					}
					res = bbs_user_authenticate(u, name, pw);
					bbs_user_destroy(u);
					if (!res) {
						break; /* Authentication succeeded */
					}
				}
			} else { /* opers */
				if (!strcmp(pw, operator->password)) {
					break;
				}
			}
		}
	}

	bbs_memzero(pw, strlen(pw)); /* Destroy the password... doesn't make much difference, since it's not obfuscated in command processing, but doesn't hurt... */

	if (!operator) {
		RWLIST_UNLOCK(&operators);
		send_numeric(user, 491, "No appropriate operator blocks were found for your host\r\n");
		return;
	}

	operators_online++; /* The only reason we need a WRLOCK, let alone a lock at all, is for atomic incrementing here */
	RWLIST_UNLOCK(&operators);
	user->modes |= USER_MODE_OPERATOR;
	send_numeric(user, 381, "You are now an IRC operator\r\n");
}

static int send_channel_members(struct irc_user *user, struct irc_channel *channel)
{
	struct irc_member *member;
	char buf[513];
	int len = 0;
	const char *symbol = PUBLIC_CHANNEL_PREFIX; /* Public channel */

	RWLIST_RDLOCK_RECURSIVE(&channel->members, &channel->recurse);
	RWLIST_TRAVERSE(&channel->members, member, entry) {
		if ((member->user->modes & USER_MODE_INVISIBLE) && !channels_in_common(member->user, user)) {
			continue; /* Hide from NAMES */
		}
		if (user->multiprefix) {
			len += snprintf(buf + len, sizeof(buf) - (size_t) len, "%s" MULTIPREFIX_FMT "%s", len ? " " : "", MULTIPREFIX_ARGS(member), member->user->nickname);
		} else {
			len += snprintf(buf + len, sizeof(buf) - (size_t) len, "%s%s%s", len ? " " : "", top_channel_membership_prefix(member), member->user->nickname);
		}
		if (len >= 400) { /* Stop well short of the 512 character message limit and clear the buffer */
			len = 0;
			send_numeric2(user, 353, "%s %s :%s\r\n", symbol, channel->name, buf);
		}
	}
	RWLIST_UNLOCK_RECURSIVE(&channel->members, &channel->recurse);
	if (len > 0) { /* Last one */
		send_numeric2(user, 353, "%s %s :%s\r\n", symbol, channel->name, buf);
	}
	if (channel->relay) {
		int res = 0;
		struct irc_relay *relay;
		RWLIST_RDLOCK(&relays);
		bbs_mutex_lock(&user->lock);
		RWLIST_TRAVERSE(&relays, relay, entry) {
			if (relay->relay_callbacks->nicklist) {
				bbs_module_ref(relay->mod, 9);
				res = relay->relay_callbacks->nicklist(user->node, user->node ? user->node->wfd : -1, 353, user->username, channel->name, NULL);
				bbs_module_unref(relay->mod, 9);
			}
			if (res) {
				break;
			}
		}
		bbs_mutex_unlock(&user->lock);
		RWLIST_UNLOCK(&relays);
	}
	send_numeric2(user, 366, "%s :End of /NAMES list.\r\n", channel->name);
	return 0;
}

static int join_leave_suppress(struct irc_user *user, struct irc_channel *channel, int join)
{
	int res = 0;
	const char *username = user->username;
	const char *channel_name = channel->name;
	struct irc_relay *relay;

	ENABLE_RECURSIVE_LOCKING(&channels_recurse);

	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		if (relay->relay_callbacks->join_leave) {
			bbs_module_ref(relay->mod, 10);
			res |= relay->relay_callbacks->join_leave(username, channel_name, join);
			bbs_module_unref(relay->mod, 10);
		}
	}
	RWLIST_UNLOCK(&relays);

	RESET_RECURSIVE_LOCKING(&channels_recurse);
	return res;
}

static struct irc_channel *find_or_create_channel_locked(struct irc_user *user, char *name)
{
	char *password;
	size_t chanlen = strlen(name);
	struct irc_channel *channel;

	password = strchr(name, ' ');
	if (password) {
		*password++ = '\0';
	}

	channel = find_channel_by_user(name, user);
	if (!channel) {
		size_t usernamelen;
		if (*name == PRIVATE_NAMESPACE_PREFIX_CHAR && !bbs_user_is_registered(user->node->user)) {
			send_numeric(user, 479, "Can't join this channel as guest\r\n");
			return NULL;
		}
		usernamelen = *name == PRIVATE_NAMESPACE_PREFIX_CHAR ? strlen(bbs_username(user->node->user)) + 1 : 0;
		if (usernamelen) {
			bbs_debug(3, "Creating channel '%s' in private namespace for user '%s'\n", name, bbs_username(user->node->user));
		} else {
			bbs_debug(3, "Creating channel '%s' for the first time\n", name);
		}
		channel = calloc(1, sizeof(*channel) + chanlen + usernamelen + 1);
		if (ALLOC_FAILURE(channel)) {
			return NULL;
		}
		strcpy(channel->data, name); /* Safe */
		channel->name = channel->data;
		if (usernamelen) {
			strcpy(channel->data + chanlen + 1, bbs_username(user->node->user));
			channel->username = channel->data + chanlen + 1;
		}
		channel->modes = CHANNEL_MODE_NONE;
		/* Set some default flags. */
		channel->modes |= CHANNEL_MODE_NO_EXTERNAL | CHANNEL_MODE_TOPIC_PROTECTED;
		if (user->node && bbs_user_is_registered(user->node->user)) {
			channel->modes |= CHANNEL_MODE_REGISTERED_ONLY;
		}
		channel->fp = NULL;
		bbs_rate_limit_init(&channel->ratelimit, 1000, 5); /* No more than 5 messages per second */
		RWLIST_HEAD_INIT(&channel->members);
		stringlist_init(&channel->invited);
		bbs_mutex_init(&channel->lock, NULL);
		bbs_mutex_init(&channel->recurse.lock, NULL);
		if (log_channels) {
			char logfile[256];
			snprintf(logfile, sizeof(logfile), "%s/irc_channel_%s.txt", BBS_LOG_DIR, name);
			channel->fp = fopen(logfile, "a"); /* Append to existing file if it already exists */
			if (!channel->fp) {
				bbs_error("Failed to open log file %s: %s\n", logfile, strerror(errno));
				/* Just continue, what can ya do? */
			}
		}
		RWLIST_INSERT_HEAD(&channels, channel, entry);
	} else if (!IS_SERVICE(user)) {
		if (channel->modes & CHANNEL_MODE_TLS_ONLY && !(user->modes & USER_MODE_SECURE)) {
			/* Channel requires secure connections, but user isn't using one. Reject. */
			send_numeric(user, 477, "Cannot join channel (+S) - you need to use a secure connection\r\n"); /* XXX This is not the right numeric code, what is? */
			return NULL;
		}
		if (channel->modes & CHANNEL_MODE_REGISTERED_ONLY && user->node && !bbs_user_is_registered(user->node->user)) {
			send_numeric(user, 477, "Cannot join channel (+r) - you need to be logged into your account\r\n");
			return NULL;
		}
		if (channel->modes & CHANNEL_MODE_PASSWORD && !strlen_zero(channel->password) && (strlen_zero(password) || strcmp(password, channel->password))) {
			send_numeric(user, 475, "Cannot join channel (+k) - bad key\r\n");
			return NULL;
		}
		if (channel->modes & CHANNEL_MODE_LIMIT && channel->limit && channel->membercount >= (int) channel->limit) {
			send_numeric(user, 471, "Cannot join channel (+l) - channel is full, try again later\r\n");
			return NULL;
		}
		if (channel->modes & CHANNEL_MODE_THROTTLED && channel->throttleusers > 0 && channel->throttleinterval > 0) {
			time_t now = time(NULL);

			bbs_mutex_lock(&channel->lock);
			if (channel->throttlebegin < now - channel->throttleinterval) {
				/* It's been at least the entire interval at this point, so start fresh. */
				channel->throttlebegin = now;
				channel->throttlecount = 1; /* Reset, but then add us, so set directly to 1 */
				bbs_mutex_unlock(&channel->lock);
				/* We're allowed to proceed. */
			} else {
				if (channel->throttlecount >= channel->throttleusers) {
					bbs_mutex_unlock(&channel->lock);
					send_numeric(user, 480, "Cannot join channel (+j) - throttle exceeded, try again later\r\n");
					return NULL;
				}
				channel->throttlecount += 1;
				bbs_mutex_unlock(&channel->lock);
			}
		}
	}

	return channel;
}

static struct irc_member *new_channel_member(struct irc_user *user, struct irc_channel *channel)
{
	struct irc_member *member, *m;

	/* Check if we're already in the channel */
	RWLIST_TRAVERSE(&channel->members, m, entry) {
		if (m->user == user) {
			break;
		}
	}
	if (m) {
		send_numeric(user, 714, "You're already on that channel\r\n");
		return NULL;
	}

	if (channel->modes & CHANNEL_MODE_INVITE_ONLY) {
		if (!stringlist_contains(&channel->invited, user->nickname)) {
			send_numeric(user, 473, "Cannot join channel (+i) - you must be invited\r\n");
			return NULL;
		}
	}

	/* Add ourself to the channel members */
	member = calloc(1, sizeof(*member));
	if (ALLOC_FAILURE(member)) {
		/* Well this is embarassing, we got this far... but we couldn't make it to the finish line.
		 * It's a bit awkward since this empty channel will linger around,
		 * but that does no real harm, and this is SUCH an edge case... */
		return NULL;
	}
	bbs_mutex_init(&member->lock, NULL);
	member->user = user;
	member->modes = CHANNEL_USER_MODE_NONE;
	if (RWLIST_EMPTY(&channel->members)) {
		/* It's a new channel, we're the first member! */
		if (!IS_SERVICE(user)) { /* Don't count ChanServ recreating the channel */
			member->modes |= CHANNEL_USER_MODE_FOUNDER; /* If you created it, you're the founder. */
		}
		member->modes |= CHANNEL_USER_MODE_OP; /* If you created it, you're an op. */
		/* OP still needs to be granted to founders (as we do above), higher prefixes don't implicitly grant lower ones.
		 * For example, Ambassador won't let you perform op operations unless you're an op. */
		channel->relay = 1; /* XXX Not currently configurable in any way, always allowing relaying for now. */
	}
	if (IS_SERVICE(user)) {
		member->modes |= CHANNEL_USER_MODE_OP; /* Always op ChanServ */
	}
	RWLIST_INSERT_HEAD(&channel->members, member, entry);
	CHANNEL_MEMBER_COUNT_ADJUST(channel, +1);
	user->channelcount += 1;
	return member;
}

static int join_channel(struct irc_user *user, char *name)
{
	char modestr[16];
	struct irc_member *member;
	struct irc_channel *channel;

	if (strlen_zero(name)) {
		send_numeric(user, 479, "Empty channel name\r\n");
		return 0;
	}

	/* Nip junk right in the bud before we even bother locking the list */
	if (!irc_valid_channel_name(name)) {
		send_numeric(user, 479, "Illegal channel name\r\n");
		return 0;
	}

	if (user->channelcount > MAX_CHANNELS) {
		send_numeric2(user, 405, "%s :You have joined too many channels\r\n", name);
		return 0;
	}

	/* We might potentially create a channel, so grab a WRLOCK from the get go */

	/* XXX This is another instance of the ugly recursive locking hack.
	 * If leave_all_channels causes a bouncer client to join,
	 * when it joins the channel (this function), we will inevitably
	 * need to grab a WRLOCK.
	 *
	 * Changing the removal code to make a first pass using RDLOCK doesn't
	 * solve the problem, since most channel modification operations
	 * grab a WRLOCK. In other words, it would be cumbersome to avoid
	 * recursive locking, so we just do it since I know it works correctly.
	 *
	 * Only this function has been specially instrumented to avoid this deadlock
	 * by way of recursive locking; the other functions would deadlock,
	 * but are not currently called by mod_irc_bouncer. */
	RWLIST_WRLOCK_RECURSIVE(&channels, &channels_recurse);
	channel = find_or_create_channel_locked(user, name);
	if (!channel) {
		RWLIST_UNLOCK_RECURSIVE(&channels, &channels_recurse);
		return -1;
	}

	RWLIST_WRLOCK_RECURSIVE(&channel->members, &channel->recurse);
	member = new_channel_member(user, channel);
	RWLIST_UNLOCK_RECURSIVE(&channel->members, &channel->recurse);

	RWLIST_UNLOCK_RECURSIVE(&channels, &channels_recurse);

	if (!member) {
		return -1;
	}

	user_setactive(user);

/* If it's a real user, we may want to suppress the JOIN, PART, etc.
 * if a programmatic user will be taking his place as a result. */
#define BROADCAST_JOIN_LEAVE(user, channel, is_join) (IS_SERVICE(user) || (IS_REAL_USER(user) && !join_leave_suppress(user, channel, is_join)))

	if (BROADCAST_JOIN_LEAVE(user, channel, 1)) {
		/* These MUST be in this order: https://modern.ircdocs.horse/#join-message */
		channel_broadcast(channel, NULL, ":" HOSTMASK_FMT " JOIN %s\r\n", HOSTMASK_ARGS(user), channel->name); /* Send join message to everyone, including us */
		if (channel->relay) {
			char joinmsg[92];
			snprintf(joinmsg, sizeof(joinmsg), HOSTMASK_FMT " has joined %s", HOSTMASK_ARGS(user), channel->name);
			relay_broadcast(channel, NULL, NULL, joinmsg, NULL);
		}
		/* Don't send the mode now, because the client will just send a MODE command on its own anyways regardless */
		if (channel->topic) {
			channel_print_topic(user, channel);
		}
		send_channel_members(user, channel);
		if (!get_channel_user_modes(modestr, sizeof(modestr), member)) {
			channel_broadcast(channel, NULL, ":%s MODE %s %s %s\r\n", IS_SERVICE(user) ? "services" : "ChanServ", channel->name, modestr, user->nickname);
		}
		broadcast_channel_event_internal(IRCCMD_EVENT_JOIN, channel, user, NULL);
	} else {
		/* Even though it's supressed for everyone else, the actual user should still get the confirmation! */
		irc_other_thread_writef(user->node, ":" HOSTMASK_FMT " JOIN %s\r\n", HOSTMASK_ARGS(user), channel->name);
		/* Don't send the mode now, because the client will just send a MODE command on its own anyways regardless */
		if (channel->topic) {
			channel_print_topic(user, channel);
		}
		send_channel_members(user, channel);
	}
	return 0;
}

/*! \brief Must be called with WRLOCK on channels */
static int remove_channel(struct irc_channel *channel)
{
	struct irc_channel *c;
	RWLIST_TRAVERSE_SAFE_BEGIN(&channels, c, entry) {
		if (c == channel) {
			RWLIST_REMOVE_CURRENT(entry);
			bbs_debug(3, "Channel %s is now empty, removing\n", channel->name);
			channel_free(channel);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	return c ? 0 : -1;
}

static int leave_channel(struct irc_user *user, const char *name)
{
	struct irc_channel *channel;
	struct irc_member *member;

	user_setactive(user);

	/* WRLOCK, since channel might become empty and need to be removed */
	RWLIST_WRLOCK_RECURSIVE(&channels, &channels_recurse);
	channel = find_channel_by_user(name, user);
	if (!channel) { /* Channel doesn't exist */
		RWLIST_UNLOCK_RECURSIVE(&channels, &channels_recurse);
		send_numeric2(user, 403, "%s :No such channel\r\n", name);
		return -1;
	}
	RWLIST_WRLOCK_RECURSIVE(&channel->members, &channel->recurse);
	RWLIST_TRAVERSE_SAFE_BEGIN(&channel->members, member, entry) {
		if (member->user == user) {
			/* It is important that in code blocks where
			 * a channel member is removed from a list,
			 * it happens at the BEGINNING of the block.
			 *
			 * We need to remove this from the list BEFORE
			 * broadcast_channel_event_internal runs, since it
			 * may recursively trigger calls back into net_irc
			 * that end up modifiying the channel members list,
			 * i.e. if our leaving causes a bouncer user to join.
			 * If we didn't remove ourselves first, it would be
			 * possible for the newly added member to be attached
			 * to the linked list via the entry that is going to
			 * be removed, leading to entries leaking out of the
			 * list, not good! */
			RWLIST_REMOVE_CURRENT(entry);
			CHANNEL_MEMBER_COUNT_ADJUST(channel, -1);

			if (BROADCAST_JOIN_LEAVE(user, channel, 0)) {
				channel_broadcast_nolock(channel, NULL, ":" HOSTMASK_FMT " PART %s\r\n", HOSTMASK_ARGS(user), channel->name); /* Make sure leaver gets his/her own PART message! */
				if (channel->relay) {
					char partmsg[92];
					snprintf(partmsg, sizeof(partmsg), HOSTMASK_FMT " has left %s", HOSTMASK_ARGS(user), channel->name);
					relay_broadcast(channel, NULL, NULL, partmsg, NULL);
				}
				ENABLE_RECURSIVE_LOCKING(&channels_recurse); /* Need to allow recursive locking since channel->members is locked */
				broadcast_channel_event_internal(IRCCMD_EVENT_PART, channel, user, NULL);
				RESET_RECURSIVE_LOCKING(&channels_recurse);
			} else {
				/* Even though it's supressed for everyone else, the actual user should still get the confirmation! */
				irc_other_thread_writef(user->node, ":" HOSTMASK_FMT " PART %s\r\n", HOSTMASK_ARGS(user), channel->name); /* Make sure leaver gets his/her own PART message! */
			}
			member->user->channelcount -= 1;
			member_free(member);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK_RECURSIVE(&channel->members, &channel->recurse);
	if (RWLIST_EMPTY(&channel->members) && !(channel->modes & CHANNEL_MODE_PERMANENT)) {
		remove_channel(channel);
	}
	RWLIST_UNLOCK_RECURSIVE(&channels, &channels_recurse);
	/* member is not a valid reference now, we just care that it was a reference */
	if (!member) { /* User doesn't exist in this channel */
		send_numeric(user, 442, "You're not on that channel\r\n");
		return -1;
	}
	return 0;
}

static void drop_member_if_present(struct irc_channel *channel, struct irc_user *user, const char *leavecmd, const char *message)
{
	struct irc_member *member;

	/* If we're going to remove the user, we need a WRLOCK, so grab it from the get go. */
	RWLIST_WRLOCK_RECURSIVE(&channel->members, &channel->recurse);
	RWLIST_TRAVERSE_SAFE_BEGIN(&channel->members, member, entry) {
		if (member->user == user) {
			/* If we're leaving ALL channels, don't relay QUIT messages to ourselves. */
			bbs_debug(3, "Dropping user %s from channel %s\n", user->nickname, channel->name);
			RWLIST_REMOVE_CURRENT(entry);
			CHANNEL_MEMBER_COUNT_ADJUST(channel, -1);
			member->user->channelcount -= 1;
			member_free(member);
			if (BROADCAST_JOIN_LEAVE(user, channel, 0)) {
				/* Already locked, so don't try to recursively lock: */
				channel_broadcast_nolock(channel, user, ":" HOSTMASK_FMT " %s %s :%s\r\n", HOSTMASK_ARGS(user), leavecmd, channel->name, S_IF(message));
				if (channel->relay && !bbs_is_shutting_down()) { /* If BBS shutting down, don't relay a bunch of quit messages */
					char quitmsg[92];
					snprintf(quitmsg, sizeof(quitmsg), HOSTMASK_FMT " has quit %s%s%s%s", HOSTMASK_ARGS(user), channel->name, message ? " (" : "", S_IF(message), message ? ")" : "");
					relay_broadcast(channel, NULL, NULL, quitmsg, NULL);
				}
				/* Need to allow recursive locking since channel->members is locked,
				 * but we're called by leave_all_channels, which already enables it. */
				broadcast_channel_event_internal(IRCCMD_EVENT_QUIT, channel, user, message);
			} else {
				/* Even though it's supressed for everyone else, the actual user should still get the confirmation! */
				irc_other_thread_writef(user->node, ":" HOSTMASK_FMT " %s %s :%s\r\n", HOSTMASK_ARGS(user), leavecmd, channel->name, S_IF(message)); /* Make sure leaver gets his/her own PART message! */
			}
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK_RECURSIVE(&channel->members, &channel->recurse);
	/* Rather than freeing channel here, we do it after this function
	 * returns since we can more efficiently remove it from the list there. */
}

static void kick_member(struct irc_channel *channel, struct irc_user *kicker, struct irc_user *kicked, const char *message)
{
	struct irc_member *member;

	if (IS_SERVICE(kicked)) {
		send_numeric(kicker, 484, "%s %s :Cannot kick or drop a network service\r\n", kicked->nickname, channel->name);
		return;
	}

	/* If we're going to remove the user, we need a WRLOCK, so grab it from the get go. */
	RWLIST_WRLOCK(&channel->members);
	RWLIST_TRAVERSE_SAFE_BEGIN(&channel->members, member, entry) {
		if (member->user == kicked) {
			/* If we're leaving ALL channels, don't relay QUIT messages to ourselves. */
			bbs_debug(3, "Dropping user %s from channel %s\n", kicked->nickname, channel->name);
			RWLIST_REMOVE_CURRENT(entry);
			CHANNEL_MEMBER_COUNT_ADJUST(channel, -1);
			member_free(member);
			/* XXX For programmatic users, this is a bit of a weird case.
			 * If a user has a bouncer configured to watch a channel,
			 * and he gets kicked, the bouncer would silently rejoin.
			 * Therefore, for these, we ALWAYS broadcast, instead of using BROADCAST_JOIN_LEAVE,
			 * otherwise it would not be transparent as to what's going on. */
			channel_broadcast_nolock(channel, NULL, ":" HOSTMASK_FMT " KICK %s %s :%s\r\n", HOSTMASK_ARGS(kicker), channel->name, kicked->nickname, S_IF(message)); /* Already locked, don't try to recursively lock */
			/*! \todo Shouldn't we call relay_broadcast for kick as well? */
			ENABLE_RECURSIVE_LOCKING(&channel->recurse); /* Need to allow recursive locking since channel->members is locked */
			broadcast_channel_event_internal(IRCCMD_EVENT_KICK, channel, kicked, message);
			RESET_RECURSIVE_LOCKING(&channel->recurse);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&channel->members);
	if (RWLIST_EMPTY(&channel->members) && !(channel->modes & CHANNEL_MODE_PERMANENT)) {
		remove_channel(channel);
	}
}

static void leave_all_channels(struct irc_user *user, const char *leavecmd, const char *message)
{
	struct irc_channel *channel;

	/* Remove from all channels the user is currently in, and broadcast a message to each of them.
	 * Because we might remove a user if this is the last user in the channel, we need a WRLOCK. */
	ENABLE_RECURSIVE_LOCKING(&channel->recurse);
	RWLIST_WRLOCK_RECURSIVE(&channels, &channels_recurse);
	/* We're going to have to traverse channels to find channels anyways,
	 * so simply traversing them all and seeing if the user is a member of each
	 * isn't as bad when you think about it that way. */
	RWLIST_TRAVERSE_SAFE_BEGIN(&channels, channel, entry) { /* We must use a safe traversal, since drop_member_if_present could cause the channel to be removed if it's now empty */
		drop_member_if_present(channel, user, leavecmd, message);
		/* drop_member_if_present skips the removal check,
		 * since we already are iterating the list and easily able to remove channels,
		 * so we can avoid remove_channel, which does another linear scan of the channel list. */
		if (RWLIST_EMPTY(&channel->members) && !(channel->modes & CHANNEL_MODE_PERMANENT)) {
			RWLIST_REMOVE_CURRENT(entry);
			bbs_debug(3, "Channel %s is now empty, removing\n", channel->name);
			channel_free(channel);
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK_RECURSIVE(&channels, &channels_recurse);
	RESET_RECURSIVE_LOCKING(&channel->recurse);
}

/*!
 * \param Indicate to any relay modules a change in away/here status
 * \param user
 * \param userstatus
 * \param Away message if away, NULL if back
 */
static void set_away_via_relays(struct irc_user *user, enum irc_user_status userstatus, const char *awaymsg)
{
	struct irc_relay *relay;

	/* No message goes out to the channel when a user marks himself as away,
	 * clients will poll for this information periodically using commands like WHO.
	 * However, if a private relay is configured for this channel,
	 * then it will want to mirror the client's away/back status to the
	 * paired channel. Therefore, we need to let relay modules know. */
	RWLIST_RDLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		if (relay->relay_callbacks->away) {
			bbs_module_ref(relay->mod, 11);
			if (relay->relay_callbacks->away(user->nickname, userstatus, awaymsg)) {
				bbs_module_unref(relay->mod, 4);
				break;
			}
			bbs_module_unref(relay->mod, 11);
		}
	}
	RWLIST_UNLOCK(&relays);
}

static void set_away(struct irc_user *user, char *s)
{
	/* Set user as away or back */
	bbs_mutex_lock(&user->lock);
	free_if(user->awaymsg);
	if (!strlen_zero(s)) { /* Format is AWAY :optional multi-word message */
		if (!strncmp(s, ":", 1)) {
			s++;
		}
	}
	if (!strlen_zero(s)) { /* Away */
		user->awaymsg = strdup(s);
		user->away = 1;
	} else { /* No longer away */
		user->away = 0;
	}
	bbs_mutex_unlock(&user->lock);
	set_away_via_relays(user, user->away ? IRC_USER_STATUS_AWAY : IRC_USER_STATUS_BACK, user->awaymsg);
	send_numeric(user, user->away ? 306 : 305, "You %s marked as being away\r\n", user->away ? "have been" : "are no longer");
}

static int channel_count(void)
{
	int c;
	struct irc_channel *channel;
	RWLIST_RDLOCK(&channels);
	c = RWLIST_SIZE(&channels, channel, entry);
	RWLIST_UNLOCK(&channels);
	return c;
}

static time_t motd_last_read = 0;
static bbs_mutex_t motd_lock;

/*! \brief Message of the Day */
static void motd(struct irc_user *user)
{
	send_numeric(user, 375, "- %s Message of the Day -\r\n", irc_hostname);
	send_numeric(user, 372, "- This server powered by the Lightweight Bulletin Board System\r\n");
	send_numeric(user, 372, "- Visit us at %s\r\n", BBS_SOURCE_URL);

	bbs_mutex_lock(&motd_lock);
	if (!s_strlen_zero(motd_file)) { /* Custom MOTD text */
		/* Reread the MOTD from disk at most once an hour. */
		time_t now = time(NULL);
		if (!motd_last_read || motd_last_read < now - 3600) {
			free_if(motdstring);
			motdstring = bbs_file_to_string(motd_file, 4096, NULL);
		}
		motd_last_read = now;
		if (!strlen_zero(motdstring)) {
			/* File could have multiple lines, and have either LF or CR LF line endings,
			 * and have or not have a newline at the EOF.
			 * Try to accomodate all of these possibilities. */
			char motdlines[2048];
			char *line, *lines = motdlines;
			safe_strncpy(motdlines, motdstring, sizeof(motdlines));
			bbs_mutex_unlock(&motd_lock);
			while ((line = strsep(&lines, "\n"))) {
				if (strlen_zero(line)) {
					continue;
				}
				bbs_strterm(line, '\r'); /* In case using CR LF */
				send_numeric(user, 372, "- %s\r\n", line);
			}
		} else {
			bbs_mutex_unlock(&motd_lock);
			send_numeric(user, 372, "- Welcome to %s chat\r\n", bbs_name());
		}
	} else {
		bbs_mutex_unlock(&motd_lock);
	}

	send_numeric(user, 376, "End of /MOTD command.\r\n");
}

static int client_welcome(struct irc_user *user)
{
	char starttime[30];
	int count;
	int chancount;
	struct irc_user *u;
	char timebuf[30];

	RWLIST_RDLOCK(&users);
	count = RWLIST_SIZE(&users, u, entry) + 1; /* Add 1 for this user, since we're not in the users list until add_user() */
	RWLIST_UNLOCK(&users);

	bbs_time_friendly(loadtime, starttime, sizeof(starttime));

	send_numeric(user, 1, "Welcome to the %s Internet Relay Chat Network %s\r\n", bbs_name(), user->nickname);
	send_numeric(user, 2, "Your host is %s, running version %s\r\n", irc_hostname, IRC_SERVER_VERSION);
	send_numeric(user, 3, "This server was created %s\r\n", starttime);
	send_numeric2(user, 4, "%s %s %s %s %s\r\n", irc_hostname, IRC_SERVER_VERSION, usermodes, channelmodes, paramchannelmodes);
	/* We must explicitly advertise what prefixes we support or clients won't support them:
	 * https://modern.ircdocs.horse/#rplisupport-parameters
	 * https://defs.ircdocs.horse/defs/isupport.html
	 * https://defs.ircdocs.horse/defs/chanmembers.html
	 * http://www.irc.org/tech_docs/005.html
	 */
	/* MAX_CHANNELS applies to both # and &, but seems the spec doesn't allow providing a "combined" value for all channels? */
	send_numeric2(user, 5, "SAFELIST CHANTYPES=#& CHANMODES=%s CHANLIMIT=#:%d,&:%d :are supported by this server\r\n", chanmodes, MAX_CHANNELS, MAX_CHANNELS);
	send_numeric2(user, 5, "PREFIX=%s KNOCK MAXLIST=%s MODES=26 CASEMAPPING=rfc1459 :are supported by this server\r\n", "(qaohv)~&@%+", DEF_MAXLIST); /* Ambassador ignores ascii for some reason but accepts rfc1459 */
	send_numeric2(user, 5, "NICKLEN=%d MAXNICKLEN=%d USERLEN=%d ELIST=TU AWAYLEN=%d CHANNELLEN=%d HOSTLEN=%d NETWORK=%s STATUSMSG=%s TOPICLEN=%d :are supported by this server\r\n",
		MAX_NICKLEN, MAX_NICKLEN, MAX_NICKLEN, MAX_AWAY_LEN, MAX_CHANNEL_LENGTH, MAX_HOSTLEN, bbs_name(), "&@%+", MAX_TOPIC_LENGTH);

	chancount = channel_count();

	send_numeric(user, 251, "There %s %d user%s on %d server%s\r\n", count == 1 ? "is" : "are", count, ESS(count), 1, ESS(1));
	send_numeric2(user, 252, "%d :IRC Operator%s online\r\n", operators_online, ESS(operators_online));
	send_numeric2(user, 254, "%d :channel%s formed\r\n", chancount, ESS(chancount));

	motd(user);

	if (bbs_user_is_registered(user->node->user) && user->node->user->lastlogin && strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M %P %Z", user->node->user->lastlogin) > 0) { /* bbs_time_friendly does this internally */
		send_reply(user, "%s NOTICE %s :Last login was %s\r\n", irc_hostname, user->username, timebuf);
	}

	if (user->node->user) {
		add_user(user);
		whowas_update(user, 0);
		post_login(user);
	} else {
		if (bbs_user_exists(user->nickname)) {
			send_reply(user, "NOTICE AUTH :*** This nickname is registered. Please choose a different nickname, or identify...\r\n");
		} else {
			add_user(user); /* Nickname is not claimed. It's fine. */
		}
	}

	return 0;
}

static int do_sasl_auth(struct irc_user *user, char *s)
{
	int res;
	unsigned char *decoded;
	char *nickname, *username, *password;
	char *encoded;

	if (!STARTS_WITH(s, "AUTHENTICATE ")) {
		bbs_warning("Unhandled message: %s\n", s);
		return -1;
	}
	encoded = s + STRLEN("AUTHENTICATE ");
	/* AUTHENTICATE <BASE64(nick NUL username NUL password)> */
	decoded = bbs_sasl_decode(encoded, &nickname, &username, &password);
	if (!decoded) {
		return -1;
	}
	if (strcmp(nickname, user->nickname)) {
		bbs_warning("Nickname received '%s' does not match initial nick '%s'\n", nickname, user->nickname);
		free(decoded);
		return -1;
	}
	user->username = strdup(username);
	res = bbs_authenticate(user->node, username, password);
	bbs_memzero(password, strlen(password)); /* Destroy the password from memory before we free it */
	free(decoded);
	if (res) {
		send_numeric(user, 904, "SASL authentication failed\r\n");
		return -1;
	}
	/* The prefix is nick!ident@host */
	send_numeric(user, 903, "SASL authentication successful\r\n");
	send_numeric(user, 900, HOSTMASK_FMT " %s You are now logged in as %s\r\n", HOSTMASK_ARGS(user), user->username, user->username);
	return 0;
}

static int handle_user(struct irc_user *user)
{
	char hostname[260];
	if (!user->nickname) {
		bbs_warning("Received USER without NICK?\n"); /* Invalid command sequence */
		return -1;
	}
	send_reply(user, "NOTICE AUTH :*** Processing connection to %s\r\n", irc_hostname);
	send_reply(user, "NOTICE AUTH :*** Looking up your hostname...\r\n");
	/* Resolve IP address to hostname */
	if (!bbs_get_hostname(user->hostname, hostname, sizeof(hostname))) {
		bbs_debug(3, "Resolved IP %s to hostname %s\n", user->node->ip, hostname);
		REPLACE(user->hostname, hostname);
		send_reply(user, "NOTICE AUTH :*** Checking Ident\r\n"); /* XXX Not really, we're not */
		send_reply(user, "NOTICE AUTH :*** No Ident response\r\n");
		send_reply(user, "NOTICE AUTH :*** Found your hostname: %s\r\n", user->hostname);
	} else {
		send_reply(user, "NOTICE AUTH :*** Couldn't look up your hostname\r\n");
	}
	return 0;
}

static void handle_client(struct irc_user *user)
{
	int capnegotiate = 0;
	ssize_t res;
	int started = 0;
	char buf[513];
	int sasl_attempted = 0;
	int graceful_close = 0;
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));

	for (;;) {
		char *s = buf;

		/* XXX For some reason, using \r\n as the delimiter for bbs_readline breaks Ambassador.
		 * Doesn't seem like a bug in bbs_readline, though it is suspicious since
		 * the RFCs are very clear that CR LF is the delimiter.
		 * So even though this feels wrong, accept just LF for compatibility, and strip trailing CR if present.
		*/
		res = bbs_node_readline(user->node, &rldata, "\n", 2 * PING_TIME); /* Wait up to the ping interval time for something, anything, otherwise disconnect. */
		if (res <= 0) {
			/* Don't set graceful_close to 0 here, since after a QUIT, the client may close the connection first.
			 * The QUIT message should be whatever the client sent, since it was graceful, not connection closed by remote host. */
			bbs_debug(3, "bbs_readline returned %ld\n", res);
			break;
		}
		bbs_strterm(s, '\r');

		/* Don't fully print out commands containing sensitive info */
		if (STARTS_WITH(s, "OPER ")) {
			bbs_debug(8, "%p => OPER *****\n", user);
		} else if (STARTS_WITH(s, "PASS ")) {
			bbs_debug(8, "%p => PASS *****\n", user);
		} else if (STARTS_WITH(s, "NS IDENTIFY")) {
			bbs_debug(8, "%p => NS IDENTIFY *****\n", user);
		} else if (STARTS_WITH(s, "PRIVMSG NickServ")) {
			bbs_debug(8, "%p => PRIVMSG NickServ *****\n", user);
		} else {
			bbs_debug(8, "%p => %s\n", user, s); /* No trailing LF, so addding one here is fine */
		}
		if (capnegotiate) {
			int sasl_failed = 0;
			/* XXX This is pretty rudimentary CAP support, it doesn't really support anything besides PLAIN SASL auth.
			 * It also doesn't fully account for all the possible scenarios allowed by the specs, only what's commonly done in practice. */
			if (capnegotiate == 1) {
				char *command = strsep(&s, " ");
				if (!s) {
					bbs_warning("No data after command %s\n", command);
					break; /* Just disconnect on the client */
				}
				/* Client will send a NICK, then USER: https://ircv3.net/specs/extensions/capability-negotiation.html */
				if (!strcasecmp(command, "NICK")) {
					if (!started) {
						/* Users that aren't started, and more importantly, in the user list, (!started, !user->registered)
						 * can change their nickname arbitrarily, but can't use it without identifying. */
						REPLACE(user->nickname, s);
						bbs_debug(5, "Nickname is %s\n", user->nickname);
					}
				} else if (!strcasecmp(command, "USER")) { /* Whole message is something like 'ambassador * * :New Now Know How' */
					char *realname;
					bbs_debug(5, "Username data is %s\n", s);
					realname = strsep(&s, " ");
					REPLACE(user->realname, realname);
					if (handle_user(user)) {
						break;
					}
					send_reply(user, "CAP * LS :multi-prefix sasl=PLAIN\r\n");
					capnegotiate++;
				} else {
					bbs_warning("Unhandled message: %s %s\n", command, s);
				}
			} else if (capnegotiate == 2) {
				int multiple = 0;
				if (STARTS_WITH(s, "CAP REQ ")) {
					/* Tolerate either e.g. CAP REQ :multi-prefix or CAP REQ multi-prefix (colon is not always mandatory) */
					s += STRLEN("CAP REQ ");
					REQUIRE_PARAMETER(user, s);
					if (*s == ':') { /* Colon technically optional, if there's only one capability */
						multiple = 1;
						s++;
					}
					REQUIRE_PARAMETER(user, s);
					/* Not very robust, these are the few cases that matter to us: */
					if (!strcmp(s, "multi-prefix")) { /* See https://ircv3.net/specs/extensions/multi-prefix */
						send_reply(user, "CAP * ACK :multi-prefix\r\n"); /* Colon technically optional, since there's only one capability */
						/* SASL *not* supported */
						/* Don't increment capnegotiate, just wait for the client to send CAP END */
						user->multiprefix = 1;
					} else if (!strcmp(s, "sasl")) {
						send_reply(user, "CAP * ACK :sasl\r\n");
						capnegotiate++;
					} else if (multiple && !strcmp(s, "multi-prefix sasl")) {
						send_reply(user, "CAP * ACK :multi-prefix sasl\r\n");
						capnegotiate++;
						user->multiprefix = 1;
					} else {
						bbs_warning("Unhandled message: %s\n", s);
					}
				} else if (strcmp(s, "CAP END")) {
					bbs_warning("Unhandled message: %s\n", s);
				}
			} else if (capnegotiate == 3) {
				if (!strcmp(s, "AUTHENTICATE PLAIN")) {
					send_reply(user, "AUTHENTICATE +\r\n");
					capnegotiate++;
				} else if (strcmp(s, "CAP END")) {
					bbs_warning("Unhandled message: %s\n", s);
				}
			} else if (capnegotiate == 4) {
				capnegotiate++;
				sasl_attempted = 1;
				sasl_failed = do_sasl_auth(user, s);
			} else if (capnegotiate == 5) {
				if (!strcmp(s, "CAP END")) {
					capnegotiate = 0; /* Done with CAP */
					bbs_debug(5, "Capability negotiation finished\n");
					if (!started) {
						if (!client_welcome(user)) {
							started = 1;
						}
					} else {
						bbs_error("Client %p already started?\n", user);
					}
				} else {
					char *command;
					bbs_warning("Unhandled message: %s\n", s);
					command = strsep(&s, " ");
					send_numeric2(user, 421, "%s :Unknown command or invalid in current state\r\n", command);
				}
			} else {
				bbs_warning("Unhandled message: %s\n", s);
				send_numeric(user, 410, "Invalid CAP command\r\n");
				/* First message: Didn't start with CAP LS 302? Then client doesn't support SASL, just get going. */
			}
			if (capnegotiate == 5 && sasl_failed) {
				send_numeric(user, 906, "SASL authentication aborted\r\n");
			} else if (!started && !strlen_zero(s) && !strcmp(s, "CAP END")) { /* CAP END can be sent at any time during capability negotiation */
				capnegotiate = 0; /* Done with CAP */
				bbs_debug(5, "Capability negotiation cancelled by client\n");
				if (!client_welcome(user)) {
					started = 1;
					/*! \todo once we auth, need to explicitly call add_user */
				}
			}
		} else if (!strcasecmp(s, "CAP LS 302")) {
			if (started) {
				send_numeric(user, 462, "You are already connected and cannot handshake again\r\n");
			} else {
				bbs_debug(5, "Client wants to negotiate\n"); /* Technically, a client could also just start with an unsolicited CAP REQ */
				capnegotiate = 1; /* Begin negotiation */
			}
		} else { /* Post-CAP/SASL */
			char *current, *command = strsep(&s, " ");
			if (!strcasecmp(command, "PONG")) {
				struct timeval now_us, diff_us;
				gettimeofday(&now_us, NULL);
				bbs_mutex_lock(&user->lock);
				timersub(&now_us, &user->lastping_us, &diff_us);
				user->lag = (int) ((1000 * diff_us.tv_sec) + (diff_us.tv_usec / 1000));
				user->lastpong = time(NULL);
				bbs_mutex_unlock(&user->lock);
			} else if (!strcasecmp(command, "PING")) { /* Usually servers ping clients, but clients can ping servers too */
				/* The server PONG response slightly differs from the client PONG response.
				 * We include the hostname of the pinged server, before echoing back whatever was received. */
				send_reply(user, "PONG %s %s\r\n", irc_hostname, S_IF(s)); /* Don't add another : because it's still in s, if present. */
			} else if (!strcasecmp(command, "PASS")) {
				REQUIRE_PARAMETER(user, s);
				free_if(user->password);
				user->password = strdup(s);
			} else if (!strcasecmp(command, "NICK")) {
				REQUIRE_PARAMETER(user, s);
				handle_nick(user, s);
			} else if (!strcasecmp(command, "USER")) {
				int authres;
				char *realname;
				REQUIRE_PARAMETER(user, s);
				realname = strsep(&s, " ");
				REPLACE(user->realname, realname);
				if (handle_user(user)) {
					break;
				}
				authres = bbs_authenticate(user->node, user->nickname, user->password);
				if (user->password) {
					bbs_memzero(user->password, strlen(user->password)); /* Destroy password before freeing it */
				}
				FREE(user->password);
				if (authres) {
					send_numeric(user, 464, "Password incorrect\r\n");
				} else {
					free_if(user->username);
					user->username = strdup(user->nickname);
					add_user(user);
					send_numeric(user, 900, HOSTMASK_FMT " %s You are now logged in as %s\r\n", HOSTMASK_ARGS(user), user->username, user->username);
					post_login(user);
				}
			/* Any remaining commands require authentication.
			 * The nice thing about this IRC server is we authenticate using the BBS user,
			 * e.g. you don't create accounts using IRC, so we don't need to support guest access at all. */
			} else if (!sasl_attempted && !bbs_user_is_registered(user->node->user) && require_sasl) {
				send_reply(user, "NOTICE AUTH :*** This server requires SASL for authentication. Please reconnect with SASL enabled.\r\n");
				goto quit; /* Disconnect at this point, there's no point in lingering around further. */
			/* We can't necessarily use %s (user->username) instead of %p (user), since if require_sasl == false, we might not have a username still. */
			} else if (!user->node->user || !user->registered) {
				char *target;
				/* Okay to message NickServ without being registered, but nobody else. */
				/* Can be NS IDENTIFY <password> or a regular PRIVMSG */
				if (!strcasecmp(command, "NS")) {
					REQUIRE_PARAMETER(user, s);
					if (nickserv(user, s)) {
						break;
					}
					continue;
				} else if (!strcasecmp(command, "PRIVMSG")) {
					target = strsep(&s, " ");
					REQUIRE_PARAMETER(user, s);
					REQUIRE_PARAMETER(user, target);
					if (s && *s == ':') {
						s++; /* Skip leading : */
					}
					if (!strcmp(target, "NickServ")) {
						nickserv(user, s);
						continue;
					}
				}
				if (!user->node->user) {
					send_numeric(user, 451, "You have not registered\r\n");
				} else {
					send_numeric(user, 433, "Nickname is already in use\r\n");
				}
			} else if (!user->registered) {
				send_numeric(user, 433, "Nickname is already in use\r\n"); /* XXX Ambassador displays "Nickname is already in use" as the username that was rejected */
			} else if (!strcasecmp(command, "NS")) { /* NickServ alias */
				nickserv(user, s);
			} else if (!strcasecmp(command, "CS")) { /* ChanServ alias (much like NS ~ NickServ) */
				chanserv_msg(user, s);
			} else if (!strcasecmp(command, "PRIVMSG")) { /* List this as high up as possible, since this is the most common command */
				handle_privmsg(user, s, 0);
			} else if (!strcasecmp(command, "NOTICE")) { /* List this as high up as possible, since this is the most common command */
				handle_privmsg(user, s, 1);
			} else if (!strcasecmp(command, "MODE")) {
				REQUIRE_PARAMETER(user, s);
				handle_modes(user, s);
			} else if (!strcasecmp(command, "TOPIC")) { /* Get or set the topic */
				handle_topic(user, s);
			} else if (!strcasecmp(command, "JOIN")) {
				bbs_debug(3, "User %p wants to join channels: %s\n", user, s);
				rtrim(s); /* Not sure why this is necessary, but there's an extra space on the end it seems with Ambassador, at least. */
				while ((current = strsep(&s, ","))) {
					join_channel(user, current);
				}
			} else if (!strcasecmp(command, "PART")) {
				bbs_strterm(s, ':'); /* If there's a :, ignore anything after it */
				rtrim(s);
				bbs_debug(3, "User %p wants to leave channels: %s\n", user, s);
				while ((current = strsep(&s, ","))) {
					leave_channel(user, current);
				}
			} else if (!strcasecmp(command, "QUIT")) {
				bbs_debug(3, "User %p wants to quit: %s\n", user, S_IF(s));
				rtrim(s);
				graceful_close = 1;
				leave_all_channels(user, "QUIT", s);
				break; /* We're done. */
			} else if (!strcasecmp(command, "AWAY")) {
				if (!strlen_zero(s) && strlen(s) > MAX_AWAY_LEN) {
					send_numeric(user, 416, "Input too large\r\n"); /* XXX Not really the appropriate numeric */
					continue;
				}
				set_away(user, s);
			} else if (!strcasecmp(command, "KICK")) {
				struct irc_member *member;
				char *reason, *kickusername, *channame = strsep(&s, " ");
				kickusername = strsep(&s, " ");
				reason = s;
				REQUIRE_PARAMETER(user, kickusername);
				/* KICK #channel jsmith :Reason for kicking user */
				member = get_member_by_channel_name(user, channame);
				if (!member || !authorized_atleast(member, CHANNEL_USER_MODE_HALFOP)) { /* Need at least half op to kick */
					send_numeric2(user, 482, "%s: You're not a channel operator\r\n", channame);
				} else {
					struct irc_member *kickuser;
					struct irc_channel *kickchan = find_channel_by_user(channame, user);
					if (!kickchan) {
						send_numeric2(user, 403, "%s :No such channel\r\n", channame);
						continue;
					}
					kickuser = get_member_by_nickname(kickusername, kickchan->name);
					if (!kickuser) {
						send_numeric2(user, 401, "%s :No such nick/channel\r\n", kickchan->name);
						continue;
					}
					kick_member(kickchan, user, kickuser->user, reason);
				}
			} else if (!strcasecmp(command, "KILL")) {
				struct irc_user *u;
				char *killusername, *reason;
				killusername = strsep(&s, " ");
				reason = s;
				REQUIRE_PARAMETER(user, killusername);
				REQUIRE_OPER(user);
				/* KILL jsmith :Reason for kicking user */
				u = get_user(killusername);
				if (!u) {
					send_numeric2(user, 401, "%s :No such nick/channel\r\n", killusername);
					continue;
				}
				/* Kill the user */
				leave_all_channels(u, "QUIT", reason); /* Just use QUIT for now, KILL doesn't render properly in Ambassador. */
				send_reply(u, "KILL %s%s\r\n", !strlen_zero(reason) ? ":" : "", S_IF(reason));
				bbs_debug(5, "Shutting down client on node %d\n", user->node->id);
				bbs_socket_shutdown(u->node->fd); /* Make the client handler thread break */
			} else if (!strcasecmp(command, "INVITE")) {
				handle_invite(user, s);
			} else if (!strcasecmp(command, "KNOCK")) {
				handle_knock(user, s);
			} else if (!strcasecmp(command, "NAMES")) {
				struct irc_channel *channel;
				REQUIRE_PARAMETER(user, s);
				channel = find_channel_by_user(s, user);
				/* Many servers don't allow NAMES unless you're in the channel: we do... */
				if (!channel) {
					send_numeric2(user, 403, "%s :No such channel\r\n", s);
					continue;
				}
				/* ...unless it's private/secret */
				if (channel->modes & CHANNEL_HIDDEN && suppress_channel(user, channel)) {
					send_numeric(user, 442, "You're not on that channel\r\n");
					continue;
				}
				send_channel_members(user, channel);
			} else if (!strcasecmp(command, "WHO")) {
				/* WHO username or WHO #channel, mask patterns not supported */
				handle_who(user, s);
			} else if (!strcasecmp(command, "WHOIS")) {
				REQUIRE_PARAMETER(user, s);
				handle_whois(user, s);
			} else if (!strcasecmp(command, "WHOWAS")) {
				REQUIRE_PARAMETER(user, s);
				handle_whowas(user, s);
			} else if (!strcasecmp(command, "USERHOST")) {
				handle_userhost(user, s);
			} else if (!strcasecmp(command, "LIST")) {
				handle_list(user, s);
			} else if (!strcasecmp(command, "STATS")) {
				REQUIRE_PARAMETER(user, s);
				handle_stats(user, s);
			} else if (!strcasecmp(command, "ISON")) {
				char *name, *names = s;
				REQUIRE_PARAMETER(user, s);
				while ((name = strsep(&names, " "))) {
					if (get_user(name)) {
						send_numeric(user, 303, "%s\r\n", name);
					}
				}
			} else if (!strcasecmp(command, "MOTD")) {
				motd(user);
			} else if (!strcasecmp(command, "HELP")) {
				handle_help(user, s);
			} else if (!strcasecmp(command, "VERSION")) {
				send_numeric(user, 351, "%s %s :%s\r\n", BBS_VERSION, irc_hostname, IRC_SERVER_VERSION);
			} else if (!strcasecmp(command, "TIME")) {
				time_t lognow;
				struct tm logdate;
				char datestr[20];
				lognow = time(NULL);
				localtime_r(&lognow, &logdate);
				strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);
				send_numeric(user, 391, "%s\r\n", datestr);
			} else if (!strcasecmp(command, "INFO")) {
				char starttime[30];
				bbs_time_friendly(loadtime, starttime, sizeof(starttime));
				send_numeric(user, 371, "%s (%s) v%s - Integrated IRC Server\r\n", BBS_SHORTNAME, BBS_TAGLINE, BBS_VERSION);
				send_numeric(user, 371, "Copyright (C) 2023 %s\r\n", BBS_AUTHOR);
				send_numeric(user, 371, "%s\r\n", BBS_SOURCE_URL);
				send_numeric(user, 371, "\r\n");
				send_numeric(user, 371, "This program is free software; you can redistribute it and/or\r\n");
				send_numeric(user, 371, "modify it under the terms of the GNU General Public License\r\n");
				send_numeric(user, 371, "Version 2 as published by the Free Software Foundation.\r\n");
				send_numeric(user, 371, "\r\n");
				send_numeric(user, 371, "On-line since %s\r\n", starttime);
				send_numeric(user, 374, "End of /INFO list.\r\n");
			} else if (!strcasecmp(command, "OPER")) {
				handle_oper(user, s);
			} else if (!strcasecmp(command, "WALLOPS")) {
				struct irc_user *u;
				REQUIRE_OPER(user);
				RWLIST_RDLOCK(&users);
				RWLIST_TRAVERSE(&users, u, entry) {
					if (u->modes & USER_MODE_WALLOPS) {
						irc_other_thread_writef(u->node, ":" HOSTMASK_FMT " %s %s :%s\r\n", HOSTMASK_ARGS(user), "WALLOPS", u->nickname, s);
					}
				}
				RWLIST_UNLOCK(&users);
			} else if (!strcasecmp(command, "REHASH")) {
				REQUIRE_OPER(user);
				/* Reread the config, although not everything can be updated this way. */
				send_numeric(user, 382, "%s :Rehashing\r\n", irc_hostname);
				destroy_operators(); /* Remove any existing operators */
				load_config();
			} else if (!strcasecmp(command, "RESTART")) {
				REQUIRE_OPER(user);
				/* Restart the IRC server */
				need_restart = 2; /* This will get processed by the ping thread, so that we can be disconnected. */
				send_reply(user, "NOTICE :Server will restart momentarily\r\n");
			} else if (!strcasecmp(command, "DIE")) {
				REQUIRE_OPER(user);
				/* Stop the IRC server */
				need_restart = 1; /* This will get processed by the ping thread, so that we can be disconnected. */
				send_reply(user, "NOTICE :Server will halt momentarily\r\n");
			/* Ignore SQUIT for now, since this is a single-server network */
			} else {
				send_numeric2(user, 421, "%s :Unknown command\r\n", command);
				bbs_warning("%p: Unhandled message: %s %s\n", user, command, S_IF(s));
			}
		}
	}

quit:
	if (!graceful_close) {
		leave_all_channels(user, "QUIT", "Remote user closed the connection"); /* poll or read failed */
	}
	if (user->registered) {
		whowas_update(user, 1);
		set_away_via_relays(user, IRC_USER_STATUS_QUIT, "Away");
		unlink_user(user);
	}
}

int irc_user_exec(struct irc_user *user, char *s)
{
	char *command = strsep(&s, " ");

	bbs_assert_exists(user);

	/* Execute command as a programmatic user. Thankfully, there are a limited number of commands that we need to support. */
	if (!strcasecmp(command, "PRIVMSG")) { /* List this as high up as possible, since this is the most common command */
		handle_privmsg(user, s, 0);
	} else if (!strcasecmp(command, "NOTICE")) {
		handle_privmsg(user, s, 1);
	} else if (!strcasecmp(command, "JOIN")) {
		join_channel(user, s); /* ChanServ and programmatic users will only join one channel at a time */
	} else if (!strcasecmp(command, "PART")) {
		leave_channel(user, s);
	/* Note that there is no QUIT handling here.
	 * Programmatic users do not use QUIT and get freed using the appropriate interface,
	 * e.g. irc_user_destroy or irc_chanserv_unregister. */
	} else if (!strcasecmp(command, "MODE")) {
		handle_modes(user, s);
	} else if (!strcasecmp(command, "TOPIC")) {
		handle_topic(user, s);
	} else if (!strcasecmp(command, "INVITE")) {
		handle_invite(user, s);
	} else {
		bbs_error("Command '%s' is unsupported for programmatic users\n", command);
		return -1;
	}
	return 0;
}

int chanserv_exec(char *s)
{
	/*! \note In theory, ChanServ could probably be written to use the programmatic user interface,
	 * which didn't exist before, but since ChanServ needs to be handled specially in many places,
	 * it also makes sense to keep it as is. */
	struct irc_user *user = &user_chanserv;
	if (!chanserv_registered) {
		bbs_error("ChanServ is not currently registered\n");
		return -1;
	}
	return irc_user_exec(user, s);
}

/*! \brief Callback that allows other parts of the BBS to send a message to a user via IRC */
static int alertmsg(unsigned int userid, const char *msg)
{
	char username[48];
	int res = -1;

	if (!bbs_username_from_userid(userid, username, sizeof(username))) {
		char dup[512];
		safe_strncpy(dup, msg, sizeof(dup));
		res = privmsg(&user_messageserv, username, 1, dup); /* Send a NOTICE to the user */
	}
	return res;
}

static int ping_alertpipe[2] = { -1, -1 };

/* The threading model here is pretty basic.
 * We have one thread per client.
 * Each of these threads will wait for activity from the client.
 * Messages are relayed to all participants in the channel when a client sends a message,
 * which is fine since we can read/write to sockets independently (with the appropriate locking, of course).
 * There are no separate threads for channels. The only other thread that exists is the periodic ping thread.
 *
 * In theory, we don't need one thread per client.
 * We could poll all the clients and handle activity as we get them, in a single thread.
 * However, the current node threading model expects a unique thread per node,
 * and admittedly this is simpler so that's how it is for now. But this is certainly a potential future improvement.
 *
 * TL;DR This IRC server uses N+1 threads, where N is the number of clients connected.
 */

/*! \todo RFC 1459 4.6.2 says a PING is sent... if no other activity detected from a connection.
 * This means we don't actually need this separate thread to ping clients at all, handle_client can send PINGs if the poll timeout expires,
 * with additional logic to disconnect if nothing further is heard afterwards. */
static void ping_client(struct irc_user *user, time_t now)
{
	irc_other_thread_writef(user->node, "PING :%" TIME_T_FMT "\r\n", now);
	user->lastping = now;
	gettimeofday(&user->lastping_us, NULL);
}

/*! \brief Thread to periodically ping all clients and dump any that don't respond with a pong back in time */
static void *ping_thread(void *unused)
{
	struct irc_user *user;

	UNUSED(unused);

	for (;;) {
		time_t now;
		int clients = 0;
		if (bbs_alertpipe_poll(ping_alertpipe, PING_TIME)) {
			break;
		}

		now = time(NULL);
		RWLIST_RDLOCK(&users);
		RWLIST_TRAVERSE(&users, user, entry) {
			if (user->programmatic) {
				continue; /* No need to ping programmatic clients */
			}
			if (need_restart || (user->lastping && user->lastpong < now - 2 * PING_TIME)) {
				char buf[32] = "";
				/* Client never responded to the last ping. Disconnect it. */
				if (!need_restart && user->lastpong) {
					bbs_debug(3, "Ping expired for %p: last ping=%" TIME_T_FMT ", last pong=%" TIME_T_FMT " (now %" TIME_T_FMT ")\n", user, user->lastping, user->lastpong, now);
					snprintf(buf, sizeof(buf), "Ping timeout: %" TIME_T_FMT " seconds", now - user->lastpong); /* No CR LF */
				}
				leave_all_channels(user, "QUIT", need_restart ? "Server restart" : buf);
				if (!need_restart) {
					send_reply(user, "ERROR :Connection timeout\r\n");
				}
				bbs_debug(5, "Shutting down client on node %d\n", user->node->id);
				bbs_socket_shutdown(user->node->fd); /* Make the client handler thread break */
			} else {
				ping_client(user, now);
				clients++;
			}
		}
		RWLIST_UNLOCK(&users);
		if (clients) {
			bbs_debug(5, "Performed periodic ping of %d client%s\n", clients, ESS(clients));
		}
		if (need_restart) {
			static char file_without_ext[] = __FILE__;
			bbs_strterm(file_without_ext, '.'); /* There's no macro like __FILE__ w/o ext, so this is what we gotta do. */
			bbs_debug(1, "Ping thread exiting due to pending restart\n");
			/* Okay, at this point, all the users should be kicked and gone.
			 * There shouldn't be any users left of this module.
			 * Now, request the BBS core unload and load us again. */
			bbs_request_module_unload(file_without_ext, need_restart - 1);
			break;
		}
	}
	return NULL;
}

static int cli_irc_users(struct bbs_cli_args *a)
{
	struct irc_user *user;
	char modes[53];
	int i = 0;
	time_t now = time(NULL);

	bbs_dprintf(a->fdout, "%3s %2s %4s %-20s %4s %4s %-15s %-20s %s\n", "#", "Op", "Node", "User", "Ping", "Lag", "Modes", "Nick", "Hostmask");
	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, user, entry) {
		char hostmask[128];
		char node_id[15];
		char pingbuf[20];
		char lagbuf[20]; /* min size possible */
		time_t ping = user->lastpong ? now - user->lastpong : -1;
		++i;
		get_user_modes(modes, sizeof(modes), user);
		if (IS_REAL_USER(user)) {
			snprintf(node_id, sizeof(node_id), "%d", user->node->id);
		} else {
			strcpy(node_id, "-");
		}
		snprintf(hostmask, sizeof(hostmask), HOSTMASK_FMT, HOSTMASK_ARGS(user));
		if (user->lastpong) {
			int lag_sec = user->lag / 1000;
			snprintf(lagbuf, sizeof(lagbuf), "%01d.%02d", lag_sec, (user->lag - (lag_sec * 1000)) / 10);
		} else {
			strcpy(lagbuf, "-");
		}
		if (ping != -1) {
			snprintf(pingbuf, sizeof(pingbuf), "%" TIME_T_FMT, ping);
		} else {
			strcpy(pingbuf, "-");
		}
		bbs_dprintf(a->fdout, "%3d %2s %4s %-20s %4s %4s %-15s %-20s %s\n",
			i, user->modes & USER_MODE_OPERATOR ? "*" : "", node_id, user->username, pingbuf, lagbuf, modes, user->nickname, hostmask);
	}
	RWLIST_UNLOCK(&users);
	bbs_dprintf(a->fdout, "%d user%s online\n", i, ESS(i));
	return 0;
}

static int cli_irc_whowas(struct bbs_cli_args *a)
{
	struct whowas *w;

	bbs_dprintf(a->fdout, "%-30s %s\n", "Joined", "WHOWAS");
	RWLIST_RDLOCK(&whowas_users);
	RWLIST_TRAVERSE(&whowas_users, w, entry) {
		char timebuf[56];
		struct tm logdate;
		localtime_r(&w->joined, &logdate);
		strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M %P %Z", &logdate);
		bbs_dprintf(a->fdout, "%-30s %s\n", timebuf, w->who);
	}
	RWLIST_UNLOCK(&whowas_users);
	return 0;
}

static int cli_irc_channels(struct bbs_cli_args *a)
{
	int i = 0;
	char modes[53];
	struct irc_channel *channel;

	bbs_dprintf(a->fdout, "%-20s %15s %4s %3s %-20s %s\n", "Channel", "Priv Owner (+)", "Mbrs", "Rly", "Modes", "Topic");
	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		get_channel_modes(modes, sizeof(modes), channel);
		bbs_dprintf(a->fdout, "%-20s %15s %4d %3s %-20s %s\n", channel->name, S_IF(channel->username), channel->membercount, BBS_YN(channel->relay), modes, S_IF(channel->topic));
		i++;
	}
	RWLIST_UNLOCK(&channels);
	bbs_dprintf(a->fdout, "%d channel%s\n", i, ESS(i));
	return 0;
}

static int cli_irc_members(struct bbs_cli_args *a)
{
	int i = 0;
	char modes[53];
	struct irc_member *member;
	struct irc_channel *channel = get_channel(a->argv[2]); /* get_channel is fine, since private namespace channels would only have 1 user (maybe multiple nicks/nodes) in it */

	if (!channel) {
		bbs_dprintf(a->fdout, "No such channel: %s\n", a->argv[2]);
		return -1;
	}

	bbs_dprintf(a->fdout, "%4s %-20s %-20s %s\n", "Node", "Modes", "Nick", "Hostmask");
	RWLIST_RDLOCK(&channel->members);
	RWLIST_TRAVERSE(&channel->members, member, entry) {
		get_channel_user_modes(modes, sizeof(modes), member);
		if (IS_REAL_USER(member->user)) {
			bbs_dprintf(a->fdout, "%4d %-20s %-20s %s\n", member->user->node->id, modes, member->user->nickname, member->user->hostname);
		} else {
			bbs_dprintf(a->fdout, "%4s %-20s %-20s %s\n", "", modes, member->user->nickname, member->user->hostname);
		}
		i++;
	}
	RWLIST_UNLOCK(&channel->members);
	bbs_dprintf(a->fdout, "%d member%s in channel %s\n", i, ESS(i), a->argv[2]);
	return 0;
}

static struct bbs_cli_entry cli_commands_irc[] = {
	BBS_CLI_COMMAND(cli_irc_users, "irc users", 2, "List all IRC users", NULL),
	BBS_CLI_COMMAND(cli_irc_whowas, "irc whowas", 2, "List all former IRC users", NULL),
	BBS_CLI_COMMAND(cli_irc_channels, "irc chans", 2, "List all IRC channels", NULL),
	BBS_CLI_COMMAND(cli_irc_members, "irc members", 3, "List all members in an IRC channel", "irc members <channel>"),
};

struct irc_user *irc_user_create(enum user_modes modes)
{
	struct irc_user *user;

	if (need_restart) {
		return NULL; /* Reject new connections. */
	}

	if (require_chanserv && !chanserv_registered) {
		bbs_warning("Received IRC client connection prior to ChanServ initialization, rejecting\n");
		return NULL;
	}

	user = calloc(1, sizeof(*user));
	if (ALLOC_FAILURE(user)) {
		return NULL;
	}
	bbs_mutex_init(&user->lock, NULL);

	user->joined = time(NULL);
	user->modes = USER_MODE_NONE;
	user->modes |= (USER_MODE_WALLOPS | modes); /* Receive wallops by default */

	user->programmatic = 1;
	return user;
}

void irc_user_destroy(struct irc_user *user)
{
	leave_all_channels(user, "QUIT", "Bouncer closed the connection"); /* Silently leave any channels we're still in */
	unlink_user(user); /* Remove from the users list */
	user_free(user);
}

int irc_user_set_identity(struct irc_user *user, const char *username, const char *nickname, const char *realname, const char *hostname)
{
	if (set_or_default_nickname(user, nickname, NULL, 0)) {
		return -1;
	}
	REPLACE(user->username, username);
	REPLACE(user->realname, realname);
	REPLACE(user->hostname, hostname);
	if (!user->username || !user->nickname || !user->realname || !user->hostname) {
		return -1;
	}
	/* Register the user so it's in the users list */
	if (!user->registered) {
		add_user(user);
	}
	return 0;
}

int irc_user_set_nickname(struct irc_user *user, const char *nickname)
{
	return set_nickname(user, nickname, NULL, 0);
}

/*! \brief Thread to handle a single IRC/IRCS client */
static void irc_handler(struct bbs_node *node, int secure)
{
	struct irc_user *user = irc_user_create(USER_MODE_NONE);

	if (!user) {
		return;
	}
	user->programmatic = 0; /* Defaults to 1, so overwrite for real users */

	/* Start TLS if we need to */
	if (secure && bbs_node_starttls(node)) {
		free(user);
		return;
	}

	user->node = node;
	user->hostname = strdup(node->ip);
	if (secure) {
		user->modes |= USER_MODE_SECURE;
	}

	handle_client(user);
	user_free(user);
}

static void *__irc_handler(void *varg)
{
	struct bbs_node *node = varg;

	bbs_node_net_begin(node);
	irc_handler(node, !strcmp(node->protname, "IRCS") ? 1 : 0); /* Actually handle the IRC/IRCS client */
	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

	cfg = bbs_config_load("net_irc.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "logchannels", &log_channels);
	bbs_config_val_set_true(cfg, "general", "requiresasl", &require_sasl);
	bbs_config_val_set_true(cfg, "general", "requirechanserv", &require_chanserv);
	irc_hostname[0] = '\0';
	bbs_config_val_set_str(cfg, "general", "hostname", irc_hostname, sizeof(irc_hostname));
	motd_file[0] = '\0';
	bbs_config_val_set_str(cfg, "general", "motdfile", motd_file, sizeof(motd_file));
	motd_last_read = 0; /* Force rereading MOTD from disk */

	if (s_strlen_zero(irc_hostname)) {
		safe_strncpy(irc_hostname, bbs_hostname(), sizeof(irc_hostname)); /* Default to BBS hostname */
		if (s_strlen_zero(irc_hostname)) {
			if (bbs_get_local_ip(NULL, irc_hostname, sizeof(irc_hostname))) {
				bbs_error("No IRC or BBS hostname specified, and unable to determine local IP address. Aborting.\n");
				bbs_config_unlock(cfg);
				return -1;
			}
		}
	}

	/* IRC */
	bbs_config_val_set_true(cfg, "irc", "enabled", &irc_enabled);
	bbs_config_val_set_port(cfg, "irc", "port", &irc_port);

	/* IRCS */
	bbs_config_val_set_true(cfg, "ircs", "enabled", &ircs_enabled);
	bbs_config_val_set_port(cfg, "ircs", "port", &ircs_port);

	/* Do this check before we start dynamically allocating memory */
	if (ircs_enabled && !ssl_available()) {
		bbs_error("TLS is not available, IRCS may not be used\n");
		bbs_config_unlock(cfg);
		return -1;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		/* Already processed */
		if (!strcmp(bbs_config_section_name(section), "general") || !strcmp(bbs_config_section_name(section), "irc") || !strcmp(bbs_config_section_name(section), "ircs")) {
			continue;
		}

		if (!strcmp(bbs_config_section_name(section), "opers")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				/* Format is simple:
				 * [opers]
				 * admin=P@ssw0rd
				 *
				 * Currently doesn't allow specifying host/range(s), more granular permissions, etc.
				 */
				const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
				add_operator(key, value);
			}
		} else if (!strcmp(bbs_config_section_name(section), "nativeopers")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				const char *key = bbs_keyval_key(keyval);
				add_operator(key, NULL);
			}
		}
	}

	bbs_config_unlock(cfg);
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!irc_enabled && !ircs_enabled) {
		bbs_debug(3, "Neither IRC nor IRCS is enabled, declining to load\n");
		goto decline; /* Nothing is enabled */
	}

	bbs_mutex_init(&motd_lock, NULL);
	loadtime = time(NULL);

	if (bbs_alertpipe_create(ping_alertpipe)) {
		goto decline;
	}

	if (bbs_pthread_create(&irc_ping_thread, NULL, ping_thread, NULL)) {
		bbs_error("Unable to create IRC ping thread.\n");
		bbs_alertpipe_close(ping_alertpipe);
		goto decline;
	}

	if (bbs_start_tcp_listener3(irc_enabled ? irc_port : 0, ircs_enabled ? ircs_port : 0, 0, "IRC", "IRCS", NULL, __irc_handler)) {
		bbs_alertpipe_close(ping_alertpipe);
		goto decline;
	}

	bbs_register_alerter(alertmsg, 5);
	bbs_cli_register_multiple(cli_commands_irc);
	return 0;

decline:
	destroy_operators();
	return -1;
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_irc);
	bbs_unregister_alerter(alertmsg);
	bbs_alertpipe_write(ping_alertpipe);
	bbs_pthread_join(irc_ping_thread, NULL);
	if (irc_enabled) {
		bbs_stop_tcp_listener(irc_port);
	}
	if (ircs_enabled) {
		bbs_stop_tcp_listener(ircs_port);
	}
	RWLIST_WRLOCK_REMOVE_ALL(&whowas_users, entry, free);
	destroy_channels();
	destroy_operators();
	bbs_mutex_destroy(&motd_lock);
	free_if(motdstring);
	bbs_alertpipe_close(ping_alertpipe);
	return 0;
}

BBS_MODULE_INFO_FLAGS("RFC1459 Internet Relay Chat Server", MODFLAG_GLOBAL_SYMBOLS);
