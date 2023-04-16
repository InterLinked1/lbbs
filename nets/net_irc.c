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
#include <ctype.h>
#include <signal.h>
#include <unistd.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/stringlist.h"
#include "include/ansi.h"
#include "include/notify.h"

#include "include/net_irc.h"

#define DEFAULT_IRC_PORT 6667
#define DEFAULT_IRCS_PORT 6697

/* Allow this module to use dprintf */
#undef dprintf

#define IRC_SERVER_VERSION BBS_NAME "-" BBS_VERSION "-irc"

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

/* Hostmask stuff */
#define IDENT_PREFIX_FMT "%s!%s@%s"
#define IDENT_PREFIX_ARGS(user) user->nickname, user->username, user->hostname

#define send_reply(user, fmt, ...) bbs_debug(3, "%p <= " fmt, user, ## __VA_ARGS__); pthread_mutex_lock(&user->lock); dprintf(user->wfd, fmt, ## __VA_ARGS__); pthread_mutex_unlock(&user->lock);
#define send_numeric(user, numeric, fmt, ...) send_reply(user, "%03d %s :" fmt, numeric, user->nickname, ## __VA_ARGS__)
#define send_numeric2(user, numeric, fmt, ...) send_reply(user, "%03d %s " fmt, numeric, user->nickname, ## __VA_ARGS__)
#define send_numeric_broadcast(channel, user, numeric, fmt, ...) channel_broadcast(channel, user, "%03d %s " fmt, numeric, irc_hostname, ## __VA_ARGS__)

/*! \note Currently this is a single-server network, so there is no difference in practice between # and & channels. */
/*! \todo Make this IRC network daemon multi-server capable somehow? Perhaps linkable with other servers running the same IRC module? Would also allow sharing state... */
#define IS_CHANNEL_NAME(s) (*s == '#' || *s == '&')
#define VALID_CHANNEL_NAME(s) (!strlen_zero(s) && IS_CHANNEL_NAME(s))

/*! \todo include irc.h from LIRC, so we can use macro names for numerics, at least */

static int irc_port = DEFAULT_IRC_PORT;
static int ircs_port = DEFAULT_IRCS_PORT;

static pthread_t irc_listener_thread = -1;
static pthread_t irc_ping_thread = -1;

static int irc_enabled = 1, ircs_enabled = 1;
static int irc_socket = -1, ircs_socket = -1;
static int require_sasl = 1;
static int require_chanserv = 1;
static int log_channels = 0;

static int loadtime = 0;
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
	char data[0];
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
	int rfd;						/* Read file descriptor */
	int wfd;						/* Write file descriptor */
	int joined;						/* Time joined */
	int lastactive;					/* Time of last JOIN, PART, PRIVMSG, NOTICE, etc. */
	int lastping;					/* Last ping sent */
	int lastpong;					/* Last pong received */
	pthread_mutex_t lock;			/* User lock */
	char *awaymsg;					/* Away message */
	unsigned int away:1;			/* User is currently away (default is 0, i.e. user is here) */
	unsigned int multiprefix:1;		/* Supports multi-prefix */
	unsigned int registered:1;		/* Fully registered */
	RWLIST_ENTRY(irc_user) entry;	/* Next user */
	/* Avoid using a flexible struct member since we'll probably strdup both the username and nickname beforehand anyways */
};

/*! \brief Static user struct for ChanServ operations */
static struct irc_user user_chanserv = {
	.node = NULL,
	.channelcount = 0,
	.username = "ChanServ",
	.nickname = "ChanServ",
	.realname = "Channel Services",
	.hostname = "services",
	.modes = USER_MODE_OPERATOR, /* Grant ChanServ permissions to do whatever it wants */
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
};

#define IS_SERVICE(user) (user == &user_chanserv || user == &user_messageserv)

static RWLIST_HEAD_STATIC(users, irc_user);	/* Container for all users */

/*! \brief A user in a channel (1:1) */
struct irc_member {
	struct irc_user *user;			/* Reference to user (must be in the users list) */
	enum channel_user_modes modes;	/* User's channel flags (flags for this channel) */
	pthread_mutex_t lock;			/* Member lock */
	RWLIST_ENTRY(irc_member) entry;	/* Next member */
};

RWLIST_HEAD(channel_members, irc_member);

struct irc_channel {
	const char *name;					/* Name of channel */
	unsigned int membercount;			/* Current member count, for constant-time member count access */
	char *password;						/* Channel password */
	char *topic;						/* Channel topic */
	char *topicsetby;					/* Ident of who set the channel topic */
	unsigned int topicsettime;			/* Epoch time of when the topic was last set */
	struct channel_members members;		/* List of users currently in this channel */
	enum channel_modes modes;			/* Channel modes (non-user specific) */
	unsigned int limit;					/* Limit on number of users in channel (only enforced on joins) */
	unsigned int throttleusers;			/* Users allowed to join per interval */
	unsigned int throttleinterval;		/* Throttle interval duration (s) */
	unsigned int throttlebegin;			/* When last throttle interval began */
	unsigned int throttlecount;			/* # of users that joined in the last throttle interval */
	struct stringlist invited;			/* String list of invited nicks */
	FILE *fp;							/* Optional log file to which to log all channel activity */
	RWLIST_ENTRY(irc_channel) entry;	/* Next channel */
	unsigned int relay:1;				/* Enable relaying */
	pthread_mutex_t lock;				/* Channel lock */
	char data[0];						/* Flexible struct member for channel name */
};

static RWLIST_HEAD_STATIC(channels, irc_channel);	/* Container for all channels */

struct irc_relay {
	int (*relay_send)(const char *channel, const char *sender, const char *msg);
	int (*nicklist)(int fd, int numeric, const char *requsername, const char *channel, const char *user);
	int (*privmsg)(const char *recipient, const char *sender, const char *user);
	void *mod;
	RWLIST_ENTRY(irc_relay) entry;
};

static RWLIST_HEAD_STATIC(relays, irc_relay); /* Container for all relays */

static int add_operator(const char *name, const char *password)
{
	struct irc_operator *operator;
	int namelen, pwlen;

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

int irc_relay_register(int (*relay_send)(const char *channel, const char *sender, const char *msg),
	int (*nicklist)(int fd, int numeric, const char *requsername, const char *channel, const char *user),
	int (*privmsg)(const char *recipient, const char *sender, const char *user),
	void *mod)
{
	struct irc_relay *relay;

	RWLIST_WRLOCK(&relays);
	RWLIST_TRAVERSE(&relays, relay, entry) {
		if (relay_send == relay->relay_send) {
			break;
		}
	}
	if (relay) {
		bbs_error("Relay %p is already registered\n", relay_send);
		RWLIST_UNLOCK(&relays);
		return -1;
	}
	relay = calloc(1, sizeof(*relay));
	if (ALLOC_FAILURE(relay)) {
		RWLIST_UNLOCK(&relays);
		return -1;
	}
	relay->relay_send = relay_send;
	relay->nicklist = nicklist;
	relay->privmsg = privmsg;
	relay->mod = mod;
	RWLIST_INSERT_HEAD(&relays, relay, entry);
	bbs_module_ref(BBS_MODULE_SELF); /* Bump our module ref count */
	RWLIST_UNLOCK(&relays);
	return 0;
}

/* No need for a separate cleanup function since this module cannot be unloaded until all relays have unregistered */

int irc_relay_unregister(int (*relay_send)(const char *channel, const char *sender, const char *msg))
{
	struct irc_relay *relay;

	relay = RWLIST_WRLOCK_REMOVE_BY_FIELD(&relays, relay_send, relay_send, entry);
	if (relay) {
		free(relay);
		bbs_module_unref(BBS_MODULE_SELF); /* And decrement the module ref count back again */
	} else {
		bbs_error("Relay %p was not previously registered\n", relay_send);
		return -1;
	}
	return 0;
}

/* ChanServ interface */

static void (*chanserv_privmsg)(const char *username, char *msg);
static void (*chanserv_eventcb)(const char *command, const char *channel, const char *username, const char *data);
static void *chanserv_mod;

#define chanserv_broadcast(cmd, chan, username, data) if (chanserv_eventcb) { chanserv_eventcb(cmd, chan, username, data); }

int irc_chanserv_register(void (*privmsg)(const char *username, char *msg), void (*eventcb)(const char *command, const char *channel, const char *username, const char *data), void *mod)
{
	if (chanserv_mod) {
		bbs_error("ChanServ is already registered\n");
		return -1;
	}
	/* This is the right order for these operations. Use reverse order for unregister. */
	bbs_module_ref(BBS_MODULE_SELF); /* Bump our module ref count */
	chanserv_mod = mod;
	chanserv_privmsg = privmsg;
	chanserv_eventcb = eventcb;
	return 0;
}

int irc_chanserv_unregister(void (*privmsg)(const char *username, char *msg))
{
	if (privmsg != chanserv_privmsg) {
		bbs_error("ChanServ unregistration mismatch\n");
		return -1;
	}
	chanserv_privmsg = NULL;
	chanserv_eventcb = NULL;
	chanserv_mod = NULL;
	bbs_module_unref(BBS_MODULE_SELF);
	return 0;
}

static int chanserv_msg(struct irc_user *user, char *s)
{
	/* There is no mechanism here for writing output back to user.
	 * ChanServ will send a PRIVMSG if it needs to.
	 * It may very well do other things, too. */
	if (chanserv_privmsg) {
		bbs_module_ref(chanserv_mod);
		chanserv_privmsg(user->nickname, s);
		bbs_module_unref(chanserv_mod);
		return 0;
	} else {
		return -1;
	}
}

static int authorized_atleast_bymode(enum channel_user_modes modes, int atleast)
{
	int auth = 0;

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

	return auth;
}

static int authorized_atleast(struct irc_member *member, int atleast)
{
	int auth = 0;

	pthread_mutex_lock(&member->lock);
	auth = authorized_atleast_bymode(member->modes, atleast);
	pthread_mutex_unlock(&member->lock);

	return auth;
}

#define APPEND_MODE(buf, len, modes, mode, letter) if ((modes & mode) && (len-- >= 1)) { buf[pos++] = letter; }

static int get_channel_user_modes(char *buf, size_t len, struct irc_member *member)
{
	int pos = 0;

	pthread_mutex_lock(&member->lock);
	if (!member->modes) {
		pthread_mutex_unlock(&member->lock);
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
	pthread_mutex_unlock(&member->lock);
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

	pthread_mutex_lock(&user->lock);
	if (!user->modes) {
		pthread_mutex_unlock(&user->lock);
		buf[0] = '\0';
		return -1;
	}
	buf[pos++] = '+';
	APPEND_MODE(buf, len, user->modes, USER_MODE_INVISIBLE, 'i');
	APPEND_MODE(buf, len, user->modes, USER_MODE_OPERATOR, 'o');
	APPEND_MODE(buf, len, user->modes, USER_MODE_WALLOPS, 'w');
	APPEND_MODE(buf, len, user->modes, USER_MODE_SECURE, 'Z');
	(void) len; /* Suppress cppcheck whining about len being unused for the last APPEND_MODE call */
	pthread_mutex_unlock(&user->lock);
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
	pthread_mutex_destroy(&user->lock);
	free_if(user->password);
	free_if(user->hostname);
	free_if(user->awaymsg);
	free_if(user->realname);
	free_if(user->username);
	free_if(user->nickname);
	free(user);
}

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

/*! \note This returns a user with no locks */
static struct irc_member *get_member_by_channel_name(struct irc_user *user, const char *channame)
{
	struct irc_channel *channel;
	struct irc_member *member;

	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (!strcmp(channel->name, channame)) {
			break;
		}
	}
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
static struct irc_user *get_user(const char *username)
{
	struct irc_user *user;

	if (!strcasecmp(username, "ChanServ") && chanserv_mod) {
		return &user_chanserv;
	}

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, user, entry) {
		if (!strcasecmp(user->username, username)) {
			break;
		}
	}
	RWLIST_UNLOCK(&users);
	return user;
}

static struct irc_member *get_member_by_username(const char *username, const char *channame)
{
	struct irc_user *user = get_user(username);
	if (!user) {
		return NULL;
	}
	return get_member_by_channel_name(user, channame);
}

/*! \note Mainly exists so that ChanServ can easily get the modes of channel members */
enum channel_user_modes irc_get_channel_member_modes(const char *channel, const char *username)
{
	struct irc_member *member = get_member_by_username(username, channel);
	if (!member) {
		return CHANNEL_USER_MODE_NONE;
	}
	return member->modes;
}

/*! \note This returns a channel with no locks */
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
	struct irc_channel *c = get_channel(channel);
	if (!c) {
		return NULL;
	}
	return c->topic;
}

static int valid_channame(const char *s)
{
	int i = 0;
	while (*s) {
		if (!isalnum(*s) && !(!i && (*s == '#' || *s == '&')) && *s != '-') {
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
	stringlist_empty(&channel->invited);
	pthread_mutex_destroy(&channel->lock);
	if (channel->fp) {
		fclose(channel->fp);
		channel->fp = NULL;
	}
	free_if(channel->password);
	free_if(channel->topicsetby);
	free_if(channel->topic);
	free(channel);
}

static void destroy_channels(void)
{
	struct irc_channel *channel;

	RWLIST_WRLOCK(&channels);
	while ((channel = RWLIST_REMOVE_HEAD(&channels, entry))) {
		struct irc_member *member;
		RWLIST_WRLOCK(&channel->members); /* Kick any members still present */
		while ((member = RWLIST_REMOVE_HEAD(&channel->members, entry))) {
			channel->membercount -= 1;
			free(member);
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

/*!
 * \brief Send a message to everyone (or almost everyone) in a channel
 * \param channel Channel to which to broadcast
 * \param user A user to which to NOT send the message (typically to prevent echoes of a user's own messages). NULL to really send to everyone.
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
static int __attribute__ ((format (gnu_printf, 5, 6))) __channel_broadcast(int lock, struct irc_channel *channel, struct irc_user *user, enum channel_user_modes minmode, const char *fmt, ...)
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
		/* Careful here... we want member->user, not user */
		pthread_mutex_lock(&member->user->lock); /* Serialize writes to this user */
		write(member->user->wfd, buf, len); /* Use write instead of dprintf, because we already have the length, and it's just a simple string now */
		pthread_mutex_unlock(&member->user->lock);
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
	pthread_mutex_lock(&user->lock);
	user->lastactive = time(NULL);
	pthread_mutex_unlock(&user->lock);
}

/*! \param user Should be NULL for "system" generated messages and provided for messages actually sent by that user. */
static void relay_broadcast(struct irc_channel *channel, struct irc_user *user, const char *username, const char *buf, void *sendingmod)
{
	/* Now, relay it to any other external integrations that may exist. */
	struct irc_relay *relay;

	if (channel->relay) {
		RWLIST_RDLOCK(&relays);
		RWLIST_TRAVERSE(&relays, relay, entry) {
			if (sendingmod == relay->mod) {
				/* Don't relay messages from a module back to itself! */
#ifdef EXTRA_DEBUG
				bbs_debug(8, "Not relaying message back to module %p\n", sendingmod);
#endif
				continue;
			}
			bbs_module_ref(relay->mod);
			if (relay->relay_send(channel->name, user ? user->nickname : username ? username : NULL, buf)) {
				bbs_module_unref(relay->mod);
				break;
			}
			bbs_module_unref(relay->mod);
		}
		RWLIST_UNLOCK(&relays);
	}
}

int _irc_relay_raw_send(const char *channel, const char *msg, void *mod)
{
	struct irc_channel *c = get_channel(channel);
	if (!c) {
		return -1;
	}
	channel_broadcast_nolock(c, NULL, "%s\r\n", msg);
	if (c->relay) {
		relay_broadcast(c, NULL, NULL, msg, mod);
	}
	return 0;
}

/*! \brief Somewhat condensed version of privmsg, for relay integration */
int _irc_relay_send(const char *channel, enum channel_user_modes modes, const char *relayname, const char *sender, const char *msg, void *mod)
{
	char hostname[84];
	struct irc_channel *c;
	enum channel_user_modes minmode = CHANNEL_USER_MODE_NONE;

	/*! \todo need to respond with appropriate numerics here */
	if (strlen_zero(msg)) {
		return -1;
	}
	if (strlen(msg) >= 510) { /* Include CR LF */
		return -1;
	}

	snprintf(hostname, sizeof(hostname), "%s/%s", relayname, sender);

	/* It's not our job to filter messages, clients can do that. For example, decimal 1 is legitimate for CTCP commands. */

	if (!IS_CHANNEL_NAME(channel)) {
		struct irc_user *user2 = get_user(channel);
		/* Private message to another user. This is super simple, there's no other overhead or anything involved. */
		if (!user2) {
			bbs_debug(7, "No such user: %s\n", channel);
			return -1;
		}
		pthread_mutex_lock(&user2->lock); /* Serialize writes to this user */
		dprintf(user2->wfd, ":" IDENT_PREFIX_FMT " %s %s :%s\r\n", sender, relayname, hostname, "PRIVMSG", user2->nickname, msg);
		pthread_mutex_unlock(&user2->lock);
		/* Don't care if user is away in this case */
		return 0;
	}

	/*! \todo simplify using get_channel, get_member? But then we may have more locking issues... */
	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, c, entry) {
		if (!strcmp(c->name, channel)) {
			break;
		}
	}
	RWLIST_UNLOCK(&channels);
	if (!c) {
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

	channel_broadcast_selective(c, NULL, minmode, ":" IDENT_PREFIX_FMT " %s %s :%s\r\n", sender, relayname, hostname, "PRIVMSG", c->name, msg);
	relay_broadcast(c, NULL, sender, msg, mod);
	return 0;
}

static void nickserv(struct irc_user *user, char *s);

static int privmsg(struct irc_user *user, const char *channame, int notice, const char *message)
{
	struct irc_channel *channel;
	struct irc_member *m;
	char stripbuf[513];
	int msglen;
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

	/* XXX Could be multiple channels, comma-separated (not currently supported) */

	if (!notice && !strcasecmp(channame, "ChanServ")) {
		if (!chanserv_msg(user, (char*) message)) {
			return 0;
		} /* else, fall through to IS_CHANNEL_NAME so we can send a 401 response. */
	} else if (!notice && !strcasecmp(channame, "NickServ")) {
		nickserv(user, (char*) message);
		return 0;
	}
	if (!IS_CHANNEL_NAME(channame)) {
		struct irc_user *user2 = get_user(channame);
		/* Private message to another user. This is super simple, there's no other overhead or anything involved. */
		if (!user2) {
			struct irc_relay *relay;
			/* Check if the user exists in any callbacks. */
			RWLIST_RDLOCK(&relays);
			RWLIST_TRAVERSE(&relays, relay, entry) {
				if (!relay->privmsg) {
					continue;
				}
				bbs_module_ref(relay->mod);
				if (relay->privmsg(channame, user->nickname, message)) {
					bbs_module_unref(relay->mod);
					break;
				}
				bbs_module_unref(relay->mod);
			}
			RWLIST_UNLOCK(&relays);
			if (!relay) { /* Didn't exist in a relay either */
				send_numeric2(user, 401, "%s :No such nick/channel\r\n", channame);
				return -1;
			}
		} else {
			pthread_mutex_lock(&user2->lock); /* Serialize writes to this user */
			dprintf(user2->wfd, ":" IDENT_PREFIX_FMT " %s %s :%s\r\n", IDENT_PREFIX_ARGS(user), notice ? "NOTICE" : "PRIVMSG", user2->nickname, message);
			pthread_mutex_unlock(&user2->lock);
			if (user2->away) {
				send_numeric(user, 301, "%s :%s\r\n", user2->nickname, S_IF(user2->awaymsg));
			}
		}
		return 0;
	}

	/*! \todo simplify using get_channel, get_member? But then we may have more locking issues... */
	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (!strcmp(channel->name, channame)) {
			break;
		}
	}
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

	if (channel->modes & CHANNEL_MODE_MODERATED && !authorized_atleast(m, CHANNEL_USER_MODE_VOICE)) {
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
	channel_broadcast_selective(channel, user, minmode, ":" IDENT_PREFIX_FMT " %s %s :%s\r\n", IDENT_PREFIX_ARGS(user), notice ? "NOTICE" : "PRIVMSG", channel->name, message);
	if (channel->relay && !notice) {
		relay_broadcast(channel, user, NULL, message, NULL);
	}
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
	if (!user) {
		send_numeric2(user, 401, "%s :No such nick/channel\r\n", ""); /* Whoops */
		return -1;
	}
	get_user_modes(usermode, sizeof(usermode), user);
	send_reply(user, ":%s MODE %s :%s\r\n", user->nickname, user->nickname, usermode);
	return 0;
}

#define SET_MODE(modes, set, mode) \
	if (set && !(modes & mode)) { \
		bbs_debug(6, "Set mode %s\n", #mode); \
		modes |= mode; \
		changed++; \
	} else if (!set && modes & mode) { \
		bbs_debug(6, "Cleared mode %s\n", #mode); \
		modes &= ~mode; \
		changed++; \
	} else { \
		bbs_debug(6, "Not %sting mode %s (no change)\n", set ? "set" : "unset", #mode); \
	}

#define SET_MODE_FORCE(modes, set, mode) \
	if (set) { \
		bbs_debug(6, "Set mode %s\n", #mode); \
		modes |= mode; \
		changed++; \
	} else { \
		bbs_debug(6, "Cleared mode %s\n", #mode); \
		modes &= ~mode; \
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
	channel = get_channel(channel_name);
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
		bbs_debug(3, "User %p requested %s modes for %s: %s\n", user, set ? "set" : "unset", target, channel_name);
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
			targetmember = get_member_by_username(target, channel_name);
		}
		for (modes++; *modes; modes++) { /* Skip the + or - to start */
			char mode = *modes;
			bbs_debug(5, "Requesting %s mode %c for %s (%s)\n", set ? "set" : "unset", mode, target, S_IF(channel_name));
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
						pthread_mutex_lock(&targetmember->lock);
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
						pthread_mutex_unlock(&targetmember->lock);
						if (changed) {
							channel_broadcast(channel, NULL, ":%s MODE %s %c%c %s\r\n", user->nickname, channel->name, set ? '+' : '-', mode, targetmember->user->nickname);
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
							channel->throttleusers = atoi(target);
							channel->throttleinterval = atoi(S_IF(args));
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
							channel_broadcast(channel, NULL, ":%s MODE %s %c%c %s\r\n", user->nickname, channel->name, '+', mode, target);
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
						channel->limit = set ? atoi(target) : 0; /* If this fails, the limit will be 0 (turned off), so not super dangerous... */
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
					channel_broadcast(channel, NULL, ":%s MODE %s %c%c\r\n", user->nickname, channel->name, set ? '+' : '-', mode);
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

static void channel_print_topic(struct irc_user *user, struct irc_channel *channel)
{
	if (channel->topic) {
		if (!user) { /* Broadcast (topic change) */
			send_numeric_broadcast(channel, NULL, 332, "%s :%s\r\n", channel->name, S_IF(channel->topic));
			send_numeric_broadcast(channel, user, 333, "%s %s %d\r\n", channel->name, channel->topicsetby, channel->topicsettime);
		} else {
			send_numeric2(user, 332, "%s :%s\r\n", channel->name, S_IF(channel->topic));
			send_numeric2(user, 333, "%s %s %d\r\n", channel->name, channel->topicsetby, channel->topicsettime);
		}
	} else {
		if (!user) {
			send_numeric_broadcast(channel, user, 331, "%s :No topic is set\r\n", channel->name);
		} else {
			send_numeric2(user, 331, "%s :No topic is set\r\n", channel->name);
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

	channel = get_channel(channame);
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
		m = get_member_by_username(user->nickname, channel->name);
		if (!m || (channel->modes & CHANNEL_MODE_TOPIC_PROTECTED && !authorized_atleast(m, CHANNEL_USER_MODE_HALFOP))) { /* Need at least half op to set the topic, if protected. */
			send_numeric(user, 482, "You're not a channel operator\r\n");
		} else {
			char buf[128];
			REPLACE(channel->topic, s);
			snprintf(buf, sizeof(buf),IDENT_PREFIX_FMT, IDENT_PREFIX_ARGS(user));
			REPLACE(channel->topicsetby, buf);
			channel->topicsettime = time(NULL);
			channel_print_topic(NULL, channel);
			chanserv_broadcast("TOPIC", channel->name, user->nickname, s);
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
	channel = get_channel(channame);
	if (!channel) {
		send_numeric2(user, 403, "%s :No such channel\r\n", channame);
		return;
	}
	member = get_member_by_channel_name(user, channame);
	if (!member) {
		send_numeric(user, 442, "You're not on that channel\r\n");
		return;
	}
	member2 = get_member_by_username(nick, channame);
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
	if (!stringlist_contains(&channel->invited, nick)) {
		stringlist_push(&channel->invited, nick); /* Add nick to invite list so we can keep track of the invite */
	}
	RWLIST_UNLOCK(&channel->invited);

	send_reply(inviteduser, ":" IDENT_PREFIX_FMT " INVITE %s %s\r\n", IDENT_PREFIX_ARGS(user), inviteduser->nickname, channame);
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

	channel = get_channel(channame);
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
	channel_broadcast_selective(channel, NULL, CHANNEL_USER_MODE_OP, ":%s %d %s " IDENT_PREFIX_FMT " :has asked for an invite\r\n", irc_hostname, 710, channel->name, IDENT_PREFIX_ARGS(user)); /* XXX msg is not used, seems there's no place for it in this numeric? */
	send_numeric(user, 711, "Your KNOCK has been delivered.\r\n");
}

static void dump_who(struct irc_user *user, struct irc_user *whouser, struct irc_member *member)
{
	const char *chan = "*"; /* https://modern.ircdocs.horse/#rplwhoreply-352 */
	int hopcount = 0;
	char prefixes[6] = "";
	char userflags[3 + sizeof(prefixes)];

	pthread_mutex_lock(&whouser->lock);
	if (member) {
		if (user->multiprefix) {
			snprintf(prefixes, sizeof(prefixes), MULTIPREFIX_FMT, MULTIPREFIX_ARGS(member));
		} else {
			snprintf(prefixes, sizeof(prefixes), "%s", top_channel_membership_prefix(member));
		}
	}
	snprintf(userflags, sizeof(userflags), "%c%s%s", whouser->away ? 'G' : 'H', whouser->modes & USER_MODE_OPERATOR ? "*" : "", prefixes);
	pthread_mutex_unlock(&whouser->lock);

	send_numeric2(user, 352, "%s %s %s %s %s %s :%d %s\r\n", chan, whouser->username, whouser->hostname, irc_hostname, whouser->nickname, userflags, hopcount, whouser->realname);
}

/*! \brief Whether two users share any IRC channels in common */
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
		RWLIST_RDLOCK(&channel->members);
		RWLIST_TRAVERSE(&channel->members, m, entry) {
			if (m->user == u1) {
				m1 = m;
			} else if (m->user == u2) {
				m2 = m;
			}
		}
		RWLIST_UNLOCK(&channel->members);
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
		struct irc_channel *channel = get_channel(s);
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
			pthread_mutex_lock(&user->lock); /* Lock the user here so the relay module can use dprintf without worrying about race conditions */
			RWLIST_RDLOCK(&relays);
			RWLIST_TRAVERSE(&relays, relay, entry) {
				if (relay->nicklist) {
					bbs_module_ref(relay->mod);
					res = relay->nicklist(user->wfd, 352, user->username, s, NULL);
					bbs_module_unref(relay->mod);
				}
				if (res) {
					break;
				}
			}
			RWLIST_UNLOCK(&relays);
			pthread_mutex_unlock(&user->lock);
		}
	} else {
		struct irc_user *whouser = get_user(s);
		if (whouser && (!opersonly || whouser->modes & USER_MODE_OPERATOR)) {
			dump_who(user, whouser, NULL);
		} else if (!opersonly) { /* Relays don't have any operators */
			/* Check relays, we don't have a channel handle so we don't really know if the user exists in a relay */
			pthread_mutex_lock(&user->lock);
			RWLIST_RDLOCK(&relays);
			RWLIST_TRAVERSE(&relays, relay, entry) {
				if (relay->nicklist) {
					bbs_module_ref(relay->mod);
					res = relay->nicklist(user->wfd, 352, user->username, NULL, s);
					bbs_module_unref(relay->mod);
				}
				if (res) {
					break;
				}
			}
			RWLIST_UNLOCK(&relays);
			pthread_mutex_unlock(&user->lock);
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
	int now;
	char umodes[15];
	struct irc_channel *channel;
	struct irc_user *u = get_user(s);
	if (!u) {
		int res = 0;
		struct irc_relay *relay;
		pthread_mutex_lock(&user->lock);
		RWLIST_RDLOCK(&relays);
		RWLIST_TRAVERSE(&relays, relay, entry) {
			if (relay->nicklist) {
				bbs_module_ref(relay->mod);
				res = relay->nicklist(user->wfd, 318, user->username, NULL, s);
				bbs_module_unref(relay->mod);
			}
			if (res) {
				break;
			}
		}
		RWLIST_UNLOCK(&relays);
		pthread_mutex_unlock(&user->lock);
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
						len += snprintf(buf + len, sizeof(buf) - len, "%s" MULTIPREFIX_FMT "%s", len ? " " : "", MULTIPREFIX_ARGS(member), channel->name);
					} else {
						len += snprintf(buf + len, sizeof(buf) - len, "%s%s%s", len ? " " : "", top_channel_membership_prefix(member), channel->name);
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
		send_numeric2(user, 317, "%s %d %d :seconds idle, signon time\r\n", u->nickname, now - u->lastactive, u->joined);
	}
	if (user->modes & USER_MODE_SECURE) {
		send_numeric2(user, 671, "%s :is using a secure connection\r\n", u->nickname);
	}
	send_numeric2(user, 318, "%s :End of /WHOIS list\r\n", s); /* case must be preserved, so use s instead of u->nickname */
}

static void handle_userhost(struct irc_user *user, char *s)
{
	char buf[256];
	struct irc_user *u = get_user(s);
	if (!u) {
		send_numeric2(user, 401, "%s :No such nick/channel\r\n", s);
		return;
	}
	pthread_mutex_lock(&u->lock);
	snprintf(buf, sizeof(buf), "%s %s = %c %s %s", u->nickname, u->modes & USER_MODE_OPERATOR ? "*" : "", u->away ? '-' : '+', S_IF(u->awaymsg), u->hostname);
	pthread_mutex_unlock(&u->lock);
	send_numeric(user, 302, "%s\r\n", buf);
}

static void handle_list(struct irc_user *user, char *s)
{
	struct irc_channel *channel;
	unsigned int minmembers = 0, maxmembers = 0;
	unsigned int mintopicage = 0, maxtopicage = 0;
	unsigned int now = time(NULL);
	char *elistcond, *conds;

	conds = s;
	while ((elistcond = strsep(&conds, ","))) {
		if (strlen_zero(elistcond) || strlen_zero(elistcond + 1)) {
			continue;
		}
		switch (*elistcond) {
			/* These are not inclusive */
			case '>':
				minmembers = atoi(elistcond + 1);
				break;
			case '<':
				maxmembers = atoi(elistcond + 1);
				break;
			case 'T':
				elistcond++;
				if (*elistcond == '<' && !strlen_zero(elistcond + 1)) {
					maxtopicage = atoi(elistcond + 1);
				} else if (*elistcond == '>' && !strlen_zero(elistcond + 1)) {
					mintopicage = atoi(elistcond + 1);
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
		/* Remember, the conditions are NOT inclusive. If they are equal, in other words, that is not a match, skip. */
		if (minmembers && channel->membercount <= minmembers) {
			continue;
		} else if (maxmembers && channel->membercount >= maxmembers) {
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
		send_numeric(user, 705, "index AWAY HELP INVITE JOIN KICK LIST MOTD NAMES NOTICE PART PING PONG PRIVMSG QUIT TOPIC USERHOST WHO WHOIS\r\n");
		send_numeric(user, 706, "index :End of /HELP\r\n");
		return;
	}
	/*! \todo add individual command help here */
	send_numeric(user, 524, "I don't know anything about that\r\n");
}

static void hostmask(struct irc_user *user)
{
	char mask[32];
	/* Replace hostname with host mask, since nobody actually wants his or her location publicly shared */
	snprintf(mask, sizeof(mask), "node/%d", user->node->id);
	bbs_debug(6, "Changing hostmask for node %d from %s to %s\n", user->node->id, user->hostname, mask);
	REPLACE(user->hostname, mask);
}

static int add_user(struct irc_user *user)
{
	struct irc_user *u;

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

	if (bbs_user_is_registered(user->node->user)) {
		hostmask(user); /* Cloak the user before adding to users list, so our IP doesn't leak on WHO/WHOIS */
	}

	RWLIST_WRLOCK(&users);
	RWLIST_TRAVERSE(&users, u, entry) {
		if (!strcasecmp(u->nickname, user->nickname)) {
			break;
		}
	}
	if (u) {
		send_numeric(user, 433, "Nickname is already in use\r\n");
		RWLIST_UNLOCK(&users);
		return -1;
	}
	user->registered = 1;
	RWLIST_INSERT_HEAD(&users, user, entry);
	RWLIST_UNLOCK(&users);
	return 0;
}

static void broadcast_nick_change(struct irc_user *user, const char *oldnick)
{
	struct irc_channel *channel;
	struct irc_member *member;

	RWLIST_RDLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
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

static void handle_nick(struct irc_user *user, char *s)
{
	if (user->node->user && strcasecmp(s, bbs_username(user->node->user))) {
		/* Don't allow changing nick if already logged in, unless it's to our actual username. */
		send_numeric(user, 902, "You must use a nick assigned to you\r\n");
	} else if (bbs_user_exists(s)) {
		send_numeric(user, 433, "%s :Nickname is already in use.\r\n", s);
		send_reply(user, "NOTICE AUTH :*** This nickname is registered. Please choose a different nickname, or identify using NickServ\r\n");
		/* Client will need to send NS IDENTIFY <password> or PRIVMSG NickServ :IDENTIFY <password> */
	} else { /* Nickname is not claimed. It's fine. */
		char oldnick[64] = "";
		char *newnick = strdup(s);

		if (ALLOC_FAILURE(newnick)) {
			return;
		}
		/* Now, the nick change can't fail. */
		RWLIST_WRLOCK(&users);
		bbs_debug(5, "Nickname changed from %s to %s\n", user->nickname, s);
		if (user->nickname) {
			safe_strncpy(oldnick, user->nickname, sizeof(oldnick));
			free_if(user->nickname);
		}
		user->nickname = newnick;
		RWLIST_UNLOCK(&users);
		if (!s_strlen_zero(oldnick)) {
			send_reply(user, ":%s NICK %s\r\n", oldnick, user->nickname);
			broadcast_nick_change(user, oldnick); /* XXX Won't actually traverse, if registered users aren't allowed to change nicks? */
		}
	}
}

static void handle_identify(struct irc_user *user, char *s)
{
	int res;
	char *username, *pw;

	username = strsep(&s, " ");
	pw = s;
	if (!username) {
		send_numeric(user, 461, "Not enough parameters\r\n");
		return;
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
			REPLACE(user->nickname, username);
		}
		if (!user->registered) {
			add_user(user);
		} else {
			hostmask(user);
		}
		send_numeric(user, 900, IDENT_PREFIX_FMT " %s You are now logged in as %s\r\n", IDENT_PREFIX_ARGS(user), user->username, user->username);
	}
}

static void nickserv(struct irc_user *user, char *s)
{
	char *target = strsep(&s, " ");

	/* This is all we need from NickServ, we don't need "it" to handle registration or anything else */
	if (!strcasecmp(target, "IDENTIFY")) {
		if (!user->registered || !bbs_user_is_registered(user->node->user)) {
			handle_identify(user, s);
		} else {
			send_reply(user, "NOTICE AUTH :*** Nickname change not supported.\r\n");
		}
	/* LOGOUT is not supported, since we need all users in the users list to have a name */
	} else {
		bbs_debug(3, "Unsupported NickServ command: %s\n", target);
		send_reply(user, "NOTICE AUTH :*** NickServ does not support registration on this server. Please register interactively via a terminal session.\r\n");
	}
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

	RWLIST_RDLOCK(&channel->members);
	RWLIST_TRAVERSE(&channel->members, member, entry) {
		if ((member->user->modes & USER_MODE_INVISIBLE) && !channels_in_common(member->user, user)) {
			continue; /* Hide from NAMES */
		}
		if (user->multiprefix) {
			len += snprintf(buf + len, sizeof(buf) - len, "%s" MULTIPREFIX_FMT "%s", len ? " " : "", MULTIPREFIX_ARGS(member), member->user->nickname);
		} else {
			len += snprintf(buf + len, sizeof(buf) - len, "%s%s%s", len ? " " : "", top_channel_membership_prefix(member), member->user->nickname);
		}
		if (len >= 400) { /* Stop well short of the 512 character message limit and clear the buffer */
			len = 0;
			send_numeric2(user, 353, "%s %s :%s\r\n", symbol, channel->name, buf);
		}
	}
	RWLIST_UNLOCK(&channel->members);
	if (len > 0) { /* Last one */
		send_numeric2(user, 353, "%s %s :%s\r\n", symbol, channel->name, buf);
	}
	if (channel->relay) {
		int res = 0;
		struct irc_relay *relay;
		RWLIST_RDLOCK(&relays);
		pthread_mutex_lock(&user->lock);
		RWLIST_TRAVERSE(&relays, relay, entry) {
			if (relay->nicklist) {
				bbs_module_ref(relay->mod);
				res = relay->nicklist(user->wfd, 353, user->username, channel->name, NULL);
				bbs_module_unref(relay->mod);
			}
			if (res) {
				break;
			}
		}
		pthread_mutex_unlock(&user->lock);
		RWLIST_UNLOCK(&relays);
	}
	send_numeric2(user, 366, "%s :End of /NAMES list.\r\n", channel->name);
	return 0;
}

static int join_channel(struct irc_user *user, char *name)
{
	struct irc_channel *channel;
	struct irc_member *member, *m;
	int newchan = 0;
	char modestr[16];
	int chanlen = strlen(name);
	char *password;

	password = strchr(name, ' ');
	if (password) {
		*password++ = '\0';
	}

	/* Nip junk right in the bud before we even bother locking the list */
	if (!VALID_CHANNEL_NAME(name) || chanlen > MAX_CHANNEL_LENGTH || !valid_channame(name)) {
		send_numeric(user, 479, "Illegal channel name\r\n");
		return 0;
	}

	if (user->channelcount > MAX_CHANNELS) {
		send_numeric2(user, 405, "%s :You have joined too many channels\r\n", name);
		return 0;
	}

	/* We might potentially create a channel, so grab a WRLOCK from the get go */
	RWLIST_WRLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (!strcmp(channel->name, name)) {
			break;
		}
	}
	if (!channel) {
		bbs_debug(3, "Creating channel '%s' for the first time\n", name);
		newchan = 1;
		channel = calloc(1, sizeof(*channel) + chanlen + 1);
		if (ALLOC_FAILURE(channel)) {
			RWLIST_UNLOCK(&channels);
			return -1;
		}
		strcpy(channel->data, name); /* Safe */
		channel->name = channel->data;
		channel->modes = CHANNEL_MODE_NONE;
		/* Set some default flags. */
		channel->modes |= CHANNEL_MODE_NO_EXTERNAL | CHANNEL_MODE_TOPIC_PROTECTED;
		if (user->node && bbs_user_is_registered(user->node->user)) {
			channel->modes |= CHANNEL_MODE_REGISTERED_ONLY;
		}
		channel->fp = NULL;
		pthread_mutex_init(&channel->lock, NULL);
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
			RWLIST_UNLOCK(&channels);
			/* Channel requires secure connections, but user isn't using one. Reject. */
			send_numeric(user, 477, "Cannot join channel (+S) - you need to use a secure connection\r\n"); /* XXX This is not the right numeric code, what is? */
			return -1;
		}
		if (channel->modes & CHANNEL_MODE_REGISTERED_ONLY && user->node && !bbs_user_is_registered(user->node->user)) {
			RWLIST_UNLOCK(&channels);
			send_numeric(user, 477, "Cannot join channel (+r) - you need to be logged into your account\r\n");
			return -1;
		}
		if (channel->modes & CHANNEL_MODE_PASSWORD && !strlen_zero(channel->password) && (strlen_zero(password) || strcmp(password, channel->password))) {
			RWLIST_UNLOCK(&channels);
			send_numeric(user, 475, "Cannot join channel (+k) - bad key\r\n");
			return -1;
		}
		if (channel->modes & CHANNEL_MODE_LIMIT && channel->limit && channel->membercount >= channel->limit) {
			RWLIST_UNLOCK(&channels);
			send_numeric(user, 471, "Cannot join channel (+l) - channel is full, try again later\r\n");
			return -1;
		}
		if (channel->modes & CHANNEL_MODE_THROTTLED && channel->throttleusers > 0 && channel->throttleinterval > 0) {
			unsigned int now = time(NULL);

			pthread_mutex_lock(&channel->lock);
			if (channel->throttlebegin < now - channel->throttleinterval) {
				/* It's been at least the entire interval at this point, so start fresh. */
				channel->throttlebegin = now;
				channel->throttlecount = 1; /* Reset, but then add us, so set directly to 1 */
				pthread_mutex_unlock(&channel->lock);
				/* We're allowed to proceed. */
			} else {
				if (channel->throttlecount >= channel->throttleusers) {
					pthread_mutex_unlock(&channel->lock);
					RWLIST_UNLOCK(&channels);
					send_numeric(user, 480, "Cannot join channel (+j) - throttle exceeded, try again later\r\n");
					return -1;
				}
				channel->throttlecount += 1;
				pthread_mutex_unlock(&channel->lock);
			}
		}
	}

	/* Check if we're already in the channel */
	RWLIST_WRLOCK(&channel->members);
	RWLIST_TRAVERSE(&channel->members, m, entry) {
		if (m->user == user) {
			break;
		}
	}
	if (m) {
		send_numeric(user, 714, "You're already on that channel\r\n");
		RWLIST_UNLOCK(&channel->members);
		RWLIST_UNLOCK(&channels);
		return -1;
	}

	if (channel->modes & CHANNEL_MODE_INVITE_ONLY) {
		if (!stringlist_contains(&channel->invited, user->nickname)) {
			RWLIST_UNLOCK(&channel->members);
			RWLIST_UNLOCK(&channels);
			send_numeric(user, 473, "Cannot join channel (+i) - you must be invited\r\n");
			return -1;
		}
	}

	/* Add ourself to the channel members */
	member = calloc(1, sizeof(*member));
	if (ALLOC_FAILURE(member)) {
		RWLIST_UNLOCK(&channel->members);
		if (newchan) {
			channel_free(channel); /* If we just created a new channel but couldn't join it, destroy it, since it has no members. Not yet in the list, so just free directly. */
		}
		RWLIST_UNLOCK(&channels);
		return -1; /* Well this is embarassing, we got this far... but we couldn't make it to the finish line */
	}
	member->user = user;
	member->modes = CHANNEL_USER_MODE_NONE;
	if (newchan) {
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
	channel->membercount += 1;
	user->channelcount += 1;
	RWLIST_UNLOCK(&channel->members);
	RWLIST_UNLOCK(&channels);

	user_setactive(user);

	/* These MUST be in this order: https://modern.ircdocs.horse/#join-message */
	channel_broadcast(channel, NULL, ":" IDENT_PREFIX_FMT " JOIN %s\r\n", IDENT_PREFIX_ARGS(user), channel->name); /* Send join message to everyone, including us */
	if (channel->relay) {
		char joinmsg[92];
		snprintf(joinmsg, sizeof(joinmsg), IDENT_PREFIX_FMT " has joined %s", IDENT_PREFIX_ARGS(user), channel->name);
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

	chanserv_broadcast("JOIN", channel->name, user->nickname, NULL);

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
	RWLIST_WRLOCK(&channels);
	RWLIST_TRAVERSE(&channels, channel, entry) {
		if (!strcmp(channel->name, name)) {
			break;
		}
	}
	if (!channel) { /* Channel doesn't exist */
		RWLIST_UNLOCK(&channels);
		send_numeric2(user, 403, "%s :No such channel\r\n", name);
		return -1;
	}
	RWLIST_WRLOCK(&channel->members);
	RWLIST_TRAVERSE_SAFE_BEGIN(&channel->members, member, entry) {
		if (member->user == user) {
			channel_broadcast_nolock(channel, NULL, ":" IDENT_PREFIX_FMT " PART %s\r\n", IDENT_PREFIX_ARGS(user), channel->name); /* Make sure leaver gets his/her own PART message! */
			if (channel->relay) {
				char partmsg[92];
				snprintf(partmsg, sizeof(partmsg), IDENT_PREFIX_FMT " has left %s", IDENT_PREFIX_ARGS(user), channel->name);
				relay_broadcast(channel, NULL, NULL, partmsg, NULL);
			}
			RWLIST_REMOVE_CURRENT(entry);
			channel->membercount -= 1;
			member->user->channelcount -= 1;
			free(member);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&channel->members);
	if (RWLIST_EMPTY(&channel->members) && !(channel->modes & CHANNEL_MODE_PERMANENT)) {
		remove_channel(channel);
	}
	RWLIST_UNLOCK(&channels);
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
	RWLIST_WRLOCK(&channel->members);
	RWLIST_TRAVERSE_SAFE_BEGIN(&channel->members, member, entry) {
		if (member->user == user) {
			/* If we're leaving ALL channels, don't relay QUIT messages to ourselves. */
			bbs_debug(3, "Dropping user %s from channel %s\n", user->nickname, channel->name);
			RWLIST_REMOVE_CURRENT(entry);
			channel->membercount -= 1;
			member->user->channelcount -= 1;
			free(member);
			/* Already locked, so don't try to recursively lock: */
			channel_broadcast_nolock(channel, user, ":" IDENT_PREFIX_FMT " %s %s :%s\r\n", IDENT_PREFIX_ARGS(user), leavecmd, channel->name, S_IF(message));
			if (channel->relay && !bbs_is_shutting_down()) { /* If BBS shutting down, don't relay a bunch of quit messages */
				char quitmsg[92];
				snprintf(quitmsg, sizeof(quitmsg), IDENT_PREFIX_FMT " has quit %s%s%s%s", IDENT_PREFIX_ARGS(user), channel->name, message ? " (" : "", S_IF(message), message ? ")" : "");
				relay_broadcast(channel, NULL, NULL, quitmsg, NULL);
			}
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&channel->members);
	if (RWLIST_EMPTY(&channel->members) && !(channel->modes & CHANNEL_MODE_PERMANENT)) {
		remove_channel(channel);
	}
}

static void kick_member(struct irc_channel *channel, struct irc_user *kicker, struct irc_user *kicked, const char *message)
{
	struct irc_member *member;

	if (IS_SERVICE(kicked)) {
		send_numeric(kicker, 484, "%s %s :Cannot kick or deop a network service\r\n", kicked->nickname, channel->name);
		return;
	}

	/* If we're going to remove the user, we need a WRLOCK, so grab it from the get go. */
	RWLIST_WRLOCK(&channel->members);
	RWLIST_TRAVERSE_SAFE_BEGIN(&channel->members, member, entry) {
		if (member->user == kicked) {
			/* If we're leaving ALL channels, don't relay QUIT messages to ourselves. */
			bbs_debug(3, "Dropping user %s from channel %s\n", kicked->nickname, channel->name);
			RWLIST_REMOVE_CURRENT(entry);
			channel->membercount -= 1;
			free(member);
			/* Already locked, so don't try to recursively lock: */
			channel_broadcast_nolock(channel, NULL, ":" IDENT_PREFIX_FMT " KICK %s %s :%s\r\n", IDENT_PREFIX_ARGS(kicker), channel->name, kicked->nickname, S_IF(message));
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
	RWLIST_WRLOCK(&channels);
	/* We're going to have to traverse channels to find channels anyways,
	 * so simply traversing them all and seeing if the user is a member of each
	 * isn't as bad when you think about it that way. */
	RWLIST_TRAVERSE_SAFE_BEGIN(&channels, channel, entry) { /* We must use a safe traversal, since drop_member_if_present could cause the channel to be removed if it's now empty */
		drop_member_if_present(channel, user, leavecmd, message);
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&channels);
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

static int motd_last_read = 0;
static pthread_mutex_t motd_lock;

/*! \brief Message of the Day */
static void motd(struct irc_user *user)
{
	send_numeric(user, 375, "- %s Message of the Day -\r\n", irc_hostname);
	send_numeric(user, 372, "- This server powered by the Lightweight Bulletin Board System\r\n");
	send_numeric(user, 372, "- Visit us at %s\r\n", BBS_SOURCE_URL);

	pthread_mutex_lock(&motd_lock);
	if (!s_strlen_zero(motd_file)) { /* Custom MOTD text */
		/* Reread the MOTD from disk at most once an hour. */
		int now = time(NULL);
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
			pthread_mutex_unlock(&motd_lock);
			while ((line = strsep(&lines, "\n"))) {
				if (strlen_zero(line)) {
					continue;
				}
				bbs_strterm(line, '\r'); /* In case using CR LF */
				send_numeric(user, 372, "- %s\r\n", line);
			}
		} else {
			pthread_mutex_unlock(&motd_lock);
			send_numeric(user, 372, "- Welcome to %s chat\r\n", bbs_name());
		}
	} else {
		pthread_mutex_unlock(&motd_lock);
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

	bbs_time_friendly(loadtime, starttime, sizeof(starttime));

	if (user->node->user) {
		add_user(user);
	}

	RWLIST_RDLOCK(&users);
	count = RWLIST_SIZE(&users, u, entry);
	RWLIST_UNLOCK(&users);

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

	if (!user->node->user) {
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
	send_numeric(user, 903, "SASL authentication successful\r\n");
	/* The prefix is nick!ident@host */
	send_numeric(user, 900, IDENT_PREFIX_FMT " %s You are now logged in as %s\r\n", IDENT_PREFIX_ARGS(user), user->username, user->username);
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
	int res, started = 0;
	char buf[513];
	int mcount = 0;
	int sasl_attempted = 0;
	int graceful_close = 0;

	for (;;) {
		char *s, *m = buf;
		res = bbs_fd_poll_read(user->rfd, 2 * PING_TIME, buf, sizeof(buf) - 1); /* Wait up to the ping interval time for something, anything, otherwise disconnect. */
		if (res <= 0) {
			/* Don't set graceful_close to 0 here, since after a QUIT, the client may close the connection first.
			 * The QUIT message should be whatever the client sent, since it was graceful, not connection closed by remote host. */
			bbs_debug(3, "poll/read returned %d\n", res);
			break;
		}
		buf[res] = '\0'; /* Safe */
		/* Messages end in CR LF */
		if (res >= 2 && buf[res - 1] == '\n' && buf[res - 2] == '\r') {
			buf[res - 2] = '\0';
		} else if (buf[res - 1] == '\n') { /* No CR, but did get a LF at the end... okay, weird, but just go with it. */
			buf[res - 1] = '\0';
		} else {
			bbs_warning("Incomplete message from client: %s (ends in %d %d)\n", buf, res >= 2 ? buf[res - 2] : ' ', buf[res - 1]); /* XXX Now what? Continue reading? */
		}
		/* In practice, most IRC clients are nice and buffer any messages they sent to the server on connection,
		 * so dealing with a flood of messages at once that could be read all at once into the buffer isn't super likely.
		 * But it can happen, heck, lirc (the library used by door_irc) does this type of flooding for capability negotiation, first thing.
		 * Assume we could've gotten multiple complete messages, but the last one wasn't split between reads.
		 */
		while ((s = strsep(&m, "\r\n"))) {
			if (strlen_zero(s)) { /* For some reason, every other strsep we do returns an empty string? */
				continue;
			}
			mcount++;
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
							user->nickname = strdup(s);
							bbs_debug(5, "Nickname is %s\n", user->nickname);
						}
					} else if (!strcasecmp(command, "USER")) { /* Whole message is something like 'ambassador * * :New Now Know How' */
						char *realname;
						bbs_debug(5, "Username data is %s\n", s);
						realname = strsep(&s, " ");
						free_if(user->realname);
						user->realname = strdup(realname);
						if (handle_user(user)) {
							break;
						}
						send_reply(user, "CAP * LS :multi-prefix sasl=PLAIN\r\n");
						capnegotiate++;
					} else {
						bbs_warning("Unhandled message: %s %s\n", command, s);
					}
				} else if (capnegotiate == 2) {
					if (!strcmp(s, "CAP REQ :multi-prefix")) { /* See https://ircv3.net/specs/extensions/multi-prefix */
						send_reply(user, "CAP * ACK :multi-prefix\r\n"); /* Colon technically optional, since there's only one capability */
						/* SASL *not* supported */
						/* Don't increment capnegotiate, just wait for the client to send CAP END */
						user->multiprefix = 1;
					} else if (!strcmp(s, "CAP REQ :multi-prefix sasl")) {
						send_reply(user, "CAP * ACK :multi-prefix sasl\r\n");
						capnegotiate++;
						user->multiprefix = 1;
					} else if (!strcmp(s, "CAP REQ :sasl")) {
						send_reply(user, "CAP * ACK :sasl\r\n");
						capnegotiate++;
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
						bbs_warning("Unhandled message: %s\n", s);
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
					pthread_mutex_lock(&user->lock);
					user->lastpong = time(NULL);
					pthread_mutex_unlock(&user->lock);
				} else if (!strcasecmp(command, "PING")) { /* Usually servers ping clients, but clients can ping servers too */
					send_reply(user, "PONG %s\r\n", S_IF(s)); /* Don't add another : because it's still in s, if present. */
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
					bbs_memzero(user->password, strlen(user->password)); /* Destroy password before freeing it */
					free(user->password);
					if (authres) {
						send_numeric(user, 464, "Password incorrect\r\n");
					} else {
						free_if(user->username);
						user->username = strdup(user->nickname);
						add_user(user);
						send_numeric(user, 900, IDENT_PREFIX_FMT " %s You are now logged in as %s\r\n", IDENT_PREFIX_ARGS(user), user->username, user->username);
					}
				/* Any remaining commands require authentication.
				 * The nice thing about this IRC server is we authenticate using the BBS user,
				 * e.g. you don't create accounts using IRC, so we don't need to support guest access at all. */
				} else if (!sasl_attempted && !bbs_user_is_registered(user->node->user) && require_sasl) {
					send_reply(user, "NOTICE AUTH :*** This server requires SASL for authentication. Please reconnect with SASL enabled.\r\n");
					goto quit; /* Disconnect at this point, there's no point in lingering around further. */
				/* We can't necessarily use %s (user->username) instead of %p (user), since if require_sasl == false, we might not have a username still. */
				} else if (!user->node->user) {
					char *target;
					/* Okay to message NickServ without being registered, but nobody else. */
					/* Can be NS IDENTIFY <password> or a regular PRIVMSG */
					if (!strcasecmp(command, "NS")) {
						REQUIRE_PARAMETER(user, s);
						nickserv(user, s);
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
					send_numeric(user, 451, "You have not registered\r\n");
				} else if (!strcasecmp(command, "NS")) { /* NickServ alias */
					nickserv(user, s);
				} else if (!strcasecmp(command, "CS")) { /* ChanServ alias (much like NS ~ NickServ) */
					chanserv_msg(user, s);
				} else if (!strcasecmp(command, "PRIVMSG")) { /* List this as high up as possible, since this is the most common command */
					handle_privmsg(user, s, 0);
				} else if (!strcasecmp(command, "NOTICE")) { /* List this as high up as possible, since this is the most common command */
					handle_privmsg(user, s, 1);
				} else if (!strcasecmp(command, "MODE")) {
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
					leave_all_channels(user, "QUIT", s);
					graceful_close = 1; /* Defaults to 1 anyways, but this is definitely graceful */
					break; /* We're done. */
				} else if (!strcasecmp(command, "AWAY")) {
					if (!strlen_zero(s) && strlen(s) > MAX_AWAY_LEN) {
						send_numeric(user, 416, "Input too large\r\n"); /* XXX Not really the appropriate numeric */
						continue;
					}
					pthread_mutex_lock(&user->lock);
					free_if(user->awaymsg);
					if (!strlen_zero(s)) { /* Away */
						user->awaymsg = strdup(s);
						user->away = 1;
					} else { /* No longer away */
						user->away = 0;
					}
					pthread_mutex_unlock(&user->lock);
					send_numeric(user, user->away ? 306 : 305, "You %s marked as being away\r\n", user->away ? "have been" : "are no longer");
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
						struct irc_channel *kickchan = get_channel(channame);
						if (!kickchan) {
							send_numeric2(user, 403, "%s :No such channel\r\n", channame);
							continue;
						}
						kickuser = get_member_by_username(kickusername, kickchan->name);
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
					shutdown(u->node->fd, SHUT_RDWR); /* Make the client handler thread break */
				} else if (!strcasecmp(command, "INVITE")) {
					handle_invite(user, s);
				} else if (!strcasecmp(command, "KNOCK")) {
					handle_knock(user, s);
				} else if (!strcasecmp(command, "NAMES")) {
					struct irc_channel *channel;
					REQUIRE_PARAMETER(user, s);
					channel = get_channel(s);
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
					handle_whois(user, s);
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
							pthread_mutex_lock(&u->lock); /* Serialize writes to this user */
							dprintf(u->wfd, ":" IDENT_PREFIX_FMT " %s %s :%s\r\n", IDENT_PREFIX_ARGS(user), "WALLOPS", u->nickname, s);
							pthread_mutex_unlock(&u->lock);
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
					bbs_warning("%p: Unhandled message: %s %s\n", user, command, s);
				}
			}
		}
	}

quit:
	if (!graceful_close) {
		leave_all_channels(user, "QUIT", "Remote user closed the connection"); /* poll or read failed */
	}
	if (user->registered) {
		unlink_user(user);
	}
}

int __chanserv_exec(void *mod, char *s)
{
	struct irc_user *user = &user_chanserv;
	char *command = strsep(&s, " ");

	if (!chanserv_mod || mod != chanserv_mod) {
		/* Limit this function to being called from the module that registered as ChanServ. */
		bbs_error("Caller is not authorized to operate as ChanServ\n");
		return -1;
	}
	/* Execute command as ChanServ. Thankfully, there are a limited number of commands that we need to support. */
	if (!strcasecmp(command, "PRIVMSG")) { /* List this as high up as possible, since this is the most common command */
		handle_privmsg(user, s, 0);
	} else if (!strcasecmp(command, "NOTICE")) {
		handle_privmsg(user, s, 1);
	} else if (!strcasecmp(command, "JOIN")) {
		join_channel(user, s); /* ChanServ will only join one channel at a time */
	} else if (!strcasecmp(command, "PART")) {
		leave_channel(user, s);
	} else if (!strcasecmp(command, "MODE")) {
		handle_modes(user, s);
	} else if (!strcasecmp(command, "TOPIC")) {
		handle_topic(user, s);
	} else {
		bbs_error("Command '%s' is unsupported for ChanServ\n", command);
		return -1;
	}
	return 0;
}

/*! \brief Callback that allows other parts of the BBS to send a message to a user via IRC */
static int alertmsg(unsigned int userid, const char *msg)
{
	char username[48];
	int res = -1;

	if (!bbs_username_from_userid(userid, username, sizeof(username))) {
		res = privmsg(&user_messageserv, username, 1, msg); /* Send a NOTICE to the user */
	}
	return res;
}

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

/*! \brief Thread to periodically ping all clients and dump any that don't respond with a pong back in time */
static void *ping_thread(void *unused)
{
	struct irc_user *user;

	UNUSED(unused);

	for (;;) {
		int now, clients = 0;
		usleep(PING_TIME * 1000); /* convert ms to us */

		now = time(NULL);
		RWLIST_RDLOCK(&users);
		RWLIST_TRAVERSE(&users, user, entry) {
			/* Prevent concurrent writes to a user */
			pthread_mutex_lock(&user->lock);
			if (need_restart || (user->lastping && user->lastpong < now - 2 * PING_TIME)) {
				char buf[32];
				/* Client never responded to the last ping. Disconnect it. */
				if (!need_restart) {
					bbs_debug(3, "Ping expired for %p: last ping=%d, last pong=%d (now %d)\n", user, user->lastping, user->lastpong, now);
					snprintf(buf, sizeof(buf), "Ping timeout: %d seconds", now - user->lastpong); /* No CR LF */
				}
				leave_all_channels(user, "QUIT", need_restart ? "Server restart" : buf);
				if (!need_restart) {
					send_reply(user, "ERROR :Connection timeout\r\n");
				}
				bbs_debug(5, "Shutting down client on node %d\n", user->node->id);
				shutdown(user->node->fd, SHUT_RDWR); /* Make the client handler thread break */
			} else {
				dprintf(user->wfd, "PING :%d\r\n", now);
				user->lastping = now;
				clients++;
			}
			pthread_mutex_unlock(&user->lock);
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

			/*! \todo BUGBUG FIXME mod_discord won't load again once we do, this is a crummy solution.
			 * We need something in module.c that will unload any dependencies,
			 * reload us, and then load all the dependencies again. */
			bbs_module_unload("mod_discord"); /* mod_discord depends on net_irc, so we can't unload while it's loaded. */
			bbs_module_unload("mod_relay_irc"); /* Ditto */
			bbs_request_module_unload(file_without_ext, need_restart - 1);
			break;
		}
	}
	return NULL;
}

/*! \brief Thread to handle a single IRC/IRCS client */
static void irc_handler(struct bbs_node *node, int secure)
{
#ifdef HAVE_OPENSSL
	SSL *ssl;
#endif
	int rfd, wfd;
	struct irc_user *user;

	if (need_restart) {
		return; /* Reject new connections. */
	}

	if (require_chanserv && !chanserv_mod) {
		bbs_warning("Received IRC client connection prior to ChanServ initialization, rejecting\n");
		return;
	}

	user = calloc(1, sizeof(*user));
	if (ALLOC_FAILURE(user)) {
		return;
	}
	pthread_mutex_init(&user->lock, NULL);

	/* Start TLS if we need to */
	if (secure) {
		ssl = ssl_new_accept(node->fd, &rfd, &wfd);
		if (!ssl) {
			bbs_error("Failed to create SSL\n");
			return;
		}
	} else {
		rfd = wfd = node->fd;
	}

	user->rfd = rfd;
	user->wfd = wfd;
	user->node = node;
	user->modes = USER_MODE_NONE;
	user->joined = time(NULL);
	user->hostname = strdup(node->ip);
	user->modes |= USER_MODE_WALLOPS; /* Receive wallops by default */
	if (secure) {
		user->modes |= USER_MODE_SECURE;
	}

	handle_client(user);

#ifdef HAVE_OPENSSL
	if (secure) { /* implies ssl */
		ssl_close(ssl);
		ssl = NULL;
	}
#endif
	user_free(user);
}

static void *__irc_handler(void *varg)
{
	struct bbs_node *node = varg;

	node->thread = pthread_self();
	bbs_node_begin(node);

	irc_handler(node, !strcmp(node->protname, "IRCS") ? 1 : 0); /* Actually handle the IRC/IRCS client */

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

/*! \brief Single listener thread for IRC and/or IRCS */
static void *irc_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener2(irc_socket, ircs_socket, "IRC", "IRCS", __irc_handler, BBS_MODULE_SELF);
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
			if (bbs_get_local_ip(irc_hostname, sizeof(irc_hostname))) {
				bbs_error("No IRC or BBS hostname specified, and unable to determine local IP address. Aborting.\n");
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
				/* Format is simple:
				 * [opers]
				 * admin=P@ssw0rd
				 *
				 * Currently doesn't allow specifying host/range(s), more granular permissions, etc.
				 */
				const char *key = bbs_keyval_key(keyval);
				add_operator(key, NULL);
			}
		}
	}

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

	pthread_mutex_init(&motd_lock, NULL);

	/* If we can't start the TCP listeners, decline to load */
	if (irc_enabled && bbs_make_tcp_socket(&irc_socket, irc_port)) {
		goto decline;
	}
	if (ircs_enabled && bbs_make_tcp_socket(&ircs_socket, ircs_port)) {
		goto decline;
	}

	loadtime = time(NULL);

	if (bbs_pthread_create(&irc_ping_thread, NULL, ping_thread, NULL)) {
		bbs_error("Unable to create IRC ping thread.\n");
		goto decline;
	}
	if (bbs_pthread_create(&irc_listener_thread, NULL, irc_listener, NULL)) {
		bbs_error("Unable to create IRC listener thread.\n");
		pthread_cancel(irc_ping_thread);
		bbs_pthread_join(irc_ping_thread, NULL);
		goto decline;
	}

	if (irc_enabled) {
		bbs_register_network_protocol("IRC", irc_port);
	}
	if (ircs_enabled) {
		bbs_register_network_protocol("IRCS", ircs_port);
	}
	bbs_register_alerter(alertmsg, 5);
	return 0;

decline:
	destroy_operators();
	close_if(irc_socket);
	close_if(ircs_socket);
	return -1;
}

static int unload_module(void)
{
	bbs_unregister_alerter(alertmsg);
	pthread_cancel(irc_ping_thread);
	bbs_pthread_cancel_kill(irc_listener_thread);
	bbs_pthread_join(irc_ping_thread, NULL);
	bbs_pthread_join(irc_listener_thread, NULL);
	if (irc_enabled) {
		bbs_unregister_network_protocol(irc_port);
		close_if(irc_socket);
	}
	if (ircs_enabled) {
		bbs_unregister_network_protocol(ircs_port);
		close_if(ircs_socket);
	}
	destroy_channels();
	destroy_operators();
	pthread_mutex_destroy(&motd_lock);
	free_if(motdstring);
	return 0;
}

BBS_MODULE_INFO_FLAGS("RFC1459 Internet Relay Chat Server", MODFLAG_GLOBAL_SYMBOLS);
