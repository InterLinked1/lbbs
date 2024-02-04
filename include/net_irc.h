/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Internet Relay Chat (IRC) Server
 *
 * \note Public relay integration
 *
 */

#define PUBLIC_CHANNEL_PREFIX "="
#define PRIVATE_CHANNEL_PREFIX "*"
#define SECRET_CHANNEL_PREFIX "@"

/*! \brief RFC 2811 channel names namespace */
/*! \note There is no real support for &, +,  and ! channels, as defined in the RFC; these are just defined here for completeness.
 * Consequently, we hijack + (modeless channels) for private namespace channels (separate namespace per user),
 * since we don't need modes for these anyways, and there's not much use for modeless channels otherwise.
 * We can't use some other arbitrary prefix because IRC clients will just prefix # automatically
 * if the channel name doesn't begin with one of the officially valid prefixes. */
/* "Standard" channels */
#define CHANNEL_NAME_PREFIX_NETWORK "#"
#define CHANNEL_NAME_PREFIX_LOCAL "&"
#define CHANNEL_NAME_PREFIX_MODELESS "+"
/* "Safe" channels */
#define CHANNEL_NAME_PREFIX_TIMESTAMPED "!"

#define PREFIX_FOUNDER "~"
#define PREFIX_ADMIN "&"
#define PREFIX_OP "@"
#define PREFIX_HALFOP "%"
#define PREFIX_VOICE "+"

/*! \brief Channel modes (apply to all users) */
enum channel_modes {
	CHANNEL_MODE_NONE =					0,
	CHANNEL_MODE_COLOR_FILTER =			(1 << 0), /* c: Strip color and formatting codes from channel messages */
	CHANNEL_MODE_FREE_INVITE =			(1 << 1), /* g: Free invite. Anyone in the channel can invite (not just ops) */
	CHANNEL_MODE_INVITE_ONLY =			(1 << 2), /* i: Invite only */
	/*! \todo implement throttled */
	CHANNEL_MODE_THROTTLED =			(1 << 3), /* j <n:t>: Channel is throttled. Only n users may join each t seconds. */
	CHANNEL_MODE_PASSWORD =				(1 << 4), /* k <password>: Password required to join channel */
	CHANNEL_MODE_LIMIT =				(1 << 5), /* l<max>: Channel capacity limited to max. */
	CHANNEL_MODE_MODERATED =			(1 << 6), /* m: Channel moderated: only opped and voiced users can send */
	CHANNEL_MODE_NO_EXTERNAL =			(1 << 7), /* n: No external messages */
	/* See https://www.irchelp.org/misc/ccosmos.html#sec3-5-3 for difference between private and secret.
	 * This implementation makes a distinction between the two, unlike many servers nowadays which treat them identically.
	 * Secret does everything private does, but is even more secret.
	 */
	CHANNEL_MODE_PRIVATE =				(1 << 8), /* p: Private channel: membership is private outside of the channel, but channel shows up in lists */
	CHANNEL_MODE_REGISTERED_ONLY =		(1 << 9), /* r: Registered users only */
	CHANNEL_MODE_SECRET =				(1 << 10), /* s: Secret channel: membership and listing are private */
	CHANNEL_MODE_TOPIC_PROTECTED =		(1 << 11), /* t: Topic protected: only half ops or above can change the topic */
	CHANNEL_MODE_REDUCED_MODERATION =	(1 << 12), /* z: Reduced moderation. Normally blocked messages will be sent to half operators and above. */
	CHANNEL_MODE_CTCP_BLOCK =			(1 << 13), /* C: Block CTCP commands, other than /me actions */
	CHANNEL_MODE_PERMANENT =			(1 << 14), /* P: Permanent channel (not removed on empty). Can only be set by IRC operators. */
	CHANNEL_MODE_TLS_ONLY =				(1 << 15), /* S: Only users connected via TLS may join */
	CHANNEL_MODE_NOTICE_BLOCK =			(1 << 16), /* T: Block channel notices (other than CTCP replies) */
};

/*! \brief Channel "hidden" from queries unless the user is also in it */
#define CHANNEL_HIDDEN (CHANNEL_MODE_PRIVATE | CHANNEL_MODE_SECRET)

/*! \brief Channel modes that apply to users (on a per-user basis) */
enum channel_user_modes {
	CHANNEL_USER_MODE_NONE =	0,
	/* Note that founder and admin don't confer any of the privileges of operator.
	 * Therefore, in most cases, you'll want to assign founder and op (or admin an op),
	 * if you want to assign these top 2 privileges.
	 * Think of these as "enhancements" to op, rather than inherently higher privilege levels,
	 * much the same way Flash Override in AUTOVON is not technically its own priority level.
	 */
	CHANNEL_USER_MODE_FOUNDER =	(1 << 0), /* q: Founder: total and complete control */
	CHANNEL_USER_MODE_ADMIN =	(1 << 1), /* a: Admin/Protected: can only be demoted by founders */
	CHANNEL_USER_MODE_HALFOP =	(1 << 2), /* h: Half operator: can kick users, set most channel modes, grant voice */
	CHANNEL_USER_MODE_OP =		(1 << 3), /* o: Operator: is an op */
	CHANNEL_USER_MODE_VOICE =	(1 << 4), /* v: Voice: has voice */
};

/*! \brief User modes */
enum user_modes {
	USER_MODE_NONE =		0,
	USER_MODE_INVISIBLE =	(1 << 0), /* i: User hidden from global WHO */
	USER_MODE_OPERATOR =	(1 << 1), /* o: Global server operator */
	USER_MODE_WALLOPS =		(1 << 2), /* w: Wallops: receive WALLOPS messages */
	USER_MODE_SECURE =		(1 << 3), /* Z: Connected via SSL/TLS */
};

/*!
 * \brief Get the channel user modes for a user
 * \param channel Channel name
 * \param username Nickname
 * \retval CHANNEL_USER_MODE_NONE if not in channel, modes if in the channel
 */
enum channel_user_modes irc_get_channel_member_modes(const char *channel, const char *username);

/*!
 * \brief Get the topic of a channel
 * \param channel Channel name
 * \returns Channel topic, or NULL if no topic or channel does not exist
 */
const char *irc_channel_topic(const char *channel);

#define irc_relay_register(relay_send, nicklist, privmsg) __irc_relay_register(relay_send, nicklist, privmsg, BBS_MODULE_SELF)

struct irc_relay_message {
	const char *channel;
	const char *sender;		/*!< Could be NULL, but will contain the sending user's nickname, if available. */
	const char *msg;
	const void *sendingmod;	/*!< Sending module */
};

/*!
 * \brief Register a relay function that will be used to receive messages sent on IRC channels for rebroadcast on other protocols.
 * \param relay_send Callback function. The function should return 0 to continue processing any other relays and nonzero to stop immediately.
 * \param nicklist Callback function to obtain an IRC NAMES or WHO format of any users that should be displayed as channel members. NULL if not applicable.
 *                  If channel is non-NULL, function should return all members in channel. Otherwise, it should return the specified user.
 * \param privmsg  Callback function to relay a private message to a user on another network. NULL if not applicable.
 * \param mod Module reference.
 * \retval 0 on success, -1 on failure
 */
int __irc_relay_register(int (*relay_send)(struct irc_relay_message *rmsg),
	int (*nicklist)(struct bbs_node *node, int fd, int numeric, const char *requsername, const char *channel, const char *user),
	int (*privmsg)(const char *recipient, const char *sender, const char *user),
	void *mod);

/*! \brief Unregister a relay previously registered using irc_relay_register */
int irc_relay_unregister(int (*relay_send)(struct irc_relay_message *rmsg));

#define irc_relay_send_multiline(channel, modes, relayname, sender, hostsender, msg, transform, ircuser) _irc_relay_send_multiline(channel, modes, relayname, sender, hostsender, msg, transform, ircuser, BBS_MODULE_SELF)

/*!
 * \brief Send a (possibly multiline) message to an IRC channel
 * \param channel IRC channel name
 * \param modes User modes
 * \param relayname Name of relay provider
 * \param sender Name of sender (for IRC)
 * \param hostsender
 * \param msg
 * \param transform Callback function to run on each line of the message. Return -1 to abort sending of message.
 * \param ircuser If non-NULL, indicates a personal relay for the specified IRC user.
 *                If this user is currently online but not in this channel, s/he will be invited to the channel.
 * \param mod Module
 * \retval 0 on success
 * \retval -1 on failure (message not relayed)
 * \retval 1 Partial success (e.g. message truncated due to consisting of too many lines)
 */
int _irc_relay_send_multiline(const char *channel, enum channel_user_modes modes, const char *relayname, const char *sender, const char *hostsender, const char *msg, int(*transform)(const char *line, char *buf, size_t len), const char *ircuser, void *mod);

#define irc_relay_send(channel, modes, relayname, sender, hostsender, msg, ircuser) _irc_relay_send(channel, modes, relayname, sender, hostsender, msg, ircuser, 0, BBS_MODULE_SELF)

#define irc_relay_send_notice(channel, modes, relayname, sender, hostsender, msg, ircuser) _irc_relay_send(channel, modes, relayname, sender, hostsender, msg, ircuser, 1, BBS_MODULE_SELF)

/*!
 * \brief Send a single message to an IRC channel
 * \param channel IRC channel name
 * \param modes User modes
 * \param relayname Name of relay provider
 * \param sender Name of sender (for IRC)
 * \param hostsender
 * \param msg
 * \param ircuser If non-NULL, indicates a personal relay for the specified IRC user.
 *                If this user is currently online but not in this channel, s/he will be invited to the channel.
 * \param mod Module
 * \retval 0 on success, -1 on failure (message not relayed)
 */
int _irc_relay_send(const char *channel, enum channel_user_modes modes, const char *relayname, const char *sender, const char *hostsender, const char *msg, const char *ircuser, int notice, void *mod);

/*!
 * \brief Set the channel topic (from a relay)
 * \param channel Channel name
 * \param topic Topic description
 * \param ircuser Name of owner, for private namespace channels
 * \retval 0 on success, -1 on failure
 */
int irc_relay_set_topic(const char *channel, const char *topic, const char *ircuser);

#define irc_relay_raw_send(channel, msg) _irc_relay_raw_send(channel, msg, BBS_MODULE_SELF)

/*!
 * \brief Send a raw message to an IRC channel (e.g. for system messages). Do not include CR LF.
 * \retval 0 on success, -1 on failure (message not relayed)
 */
int _irc_relay_raw_send(const char *channel, const char *msg, void *mod);

/*!
 * \brief Send an arbitary numeric response from a relay module.
 * \param node
 * \param fd
 * \param numeric
 * \param fmt printf-style arguments. Do not include trailing CR LF.
 */
#define irc_relay_numeric_response(node, fd, numeric, fmt, ...) __irc_relay_numeric_response(node, fd, "%03d " fmt "\r\n", numeric, ## __VA_ARGS__)

int __attribute__ ((format (gnu_printf, 3, 4))) __irc_relay_numeric_response(struct bbs_node *node, int fd, const char *fmt, ...);

/*!
 * \brief Generate a 352 numeric WHO response from a relay module
 * \param node
 * \param fd File descriptor of IRC client. net_irc has locked the client for writing when triggering callbacks that should call this function
 *           so interleaved writes are not possible.
 * \param relayname Name of relay
 * \param ircusername IRC username representation of the client
 * \param hostsuffix Suffix for hostmask
 * \param uniqueid Unique identifier of user on relay
 * \param active Whether user is currently active
 */
void irc_relay_who_response(struct bbs_node *node, int fd, const char *relayname, const char *ircusername, const char *hostsuffix, const char *uniqueid, int active);

/*!
 * \brief Generate a 353 numeric NAMES response from a relay module
 * \param node
 * \param fd File descriptor of IRC client. net_irc has locked the client for writing when triggering callbacks that should call this function
 *           so interleaved writes are not possible.
 * \param ircusername IRC username representation of the client
 * \param channel IRC channel name
 * \param names List of space-separated names to send in this response
 */
void irc_relay_names_response(struct bbs_node *node, int fd, const char *ircusername, const char *channel, const char *names);

/*! \brief Register a ChanServ (channel services) provider */
int irc_chanserv_register(void (*privmsg)(const char *username, char *msg), void (*eventcb)(const char *command, const char *channel, const char *username, const char *data), void *mod);

/*! \brief Unregister ChanServ */
int irc_chanserv_unregister(void (*privmsg)(const char *username, char *msg));

#define chanserv_exec(s) __chanserv_exec(BBS_MODULE_SELF, s)

/*! \brief Execute an IRC command as ChanServ */
int __chanserv_exec(void *mod, char *s);
