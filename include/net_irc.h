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

/*! \brief Channel modes (apply to all users) */
enum channel_modes {
	CHANNEL_MODE_NONE =					0,
	/*! \todo add invite only (i) */
	/*! \todo implement throttled */
	CHANNEL_MODE_THROTTLED =			(1 << 0), /* j<n:t>: Channel is throttled. Only n users may join each t seconds. */
	CHANNEL_MODE_LIMIT =				(1 << 1), /* l<max>: Channel capacity limited to max. */
	CHANNEL_MODE_MODERATED =			(1 << 2), /* m: Channel moderated: only opped and voiced users can send */
	CHANNEL_MODE_NO_EXTERNAL =			(1 << 3), /* n: No external messages */
	/* See https://www.irchelp.org/misc/ccosmos.html#sec3-5-3 for difference between private and secret.
	 * This implementation makes a distinction between the two, unlike many servers nowadays which treat them identically.
	 * Secret does everything private does, but is even more secret.
	 */
	CHANNEL_MODE_PRIVATE =				(1 << 4), /* p: Private channel: membership is private outside of the channel, but channel shows up in lists */
	CHANNEL_MODE_REGISTERED_ONLY =		(1 << 5), /* r: Registered users only */
	CHANNEL_MODE_SECRET =				(1 << 6), /* s: Secret channel: membership and listing are private */
	CHANNEL_MODE_TOPIC_PROTECTED =		(1 << 7), /* t: Topic protected: only half ops or above can change the topic */
	CHANNEL_MODE_REDUCED_MODERATION =	(1 << 8), /* z: Reduced moderation. Normally blocked messages will be sent to half operators and above. */
	CHANNEL_MODE_TLS_ONLY =				(1 << 9), /* S: Only users connected via TLS may join */
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
	USER_MODE_SECURE =		(1 << 2), /* Z: Connected via SSL/TLS */
};

/*!
 * \brief Register a relay function that will be used to receive messages sent on IRC channels for rebroadcast on other protocols.
 * \param relay_send. Callback function. Note that sender could be NULL, but will contain the sending user's nickname, if available.
 *                    The function should return 0 to continue processing any other relays and nonzero to stop immediately.
 * \param mod Module reference.
 * \retval 0 on success, -1 on failure
 */
int irc_relay_register(int (*relay_send)(const char *channel, const char *sender, const char *msg), void *mod);

/*! \brief Unregister a relay previously registered using irc_relay_register */
int irc_relay_unregister(int (*relay_send)(const char *channel, const char *sender, const char *msg));

/*!
 * \brief Send a message to an IRC channel
 * \retval 0 on success, -1 on failure (message not relayed)
 */
int irc_relay_send(const char *channel, enum channel_user_modes modes, const char *relayname, const char *sender, const char *msg);
