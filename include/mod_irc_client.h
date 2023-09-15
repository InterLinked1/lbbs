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
 * \brief IRC client
 *
 */

/* Mirror enum irc_msg_type here,
 * to avoid depending modules having a direct dependency on lirc */
enum irc_callback_msg_type {
	CMD_PRIVMSG,
	CMD_NOTICE,
	CMD_PING,
	CMD_JOIN,
	CMD_PART,
	CMD_QUIT,
	CMD_KICK,
	CMD_NICK,
	CMD_MODE,
	CMD_TOPIC,
	CMD_UNSUPPORTED,
};

/*!
 * \brief Register a callback to receive messages from mod_irc_client IRC clients that have callbacks=yes
 * \param msg_cb Callback for IRC messages
 * \param numeric_cb Callback for IRC numeric responses/messages. NULL if not needed.
 * \param mod Module reference
 * \retval 0 on success, -1 on failure
 */
int __bbs_irc_client_msg_callback_register(void (*msg_cb)(const char *clientname, enum irc_callback_msg_type type, const char *channel, const char *prefix, int ctcp, const char *msg), void (*numeric_cb)(const char *clientname, const char *prefix, int numeric, const char *msg), void *mod);

#define bbs_irc_client_msg_callback_register(msg_cb, numeric_cb) __bbs_irc_client_msg_callback_register(msg_cb, numeric_cb, BBS_MODULE_SELF)

/*! \brief Unregister a callback */
int bbs_irc_client_msg_callback_unregister(void (*msg_cb)(const char *clientname, enum irc_callback_msg_type type, const char *channel, const char *prefix, int ctcp, const char *msg));

/*!
 * \brief Whether a named IRC client exists
 * \param clientname Name of client configured in mod_irc_client.conf
 * \retval 1 if a client with this name exists
 * \retval 0 if no such client exists
 */
int bbs_irc_client_exists(const char *clientname);

/*!
 * \brief Send a raw IRC message to an IRC channel using a mod_irc_client client (can be used anywhere in the BBS)
 * \param clientname Name of client configured in mod_irc_client.conf. NULL to use default (first one).
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
int bbs_irc_client_send(const char *clientname, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3)));

/*!
 * \brief Send a PRIVMSG message to an IRC channel using a mod_irc_client client (can be used anywhere in the BBS)
 * \param clientname Name of client configured in mod_irc_client.conf. NULL to use default (first one).
 * \param channel Channel name.
 * \param prefix. Sender prefix.
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
int bbs_irc_client_msg(const char *clientname, const char *channel, const char *prefix, const char *fmt, ...) __attribute__ ((format (gnu_printf, 4, 5)));
