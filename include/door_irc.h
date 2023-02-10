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

/*!
 * \brief Register a callback to receive messages from door_irc IRC clients that have callbacks=yes
 * \param clientname Client name from door_irc.conf
 * \param msg_cb Callback for IRC messages
 * \param numeric_cb Callback for IRC numeric responses/messages. NULL if not needed.
 * \param mod Module reference
 * \retval 0 on success, -1 on failure
 */
int bbs_irc_client_msg_callback_register(void (*msg_cb)(const char *clientname, const char *channel, const char *msg), void (*numeric_cb)(const char *clientname, const char *prefix, int numeric, const char *msg), void *mod);

/*! \brief Unregister a callback */
int bbs_irc_client_msg_callback_unregister(void (*msg_cb)(const char *clientname, const char *channel, const char *msg));

/*!
 * \brief Send a raw IRC message to an IRC channel using a door_irc client (can be used anywhere in the BBS)
 * \param clientname Name of client configured in door_irc.conf. NULL to use default (first one).
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
int __attribute__ ((format (gnu_printf, 2, 3))) bbs_irc_client_send(const char *clientname, const char *fmt, ...);

/*!
 * \brief Send a PRIVMSG message to an IRC channel using a door_irc client (can be used anywhere in the BBS)
 * \param clientname Name of client configured in door_irc.conf. NULL to use default (first one).
 * \param channel Channel name.
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
int __attribute__ ((format (gnu_printf, 3, 4))) bbs_irc_client_msg(const char *clientname, const char *channel, const char *fmt, ...);
