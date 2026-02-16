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
 * \brief Asterisk Manager Interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/* Wrappers around libcami functions
 * Instead of accepting an ami_session,
 * the "session" argument denotes a named AMI connection.
 *
 * This can be NULL for the default connection.
 *
 * Currently, only one connection is supported so this argument
 * is ignored, but if in the future multiple sessions
 * were supported (see [LBBS-111]), then it would be used. */

struct ami_response *bbs_ami_action(const char *session, const char *action, const char *fmt, ...);
int bbs_ami_action_setvar(const char *session, const char *variable, const char *value, const char *channel);
int bbs_ami_action_getvar_buf(const char *session, const char *variable, const char *channel, char *buf, size_t len);
int bbs_ami_action_response_result(const char *session, struct ami_response *resp);
char *bbs_ami_action_getvar(const char *session, const char *variable, const char *channel);
int bbs_ami_action_redirect(const char *session, const char *channel, const char *context, const char *exten, const char *priority);
#define bbs_ami_action_axfer(sess, chan, exten, context) bbs_ami_action(sess, "Atxfer", "Channel:%s\r\nExten:%s\r\nContext:%s", chan, exten, context)
#define bbs_ami_action_cancel_axfer(sess, chan) bbs_ami_action(sess, "CancelAtxfer", "Channel:%s", chan)

/* Forward declaration for modules that don't need to include <cami/cami.h> */
struct ami_event;

/*!
 * \brief Get Caller ID information for the caller associated with an incoming softmodem call via TCP
 * \param node
 * \param[out] numberbuf Buffer for Caller ID number. May be empty.
 * \param num_len Length of numberbuf. Should be at least 16.
 * \param[out] namebuf Buffer for Caller ID name. May be empty.
 * \param num_len Length of namebuf. Should be at least 16.
 * \retval 0 on success (successfully retrieved a session with associated Caller ID information)
 * \retval -1 No Softmodem session corresponds with this TCP connection
 */
int bbs_ami_softmodem_get_callerid(struct bbs_node *node, char *numberbuf, size_t num_len, char *namebuf, size_t name_len);

int __bbs_ami_callback_register(int (*callback)(struct ami_event *event, const char *eventname), void *mod);

/*!
 * \brief Register an AMI callback
 * \param callback Callback function to execute on AMI events
 * \retval 0 on success, -1 on failure
 */
#define bbs_ami_callback_register(callback) __bbs_ami_callback_register(callback, BBS_MODULE_SELF)

/*!
 * \brief Unregister an AMI callback previously registered using bbs_ami_callback_register
 * \param callback
 * \retval 0 on success, -1 on failure
 */
int bbs_ami_callback_unregister(int (*callback)(struct ami_event *event, const char *eventname));
