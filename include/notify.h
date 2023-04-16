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
 * \brief System and User Notifications
 *
 */

/*!
 * \brief Email the sysop
 * \param user. Sending user. NULL for general system notifications.
 * \param subject
 * \param fmt Email printf-style format string
 * \retval 0 on success, -1 on failure
 */
int __attribute__ ((format (gnu_printf, 3, 4))) bbs_sysop_email(struct bbs_user *user, const char *subject, const char *fmt, ...);

enum notify_delivery_type {
	DELIVERY_GUARANTEED = 0,
	DELIVERY_EPHEMERAL,
};

/*!
 * \brief Deliver an alert message to a user
 * \param userid
 * \param persistence Delivery type. If guaranteed, an email will be sent to the user if the alert cannot be delivered via an ephemeral channel.
 * \param fmt printf-style format string
 * \note This should only be used for *short* messages, i.e. a sentence or two at most. Do not include a trailing CR LF.
 */
int __attribute__ ((format (gnu_printf, 3, 4))) bbs_alert_user(unsigned int userid, enum notify_delivery_type persistence, const char *fmt, ...);

#define ALERTER_PARAMS unsigned int userid, const char *msg

/*!
 * \brief Register an alerter
 * \param alerter Callback that will attempt to deliver an alert message to a user. Should return 0 if successful and nonzero otherwise.
 * \param priority A lower priority callback will be preferred first over higher number priorities
 * \retval 0 on success, -1 on failure
 */
#define bbs_register_alerter(alerter, priority) __bbs_register_alerter(alerter, BBS_MODULE_SELF, priority)

int __bbs_register_alerter(int (*alerter)(ALERTER_PARAMS), void *mod, int priority);

int bbs_unregister_alerter(int (*alerter)(ALERTER_PARAMS));
