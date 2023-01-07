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
