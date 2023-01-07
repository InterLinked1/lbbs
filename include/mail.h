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
 * \brief Email generation and transmission
 *
 */

/*!
 * \brief Send an email
 * \param async Whether to send the email asynchronously
 * \param to Recipient. If NULL, default from mail.conf will be used. Name is optional (use email <name> format).
 * \param from Sender. If NULL, default from mail.conf will be used. Name is optional (use email <name> format).
 * \param replyto Optional Reply-To address.  Name is optional (use email <name> format).
 * \param subject
 * \param body
 * \retval 0 on success, -1 on failure
 */
int bbs_mail(int async, const char *to, const char *from, const char *replyto, const char *subject, const char *body);

/*!
 * \brief Send an email, with variadic printf-style arguments
 * \param async Whether to send the email asynchronously
 * \param to Recipient. If NULL, default from mail.conf will be used. Name is optional (use email <name> format).
 * \param from Sender. If NULL, default from mail.conf will be used. Name is optional (use email <name> format).
 * \param replyto Optional Reply-To address.  Name is optional (use email <name> format).
 * \param subject
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
int __attribute__ ((format (gnu_printf, 6, 7))) bbs_mail_fmt(int async, const char *to, const char *from, const char *replyto, const char *subject, const char *fmt, ...);

/*! \brief Initialize mail config */
int bbs_mail_init(void);
