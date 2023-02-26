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

/*!
 * \brief Create an email
 * \param p File handler into which to write the email
 * \param subject Email subject
 * \param body Email body
 * \param to Recipient
 * \param from Sender
 * \param replyto Reply-To address. If NULL, not added.
 * \param errorsto Errors-To address. If NULL, not added.
 * \param attachments Pipe (|) separated list of full file paths of attachments to attach.
 * \param delete Whether to delete attachments afterwards
 * \retval 0 on total success and -1 on partial or total failure to generate the message properly
 */
int bbs_make_email_file(FILE *p, const char *subject, const char *body, const char *to, const char *from, const char *replyto, const char *errorsto, const char *attachments, int deleteafter);

/*! \brief Initialize mail config */
int bbs_mail_init(void);
