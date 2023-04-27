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
 * \param to Recipient. If NULL, default from mail.conf will be used. Name is optional (use name \<email> format).
 * \param from Sender. If NULL, default from mail.conf will be used. Name is optional (use name \<email> format).
 * \param replyto Optional Reply-To address.  Name is optional (use name \<email> format).
 * \param subject
 * \param body
 * \retval 0 on success, -1 on failure
 */
int bbs_mail(int async, const char *to, const char *from, const char *replyto, const char *subject, const char *body);

/*!
 * \brief Send an email, with variadic printf-style arguments
 * \param async Whether to send the email asynchronously
 * \param to Recipient. If NULL, default from mail.conf will be used. Name is optional (use email \<name> format).
 * \param from Sender. If NULL, default from mail.conf will be used. Name is optional (use email \<name> format).
 * \param replyto Optional Reply-To address.  Name is optional (use email \<name> format).
 * \param subject
 * \param fmt printf-style format string
 * \retval 0 on success, -1 on failure
 */
int bbs_mail_fmt(int async, const char *to, const char *from, const char *replyto, const char *subject, const char *fmt, ...) __attribute__ ((format (gnu_printf, 6, 7))) ;

/*!
 * \brief Create an email
 * \param p File handler into which to write the email
 * \param subject Email subject
 * \param body Email body
 * \param to Recipient. If no domain portion is specified, it will be interpreted as a local BBS user.
 * \param from Sender
 * \param replyto Reply-To address. If NULL, not added.
 * \param errorsto Errors-To address. If NULL, not added.
 * \param attachments Pipe (|) separated list of full file paths of attachments to attach.
 * \param deleteafter Whether to delete attachments afterwards
 * \retval 0 on total success and -1 on partial or total failure to generate the message properly
 * \note This is purely a convenience function. It does not handle all possible cases. In particular, note that this function does not accept multiple recipients.
 */
int bbs_make_email_file(FILE *p, const char *subject, const char *body, const char *to, const char *from, const char *replyto, const char *errorsto, const char *attachments, int deleteafter);

/*! \brief Initialize mail config */
int bbs_mail_init(void);

#define	MAIL_FILE_MODE	0600
#define MAILER_PARAMS int async, const char *to, const char *from, const char *replyto, const char *errorsto, const char *subject, const char *body

/*!
 * \brief Register a mailer
 * \param mailer A callback that will send an email (accepting MAILER_PARAMS), that should return 0 if the message was handled, -1 if not handled, and 1 if delivery failed.
 *        Note that "handled" does not necessarily mean "delivery guaranteed".
 * \param priority Positive priority to control order of callback preference. Like with MX records, a lower priority is preferred.
 * \retval 0 on success, -1 on failure
 */
#define bbs_register_mailer(mailer, priority) __bbs_register_mailer(mailer, BBS_MODULE_SELF, priority)

int __bbs_register_mailer(int (*mailer)(MAILER_PARAMS), void *mod, int priority);

int bbs_unregister_mailer(int (*mailer)(MAILER_PARAMS));
