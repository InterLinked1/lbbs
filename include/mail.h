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

/* Forward declaration for bbs_mail_message prototype */
struct stringlist;

#define	MAIL_FILE_MODE	0600
#define SIMPLE_MAILER_PARAMS int async, const char *to, const char *from, const char *replyto, const char *errorsto, const char *subject, const char *body
#define FULL_MAILER_PARAMS const char *tmpfile, const char *mailfrom, struct stringlist *recipients

/*!
 * \brief Send an entire RFC822 message
 * \param tmpfile Temporary file containing RFC822 message, which will be deleted after sending. MUST use CR LF line endings.
 * \param mailfrom MAIL FROM address. If NULL, the empty MAIL FROM is used. Do not include <>.
 * \param rcpt Recipient stringlist (including <>, but no names). If NULL, recipients will be extracted from the message itself,
 *             using the To, Cc, and Bcc headers.
 *             If the message contains any Bcc headers, you should pass NULL for this argument,
 *             since that will force recipients to be extracted and remove any Bcc headers
 *             in the sent message. If recipients is non-NULL, the message will NOT be modified
 *             at all, and thus should NOT include any Bcc headers, since this would leak information.
 *             The provided stringlist will be consumed and cleaned up, and should not be used afterwards.
 * \retval 0 on success, -1 on failure
 */
int bbs_mail_message(const char *tmpfile, const char *mailfrom, struct stringlist *recipients);

/*! \note "Simple" messages have only a single recipient,
 * a limited number of customizable headers,
 * and use the default Content-Type.
 * If this does not meet the requirements of a message,
 * bbs_mail_message should be used instead, since that
 * accepts a raw RFC822 message for delivery. */

/*!
 * \brief Create and send a simple email
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
 * \brief Create and send a simple email, with variadic printf-style arguments
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
 * \brief Create a simple email
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

/*!
 * \brief Register a mailer
 * \param simple_mailer A callback that will send an email (accepting SIMPLE_MAILER_PARAMS), that should return 0 if the message was handled, -1 if not handled, and 1 if delivery failed.
 *        Note that "handled" does not necessarily mean "delivery guaranteed".
 * \param full_mailer Same as simple mailer, but accepts a filename containing an entire RFC 822 message instead, and accepts responsibility for deleting it.
 *        Callback arguments will be non-NULL (even if bbs_mail_message is called with NULL arguments).
 *        Callback is responsible for cleaning up the recipients stringlist.
 * \param priority Positive priority to control order of callback preference. Like with MX records, a lower priority is preferred.
 * \retval 0 on success, -1 on failure
 */
#define bbs_register_mailer(simple_mailer, full_mailer, priority) __bbs_register_mailer(simple_mailer, full_mailer, BBS_MODULE_SELF, priority)

int __bbs_register_mailer(int (*simple_mailer)(SIMPLE_MAILER_PARAMS), int (*full_mailer)(FULL_MAILER_PARAMS), void *mod, int priority);

int bbs_unregister_mailer(int (*simple_mailer)(SIMPLE_MAILER_PARAMS), int (*full_mailer)(FULL_MAILER_PARAMS));
