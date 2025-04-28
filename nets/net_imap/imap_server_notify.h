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
 * \brief IMAP Server NOTIFY (RFC 5465)
 *
 */

/*
 * These are the RFC 5423 events that are supported in IMAP and their IMAP event equivalents:
 *
 * - FlagChange (FlagsSet, FlagsClear, MessageRead, MessageTrash)
 * - MessageNew (MessageNew, MessageAppend)
 * - MessageExpunge (MessageExpunge, MessageExpire)
 * - MailboxName (MailboxRename)
 * - SubscriptionChange (MailboxSubscribe, MailboxUnsubscribe)
 * ANNOTATION events (if supported):
 * - AnnotationChange
 * METADATA events (if supported):
 * - MailboxMetadataChange (MetadataChange)
 * - ServerMetadataChange
 *
 * Message events are:
 * MessageNew, MessageExpunge, FlagChange, AnnotationChange
 */

#define IMAP_EVENT_FLAG_CHANGE (EVENT_MESSAGE_READ | EVENT_MESSAGE_TRASH | EVENT_FLAGS_SET | EVENT_FLAGS_CLEAR)
#define IMAP_EVENT_MESSAGE_NEW (EVENT_MESSAGE_NEW | EVENT_MESSAGE_APPEND)
#define IMAP_EVENT_MESSAGE_EXPUNGE (EVENT_MESSAGE_EXPUNGE | EVENT_MESSAGE_EXPIRE)
#define IMAP_EVENT_MAILBOX_NAME EVENT_MAILBOX_RENAME
#define IMAP_EVENT_SUBSCRIPTION_CHANGE (EVENT_MAILBOX_SUBSCRIBE | EVENT_MAILBOX_UNSUBSCRIBE)

#define IMAP_EVENT_ANNOTATION_CHANGE EVENT_ANNOTATION_CHANGE

/* Uncomment if/when METADATA support is added */
#if 0
#define IMAP_EVENT_MAILBOX_METADATA_CHANGE EVENT_METADATA_CHANGE
#define IMAP_EVENT_SERVER_METADATA_CHANGE EVENT_SERVER_METADATA_CHANGE
#endif

/*!
 * \brief Whether an IMAP update should be indicated to a client
 * \param imap Client to check if an update should be delivered to this client
 * \param mbox Mailbox for which the event was generated
 * \param folder IMAP folder name, if available
 * \param maildir Full maildir path, if available
 * \param e Mask of relevant events
 * \retval 1 if update should be sent, mailbox currently selected
 * \retval -1 if update should be sent, mailboxb not currently selected
 * \retval 0 if update should not be sent
 */
int imap_notify_applicable(struct imap_session *imap, struct mailbox *mbox, const char *folder, const char *maildir, enum mailbox_event_type e) __attribute__((nonnull (1)));

/*!
 * \brief Whether an IMAP update should be indicated to a client
 * \param imap Client to check if an update should be delivered to this client
 * \param mbox Mailbox for which the event was generated
 * \param folder IMAP folder name, if available
 * \param maildir Full maildir path, if available
 * \param e Mask of relevant events
 * \param[out] fetchargs FETCH items requested by client for IMAP MessageNew
 * \retval 1 if update should be sent, mailbox currently selected
 * \retval -1 if update should be sent, mailbox not currently selected
 * \retval 0 if update should not be sent
 */
int imap_notify_applicable_fetchargs(struct imap_session *imap, struct mailbox *mbox, const char *folder, const char *maildir, enum mailbox_event_type e, const char **fetchargs) __attribute__((nonnull (1)));

void imap_notify_cleanup(struct imap_session *imap);

/*! \brief Whether sequence numbers are restricted from being used in IMAP commands */
int imap_sequence_numbers_prohibited(struct imap_session *imap);

int handle_notify(struct imap_session *imap, char *s);
