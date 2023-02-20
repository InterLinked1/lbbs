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
 * \brief E-Mail Resource Module
 *
 */

/* Forward declaration */
struct mailbox;

/*!
 * \brief Get the mailbox by user ID and/or email address username
 * \param userid. The user ID of the target mailbox, if known (will be for POP/IMAP, will not be for SMTP, so specify 0)
 * \param name. The username of the mailbox. This MUST be specified for SMTP, for alias resolution if needed, but optional for POP/IMAP.
 * \retval mailbox on success, NULL on failure
 */
struct mailbox *mailbox_get(unsigned int userid, const char *name);

/*!
 * \brief Attempt to obtain a read lock on mailbox
 * \retval 0 on success (lock obtained), error number otherwise
 * \note IMAP operations may use this function
 */
int mailbox_rdlock(struct mailbox *mbox);

/*!
 * \brief Attempt to obtain a write lock on mailbox
 * \retval 0 on success (lock obtained), error number otherwise
 * \note POP operations should use this function
 */
int mailbox_wrlock(struct mailbox *mbox);

/*! \brief Unlock a previously locked mailbox */
void mailbox_unlock(struct mailbox *mbox);

/*! \brief Grab an exclusive lock on UID operations for this mailbox */
int mailbox_uid_lock(struct mailbox *mbox);

/*! \brief Unlock a previously acquired UID lock on this mailbox */
void mailbox_uid_unlock(struct mailbox *mbox);

/*! \brief Get the quota of a mailbox in bytes */
unsigned long mailbox_quota(struct mailbox *mbox);

/*! \brief Get the quota remaining (available) of a mailbox in bytes */
unsigned long mailbox_quota_remaining(struct mailbox *mbox);

/*!
 * \brief Get the maildir of a mailbox
 * \param mbox Mailbox. If NULL, the top-level maildir path will be returned.
 */
const char *mailbox_maildir(struct mailbox *mbox);

/*!
 * \brief Ensure that maildir directories exist in the specified directory
 * \retval 0 on success, -1 on failure
 */
int mailbox_maildir_init(const char *path);

/*!
 * \brief Create a unique file in the tmp subdirectory of a maildir
 * \param path Path to maildir
 * \param[out] buf Generated filename
 * \param len Size of buffer
 * \param[out] newbuf Generated filename for rename target 
 * \retval -1 on failure, file descriptor on success
 */
int maildir_mktemp(const char *path, char *buf, size_t len, char *newbuf);
