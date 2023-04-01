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
 * \brief Get all the destination addresses for a listserv
 * \param listname User portion of address
 * \returns list of addresses, NULL if address does not resolve to a mailing list
 */
const char *mailbox_expand_list(const char *listname);

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

/*! \brief Start watching a mailbox for new messages */
void mailbox_watch(struct mailbox *mbox);

/*! \brief Stop watching a mailbox for new messages. This SHOULD be called at some point during execution if mailbox_watch is called. */
void mailbox_unwatch(struct mailbox *mbox);

/*!
 * \brief Called by producer applications (e.g. SMTP) to indicate new messages are available for subscribers actively watching the mailbox
 * \note This will also set the activity flag for the mailbox.
 */
void mailbox_notify(struct mailbox *mbox, const char *newfile);

/*!
 * \brief Check if a mailbox has activity
 * \retval 1 if mailbox has activity, 0 if not
 * \note Calling this function will clear the activity flag so multiple simultaneous calls will not all return 1
 */
int mailbox_has_activity(struct mailbox *mbox);

#define mailbox_register_watcher(callback) __mailbox_register_watcher(callback, BBS_MODULE_SELF)

/*! \brief Register a mailbox watching application (intended for IMAP) */
int __mailbox_register_watcher(void (*callback)(struct mailbox *mbox, const char *newfile), void *mod);

/*! \brief Unregister a mailbox watching application */
int mailbox_unregister_watcher(void (*callback)(struct mailbox *mbox, const char *newfile));

/*! \brief Invalidate the cached quota usage for this mailbox */
void mailbox_invalidate_quota_cache(struct mailbox *mbox);

/*!
 * \brief Manually adjust the quota usage of a mailbox
 * \param mbox
 * \param bytes. Positive number to increase quota usage or negative number to decrease quota usage
 */
void mailbox_quota_adjust_usage(struct mailbox *mbox, int bytes);

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
 * \brief Get the mailbox ID of a mailbox (same as the user ID of the user that owns this mailbox)
 * \param mbox Mailbox. Must not be NULL.
 * \retval positive mailbox ID
 */
int mailbox_id(struct mailbox *mbox);

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

/*!
 * \brief Get the next or current UID value of a mailbox directory, atomically
 * \param mbox Mailbox
 * \param directory Full system path of directory
 * \param allocate Whether to generate a new valid message UID or simply returning the current maximum UID value
 * \param[out] newuidvalidity The UIDVALIDITY of this directory
 * \param[out] newuidnext The current maximum UID in this directory (this is somewhat of a misnomer, you need to add 1 to compute the actual UIDNEXT)
 * \retval 0 on failure, otherwise the current maximum or newly allocated UID (depending on the allocate argument)
 * \note This operation is used by both the IMAP and POP3 servers, although UIDs are only relevant for IMAP.
 *       POP3 calls this function to ensure consistency for IMAP operations.
 * \note This operation internally maintains the .uidvalidity of a maildir directory.
 */
unsigned int mailbox_get_next_uid(struct mailbox *mbox, const char *directory, int allocate, unsigned int *newuidvalidity, unsigned int *newuidnext);

/*!
 * \brief Move a message from the new directory to the cur directory, atomically
 * \param mbox Mailbox
 * \param dir Full system path to the active maildir directory
 * \param curdir Full system path to cur directory (should be an immediate subdirectory of dir)
 * \param newdir Full system path to new directory (should be an immediate subdirectory of dir)
 * \param filename The original name (just the name, not the full path) of the message file in the new directory
 * \param[out] newuidvalidity The UIDVALIDITY of this directory
 * \param[out] newuidnext The current maximum UID in this directory (this is somewhat of a misnomer, you need to add 1 to compute the actual UIDNEXT)
 * \retval -1 on failure, number of bytes in file on success (useful for POP3)
 */
int maildir_move_new_to_cur(struct mailbox *mbox, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext);

/*!
 * \brief Move a message from the new directory to the cur directory, atomically
 * \param mbox Mailbox
 * \param dir Full system path to the active maildir directory
 * \param curdir Full system path to cur directory (should be an immediate subdirectory of dir)
 * \param newdir Full system path to new directory (should be an immediate subdirectory of dir)
 * \param filename The original name (just the name, not the full path) of the message file in the new directory
 * \param[out] newuidvalidity The UIDVALIDITY of this directory
 * \param[out] newuidnext The current maximum UID in this directory (this is somewhat of a misnomer, you need to add 1 to compute the actual UIDNEXT)
 * \param[out] newpath The resulting new filename
 * \param len Length of newpath
 * \retval -1 on failure, number of bytes in file on success (useful for POP3)
 */
int maildir_move_new_to_cur_file(struct mailbox *mbox, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext, char *newpath, size_t len);

/*!
 * \brief Move a message from one maildir to another maildir (including a subdirectory of the same account), adjusting the UID as needed
 * \param mbox Mailbox
 * \param curfile Full path to current file
 * \param curfilename The base name of the current file
 * \param destmaildir The directory path of the maildir to which the message should be moved (do not include new or cur at the end)
 * \param[out] uidvalidity The new UIDVALIDITY of the destination maildir
 * \param[out] uidnext The new max UID of the destination maildir
 * \retval 0 on failure, UID of new message file on success
 */
int maildir_move_msg(struct mailbox *mbox, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext);

/*! \brief Same as maildir_move_msg, but deep copy the message instead of moving it. The original file is left intact. */
int maildir_copy_msg(struct mailbox *mbox, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext);

/* SMTP processor callbacks */

#define SMTP_MSG_DIRECTION_IN 0
#define SMTP_MSG_DIRECTION_OUT 1

struct smtp_msg_process {
	/* Inputs */
	int fd;						/*!< File descriptor of SMTP session */
	struct mailbox *mbox;		/*!< Mailbox (incoming only) */
	struct bbs_user *user;		/*!< BBS user (outgoing only) */
	struct bbs_node *node;		/*!< BBS node */
	const char *data;			/*!< Email data */
	const char *from;			/*!< Envelope from */
	int size;					/*!< Size of email */
	int userid;					/*!< User ID (outgoing only) */
	unsigned int direction:1;	/*!< 0 = incoming, 1 = outgoing */
	/* Outputs */
	unsigned int bounce:1;		/*!< Whether to send a bounce */
	unsigned int drop:1;		/*!< Whether message should be dropped */
	int res;					/*!< General return code */
	char *newdir;				/*!< New message location (incoming only) */
	char *bouncemsg;			/*!< Bounce message */
	struct stringlist *forward;	/*!< Forwarding addresses */
	char *relayroute;			/*!< Relay route */
};

/*!
 * \brief Register an SMTP processor callback to run on each message received or sent
 * \param cb Callback that should return nonzero to stop processing further callbacks
 */
#define smtp_register_processor(cb) __smtp_register_processor(cb, BBS_MODULE_SELF)

int __smtp_register_processor(int (*cb)(struct smtp_msg_process *mproc), void *mod);

/*! \brief Unregister an SMTP processor previously registered with smtp_register_processor */
int smtp_unregister_processor(int (*cb)(struct smtp_msg_process *mproc));

/*!
 * \brief Run SMTP callbacks for a message (only called by net_smtp)
 */
int smtp_run_callbacks(struct smtp_msg_process *mproc);
