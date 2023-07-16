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

/* Forward declarations */
struct mailbox;
struct bbs_user;
struct bbs_url;
struct bbs_tcp_client;
struct dirent;

/*! \brief RFC 5423 Section 4 message store events */
enum mailbox_event_type {
	/* Message Addition and Deletion */
	EVENT_MESSAGE_APPEND = (1 << 0),			/*!< Message(s) appended */
	EVENT_MESSAGE_EXPIRE = (1 << 1),			/*!< Message(s) expired */
	EVENT_MESSAGE_EXPUNGE = (1 << 2),			/*!< Message(s) expunged */
	EVENT_MESSAGE_NEW = (1 << 3),				/*!< Message delivered */
	EVENT_QUOTA_EXCEED = (1 << 4),				/*!< Operation failed due to exceeding quota */
	EVENT_QUOTA_WITHIN = (1 << 5),				/*!< Quota usage is now under the quota limit */
	EVENT_QUOTA_CHANGE = (1 << 6),				/*!< Quota limit changed. Not currently a supported event. */
	/* Message flag changes */
	EVENT_MESSAGE_READ = (1 << 7),				/*!< Message(s) marked as seen */
	EVENT_MESSAGE_TRASH = (1 << 8),				/*!< Message(s) marked as deleted */
	EVENT_FLAGS_SET = (1 << 9),					/*!< Message(s) had flags added */
	EVENT_FLAGS_CLEAR = (1 << 10),				/*!< Message(s) had flags removed */
	/* Access accounting */
	EVENT_LOGIN = (1 << 11),					/*!< User login */
	EVENT_LOGOUT = (1 << 12),					/*!< User logout */
	/* Mailbox management */
	/*! \note IMAP uses MailboxName to encompass create, delete, and rename */
	EVENT_MAILBOX_CREATE = (1 << 13),			/*!< Mailbox created or newly accessible */
	EVENT_MAILBOX_DELETE = (1 << 14),			/*!< Mailbox deleted or no longer accessible */
	EVENT_MAILBOX_RENAME = (1 << 15),			/*!< Mailbox renamed */
	EVENT_MAILBOX_SUBSCRIBE = (1 << 16),		/*!< Mailbox added to subscription list */
	EVENT_MAILBOX_UNSUBSCRIBE = (1 << 17),		/*!< Mailbox removed from subscription list */
	/* IMAP specific, and none of these are currently supported yet, since the underlying extensions aren't supported yet */
	EVENT_METADATA_CHANGE = (1 << 18),			/*!< Metadata changed (RFC 5464 METADATA) */
	EVENT_SERVER_METADATA_CHANGE = (1 << 19),
	EVENT_ANNOTATION_CHANGE = (1 << 20),		/*!< Message annotation changed */
	/* Internal events (not part of any RFC, only used by the BBS) */
	EVENT_MAILBOX_UIDVALIDITY_CHANGE = (1 << 21)	/*!< UIDVALIDITY reset */
};

/*! \brief Get the name of a mailbox event type */
const char *mailbox_event_type_name(enum mailbox_event_type type);

/*! \brief RFC 5423 Section 5 event parameters */
enum mailbox_event_parameter {
	EVENT_PARAMETER_ADMIN = (1 << 0),				/*!< Message access: authentication identity, if distinct from authorization identity */
	EVENT_PARAMETER_BODYSTRUCTURE = (1 << 1),		/*!< May be included with MessageAppend and MessageNew: BODYSTRUCTURE of message */
	EVENT_PARAMETER_CLIENT_IP = (1 << 2),			/*!< Message access: client IPv4 or IPv6 address */
	EVENT_PARAMETER_CLIENT_PORT = (1 << 3),			/*!< Message access: client port */
	EVENT_PARAMETER_DISK_QUOTA = (1 << 4),			/*!< QuotaExceed, QuotaWithin, QuotaChange: disk quota in KB */
	EVENT_PARAMETER_DISK_USED = (1 << 5),			/*!< QuotaExceed, QuotaWithin: quota used in KB */
	EVENT_PARAMETER_ENVELOPE = (1 << 6),			/*!< May be included with MessageNew: SMTP envelope */
	EVENT_PARAMETER_FLAG_NAMES = (1 << 7),			/*!< FlagsSet, FlagsClear: (space separated) list of flags/keywords added/removed */
	EVENT_PARAMETER_MAILBOX_ID = (1 << 8),			/*!< MailboxRename and mailbox affecting effects. URI describing mailbox */
	EVENT_PARAMETER_MAX_MESSAGES = (1 << 9),		/*!< QuotaExceed, QuotaWithin: limit on # of messages in a mailbox */
	EVENT_PARAMETER_MESSAGE_CONTENT = (1 << 10),	/*!< May be included with MessageAppend, MessageNew: entire message */
	EVENT_PARAMETER_MESSAGE_SIZE = (1 << 11),		/*!< May be included with MessageAppend, MessageNew: size of message */
	EVENT_PARAMETER_MESSAGES = (1 << 12),			/*!< QuotaExceed, QuotaWithin: Number of messages in mailbox */
	EVENT_PARAMETER_MODSEQ = (1 << 13),				/*!< Any single-message notification */
	EVENT_PARAMETER_OLD_MAILBOX_ID = (1 << 14),		/*!< URI for old name of renamed mailbox */
	EVENT_PARAMETER_PID = (1 << 15),				/*!< Process ID */
	EVENT_PARAMETER_PROCESS = (1 << 16),			/*!< Process name */
	EVENT_PARAMETER_SERVER_DOMAIN = (1 << 17),		/*!< Login, optionally Logout: local domain name or IP address used for access */
	EVENT_PARAMETER_SERVER_PORT	= (1 << 18),		/*!< Login, optionally Logout: local port number used for access */
	EVENT_PARAMETER_SERVER_FQDN = (1 << 19),		/*!< FQDN of server generating event */
	EVENT_PARAMETER_SERVICE = (1 << 20),			/*!< Name of event-triggering service */
	EVENT_PARAMETER_TAGS = (1 << 21),				/*!< Tags */
	EVENT_PARAMETER_TIMESTAMP = (1 << 22),			/*!< Timestamp */
	EVENT_PARAMETER_UIDNEXT = (1 << 23),			/*!< Any mailbox-related notification: UIDNEXT */
	EVENT_PARAMETER_UIDSET = (1 << 24),				/*!< MessageExpires, MessageExpunges, MessageRead, MessageTrash, FlagsSet, FlagsClear: set of UIDs */
	EVENT_PARAMETER_URI = (1 << 25),				/*!< All notifications: IMAP URL */
	EVENT_PARAMETER_USER = (1 << 26),				/*!< Message access: Authorization identifier used */
};

struct mailbox_event {
	enum mailbox_event_type type;	/*!< Type of event */
	struct bbs_node *node;			/*!< Client that triggered the operation (includes IP, port, protocol, user) */
	struct mailbox *mbox;			/*!< Mailbox for event */
	const char *maildir;			/*!< Maildir for event */
	/* uid and uids/numuids are mutually exclusive: a list may be provided, or a single UID, or neither */
	unsigned int *uids;				/*!< UID(s) of messages */
	unsigned int *seqnos;			/*!< Sequence numbers of messages */
	int numuids;					/*!< Number of UIDs/seqnos in uids and seqnos list */
	unsigned long modseq;			/*!< MODSEQ */
	size_t msgsize;					/*!< RFC822 SIZE */
	const char *flagnames;			/*!< Flag names, for FlagsSet and FlagsClear */
	unsigned int messageaccess:1;	/*!< If client is using a message access protocol */
	/* Automatic properties */
	unsigned long id;				/*!< Event ID */
	time_t timestamp;				/*!< Event time */
	/* Computed properties */
	unsigned int uidvalidity;		/*!< UIDVALIDITY of mailbox */
	unsigned int uidnext;			/*!< UIDNEXT of message */
	/* Module specific flags */
	unsigned int expungesilent:1;	/*!< net_imap EXPUNGE/CLOSE: Do not send untagged EXPUNGE responses */
	const char *oldmaildir;			/*!< net_imap RENAME: Old mailbox name */
};

#define mailbox_register_watcher(callback) __mailbox_register_watcher(callback, BBS_MODULE_SELF)

/*! \brief Register a mailbox watching application (intended for IMAP) */
int __mailbox_register_watcher(void (*callback)(struct mailbox_event *event), void *mod);

/*! \brief Unregister a mailbox watching application */
int mailbox_unregister_watcher(void (*callback)(struct mailbox_event *event));

/*!
 * \brief Broadcast a mailbox event
 * \param event Mailbox event
 */
void mailbox_dispatch_event(struct mailbox_event *event);

/*!
 * \brief Initialize basic properties of a mailbox event
 * \param[out] e Initialized event. The event will be zeroed and have attributes set to the other parameters.
 * \param[in] node
 * \param[in] mbox
 * \param[in] maildir
 * \note This is purely a convenience function, useful for many events, but is not needed to create and dispatch an event
 */
void mailbox_initialize_event(struct mailbox_event *e, enum mailbox_event_type type, struct bbs_node *node, struct mailbox *mbox, const char *maildir);

/*!
 * \brief Convenience function to dispatch an event for simple events
 * \param type Event type
 * \param node
 * \param mbox
 * \param maildir
 */
void mailbox_dispatch_event_basic(enum mailbox_event_type type, struct bbs_node *node, struct mailbox *mbox, const char *maildir);

/*!
 * \brief Indicate a message has been delivered to a mailbox
 * \param node Client node that triggered this notification
 * \param mbox
 * \param maildir Maildir directory
 * \param newfile Full path of new message
 * \param size Length of message in bytes
 * \note This will also set the activity flag for the mailbox.
 */
void mailbox_notify_new_message(struct bbs_node *node, struct mailbox *mbox, const char *maildir, const char *newfile, size_t size);

/*!
 * \brief Indicate quota is exceeded for a mailbox
 * \param node
 * \param mbox
 */
void mailbox_notify_quota_exceeded(struct bbs_node *node, struct mailbox *mbox);

/*! \brief Get the uidvalidity parameter of a mailbox event */
unsigned int mailbox_event_uidvalidity(struct mailbox_event *e);

/*! \brief Get the uidnext parameter of a mailbox event */
unsigned int mailbox_event_uidnext(struct mailbox_event *e);

/*!
 * \brief Check if a mailbox has activity (this includes any maildir in the mailbox)
 * \retval 1 if mailbox has activity, 0 if not
 * \note Calling this function will clear the activity flag so multiple simultaneous calls will not all return 1
 */
int mailbox_has_activity(struct mailbox *mbox);

/*!
 * \brief Check whether an SMTP domain or domain literal matches a local domain or hostname
 * \param domain Domain or IP address
 * \param addr Domain or domain literal (enclosed in [] for IP addresses)
 * \retval 1 if matches
 * \retval 0 if doesn't match
 */
int smtp_domain_matches(const char *domain, const char *addr);

/*! \brief Check whether a particular domain's mail is handled local to the BBS */
int mail_domain_is_local(const char *domain);

/*!
 * \brief Get a mailbox by BBS username
 * \param username The user's username
 * \retval mailbox on success, NULL on failure
 */
#define mailbox_get_by_username(username) mailbox_get_by_name(username, NULL)

/*!
 * \brief Get a mailbox by email address
 * \param user The user portion of the address
 * \param domain The domain portion of the address
 * \retval mailbox on success, NULL on failure
 */
struct mailbox *mailbox_get_by_name(const char *user, const char *domain);

/*!
 * \brief Get a mailbox by user ID
 * \param userid The user ID of the target mailbox
 * \retval mailbox on success, NULL on failure
 */
struct mailbox *mailbox_get_by_userid(unsigned int userid);

/*!
 * \brief Get all the destination addresses for a listserv
 * \param user User portion of address
 * \param domain Domain portion of address
 * \returns list of addresses, NULL if address does not resolve to a mailing list
 */
const char *mailbox_expand_list(const char *user, const char *domain);

/*!
 * \brief Attempt to obtain a read lock on mailbox
 * \param mbox
 * \retval 0 on success (lock obtained), error number otherwise
 * \note IMAP operations may use this function
 */
int mailbox_rdlock(struct mailbox *mbox);

/*!
 * \brief Attempt to obtain a write lock on mailbox
 * \param mbox
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

/*! \brief Invalidate the cached quota usage for this mailbox */
void mailbox_invalidate_quota_cache(struct mailbox *mbox);

/*!
 * \brief Manually adjust the quota usage of a mailbox
 * \param mbox
 * \param bytes Positive number to increase quota usage or negative number to decrease quota usage
 */
void mailbox_quota_adjust_usage(struct mailbox *mbox, int bytes);

/*! \brief Get the quota limit of a mailbox in bytes */
unsigned long mailbox_quota(struct mailbox *mbox);

/*! \brief Get the quota usage of a mailbox in bytes */
unsigned long mailbox_quota_used(struct mailbox *mbox);

/*! \brief Get the quota remaining (available) of a mailbox in bytes */
unsigned long mailbox_quota_remaining(struct mailbox *mbox);

/*!
 * \brief Get the maildir of a mailbox
 * \param mbox Mailbox. If NULL, the top-level maildir path will be returned.
 */
const char *mailbox_maildir(struct mailbox *mbox);

/*! \brief Get the string length of a mailbox's maildir */
size_t mailbox_maildir_len(struct mailbox *mbox);

/*!
 * \brief Get the mailbox ID of a mailbox for personal mailboxes (same as the user ID of the user that owns this mailbox)
 * \param mbox Mailbox. Must not be NULL.
 * \return positive mailbox ID, for personal mailboxes
 * \retval 0 if not a personal mailbox
 */
int mailbox_id(struct mailbox *mbox);

/*!
 * \brief Get the mailbox name of a mailbox for non-personal mailboxes
 * \param mbox Mailbox. Must not be NULL.
 * \return Mailbox name, if non-personal
 * \retval NULL, if personal
 */
const char *mailbox_name(struct mailbox *mbox);

/*!
 * \brief Get a unique prefix ID for the mailbox (across all mailboxes)
 * \param[in] mbox Mailbox. Must not be NULL.
 * \param[out] buf Buffer in which to store unique prefix.
 * \param[in] len Length of buf.
 * \retval 0 on success, -1 on failure
 */
int mailbox_uniqueid(struct mailbox *mbox, char *buf, size_t len);

/*!
 * \brief Get the maximum number of messages permitted in a mailbox (any maildir in the mailbox)
 * \return Maximum number of messages allowed in a mailbox
 */
unsigned long mailbox_max_messages(struct mailbox *mbox);

/*!
 * \brief Ensure that maildir directories exist in the specified directory
 * \retval 0 on success, -1 on failure
 */
int mailbox_maildir_init(const char *path);

/*!
 * \brief Whether a maildir is a mailbox (as opposed to some kind of special system maildir)
 * \param basename Base name of directory inside the root maildir
 * \retval 1 maildir is a mailbox (either personal or shared)
 * \retval 0 maildir is a special system maildir
 */
int maildir_is_mailbox(const char *basename);

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
 * \param node
 * \param directory Full system path of directory
 * \param allocate Whether to generate a new valid message UID or simply returning the current maximum UID value
 * \param[out] newuidvalidity The UIDVALIDITY of this directory
 * \param[out] newuidnext The current maximum UID in this directory (this is somewhat of a misnomer, you need to add 1 to compute the actual UIDNEXT)
 * \retval 0 on failure, otherwise the current maximum or newly allocated UID (depending on the allocate argument)
 * \note This operation is used by both the IMAP and POP3 servers, although UIDs are only relevant for IMAP.
 *       POP3 calls this function to ensure consistency for IMAP operations.
 * \note This operation internally maintains the .uidvalidity of a maildir directory.
 * \todo This function should really be renamed maildir_get_next_uid, it's a maildir function, not a mailbox function. Currently, it's a misnomer.
 */
unsigned int mailbox_get_next_uid(struct mailbox *mbox, struct bbs_node *node, const char *directory, int allocate, unsigned int *newuidvalidity, unsigned int *newuidnext);

/*!
 * \brief Indicate a sequence of expunges
 * \param type (either EVENT_MESSAGE_EXPUNGE or EVENT_MESSAGE_EXPIRE)
 * \param mbox
 * \param directory Full system path of the cur directory for this maildir
 * \param uids A list of message UIDs for expunged messages
 * \param seqnos A list of sequence numbers for expunged messages
 * \param length Number of expunged messages in the list
 * \param silent For IMAP, 1 to inhibit untagged EXPUNGE responses, 0 otherwise
 * \retval The new HIGHESTMODSEQ for the mailbox
 * \note For performance reasons, calls to this function should be batched if possible (which is why it takes a list, rather than only a single UID)
 * \note This function MUST be called whenever messages are expunged from a directory, by IMAP, POP3, or SMTP
 */
unsigned long maildir_indicate_expunged(enum mailbox_event_type type, struct bbs_node *node, struct mailbox *mbox, const char *directory, unsigned int *uids, unsigned int *seqnos, int length, int silent);

/*!
 * \brief Get the highest MODSEQ (modification sequence number) in a maildir
 * \param mbox Mailbox
 * \param directory Full system path of the cur directory for this maildir
 * \retval 0 on failure or no assigned MODSEQs currently, positive number for max MODSEQ currently assigned
 */
unsigned long maildir_max_modseq(struct mailbox *mbox, const char *directory);

/*!
 * \brief Retrieve all messages in a mailbox expunged since a certain MODSEQ
 * \param directory Full system path of the cur directory for this maildir
 * \param lastmodseq MODSEQ to use for comparisons
 * \param uidrangebuf A buffer that is the same size as uidrange, used as scratch space
 * \param minuid Minimum UID to match
 * \param uidrange Range of UIDs in request
 * \return NULL on failure or no results, list of UIDs otherwise
 */
char *maildir_get_expunged_since_modseq(const char *directory, unsigned long lastmodseq, char *uidrangebuf, unsigned int minuid, const char *uidrange);

/*!
 * \brief Get a modification sequence suitable for assigning to a new (e.g. APPEND, COPY, MOVE), new -> cur message
 * \param mbox
 * \param directory The full path to the /cur directory of the maildir
 * \retval A modification sequence higher than any other for this directory
 */
unsigned long maildir_new_modseq(struct mailbox *mbox, const char *directory);

/*!
 * \brief Move a message from the new directory to the cur directory, atomically
 * \param mbox Mailbox
 * \param node
 * \param dir Full system path to the active maildir directory
 * \param curdir Full system path to cur directory (should be an immediate subdirectory of dir)
 * \param newdir Full system path to new directory (should be an immediate subdirectory of dir)
 * \param filename The original name (just the name, not the full path) of the message file in the new directory
 * \param[out] uidvalidity The UIDVALIDITY of this directory
 * \param[out] uidnext The current maximum UID in this directory (this is somewhat of a misnomer, you need to add 1 to compute the actual UIDNEXT)
 * \retval -1 on failure, number of bytes in file on success (useful for POP3)
 */
int maildir_move_new_to_cur(struct mailbox *mbox, struct bbs_node *node, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext);

/*!
 * \brief Move a message from the new directory to the cur directory, atomically
 * \param mbox Mailbox
 * \param node
 * \param dir Full system path to the active maildir directory
 * \param curdir Full system path to cur directory (should be an immediate subdirectory of dir)
 * \param newdir Full system path to new directory (should be an immediate subdirectory of dir)
 * \param filename The original name (just the name, not the full path) of the message file in the new directory
 * \param[out] uidvalidity The UIDVALIDITY of this directory
 * \param[out] uidnext The current maximum UID in this directory (this is somewhat of a misnomer, you need to add 1 to compute the actual UIDNEXT)
 * \param[out] newpath The resulting new filename
 * \param len Length of newpath
 * \retval -1 on failure, number of bytes in file on success (useful for POP3)
 */
int maildir_move_new_to_cur_file(struct mailbox *mbox, struct bbs_node *node, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext, char *newpath, size_t len);

/*!
 * \brief Move a message from one maildir to another maildir (including a subdirectory of the same account), adjusting the UID as needed
 * \param mbox Mailbox
 * \param node
 * \param curfile Full path to current file
 * \param curfilename The base name of the current file
 * \param destmaildir The directory path of the maildir to which the message should be moved (do not include new or cur at the end)
 * \param[out] uidvalidity The new UIDVALIDITY of the destination maildir
 * \param[out] uidnext The new max UID of the destination maildir
 * \retval 0 on failure, UID of new message file on success
 */
int maildir_move_msg(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext);

/*!
 * \brief Move a message from one maildir to another maildir (including a subdirectory of the same account), adjusting the UID as needed
 * \param mbox Mailbox
 * \param node
 * \param curfile Full path to current file
 * \param curfilename The base name of the current file
 * \param destmaildir The directory path of the maildir to which the message should be moved (do not include new or cur at the end)
 * \param[out] uidvalidity The new UIDVALIDITY of the destination maildir
 * \param[out] uidnext The new max UID of the destination maildir
 * \param[out] newfile The new filename of the message
 * \param len Size of newfile
 * \retval 0 on failure, UID of new message file on success
 */
int maildir_move_msg_filename(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newfile, size_t len);

/*! \brief Same as maildir_move_msg, but deep copy the message instead of moving it. The original file is left intact. */
int maildir_copy_msg(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext);

/*! \brief Same as maildir_copy_msg, but also store the new filename of the message, like maildir_move_msg_filename */
int maildir_copy_msg_filename(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newfile, size_t len);

/*!
 * \brief Get the UID of a maildir file in cur directory
 * \param filename Base name of file
 * \param[out] uid
 * \retval 0 on success, -1 on failure
 */
int maildir_parse_uid_from_filename(const char *filename, unsigned int *uid);

/*!
 * \brief Sort callback for scandir (for maildirs)
 * \note This function may not be specified as a callback parameter inside modules (outside of mod_mail) directly,
 *       because RTLD_LAZY does not ignore unresolved data arguments, only unresolved functions.
 *       See comments at top of nets/net_imap/imap_server_maildir.c
 */
int uidsort(const struct dirent **da, const struct dirent **db);

/*! \brief Perform an ordered traversal of a maildir cur directory */
int maildir_ordererd_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, int seqno, void *obj), void *obj);

/* IMAP client */
#define IMAP_CLIENT_EXPECT(client, s) if (bbs_tcp_client_expect(client, "\r\n", 1, 2000, s)) { bbs_debug(3, "Didn't receive expected '%s'\n", s); goto cleanup; }
#define IMAP_CLIENT_SEND(client, fmt, ...) bbs_tcp_client_send(client, fmt "\r\n", ## __VA_ARGS__);

#define IMAP_CAPABILITY_IDLE (1 << 0)
#define IMAP_CAPABILITY_CONDSTORE (1 << 1)
#define IMAP_CAPABILITY_ENABLE (1 << 2)
#define IMAP_CAPABILITY_QRESYNC (1 << 3)
#define IMAP_CAPABILITY_SASL_IR (1 << 4)
#define IMAP_CAPABILITY_LITERAL_PLUS (1 << 5)
#define IMAP_CAPABILITY_LITERAL_MINUS (1 << 6)
#define IMAP_CAPABILITY_AUTH_PLAIN (1 << 7)
#define IMAP_CAPABILITY_AUTH_XOAUTH (1 << 8)
#define IMAP_CAPABILITY_AUTH_XOAUTH2 (1 << 9)
#define IMAP_CAPABILITY_ACL (1 << 10)
#define IMAP_CAPABILITY_QUOTA (1 << 11)
#define IMAP_CAPABILITY_LIST_EXTENDED (1 << 12)
#define IMAP_CAPABILITY_SPECIAL_USE (1 << 13)
#define IMAP_CAPABILITY_LIST_STATUS (1 << 14)
#define IMAP_CAPABILITY_STATUS_SIZE (1 << 15)
#define IMAP_CAPABILITY_UNSELECT (1 << 16)
#define IMAP_CAPABILITY_SORT (1 << 17)
#define IMAP_CAPABILITY_THREAD_ORDEREDSUBJECT (1 << 18)
#define IMAP_CAPABILITY_THREAD_REFERENCES (1 << 19)
#define IMAP_CAPABILITY_MOVE (1 << 20)
#define IMAP_CAPABILITY_BINARY (1 << 21)

/*!
 * \brief Log in to a remote IMAP server
 * \param client TCP client
 * \param url IMAP URL
 * \param user Currently authenticated user, used to control what OAuth profiles can be used
 * \param[out] capsptr Remote server's IMAP capabilities
 * \retval 0 on success, -1 on failure
 */
int imap_client_login(struct bbs_tcp_client *client, struct bbs_url *url, struct bbs_user *user, int *capsptr);

/* Sieve integration */

/*!
 * \brief Register a Sieve implementation
 * \param validate A callback that will validate a Sieve script and return 0 if valid, 1 if invalid, and -1 on failure
 * \param capabilities A dynamically allocated string of Sieve capabilities. The caller should never free this.
 * \note This does not register the Sieve implementation with the SMTP server to actually filter mail. Use smtp_register_processor to do that.
 *       The callbacks here are only used for the ManageSieve service.
 * \retval 0 on success, -1 on failure (e.g. another Sieve implementation already registered)
 */
#define sieve_register_provider(validate, capabilities) __sieve_register_provider(validate, capabilities, BBS_MODULE_SELF)

int __sieve_register_provider(int (*validate)(const char *filename, struct mailbox *mbox, char **errormsg), char *capabilities, void *mod);

/*! \brief Unregister a previously registered Sieve implementation */
int sieve_unregister_provider(int (*validate)(const char *filename, struct mailbox *mbox, char **errormsg));

/*!
 * \brief Get list of Sieve capabilities
 * \returns NULL on failure, capability list on success that must be freed
 */
char *sieve_get_capabilities(void);

/*!
 * \brief Validate a Sieve script
 * \param filename Full path to file containing Sieve script
 * \param mbox
 * \param[out] errormsg error message for user, which must be freed
 * \retval 0 if valid, 1 if invalid, -1 on error or failure
 */
int sieve_validate_script(const char *filename, struct mailbox *mbox, char **errormsg);

/* SMTP processor callbacks */

#define SMTP_MSG_DIRECTION_IN 0
#define SMTP_MSG_DIRECTION_OUT 1

struct smtp_msg_process {
	/* Inputs */
	int fd;						/*!< File descriptor of SMTP session */
	struct mailbox *mbox;		/*!< Mailbox (incoming only) */
	struct bbs_user *user;		/*!< BBS user (outgoing only) */
	struct bbs_node *node;		/*!< BBS node */
	char datafile[128];			/*!< Name of email data file */
	FILE *fp;					/*!< Email data file (used internally only) */
	const char *from;			/*!< Envelope from */
	const char *recipient;		/*!< Envelope to - only for INCOMING messages */
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
