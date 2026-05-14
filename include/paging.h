/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Generic Paging Interface
 *
 */

/*
 * Note: This is a generic paging interface used for both the
 * (relatively simple) TAP/IXO protocol and the richer SNPP protocol.
 * The actual "terminal" functionality to handle receipt and delivery
 * of pages is not in paging.c, but provided by paging provider modules.
 */

#include "include/linkedlists.h"

/*! \brief Pager type and special properties */
enum pager_type {
	PAGER_TONE_ONLY = (1 << 0),
	PAGER_NUMERIC = (1 << 1),
	PAGER_ALPHANUMERIC = (1 << 2),
	/* Other modifiers */
	PAGER_TWOWAY = (1 << 8),
};

enum pager_requirements {
	PAGER_REQ_TWOWAY = (1 << 0),
};

/* Note: It is assumed this only requires 3 bits, update struct bbs_paging_data if this changes */
/* Protocol handling is slightly bifurcated.
 * mod_paging (PAGING_PROT_DEFAULT) handles most functionality for all protocols,
 * and then farms out specific sending work to other handlers
 * using one of the other values. */
enum paging_protocol {
	PAGING_PROT_DEFAULT = 0,		/*!< Dummy protocol for mod_paging. Intentionally 0 so it's the default after memset. */
	PAGING_PROT_SNPP = (1 << 0),	/*!< Simple Network Paging Protocol */
	PAGING_PROT_SMTP = (1 << 1),	/*!< Simple Mail Transfer Protocol */
	PAGING_PROT_TAP_IXO = (1 << 2),	/*!< Telocator Alphanumeric Protocol (TAP/IXO) */
};

/*! \brief Paging recipient optiosn */
struct bbs_paging_options {
	/* Level 2 */
	int level;				/*!< Level of service (0-11) */
	int coverage;			/*!< Coverage area */
	time_t holduntil;		/*!< Hold message for delivery until this time */
	unsigned int alert:1;	/*!< Alert subscriber upon receipt of message */
	/* Whether settings with non-0 defaults were actually set,
	 * this way we can just memset this structure to reset it) */
	unsigned int level_set:1;
	unsigned int coverage_set:1;
};

/*! \brief Paging message data and options */
struct bbs_paging_data {
	/* Level 1 */
	char *message;								/*!< Single-line message */
	/* Level 2 */
	char *body;									/*!< Multi-line message */
	char *subject;								/*!< Subject */
	char *callerid;								/*!< Caller ID or From header */
	/* Level 3: Two-Way Options */
	int expiry;				/*!< Expiry hours */
	unsigned int twoway:1;	/*!< Two-way paging */
	unsigned int noqueue:1;	/*!< Do not queue, either send immediately or reject */
	unsigned int readack:1;	/*!< Read acknowledgment */
	/* Other */
	enum paging_protocol prot:3;	/*!< Not set outside of mod_paging, will default to PAGING_PROT_DEFAULT */
	struct bbs_node *node;	/*!< Node associated with this transaction, if any. Network protocol handlers should set this. */
	const char *gateway;	/*!< Field for mod_paging to pass the server hostname / phone number to other paging modules */
};

/*! \brief Free any allocated strings in a bbs_paging_data struct */
void bbs_paging_data_free_contents(struct bbs_paging_data *data);

/*! \brief A single paging recipient */
struct bbs_paging_recipient {
	/* Level 1 */
	const char *pagerid;
	/* Level 2 */
	const char *pin;
	struct bbs_paging_options parameters;
	RWLIST_ENTRY(bbs_paging_recipient) entry;
	char data[];
};

enum bbs_paging_message_delivery_status {
	PAGE_DELIVERED = (1 << 0),			/*!< Message delivered. If not set, message is still deferred, in queue (or expired) */
	/* Read/unread flags */
	PAGE_AWAITING_READACK = (1 << 4),	/*!< Awaiting read ack */
	PAGE_READ =	(1 << 5),				/*!< Message read */
	/* Reply flags */
	PAGE_AWAITING_REPLY = (1 << 6),		/*!< Awaiting reply (MCR) */
	PAGE_REPLY_RECEIVED_MC = (1 << 7),	/*!< MC reply received */
	PAGE_REPLY_RECEIVED_TEXT = (1 << 8),	/*!< Text reply received */
};

#define PAGE_REPLY_RECEIVED (PAGE_REPLY_RECEIVED_MC | PAGE_REPLY_RECEIVED_TEXT)

#define PAGE_MESSAGE_TAG_LENGTH 12
#define PAGE_MESSAGE_PASSCODE_LENGTH 8

struct bbs_paging_message_metadata {
	enum bbs_paging_message_delivery_status status;	/*!< Output: Current delivery status of a message that was accepted */
	time_t timestamp;								/*!< Output: Time of last status change */
	char msgtag[PAGE_MESSAGE_TAG_LENGTH + 1];		/*!< Input/Output: Message Tag, for future lookups */
	char passcode[PAGE_MESSAGE_PASSCODE_LENGTH + 1];/*!< Input/Output: Pass Code, for future lookups */
	/* Only set for MSTA, not SEND */
	const char *response;							/*!< Output: Reply received, if PAGE_REPLY_RECEIVED is set */
};

RWLIST_HEAD(bbs_paging_recipients, bbs_paging_recipient);

#define PAGING_TIMESTAMP_LENGTH 32

/*!
 * \brief Generate a timestamp string in YYMMDDHHMMSS+T format, e.g. 950925143501+12
 * \param[in] timestamp
 * \param[out] buf
 * \param[in] len Size of buf. Should be at least PAGING_TIMESTAMP_LENGTH.
 * \retval 0 on success, -1 on failure
 */
int bbs_paging_timestamp(time_t timestamp, char *buf, size_t len);

/*! \brief Whether paging is currently possible (i.e. any paging providers are registered) */
int bbs_paging_available(void);

/*!
 * \brief Whether a pager ID exists
 * \param[in] pagerid Pager ID
 * \param[out] type If recipient exists, mask of type flags
 * \param[in] requirements Special requirements in order to return a successful match
 * \retval 1 if valid recipient
 * \retval 0 if invalid recipient
 * \retval -1 if valid recipient, but with caveat or invalid in this case, with errno set as follows:
 *   ECHILD - No paging providers registered (tell client to retry later, disconnect now)
 *  (Two-way pager error codes, only returned if requirements includes PAGER_REQ_TWOWAY
 *   ENETDOWN - Two-way pager not online, transaction denied
 *   ENOTCONN - Two-way pager not online, will be queued for later delivery (Note: This should be processed as success!!!!!!!!!)
 *   EPROTOTYPE - Pager not two-way capable
 * \note If -1 is returned, it may indicate success OR failure, you must check errno!
 */
int bbs_pager_exists(const char *pagerid, enum pager_type *type, enum pager_requirements requirements);

/*!
 * \brief Ping a two-way pager to get its location and/or status
 * \param[in] pagerid Pager ID
 * \param[out] buf Buffer in which to store Locus Code. Set only on success (return 0)
 * \param[in] len Length of buf
 * \retval 0 on success
 * \retval -1 on error or modified success, with errno set as follows:
 *   ECHILD - No paging providers registered (tell client to retry later, disconnect now)
 *   ENOSYS - Command Not implemented
 *   EIDRM - Unit on system, but no location information available (ACLU mode)
 *   ENETDOWN - Unit valid, not online at this time
 *   ENOTCONN - Two-way pager not online but can queue message for later delivery
 *   ENOTTY - Can't ping, unit not 2-way capable
 *   EINVAL - Illegal pager ID
 *   ENOENT - Invalid pager ID
 * \note If -1 is returned, it may indicate success OR failure, you must check errno!
 */
int bbs_pager_ping(const char *pagerid, char *buf, size_t len);

/*
 * For functions that return -1 and set errno, it will be set as follows:
 *   ENXIO - Desired paging protocol unavailable (only used by mod_paging)
 *   ENOENT - No such pager ID
 *   EAGAIN - Temporary delivery failure, retry later
 *   ECHILD - No paging providers registered (tell client to retry later, disconnect now)
 *   ENOSYS - Command not implemented
 *   EACCES - PIN required to page this number, correct PIN not provided
 *   EINVAL - Illegal pager ID format
 *   EDOM - Tone-only pager, no message allowed
 *   ERANGE - Numeric paging only, no alphabetic characters allowed
 *   EMSGSIZE - Long message rejected, exceeds max character length
 *   EDQUOT - Message quota temporarily exceeded
 */

/*!
 * \brief Page a single recipient
 * \param[in] recipient Recipient to page
 * \param[in] data Paging data. Its fields will not be modified.
 * \param[out] Message delivery status, on success
 * \note Caller is responsible for cleaning up data passed to this function
 * \retval 0 on success, -1 on failure (errno set as noted above)
 */
int bbs_page_single(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta);

/*!
 * \brief Page a single recipient
 * \param[in] recipients Recipients to page
 * \param[in] data Paging data. Its fields will not be modified.
 * \param[out] Message delivery status, on success
 * \note recipients is not modified, and caller is still responsible for cleaning up data passed to this function
 * \retval 0 on success, -1 on failure (errno set as noted above)
 */
int bbs_page_multiple(struct bbs_paging_recipients *recipients, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta);

/*!
 * \brief Check the status of a page that has been sent (primarily used for two-way pages)
 * \param meta Message tag and pass code (the status field does not need to be set when passed in, but will be filled in upon return)
 * \retval 0 on success. meta->status has been updated with the current status.
 * \retval -1 on error, with errno set as follows:
 *   ECHILD - No paging providers registered (tell client to retry later, disconnect now)
 *   ENOSYS - Command Not implemented
 *   EINVAL - Invalid message tag or pass code
 *   EACCES - Wrong passcode
 *   ETIMEDOUT - Message expired prior to delivery
 */
int bbs_paging_message_status(struct bbs_paging_message_metadata *meta);

/*!
 * \brief Courteously expire a message tag (primarily used for two-way pages)
 * \param meta Message tag and pass code (the status field does not need to be set when passed in, but will be filled in upon return)
 * \retval 0 on success. meta->status has been updated with the current status.
 * \retval -1 on error, with errno set as follows:
 *   ECHILD - No paging providers registered (tell client to retry later, disconnect now)
 *   ENOSYS - Command Not implemented
 *   EINVAL - Invalid message tag or pass code
 *   EACCES - Wrong passcode
 */
int bbs_paging_message_expire(struct bbs_paging_message_metadata *meta);

/*
 * Note for paging providers:
 * data must not be modified
 * recipients can be modified only to remove/free elements from the recipients list to indicate those have been handled.
 *
 * Paging callbacks should return values (and set errno, if needed) as indicated in the documentation
 * for the function above to which the callback corresponds: */

struct bbs_paging_callbacks {
	/* Return if a pager exists (is serviced by this provider), and what type */
	int (*pager_exists)(const char *pagerid, enum pager_type *type, enum pager_requirements req);
	/* Ping a two-way pager */
	int (*pager_ping)(const char *pagerid, char *buf, size_t len);
	/* Page a single recipient. If your handler doesn't handle the recipient, set errno to ENOENT and return -1 */
	int (*page_single)(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta);
	/* Page multiple recipients. This callback is optional, but can provide greater efficiency.
	 * This handler (but not page_single) is responsible for removing any recipients
	 * for which delivery succeeded (remove from recipients list, and then free using free()) */
	int (*page_multiple)(struct bbs_paging_recipients *recipients, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta);
	/* Check the status of a sent page (for two-way paging) */
	int (*page_status)(struct bbs_paging_message_metadata *meta);
	/* Expire the status of a sent page (for two-way paging) */
	int (*page_expire)(struct bbs_paging_message_metadata *meta);
};

/*!
 * \brief Register a paging provider
 * \param cb Paging callbacks
 * \param priority Priority for callback precedence (like with MX, lower is more important). Should be 1 if PAGING_PROT_DEFAULT, >= 2 if not
 * \param protocols Protocol support
 * \retval 0 on success, -1 on failure
 * \note Multiple paging providers can register, but they are expected to service mutually exclusive sets of recipients
 */
#define bbs_register_paging_provider(cb, priority, protocols) __bbs_register_paging_provider(cb, priority, protocols, BBS_MODULE_SELF)

int __bbs_register_paging_provider(struct bbs_paging_callbacks *cb, int priority, enum paging_protocol protocols, void *mod);

/*!
 * \brief Unregister a paging provider
 * \param cb
 * \retval 0 on success, -1 on failure
 */
int bbs_unregister_paging_provider(struct bbs_paging_callbacks *cb);

int bbs_paging_init(void);
