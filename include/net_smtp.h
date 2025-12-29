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
 * \brief RFC5321 Simple Mail Transfer Protocol (SMTP)
 *
 */

/* Needed since struct smtp_filter_data declares a stack-allocated stringlist.
 * We do this to avoid needing to handle allocation failure if we were to allocate it. */
#include "include/stringlist.h"

/* SMTP relay port (mail transfer agents) */
#define DEFAULT_SMTP_PORT 25

/* Mainly for encrypted SMTP message submission agents, though not explicitly in the RFC */
#define DEFAULT_SMTPS_PORT 465

/* Mainly for message submission agents, not encrypted by default, but may use STARTTLS */
#define DEFAULT_SMTP_MSA_PORT 587

/* RFC 2822 2.1.1: Max line length (not including CR LF) */
#define SMTP_MAX_LINE_LENGTH 998

/* Adds on CR, LF, and NUL */
#define SMTP_MAX_BUFSIZE 1001

#define _smtp_reply(smtp, fmt, ...) \
	bbs_debug(6, "%p <= " fmt, smtp, ## __VA_ARGS__); \
	bbs_auto_fd_writef(smtp_node(smtp), smtp_node(smtp) ? smtp_node(smtp)->wfd : -1, fmt, ## __VA_ARGS__); \

/*! \brief Final SMTP response with this code */
#define smtp_resp_reply(smtp, code, subcode, reply) _smtp_reply(smtp, "%d %s %s\r\n", code, subcode, reply)
#define smtp_reply(smtp, code, status, fmt, ...) _smtp_reply(smtp, "%d %s " fmt "\r\n", code, #status, ## __VA_ARGS__)
#define smtp_reply_nostatus(smtp, code, fmt, ...) _smtp_reply(smtp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

/*! \brief Non-final SMTP response (subsequent responses with the same code follow) */
#define smtp_reply0_nostatus(smtp, code, fmt, ...) _smtp_reply(smtp, "%d-" fmt "\r\n", code, ## __VA_ARGS__)

struct smtp_session;

void __attribute__ ((format (gnu_printf, 3, 4))) bbs_smtp_log(int level, struct smtp_session *smtp, const char *fmt, ...);

/*! \brief Get the SMTP hostname of the local SMTP server, suitable for use in HELO/EHLO */
const char *smtp_hostname(void);

/*!
 * \brief Whether an external host is allowed to relay mail for a particular domain
 * \param srcip Client IP address
 * \param hostname MAIL FROM domain
 * \retval 1 if explicitly authorized
 * \retval 0 if not authorized
 */
int smtp_relay_authorized(const char *srcip, const char *hostname);

/*!
 * \brief Whether a message is exempt from certain checks due to it being accepted for relay from another MTA
 * \param smtp
 * \retval 1 if exempt
 * \retval 0 if not exempt
 */
int smtp_is_exempt_relay(struct smtp_session *smtp);

/*!
 * \brief Get a timestamp string appropriate for the Received header
 * \param received Received time
 * \param[out] buf
 * \param len Length of buf
 */
void smtp_timestamp(time_t received, char *buf, size_t len);

/* == SMTP filters: these modify the message itself, but (generally) do not determine what will happen to it == */

enum smtp_filter_type {
	SMTP_FILTER_PREPEND = 0, 	/* Prepend headers to the received message (efficient, but only suitable for a narrow range of functions) */
	/* Allow for future expansion, e.g. milters (though this would require hooks at multiple stages, not just after body received) */
};

enum smtp_filter_kind {
	/* Sign/verify */
	SMTP_FILTER_SIGN = (1 << 0),
	SMTP_FILTER_VERIFY = (1 << 1),
	/* Header operations */
	SMTP_FILTER_SPF = (1 << 2),
	SMTP_FILTER_DKIM = (1 << 3),
	SMTP_FILTER_DMARC = (1 << 4),
	SMTP_FILTER_ARC = (1 << 5),
	SMTP_FILTER_SPAM_FILTER = (1 << 6),
	SMTP_FILTER_OTHER = (1 << 7), /* Any other filter */
};

enum smtp_filter_scope {
	SMTP_SCOPE_INDIVIDUAL = (1 << 0),	/* Run individually for each recipient of a message */
	SMTP_SCOPE_COMBINED = (1 << 1),		/* Run once for all recipients of a message */
};

enum smtp_direction {
	SMTP_DIRECTION_SUBMIT = (1 << 0),	/*!< Message submission */
	SMTP_DIRECTION_IN = (1 << 1),		/*!< Incoming mail from another MTA */
	SMTP_DIRECTION_OUT = (1 << 2),		/*!< Outgoing mail to another MTA */
};

#define SMTP_DIRECTION_ALL (SMTP_DIRECTION_SUBMIT | SMTP_DIRECTION_IN | SMTP_DIRECTION_OUT)

/*!
 * \note There are two different "filtering" APIs available,
 * based on the smtp_filter_data (filters) and smtp_msg_process (message processors) structures.
 * They are very similar and they probably could theoretically be combined.
 * That said, there are a few major differences between them as they exist now,
 * that should be considered when deciding which one to use.
 *
 * - The filtering API can modify/rewrite messages. The message processors do not.
 *   Thus, filtering here is probably also more akin to "milters" in standard POSIX MTAs.
 *   This is probably the most important difference. Message processors don't (and can't)
 *   rewrite messages, so they are probably more efficient to run if you don't need to modify the input.
 * - Both can reject messages; message processors have more control over how they are rejected, though filters can quarantine the message.
 * - Both can operation on incoming and outgoing messages to varying degrees.
 * - In practice, message processors are used for "filtering engines" (ironically) - Sieve and MailScript.
 *   "Filters" are used for more traditional milter applications, such as SPF, DKIM, etc. - things that prepend headers to the message.
 * - Other differences exist. Compare the structs and APIs to see what information is available.
 */

/* == SMTP filter callbacks - these receive a message and potentially modify it == */

struct smtp_filter_data {
	struct smtp_session *smtp;		/*!< SMTP session */
	int inputfd;					/*!< File descriptor from which message can be read */
	const char *recipient;			/*!< Recipient (RCPT TO). Only available for SMTP_DIRECTION_IN and SMTP_DIRECTION_SUBMIT, and if the scope is SMTP_SCOPE_INDIVIDUAL */
	size_t size;					/*!< Message length */
	enum smtp_direction dir;		/*!< Direction */
	time_t received;				/*!< Time that message was received */
	/* Duplicated fields: these are simply duplicated from smtp: */
	struct bbs_node *node;			/*!< Node */
	const char *from;				/*!< Envelope from */
	const char *helohost;			/*!< HELO/EHLO hostname */
	/* Set by filter callbacks, but accessible only during filter execution */
	char *spf;						/*!< Allocated SPF header value */
	char *dkim;						/*!< Allocated DKIM results */
	char *dmarc;					/*!< Allocated DMARC results */
	char *arc;						/*!< Allocated ARC results */
	char *authresults;				/*!< Allocated Authentication-Results header */
	/* Set by filter callbacks, and accessible after filter execution */
	unsigned int reject:1;			/*!< Set by filter(s) to TRUE to reject acceptance of message. */
	unsigned int quarantine:1;		/*!< Set by filter(s) to TRUE to quarantine message. */
	/* INTERNAL: Do not access these fields directly. Use the publicly exposed functions. */
	struct stringlist headers;		/*!< Prepended headers that need to be written to the message */
	int outputfd;					/*!< File descriptor to write to, to prepend to message */
	char outputfile[64];			/*!< Temporary output file name */
	char *body;						/*!< RFC822 message as string */
};

struct smtp_filter_provider {
	int (*on_body)(struct smtp_filter_data *data);	/*!< Callback for SMTP_FILTER_PREPEND. Return 0 on success, -1 on failure (continue), 1 to abort further processing. */
};

/*!
 * \brief Register an SMTP filter
 * \param cb Callback function
 * \param name The name of the filter
 * \param kind The kind of filter
 * \param type The type of filter
 * \param scope Scope for which this filter applies
 * \param dir Bitmask of directions for which this filter applies
 * \param priority Priority of filter. Lower-number priorities are executed first.
 * \param mod
 * \retval 0 on success, -1 on failure
 */
int __smtp_filter_register(struct smtp_filter_provider *provider, const char *name, enum smtp_filter_kind kind, enum smtp_filter_type type, enum smtp_filter_scope scope, enum smtp_direction dir, int priority, void *mod);

#define smtp_filter_register(cb, name, kind, type, scope, dir, priority) __smtp_filter_register(cb, name, kind, type, scope, dir, priority, BBS_MODULE_SELF)

/*!
 * \brief Unregister an SMTP filter
 * \param cb
 * \retval 0 on success, -1 on failure
 */
int smtp_filter_unregister(struct smtp_filter_provider *provider);

/*! \brief Get the BBS node of an SMTP session */
struct bbs_node *smtp_node(struct smtp_session *smtp);

/*! \brief Get the upstream IP address */
const char *smtp_sender_ip(struct smtp_session *smtp);

/*! \brief Get HELO/EHLO hostname for session */
const char *smtp_sender_hostname(struct smtp_session *smtp);

/*! \brief Get SMTP protocol used */
const char *smtp_protname(struct smtp_session *smtp);

/*!
 * \brief Get SMTP recipient list from RCPT TO
 * \note Do not use this from user mail filters (e.g. Sieve/MailScript)
 */
struct stringlist *smtp_recipients(struct smtp_session *smtp);

/*! \brief Get the MAIL FROM address */
const char *smtp_from(struct smtp_session *smtp);

/*! \brief Get the From address */
const char *smtp_from_address(struct smtp_session *smtp);

/*! \brief Get the full From header (including name, if present) */
const char *smtp_from_header(struct smtp_session *smtp);

/*! \brief Get the domain of the MAIL FROM address */
const char *smtp_mail_from_domain(struct smtp_session *smtp);

/*!
 * \brief Get the MAIL FROM or From address domain
 * \note This will return the From address domain if a From address is available and the MAIL FROM domain if not
 */
const char *smtp_from_domain(struct smtp_session *smtp);

/*! \brief Whether SPF validation should be performed */
int smtp_should_validate_spf(struct smtp_session *smtp);

/*! \brief Whether DKIM validation should be performed */
int smtp_should_validate_dkim(struct smtp_session *smtp);

/*! \brief Whether DMARC verification should be performed */
int smtp_should_verify_dmarc(struct smtp_session *smtp);

/*! \brief Whether this is a message submission */
int smtp_is_message_submission(struct smtp_session *smtp);

/*! \brief Whether the sender's privacy should be protected */
int smtp_should_preserve_privacy(struct smtp_session *smtp);

/*!
 * \brief Get the estimated message size provided in MAIL FROM (SIZE=)
 * \return Size provided during MAIL FROM (may or may not be accurate!)
 * \return 0 if no estimated size provided
 */
size_t smtp_message_estimated_size(struct smtp_session *smtp);

/*!
 * \brief Get the Content-Type of a message, if available
 * \param smtp
 * \return Content-Type value
 * \return NULL if unavailable
 */
const char *smtp_message_content_type(struct smtp_session *smtp);

/*!
 * \brief Get the Message-ID of a message, if available
 * \param smtp
 * \return Message-ID value
 * \return NULL if unavailable
 */
const char *smtp_messageid(struct smtp_session *smtp);

/*! \brief Time that message was received */
time_t smtp_received_time(struct smtp_session *smtp);

/*! \brief Score of protocol violation or spaminess severity */
unsigned int smtp_failure_count(struct smtp_session *smtp);

/*! \brief Get RFC822 message as string */
const char *smtp_message_body(struct smtp_filter_data *f);

/*! \brief Initialize smtp_filter_data struct */
void smtp_filter_data_init(struct smtp_filter_data *f, struct smtp_session *smtp, const char *recipient, size_t datalen, int srcfd, int outputfd) __attribute__ ((nonnull (1, 2)));

/*! \brief Cleanup smtp_filter_data struct */
void smtp_filter_data_cleanup(struct smtp_filter_data *f)  __attribute__ ((nonnull (1)));

/*!
 * \brief Write currently buffered prepended headers not yet part of the main message file to a file descriptor in the correct order
 * \param f
 * \param fd File descriptor to which to write the headers
 * \retval 0 on success, -1 on failure
 */
int smtp_filter_write_prepended_headers(struct smtp_filter_data *f, int fd);

/*! \brief Prepend arbitrary data to a message */
#define smtp_filter_write(f, fmt, ...) __smtp_filter_write(f, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__)
int __attribute__ ((format (gnu_printf, 5, 6))) __smtp_filter_write(struct smtp_filter_data *f, const char *file, int line, const char *func, const char *fmt, ...);

/*! \brief Prepend a header to a message */
int smtp_filter_add_header(struct smtp_filter_data *f, const char *name, const char *value);

/*! \brief Run a group of SMTP filters */
void smtp_run_filters(struct smtp_filter_data *fdata, enum smtp_direction dir);

/*! \brief Whether a message should be quarantined when delivered */
int smtp_message_quarantinable(struct smtp_session *smtp);

/* == SMTP processor callbacks - these determine what will happen to a message, based on the message, but do not modify it == */

#define SMTP_MSG_DIRECTION_IN 0
#define SMTP_MSG_DIRECTION_OUT 1

enum msg_process_iteration {
	FILTER_BEFORE_MAILBOX = (1 << 0),	/*!< Execute before the mailbox filters */
	FILTER_MAILBOX = (1 << 1),			/*!< Mailbox filter execution */
	FILTER_AFTER_MAILBOX = (1 << 2), 	/*!< Execute after the mailbox filters */
};

#define FILTER_ALL_PASSES (FILTER_BEFORE_MAILBOX | FILTER_MAILBOX | FILTER_AFTER_MAILBOX)

struct smtp_msg_process {
	/* Inputs */
	struct smtp_session *smtp;	/*!< SMTP session. Not originally included, so try to avoid using this! */
	int fd;						/*!< File descriptor of SMTP session */
	struct mailbox *mbox;		/*!< Mailbox (incoming only) */
	struct bbs_user *user;		/*!< BBS user (outgoing only) */
	struct bbs_node *node;		/*!< BBS node */
	const char *datafile;		/*!< Name of email data file */
	FILE *fp;					/*!< Email data file (used internally only) */
	const char *from;			/*!< Envelope from */
	const struct stringlist *recipients; /*!< All envelope recipients (RCPT TO). Only available for SMTP_SCOPE_COMBINED/SMTP_DIRECTION_SUBMIT, not SMTP_DIRECTION_IN or SMTP_DIRECTION_OUT */
	const char *recipient;		/*!< Envelope to - only for INCOMING messages */
	int size;					/*!< Size of email */
	unsigned int userid;		/*!< User ID (outgoing only) */
	enum smtp_direction dir;	/*!< Full direction (IN, OUT, or SUBMIT) */
	unsigned int direction:1;	/*!< 0 = incoming, 1 = outgoing */
	enum smtp_filter_scope scope; /*!< COMBINED (for outside a delivery handler) or INDIVIDUAL (for within a delivery handler) */
	enum msg_process_iteration iteration; /*!< Which processing pass this is */
	/* Outputs */
	unsigned int bounce:1;		/*!< Whether to send a bounce. This on its own does not also implicitly drop the message, that bit must be explicitly set. */
	unsigned int drop:1;		/*!< Whether message should be dropped */
	int res;					/*!< General return code */
	char *newdir;				/*!< New message location (incoming only) */
	char *bouncemsg;			/*!< Bounce message */
	struct stringlist *forward;	/*!< Forwarding addresses */
	char *relayroute;			/*!< Relay route */
};

struct smtp_message_processor {
	int (*callback)(struct smtp_msg_process *mproc); /*!< Callback function to execute to process the message */
	enum smtp_direction dir; /*!< Direction(s) for which to execute callback */
	enum smtp_filter_scope scope; /*!< Scope(s) for which to execute callback */
	enum msg_process_iteration iteration; /*!< Pass(es) for which to execute callback (3 passes are done for each processor) */
};

/*! \brief Initialize an smtp_msg_process structure for use */
void smtp_mproc_init(struct smtp_session *smtp, struct smtp_msg_process *mproc);

/*!
 * \brief Register an SMTP processor callback to run on each message received or sent. Callback will be called 3x, once for each msg_process_order.
 * \param cb Callback that should return 1 to stop processing further callbacks and -1 to additionally terminate the SMTP transaction (after having already responded)
 */
#define smtp_register_processor(cb) __smtp_register_processor(cb, BBS_MODULE_SELF)

int __smtp_register_processor(struct smtp_message_processor *proc, void *mod);

/*! \brief Unregister an SMTP processor previously registered with smtp_register_processor */
int smtp_unregister_processor(struct smtp_message_processor *proc);

/*!
 * \brief Run SMTP callbacks for a message (only called by net_smtp)
 * \param mproc
 * \retval 0 to continue (some or all callbacks were executed and none returned -1), -1 to abort transaction immediately (because a callback returned -1)
 */
#define smtp_run_callbacks(mproc, scope) __smtp_run_callbacks(mproc, scope, __FILE__, __LINE__, __func__)

int __smtp_run_callbacks(struct smtp_msg_process *mproc, enum smtp_filter_scope scope, const char *file, int line, const char *func);

struct smtp_response {
	/* Response */
	int code;
	const char *subcode;
	const char *reply;
};

/*!
 * \brief Wrapper around smtp_run_callbacks, for use by delivery handlers
 * \param smtp
 * \param mproc Does not need to be (and should not be) initialized
 * \param mbox Mailbox or NULL
 * \param resp
 * \param dir SMTP_DIRECTION_IN or SMTP_DIRECTION_OUT. If this is a submission, SMTP_DIRECTION_IN will be autoconverted to SMTP_DIRECTION_SUBMIT
 * \param scope
 * \param recipient Recipient, with <>
 * \param datalen Message size
 * \param freedata
 * \retval 0 to continue, -1 if message should be aborted and a failure response generated, 1 if message is being silently dropped
 */
#define smtp_run_delivery_callbacks(smtp, mproc, mbox, resp, dir, scope, recipient, datalen, freedata) __smtp_run_delivery_callbacks(smtp, mproc, mbox, resp, dir, scope, recipient, datalen, freedata, __FILE__, __LINE__, __func__)

int __smtp_run_delivery_callbacks(struct smtp_session *smtp, struct smtp_msg_process *mproc, struct mailbox *mbox, struct smtp_response **restrict resp,
	enum smtp_direction dir, enum smtp_filter_scope scope, const char *recipient, size_t datalen, void **freedata, const char *file, int line, const char *func);

#define smtp_abort(r, c, sub, msg) \
	r->code = c; \
	r->subcode = #sub; \
	r->reply = msg;

int __smtp_register_queue_processor(int (*queue_processor)(struct smtp_session *smtp, const char *cmd, const char *args), void *mod);

/*!
 * \brief Register queue processor
 * \param queue_processor Queue processor callback, which returns an SMTP numeric response code
 * \retval 0 on success, -1 on failure
 */
#define smtp_register_queue_processor(queue_processor) __smtp_register_queue_processor(queue_processor, BBS_MODULE_SELF)

/*!
 * \brief Unregister queue processor
 * \param queue_processor Queue processor callback
 * \retval 0 on success, -1 on failure
 */
int smtp_unregister_queue_processor(int (*queue_processor)(struct smtp_session *smtp, const char *cmd, const char *args));

enum dns_record_type {
	DNS_RECORD_A = (1 << 0),
	DNS_RECORD_CNAME = (1 << 1),
};

/*!
 * \brief Register partial DNS lookup callback function, which will only look for either an A record or a CNAME record
 * \param cb
 * \retval 0 on success, -1 on failure
 */
#define smtp_register_partial_lookup(cb) __smtp_register_partial_lookup(cb, BBS_MODULE_SELF)

int __smtp_register_partial_lookup(int (*callback)(const char *domain, enum dns_record_type rectype, char *buf, size_t len), void *mod);

/*! \brief Unregister partial DNS lookup callback function */
int smtp_unregister_partial_lookup(int (*callback)(const char *domain, enum dns_record_type rectype, char *buf, size_t len));

enum smtp_delivery_agent_type {
	SMTP_DELIVERY_AGENT_LOCAL = (1 << 0),
	SMTP_DELIVERY_AGENT_EXTERNAL = (1 << 1),
	SMTP_DELIVERY_AGENT_MAILING_LIST = (1 << 2),
};

struct smtp_delivery_agent {
	/*! \brief Type of delivery agent */
	enum smtp_delivery_agent_type type;
	/*!
	 * \brief RCPT TO handler: can we deliver to this address?
	 * \param fromlocal Message is either a submission or originates locally (e.g. bounce message)
	 * \retval 0 if this recipient cannot be handled by this delivery agent, 1 if yes, -1 if no and no other handler may handle it
	 */
	int (*exists)(struct smtp_session *smtp, struct smtp_response *resp, const char *address, const char *user, const char *domain, int fromlocal, int tolocal);
	/*!
	 * \brief Deliver message (final delivery)
	 * \param fromlocal Message is either a submission or originates locally (e.g. bounce message)
	 */
	int (*deliver)(struct smtp_session *smtp, struct smtp_response *resp, const char *from, const char *recipient, const char *user, const char *domain, int fromlocal, int srcfd, size_t datalen, void **freedata);

	/* Supplementary (and very optional) callbacks, only need to be provided by one module */
	/*! \brief Save a copy of a sent message */
	int (*save_copy)(struct smtp_session *smtp, struct smtp_msg_process *mproc, int srcfd, size_t datalen, char *newfile, size_t newfilelen);
	/*! \brief Relay a message through another message submission agent */
	int (*relay)(struct smtp_session *smtp, struct smtp_msg_process *mproc, int srcfd, size_t datalen, struct stringlist *recipients);
};

#define smtp_register_delivery_handler(agent, priority) __smtp_register_delivery_handler(agent, priority, BBS_MODULE_SELF)

/*!
 * \brief Register an SMTP delivery agent
 * \param agent
 * \param priority Used for preference ordering. Like MX priorities, lower is more important.
 * \param void
 * \retval 0 on success, -1 on failure
 */
int __smtp_register_delivery_handler(struct smtp_delivery_agent *agent, int priority, void *mod);

/*!
 * \brief Unregister an SMTP delivery agent
 * \param agent
 * \retval 0 on success, -1 on failure
 */
/*! \todo Why is this named differently from the registration function? */
int smtp_unregister_delivery_agent(struct smtp_delivery_agent *agent);

/*! \brief Copy of flags from original SMTP session, used for queue files and DSNs */
struct smtp_session_info {
	unsigned int fromlocal:1;
	unsigned int msa:1;
	char helohost[256]; /* HELO/EHLO hostname */
};

/*! \brief RFC 3464 2.3.3 Action field values */
enum smtp_delivery_action {
	DELIVERY_FAILED,
	DELIVERY_DELAYED,
	DELIVERY_DELIVERED,
	DELIVERY_RELAYED,
	DELIVERY_EXPANDED,
};

struct smtp_delivery_outcome;

/*!
 * \brief Create a delivery status notification for a recipient
 * \param recipient Email address of the recipient for which delivery failed
 * \param hostname Hostname of the remote MTA. NULL for local mail server.
 * \param ipaddr IP address of the remote MTA. NULL for local mail server.
 * \param status Status code
 * \param error The error as reported by the remote (or local) MTA.
 * \param stage The stage of delivery, e.g. "end of DATA", "RCPT TO", etc.
 * \param prot Protocol name for this stage, e.g. smtp, x-unix, etc.
 * \param action Delivery action
 * \param retryuntil Time until which message delivery will be retried (only if action is DELIVERY_DELAYED)
 * \return NULL on failure
 * \return Delivery failure, which must be freed using smtp_delivery_outcome_free
 */
struct smtp_delivery_outcome *smtp_delivery_outcome_new(const char *recipient, const char *hostname, const char *ipaddr, const char *status, const char *error, const char *prot, const char *stage, enum smtp_delivery_action action, struct tm *retryuntil);

/*!
 * \brief Free smtp_delivery_outcome (or multiple) allocated by smtp_delivery_outcome_new
 * \param f
 * \param n Number of elements (must be contiguous)
 */
void smtp_delivery_outcome_free(struct smtp_delivery_outcome **f, int n);

/*!
 * \brief Deliver an SMTP non-delivery report (bounce), originating from the postmaster
 * \param sinfo SMTP session information
 * \param arrival Time that message was originally delivered by sender for delivery
 * \param sender Email address that will receive the non-delivery report
 * \param srcfd File descriptor from which original message may be read.
 * \param msglen Number of bytes to read from srcfd, starting at offset 0
 * \param f Delivery failure
 * \param n Number of delivery failures (must be contiguous)
 * \retval 0 if bounce was delivered or queued, -1 on failure
 * \note You should ignore the return code, because there is nothing that can be done if the bounce fails to be delivered.
 */
int smtp_dsn(struct smtp_session_info *sinfo, struct tm *arrival, const char *sender, int srcfd, size_t msglen, struct smtp_delivery_outcome **f, int n);

/*!
 * \brief Inject a message to deliver via SMTP, from outside of the SMTP protocol
 * \param mailfrom MAIL FROM. Do not include <>.
 * \param recipients List of recipients for RCPT TO. Must include <>. This list will be consumed and be empty and invalid upon returning.
 *        If recipients is stack-allocated, no further cleanup is needed; otherwise, use free().
 * \param filename Entire RFC822 message
 * \return Same as expand_and_deliver's return value.
 */
int smtp_inject(const char *mailfrom, struct stringlist *recipients, const char *filename, size_t length);
