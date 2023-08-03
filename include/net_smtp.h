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

struct smtp_session;

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

enum smtp_filter_scope {
	SMTP_SCOPE_INDIVIDUAL = 0, 	/* Run individually for each recipient of a message */
	SMTP_SCOPE_COMBINED, 		/* Run once for all recipients of a message */
};

enum smtp_direction {
	SMTP_DIRECTION_SUBMIT = (1 << 0),	/*!< Message submission */
	SMTP_DIRECTION_IN = (1 << 1),		/*!< Incoming mail from another MTA */
	SMTP_DIRECTION_OUT = (1 << 2),		/*!< Outgoing mail to another MTA */
};

struct smtp_filter_data {
	struct smtp_session *smtp;		/*!< SMTP session */
	int inputfd;					/*!< File descriptor from which message can be read */
	const char *recipient;			/*!< Recipient (RCPT TO). Only available for SMTP_DIRECTION_IN and SMTP_DIRECTION_SUBMIT, and if the scope is SMTP_SCOPE_INDIVIDUAL */
	size_t size;					/*!< Message length */
	enum smtp_direction dir;		/*!< Direction */
	int received;					/*!< Time that message was received */
	/* Duplicated fields: these are simply duplicated from smtp: */
	struct bbs_node *node;			/*!< Node */
	const char *from;				/*!< Envelope from */
	/* Set by filter callbacks */
	char *spf;						/*!< Allocated SPF header value */
	char *dkim;						/*!< Allocated DKIM results */
	char *dmarc;					/*!< Allocated DMARC results */
	char *arc;						/*!< Allocated ARC results */
	char *authresults;				/*!< Allocated Authentication-Results header */
	/* INTERNAL: Do not access these fields directly. Use the publicly exposed functions. */
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
 * \param type The type of filter
 * \param scope Scope for which this filter applies
 * \param dir Bitmask of directions for which this filter applies
 * \param priority Priority of filter. Lower-number priorities are executed first.
 * \param mod
 * \retval 0 on success, -1 on failure
 */
int __smtp_filter_register(struct smtp_filter_provider *provider, enum smtp_filter_type type, enum smtp_filter_scope scope, enum smtp_direction dir, int priority, void *mod);

#define smtp_filter_register(cb, type, scope, dir, priority) __smtp_filter_register(cb, type, scope, dir, priority, BBS_MODULE_SELF)

/*!
 * \brief Unregister an SMTP filter
 * \param cb
 * \retval 0 on success, -1 on failure
 */
int smtp_filter_unregister(struct smtp_filter_provider *provider);

/*! \brief Get SMTP protocol used */
const char *smtp_protname(struct smtp_session *smtp);

/*! \brief Whether SPF validation should be performed */
int smtp_should_validate_spf(struct smtp_session *smtp);

/*! \brief Whether DKIM validation should be performed */
int smtp_should_validate_dkim(struct smtp_session *smtp);

/*! \brief Whether the sender's privacy should be protected */
int smtp_should_preserve_privacy(struct smtp_session *smtp);

/*! \brief Whether this is a bulk mailing */
int smtp_is_bulk_mailing(struct smtp_session *smtp);

/*! \brief Time that message was received */
time_t smtp_received_time(struct smtp_session *smtp);

/*! \brief Get RFC822 message as string */
const char *smtp_message_body(struct smtp_filter_data *f);

/*! \brief Prepend arbitrary data to a message */
int __attribute__ ((format (gnu_printf, 2, 3))) smtp_filter_write(struct smtp_filter_data *f, const char *fmt, ...);

/*! \brief Prepend a header to a message */
int smtp_filter_add_header(struct smtp_filter_data *f, const char *name, const char *value);

/* == SMTP processor callbacks - these determine what will happen to a message, based on the message, but do not modify it == */

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
