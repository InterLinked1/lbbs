/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief RFC 1861 Simple Network Paging Protocol
 *
 * \note Includes STARTTLS support (non-standard)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <ctype.h> /* use isalnum */

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/paging.h"

#define DEFAULT_SNPP_PORT 444

/* Implementation constants */
#define MAX_MESSAGE_LEN 256
#define MAX_SERVICE_LEVEL 11
#define MAX_SUBJECT_LEN 32

static int snpp_port = DEFAULT_SNPP_PORT;

#define snpp_send(snpp, fmt, ...) \
	bbs_debug(6, "%p <= " fmt, snpp, ## __VA_ARGS__); \
	bbs_auto_fd_writef(snpp->node, snpp->node->wfd, fmt, ## __VA_ARGS__); \

#define snpp_reply(snpp, code, fmt, ...) snpp_send(snpp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

struct snpp_session {
	struct bbs_node *node;
	struct bbs_paging_recipients recipients;	/*!< Recipients for message */
	struct bbs_paging_options parameters;		/*!< Current parameters to be applied to next recipient */
	struct bbs_paging_data data;				/*!< Paging data */
};

static void reset_recipients(struct snpp_session *snpp)
{
	RWLIST_REMOVE_ALL(&snpp->recipients, entry, free);
}

static void reset_delivery_options(struct bbs_paging_options *options)
{
	memset(options, 0, sizeof(struct bbs_paging_options));
}

static void reset_delivery_data(struct bbs_paging_data *data)
{
	bbs_paging_data_free_contents(data);
	data->expiry = 0;
	data->twoway = 0;
	data->noqueue = 0;
	data->readack = 0;
}

static void reset_delivery(struct snpp_session *snpp)
{
	reset_recipients(snpp);
	reset_delivery_options(&snpp->parameters);
	reset_delivery_data(&snpp->data);
}

static int add_recipient(struct snpp_session *snpp, char *pagerid, char *pin)
{
	struct bbs_paging_recipient *r;
	size_t pageridlen;

	pageridlen = strlen(pagerid);
	r = calloc(1, sizeof(*r) + pageridlen + strlen(S_IF(pin)) + 2);
	if (ALLOC_FAILURE(r)) {
		return -1;
	}
	strcpy(r->data, pagerid); /* Safe */
	r->pagerid = r->data;
	strcpy(r->data + pageridlen + 1, S_IF(pin));
	r->pin = r->data + pageridlen + 1;

	memcpy(&r->parameters, &snpp->parameters, sizeof(r->parameters)); /* Copy whatever parameters are currently set */
	reset_delivery_options(&snpp->parameters); /* Reset per-recipient parameters for next one */

	RWLIST_INSERT_TAIL(&snpp->recipients, r, entry);
	return 0;
}

static int recipient_exists(struct bbs_paging_recipients *recipients, const char *pagerid)
{
	struct bbs_paging_recipient *r;
	RWLIST_TRAVERSE(recipients, r, entry) {
		if (!strcasecmp(r->pagerid, pagerid)) {
			return 1;
		}
	}
	return 0;
}

static int invalid_message(const char *s)
{
	return strlen(s) > MAX_MESSAGE_LEN;
}

#define REQUIRE_ARGS(s) \
	if (!s || !*s) { \
		snpp_reply(snpp, 550, "Syntax Error"); \
		return 0; \
	}

#define TRANSACTION_IN_PROGRESS(snpp) (snpp->data.message || snpp->data.body || snpp->data.subject || snpp->data.callerid || !RWLIST_EMPTY(&snpp->recipients))
#define IS_2WAY(snpp) (snpp->data.twoway)
#define REQUIRE_2WAY(snpp) if (!IS_2WAY(snpp)) { snpp_reply(snpp, 550, "Command Only Valid For 2-Way Transactions"); return 0; }

/*! \brief Parse a [+/-]XXXX time zone offset into UTC offset in seconds */
static int parse_tz_offset(const char *s, int *offset)
{
	int neg = 0;
	char hr[3], min[3];
	if (*s == '-') {
		neg = -1;
	} else if (*s == '+') {
		neg = 0;
	} else {
		return -1; /* Invalid format */
	}
	s++;
	if (strlen(s) != 4) {
		return -1;
	}
	/* Now we could have strings remaining like 600, 730, etc. */
	memcpy(hr, s, 2);
	hr[2] = '\0';
	strcpy(min, s + 2); /* Safe */
	*offset = neg * (atoi(hr) * 3600) * (atoi(min) * 60);
	return 0;
}

static int valid_snpp_callerid(const char *s)
{
	/* RFC 1861 says CALL allows for the specification of the CallerIdentifier function as specified in TME (Telocator Message Entry Protocol),
	 * a more flexible "standard" protocol that was to succeed TAP/IXO (but never materialized, as far as I know).
	 * So, what do we allow?
	 * Well, phone numbers, obviously, but it's also reasonable to allow email addresses here,
	 * to accomodate pages that may enter a system via SMTP, but traverse it using SNPP.
	 * So, that means almost any valid email address or phone number or paging endpoint we could define (a fully alphanumeric string). */
	if (bbs_str_fully_alphanumeric(s)) {
		return 1;
	}
	/* We don't use bbs_parse_email_address here, since that doesn't actually
	 * validate that s doesn't contain characters that are invalid for an email address.
	 * In particular, we don't want to allow spaces here.
	 * We impose a much stricter requirement here: only alphanumeric, -, +, ., and @.
	 * That should cover most legitimate email addresses we'd want to allow as SNPP identities. */
	while (*s) {
		if (!isalnum(*s) && *s != '-' && *s != '+' && *s != '.' && *s != '@') {
			return 0;
		}
		s++;
	}
	return 1;
}

static int snpp_process(struct snpp_session *snpp, struct readline_data *rldata, char *s)
{
	char *cmd = strsep(&s, " ");

	if (strlen_zero(cmd)) {
		return 0;
	}

	if (!strcasecmp(cmd, "STARTTLS")) {
		/* This is an unofficial extension not standardized in the latest revision of SNPP.
		 * Since some paging providers (e.g. Spok) offer encrypted paging,
		 * and there may be other non-traditional paging endpoints that support secure delivery,
		 * it may be desirable and possible to maintain end-to-end encryption.
		 * This can be done if using email to relay or submit pages, but sadly not with SNPP.
		 * At least when dealing with paired SNPP systems that support it (e.g. two instances
		 * of the BBS connected over a WAN line), we may want to support encryption. */
		if (snpp->node->secure) {
			snpp_reply(snpp, 500, "STARTTLS may not be repeated");
		} else if (!ssl_available()) {
			snpp_reply(snpp, 500, "STARTTLS not available");
		} else {
			snpp_reply(snpp, 220, "Ready to start TLS");
			if (bbs_node_starttls(snpp->node)) {
				return -1; /* Just abort */
			}
			bbs_readline_flush(rldata); /* Prevent STARTTLS response injection by resetting the buffer after TLS upgrade */
			snpp_reply(snpp, 220, "SNPP Gateway Ready");
		}
		return 0;
	}

	/* Level 1 Commands */
	if (!strcasecmp(cmd, "PAGE")) {
		char *pagerid, *pin;
		int res;
		enum pager_type type;
		pagerid = strsep(&s, " ");
		pin = strsep(&s, " ");
		/* PAGEr ID */
		/* Save pager ID (PID) for next messaging transaction. */
		/* We may not always be able to verify validity ahead of time, so acceptance here is not necessarily final.
		 * However, if we can detect an invalid PID now, reject it. */
		REQUIRE_ARGS(pagerid);
		if (recipient_exists(&snpp->recipients, pagerid)) {
			snpp_reply(snpp, 503, "Duplicate Pager");
			return 0;
		}
		res = bbs_pager_exists(pagerid, &type, IS_2WAY(snpp) ? PAGER_REQ_TWOWAY : 0);
		if (res < 0) {
			switch (errno) {
				/* Two-way paging */
				case ENETDOWN:
					res = 1; /* Success */
					snpp_reply(snpp, 950, "Unit NOT Online; Message Will Be Queued for Later Delivery");
					break;
				case ENOSYS:
					snpp_reply(snpp, 500, "Command Not Implemented");
					break;
				case ENOTCONN:
					snpp_reply(snpp, 750, "Two-Way Unit NOT Online; Transaction Denied");
					return 0;
				case EPROTOTYPE:
					snpp_reply(snpp, 550, "Pager Not 2WAY Capable");
					return 0;
				/* Other */
				default:
					/* Shouldn't happen */
					/* Fall through */
				case ECHILD:
					snpp_reply(snpp, 421, "Gateway Service Unavailable");
					return -1;
			}
		}
		if (!res) {
			snpp_reply(snpp, 550, "Pager ID %s does not exist", pagerid);
			return 0;
		}
		if (IS_2WAY(snpp) && !(type & PAGER_TWOWAY)) {
			snpp_reply(snpp, 550, "Pager Not 2WAY Capable");
			return 0;
		}
		if (add_recipient(snpp, pagerid, pin)) {
			snpp_reply(snpp, 554, "System Error");
			return 0;
		}
		if (IS_2WAY(snpp)) {
			snpp_reply(snpp, 850, "Two-Way Unit Online and Available; Transaction Accepted");
		} else {
			snpp_reply(snpp, 250, "OK, Pager ID %s Accepted", pagerid);
		}
	} else if (!strcasecmp(cmd, "MESS")) {
		/* Single-line message body */
		if (snpp->data.message) {
			snpp_reply(snpp, 503, "Duplicate Command Entry");
		} else if (snpp->data.body) {
			snpp_reply(snpp, 503, "Message Already Entered");
		} else {
			REQUIRE_ARGS(s);
			if (invalid_message(s)) {
				snpp_reply(snpp, 550, "Invalid Message");
			} else {
				REPLACE(snpp->data.message, s);
				snpp_reply(snpp, 250, "Message OK");
			}
		}
	} else if (!strcasecmp(cmd, "RESE")) {
		/* Reset */
		reset_delivery(snpp);
		snpp_reply(snpp, 250, "OK, Reset");
	} else if (!strcasecmp(cmd, "SEND")) {
		int res;
		struct bbs_paging_message_metadata meta;
		/* Actually send message */
		if (RWLIST_EMPTY(&snpp->recipients)) {
			/* Need at least 1 recipient! */
			snpp_reply(snpp, 503, "Pager ID Incomplete");
			return 0;
		}
		if (!snpp->data.message && !snpp->data.body) {
			/* Unlike TAP/IXO, a message is mandatory in SNPP */
			snpp_reply(snpp, 503, "Message Incomplete");
			return 0;
		}
		snpp->data.node = snpp->node;
		res = bbs_page_multiple(&snpp->recipients, &snpp->data, &meta);
		if (res) {
			switch (errno) {
				case ENOENT:
					snpp_reply(snpp, 550, "Invalid Pager ID");
					break;
				case ENOSYS:
					snpp_reply(snpp, 500, "Command Not Implemented");
					break;
				case EAGAIN:
					snpp_reply(snpp, 554, "Temporary Delivery Failure");
					break;
				case ECHILD:
					snpp_reply(snpp, 421, "Gateway Service Unavailable");
					return -1;
				case EACCES: /* Pager requires a PIN, which TAP 1.8 does not support (but SNPP does) */
					snpp_reply(snpp, 554, "This Pager Requires A PIN");
					break;
				case EINVAL:
					snpp_reply(snpp, 550, "Illegal Pager ID");
					break;
				case EDOM:
					/* What's weird here is that in SNPP, the message is mandatory,
					 * although in TAP/IXO, it's not.
					 *
					 * If we're sending a message to multiple recipients,
					 * some of which are tone-only, and some of which accepts messages,
					 * then it makes sense we'd provide a message that is silently
					 * ignored for the tone-only pagers and return success.
					 *
					 * XXX So what do we do then? */
					snpp_reply(snpp, 554, "Tone-Only Pager, No Message");
					break;
				case ERANGE:
					snpp_reply(snpp, 554, "Numeric Pager, No Alphabetic Characters");
					break;
				case EMSGSIZE:
					snpp_reply(snpp, 554, "Message Too Long");
					break;
				case EDQUOT:
					snpp_reply(snpp, 421, "Message Quota Exceeded");
					return -1;
				default:
					bbs_warning("Unhandled error: %s\n", strerror(errno));
					snpp_reply(snpp, 550, "Delivery Failed! Message Destroyed"); /* Shouldn't happen */
					return -1;
			}
			reset_delivery(snpp); /* Flush after a successful (or failed) delivery */
			return 0;
		}
		if (IS_2WAY(snpp)) {
			/* Replies used only for two-way paging */
			if (!(meta.status & PAGE_DELIVERED)) {
				snpp_reply(snpp, 960, "%s %s OK, Message QUEUED For Delivery", meta.msgtag, meta.passcode);
			} else { /* PAGE_DELIVERED */
				if (meta.status & PAGE_AWAITING_READACK) {
					snpp_reply(snpp, 860, "%s %s Delivered, Awaiting Read Ack", meta.msgtag, meta.passcode);
				} else if (meta.status & PAGE_AWAITING_REPLY) {
					snpp_reply(snpp, 861, "%s %s Delivered, Awaiting Reply (MCR)", meta.msgtag, meta.passcode);
				} else {
					snpp_reply(snpp, 880, "%s %s Message Delivered", meta.msgtag, meta.passcode);
				}
			}
		} else {
			/* This is a bit weird, returning the message tag for a non-2WAY transaction,
			 * given that you can only use MSTA in a 2WAY-transaction.
			 * However, this is consistent with how Spok behaves, and it also makes sense:
			 * even for one-way pages, there may be deferred/delivered status to check
			 * (at least in our implementation; normally, a page would go out immediately
			 *  via POCSAG, so it may not make sense in that case). */
			if (!(meta.status & PAGE_DELIVERED)) {
				snpp_reply(snpp, 250, "%s %s OK, Message QUEUED For Delivery", meta.msgtag, meta.passcode);
			} else { /* PAGE_DELIVERED */
				snpp_reply(snpp, 250, "%s %s Message Sent", meta.msgtag, meta.passcode);
			}
		}
		reset_delivery(snpp); /* Flush after a successful (or failed) delivery */
	} else if (!strcasecmp(cmd, "QUIT")) {
		snpp_reply(snpp, 221, "OK, Goodbye");
		return -1;
	} else if (!strcasecmp(cmd, "HELP")) {
		snpp_reply(snpp, 214, "Multiline Information");
		if (!snpp->node->secure && ssl_available()) {
			snpp_send(snpp,
				"SNPP Help\r\n"
				"Valid commands for this version are:\r\n"
				"\tSTARTTLS\r\n"
				"\tHELP RESE LOGI\r\n"
				"\tPAGE SEND MESS\r\n"
				"\tDATA .    2WAY\r\n"
				"\tALER COVE HOLD\r\n"
				"\tCALL SUBJ PING\r\n"
				"\tRTYP MCRE MSTA\r\n"
				"\tKTAG EXPT NOQUEUE\r\n"
				"\tACKR QUIT\r\n");
		} else {
			snpp_send(snpp,
				"SNPP Help\r\n"
				"Valid commands for this version are:\r\n"
				"\tHELP RESE LOGI\r\n"
				"\tPAGE SEND MESS\r\n"
				"\tDATA .    2WAY\r\n"
				"\tALER COVE HOLD\r\n"
				"\tCALL SUBJ PING\r\n"
				"\tRTYP MCRE MSTA\r\n"
				"\tKTAG EXPT NOQUEUE\r\n"
				"\tACKR QUIT\r\n");
		}
		snpp_reply(snpp, 250, "End of Help");
	} else
	/* Level 2 Commands */
	if (!strcasecmp(cmd, "DATA")) {
		/* Multi-line message body */
		if (snpp->data.message) {
			snpp_reply(snpp, 503, "Message Already Entered");
		} else if (snpp->data.body) {
			snpp_reply(snpp, 503, "Message Already Entered");
		} else {
			struct dyn_str dstr;
			memset(&dstr, 0, sizeof(dstr));
			snpp_reply(snpp, 354, "End with <CRLF>.<CRLF>");
			for (;;) {
				ssize_t rres = bbs_node_readline(snpp->node, rldata, "\r\n", SEC_MS(30));
				if (rres < 0) {
					if (rres == 0) {
						snpp_reply(snpp, 421, "Timeout, Goodbye"); /* Timeout occured. */
					}
					return -1;
				}
				if (rres == 1 && rldata->buf[0] == '.') {
					break; /* We're done */
				}
				dyn_str_append_fmt(&dstr, "%.*s\r\n", (int) rres, rldata->buf);
			}
			free_if(snpp->data.body);
			snpp->data.body = dstr.buf; /* Steal the reference directly */
			snpp_reply(snpp, 250, "DATA Accepted");
		}
	} else
	/* Level 2 - Optional Extensions */
	if (!strcasecmp(cmd, "LOGI")) {
		char *user, *pass;
		int res;
		user = strsep(&s, " ");
		pass = strsep(&s, " ");
		/* MUAs typically enclose these in quotes: */
		REQUIRE_ARGS(user);
		REQUIRE_ARGS(pass);
		if (bbs_user_is_registered(snpp->node->user)) {
			snpp_reply(snpp, 550, "Already Logged In");
			return 0;
		}
		res = bbs_authenticate(snpp->node, user, pass);
		if (pass) {
			bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
		}
		if (res) {
			snpp_reply(snpp, 550, "Invalid LoginID or Password");
		} else {
			snpp_reply(snpp, 250, "Login Accepted");
		}
	} else if (!strcasecmp(cmd, "LEVE")) {
		/* Level of service */
		int level;
		REQUIRE_ARGS(s);
		level = atoi(s);
		if (level < 0 || level > MAX_SERVICE_LEVEL || (!level && *s != '0')) {
			snpp_reply(snpp, 550, "Invalid Service Level");
		} else {
			snpp->parameters.level = level;
			snpp->parameters.level_set = 1;
			snpp_reply(snpp, 250, "Alternate Service Level Accepted");
		}
	} else if (!strcasecmp(cmd, "ALER")) {
		int alert;
		/* Override default security setting */
		REQUIRE_ARGS(s);
		alert = atoi(s);
		if (alert < 0 || alert > 1 || (!alert && *s != '0')) {
			snpp_reply(snpp, 550, "Invalid Alert Parameter");
		} else {
			SET_BITFIELD(snpp->parameters.alert, alert);
			snpp_reply(snpp, 250, "Alert Override Accepted");
		}
	} else if (!strcasecmp(cmd, "COVE")) {
		int coverage;
		/* Specify alternate coverage region */
		REQUIRE_ARGS(s);
		coverage = atoi(s);
		if (coverage < 1) {
			snpp_reply(snpp, 550, "Invalid Alternate Region");
		} else {
			snpp->parameters.coverage = coverage;
			snpp->parameters.coverage_set = 1;
			snpp_reply(snpp, 250, "Alert Coverage Selected");
		}
	} else if (!strcasecmp(cmd, "HOLD")) {
		struct tm tm;
		time_t holduntil;
		char *datestr, *offset;
		int offsetsec;
		/* Delay delivery to the recipient until a future time */
		datestr = strsep(&s, " "); /* YYMMDDHHMMSS */
		offset = s; /* e.g. -0600 */
		REQUIRE_ARGS(datestr);
		memset(&tm, 0, sizeof(tm));
		if (!strptime(datestr, "%y%02m%02d%H%M%S", &tm)) {
			snpp_reply(snpp, 550, "Invalid Delivery Date/Time");
			return 0;
		}
		/* Convert to time */
		tm.tm_isdst = -1;
		if (!strlen_zero(offset)) {
			holduntil = timegm(&tm); /* Use UTC, then apply the offset */
		} else {
			holduntil = mktime(&tm); /* Local time, if no offset specified */
		}
		if (holduntil == (time_t) -1) {
			snpp_reply(snpp, 550, "Invalid Delivery Date/Time");
			return 0;
		}
		/* Now, add the time zone offset, if needed */
		if (!strlen_zero(offset)) {
			if (parse_tz_offset(offset, &offsetsec)) {
				snpp_reply(snpp, 550, "Invalid Delivery Date/Time");
				return 0;
			}
			/* We add the negated offset.
			 * Say we were provided -0600, 6 hours behind UTC.
			 * Then offsetsec is -21600.
			 * The parsed time in that time zone is 6 hours LATER
			 * compared to UTC, so we would subtract -21600
			 * to get a bigger time value. */
			holduntil -= offsetsec;
		}
		if (holduntil < time(NULL)) {
			snpp_reply(snpp, 550, "Date/Time is in the Past");
			return 0;
		}
		snpp->parameters.holduntil = holduntil;
		snpp_reply(snpp, 250, "Delayed Messaging Selected");
	} else if (!strcasecmp(cmd, "CALL")) {
		/* Set Caller ID */
		REQUIRE_ARGS(s);
		if (!valid_snpp_callerid(s)) {
			snpp_reply(snpp, 550, "Invalid Caller ID");
		} else {
			REPLACE(snpp->data.callerid, s);
			snpp_reply(snpp, 250, "Caller ID Accepted");
		}
	} else if (!strcasecmp(cmd, "SUBJ")) {
		/* Set subject */
		REQUIRE_ARGS(s);
		if (strlen(s) > MAX_SUBJECT_LEN) {
			snpp_reply(snpp, 550, "Subject Too Long");
		} else {
			REPLACE(snpp->data.subject, s);
			snpp_reply(snpp, 250, "Message Subject Accepted");
		}
	} else
	/* Level 3 Commands (Two-Way) */
	if (!strcasecmp(cmd, "2WAY")) {
		/* Enable two-way paging */
		if (TRANSACTION_IN_PROGRESS(snpp)) {
			snpp_reply(snpp, 550, "Standard Transaction Already Underway, Use RESEt");
		} else {
			snpp->data.twoway = 1;
			snpp_reply(snpp, 250, "OK, Beginning 2-Way Transaction");
		}
	} else if (!strcasecmp(cmd, "PING")) {
		char locus_code[32];
		/* Localize the field message unit and return location and/or status.
		 * Because this is sensitive information, this command is restricted. */
		REQUIRE_2WAY(snpp);
		if (bbs_pager_ping(s, locus_code, sizeof(locus_code))) {
			switch (errno) {
				case ECHILD:
					snpp_reply(snpp, 421, "Gateway Service Unavailable");
					return -1;
				case ENOSYS:
					snpp_reply(snpp, 500, "Command Not Implemented");
					return -1;
				case EIDRM:
					snpp_reply(snpp, 821, "Unit On System, No Location Information Available (ACLU mode)");
					break;
				case ENETDOWN:
					snpp_reply(snpp, 750, "Unit Valid But Not Online At This Time");
					break;
				case ENOTCONN:
					snpp_reply(snpp, 920, "Unit Not Online, But Can Queue Message for Later Delivery");
					break;
				case ENOTTY:
					snpp_reply(snpp, 550, "Can't PING; Unit NOT 2WAY Capable");
					break;
				case EINVAL:
					snpp_reply(snpp, 550, "Illegal Pager ID");
					break;
				case ENOENT:
					snpp_reply(snpp, 550, "Unknown Pager ID");
					break;
				default: /* Shouldn't happen */
					snpp_reply(snpp, 554, "Error, failed");
					break;
			}
		} else {
			snpp_reply(snpp, 820, "%s Unit On System, This Area", locus_code);
		}
	} else if (!strcasecmp(cmd, "EXPT")) {
		int expiry_hours;
		/* Change expiry time for a queued message */
		REQUIRE_2WAY(snpp);
		REQUIRE_ARGS(s);
		expiry_hours = atoi(s);
		if (expiry_hours < 0) {
			snpp_reply(snpp, 550, "Invalid Expiry Time");
		} else {
			snpp->data.expiry = expiry_hours;
			snpp_reply(snpp, 250, "Message Expiry Time Changed to '%d' Hours", snpp->data.expiry);
		}
	} else if (!strcasecmp(cmd, "NOQUEUE")) {
		/* Don't allow queuing for this transaction */
		REQUIRE_2WAY(snpp);
		snpp->data.noqueue = 1;
		snpp_reply(snpp, 250, "Queuing Disabled, This Transaction");
	/* In the RFC, the example includes the full names, so allow those too */
	} else if (!strcasecmp(cmd, "ACKR") || !strcasecmp(cmd, "ACKRead")) {
		int ack;
		/* Enable/disable "read" acknowledgment */
		REQUIRE_2WAY(snpp);
		ack = atoi(s);
		if (ack != 0 && ack != 1) {
			snpp_reply(snpp, 550, "Invalid Read Acknowledge Setting");
		} else {
			SET_BITFIELD(snpp->data.readack, ack);
			snpp_reply(snpp, 250, "Read Acknowledgment %s", snpp->data.readack ? "Enabled" : "Disabled");
		}
	} else if (!strcasecmp(cmd, "RTYP") || !strcasecmp(cmd, "RTYPE")) {
		snpp_reply(snpp, 500, "Command Not Implemented");
	} else if (!strcasecmp(cmd, "MCRE") || !strcasecmp(cmd, "MCRESP")) {
		snpp_reply(snpp, 500, "Command Not Implemented");
	} else if (!strcasecmp(cmd, "MSTA")) {
		struct bbs_paging_message_metadata meta;
		char timestampbuf[PAGING_TIMESTAMP_LENGTH] = "";
		char *msgtag, *passcode;
		/* Check status of message */
		msgtag = strsep(&s, " ");
		passcode = s;
		/* Although conventionally, MSTA does require 2WAY, we allow it to be used in all cases */
		REQUIRE_ARGS(msgtag);
		REQUIRE_ARGS(passcode);
		safe_strncpy(meta.msgtag, msgtag, sizeof(meta.msgtag));
		safe_strncpy(meta.passcode, passcode, sizeof(meta.passcode));
		/* Note: Spok seems to just reply with 556 Unknown status here, for any valid pager ID + any arbitrary pass code */
		if (meta.timestamp) {
			bbs_paging_timestamp(meta.timestamp, timestampbuf, sizeof(timestampbuf));
		}
		if (bbs_paging_message_status(&meta)) {
			switch (errno) {
				case ECHILD:
					snpp_reply(snpp, 421, "Gateway Service Unavailable");
					return -1;
				case ENOSYS:
					snpp_reply(snpp, 500, "Command Not Implemented");
					break;
				case EINVAL:
				case EACCES:
					snpp_reply(snpp, 550, "Unknown or Illegal Message_Tag or Pass_Code");
					break;
				case ETIMEDOUT:
					snpp_reply(snpp, 780, "%s %s Message Expired Before Delivery", meta.msgtag, timestampbuf);
					break;
				default: /* Shouldn't happen */
					snpp_reply(snpp, 554, "Error, failed");
					break;
			}
			return 0;
		}
		if (!(meta.status & PAGE_DELIVERED)) {
			snpp_reply(snpp, 960, "%s %s OK, Queued For Delivery", meta.msgtag, timestampbuf);
		} else { /* PAGE_DELIVERED */
			if (meta.status & PAGE_REPLY_RECEIVED) { /* Reply received (and obviously it's read */
				if (meta.status & PAGE_REPLY_RECEIVED_MC) {
					snpp_reply(snpp, 888, "%s %s %s MCR Reply Received", meta.msgtag, timestampbuf, meta.response);
				} else { /* PAGE_REPLY_RECEIVED_TEXT */
					snpp_reply(snpp, 889, "%s %s %s", meta.msgtag, timestampbuf, meta.response);
				}
			} else if (meta.status & PAGE_READ) {
				if (meta.status & PAGE_AWAITING_REPLY) {
					snpp_reply(snpp, 870, "%s %s Delivered, Read, Awaiting Reply (MCR)", meta.msgtag, timestampbuf);
				} else {
					snpp_reply(snpp, 881, "%s %s Message Delivered and Read by Recipient", meta.msgtag, timestampbuf);
				}
			} else { /* PAGE_AWAITING_READACK */
				if (meta.status & PAGE_AWAITING_READACK) {
					snpp_reply(snpp, 860, "%s %s Delivered, Awaiting Read Ack", meta.msgtag, timestampbuf);
				} else if (meta.status & PAGE_AWAITING_REPLY) {
					snpp_reply(snpp, 861, "%s %s Delivered, Awaiting Reply (MCR)", meta.msgtag, timestampbuf);
				} else {
					snpp_reply(snpp, 880, "%s %s Message Delivered (No Reply Pending)", meta.msgtag, timestampbuf);
				}
			}
		}
	} else if (!strcasecmp(cmd, "KTAG")) {
		struct bbs_paging_message_metadata meta;
		char timestampbuf[PAGING_TIMESTAMP_LENGTH] = "";
		char *msgtag, *passcode;
		/* Courtesy kill message tag */
		msgtag = strsep(&s, " ");
		passcode = s;
		/* Although conventionally, KTAG does require 2WAY, we allow it to be used in all cases */
		REQUIRE_ARGS(msgtag);
		REQUIRE_ARGS(passcode);
		safe_strncpy(meta.msgtag, msgtag, sizeof(meta.msgtag));
		safe_strncpy(meta.passcode, passcode, sizeof(meta.passcode));
		if (bbs_paging_message_expire(&meta)) {
			switch (errno) {
				case ECHILD:
					snpp_reply(snpp, 421, "Gateway Service Unavailable");
					return -1;
				case ENOSYS:
					snpp_reply(snpp, 500, "Command Not Implemented");
					break;
				case EINVAL:
					snpp_reply(snpp, 550, "Unknown or Illegal Message_Tag or Pass_Code");
					break;
				default: /* Shouldn't happen */
					snpp_reply(snpp, 554, "Error, failed");
					break;
			}
		} else {
			if (meta.timestamp) {
				bbs_paging_timestamp(meta.timestamp, timestampbuf, sizeof(timestampbuf));
			}
			snpp_reply(snpp, 250, "%s %s OK, message tag purged", meta.msgtag, timestampbuf);
		}
	} else {
		bbs_warning("Unrecognized SNPP command '%s'\n", cmd);
		snpp_reply(snpp, 500, "Command Not Implemented");
	}
	return 0;
}

static void handle_client(struct snpp_session *snpp)
{
	char buf[1001];
	struct readline_data rldata;

	/* Don't bother starting a transaction if nobody's listening */
	if (!bbs_paging_available()) {
		snpp_reply(snpp, 421, "Service Temporarily Unavailable, Goodbye");
		return;
	}

	bbs_readline_init(&rldata, buf, sizeof(buf));
	reset_delivery_options(&snpp->parameters); /* Some delivery options have defaults that are not 0 */

	snpp_reply(snpp, 220, "SNPP Gateway Ready");

	for (;;) {
		/* RFC 1861 doesn't explicitly mention what line ending is used, we assume CR LF */
		ssize_t res = bbs_node_readline(snpp->node, &rldata, "\r\n", SEC_MS(30));
		if (res < 0) {
			res += 1; /* Convert the res back to a normal one. */
			if (res == 0) {
				snpp_reply(snpp, 421, "Timeout, Goodbye"); /* Timeout occured. */
			}
			break;
		}
		if (!STARTS_WITH(buf, "LOGI")) {
			bbs_debug(3, "=> %s\n", buf);
		}
		if (snpp_process(snpp, &rldata, buf)) {
			break;
		}
	}

	reset_delivery(snpp); /* Free anything leftover */
}

static void *snpp_handler(void *varg)
{
	struct snpp_session snpp;
	struct bbs_node *node = varg;

	bbs_node_net_begin(node);

	memset(&snpp, 0, sizeof(snpp));
	snpp.node = node;
	handle_client(&snpp);

	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	int res;
	struct bbs_config *cfg = bbs_config_load("net_snpp.conf", 1);

	if (!cfg) {
		return 0;
	}

	res = bbs_config_val_set_port(cfg, "general", "port", &snpp_port);
	bbs_config_unlock(cfg);
	return res;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	return bbs_start_tcp_listener(snpp_port, "SNPP", snpp_handler);
}

static int unload_module(void)
{
	bbs_stop_tcp_listener(snpp_port);
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC1861 Simple Network Paging Protocol");
