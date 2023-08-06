/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief RFC5321 Simple Mail Transfer Protocol (SMTP) Server (Mail Transfer Agent and Message Submission Agent)
 *
 * \note Supports RFC1870 Size Declarations
 * \note Supports RFC1893 Enhanced Status Codes
 * \note Supports RFC3207 STARTTLS
 * \note Supports RFC4954 AUTH
 * \note Supports RFC4468 BURL
 * \note Supports RFC6409 Message Submission
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sendfile.h>

#include <dirent.h> /* for msg_to_filename */

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/os.h"
#include "include/base64.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/stringlist.h"
#include "include/test.h"
#include "include/mail.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"

#define MAX_RECIPIENTS 100
#define MAX_LOCAL_RECIPIENTS 100
#define MAX_EXTERNAL_RECIPIENTS 10

#define MAX_HOPS 50

static int smtp_port = DEFAULT_SMTP_PORT;
static int smtps_port = DEFAULT_SMTPS_PORT;
static int msa_port = DEFAULT_SMTP_MSA_PORT;

static int smtp_enabled = 1, smtps_enabled = 1, msa_enabled = 1;

static int accept_relay_in = 1;
static int require_starttls = 1;
static int requirefromhelomatch = 0;
static int validatespf = 1;
static int add_received_msa = 0;
static int archivelists = 1;

/*! \brief Max message size, in bytes */
static unsigned int max_message_size = 300000;

/* Allow this module to use dprintf */
#undef dprintf

#define _smtp_reply(smtp, fmt, ...) bbs_debug(6, "%p <= " fmt, smtp, ## __VA_ARGS__); dprintf(smtp->wfd, fmt, ## __VA_ARGS__);

/*! \brief Final SMTP response with this code */
#define smtp_resp_reply(smtp, code, subcode, reply) _smtp_reply(smtp, "%d %s %s\r\n", code, subcode, reply)
#define smtp_reply(smtp, code, status, fmt, ...) _smtp_reply(smtp, "%d %s " fmt "\r\n", code, #status, ## __VA_ARGS__)
#define smtp_reply_nostatus(smtp, code, fmt, ...) _smtp_reply(smtp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

/*! \brief Non-final SMTP response (subsequent responses with the same code follow) */
#define smtp_reply0_nostatus(smtp, code, fmt, ...) _smtp_reply(smtp, "%d-" fmt "\r\n", code, ## __VA_ARGS__)

/*
 * Wikipedia sums up the difference between MTAs/MSAs very nicely, if the difference is confusing:
 *
 * The MTA accepts a user's incoming mail, while the MSA accepts a user's outgoing mail.
 *
 * ...Separating the MTA and MSA functions makes it easier for an MTA to deny relaying,
 * that is to refuse any mail that is not addressed to a recipient at a domain that is served locally...
 * By contrast, an MSA must generally accept mail for any recipient on the Internet,
 * though it only accepts such mail from authors who are authorized to use that MSA
 * and who have established their identity to the MSA via authentication.
 *
 * In times when both mail submission and acceptance of incoming mail were usually accomplished
 * using the same protocol and the same server, the ability to send mail to arbitrary destinations
 * without authentication allowed spammers to use MTAs as a means of distributing spam...
 */

struct smtp_session {
	struct bbs_node *node;
	int rfd;
	int wfd;

	/* Transaction data */
	char *from;
	struct stringlist recipients;
	struct stringlist sentrecipients;

	char template[64];
	FILE *fp;

	char *helohost;				/* Hostname for HELO/EHLO */
	char *contenttype;			/* Primary Content-Type of message */
	/* AUTH: Temporary */
	char *authuser;				/* Authentication username */
	char *fromheaderaddress;	/* Address in the From: header */

	struct {
		unsigned long datalen;
		unsigned long sizepreview;	/* Size as advertised in the MAIL FROM */
		int hopcount;				/* Number of hops so far according to count of Received headers in message. */

		int numrecipients;
		int numlocalrecipients;
		int numexternalrecipients;

		time_t received;			/* Time that message was received */
		unsigned int dostarttls:1;	/* Whether we are initiating STARTTLS */

		unsigned int indata:1;		/* Whether client is currently sending email body (DATA) */
		unsigned int indataheaders:1;	/* Whether client is currently sending headers for the message */
		unsigned int datafail:1;	/* Data failure */
		unsigned int inauth:2;		/* Whether currently doing AUTH (1 = need PLAIN, 2 = need LOGIN user, 3 = need LOGIN pass) */
		unsigned int dkimsig:1;		/* Message has a DKIM-Signature header */
	} tflags; /* Transaction flags */

	/* Not affected by RSET */
	unsigned int failures;		/* Number of protocol violations or failures */
	unsigned int gothelo:1;		/* Got a HELO/EHLO */
	unsigned int ehlo:1;		/* Client supports ESMTP (EHLO) */
	unsigned int fromlocal:1;	/* Sender is local */
	unsigned int msa:1;			/* Whether connection was to the Message Submission Agent port (as opposed to the Mail Transfer Agent port) */
	unsigned int secure:1;		/* Whether session is secure (TLS, STARTTLS) */
};

static void smtp_reset_data(struct smtp_session *smtp)
{
	if (smtp->fp) {
		fclose(smtp->fp);
		smtp->fp = NULL;
		if (unlink(smtp->template)) {
			bbs_error("Failed to delete %s: %s\n", smtp->template, strerror(errno));
		}
		smtp->template[0] = '\0';
	}
}

static void smtp_reset(struct smtp_session *smtp)
{
	smtp_reset_data(smtp);
	free_if(smtp->authuser);
	free_if(smtp->fromheaderaddress);
	free_if(smtp->from);
	free_if(smtp->contenttype);
	stringlist_empty(&smtp->recipients);
	stringlist_empty(&smtp->sentrecipients);
	memset(&smtp->tflags, 0, sizeof(smtp->tflags)); /* Zero all the numbers */
}

static void smtp_destroy(struct smtp_session *smtp)
{
	/* Reset */
	smtp->ehlo = 0;
	smtp->gothelo = 0;
	free_if(smtp->helohost);
	smtp_reset(smtp);
}

static struct stringlist blacklist;

/*
 * Status code references:
 * - https://www.iana.org/assignments/smtp-enhanced-status-codes/smtp-enhanced-status-codes.xhtml
 * - https://support.google.com/a/answer/3221692
 * - https://support.google.com/a/answer/3726730?hl=en
 */

#define REQUIRE_ARGS(s) \
	if (!s || !*s) { \
		smtp_reply(smtp, 501, 5.5.2, "Syntax Error"); \
		smtp->failures++; \
		return 0; \
	}

#define REQUIRE_HELO() \
	if (!smtp->gothelo) { \
		smtp_reply(smtp, 503, 5.5.1, "EHLO/HELO first."); \
		smtp->failures++; \
		return 0; \
	}

#define REQUIRE_MAIL_FROM() \
	if (!smtp->from) { \
		smtp_reply(smtp, 503, 5.5.1, "MAIL first."); \
		smtp->failures++; \
		return 0; \
	}

#define REQUIRE_RCPT() \
	if (!smtp->tflags.numrecipients) { \
		smtp_reply(smtp, 503, 5.5.1, "RCPT first."); \
		smtp->failures++; \
		return 0; \
	}

static int handle_helo(struct smtp_session *smtp, char *s, int ehlo)
{
	if (strlen_zero(s)) {
		/* Submissions won't contain any data for HELO/EHLO, only relayers will. */
		if (!smtp->msa) {
			smtp_reply(smtp, 501, 5.5.4, "Empty HELO/EHLO argument not allowed, closing connection.");
			return -1;
		}
	} else {
		REPLACE(smtp->helohost, s);
		/* Note that enforcing that helohost matches sending IP is noncompliant with RFC 2821:
		 * "An SMTP server MAY verify that the domain name parameter in the EHLO command
		 * actually corresponds to the IP address of the client.
		 * However, the server MUST NOT refuse to accept a message for this reason if the verification fails:
		 * the information about verification failure is for logging and tracing only. */
		/* Another reason to not enforce: many IPs may be authorized to send mail for a domain,
		 * but hostname will resolve only to one of those IPs. In other words, we can't assume
		 * any relationship between hostname resolution and authorized IPs for sending mail.
		 * This is the kind of problem SPF records are better off at handling anyways.
		 */
	}

	if (smtp->gothelo) {
		/* RFC 5321 4.1.4 says a duplicate EHLO is treated as a RSET */
		smtp_reset(smtp);
		smtp_reply(smtp, 250, 2.1.5, "Flushed");
		return 0;
	}

	SET_BITFIELD(smtp->gothelo, 1);
	SET_BITFIELD(smtp->ehlo, ehlo);

	if (ehlo) {
		smtp_reply0_nostatus(smtp, 250, "%s at your service [%s]", bbs_hostname(), smtp->node->ip);
		/* The RFC says that login should only be allowed on secure connections,
		 * but if we don't allow login on plaintext connections, then they're functionally useless. */
		if (smtp->secure || !require_starttls) {
			smtp_reply0_nostatus(smtp, 250, "AUTH LOGIN PLAIN"); /* RFC-complaint way */
			smtp_reply0_nostatus(smtp, 250, "AUTH=LOGIN PLAIN"); /* For non-compliant user agents, e.g. Outlook 2003 and older */
		}
		smtp_reply0_nostatus(smtp, 250, "PIPELINING");
		smtp_reply0_nostatus(smtp, 250, "SIZE %u", max_message_size); /* RFC 1870 */
		if (!smtp->secure && ssl_available()) {
			smtp_reply0_nostatus(smtp, 250, "STARTTLS");
		}
		if (bbs_user_is_registered(smtp->node->user)) {
			/* BURL imap indicates that we support URLAUTH (RFC4467).
			 * A specific IMAP URL indicates we have a trust relationship with an IMAP server and don't need URLAUTH.
			 * Since the IMAP server here is the same server as the SMTP server, that is the case for us.
			 * RFC 4468 3.3 conveniently allows us to not support URLAUTH at all if we don't list just "imap".
			 * Here we indicate that BURL is only supported for our IMAP server, and URLAUTH is not necessary (and indeed, is not supported).
			 */
			smtp_reply0_nostatus(smtp, 250, "BURL imap://%s", bbs_hostname()); /* RFC 4468 BURL */
		}
		smtp_reply_nostatus(smtp, 250, "ENHANCEDSTATUSCODES");
	} else {
		smtp_reply_nostatus(smtp, 250, "%s at your service [%s]", bbs_hostname(), smtp->node->ip);
	}
	return 0;
}

/*! \brief RFC4954 Authentication */
static int handle_auth(struct smtp_session *smtp, char *s)
{
	int res;
	int inauth = smtp->tflags.inauth;

	smtp->tflags.inauth = 0;
	REQUIRE_ARGS(s);

	if (!strcmp(s, "*")) {
		/* Client cancelled exchange */
		smtp_reply(smtp, 501, "Authentication cancelled", "");
	} else if (inauth == 1) {
		unsigned char *decoded;
		char *authorization_id, *authentication_id, *password;

		decoded = bbs_sasl_decode(s, &authorization_id, &authentication_id, &password);
		if (!decoded) {
			smtp_reply(smtp, 501, 5.5.2, "Cannot decode response");
			return -1;
		}

		/* Can't use bbs_sasl_authenticate directly since we need to strip the domain */
		bbs_strterm(authentication_id, '@');
		res = bbs_authenticate(smtp->node, authentication_id, password);
		bbs_memzero(password, strlen(password)); /* Destroy the password from memory before we free it */
		free(decoded);

		/* Have a combined username and password */
		goto logindone;
	} else if (inauth == 2) {
		REPLACE(smtp->authuser, s);
		smtp->tflags.inauth = 3; /* Get password */
		_smtp_reply(smtp, "334 UGFzc3dvcmQ6\r\n"); /* Prompt for password (base64 encoded) */
	} else if (inauth == 3) {
		int userlen, passlen;
		unsigned char *user, *pass;
		/* Have a password, and a stored username */
		user = base64_decode((unsigned char*) smtp->authuser, (int) strlen(smtp->authuser), &userlen);
		if (!user) {
			smtp_reply(smtp, 502, 5.5.2, "Decoding failure");
			return 0;
		}
		pass = base64_decode((unsigned char*) s, (int) strlen(s), &passlen);
		if (!pass) {
			free(user);
			smtp_reply(smtp, 502, 5.5.2, "Decoding failure");
			return 0;
		}
		res = bbs_authenticate(smtp->node, (char*) user, (char*) pass);
		free(user);
		free(pass);
		goto logindone;
	} else {
		bbs_assert(0);
	}
	return 0;

logindone:
	if (res) {
		smtp_reply(smtp, 535, 5.7.8, "Authentication credentials invalid");
	} else {
		smtp_reply(smtp, 235, 2.7.0, "Authentication successful");
		mailbox_dispatch_event_basic(EVENT_LOGIN, smtp->node, NULL, NULL);
	}
	return 0;
}

static int test_parse_email(void)
{
	int res = -1;
	char s[84] = "John Smith <test@example.com>";
	char *name, *user, *domain;

	bbs_test_assert_equals(0, bbs_parse_email_address(s, &name, &user, &domain));
	bbs_test_assert_str_equals(name, "John Smith");
	bbs_test_assert_str_equals(user, "test");
	bbs_test_assert_str_equals(domain, "example.com");

	safe_strncpy(s, "test@example.com", sizeof(s));
	bbs_test_assert_equals(0, bbs_parse_email_address(s, &name, &user, &domain));
	bbs_test_assert_equals(1, name == NULL); /* Clunky since bbs_test_assert_equals is only for integer comparisons */
	bbs_test_assert_str_equals(user, "test");
	bbs_test_assert_str_equals(domain, "example.com");

	res = 0;

cleanup:
	return res;
}

static struct bbs_unit_test tests[] =
{
	{ "Parse Email Addresses", test_parse_email },
};

struct smtp_delivery_handler {
	struct smtp_delivery_agent *agent;
	int priority;
	void *mod;
	RWLIST_ENTRY(smtp_delivery_handler) entry;
};

static RWLIST_HEAD_STATIC(handlers, smtp_delivery_handler);

int __smtp_register_delivery_handler(struct smtp_delivery_agent *agent, int priority, void *mod)
{
	struct smtp_delivery_handler *h;

	h = calloc(1, sizeof(*h));
	if (ALLOC_FAILURE(h)) {
		return -1;
	}

	h->agent = agent;
	h->priority = priority;
	h->mod = mod;

	RWLIST_WRLOCK(&handlers);
	RWLIST_INSERT_SORTED(&handlers, h, entry, priority);
	RWLIST_UNLOCK(&handlers);
	return 0;
}

int smtp_unregister_delivery_agent(struct smtp_delivery_agent *agent)
{
	struct smtp_delivery_handler *h;

	RWLIST_WRLOCK(&handlers);
	RWLIST_TRAVERSE_SAFE_BEGIN(&handlers, h, entry) {
		if (h->agent == agent) {
			RWLIST_REMOVE_CURRENT(entry);
			free(h);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&handlers);
	return h ? 0 : -1;
}

static int add_recipient(struct smtp_session *smtp, int local, const char *s, int assumelocal)
{
	char buf[256];
	const char *recipient = s;

	if (!strchr(recipient, '@')) {
		/* Assume local user if no domain present */
		if (assumelocal) {
			snprintf(buf, sizeof(buf), "%s@%s", recipient, bbs_hostname());
			recipient = buf;
		}
	}

	if (stringlist_contains(&smtp->recipients, recipient)) {
		/* Recipient was already added. */
		return 1;
	}
	stringlist_push(&smtp->recipients, recipient);
	smtp->tflags.numrecipients += 1;
	if (local) {
		smtp->tflags.numlocalrecipients += 1;
	} else {
		smtp->tflags.numexternalrecipients += 1;
	}
	return 0;
}

static int handle_rcpt(struct smtp_session *smtp, char *s)
{
	int local, res = 0;
	char *user, *domain;
	char *address;
	struct smtp_delivery_handler *h;
	struct smtp_response error;

	/* If MAIL FROM is an address that belongs to us,
	 * then authentication is required. Any recipients are allowed.
	 * If not, it's an external email, no authentication is required,
	 * and all the recipients must belong to us (we're not an open mail relay!) */

	/* If the email is being sent from a local user, must be authenticated. */
	if (smtp->fromlocal && !bbs_user_is_registered(smtp->node->user)) {
		smtp_reply(smtp, 530, 5.7.0, "Authentication required");
		return 0;
	}

	if (!smtp->fromlocal && !accept_relay_in) {
		smtp_reply(smtp, 550, 5.7.1, "Mail not accepted externally here");
		return 0;
	}

	/* Check the recipient format. */
	address = strdup(s); /* Avoid strdupa for gcc stack protector warnings, and who knows how long this is... */
	if (ALLOC_FAILURE(address)) {
		smtp_reply(smtp, 451, "Local error in processing", "");
		return 0;
	}
	if (bbs_parse_email_address(address, NULL, &user, &domain)) {
		free(address);
		smtp_reply(smtp, 501, 5.1.7, "Syntax error in RCPT command"); /* Email address must be enclosed in <> */
		return 0;
	}

	local = mail_domain_is_local(domain);

	memset(&error, 0, sizeof(error));
	/* Check if it's a real mailbox (or an alias that maps to one), a mailing list, etc. */
	RWLIST_RDLOCK(&handlers);
	RWLIST_TRAVERSE(&handlers, h, entry) {
		bbs_module_ref(h->mod);
		res = h->agent->exists(smtp, &error, s, user, domain, smtp->fromlocal, local);
		bbs_module_unref(h->mod);
		if (res) {
			break;
		}
	}
	free(address); /* user and domain are mapped here */
	if (!res) {
		RWLIST_UNLOCK(&handlers);
		smtp_reply(smtp, 550, 5.1.1, "No such user here");
		smtp->failures++;
		return 0;
	} else if (res < 0) {
		smtp_resp_reply(smtp, error.code, error.subcode, error.reply);
		RWLIST_UNLOCK(&handlers);
		smtp->failures++;
		return 0;
	}
	/* Don't unlock handlers yet because error is filled in with memory from handler modules.
	 * Therefore these modules cannot unregister until we're done with that. */
	RWLIST_UNLOCK(&handlers);

	if (smtp->tflags.numlocalrecipients >= MAX_LOCAL_RECIPIENTS || smtp->tflags.numexternalrecipients >= MAX_EXTERNAL_RECIPIENTS || smtp->tflags.numrecipients >= MAX_RECIPIENTS) {
		smtp_reply(smtp, 452, 4.5.3, "Your message has too many recipients");
		return 0;
	}

	/* Actually add the recipient to the recipient list. */
	res = add_recipient(smtp, local, s, 0);
	if (res == 1) {
		smtp_reply(smtp, 250, 2.1.5, "OK, duplicate recipients will be consolidated.");
	} else {
		smtp_reply(smtp, 250, 2.0.0, "OK");
	}
	return 0;
}

void smtp_timestamp(time_t received, char *buf, size_t len)
{
    struct tm smtpdate;

	/* Timestamp is something like Wed, 22 Feb 2023 03:02:22 +0300 */
    localtime_r(&received, &smtpdate);
	strftime(buf, len, "%a, %b %e %Y %H:%M:%S %z", &smtpdate);
}

struct smtp_filter {
	enum smtp_filter_type type;
	enum smtp_filter_scope scope;
	enum smtp_direction direction;
	struct smtp_filter_provider *provider;
	int priority;
	void *mod;
	RWLIST_ENTRY(smtp_filter) entry;
};

static RWLIST_HEAD_STATIC(filters, smtp_filter);

static const char *smtp_filter_type_name(enum smtp_filter_type type)
{
	switch (type) {
		case SMTP_FILTER_PREPEND: return "PREPEND";
		/* No default */
	}
	bbs_assert(0);
	return NULL;
}

int __smtp_filter_register(struct smtp_filter_provider *provider, enum smtp_filter_type type, enum smtp_filter_scope scope, enum smtp_direction dir, int priority, void *mod)
{
	struct smtp_filter *f;

	/* Not all combinations of scope and direction are supported */
	if (scope == SMTP_SCOPE_INDIVIDUAL && dir == SMTP_DIRECTION_SUBMIT) {
		bbs_error("Individual filters not supported for submission direction\n");
		return -1;
	}

	f = calloc(1, sizeof(*f));
	if (ALLOC_FAILURE(f)) {
		return -1;
	}
	f->provider = provider;
	f->type = type;
	f->scope = scope;
	f->direction = dir;
	f->priority = priority;
	f->mod = mod;
	RWLIST_WRLOCK(&filters);
	RWLIST_INSERT_SORTED(&filters, f, entry, priority);
	RWLIST_UNLOCK(&filters);
	return 0;
}

int smtp_filter_unregister(struct smtp_filter_provider *provider)
{
	struct smtp_filter *f;
	RWLIST_WRLOCK(&filters);
	RWLIST_TRAVERSE_SAFE_BEGIN(&filters, f, entry) {
		if (f->provider == provider) {
			RWLIST_REMOVE_CURRENT(entry);
			free(f);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&filters);
	return f ? 0 : -1;
}

struct bbs_node *smtp_node(struct smtp_session *smtp)
{
	return smtp->node;
}

const char *smtp_protname(struct smtp_session *smtp)
{
	/* RFC 2822, RFC 3848, RFC 2033 */
	if (smtp->ehlo) {
		if (smtp->secure) {
			if (bbs_user_is_registered(smtp->node->user)) {
				return "ESMTPSA";
			} else {
				return "ESMTPS";
			}
		}
		return "ESMTP";
	}
	return "SMTP";
}

int smtp_should_validate_spf(struct smtp_session *smtp)
{
	return validatespf && !smtp->fromlocal;
}

int smtp_should_validate_dkim(struct smtp_session *smtp)
{
	return smtp->tflags.dkimsig;
}

int smtp_is_message_submission(struct smtp_session *smtp)
{
	return smtp->msa;
}

int smtp_should_preserve_privacy(struct smtp_session *smtp)
{
	return smtp->msa && !add_received_msa;
}

size_t smtp_message_estimated_size(struct smtp_session *smtp)
{
	return smtp->tflags.sizepreview;
}

const char *smtp_message_content_type(struct smtp_session *smtp)
{
	return smtp->contenttype;
}

time_t smtp_received_time(struct smtp_session *smtp)
{
	return smtp->tflags.received;
}

const char *smtp_message_body(struct smtp_filter_data *f)
{
	if (!f->body) {
		ssize_t res;
		f->body = malloc(f->size + 1);
		if (ALLOC_FAILURE(f->body)) {
			return NULL;
		}
		res = read(f->inputfd, f->body, f->size);
		if (res != (ssize_t) f->size) {
			bbs_warning("Wanted to read %lu bytes but read %ld?\n", f->size, res);
			FREE(f->body);
			return NULL;
		}
		f->body[f->size] = '\0';
	}
	return f->body;
}

int smtp_filter_write(struct smtp_filter_data *f, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int len;

	if (f->outputfd == -1) {
		strcpy(f->outputfile, "/tmp/smtpXXXXXX");
		f->outputfd = mkstemp(f->outputfile);
		if (f->outputfd < 0) {
			bbs_error("mkstemp failed: %s\n", strerror(errno));
			return -1;
		}
		bbs_debug(2, "Creating temporary output file (fd %d)\n", f->outputfd);
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	bbs_write(f->outputfd, buf, (size_t) len);
	bbs_debug(6, "Prepending: %s\n", buf);

	free(buf);
	return len;
}

int smtp_filter_add_header(struct smtp_filter_data *f, const char *name, const char *value)
{
	return smtp_filter_write(f, "%s: %s\r\n", name, value);
}

static const char *smtp_filter_direction_name(enum smtp_direction dir)
{
	if (dir & SMTP_DIRECTION_IN) {
		if (dir & SMTP_DIRECTION_OUT) {
			return dir & SMTP_DIRECTION_SUBMIT ? "SUBMIT|OUT|IN" : "IN|OUT";
		} else {
			return dir & SMTP_DIRECTION_SUBMIT ? "SUBMIT|IN" : "IN";
		}
	} else if (dir & SMTP_DIRECTION_OUT) {
		return dir & SMTP_DIRECTION_SUBMIT ? "SUBMIT|OUT" : "OUT";
	} else if (dir & SMTP_DIRECTION_SUBMIT) {
		return "SUBMIT";
	} else {
		return "NONE";
	}
}

/*! \note This is currently only executed once the entire message has been received.
 * If milter support is added, we'll need hooks at each stage of the delivery process (MAIL FROM, RCPT TO, etc.) */
void smtp_run_filters(struct smtp_filter_data *fdata, enum smtp_direction dir)
{
	struct smtp_filter *f;
	enum smtp_filter_scope scope = fdata->recipient ? SMTP_SCOPE_INDIVIDUAL : SMTP_SCOPE_COMBINED;

	if (!fdata->smtp) {
		bbs_error("Cannot run filters without an SMTP session\n");
		return;
	}

	fdata->dir = dir;
	fdata->from = fdata->smtp->from;
	fdata->node = fdata->smtp->node;

	bbs_debug(4, "Running %s (%s) filters\n", scope == SMTP_SCOPE_COMBINED ? "COMBINED" : "INDIVIDUAL", smtp_filter_direction_name(dir));

	RWLIST_RDLOCK(&filters);
	RWLIST_TRAVERSE(&filters, f, entry) {
		int res = 0;
		if (!(f->direction & fdata->dir)) {
			bbs_debug(5, "Ignoring %s SMTP filter %s %p (wrong direction)...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
			continue;
		}

		/*! \todo SMTP_SCOPE_COMBINED is not currently supported for SMTP_DIRECTION_OUT.
		 * That is treated as SMTP_SCOPE_INDIVIDUAL for now, for the sake of transparency. */
		if (fdata->dir == SMTP_DIRECTION_OUT && f->scope == SMTP_SCOPE_COMBINED) {
			bbs_debug(3, "Treating COMBINED filter as individual due to current lack of native COMBINED/OUT support\n");
		} else

		/* Filter applicable to this direction */
		if (f->scope == SMTP_SCOPE_INDIVIDUAL) {
			if (!fdata->recipient) {
				bbs_debug(5, "Ignoring %s SMTP filter %s %p (wrong scope)...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
				continue;
			}
		} else {
			if (fdata->recipient) {
				bbs_debug(5, "Ignoring %s SMTP filter %s %p (wrong scope)...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
				continue;
			}
		}
		if (fdata->dir == SMTP_DIRECTION_IN && !fdata->node) {
			/* Something like a Delivery Status Notification or other injected mail without a node... filters don't apply anyways. */
			continue;
		}
		/* Filter applicable to scope */
		bbs_debug(5, "Executing %s SMTP filter %s %p...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
		bbs_module_ref(f->mod);
		if (f->type == SMTP_FILTER_PREPEND) {
			bbs_assert_exists(f->provider);
			res = f->provider->on_body(fdata);
		} else {
			bbs_error("Filter type %d not supported\n", f->type);
		}
		bbs_module_unref(f->mod);
		lseek(fdata->inputfd, 0, SEEK_SET); /* Rewind to beginning of file */
		if (res == 1) {
			bbs_debug(5, "Aborting filter execution\n");
			break;
		} else if (res < 0) {
			bbs_warning("%s SMTP filter %s %p failed to execute\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
		}
	}
	RWLIST_UNLOCK(&filters);

	free_if(fdata->body);
	free_if(fdata->spf);
	free_if(fdata->dkim);
	free_if(fdata->arc);
	free_if(fdata->dmarc);
	free_if(fdata->authresults);
}

void smtp_mproc_init(struct smtp_session *smtp, struct smtp_msg_process *mproc)
{
	memset(mproc, 0, sizeof(struct smtp_msg_process));
	mproc->fd = smtp->wfd;
	safe_strncpy(mproc->datafile, smtp->template, sizeof(mproc->datafile));
	mproc->node = smtp->node;
	mproc->from = smtp->from;
	mproc->forward = &smtp->recipients; /* Tack on forwarding targets to the recipients list */
}

struct smtp_processor {
	int (*cb)(struct smtp_msg_process *proc);
	void *mod;
	RWLIST_ENTRY(smtp_processor) entry;
};

static RWLIST_HEAD_STATIC(processors, smtp_processor);

int __smtp_register_processor(int (*cb)(struct smtp_msg_process *mproc), void *mod)
{
	struct smtp_processor *proc;

	proc = calloc(1, sizeof(*proc));
	if (ALLOC_FAILURE(proc)) {
		return -1;
	}

	proc->cb = cb;
	proc->mod = mod;

	RWLIST_WRLOCK(&processors);
	RWLIST_INSERT_TAIL(&processors, proc, entry);
	RWLIST_UNLOCK(&processors);
	return 0;
}

int smtp_unregister_processor(int (*cb)(struct smtp_msg_process *mproc))
{
	struct smtp_processor *proc;

	proc = RWLIST_WRLOCK_REMOVE_BY_FIELD(&processors, cb, cb, entry);
	if (!proc) {
		bbs_error("Couldn't remove processor %p\n", cb);
		return -1;
	}
	free(proc);
	return 0;
}

int smtp_run_callbacks(struct smtp_msg_process *mproc)
{
	int res = 0;
	struct smtp_processor *proc;

	RWLIST_RDLOCK(&processors);
	RWLIST_TRAVERSE(&processors, proc, entry) {
		bbs_module_ref(proc->mod);
		res |= proc->cb(mproc);
		bbs_module_unref(proc->mod);
		if (res) {
			break; /* Stop processing immediately if a processor returns nonzero */
		}
	}
	RWLIST_UNLOCK(&processors);
	return res;
}

struct smtp_delivery_outcome {
	/* Allocated using data FSM */
	const char *recipient;
	const char *hostname;
	const char *ipaddr;
	const char *status;
	const char *error;
	/* Not allocated */
	const char *prot;
	const char *stage;
	enum smtp_delivery_action action;
	struct tm *retryuntil;
	char data[];
};

struct smtp_delivery_outcome *smtp_delivery_outcome_new(const char *recipient, const char *hostname, const char *ipaddr, const char *status, const char *error, const char *prot, const char *stage, enum smtp_delivery_action action, struct tm *retryuntil)
{
	struct smtp_delivery_outcome *f;
	size_t reciplen, hostlen, iplen, statuslen, errorlen;
	char *data;

	reciplen = STRING_ALLOC_SIZE(recipient);
	hostlen = STRING_ALLOC_SIZE(hostname);
	iplen = STRING_ALLOC_SIZE(ipaddr);
	statuslen = STRING_ALLOC_SIZE(status);
	errorlen = STRING_ALLOC_SIZE(error);

	f = calloc(1, sizeof(*f) + reciplen + hostlen + iplen + errorlen);
	if (ALLOC_FAILURE(f)) {
		return NULL;
	}

	data = f->data;
	SET_FSM_STRING_VAR(f, data, recipient, recipient, reciplen);
	SET_FSM_STRING_VAR(f, data, hostname, hostname, hostlen);
	SET_FSM_STRING_VAR(f, data, ipaddr, ipaddr, iplen);
	SET_FSM_STRING_VAR(f, data, status, status, statuslen);
	SET_FSM_STRING_VAR(f, data, error, error, errorlen);

	f->stage = stage; /* This is constant memory and will remain valid, just use that */
	f->prot = prot;
	f->action = action;
	f->retryuntil = retryuntil;
	return f;
}

void smtp_delivery_outcome_free(struct smtp_delivery_outcome **f, int n)
{
	int i = 0;
	for (i = 0; i < n; i++) {
		free(f[i]);
	}
}

static const char *delivery_action_name(enum smtp_delivery_action action)
{
	switch (action) {
		case DELIVERY_FAILED: return "failed";
		case DELIVERY_DELAYED: return "delayed";
		case DELIVERY_DELIVERED: return "delivered";
		case DELIVERY_RELAYED: return "relayed";
		case DELIVERY_EXPANDED: return "expanded";
		/* No default */
	}
	bbs_assert(0);
	return NULL;
}

static const char *delivery_subject_name(struct smtp_delivery_outcome **f, int n)
{
	if (n != 1) {
		/* Could be multiple different actions, just stay generic */
		return "Delivery Status Notification";
	}
	switch (f[0]->action) {
		/* "Undelivered Mail Returned to Sender" is another common subject for failures */
		case DELIVERY_FAILED: return "Delivery Status Notification (Failure)";
		case DELIVERY_DELAYED: return "Delivery Status Notification (Delay)";
		case DELIVERY_DELIVERED: return "Delivery Status Notification (Delivered)";
		case DELIVERY_RELAYED: return "Delivery Status Notification (Relayed)";
		case DELIVERY_EXPANDED: return "Delivery Status Notification (Expanded)";
		/* No default */
	}
	bbs_assert(0);
	return NULL;
}

/* Forward declaration */
static int nosmtp_deliver(const char *filename, const char *sender, const char *recipient, size_t length);

static int any_failures(struct smtp_delivery_outcome **f, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (f[i]->action != DELIVERY_DELIVERED) {
			return 1;
		}
	}
	return 0;
}

int smtp_dsn(const char *sendinghost, struct tm *arrival, const char *sender, int srcfd, int offset, size_t msglen, struct smtp_delivery_outcome **f, int n)
{
	int i, res;
	char tmpattach[256] = "/tmp/bouncemsgXXXXXX";
	FILE *fp;
	char bound[256];
	char date[256], date2[256];
	struct tm tm;
	size_t length;
	time_t t = time(NULL);

	/* The MAIL FROM in non-delivery reports is always empty to prevent looping.
	 * e.g. if we're bouncing a bounce, just abort. */
	if (strlen_zero(sender)) {
		bbs_warning("MAIL FROM is empty, cannot deliver non-delivery report\n");
		return -1;
	}

	fp = bbs_mkftemp(tmpattach, 0600);
	if (!fp) {
		return -1;
	}

	/* Format of the non-delivery report is defined in RFC 3461 Section 6 */

	/* Generate headers */
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", localtime_r(&t, &tm));
	fprintf(fp, "Date: %s\r\n", date);
	fprintf(fp, "From: \"Mail Delivery Subsystem\" <mailer-daemon@%s>\r\n", bbs_hostname());
	fprintf(fp, "Subject: %s\r\n", delivery_subject_name(f, n));
	fprintf(fp, "To: %s\r\n", sender);
	fprintf(fp, "Auto-Submitted: auto-replied\r\n");
	fprintf(fp, "Message-ID: <%s-%u-%d@%s>\r\n", "LBBS-NDR", (unsigned int) random(), (int) getpid(), bbs_hostname());
	fprintf(fp, "MIME-Version: 1.0\r\n");
	snprintf(bound, sizeof(bound), "----attachment_%d%u", (int) getpid(), (unsigned int) random());
	fprintf(fp, "Content-Type: multipart/report; report-type=delivery-status;\r\n"
		"\tboundary=\"%s\"\r\n", bound);
	fprintf(fp, "\r\n" "This is a multi-part message in MIME format.\r\n\r\n");

	/* Generate body */

	/* Notification */
	fprintf(fp, "--%s\r\n", bound);
	fprintf(fp, "Content-Description: Notification\r\n");
	fprintf(fp, "Content-Type: text/plain; charset=utf-8\r\n");
	fprintf(fp, "\r\n");

	fprintf(fp, "This is the mail system at host %s.\r\n\r\n", bbs_hostname());
	if (any_failures(f, n)) {
		fprintf(fp, "I'm sorry to have to inform you that your message could not\r\n"
			"be delivered to one or more recipients. It's attached below.\r\n\r\n");
		fprintf(fp, "For further assistance, please send mail to postmaster.\r\n\r\n");
		fprintf(fp, "If you do so, please include this problem report. You can delete your own text from the attached returned message.\r\n\r\n");
	}
	fprintf(fp, "Please, do not reply to this message.\r\n\r\n\r\n");

	/* One for each recipient in the report */
	for (i = 0; i < n; i++) {
		const char *hostname = S_OR(f[i]->hostname, bbs_hostname());
		fprintf(fp, "%s:\r\n\thost %s", f[i]->recipient, hostname);
		if (f[i]->ipaddr) { /* Maybe not be one if we could not connect */
			fprintf(fp, "[%s]", f[i]->ipaddr);
		}
		if (!strlen_zero(f[i]->error)) {
			fprintf(fp, " said:\r\n\t%s\r\n", f[i]->error);
		}
		if (f[i]->stage) {
			fprintf(fp, "(in reply to %s command)\r\n", f[i]->stage);
		}
	}
	fprintf(fp, "\r\n");

	/* RFC 3464 Delivery report */
	/* 2.2: per-message DSN fields */
	fprintf(fp, "--%s\r\n", bound);
	fprintf(fp, "Content-Description: Delivery report\r\n");
	fprintf(fp, "Content-Type: message/delivery-status\r\n");
	fprintf(fp, "\r\n");

	fprintf(fp, "Reporting-MTA: %s; %s\r\n", !bbs_hostname_is_ipv4(bbs_hostname()) ? "dns" : "x-local-hostname", bbs_hostname()); /* 2.2.2 */
	if (sendinghost) {
		fprintf(fp, "Received-From-MTA: %s\r\n", sendinghost); /* 2.2.4 */
	}
	if (arrival) {
		strftime(date2, sizeof(date2), "%a, %d %b %Y %H:%M:%S %z", arrival);
		fprintf(fp, "Arrival-Date: %s\r\n", date2); /* 2.2.5 */
	}

	for (i = 0; i < n; i++) {
		/* RFC 3464 2.3: per-recipient DSN fields */
		fprintf(fp, "\r\n"); /* Each recipient preceded by blank line */
		fprintf(fp, "Final-Recipient: rfc822; %s\r\n", f[i]->recipient); /* 2.3.2 */
		fprintf(fp, "Action: %s\r\n", delivery_action_name(f[i]->action)); /* 2.3.3 Action field */
		if (!strlen_zero(f[i]->status)) { /* This is mandatory, but if we don't have one, don't send a null status */
			fprintf(fp, "Status: %s\r\n", f[i]->status); /* 2.3.4: RFC 3463 status code */
		}
		if (!strlen_zero(f[i]->hostname)) {
			fprintf(fp, "Remote-MTA: %s; %s\r\n", !bbs_hostname_is_ipv4(f[i]->hostname) ? "dns" : "x-local-hostname", f[i]->hostname); /* 2.3.5 */
		}
		if (!strlen_zero(f[i]->error)) {
			fprintf(fp, "Diagnostic-Code: %s; %s\r\n", S_OR(f[i]->prot, "x-unknown"), f[i]->error); /* 2.3.6 */
		}
		if (f[i]->action == DELIVERY_DELAYED || f[i]->action == DELIVERY_RELAYED) {
			fprintf(fp, "Last-Attempt-Date: %s\r\n", date); /* 2.3.7: Same as Date, in our case (technically, a little bit before maybe, but not by much) */
		}
		if (f[i]->action == DELIVERY_DELAYED && f[i]->retryuntil) {
			strftime(date2, sizeof(date2), "%a, %d %b %Y %H:%M:%S %z", f[i]->retryuntil);
			fprintf(fp, "Will-Retry-Until: %s\r\n", date2); /* 2.3.9 */
		}
	}
	fprintf(fp, "\r\n");

	/* Actual message, if provided */
	/* XXX Even if available, we may not want to include this for all actions. Failure, definitely. Delayed? Maybe not... */
	if (srcfd != -1 && msglen) {
		fprintf(fp, "--%s\r\n", bound);
		fprintf(fp, "Content-Description: Undelivered message\r\n");
		fprintf(fp, "Content-Type: message/rfc822\r\n");
		fprintf(fp, "\r\n");
		fflush(fp);

		/* Skip first metalen characters, and send msgsize - metalen, to copy over just the message itself. */
		bbs_copy_file(srcfd, fileno(fp), offset, (int) msglen);

		fseek(fp, 0, SEEK_END);
		fprintf(fp, "--%s\r\n", bound);
	}

	fflush(fp);
	length = (size_t) ftell(fp);
	fclose(fp);

	res = nosmtp_deliver(tmpattach, "", sender, length); /* Empty MAIL FROM for DSNs */
	unlink(tmpattach);
	return res;
}

static int duplicate_loop_avoidance(struct smtp_session *smtp, char *recipient)
{
	char *tmp = NULL;
	const char *normalized_recipient;
	/* The MailScript FORWARD rule will result in recipients being added to
	 * the recipients list while we're in this loop.
	 * However the same message is sent to the new target, since we forward the raw message, which means
	 * we can't rely on counting Received headers to detect mail loops (for local users).
	 * Perhaps even more appropriate would be keeping track of the user ID instead of the recipient,
	 * to also account for aliases (but it should be fine).
	 * This avoids loops not detected by counting Received headers:
	 */
	/*! \todo Is this entirely sufficient/appropriate? We should ALSO add a single Received header on forwards */
	/* Keep track that we have sent a message to this recipient */
	if (*recipient == '<') {
		tmp = strrchr(recipient, '>');
		if (tmp && *(tmp + 1)) {
			tmp = NULL;
		}
		if (tmp) {
			*tmp = '\0';
		}
	}
	/* Add (and check) without <> so it's more normalized and consistent for comparisons. */
	normalized_recipient = tmp ? recipient + 1 : recipient;
	if (stringlist_contains(&smtp->sentrecipients, normalized_recipient)) {
		bbs_warning("Skipping duplicate delivery to %s\n", normalized_recipient);
		free(recipient);
		return -1;
	}
	stringlist_push(&smtp->sentrecipients, normalized_recipient);
	bbs_debug(7, "Processing delivery to %s\n", normalized_recipient);
	if (tmp) {
		*tmp = '>'; /* Restore it back */
	}
	return 0;
}

/*! \brief "Stand and deliver" that email! */
static int expand_and_deliver(struct smtp_session *smtp, const char *filename, size_t datalen)
{
	char *recipient;
	int res = 0;
	int srcfd;
	int total, succeeded = 0;
	struct smtp_filter_data filterdata;
	struct smtp_delivery_outcome *bounces[MAX_RECIPIENTS];
	int numbounces = 0;
	struct smtp_response resp;
	void *freedata = NULL;

	/* Preserve the actual received time for the Received header, in case filters take a moment to run */
	smtp->tflags.received = time(NULL);

	srcfd = open(filename, O_RDONLY);
	if (srcfd < 0) {
		bbs_error("open(%s) failed: %s\n", filename, strerror(errno));
		return -1;
	}

	/* Ordering here is important. For local delivery:
	 * 1) First, filters are run for the message itself (SMTP_SCOPE_COMBINED). Filters may MODIFY the data, but may do nothing at all.
	 *    This first stage is where spam filtering should be done to prepend spam-related headers.
	 * 2) Then, smtp_mproc callbacks are run. These callbacks are READ ONLY and are action-oriented.
	 *    This might be where a user has a rule like "If spam header says this is spam, move it to Junk".
	 *    Importantly, the spam filter MUST have already run and modified the message by this point.
	 * 3) Finally, filters are run AGAIN for the message, for each individual recipient. This is where the Received header, etc. are prepended.
	 *    Note that it's possible we might abort at Step 2 if a rule says to reject the message.
	 *    This is fine, because the filters at step 3 only matter if we're going to deliver the message anyways. Otherwise, why bother?
	 *
	 * Only after all of this is the message actually written into the user's maildir.
	 *
	 * Note that DKIM signing is done for SUBMIT scope, and MailScript rules for SMTP_MSG_DIRECTION_OUT have already run,
	 * so if headers were rewritten by rules, that's already done by the time of DKIM signing.
	 */
	memset(&filterdata, 0, sizeof(filterdata));
	filterdata.smtp = smtp;
	filterdata.recipient = NULL; /* This is for the message as a whole, not each recipient. Just making that explicit. */
	filterdata.inputfd = srcfd;
	filterdata.size = datalen;
	filterdata.outputfd = -1;
	smtp_run_filters(&filterdata, smtp->msa ? SMTP_DIRECTION_SUBMIT : SMTP_DIRECTION_IN);

	/* Since outputfd was originally -1, if it's not any longer,
	 * that means the source has been modified and we should use that as the new source */
	if (filterdata.outputfd != -1) {
		int oldsrcfd = srcfd;
		srcfd = filterdata.outputfd;
		bbs_debug(6, "New source file descriptor: %d -> %d\n", oldsrcfd, srcfd);

		/* Since we had to make a new interim file, copy the original message and append it to the newly created file. */
		if (bbs_copy_file(oldsrcfd, srcfd, 0, (int) datalen) != (int) datalen) {
			return -1;
		}
		close(oldsrcfd);
		datalen = (size_t) lseek(srcfd, 0, SEEK_CUR); /* Get new size of data */
		close(srcfd);
		srcfd = open(filterdata.outputfile, O_RDONLY);
		if (srcfd < 0) {
			bbs_error("open(%s) failed: %s\n", filterdata.outputfile, strerror(errno));
			return -1;
		}
	}

	total = stringlist_size(&smtp->recipients);
	if (total < 1) {
		bbs_warning("Message has no recipients?\n");
		return -1;
	}

	memset(&resp, 0, sizeof(resp)); /* Just in case there are no recipients? */
	RWLIST_RDLOCK(&handlers);
	while ((recipient = stringlist_pop(&smtp->recipients))) {
		char *user, *domain;
		char *dup;
		int local;
		struct smtp_delivery_handler *h;
		int mres = 0;

		if (duplicate_loop_avoidance(smtp, recipient)) {
			continue;
		}

		dup = strdup(recipient);
		if (ALLOC_FAILURE(dup)) {
			goto next;
		}
		/* We already did this when we got RCPT TO, so hopefully we're all good here. */
		if (bbs_parse_email_address(dup, NULL, &user, &domain)) {
			goto next;
		}
		local = mail_domain_is_local(domain);
		RWLIST_TRAVERSE(&handlers, h, entry) {
			memset(&resp, 0, sizeof(resp));
			bbs_module_ref(h->mod);
			mres = h->agent->deliver(smtp, &resp, smtp->from, recipient, user, domain, smtp->fromlocal, local, srcfd, datalen, &freedata);
			bbs_module_unref(h->mod);
			if (mres) {
				bbs_debug(6, "SMTP delivery agent returned %d\n", mres);
				break;
			}
		}
		if (mres == 1) {
			/* Delivery or queuing to this recipient succeeded */
			succeeded++;
		} else if (res < 0) { /* Includes if the message has no handler */
			/* Process any error message before unlocking the list.
			 * If there are multiple recipients, we cannot send an SMTP reply
			 * just for one of the recipients (otherwise we might send multiple SMTP responses).
			 * Instead, we have to send a bounce message.
			 * If this is the only recipient, we can bounce at the SMTP level. */
			if (total > 1) {
				char bouncemsg[512];
				struct smtp_delivery_outcome *f;
				/* Since there's more than one recipient, we need to send a bounce
				 * to the sender. This ensures there is only one SMTP reply at the
				 * end of the entire operation. We still send at most 1 nondelivery report here.
				 * Note that there may still be multiple NDRs sent overall, because
				 * this path is only likely to catch failures to local mailboxes.
				 * Remote deliveries are queued and thus will result in individual
				 * NDRs per recipient returned. */
				/* Ideally, this path is avoided as much as possible. Invalid recipients are rejected at RCPT TO stage,
				 * and ideally we should catch all other recipient errors (e.g. out of quota) there, rather than here,
				 * so that the upstream MTA can handle errors for each recipient directly. */
				snprintf(bouncemsg, sizeof(bouncemsg), "%d%s%s %s",
					resp.code ? resp.code : 451, resp.subcode ? " " : "", S_OR(resp.subcode, ""),
					S_OR(resp.reply, "Message delivery failed"));
				f = smtp_delivery_outcome_new(recipient, NULL, NULL, resp.subcode, bouncemsg, "x-unix", "end of DATA", DELIVERY_FAILED, NULL);
				if (ALLOC_SUCCESS(f)) {
					bounces[numbounces++] = f;
				}
			}
		}
next:
		free_if(dup);
		free(recipient);
	}

	if (succeeded && total > succeeded) {
		/* Delivery to some (but not all) recipients failed. We need to send a bounce.
		 * We use the MAIL FROM here, and our MAIL FROM is empty (postmaster). */
		struct tm tm;
		lseek(srcfd, 0, SEEK_SET);
		localtime_r(&smtp->tflags.received, &tm);
		smtp_dsn(smtp->helohost, &tm, smtp->from, srcfd, 0, datalen, bounces, numbounces);
	} else {
		/* If delivery to all recipients failed, then we can just reply with an SMTP error code.
		 * We'll just use the error code for the last recipient attempted, even though that
		 * may not accurately reflect the issues pertaining to all other recipients. */
	}

	smtp_delivery_outcome_free(bounces, numbounces);

	if (succeeded) { /* If anything succeeded, reply with a 250 OK. We already send individual bounces for the failed recipients. */
		smtp_reply(smtp, 250, 2.6.0, "Message accepted for delivery");
	} else if (resp.code && !strlen_zero(resp.subcode) && !strlen_zero(resp.reply)) { /* All deliveries failed */
		/* We could also send a bounce in this case, but even easier, just do it in the SMTP transaction */
		smtp_resp_reply(smtp, resp.code, resp.subcode, resp.reply);
	}

	RWLIST_UNLOCK(&handlers); /* Can't unlock while resp might still be used, and it's a RDLOCK, so okay */

	free_if(freedata);
	close(srcfd);
	if (filterdata.outputfd != -1) {
		if (unlink(filterdata.outputfile)) {
			bbs_error("unlink(%s) failed: %s\n", filterdata.outputfile, strerror(errno));
		}
	}

	return succeeded ? 0 : resp.code ? 1 : -1; /* -1: Trigger the default failure reply */
}

int smtp_inject(const char *mailfrom, struct stringlist *recipients, const char *filename, size_t length)
{
	int res;
	struct smtp_session smtp;

	/*! \todo Refactor things so we don't have to create a dummy SMTP structure */
	memset(&smtp, 0, sizeof(smtp));

	smtp.fromlocal = 1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	/*! \todo Also kind of annoying that MAIL FROM should not have <> but RCPT TO needs to. Should be consistent (ideally without?) */
	smtp.from = (char*) mailfrom;
#pragma GCC diagnostic pop

	safe_strncpy(smtp.template, filename, sizeof(smtp.template));

	memcpy(&smtp.recipients, recipients, sizeof(smtp.recipients));

	res = expand_and_deliver(&smtp, filename, length);
	/* Since these are normally consumed, there is no guarantee to the caller what will be leftover here, so just clean up */
	stringlist_empty(&smtp.recipients);
	stringlist_empty(&smtp.sentrecipients);

	return res;
}

/*!
 * \brief Inject a message to deliver via SMTP, from outside of the SMTP protocol
 * \param filename Entire RFC822 message
 * \param from MAIL FROM. Do not include <>.
 * \param recipient RCPT TO. Must include <>.
 * \return Same as expand_and_deliver's return value.
 */
static int nosmtp_deliver(const char *filename, const char *sender, const char *recipient, size_t length)
{
	struct stringlist slist;

	/*! \todo The mail interface should probably accept a stringlist globally, since it's reasonable to have multiple recipients */
	memset(&slist, 0, sizeof(slist));
	stringlist_push(&slist, recipient);

	return smtp_inject(sender, &slist, filename, length);
}

/*! \brief Accept messages injected from the BBS to deliver, to local or external recipients */
static int injectmail(MAILER_PARAMS)
{
	int res;
	FILE *fp;
	long int length;
	char tmp[80] = "/tmp/bbsmail-XXXXXX";
	char sender[256];
	char recipient[256];
	char *tmpaddr;

	UNUSED(async); /* Currently they're synchronous if local and asynchronous if external, which is just fine */

	/* Build the message itself */
	fp = bbs_mkftemp(tmp, MAIL_FILE_MODE);
	if (!fp) {
		return -1;
	}
	/*! \note Lines must be no longer than 998 lines. bbs_make_email_file file doesn't enforce that,
	 * the overarching application needs to. */
	bbs_make_email_file(fp, subject, body, to, from, replyto, errorsto, NULL, 0);
	length = ftell(fp);
	fclose(fp);

	/* Set up the envelope */
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	/* This is just for the MAIL FROM, so just the address, no name */
	tmpaddr = strchr(from, '<');
	if (tmpaddr) {
		bbs_strncpy_until(sender, tmpaddr + 1, sizeof(sender), '>');
	} else {
		safe_strncpy(sender, from, sizeof(sender));
	}
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
	

	/* This should be enclosed in <>, but there must not be a name.
	 * That's because the queue file writer expects us to provide <> around TO, but not FROM... it's a bit flimsy. */
	tmpaddr = strchr(to, '<');
	if (tmpaddr) {
		safe_strncpy(recipient, tmpaddr, sizeof(recipient));
	} else {
		snprintf(recipient, sizeof(recipient), "<%s>", to);
	}

	res = nosmtp_deliver(tmp, sender, recipient, (size_t) length);

	unlink(tmp);
	bbs_debug(3, "injectmail res=%d, sender=%s, recipient=%s\n", res, sender, recipient);

	/* This is likely to be used for sending mail to only one user at a time, so we can just return
	 * 0 if it succeeds, 1 if exists but unable to deliver, and -1 if couldn't deliver. */
	return res ? -1 : 0;
}

static int check_identity(struct smtp_session *smtp, char *s)
{
	char *user, *domain;
	struct mailbox *sendingmbox;
	char sendersfile[256];
	char buf[32];
	FILE *fp;

	/* Must use bbs_parse_email_address for sure, since From header could contain a name, not just the address that's in the <> */
	if (bbs_parse_email_address(s, NULL, &user, &domain)) {
		smtp_reply(smtp, 550, 5.7.1, "Malformed From header");
		return -1;
	}
	if (!domain || !mail_domain_is_local(domain)) { /* Wrong domain, or missing domain altogether, yikes */
		smtp_reply(smtp, 550, 5.7.1, "You are not authorized to send email using this identity");
		return -1;
	}
	/* Check what mailbox the sending username resolves to.
	 * One corner case is the catch all address. This user is allowed to send email as any address,
	 * which makes sense since the catch all is going to be the sysop, if it exists. */
	sendingmbox = mailbox_get_by_name(user, domain);
	if (!sendingmbox) {
		goto fail; /* If you can't send email to this address, then email can't be sent from it, simple as that. */
	}

	if (mailbox_id(sendingmbox) && mailbox_id(sendingmbox) == (int) smtp->node->user->id) {
		goto success; /* This is the common case. It's the same user sending email as him or herself. */
	}

	bbs_assert(bbs_user_is_registered(smtp->node->user));

	/* Finally, check if user is authorized by ACL explicitly to send email as a certain user.
	 * The 'p' IMAP ACL right is actually not relevant for this. That is used to
	 * denote authorization to submit mail *to* the IMAP folder.
	 * This right is not used by the BBS mail servers.
	 *
	 * So we use a separate file for this, a .senders file in the root maildir for a mailbox,
	 * that explicitly lists users authorized to send mail as a certain user / address.
	 * Currently, there is no way for this to be managed; the file must be manually created and modified as needed by the sysop.
	 */

	snprintf(sendersfile, sizeof(sendersfile), "%s/.senders", mailbox_maildir(sendingmbox));
	fp = fopen(sendersfile, "r");
	if (!fp) {
		goto fail;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		bbs_term_line(buf); /* Since this file is manually modified, tolerate CR LF line endings as well. */
		if (!strcasecmp(buf, bbs_username(smtp->node->user))) {
			bbs_debug(6, "Send-as capability granted explicitly to %s for %s\n", bbs_username(smtp->node->user), user);
			fclose(fp);
			goto success;
		}
	}
	fclose(fp);

success:
	bbs_debug(5, "User %s authorized to send mail as %s@%s\n", bbs_username(smtp->node->user), user, domain);
	return 0;

fail:
	/* It resolved to something else (or maybe nothing at all, if NULL). Reject. */
	bbs_warning("Rejected attempt by %s to send email as %s@%s (%d != %u)\n", bbs_username(smtp->node->user), user, domain,
		sendingmbox ? mailbox_id(sendingmbox) : 0, smtp->node->user->id);
	smtp_reply(smtp, 550, 5.7.1, "You are not authorized to send email using this identity");
	return -1;
}

/*! \brief Actually send an email or queue it for delivery */
static int do_deliver(struct smtp_session *smtp, const char *filename, size_t datalen)
{
	int res = 0;
	struct smtp_msg_process mproc;

	memset(&mproc, 0, sizeof(mproc));

	bbs_debug(7, "Processing message from %s for delivery: local=%d, size=%lu, from=%s\n", smtp->msa ? "MSA" : "MTA", smtp->fromlocal, datalen, smtp->from);

	if (smtp->tflags.datalen >= max_message_size) {
		/* XXX Should this only apply for local deliveries? */
		smtp_reply(smtp, 552, 5.3.4, "Message too large");
		return 0;
	}

	/* SMTP callbacks for outgoing messages */
	if (smtp->msa) {
		char newfile[256] = "";
		int srcfd = -1;
		smtp_mproc_init(smtp, &mproc);
		mproc.size = (int) datalen;
		mproc.direction = SMTP_MSG_DIRECTION_OUT;
		mproc.mbox = NULL;
		mproc.userid = (int) smtp->node->user->id;
		mproc.user = smtp->node->user;
		if (smtp_run_callbacks(&mproc)) {
			return 0; /* If returned nonzero, it's assumed it responded with an SMTP error code as appropriate. */
		}
		/*
		 * For incoming messages, we process MOVETO after DROP, since if we drop, we're probably discarding,
		 * but here we process it first.
		 * By default, outgoing SMTP submissions aren't saved at all (persistently).
		 * This accounts for the case where we want to save a local copy,
		 * i.e. emulating IMAP's APPEND, but having the SMTP server do it
		 * to the client doesn't have to upload the message twice.
		 * If we're relaying, we might RELAY and then DROP, so we should save the copy before we abort.
		 *
		 * This is the same idea behind BURL IMAP by the way, but BURL IMAP requires both client and server supports,
		 * and BURL support is virtually nonexistent amongst clients - only Trojita supports it.
		 * Some servers, including this one, support BURL, but it's not very useful for that reason.
		 *
		 * This here is more similar to the old "auto Bcc yourself on all emails, filter those into Sent,
		 * and don't upload Sent copies" trick, which takes advantage of user's faster download speeds
		 * compared to upload speeds, typically (e.g. ADSL).
		 * Likewise, the functionality here requires no special client support, other than disabling
		 * "Save a sent copy of messages to... (Sent)", as now the server will save messages for the client.
		 *
		 * Some servers like Gmail in fact do this automatically (which is why you may see duplicate Sent messages
		 * if your client is also uploading them). The difference here is hopefully the client is smart and does
		 * MOVETO Sent to save sent messages to the Sent folder, rather than Gmail just placing them in the same one (e.g. INBOX).
		 *
		 * Now, for some implementation concerns:
		 * Mail clients will try to save sent messages in the account's main Sent mailbox,
		 * even if this is for a "subaccount" visible in Other Users / Shared Folders.
		 * This makes sense, since if you just change the From address, the MUA doesn't really know what you're doing.
		 * Yet another reason why you might prefer to have the mail client NOT save copies of sent messages itself,
		 * and handle that server side: the mail client will always put sent messages in the account's main Sent folder,
		 * but maybe they should be saved in one of the Other Users / Shared Folders sent folders instead,
		 * or it should be appended to a remote IMAP mailbox (in the case of an SMTP relayed submission),
		 * and our job is basically to act as a sort of BURL-like proxy: append the message on behalf of the client,
		 * which means that the message is still sent twice, ultimately, but the client only sends it once to us,
		 * and we send it twice, to the SMTP server, and then APPENDing to the IMAP server.
		 * Regardless of the scenario, handling saving of sent messages server-side is going to be more efficient.
		 *
		 * For Proxied SMTP accounts, the MOVETO to a remote location needs to transparently APPEND.
		 *
		 * Note that we actually save a copy of the message BEFORE it gets Sent (kind of like BURL IMAP).
		 * The reason for this is that if we relayed it first and then saved it, but saving failed,
		 * then we would not be able to return an error at that point since the message was already sent.
		 * But that would mean the user wouldn't know the message wasn't saved, which is bad.
		 * By trying to save it first (which should succeed), we ensure we can return an error at that point
		 * and also decline to relay or send messages if we were told to save them but failed to.
		 * Now done this way, the actual relaying could still fail, and we'll have saved a copy unnecessarily,
		 * but I guess that's easier to deal with... better to have superflous copies than be missing one altogether.
		 */
		if (mproc.newdir) {
			srcfd = open(filename, O_RDONLY);
			if (srcfd < 0) {
				bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
				res = -1;
			} else {
				struct smtp_delivery_handler *h;
				res = -1;
				RWLIST_RDLOCK(&handlers);
				RWLIST_TRAVERSE(&handlers, h, entry) {
					if (!h->agent->save_copy) {
						continue;
					}
					bbs_module_ref(h->mod);
					/* provided by mod_smtp_delivery_local */
					res = h->agent->save_copy(smtp, &mproc, srcfd, datalen, newfile, sizeof(newfile));
					bbs_module_unref(h->mod);
					if (!res) {
						break;
					}
				}
				RWLIST_UNLOCK(&handlers);
			}
			if (res) {
				smtp_reply(smtp, 550, 5.7.0, "Unable to save sent message"); /* XXX Appropriate SMTP code? */
				CLOSE(srcfd);
				return -1;
			}
		}
		if (mproc.relayroute) { /* This happens BEFORE we check the From identity, which is important for relaying since typically this would be rejected locally. */
			/* Relay it through another MSA */
			if (srcfd == -1) {
				srcfd = open(filename, O_RDONLY);
				if (srcfd < 0) {
					bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
					res = -1;
				}
			}
			if (!res) {
				struct smtp_delivery_handler *h;
				res = -1;
				RWLIST_RDLOCK(&handlers);
				RWLIST_TRAVERSE(&handlers, h, entry) {
					if (!h->agent->relay) {
						continue;
					}
					bbs_module_ref(h->mod);
					/* provided by mod_smtp_delivery_local */
					res = h->agent->relay(smtp, &mproc, srcfd, datalen, &smtp->recipients);
					bbs_module_unref(h->mod);
					if (!res) {
						break;
					}
				}
				RWLIST_UNLOCK(&handlers);
			}
			FREE(mproc.relayroute);
			mproc.drop = 1; /* We MUST drop any messages that are relayed. We wouldn't be relaying them if we could send them ourselves. */
			if (!res) {
				smtp_reply(smtp, 250, 2.6.0, "Message accepted for relay");
			} else {
				/* XXX If we couldn't relay it immediately, don't queue it, just reject it */
				smtp_reply(smtp, 550, 5.7.0, "Mail relay rejected.");
				if (!s_strlen_zero(newfile)) {
					/* This is the one case where it's convenient to clean up, so we do so.
					 * It's possible, of course, that the message is no longer in "new" but has been moved to "cur".
					 * However, given the common use case is the Sent folder, which most clients don't idle on,
					 * that is still probably unlikely. Delete it if we can, if not, no big deal.
					 *
					 * This also only covers the relaying case. Since messages we sent to another MTA directly
					 * are done in another thread, we don't keep track of saved copies beyond this point,
					 * since we're not going to know immediately if we succeeded or not anyways. So the user will
					 * just have to deal with superflous saved copies, even if the actual sending failed. */
					bbs_delete_file(newfile);
				}
			}
			bbs_debug(5, "Discarding message and ceasing all further processing\n");
			free_if(mproc.bouncemsg);
			return 0;
		}
		close_if(srcfd);
		if (mproc.bounce) {
			const char *msg = "This message has been rejected by the sender";
			msg = S_OR(mproc.bouncemsg, msg);
			smtp_reply(smtp, 554, 5.7.1, "%s", msg); /* XXX Best default SMTP code for this? */
			free_if(mproc.bouncemsg);
		}
		if (mproc.drop) {
			/*! \todo BUGBUG For DIRECTION OUT, if we FORWARD, then DROP, we'll just drop here and forward won't happen (same for BOUNCE) */
			bbs_debug(5, "Discarding message and ceasing all further processing\n");
			return 0; /* Silently drop message. We MUST do this for RELAYed messages, since we must not allow those to be sent again afterwards. */
		}
	}

	if (smtp->msa) {
		/* Verify the address used is one the sender is authorized to use. */
		char fromdup[256];

		bbs_assert(smtp->node->user->id > 0); /* Must be logged in for MSA. */

		/* Check the envelope (MAIL FROM) */
		safe_strncpy(fromdup, smtp->from, sizeof(fromdup));
		if (check_identity(smtp, fromdup)) {
			return 0;
		}
		/* Check From: header in email itself */
		if (!smtp->fromheaderaddress) { /* Didn't get a From address at all. According to RFC 6409, we COULD add a Sender header, but just reject. */
			smtp_reply(smtp, 550, 5.7.1, "Missing From header");
			return 0;
		}
		/* If the two addresses are exactly the same, no need to do the same check twice. */
		if (strcmp(smtp->from, smtp->fromheaderaddress) && check_identity(smtp, smtp->fromheaderaddress)) {
			return 0;
		}
		/* We're good: the From header is either the actual username, or an alias that maps to it. */
		free_if(smtp->fromheaderaddress);
	}

	res = expand_and_deliver(smtp, filename, datalen);
	if (res < 0) { /* Other cases are all handled by expand_and_deliver */
		smtp_reply_nostatus(smtp, 451, "Delivery failed"); /*! \todo add a more specific code */
	}
	return 0;
}

/*! \brief Get the full filename of a message in a folder from its UID */
static int msg_to_filename(const char *path, int uid, char *buf, size_t len)
{
	DIR *dir;
	struct dirent *entry;
	unsigned int msguid;

	/* Order doesn't matter here, we just want the total number of messages, so fine (and faster) to use opendir instead of scandir */
	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		if (maildir_parse_uid_from_filename(entry->d_name, &msguid)) {
			continue;
		}
		if (msguid == (unsigned int) uid) {
			snprintf(buf, len, "%s/%s", path, entry->d_name);
			closedir(dir);
			return 0;
		}
	}

	closedir(dir);
	return -1;
}

static int handle_burl(struct smtp_session *smtp, char *s)
{
	char sentdir[256];
	char msgfile[512];
	char *imapurl, *last;
	char *user, *host, *location, *uidvalidity, *uidstr;
	char *tmp;
	long int msglen;
	char buf[1001];
	FILE *fp;

	REQUIRE_HELO();
	REQUIRE_MAIL_FROM();
	REQUIRE_RCPT();
	REQUIRE_ARGS(s);
	smtp_reset_data(smtp);
	/* Wow! A client that actually supports BURL! That's a rare one...
	 * (at the time of this programming, only Trojita does. Maybe Thunderbird forks will some day?)
	 * In the meantime, this is a feature that almost nobody can use. */
	imapurl = strsep(&s, " "); /* We don't use the generic bbs_parse_url here since we need to parse the IMAP URL fully */
	last = s;
	REQUIRE_ARGS(last);
	if (strcmp(last, "LAST")) {
		smtp_reply(smtp, 554, 5.7.0, "Invalid BURL command");
		return 0;
	}
	/*! \todo RFC 4468 says we MUST support 8BITMIME extension if we support BURL
	 * We probably already do without doing anything, but verify that and add that to the EHLO response */

	/* We'll get a URL that looks something like this:
	 * imap://jsmith@imap.example.com/Sent;UIDVALIDITY=1677584102/;UID=8;urlauth=submit+jsmith:internal
	 */
	bbs_debug(5, "BURL URL: %s\n", imapurl);
	if (STARTS_WITH(imapurl, "imap://")) {
		imapurl += STRLEN("imap://");
	} else if (STARTS_WITH(imapurl, "imaps://")) {
		imapurl += STRLEN("imaps://");
	} else {
		smtp_reply(smtp, 554, 5.7.8, "Invalid IMAP URL");
		return 0;
	}
	host = strsep(&imapurl, "/");
	tmp = strrchr(host, '@'); /* Just in case username contains an @ symbol as well?? */
	if (!tmp) {
		smtp_reply(smtp, 554, 5.7.8, "Invalid IMAP URL");
		return 0;
	}
	*tmp++ = '\0';
	user = host;
	host = tmp;

	if (strcasecmp(host, bbs_hostname())) { /* Hostname is for a different IMAP server */
		smtp_reply(smtp, 554, 5.7.8, "URL resolution requires trust relationship");
		return 0;
	}

	/* Valid check for our minimal BURL implementation, but not if we support URLAUTH in general for arbitrary IMAP servers. */
	if (strcasecmp(user, bbs_username(smtp->node->user))) { /* Different user? */
		smtp_reply(smtp, 554, 5.7.8, "URL invalid for current user");
		return 0;
	}

	location = strsep(&imapurl, ";");
	uidvalidity = strsep(&imapurl, ";");
	uidstr = strsep(&imapurl, ";");
	REQUIRE_ARGS(location);
	REQUIRE_ARGS(uidvalidity);
	REQUIRE_ARGS(uidstr);
	/* Ignore everything else for our minimal implementation */

	/* Why would it be anything besides the Sent folder?
	 * Since the IMAP path parsing routines are all in net_imap,
	 * we can't easily do thorough parsing of arbitrary paths here anyways,
	 * so this allows us to just use the maildir's sent folder. */
	if (strcmp(location, "Sent")) {
		smtp_reply(smtp, 554, 5.7.8, "URL invalid for current user");
		return 0;
	}

	/* Retrieve the message with UID from this folder */
	snprintf(sentdir, sizeof(sentdir), "%s/.Sent/cur", mailbox_maildir(mailbox_get_by_userid(smtp->node->user->id))); /* It was stored using APPEND so it's in cur, not new */
	/* Since this is by UID, not sequence number, the directory scan doesn't need to be sorted. */
	/* Here's the trick: Instead of contacting the IMAP server agnostically, just pull the message right from disk directly. */
	if (!STARTS_WITH(uidstr, "UID=")) {
		smtp_reply(smtp, 554, 5.6.6, "IMAP URL resolution failed");
		return 0;
	}
	uidstr += STRLEN("UID=");
	if (strlen_zero(uidstr) || msg_to_filename(sentdir, atoi(uidstr), msgfile, sizeof(msgfile))) {
		smtp_reply(smtp, 554, 5.6.6, "IMAP URL resolution failed");
		return 0;
	}
	/* XXX Should probably verify uidvalidity has not changed as well (more important if we were using IMAP's URLFETCH) */

	/* Need to find this as do_deliver expects this was sent while receiving data */
	fp = fopen(msgfile, "r");
	if (!fp) {
		bbs_error("Failed to open file %s: %s\n", msgfile, strerror(errno));
		smtp_reply(smtp, 451, 4.4.1, "IMAP server unavailable");
		return 0;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		if (STARTS_WITH(buf, "From:")) {
			char *from;
			bbs_strterm(buf, '\r');
			from = buf + STRLEN("From:");
			ltrim(from);
			smtp->fromheaderaddress = strdup(from);
			break;
		} else if (!strcmp(buf, "\r\n")) {
			bbs_warning("BURL submission is missing From header\n"); /* Transmission will probably be rejected, but not our concern here. */
			break; /* End of headers. Definitely break. */
		}
	}
	fseek(fp, 0L, SEEK_END); /* We could also get the length from the filename (S=), but we've already got it open, so whatever */
	msglen = ftell(fp);
	fclose(fp);

	do_deliver(smtp, msgfile, (size_t) msglen); /* do_deliver will send the reply code */
	return 0;
}

static int smtp_process(struct smtp_session *smtp, char *s, size_t len)
{
	char *command;

	if (smtp->tflags.inauth) {
		return handle_auth(smtp, s);
	} else if (smtp->tflags.indata) {
		int res;

		if (!strcmp(s, ".")) { /* Entire message has now been received */
			smtp->tflags.indata = 0;
			if (smtp->tflags.datafail) {
				smtp->tflags.datafail = 0;
				if (smtp->tflags.datalen >= max_message_size) {
					/* Message too large. */
					smtp_reply(smtp, 552, 5.2.3, "Your message exceeded our message size limits");
				} else {
					/* Message not successfully received in totality, so reject it. */
					smtp_reply(smtp, 451, 4.3.0, "Message not received successfully, try again");
				}
				return 0;
			} else if (smtp->tflags.hopcount >= MAX_HOPS) {
				smtp_reply(smtp, 554, 5.6.0, "Message exceeded %d hops, this may indicate a mail loop", MAX_HOPS);
				return 0;
			}
			fclose(smtp->fp); /* Have to close and reopen in read mode anyways */
			smtp->fp = NULL;
			bbs_debug(5, "Handling receipt of %lu-byte message\n", smtp->tflags.datalen);
			res = do_deliver(smtp, smtp->template, smtp->tflags.datalen);
			bbs_delete_file(smtp->template);
			smtp->tflags.datalen = 0;
			return res;
		}

		if (smtp->tflags.datafail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		if (smtp->tflags.indataheaders) {
			if ((smtp->fromlocal || smtp->msa) && STARTS_WITH(s, "From:")) {
				const char *newfromhdraddr = S_IF(s + 5);
				REPLACE(smtp->fromheaderaddress, newfromhdraddr);
			} else if (STARTS_WITH(s, "Received:")) {
				smtp->tflags.hopcount++;
			} else if (!smtp->contenttype && STARTS_WITH(s, "Content-Type:")) {
				const char *tmp = s + STRLEN("Content-Type:");
				if (!strlen_zero(tmp)) {
					ltrim(tmp);
				}
				if (!strlen_zero(tmp)) {
					REPLACE(smtp->contenttype, tmp);
				}
			} else if (!smtp->tflags.dkimsig && STARTS_WITH(s, "DKIM-Signature")) {
				smtp->tflags.dkimsig = 1;
			} else if (!len) {
				smtp->tflags.indataheaders = 0; /* CR LF on its own indicates end of headers */
			}
		}

		if (smtp->tflags.datalen + len >= max_message_size) {
			smtp->tflags.datafail = 1;
			smtp->tflags.datalen = max_message_size; /* This isn't really true, this is so we can detect that the message was too large. */
		}

		res = bbs_append_stuffed_line_message(smtp->fp, s, len); /* Should return len + 2, unless it was byte stuffed, in which case it'll be len + 1 */
		if (res < 0) {
			smtp->tflags.datafail = 1;
		}
		smtp->tflags.datalen += (long unsigned) res;
		return 0;
	}

	command = strsep(&s, " ");
	REQUIRE_ARGS(command);

	/* Slow down spam using tarpit like techniques */
	if (smtp->failures) {
		bbs_debug(4, "%p: Current number of SMTP failures: %d\n", smtp, smtp->failures);
		if (smtp->failures > 4) { /* Do not do this with <= 3 or we'll slow down the test suite (and get test failures) */
			/* Exponential delay as # of failures increases: */
			if (bbs_node_safe_sleep(smtp->node, 1000 * (1 << smtp->failures))) {
				return -1;
			}
		}
	}

	if (!strcasecmp(command, "RSET")) {
		if (smtp->failures > 50) { /* Don't let SMTP clients keep trying forever */
			bbs_debug(3, "Forcibly disconnecting client for too many resets\n");
			return -1;
		}
		smtp_reset(smtp);
		smtp_reply(smtp, 250, 2.1.5, "Flushed");
	} else if (!strcasecmp(command, "NOOP")) {
		smtp_reply(smtp, 250, 2.0.0, "OK");
	} else if (!strcasecmp(command, "QUIT")) {
		smtp_reply(smtp, 221, 2.0.0, "Closing connection");
		return -1; /* Will destroy SMTP session after returning */
	} else if (!strcasecmp(command, "HELO")) {
		return handle_helo(smtp, s, 0);
	} else if (!strcasecmp(command, "EHLO")) {
		return handle_helo(smtp, s, 1);
	} else if (!strcasecmp(command, "STARTTLS")) {
		if (!smtp->secure) {
			smtp_reply_nostatus(smtp, 220, "Ready to start TLS");
			smtp->tflags.dostarttls = 1;
			smtp->gothelo = 0; /* Client will need to start over. */
		} else {
			smtp_reply(smtp, 454, 5.5.1, "STARTTLS may not be repeated");
		}
	} else if (smtp->msa && !smtp->secure && require_starttls) {
		smtp_reply(smtp, 504, 5.5.4, "Must issue a STARTTLS command first");
	} else if (!strcasecmp(command, "AUTH")) {
		/* https://www.samlogic.net/articles/smtp-commands-reference-auth.htm */
		if (smtp->tflags.inauth) { /* Already in authorization */
			smtp_reply(smtp, 503, 5.5.1, "Bad sequence of commands.");
		} else if (bbs_user_is_registered(smtp->node->user)) { /* Already authed */
			smtp_reply(smtp, 503, 5.7.0, "Already authenticated, no identity changes permitted");
		} else if (!smtp->secure && require_starttls) {
			/* Must not offer PLAIN or LOGIN on insecure connections. */
			smtp_reply(smtp, 504, 5.5.4, "Must issue a STARTTLS command first");
		} else {
			command = strsep(&s, " ");
			if (!strcasecmp(command, "PLAIN")) {
				/* https://datatracker.ietf.org/doc/html/rfc4616 */
				/* Client could send the encoded string now or separately. */
				smtp->tflags.inauth = 1;
				if (strlen_zero(s)) {
					smtp_reply(smtp, 334, "", ""); /* Just a 334, nothing else */
				} else {
					return handle_auth(smtp, s);
				}
			} else if (!strcasecmp(command, "LOGIN")) {
				/* https://www.ietf.org/archive/id/draft-murchison-sasl-login-00.txt */
				smtp->tflags.inauth = 2;
				/* Prompt for username (base64 encoded) */
				_smtp_reply(smtp, "334 VXNlcm5hbWU6\r\n"); /* Microsoft Outlook doesn't like quotes around the encoded string. XXX Why are there quotes anyways? */
			} else {
				smtp_reply(smtp, 504, 5.7.4, "Unrecognized Authentication Type");
			}
		}
	} else if (!strcasecmp(command, "MAIL")) {
		char *tmp, *from;
		REQUIRE_HELO();
		REQUIRE_ARGS(s);
		if (strncasecmp(s, "FROM:", 5)) {
			smtp_reply(smtp, 501, 5.5.4, "Unrecognized parameter");
			return 0;
		}
		s += 5;

		/* If the connection was to the MSA port, then we only accept outgoing mail from our users, not incoming mail. */
		if (smtp->msa && !bbs_user_is_registered(smtp->node->user)) {
			smtp_reply(smtp, 530, 5.7.0, "Authentication required");
			return 0;
		}

		smtp->fromlocal = smtp->msa; /* XXX This is kind of a redundant variable, although usage is slightly different */

		REQUIRE_ARGS(s);
		ltrim(s);
		REQUIRE_ARGS(s);
		from = strsep(&s, " ");
		if (!strlen_zero(s)) {
			char *sizestring;
			/* Part of the SIZE extension. For ESMTP, something like SIZE=XXX */
			sizestring = strchr(s, '=');
			if (sizestring) {
				sizestring++;
				if (!strlen_zero(sizestring)) {
					long freebytes;
					unsigned int sizebytes = (unsigned int) atoi(sizestring);
					if (sizebytes >= max_message_size) {
						smtp_reply(smtp, 552, 5.3.4, "Message too large");
						return 0;
					}
					smtp->tflags.sizepreview = sizebytes;
					freebytes = bbs_disk_bytes_free();
					if ((long) smtp->tflags.sizepreview > freebytes) {
						bbs_warning("Disk full? Need %lu bytes to receive message, but only %ld available\n", smtp->tflags.sizepreview, freebytes);
						smtp_reply(smtp, 452, 4.3.1, "Insufficient system storage");
						return 0;
					}
				} else {
					bbs_warning("Malformed MAIL directive: %s\n", s);
				}
			}
		}
		bbs_debug(3, "%s/%s\n", from, s);
		if (*from != '<') {
			smtp_reply(smtp, 501, 5.1.7, "Syntax error in MAIL command"); /* Email address must be enclosed in <> */
			return 0;
		}
		if (!*(from + 1)) {
			smtp_reply(smtp, 501, 5.1.7, "Syntax error in MAIL command"); /* Email address must be enclosed in <> */
			return 0;
		}
		if (*from != '<' || !*(from + 1) || !(tmp = strchr(from, '>'))) {
			smtp_reply(smtp, 501, 5.1.7, "Syntax error in MAIL command"); /* Email address must be enclosed in <> */
			return 0;
		}
		*tmp = '\0'; /* Stop at < */
		from++; /* Skip < */
		/* Can use MAIL FROM more than once (to replace previous one) */
		if (strlen_zero(from)) {
			/* Empty MAIL FROM. This means postmaster, i.e. an email that should not be auto-replied to.
			 * This does bypass some checks below, but we shouldn't reject such mail. */
			bbs_debug(5, "MAIL FROM is empty\n");
			smtp->fromlocal = 0;
			REPLACE(smtp->from, "");
			smtp_reply(smtp, 250, 2.0.0, "OK");
			return 0;
		}
		tmp = strchr(from, '@');
		REQUIRE_ARGS(tmp); /* Must be user@domain */
		tmp++; /* Skip @ */
		/* Don't require authentication simply because the sending domain is local.
		 * There may be other servers that are authorized to send mail from such domains.
		 * If it's not legitimate, the SPF checks should reveal that. */
		if (strlen_zero(smtp->helohost) || (requirefromhelomatch && !smtp_domain_matches(smtp->helohost, tmp))) {
			smtp_reply(smtp, 530, 5.7.0, "HELO/EHLO domain does not match MAIL FROM domain");
			return 0;
		}
		if (stringlist_contains(&blacklist, tmp)) { /* Entire domain is blacklisted */
			smtp_reply(smtp, 554, 5.7.1, "This domain is blacklisted");
			return 0;
		} else if (stringlist_contains(&blacklist, from)) { /* This user is blacklisted */
			smtp_reply(smtp, 554, 5.7.1, "This email address is blacklisted");
			return 0;
		}
		REPLACE(smtp->from, from);
		smtp_reply(smtp, 250, 2.1.0, "OK");
	} else if (!strcasecmp(command, "RCPT")) {
		REQUIRE_HELO();
		REQUIRE_MAIL_FROM();
		REQUIRE_ARGS(s);
		if (strncasecmp(s, "TO:", 3)) {
			smtp_reply(smtp, 501, 5.5.4, "Unrecognized parameter");
			return 0;
		}
		s += 3;
		REQUIRE_ARGS(s);
		ltrim(s);
		return handle_rcpt(smtp, s);
	} else if (!strcasecmp(command, "DATA")) {
		REQUIRE_HELO();
		REQUIRE_MAIL_FROM();
		REQUIRE_RCPT();
		smtp_reset_data(smtp);
		strcpy(smtp->template, "/tmp/smtpXXXXXX");
		smtp->fp = bbs_mkftemp(smtp->template, 0600);
		if (!smtp->fp) {
			smtp_reply_nostatus(smtp, 452, "Server error, unable to allocate buffer");
		} else {
			/* Begin reading data. */
			smtp->tflags.indata = 1;
			smtp->tflags.indataheaders = 1;
			smtp_reply_nostatus(smtp, 354, "Start mail input; end with a period on a line by itself");
		}
	} else if (!strcasecmp(command, "BURL")) {
		return handle_burl(smtp, s);
	} else { /* GENURLAUTH */
		/* Deliberately not supported: VRFY, EXPN */
		smtp_reply(smtp, 502, 5.5.1, "Unrecognized command");
	}

	return 0;
}

static void handle_client(struct smtp_session *smtp, SSL **sslptr)
{
	char buf[1001]; /* Maximum length, including CR LF, is 1000 */
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));

	smtp_reply_nostatus(smtp, 220, "%s ESMTP Service Ready", bbs_hostname());

	for (;;) {
		int res = bbs_readline(smtp->rfd, &rldata, "\r\n", 60000); /* Wait 60 seconds, that ought to be plenty even for manual testing... real SMTP clients won't need more than a couple seconds. */
		if (res < 0) {
			res += 1; /* Convert the res back to a normal one. */
			if (res == 0) {
				/* Timeout occured. */
				/* XXX This also happens if a noncompliant SMTP client sends us more than 1,000 bytes in a single line
				 * and exhausts our buffer. In this case, bbs_readline returns -1.
				 * We should probably send a more appropriate error in this event. */
				smtp_reply(smtp, 451, 4.4.2, "Timeout - closing connection"); /* XXX Should do only if poll returns 0, not if read returns 0 */
			}
			break;
		}
		if (smtp->tflags.indata) {
			bbs_debug(8, "%p => [%d data bytes]\n", smtp, res); /* This could be a lot of output, don't show it all. */
		} else {
			if (STARTS_WITH(buf, "AUTH PLAIN ")) {
				bbs_debug(6, "%p => AUTH PLAIN ******\n", smtp);
			} else {
				bbs_debug(6, "%p => %s\n", smtp, buf);
			}
		}
		if (smtp_process(smtp, buf, (size_t) res)) {
			break;
		}
		if (smtp->tflags.dostarttls) {
			/* RFC3207 STARTTLS */
			/* You might think this would be more complicated, but nope, this is literally all there is to it. */
			bbs_debug(3, "Starting TLS\n");
			smtp->tflags.dostarttls = 0;
			*sslptr = ssl_new_accept(smtp->node->fd, &smtp->rfd, &smtp->wfd);
			if (!*sslptr) {
				bbs_error("Failed to create SSL\n");
				break; /* Just abort */
			}
			smtp->secure = 1;
			/* Prevent STARTTLS command injection by resetting the buffer after TLS upgrade:
			 * http://www.postfix.org/CVE-2011-0411.html
			 * https://blog.apnic.net/2021/11/18/vulnerabilities-show-why-starttls-should-be-avoided-if-possible/ */
			bbs_readline_flush(&rldata);
		}
	}
}

/*! \brief Thread to handle a single SMTP/SMTPS client */
static void smtp_handler(struct bbs_node *node, int msa, int secure)
{
#ifdef HAVE_OPENSSL
	SSL *ssl = NULL;
#endif
	int rfd, wfd;
	struct smtp_session smtp;

	/* Start TLS if we need to */
	if (secure) {
		ssl = ssl_new_accept(node->fd, &rfd, &wfd);
		if (!ssl) {
			bbs_error("Failed to create SSL\n");
			return;
		}
	} else {
		rfd = wfd = node->fd;
	}

	memset(&smtp, 0, sizeof(smtp));
	smtp.rfd = rfd;
	smtp.wfd = wfd;
	smtp.node = node;
	SET_BITFIELD(smtp.secure, secure);
	SET_BITFIELD(smtp.msa, msa);

	handle_client(&smtp, &ssl);
	mailbox_dispatch_event_basic(EVENT_LOGOUT, node, NULL, NULL);

#ifdef HAVE_OPENSSL
	/* Note that due to STARTTLS, smtp.secure might not always equal secure at this point (session could start off insecure and end up secure) */
	if (smtp.secure) { /* implies ssl */
		ssl_close(ssl);
		ssl = NULL;
	}
#endif
	smtp_destroy(&smtp);
}

static void *__smtp_handler(void *varg)
{
	struct bbs_node *node = varg;
	int secure = !strcmp(node->protname, "SMTPS") ? 1 : 0;

	node->thread = pthread_self();
	bbs_node_begin(node);

	/* If it's secure, it's for message submission agent, MTAs are never secure by default. */
	smtp_handler(node, secure || !strcmp(node->protname, "SMTP (MSA)"), secure); /* Actually handle the SMTP/SMTPS/message submission agent client */

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("net_smtp.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "relayin", &accept_relay_in);
	bbs_config_val_set_uint(cfg, "general", "maxsize", &max_message_size);
	bbs_config_val_set_true(cfg, "general", "requirefromhelomatch", &requirefromhelomatch);
	bbs_config_val_set_true(cfg, "general", "validatespf", &validatespf);
	bbs_config_val_set_true(cfg, "general", "addreceivedmsa", &add_received_msa);
	bbs_config_val_set_true(cfg, "general", "archivelists", &archivelists);

	/* SMTP */
	bbs_config_val_set_true(cfg, "smtp", "enabled", &smtp_enabled);
	bbs_config_val_set_port(cfg, "smtp", "port", &smtp_port);

	/* SMTPS */
	bbs_config_val_set_true(cfg, "smtps", "enabled", &smtps_enabled);
	bbs_config_val_set_port(cfg, "smtps", "port", &smtps_port);

	/* MSA */
	bbs_config_val_set_true(cfg, "msa", "enabled", &msa_enabled);
	bbs_config_val_set_port(cfg, "msa", "port", &msa_port);
	bbs_config_val_set_true(cfg, "msa", "requirestarttls", &require_starttls);

	/* Blacklist */
	while ((section = bbs_config_walk(cfg, section))) {
		struct bbs_keyval *keyval = NULL;
		if (strcmp(bbs_config_section_name(section), "blacklist")) {
			continue; /* Not the blacklist section */
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval);
			if (!stringlist_contains(&blacklist, key)) {
				stringlist_push(&blacklist, key);
			}
		}
	}

	return 0;
}

static int load_module(void)
{
	memset(&blacklist, 0, sizeof(blacklist));

	if (load_config()) {
		return -1;
	}
	if (!smtp_enabled && !smtps_enabled && !msa_enabled) {
		bbs_debug(3, "Neither SMTP nor SMTPS nor MSA is enabled, declining to load\n");
		goto cleanup; /* Nothing is enabled */
	}
	if (smtps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, SMTPS may not be used\n");
		goto cleanup;
	}

	if (strlen_zero(bbs_hostname())) {
		bbs_error("A BBS hostname in nodes.conf is required for mail services\n");
		goto cleanup;
	}

	/* If we can't start the TCP listeners, decline to load */
	if (bbs_start_tcp_listener3(smtp_enabled ? smtp_port : 0, smtps_enabled ? smtps_port : 0, msa_enabled ? msa_port : 0, "SMTP", "SMTPS", "SMTP (MSA)", __smtp_handler)) {
		goto cleanup;
	}

	bbs_register_tests(tests);
	bbs_register_mailer(injectmail, 1);
	return 0;

cleanup:
	stringlist_empty(&blacklist);
	return -1;
}

static int unload_module(void)
{
	bbs_unregister_mailer(injectmail);
	bbs_unregister_tests(tests);
	if (smtp_enabled) {
		bbs_stop_tcp_listener(smtp_port);
	}
	if (smtps_enabled) {
		bbs_stop_tcp_listener(smtps_port);
	}
	if (msa_enabled) {
		bbs_stop_tcp_listener(msa_port);
	}
	stringlist_empty(&blacklist);
	return 0;
}

BBS_MODULE_INFO_FLAGS_DEPENDENT("RFC5321 SMTP Message Transfer/Submission", MODFLAG_GLOBAL_SYMBOLS, "mod_mail.so");
