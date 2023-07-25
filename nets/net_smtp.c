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
 * \note Supports RFC3207 STARTTLS
 * \note Supports RFC4954 AUTH
 * \note Supports RFC1893 Enhanced Status Codes
 * \note Supports RFC1870 Size Declarations
 * \note Supports RFC6409 Message Submission
 * \note Supports RFC4468 BURL
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

#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/utils.h"
#include "include/os.h"
#include "include/base64.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/stringlist.h"
#include "include/test.h"
#include "include/mail.h"
#include "include/oauth.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"

/* SMTP relay port (mail transfer agents) */
#define DEFAULT_SMTP_PORT 25

/* Mainly for encrypted SMTP message submission agents, though not explicitly in the RFC */
#define DEFAULT_SMTPS_PORT 465

/* Mainly for message submission agents, not encrypted by default, but may use STARTTLS */
#define DEFAULT_SMTP_MSA_PORT 587

#define MAX_RECIPIENTS 100
#define MAX_LOCAL_RECIPIENTS 100
#define MAX_EXTERNAL_RECIPIENTS 10

#define MAX_HOPS 50

static int smtp_port = DEFAULT_SMTP_PORT;
static int smtps_port = DEFAULT_SMTPS_PORT;
static int msa_port = DEFAULT_SMTP_MSA_PORT;

static pthread_t queue_thread = 0;

static int smtp_enabled = 1, smtps_enabled = 1, msa_enabled = 1;

static pthread_mutex_t queue_lock;

static int accept_relay_in = 1;
static int accept_relay_out = 1;
static int minpriv_relay_in = 0;
static int minpriv_relay_out = 0;
static int queue_outgoing = 1;
static int send_async = 1;
static int always_queue = 0;
static int notify_queue = 0;
static int require_starttls = 1;
static int require_starttls_out = 0;
static int requirefromhelomatch = 0;
static int validatespf = 1;
static int add_received_msa = 0;
static int archivelists = 1;
static int notify_external_firstmsg = 1;

/*! \brief Max message size, in bytes */
static unsigned int max_message_size = 300000;

static unsigned int queue_interval = 900;
static unsigned int max_retries = 10;
static unsigned int max_age = 86400;

static char queue_dir[256];

/* Allow this module to use dprintf */
#undef dprintf

#define _smtp_reply(smtp, fmt, ...) bbs_debug(6, "%p <= " fmt, smtp, ## __VA_ARGS__); dprintf(smtp->wfd, fmt, ## __VA_ARGS__);

/*! \brief Final SMTP response with this code */
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
	char *from;
	struct stringlist recipients;
	struct stringlist sentrecipients;
	int numrecipients;
	int numlocalrecipients;
	int numexternalrecipients;
	char template[64];
	FILE *fp;
	unsigned long datalen;
	unsigned long sizepreview;	/* Size as advertised in the MAIL FROM */
	unsigned int maxsize;	/* Max message size permitted (used for mailing lists) */
	int hopcount;			/* Number of hops so far according to count of Received headers in message. */
	char *helohost;			/* Hostname for HELO/EHLO */
	char *contenttype;		/* Primary Content-Type of message */
	/* AUTH: Temporary */
	char *authuser;			/* Authentication username */
	char *fromheaderaddress;	/* Address in the From: header */
	char *listname;				/* Name of mailing list */
	time_t received;			/* Time that message was received */
	unsigned int failures;		/* Number of protocol violations or failures */
	unsigned int msa:1;		/* Whether connection was to the Message Submission Agent port (as opposed to the Mail Transfer Agent port) */
	unsigned int secure:1;	/* Whether session is secure (TLS, STARTTLS) */
	unsigned int dostarttls:1;	/* Whether we are initiating STARTTLS */
	unsigned int gothelo:1;	/* Got a HELO/EHLO */
	unsigned int ehlo:1;	/* Client supports ESMTP (EHLO) */
	unsigned int fromlocal:1;	/* Sender is local */
	unsigned int indata:1;	/* Whether client is currently sending email body (DATA) */
	unsigned int indataheaders:1;	/* Whether client is currently sending headers for the message */
	unsigned int datafail:1;	/* Data failure */
	unsigned int inauth:2;	/* Whether currently doing AUTH (1 = need PLAIN, 2 = need LOGIN user, 3 = need LOGIN pass) */
	unsigned int sentself:1;
	unsigned int ptonly:1;	/* Message must be plain text for acceptance (used for mailing lists) */
};

static void smtp_reset_data(struct smtp_session *smtp)
{
	if (smtp->fp) {
		fclose(smtp->fp);
		smtp->fp = NULL;
		if (unlink(smtp->template)) {
			bbs_error("Failed to delete %s: %s\n", smtp->template, strerror(errno));
		}
	}
}

static void smtp_reset(struct smtp_session *smtp)
{
	smtp_reset_data(smtp);
	/* XXX In reality, we want to zero most (but not all) of the struct.
	 * Consider moving the flags and session specific stuff to a separate struct,
	 * so we can more easily wipe that just using a single memset call */
	smtp->ptonly = 0;
	smtp->maxsize = 0;
	smtp->indata = 0;
	smtp->indataheaders = 0;
	smtp->inauth = 0;
	smtp->hopcount = 0;
	free_if(smtp->authuser);
	free_if(smtp->fromheaderaddress);
	free_if(smtp->from);
	free_if(smtp->contenttype);
	smtp->datalen = 0;
	smtp->datafail = 0;
	smtp->numrecipients = 0;
	smtp->numlocalrecipients = 0;
	smtp->numexternalrecipients = 0;
	stringlist_empty(&smtp->recipients);
	stringlist_empty(&smtp->sentrecipients);
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
	if (!smtp->numrecipients) { \
		smtp_reply(smtp, 503, 5.5.1, "RCPT first."); \
		smtp->failures++; \
		return 0; \
	}

static int handle_helo(struct smtp_session *smtp, char *s, int ehlo)
{
	if (strlen_zero(s)) {
#if 0
		/* Submissions won't contain any data for HELO/EHLO, only relayers will. */
		smtp_reply(smtp, 501, 5.5.4, "Empty HELO/EHLO argument not allowed, closing connection.");
		return -1;
#endif
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
	int inauth = smtp->inauth;

	smtp->inauth = 0;
	REQUIRE_ARGS(s);

	if (!strcmp(s, "*")) {
		/* Client cancelled exchange */
		smtp_reply(smtp, 501, "Authentication cancelled", "");
		return 0;
	}

	if (inauth == 1) {
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
		smtp->inauth = 3; /* Get password */
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

static int add_recipient(struct smtp_session *smtp, int local, const char *s, int assumelocal)
{
	char buf[256];
	const char *recipient = s;

	/* Assume local user if no domain present */
	if (assumelocal && !strchr(recipient, '@')) {
		snprintf(buf, sizeof(buf), "%s@%s", recipient, bbs_hostname());
		recipient = buf;
	}

	if (stringlist_contains(&smtp->recipients, recipient)) {
		/* Recipient was already added. */
		return 1;
	}
	stringlist_push(&smtp->recipients, recipient);
	smtp->numrecipients += 1;
	if (local) {
		smtp->numlocalrecipients += 1;
	} else {
		smtp->numexternalrecipients += 1;
	}
	return 0;
}

struct mailing_list {
	char *recipients;
	char *senders;
	/* Attributes */
	unsigned int maxsize;	/* Maximum permitted posting size */
	unsigned int ptonly:1;	/* Plain text only? */
};

static void parse_mailing_list(struct mailing_list *l, char *s)
{
	char *attributes;

	memset(l, 0, sizeof(struct mailing_list));

	l->recipients = strsep(&s, "|");
	l->senders = strsep(&s, "|");
	attributes = strsep(&s, "|");
	if (!strlen_zero(attributes)) {
		char *attr;
		while ((attr = strsep(&attributes, ","))) {
			char *name, *value = attr;
			name = strsep(&value, "=");
			if (strlen_zero(name)) {
				continue;
			} else if (!strcasecmp(name, "maxsize")) {
				l->maxsize = (unsigned int) atoi(S_IF(value));
			} else if (!strcasecmp(name, "ptonly")) {
				l->ptonly = 1;
			} else {
				bbs_warning("Unknown mailing list attribute: %s\n", name);
			}
		}
	}
}

static int handle_rcpt(struct smtp_session *smtp, char *s)
{
	int local, res;
	char *user, *domain;
	char *address;

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
	if (local) {
		struct mailbox *mbox;
		const char *recipients;

		/* Check if it's a mailing list. */
		recipients = mailbox_expand_list(user, domain);
		if (recipients) { /* It's a mailing list */
			int added = 0;
			struct mailing_list list;
			char *senders, *recip, *recips, *dup = strdup(recipients);

			if (ALLOC_FAILURE(dup)) {
				smtp_reply(smtp, 451, "Local error in processing", "");
				return 0;
			}
			bbs_debug(8, "List %s: %s\n", user, dup);
			parse_mailing_list(&list, dup);
			recips = list.recipients;
			senders = list.senders;
			if (senders) {
				int authorized = 0;
				char *sender;
				bbs_debug(6, "List %s (recipients: %s) (senders: %s), maxsize=%u, ptonly=%d\n", user, recips, senders, list.maxsize, list.ptonly);
				/* Check if sender is authorized to send to this list. */
				/* Could be multiple authorizations, so check against all of them. */
				while ((sender = strsep(&senders, ","))) {
					if (!strcmp(sender, "*") && smtp->fromlocal) { /* Any local user? */
						authorized = 1;
						bbs_debug(6, "Message authorized via local user membership\n");
						break;
					} else if (smtp->fromlocal && !strcasecmp(bbs_username(smtp->node->user), sender)) { /* Local user match? */
						authorized = 1;
						bbs_debug(6, "Message authorized via explicit local mapping\n");
						break;
					} else if (!strcasecmp(smtp->from, sender)) { /* Any arbitrary match? (including external senders) */
						authorized = 1;
						bbs_debug(6, "Message authorized via explicit generic mapping\n");
						break;
					}
				}
				if (!authorized) {
					bbs_warning("Unauthorized attempt to post to list %s by %s (%s) (fromlocal: %d)\n",
						user, smtp->from, smtp->fromlocal ? bbs_username(smtp->node->user) : "", smtp->fromlocal);
					smtp_reply(smtp, 550, 5.7.1, "You are not authorized to post to this list");
					return 0;
				}
			} else {
				bbs_debug(6, "List %s (recipients: %s)\n", user, recips);
			}
			/* Save attributes for later, since we don't have the body yet and can't do these checks now. */
			smtp->maxsize = list.maxsize;
			if (smtp->sizepreview && smtp->maxsize && smtp->sizepreview > smtp->maxsize) {
				/* If the client told us in advance how large the message will be,
				 * and we already know it's going to be too large, reject it now. */
				smtp_reply(smtp, 552, 5.3.4, "Message too large");
				return 0;
			}
			smtp->ptonly = list.ptonly;
			/* Send a copy of the message to everyone the list. */
			while ((recip = strsep(&recips, ","))) {
				if (strlen_zero(recip)) {
					continue;
				}
				/* We intentionally don't check if the recipient limit here, since lists may have more than that many recipients. */
				/* also local is true when adding the recipient, even if the recipient is not actually local (doesn't count against external limit) */
				if (!strcmp(recip, "*")) { /* Expands to all local users */
					/* We'll deliver a copy to every user that actually has an active mailbox at the moment.
					 * In other words, if there are 50 users on the BBS, but only 15 have mailbox directories,
					 * we'll only deliver 15, to avoid the hassle of creating mailboxes for users that may
					 * not check them anyways. */
					struct bbs_user **users = bbs_user_list();
					if (users) {
						struct bbs_user *bbsuser;
						int index = 0;
						while ((bbsuser = users[index++])) {
							char maildir[256];
							snprintf(maildir, sizeof(maildir), "%s/%d", mailbox_maildir(NULL), bbsuser->id);
							if (eaccess(maildir, R_OK)) {
								continue; /* User doesn't have a mailbox, skip */
							}
							bbs_debug(5, "Adding recipient %s (user %d)\n", bbs_username(bbsuser), bbsuser->id);
							if (!add_recipient(smtp, local, bbs_username(bbsuser), 1)) {
								added++;
							}
						}
						bbs_user_list_destroy(users);
					} else {
						bbs_error("Failed to fetch user list\n");
					}
					/* Don't break from the loop just yet: list may contain external users too (in other words, may expand to more than just '*') */
				} else {
					bbs_debug(5, "Adding recipient %s\n", recip);
					if (!add_recipient(smtp, local, recip, 1)) {
						added++;
					}
				}
			}
			free(dup);
			if (!added) {
				smtp_reply(smtp, 550, 5.7.1, "This mailing list contained no recipients when expanded");
				return 0;
			}
			bbs_debug(3, "Message expanded to %d recipient%s on mailing list %s\n", added, ESS(added), user);
			smtp_reply(smtp, 250, 2.0.0, "OK");
			REPLACE(smtp->listname, user);
			return 0;
		}

		/* It's not a mailing list, check if it's a real mailbox (or an alias that maps to one) */
		mbox = mailbox_get_by_name(user, domain);
		free(address);
		if (!mbox) {
			smtp_reply(smtp, 550, 5.1.1, "No such user here");
			return 0;
		}
		/* User exists, great! */
		if (!smtp->fromlocal && minpriv_relay_in) {
			int userpriv = bbs_user_priv_from_userid((unsigned int) mailbox_id(mbox));
			if (userpriv < minpriv_relay_in) {
				smtp_reply(smtp, 550, 5.1.1, "User unauthorized to receive external mail");
				return 0;
			}
		}
	} else {
		free(address);
		if (!smtp->fromlocal) { /* External user trying to send us mail that's not for us. */
			smtp_reply(smtp, 550, 5.7.0, "Mail relay denied. Forwarding to remote hosts disabled"); /* We're not an open relay. */
			smtp->failures++;
			return 0;
		}
		/* It's a submission of outgoing mail, do no further validation here. */
	}

	if (smtp->numlocalrecipients >= MAX_LOCAL_RECIPIENTS || smtp->numexternalrecipients >= MAX_EXTERNAL_RECIPIENTS || smtp->numrecipients >= MAX_RECIPIENTS) {
		smtp_reply(smtp, 452, 4.5.3, "Your message has too many recipients");
		return 0;
	}

	/* Actually add the recipient to the recipient list. */
	res = add_recipient(smtp, local, s, 0);
	if (res == 1) {
		smtp_reply(smtp, 250, 2.0.0, "Duplicate recipient ignored"); /* XXX Appropriate response code? */
	} else {
		smtp_reply(smtp, 250, 2.0.0, "OK");
	}
	return 0;
}

struct mx_record {
	int priority;
	RWLIST_ENTRY(mx_record) entry;
	char data[];
};

RWLIST_HEAD(mx_records, mx_record);

/*! \brief Fill the results list with the MX results in order of priority */
static int lookup_mx_all(const char *domain, struct stringlist *results)
{
	char *hostname, *tmp;
	unsigned char answer[PACKETSZ] = "";
	char dispbuf[PACKETSZ] = "";
	int res, i;
	ns_msg msg;
	ns_rr rr;
	struct mx_records mxs; /* No need to bother locking this list, nobody else knows about it */
	int priority;
	struct mx_record *mx;
	int added = 0;

	if (strlen_zero(domain)) {
		bbs_error("Missing domain\n");
		return -1;
	} else if (bbs_hostname_is_ipv4(domain)) { /* IP address? Just send it there */
		stringlist_push_tail(results, domain);
		return 0;
	}

	res = res_query(domain, C_IN, T_MX, answer, sizeof(answer));
	if (res == -1) {
		bbs_error("res_query failed\n");
		return -1;
	}
	res = ns_initparse(answer, res, &msg);
	if (res < 0) {
		bbs_error("Failed to look up MX record: %s\n", strerror(errno));
		return -1;
	}
	res = ns_msg_count(msg, ns_s_an);
	if (res < 1) {
		bbs_error("No MX records available\n");
		return -1;
	}

	memset(&mxs, 0, sizeof(mxs));

	/* Add each record to our sorted list */
	for (i = 0; i < res; i++) {
		ns_parserr(&msg, ns_s_an, i, &rr);
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* ns_sprintrr deprecated */
		ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
#pragma GCC diagnostic pop /* -Wdeprecated-declarations */
		bbs_debug(8, "NS answer: %s\n", dispbuf);
		/* Parse the result */
		/*! \todo BUGBUG This is very rudimentary and needs to be made much more robust.
		 * For example, this doesn't correctly parse results that don't have an MX record.
		 * We also need to pick the mail server with the LOWEST score,
		 * and potentially try multiple if the first one fails.
		 */
		hostname = dispbuf;

		/* Results will be formatted like so:
		 * gmail.com.         1H IN MX        30 alt3.gmail-smtp-in.l.google.com.
		 * gmail.com.         1H IN MX        5 gmail-smtp-in.l.google.com.
		 * gmail.com.         1H IN MX        20 alt2.gmail-smtp-in.l.google.com.
		 * gmail.com.         1H IN MX        40 alt4.gmail-smtp-in.l.google.com.
		 * gmail.com.         1H IN MX        10 alt1.gmail-smtp-in.l.google.com.
		 *
		 * If there is no MX record, we'll get something like:
		 * example.com.               1D IN MX        0 .
		 */

		tmp = strstr(hostname, "MX");
		if (!tmp) {
			bbs_debug(3, "Skipping unexpected MX NS answer: %s\n", dispbuf);
			continue;
		}
		tmp += STRLEN("MX");
		ltrim(tmp);
		hostname = tmp;
		tmp = strsep(&hostname, " ");
		priority = atoi(tmp); /* Note that 0 is a valid (and the highest) priority */
		tmp = strrchr(hostname, '.');
		if (tmp) {
			*tmp = '\0'; /* Strip trailing . */
		}

		if (strlen_zero(hostname)) { /* No MX record */
			continue;
		}

		/* Insert in order of priority */
		mx = calloc(1, sizeof(*mx) + strlen(hostname) + 1);
		if (ALLOC_FAILURE(mx)) {
			continue;
		}
		strcpy(mx->data, hostname); /* Safe */
		mx->priority = priority;
		RWLIST_INSERT_SORTED(&mxs, mx, entry, priority);
		added++;
	}

	if (!added) {
		bbs_error("No MX records available for %s\n", domain);
		return -1;
	}

	/* Now that we have it ordered, we don't actually care about the priorities themselves.
	 * Just return a stringlist to the client, with results ordered by priority. */
	/* XXX Technically, the SMTP spec says we should randomly choose between MX servers
	 * with the same priority.
	 * While we don't do this currently, the DNS response has them in random order to begin with,
	 * so that might add some randomness.
	 */
	while ((mx = RWLIST_REMOVE_HEAD(&mxs, entry))) {
		stringlist_push_tail(results, mx->data);
		bbs_debug(3, "MX result for %s: server %s has priority %d\n", domain, mx->data, mx->priority);
		free(mx);
	}

	return 0;
}

#define SMTP_EXPECT(fd, ms, str) \
	res = bbs_expect_line(fd, ms, rldata, str); \
	if (res) { bbs_warning("Expected '%s', got: %s\n", str, buf); goto cleanup; } else { bbs_debug(9, "Found '%s': %s\n", str, buf); }

#define smtp_client_send(fd, fmt, ...) dprintf(fd, fmt, ## __VA_ARGS__); bbs_debug(3, " => " fmt, ## __VA_ARGS__);

#define SMTP_CAPABILITY_STARTTLS (1 << 0)
#define SMTP_CAPABILITY_PIPELINING (1 << 1)
#define SMTP_CAPABILITY_8BITMIME (1 << 2)
#define SMTP_CAPABILITY_ENHANCEDSTATUSCODES (1 << 3)
#define SMTP_CAPABILITY_AUTH_LOGIN (1 << 4)
#define SMTP_CAPABILITY_AUTH_PLAIN (1 << 5)
#define SMTP_CAPABILITY_AUTH_XOAUTH2 (1 << 6)

static void process_capabilities(int *caps, const char *capname)
{
	if (strlen_zero(capname) || !isupper(*capname)) { /* Capabilities are all uppercase XXX but is that required by the RFC? */
		return;
	}

#define PARSE_CAPABILITY(name, flag) \
	else if (!strcmp(capname, name)) { \
		*caps |= flag; \
	}

	if (0) {
		/* Unused */
	}
	PARSE_CAPABILITY("STARTTLS", SMTP_CAPABILITY_STARTTLS)
	PARSE_CAPABILITY("PIPELINING", SMTP_CAPABILITY_PIPELINING)
	PARSE_CAPABILITY("8BITMIME", SMTP_CAPABILITY_8BITMIME)
	PARSE_CAPABILITY("ENHANCEDSTATUSCODES", SMTP_CAPABILITY_ENHANCEDSTATUSCODES)
#undef PARSE_CAPABILITY
	else if (STARTS_WITH(capname, "AUTH ")) {
		capname += STRLEN("AUTH ");
		if (strstr(capname, "LOGIN")) {
			*caps |= SMTP_CAPABILITY_AUTH_LOGIN;
		}
		if (strstr(capname, "PLAIN")) {
			*caps |= SMTP_CAPABILITY_AUTH_PLAIN;
		}
		if (strstr(capname, "XOAUTH2")) {
			bbs_debug(3, "Supports oauth2\n");
			*caps |= SMTP_CAPABILITY_AUTH_XOAUTH2;
		}
	} else if (STARTS_WITH(capname, "SIZE ")) {
		/*! \todo parse and store the limit, abort early if our message length is greater than this */
	} else if (!strcasecmp(capname, "CHUNKING") || !strcasecmp(capname, "SMTPUTF8") || !strcasecmp(capname, "VRFY") || !strcasecmp(capname, "ETRN") || !strcasecmp(capname, "DSN") || !strcasecmp(capname, "HELP")) {
		/* Don't care about */
	} else {
		bbs_warning("Unknown capability advertised: %s\n", capname);
	}
}

static int smtp_client_handshake(struct readline_data *rldata, int rfd, int wfd, char *buf, const char *hostname, int *capsptr)
{
	int res = 0;

	smtp_client_send(wfd, "EHLO %s\r\n", bbs_hostname());
	res = bbs_expect_line(rfd, 1000, rldata, "250");
	if (res) { /* Fall back to HELO if EHLO not supported */
		if (require_starttls_out) { /* STARTTLS is only supported by EHLO, not HELO */
			bbs_warning("SMTP server %s does not support STARTTLS, but encryption is mandatory. Delivery failed.\n", hostname);
			res = 1;
			goto cleanup;
		}
		bbs_debug(3, "SMTP server %s does not support ESMTP, falling back to regular SMTP\n", hostname);
		smtp_client_send(wfd, "HELO %s\r\n", bbs_hostname());
		SMTP_EXPECT(rfd, 1000, "250");
	} else {
		/* Keep reading the rest of the multiline EHLO */
		while (STARTS_WITH(buf, "250-")) {
			bbs_debug(9, "<= %s\n", buf);
			process_capabilities(capsptr, buf + 4);
			res = bbs_expect_line(rfd, 1000, rldata, "250");
		}
		bbs_debug(9, "<= %s\n", buf);
		process_capabilities(capsptr, buf + 4);
		bbs_debug(6, "Finished processing multiline EHLO\n");
	}

cleanup:
	return res;
}

/*! \todo redo try_send using a bbs_tcp_client instead, just like net_imap uses */

/*!
 * \brief Attempt to send an external message to another mail transfer agent or message submission agent
 * \param smtp SMTP session. Generally, this will be NULL except for relayed messages, which are typically the only time this is needed.
 * \param hostname Hostname of mail server
 * \param port Port of mail server
 * \param secure Whether to use Implicit TLS (typically for MSAs on port 465). If 0, STARTTLS will be attempted (but not required unless require_starttls_out = yes)
 * \param username SMTP MSA username
 * \param password SMTP MSA password
 * \param sender The MAIL FROM for the message
 * \param recipient A single recipient for RCPT TO
 * \param recipients A list of recipients for RCPT TO. Either recipient or recipients must be specified.
 * \param prepend Data to prepend
 * \param prependlen Length of prepend
 * \param datafd A file descriptor containing the message data (used instead of data/datalen)
 * \param offset sendfile offset for message (sent data will begin here)
 * \param writelen Number of bytes to send
 * \param[out] buf Buffer in which to temporarily store SMTP responses
 * \param len Size of buf.
 * \retval -1 on temporary error, 1 on permanent error, 0 on success
 */
static int try_send(struct smtp_session *smtp, const char *hostname, int port, int secure, const char *username, const char *password, const char *sender, const char *recipient, struct stringlist *recipients,
	const char *prepend, size_t prependlen, int datafd, off_t offset, size_t writelen, char *buf, size_t len)
{
	SSL *ssl = NULL;
	int sfd, res, wrote = 0;
	int rfd, wfd;
	struct readline_data rldata_stack;
	struct readline_data *rldata = &rldata_stack;
	off_t send_offset = offset;
	int caps = 0;
	char sendercopy[64];
	char *user, *domain;

	bbs_assert(datafd != -1);
	bbs_assert(writelen > 0);

	/* RFC 5322 3.4.1 allows us to use IP addresses in SMTP as well (domain literal form). They just need to be enclosed in square brackets. */
	safe_strncpy(sendercopy, sender, sizeof(sendercopy));

	/* Properly parse, since if a name is present, in addition to the email address, we must exclude the name in the MAIL FROM */
	if (bbs_parse_email_address(sendercopy, NULL, &user, &domain)) {
		bbs_error("Invalid email address: %s\n", sender);
		return -1;
	}

	/* Connect on port 25, and don't set up TLS initially. */
	sfd = bbs_tcp_connect(hostname, port);
	if (sfd < 0) {
		/* Unfortunately, we can't try an alternate port as there is no provision
		 * for letting other SMTP MTAs know that they should try some port besides 25.
		 * So if your ISP blocks incoming traffic on port 25 or you can't use port 25
		 * for whatever reason, you're kind of out luck: you won't be able to receive
		 * mail from the outside world. */
		bbs_debug(3, "Failed to set up TCP connection to %s\n", hostname);
		return -1;
	}

	wfd = rfd = sfd;
	bbs_debug(3, "Attempting delivery of %lu-byte message from %s -> %s via %s\n", writelen, sender, recipient, hostname);

	if (secure) {
		ssl = ssl_client_new(sfd, &rfd, &wfd, hostname);
		if (!ssl) {
			bbs_debug(3, "Failed to set up TLS\n");
			res = 1;
			goto cleanup; /* Abort if we failed to set up implicit TLS */
		}
	}

	bbs_readline_init(&rldata_stack, buf, len);

	/* The logic for being an SMTP client with an SMTP MTA is pretty straightforward. */
	SMTP_EXPECT(rfd, 1000, "220");

	res = smtp_client_handshake(rldata, rfd, wfd, buf, hostname, &caps);
	if (res) {
		goto cleanup;
	}

	if (caps & SMTP_CAPABILITY_STARTTLS) {
		smtp_client_send(wfd, "STARTTLS\r\n");
		SMTP_EXPECT(rfd, 2500, "220");
		bbs_debug(3, "Starting TLS\n");
		ssl = ssl_client_new(sfd, &rfd, &wfd, hostname);
		if (!ssl) {
			bbs_debug(3, "Failed to set up TLS\n");
			goto cleanup; /* Abort if we were told STARTTLS was available but failed to negotiate. */
		}
		bbs_readline_flush(rldata); /* Prevent STARTTLS response injection by resetting the buffer after TLS upgrade */
		/* Start over again. */
		caps = 0;
		res = smtp_client_handshake(rldata, rfd, wfd, buf, hostname, &caps);
		if (res) {
			goto cleanup;
		}
	} else if (require_starttls_out) {
		bbs_warning("SMTP server %s does not support STARTTLS, but encryption is mandatory. Delivery failed.\n", hostname);
		res = 1;
		goto cleanup;
	} else {
		bbs_warning("SMTP server %s does not support STARTTLS. This message will not be transmitted securely!\n", hostname);
	}

	if (username && password) {
		if (STARTS_WITH(password, "oauth:")) { /* OAuth authentication */
			char token[512];
			char decoded[568];
			int decodedlen, encodedlen;
			char *encoded;
			const char *oauthprofile = password + STRLEN("oauth:");

			if (!(caps & SMTP_CAPABILITY_AUTH_XOAUTH2)) {
				bbs_warning("SMTP server does not support XOAUTH2\n");
				res = -1;
				goto cleanup;
			} else if (!smtp || !smtp->node || !bbs_user_is_registered(smtp->node->user)) {
				bbs_warning("Cannot look up OAuth tokens without an authenticated SMTP session\n");
				res = -1;
				goto cleanup;
			}

			/* Typically, smtp is NULL, except for relayed mail.
			 * This means this functionality here only works for relayed mail (from MailScript RELAY rule).
			 * The reason we need it in this case is to ensure that the oauth: profile specified by the user
			 * is one that the user is actually authorized to use. */
			res = bbs_get_oauth_token(smtp->node->user, oauthprofile, token, sizeof(token));
			if (res) {
				bbs_warning("OAuth token '%s' does not exist for user %d\n", oauthprofile, smtp->node->user->id);
				res = -1;
				goto cleanup;
			}
			/* https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange */
			decodedlen = snprintf(decoded, sizeof(decoded), "user=%s%cauth=Bearer %s%c%c", username, 0x01, token, 0x01, 0x01);
			encoded = base64_encode(decoded, decodedlen, &encodedlen);
			if (!encoded) {
				bbs_error("Base64 encoding failed\n");
				res = -1;
				goto cleanup;
			}
			smtp_client_send(wfd, "AUTH XOAUTH2 %s\r\n", encoded);
			free(encoded);
			res = bbs_expect_line(rfd, 1000, rldata, "235");
			if (res) {
				/* If we get 334 here, that means we failed: https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange
				 * We should send an empty reply to get the error message. */
				if (STARTS_WITH(buf, "334")) {
					smtp_client_send(wfd, "\r\n");
					SMTP_EXPECT(rfd, 1000, "235"); /* We're not actually going to get a 235, but send the error to the console and abort */
					bbs_warning("Huh? It worked?\n"); /* Shouldn't happen */
				} else {
					bbs_warning("Expected '%s', got: %s\n", "235", buf);
					goto cleanup;
				}
			}
		} else if (caps & SMTP_CAPABILITY_AUTH_LOGIN) {
			char *saslstr = bbs_sasl_encode(username, username, password);
			if (!saslstr) {
				res = -1;
				goto cleanup;
			}
			smtp_client_send(wfd, "AUTH PLAIN\r\n"); /* AUTH PLAIN is preferred to the deprecated AUTH LOGIN */
			SMTP_EXPECT(rfd, 1000, "334");
			smtp_client_send(wfd, "%s\r\n", saslstr);
			SMTP_EXPECT(rfd, 1000, "235");
		} else {
			bbs_warning("No mutual login methods available\n");
			res = -1;
			goto cleanup;
		}
	}

	if (bbs_hostname_is_ipv4(domain)) {
		smtp_client_send(wfd, "MAIL FROM:<%s@[%s]>\r\n", user, domain);
	} else {
		smtp_client_send(wfd, "MAIL FROM:<%s@%s>\r\n", user, domain); /* sender lacks <>, but recipient has them */
	}
	SMTP_EXPECT(rfd, 1000, "250");
	if (recipient) {
		if (*recipient == '<') {
			smtp_client_send(wfd, "RCPT TO:%s\r\n", recipient);
		} else {
			bbs_warning("Queue file recipient did not contain <>\n"); /* Support broken queue files, but make some noise */
			smtp_client_send(wfd, "RCPT TO:<%s>\r\n", recipient);
		}
		SMTP_EXPECT(rfd, 1000, "250");
	} else if (recipients) {
		char *r;
		while ((r = stringlist_pop(recipients))) {
			smtp_client_send(wfd, "RCPT TO:%s\r\n", r);
			SMTP_EXPECT(rfd, 1000, "250");
			free(r);
		}
	} else {
		bbs_error("No recipients specified\n");
		goto cleanup;
	}
	smtp_client_send(wfd, "DATA\r\n");
	SMTP_EXPECT(rfd, 1000, "354");
	if (prepend && prependlen) {
		wrote = bbs_write(wfd, prepend, (unsigned int) prependlen);
	}

	/* sendfile will be much more efficient than reading the file ourself, as email body could be quite large, and we don't need to involve userspace. */
	res = (int) sendfile(wfd, datafd, &send_offset, writelen);

	/* XXX If email doesn't end in CR LF, we need to tack that on. But ONLY if it doesn't already end in CR LF. */
	smtp_client_send(wfd, "\r\n.\r\n"); /* (end of) EOM */
	if (res != (int) writelen) { /* Failed to write full message */
		bbs_error("Wanted to write %lu bytes but wrote only %d?\n", writelen, res);
		res = -1;
		goto cleanup;
	}
	wrote += res;
	bbs_debug(5, "Sent %d bytes\n", wrote);
	SMTP_EXPECT(rfd, 5000, "250"); /* Okay, this email is somebody else's problem now. */

	bbs_debug(3, "Message successfully delivered to %s\n", recipient);
	res = 0;

cleanup:
	if (res > 0) {
		smtp_client_send(wfd, "QUIT\r\n");
	}
	if (ssl) {
		ssl_close(ssl);
	}
	close(sfd);

	/* Check if it's a permanent error, if it's not, return -1 instead of 1 */
	if (res > 0) {
		res = -1; /* Assume temporary unless we're sure it's not. */
		if (STARTS_WITH(buf, "5")) {
			bbs_debug(5, "Encountered permanent failure (%s)\n", buf);
			res = 1; /* Permanent error. */
		}
	}
	return res;
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
	struct smtp_filter *f = calloc(1, sizeof(*f));
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

int smtp_should_preserve_privacy(struct smtp_session *smtp)
{
	return smtp->fromlocal && !add_received_msa;
}

int smtp_is_bulk_mailing(struct smtp_session *smtp)
{
	return smtp->listname ? 1 : 0;
}

time_t smtp_received_time(struct smtp_session *smtp)
{
	return smtp->received;
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

/*! \note This is currently only executed once the entire message has been received.
 * If milter support is added, we'll need hooks at each stage of the delivery process (MAIL FROM, RCPT TO, etc.) */
static void smtp_run_filters(struct smtp_filter_data *fdata, enum smtp_direction dir)
{
	struct smtp_filter *f;

	if (!fdata->smtp) {
		bbs_error("Cannot run filters without an SMTP session\n");
		return;
	}

	fdata->dir = dir;
	fdata->from = fdata->smtp->from;
	fdata->node = fdata->smtp->node;

	RWLIST_RDLOCK(&filters);
	RWLIST_TRAVERSE(&filters, f, entry) {
		if (f->direction & fdata->dir) {
			int res = 0;
			/* Filter applicable to this direction */
			if (f->scope == SMTP_SCOPE_INDIVIDUAL) {
				if (!fdata->recipient) {
					continue;
				}
			} else {
				if (fdata->recipient) {
					continue;
				}
			}
			/* Filter applicable to scope */
			bbs_debug(5, "Executing %s SMTP filter %s %p...\n", dir == SMTP_DIRECTION_IN ? "incoming" : "outgoing", smtp_filter_type_name(f->type), f);
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
				break;
			} else if (res < 0) {
				bbs_warning("%s SMTP filter %s %p failed to execute\n", dir == SMTP_DIRECTION_IN ? "Incoming" : "Outgoing", smtp_filter_type_name(f->type), f);
			}
		}
	}
	RWLIST_UNLOCK(&filters);
}

static void notify_firstmsg(struct mailbox *mbox)
{
	char newdir[256];

	snprintf(newdir, sizeof(newdir), "%s/new", mailbox_maildir(mbox));
	if (eaccess(newdir, R_OK)) {
		struct bbs_user *user;
		const char *email;
		char popstr[32] = "", imapstr[32] = "";
		int port_imap, port_pop3;
		/* Doesn't exist yet. So this is the first message for the user. */
		/* Send a message to the user's off-net address. */
		user = bbs_user_from_userid((unsigned int) mailbox_id(mbox));
		if (!user) {
			bbs_error("Couldn't find any user for mailbox %d?\n", mailbox_id(mbox));
			return;
		}
		email = bbs_user_email(user);
		if (strlen_zero(email)) {
			goto cleanup; /* No email? Forget about it */
		}
		port_imap = bbs_protocol_port("IMAPS");
		port_pop3 = bbs_protocol_port("POP3S");
		if (port_imap) {
			snprintf(imapstr, sizeof(imapstr), "IMAP: %d (TLS)\r\n", port_imap);
		} else {
			port_imap = bbs_protocol_port("IMAP");
			if (port_imap) {
				snprintf(imapstr, sizeof(imapstr), "IMAP: %d (plaintext)\r\n", port_imap);
			}
		}
		if (port_pop3) {
			snprintf(popstr, sizeof(popstr), "POP3: %d (TLS)\r\n", port_pop3);
		} else {
			port_pop3 = bbs_protocol_port("POP3");
			if (port_pop3) {
				snprintf(popstr, sizeof(popstr), "POP3: %d (plaintext)\r\n", port_pop3);
			}
		}
		if (!port_pop3 && !port_imap) {
			bbs_warning("No message retrieval protocols are currently enabled, user cannot retrieve mail\n");
			return;
		}
		bbs_debug(3, "Notifying %s via %s since this is the first message delivered to this user\n", bbs_username(user), email);
		bbs_mail_fmt(1, email, NULL, NULL, "You Have Mail",
			"Hello, %s\r\n\tYou just received your first email in your BBS email account.\r\n"
			"To check your messages, you can connect your mail client client to %s.\r\n"
			"== Connection Details: ==\r\n"
			"%s"
			"%s"
			,bbs_username(user), bbs_hostname(), imapstr, popstr);
cleanup:
		bbs_user_destroy(user);
	}
}

static inline void smtp_mproc_init(struct smtp_session *smtp, struct smtp_msg_process *mproc)
{
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

/*! \note This is in mod_mail instead of net_smtp since the BBS doesn't currently support
 * modules that both have dependencies and are dependencies of other modules,
 * since the module autoloader only does a single pass to load modules that export global symbols.
 * e.g. mod_mailscript depending on net_smtp, which depends on mod_mail.
 * So we make both mod_mailscript and net_smtp depend on mod_mail directly.
 * If this is resolved in the future, it may make sense to move this to net_smtp. */
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

/*!
 * \brief Save a message to a maildir folder
 * \param smtp SMTP session
 * \param mbox Mailbox to which message is being appended
 * \param mproc
 * \param recipient Recipient address (incoming), NULL for saving copies of sent messages (outgoing)
 * \param srcfd Source file descriptor containing message
 * \param datalen Length of message
 * \param[out] newfilebuf Saved filename
 * \param len Length of newfilebuf
 * \retval 0 on success, nonzero on error
 */
/*! \todo Can smtp be NULL to this function? If so, we have a problem */
static int appendmsg(struct smtp_session *smtp, struct mailbox *mbox, struct smtp_msg_process *mproc, const char *recipient, int srcfd, size_t datalen, char *newfilebuf, size_t len)
{
	char tmpfile[256];
	char newfile[sizeof(tmpfile)];
	int fd, res;
	unsigned long quotaleft;

	/* Enforce mail quota for message delivery. We check this after callbacks,
	 * since maybe the callback opted to drop the message, or relay it,
	 * or do something to the message that can succeed even with insufficient quota to save it. */
	quotaleft = mailbox_quota_remaining(mbox);
	bbs_debug(5, "Mailbox %d has %lu bytes quota remaining (need %lu)\n", mailbox_id(mbox), quotaleft, datalen);
	if (quotaleft < datalen) {
		/* Mailbox is full, insufficient quota remaining for this message. */
		mailbox_notify_quota_exceeded(smtp->node, mbox);
		return -2;
	}

	if (mproc->newdir) {
		char newdir[512];
		/*! \todo We need to prepend a dot here if the mailbox name is not INBOX */
		snprintf(newdir, sizeof(newdir), "%s/%s", mailbox_maildir(mbox), mproc->newdir);
		free(mproc->newdir);
		if (eaccess(newdir, R_OK)) {
			bbs_warning("maildir %s does not exist. Defaulting to INBOX\n", newdir);
			fd = maildir_mktemp(mailbox_maildir(mbox), tmpfile, sizeof(tmpfile), newfile);
		} else {
			fd = maildir_mktemp(newdir, tmpfile, sizeof(tmpfile), newfile);
		}
	} else {
		fd = maildir_mktemp(mailbox_maildir(mbox), tmpfile, sizeof(tmpfile), newfile);
	}

	if (fd < 0) {
		return -1;
	}

	if (recipient) { /* For incoming messages, but not for saving copies of outgoing messages */
		struct smtp_filter_data filterdata;
		memset(&filterdata, 0, sizeof(filterdata));
		filterdata.smtp = smtp;
		filterdata.recipient = recipient;
		filterdata.inputfd = srcfd;
		filterdata.size = datalen;
		filterdata.outputfd = fd;
		smtp_run_filters(&filterdata, SMTP_DIRECTION_IN);
	}

	/* Write the entire body of the message. */
	res = bbs_copy_file(srcfd, fd, 0, (int) datalen);
	close(fd);
	if (res != (int) datalen) {
		bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", datalen, tmpfile, res);
		return -1;
	}

	if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		return -1;
	} else {
		/* Because the notification is delivered before we actually return success to the sending client,
		 * this can result in the somewhat strange experience of receiving an email send to yourself
		 * before it seems that the email has been fully sent.
		 * This is just a side effect of processing the email completely synchronously
		 * "real" mail servers typically queue the message to decouple it. We just deliver it immediately.
		 */
		bbs_debug(6, "Delivered message to %s\n", newfile);
		if (newfilebuf) {
			safe_strncpy(newfilebuf, newfile, len);
		}
		if (!mproc->newdir && recipient) { /* Reference is invalid by now, but we only care about if it existed */
			/*! \todo For now, no need to notify ourselves for saving copies of Sent messages. Clients probably aren't idling on the Sent folder anyways
			 * If/when IMAP NOTIFY support is added, we still need to notify mod_mail about new messages,
			 * here and everywhere else in net_smtp where messages are saved to disk.
			 */
			mailbox_notify_new_message(smtp->node, mbox, mailbox_maildir(mbox), newfile, datalen);
		}
	}
	return 0;
}

static int do_local_delivery(struct smtp_session *smtp, const char *recipient, const char *user, const char *domain, int srcfd, size_t datalen, int *responded)
{
	struct mailbox *mbox;
	struct smtp_msg_process mproc;

	mbox = mailbox_get_by_name(user, domain);
	if (!mbox) {
		/* We should've caught this before. */
		bbs_warning("Mailbox '%s' does not exist locally\n", user);
		return -1;
	}

	/* .Drafts, .Sent, .Trash etc. are auto-created by mailbox_get if needed.
	 * However, new, cur, and tmp aren't created until we called mailbox_maildir_init.
	 * So if they don't exist right now, this is a mailbox whose maildir we just created.
	 * In other words, this is the first message this user has ever received. */
	if (notify_external_firstmsg) {
		notify_firstmsg(mbox);
	}

	/* No need to get a mailbox lock, really. */
	if (mailbox_maildir_init(mailbox_maildir(mbox))) {
		return -1;
	}

	/* SMTP callbacks for incoming messages */
	memset(&mproc, 0, sizeof(mproc));
	smtp_mproc_init(smtp, &mproc);
	mproc.size = (int) datalen;
	mproc.recipient = recipient;
	mproc.direction = SMTP_MSG_DIRECTION_IN;
	mproc.mbox = mbox;
	mproc.userid = 0;
	if (smtp_run_callbacks(&mproc)) {
		return 0; /* If returned nonzero, it's assumed it responded with an SMTP error code as appropriate. */
	}

	/*! \todo BUGBUG Shouldn't send reply here if there are multiple recipients, need to send a separate message
	 * Need to refactor some of this stuff so multiple-recipient delivery results in only one SMTP reply code.
	 * In particular, for sending messages to multiple local recipients, there are currently 3 places where
	 * we could send return codes/messages.
	 *
	 * The responded variable that we set to 1 here is a hack until that happens.
	 */
	if (mproc.bounce) {
		const char *msg = "This message has been rejected by the recipient";
		if (mproc.bouncemsg) {
			msg = mproc.bouncemsg;
		}
		if (smtp->node) { /*! \todo FIXME XXX Since injection doesn't have a node->fd... and doesn't have a node either for mod_mailscript to do variable substitution */
			/*! \todo We should allow the filtering engine to set the response code too (e.g. greylisting) */
			smtp_reply(smtp, 554, 5.7.1, "%s", msg); /* XXX Best default SMTP code for this? */
		}
		free_if(mproc.bouncemsg);
		*responded = 1;
	}
	if (mproc.drop) {
		return 0; /* Silently drop message */
	}

	return appendmsg(smtp, mbox, &mproc, recipient, srcfd, datalen, NULL, 0);
}

/*! \brief Generate "Undelivered Mail Returned to Sender" email and send it to the sending user using do_local_delivery (then delete the message) */
static int return_dead_letter(const char *from, const char *to, const char *msgfile, size_t msgsize, size_t metalen, const char *error)
{
	int res;
	char fromaddr[256];
	char body[512];
	int origfd, attachfd, msgfd;
	struct mailbox *mbox;
	char dupaddr[256];
	char tmpattach[256] = "/tmp/bouncemsgXXXXXX";
	char tmpfile[256];
	char newfile[256];
	char *user, *domain;
	FILE *fp;
	size_t size;

	/* This server does not relay mail from the outside,
	 * so we're only responsible for dispatching Delivery Failure notices
	 * to local users. */
	safe_strncpy(dupaddr, from, sizeof(dupaddr));
	if (bbs_parse_email_address(dupaddr, NULL, &user, &domain)) {
		bbs_error("Invalid email address: %s\n", from);
		return -1;
	}
	if (!mail_domain_is_local(domain)) {
		bbs_error("Address %s is not local (user: %s, host: %s)\n", from, user, domain);
		return -1;
	}
	mbox = mailbox_get_by_name(user, domain);
	if (!mbox) {
		bbs_error("Couldn't find mailbox for '%s'\n", user);
		return -1;
	}

	origfd = open(msgfile, O_RDONLY, 0600);
	if (origfd < 0) {
		bbs_error("open(%s) failed: %s\n", msgfile, strerror(errno));
		return -1;
	}

	/* Make a copy of the original email, with the first two lines removed (contains queue metadata just for us) */
	attachfd = mkstemp(tmpattach); /* In practice, most mail servers will name the attachment with the name of the original subject, with a .eml extension */
	if (attachfd < 0) {
		bbs_error("mkstemp failed: %s\n", strerror(errno));
		close(origfd);
		return -1;
	}

	/* Skip first metalen characters, and send msgsize - metalen, to copy over just the message itself. */
	bbs_copy_file(origfd, attachfd, (int) metalen, (int) (msgsize - metalen));
	close(origfd);
	close(attachfd);
	snprintf(fromaddr, sizeof(fromaddr), "mailer-daemon@%s", bbs_hostname()); /* We can be whomever we want to say we are... but let's be a mailer daemon. */

	/* XXX This is not a standard bounce message format (we need multipart/report for that)
	 * See RFC 3461 Section 6. */
	snprintf(body, sizeof(body),
		"This is the mail system at %s.\r\n\r\n"
		"I'm sorry to inform you that your message could not\r\nbe delivered to one or more recipients. It's attached below.\r\n\r\n"
		"Please, do not reply to this message.\r\n\r\n\r\n"
		"%s: %s\r\n", /* from already has <> */
		/* The original from is the new to. */
		bbs_hostname(), to, error);

	/* We'll deliver the bounce message to the user's INBOX. */
	msgfd = maildir_mktemp(mailbox_maildir(mbox), tmpfile, sizeof(tmpfile), newfile);
	if (msgfd < 0) {
		unlink(tmpattach);
		return -1;
	}

	fp = fdopen(msgfd, "w");
	if (!fp) {
		bbs_error("fdopen failed: %s\n", strerror(errno));
		unlink(tmpattach);
		return -1;
	}
	/* Don't have bbs_make_email_file delete the message, since we always want it deleted. */
	res = bbs_make_email_file(fp, "Undelivered Message Returned to Sender", body, from, fromaddr, NULL, NULL, tmpattach, 0);
	size = (size_t) ftell(fp);
	fclose(fp);

	/* Deliver the message. */
	if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		return -1;
	} else {
		mailbox_notify_new_message(NULL, mbox, mailbox_maildir(mbox), newfile, size);
	}

	if (unlink(tmpattach)) {
		bbs_error("unlink(%s) failed: %s\n", tmpattach, strerror(errno));
	}
	if (!res) {
		if (unlink(msgfile)) { /* Delete queue file if we successfully returned the message to sender. */
			bbs_error("unlink(%s) failed: %s\n", msgfile, strerror(errno));
		}
	}
	return res;
}

static int notify_stalled_delivery(const char *from, const char *to, const char *error)
{
	int res;
	char fromaddr[256];
	char body[768];
	int msgfd;
	struct mailbox *mbox;
	char dupaddr[256];
	char tmpfile[256];
	char newfile[256];
	char *user, *domain;
	FILE *fp;
	size_t size;

	safe_strncpy(dupaddr, from, sizeof(dupaddr));
	if (bbs_parse_email_address(dupaddr, NULL, &user, &domain)) {
		bbs_error("Invalid email address: %s\n", from);
		return -1;
	}
	if (!mail_domain_is_local(domain)) {
		bbs_error("Address %s is not local (user: %s, host: %s)\n", from, user, domain);
		return -1;
	}
	mbox = mailbox_get_by_name(user, domain);
	if (!mbox) {
		bbs_error("Couldn't find mailbox for '%s'\n", user);
		return -1;
	}

	snprintf(fromaddr, sizeof(fromaddr), "mailer-daemon@%s", bbs_hostname()); /* We can be whomever we want to say we are... but let's be a mailer daemon. */
	snprintf(body, sizeof(body),
		"This is the mail system at %s.\r\n\r\n"
		"This is an informational notice that a message you recently sent has not yet been successfully delivered.\r\n\r\n"
		"It is possible that delivery will succeed on future attempts to deliver this message. "
		"If all subsequent attempts fail, you will receive a final delivery notice detailing the failure.\r\n\r\n"
		"Please, do not reply to this message.\r\n\r\n\r\n"
		"%s: %s\r\n", /* from already has <> */
		/* The original from is the new to. */
		bbs_hostname(), to, error);

	/* Deliver to INBOX. */
	msgfd = maildir_mktemp(mailbox_maildir(mbox), tmpfile, sizeof(tmpfile), newfile);
	if (msgfd < 0) {
		return -1;
	}

	fp = fdopen(msgfd, "w");
	if (!fp) {
		bbs_error("fdopen failed: %s\n", strerror(errno));
		return -1;
	}
	res = bbs_make_email_file(fp, "Message Delivery Delayed", body, from, fromaddr, NULL, NULL, NULL, 0);
	size = (size_t) ftell(fp);
	fclose(fp);

	/* Deliver the message. */
	if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		return -1;
	} else {
		mailbox_notify_new_message(NULL, mbox, mailbox_maildir(mbox), newfile, size);
	}
	return res;
}

static int on_queue_file(const char *dir_name, const char *filename, void *obj)
{
	FILE *fp;
	char fullname[516], newname[sizeof(fullname) + 11];
	char from[1000], recipient[1000], todup[256];
	char *hostname;
	char *realfrom, *realto;
	char *user, *domain;
	char *retries;
	int newretries;
	int res = -1;
	unsigned long size;
	size_t metalen;
	char buf[256] = "";
	struct stringlist mxservers;

	UNUSED(obj);

	snprintf(fullname, sizeof(fullname), "%s/%s", dir_name, filename);

	fp = fopen(fullname, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
		return 0;
	}

	fseek(fp, 0L, SEEK_END); /* Go to EOF */
	size = (long unsigned) ftell(fp);
	rewind(fp); /* Be kind, rewind */

	if (!fgets(from, sizeof(from), fp) || !fgets(recipient, sizeof(recipient), fp)) {
		bbs_error("Failed to read metadata from %s\n", fullname);
		goto cleanup;
	}

	metalen = strlen(from) + strlen(recipient); /* This already includes the newlines */

	retries = strchr(fullname, '.');
	if (!retries++ || strlen_zero(retries)) { /* Shouldn't happen for mail queue files legitimately generated by this module, but somebody else might have dumped stuff in. */
		bbs_error("File name '%s' is non-compliant with our filename format\n", fullname);
		goto cleanup;
	}

	/* If you manually edit the queue files, the line endings will get converted,
	 * and since the queue files use a combination of LF and CR LF,
	 * that can mess things up.
	 * In particular, something like nano will convert everything to LF,
	 * so bbs_readline will return the entire body as one big blob,
	 * since the file has no CR LF delimiters at all.
	 * And because rely on CR LF . CR LF for end of email detection,
	 * we'll only see LF . CR LF at the end, and delivery will thus fail.
	 * Do not modify the mail queue files manually for debugging, unless you really know what you are doing,
	 * and in particular are preserving the mixed line endings. */
	bbs_term_line(from);
	bbs_term_line(recipient);

	realfrom = strchr(from, '<');
	realto = strchr(recipient, '<');

	if (!realfrom) {
		bbs_error("Mail queue file MAIL FROM missing <>: %s\n", fullname);
		goto cleanup;
	} else if (!realto) {
		bbs_error("Mail queue file RCPT TO missing <>: %s\n", fullname);
		goto cleanup;
	}

	realfrom++; /* Skip < */
	if (strlen_zero(realfrom)) {
		bbs_error("Malformed MAIL FROM: %s\n", fullname);
		goto cleanup;
	}
	bbs_strterm(realfrom, '>'); /* try_send will add <> for us, so strip it here to match */

	if (bbs_str_count(realfrom, '<') || bbs_str_count(realfrom, '>') || bbs_str_count(realto, '<') != 1 || bbs_str_count(realto, '>') != 1) {
		bbs_error("Sender or recipient address malformed %s -> %s\n", realfrom, realto);
		goto cleanup;
	}
	bbs_debug(5, "Processing message from %s -> %s\n", realfrom, realto);

	safe_strncpy(todup, realto, sizeof(todup));
	if (strlen_zero(realfrom) || bbs_parse_email_address(todup, NULL, &user, &domain)) {
		bbs_error("Address parsing error\n");
		goto cleanup;
	}

	bbs_debug(2, "Retrying delivery of %s (%s -> %s)\n", fullname, realfrom, realto);

	memset(&mxservers, 0, sizeof(mxservers));
	if (lookup_mx_all(domain, &mxservers)) {
		char a_ip[256];
		/* Fall back to trying the A record */
		if (bbs_resolve_hostname(domain, a_ip, sizeof(a_ip))) {
			bbs_warning("Recipient domain %s does not have any MX or A records\n", domain);
			/* Just treat as undeliverable at this point and return to sender (if no MX records now, probably won't be any the next time we try) */
			/* Send a delivery failure response, then delete the file. */
			bbs_warning("Delivery of message %s from %s to %s has failed permanently (no MX records)\n", fullname, realfrom, realto);
			/* There isn't any SMTP level error at this point yet, we have to make our own error message for the bounce message */
			snprintf(buf, sizeof(buf), "No MX record(s) located for hostname %s", domain);
			return_dead_letter(realfrom, realto, fullname, size, metalen, buf);
			goto cleanup;
		}
		bbs_warning("Recipient domain %s does not have any MX records, falling back to A record %s\n", domain, a_ip);
		stringlist_push(&mxservers, a_ip);
	}

	/* Try all the MX servers in order, if necessary */
	while (res < 0 && (hostname = stringlist_pop(&mxservers))) {
		res = try_send(NULL, hostname, DEFAULT_SMTP_PORT, 0, NULL, NULL, realfrom, realto, NULL, NULL, 0, fileno(fp), (off_t) metalen, size - metalen, buf, sizeof(buf));
		free(hostname);
	}
	stringlist_empty(&mxservers);
	fclose(fp);
	if (!res) {
		/* Successful delivery. */
		if (unlink(fullname)) {
			bbs_error("Failed to remove file %s\n", fullname);
		}
		return 0;
	}

	newretries = atoi(retries) + 1;
	bbs_debug(3, "Delivery of %s to %s has been attempted %d/%d times\n", fullname, realto, newretries, max_retries);
	if (res > 0 || newretries >= (int) max_retries) {
		/* Send a delivery failure response, then delete the file. */
		bbs_warning("Delivery of message %s from %s to %s has failed permanently after %d retries\n", fullname, realfrom, realto, newretries);
		return_dead_letter(realfrom, realto, fullname, size, metalen, buf);
	} else {
		char tmpbuf[256];
		bbs_strncpy_until(tmpbuf, fullname, sizeof(tmpbuf), '.');
		/* Store retry information in the filename itself, so we don't have to modify the file, we can just rename it. Inspired by IMAP. */
		snprintf(newname, sizeof(newname), "%s.%d", tmpbuf, newretries);
		if (rename(fullname, newname)) {
			bbs_error("Failed to rename %s to %s\n", fullname, newname);
		}
		/* Optionally notify the sender that we haven't successfully delivered this message yet,
		 * since most people nowadays will assume email is delivered immediately. */
		if (notify_queue) {
			notify_stalled_delivery(realfrom, realto, buf);
		}
	}
	return 0; /* Already closed fp */

cleanup:
	fclose(fp);
	return 0;
}

/*! \brief Periodically retry delivery of outgoing mail */
static void *queue_handler(void *unused)
{
	UNUSED(unused);

	if (!queue_outgoing) {
		bbs_debug(4, "Outgoing queue is disabled, queue handler exiting\n");
		return NULL; /* Not needed, queuing disabled */
	}

	usleep(10000000); /* Wait 10 seconds after the module loads, then try to flush anything in the queue. */

	for (;;) {
		bbs_pthread_disable_cancel();
		pthread_mutex_lock(&queue_lock);
		bbs_dir_traverse(queue_dir, on_queue_file, NULL, -1);
		pthread_mutex_unlock(&queue_lock);
		bbs_pthread_enable_cancel();
		usleep(1000000 * queue_interval);
	}
	return NULL;
}

/*! \note Enable a workaround for socket connects to mail servers failing if we try to send them synchronously. This effectively always enables sendasync=yes. */
#define BUGGY_SEND_IMMEDIATE

static void *smtp_async_send(void *varg)
{
	char mailnewdir[260];
	char fullname[512];
	char *filename = varg;

	snprintf(mailnewdir, sizeof(mailnewdir), "%s/mailq/new", mailbox_maildir(NULL));

	/* Acquiring this lock is not guaranteed to happen immediately,
	 * but that's okay since this thread is running asynchronously. */
	pthread_mutex_lock(&queue_lock);
	/* We could move it to the tmp dir to prevent a conflict with the periodic queue thread,
	 * but the nice thing about doing it exactly the same way is that if delivery fails temporarily
	 * this first round, it'll be automatically handled by the queue retry logic.
	 * So we can always report 250 success here immediately.
	 * In fact, this doesn't even need to be done in this thread.
	 * The downside, of course, is that locking is needed to ensure
	 * we don't try to send the same message twice.
	 */

	snprintf(fullname, sizeof(fullname), "%s/%s", mailnewdir, filename);
	if (!bbs_file_exists(fullname)) {
		/* If we couldn't acquire the lock immediately,
		 * that means the queue thread was already running.
		 * It may or may not have already picked up this file,
		 * depending on how the timing worked out.
		 * If it was processed, then the file was already renamed,
		 * so we can detect that and bail. */
		bbs_debug(5, "Ooh, file %s was already handled before its owner got a chance to send it asynchronously\n", fullname);
	} else {
		on_queue_file(mailnewdir, filename, NULL);
	}

	pthread_mutex_unlock(&queue_lock);
	free(filename);
	return NULL;
}

/*! \brief Accept delivery of a message to an external recipient, sending it now if possible and queuing it otherwise */
static int external_delivery(struct smtp_session *smtp, const char *recipient, const char *domain, int srcfd, unsigned long datalen)
{
#ifndef BUGGY_SEND_IMMEDIATE
	char buf[256] = "";
	int res = -1;
#endif

	bbs_assert(smtp->fromlocal);
	if (!accept_relay_out) {
		smtp_reply(smtp, 550, 5.7.0, "Mail relay denied.");
		return 0;
	} else if (smtp->fromlocal && minpriv_relay_out) {
		if (smtp->node->user->priv < minpriv_relay_out) {
			smtp_reply(smtp, 550, 5.7.0, "Mail relay denied. Unauthorized to relay external mail.");
			return 0;
		}
	}

	if (!always_queue && !send_async) {  /* Try to send it synchronously */
		struct stringlist mxservers;
		/* Start by trying to deliver it directly, immediately, right now. */
		memset(&mxservers, 0, sizeof(mxservers));
		if (lookup_mx_all(domain, &mxservers)) {
			smtp_reply(smtp, 553, 5.1.2, "Recipient domain not found.");
			return 0;
		}
#ifndef BUGGY_SEND_IMMEDIATE
		/* Try all the MX servers in order, if necessary */
		while (res < 0 && (hostname = stringlist_pop(&mxservers))) {
			res = try_send(NULL, hostname, DEFAULT_SMTP_PORT, 0, NULL, NULL, realfrom, realto, NULL, NULL, 0, srcfd, datalen, size - datalen, buf, sizeof(buf));
			free(hostname);
		}
		stringlist_empty(&mxservers);

		if (res > 0) { /* Permanent error */
			/* We've still got the sender on the socket, just relay the error. */
			_smtp_reply(smtp, "%s\r\n", buf);
			return -1;
		} else if (res) { /* Temporary error */
			/* This can happen legitimately, if a mail server is unavailable, but it's generally unusual and could mean there are issues. */
			bbs_warning("Initial synchronous delivery of message to %s failed\n", domain);
		}
#endif
	}

#ifndef BUGGY_SEND_IMMEDIATE
	if (res && !queue_outgoing) {
		bbs_debug(3, "Delivery failed and can't queue message, rejecting\n");
		return -1; /* Can't queue failed message, so reject it now. */
	} else if (res) {
		int doasync;
#else
	if (1) {
		int res;
#endif
		int fd;
		char qdir[256];
		char tmpfile[256], newfile[256];
		struct smtp_filter_data filterdata;

		if (!queue_outgoing) {
			return -1;
		}
		/* Queue delivery for later */
		snprintf(qdir, sizeof(qdir), "%s/%s", mailbox_maildir(NULL), "mailq");
		if (mailbox_maildir_init(qdir)) {
			return -1; /* Can't queue */
		}
		fd = maildir_mktemp(qdir, tmpfile, sizeof(tmpfile) - 3, newfile);
		strncat(newfile, ".0", sizeof(newfile) - 1);
		if (fd < 0) {
			return -1;
		}
		/* Prepend some metadata to the message. postfix has some file format that it uses for this,
		 * (the output of postcat is formatted)
		 * (https://www.reddit.com/r/postfix/comments/42ku9j/format_of_the_files_in_the_deferred_mailq/)
		 * (https://serverfault.com/questions/391995/how-can-i-see-the-contents-of-the-mail-whose-id-i-get-from-mailq-command)
		 * but a) I can't find any good documentation on it
		 * and b) It's probably overkill for what we need here.
		 * The queue files are mostly just RFC 822 messages.
		 *
		 * The metadata is LF terminated (not CR LF) to make it easier to parse back using fread (we won't have a stray CR present).
		 * Note that this means this file contains mixed line endings (both LF and CR LF), so if manually edited in a text editor,
		 * it will probably get screwed up. Don't do it!
		 */

		dprintf(fd, "MAIL FROM:<%s>\nRCPT TO:%s\n", smtp->from, recipient); /* First 2 lines contain metadata, and recipient is already enclosed in <> */

		memset(&filterdata, 0, sizeof(filterdata));
		filterdata.smtp = smtp;
		filterdata.recipient = recipient;
		filterdata.inputfd = srcfd;
		filterdata.size = datalen;
		filterdata.outputfd = fd;
		smtp_run_filters(&filterdata, SMTP_DIRECTION_OUT);

		/* Write the entire body of the message. */
		res = bbs_copy_file(srcfd, fd, 0, (int) datalen);
		if (res != (int) datalen) {
			bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", datalen, tmpfile, res);
			close(fd);
			return -1;
		}
		if (rename(tmpfile, newfile)) {
			bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
			close(fd);
			return -1;
		}
		close(fd);
#ifndef BUGGY_SEND_IMMEDIATE
		doasync = send_async;
		if (doasync) {
#else
		if (1) {
#endif
			pthread_t sendthread;
			const char *filename;
			char *filenamedup;
			/* For some reason, this works, even though calling try_send on the smtp structure directly above did not. */
			filename = strrchr(newfile, '/');
			filenamedup = strdup(filename + 1); /* Need to duplicate since filename is on the stack and we're returning now */
			if (ALLOC_SUCCESS(filenamedup)) {
				/* Yes, I know spawning a thread for every email is not very efficient.
				 * If this were a high traffic mail server, this might be architected differently.
				 * Do note that this is mainly a WORKAROUND for BUGGY_SEND_IMMEDIATE. */
				if (bbs_pthread_create_detached(&sendthread, NULL, smtp_async_send, filenamedup)) {
					free(filenamedup);
				}
			}
			bbs_debug(4, "Successfully queued message for immediate delivery\n");
		} else {
			bbs_debug(4, "Successfully queued message for delayed delivery\n");
		}
	}
	return 0;
}

static int archive_list_msg(struct smtp_session *smtp, int srcfd)
{
	char listsdir[256];
	char listdir[384];
	int fd, res;
	char tmpfile[256], newfile[256];

	/* Archive a copy of the message sent to this mailing list. */

	snprintf(listsdir, sizeof(listsdir), "%s/lists", mailbox_maildir(NULL));
	if (eaccess(listsdir, R_OK)) {
		if (mkdir(listsdir, 0700)) {
			bbs_error("mkdir(%s) failed: %s\n", listsdir, strerror(errno));
			return -1;
		}
	}

	snprintf(listdir, sizeof(listdir), "%s/%s", listsdir, smtp->listname);
	if (eaccess(listdir, R_OK)) {
		if (mkdir(listdir, 0700)) {
			bbs_error("mkdir(%s) failed: %s\n", listdir, strerror(errno));
			return -1;
		}
	}

	/* This isn't really a mailbox, but just use the maildir functions for convenience. */
	if (mailbox_maildir_init(listdir)) {
		return -1;
	}

	fd = maildir_mktemp(listdir, tmpfile, sizeof(tmpfile), newfile);
	if (fd < 0) {
		return -1;
	}

	/* Write the entire body of the message. */
	res = bbs_copy_file(srcfd, fd, 0, (int) smtp->datalen);
	if (res != (int) smtp->datalen) {
		bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", smtp->datalen, tmpfile, res);
		close(fd);
		return -1;
	}

	close(fd);
	if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		return -1;
	}

	bbs_debug(7, "Archived list message to %s\n", newfile);
	return 0;
}

static int expand_and_deliver(struct smtp_session *smtp, const char *filename, size_t datalen, int *responded, int *quotaexceeded)
{
	char *recipient;
	int mres;
	int res = 0;
	int srcfd;
	struct smtp_filter_data filterdata;

	/* Preserve the actual received time for the Received header, in case filters take a moment to run */
	smtp->received = time(NULL);

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
	 */
	memset(&filterdata, 0, sizeof(filterdata));
	filterdata.smtp = smtp;
	filterdata.recipient = NULL; /* This is for the message as a whole, not each recipient. Just making that explicit. */
	filterdata.inputfd = srcfd;
	filterdata.size = datalen;
	filterdata.outputfd = -1;
	smtp_run_filters(&filterdata, SMTP_DIRECTION_IN);

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

	if (smtp->listname && archivelists) {
		archive_list_msg(smtp, srcfd);
	}
	while ((recipient = stringlist_pop(&smtp->recipients))) {
		char *user, *domain;
		char *dup, *tmp = NULL;
		const char *normalized_recipient;
		/* The MailScript FORWARD rule will result in recipients being added to
		 * the recipients list while we're in this loop.
		 * However the same message is sent to the new target, since we forward the raw message, which means
		 * we can't rely on counting Received headers to detect mail loops (for local users).
		 * Perhaps even more appropriate would be keeping track of the user ID instead of the recipient,
		 * to also account for aliases (but it should be fine).
		 * This avoids loops not detected by counting Received headers:
		 */
		/*! \todo Is this entirely sufficient/appropriate? Maybe we should ALSO add a single Received header on forwards? */
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
			continue;
		}
		stringlist_push(&smtp->sentrecipients, normalized_recipient);
		bbs_debug(7, "Processing delivery to %s\n", normalized_recipient);
		if (tmp) {
			*tmp = '>'; /* Restore it back */
		}
		dup = strdup(recipient);
		if (ALLOC_FAILURE(dup)) {
			goto next;
		}
		/* We already did this when we got RCPT TO, so hopefully we're all good here. */
		if (bbs_parse_email_address(dup, NULL, &user, &domain)) {
			goto next;
		}
		if (mail_domain_is_local(domain)) {
			mres = do_local_delivery(smtp, recipient, user, domain, srcfd, datalen, responded);
			if (mres == -2) {
				/*! \todo Needs total overhaul, use a separate structure to keep track of delivery failure reasons and outcomes */
				*quotaexceeded = 1;
			}
			res |= mres;
		} else {
			res |= external_delivery(smtp, recipient, domain, srcfd, datalen);
		}
next:
		free_if(dup);
		free(recipient);
	}

	close(srcfd);
	if (filterdata.outputfd != -1) {
		if (unlink(filterdata.outputfile)) {
			bbs_error("unlink(%s) failed: %s\n", filterdata.outputfile, strerror(errno));
		}
	}
	return res;
}

/*! \brief Accept messages injected from the BBS to deliver, to local or external recipients */
static int injectmail(MAILER_PARAMS)
{
	struct smtp_session smtp;
	int responded = 0, quotaexceeded = 0;
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

	/*! \todo Refactor things so we don't have to create a dummy SMTP structure */
	memset(&smtp, 0, sizeof(smtp));

	smtp.fromlocal = 1;

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
	smtp.from = sender;
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
	safe_strncpy(smtp.template, tmp, sizeof(smtp.template));
	/*! \todo The mail interface should probably accept a stringlist globally, since it's reasonable to have multiple recipients */

	/* This should be enclosed in <>, but there must not be a name.
	 * That's because the queue file writer expects us to provide <> around TO, but not FROM... it's a bit flimsy. */
	tmpaddr = strchr(to, '<');
	if (tmpaddr) {
		safe_strncpy(recipient, tmpaddr, sizeof(recipient));
	} else {
		snprintf(recipient, sizeof(recipient), "<%s>", to);
	}
	stringlist_push(&smtp.recipients, recipient);

	res = expand_and_deliver(&smtp, tmp, (size_t) length, &responded, &quotaexceeded);
	stringlist_empty(&smtp.recipients);
	stringlist_empty(&smtp.sentrecipients);
	unlink(tmp);
	bbs_debug(3, "injectmail res=%d, responded=%d, quotaexceeded=%d, sender=%s, recipient=%s\n", res, responded, quotaexceeded, sender, recipient);
	if (res) {
		return -1;
	}
	if (responded || quotaexceeded) {
		return 1;
	}
	return 0;
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
	if (!domain) { /* Missing domain altogether, yikes */
		smtp_reply(smtp, 550, 5.7.1, "You are not authorized to send email using this identity");
		return -1;
	}
	if (!mail_domain_is_local(domain)) { /* Wrong domain */
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

static int upload_file(struct smtp_session *smtp, struct smtp_msg_process *mproc, int srcfd, size_t datalen)
{
	struct bbs_tcp_client client;
	struct bbs_url url;
	char tmpbuf[1024];
	int imapcaps;
	off_t offset = 0;
	ssize_t res;

	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));
	if (bbs_parse_url(&url, mproc->newdir) || strlen_zero(url.resource) || bbs_tcp_client_connect(&client, &url, !strcmp(url.prot, "imaps"), tmpbuf, sizeof(tmpbuf))) {
		smtp_reply(smtp, 550, 5.7.0, "Unable to save sent message"); /* XXX Appropriate SMTP code? */
		return -1;
	}

	if (imap_client_login(&client, &url, smtp->node->user, &imapcaps)) {
		bbs_debug(3, "IMAP login fail!\n");
		goto cleanup;
	}

	if (imapcaps & IMAP_CAPABILITY_LITERAL_PLUS) {
		/* Avoid an RTT if possible by using a non-synchronizing literal */
		IMAP_CLIENT_SEND(&client, "a2 APPEND \"%s\" (\\Seen) {%lu+}", url.resource, datalen);
	} else {
		IMAP_CLIENT_SEND(&client, "a2 APPEND \"%s\" (\\Seen) {%lu}", url.resource, datalen);
		IMAP_CLIENT_EXPECT(&client, "+");
	}

	res = sendfile(client.wfd, srcfd, &offset, datalen); /* Don't use bbs_copy_file, the target is a pipe/socket, not a file */
	if (res != (ssize_t) datalen) {
		bbs_warning("Wanted to upload %lu bytes but only uploaded %ld? (%s)\n", datalen, res, strerror(errno));
		goto cleanup;
	}
	IMAP_CLIENT_SEND(&client, ""); /* CR LF to finish */
	IMAP_CLIENT_EXPECT(&client, "a2 OK");
	IMAP_CLIENT_SEND(&client, "a3 LOGOUT");
	bbs_tcp_client_cleanup(&client);
	return 0;

cleanup:
	bbs_debug(5, "Remote IMAP login to %s:%d failed\n", url.host, url.port);
	bbs_tcp_client_cleanup(&client);
	return -1;
}

/*! \brief Actually send an email or queue it for delivery */
static int do_deliver(struct smtp_session *smtp, const char *filename, size_t datalen)
{
	int res = 0;
	int quotaexceeded = 0;
	int responded = 0;
	struct smtp_msg_process mproc;

	memset(&mproc, 0, sizeof(mproc));

	bbs_debug(7, "Processing message from %s for delivery: local=%d, size=%lu, from=%s\n", smtp->msa ? "MSA" : "MTA", smtp->fromlocal, datalen, smtp->from);

	if (smtp->datalen >= max_message_size) {
		/* XXX Should this only apply for local deliveries? */
		smtp_reply(smtp, 552, 5.3.4, "Message too large");
		return 0;
	}

	if (smtp->maxsize > 0 && smtp->datalen > smtp->maxsize) {
		smtp_reply(smtp, 552, 5.3.4, "Message too large (maximum size permitted is %u bytes)", smtp->maxsize);
		return 0;
	}
	if (smtp->ptonly) {
		bbs_debug(6, "Analyzing content type: %s\n", smtp->contenttype);
		if (smtp->contenttype && !STARTS_WITH(smtp->contenttype, "text/plain")) {
			smtp_reply_nostatus(smtp, 550, "Only plain text emails permitted to this destination");
			return 0;
		}
	}

	/* SMTP callbacks for outgoing messages */
	if (smtp->msa || smtp->fromlocal) {
		char newfile[256];
		int savedcopy = 0;
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
		 * MOVETO .Sent to save sent messages to the Sent folder, rather than Gmail just placing them in the same one (e.g. INBOX).
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
			if (STARTS_WITH(mproc.newdir, "imap://") || STARTS_WITH(mproc.newdir, "imaps://")) {
				res = upload_file(smtp, &mproc, srcfd, datalen); /* Connect to some remote IMAP server and APPEND the message */
				free(mproc.newdir);
			} else {
				if (srcfd < 0) {
					bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
					res = -1;
				} else {
					struct mailbox *mbox = mailbox_get_by_userid(smtp->node->user->id);
					res = appendmsg(smtp, mbox, &mproc, NULL, srcfd, datalen, newfile, sizeof(newfile)); /* Save the Sent message locally */
					/* appendmsg frees mproc.newdir */
					if (!res) {
						savedcopy = 1;
					}
				}
			}
			CLOSE(srcfd);
			if (res) {
				smtp_reply(smtp, 550, 5.7.0, "Unable to save sent message"); /* XXX Appropriate SMTP code? */
				return -1;
			}
		}
		if (mproc.relayroute) { /* This happens BEFORE we check the From identity, which is important for relaying since typically this would be rejected locally. */
			/* Relay it through another MSA */
			/* Format is smtps://user:password@host:port - https://datatracker.ietf.org/doc/html/draft-earhart-url-smtp-00 */
			struct bbs_url url;
			memset(&url, 0, sizeof(url));
			if (bbs_parse_url(&url, mproc.relayroute)) {
				bbs_warning("Failed to parse SMTP URL\n");
				res = -1;
			} else if (!STARTS_WITH(url.prot, "smtp")) {
				bbs_warning("Invalid SMTP protocol: %s\n", url.prot);
			} else {
				char buf[132];
				char prepend[256] = "";
				int prependlen = 0;

				/* Still prepend a Received header, but less descriptive than normal (don't include Authenticated sender) since we're relaying */
				if (smtp->fromlocal && !add_received_msa) {
					char timestamp[40];
					time_t now = time(NULL);
					smtp_timestamp(now, timestamp, sizeof(timestamp));
					prependlen = snprintf(prepend, sizeof(prepend), "Received: from [HIDDEN]\r\n\tby %s with %s\r\n\t%s\r\n",
						bbs_hostname(), smtp_protname(smtp), timestamp);
				}

				bbs_debug(5, "Relaying message via %s:%d (user: %s)\n", url.host, url.port, S_IF(url.user));
				/* XXX smtp->recipients is "used up" by try_send, so this relies on the message being DROP'ed as there will be no recipients remaining afterwards
				 * Instead, we could duplicate the recipients list to avoid this restriction. */
				srcfd = open(filename, O_RDONLY);
				if (srcfd >= 0) {
					/* XXX A cool optimization would be if the IMAP server supported BURL IMAP and we did a MOVETO, use BURL with the SMTP server */
					res = try_send(smtp, url.host, url.port, STARTS_WITH(url.prot, "smtps"), url.user, url.pass, url.user, NULL, &smtp->recipients, prepend, (size_t) prependlen, srcfd, 0, datalen, buf, sizeof(buf));
					mproc.drop = 1; /* We MUST drop any messages that are relayed. We wouldn't be relaying them if we could send them ourselves. */
				} else {
					bbs_error("open(%s) failed: %s\n", filename, strerror(errno));
					res = -1;
				}
				if (!res) {
					smtp_reply(smtp, 250, 2.6.0, "Message accepted for relay");
				} else {
					/* XXX If we couldn't relay it immediately, don't queue it, just reject it */
					smtp_reply(smtp, 550, 5.7.0, "Mail relay rejected.");
					if (savedcopy) {
						/* This is the one case where it's convenient to clean up, so we do so.
						 * It's possible, of course, that the message is no longer in "new" but has been moved to "cur".
						 * However, given the common use case is the Sent folder, which most clients don't idle on,
						 * that is still probably unlikely. Delete it if we can, if not, no big deal.
						 *
						 * This also only covers the relaying case. Since messages we sent to another MTA directly
						 * are done in another thread, we don't keep track of saved copies beyond this point,
						 * since we're not going to know immediately if we succeeded or not anyways. So the user will
						 * just have to deal with superflous saved copies, even if the actual sending failed. */
						unlink(newfile);
					}
				}
			}
			if (url.pass) {
				bbs_memzero(url.pass, strlen(url.pass)); /* Destroy the password */
			}
			FREE(mproc.relayroute);
		}
		if (mproc.bounce) {
			const char *msg = "This message has been rejected by the sender";
			if (mproc.bouncemsg) {
				msg = mproc.bouncemsg;
			}
			smtp_reply(smtp, 554, 5.7.1, "%s", msg); /* XXX Best default SMTP code for this? */
			free_if(mproc.bouncemsg);
		}
		if (mproc.drop) {
			/*! \todo BUGBUG For DIRECTION OUT, if we FORWARD, then DROP, we'll just drop here and forward won't happen */
			bbs_debug(5, "Discarding message and ceasing all further processing\n");
			return 0; /* Silently drop message. We MUST do this for RELAYed messages, since we must not allow those to be sent again afterwards. */
		}
	}

	if (smtp->fromlocal || smtp->msa) {
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
			return -1;
		}
		/* If the two addresses are exactly the same, no need to do the same check twice. */
		if (strcmp(smtp->from, smtp->fromheaderaddress) && check_identity(smtp, smtp->fromheaderaddress)) {
			return 0;
		}
		/* We're good: the From header is either the actual username, or an alias that maps to it. */
		free_if(smtp->fromheaderaddress);
	}

	res = expand_and_deliver(smtp, filename, datalen, &responded, &quotaexceeded);
	if (mproc.bounce || responded) {
		return 0; /* If we sent a bounce but didn't drop, don't send a further SMTP reply */
	}

	if (res) {
		/*! \todo BUGBUG FIXME Could be multiple responses */
		if (quotaexceeded) {
			smtp_reply(smtp, 552, 5.2.2, "The mailbox you've tried to reach is full (over quota)");
		} else {
			smtp_reply_nostatus(smtp, 451, "Delivery failed"); /*! \todo add a more specific code */
		}
	} else {
		smtp_reply(smtp, 250, 2.6.0, "Message accepted for delivery");
	}
	return 0;
}

static int msg_to_filename(const char *path, int uid, char *buf, size_t len)
{
	DIR *dir;
	struct dirent *entry;
	int msguid;

	/* Order doesn't matter here, we just want the total number of messages, so fine (and faster) to use opendir instead of scandir */
	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		char *uidstr;
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		/*! \todo refactor parse_uid_from_filename from net_imap and use that here */
		uidstr = strstr(entry->d_name, ",U=");
		if (!uidstr) {
			bbs_error("Invalid maildir filename: %s\n", entry->d_name);
			continue;
		}
		msguid = atoi(uidstr);
		if (msguid == uid) {
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
	if (msg_to_filename(sentdir, atoi(uidstr), msgfile, sizeof(msgfile))) {
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

	if (smtp->inauth) {
		return handle_auth(smtp, s);
	} else if (smtp->indata) {
		int res;

		if (!strcmp(s, ".")) { /* Entire message has now been received */
			smtp->indata = 0;
			if (smtp->datafail) {
				smtp->datafail = 0;
				if (smtp->datalen >= max_message_size) {
					/* Message too large. */
					smtp_reply(smtp, 552, 5.2.3, "Your message exceeded our message size limits");
				} else {
					/* Message not successfully received in totality, so reject it. */
					smtp_reply(smtp, 451, 4.3.0, "Message not received successfully, try again");
				}
				return 0;
			} else if (smtp->hopcount >= MAX_HOPS) {
				smtp_reply(smtp, 554, 5.6.0, "Message exceeded %d hops, this may indicate a mail loop", MAX_HOPS);
				return 0;
			}
			fclose(smtp->fp); /* Have to close and reopen in read mode anyways */
			smtp->fp = NULL;
			bbs_debug(5, "Handling receipt of %lu-byte message\n", smtp->datalen);
			res = do_deliver(smtp, smtp->template, smtp->datalen);
			unlink(smtp->template);
			smtp->datalen = 0;
			return res;
		}

		if (smtp->datafail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		if (smtp->indataheaders) {
			if ((smtp->fromlocal || smtp->msa) && STARTS_WITH(s, "From:")) {
				const char *newfromhdraddr = S_IF(s + 5);
				REPLACE(smtp->fromheaderaddress, newfromhdraddr);
			} else if (STARTS_WITH(s, "Received:")) {
				smtp->hopcount++;
			} else if (!smtp->contenttype && STARTS_WITH(s, "Content-Type:")) {
				const char *tmp = s + STRLEN("Content-Type:");
				if (!strlen_zero(tmp)) {
					ltrim(tmp);
				}
				if (!strlen_zero(tmp)) {
					REPLACE(smtp->contenttype, tmp);
				}
			} else if (!len) {
				smtp->indataheaders = 0; /* CR LF on its own indicates end of headers */
			}
		}

		if (smtp->datalen + len >= max_message_size) {
			smtp->datafail = 1;
			smtp->datalen = max_message_size; /* This isn't really true, this is so we can detect that the message was too large. */
		}

		res = bbs_append_stuffed_line_message(smtp->fp, s, len); /* Should return len + 2, unless it was byte stuffed, in which case it'll be len + 1 */
		if (res < 0) {
			smtp->datafail = 1;
		}
		smtp->datalen += (long unsigned) res;
		return 0;
	}

	command = strsep(&s, " ");
	REQUIRE_ARGS(command);

	/* Slow down spam using tarpit like techniques */
	if (smtp->failures) {
		bbs_debug(4, "%p: Current number of SMTP failures: %d\n", smtp, smtp->failures);
		if (smtp->failures > 3) { /* Do not do this with <= 3 or we'll slow down the test suite (and get test failures) */
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
			smtp->dostarttls = 1;
			smtp->gothelo = 0; /* Client will need to start over. */
		} else {
			smtp_reply(smtp, 454, 5.5.1, "STARTTLS may not be repeated");
		}
	} else if (smtp->msa && !smtp->secure && require_starttls) {
		smtp_reply(smtp, 504, 5.5.4, "Must issue a STARTTLS command first");
	} else if (!strcasecmp(command, "AUTH")) {
		/* https://www.samlogic.net/articles/smtp-commands-reference-auth.htm */
		if (smtp->inauth) { /* Already in authorization */
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
				smtp->inauth = 1;
				if (strlen_zero(s)) {
					smtp_reply(smtp, 334, "", ""); /* Just a 334, nothing else */
				} else {
					return handle_auth(smtp, s);
				}
			} else if (!strcasecmp(command, "LOGIN")) {
				/* https://www.ietf.org/archive/id/draft-murchison-sasl-login-00.txt */
				smtp->inauth = 2;
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

		/* XXX If MAIL FROM is empty (<>), it's implicitly postermaster [at] (HELO domain), according to RFC 5321 4.5.5 */

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
					smtp->sizepreview = sizebytes;
					freebytes = bbs_disk_bytes_free();
					if ((long) smtp->sizepreview > freebytes) {
						bbs_warning("Disk full? Need %lu bytes to receive message, but only %ld available\n", smtp->sizepreview, freebytes);
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
			/* Empty MAIL FROM. This means postmaster, i.e. an email that should not be auto-replied to. */
			/* XXX This does bypass some checks below, but we shouldn't reject such mail. */
			bbs_debug(5, "MAIL FROM is empty\n");
			smtp->fromlocal = 0;
			REPLACE(smtp->from, "");
			smtp_reply(smtp, 250, 2.0.0, "OK");
			return 0;
		}
		tmp = strchr(from, '@');
		REQUIRE_ARGS(tmp); /* Must be user@domain */
		tmp++; /* Skip @ */
		if (mail_domain_is_local(tmp)) {
			/* It's one of our addresses. Authentication is required. */
			if (!bbs_user_is_registered(smtp->node->user)) {
				smtp_reply(smtp, 530, 5.7.0, "Authentication required");
				return 0;
			}
			smtp->fromlocal = 1;
		} else {
			smtp->fromlocal = 0; /* It's not something that belongs to us. No authentication required. */
			if (strlen_zero(smtp->helohost) || (requirefromhelomatch && !smtp_domain_matches(smtp->helohost, tmp))) {
				smtp_reply(smtp, 530, 5.7.0, "HELO/EHLO domain does not match MAIL FROM domain");
				return 0;
			}
		}
		if (stringlist_contains(&blacklist, tmp)) { /* Entire domain is blacklisted */
			smtp_reply(smtp, 554, 5.7.1, "This domain is blacklisted");
			return 0;
		} else if (stringlist_contains(&blacklist, from)) { /* This user is blacklisted */
			smtp_reply(smtp, 554, 5.7.1, "This email address is blacklisted");
			return 0;
		}
		REPLACE(smtp->from, from);
		smtp_reply(smtp, 250, 2.0.0, "OK");
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
			smtp->indata = 1;
			smtp->indataheaders = 1;
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

/*! \todo XXX Relay settings: could either reject external mail or silently accept it but not really send it? "impersonate"? e.g. spamhole - open relay honeypot*/

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
		if (smtp->indata) {
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
		if (smtp->dostarttls) {
			/* RFC3207 STARTTLS */
			/* You might think this would be more complicated, but nope, this is literally all there is to it. */
			bbs_debug(3, "Starting TLS\n");
			smtp->dostarttls = 0;
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
	bbs_config_val_set_true(cfg, "general", "relayout", &accept_relay_out);
	bbs_config_val_set_true(cfg, "general", "minprivrelayin", &minpriv_relay_in);
	bbs_config_val_set_true(cfg, "general", "minprivrelayout", &minpriv_relay_out);
	bbs_config_val_set_true(cfg, "general", "mailqueue", &queue_outgoing);
	bbs_config_val_set_true(cfg, "general", "sendasync", &send_async);
	bbs_config_val_set_true(cfg, "general", "alwaysqueue", &always_queue);
	bbs_config_val_set_uint(cfg, "general", "queueinterval", &queue_interval);
	bbs_config_val_set_true(cfg, "general", "notifyqueue", &notify_queue);
	bbs_config_val_set_uint(cfg, "general", "maxretries", &max_retries);
	bbs_config_val_set_uint(cfg, "general", "maxage", &max_age);
	bbs_config_val_set_uint(cfg, "general", "maxsize", &max_message_size);
	bbs_config_val_set_true(cfg, "general", "requirefromhelomatch", &requirefromhelomatch);
	bbs_config_val_set_true(cfg, "general", "validatespf", &validatespf);
	bbs_config_val_set_true(cfg, "general", "addreceivedmsa", &add_received_msa);
	bbs_config_val_set_true(cfg, "general", "archivelists", &archivelists);
	bbs_config_val_set_true(cfg, "general", "notifyextfirstmsg", &notify_external_firstmsg);

	bbs_config_val_set_true(cfg, "privs", "relayin", &minpriv_relay_in);
	bbs_config_val_set_true(cfg, "privs", "relayout", &minpriv_relay_out);

	if (queue_interval < 60) {
		queue_interval = 60;
	}

	/* SMTP */
	bbs_config_val_set_true(cfg, "smtp", "enabled", &smtp_enabled);
	bbs_config_val_set_port(cfg, "smtp", "port", &smtp_port);
	bbs_config_val_set_true(cfg, "msa", "requirestarttls", &require_starttls_out);

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
	/* Since load_config returns 0 if no config, do this stuff here instead of in load_config: */
	snprintf(queue_dir, sizeof(queue_dir), "%s/mailq", mailbox_maildir(NULL));
	mailbox_maildir_init(queue_dir); /* The queue dir is also like a maildir, it has a new, tmp, and cur */
	snprintf(queue_dir, sizeof(queue_dir), "%s/mailq/new", mailbox_maildir(NULL));
	if (eaccess(queue_dir, R_OK) && mkdir(queue_dir, 0700)) {
		bbs_error("mkdir(%s) failed: %s\n", queue_dir, strerror(errno));
		goto cleanup;
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

	pthread_mutex_init(&queue_lock, NULL);

	if (bbs_pthread_create(&queue_thread, NULL, queue_handler, NULL)) {
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
	bbs_pthread_cancel_kill(queue_thread);
	bbs_pthread_join(queue_thread, NULL);
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
	pthread_mutex_destroy(&queue_lock);
	return 0;
}

BBS_MODULE_INFO_FLAGS_DEPENDENT("RFC5321 SMTP MTA/MSA Servers", MODFLAG_GLOBAL_SYMBOLS, "mod_mail.so");
