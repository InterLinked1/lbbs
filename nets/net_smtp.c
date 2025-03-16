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
 * \note Supports RFC1870 Message Size Declarations
 * \note Supports RFC1893 Enhanced Status Codes
 * \note Supports RFC1985 ETRN (Remote Message Queue Starting)
 * \note Supports RFC3207 STARTTLS
 * \note Supports RFC4954 AUTH
 * \note Supports RFC4468 BURL
 * \note Supports RFC6152 8BITMIME
 * \note Supports RFC6409 Message Submission
 *
 * \todo Not currently supported, but would be nice to support eventually:
 * - RFC 2645 ATRN (Authenticated TURN)
 * - RFC 2852 DELIVERBY
 * - RFC 3030 CHUNKING, BDAT, BINARYMIME
 * - RFC 3461 DSN (the format is mostly implemented, but needs fuller integration)
 * - RFC 3798 Message Disposition Notification
 * - RFC 6531 SMTPUTF8
 *
 * \note Not currently supported, and no current plans to support:
 * - VRFY, EXPN (somewhat intentionally) - could be useful when authenticated, though
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h> /* struct timeval for musl */

#include <dirent.h> /* for msg_to_filename */

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
#include "include/cli.h"
#include "include/callback.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"

#define MAX_RECIPIENTS 100
#define MAX_LOCAL_RECIPIENTS 100
#define MAX_EXTERNAL_RECIPIENTS 10

/* Loop avoidance */
#define MAX_HOPS 100 /* RFC 5321 6.3 */
#define HOP_COUNT_MAX_NORMAL_LEVEL 5 /* If more than 5 loops, tarpit message processing to slow down possible loops */
#define HOP_COUNT_WARN_LEVEL 15 /* Very unlikely non-malformed/routed/looped emails would see more than a dozen hops */

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

static struct stringlist trusted_relays;
static struct stringlist starttls_exempt;

static FILE *smtplogfp = NULL;
static unsigned int smtp_log_level = 5;
static bbs_mutex_t loglock = BBS_MUTEX_INITIALIZER;

/*! \brief Max message size, in bytes */
static unsigned int max_message_size = 300000;

/*! \brief Maximum number of hops, per local policy */
static unsigned int max_hops = MAX_HOPS;

void bbs_smtp_log(int level, struct smtp_session *smtp, const char *fmt, ...)
{
	va_list ap;
	char datestr[20];
	time_t lognow;
	struct tm logdate;
	struct timeval now;

	if (!smtplogfp || (unsigned int) level > smtp_log_level) { /* This is static to this file, so we can't do this in a macro. */
		return;
	}

#pragma GCC diagnostic ignored "-Waggregate-return"
	now = bbs_tvnow();
#pragma GCC diagnostic pop
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);

	bbs_mutex_lock(&loglock);
	if (smtp) {
		fprintf(smtplogfp, "[%s.%03d] %p: ", datestr, (int) now.tv_usec / 1000, smtp);
	} else {
		fprintf(smtplogfp, "[%s.%03d] ", datestr, (int) now.tv_usec / 1000);
	}

	va_start(ap, fmt);
	vfprintf(smtplogfp, fmt, ap);
	va_end(ap);

	bbs_mutex_unlock(&loglock);
	fflush(smtplogfp);
}

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

static char smtp_hostname_buf[256];

const char *smtp_hostname(void)
{
	return smtp_hostname_buf;
}

struct smtp_session {
	struct bbs_node *node;

	/* Transaction data */
	char *from;					/* MAIL FROM address */
	struct stringlist recipients;
	struct stringlist sentrecipients;

	char *helohost;				/* Hostname for HELO/EHLO */
	char *contenttype;			/* Primary Content-Type of message */
	char *messageid;			/* Message-ID header value */
	/* AUTH: Temporary */
	char *authuser;				/* Authentication username */
	char *fromheaderaddress;	/* Address in the From: header, e.g. "John Smith" <jsmith@example.com> */
	char *fromaddr;		/* Normalized from address, e.g. jsmith@example.com */

	const char *datafile;

	struct {
		unsigned long datalen;
		unsigned long sizepreview;	/* Size as advertised in the MAIL FROM size declaration */
		int hopcount;				/* Number of hops so far according to count of Received headers in message. */

		int numrecipients;
		int numlocalrecipients;
		int numexternalrecipients;

		time_t received;			/* Time that message was received */
		unsigned int dostarttls:1;	/* Whether we are initiating STARTTLS */

		unsigned int inauth:2;		/* Whether currently doing AUTH (1 = need PLAIN, 2 = need LOGIN user, 3 = need LOGIN pass) */
		unsigned int dkimsig:1;		/* Message has a DKIM-Signature header */
		unsigned int is8bit:1;		/* 8BITMIME */
		unsigned int relay:1;		/* Message being relayed */
		unsigned int quarantine:1;	/* Quarantine message */
	} tflags; /* Transaction flags */

	/* Not affected by RSET */
	unsigned int failures;		/* Number of protocol violations or failures */
	unsigned int gothelo:1;		/* Got a HELO/EHLO */
	unsigned int ehlo:1;		/* Client supports ESMTP (EHLO) */
	unsigned int fromlocal:1;	/* Sender is local */
	unsigned int msa:1;			/* Whether connection was to the Message Submission Agent port (as opposed to the Mail Transfer Agent port) */
};

static void smtp_reset(struct smtp_session *smtp)
{
	free_if(smtp->authuser);
	free_if(smtp->fromheaderaddress);
	free_if(smtp->fromaddr);
	free_if(smtp->from);
	free_if(smtp->contenttype);
	free_if(smtp->messageid);
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
	smtp_reset(smtp); /* Must be called before stringlist_empty_destroy */
	stringlist_empty_destroy(&smtp->recipients);
	stringlist_empty_destroy(&smtp->sentrecipients);
}

static struct stringlist blacklist;

struct smtp_relay_host {
	const char *source;			/*!< IP address, hostname, or CIDR range */
	struct stringlist domains;	/*!< Domains (including wildcards) for which this host is allowed to relay mail */
	RWLIST_ENTRY(smtp_relay_host) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(authorized_relays, smtp_relay_host);

struct smtp_authorized_identity {
	const char *username;
	struct stringlist identities;
	RWLIST_ENTRY(smtp_authorized_identity) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(authorized_identities, smtp_authorized_identity);

static void add_authorized_relay(const char *source, const char *domains)
{
	struct smtp_relay_host *h;

	if (STARTS_WITH(source, "0.0.0.0")) {
		/* If someone wants to shoot him/herself in the foot, at least provide a warning */
		bbs_notice("This server is configured as an open mail relay and may be abused!\n");
	}

	h = calloc(1, sizeof(*h) + strlen(source) + 1);
	if (ALLOC_FAILURE(h)) {
		return;
	}

	strcpy(h->data, source); /* Safe */
	h->source = h->data;
	stringlist_init(&h->domains);
	stringlist_push_list(&h->domains, domains);

	/* Head insert, so later entries override earlier ones, in case multiple match */
	RWLIST_INSERT_HEAD(&authorized_relays, h, entry);
}

static void relay_free(struct smtp_relay_host *h)
{
	stringlist_empty_destroy(&h->domains);
	free(h);
}

static void add_authorized_identity(const char *username, const char *identities)
{
	struct smtp_authorized_identity *i;

	if (!strcmp(identities, "*")) {
		bbs_notice("This server is configured as an open mail relay for user '%s' and may be abused!\n", username);
	}

	i = calloc(1, sizeof(*i) + strlen(username) + 1);
	if (ALLOC_FAILURE(i)) {
		return;
	}

	strcpy(i->data, username); /* Safe */
	i->username = i->data;
	stringlist_init(&i->identities);
	stringlist_push_list(&i->identities, identities);

	/* Head insert, so later entries override earlier ones, in case multiple match */
	RWLIST_INSERT_HEAD(&authorized_identities, i, entry);
}

/*!
 * \brief Whether this client is an authorized relay
 * \param srcip Source IP of connection
 * \param hostname Hostname for authorization check, or NULL for any hostname(s)
 * \retval 1 if authorized for any/specified hostname, 0 if not
 */
static int __smtp_relay_authorized(const char *srcip, const char *hostname)
{
	struct smtp_relay_host *h;

	RWLIST_RDLOCK(&authorized_relays);
	RWLIST_TRAVERSE(&authorized_relays, h, entry) {
		if (bbs_ip_match_ipv4(srcip, h->source)) {
			/* Just needs to be allowed by one matching entry */
			if (!hostname || stringlist_contains(&h->domains, hostname)) {
				RWLIST_UNLOCK(&authorized_relays);
				return 1;
			}
		}
	}
	RWLIST_UNLOCK(&authorized_relays);
	return 0;
}

static int smtp_relay_authorized_any(const char *srcip)
{
	return __smtp_relay_authorized(srcip, NULL);
}

int smtp_relay_authorized(const char *srcip, const char *hostname)
{
	bbs_assert_exists(hostname);
	return __smtp_relay_authorized(srcip, hostname);
}

/*!
 * \brief Whether this user is authorized to send email as a particular identity
 * \param username User's username
 * \param identity Email address using which the user is attempting to submit mail
 * \retval 1 if authorized, 0 if not
 */
static int smtp_user_authorized_for_identity(const char *username, const char *identity)
{
	const char *domain;
	struct smtp_authorized_identity *i;

	RWLIST_RDLOCK(&authorized_identities);
	RWLIST_TRAVERSE(&authorized_identities, i, entry) {
		if (strcasecmp(username, i->username)) {
			continue;
		}
		/* XXX In theory, we could do just a single traversal of &i->identities,
		 * and just do each of the 3 checks for each item.
		 * In the meantime, these checks are ordered from common case to least likely. */
		/* First, check for explicit match. */
		if (stringlist_case_contains(&i->identities, identity)) {
			RWLIST_UNLOCK(&authorized_identities);
			return 1;
		}
		/* Next, check for domain match. */
		domain = strchr(identity, '@');
		if (domain++ && *domain) {
			char searchstr[256];
			snprintf(searchstr, sizeof(searchstr), "*@%s", domain);
			if (stringlist_case_contains(&i->identities, searchstr)) {
				RWLIST_UNLOCK(&authorized_identities);
				return 1;
			}
		}
		/* Last check, is the user blank authorized to relay mail for any address? */
		if (stringlist_contains(&i->identities, "*")) {
			RWLIST_UNLOCK(&authorized_identities);
			return 1;
		}
	}
	RWLIST_UNLOCK(&authorized_identities);
	return 0;
}

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

/* RFC 5321 4.1.1 - RSET, DATA, QUIT do not permit parameters */
#define REQUIRE_EMPTY(s) \
	if (!strlen_zero(s)) { \
		smtp_reply(smtp, 501, 5.5.2, "Syntax Error"); \
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

/*!
 * \brief Slow down suspicious connections using tarpitting techniques
 * \param smtp
 * \param code If nonzero, a code to include in intermittent nonfinal responses. 0 to sleep only.
 * \retval -1 to disconnect, 0 to continue
 */
static int smtp_tarpit(struct smtp_session *smtp, int code, const char *message)
{
	/* Tarpitting is the practice of slowing down suspicious (likely spam)
	 * senders, often in response to protocol violations, frustrating their progress
	 * and simultaneously preoccupying them for a long time, preventing them
	 * from spamming other servers.
	 * This deters many spam attempts from incompliant SMTP clients,
	 * but should have no effect on any compliant MTAs. */

	if (!smtp->failures) {
		return 0;
	}
	bbs_debug(4, "%p: Current number of SMTP failures: %d\n", smtp, smtp->failures);
	if (smtp->failures <= 4) {
		/* Do not do this with <= 4 or we'll slow down the test suite when it's testing bad behavior (and get test failures) */
		if (smtp->failures <= 2 || bbs_is_loopback_ipv4(smtp->node->ip)) {
			return 0;
		}
		/* Exempt authorized relays, since there is a lot of broken and non-compliant SMTP code out there,
		 * and tarpitting will almost certainly break them. */
		if (smtp->gothelo) {
			if (smtp_relay_authorized(smtp->node->ip, smtp->helohost)) {
				return 0;
			}
		} else {
			if (smtp_relay_authorized_any(smtp->node->ip)) {
				return 0;
			}
		}
	}

	/* We don't want to wait too long inbetween or, in practice, some clients will disconnect and reconnect, e.g. sendmail-msp */
	if (code) {
		int i;
		/* Start with 5 second delay, and it only goes up from there.
		 * Maximum of 4 minutes, 55 seconds per tarpit, since 5 minutes is the timeout for many commands. */
		int max = MIN((int) smtp->failures - 3, 59);
		for (i = 0; i < max; i++) {
			if (bbs_node_safe_sleep(smtp->node, SEC_MS(5))) { /* 5 seconds each one */
				return -1;
			}
			message = S_OR(message, "Processing...");
			smtp_reply0_nostatus(smtp, code, "%s", message);
		}
	} else { /* All we can do here is sleep, no longer than 15 seconds. */
		/* Exponential delay as # of failures increases: */
		int sleepms = MIN(SEC_MS(1) * (1 << smtp->failures), SEC_MS(15));
		if (sleepms <= 0) {
			/* If the bit shift results in a negative, fix it */
			sleepms = SEC_MS(15);
		}
		bbs_debug(3, "Tarpitting node %d for %d ms\n", smtp->node->id, sleepms);
		if (bbs_node_safe_sleep(smtp->node, sleepms)) {
			return -1;
		}
	}
	return 0;
}

/*! \brief Forward-confirmed reverse DNS (FCrDNS) check */
static int fcrdns_check(struct smtp_session *smtp)
{
	char hostname[256];

	/* This is a relatively lenient check that most any legitimate SMTP server should pass.
	 * The hostname provided by the MTA must resolve to the IP address of the connection,
	 * as suggested in RFC 1912 2.1.
	 * If this fails, we won't reject the connection outright, but we'll heavily penalize it. */

	/* This check succeeds if:
	 * 1) The sending IP has a valid PTR record which resolves to a valid hostname
	 * 2) The hostname has an A record matching the sending IP address
	 *
	 * Importantly, the hostname mentioned above may not and does not have to be
	 * related to the SMTP transaction, i.e. the HELO hostname. This makes sense,
	 * as a single SMTP server may be hosting multiple domains, and the above procedure
	 * only allows for the PTR record to resolve to a single domain.
	 *
	 * Thanks to this, we can do this check immediately, before even the HELO,
	 * and we can do it while we're waiting to see if the client will speak out of turn.
	 */

	if (bbs_get_hostname(smtp->node->ip, hostname, sizeof(hostname))) { /* Get reverse PTR record for client's IP */
		bbs_warning("Unable to look up reverse DNS record for %s\n", smtp->node->ip);
		smtp->failures += 4; /* Heavy penalty */
	} else if (!bbs_hostname_has_ip(hostname, smtp->node->ip)) { /* Ensure that there's a match, with at least one A record */
		bbs_warning("FCrDNS check failed: %s != %s\n", hostname, smtp->node->ip);
		smtp->failures += 5;
	}
	return 0;
}

static int handle_connect(struct smtp_session *smtp)
{
	if (!smtp->msa) {
		/* We're allowed to send multiple banner lines, just with any other SMTP response.
		 * This is something that postscreen does for postfix (PREGREET check).
		 * After sending a line, if we get any input from the client, that is invalid.
		 * Clients MUST wait until the server banner finishes before sending anything.
		 * Additionally, the multiline response may possibly confuse spammers, but shouldn't
		 * confuse any compliant SMTP client.
		 *
		 * Unfortunately, there is a lot of broken SMTP client code out there,
		 * and this can break some "trusted" enterprise software with garbage SMTP implementations
		 * (e.g. HP Management Agents - Event Notifier), so exempt any clients that are authorized
		 * to relay outgoing messages for any domains from getting thrown this curveball for compatibility.
		 */
		if (!smtp_relay_authorized_any(smtp->node->ip)) {
			smtp_reply0_nostatus(smtp, 220, "%s ESMTP Service Ready", bbs_hostname());
		}

		/*! \todo This would be a good place to check blacklist IPs (currently we only allow blacklisting hostnames).
		 * This would allow us to avoid a DNS request for known bad sender IPs. */

		if (fcrdns_check(smtp)) {
			/* This isn't if the FCrDNS check fails, it's if we couldn't do the check at all.
			 * In this case, things are really broken, and we should just abort the connection. */
			/* XXX We changed the response code from nonfinal 220 to final 421, not sure that's actually valid... */
			smtp_reply_nostatus(smtp, 421, "Service unavailable, closing transmission channel");
			return -1;
		}

		if (smtp_tarpit(smtp, 220, "Waiting for service to initialize...")) {
			return -1;
		}

		/* This works even with TLS, because of the TLS I/O thread, it's either socket or pipe activity.
		 * Then again, that doesn't matter because for MTAs, TLS isn't yet set up at this point in the connection,
		 * so the SMTP file descriptor refers to the actual node socket, not a pipe. */
		if (bbs_poll(smtp->node->rfd, 100)) { /* Guarantees up to a minimum 100ms sleep */
			/* We don't know what was received (or even how many bytes) since we haven't called read() yet, but we could peek: */
			size_t bytes = 0;
			if (ioctl(smtp->node->rfd, FIONREAD, &bytes)) {
				bbs_error("ioctl failed: %s\n", strerror(errno));
				return -1;
			}
			if (!bytes) {
				/* Client disconnected, same as read returning 0. */
				bbs_debug(3, "Client appears to have disconnected\n");
				return -1;
			}
			bbs_warning("Pregreet: %lu byte%s received before banner finished\n", bytes, ESS(bytes));
			smtp->failures += 3;
			if (smtp_tarpit(smtp, 220, "Waiting for service to initialize...")) {
				return -1;
			}
		}
	}
	smtp_reply_nostatus(smtp, 220, "%s ESMTP Service Ready", bbs_hostname());
	return 0;
}

static int smtp_ip_mismatch(const char *actual, const char *hostname)
{
	char buf[256];

	if (bbs_is_loopback_ipv4(actual)) {
		return 0; /* Ignore for localhost */
	}

	/* This should be either a domain name or address literal (enclosed in []).
	 * If it's just a raw IP address, that is not valid.
	 * IPv6 literals as described in RFC 5321 4.1.3 are not supported. */
	if (bbs_hostname_is_ipv4(hostname)) {
		if (!strcmp(actual, hostname)) {
			bbs_warning("SMTP IP address '%s' is in non-canonical format\n", hostname); /* Should be surrounded by [] */
			return 0;
		}
		return -1;
	} else if (*hostname == '[' && *(hostname + 1)) {
		/* Domain literal */
		bbs_strncpy_until(buf, hostname + 1, sizeof(buf), ']');
		hostname = buf;
	}
	if (!bbs_ip_match_ipv4(actual, hostname)) {
		return -1;
	}
	return 0;
}

static int is_trusted_relay(const char *ip)
{
	const char *s;
	struct stringitem *i = NULL;

	while ((s = stringlist_next(&trusted_relays, &i))) {
		if (bbs_ip_match_ipv4(ip, s)) {
			return 1;
		}
	}
	return 0;
}

static int exempt_from_starttls(struct smtp_session *smtp)
{
	const char *s;
	struct stringitem *i = NULL;

	while ((s = stringlist_next(&starttls_exempt, &i))) {
		if (bbs_ip_match_ipv4(smtp->node->ip, s)) {
			return 1;
		}
	}
	return 0;
}

static int is_benign_ip_mismatch(const char *helohost, const char *srcip)
{
	/* Not all mismatches are malicious.
	 * This covers the case of a private IP tunnel between two SMTP servers.
	 * The egress IP may differ from the actual source route IP of the connecting server.
	 * However, if this is the case, then there is probably an entry for the domain
	 * by BOTH IP addresses in [authorized_relays]. */

	if (bbs_hostname_is_ipv4(helohost)) {
		/* This workaround only works if the HELO hostname is a domain,
		 * rather than an IP address. If it's a hostname, we can check
		 * if the source IP is authorized to send mail as that domain.
		 * If we just have an IP address, we don't have enough information. */
		return 0;
	}

	return smtp_relay_authorized(srcip, helohost) || is_trusted_relay(srcip);
}

static int handle_helo(struct smtp_session *smtp, char *s, int ehlo)
{
	if (strlen_zero(s)) {
		/* Submissions won't contain any data for HELO/EHLO, only relayers will. */
		if (!smtp->msa) {
			/* RFC 5321 4.1.1.1 */
			smtp_reply(smtp, 501, 5.5.4, "Empty HELO/EHLO argument not allowed, closing connection.");
			return -1;
		}
	} else {
		REPLACE(smtp->helohost, s);
		/* Note that enforcing that helohost matches sending IP is noncompliant with RFC 2821:
		 * "An SMTP server MAY verify that the domain name parameter in the EHLO command
		 * actually corresponds to the IP address of the client.
		 * However, the server MUST NOT refuse to accept a message for this reason if the verification fails:
		 * the information about verification failure is for logging and tracing only.
		 *
		 * However, RFC 7208 is more favorable to this practice, and indeed RECOMMENDS that
		 * this hostname be used for SPF verification.
		 * Because this is still useful information, we don't block any clients if the HELO hostname
		 * does not match the connection IP, but if it doesn't, we do penalize the connection.
		 */
		if (smtp_relay_authorized(smtp->node->ip, smtp->helohost)) {
			/* The HELO host isn't used for determining if it's allowed to relay,
			 * but in case the HELO host is something else, we shouldn't penalize it either. */
			bbs_debug(2, "%s is explicitly authorized to relay mail from %s\n", smtp->node->ip, smtp->helohost);
		} else if (!smtp->msa && smtp_ip_mismatch(smtp->node->ip, smtp->helohost) && !is_benign_ip_mismatch(smtp->helohost, smtp->node->ip)) {
			/* Message submission is exempt from these checks, the HELO hostname is not useful anyways */
			bbs_warning("HELO/EHLO hostname '%s' does not resolve to client IP %s\n", smtp->helohost, smtp->node->ip);
			/* This is suspicious. It is not invalid, but it very well might be.
			 * I'm aware that this doesn't support IPv6. IPv4 is pretty important for email,
			 * if you're sending email using an IPv6 address, then that'll be penalized as well. */
			smtp->failures += 2;
		}
	}

	if (smtp->gothelo) {
		/* RFC 5321 4.1.4 says a duplicate EHLO is treated as a RSET.
		 * Don't penalize clients that do this either, since it's useful for delivering multiple messages at a time. */
		smtp_reset(smtp);
		smtp_reply(smtp, 250, 2.1.5, "Flushed");
		return 0;
	}

	SET_BITFIELD(smtp->gothelo, 1);
	SET_BITFIELD(smtp->ehlo, ehlo);

	if (ehlo) {
		/* We dereference smtp->node twice here (smtp->node->ip)
		 * and the smtp_reply macros eventually do a check for smtp->node being NULL.
		 * Because of that, gcc thinks that smtp->node here could be a NULL dereference.
		 * However, that check is only for SMTP replies (e.g. for injection),
		 * any SMTP session in this function will have a node. This can be safely ignored. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnull-dereference"
		smtp_reply0_nostatus(smtp, 250, "%s at your service [%s]", bbs_hostname(), smtp->node->ip);
		/* The RFC says that login should only be allowed on secure connections,
		 * but if we don't allow login on plaintext connections, then they're functionally useless. */
		if (smtp->node->secure || !require_starttls || exempt_from_starttls(smtp)) {
			smtp_reply0_nostatus(smtp, 250, "AUTH LOGIN PLAIN"); /* RFC-complaint way */
			smtp_reply0_nostatus(smtp, 250, "AUTH=LOGIN PLAIN"); /* For non-compliant user agents, e.g. Outlook 2003 and older */
		}
		smtp_reply0_nostatus(smtp, 250, "PIPELINING");
		smtp_reply0_nostatus(smtp, 250, "SIZE %u", max_message_size); /* RFC 1870 */
		smtp_reply0_nostatus(smtp, 250, "8BITMIME"); /* RFC 6152 */
		smtp_reply0_nostatus(smtp, 250, "ETRN"); /* RFC 1985 */
		if (!smtp->node->secure && ssl_available() && !exempt_from_starttls(smtp)) {
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
#pragma GCC diagnostic pop
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
		bbs_strterm((char*) user, '@'); /* Strip domain */
		res = bbs_authenticate(smtp->node, (char*) user, (char*) pass);
		bbs_memzero((unsigned char*) pass, strlen((char*) pass)); /* Destroy the password from memory before we free it */
		free(user);
		free(pass);
		goto logindone;
	} else {
		__builtin_unreachable();
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

BBS_SINGULAR_CALLBACK_DECLARE(smtp_queue_processor, int, struct smtp_session *smtp, const char *cmd, const char *args);

int __smtp_register_queue_processor(int (*queue_processor)(struct smtp_session *smtp, const char *cmd, const char *args), void *mod)
{
	return bbs_singular_callback_register(&smtp_queue_processor, queue_processor, mod);
}

int smtp_unregister_queue_processor(int (*queue_processor)(struct smtp_session *smtp, const char *cmd, const char *args))
{
	return bbs_singular_callback_unregister(&smtp_queue_processor, queue_processor);
}

/*! \brief Parse parameter data in MAIL FROM */
static int parse_mail_parameters(struct smtp_session *smtp, char *s)
{
	char *d;

	while ((d = strsep(&s, " "))) {
		char *ext = strsep(&d, "=");
		if (strlen_zero(ext)) {
			bbs_warning("No extension name?\n");
			continue;
		} else if (strlen_zero(d)) {
			bbs_warning("Empty extension data value\n");
			continue;
		} else if (!strcasecmp(ext, "SIZE")) {
			long freebytes;
			unsigned int sizebytes;
			/* RFC 1870 Message Size Declaration */
			if (smtp->tflags.sizepreview) {
				bbs_warning("Duplicate SIZE declaration (%lu)\n", smtp->tflags.sizepreview);
				smtp->failures++;
				continue;
			}
			sizebytes = (unsigned int) atoi(d);
			if (sizebytes >= max_message_size) {
				smtp_reply(smtp, 552, 5.3.4, "Message too large");
				return -1;
			}
			smtp->tflags.sizepreview = sizebytes;
			freebytes = bbs_disk_bytes_free();
			if ((long) smtp->tflags.sizepreview > freebytes) {
				bbs_warning("Disk full? Need %lu bytes to receive message, but only %ld available\n", smtp->tflags.sizepreview, freebytes);
				smtp_reply(smtp, 452, 4.3.1, "Insufficient system storage");
				return -1;
			}
		} else if (!strcasecmp(ext, "AUTH")) {
			/* RFC 4954 Section 5
			 * This allows an SMTP user that is authorized to send mail on behalf of multiple identities
			 * to specify as which identity this message is being sent. If we actually supported this,
			 * we'd want to check to ensure that the user is authenticated already.
			 * Currently, we don't really support this so just ignore. This is valid:
			 * The RFC allows such implementations to parse and discard;
			 * we don't pass empty AUTH=<> on since we don't authenticate to other servers for submissions,
			 * and we don't trust any other MTAs, so that's fine. */
			bbs_warning("Ignoring AUTH identity: %s\n", d);
		} else if (!strcasecmp(ext, "BODY")) {
			/* RFC 6152 8BITMIME
			 * In my experience, most mail that requires 8BITMIME is spam.
			 * But it's probably not our place to reject such mail. */
			if (!strcasecmp(d, "8BITMIME")) {
				bbs_debug(3, "Sender indicated this is an 8-bit message... increasing spam score\n");
				smtp->tflags.is8bit = 1;
				smtp->failures++; /* Penalize 8-bit messages. These are probably spam. */
			} else if (!strcasecmp(d, "7BIT")) {
				smtp->tflags.is8bit = 0;
			} else {
				bbs_warning("Invalid BODY type: %s\n", d);
				smtp->failures++;
			}
		} else {
			bbs_warning("Unknown SMTP MAIL parameter: %s\n", ext);
			smtp_reply(smtp, 455, 4.5.1, "Unsupported parameter");
			return -1;
		}
	}

	return 0;
}

static int handle_etrn(struct smtp_session *smtp, char *s)
{
	int res;
	char *args;

	if (smtp->from) {
		/* RFC 1985 5: Illegal during transactions */
		smtp_reply(smtp, 502, 5.5.1, "Unsupported command");
		return 0;
	}

	args = strsep(&s, " ");
	if (strlen_zero(args)) {
		smtp_reply(smtp, 501, 5.5.1, "Missing required parameter for ETRN");
		return 0;
	}

	if (bbs_singular_callback_execute_pre(&smtp_queue_processor)) {
		/* No queue processor registered, so ETRN not supported */
		smtp_reply(smtp, 501, 5.5.4, "Unrecognized parameter");
		return 0;
	}
	res = BBS_SINGULAR_CALLBACK_EXECUTE(smtp_queue_processor)(smtp, "ETRN", args);
	bbs_singular_callback_execute_post(&smtp_queue_processor);

	switch (res) {
		case 250:
			smtp_reply_nostatus(smtp, 250, "OK, queue processed");
			break;
		case 251:
			smtp_reply_nostatus(smtp, 251, "OK, no messages waiting");
			break;
		case 252:
			smtp_reply_nostatus(smtp, 252, "OK, pending messages queued");
			break;
		/* 253 allows us to be specific about how many messages,
		 * but mod_smtp_delivery_external doesn't pass that up to us,
		 * so this is unused. */
		case 458:
			smtp_reply_nostatus(smtp, 458, "Unable to queue messages");
			break;
		case 459:
			smtp_reply_nostatus(smtp, 459, "Requested queuing not allowed");
			break;
		case 500:
			smtp_reply_nostatus(smtp, 500, "Syntax Error");
			break;
		case 501:
			smtp_reply_nostatus(smtp, 501, "Syntax Error in Parameters");
			break;
		default:
			bbs_error("Unexpected SMTP response code %d\n", res);
			smtp_reply_nostatus(smtp, 500, "Syntax Error");
	}

	return 0;
}

/*! \brief Parse MAIL FROM */
static int handle_mail(struct smtp_session *smtp, char *s)
{
	char *tmp, *from;
	REQUIRE_HELO();
	REQUIRE_ARGS(s);
	if (!STARTS_WITH(s, "FROM:")) {
		smtp_reply(smtp, 501, 5.5.4, "Unrecognized parameter");
		return 0;
	}
	s += STRLEN("FROM:");

	/* If the connection was to the MSA port, then we only accept outgoing mail from our users, not incoming mail. */
	if (smtp->msa && !bbs_user_is_registered(smtp->node->user)) {
		smtp_reply(smtp, 530, 5.7.0, "Authentication required");
		return 0;
	}

	/* fromlocal is slightly different from msa.
	 * fromlocal indicates the message is from an MSA or originating locally (e.g. bounce messages).
	 * fromlocal is a superset of MSA */
	smtp->fromlocal = smtp->msa;

	REQUIRE_ARGS(s);
	if (*s != '<') {
		/* No space is permitted between MAIL FROM: and the opening < for the recipient. */
		bbs_warning("Malformed MAIL FROM (contains extraneous space): %s\n", s);
		smtp->failures++;
		ltrim(s);
		REQUIRE_ARGS(s);
	}

	from = strsep(&s, " ");
	if (!strlen_zero(s) && parse_mail_parameters(smtp, s)) {
		return 0; /* Already returned an error code */
	}
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
		if (!smtp->fromheaderaddress) {
			/* Don't have a From address yet, so this is our most specific sender identity */
			REPLACE(smtp->fromaddr, smtp->from);
		}
		smtp_reply(smtp, 250, 2.0.0, "OK");
		return 0;
	}
	tmp = strchr(from, '@');
	REQUIRE_ARGS(tmp); /* Must be user@domain */
	tmp++; /* Skip @ */

	if (smtp_relay_authorized(smtp->node->ip, tmp)) {
		bbs_debug(2, "%s is explicitly authorized to relay mail from %s\n", smtp->node->ip, tmp);
		smtp->tflags.relay = 1;
	} else if (!smtp->msa) {
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
	}

	REPLACE(smtp->from, from);
	if (!smtp->fromheaderaddress) {
		/* Don't have a From address yet, so this is our most specific sender identity */
		REPLACE(smtp->fromaddr, smtp->from);
	}
	smtp_reply(smtp, 250, 2.1.0, "OK");
	return 0;
}

static int add_recipient(struct smtp_session *smtp, int local, const char *s)
{
	const char *recipient = s;

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

	if (strncasecmp(s, "TO:", 3)) {
		smtp_reply(smtp, 501, 5.5.4, "Unrecognized parameter");
		return 0;
	}
	s += 3;
	REQUIRE_ARGS(s);

	if (*s != '<') {
		/* Space not permitted between : and < */
		bbs_warning("Extraneous space in RCPT TO: %s\n", s);
		smtp->failures++;
		ltrim(s);
	}

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
		smtp->failures++;
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
		smtp->failures++;
		return 0;
	}

	local = mail_domain_is_local(domain);

	memset(&error, 0, sizeof(error));
	/* Check if it's a real mailbox (or an alias that maps to one), a mailing list, etc. */
	RWLIST_RDLOCK(&handlers);
	RWLIST_TRAVERSE(&handlers, h, entry) {
		bbs_module_ref(h->mod, 1);
		res = h->agent->exists(smtp, &error, s, user, domain, smtp->fromlocal, local);
		bbs_module_unref(h->mod, 1);
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
	/* Don't unlock handlers until here because error is filled in with memory from handler modules.
	 * Therefore these modules cannot unregister until we're done with that. */
	RWLIST_UNLOCK(&handlers);

	if (smtp->tflags.numlocalrecipients >= MAX_LOCAL_RECIPIENTS || smtp->tflags.numexternalrecipients >= MAX_EXTERNAL_RECIPIENTS || smtp->tflags.numrecipients >= MAX_RECIPIENTS) {
		smtp_reply(smtp, 452, 4.5.3, "Your message has too many recipients");
		return 0;
	}

	/* Actually add the recipient to the recipient list. */
	res = add_recipient(smtp, local, s);
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
	__builtin_unreachable();
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

const char *smtp_sender_ip(struct smtp_session *smtp)
{
	return smtp->node ? smtp->node->ip : "127.0.0.1";
}

const char *smtp_protname(struct smtp_session *smtp)
{
	/* RFC 2822, RFC 3848, RFC 2033 */
	if (smtp->ehlo) {
		if (smtp->node->secure) {
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

struct stringlist *smtp_recipients(struct smtp_session *smtp)
{
	return &smtp->recipients;
}

const char *smtp_from(struct smtp_session *smtp)
{
	return smtp->from;
}

const char *smtp_from_header(struct smtp_session *smtp)
{
	return smtp->fromheaderaddress;
}

const char *smtp_mail_from_domain(struct smtp_session *smtp)
{
	return bbs_strcnext(smtp->from, '@');
}

const char *smtp_from_domain(struct smtp_session *smtp)
{
	if (!smtp->from) {
		return NULL;
	}
	if (smtp->fromaddr) {
		/* Use From header email address if available */
		return bbs_strcnext(smtp->fromaddr, '@');
	}
	/* Fall back to MAIL FROM address if not */
	return smtp_mail_from_domain(smtp);
}

int smtp_is_exempt_relay(struct smtp_session *smtp)
{
	return smtp->tflags.relay;
}

int smtp_should_validate_spf(struct smtp_session *smtp)
{
	return validatespf && !smtp->fromlocal && !smtp->tflags.relay && (!smtp->node || !is_trusted_relay(smtp->node->ip));
}

int smtp_should_validate_dkim(struct smtp_session *smtp)
{
	return smtp->tflags.dkimsig && !smtp->tflags.relay && (!smtp->node || !is_trusted_relay(smtp->node->ip));
}

int smtp_should_verify_dmarc(struct smtp_session *smtp)
{
	return !is_trusted_relay(smtp->node->ip);
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

const char *smtp_messageid(struct smtp_session *smtp)
{
	return smtp->messageid;
}

time_t smtp_received_time(struct smtp_session *smtp)
{
	return smtp->tflags.received;
}

unsigned int smtp_failure_count(struct smtp_session *smtp)
{
	return smtp->failures;
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

int __smtp_filter_write(struct smtp_filter_data *f, const char *file, int line, const char *func, const char *fmt, ...)
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

	__bbs_log(LOG_DEBUG, 6, file, line, func, "Prepending(%d): %s", len, buf); /* Already ends in CR LF */
	if (bbs_str_contains_bare_lf(buf)) {
		bbs_warning("Appended data that contains bare LFs! Message is not RFC-compliant!\n");
	}
	bbs_write(f->outputfd, buf, (size_t) len);

	free(buf);
	return len;
}

int smtp_filter_add_header(struct smtp_filter_data *f, const char *name, const char *value)
{
	if (strchr(name, ':')) {
		bbs_warning("Invalid header name: %s\n", name);
	}
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
	int total = 0, run = 0;
	enum smtp_filter_scope scope = fdata->recipient ? SMTP_SCOPE_INDIVIDUAL : SMTP_SCOPE_COMBINED;

	if (!fdata->smtp) {
		bbs_error("Cannot run filters without an SMTP session\n");
		return;
	}

	fdata->dir = dir;
	fdata->from = fdata->smtp->from;
	fdata->helohost = fdata->smtp->helohost;
	fdata->node = fdata->smtp->node;

	bbs_debug(4, "Running %s (%s) filters\n", scope == SMTP_SCOPE_COMBINED ? "COMBINED" : "INDIVIDUAL", smtp_filter_direction_name(dir));

	RWLIST_RDLOCK(&filters);
	RWLIST_TRAVERSE(&filters, f, entry) {
		int res = 0;
		total++;
		if (!(f->direction & fdata->dir)) {
#ifdef DEBUG_FILTERS
			bbs_debug(5, "Ignoring %s SMTP filter %s %p (wrong direction)...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
#endif
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
#ifdef DEBUG_FILTERS
				bbs_debug(5, "Ignoring %s SMTP filter %s %p (wrong scope)...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
#endif
				continue;
			}
		} else {
			if (fdata->recipient) {
#ifdef DEBUG_FILTERS
				bbs_debug(5, "Ignoring %s SMTP filter %s %p (wrong scope)...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
#endif
				continue;
			}
		}
		if (fdata->dir == SMTP_DIRECTION_IN && !fdata->node) {
			/* Something like a Delivery Status Notification or other injected mail without a node... filters don't apply anyways.
			 * Unless, it's simply adding the Received header, in which case, still do it,
			 * for things like mailing lists which involve using smtp_inject. */
			if (f->priority != 0) {
#ifdef DEBUG_FILTERS
				bbs_debug(5, "Ignoring %s SMTP filter %s %p (no node)...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
#endif
				continue;
			}
		}

		/* Filter applicable to scope, execute it */

		/*! \note SMTP filters will receive the message by reading it from f->inputfd,
		 * and then use smtp_filter_add_header or smtp_filter_write
		 * in order to prepend to the message headers (which is f->outputfile)
		 *
		 * The complication is that if we reuse the same output file for all filter callbacks,
		 * then headers added earlier on are not available to successive filters.
		 * For example, SpamAssassin needs SPF, DMARC, etc. headers,
		 * and the priorities of these filters ensure they run before SpamAssassin does.
		 * But if the headers they add are only in the output file, then SpamAssassin
		 * won't read them, just by reading from f->inputfd.
		 *
		 * While we could close the file and create a new combined file after each iteration,
		 * that would be somewhat inefficient, given that currently the only filter that requires
		 * this sort of thing is the SpamAssassin one. Therefore, that module has logic
		 * to also process what's been appended to the output file as well as the original input file. */

		bbs_debug(4, "Executing %s SMTP filter %s %p...\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
		bbs_module_ref(f->mod, 2);
		if (f->type == SMTP_FILTER_PREPEND) {
			bbs_assert_exists(f->provider);
			res = f->provider->on_body(fdata);
			run++;
		} else {
			bbs_error("Filter type %d not supported\n", f->type);
		}
		bbs_module_unref(f->mod, 2);
		lseek(fdata->inputfd, 0, SEEK_SET); /* Rewind to beginning of file */
		if (res == 1) {
			bbs_debug(5, "Aborting filter execution\n");
			break;
		} else if (res < 0) {
			bbs_warning("%s SMTP filter %s %p failed to execute\n", smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), f);
		}
	}
	RWLIST_UNLOCK(&filters);

	bbs_debug(6, "Ran %d/%d filter%s (skipped %d)\n", run, total, ESS(total), total - run);

	free_if(fdata->body);
	free_if(fdata->spf);
	free_if(fdata->dkim);
	free_if(fdata->arc);
	free_if(fdata->dmarc);
	free_if(fdata->authresults);
}

static int cli_filters(struct bbs_cli_args *a)
{
	struct smtp_filter *f;
	bbs_dprintf(a->fdout, "%-14s %-20s %-8s %s\n", "ID", "Direction", "Type", "Module");
	RWLIST_RDLOCK(&filters);
	RWLIST_TRAVERSE(&filters, f, entry) {
		bbs_dprintf(a->fdout, "%-14p %-20s %-8s %s\n", f, smtp_filter_direction_name(f->direction), smtp_filter_type_name(f->type), bbs_module_name(f->mod));
	}
	RWLIST_UNLOCK(&filters);
	return 0;
}

void smtp_mproc_init(struct smtp_session *smtp, struct smtp_msg_process *mproc)
{
	memset(mproc, 0, sizeof(struct smtp_msg_process));
	mproc->smtp = smtp;
	mproc->datafile = smtp->datafile;
	mproc->node = smtp->node;
	mproc->fd = mproc->node ? smtp->node->wfd : -1;
	mproc->from = smtp->from;
	mproc->forward = &smtp->recipients; /* Tack on forwarding targets to the recipients list */
}

struct smtp_processor {
	const struct smtp_message_processor *processor;
	void *mod;
	RWLIST_ENTRY(smtp_processor) entry;
};

static RWLIST_HEAD_STATIC(processors, smtp_processor);

int __smtp_register_processor(struct smtp_message_processor *processor, void *mod)
{
	struct smtp_processor *proc;

	if (!processor->callback) {
		bbs_error("Processor has no callback?\n");
		return -1;
	}

	proc = calloc(1, sizeof(*proc));
	if (ALLOC_FAILURE(proc)) {
		return -1;
	}

	proc->processor = processor;
	proc->mod = mod;

	RWLIST_WRLOCK(&processors);
	RWLIST_INSERT_TAIL(&processors, proc, entry);
	RWLIST_UNLOCK(&processors);
	return 0;
}

int smtp_unregister_processor(struct smtp_message_processor *processor)
{
	struct smtp_processor *proc;

	proc = RWLIST_WRLOCK_REMOVE_BY_FIELD(&processors, processor, processor, entry);
	if (!proc) {
		bbs_error("Couldn't remove processor %p\n", processor);
		return -1;
	}
	free(proc);
	return 0;
}

/*! \brief Single pass of callbacks */
static int __run_callbacks(struct smtp_msg_process *mproc, enum msg_process_iteration iteration, const char *file, int line, const char *func)
{
	int res;
	struct smtp_processor *proc;

	mproc->iteration = iteration;

	__bbs_log(LOG_DEBUG, 3, file, line, func, "Running SMTP callbacks for %s scope, %s (%s) direction, %s pass\n",
		mproc->scope == SMTP_SCOPE_INDIVIDUAL ? "INDIVIDUAL" : "COMBINED",
		mproc->direction == SMTP_MSG_DIRECTION_IN ? "IN" : "OUT",
		mproc->dir == SMTP_DIRECTION_IN ? "IN" : mproc->dir == SMTP_DIRECTION_SUBMIT ? "SUBMIT" : "OUT",
		mproc->iteration == FILTER_BEFORE_MAILBOX ? "pre-mailbox" : mproc->iteration == FILTER_AFTER_MAILBOX ? "post-mailbox" : "mailbox");

	RWLIST_TRAVERSE(&processors, proc, entry) {
		const struct smtp_message_processor *processor = proc->processor;
		/* If it doesn't match what the processor wants, skip it */
		if (!(processor->dir & mproc->dir)) {
			continue;
		} else if (!(processor->scope & mproc->scope)) {
			continue;
		} else if (!(processor->iteration & mproc->iteration)) {
			continue;
		}
		/* No need to ref the module unless we are actually going to execute.
		 * The module can't unregister the processor without WRLOCK'ing the list,
		 * and we have it locked for this traversal. */
		bbs_module_ref(proc->mod, 3);
		res = processor->callback(mproc); /* callback is guaranteed to be non-NULL here */
		bbs_module_unref(proc->mod, 3);
		if (res) {
			__bbs_log(LOG_DEBUG, 4, file, line, func, "Message processor returned %d\n", res);
			return res; /* Stop processing immediately if a processor returns nonzero */
		}
	}
	return 0;
}

int __smtp_run_callbacks(struct smtp_msg_process *mproc, enum smtp_filter_scope scope, const char *file, int line, const char *func)
{
	int res = 0;

	mproc->scope = scope; /* This could be set earlier, but is made an argument to this function to ensure callers explicitly set it */

	/* We make 3 passes, so that the postmaster can enforce a hierarchy of filters,
	 * with some always executing before or after a mailbox's rules. */
	RWLIST_RDLOCK(&processors);
	res |= __run_callbacks(mproc, FILTER_BEFORE_MAILBOX, file, line, func);
	if (!res && mproc->userid) {
		/* The mailbox pass can happen for both INDIVIDUAL and COMBINED scope.
		 * mproc->mbox is also NULL for submissions.
		 * mproc->userid is the best thing to use. */
		res |= __run_callbacks(mproc, FILTER_MAILBOX, file, line, func);
	}
	if (!res) {
		res |= __run_callbacks(mproc, FILTER_AFTER_MAILBOX, file, line, func);
	}
	RWLIST_UNLOCK(&processors);

	if (mproc->fp) {
		/* Although in most cases, we do the COMBINED pass and then the INDIVIDUAL pass,
		 * in some cases we might just do the COMBINED pass and then abort,
		 * so close here, just to be safe. */
		fclose(mproc->fp);
		mproc->fp = NULL;
	}

	return res == -1 ? -1 : 0; /* If we aborted callbacks, 1 was returned, but we should return 0 since most callers just check for nonzero return */
}

/* Note: In the case of SMTP_SCOPE_COMBINED, this is kind of a misnomer, since it's not being called from a delivery handler, but the wrapper is still useful */
int __smtp_run_delivery_callbacks(struct smtp_session *smtp, struct smtp_msg_process *mproc, struct mailbox *mbox, struct smtp_response **restrict resp_ptr,
	enum smtp_direction dir, enum smtp_filter_scope scope, const char *recipient, size_t datalen, void **freedata,
	const char *file, int line, const char *func)
{
	unsigned int mailboxid;
	char recip_buf[256];
	struct smtp_response *resp = *resp_ptr;

	/* Caller may use IN for either "IN" or "SUBMIT", use the more specific one */
	dir = smtp->msa && dir == SMTP_DIRECTION_IN ? SMTP_DIRECTION_SUBMIT : dir;

	/* The local delivery agent (mod_smtp_delivery_local) also runs message processing
	 * so that individual users' filter rules (Sieve or MailScript) will run.
	 * For external delivery, the destination mailbox is not local, so it does not make
	 * sense to run any individual user rules in that case... there is no user!
	 * However, in both cases, the postmaster may configure system-wide MailScript rules that
	 * apply to all messages, e.g. refuse acceptance of any messages
	 * with an X-Spam-Score of 10 or greater, etc. We should run those rules here. */
	smtp_mproc_init(smtp, mproc);
	mproc->size = (int) datalen;

	/* mbox and recipient are always NULL if scope is SMTP_SCOPE_COMBINED
	 * (mbox can also be NULL for SMTP_SCOPE_INDIVIDUAL, but recipient can't be) */
	if (scope == SMTP_SCOPE_INDIVIDUAL) {
		/* recipient includes <>,
		 * but the mail filtering engines don't want that,
		 * and just want to consume the address itself.
		 * XXX Can be revisited if the use of variables with and without <> is ever made consistent! */
		safe_strncpy(recip_buf, recipient, sizeof(recip_buf));
		bbs_strterm(recip_buf, '>');

		bbs_strterm(recip_buf, '>');
		mproc->recipient = recip_buf + 1; /* Without <> */
	}

	/* This is a little bit ambiguous, honestly...
	 * the message was either incoming or a submission, initially,
	 * but for non-local delivery, it is really an outgoing at this point.
	 * This also allows differentiating from local delivery in the global
	 * MailScript rules: if direction is IN, then it will only apply to local mailboxes.
	 * If direction is OUT, then it will only apply to messages for non-local mailboxes. */
	mproc->dir = dir;
	mproc->direction = dir == SMTP_DIRECTION_OUT ? SMTP_MSG_DIRECTION_OUT : SMTP_MSG_DIRECTION_IN;
	/* We only want to run global/system-wide rules, not per-user rules,
	 * there may not even be an associated local mailbox. */
	mproc->mbox = mbox;
	/* Determine the user ID associated with the mailbox.
	 * We want the user ID of the mailbox, not the user ID of the authenticated user, if the connection is even authenticated at all.
	 * The rules being run are those that belong to the mailbox to which we are attempting delivery.
	 * Therefore, using smtp->node->user->id as a fallback is wrong. */
	mailboxid = mbox ? (unsigned int) mailbox_id(mbox) : 0;
	mproc->userid = mailboxid ? mailboxid : 0;

	if (dir == SMTP_DIRECTION_IN && smtp_message_quarantinable(smtp)) { /* e.g. DMARC failure */
		/* We set the override mailbox before running callbacks,
		 * because users should have the final say in being able
		 * to override moving messages to particular mailboxes.
		 * Moving quarantined messages to "Junk" is just the default. */
		bbs_debug(5, "Message should be quarantined, so initializing destination mailbox to 'Junk'\n");
		mproc->newdir = strdup("Junk");
	}

	if (__smtp_run_callbacks(mproc, scope, file, line, func)) {
		return -1; /* If returned nonzero, it's assumed it responded with an SMTP error code as appropriate. */
	}

	/* mod_sieve and mod_mailscript don't check for this and won't prevent it, but this won't work if it happens: */
	if (!mbox && mproc->newdir) {
		/* This is a global before/after rule that does not correspond to any mailbox,
		 * for example a message we accepted that needs to be delivered to another server.
		 * Since this is something the administrator configured, it isn't inappropriate to warn here,
		 * since this is an actionable warning. */
		bbs_warning("Messages cannot be moved for non-mailbox destinations\n"); /* fileinto (Sieve) or MOVETO (MailScript), will get ignored */
	}

	if (mproc->bounce) {
		const char *msg = S_OR(mproc->bouncemsg, "This message has been rejected by the recipient"); /* Use custom response if provided, default otherwise */
		/*! \todo We should allow the filtering engine to set the response code too (not just the message) */
		smtp_abort(resp, 554, 5.7.1, msg); /* XXX Best default SMTP code for this? */
		*freedata = mproc->bouncemsg; /* This is a bit awkward. We still need to use this after we return. Make it net_smtp's problem now. */
		*resp_ptr = NULL; /* We already set the error, don't let anything else set it afterwards */
	}
	if (mproc->drop) {
		return mproc->bounce ? -1 : 1; /* Silently drop message */
	}
	return 0;
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

	f = calloc(1, sizeof(*f) + reciplen + hostlen + iplen + statuslen + errorlen);
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
	__builtin_unreachable();
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
	__builtin_unreachable();
}

/* Forward declaration */
static int nosmtp_deliver(const char *filename, const char *sender, const char *recipient, size_t length);

static int any_failures(struct smtp_delivery_outcome **f, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (f[i]->action == DELIVERY_FAILED) {
			return 1;
		}
	}
	return 0;
}

int smtp_dsn(const char *sendinghost, struct tm *arrival, const char *sender, int srcfd, int offset, size_t msglen, struct smtp_delivery_outcome **f, int n)
{
	int i, res;
	char full_sender[256];
	char tmpattach[32] = "/tmp/bouncemsgXXXXXX";
	FILE *fp;
	char bound[256];
	char date[50], date2[50];
	struct tm tm;
	size_t length;
	time_t t = time(NULL);

	/* The MAIL FROM in non-delivery reports is always empty to prevent looping.
	 * e.g. if we're bouncing a bounce, just abort. */
	if (strlen_zero(sender)) {
		bbs_warning("MAIL FROM is empty, cannot deliver delivery status notification\n");
		return -1;
	}

	if (*sender == '<') {
		/* Sender arrives without <>, so this shouldn't happen */
		safe_strncpy(full_sender, sender, sizeof(full_sender));
	} else {
		snprintf(full_sender, sizeof(full_sender), "<%s>", sender);
	}
	bbs_debug(1, "Sending SMTP DSN to %s\n", full_sender);

	fp = bbs_mkftemp(tmpattach, 0600);
	if (!fp) {
		return -1;
	}

	/* Format of the DSN report is defined in RFC 3461 Section 6 */

	/* Generate headers */
	if (!strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", localtime_r(&t, &tm))) {
		bbs_error("strftime failed\n");
		date[0] = '\0';
	}
	fprintf(fp, "Date: %s\r\n", date);
	fprintf(fp, "From: \"Mail Delivery Subsystem\" <mailer-daemon@%s>\r\n", bbs_hostname());
	fprintf(fp, "Subject: %s\r\n", delivery_subject_name(f, n));
	fprintf(fp, "To: %s\r\n", full_sender);
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
	} else if (n == 1) {
		switch (f[0]->action) {
			case DELIVERY_DELAYED:
				fprintf(fp, "Your message has been delayed. Delivery may succeed in the future, and we will send a final nondelivery notice if we are unable to deliver the message successfully.\r\n\r\n");
				break;
			case DELIVERY_DELIVERED:
				fprintf(fp, "Your message has been delivered. A copy has been included for your reference.\r\n\r\n");
				break;
			case DELIVERY_RELAYED:
			case DELIVERY_EXPANDED:
				break;
			case DELIVERY_FAILED: __builtin_unreachable(); /* any_failures() would be true for this case */
		}
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
	}

	fflush(fp);
	/* Include CR LF first, in case original message did not end with one, to prevent boundary from leaking onto last line of attachment. */
	fprintf(fp, "\r\n--%s--\r\n", bound); /* Last one, so include 2 dashes after the boundary */
	length = (size_t) ftell(fp);
	fclose(fp);

	res = nosmtp_deliver(tmpattach, "", full_sender, length); /* Empty MAIL FROM for DSNs */
	unlink(tmpattach);
	return res;
}

static int duplicate_loop_avoidance(struct smtp_session *smtp, char *recipient)
{
	char *tmp = NULL;
	const char *normalized_recipient;
	/* The MailScript REDIRECT rule will result in recipients being added to
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

int smtp_message_quarantinable(struct smtp_session *smtp)
{
	/* In theory, a filter rule could exist to quarantine mail on DMARC failure,
	 * but this is builtin for ease of use. */
	return smtp->tflags.quarantine;
}

/*! \brief "Stand and deliver" that email! */
static int expand_and_deliver(struct smtp_session *smtp, const char *filename, size_t datalen)
{
	char *recipient;
	int srcfd;
	int total, succeeded = 0;
	struct smtp_filter_data filterdata;
	struct smtp_msg_process mproc;
	struct smtp_delivery_outcome *bounces[MAX_RECIPIENTS];
	int numbounces = 0;
	struct smtp_response resp, *resp_ptr;
	void *freedata = NULL;
	int res;

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

	if (filterdata.reject) {
		/* A filter has indicated that this message should be rejected.
		 * XXX Currently, this only happens if a DMARC reject occured, so that is hardcoded here for now. */
		close(srcfd);
		bbs_smtp_log(2, smtp, "Message from <%s> rejected due to policy failure\n", smtp->from);
		smtp_reply(smtp, 550, 5.7.1, "Message rejected due to policy failure");
		return 0; /* Return 0 to inhibit normal failure message, since we already responded */
	} else if (filterdata.quarantine) {
		/* This is kind of a clunky hack.
		 * We need to be able to move quarantined messages into "Junk"
		 * in the local delivery handler. However, it only has access to the mproc structure,
		 * which is stack allocated inside the handler, so we can't access it from net_smtp.
		 * As a workaround, save off the quarantine flag onto the SMTP structure for permanence,
		 * and then check that from within the delivery handler.
		 *
		 * If we defined a structure that could be passed into all delivery handlers,
		 * instead of passing all the arguments directly, it would be appropriate to remove
		 * this bitfield from the SMTP struct and add it to that instead, and remove the API to check.
		 */
		smtp->tflags.quarantine = 1;
	}

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
		/* smtp->datafile originally pointed to the original message received,
		 * but if it has been modified by filter callbacks, update it to
		 * point to the amended file.
		 * This way, even though filters don't have access to headers added
		 * by other filters, at this point, we can ensure that message processors
		 * have access to any headers added by the filter stage. */
		smtp->datafile = filterdata.outputfile;
	}

	total = stringlist_size(&smtp->recipients);
	if (total < 1) {
		bbs_warning("Message has no recipients?\n");
		close(srcfd);
		return -1;
	}

	memset(&resp, 0, sizeof(resp)); /* Just in case there are no recipients? Or the first call to smtp_run_delivery_callbacks here returns nonzero. */

	/* Also allow message processors to be run once, for all recipients */
	resp_ptr = &resp;
	res = smtp_run_delivery_callbacks(smtp, &mproc, NULL, &resp_ptr, SMTP_DIRECTION_IN, SMTP_SCOPE_COMBINED, NULL, datalen, freedata);
	RWLIST_RDLOCK(&handlers); /* This is correct. When we goto finalize, the list should be locked, so we want to lock either way. */
	if (res) {
		if (res == 1) {
			/* We haven't actually delivered the message, if this happens.
			 * The only time this happens is if we decide to drop a message,
			 * but NOT send a bounce, which in practice cannot happen
			 * with current message processors that do SMTP_SCOPE_COMBINED.
			 *
			 * Even though we didn't actually save the message, as with a delivery agent,
			 * this still counts as success. */
			bbs_debug(4, "Message dropped pre-delivery, returning success\n");
			succeeded++;
		} else {
			/* This is probably a bounce + drop.
			 * If we are just bouncing but not dropping (opposite of res == 1 case),
			 * then 0 would have been returned. We don't actually handle that
			 * case here as would be conformant... since bounce already may have set a response
			 * if resp_ptr is now NULL, in theory, that should be used,
			 * but delivery agents could override that.
			 * But again, just like the res == 1 case, being in this branch AND having !resp_ptr
			 * is not something that actually happens with current message processors,
			 * so that edge case is ignored here. */
			bbs_debug(4, "Message dropped pre-delivery, returning failure\n");
			/* The actual value here doesn't matter as long as it's not 0.
			 * At the end of this function, this makes us return 1 instead of -1,
			 * to ensure the default 451 Delivery failed message is not sent out,
			 * since a message processor already responded with its own failure message. */
			resp.code = 421;
		}
		goto finalize;
	}

	while ((recipient = stringlist_pop(&smtp->recipients))) {
		char *user, *domain;
		char *dup;
		int local;
		struct smtp_delivery_handler *h;
		int mres = 0;

		if (duplicate_loop_avoidance(smtp, recipient)) {
			continue;
		}

		if (*recipient != '<') {
			bbs_warning("Malformed recipient (missing <>): %s\n", recipient);
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
			bbs_module_ref(h->mod, 4);
			/* Delivery handlers return 0 if recipient can't be handled by that delivery agent,
			 * 1 if the message was delivered using the delivery agent,
			 * and -1 if not delivered and no other handler may handle it either. */
			mres = h->agent->deliver(smtp, &resp, smtp->from, recipient, user, domain, smtp->fromlocal, local, srcfd, datalen, &freedata);
			bbs_module_unref(h->mod, 4);
			if (mres) {
				bbs_debug(6, "SMTP delivery agent returned %d\n", mres);
				break;
			}
		}
		if (mres == 1) {
			/* Delivery or queuing to this recipient succeeded */
			bbs_smtp_log(4, smtp, "Delivery succeeded or queued: <%s> -> %s\n", smtp->from, recipient);
			succeeded++;
		} else if (mres < 0) { /* Includes if the message has no handler */
			char bouncemsg[512];
			/* Process any error message before unlocking the list.
			 * If there are multiple recipients, we cannot send an SMTP reply
			 * just for one of the recipients (otherwise we might send multiple SMTP responses).
			 * Instead, we have to send a bounce message.
			 * If this is the only recipient, we can bounce at the SMTP level. */
			const char *replymsg = S_OR(resp.reply, "Message delivery failed");
			snprintf(bouncemsg, sizeof(bouncemsg), "%d%s%s %s",
				resp.code ? resp.code : 451, resp.subcode ? " " : "", S_OR(resp.subcode, ""), replymsg);
			bbs_smtp_log(2, smtp, "Delivery failed: <%s> -> %s: %s\n", smtp->from, recipient, bouncemsg);
			if (total > 1) {
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

finalize:
	if (succeeded) { /* If anything succeeded, reply with a 250 OK. We already send individual bounces for the failed recipients. */
		bbs_smtp_log(2, smtp, "Message from <%s> accepted for delivery to %d/%d recipient%s\n", smtp->from, succeeded, total, ESS(total));
		smtp_reply(smtp, 250, 2.6.0, "Message accepted for delivery");
	} else if (resp.code && !strlen_zero(resp.subcode) && !strlen_zero(resp.reply)) { /* All deliveries failed */
		/* We could also send a bounce in this case, but even easier, just do it in the SMTP transaction */
		bbs_smtp_log(2, smtp, "Message from <%s> rejected in full by custom policy: %d %s %s\n", smtp->from, resp.code, resp.subcode, resp.reply);
		smtp_resp_reply(smtp, resp.code, resp.subcode, resp.reply);
	} else {
		/* This is reachable if all deliveries fail and no custom failure code was set */
		bbs_smtp_log(2, smtp, "Message from <%s> failed delivery to %d/%d recipient%s\n", smtp->from, succeeded, total, ESS(total));
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

	smtp.datafile = filename;

	stringlist_init(&smtp.sentrecipients);
	memcpy(&smtp.recipients, recipients, sizeof(smtp.recipients));

	bbs_debug(5, "Injecting SMTP message MAILFROM <%s>, file: %s, size %lu\n", S_IF(mailfrom), filename, length);

	res = expand_and_deliver(&smtp, filename, length);
	/* Since these are normally consumed, there is no guarantee to the caller what will be leftover here, so just clean up */
	stringlist_empty_destroy(&smtp.recipients);
	stringlist_empty_destroy(&smtp.sentrecipients);

	return res;
}

/*!
 * \brief Inject a message to deliver via SMTP, to a single recipient, from outside of the SMTP protocol
 * \param filename Entire RFC822 message
 * \param from MAIL FROM. Do not include <>.
 * \param recipient RCPT TO. Must include <>.
 * \return Same as expand_and_deliver's return value.
 */
static int nosmtp_deliver(const char *filename, const char *sender, const char *recipient, size_t length)
{
	struct stringlist slist;

	stringlist_init(&slist);
	stringlist_push(&slist, recipient);

	return smtp_inject(sender, &slist, filename, length);
}

/*! \brief Accept messages injected from the BBS to deliver, to local or external recipients */
static int injectmail_simple(SIMPLE_MAILER_PARAMS)
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

static int injectmail_full(const char *tmpfile, const char *mailfrom, struct stringlist *recipients)
{
	int res;
	FILE *fp;
	long int length;

	fp = fopen(tmpfile, "r");
	if (!fp) {
		bbs_error("fopen(%s) failed: %s\n", tmpfile, strerror(errno));
		stringlist_empty_destroy(recipients);
		return -1;
	}

	fseek(fp, 0L, SEEK_END); /* Go to EOF */
	length = ftell(fp);
	fclose(fp);

	res = smtp_inject(mailfrom, recipients, tmpfile, (size_t) length);
	unlink(tmpfile);
	bbs_debug(3, "injectmail res=%d, mailfrom=%s\n", res, mailfrom);

	return res ? -1 : 0;
}

static int check_identity(struct smtp_session *smtp, char *s)
{
	char *user, *domain;
	struct mailbox *sendingmbox;
	char sendersfile[256];
	char buf[32];
	FILE *fp;
	int domain_is_local;

	/* Must use bbs_parse_email_address for sure, since From header could contain a name, not just the address that's in the <> */
	if (bbs_parse_email_address(s, NULL, &user, &domain)) {
		smtp_reply(smtp, 550, 5.7.1, "Malformed From header");
		return -1;
	}

	domain_is_local = domain ? mail_domain_is_local(domain) : 1;
	if (!domain) { /* Missing domain altogether, yikes */
		smtp_reply(smtp, 550, 5.7.1, "You are not authorized to send email using this identity");
		return -1;
	}
	if (!domain_is_local) { /* Wrong domain? */
		/* For non-local domains, if the user is explicitly authorized to send mail as this identity,
		 * Then allow it. */
		char addr[256];
		snprintf(addr, sizeof(addr), "%s@%s", user, domain); /* Reconstruct instead of using s, to ensure no <> */
		if (bbs_user_is_registered(smtp->node->user) && smtp_user_authorized_for_identity(bbs_username(smtp->node->user), addr)) {
			bbs_debug(3, "User '%s' explicitly authorized to submit mail as %s\n", bbs_username(smtp->node->user), addr);
			return 0; /* No further checks apply in this case */
		}
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
		mproc.dir = SMTP_DIRECTION_SUBMIT;
		mproc.direction = SMTP_MSG_DIRECTION_OUT; /* It's an outbound message from the user */
		mproc.mbox = NULL;
		mproc.userid = smtp->node->user->id;
		mproc.user = smtp->node->user;
		if (smtp->msa) {
			/* All envelope recipients of the message, only added for message submissions.
			 * We don't do this for SMTP_DIRECTION_IN, because allowing one recipient to view
			 * who the other recipients were (for example, if they were Bcc'd) would leak information.
			 * If the user is the one sending it, then this information is already known and not secret. */
			mproc.recipients = &smtp->recipients;
		}
		/* Note that mproc.to here is NULL, since we don't process recipients until expand_and_deliver,
		 * i.e. we run the callbacks here per-message, not per-recipient, so we don't have access
		 * to a specific recipient for this outgoing rules. This is "pre transaction"
		 * so there's not really an "envelope" recipient per se we can use.
		 * XXX We do have access to &smtp->recipients at this point, so we could make those available
		 * to rules if needed. */
		if (smtp_run_callbacks(&mproc, SMTP_SCOPE_COMBINED)) {
			return 0; /* If returned nonzero, it's assumed it responded with an SMTP error code as appropriate. */
		}
		/*
		 * For incoming messages, we process MOVETO after DISCARD, since if we drop, we're probably discarding,
		 * but here we process it first.
		 * By default, outgoing SMTP submissions aren't saved at all (persistently).
		 * This accounts for the case where we want to save a local copy,
		 * i.e. emulating IMAP's APPEND, but having the SMTP server do it
		 * to the client doesn't have to upload the message twice.
		 * If we're relaying, we might RELAY and then DISCARD, so we should save the copy before we abort.
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
					bbs_module_ref(h->mod, 5);
					/* provided by mod_smtp_delivery_local */
					res = h->agent->save_copy(smtp, &mproc, srcfd, datalen, newfile, sizeof(newfile));
					bbs_module_unref(h->mod, 5);
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
					bbs_module_ref(h->mod, 6);
					/* provided by mod_smtp_delivery_external */
					res = h->agent->relay(smtp, &mproc, srcfd, datalen, &smtp->recipients);
					bbs_module_unref(h->mod, 6);
					if (!res) {
						bbs_smtp_log(4, smtp, "Outgoing message successfully relayed for submission: MAIL FROM %s\n", smtp->from);
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
				bbs_smtp_log(4, smtp, "Relay rejected: MAIL FROM %s\n", smtp->from);
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
			close_if(srcfd);
			return 0;
		}
		close_if(srcfd);
		if (mproc.bounce) {
			smtp_reply(smtp, 554, 5.7.1, "%s", S_OR(mproc.bouncemsg, "This message has been rejected by the sender")); /* XXX Best default SMTP code for this? */
			free_if(mproc.bouncemsg);
			/* We don't return here, because technically, we allow a bounce message to be sent,
			 * without actually dropping the message at this point.
			 * In Sieve filtering, there is no distinction, REJECT will set bounce and drop to 1,
			 * as will the REJECT action in MailScript. However, the BOUNCE action on its own
			 * in MailScript can be used to reject the message, outwardly, but continue processing it,
			 * and even accept it. This flexibility is intended for advanced filter usage. */
		}
		if (mproc.drop) {
			/*! \todo BUGBUG For DIRECTION OUT, if we REDIRECT, then DISCARD, we'll just drop here and forward won't happen (same for REJECT) */
			bbs_debug(5, "Discarding message and ceasing all further processing\n");
			return 0; /* Silently drop message. We MUST do this for RELAYed messages, since we must not allow those to be sent again afterwards. */
		}
	}

	if (smtp->msa) {
		/* Verify the address used is one the sender is authorized to use. */
		char fromdup[256];
		char fromhdrdup[256];
		char *fromaddr;

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
		safe_strncpy(fromhdrdup, smtp->fromheaderaddress, sizeof(fromhdrdup));
		/* If the two addresses are exactly the same, no need to do the same check twice. */
		if (strcmp(smtp->from, smtp->fromheaderaddress) && check_identity(smtp, smtp->fromheaderaddress)) {
			return 0;
		}
		/* We're good: the From header is either the actual username, or an alias that maps to it. */
		/* If the From header differs from the MAIL FROM address, we should use the From header,
		 * since for DKIM signing, etc. this is the relevant domain. */
		fromaddr = strchr(fromhdrdup, '<');
		if (fromaddr) {
			fromaddr++;
			if (!strlen_zero(fromaddr)) {
				bbs_strterm(fromaddr, '>');
			}
		} else {
			fromaddr = fromhdrdup;
		}
		bbs_debug(4, "Updating internal from address from '%s' to '%s'\n", smtp->from, fromaddr);
		REPLACE(smtp->fromaddr, fromaddr);
		/* Don't free smtp->fromheaderaddress yet, that we can still use it */
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

	/* We'll get a URL that looks something like this:
	 * imap://jsmith@imap.example.com/Sent;UIDVALIDITY=1677584102/;UID=8;urlauth=submit+jsmith:internal */
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
			REPLACE(smtp->fromheaderaddress, from);
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

static int handle_data(struct smtp_session *smtp, char *s, struct readline_data *rldata)
{
	FILE *fp;
	char template[256];
	int datafail = 0;
	int indataheaders = 1;

	REQUIRE_HELO();
	REQUIRE_MAIL_FROM();
	REQUIRE_RCPT();
	REQUIRE_EMPTY(s);

	strcpy(template, "/tmp/smtpXXXXXX");
	fp = bbs_mkftemp(template, 0600);
	if (!fp) {
		smtp_reply_nostatus(smtp, 452, "Server error, unable to allocate buffer");
		return -1;
	}

	/* Begin reading data. */
	smtp_reply_nostatus(smtp, 354, "Start mail input; end with a period on a line by itself");

	for (;;) {
		size_t len;
		ssize_t res = bbs_node_readline(smtp->node, rldata, "\r\n", MIN_MS(3)); /* RFC 5321 4.5.3.2.5 */
		if (res < 0) {
			bbs_delete_file(template);
			fclose(fp);
			if (res == -3) {
				/* Buffer was exhausted.
				 * RFC 5322 2.1.1 says lines MUST be no longer than 998 characters.
				 * This is the sending mail user agent's resonsibility, not the responsibility of any MTA.
				 * Some user agents don't conform to this requirement, and some MTAs will happily relay them anyways.
				 * In practice, most messages that violate this seem to be spam anyways,
				 * so we have no reason to tolerate noncompliant messages.
				 * However, we need to reject it properly with the right error message before disconnecting. */
				smtp_reply_nostatus(smtp, 550, "Maximum line length exceeded");
				smtp->failures += 3; /* Semantically, this is a bad client. However, we're just going to disconnect now anyways, so this doesn't really matter. */
			}
			return -1;
		}
		s = rldata->buf;
		len = (size_t) res;
		/* This is a very spammy message for large emails: */
		bbs_debug(10, "%p => [%lu data bytes]\n", smtp, len); /* This could be a lot of output, don't show it all. */
		if (!strcmp(s, ".")) { /* Entire message has now been received */
			int dres;
			fclose(fp); /* Have to close and reopen in read mode anyways */
			if (datafail) {
				if (smtp->tflags.datalen >= max_message_size) {
					/* Message too large. */
					smtp_reply(smtp, 552, 5.2.3, "Your message exceeded our message size limits");
				} else {
					/* Message not successfully received in totality, so reject it. */
					smtp_reply(smtp, 451, 4.3.0, "Message not received successfully, try again");
				}
				break;
			} else if (smtp->tflags.hopcount > 1) {
				if (smtp->tflags.hopcount >= HOP_COUNT_WARN_LEVEL) {
					bbs_warning("Current SMTP hop count is %d\n", smtp->tflags.hopcount);
				} else {
					bbs_debug(3, "Current SMTP hop count is %d\n", smtp->tflags.hopcount);
				}
				if (smtp->tflags.hopcount >= HOP_COUNT_MAX_NORMAL_LEVEL && smtp->node && strcmp(smtp->node->ip, "127.0.0.1")) {
					/* The greater the hop count, the more we slow the message down.
					 * We only do this for non-localhost, mainly to avoid holding up the test suite. */
					if (bbs_node_safe_sleep(smtp->node, 200 * smtp->tflags.hopcount)) {
						return -1;
					}
				}
				if (smtp->tflags.hopcount >= (int) max_hops) {
					smtp_reply(smtp, 554, 5.6.0, "Message exceeded %u hops, this may indicate a mail loop", max_hops);
					break;
				}
			}

			bbs_debug(5, "Handling receipt of %lu-byte message\n", smtp->tflags.datalen);
			bbs_smtp_log(5, smtp, "Received message: IP=%s,MAILFROM=<%s>,SIZE=%lu,recipients=%d,hopcount=%d,failcount=%d,8bit=%s,quarantine=%s\n",
				smtp->node->ip, smtp->from, smtp->tflags.datalen, smtp->tflags.numrecipients, smtp->tflags.hopcount, smtp->failures,
				BBS_YN(smtp->tflags.is8bit), BBS_YN(smtp->tflags.quarantine));

			smtp->datafile = template;
			dres = do_deliver(smtp, template, smtp->tflags.datalen);
			smtp->datafile = NULL;

			bbs_delete_file(template);
			smtp->tflags.datalen = 0;
			/* RFC 5321 4.1.1.4: After DATA, must clear buffers */
			smtp_reset(smtp);
			return dres;
		}

		if (datafail) {
			continue; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		if (indataheaders) {
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
			} else if (!smtp->messageid && STARTS_WITH(s, "Message-ID:")) {
				const char *tmp = s + STRLEN("Message-ID:");
				if (!strlen_zero(tmp)) {
					ltrim(tmp);
				}
				if (!strlen_zero(tmp)) {
					REPLACE(smtp->messageid, tmp);
				}
			} else if (!smtp->tflags.dkimsig && STARTS_WITH(s, "DKIM-Signature")) {
				smtp->tflags.dkimsig = 1;
			} else if (STARTS_WITH(s, "Bcc:")) {
				/* This is unexpected, and probably not good news for whatever
				 * is sending this message.
				 *
				 * According to RFC 2822 3.6.3, the sending agent is responsible
				 * for removing the Bcc: line and just providing it using RCPT.
				 * So, MTAs should not need to be concerned with Bcc at all,
				 * since it won't (or shouldn't) appear in the DATA, i.e.
				 * there should never be "Bcc" headers in messages.
				 *
				 * mail.c does handle this in bbs_mail_message, but that's because
				 * this API is used by things that generate messages and include
				 * the recipients in the message. It's not unlike the sendmail
				 * client program which also removes Bcc lines but includes them
				 * in the RCPT: they need to be processed *somewhere*, but that's
				 * before it hits core MTA logic, and mail.c is here acting as
				 * the submitter / user agent.
				 *
				 * So, if we see this, then somebody's mail user agent is probably
				 * not RFC-compliant and is leaking BCC's... probably not desired. */
				bbs_warning("Message contains a 'Bcc' header? (%s)\n", s);
			} else if (!len) {
				indataheaders = 0; /* CR LF on its own indicates end of headers */
			}
		}

		if (smtp->tflags.datalen + len >= max_message_size) {
			datafail = 1;
			smtp->tflags.datalen = max_message_size; /* This isn't really true, this is so we can detect that the message was too large. */
		}

		res = bbs_append_stuffed_line_message(fp, s, len); /* Should return len + 2, unless it was byte stuffed, in which case it'll be len + 1 */
		if (res < 0) {
			datafail = 1;
		}
		smtp->tflags.datalen += (long unsigned) res;
	}
	bbs_delete_file(template);
	return 0;
}

static int smtp_process(struct smtp_session *smtp, char *s, struct readline_data *rldata)
{
	char *command;

	if (smtp->tflags.inauth) {
		return handle_auth(smtp, s);
	}

	command = strsep(&s, " ");
	REQUIRE_ARGS(command);

	/* Slow down spam using tarpit like techniques */
	if (smtp_tarpit(smtp, 0, NULL)) {
		return -1;
	}

	if (!strcasecmp(command, "RSET")) {
		if (smtp->failures > 50) { /* Don't let SMTP clients keep trying forever */
			bbs_debug(3, "Forcibly disconnecting client for too many resets\n");
			return -1;
		}
		REQUIRE_EMPTY(s);
		smtp_reset(smtp);
		smtp_reply(smtp, 250, 2.1.5, "Flushed");
	} else if (!strcasecmp(command, "NOOP")) {
		smtp_reply(smtp, 250, 2.0.0, "OK");
	} else if (!strcasecmp(command, "QUIT")) {
		REQUIRE_EMPTY(s);
		smtp_reply(smtp, 221, 2.0.0, "Closing connection");
		return -1; /* Will destroy SMTP session after returning */
	} else if (!strcasecmp(command, "HELO")) {
		return handle_helo(smtp, s, 0);
	} else if (!strcasecmp(command, "EHLO")) {
		return handle_helo(smtp, s, 1);
	} else if (!strcasecmp(command, "STARTTLS")) {
		if (!smtp->node->secure) {
			smtp_reply_nostatus(smtp, 220, "Ready to start TLS");
			smtp->tflags.dostarttls = 1;
			smtp->gothelo = 0; /* Client will need to start over. */
		} else {
			smtp_reply(smtp, 454, 5.5.1, "STARTTLS may not be repeated");
		}
	} else if (smtp->msa && !smtp->node->secure && require_starttls && !exempt_from_starttls(smtp)) {
		smtp_reply(smtp, 504, 5.5.4, "Must issue a STARTTLS command first");
	} else if (!strcasecmp(command, "AUTH")) {
		/* https://www.samlogic.net/articles/smtp-commands-reference-auth.htm */
		if (smtp->tflags.inauth) { /* Already in authorization */
			smtp_reply(smtp, 503, 5.5.1, "Bad sequence of commands.");
		} else if (bbs_user_is_registered(smtp->node->user)) { /* Already authed */
			smtp_reply(smtp, 503, 5.7.0, "Already authenticated, no identity changes permitted");
		} else if (!smtp->node->secure && require_starttls && !exempt_from_starttls(smtp)) {
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
	} else if (!strcasecmp(command, "ETRN")) {
		REQUIRE_ARGS(s);
		return handle_etrn(smtp,s);
	} else if (!strcasecmp(command, "MAIL")) {
		return handle_mail(smtp, s);
	} else if (!strcasecmp(command, "RCPT")) {
		REQUIRE_HELO();
		REQUIRE_MAIL_FROM();
		REQUIRE_ARGS(s);
		return handle_rcpt(smtp, s);
	} else if (!strcasecmp(command, "DATA")) {
		return handle_data(smtp, s, rldata);
	} else if (!strcasecmp(command, "BURL")) {
		return handle_burl(smtp, s);
	} else if (!strcasecmp(command, "VRFY")) {
		smtp_reply(smtp, 502, 5.5.1, "Unsupported command");
	} else if (!strcasecmp(command, "EXPN")) {
		smtp_reply(smtp, 502, 5.5.1, "Unsupported command");
	} else if (!strcasecmp(command, "HELP")) {
		/* RFC 4.1.1.8 says servers SHOULD support HELP and that they MAY support HELP for specific commands (we don't) */
		smtp_reply0_nostatus(smtp, 214, "This server supports the following commands:");
		smtp_reply_nostatus(smtp, 214, "HELO EHLO RSET HELP QUIT STARTTLS AUTH MAIL RCPT DATA BURL");
	} else { /* GENURLAUTH */
		if (smtp_tarpit(smtp, 502, NULL)) {
			return -1;
		}
		smtp_reply(smtp, 502, 5.5.1, "Unrecognized command");
	}

	return 0;
}

static void handle_client(struct smtp_session *smtp)
{
	char buf[1001]; /* Maximum length, including CR LF, is 1000 */
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));

	if (handle_connect(smtp)) {
		return;
	}

	for (;;) {
		ssize_t res = bbs_node_readline(smtp->node, &rldata, "\r\n", MIN_MS(5)); /* RFC 5321 4.5.3.2.7 */
		if (res < 0) {
			res += 1; /* Convert the res back to a normal one. */
			if (res == 0) {
				/* Timeout occured. */
				smtp_reply(smtp, 451, 4.4.2, "Timeout - closing connection");
			} else if (res == -2) {
				/* bbs_readline returns -3 on buffer exhaustion (which we've incremented by 1).
				 * Since our connection state is messed up at this point, the only sane thing
				 * we can do is print an error and disconnect. */
				smtp_reply_nostatus(smtp, 550, "Maximum line length exceeded");
				smtp->failures += 3; /* Semantically, this is a bad client; however, we're just going to disconnect now anyways */
			}
			break;
		}
		if (STARTS_WITH(buf, "AUTH PLAIN ")) {
			bbs_debug(6, "%p => AUTH PLAIN ******\n", smtp);
		} else {
			bbs_debug(6, "%p => %s\n", smtp, buf);
		}
		if (smtp_process(smtp, buf, &rldata)) {
			break;
		}
		if (smtp->tflags.dostarttls) {
			/* RFC3207 STARTTLS */
			/* You might think this would be more complicated, but nope, this is literally all there is to it. */
			bbs_debug(3, "Starting TLS\n");
			smtp->tflags.dostarttls = 0;
			if (bbs_node_starttls(smtp->node)) {
				break; /* Just abort */
			}
			smtp->node->secure = 1;
			/* Prevent STARTTLS command injection by resetting the buffer after TLS upgrade:
			 * http://www.postfix.org/CVE-2011-0411.html
			 * https://blog.apnic.net/2021/11/18/vulnerabilities-show-why-starttls-should-be-avoided-if-possible/
			 * Also RFC 3207 Section 6 */
			bbs_readline_flush(&rldata);
		}
	}
}

/*! \brief Thread to handle a single SMTP/SMTPS client */
static void smtp_handler(struct bbs_node *node, int msa, int secure)
{
	struct smtp_session smtp;

	/* Start TLS if we need to */
	if (secure && bbs_node_starttls(node)) {
		return;
	}

	memset(&smtp, 0, sizeof(smtp));
	smtp.node = node;
	SET_BITFIELD(smtp.msa, msa);

	stringlist_init(&smtp.recipients);
	stringlist_init(&smtp.sentrecipients);

	handle_client(&smtp);

	/* If this was not an authenticated SMTP session, don't generate a logout event. */
	if (bbs_user_is_registered(node->user)) {
		mailbox_dispatch_event_basic(EVENT_LOGOUT, node, NULL, NULL);
	}

	smtp_destroy(&smtp);
}

static void *__smtp_handler(void *varg)
{
	struct bbs_node *node = varg;
	int secure = !strcmp(node->protname, "SMTPS") ? 1 : 0;

	bbs_node_net_begin(node);

	/* If it's secure, it's for message submission agent, MTAs are never secure by default. */
	smtp_handler(node, secure || !strcmp(node->protname, "SMTP (MSA)"), secure); /* Actually handle the SMTP/SMTPS/message submission agent client */
	bbs_node_exit(node);
	return NULL;
}

static struct bbs_cli_entry cli_commands_smtp[] = {
	BBS_CLI_COMMAND(cli_filters, "smtp filters", 2, "List all SMTP filters", NULL),
};

static int load_config(void)
{
	char smtp_log_file[256];
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("net_smtp.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "relayin", &accept_relay_in);
	bbs_config_val_set_uint(cfg, "general", "maxsize", &max_message_size);
	if (!bbs_config_val_set_uint(cfg, "general", "maxhops", &max_hops)) {
		if (max_hops > MAX_HOPS) {
			bbs_warning("Maximum possible value for setting 'maxhops' is %d\n", MAX_HOPS);
			max_hops = MAX_HOPS;
		} else if (max_hops < 1) {
			bbs_warning("Minimum possible value for setting 'maxhops' is %d\n", 1);
			max_hops = 1;
		}
	}
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

/*! \brief Section names that are valid but not parsed in the loop */
#define VALID_SECT_NAME(s) (!strcmp(s, "general") || !strcmp(s, "logging") || !strcmp(s, "privs") || !strcmp(s, "smtp") || !strcmp(s, "smtps") || !strcmp(s, "msa") || !strcmp(s, "static_relays"))

	while ((section = bbs_config_walk(cfg, section))) {
		struct bbs_keyval *keyval = NULL;
		const char *key, *val;

		if (!strcmp(bbs_config_section_name(section), "blacklist")) { /* Blacklist */
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				key = bbs_keyval_key(keyval);
				if (!stringlist_contains(&blacklist, key)) {
					stringlist_push(&blacklist, key);
				}
			}
		} else if (!strcmp(bbs_config_section_name(section), "authorized_relays")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				key = bbs_keyval_key(keyval);
				val = bbs_keyval_val(keyval);
				add_authorized_relay(key, val);
			}
		} else if (!strcmp(bbs_config_section_name(section), "trusted_relays")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				key = bbs_keyval_key(keyval);
				if (!stringlist_contains(&trusted_relays, key)) {
					stringlist_push(&trusted_relays, key);
				}
			}
		} else if (!strcmp(bbs_config_section_name(section), "authorized_senders")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				key = bbs_keyval_key(keyval);
				val = bbs_keyval_val(keyval);
				add_authorized_identity(key, val);
			}
		} else if (!strcmp(bbs_config_section_name(section), "starttls_exempt")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				key = bbs_keyval_key(keyval);
				val = bbs_keyval_val(keyval);
				if (!stringlist_contains(&starttls_exempt, key)) {
					stringlist_push(&starttls_exempt, key);
				}
			}
		} else if (!VALID_SECT_NAME(bbs_config_section_name(section))) {
			bbs_warning("Invalid section name '%s'\n", bbs_config_section_name(section));
		}
	}

	if (!bbs_config_val_set_str(cfg, "logging", "logfile", smtp_log_file, sizeof(smtp_log_file))) {
		smtplogfp = fopen(smtp_log_file, "a");
		if (!smtplogfp) {
			bbs_error("Failed to open SMTP log file for appending: %s\n", smtp_log_file);
		}
		bbs_config_val_set_uint(cfg, "logging", "loglevel", &smtp_log_level);
	}

	return 0;
}

static int load_module(void)
{
	stringlist_init(&trusted_relays);
	stringlist_init(&starttls_exempt);
	stringlist_init(&blacklist);

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

	if (bbs_hostname_is_ipv4(bbs_hostname())) {
		/* Address literals are surrounded in [], per RFC 5321 4.1.3 */
		snprintf(smtp_hostname_buf, sizeof(smtp_hostname_buf), "[%s]", bbs_hostname());
	} else {
		safe_strncpy(smtp_hostname_buf, bbs_hostname(), sizeof(smtp_hostname_buf));
	}

	/* If we can't start the TCP listeners, decline to load */
	if (bbs_start_tcp_listener3(smtp_enabled ? smtp_port : 0, smtps_enabled ? smtps_port : 0, msa_enabled ? msa_port : 0, "SMTP", "SMTPS", "SMTP (MSA)", __smtp_handler)) {
		bbs_singular_callback_destroy(&smtp_queue_processor);
		goto cleanup;
	}

	bbs_register_tests(tests);
	bbs_register_mailer(injectmail_simple, injectmail_full, 1);
	bbs_cli_register_multiple(cli_commands_smtp);

	return 0;

cleanup:
	stringlist_empty_destroy(&blacklist);
	RWLIST_WRLOCK_REMOVE_ALL(&authorized_relays, entry, relay_free);
	return -1;
}

static int unload_module(void)
{
	bbs_unregister_mailer(injectmail_simple, injectmail_full);
	bbs_unregister_tests(tests);
	bbs_cli_unregister_multiple(cli_commands_smtp);
	if (smtp_enabled) {
		bbs_stop_tcp_listener(smtp_port);
	}
	if (smtps_enabled) {
		bbs_stop_tcp_listener(smtps_port);
	}
	if (msa_enabled) {
		bbs_stop_tcp_listener(msa_port);
	}
	stringlist_empty_destroy(&blacklist);
	RWLIST_WRLOCK_REMOVE_ALL(&authorized_relays, entry, relay_free);
	stringlist_empty_destroy(&trusted_relays);
	stringlist_empty_destroy(&starttls_exempt);
	if (!RWLIST_EMPTY(&filters)) {
		bbs_error("Filter(s) still registered at unload?\n");
	}
	if (smtplogfp) {
		fclose(smtplogfp);
	}
	bbs_singular_callback_destroy(&smtp_queue_processor);
	return 0;
}

BBS_MODULE_INFO_FLAGS_DEPENDENT("RFC5321 SMTP Message Transfer/Submission", MODFLAG_GLOBAL_SYMBOLS, "mod_mail.so");
