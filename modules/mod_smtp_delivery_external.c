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
 * \brief External mail queuing and delivery
 *
 * \note Supports RFC 7505 Null MX
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <utime.h> /* use utimbuf */

#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/nameser.h>

#ifdef __FreeBSD__
/* Needed for sockaddr_in in resolv.h on FreeBSD */
#include <netinet/in.h>
#endif

#include <resolv.h>

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/user.h"
#include "include/stringlist.h"
#include "include/linkedlists.h"
#include "include/oauth.h"
#include "include/base64.h"
#include "include/cli.h"
#include "include/parallel.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"
#include "include/mod_smtp_client.h"

#if !defined(linux) || defined(__GLIBC__)
#define HAVE_NS_SPRINTRR
#endif

/* Enable to debug DNS replies, but only if HAVE_NS_SPRINTRR on your platform,
 * e.g. musl doesn't have it. */
/* #define DEBUG_DNS_REPLIES */

/* Do not modify this: */
#ifndef HAVE_NS_SPRINTRR
#ifdef DEBUG_DNS_REPLIES
#error "DEBUG_DNS_REPLIES can only be enabled if HAVE_NS_SPRINTRR"
#endif /* DEBUG_DNS_REPLIES */
#endif /* !HAVE_NS_SPRINTRR */

static int accept_relay_out = 1;
static int minpriv_relay_out = 0;

static int require_starttls_out = 0;

static int notify_queue = 0;
static pthread_t queue_thread = 0;
static bbs_rwlock_t queue_lock;
static char queue_dir[256];
static int queue_immediate = 1;
static unsigned int queue_interval = 60;
static unsigned int max_retries = 10;
static unsigned int max_age = 604800; /* 7 days */

static int unloading = 0;
static time_t last_periodic_queue_run = 0;

struct mx_record {
	int priority;
	RWLIST_ENTRY(mx_record) entry;
	char data[];
};

RWLIST_HEAD(mx_records, mx_record);

/*! \brief List of stringlists for static routes */
struct static_relay {
	const char *hostname;
	struct stringlist routes;
	RWLIST_ENTRY(static_relay) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(static_relays, static_relay);

/*! \note static_relays should be locked when calling */
static int add_static_relay(const char *hostname, const char *route)
{
	struct static_relay *s;

	s = calloc(1, sizeof(*s) + strlen(hostname) + 1);
	if (ALLOC_FAILURE(s)) {
		return -1;
	}
	strcpy(s->data, hostname); /* Safe */
	s->hostname = s->data;
	stringlist_init(&s->routes);
	stringlist_push_list(&s->routes, route);
	RWLIST_INSERT_TAIL(&static_relays, s, entry);
	return 0;
}

static void free_static_relay(struct static_relay *s)
{
	stringlist_empty_destroy(&s->routes);
	free(s);
}

/*!
 * \brief Check whether a domain has a defined static route
 * \internal
 * \param domain
 * \return Static routes to use, if defined (override MX lookup)
 * \return NULL if no static routes (do MX lookup instead)
 */
static struct stringlist *get_static_routes(const char *domain)
{
	char domainbuf[256];
	struct stringlist *routes = NULL;
	struct static_relay *s, *wildcard = NULL;

	/* If it's an IP address, then we need to use that IP address, literally,
	 * i.e. static routes don't apply. */
	if (*domain == '[') {
		/* Probably begins a domain literal */
		domain++;
		if (!strlen_zero(domain)) {
			bbs_strncpy_until(domainbuf, domain, sizeof(domainbuf), ']');
			domain = domainbuf;
		}
	}
	if (bbs_hostname_is_ipv4(domain)) {
		return NULL;
	}

	RWLIST_RDLOCK(&static_relays);
	RWLIST_TRAVERSE(&static_relays, s, entry) {
		if (!strcmp(s->hostname, "*")) {
			wildcard = s;
		} else if (!strcasecmp(s->hostname, domain)) {
			break;
		}
	}
	s = s ? s : wildcard; /* The '*' route is special, and should match last. */
	if (s) {
		/* It's okay to return this directly,
		 * since once added, routes are not removed until the module unloads. */
		routes = &s->routes;
	}
	RWLIST_UNLOCK(&static_relays);
	return routes;
}

/*! \brief Copy the result record data into a string buffer */
static int copy_ns_result(ns_msg msg, ns_rr rr, char *buf, size_t len)
{
	/* The source code for nslookup shows how to print each of the different record types */
	if (ns_rr_type(rr) == T_A) {
		inet_ntop(AF_INET, ns_rr_rdata(rr), buf, (socklen_t) len);
	} else if (ns_rr_type(rr) == T_CNAME) {
		if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), ns_rr_rdata(rr), buf, len) < 0) {
			bbs_warning("ns_name_uncompress failed\n");
			return -1;
		}
	} else if (ns_rr_type(rr) == T_MX) {
		if (ns_rr_rdlen(rr) < 2) {
			return -1;
		}
		if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), ns_rr_rdata(rr) + 2, buf, len) < 0) {
			bbs_warning("ns_name_uncompress failed\n");
			return -1;
		}
	} else {
		return -1;
	}
	return 0;
}

static int dns_record_lookup(const char *domain, enum dns_record_type rectype, char *buf, size_t len)
{
	unsigned char answer[PACKETSZ] = "";
	int res;
	ns_msg msg;
	int i;
	int records = 0;

	bbs_assert_exists(domain);
	res = res_query(domain, C_IN, rectype & DNS_RECORD_CNAME ? T_CNAME : T_A, answer, sizeof(answer));
	if (res == -1) {
		/* This is expected if no record of this type exists. */
		bbs_debug(4, "res_query %s failed for '%s': %s\n", rectype & DNS_RECORD_CNAME ? "CNAME" : "A", domain, hstrerror(h_errno)); /* res_query sets h_errno, not errno */
		return 0;
	}
	res = ns_initparse(answer, res, &msg);
	if (res < 0) {
		bbs_error("Failed to look up %s record: %s\n", rectype & DNS_RECORD_CNAME ? "CNAME" : "A", strerror(errno));
		return 0;
	}
	res = ns_msg_count(msg, ns_s_an);
	if (res < 1) {
		bbs_error("No %s records available for %s\n", rectype & DNS_RECORD_CNAME ? "CNAME" : "A", domain);
		return 0;
	}

	/* The RFCs don't explicitly forbid multiple PTR records for an IP,
	 * but the convention is just 1, and that's what we expect. */
	/* Add each record to our sorted list */
	for (i = 0; i < res; i++) {
#ifdef DEBUG_DNS_REPLIES
		char dispbuf[PACKETSZ] = "";
#endif
		ns_rr rr;
		if (ns_parserr(&msg, ns_s_an, i, &rr)) {
			continue;
		}
#ifdef DEBUG_DNS_REPLIES
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* ns_sprintrr deprecated */
		ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
		bbs_debug(8, "DNS answer: %s\n", dispbuf);
#pragma GCC diagnostic pop /* -Wdeprecated-declarations */
#endif /* DEBUG_DNS_REPLIES */
		/* For CNAME lookups, any records we get will be CNAME records.
		 * However, A record lookups may also encounter CNAME records
		 * in the process of resolution. */
		if (ns_rr_type(rr) == T_A) {
			records |= DNS_RECORD_A;
		} else if (ns_rr_type(rr) == T_CNAME) {
			records |= DNS_RECORD_CNAME;
		} else {
			continue;
		}
		/* Copy the result back to the caller so it can analyze it */
		copy_ns_result(msg, rr, buf, len);
	}
	return records;
}

/*!
 * \brief Fill the results list with the MX results in order of priority
 * \param domain
 * \param[out] results
 * \retval 0 on success
 * \retval -1 on failure
 * \retval -2 if domain accepts no mail
 */
static int lookup_mx_all(const char *domain, struct stringlist *results)
{
	unsigned char answer[PACKETSZ] = "";
	char domainbuf[256];
	struct mx_records mxs; /* No need to bother locking this list, nobody else knows about it */
	int res;
	struct mx_record *mx;
	int added = 0;
	ns_msg msg;
	int i;

	if (strlen_zero(domain)) {
		bbs_error("Missing domain\n");
		return -1;
	}
	if (*domain == '[') {
		/* Probably begins a domain literal */
		domain++;
		if (!strlen_zero(domain)) {
			bbs_strncpy_until(domainbuf, domain, sizeof(domainbuf), ']');
			domain = domainbuf;
		}
	}
	if (bbs_hostname_is_ipv4(domain)) { /* IP address? Just send it there */
		stringlist_push_tail(results, domain);
		return 0;
	}

	res = res_query(domain, C_IN, T_MX, answer, sizeof(answer));
	if (res == -1) {
		bbs_warning("res_query failed for '%s': %s\n", domain, hstrerror(h_errno)); /* res_query sets h_errno, not errno */
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

	RWLIST_HEAD_INIT(&mxs);

	/* Add each record to our sorted list */
	for (i = 0; i < res; i++) {
#ifdef DEBUG_DNS_REPLIES
		char dispbuf[PACKETSZ] = "";
#endif
		char hostname[256] = "";
		ns_rr rr;
		int priority;

		if (ns_parserr(&msg, ns_s_an, i, &rr)) {
			continue;
		}
#ifdef DEBUG_DNS_REPLIES
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* ns_sprintrr deprecated */
		ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
#pragma GCC diagnostic pop /* -Wdeprecated-declarations */
		bbs_debug(8, "NS answer: %s\n", dispbuf);
#endif /* DEBUG_DNS_REPLIES */

		if (ns_rr_type(rr) != T_MX) {
			bbs_debug(3, "Skipping non-MX record\n");
			continue;
		}

		priority = (int) ns_get16(ns_rr_rdata(rr)); /* Note that 0 is a valid (and the highest) priority */
		if (copy_ns_result(msg, rr, hostname, sizeof(hostname))) {
			continue;
		}

		if (!strcmp(hostname, ".")) { /* The record was just a ., which means the domain accepts no mail. */
			RWLIST_REMOVE_ALL(&mxs, entry, free);
			RWLIST_HEAD_DESTROY(&mxs);
			stringlist_empty(results);
			bbs_warning("Domain %s does not accept mail\n", domain);
			return -2;
		}

		/* Insert in order of priority */
		mx = calloc(1, sizeof(*mx) + strlen(hostname) + 1);
		if (ALLOC_FAILURE(mx)) {
			continue;
		}
		strcpy(mx->data, hostname); /* Safe */
		mx->priority = priority;
		bbs_debug(6, "MX record: %s = %d\n", hostname, priority);
		RWLIST_INSERT_SORTED(&mxs, mx, entry, priority);
		added++;
	}

	if (!added) {
		bbs_warning("No MX records available for %s\n", domain);
		RWLIST_HEAD_DESTROY(&mxs);
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

	RWLIST_HEAD_DESTROY(&mxs);
	return 0;
}

static int cli_mx_lookup(struct bbs_cli_args *a)
{
	struct stringlist mxservers;
	int i = 0;
	char *hostname;
	int res;

	stringlist_init(&mxservers);
	res = lookup_mx_all(a->argv[1], &mxservers);
	if (res == -2) {
		bbs_dprintf(a->fdout, "Domain '%s' does not accept mail\n", a->argv[1]);
	} else if (res) {
		bbs_dprintf(a->fdout, "MX lookup for '%s' failed\n", a->argv[1]);
	} else {
		while ((hostname = stringlist_pop(&mxservers))) {
			/* We didn't store the priorities, so we can't print them here, but the order is correct!
			 * (The priorities will show up in the debug log messages as well from lookup_mx_all.) */
			bbs_dprintf(a->fdout, "#%d: %s\n", ++i, hostname);
			free(hostname);
		}
	}
	stringlist_empty_destroy(&mxservers);
	return 0;
}

struct smtp_tx_data {
	char hostname[256];
	char ipaddr[128];
	const char *prot;
	const char *stage;
};

static void smtp_tx_data_reset(struct smtp_tx_data *tx)
{
	tx->hostname[0] = '\0';
	tx->ipaddr[0] = '\0';
	tx->prot = NULL;
	tx->stage = NULL;
}

#ifdef DEBUG_MAIL_DATA
#define debug_data(srcfd, writelen) __debug_data(srcfd, writelen, __LINE__)
static int __debug_data(int srcfd, size_t writelen, int lineno)
{
	/* Some built in dumping is included,
	 * since most connections probably use STARTTLS,
	 * making it more difficult to use tcpdump / tcpflow to debug. */
	/* WARNING: This could malloc a lot of data. Do not define DEBUG_MAIL_DATA in production!
	 * Only compile with it when actively debugging a delivery issue. */
	char *debugbuf;

	if (lseek(srcfd, 0, SEEK_SET) == -1) {
		bbs_error("lseek failed: %s\n", strerror(errno));
		return -1;
	}

	debugbuf = malloc(writelen + 1); /* NUL terminate for bbs_str_contains_bare_lf */
	if (ALLOC_SUCCESS(debugbuf)) {
		ssize_t rres = bbs_timed_read(srcfd, debugbuf, writelen, 50);
		if (rres > 0) {
			int bare_lf;
			debugbuf[writelen] = '\0'; /* NUL terminate for bbs_str_contains_bare_lf */
			bare_lf = bbs_str_contains_bare_lf(debugbuf);
			if (bare_lf) {
				bbs_warning("Line %d: message contains %d bare LF%s and may be rejected by receiving MTA\n", lineno, bare_lf, ESS(bare_lf));
				bbs_debug(7, "Dumping %ld-byte body:\n", rres);
				bbs_dump_mem((const unsigned char*) debugbuf, (size_t) rres);
				free(debugbuf);
				return 1;
			}
		} else if (rres < 0) {
			bbs_error("read failed: %s\n", strerror(errno));
		}
		free(debugbuf);
	}
	return 0;
}
#endif

/*!
 * \brief Attempt to send an external message to another mail transfer agent or message submission agent
 * \param smtp SMTP session. Generally, this will be NULL except for relayed messages, which are typically the only time this is needed.
 * \param tx
 * \param hostname Hostname of mail server
 * \param port Port of mail server
 * \param use_implicit_tls Whether to use Implicit TLS (typically for MSAs on port 465). If 0, STARTTLS will be attempted (but not required unless require_starttls_out = yes)
 * \param allow_starttls Whether to attempt Explicit TLS, if STARTTLS is available. Only applies if use_implicit_tls is 0.
 * \param username SMTP MSA username
 * \param password SMTP MSA password
 * \param sender The MAIL FROM for the message
 * \param recipient A single recipient for RCPT TO
 * \param recipients A list of recipients for RCPT TO. Either recipient or recipients must be specified.
 * \param prepend Data to prepend
 * \param prependlen Length of prepend
 * \param datafd A file descriptor containing the message data (used instead of data/datalen)
 * \param writelen Number of bytes to send
 * \param[out] buf Buffer in which to temporarily store SMTP responses
 * \param len Size of buf.
 * \retval 0 on success, 1 on permanent error, -1 on temporary error, -2 if STARTTLS was attempted and failed (temporary error)
 */
static int __attribute__ ((nonnull (2, 3, 9, 16))) try_send(struct smtp_session *smtp, struct smtp_tx_data *tx, const char *hostname, int port, int use_implicit_tls, int allow_starttls,
	const char *username, const char *password, const char *sender, const char *recipient, struct stringlist *recipients,
	const char *prepend, size_t prependlen, int datafd, size_t writelen, char *buf, size_t len)
{
	int res = -1;
	ssize_t wrote = 0;
	struct bbs_smtp_client smtpclient;
	off_t send_offset;
	char sendercopy[MAX_EMAIL_ADDRESS_LENGTH];
	char *user, *domain, *saslstr = NULL; /* saslstr is scoped here for cleanup */

#define SMTP_EOM "\r\n.\r\n"

	bbs_assert(datafd != -1);
	bbs_assert(writelen > 0);

	/* RFC 5322 3.4.1 allows us to use IP addresses in SMTP as well (domain literal form). They just need to be enclosed in square brackets. */
	safe_strncpy(sendercopy, sender, sizeof(sendercopy));

	/* Properly parse, since if a name is present, in addition to the email address, we must exclude the name in the MAIL FROM */
	if (bbs_parse_email_address(sendercopy, NULL, &user, &domain)) {
		bbs_error("Invalid email address: %s\n", sender);
		return -1;
	}

	if (!strlen_zero(user) && strlen_zero(domain)) {
		/* Can't pass NULL domain to bbs_hostname_is_ipv4 */
		bbs_error("Invalid email address (user=%s, empty domain)\n", user);
		return -1;
	}

#ifdef DEBUG_MAIL_DATA
	/* Dump the DATA of the transaction to the CLI for debugging purposes. */
	if (prepend && prependlen) {
		bbs_dump_mem((const unsigned char*) prepend, prependlen);
	}
	if (debug_data(datafd, 0, writelen)) {
		/* Proactively reject the message ourselves,
		 * before even establishing a connection to another MTA,
		 * which would make us look bad. */
		if (strstr(hostname, "me.com") || strstr(hostname, "icloud.com")) {
			snprintf(buf, len, "Bare <LF> detected (in DATA command)");
			return 1; /* Return permanent failure */
		}
	}
	bbs_dump_mem((const unsigned char*) SMTP_EOM, STRLEN(SMTP_EOM));
#endif

	tx->prot = "x-tcp";
	if (bbs_smtp_client_connect(&smtpclient, smtp_hostname(), hostname, port, use_implicit_tls, buf, len)) {
		/* Unfortunately, we can't try an alternate port as there is no provision
		 * for letting other SMTP MTAs know that they should try some port besides 25.
		 * So if your ISP blocks incoming traffic on port 25 or you can't use port 25
		 * for whatever reason, you're kind of out luck: you won't be able to receive
		 * mail from the outside world. */
		snprintf(buf, len, "Connection refused");
		return -1;
	}

	smtp_tx_data_reset(tx);
	bbs_get_fd_ip(smtpclient.client.fd, tx->ipaddr, sizeof(tx->ipaddr));
	safe_strncpy(tx->hostname, hostname, sizeof(tx->hostname));

	bbs_debug(3, "Attempting delivery of %lu-byte message from %s -> %s via %s\n", writelen, sender, recipient, hostname);

	SMTP_CLIENT_EXPECT_FINAL(&smtpclient, MIN_MS(5), "220"); /* RFC 5321 4.5.3.2.1 (though for final 220, not any of them) */

	res = bbs_smtp_client_handshake(&smtpclient, require_starttls_out);
	if (res) {
		goto cleanup;
	}

	tx->prot = "smtp";

	if (!use_implicit_tls) {
		if (allow_starttls) {
			if (smtpclient.caps & SMTP_CAPABILITY_STARTTLS) {
				if (!ssl_available() && require_starttls_out) {
					bbs_warning("Encryption is mandatory, but TLS module is not loaded. Delivery failed.\n");
					snprintf(buf, len, "TLS subsystem is unavailable");
					res = -2;
					goto cleanup;
				} else if (bbs_smtp_client_starttls(&smtpclient)) {
					res = -2;
					goto cleanup; /* Abort if we were told STARTTLS was available but failed to negotiate. */
				}
			} else if (require_starttls_out) {
				bbs_warning("SMTP server %s does not support STARTTLS, but encryption is mandatory. Delivery failed.\n", hostname);
				snprintf(buf, len, "STARTTLS not supported");
				res = 1;
				goto cleanup;
			} else if (!bbs_address_nonpublic(hostname)) { /* Don't emit this warning for non-public IPs */
				bbs_warning("SMTP server %s does not support STARTTLS. This message will not be transmitted securely!\n", hostname);
			}
		} else {
			/* If STARTTLS isn't allowed, this is the case where we already made a pass and tried STARTTLS and
			 * delivery failed across all servers, and at least one of the failures was due to STARTTLS failing.
			 * It's possible delivery will succeed if we try plain text delivery.
			 * However, we won't do a retry if require_starttls_out is true, so that should never be true here. */
			bbs_assert(!require_starttls_out);
		}
	}

	if (smtpclient.maxsendsize && (int) (prependlen + writelen) > smtpclient.maxsendsize) {
		/* We know the message we're trying to send is larger than the max message size the server will accept.
		 * Just abort now. */
		bbs_warning("Total message size (%lu) is larger than server accepts (%d)\n", prependlen + writelen, smtpclient.maxsendsize);
		snprintf(buf, len, "Message too large (%lu bytes, maximum is %d)", prependlen + writelen, smtpclient.maxsendsize);
		res = 1;
		goto cleanup;
	}

	if (username && password) {
		if (STARTS_WITH(password, "oauth:")) { /* OAuth authentication */
			char token[4096];
			char decoded[4096];
			int decodedlen, encodedlen;
			char *encoded;
			const char *oauthprofile = password + STRLEN("oauth:");

			if (!(smtpclient.caps & SMTP_CAPABILITY_AUTH_XOAUTH2)) {
				bbs_warning("SMTP server does not support XOAUTH2\n");
				snprintf(buf, len, "XOAUTH2 not supported");
				res = -1;
				goto cleanup;
			} else if (!smtp || !smtp_node(smtp) || !bbs_user_is_registered(smtp_node(smtp)->user)) {
				bbs_warning("Cannot look up OAuth tokens without an authenticated SMTP session\n");
				res = -1;
				goto cleanup;
			}

			/* Typically, smtp is NULL, except for relayed mail.
			 * This means this functionality here only works for relayed mail (from MailScript RELAY rule).
			 * The reason we need it in this case is to ensure that the oauth: profile specified by the user
			 * is one that the user is actually authorized to use. */
			res = bbs_get_oauth_token(smtp_node(smtp)->user, oauthprofile, token, sizeof(token));
			if (res) {
				bbs_warning("OAuth token '%s' does not exist for user %d\n", oauthprofile, smtp_node(smtp)->user->id);
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
			bbs_smtp_client_send(&smtpclient, "AUTH XOAUTH2 %s\r\n", encoded);
			free(encoded);
			res = bbs_tcp_client_expect(&smtpclient.client, "\r\n", 1, SEC_MS(5), "235");
			if (res) {
				/* If we get 334 here, that means we failed: https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange
				 * We should send an empty reply to get the error message. */
				if (STARTS_WITH(buf, "334")) {
					bbs_smtp_client_send(&smtpclient, "\r\n");
					SMTP_EXPECT(&smtpclient, SEC_MS(5), "235"); /* We're not actually going to get a 235, but send the error to the console and abort */
					bbs_warning("Huh? It worked?\n"); /* Shouldn't happen */
				} else {
					bbs_warning("Expected '%s', got: %s\n", "235", buf);
					goto cleanup;
				}
			}
		} else if (smtpclient.caps & SMTP_CAPABILITY_AUTH_PLAIN) {
			saslstr = bbs_sasl_encode(username, username, password);
			if (!saslstr) {
				res = -1;
				goto cleanup;
			}
			bbs_smtp_client_send(&smtpclient, "AUTH PLAIN\r\n"); /* AUTH PLAIN is preferred to the deprecated AUTH LOGIN */
			SMTP_EXPECT(&smtpclient, SEC_MS(10), "334");
			bbs_smtp_client_send(&smtpclient, "%s\r\n", saslstr);
			SMTP_EXPECT(&smtpclient, SEC_MS(10), "235");
		} else if (smtpclient.caps & SMTP_CAPABILITY_AUTH_LOGIN) {
			char *encoded;
			int encodedlen;
			/* AUTO LOGIN is obsoleted in favor of AUTH PLAIN, so only use as last resort */
			bbs_smtp_client_send(&smtpclient, "AUTH LOGIN\r\n");

			/* In both cases, we free before SMTP_EXPECT to avoid memory leaks on failure. */

			/* Send username */
			SMTP_EXPECT(&smtpclient, SEC_MS(10), "334");
			encoded = base64_encode(username, (int) strlen(username), &encodedlen);
			if (!encoded) {
				bbs_error("Base64 encoding failed\n");
				res = -1;
				goto cleanup;
			}
			bbs_smtp_client_send(&smtpclient, "%s\r\n", encoded);
			free(encoded);

			/* Send password */
			SMTP_EXPECT(&smtpclient, SEC_MS(10), "334");
			encoded = base64_encode(password, (int) strlen(password), &encodedlen);
			if (!encoded) {
				bbs_error("Base64 encoding failed\n");
				res = -1;
				goto cleanup;
			}
			bbs_smtp_client_send(&smtpclient, "%s\r\n", encoded);
			bbs_memzero(encoded, strlen(encoded)); /* Destroy encoded password */
			free(encoded);

			SMTP_EXPECT(&smtpclient, SEC_MS(10), "235");
		} else {
			bbs_warning("No mutual login methods available\n");
			res = -1;
			goto cleanup;
		}
	}

	tx->prot = "smtp";
	tx->stage = "MAIL FROM";
	if (!strlen_zero(user)) {
		if (bbs_hostname_is_ipv4(domain)) {
			bbs_smtp_client_send(&smtpclient, "MAIL FROM:<%s@[%s]>\r\n", user, domain); /* Domain literal for IP address */
		} else {
			bbs_smtp_client_send(&smtpclient, "MAIL FROM:<%s@%s>\r\n", user, domain); /* sender lacks <>, but recipient has them */
		}
	} else {
		/* For non-delivery / postmaster sending */
		bbs_smtp_client_send(&smtpclient, "MAIL FROM:<>\r\n");
	}
	SMTP_CLIENT_EXPECT_FINAL(&smtpclient, MIN_MS(5), "250"); /* RFC 5321 4.5.3.2.2 */
	tx->stage = "RCPT FROM";
	if (recipient) {
		if (*recipient == '<') {
			bbs_smtp_client_send(&smtpclient, "RCPT TO:%s\r\n", recipient);
		} else {
			bbs_warning("Queue file recipient did not contain <>\n"); /* Support broken queue files, but make some noise */
			bbs_smtp_client_send(&smtpclient, "RCPT TO:<%s>\r\n", recipient);
		}
		SMTP_CLIENT_EXPECT_FINAL(&smtpclient, MIN_MS(5), "250"); /* RFC 5321 4.5.3.2.3 */
	} else if (recipients) {
		char *r;
		while ((r = stringlist_pop(recipients))) {
			bbs_smtp_client_send(&smtpclient, "RCPT TO:%s\r\n", r);
			SMTP_CLIENT_EXPECT_FINAL(&smtpclient, MIN_MS(5), "250"); /* RFC 5321 4.5.3.2.3 */
			free(r);
		}
	} else {
		bbs_error("No recipients specified\n");
		goto cleanup;
	}
	tx->stage = "DATA";
	bbs_smtp_client_send(&smtpclient, "DATA\r\n");
	SMTP_CLIENT_EXPECT_FINAL(&smtpclient, MIN_MS(2), "354"); /* RFC 5321 4.5.3.2.4 */
	if (prepend && prependlen) {
		wrote = bbs_write(smtpclient.client.wfd, prepend, (unsigned int) prependlen);
	}

	/* sendfile will be much more efficient than reading the file ourself, as email body could be quite large, and we don't need to involve userspace. */
	send_offset = 0;
	res = (int) bbs_sendfile(smtpclient.client.wfd, datafd, &send_offset, writelen);

	/* XXX If email doesn't end in CR LF, we need to tack that on. But ONLY if it doesn't already end in CR LF. */
	bbs_smtp_client_send(&smtpclient, SMTP_EOM); /* (end of) EOM */
	tx->stage = "end of DATA";
	if (res != (int) writelen) { /* Failed to write full message */
		res = -1;
		goto cleanup;
	}
	wrote += res;
	bbs_debug(5, "Sent %lu bytes\n", wrote);
	/* RFC 5321 4.5.3.2.6 */
	SMTP_CLIENT_EXPECT_FINAL(&smtpclient, MIN_MS(10), "250"); /* Okay, this email is somebody else's problem now. */

	if (recipient) {
		bbs_debug(3, "Message successfully delivered to %s\n", recipient);
	} else { /* recipients (which are already freed now) */
		bbs_debug(3, "Message successfully delivered\n");
	}
	res = 0;

cleanup:
	free_if(saslstr);
	if (res > 0) {
		bbs_smtp_client_send(&smtpclient, "QUIT\r\n");
	}
	bbs_smtp_client_destroy(&smtpclient);

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

static void smtp_trigger_dsn(struct smtp_session_info *sinfo, enum smtp_delivery_action action, struct smtp_tx_data *restrict tx, struct tm *created, const char *from, const char *to, char *error, int fd, size_t datalen, int attempt_number)
{
	char *tmp;
	char status[15] = ""; /* Status code should be the 2nd word? */
	struct smtp_delivery_outcome *f;

	if (strlen_zero(from)) {
		/* If this was triggered by a non-delivery report,
		 * then bail out now, since we can't
		 * reply if there was no MAIL FROM */
		return;
	}

	if (action == DELIVERY_DELIVERED) {
		/* Don't send reports on success UNLESS a message was previously delayed */
		if (!attempt_number) {
			return;
		}
	} else if (action != DELIVERY_FAILED && !notify_queue) {
		return;
	}

	tmp = strchr(error, ' ');
	if (tmp && ++tmp) {
		ltrim(tmp);
		if (isdigit(*tmp)) {
			bbs_strncpy_until(status, error, sizeof(status), ' ');
		}
	}

	f = smtp_delivery_outcome_new(to, tx->hostname, tx->ipaddr, status, error, tx->prot, tx->stage, action, NULL);
	if (ALLOC_SUCCESS(f)) {
		smtp_dsn(sinfo, created, from, fd, datalen, &f, 1);
		smtp_delivery_outcome_free(&f, 1);
	}
}

enum mailq_run_type {
	QUEUE_RUN_PERIODIC,		/*!< Periodic queue run */
	QUEUE_RUN_FORCED,		/*!< On-demand queue run */
	QUEUE_RUN_STAT,			/*!< Not a real queue run, just for statistical purposes */
};

/*! \brief A single run of the mail queue */
struct mailq_run {
	enum mailq_run_type type;
	time_t runstart;	/* Time that queue run started */
	struct bbs_parallel *parallel;	/* Parallel task set, if running in parallel. NULL if serial. */
	/* Queue run filters to control what messages are processed */
	const char *match_filename; /* Exact filename match */
	const char *host_match;	/* Domain restriction for queue processing */
	const char *host_ends_with;	/* Domain or suffix of domain, e.g. com, example.com, sub.example.com, etc. Queued processing will be restricted to matches. */
	/* Queue run statistics */
	/* processed is a subset of total, delivered + failed + delayed + skipped should = processed */
	int total;			/* Total number of queued messages considered */
	int processed;		/* Total number of queued messages processed. */
	int delivered;		/* Total number of queued messages actually delivered and removed from queue. */
	int failed;			/* Total number of queued messages failed permanently and removed from queue. */
	int delayed;		/* Total number of queued messages not yet delivered and remaining in queue. */
	int skipped;		/* Total number of queued messages skipped since it's too soon to retry delivery. */
	/* Misc */
	int clifd;				/* CLI file descriptor */
	bbs_mutex_t lock;
};

static void mailq_run_init(struct mailq_run *qrun, enum mailq_run_type type)
{
	/* We could individually initialize each element in the struct,
	 * but as the struct probably has no padding,
	 * it's probably faster to just zero the whole darn thing. */
	memset(qrun, 0, sizeof(struct mailq_run));
	qrun->type = type;
	bbs_mutex_init(&qrun->lock, NULL);
	qrun->runstart = time(NULL);
}

static void mailq_run_cleanup(struct mailq_run *qrun)
{
	bbs_mutex_destroy(&qrun->lock);
}

#define MAILQ_FILENAME_SIZE 516

/*! \brief A single message in the mail queue */
struct mailq_file {
	FILE *fp;	/*!< File handle for data file */
	FILE *cfp;	/*!< File handle for control file */
	unsigned long size;
	char *realfrom, *realto;
	char *user, *domain;
	int retries;		/*!< Number of times retried so far */
	struct tm created;	/*!< Time message was added to the queue */
	struct tm retried;	/*!< Time message delivery was last attempted */
	time_t createdtime;	/*!< time_t of created */
	time_t retriedtime;	/*!< time_t of retried */
	char controlfile[MAILQ_FILENAME_SIZE];
	char datafile[MAILQ_FILENAME_SIZE];
	char sourceip[55];
	char from[MAX_EMAIL_ADDRESS_LENGTH + 1];
	char recipient[MAX_EMAIL_ADDRESS_LENGTH + 1];
	char todup[MAX_EMAIL_ADDRESS_LENGTH + 1];
	struct mailq_run *qrun;	/*!< mailq_run to which this mailq_file belongs */
	struct smtp_session_info sinfo;
	unsigned int purge:1; /*!< Purge message */
};

static inline void mailq_file_init(struct mailq_file *mqf, struct mailq_run *qrun)
{
	memset(mqf, 0, sizeof(struct mailq_file));
	mqf->qrun = qrun;
}

/*! \brief Cleanup callback called for parallel invocations */
static void mailq_file_destroy(void *varg)
{
	struct mailq_file *mqf = varg;
	/* If the file is still open, close it.
	 * Normally, we always close the file in process_queue_file,
	 * so this would only happen if allocating the task itself failed for some reason,
	 * and we had to abort and call the cleanup function. */
	if (mqf->fp) {
		fclose(mqf->fp);
	}
	if (mqf->cfp) {
		fclose(mqf->cfp);
	}
	free(mqf);
}

static void mqf_file_cleanup(struct mailq_file *mqf)
{
	fclose(mqf->cfp);
	fclose(mqf->fp);
	mqf->cfp = mqf->fp = NULL; /* For parallel task framework, since cleanup is always called */
}

/*! \brief Delete a message's control file and data file (after successful delivery, permanent failure, or retries exceeded) */
static void mqf_file_purge(struct mailq_file *mqf)
{
	bbs_delete_file(mqf->controlfile);
	bbs_delete_file(mqf->datafile);
}

static void reset_accessed_time(struct mailq_file *restrict mqf)
{
	struct utimbuf utb;

	/* Since we didn't process this file for queuing,
	 * we reset the access timestamp to what it was
	 * before we accessed it. This allows us to accurately
	 * keep track of when delivery should be attempted next,
	 * without storing the timestamp explicitly anywhere else. */

	/* We have to specify both times explicitly, not just one. */
	utb.modtime = mqf->createdtime;
	utb.actime = mqf->retriedtime;

	if (utime(mqf->datafile, &utb)) {
		bbs_error("Failed to set file timestamps for %s: %s\n", mqf->datafile, strerror(errno));
	}
}

static int seek_to_beginning_of_line(FILE *fp)
{
	int gotcolon = 0;
	for (;;) {
		int c;
		if (fseek(fp, -1L, SEEK_CUR)) {
			bbs_error("fseek failed: %s\n", strerror(errno));
			return -1;
		}
		c = fgetc(fp);
		if (c == ':') {
			gotcolon = 1;
		}
		if ((c == '\n' && gotcolon) || ftell(fp) == 0) {
			break;
		}
		ungetc(c, fp);
	}
	return 0;
}

/*! \brief Increment Delivery-Attempts directive in control file */
static int mailq_file_punt(struct mailq_file *mqf)
{
	char buf[64];
	char datebuf[32];
	int last_retry = 0;

	/* Seek to the beginning of the control file */
	if (fseek(mqf->cfp, 0, SEEK_SET)) {
		bbs_error("fseek failed: %s\n", strerror(errno));
		return -1;
	}

	smtp_timestamp(time(NULL), datebuf, sizeof(datebuf));

	/* Currently, there are up to two mutable fields (Delivery-Attempts and Last-Retry-Time).
	 * First, look for Last-Retry-Time, since if it's not present, we'll need to add this header,
	 * and the file will expand and subsequent lines (e.g. Delivery-Attempts) will need to be rewritten. */
	while (fgets(buf, sizeof(buf), mqf->cfp)) {
		if (STARTS_WITH(buf, "Last-Retry-Time:")) {
			if (seek_to_beginning_of_line(mqf->cfp)) {
				return -1;
			}
			fprintf(mqf->cfp, "Last-Retry-Time: %s\n", datebuf);
			last_retry = 1;
			break;
		}
	}
	if (!last_retry) {
		/* We need to add the header. Add it before Delivery-Attempts and rewrite that header,
		 * so that in the future, we only need to rewrite that header.
		 * Also added for compatibility with control files without a Last-Retry-Time header. */
		if (seek_to_beginning_of_line(mqf->cfp)) { /* Already at EOF, back up */
			return -1;
		}
		fprintf(mqf->cfp, "Last-Retry-Time: %s\n", datebuf);
		fprintf(mqf->cfp, "Delivery-Attempts: %d\n", mqf->retries + 1);
	} else {
		/* Just update Delivery-Attempts, which should be the last line present. */
		if (fseek(mqf->cfp, 0, SEEK_END)) {
			bbs_error("fseek failed: %s\n", strerror(errno));
			return -1;
		}
		if (seek_to_beginning_of_line(mqf->cfp)) {
			return -1;
		}
		fprintf(mqf->cfp, "Delivery-Attempts: %d\n", mqf->retries + 1);
	}

	return 0;
}

/* Do not define IMPLICIT_TIMESTAMPS, as timestamps can change for reasons out of our control and may not be reliable.
 * The queue control file now stores the timestamps explicitly. */

static int mailq_file_load(struct mailq_file *restrict mqf, const char *dir_name, const char *controlfile)
{
	char buf[256];
	struct stat st;
	struct tm tm;
	char *val;

#ifndef IMPLICIT_TIMESTAMPS
	memset(&st, 0, sizeof(st));
#endif

	/* First, parse everything out of the control file */
	snprintf(mqf->controlfile, sizeof(mqf->controlfile), "%s/%s", dir_name, controlfile);
	mqf->cfp = fopen(mqf->controlfile, "r+"); /* when updating Delivery-Attempts on a temporary failure, we'll need to edit */
	if (!mqf->cfp) {
		bbs_error("Failed to open %s: %s\n", mqf->controlfile, strerror(errno));
		return -1;
	}
	while ((val = fgets(buf, sizeof(buf), mqf->cfp))) {
		char *key;
		bbs_term_line(val); /* Terminate line since fgets leaves newlines intact */
		key = strsep(&val, ":");
		if (!strlen_zero(val)) {
			ltrim(val);
		}
		if (strlen_zero(key) || strlen_zero(val)) {
			bbs_warning("Invalid data in control file: '%s' = '%s'\n", S_IF(key), S_IF(val)); /* Warn but ignore */
		} else if (!strcmp(key, "Source-IP")) {
			safe_strncpy(mqf->sourceip, val, sizeof(mqf->sourceip));
		} else if (!strcmp(key, "SMTP-Hostname")) {
			safe_strncpy(mqf->sinfo.helohost, val, sizeof(mqf->sinfo.helohost));
		} else if (!strcmp(key, "Source-Local")) {
			SET_BITFIELD(mqf->sinfo.fromlocal, atoi(val));
		} else if (!strcmp(key, "SMTP-Submission")) {
			SET_BITFIELD(mqf->sinfo.msa, atoi(val));
		} else if (!strcmp(key, "Envelope-Sender")) {
			safe_strncpy(mqf->from, val, sizeof(mqf->from));
		} else if (!strcmp(key, "Envelope-Recipient")) {
			safe_strncpy(mqf->recipient, val, sizeof(mqf->recipient));
		} else if (!strcmp(key, "Data-File")) {
			safe_strncpy(mqf->datafile, val, sizeof(mqf->datafile));
		} else if (!strcmp(key, "Arrival-Time")) {
			memset(&tm, 0, sizeof(tm));
			if (!strptime(val, "%a, %b %e %Y %H:%M:%S %z", &tm)) {
				bbs_error("Failed to parse date: %s\n", val);
			}
			st.st_mtim.tv_sec = mktime(&tm);
			if (st.st_mtim.tv_sec < 0) {
				bbs_error("mktime failed: %s\n", strerror(errno));
			}
		} else if (!strcmp(key, "Last-Retry-Time")) {
			memset(&tm, 0, sizeof(tm));
			if (!strptime(val, "%a, %b %e %Y %H:%M:%S %z", &tm)) {
				bbs_error("Failed to parse date: %s\n", val);
			}
			st.st_atim.tv_sec = mktime(&tm);
			if (st.st_atim.tv_sec < 0) {
				bbs_error("mktime failed: %s\n", strerror(errno));
			}
		} else if (!strcmp(key, "Delivery-Attempts")) {
			mqf->retries = atoi(val);
		} else {
			bbs_warning("Ignoring invalid control directive '%s' in %s\n", key, controlfile);
		}
	}
	/* Leave mqf->cfp open as mailq_file_punt may use it */

#ifdef IMPLICIT_TIMESTAMPS
	/* Do the stat call before opening the file,
	 * since opening it will change the file timestamps. */
	if (stat(mqf->datafile, &st)) {
		bbs_error("stat(%s) failed: %s\n", mqf->datafile, strerror(errno));
		fclose(mqf->cfp);
		return -1;
	}
#endif

	mqf->fp = fopen(mqf->datafile, "rb");
	if (!mqf->fp) {
		bbs_error("Failed to open %s: %s\n", mqf->datafile, strerror(errno));
		fclose(mqf->cfp);
		return -1;
	}

	fseek(mqf->fp, 0L, SEEK_END); /* Go to EOF */
	mqf->size = (long unsigned) ftell(mqf->fp);
	rewind(mqf->fp); /* Be kind, rewind */

	/* The actual MAIL FROM can be empty if this is a nondelivery report, so we do not validate that it is non-empty (it may be the empty string). */
	if (!(mqf->realfrom = strchr(mqf->from, '<'))) {
		bbs_error("Mail queue file MAIL FROM missing <>: %s\n", mqf->datafile);
		goto cleanup;
	} else if (!(mqf->realto = strchr(mqf->recipient, '<'))) {
		bbs_error("Mail queue file RCPT TO missing <>: %s\n", mqf->datafile);
		goto cleanup;
	}

	mqf->realfrom++; /* Skip < */
	if (strlen_zero(mqf->realfrom)) {
		bbs_error("Malformed MAIL FROM: %s\n", mqf->datafile);
		goto cleanup;
	}
	bbs_strterm(mqf->realfrom, '>'); /* try_send will add <> for us, so strip it here to match */

	if (bbs_str_count(mqf->realfrom, '<') || bbs_str_count(mqf->realfrom, '>') || bbs_str_count(mqf->realto, '<') != 1 || bbs_str_count(mqf->realto, '>') != 1) {
		bbs_error("Sender or recipient address malformed %s -> %s\n", mqf->realfrom, mqf->realto);
		goto cleanup;
	}

	safe_strncpy(mqf->todup, mqf->realto, sizeof(mqf->todup));
	if (bbs_parse_email_address(mqf->todup, NULL, &mqf->user, &mqf->domain)) {
		bbs_error("Address parsing error\n");
		goto cleanup;
	}

#ifdef IMPLICIT_TIMESTAMPS
	/* See stat(3) for how stat presents the time.
	 * st_atime = st_atim.tv_sec
	 * st_mtime = st_mtim.tv_sec
	 *
	 * st_atim and st_mtim themselves are of type struct timespec.
	 * st_atime and st_mtime (and the tv_sec components) are time_t.
	 *
	 * To debug timestamps, can print created, access, modified, status change:
	 * stat -c '%w %x %y %z' /home/bbs/maildir/mailq/new/QUEUEID.d
	 */
#endif

	/* These are useful for doing time calculations */
	mqf->createdtime = st.st_mtim.tv_sec;
	mqf->retriedtime = st.st_atim.tv_sec;
	if (mqf->createdtime <= 0) {
		bbs_warning("Message %s missing creation time\n", controlfile);
	}
	/* It could be missing the last modification time if there's no Last-Retry-Time header */

	/* These variants are more useful for printing timestamps */
	memset(&mqf->created, 0, sizeof(mqf->created));
	memset(&mqf->retried, 0, sizeof(mqf->retried));
	/* st_mtim is the time of the last modifications.
	 * We don't modify queue files after they are created,
	 * (renaming does not update this timestamp)
	 * so this should be when the file was created,
	 * i.e. when the message was added to the queue. */
	localtime_r(&st.st_mtim.tv_sec, &mqf->created);

	/* Now, for when the message was last attempted.
	 * st_atim is a good candidate for this, since it's
	 * updated whenever the file is accessed, e.g. opened,
	 * so it will update every time it's retried for queuing.
	 * Problem is that if skip_qfile is true, we DIDN'T retry
	 * delivery (and even if not, for QUEUE_RUN_STAT, we didn't retry anything).
	 * So, we need to reset st_atim when we've accessed a queue file
	 * without attempting delivery.
	 *
	 * If people manually open a queue file, that will also update
	 * the timestamp and interfere with this, but otherwise, this covers everything. */
	localtime_r(&st.st_atim.tv_sec, &mqf->retried);

	return 0;

cleanup:
	fclose(mqf->cfp);
	fclose(mqf->fp);
	mqf->fp = NULL;
	/* Okay if file timestamps are updated, since an error happened, anyways */
	return -1;
}

/*! \brief Attempt to send a message via SMTP using static routes instead of doing an MX lookup */
static int __attribute__ ((nonnull (2, 3, 4, 5, 8))) try_static_delivery(struct smtp_session *smtp, struct smtp_tx_data *tx, struct stringlist *static_routes, const char *sender, const char *recipient, int datafd, size_t writelen, char *buf, size_t len)
{
	const char *route;
	struct stringitem *i = NULL;
	int res = -1; /* Make condition true to start */

	/* Static routes override doing an MX lookup for this domain.
	 * We have one or more hostnames (with an optionally specified port) to try. */
	while (res < 0 && (route = stringlist_next(static_routes, &i))) {
		char hostbuf[256];
		const char *colon;
		const char *hostname = route;
		int port = DEFAULT_SMTP_PORT;

		/* If this is a hostname:port, we need to split.
		 * Otherwise, we can use it directly. This is more efficient,
		 * since no allocations or copies are performed in this case. */
		colon = strchr(route, ':');
		if (colon) {
			/* There's a port specified. */
			bbs_strncpy_until(hostbuf, route, sizeof(hostbuf), ':'); /* Copy just the hostname */
			hostname = hostbuf;
			colon++;
			if (!strlen_zero(colon)) {
				port = atoi(colon); /* Parse the port */
				if (port < 1) {
					bbs_warning("Invalid port in route '%s', defaulting to port %d\n", route, DEFAULT_SMTP_PORT);
					port = DEFAULT_SMTP_PORT;
				}
			}
		}

		res = try_send(smtp, tx, hostname, port, 0, 1, NULL, NULL, sender, recipient, NULL, NULL, 0, datafd, writelen, buf, len);
	}
	return res;
}

/*!
 * \brief Attempt to send a message using MX records
 * \param smtp SMTP session. Generally, this will be NULL except for relayed messages, which are typically the only time this is needed.
 * \param tx
 * \param mqf
 * \param mxservers
 * \param sender The MAIL FROM for the message
 * \param recipient A single recipient for RCPT TO
 * \param recipients A list of recipients for RCPT TO. Either recipient or recipients must be specified.
 * \param datafd A file descriptor containing the message data (used instead of data/datalen)
 * \param writelen Number of bytes to send
 * \param[out] buf Buffer in which to temporarily store SMTP responses
 * \param len Size of buf.
 * \retval 0 on success, 1 on permanent error, -1 on temporary error
 * \note This function leaves the items in mxservers intact so they can be used again if needed
 */
static int __attribute__ ((nonnull (2, 3, 4, 5, 6, 9))) try_mx_delivery(struct smtp_session *smtp, struct smtp_tx_data *tx, struct mailq_file *mqf, struct stringlist *mxservers, const char *sender, const char *recipient, int datafd, size_t writelen, char *buf, size_t len)
{
	const char *hostname;
	struct stringitem *i = NULL;
	int start_tls_failures = 0;
	int res = -1; /* Make condition true to start */

	/* Try all the MX servers in order, if necessary */
	while (res < 0 && (hostname = stringlist_next(mxservers, &i))) {
		res = try_send(smtp, tx, hostname, DEFAULT_SMTP_PORT, 0, 1, NULL, NULL, sender, recipient, NULL, NULL, 0, datafd, writelen, buf, len);
		if (res == -2) {
			start_tls_failures++;
			res = -1;
		}
	}

	if (res < 0 && start_tls_failures) {
		/* Delivery failed, but at least one failure was because STARTTLS failed. */
		if (!require_starttls_out) {
			bbs_warning("Reattempting delivery to %s insecurely since STARTTLS failed\n", recipient);
			/* Retry without using STARTTLS.
			 * First, send a delay notification so the sender is aware the message was not delivered securely.
			 * The sender could then choose to notify the recipient's postmaster of the issue, but it's not really our problem. */
			smtp_trigger_dsn(&mqf->sinfo, DELIVERY_DELAYED, tx, &mqf->created, sender, recipient, buf, datafd, writelen, mqf->retries);
			/* Do another pass, but don't attempt STARTTLS.
			 * It's possible delivery will succeed without encryption.
			 * Obviously, this isn't ideal, but most mail servers generally retry delivery without TLS if it fails.
			 * To prevent falling back to plain text, require_starttls_out should be configured to true. */
			i = NULL;
			while (res < 0 && (hostname = stringlist_next(mxservers, &i))) {
				res = try_send(smtp, tx, hostname, DEFAULT_SMTP_PORT, 0, 0, NULL, NULL, sender, recipient, NULL, NULL, 0, datafd, writelen, buf, len);
				bbs_assert(res != -2); /* Since we don't attempt STARTTLS, res should never be -2 */
			}
			if (res == 0) {
				/* Since we send a delayed DSN, if we succeeded, we now need to also send one for success,
				 * or the user will think the message hasn't been able to be delivered. */
				smtp_trigger_dsn(&mqf->sinfo, DELIVERY_DELIVERED, tx, &mqf->created, sender, recipient, buf, datafd, writelen, mqf->retries);
			}
		}
	}

	return res;
}

/*!
 * \brief Calculate how long we should wait, at minimum, before retrying delivery of a requeued message
 * \param retrycount Count of many times delivery has been attempted so far
 * \return Number of seconds that should pass from the last retry before we attempt delivery again
 */
static time_t queue_retry_threshold(int retrycount)
{
	/* We use ~exponential backoff for queue retry timing,
	 * as is generally recommended. */
	switch (retrycount) {
		case 0:
			return 0;
		/* RFC 5321 4.5.4.1 says the retry interval SHOULD be at least 30 minutes,
		 * but if the first delivery failed due to a super transient thing,
		 * it might be good to try a little sooner, at least once or twice.
		 * This is especially true if the other server has greylisted us,
		 * in which case the first retry should succeed. */
		case 1:
			return 60; /* 1 minute */
		case 2:
			return 360; /* 10 minutes */
		case 3:
			return 1800; /* 30 minutes */
		case 4:
			return 3600; /* 1 hour */
		case 5:
			return 10800; /* 3 hours */
		case 6:
			return 43200; /* 12 hours */
		case 7 ... 10:
		/* Per the RFC, the give-up time should be at least 4-5 days.
		 * At this point, it's already been over 4.5 days. */
		default:
			/* As we get to longer periods, cap retry interval at 1 day between attempts. */
			return 86400; /* 1 day */
	}
	__builtin_unreachable();
}

static int skip_qfile(struct mailq_run *qrun, struct mailq_file *mqf, const char *controlfile)
{
	qrun->total++; /* Count messages in queue */

	/* This queue run may have filters applied to it */

	/* Yeah, if we have a filter, we're possibly going to open
	 * all the files in the queue, only to almost immediately close most of them.
	 * One of our assumptions is the queue isn't going to be super large.
	 * If it were, it would very much be worth using a single queue "control file"
	 * with metadata about all the queue files, to avoid unnecessary file I/O. */

	if (!strlen_zero(qrun->match_filename) && strcmp(qrun->match_filename, controlfile)) {
		return 1; /* Exact queue file requested and this isn't it */
	} else if (!strlen_zero(qrun->host_match) && !strlen_zero(mqf->domain) && strcmp(mqf->domain, qrun->host_match)) {
		/* Exact match required */
#ifdef DEBUG_QUEUES
		bbs_debug(8, "Skipping queue file %s (domain '%s' does not match filter '%s')\n", controlfile, mqf->domain, qrun->host_match);
#endif
		return 1;
	} else if (!strlen_zero(qrun->host_ends_with) && !strlen_zero(mqf->domain) && !bbs_str_ends_with(mqf->domain, qrun->host_ends_with)) {
		/* Domain must end in host_ends_with, to match. */
#ifdef DEBUG_QUEUES
		bbs_debug(8, "Skipping queue file %s (domain '%s' does not match filter '*%s')\n", controlfile, mqf->domain, qrun->host_ends_with);
#endif
		return 1;
	}

	/* If QUEUE_RUN_FORCED or QUEUE_RUN_STAT, always process everything.
	 * If QUEUE_RUN_PERIODIC, this is the normal queue retry mechanism.
	 * Since we want to use exponential backoff, every time the periodic queue handler runs,
	 * we don't necessarily want to retry all messages.
	 *
	 * So we'll check what the retry index is currently and check when delivery was last attempted,
	 * and only retry it if we've now exceeded the threshold for our number of retries. */

	if (qrun->type == QUEUE_RUN_PERIODIC) {
		time_t retry_sec_wait;
		time_t now;
		retry_sec_wait = queue_retry_threshold(mqf->retries);

		/* XXX Because the queue handler retries delivery of all messages in the queue sequentially,
		 * we have to check the time for each message, since delivery of a particular message
		 * could take a bit, so the time for each message might be different.
		 * If we parallelize the queue handler in the future,
		 * then we could only get the time for each batch of threads we create, to make this more efficient. */
		now = time(NULL);

		if (mqf->retriedtime + retry_sec_wait > now) {
			/* It's been too soon since the last retry. */
#ifdef DEBUG_QUEUES
			bbs_debug(8, "Skipping queue file %s (last retry was %ld s ago, waiting at least %ld s longer)\n", controlfile, now - mqf->retriedtime, mqf->retriedtime + retry_sec_wait - now);
#endif
			return 1;
		}
	}

	return 0;
}

/* If processing in parallel, multiple queue files could be processed simultaneously,
 * so we need to make sure increments are atomic.
 * If not parallel, everything is serial, and there is no need to lock and unlock. */
#define QUEUE_INCR_STAT(field) \
	if (qrun->parallel) { \
		bbs_mutex_lock(&qrun->lock); \
	} \
	qrun->field++; \
	if (qrun->parallel) { \
		bbs_mutex_unlock(&qrun->lock); \
	}

static int process_queue_file(struct mailq_run *qrun, struct mailq_file *mqf)
{
	int res = -1;
	char buf[256] = "";
	struct stringlist *static_routes;
	struct smtp_tx_data tx;
	time_t message_age;
	int attempts = mqf->retries + 1;

	memset(&tx, 0, sizeof(tx));

	QUEUE_INCR_STAT(processed);

	message_age = time(NULL) - mqf->createdtime;
	if (mqf->purge) {
		goto permfail;
	} else if (mqf->retries >= (int) max_retries) {
		bbs_warning("Message %s has already been processed %d times\n", mqf->datafile, mqf->retries); /* If it's still in queue, it shouldn't have reached max retries yet */
	}

	static_routes = get_static_routes(mqf->domain);
	bbs_debug(2, "Processing message %s (<%s> -> %s), via %s for '%s'\n", mqf->datafile, mqf->realfrom, mqf->realto, static_routes ? "static route(s)" : "MX lookup", mqf->domain);
	if (static_routes) {
		if (stringlist_is_empty(static_routes)) {
			/* In theory, should never happen */
			bbs_error("No static routes available for delivery to %s?\n", mqf->domain);
			mqf_file_cleanup(mqf); /* For parallel task framework, since cleanup is always called */
			return 0;
		} else {
			res = try_static_delivery(NULL, &tx, static_routes, mqf->realfrom, mqf->realto, fileno(mqf->fp), mqf->size, buf, sizeof(buf));
		}
	} else {
		struct stringlist mxservers;
		stringlist_init(&mxservers);
		res = lookup_mx_all(mqf->domain, &mxservers);
		if (res == -2) {
			smtp_tx_data_reset(&tx);
			/* Do not set tx.hostname, since this message is from us, not the remote server */
			snprintf(buf, sizeof(buf), "Domain does not accept mail");
		} else {
			if (res) {
				char a_ip[256];
				/* Fall back to trying the A record */
				if (bbs_resolve_hostname(mqf->domain, a_ip, sizeof(a_ip))) {
					bbs_warning("Recipient domain %s does not have any MX or A records\n", mqf->domain);
					/* Just treat as undeliverable at this point and return to sender (if no MX records now, probably won't be any the next time we try) */
					/* Send a delivery failure response, then delete the file. */
					bbs_warning("Delivery of message %s from <%s> to %s has failed permanently (no MX records)\n", mqf->datafile, mqf->realfrom, mqf->realto);
					/* There isn't any SMTP level error at this point yet, we have to make our own error message for the bounce message */
					snprintf(buf, sizeof(buf), "No MX record(s) located for hostname %s", mqf->domain); /* No status code */
					smtp_tx_data_reset(&tx);
					/* Do not set tx.hostname, since this message is from us, not the remote server */
					smtp_trigger_dsn(&mqf->sinfo, DELIVERY_FAILED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->size, mqf->retries);
					mqf_file_cleanup(mqf);
					mqf_file_purge(mqf);
					QUEUE_INCR_STAT(failed);
					return 0;
				}
				bbs_warning("Recipient domain %s does not have any MX records, falling back to A record %s\n", mqf->domain, a_ip);
				stringlist_push(&mxservers, a_ip);
			}

			res = try_mx_delivery(NULL, &tx, mqf, &mxservers, mqf->realfrom, mqf->realto, fileno(mqf->fp), mqf->size, buf, sizeof(buf));
			stringlist_empty_destroy(&mxservers);
		}
	}

	if (!res) { /* Successful delivery. */
		bbs_debug(6, "Delivery successful after %d attempt%s, discarding queue file\n", attempts, ESS(attempts));
		bbs_smtp_log(4, NULL, "Delivery succeeded after queuing: <%s> -> %s (%s)\n", mqf->realfrom, mqf->realto, buf);
		smtp_trigger_dsn(&mqf->sinfo, DELIVERY_DELIVERED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->size, mqf->retries);
		mqf_file_cleanup(mqf);
		mqf_file_purge(mqf);
		QUEUE_INCR_STAT(delivered);
	} else if (res == -2 || res > 0 || attempts >= (int) max_retries) { /* Permanent failure or retries exceeded */
permfail:
		/* Send a delivery failure response, then delete the file. */
		bbs_warning("Delivery of message <%s> from %s to %s has failed permanently after %d attempt%s\n", mqf->datafile, mqf->realfrom, mqf->realto, attempts, ESS(attempts));
		bbs_smtp_log(1, NULL, "Delivery failed permanently after queuing: <%s> -> %s (%s)\n", mqf->realfrom, mqf->realto, buf);
		/* To the dead letter office we go */
		/* XXX buf will only contain the last line of the SMTP transaction, since it was using the readline buffer
		 * Thus, if we got a multiline error, only the last line is currently included in the non-delivery report */
		smtp_trigger_dsn(&mqf->sinfo, DELIVERY_FAILED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->size, mqf->retries);
		mqf_file_cleanup(mqf);
		mqf_file_purge(mqf);
		QUEUE_INCR_STAT(failed);
	} else { /* Delivery deferred due to temporary failure */
		if (message_age > max_age) {
			bbs_warning("Message expired while in queue (message created at %" TIME_T_FMT ", now %" TIME_T_FMT "/%d s old)\n", mqf->createdtime, message_age, max_age);
			goto permfail;
		}
		bbs_debug(3, "Delivery of %s to %s has been attempted %d/%d times\n", mqf->datafile, mqf->realto, attempts, max_retries);
		bbs_smtp_log(3, NULL, "Delivery delayed after queuing: <%s> -> %s (%s)\n", mqf->realfrom, mqf->realto, buf);
		mailq_file_punt(mqf); /* Try again later */
		smtp_trigger_dsn(&mqf->sinfo, DELIVERY_DELAYED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->size, mqf->retries);
		QUEUE_INCR_STAT(delayed);
		mqf_file_cleanup(mqf);
	}
	return 0;
}

static int parallel_process_queue_file_cb(void *data)
{
	struct mailq_file *mqf = data;
	return process_queue_file(mqf->qrun, mqf);
}

/*! \brief Primary callback to process each queue file */
static int on_queue_file(const char *dir_name, const char *controlfile, void *obj)
{
	struct mailq_run *qrun = obj;
	struct mailq_file mqf_stack, *mqf = &mqf_stack;

	if (qrun->parallel) {
		/* Heap allocate since we'll need this after we return */
		mqf = calloc(1, sizeof(struct mailq_file)); /* malloc instead of calloc since mailq_file_init will memset regardless */
		if (ALLOC_FAILURE(mqf)) {
			return 0;
		}
	}

	mailq_file_init(mqf, qrun);

	/* Whether we're processing the queue in parallel or not,
	 * we always do this stuff sequentially.
	 * In the parallel case, in particular if we have a filter,
	 * we may not even end up processing most files in the queue.
	 * It would be extremely wasteful to create a task for everything,
	 * only to abort most of them because we're going to skip the file.
	 * Therefore, synchronously check what will need to be processed first,
	 * since that doesn't take an appreciable amount of time,
	 * and only create a task if we're actually going to process it.
	 * This also allows us to avoid locking for incrementing total here. */

	bbs_assert_exists(qrun);

	if (mailq_file_load(mqf, dir_name, controlfile)) {
		/* If a queue is malformed, this will continue indefinitely,
		 * since we never increment its retry count.
		 * The sysop will need to manually remove the broken queued message. */
		return 0;
	} else if (skip_qfile(qrun, mqf, controlfile)) {
		qrun->skipped++; /* No need to use the QUEUE_INCR_STAT wrapper for locking since this is pre-parallel portion */
		mqf_file_cleanup(mqf); /* Not necessary to set mqf->fp to NULL, since we're not calling mailq_file_destroy */
		/* Not sure when the access times are changed: when the file is opened, or closed, or both,
		 * but just to be completely safe, we only reset the timestamps after closing. */
		reset_accessed_time(mqf);
		return 0;
	}

	if (qrun->parallel) {
		/* Schedule the task now but return immediately:
		 * controlfile: Every queue file is allowed to be processed in parallel, so use a unique prefix for each queue file, e.g. the controlfile works great.
		 * mqf: Only a single callback argument can be provided, but mqf has a reference to qrun
		 * duplicate: NULL, since we already heap allocated.
		 * cleanup: We do need to clean up the heap allocated structure, even though we didn't duplicate it */
		bbs_parallel_schedule_task(qrun->parallel, controlfile, mqf, parallel_process_queue_file_cb, NULL, mailq_file_destroy);
	} else {
		/* Process the queued message now, synchronously */
		process_queue_file(qrun, mqf);
	}
	return 0; /* Return 0 regardless of individual task success, to continue processing the queue */
}

static int on_queue_file_purge(const char *dir_name, const char *controlfile, void *obj)
{
	struct mailq_run *qrun = obj;
	struct mailq_file mqf_stack, *mqf = &mqf_stack;

	mailq_file_init(mqf, qrun);
	bbs_assert_exists(qrun);

	if (mailq_file_load(mqf, dir_name, controlfile)) {
		return 0;
	} else if (skip_qfile(qrun, mqf, controlfile)) {
		qrun->skipped++;
		mqf_file_cleanup(mqf);
		reset_accessed_time(mqf);
		return 0;
	}

	mqf->purge = 1; /* Discard without processing */
	process_queue_file(qrun, mqf);
	return 0;
}

/* Don't parallelize unless there's at least 2 messages in the queue,
 * and only deliver 5 messages concurrently */
#define QUEUE_PARALLELIZATION_THRESHOLD 2
#define MAX_QUEUE_PARALLELIZATION 5

/*! \brief Traverse and process the mail queue */
static int run_queue(struct mailq_run *qrun, int (*queue_file_cb)(const char *dir_name, const char *filename, void *obj))
{
	int res;
	int queued_messages;

	if (unloading) {
		return -1;
	}

	/*! \todo Rather than a global queue lock, each individual queue file should be locked using flock,
	 * so that the queue can be processed concurrently, as long as the same message is only handled once.
	 * This can help in the situation of a message already in the process of being sent when the queue runs,
	 * which is increasingly likelier on busier systems. */
	bbs_rwlock_wrlock(&queue_lock);
	queued_messages = bbs_dir_num_files(queue_dir);
	if (!queued_messages) {
		bbs_rwlock_unlock(&queue_lock);
		return 0; /* If nothing in directory, nothing at all to process, return early */
	}
	bbs_debug(7, "Processing mail queue (%d message%s)\n", queued_messages, ESS(queued_messages));
	/* If the number of queued messages is relatively small, we can just process them serially.
	 * It's not worth the overhead of parallelization.
	 * On the other hand, if there's more than a couple, then we probably want to parallelize if possible.
	 * If we're just gathering statistics, then we should run synchronously,
	 * since we want the ordering to be consistent and that's not going to take long. */
	if (qrun->type != QUEUE_RUN_STAT && queued_messages >= QUEUE_PARALLELIZATION_THRESHOLD) {
		/* Process in parallel, to some degree */
		struct bbs_parallel p;
		bbs_parallel_init(&p, QUEUE_PARALLELIZATION_THRESHOLD, MAX_QUEUE_PARALLELIZATION);
		qrun->parallel = &p;
		res = bbs_dir_traverse(queue_dir, queue_file_cb, qrun, -1);
		bbs_parallel_join(&p);
	} else {
		/* Process serially */
		res = bbs_dir_traverse(queue_dir, queue_file_cb, qrun, -1);
	}
	bbs_rwlock_unlock(&queue_lock);

	return res;
}

/*! \brief Periodically retry delivery of outgoing mail */
static void *queue_handler(void *unused)
{
	UNUSED(unused);

	if (bbs_safe_sleep_interrupt(SEC_MS(10))) { /* Wait 10 seconds after the module loads, then try to flush anything in the queue. */
		bbs_debug(5, "BBS shutdown occured before queue could run\n");
		return NULL;
	}

	for (;;) {
		struct mailq_run qrun;

		mailq_run_init(&qrun, QUEUE_RUN_PERIODIC);
		run_queue(&qrun, on_queue_file);
		if (qrun.total) {
			/* Only log a message if something happened. If the queue was empty, don't bother. */
			bbs_debug(1, "%d/%d message%s processed: %d delivered, %d failed, %d delayed, %d skipped\n", qrun.processed, qrun.total, ESS(qrun.total), qrun.delivered, qrun.failed, qrun.delayed, qrun.skipped);
		}
		mailq_run_cleanup(&qrun);

		/* We set this at the end, rather than the beginning, because
		 * the queue will be processed again based on when we end,
		 * so if we want to calculate the next periodic queue run,
		 * we want this time. */
		last_periodic_queue_run = time(NULL);

		/* Don't use usleep, as the SIGURG signal doesn't succeed in interrupting it */
		if (bbs_safe_sleep_interrupt(SEC_MS((int) queue_interval))) {
			bbs_debug(5, "Safe sleep returned\n");
			break;
		}
	}
	return NULL;
}

/*!
 * \brief Whether an IP address is authorized for a domain by source route
 * \param ip IP address
 * \param domain Domain
 * \retval 1 if yes, 0 if no
 */
static int authorized_for_hostname(const char *ip, const char *domain)
{
	int res;
	struct stringlist mxservers, *static_routes;

	stringlist_init(&mxservers);

	/* Start by trying to deliver it directly, immediately, right now. */
	static_routes = get_static_routes(domain);
	if (static_routes) {
		struct stringitem *i = NULL;
		const char *route;
		while ((route = stringlist_next(static_routes, &i))) {
			char hostbuf[256];
			const char *colon;
			const char *hostname = route;

			/* If this is a hostname:port, we need to split.
			 * Otherwise, we can use it directly. This is more efficient,
			 * since no allocations or copies are performed in this case. */
			colon = strchr(route, ':');
			if (colon) {
				/* There's a port specified. */
				bbs_strncpy_until(hostbuf, route, sizeof(hostbuf), ':'); /* Copy just the hostname */
				hostname = hostbuf;
			}
			if (bbs_ip_match_ipv4(ip, hostname)) {
				return 1;
			}
		}
	} else {
		char *hostname;
		res = lookup_mx_all(domain, &mxservers);
		while (res < 0 && (hostname = stringlist_pop(&mxservers))) {
			if (bbs_ip_match_ipv4(ip, hostname)) {
				free(hostname);
				stringlist_empty_destroy(&mxservers);
				return 1;
			}
			free(hostname);
		}
		stringlist_empty_destroy(&mxservers);
	}
	return 0;
}

/*! \brief Queue processor callback */
static int queue_processor(struct smtp_session *smtp, const char *cmd, const char *args)
{
	int res = 250; /* Start with 250 OK by default */
	struct mailq_run qrun;
	int identity_confirmed = 0;

	UNUSED(smtp); /* For now, this is unused, but could be useful in the future */

	if (smtp_is_message_submission(smtp)) {
		return 458;
	}

	mailq_run_init(&qrun, QUEUE_RUN_FORCED);

	/* The RFCs suggest that queue processing should be done asynchronously
	 * when requested. Currently, we do it synchronously, since it's simpler.
	 * If we change it to async, we will need to copy the args and either
	 * spawn a new thread or make the regular queue_handler thread do this for us. */

	if (!strcmp(cmd, "ETRN")) {
		/* RFC 1985 Remote Message Queue Starting */
		if (*args == '@') {
			/* RFC 1985 5.3: subdomain option character */
			args++;
			if (strlen_zero(args)) {
				res = 501;
			}
			qrun.host_ends_with = args;
		} else if (*args == '#') {
			/* RFC 1985 5.3: non-domain queue */
			/* Currently, we don't support any such queues, so reject */
			res = 458;
			goto cleanup;
		} else {
			qrun.host_match = args;
		}

		run_queue(&qrun, on_queue_file);

		/* The RFC makes no mention of such security considerations,
		 * but it would be a good idea to avoid leaking too much information
		 * if the connected host is asking for somebody else's mail to be relayed.
		 * But we shouldn't use bbs_ip_match_ipv4, we should use static_routes.
		 */
		if (authorized_for_hostname(smtp_sender_ip(smtp), args)) {
			identity_confirmed = 1;
		} else {
			bbs_debug(3, "Requested mail for '%s', but source IP address does not match source route\n", args);
		}

		/* One benefit of running the queue synchronously
		 * if that we now have more specific information about what happened.
		 * (Could also be done if we waited for all tasks to be created and returned
		 * before running them.) */
		if (!identity_confirmed) {
			/* If we're not sure if this host is authorized,
			 * just provide a generic response, to avoid leaking info. */
			res = 250;
		} else if (qrun.processed) {
			res = 252;
			/* The 253 response code allows us to say how many messages
			 * are pending, but the current callback interface doesn't
			 * give us a way to provide that back to net_smtp,
			 * since we can't use smtp_reply directly here.
			 * So we'll only be able say some number pending, rather than the specific number,
			 * even though we've got that information right here! */
		} else {
			res = 251;
		}
	} else {
		bbs_error("SMTP command '%s' is foreign to queue processor\n", cmd);
		res = 500;
		goto cleanup;
	}

cleanup:
	mailq_run_cleanup(&qrun);
	return res;
}

static int on_queue_file_cli_mailq(const char *dir_name, const char *filename, void *obj)
{
	struct mailq_run *qrun = obj;
	struct mailq_file mqf_stack, *mqf = &mqf_stack;
	char arrival_date[32];
	char retry_date[32];
	char next_retry_date[32];
	time_t next_queue_run, next_retry_time;
	struct tm est_retry;
	char msgsizebuf[32];
	size_t msgsize;

	mailq_file_init(&mqf_stack, qrun);

	if (mailq_file_load(&mqf_stack, dir_name, filename)) {
		return 0;
	} else if (skip_qfile(qrun, mqf, filename)) {
		mqf_file_cleanup(mqf);
		reset_accessed_time(mqf);
		return 0;
	}

	strftime(arrival_date, sizeof(arrival_date), "%a, %d %b %H:%M:%S", &mqf->created);
	if (mqf->retriedtime) {
		strftime(retry_date, sizeof(retry_date), "%a, %d %b %H:%M:%S", &mqf->retried);
	} else {
		strcpy(retry_date, "Never");
	}

	if (queue_interval) {
		/* For user convenience, try to calculate when message delivery will be attempted next. */
		next_retry_time = mqf->retriedtime + queue_retry_threshold(mqf->retries); /* Minimum time that it would get processed */

		/* If the queue hasn't run yet, assume it will run now, and count up from there */
		next_queue_run = last_periodic_queue_run ? last_periodic_queue_run + queue_interval : qrun->runstart + queue_interval;
		if (next_queue_run < qrun->runstart) {
			/* Shouldn't happen. Because we're holding the queue_lock,
			 * the queue can't be running now, which means it's either finished an iteration some time in the past,
			 * or it hasn't run at all yet. As soon as next_queue_run hits, the handler should start executing,
			 * and we wouldn't be able to grab the lock until after it were done, and had updated that again. */
			bbs_warning("Projected next queue run is %ld seconds ago?\n", qrun->runstart - next_queue_run);
			next_queue_run = qrun->runstart;
		}

		/* If the next time that the message would be processed is earlier in time
		 * than the next time the queue is projected to actually run,
		 * then increment the message retry time by the queue interval time.
		 * Because the queue run could take a non-trivial amount of time,
		 * this means that each time the queue runs, even for messages that weren't attempted that round,
		 * the timestamps will probably change (get pushed out slightly further ahead in time),
		 * though we'll eventually converge since the closer it gets, the more accurate we'll be. */
		while (next_retry_time < next_queue_run) {
			next_retry_time += queue_interval;
		}

		localtime_r(&next_retry_time, &est_retry);
		strftime(next_retry_date, sizeof(next_retry_date), "%a, %d %b %H:%M:%S", &est_retry);
	} else {
		strcpy(next_retry_date, "On Demand Only");
	}

	/* Ensure the format is synchronized with the heading in cli_mailq */
	/* Printing mqf->retries this way is already 1-indexed as well. */
	msgsize = (mqf->size + 1023) / 1024; /* Display size in KB, rounded up to the nearest KB */
	if (msgsize <= 999) {
		snprintf(msgsizebuf, sizeof(msgsizebuf), "%lu%s", msgsize, "K");
	} else {
		msgsize = (msgsize + 1023) / 1024; /* Round up to nearest MB, but only if at least 1,000 KB */
		snprintf(msgsizebuf, sizeof(msgsizebuf), "%lu%s", msgsize, "M");
	}
	/* If delivery has never been attempted, mqf->retries is 0. However, 1-index it in the queue (i.e. the queued file is attempt #1). */
	bbs_dprintf(qrun->clifd, "%-18s %3d %-20s %-20s %-20s %4s %s -> %s\n",
		filename, mqf->retries + 1, arrival_date, retry_date, next_retry_date, msgsizebuf,
		S_OR(mqf->realfrom, "<>"), mqf->realto);
	mqf_file_cleanup(mqf);
	reset_accessed_time(mqf); /* This was just for stats, we didn't actually do anything, so reset */
	return 0;
}

static int is_queue_filename(const char *s)
{
	/* Formatted like 1749798013359795.q */
	return strlen(s) == 18 && !strcmp(s + 16, ".q") && isdigit(*s);
}

static int cli_mailq(struct bbs_cli_args *a)
{
	struct mailq_run qrun;

	mailq_run_init(&qrun, QUEUE_RUN_STAT);
	qrun.clifd = a->fdout;
	if (a->argc >= 2) {
		if (is_queue_filename(a->argv[1])) {
			qrun.match_filename = a->argv[1];
		} else {
			qrun.host_ends_with = a->argv[1];
		}
	}

	bbs_dprintf(a->fdout, "%-18s %3s %-20s %-20s %-20s %4s %s\n", "ControlFile", "Try", "Orig Date", "Last Retry", "Est. Next Retry", "Size", "Sender -> Recipient");
	run_queue(&qrun, on_queue_file_cli_mailq);
	bbs_dprintf(a->fdout, "%d message%s currently in mail queue\n", qrun.total, ESS(qrun.total));
	mailq_run_cleanup(&qrun);
	return 0;
}

static int cli_runq(struct bbs_cli_args *a)
{
	struct mailq_run qrun;

	mailq_run_init(&qrun, QUEUE_RUN_FORCED);
	if (a->argc >= 2) {
		if (is_queue_filename(a->argv[1])) {
			qrun.match_filename = a->argv[1];
		} else {
			qrun.host_ends_with = a->argv[1];
		}
	}

	/* Process the queue, now, synchronously */
	run_queue(&qrun, on_queue_file);
	bbs_dprintf(a->fdout, "%d/%d message%s processed: %d delivered, %d failed, %d delayed\n", qrun.processed, qrun.total, ESS(qrun.total), qrun.delivered, qrun.failed, qrun.delayed);
	mailq_run_cleanup(&qrun);
	return 0;
}

static int cli_purgeq(struct bbs_cli_args *a)
{
	struct mailq_run qrun;

	mailq_run_init(&qrun, QUEUE_RUN_FORCED);
	qrun.match_filename = a->argv[1];

	run_queue(&qrun, on_queue_file_purge);
	bbs_dprintf(a->fdout, "%d/%d message%s processed: %d delivered, %d failed, %d delayed\n", qrun.processed, qrun.total, ESS(qrun.total), qrun.delivered, qrun.failed, qrun.delayed);
	mailq_run_cleanup(&qrun);
	if (!qrun.processed) {
		bbs_dprintf(a->fdout, "No such message file: %s\n", a->argv[1]);
	}
	return qrun.processed ? 0 : -1;
}

static struct bbs_cli_entry cli_commands_mailq[] = {
	BBS_CLI_COMMAND(cli_mailq, "mailq", 1, "Show the current mail queue (optionally restricted to specified file or messages ending in a particular host suffix)", "mailq <file/hostsuffix>"),
	BBS_CLI_COMMAND(cli_runq, "runq", 1, "Retry delivery of messages in the mail queue (optionally restricted to specified file or messages directed at certain hosts)", "runq <file/hostsuffix>"),
	BBS_CLI_COMMAND(cli_purgeq, "purgeq", 2, "Cancel delivery of a specific message in the mail queue", "purgeq <file>"),
	BBS_CLI_COMMAND(cli_mx_lookup, "mxlookup", 2, "Return ordered MX records for a hostname (ordered by, but without, the priorities)", "mxlookup <domain>"),
};

/*! \brief Send a specific message asynchronously */
static void *smtp_async_send(void *varg)
{
	char mailtmpdir[260];
	char fullname[512];
	char *controlfile = varg;

	snprintf(mailtmpdir, sizeof(mailtmpdir), "%s/mailq/tmp", mailbox_maildir(NULL)); /* control files live in tmp, data files in new */

	if (unloading) {
		free(controlfile);
		return NULL;
	}

	/* Acquiring this lock is not guaranteed to happen immediately,
	 * but that's okay since this thread is running asynchronously. */
	bbs_rwlock_rdlock(&queue_lock);
	/* We could move it to the tmp dir to prevent a conflict with the periodic queue thread,
	 * but the nice thing about doing it exactly the same way is that if delivery fails temporarily
	 * this first round, it'll be automatically handled by the queue retry logic.
	 * So we can always report 250 success here immediately.
	 * In fact, this doesn't even need to be done in this thread.
	 * The downside, of course, is that locking is needed to ensure
	 * we don't try to send the same message twice. */

	snprintf(fullname, sizeof(fullname), "%s/%s", mailtmpdir, controlfile);
	if (!bbs_file_exists(fullname)) {
		/* If we couldn't acquire the lock immediately,
		 * that means the queue thread was already running.
		 * It may or may not have already picked up this file,
		 * depending on how the timing worked out.
		 * If it was processed, then the file was already renamed,
		 * so we can detect that and bail. */
		bbs_debug(5, "Ooh, file %s was already handled before its owner got a chance to send it asynchronously\n", fullname);
	} else {
		/* We do need to lock, because we need to prevent the entire queue running at the same time
		 * that smtp_async_send is trying to send a message, to prevent possible duplicate delivery.
		 * However, there is a subtle but very important difference here:
		 * whole queue handlers should NEVER be running simultaneously, because they traverse all messages.
		 * Each invocation of smtp_async_send is for a unique message, so it is perfectly fine
		 * to have many invocations of smtp_async_send running simultaneously (and in fact,
		 * not allowing this would be bad since it would unnecessarily bottleneck concurrent outgoing mail).
		 *
		 * This is nicely captured by using a rwlock instead of a mutex.
		 * We rdlock in smtp_async_send, since it's okay for this to be running multiple times,
		 * since they're operating on different messages.
		 * Everywhere else, we wrlock.
		 * This ensures that only smtp_async_send, and nothing else, is doing queue stuff concurrently
		 * (The queue can be processed in parallel, but we lock only once at the top level while processing the queue). */

		/*! \todo Improve the locking to be less restrictive.
		 * SMTP transactions could technically take minutes,
		 * and since we are rdlock'ed this entire time,
		 * we may not be able to wrlock the queue for a while. */

		struct mailq_run qrun;
		mailq_run_init(&qrun, QUEUE_RUN_FORCED); /* We're forcing the queue to run for a specific message, technically */
		on_queue_file(mailtmpdir, controlfile, &qrun);
		mailq_run_cleanup(&qrun);
	}

	bbs_rwlock_unlock(&queue_lock);
	free(controlfile);
	return NULL;
}

/*! \brief Schedule delivery of a message asynchronously in another thread */
static int launch_delivery_task(const char *controlfile)
{
	pthread_t sendthread;
	const char *filename;
	char *filenamedup;

	filename = strrchr(controlfile, '/'); /* No need to duplicate the directory portion, just the basename */
	bbs_assert_exists(filename);
	filenamedup = strdup(filename + 1); /* Need to duplicate since filename is on the stack and we're returning now */
	if (ALLOC_FAILURE(filenamedup)) {
		return -1;
	}

	/* Yes, spawning a thread for every email is not very efficient.
	 * If this were a high traffic mail server, this might be architected differently. */
	if (bbs_pthread_create_detached(&sendthread, NULL, smtp_async_send, filenamedup)) {
		free(filenamedup);
		return -1;
	}
	return 0;
}

/*!
 * \brief Queue a message for delivery in the future
 * \param smtp
 * \param from Sender without <>
 * \param recipient Recipient with <>
 * \param datafile Queued message ID
 * \retval 1 if message was queued successfully
 * \retval -1 if message could not be queued
 */
static int queue_message(struct smtp_session *smtp, const char *from, const char *recipient, const char *datafile)
{
	char controlfile[512];
	char datebuf[32];
	FILE *fp;
	char *c;

	/* Write queue control file */
	safe_strncpy(controlfile, datafile, sizeof(controlfile));
	/* The data file name format is something like:  /home/bbs/maildir/mailq/new/aBcDeFgHxyz.d
	 * Use a similar format for queue control file:  /home/bbs/maildir/mailq/tmp/aBcDeFgHxyz.q
	 * Since the data file was created to be unique, the control file should be too.
	 * The d and q suffixes are based on sendmail queue file naming conventions: http://osr507doc.xinuos.com/en/MailMsgG/sndmlT18.html
	 */
	c = strrchr(controlfile, '.');
	if (!c) {
		return -1;
	}
	strcpy(c, ".q"); /* Safe */

	/* Change the directory, so that we can store the data files in new (will be moved to cur)
	 * and we can store the control files separately in tmp. */
	while (*c != '/') {
		c--;
	}
	c -= 3; /* Back up past new */
	memcpy(c, "tmp", STRLEN("tmp")); /* Use memcpy since we do NOT want a NUL terminator added after */

	bbs_debug(4, "Creating queue control file '%s'\n", controlfile);
	if (bbs_file_exists(controlfile)) {
		bbs_error("Queue file '%s' already exists?\n", controlfile);
		return -1;
	}
	fp = fopen(controlfile, "w");
	if (!fp) {
		bbs_error("Failed to create control file %s: %s\n", controlfile, strerror(errno));
		return -1;
	}

	/* We can use LF endings for the control file */
	fprintf(fp, "Source-IP: %s\n", smtp_sender_ip(smtp));
	fprintf(fp, "SMTP-Hostname: %s\n", smtp_sender_hostname(smtp));
	fprintf(fp, "SMTP-Submission: %d\n", smtp_is_message_submission(smtp));
	fprintf(fp, "Envelope-Sender: <%s>\n", from);
	/*! \todo Implement smarter queuing:
	 * If delivering the same message to multiple recipients on a single server, it would be nice
	 * to be able to do that in a single transaction. Sharing a queue file might make sense in this scenario? */
	fprintf(fp, "Envelope-Recipient: %s\n", recipient); /* Includes <> already */
	fprintf(fp, "Data-File: %s\n", datafile); /* Full path to data file containing message */
	/*! \todo In the future, include any DSN preferences here */
	smtp_timestamp(smtp_received_time(smtp), datebuf, sizeof(datebuf));
	fprintf(fp, "Arrival-Time: %s\n", datebuf);
	/* Put fields that may be mutated while in queue last: */
	fprintf(fp, "Delivery-Attempts: %d\n", 0); /* Include this last, since this is the only thing we'll be changing between attempts */
	fclose(fp);

	if (queue_immediate) {
		if (!launch_delivery_task(controlfile)) {
			bbs_debug(4, "Successfully queued message %s for immediate delivery\n", controlfile);
		}
	} else {
		bbs_debug(4, "Successfully queued message %s for delayed delivery\n", controlfile);
	}
	return 1; /* Even if queuing fails for some reason, it's in the queue, so the message will be delivered eventually */
}

/*! \brief Accept delivery of a message to an external recipient, sending it now if possible and queuing it otherwise */
static int external_delivery(struct smtp_session *smtp, struct smtp_response *resp, const char *from, const char *recipient, const char *user, const char *domain, int fromlocal, int srcfd, size_t datalen, void **freedata)
{
	struct smtp_msg_process mproc;
	struct smtp_response tmpresp; /* Dummy that gets thrown away, if needed */
	int res;
	int fd;
	char qdir[256];
	char tmpfile[256], newfile[256];
	struct smtp_filter_data filterdata;

	UNUSED(user);

	/* Even though it's not really an "outgoing" message, it makes more sense to run callbacks as such here.
	 * There is no mailbox corresponding to this filter execution, so this is purely for global before/after rules
	 * that may want to target non-mailbox mail. */
	res = smtp_run_delivery_callbacks(smtp, &mproc, NULL, &resp, SMTP_DIRECTION_OUT, SMTP_SCOPE_INDIVIDUAL, recipient, datalen, freedata);
	if (res) {
		return res;
	}
	if (!resp) {
		resp = &tmpresp;
	}

	if (smtp_is_exempt_relay(smtp)) {
		bbs_debug(2, "%s is explicitly authorized to relay mail from %s\n", smtp_sender_ip(smtp), smtp_from_domain(smtp));
	} else if (get_static_routes(domain)) {
		bbs_debug(2, "%s has static route(s)\n", domain);
	} else {
		/* fromlocal is usually, but not necessarily always, true here.
		 * For example, if the local user has a rule to forward certain messages elsewhere,
		 * then that authorizes an external message to be relayed externally. */
		if (!accept_relay_out) {
			smtp_abort(resp, 550, 5.7.0, "Mail relay denied.");
			return -1;
		} else if (fromlocal && minpriv_relay_out) {
			if (smtp_node(smtp)->user->priv < minpriv_relay_out) {
				smtp_abort(resp, 550, 5.7.0, "Mail relay denied. Unauthorized to relay external mail.");
				return -1;
			}
		}
	}

	bbs_assert_exists(recipient);
	if (*recipient != '<') {
		bbs_warning("Invalid recipient: %s\n", recipient);
		return -1;
	}

	/* Write the full message into the queue */
	snprintf(qdir, sizeof(qdir), "%s/%s", mailbox_maildir(NULL), "mailq");
	if (mailbox_maildir_init(qdir)) {
		return -1; /* Can't queue */
	}
	fd = maildir_mktemp(qdir, tmpfile, sizeof(tmpfile) - 3, newfile); /* Subtract 3 for .d */

#undef strcat
	strcat(newfile, ".d"); /* Safe */
	if (fd < 0) {
		return -1;
	}

	smtp_filter_data_init(&filterdata, smtp, recipient, datalen, srcfd, fd);
	smtp_run_filters(&filterdata, SMTP_DIRECTION_OUT);
	smtp_filter_write_prepended_headers(&filterdata, fd);
	smtp_filter_data_cleanup(&filterdata);

	/* Write the entire body of the message. */
	res = bbs_copy_file(srcfd, fd, 0, (int) datalen);
	if (res != (int) datalen) {
		bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", datalen, tmpfile, res);
		close(fd);
		return -1;
	} else if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	return queue_message(smtp, from, recipient, newfile);
}

static int relay(struct smtp_session *smtp, struct smtp_msg_process *mproc, int srcfd, size_t datalen, struct stringlist *recipients)
{
	/* Format is smtps://user:password@host:port - https://datatracker.ietf.org/doc/html/draft-earhart-url-smtp-00 */
	struct bbs_url url;
	int res;
	memset(&url, 0, sizeof(url));
	if (bbs_parse_url(&url, mproc->relayroute)) {
		bbs_warning("Failed to parse SMTP URL\n");
		res = -1;
	} else if (!STARTS_WITH(url.prot, "smtp")) {
		bbs_warning("Invalid SMTP protocol: %s\n", url.prot);
		res = -1;
	} else {
		struct smtp_tx_data tx; /* Capture but ignore */
		char buf[512];
		char prepend[256] = "";
		int prependlen = 0;
		char timestamp[40];
		time_t now = time(NULL);

		/* Still prepend a Received header, but less descriptive than normal (don't include Authenticated sender) since we're relaying */
		smtp_timestamp(now, timestamp, sizeof(timestamp));
		prependlen = snprintf(prepend, sizeof(prepend), "Received: from [HIDDEN]\r\n\tby %s with %s\r\n\t%s\r\n",
			smtp_hostname(), smtp_protname(smtp), timestamp);

		bbs_debug(5, "Relaying message via %s:%d (user: %s)\n", url.host, url.port, S_IF(url.user));
		/* XXX smtp->recipients is "used up" by try_send, so this relies on the message being discarded as there will be no recipients remaining afterwards
		 * Instead, we could duplicate the recipients list to avoid this restriction. */
		/* XXX A cool optimization would be if the IMAP server supported BURL IMAP and we did a MOVETO, use BURL with the SMTP server */
		res = try_send(smtp, &tx, url.host, url.port, STARTS_WITH(url.prot, "smtps"), 1, url.user, url.pass, url.user, NULL, recipients, prepend, (size_t) prependlen, srcfd, datalen, buf, sizeof(buf));
	}
	if (url.pass) {
		bbs_memzero(url.pass, strlen(url.pass)); /* Destroy the password */
	}
	return res;
}

static int exists(struct smtp_session *smtp, struct smtp_response *resp, const char *address, const char *user, const char *domain, int fromlocal, int tolocal)
{
	struct stringlist *s;

	UNUSED(smtp);
	UNUSED(address);
	UNUSED(user);
	UNUSED(domain);

	if (tolocal) {
		return 0; /* We are not the right handler for local mail */
	}

	if (smtp_is_exempt_relay(smtp)) {
		/* Allow an external host to relay messages for a domain if it's explicitly authorized to. */
		bbs_debug(2, "%s is explicitly authorized to relay mail from %s\n", smtp_sender_ip(smtp), smtp_from_domain(smtp));
		return 1;
	}

	s = get_static_routes(domain);
	if (s) {
		/* e.g. we accept mail for another domain by forwarding it to an SMTP MTA that isn't directly exposed to the Internet */
		bbs_debug(2, "%s has static route(s) defined\n", domain);
		return 1;
	}

	if (!fromlocal) {/* External user trying to send us mail that's not for us. */
		/* Built in rejection of relayed mail. If another delivery agent wants to override this, it can,
		 * (e.g. to set up a honeypot), it would just need to have a more urgent priority. */
		smtp_abort(resp, 550, 5.7.0, "Mail relay denied. Forwarding to remote hosts disabled"); /* We're not an open relay. */
		return -1;
	}
	return !tolocal;
}

struct smtp_delivery_agent extdeliver = {
	.type = SMTP_DELIVERY_AGENT_EXTERNAL,
	.exists = exists,
	.deliver = external_delivery,
	.relay = relay,
};

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("net_smtp.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "relayout", &accept_relay_out);
	bbs_config_val_set_uint(cfg, "general", "maxretries", &max_retries);
	bbs_config_val_set_uint(cfg, "general", "maxage", &max_age);
	bbs_config_val_set_true(cfg, "general", "queueimmediate", &queue_immediate);
	bbs_config_val_set_uint(cfg, "general", "queueinterval", &queue_interval);
	bbs_config_val_set_true(cfg, "general", "notifyqueue", &notify_queue);

	bbs_config_val_set_true(cfg, "smtp", "requirestarttls", &require_starttls_out);

	bbs_config_val_set_true(cfg, "privs", "relayout", &minpriv_relay_out);

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "static_relays")) {
			struct bbs_keyval *keyval = NULL;
			RWLIST_WRLOCK(&static_relays);
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_static_relay(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
			RWLIST_UNLOCK(&static_relays);
		} /* else, ignore. net_smtp will warn about any invalid section names in net_smtp.conf. */
	}
	bbs_config_unlock(cfg);

	if (queue_interval != 0 && queue_interval < 60) {
		queue_interval = 60;
	}
	return 0;
}

static int load_module(void)
{
	load_config();
	snprintf(queue_dir, sizeof(queue_dir), "%s/mailq", mailbox_maildir(NULL));
	mailbox_maildir_init(queue_dir); /* The queue dir is also like a maildir, it has a new, tmp, and cur */
	snprintf(queue_dir, sizeof(queue_dir), "%s/mailq/tmp", mailbox_maildir(NULL)); /* The control files are in tmp, while the data files are in new */
	if (eaccess(queue_dir, R_OK) && mkdir(queue_dir, 0700)) {
		bbs_error("mkdir(%s) failed: %s\n", queue_dir, strerror(errno));
		return -1;
	}
	bbs_rwlock_init(&queue_lock, NULL);
	if (queue_interval && bbs_pthread_create(&queue_thread, NULL, queue_handler, NULL)) {
		bbs_rwlock_destroy(&queue_lock);
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_mailq);
	smtp_register_queue_processor(queue_processor);
	smtp_register_partial_lookup(dns_record_lookup);
	return smtp_register_delivery_handler(&extdeliver, 90); /* Lowest priority */
}

static int unload_module(void)
{
	int res;
	unloading = 1;
	res = smtp_unregister_delivery_agent(&extdeliver);
	smtp_unregister_partial_lookup(dns_record_lookup);
	smtp_unregister_queue_processor(queue_processor);
	bbs_cli_unregister_multiple(cli_commands_mailq);
	if (queue_interval) {
		bbs_pthread_interrupt(queue_thread);
		bbs_pthread_join(queue_thread, NULL);
	}
	/* It's possible messages may be in the middle of being sent still,
	 * which could result in an attempt to destroy queue_lock while still being used.
	 * Wait until we can get a write lock, since there won't be any new users after
	 * unloading flag is set true. */
	bbs_rwlock_wrlock(&queue_lock);
	bbs_rwlock_unlock(&queue_lock);
	bbs_rwlock_destroy(&queue_lock);
	RWLIST_WRLOCK_REMOVE_ALL(&static_relays, entry, free_static_relay);
	return res;
}

BBS_MODULE_INFO_DEPENDENT("E-Mail External Delivery", "net_smtp.so,mod_smtp_client.so");
