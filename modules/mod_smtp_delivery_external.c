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

#include "include/mod_mail.h"
#include "include/net_smtp.h"

static int accept_relay_out = 1;
static int minpriv_relay_out = 0;

static int require_starttls_out = 0;

static int queue_outgoing = 1;
static int send_async = 1;
static int always_queue = 0;
static int notify_queue = 0;
static pthread_t queue_thread = 0;
static pthread_mutex_t queue_lock;
static char queue_dir[256];
static unsigned int queue_interval = 900;
static unsigned int max_retries = 10;
static unsigned int max_age = 86400;

struct mx_record {
	int priority;
	RWLIST_ENTRY(mx_record) entry;
	char data[];
};

RWLIST_HEAD(mx_records, mx_record);

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
		 * This is actually a special case in RFC 7505, which indicates the domain
		 * receives no mail. In this case, we should NOT fall back to the A or AAAA record.
		 * We should immediately abort.
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
			/* The record was just a ., which means
			 * the domain accepts no mail. */
			RWLIST_REMOVE_ALL(&mxs, entry, free);
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
		RWLIST_INSERT_SORTED(&mxs, mx, entry, priority);
		added++;
	}

	if (!added) {
		bbs_warning("No MX records available for %s\n", domain);
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

#define SMTP_EXPECT(client, ms, str) \
	res = bbs_tcp_client_expect(client, "\r\n", 1, ms, str); \
	if (res) { bbs_warning("Expected '%s', got: %s\n", str, (client)->rldata.buf); goto cleanup; } else { bbs_debug(9, "Found '%s': %s\n", str, (client)->rldata.buf); }

#define smtp_client_send(client, fmt, ...) bbs_tcp_client_send(client, fmt, ## __VA_ARGS__); bbs_debug(3, " => " fmt, ## __VA_ARGS__);

#define SMTP_CAPABILITY_STARTTLS (1 << 0)
#define SMTP_CAPABILITY_PIPELINING (1 << 1)
#define SMTP_CAPABILITY_8BITMIME (1 << 2)
#define SMTP_CAPABILITY_ENHANCEDSTATUSCODES (1 << 3)
#define SMTP_CAPABILITY_AUTH_LOGIN (1 << 4)
#define SMTP_CAPABILITY_AUTH_PLAIN (1 << 5)
#define SMTP_CAPABILITY_AUTH_XOAUTH2 (1 << 6)

static void process_capabilities(int *restrict caps, int *restrict maxsendsize, const char *capname)
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
	} else if (STARTS_WITH(capname, "SIZE")) { /* The argument containing the size is optional */
		const char *size = capname + STRLEN("SIZE");
		if (!strlen_zero(size)) {
			/* If there's a limit provided in the capabilities, store it and abort early if message length exceeds this */
			size++;
			if (!strlen_zero(size)) {
				*maxsendsize = atoi(size);
			}
		}
	} else if (!strcasecmp(capname, "CHUNKING") || !strcasecmp(capname, "SMTPUTF8") || !strcasecmp(capname, "VRFY") || !strcasecmp(capname, "ETRN") || !strcasecmp(capname, "DSN") || !strcasecmp(capname, "HELP")) {
		/* Don't care about */
	} else if (!strcmp(capname, "PIPECONNECT")) {
		/* Don't care about, at the moment, but could be used in the future to optimize:
		 * https://www.exim.org/exim-html-current/doc/html/spec_html/ch-main_configuration.html */
	} else if (!strcmp(capname, "AUTH=LOGIN PLAIN")) {
		/* Ignore: this SMTP server advertises this capability (even though it's malformed) to support some broken clients */
	} else {
		bbs_warning("Unknown capability advertised: %s\n", capname);
	}
}

/*! \brief Await a final SMTP response code */
static int smtp_client_expect_final(struct bbs_tcp_client *restrict client, int ms, const char *code, size_t codelen)
{
	int res;
	/* Read until we get a response that isn't the desired code or isn't a nonfinal response */
	do {
		res = bbs_tcp_client_expect(client, "\r\n", 1, ms, code);
		bbs_debug(3, "Found '%s': %s\n", code, client->rldata.buf);
	} while (!strncmp(client->rldata.buf, code, codelen) && client->rldata.buf[codelen] == '-');
	if (res > 0) {
		bbs_warning("Expected '%s', got: %s\n", code, client->rldata.buf);
	} else if (res < 0) {
		bbs_warning("Failed to receive '%s'\n", code);
	}
	return res;
}

#define SMTP_CLIENT_EXPECT_FINAL(client, ms, code) if ((res = smtp_client_expect_final(client, ms, code, STRLEN(code)))) { goto cleanup; }

static int smtp_client_handshake(struct bbs_tcp_client *restrict client, const char *hostname, int *restrict capsptr, int *restrict maxsendsize)
{
	int res = 0;

	smtp_client_send(client, "EHLO %s\r\n", smtp_hostname());
	/* Don't use smtp_client_expect_final as we'll miss reading the capabilities */
	res = bbs_tcp_client_expect(client, "\r\n", 1, MIN_MS(5), "250"); /* Won't return 250 if ESMTP not supported */
	if (res) { /* Fall back to HELO if EHLO not supported */
		if (require_starttls_out) { /* STARTTLS is only supported by EHLO, not HELO */
			bbs_warning("SMTP server %s does not support STARTTLS, but encryption is mandatory. Delivery failed.\n", hostname);
			res = 1;
			goto cleanup;
		}
		bbs_debug(3, "SMTP server %s does not support ESMTP, falling back to regular SMTP\n", hostname);
		smtp_client_send(client, "HELO %s\r\n", smtp_hostname());
		SMTP_CLIENT_EXPECT_FINAL(client, MIN_MS(5), "250");
	} else {
		/* Keep reading the rest of the multiline EHLO */
		while (STARTS_WITH(client->rldata.buf, "250-")) {
			bbs_debug(9, "<= %s\n", client->rldata.buf);
			process_capabilities(capsptr, maxsendsize, client->rldata.buf + 4);
			res = bbs_tcp_client_expect(client, "\r\n", 1, SEC_MS(15), "250");
		}
		bbs_debug(9, "<= %s\n", client->rldata.buf);
		process_capabilities(capsptr, maxsendsize, client->rldata.buf + 4);
		bbs_debug(6, "Finished processing multiline EHLO\n");
	}

cleanup:
	return res;
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
static int try_send(struct smtp_session *smtp, struct smtp_tx_data *tx, const char *hostname, int port, int secure, const char *username, const char *password, const char *sender, const char *recipient, struct stringlist *recipients,
	const char *prepend, size_t prependlen, int datafd, off_t offset, size_t writelen, char *buf, size_t len)
{
	int res = -1;
	ssize_t wrote = 0;
	struct bbs_tcp_client client;
	struct bbs_url url;
	off_t send_offset = offset;
	int caps = 0, maxsendsize = 0;
	char sendercopy[64];
	char *user, *domain, *saslstr = NULL;

	bbs_assert(datafd != -1);
	bbs_assert(writelen > 0);

	/* RFC 5322 3.4.1 allows us to use IP addresses in SMTP as well (domain literal form). They just need to be enclosed in square brackets. */
	safe_strncpy(sendercopy, sender, sizeof(sendercopy));

	/* Properly parse, since if a name is present, in addition to the email address, we must exclude the name in the MAIL FROM */
	if (bbs_parse_email_address(sendercopy, NULL, &user, &domain)) {
		bbs_error("Invalid email address: %s\n", sender);
		return -1;
	}

	memset(&client, 0, sizeof(client));
	memset(&url, 0, sizeof(url));
	url.host = hostname;
	url.port = port;

	tx->prot = "x-tcp";
	if (bbs_tcp_client_connect(&client, &url, secure, buf, len)) {
		/* Unfortunately, we can't try an alternate port as there is no provision
		 * for letting other SMTP MTAs know that they should try some port besides 25.
		 * So if your ISP blocks incoming traffic on port 25 or you can't use port 25
		 * for whatever reason, you're kind of out luck: you won't be able to receive
		 * mail from the outside world. */
		bbs_debug(3, "Failed to set up TCP connection to %s\n", hostname);
		snprintf(buf, len, "Connection refused");
		return -1;
	}

	smtp_tx_data_reset(tx);
	bbs_get_fd_ip(client.fd, tx->ipaddr, sizeof(tx->ipaddr));
	safe_strncpy(tx->hostname, hostname, sizeof(tx->hostname));

	bbs_debug(3, "Attempting delivery of %lu-byte message from %s -> %s via %s\n", writelen, sender, recipient, hostname);

	SMTP_CLIENT_EXPECT_FINAL(&client, MIN_MS(5), "220"); /* RFC 5321 4.5.3.2.1 (though for final 220, not any of them) */

	res = smtp_client_handshake(&client, hostname, &caps, &maxsendsize);
	if (res) {
		goto cleanup;
	}

	tx->prot = "smtp";
	if (caps & SMTP_CAPABILITY_STARTTLS) {
		if (!secure) {
			smtp_client_send(&client, "STARTTLS\r\n");
			SMTP_CLIENT_EXPECT_FINAL(&client, 2500, "220");
			bbs_debug(3, "Starting TLS\n");
			if (bbs_tcp_client_starttls(&client, hostname)) {
				goto cleanup; /* Abort if we were told STARTTLS was available but failed to negotiate. */
			}
			/* Start over again. */
			caps = 0;
			res = smtp_client_handshake(&client, hostname, &caps, &maxsendsize);
			if (res) {
				goto cleanup;
			}
		}
	} else if (require_starttls_out) {
		bbs_warning("SMTP server %s does not support STARTTLS, but encryption is mandatory. Delivery failed.\n", hostname);
		snprintf(buf, len, "STARTTLS not supported");
		res = 1;
		goto cleanup;
	} else {
		bbs_warning("SMTP server %s does not support STARTTLS. This message will not be transmitted securely!\n", hostname);
	}

	if (maxsendsize && (int) (prependlen + writelen) > maxsendsize) {
		/* We know the message we're trying to send is larger than the max message size the server will accept.
		 * Just abort now. */
		bbs_warning("Total message size (%lu) is larger than server accepts (%d)\n", prependlen + writelen, maxsendsize);
		snprintf(buf, len, "Message too large (%lu bytes, maximum is %d)", prependlen + writelen, maxsendsize);
		res = 1;
		goto cleanup;
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
			smtp_client_send(&client, "AUTH XOAUTH2 %s\r\n", encoded);
			free(encoded);
			res = bbs_tcp_client_expect(&client, "\r\n", 1, SEC_MS(5), "235");
			if (res) {
				/* If we get 334 here, that means we failed: https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange
				 * We should send an empty reply to get the error message. */
				if (STARTS_WITH(buf, "334")) {
					smtp_client_send(&client, "\r\n");
					SMTP_EXPECT(&client, SEC_MS(5), "235"); /* We're not actually going to get a 235, but send the error to the console and abort */
					bbs_warning("Huh? It worked?\n"); /* Shouldn't happen */
				} else {
					bbs_warning("Expected '%s', got: %s\n", "235", buf);
					goto cleanup;
				}
			}
		} else if (caps & SMTP_CAPABILITY_AUTH_LOGIN) {
			saslstr = bbs_sasl_encode(username, username, password);
			if (!saslstr) {
				res = -1;
				goto cleanup;
			}
			smtp_client_send(&client, "AUTH PLAIN\r\n"); /* AUTH PLAIN is preferred to the deprecated AUTH LOGIN */
			SMTP_EXPECT(&client, SEC_MS(10), "334");
			smtp_client_send(&client, "%s\r\n", saslstr);
			SMTP_EXPECT(&client, SEC_MS(10), "235");
		} else {
			bbs_warning("No mutual login methods available\n");
			res = -1;
			goto cleanup;
		}
	}

	tx->prot = "smtp";
	tx->stage = "MAIL FROM";
	if (bbs_hostname_is_ipv4(domain)) {
		smtp_client_send(&client, "MAIL FROM:<%s@[%s]>\r\n", user, domain); /* Domain literal for IP address */
	} else {
		smtp_client_send(&client, "MAIL FROM:<%s@%s>\r\n", user, domain); /* sender lacks <>, but recipient has them */
	}
	SMTP_CLIENT_EXPECT_FINAL(&client, MIN_MS(5), "250"); /* RFC 5321 4.5.3.2.2 */
	tx->stage = "RCPT FROM";
	if (recipient) {
		if (*recipient == '<') {
			smtp_client_send(&client, "RCPT TO:%s\r\n", recipient);
		} else {
			bbs_warning("Queue file recipient did not contain <>\n"); /* Support broken queue files, but make some noise */
			smtp_client_send(&client, "RCPT TO:<%s>\r\n", recipient);
		}
		SMTP_CLIENT_EXPECT_FINAL(&client, MIN_MS(5), "250"); /* RFC 5321 4.5.3.2.3 */
	} else if (recipients) {
		char *r;
		while ((r = stringlist_pop(recipients))) {
			smtp_client_send(&client, "RCPT TO:%s\r\n", r);
			SMTP_CLIENT_EXPECT_FINAL(&client, MIN_MS(5), "250"); /* RFC 5321 4.5.3.2.3 */
			free(r);
		}
	} else {
		bbs_error("No recipients specified\n");
		goto cleanup;
	}
	tx->stage = "DATA";
	smtp_client_send(&client, "DATA\r\n");
	SMTP_CLIENT_EXPECT_FINAL(&client, MIN_MS(2), "354"); /* RFC 5321 4.5.3.2.4 */
	if (prepend && prependlen) {
		wrote = bbs_write(client.wfd, prepend, (unsigned int) prependlen);
	}

	/* sendfile will be much more efficient than reading the file ourself, as email body could be quite large, and we don't need to involve userspace. */
	res = (int) bbs_sendfile(client.wfd, datafd, &send_offset, writelen);

	/* XXX If email doesn't end in CR LF, we need to tack that on. But ONLY if it doesn't already end in CR LF. */
	smtp_client_send(&client, "\r\n.\r\n"); /* (end of) EOM */
	tx->stage = "end of DATA";
	if (res != (int) writelen) { /* Failed to write full message */
		res = -1;
		goto cleanup;
	}
	wrote += res;
	bbs_debug(5, "Sent %lu bytes\n", wrote);
	/* RFC 5321 4.5.3.2.6 */
	SMTP_CLIENT_EXPECT_FINAL(&client, MIN_MS(10), "250"); /* Okay, this email is somebody else's problem now. */

	bbs_debug(3, "Message successfully delivered to %s\n", recipient);
	res = 0;

cleanup:
	free_if(saslstr);
	if (res > 0) {
		smtp_client_send(&client, "QUIT\r\n");
	}
	bbs_tcp_client_cleanup(&client);

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

static void smtp_trigger_dsn(enum smtp_delivery_action action, struct smtp_tx_data *restrict tx, struct tm *created, const char *from, const char *to, char *error, int fd, size_t offset, size_t datalen)
{
	char *tmp;
	char status[15] = ""; /* Status code should be the 2nd word? */
	struct smtp_delivery_outcome *f;

	if (action != DELIVERY_FAILED && !notify_queue) {
		return;
	} else if (action == DELIVERY_DELIVERED) {
		time_t sent;
		if (!created) {
			bbs_warning("Message has no sent time?\n");
			return;
		}
		sent = mktime(created);
		if (sent > time(NULL) - 30) {
			return; /* Don't send reports on success UNLESS a message was previously delayed */
		}
		/* Do send a delivery report, it was likely previous queued and succeeded only on a retry */
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
		/*! \todo parameter 1 is the sendinghost: we should store this in the queue file so this information is available to us
		 * Even better, rather than trying to stuff it into the same file and using an offset, using some kind of out of band
		 * control file where we can record all the relevant information we'll want to keep. */
		smtp_dsn(NULL, created, from, fd, (int) offset, datalen, &f, 1);
		smtp_delivery_outcome_free(&f, 1);
	}
}

#define MAILQ_FILENAME_SIZE 516

struct mailq_file {
	FILE *fp;
	unsigned long size;
	size_t metalen;
	char *realfrom, *realto;
	char *user, *domain;
	char *retries;
	int newretries;
	struct tm created;
	char fullname[MAILQ_FILENAME_SIZE];
	char from[1000], recipient[1000], todup[256];
};

static int mailq_file_load(struct mailq_file *restrict mqf, const char *dir_name, const char *filename)
{
	struct stat st;

	snprintf(mqf->fullname, sizeof(mqf->fullname), "%s/%s", dir_name, filename);
	mqf->fp = fopen(mqf->fullname, "r");
	if (!mqf->fp) {
		bbs_error("Failed to open %s: %s\n", mqf->fullname, strerror(errno));
		return -1;
	}

	fseek(mqf->fp, 0L, SEEK_END); /* Go to EOF */
	mqf->size = (long unsigned) ftell(mqf->fp);
	rewind(mqf->fp); /* Be kind, rewind */

	if (!fgets(mqf->from, sizeof(mqf->from), mqf->fp) || !fgets(mqf->recipient, sizeof(mqf->recipient), mqf->fp)) {
		bbs_error("Failed to read metadata from %s\n", mqf->fullname);
		goto cleanup;
	}

	mqf->metalen = strlen(mqf->from) + strlen(mqf->recipient); /* This already includes the newlines */

	mqf->retries = strchr(mqf->fullname, '.');
	if (!mqf->retries++ || strlen_zero(mqf->retries)) { /* Shouldn't happen for mail queue files legitimately generated by this module, but somebody else might have dumped stuff in. */
		bbs_error("File name '%s' is non-compliant with our filename format\n", mqf->fullname);
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
	bbs_term_line(mqf->from);
	bbs_term_line(mqf->recipient);

	mqf->realfrom = strchr(mqf->from, '<');
	mqf->realto = strchr(mqf->recipient, '<');

	if (!mqf->realfrom) {
		bbs_error("Mail queue file MAIL FROM missing <>: %s\n", mqf->fullname);
		goto cleanup;
	} else if (!mqf->realto) {
		bbs_error("Mail queue file RCPT TO missing <>: %s\n", mqf->fullname);
		goto cleanup;
	}

	mqf->realfrom++; /* Skip < */
	if (strlen_zero(mqf->realfrom)) {
		bbs_error("Malformed MAIL FROM: %s\n", mqf->fullname);
		goto cleanup;
	}
	bbs_strterm(mqf->realfrom, '>'); /* try_send will add <> for us, so strip it here to match */

	if (bbs_str_count(mqf->realfrom, '<') || bbs_str_count(mqf->realfrom, '>') || bbs_str_count(mqf->realto, '<') != 1 || bbs_str_count(mqf->realto, '>') != 1) {
		bbs_error("Sender or recipient address malformed %s -> %s\n", mqf->realfrom, mqf->realto);
		goto cleanup;
	}

	safe_strncpy(mqf->todup, mqf->realto, sizeof(mqf->todup));
	if (strlen_zero(mqf->realfrom) || bbs_parse_email_address(mqf->todup, NULL, &mqf->user, &mqf->domain)) {
		bbs_error("Address parsing error\n");
		goto cleanup;
	}

	memset(&mqf->created, 0, sizeof(mqf->created));
	if (stat(mqf->fullname, &st)) {
		bbs_error("stat(%s) failed: %s\n", mqf->fullname, strerror(errno));
	} else {
		localtime_r(&st.st_mtim.tv_sec, &mqf->created);
	}

	return 0;

cleanup:
	fclose(mqf->fp);
	mqf->fp = NULL;
	return -1;
}

static int mailq_file_punt(struct mailq_file *mqf)
{
	char newname[MAILQ_FILENAME_SIZE + 11];
	char tmpbuf[256];

	bbs_strncpy_until(tmpbuf, mqf->fullname, sizeof(tmpbuf), '.');
	/* Store retry information in the filename itself, so we don't have to modify the file, we can just rename it. Inspired by IMAP. */
	snprintf(newname, sizeof(newname), "%s.%d", tmpbuf, mqf->newretries);
	if (rename(mqf->fullname, newname)) {
		bbs_error("Failed to rename %s to %s\n", mqf->fullname, newname);
		return -1;
	}
	return 0;
}

static int on_queue_file(const char *dir_name, const char *filename, void *obj)
{
	int res = -1;
	char *hostname;
	char buf[256] = "";
	struct stringlist mxservers;
	struct smtp_tx_data tx;
	struct mailq_file mqf_stack, *mqf = &mqf_stack;

	UNUSED(obj);

	memset(&mqf_stack, 0, sizeof(mqf_stack));
	memset(&tx, 0, sizeof(tx));

	if (mailq_file_load(&mqf_stack, dir_name, filename)) {
		return 0;
	}

	bbs_debug(5, "Processing message from %s -> %s\n", mqf->realfrom, mqf->realto);
	bbs_debug(2, "Retrying delivery of %s (%s -> %s)\n", mqf->fullname, mqf->realfrom, mqf->realto);

	memset(&mxservers, 0, sizeof(mxservers));
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
				bbs_warning("Delivery of message %s from %s to %s has failed permanently (no MX records)\n", mqf->fullname, mqf->realfrom, mqf->realto);
				/* There isn't any SMTP level error at this point yet, we have to make our own error message for the bounce message */
				snprintf(buf, sizeof(buf), "No MX record(s) located for hostname %s", mqf->domain); /* No status code */
				smtp_tx_data_reset(&tx);
				/* Do not set tx.hostname, since this message is from us, not the remote server */
				smtp_trigger_dsn(DELIVERY_FAILED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->metalen, mqf->size - mqf->metalen);
				fclose(mqf->fp);
				bbs_delete_file(mqf->fullname);
				return 0;
			}
			bbs_warning("Recipient domain %s does not have any MX records, falling back to A record %s\n", mqf->domain, a_ip);
			stringlist_push(&mxservers, a_ip);
		}

		/* Try all the MX servers in order, if necessary */
		res = -1; /* Make condition true to start */
		while (res < 0 && (hostname = stringlist_pop(&mxservers))) {
			res = try_send(NULL, &tx, hostname, DEFAULT_SMTP_PORT, 0, NULL, NULL, mqf->realfrom, mqf->realto, NULL, NULL, 0, fileno(mqf->fp), (off_t) mqf->metalen, mqf->size - mqf->metalen, buf, sizeof(buf));
			free(hostname);
		}
		stringlist_empty(&mxservers);
	}

	mqf->newretries = atoi(mqf->retries); /* This is actually current # of retries, not new # yet */
	if (!res) {
		/* Successful delivery. */
		bbs_debug(6, "Delivery successful after %d attempt%s, discarding queue file\n", mqf->newretries, ESS(mqf->newretries));
		bbs_smtp_log(4, NULL, "Delivery succeeded after queuing: %s -> %s\n", mqf->realfrom, mqf->realto);
		smtp_trigger_dsn(DELIVERY_DELIVERED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->metalen, mqf->size - mqf->metalen);
		fclose(mqf->fp);
		bbs_delete_file(mqf->fullname);
		return 0;
	}

	mqf->newretries++; /* Now it's the new number */
	bbs_debug(3, "Delivery of %s to %s has been attempted %d/%d times\n", mqf->fullname, mqf->realto, mqf->newretries, max_retries);
	if (res == -2 || res > 0 || mqf->newretries >= (int) max_retries) {
		/* Send a delivery failure response, then delete the file. */
		bbs_warning("Delivery of message %s from %s to %s has failed permanently after %d retries\n", mqf->fullname, mqf->realfrom, mqf->realto, mqf->newretries);
		bbs_smtp_log(1, NULL, "Delivery failed permanently after queuing: %s -> %s\n", mqf->realfrom, mqf->realto);
		/* To the dead letter office we go */
		/* XXX buf will only contain the last line of the SMTP transaction, since it was using the readline buffer
		 * Thus, if we got a multiline error, only the last line is currently included in the non-delivery report */
		smtp_trigger_dsn(DELIVERY_FAILED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->metalen, mqf->size - mqf->metalen);
		fclose(mqf->fp);
		bbs_delete_file(mqf->fullname);
		return 0;
	} else {
		bbs_smtp_log(3, NULL, "Delivery delayed after queuing: %s -> %s\n", mqf->realfrom, mqf->realto);
		mailq_file_punt(mqf); /* Try again later */
		smtp_trigger_dsn(DELIVERY_DELAYED, &tx, &mqf->created, mqf->realfrom, mqf->realto, buf, fileno(mqf->fp), mqf->metalen, mqf->size - mqf->metalen);
	}

	fclose(mqf->fp);
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
		/*! \todo Implement smarter queuing:
		 * - Rather than retrying delivery for all queued messages at fixed intervals, use exponential backoff per message
		 * - Store envelope message separately from the file so we don't need to hackily start sending from a file into the offset,
		 *   and so we can easily store other information out of band for queuing purposes.
		 * - Use a separate thread (or some kind of pseudo threadpool) to deliver messages, so a single message delivery taking a long time
		 *   won't block the rest of the queue.
		 * - If delivering the same message to multiple recipients on a single server, it would be nice
		 *   to be able to do that in a single transaction. Sharing a queue file might make sense in this scenarios?
		 */
		bbs_pthread_disable_cancel();
		pthread_mutex_lock(&queue_lock);
		bbs_dir_traverse(queue_dir, on_queue_file, NULL, -1);
		pthread_mutex_unlock(&queue_lock);
		bbs_pthread_enable_cancel();
		usleep(1000000 * queue_interval);
	}
	return NULL;
}

static int on_queue_file_cli_mailq(const char *dir_name, const char *filename, void *obj)
{
	struct bbs_cli_args *a = obj;
	struct mailq_file mqf_stack, *mqf = &mqf_stack;
	char arrival_date[64];

	memset(&mqf_stack, 0, sizeof(mqf_stack));

	if (mailq_file_load(&mqf_stack, dir_name, filename)) {
		return 0;
	}

	strftime(arrival_date, sizeof(arrival_date), "%a, %d %b %Y %H:%M:%S %z", &mqf->created);

	/* Ensure the format is synchronized with the heading in cli_mailq */
	bbs_dprintf(a->fdout, "%-25s %-30s %7d %-30s %s\n", arrival_date, filename, mqf->newretries, mqf->realfrom, mqf->realto);
	return 0;
}

static int cli_mailq(struct bbs_cli_args *a)
{
	bbs_dprintf(a->fdout, "%-25s %-30s %7s %-30s %s\n", "Orig Date", "Filename", "Retries", "Sender", "Recipient");
	pthread_mutex_lock(&queue_lock);
	bbs_dir_traverse(queue_dir, on_queue_file_cli_mailq, a, -1);
	pthread_mutex_unlock(&queue_lock);
	return 0;
}

static int cli_runq(struct bbs_cli_args *a)
{
	UNUSED(a);
	pthread_mutex_lock(&queue_lock);
	bbs_dir_traverse(queue_dir, on_queue_file, NULL, -1);
	pthread_mutex_unlock(&queue_lock);
	return 0;
}

static struct bbs_cli_entry cli_commands_mailq[] = {
	BBS_CLI_COMMAND(cli_mailq, "mailq", 1, "Show the current mail queue", NULL),
	BBS_CLI_COMMAND(cli_runq, "runq", 1, "Retry delivery of all messages in the mail queue", NULL),
};

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
static int external_delivery(struct smtp_session *smtp, struct smtp_response *resp, const char *from, const char *recipient, const char *user, const char *domain, int fromlocal, int tolocal, int srcfd, size_t datalen, void **freedata)
{
#ifndef BUGGY_SEND_IMMEDIATE
	char buf[256] = "";
#endif
	int res = -1;

	UNUSED(user);
	UNUSED(freedata);

	if (tolocal) {
		return 0;
	}

	if (smtp_is_exempt_relay(smtp)) {
		bbs_debug(2, "%s is explicitly authorized to relay mail from %s\n", smtp_node(smtp)->ip, smtp_from_domain(smtp));
	} else {
		bbs_assert(fromlocal); /* Shouldn't have slipped through to this point otherwise */
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

	if (!always_queue && !send_async) {  /* Try to send it synchronously */
		struct stringlist mxservers;
		/* Start by trying to deliver it directly, immediately, right now. */
		memset(&mxservers, 0, sizeof(mxservers));
		res = lookup_mx_all(domain, &mxservers);
		if (res == -2) {
			smtp_abort(resp, 553, 5.1.2, "Recipient domain does not accept mail.");
			return -1;
		}
		if (res) {
			smtp_abort(resp, 553, 5.1.2, "Recipient domain not found.");
			return -1;
		}
#ifndef BUGGY_SEND_IMMEDIATE
		/* Try all the MX servers in order, if necessary */
		while (res < 0 && (hostname = stringlist_pop(&mxservers))) {
			res = try_send(NULL, &tx, hostname, DEFAULT_SMTP_PORT, 0, NULL, NULL, realfrom, realto, NULL, NULL, 0, srcfd, datalen, size - datalen, buf, sizeof(buf));
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

#undef strcat
		strcat(newfile, ".0"); /* Safe */
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

		dprintf(fd, "MAIL FROM:<%s>\nRCPT TO:%s\n", from, recipient); /* First 2 lines contain metadata, and recipient is already enclosed in <> */

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
			bbs_debug(4, "Successfully queued message for immediate delivery: <%s> -> %s\n", from, recipient);
		} else {
			bbs_debug(4, "Successfully queued message for delayed delivery: <%s> -> %s\n", from, recipient);
		}
	}
	return 1;
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
		char buf[132];
		char prepend[256] = "";
		int prependlen = 0;
		char timestamp[40];
		time_t now = time(NULL);

		/* Still prepend a Received header, but less descriptive than normal (don't include Authenticated sender) since we're relaying */
		smtp_timestamp(now, timestamp, sizeof(timestamp));
		prependlen = snprintf(prepend, sizeof(prepend), "Received: from [HIDDEN]\r\n\tby %s with %s\r\n\t%s\r\n",
			bbs_hostname(), smtp_protname(smtp), timestamp);

		bbs_debug(5, "Relaying message via %s:%d (user: %s)\n", url.host, url.port, S_IF(url.user));
		/* XXX smtp->recipients is "used up" by try_send, so this relies on the message being DROP'ed as there will be no recipients remaining afterwards
		 * Instead, we could duplicate the recipients list to avoid this restriction. */
		/* XXX A cool optimization would be if the IMAP server supported BURL IMAP and we did a MOVETO, use BURL with the SMTP server */
		res = try_send(smtp, &tx, url.host, url.port, STARTS_WITH(url.prot, "smtps"), url.user, url.pass, url.user, NULL, recipients, prepend, (size_t) prependlen, srcfd, 0, datalen, buf, sizeof(buf));
	}
	if (url.pass) {
		bbs_memzero(url.pass, strlen(url.pass)); /* Destroy the password */
	}
	return res;
}

static int exists(struct smtp_session *smtp, struct smtp_response *resp, const char *address, const char *user, const char *domain, int fromlocal, int tolocal)
{
	UNUSED(smtp);
	UNUSED(address);
	UNUSED(user);
	UNUSED(domain);

	if (smtp_is_exempt_relay(smtp)) {
		/* Allow an external host to relay messages for a domain if it's explicitly authorized to. */
		bbs_debug(2, "%s is explicitly authorized to relay mail from %s\n", smtp_node(smtp)->ip, smtp_from_domain(smtp));
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
	.exists = exists,
	.deliver = external_delivery,
	.relay = relay,
};

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_smtp.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "relayout", &accept_relay_out);
	bbs_config_val_set_uint(cfg, "general", "maxretries", &max_retries);
	bbs_config_val_set_uint(cfg, "general", "maxage", &max_age);
	bbs_config_val_set_true(cfg, "general", "mailqueue", &queue_outgoing);
	bbs_config_val_set_true(cfg, "general", "sendasync", &send_async);
	bbs_config_val_set_true(cfg, "general", "alwaysqueue", &always_queue);
	bbs_config_val_set_uint(cfg, "general", "queueinterval", &queue_interval);
	bbs_config_val_set_true(cfg, "general", "notifyqueue", &notify_queue);

	bbs_config_val_set_true(cfg, "smtp", "requirestarttls", &require_starttls_out);

	bbs_config_val_set_true(cfg, "privs", "relayout", &minpriv_relay_out);

	if (queue_interval < 60) {
		queue_interval = 60;
	}
	return 0;
}

static int load_module(void)
{
	load_config();
	snprintf(queue_dir, sizeof(queue_dir), "%s/mailq", mailbox_maildir(NULL));
	mailbox_maildir_init(queue_dir); /* The queue dir is also like a maildir, it has a new, tmp, and cur */
	snprintf(queue_dir, sizeof(queue_dir), "%s/mailq/new", mailbox_maildir(NULL));
	if (eaccess(queue_dir, R_OK) && mkdir(queue_dir, 0700)) {
		bbs_error("mkdir(%s) failed: %s\n", queue_dir, strerror(errno));
		return -1;
	}
	pthread_mutex_init(&queue_lock, NULL);
	if (bbs_pthread_create(&queue_thread, NULL, queue_handler, NULL)) {
		pthread_mutex_destroy(&queue_lock);
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_mailq);
	return smtp_register_delivery_handler(&extdeliver, 90); /* Lowest priority */
}

static int unload_module(void)
{
	int res;
	res = smtp_unregister_delivery_agent(&extdeliver);
	bbs_cli_unregister_multiple(cli_commands_mailq);
	bbs_pthread_cancel_kill(queue_thread);
	bbs_pthread_join(queue_thread, NULL);
	pthread_mutex_destroy(&queue_lock);
	return res;
}

BBS_MODULE_INFO_DEPENDENT("E-Mail External Delivery", "net_smtp.so");
