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

#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/utils.h"
#include "include/base64.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/stringlist.h"
#include "include/test.h"

#include "include/mod_mail.h"

/* SMTP relay port (mail transfer agents) */
#define DEFAULT_SMTP_PORT 25

/* Mainly for encrypted SMTP message submission agents, though not explicitly in the RFC */
#define DEFAULT_SMTPS_PORT 465

/* Mainly for message submission agents, not encrypted by default, but may use STARTTLS */
#define DEFAULT_SMTP_MSA_PORT 587

#define MAX_RECIPIENTS 100
#define MAX_LOCAL_RECIPIENTS 100
#define MAX_EXTERNAL_RECIPIENTS 10

static int smtp_port = DEFAULT_SMTP_PORT;
static int smtps_port = DEFAULT_SMTPS_PORT;
static int msa_port = DEFAULT_SMTP_MSA_PORT;

static pthread_t smtp_listener_thread = -1;
static pthread_t msa_listener_thread = -1;
static pthread_t queue_thread = -1;

static int smtp_enabled = 1, smtps_enabled = 1, msa_enabled = 1;
static int smtp_socket = -1, smtps_socket = -1, msa_socket = -1;

static int accept_relay_in = 1;
static int accept_relay_out = 1;
static int queue_outgoing = 1;
static int always_queue = 0;
static int require_starttls = 1;
static int require_starttls_out = 0;
static int requirefromhelomatch = 1;

/*! \brief Max message size, in bytes */
static unsigned int max_message_size = 300000;

static unsigned int queue_interval = 900;
static unsigned int max_retries = 10;
static unsigned int max_age = 86400;

/* Allow this module to use dprintf */
#undef dprintf

#define _smtp_reply(smtp, fmt, ...) bbs_debug(6, "%p <= " fmt, smtp, ## __VA_ARGS__); dprintf(smtp->wfd, fmt, ## __VA_ARGS__);

/*! \brief Final SMTP response with this code */
#define smtp_reply(smtp, code, status, fmt, ...) _smtp_reply(smtp, "%d %s " fmt "\r\n", code, #status, ## __VA_ARGS__)
#define smtp_reply_nostatus(smtp, code, fmt, ...) _smtp_reply(smtp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

/*! \brief Non-final SMTP response (subsequent responses with the same code follow) */
#define smtp_reply0(smtp, code, status, fmt, ...) _smtp_reply(smtp, "%d-%s " fmt "\r\n", code, #status, ## __VA_ARGS__)
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
	int numrecipients;
	int numlocalrecipients;
	int numexternalrecipients;
	char *data;
	unsigned long datalen;
	char *helohost;			/* Hostname for HELO/EHLO */
	/* AUTH: Temporary */
	char *authuser;			/* Authentication username */
	unsigned int msa:1;		/* Whether connection was to the Message Submission Agent port (as opposed to the Mail Transfer Agent port) */
	unsigned int secure:1;	/* Whether session is secure (TLS, STARTTLS) */
	unsigned int dostarttls:1;	/* Whether we are initiating STARTTLS */
	unsigned int gothelo:1;	/* Got a HELO/EHLO */
	unsigned int ehlo:1;	/* Client supports ESMTP (EHLO) */
	unsigned int fromlocal:1;	/* Sender is local */
	unsigned int indata:1;	/* Whether client is currently sending email body (DATA) */
	unsigned int datafail:1;	/* Data failure */
	unsigned int inauth:2;	/* Whether currently doing AUTH (1 = need PLAIN, 2 = need LOGIN user, 3 = need LOGIN pass) */
};

static void smtp_destroy(struct smtp_session *smtp)
{
	/* Reset */
	smtp->ehlo = 0;
	smtp->gothelo = 0;
	smtp->indata = 0;
	smtp->inauth = 0;
	free_if(smtp->helohost);
	free_if(smtp->authuser);
	free_if(smtp->from);
	free_if(smtp->data);
	smtp->datalen = 0;
	smtp->datafail = 0;
	smtp->numrecipients = 0;
	smtp->numlocalrecipients = 0;
	smtp->numexternalrecipients = 0;
	stringlist_empty(&smtp->recipients);
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
		return 0; \
	}

#define REQUIRE_HELO() \
	if (!smtp->gothelo) { \
		smtp_reply(smtp, 503, 5.5.1, "EHLO/HELO first."); \
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
		smtp->helohost = strdup(s);
	}

	smtp->gothelo = 1;
	smtp->ehlo = ehlo;
	

	if (ehlo) {
		smtp_reply0_nostatus(smtp, 250, "%s at your service [%s]", bbs_hostname(), smtp->node->ip);
		if (smtp->secure) {
			smtp_reply0_nostatus(smtp, 250, "AUTH LOGIN PLAIN"); /* RFC-complaint way */
			smtp_reply0_nostatus(smtp, 250, "AUTH=LOGIN PLAIN"); /* For non-compliant user agents, e.g. Outlook 2003 and older */
		}
		smtp_reply0_nostatus(smtp, 250, "SIZE %u", max_message_size); /* RFC 1870 */
		smtp_reply0_nostatus(smtp, 250, "ENHANCEDSTATUSCODES");
		smtp_reply_nostatus(smtp, 250, "STARTTLS");
	} else {
		smtp_reply_nostatus(smtp, 250, "%s at your service [%s]", bbs_hostname(), smtp->node->ip);
	}
	return 0;
}

/*! \brief RFC4954 Authentication */
static int handle_auth(struct smtp_session *smtp, char *s)
{
	int inauth = smtp->inauth;

	smtp->inauth = 0;
	REQUIRE_ARGS(s);

	if (!strcmp(s, "*")) {
		/* Client cancelled exchange */
		smtp_reply(smtp, 501, "Authentication cancelled", "");
		return 0;
	}

	if (inauth == 1) {
		int res;
		unsigned char *decoded;
		char *authorization_id, *authentication_id, *password;

		decoded = bbs_sasl_decode(s, &authorization_id, &authentication_id, &password);
		if (!decoded) {
			return -1;
		}

		/* Can't use bbs_sasl_authenticate directly since we need to strip the domain */
		bbs_strterm(authentication_id, '@');
		res = bbs_authenticate(smtp->node, authentication_id, password);
		memset(password, 0, strlen(password)); /* Destroy the password from memory before we free it */
		free(decoded);

		/* Have a combined username and password */
		if (res) {
			/* Don't really know if it was a decoding failure or invalid username/password */
			smtp_reply(smtp, 535, 5.7.8, "Authentication credentials invalid");
			smtp->inauth = 0;
			return 0;
		}
		smtp_reply(smtp, 235, 2.7.0, "Authentication successful");
	} else if (inauth == 2) {
		free_if(smtp->authuser);
		smtp->authuser = strdup(s);
		smtp->inauth = 3; /* Get password */
		smtp_reply(smtp, 334, "UGFzc3dvcmQA", ""); /* Prompt for password (base64 encoded) */
	} else if (inauth == 3) {
		int userlen, passlen;
		int res;
		unsigned char *user, *pass;
		/* Have a password, and a stored username */
		user = base64_decode((unsigned char*) smtp->authuser, strlen(smtp->authuser), &userlen);
		if (!user) {
			smtp_reply(smtp, 502, 5.5.2, "Decoding failure");
			return 0;
		}
		pass = base64_decode((unsigned char*) s, strlen(s), &passlen);
		if (!pass) {
			free(user);
			smtp_reply(smtp, 502, 5.5.2, "Decoding failure");
			return 0;
		}
		res = bbs_user_authenticate(smtp->node->user, (char*) user, (char*) pass);
		free(user);
		free(pass);
		if (res) {
			smtp_reply(smtp, 535, 5.7.8, "Authentication credentials invalid");
			return 0;
		}
		smtp_reply(smtp, 235, 2.7.0, "Authentication successful");
	} else {
		bbs_assert(0);
	}
	return 0;
}

static int parse_email_address(char *addr, char **name, char **user, char **host, int *local)
{
	char address_buf[256]; /* Our mailbox names are definitely not super long, so using a small buffer is okay. */
	char *start, *end, *domain;

	if (!name && !user && !host) { /* If we don't want to keep the parsed result, make a stack copy and leave the original intact. */
		safe_strncpy(address_buf, addr, sizeof(address_buf));
		addr = address_buf;
	}

	start = strchr(addr, '<');
	if (!start++ || strlen_zero(start)) {
		return -1; /* Email address must be enclosed in <> */
	}
	end = strchr(start, '>');
	if (!end) {
		return -1; /* Email address must be enclosed in <> */
	}
	*end = '\0'; /* Now start refers to just the portion in the <> */
	domain = strchr(start, '@');
	if (!domain) {
		return -1; /* Email address must be enclosed in <> */
	}
	domain++;

	if (!user && !host) {
		return 0; /* We only confirmed that this was a valid address. */
	}

	if (name) {
		*name = addr;
	}
	if (user) {
		*(start - 1) = '\0';
		*user = start;
		if (name) {
			rtrim(*name);
		}
	}
	if (host) {
		*(domain - 1) = '\0';
		*host = domain;
	}
	if (local) {
		*local = !strcmp(domain, bbs_hostname());
	}
	return 0;
}

static int test_parse_email(void)
{
	int res = -1;
	char s[84] = "John Smith <test@example.com>";
	char *name, *user, *domain;
	int local;

	bbs_test_assert_equals(0, parse_email_address(s, &name, &user, &domain, &local));
	bbs_test_assert_str_equals(name, "John Smith");
	bbs_test_assert_str_equals(user, "test");
	bbs_test_assert_str_equals(domain, "example.com");

	res = 0;

cleanup:
	return res;
}

static struct unit_tests {
	const char *name;
	int (*callback)(void);
} tests[] =
{
	{ "Parse Email Addresses", test_parse_email },
};

static int handle_rcpt(struct smtp_session *smtp, char *s)
{
	int local;
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
	if (!address) {
		smtp_reply(smtp, 451, "Local error in processing", "");
		return 0;
	}
	if (parse_email_address(address, NULL, &user, &domain, &local)) {
		free(address);
		smtp_reply(smtp, 501, 5.1.7, "Syntax error in RCPT command"); /* Email address must be enclosed in <> */
		return 0;
	}

	if (local) {
		struct mailbox *mbox = mailbox_get(0, user);
		free(address);
		if (!mbox) {
			smtp_reply(smtp, 550, 5.1.1, "No such user here");
			return 0;
		}
		/* User exists, great! */
	} else {
		free(address);
		if (!smtp->fromlocal) { /* External user trying to send us mail that's not for us. */
			smtp_reply(smtp, 550, 5.7.0, "Mail relay denied. Forwarding to remote hosts disabled."); /* We're not an open relay. */
			return 0;
		}
		/* It's a submission of outgoing mail, do no further validation here. */
	}

	if (smtp->numlocalrecipients >= MAX_LOCAL_RECIPIENTS || smtp->numexternalrecipients >= MAX_EXTERNAL_RECIPIENTS || smtp->numrecipients >= MAX_RECIPIENTS) {
		smtp_reply(smtp, 452, 4.5.3, "Your message has too many recipients.");
		return 0;
	}

	/* Actually add the recipient to the recipient list. */
	if (stringlist_contains(&smtp->recipients, s)) {
		/* Recipient was already added. */
		smtp_reply(smtp, 250, 2.0.0, "Duplicate recipient ignored"); /* XXX Appropriate response code? */
		return 0;
	}

	stringlist_push(&smtp->recipients, s);
	smtp->numrecipients += 1;
	if (local) {
		smtp->numlocalrecipients += 1;
	} else {
		smtp->numexternalrecipients += 1;
	}
	smtp_reply(smtp, 250, 2.0.0, "OK");
	return 0;
}

static int lookup_mx(const char *domain, char *buf, size_t len)
{
	char *hostname, *tmp;
	unsigned char answer[PACKETSZ] = "";
	char dispbuf[PACKETSZ] = "";
	int res, i;
	ns_msg msg;
	ns_rr rr;

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
	/* XXX Just pick the first one and run with it */
	for (i = 0; i < res; i++){
		ns_parserr(&msg, ns_s_an, i, &rr);
		ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
		break;
	}

	/* Parse the result */
	bbs_debug(8, "NS answer: %s\n", dispbuf);

	/*! \todo BUGBUG This is very rudimentary and needs to be made much more robust.
	 * For example, this doesn't correctly parse results that don't have an MX record. */
	hostname = dispbuf;
	while (isspace(*hostname)) {
		hostname++;
	}
	do {
		tmp = strchr(hostname, ' ');
	} while (tmp && *(tmp + 1) && (hostname = tmp + 1));

	tmp = strrchr(hostname, '.'); /* Strip the trailing . */
	if (tmp) {
		*tmp = '\0';
	}
	safe_strncpy(buf, hostname, len);
	bbs_debug(6, "MX query for %s: %s\n", domain, hostname);
	return 0;
}

#define SMTP_EXPECT(fd, ms, str) res = bbs_expect(fd, ms, buf, sizeof(buf), str); if (res) { bbs_warning("Expected '%s', got: %s\n", str, buf); goto cleanup; }

#define smtp_client_send(fd, fmt, ...) dprintf(fd, fmt, ## __VA_ARGS__); bbs_debug(3, " => " fmt, ## __VA_ARGS__);

static int try_send(const char *hostname, const char *sender, const char *recipient, const char *data, unsigned long datalen, int datafd, int offset, unsigned long writelen)
{
	SSL *ssl = NULL;
	int sfd, res;
	int rfd, wfd;
	char buf[256];
	int supports_starttls = 0;

	/* Connect on port 25, and don't set up TLS initially. */
	sfd = bbs_tcp_connect(hostname, DEFAULT_SMTP_PORT);
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
	bbs_debug(3, "Attempting delivery of %lu-byte message from %s -> %s via %s\n", datalen, sender, recipient, hostname);

	/* The logic for being an SMTP client with an SMTP MTA is pretty straightforward. */
	SMTP_EXPECT(rfd, 1000, "220");
	smtp_client_send(wfd, "EHLO %s\r\n", bbs_hostname());
	res = bbs_expect(rfd, 1000, buf, sizeof(buf), "250");
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
		while (strstr(buf, "250-")) {
			if (!supports_starttls && strstr(buf, "STARTTLS")) {
				supports_starttls = 1;
			}
			res = bbs_expect(rfd, 1000, buf, sizeof(buf), "250");
		}
		if (!supports_starttls && strstr(buf, "STARTTLS")) { /* For last line */
			supports_starttls = 1;
		}
	}
	if (supports_starttls) {
		smtp_client_send(wfd, "STARTTLS\r\n");
		SMTP_EXPECT(rfd, 2500, "220");
		bbs_debug(3, "Starting TLS\n");
		ssl = ssl_client_new(sfd, &rfd, &wfd);
		if (!ssl) {
			bbs_debug(3, "Failed to set up TLS\n");
			goto cleanup; /* Abort if we were told STARTTLS was available but failed to negotiate. */
		}
		/* Start over again. */
		smtp_client_send(wfd, "EHLO %s\r\n", bbs_hostname());
		SMTP_EXPECT(rfd, 2500, "250");
	} else if (require_starttls_out) {
		bbs_warning("SMTP server %s does not support STARTTLS, but encryption is mandatory. Delivery failed.\n", hostname);
		res = 1;
		goto cleanup;
	}
	smtp_client_send(wfd, "MAIL FROM:<%s>\r\n", sender); /* sender lacks <>, but recipient has them */
	SMTP_EXPECT(rfd, 1000, "250");
	smtp_client_send(wfd, "RCPT TO:%s\r\n", recipient);
	SMTP_EXPECT(rfd, 1000, "250");
	smtp_client_send(wfd, "DATA\r\n");
	SMTP_EXPECT(rfd, 1000, "354");
	if (datafd >= 0) {
		off_t send_offset = offset;
		/* sendfile will be much more efficient than reading the file ourself, as email body could be quite large, and we don't need to involve userspace. */
		res = sendfile(wfd, datafd, &send_offset, writelen);
		datalen = writelen;
	} else {
		res = bbs_std_write(wfd, data, datalen); /* This won't show up in debug, which is probably a good thing. */
	}
	smtp_client_send(wfd, ".\r\n");
	if (res != (int) datalen) { /* Failed to write full message */
		bbs_error("Wanted to write %lu bytes but wrote only %d?\n", datalen, res);
		res = -1;
		goto cleanup;
	}
	SMTP_EXPECT(rfd, 5000, "250"); /* Okay, this email is somebody else's problem now. */

cleanup:
	if (res > 0) {
		smtp_client_send(wfd, "QUIT\r\n");
	}
	if (ssl) {
		ssl_close(ssl);
	}
	close(sfd);
	return res;
}

static int do_local_delivery(const char *user, const char *data, unsigned long datalen)
{
	struct mailbox *mbox;
	char tmpfile[256], newfile[256];
	int fd, res;

	mbox = mailbox_get(0, user);
	if (!mbox) {
		/* We should've caught this before. */
		bbs_warning("Mailbox '%s' does not exist locally\n", user);
		return -1;
	}

	/* No need to get a mailbox lock, really. */
	if (mailbox_maildir_init(mailbox_maildir(mbox))) {
		return -1;
	}
	fd = maildir_mktemp(mailbox_maildir(mbox), tmpfile, sizeof(tmpfile), newfile);
	if (fd < 0) {
		return -1;
	}

	/* Write the entire body of the message. */
	res = bbs_std_write(fd, data, datalen); /* Faster than fwrite since we're writing a lot of data, don't need buffering, and know the length. */
	if (res != (int) datalen) {
		bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", datalen, tmpfile, res);
		close(fd);
		return -1;
	}

	close(fd);
	if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		return -1;
	}
	return 0;
}

static int on_queue_file(const char *dir_name, const char *filename, void *obj)
{
	FILE *fp;
	char fullname[256], newname[sizeof(fullname) + 11];
	char from[1000], recipient[1000], todup[256];
	char hostname[256];
	char *realfrom, *realto;
	char *user, *domain;
	int local;
	char *retries;
	int newretries;
	int res;
	unsigned long size;
	int metalen;

	UNUSED(dir_name);
	UNUSED(obj);

	snprintf(fullname, sizeof(fullname), "%s/%s", dir_name, filename);

	fp = fopen(fullname, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
		return 0;
	}

	fseek(fp, 0L, SEEK_END); /* Go to EOF */
	size = ftell(fp);
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

	realfrom = strchr(from, '<');
	realto = strchr(recipient, '<');

	/* If you manually edit the queue files, the line endings will get converted,
	 * and since the queue files use a combination of LF and CR LF,
	 * that can mess things up.
	 * In particular, something like nano will convert everything to LF,
	 * so bbs_fd_readline will return the entire body as one big blob,
	 * since the file has no CR LF delimiters at all.
	 * And because rely on CR LF . CR LF for end of email detection,
	 * we'll only see LF . CR LF at the end, and delivery will thus fail.
	 * Do not modify the mail queue files manually for debugging, unless you really know what you are doing,
	 * and in particular are preserving the mixed line endings. */
	bbs_strterm(realto, '\r'); /* XXX Shouldn't be necessary? But strip any CR if there is one. */
	bbs_strterm(realto, '\n'); /* Ditto */

	if (!realfrom || !realto) {
		bbs_error("Invalid mail queue file: %s\n", fullname);
		goto cleanup;
	}
	realfrom++;
	safe_strncpy(todup, realto, sizeof(todup));
	if (strlen_zero(realfrom) || parse_email_address(todup, NULL, &user, &domain, &local)) {
		bbs_error("Address parsing error\n");
		goto cleanup;
	}
	bbs_strterm(realfrom, '>'); /* try_send will add <> for us, so strip it here to match */

	bbs_debug(2, "Retrying delivery of %s (%s -> %s)\n", fullname, realfrom, realto);

	if (lookup_mx(domain, hostname, sizeof(hostname))) {
		bbs_error("Recipient domain does not have any MX records: %s\n", domain);
		goto cleanup; /* XXX Should just treat as undeliverable at this point and return to sender */
	}

	res = try_send(hostname, realfrom, realto, NULL, 0, fileno(fp), metalen, size - metalen);
	if (!res) {
		/* Successful delivery. */
		fclose(fp);
		if (unlink(fullname)) {
			bbs_error("Failed to remove file %s\n", fullname);
		}
		return 0;
	}

	newretries = atoi(retries) + 1;
	fclose(fp);
	bbs_debug(3, "Delivery of %s to %s has been attempted %d/%d times\n", fullname, realto, newretries, max_retries);
	if (newretries >= (int) max_retries) {
		/* Send a delivery failure response, then delete the file. */
		bbs_warning("Delivery of message %s from %s to %s has failed permanently after %d retries\n", fullname, realfrom, realto, newretries);
		/*! \todo Implement: generate "Undelivered Mail Returned to Sender" email and send it to the sending user using do_local_delivery (then delete the message) */
#if 0
		if (unlink(fullname)) {
			bbs_error("Failed to remove file %s\n", fullname);
		}
#endif
	} else {
		char tmpbuf[256];
		safe_strncpy(tmpbuf, fullname, sizeof(tmpbuf));
		bbs_strterm(tmpbuf, '.');
		/* Store retry information in the filename itself, so we don't have to modify the file, we can just rename it. Inspired by IMAP. */
		snprintf(newname, sizeof(newname), "%s.%d", tmpbuf, newretries);
		if (rename(fullname, newname)) {
			bbs_error("Failed to rename %s to %s\n", fullname, newname);
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
	char qdir[256];

	UNUSED(unused);

	if (!queue_outgoing) {
		return NULL; /* Not needed, queuing disabled */
	}

	snprintf(qdir, sizeof(qdir), "%s/mailq/new", mailbox_maildir(NULL));
	usleep(10000000); /* Wait 10 seconds after the module loads, then try to flush anything in the queue. */

	for (;;) {
		bbs_dir_traverse(qdir, on_queue_file, NULL, -1);
		usleep(1000000 * queue_interval);
	}
	return NULL;
}

/*! \brief Accept delivery of a message to an external recipient, sending it now if possible and queuing it otherwise */
static int external_delivery(struct smtp_session *smtp, const char *recipient, const char *domain)
{
	char hostname[256];
	int res = -1;

	bbs_assert(smtp->fromlocal);
	if (!accept_relay_out) {
		smtp_reply(smtp, 550, 5.7.0, "Mail relay denied.");
		return 0;
	}

	if (!always_queue) {
		/* Start by trying to deliver it directly, immediately, right now. */
		if (lookup_mx(domain, hostname, sizeof(hostname))) {
			smtp_reply(smtp, 553, 5.1.2, "Recipient domain not found.");
			return 0;
		}
		res = try_send(domain, smtp->from, recipient, smtp->data, smtp->datalen, -1, 0, 0);
	}
	if (res && !queue_outgoing) {
		bbs_debug(3, "Delivery failed and can't queue message, rejecting\n");
		return -1; /* Can't queue failed message, so reject it now. */
	} else if (res) {
		int fd;
		char qdir[256];
		char tmpfile[256], newfile[256];
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
		 */
		dprintf(fd, "MAIL FROM:<%s>\nRCPT TO:%s\n", smtp->from, recipient); /* First 2 lines contain metadata, and recipient is already enclosed in <> */
		/* Write the entire body of the message. */
		res = bbs_std_write(fd, smtp->data, smtp->datalen); /* Faster than fwrite since we're writing a lot of data, don't need buffering, and know the length. */
		if (res != (int) smtp->datalen) {
			bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", smtp->datalen, tmpfile, res);
			close(fd);
			return -1;
		}
		if (rename(tmpfile, newfile)) {
			bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
			close(fd);
			return -1;
		}
		close(fd);
		bbs_debug(4, "Successfully queued message for delayed delivery\n");
		return 0;
	}
	return 0;
}

static int local_delivery(struct smtp_session *smtp, const char *recipient, const char *user)
{
	UNUSED(recipient); /* Mailboxes implicitly only support a single domain */
	return do_local_delivery(user, smtp->data, smtp->datalen);
}

/*! \brief Actually send an email or queue it for delivery */
static int do_deliver(struct smtp_session *smtp)
{
	char *recipient;
	int res = 0;

	if (smtp->datalen >= max_message_size) {
		/* XXX Should this only apply for local deliveries? */
		smtp_reply(smtp, 552, 5.3.4, "Message too large");
		return 0;
	}

	while ((recipient = stringlist_pop(&smtp->recipients))) {
		int local;
		char *user, *domain;
		char *dup = strdup(recipient);
		if (!dup) {
			bbs_error("strdup failed\n");
			goto next;
		}
		/* We already did this when we got RCPT TO, so hopefully we're all good here. */
		if (parse_email_address(dup, NULL, &user, &domain, &local)) {
			goto next;
		}
		if (local) {
			res |= local_delivery(smtp, recipient, user);
		} else {
			res |= external_delivery(smtp, recipient, domain);
		}
next:
		free_if(dup);
		free(recipient);
	}

	if (res) {
		/*! \todo BUGBUG FIXME Could be multiple responses */
		smtp_reply_nostatus(smtp, 451, "Delivery failed");
	} else {
		smtp_reply(smtp, 250, 2.6.0, "Message accepted");
	}
	return 0;
}

static int smtp_process(struct smtp_session *smtp, char *s)
{
	char *command;

	if (smtp->inauth) {
		return handle_auth(smtp, s);
	} else if (smtp->indata) {
		int dlen;

		if (!strcmp(s, ".")) {
			smtp->indata = 0;
			if (smtp->datafail) {
				/* Message not successfully received in totality, so reject it. */
				smtp_reply(smtp, 451, 4.3.0, "Message not received successfully, try again.");
				return 0;
			}
			return do_deliver(smtp);
		} else if (*s == '.') {
			s++; /* RFC 5321 4.5.2: If first character is a period but there's more data afterwards, skip the first period. */
		}

		if (smtp->datafail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		dlen = strlen(s); /* s may be empty but will not be NULL */

		if (!smtp->data) { /* First line */
			smtp->data = malloc(dlen + 3); /* Use malloc instead of strdup so we can tack on a CR LF */
			if (!smtp->data) {
				smtp->datafail = 1;
				return 0;
			}
			strcpy(smtp->data, s); /* Safe */
			strcpy(smtp->data + dlen, "\r\n"); /* Safe */
			smtp->datalen = dlen + 2;
		} else { /* Additional line */
			char *newstr;
			newstr = realloc(smtp->data, smtp->datalen + dlen + 3);
			if (!newstr) {
				smtp->datafail = 1;
				return 0;
			}
			strcpy(newstr + smtp->datalen, s);
			strcpy(newstr + smtp->datalen + dlen, "\r\n");
			smtp->datalen += dlen + 2;
			smtp->data = newstr;
		}
		if (smtp->datalen >= max_message_size) {
			smtp->datafail = 1;
		}
		return 0;
	}

	command = strsep(&s, " ");
	REQUIRE_ARGS(command);

	if (!strcasecmp(command, "RSET")) {
		smtp_destroy(smtp);
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
		smtp_reply(smtp, 504, 5.5.4, "Must issue a STARTTLS command first.");
	} else if (!strcasecmp(command, "AUTH")) {
		/* https://www.samlogic.net/articles/smtp-commands-reference-auth.htm */
		if (smtp->inauth) { /* Already in authorization */
			smtp_reply(smtp, 503, 5.5.1, "Bad sequence of commands.");
		} else if (bbs_user_is_registered(smtp->node->user)) { /* Already authed */
			smtp_reply(smtp, 503, 5.7.0, "Already authenticated, no identity changes permitted");
		} else if (!smtp->secure) {
			/* Must not offer PLAIN or LOGIN on insecure connections. */
			smtp_reply(smtp, 504, 5.5.4, "Must issue a STARTTLS command first.");
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
				smtp_reply(smtp, 334, "VXNlciBOYW1lAA==", ""); /* Prompt for username (base64 encoded) */
			} else {
				smtp_reply(smtp, 504, 5.7.4, "Unrecognized Authentication Type.");
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

		REQUIRE_ARGS(s);
		ltrim(s);
		REQUIRE_ARGS(s);
		from = strsep(&s, " ");
		if (!strlen_zero(s)) {
			char *sizestring;
			/* Part of the SIZE extension. For ESMTP, something like SIZE=XXX */
			sizestring = strchr(s, '=');
			if (sizestring && !strlen_zero(sizestring + 1)) {
				unsigned int sizebytes = atoi(sizestring);
				if (sizebytes >= max_message_size) {
					smtp_reply(smtp, 552, 5.3.4, "Message too large");
					return 0;
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
		tmp = strchr(from, '@');
		REQUIRE_ARGS(tmp); /* Must be user@domain */
		tmp++; /* Skip @ */
		if (!strcasecmp(tmp, bbs_hostname())) {
			/* It's one of our addresses. Authentication is required. */
			if (!bbs_user_is_registered(smtp->node->user)) {
				smtp_reply(smtp, 530, 5.7.0, "Authentication required");
				return 0;
			}
			smtp->fromlocal = 1;
		} else {
			smtp->fromlocal = 0; /* It's not something that belongs to us. No authentication required. */
			if (strlen_zero(smtp->helohost) || (requirefromhelomatch && strcmp(tmp, smtp->helohost))) {
				smtp_reply(smtp, 530, 5.7.0, "HELO/EHLO domain does not match MAIL FROM domain");
				return 0;
			}
		}
		free_if(smtp->from);
		smtp->from = strdup(from);
		smtp_reply(smtp, 250, 2.0.0, "OK");
	} else if (!strcasecmp(command, "RCPT")) {
		REQUIRE_HELO();
		if (!smtp->from) {
			smtp_reply(smtp, 503, 5.5.1, "MAIL first.");
			return 0;
		}
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
		if (!smtp->from) {
			smtp_reply(smtp, 503, 5.5.1, "MAIL first.");
			return 0;
		} else if (!smtp->numrecipients) {
			smtp_reply(smtp, 503, 5.5.1, "RCPT first.");
			return 0;
		}
		free_if(smtp->data);
		smtp->indata = 1;
		/* Begin reading data. */
		smtp_reply_nostatus(smtp, 354, "Start mail input; end with a period on a line by itself");
	} else {
		smtp_reply(smtp, 502, 5.5.1, "Unrecognized command.");
	}

	return 0;
}

/*! \todo XXX Relay settings: could either reject external mail or silently accept it but not really send it? "impersonate"? e.g. spamhole - open relay honeypot*/

static void handle_client(struct smtp_session *smtp, SSL **sslptr)
{
	char buf[1001]; /* Maximum length, including CR LF, is 1000 */
	int res;
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));  

	smtp_reply_nostatus(smtp, 220, "%s ESMTP Service Ready", bbs_hostname());

	for (;;) {
		res = bbs_fd_readline(smtp->rfd, &rldata, "\r\n", 60000); /* Wait 60 seconds, that ought to be plenty even for manual testing... real SMTP clients won't need more than a couple seconds. */
		if (res < 0) {
			res += 1; /* Convert the res back to a normal one. */
			if (res == 0) {
				/* Timeout occured. */
				smtp_reply(smtp, 451, 4.4.2, "Timeout - closing connection."); /* XXX Should do only if poll returns 0, not if read returns 0 */
			}
			break;
		}
		if (smtp->indata) {
			bbs_debug(6, "%p => [%d data bytes]\n", smtp, res); /* This could be a lot of output, don't show it all. */
		} else {
			bbs_debug(6, "%p => %s\n", smtp, buf);
		}
		if (smtp_process(smtp, buf)) {
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
		}
	}
}

/*! \brief Thread to handle a single SMTP/SMTPS client */
static void smtp_handler(struct bbs_node *node, int msa, int secure)
{
#ifdef HAVE_OPENSSL
	SSL *ssl;
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
	smtp.secure = secure;
	smtp.msa = msa;

	handle_client(&smtp, &ssl);

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
	smtp_handler(node, secure, secure); /* Actually handle the SMTP/SMTPS client */

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

static void *__msa_handler(void *varg)
{
	struct bbs_node *node = varg;

	node->thread = pthread_self();
	bbs_node_begin(node);

	smtp_handler(node, 1, 0); /* Actually handle the message submission agent client */

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

/*! \brief Single listener thread for SMTP and/or SMTPS */
static void *smtp_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener2(smtp_socket, smtps_socket, "SMTP", "SMTPS", __smtp_handler, BBS_MODULE_SELF);
	return NULL;
}

static void *msa_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener(msa_socket, "SMTP (MSA)", __msa_handler, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_smtp.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "relayin", &accept_relay_in);
	bbs_config_val_set_true(cfg, "general", "relayout", &accept_relay_out);
	bbs_config_val_set_true(cfg, "general", "mailqueue", &queue_outgoing);
	bbs_config_val_set_true(cfg, "general", "alwaysqueue", &always_queue);
	bbs_config_val_set_uint(cfg, "general", "queueinterval", &queue_interval);
	bbs_config_val_set_uint(cfg, "general", "maxretries", &max_retries);
	bbs_config_val_set_uint(cfg, "general", "maxage", &max_age);
	bbs_config_val_set_uint(cfg, "general", "maxsize", &max_message_size);
	bbs_config_val_set_true(cfg, "general", "requirefromhelomatch", &requirefromhelomatch);

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

	return 0;
}

static int load_module(void)
{
	long unsigned int i;
	if (load_config()) {
		return -1;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!smtp_enabled && !smtps_enabled && !msa_enabled) {
		bbs_debug(3, "Neither SMTP nor SMTPS nor MSA is enabled, declining to load\n");
		return -1; /* Nothing is enabled */
	}
	if (smtps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, SMTPS may not be used\n");
		return -1;
	}

	if (strlen_zero(bbs_hostname())) {
		bbs_error("A BBS hostname in nodes.conf is required for mail services\n");
		return -1;
	}

	/* If we can't start the TCP listeners, decline to load */
	if (smtp_enabled && bbs_make_tcp_socket(&smtp_socket, smtp_port)) {
		return -1;
	}
	if (smtps_enabled && bbs_make_tcp_socket(&smtps_socket, smtps_port)) {
		close_if(smtp_socket);
		return -1;
	}
	if (msa_enabled && bbs_make_tcp_socket(&msa_socket, msa_port)) {
		close_if(smtps_socket);
		close_if(smtp_socket);
		return -1;
	}

	if (bbs_pthread_create(&smtp_listener_thread, NULL, smtp_listener, NULL)) {
		bbs_error("Unable to create SMTP listener thread.\n");
		close_if(msa_socket);
		close_if(smtp_socket);
		close_if(smtps_socket);
		return -1;
	} else if (bbs_pthread_create(&msa_listener_thread, NULL, msa_listener, NULL)) {
		bbs_error("Unable to create SMTP MSA listener thread.\n");
		close_if(msa_socket);
		close_if(smtp_socket);
		close_if(smtps_socket);
		pthread_cancel(smtp_listener_thread);
		pthread_kill(smtp_listener_thread, SIGURG);
		bbs_pthread_join(smtp_listener_thread, NULL);
		return -1;
	}

	if (bbs_pthread_create(&queue_thread, NULL, queue_handler, NULL)) {
		close_if(msa_socket);
		close_if(smtp_socket);
		close_if(smtps_socket);
		pthread_cancel(smtp_listener_thread);
		pthread_kill(smtp_listener_thread, SIGURG);
		bbs_pthread_join(smtp_listener_thread, NULL);
		pthread_cancel(msa_listener_thread);
		pthread_kill(msa_listener_thread, SIGURG);
		bbs_pthread_join(msa_listener_thread, NULL);
		return -1;
	}

	if (smtp_enabled) {
		bbs_register_network_protocol("SMTP", smtp_port);
	}
	if (smtps_enabled) {
		bbs_register_network_protocol("SMTPS", smtps_port); /* This is also for MSA */
	}
	if (msa_enabled) {
		bbs_register_network_protocol("SMTP (MSA)", msa_port);
	}
	for (i = 0; i < ARRAY_LEN(tests); i++) {
		bbs_register_test(tests[i].name, tests[i].callback);
	}
	return 0;
}

static int unload_module(void)
{
	long unsigned int i;
	for (i = 0; i < ARRAY_LEN(tests); i++) {
		bbs_unregister_test(tests[i].callback);
	}
	pthread_cancel(smtp_listener_thread);
	pthread_kill(smtp_listener_thread, SIGURG);
	bbs_pthread_join(smtp_listener_thread, NULL);
	pthread_cancel(msa_listener_thread);
	pthread_kill(msa_listener_thread, SIGURG);
	bbs_pthread_join(msa_listener_thread, NULL);
	pthread_cancel(queue_thread);
	pthread_kill(queue_thread, SIGURG);
	bbs_pthread_join(queue_thread, NULL);
	if (smtp_enabled) {
		bbs_unregister_network_protocol(smtp_port);
		close_if(smtp_socket);
	}
	if (smtps_enabled) {
		bbs_unregister_network_protocol(smtps_port);
		close_if(smtps_socket);
	}
	if (msa_enabled) {
		bbs_unregister_network_protocol(msa_port);
		close_if(msa_socket);
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC5321 SMTP MTA/MSA Servers", "mod_mail.so");
