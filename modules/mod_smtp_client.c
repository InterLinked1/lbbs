/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023-2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief SMTP client
 *
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>

#include "include/module.h"
#include "include/utils.h"

#include "include/mod_smtp_client.h"

int bbs_smtp_client_connect(struct bbs_smtp_client *smtpclient, const char *helohost, const char *hostname, int port, int secure, char *buf, size_t len)
{
	int res;

	memset(smtpclient, 0, sizeof(struct bbs_smtp_client));
	memset(&smtpclient->client, 0, sizeof(smtpclient->client));
	memset(&smtpclient->url, 0, sizeof(smtpclient->url));

	smtpclient->helohost = helohost;
	smtpclient->hostname = hostname;
	smtpclient->url.host = hostname;
	smtpclient->url.port = port;
	SET_BITFIELD(smtpclient->secure, secure);
	res = bbs_tcp_client_connect(&smtpclient->client, &smtpclient->url, secure, buf, len);
	if (res) {
		bbs_debug(3, "Failed to set up TCP connection to %s\n", hostname);
		return res;
	}
	return 0;
}

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
	PARSE_CAPABILITY("ETRN", SMTP_CAPABILITY_ETRN)
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
	} else if (!strcasecmp(capname, "CHUNKING") || !strcasecmp(capname, "SMTPUTF8") || !strcasecmp(capname, "BINARYMIME")
		|| !strcasecmp(capname, "VRFY") || !strcasecmp(capname, "ETRN") || !strcasecmp(capname, "DSN") || !strcasecmp(capname, "HELP")) {
		/* Don't care about */
	} else if (!strcmp(capname, "PIPECONNECT")) {
		/* Don't care about, at the moment, but could be used in the future to optimize:
		 * https://www.exim.org/exim-html-current/doc/html/spec_html/ch-main_configuration.html */
	} else if (!strcmp(capname, "AUTH=LOGIN PLAIN")) {
		/* Ignore: this SMTP server advertises this capability (even though it's malformed) to support some broken clients */
	} else if (!strcasecmp(capname, "OK")) {
		/* This is not a real capability, just ignore it. Yahoo seems to do this. Some other MTAs too, but not all uppercase (e.g. 'Ok'). */
	} else {
		/* Capabilities should be all uppercase, and could be one or multiple words
		 * The first line is often the hostname of the server followed by some friendly greeting, ignore.
		 * This callback doesn't know if it's the first line, but the hostname should have at least one period */
		if (strchr(capname, '.')) {
			return; /* Ignore, probably the hostname banner, not a real capability */
		}
		if (!strchr(capname, ' ')) {
			bbs_warning("Unknown capability advertised: %s\n", capname);
		}
	}
}

int bbs_smtp_client_expect_final(struct bbs_smtp_client *restrict smtpclient, int ms, const char *code, size_t codelen)
{
	int res;
	/* Read until we get a response that isn't the desired code or isn't a nonfinal response */
	do {
		res = bbs_tcp_client_expect(&smtpclient->client, "\r\n", 1, ms, code);
		bbs_debug(3, "Found '%s': %s\n", code, smtpclient->client.rldata.buf);
	} while (!strncmp(smtpclient->client.rldata.buf, code, codelen) && smtpclient->client.rldata.buf[codelen] == '-');
	if (res > 0) {
		bbs_warning("Expected '%s', got: %s\n", code, smtpclient->client.rldata.buf);
	} else if (res < 0) {
		bbs_warning("Failed to receive '%s'\n", code);
	}
	return res;
}

int bbs_smtp_client_handshake(struct bbs_smtp_client *restrict smtpclient, int require_secure)
{
	int res = 0;

	bbs_smtp_client_send(smtpclient, "EHLO %s\r\n", smtpclient->helohost);
	/* Don't use bbs_smtp_client_expect_final as we'll miss reading the capabilities */
	res = bbs_tcp_client_expect(&smtpclient->client, "\r\n", 1, MIN_MS(5), "250"); /* Won't return 250 if ESMTP not supported */
	if (res) { /* Fall back to HELO if EHLO not supported */
		if (require_secure && !smtpclient->secure) { /* STARTTLS is only supported by EHLO, not HELO */
			bbs_warning("SMTP server %s does not support STARTTLS, but encryption is mandatory. Aborting connection.\n", smtpclient->hostname);
			res = 1;
			goto cleanup;
		}
		bbs_debug(3, "SMTP server %s does not support ESMTP, falling back to regular SMTP\n", smtpclient->hostname);
		bbs_smtp_client_send(smtpclient, "HELO %s\r\n", smtpclient->helohost);
		SMTP_CLIENT_EXPECT_FINAL(smtpclient, MIN_MS(5), "250");
	} else {
		/* Keep reading the rest of the multiline EHLO */
		while (STARTS_WITH(smtpclient->client.rldata.buf, "250-")) {
			bbs_debug(9, "<= %s\n", smtpclient->client.rldata.buf);
			process_capabilities(&smtpclient->caps, &smtpclient->maxsendsize, smtpclient->client.rldata.buf + 4);
			res = bbs_tcp_client_expect(&smtpclient->client, "\r\n", 1, SEC_MS(15), "250");
		}
		bbs_debug(9, "<= %s\n", smtpclient->client.rldata.buf);
		process_capabilities(&smtpclient->caps, &smtpclient->maxsendsize, smtpclient->client.rldata.buf + 4);
		bbs_debug(6, "Finished processing multiline EHLO\n");
	}

cleanup:
	return res;
}

int bbs_smtp_client_starttls(struct bbs_smtp_client *restrict smtpclient)
{
	int res;
	if (smtpclient->secure) {
		bbs_error("Can't do STARTTLS, connection is already secure\n");
		return -1;
	}
	if (!ssl_available()) {
		bbs_error("Can't do STARTTLS, TLS module is not loaded\n");
		return -1;
	}
	if (smtpclient->caps & SMTP_CAPABILITY_STARTTLS) {
		bbs_smtp_client_send(smtpclient, "STARTTLS\r\n");
		SMTP_CLIENT_EXPECT_FINAL(smtpclient, 2500, "220");
		bbs_debug(3, "Starting TLS\n");
		if (bbs_tcp_client_starttls(&smtpclient->client, smtpclient->hostname)) {
			return -1; /* Abort if we were told STARTTLS was available but failed to negotiate. */
		}
		smtpclient->secure = 1;
		/* Start over again. */
		smtpclient->caps = 0;
		return bbs_smtp_client_handshake(smtpclient, 1);
	}
	/* STARTTLS not supported */

cleanup: /* Used by SMTP_CLIENT_EXPECT_FINAL */
	return -1;
}

void bbs_smtp_client_destroy(struct bbs_smtp_client *restrict smtpclient)
{
	bbs_tcp_client_cleanup(&smtpclient->client);
}

static int load_module(void)
{
	return 0;
}

static int unload_module(void)
{
	return 0;
}

BBS_MODULE_INFO_FLAGS("SMTP Client", MODFLAG_GLOBAL_SYMBOLS);
