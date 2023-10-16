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
 * \brief RFC5321 Simple Mail Transfer Protocol (SMTP) Core Filtering Callbacks
 * \note Supports RFC8601 Authentication-Results
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/module.h"
#include "include/node.h"
#include "include/utils.h"

#include "include/net_smtp.h"

/*! \brief Prepend a Received header to the received email */
static int prepend_received(struct smtp_filter_data *f)
{
	const char *prot;
	char timestamp[40];

	smtp_timestamp(smtp_received_time(f->smtp), timestamp, sizeof(timestamp));

	prot = smtp_protname(f->smtp);
	/* We don't include a message ID since we don't generate/use any internally (even though the queue probably should...). */
	if (smtp_should_preserve_privacy(f->smtp)) {
		/* For messages received by message submission agents, mask the sender's real IP address */
		smtp_filter_write(f, "Received: from [HIDDEN] (Authenticated sender: %s)\r\n\tby %s with %s\r\n\tfor %s; %s\r\n",
			f->from, bbs_hostname(), prot, f->recipient, timestamp);
	} else {
		char hostname[256];
		bbs_get_hostname(f->node->ip, hostname, sizeof(hostname)); /* Look up the sending IP */
		/* The first hostname is the HELO/EHLO hostname.
		 * The second one is the reverse DNS hostname */
		smtp_filter_write(f, "Received: from %s (%s [%s])\r\n\tby %s with %s\r\n\tfor %s; %s\r\n",
			f->helohost, hostname, f->node->ip, bbs_hostname(), prot, f->recipient, timestamp); /* recipient already in <> */
	}
	return 0;
}

/*! \brief Separate callback for adding Received header to relayed messages, since these could have multiple recipients */
static int relay_filter_cb(struct smtp_filter_data *f)
{
	if (smtp_is_exempt_relay(f->smtp)) {
		const char *prot;
		char timestamp[40];
		char hostname[256];

		prot = smtp_protname(f->smtp);
		smtp_timestamp(smtp_received_time(f->smtp), timestamp, sizeof(timestamp));
		bbs_get_hostname(f->node->ip, hostname, sizeof(hostname)); /* Look up the sending IP */
		/* The first hostname is the HELO/EHLO hostname.
		 * The second one is the reverse DNS hostname */
		smtp_filter_write(f, "Received: from %s (%s [%s])\r\n\tby %s with %s\r\n\tfor %s; %s\r\n",
			f->helohost, hostname, f->node->ip, bbs_hostname(), prot, f->recipient, timestamp); /* recipient already in <> */
	}
	return 0;
}

static int builtin_filter_cb(struct smtp_filter_data *f)
{
	/* This is a good place to tack on Return-Path (receiving MTA does this) */
	smtp_filter_add_header(f, "Return-Path", f->from); /* Envelope From - doesn't have <> so this works out just fine. */

	/* Additional headers added during final delivery.
	 * The Received headers must be newest to oldest.
	 * Not sure about the other headers: by convention, they usually appear after the original ones, but not sure it really matters. */

	prepend_received(f);
	return 0;
}

static int auth_filter_cb(struct smtp_filter_data *f)
{
#define HEADER_CONTINUE "	"
	char *buf;
	int len;

	if (smtp_is_exempt_relay(f->smtp)) {
		return 0;
	}

	/* Add Authentication-Results header with the results of various tests */
	len = asprintf(&buf, "%s" "%s%s%s%s" "%s%s" "%s%s" "%s%s",
		bbs_hostname(),
		f->spf ? ";\r\n" HEADER_CONTINUE "spf=" : "", f->spf ? f->spf : "", f->spf ? " smtp.mailfrom=" : "", f->spf ? f->from : "",
		f->dkim ? ";\r\n" HEADER_CONTINUE "dkim=" : "", S_IF(f->dkim),
		f->arc ? ";\r\n" HEADER_CONTINUE "arc=" : "", S_IF(f->arc),
		f->dmarc ? ";\r\n" HEADER_CONTINUE "dmarc=" : "", S_IF(f->dmarc)
	);
#undef HEADER_CONTINUE

	if (likely(len > 0)) {
		smtp_filter_add_header(f, "Authentication-Results", buf);
		if (f->authresults) {
			free(f->authresults);
		}
		f->authresults = buf; /* Steal reference */
		return 0;
	}

	free(buf);
	return 0;
}

struct smtp_filter_provider builtin_filter = {
	.on_body = builtin_filter_cb,
};

struct smtp_filter_provider relay_filter = {
	.on_body = relay_filter_cb,
};

struct smtp_filter_provider auth_filter = {
	.on_body = auth_filter_cb,
};

static int load_module(void)
{
	smtp_filter_register(&builtin_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_INDIVIDUAL, SMTP_DIRECTION_IN | SMTP_DIRECTION_SUBMIT, 1);
	smtp_filter_register(&relay_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_OUT, 1); /* For messages that are being relayed */
	/* Run this only after the SPF, DKIM, and DMARC filters have run: */
	smtp_filter_register(&auth_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 5);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&builtin_filter);
	smtp_filter_unregister(&relay_filter);
	smtp_filter_unregister(&auth_filter);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC5321 SMTP Filtering", "net_smtp.so");
