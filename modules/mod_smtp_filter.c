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
		smtp_filter_write(f, "Received: from %s (%s [%s])\r\n\tby %s with %s\r\n\tfor %s; %s\r\n",
			hostname, hostname, f->node->ip, bbs_hostname(), prot, f->recipient, timestamp); /* recipient already in <> */
	}
	return 0;
}

static int builtin_filter_cb(struct smtp_filter_data *f)
{
	if (f->dir == SMTP_DIRECTION_IN) {
		/* This is a good place to tack on Return-Path (receiving MTA does this) */
		smtp_filter_add_header(f, "Return-Path", f->from); /* Envelope From - doesn't have <> so this works out just fine. */
	}

	/* Additional headers added during final delivery.
	 * The Received headers must be newest to oldest.
	 * Not sure about the other headers: by convention, they usually appear after the original ones, but not sure it really matters. */

	if (smtp_is_bulk_mailing(f->smtp)) {
		/* If sent to a mailing list (or more rather, any of the recipients was a mailing list), indicate bulk precedence.
		 * Discouraged by RFC 2076, but this is common practice nonetheless. */
		smtp_filter_add_header(f, "Precedence", "bulk");
	}
	prepend_received(f);
	return 0;
}

struct smtp_filter_provider builtin_filter = {
	.on_body = builtin_filter_cb,
};

static int load_module(void)
{
	smtp_filter_register(&builtin_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_INDIVIDUAL, SMTP_DIRECTION_IN | SMTP_DIRECTION_OUT, 1);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&builtin_filter);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC5321 SMTP Filtering", "net_smtp.so");
