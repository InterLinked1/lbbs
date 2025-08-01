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
 * \note Supports RFC9228 Delivered-To
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

	prot = smtp_protname(f->smtp);
	smtp_timestamp(smtp_received_time(f->smtp), timestamp, sizeof(timestamp));

	/* We don't include a message ID since we don't generate/use any internally (even though the queue probably should...). */
	if (smtp_should_preserve_privacy(f->smtp)) {
		/* When choosing an email address to include for the 'Authenticated sender', it makes sense to
		 * prefer to use the one in the From header as opposed to the MAIL FROM.
		 * This is because the MAIL FROM for submissions is almost meaningless, and doesn't get factored
		 * into any authentication that is done. In contrast, if we allowed a From header to be used,
		 * the user was authorized to use that identity.
		 * Additionally, using the MAIL FROM, apart from being wrong, can also leak sensitive information,
		 * such as the primary email address of the account through which the message is being sent using another identity. */
		const char *from = S_OR(smtp_from_address(f->smtp), f->from);
		/* For messages received by message submission agents, mask the sender's real IP address */
		smtp_filter_write(f, "Received: from [HIDDEN] (Authenticated sender: %s)\r\n\tby %s with %s\r\n\tfor %s; %s\r\n",
			from, smtp_hostname(), prot, f->recipient, timestamp);
	} else {
		char hostname[256];
		/* We allow for running this filter even without a node (e.g. for injected mail, such as mailing list posts). */
		if (f->node) {
			bbs_get_hostname(f->node->ip, hostname, sizeof(hostname)); /* Look up the sending IP */
		}
		/* The first hostname is the HELO/EHLO hostname.
		 * The second one is the reverse DNS hostname */
		smtp_filter_write(f, "Received: from %s (%s [%s])\r\n\tby %s with %s\r\n\tfor %s; %s\r\n",
			S_OR(f->helohost, "localhost"),
			/* Do not use S_COR for the below two: f->node is not a string */
			f->node ? hostname : "localhost",
			f->node ? f->node->ip : "127.0.0.1",
			smtp_hostname(), prot, f->recipient, timestamp); /* recipient already in <> */
	}
	return 0;
}

static int received_filter_cb(struct smtp_filter_data *f)
{
	/* Additional headers added during final delivery.
	 * The Received headers must be newest to oldest.
	 * Not sure about the other headers: by convention, they usually appear after the original ones, but not sure it really matters. */
	prepend_received(f);
	return 0;
}

/*! \brief Separate callback for adding Received header to relayed messages, since these could have multiple recipients */
static int relay_filter_cb(struct smtp_filter_data *f)
{
	const char *prot;
	char timestamp[40];
	char hostname[256];

	/* XXX This is not the most elegant workaround, but is extremely critical!
	 * This handles the case where a local user submits a message that is sent to an external party.
	 * This is a submission that is leaving the system, NOT a message that is being "relayed" in the sense we care about here.
	 * In this case, we should NOT run everything in the builtin_filter_cb (such as adding Return-Path),
	 * but we SHOULD be adding the Received header based on smtp_should_preserve_privacy, since it's a user submission.
	 * (Not respecting WILL result in the user's IP address being inadvertently leaked!)
	 * Since the logic we want is exactly that in prepend_received, just call that instead here. */
	if (smtp_is_message_submission(f->smtp)) {
		return prepend_received(f);
	}

	prot = smtp_protname(f->smtp);
	smtp_timestamp(smtp_received_time(f->smtp), timestamp, sizeof(timestamp));

	if (f->node) {
		bbs_get_hostname(f->node->ip, hostname, sizeof(hostname)); /* Look up the sending IP */
	}

	/* This is to cover:
	 * 1) The case of other MTAs that relay their outgoing mail through us (smtp_is_exempt_relay(f->smtp) == 1)
	 * 2) The case of other MTAs that receive their incoming mail through us.
	 *
	 * Note: Originally, only the first case was handled here, but when the ability to forward incoming mail was
	 * added, the second case had to be considered, and as I can't think of any counterexamples
	 * to messages running the OUT filter being one or the other, the conditional was removed altogether.
	 * If we find later that there are OUT messages for which we shouldn't be adding a "Received" header,
	 * then this logic may need to be refined.
	 *
	 * The first hostname is the HELO/EHLO hostname. The second one is the reverse DNS hostname */
	smtp_filter_write(f, "Received: from %s (%s [%s])\r\n\tby %s with %s\r\n\tfor %s; %s\r\n",
		S_OR(f->helohost, "localhost"),
		/* Do not use S_COR for the below two: f->node is not a string */
		f->node ? hostname : "localhost",
		f->node ? f->node->ip : "127.0.0.1",
		smtp_hostname(), prot, f->recipient, timestamp); /* recipient already in <> */

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

	/* If we didn't do any checks, don't add the header at all. */
	if (!f->spf && !f->dkim && !f->arc && !f->dmarc) {
		return 0;
	}

	/* Add Authentication-Results header with the results of various tests */
	len = asprintf(&buf, "%s" "%s%s%s%s" "%s%s" "%s%s" "%s%s",
		smtp_hostname(),
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

static int returnpath_filter_cb(struct smtp_filter_data *f)
{
	/* This is a good place to tack on Return-Path (receiving MTA does this)
	 * The angle brackets around the address are optional, some mail servers include these, some don't.
	 * However, if the Return-Path is empty (e.g. a bounce message generated by ourself),
	 * it is standard to always include <>, regardless of whether these are present normally. */
	smtp_filter_add_header(f, "Return-Path", S_OR(f->from, "<>")); /* Envelope From - doesn't have <> so this works out just fine. */
	return 0;
}

static int deliveredto_filter_cb(struct smtp_filter_data *f)
{
	/* RFC 9228 Delivered-To header */
	if (strlen_zero(f->recipient)) {
		bbs_warning("No recipient?\n");
		return 0;
	}
	smtp_filter_add_header(f, "Delivered-To", f->recipient);
	return 0;
}

struct smtp_filter_provider received_filter = {
	.on_body = received_filter_cb,
};

struct smtp_filter_provider relay_filter = {
	.on_body = relay_filter_cb,
};

struct smtp_filter_provider auth_filter = {
	.on_body = auth_filter_cb,
};

struct smtp_filter_provider returnpath_filter = {
	.on_body = returnpath_filter_cb,
};

struct smtp_filter_provider deliveredto_filter = {
	.on_body = deliveredto_filter_cb,
};

static int load_module(void)
{
	/* We use SMTP_SCOPE_COMBINED for the Received filter since it needs to be prepended before other filters run.
	 * In particular, this is needed for SpamAssassin as it expects the topmost Received header to be ours,
	 * and we don't want it to interpret any Received header already present. */
	smtp_filter_register(&received_filter, "Received", SMTP_FILTER_OTHER, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN | SMTP_DIRECTION_SUBMIT, 0);
	smtp_filter_register(&relay_filter, "Relay", SMTP_FILTER_OTHER, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_OUT, 1); /* For messages that are being relayed or outgoing */
	/* Run this only after the SPF, DKIM, and DMARC filters have run: */
	smtp_filter_register(&auth_filter, "Auth", SMTP_FILTER_OTHER, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 6);

	/* This header is typically near the top (i.e. prepended last): */
	smtp_filter_register(&returnpath_filter, "Return Path", SMTP_FILTER_OTHER, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN | SMTP_DIRECTION_SUBMIT, 90);

	smtp_filter_register(&deliveredto_filter, "Delivered To", SMTP_FILTER_OTHER, SMTP_FILTER_PREPEND, SMTP_SCOPE_INDIVIDUAL, SMTP_DIRECTION_IN | SMTP_DIRECTION_SUBMIT, 99);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&received_filter);
	smtp_filter_unregister(&relay_filter);
	smtp_filter_unregister(&auth_filter);
	smtp_filter_unregister(&returnpath_filter);
	smtp_filter_unregister(&deliveredto_filter);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC5321 SMTP Filtering", "net_smtp.so");
