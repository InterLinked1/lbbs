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
 * \brief RFC8617 ARC (Authenticated Received Chain)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>

#include <openarc/arc.h>

#include "include/module.h"
#include "include/node.h"
#include "include/utils.h"

#include "include/net_smtp.h"
#include "include/mod_smtp_filter_dkim.h"

static ARC_LIB *lib;

static int process_message(struct smtp_filter_data *f, ARC_MESSAGE *msg)
{
	ARC_STAT stat;
	size_t headerslen, bodylen;
	char *headers, *header, *dup = NULL;
	char full_header[4096];
	char *hdrbuf;
	size_t hdrlen;
	const char *body, *dkimsig;

	body = smtp_message_body(f);
	if (!body) {
		return -1;
	}

	/* This could be a large email. Don't search the body, we only want to search the headers. */
	dkimsig = strstr(body, "\r\n\r\n");
	if (dkimsig) {
		headerslen = (size_t) (dkimsig - body);
		headers = strndup(body, headerslen);
	} else {
		bbs_warning("Failed to find end of headers in message\n");
		headers = strdup(body);
		headerslen = strlen(body);
	}
	if (ALLOC_FAILURE(headers)) {
		return -1;
	}

	dup = headers;
	SAFE_FAST_BUF_INIT(full_header, sizeof(full_header), hdrbuf, hdrlen);

	/* This is annoying. Unlike libopendmarc, we don't have the option of alternately just passing in the entire message to libopenarc.
	 * So we have to do the work of manually iterating over the headers.
	 * These kinds of functions are really better suited for more of a milter approach,
	 * where we process the message as it's received in realtime.
	 */
	while ((header = strsep(&headers, "\r\n"))) {
		if (strlen_zero(header)) {
			continue;
		}
		if (!isspace(*header) && full_header[0]) {
			/* Finalize previous header */
			stat = arc_header_field(msg, (unsigned char*) full_header, strlen(full_header));
			if (stat != ARC_STAT_OK) {
				bbs_warning("ARC header add failed: %s\n", full_header);
			}
			SAFE_FAST_BUF_INIT(full_header, sizeof(full_header), hdrbuf, hdrlen);
		}
		if (full_header[0]) { /* Continuing multiline header */
			SAFE_FAST_APPEND_NOSPACE(full_header, sizeof(full_header), hdrbuf, hdrlen, "\r\n");
		}
		SAFE_FAST_APPEND_NOSPACE(full_header, sizeof(full_header), hdrbuf, hdrlen, "%s", header);
	}

	/* Last header */
	if (full_header[0]) {
		/* Finalize previous header */
		stat = arc_header_field(msg, (unsigned char*) full_header, strlen(full_header));
		if (stat != ARC_STAT_OK) {
			bbs_warning("ARC header add failed: %s\n", full_header);
		}
	}

	free_if(dup);
	stat = arc_eoh(msg);
	if (stat != ARC_STAT_OK) {
		bbs_warning("ARC header add failed: %s\n", arc_geterror(msg));
	}

	body = smtp_message_body(f) + headerslen;
	bodylen = f->size - headerslen;
	if (STARTS_WITH(body, "\r\n\r\n")) {
		body += 2;
		bodylen -= 2;
	}
#ifdef EXTRA_CHECKS
	bbs_assert(strlen(body) == bodylen);
#endif

#pragma GCC diagnostic ignored "-Wcast-qual"
	stat = arc_body(msg, (unsigned char*) body, f->size - headerslen - 2);
	if (stat != ARC_STAT_OK) {
		bbs_warning("ARC body add failed: %s\n", arc_geterror(msg));
		return -1;
	}
	stat = arc_eom(msg);
	if (stat != ARC_STAT_OK) {
		bbs_warning("ARC message finalization failed: %s\n", arc_geterror(msg));
		return -1;
	}

	return 0;
}

static int arc_filter_verify_cb(struct smtp_filter_data *f)
{
	ARC_MESSAGE *msg;
	const unsigned char *error;

	if (!smtp_message_body(f)) {
		return 0;
	}

	/* As there is no usage documentation, simpta has been used as a reference
	 * for libarc library function usage: https://github.com/simta/simta/blob/4c34239ea990ccbbbf6e86a1463ba9cf4977a214/receive.c */

	msg = arc_message(lib, ARC_CANON_RELAXED, ARC_CANON_RELAXED, ARC_SIGN_RSASHA256, ARC_MODE_VERIFY, &error);
	if (!msg) {
		bbs_error("ARC message verify failed: %s\n", error);
		return 0;
	}

	if (process_message(f, msg)) {
		goto cleanup;
	}

	/* All right, we've now verified the message. */
	bbs_debug(3, "ARC chain: %s\n", arc_chain_status_str(msg));
	REPLACE(f->arc, arc_chain_status_str(msg));

cleanup:
	arc_free(msg);
	return 0;
}

static int arc_filter_sign_cb(struct smtp_filter_data *f)
{
	ARC_MESSAGE *msg;
	ARC_STAT stat;
	ARC_HDRFIELD *arc_seal = NULL;
	struct dkim_domain *d;
	const char *domain;
	const unsigned char *error;

	if (!smtp_message_body(f)) {
		return 0;
	}

	if (smtp_is_exempt_relay(f->smtp)) {
		bbs_debug(2, "Skipping ARC signing (%s explicitly authorized to relay mail from %s)\n", smtp_node(f->smtp)->ip, smtp_from_domain(f->smtp));
		return 0;
	}

	/* We sign the message using the same domain that will be used in the outgoing MAIL FROM. */
	domain = bbs_strcnext(f->from, '@');
	if (!domain) {
		bbs_warning("No FROM domain?\n");
		return 0;
	}

	/* Use the same settings as mod_smtp_filter_dkim does.
	 * However, we don't want to read in its config file here (that would be unnecessarily duplicative).
	 * This module is separate due to how fragile, new, and ill-supported libopenarc is compared to libopendkim.
	 * However, in many ways, it "extends" the DKIM module and indeed, is dependent on it to reuse its domains.
	 */
	d = smtp_get_dkim_domain(domain);
	if (!d) {
		bbs_debug(5, "DKIM/ARC does not apply to domain %s\n", domain);
		return 0;
	}

	msg = arc_message(lib, d->strictheaders ? ARC_CANON_SIMPLE : ARC_CANON_RELAXED, d->strictbody ? ARC_CANON_SIMPLE : ARC_CANON_RELAXED,
		d->sha256 ? ARC_SIGN_RSASHA256 : ARC_SIGN_RSASHA1, ARC_MODE_SIGN, &error);
	if (!msg) {
		bbs_error("ARC message verify failed: %s\n", error);
		return 0;
	}

	if (process_message(f, msg)) {
		goto cleanup;
	}

	stat = arc_getseal(msg, &arc_seal, (char*) domain,
		(char*) d->selector, (char*) d->domain, (unsigned char*) d->key, d->keylen, (unsigned char*) f->authresults);

	if (stat != ARC_STAT_OK) {
		bbs_warning("ARC signing failed: %s\n", arc_geterror(msg));
		goto cleanup;
	}

#pragma GCC diagnostic pop

	/* Typically you see headers appear in this order (from the beginning of the email):
	 * ARC-Seal
	 * ARC-Message-Signature
	 * ARC-Authentication-Results
	 * However, here they appear in reverse order (amongst these headers). Not actually sure that matters, just pointing it out. */
	for (; arc_seal; arc_seal = arc_hdr_next(arc_seal)) {
		const char *hdr = (const char*) arc_hdr_name(arc_seal, NULL);
		const char *val = (const char*) arc_hdr_value(arc_seal);
		smtp_filter_add_header(f, hdr, val);
	}

cleanup:
	arc_free(msg);
	return 0;
}

struct smtp_filter_provider arc_verify_filter = {
	.on_body = arc_filter_verify_cb,
};

struct smtp_filter_provider arc_sign_filter = {
	.on_body = arc_filter_sign_cb,
};

static int unload_module(void)
{
	smtp_filter_unregister(&arc_verify_filter);
	smtp_filter_unregister(&arc_sign_filter);
	arc_close(lib);
	return 0;
}

static int load_module(void)
{
	int res = 0;
	lib = arc_init();
	if (!lib) {
		bbs_error("Failed to initialize libopenarc\n");
		return -1;
	}

	/* RFC 8617 Section 5: ARC is applicable to received messagses that did not originate locally, e.g. SMTP_DIRECTION_IN
	 * RFC 8617 5.1: Sealing must be done AFTER DKIM-Signature field added, i.e ARC priority number is higher (later) than DKIM-Signature. */

	/* Wait until SPF, DKIM, and Authentication-Results have been handled before doing ARC: */
	res |= smtp_filter_register(&arc_verify_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 3);
	/* We need to verify prior to generating Authentication-Results, but sign afterwards, since that gets included */
	res |= smtp_filter_register(&arc_sign_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_OUT, 6);
	if (res) {
		unload_module();
		return -1;
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC8617 ARC Signing/Verification", "net_smtp.so,mod_smtp_filter_dkim.so");
