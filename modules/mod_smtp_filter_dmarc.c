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
 * \brief RFC7489 DMARC (Domain-based Message Authentication, Reporting, and Conformance)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <opendmarc/dmarc.h>

#include "include/module.h"
#include "include/node.h"
#include "include/utils.h"

#include "include/net_smtp.h"

static const char *policy_name(int p)
{
	switch (p) {
		case DMARC_RECORD_P_NONE:
			return "NONE";
		case DMARC_RECORD_P_QUARANTINE:
			return "QUARANTINE";
		case DMARC_RECORD_P_REJECT:
			return "REJECT";
		case DMARC_RECORD_P_UNSPECIFIED:
		default:
			return "";
	}
}

static OPENDMARC_LIB_T lib;

static int dmarc_filter_cb(struct smtp_filter_data *f)
{
	int dres;
	const char *domain;
	OPENDMARC_STATUS_T status;
	int spf_alignment, dkim_alignment;
	int is_ipv6;
	DMARC_POLICY_T *pctx;
	char dmarc_domain[256];
	char dmarc_result[sizeof(dmarc_domain) + 128];
	const char *result = NULL;
	int p = 0, sp = 0;

	if (smtp_is_exempt_relay(f->smtp)) {
		return 0;
	}

	is_ipv6 = !bbs_hostname_is_ipv4(f->node->ip); /* If it's not IPv4, must be IPv6? */
	domain = bbs_strcnext(f->from, '@');
	if (!domain) {
		bbs_warning("Missing domain for received email?\n");
		return 0;
	}

#pragma GCC diagnostic ignored "-Wcast-qual"
	pctx = opendmarc_policy_connect_init((unsigned char*) f->node->ip, is_ipv6);
	if (!pctx) {
		bbs_error("Failed to allocate DMARC policy context\n");
		return 0;
	}

	opendmarc_policy_store_from_domain(pctx, (unsigned char*) domain);

	if (f->spf) {
		int dresult;
		if (!strcmp(f->spf, "pass")) {
			dresult = DMARC_POLICY_SPF_OUTCOME_PASS;
		} else if (!strcmp(f->spf, "fail")) {
			dresult = DMARC_POLICY_SPF_OUTCOME_FAIL;
		} else if (!strcmp(f->spf, "tempfail")) {
			dresult = DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
		} else {
			dresult = DMARC_POLICY_SPF_OUTCOME_NONE;
		}
		/* We always use the MAIL FROM domain, not the HELO/EHLO domain */
		dres = opendmarc_policy_store_spf(pctx, (unsigned char*) domain, dresult, DMARC_POLICY_SPF_ORIGIN_MAILFROM, (unsigned char*) f->spf);
		if (dres != DMARC_PARSE_OKAY) {
			bbs_warning("Failed to parse SPF for DMARC: %d\n", dres);
		}
	}

	if (f->dkim) {
		char d_domain[256] = "";
		int dkim_result;
		const char *d = strstr(f->dkim, "header.d=");
		if (d) {
			d += STRLEN("header.d=");
			if (!strlen_zero(d)) {
				bbs_strncpy_until(d_domain, d, sizeof(d_domain), ' ');
			}
		}
		if (STARTS_WITH(f->dkim, "pass")) {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_PASS;
		} else if (STARTS_WITH(f->dkim, "fail")) {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_FAIL;
		} else if (STARTS_WITH(f->dkim, "tempfail")) {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_TMPFAIL;
		} else {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_NONE;
		}
#if (OPENDMARC_LIB_VERSION >= 0x01040000L) || (OPENDMARC_LIB_VERSION == 0x00000000L)
		/* Added in commit https://github.com/trusteddomainproject/OpenDMARC/commit/dbd87868f2ca9c2ef11529cd757d1cc5ab228833 */
		/* We could get this from the DKIM-Signature header, but otherwise it's not immediately readily available, so just pass NULL for now */
		dres = opendmarc_policy_store_dkim(pctx, (unsigned char*) d_domain, NULL, dkim_result, (unsigned char*) f->dkim);
#else
		dres = opendmarc_policy_store_dkim(pctx, (unsigned char*) d_domain, dkim_result, (unsigned char*) f->dkim);
#endif
		if (dres != DMARC_PARSE_OKAY) {
			bbs_warning("Failed to parse DKIM for DMARC: %d\n", dres);
		}
	}

	status = opendmarc_policy_query_dmarc(pctx, (unsigned char*) domain);
#pragma GCC diagnostic pop
	switch (status) {
		case DMARC_PARSE_OKAY:
			break;
		case DMARC_DNS_ERROR_NO_RECORD:
			bbs_debug(5, "No DMARC record found for domain %s\n", domain);
			break;
		case DMARC_DNS_ERROR_TMPERR:
			bbs_warning("Temporary DNS failure\n");
			break;
		case DMARC_DNS_ERROR_NXDOMAIN:
			bbs_warning("No DNS records for %s\n", domain);
			break;
		/* These should never happen */
		case DMARC_PARSE_ERROR_EMPTY:
		case DMARC_PARSE_ERROR_NO_DOMAIN:
		case DMARC_PARSE_ERROR_NULL_CTX:
			bbs_warning("Unexpected status %d\n", status);
			break;
	}

	status = opendmarc_get_policy_to_enforce(pctx);
	switch (status) {
		case DMARC_POLICY_ABSENT: /* No DMARC record */
			bbs_debug(5, "No DMARC record found for domain %s\n", domain);
			goto cleanup;
		case DMARC_POLICY_NONE: /* Accept */
			result = "none";
			break;
		case DMARC_POLICY_REJECT:
			result = "reject";
			break;
		case DMARC_POLICY_QUARANTINE:
			result = "quarantine";
			break;
		case DMARC_POLICY_PASS:
			result = "pass";
			break;
		/* These should never happen */
		case DMARC_FROM_DOMAIN_ABSENT:
		case DMARC_PARSE_ERROR_NULL_CTX:
			bbs_warning("Unexpected status %d\n", status);
			goto cleanup;
	}

	status = opendmarc_policy_fetch_alignment(pctx, &spf_alignment, &dkim_alignment);
	if (status == DMARC_PARSE_OKAY) {
		bbs_debug(5, "Alignments: SPF=%s, DKIM=%s\n",
			spf_alignment == DMARC_POLICY_SPF_ALIGNMENT_PASS ? "pass" : "fail",
			dkim_alignment == DMARC_POLICY_DKIM_ALIGNMENT_PASS ? "pass" : "fail");
	}

	if (opendmarc_policy_fetch_p(pctx, &p) != DMARC_PARSE_OKAY) {
		bbs_warning("Failed to parse DMARC p\n");
	} else if (opendmarc_policy_fetch_sp(pctx, &sp) != DMARC_PARSE_OKAY) {
		bbs_warning("Failed to parse DMARC sp\n");
	}

	if (opendmarc_policy_fetch_utilized_domain(pctx, (unsigned char*) dmarc_domain, sizeof(dmarc_domain)) != DMARC_PARSE_OKAY) {
		bbs_warning("Failed to get DMARC domain\n");
	}

	snprintf(dmarc_result, sizeof(dmarc_result), "%s (p=%s sp=%s) header.from=%s",
		result, policy_name(p), policy_name(sp), dmarc_domain);
	REPLACE(f->dmarc, dmarc_result);

cleanup:
	opendmarc_policy_connect_shutdown(pctx);
	return 0;
}

struct smtp_filter_provider dmarc_filter = {
	.on_body = dmarc_filter_cb,
};

static int load_module(void)
{
	if (opendmarc_policy_library_init(&lib) != DMARC_PARSE_OKAY) {
		bbs_error("Failed to initialize libopendmarc\n");
		return -1;
	}

	/* Wait until SPF and DKIM/ARC have completed (priorities 1 and 2 respectively) before making any DMARC assessment */
	smtp_filter_register(&dmarc_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 5);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&dmarc_filter);
	opendmarc_policy_library_shutdown(&lib);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC7489 DMARC Validation", "net_smtp.so");
