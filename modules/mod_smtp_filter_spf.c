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
 * \brief RFC7208 Sender Policy Framework (SPF) Validation
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>

/* Don't redeclare things from arpa/nameser.h */
#pragma GCC diagnostic ignored "-Wunused-macros"
#define HAVE_NS_TYPE
#include <spf2/spf.h>
#pragma GCC diagnostic pop

#include "include/module.h"
#include "include/node.h"
#include "include/utils.h" /* use bbs_hostname_is_ipv4 */

#include "include/net_smtp.h"

SPF_server_t *spf_server;

/*! \brief RFC 7208 SPF verification */
static int prepend_spf(struct smtp_filter_data *f)
{
	SPF_request_t *spf_request;
	SPF_response_t *spf_response = NULL;

	/* Only MAIL FROM and HELO identities are within scope of SPF. */

	/* use libspf2's SPF validation... no need to reinvent the wheel here. */
	spf_request = SPF_request_new(spf_server);
	if (!spf_request) {
		bbs_error("Failed to request new SPF\n");
		return -1;
	}
	if (bbs_hostname_is_ipv4(f->node->ip)) {
		SPF_request_set_ipv4_str(spf_request, f->node->ip);
	} else {
		SPF_request_set_ipv6_str(spf_request, f->node->ip);
	}
	/* HELO/EHLO hostname used for verification if MAIL FROM is empty (e.g. postmaster bounce)
	 * This is RECOMMENDED by RFC 7208. */
	SPF_request_set_helo_dom(spf_request, f->helohost);
	SPF_request_set_env_from(spf_request, f->from); /* Envelope from (MAIL FROM) */

#define VALID_SPF(s) (!strcmp(s, "pass") || !strcmp(s, "fail") || !strcmp(s, "softfail") || !strcmp(s, "neutral") || !strcmp(s, "none") || !strcmp(s, "temperror") || !strcmp(s, "permerror"))

	SPF_request_query_mailfrom(spf_request, &spf_response);
	if (spf_response) {
		const char *spfresult = SPF_strresult(SPF_response_result(spf_response));
		if (VALID_SPF(spfresult)) {
			smtp_filter_add_header(f, "Received-SPF", SPF_response_get_received_spf_value(spf_response));
			/* We can use just the short name for Authentication-Results header.
			 * No need to duplicate the entire header value for that. */
			REPLACE(f->spf, spfresult);
		} else {
			bbs_warning("Unexpected SPF result: %s\n", spfresult);
		}
		SPF_response_free(spf_response);
	} else {
		bbs_warning("Failed to get SPF response for %s\n", f->from);
	}
	SPF_request_free(spf_request);
	return 0;
}

static int spf_filter_cb(struct smtp_filter_data *f)
{
	if (smtp_should_validate_spf(f->smtp)) { /* Don't do SPF if the message was just submitted... that would definitely fail. */
		prepend_spf(f);
	}
	return 0;
}

struct smtp_filter_provider spf_filter = {
	.on_body = spf_filter_cb,
};

static int load_module(void)
{
	spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
	if (!spf_server) {
		bbs_error("Failed to create SPF server\n");
		return -1;
	}
	smtp_filter_register(&spf_filter, "SPF", SMTP_FILTER_SPF, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 1);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&spf_filter);
	SPF_server_free(spf_server);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC7208 SPF Validation", "net_smtp.so");
