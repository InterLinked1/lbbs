/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Remote Message Queuing client (RFC 1985 client)
 *
 * \note The goal of this module is to, at startup, and/or periodically,
 * "fetch" mail from upstream SMTP servers by connecting to servers
 * that forward us mail and requesting they flush their queues for us.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/stringlist.h"
#include "include/cli.h"

#include "include/mod_smtp_client.h"
#include "include/net_smtp.h" /* use smtp_hostname */

static pthread_t global_thread = 0;

struct upstream_host {
	const char *hostname;		/*!< IP address or hostname */
	struct stringlist domains;	/*!< Domains (including wildcards) for which this host may have queued mail for us */
	RWLIST_ENTRY(upstream_host) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(upstream_hosts, upstream_host);

static void add_upstream(const char *hostname, const char *domains)
{
	struct upstream_host *h;

	h = calloc(1, sizeof(*h) + strlen(hostname) + 1);
	if (ALLOC_FAILURE(h)) {
		return;
	}

	strcpy(h->data, hostname); /* Safe */
	h->hostname = h->data;
	stringlist_init(&h->domains);
	stringlist_push_list(&h->domains, domains);

	/* Head insert, so later entries override earlier ones, in case multiple match */
	RWLIST_INSERT_HEAD(&upstream_hosts, h, entry);
}

static void upstream_host_free(struct upstream_host *h)
{
	stringlist_empty_destroy(&h->domains);
	free(h);
}

static int fetch_single_host_domain(struct bbs_smtp_client smtpclient, const char *domain)
{
	int res;

	/*! \todo Currently only ETRN is supported, but in the future RFC 2645 On-Demand Mail Relay could be as well */

	bbs_smtp_client_send(&smtpclient, "ETRN %s\r\n", domain); /* AUTH PLAIN is preferred to the deprecated AUTH LOGIN */
	SMTP_EXPECT(&smtpclient, SEC_MS(10), "2"); /* Expect a 2XX response */

	return 1;

cleanup:
	return 0;
}

/*! \brief Fetch queued mail from a single SMTP server */
static int fetch_single_host(const char *hostname, struct stringlist *domains)
{
	struct bbs_smtp_client smtpclient;
	struct stringitem *i = NULL;
	const char *domain;
	char buf[1024];
	char hostnamebuf[256];
	const char *colon;
	int port = 25;
	int res;
	int incr_res = 0;

	/* Parse port if there is one */
	colon = strchr(hostname, ':');
	if (colon) {
		colon++;
		if (!strlen_zero(colon)) {
			bbs_strncpy_until(hostnamebuf, hostname, sizeof(hostnamebuf), ':');
			hostname = hostnamebuf;
			port = atoi(colon);
		} else {
			bbs_warning("Missing port after colon in hostname '%s'\n", hostname);
		}
	}

	/* Connect to this server and see if it supports ETRN */
	if (bbs_smtp_client_connect(&smtpclient, smtp_hostname(), hostname, port, 0, buf, sizeof(buf))) {
		return 0;
	}
	SMTP_CLIENT_EXPECT_FINAL(&smtpclient, MIN_MS(5), "220"); /* RFC 5321 4.5.3.2.1 (though for final 220, not any of them) */

	if (!(smtpclient.caps & SMTP_CAPABILITY_ETRN)) {
		bbs_warning("SMTP server %s does not support ETRN, unable to fetch mail\n", hostname);
		goto cleanup;
	}

	res = bbs_smtp_client_handshake(&smtpclient, 0);
	if (res) {
		goto cleanup;
	}
	if (smtpclient.caps & SMTP_CAPABILITY_STARTTLS) {
		if (bbs_smtp_client_starttls(&smtpclient)) {
			goto cleanup; /* Abort if we were told STARTTLS was available but failed to negotiate. */
		}
	}

	while ((domain = stringlist_next(domains, &i))) {
		incr_res += fetch_single_host_domain(smtpclient, domain);
	}

cleanup:
	if (res > 0) {
		bbs_smtp_client_send(&smtpclient, "QUIT\r\n");
	}
	bbs_smtp_client_destroy(&smtpclient);
	return incr_res;
}

/*! \brief Synchronously fetch all queued mail, on-demand */
static void *do_fetch(void *varg)
{
	int res = 0;
	int *resptr = varg;
	struct upstream_host *h;

	/* Since we're just coming online now, if we're configured to
	 * accept mail from an upstream SMTP server, reach out to that server now
	 * and use ETRN to request any mail queued for us be sent immediately. */

	RWLIST_RDLOCK(&upstream_hosts);
	RWLIST_TRAVERSE(&upstream_hosts, h, entry) {
		res += fetch_single_host(h->hostname, &h->domains);
	}
	RWLIST_UNLOCK(&upstream_hosts);

	if (resptr) {
		*resptr = res;
	}
	return NULL;
}

static void *background_task(void *varg)
{
	/* Do a fetch at module load time, since we could be just coming online now from a long hiatus. */
	do_fetch(varg);

	/* It seems natural to think that it would make sense to periodically fetch,
	 * just in case we've gone offline in the meantime while we're still running.
	 * But this seems a bit silly, since that's not really what ETRN is intended for,
	 * since as long as we're online, we should receive mail in realtime.
	 * The CLI command can be used to manually fetch mail on demand if needed.
	 * So just return immediately. */

	return NULL;
}

static int cli_fetchmail(struct bbs_cli_args *a)
{
	pthread_t fetch_thread;
	int res;

	bbs_pthread_create(&fetch_thread, NULL, do_fetch, &res);
	bbs_pthread_join(fetch_thread, NULL);
	bbs_dprintf(a->fdout, "Successfully flushed %d upstream queue%s\n", res, ESS(res));
	return 0;
}

static struct bbs_cli_entry cli_commands_fetchmail[] = {
	BBS_CLI_COMMAND(cli_fetchmail, "smtp fetchmail", 2, "Request upstream SMTP servers flush any queued messages for us", NULL),
};

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("mod_smtp_fetchmail.conf", 1);
	if (!cfg) {
		return -1;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		struct bbs_keyval *keyval = NULL;
		const char *key, *val;

		if (!strcmp(bbs_config_section_name(section), "upstreams")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				key = bbs_keyval_key(keyval);
				val = bbs_keyval_val(keyval);
				add_upstream(key, val);
			}
		} else {
			bbs_warning("Invalid section name '%s'\n", bbs_config_section_name(section));
		}
	}

	if (RWLIST_EMPTY(&upstream_hosts)) {
		bbs_debug(1, "No upstream hosts are configured, declining to load\n");
		return 1; /* No point in remaining loaded if no upstreams are configured */
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	bbs_cli_register_multiple(cli_commands_fetchmail);
	return bbs_pthread_create(&global_thread, NULL, background_task, NULL);
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_fetchmail);
	bbs_pthread_join(global_thread, NULL);
	RWLIST_WRLOCK_REMOVE_ALL(&upstream_hosts, entry, upstream_host_free);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("SMTP Remote Message Fetching", "mod_smtp_client.so,net_smtp.so");
