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
 * \brief RFC6376 DomainKeys Identified Mail (DKIM) Signing
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <opendkim/dkim.h>

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/linkedlists.h"

#include "include/net_smtp.h"

struct dkim_domain {
	const char *domain;
	const char *selector;
	const char *key;
	RWLIST_ENTRY(dkim_domain) entry;
	unsigned int strictheaders:1;
	unsigned int strictbody:1;
	unsigned int sha256:1;
	char data[];
};

static RWLIST_HEAD_STATIC(domains, dkim_domain);

DKIM_LIB *lib;

static int dkim_filter_cb(struct smtp_filter_data *f)
{
	DKIM *dkim;
	DKIM_STAT statp;
	char uniqueid[20];
	const char *body;
	struct dkim_domain *d;
	unsigned char *sig;
	size_t siglen;
	const char *from = f->from;
	const char *domain = strchr(from, '@');

	if (!domain) {
		bbs_warning("Sender has no domain?\n");
		return 0;
	}
	domain++;
	if (strlen_zero(domain)) {
		bbs_warning("Sender has no domain?\n");
		return 0;
	}

	snprintf(uniqueid, sizeof(uniqueid), "%lu", time(NULL));

	RWLIST_RDLOCK(&domains);
	RWLIST_TRAVERSE(&domains, d, entry) {
		if (!strcmp(d->domain, domain)) {
			break;
		}
	}
	if (!d) {
		/* DKIM not applicable for this domain */
		RWLIST_UNLOCK(&domains);
		bbs_debug(3, "DKIM not applicable for domain %s\n", domain);
		return 0;
	}

	body = smtp_message_body(f);
	if (!body) {
		RWLIST_UNLOCK(&domains);
		bbs_warning("Message is empty?\n");
		return 0;
	}

#pragma GCC diagnostic ignored "-Wcast-qual"
	/* Sign the message */
	dkim = dkim_sign(lib, (unsigned char*) uniqueid, NULL, (unsigned char*) d->key, (unsigned char*) d->selector, (unsigned char*) d->domain,
		d->strictheaders ? DKIM_CANON_SIMPLE : DKIM_CANON_RELAXED,
		d->strictbody ? DKIM_CANON_SIMPLE : DKIM_CANON_RELAXED,
		d->sha256 ? DKIM_SIGN_RSASHA256 : DKIM_SIGN_RSASHA1,
		-1, /* Sign entire body */
		&statp);

	if (statp != DKIM_STAT_OK) {
		bbs_error("Failed to set up DKIM signing: %d (%s)\n", statp, dkim_geterror(dkim));
		if (!dkim) {
			RWLIST_UNLOCK(&domains);
			return 0;
		}
		goto cleanup;
	}

	/* Since the headers and body aren't parse, just chunk it all at once */
	statp = dkim_chunk(dkim, (unsigned char*) body, f->size);
#pragma GCC diagnostic pop
	if (statp != DKIM_STAT_OK) {
		bbs_error("DKIM chunk failed: %d (%s)\n", statp, dkim_geterror(dkim));
		goto cleanup;
	}

	/* Indicate EOM */
	statp = dkim_chunk(dkim, NULL, 0);
	if (statp != DKIM_STAT_OK) {
		bbs_error("DKIM chunk failed: %d (%s)\n", statp, dkim_geterror(dkim));
		goto cleanup;
	}

	statp = dkim_eom(dkim, 0);
	if (statp != DKIM_STAT_OK) {
		bbs_error("DKIM signing failed: %d (%s)\n", statp, dkim_geterror(dkim));
		goto cleanup;
	}

	statp = dkim_getsighdr_d(dkim, d->strictheaders ? STRLEN(DKIM_SIGNHEADER) + 2 : 0, &sig, &siglen);
	if (statp != DKIM_STAT_OK) {
		bbs_error("DKIM signature failed: %d (%s)\n", statp, dkim_geterror(dkim));
		goto cleanup;
	}

	smtp_filter_add_header(f, "DKIM-Signature", (const char*) sig);

cleanup:
	dkim_free(dkim);
	RWLIST_UNLOCK(&domains);
	return 0;
}

struct smtp_filter_provider dkim_filter = {
	.on_body = dkim_filter_cb,
};

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_smtp_filter_dkim.conf", 1);

	if (!cfg) {
		bbs_error("File 'mod_smtp_filter_dkim.conf' is missing, declining to load\n");
		return -1;
	}

	RWLIST_WRLOCK(&domains);
	while ((section = bbs_config_walk(cfg, section))) {
		struct dkim_domain *d;
		const char *domain = NULL, *selector = NULL, *secretkey = NULL;
		char *f = NULL;
		struct bbs_keyval *keyval = NULL;
		int strictheaders = 0, strictbody = 0, sha256 = 1;
		size_t namelen, selectorlen, keylen;
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue;
		}
		domain = bbs_config_section_name(section);
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcmp(key, "selector")) {
				selector = value;
			} else if (!strcmp(key, "key")) {
				secretkey = value;
			} else if (!f && !strcmp(key, "keyfile")) {
				int len;
				if (eaccess(value, R_OK)) {
					bbs_warning("Can't read private key file %s: %s\n", value, strerror(errno));
					goto next;
				}
				f = bbs_file_to_string(value, 0, &len);
				if (!f) {
					goto next; /* In double loop */
				}
				secretkey = f;
			} else if (!strcmp(key, "strictheaders")) {
				strictheaders = S_TRUE(value);
			} else if (!strcmp(key, "strictbody")) {
				strictbody = S_TRUE(value);
			} else if (!strcmp(key, "alg")) {
				if (!strcmp(value, "sha256")) {
					sha256 = 1;
				} else if (!strcmp(value, "sha1")) {
					sha256 = 0;
				} else {
					bbs_error("Invalid signing algorithm '%s'\n", value);
				}
			} else {
				bbs_error("Unknown property '%s'\n", key);
			}
		}

		if (!selector || !secretkey) {
			bbs_warning("Missing required configuration properties\n");
			goto next;
		}

		namelen = strlen(domain);
		selectorlen = strlen(selector);
		keylen = strlen(secretkey);
		d = calloc(1, sizeof(*d) + namelen + selectorlen + keylen + 3);
		if (ALLOC_FAILURE(d)) {
			goto next;
		}
		strcpy(d->data, domain); /* Safe */
		d->domain = d->data;
		strcpy(d->data + namelen + 1, selector);
		d->selector = d->data + namelen + 1;
		strcpy(d->data + namelen + selectorlen + 2, secretkey);
		d->key = d->data + namelen + selectorlen + 2;
		SET_BITFIELD(d->strictheaders, strictheaders);
		SET_BITFIELD(d->strictbody, strictbody);
		SET_BITFIELD(d->sha256, sha256);
		RWLIST_INSERT_TAIL(&domains, d, entry);
		bbs_verb(5, "Registered DKIM for domain %s\n", d->domain);
next:
		free_if(f);
	}

	/* If no domains were registered, there's no point in the module remaining loaded. */
	if (RWLIST_EMPTY(&domains)) {
		RWLIST_UNLOCK(&domains);
		bbs_warning("Couldn't load any domains for DKIM signing, declining to load\n");
		return -1;
	}

	RWLIST_UNLOCK(&domains);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&dkim_filter);
	dkim_close(lib);
	RWLIST_WRLOCK_REMOVE_ALL(&domains, entry, free);
	return 0;
}

static int load_module(void)
{
	int res;
	if (load_config()) {
		return -1;
	}
	lib = dkim_init(NULL, NULL);
	if (!lib) {
		bbs_error("Failed to initialize DKIM library\n");
	}
	/* You might think this should be for OUT, only, but SUBMIT is more appropriate since we only DKIM sign our submissions,
	 * and they MAY contain external recipients; even if they don't, that's fine.
	 * Importantly, we want to use the COMBINED scope so we only sign each message once, not once per recipient. */
	res = smtp_filter_register(&dkim_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_SUBMIT, 1);
	if (res) {
		unload_module();
		return -1;
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC6376 DKIM Signing", "net_smtp.so");
