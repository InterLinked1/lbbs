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
 * \brief RFC6376 DomainKeys Identified Mail (DKIM) Signing and Verification
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
#include "include/mod_smtp_filter_dkim.h"

static RWLIST_HEAD_STATIC(domains, dkim_domain);

static DKIM_LIB *lib;

struct dkim_domain *smtp_get_dkim_domain(const char *name)
{
	struct dkim_domain *d;
	/* It's okay to traverse without locking,
	 * since the module can't unload while it's in use. */
	RWLIST_TRAVERSE(&domains, d, entry) {
		if (!strcmp(d->domain, name)) {
			return d;
		}
	}
	return NULL;
}

static int dkim_sign_filter_cb(struct smtp_filter_data *f)
{
	DKIM *dkim;
	DKIM_STAT statp;
	char uniqueid[20];
	const char *body;
	struct dkim_domain *d;
	unsigned char *sig;
	size_t siglen;
	const char *domain;

	domain = smtp_from_domain(f->smtp);
	if (!domain) {
		bbs_warning("Sender has no domain?\n");
		return 0;
	}

	snprintf(uniqueid, sizeof(uniqueid), "%lu", time(NULL));

	d = smtp_get_dkim_domain(domain);
	if (!d) {
		/* DKIM not applicable for this domain */
		bbs_debug(3, "DKIM not applicable for domain %s\n", domain);
		return 0;
	}

	body = smtp_message_body(f);
	if (!body) {
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
	return 0;
}

static int dkim_verify_filter_cb(struct smtp_filter_data *f)
{
	DKIM *dkim;
	DKIM_STAT statp;
	DKIM_SIGINFO *sig;
	int dkim_dnssec; /* DKIM_DNSSEC type doesn't exist? (at least on my system) */
	unsigned int sigflags;
	int bh;
	unsigned int keybits = 0;
	int sigerror;
	char uniqueid[20];
	unsigned char val[500] = "";
	char comment[500] = "";
	char substring[500];
	char dkimresult[sizeof(val) + sizeof(comment) + sizeof(substring) + 65];
	size_t substringlen = sizeof(substring) - 1;
	const char *result = NULL;
	const char *dnssec = NULL;
	const char *body;

	if (!smtp_should_validate_dkim(f->smtp)) {
		return 0;
	}

	snprintf(uniqueid, sizeof(uniqueid), "%lu", time(NULL));

	body = smtp_message_body(f);
	if (!body) {
		bbs_warning("Message is empty?\n");
		return 0;
	}

#pragma GCC diagnostic ignored "-Wcast-qual"
	/* Sign the message */
	dkim = dkim_verify(lib, (unsigned char*) uniqueid, NULL, &statp);

	if (statp != DKIM_STAT_OK) {
		bbs_error("Failed to set up DKIM signing: %d (%s)\n", statp, dkim_geterror(dkim));
		if (!dkim) {
			return 0;
		}
		goto cleanup;
	}

	/* Since the headers and body aren't parsed, just chunk it all at once */
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

	sig = dkim_getsignature(dkim);
	if (!sig) {
		bbs_debug(2, "No DKIM signature found\n");
		goto cleanup;
	}

	statp = dkim_sig_process(dkim, sig);
	if (statp != DKIM_STAT_OK) {
		bbs_error("DKIM signature verification failed: %d (%s)\n", statp, dkim_geterror(dkim));
		goto cleanup;
	}

	/* XXX We only use one signature, any reason to check all of them using dkim_getsiglist() as in RFC 6008? */
	sigflags = dkim_sig_getflags(sig);
	bh = dkim_sig_getbh(sig); /* Body hash */
	sigerror = dkim_sig_geterror(sig);

	if (sigflags & DKIM_SIGFLAG_IGNORE) {
		bbs_warning("DKIM_SIGFLAG_IGNORE\n"); /* Shouldn't happen */
	}
	if (sigflags & DKIM_SIGFLAG_PROCESSED) {
		bbs_debug(5, "DKIM_SIGFLAG_PROCESSED\n");
	}
	if (sigflags & DKIM_SIGFLAG_PASSED) {
		bbs_debug(5, "DKIM_SIGFLAG_PASSED\n");
	}
	if (sigflags & DKIM_SIGFLAG_TESTKEY) {
		bbs_debug(5, "DKIM_SIGFLAG_TESTKEY\n");
	}
	if (sigflags & DKIM_SIGFLAG_NOSUBDOMAIN) {
		bbs_debug(5, "DKIM_SIGFLAG_NOSUBDOMAIN\n");
	}

	if (bh == DKIM_SIGBH_MATCH) {
		bbs_debug(5, "DKIM_SIGBH_MATCH\n");
	} else if (bh == DKIM_SIGBH_MISMATCH) {
		bbs_debug(5, "DKIM_SIGBH_MISMATCH\n");
	} else {
		bbs_warning("DKIM_SIGBH_UNTESTED\n"); /* Shouldn't happen */
	}

	/* Some logic from php-opendkim */
	if ((sigflags & DKIM_SIGFLAG_PASSED) && (bh == DKIM_SIGBH_MATCH)) {
		result = "pass";
	} else if (sigerror == DKIM_SIGERROR_MULTIREPLY || sigerror == DKIM_SIGERROR_KEYFAIL || sigerror == DKIM_SIGERROR_DNSSYNTAX) {
		result = "temperror";
	} else if (sigerror == DKIM_SIGERROR_KEYTOOSMALL) {
		const char *err = dkim_sig_geterrorstr(dkim_sig_geterror(sig));
		result = "policy";
		if (err) {
			snprintf(comment, sizeof(comment), " reason=\"%s\"", err);
		}
	} else if (sigflags & DKIM_SIGFLAG_PROCESSED) {
		const char *err = dkim_sig_geterrorstr(dkim_sig_geterror(sig));
		result = "fail";
		if (err) {
			snprintf(comment, sizeof(comment), " reason=\"%s\"", err);
		}
	} else if (sigerror != DKIM_SIGERROR_UNKNOWN && sigerror != DKIM_SIGERROR_OK) {
		result = "permerror";
	} else {
		result = "neutral";
	}

	dkim_sig_getidentity(dkim, sig, val, sizeof(val) - 1);
	dkim_sig_getkeysize(sig, &keybits);
	statp = dkim_get_sigsubstring(dkim, sig, substring, &substringlen);

	/* DNSSEC results */
	dkim_dnssec = dkim_sig_getdnssec(sig);
	switch (dkim_dnssec) {
		case DKIM_DNSSEC_INSECURE:
			dnssec = "unprotected"; /* This verbiage seems to be what postfix uses */
			break;
		case DKIM_DNSSEC_SECURE:
			dnssec = "protected"; /* Extrapolating from the above... */
			break;
		case DKIM_DNSSEC_BOGUS:
			bbs_debug(5, "Bogus DNSSEC?\n");
			break;
		case DKIM_DNSSEC_UNKNOWN:
			/* XXX Always seem to get this, so the DNSSEC code here may not really be working? */
			bbs_debug(5, "Unknown DNSSEC?\n");
			break;
		default:
			bbs_debug(5, "DNSSEC fallthrough\n");
			break;
	}

	snprintf(dkimresult, sizeof(dkimresult), "%s%s (%u-bit key%s%s) header.d=%s header.i=%s%s%s%s",
		result, comment,
		keybits,
		dnssec ? "; " : "",
		S_IF(dnssec),
		dkim_sig_getdomain(sig), val,
		statp == DKIM_STAT_OK ? " header.b=\"" : "",
		statp == DKIM_STAT_OK ? substring : "",
		statp == DKIM_STAT_OK ? "\"" : ""
    );

	bbs_debug(5, "DKIM result: %s\n", dkimresult);
	REPLACE(f->dkim, dkimresult);

cleanup:
	dkim_free(dkim);
	return 0;
}

struct smtp_filter_provider dkim_sign_filter = {
	.on_body = dkim_sign_filter_cb,
};

struct smtp_filter_provider dkim_verify_filter = {
	.on_body = dkim_verify_filter_cb,
};

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_smtp_filter_dkim.conf", 1);

	if (!cfg) {
		return 0;
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
		d->keylen = keylen;
		SET_BITFIELD(d->strictheaders, strictheaders);
		SET_BITFIELD(d->strictbody, strictbody);
		SET_BITFIELD(d->sha256, sha256);
		RWLIST_INSERT_TAIL(&domains, d, entry);
		bbs_verb(5, "Registered DKIM for domain %s\n", d->domain);
next:
		free_if(f);
	}

	RWLIST_UNLOCK(&domains);
	return 0;
}

static int unload_module(void)
{
	if (!RWLIST_EMPTY(&domains)) {
		smtp_filter_unregister(&dkim_sign_filter);
	}
	smtp_filter_unregister(&dkim_verify_filter);
	dkim_close(lib);
	RWLIST_WRLOCK_REMOVE_ALL(&domains, entry, free);
	return 0;
}

static int load_module(void)
{
	int res = 0;
	if (load_config()) {
		return -1;
	}
	lib = dkim_init(NULL, NULL);
	if (!lib) {
		bbs_error("Failed to initialize DKIM library\n");
	}
	/* If no domains were registered, there's no point in the module remaining loaded. */
	if (!RWLIST_EMPTY(&domains)) {
		/* You might think this should be for OUT, only, but SUBMIT is more appropriate since we only DKIM sign our submissions,
		 * and they MAY contain external recipients; even if they don't, that's fine.
		 * Importantly, we want to use the COMBINED scope so we only sign each message once, not once per recipient. */
		res |= smtp_filter_register(&dkim_sign_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_SUBMIT, 1);
	}
	/* Priority of 2, so that SPF validation will already have been done */
	res |= smtp_filter_register(&dkim_verify_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 2);
	if (res) {
		unload_module();
		return -1;
	}
	return 0;
}

BBS_MODULE_INFO_FLAGS_DEPENDENT("RFC6376 DKIM Signing/Verification", MODFLAG_GLOBAL_SYMBOLS, "net_smtp.so");
