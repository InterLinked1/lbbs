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
 * \brief OAuth2 Authentication interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/linkedlists.h"
#include "include/oauth.h"

/* Allow multiple OAuth2 providers to be registered */
struct oauth_provider {
	int (*get_token)(OAUTH_PROVIDER_PARAMS);
	struct bbs_module *module;
	RWLIST_ENTRY(oauth_provider) entry;
};

static RWLIST_HEAD_STATIC(providers, oauth_provider);

int __bbs_register_oauth_provider(int (*provider)(OAUTH_PROVIDER_PARAMS), void *mod)
{
	struct oauth_provider *p;

	RWLIST_WRLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		if (p->get_token == provider) {
			break;
		}
	}
	if (p) {
		bbs_error("OAuth provider is already registered\n");
		RWLIST_UNLOCK(&providers);
		return -1;
	}
	p = calloc(1, sizeof(*p));
	if (ALLOC_FAILURE(p)) {
		RWLIST_UNLOCK(&providers);
		return -1;
	}
	p->get_token = provider;
	p->module = mod;
	RWLIST_INSERT_TAIL(&providers, p, entry);
	RWLIST_UNLOCK(&providers);
	return 0;
}

int bbs_unregister_oauth_provider(int (*provider)(OAUTH_PROVIDER_PARAMS))
{
	struct oauth_provider *p;

	p = RWLIST_WRLOCK_REMOVE_BY_FIELD(&providers, get_token, provider, entry);
	if (!p) {
		bbs_error("Failed to unregister OAuth provider: not currently registered\n");
		return -1;
	} else {
		free(p);
	}
	return 0;
}

int bbs_get_oauth_token(struct bbs_user *user, const char *name, char *buf, size_t len)
{
	int c = 0, res = -1;
	struct oauth_provider *p;

	RWLIST_RDLOCK(&providers);
	RWLIST_TRAVERSE(&providers, p, entry) {
		bbs_module_ref(p->module, 1);
		res = p->get_token(user, name, buf, len);
		bbs_module_unref(p->module, 1);
		c++;
		if (!res) {
			break; /* Somebody granted the login. Stop. */
		}
	}
	RWLIST_UNLOCK(&providers);

	/* If there weren't any providers, well, we have a problem. */
	if (c == 0) {
		bbs_warning("No OAuth providers are currently registered!\n");
	}
	return res;
}
