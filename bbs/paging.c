/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Generic Paging Interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/paging.h"
#include "include/cli.h"

static const char *paging_protocol_name(enum paging_protocol prot)
{
	switch (prot) {
		case PAGING_PROT_DEFAULT: return "Default";
		case PAGING_PROT_SNPP: return "SNPP";
		case PAGING_PROT_SMTP: return "SMTP";
		case PAGING_PROT_TAP_IXO: return "TAP/IXO";
	}
	__builtin_unreachable();
}

struct paging_provider {
	struct bbs_paging_callbacks *cb;
	int priority;
	enum paging_protocol protocols;
	void *mod;
	RWLIST_ENTRY(paging_provider) entry;
};

static RWLIST_HEAD_STATIC(paging_providers, paging_provider);

int __bbs_register_paging_provider(struct bbs_paging_callbacks *cb, int priority, enum paging_protocol protocols, void *mod)
{
	struct paging_provider *p;

	if (!cb->page_single) {
		bbs_error("The page_single callback is mandatory!\n");
		return -1;
	} else if (priority < 1 || (priority < 2 && protocols != PAGING_PROT_DEFAULT)) {
		/* Enforce PAGING_PROT_DEFAULT being first */
		bbs_error("Invalid priority argument for this protocol\n");
		return -1;
	}

	p = calloc(1, sizeof(*p));
	if (ALLOC_FAILURE(p)) {
		return -1;
	}
	p->cb = cb;
	p->protocols = protocols;
	p->priority = priority;
	p->mod = mod;
	RWLIST_WRLOCK(&paging_providers);
	RWLIST_INSERT_SORTED(&paging_providers, p, entry, priority);
	RWLIST_UNLOCK(&paging_providers);
	return 0;
}

int bbs_unregister_paging_provider(struct bbs_paging_callbacks *cb)
{
	struct paging_provider *p = RWLIST_WRLOCK_REMOVE_BY_FIELD(&paging_providers, cb, cb, entry);
	if (p) {
		free(p);
	}
	return p ? 0 : -1;
}

#define ENSURE_PROVIDERS_REGISTERED() \
	if (RWLIST_EMPTY(&paging_providers)) { \
		RWLIST_UNLOCK(&paging_providers); \
		errno = ECHILD; \
		return -1; \
	}

void bbs_paging_data_free_contents(struct bbs_paging_data *data)
{
	free_if(data->message);
	free_if(data->body);
	free_if(data->subject);
	free_if(data->callerid);
}

int bbs_paging_timestamp(time_t timestamp, char *buf, size_t len)
{
	struct tm tm;
	/* YYMMDDHHMMSS+T format, e.g. 950925143501+12 */
	memset(&tm, 0, sizeof(tm));
	if (localtime_r(&timestamp, &tm)) {
		/* We need to fix up the time zone.
		 * %z is +hhmm or -hhmm, but we want +h or -h */
		int tzoffset, hr, min;
		char *sym = buf + 13; /* After the + or - sign */
		strftime(buf, len, "%y%02m%02d%H%M%S%z", &tm);
		tzoffset = atoi(sym);
		hr = tzoffset / 100; /* e.g. 0730 -> 7 */
		min = tzoffset - (hr * 100); /* e.g. 30 */
		if (min) {
			int frac = min / 60; /* e.g. 30 -> 0.5 */
			snprintf(sym, len - 13, "%d.%01d", hr, 10 * frac); /* 0.5 -> 5 */
		} else {
			snprintf(sym, len - 13, "%d", hr);
		}
		return 0;
	}
	return -1;
}

int bbs_paging_available(void)
{
	int empty;
	RWLIST_RDLOCK(&paging_providers);
	empty = RWLIST_EMPTY(&paging_providers);
	RWLIST_UNLOCK(&paging_providers);
	return empty ? 0 : 1;
}

int bbs_pager_exists(const char *pagerid, enum pager_type *type, enum pager_requirements req)
{
	struct paging_provider *p;
	int last_errno = 0;

	RWLIST_RDLOCK(&paging_providers);
	ENSURE_PROVIDERS_REGISTERED();
	RWLIST_TRAVERSE(&paging_providers, p, entry) {
		if (p->cb->pager_exists) {
			bbs_module_ref(p->mod, 1); /* Note: Technically we don't need to ref/unref, since the provider can't unregister while we hold a RDLOCK */
			*type = p->cb->pager_exists(pagerid, type, req);
			last_errno = errno;
			bbs_module_unref(p->mod, 1);
			if (*type) {
				break;
			}
		}
	}
	RWLIST_UNLOCK(&paging_providers);
	errno = last_errno;
	return p ? 1 : 0;
}

int bbs_pager_ping(const char *pagerid, char *buf, size_t len)
{
	struct paging_provider *p;
	int res;
	int last_errno = 0;

	RWLIST_RDLOCK(&paging_providers);
	ENSURE_PROVIDERS_REGISTERED();
	RWLIST_TRAVERSE(&paging_providers, p, entry) {
		if (p->cb->pager_ping) {
			bbs_module_ref(p->mod, 1);
			res = p->cb->pager_ping(pagerid, buf, len);
			last_errno = errno;
			bbs_module_unref(p->mod, 1);
			if (!res) {
				break;
			}
		}
	}
	RWLIST_UNLOCK(&paging_providers);
	errno = last_errno;
	return p ? 0 : -1;
}

#define HANDLES_PROTOCOL(p, data) ((p->protocols & data->prot) || (p->protocols == data->prot))

int bbs_page_single(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	int res = -1;
	int last_errno = ENXIO;
	struct paging_provider *p;

	if (data->prot && !data->gateway) {
		/* If not PAGING_PROT_DEFAULT, then there must be a gateway provided */
		bbs_error("Non-default protocols require a gateway\n");
		return -1;
	}

	memset(meta, 0, sizeof(struct bbs_paging_message_metadata));
	RWLIST_RDLOCK(&paging_providers);
	ENSURE_PROVIDERS_REGISTERED();
	RWLIST_TRAVERSE(&paging_providers, p, entry) {
		if (!HANDLES_PROTOCOL(p, data)) {
			continue;
		}
		bbs_module_ref(p->mod, 2);
		res = p->cb->page_single(recipient, data, meta);
		bbs_module_unref(p->mod, 2);
		if (!res) {
			break;
		}
		last_errno = errno;
	}
	RWLIST_UNLOCK(&paging_providers);
	errno = last_errno;
	return res;
}

int bbs_page_multiple(struct bbs_paging_recipients *recipients, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	int res = -1;
	int last_errno = ENXIO;
	struct paging_provider *p;

	if (data->prot && !data->gateway) {
		/* If not PAGING_PROT_DEFAULT, then there must be a gateway provided */
		bbs_error("Non-default protocols require a gateway\n");
		errno = last_errno;
		return -1;
	}

	memset(meta, 0, sizeof(struct bbs_paging_message_metadata));
	RWLIST_RDLOCK(&paging_providers);
	ENSURE_PROVIDERS_REGISTERED();
	RWLIST_TRAVERSE(&paging_providers, p, entry) {
		if (!HANDLES_PROTOCOL(p, data)) {
			continue;
		}
		bbs_module_ref(p->mod, 3);
		if (p->cb->page_multiple) {
			res = p->cb->page_multiple(recipients, data, meta);
			last_errno = errno;
		} else {
			int mres;
			struct bbs_paging_recipient *r;
			RWLIST_TRAVERSE(recipients, r, entry) {
				mres = p->cb->page_single(r, data, meta);
				if (!mres) {
					/* If any succeed, return success. Works out since if we return -1,
					 * errno needs to be set, and we'd only do that if they all fail,
					 * so it would still be set correctly. */
					res = 0;
				} else {
					last_errno = errno; /* Save errno since it'll get overwritten before we return */
				}
			}
		}
		bbs_module_unref(p->mod, 3);
		/* If we're paging multiple recipients, we can't break early on success,
		 * since different handlers may handle different recipients.
		 * However, if the recipients have all been consumed, that's a different story. */
	}
	RWLIST_UNLOCK(&paging_providers);
	errno = last_errno;
	return res;
}

int bbs_paging_message_status(struct bbs_paging_message_metadata *meta)
{
	int res = -1;
	int last_errno = 0;
	struct paging_provider *p;
	RWLIST_RDLOCK(&paging_providers);
	ENSURE_PROVIDERS_REGISTERED();
	RWLIST_TRAVERSE(&paging_providers, p, entry) {
		if (p->cb->page_status) {
			bbs_module_ref(p->mod, 2);
			res = p->cb->page_status(meta);
			last_errno = errno;
			bbs_module_unref(p->mod, 2);
			if (!res) {
				break;
			}
		}
	}
	RWLIST_UNLOCK(&paging_providers);
	errno = last_errno;
	return res;
}

int bbs_paging_message_expire(struct bbs_paging_message_metadata *meta)
{
	int res = -1;
	int last_errno = 0;
	struct paging_provider *p;
	RWLIST_RDLOCK(&paging_providers);
	ENSURE_PROVIDERS_REGISTERED();
	RWLIST_TRAVERSE(&paging_providers, p, entry) {
		if (p->cb->page_expire) {
			bbs_module_ref(p->mod, 2);
			res = p->cb->page_expire(meta);
			last_errno = errno;
			bbs_module_unref(p->mod, 2);
			if (!res) {
				break;
			}
		}
	}
	RWLIST_UNLOCK(&paging_providers);
	errno = last_errno;
	return res;
}

static int cli_paging_providers(struct bbs_cli_args *a)
{
	struct paging_provider *p;
	int c = 0;

	bbs_dprintf(a->fdout, "Outbound Paging Providers:\n");
	bbs_dprintf(a->fdout, "%3s %s\n", "Pri", "Protocol");
	RWLIST_RDLOCK(&paging_providers);
	RWLIST_TRAVERSE(&paging_providers, p, entry) {
		bbs_dprintf(a->fdout, "%3d %s\n", p->priority, paging_protocol_name(p->protocols));
		c++;
	}
	RWLIST_UNLOCK(&paging_providers);
	bbs_dprintf(a->fdout, "%d outbound paging provider%s registered\n", c, ESS(c));
	return 0;
}

static struct bbs_cli_entry cli_commands_paging[] = {
	BBS_CLI_COMMAND(cli_paging_providers, "paging providers", 2, "List supported outbound paging providers", NULL),
};

int bbs_paging_init(void)
{
	return bbs_cli_register_multiple(cli_commands_paging);
}
