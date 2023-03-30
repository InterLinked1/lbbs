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
 * \brief Internal Event Bus
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/event.h"
#include "include/node.h"
#include "include/user.h"

struct event_consumer {
	int (*callback)(struct bbs_event *event);
	struct bbs_module *module;
	RWLIST_ENTRY(event_consumer) entry;
};

static RWLIST_HEAD_STATIC(consumers, event_consumer);

int __bbs_register_event_consumer(int (*callback)(struct bbs_event *event), void *mod)
{
	struct event_consumer *c;

	RWLIST_WRLOCK(&consumers);
	RWLIST_TRAVERSE(&consumers, c, entry) {
		if (c->callback == callback) {
			break;
		}
	}
	if (c) {
		bbs_error("Provider is already registered\n");
		RWLIST_UNLOCK(&consumers);
		return -1;
	}
	c = calloc(1, sizeof(*c));
	if (!c) {
		RWLIST_UNLOCK(&consumers);
		return -1;
	}
	c->callback = callback;
	c->module = mod;
	RWLIST_INSERT_TAIL(&consumers, c, entry);
	RWLIST_UNLOCK(&consumers);
	return 0;
}

int bbs_unregister_event_consumer(int (*callback)(struct bbs_event *event))
{
	struct event_consumer *c;

	c = RWLIST_WRLOCK_REMOVE_BY_FIELD(&consumers, callback, callback, entry);
	if (!c) {
		bbs_error("Failed to unregister event consumer: not currently registered\n");
		return -1;
	} else {
		free(c);
	}
	return 0;
}

const char *bbs_event_name(enum bbs_event_type type)
{
	switch (type) {
		case EVENT_STARTUP:
			return "STARTUP";
		case EVENT_SHUTDOWN:
			return "SHUTDOWN";
		case EVENT_NODE_SHORT_SESSION:
			return "NODE_SHORT_SESSION";
		case EVENT_NODE_LOGIN_FAILED:
			return "NODE_LOGIN_FAILED";
		case EVENT_USER_REGISTRATION:
			return "USER_REGISTRATION";
		case EVENT_USER_LOGIN:
			return "USER_LOGIN";
		case EVENT_USER_LOGOFF:
			return "USER_LOGOFF";
		case EVENT_USER_PASSWORD_CHANGE:
			return "USER_PASSWORD_CHANGE";
	}
	bbs_error("Unknown event: %d\n", type);
	return NULL;
}

int bbs_event_broadcast(struct bbs_event *event)
{
	int res = 0;
	int mres;
	struct event_consumer *c;

	/* Give each callback function a const pointer to it (since they all get the same event) */
	RWLIST_RDLOCK(&consumers);
	RWLIST_TRAVERSE(&consumers, c, entry) {
		bbs_module_ref(c->module);
		mres = c->callback(event);
		bbs_module_unref(c->module);
		res = MAX(mres, res);
		if (mres > 1) {
			break;
		}
	}
	RWLIST_UNLOCK(&consumers);
	bbs_debug(4, "Event %s dispatched and %s\n", bbs_event_name(event->type), res ? res == 2 ? "exclusively consumed" : "consumed" : "not consumed");
	return res;
}

int bbs_event_dispatch(struct bbs_node *node, enum bbs_event_type type)
{
	struct bbs_event event;

	memset(&event, 0, sizeof(event));
	event.type = type;

	switch (type) {
		case EVENT_STARTUP:
		case EVENT_SHUTDOWN:
			break;
		case EVENT_USER_REGISTRATION:
		case EVENT_USER_LOGIN:
		case EVENT_USER_LOGOFF:
		case EVENT_USER_PASSWORD_CHANGE:
			if (node && node->user) {
				safe_strncpy(event.username, bbs_username(node->user), sizeof(event.username));
			}
			/* Fall through */
		case EVENT_NODE_SHORT_SESSION:
		case EVENT_NODE_LOGIN_FAILED:
			if (!node) {
				bbs_error("Can't create an event without a node\n");
				return -1;
			}
			event.nodenum = node->id;
			if (node->user) {
				event.userid = node->user->id;
			}
			/* Copy over some of the useful node/user information. */
			safe_strncpy(event.protname, node->protname, sizeof(event.protname));
			if (node->ip) {
				safe_strncpy(event.ipaddr, node->ip, sizeof(event.ipaddr));
			}
			break;
		/* No default, so we'll have to explicitly handle any newly added events. */
	}

	return bbs_event_broadcast(&event);
}
