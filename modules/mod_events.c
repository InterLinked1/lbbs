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
 * \brief Event callbacks
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/module.h"
#include "include/node.h"
#include "include/event.h"
#include "include/notify.h"

static int event_cb(struct bbs_event *event)
{
	switch (event->type) {
		case EVENT_USER_REGISTRATION:
			/* Relatively speaking, it's a pretty big deal whenever a new user registers.
			 * Notify the sysop. */
			bbs_sysop_email(NULL, "New User Registration", "Greetings, sysop,\r\n\tA new user, %s (#%d), just registered on your BBS from IP %s.",
				event->username, event->nodenum, event->ipaddr);
			return 1;
		default:
			return 0;
	}
}

static int load_module(void)
{
	return bbs_register_event_consumer(event_cb);
}

static int unload_module(void)
{
	return bbs_unregister_event_consumer(event_cb);
}

BBS_MODULE_INFO_STANDARD("Core Event Handlers");
