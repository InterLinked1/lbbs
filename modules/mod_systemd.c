/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief systemd signal support
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <systemd/sd-daemon.h>

#include "include/module.h"
#include "include/event.h"

static int event_cb(struct bbs_event *event)
{
	switch (event->type) {
		case EVENT_STARTUP:
			sd_notifyf(0, "READY=1\nMAINPID=%lu", (unsigned long) getpid());
			break;
		case EVENT_SHUTDOWN:
			sd_notify(0, "STOPPING=1");
			break;
		case EVENT_RELOAD:
			sd_notify(0, "READY=1");
			break;
		default:
			return 0;
	}
	return 1;
}

static int load_module(void)
{
	return bbs_register_event_consumer(event_cb);
}

static int unload_module(void)
{
	return bbs_unregister_event_consumer(event_cb);
}

BBS_MODULE_INFO_STANDARD("systemd support");
