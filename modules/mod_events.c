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

#include <string.h>

#include "include/module.h"
#include "include/node.h"
#include "include/event.h"
#include "include/notify.h"
#include "include/system.h"

static int last_badnode_time = 0;
static char last_badnode_ip[64] = "";

static int event_cb(struct bbs_event *event)
{
	int now;

	switch (event->type) {
		case EVENT_NODE_LOGIN_FAILED:
		case EVENT_NODE_SHORT_SESSION:
			now = time(NULL);
#define BAD_CONNECT_THRESHOLD 3
			/* If we get two bad attempts in a row from the same IP, within 3 seconds, block it.
			 * Far from comprehensive, this is mainly to drop garbage traffic, not sophisticated brute force attempts. */
			if (!strcmp(event->ipaddr, "127.0.0.1")) {
				return 1; /* Ignore localhost */
			}
			if (!last_badnode_time || last_badnode_time < now - BAD_CONNECT_THRESHOLD || strcmp(last_badnode_ip, event->ipaddr)) {
				last_badnode_time = now;
				safe_strncpy(last_badnode_ip, event->ipaddr, sizeof(last_badnode_ip));
				return 1;
			} else {
				int res;
				if (is_root()) {
					char *argv[] = { "/usr/sbin/iptables", "-A", "INPUT", "-s", event->ipaddr, "-j", "DROP", NULL };
					res = bbs_execvp_fd(NULL, -1, -1, "/usr/sbin/iptables", argv);
				} else {
					/* There's no guarantee that the BBS user is in the sudoers file for this command, or even that sudo is installed,
					 * but this is the only way it could even work, so give it a try. */
					char *argv[] = { "/usr/bin/sudo", "-n", "/usr/sbin/iptables", "-A", "INPUT", "-s", event->ipaddr, "-j", "DROP", NULL };
					res = bbs_execvp_fd(NULL, -1, -1, "/usr/bin/sudo", argv);
				}
				if (res) {
					bbs_warning("Failed to block %s using iptables: %s\n", event->ipaddr, strerror(res));
				} else {
					bbs_auth("Temporarily blocked IP address %s\n", event->ipaddr);
				}
			}
			return 1;
		case EVENT_USER_REGISTRATION:
		/* Relatively speaking, it's a pretty big deal whenever a new user registers.
			 * Notify the sysop. */
			bbs_sysop_email(NULL, "New User Registration", "Greetings, sysop,\r\n\tA new user, %s (#%d), just registered on your BBS from IP %s.",
				event->username, event->userid, event->ipaddr);
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
