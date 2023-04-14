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
 * \brief User and Node Statistics
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/auth.h"
#include "include/door.h"
#include "include/editor.h"

static int users_exec(struct bbs_node *node, const char *args)
{
	int index = 0;
	int activeonly = 0;
	int totalonline = 0, total = 0;
	struct pager_info pginfo;
	struct bbs_user *user, **userlist = bbs_user_list();

	if (!userlist) {
		return 0;
	}

	if (!strlen_zero(args) && !strcasecmp(args, "active")) {
		activeonly = 1;
	}

	/* Don't be deceived: this is an O(n^2) operation, since we call bbs_user_online for each user */
	bbs_clear_screen(node);
	memset(&pginfo, 0, sizeof(pginfo));
	while ((user = userlist[index++])) {
		char buf[96];
		int len;
		int active;
		active = bbs_user_online(user->id);
		total++;
		if (!active && activeonly) {
			continue;
		}
		if (index == 1) {
			bbs_writef(node, COLOR(COLOR_PRIMARY) " %4s %-15s %s\r\n", "#", "USERNAME", "ONLINE");
		}
		if (active) {
			totalonline++;
		}
		len = snprintf(buf, sizeof(buf), COLOR(COLOR_SECONDARY) " %4d " COLOR_RESET "%-15s %s\r\n", user->id, bbs_username(user), (active ? "  *  " : ""));
		if (bbs_pager(node, &pginfo, MIN_MS(3), buf, len)) {
			break;
		}
	}

	bbs_user_list_destroy(userlist);
	bbs_writef(node, "%d user%s online (%d total)\n", totalonline, ESS(totalonline), total);
	NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
	return 0;
}

static int nodes_exec(struct bbs_node *node, const char *args)
{
	UNUSED(args);
	bbs_clear_screen(node);
	bbs_node_statuses(node);
	NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
	return 0;
}

static int unload_module(void)
{
	bbs_unregister_door("listusers");
	bbs_unregister_door("listnodes");
	return 0;
}

static int load_module(void)
{
	int res = 0;
	res |= bbs_register_door("listusers", users_exec);
	res |= bbs_register_door("listnodes", nodes_exec);
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_STANDARD("User and Node Statistics");
