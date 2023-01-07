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
 * \brief New User Tutorial
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/module.h"
#include "include/node.h"
#include "include/door.h"
#include "include/net.h"

static int tutorial_exec(struct bbs_node *node, const char *args)
{
	UNUSED(args);

	bbs_clear_screen(node);
	bbs_draw_line(node, '=');
	bbs_writef(node, "%sHere are some tips to help you enjoy your %sBBSing%s experience:\n", COLOR(COLOR_WHITE), COLOR(COLOR_GREEN), COLOR(COLOR_WHITE));
	bbs_draw_line(node, '=');

	bbs_writef(node, COLOR(COLOR_BLUE) "\n");
	bbs_writef(node, "You can access this BBS directly from the Internet at %s%s%s.\n", COLOR(COLOR_GREEN), bbs_hostname(), COLOR(COLOR_BLUE));
	bbs_writef(node, "You can connect to this BBS using any of the following protocols:\n");
	bbs_list_network_protocols(node->slavefd); /* bbs_list_network_protocols takes a fd, not a node */
	bbs_writef(node, "Direct dial access may also be available - just ask your sysop.\n");
	NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));

	bbs_writef(node, COLOR(COLOR_BLUE) "\r"); /* Erase "hit a key" prompt and continue onwards */
	bbs_writef(node, "You can navigate the BBS by choosing options available on the current menu.\n");
	bbs_writef(node, "You may find that you frequently access options in a submenu.\nTo more quickly access these options, you can skip over\nintermediate menus using the %s/%s command.\n", COLOR(COLOR_RED), COLOR(COLOR_BLUE));
	bbs_writef(node, "For example, instead of pressing %sa%s, %sb%s, then %sc%s, rendering each\nintermediate submenu, you could simply press %s/abc%s to access this option.\n", COLOR(COLOR_RED), COLOR(COLOR_BLUE), COLOR(COLOR_RED), COLOR(COLOR_BLUE), COLOR(COLOR_RED), COLOR(COLOR_BLUE), COLOR(COLOR_RED), COLOR(COLOR_BLUE));
	NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));

	bbs_writef(node, COLOR(COLOR_BLUE) "\r"); /* Erase "hit a key" prompt and continue onwards */
	bbs_writef(node, "When you see %s:%s, output is being paged to the screen.\nYou can use these keys to navigate:\n", COLOR(COLOR_WHITE), COLOR(COLOR_BLUE));
	bbs_writef(node, "%s%10s%s => Quit\n", COLOR(COLOR_RED), "q", COLOR(COLOR_BLUE));
	bbs_writef(node, "%s%10s%s => Line down\n", COLOR(COLOR_RED), "DOWN ARROW", COLOR(COLOR_BLUE));
	bbs_writef(node, "%s%10s%s => Page down\n", COLOR(COLOR_RED), "SPACE", COLOR(COLOR_BLUE));
	bbs_writef(node, "%s%10s%s => Skip to end of output\n", COLOR(COLOR_RED), "g", COLOR(COLOR_BLUE));
	bbs_writef(node, "The %s:%s prompt will change to %sEOF:%s once you have reached\nthe end of the available output.\n", COLOR(COLOR_WHITE), COLOR(COLOR_BLUE), COLOR(COLOR_WHITE), COLOR(COLOR_BLUE));

	bbs_writef(node, COLOR(COLOR_BLUE) "\n");
	bbs_writef(node, "If you have further questions, feel free to contact your friendly sysop!\n");

	NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
	return 0;
}

static int load_module(void)
{
	return bbs_register_door("tutorial", tutorial_exec);
}

static int unload_module(void)
{
	return bbs_unregister_door("tutorial");
}

BBS_MODULE_INFO_STANDARD("New User Tutorial");
