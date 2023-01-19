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
 * \brief Messaging
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/editor.h"
#include "include/door.h"
#include "include/notify.h"
#include "include/utils.h"

static int msg_sysop_exec(struct bbs_node *node, const char *args)
{
	int res;
	char buf[1024];

	UNUSED(args);

	res = bbs_line_editor(node, "Compose message, then process to send", buf, sizeof(buf) - 1);
	if (res < 0) {
		return res;
	} else if (res > 0) {
		NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
		return 0;
	}

	if (strlen(buf) < 10 || !bbs_str_isprint(buf)) {
		bbs_writef(node, "%sMessage rejected, aborting%s\n", COLOR(COLOR_FAILURE), COLOR_RESET);
		NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
		return 0;
	}

	if (bbs_user_is_guest(node->user)) {
		res = bbs_sysop_email(node->user, "New Sysop Inquiry", "Guest user %s has just messaged you:\r\n\r\n%s\r\n", bbs_user_alias(node->user), buf);
	} else {
		res = bbs_sysop_email(node->user, "New Sysop Inquiry", "User %s (#%d) has just messaged you:\r\n\r\n%s\r\n", bbs_username(node->user), node->user->id, buf);
	}
	if (res) {
		bbs_writef(node, "%sSystem error, message not sent.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET);
		NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
		return 0;
	}
	bbs_writef(node, "%sYour message has been sent!%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET);
	NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
	return 0;
}

static int load_module(void)
{
	return bbs_register_door("msgsysop", msg_sysop_exec);
}

static int unload_module(void)
{
	return bbs_unregister_door("msgsysop");
}

BBS_MODULE_INFO_STANDARD("Direct Messaging");
