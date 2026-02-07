/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Evergreen email client wrapper
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/auth.h"
#include "include/door.h"
#include "include/term.h"
#include "include/system.h"
#include "include/utils.h" /* use safe_strncpy */

static int evergreen_exec(struct bbs_node *node, const char *args)
{
	struct bbs_exec_params x;
	char username[64];
	char fromname[64];
	char fromaddr[64];
	char passwordbuf[TEMP_PASSWORD_TOKEN_BUFLEN];
	/* Default is plaintext ports, localhost, no security, so we're good for plaintext */
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	/* Moderate debug to log file */
	char *const argv[] = { "evergreen", "-ddddd", "-l" "/var/log/lbbs/evergreen.log", "--fromname", fromname, "--fromaddr", fromaddr, "--imap-username", username, "--imap-password", passwordbuf, "--smtp-password", passwordbuf, NULL };
#pragma GCC diagnostic pop

	UNUSED(args);

	if (!bbs_user_is_registered(node->user)) {
		bbs_node_writef(node, "You must be registered to check email");
		bbs_node_wait_key(node, MIN_MS(1));
		return 0;
	}

	safe_strncpy(username, bbs_username(node->user), sizeof(username));
	if (!strlen_zero(node->user->fullname)) {
		safe_strncpy(fromname, node->user->fullname, sizeof(fromname));
	}
	snprintf(fromaddr, sizeof(fromaddr), "%s@%s", bbs_username(node->user), bbs_hostname());
	bbs_str_tolower(fromaddr);

	/* Create a temporary password for the user for IMAP/SMTP authentication.
	 * Token needs to linger, not for IMAP, but for SMTP. */
	if (bbs_user_semiperm_authorization_token(node->user, passwordbuf, sizeof(passwordbuf))) {
		return 0;
	}

	EXEC_PARAMS_INIT(x);
	bbs_execvp(node, &x, "evergreen", argv);
	bbs_user_semiperm_authorization_token_purge(passwordbuf);
	return 0; /* Don't return -1 or the node will abort */
}

static int load_module(void)
{
	/*! \todo See LBBS-11. Note that in the future if we use isonetexec to run evergreen, it only needs to exist in the container, not on the system */
	BBS_REQUIRE_EXTERNAL_PROGRAM("evergreen");
	return bbs_register_door("mail", evergreen_exec);
}

static int unload_module(void)
{
	return bbs_unregister_door("mail");
}

BBS_MODULE_INFO_STANDARD("Evergreen Mail Client");
