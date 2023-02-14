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
 * \brief Protocol-agnostic file transfer settings
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/config.h"
#include "include/transfer.h"
#include "include/node.h" /* for node->user */
#include "include/user.h"

static char rootdir[84];
static int privs[5];
static int access_priv, download_priv, upload_priv, delete_priv, newdir_priv;
static int idletimeout;

const char *bbs_transfer_rootdir(void)
{
	return rootdir;
}

int bbs_transfer_timeout(void)
{
	return idletimeout;
}

int bbs_transfer_operation_allowed(struct bbs_node *node, int operation)
{
	int required_priv;

	bbs_assert(IN_BOUNDS(operation, 0, (int) ARRAY_LEN(privs)));

	required_priv = privs[operation];
	if (bbs_user_priv(node->user) >= required_priv) {
		return 1;
	}
	return 0;
}

int bbs_transfer_config_load(void)
{
	struct bbs_config *cfg = bbs_config_load("transfers.conf", 1); /* Load cached version, since multiple transfer protocols may use this config */

	if (!cfg) {
		return -1; /* Decline to load if there is no config. */
	}

	idletimeout = 60000;
	if (!bbs_config_val_set_int(cfg, "transfers", "timeout", &idletimeout)) {
		idletimeout *= 1000; /* convert s to ms */
	}
	if (bbs_config_val_set_path(cfg, "transfers", "rootdir", rootdir, sizeof(rootdir))) { /* Must explicitly specify */
		bbs_error("No rootdir specified, transfers will be disabled\n");
		return -1;
	}

	access_priv = 0;
	download_priv = 0;
	upload_priv = 1;
	delete_priv = 2;
	newdir_priv = 2;
	bbs_config_val_set_int(cfg, "privs", "access", &privs[TRANSFER_ACCESS]);
	bbs_config_val_set_int(cfg, "privs", "download", &privs[TRANSFER_DOWNLOAD]);
	bbs_config_val_set_int(cfg, "privs", "upload", &privs[TRANSFER_UPLOAD]);
	bbs_config_val_set_int(cfg, "privs", "delete", &privs[TRANSFER_NEWDIR]);
	bbs_config_val_set_int(cfg, "privs", "newdirs", &privs[TRANSFER_DESTRUCTIVE]);

	return 0;
}
