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
 * \brief RFC 1288 Finger Information Protocol
 *
 * \note This protocol provides no authentication, encryption, or security whatsoever. Use at your own risk.
 * \note Sorry, no vending machine support.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <signal.h>

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/user.h"

#define DEFAULT_FINGER_PORT 79

static int finger_port = DEFAULT_FINGER_PORT;

static int allusersallowed = 0;

static void *finger_handler(void *varg)
{
	char buf[256];
	struct bbs_node *node = varg;
	char *tmp, *query;
	char *username = NULL;
	char *hostname = NULL;
	int verbose = 0;
	ssize_t res;

	/* This thread is running instead of the normal node handler thread */
	/* Remember, no pseudoterminal is allocated for this node! Can NOT use normal bbs_ I/O functions. */
	bbs_node_begin(node);

	/* A RUIP (Remote User Information Program) client has connected to us.
	 * Note that the GNU finger client doesn't seem to work for me but the Windows one does. Go figure.
	 * Query string formats are:
	 * [/W ] username@host CR LF <- specific user
	 * CR LF <- all users
	 * The /W modifier increases verbosity. */

	/* This is not buffered since there's no pseudoterminal. */
	res = bbs_poll_read(node->fd, 1000, buf, sizeof(buf) - 1);
	if (res <= 0) {
		goto cleanup;
	}
	buf[res] = '\0'; /* Safe */
	tmp = strstr(buf, "\r\n");
	if (!tmp) {
		bbs_debug(1, "Incomplete finger query? (%s)\n", buf);
		/* Just assume CR LF was next and try to parse it, sometimes this happens, so we'll be liberal with what we accept */
	} else {
		*tmp = '\0';
	}
	query = buf;
	bbs_debug(1, "Finger query from %s: %s\n", node->ip, query); /* Raw query, without CR LF */
	if (!strlen_zero(query)) {
		int hashost = strchr(query, '@') ? 1 : 0;
		tmp = strsep(&query, " ");
		if (tmp && !strcmp(tmp, "/W")) {
			verbose = 1; /* -l or long list format switch */
			tmp = strsep(&query, " ");
		}
		if (hashost) {
			query = tmp;
			tmp = strsep(&query, "@");
			if (!strlen_zero(tmp)) {
				username = tmp;
			}
			hostname = query;
		} else {
			username = tmp;
		}
	} /* else, all users */
	bbs_verb(4, "Finger query from %s: %s@%s%s\n", node->ip, S_IF(username), S_IF(hostname), verbose ? " (verbose)" : "");

	if (!strlen_zero(hostname)) {
		goto cleanup; /* This RUIP does not support query forwarding to other RUIPs, so the hostname portion should be empty. */
	}

	if (!strlen_zero(username)) {
		if (bbs_user_dump(node->fd, username, 4)) {
			bbs_debug(1, "No such user: %s\n", username);
		}
	} else {
		/* All users */
		if (!allusersallowed) {
			bbs_dprintf(node->fd, "Finger online user list denied\r\n"); /* Other finger servers don't seem to do this, but the RFC says to... */
		} else {
			bbs_users_dump(node->fd, 4);
		}
	}

cleanup:
	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("net_finger.conf", 0);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_port(cfg, "finger", "port", &finger_port);
	bbs_config_val_set_true(cfg, "finger", "allusersallowed", &allusersallowed);

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	return bbs_start_tcp_listener(finger_port, "Finger", finger_handler);
}

static int unload_module(void)
{
	bbs_stop_tcp_listener(finger_port);
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC1288 Finger");
