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
#include <fcntl.h>

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/user.h"

#include "include/transfer.h"

#define DEFAULT_FINGER_PORT 79

static int finger_port = DEFAULT_FINGER_PORT;

static int allusersallowed = 0;

/*!
 * \brief Print a file's contents to a file descriptor
 * \param wfd File descriptor to which to write.
 * \param filename Name of file. Assumed to exist.
 * \param endl Line endings to enforce (NULL if no conversion needed)
 * \param maxlines Maximum number of lines to print. 0 for no limit. Only supported if endl is not NULL.
 * \param maxbytes Maximum number of bytes to print. 0 for no limit.
 * \retval 0 on success, -1 on failure
 */
static int print_file(int wfd, const char *filename, const char *endl, int maxlines, size_t maxbytes)
{
	int res;

	if (!endl && !maxbytes) {
		res = bbs_send_file(filename, wfd) <= 0 ? -1 : 0;
	} else if (!endl) {
		/* maxbytes != 0 */
		int fd = open(filename, O_RDONLY);
		if (fd < 0) {
			bbs_warning("Failed to open(%s): %s\n", filename, strerror(errno));
			return -1;
		}
		res = bbs_sendfile(wfd, fd, NULL, maxbytes) <= 0 ? -1 : 0;
		close(fd);
	} else {
		/* Read line by line so we can do line ending conversions. */
		char buf[1024];
		int lines = 0;
		size_t written = 0;
		size_t endlen = strlen(endl);
		FILE *fp = fopen(filename, "r");
		if (!fp) {
			bbs_warning("Failed to fopen(%s): %s\n", filename, strerror(errno));
			return -1;
		}
		while ((fgets(buf, sizeof(buf), fp))) {
			bbs_term_line(buf);
			if (maxlines && lines++ >= maxlines) {
				bbs_debug(1, "Exceeded maximum lines allowed\n");
				break;
			}
			if (maxbytes) {
				size_t linebytes = strlen(buf);
				written += linebytes + endlen;
				/* We could truncate the line early,
				 * to be more precise,
				 * or we could just abort now. */
				if (written > maxbytes) {
					bbs_debug(1, "Exceeded maximum bytes allowed\n");
					break;
				}
			}
			bbs_writef(wfd, "%s%s", buf, endl);
		}
		res = 0;
		fclose(fp);
	}

	return res;
}

static void *finger_handler(void *varg)
{
	char buf[256];
	struct bbs_node *node = varg;
	char *tmp, *query;
	char *username = NULL;
	char *hostname = NULL;
	int verbose = 0;
	ssize_t res;

	bbs_node_net_begin(node);

	/* A RUIP (Remote User Information Program) client has connected to us.
	 * Note that the GNU finger client doesn't seem to work for me but the Windows one does. Go figure.
	 * Query string formats are:
	 * [/W ] username@host CR LF <- specific user
	 * CR LF <- all users
	 * The /W modifier increases verbosity. */

	/* This is not buffered since there's no pseudoterminal. */
	res = bbs_poll_read(node->rfd, 1000, buf, sizeof(buf) - 1);
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
		if (bbs_user_dump(node->wfd, username, 4)) {
			bbs_debug(1, "No such user: %s\n", username);
		} else {
			char pfile[256];
			unsigned int userid;
			/* If user exists, also display project and plan, if available */
			userid = bbs_userid_from_username(username);
			if (!bbs_transfer_home_config_file(userid, ".project", pfile, sizeof(pfile))) {
				bbs_node_fd_writef(node, node->wfd, "Project: ");
				if (print_file(node->wfd, pfile, "\r\n", 1, 128)) {
					/* If it failed, add a new line ourselves. */
					bbs_node_fd_writef(node, node->wfd, "\r\n");
				}
			}
			if (!bbs_transfer_home_config_file(userid, ".plan", pfile, sizeof(pfile))) {
				/* If the user wants the plan to begin on its own line,
				 * then the first line of the plan can simply be a line break. */
				bbs_node_fd_writef(node, node->wfd, "Plan: ");
				print_file(node->wfd, pfile, "\r\n", 10, 512);
				/* Don't really care if there's a line break here or not */
			} else {
				bbs_node_fd_writef(node, node->wfd, "No Plan.\r\n");
			}
		}
	} else {
		/* All users */
		if (!allusersallowed) {
			bbs_node_fd_writef(node, node->wfd, "Finger online user list denied\r\n"); /* Other finger servers don't seem to do this, but the RFC says to... */
		} else {
			bbs_users_dump(node->wfd, 4);
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
	bbs_config_unlock(cfg);
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
