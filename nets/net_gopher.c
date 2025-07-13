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
 * \brief RFC 1436 Gopher server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"

#define DEFAULT_GOPHER_PORT 70

static int gopher_port = DEFAULT_GOPHER_PORT;
static char gopher_root[256] = "";

/* Types that we support:
 * 0 - text file
 * 1 - directory (submenu)
 * 3 - error code
 * i - informational message (noncanonical, not in RFC 1436, but widely used)
 *
 * User display strings should be <= 70 characters.
 */
#define GOPHER_FILE '0'
#define GOPHER_DIRECTORY '1'
#define GOPHER_ERROR '3'
#define GOPHER_INFO 'i'

static int directory_menu(const char *dir_name, const char *filename, int dir, void *obj)
{
	struct bbs_node *node = obj;
	const char *parent = dir_name + strlen(gopher_root);

	/* Format is <type><display string>\t<selector string>\t<hostname>\t<port>\r\n */
	bbs_node_fd_writef(node, node->fd, "%c%s\t%s/%s\t%s\t%d\r\n", dir ? GOPHER_DIRECTORY : GOPHER_FILE, filename, parent, filename, bbs_hostname(), gopher_port);
	bbs_debug(4, "%c%s\t%s/%s\t%s\t%d\r\n", dir ? GOPHER_DIRECTORY : GOPHER_FILE, filename, parent, filename, bbs_hostname(), gopher_port);
	return 0;
}

static void *gopher_handler(void *varg)
{
	char fullpath[512];
	char buf[256];
	struct bbs_node *node = varg;
	char *tmp;
	struct stat st;
	ssize_t res;

	bbs_node_net_begin(node);

	/* This is not buffered since there's no pseudoterminal. */
	res = bbs_poll_read(node->fd, 1000, buf, sizeof(buf) - 1); /* Read the retrieval/selector string from the client */
	if (res <= 0) {
		goto cleanup;
	}
	buf[res] = '\0'; /* Safe */

	tmp = strstr(buf, "\r\n");
	if (!tmp && (!(tmp = strchr(buf, '\t')))) { /* Tabs can also indicate end of retrieval string, according to RFC 1436 3.6  */
		goto cleanup; /* Request is incomplete */
	}
	*tmp = '\0';
	snprintf(fullpath, sizeof(fullpath), "%s%s", gopher_root, buf); /* selectors should start with a '/' */
	bbs_debug(1, "Gopher request from %s: %s => %s\n", node->ip, buf, fullpath);

	/* Dangerous path request or nonexistent file */
	if (strstr(buf, "..") || stat(fullpath, &st)) {
		bbs_node_fd_writef(node, node->fd, "%c'%s' doesn't exist!\r\n", GOPHER_ERROR, buf);
		bbs_node_fd_writef(node, node->fd, "%c'This resource cannot be located.\r\n", GOPHER_INFO);
		goto cleanup;
	}

	if (S_ISDIR(st.st_mode)) {
		bbs_dir_traverse_items(fullpath, directory_menu, node); /* Dump the directory */
	} else if (S_ISREG(st.st_mode)) {
		FILE *fp = fopen(fullpath, "r");
		if (fp) {
			off_t offset = 0;
			int size;

			fseek(fp, 0L, SEEK_END); /* Go to EOF to determine how big the file is. */
			size = (int) ftell(fp);
			rewind(fp); /* Be kind, rewind */

			res = (int) bbs_sendfile(node->fd, fileno(fp), &offset, (size_t) size); /* We must manually tell it the offset or it will be at the EOF, even with rewind() */
			fclose(fp);
		} else {
			bbs_error("fopen failed: %s\n", strerror(errno));
		}
	} else { /* Anything else doesn't exist as far as the user is concerned */
		bbs_node_fd_writef(node, node->fd, "%c'%s' doesn't exist!\r\n", GOPHER_ERROR, buf);
		bbs_node_fd_writef(node, node->fd, "%c'This resource cannot be located.\r\n", GOPHER_INFO);
	}

	/* XXX Lynx gopher client seems to display the period. Not sure why, but not all Gopher servers send the trailing period. */
	bbs_node_fd_writef(node, node->fd, ".\r\n"); /* End with period on a line by itself */

cleanup:
	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("net_gopher.conf", 0);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_port(cfg, "gopher", "port", &gopher_port);
	if (bbs_config_val_set_path(cfg, "gopher", "root", gopher_root, sizeof(gopher_root))) {
		bbs_config_unlock(cfg);
		return -1;
	}

	bbs_config_unlock(cfg);
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	return bbs_start_tcp_listener(gopher_port, "Gopher", gopher_handler);
}

static int unload_module(void)
{
	bbs_stop_tcp_listener(gopher_port);
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC1436 Gopher");
