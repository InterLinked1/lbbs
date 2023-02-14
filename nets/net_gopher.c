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
#include <sys/sendfile.h>

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/utils.h"
#include "include/node.h"

#define DEFAULT_GOPHER_PORT 70

static int gopher_port = DEFAULT_GOPHER_PORT;
static int gopher_socket = -1;
static pthread_t gopher_listener_thread = -1;
static char gopher_root[256] = "";

#undef dprintf

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
	dprintf(node->fd, "%c%s\t%s/%s\t%s\t%d\r\n", dir ? GOPHER_DIRECTORY : GOPHER_FILE, filename, parent, filename, bbs_hostname(), gopher_port);
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
	int res;

	/* This thread is running instead of the normal node handler thread */
	/* Remember, no pseudoterminal is allocated for this node! Can NOT use normal bbs_ I/O functions. */
	bbs_node_begin(node);

	/* This is not buffered since there's no pseudoterminal. */
	res = bbs_fd_poll_read(node->fd, 1000, buf, sizeof(buf) - 1); /* Read the retrieval/selector string from the client */
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
	if (strstr(buf, "..") || eaccess(fullpath, R_OK) || stat(fullpath, &st)) {
		dprintf(node->fd, "%c'%s' doesn't exist!\r\n", GOPHER_ERROR, buf);
		dprintf(node->fd, "%c'This resource cannot be located.\r\n", GOPHER_INFO);
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
			size = ftell(fp);
			rewind(fp); /* Be kind, rewind */

			res = sendfile(node->fd, fileno(fp), &offset, size); /* We must manually tell it the offset or it will be at the EOF, even with rewind() */
			if (res != size) {
				bbs_error("sendfile failed (%d): %s\n", res, strerror(errno));
			}
			fclose(fp);
		} else {
			bbs_error("fopen failed: %s\n", strerror(errno));
		}
	} else { /* Anything else doesn't exist as far as the user is concerned */
		dprintf(node->fd, "%c'%s' doesn't exist!\r\n", GOPHER_ERROR, buf);
		dprintf(node->fd, "%c'This resource cannot be located.\r\n", GOPHER_INFO);
	}

	/* XXX Lynx gopher client seems to display the period. Not sure why, but not all Gopher servers send the trailing period. */
	dprintf(node->fd, ".\r\n"); /* End with period on a line by itself */

cleanup:
	bbs_node_exit(node);
	return NULL;
}

static void *gopher_listener(void *unused)
{
	UNUSED(unused);
	/* Use a generic listener, even though it will allocate a node, which isn't really needed */
	bbs_tcp_listener(gopher_socket, "Gopher", gopher_handler, BBS_MODULE_SELF);
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
		return -1;
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	/* If we can't start the TCP listener, decline to load */
	if (bbs_make_tcp_socket(&gopher_socket, gopher_port)) {
		return -1;
	}

	if (bbs_pthread_create(&gopher_listener_thread, NULL, gopher_listener, NULL)) {
		bbs_error("Unable to create Gopher listener thread.\n");
		close_if(gopher_socket);
		return -1;
	}

	bbs_register_network_protocol("Gopher", gopher_port);
	return 0;
}

static int unload_module(void)
{
	pthread_cancel(gopher_listener_thread);
	pthread_kill(gopher_listener_thread, SIGURG);
	bbs_pthread_join(gopher_listener_thread, NULL);
	close_if(gopher_socket);
	bbs_unregister_network_protocol(gopher_port);
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC1436 Gopher");
