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
 * \brief BBS nodes
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h> /* use calloc */
#include <stdio.h> /* use vasprintf */
#include <unistd.h> /* use close */
#include <string.h> /* use strchr */
#include <ctype.h> /* use tolower */
#include <poll.h>
#include <signal.h> /* use pthread_kill */
#include <math.h> /* use ceil, floor */
#include <sys/ioctl.h>
#include <limits.h>

/* For FreeBSD */
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#include "include/time.h" /* use timespecsub */
#include "include/node.h"
#include "include/user.h"
#include "include/variables.h"
#include "include/term.h"
#include "include/ansi.h"
#include "include/pty.h"
#include "include/menu.h"
#include "include/auth.h"
#include "include/config.h"
#include "include/module.h" /* use bbs_module_unref */
#include "include/utils.h" /* use print_time_elapsed */
#include "include/event.h"
#include "include/notify.h"
#include "include/cli.h"
#include "include/reload.h"

#define DEFAULT_MAX_NODES 64

static int shutting_down = 0;

static RWLIST_HEAD_STATIC(nodes, bbs_node);

/*! \brief Guest login is allowed by default */
#define DEFAULT_ALLOW_GUEST 1

/*! \brief Whether to ask guests for additional details */
#define DEFAULT_GUEST_ASK_INFO 1

static unsigned int maxnodes;
static unsigned int maxnodes_perip;
static unsigned int minuptimedisplayed = 0;
static int allow_guest = DEFAULT_ALLOW_GUEST;
static int guest_ask_info = DEFAULT_GUEST_ASK_INFO; /* 0 = don't ask, 1 = ask if not using TDD, 2 = always ask */
static unsigned int defaultbps = 0;
static unsigned int idlemins = 0;

static unsigned int default_cols = 80;
static unsigned int default_rows = 24;
static int ask_dimensions = 1;

static char bbs_name_buf[32] = "BBS"; /* A simple default so this is never empty. */
static char bbs_tagline_buf[84] = "";
static char bbs_hostname_buf[92] = "";
static char bbs_sysop_buf[16] = "";
static char bbs_exitmsg[484] = "";

static int load_config(void)
{
	char tmp[16];
	struct bbs_config *cfg = bbs_config_load("nodes.conf", 1); /* Use cached version if possible and not stale */

	/* Set some basic defaults, whether there's a config or not */
	maxnodes = DEFAULT_MAX_NODES;
	maxnodes_perip = DEFAULT_MAX_NODES / 2;
	allow_guest = DEFAULT_ALLOW_GUEST;
	guest_ask_info = DEFAULT_GUEST_ASK_INFO;
	defaultbps = 0;
	idlemins = 30;

	if (!cfg) {
		return 0;
	}

	/* Since these are technically static buffers, this memory will always be valid as long as
	 * the BBS is running. Some of these are returned through APIs (e.g. bbs_hostname()),
	 * and as such, we can't feasibly do locking of these variables,
	 * but it's okay since the worst that can happen is we happen to read while
	 * we're updating the buffer, in which case the name may be partially the old and new value.
	 * Now, if we were using bbs_config_val_set_dstr, that would NOT be safe! */

	if (bbs_config_val_set_str(cfg, "bbs", "name", bbs_name_buf, sizeof(bbs_name_buf))) {
		bbs_warning("No name is configured for this BBS in nodes.conf - BBS will be impersonal!\n");
	}
	bbs_config_val_set_str(cfg, "bbs", "tagline", bbs_tagline_buf, sizeof(bbs_tagline_buf));
	bbs_config_val_set_str(cfg, "bbs", "hostname", bbs_hostname_buf, sizeof(bbs_hostname_buf));
	bbs_config_val_set_str(cfg, "bbs", "sysop", bbs_sysop_buf, sizeof(bbs_sysop_buf));
	bbs_config_val_set_uint(cfg, "bbs", "minuptimedisplayed", &minuptimedisplayed);
	bbs_config_val_set_str(cfg, "bbs", "exitmsg", bbs_exitmsg, sizeof(bbs_exitmsg));
	bbs_config_val_set_uint(cfg, "nodes", "maxnodes", &maxnodes);
	bbs_config_val_set_uint(cfg, "nodes", "maxnodesperip", &maxnodes_perip);
	bbs_config_val_set_uint(cfg, "nodes", "defaultbps", &defaultbps);
	bbs_config_val_set_uint(cfg, "nodes", "defaultrows", &default_rows);
	bbs_config_val_set_uint(cfg, "nodes", "defaultcols", &default_cols);
	bbs_config_val_set_true(cfg, "nodes", "askdimensions", &ask_dimensions);
	bbs_config_val_set_uint(cfg, "nodes", "idlemins", &idlemins);
	bbs_config_val_set_true(cfg, "guests", "allow", &allow_guest);
	bbs_config_val_set_true(cfg, "guests", "askinfo", &guest_ask_info);
	if (!bbs_config_val_set_str(cfg, "guests", "askinfo", tmp, sizeof(tmp)) && !strcasecmp(tmp, "always")) {
		guest_ask_info = 2;
	}

	if (!idlemins) {
		idlemins = INT_MAX; /* If 0, disable */
	} else {
		idlemins = idlemins * 60000; /* Convert minutes to milliseconds just once, up front */
	}

	return 0;
}

static int reload_nodes(int fd)
{
	/* Reload without locking, since we technically can */
	load_config();
	bbs_dprintf(fd, "Reloaded node settings\n");
	return 0;
}

int bbs_guest_login_allowed(void)
{
	return allow_guest;
}

unsigned int bbs_node_count(void)
{
	struct bbs_node *node;
	unsigned int count = 0;

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, node, entry) {
		count++;
	}
	RWLIST_UNLOCK(&nodes);

	return count;
}

unsigned int bbs_node_mod_count(void *mod)
{
	struct bbs_node *node;
	unsigned int count = 0;

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, node, entry) {
		if (node->module == mod || node->doormod == mod) {
			count++;
		}
	}
	RWLIST_UNLOCK(&nodes);

	return count;
}

unsigned int bbs_node_ip_count(struct sockaddr_in *sinaddr)
{
	struct bbs_node *node;
	unsigned int count = 0;

	/* XXX This function is implemented this way so that if/when we store
	 * the sockaddr_in for IP addresses rather than char*,
	 * we don't have to make any API changes. For the moment,
	 * yes, this is less efficient since we do more conversions. */
	char addrstr[64];
	if (bbs_get_remote_ip(sinaddr, addrstr, sizeof(addrstr))) {
		return 0;
	}

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, node, entry) {
		if (!strcmp(addrstr, node->ip)) {
			count++;
		}
	}
	RWLIST_UNLOCK(&nodes);

	return count;
}

unsigned int bbs_max_nodenum(void)
{
	struct bbs_node *node;
	unsigned int maxnodenum = 0;

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, node, entry) {
		maxnodenum = node->id;
	}
	RWLIST_UNLOCK(&nodes);

	return maxnodenum;
}

unsigned int bbs_min_uptime_threshold(void)
{
	return minuptimedisplayed;
}

unsigned int bbs_idle_ms(void)
{
	return idlemins;
}

unsigned int bbs_maxnodes(void)
{
	return maxnodes;
}

unsigned int bbs_maxnodes_per_ip(void)
{
	return maxnodes_perip;
}

const char *bbs_hostname(void)
{
	return bbs_hostname_buf;
}

const char *bbs_name(void)
{
	return bbs_name_buf;
}

const char *bbs_tagline(void)
{
	return bbs_tagline_buf;
}

const char *bbs_sysop(void)
{
	return bbs_sysop_buf;
}

static unsigned int lifetime_nodes = 0;

struct bbs_node *__bbs_node_request(int fd, const char *protname, struct sockaddr_in *restrict sinaddr, int sfd, void *mod)
{
	struct bbs_node *node = NULL, *prev = NULL;
	unsigned int count = 0;
	unsigned int newnodenumber = 1, keeplooking = 1;

	if (unlikely(fd <= 2)) { /* Should not be STDIN, STDOUT, or STDERR, or negative */
		bbs_error("Invalid file descriptor for BBS node: %d\n", fd); /* This would happen if a bug results in calling close on 0, 1, or 2 */
		return NULL;
	}

	if (shutting_down) {
		/* On the small chance we get a connection between when bbs_node_shutdown_all is called
		 * but before I/O modules are unloaded, bail now. */
		bbs_warning("Declining node allocation due to active shutdown\n");
		return NULL;
	}

	/* We want to allocate a node with the smallest node number available.
	 * Additionally, we should refuse if we have hit bbs_maxnodes().
	 * Remember that node IDs are 1-indexed.
	 */

	RWLIST_WRLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, node, entry) {
		count++;
		if (keeplooking) {
			if (node->id == newnodenumber) {
				/* Keep looking. */
				newnodenumber++;
				prev = node;
			} else {
				bbs_assert(node->id > newnodenumber);
				/* The node->id is greater than newnodenumber. So we've found the smallest available node ID. */
				keeplooking = 0;
			}
		}
	}
	if (count >= bbs_maxnodes()) { /* Nodes are at capacity. */
		bbs_warning("Node request failed since we currently have %d active nodes\n", count);
		RWLIST_UNLOCK(&nodes);
		return NULL;
	}

	node = calloc(1, sizeof(*node));
	if (ALLOC_FAILURE(node)) {
		RWLIST_UNLOCK(&nodes);
		return NULL;
	}

	if (sinaddr) {
		if (bbs_save_remote_ip(sinaddr, node)) {
			free(node);
			RWLIST_UNLOCK(&nodes);
			return NULL;
		}
	} else {
		node->ip = strdup("127.0.0.1"); /* Connection is from localhost */
		if (ALLOC_FAILURE(node->ip)) {
			free(node);
			RWLIST_UNLOCK(&nodes);
			return NULL;
		}
	}

	bbs_mutex_init(&node->lock, NULL);
	bbs_mutex_init(&node->ptylock, NULL);
	node->id = newnodenumber;
	node->fd = fd;
	/* By default, same file descriptor for reading and writing.
	 * These may differ when directly interacting with a TLS session,
	 * due to the way that TLS relaying is implemented in the BBS. */
	node->rfd = node->wfd = fd;

	/* By default, the socket file descriptor is the same as the regular file descriptor.
	 * Only net_ssh overrides this. */
	node->sfd = sfd != -1 ? sfd : fd;

	/* Not all nodes will get a pseudoterminal, so initialize to -1 so if not, we don't try to close STDIN erroneously on shutdown */
	node->amaster = -1;
	node->slavefd = -1;

	node->spyfd = -1;
	node->spyfdin = -1;

	node->user = NULL; /* No user exists yet. We calloc'd so this is already NULL, but this documents that user may not exist at first. */
	node->active = 1;
	node->created = time(NULL);

	node->protname = protname;
	node->ansi = 1; /* Assume nodes support ANSI escape sequences by default. */

	/* Assume 80x24 terminal by default, for interactive nodes,
	 * to support dumb terminals over modems that won't tell us their size. */
	node->cols = default_cols;
	node->rows = default_rows;

	/* This prevents this module from being unloaded as long as there are nodes using it.
	 * For example, since node->protname is constant in this module, if we unload it,
	 * even though no code is being executed in the module actively, if we list nodes,
	 * then we'll crash since node->protname isn't valid memory anymore.
	 * Yes, sure we could copy the string instead of storing a reference, but that's not the point.
	 * Nodes should increment the ref count of the module, which will force disconnecting
	 * relevant nodes before we attempt to unload or reload the module.
	 */
	node->module = mod;
	bbs_module_ref(mod, 1);

	if (prev) {
		RWLIST_INSERT_AFTER(&nodes, prev, node, entry); /* Insert at the appropriate index. */
	} else {
		RWLIST_INSERT_HEAD(&nodes, node, entry); /* This is the first node. */
	}
	node->lifetimeid = ++lifetime_nodes; /* Starts at 0 so increment first before assigning */
	bbs_io_session_register(&node->trans, TRANSFORM_SESSION_NODE, node);
	RWLIST_UNLOCK(&nodes);

	bbs_debug(1, "Allocated new node with ID %u (lifetime ID %d)\n", node->id, node->lifetimeid);
	return node;
}

int __bbs_node_lock(struct bbs_node *node, const char *file, int lineno, const char *func, const char *lockname)
{
	bbs_assert_exists(node);
	return __bbs_mutex_lock(&node->lock, file, lineno, func, lockname);
}

int __bbs_node_trylock(struct bbs_node *node, const char *file, int lineno, const char *func, const char *lockname)
{
	bbs_assert_exists(node);
	return __bbs_mutex_trylock(&node->lock, file, lineno, func, lockname);
}

int bbs_node_unlock(struct bbs_node *node)
{
	bbs_assert_exists(node);
	return bbs_mutex_unlock(&node->lock);
}

int __bbs_node_pty_lock(struct bbs_node *node, const char *file, int lineno, const char *func, const char *lockname)
{
	bbs_assert_exists(node);
	return __bbs_mutex_lock(&node->ptylock, file, lineno, func, lockname);
}

int bbs_node_pty_unlock(struct bbs_node *node)
{
	bbs_assert_exists(node);
	return bbs_mutex_unlock(&node->ptylock);
}

char bbs_node_input_translate(struct bbs_node *node, char c)
{
	char ret = c;

	bbs_node_lock(node);
	if (node->ioreplaces) {
		long unsigned int i;
		for (i = 0; i < ARRAY_LEN(node->ioreplace); i++) {
			if (node->ioreplace[i][0] == c) {
				ret = node->ioreplace[i][1];
				bbs_debug(6, "Translating %c (%d) to %c (%d)\n", c, c, ret, ret);
				break;
			}
		}
	}
	bbs_node_unlock(node);
	return ret;
}

int bbs_node_input_replace(struct bbs_node *node, char in, char out)
{
	long unsigned int i;
	int res = -1;

	bbs_node_lock(node);
	/* Make sure it's not already being replaced */
	for (i = 0; i < ARRAY_LEN(node->ioreplace); i++) {
		if (node->ioreplace[i][0] == in) {
			bbs_error("Character '%c' (%d) is currently being replaced by %c (%d)\n", in, in, node->ioreplace[i][1], node->ioreplace[i][1]);
			bbs_node_unlock(node);
			return -1;
		}
	}

	for (i = 0; i < ARRAY_LEN(node->ioreplace); i++) {
		if (!node->ioreplace[i][0]) {
			node->ioreplace[i][0] = in;
			node->ioreplace[i][1] = out;
			res = 0;
			node->ioreplaces++;
			break;
		}
	}
	bbs_node_unlock(node);
	if (res) {
		bbs_error("Character replacement table for node %d is full\n", node->id);
	}
	return res;
}

int bbs_node_input_unreplace(struct bbs_node *node, char in)
{
	long unsigned int i;
	int res = -1;

	bbs_node_lock(node);
	for (i = 0; i < ARRAY_LEN(node->ioreplace); i++) {
		if (node->ioreplace[i][0] == in) {
			node->ioreplace[i][0] = 0;
			node->ioreplace[i][1] = 0;
			res = 0;
			node->ioreplaces--;
			break;
		}
	}
	bbs_node_unlock(node);
	if (res) {
		bbs_error("Character '%c' (%d) is not currently being translated\n", in, in);
	}
	return res;
}

int bbs_node_safe_sleep(struct bbs_node *node, int ms)
{
	struct pollfd pfd;
	int res;

	bbs_soft_assert(ms > 0);
	if (ms < 0) {
		ms = 0;
	}

	bbs_debug(6, "Sleeping on node %d for %d ms\n", node->id, ms);
	/* We're polling the raw socket fd since that's closed if node is kicked (or at shutdown),
	 * and that's all we care about here. We're not actually doing any I/O on this fd.
	 * Avoid using bbs_poll because we don't care about (and shouldn't be affected by) POLLIN.
	 * This thus allows this to function like a sleep operation, interrupted only if the remote
	 * client disconnects or is disconnected. */
	pfd.fd = node->fd;
	pfd.events = POLLPRI | POLLERR | POLLHUP | POLLNVAL; /* Don't include POLLIN, we don't care about data sent by client */
	pfd.revents = 0;

	res = poll(&pfd, 1, ms);
	if (res) {
		bbs_debug(5, "Node %d sleep interrupted: poll returned %d\n", node->id, res);
	}
	return res;
}

static int kill_pid(pid_t *pidptr)
{
	int i;
	pid_t pid = *pidptr;

	/* Executing an external process? Kill it, so the node thread (which is the thread waiting on it) can return.
	 * First, try politely, but get aggressive if we have to.
	 * Remember that there's already another thread waiting on the child in system.c.
	 * It's not our job to wait on the child, the thread that called fork() is doing that right now.
	 */

	/* Send a SIGINT first, in case that will effect an exit. */
	if (kill(pid, SIGINT)) {
		bbs_error("kill failed: %s\n", strerror(errno));
	}
	for (i = 0; *pidptr && i < 25; i++) {
		/* In practice, even 1 us is enough time for this to work.
		 * But if some reason it takes longer,
		 * keep trying for a little bit with exponential backoff. */
		usleep((unsigned int) i + 1);
	}
	/* Next, try a SIGTERM */
	if (*pidptr) {
		if (kill(pid, SIGTERM)) {
			bbs_error("kill failed: %s\n", strerror(errno));
		}
		/* Just to make sure, see if it really died. */
		for (i = 0; *pidptr && i < 25; i++) {
			usleep((unsigned int) i + 1);
		}
		/* If node->childpid is still set, then send a SIGKILL and get on with it. */
		if (*pidptr) {
			if (kill(pid, SIGKILL)) {
				bbs_error("kill failed: %s\n", strerror(errno));
			}
			/* Just to make sure, see if it really died. */
			for (i = 0; *pidptr && i < 25; i++) {
				usleep((unsigned int) i + 1);
			}
			if (*pidptr) {
				bbs_error("Child process %d has not exited yet?\n", pid);
				return -1;
			} else {
				bbs_debug(3, "Killed child process %d using SIGKILL after %d iterations\n", pid, i);
			}
		} else {
			bbs_debug(3, "Killed child process %d using SIGINT after %d iterations\n", pid, i);
		}
	} else {
		bbs_debug(3, "Killed child process %d using SIGINT after %d iterations\n", pid, i);
	}
	return 0;
}

int bbs_node_kill_child(struct bbs_node *node)
{
	if (node->childpid) {
		return kill_pid(&node->childpid);
	}
	return -1;
}

int bbs_node_logout(struct bbs_node *node)
{
	bbs_user_destroy(node->user);
	node->user = NULL;
	return 0;
}

static void node_shutdown(struct bbs_node *node, int unique)
{
	pthread_t node_thread;
	unsigned int nodeid;
	int skipjoin;
	time_t now;
	int wasloggedin = 0;

	/* Prevent node from being freed until we release the lock. */
	bbs_node_lock(node);
	if (!node->active) {
		bbs_error("Attempt to shut down already inactive node %d?\n", node->id);
		bbs_node_unlock(node);
		return;
	}
	node->active = 0;
	bbs_debug(2, "Terminating node %d\n", node->id);

	now = time(NULL);

	bbs_io_teardown_all_transformers(&node->trans);
	bbs_io_session_unregister(&node->trans);

	bbs_node_kill_child(node);

	/* Destroy the user */
	if (node->user) {
		wasloggedin = 1;
		bbs_node_logout(node);
	}

	/* If the node is still connected, be nice and reset it. If it's gone already, forget about it. */
	if (node->slavefd != -1) {
		/* Restore the terminal on node exit: re-enable canonical mode and re-enable echo. */
		bbs_node_buffer_input(node, 1);
		/* Be nice and try to reset its color.
		 * No need to go through the psuedoterminal for this. If it fails, then it didn't matter anyways.
		 * Don't use bbs_node_reset_color because we already hold the node lock, so we can't call bbs_node_write,
		 * as that will try to get a recursive lock.
		 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
		SWRITE(node->wfd, COLOR_RESET); /* Node is already locked, don't use NODE_SWRITE */
#pragma GCC diagnostic pop
	}

	if (node->ptythread) {
		if (node->amaster != -1) {
			bbs_socket_close(&node->amaster);
		}
		if (node->slavefd != -1) {
			bbs_socket_close(&node->slavefd);
		}
		bbs_pthread_join(node->ptythread, 0); /* Wait for the PTY master thread to exit, and then clean it up. */
		if (node->spy) {
			/* The sysop was spying on this node when it got disconnected.
			 * Let the sysop know this node is dead. */
			bbs_dprintf(node->spyfd, COLOR_RESET "\nNode %d has disconnected.\nPress ^C to exit spy mode.\n", node->id);
			bbs_node_pty_lock(node);
			node->spy = 0;
			bbs_node_pty_unlock(node);
		}
	} else {
		bbs_debug(8, "Node %u has no PTY thread to clean up\n", node->id);
	}

	if (node->fd != -1) {
		bbs_socket_close(&node->fd);
	}

	node_thread = node->thread;
	nodeid = node->id;
	skipjoin = node->skipjoin;

	if (!wasloggedin && !shutting_down && now < node->created + 5) {
		bbs_event_dispatch(node, EVENT_NODE_SHORT_SESSION);
	}

	/* After we release the lock, node could be freed, so don't keep any references to it. */
	bbs_node_unlock(node);

	if (!unique) {
		/* node is now no longer a valid reference, since bbs_node_handler calls node_free (in another thread) before it quits. */
		if (skipjoin) {
			bbs_debug(3, "Skipping join of node %d thread %lu\n", nodeid, (unsigned long) node_thread);
		} else if (node_thread) { /* Either bbs_node_handler thread is detached, or somebody else is joining it */
			bbs_debug(3, "Waiting for node %d to exit\n", nodeid);
			bbs_pthread_join(node_thread, NULL); /* Wait for the bbs_node_handler thread to exit, and then clean it up. */
		} else {
			bbs_debug(3, "Node %d has no associated thread\n", nodeid);
		}
	} else {
		/* node_thread is what called this, so don't join ourself.
		 * The node owning thread will free it subsequently. */
		bbs_debug(3, "Shutdown pending finalization for node %u\n", nodeid);
	}
}

static void node_free(struct bbs_node *node)
{
	/* Wait for node_shutdown to release lock. */
	bbs_node_lock(node);
	if (node->module) {
		bbs_module_unref(node->module, 1);
		node->module = NULL;
	}
	if (node->vars) {
		bbs_vars_destroy(node->vars);
		FREE(node->vars); /* Free the list itself */
	}
	free_if(node->ip);
	free_if(node->term);
	bbs_debug(4, "Node %d now freed\n", node->id);
	bbs_verb(3, "Node %d has exited\n", node->id);
	bbs_node_unlock(node);
	bbs_mutex_destroy(&node->lock);
	bbs_mutex_destroy(&node->ptylock);
	free(node);
}

int bbs_node_unlink(struct bbs_node *node)
{
	struct bbs_node *n;

	RWLIST_WRLOCK(&nodes);
	n = RWLIST_REMOVE(&nodes, node, entry);
	RWLIST_UNLOCK(&nodes);

	if (!n) {
		/* If bbs_node_shutdown_all was used, nodes are removed from the list
		 * but not freed there. */
		bbs_debug(1, "Node %d was already unlinked, freeing directly\n", node->id);
	} else {
		node_shutdown(node, 1);
	}

	/* If unlinking a single node, also free here */
	node_free(node);
	return 0;
}

int bbs_node_shutdown_node(unsigned int nodenum)
{
	struct bbs_node *n;

	RWLIST_WRLOCK(&nodes);
	n = RWLIST_REMOVE_BY_FIELD(&nodes, id, nodenum, entry);
	if (n) {
		/* Wait for shutdown of node to finish. */
		node_shutdown(n, 0);
	} else {
		bbs_error("Node %d not found in node list?\n", nodenum);
	}
	RWLIST_UNLOCK(&nodes);

	return n ? 0 : -1;
}

static int interrupt_node(struct bbs_node *node)
{
	int res = -1;
	if (!node->thread) {
		bbs_debug(1, "Node %u is not owned by a thread, and cannot be interrupted\n", node->id);
	} else if (!node->slavefd) {
		/* If there's no PTY, bbs_node_poll can't be used anyways.
		 * And if there's no PTY, it's a network protocol that doesn't make sense to interrupt.
		 * Only terminal protocols should be interrupted. */
		bbs_debug(1, "Node %u has no PTY\n", node->id);
	} else {
		int err;
		/* The node thread should never interrupt itself, this is only for other threads to
		 * interrupt a blocking I/O call. */
		bbs_assert(node->thread != pthread_self());
		node->interruptack = 0;
		node->interrupt = 1; /* Indicate that interrupt was requested */

		bbs_node_kill_child(node); /* If executing an external program, kill it */

		/* Make the I/O function (probably poll(2)) exit with EINTR.
		 * Less overhead than always polling another alertpipe just for getting out of band alerts like this,
		 * since we can easily enough check the interrupt status in the necessary places on EINTR. */
		err = pthread_kill(node->thread, SIGUSR1); /* Uncaught signal, so the blocking I/O call will get interrupted */
		if (err) {
			bbs_warning("pthread_kill(%lu) failed: %s\n", (unsigned long) node->thread, strerror(err));
			bbs_node_unlock(node);
			return 1;
		}

		if (node->buffered) {
			/* Since the pseudoterminal is buffered, poll won't return any activity at all
			 * until a buffered line has been received.
			 * Spoof an ENTER on the master side of the PTY towards the slave, since
			 * we'll just throw away whatever the slave receives anyways. */
			bbs_debug(1, "Node %u is currently buffered, spoofing line return on slave\n", node->id);
			if (SWRITE(node->amaster, "\n") < 0) {
				bbs_warning("Failed to write to master side to wake up buffered poll: %s\n", strerror(errno));
			}
		}

		bbs_verb(5, "Interrupted node %u\n", node->id);
		res = 0;
	}
	return res;
}

unsigned int bbs_node_shutdown_mod(void *mod)
{
	struct bbs_node *n;
	unsigned int count = 0;

	RWLIST_WRLOCK(&nodes);
	RWLIST_TRAVERSE_SAFE_BEGIN(&nodes, n, entry) {
		if (n->doormod == mod) {
			int res;
			/* "Dump" any nodes executing door modules from their current door.
			 * We don't need to kick these nodes, just interrupt them. */
			bbs_verb(5, "Interrupting node %u to allow %s to unload\n", n->id, bbs_module_name(mod));
			/* Can't use bbs_interrupt_node since that will call bbs_node_get,
			 * which invokes a RDLOCK on the node list.
			 * Since we already hold a WRLOCK, that would cause a deadlock.
			 * Instead, use interrupt_node directly. */
			bbs_node_lock(n);
			res = interrupt_node(n);
			bbs_node_unlock(n);
			/* Wait for this node to exit the door */
			if (!res && bbs_node_interrupt_wait(n, 250)) { /* Don't wait more than 250 ms for the node to exit the door */
				count++;
			}
		} else if (n->module == mod) {
			/* Kill any nodes that might be using a particular network module;
			 * since they created the node and "own it", we can't unload them
			 * without killing all their nodes. */
			RWLIST_REMOVE_CURRENT(entry);
			/* Wait for shutdown of node to finish. */
			bbs_verb(5, "Kicking node %u to allow %s to unload\n", n->id, bbs_module_name(mod));
			node_shutdown(n, 0);
			count++;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&nodes);

	return count;
}

#define node_shutdown_nonunique(n) node_shutdown(n, 0)

int bbs_node_shutdown_all(int shutdown)
{
	RWLIST_WRLOCK(&nodes);
	shutting_down = shutdown;
	RWLIST_REMOVE_ALL(&nodes, entry, node_shutdown_nonunique); /* Wait for shutdown of each node to finish. */
	RWLIST_UNLOCK(&nodes);
	bbs_debug(1, "All nodes have been shut down\n");
	return 0;
}

static int cli_nodes(struct bbs_cli_args *a)
{
	char elapsed[24];
	struct bbs_node *n;
	int c = 0;
	time_t now = time(NULL);

	bbs_dprintf(a->fdout, "%3s %9s %9s %-15s %-25s"
		" %15s %5s %7s %3s %3s %3s %3s"
		" %3s %3s %3s"
		" %1s %1s %1s"
		" %7s %8s %4s %5s %6s %6s %4s"
		"\n",
		"#", "PROTOCOL", "ELAPSED", "USER", "MENU/PAGE/LOCATION",
		"IP ADDRESS", "RPORT", "TID", "SFD", "FD", "RFD", "WFD",
		"MST", "SLV", "SPY",
		"E", "B", "!",
		"TRM SZE", "TYPE", "ANSI", "SPEED", "BPS", "(RPT)", "SLOW");

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, n, entry) {
		char menufull[26];
		char termsize[8];
		char speed[NODE_SPEED_BUFSIZ_SMALL];
		int lwp;
		/* Do not lock the node here.
		 * Even though we are accessing some properties of the node which could change,
		 * because the node list is locked, there is no possibility of the node itself
		 * disappearing out from underneath us.
		 * Because most of the I/O done in the BBS is blocking, if a BBS node is blocked
		 * in a write, nodes could be blocked for very long times, and if any thread
		 * besides the node thread tries to write to it, that could cause that thread to
		 * block waiting on the lock, causing a cascading deadlock. */
		print_time_elapsed(n->created, now, elapsed, sizeof(elapsed));
		snprintf(menufull, sizeof(menufull), "%s%s%s%s", S_IF(n->menu), n->menuitem ? " (" : "", S_IF(n->menuitem), n->menuitem ? ")" : "");
		lwp = bbs_pthread_tid(n->thread);

		bbs_dprintf(a->fdout, "%3d %9s %9s %-15s %-25s"
			" %15s %5u %7d %3d %3d %3d %3d",
			n->id, n->protname, elapsed, bbs_username(n->user), menufull,
			n->ip, n->rport, lwp, n->sfd, n->fd, n->rfd, n->wfd);
		if (NODE_INTERACTIVE(n)) {
			/* If the size is speculative, put a '?' afterwards */
			snprintf(termsize, sizeof(termsize), "%dx%d%s", n->cols, n->rows, n->dimensions ? "" : "?");
			bbs_node_format_speed(n, speed, sizeof(speed));
			bbs_dprintf(a->fdout,
				" %3d %3d %3d"
				" %1s %1s %1s"
				" %7s %8s %4s %5s %6u %6u %4s"
				"\n",
				n->amaster, n->slavefd, n->spyfd,
				BBS_YN(n->echo), BBS_YN(n->buffered), bbs_node_interrupted(n) ? "*" : "",
				termsize, S_IF(n->term), BBS_YESNO(n->ansi), speed, n->bps, n->reportedbps, BBS_YN(n->slow));
		} else {
			bbs_dprintf(a->fdout, "\n");
		}
		c++;
	}
	RWLIST_UNLOCK(&nodes);

	bbs_dprintf(a->fdout, "%d active node%s, %u lifetime node%s\n", c, ESS(c), lifetime_nodes, ESS(lifetime_nodes));
	return 0;
}

int bbs_interrupt_node(unsigned int nodenum)
{
	int res;
	struct bbs_node *node = bbs_node_get(nodenum);

	if (!node) {
		return -1;
	}

	res = interrupt_node(node);

	bbs_node_unlock(node);
	return res;
}

void __bbs_node_interrupt_ack(struct bbs_node *node, const char *file, int line, const char *func)
{
	bbs_assert(node->thread == pthread_self());
	__bbs_log(LOG_DEBUG, 2, file, line, func, "Node %u acknowledged interrupt\n", node->id);
	node->interruptack = 1;
}

void bbs_node_interrupt_clear(struct bbs_node *node)
{
	node->interrupt = 0;
	/* The interrupt should've been acknowledged (e.g. if poll was interrupted),
	 * but it's entirely possible the node might have returned without ever calling poll,
	 * in which case it might never have been acknowledged.
	 * As far as the node thread is concerned, this doesn't matter.
	 * Currently, we do nothing based on the value of this variable, but we may in the future... */
	node->interruptack = 0;
}

int bbs_node_interrupted(struct bbs_node *node)
{
	return node->interrupt;
}

int bbs_node_interrupt_wait(struct bbs_node *node, int ms)
{
	int elapsed = 0;

	for (;;) {
		if (!bbs_node_interrupted(node)) {
			/* Interrupt was cleared */
			return 1;
		}
		/* XXX Ideally, we would use an alertpipe or something
		 * of the sort, to avoid the need to poll for interrupt clear. */
		usleep(10000); /* Wait 10 ms */
		elapsed += 10;
		if (ms > 0 && elapsed >= ms) {
			return 0;
		}
	}
	__builtin_unreachable();
}

static int cli_interrupt(struct bbs_cli_args *a)
{
	int res, node = atoi(a->argv[1]);
	if (node <= 0) {
		bbs_dprintf(a->fdout, "Invalid node %s\n", a->argv[1]);
		return -1;
	}
	res = bbs_interrupt_node((unsigned int) node);
	bbs_dprintf(a->fdout, "%s node %d\n", res ? "Failed to interrupt" : "Successfully interrupted", node);
	return res;
}

static int cli_kick(struct bbs_cli_args *a)
{
	int node = atoi(a->argv[1]);
	if (node <= 0) {
		bbs_dprintf(a->fdout, "Invalid node %s\n", a->argv[1]);
		return -1;
	}
	return bbs_node_shutdown_node((unsigned int) node);
}

static int cli_kickall(struct bbs_cli_args *a)
{
	UNUSED(a);
	return bbs_node_shutdown_all(0);
}

static int node_info(int fd, unsigned int nodenum)
{
	char elapsed[24];
	char connecttime[29];
	struct bbs_node *n;
	char menufull[16];
	time_t now = time(NULL);

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, n, entry) {
		if (n->id == nodenum) {
			break;
		}
	}
	if (!n) {
		RWLIST_UNLOCK(&nodes);
		bbs_dprintf(fd, "Node %d is not currently in use\n", nodenum);
		return 0;
	}

	print_time_elapsed(n->created, now, elapsed, sizeof(elapsed));
	bbs_time_friendly(n->created, connecttime, sizeof(connecttime));
	snprintf(menufull, sizeof(menufull), "%s%s%s%s", S_IF(n->menu), n->menuitem ? " (" : "", S_IF(n->menuitem), n->menuitem ? ")" : "");

#define BBS_FMT_S "%-20s : %s\n"
#define BBS_FMT_D "%-20s : %d\n"
#define BBS_FMT_DSDS "%-20s : %d%s%d%s\n"

/* This addresses the desire to be able to do something like this:
 * bbs_dprintf(fd, n->childpid ? BBS_FMT_D : BBS_FMT_S, "CHILD PID", n->childpid ? n->childpid : "None");
 * Unfortunately, you can't do that since it's mixing types.
 * Et voila, here is a helper macro to make this less painful.
 */
#define PRINT_D_OR_S(fd, title, var, fallback) \
	if (var) { \
		bbs_dprintf(fd, BBS_FMT_D, title, var); \
	} else { \
		bbs_dprintf(fd, BBS_FMT_S, title,fallback); \
	}

	bbs_mutex_lock(&n->lock);
	bbs_dprintf(fd, BBS_FMT_D, "#", n->id);
	bbs_dprintf(fd, BBS_FMT_D, "Lifetime #", n->lifetimeid);
	bbs_dprintf(fd, BBS_FMT_S, "Protocol", n->protname);
	bbs_dprintf(fd, BBS_FMT_S, "IP Address", n->ip);
	bbs_dprintf(fd, BBS_FMT_S, "Connected", connecttime);
	bbs_dprintf(fd, BBS_FMT_S, "Elapsed", elapsed);

	if (NODE_INTERACTIVE(n)) {
		char speed[NODE_SPEED_BUFSIZ_LARGE];
		bbs_node_format_speed(n, speed, sizeof(speed));
		bbs_dprintf(fd, BBS_FMT_DSDS, "Term Size", n->cols, "x", n->rows, n->dimensions ? "" : "?");
		bbs_dprintf(fd, BBS_FMT_S, "Term Type", S_IF(n->term));
		bbs_dprintf(fd, BBS_FMT_S, "Term ANSI", BBS_YN(n->ansi));
		bbs_dprintf(fd, BBS_FMT_S, "Term Speed (Measured)", speed);
		bbs_dprintf(fd, BBS_FMT_D, "Term Speed (Reported)", n->reportedbps);
		bbs_dprintf(fd, BBS_FMT_S, "Term Echo", BBS_YN(n->echo));
		bbs_dprintf(fd, BBS_FMT_S, "Term Buffered", BBS_YN(n->buffered));
	}

	bbs_dprintf(fd, BBS_FMT_D, "Node Network FD", n->sfd);
	bbs_dprintf(fd, BBS_FMT_D, "Node Read FD", n->rfd);
	bbs_dprintf(fd, BBS_FMT_D, "Node Write FD", n->wfd);
	bbs_dprintf(fd, BBS_FMT_D, "Node PTY Master FD", n->amaster);
	bbs_dprintf(fd, BBS_FMT_D, "Node PTY Slave FD", n->slavefd);
	bbs_dprintf(fd, BBS_FMT_S, "Node PTY Slave Name", n->slavename);
	bbs_dprintf(fd, BBS_FMT_D, "Node PTY Thread ID", bbs_pthread_tid(n->ptythread));
	bbs_dprintf(fd, BBS_FMT_D, "Node Thread ID", bbs_pthread_tid(n->thread));
	bbs_dprintf(fd, BBS_FMT_S, "User", bbs_username(n->user));
	if (bbs_user_is_guest(n->user)) {
		bbs_dprintf(fd, BBS_FMT_S, "Guest Name/Alias",  S_IF(n->user->guestname));
		bbs_dprintf(fd, BBS_FMT_S, "Guest EMail",  S_IF(n->user->guestemail));
		bbs_dprintf(fd, BBS_FMT_S, "Guest Location",  S_IF(n->user->guestlocation));
	} else if (bbs_user_is_registered(n->user)) {
		bbs_dprintf(fd, BBS_FMT_S, "Email", bbs_user_email(n->user));
	}
	bbs_dprintf(fd, BBS_FMT_S, "Menu/Page", menufull);
	bbs_dprintf(fd, BBS_FMT_D, "Menu Level", n->menustack);
	PRINT_D_OR_S(fd, "Child PID", n->childpid, "None");
	PRINT_D_OR_S(fd, "Speed (BPS)", n->speed, "Unthrottled");
	bbs_dprintf(fd, BBS_FMT_S, "Shutting Down", BBS_YN(!n->active));
	bbs_node_vars_dump(fd, n);
	bbs_mutex_unlock(&n->lock);

#undef BBS_FMT_S
#undef BBS_FMT_D
#undef BBS_FMT_DSD

	RWLIST_UNLOCK(&nodes);
	return 0;
}

static int cli_node(struct bbs_cli_args *a)
{
	int node = atoi(a->argv[1]);
	if (node <= 0) {
		bbs_dprintf(a->fdout, "Invalid node %s\n", a->argv[1]);
		return -1;
	}
	return node_info(a->fdout, (unsigned int) node);
}

int bbs_user_online(unsigned int userid)
{
	struct bbs_node *n;

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, n, entry) {
		if (n->user && n->user->id == userid) {
			break;
		}
	}
	RWLIST_UNLOCK(&nodes);

	return n ? 1 : 0;
}

struct bbs_node *bbs_node_get(unsigned int nodenum)
{
	struct bbs_node *n;

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, n, entry) {
		if (n->id == nodenum) {
			break;
		}
	}
	if (n) {
		bbs_mutex_lock(&n->lock);
	}
	RWLIST_UNLOCK(&nodes);
	return n;
}

int bbs_node_update_winsize(struct bbs_node *node, int cols, int rows)
{
	struct winsize ws;
	pid_t child;
	unsigned int oldcols = node->cols, oldrows = node->rows;

	if (bbs_is_shutting_down()) {
		bbs_debug(3, "Declining to update node dimensions due to active shutdown\n");
		return -1;
	}

	if (rows >= 0 && cols >= 0) {
		bbs_debug(3, "Node %d's terminal now has %d cols and %d rows\n", node->id, cols, rows);
		/* If this were a program that had forked and had children, then we might send a SIGWINCH.
		 * But we're not, so we don't. The menu and terminal routines will simply check cols/rows
		 * when drawing menus or other things on the screen.
		 */
		node->cols = (unsigned int) cols;
		node->rows = (unsigned int) rows;
		node->dimensions = 1;
	}

	/*
	 * Ah, yes, SIGWINCH.
	 * In general, we actually don't send a SIGWINCH (manually or by using ioctl).
	 * TIOCSWINSZ is used to set the current window size (send SIGWINCH)
	 * TIOCGWINSZ is used to get the current window size (i.e. after receiving a SIGWINCH signal)
	 *
	 * Since the BBS runs as a single process for all nodes,
	 * there isn't any handling of the SIGWINCH signal itself in the BBS.
	 * We simply check the node's dimensions whenever we need them.
	 * However, if the node is currently executing an external program (another process),
	 * then do actually pass it on.
	 */
	bbs_node_lock(node);
	child = node->childpid;
	bbs_node_unlock(node);

	memset(&ws, 0, sizeof(ws));
	ws.ws_row = (short unsigned int) node->rows;
	ws.ws_col = (short unsigned int) node->cols;

	if (node->amaster == -1) {
		bbs_debug(3, "Skipping TIOCSWINSZ for winsize on node %d (no active PTY allocation)\n", node->id);
		return 0;
	}

	/* Do TIOCSWINSZ call on the master PTY fd, so that the slave gets the SIGWINCH,
	 * since the external process's STDIN/STDOUT would be connected to the slave right now.
	 * Even if there's no child currently, always call TIOCSWINSZ on the PTY when there's
	 * a window resize. Don't worry, the main BBS process doesn't get a SIGWINCH when this happens,
	 * there is a handler in bbs.c for SIGWINCH and it's never triggered by nodes resizing, only the
	 * foreground sysop console.
	 *
	 * Because we don't do a TIOCSWINSZ when there's no child process, if/when we do execute
	 * a child using the node's PTY, then system.c forces a SIGWINCH after fork() but before exec()
	 * from the parent so that the PTY and the child have the current dimensions at that point.
	 * We don't always do this here, even when there's no child, because doing that can occasionally
	 * lead to this process getting SIGWINCHes, and if we SIGWINCH ourselves, and we have a foreground
	 * console, then if the sysop were to exit the BBS, the terminal dimensions will be all wrong,
	 * since they'll be the terminal dimensions of whatever node last resized its window! Yikes!
	 *
	 * If there's actually a child executing, then we'll finish it off by sending a SIGWINCH
	 * signal to the child so it can fetch the new window size. This is necessary if there is a child,
	 * or otherwise the new dimensions will be available but the TIOCSWINSZ on its own doesn't actually
	 * cause a signal to go to the child.
	 * (The code in system.c that calls tcsetpgrp isn't necessary to make SIGWINCH work for direct children,
	 *  but we do need to set the controlling terminal there, e.g. for job control to work when launching a shell).
	 */

	if (child) {
		/* Only do TIOCSWINSZ when there's a child, or otherwise the other end of the PTY will end up
		 * being this process, potentially SIGWINCHing ourselves on the off-chance this does produce a SIGWINCH at all. */
		if (ioctl(node->amaster, TIOCSWINSZ, &ws)) {
			bbs_error("TIOCSWINSZ failed for fd %d: %s\n", node->amaster, strerror(errno));
		}

		/* If node->child is actually 0 again due to a race condition, this won't do anything anyways, so it doesn't hurt per se */
		bbs_debug(3, "Sending SIGWINCH to foreground process %d for node %d\n", child, node->id);
		/* For some reason, just doing the TIOCSWINSZ isn't sufficient to actually send the SIGWINCH.
		 * Finish it off by doing it manually.
		 * XXX Sometimes, we get 2 SIGWINCHes in the child, suggesting that sometimes the TIOCSWINSZ alone
		 * is sufficient, but not always (and usually not), which is why we always call kill() here.
		 * It's not consistent, for example, executing the demo sigwinch program, sometimes the first few resizes
		 * will result in duplicates, and then there won't be some but it'll be kind of random.
		 * An extra SIGWINCH isn't ideal but it's not a big deal either.
		 * Better too many than too few. */
		if (kill(child, SIGWINCH)) {
			bbs_error("SIGWINCH failed: %s\n", strerror(errno));
		}
	} else if (node->inmenu) {
		/* Currently displaying a menu. */
		/* If the menu size changed significantly, in particular, if it got SMALLER,
		 * and particularly in the horizontal direction, then we should redraw the menu.
		 * If it shrunk vertically, the only way we can redraw the menu to show the options
		 * better would be if there are more columns now.
		 */
#ifdef CONSERVATIVE_RESIZE
		if (node->cols < oldcols || (node->rows < oldrows && node->cols > oldcols)) {
#else
		if (node->cols != oldcols) {
#endif
			char c = MENU_REFRESH_KEY;
			bbs_debug(5, "Screen size has changed (%dx%d -> %dx%d) such that a menu redraw is warranted\n", oldcols, oldrows, cols, rows);
			/* Don't even need an alertpipe - we know that we're in bbs_node_tread in the menu, spoof a special control char as input. */
			if (!node->buffered) {
				ssize_t wres = write(node->amaster, &c, 1);
				if (wres != 1) {
					bbs_error("Screen refresh failed for node %d (fd %d)\n", node->id, node->amaster);
				}
			} else {
				/* If input buffered, control key won't be received immediately */
				bbs_error("In menu but input is buffered?\n");
			}
		}
	}

	return 0;
}

unsigned int bbs_node_speed(struct bbs_node *node)
{
	/* If we are explicitly throttling the node,
	 * then that is the speed. */
	if (node->bps) {
		return node->bps;
	}

	/* If we measured the connection speed earlier and believe
	 * it to be reasonably slow, use that.
	 * These measurements are not the most accurate,
	 * but should be roughly in the right neighborhood, much of the time. */
	if (node->calcbps > 1 && node->calcbps <= 64000) {
		return (unsigned int) node->calcbps;
	}

	/* If the client told us its terminal speed, use that as the last resort.
	 * This is likely to be a pretty high number anyways (e.g. 115200). */
	if (node->reportedbps) {
		return node->reportedbps;
	}

	return 0;
}

int bbs_node_set_speed(struct bbs_node *node, unsigned int bps)
{
	unsigned int cps;
	unsigned int pauseus;

	/*
	 * Emulated output speeds for TTYs.
	 * The termios speed settings only apply to serial lines.
	 * They don't work if you call them on other TTYs, e.g. telnet, SSH, etc.
	 * However, we can simulate a specified baud rate in the pty_master
	 * thread in pty.c, since all bytes have to be relayed there anyways.
	 *
	 * It's kind of a kludge, but it's probably the most elegant way to do it
	 * without explicitly throttling the bandwidth, and from within the BBS itself.
	 * The advantage of this is that BBS modules can change the speed as desired.
	 */

	/* bps = bits per second (~baud, but not 100% really)
	 * A character is 1 byte or 8 bits.
	 * So if we want to emulate 300bps, that's really 37.5 characters per second.
	 * That means print a character about once every 26.666 ms.
	 */

#define MAX_REALTIME_BPS 9600

	if (bps > MAX_REALTIME_BPS) {
		bbs_warning("Emulated node speed %u is too high\n", bps);
		return -1;
	}

	if (bps == 0) {
		/* "Reset" to full speed with no artificial slowdowns */
		if (node->nonagle) {
			/* Disable Nagle's algorithm, we don't need it anymore. */
			bbs_set_fd_tcp_nodelay(node->sfd, 0);
			node->nonagle = 0;
		} else if (node->bps) {
			if (bbs_set_fd_tcp_pacing_rate(node->sfd, 0)) {
				return -1;
			}
		}
		node->bps = 0;
		node->speed = 0;
		return 0;
	}

	/* Don't use bbs_set_fd_tcp_pacing_rate here,
	 * it doesn't actually work as desired, unfortunately.
	 * So for now, this condition is always true here. */
	if (bps <= MAX_REALTIME_BPS) {
		cps = (bps + (8 - 1)) / 8; /* Round characters per second up */
		pauseus = 1000000 / cps; /* Round pause time between chars down */
		node->bps = bps;
		node->speed = pauseus;

		/* For slow speeds, disable Nagle's algorithm to ensure characters go out one at a time if possible
		 * to ensure that characters are sent as real time as possible, making it seem more authentic.
		 *
		 * For higher speeds, this really isn't that feasible, since
		 * it would involve a huge velocity of packets, and the data would be sent so fast
		 * that chunking data together in packets won't be as perceptible.
		 * So in those cases, we handle things differently (by setting the pacing rate).
		 *
		 * Nagle's algorithm applies to the raw TCP socket, so we operate on that,
		 * not the PTY slave or any TLS pipes, since those don't matter. */
		if (!node->nonagle) {
			bbs_set_fd_tcp_nodelay(node->sfd, 1);
			node->nonagle = 1;
		}
		bbs_debug(3, "Set node %d speed to emulated %ubps (%d us/char)\n", node->id, bps, pauseus);
	} else {
		/* At higher speeds, calling write() thousands of time per second is intractable,
		 * and unlikely to accomplish must anyways.
		 * Since the data is getting sent so fast already,
		 * let the kernel do the pacing.
		 * Downside is this won't apply to sysop spy sessions, but since this is for faster speeds,
		 * the buffer won't take as long to drain, which should prevent getting too far out of sync. */
		node->bps = bps;
		node->speed = 0;
		if (bbs_set_fd_tcp_pacing_rate(node->sfd, (int) bps / 8)) {
			return -1;
		}
		bbs_debug(3, "Set node %d speed to emulated %ubps\n", node->id, bps);
	}

	return 0;
}

static int authenticate(struct bbs_node *node)
{
	int attempts, additional_attempts = 0;
	char username[64];
	char password[64];

	if (bbs_node_logged_in(node)) {
		bbs_error("Node %d is already logged in\n", node->id);
	}

#define MAX_AUTH_ATTEMPTS 3

	for (attempts = 0; attempts < (MAX_AUTH_ATTEMPTS + additional_attempts); attempts++) {
		NEG_RETURN(bbs_node_buffer(node));
		if (!NODE_IS_TDD(node)) {
			NEG_RETURN(bbs_node_writef(node, "%s%s %s%s %s%s %s%s", COLOR(COLOR_PRIMARY), "Enter", COLOR(TERM_COLOR_WHITE), "Username", COLOR(COLOR_PRIMARY), "or", COLOR(TERM_COLOR_WHITE), "New"));
			if (allow_guest) {
				NEG_RETURN(bbs_node_writef(node, " %s%s %s%s\n", COLOR(COLOR_PRIMARY), "or", COLOR(TERM_COLOR_WHITE), "Guest"));
			}
			NEG_RETURN(bbs_node_writef(node, "\n"));
		}

		NEG_RETURN(bbs_node_writef(node, "%s%-10s%s", COLOR(COLOR_PRIMARY), "Login: ", COLOR(TERM_COLOR_WHITE)));
		NONPOS_RETURN(bbs_node_readline(node, MIN_MS(1), username, sizeof(username)));
		if (!strcasecmp(username, "Quit") || !strcasecmp(username, "Exit")) {
			bbs_debug(3, "User entered '%s', exiting\n", username);
			return -1;
		} else if (!strcasecmp(username, "New")) {
			int res;
			
			/* User registration could vary from system to system,
			 * for example, some systems may allow users to self-register,
			 * others may have a process for sysops verifying new users, etc.
			 * let's just pass it off to the registration handler immediately,
			 * and it can do whatever the heck it wants to. */
			res = bbs_user_register(node);
			if (res == 0) {
				break;
			} else if (res > 0) {
				bbs_node_writef(node, "%sUser registration aborted by system.\n", COLOR(COLOR_FAILURE));
				/* Don't even bother resetting the color, we're hanging up now */
			}
			return -1;
		} else if (!strcasecmp(username, "Guest")) {
			if (allow_guest) {
				bbs_debug(3, "User continuing as guest\n");
				if ((guest_ask_info && !NODE_IS_TDD(node)) || (guest_ask_info == 2)) {
					int tries = 4;
					char guestname[64], guestemail[64], guestlocation[64];
					/* No newlines necessary inbetween reads, since echo is on
					 * and input is terminated by a return. */
					NONZERO_NEGRETURN(bbs_get_response(node, 0, NODE_IS_TDD(node) ? "Name/alias: " : "Please enter your name or alias:  ", MIN_MS(1), guestname, sizeof(guestname), &tries, 2, NULL));
					if (NODE_IS_TDD(node)) {
						bbs_node_input_replace(node, '!', '@');
						/* Don't print out @ explicitly, because ASCII @ is converted to the same encoding as X. */
						NONZERO_NEGRETURN(bbs_get_response(node, 0, "E-Mail (use ! for at): ", MIN_MS(1), guestemail, sizeof(guestemail), &tries, 5, "@."));
						bbs_node_input_unreplace(node, '!');
					} else {
						NONZERO_NEGRETURN(bbs_get_response(node, 0, "Please enter your e-mail address: ", MIN_MS(1), guestemail, sizeof(guestemail), &tries, 5, "@."));
					}
					NONZERO_NEGRETURN(bbs_get_response(node, 0, NODE_IS_TDD(node) ? "Location (City,St): " : "Please enter your location (City, State): ", MIN_MS(1), guestlocation, sizeof(guestlocation), &tries, 5, ","));
					NEG_RETURN(bbs_authenticate(node, NULL, NULL)); /* Authenticate as guest */
					bbs_user_guest_info_set(node->user, guestname, guestemail, guestlocation);
				} else {
					NEG_RETURN(bbs_authenticate(node, NULL, NULL)); /* Authenticate as guest */
				}
				break;
			} else {
				bbs_node_writef(node, "\n\n%s%s\n\n", COLOR(COLOR_FAILURE), "Sorry, guest login is not permitted");
			}
		} else {
			/* Not a special keyword, so a normal username */
			int res, all_printable;
			/* Don't echo the password, duh... */
			NEG_RETURN(bbs_node_echo_off(node));
			NEG_RETURN(bbs_node_writef(node, "%s%-10s%s", COLOR(COLOR_PRIMARY), "Password: ", COLOR(TERM_COLOR_WHITE)));
			NONPOS_RETURN(bbs_node_readline(node, 20000, password, sizeof(password)));
			res = bbs_authenticate(node, username, password);
			if (res) {
				/* If it contains non-printable characters, it's probably not part of the actual password anyways. */
				all_printable = bbs_str_isprint(password);
			}
			bbs_memzero(password, sizeof(password)); /* Overwrite (zero out) the plain text password before we return */
			NEG_RETURN(bbs_node_echo_on(node)); /* Turn echo back on */
			if (!res) {
				break; /* Correct username and password */
			}
			/* Sorry, wrong password. Let the user try again, if his/her chances aren't up yet. */
			bbs_node_writef(node, "\n\n%s%s\n\n", COLOR(COLOR_FAILURE), "Login Failed");
			/* Logins from a TDD (or other dial-up connection), especially on a poor quality phone line, often introduced distortion and garbling
			 * of the received text. Since we need an exact match for the username and password, tolerate
			 * this by giving the user a few more tries before finally disconnect, which can be really frustrating
			 * to legitimate user. Don't increase the limit indefinitely though, for obvious reasons...
			 * and if we see 6 consecutive login failures, it's probably futile anyways. */
			if (!all_printable && additional_attempts < 3) {
				bbs_debug(5, "Granting an additional login attempt, since password contained non-printable characters\n");
				additional_attempts++;
			}
		}
	}

	/* Three strikes and you're out. */
	if (attempts >= MAX_AUTH_ATTEMPTS) {
		bbs_debug(3, "Too many failed authentication attempts on node %d, disconnecting\n", node->id);
		return -1; /* Just close the connection / hang up */
	}

	/* If we're here, then authentication was successful, either as guest or as a registered user */
	bbs_assert(bbs_node_logged_in(node));
	return 0;
}

static long ns_since(struct timespec *start, struct timespec *now)
{
	struct timespec diff;
	timespecsub(now, start, &diff);
	return (1000000000 * diff.tv_sec) + (diff.tv_nsec);
}

static int record_start_time(struct timespec *restrict start)
{
	if (clock_gettime(CLOCK_MONOTONIC_RAW, start)) {
		bbs_error("clock_gettime failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int parse_cursor_pos(char *restrict s, int *restrict row, int *restrict col)
{
	char *tmp;

	/* If we get something like \e[n;mR, n is the row and m is the column.
	 * Don't bother trying to dump the entire response, since it contains escape characters, etc. */

	tmp = strchr(s, '[');
	if (!tmp++) {
		return -1;
	}
	if (strlen_zero(tmp)) {
		return -1;
	}
	*row = atoi(tmp);
	tmp = strchr(tmp, ';');
	if (!tmp++) {
		return -1;
	}
	if (strlen_zero(tmp)) {
		return -1;
	}
	*col = atoi(tmp);
	return 0;
}

/*!
 * \brief Read cursor position response from a node. This does not send the cursor position query.
 * \param node, which should be unbuffered
 * \param timeout poll timeout for first character. Subsequent characters have a timeout of 5 seconds if a first character is received.
 * \param[out] row The row position on success (return value > 0). 1-indexed, not 0-indexed.
 * \param[out] col The col position on success (return value > 0). 1-indexed, not 0-indexed.
 * \retval -1 on node disconnect
 * \retval 1 if positive cursor position query response received
 * \retval 0 Non-ANSI terminal (no positive response)
 */
static int node_read_cursor_pos(struct bbs_node *node, int timeout, int *restrict row, int *restrict col)
{
	ssize_t res;
	char buf[84];
	char c;
	char *pos = buf;
	size_t left = sizeof(buf);

	/* It could take a moment to get the first character */
	res = bbs_node_poll(node, timeout);
	if (res <= 0) {
		if (!res) {
			bbs_debug(3, "No response to cursor position query after %d seconds...\n", timeout / 1000);
		}
		return res ? -1 : 0;
	}
	/* We read and poll separately because bbs_node_tread triggers the "timed out due to inactivity" log message */
	res = bbs_node_read(node, pos, 1);
	if (res <= 0) {
		return res ? -1 : 0;
	}
	pos++;
	left--;
	/* Read byte by byte, just in case there's more data,
	 * so we don't risk reading past the R. */
	do {
		res = bbs_node_poll(node, SEC_MS(5));
		if (res <= 0) {
			if (!res) {
				/* We started getting something but didn't get a full response to the cursor position query.
				 * Could be other random data or maybe corruption? */
				bbs_debug(1, "Incomplete response to cursor position query...\n");
			}
			return res ? -1 : 0;
		}
		res = bbs_node_read(node, &c, 1);
		if (res <= 0) {
			return res ? -1 : 0;
		}
		*pos = c;
		pos++;
		left--;
	} while (c != 'R' && left > 1);
	*pos = '\0';
	if (!left) {
		bbs_warning("Buffer exhausted reading cursor position response: '%s'\n", buf);
		return 0;
	}
	if (parse_cursor_pos(buf, row, col)) {
		bbs_warning("Received invalid cursor position response\n");
		return 0;
	}
	bbs_debug(3, "Cursor position response: row %d, col %d\n", *row, *col);
	return 1;
}

int node_get_cursor_pos(struct bbs_node *node, int *restrict row, int *restrict col)
{
	/* Send cursor position query */
	if (bbs_node_write(node, TERM_CURSOR_POS_QUERY, STRLEN(TERM_CURSOR_POS_QUERY)) < 0) {
		return -1;
	}
	/* Read cursor position query response */
	return node_read_cursor_pos(node, SEC_MS(1), row, col); /* Since we know this terminal supports this sequence, don't wait very long for a response, since we do expect one */
}

/*!
 * \brief Test if several kinds of ANSI escape sequences are supported
 * \param node, which should be unbuffered, and known to support the cursor position query (at least)
 * \retval 0 Ran tests
 * \retval -1 node disconnected
 */
static int init_term_query_ansi_escape_support(struct bbs_node *node)
{
	int res, row, col;
	int oldrow, oldcol;

	/* Some terminals support certain escape sequences, others don't.
	 * Try to detect if there are certain escape sequences this
	 * terminal does not support. We do this by running tests which
	 * position the cursor at a certain place if supported and at
	 * a different place if not supported, allowing us to distinguish
	 * supporting and unsupporting clients. */

#ifdef DEV_DEBUG
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
#endif

	node->ans |= ANSI_CURSOR_QUERY; /* If node_get_cursor_pos returned positive, then obviously this is supported */

	/* The above test is not necessary, and was only used to verify that
	 * presently, the terminal should be at row 3, col 1 (we are 1-indexed, not 0-indexed). */

	bbs_node_writef(node, "\n\n\n   "); /* Add 3 rows and 3 columns, so 3,1 -> 6,4 (verified with DEV_DEBUG). */

#ifdef DEV_DEBUG
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
#endif

	/* Tests here have been structured to minimize the number of
	 * output characters required between tests (e.g. newlines, spaces).
	 * For instance, clear screen should be tested last, since that
	 * would reset col and row to 0, and we would need to offset both
	 * for any subsequent tests.
	 *
	 * Also, most terminals support most things, so only print something
	 * if a terminal does NOT support the tested capability. */

	/* Clear line */
	bbs_node_write(node, TERM_RESET_LINE, STRLEN(TERM_RESET_LINE));
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
	/* If clear line was supported, col should now be 1. */
	if (col == 1) {
		node->ans |= ANSI_CLEAR_LINE;
	} else {
		bbs_verb(6, "Terminal does not support clear line\n");
	}

	/* Go up 1 line */
	oldrow = row;
	bbs_node_write(node, TERM_UP_ONE_LINE, STRLEN(TERM_UP_ONE_LINE));
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
	/* If up 1 line is supported, row should have decreased. */
	if (row == oldrow - 1) {
		node->ans |= ANSI_UP_ONE_LINE;
	} else {
		bbs_verb(6, "Terminal does not support up one line\n");
	}

	/* Colors */
	oldcol = col;
	oldrow = row;
	bbs_node_writef(node, COLOR(TERM_COLOR_GREEN) COLOR_RESET);
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
	/* If colors supported, the color escape sequences should not occupy "space" on the terminal. */
	if (row == oldrow && col == oldcol) {
		node->ans |= ANSI_COLORS;
	} else {
		bbs_verb(6, "Terminal does not support colors\n");
	}

	/* Terminal title */
	oldcol = col;
	oldrow = row;
	bbs_node_writef(node, TERM_TITLE_FMT, "LBBS"); /* We'll set a new title in the intro anyways, so okay to do this momentarily */
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
	/* If setting terminal title is supported, it won't occupy "space" on the terminal */
	if (row == oldrow && col == oldcol) {
		node->ans |= ANSI_TERM_TITLE;
	} else {
		bbs_verb(6, "Terminal does not support titles\n");
	}

	/* Unfortunately, we can't really test if TERM_TITLE_RESTORE_FMT is supported.
	 * There is an escape sequence to get the client's current terminal title,
	 * but many clients (e.g. PuTTY/KiTTY) are programmed to not return that,
	 * for security reasons, so not really worth bothering with.
	 *
	 * Could also test TERM_ICON_FMT, but that doesn't seem to be used, currently,
	 * so not worth doing right now (we would also need to overwrite subsequently).
	 */

	/* Set cursor position */
	oldcol = col;
	oldrow = row;
	bbs_node_writef(node, TERM_CURSOR_POS_SET_FMT, 4, 6);
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
	/* If cursor pos explicitly supported, should be what we set it to */
	if (row == 4 && col == 6) {
		node->ans |= ANSI_CURSOR_SET;
	} else {
		bbs_verb(6, "Terminal does not support cursor position setting\n");
	}

	/* Clear screen */
	bbs_node_write(node, TERM_CLEAR, STRLEN(TERM_CLEAR));
	res = node_get_cursor_pos(node, &row, &col);
	if (res <= 0) {
		return res;
	}
	/* If clear screen was supported, now both row and col should be 1. */
	if (row == 1 && col == 1) {
		node->ans |= ANSI_CLEAR_SCREEN;
	} else {
		bbs_verb(6, "Terminal does not support clear screen\n");
	}

	/* No need to test support TERM_CLEAR_SCROLLBACK, since only mod_sysop uses that,
	 * for sysop consoles, not for nodes. */

	return 0;
}

/*!
 * \brief Read cursor position response
 * \param node, which should be unbuffered
 * \retval -1 on node disconnect
 * \retval 1 if positive cursor position query response received
 * \retval 0 Non-ANSI terminal (no positive response)
 */
static int read_cursor_pos_response(struct bbs_node *node, struct timespec *restrict start, const char *restrict buf, int len)
{
	int i;
	int res;
	int row, col;
	int retries = 0;

	if (record_start_time(start)) {
		return 0;
	}
	if (bbs_node_write(node, buf, (size_t) len) < (ssize_t) len) {
		return -1;
	}
	/* Most modern terminals support ANSI and will respond immediately,
	 * so don't wait too long for that. */
	res = node_read_cursor_pos(node, SEC_MS(3), &row, &col);
	if (res) {
		return res;
	}

	/* Modem connections can take (significantly) longer to handshake
	 * and negotiate, and it's a good idea to require a character to be
	 * pressed on the user's side before sending anything for real,
	 * or stuff will get missed. */
	for (i = 0; i < 5; i++) {
		ssize_t pres;
		bbs_node_writef(node, "%sPress ENTER: ", i ? "\r" : "");
		pres = bbs_node_poll(node, SEC_MS(4));
		if (pres < 0) {
			return -1;
		} else if (pres) {
			bbs_debug(4, "Retrying cursor position query due to timeout (attempt %d)\n", i + 2); /* 1-index it, plus we already tried once prior */
			/* Reset start time, since we're really starting now */
			if (record_start_time(start)) {
				return 0;
			}
			/* Resend, now that we know. */
			if (bbs_node_write(node, buf, (size_t) len) < 0) {
				return -1;
			}
			/* We got input from the terminal, so that means
			 * this is after the CONNECT, and we're really synchronized.
			 * Go ahead and do the test again. */
			res = node_read_cursor_pos(node, SEC_MS(5), &row, &col);
			if (res || retries) {
				if (retries) {
					bbs_verb(5, "Failed to read cursor position query response, bad client or broken connection?\n");
				}
				return res;
			}
			/* Sometimes this fails with low-speed modem connections
			 * without error correction (e.g. 300 / 1200 bps)
			 * due to corruption on the link; try again
			 * if it fails the first time, but only once. */
			retries++;
		}
	}

	bbs_verb(4, "No input received from node, disconnecting...\n");
	return -1;
}

/*! \brief Round to the nearest modem speed */
static long int estimate_bps(long int bps)
{
	if (bps < 75) {
		return 45;
	} else if (bps < 150) {
		return 110;
	} else if (bps < 450) {
		return 300;
	} else if (bps < 900) {
		return 600;
	} else if (bps < 1800) {
		return 1200;
	} else if (bps < 3600) {
		return 2400;
	} else if (bps < 7200) {
		return 4800;
	} else if (bps < 12000) {
		return 9600;
	} else if (bps < 16800) {
		return 14400;
	} else if (bps < 24000) {
		return 19200;
	} else if (bps < 30000) {
		return 28800;
	} else if (bps < 32400) {
		return 31200;
	} else if (bps < 36000) {
		return 33600;
	} else if (bps < 64000) {
		return 56000;
	} else if (bps < 72000) {
		return 64000;
	} else {
		return bps;
	}
}

int bbs_node_format_speed(struct bbs_node *node, char *restrict buf, size_t len)
{
	if (node->calcbps <= 0) {
		safe_strncpy(buf, len >= STRLEN("Unknown") + 1 ? "Unknown" : "???", len);
		return -1;
	} else if (node->calcbps < 10000) {
		/* gcc thinks the buffer could be too small for a long, but since we're checking the size, it can't be */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
		snprintf(buf, len, "%ld", node->calcbps);
		return 0;
	} else if (node->calcbps <= 64000) {
		long kbps = node->calcbps / 1000;
		snprintf(buf, len, "%ld.%ldk", kbps, (node->calcbps - (1000 * kbps)) / 100); /* Display with 1 decimal point, using integer math */
#pragma GCC diagnostic pop
		return 0;
	} else { /* Broadband */
		safe_strncpy(buf, len >= STRLEN("Broadband") + 1 ? "Broadband" : " BrdBd", len);
		return 1;
	}
}

/*!
 * \brief Check whether the client's terminal supports ANSI and how fast it is
 * \param node
 * \retval -1 node disconnected
 * \retval 0 Successful ANSI handshake
 * \retval 1 Failed ANSI handshake
 */
static int init_term_properties_automatic(struct bbs_node *node)
{
	struct timespec start, end;
	long ns, bps;
	int bits;
	double ns_factor;
	ssize_t res;
	char buf[256];
	int bytes;

	/* Prepare it into a buffer first and send all at once, so we know exactly how many bytes we sent. */
	bytes = snprintf(buf, sizeof(buf),
		"%s%s"
		"%s  Version %d.%d.%d\n"
		"%s connection from: %s\n"
		/* Try to determine the speed of the connected terminal.
		 * No, we don't need any fancy black magic to do that.
		 * Just query the terminal with something that should elicit
		 * a response from most terminals, and time when we get the response. */
		TERM_CURSOR_POS_QUERY, /* Ask for cursor position, don't care what it is, just want to get a response. */
		TERM_CLEAR, COLOR_RESET,
		BBS_TAGLINE, BBS_MAJOR_VERSION, BBS_MINOR_VERSION, BBS_PATCH_VERSION,
		node->protname, node->ip);

	if (record_start_time(&start)) {
		return 1;
	} else if (bbs_set_fd_tcp_nodelay(node->sfd, 1)) { /* Temporarily disable Nagle's algorithm, so that we can flush packets immediately. */
		return 1;
	} else if (bbs_node_unbuffer(node)) {
		return 1;
	}

	/* Most modern terminals support ANSI and will respond immediately,
	 * so don't wait too long for that. */
	res = read_cursor_pos_response(node, &start, buf, bytes);
	if (res <= 0) {
		return res ? -1 : 1;
	}

	/* Terminal supports ANSI escape sequences. Already initialized to 1, but be explicit.
	 * We initialize to 1, by the way, or bbs_node_write would automatically strip ANSI,
	 * but we want to assume nodes support ANSI for the test, or it won't work. */
	node->ansi = 1;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &end)) {
		bbs_error("clock_gettime failed: %s\n", strerror(errno));
		return 1;
	}

	ns = ns_since(&start, &end);
	bbs_debug(1, "%ld ns elapsed for cursor position query (sent %d bytes)\n", ns, bytes);

	/* It might seem like it would be a good idea to divide ns by 2, since
	 * the actual time it took the data to get to the client should be ~half the RTT.
	 * But we sent a lot more data to the client than it sent us, so that download
	 * to the client is probably a much larger portion of the elapsed time than the upload.
	 * So, compromise between halving and not half and take, say, 80%.
	 *
	 * Normally, we also want to account for Nagle's delay, since we don't open
	 * sockets with that option disabled, but Nagle's algorithm is disabled
	 * for these calculations.
	 *
	 * This isn't going to be super accurate either way, since we sent such a small
	 * amount of data that the margin for error is huge. We'd want to send a lot more
	 * data to maximize the amount of "goodput" in arriving at these calculations.
	 *
	 * If the client is on any kind of sub-broadband connection, that's almost certainly
	 * going to be the bottleneck and will domination the calculations. */
	ns /= 5;
	ns *= 4;

	bits = bytes * 8; /* Amount of data sent */

#define NS_PER_SEC 1000000000

	ns_factor = ((double) ns) / NS_PER_SEC; /* If < 1, it took under a second. If > 1, it took more than a second. */
	bps = (int) ((1.0 * (double) bits) / ns_factor); /* To get bps, just multiply bits by the same scale factor */
	bbs_debug(2, "Calculated speed is %ld bps\n", bps); /* Pre-rounding */

	bps = estimate_bps(bps); /* Take our estimate and round it to the nearest actual modem speed */
	node->calcbps = bps;
	if (bps < 10000) {
		bbs_verb(4, "Node %u supports ANSI, downlink ~ %ld bps\n", node->id, bps);
		if (node->calcbps <= 4800) {
			/* Consider any terminals running at 300, 1200, 2400, and 4800 baud to be particularly "slow". */
			node->slow = 1;
		}
	} else if (bps <= 64000) {
		long kbps = bps / 1000;
		bbs_verb(4, "Node %u supports ANSI, downlink ~ %ld.%ld kbps\n", node->id, kbps, (bps - (1000 * kbps)) / 100); /* Display with 1 decimal point, using integer math */
	} else {
		bbs_verb(4, "Node %u supports ANSI, downlink ~ broadband\n", node->id);
	}

	return 0;
}

static int ask_yn(struct bbs_node *node, const char *question)
{
	int i;
	char c;
	/* Since we're not sure if this terminal supports ANSI,
	 * don't use any ANSI escape sequences, just keep it nice and simple. */
	for (i = 0; i < 3; i++) {
		bbs_node_writef(node, "\n%s? (y/n) ", question);
		c = bbs_node_tread(node, SEC_MS(30));
		if (tolower(c) == 'y') {
			return 1;
		} else if (tolower(c) == 'n') {
			return 0;
		}
	}
	return -1;
}

static int ask_dimension(struct bbs_node *node, const char *question)
{
	int i;
	ssize_t res;
	char buf[16];

	for (i = 0; i < 3; i++) {
		bbs_node_writef(node, "\n%s? ", question);
		res = bbs_node_readline(node, SEC_MS(30), buf, sizeof(buf) - 1);
		if (res < 0) {
			return -1;
		} else if (res) {
			int num;
			buf[res] = '\0';
			num = atoi(buf);
			if (!num) {
				char buf2[16];
				int newlen;
				/* Sometimes we read other characters here */
				bbs_dump_mem((unsigned char*) buf, (size_t) res);
				/* XXX For some reason, the flush prior to calling ask_dimension
				 * doesn't do what's desired, and we end up reading an escape sequence here.
				 * So, manually strip that. */
				bbs_ansi_strip(buf, (size_t) res, buf2, sizeof(buf2), &newlen);
				num = atoi(buf2);
			}
			if (num <= 0 || num > 1024) {
				bbs_debug(3, "Ignoring non-numeric, negative, or invalid response '%s' (%d)\n", buf, num);
				continue;
			}
			return num;
		}
	}
	return -1;
}

static int init_term_properties_manual(struct bbs_node *node)
{
	int res;

	res = ask_yn(node, "ANSI support");
	if (res < 0) {
		return -1;
	}
	SET_BITFIELD(node->ansi, res);

	res = ask_yn(node, "Slow terminal");
	if (res < 0) {
		return -1;
	}
	SET_BITFIELD(node->slow, res);

	bbs_node_writef(node, "\n"); /* ask_yn doesn't end with LF */
	return 0;
}

static int _bbs_intro(struct bbs_node *node)
{
	int res;

	/* To be compatible with all terminals, we need to tolerate connections as slow as 300 bps
	 * (no slower, since 110 bps is extremely rare, and TTDs don't execute _bbs_intro, as we
	 *  already know they are slow).
	 * At 300 baud, it might take a few seconds to print the above banners and then receive the check,
	 * and finally send back the response. If we haven't gotten a response by then, assume
	 * that the terminal doesn't support this kind of stuff and proceed anyways. */
	res = init_term_properties_automatic(node);
	if (res < 0) {
		return res;
	} else if (res) {
		/* Could not autodetect ANSI support */
		bbs_verb(4, "Could not autodetect ANSI support for node %u\n" ,node->id);
		res = init_term_properties_manual(node);
		if (res < 0) {
			return res;
		}
	} else {
		/* Since this is an ANSI terminal, see what ANSI escape sequences are supported by this terminal. */
		bbs_debug(2, "Autodetecting ANSI escape sequence support\n");
		res = init_term_query_ansi_escape_support(node);
	}

	if (!node->dimensions && ask_dimensions) {
		/* If the client didn't send us its dimensions automatically,
		 * prompt the client for dimensions. */
		int rows, cols;

		/* Eat any responses to previous terminal queries, if they elicited some response */
		bbs_node_buffer(node);
		bbs_write(node->amaster, "\n", 1); /* Spoof newline to force buffered read to process */
		bbs_node_flush_input(node);

		cols = ask_dimension(node, "Terminal number of cols");
		if (cols <= 0) {
			return -1;
		} else if (cols < 16) {
			/* Unlikely to be a display this small */
			bbs_node_writef(node, "Terminal too small, goodbye\n");
			return -1;
		}
		rows = ask_dimension(node, "Terminal number of rows");
		if (rows <= 0) {
			return -1;
		}
		node->rows = (unsigned int) rows;
		node->cols = (unsigned int) cols;
		node->dimensions = 1;
	}

	bbs_node_buffer(node); /* Reset */
	bbs_set_fd_tcp_nodelay(node->sfd, 0); /* Undo the disable */
	return 0;
}

static int node_intro(struct bbs_node *node)
{
	/* Display any pre-auth banners */
	if (bbs_event_dispatch(node, EVENT_NODE_INTERACTIVE_START)) {
		return -1;
	}

	/* Some protocols like SSH may support direct login of users. Otherwise, do a normal login. */
	if (!bbs_node_logged_in(node)) {
		NEG_RETURN(bbs_node_clear_line(node));
		NEG_RETURN(authenticate(node));
	}

	/* At this point, we are logged in. */
	bbs_assert(bbs_node_logged_in(node));

	/* Run any callbacks that should run on user login.
	 * We do it here rather than in bbs_authenticate, because the SSH module can do native login
	 * where bbs_node_logged_in will be true right above here.
	 * So doing it here ensures that, no matter how authentication happened, we run the code. */
	if (bbs_event_dispatch(node, EVENT_NODE_INTERACTIVE_LOGIN)) {
		return -1;
	}
	return 0;
}

int bbs_node_statuses(struct bbs_node *node, const char *username)
{
	struct bbs_node *n;

	NEG_RETURN(bbs_node_writef(node, "%s%s\n\n", COLOR(TERM_COLOR_WHITE), "Node Status"));
	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, n, entry) {
		if (username && (!bbs_user_is_registered(node->user) || strcmp(bbs_username(node->user), username))) {
			continue;
		}
		if (n->slavefd != -1) {
			if (username && !strlen_zero(n->menuitem)) {
				/* Show more details if for a specific user */
				bbs_node_writef(node, "%s%3d  %s%s%s at %s menu (%s) via %s\n",
					COLOR(TERM_COLOR_WHITE), n->id, COLOR(COLOR_PRIMARY), bbs_username(n->user), COLOR(COLOR_SECONDARY), S_IF(n->menu), n->menuitem, n->protname);
			} else {
				bbs_node_writef(node, "%s%3d  %s%s%s at %s menu via %s\n",
					COLOR(TERM_COLOR_WHITE), n->id, COLOR(COLOR_PRIMARY), bbs_username(n->user), COLOR(COLOR_SECONDARY), S_IF(n->menu), n->protname);
			}
		} else {
			bbs_node_writef(node, "%s%3d  %s%s%s connected via %s\n",
				COLOR(TERM_COLOR_WHITE), n->id, COLOR(COLOR_PRIMARY), bbs_username(n->user), COLOR(COLOR_SECONDARY), n->protname);
		}
	}
	RWLIST_UNLOCK(&nodes);
	return 0;
}

static int bbs_goodbye(struct bbs_node *node)
{
	NEG_RETURN(bbs_node_clear_screen(node));
	if (!s_strlen_zero(bbs_exitmsg)) {
		char sub[512];
		bbs_node_substitute_vars(node, bbs_exitmsg, sub, sizeof(sub));
		NEG_RETURN(bbs_node_writef(node, "%s", sub));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(12))); /* Give time to display message before session closes */
	}
	return 0;
}

static int node_handler_term(struct bbs_node *node)
{
	if (shutting_down) {
		bbs_debug(5, "Exiting\n");
		return -1;
	}

	/* Set up the psuedoterminal */
	bbs_node_lock(node); /* Lock to prevent node thread from being cancelled while it's registering itself. */
	if (bbs_pty_allocate(node)) {
		bbs_node_unlock(node);
		bbs_debug(5, "Exiting\n");
		return -1;
	}
	bbs_node_unlock(node);

	if (defaultbps) {
		/* If there's a default speed to emulate, set it */
		bbs_node_set_speed(node, defaultbps);
	}

	if (!NODE_IS_TDD(node) && bbs_node_set_term_title(node, bbs_name_buf) < 0) {
		bbs_debug(5, "Exiting\n");
		return -1;
	} else if (tty_set_line_discipline(node->slavefd)) {
		bbs_debug(5, "Exiting\n");
		return -1;
	} else if (!NODE_IS_TDD(node) && _bbs_intro(node)) {
		bbs_debug(5, "Exiting\n");
		return -1;
	} else if (node_intro(node)) {
		bbs_debug(5, "Exiting\n");
		return -1;
	}

	/* Should be authenticated by now (either as a user or continuing as guest) */
	bbs_assert(bbs_node_logged_in(node));

	if (bbs_node_menuexec(node)) { /* Run the BBS on this node. */
		return -1;
	}

	/* Display goodbye message (if node TTY still active)
	 * At this point, it's only a matter of time until the node is going away,
	 * there's nothing the user can do at this point to keep the link active. */
	bbs_goodbye(node);
	return 0; /* Normal user-initiated exit */
}

void bbs_node_begin(struct bbs_node *node)
{
	bbs_assert_exists(node);
	bbs_assert((unsigned long) node->thread > 0);
	bbs_assert(node->fd != -1);
	bbs_assert_exists(node->protname); /* Will fail if a network comm driver forgets to set before calling bbs_node_handler */

	bbs_debug(1, "Running BBS for node %d\n", node->id);
	bbs_auth("New %s connection to node %d from %s:%u\n", node->protname, node->id, node->ip, node->rport);
}

void bbs_node_net_begin(struct bbs_node *node)
{
	node->thread = pthread_self();
	bbs_node_begin(node);
}

int bbs_node_starttls(struct bbs_node *node)
{
	int res;

	if (unlikely(node->secure)) {
		bbs_error("Can't start TLS, connection already encrypted\n");
		return 1;
	}

	if (!bbs_io_transformer_available(TRANSFORM_TLS_ENCRYPTION)) {
		return 1;
	}

	res = bbs_io_transform_setup(&node->trans, TRANSFORM_TLS_ENCRYPTION, TRANSFORM_SERVER, &node->rfd, &node->wfd, NULL);
	if (res) {
		/* If TLS setup fails, it's probably garbage traffic and safe to penalize: */
		if (node) {
			bbs_event_dispatch(node, EVENT_NODE_ENCRYPTION_FAILED);
		}
	} else {
		node->secure = 1;
	}
	return res;
}

void bbs_node_exit(struct bbs_node *node)
{
	bbs_soft_assert(node->id > 0);
	bbs_soft_assert(node->protname != NULL);
	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	if (node->active) {
		/* User quit: unlink and free */
		bbs_node_unlink(node);
	} else {
		/* Server force quit the node.
		 * For example, bbs_node_shutdown_all was called, which already holds a WRLOCK,
		 * so we shouldn't call bbs_node_unlink or that will grab another WRLOCK and cause deadlock.
		 * node_cleanup was already called, all we need to do is free.
		 */
		node_free(node);
	}
}

void *bbs_node_handler(void *varg)
{
	struct bbs_node *node = varg;

	bbs_node_begin(node);
	node_handler_term(node); /* Run the normal terminal handler */
	bbs_node_exit(node);

	return NULL;
}

static int cli_spy(struct bbs_cli_args *a)
{
	int res;
	int node = atoi(a->argv[1]);
	if (node <= 0) {
		bbs_dprintf(a->fdout, "Invalid node %s\n", a->argv[1]);
		return -1;
	}
	bbs_cli_set_stdout_logging(a->fdout, 0);
	res = bbs_node_spy(a->fdin, a->fdout, (unsigned int) node);
	/* Let mod_sysop re-enable logging to stdout, if configured */
	return res;
}

static int cli_node_set_speed(struct bbs_cli_args *a)
{
	int res;
	struct bbs_node *node;
	int bps, nodenum = atoi(a->argv[1]);

	bbs_cli_set_stdout_logging(a->fdout, 0);
	if (nodenum <= 0) {
		bbs_dprintf(a->fdout, "Invalid node %s\n", a->argv[1]);
		return -1;
	}
	bps = atoi(a->argv[2]);
	if (bps < 0) {
		bbs_dprintf(a->fdout, "Invalid speed: %s\n", a->argv[2]);
		return -1;
	}

	node = bbs_node_get((unsigned int) nodenum);
	if (!node) {
		bbs_dprintf(a->fdout, "Node %d does not exist\n", nodenum);
		return -1;
	}
	res = bbs_node_set_speed(node, (unsigned int) bps);
	bbs_node_unlock(node);
	return res;
}

static int cli_user(struct bbs_cli_args *a)
{
	const char *username = a->argv[1];
	if (bbs_user_dump(a->fdout, username, 10)) {
		bbs_dprintf(a->fdout, "No such user '%s'\n", username);
		return -1;
	}
	return 0;
}

static int cli_users(struct bbs_cli_args *a)
{
	return bbs_users_dump(a->fdout, 10);
}

static int cli_alert(struct bbs_cli_args *a)
{
	unsigned int userid;
	const char *msg;

	userid = bbs_userid_from_username(a->argv[1]);
	if (!userid) {
		bbs_dprintf(a->fdout, "No such user '%s'\n", a->argv[1]);
		return -1;
	}

	msg = a->command + STRLEN("alert "); /* We know it starts with this */
	msg = bbs_strcnext(msg, ' '); /* Skip the next space, after the username. Now, we have the beginning of the message */

	if (bbs_alert_user(userid, DELIVERY_EPHEMERAL, "%s", msg)) {
		bbs_dprintf(a->fdout, "Failed to deliver message\n");
		return -1;
	} else {
		bbs_dprintf(a->fdout, "Message delivered\n");
		return 0;
	}
}

static struct bbs_cli_entry cli_commands_nodes[] = {
	/* Node commands */
	BBS_CLI_COMMAND(cli_nodes, "nodes", 1, "List all nodes", NULL),
	BBS_CLI_COMMAND(cli_node, "node", 2, "View information about specified node", "node <nodenum>"),
	BBS_CLI_COMMAND(cli_interrupt, "interrupt", 2, "Interrupt specified node", "interrupt <nodenum>"),
	BBS_CLI_COMMAND(cli_kick, "kick", 2, "Kick specified node", "kick <nodenum>"),
	BBS_CLI_COMMAND(cli_kickall, "kickall", 1, "Kick all nodes", NULL),
	BBS_CLI_COMMAND(cli_spy, "spy", 2, "Spy on specified node (^C to stop)", "spy <nodenum>"),
	BBS_CLI_COMMAND(cli_node_set_speed, "speed", 3, "Set emulated speed of specified node (0 = unthrottled)", "speed <nodenum> <bps>"),
	/* User commands */
	BBS_CLI_COMMAND(cli_user, "user", 2, "View information about specified user", "user <username>"),
	BBS_CLI_COMMAND(cli_users, "users", 1, "List all users", NULL),
	BBS_CLI_COMMAND(cli_alert, "alert", 3, "Send a message to a user", "alert <username> <message>"),
};

int bbs_load_nodes(void)
{
	bbs_register_reload_handler("nodes", "Reload node configuration", reload_nodes);
	return load_config() || bbs_cli_register_multiple(cli_commands_nodes);
}
