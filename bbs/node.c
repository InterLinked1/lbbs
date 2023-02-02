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
#include <poll.h>
#include <pthread.h>
#include <signal.h> /* use pthread_kill */
#include <math.h> /* use ceil, floor */
#include <sys/ioctl.h>

#include "include/node.h"
#include "include/user.h"
#include "include/variables.h"
#include "include/term.h"
#include "include/pty.h"
#include "include/os.h"
#include "include/menu.h"
#include "include/auth.h"
#include "include/config.h"
#include "include/module.h" /* use bbs_module_unref */
#include "include/utils.h" /* use print_time_elapsed */

#define DEFAULT_MAX_NODES 64

static int shutting_down = 0;

static RWLIST_HEAD_STATIC(nodes, bbs_node);

/*! \brief Guest login is allowed by default */
#define DEFAULT_ALLOW_GUEST 1

/*! \brief Whether to ask guests for additional details */
#define DEFAULT_GUEST_ASK_INFO 1

static unsigned int maxnodes;
static unsigned int minuptimedisplayed = 0;
static int allow_guest = DEFAULT_ALLOW_GUEST;
static int guest_ask_info = DEFAULT_GUEST_ASK_INFO;
static unsigned int defaultbps = 0;

static char bbs_name_buf[32] = "BBS"; /* A simple default so this is never empty. */
static char bbs_tagline[84] = "";
static char bbs_hostname_buf[92] = "";
static char bbs_sysop[16] = "";
static char bbs_exitmsg[484] = "";

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("nodes.conf", 1); /* Use cached version if possible and not stale */

	/* Set some basic defaults, whether there's a config or not */
	maxnodes = DEFAULT_MAX_NODES;
	allow_guest = DEFAULT_ALLOW_GUEST;
	guest_ask_info = DEFAULT_GUEST_ASK_INFO;
	defaultbps = 0;

	if (!cfg) {
		return 0;
	}

	if (bbs_config_val_set_str(cfg, "bbs", "name", bbs_name_buf, sizeof(bbs_name_buf))) {
		bbs_warning("No name is configured for this BBS in nodes.conf - BBS will be impersonal!\n");
	}
	bbs_config_val_set_str(cfg, "bbs", "tagline", bbs_tagline, sizeof(bbs_tagline));
	bbs_config_val_set_str(cfg, "bbs", "hostname", bbs_hostname_buf, sizeof(bbs_hostname_buf));
	bbs_config_val_set_str(cfg, "bbs", "sysop", bbs_sysop, sizeof(bbs_sysop));
	bbs_config_val_set_uint(cfg, "bbs", "minuptimedisplayed", &minuptimedisplayed);
	bbs_config_val_set_str(cfg, "bbs", "exitmsg", bbs_exitmsg, sizeof(bbs_exitmsg));
	bbs_config_val_set_uint(cfg, "nodes", "maxnodes", &maxnodes);
	bbs_config_val_set_uint(cfg, "nodes", "defaultbps", &defaultbps);
	bbs_config_val_set_true(cfg, "guests", "allow", &allow_guest);
	bbs_config_val_set_true(cfg, "guests", "askinfo", &guest_ask_info);
	return 0;
}

int bbs_guest_login_allowed(void)
{
	return allow_guest;
}

int bbs_load_nodes(void)
{
	return load_config();
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

unsigned int bbs_maxnodes(void)
{
	return maxnodes;
}

const char *bbs_hostname(void)
{
	return bbs_hostname_buf;
}

const char *bbs_name(void)
{
	return bbs_name_buf;
}

struct bbs_node *__bbs_node_request(int fd, const char *protname, void *mod)
{
	struct bbs_node *node = NULL, *prev = NULL;
	unsigned int count = 0;
	unsigned int newnodenumber = 1, keeplooking = 1;

	if (fd <= 2) { /* Should not be STDIN, STDOUT, or STDERR, or negative */
		bbs_error("Invalid file descriptor for BBS node: %d\n", fd);
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
	if (!node) {
		bbs_error("calloc failed\n");
		RWLIST_UNLOCK(&nodes);
		return NULL;
	}
	pthread_mutex_init(&node->lock, NULL);
	node->id = newnodenumber;
	node->fd = fd;

	/* Not all nodes will get a pseudoterminal, so initialize to -1 so if not, we don't try to close STDIN erroneously on shutdown */
	node->amaster = -1;
	node->slavefd = -1;

	node->spyfd = -1;
	node->spyfdin = -1;

	node->user = NULL; /* No user exists yet. We calloc'd so this is already NULL, but this documents that user may not exist at first. */
	node->active = 1;
	node->created = time(NULL);
	/* Assume TTY will be in canonical mode with echo enabled to start. */
	node->echo = 1;
	node->buffered = 1;
	node->protname = protname;
	node->ansi = 1; /* Assume nodes support ANSI escape sequences by default. */

	/* This prevents this module from being unloaded as long as there are nodes using it.
	 * For example, since node->protname is constant in this module, if we unload it,
	 * even though no code is being executed in the module actively, if we list nodes,
	 * then we'll crash since node->protname isn't valid memory anymore.
	 * Yes, sure we could copy the string instead of storing a reference, but that's not the point.
	 * Nodes should increment the ref count of the module, which will force disconnecting
	 * relevant nodes before we attempt to unload or reload the module.
	 */
	node->module = mod;
	bbs_module_ref(mod);

	if (prev) {
		RWLIST_INSERT_AFTER(&nodes, prev, node, entry); /* Insert at the appropriate index. */
	} else {
		RWLIST_INSERT_HEAD(&nodes, node, entry); /* This is the first node. */
	}
	RWLIST_UNLOCK(&nodes);

	bbs_debug(1, "Allocated new node with ID %u\n", node->id);

	return node;
}

int bbs_node_lock(struct bbs_node *node)
{
	bbs_assert_exists(node);
	return pthread_mutex_lock(&node->lock);
}

int bbs_node_unlock(struct bbs_node *node)
{
	bbs_assert_exists(node);
	return pthread_mutex_unlock(&node->lock);
}

char bbs_node_input_translate(struct bbs_node *node, char c)
{
	long unsigned int i;
	char ret = c;

	bbs_node_lock(node);
	if (node->ioreplaces) {
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
		usleep(i + 1);
	}
	/* Next, try a SIGTERM */
	if (*pidptr) {
		if (kill(pid, SIGTERM)) {
			bbs_error("kill failed: %s\n", strerror(errno));
		}
		/* Just to make sure, see if it really died. */
		for (i = 0; *pidptr && i < 25; i++) {
			usleep(i + 1);
		}
		/* If node->childpid is still set, then send a SIGKILL and get on with it. */
		if (*pidptr) {
			if (kill(pid, SIGKILL)) {
				bbs_error("kill failed: %s\n", strerror(errno));
			}
			/* Just to make sure, see if it really died. */
			for (i = 0; *pidptr && i < 25; i++) {
				usleep(i + 1);
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

	/* Prevent node from being freed until we release the lock. */
	bbs_node_lock(node);
	if (!node->active) {
		bbs_error("Attempt to shut down already inactive node %d?\n", node->id);
		bbs_node_unlock(node);
		return;
	}
	node->active = 0;
	bbs_debug(2, "Terminating node %d\n", node->id);

	bbs_node_kill_child(node);

	/* Destroy the user */
	if (node->user) {
		bbs_node_logout(node);
	}

	/* If the node is still connected, be nice and reset it. If it's gone already, forget about it. */
	if (node->slavefd != -1) {
		/* Restore the terminal on node exit: re-enable canonical mode and re-enable echo. */
		bbs_buffer_input(node, 1);
		/* Be nice and try to reset its color.
		 * No need to go through the psuedoterminal for this. If it fails, then it didn't matter anyways.
		 * Don't use bbs_reset_color because we already hold the node lock, so we can't call bbs_write,
		 * as that will try to get a recursive lock.
		 */
		SWRITE(node->fd, COLOR_RESET);
	}

	if (node->ptythread) {
		pthread_cancel(node->ptythread);
		pthread_kill(node->ptythread, SIGURG);
		bbs_pthread_join(node->ptythread, NULL); /* Wait for the PTY master thread to exit, and then clean it up. */
		if (node->spy) {
			/* The sysop was spying on this node when it got disconnected.
			 * Let the sysop know this node is dead. */
			bbs_dprintf(node->spyfd, COLOR_RESET "\nNode %d has disconnected.\nPress ^C to exit spy mode.\n", node->id);
			node->spy = 0;
		}
	}

	if (node->fd) { /* Properly shut down */
		/* If we just close our end of the socket, poll doesn't see that */
		shutdown(node->fd, SHUT_RDWR); /* XXX Using for PTY fds could fix poll not waking up on node disconnect? */
	}

	close_if(node->amaster);
	close_if(node->slavefd);
	close_if(node->fd);

	node_thread = node->thread;
	nodeid = node->id;
	skipjoin = node->skipjoin;

	bbs_node_unlock(node);

	if (!unique) {
		/* node is now no longer a valid reference, since bbs_node_handler calls node_free (in another thread) before it quits. */
		if (skipjoin) {
			bbs_debug(3, "Skipping join of node %d thread %lu\n", nodeid, node_thread);
		} else {
			bbs_debug(3, "Waiting for node %d to exit\n", nodeid);
			bbs_pthread_join(node_thread, NULL); /* Wait for the bbs_node_handler thread to exit, and then clean it up. */
		}
	} else {
		/* node_thread is what called this, so don't join ourself. Just go ahead and call node_free.
		 * It is safe to use node here since it will be freed in this thread after we return, no race condition. */
		bbs_debug(3, "Shutdown pending finalization for node %d\n", node->id);
	}
}

static void node_free(struct bbs_node *node)
{
	/* Wait for node_shutdown to release lock. */
	bbs_node_lock(node);
	if (node->module) {
		bbs_module_unref(node->module);
		node->module = NULL;
	}
	if (node->vars) {
		bbs_vars_destroy(node->vars);
		free(node->vars); /* Free the list itself */
		node->vars = NULL;
	}
	free_if(node->ip);
	bbs_debug(4, "Node %d now freed\n", node->id);
	bbs_verb(3, "Node %d has exited\n", node->id);
	bbs_node_unlock(node);
	pthread_mutex_destroy(&node->lock);
	free(node);
}

int bbs_node_unlink(struct bbs_node *node)
{
	struct bbs_node *n;

	RWLIST_WRLOCK(&nodes);
	RWLIST_TRAVERSE_SAFE_BEGIN(&nodes, n, entry) {
		if (node == n) {
			RWLIST_REMOVE_CURRENT(entry);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&nodes);

	if (!n) {
		bbs_error("Node %d not found in node list?\n", node->id);
		return -1;
	}

	node_shutdown(n, 1);
	/* If unlinking a single node, also free here */
	node_free(n);
	return 0;
}

int bbs_node_shutdown_node(unsigned int nodenum)
{
	struct bbs_node *n;

	RWLIST_WRLOCK(&nodes);
	RWLIST_TRAVERSE_SAFE_BEGIN(&nodes, n, entry) {
		if (n->id != nodenum) {
			continue;
		}
		RWLIST_REMOVE_CURRENT(entry);
		/* Wait for shutdown of node to finish. */
		node_shutdown(n, 0);
		break;
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&nodes);

	if (!n) {
		bbs_warning("Node %d not found in node list?\n", nodenum);
	}

	return n ? 0 : -1;
}

int bbs_node_shutdown_all(int shutdown)
{
	struct bbs_node *n;

	RWLIST_WRLOCK(&nodes);
	shutting_down = shutdown;
	while ((n = RWLIST_REMOVE_HEAD(&nodes, entry))) {
		/* Wait for shutdown of each node to finish. */
		node_shutdown(n, 0);
	}
	RWLIST_UNLOCK(&nodes);

	return 0;
}

int bbs_nodes_print(int fd)
{
	char elapsed[24];
	struct bbs_node *n;
	int c = 0;
	int now = time(NULL);

	bbs_dprintf(fd, "%3s %8s %9s %7s %-15s %-15s %15s %1s %1s %3s %3s %3s %3s %s\n", "#", "PROTOCOL", "ELAPSED", "TRM SZE", "USER", "MENU/PAGE", "IP ADDRESS", "E", "B", "FD", "MST", "SLV", "SPY", "SLV NAME");

	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, n, entry) {
		char menufull[16];
		bbs_node_lock(n);
		print_time_elapsed(n->created, now, elapsed, sizeof(elapsed));
		snprintf(menufull, sizeof(menufull), "%s%s%s%s", S_IF(n->menu), n->menuitem ? " (" : "", S_IF(n->menuitem), n->menuitem ? ")" : "");
		bbs_dprintf(fd, "%3d %8s %9s %3dx%3d %-15s %-15s %15s %1s %1s %3d %3d %3d %3d %s\n",
			n->id, n->protname, elapsed, n->cols, n->rows, bbs_username(n->user), menufull, n->ip, BBS_YN(n->echo), BBS_YN(n->buffered),
			n->fd, n->amaster, n->slavefd, n->spyfd, n->slavename);
		bbs_node_unlock(n);
		c++;
	}
	RWLIST_UNLOCK(&nodes);

	bbs_dprintf(fd, "%d active node%s\n", c, ESS(c));

	return 0;
}

int bbs_node_info(int fd, unsigned int nodenum)
{
	char elapsed[24];
	char connecttime[29];
	struct bbs_node *n;
	char menufull[16];
	int now = time(NULL);

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
#define BBS_FMT_DSD "%-20s : %d%s%d\n"

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

	pthread_mutex_lock(&n->lock);
	bbs_dprintf(fd, BBS_FMT_D, "#", n->id);
	bbs_dprintf(fd, BBS_FMT_S, "Protocol", n->protname);
	bbs_dprintf(fd, BBS_FMT_S, "IP Address", n->ip);
	bbs_dprintf(fd, BBS_FMT_S, "Connected", connecttime);
	bbs_dprintf(fd, BBS_FMT_S, "Elapsed", elapsed);
	bbs_dprintf(fd, BBS_FMT_DSD, "Term Size", n->cols, "x", n->rows);
	bbs_dprintf(fd, BBS_FMT_S, "Term Echo", BBS_YN(n->echo));
	bbs_dprintf(fd, BBS_FMT_S, "Term Buffered", BBS_YN(n->buffered));
	bbs_dprintf(fd, BBS_FMT_D, "Node FD", n->fd);
	bbs_dprintf(fd, BBS_FMT_D, "Node PTY Master FD", n->amaster);
	bbs_dprintf(fd, BBS_FMT_D, "Node PTY Slave FD", n->slavefd);
	bbs_dprintf(fd, BBS_FMT_S, "Node PTY Slave Name", n->slavename);
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
	bbs_vars_dump(fd, n);
	pthread_mutex_unlock(&n->lock);

#undef BBS_FMT_S
#undef BBS_FMT_D
#undef BBS_FMT_DSD

	RWLIST_UNLOCK(&nodes);
	return 0;
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
	RWLIST_UNLOCK(&nodes);

	if (n) {
		pthread_mutex_lock(&n->lock);
	}
	return n;
}

int bbs_node_update_winsize(struct bbs_node *node, int cols, int rows)
{
	struct winsize ws;
	pid_t child;
	int oldcols = node->cols, oldrows = node->rows;

	if (rows >= 0 && cols >= 0) {
		bbs_debug(3, "Node %d's terminal now has %d cols and %d rows\n", node->id, cols, rows);
		/* If this were a program that had forked and had children, then we might send a SIGWINCH.
		 * But we're not, so we don't. The menu and terminal routines will simply check cols/rows
		 * when drawing menus or other things on the screen.
		 */
		node->cols = cols;
		node->rows = rows;
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
	ws.ws_row = node->rows;
	ws.ws_col = node->cols;

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
		if (cols < oldcols || (rows < oldrows && cols > oldcols)) {
			char c = MENU_REFRESH_KEY;
			bbs_debug(5, "Screen size has changed (%dx%d -> %dx%d) such that a menu redraw is warranted\n", oldcols, oldrows, cols, rows);
			/* Don't even need an alertpipe - we know that we're in bbs_tread in the menu, spoof a special control char as input. */
			if (!node->buffered) {
				int wres = write(node->amaster, &c, 1);
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

int bbs_node_set_speed(struct bbs_node *node, unsigned int bps)
{
	int cps;
	int pauseus;

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

	if (bps == 0) {
		/* "Reset" to full speed with no artificial slowdowns */
		node->bps = 0;
		node->speed = 0;
		return 0;
	}

	cps = (int) ceil((1.0 * bps) / 8); /* Round characters per second up */
	pauseus = (int) floor(1000000.0 / cps); /* Round pause time between chars down */
	node->bps = bps;
	node->speed = pauseus;
	bbs_debug(3, "Set node %d speed to emulated %ubps (%d us/char)\n", node->id, bps, pauseus);
	return 0;
}

static int authenticate(struct bbs_node *node)
{
	int attempts;
	char username[64];
	char password[64];

	if (bbs_node_logged_in(node)) {
		bbs_error("Node %d is already logged in\n", node->id);
	}

#define MAX_AUTH_ATTEMPTS 3

	for (attempts = 0; attempts < MAX_AUTH_ATTEMPTS; attempts++) {
		NEG_RETURN(bbs_buffer(node));
		if (!NODE_IS_TDD(node)) {
			NEG_RETURN(bbs_writef(node, "%s%s %s%s %s%s %s%s", COLOR(COLOR_PRIMARY), "Enter", COLOR(COLOR_WHITE), "Username", COLOR(COLOR_PRIMARY), "or", COLOR(COLOR_WHITE), "New"));
			if (allow_guest) {
				NEG_RETURN(bbs_writef(node, " %s%s %s%s\n", COLOR(COLOR_PRIMARY), "or", COLOR(COLOR_WHITE), "Guest"));
			}
			NEG_RETURN(bbs_writef(node, "\n"));
		}

		NEG_RETURN(bbs_writef(node, "%s%-10s%s", COLOR(COLOR_PRIMARY), "Login: ", COLOR(COLOR_WHITE)));
		NONPOS_RETURN(bbs_readline(node, MIN_MS(1), username, sizeof(username)));
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
				bbs_writef(node, "%sUser registration aborted by system.\n", COLOR(COLOR_FAILURE));
				/* Don't even bother resetting the color, we're hanging up now */
			}
			return -1;
		} else if (!strcasecmp(username, "Guest")) {
			if (allow_guest) {
				bbs_debug(3, "User continuing as guest\n");
				if (guest_ask_info) {
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
				bbs_writef(node, "\n\n%s%s\n\n", COLOR(COLOR_RED), "Sorry, guest login is not permitted");
			}
		} else {
			/* Not a special keyword, so a normal username */
			int res;
			/* Don't echo the password, duh... */
			NEG_RETURN(bbs_echo_off(node));
			NEG_RETURN(bbs_writef(node, "%s%-10s%s", COLOR(COLOR_PRIMARY), "Password: ", COLOR(COLOR_WHITE)));
			NONPOS_RETURN(bbs_readline(node, 20000, password, sizeof(password)));
			res = bbs_authenticate(node, username, password);
			memset(password, 0, sizeof(password)); /* Overwrite (zero out) the plain text password before we return */
			NEG_RETURN(bbs_echo_on(node)); /* Turn echo back on */
			if (!res) {
				break; /* Correct username and password */
			}
			/* Sorry, wrong password. Let the user try again, if his/her 3 chances aren't up yet. */
			bbs_writef(node, "\n\n%s%s\n\n", COLOR(COLOR_RED), "Login Failed");
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

static int _bbs_intro(struct bbs_node *node)
{
	NEG_RETURN(bbs_clear_screen(node));
	NEG_RETURN(bbs_reset_color(node));
	NEG_RETURN(bbs_writef(node, "%s  Version %d.%d.%d\n", BBS_TAGLINE, BBS_MAJOR_VERSION, BBS_MINOR_VERSION, BBS_PATCH_VERSION));
	NEG_RETURN(bbs_writef(node, "%s connection from: %s\n", node->protname, node->ip));
	usleep(300000);
	return 0;
}

static int node_intro(struct bbs_node *node)
{
	char timebuf[29];

	if (!NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_clear_screen(node));
		NEG_RETURN(bbs_writef(node, "%s %d.%d.%d  %s\n\n", BBS_TAGLINE, BBS_MAJOR_VERSION, BBS_MINOR_VERSION, BBS_PATCH_VERSION, BBS_COPYRIGHT));
		usleep(150000);
		NEG_RETURN(bbs_writef(node, COLOR(COLOR_PRIMARY)));
	} else {
		/* Print some spaces as TDD carrier starts up, so we don't clip the beginning of output,
		 * and because the TDD could be in FIGS mode and this gives it a chance to get into LTRS mode. */
		NEG_RETURN(bbs_writef(node, "%10s", ""));
		/* Since the server will keep going until we block (hit a key),
		 * sleep explicitly as it will take some for the TDD to print the output anyways.
		 * This will allow the sysop to begin spying on the node here and catch the next output.
		 * Really, mainly to help with testing and debugging. */
		usleep(2500000);
		NEG_RETURN(bbs_writef(node, "%s %d.%d.%d  %s\n\n", BBS_SHORTNAME, BBS_MAJOR_VERSION, BBS_MINOR_VERSION, BBS_PATCH_VERSION, BBS_COPYRIGHT_SHORT));
	}

	NEG_RETURN(bbs_writef(node, "%s\n", bbs_name_buf)); /* Print BBS name */
	if (!s_strlen_zero(bbs_tagline)) {
		NEG_RETURN(bbs_writef(node, "%s\n\n", bbs_tagline)); /* Print BBS tagline */
	}

	if (!NODE_IS_TDD(node)) {
		bbs_time_friendly_now(timebuf, sizeof(timebuf));
		NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%s\n", COLOR(COLOR_WHITE), "CLIENT", COLOR(COLOR_SECONDARY), "CONN", COLOR(COLOR_PRIMARY), node->protname));
		NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "ADDR", COLOR(COLOR_PRIMARY), node->ip));
		NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%dx%d\n", "", "", COLOR(COLOR_SECONDARY), "TERM", COLOR(COLOR_PRIMARY), node->cols, node->rows));
		NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%s\n", COLOR(COLOR_WHITE), "SERVER", COLOR(COLOR_SECONDARY), "NAME", COLOR(COLOR_WHITE), bbs_name_buf));
		if (!s_strlen_zero(bbs_hostname_buf)) {
			NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "ADDR", COLOR(COLOR_PRIMARY), bbs_hostname_buf));
		}
		NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%d %s(of %s%d%s) - %s%s\n", "", "", COLOR(COLOR_SECONDARY), "NODE", COLOR(COLOR_PRIMARY),
			node->id, COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), bbs_maxnodes(), COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), bbs_get_osver()));
		NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "TIME", COLOR(COLOR_PRIMARY), timebuf));
		if (!s_strlen_zero(bbs_hostname_buf)) {
			NEG_RETURN(bbs_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "ADMN", COLOR(COLOR_PRIMARY), bbs_sysop));
		}
	} else {
		bbs_time_friendly_short_now(timebuf, sizeof(timebuf)); /* Use condensed date for TDDs */
		NEG_RETURN(bbs_writef(node, "Node %d - %s\n", node->id, timebuf));
	}

	usleep(300000);

	NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));

	/* Some protocols like SSH may support direct login of users. Otherwise, do a normal login. */
	if (!bbs_node_logged_in(node)) {
		NEG_RETURN(bbs_clear_line(node));
		NEG_RETURN(authenticate(node));
	}

	/* At this point, we are logged in. */
	bbs_assert(bbs_node_logged_in(node));

	/* Run any callbacks that should run on user login.
	 * We do it here rather than in bbs_authenticate, because the SSH module can do native login
	 * where bbs_node_logged_in will be true right above here.
	 * So doing it here ensures that, no matter how authentication happened, we run the code. */

	/* Make some basic variables available that can be used in menus.conf scripting
	 * For example, something in the menu could say Welcome ${BBS_USERNAME}!
	 */
	bbs_var_set_fmt(node, "BBS_NODENUM", "%d", node->id);
	bbs_var_set_fmt(node, "BBS_USERID", "%d", node->user->id);
	bbs_var_set_fmt(node, "BBS_USERPRIV", "%d", node->user->priv);
	bbs_var_set(node, "BBS_USERNAME", bbs_username(node->user));

	/*! \todo Notify user's friends that s/he's logged on now */
	/*! \todo Notify the sysop (sysop console), via BELL, that a new user has logged in, if and only if the sysop console is idle */

	NEG_RETURN(bbs_writef(node, COLOR_RESET "\r\n"));
	return 0;
}

static int bbs_node_statuses(struct bbs_node *node)
{
	struct bbs_node *n;

	NEG_RETURN(bbs_writef(node, "%s%s\n\n", COLOR(COLOR_WHITE), "Node Status"));
	RWLIST_RDLOCK(&nodes);
	RWLIST_TRAVERSE(&nodes, n, entry) {
		bbs_writef(node, "%s%3d  %s%s%s at %s menu via %s\n",
			COLOR(COLOR_WHITE), n->id, COLOR(COLOR_PRIMARY), bbs_username(n->user), COLOR(COLOR_SECONDARY), S_IF(n->menu), n->protname);
	}
	RWLIST_UNLOCK(&nodes);
	return 0;
}

static int bbs_node_splash(struct bbs_node *node)
{
	node->menu = "welcome"; /* Not really a menu, but it's a page and we should give it a name */
	NEG_RETURN(bbs_clear_screen(node));

#if 0
	NEG_RETURN(bbs_writef(node, "%sLast few callers:\n\n", COLOR(COLOR_PRIMARY)));
	/*! \todo Finish this: need to be able to retrieve past authentication info, e.g. from DB */
#endif

	/* System stats */
	if (!NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_writef(node, "%s%-20s: %s%s\n", COLOR(COLOR_SECONDARY), "System", COLOR(COLOR_PRIMARY), bbs_name_buf));
		NEG_RETURN(bbs_writef(node, "%s%6s%s %4u%9s%s: %s%s\n", COLOR(COLOR_SECONDARY), "User #", COLOR(COLOR_PRIMARY), node->user->id, "", COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), bbs_username(node->user)));
	} else {
		/* Omit the # sign since TDDs display # as $ */
		NEG_RETURN(bbs_writef(node, "User %d - %s\n", node->user->id, bbs_username(node->user)));
	}

	/*! \todo Add more stats here, e.g. num logins today, since started, lifetime, etc. */

	if (bbs_starttime() > (int) minuptimedisplayed) {
		char timebuf[24], daysbuf[36];
		int now = time(NULL);
		print_time_elapsed(bbs_starttime(), now, timebuf, sizeof(timebuf)); /* Formatting for timebuf (11 chars) should be enough for 11 years uptime, I think that's good enough */
		if (!NODE_IS_TDD(node)) {
			print_days_elapsed(bbs_starttime(), now, daysbuf, sizeof(daysbuf));
			NEG_RETURN(bbs_writef(node, "%s%6s%s %2s%-11s%s: %s%s\n", COLOR(COLOR_SECONDARY), "Uptime", COLOR(COLOR_PRIMARY), "", timebuf, COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), daysbuf));
		} else {
			NEG_RETURN(bbs_writef(node, "Uptime %s\n", timebuf)); /* Only print the condensed uptime */
		}
	}

#if 0
	/*! \todo Finish these and make them work */
	NEG_RETURN(bbs_writef(node, "%s%-20s: %s%5d %s%-9s%s%6d%s%s\n", COLOR(COLOR_SECONDARY), "Logons Today", COLOR(COLOR_PRIMARY), 1, COLOR(COLOR_SECONDARY), "(Max ", COLOR(COLOR_PRIMARY), 22, COLOR(COLOR_SECONDARY), ")"));
	NEG_RETURN(bbs_writef(node, "%s%-20s: %s%5d %s%-9s%s%6d%s%s\n", COLOR(COLOR_SECONDARY), "Time on Today", COLOR(COLOR_PRIMARY), 26, COLOR(COLOR_SECONDARY), "(Max ", COLOR(COLOR_PRIMARY), 86, COLOR(COLOR_SECONDARY), ")"));
	NEG_RETURN(bbs_writef(node, "%s%-20s: %s%5d %s%-9s%s%6d%s%s\n", COLOR(COLOR_SECONDARY), "Mail Waiting", COLOR(COLOR_PRIMARY), 0, COLOR(COLOR_SECONDARY), "(Unread ", COLOR(COLOR_PRIMARY), 0, COLOR(COLOR_SECONDARY), ")"));
#endif
	if (!s_strlen_zero(bbs_sysop) && !NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_writef(node, "%s%-20s: %s%s\n", COLOR(COLOR_SECONDARY), "Sysop is", COLOR(COLOR_PRIMARY), bbs_sysop));
	}

	NEG_RETURN(bbs_writef(node, "\n")); /* Separation before next section */
	if (!NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_node_statuses(node));
	}
	NEG_RETURN(bbs_wait_key(node, MIN_MS(2)));
	return 0;
}

static int bbs_goodbye(struct bbs_node *node)
{
	char sub[512];

	NEG_RETURN(bbs_clear_screen(node));
	bbs_substitute_vars(node, bbs_exitmsg, sub, sizeof(sub));
	NEG_RETURN(bbs_writef(node, "%s", sub));
	NEG_RETURN(bbs_wait_key(node, SEC_MS(12)));
	return 0;
}

static int node_handler_term(struct bbs_node *node)
{
	/* Set up the psuedoterminal */
	if (bbs_pty_allocate(node)) {
		bbs_debug(5, "Exiting\n");
		return -1;
	}
	if (defaultbps) {
		/* If there's a default speed to emulate, set it */
		bbs_node_set_speed(node, defaultbps);
	}

	if (!NODE_IS_TDD(node) && bbs_set_term_title(node, bbs_name_buf) <= 0) {
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

	/* Display welcome updates and alerts */
	if (bbs_node_splash(node)) {
		bbs_debug(5, "Exiting\n");
		return -1;
	} else if (bbs_node_menuexec(node)) { /* Run the BBS on this node. */
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
	bbs_assert(node->thread);
	bbs_assert(node->fd);
	bbs_assert_exists(node->protname); /* Will fail if a network comm driver forgets to set before calling bbs_node_handler */

	bbs_debug(1, "Running BBS for node %d\n", node->id);
	bbs_auth("New %s connection to node %d from %s\n", node->protname, node->id, node->ip);
}

void bbs_node_exit(struct bbs_node *node)
{
	bbs_node_lock(node);
	if (node->active) {
		bbs_node_unlock(node);
		/* User quit: unlink and free */
		bbs_node_unlink(node);
	} else {
		bbs_node_unlock(node);
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
