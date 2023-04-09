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
 * \brief Unix Domain Socket server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>	/* use struct sockaddr_un */
#include <pthread.h>
#include <sys/stat.h> /* use chmod */

#include "include/module.h"
#include "include/node.h"
#include "include/utils.h" /* use bbs_pthread_create_detached */

static int uds_socket = -1; /*!< UDS socket for allowing incoming local UNIX connections */
static pthread_t uds_thread;

/*! \brief Socket file */
#define BBS_RUN_SOCKET DIRCAT(DIRCAT("/var/run", BBS_NAME), "bbs.sock")

#define BBS_CTL_PERMISSIONS ""

/*
 * If you're wondering, you can use socat locally to connect to a UNIX domain socket, i.e.
 * stty -icanon -echo && socat - UNIX-CONNECT:/var/run/lbbs/bbs.sock ; reset
 *
 * First, if connecting from a local terminal session, you need to disable canonical mode
 * and echo in the terminal session so that the BBS's terminal settings apply correctly.
 * Finally, when done, reset the terminal back to normal.
 *
 * It's worth noting that this comm driver can be used to provide access to the BBS
 * from a standard shell session. For example, if you have an SSH user configured
 * using the system's normal SSH server, you can have it launch a shell script
 * that runs the commands above, as opposed to providing a shell, to provide access to the BBS.
 * i.e. You can use your normal network login services (telnetd, sshd, etc.) and simply
 * execute the BBS as a program, rather than accepting network connections directly from within the BBS.
 * Simply make the account credentials publicly available, since anyone who connects will just get the BBS.
 *
 * This offloads the responsibility of network I/O from the BBS to the rest of your system, and also
 * means you don't need to juggle port conflicts if you'd like the BBS to run on the well-known ports (e.g. 22, 23, etc.)
 * but you want those to be handled by the system network login services instead.
 *
 * NOTE: You are much better of proxying to the BBS's SSH module even if it's running on a different port.
 *       For example, exec ssh localhost -p 2222
 * The UNIX socket driver will not properly pass signals and does not support window sizing. It's very primitive.
 * You are advised to avoid using this module for production usage.
 *
 *                                *** WARNING WARNING WARNING ***
 * If you do the above, you have essentially created a normal user account with public access on your server.
 * If you do this, be sure to disable X11 forwarding and TCP forwarding, or you will allow anyone on the entire
 * Internet to connect to ports on your system, where they can do all kinds of malicious things, e.g. send
 * email if you have a local mail server setup like postfix (simply by connecting to the postfix socket).
 * You have been warned!
 *
 * To secure your system, add the following to your /etc/ssh/sshd_config:
 * (assumes the public user account is named 'bbs'):
 *
 * Match User bbs
 *   X11Forwarding no
 *   AllowTcpForwarding no
 *
 */

static void *uds_listener(void *unused)
{
	struct sockaddr_un sunaddr;
	socklen_t len;
	int sfd, res;
	struct pollfd pfd;

	UNUSED(unused);

	pfd.fd = uds_socket;
	pfd.events = POLLIN;

	bbs_debug(1, "Started UDS listener thread\n");

	for (;;) {
		struct bbs_node *node;
		res = poll(&pfd, 1, -1); /* Wait forever for an incoming connection. */
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (pfd.revents) {
			bbs_debug(1, "Accepting new UDS connection\n");
			len = sizeof(sunaddr);
			sfd = accept(uds_socket, (struct sockaddr *) &sunaddr, &len);
		} else {
			continue; /* Shouldn't happen? */
		}
		if (sfd < 0) {
			if (errno != EINTR) {
				bbs_warning("accept returned %d: %s\n", sfd, strerror(errno));
				break;
			}
			continue;
		}

		node = bbs_node_request(sfd, "UNIX");
		if (!node) {
			close(sfd);
			continue;
		}

		node->ip = strdup("127.0.0.1"); /* Connection is from localhost */

		/* Run the BBS on this node */
		if (bbs_pthread_create_detached(&node->thread, NULL, bbs_node_handler, node)) {
			bbs_node_unlink(node);
			continue;
		}
	}
	/* Normally, we never get here, as pthread_cancel snuffs out the thread ungracefully */
	bbs_warning("UDS listener thread exiting abnormally\n");
	return NULL;
}

static int load_module(void)
{
	/* If we can't start the UDS listener, decline to load */
	if (bbs_make_unix_socket(&uds_socket, BBS_RUN_SOCKET, BBS_CTL_PERMISSIONS, -1, -1)) {
		return -1;
	}
	bbs_assert(uds_socket >= 0);
	if (bbs_pthread_create(&uds_thread, NULL, uds_listener, NULL)) {
		close(uds_socket);
		uds_socket = -1;
		return -1;
	}
	return 0;
}

static int unload_module(void)
{
	if (uds_socket > -1) {
		close(uds_socket);
		uds_socket = -1;
		bbs_pthread_cancel_kill(uds_thread);
		bbs_pthread_join(uds_thread, NULL);
		unlink(BBS_RUN_SOCKET);
	} else {
		bbs_error("UDS socket already closed at unload?\n");
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("UNIX Domain Sockets");
