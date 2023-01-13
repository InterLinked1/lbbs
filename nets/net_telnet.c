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
 * \brief Telnet and TTY/TDD network driver
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
#include <netinet/in.h> /* use sockaddr_in */
#include <pthread.h>
#include <signal.h> /* use pthread_kill */

/* Expose the telcmds and telopts string arrays */
#define TELCMDS
#define TELOPTS
#include "arpa/telnet.h"

#include "include/module.h"
#include "include/node.h"
#include "include/pty.h" /* use bbs_pty_allocate */
#include "include/utils.h"
#include "include/config.h"
#include "include/net.h"

static int telnet_socket = -1, tty_socket = -1; /*!< TCP Socket for allowing incoming network connections */
static pthread_t telnet_thread, tty_thread;

/*! \brief Telnet port is 23 */
#define DEFAULT_TELNET_PORT 23

static int telnet_port = DEFAULT_TELNET_PORT;
static int tty_port = 0; /* Disabled by default */

static int telnet_send_command(int fd, unsigned char cmd, unsigned char opt)
{
	unsigned char ctl[] = {IAC, cmd, opt};
	int res = write(fd, ctl, 3);
	if (res <= 0) {
		bbs_error("Failed to set telnet echo\n");
	}
	/* telcmds[0] is EOF (236), so normalize the index to 236 */
	/* telopts[0] is simply 0, so no modification needed */
	bbs_debug(5, "Sent Telnet command: %s %s %s\n", telcmds[IAC - 236], telcmds[cmd - 236], telopts[opt]); 
	return res <= 0 ? -1 : 0; 
}

/*!
 * \brief Disable or enable Telnet's local echo
 * \retval Same as write
 */
static int telnet_echo(int fd, int echo)
{
	/* http://www.verycomputer.com/174_d636f401932e1db5_1.htm */
	/* If using telnet as a TCP client, this will properly disable echo.
	 * This is necessary, in addition to actually setting the termios as normal.
	 * If you are using netcat, make sure to disable canonical mode and echo when launching
	 * netcat, i.e.: stty -icanon -echo && nc 127.0.0.1 23
	 */

	/* Might seem backwards to do WILL echo to turn local echo off, but think of it as
	 * us saying that WE'LL do the echoing so local echo, please stop. */
	return telnet_send_command(fd, echo ? WONT : WILL, TELOPT_ECHO);
}

static int telnet_handshake(struct bbs_node *node)
{
	unsigned char buf[32];
	int res;

	/* Disable Telnet echo or we'll get double echo when slave echo is on and single echo when it's off. */
	/* XXX Only for Telnet, not raw TCP */
	if (telnet_echo(node->fd, 0)) {
		return -1;
	}

	/* RFC 1073 Request window size */
	if (telnet_send_command(node->fd, DO, TELOPT_NAWS)) {
		return -1;
	}

	/* For telnet connections, we MAY get a connection string
	 * Don't get one with SyncTERM or PuTTY/KiTTY, but Windows Telnet client does send one.
	 * We should actually process this,
	 * until we do that, flush the input so that there's no input pending and we can use poll properly once the BBS starts. */

	usleep(100000); /* Wait a moment, in case the connection string is delayed arriving, or we'll skip it. */

	/* Process any Telnet commands received. Wait 100ms after sending our commands. */
	for (;;) {
		res = bbs_std_poll(node->fd, 100);
		if (res <= 0) {
			return res;
		}
		res = read(node->fd, buf, sizeof(buf));
		/* Process the command */
		if (res <= 0) {
			return res;
		} else if (res >= 3) {
			int a, b, c;
			if (buf[0] != IAC) {
				/* Got something that wasn't the beginning of a telnet command */
				bbs_debug(3, "Read %d %d %d, aborting handshake\n", buf[0], buf[1], buf[2])
				break;
			}
			/* Don't let the client make us index out of bounds */
			if (!IN_BOUNDS(buf[0], xEOF, IAC) || !IN_BOUNDS(buf[1], xEOF, IAC) || !IN_BOUNDS(buf[2], TELOPT_BINARY, TELOPT_EXOPL)) {
				bbs_warning("Got out of bounds command: %d %d %d\n", buf[0], buf[1], buf[2]);
				break;
			}
			a = buf[0] - xEOF; /* We know this is IAC */
			b = buf[1] - xEOF;
			c = buf[2];
			bbs_debug(3, "Received Telnet command: %s %s %s\n", telcmds[a], telcmds[b], telopts[c]);
			if (buf[1] == SB && buf[2] == TELOPT_NAWS) {
				/* Get the window size
				 * IAC SB NAWS WIDTH[1] WIDTH[0] HEIGHT[1] HEIGHT[0] IAC SE
				 * According to RFC 1073, there are 2 bytes for the width and the height each,
				 * to support clients with a window height/width of up to 65536 rows/cols.
				 * I'm sorry, there's no way there are any clients with screens that large.
				 * Here's what these bytes would look for a standard 80x24 terminal:
				 * 0 80 0 24 255 240
				 * So we can simply ignore WIDTH[1] and HEIGHT[1] altogether.
				 */
				if (res >= 9) {
					bbs_debug(7, "Got %d %d %d %d %d %d\n", buf[3], buf[4], buf[5], buf[6], buf[7], buf[8]);
					bbs_node_update_winsize(node, buf[4], buf[6]);
				} else {
					bbs_warning("Received window subnegotiation, but only got %d bytes?\n", res);
				}

				/* XXX Now, tell the client not to send window updates
				 * Because we're going to step out of the way and all socket I/O is going to
				 * go right into the PTY master, we won't be able to intercept future Telnet
				 * commands, so if a window update is sent, we won't be able to process it.
				 * It would probably be better to add an intermediate layer here to handle that
				 * (similar to what the SSH module does).
				 * Or, the PTY thread could handle telnet commands (beginning with IAC),
				 * if node->protname == "Telnet", but that would break the abstraction
				 * that the BBS has from the communications protocol.
				 *
				 * Either way, for now, we don't support window updates.
				 */
				if (telnet_send_command(node->fd, DONT, TELOPT_NAWS)) {
					return -1;
				}
			}
		} else {
			bbs_warning("Read %d bytes, not enough to do anything with, discarding\n", res);
		}
	}

	return 0;
}

static int tty_handshake(struct bbs_node *node)
{
	/* Not really a handshake, just use this as a callback to set a few things */
	node->ansi = 0; /* TDDs don't support ANSI escape sequences, disable them */
	/* Assume standard TDD screen size */
	node->rows = 24;
	node->cols = 1;
	return 0;
}

static void *telnet_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_comm_listener(telnet_socket, "Telnet", telnet_handshake, BBS_MODULE_SELF);
	return NULL;
}

static void *tty_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_comm_listener(tty_socket, "TDD", tty_handshake, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	const char *val;
	int tmp;
	struct bbs_config *cfg = bbs_config_load("net_telnet.conf", 0);

	if (!cfg) {
		/* Assume defaults if we failed to load the config (e.g. file doesn't exist). */
		return 0;
	}

	val = bbs_config_val(cfg, "telnet", "port");
	if (val) {
		tmp = atoi(val);
		if (PORT_VALID(tmp)) {
			telnet_port = tmp;
		} else {
			bbs_warning("Invalid Telnet port: %s\n", val);
		}
	} else {
		telnet_port = DEFAULT_TELNET_PORT;
	}

	val = bbs_config_val(cfg, "telnet", "ttyport");
	if (val) {
		tmp = atoi(val);
		if (PORT_VALID(tmp)) {
			tty_port = tmp;
		} else {
			bbs_warning("Invalid TTY port: %s\n", val);
		}
	} else {
		tty_port = 0;
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	/* If we can't start the TCP listener, decline to load */
	if (bbs_make_tcp_socket(&telnet_socket, telnet_port)) {
		return -1;
	}
	bbs_assert(telnet_socket >= 0);
	if (bbs_pthread_create(&telnet_thread, NULL, telnet_listener, NULL)) {
		close(telnet_socket);
		telnet_socket = -1;
		return -1;
	}
	if (tty_port) {
		if (bbs_make_tcp_socket(&tty_socket, tty_port)) {
			return -1;
		}
		if (bbs_pthread_create(&tty_thread, NULL, tty_listener, NULL)) {
			close(tty_socket);
			tty_socket = -1;
			return -1;
		}
	}
	bbs_register_network_protocol("Telnet", telnet_port);
	return 0;
}

static int unload_module(void)
{
	if (tty_socket > -1) {
		close(tty_socket);
		tty_socket = -1;
		pthread_cancel(tty_thread);
		pthread_kill(tty_thread, SIGURG);
		bbs_pthread_join(tty_thread, NULL);
	}
	if (telnet_socket > -1) {
		bbs_unregister_network_protocol(telnet_port);
		close(telnet_socket);
		telnet_socket = -1;
		pthread_cancel(telnet_thread);
		pthread_kill(telnet_thread, SIGURG);
		bbs_pthread_join(telnet_thread, NULL);
	} else {
		bbs_error("Telnet socket already closed at unload?\n");
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC854 Telnet and TTY/TDD");
