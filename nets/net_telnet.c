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
#include "include/tls.h"

static int telnet_socket = -1, telnets_socket = -1, tty_socket = -1, ttys_socket = -1; /*!< TCP Socket for allowing incoming network connections */
static pthread_t telnet_thread, telnets_thread, tty_thread;

/*! \brief Telnet port is 23 */
#define DEFAULT_TELNET_PORT 23

/*! \brief TELNETS (Telnet over TLS) port is 992 */
#define DEFAULT_TELNETS_PORT 992

static int telnet_port = DEFAULT_TELNET_PORT;
static int telnets_port = DEFAULT_TELNETS_PORT;
static int telnets_enabled = 0;
static int tty_port = 0, ttys_port = 0; /* Disabled by default */

static int telnet_send_command(int fd, unsigned char cmd, unsigned char opt)
{
	unsigned char ctl[] = {IAC, cmd, opt};
	ssize_t res = write(fd, ctl, 3);
	if (res <= 0) {
		if (errno != EPIPE) { /* Ignore if client just closed connection immediately */
			bbs_error("Failed to set telnet echo: %s\n", strerror(errno));
		}
	} else {
		/* telcmds[0] is EOF (236), so normalize the index to 236 */
		/* telopts[0] is simply 0, so no modification needed */
		bbs_debug(5, "Sent Telnet command: %s %s %s\n", telcmds[IAC - 236], telcmds[cmd - 236], telopts[opt]);
	}
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

	/* Disable Telnet echo or we'll get double echo when slave echo is on and single echo when it's off. */
	/* XXX Only for Telnet, not raw TCP */
	if (telnet_echo(node->wfd, 0)) {
		return -1;
	}

	/* RFC 1073 Request window size */
	if (telnet_send_command(node->wfd, DO, TELOPT_NAWS)) {
		return -1;
	}

	/* For telnet connections, we MAY get a connection string
	 * Don't get one with SyncTERM or PuTTY/KiTTY, but Windows Telnet client does send one.
	 * We should actually process this,
	 * until we do that, flush the input so that there's no input pending and we can use poll properly once the BBS starts. */

	usleep(100000); /* Wait a moment, in case the connection string is delayed arriving, or we'll skip it. */

	/* Process any Telnet commands received. Wait 100ms after sending our commands. */
	for (;;) {
		int res = bbs_poll(node->rfd, 100);
		if (res <= 0) {
			return res;
		}
		res = (int) read(node->rfd, buf, sizeof(buf));
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
				if (telnet_send_command(node->wfd, DONT, TELOPT_NAWS)) {
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
	node->cols = NUM_TDD_COLS;
	node->rows = 1;
	/* Note that because we don't actually call telnet_handshake,
	 * as we assume an actual TDD is on the other end of the connection,
	 * things like echo and input buffering which require Telnet commands
	 * will not be sent, so using a telnet client with the TTY port
	 * will be completely unsuitable. */
	return 0;
}

static void *telnet_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_comm_listener(telnet_socket, "TELNET", telnet_handshake, BBS_MODULE_SELF);
	return NULL;
}

/* A quick way to test this is simply: openssl s_client -port 992
 * However, I think s_client is cookied / canonical,
 * so input isn't flushed to the server until you hit ENTER locally.
 * Additionally, output that shouldn't be echoed obviously is.
 * A proper TELNETS client probably doesn't have this issue.
 * (And no, -nbio doesn't help with input buffering either)
 */
static void *telnets_handler(void *varg)
{
	struct bbs_node *node = varg;
	SSL *ssl = NULL;

	/* Yikes... a TELNETS client needs 3 threads:
	 * the network thread, the PTY thread,
	 * and the actual application thread.
	 * Please don't implement proper Telnet support
	 * as another intermediary layer that looks for 255 bytes,
	 * and add yet a fourth thread! */
	/* Set up TLS, then do the handshake, then proceed as normal. */
	ssl = ssl_new_accept(node->fd, &node->rfd, &node->wfd);
	if (!ssl) {
		bbs_node_exit(node); /* Since we're not calling bbs_node_handler, we're responsible for manually cleaning the node up */
		return NULL;
	}

	if (!telnet_handshake(node)) {
		bbs_node_handler(node); /* Run the normal node handler */
	}

	ssl_close(ssl);
	return NULL;
}

static void *tty_handler(void *varg)
{
	struct bbs_node *node = varg;
	SSL *ssl = NULL;

	if (!strcmp(node->protname, "TDDS")) {
		/* Use TDD for both secure and plaintext TDD. Used in NODE_IS_TDD macro. */
		node->protname = "TDD";
		bbs_debug(5, "Connection accepted on secure TTY port\n");
		ssl = ssl_new_accept(node->fd, &node->rfd, &node->wfd);
		if (!ssl) {
			bbs_node_exit(node);
			return NULL;
		}
	}

	tty_handshake(node);
	bbs_node_handler(node); /* Run the normal node handler */

	if (ssl) {
		ssl_close(ssl);
	}
	return NULL;
}

static void *telnets_listener(void *unused)
{
	UNUSED(unused);
	/* We need to start TLS before doing the application-level handshake, so use the generic TCP listener for TELNETS */
	bbs_tcp_listener(telnets_socket, "TELNETS", telnets_handler, BBS_MODULE_SELF);
	return NULL;
}

static void *tty_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener2(tty_socket, ttys_socket, "TDD", "TDDS", tty_handler, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("net_telnet.conf", 0);

	if (!cfg) {
		/* Assume defaults if we failed to load the config (e.g. file doesn't exist). */
		return 0;
	}

	telnet_port = DEFAULT_TELNET_PORT;
	bbs_config_val_set_port(cfg, "telnet", "port", &telnet_port);

	telnets_port = DEFAULT_TELNETS_PORT;
	bbs_config_val_set_port(cfg, "telnets", "port", &telnets_port);
	bbs_config_val_set_true(cfg, "telnets", "enabled", &telnets_enabled);

	if (telnets_enabled && !ssl_available()) {
		bbs_error("TLS is not available, TELNETS cannot be used\n");
		return -1;
	}

	tty_port = ttys_port = 0; /* Disabled by default */
	bbs_config_val_set_port(cfg, "telnet", "ttyport", &tty_port);
	bbs_config_val_set_port(cfg, "telnets", "ttyport", &ttys_port);

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
	if (telnets_enabled && bbs_make_tcp_socket(&telnets_socket, telnets_port)) {
		close(telnet_socket);
		return -1;
	}
	bbs_assert(telnet_socket >= 0);
	if (bbs_pthread_create(&telnet_thread, NULL, telnet_listener, NULL)) {
		close(telnet_socket);
		close_if(telnets_socket);
		telnet_socket = -1;
		return -1;
	}
	if (telnets_enabled && bbs_pthread_create(&telnets_thread, NULL, telnets_listener, NULL)) {
		close_if(telnets_socket);
		bbs_socket_thread_shutdown(&telnet_socket, telnet_thread);
		return -1;
	}
	if (tty_port || ttys_port) {
		if (tty_port) {
			if (bbs_make_tcp_socket(&tty_socket, tty_port)) {
				return -1;
			}
		}
		if (ttys_port) {
			if (bbs_make_tcp_socket(&ttys_socket, ttys_port)) {
				close_if(tty_socket);
				return -1;
			}
		}
		if (bbs_pthread_create(&tty_thread, NULL, tty_listener, NULL)) {
			bbs_socket_thread_shutdown(&telnet_socket, telnet_thread);
			if (telnets_enabled) {
				bbs_socket_thread_shutdown(&telnets_socket, telnets_thread);
			}
			close_if(tty_socket);
			close_if(ttys_socket);
			return -1;
		}
	}
	bbs_register_network_protocol("TELNET", (unsigned int) telnet_port);
	if (telnets_enabled) {
		bbs_register_network_protocol("TELNETS", (unsigned int) telnets_port);
	}
	return 0;
}

static int unload_module(void)
{
	if (tty_socket > -1 || ttys_socket > -1) {
		if (tty_socket != -1) {
			bbs_socket_close(&tty_socket);
		}
		if (ttys_socket != -1) {
			bbs_socket_close(&ttys_socket);
		}
		bbs_pthread_join(tty_thread, NULL);
	}
	if (telnet_socket > -1) {
		bbs_unregister_network_protocol((unsigned int) telnet_port);
		if (telnets_socket > -1) {
			bbs_unregister_network_protocol((unsigned int) telnets_port);
		}
		bbs_socket_thread_shutdown(&telnet_socket, telnet_thread);
		if (telnets_enabled) {
			bbs_socket_thread_shutdown(&telnets_socket, telnets_thread);
		}
	} else {
		bbs_error("Telnet socket already closed at unload?\n");
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC854 Telnet and TTY/TDD");
