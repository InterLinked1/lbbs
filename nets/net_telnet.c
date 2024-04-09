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
 * \note Supports RFC 857 Echo
 * \note Supports RFC 858 Suppress Go Ahead
 * \note Supports RFC 1073 Window Size
 * \note Supports RFC 1079 Terminal Speed
 * \note Supports RFC 1091 Terminal Type
 * \note Supports RFC 1116 Line Mode (disabling only)
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
	ssize_t res = write(fd, ctl, ARRAY_LEN(ctl));
	if (res <= 0) {
		if (errno != EPIPE) { /* Ignore if client just closed connection immediately */
			bbs_error("Failed to set telnet echo: %s\n", strerror(errno));
		}
	} else {
		/* telcmds[0] is EOF (236), so normalize the index to 236 */
		/* telopts[0] is simply 0, so no modification needed */
		bbs_debug(5, "Sent Telnet command: %s %s %s\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt]);
	}
	return res <= 0 ? -1 : 0;
}

static int telnet_send_command6(int fd, unsigned char cmd, unsigned char opt, unsigned char opt2, unsigned char opt3, unsigned char opt4)
{
	unsigned char ctl[] = {IAC, cmd, opt, opt2, opt3, opt4};
	ssize_t res = write(fd, ctl, ARRAY_LEN(ctl));
	if (res <= 0) {
		if (errno != EPIPE) { /* Ignore if client just closed connection immediately */
			bbs_error("Failed to set telnet echo: %s\n", strerror(errno));
		}
	} else {
		/* telcmds[0] is EOF (236), so normalize the index to 236 */
		/* telopts[0] is simply 0, so no modification needed */
		bbs_debug(5, "Sent Telnet command: %s %s %s %s %s %s\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt], telopts[opt2], telcmds[opt3 - xEOF], telcmds[opt4 - xEOF]);
	}
	return res <= 0 ? -1 : 0;
}

struct telnet_settings {
	unsigned int rcv_noecho:1;
	unsigned int sent_winsize:1;
};

static int telnet_read_command(int fd, unsigned char *buf, size_t len)
{
	ssize_t res = bbs_poll(fd, 150);
	if (res <= 0) {
		bbs_debug(4, "poll returned %ld: %s\n", res, strerror(errno));
		return (int) res;
	}
	res = read(fd, buf, len - 1);
	/* Process the command */
	if (res <= 0) {
		bbs_debug(4, "read returned %ld: %s\n", res, strerror(errno));
		return (int) res;
	} else if (res >= 3) {
		int a, b, c;
		buf[res] = '\0'; /* Don't read uninitialized memory later */
		if (buf[0] != IAC) {
			/* Got something that wasn't the beginning of a telnet command */
			bbs_debug(3, "Read %d %d %d, aborting handshake\n", buf[0], buf[1], buf[2])
			return 0;
		}
		/* Don't let the client make us index out of bounds */
		if (!TELCMD_OK(buf[0]) || !TELCMD_OK(buf[1])) {
			bbs_warning("Got out of bounds command: %d %d %d\n", buf[0], buf[1], buf[2]);
			return 0;
		}
		if (!TELOPT_OK(buf[2])) {
			bbs_warning("Got out of bounds option: %d %d %d\n", buf[0], buf[1], buf[2]);
			return 0;
		}
		a = buf[0] - xEOF; /* We know this is IAC */
		b = buf[1] - xEOF;
		c = buf[2];
		bbs_assert(telcmds[a] != NULL);
		bbs_assert(telcmds[b] != NULL);
		bbs_assert(telopts[c] != NULL);
		bbs_debug(3, "Received Telnet command %s %s %s\n", telcmds[a], telcmds[b], telopts[c]);
		return (int) res;
	} else {
		bbs_warning("Read %ld bytes, not enough to do anything with, discarding\n", res);
		return 0;
	}
}

#define telnet_process_command(node, settings, buf, len, res) __telnet_process_command(node, settings, buf, len, res, depth + 1)

static int __telnet_process_command(struct bbs_node *node, struct telnet_settings *settings, unsigned char *buf, size_t len, int res, int depth)
{
	if (depth > 3) {
		/* Prevent infinite recursion if the client replies with the same thing that triggered another command */
		bbs_warning("Exceeded command stack depth %d\n", depth);
		return 0;
	}

	if (buf[1] == DO && buf[2] == TELOPT_ECHO) {
		settings->rcv_noecho = 1;
		bbs_debug(3, "Client acknowledged local echo disable\n");
	} else if (buf[1] == WILL && buf[2] == TELOPT_NAWS) {
		if (!settings->sent_winsize) {
			if (telnet_send_command(node->wfd, DO, TELOPT_NAWS)) {
				return -1;
			}
			settings->sent_winsize = 1;
		}
		/* Read terminal type, coming up next */
		res = telnet_read_command(node->rfd, buf, len);
		if (res > 0) {
			res = telnet_process_command(node, settings, buf, len, res);
		}
	} else if (buf[1] == WONT && buf[2] == TELOPT_NAWS) {
		/* Client disabled NAWS, at our request, good. */
		res = 1;
	} else if (buf[1] == SB && buf[2] == TELOPT_NAWS) {
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
		res = telnet_read_command(node->rfd, buf, len);
		if (res > 0) {
			res = telnet_process_command(node, settings, buf, len, res);
		}
	} else if (buf[1] == WILL && buf[2] == TELOPT_TTYPE) {
		/* Client supports sending terminal type */
		if (telnet_send_command6(node->wfd, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE)) {
			return -1;
		}
		res = telnet_read_command(node->rfd, buf, len);
		if (res < 0) {
			return res;
		} else if (res > 0) {
			if (buf[1] == SB && buf[2] == TELOPT_TTYPE && buf[3] == TELQUAL_IS && res >= 6) {
				bbs_debug(3, "Terminal type is %.*s\n", (int) res - 6, buf + 4); /* First 4 bytes are command, and last two are IAC SE */
				if (res - 6 < (int) len - 1) {
					memcpy(buf, buf + 4, (size_t) res - 6);
					buf[res - 6] = '\0';
					REPLACE(node->term, (char*) buf);
				}
			} else {
				bbs_warning("Foreign %d-byte response received in response to terminal type\n", res);
			}
		}
	} else if (buf[1] == WILL && buf[2] == TELOPT_TSPEED) {
		/* Client supports sending terminal speed */
		if (telnet_send_command6(node->wfd, SB, TELOPT_TSPEED, TELQUAL_SEND, IAC, SE)) {
			return -1;
		}
		res = telnet_read_command(node->rfd, buf, len);
		if (res < 0) {
			return res;
		} else if (res > 0) {
			if (buf[1] == SB && buf[2] == TELOPT_TSPEED && buf[3] == TELQUAL_IS && res >= 3) {
				bbs_debug(3, "Terminal speed is %.*s\n", (int) res - 6, buf + 4); /* First 4 bytes are command, and last two are IAC SE */
				if (res - 6 < (int) len - 1) {
					memcpy(buf, buf + 4, (size_t) res - 6);
					buf[res - 6] = '\0';
					node->reportedbps = (unsigned int) atoi((char*) buf);
				}
			} else {
				bbs_warning("Foreign %d-byte response received in response to terminal type\n", res);
			}
		}
	} else {
		bbs_debug(3, "Ignoring unhandled response %d %d %d\n", buf[0], buf[1], buf[2]);
	}
	return 1;
}

static int read_and_process_command(struct bbs_node *node, struct telnet_settings *settings, unsigned char *buf, size_t len)
{
	int depth = 0;
	int res = telnet_read_command(node->rfd, buf, len);
	if (res > 0) {
		res = telnet_process_command(node, settings, buf, len, res);
	}
	return res;
}

static int telnet_handshake(struct bbs_node *node)
{
	int res;
	struct telnet_settings settings;
	unsigned char buf[32];

	memset(&settings, 0, sizeof(settings));

	/* RFC 857 Disable Telnet echo or we'll get double echo when slave echo is on and single echo when it's off. */

	/* http://www.verycomputer.com/174_d636f401932e1db5_1.htm
	 * If using telnet as a TCP client, this will properly disable echo.
	 * This is necessary, in addition to actually setting the termios as normal.
	 * If you are using netcat, make sure to disable canonical mode and echo when launching
	 * netcat, i.e.: stty -icanon -echo && nc 127.0.0.1 23
	 *
	 * Might seem backwards to do WILL echo to turn local echo off, but think of it as
	 * us saying that WE'LL do the echoing so local echo, please stop. */
	if (telnet_send_command(node->wfd, WILL, TELOPT_ECHO)) {
		return -1;
	}

	/* Send the following to disable line buffering and make the terminal "uncooked" from a Telnet perspective.
	 * In particular, this is needed to get PuTTY to work properly, since it will assume cooked by default. */
	if (telnet_send_command(node->wfd, WILL, TELOPT_SGA)) { /* Suppress Go Ahead */
		return -1;
	} else if (telnet_send_command(node->wfd, WONT, TELOPT_LINEMODE)) { /* Disable line mode */
		return -1;
	}

	/* Read anything the client sends upon connect, if anything.
	 * For example, some clients, like SyncTERM, will acknowledge everything with a response,
	 * while others, like PuTTY, will not. */
	do {
		res = read_and_process_command(node, &settings, buf, sizeof(buf));
	} while (res > 0);
	if (res < 0) {
		return -1;
	}

	/* RFC 1073 Request window size */
	if (!settings.sent_winsize) {
		settings.sent_winsize = 1;
		if (telnet_send_command(node->wfd, DO, TELOPT_NAWS)) {
			return -1;
		}
		res = read_and_process_command(node, &settings, buf, sizeof(buf));
		if (res < 0) {
			return res;
		}
	}

	/* RFC 1091 Terminal Type */
	if (telnet_send_command(node->wfd, DO, TELOPT_TTYPE)) {
		return -1;
	}
	res = read_and_process_command(node, &settings, buf, sizeof(buf));
	if (res < 0) {
		return res;
	}

	/* RFC 1079 Terminal Speed */
	if (telnet_send_command(node->wfd, DO, TELOPT_TSPEED)) {
		return -1;
	}
	res = read_and_process_command(node, &settings, buf, sizeof(buf));
	if (res < 0) {
		return res;
	}

	if (!settings.rcv_noecho) {
		bbs_debug(3, "Request to enable ECHO not yet acknowledged, retrying\n");
		if (telnet_send_command(node->wfd, WONT, TELOPT_ECHO) || telnet_send_command(node->wfd, WILL, TELOPT_ECHO)) {
			return -1;
		}
	}

	/* Read anything leftover, if anything */
	do {
		res = read_and_process_command(node, &settings, buf, sizeof(buf));
	} while (res > 0);
	if (res < 0) {
		return -1;
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

	/* Yikes... a TELNETS client needs 3 threads:
	 * the network thread, the PTY thread,
	 * and the actual application thread.
	 * Please don't implement proper Telnet support
	 * as another intermediary layer that looks for 255 bytes,
	 * and add yet a fourth thread! */
	/* Set up TLS, then do the handshake, then proceed as normal. */
	if (bbs_node_starttls(node)) {
		bbs_node_exit(node); /* Since we're not calling bbs_node_handler, we're responsible for manually cleaning the node up */
		return NULL;
	}

	if (!telnet_handshake(node)) {
		bbs_node_handler(node); /* Run the normal node handler */
	} else {
		bbs_node_exit(node); /* Manual cleanup */
	}

	return NULL;
}

static void *tty_handler(void *varg)
{
	struct bbs_node *node = varg;

	if (!strcmp(node->protname, "TDDS")) {
		/* Use TDD for both secure and plaintext TDD. Used in NODE_IS_TDD macro. */
		node->protname = "TDD";
		bbs_debug(5, "Connection accepted on secure TTY port\n");
		if (bbs_node_starttls(node)) {
			bbs_node_exit(node);
			return NULL;
		}
	}

	tty_handshake(node);
	bbs_node_handler(node); /* Run the normal node handler */

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
	struct bbs_config *cfg = bbs_config_load("net_telnet.conf", 1);

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
