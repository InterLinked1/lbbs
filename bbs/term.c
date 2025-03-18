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
 * \brief BBS terminal manipulation
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h> /* use memset */
#include <termios.h>
#include <unistd.h> /* use write */

#include "include/node.h"
#include "include/term.h"
#include "include/socket.h" /* use bbs_fd_valid, don't need full utils.h */

#pragma GCC diagnostic ignored "-Wsign-conversion"
static int bbs_input_set(int fd, int canonical, int echo)
{
	struct termios term;

	memset(&term, 0, sizeof(term)); /* Prevent valgrind: Syscall param ioctl(TCSET{S,SW,SF}) points to uninitialised byte(s) */

	if (tcgetattr(fd, &term)) {
		bbs_error("tcgetattr(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	if (canonical) {
		term.c_lflag |= ICANON;
	} else {
		term.c_lflag &= ~ICANON; /* Disable canonical mode to disable input buffering */
	}
	if (echo) {
		term.c_lflag |= ECHO;
	} else {
		term.c_lflag &= ~ECHO;
	}
	if (tcsetattr(fd, TCSANOW, &term)) {
		bbs_error("tcsetattr(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_echo(int fd, int echo)
{
	struct termios term;

	memset(&term, 0, sizeof(term)); /* Prevent valgrind: Syscall param ioctl(TCSET{S,SW,SF}) points to uninitialised byte(s) */

	if (tcgetattr(fd, &term)) {
		bbs_error("tcgetattr(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	if (echo) {
		term.c_lflag |= ECHO;
	} else {
		term.c_lflag &= ~ECHO;
	}
	if (tcsetattr(fd, TCSANOW, &term)) {
		bbs_error("tcsetattr(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	return 0;
}
#pragma GCC diagnostic pop

int bbs_unbuffer_input(int fd, int echo)
{
	return bbs_input_set(fd, 0, echo);
}

int bbs_buffer_input(int fd, int echo)
{
	return bbs_input_set(fd, 1, echo);
}

static int bbs_node_set_input(struct bbs_node *node, int buffered, int echo)
{
	int res;

	/* Don't lock the node in this function, node_shutdown calls this with the lock held */

	/* We're going to disable/enable buffering on the slave end of the node's PTY.
	 * You can't perform terminal operations directly on socket file descriptors. */
	if (node->slavefd == -1) {
		bbs_error("Node %d has no slave fd\n", node->id);
		return -1;
	}

	if (NODE_IS_TDD(node) && echo) {
		bbs_debug(6, "Overriding echo to OFF for TDD on node %d\n", node->id); /* See comment in bbs_node_echo about TDDs and echo */
		echo = 0;
	}

	if (node->buffered == buffered && node->echo == echo) {
		bbs_debug(6, "Buffering/echo settings (%d/%d) have not changed for node %d\n", node->buffered, node->echo, node->id);
		return 0; /* Nothing is changing. */
	}

	res = bbs_input_set(node->slavefd, buffered, echo);

	if (!res) {
		bbs_debug(5, "Node %d (fd %d): input now %s, echo %s\n", node->id, node->slavefd, buffered ? "buffered" : "unbuffered", echo ? "enabled" : "disabled");
		SET_BITFIELD(node->buffered, buffered);
		SET_BITFIELD(node->echo, echo);
	}
	return 0;
}

int bbs_node_unbuffer_input(struct bbs_node *node, int echo)
{
	/* Do not lock the node here: node_shutdown already holds it */
	return bbs_node_set_input(node, 0, echo);
}

int bbs_node_buffer_input(struct bbs_node *node, int echo)
{
	/* Do not lock the node here: node_shutdown already holds it */
	return bbs_node_set_input(node, 1, echo);
}

int bbs_node_echo(struct bbs_node *node, int echo)
{
	int res;

	if (NODE_IS_TDD(node) && echo) {
		/* Echo should always be disabled for TDDs, since they *always* do a local echo.
		 * If we also echo, then the pseudoterminal echoing back input will lead to double input.
		 * Furthermore, because TDDs are half duplex, we'll start sending "output" (the echo)
		 * while the user is inputting stuff, and that will totally screw everything up.
		 * (For one, it causes TDDs to stop input, send a CR LF, and wait for output to stop) */
		bbs_debug(6, "Not setting echo on for TDD on node %d\n", node->id);
		return 0;
	}

	if (node->echo == echo) {
		bbs_debug(6, "Echo setting (%d) has not changed for node %d\n", echo, node->id);
		return 0;
	}

	res = bbs_echo(node->slavefd, echo);

	if (!res) {
		SET_BITFIELD(node->echo, echo);
	}
	return res;
}

#pragma GCC diagnostic ignored "-Wsign-conversion"
int bbs_term_makeraw(int fd)
{
	struct termios t;

	if (!isatty(fd)) {
		bbs_error("File descriptor %d is not a TTY\n", fd);
		return -1;
	} else if (tcgetattr(fd, &t) == -1) {
		bbs_error("tcgetattr(%d): %s\n", fd, strerror(errno));
		return -1;
	}

	t.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO); /* Noncanonical mode, disable signals, extended input processing, and echoing */
	/* Disable special handling of CR, NL, and BREAK. No 8th-bit stripping or parity error handling. Disable START/STOP output flow control. */
	t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR | INPCK | ISTRIP | IXON | PARMRK);
	t.c_oflag &= ~OPOST; /* Disable all output processing */
	t.c_cc[VMIN] = 1; /* Character-at-a-time input */
	t.c_cc[VTIME] = 0; /* with blocking */

	if (tcsetattr(fd, TCSANOW, &t) == -1) {
		bbs_error("tcsetattr(%d): %s\n", fd, strerror(errno));
		return -1;
	}
	return 0;
}

int tty_set_line_discipline(int fd)
{
	struct termios t;

	if (!isatty(fd)) {
		bbs_error("File descriptor %d is not a TTY\n", fd);
		return -1;
	} else if (tcgetattr(fd, &t) == -1) {
		bbs_error("tcgetattr(%d): %s\n", fd, strerror(errno));
		return -1;
	}

	/* Set ICRNL, which is needed for clients that just send CR (e.g. PuTTY/KiTTY), since we need to see a newline in canonical mode.
	 * Do NOT set IGNCR, as that causes ICRNL to be ignored. */
	t.c_iflag |= ICRNL;
	t.c_iflag &= ~(INLCR | IGNCR);
	if (tcsetattr(fd, TCSANOW, &t) == -1) {
		bbs_error("tcsetattr(%d): %s\n", fd, strerror(errno));
		return -1;
	}
	return 0;
}
#pragma GCC diagnostic pop
