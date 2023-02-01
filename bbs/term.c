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

static int bbs_fd_input_set(int fd, int canonical, int echo)
{
	struct termios term;

	memset(&term, 0, sizeof(term)); /* Prevent valgrind: Syscall param ioctl(TCSET{S,SW,SF}) points to uninitialised byte(s) */ 

	if (tcgetattr(fd, &term)) {
		bbs_error("tcgetattr failed: %s\n", strerror(errno));
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
		bbs_error("tcsetattr failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_fd_echo(int fd, int echo)
{
	struct termios term;

	memset(&term, 0, sizeof(term)); /* Prevent valgrind: Syscall param ioctl(TCSET{S,SW,SF}) points to uninitialised byte(s) */ 

	if (tcgetattr(fd, &term)) {
		bbs_error("tcgetattr failed: %s\n", strerror(errno));
		return -1;
	}
	if (echo) {
		term.c_lflag |= ECHO;
	} else {
		term.c_lflag &= ~ECHO;
	}
	if (tcsetattr(fd, TCSANOW, &term)) {
		bbs_error("tcsetattr failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_fd_unbuffer_input(int fd, int echo)
{
	return bbs_fd_input_set(fd, 0, echo);
}

int bbs_fd_buffer_input(int fd, int echo)
{
	return bbs_fd_input_set(fd, 1, echo);
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
		bbs_debug(6, "Overriding echo to OFF for TDD on node %d\n", node->id); /* See comment in bbs_echo about TDDs and echo */
		echo = 0;
	}

	if (node->buffered == buffered && node->echo == echo) {
		bbs_debug(6, "Buffering/echo settings (%d/%d) have not changed for node %d\n", node->buffered, node->echo, node->id);
		return 0; /* Nothing is changing. */
	}

	res = bbs_fd_input_set(node->slavefd, buffered, echo);

	if (!res) {
		bbs_debug(5, "Node %d (fd %d): input now %s, echo %s\n", node->id, node->slavefd, buffered ? "buffered" : "unbuffered", echo ? "enabled" : "disabled");
		node->buffered = buffered;
		node->echo = echo;
	}
	return 0;
}

int bbs_unbuffer_input(struct bbs_node *node, int echo)
{
	/* Do not lock the node here: node_shutdown already holds it */
	return bbs_node_set_input(node, 0, echo);
}

int bbs_buffer_input(struct bbs_node *node, int echo)
{
	/* Do not lock the node here: node_shutdown already holds it */
	return bbs_node_set_input(node, 1, echo);
}

int bbs_echo(struct bbs_node *node, int echo)
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

	res = bbs_fd_echo(node->slavefd, echo);

	if (!res) {
		node->echo = echo;
	}
	return res;
}

int bbs_term_makeraw(int fd)
{
	struct termios t;

	bbs_assert(isatty(fd));

	if (tcgetattr(fd, &t) == -1) {
		bbs_error("tcgetattr: %s\n", strerror(errno));
		return -1;
	}

	t.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO); /* Noncanonical mode, disable signals, extended input processing, and echoing */
	/* Disable special handling of CR, NL, and BREAK. No 8th-bit stripping or parity error handling. Disable START/STOP output flow control. */
	t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR | INPCK | ISTRIP | IXON | PARMRK); 
	t.c_oflag &= ~OPOST; /* Disable all output processing */
	t.c_cc[VMIN] = 1; /* Character-at-a-time input */
	t.c_cc[VTIME] = 0; /* with blocking */

	if (tcsetattr(fd, TCSANOW, &t) == -1) {
		bbs_error("tcsetattr: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int tty_set_line_discipline(int fd)
{
	struct termios t;

	bbs_assert(isatty(fd));

	if (tcgetattr(fd, &t) == -1) {
		bbs_error("tcgetattr: %s\n", strerror(errno));
		return -1;
	}

	/* Keep ICRNL on or we get ^M in the terminal
	 * Enabling IGNCR allows us to prevent double new lines on ENTER (empty lines, with SyncTERM and Windows Telnet client)
	 * By itself, this majorly screws PuTTY/KiTTY up as, apart from not fixing the ^@ issue, it results in no line breaks at all.
	 * However, this was fixed in pty.c by translating CR NUL to CR LF there, and now all is well.
	 *
	 * ISIG: Disable signals. Since most of the time the slave end of the PTY is being controlled by this main server process
	 * (the exception is when the node is executing a child process), there's no point in passing signals through.
	 * VINT: SIGINT support (when ISIG is set)
	 * XXX For some reason, neither disabling nor enabling ISIG/VINT here seem to have any effect on making ^C -> SIGINT
	 * to child processes. So for now this is handled manually in a rather hacky way in the PTY master thread,
	 * since the master side *does* see the ^C as decimal 3 (ETX) so it can do something with that, at least.
	 * Provided, of course, any previous PTY is in raw mode so all that stuff gets sent.
	 */
	t.c_iflag |= (ICRNL | IGNCR);
	t.c_iflag &= ~(INLCR);
	if (tcsetattr(fd, TCSANOW, &t) == -1) {
		bbs_error("tcsetattr: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}
