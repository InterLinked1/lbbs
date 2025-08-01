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
 * \brief Remote Sysop Console Access
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* strerror on FreeBSD */
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>	/* use struct sockaddr_un */

struct termios orig;

static int term_makeraw(int fd)
{
	struct termios t;

	if (tcgetattr(fd, &t) == -1) {
		fprintf(stderr, "tcgetattr: %s\n", strerror(errno));
		return -1;
	}

	memcpy(&orig, &t, sizeof(orig));

	t.c_lflag &= ~(ICANON | ECHO); /* Noncanonical mode, disable signals, extended input processing, and echoing */
	t.c_cc[VMIN] = 1; /* Character-at-a-time input */
	t.c_cc[VTIME] = 0; /* with blocking */

	if (tcsetattr(fd, TCSANOW, &t) == -1) {
		fprintf(stderr, "tcsetattr: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void reset_term(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &orig); /* Restore the terminal on exit */
	printf("\e]2;\a"); /* Restore previous terminal title */
	fflush(stdout);
}

static void sigint_handler(int sig)
{
	(void) sig;
	reset_term();
	fprintf(stderr, "\nDisconnected from BBS\n"); /* We disconnected from BBS */
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	struct sockaddr_un sunaddr;
	int res;
	struct pollfd pfds[2];
	char buf[8192];
	const char *command;
	int sockfd;

	/* Hack to print response to a CLI command and then exit */
	command = argc > 1 ? argv[1] : NULL;
	if (command && *command == '-') {
		/* Interpret as options. Just display usage. */
		fprintf(stderr, "rsysop - LBBS sysop console\n\n");
		fprintf(stderr, "  rsysop                          - Run interactive sysop console\n");
		fprintf(stderr, "  rsysop \"command to execute\"     - Single command to execute\n"); /* misaligned to align escaped quotes */
		fprintf(stderr, "  rsysop -h                       - Display usage\n");
		return -1;
	}

	signal(SIGINT, sigint_handler);

	sockfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
		return 0;
	}

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	strncpy(sunaddr.sun_path, "/var/run/lbbs/sysop.sock", sizeof(sunaddr.sun_path) - 1);
	sunaddr.sun_path[sizeof(sunaddr.sun_path) - 1] = '\0';

	res = connect(sockfd, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (res) {
		fprintf(stderr, "Unable to connect to BBS, socket error: %s\n", strerror(errno));
		close(sockfd);
		sockfd = -1;
		return -1;
	}

	pfds[0].fd = sockfd;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;
	if (!command) {
		pfds[1].fd = STDIN_FILENO;
		pfds[1].events = POLLIN;
		pfds[1].revents = 0;
	}

	/* Make the terminal nonblocking */
	if (!command && term_makeraw(STDIN_FILENO)) {
		fprintf(stderr, "Unable to set terminal\n");
		close(sockfd);
		return -1;
	}

	/* Relay data between STDIN and the socket */
	if (command) {
		if (strlen(command) > 1) {
			write(sockfd, "/", 1); /* Start command */
		}
		write(sockfd, command, strlen(command));
		if (strlen(command) > 1) {
			write(sockfd, "\n", 2);
		}
	} else {
		fprintf(stderr, "Connecting to BBS...\n");
	}
	for (;;) {
		res = poll(pfds, 2, -1);
		if (res <= 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (pfds[0].revents) { /* BBS -> STDOUT */
			res = read(sockfd, buf, sizeof(buf));
			if (res <= 0) {
				break;
			}
			write(STDOUT_FILENO, buf, (size_t) res);
		} else if (!command && pfds[1].revents) { /* STDIN -> BBS */
			res = read(STDIN_FILENO, buf, sizeof(buf));
			if (res <= 0) {
				break;
			}
			write(sockfd, buf, (size_t) res);
		}
	}

	if (!command) {
		reset_term(); /* Restore terminal on server disconnect */
		fprintf(stderr, "BBS server disconnected\n");
		return -1; /* If we get here, then the socket closed on us. */
	}
	return 0;
}
