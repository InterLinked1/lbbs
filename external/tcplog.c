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
 * \brief TCP Logger
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <getopt.h>

static void *handler(void *varg)
{
	int *fdptr = varg;
	int fd = *fdptr;
	unsigned char buf[8192];
	int i;

	fprintf(stderr, "New connection on fd %d\n", fd);

	for (;;) {
		int res = read(fd, (char*) buf, sizeof(buf));
		if (res <= 0) {
			fprintf(stderr, "read(%d) returned %d: %s\n", fd, res, strerror(errno));
			break;
		}
		for (i = 0; i < res; i++) {
			if (isprint(buf[i])) {
				printf("[%d] %3d: %c\n", fd, buf[i], buf[i]);
			} else {
				printf("[%d] %3d\n", fd, buf[i]);
			}
		}
	}
	return NULL;
}

static int listen_port = -1;
static int listen_local = 0;
static int debug_level = 0;

static int parse_options(int argc, char *argv[])
{
	static const char *getopt_settings = "lhpv";
	int c;

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case 'l':
			listen_local = 1;
			break;
		case 'h':
			fprintf(stderr, "tcplog [-options]\n");
			fprintf(stderr, "   -l        Listen only on localhost\n");
			fprintf(stderr, "   -p port   Port on which to listen\n");
			fprintf(stderr, "   -v        Increase verbosity\n");
			return -1;
		case 'p':
			listen_port = atoi(argv[optind++]);
			break;
		case 'v':
			debug_level++;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", c);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in sinaddr;
	socklen_t len;
	int sfd, res;
	int sock;
	const int enable = 1;

	if (parse_options(argc, argv)) {
		return -1;
	} else if (listen_port == -1) {
		fprintf(stderr, "Must specify a port: tcplog -p <port>\n");
		return -1;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Unable to create TCP socket: %s\n", strerror(errno));
		return -1;
	}

	/* Allow reuse so we can rerun quickly */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		fprintf(stderr, "Unable to create setsockopt: %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
		fprintf(stderr, "Unable to create setsockopt: %s\n", strerror(errno));
		return -1;
	}

	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr.s_addr = listen_local ? INADDR_LOOPBACK : INADDR_ANY;
	sinaddr.sin_port = htons(listen_port);

	if (bind(sock, (struct sockaddr *) &sinaddr, sizeof(sinaddr))) {
		fprintf(stderr, "Unable to bind TCP socket to port %d: %s\n", listen_port, strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, 2) < 0) {
		fprintf(stderr, "Unable to listen on TCP socket on port %d: %s\n", listen_port, strerror(errno));
		close(sock);
		return -1;
	}

	fprintf(stderr, "Listening on port %d\n", listen_port);

	for (;;) {
		pthread_attr_t attr;
		pthread_t thread;
		sfd = accept(sock, (struct sockaddr *) &sinaddr, &len);
		if (sfd < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "accept returned %d: %s\n", sfd, strerror(errno));
				break;
			}
			continue;
		}

		/* Make the thread detached, since we're not going to join it, ever */
		pthread_attr_init(&attr);
		res = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (res) {
			fprintf(stderr, "pthread_attr_setdetachstate: %s\n", strerror(res));
			close(sfd);
			continue;
		}
		if (pthread_create(&thread, &attr, handler, &sfd)) {
			fprintf(stderr, "pthread_create failed: %s\n", strerror(errno));
			close(sfd);
		}
		usleep(100000); /* Wait for thread to start and dereference sfd before we accept() and overwrite it */
	}

	close(sock);
	fprintf(stderr, "Listener thread has exited\n");
}
