/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Telnet Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <arpa/inet.h> /* use inet_ntop */

static int pre(void)
{
	test_load_module("net_telnet.so");
	/* no net_telnet.conf needed, defaults are sufficient */
	return 0;
}

/* Tunable, but increasing this doesn't really speed up the test */
#define MAX_PARALLEL_CONNECTIONS 1

static void init_fds(int fds[MAX_PARALLEL_CONNECTIONS])
{
	int i;
	for (i = 0; i < MAX_PARALLEL_CONNECTIONS; i++) {
		fds[i] = -1;
	}
}

static void cleanup_fds(int fds[MAX_PARALLEL_CONNECTIONS])
{
	int i;
	for (i = 0; i < MAX_PARALLEL_CONNECTIONS; i++) {
		close_if(fds[i]);
	}
}

static int test_make_nonblocking_socket(int port)
{
	struct sockaddr_in sinaddr; /* Internet socket */
	int sock;
	socklen_t len;

	sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (sock < 0) {
		bbs_error("Unable to create TCP socket: %s\n", strerror(errno));
		return -1;
	}
	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sinaddr.sin_port = htons((uint16_t) port);

	len = sizeof(sinaddr);
	for (;;) {
		if (connect(sock, (struct sockaddr *) &sinaddr, len) < 0) {
			if (errno = EAGAIN) {
				continue;
			}
			bbs_error("Unable to connect to TCP port %d: %s\n", port, strerror(errno));
			close(sock);
			return -1;
		}
		break;
	}
	bbs_debug(1, "Connected to %s port %d\n", "TCP", port);
	return sock;
}

static int run(void)
{
	int fds[MAX_PARALLEL_CONNECTIONS];
	int res = -1;
	unsigned int i, winmin, idx;

	init_fds(fds);

	/* Fuzz the Telnet server with arbitrary data and ensure it doesn't crash */

	/* Try invalid commands */
	i = 0;
	while (i < 255) {
		winmin = i;
		for (idx = 0; i < winmin + MAX_PARALLEL_CONNECTIONS; i++, idx++) {
			/* Make nonblocking so we don't have to wait for writes.
			 * This shaves a few seconds off the total test time. */
			fds[idx] = test_make_nonblocking_socket(23);
			REQUIRE_FD(fds[idx]);
		}
		i = winmin;
		for (idx = 0; i < winmin + MAX_PARALLEL_CONNECTIONS; i++, idx++) {
			unsigned char data[] = { (unsigned char) i, 250, (unsigned char) i };
			write(fds[idx], data, 3);
		}
		cleanup_fds(fds);
	}

	/* Try invalid options */
	i = 0;
	while (i < 255) {
		winmin = i;
		for (idx = 0; i < winmin + MAX_PARALLEL_CONNECTIONS; i++, idx++) {
			fds[idx] = test_make_nonblocking_socket(23);
			REQUIRE_FD(fds[idx]);
		}
		i = winmin;
		for (idx = 0; i < winmin + MAX_PARALLEL_CONNECTIONS; i++, idx++) {
			unsigned char data[] = { 255, 250, (unsigned char) i };
			write(fds[idx], data, 3);
		}
		cleanup_fds(fds);
	}

	res = 0;

	cleanup_fds(fds);
	return res;
}

TEST_MODULE_INFO_STANDARD("Telnet Tests");
