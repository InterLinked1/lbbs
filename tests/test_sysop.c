/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Sysop Console Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "ansi.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>	/* use struct sockaddr_un */

static int pre(void)
{
	test_load_module("mod_menu_handlers.so");
	test_load_module("mod_node_callbacks.so");
	test_load_module("net_telnet.so");
	test_load_module("mod_sysop.so");

	/* no net_telnet.conf needed, defaults are sufficient */
	TEST_ADD_CONFIG("menus.conf");

	return 0;
}

static int sysop_connect(void)
{
	struct sockaddr_un sunaddr;
	int fd;

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
		return 0;
	}

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	strncpy(sunaddr.sun_path, BBS_SYSOP_SOCKET, sizeof(sunaddr.sun_path) - 1);
	sunaddr.sun_path[sizeof(sunaddr.sun_path) - 1] = '\0';

	if (connect(fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr))) {
		bbs_error("Unable to connect to BBS, socket error: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int run(void)
{
	int clientfd = -1;
	int sysopfd = -1;
	int res = -1;

	/* Test #1: Test basic console connection and node spying */

	/* Connect to the sysop console directly (not using rsysop program)
	 * Small caveat is that we are not a real terminal emulator (TTY),
	 * and the BBS will know that, since we don't set up a pseudoterminal here. */
	sysopfd = sysop_connect();
	REQUIRE_FD(sysopfd);
	CLIENT_EXPECT_EVENTUALLY(sysopfd, BBS_TAGLINE); /* First, we get the sysop console banner */

	clientfd = test_make_socket(23);
	REQUIRE_FD(clientfd);

	if (test_ansi_handshake(clientfd)) {
		goto cleanup;
	}

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Hit a key");
	SWRITE(clientfd, " "); /* Hit a key */

	/* At this point, the sysop begins a spy session on this node */
	SWRITE(sysopfd, "/spy 1\r");

	/* Must always use CLIENT_EXPECT_EVENTUALLY since our input is also echoed back to us */
	CLIENT_EXPECT_EVENTUALLY(clientfd, "Login");
	SWRITE(clientfd, TEST_USER "\n");

	/* Now, the sysop should see this too */
	CLIENT_EXPECT_EVENTUALLY(sysopfd, TEST_USER); /* The username should echo to both the user and the sysop in the spy session */

	CLIENT_EXPECT_EVENTUALLY(clientfd, "Password");
	SWRITE(clientfd, TEST_PASS "\n");
	CLIENT_EXPECT_EVENTUALLY(clientfd, "at welcome menu via T");
	CLIENT_EXPECT_EVENTUALLY(sysopfd, "at welcome menu via T");

	close_if(clientfd);
	close_if(sysopfd);

	/* Test #2: Test SIGINT to exit */
	sysopfd = sysop_connect();
	REQUIRE_FD(sysopfd);
	CLIENT_EXPECT_EVENTUALLY(sysopfd, BBS_TAGLINE); /* First, we get the sysop console banner */

	/* Intentionally leak this file descriptor, to make sure the BBS cleans up properly
	 * when there is still a console active at shutdown. */
	sysopfd = -1;

	res = 0;

cleanup:
	close_if(clientfd);
	close_if(sysopfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Sysop Console Tests");
