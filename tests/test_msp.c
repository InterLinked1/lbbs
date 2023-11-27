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
 * \brief Message Send Protocol Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <arpa/inet.h>

static int pre(void)
{
	test_preload_module("net_irc.so");
	test_load_module("net_msp.so");

	TEST_ADD_CONFIG("net_irc.conf");
	TEST_ADD_CONFIG("net_msp.conf");
	return 0;
}

/* Adapted from examples in RFC 1312 */
#define VERSION_1_REQUEST "A" TEST_USER "\0\0Hi\r\nHow about lunch?\0"
#define VERSION_2_REQUEST "B" TEST_USER "\0\0Hi\r\nHow about lunch?\0sandy\0console\0910806121325\0\0"

static int udp_client_test(void)
{
	ssize_t res;
	int sfd;
	char resp[32];
	struct sockaddr_in saddr;

	memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(18);              
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sfd < 0) {
        bbs_error("socket failed: %s\n", strerror(errno));
        return -1;
    }

	/* Now, test sending and receiving with the UDP version:
	 * Since the response is coming from the same place the packet is being sent,
	 * we can call connect() and then use send() and recv()
	 * instead of sendto() and recvfrom()
	 * See udp(7) */
	if (connect(sfd, (struct sockaddr*) &saddr, sizeof(struct sockaddr_in))) {
		bbs_error("connect failed: %s\n", strerror(errno));
		close(sfd);
		return -1;
	}

	/* It's UDP, so it probably won't fail anyways */
	res = send(sfd, VERSION_2_REQUEST, STRLEN(VERSION_2_REQUEST), 0);
	if (res <= 0) {
		bbs_error("send failed: %s\n", strerror(errno));
		close(sfd);
		return -1;
	}

	res = recv(sfd, resp, sizeof(resp), 0);
	if (res <= 0) {
		bbs_error("recv failed: %s\n", strerror(errno));
		close(sfd);
		return -1;
	}

	close(sfd);
	return strncmp(resp, "+", 1);
}

static int run(void)
{
	int clientfd = -1;
	int ircfd = -1;
	int res = -1;

	/* Connect to IRC to receive messages */
	ircfd = test_make_socket(6667);
	REQUIRE_FD(ircfd);

	SWRITE(ircfd, "CAP LS 302\r\n");
	SWRITE(ircfd, "NICK " TEST_USER ENDL);
	SWRITE(ircfd, "USER " TEST_USER ENDL);
	CLIENT_EXPECT_EVENTUALLY(ircfd, "CAP * LS");
	SWRITE(ircfd, "CAP REQ :sasl\r\n");
	CLIENT_EXPECT(ircfd, "CAP * ACK");
	SWRITE(ircfd, "AUTHENTICATE PLAIN\r\n");
	CLIENT_EXPECT(ircfd, "AUTHENTICATE +\r\n");
	SWRITE(ircfd, "AUTHENTICATE " TEST_SASL "\r\n");
	CLIENT_EXPECT(ircfd, "903");
	SWRITE(ircfd, "CAP END\r\n");

	CLIENT_EXPECT_EVENTUALLY(ircfd, "376"); /* End of MOTD */

	SWRITE(ircfd, "JOIN #test1,#test2,#test3\r\n");
	CLIENT_EXPECT_EVENTUALLY(ircfd, "MODE #test3 +oq testuser"); /* Nobody else was in these channels */

	/* Connected to IRC, now do the MSP stuff */

	clientfd = test_make_socket(18);
	REQUIRE_FD(clientfd);

	/* Version 2 request via TCP */
	SWRITE(clientfd, VERSION_2_REQUEST);
	CLIENT_EXPECT_EVENTUALLY(clientfd, "+");

	/* Version 1 request via TCP */
	SWRITE(clientfd, VERSION_1_REQUEST);
	CLIENT_EXPECT(clientfd, "-"); /* We expect this to be rejected since we only support Version 2 */

	close_if(clientfd);
	res = udp_client_test();

	/* Should've gotten these via IRC */
	CLIENT_EXPECT_EVENTUALLY(ircfd, "How about lunch?");

cleanup:
	close_if(clientfd);
	close_if(ircfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Message Send Protocol Tests");
