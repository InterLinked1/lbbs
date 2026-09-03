/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief IMAP Slow FETCH / Lock Interaction Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 */

#include "test.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_SUBCONFIG("smtp_large", "net_smtp.conf"); /* Need increased message size limit */
	TEST_ADD_CONFIG("net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	return 0;
}

/*! \brief Send a really big email message */
static int deliver_message(int smtpfd, unsigned int subject_id, size_t bodysize)
{
	size_t written = 0;
#define BODY_LINE_LEN 76
	char line[BODY_LINE_LEN + 1];
	int i;

	SWRITE(smtpfd, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "RCPT TO:<" TEST_EMAIL ">" ENDL);
	CLIENT_EXPECT(smtpfd, "250");
	SWRITE(smtpfd, "DATA" ENDL);
	CLIENT_EXPECT(smtpfd, "354");

	FMT_WRITE(smtpfd, "From: \"External Sender\" <" TEST_EMAIL_EXTERNAL ">" ENDL);
	FMT_WRITE(smtpfd, "To: <" TEST_EMAIL ">" ENDL);
	FMT_WRITE(smtpfd, "Subject: Lock test message %u" ENDL, subject_id);
	FMT_WRITE(smtpfd, "Date: Thu, 21 May 1998 05:33:29 -0700" ENDL);
	FMT_WRITE(smtpfd, "Message-ID: <locktest%u@" TEST_EXTERNAL_DOMAIN ">" ENDL, subject_id);
	FMT_WRITE(smtpfd, "MIME-Version: 1.0" ENDL);
	FMT_WRITE(smtpfd, "Content-Type: text/plain; charset=us-ascii" ENDL);
	SWRITE(smtpfd, ENDL); /* EOH */

	for (i = 0; i < BODY_LINE_LEN - 2; i++) {
		line[i] = (char) ('A' + (i % 26));
	}
	line[BODY_LINE_LEN - 2] = '\r';
	line[BODY_LINE_LEN - 1] = '\n';
	line[BODY_LINE_LEN] = '\0';

	while (written < bodysize) {
		if (write(smtpfd, line, BODY_LINE_LEN) != BODY_LINE_LEN) {
			bbs_error("Short write streaming body: %s\n", strerror(errno));
			return -1;
		}
		written += BODY_LINE_LEN;
	}
#undef BODY_LINE_LEN

	SWRITE(smtpfd, "." ENDL); /* EOM */
	CLIENT_EXPECT(smtpfd, "250");

	bbs_debug(2, "Delivered ~%lu byte message (subject %u)\n", written, subject_id);
	return 0;

cleanup:
	return -1;
}

static int deliver_messages(void)
{
	int smtpfd;
	int res = -1;

	smtpfd = test_make_socket(25);
	REQUIRE_FD_RETURN(smtpfd);

	CLIENT_EXPECT_EVENTUALLY(smtpfd, "220 ");
	SWRITE(smtpfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
	CLIENT_EXPECT_EVENTUALLY(smtpfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */

	/* First, send a really big message, to cause a stall for client 1 */
	if (deliver_message(smtpfd, 1, 8 * 1024 * 1024)) {
		goto cleanup;
	}

	/* Next, send a normal (small) message. */
	if (deliver_message(smtpfd, 2, 128)) {
		goto cleanup;
	}

	res = 0;

cleanup:
	close(smtpfd);
	return res;
}

static int test_make_socket_small_rcvbuf(int port)
{
	struct sockaddr_in sinaddr;
	int sock;
	int rcvbuf = 4096; /* Small enough to simulate a client that stops reading in the middle of a large message */

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		bbs_error("Unable to create TCP socket: %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf))) {
		bbs_error("setsockopt(SO_RCVBUF) failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sinaddr.sin_port = htons((uint16_t) port);

	if (connect(sock, (struct sockaddr *) &sinaddr, sizeof(sinaddr)) < 0) {
		bbs_error("Unable to connect to TCP port %d: %s\n", port, strerror(errno));
		close(sock);
		return -1;
	}
	bbs_debug(1, "Connected to TCP port %d (SO_RCVBUF=%d)\n", port, rcvbuf);
	return sock;
}

static int run(void)
{
	int client1 = -1, client2 = -1, client3 = -1;
	int res = -1;

	if (deliver_messages()) {
		return -1;
	}

	client1 = test_make_socket_small_rcvbuf(143);
	REQUIRE_FD(client1);
	CLIENT_EXPECT(client1, "* OK [CAPABILITY");
	SWRITE(client1, "a1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a1 OK");
	SWRITE(client1, "a2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client1, "a2 OK");

	client2 = test_make_socket(143);
	REQUIRE_FD(client2);
	CLIENT_EXPECT(client2, "* OK [CAPABILITY");
	SWRITE(client2, "b1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client2, "b1 OK");
	SWRITE(client2, "b2 SELECT INBOX" ENDL);
	CLIENT_EXPECT_EVENTUALLY(client2, "b2 OK");

	/* Client 1 requests the big message but stops reading the message,
	 * which means in imap_server_fetch.c, we'll stall on the sendfile call
	 * until it times out (after ~30 seconds).
	 * In the past, that would trigger soft assertions due to other
	 * threads trying to obtain the lock. However, with the addition
	 * of updatelock and more targeted locking, this should be gracefully
	 * handled so that even that doesn't cause other threads to stall (even for 30 seconds). */
	SWRITE(client1, "a3 UID FETCH 1 (BODY.PEEK[])" ENDL);

	/* Sleep a second to make sure we're blocked in sendfile */
	usleep(1000000);

	/* Client 2 fetches a message, without PEE, which will cause the \Seen flag to be read
	 * and an update to go out to Client 1, whose lock is held on the above FETCH.
	 * We should gracefully do a delayed write to its pipe, without blocking client 2. */

	SWRITE(client2, "b3 UID FETCH 2 (BODY[])" ENDL);

	usleep(1000000);

	/* New clients should be able to connect as well, without being blocked by
	 * the main sessions list being held from the update from client 2
	 * doing a traversal of all clients. */
	client3 = test_make_socket(143);
	REQUIRE_FD(client3);
	CLIENT_EXPECT_EVENTUALLY_SEC(client3, 10, "* OK [CAPABILITY");
	SWRITE(client3, "c1 LOGIN \"" TEST_USER "\" \"" TEST_PASS "\"" ENDL);
	if (test_client_expect_eventually(client3, SEC_MS(10), "c1 OK", __LINE__)) {
		bbs_error("New IMAP session couldn't log in: sessions list is blocked\n");
		goto cleanup;
	}

	SWRITE(client3, "c2 SELECT INBOX" ENDL);
	if (test_client_expect_eventually(client3, SEC_MS(15), "c2 OK", __LINE__)) {
		bbs_error("New IMAP session couldn't log in: sessions list is blocked\n");
		goto cleanup;
	}

	/* Client 2's FETCH also should have completed, even if client 1 never finished */
	if (test_client_expect_eventually(client2, SEC_MS(15), "b3 OK", __LINE__)) {
		bbs_error("Second session's FETCH never completed: blocked on the stalled session's lock\n");
		goto cleanup;
	}

	res = 0;

cleanup:
	if (res) {
		test_get_live_backtrace();
	}
	close_if(client1);
	close_if(client2);
	close_if(client3);
	return res;
}

TEST_MODULE_INFO_STANDARD("IMAP Slow Fetch / Locking Interaction");
