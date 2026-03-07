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
 * \brief Mail Stress Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "email.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/socket.h> /* use SOMAXCONN */
#include <netinet/in.h> /* use sockaddr_in */

#define TARGET_MESSAGES 10000

/* Much more than this and *we* (the test program) will run out of file descriptors */
#if SOMAXCONN >= 512
#define NUM_SMTP_THREADS 512
#else
#define NUM_SMTP_THREADS SOMAXCONN
#endif

#define LISTEN_BACKLOG NUM_SMTP_THREADS
#define NUM_CHILD_FDS 2048

extern int listen_backlog;
extern int child_max_fds;

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");

	if (!listen_backlog) {
		test_load_module("mod_mail_events.so");
		TEST_ADD_CONFIG("mod_mail_events.conf");
	}

	TEST_RESET_MKDIR(TEST_MAIL_DIR);

	listen_backlog = LISTEN_BACKLOG; /* Default in socket.c is 64, increase to ensure all connections can get handled immediately */
	child_max_fds = NUM_CHILD_FDS; /* Increase max file descriptors, otherwise we'll run out if NUM_SMTP_THREADS is much more than 256 */

	return 0;
}

static int smtp_index[NUM_SMTP_THREADS];
static pthread_t smtp_threads[NUM_SMTP_THREADS];
static int test_abort = 0;
static int sent_messages = 0;

static void *send_thread(void *varg)
{
	int i, fd = -1, lport;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	int sendcount = 0; /* Since we're multithreaded, each client needs its own send count */
	int index = *((int*) varg);

	/* Establish SMTP connection */
	fd = test_make_socket(25);
	if (fd < 0) {
		test_abort = 1;
		return NULL;
	}

	/* Figure out what port we're using locally for this connection */
	if (getsockname(fd, (struct sockaddr *) &sin, &slen)) {
		bbs_warning("getsockname failed: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Our local port allows us to correlate the client session to the handling server thread in the BBS */
	lport = ntohs(sin.sin_port);

	/* Send our share of the messages */
	for (i = 0; i < TARGET_MESSAGES; i++) {
		if (i % NUM_SMTP_THREADS == index) {
			char sender[64];
			if (test_abort) {
				goto cleanup; /* As soon as one thread fails, all others should stop */
			}
			snprintf(sender, sizeof(sender), "external%d@" TEST_EXTERNAL_DOMAIN, i);
			if (test_send_message_full(fd, &sendcount, sender, TEST_EMAIL, 0)) {
				test_abort = 1;
				bbs_warning("Failed to send message %d from %s on client %d from port %d (%d sent so far)\n", i, sender, index, lport, sent_messages);
				goto cleanup;
			}
			bbs_atomic_fetchadd_int(&sent_messages, +1);
		}
	}

cleanup:
	close_if(fd);
	return NULL;
}

static int run(void)
{
	int i, res = -1;

	/* Initialization */
	for (i = 0; i < NUM_SMTP_THREADS; i++) {
		smtp_threads[i] = 0;
		smtp_index[i] = i;
	}

	/* First, send all the test messages */
	for (i = 0; i < NUM_SMTP_THREADS; i++) {
		int pres = pthread_create(&smtp_threads[i], NULL, send_thread, &smtp_index[i]);
		if (pres) {
			bbs_error("Failed to create thread: %s\n", strerror(pres));
			test_abort = 1;
			goto cleanup;
		}
		usleep(50);
	}

	/* Join sending threads */
	for (i = 0; i < NUM_SMTP_THREADS; i++) {
		if (smtp_threads[i]) {
			pthread_join(smtp_threads[i], NULL);
			smtp_threads[i] = 0;
		}
	}

	/* Verify that the email messages were all sent properly. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", TARGET_MESSAGES);

	res = 0;

cleanup:
	for (i = 0; i < NUM_SMTP_THREADS; i++) {
		if (smtp_threads[i]) {
			pthread_join(smtp_threads[i], NULL);
			smtp_threads[i] = 0;
		}
	}
	return res;
}

/* Do not run this test under valgrind, due to timeouts on initial 220 and final 250 */
TEST_MODULE_INFO_STANDARD_FLAGS("Mail Stress Tests", TEST_FLAG_NO_AUTOLOAD | TEST_FLAG_NO_VALGRIND);
