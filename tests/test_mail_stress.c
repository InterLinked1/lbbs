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
#include <sys/time.h>
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
	int imapfd = -1;
	struct timeval tv_start, tv_end;
	long t_smtp, t_list_status, t_select, t_copy1, t_copy4, t_copy5, t_copy20, t_copy40;
	long t2_list_status, t2_select, t2_search;

#define START_TIMER() gettimeofday(&tv_start, NULL)
#define END_TIMER(var) \
	gettimeofday(&tv_end, NULL); \
	var = (1000000 * tv_end.tv_sec + tv_end.tv_usec) - (1000000 * tv_start.tv_sec + tv_start.tv_usec)
#define PRINT_TIME(var, name) \
	fprintf(stderr, "%-25s | %5ld.%03d ms\n", name, var / 1000, (int) (var % 1000))

	/* Initialization */
	for (i = 0; i < NUM_SMTP_THREADS; i++) {
		smtp_threads[i] = 0;
		smtp_index[i] = i;
	}

	/* First, send all the test messages */
	START_TIMER();
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
	END_TIMER(t_smtp);

	/* Verify that the email messages were all sent properly. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/1/new", TARGET_MESSAGES);

	/* If this test is being run from a console, clear the screen at this point, since the above SMTP output is lengthy.
	 * That way, we can focus on the IMAP stuff from here on out. */
	fprintf(stderr, TERM_CLEAR_SCROLLBACK);

	/* Log in via IMAP to look at some of the messages */
	CREATE_IMAP_CONNECTION(imapfd, TEST_USER, TEST_PASS);

	/* Perform some operations that are linear with respect to the current mailbox,
	 * things that would likely perform better with some kind of caching mechanism. */

	/* First, LIST-STATUS with STATUS=SIZE. */
	START_TIMER();
	SWRITE(imapfd, "a2 LIST \"\" \"*\" RETURN (CHILDREN STATUS (MESSAGES RECENT UNSEEN SIZE))" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "a2 OK");
	END_TIMER(t_list_status);

	/* Select the INBOX (where all the messages are) */
	START_TIMER();
	SELECT_MAILBOX(imapfd, "a3", "INBOX");
	END_TIMER(t_select);

	/* Copy the initial 10k messages a few times so we end up with 100k messages for IMAP load testing.
	 * Start by copying small batches, and move up towards increasingly large batches.
	 * It's MUCH faster to create new messages this way than using SMTP transactions. */
	START_TIMER();
	SWRITE(imapfd, "b1 UID COPY 1:1000 \"INBOX\"" ENDL); /* End with 11,000 */
	CLIENT_EXPECT_EVENTUALLY(imapfd, "b1 OK");
	END_TIMER(t_copy1);

	START_TIMER();
	SWRITE(imapfd, "b2 UID COPY 1001:5000 \"INBOX\"" ENDL); /* End with 15,000 */
	CLIENT_EXPECT_EVENTUALLY(imapfd, "b2 OK");
	END_TIMER(t_copy4);

	START_TIMER();
	SWRITE(imapfd, "b3 UID COPY 5001:10000 \"INBOX\"" ENDL); /* End with 20,000 */
	CLIENT_EXPECT_EVENTUALLY(imapfd, "b3 OK");
	END_TIMER(t_copy5);

	START_TIMER();
	SWRITE(imapfd, "b4 UID COPY 1:20000 \"INBOX\"" ENDL); /* End with 40,000 */
	CLIENT_EXPECT_EVENTUALLY_SEC(imapfd, 15, "b4 OK"); /* May need more time with high debug */
	END_TIMER(t_copy20);

	START_TIMER();
	SWRITE(imapfd, "b5 UID COPY 1:40000 \"INBOX\"" ENDL); /* End with 80,000 */
	CLIENT_EXPECT_EVENTUALLY_SEC(imapfd, 30, "b5 OK"); /* May need more time with high debug */
	END_TIMER(t_copy40);

	SWRITE(imapfd, "b6 UNSELECT" ENDL);
	CLIENT_EXPECT(imapfd, "b6 OK");

	/* Now that the mailbox is somewhat large (80k messages), repeat some of the initial tests. */
	START_TIMER();
	SWRITE(imapfd, "c1 LIST \"\" \"*\" RETURN (CHILDREN STATUS (MESSAGES RECENT UNSEEN SIZE))" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "c1 OK");
	END_TIMER(t2_list_status);

	START_TIMER();
	SELECT_MAILBOX(imapfd, "c2", "INBOX");
	END_TIMER(t2_select);

	/* Search for messages with subject containing "1337".
	 * There should be exactly 8 (the original one from SMTP, and the 7 copies we made).
	 * This should take a little more time, given we actually need to OPEN 80,000 messages
	 * and parse all their headers. */
	START_TIMER();
	SWRITE(imapfd, "c3 SEARCH HEADER \"From\" \"1337\"" ENDL);
	/* We can't expect exact sequence numbers, as depending on the order in which the initial messages delivered
	 * via SMTP were processed, the last 4 digits may vary, i.e. 1ABC, 11ABC, 21ABC, 31ABC, etc.
	 * Sometimes the first result has a sequence number below 1,000; sometimes, it's above.
	 * Manually run the test, can confirm the last 4 digits, i.e. 1ABC are the same for all the results. */
	CLIENT_EXPECT(imapfd, "1"); /* This just matches the beginning (i.e. search result is non-empty and contains at least 1 result with '1' in it - which it has to) */
	END_TIMER(t2_search);

	res = 0;

	PRINT_TIME(t_smtp, "SMTP send 10k");
	PRINT_TIME(t_list_status, "LIST-STATUS 10k");
	PRINT_TIME(t_select, "SELECT 10k");
	PRINT_TIME(t_copy1, "COPY 1k");
	PRINT_TIME(t_copy4, "COPY 4k");
	PRINT_TIME(t_copy5, "COPY 5k");
	PRINT_TIME(t_copy20, "COPY 20k");
	PRINT_TIME(t_copy40, "COPY 40k");
	PRINT_TIME(t2_list_status, "LIST-STATUS 80k");
	PRINT_TIME(t2_select, "SELECT 80k");
	PRINT_TIME(t2_search, "SEARCH 80k");

cleanup:
	for (i = 0; i < NUM_SMTP_THREADS; i++) {
		if (smtp_threads[i]) {
			pthread_join(smtp_threads[i], NULL);
			smtp_threads[i] = 0;
		}
	}
	close_if(imapfd);
	return res;
}

/* Do not run this test under valgrind, due to timeouts on initial 220 and final 250 */
TEST_MODULE_INFO_STANDARD_FLAGS("Mail Stress Tests", TEST_FLAG_NO_AUTOLOAD | TEST_FLAG_NO_VALGRIND);
