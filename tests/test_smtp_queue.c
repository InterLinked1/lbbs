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
 * \brief SMTP Message Queue Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "email.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <dirent.h>

#define TMP_HOSTS_FILE "/etc/hosts.lbbs.bak"
#define SAVE_HOSTS() system("cp /etc/hosts " TMP_HOSTS_FILE)
#define RESTORE_HOSTS() system("mv " TMP_HOSTS_FILE " /etc/hosts")
#define RESET_HOSTS() RESTORE_HOSTS(); SAVE_HOSTS();

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_external.so");
	test_load_module("mod_sysop.so");

	TEST_ADD_CONFIG("bbs.conf"); /* For short connect() timeout */
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_SUBCONFIG("smtp_dsn", "net_smtp.conf"); /* has relayout=yes, that's all we need */

	/* Needed for loopback test: */
	test_load_module("mod_smtp_delivery_local.so"); /* Needed for loopback test */
	test_preload_module("mod_mimeparse.so");
	test_load_module("net_imap.so");
	TEST_ADD_CONFIG("net_imap.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	SAVE_HOSTS();
	ADD_TO_HOSTS_FILE(TEST_EMAIL_EXTERNAL_OUTGOING_TEMPFAIL_DOMAIN, "192.0.2.0"); /* TEST-NET-1 */

	return 0;
}

static int handshake(int clientfd, int reset)
{
	if (reset) {
		/* We should be able to reset at any point without losing our authenticated state, or needing to re-HELO/EHLO */
		SWRITE(clientfd, "RSET" ENDL);
		CLIENT_EXPECT(clientfd, "250");
	} else {
		CLIENT_EXPECT_EVENTUALLY(clientfd, "220 ");
		SWRITE(clientfd, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
		CLIENT_EXPECT_EVENTUALLY(clientfd, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	}
	return 0;
cleanup:
	return -1;
}

static int inspect_queue_file(const char *file)
{
	int res = 0;
	int flags = 0;
	int attempts = -1;
	char buf[256];
	FILE *fp = fopen(file, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", file, strerror(errno));
		return -1;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
#define CHECK_HDR(name, bit) \
	else if (!strncmp(buf, name ":", STRLEN(name ":"))) { \
		if (flags & (1 << bit)) { \
			bbs_error("Header '%s' appears to be set multiple times?\n", name); \
			res = -1; \
		} \
		flags |= (1 << bit); \
	}
		bbs_debug(5, "%s", buf); /* Already includes LF */
		/* Check that all desired headers are present, exactly once. */
		if (0) { } /* The below should work up to 32 bits (32 headers) */
		/* Mandatory */
		CHECK_HDR("Source-IP", 0)
		CHECK_HDR("SMTP-Hostname", 1)
		CHECK_HDR("SMTP-Submission", 2)
		CHECK_HDR("Envelope-Sender", 3)
		CHECK_HDR("Envelope-Recipient", 4)
		CHECK_HDR("Data-File", 5)
		CHECK_HDR("Arrival-Time", 6)
		CHECK_HDR("Delivery-Attempts", 7)
		/* Optional */
		CHECK_HDR("Last-Retry-Time", 8)
		else {
			bbs_warning("Unknown header found: %s\n", buf);
			res = -1;
		}
		if (STARTS_WITH(buf, "Delivery-Attempts:")) {
			const char *attempts_str = buf + STRLEN("Delivery-Attempts:");
			attempts = atoi(attempts_str);
		}
	}
	fclose(fp);
	/* The mandatory headers all better be present */
	if (!(flags & 0x7F)) {
		bbs_warning("At least one mandatory header missing\n");
		res = -1;
	}
	if (attempts < 0) {
		bbs_warning("Delivery-Attempts not set\n");
		res = -1;
	} else if (attempts > 0 && !(flags & (1 << 8))) {
		bbs_warning("Delivery attempted at least once, but Last-Retry-Time not set\n");
		res = -1;
	}
	return res;
}

static int inspect_controldir(const char *dirname)
{
	DIR *dir;
	int res = -1;
	struct dirent *ent;

	dir = opendir(dirname);
	if (!dir) {
		bbs_error("Failed to open directory %s: %s\n", dirname, strerror(errno));
		return -1;
	}
	while ((ent = readdir(dir))) {
		char file[512];
		if (ent->d_name[0] == '.') {
			continue; /* Skip . and .. */
		}
		/* There should only be one queue file, and this is it */
		snprintf(file, sizeof(file), "%s/%s", dirname, ent->d_name);
		res = inspect_queue_file(file);
	}
	closedir(dir);
	return res;
}

static int run(void)
{
	int clientfd;
	int imapfd = -1;
	int res = -1;
	int i;

	clientfd = test_make_socket(587);
	REQUIRE_FD(clientfd);

	if (handshake(clientfd, 0)) {
		goto cleanup;
	}

	/* Log in */
	SWRITE(clientfd, "AUTH PLAIN\r\n");
	CLIENT_EXPECT(clientfd, "334");
	SWRITE(clientfd, TEST_SASL "\r\n");
	CLIENT_EXPECT(clientfd, "235");

	/* Set up IMAP connection to watch for new messages and inspect them */
	CREATE_IMAP_CONNECTION(imapfd, TEST_USER, TEST_PASS);
	SELECT_MAILBOX(imapfd, "a2", "INBOX");
	SWRITE(imapfd, "b1 IDLE" ENDL);
	CLIENT_EXPECT(imapfd, "+");

	/* Send a message that will end up in the queue, due to a temporary failure. */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL_EXTERNAL_OUTGOING_TEMPFAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	if (test_send_sample_body(clientfd, TEST_EMAIL)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "250");

	/* Wait for the outgoing attempt to temporarily fail and finish (will abort connect after 1 second) */
	usleep(1100000);

	/* Verify that the email message is still in queue. */
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/mailq/new", 1);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/mailq/tmp", 1);

	if (inspect_controldir(TEST_MAIL_DIR "/mailq/tmp")) {
		goto cleanup;
	}

	for (i = 1; i < 9; i++) {
		/* Run the queue again, which will force another try */
		TEST_CLI_COMMAND("runq");
		if (inspect_controldir(TEST_MAIL_DIR "/mailq/tmp")) {
			goto cleanup;
		}
	}

	/* Now, the message should get expired from the queue since we've reached maxattempts */
	TEST_CLI_COMMAND("runq");
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/mailq/new", 0);
	DIRECTORY_EXPECT_FILE_COUNT(TEST_MAIL_DIR "/mailq/tmp", 0);

	CLIENT_EXPECT(imapfd, "* 1 EXISTS"); /* Receive non-delivery report */
	SWRITE(imapfd, "DONE" ENDL);
	CLIENT_EXPECT(imapfd, "b1 OK");
	SWRITE(imapfd, "b2 UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (Content-Type)])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "Content-Type: multipart/report; report-type=delivery-status");
	CLOSE(imapfd); /* reloading mod_mail will kick the IMAP client, we'll need to open the connection again */

	ENSURE_TMP_QUEUE_FILES_CLEANED_UP();

#define TEST_EMAIL_EXTERNAL_OUTGOING_LOOPBACK_DOMAIN "loopback.example.com"
#define TEST_EMAIL_EXTERNAL_OUTGOING_LOOPBACK "loopback@" TEST_EMAIL_EXTERNAL_OUTGOING_LOOPBACK_DOMAIN

	/* Initially, we add the loopback domain with a valid but unreachable address,
	 * so delivery will fail temporarily (rather than permanently).
	 * That allows us to get the message into the queue. */
	ADD_TO_HOSTS_FILE(TEST_EMAIL_EXTERNAL_OUTGOING_LOOPBACK_DOMAIN, "192.0.2.0"); /* TEST-NET-1 */

	/* Send a message that involves dot-stuffing, ensuring that
	 * when it gets sent again by mod_smtp_delivery_external, the dot-stuffing
	 * is added back again, and finally that the final message is not dot-stuffed. */
	SWRITE(clientfd, "MAIL FROM:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "RCPT TO:<" TEST_EMAIL_EXTERNAL_OUTGOING_LOOPBACK ">\r\n");
	CLIENT_EXPECT(clientfd, "250");
	/* test_send_sample_body actually has a dot-stuffed line: "....See you there!"
	 * Only difference here is we send to a deliverable address so we can exercise DATA from the queue. */
	if (test_send_sample_body(clientfd, TEST_EMAIL)) {
		goto cleanup;
	}
	CLIENT_EXPECT(clientfd, "250");

	/* Wait for the outgoing attempt to temporarily fail and finish (will abort connect after 1 second) */
	usleep(1050000);

	/* Now that it has been accepted for what was originally an "external" domain,
	 * we modify the hosts file to make the domain loop back, so that we'll
	 * deliver the message back to ourselves and we won't reject it at RCPT TO. */
	RESET_HOSTS();
	ADD_TO_HOSTS_FILE(TEST_EMAIL_EXTERNAL_OUTGOING_LOOPBACK_DOMAIN, "127.0.0.1");
	TEST_ADD_SUBCONFIG("smtp_loopback", "mod_mail.conf");
	TEST_CLI_COMMAND("reload mod_mail");

	CREATE_IMAP_CONNECTION(imapfd, TEST_USER, TEST_PASS);
	SELECT_MAILBOX(imapfd, "a2", "INBOX");

	SWRITE(imapfd, "c1 IDLE" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "+");

	TEST_CLI_COMMAND("runq");

	CLIENT_EXPECT(imapfd, "* 2 EXISTS"); /* Non-delivery report was received, so this will be message #2 */
	SWRITE(imapfd, "DONE" ENDL);
	CLIENT_EXPECT(imapfd, "c1 OK");
	ENSURE_TMP_QUEUE_FILES_CLEANED_UP();

	SWRITE(imapfd, "c2 UID FETCH 2 (BODY[TEXT])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, ENDL "...See you there!" ENDL);

	ENSURE_TMP_QUEUE_FILES_CLEANED_UP();

	res = 0;

cleanup:
	close(clientfd);
	close_if(imapfd);
	RESTORE_HOSTS();
	return res;
}

TEST_MODULE_INFO_STANDARD("SMTP Queue Tests");
