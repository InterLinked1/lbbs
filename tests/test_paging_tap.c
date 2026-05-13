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
 * \brief TAP/IXO Paging Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Things this test module tests (to some extent):
 * - Inbound TAP/IXO - also manually tested March 2026 using Motorola AlphaMate II
 * - Outbound TAP/IXO - also manually tested March 2026, works on same LAN and outbound to Spok over POTS (with SUPPORT_LOW_QUALITY_PHONE_LINES),
 * - Inbound TMP - also manually tested March 2026 using Ultratec Superprint 4425 TDD
 */

static int pre(void)
{
	/* This test module mostly tests SNPP as far as the paging protocols go,
	 * but the main goal is really to excercise the paging core and mod_paging. */
	test_preload_module("mod_mail.so");
	test_preload_module("mod_asterisk_ami.so");
	test_load_module("mod_paging.so");
	test_load_module("mod_paging_snpp.so");
	test_load_module("mod_paging_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_snpp.so");
	test_load_module("net_smtp.so");
	test_load_module("net_tap.so");
	test_load_module("net_tmp.so");
	/* For IMAP: */
	test_preload_module("mod_mimeparse.so");
	test_load_module("net_imap.so");

	TEST_ADD_CONFIG("transfers.conf"); /* So we can use home directory configs */
	TEST_ADD_SUBCONFIG("paging", "mod_asterisk_ami.conf")
	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("mod_paging.conf");
	TEST_ADD_CONFIG("net_imap.conf");
	TEST_ADD_CONFIG("net_tap.conf");
	TEST_ADD_CONFIG("net_tmp.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);

	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);
	TEST_MKDIR(TEST_HOME_DIR_ROOT);
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/1/.config");
	TEST_ADD_CONFIG_INTO_DIR("paging/.paging.1", TEST_HOME_DIR_ROOT "/1/.config/.paging");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/2");
	TEST_MKDIR(TEST_HOME_DIR_ROOT "/2/.config");
	TEST_ADD_CONFIG_INTO_DIR("paging/.paging.2", TEST_HOME_DIR_ROOT "/2/.config/.paging");

	/* This test requires an Asterisk server running for the softmodem connection
	 * We don't use /etc/asterisk to avoid clobbering system configs if this
	 * host is already running Asterisk for a different reason. */
	TEST_RESET_MKDIR("/tmp/etc_asterisk");
	TEST_ADD_SUBCONFIG_ABS("paging/asterisk", "/tmp/etc_asterisk", "asterisk.conf");
	TEST_ADD_SUBCONFIG_ABS("paging/asterisk", "/tmp/etc_asterisk", "modules.conf");
	TEST_ADD_SUBCONFIG_ABS("paging/asterisk", "/tmp/etc_asterisk", "logger.conf");
	TEST_ADD_SUBCONFIG_ABS("paging/asterisk", "/tmp/etc_asterisk", "cli.conf");
	TEST_ADD_SUBCONFIG_ABS("paging/asterisk", "/tmp/etc_asterisk", "extensions.conf");
	TEST_ADD_SUBCONFIG_ABS("paging/asterisk", "/tmp/etc_asterisk", "manager.conf");
	TEST_ADD_SUBCONFIG_ABS("paging/asterisk", "/tmp/etc_asterisk", "confbridge.conf");

	/* Start Asterisk, truncating logs inbetween */
	system("(killall asterisk && sleep 1); rm -f " TEST_ROOT_DIR "/asterisk.log " TEST_ROOT_DIR "/ami.log");
	if (system("/usr/sbin/asterisk -C /tmp/etc_asterisk/asterisk.conf")) {
		system("(killall asterisk && sleep 1)"); /* Repeat and try again */
		if (system("/usr/sbin/asterisk -C /tmp/etc_asterisk/asterisk.conf")) {
			bbs_error("Couldn't start Asterisk\n");
			return -1;
		}
	}

	usleep(1000 * SEC_MS(1)); /* wait for Asterisk to start up */

	/* Asterisk needs to be running for this test */
	TEST_REQUIRE_FILE("/usr/sbin/asterisk");
	TEST_REQUIRE_FILE("/var/run/asterisk/asterisk.ctl");
	TEST_REQUIRE_FILE("/var/run/asterisk/asterisk.pid");

	return 0;
}

static int run(void)
{
	int clientfd = -1, imapfd = -1;
	int res = -1;
	char buf[512];

	/* Set up IMAP connection to receive events */
	CREATE_IMAP_CONNECTION(imapfd, TEST_USER2, TEST_PASS2);
	SELECT_MAILBOX(imapfd, "a2", "INBOX");
	SWRITE(imapfd, "a3 IDLE" ENDL);
	CLIENT_EXPECT(imapfd, "+");

	/* Set up an SNPP client connection */
	clientfd = test_make_socket(444);
	REQUIRE_FD(clientfd);
	CLIENT_EXPECT(clientfd, "220");

	/* Send a message that will get delivered by TAP to 5551202 (which belongs to user 2) */
	SWRITE(clientfd, "PAGE 5559901\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This is a short message that will be sent by modem\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT_BUF(clientfd, "250", buf);

	/* It will take some time for the message to get sent by TAP,
	 * since we need to set up a data session over a phone call. */
	CLIENT_EXPECT_EVENTUALLY_SEC(imapfd, 15, "* 1 EXISTS");

	/* Send a message that will require multiple blocks to be transmitted (> 251 chars) */
	SWRITE(clientfd, "PAGE 5559901\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "MESS This is a long message that will be sent by modem. Well, it's not particularly large, in the grand scheme of messages, but it is longer than the previous one, it's somewhat long for a page in general, and it's long enough to require multiple blocks, because it is longer than 251 characters.\r\n");
	CLIENT_EXPECT(clientfd, "250");
	SWRITE(clientfd, "SEND\r\n");
	CLIENT_EXPECT_BUF(clientfd, "250", buf);

	CLIENT_EXPECT_EVENTUALLY_SEC(imapfd, 20, "* 2 EXISTS");

	/* Since testing TMP requires all the same mechanics as TAP (i.e. a running Asterisk system),
	 * go ahead and test that real quickly now as well.
	 * Message 2 in the dialplan will trigger message 3 to be sent via TMP */
	CLIENT_EXPECT_EVENTUALLY_SEC(imapfd, 15, "* 3 EXISTS");

	SWRITE(imapfd, "DONE" ENDL);
	CLIENT_EXPECT(imapfd, "a3 OK");

	SWRITE(imapfd, "a4 UID FETCH 1 (BODY[TEXT])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "This is a short message that will be sent by modem");

	SWRITE(imapfd, "a5 UID FETCH 2 (BODY[TEXT])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "This is a long message that will be sent by modem. Well, it's not particularly large, in the grand scheme of messages, but it is longer than the previous one, it's somewhat long for a page in general, and it's long enough to require multiple blocks, because it is longer than 251 characters.");

	SWRITE(imapfd, "a6 UID FETCH 3 (BODY[TEXT])" ENDL);
	CLIENT_EXPECT_EVENTUALLY(imapfd, "THIS IS A TEST MESSAGE SENT BY TDD");

	res = 0;

	usleep(1000 * SEC_MS(3)); /* Wait a moment for the TAP/TMP clients to disconnect, for clean shutdown */

cleanup:
	close_if(clientfd);
	close_if(imapfd);
#if 1
	if (res) {
		/* If the test fails, dump the Asterisk and AMI logs in case that's part of the issue */
		system("cat " TEST_ROOT_DIR "/asterisk.log " TEST_ROOT_DIR "/ami.log");
	}
#endif
	return res;
}

TEST_MODULE_INFO_STANDARD_FLAGS("TAP/IXO Paging Tests", TEST_FLAG_NO_AUTOLOAD);
