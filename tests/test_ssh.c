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
 * \brief SSH Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <libssh/libssh.h>

#define TEST_SSH_PORT 2222

static int pre(void)
{
	test_load_module("mod_ip_blocker.so");
	test_load_module("net_ssh.so");

	TEST_ADD_CONFIG("net_ssh.conf");

	if (ssh_init() != SSH_OK) { /* Init SSH library */
		bbs_error("libssh ssh_init failed\n");
		return -1;
	}
	return 0;
}

static int post(void)
{
	/* After the BBS has exited, clean up the SSH library. */
	ssh_finalize();
	return 0;
}

static ssh_session start_ssh(int badconnect)
{
	ssh_session session = NULL;
	unsigned int methods;
	char *banner;
	static int port = TEST_SSH_PORT;

	session = ssh_new();
	if (!session) {
		goto cleanup;
	}

	/* Connect */
	if (ssh_options_set(session, SSH_OPTIONS_HOST, "127.0.0.1") < 0) {
		bbs_error("Failed to set option: %s\n", ssh_get_error(session));
		goto cleanup;
	} else if (ssh_options_set(session, SSH_OPTIONS_PORT, &port) < 0) {
		bbs_error("Failed to set option: %s\n", ssh_get_error(session));
		goto cleanup;
	} else if (ssh_options_set(session, SSH_OPTIONS_USER, TEST_USER) < 0) {
		bbs_error("Failed to set option: %s\n", ssh_get_error(session));
		goto cleanup;
	}
	if (ssh_connect(session)) {
		bbs_error("Connection failed: %s\n", ssh_get_error(session));
	}

	/* Authenticate */
	if (ssh_userauth_none(session, NULL) == SSH_AUTH_ERROR) { /* Need to do this in order to get methods */
		bbs_error("Authentication failed: %s\n", ssh_get_error(session));
		goto cleanup;
	}
	methods = (unsigned int) ssh_userauth_list(session, NULL);
	if (!(methods & SSH_AUTH_METHOD_PASSWORD)) {
		bbs_error("Password auth unavailable\n");
		goto cleanup;
	}
	if (badconnect) {
		/* Use the wrong password for this user */
		int i;
		for (i = 0; i < 4; i++) { /* Only 3 auth attempts are allowed */
			if (ssh_userauth_password(session, NULL, "wrongpassword") == SSH_AUTH_SUCCESS) {
				bbs_error("Authentication succeeded\n");
				goto cleanup;
			}
			usleep(25000);
		}
		goto cleanup;
	} else {
		if (ssh_userauth_password(session, NULL, TEST_PASS) != SSH_AUTH_SUCCESS) {
			bbs_error("Authentication failed: %s\n", ssh_get_error(session));
			goto cleanup;
		}
	}

	banner = ssh_get_issue_banner(session);
	if (banner) {
		bbs_debug(1, "SSH banner: '%s'\n", banner);
		SSH_STRING_FREE_CHAR(banner);
	}
	return session;

cleanup:
	if (session) {
		ssh_disconnect(session);
		ssh_free(session);
	}
	return NULL;
}

static int do_ssh(ssh_session session)
{
	int res = -1;
	ssh_channel channel;

	channel = ssh_channel_new(session);
	if (channel == NULL) {
		return -1;
	}

	if (ssh_channel_open_session(channel)) {
		bbs_error("Couldn't open channel: %s\n", ssh_get_error(session));
		goto cleanup;
	} else if (ssh_channel_request_pty(channel)) {
		bbs_error("Couldn't request PTY: %s\n", ssh_get_error(session));
		goto cleanup;
	} else if (ssh_channel_request_shell(channel)) {
		bbs_error("%s\n", ssh_get_error(session));
		goto cleanup;
	}

	/* This client won't do anything and won't work,
	 * but this test ensures we don't leak memory on off-nominal paths. */
	usleep(1000000);

	res = 0;

cleanup:
	ssh_channel_free(channel);
	return res;
}

static int run(void)
{
	int clientfd = -1;
	ssh_session session = NULL;
	int res = -1;

	/* Normal session, disconnect cleanly at the end */
	session = start_ssh(0);
	if (!session) {
		goto cleanup;
	}
	if (do_ssh(session)) {
		goto cleanup;
	}
	ssh_disconnect(session);
	ssh_free(session);

	/* Force failure to test that cleanup path */
	clientfd = test_make_socket(TEST_SSH_PORT);
	REQUIRE_FD(clientfd);
	SWRITE(clientfd, "gobbledygook\r\n"); /* Emulate a non-SSH client to force key exchange failure */
	usleep(10000); /* Allow time for server to handle it has a key exchange failure */
	CLOSE(clientfd);

	/* Test by closing immediately */
	clientfd = test_make_socket(TEST_SSH_PORT);
	REQUIRE_FD(clientfd);
	CLOSE(clientfd);

	/* Use the wrong password */
	session = start_ssh(1);
	if (session) {
		goto cleanup; /* This one should not return a session */
	}

	/* Normal session, don't disconnect cleanly at the end */
	session = start_ssh(0);
	if (!session) {
		goto cleanup;
	}
	if (do_ssh(session)) {
		goto cleanup;
	}
	close(ssh_get_fd(session)); /* Rudely close the socket instead of doing a proper application-layer shutdown first */

	res = 0;

cleanup:
	if (session) {
		ssh_disconnect(session);
		ssh_free(session);
	}
	return res;
}

TEST_MODULE_INFO_POST("SSH Tests");
