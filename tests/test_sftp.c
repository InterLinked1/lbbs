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
 * \brief SFTP Tests
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
#include <libssh/sftp.h>

static int pre(void)
{
	test_load_module("net_ssh.so");

	TEST_ADD_CONFIG("transfers.conf");
	TEST_ADD_CONFIG("net_ssh.conf");

	TEST_RESET_MKDIR(TEST_TRANSFER_DIR);

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

static ssh_session start_ssh(void)
{
	ssh_session session = NULL;
	unsigned int methods;
	char *banner;
	static int port = 2222;

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
		bbs_error("Connection failed: %s\n",ssh_get_error(session));
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
	if (ssh_userauth_password(session, NULL, TEST_PASS) != SSH_AUTH_SUCCESS) {
		bbs_error("Authentication failed: %s\n", ssh_get_error(session));
		goto cleanup;
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

static int do_sftp(ssh_session session)
{
	char buf[128];
	int res = -1;
	unsigned int count, i;
	char *path = NULL;
	ssize_t len;
	sftp_dir dir = NULL;
	sftp_attributes attr;
	sftp_file file = NULL;
	sftp_session sftp;

	sftp = sftp_new(session);
	if (!sftp) {
		return -1;
	}

	if (sftp_init(sftp)) {
		bbs_error("Error initializing SFTP: %s\n", ssh_get_error(session));
		goto cleanup;
	}

	count = sftp_extensions_get_count(sftp);
	bbs_debug(3, "%d extension%s supported:\n", count, ESS(count));
    for (i = 0; i < count; i++) {
		bbs_debug(3, "\t%s, version: %s\n", sftp_extensions_get_name(sftp, i), sftp_extensions_get_data(sftp, i));
    }

#define TEST_FILE_CONTENTS "This a test file, which we will upload via SFTP, download via SFTP, and then compare to ensure they match!\r\n"

	/* Upload a file in the user's home directory */
	file = sftp_open(sftp, "testfile.txt", O_WRONLY | O_CREAT, 0700);
    if (!file) {
		bbs_error("Failed to open file for writing: %s\n", ssh_get_error(session));
		goto cleanup;
    }

	len = sftp_write(file, TEST_FILE_CONTENTS, STRLEN(TEST_FILE_CONTENTS));
	if (len != STRLEN(TEST_FILE_CONTENTS)) {
		bbs_error("Failed to write file: %s\n", ssh_get_error(session));
		goto cleanup;
	}
	sftp_close(file);

	/* Test file path canonicalization */
	path = sftp_canonicalize_path(sftp, "../../home/./" TEST_USER "/testfile.txt");
	if (!path) {
		bbs_error("Failed to canonicalize path\n");
		goto cleanup;
	}

	/* Download the file */
	file = sftp_open(sftp, path, O_RDONLY, 0);
	FREE(path);
	if (!file) {
		bbs_error("Failed to open file for reading: %s\n", ssh_get_error(session));
		goto cleanup;
	}

	len = sftp_read(file, buf, sizeof(buf));
	if (len != STRLEN(TEST_FILE_CONTENTS)) {
		bbs_error("File expected to be of size %lu but was size %lu\n", STRLEN(TEST_FILE_CONTENTS), len);
		goto cleanup;
	}
	sftp_close(file);
	file = NULL;

	/* Repeat, using absolute path */
	file = sftp_open(sftp, "/home/" TEST_USER "//./testfile.txt", O_RDONLY, 0);
	if (!file) {
		bbs_error("Failed to open file for reading: %s\n", ssh_get_error(session));
		goto cleanup;
	}
	sftp_close(file);
	file = NULL;

	/* This path doesn't exist */
	file = sftp_open(sftp, "/home/" TEST_USER "/testfile.txt2", O_RDONLY, 0);
	if (file) {
		bbs_error("File should be NULL");
		goto cleanup;
	}

	/* Open our home directory and ensure the file is in the file listing */
	dir = sftp_opendir(sftp, "./");
	if (!dir) {
		bbs_error("Failed to open directory: %s\n", ssh_get_error(session));
		goto cleanup;
	}

	len = 0;
	while ((attr = sftp_readdir(sftp, dir))) {
		if (!strcmp(attr->name, "testfile.txt")) {
			len = 1;
		}
        sftp_attributes_free(attr);
    }
	if (!sftp_dir_eof(dir)) {
		bbs_error("Error reading directory: %s\n", ssh_get_error(session));
		goto cleanup;
    }

	if (!len) {
		bbs_error("Didn't find file in file listing\n");
		goto cleanup;
	}

	res = 0;

cleanup:
	free_if(path);
	if (file) {
		sftp_close(file);
	}
	if (dir) {
		sftp_closedir(dir);
	}
	sftp_free(sftp);
	return res;
}

static int run(void)
{
	ssh_session session = NULL;
	int res = -1;

	/* First session, disconnect cleanly at the end */
	session = start_ssh();
	if (!session) {
		goto cleanup;
	}
	if (do_sftp(session)) {
		goto cleanup;
	}
	ssh_disconnect(session);
	ssh_free(session);

	/* Second session, don't disconnect cleanly at the end */
	session = start_ssh();
	if (!session) {
		goto cleanup;
	}
	if (do_sftp(session)) {
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

TEST_MODULE_INFO_POST("SFTP Tests");
