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
 * \brief SpamAssassin spam filtering
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/module.h"
#include "include/utils.h"
#include "include/system.h"

#include "include/net_smtp.h"

/* There are a few ways SpamAssassin can be used by an MTA.
 * Some approaches rely on a spamd daemon, e.g. milter, spamc.
 * This approach doesn't rely on a daemon, but it won't perform
 * as well on high-traffic servers. */

static int spam_filter_cb(struct smtp_filter_data *f)
{
	char *argv[16];
	char args[64];
	int res;
	int input[2], output[2];
	char buf[1024];
	struct readline_data rldata;
	off64_t off_in = 0;

	/* The only thing that this module really does is
	 * execute the SpamAssassin binary, passing it the email message on STDIN,
	 * and reading a few headers of interest from the output stream to prepend.
	 * This is a rather trivial wrapper, but it exists mainly because
	 * we are prepending, not replacing, as most simple filters intended to be
	 * executed directly from an MTA do. Some logic is required here to only
	 * pluck the lines we want and ignore everything else.
	 * For that reason, a generic mechanism in net_smtp.conf to allow
	 * executing certain filters on incoming messages (like postfix or sendmail might allow)
	 * wouldn't be very appropriate. Almost certainly, somebody's going to
	 * omit the termination connection, and then the message will end up prepended to itself.
	 */

	/* This isn't necessary for now since it's hardcoded, but in the future, we may
	 * want to allow the user to provide the spamassassin (or other arbitrary) command to execute,
	 * so in anticipation of that: */

	strcpy(args, "spamassassin");
	res = bbs_argv_from_str(argv, ARRAY_LEN(argv), args);
	if (res < 1 || res >= (int) ARRAY_LEN(argv)) { /* Failure or truncation */
		return -1;
	}

	if (pipe(input)) {
		return -1;
	} else if (pipe(output)) {
		PIPE_CLOSE(input);
		return -1;
	}
	/* We cannot use bbs_copy_file because that will attempt to use copy_file_range,
	 * which only works for regular files.
	 * In this case, since the destination is a pipe, we can use splice(2) */
	if (splice(f->inputfd, &off_in, input[1], NULL, f->size, 0) != (ssize_t) f->size) {
		bbs_error("splice %d -> %d failed: %s\n", f->inputfd, input[1], strerror(errno));
		res = -1;
		goto cleanup;
	}

	CLOSE(input[1]); /* Close write end of STDIN */
	res = bbs_execvp_fd_headless(f->node, input[0], output[1], argv[0], argv);
	if (res) {
		res = -1;
		goto cleanup;
	}

	/* We want just the first few lines, so we need to reliably read line by line */
	bbs_readline_init(&rldata, buf, sizeof(buf));

	/* Don't wait more than 20 seconds for SpamAssassin to return a line (really, the first line).
	 * The network tests could take a second, so we don't want to be too low here.
	 * At the same time, we need to be mindful that we are blocking the SMTP connection right now,
	 * so we can't wait forever. */
	for (;;) {
		/* All the SpamAssassin headers begin with X-Spam, and appear at the very top.
		 * Some of these headers are multiple lines.
		 * So keep prepending lines until we get to a line that does not begin with a space,
		 * and does not begin wtih X-Spam. */
		res = bbs_readline(output[0], &rldata, "\r\n", SEC_MS(20));
		if (res < 0) {
			/* Timeout */
			bbs_warning("Timeout waiting for SpamAssassin\n");
			break;
		} else if (res == 0) {
			/* This would be end of headers (CR LF).
			 * It's unlikely that there would be ONLY SpamAssassin headers and nothing else,
			 * but it could happen... */
			bbs_debug(7, "Got end of headers\n");
			break;
		}
		/* Don't use isspace because we don't want to count newlines */
		if (buf[0] != ' ' && buf[0] != '\t' && !STARTS_WITH(buf, "X-Spam-")) {
			res = 0;
			break;
		}
		smtp_filter_write(f, "%s\r\n", buf);
	}

cleanup:
	PIPE_CLOSE(input);
	PIPE_CLOSE(output);
	return res;
}

struct smtp_filter_provider spam_filter = {
	.on_body = spam_filter_cb,
};

static int load_module(void)
{
	/* This module has no hard prerequisites (i.e. for compiling or linking).
	 * However, it's obviously not useful without SpamAssassin.
	 * The spamassassin binary could potentially be in a few different directories.
	 * But if it exists, /etc/spamassassin is bound to exist, so use that as a proxy.
	 * Don't bother loading if SpamAssassin isn't even on the system. */
	if (!bbs_file_exists("/etc/spamassassin/local.cf")) {
		bbs_error("/etc/spamassassin/local.cf doesn't exist, declining to load\n");
		return -1;
	}
	smtp_filter_register(&spam_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 10);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&spam_filter);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("SpamAssassin spam filtering", "net_smtp.so");
