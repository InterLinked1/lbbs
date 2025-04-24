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

#include <sys/wait.h>

#include "include/module.h"
#include "include/utils.h"
#include "include/system.h"
#include "include/node.h" /* for childpid */

#include "include/net_smtp.h"

/*! \todo
 * Make CONFIG_FILE and SPAM_CMD configurable,
 * would need to add a config file for this module.
 * Configurable options should be:
 * - config file
 * - command to run
 * - max message size that spam filtering should run on
 */

#define CONFIG_FILE "/etc/spamassassin/local.cf"

/* There are two ways to use SpamAssassin:
 * One is the standalone spamassassin binary.
 * The other is using the spamc client in conjunction with the spamd daemon.
 *
 * spamc is intended for scripts and loads much faster than spamassassin.
 * The --headers available in spamc (but not spamassassin) also allows spamd to return only the headers back to spamc.
 * spamc will still return the full message back to us, unfortunately there's no option to not to do that,
 * we just ignore everything after the headers. */
#if 0
/* This seems slightly more optimal in theory,
 * but this command doesn't actually work,
 * the config file /etc/spamassassin/local.cf is ignored,
 * so use the standalone binary for now for the right output.
 *
 * Additionally, and potentially more problematically,
 * spamc seems to hang when receiving messages more than around ~500 KB.
 * While those probably shouldn't be filtered anyways, that's not good.
 * spamassassin doesn't seem to suffer from this issue. */
#define SPAM_CMD "spamc --headers -F " CONFIG_FILE
#else
#define SPAM_CMD "spamassassin"
#endif

#define MAX_SPAM_SIZE SIZE_KB(768) /* About 3/4 MB */

/* There are a few ways SpamAssassin can be used by an MTA.
 * Some approaches rely on a spamd daemon, e.g. milter, spamc.
 * This approach doesn't rely on a daemon, but it won't perform
 * as well on high-traffic servers. */

static int spam_filter_cb(struct smtp_filter_data *f)
{
	char *argv[16];
	char args[64];
	int res;
	ssize_t spliced;
	int input[2], output[2];
	char buf[1024];
	struct readline_data rldata;
	int headers_written = 0;
	pid_t pid;

	/* We only want to analyze incoming mail FROM the Internet, not outgoing mail TO the Internet.
	 * Of course, from our vantage point, there is no way to explicitly tell that, but we can
	 * figure it out by looking at the source IP address.
	 * Even though this filter only runs for SMTP_DIRECTION_IN, relayed mail still passes through as IN before OUT.
	 * If that IP is allowed to relay mail through us, then it's outbound (to the Internet) mail, and we skip the check.
	 * If that IP is allowed to deliver mail to us, then it's inbound (from the Internet) mail, and we do the check!
	 * In other words, authorized relays (which egress mail) should be exempt from this.
	 * Trusted relays (which deliver mail to us) (along with any other server) are not. */
	if (smtp_is_exempt_relay(f->smtp)) {
		return 0; /* This mail originating on a trusted server and is currently outbound, skip */
	}

	/* At this point, technically eligible for spam filtering. However, large messages typically don't get filtered.
	 * Most spam doesn't exceed this threshold so it's unlikely that such mail would be spam.
	 * Per https://spamassassin.apache.org/full/3.2.x/doc/spamassassin-run.html:
	 *
	 * Please note that SpamAssassin is not designed to scan large messages.
	 * Don't feed messages larger than about 500 KB to SpamAssassin, as this will consume a huge amount of memory. */
	if (f->size > MAX_SPAM_SIZE) {
		bbs_debug(5, "Message is too big to analyze\n");
		return 0;
	}

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
	 * want to allow the user to provide the spamassassin / spamc (or other arbitrary) command to execute,
	 * so in anticipation of that: */

	strcpy(args, SPAM_CMD);
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

	/* We can't use bbs_execvp, because we need to fork BEFORE we start writing data into the pipes.
	 * Otherwise, if the pipes fill up, we'll just block here. So SpamAssassin needs to be running
	 * while we feed it the input. */
	pid = fork();
	if (pid == -1) {
		bbs_error("fork failed: %s\n", strerror(errno));
		goto cleanup;
	} else if (!pid) {
		bbs_child_exec_prep(input[0], output[1]);
		res = execvp(argv[0], argv);
		_exit(errno);
	}

	smtp_node(f->smtp)->childpid = pid; /* Since we're not using bbs_execvp, we need to manually store the child while it's running */
	CLOSE(input[0]); /* Close read end of STDIN */
	CLOSE(output[1]); /* Close write end of STDOUT */

	/* See comment from smtp_run_filters, in net_smtp.c.
	 * TL;DR f->inputfd only gives us the original message, not headers
	 * appended by other filters that just ran, like Received, SPF, DMARC, etc.
	 * Unlike most other filters, SpamAssassin needs those headers
	 * in order to do its job accurately, so we also explicitly
	 * read whatever is in the output file BEFORE the rest of the message.
	 *
	 * So, we explicitly write headers that were prepended by filters that ran before us.
	 *
	 * Conveniently, this actually ends up matching the order that the
	 * headers will be in when the final message is actually written to disk,
	 * so this faithfully reproduces the message up to this point in time,
	 * up to the last filter that executed just before this one. */
	if (smtp_filter_write_prepended_headers(f, input[1])) {
		res = -1;
		CLOSE(input[1]);
		CLOSE(output[0]);
		waitpid(pid, NULL, 0);
		smtp_node(f->smtp)->childpid = 0;
		goto cleanup;
	}

	/* We cannot use bbs_copy_file because that will attempt to use copy_file_range,
	 * which only works for regular files.
	 * In this case, since the destination is a pipe, we can use splice(2) */
	spliced = bbs_splice(f->inputfd, input[1], f->size);
	if (spliced != (ssize_t) f->size) {
		bbs_error("splice %d -> %d failed (%ld != %lu): %s\n", f->inputfd, input[1], spliced, f->size, strerror(errno));
		res = -1;
		CLOSE(input[1]);
		CLOSE(output[0]);
		waitpid(pid, NULL, 0);
		smtp_node(f->smtp)->childpid = 0;
		goto cleanup;
	}

	CLOSE(input[1]); /* Done writing input, close write end of STDIN to child */

	/* Lucky for us, SpamAssassin will wait for output to finish before it starts writing any output.
	 * That means we can send all the input (above) and then read all the output (below).
	 * If we started receiving output in the middle, and that had the potential to block the input writing,
	 * then that would complicate things significantly, but we don't need to worry about that! */

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
		ssize_t rres = bbs_readline(output[0], &rldata, "\r\n", SEC_MS(20));
		if (rres < 0) {
			/* Timeout */
			bbs_warning("Timeout waiting for SpamAssassin\n");
			res = -1;
			break;
		} else if (rres == 0) {
			/* End of headers (CR LF). */
			break;
		}
		/* Don't use isspace because we don't want to count newlines */
		if (buf[0] != ' ' && buf[0] != '\t' && !STARTS_WITH(buf, "X-Spam-")) {
			if (headers_written) {
				break;
			}
			continue;
		}
		smtp_filter_write(f, "%s\r\n", buf);
		headers_written++;
	}

	CLOSE(output[0]); /* Close read end to force child process to exit */
	waitpid(pid, NULL, 0); /* Reap the child before exiting */
	smtp_node(f->smtp)->childpid = 0;

	if (!headers_written) {
		bbs_warning("No X-Spam headers prepended?\n");
	}

	res = 0;

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
	if (!bbs_file_exists(CONFIG_FILE)) {
		bbs_error("%s doesn't exist, declining to load\n", CONFIG_FILE);
		return -1;
	}
	smtp_filter_register(&spam_filter, "SpamAssassin", SMTP_FILTER_SPAM_FILTER, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 10);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&spam_filter);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("SpamAssassin spam filtering", "net_smtp.so");
