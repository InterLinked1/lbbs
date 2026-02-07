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
 * \brief Email generation and transmission using sendmail
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h> /* use int64_t */
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h> /* use struct tm */
#include <sys/stat.h> /* use mode_t */
#include <unistd.h> /* use close */
#include <sys/time.h> /* use gettimeofday */

#include "include/mail.h"
#include "include/system.h"
#include "include/utils.h"
#include "include/module.h"

#define SENDMAIL "/usr/sbin/sendmail"
#define SENDMAIL_ARG "-t"
#define SENDMAIL_CMD "/usr/sbin/sendmail -t"

static int sendmail_helper(const char *tmp, FILE *p, int async)
{
	struct bbs_exec_params x;
	int res;

	/* XXX We could be calling this function from a node thread.
	 * If it's async, it's totally fine and there's no problem, but if not, we're really hoping sendmail doesn't block very long or it will block shutdown.
	 * Probably okay here, but in general don't do this... always pass a handle to node using the headless function variant.
	 */

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	if (async) {
		char tmp2[256];
		/* We can't simply double fork() and call it a day, to run this in the background,
		 * since we're doing input redirection (and need to clean up afterwards).
		 * The shell will have to help us out with that. */
		char *argv[4] = { "/bin/sh", "-c", tmp2, NULL };

		/* Run it in the background using a shell */
		fclose(p);
		snprintf(tmp2, sizeof(tmp2), "( %s < %s ; rm -f %s ) &", SENDMAIL_CMD, tmp, tmp);
		EXEC_PARAMS_INIT_HEADLESS(x);
		res = bbs_execvp(NULL, &x, "/bin/sh", argv);
	} else {
		/* Call sendmail synchronously. */
		char *argv[3] = { SENDMAIL, SENDMAIL_ARG, NULL };
		/* Have sendmail read STDIN from the file itself */
		rewind(p);
		EXEC_PARAMS_INIT_FD(x, fileno(p), -1);
		res = bbs_execvp(NULL, &x, SENDMAIL, argv);
		fclose(p);
		if (remove(tmp)) {
			bbs_error("Failed to delete temporary email file '%s'\n", tmp);
		} else {
			bbs_debug(7, "Removed temporary file '%s'\n", tmp);
		}
	}
#pragma GCC diagnostic pop

	if ((res < 0) && (errno != ECHILD)) {
		bbs_error("Unable to execute '%s'\n", SENDMAIL_CMD);
	} else if (res == 127) {
		bbs_error("Unable to execute '%s'\n", SENDMAIL_CMD);
	} else {
		/* Translate exec return value to a normal C-style res */
		if (res < 0) {
			res = 0; /* If ECHILD, ignore */
		}
		if (res != 0) {
			res = -1; /* If nonzero, ignore */
		} else {
			bbs_debug(1, "%s sent mail with command '%s'\n", async ? "Asynchronously" : "Synchronously", SENDMAIL_CMD);
		}
	}
	return res;
}

static int sendmail_full(FULL_MAILER_PARAMS)
{
	FILE *p;

	if (mailfrom) {
		return -1; /* Can't handle explicit MAIL FROM */
	} else if (recipients) {
		return -1; /* Can't handle explicit recipients, since sendmail will extract from the message */
	}

	p = fopen(tmpfile, "r");
	if (!p) {
		fprintf(stderr, "fopen(%s) failed: %s\n", tmpfile, strerror(errno));
		return -1;
	}

	return sendmail_helper(tmpfile, p, 0);
}

static int sendmail_simple(SIMPLE_MAILER_PARAMS)
{
	FILE *p;
	int res;
	char tmp[80] = "/tmp/bbsmail-XXXXXX";

	/* We can't count on sendmail existing. Check first. */
	if (eaccess(SENDMAIL, R_OK)) {
		bbs_error("System mailer '%s' does not exist, unable to send email to %s\n", SENDMAIL, to);
		return -1;
	}

	bbs_debug(4, "Sending %semail: %s -> %s (replyto %s), subject: %s\n", async ? "async " : "", from, to, S_IF(replyto), subject);

	/* Make a temporary file instead of piping directly to sendmail:
	 * a) to make debugging easier
	 * b) in case the mail command hangs
	 */
	p = bbs_mkftemp(tmp, MAIL_FILE_MODE);
	if (!p) {
		bbs_error("Unable to launch '%s' (can't create temporary file)\n", SENDMAIL_CMD);
		return -1;
	}
	bbs_make_email_file(p, subject, body, to, from, replyto, errorsto, NULL, 0);

	res = sendmail_helper(tmp, p, async);
	if (res) {
		bbs_error("Failed to send email to %s\n", to);
	}
	return res;
}

static int load_module(void)
{
	BBS_REQUIRE_EXTERNAL_PROGRAM(SENDMAIL);
	return bbs_register_mailer(sendmail_simple, sendmail_full, 10);
}

static int unload_module(void)
{
	return bbs_unregister_mailer(sendmail_simple, sendmail_full);
}

BBS_MODULE_INFO_STANDARD("SendMail email transmission");
