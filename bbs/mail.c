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
 * \brief Email generation and transmission
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

#include "include/base64.h"
#include "include/mail.h"
#include "include/system.h"
#include "include/config.h"
#include "include/utils.h"

#define MESSAGE_ID_PREFIX "LBBS"

#define SENDMAIL "/usr/sbin/sendmail"
#define SENDMAIL_ARG "-t"
#define SENDMAIL_CMD "/usr/sbin/sendmail -t"
#define ENDL "\n"
#define	MAIL_FILE_MODE	0600
#define MAXHOSTNAMELEN   256

static char default_to[84];
static char default_from[84];
static char default_errorsto[84];

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("mail.conf", 1);

	if (!cfg) {
		return 0;
	}

	if (eaccess(SENDMAIL, R_OK)) {
		/* If mail.conf exists, warn now if sendmail is not detected */
		bbs_warning("System mailer '%s' does not exist, email transmission will fail.\n", SENDMAIL);
	}

	bbs_config_val_set_str(cfg, "general", "errorsto", default_errorsto, sizeof(default_errorsto));
	bbs_config_val_set_str(cfg, "defaults", "to", default_to, sizeof(default_to));
	bbs_config_val_set_str(cfg, "defaults", "from", default_from, sizeof(default_from));
	return 0;
}

int bbs_mail_init(void)
{
	return load_config();
}

/*!
 * \brief Create an email
 * \param p File handler into which to write the email
 * \param subject Email subject
 * \param body Email body
 * \param to Recipient
 * \param from Sender
 * \param replyto Reply-To address. If NULL, not added.
 * \param errorsto Errors-To address. If NULL, not added.
 * \param attachments Pipe (|) separated list of full file paths of attachments to attach.
 * \param delete Whether to delete attachments afterwards
 * \retval 0 on total success and -1 on partial or total failure to generate the message properly
 */
int bbs_make_email_file(FILE *p, const char *subject, const char *body, const char *to, const char *from, const char *replyto, const char *errorsto, const char *attachments, int deleteafter)
{
	struct tm tm;
	char date[256];
	char host[MAXHOSTNAMELEN] = "";
	char who[257];
	char bound[256];
	char filename[256];
	char *attachmentsbuf, *attachmentlist, *attachment;
	struct timeval when;
	int res = 0;
	time_t t = time(NULL);

	gettimeofday(&when, NULL);
	gethostname(host, sizeof(host) - 1);

	if (strchr(to, '@')) {
		safe_strncpy(who, to, sizeof(who));
	} else {
		snprintf(who, sizeof(who), "%s@%s", to, host);
	}

	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", localtime_r(&t, &tm));
	fprintf(p, "Date: %s" ENDL, date);
	fprintf(p, "Return-Path: %s" ENDL, from); /* Can be needed for email deliverability (SPF) */
	fprintf(p, "Sender: %s" ENDL, from);
	fprintf(p, "From: %s" ENDL, from);
	if (!strlen_zero(replyto)) {
		fprintf(p, "Reply-To: %s" ENDL, replyto);
	}
	fprintf(p, "To: %s" ENDL, to);
	fprintf(p, "Subject: %s" ENDL, subject);
	fprintf(p, "Message-ID: <%s-%u-%d@%s>" ENDL, MESSAGE_ID_PREFIX, (unsigned int) random(), (int) getpid(), host);
	fprintf(p, "MIME-Version: 1.0" ENDL);
	if (!strlen_zero(attachments)) {
		/* Something unique. */
		snprintf(bound, sizeof(bound), "----attachment_%d%u", (int) getpid(), (unsigned int) random());
		fprintf(p, "Content-Type: multipart/mixed; boundary=\"%s\"" ENDL, bound);
		fprintf(p, ENDL ENDL "This is a multi-part message in MIME format." ENDL ENDL);
		fprintf(p, "--%s" ENDL, bound);
	}
	fprintf(p, "Content-Type: text/plain; charset=%s; format=flowed" ENDL "Content-Transfer-Encoding: 8bit" ENDL, "ISO-8859-1");
	fprintf(p, "Content-Language: %s" ENDL, "en-US");
	if (!strlen_zero(errorsto)) {
		fprintf(p, "Errors-To: %s" ENDL, errorsto);
	}
	fprintf(p, ENDL);
	fprintf(p, "%s", body);
	if (strlen_zero(attachments)) {
		return 0;
	}
	/* Use strdup instead of strdupa, as we don't know how long the list is, and to make gcc happy with -Wstack-protector */
	attachmentlist = attachmentsbuf = strdup(attachments); /* Dup pointer for strsep so we can still free() it */
	if (ALLOC_FAILURE(attachmentsbuf)) {
		return -1;
	}
	while ((attachment = strsep(&attachmentlist, "|"))) {
		char *fullname, *friendlyname, *mimetype;
		snprintf(filename, sizeof(filename), "%s", basename(attachment));

		mimetype = attachment;
		fullname = strsep(&mimetype, ":");
		friendlyname = strsep(&mimetype, ":");

		if (strlen_zero(friendlyname)) {
			friendlyname = filename; /* no specified name, so use the full base file name */
		}

		if (!bbs_file_exists(fullname)) {
			bbs_error("File does not exist: %s\n", fullname);
			res = -1;
			continue;
		}
		bbs_debug(5, "Creating attachment: %s (named %s)\n", fullname, friendlyname);
		fprintf(p, ENDL "--%s" ENDL, bound);

		if (!strlen_zero(mimetype)) {
			/* is Content-Type name just the file name? Or maybe there's more to it than that? */
			fprintf(p, "Content-Type: %s; name=\"%s\"" ENDL, mimetype, friendlyname);
		}

		fprintf(p, "Content-Transfer-Encoding: base64" ENDL);
		fprintf(p, "Content-Description: File attachment." ENDL);
		fprintf(p, "Content-Disposition: attachment; filename=\"%s\"" ENDL ENDL, friendlyname);
		if (base64_encode_file(fullname, p, ENDL)) {
			bbs_error("Failed to add attachment (base64 encoding failure)\n");
			res = -1;
			continue;
		}
		if (deleteafter) {
			unlink(fullname);
		}
	}
	free(attachmentsbuf);
	fprintf(p, ENDL ENDL "--%s--" ENDL "." ENDL, bound); /* After the last attachment */
	return res;
}

int __attribute__ ((format (gnu_printf, 6, 7))) bbs_mail_fmt(int async, const char *to, const char *from, const char *replyto, const char *subject, const char *fmt, ...)
{
	int len, res;
	char *buf;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* No format strings, avoid unnecessary allocation and call directly */
		return bbs_mail(async, to, from, replyto, subject, fmt);
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	res = bbs_mail(async, to, from, replyto, subject, buf);
	free(buf);
	return res;
}

int bbs_mail(int async, const char *to, const char *from, const char *replyto, const char *subject, const char *body)
{
	int res;
	FILE *p;
	char tmp[80] = "/tmp/bbsmail-XXXXXX";
	const char *errorsto;

	/* Use default email addresses if necessary */
	errorsto = default_errorsto;
	if (strlen_zero(from)) {
		from = default_from;
	}
	if (strlen_zero(to)) {
		to = default_to;
	}

	if (strlen_zero(to)) {
		bbs_error("No recipient provided, and no default in mail.conf, aborting\n");
		return -1;
	} else if (strlen_zero(from)) {
		bbs_error("No sender address provided, and no default in mail.conf, aborting\n");
		return -1;
	}

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

	/* XXX We could be calling this function from a node thread.
	 * If it's async, it's totally fine and there's no problem, but if not, we're really hoping sendmail doesn't block very long or it will block shutdown.
	 * Probably okay here, but in general don't do this... always pass a handle to node using the headless function variant.
	 */
	if (async) {
		char tmp2[256];
		/* We can't simply double fork() and call it a day, to run this in the background,
		 * since we're doing input redirection (and need to clean up afterwards).
		 * The shell will have to help us out with that. */
		char *argv[4] = { "/bin/sh", "-c", tmp2, NULL };

		/* Run it in the background using a shell */
		fclose(p);
		snprintf(tmp2, sizeof(tmp2), "( %s < %s ; rm -f %s ) &", SENDMAIL_CMD, tmp, tmp);
		res = bbs_execvp(NULL, "/bin/sh", argv);
	} else {
		/* Call sendmail synchronously. */
		char *argv[3] = { SENDMAIL, SENDMAIL_ARG, NULL };
		/* Have sendmail read STDIN from the file itself */
		rewind(p);
		res = bbs_execvp_fd(NULL, fileno(p), -1, SENDMAIL, argv);
		fclose(p);
		if (remove(tmp)) {
			bbs_error("Failed to delete temporary email file '%s'\n", tmp);
		} else {
			bbs_debug(7, "Removed temporary file '%s'\n", tmp);
		}
	}

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
			bbs_debug(1, "%s sent mail to %s with command '%s'\n", async ? "Asynchronously" : "Synchronously", to, SENDMAIL_CMD);
		}
	}
	if (res) {
		bbs_error("Failed to send email to %s\n", to);
	}
	return res;
}
