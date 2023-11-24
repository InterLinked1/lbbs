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

#ifdef __FreeBSD__
#include <libgen.h> /* use basename */
#endif

#include "include/base64.h"
#include "include/mail.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/module.h"
#include "include/linkedlists.h"
#include "include/startup.h"

struct mailer {
	int (*mailer)(MAILER_PARAMS);
	struct bbs_module *module;
	RWLIST_ENTRY(mailer) entry;
	unsigned int priority;
};

static RWLIST_HEAD_STATIC(mailers, mailer);

#define MESSAGE_ID_PREFIX "LBBS"
#define ENDL "\n"
#define MAXHOSTNAMELEN   256

static char default_to[84];
static char default_from[84];
static char default_errorsto[84];

static int config_exists = 0;

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("mail.conf", 1);

	if (!cfg) {
		return 0;
	}

	config_exists = 1;

	bbs_config_val_set_str(cfg, "general", "errorsto", default_errorsto, sizeof(default_errorsto));
	bbs_config_val_set_str(cfg, "defaults", "to", default_to, sizeof(default_to));
	bbs_config_val_set_str(cfg, "defaults", "from", default_from, sizeof(default_from));
	return 0;
}

static int check_mailers(void)
{
	struct mailer *m;
	int c;

	/* If mail.conf exists, warn if no mailers are registered */
	RWLIST_RDLOCK(&mailers);
	c = RWLIST_SIZE(&mailers, m, entry);
	RWLIST_UNLOCK(&mailers);

	if (!c) {
		bbs_warning("No mailers are registered, email transmission will fail!\n");
	}
	return 0;
}

int bbs_mail_init(void)
{
	int res = load_config();
	if (config_exists) {
		bbs_register_startup_callback(check_mailers, STARTUP_PRIORITY_DEFAULT);
	}
	return res;
}

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

int __bbs_register_mailer(int (*mailer)(MAILER_PARAMS), void *mod, int priority)
{
	struct mailer *m;

	RWLIST_WRLOCK(&mailers);
	RWLIST_TRAVERSE(&mailers, m, entry) {
		if (m->mailer == mailer) {
			break;
		}
	}
	if (m) {
		bbs_error("Mailer is already registered\n");
		RWLIST_UNLOCK(&mailers);
		return -1;
	}
	m = calloc(1, sizeof(*m) + 1);
	if (ALLOC_FAILURE(m)) {
		RWLIST_UNLOCK(&mailers);
		return -1;
	}
	m->mailer = mailer;
	m->module = mod;
	m->priority = (unsigned int) priority;
	RWLIST_INSERT_SORTED(&mailers, m, entry, priority); /* Insert in order of priority */
	RWLIST_UNLOCK(&mailers);
	return 0;
}

int bbs_unregister_mailer(int (*mailer)(MAILER_PARAMS))
{
	struct mailer *m;

	m = RWLIST_WRLOCK_REMOVE_BY_FIELD(&mailers, mailer, mailer, entry);
	if (!m) {
		bbs_error("Failed to unregister mailer: not currently registered\n");
		return -1;
	} else {
		free(m);
	}
	return 0;
}

int bbs_mail(int async, const char *to, const char *from, const char *replyto, const char *subject, const char *body)
{
	struct mailer *m;
	int res = -1;
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

	/* Hand off the delivery of the message itself to the appropriate module */
	RWLIST_RDLOCK(&mailers);
	RWLIST_TRAVERSE(&mailers, m, entry) {
		bbs_module_ref(m->module, 1);
		res = m->mailer(async, to, from, replyto, errorsto, subject, body);
		bbs_module_unref(m->module, 1);
		if (res >= 0) {
			break;
		}
	}
	RWLIST_UNLOCK(&mailers);

	return res;
}
