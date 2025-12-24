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

#if defined(linux) && !defined(__GLIBC__)
#include <libgen.h> /* use non-GNU basename */
#endif

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
#include "include/reload.h"
#include "include/stringlist.h"

struct mailer {
	int (*simple_mailer)(SIMPLE_MAILER_PARAMS);
	int (*full_mailer)(FULL_MAILER_PARAMS);
	struct bbs_module *module;
	RWLIST_ENTRY(mailer) entry;
	unsigned int priority;
};

static RWLIST_HEAD_STATIC(mailers, mailer);

#define MESSAGE_ID_PREFIX "LBBS"
#define ENDL "\r\n"
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
	bbs_config_unlock(cfg);
	return 0;
}

static int reload_mail(int fd)
{
	RWLIST_WRLOCK(&mailers);
	default_to[0] = '\0';
	default_from[0] = '\0';
	default_errorsto[0] = '\0';
	load_config();
	RWLIST_UNLOCK(&mailers);
	bbs_dprintf(fd, "Reloaded mail defaults\n");
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
	bbs_register_reload_handler("mail", "Reload mail defaults", reload_mail);
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
	fprintf(p, ENDL); /* End of headers */
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

int __bbs_register_mailer(int (*simple_mailer)(SIMPLE_MAILER_PARAMS), int (*full_mailer)(FULL_MAILER_PARAMS), void *mod, int priority)
{
	struct mailer *m;

	RWLIST_WRLOCK(&mailers);
	RWLIST_TRAVERSE(&mailers, m, entry) {
		if (m->simple_mailer == simple_mailer && m->full_mailer == full_mailer) {
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
	m->simple_mailer = simple_mailer;
	m->full_mailer = full_mailer;
	m->module = mod;
	m->priority = (unsigned int) priority;
	RWLIST_INSERT_SORTED(&mailers, m, entry, priority); /* Insert in order of priority */
	RWLIST_UNLOCK(&mailers);
	return 0;
}

int bbs_unregister_mailer(int (*simple_mailer)(SIMPLE_MAILER_PARAMS), int (*full_mailer)(FULL_MAILER_PARAMS))
{
	struct mailer *m;

	RWLIST_WRLOCK(&mailers);
	RWLIST_TRAVERSE_SAFE_BEGIN(&mailers, m, entry) {
		if (m->simple_mailer == simple_mailer && m->full_mailer == full_mailer) {
			RWLIST_REMOVE_CURRENT(entry);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&mailers);

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
	RWLIST_RDLOCK(&mailers);
	errorsto = default_errorsto;
	if (strlen_zero(from)) {
		from = default_from;
	}
	if (strlen_zero(to)) {
		to = default_to;
	}

	if (strlen_zero(to)) {
		RWLIST_UNLOCK(&mailers);
		bbs_error("No recipient provided, and no default in mail.conf, aborting\n");
		return -1;
	} else if (strlen_zero(from)) {
		RWLIST_UNLOCK(&mailers);
		bbs_error("No sender address provided, and no default in mail.conf, aborting\n");
		return -1;
	}

	/* Hand off the delivery of the message itself to the appropriate module */
	RWLIST_TRAVERSE(&mailers, m, entry) {
		if (!m->simple_mailer) {
			continue;
		}
		bbs_module_ref(m->module, 1);
		res = m->simple_mailer(async, to, from, replyto, errorsto, subject, body);
		bbs_module_unref(m->module, 1);
		if (res >= 0) {
			break;
		}
	}
	RWLIST_UNLOCK(&mailers);

	return res;
}

static void push_recipients(struct stringlist *restrict slist, int *restrict count, char *restrict s)
{
	char *recip, *recips = s;

	if (strlen_zero(recips)) {
		return;
	}

	bbs_term_line(recips);
	while ((recip = strsep(&recips, ","))) {
		char buf[256];
		char *name, *user, *host;
		if (strlen_zero(recip)) {
			continue;
		}
		trim(recip);
		if (strlen_zero(recip)) {
			continue;
		}

		/* We just want the address, not the name, if there is one */
		if (bbs_parse_email_address(recip, &name, &user, &host)) {
			bbs_warning("Skipping invalid email address in header\n"); /* We butchered the address by modifying in place */
			continue;
		}

		snprintf(buf, sizeof(buf), "<%s%s%s>", user, host ? "@" : "", S_IF(host)); /* Recipients need to be surrounded by <> */
		bbs_debug(6, "Adding recipient '%s'\n", buf);
		stringlist_push(slist, buf);
		(*count)++;
	}
}

int bbs_mail_message(const char *tmpfile, const char *mailfrom, struct stringlist *recipients)
{
	struct mailer *m;
	char mailfrombuf[256];
	char tmpfile2[256];
	int res = -1;
	struct stringlist reciplist;

	if (!mailfrom) {
		mailfrom = ""; /* Empty MAIL FROM address */
	} else {
		const char *tmpaddr = strchr(mailfrom, '<');
		/* This is just for the MAIL FROM, so just the address, no name */
		if (tmpaddr) {
			/* Shouldn't have <>, but if it does, transparently remove them */
			bbs_strncpy_until(mailfrombuf, tmpaddr + 1, sizeof(mailfrombuf), '>');
			mailfrom = mailfrombuf;
		}
	}

	/* Extract recipients from message if needed */
	if (!recipients) {
		int rewrite = 0;
		int in_header = 0;
		int recipient_count = 0;
		char line[1002];
		/* Parse message for recipients to add.
		 * Check To, Cc, and Bcc headers. */
		FILE *fp = fopen(tmpfile, "r");
		if (!fp) {
			bbs_error("fopen(%s) failed: %s\n", tmpfile, strerror(errno));
			return -1;
		}
		/* Process each line until end of headers */
		stringlist_init(&reciplist);
		while ((fgets(line, sizeof(line), fp))) {
			if (strlen(line) <= 2) {
				break;
			}
			if (STARTS_WITH(line, "To:")) {
				push_recipients(&reciplist, &recipient_count, line + STRLEN("To:"));
				in_header = 1;
			} else if (STARTS_WITH(line, "Cc:")) {
				push_recipients(&reciplist, &recipient_count, line + STRLEN("Cc:"));
				in_header = 1;
			} else if (STARTS_WITH(line, "Bcc:")) {
				push_recipients(&reciplist, &recipient_count, line + STRLEN("Bcc:"));
				in_header = 1;
				rewrite = 1;
			}
			if (line[0] == ' ') {
				/* Continue previous header */
				if (in_header) { /* In header we care about */
					push_recipients(&reciplist, &recipient_count, line + 1);
				}
			} else {
				in_header = 0;
			}
		}
		if (!recipient_count) {
			bbs_warning("No recipients explicitly passed for message %s from %s (and none found in headers)\n", tmpfile, mailfrom);
		}
		bbs_debug(4, "Parsed %d recipient%s from message %s from %s\n", recipient_count, ESS(recipient_count), tmpfile, mailfrom);
		/* If there are any Bcc headers, we need to remove those recipients,
		 * and regenerate the message. */
		if (rewrite) {
			int inheaders = 1;
			FILE *fp2;
			strcpy(tmpfile2, "/tmp/smtpbccXXXXXX");
			fp2 = bbs_mkftemp(tmpfile2, MAIL_FILE_MODE);
			if (!fp2) {
				stringlist_empty_destroy(&reciplist);
				return -1;
			}
			rewind(fp);
			bbs_debug(2, "Rewriting message since it contains a Bcc header\n");
			while ((fgets(line, sizeof(line), fp))) {
				if (inheaders) {
					if (!strncmp(line, "\r\n", 2)) {
						inheaders = 0;
					} else if (STARTS_WITH(line, "Bcc:")) {
						in_header = 1;
						continue; /* Skip this line */
					} else if (line[0] == ' ') {
						if (in_header) {
							/* Skip if this is a multiline Bcc header */
							continue;
						}
					} else {
						in_header = 0;
					}
				}
				/* Copy line */
				fwrite(line, 1, strlen(line), fp2);
			}
			fclose(fp2);
			fclose(fp);
			/* Swap the files */
			bbs_delete_file(tmpfile);
			tmpfile = tmpfile2;
		} else {
			fclose(fp);
		}
	}

	/* XXX smtp_inject consumes the stringlist and assumes responsibility for destroying it.
	 * The code here is in theory set up to try another mailer if the first one fails.
	 * However, it seems possible that the stringlist could have been modified prior to failure,
	 * meaning a retry using another mailer wouldn't get the full list.
	 * In practice, this is not currently an issue, since there are only two mailers,
	 * and only in net_smtp do we accept a stringlist of recipients.
	 * However, in the future, especially if that changes, it might be worth duplicating
	 * the stringlist here prior to each attempt, just to be safe.
	 * If we did that, we'd also want to destroy the stringlist after the list iteration.
	 */

	RWLIST_RDLOCK(&mailers);
	RWLIST_TRAVERSE(&mailers, m, entry) {
		if (!m->full_mailer) {
			continue;
		}
		bbs_module_ref(m->module, 2);
		res = m->full_mailer(tmpfile, mailfrom, recipients ? recipients : &reciplist);
		bbs_module_unref(m->module, 2);
		if (res >= 0) {
			break;
		}
	}
	RWLIST_UNLOCK(&mailers);

	return res;
}
