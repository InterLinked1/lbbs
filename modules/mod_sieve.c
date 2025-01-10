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
 * \brief RFC 5228 Sieve Filtering Engine
 *
 * \note Obsoletes RFC 3028
 *
 * \note This uses the libsieve library, which is
 *       the canonical C library for Sieve,
 *       but the library is full of bugs, isn't very flexible,
 *       and isn't maintained anymore.
 *       This should be replaced with a custom library.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <sieve2.h>
#include <sieve2_error.h>

#include "include/module.h"
#include "include/utils.h"
#include "include/mail.h"
#include "include/transfer.h"
#include "include/stringlist.h"
#include "include/linkedlists.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"

struct sieve_exec {
	char **header;
	char *headers;
	char *subaddress;
	char *script_data;
	char *errormsg;
	char scriptpath[264];
	struct smtp_msg_process *mproc;
	unsigned int error_parse:1;
	unsigned int error_runtime:1;
	unsigned int actiontaken:1;
};

/* Old versions of libsieve don't use const pointers,
 * so this entire module disables this compiler check,
 * because dealing with this would be a mess otherwise. */
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

static int my_debug(sieve2_context_t *s, void *varg)
{
#ifdef DEBUG_LIBSIEVE
	__bbs_log(LOG_DEBUG, 7, __FILE__, __LINE__, sieve2_getvalue_string(s, "function"), "[%d] %s(%s): %s\n",
		sieve2_getvalue_int(s, "level"),
		sieve2_getvalue_string(s, "module"),
		sieve2_getvalue_string(s, "file"),
		sieve2_getvalue_string(s, "message"));
#else
	UNUSED(s);
#endif
	UNUSED(varg);
	return SIEVE2_OK;
}

/*! \brief RFC 5435 Notifications */
static int my_notify(sieve2_context_t *s, void *varg)
{
#if 0
	struct sieve_exec *sieve = varg;
#endif
	char **options;
	const char *msg = sieve2_getvalue_string(s, "message");
	int i;
#if 1
	UNUSED(varg);
#endif

	/* Importance/priority is not used */
	bbs_debug(5, "NOTIFY: ID \"%s\": %s, method: %s, priority: %s\n",
		sieve2_getvalue_string(s, "id"), sieve2_getvalue_string(s, "active"),
		sieve2_getvalue_string(s, "method"), sieve2_getvalue_string(s, "priority"));
	bbs_debug(5, "Message: %s\n", msg);

	options = sieve2_getvalue_stringlist(s, "options");
	if (!options) {
		return SIEVE2_ERROR_BADARGS;
	}

	/* These are not currently used */
	for (i = 0; options[i]; i++) {
		bbs_debug(5, "Options: %s\n", options[i]);
	}

#if 0
	/* Since notify can be used multiple times,
	 * just send the notification right here rather than storing state for later. */
	if (bbs_mail(0, sieve->mproc->from, sieve->mproc->recipient, NULL, "Notification", msg)) {
		return SIEVE2_ERROR_FAIL;
	}
	sieve->actiontaken = 1;
	return SIEVE2_OK;
#else
	/*! \todo libsieve doesn't seem to parse notify properly */
	return SIEVE2_ERROR_UNSUPPORTED;
#endif
}

/* Old versions of libsieve segfault in sieve2_free when my_vacation is used.
 * We must not use the vacation functionality unless we are sure the
 * version of libsieve available is at least this commit:
 * https://github.com/sodabrew/libsieve/commit/741148538abe8d826b558989200f92604c94b564
 * Older packages may not have caught up this far yet (mine hasn't).
 * Obviously, this also requires a reliable way to detect the libsieve version,
 * until we have that, assume it has the buggy version to be safe.
 *
 * XXX Seems if vacation is used in a script when not available,
 * that will still result in leaks.
 */
#define HAVE_WORKING_LIBSIEVE_VACATION 0

/*! \brief RFC 5230 Vacation */
static int my_vacation(sieve2_context_t *s, void *varg)
{
	int sendautoreply = 1;
#if HAVE_WORKING_LIBSIEVE_VACATION
	struct sieve_exec *sieve = varg;
#else
	UNUSED(varg);
#endif

	bbs_debug(3, "Responded to '%s' in past %d days?\n", sieve2_getvalue_string(s, "hash"), sieve2_getvalue_int(s, "days"));

	if (sendautoreply) { /*! \todo auto reply */
		const char *subject = sieve2_getvalue_string(s, "subject");
		const char *msg = sieve2_getvalue_string(s, "message");
		bbs_debug(5, "Autoreply: %s / %s / %s / %s\n",
			msg,
			subject,
			sieve2_getvalue_string(s, "address"),
			sieve2_getvalue_string(s, "name"));
#if HAVE_WORKING_LIBSIEVE_VACATION
		/* XXX SMTP MAIL FROM should be empty (<>) */
		if (bbs_mail(0, sieve->mproc->from, sieve2_getvalue_string(s, "address"), NULL, subject, msg)) {
			return SIEVE2_ERROR_FAIL;
		}
		sieve->actiontaken = 1;
#else
		return SIEVE2_ERROR_UNSUPPORTED;
#endif
	}
	return SIEVE2_OK;
}

static int my_redirect(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	const char *dest = sieve2_getvalue_string(s, "address");
	bbs_debug(3, "Action: REDIRECT, destination: %s\n", dest);
	sieve->actiontaken = 1;
	if (!stringlist_contains(sieve->mproc->forward, dest)) {
		stringlist_push(sieve->mproc->forward, dest);
	}
	return SIEVE2_OK;
}

static int my_reject(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	const char *msg = sieve2_getvalue_string(s, "message");
	bbs_debug(3, "Action: REJECT, message: %s\n", msg);
	sieve->actiontaken = 1;
	sieve->mproc->bounce = 1;
	sieve->mproc->drop = 1;
	REPLACE(sieve->mproc->bouncemsg, msg);
	return SIEVE2_OK;
}

static int my_discard(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	UNUSED(s);
	bbs_debug(3, "Action: DISCARD\n");
	sieve->actiontaken = 1;
	sieve->mproc->drop = 1;
	return SIEVE2_OK;
}

static int my_fileinto(sieve2_context_t *s, void *varg)
{
	char **flags;
	struct sieve_exec *sieve = varg;
	const char *mailbox = sieve2_getvalue_string(s, "mailbox");
	char newdir[512];

	if (sieve->mproc->direction != SMTP_MSG_DIRECTION_IN) {
		return SIEVE2_ERROR_UNSUPPORTED;
	}

	bbs_debug(3, "Action: FILEINTO: %s\n", mailbox);

	/*! \todo add support for flags */
	flags = sieve2_getvalue_stringlist(s, "flags");
	if (flags) {
		int i;
		for (i = 0; flags[i]; i++) {
			bbs_debug(6, "Flag %d: %s\n", i, flags[i]);
		}
	}

	/* INBOX is excluded here, because fileinto INBOX is redundant; it's being filed elsewhere FROM the INBOX */
	if (sieve->mproc->userid) {
		snprintf(newdir, sizeof(newdir), "%s/%d/.%s", mailbox_maildir(NULL), sieve->mproc->userid, mailbox);
	} else {
		snprintf(newdir, sizeof(newdir), "%s/.%s", mailbox_maildir(sieve->mproc->mbox), mailbox);
	}

	free_if(sieve->mproc->newdir); /* Free first, instead of using REPLACE, because if this fails, the previous mailbox should not linger */
	if (eaccess(newdir, R_OK)) {
		bbs_warning("FILEINTO %s failed (no such mailbox)\n", mailbox);
		return SIEVE2_ERROR_FAIL;
	}
	sieve->mproc->newdir = strdup(mailbox);
	sieve->actiontaken = 1;
	return SIEVE2_OK;
}

/*! \note KEEP is essentially the default case of FILEINTO "INBOX". */
static int my_keep(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	UNUSED(s);
	bbs_debug(3, "Action: KEEP\n");
	sieve->actiontaken = 1;
	/* No need to do anything, this is the default action */
	return SIEVE2_OK;
}

static int my_errparse(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	bbs_warning("Error parsing script %s on line %d: %s\n", sieve->scriptpath, sieve2_getvalue_int(s, "lineno"), sieve2_getvalue_string(s, "message"));
	sieve->error_parse = 1;
	if (!sieve->errormsg) {
		asprintf(&sieve->errormsg, "line %d: %s", sieve2_getvalue_int(s, "lineno"), sieve2_getvalue_string(s, "message"));
	}
	return SIEVE2_OK;
}

static int my_erraddress(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	bbs_warning("Error parsing address: %s\n", sieve2_getvalue_string(s, "message"));
	sieve->error_parse = 1;
	if (!sieve->errormsg) {
		asprintf(&sieve->errormsg, "line %d: %s", sieve2_getvalue_int(s, "lineno"), sieve2_getvalue_string(s, "message"));
	}
	return SIEVE2_OK;
}

static int my_errheader(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	bbs_warning("Error parsing header in %s on line %d: %s\n", sieve->scriptpath, sieve2_getvalue_int(s, "lineno"), sieve2_getvalue_string(s, "message"));
	sieve->error_parse = 1;
	if (!sieve->errormsg) {
		asprintf(&sieve->errormsg, "line %d: %s", sieve2_getvalue_int(s, "lineno"), sieve2_getvalue_string(s, "message"));
	}
	return SIEVE2_OK;
}

static int my_errexec(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	bbs_warning("Execution error: %s\n", sieve2_getvalue_string(s, "message"));
	sieve->error_runtime = 1;
	if (!sieve->errormsg) {
		asprintf(&sieve->errormsg, "line %d: %s", sieve2_getvalue_int(s, "lineno"), sieve2_getvalue_string(s, "message"));
	}
	return SIEVE2_OK;
}

static int my_getscript(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	const char *path, *name;

	/* Path could be :general, :personal, or empty. */
	path = sieve2_getvalue_string(s, "path");

	/* If no file is named, we're looking for the main file. */
	name = sieve2_getvalue_string(s, "name");

	if (!path || !name) {
		return SIEVE2_ERROR_BADARGS;
	}

	if (!strlen_zero(path) && !strlen_zero(name)) {
		bbs_debug(5, "Include requested from '%s' named '%s'\n", path, name);
	} else if (strlen_zero(path) && strlen_zero(name)) {
		int length;
		/* Called again */
		free_if(sieve->script_data);
		sieve->script_data = bbs_file_to_string(sieve->scriptpath, 50000, &length); /* 50 KB should be more than plenty for a Sieve script */
		if (!sieve->script_data) {
			return SIEVE2_ERROR_FAIL;
		}
		sieve2_setvalue_string(s, "script", sieve->script_data);
	}
	return SIEVE2_OK;
}

static int my_getheaders(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;

	if (!sieve->headers) {
		char buf[1001];
		FILE *fp;
		struct dyn_str dynstr;
		fp = fopen(sieve->mproc->datafile, "r");
		if (!fp) {
			bbs_error("Failed to open %s: %s\n", sieve->mproc->datafile, strerror(errno));
			return SIEVE2_ERROR_FAIL;
		}

		memset(&dynstr, 0, sizeof(dynstr));
		while ((fgets(buf, sizeof(buf), fp))) {
			if (!strcmp(buf, "\r\n")) {
				break; /* End of headers */
			}
			dyn_str_append(&dynstr, buf, strlen(buf)); /* Already includes CR LF */
		}
		fclose(fp);
		sieve->headers = dynstr.buf;
	}

	sieve2_setvalue_string(s, "allheaders", sieve->headers); /* libsieve is not responsible for freeing this, we must keep a reference */
	return SIEVE2_OK;
}

static void free_header_list(struct sieve_exec *sieve)
{
	if (sieve->header) {
		int i;
		char **headers = sieve->header;
		for (i = 0; headers[i]; i++) {
			free(headers[i]);
		}
		free_if(sieve->header);
	}
}

static int my_getheader(sieve2_context_t *s, void *varg)
{
	FILE *fp;
	char buf[1001];
	const char *header = sieve2_getvalue_string(s, "header");
	struct sieve_exec *sieve = varg;
	size_t headerlen = strlen(header);
	char **headers;
	int c = 0;

	/* libsieve will call this function every time it wants a header,
	 * so we are good to free the last result, if any, each time. */
	free_header_list(sieve);
	headers = calloc(32, sizeof(char*)); /* All are NULL to start */
	if (ALLOC_FAILURE(headers)) {
		return SIEVE2_ERROR_FAIL;
	}
	fp = fopen(sieve->mproc->datafile, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", sieve->mproc->datafile, strerror(errno));
		free(headers);
		return SIEVE2_ERROR_FAIL;
	}

	while ((fgets(buf, sizeof(buf), fp))) {
		if (!strncasecmp(buf, header, headerlen) && *(buf + headerlen) == ':') {
			char *value = buf + headerlen + 1;
			ltrim(value);
			bbs_strterm(value, '\r');
			headers[c] = strdup(value); /* It wants just the header value and nothing else */
			if (ALLOC_FAILURE(headers[c])) {
				c++;
				break; /* Don't leave gaps or we won't free properly */
			}
			c++;
		}
		if (!strcmp(buf, "\r\n")) {
			break; /* End of headers */
		} else if (c == 32 - 1) { /* Must be NULL terminated, leave room */
			bbs_warning("Headers truncated\n");
			break;
		}
	}
	fclose(fp);
	headers[c] = NULL;
	sieve2_setvalue_stringlist(s, "body", headers); /* Yes, it's called body for some reason */
	sieve->header = headers; /* Keep a reference so we can free */

	bbs_debug(7, "Header '%s' appears %d time%s\n", header, c, ESS(c));

	sieve2_setvalue_string(s, "allheaders", sieve->headers); /* libsieve is not responsible for freeing this, we must keep a reference */
	return SIEVE2_OK;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
static int my_getenvelope(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	/* In master, sieve2_setvalue_string accepts const chars, but the library version seems to have just char * */
	sieve2_setvalue_string(s, "to", (char*) sieve->mproc->recipient);
	sieve2_setvalue_string(s, "from", (char*) sieve->mproc->from);
	return SIEVE2_OK;
}
#pragma GCC diagnostic pop /* -Wcast-qual */

static int my_getbody(sieve2_context_t *s, void *varg)
{
	UNUSED(s);
	UNUSED(varg);
	/* libsieve actually doesn't support this callback currently,
	 * (it's not used in src/sv_interface/script.c)
	 * so there's no point in providing an implementation for it. */
	return SIEVE2_ERROR_UNSUPPORTED;
}

static int my_getsize(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	sieve2_setvalue_int(s, "size", sieve->mproc->size);
	bbs_debug(3, "Size: %d\n", sieve->mproc->size);
	return SIEVE2_OK;
}

static int my_getsubaddress(sieve2_context_t *s, void *varg)
{
	struct sieve_exec *sieve = varg;
	char *dup, *name, *user, *host;
	const char *address = sieve2_getvalue_string(s, "address");

	free_if(sieve->subaddress);
	dup = strdup(address);
	if (!dup) {
		return SIEVE2_ERROR_FAIL;
	}
	if (bbs_parse_email_address(dup, &name, &user, &host)) {
		return SIEVE2_ERROR_BADARGS;
	}
	sieve2_setvalue_string(s, "user", user);
	sieve2_setvalue_string(s, "detail", NULL);
	sieve2_setvalue_string(s, "localpart", user);
	sieve2_setvalue_string(s, "domain", host);
	sieve->subaddress = dup; /* Keep a reference so we can free it */

	return SIEVE2_OK;
}

sieve2_callback_t sieve_callbacks[] = {
	{ SIEVE2_DEBUG_TRACE,			my_debug },
	{ SIEVE2_ERRCALL_PARSE,			my_errparse },
	{ SIEVE2_ERRCALL_RUNTIME,		my_errexec },
	{ SIEVE2_ERRCALL_ADDRESS,		my_erraddress },
	{ SIEVE2_ERRCALL_HEADER,		my_errheader },
	{ SIEVE2_ACTION_FILEINTO,		my_fileinto },
	{ SIEVE2_ACTION_DISCARD,		my_discard },
	{ SIEVE2_ACTION_REDIRECT,		my_redirect },
	{ SIEVE2_ACTION_REJECT,			my_reject },
	{ SIEVE2_ACTION_NOTIFY,			my_notify },
	{ SIEVE2_ACTION_VACATION,		my_vacation },
	{ SIEVE2_ACTION_KEEP,			my_keep },
	{ SIEVE2_SCRIPT_GETSCRIPT,		my_getscript },
	/* Technically, libsieve has its own header parsing
	 * capability so the GETHEADER callback is "optional".
	 * However, the libsieve get header implementation
	 * results in memory corruption after the first Sieve execution
	 * on subsequent calls.
	 * Providing our own implementation avoids that.
	 *
	 * If you want to debug bugs with libsieve,
	 * replace my_getheader here with NULL
	 * and run the test_sieve test suite module,
	 * and you'll see what I mean.
	 */
	{ SIEVE2_MESSAGE_GETHEADER,		my_getheader },
	{ SIEVE2_MESSAGE_GETALLHEADERS,	my_getheaders },
	{ SIEVE2_MESSAGE_GETSUBADDRESS,	my_getsubaddress },
	{ SIEVE2_MESSAGE_GETENVELOPE,	my_getenvelope },
	{ SIEVE2_MESSAGE_GETBODY,		my_getbody },
	{ SIEVE2_MESSAGE_GETSIZE,		my_getsize },
	{ 0 }, /* NULL doesn't work here */
};

/*!
 * \brief Execute a single Sieve script
 * \param mproc
 * \param scriptfile Full path to Sieve script to execute
 * \retval 0 to continue, -1 to abort rules processing
 */
static int script_exec(struct smtp_msg_process *mproc, const char *scriptfile)
{
	int res;
	struct sieve_exec sieve;
	sieve2_context_t *sieve2_context = NULL;

	if (!bbs_file_exists(scriptfile)) {
		bbs_debug(7, "Sieve script %s doesn't exist\n", scriptfile);
		return 0; /* Script doesn't exist */
	}

	memset(&sieve, 0, sizeof(sieve));
	safe_strncpy(sieve.scriptpath, scriptfile, sizeof(sieve.scriptpath));

	/* libsieve setup */
	sieve.mproc = mproc;
	res = sieve2_alloc(&sieve2_context);
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_alloc %d: %s\n", res, sieve2_errstr(res));
		return 0;
	}
	res = sieve2_callbacks(sieve2_context, sieve_callbacks);
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_callbacks %d: %s\n", res, sieve2_errstr(res));
		goto cleanup;
	}

	/* sieve2_validate is redundant here, since execution will validate the script anyways.
	 * This is mainly useful for standalone validation.
	 * However, Sieve scripts should be executed atomically (all intended actions, or none at all),
	 * so maybe this would be useful for validating first and bailing out early if needed?
	 */
	res = sieve2_execute(sieve2_context, &sieve);
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_execute %d: %s\n", res, sieve2_errstr(res));
		goto cleanup;
	}
	bbs_debug(4, "Action %s\n", sieve.actiontaken ? "taken" : "not taken");

cleanup:
	res = sieve2_free(&sieve2_context);
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_free %d: %s\n", res, sieve2_errstr(res));
	} else {
		bbs_assert(sieve2_context == NULL);
	}

	free_if(sieve.script_data);
	free_if(sieve.headers);
	free_if(sieve.subaddress);
	free_if(sieve.errormsg);
	free_header_list(&sieve);
	return 0;
}

static char before_rules[256];
static char after_rules[256];

static int sieve(struct smtp_msg_process *mproc)
{
	char filepath[256];
	const char *mboxmaildir;

	if (mproc->scope != SMTP_SCOPE_INDIVIDUAL) {
		return 0; /* Filters are only run for individual delivery */
	}

	if (mproc->direction != SMTP_MSG_DIRECTION_IN) {
		return 0; /* Currently, Sieve can only be used for filtering inbound mail. If support for Sieve extension for outbound mail is added, this could change. */
	}

	/* Calculate maildir path, if we have a mailbox */
	if (mproc->userid) {
		snprintf(filepath, sizeof(filepath), "%s/%d", mailbox_maildir(NULL), mproc->userid);
		mboxmaildir = filepath;
	} else if (mproc->mbox) {
		mboxmaildir = mailbox_maildir(mproc->mbox);
	} else {
		mboxmaildir = NULL;
	}

	/* Unlike MailScript, we don't use mboxmaildir at all currently,
	 * apart from computing the mailbox's Sieve script (below) if non-NULL. */

	if (mproc->iteration == FILTER_BEFORE_MAILBOX) {
		return script_exec(mproc, before_rules);
	} else if (mproc->iteration == FILTER_AFTER_MAILBOX) {
		return script_exec(mproc, after_rules);
	} else { /* FILTER_MAILBOX */
		char script[263];
		if (!mboxmaildir) {
			return 0; /* Can't execute per-mailbox callback if there is no mailbox */
		}
		/* Unlike MailScript, which checks both locations, for Sieve, we only use one.
		 * For user mailboxes, we use the home directory, else we use the maildir.
		 * This is primarily to avoid ambiguity within the ManageSieve protocol.
		 * It supports multiple Sieve scripts, but not the notion of different "directories",
		 * and there is no real benefit to allowing it to exists in both places for any
		 * given mailbox.
		 *
		 * In practice, since the active script symlink is always in the maildir,
		 * we always use that regardless. */
		snprintf(script, sizeof(script), "%s/.sieve", mboxmaildir);
		return script_exec(mproc, script);
	}
}

static char *get_capabilities(void)
{
	char *caps;
	int res;
	sieve2_context_t *sieve2_context = NULL;

	res = sieve2_alloc(&sieve2_context);
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_alloc %d: %s\n", res, sieve2_errstr(res));
		return NULL;
	}
	res = sieve2_callbacks(sieve2_context, sieve_callbacks);
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_callbacks %d: %s\n", res, sieve2_errstr(res));
		sieve2_free(&sieve2_context);
		return NULL;
	}
	caps = sieve2_listextensions(sieve2_context);
	caps = strdup(caps);
	if (ALLOC_SUCCESS(caps)) {
		rtrim(caps); /* there's a space after the last one, get rid of it */
	}
	sieve2_free(&sieve2_context);
	return caps;
}

static int script_validate(const char *filename, struct mailbox *mbox, char **errormsg)
{
	int res, vres = -1;
	struct sieve_exec sieve;
	sieve2_context_t *sieve2_context = NULL;

	memset(&sieve, 0, sizeof(sieve));
	safe_strncpy(sieve.scriptpath, filename, sizeof(sieve.scriptpath));

	res = sieve2_alloc(&sieve2_context);
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_alloc %d: %s\n", res, sieve2_errstr(res));
		return -1;
	}
	res = sieve2_callbacks(sieve2_context, sieve_callbacks); /* Use the verify callbacks, so we can also check fileinto targets for existence. */
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_callbacks %d: %s\n", res, sieve2_errstr(res));
		sieve2_free(&sieve2_context);
		return -1;
	}

	UNUSED(mbox); /* Not currently used, but could be used to validate fileinto targets exist in the mailbox */

	res = sieve2_validate(sieve2_context, &sieve);
	free_if(sieve.script_data);
	vres = sieve.errormsg ? 1 : 0;

#if 0
	if (!vres) {
		/* If so far, so good, then do a dummy execution for fileinto so we can verify fileinto targets for existence. */
		/* XXX Good idea, but doesn't actually work since the rules aren't just true, and we can't easily manually
		 * trigger the "true" callback for fileinto somehow.
		 * We need to be able to parse the file and do a callback for every fileinto, similar to how it builds the parse tree internally.
		 * Not possible with libsieve currently, but could be doable in a custom sieve parser. */
		res = sieve2_execute(sieve2_context, &sieve);
		if (res != SIEVE2_OK) {
			bbs_error("sieve2_execute %d: %s\n", res, sieve2_errstr(res));
		}
	}
#endif

	if (errormsg) {
		*errormsg = sieve.errormsg;
	} else {
		free_if(sieve.errormsg);
	}
	if (res != SIEVE2_OK) {
		bbs_error("sieve2_validate %d: %s\n", res, sieve2_errstr(res));
		sieve2_free(&sieve2_context);
		return 1;
	}
	sieve2_free(&sieve2_context);
	return vres;
}
#pragma GCC diagnostic pop /* -Wdiscarded-qualifiers */

static int load_module(void)
{
	if (SIEVE2_VALUE_LAST != 27) {
		/* See libsieve's src/sv_include/sieve2.h */
		bbs_warning("Expected SIEVE2_VALUE_LAST to be 27, but was %d?\n", SIEVE2_VALUE_LAST);
	}
	snprintf(before_rules, sizeof(before_rules), "%s/before.sieve", mailbox_maildir(NULL));
	snprintf(after_rules, sizeof(after_rules), "%s/after.sieve", mailbox_maildir(NULL));
	if (sieve_register_provider(script_validate, get_capabilities())) {
		return -1;
	}
	return smtp_register_processor(sieve);
}

static int unload_module(void)
{
	sieve_unregister_provider(script_validate);
	return smtp_unregister_processor(sieve);
}

BBS_MODULE_INFO_DEPENDENT("RFC5228 Sieve Filtering", "net_smtp.so");
