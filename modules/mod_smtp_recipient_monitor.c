/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Recipient Greylist-Like Monitoring
 *
 * \description This module is a helpful tool for local email users.
 * It automatically analyzes their outgoing mail, specifically analyzing
 * the recipients for each message they send. If the set of recipients
 * exactly matches a set of recipients to whom they have previously sent
 * messages, the message is accepted. If not, the message is bounced
 * with a temporary failure code, to indicate to users they are attempting
 * to send a message to a new set of recipients they have never sent email
 * to before. This can help prevent sending messages to the wrong recipients,
 * or from the wrong email address.
 *
 * TL;DR It's basically greylisting for new sets of recipients to catch potential mistakes
 * with the From identity or set of recipients.
 *
 * This functionality is enabled on a per-user basis. To do so,
 * the user simply creates the file .recipientmap in his or her home directory's
 * .config subdirectory.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/stringlist.h"
#include "include/transfer.h"
#include "include/node.h"

#include "include/net_smtp.h"

struct deferred_attempt {
	unsigned int userid;
	time_t time;
	RWLIST_ENTRY(deferred_attempt) entry;
	char line[];
};

/*!
 * \note We only WRLOCK this list, never RDLOCK it,
 * so in theory the list could just use a mutex. */
static RWLIST_HEAD_STATIC(deferred_attempts, deferred_attempt);

static int processor(struct smtp_msg_process *mproc)
{
	char fullfile[265];
	char line[1024] = "";
	char buf[1024];
	char *linebuf = line;
	const char *s;
	char *s2;
	int found_match = 0;
	int was_deferred = 0;
	struct stringlist sorted_recipients;
	struct stringitem *i = NULL;
	size_t lineleft = sizeof(line);
	FILE *fp;
	time_t now;
	struct deferred_attempt *attempt;

	if (mproc->dir != SMTP_DIRECTION_SUBMIT) {
		return 0; /* Only applies to user submissions */
	}
	if (mproc->iteration != FILTER_MAILBOX) {
		return 0; /* Only execute for mailboxes, and not before/after as well */
	}
	if (!mproc->userid) {
		return 0; /* Only for user-level filters, not global */
	}
	if (!mproc->recipients) {
		bbs_warning("Recipient list not available?\n");
		return 0;
	}
	if (!mproc->smtp) {
		bbs_warning("Not an interactive session?\n");
		return 0;
	}

	/* Users need to manually create the file to enable its functionality.
	 * Otherwise, its lack of existence is treated as "feature disabled". */
	if (bbs_transfer_home_config_file(mproc->userid, ".recipientmap", fullfile, sizeof(fullfile))) {
		/* File doesn't exist, so we don't need to do anything. Not an error. */
		return 0;
	}
	fp = fopen(fullfile, "r+");
	if (!fp) {
		/* Since bbs_transfer_home_config_file returned 0, this should've succeeded... */
		bbs_error("Failed to open file %s: %s\n", fullfile, strerror(errno));
		return 0;
	}

	/* This file is assumed to have a format as follows:
	 * <from 1>,<recipients 1> LF
	 * <from 2>,<recipients 2> LF
	 * ...
	 * <from N>,<recipients N> LF
	 *
	 * Each line contains one list. Each list is the From address followed by a comma-separated list of email addresses sorted alphabetically.
	 * (Email addresses only, no names, so just what you would get from RCPT TO)
	 * Because of this invariant, we can sort the email addresses for this message the same way,
	 * and then just do string comparisons of each line in 1 pass over the file.
	 * Even though we have to sort the list of recipients for THIS message, it will probably be small in most cases,
	 * and though the file could be very large, it's not being sorted, we are just making a linear pass over it,
	 * so this should be a fairly efficient operation.
	 *
	 * Note that each set of recipients is sorted, but the From addresses at the beginning of each line are not sorted with respect to each other,
	 * since we simply append to the end of the file when adding a new entry. This doesn't really affect the performance in any way either. */

	/* First, go ahead and construct the "equivalent line" for this message, which we must find an exact match for. */
	SAFE_FAST_APPEND_NOSPACE(line, sizeof(line), linebuf, lineleft, "%s", mproc->from);
	/* We can't just append directly to the string, first we need to sort the recipients.
	 * Since we have to construct a new list anyways, sort the list as we add to it,
	 * rather than doing it afterwards. */
	stringlist_init(&sorted_recipients);
	while ((s = stringlist_next(mproc->recipients, &i))) {
		stringlist_push_sorted(&sorted_recipients, s);
	}
	/* Now, iterate through the new list and construct the recipients part of the line */
	while ((s2 = stringlist_pop(&sorted_recipients))) {
		SAFE_FAST_APPEND_NOSPACE(line, sizeof(line), linebuf, lineleft, ",%s", s2);
		free(s2);
	}
	stringlist_empty_destroy(&sorted_recipients);
	/* Since the line we read using fgets ends with LF, add one here, so we can do an exact comparison. */
	SAFE_FAST_APPEND_NOSPACE(line, sizeof(line), linebuf, lineleft, "\n");

	/* First, see if the set was recently attempted.
	 * If so, this is the retry and it should be approved. */
	now = time(NULL) - 60;

	/* This is the main bottleneck since only one transaction can be using the list at a time here,
	 * but message submissions are infrequent, and this list will usually be empty or near-empty,
	 * so this is unlikely to be an issue. */
	RWLIST_WRLOCK(&deferred_attempts);
	RWLIST_TRAVERSE_SAFE_BEGIN(&deferred_attempts, attempt, entry) {
		if (attempt->time < now) {
			int sec_ago = (int) (now + 60 - attempt->time); /* Add 60 to get actual "now", since we previously subtracted it from now */
			/* It's been more than a minute, purge it */
			bbs_debug(3, "From/Recipients set combo was previously deferred, but that was %d seconds ago (expired)\n", sec_ago);
			RWLIST_REMOVE_CURRENT(entry);
			free(attempt);
			continue;
		}
		if (mproc->userid != attempt->userid) {
			continue;
		}
		if (!strcasecmp(attempt->line, line)) {
			was_deferred = 1;
			RWLIST_REMOVE_CURRENT(entry);
			free(attempt);
			/* Don't break yet.
			 * Continue iterating to clear out any entries that might be stale. */
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&deferred_attempts);

	/* Now, iterate through the file to look for a match.
	 * Although not strictly necessary, we do this in case the file was modified since we added it to the deferred list,
	 * to avoid possibly adding a duplicate. */
	while (fgets(buf, sizeof(buf), fp)) {
		/* We need an exact match, but case-insensitive is fine for email addresses */
		if (!strcasecmp(buf, line)) {
			found_match = 1;
			break;
		}
	}

	if (found_match) {
		fclose(fp);
		/* Already exists in file, accept */
		bbs_debug(4, "From/Recipient set already exists, accepting\n");
		return 0;
	} else if (was_deferred) {
		size_t line_strlen = (size_t) (linebuf - line);
		/* Append to end of file so it will match in the future, and accept */
		fseek(fp, 0, SEEK_END);
		fwrite(line, 1, line_strlen, fp);
		fclose(fp);
		bbs_debug(4, "Added deferred From/Recipient set, accepting\n");
		return 0;
	}

	fclose(fp);

	/* Temporarily reject the message to warn user that he or she is sending to a new set of recipients from the given From identity.
	 * This gives the user a chance to correct the message if needed (either the wrong From identity, or wrong set of recipients).
	 * If it's not a mistake, the user can immediately reattempt submission to force it to succeed and add the set to the file
	 * so it will be immediately accepted in the future. */

	/* Now, keep track that this set was attempted once, and we deferred it,
	 * so if we detect the same set again, we can accept it. */
	attempt = calloc(1, sizeof(*attempt) + strlen(line) + 1);
	if (ALLOC_SUCCESS(attempt)) {
		strcpy(attempt->line, line); /* Safe */
		attempt->userid = mproc->userid;
		attempt->time = time(NULL);
		RWLIST_WRLOCK(&deferred_attempts);
		RWLIST_INSERT_HEAD(&deferred_attempts, attempt, entry);
		RWLIST_UNLOCK(&deferred_attempts);
	}

	bbs_debug(4, "From/Recipient set not seen before, deferring\n");
	bbs_smtp_log(4, mproc->smtp, "Submission deferred: From/Recipient set not seen before: %s\n", line);
	/* The effectiveness of this depends heavily on the user's mail user agent presenting
	 * the entire SMTP failure code/message directly to the user.
	 * But if that doesn't happen, then that's a problem with the user's client. */
	smtp_reply_nostatus(mproc->smtp, 421, "From/Recipient set not seen before, resubmit if intentional");
	return 1;
}

static int load_module(void)
{
	return smtp_register_processor(processor);
}

static int unload_module(void)
{
	int res = smtp_unregister_processor(processor);
	RWLIST_WRLOCK_REMOVE_ALL(&deferred_attempts, entry, free);
	return res;
}

BBS_MODULE_INFO_DEPENDENT("Recipient Monitor", "net_smtp.so");
