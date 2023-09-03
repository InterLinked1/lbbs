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
 * \brief RFC5423 Message Store Events Logger
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <pthread.h>

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/node.h"
#include "include/user.h"
#include "include/range.h"

#include "include/mod_mail.h"

static FILE *fp = NULL;
static pthread_mutex_t loglock = PTHREAD_MUTEX_INITIALIZER;

static const char *service_name(struct bbs_node *node)
{
	if (STARTS_WITH(node->protname, "IMAP")) {
		return "imap";
	} else if (STARTS_WITH(node->protname, "POP3")) {
		return "pop";
	} else if (STARTS_WITH(node->protname, "SMTP")) {
		return "smtp";
	} else {
		bbs_warning("Unexpected message client protocol: %s\n", node->protname);
	}
	return "";
}

static int generate_imap_uri(struct mailbox *mbox, const char *maildir, char *restrict buf, size_t len)
{
	/* Events that affect mailboxes */
	/* URI describing mailbox: */
	int imap_port;
	const char *mboxname = "";
	size_t dirlen = maildir ? strlen(maildir) : 0;

	if (dirlen && dirlen < mailbox_maildir_len(mbox)) {
		bbs_warning("maildir len (%lu) is less than maildir root len (%lu)?\n", dirlen, mailbox_maildir_len(mbox));
		return -1;
	}

	imap_port = bbs_protocol_port("IMAPS");
	if (maildir) {
		mboxname = maildir + mailbox_maildir_len(mbox);
		mboxname = strlen_zero(mboxname) ? "/INBOX" : mboxname;
	}
	/* XXX This is slightly fragile, as we don't actually know what the username@domain for the mailbox should be for sure.
	* We support multiple domains and, particularly for message access, wouldn't necessarily know this. */
	if (mailbox_id(mbox)) {
		char username[64] = "";
		bbs_username_from_userid((unsigned int) mailbox_id(mbox), username, sizeof(username));
		/* User's personal mailbox */
		snprintf(buf, len, "imap://%s@%s:%d%s", username, bbs_hostname(), imap_port, mboxname);
	} else {
		/* Shared (named) mailbox */
		snprintf(buf, len, "imap://%s@%s:%d%s", mailbox_name(mbox), bbs_hostname(), imap_port, mboxname);
	}
	return 0;
}

static void log_cb(struct mailbox_event *e)
{
	char timebuf[40];
	char mailboxid[256];
	char oldmboxuri[256];
	struct tm tm;

	/* There are several logging formats that could be used:
	 * header-style, JSON format, XML, etc.
	 * Here we use the first one, since it's the simplest: we don't need to encode anything.
	 * However, this type of formatting dictates that the logs be relatively simple,
	 * e.g. we only log parameters that are at most a single line.
	 */

	/* General properties of all events */
	fprintf(fp, "Event: %s\n", mailbox_event_type_name(e->type));
	fprintf(fp, "ID: %lu\n", e->id);
	localtime_r(&e->timestamp, &tm);
	strftime(timebuf, sizeof(timebuf), "%FT%T%z", &tm); /* RFC 3339 timestamp */
	fprintf(fp, "timestamp: %s\n", timebuf);
	if (e->node) { /* e->node can be NULL for the EXPUNGE event (scan_mailboxes in mod_mail) */
		fprintf(fp, "service: %s\n", service_name(e->node));
		if (e->messageaccess) {
			/* Mandatory: admin, if authorization identity != authentication identity */
			fprintf(fp, "clientIP: %s\n", e->node->ip);
			fprintf(fp, "clientPort: %u\n", e->node->rport);
			if (bbs_user_is_registered(e->node->user)) {
				fprintf(fp, "user: %s\n", bbs_username(e->node->user));
			}
		}
	}

	if (e->maildir) {
		if (!generate_imap_uri(e->mbox, e->maildir, mailboxid, sizeof(mailboxid))) {
			fprintf(fp, "mailboxID: %s\n", mailboxid);
		}
	}

	/* Mandatory: uri - either for server, mailbox, or message */
	if (e->mbox) {
		if (e->maildir) {
			if (e->numuids == 1) {
				if (!generate_imap_uri(e->mbox, e->maildir, mailboxid, sizeof(mailboxid))) {
					fprintf(fp, "uri: %s;UIDVALIDITY=%u;UID=%u\n", mailboxid, mailbox_event_uidvalidity(e), e->uids[0]);
				}
				if (e->modseq) {
					fprintf(fp, "modseq: %lu\n", e->modseq);
				}
			} else {
				if (!generate_imap_uri(e->mbox, e->maildir, mailboxid, sizeof(mailboxid))) {
					fprintf(fp, "uri: %s;UIDVALIDITY=%u\n", mailboxid, mailbox_event_uidvalidity(e));
				}
			}
			fprintf(fp, "uidnext: %u\n", mailbox_event_uidnext(e));
		} else {
			if (!generate_imap_uri(e->mbox, NULL, mailboxid, sizeof(mailboxid))) {
				fprintf(fp, "uri: %s\n", mailboxid);
			}
		}
	}

	/* Event specific parameters */
	switch (e->type) {
		case EVENT_QUOTA_EXCEED:
		case EVENT_QUOTA_WITHIN:
			bbs_assert_exists(e->mbox);
			fprintf(fp, "maxMessages: %lu\n", mailbox_max_messages(e->mbox));
			/* Mandatory: messages - # of messages in this maildir (could also include for NEW, APPEND, EXPUNGE, EXPIRE events */
			/* Fall through */
		case EVENT_QUOTA_CHANGE:
			bbs_assert_exists(e->mbox);
			fprintf(fp, "diskQuota: %lu\n", mailbox_quota(e->mbox));
			fprintf(fp, "diskUsed: %lu\n", mailbox_quota_used(e->mbox));
			break;
		case EVENT_MESSAGE_NEW:
			/* Optional: envelope */
			/* Fall through */
		case EVENT_MESSAGE_APPEND:
			/* Optional: bodyStructure */
			/* Optional: flagNames */
			/* Optional: messageContent. Size-based suppression SHOULD be available (e.g. if over some number of KB) */
			fprintf(fp, "messageSize: %lu\n", e->msgsize);
			break;
		case EVENT_FLAGS_SET:
		case EVENT_FLAGS_CLEAR:
			fprintf(fp, "flagNames: %s\n", e->flagnames);
			break;
		case EVENT_MAILBOX_RENAME:
			if (!generate_imap_uri(e->mbox, e->oldmaildir, oldmboxuri, sizeof(oldmboxuri))) {
				fprintf(fp, "oldMailboxID: %s\n", oldmboxuri);
			}
			break;
		case EVENT_LOGIN:
			/* Mandatory: serverDomain */
			fprintf(fp, "serverPort: %u\n", e->node->port);
			break;
		default:
			break;
	}

	if (e->type & (EVENT_FLAGS_SET | EVENT_FLAGS_CLEAR | EVENT_MESSAGE_READ | EVENT_MESSAGE_TRASH | EVENT_MESSAGE_EXPUNGE | EVENT_MESSAGE_EXPIRE)) {
		/* uidset */
		if (e->numuids) {
			char *uidset = gen_uintlist(e->uids, e->numuids);
			if (uidset) {
				fprintf(fp, "uidset: %s\n", uidset);
				free(uidset);
			}
		} else {
			bbs_warning("No UID list provided for event %s?\n", mailbox_event_type_name(e->type));
		}
	}

	/* Included in the spec, but not generated by us:
	 * - pid (process ID)
	 * - process (process name)
	 * - serverFQDN
	 * - tags
	 */
	fprintf(fp, "\n"); /* Empty line to end the event */
}

/*! \brief Callback for all mailbox events */
static void mbox_event_callback(struct mailbox_event *event)
{
	/* Serialize logging for events, so events aren't logged partially interleaved with each other.
	 * Obviously, this may reduce performance. */
	pthread_mutex_lock(&loglock);
	log_cb(event);
	pthread_mutex_unlock(&loglock);
}

static int load_config(void)
{
	char logfile[256];
	struct bbs_config *cfg;

	cfg = bbs_config_load("mod_mail_events.conf", 1);
	if (!cfg) {
		return -1;
	}

	/* General */
	if (bbs_config_val_set_str(cfg, "general", "logfile", logfile, sizeof(logfile))) {
		return -1;
	}
	fp = fopen(logfile, "a");
	return fp ? 0 : -1;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	if (mailbox_register_watcher(mbox_event_callback)) {
		fclose(fp);
		return -1;
	}
	return 0;
}

static int unload_module(void)
{
	mailbox_unregister_watcher(mbox_event_callback);
	fclose(fp);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC5423 Mailbox Event Logger", "mod_mail.so");
