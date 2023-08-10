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
 * \brief E-Mail Trash Auto-Purge
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <pthread.h>
#include <dirent.h>

#include "include/module.h"
#include "include/config.h"
#include "include/range.h"
#include "include/utils.h"

#include "include/mod_mail.h"

static unsigned int trashdays = 7;

static pthread_t trash_thread = 0;

struct trash_traversal {
	unsigned int *a;	/* For UIDs */
	unsigned int *sa;	/* For sequence numbers */
	int lengths;
	int allocsizes;
	struct mailbox *mbox;
};

static int on_mailbox_trash(const char *dir_name, const char *filename, int seqno, void *obj)
{
	struct stat st;
	char fullname[256];
	int tstamp;
	int trashsec = 86400 * (int) trashdays;
	int elapsed, now = (int) time(NULL);
	unsigned int msguid;
	struct trash_traversal *traversal = obj;
	struct mailbox *mbox = traversal->mbox;

	/* For autopurging, we don't care if the Deleted flag is set or not.
	 * (If it were set, an IMAP user already flagged it for permanent deletion and it would just be awaiting expunge) */

	snprintf(fullname, sizeof(fullname), "%s/%s", dir_name, filename);
	if (stat(fullname, &st)) {
		bbs_error("stat(%s) failed: %s\n", fullname, strerror(errno));
		return 0;
	}
	tstamp = (int) st.st_ctime;
	elapsed = now - tstamp;
	bbs_debug(7, "Encountered in trash: %s (%d s ago)\n", fullname, elapsed);
	if (elapsed > trashsec) {
		if (unlink(fullname)) {
			bbs_error("unlink(%s) failed: %s\n", fullname, strerror(errno));
		} else {
			bbs_debug(4, "Permanently deleted %s\n", fullname);
			mailbox_quota_adjust_usage(mbox, (int) -st.st_size); /* Subtract file size from quota usage */
		}
		maildir_parse_uid_from_filename(filename, &msguid);
		uintlist_append2(&traversal->a, &traversal->sa, &traversal->lengths, &traversal->allocsizes, msguid, (unsigned int) seqno);
	}
	return 0;
}

static void scan_mailboxes(void)
{
	DIR *dir;
	struct dirent *entry;
	char trashdir[515];

	/* Traverse each mailbox top-level maildir. The order of maildir traversal does not matter. */
	if (!(dir = opendir(mailbox_maildir(NULL)))) {
		bbs_error("Error opening directory - %s: %s\n", mailbox_maildir(NULL), strerror(errno));
		return;
	}
	while ((entry = readdir(dir)) != NULL) {
		struct mailbox *mbox;
		unsigned int mboxnum;
		struct trash_traversal traversal;
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		if (!maildir_is_mailbox(entry->d_name)) {
			continue;
		}
		snprintf(trashdir, sizeof(trashdir), "%s/%s/.Trash/cur", mailbox_maildir(NULL), entry->d_name);
		if (eaccess(trashdir, R_OK)) {
			bbs_debug(2, "Directory %s doesn't exist?\n", trashdir); /* It should if it's a maildir we created, unless user has never accessed it yet. */
			continue;
		}
		bbs_debug(3, "Analyzing trash folder %s\n", trashdir);
		mboxnum = (unsigned int) atoi(entry->d_name);
		mbox = mboxnum ? mailbox_get_by_userid(mboxnum) : mailbox_get_by_name(entry->d_name, NULL);
		memset(&traversal, 0, sizeof(traversal));
		traversal.mbox = mbox;
		maildir_ordered_traverse(trashdir, on_mailbox_trash, &traversal); /* Traverse files in the Trash folder */
		if (traversal.lengths) {
			maildir_indicate_expunged(EVENT_MESSAGE_EXPIRE, NULL, mbox, entry->d_name, traversal.a, traversal.sa, traversal.lengths, 0);
			free_if(traversal.a);
			free_if(traversal.sa);
		}
	}

	closedir(dir);
}

static void *trash_monitor(void *unused)
{
	UNUSED(unused);
	for (;;) {
		bbs_pthread_disable_cancel();
		scan_mailboxes();
		bbs_pthread_enable_cancel();
		/* Not necessary to run more frequently than once per hour. */
		sleep(60 * 60); /* use sleep instead of usleep since the argument to usleep would overflow an int */
	}
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("mod_mail.conf", 1);
	if (!cfg) {
		return -1;
	}

	bbs_config_val_set_uint(cfg, "general", "trashdays", &trashdays);
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	if (trashdays && bbs_pthread_create(&trash_thread, NULL, trash_monitor, NULL)) {
		return -1;
	}

	return 0;
}

static int unload_module(void)
{
	if (trashdays) {
		bbs_pthread_cancel_kill(trash_thread);
		bbs_pthread_join(trash_thread, NULL);
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("E-Mail Garbage Collection", "mod_mail.so");
