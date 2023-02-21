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
 * \brief E-Mail Resource Module
 *
 * \note Common e-mail resources for SMTP, POP3, and IMAP4 servers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/config.h"
#include "include/user.h"
#include "include/utils.h"

#include "include/mod_mail.h"

static char maildir[248] = "";
static char catchall[256] = "";
static unsigned int maxquota = 10000000;

/*! \brief Opaque structure for a user's mailbox */
struct mailbox {
	unsigned int id;					/* Mailbox ID. Corresponds with user ID. */
	char maildir[256];					/* User's mailbox directory, on disk. */
	pthread_rwlock_t lock;				/* R/W lock for entire mailbox. R/W instead of a mutex, because POP write locks the entire mailbox, IMAP can just read lock. */
	pthread_mutex_t uidlock;			/* Mutex for UID operations. */
	RWLIST_ENTRY(mailbox) entry;		/* Next mailbox */
};

/* Once created, mailboxes are not destroyed until module unload,
 * so reference counting is not needed. It is safe to return
 * mailboxes unlocked and use them in the net modules,
 * since they bump the refcount of this module itself. */
static RWLIST_HEAD_STATIC(mailboxes, mailbox);

/* E-Mail Address Alias */
struct alias {
	int userid;
	const char *alias;
	const char *target;
	RWLIST_ENTRY(alias) entry;		/* Next alias */
	char data[0];
};

static RWLIST_HEAD_STATIC(aliases, alias);

static void mailbox_free(struct mailbox *mbox)
{
	pthread_rwlock_destroy(&mbox->lock);
	pthread_mutex_destroy(&mbox->uidlock);
	free(mbox);
}

static void mailbox_cleanup(void)
{
	struct mailbox *mbox;
	struct alias *alias;

	/* Clean up mailboxes */
	RWLIST_WRLOCK(&mailboxes);
	while ((mbox = RWLIST_REMOVE_HEAD(&mailboxes, entry))) {
		mailbox_free(mbox);
	}
	RWLIST_UNLOCK(&mailboxes);

	RWLIST_WRLOCK(&aliases);
	while ((alias = RWLIST_REMOVE_HEAD(&aliases, entry))) {
		free(alias);
	}
	RWLIST_UNLOCK(&aliases);
}

/*!
 * \brief Retrieve the user ID of the mailbox to which an alias maps
 * \retval 0 on failure/no such alias, positive user ID on success
 */
static unsigned int resolve_alias(const char *aliasname)
{
	struct alias *alias;
	unsigned int res;

	RWLIST_RDLOCK(&aliases);
	RWLIST_TRAVERSE(&aliases, alias, entry) {
		if (!strcmp(alias->alias, aliasname)) {
			break;
		}
	}
	if (!alias) {
		RWLIST_UNLOCK(&aliases);
		return 0;
	}
	if (alias->userid > 0) {
		RWLIST_UNLOCK(&aliases);
		return (unsigned int) alias->userid;
	} else if (alias->userid == 0) {
		RWLIST_UNLOCK(&aliases);
		return 0;
	}
	/* First access, compute what the actual user ID mapping is. */
	res = bbs_userid_from_username(alias->target);
	if (!res) {
		alias->userid = -1; /* Indicate no such user exists, so we don't have to look this up again in the future. */
		/* XXX If the user is created while mod_mail is running, we won't pick that up, but performance benefit of this optimization is probably worth it? */
		res = 0;
	} else {
		alias->userid = res;
	}
	RWLIST_UNLOCK(&aliases);
	return res;
}

static void add_alias(const char *aliasname, const char *target)
{
	struct alias *alias;
	int aliaslen, targetlen;

	RWLIST_WRLOCK(&aliases);
	RWLIST_TRAVERSE(&aliases, alias, entry) {
		if (!strcmp(alias->alias, aliasname)) {
			break;
		}
	}
	if (alias) {
		bbs_warning("Alias %s already mapped to user %s\n", alias->alias, alias->target);
		RWLIST_UNLOCK(&aliases);
		return;
	}
	aliaslen = strlen(aliasname);
	targetlen = strlen(target);
	alias = calloc(1, sizeof(*alias) + aliaslen + targetlen + 2);
	if (!alias) {
		bbs_error("calloc failed\n");
		RWLIST_UNLOCK(&aliases);
		return;
	}
	strcpy(alias->data, aliasname);
	strcpy(alias->data + aliaslen + 1, target);
	alias->alias = alias->data;
	/* Store the actual target name directly, instead of converting to a username immediately, since mod_mysql might not be loaded when the config is parsed. */
	alias->target = alias->data + aliaslen;
	alias->userid = 0; /* Not known yet, will get the first time we access this. */
	RWLIST_INSERT_HEAD(&aliases, alias, entry);
	bbs_debug(3, "Added alias mapping %s => %s\n", alias->alias, alias->target);
	RWLIST_UNLOCK(&aliases);
}

static int create_if_nexist(const char *path)
{
	if (eaccess(path, R_OK)) {
		if (mkdir(path, 0700)) {
			bbs_error("mkdir(%s) failed: %s\n", path, strerror(errno));
			return -1;
		}
	}
	return 0;
}

/*!
 * \brief Retrieve a mailbox, creating it if it does not already exist
 * \retval mailbox on success, NULL on failure
 */
static struct mailbox *mailbox_find_or_create(unsigned int userid)
{
	struct mailbox *mbox;

	if (!userid) {
		bbs_error("Can't create mailbox for user ID %u\n", userid); /* Probably a bug somewhere else */
		return NULL;
	}

	RWLIST_WRLOCK(&mailboxes);
	RWLIST_TRAVERSE(&mailboxes, mbox, entry) {
		if (mbox->id == userid) {
			break;
		}
	}
	if (!mbox) {
		char newdirname[265];
		bbs_debug(3, "Creating mailbox for user %u for the first time\n", userid);
		mbox = calloc(1, sizeof(*mbox));
		if (!mbox) {
			bbs_error("calloc failed\n");
			RWLIST_UNLOCK(&mailboxes);
			return NULL;
		}
		pthread_rwlock_init(&mbox->lock, NULL);
		pthread_mutex_init(&mbox->uidlock, NULL);
		mbox->id = userid;
		snprintf(mbox->maildir, sizeof(mbox->maildir), "%s/%u", maildir, userid);
		RWLIST_INSERT_HEAD(&mailboxes, mbox, entry);
		/* Before we return the mailbox to a mail server module for operations,
		 * make sure that the user's mail directory actually exists. */
		if (eaccess(mbox->maildir, R_OK)) {
			/* Can't even read this directory, so it probably doesn't exist. Try creating it. */
			if (mkdir(mbox->maildir, 0700)) {
				bbs_error("mkdir(%s) failed: %s\n", mbox->maildir, strerror(errno));
			} else {
				bbs_verb(5, "Created mail directory %s\n", mbox->maildir);
			}
		}
		/* Create any needed special directories for the user. */
		/* directories are prefixed with a . for maildir++ format */
		snprintf(newdirname, sizeof(newdirname), "%s/.%s", mbox->maildir, "Drafts");
		create_if_nexist(newdirname);
		snprintf(newdirname, sizeof(newdirname), "%s/.%s", mbox->maildir, "Junk");
		create_if_nexist(newdirname);
		snprintf(newdirname, sizeof(newdirname), "%s/.%s", mbox->maildir, "Sent");
		create_if_nexist(newdirname);
		snprintf(newdirname, sizeof(newdirname), "%s/.%s", mbox->maildir, "Trash");
		create_if_nexist(newdirname);
		/* Skip All and Flagged (virtual folders) */
		/* Skip Archive */
	}
	RWLIST_UNLOCK(&mailboxes);
	return mbox;
}

struct mailbox *mailbox_get(unsigned int userid, const char *name)
{
	struct mailbox *mbox = NULL;

	/* If we have a user ID, use that directly. */
	if (!userid) {
		if (strlen_zero(name)) {
			bbs_error("Must specify at least either a user ID or name\n");
			return NULL;
		}
		/* New mailboxes could be created while the module is running (e.g. new user registration), so we may have to query the DB anyways. */
		userid = bbs_userid_from_username(name);
	}

	/* If we had a user ID or were able to translate the name to one, lookup the mailbox by user ID. */
	if (userid) {
		bbs_debug(5, "Found mailbox mapping via username directly\n");
		mbox = mailbox_find_or_create(userid);
	}

	/* If we still don't have a valid mailbox at this point, see if it's an alias. */
	if (!mbox && !strlen_zero(name)) {
		userid = resolve_alias(name);
		if (userid) {
			bbs_debug(5, "Found mailbox mapping via alias\n");
			mbox = mailbox_find_or_create(userid);
		}
	}

	if (!mbox && !s_strlen_zero(catchall)) {
		static int catch_all_userid = 0; /* This won't change, so until we having caching of user ID to usernames in the core, don't look this up again after we find a match. */
		if (!catch_all_userid) {
			catch_all_userid = bbs_userid_from_username(catchall);
		}
		if (catch_all_userid) {
			bbs_debug(5, "Found mailbox mapping via catch all\n");
			mbox = mailbox_find_or_create(catch_all_userid);
		} else {
			bbs_warning("No user exists for catch all mailbox '%s'\n", catchall); /* If a catch all address was explicitly specified, it was probably intended that it works. */
		}
	}

	return mbox;
}

int mailbox_rdlock(struct mailbox *mbox)
{
	return pthread_rwlock_tryrdlock(&mbox->lock);
}

int mailbox_wrlock(struct mailbox *mbox)
{
	return pthread_rwlock_trywrlock(&mbox->lock);
}

void mailbox_unlock(struct mailbox *mbox)
{
	pthread_rwlock_unlock(&mbox->lock);
}

int mailbox_uid_lock(struct mailbox *mbox)
{
	return pthread_mutex_lock(&mbox->uidlock);
}

void mailbox_uid_unlock(struct mailbox *mbox)
{
	pthread_mutex_unlock(&mbox->uidlock);
}

unsigned long mailbox_quota(struct mailbox *mbox)
{
	UNUSED(mbox); /* Not currently per-mailbox, but leave open the possibility of being more granular in the future. */
	return (unsigned long) maxquota;
}

unsigned long mailbox_quota_remaining(struct mailbox *mbox)
{
	long quota, quotaused;

	quota = mailbox_quota(mbox);
	quotaused = bbs_dir_size(mailbox_maildir(mbox));
	if (quotaused < 0) {
		/* An error occured, so we have no idea how much space is used.
		 * Err on the side of assuming no quota for now. */
		bbs_warning("Unable to calculate quota usage for mailbox %p\n", mbox);
		return quota;
	}
	quota -= quotaused;
	if (quota <= 0) {
		return 0; /* Quota already exceeded. Don't cast to unsigned or it will underflow and be huge. */
	}
	return (unsigned long) (quota - quotaused);
}

int mailbox_maildir_init(const char *path)
{
	char buf[256];
	int res = 0;

	res |= create_if_nexist(path);
	snprintf(buf, sizeof(buf), "%s/new", path);
	res |= create_if_nexist(buf);
	snprintf(buf, sizeof(buf), "%s/cur", path);
	res |= create_if_nexist(buf);
	snprintf(buf, sizeof(buf), "%s/tmp", path);
	res |= create_if_nexist(buf);

	return res;
}

const char *mailbox_maildir(struct mailbox *mbox)
{
	if (!mbox) {
		return maildir;
	}
	return mbox->maildir;
}

int mailbox_id(struct mailbox *mbox)
{
	return mbox->id;
}

int maildir_mktemp(const char *path, char *buf, size_t len, char *newbuf)
{
	struct timeval tvnow;
	struct stat st;
	int fd;

	for (;;) {
		tvnow = bbs_tvnow();
		snprintf(buf, len, "%s/tmp/%lu%06lu", path, tvnow.tv_sec, tvnow.tv_usec);
		snprintf(newbuf, len, "%s/new/%lu%06lu", path, tvnow.tv_sec, tvnow.tv_usec);
		if (stat(buf, &st) == -1 && errno == ENOENT) {
			/* Error means it doesn't exist. */
			if (stat(newbuf, &st) == -1 && errno == ENOENT) {
				break;
			}
		}
		usleep(100 + bbs_rand(1, 25));
	}

	fd = open(buf, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		bbs_error("open failed: %s\n", strerror(errno));
	}
	return fd;
}

/*
 * maildir format: http://cr.yp.to/proto/maildir.html
 * also: http://www.courier-mta.org/maildir.html
 * and: https://www.courier-mta.org/imap/README.maildirquota.html
 * and: https://www.systutorials.com/docs/linux/man/2-gettimeofday/
 * Note that some information here is obsolete.
 * For exmaple, mkstemp safely returns a unique temporary filename.
 */

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

	cfg = bbs_config_load("mod_mail.conf", 1);
	if (!cfg) {
		return -1;
	}

	if (bbs_config_val_set_str(cfg, "general", "maildir", maildir, sizeof(maildir))) {
		return -1;
	}
	bbs_config_val_set_str(cfg, "general", "catchall", catchall, sizeof(catchall));
	bbs_config_val_set_uint(cfg, "general", "quota", &maxquota);

	if (eaccess(maildir, X_OK)) { /* This is a directory, so we better have execute permissions on it */
		bbs_error("Directory %s does not exist\n", maildir);
		return -1;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		/* Already processed */
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue;
		}

		if (!strcmp(bbs_config_section_name(section), "aliases")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
				add_alias(key, value);
			}
		} else {
			bbs_warning("Unknown section name, ignoring: %s\n", bbs_config_section_name(section));
		}
	}
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	return 0;
}

static int unload_module(void)
{
	mailbox_cleanup();
	return 0;
}

BBS_MODULE_INFO_FLAGS("E-Mail Resource", MODFLAG_GLOBAL_SYMBOLS);
