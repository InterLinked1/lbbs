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
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/config.h"
#include "include/user.h"
#include "include/utils.h"

#include "include/mod_mail.h"

static char maildir[248] = "";
static char catchall[256] = "";
static unsigned int maxquota = 10000000;
static unsigned int trashdays = 7;

static pthread_t trash_thread = -1;

/*! \brief Opaque structure for a user's mailbox */
struct mailbox {
	unsigned int id;					/* Mailbox ID. Corresponds with user ID. */
	unsigned int watchers;				/* Number of watchers for this mailbox. */
	unsigned int quotausage;			/* Cached quota usage calculation */
	char maildir[256];					/* User's mailbox directory, on disk. */
	pthread_rwlock_t lock;				/* R/W lock for entire mailbox. R/W instead of a mutex, because POP write locks the entire mailbox, IMAP can just read lock. */
	pthread_mutex_t uidlock;			/* Mutex for UID operations. */
	RWLIST_ENTRY(mailbox) entry;		/* Next mailbox */
	unsigned int activity:1;			/* Mailbox has activity */
	unsigned int quotavalid:1;			/* Whether cached quota calculations may still be used */
	char *name;
};

/* Once created, mailboxes are not destroyed until module unload,
 * so reference counting is not needed. It is safe to return
 * mailboxes unlocked and use them in the net modules,
 * since they bump the refcount of this module itself. */
static RWLIST_HEAD_STATIC(mailboxes, mailbox);

static void (*watchcallback)(struct mailbox *mbox, const char *newfile) = NULL;
static void *watchmod = NULL;

int __mailbox_register_watcher(void (*callback)(struct mailbox *mbox, const char *newfile), void *mod)
{
	/* Can only be one (IMAP). Could support more, but that's all we need this for,
	 * so no need to add complexity by maintaining a list of callbacks at the moment. */
	if (watchcallback) {
		bbs_error("A mailbox watcher is already registered.\n");
		return -1;
	}

	watchcallback = callback;
	watchmod = mod;
	return 0;
}

int mailbox_unregister_watcher(void (*callback)(struct mailbox *mbox, const char *newfile))
{
	if (watchcallback != callback) {
		bbs_error("Mailbox watcher %p does not match registered provider %p\n", callback, watchcallback);
		return -1;
	}

	watchcallback = NULL;
	watchmod = NULL;
	return 0;
}

struct smtp_processor {
	int (*cb)(struct smtp_msg_process *proc);
	void *mod;
	RWLIST_ENTRY(smtp_processor) entry;
};

static RWLIST_HEAD_STATIC(processors, smtp_processor);

/*! \note This is in mod_mail instead of net_smtp since the BBS doesn't currently support
 * modules that both have dependencies and are dependencies of other modules,
 * since the module autoloader only does a single pass to load modules that export global symbols.
 * e.g. mod_mailscript depending on net_smtp, which depends on mod_mail.
 * So we make both mod_mailscript and net_smtp depend on mod_mail directly.
 * If this is resolved in the future, it may make sense to move this to net_smtp. */
int __smtp_register_processor(int (*cb)(struct smtp_msg_process *mproc), void *mod)
{
	struct smtp_processor *proc;

	proc = calloc(1, sizeof(*proc));
	if (ALLOC_FAILURE(proc)) {
		return -1;
	}

	proc->cb = cb;
	proc->mod = mod;

	RWLIST_WRLOCK(&processors);
	RWLIST_INSERT_TAIL(&processors, proc, entry);
	RWLIST_UNLOCK(&processors);
	return 0;
}

int smtp_unregister_processor(int (*cb)(struct smtp_msg_process *mproc))
{
	struct smtp_processor *proc;

	proc = RWLIST_WRLOCK_REMOVE_BY_FIELD(&processors, cb, cb, entry);
	if (!proc) {
		bbs_error("Couldn't remove processor %p\n", cb);
		return -1;
	}
	free(proc);
	return 0;
}

int smtp_run_callbacks(struct smtp_msg_process *mproc)
{
	int res = 0;
	struct smtp_processor *proc;

	RWLIST_RDLOCK(&processors);
	RWLIST_TRAVERSE(&processors, proc, entry) {
		bbs_module_ref(proc->mod);
		res |= proc->cb(mproc);
		bbs_module_unref(proc->mod);
		if (res) {
			break; /* Stop processing immediately if a processor returns nonzero */
		}
	}
	RWLIST_UNLOCK(&processors);
	return res;
}

/* E-Mail Address Alias */
struct alias {
	int userid;
	const char *alias;
	const char *target;
	RWLIST_ENTRY(alias) entry;		/* Next alias */
	char data[0];
};

static RWLIST_HEAD_STATIC(aliases, alias);

struct listserv {
	const char *name;
	const char *target;
	RWLIST_ENTRY(listserv) entry;		/* Next alias */
	char data[0];
};

static RWLIST_HEAD_STATIC(listservs, listserv);

static void mailbox_free(struct mailbox *mbox)
{
	pthread_rwlock_destroy(&mbox->lock);
	pthread_mutex_destroy(&mbox->uidlock);
	free(mbox);
}

static void mailbox_cleanup(void)
{
	/* Clean up mailboxes */
	RWLIST_WRLOCK_REMOVE_ALL(&mailboxes, entry, mailbox_free);
	RWLIST_WRLOCK_REMOVE_ALL(&aliases, entry, free);
	RWLIST_WRLOCK_REMOVE_ALL(&listservs, entry, free);
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
	} else if (alias->userid == -1) { /* Previously confirmed that this alias does not map to anything, skip an unnecessary lookup that will fail */
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

	if (strlen_zero(target)) {
		bbs_error("Empty translation for alias %s\n", aliasname);
		return;
	}

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
	if (ALLOC_FAILURE(alias)) {
		RWLIST_UNLOCK(&aliases);
		return;
	}
	strcpy(alias->data, aliasname);
	strcpy(alias->data + aliaslen + 1, target);
	alias->alias = alias->data;
	/* Store the actual target name directly, instead of converting to a username immediately, since mod_mysql might not be loaded when the config is parsed. */
	alias->target = alias->data + aliaslen + 1;
	alias->userid = 0; /* Not known yet, will get the first time we access this. */
	RWLIST_INSERT_HEAD(&aliases, alias, entry);
	bbs_debug(3, "Added alias mapping %s => %s\n", alias->alias, alias->target);
	RWLIST_UNLOCK(&aliases);
}

static void add_listserv(const char *listname, const char *target)
{
	struct listserv *l;
	int listlen, targetlen;

	if (strlen_zero(target)) {
		bbs_error("Empty membership for listserv %s\n", listname);
		return;
	}

	RWLIST_WRLOCK(&listservs);
	RWLIST_TRAVERSE(&listservs, l, entry) {
		if (!strcmp(l->name, listname)) {
			break;
		}
	}
	if (l) {
		bbs_warning("List %s already defined: %s\n", l->name, l->target);
		RWLIST_UNLOCK(&listservs);
		return;
	}
	listlen = strlen(listname);
	targetlen = strlen(target);
	l = calloc(1, sizeof(*l) + listlen + targetlen + 2);
	if (ALLOC_FAILURE(l)) {
		RWLIST_UNLOCK(&listservs);
		return;
	}
	strcpy(l->data, listname);
	strcpy(l->data + listlen + 1, target);
	l->name = l->data;
	/* Store the actual target name directly, instead of converting to a username immediately, since mod_mysql might not be loaded when the config is parsed. */
	l->target = l->data + listlen + 1;
	RWLIST_INSERT_HEAD(&listservs, l, entry);
	bbs_debug(3, "Added listserv mapping %s => %s\n", l->name, l->target);
	RWLIST_UNLOCK(&listservs);
}

const char *mailbox_expand_list(const char *listname)
{
	struct listserv *l;

	RWLIST_RDLOCK(&listservs);
	RWLIST_TRAVERSE(&listservs, l, entry) {
		if (!strcmp(l->name, listname)) {
			break;
		}
	}
	if (!l) {
		RWLIST_UNLOCK(&listservs);
		return NULL;
	}
	RWLIST_UNLOCK(&listservs);
	return l->target; /* l cannot be removed until mod_mail is unloaded, at which point its dependents would no longer be running, so this is safe. */
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
static struct mailbox *mailbox_find_or_create(unsigned int userid, const char *name)
{
	struct mailbox *mbox;

	if (!userid && strlen_zero(name)) {
		bbs_error("Can't create mailbox for user ID %u\n", userid); /* Probably a bug somewhere else */
		return NULL;
	}

	RWLIST_WRLOCK(&mailboxes);
	RWLIST_TRAVERSE(&mailboxes, mbox, entry) {
		if ((userid && mbox->id == userid) || (!userid && mbox->name && !strcmp(name, mbox->name))) {
			break;
		}
	}
	if (!mbox) {
		char newdirname[265];
		bbs_debug(3, "Creating mailbox for user %u for the first time\n", userid);
		mbox = calloc(1, sizeof(*mbox));
		if (ALLOC_FAILURE(mbox)) {
			RWLIST_UNLOCK(&mailboxes);
			return NULL;
		}
		pthread_rwlock_init(&mbox->lock, NULL);
		pthread_mutex_init(&mbox->uidlock, NULL);
		mbox->id = userid;
		if (name) {
			mbox->name = strdup(name);
		}
		if (userid) {
			snprintf(mbox->maildir, sizeof(mbox->maildir), "%s/%u", maildir, userid);
		} else {
			snprintf(mbox->maildir, sizeof(mbox->maildir), "%s/%s", maildir, name);
		}
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
		char mboxpath[256];
		if (strlen_zero(name)) {
			bbs_error("Must specify at least either a user ID or name\n");
			return NULL;
		}
		/* Check for mailbox with this name, explicitly (e.g. shared mailboxes) */
		snprintf(mboxpath, sizeof(mboxpath), "%s/%s", mailbox_maildir(NULL), name);
		if (!eaccess(mboxpath, R_OK)) {
			mbox = mailbox_find_or_create(0, name);
		}
		if (!mbox) {
			/* New mailboxes could be created while the module is running (e.g. new user registration), so we may have to query the DB anyways. */
			userid = bbs_userid_from_username(name);
		}
	}

	/* If we had a user ID or were able to translate the name to one, lookup the mailbox by user ID. */
	if (userid) {
		bbs_debug(5, "Found mailbox mapping via username directly\n");
		mbox = mailbox_find_or_create(userid, NULL);
	}

	/* If we still don't have a valid mailbox at this point, see if it's an alias. */
	if (!mbox && !strlen_zero(name)) {
		userid = resolve_alias(name);
		if (userid) {
			bbs_debug(5, "Found mailbox mapping via alias\n");
			mbox = mailbox_find_or_create(userid, NULL);
		}
	}

	if (!mbox && !s_strlen_zero(catchall)) {
		static int catch_all_userid = 0; /* This won't change, so until we having caching of user ID to usernames in the core, don't look this up again after we find a match. */
		if (!catch_all_userid) {
			catch_all_userid = bbs_userid_from_username(catchall);
		}
		if (catch_all_userid) {
			bbs_debug(5, "Found mailbox mapping via catch all\n");
			mbox = mailbox_find_or_create(catch_all_userid, NULL);
		} else {
			bbs_warning("No user exists for catch all mailbox '%s'\n", catchall); /* If a catch all address was explicitly specified, it was probably intended that it works. */
		}
	}

	if (!mbox && !strlen_zero(name)) {
		bbs_debug(5, "No user or alias exists for %s\n", name);
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

void mailbox_watch(struct mailbox *mbox)
{
	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	mbox->watchers += 1;
	mailbox_uid_unlock(mbox);
}

void mailbox_unwatch(struct mailbox *mbox)
{
	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	mbox->watchers -= 1;
	mailbox_uid_unlock(mbox);
}

void mailbox_notify(struct mailbox *mbox, const char *newfile)
{
	struct stat st;

	if (stat(newfile, &st)) {
		mailbox_invalidate_quota_cache(mbox);
	} else {
		mailbox_quota_adjust_usage(mbox, st.st_size);
	}

	if (!mbox->watchers) {
		return; /* Nobody is watching the mailbox right now, so no need to bother notifying any watchers. */
	}

	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	mbox->activity = 1;
	mailbox_uid_unlock(mbox);

	if (watchcallback) {
		bbs_module_ref(watchmod);
		watchcallback(mbox, newfile);
		bbs_module_unref(watchmod);
	}
}

int mailbox_has_activity(struct mailbox *mbox)
{
	int res;
	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	res = mbox->activity;
	mbox->activity = 0; /* If it was, we ate it */
	mailbox_uid_unlock(mbox);
	return res;
}

void mailbox_invalidate_quota_cache(struct mailbox *mbox)
{
	bbs_debug(5, "Cached quota usage for mailbox %d has been invalidated\n", mailbox_id(mbox));
	mbox->quotavalid = 0; /* No lock needed since a race condition here wouldn't have any effect. */
}

void mailbox_quota_adjust_usage(struct mailbox *mbox, int bytes)
{
	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	if (mbox->quotavalid) {
		mbox->quotausage += bytes;
		if (unlikely(mbox->quotausage > mailbox_quota(mbox))) {
			/* Could also happen if we underflow below 0, since quotausage is unsigned */
			/* Either our adjustments to the cached value went off somewhere, or we didn't check the quota somewhere. Either way, somebody screwed up. */
			bbs_error("Mailbox quota usage (%u) exceeds quota allowed (%lu)\n", mbox->quotausage, mailbox_quota(mbox));
			mailbox_invalidate_quota_cache(mbox);
		}
	}
	mailbox_uid_unlock(mbox);
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

	if (mbox->quotavalid) {
		/* Use the cached quota calculations if mailbox usage hasn't really changed */
		return (unsigned long) (quota - mbox->quotausage);
	}

	quotaused = bbs_dir_size(mailbox_maildir(mbox));
	if (quotaused < 0) {
		/* An error occured, so we have no idea how much space is used.
		 * Err on the side of assuming no quota for now. */
		bbs_warning("Unable to calculate quota usage for mailbox %p\n", mbox);
		return quota;
	}
	mbox->quotausage = quotaused;
	mbox->quotavalid = 1; /* This can be cached until invalidated again */
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

	/* In case this maildir has never been accessed before */
	mailbox_maildir_init(path);

	fd = open(buf, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		bbs_error("open(%s) failed: %s\n", buf, strerror(errno));
	}
	return fd;
}

unsigned int mailbox_get_next_uid(struct mailbox *mbox, const char *directory, int allocate, unsigned int *newuidvalidity, unsigned int *newuidnext)
{
	FILE *fp = NULL;
	char uidfile[256];
	unsigned int uidvalidity = 0, uidnext = 0;

	/* If the directory is not executable, any files created will be owned by root, which is bad.
	 * We won't be able to write to these files, and mailbox corruption will ensue. */
	if (eaccess(directory, X_OK)) {
		if (chmod(directory, 0700)) {
			bbs_error("chmod(%s) failed: %s\n", directory, strerror(errno));
		}
	}

	/* A single file that stores the UIDVALIDITY and UIDNEXT for this folder.
	 * We can't use a single file since the UIDNEXT for each directory has to be unique.
	 * We probably wouldn't want to use the same UIDVALIDITY globally either for the entire mailbox,
	 * as invalidating one folder would have to invalidate all of them.
	 * So we do it per folder, and since we don't have a data structure for individual mailbox folders,
	 * just the top-level mailbox structure for the entire mailbox,
	 * we have to read and write from disk every time.
	 *
	 * The impact of this is hopefully limited since UIDs are only allocated once per message anyways.
	 */
	snprintf(uidfile, sizeof(uidfile), "%s/.uidvalidity", directory);

	mailbox_uid_lock(mbox);
	/* In theory, since fp will only be accessed atomically, we could leave fp open for writing
	 * while the module is running.
	 * In practice, clients could have many folders, so if even with 100 users with 10 folders each,
	 * that's 1000 file descriptors open, all the time, while the BBS is running, with very little benefit.
	 * Just open and close the files as needed. */
	if (eaccess(uidfile, R_OK)) {
		bbs_debug(3, "No UID file yet exists for directory %s\n", directory);
		fp = fopen(uidfile, "w"); /* Nothing to read, open write only */
		if (!fp) {
			bbs_error("fopen(%s) failed: %s\n", uidfile, strerror(errno));
		}
	} else {
		/* If it exists, we better be able to write to this file, too. */
		if (eaccess(uidfile, W_OK)) {
			bbs_error("UID file %s is readable but not writable!\n", uidfile);
			/* Well, this is awkward.
			 * The only sane thing we can really do is invalidate all the UIDs
			 * and start over at this point.
			 *
			 * Note that we are allowed to reset HIGHESTMODSEQ whenever we reset UIDVALIDITY.
			 * However, we do not currently do so, and UIDVALIDITY should never be reset
			 * in a correct implementation, anyways.
			 */
		} else {
			fp = fopen(uidfile, "r+"); /* Open for reading and writing */
			if (!fp) {
				bbs_error("fopen(%s) failed: %s\n", uidfile, strerror(errno));
			} else {
				char uidv[32] = "";
				char *uidvaliditystr, *tmp = uidv;
				if (!fgets(uidv, sizeof(uidv), fp) || !uidv[0]) {
					bbs_error("Failed to read UID from %s (read: %s)\n", uidfile, uidv);
				} else if (!(uidvaliditystr = strsep(&tmp, "/")) || !(uidvalidity = atoi(uidvaliditystr)) || !(uidnext = atoi(tmp))) {
					/* If we create a maildir but don't do anything yet, uidnext will be 0.
					 * So !atoi isn't a sufficient check as it may have successfully parsed 0.
					 */
					if (!tmp || *tmp != '0') {
						bbs_error("Failed to parse UIDVALIDITY/UIDNEXT from %s (%s/%s)\n", uidfile, S_IF(uidvaliditystr), S_IF(tmp));
					}
				}
				rewind(fp);
			}
		}
	}

	if (!fp || !uidvalidity || !uidnext) {
		/* UIDVALIDITY must be strictly increasing, so time is a good thing to use. */
		uidvalidity = time(NULL); /* If this isn't the first access to this folder, this will invalidate the client's cache of this entire folder. */
		/* Since we're starting over, we must broadcast the new UIDVALIDITY value (we always do for SELECTs). */
	}

	/* See RFC 3501 2.3.1.1. The next UID must be at least UIDNEXT, but it could be greater than it, too. */
	if (allocate) {
		uidnext++; /* Increment and write back */
	} /* else, we just wanted to read the current values */
	/* uidnext is now the current max UID.
	 * Admittedly, this can be confusing here (the now clunky API for this function doesn't help matters, either)
	 * Say we read 11 from the .uidvalidity file.
	 * This means that no message has a UID greater than 11, including the current one.
	 * If we're allocating in this function (assigning and incrementing), then we'll want to write 12 into .uidvalidity and reutnr that.
	 * So depending on what we're referring to, the right answer is 11 or 12. */

	/* Write updated UID to persistent storage. It's super important that this succeed. */
	if (likely(fp != NULL)) {
		if (fprintf(fp, "%u/%u", uidvalidity, uidnext) < 0) { /* Would need to do if we created the directory anyways */
			bbs_error("Failed to write data to UID file\n");
		}
		fflush(fp);
		if (fclose(fp)) {
			bbs_error("fclose(%s) failed: %s\n", uidfile, strerror(errno));
		}
	}

	if (allocate) {
		bbs_debug(5, "Assigned UIDNEXT %u (UIDVALIDITY %u) - current max UID: %d\n", uidnext, uidvalidity, uidnext);
	} else {
		bbs_debug(8, "Current max UID: %d\n", uidnext);
	}

	/* These are only valid for this folder: */
	*newuidvalidity = uidvalidity;
	*newuidnext = uidnext;
	mailbox_uid_unlock(mbox);
	return uidnext;
}

static unsigned long __maildir_modseq(struct mailbox *mbox, const char *directory, int increment)
{
	unsigned long max_modseq = 0;
	char modseqfile[256];
	FILE *fp;
	long unsigned int res;

	UNUSED(mbox); /* Not currently used, but could be useful for future caching strategies? */

	/* Use a separate file from .uidvalidity for simplicity and ease of parsing, since this file is going to get used a lot more than the uidvalidity file
	 * Also, since this file may be very large, since it needs to permanently store the MODSEQ of every single expunged message, forever.
	 * For this reason, and for ease and speed of modifying the file in place, this is also a binary file, NOT a text file. */
	snprintf(modseqfile, sizeof(modseqfile), "%s/../.modseqs", directory); /* Go up one directory, since we're in the cur directory, but file is stored in the maildir root */

	/* If the file doesn't yet exist, scan the directory */
	if (!bbs_file_exists(modseqfile)) {
		DIR *dir;
		struct dirent *entry;
		const char *modseq;
		/* Order of traversal does not matter, so use opendir instead of scandir for efficiency. */
		if (!(dir = opendir(directory))) {
			bbs_error("Error opening directory - %s: %s\n", directory, strerror(errno));
			return 0;
		}

		while ((entry = readdir(dir)) != NULL) {
			unsigned long cur;
			if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
				continue;
			}
			modseq = strstr(entry->d_name, ",M=");
			if (!modseq) {
				/* For backwards compatibility, since MODSEQ was not initially present,
				 * tolerate maildir files that don't have a M= component.
				 * However, at some point, whenever they are modified, a M= component
				 * will need to be inserted into the filename.
				 * For now, just treat it as 0 (never modified, which is true, at least since we started tracking). */
				continue;
			}
			modseq += STRLEN(",M=");
			/* UIDs are 32-bit integers according to the IMAP RFCs, so an int is sufficiently large.
			 * This still provides over ~2 billion possible messages in a single mailbox folder (unlikely to be realized in the real world).
			 * There could conceivably be a much larger number of modifications than that, however, to a folder over time.
			 * MODSEQ is 63/64 bit (originally 64-bit in RFC 4551, changed to 63-bit in RFC 7162)
			 * So we use an unsigned long for just these, and not for any UID related numbers. */
			cur = atol(modseq);
			if (cur > max_modseq) {
				max_modseq = cur;
			}
		}
		closedir(dir);
		if (!max_modseq) {
			max_modseq = 1; /* Must be at least 1 */
		}
		fp = fopen(modseqfile, "wb");
		if (likely(fp != NULL)) {
			fwrite(&max_modseq, sizeof(unsigned long), 1, fp);
			fclose(fp);
		}
		return max_modseq;
	}

	fp = fopen(modseqfile, "rb+");
	if (unlikely(fp == NULL)) {
		bbs_error("Failed to open %s\n", modseqfile);
		/* There is no sane thing to do at this point. */
		return 0; /* This is not a correct behavior */
	}

	res = fread(&max_modseq, sizeof(unsigned long), 1, fp); /* Returns number of elements, not bytes (so should be 1) */
	if (res != 1) {
		bbs_error("Error reading HIGHESTMODSEQ from %s\n", modseqfile);
		/* No sane thing we can do here either */
		return 0;
	}

	if (increment) {
		max_modseq += 1;
		rewind(fp);
		/* Update new value */
		fwrite(&max_modseq, sizeof(unsigned long), 1, fp);
	}

	fclose(fp);
	return max_modseq;
}

unsigned long maildir_indicate_expunged(struct mailbox *mbox, const char *directory, unsigned int *uids, int length)
{
	char modseqfile[256];
	unsigned long maxmodseq;
	FILE *fp;
	long pos;
	int created, i;
#ifdef VERIFY_MODSEQ_INTEGRITY
	int res;
#endif

	/* Increment HIGHESTMODSEQ by 1.
	 * We CAN use the same MODSEQ for all the expunged messages, if there are multiple. MODSEQ does not have to be unique. */
	mailbox_uid_lock(mbox);
	maxmodseq = __maildir_modseq(mbox, directory, 1); /* Must be atomic */

	snprintf(modseqfile, sizeof(modseqfile), "%s/../.modseqs", directory);
	fp = fopen(modseqfile, "wb");
	if (!fp) {
		bbs_error("Failed to open %s\n", modseqfile);
		mailbox_uid_unlock(mbox);
		return maxmodseq;
	}

	/* We need to also store all the expunged message UIDs and MODSEQs, indefinitely,
	 * to fulfill RFC 7162 3.2.7
	 * RFC 7162 Section 5.3 has some pertinent recommendations on this:
	 * - this state should be persistent, but is not required to be (we make it persistent indefinitely)
	 * - RFC cautions that indefinite storage could cause storage issues (64 GB in worst case, though this is far from likely)
	 * - We could expire old MODSEQ values if needed to keep storage under control (subject to implementation, see the RFC)
	 */

	/* Check if we created the file or opened an existing one by getting our position.
	 * If the file is empty, write HIGHESTMODSEQ first, then the expunged messages.
	 * Otherwise, append all the expunged messages, then seek back to the beginning and overwrite HIGHESTMODSEQ. */
	fseek(fp, -1, SEEK_END);
	pos = ftell(fp);
	bbs_debug(7, "Current position is %ld\n", pos);
	created = pos == 0;
	if (created) {
		fwrite(&maxmodseq, sizeof(unsigned long), 1, fp);
	}
	for (i = 0; i < length; i++) {
		if (!uids[i]) {
			bbs_error("Invalid UID at index %d\n", i);
			continue;
		}
		fwrite(&uids[i], sizeof(unsigned int), 1, fp);
		fwrite(&maxmodseq, sizeof(unsigned long), 1, fp);
		bbs_debug(6, "Added %u/%lu to expunge log\n", uids[i], maxmodseq);
	}
	if (!created) {
		rewind(fp);
		fwrite(&maxmodseq, sizeof(unsigned long), 1, fp);
		bbs_debug(6, "Updated HIGHESTMODSEQ to %lu\n", maxmodseq);
	}

	fclose(fp); /* Flush changes before releasing the lock */
	mailbox_uid_unlock(mbox);

/* Enable this to automatically check the file for corruption after writing */
/* See also the standalone MODSEQ dump utility in external/modseqdecode */
#ifdef VERIFY_MODSEQ_INTEGRITY
	fp = fopen(modseqfile, "r");
	if (!fp) {
		return maxmodseq;
	}
	res = fread(&maxmodseq, sizeof(unsigned long), 1, fp);
	if (res != 1 || !maxmodseq) {
		bbs_error("MODSEQ corruption detected: missing HIGHESTMODSEQ\n");
	}
	for (;;) {
		unsigned int uid;
		res = fread(&uid, sizeof(unsigned int), 1, fp);
		if (res != 1) {
			break;
		}
		if (!uid) {
			bbs_debug(6, "Detected UID %u, stopping\n", uid);
			/* Sometimes (often), it seems that 0 can crop in at the end of a file,
			 * even though we never wrote one explicitly.
			 * Not really sure why that happens, but be tolerant of it. */
			break; /* If we get a UID of 0, just stop */
		}
		res = fread(&modseq, sizeof(unsigned long), 1, fp);
		if (res != 1) {
			bbs_error("MODSEQ corruption detected: MODSEQ file contains UID %u with no corresponding MODSEQ (possible corruption)\n", uid);
			break;
		}
		if (!uid) {
			bbs_error("MODSEQ corruption detected: UID is 0 for MODSEQ %lu?\n", modseq);
		}
		if (!modseq) {
			bbs_error("MODSEQ corruption detected: UID %u's MODSEQ is 0?\n", uid);
		}
	}
	fclose(fp);
#endif
	return maxmodseq;
}

unsigned long maildir_max_modseq(struct mailbox *mbox, const char *directory)
{
	return __maildir_modseq(mbox, directory, 0);
}

unsigned long maildir_new_modseq(struct mailbox *mbox, const char *directory)
{
	unsigned long modseq;
	mailbox_uid_lock(mbox);
	modseq = __maildir_modseq(mbox, directory, 1); /* Must be atomic */
	mailbox_uid_unlock(mbox);
	return modseq;
}

int maildir_move_new_to_cur(struct mailbox *mbox, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext)
{
	return maildir_move_new_to_cur_file(mbox, dir, curdir, newdir, filename, uidvalidity, uidnext, NULL, 0);
}

int maildir_move_new_to_cur_file(struct mailbox *mbox, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext, char *newpath, size_t len)
{
	char oldname[256];
	char newname[272];
	struct stat st;
	int bytes;
	unsigned int uid;
	unsigned int newuidvalidity, newuidnext;

	snprintf(oldname, sizeof(oldname), "%s/%s", newdir, filename);

	/* dovecot adds a couple pieces of info as well to optimize future access
	 * since it can get relevant info right from the filename, rather than needing to use stat(2)
	 * https://doc.dovecot.org/admin_manual/mailbox_formats/maildir/
	 * Since this is a one-time operation, this is an excellent time to do this kind of thing,
	 * since nobody else even knows about this message yet.
	 *
	 * Additionally, we may as well create the UID at this point in time.
	 * mbsync(1) has a suggestion on a good way of doing this:
	 * "The native scheme is stolen from the latest Maildir patches to c-client and
	 * is therefore compatible with pine. The UID validity is stored in a file named .uidvalidity;
	 * the UIDs are encoded in the file names of the messages...
	 * The native scheme is faster, more space efficient, endianess independent and "human readable",
	 * but will be disrupted if a message is copied from another mailbox without getting a new file name;
	 * this would result in duplicated UIDs sooner or later, which in turn results in a UID validity change..."
	 *
	 * Our invariant is that no process outside of the BBS is allowed to manipulate the maildir directories,
	 * in particular, the cur directory (if adhering to our naming convention, adding files to new might be okay).
	 * If this is satisfied, UID corruption should not occur.
	 *
	 * Just as dovecot extends maildir by using S= to store size, use U= to store the UID of this file.
	 */
	if (stat(oldname, &st)) {
		bbs_error("stat(%s) failed: %s\n", oldname, strerror(errno));
		return -1;
	}
	bytes = st.st_size;

	/* XXX Calling this once per every file, if there are a lot of files, is not efficient.
	 * Would be better to read the file at the beginning of the directory traversal,
	 * update in memory only as we traverse the directory, and then write the final value
	 * to the file and close it after the traversal ends. */
	uid = mailbox_get_next_uid(mbox, dir, 1, &newuidvalidity, &newuidnext);
	if (!uid) {
		return -1; /* Don't continue if we failed to get a UID */
	}
	if (uidvalidity) {
		*uidvalidity = newuidvalidity;
	}
	if (uidnext) {
		*uidnext = newuidnext; /* Should be same as uid as well */
	}

/* XXX maildir example shows S= and W= are different,
	 * but I'm not sure why the number of bytes in the file
	 * would not be st_size? So just use S= for now and skip W=. */
	snprintf(newname, sizeof(newname), "%s/%s,S=%d,U=%u,M=%lu:2,", curdir, filename, bytes, uid, maildir_max_modseq(mbox, curdir)); /* Add no flags now, but anticipate them being added */
	if (rename(oldname, newname)) {
		bbs_error("rename %s -> %s failed: %s\n", oldname, newname, strerror(errno));
		return -1;
	}
	if (newpath) {
		safe_strncpy(newpath, newname, len);
	}
	return bytes;
}

static int gen_newname(struct mailbox *mbox, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newpath, size_t newpathlen)
{
	char newname[156];
	unsigned int uid;
	unsigned int newuidvalidity, newuidnext;
	char *tmp;

	/* Keep all the message's flags when moving.
	 * The only thing we change is the UID.
	 * The message's old UID (from the original location) isn't (and cannot be) reused. It's just gone now. */

	/* If moving to .Trash, we do NOT set the Deleted flag.
	 * That is set by the client when it requests to delete messages from the Trash folder. */

	uid = mailbox_get_next_uid(mbox, destmaildir, 1, &newuidvalidity, &newuidnext);
	if (!uid) {
		bbs_error("Failed to allocate a UID for message\n");
		return -1; /* Failed to get a UID, don't move it */
	}
	if (uidvalidity) {
		*uidvalidity = newuidvalidity;
	}
	if (uidnext) {
		*uidnext = newuidnext; /* Should be same as uid as well */
	}

	safe_strncpy(newname, curfilename, sizeof(newname));
	tmp = strstr(newname, ",U=");
	if (tmp) { /* Message already had a UID (was in cur, as opposed to new) */
		unsigned long modseq;
		char curdir[256];
		char *next;
		/* Replace old UID with new UID */
		tmp += STRLEN(",U=");
		next = strchr(tmp, ':');
		*tmp++ = '\0';
		/* If it's moving folders, discard current MODSEQ as well and assign one based on new folder */
		snprintf(curdir, sizeof(curdir), "%s/cur", destmaildir);
		modseq = maildir_max_modseq(mbox, curdir);
		modseq++;
		/* Now, next points to the remainder of the filename. Need to do it this way and concatenate, since UIDs could be of different lengths */
		/* Move to cur, because messages in new are always inferred to be unseen, and would also get renamed again erroneously */
		snprintf(newpath, newpathlen, "%s/cur/%s%u,M=%lu%s", destmaildir, newname, uid, modseq, next);
	} else {
		bbs_error("Trying to move a message that had no previous UID?\n");
		return -1;
	}
	mailbox_maildir_init(destmaildir); /* Make sure the maildir is ready if it hasn't been used before */
	return uid;
}

int maildir_move_msg(struct mailbox *mbox, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext)
{
	return maildir_move_msg_filename(mbox, curfile, curfilename, destmaildir, uidvalidity, uidnext, NULL, 0);
}

int maildir_move_msg_filename(struct mailbox *mbox, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newfile, size_t len)
{
	char newpath[272];
	int uid;

	uid = gen_newname(mbox, curfilename, destmaildir, uidvalidity, uidnext, newpath, sizeof(newpath));
	if (uid <= 0) {
		return -1;
	}
	if (rename(curfile, newpath)) {
		bbs_error("rename %s -> %s failed: %s\n", curfile, newpath, strerror(errno));
		return -1;
	}
	bbs_debug(6, "Renamed %s -> %s\n", curfile, newpath);
	if (newfile) {
		safe_strncpy(newfile, newpath, len);
	}
	return uid;
}

int maildir_copy_msg(struct mailbox *mbox, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext)
{
	return maildir_copy_msg_filename(mbox, curfile, curfilename, destmaildir, uidvalidity, uidnext, NULL, 0);
}

int maildir_copy_msg_filename(struct mailbox *mbox, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newfile, size_t len)
{
	char newpath[272];
	unsigned int uid;
	int origfd, newfd;
	int size, copied;

	uid = gen_newname(mbox, curfilename, destmaildir, uidvalidity, uidnext, newpath, sizeof(newpath));
	if (!uid) {
		return -1;
	}

	newfd = open(newpath, O_WRONLY | O_CREAT, 0600);
	if (newfd < 0) {
		bbs_error("open(%s) failed: %s\n", newpath, strerror(errno));
		return -1;
	}

	origfd = open(curfile, O_RDONLY, 0600);
	if (origfd < 0) {
		bbs_error("open(%s) failed: %s\n", curfile, strerror(errno));
		close(newfd);
		return -1;
	}

	size = lseek(origfd, 0, SEEK_END); /* Don't blindly trust the size in the filename's S= */
	lseek(origfd, 0, SEEK_SET); /* rewind to beginning */

	copied = bbs_copy_file(origfd, newfd, 0, size);
	if (copied != size) {
		if (unlink(newpath)) {
			bbs_error("Failed to delete %s: %s\n", newpath, strerror(errno));
		}
		return -1;
	}
	bbs_debug(6, "Copied %s -> %s\n", curfile, newpath);
	if (newfile) {
		safe_strncpy(newfile, newpath, len);
	}
	/* Rather than invalidating quota usage for no reason, just update it so it stays in sync */
	mailbox_quota_adjust_usage(mbox, copied);
	return uid;
}

int maildir_parse_uid_from_filename(const char *filename, unsigned int *uid)
{
	char *uidstr = strstr(filename, ",U=");
	if (!uidstr) {
		return -1;
	}
	uidstr += STRLEN(",U=");
	if (!strlen_zero(uidstr)) {
		*uid = atoi(uidstr); /* Should stop as soon we encounter the first nonnumeric character, whether , or : */
		if (!*uid) {
			bbs_warning("Failed to parse UID for %s\n", filename);
			return -1;
		}
	} else {
		bbs_debug(5, "Filename %s does not contain a UID\n", filename);
		return -1;
	}
	return 0;
}

/*
 * maildir format: http://cr.yp.to/proto/maildir.html
 * also: http://www.courier-mta.org/maildir.html
 * and: https://www.courier-mta.org/imap/README.maildirquota.html
 * and: https://www.systutorials.com/docs/linux/man/2-gettimeofday/
 * Note that some information here is obsolete.
 * For exmaple, mkstemp safely returns a unique temporary filename.
 */

static int on_mailbox_trash(const char *dir_name, const char *filename, void *obj)
{
	struct stat st;
	char fullname[256];
	int tstamp;
	int trashsec = 86400 * trashdays;
	int elapsed, now = time(NULL);
	int mboxnum, *boxptr;
	struct mailbox *mbox = NULL;
	unsigned int msguid;

	boxptr = obj;
	mboxnum = *boxptr;

	/* For autopurging, we don't care if the Deleted flag is set or not.
	 * (If it were set, an IMAP user already flagged it for permanent deletion and it would just be awaiting expunge) */

	snprintf(fullname, sizeof(fullname), "%s/%s", dir_name, filename);
	if (stat(fullname, &st)) {
		bbs_error("stat(%s) failed: %s\n", fullname, strerror(errno));
		return 0;
	}
	tstamp = st.st_ctime;
	elapsed = now - tstamp;
	bbs_debug(7, "Encountered in trash: %s (%d s ago)\n", fullname, elapsed);
	if (elapsed > trashsec) {
		if (unlink(fullname)) {
			bbs_error("unlink(%s) failed: %s\n", fullname, strerror(errno));
		} else {
			bbs_debug(4, "Permanently deleted %s\n", fullname);
			mbox = mailbox_get(mboxnum, NULL);
			if (likely(mbox != NULL)) {
				mailbox_quota_adjust_usage(mbox, -st.st_size); /* Subtract file size from quota usage */
			}
		}
		maildir_parse_uid_from_filename(filename, &msguid);
		/*! \todo Since many messages are probably deleted at the same time,
		 * it would be more efficient to store a list of message UIDs deleted
		 * and pass them to this function at once at the end.
		 * Not as critical as in net_imap though since this is a background task.
		 */
		maildir_indicate_expunged(mbox, dir_name, &msguid, 1);
	}
	return 0;
}

static void scan_mailboxes(void)
{
	DIR *dir;
	struct dirent *entry;
	char trashdir[515];
	int mboxnum;

	/* Traverse each mailbox top-level maildir */
	if (!(dir = opendir(maildir))) {
		bbs_error("Error opening directory - %s: %s\n", maildir, strerror(errno));
		return;
	}
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		mboxnum = atoi(entry->d_name);
		if (!mboxnum) {
			continue; /* Ignore non-numeric directories, these are other things (e.g. mailq) */
		}
		snprintf(trashdir, sizeof(trashdir), "%s/%s/.Trash/cur", maildir, entry->d_name);
		if (eaccess(trashdir, R_OK)) {
			bbs_debug(2, "Directory %s doesn't exist?\n", trashdir); /* It should if it's a maildir we created, unless user has never accessed it yet. */
			continue;
		}
		bbs_debug(3, "Analyzing trash folder %s\n", trashdir);
		bbs_dir_traverse(trashdir, on_mailbox_trash, &mboxnum, -1); /* Traverse files in the Trash folder */
	}

	closedir(dir);
}

static void *trash_monitor(void *unused)
{
	UNUSED(unused);
	for (;;) {
		scan_mailboxes();
		/* Not necessary to run more frequently than once per hour. */
		sleep(60 * 60); /* use sleep instead of usleep since the argument to usleep would overflow an int */
	}
	return NULL;
}

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
	bbs_config_val_set_uint(cfg, "general", "trashdays", &trashdays);

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
		} else if (!strcmp(bbs_config_section_name(section), "lists")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
				add_listserv(key, value);
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
	mailbox_cleanup();
	return 0;
}

BBS_MODULE_INFO_FLAGS("E-Mail Resource", MODFLAG_GLOBAL_SYMBOLS);
