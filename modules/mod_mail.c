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
 * \note Supports RFC 5423 Message Store Events
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h> /* use dirname */
#include <sys/time.h> /* struct timeval for musl */

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/config.h"
#include "include/node.h" /* use bbs_hostname */
#include "include/user.h"
#include "include/auth.h"
#include "include/utils.h"
#include "include/oauth.h"
#include "include/base64.h"
#include "include/stringlist.h"
#include "include/range.h"
#include "include/cli.h"
#include "include/callback.h"

#include "include/mod_mail.h"

static char root_maildir[248] = "";
static char catchall[256] = "";
static unsigned int maxquota = 10000000;

struct stringlist local_domains;

/*! \brief Opaque structure for a user's mailbox */
struct mailbox {
	unsigned int id;					/* Mailbox ID. Corresponds with user ID. */
	unsigned int watchers;				/* Number of watchers for this mailbox. */
	unsigned int quota;					/* Total quota for this mailbox */
	unsigned int quotausage;			/* Cached quota usage calculation */
	char maildir[266];					/* User's mailbox directory, on disk. */
	size_t maildirlen;					/* Length of maildir */
	bbs_rwlock_t lock;					/* R/W lock for entire mailbox. R/W instead of a mutex, because POP write locks the entire mailbox, IMAP can just read lock. */
	bbs_mutex_t uidlock;				/* Mutex for UID operations. */
	bbs_mutex_t proxylock;				/* Mutex for proxy client access */
	RWLIST_ENTRY(mailbox) entry;		/* Next mailbox */
	unsigned int activity:1;			/* Mailbox has activity */
	unsigned int quotavalid:1;			/* Whether cached quota calculations may still be used */
	unsigned int overquota:1;			/* Cached determination of being over quota (to compare later) */
	char *name;
};

/* Once created, mailboxes are not destroyed until module unload,
 * so reference counting is not needed. It is safe to return
 * mailboxes unlocked and use them in the net modules,
 * since they bump the refcount of this module itself. */
static RWLIST_HEAD_STATIC(mailboxes, mailbox);

int smtp_domain_matches(const char *domain, const char *addr)
{
	if (*addr == '[') {
		size_t domainlen;
		/* Domain literal */
		addr++;
		if (strlen_zero(addr)) {
			return 0;
		}
		domainlen = strlen(domain);
		if (strncmp(domain, addr, domainlen)) {
			return 0;
		}
		addr += domainlen;
		if (*addr != ']') {
			return 0;
		}
		addr++;
		return strlen_zero(addr); /* Should be the end of that now */
	} else {
		/* Domains are case-insensitive */
		return !strcasecmp(domain, addr);
	}
}

int mail_domain_is_local(const char *domain)
{
	if (strlen_zero(domain)) {
		return 1;
	}
	if (smtp_domain_matches(bbs_hostname(), domain)) {
		return 1;
	}
	if (stringlist_case_contains(&local_domains, domain)) { /* Domains are case-insensitive */
		return 1;
	}
	bbs_debug(5, "Domain '%s' is not local\n", domain);
	return 0;
}

struct mailbox_watcher {
	void (*watchcallback)(struct mailbox_event *event);
	void *watchmod;
	RWLIST_ENTRY(mailbox_watcher) entry;
};

static RWLIST_HEAD_STATIC(watchers, mailbox_watcher);

int __mailbox_register_watcher(void (*callback)(struct mailbox_event *event), void *mod)
{
	struct mailbox_watcher *w;

	w = calloc(1, sizeof(*w));
	if (ALLOC_FAILURE(w)) {
		return -1;
	}

	w->watchcallback = callback;
	w->watchmod = mod;

	RWLIST_WRLOCK(&watchers);
	RWLIST_INSERT_HEAD(&watchers, w, entry);
	RWLIST_UNLOCK(&watchers);
	return 0;
}

int mailbox_unregister_watcher(void (*callback)(struct mailbox_event *event))
{
	struct mailbox_watcher *w;

	RWLIST_WRLOCK(&watchers);
	RWLIST_TRAVERSE_SAFE_BEGIN(&watchers, w, entry) {
		if (w->watchcallback == callback) {
			RWLIST_REMOVE_CURRENT(entry);
			free(w);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&watchers);

	if (!w) {
		bbs_error("Mailbox watcher %p not currently registered\n", callback);
		return -1;
	}

	return 0;
}

const char *mailbox_event_type_name(enum mailbox_event_type type)
{
	switch (type) {
		case EVENT_MESSAGE_APPEND:
			return "MessageAppend";
		case EVENT_MESSAGE_EXPIRE:
			return "MessageExpire";
		case EVENT_MESSAGE_EXPUNGE:
			return "MessageExpunge";
		case EVENT_MESSAGE_NEW:
			return "MessageNew";
		case EVENT_QUOTA_EXCEED:
			return "QuotaExceed";
		case EVENT_QUOTA_WITHIN:
			return "QuotaChange";
		case EVENT_QUOTA_CHANGE:
			return "QuotaChange";
		case EVENT_MESSAGE_READ:
			return "MessageRead";
		case EVENT_MESSAGE_TRASH:
			return "MessageTrash";
		case EVENT_FLAGS_SET:
			return "FlagsSet";
		case EVENT_FLAGS_CLEAR:
			return "FlagsClear";
		case EVENT_LOGIN:
			return "Login";
		case EVENT_LOGOUT:
			return "Logout";
		case EVENT_MAILBOX_CREATE:
			return "MailboxCreate";
		case EVENT_MAILBOX_DELETE:
			return "MailboxDelete";
		case EVENT_MAILBOX_RENAME:
			return "MailboxRename";
		case EVENT_MAILBOX_SUBSCRIBE:
			return "MailboxSubscribe";
		case EVENT_MAILBOX_UNSUBSCRIBE:
			return "MailboxUnsubscribe";
		case EVENT_METADATA_CHANGE:
			return "MetadataChange";
		case EVENT_SERVER_METADATA_CHANGE:
			return "ServerMetadataChange";
		case EVENT_ANNOTATION_CHANGE:
			return "AnnotationChange";
		case EVENT_MAILBOX_UIDVALIDITY_CHANGE:
			return "UIDVALIDITYChange";
		/* No default case */
	}
	__builtin_unreachable();
}

static bbs_mutex_t eventidlock = BBS_MUTEX_INITIALIZER;
static unsigned long next_eventid = 0;

void mailbox_dispatch_event(struct mailbox_event *event)
{
	struct mailbox_watcher *w;

	bbs_mutex_lock(&eventidlock);
	event->id = ++next_eventid;
	bbs_mutex_unlock(&eventidlock);

	/* Sanity checks */
	bbs_assert(!event->uids || event->numuids > 0); /* If we provided UIDs, then we must specify how many */
	bbs_assert(!event->maildir || event->maildir[0] == '/'); /* This is supposed to be a full path, not relative */

	bbs_debug(6, "Dispatching mailbox event '%s' (maildir: %s)\n", mailbox_event_type_name(event->type), S_IF(event->maildir));
	if (!strlen_zero(event->maildir)) {
		mailbox_maildir_validate(event->maildir);
	}

	/* At this point in time, we have an event,
	 * with all the information that was "free" for the caller to provide.
	 * e.g. If the caller already knew the MODSEQ, it should be filled in,
	 * but if not, no effort has been made to fill in missing information.
	 * If events request information that we don't have,
	 * we can go and fetch that information as needed,
	 * but otherwise, there's no point in doing the work up front, potentially needlessly. */

	time(&event->timestamp);

	if (event->node) {
		if (!strcmp(event->node->protname, "IMAP") || !strcmp(event->node->protname, "POP3")) {
			event->messageaccess = 1;
		}
	}

	RWLIST_RDLOCK(&watchers);
	RWLIST_TRAVERSE(&watchers, w, entry) {
		bbs_module_ref(w->watchmod, 1);
		w->watchcallback(event);
		bbs_module_unref(w->watchmod, 1);
	}
	RWLIST_UNLOCK(&watchers);
}

void mailbox_initialize_event(struct mailbox_event *e, enum mailbox_event_type type, struct bbs_node *node, struct mailbox *mbox, const char *maildir)
{
	memset(e, 0, sizeof(struct mailbox_event));
	e->type = type;
	e->node = node;
	e->mbox = mbox;
	e->maildir = maildir;
}

void mailbox_dispatch_event_basic(enum mailbox_event_type type, struct bbs_node *node, struct mailbox *mbox, const char *maildir)
{
	struct mailbox_event e;
	mailbox_initialize_event(&e, type, node, mbox, maildir);
	mailbox_dispatch_event(&e);
}

void mailbox_notify_new_message(struct bbs_node *node, struct mailbox *mbox, const char *maildir, const char *newfile, size_t size)
{
	struct mailbox_event e;
	struct stat st;

	/* Update mailbox quota to account for new message.
	 * We don't do this for APPEND in net_imap, since we update the quota for each message when processed. */
	if (stat(newfile, &st)) {
		mailbox_invalidate_quota_cache(mbox);
	} else {
		mailbox_quota_adjust_usage(mbox, (int) st.st_size);
	}
	/* Set activity on this mailbox */
	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	mbox->activity = 1;
	mailbox_uid_unlock(mbox);

	/*! \todo FIXME RFC 5423 4.1 says MessageNew MUST provide both UIDVALIDITY and UID.
	 * UIDVALIDITY could be done easily, but we currently have no way of providing a UID.
	 * This is because UIDs are not assigned until a maildir-reading process (net_imap) moves messages
	 * from the new subdir to the cur subdir of the maildir.
	 * Thus, there is literally no UID assigned at this point in time we can provide.
	 * We also can't "speculate" what the UID will be. Further messages could be appended to the mailbox
	 * between now and when the messages are moved to cur, so even if the ordering of moving messages
	 * from new to cur was deterministic, that still wouldn't help.
	 * What we *could* do is, if any subscribers (IMAP clients, specifically) want the UID attribute
	 * for a MessageNew event, implicitly move the message from new to cur NOW, which will assign it a UID.
	 * Otherwise, there is really no good workaround. */

	mailbox_initialize_event(&e, EVENT_MESSAGE_NEW, node, mbox, maildir);
	e.msgsize = size;
	mailbox_dispatch_event(&e);
}

void mailbox_notify_quota_exceeded(struct bbs_node *node, struct mailbox *mbox)
{
	struct mailbox_event e;

	/* The quota should already be cached for this mailbox (since we just calculated we're over it),
	 * so calling mailbox_quota_remaining and mailbox_quota are not expensive.
	 * However, we don't need to call them here and cache it on the event,
	 * we can just get it in realtime as needed. */

	mailbox_initialize_event(&e, EVENT_QUOTA_EXCEED, node, mbox, NULL);
	mailbox_dispatch_event(&e);
}

static int use_mailbox_for_event(struct mailbox_event *e)
{
	if (!e->mbox || !e->maildir) {
		bbs_error("No mailbox and/or maildir\n");
		return 0;
	} else if (e->type == EVENT_MAILBOX_DELETE) {
		bbs_debug(3, "Mailbox has been deleted\n");
		return 0;
	}
	/* Certain types of mailbox events don't require that the mailbox actually needs to exist.
	 * In particular, SUBSCRIBE and UNSUBSCRIBE could be for arbitrary mailboxes,
	 * and those mailboxes may or may not exist. */
	if (e->type == EVENT_MAILBOX_SUBSCRIBE || e->type == EVENT_MAILBOX_UNSUBSCRIBE) {
		return 0;
	}
	return 1;
}

unsigned int mailbox_event_uidvalidity(struct mailbox_event *e)
{
	if (!e->uidvalidity) {
		if (!use_mailbox_for_event(e)) {
			return 0;
		}
		mailbox_get_next_uid(e->mbox, e->node, e->maildir, 0, &e->uidvalidity, &e->uidnext);
	}
	return e->uidvalidity;
}

unsigned int mailbox_event_uidnext(struct mailbox_event *e)
{
	if (!e->uidnext) {
		if (!use_mailbox_for_event(e)) {
			return 0;
		}
		mailbox_get_next_uid(e->mbox, e->node, e->maildir, 0, &e->uidvalidity, &e->uidnext);
	}
	return e->uidnext;
}

int mailbox_has_activity(struct mailbox *mbox)
{
	int res;

	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	/* XXX A problem with this is that mailbox_has_activity will apply to all folders in an account, even if *this* maildir hasn't changed... */
	res = mbox->activity;
	mbox->activity = 0; /* If it was, we ate it */
	mailbox_uid_unlock(mbox);
	return res;
}

BBS_SINGULAR_CALLBACK_DECLARE(sieve_validate, int, const char *filename, struct mailbox *mbox, char **errormsg);
static char *sieve_capabilities = NULL; /* Additional callback data not handled by singular callback interface */

int __sieve_register_provider(int (*validate)(const char *filename, struct mailbox *mbox, char **errormsg), char *capabilities, void *mod)
{
	int res;
	if (strlen_zero(capabilities)) {
		bbs_error("Missing capabilities\n");
		return -1;
	}
	res = bbs_singular_callback_register(&sieve_validate, validate, mod);
	if (!res) {
		sieve_capabilities = capabilities; /* Steal the reference */
	} else {
		free(capabilities);
	}
	return res;
}

int sieve_unregister_provider(int (*validate)(const char *filename, struct mailbox *mbox, char **errormsg))
{
	int res = bbs_singular_callback_unregister(&sieve_validate, validate);
	if (!res) {
		FREE(sieve_capabilities);
	}
	return res;
}

char *sieve_get_capabilities(void)
{
	char *caps;

	/* Technically not safe to just return directly, since the module could go away while we're using it?
	 * So duplicate it and return that. */

	if (bbs_singular_callback_execute_pre(&sieve_validate)) {
		bbs_error("No Sieve implementation is currently registered\n");
		return NULL;
	}
	caps = strdup(sieve_capabilities);
	bbs_singular_callback_execute_post(&sieve_validate);
	return caps;
}

int sieve_validate_script(const char *filename, struct mailbox *mbox, char **errormsg)
{
	int res;
	if (bbs_singular_callback_execute_pre(&sieve_validate)) {
		bbs_error("No Sieve implementation is currently registered\n");
		return -1;
	}
	res = BBS_SINGULAR_CALLBACK_EXECUTE(sieve_validate)(filename, mbox, errormsg);
	bbs_singular_callback_execute_post(&sieve_validate);
	return res;
}

/* E-Mail Address Alias */
struct alias {
	int userid;
	const char *aliasuser;
	const char *aliasdomain;
	const char *target;
	RWLIST_ENTRY(alias) entry;		/* Next alias */
	char data[];
};

static RWLIST_HEAD_STATIC(aliases, alias);

static void mailbox_free(struct mailbox *mbox)
{
	bbs_rwlock_destroy(&mbox->lock);
	bbs_mutex_destroy(&mbox->uidlock);
	bbs_mutex_destroy(&mbox->proxylock);
	free_if(mbox->name);
	free(mbox);
}

static void mailbox_cleanup(void)
{
	/* Clean up mailboxes */
	RWLIST_WRLOCK_REMOVE_ALL(&mailboxes, entry, mailbox_free);
	RWLIST_WRLOCK_REMOVE_ALL(&aliases, entry, free);
	stringlist_empty_destroy(&local_domains);
}

/*!
 * \brief Retrieve the user ID of the mailbox to which an alias maps
 * \retval alias mapping, NULL if none
 */
static const char *resolve_alias(const char *user, const char *domain)
{
	const char *retval = NULL;
	struct alias *alias;

	/* Note that we do not look for the most explicit match,
	 * just for a match. For this reason, *@example.com
	 * should always be defined in the config BEFORE
	 * anything else at the domain (and * should be first, if present),
	 * since we add using head insert, so the first things will be
	 * last and thus if a more specific match exists, we would have
	 * encountered it first. */

	RWLIST_RDLOCK(&aliases);
	RWLIST_TRAVERSE(&aliases, alias, entry) {
		int user_match;
		if (!strcmp(alias->aliasuser, "*")) {
			user_match = 1; /* Match like '*@example.com' */
		} else if (!strcasecmp(alias->aliasuser, "postmaster")) {
			/* RFC 5321 4.5.1: postmaster match must be case-insensitive.
			 * All other matches could be case-sensitive,
			 * but we also make them case-insensitively for compatibility. */
			user_match = !strcasecmp(user, "postmaster");
		} else {
			user_match = !strcasecmp(alias->aliasuser, user); /* Explicit user match */
		}
		if (!user_match) {
			continue;
		}
		/* Unqualified match, or domain must match */
		if (!alias->aliasdomain || (domain && !strcasecmp(alias->aliasdomain, domain))) {
			retval = alias->target; /* Safe to return in practice since aliases cannot be unloaded while the module is running */
			break;
		}
	}
	RWLIST_UNLOCK(&aliases);
	return retval;
}

/*! \note domain must be initialized to NULL before calling this function */
static void parse_user_domain(char *restrict buf, size_t len, const char *restrict address, char **restrict user, char **restrict domain)
{
	safe_strncpy(buf, address, len);
	*user = buf;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	*domain = (char*) bbs_strcnext(buf, '@');
#pragma GCC diagnostic pop
	if (*domain && *domain > *user) {
		*(*domain - 1) = '\0';
	}
}

static void add_alias(const char *aliasname, const char *target)
{
	struct alias *alias;
	size_t aliaslen, domainlen, targetlen;
	char aliasbuf[256];
	char *aliasuser, *aliasdomain = NULL;

	if (strlen_zero(target)) {
		bbs_error("Empty translation for alias %s\n", aliasname);
		return;
	}

	parse_user_domain(aliasbuf, sizeof(aliasbuf), aliasname, &aliasuser, &aliasdomain);

	RWLIST_WRLOCK(&aliases);
	RWLIST_TRAVERSE(&aliases, alias, entry) {
		if (!strcmp(alias->aliasuser, aliasuser)) {
			if (!alias->aliasdomain) { /* Unqualified alias matches any domain */
				break;
			} else if (aliasdomain && !strcmp(alias->aliasdomain, aliasdomain)) { /* Explicit domain match */
				break;
			}
		}
	}
	if (alias) {
		bbs_warning("Alias %s already mapped to mailbox %s\n", alias->aliasuser, alias->target);
		RWLIST_UNLOCK(&aliases);
		return;
	}
	aliaslen = strlen(aliasuser);
	domainlen = aliasdomain ? strlen(aliasdomain) : 0;
	targetlen = strlen(target);
	alias = calloc(1, sizeof(*alias) + aliaslen + domainlen + targetlen + 3);
	if (ALLOC_FAILURE(alias)) {
		RWLIST_UNLOCK(&aliases);
		return;
	}

	strcpy(alias->data, aliasuser);
	strcpy(alias->data + aliaslen + 1, target);
	if (aliasdomain) {
		strcpy(alias->data + aliaslen + targetlen + 2, aliasdomain);
		alias->aliasdomain = alias->data + aliaslen + targetlen + 2;
	}
	alias->aliasuser = alias->data;
	/* Store the actual target name directly, instead of converting to a username immediately, since mod_mysql might not be loaded when the config is parsed.
	 * Also, we can have aliases resolve to non-user mailboxes, e.g. shared mailboxes. */
	alias->target = alias->data + aliaslen + 1;
	alias->userid = 0; /* Not known yet, will get the first time we access this. */
	RWLIST_INSERT_HEAD(&aliases, alias, entry);
	bbs_debug(3, "Added alias mapping %s%s%s => %s\n", alias->aliasuser, alias->aliasdomain ? "@" : "", S_IF(alias->aliasdomain), alias->target);
	RWLIST_UNLOCK(&aliases);
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
		char newdirname[277];
		bbs_debug(3, "Loading mailbox for user %u for the first time\n", userid);
		mbox = calloc(1, sizeof(*mbox));
		if (ALLOC_FAILURE(mbox)) {
			RWLIST_UNLOCK(&mailboxes);
			return NULL;
		}
		bbs_rwlock_init(&mbox->lock, NULL);
		bbs_mutex_init(&mbox->uidlock, NULL);
		bbs_mutex_init(&mbox->proxylock, NULL);
		mbox->id = userid;
		if (name) {
			mbox->name = strdup(name);
		}
		if (userid) {
			snprintf(mbox->maildir, sizeof(mbox->maildir), "%s/%u", root_maildir, userid);
		} else {
			snprintf(mbox->maildir, sizeof(mbox->maildir), "%s/%s", root_maildir, name);
		}
		mbox->maildirlen = strlen(mbox->maildir);
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
		bbs_ensure_directory_exists(newdirname);
		snprintf(newdirname, sizeof(newdirname), "%s/.%s", mbox->maildir, "Junk");
		bbs_ensure_directory_exists(newdirname);
		snprintf(newdirname, sizeof(newdirname), "%s/.%s", mbox->maildir, "Sent");
		bbs_ensure_directory_exists(newdirname);
		snprintf(newdirname, sizeof(newdirname), "%s/.%s", mbox->maildir, "Trash");
		bbs_ensure_directory_exists(newdirname);
		/* Skip All and Flagged (virtual folders) */
		/* Skip Archive */
	}
	RWLIST_UNLOCK(&mailboxes);
	return mbox;
}

static struct mailbox *mailbox_get(unsigned int userid, const char *user, const char *domain, int include_catchall)
{
	char mboxpath[256];
	struct mailbox *mbox = NULL;

	/* If we have a user ID, use that directly. */
	if (!userid && (!domain || smtp_domain_matches(bbs_hostname(), domain))) { /* Only for primary domain */
		char userpart[64];
		if (strlen_zero(user)) {
			bbs_error("Must specify at least either a user ID or name\n");
			return NULL;
		}
		if (strchr(user, '+')) {
			/* Email subaddressing, using the plus symbol. Ignore the subaddress portion for the lookup.
			 * Many mail servers support this convention to allow for users to use implicit aliases. */
			bbs_strncpy_until(userpart, user, sizeof(userpart), '+');
			user = userpart;
		}
		/* Check for mailbox with this name, explicitly (e.g. shared mailboxes) */
		snprintf(mboxpath, sizeof(mboxpath), "%s/%s", mailbox_maildir(NULL), user);
		if (!eaccess(mboxpath, R_OK)) {
			mbox = mailbox_find_or_create(0, user);
		}
		if (!mbox) {
			/* New mailboxes could be created while the module is running (e.g. new user registration), so we may have to query the DB anyways. */
			userid = bbs_userid_from_username(user);
		}
	}

	/* If we had a user ID or were able to translate the name to one, look up the mailbox by user ID. */
	if (userid) {
		bbs_debug(5, "Found mailbox mapping via username directly\n");
		mbox = mailbox_find_or_create(userid, NULL);
	}

	/* If we still don't have a valid mailbox at this point, see if it's an alias. */
	if (!mbox && !strlen_zero(user)) {
		const char *target = resolve_alias(user, domain);
		if (target) {
			bbs_debug(5, "Resolved alias '%s%s%s' => mailbox %s\n", user, domain ? "@" : "", S_IF(domain), target);
			/* The alias could resolve to a shared mailbox, for example, not necessarily a user,
			 * so take advantage of the existing lookup strategy for that. */
			snprintf(mboxpath, sizeof(mboxpath), "%s/%s", mailbox_maildir(NULL), target);
			if (!eaccess(mboxpath, R_OK)) {
				mbox = mailbox_find_or_create(0, target);
			}
			if (!mbox) {
				/* New mailboxes could be created while the module is running (e.g. new user registration), so we may have to query the DB anyways. */
				userid = bbs_userid_from_username(target); /* These are cached so not super terrible to look up every time... */
			}
			if (!userid) {
				bbs_warning("Alias target '%s' cannot be resolved\n", target);
			} else {
				mbox = mailbox_find_or_create(userid, NULL);
			}
		}
	}

	if (!mbox && !s_strlen_zero(catchall) && include_catchall) {
		static unsigned int catch_all_userid = 0; /* This won't change, so until we having caching of user ID to usernames in the core, don't look this up again after we find a match. */
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

	if (!mbox && !strlen_zero(user)) {
		bbs_debug(5, "No user or alias exists for %s%s%s\n", user, domain ? "@" : "", S_IF(domain));
	}
	return mbox;
}

struct mailbox *mailbox_get_by_name(const char *user, const char *domain)
{
	return mailbox_get(0, user, domain, 1);
}

static int mailbox_exists_by_username(const char *user)
{
	/* Exclude catch-all, so we can see if it really exists or not */
	return mailbox_get(0, user, NULL, 0) ? 1 : 0;
}

struct mailbox *mailbox_get_by_userid(unsigned int userid)
{
	return mailbox_get(userid, NULL, NULL, 1);
}

int mailbox_rdlock(struct mailbox *mbox)
{
	bbs_assert_exists(mbox);
	return bbs_rwlock_tryrdlock(&mbox->lock);
}

int mailbox_wrlock(struct mailbox *mbox)
{
	bbs_assert_exists(mbox);
	return bbs_rwlock_trywrlock(&mbox->lock);
}

void mailbox_unlock(struct mailbox *mbox)
{
	bbs_assert_exists(mbox);
	bbs_rwlock_unlock(&mbox->lock);
}

int mailbox_uid_lock(struct mailbox *mbox)
{
	bbs_assert_exists(mbox);
	return bbs_mutex_lock(&mbox->uidlock);
}

void mailbox_uid_unlock(struct mailbox *mbox)
{
	bbs_assert_exists(mbox);
	bbs_mutex_unlock(&mbox->uidlock);
}

int mailbox_proxy_trylock(struct mailbox *mbox)
{
	bbs_assert_exists(mbox);
	return bbs_mutex_trylock(&mbox->proxylock);
}

void mailbox_proxy_unlock(struct mailbox *mbox)
{
	bbs_assert_exists(mbox);
	bbs_mutex_unlock(&mbox->proxylock);
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

void mailbox_invalidate_quota_cache(struct mailbox *mbox)
{
	bbs_debug(5, "Cached quota usage for mailbox %d has been invalidated\n", mailbox_id(mbox));
	mbox->quotavalid = 0; /* No lock needed since a race condition here wouldn't have any effect. */
}

void mailbox_quota_adjust_usage(struct mailbox *mbox, int bytes)
{
	mailbox_uid_lock(mbox); /* Borrow the UID lock since we need to do this atomically */
	if (mbox->quotavalid) {
		mbox->quotausage += (unsigned int) bytes;
		if (mbox->quotausage > mailbox_quota(mbox)) {
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
	char quotafile[256];
	char quotabuf[256];
	FILE *fp;

	if (mbox->quota) {
		return mbox->quota; /* At this point, this value is read only */
	}

	/* This only needs to be done once for any given mailbox. */
	snprintf(quotafile, sizeof(quotafile), "%s/.quota", mailbox_maildir(mbox));
	fp = fopen(quotafile, "r");
	if (fp && fgets(quotabuf, sizeof(quotabuf), fp)) { /* Use the default */
		mbox->quota = (unsigned int) atoi(quotabuf);
		fclose(fp);
	} else {
		mbox->quota = (unsigned int) maxquota;
		if (fp) {
			fclose(fp);
		}
	}
	return mbox->quota;
}

unsigned long mailbox_quota_used(struct mailbox *mbox)
{
	unsigned long quotaused;
	long tmp;

	if (mbox->quotavalid) {
		/* Use the cached quota calculations if mailbox usage hasn't really changed */
		return mbox->quotausage;
	}

	tmp = bbs_dir_size(mailbox_maildir(mbox));
	if (tmp < 0) {
		/* An error occured, so we have no idea how much space is used. */
		bbs_warning("Unable to calculate quota usage for mailbox %p\n", mbox);
		return 0;
	}
	quotaused = (unsigned long) tmp;
	mbox->quotausage = (unsigned int) quotaused;
	mbox->quotavalid = 1; /* This can be cached until invalidated again */
	return quotaused;
}

unsigned long mailbox_quota_remaining(struct mailbox *mbox)
{
	unsigned long quota, quotaused;
	long tmp;

	quota = mailbox_quota(mbox);

	if (mbox->quotavalid) {
		/* Use the cached quota calculations if mailbox usage hasn't really changed */
		if (quota > mbox->quotausage) {
			return quota - mbox->quotausage;
		}
		bbs_debug(5, "No quota remaining in this mailbox (%u used, %lu available)\n", mbox->quotausage, quota);
		return 0; /* Already over quota */
	}

	tmp = bbs_dir_size(mailbox_maildir(mbox));
	if (tmp < 0) {
		/* An error occured, so we have no idea how much space is used.
		 * Err on the side of assuming no quota for now. */
		bbs_warning("Unable to calculate quota usage for mailbox %p\n", mbox);
		return quota;
	}
	quotaused = (unsigned long) tmp;
	mbox->quotausage = (unsigned int) quotaused;
	mbox->quotavalid = 1; /* This can be cached until invalidated again */
	if (quotaused >= quota) {
		bbs_debug(5, "No quota remaining in this mailbox (%lu used, %lu available)\n", quotaused, quota);
		mbox->overquota = 1;
		return 0; /* Quota already exceeded. Don't cast to unsigned or it will underflow and be huge. */
	}
	quota -= quotaused;
	return (unsigned long) (quota - quotaused);
}

#define MAX_UID 4294967295

unsigned long mailbox_max_messages(struct mailbox *mbox)
{
	UNUSED(mbox);
	/* XXX Currently we do not really support limits on the number of messages
	 * in a mailbox (though we probably should)
	 * The absolute max is the highest possible UID, so it will never be more than that. */
	return MAX_UID;
}

int mailbox_maildir_init(const char *path)
{
	char buf[256];
	int res = 0;

	res |= bbs_ensure_directory_exists(path);
	snprintf(buf, sizeof(buf), "%s/new", path);
	res |= bbs_ensure_directory_exists(buf);
	snprintf(buf, sizeof(buf), "%s/cur", path);
	res |= bbs_ensure_directory_exists(buf);
	snprintf(buf, sizeof(buf), "%s/tmp", path);
	res |= bbs_ensure_directory_exists(buf);

	return res;
}

int maildir_is_mailbox(const char *basename)
{
	if (!strcmp(basename, "mailq") || !strcmp(basename, "lists")) {
		return 0;
	}
	/* Otherwise, if it's a numeric directory, it's a user's personal mailbox,
	 * and if it's not, then it's a named shared mailbox. */
	return 1;
}

const char *mailbox_maildir(struct mailbox *mbox)
{
	if (!mbox) {
		return root_maildir;
	}
	return mbox->maildir;
}

#define CHECK_MAILDIR_LEN_INTEGRITY

size_t mailbox_maildir_len(struct mailbox *mbox)
{
#ifdef CHECK_MAILDIR_LEN_INTEGRITY
	if (bbs_assertion_failed(strlen(mbox->maildir) == mbox->maildirlen)) {
		bbs_warning("maildir length mismatch: %lu != %lu\n", strlen(mbox->maildir), mbox->maildirlen);
	}
#endif
	return mbox->maildirlen;
}

int mailbox_maildir_validate(const char *maildir)
{
	size_t dirlen = maildir ? strlen(maildir) : 0;
	size_t rootmaildirlen = strlen(mailbox_maildir(NULL));

	if (!dirlen) {
		return 0;
	}
	if (bbs_assertion_failed(dirlen > rootmaildirlen)) {
		bbs_warning("maildir (%s) len (%lu) <= maildir root (%s) len (%lu)?\n", maildir, dirlen, mailbox_maildir(NULL), rootmaildirlen);
		return -1;
	}
	return 0;
}

int mailbox_id(struct mailbox *mbox)
{
	return (int) mbox->id;
}

const char *mailbox_name(struct mailbox *mbox)
{
	return mbox->name;
}

int mailbox_uniqueid(struct mailbox *mbox, char *buf, size_t len)
{
	/* We need a unique prefix based on the mailbox.
	 * All mailboxes either have an ID or have a name. */
	if (mbox->id) {
		snprintf(buf, len, "%u", mbox->id);
	} else if (mbox->name) {
		safe_strncpy(buf, mbox->name, len);
	} else {
		return -1;
	}
	return 0;
}

int maildir_mktemp(const char *path, char *buf, size_t len, char *newbuf)
{
	struct timeval tvnow;
	struct stat st;
	int fd;

	for (;;) {
#pragma GCC diagnostic ignored "-Waggregate-return"
		tvnow = bbs_tvnow();
#pragma GCC diagnostic pop
		snprintf(buf, len, "%s/tmp/%lu%06lu", path, tvnow.tv_sec, tvnow.tv_usec);
		snprintf(newbuf, len, "%s/new/%lu%06lu", path, tvnow.tv_sec, tvnow.tv_usec);
		if (stat(buf, &st) == -1 && errno == ENOENT) {
			/* Error means it doesn't exist. */
			if (stat(newbuf, &st) == -1 && errno == ENOENT) {
				break;
			}
		}
		usleep(100 + (unsigned int) bbs_rand(1, 25));
	}

	/* In case this maildir has never been accessed before */
	mailbox_maildir_init(path);

	fd = open(buf, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		bbs_error("open(%s) failed: %s\n", buf, strerror(errno));
	}
	return fd;
}

static int parse_uidfile(FILE *fp, const char *uidfile, unsigned int *uidvalidity, unsigned int *uidnext, int *ascii)
{
	/* Because .uidvalidity was originally a plain text file,
	 * prefer to parse it as binary, but if that fails, fall back to parsing as plain text,
	 * so this remains backwards compatible. */
	char c;
	char uidv[32] = "";
	char *uidvaliditystr, *tmp;

	if (fread(uidvalidity, sizeof(unsigned int), 1, fp) != 1) {
		bbs_debug(2, "Failed to read UIDVALIDITY from %s: %s (empty file?)\n", uidfile, strerror(errno)); /* If we just created the file, it's empty, so this could happen */
		return 1;
	} else if (fread(uidnext, sizeof(unsigned int), 1, fp) != 1) {
		bbs_error("Failed to read UID from %s\n", uidfile);
		return -1; /* Can't be a text file, because that would have more bytes than the binary version, not fewer */
	}

	/* If this is a binary file, the next byte is 3. Verify that. */
	if (fread(&c, sizeof(char), 1, fp) != 1) {
		bbs_error("Failed to read byte from %s\n", uidfile);
		return -1; /* Ditto */
	}
	if (c == 3) {
		/* It was in binary format */
		return 0;
	}

	/* It's still in plain text format. */
	bbs_debug(4, "%s is still in ASCII format (c == %d)\n", uidfile, c);
	*ascii = 1;
	rewind(fp);

	tmp = uidv;
	if (!fgets(uidv, sizeof(uidv), fp) || !uidv[0]) {
		bbs_error("Failed to read UID from %s (read: %s)\n", uidfile, uidv);
		return -1;
	} else if (!(uidvaliditystr = strsep(&tmp, "/")) || !(*uidvalidity = (unsigned int) atoi(uidvaliditystr)) || !(*uidnext = (unsigned int) atoi(tmp))) {
		/* If we create a maildir but don't do anything yet, uidnext will be 0.
		 * So !atoi isn't a sufficient check as it may have successfully parsed 0.
		 */
		if (!tmp || *tmp != '0') {
			bbs_error("Failed to parse UIDVALIDITY/UIDNEXT from %s (%s/%s)\n", uidfile, S_IF(uidvaliditystr), S_IF(tmp));
			return -1;
		}
	}

	return 0;
}

unsigned int mailbox_get_next_uid(struct mailbox *mbox, struct bbs_node *node, const char *directory, int allocate, unsigned int *newuidvalidity, unsigned int *newuidnext)
{
	FILE *fp = NULL;
	char uidfile[256];
	int uidvchange = 0, uidfile_existed = 1;
	unsigned int uidvalidity = 0, uidnext = 0;
	int ascii = 0;

	/* If the directory is not executable, any files created will be owned by root, which is bad.
	 * We won't be able to write to these files, and mailbox corruption will ensue. */
	if (eaccess(directory, X_OK)) {
		if (chmod(directory, 0700)) {
			bbs_error("chmod(%s) failed: %s\n", directory, strerror(errno));
		}
	}

	/* This should be a subdirectory of the root maildir,
	 * as there shouldn't be a UID file in that directory. */
	mailbox_maildir_validate(directory);

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

	/* There is no fopen mode that actually does what we want.
	 * We would like to open the file for reading and writing (but not appending), without truncating, creating if needed.
	 * a+ is close, but forces writes to append. You can't write to existing bytes.
	 * w+ is close, but truncates the file when opened.
	 * r+ is close, but doesn't create the file if needed.
	 *
	 * Ultimately, the best thing to do here is try opening with r+ first.
	 * If that fails, then create the file and reopen with r+. */

	fp = fopen(uidfile, "r+"); /* Open for reading and writing, don't truncate it, and create if it doesn't exist */
	if (!fp) {
		/* Assume the file doesn't yet exist. */
		uidfile_existed = bbs_file_exists(uidfile);
		fp = fopen(uidfile, "a");
		if (unlikely(!fp)) { /* Don't use bbs_assertion_failed, because we want to preserve errno */
			bbs_error("fopen(%s) failed: %s\n", uidfile, strerror(errno));
			bbs_soft_assert(0);
		} else {
			fclose(fp);
			/* Now, the file should exist. Reopen it (it'll be empty) */
			fp = fopen(uidfile, "r+");
			if (unlikely(!fp)) {
				bbs_error("fopen(%s) failed: %s\n", uidfile, strerror(errno));
			}
		}
		/* If fp is still NULL here, this is awkward.
		 * The only sane thing we can really do is invalidate all the UIDs
		 * and start over at this point.
		 *
		 * Note that we are allowed to reset HIGHESTMODSEQ whenever we reset UIDVALIDITY.
		 * However, we do not currently do so, and UIDVALIDITY should never be reset
		 * in a correct implementation, anyways.
		 */
	}

	if (likely(fp != NULL)) {
		/* At this point, the file is open and it's readable and writable. */
		parse_uidfile(fp, uidfile, &uidvalidity, &uidnext, &ascii);
	}

	if (!uidvalidity || !fp) { /* uidnext can be 0 here */
		struct stat st;
		/* If there's no uidvalidity currently, not a big deal, that's expected and we'll create one now.
		 * If there is one and we failed, then this is really, really bad. */
		if (uidfile_existed) {
			bbs_error("Couldn't read already existing uidvalidity file (%s)\n", uidfile);
		}
		if (!stat(uidfile, &st)) {
			if (st.st_size > 0) {
				bbs_error("Failed to read current UID file %s\n", uidfile);
			} else if (uidfile_existed) {
				bbs_debug(3, "File %s is currently empty\n", uidfile);
			}
		} else {
			bbs_debug(3, "Failed to stat(%s): %s\n", uidfile, strerror(errno));
		}
		/* UIDVALIDITY must be strictly increasing, so time is a good thing to use. */
		uidvalidity = (unsigned int) time(NULL); /* If this isn't the first access to this folder, this will invalidate the client's cache of this entire folder. */
		/* Since we're starting over, we must broadcast the new UIDVALIDITY value (we always do for SELECTs). */
		if (allocate) {
			uidvchange = 1; /* Don't do this if !allocate, or we could recurse if callbacks try to read the current UIDVALIDITY */
		}
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
	if (ascii || !fp) {
		/* If it was an ASCII file, we'll want to reopen with mode 'w',
		 * to truncate the file, since otherwise if the new file is smaller,
		 * there would be old bytes leftover at the end otherwise.
		 * This isn't very efficient, but thankfully we'll only do it a maximum of once per mailbox.
		 * If we failed to open the file before, we can always try creating it now.
		 * We don't need to read anything, so w is sufficient, w+ isn't needed. */
		if (fp) {
			fclose(fp);
		}
		fp = fopen(uidfile, "w+"); /* If it's ASCII, we're going to call parse_uid again to verify it's not anymore, so need to be readable too */
		if (unlikely(!fp)) {
			bbs_error("fopen(%s) failed: %s\n", uidfile, strerror(errno));
		}
	} else {
		rewind(fp);
	}
	if (likely(fp != NULL)) {
		/* Always write back to the file in the binary format. UIDVALIDITY first, then UIDNEXT. */
		char c = 3; /* This is binary, so it will never appear in an ASCII file */
		if (ascii) {
			bbs_verb(5, "Converting %s from ASCII to binary format\n", uidfile);
		}
		if (fwrite(&uidvalidity, sizeof(unsigned int), 1, fp) != 1 || fwrite(&uidnext, sizeof(unsigned int), 1, fp) != 1 || fwrite(&c, sizeof(char), 1, fp) != 1) {
			bbs_error("Failed to write data to UID file %s\n", uidfile); /* Would need to do if we created the directory anyways */
		}
		if (ascii) { /* It was previously a text file but should now be binary */
			/* Check that the conversion happened correctly. */
			unsigned int a, b;
			rewind(fp);
			ascii = 0;
			parse_uidfile(fp, uidfile, &a, &b, &ascii);
			if (ascii) {
				bbs_error("Failed to convert %s from ASCII to binary\n", uidfile);
			}
		}
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

	if (uidvchange && uidfile_existed) {
		/* Don't do this while mailbox UID lock is held, or we could cause a deadlock
		 * if an event callback is triggered that tries to grab that lock. */
		bbs_debug(2, "UIDVALIDITY has changed (UIDVALIDITY=%d,UIDNEXT=%d)\n", uidvalidity, uidnext);
		mailbox_dispatch_event_basic(EVENT_MAILBOX_UIDVALIDITY_CHANGE, node, mbox, directory);
	}

	return uidnext;
}

static unsigned long __maildir_modseq(struct mailbox *mbox, const char *directory, int increment)
{
	unsigned long max_modseq = 0;
	char modseqfile[256];
	FILE *fp;
	long unsigned int res;

	UNUSED(mbox); /* Not currently used, but could be useful for future caching strategies? */

	bbs_soft_assert(strchr(directory, '/') != NULL);

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
			if (errno != ENOENT) { /* If the directory hasn't been created yet, then there is no modseqs modification file, simple as that */
				bbs_error("Error opening directory '%s': %s\n", directory, strerror(errno));
			}
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
			cur = (unsigned long) atol(modseq);
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
		fclose(fp);
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

char *maildir_get_expunged_since_modseq_range(const char *directory, unsigned long lastmodseq, char *uidrangebuf, unsigned int minuid, const char *uidrange)
{
	return maildir_get_expunged_since_modseq(directory, lastmodseq, uidrangebuf, minuid, uidrange);
}

char *maildir_get_expunged_since_modseq(const char *directory, unsigned long lastmodseq, char *uidrangebuf, unsigned int minuid, const char *uidrange)
{
	char modseqfile[256];
	FILE *fp;
	unsigned long modseq;
	unsigned int uid;
	size_t res;
	unsigned int *a = NULL;
	int lengths = 0, allocsizes = 0;

	snprintf(modseqfile, sizeof(modseqfile), "%s/../.modseqs", directory);
	fp = fopen(modseqfile, "rb");
	if (!fp) {
		bbs_error("Failed to open %s\n", modseqfile);
		return NULL;
	}
	res = fread(&modseq, sizeof(unsigned long), 1, fp);
	if (res != 1) {
		bbs_error("Failed to read HIGHESTMODSEQ from %s\n", directory);
		fclose(fp);
		return NULL;
	}

	for (;;) {
		/* Note that this file is sorted by MODSEQ, not be UID */
		res = fread(&uid, sizeof(unsigned int), 1, fp);
		if (res != 1) {
			break;
		}
		res = fread(&modseq, sizeof(unsigned long), 1, fp);
		if (res != 1 || !uid) { /* Break early if UID is 0, see maildir_indicate_expunged */
			break;
		}
		if (uid < minuid) {
			continue;
		}
		if (modseq <= lastmodseq) {
			continue;
		}
		if (uidrange && !in_range_allocated(uidrange, (int) uid, uidrangebuf)) {
			continue;
		}
		uintlist_append(&a, &lengths, &allocsizes, uid);
	}

	fclose(fp);

	if (lengths) {
		char *str = gen_uintlist(a, lengths);
		free(a);
		return str;
	} else {
		return NULL;
	}
}

static void expire_expunge_event(enum mailbox_event_type type, struct bbs_node *node, struct mailbox *mbox, const char *curdir, unsigned int *uids, unsigned int *seqnos, int length, int silent, unsigned long maxmodseq)
{
	char buf[256];
	const char *maildir;
	struct mailbox_event e;

	/* Our callers all provide the curdir, and some don't have the maildir handy easily, so just create it here */
	safe_strncpy(buf, curdir, sizeof(buf));
	maildir = dirname(buf);

	mailbox_initialize_event(&e, type, node, mbox, maildir);
	e.uids = uids;
	e.seqnos = seqnos;
	e.numuids = length;
	e.modseq = maxmodseq;
	SET_BITFIELD(e.expungesilent, silent); /* Used by net_imap */
	mailbox_dispatch_event(&e);

	if (mbox->overquota && mailbox_quota_remaining(mbox) > 0) {
		/* We're no longer over quota. */
		mbox->overquota = 0;
		mailbox_initialize_event(&e, EVENT_QUOTA_WITHIN, node, mbox, NULL); /* No maildir needed for this event */
		mailbox_dispatch_event(&e);
	}
}

unsigned long maildir_indicate_expunged(enum mailbox_event_type type, struct bbs_node *node, struct mailbox *mbox, const char *directory, unsigned int *uids, unsigned int *seqnos, int length, int silent)
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

	bbs_soft_assert(strstr(directory, "/cur") != NULL); /* directory should be the curdir for this maildir, not the maildir itself */
	snprintf(modseqfile, sizeof(modseqfile), "%s/../.modseqs", directory);
	fp = fopen(modseqfile, "ab");
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
	 * Per fopen(3), when appending, stream is positioned at end of file.
	 * Thus, we can use the current file offset when opening the file to determine if we just created it
	 * (this assumes that we didn't create an empty file early, i.e. if the file existed it was non-empty).
	 * If the file is empty, write HIGHESTMODSEQ first, then the expunged messages.
	 * Otherwise, append all the expunged messages, then seek back to the beginning and overwrite HIGHESTMODSEQ. */
	if (fseek(fp, -1, SEEK_END)) {
		bbs_warning("fseek(%s) failed: %s\n", modseqfile, strerror(errno));
	}
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

	if (length) {
		expire_expunge_event(type, node, mbox, directory, uids, seqnos, length, silent, maxmodseq);
	}
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

int maildir_move_new_to_cur(struct mailbox *mbox, struct bbs_node *node, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext)
{
	return maildir_move_new_to_cur_file(mbox, node, dir, curdir, newdir, filename, uidvalidity, uidnext, NULL, 0);
}

int maildir_move_new_to_cur_file(struct mailbox *mbox, struct bbs_node *node, const char *dir, const char *curdir, const char *newdir, const char *filename, unsigned int *uidvalidity, unsigned int *uidnext, char *newpath, size_t len)
{
	char oldname[256];
	char newname[272];
	struct stat st;
	int bytes;
	int markseen;
	unsigned int uid;
	unsigned int newuidvalidity, newuidnext;

	snprintf(oldname, sizeof(oldname), "%s/%s", newdir, filename);

	/* This logic exists to handle net_smtp automatically saving Sent messages to the new directory
	 * (if this functionality is enabled by a filtering rule).
	 * Thus in the future, net_imap might find those and move them to cur.
	 * The messages need to have the Seen flag, which isn't added at the time net_smtp saves them,
	 * so we do it here, so that sent messages don't show up as unread.
	 */
	/*! \todo Once Sieve/MailScript filtering rules support adding flags to a message, we should
	 * remove this logic and let the user do that there (of course, this logic will need to be
	 * updated to apply those flags).
	 * This is so users can apply whatever arbitrary flags they want, at which point
	 * auto-applying the Seen flag no longer would make sense. */
	markseen = !strcmp(dir + mbox->maildirlen, "/.Sent");

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
	bytes = (int) st.st_size;

	/* XXX Calling this once per every file, if there are a lot of files, is not efficient.
	 * Would be better to read the file at the beginning of the directory traversal,
	 * update in memory only as we traverse the directory, and then write the final value
	 * to the file and close it after the traversal ends. */
	uid = mailbox_get_next_uid(mbox, node, dir, 1, &newuidvalidity, &newuidnext);
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
	snprintf(newname, sizeof(newname), "%s/%s,S=%d,U=%u,M=%lu:2,%s", curdir, filename, bytes, uid, maildir_max_modseq(mbox, curdir), markseen ? "S" : ""); /* Add no flags now, but anticipate them being added */
	if (rename(oldname, newname)) {
		bbs_error("rename %s -> %s failed: %s\n", oldname, newname, strerror(errno));
		return -1;
	}
	if (newpath) {
		safe_strncpy(newpath, newname, len);
	}
	bbs_debug(7, "Renamed %s -> %s%s\n", oldname, newname, markseen ? " (and auto-marked as Seen)" : "");
	return bytes;
}

static int gen_newname(struct mailbox *mbox, struct bbs_node *node, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newpath, size_t newpathlen)
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

	uid = mailbox_get_next_uid(mbox, node, destmaildir, 1, &newuidvalidity, &newuidnext);
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
	return (int) uid;
}

void maildir_extract_from_filename(char *restrict filename)
{
	char *tmp;

	tmp = strrchr(filename, '/'); /* filename can be mutiliated at this point */
	if (unlikely(!tmp)) {
		return;
	}
	*tmp = '\0'; /* Truncating once gets rid of the filename, need to do it again to get the maildir without /new or /cur at the end */
	/* Since we're already near the end of the string, it's more efficient to back up from here than start from the beginning a second time */
	while (tmp > filename && *tmp != '/') {
		tmp--;
	}
	*tmp = '\0';
}

static int copy_move_untagged_exists(struct bbs_node *node, struct mailbox *mbox, const char *newpath, size_t size)
{
	char maildir[256];

	safe_strncpy(maildir, newpath, sizeof(maildir));
	maildir_extract_from_filename(maildir);
	mailbox_notify_new_message(node, mbox, maildir, newpath, size);
	return 0;
}

int maildir_move_msg(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext)
{
	return maildir_move_msg_filename(mbox, node, curfile, curfilename, destmaildir, uidvalidity, uidnext, NULL, 0);
}

int maildir_move_msg_filename(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newfile, size_t len)
{
	char newpath[272];
	int uid;

	uid = gen_newname(mbox, node, curfilename, destmaildir, uidvalidity, uidnext, newpath, sizeof(newpath));
	if (uid <= 0) {
		return -1;
	}
	if (rename(curfile, newpath)) {
		bbs_error("rename %s -> %s failed: %s\n", curfile, newpath, strerror(errno));
		return -1;
	}
	bbs_debug(6, "Renamed %s -> %s\n", curfile, newpath);
	copy_move_untagged_exists(node, mbox, newpath, len);
	if (newfile) {
		safe_strncpy(newfile, newpath, len);
	}
	return uid;
}

int maildir_copy_msg(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext)
{
	return maildir_copy_msg_filename(mbox, node, curfile, curfilename, destmaildir, uidvalidity, uidnext, NULL, 0);
}

int maildir_copy_msg_filename(struct mailbox *mbox, struct bbs_node *node, const char *curfile, const char *curfilename, const char *destmaildir, unsigned int *uidvalidity, unsigned int *uidnext, char *newfile, size_t len)
{
	char newpath[272];
	unsigned int uid;
	int origfd, newfd;
	int size, copied;

	uid = (unsigned int) gen_newname(mbox, node, curfilename, destmaildir, uidvalidity, uidnext, newpath, sizeof(newpath));
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

	size = (int) lseek(origfd, 0, SEEK_END); /* Don't blindly trust the size in the filename's S= */
	lseek(origfd, 0, SEEK_SET); /* rewind to beginning */

	copied = bbs_copy_file(origfd, newfd, 0, size);
	close(origfd);
	close(newfd);
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
	copy_move_untagged_exists(node, mbox, newpath, len);
	return (int) uid;
}

int maildir_parse_uid_from_filename(const char *filename, unsigned int *uid)
{
	const char *uidstr = strstr(filename, ",U=");
	if (!uidstr) {
		return -1;
	}
	uidstr += STRLEN(",U=");
	if (!strlen_zero(uidstr)) {
		*uid = (unsigned int) atoi(uidstr); /* Should stop as soon we encounter the first nonnumeric character, whether , or : */
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

static int imap_client_parse_capabilities(struct bbs_tcp_client *client, int *capsptr)
{
	char *cur, *capstring;
	int caps = 0;

#define PARSE_CAPABILITY(name, flag) \
	else if (!strcmp(cur, name)) { \
		caps |= flag; \
	}
#define IGNORE_CAPABILITY(name) \
	else if (!strcmp(cur, name)) { }

	/* Enable any capabilities the client may have enabled. */
	capstring = strstr(client->buf, "* CAPABILITY ");
	if (capstring) {
		capstring += STRLEN("* CAPABILITY ");
	} else {
		capstring = strstr(client->buf, "[CAPABILITY ");
		if (capstring) {
			capstring += STRLEN("[CAPABILITY ");
			bbs_strterm(capstring, ']'); /* This is part of a larger response, don't parse anything after or including ] */
		}
	}
	if (strlen_zero(capstring)) {
		bbs_error("CAPABILITIES response doesn't contain capabilities? '%s'\n", client->buf);
		return -1;
	}
	bbs_debug(5, "Capabilities: %s\n", capstring);
	if (strlen_zero(capstring)) {
		return -1;
	}
	while ((cur = strsep(&capstring, " "))) { /* It's okay to consume the capabilities, nobody else needs them */
		if (strlen_zero(cur) || !strcmp(cur, "IMAP4rev1") || !strcmp(cur, "IMAP4")) {
			continue;
		}
		PARSE_CAPABILITY("IDLE", IMAP_CAPABILITY_IDLE)
		PARSE_CAPABILITY("CONDSTORE", IMAP_CAPABILITY_CONDSTORE)
		PARSE_CAPABILITY("ENABLE", IMAP_CAPABILITY_ENABLE)
		PARSE_CAPABILITY("QRESYNC", IMAP_CAPABILITY_QRESYNC)
		PARSE_CAPABILITY("SASL-IR", IMAP_CAPABILITY_SASL_IR)
		PARSE_CAPABILITY("LITERAL+", IMAP_CAPABILITY_LITERAL_PLUS)
		PARSE_CAPABILITY("LITERAL-", IMAP_CAPABILITY_LITERAL_MINUS)
		PARSE_CAPABILITY("AUTH=PLAIN", IMAP_CAPABILITY_AUTH_PLAIN)
		PARSE_CAPABILITY("AUTH=XOAUTH2", IMAP_CAPABILITY_AUTH_XOAUTH2)
		PARSE_CAPABILITY("ACL", IMAP_CAPABILITY_ACL)
		PARSE_CAPABILITY("QUOTA", IMAP_CAPABILITY_QUOTA)
		PARSE_CAPABILITY("LIST-EXTENDED", IMAP_CAPABILITY_LIST_EXTENDED)
		PARSE_CAPABILITY("SPECIAL-USE", IMAP_CAPABILITY_SPECIAL_USE)
		PARSE_CAPABILITY("LIST-STATUS", IMAP_CAPABILITY_LIST_STATUS)
		PARSE_CAPABILITY("STATUS=SIZE", IMAP_CAPABILITY_STATUS_SIZE)
		PARSE_CAPABILITY("UNSELECT", IMAP_CAPABILITY_UNSELECT)
		PARSE_CAPABILITY("SORT", IMAP_CAPABILITY_SORT)
		PARSE_CAPABILITY("THREAD=ORDEREDSUBJECT", IMAP_CAPABILITY_THREAD_ORDEREDSUBJECT)
		PARSE_CAPABILITY("THREAD=REFERENCES", IMAP_CAPABILITY_THREAD_REFERENCES)
		IGNORE_CAPABILITY("THREAD=REFS")
		PARSE_CAPABILITY("MOVE", IMAP_CAPABILITY_MOVE)
		PARSE_CAPABILITY("BINARY", IMAP_CAPABILITY_BINARY)
		PARSE_CAPABILITY("MULTIAPPEND", IMAP_CAPABILITY_MULTIAPPEND)
		/* Not currently used */
		IGNORE_CAPABILITY("UNAUTHENTICATE")
		IGNORE_CAPABILITY("QUOTA=RES-STORAGE")
		IGNORE_CAPABILITY("QUOTA=RES-MESSAGE")
		IGNORE_CAPABILITY("URLAUTH")
		IGNORE_CAPABILITY("APPENDLIMIT") /* Will pass through as needed, no need to do anything with it here */
		IGNORE_CAPABILITY("LOGIN-REFERRALS")
		IGNORE_CAPABILITY("SORT=DISPLAY")
		IGNORE_CAPABILITY("URL-PARTIAL")
		IGNORE_CAPABILITY("CATENATE")
		IGNORE_CAPABILITY("CONTEXT=SEARCH")
		IGNORE_CAPABILITY("SNIPPET=FUZZY")
		IGNORE_CAPABILITY("PREVIEW=FUZZY")
		IGNORE_CAPABILITY("SAVEDATE")
		IGNORE_CAPABILITY("NOTIFY")
		IGNORE_CAPABILITY("SPECIAL-USE")
		IGNORE_CAPABILITY("CHILDREN")
		IGNORE_CAPABILITY("NAMESPACE")
		IGNORE_CAPABILITY("ID")
		IGNORE_CAPABILITY("UIDPLUS")
		IGNORE_CAPABILITY("XLIST")
		IGNORE_CAPABILITY("I18NLEVEL=1")
		IGNORE_CAPABILITY("ANNOTATION")
		IGNORE_CAPABILITY("RIGHTS=")
		IGNORE_CAPABILITY("WITHIN")
		IGNORE_CAPABILITY("ESEARCH")
		IGNORE_CAPABILITY("ESORT")
		IGNORE_CAPABILITY("SEARCHRES")
		IGNORE_CAPABILITY("COMPRESS=DEFLATE")
		IGNORE_CAPABILITY("UTF8=ACCEPT")
		/* Esoteric Microsoft stuff, don't care */
		IGNORE_CAPABILITY("CLIENTACCESSRULES")
		IGNORE_CAPABILITY("CLIENTNETWORKPRESENCELOCATION")
		IGNORE_CAPABILITY("BACKENDAUTHENTICATE")
		IGNORE_CAPABILITY("BACKENDAUTHENTICATE-IR")
		else if (STARTS_WITH(cur, "X") || STARTS_WITH(cur, "AUTH=")) {
			/* Don't care */
		} else if (!strcmp(cur, "LOGINDISABLED")) { /* RFC 3501 7.2.1 */
			/* Could happen if we connect to a plain text port and STARTTLS is required.
			 * Here we only support implicit TLS */
			bbs_warning("IMAP server does not support login\n");
			return -1;
		} else if (STARTS_WITH(cur, "APPENDLIMIT=")) {
			/*! \todo This should be stored somewhere */
		} else {
			bbs_warning("Unknown IMAP capability: %s\n", cur);
		}
	}

#undef PARSE_CAPABILITY
#undef IGNORE_CAPABILITY

	*capsptr = caps;
	return 0;
}

int imap_client_login(struct bbs_tcp_client *client, struct bbs_url *url, struct bbs_user *user, int *capsptr)
{
	ssize_t res;
	int caps;
	char *encoded = NULL;
	int ok_had_caps = 0;

	/* Parse the server greeting until we get an untagged OK response,
	 * processing the CAPABILITIES if we get an untagged CAPABILITY response. */
	for (;;) {
		res = bbs_readline(client->rfd, &client->rldata, "\r\n", 2500);
		if (res <= 0) {
			bbs_warning("No response from IMAP server %s:%d?\n", url->host, url->port);
			return -1;
		}
		if (STARTS_WITH(client->buf, "* CAPABILITY")) {
			ok_had_caps = 1; /* Don't need to parse again until authenticated */
			if (imap_client_parse_capabilities(client, capsptr)) { /* Parse unauthenticated capabilities */
				return -1;
			}
		}
		if (STARTS_WITH(client->buf, "* OK")) {
			break;
		}
	}

	if (!ok_had_caps) {
		/* If the OK response contained capabilities, avoid an extra RTT to ask for something we already got. */
		ok_had_caps = strstr(client->buf, "[CAPABILITY") ? 1 : 0;
		/* Gmail will send an untagged CAPABILITIES response rather than including them in the OK response.
		 * This is somewhat nonstandard, and although we handle it below, we don't handle it here,
		 * since we only have access to the last response at this point. */
		if (!ok_had_caps) {
			IMAP_CLIENT_SEND(client, "a0 CAPABILITY");
			IMAP_CLIENT_EXPECT(client, "* CAPABILITY ");
		}
		if (imap_client_parse_capabilities(client, capsptr)) { /* Parse unauthenticated capabilities */
			return -1;
		}
		if (!ok_had_caps) {
			IMAP_CLIENT_EXPECT(client, "a0 OK");
		}
	}

	caps = *capsptr;
	if (STARTS_WITH(url->pass, "oauth:")) { /* OAuth authentication */
		char token[4096];
		char decoded[4096];
		int decodedlen, encodedlen;
		const char *oauthprofile = url->pass + STRLEN("oauth:");

		if (!(caps & IMAP_CAPABILITY_AUTH_XOAUTH2)) {
			bbs_warning("IMAP server does not support XOAUTH2\n");
			return -1;
		}
		if (!bbs_user_is_registered(user)) {
			bbs_warning("IMAP user not logged in?\n");
			return -1;
		}

		res = bbs_get_oauth_token(user, oauthprofile, token, sizeof(token));
		if (res) {
			bbs_warning("OAuth token '%s' does not exist for user %d\n", oauthprofile, user->id);
			return -1;
		}
		/* https://developers.google.com/gmail/imap/imap-smtp
		 * https://developers.google.com/gmail/imap/xoauth2-protocol */
		decodedlen = snprintf(decoded, sizeof(decoded), "user=%s%cauth=Bearer %s%c%c", url->user, 0x01, token, 0x01, 0x01);
		encoded = base64_encode(decoded, decodedlen, &encodedlen);
		if (!encoded) {
			bbs_error("Base64 encoding failed\n");
			return -1;
		}

		if (caps & IMAP_CAPABILITY_SASL_IR) { /* Save an RTT if the server supports RFC4959 SASL-IR */
			IMAP_CLIENT_SEND(client, "a1 AUTHENTICATE XOAUTH2 %s", encoded);
		} else {
			IMAP_CLIENT_SEND(client, "a1 AUTHENTICATE XOAUTH2");
			IMAP_CLIENT_EXPECT(client, "+");
			IMAP_CLIENT_SEND(client, "%s", encoded);
		}
		free(encoded);
		encoded = NULL;
	} else { /* Normal password auth */
		IMAP_CLIENT_SEND(client, "a1 LOGIN \"%s\" \"%s\"", url->user, url->pass);
	}

	/* Gimap (Gmail) sends the capabilities again when you log in,
	 * so tolerate CAPABILITY then OK as well as just OK (possibly also with CAPABILITY). */
	res = bbs_readline(client->rfd, &client->rldata, "\r\n", SEC_MS(10));
	if (res <= 0) {
		bbs_warning("No response from IMAP server %s:%d?\n", url->host, url->port);
		return -1;
	}
	if (STARTS_WITH(client->buf, "* CAPABILITY")) {
		if (imap_client_parse_capabilities(client, capsptr)) {
			return -1;
		}
		IMAP_CLIENT_EXPECT(client, "a1 OK");
	} else {
		if (!strstr(client->buf, "a1 OK")) {
			bbs_warning("Login failed, got '%s'\n", client->buf);
			if (STARTS_WITH(client->buf, "+ ")) {
				/* It failed, send an empty response to get the error message */
				IMAP_CLIENT_SEND(client, "");
			}
			/* Won't get it, but at least see what the server had to say */
			bbs_tcp_client_expect(client, "\r\n", 1, SEC_MS(7), "a1 OK"); /* Don't use IMAP_CLIENT_EXPECT, or we'll bypass the warning below when it fails */
			bbs_warning("Login failed, got '%s'\n", client->buf);
			return -1;
		}
		/* Request capabilities again, in case we have more now, now that we're logged in */
		ok_had_caps = strstr(client->buf, "[CAPABILITY") ? 1 : 0;
		if (!ok_had_caps) {
			IMAP_CLIENT_SEND(client, "a2 CAPABILITY");
			IMAP_CLIENT_EXPECT(client, "* CAPABILITY ");
		}
		if (imap_client_parse_capabilities(client, capsptr)) { /* Parse authenticated capabilities */
			return -1;
		}
		if (!ok_had_caps) {
			IMAP_CLIENT_EXPECT(client, "a2 OK");
		}
	}

	return 0;

cleanup:
	free_if(encoded);
	return -1;
}

/*
 * maildir format: http://cr.yp.to/proto/maildir.html
 * also: http://www.courier-mta.org/maildir.html
 * and: https://www.courier-mta.org/imap/README.maildirquota.html
 * and: https://www.systutorials.com/docs/linux/man/2-gettimeofday/
 * Note that some information here is obsolete.
 * For exmaple, mkstemp safely returns a unique temporary filename.
 */

int uidsort(const struct dirent **da, const struct dirent **db)
{
	unsigned int auid, buid;
	int failures = 0;
	const char *a = (*da)->d_name;
	const char *b = (*db)->d_name;

	/* We still have to deal with stuff like ., .., etc. here.
	 * We're iterating over the "cur" directory of a maildir,
	 * which will not have subfolders, so we should not encounter any. */

	/* Don't care about these, just return any *consistent* ordering. */
	if (!strcmp(a, ".") || !strcmp(a, "..")) {
		return strcmp(a, b);
	} else if (!strcmp(b, ".") || !strcmp(b, "..")) {
		return strcmp(a, b);
	}

	/* Note: Sequence numbers MUST be ordered by ascending unique identifiers, according to RFC 9051 2.3.1.2.
	 * So using any consistent ordering is not sufficient; they must be ordered by UID.
	 * For this reason, we use uidsort as the compare function instead of alphasort,
	 * since alphasort will sort by the order messages were originally created in any maildir.
	 * This is irrelevant for our purposes.
	 *
	 * Kind of learned this the hard way, too. Clients like Thunderbird-based clients will do
	 * funky things the sequence numbers are not in the right order.
	 * For example, just using opendir instead of scandir (which means arbitrary ordering, not even consistent ordering)
	 * leads to "flip floppings" where some messages are visible at one point, and if you click "Get Messages"
	 * to refresh, a different set of messages is shown (mostly overlapping, but the start/end is disjoint).
	 * Clicking "Get Messages" again goes back again, and so forth, flip flopping back and forth.
	 * This same thing happens even when using scandir with alphasort if messages in the directory
	 * are not in UID order. This can happen when moving/copying messages between folders.
	 * A simple mailbox test won't catch this, but in real world mailboxes, this is likely to happen.
	 */

	failures += !!maildir_parse_uid_from_filename(a, &auid);
	failures += !!maildir_parse_uid_from_filename(b, &buid);

	if (failures == 2) {
		/* If this is the new dir instead of a cur dir, then there won't be any UIDs. Key is that either both or neither filename must have UIDs. */
		auid = (unsigned int) atoi(a);
		buid = (unsigned int) atoi(b);
	} else if (unlikely(failures == 1)) {
		bbs_error("Failed to parse UID for %s / %s\n", a, b);
		return 0;
	} else if (unlikely(auid == buid)) {
		bbs_error("Message UIDs are equal? (%u = %u)\n", auid, buid);
		return 0;
	}

	return auid < buid ? -1 : 1;
}

static int maildir_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, int seqno, void *obj), void *obj, int (*sortfunc)(const struct dirent **da, const struct dirent **db))
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res = 0;
	int seqno = 0;

	bbs_soft_assert(!strlen_zero(path));

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(path, &entries, NULL, sortfunc);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		seqno++;
		if ((res = on_file(path, entry->d_name, seqno, obj))) {
			break; /* If the handler returns non-zero then stop */
		}
	}
	bbs_free_scandir_entries(entries, files); /* Free all at once at the end, in case we break from the loop early */
	free(entries);
	return res;
}

int maildir_ordered_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, int seqno, void *obj), void *obj)
{
	return maildir_traverse(path, on_file, obj, uidsort);
}

int maildir_uidless_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, int seqno, void *obj), void *obj)
{
	/* When traversing the new dir, UIDs have not yet been assigned,
	 * so using uidsort is wrong and will result in random ordering.
	 * However, there is still an ordering that must be preserved,
	 * and it's simply the normal ordering by entire filename. */
	return maildir_traverse(path, on_file, obj, alphasort);
}

static int cli_mailboxes(struct bbs_cli_args *a)
{
	struct mailbox *mbox;
	RWLIST_RDLOCK(&mailboxes);
	RWLIST_TRAVERSE(&mailboxes, mbox, entry) {
		if (mbox->name) {
			bbs_dprintf(a->fdout, "%s\n", mbox->name);
		} else {
			bbs_dprintf(a->fdout, "User ID: %u\n", mbox->id);
		}
	}
	RWLIST_UNLOCK(&mailboxes);
	return 0;
}

static int cli_mailbox(struct bbs_cli_args *a)
{
	struct mailbox *mbox = mailbox_get_by_name(a->argv[1], a->argc >= 3 ? a->argv[2] : NULL);
	if (!mbox) {
		bbs_dprintf(a->fdout, "No such mailbox: %s%s%s\n", a->argv[1], a->argc >= 3 ? "@" : "", a->argc >= 3 ? a->argv[2] : "");
		return 0;
	}
	bbs_dprintf(a->fdout, "%-20s: %u\n", "User ID", mbox->id);
	bbs_dprintf(a->fdout, "%-20s: %s\n", "Name", S_IF(mbox->name));
	bbs_dprintf(a->fdout, "%-20s: %s\n", "Maildir", mbox->maildir);
	bbs_dprintf(a->fdout, "%-20s: %9lu KB\n", "Total Quota", mailbox_quota(mbox) / 1024);
	bbs_dprintf(a->fdout, "%-20s: %9lu KB\n", "Quota Used", mailbox_quota_used(mbox) / 1024);
	bbs_dprintf(a->fdout, "%-20s: %9lu KB\n", "Quota Remaining", mailbox_quota_remaining(mbox) / 1024);
	bbs_dprintf(a->fdout, "%-20s: %u\n", "# Mailbox Watchers", mbox->watchers);
	bbs_dprintf(a->fdout, "%-20s: %s\n", "Activity Pending", BBS_YN(mbox->activity));
	return 0;
}

static struct bbs_cli_entry cli_commands_mailboxes[] = {
	BBS_CLI_COMMAND(cli_mailboxes, "mailboxes", 1, "List currently loaded mailboxes", NULL),
	BBS_CLI_COMMAND(cli_mailbox, "mailbox", 2, "Show mailbox details", "mailbox <user> [<domain>]"),
};

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

	cfg = bbs_config_load("mod_mail.conf", 1);
	if (!cfg) {
		return -1;
	}

	if (bbs_config_val_set_str(cfg, "general", "maildir", root_maildir, sizeof(root_maildir))) {
		bbs_config_unlock(cfg);
		return -1;
	}
	bbs_config_val_set_str(cfg, "general", "catchall", catchall, sizeof(catchall));
	bbs_config_val_set_uint(cfg, "general", "quota", &maxquota);

	if (eaccess(root_maildir, X_OK)) { /* This is a directory, so we better have execute permissions on it */
		bbs_error("Directory %s does not exist\n", root_maildir);
		bbs_config_unlock(cfg);
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
		} else if (!strcmp(bbs_config_section_name(section), "domains")) {
			stringlist_init(&local_domains);
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				const char *key = bbs_keyval_key(keyval);
				if (!stringlist_contains(&local_domains, key)) {
					bbs_debug(3, "Added local domain %s\n", key);
					stringlist_push(&local_domains, key);
				}
			}
		} else {
			bbs_warning("Unknown section name, ignoring: %s\n", bbs_config_section_name(section));
		}
	}
	bbs_config_unlock(cfg);
	return 0;
}

static int load_module(void)
{
	stringlist_init(&local_domains);
	if (load_config()) {
		return -1;
	}
	bbs_username_reserved_callback_register(mailbox_exists_by_username);
	bbs_cli_register_multiple(cli_commands_mailboxes);
	return 0;
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_mailboxes);
	bbs_username_reserved_callback_unregister(mailbox_exists_by_username);
	mailbox_cleanup();
	bbs_singular_callback_destroy(&sieve_validate);
	return 0;
}

BBS_MODULE_INFO_FLAGS("E-Mail Resource", MODFLAG_GLOBAL_SYMBOLS);
