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
 * \brief maildir++ interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/node.h"
#include "include/user.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_server_acl.h"
#include "nets/net_imap/imap_client.h"

int imap_uidsort(const struct dirent **da, const struct dirent **db)
{
	/* From dlopen(3):
	 * "Lazy binding is performed only for function references;
	 * references to variables are always immediately bound when the shared object is loaded."
	 *
	 * In other words, unresolved function references are fine with RTLD_LAZY, but unresolved variables are NOT.
	 * This matters because uidsort is used as a callback to several IMAP functions.
	 * For this reason, we have an in-module wrapper around this function, so that there are no unresolved data references,
	 * (since they all point to this function), only an unresolved function call in this function, which is fine with RTLD_LAZY. */
	return uidsort(da, db);
}

static void set_current_mailbox(struct imap_session *imap, struct mailbox *mbox)
{
	struct mailbox *old = imap->mbox;
	if (old == mbox) {
		return; /* No need to do anything */
	}
	if (old) {
		mailbox_unwatch(old); /* Stop watching whatever other/shared mailbox we were watching */
	}
	imap->mbox = mbox;
	/*! \todo Might be ideal to always be watching ALL mailboxes to which we have access, rather than only non-personal ones when we SELECT them */
	if (mbox) {
		mailbox_watch(mbox);
	}
}

static int __imap_translate_dir(struct imap_session *imap, const char *directory, char *buf, size_t len, int *acl, struct mailbox **mboxptr)
{
	enum mailbox_namespace ns;
	const char *remainder;
	struct mailbox *mbox;
	int res = 0;

	*acl = 0; /* Assume no rights by default */

	/* With the maildir format, the INBOX is the top-level maildir for a user.
	 * Other directories are subdirectories */
	if (!strcasecmp(directory, "INBOX")) {
		mbox = imap->mymbox;
		safe_strncpy(buf, mailbox_maildir(mbox), len);
		ns = NAMESPACE_PRIVATE;
	} else if (strstr(directory, "..")) {
		bbs_warning("Invalid IMAP directory: %s\n", directory);
		return -1;
	} else {
		/* Determine what namespace this mailbox is in */
		if (STARTS_WITH(directory, SHARED_NAMESPACE_PREFIX)) {
			char name[64];

			/* Translate as needed, starting from the root maildir */
			remainder = directory + STRLEN(SHARED_NAMESPACE_PREFIX); /* e.g. .public, .public.Sent */
			if (strlen_zero(remainder)) { /* Not \Select'able */
				return -1;
			}
			remainder++;
			if (strlen_zero(remainder)) {
				return -1;
			}
			safe_strncpy(name, remainder, sizeof(name));
			bbs_strterm(name, '.');
			mbox = mailbox_get_by_username(name);
			if (!mbox) {
				return -1;
			}
			remainder += strlen(name);
			snprintf(buf, len, "%s/%s%s%s", mailbox_maildir(NULL), name, !strlen_zero(remainder) ? "/" : "", remainder);
			mailbox_maildir_init(mailbox_maildir(mbox)); /* Edge case: initialize if needed (necessary if user is accessing via POP before any messages ever delivered to it via SMTP) */
			ns = NAMESPACE_SHARED;
		} else if (STARTS_WITH(directory, OTHER_NAMESPACE_PREFIX)) {
			char username[64];
			unsigned int userid;
			/* Translate as needed, starting from the root maildir */
			/* This is a bit more complicated, since we need to replace the username with the user ID,
			 * e.g. Other Users.jsmith -> 1, Other Users.jsmith.Sent -> 1/.Sent
			 * The first chunk after OTHER_NAMESPACE_PREFIX is the directory, and everything else is the subdirectory. */
			remainder = directory + STRLEN(OTHER_NAMESPACE_PREFIX); /* e.g. .jsmith, .jsmith.Sent */
			if (strlen_zero(remainder)) { /* Not \Select'able */
				return -1;
			}
			remainder++;
			if (strlen_zero(remainder)) {
				return -1;
			}
			safe_strncpy(username, remainder, sizeof(username));
			bbs_strterm(username, HIERARCHY_DELIMITER_CHAR);
			if (stringlist_contains(&imap->remotemailboxes, username)) {
				/* If we know there's a virtual/remote mailbox mapping, skip a DB call that will likely return nothing anyways.
				 * This has the benefit that if a user explicitly defines a mapping in .imapremote,
				 * it will take priority over a user with that particular username, preventing
				 * "hijacking" of names that others have used for a mapping.
				 * And from a performance perspective, it's way better to call stringlist_contains than query the DB every time.
				 */
				return -1;
			}
			userid = bbs_userid_from_username(username);
			if (!userid) {
				return -1;
			}
			remainder += strlen(username);
			/* Just this is \Select'able, it's the INBOX (INBOX isn't shown as a separate subdir for Other Users, etc.) */
			snprintf(buf, len, "%s/%u%s%s", mailbox_maildir(NULL), userid, !strlen_zero(remainder) ? "/" : "", remainder); /* Don't end in a trailing slash */
			/* Update mailbox to pointer to the right one */
			/* imap->mbox refers to the personal mailbox, not this other user's mailbox...
			 * imap->mbox needs to point to the other user's mailbox now. */
			/* Keep watching our personal mailbox, but also watch the new one. */
			mbox = mailbox_get_by_userid(userid);
			if (!mbox) {
				return -1;
			}
			mailbox_maildir_init(mailbox_maildir(imap->mbox)); /* Edge case: initialize if needed (necessary if user is accessing via POP before any messages ever delivered to it via SMTP) */
			ns = NAMESPACE_OTHER;
		} else { /* Personal namespace */
			/* For subdirectories, if they don't exist, don't automatically create them. */
			/* need to prefix with . for maildir++ format */
			/* Any time we do a SELECT, it's all relative to our personal mailbox.
			 * i.e. if we're selecting a mailbox in a different namespace, imap_translate_dir will handle that.
			 * So we should always reset to our personal mailbox here first. */
			snprintf(buf, len, "%s/.%s", mailbox_maildir(imap->mymbox), directory); /* Always evaluate in the context of our personal mailbox */
			ns = NAMESPACE_PRIVATE;
			mbox = imap->mymbox; /* Switch back to personal mailbox if needed */
		}
		if (eaccess(buf, R_OK)) {
			bbs_debug(5, "Directory %s does not exist\n", buf);
			res = -1;
			/* Load the ACLs we would have even if directory doesn't exist, for operations like CREATE where we return -1 */
		}
	}

	*mboxptr = mbox;

	load_acl(imap, buf, ns, acl); /* If we succeeded so far, get the user's ACLs for this mailbox */
	return res;
}

int imap_translate_dir(struct imap_session *imap, const char *directory, char *buf, size_t len, int *acl)
{
	struct mailbox *mbox = NULL;
	int res = __imap_translate_dir(imap, directory, buf, len, acl, &mbox);
	set_current_mailbox(imap, mbox);
	return res;
}

int set_maildir(struct imap_session *imap, const char *mailbox)
{
	char dir[256];
	int acl;
	if (strlen_zero(mailbox)) {
		imap_reply(imap, "BAD [CLIENTBUG] Missing argument");
		return -1;
	}

	/* Don't immediately close the remote mailbox (imap_close_remote_mailbox), if there is one,
	 * because if we're selecting a different mailbox on the same remote account,
	 * we can just reuse the connection. */
	if (imap_translate_dir(imap, mailbox, dir, sizeof(dir), &acl)) {
		int exists = 0;
		struct imap_client *client = load_virtual_mailbox(imap, mailbox, &exists);
		if (client) {
			imap->client = client; /* Set as active remote client (and currently in remote mailbox) */
			bbs_debug(6, "Mailbox '%s' has a virtual mapping\n", mailbox);
			imap->acl = 0; /* ACL not used for virtual mapped mailboxes. If the client does GETACL, that should passthrough to the remote. */
			/* This isn't really in a mailbox, since it's a remote, but use the private mailbox structure since nothing else would make sense */
			set_current_mailbox(imap, imap->mymbox); /* Switch back to personal mailbox if needed... (somewhat arbitrary) */
			return 0;
		} else if (exists) { /* Mapping exists, but couldn't connect for some reason */
			imap_reply(imap, "NO Remote server unavailable");
			goto fail;
		}
		/* Mailbox doesn't exist on this server, and there is no mapping for it to any remote */
		imap_reply(imap, "NO [NONEXISTENT] No such mailbox '%s'", mailbox);
fail:
		if (imap->client) {
			imap_close_remote_mailbox(imap);
		}
		return -1;
	}

	if (imap->client) {
		imap_close_remote_mailbox(imap);
	}

	IMAP_REQUIRE_ACL(acl, IMAP_ACL_READ);

	/* Actually copy over ACL once we are sure it will apply. */
	imap->acl = acl;
	safe_strncpy(imap->dir, dir, sizeof(imap->dir));
	imap_debug(3, "New effective maildir for user %d is %s\n", bbs_user_is_registered(imap->node->user) ? imap->node->user->id : 0, imap->dir);
	snprintf(imap->newdir, sizeof(imap->newdir), "%s/new", imap->dir);
	snprintf(imap->curdir, sizeof(imap->curdir), "%s/cur", imap->dir);
	return mailbox_maildir_init(imap->dir);
}

int set_maildir_readonly(struct imap_session *imap, struct imap_traversal *traversal, const char *mailbox)
{
	int res;

	if (strlen_zero(mailbox)) {
		imap_reply(imap, "BAD [CLIENTBUG] Missing argument");
		return -1;
	}

	res = __imap_translate_dir(imap, mailbox, traversal->dir, sizeof(traversal->dir), &traversal->acl, &traversal->mbox);

	if (res) {
		int exists = 0;
		struct imap_client *client = load_virtual_mailbox(imap, mailbox, &exists);
		if (client) {
			traversal->client = client;
			bbs_debug(6, "Mailbox '%s' has a virtual mapping\n", mailbox);
			return 0;
		} else if (exists) {
			imap_reply(imap, "NO Remote server unavailable");
			return -1;
		}
		/* Mailbox doesn't exist on this server, and there is no mapping for it to any remote */
		imap_reply(imap, "NO [NONEXISTENT] No such mailbox '%s'", mailbox);
		return -1;
	}

	IMAP_REQUIRE_ACL(traversal->acl, IMAP_ACL_READ);
	snprintf(traversal->newdir, sizeof(traversal->newdir), "%s/new", traversal->dir);
	snprintf(traversal->curdir, sizeof(traversal->curdir), "%s/cur", traversal->dir);
	return mailbox_maildir_init(traversal->dir);
}

long parse_modseq_from_filename(const char *filename, unsigned long *modseq)
{
	char *modseqstr = strstr(filename, ",M=");
	if (!modseqstr) {
		/* Don't use 0 since HIGHESTMODSEQ=0 indicates persistent mod sequences not supported (RFC 7162 Section 7) */
		*modseq = 1; /* At least since we started keeping track of MODSEQ, this file has not been modified to have it added to the filename */
		return -1;
	}
	modseqstr += STRLEN(",M=");
	if (!strlen_zero(modseqstr)) {
		*modseq = (unsigned long) atol(modseqstr); /* Should stop as soon we encounter the first nonnumeric character, whether , or : */
		if (!*modseq) {
			bbs_warning("Failed to parse modseq for %s\n", filename);
			return -1;
		}
	} else {
		bbs_debug(5, "Filename %s does not contain a modseq\n", filename);
		return -1;
	}
	return 0;
}

int parse_size_from_filename(const char *filename, unsigned long *size)
{
	const char *sizestr = strstr(filename, ",S=");
	if (!sizestr) {
		bbs_error("Missing size in file %s\n", filename);
		*size = 0;
		return -1;
	}
	sizestr += STRLEN(",S=");
	*size = (unsigned long) atol(sizestr);
	if (!*size) {
		bbs_warning("Invalid size (%lu) for %s\n", *size, filename);
	}
	return 0;
}

int imap_msg_to_filename(const char *directory, int seqno, unsigned int uid, char *buf, size_t len)
{
	struct dirent *entry;

	/*! \todo We should cache all the filenames in a single file perhaps to speed up lookups */
	if (uid) {
		DIR *dir;
		char fbuf[25];
		snprintf(fbuf, sizeof(fbuf), ",U=%u", uid);
		/* Doesn't need to be an ordered traversal. readdir is okay. */
		if (!(dir = opendir(directory))) {
			bbs_error("Error opening directory - %s: %s\n", directory, strerror(errno));
			return -1;
		}
		while ((entry = readdir(dir)) != NULL) {
			if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
				continue;
			}
			if (strstr(entry->d_name, fbuf)) {
				safe_strncpy(buf, entry->d_name, len);
				closedir(dir);
				return 0;
			}
		}
		return 1;
	} else {
		struct dirent **entries;
		int files, myseqno = 0, fno = 0;
		int res = 1;

		/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
		files = scandir(directory, &entries, NULL, imap_uidsort);
		if (files < 0) {
			bbs_error("scandir(%s) failed: %s\n", directory, strerror(errno));
			return -1;
		}
		while (fno < files && (entry = entries[fno++])) {
			if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
				continue;
			}
			myseqno++;
			if (myseqno == seqno) {
				safe_strncpy(buf, entry->d_name, len);
				res = 0;
				break;
			}
		}
		bbs_free_scandir_entries(entries, files); /* Free all at once, since we might break out of the loop early */
		free(entries);
		return res;
	}
}
