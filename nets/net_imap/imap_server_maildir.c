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

int imap_translate_dir(struct imap_session *imap, const char *directory, char *buf, size_t len, int *acl)
{
	enum mailbox_namespace ns;
	const char *remainder;
	struct mailbox *mbox;
	int res = 0;

	*acl = 0; /* Assume no rights by default */

	/* With the maildir format, the INBOX is the top-level maildir for a user.
	 * Other directories are subdirectories */
	if (!strcasecmp(directory, "INBOX")) {
		if (imap->mbox != imap->mymbox) {
			mailbox_unwatch(imap->mbox); /* Stop watching whatever other/shared mailbox we were watching */
		}
		imap->mbox = imap->mymbox;
		safe_strncpy(buf, mailbox_maildir(imap->mbox), len);
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
			imap->mbox = mbox;
			remainder += strlen(name);
			snprintf(buf, len, "%s/%s%s%s", mailbox_maildir(NULL), name, !strlen_zero(remainder) ? "/" : "", remainder);
			mailbox_maildir_init(mailbox_maildir(imap->mbox)); /* Edge case: initialize if needed (necessary if user is accessing via POP before any messages ever delivered to it via SMTP) */
			mailbox_watch(imap->mbox);
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
			imap->mbox = mbox;
			mailbox_maildir_init(mailbox_maildir(imap->mbox)); /* Edge case: initialize if needed (necessary if user is accessing via POP before any messages ever delivered to it via SMTP) */
			mailbox_watch(imap->mbox); /*! \todo Might be ideal to always be watching ALL mailboxes to which we have access, rather than only non-personal ones when we SELECT them */
			ns = NAMESPACE_OTHER;
		} else { /* Personal namespace */
			/* For subdirectories, if they don't exist, don't automatically create them. */
			/* need to prefix with . for maildir++ format */
			/* Any time we do a SELECT, it's all relative to our personal mailbox.
			 * i.e. if we're selecting a mailbox in a different namespace, imap_translate_dir will handle that.
			 * So we should always reset to our personal mailbox here first. */
			snprintf(buf, len, "%s/.%s", mailbox_maildir(imap->mymbox), directory); /* Always evaluate in the context of our personal mailbox */
			ns = NAMESPACE_PRIVATE;
			if (imap->mbox != imap->mymbox) {
				/* Switch back to personal mailbox if needed */
				mailbox_unwatch(imap->mbox); /* Stop watching whatever other/shared mailbox we were watching */
				imap->mbox = imap->mymbox;
			}
		}
		if (eaccess(buf, R_OK)) {
			bbs_debug(5, "Directory %s does not exist\n", buf);
			res = -1;
			/* Load the ACLs we would have even if directory doesn't exist, for operations like CREATE where we return -1 */
		}
	}

	load_acl(imap, buf, ns, acl); /* If we succeeded so far, get the user's ACLs for this mailbox */
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

	/* Don't close the virtmbox, if there is one,
	 * because if we're selecting a different mailbox on the same remote account,
	 * we can just reuse the connection. */
	if (imap_translate_dir(imap, mailbox, dir, sizeof(dir), &acl)) {
		int res = load_virtual_mailbox(imap, mailbox);
		if (res >= 0) {
			/* XXX If a user named a mailbox "foobar" and then a foobar user was created,
			 * the other user's mailbox would take precedence over the virtual mailbox mapping.
			 * That's probably not a good thing... it would be nice to have a 4th namespace for this, but we don't. */
			bbs_debug(6, "Mailbox '%s' has a virtual mapping\n", mailbox);
			if (res) { /* Mapping exists, but couldn't connect for some reason */
				imap_reply(imap, "NO Remote server unavailable");
				goto fail;
			}
			imap->acl = 0; /* ACL not used for virtual mapped mailboxes. If the client does GETACL, that should passthrough to the remote. */
			/* This isn't really in a mailbox, since it's a remote, but use the private mailbox structure since nothing else would make sense */
			if (imap->mbox != imap->mymbox) {
				/* Switch back to personal mailbox if needed */
				mailbox_unwatch(imap->mbox); /* Stop watching whatever other/shared mailbox we were watching */
				imap->mbox = imap->mymbox; /* XXX Could we even set imap->mbox to NULL? In theory, it should now be used for virtual mailboxes. */
			}
			return 0;
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

void free_scandir_entries(struct dirent **entries, int numfiles)
{
	int fno = 0;
	struct dirent *entry;

	while (fno < numfiles && (entry = entries[fno++])) {
		free(entry);
	}
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
		files = scandir(directory, &entries, NULL, uidsort);
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
		free_scandir_entries(entries, files); /* Free all at once, since we might break out of the loop early */
		free(entries);
		return res;
	}
}

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
