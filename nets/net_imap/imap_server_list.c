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
 * \brief IMAP Server LIST
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>
#include <dirent.h>

#include "include/node.h"
#include "include/user.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_server_acl.h"
#include "nets/net_imap/imap_server_list.h"

/*! \note Only non-static because it's unit tested in net_imap.c */
int list_match(const char *dirname, const char *query)
{
	const char *a, *b;
	int res = 1;
	int had_wildcard = 0;

	/* A user's account is commonly called a "mailbox", and IMAP refers to folders as mailboxes...
	 * and the 2nd argument to LIST is the mailbox argument... to disambiguate here, I'll refer
	 * to this 2nd argument as $mailbox:
	 *
	 * Now, try to see if the pattern specified by $mailbox matches whatever we see here.
	 * A simple technique is basically walk through $mailbox with the filename,
	 * and if we get to the end of $mailbox without NOT matching on anything (every match
	 * was literal or a wildcard), then we're good to include this in the result.
	 * If the last wildcard is a %, don't include subdirectories.
	 * In other words % should match any character EXCEPT the hierarchy delimiter.
	 */

	a = dirname;
	b = query;

	for (; *a && *b; a++, b++) {
		if (*a == *b) {
			had_wildcard = 0;
			continue; /* Exact match on this character. */
		} else if (*b == '*' || (*b == '%' && *a != '.')) {
			if (*b == '*') {
				had_wildcard = 1;
			}
			continue;
		}
		/* XXX The logic here is a hack. It might work, but it doesn't change that.
		 * The pattern matching in this function should be externalized to something more robust and well tested. */
		if (had_wildcard) { /* Last char was a wildcard */
			a = strchr(a, *b); /* For patterns like *2, baz2 should match. Here, we look for the 2 instead of a. */
			if (a) {
				continue; /* Keep going */
			}
		}
#ifdef DEBUG_LIST_MATCH
		imap_debug(9, "IMAP path '%s' failed prefix test: %s != %s (%s, %s)\n", dirname, a, b, dirname, query);
#endif
		res = 0;
		goto ret;
	}
	/* If there was no wildcard at the end, but there's more of the directory name remaining, it's NOT a match. */
	if (!strlen_zero(a)) {
		if (!strlen_zero(query) && *(b - 1) != '*' && *(b - 1) != '%') {
#ifdef DEBUG_LIST_MATCH
			imap_debug(9, "IMAP path '%s' failed wildcard test\n", dirname);
#endif
			res = 0;
			goto ret;
		}
	}

ret:
#ifdef DEBUG_LIST_MATCH
	if (res) {
		imap_debug(9, "IMAP path '%s' matches query '%s'\n", dirname, query);
	}
#endif
	return res;
}

static int imap_dir_has_subfolders(const char *path, const char *prefix)
{
	DIR *dir;
	struct dirent *entry;
	int res = 0;
	size_t prefixlen = strlen(prefix);

	/* Order doesn't matter here */
	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		} else if (!strncmp(entry->d_name, prefix, prefixlen)) {
			const char *rest = entry->d_name + prefixlen; /* do not add these within the strlen_zero macro! */
			if (!strlen_zero(rest)) {
				res = 1;
				break;
			}
		}
	}

	closedir(dir);
	return res;
}

static int imap_dir_contains_files(const char *path)
{
	DIR *dir;
	struct dirent *entry;
	int res = 0;

	/* Order doesn't matter here */
	if (!(dir = opendir(path))) {
		bbs_debug(3, "Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		res = 1;
		break;
	}

	closedir(dir);
	return res;
}

static int get_attributes(const char *parentdir, const char *mailbox, const char *maildir, int flags)
{
	char newdir[512];
	int res;

	/* Great, we've just turned this into an n^2 operation now (the downside of IMAP hierarchy being only 2 levels on disk):
	 * But HasNoChildren and HasChildren are mandatory in the RFC, and they're pretty important attributes for the client, so compute them.
	 * In reality, it shouldn't take *too* terribly long since the number of folders (all folders, recursively), is still likely to be
	 * (some kind of small) constant, not even linear, so it's sublinear * sublinear. */
	if (!(flags & DIR_HAS_CHILDREN)) { /* If we already know it does, don't need to check here */
		res = imap_dir_has_subfolders(parentdir, mailbox);
		if (res == 1) {
			flags |= DIR_HAS_CHILDREN;
		} else if (res == 0) {
			flags |= DIR_NO_CHILDREN;
		}
	}

	/* If the mailbox has any \Recent messages (e.g. there are files in the new directory),
	 * then it's \Marked. Otherwise, it's \Unmarked. */
	snprintf(newdir, sizeof(newdir), "%s/new", maildir);
	res = imap_dir_contains_files(newdir);
	if (res == 1) {
		flags |= DIR_MARKED;
	} else if (res == 0) {
		flags |= DIR_UNMARKED;
	}

	/* Special folders that must be named as such on our end: let the client know these are special using RFC 6154 */
	if (!strcmp(mailbox, ".Drafts")) {
		flags |= DIR_DRAFTS;
	} else if (!strcmp(mailbox, ".Junk")) {
		flags |= DIR_JUNK;
	} else if (!strcmp(mailbox, ".Sent")) {
		flags |= DIR_SENT;
	} else if (!strcmp(mailbox, ".Trash")) {
		flags |= DIR_TRASH;
	}

	return flags;
}

void build_attributes_string(char *buf, size_t len, int attrs)
{
	char *pos = buf;
	size_t left = len;

	bbs_assert(!(attrs & DIR_NO_CHILDREN && attrs & DIR_HAS_CHILDREN)); /* This would make no sense. */

	ASSOC_ATTR(DIR_NO_SELECT, ATTR_NOSELECT);
	ASSOC_ATTR(DIR_NO_CHILDREN, ATTR_NO_CHILDREN);
	ASSOC_ATTR(DIR_HAS_CHILDREN, ATTR_HAS_CHILDREN);
	ASSOC_ATTR(DIR_DRAFTS, ATTR_DRAFTS);
	ASSOC_ATTR(DIR_JUNK, ATTR_JUNK);
	ASSOC_ATTR(DIR_SENT, ATTR_SENT);
	ASSOC_ATTR(DIR_TRASH, ATTR_TRASH);
	ASSOC_ATTR(DIR_INBOX, ATTR_INBOX);
	ASSOC_ATTR(DIR_SUBSCRIBED, ATTR_SUBSCRIBED);
	ASSOC_ATTR(DIR_MARKED, ATTR_MARKED);
	ASSOC_ATTR(DIR_UNMARKED, ATTR_UNMARKED);

	if (left <= 0) {
		bbs_error("Truncation occured when building attribute string (%lu)\n", left);
		*(buf + len - 1) = '\0';
	} else {
		*pos = '\0';
		/* SAFE_FAST_COND_APPEND automatically adds spacing as needed, no need to remove the last space */
	}
}

static int list_mailbox_pattern_matches_inbox(struct list_command *lcmd)
{
	size_t i;

	for (i = 0; i < lcmd->patterns; i++) {
		if (list_mailbox_pattern_matches_inbox_single(lcmd->mailboxes[i])) {
			return 1;
		}
	}
	return 0;
}

int list_mailbox_pattern_matches(struct list_command *lcmd, const char *dirname)
{
	size_t i;

	/* It just needs to match one (any) of them */
	for (i = 0; i < lcmd->patterns; i++) {
#ifdef DEBUG_LIST_MATCH
		imap_debug(10, "Checking '%s' against (%d) '%s'\n", dirname, lcmd->nslist[i], lcmd->mailboxes[i] + lcmd->skiplens[i]);
#endif
		if (lcmd->nslist[i] == NAMESPACE_OTHER && lcmd->ns != NAMESPACE_OTHER) {
			continue;
		} else if (lcmd->nslist[i] == NAMESPACE_SHARED && lcmd->ns != NAMESPACE_SHARED) {
			continue;
		}
		/* lcmd->mailboxes[i] is guaranteed to be at least lcmd->skiplens[i] chars long */
		if (list_match(dirname, lcmd->mailboxes[i] + lcmd->skiplens[i])) { /* Compare mailbox with the pattern (on the right) */
			return 1;
		}
	}
	return 0;
}

/*! \retval 0 if skipped, 1 if included */
static int list_scandir_single(struct imap_session *imap, struct list_command *lcmd, int level,
	const char *fulldir, const char *mailboxname, const char *prefix, const char *listscandir, const char *leafname)
{
	int flags = 0, myacl;
	char extended_buf[512] = "";
	char attributes[128];
	char fullmailboxname[256];
	const char *extended_data_items = extended_buf;

	load_acl(imap, fulldir, lcmd->ns, &myacl);

	/* Suppress mailbox from LIST output if user doesn't at least have IMAP_ACL_LOOKUP for this mailbox. */
	if (!IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
#ifdef DEBUG_LIST_MATCH
		char aclbuf[256] = "";
		if (myacl != 0) {
			generate_acl_string(myacl, aclbuf, sizeof(aclbuf));
		}
		bbs_debug(6, "User lacks permission for %s: %s\n", fulldir, aclbuf);
#endif
		return 0; /* We don't have permission to LIST this mailbox, but might have permission to list one of its children. */
	}

	/* lcmd->remote is never true on this server (but this only expands the selection, so we can also functionally ignore it).
	 * We always return children (\HasChildren or \HasNoChildren), regardless of lcmd->retchildren.
	 * lcmd->retsubscribed XXX */

	if (level == 0 && lcmd->ns != NAMESPACE_PRIVATE) { /* Most LISTs will be for the private namespace, so check that case first */
		/* We can't use get_attributes for the mailbox itself, since there won't be other directories
		 * in this same directory with the maildir++ format (e.g. for mailbox public, there is .Sent folder in public, e.g. public/.Sent,
		 * but public.Sent does not exist anywhere on disk.
		 * But we know it has children, since every mailbox has Sent/Drafts/Junk/etc. so just hardcode that here: */
		flags |= DIR_HAS_CHILDREN;
	}

	/* We always return special use attributes, regardless of lcmd->retspecialuse */
	flags = get_attributes(listscandir, leafname, fulldir, flags);

	if (lcmd->cmdtype == CMD_XLIST && strstr(leafname, "INBOX")) { /* XXX This is not the right way to detect this */
		flags |= DIR_INBOX;
	}
	if (lcmd->retsubscribed) {
		flags |= DIR_SUBSCRIBED; /* All folders are always subscribed on this server. */
	}

	/* Check selection criteria */
	if (lcmd->specialuse && !(flags & DIR_SPECIALUSE)) {
#ifdef DEBUG_LIST_MATCH
		imap_debug(8, "Omitting listing due to SPECIAL-USE: %s\n", mailboxname);
#endif
		/*! \todo need to implement lcmd->recursive: if child mailboxes are matched and this is not, also return this one
		 * (still has to match pattern, but maybe selection criteria did not match)
		 * We also need to support the CHILDINFO extended data item as in RFC 5258 3.5,
		 * which will indicate the reason a parent folder was included.
		 * Also note that LSUB behaves differently than LIST (SUBSCRIBED) here.
		 */
		return 0;
	}

	if (lcmd->retstatus) { /* RFC 5819 LIST-STATUS */
		if (!IMAP_HAS_ACL(myacl, IMAP_ACL_READ)) {
			/* Do not send a STATUS response for this mailbox.
			 * Additionally, this is a NoSelect mailbox (RFC 5819 Section 2) */
			flags |= DIR_NO_SELECT;
		}
	}

#ifdef DEBUG_LIST_MATCH
	imap_debug(10, "level %d, reference: %s, prefix: %s, mailboxname: %s\n", level, lcmd->reference, prefix, mailboxname);
#endif

	snprintf(fullmailboxname, sizeof(fullmailboxname), "%s%s%s%s",
		lcmd->ns == NAMESPACE_SHARED ? SHARED_NAMESPACE_PREFIX HIERARCHY_DELIMITER : lcmd->ns == NAMESPACE_OTHER ? OTHER_NAMESPACE_PREFIX HIERARCHY_DELIMITER : "",
		S_IF(prefix), !strlen_zero(prefix) ? HIERARCHY_DELIMITER : "", mailboxname);

	build_attributes_string(attributes, sizeof(attributes), flags);
	imap_send(imap, "%s (%s) \"%s\" \"%s\"%s%s", lcmd->cmd, attributes, HIERARCHY_DELIMITER, fullmailboxname,
		!strlen_zero(extended_data_items) ? " " : "", S_IF(extended_data_items)); /* Always send the delimiter */

	if (lcmd->retstatus && IMAP_HAS_ACL(myacl, IMAP_ACL_READ)) { /* Part 2 for LIST-STATUS: actually send listing if we can */
		struct imap_traversal traversal;
		memset(&traversal, 0, sizeof(traversal));
		if (set_maildir_readonly(imap, &traversal, fullmailboxname)) {
			bbs_error("Failed to set maildir for %s\n", mailboxname);
		} else {
			local_status(imap, &traversal, fullmailboxname, lcmd->retstatus); /* We know this folder is local, not remote */
		}
	}

	return 1;
}

/*! \note XXX Essentially just a stripped down version of list_scandir */
int list_iterate(struct imap_session *imap, struct list_command *lcmd, int level, const char *prefix, const char *listscandir, int (*cb)(struct imap_session *imap, struct list_command *lcmd, const char *name, void *data), void *data)
{
	struct dirent *entry, **entries;
	int files, fno = 0;

	/* Handle INBOX, since that's also a special case. */
	if (level == 0 && lcmd->ns == NAMESPACE_PRIVATE) {
		if (cb(imap, lcmd, "INBOX", data)) {
			return -1;
		}
	}

	files = scandir(listscandir, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", mailbox_maildir(imap->mbox), strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		char fulldir[257];
		char mailboxbuf[256];
		char relativepath[512];
		const char *mailboxname = entry->d_name;

		/* Only care about directories, not files. */
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}

		if (level == 0) {
			if (lcmd->ns != NAMESPACE_PRIVATE) {
				if (!strcmp(entry->d_name, "cur") || !strcmp(entry->d_name, "new") || !strcmp(entry->d_name, "tmp")) {
					goto cleanup;
				}
				if (!maildir_is_mailbox(entry->d_name)) {
					goto cleanup; /* Not a mailbox */
				}
			}
		}

		if (level == 0 && lcmd->ns == NAMESPACE_OTHER && isdigit(*entry->d_name)) {
			unsigned int userid = (unsigned int) atoi(entry->d_name);
			if (userid == imap->node->user->id) {
				goto cleanup; /* Skip ourself */
			}
			if (bbs_username_from_userid(userid, mailboxbuf, sizeof(mailboxbuf))) {
				bbs_warning("No user for maildir %s\n", entry->d_name);
				goto cleanup;
			}
			str_tolower(mailboxbuf); /* Convert to all lowercase since that's the convention we use for email */
			mailboxname = mailboxbuf; /* e.g. jsmith instead of 1 */
		} else if (level == 0 && lcmd->ns == NAMESPACE_SHARED && !isdigit(*entry->d_name)) {
			mailboxname = entry->d_name; /* Mailbox name stays the same, this is technically a redundant instruction */
		} else if (*entry->d_name != '.') {
			goto cleanup; /* Not a maildir++ directory (or it's an INBOX folder) */
		}

		if (lcmd->ns == NAMESPACE_PRIVATE) {
			safe_strncpy(relativepath, entry->d_name + 1, sizeof(relativepath));
		} else if (level == 1) {
			snprintf(relativepath, sizeof(relativepath), ".%s%s", prefix, entry->d_name);
		} else {
			snprintf(relativepath, sizeof(relativepath), ".%s", mailboxname);
		}

		if (*mailboxname == HIERARCHY_DELIMITER_CHAR) {
			mailboxname++;
		}

		if (cb(imap, lcmd, relativepath, data)) {
			goto cleanup;
		}

		snprintf(fulldir, sizeof(fulldir), "%s/%s", listscandir, entry->d_name);
		if (level == 0 && lcmd->ns != NAMESPACE_PRIVATE) {
			list_iterate(imap, lcmd, 1, mailboxname, fulldir, cb, data);
		}
cleanup:
		free(entry);
	}
	free(entries);
	return 0;
}

int list_scandir(struct imap_session *imap, struct list_command *lcmd, int level, const char *prefix, const char *listscandir)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int matches = 0;

	/* Handle INBOX, since that's also a special case. */
	if (level == 0 && lcmd->ns == NAMESPACE_PRIVATE && !lcmd->specialuse && list_mailbox_pattern_matches_inbox(lcmd)) {
		matches += list_scandir_single(imap, lcmd, level, mailbox_maildir(imap->mbox), "INBOX", prefix, mailbox_maildir(imap->mbox), "INBOX");
	}

#ifdef DEBUG_LIST_MATCH
	imap_debug(9, "Traversing directory at level %d (ns filter %d): %s\n", level, lcmd->ns, listscandir);
#endif
	files = scandir(listscandir, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", mailbox_maildir(imap->mbox), strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		char fulldir[257];
		char mailboxbuf[256];
		char relativepath[512];
		const char *mailboxname = entry->d_name;

		/* Only care about directories, not files. */
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}

		if (level == 0) {
			if (lcmd->ns != NAMESPACE_PRIVATE) {
				if (!strcmp(entry->d_name, "cur") || !strcmp(entry->d_name, "new") || !strcmp(entry->d_name, "tmp")) {
					goto cleanup;
				}
				if (!maildir_is_mailbox(entry->d_name)) {
					goto cleanup; /* Not a mailbox */
				}
			}
		}

		if (level == 0 && lcmd->ns == NAMESPACE_OTHER && isdigit(*entry->d_name)) {
			unsigned int userid = (unsigned int) atoi(entry->d_name);
			if (userid == imap->node->user->id) {
				goto cleanup; /* Skip ourself */
			}
			if (bbs_username_from_userid(userid, mailboxbuf, sizeof(mailboxbuf))) {
				bbs_warning("No user for maildir %s\n", entry->d_name);
				goto cleanup;
			}
			str_tolower(mailboxbuf); /* Convert to all lowercase since that's the convention we use for email */
			mailboxname = mailboxbuf; /* e.g. jsmith instead of 1 */
		} else if (level == 0 && lcmd->ns == NAMESPACE_SHARED && !isdigit(*entry->d_name)) {
			mailboxname = entry->d_name; /* Mailbox name stays the same, this is technically a redundant instruction */
		} else if (*entry->d_name != '.') {
			goto cleanup; /* Not a maildir++ directory (or it's an INBOX folder) */
		}
		/* This is an instance where maildir format is nice, we don't have to recurse in this subdirectory. */
		if (strncmp(mailboxname, lcmd->reference, lcmd->reflen)) {
#ifdef DEBUG_LIST_MATCH
			imap_debug(10, "Directory %s doesn't start with prefix %s\n", entry->d_name, lcmd->reference);
#endif
			goto cleanup; /* It doesn't start with the same prefix as the reference */
		}

		/* This part can get tricky, not especially for the private namespace, but to handle all namespaces properly, and subdirectories.
		 * Private namespace is fairly straightforward.
		 * (Paths here are relative to the global root maildir):
		 * Other namespace:
		 * - Other Users.jsmith.Sent -> 1/.Sent
		 * - Shared Folders.public -> public
		 * - Shared Folders.public.Sent -> public/.Sent
		 *
		 * Notice how there are only two possible levels of hierarchy here.
		 * We can either be looking at folders in the root maildir itself, or folders that are in those folders.
		 * This is why the level variable is always 0 (root) or 1 (subfolder).
		 *
		 * We need to match the folders on disk against the patterns submitted by the client.
		 * The thing to note is that "Other Users" and "Shared Folders" will never match because they don't exist in any part of the path.
		 * We need to skip that and jump to what comes afterwards for this part.
		 *
		 * So for Other Users.jsmith, we would match the "1" directory on disk.
		 * And for Shared Folders.public, we would match the "public" directory on disk.
		 *
		 * skiplen will let us skip that part. So mailbox + skiplen would just leave .jsmith, .public, etc.
		 * Clearly, for other/shared, we need to match on the first chunk (anything before the 2nd period, skipping the first period),
		 * and anything starting with (and including) the second period is part of the subdirectory folder name.
		 * But remember, we're not done yet, since for Other Users, we need to translate the user ID in the filepath to the username, as in the IMAP path.
		 *
		 * So mailboxname = the directory name for shared and the username for other, and this is then the first "chunk" in the IMAP path at mailbox + skiplen.
		 *
		 * For personal namespace, it's difference since we're starting from the user's maildir. So there is really only 1 level of traversal, not two.
		 * Other and Shared effectively "escape" to the root first.
		 */

		/* listscandir is the directory we're traversing.
		 * For level 0, this is the root maildir for other/shared.
		 * For level 1, this is the actual mailbox itself, just like for personal namespace.
		 */

		if (lcmd->ns == NAMESPACE_PRIVATE) {
			/* For personal, you only see the contents of your mailbox, never mailboxes themselves. */
			/* Add +1 to skip the leading ., since that doesn't appear in the mailbox name */
			safe_strncpy(relativepath, entry->d_name + 1, sizeof(relativepath)); /*! \todo Optimize for this (common case) by updating a pointer when needed, rather than copying. */
		} else if (level == 1) {
			/* Other or Shared, inside the mailbox
			 * listscandir = mailbox path, prefix = the name of this mailbox
			 * entry->d_name = name of the mailbox folder (e.g. .Sent, .Trash, .Sub.Folder, etc.) */
			snprintf(relativepath, sizeof(relativepath), ".%s%s", prefix, entry->d_name);
		} else {
			/* Other or Shared, in the root maildir
			 * listscandir = root maildir path, prefix is NULL, mailboxname = e.g. jsmith, public */
			snprintf(relativepath, sizeof(relativepath), ".%s", mailboxname);
		}

		/* Skip leading hierarchy delimiter, since it doesn't appear in the mailbox name */
		if (*mailboxname == HIERARCHY_DELIMITER_CHAR) {
			mailboxname++;
		}

		/* At this point, relativepath should be something we can use for a match comparison.
		 * Note that for other/shared, a leading . is included in the part of the query we look at (mailbox + skiplen),
		 * so we've included that above as well, since that first leading period doesn't exist anywhere in the filepaths on disk.
		 *
		 * list_match takes the directory name and then the query (which can contain wildcards).
		 *
		 * The query doesn't need to be translated, we instead translated the path on disk to fit the query.
		 * The query is "mailbox" variable... but don't forget reference (handled above)
		 * However, most clients seem to provide an empty reference and put everything in the mailbox argument to LIST, and that's what I've mostly tested.
		 */

		if (!list_mailbox_pattern_matches(lcmd, relativepath)) {
			goto cleanup;
		}

		/* If it matches, we MIGHT want to include this in the results.
		 * That depends on if we're authorized by the ACL.
		 * Generate the full directory name so we can load the ACL from it */
		snprintf(fulldir, sizeof(fulldir), "%s/%s", listscandir, entry->d_name);
		matches += list_scandir_single(imap, lcmd, level, fulldir, mailboxname, prefix, listscandir, entry->d_name);

		/* User may not be authorized for some mailbox, but may be authorized for a subdirectory (e.g. not INBOX, but some subfolder)
		 * However, this is incredibly expensive as it means "Other Users" will literally traverse every user's entire maildir. */
		if (level == 0 && lcmd->ns != NAMESPACE_PRIVATE) {
			/* Recurse only the first time, since there are no more maildirs within afterwards */
			list_scandir(imap, lcmd, 1, mailboxname, fulldir);
		}
cleanup:
		free(entry);
	}
	free(entries);
	return matches;
}
