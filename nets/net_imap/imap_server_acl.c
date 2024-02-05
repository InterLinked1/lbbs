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
 * \brief IMAP Server ACLs (Access Control List)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>

#include "include/node.h"
#include "include/user.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_acl.h"

int parse_acl(const char *aclstring)
{
	int acl = 0;

	for (; *aclstring; aclstring++) {
		switch (*aclstring) {
			PARSE_ACL_LETTER(IMAP_ACL_LOOKUP);
			PARSE_ACL_LETTER(IMAP_ACL_READ);
			PARSE_ACL_LETTER(IMAP_ACL_SEEN);
			PARSE_ACL_LETTER(IMAP_ACL_WRITE);
			PARSE_ACL_LETTER(IMAP_ACL_INSERT);
			PARSE_ACL_LETTER(IMAP_ACL_POST);
			PARSE_ACL_LETTER(IMAP_ACL_MAILBOX_CREATE);
			PARSE_ACL_LETTER(IMAP_ACL_MAILBOX_DELETE);
			PARSE_ACL_LETTER(IMAP_ACL_DELETE);
			PARSE_ACL_LETTER(IMAP_ACL_EXPUNGE);
			PARSE_ACL_LETTER(IMAP_ACL_ADMINISTER);
			/* If an obsolete right is specified, we must treat it as if the client included all underlying rights */
			case IMAP_ACL_UNION_CREATE_LETTER:
				acl |= IMAP_ACL_MAILBOX_CREATE | IMAP_ACL_MAILBOX_DELETE;
				break;
			case IMAP_ACL_UNION_DELETE_LETTER:
				acl |= IMAP_ACL_DELETE | IMAP_ACL_EXPUNGE;
				break;
			case '\n':
				break; /* Ignore newlines if present */
			default:
				bbs_warning("Unknown IMAP right: %c\n", *aclstring);
		}
	}

	return acl;
}

void generate_acl_string(int acl, char *buf, size_t len)
{
	bbs_assert(len >= 14); /* Need at least 14 for all of them */
	WRITE_ACL_LETTER(IMAP_ACL_LOOKUP);
	WRITE_ACL_LETTER(IMAP_ACL_READ);
	WRITE_ACL_LETTER(IMAP_ACL_SEEN);
	WRITE_ACL_LETTER(IMAP_ACL_WRITE);
	WRITE_ACL_LETTER(IMAP_ACL_INSERT);
	WRITE_ACL_LETTER(IMAP_ACL_POST);
	WRITE_ACL_LETTER(IMAP_ACL_MAILBOX_CREATE);
	WRITE_ACL_LETTER(IMAP_ACL_MAILBOX_DELETE);
	WRITE_ACL_LETTER(IMAP_ACL_DELETE);
	WRITE_ACL_LETTER(IMAP_ACL_EXPUNGE);
	WRITE_ACL_LETTER(IMAP_ACL_ADMINISTER);
	/* If any of the members of an obsolete right is included, we must include the obsolete right */
	if (acl & (IMAP_ACL_MAILBOX_CREATE | IMAP_ACL_MAILBOX_DELETE)) {
		*buf++ = IMAP_ACL_UNION_CREATE_LETTER;
	}
	if (acl & (IMAP_ACL_DELETE | IMAP_ACL_EXPUNGE)) {
		*buf++ = IMAP_ACL_UNION_DELETE_LETTER;
	}
	*buf = '\0';
}

#define PARSE_ACL(var) \
	aclstr = strchr(aclbuf, ' '); \
	if (!aclstr) { \
		bbs_error("Invalid ACL entry: %s\n", aclbuf); \
		continue; \
	} \
	aclstr++; \
	var = parse_acl(aclstr);

static int load_acl_file(const char *filename, const char *matchstr, size_t matchlen, int *acl)
{
	char aclbuf[72];
	FILE *fp;
	int found_anyone = 0, found_authenticated = 0;
	int anyone_acl = 0, authenticated_acl = 0;
	int negative_acl = 0;
	int res = -1; /* If no match for this user, we still need to use the defaults. */

	fp = fopen(filename, "r");
	if (!fp) {
		return -1;
	}

	/* The RFC says that server implementations can choose how to apply the ACLs (union rights, or pick most specific match).
	 * We pick the most specific match, but we always apply the negative ACL for a user to the result, if one exists. */

	while ((fgets(aclbuf, sizeof(aclbuf), fp))) {
		char *aclstr;
		if (aclbuf[0] == '-') {
			/* Negative ACL rights. Not required by RFC 4314, but commonly supported.
			 * The negative ACL is a separate entry in the ACL file.
			 * It removes the specified ACL rights, and is NOT the same as DELETEACL (the lack of any ACL)
			 * See RFC 4314 Section 2.
			 * Also note this is NOT the same as +/- in SETACL, which adds or remove the specified rights
			 * from the specified ACL. So you could well have something like SETACL INBOX -jsmith -a
			 * This removes the right that prevents jsmith from administering the mailbox (pardon the double negative).
			 * If jsmith is able to administer the mailbox via some other ACL, then he can manage it; otherwise not.
			 */
			if (!strncasecmp(aclbuf, matchstr, matchlen)) {
				PARSE_ACL(negative_acl);
			}
		} else if (!strncasecmp(aclbuf, matchstr, matchlen)) {
			PARSE_ACL(*acl);
			res = 0;
			break;
		} else if (STARTS_WITH(aclbuf, "anyone ")) { /* XXX IMAP server doesn't really currently support "guest login", so not much different from authenticated */
			found_anyone = 1;
			PARSE_ACL(anyone_acl);
		} else if (STARTS_WITH(aclbuf, "authenticated ")) {
			found_authenticated = 1;
			PARSE_ACL(authenticated_acl);
		}
		/* Dovecot and Cyrus also support $group, but we don't have IMAP groups so just stick with these for now. */
	}
	fclose(fp);

	if (res) { /* Didn't find a user-specific match. If there was a generic match, use that instead. */
		if (found_authenticated) {
			*acl = authenticated_acl;
			res = 0;
		} else if (found_anyone) {
			*acl = anyone_acl;
			res = 0;
		}
	}
	/* Finally, apply any negative ACL. Since this is initialized to 0, we can always do this even if there was no negative ACL. */
	if (!res) {
		*acl = *acl & ~negative_acl;
	}
	return res;
}

void load_acl(struct imap_session *imap, const char *directory, enum mailbox_namespace ns, int *acl)
{
	char fullname[256];
	char matchbuf[256];
	int matchlen;
	char *slash;
#ifdef DEBUG_ACL
	char buf[15];
	bbs_debug(7, "Loading ACLs for user %d for (ns %d) %s\n", mailbox_id(imap->mbox), ns, directory);
#endif

	/* Read .acl file in the maildir to check what the user's perms are, and load them in.
	 * If mailbox doesn't have one, it inherits from its parent.
	 * If no match anywhere, apply defaults. */

	matchlen = snprintf(matchbuf, sizeof(matchbuf), "%s ", bbs_username(imap->node->user));
	snprintf(fullname, sizeof(fullname), "%s/.acl", directory); /* Start off in this directory and traverse up if needed */

	for (;;) {
		if (!load_acl_file(fullname, matchbuf, (size_t) matchlen, acl)) {
			goto done;
		}
		/* Traverse up to the .acl directory in the parent dir */
		/*! \todo Probably should not do this actually, if no .acl file in current, apply defaults immediately */
		slash = strrchr(fullname, '/');
		bbs_assert_exists(slash);
		*slash = '\0'; /* This will always succeed, slash can never be NULL */
		slash = strrchr(fullname, '/');
		bbs_assert_exists(slash);
		*slash = '\0'; /* This will always succeed, slash can never be NULL */
		if (!strcmp(fullname, mailbox_maildir(NULL))) {
			/* XXX About as efficient as calculating strlen(mailbox_maildir(NULL)) in advance, since we have to get the length of this anyways,
			 * unless we do that just once and subtract as needed. */
			break; /* If we reach the root maildir, then stop. There aren't any user ACLs here, and certainly not above either */
		}
		strcpy(slash, "/.acl"); /* Safe, since the buffer has more room than it did initially */
	}

#ifdef DEBUG_ACL
	bbs_debug(8, "No explicit ACL assignments, using defaults\n");
#endif

/* gcc gets a little confused here. IMAP_ACL_DEFAULT_OTHER and IMAP_ACL_DEFAULT_SHARED happen to be the same value,
 * so with -Wduplicated-branches, it will throw a warning here.
 * However, semantically, these are not necessarily the same and so we treat them separately. */
#pragma GCC diagnostic ignored "-Wduplicated-branches"
	/* If no ACLs specified for this user, for this mailbox, go with the default for this namespace */
	if (ns == NAMESPACE_PRIVATE) {
		*acl = IMAP_ACL_DEFAULT_PRIVATE;
	} else if (ns == NAMESPACE_OTHER) {
		*acl = IMAP_ACL_DEFAULT_OTHER;
	} else {
		*acl = IMAP_ACL_DEFAULT_SHARED;
	}
#pragma GCC diagnostic pop

done:
#ifdef DEBUG_ACL
	generate_acl_string(*acl, buf, sizeof(buf));
	bbs_debug(5, "Effective ACL for %s: %s\n", directory, buf);
#else
	return;
#endif
}

int getacl(struct imap_session *imap, const char *directory, const char *mailbox)
{
	char fullname[261]; /* + .acl */
	char buf[256];
	FILE *fp;
	struct dyn_str dynstr;

	snprintf(fullname, sizeof(fullname), "%s/.acl", directory);
	fp = fopen(fullname, "r");
	if (!fp) {
		/* No ACLs, just include the default (current user's ACL???) XXXXX */
		return 0; 
	}

	memset(&dynstr, 0, sizeof(dynstr));

	while ((fgets(buf, sizeof(buf), fp))) {
		char appendbuf[64];
		int len;
		char *username, *aclstr, *s = buf;
		username = strsep(&s, " ");
		aclstr = s;
		bbs_strterm(aclstr, '\n'); /* Remove newline from output */
		len = snprintf(appendbuf, sizeof(appendbuf), " %s %s", username, aclstr); /* For now, this accomplishes (almost) nothing, but in the future we may need to manipulate first */
		dyn_str_append(&dynstr, appendbuf, (size_t) len);
	}

	fclose(fp);

	imap_send(imap, "ACL %s%s", mailbox, S_IF(dynstr.buf));
	if (dynstr.buf) {
		free(dynstr.buf);
	}

	return 0;
}

static bbs_mutex_t acl_lock = BBS_MUTEX_INITIALIZER;

int setacl(struct imap_session *imap, const char *directory, const char *mailbox, const char *user, const char *newacl)
{
	char fullname[261]; /* + .acl */
	char fullname2[264]; /* + .aclnew */
	char findstr[64];
	char buf[256];
	FILE *fp, *fp2;
	size_t userlen;
	int existed = 0;
	int action = 0;

	UNUSED(imap);
	UNUSED(mailbox);

	if (newacl) {
		if (*newacl == '+') {
			action = 1;
			newacl++;
		} else if (*newacl == '-') {
			action = -1;
			newacl++;
		}
	}

	snprintf(fullname, sizeof(fullname), "%s/.acl", directory);
	bbs_mutex_lock(&acl_lock); /* Ordinarily, a global mutex for all SETACLs would be terrible on a large IMAP server, but fine here */
	fp = fopen(fullname, "r+"); /* Open with r+ in case we end up appending to the original file */
	if (!fp) {
		/* No existing ACLs, this is the easy case. Just write a new file and return.
		 * There is technically a race condition possible here, we're the only process using this file,
		 * but another thread could be trying to access it too. So that's why we have a lock. */
		if (action == -1) {
			bbs_debug(3, "No rights to remove - no ACL match for %s\n", user);
			bbs_mutex_unlock(&acl_lock);
			return 0;
		}
		fp = fopen(fullname, "w");
		if (!fp) {
			bbs_error("Failed to open %s for writing\n", fullname);
			bbs_mutex_unlock(&acl_lock);
			return -1;
		}
		/* XXX Should probably validate and verify this first */
		fprintf(fp, "%s %s\n", user, newacl);
		fclose(fp);
		bbs_mutex_unlock(&acl_lock);
		return 0;
	}

	/* We have to read from the current ACL file and write out the new ACL file at the same time. */
	snprintf(fullname2, sizeof(fullname2), "%s/.aclnew", directory);
	fp2 = fopen(fullname2, "w");
	if (!fp2) {
		bbs_error("Failed to open %s for writing\n", fullname2);
		bbs_mutex_unlock(&acl_lock);
		fclose(fp);
		return -1;
	}

	userlen = strlen(user);
	snprintf(findstr, sizeof(findstr), "%s ", user);

	while ((fgets(buf, sizeof(buf), fp))) {
		/* XXX Note that if usernames change, we'll have to update the ACL file.
		 * But it's worth doing it this way as we don't have to translate user IDs <=> usernames
		 * when reading or writing the ACL file. */
		if (existed || strncasecmp(buf, findstr, userlen + 1)) {
			/* Just copy to the new file. */
			fprintf(fp2, "%s", buf); /* Includes a newline already, don't add another one */
		} else {
			/* Okay, we found a string starting with the username, followed by a space (so it's not merely a prefix) */
			if (action) {
				char eff_acl[16];
				int pos = 0;
				const char *oldacl = buf + userlen + 1;
				/* If action == 1 (+), union the old and new ACL.
				 * If action == -1 (-), keep anything in old that isn't in new. */
				while (*oldacl) {
					/* Copy anything over not in the new ACL.
					 * Then for +, concatenate the new (this avoids duplicates)
					 * For -, we're already done. */
					if (!strchr(newacl, *oldacl)) {
						eff_acl[pos++] = '\0';
						if (pos < (int) sizeof(eff_acl) - 1) {
							break; /* Only check bounds when we add to the buffer */
						}
					}
				}
				eff_acl[pos] = '\0';
				if (action == 1) {
					safe_strncpy(eff_acl + pos, newacl, sizeof(eff_acl) - (size_t) pos); /* Since we know the end, can use safe_strncpy instead of strncat */
				}
			} else { /* We want to replace this line */
				/* XXX Should probably validate and verify this first */
				if (newacl) { /* Copy over, unless we're deleting */
					fprintf(fp2, "%s %s\n", user, newacl);
				}
			}
			existed = 1;
			/* Can't break, need to copy over the rest of the file. But since users can only appear once, we know IF will always evaluate to true now */
		}
	}

	if (existed) {
		fclose(fp);
		fclose(fp2);
		/* Replace the old file with the new one */
		if (rename(fullname2, fullname)) {
			bbs_error("rename %s -> %s failed: %s\n", fullname2, fullname, strerror(errno));
			unlink(fullname2);
			bbs_mutex_unlock(&acl_lock);
			return -1;
		}
		bbs_debug(5, "Replaced ACL file %s\n", fullname);
	} else {
		/* No rename needed, just append to the old file after all. */
		/* XXX Should probably validate and verify this first */
		fprintf(fp, "%s %s\n", user, newacl);
		fclose(fp);
		fclose(fp2);
		unlink(fullname2); /* Remove, not needed after all */
		bbs_debug(5, "Updated ACL file %s\n", fullname);
	}
	bbs_mutex_unlock(&acl_lock);
	return 0;
}
