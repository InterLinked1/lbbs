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
 * \brief IMAP Server Flags and Keywords
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <ctype.h>

#if defined(linux) && defined(__GLIBC__)
#include <bsd/string.h>
#endif

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_acl.h"
#include "nets/net_imap/imap_server_flags.h"

void parse_keyword(struct imap_session *imap, const char *s, const char *directory, int create)
{
	char filename[266];
	char buf[32];
	FILE *fp;
	char index = 0;

	if (bbs_assertion_failed(!strlen_zero(directory))) {
		return;
	}

	/* Many keywords start with $, but not all of them do */
	if (imap->numappendkeywords >= MAX_KEYWORDS) {
		bbs_warning("Can't store any more keywords\n"); /* XXX A NO [LIMIT] response might make sense if the whole STORE has failed */
		return;
	}

	/* Check using file in current maildir */
	snprintf(filename, sizeof(filename), "%s/.keywords", directory);
	/* Open the file in read + append mode.
	 * If the file does not yet exist, it should be created.
	 * However, we need to lock if we're appending, so this whole thing must be atomic.
	 */

	mailbox_uid_lock(imap->mbox); /* We're not doing anything with the UID, but that's a global short-lived lock for the mailbox we can use (unlike mailbox_wrlock) */
	fp = fopen(filename, "a+"); /* XXX Silly to reopen this file in every loop of parse_flags_string. In practice, most messages will probably only have 1 keyword, if any. */
	if (unlikely(fp == NULL)) {
		bbs_error("File %s does not exist and could not be created: %s\n", filename, strerror(errno)); /* This really should not happen */
		mailbox_uid_unlock(imap->mbox);
		return;
	}

	/* Unlike dovecot, which indexes 0... 25, since it can still store more in the index file,
	 * we strictly store a max of 26 keywords, indexed a...z, since more are not usable if they can't be stored in the filename
	 * (we don't have an index file, like dovecot does)
	 * This file MUST NOT BE MANUALLY MODIFIED (in particular, keywords MUST NOT be reordered), since the filenames store the index into the file of the keyword.
	 * and such an operation would result in all the keywords changing in arbitrary ways.
	 *
	 * Because keywords are stored per maildir, different 'letters' (indices) in different maildirs for a mailbox
	 * may in fact refer to the same actual keyword, and vice versa.
	 */

	while ((fgets(buf, sizeof(buf), fp))) {
		const char *keyword = buf + 2; /* Skip index + space */
		bbs_strterm(buf, '\n');
		if (!strlen_zero(keyword) && !strcmp(keyword, s)) {
			imap->appendkeywords[imap->numappendkeywords++] = buf[0]; /* Safe, since we know we're in bounds */
			fclose(fp);
			mailbox_uid_unlock(imap->mbox);
			return;
		}
		index++;
	}

	if (create) {
		/* Didn't find it. Add it if we can. */
		if (index >= MAX_KEYWORDS) {
			bbs_warning("Can't store any new keywords for this maildir (already have %d)\n", index);
		} else {
			char newindex = (char) ('a' + index);
			fprintf(fp, "%c %s\n", newindex, s);
			imap->appendkeywords[imap->numappendkeywords++] = newindex; /* Safe, since we know we're in bounds */
			imap->createdkeyword = 1;
		}
	}

	mailbox_uid_unlock(imap->mbox);
	fclose(fp);
}

int __gen_keyword_names(const char *s, char *inbuf, size_t inlen, const char *directory)
{
	FILE *fp;
	char fbuf[32];
	char filename[266];
	char *buf = inbuf;
	int matches = 0;
	int left = (int) inlen;
	const char *custom_start = s;

	snprintf(filename, sizeof(filename), "%s/.keywords", directory);

	*buf = '\0';
	fp = fopen(filename, "r");
	if (!fp) {
#ifdef DEBUG_FLAGS
		bbs_debug(9, "maildir %s has no keywords\n", directory);
#endif
		return 0;
	}

	while ((fgets(fbuf, sizeof(fbuf), fp))) {
		if (!s || strchr(s, fbuf[0])) {
			matches++;
			bbs_strterm(fbuf, '\n');
			SAFE_FAST_COND_APPEND_NOSPACE(inbuf, inlen, buf, left, 1, " %s", fbuf + 2);
		}
	}

	if (s) {
		int keywordslen = 0;
		while (!strlen_zero(s)) {
			if (islower(*s)) {
				keywordslen++;
			}
			s++;
		}

		if (keywordslen > matches) {
			/* Print out the keywords in the mapping file and the ones in the filename for comparison. */
			char mappings[27];
			int mpos = 0;
			rewind(fp);
			while ((fgets(fbuf, sizeof(fbuf), fp))) {
				if (!s || strchr(s, fbuf[0])) {
					mappings[mpos++] = fbuf[0];
					if (mpos >= (int) sizeof(mappings) - 1) {
						break;
					}
				}
			}
			mappings[mpos] = '\0';
			while (*custom_start && !islower(*custom_start)) {
				custom_start++;
			}

			bbs_warning("File has %d custom flags (%s), but we only have mappings for %d of them (%s)?\n", keywordslen, custom_start, matches, mappings);
		}
	}
	fclose(fp);
	return matches;
}

int __parse_flags_string(struct imap_session *imap, char *s, const char *directory)
{
	int flags = 0;
	char *f;

	/* Reset keywords */
	if (imap) {
		imap->appendkeywords[0] = '\0';
		imap->numappendkeywords = 0;
		imap->createdkeyword = 0;
	}

	while ((f = strsep(&s, " "))) {
		if (strlen_zero(f)) {
			continue;
		}
		if (!strcasecmp(f, FLAG_NAME_FLAGGED)) {
			flags |= FLAG_BIT_FLAGGED;
		} else if (!strcasecmp(f, FLAG_NAME_SEEN)) {
			flags |= FLAG_BIT_SEEN;
		} else if (!strcasecmp(f, FLAG_NAME_ANSWERED)) {
			flags |= FLAG_BIT_ANSWERED;
		} else if (!strcasecmp(f, FLAG_NAME_DELETED)) {
			flags |= FLAG_BIT_DELETED;
		} else if (!strcasecmp(f, FLAG_NAME_DRAFT)) {
			flags |= FLAG_BIT_DRAFT;
		} else if (!strcasecmp(f, FLAG_NAME_RECENT)) {
			bbs_warning("The \\Recent flag cannot be set by clients\n");
		} else if (*f == '\\') {
			bbs_warning("Failed to parse flag: %s\n", f); /* Unknown non-custom flag */
		} else if (imap) { /* else, it's a custom flag (keyword), if we have a mailbox, check the translation. */
			parse_keyword(imap, f, directory, 1);
		}
	}
	if (imap) {
		imap->appendkeywords[imap->numappendkeywords] = '\0'; /* Null terminate the keywords buffer */
	}
	return flags;
}

int parse_flags_letters(const char *restrict f, const char **keywords)
{
	int flags = 0;

	while (*f) {
		if (!isalpha(*f)) {
			/* This way we can pass in the start of flags in the filename, and it will stop parsing at the appropriate point */
#if 0
			imap_debug(8, "Stopping flags parsing since encountered non-alpha char %d\n", *f);
#endif
			break;
		}
		switch (*f) {
			case FLAG_DRAFT:
				flags |= FLAG_BIT_DRAFT;
				break;
			case FLAG_FLAGGED:
				flags |= FLAG_BIT_FLAGGED;
				break;
			case FLAG_SEEN:
				flags |= FLAG_BIT_SEEN;
				break;
			case FLAG_TRASHED:
				flags |= FLAG_BIT_DELETED;
				break;
			case FLAG_REPLIED:
				flags |= FLAG_BIT_ANSWERED;
				break;
			case 'a' ... 'z':
				if (keywords) {
					*keywords = f;
				}
				return flags; /* If we encounter keywords (custom flags), we know we're done parsing builtin flags */
			case FLAG_PASSED:
			default:
				bbs_warning("Unhandled flag: %c\n", *f);
		}
		f++;
	}

	return flags;
}

int parse_flags_letters_from_filename(const char *filename, int *flags, char *keywordsbuf)
{
	const char *keywords = NULL;
	const char *flagstr = strchr(filename, ':');
	if (!flagstr++) {
		return -1;
	}
	*flags = parse_flags_letters(flagstr + 2, &keywords); /* Skip first 2 since it's always just "2," and real flags come after that */
	if (keywordsbuf) {
		/* The buffer and the string to copy SHOULD always be 26 or fewer characters,
		 * but if the file were maliciously renamed to be longer, that would risk a buffer overflow.
		 * We know for sure the buffer will be of size 27, but can't guarantee strlen(keywords) <= 26
		 */
		safe_strncpy(keywordsbuf, S_IF(keywords), MAX_KEYWORDS + 1);
	}
	return 0;
}

void gen_flag_letters(int flags, char *buf, size_t len)
{
	/* Note: these MUST be in alphabetic order to comply with maildir filename format! */
	bbs_assert(len > NUM_FLAG_BITS); /* Make sure the buffer will be large enough. */

	SET_LETTER_IF_FLAG(FLAG_BIT_DRAFT, FLAG_DRAFT); /* D */
	SET_LETTER_IF_FLAG(FLAG_BIT_FLAGGED, FLAG_FLAGGED); /* F */
	SET_LETTER_IF_FLAG(FLAG_BIT_ANSWERED, FLAG_REPLIED); /* D */
	SET_LETTER_IF_FLAG(FLAG_BIT_SEEN, FLAG_SEEN); /* S */
	SET_LETTER_IF_FLAG(FLAG_BIT_DELETED, FLAG_TRASHED); /* T */
	*buf = '\0';
}

void gen_flag_names(const char *flagstr, char *fullbuf, size_t len)
{
	char *buf = fullbuf;
	int left = (int) len;
	*buf = '\0';
	SAFE_FAST_COND_APPEND(fullbuf, len, buf, left, strchr(flagstr, FLAG_DRAFT), FLAG_NAME_DRAFT);
	SAFE_FAST_COND_APPEND(fullbuf, len, buf, left, strchr(flagstr, FLAG_FLAGGED), FLAG_NAME_FLAGGED);
	SAFE_FAST_COND_APPEND(fullbuf, len, buf, left, strchr(flagstr, FLAG_REPLIED), FLAG_NAME_ANSWERED);
	SAFE_FAST_COND_APPEND(fullbuf, len, buf, left, strchr(flagstr, FLAG_SEEN), FLAG_NAME_SEEN);
	SAFE_FAST_COND_APPEND(fullbuf, len, buf, left, strchr(flagstr, FLAG_TRASHED), FLAG_NAME_DELETED);
	SAFE_FAST_COND_APPEND(fullbuf, len, buf, left, strchr(flagstr, FLAG_RECENT), FLAG_NAME_RECENT);
}

int restrict_flags(int acl, int *flags)
{
	int flagpermsdenied = 0;

	/* Check if user is authorized to set these flags. */
	if (*flags & FLAG_BIT_SEEN && !IMAP_HAS_ACL(acl, IMAP_ACL_SEEN)) {
		bbs_debug(3, "User denied access to modify \\Seen flag\n");
		*flags &= ~FLAG_BIT_SEEN;
		flagpermsdenied++;
	}
	if (*flags & FLAG_BIT_DELETED && !IMAP_HAS_ACL(acl, IMAP_ACL_DELETE)) {
		bbs_debug(3, "User denied access to modify \\Deleted flag\n");
		*flags &= ~FLAG_BIT_DELETED;
		flagpermsdenied++;
	}
	if (!IMAP_HAS_ACL(acl, IMAP_ACL_WRITE)) {
		/* Cannot set any other remaining flags */
		*flags &= (*flags & (FLAG_BIT_SEEN | FLAG_BIT_DELETED)); /* Restrict to these two flags, if they are set. */
		flagpermsdenied++;
	}
	return flagpermsdenied;
}

int translate_maildir_flags(struct imap_session *imap, const char *oldmaildir, const char *oldfilenamefull, const char *oldfilename, const char *newmaildir, int destacl)
{
	char keywords[256] = "";
	char newflagletters[53] = "";
	int numkeywords;
	int oldflags;

	/* Fix a little "oopsie" in the current implementation.
	 * Because keywords are stored *per mailbox*, rather than globally (either per account, or all mailboxes),
	 * when messages are moved or copied between folders, the mapping between the letters in the filename
	 * and the keywords to which they correspond MAY change.
	 * In particular, there is NO GUARANTEE that they will NOT change.
	 * Therefore, we must translate the letters in the old filename to the keywords themselves,
	 * and then translate them back to the letters for the new folder (which may create them if needed).
	 * This MUST be done after any copy or move operation between folders.
	 *
	 * Ideally, this would be an atomic operation done inside maildir_copy_msg or maildir_move_msg,
	 * but since it isn't, we call this immediately after those calls, if they succeed.
	 *
	 * Because the semantics of flags are purely within the IMAP module, the mod_mail module
	 * cannot currently handle this logic, so this step has to be done manually in the IMAP module.
	 * If in the future, mod_mail is aware of IMAP keywords, this logic should be moved there
	 * and abstracted away from the IMAP module (i.e. done automatically on any move or copy). */

	/* Get the old keyword names themselves */
	numkeywords = __gen_keyword_names(oldfilename, keywords, sizeof(keywords), oldmaildir); /* prepends a space before all of them, so this (usually) works out great */

	if (numkeywords <= 0) {
#ifdef EXTRA_DEBUG
		bbs_debug(8, "No keywords require translation for %s / %s\n", oldmaildir, oldfilename);
#endif
		return 0; /* If it doesn't have any keywords now, we don't need to do anything. */
	}

	/* Extract current system flags, and any keywords */
	parse_flags_letters_from_filename(oldfilename, &oldflags, NULL);

	/* Convert keyword names to the letters in the new directory */
	__parse_flags_string(imap, keywords, newmaildir); /* Note: __parse_flags_string "uses up" keyword so don't attempt to print it out afterwards */

	/* Per RFC 4314, we should only copy the flags over if the user has permission to do so.
	 * Even if the user does not have permission, per the RFC we must not fail the COPY/APPEND with a NO,
	 * we just silently ignore those flags.
	 * Since we already have to translate them anyways, this is a perfect place to
	 * remove any flags that the user is not allowed to set in the new directory.
	 */
	restrict_flags(destacl, &oldflags);

	/* Now, we need to replace the original keyword letters with the ones for the new directory.
	 * The lengths will be the same, the letters themselves may not be.
	 * newflagletters is all the flags, so we need to preserve the system flags (uppercase) too.
	 */
	gen_flag_letters(oldflags, newflagletters, sizeof(newflagletters)); /* Copy the old uppercase flags over */
	if (IMAP_HAS_ACL(imap->acl, IMAP_ACL_WRITE)) {
		bbs_append_string(newflagletters, imap->appendkeywords, sizeof(newflagletters) - 1); /* Append the keywords */
	}

	bbs_debug(5, "Flags for %s have changed to '%s' due to location/permission change\n", oldfilename, newflagletters);
	return maildir_msg_setflags(imap, 0, oldfilenamefull, newflagletters);
}

void generate_flag_names_full(struct imap_session *imap, const char *filename, char *bufstart, size_t bufsize, char **bufptr, int *lenptr)
{
	char flagsbuf[256] = "";
	int has_flags;
	int custom_keywords;

	char *buf = *bufptr;
	size_t len = (size_t) *lenptr;

	if (isdigit(*filename)) { /* We have an entire filename */
		filename = strchr(filename, ':'); /* Skip everything before the flags, so we don't e.g. interpret ,S= as the Seen flag. */
		if (!filename) {
			filename = ""; /* There ain't no flags here */
		}
	} /* else, must just have the "flags" portion of the filename to begin with */

	gen_flag_names(filename, flagsbuf, sizeof(flagsbuf));
	has_flags = flagsbuf[0] ? 1 : 0;
	SAFE_FAST_COND_APPEND(bufstart, bufsize, buf, len, 1, "FLAGS (%s", flagsbuf);
	/* If there are any keywords (custom flags), include those as well */
	custom_keywords = gen_keyword_names(imap, filename, flagsbuf, sizeof(flagsbuf));
	if (has_flags) {
		SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufsize, buf, len, custom_keywords > 0, "%s", flagsbuf);
	} else {
		/* No leading space if there were no other flags, would be more elegantly if everything just appended to the same buffer using _NOSPACE */
		SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufsize, buf, len, custom_keywords > 0, "%s", flagsbuf + 1); /* flagsbuf + 1 is safe since custom_keywords > 0 */
	}
	SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufsize, buf, len, 1, ")");

	*bufptr = buf;
	*lenptr = (int) len;
}

int maildir_msg_setflags_modseq(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters, unsigned long *newmodseq)
{
	char fullfilename[524];
	char newflags[512] = "";
	char *newbuf = newflags;
	int newlen = sizeof(newflags);
	char dirpath[256];
	char *tmp, *filename;
	unsigned long modseq;

	/* Generate new filename and do the rename */
	safe_strncpy(dirpath, origname, sizeof(dirpath));
	/* For RFC 7162 CONDSTORE, we also need to increment the MODSEQ.
	 * So we might end up turning a filename like:
	 * 123456789,S=123,U=13:2,S     -> 123456789,S=123,U=13,M=1:2,S
	 * OR
	 * 123456789,S=123,U=13,M=1:2,S -> 123456789,S=123,U=13,M=2:2,S
	 */
	tmp = strrchr(dirpath, '/');
	if (likely(tmp != NULL)) {
		*tmp++ = '\0';
		filename = tmp;
		bbs_strterm(filename, ':'); /* Everything after the : is flags, which we're fully replacing anyways */
	} else {
		bbs_error("Invalid filename: %s\n", origname);
		return -1;
	}

	if (strchr(newflagletters, ',')) {
		/* This should just contain upper and lower case letters.
		 * If there's a comma, something got concatenated wrong somewhere,
		 * and we'll create an invalid maildir filename. */
		bbs_warning("Invalid flag letters: '%s'\n", newflagletters);
	}

	/* First, check if the filename itself would actually change, without updating MODSEQ.
	 * If not, then don't update MODSEQ, or do any rename at all. */
	snprintf(fullfilename, sizeof(fullfilename), "%s/%s:2,%s", dirpath, filename, newflagletters);
	if (!strcmp(origname, fullfilename)) {
		return 0; /* If the flags didn't change, no point in making an unnecessary system call, or more importantly, sending unnecessary unilateral FETCH responses */
	}

	/* To make things easier, M= will always come after U=. So we'll either be terminating or appending. */
	tmp = strstr(filename, ",M=");
	if (!tmp) {
		/* In theory, any messages in cur should always have a modseq.
		 * In practice, since this functionality is being added later, for compatibility, old messages may not,
		 * so properly handle that case. */
		modseq = maildir_new_modseq(imap->mbox, dirpath);
		snprintf(fullfilename, sizeof(fullfilename), "%s/%s,M=%lu:2,%s", dirpath, filename, modseq, newflagletters); /* Start at 1 initially */
	} else {
		*tmp = '\0'; /* Already has one, update it */
		/* The RFC is a bit vague on what the new MODSEQ should actually be, but I think it should also be greater than any existing MODSEQ. */
		modseq = maildir_new_modseq(imap->mbox, dirpath);
		snprintf(fullfilename, sizeof(fullfilename), "%s/%s,M=%lu:2,%s", dirpath, filename, modseq, newflagletters);
	}

	if (newmodseq) {
		*newmodseq = modseq;
	}

	/*! \todo BUGBUG Since this calls rename, callers to maildir_msg_setflags should probably try to WRLOCK the mailbox first, in case of a race condition. Otherwise this may fail. */

	bbs_debug(4, "Renaming %s -> %s\n", origname, fullfilename);
	if (rename(origname, fullfilename)) {
		bbs_error("rename %s -> %s failed: %s\n", origname, fullfilename, strerror(errno));
		return -1;
	}

	/*
	 * RFC 7162 3.2.4:
	 * Once a CONDSTORE enabling command is issued by the client, the server
	 * MUST automatically include both UID and mod-sequence data in all
	 * subsequent untagged FETCH responses (until the connection is closed),
	 * whether they were caused by a regular STORE/UID STORE, a STORE/UID
	 * STORE with an UNCHANGEDSINCE modifier, a FETCH/UID FETCH that
	 * implicitly set the \Seen flag, or an external agent.  Note that this
	 * rule doesn't affect untagged FETCH responses caused by a FETCH
	 * command that doesn't include UID and/or a MODSEQ FETCH data item (and
	 * doesn't implicitly set the \Seen flag) or UID FETCH without the
	 * MODSEQ FETCH data item.
	 */

	/* If newmodseq is not NULL, then we need to send responses as needed. XXX What if it's not? */

	/* Send unilateral untagged FETCH responses to everyone except this session, to notify of the new flags */
	generate_flag_names_full(imap, newflagletters, newflags, sizeof(newflags), &newbuf, &newlen);
	if (seqno) { /* Skip for merely translating flag mappings between maildirs */
		char *end;
		unsigned int uid;
		maildir_parse_uid_from_filename(filename, &uid);
		/* Right now, dir ends in '/cur', since it's the physical maildir cur dir path,
		 * here, we want just the base maildir path (without '/cur' at the end). */
		end = strrchr(dirpath, '/');
		if (!bbs_assertion_failed(end != NULL)) {
			*end = '\0';
		}
		send_untagged_fetch(imap, dirpath, seqno, uid, modseq, newflags);
	}
	return 0;
}

int maildir_msg_setflags(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters)
{
	return maildir_msg_setflags_modseq(imap, seqno, origname, newflagletters, NULL);
}

int maildir_msg_setflags_notify(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters)
{
	unsigned long newmodseq; /* newmodseq will be non NULL, so we'll know that we need to send out the FETCH accordingly */
	return maildir_msg_setflags_modseq(imap, seqno, origname, newflagletters, &newmodseq);
}
