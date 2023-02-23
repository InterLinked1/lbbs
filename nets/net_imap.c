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
 * \brief RFC9051 Internet Message Access Protocol (IMAP) version 4rev2 (updates RFC3501 IMAP 4rev1)
 *
 * \note STARTTLS is not supported for cleartext IMAP, as proposed in RFC2595, as this guidance
 *       is obsoleted by RFC8314. Implicit TLS (IMAPS) should be preferred.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <dirent.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/test.h"

#include "include/mod_mail.h"

/* IMAP ports */
#define DEFAULT_IMAP_PORT 143
#define DEFAULT_IMAPS_PORT 993

static int imap_port = DEFAULT_IMAP_PORT;
static int imaps_port = DEFAULT_IMAPS_PORT;

static pthread_t imap_listener_thread = -1;

static int imap_enabled = 0, imaps_enabled = 1;
static int imap_socket = -1, imaps_socket = -1;

static int imap_debug_level = 10;
#define imap_debug(level, fmt, ...) if (imap_debug_level >= level) { bbs_debug(level, fmt, ## __VA_ARGS__); }

#undef dprintf
#define _imap_reply(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); dprintf(imap->wfd, fmt, ## __VA_ARGS__);
#define imap_send(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", "*", ## __VA_ARGS__)
#define imap_reply(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", S_IF(imap->tag), ## __VA_ARGS__)

/* All IMAP traversals must be ordered, so we can't use these functions or we'll get a ~random (at least incorrect) order */
/* Sequence numbers must strictly be in order, if they aren't, all sorts of weird stuff will happened.
 * I know this because I tried using these functions first, and it didn't really work.
 * Because scandir allocates memory for all the files in a directory up front, it could result in a lot of memory usage.
 * Technically, for this reason, may want to limit the number of messages in a single mailbox (folder) for this reason.
 */
#define opendir __Do_not_use_readdir_or_opendir_use_scandir
#define readdir __Do_not_use_readdir_or_opendir_use_scandir
#define closedir __Do_not_use_readdir_or_opendir_use_scandir

struct imap_session {
	int rfd;
	int wfd;
	char *tag;
	struct bbs_node *node;
	struct mailbox *mbox;
	char *folder;
	/* maildir */
	char dir[256];
	char newdir[260]; /* 4 more, for /new and /cur */
	char curdir[260];
	unsigned int uidvalidity;
	unsigned int uidnext;
	/* Traversal flags */
	unsigned int totalnew;		/* In "new" maildir. Will be moved to "cur" when seen. */
	unsigned int totalcur;		/* In "cur" maildir. */
	unsigned int totalunseen;	/* Messages with Unseen flag (or more rather, without the Seen flag). */
	unsigned int firstunseen;	/* Oldest message that is not Seen. */
	unsigned int innew:1; /* So we can use the same callback for both new and cur */
	unsigned int readonly:1;	/* SELECT vs EXAMINE */
};

static void imap_destroy(struct imap_session *imap)
{
	/* Do not free tag, since it's stack allocated */
	free_if(imap->folder);
}

/*! \brief Faster than strncat, since we store our position between calls, but maintain its safety */
#define SAFE_FAST_COND_APPEND(bufstart, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, buflen, bufpos == bufstart ? fmt : " " fmt, ## __VA_ARGS__); \
		bufpos += _bytes; \
		buflen -= _bytes; \
		if (buflen <= 0) { \
			bbs_warning("Buffer truncation\n"); \
			*(bufpos + buflen - 1) = '\0';  \
		} \
	}

#define SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, buflen, fmt, ## __VA_ARGS__); \
		bufpos += _bytes; \
		buflen -= _bytes; \
		if (buflen <= 0) { \
			bbs_warning("Buffer truncation\n"); \
			*(bufpos + buflen - 1) = '\0';  \
		} \
	}

/* We traverse cur first, since messages from new are moved to cur, and we don't want to double count them */
#define IMAP_TRAVERSAL(imap, callback) \
	MAILBOX_TRYRDLOCK(imap); \
	imap->totalnew = 0; \
	imap->totalcur = 0; \
	imap->totalunseen = 0; \
	imap->firstunseen = 0; \
	imap->innew = 0; \
	imap->uidvalidity = 0; \
	imap->uidnext = 0; \
	imap_traverse(imap->curdir, callback, imap); \
	imap->innew = 1; \
	imap_traverse(imap->newdir, callback, imap); \
	if (!imap->uidvalidity || !imap->uidnext) { \
		get_uidnext(imap, imap->dir); \
	} \
	mailbox_unlock(imap->mbox);

#define FLAG_BIT_FLAGGED (1 << 0)
#define FLAG_BIT_SEEN (1 << 1)
#define FLAG_BIT_ANSWERED (1 << 2)
#define FLAG_BIT_DELETED (1 << 3)
#define FLAG_BIT_DRAFT (1 << 4)
/*! \note Must be the number of FLAG_BIT macros */
#define NUM_FLAG_BITS 5

#define FLAG_NAME_FLAGGED "\\Flagged"
#define FLAG_NAME_SEEN "\\Seen"
#define FLAG_NAME_ANSWERED "\\Answered"
#define FLAG_NAME_DELETED "\\Deleted"
#define FLAG_NAME_DRAFT "\\Draft"

#define IMAP_REV "IMAP4rev1"
/*! \todo need to add actual capabilities here too */
#define IMAP_CAPABILITIES IMAP_REV
#define IMAP_FLAGS FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN " " FLAG_NAME_ANSWERED " " FLAG_NAME_DELETED " " FLAG_NAME_DRAFT
#define HIERARCHY_DELIMITER "."

/* maildir flags, that appear in a single string and must appear in ASCII order: https://cr.yp.to/proto/maildir.html */
#define FLAG_DRAFT 'D'
#define FLAG_FLAGGED 'F'
#define FLAG_PASSED 'P'
#define FLAG_REPLIED 'R'
#define FLAG_SEEN 'S'
#define FLAG_TRASHED 'T'

#define SET_LETTER_IF_FLAG(flag, letter) \
	if (flags & flag) { \
		*buf++ = letter; \
	}

static int parse_flags_string(char *s)
{
	int flags = 0;
	char *f;
	while ((f = strsep(&s, " "))) {
		if (!strcmp(f, FLAG_NAME_FLAGGED)) {
			flags |= FLAG_BIT_FLAGGED;
		} else if (!strcmp(f, FLAG_NAME_SEEN)) {
			flags |= FLAG_BIT_SEEN;
		} else if (!strcmp(f, FLAG_NAME_ANSWERED)) {
			flags |= FLAG_BIT_ANSWERED;
		} else if (!strcmp(f, FLAG_NAME_DELETED)) {
			flags |= FLAG_BIT_DELETED;
		} else if (!strcmp(f, FLAG_NAME_DRAFT)) {
			flags |= FLAG_BIT_DRAFT;
		} else {
			bbs_warning("Failed to parse flag: %s\n", f);
		}
	}
	return flags;
}

static int parse_flags_letters(const char *f)
{
	int flags = 0;

	while (*f) {
		if (!isalpha(*f)) {
			/* This way we can pass in the start of flags in the filename, and it will stop parsing at the appropriate point */
			imap_debug(6," Stopping flags parsing since encountered non-alpha char %d\n", *f);
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
			case FLAG_PASSED:
			case FLAG_REPLIED:
			default:
				bbs_warning("Unhandled flag: %c\n", *f);
		}
		f++;
	}

	return flags;
}

static void gen_flag_letters(int flags, char *buf, size_t len)
{
	/* Note: these MUST be in alphabetic order to comply with maildir filename format! */
	bbs_assert(len > NUM_FLAG_BITS); /* Make sure the buffer will be large enough. */

	SET_LETTER_IF_FLAG(FLAG_BIT_DRAFT, FLAG_DRAFT); /* D */
	SET_LETTER_IF_FLAG(FLAG_BIT_FLAGGED, FLAG_FLAGGED); /* F */
	SET_LETTER_IF_FLAG(FLAG_BIT_SEEN, FLAG_SEEN); /* S */
	SET_LETTER_IF_FLAG(FLAG_BIT_DELETED, FLAG_TRASHED); /* T */
	*buf = '\0';
}

static void gen_flag_names(const char *flagstr, char *fullbuf, size_t len)
{
	char *buf = fullbuf;
	int left = len;
	*buf = '\0';
	SAFE_FAST_COND_APPEND(fullbuf, buf, left, strchr(flagstr, FLAG_DRAFT), FLAG_NAME_DRAFT);
	SAFE_FAST_COND_APPEND(fullbuf, buf, left, strchr(flagstr, FLAG_FLAGGED), FLAG_NAME_FLAGGED);
	SAFE_FAST_COND_APPEND(fullbuf, buf, left, strchr(flagstr, FLAG_SEEN), FLAG_NAME_SEEN);
}

static int test_flags_parsing(void)
{
	char buf[64] = FLAG_NAME_DELETED " " FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN;
	bbs_test_assert_equals(FLAG_BIT_DELETED | FLAG_BIT_FLAGGED | FLAG_BIT_SEEN, parse_flags_string(buf));
	bbs_test_assert_equals(FLAG_BIT_DRAFT | FLAG_BIT_SEEN, parse_flags_letters("DS"));

	gen_flag_letters(FLAG_BIT_FLAGGED | FLAG_BIT_SEEN, buf, sizeof(buf));
	bbs_test_assert_str_equals("FS", buf);

	gen_flag_names("FS", buf, sizeof(buf));
	bbs_test_assert_str_equals(FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN, buf);

	return 0;

cleanup:
	return -1;
}

#define REQUIRE_ARGS(s) \
	if (!s || !*s) { \
		imap_reply(imap, "BAD Missing arguments"); \
		return 0; \
	}

/*! \brief Strip begin/end quotes from a string */
#define STRIP_QUOTES(s) { \
	if (*s == '"') { \
		char *tmps; \
		s++; \
		tmps = strrchr(s, '"'); \
		if (tmps && !*(tmps + 1)) { \
			*tmps = '\0'; \
		} \
	} \
}

#define REPLACE(var, val) free_if(var); var = strdup(val);

/*! \todo There is locking in a few places, but there probably needs to be a lot more of it.
 * POP3 WRLOCKs the entire mailbox when it starts a session,
 * and we need to ensure that we try to at least grab a RDLOCK when doing anything that
 * could potentially interfere with that. */
#define MAILBOX_TRYRDLOCK(imap) \
	if (mailbox_rdlock(imap->mbox)) { \
		imap_reply(imap, "NO Mailbox busy"); \
		return 0; \
	}

static int set_maildir(struct imap_session *imap, const char *mailbox)
{
	if (strlen_zero(mailbox)) {
		imap_reply(imap, "BAD Missing argument");
		return -1;
	}

	/* With the maildir format, the INBOX is the top-level maildir for a user.
	 * Other directories are subdirectories */
	if (!strcasecmp(mailbox, "INBOX")) {
		safe_strncpy(imap->dir, mailbox_maildir(imap->mbox), sizeof(imap->dir));
	} else {
		/*! \todo Add support for subdirectories (translate to periods for maildir) */
		/* For subdirectories, if they don't exist, don't automatically create them. */
		/* need to prefix with . for maildir++ format */
		snprintf(imap->dir, sizeof(imap->dir), "%s/.%s", mailbox_maildir(imap->mbox), mailbox);
		if (eaccess(imap->dir, R_OK)) {
			imap_reply(imap, "NO No such mailbox '%s'", mailbox);
			return -1;
		}
	}

	imap_debug(3, "New effective maildir is %s\n", imap->dir);
	snprintf(imap->newdir, sizeof(imap->newdir), "%s/new", imap->dir);
	snprintf(imap->curdir, sizeof(imap->curdir), "%s/cur", imap->dir);
	return mailbox_maildir_init(imap->dir);
}

#define get_uidnext(imap, directory) mailbox_get_next_uid(imap->mbox, directory, 0, &imap->uidvalidity, &imap->uidnext)

static int on_select(const char *dir_name, const char *filename, struct imap_session *imap)
{
	char *flags;

	imap_debug(4, "Analyzing file %s/%s\n", dir_name, filename);

	/* RECENT is not the same as UNSEEN.
	 * In the context of maildir, RECENT refers to messages in the new directory.
	 * UNSEEN is messages that aren't read (i.e. not marked as \Seen). */

	if (imap->innew) {
		imap->totalnew += 1;
		imap->totalunseen += 1; /* If it's in the new dir, it definitely can't have been seen yet. */
	} else {
		imap->totalcur += 1;
		flags = strchr(filename, ':');
		if (!flags++) {
			bbs_error("File %s/%s is noncompliant with maildir\n", dir_name, filename);
		} else if (!strlen_zero(flags)) {
			unsigned int uid = 0;
			char *uidstr = strstr(filename, ",U=");
			flags++;
			if (uidstr) {
				uidstr += STRLEN(",U=");
				if (!strlen_zero(uidstr)) {
					uid = atoi(uidstr);
				}
			}
			if (!strchr(flags, FLAG_SEEN)) {
				imap->totalunseen += 1;
				/* scandir will traverse in the order files were added,
				 * which if the mailbox were read-only, would line up with the filename ordering,
				 * but otherwise there's no guarantee of this, since messages can be moved.
				 * So explicitly look for the message with the smallest UID.
				 */
				if (!imap->firstunseen) {
					imap->firstunseen = uid; /* If it's the first unseen message in the traversal, use that. */
				} else {
					imap->firstunseen = MIN(imap->firstunseen, uid); /* Otherwise, keep the lowest numbered one. */
				}
			}
		}
	}

	if (imap->innew && !imap->readonly) {
		maildir_move_new_to_cur(imap->mbox, imap->dir, imap->curdir, imap->newdir, filename, &imap->uidvalidity, &imap->uidnext);
	}

	return 0;
}

static int imap_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, struct imap_session *imap), struct imap_session *imap)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res;

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		if ((res = on_file(path, entry->d_name, imap))) {
			break; /* If the handler returns non-zero then stop */
		}
	}
	free(entries);
	return res;
}

static int handle_select(struct imap_session *imap, char *s, int readonly)
{
	char *mailbox = strsep(&s, " "); /* The STATUS command will have additional arguments */

	REQUIRE_ARGS(mailbox);
	STRIP_QUOTES(mailbox);

	/*! \todo need to save/restore current maildir for STATUS, so it doesn't mess up the selected mailbox? */
	if (set_maildir(imap, mailbox)) { /* Note that set_maildir handles mailbox being "INBOX" */
		return 0;
	}
	if (readonly <= 1) { /* SELECT and EXAMINE should update currently selected mailbox, STATUS should not */
		REPLACE(imap->folder, mailbox);
	}
	if (readonly == 1) {
		imap->readonly = readonly;
	}
	IMAP_TRAVERSAL(imap, on_select);
	if (readonly <= 1) { /* SELECT, EXAMINE */
		imap_send(imap, "FLAGS (%s)", IMAP_FLAGS);
		imap_send(imap, "%u EXISTS", imap->totalnew + imap->totalcur); /* Number of messages in the mailbox. */
		imap_send(imap, "%u RECENT", imap->totalnew); /* Number of messages with \Recent flag (maildir: new, instead of cur). */
		if (imap->firstunseen) {
			/* Both of these are supposed to be firstunseen (the first one is NOT totalunseen) */
			imap_send(imap, "OK [UNSEEN %u] Message %u is first unseen", imap->firstunseen, imap->firstunseen);
		}
		imap_send(imap, "OK [UIDVALIDITY %u] UIDs valid", imap->uidvalidity);
		/* uidnext is really the current max UID allocated. The next message will have at least UID of uidnext + 1, but it could be larger. */
		imap_send(imap, "OK [UIDNEXT %u] Predicted next UID", imap->uidnext + 1);
		/* Some other stuff might appear here, e.g. HIGHESTMODSEQ (RFC4551) that we don't currently support. */
		/* XXX All mailboxes are READ-WRITE right now, but could be just READ-ONLY. Need to add ACL extensions for that. */
		imap_reply(imap, "OK [%s] %s completed", "READ-WRITE", readonly ? "EXAMINE" : "SELECT");
	} else if (readonly == 2) { /* STATUS */
		/*! \todo imap->totalnew and imap->totalcur, etc. are now for this other mailbox we one-offed, rather than currently selected.
		 * Will that mess anything up? Maybe we should save these in tmp vars, and only set on the imap struct if readonly <= 1? */
		char status_items[84] = "";
		if (!strlen_zero(s)) {
			char *pos = status_items;
			int left = sizeof(status_items);
			SAFE_FAST_COND_APPEND(status_items, pos, left, strstr(s, "MESSAGES"), "MESSAGES %d", imap->totalnew + imap->totalcur);
			SAFE_FAST_COND_APPEND(status_items, pos, left, strstr(s, "RECENT"), "RECENT %d", imap->totalnew);
			SAFE_FAST_COND_APPEND(status_items, pos, left, strstr(s, "UIDNEXT"), "UIDNEXT %d", imap->uidnext + 1);
			SAFE_FAST_COND_APPEND(status_items, pos, left, strstr(s, "UIDVALIDITY"), "UIDVALIDITY %d", imap->uidvalidity);
			/* Unlike with SELECT, this is the TOTAL number of unseen messages, not merely the first one */
			SAFE_FAST_COND_APPEND(status_items, pos, left, strstr(s, "UNSEEN"), "UNSEEN %d", imap->totalunseen);
		}
		imap_send(imap, "STATUS %s (%s)", mailbox, status_items);
		imap_reply(imap, "OK STATUS completed");
	}
	return 0;
}

#define EMPTY_QUOTES "\"\""
#define QUOTED_ROOT "\"/\""

/*! \brief Determine if the interpreted result of the LIST arguments matches a directory in the maildir */
static inline int list_match(const char *dirname, const char *query)
{
	const char *a, *b;

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
			continue; /* Exact match on this character. */
		} else if (*b == '*' || (*b == '%' && *a != '.')) {
			continue;
		}
		return 0;
	}
	/* If there was no wildcard at the end, but there's more of the directory name remaining, it's NOT a match. */
	if (!strlen_zero(a)) {
		if (!strlen_zero(query) && *(b - 1) != '*' && *(b - 1) != '%') {
			return 0;
		}
	}
	return 1;
}

static int test_list_interpretation(void)
{
	bbs_test_assert_equals(1, list_match("Sent", "Sent"));
	bbs_test_assert_equals(1, list_match("Sent", "S*"));
	bbs_test_assert_equals(1, list_match("Sent", "S%"));
	bbs_test_assert_equals(0, list_match("Sent", "S"));
	bbs_test_assert_equals(1, list_match("Sent", "S*nt"));
	bbs_test_assert_equals(0, list_match("Foo.Bar", "Foo%"));
	bbs_test_assert_equals(1, list_match("Foo.Bar", "Foo*"));
	bbs_test_assert_equals(1, list_match("Trash", "Trash"));

	return 0;

cleanup:
	return -1;
}

static int imap_dir_has_subfolders(const char *path, const char *prefix)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res;
	int prefixlen = strlen(prefix);

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		} else if (!strncmp(entry->d_name, prefix, prefixlen)) {
			const char *rest = entry->d_name + prefixlen; /* do not add these within the strlen_zero macro! */
			/* XXX Check entire code tree for strlen_zero with + inside adding arguments. That's a bug!!! */
			if (!strlen_zero(rest)) {
				res = 1;
				break;
			}
		}
	}
	free(entries);
	return res;
}

#define IS_SPECIAL_NAME(s) (!strcmp(s, "INBOX") || !strcmp(s, "Drafts") || !strcmp(s, "Junk") || !strcmp(s, "Sent") || !strcmp(s, "Trash"))

#define DIR_NO_SELECT (1 << 0)
#define DIR_NO_CHILDREN (1 << 1)
#define DIR_HAS_CHILDREN (1 << 2)
#define DIR_DRAFTS (1 << 3)
#define DIR_JUNK (1 << 4)
#define DIR_SENT (1 << 5)
#define DIR_TRASH (1 << 6)

#define ATTR_NOSELECT "\\Noselect"
#define ATTR_HAS_CHILDREN "\\HasChildren"
#define ATTR_NO_CHILDREN "\\HasNoChildren"
#define ATTR_DRAFTS "\\Drafts"
#define ATTR_JUNK "\\Junk"
#define ATTR_SENT "\\Sent"
#define ATTR_TRASH "\\Trash"

#define ASSOC_ATTR(flag, string) SAFE_FAST_COND_APPEND(buf, pos, left, (attrs & flag), string)

static int get_attributes(struct imap_session *imap, const char *mailbox)
{
	int flags = 0;

	/* Great, we've just turned this into an n^2 operation now (the downside of IMAP hierarchy being only 2 levels on disk):
	 * But HasNoChildren and HasChildren are mandatory in the RFC, and they're pretty important attributes for the client, so compute them.
	 * In reality, it shouldn't take *too* terribly long since the number of folders (all folders, recursively), is still likely to be
	 * (some kind of small) constant, not even linear, so it's sublinear * sublinear. */
	if (imap_dir_has_subfolders(mailbox_maildir(imap->mbox), mailbox)) {
		flags |= DIR_HAS_CHILDREN;
	} else {
		flags |= DIR_NO_CHILDREN;
	}

	/* Special folders that must be named as such on our end: let the client know these are special using RFC 6154 */
	if (!strcmp(mailbox, "Drafts")) {
		flags |= DIR_DRAFTS;
	} else if (!strcmp(mailbox, "Junk")) {
		flags |= DIR_JUNK;
	} else if (!strcmp(mailbox, "Sent")) {
		flags |= DIR_SENT;
	} else if (!strcmp(mailbox, "Trash")) {
		flags |= DIR_TRASH;
	}

	return flags;
}

static void build_attributes_string(char *buf, size_t len, int attrs)
{
	char *pos = buf;
	int left = len;

	bbs_assert(!(attrs & DIR_NO_CHILDREN && attrs & DIR_HAS_CHILDREN)); /* This would make no sense. */

	ASSOC_ATTR(DIR_NO_SELECT, ATTR_NOSELECT);
	ASSOC_ATTR(DIR_NO_CHILDREN, ATTR_NO_CHILDREN);
	ASSOC_ATTR(DIR_HAS_CHILDREN, ATTR_HAS_CHILDREN);
	ASSOC_ATTR(DIR_DRAFTS, ATTR_DRAFTS);
	ASSOC_ATTR(DIR_JUNK, ATTR_JUNK);
	ASSOC_ATTR(DIR_SENT, ATTR_SENT);
	ASSOC_ATTR(DIR_TRASH, ATTR_TRASH);

	if (left <= 0) {
		bbs_error("Truncation occured when building attribute string (%d)\n", left);
		*(buf + len - 1) = '\0';
	} else {
		*pos = '\0';
		/* SAFE_FAST_COND_APPEND automatically adds spacing as needed, no need to remove the last space */
	}
}

static int test_build_attributes(void)
{
	char buf[64];

	build_attributes_string(buf, sizeof(buf), DIR_NO_CHILDREN);
	bbs_test_assert_str_equals(ATTR_NO_CHILDREN, buf);

	build_attributes_string(buf, sizeof(buf), DIR_HAS_CHILDREN);
	bbs_test_assert_str_equals(ATTR_HAS_CHILDREN, buf);

	return 0;

cleanup:
	return -1;
}

static int handle_list(struct imap_session *imap, char *s)
{
	char *reference, *mailbox;
	int reflen;
	struct dirent *entry, **entries;
	int files, fno = 0;
	char attributes[128];

	reference = strsep(&s, " ");
	mailbox = strsep(&s, " ");
	REQUIRE_ARGS(reference);
	REQUIRE_ARGS(mailbox);
	/* Doesn't seem to matter if arguments are in quotes, so we just remove them up front. */
	STRIP_QUOTES(reference);
	STRIP_QUOTES(mailbox);

	/* Examples:
	 * LIST "" % should return all top-level folders.
	 * LIST "" * should return all folders.
	 * LIST "" S% should return all top-level folders starting with S.
	 * LIST "" S* should return all folders starting with S.
	 * Swapping these 2 arguments often results in a similar response, with subtle differences.
	 */

	/*
	 * Mailbox attributes (https://www.iana.org/assignments/imap-mailbox-name-attributes/imap-mailbox-name-attributes.xhtml)
	 * Some defined in RFC 3501
	 * \NonExistent (RFC 5258) - implies \NoSelect
	 * \NoSelect - e.g. [Gmail] is a common example of this. Not a SELECTable mailbox.
	 * \Remote - remote mailbox
	 * \Marked - marked "interesting" by server: contains messages added since last time this mailbox was selected.
	 * \Unmarked - no new messages since last select
	 * \NoInferiors - implies \HasNoChildren. No children are allowed to exist.
	 * \HasChildren - MANDATORY. See RFC 5258 Section 4
	 * \HasNoChildren - MANDATORY
	 * \Subscribed
	 * \Important
	 *
	 * RFC 6154 SPECIAL-USE attributes (not always explicitly advertised, but this supersedes the deprecated XLIST)
	 * \All
	 * \Archive
	 * \Drafts
	 * \Flagged
	 * \Junk
	 * \Sent
	 * \Trash
	 */

	/* A detailed reading and reading of the RFC (e.g. RFC 3501) is very handy for understanding the LIST command in its entirety. */
	if (strlen_zero(mailbox)) {
		/* Just return hierarchy delimiter and root name of reference */
		/* When testing other servers, the reference argument doesn't even seem to matter, I always get something like this: */
		imap_send(imap, "LIST (%s %s) %s %s", ATTR_NOSELECT, ATTR_HAS_CHILDREN, QUOTED_ROOT, EMPTY_QUOTES);
		imap_reply(imap, "OK LIST completed.");
		return 0;
	}

	if (strlen_zero(reference)) { /* Empty reference ("") means same mailbox selected using SELECT */
		/* Default to INBOX if nothing has been selected yet, since it is the root */
	} else if (!strcmp(reference, "INBOX")) {
		reference = ""; /* It's the root. */
	}

	reflen = strlen(reference);

	/* If there are subdirectories (say one level down), it doesn't even matter which side
	 * has the hierarchy delimiter: could be end of the reference or beginning of the mailbox. */

	/* In doing our traversal of the maildir, we're going to look for directories
	 * that start with reference, and then match the pattern specified by mailbox.
	 * If it ends in %, that's a wildcard for the current directory.
	 * If it ends in *, that's a wildcard for all subdirectories as well.
	 *
	 * However, note that % and * can appear anywhere in the mailbox argument. And they function just like a wildcard character you'd expect.
	 * For that reason, we can't just concatenate reference and mailbox and use that as the prefix. */

	bbs_debug(6, "LIST traversal for '%s' '%s' => %s%s\n", reference, S_IF(mailbox), reference, S_IF(mailbox));

	/* XXX Hack for INBOX (since it's the top level maildir folder for the user), though this feels very klunky (but it's the target of the dir traversal, so...) */
	if (strlen_zero(reference) && (strlen_zero(mailbox) || !strcmp(mailbox, "*") || !strcmp(mailbox, "%"))) {
		build_attributes_string(attributes, sizeof(attributes), DIR_NO_CHILDREN);
		imap_send(imap, "LIST (%s) \"%s\" \"%s\"", attributes, HIERARCHY_DELIMITER, "INBOX");
	} else if (!strcmp(mailbox, "INBOX")) {
		build_attributes_string(attributes, sizeof(attributes), DIR_NO_CHILDREN);
		imap_send(imap, "LIST (%s) \"%s\" \"%s\"", attributes, HIERARCHY_DELIMITER, "INBOX");
		/* This was just for INBOX, so nothing else can possibly match. */
		/* XXX Again, the special handling of this feels clunky here */
		imap_reply(imap, "OK LIST completed.");
		return 0;
	}

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(mailbox_maildir(imap->mbox), &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", mailbox_maildir(imap->mbox), strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type == DT_DIR && (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))) { /* We only care about directories, not files. */
			int flags = 0;
			if (*entry->d_name != '.') {
				/* maildir subdirectories start with . (maildir++ standard) */
				continue;
			}
			/* This is an instance where maildir format is nice, we don't have to recurse in this subdirectory. */
			if (strncmp(entry->d_name, reference, reflen)) {
				imap_debug(10, "Directory %s doesn't start with prefix %s\n", entry->d_name, reference);
				continue; /* It doesn't start with the same prefix as the reference */
			} else if (!list_match(entry->d_name + reflen + 1, mailbox)) { /* Didn't match the mailbox (folder) query */
				/* Need to add 1 since all subdirectories start with . (maildir++ format) */
				imap_debug(10, "Name '%s' doesn't match query '%s'\n", entry->d_name + reflen + 1, mailbox);
				continue;
			}

			flags = get_attributes(imap, entry->d_name);
			build_attributes_string(attributes, sizeof(attributes), flags);
			/* Skip first character of directory name since it's . */
			imap_send(imap, "LIST (%s) \"%s\" \"%s\"", attributes, HIERARCHY_DELIMITER, entry->d_name + 1); /* Always send the delimiter */
		}
	}
	free(entries);
	imap_reply(imap, "OK LIST completed.");
	return 0;
}

/*! \brief strsep-like FETCH items tokenizer */
static char *fetchitem_sep(char **s)
{
	int in_bracket = 0;
	/* Can't use strsep, since a single token could be multiple words. */
	char *cur, *begin = *s;

	if (!*s) {
		return NULL;
	}

	cur = begin;
	while (*cur) {
		if (*cur == '[') {
			in_bracket = 1;
		} else if (*cur == ']') {
			if (in_bracket) {
				in_bracket = 0;
			} else {
				bbs_warning("Malformed FETCH request item string: %s\n", *s);
			}
		} else if (*cur == ' ') {
			if (!in_bracket) {
				break; /* Found the end */
			}
		}
		cur++;
	}

	*s = *cur ? cur + 1 : cur; /* If we got to the end, next item will be NULL, otherwise eat the space */
	if (*cur) {
		*cur = '\0'; /* Null terminate the previous string here */
	}

	if (strlen_zero(begin)) {
		return NULL; /* Empty string = nothing left */
	}

	return begin;
}

static int test_parse_fetch_items(void)
{
	char buf[64] = "FLAGS BODY[HEADER.FIELDS (DATE FROM)] INTERNALDATE";
	char *item, *items = buf;

	item = fetchitem_sep(&items);
	bbs_test_assert_str_equals(item, "FLAGS");
	item = fetchitem_sep(&items);
	bbs_test_assert_str_equals(item, "BODY[HEADER.FIELDS (DATE FROM)]");
	item = fetchitem_sep(&items);
	bbs_test_assert_str_equals(item, "INTERNALDATE");
	item = fetchitem_sep(&items);
	bbs_test_assert(item == NULL);
	return 0;

cleanup:
	return -1;
}

struct fetch_request {
	const char *bodyargs;
	const char *bodypeek;
	const char *flags;
	unsigned int envelope:1;
	unsigned int body:1;
	unsigned int bodystructure:1;
	unsigned int internaldate:1;
	unsigned int rfc822:1;
	unsigned int rfc822header:1;
	unsigned int rfc822size:1;
	unsigned int rfc822text:1;
	unsigned int uid:1;
};

/*! \note This is re-evaluated for every single message in the folder, which is not terribly efficient */
static int in_range(const char *s, int num)
{
	char buf[64];
	char *sequence, *sequences = buf;
	safe_strncpy(buf, s, sizeof(buf));

	while ((sequence = strsep(&sequences, ","))) {
		int min, max;
		char *begin = strsep(&sequence, ":");
		if (strlen_zero(begin)) {
			bbs_warning("Malformed range: %s\n", s);
			continue;
		}
		min = atoi(begin);
		if (num < min) {
			continue;
		}
		if (sequence) {
			if (!strcmp(sequence, "*")) {
				max = INT_MAX;
			} else {
				max = atoi(sequence);
			}
		} else {
			max = min;
		}
		if (num > max) {
			continue;
		}
		return 1; /* Matches */
	}
	return 0;
}

static int test_sequence_in_range(void)
{
	bbs_test_assert_equals(1, in_range("2:3,6", 2));
	bbs_test_assert_equals(1, in_range("2:3,6", 3));
	bbs_test_assert_equals(1, in_range("2:3,6", 6));
	bbs_test_assert_equals(0, in_range("2:3,6", 4));
	bbs_test_assert_equals(1, in_range("2:3,6,7:9", 8));
	bbs_test_assert_equals(1, in_range("1:*", 8));
	return 0;

cleanup:
	return -1;
}

static int process_fetch(struct imap_session *imap, int usinguid, struct fetch_request *fetchreq, const char *sequences)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int seqno = 0;
	char response[512];
	char headers[4096]; /* XXX Large enough for all headers, etc.? */
	char *buf;
	int len;
	int multiline = 0;
	int bodylen = 0;

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		char *uidstr;
		unsigned int msguid;
		const char *flags;
		FILE *fp;
		char fullname[516];
		int res;
		int sendbody = 0;
		int peek = 0;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		seqno++;
		if (!usinguid) {
			/* XXX UIDs aren't guaranteed to be in order (see comment below), so we can't break if seqno > max */
			if (!in_range(sequences, seqno)) {
				continue;
			}
		}

		/* Since we use scandir, msg sequence #s should be in order of oldest to newest */

		/* Parse UID */
		uidstr = strstr(entry->d_name, ",U=");
		if (!uidstr) {
			bbs_error("Missing UID for file %s?\n", entry->d_name);
			continue;
		}
		uidstr += STRLEN(",U=");
		msguid = atoi(uidstr); /* Should stop as soon we encounter the first nonnumeric character, whether , or : */
		if (msguid <= 0) {
			bbs_error("Unexpected UID: %u\n", msguid);
			continue;
		}
		if (usinguid) {
			if (!in_range(sequences, msguid)) {
				continue;
			}
		}
		/* At this point, the message is a match. Fetch everything we're supposed to for it. */
		buf = response;
		len = sizeof(response);
		snprintf(fullname, sizeof(fullname), "%s/%s", imap->curdir, entry->d_name);

		if (fetchreq->flags) {
			char flagsbuf[256];
			flags = strchr(entry->d_name, ':'); /* maildir flags */
			if (!flags) {
				bbs_error("Message file %s contains no flags?\n", entry->d_name);
				continue;
			}
			/* If we wanted to microptimize, we could set flags = current flag on a match, since these must appear in order (for maildir) */
			gen_flag_names(flags, flagsbuf, sizeof(flagsbuf));
			SAFE_FAST_COND_APPEND(response, buf, len, 1, "FLAGS (%s)", flagsbuf);
		}
		if (fetchreq->rfc822size) {
			unsigned long size;
			const char *sizestr = strstr(entry->d_name, ",S=");
			if (!sizestr) {
				bbs_error("Missing size in file %s\n", entry->d_name);
				continue;
			}
			sizestr += STRLEN(",S=");
			size = atoi(sizestr);
			SAFE_FAST_COND_APPEND(response, buf, len, 1, "RFC822.SIZE %lu", size);
		}
		/* Must include UID in response, whether requested or not (so fetchreq->uid ignored) */
		SAFE_FAST_COND_APPEND(response, buf, len, 1, "UID %u", msguid);
		if (fetchreq->bodyargs || fetchreq->bodypeek) {
			char linebuf[1001];
			char *headpos = headers;
			int headlen = sizeof(headers);
			/* e.g. BODY[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To Received)] */
			const char *bodyargs = fetchreq->bodyargs ? fetchreq->bodyargs + 5 : fetchreq->bodypeek + 10;
			if (fetchreq->bodypeek) {
				peek = 1;
			}
			if (STARTS_WITH(bodyargs, "HEADER.FIELDS")) {
				multiline = 1;
				bodyargs += STRLEN("HEADER.FIELDS (");
				/* Read the file until the first CR LF CR LF (end of headers) */
				fp = fopen(fullname, "r");
				if (!fp) {
					bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
					continue;
				}
				/* The RFC says no line should be more than 1,000 octets (bytes).
				 * Most clients will wrap at 72 characters, but we shouldn't rely on this. */
				while ((fgets(linebuf, sizeof(linebuf), fp))) {
					char headername[64];
					/* fgets does store the newline, so line should end in CR LF */
					if (!strcmp(linebuf, "\r\n")) {
						break; /* End of headers (LF is eaten by fgets) */
					}
					/* I hope gcc optimizes this to not use snprintf under the hood */
					safe_strncpy(headername, linebuf, sizeof(headername)); /* Don't copy the whole line. XXX This assumes that no header name is longer than 64 chars. */
					bbs_strterm(headername, ':');
					/* Only include headers that were asked for. */
					if (strstr(bodyargs, headername)) {
						SAFE_FAST_COND_APPEND_NOSPACE(headers, headpos, headlen, 1, "%s", linebuf);
					}
				}
				fclose(fp);
				bodylen = strlen(headers); /* Can't just subtract end of headers, we'd have to keep track of bytes added on each round (which we probably should anyways) */
				/* bodyargs ends in a ')', so don't tack an additional one on afterwards */
				SAFE_FAST_COND_APPEND(response, buf, len, 1, "BODY[HEADER.FIELDS (%s", bodyargs);
			} else if (!strcmp(bodyargs, "]")) { /* Empty (e.g. BODY.PEEK[] or BODY[] */
				multiline = 1;
				sendbody = 1;
			} else {
				bbs_warning("Unsupported BODY[] argument: %s (%s)\n", bodyargs, fetchreq->bodyargs);
			}
		} else if (fetchreq->rfc822header) {
			char linebuf[1001];
			char *headpos = headers;
			int headlen = sizeof(headers);
			multiline = 1;
			/* Read the file until the first CR LF CR LF (end of headers) */
			fp = fopen(fullname, "r");
			if (!fp) {
				bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
				continue;
			}
			/* The RFC says no line should be more than 1,000 octets (bytes).
			 * Most clients will wrap at 72 characters, but we shouldn't rely on this. */
			while ((fgets(linebuf, sizeof(linebuf), fp))) {
				/* fgets does store the newline, so line should end in CR LF */
				if (!strcmp(linebuf, "\r\n")) {
					break; /* End of headers (LF is eaten by fgets) */
				}
				/* I hope gcc optimizes this to not use snprintf under the hood */
				SAFE_FAST_COND_APPEND_NOSPACE(headers, headpos, headlen, 1, "%s", linebuf);
			}
			fclose(fp);
			bodylen = headpos - headers; /* XXX cheaper than strlen, although if truncation happened, this may be wrong (too high). */
			SAFE_FAST_COND_APPEND(response, buf, len, 1, "RFC822.HEADER");
		}

		/*! \todo Still missing lots of stuff here!!! +need to mark as Seen unless peeking */

		/* Actual body, if being sent, should be last */
		if (fetchreq->rfc822) {
			multiline = 1;
			sendbody = 1;
		}
		if (multiline) {
			/* {D} tells client this is a multiline response, with D more bytes remaining */
			long size;
			if (sendbody) {
				off_t offset;
				fp = fopen(fullname, "r");
				if (!fp) {
					bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
					continue;
				}
				fseek(fp, 0L, SEEK_END); /* Go to EOF */
				size = ftell(fp);
				rewind(fp); /* Be kind, rewind */
				imap_send(imap, "%d FETCH (%s %s {%ld}", seqno, response, fetchreq->rfc822 ? "RFC822" : "BODY[]", size + 2); /* No close paren here, last dprintf will do that */
				/* XXX Assumes not sending headers and bodylen at same time.
				 * In reality, I think that *might* be fine because the body contains everything,
				 * and you wouldn't request just the headers and then the whole body in the same FETCH.
				 * Now if there is a request for just the body text without the headers, we might be in trouble...
				 */
				if (bodylen) {
					bbs_warning("XXX This is not handled and needs to be fixed\n");
				}
				offset = 0;
				/* XXX Doesn't handle partial bodies */
				res = sendfile(imap->wfd, fileno(fp), &offset, size); /* We must manually tell it the offset or it will be at the EOF, even with rewind() */
				if (res != size) {
					bbs_error("sendfile failed (%d != %ld): %s\n", res, size, strerror(errno));
				} else {
					imap_debug(5, "Sent %d-byte body\n", res);
				}
				dprintf(imap->wfd, "\r\n)\r\n"); /* And the finale (don't use imap_send for this) */
			} else {
				/* Need to add 2 for last CR LF we tack on before ) */
				imap_send(imap, "%d FETCH (%s {%d}\r\n%s\r\n)", seqno, response, bodylen + 2, headers);
			}
		} else {
			/* Number after FETCH is always a message sequence number, not UID, even if usinguid */
			imap_send(imap, "%d FETCH (%s)", seqno, response); /* Single line response */
		}

		/*! \todo mark as read if !peek (in reality, not critical, since most clients will manually set the flags, and use peek extensively) */
		UNUSED(peek);
	}
	free(entries);
	imap_reply(imap, "OK %sFETCH Completed", usinguid ? "UID " : "");
	return 0;
}

/*! \brief Retrieve data associated with a message */
static int handle_fetch(struct imap_session *imap, char *s, int usinguid)
{
	char tmpbuf[56]; /* Buffer for macro expansion */
	char *sequences;
	char *items, *item;
	struct fetch_request fetchreq;

	if (s_strlen_zero(imap->dir)) {
		imap_reply(imap, "NO Must select a mailbox first");
		return 0;
	}

	REQUIRE_ARGS(s);
	sequences = strsep(&s, " "); /* Messages, specified by sequence number or by UID (if usinguid) */
	REQUIRE_ARGS(s); /* What remains are the items to select */

	/* Special macros, defined in RFC 3501. They must only be used by themselves, which makes their usage easy for us. Just expand them. */
	items = tmpbuf; /* If it's special, if not items will be set to s */
	if (!strcmp(s, "ALL")) {
		safe_strncpy(tmpbuf, "FLAGS INTERNALDATE RFC822.SIZE ENVELOPE", sizeof(tmpbuf));
	} else if (!strcmp(s, "FAST")) {
		safe_strncpy(tmpbuf, "FLAGS INTERNALDATE RFC822.SIZE", sizeof(tmpbuf));
	} else if (!strcmp(s, "FULL")) {
		safe_strncpy(tmpbuf, "FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY", sizeof(tmpbuf));
	} else {
		/* Remove the surrounding parentheses for parsing */
		char *end;
		items = s;
		if (*items == '(') {
			items++;
		}
		end = strrchr(items, ')');
		if (end && !*(end + 1)) {
			*end = '\0';
		}
	}

	/* Only parse the request once. */
	memset(&fetchreq, 0, sizeof(fetchreq));
	while ((item = fetchitem_sep(&items))) {
		if (!strcmp(item, "BODY")) {
			/* Same as BODYSTRUCTURE, basically */
			fetchreq.body = 1;
		} else if (!strcmp(item, "BODYSTRUCTURE")) {
			fetchreq.bodystructure = 1;
		} else if (STARTS_WITH(item, "BODY[")) {
			/* BODY[]<> */
			fetchreq.bodyargs = item;
		} else if (STARTS_WITH(item, "BODY.PEEK[")) {
			fetchreq.bodypeek = item;
		} else if (!strcmp(item, "ENVELOPE")) {
			fetchreq.envelope = 1;
		} else if (!strcmp(item, "FLAGS")) {
			fetchreq.flags = item;
		} else if (!strcmp(item, "INTERNALDATE")) {
			fetchreq.internaldate = 1;
		} else if (!strcmp(item, "RFC822")) { /* Technically deprecated nowadays, in favor of BODY[], but clients still use it */
			/* Same as BODY[], basically */
			fetchreq.rfc822 = 1;
		} else if (!strcmp(item, "RFC822.HEADER")) {
			/* Same as BODY.PEEK[HEADER], basically */
			fetchreq.rfc822header = 1;
		} else if (!strcmp(item, "RFC822.SIZE")) {
			fetchreq.rfc822size = 1;
		} else if (!strcmp(item, "RFC822.TEXT")) {
			/* Same as BODY[TEXT], basically */
			fetchreq.rfc822text = 1;
		} else if (!strcmp(item, "UID")) {
			fetchreq.uid = 1;
		} else {
			bbs_warning("Unsupported FETCH item: %s\n", item);
		}
	}

	/* Process the request, for each message that matches sequence number. */
	return process_fetch(imap, usinguid, &fetchreq, sequences);
}

static int process_flags(struct imap_session *imap, char *s, int usinguid, const char *sequences, int flagop, int silent)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int seqno = 0;
	int opflags = 0;
	int oldflags;

	/* Convert something like (\Deleted) into the actual flags (parse once, use for all matches) */
	/* Remove parentheses */
	s++;
	if (!strlen_zero(s)) {
		bbs_strterm(s, ')');
	}

	opflags = parse_flags_string(s);

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		char *uidstr;
		unsigned int msguid;
		const char *flags;
		char oldname[516];
		char fullfilename[524];
		char fullname[256];
		char newflagletters[NUM_FLAG_BITS + 1];
		int i;
		int newflags;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		seqno++;
		if (!usinguid) {
			/* XXX UIDs aren't guaranteed to be in order (see comment below), so we can't break if seqno > max */
			if (!in_range(sequences, seqno)) {
				continue;
			}
		}

		/* XXX See comments in handle_fetch */
		uidstr = strstr(entry->d_name, ",U=");
		if (!uidstr) {
			bbs_error("Missing UID for file %s?\n", entry->d_name);
			continue;
		}
		uidstr += STRLEN(",U=");
		msguid = atoi(uidstr); /* Should stop as soon we encounter the first nonnumeric character, whether , or : */
		if (msguid <= 0) {
			bbs_error("Unexpected UID: %u\n", msguid);
			continue;
		}
		if (usinguid) {
			if (!in_range(sequences, msguid)) {
				continue;
			}
		}
		/* Get the message's current flags. */
		flags = strchr(entry->d_name, ':'); /* maildir flags */
		if (!flags) {
			bbs_error("Message file %s contains no flags?\n", entry->d_name);
			continue;
		}
		oldflags = parse_flags_letters(flags + 2); /* Skip first 2 since it's always just "2," and real flags come after that */
		/* If we wanted to microptimize, we could set flags = current flag on a match, since these must appear in order (for maildir) */

		/* Build the new flags by iterating over opflags and comparing with oldflags */
		if (flagop == 1) { /* Append */
			newflags = oldflags; /* Start with existing. */
			for (i = 0; i < NUM_FLAG_BITS; i++) {
				if (opflags & (1 << i)) {
					newflags |= (1 << i);
				}
			}
		} else if (flagop == -1) { /* Remove */
			newflags = oldflags; /* Start with existing. */
			for (i = 0; i < NUM_FLAG_BITS; i++) {
				if (opflags & (1 << i)) {
					newflags &= ~(1 << i);
				}
			}
		} else {
			newflags = opflags; /* Just replace. That was easy. */
		}

		/* Generate flag letters from flag bits */
		gen_flag_letters(newflags, newflagletters, sizeof(newflagletters));

		/* Generate new filename and do the rename */
		snprintf(oldname, sizeof(oldname), "%s/%s", imap->curdir, entry->d_name);
		safe_strncpy(fullname, entry->d_name, sizeof(fullname));
		bbs_strterm(fullname, ':');
		snprintf(fullfilename, sizeof(fullfilename), "%s/%s:2,%s", imap->curdir, fullname, newflagletters);
		bbs_debug(3, "Renaming %s -> %s\n", oldname, fullfilename);
		if (rename(oldname, fullfilename)) {
			bbs_error("rename %s -> %s failed: %s\n", oldname, fullfilename, strerror(errno));
			continue;
		}

		/* Send the response if not silent */
		if (!silent) {
			char flagstr[256];
			gen_flag_names(newflagletters, flagstr, sizeof(flagstr));
			imap_send(imap, "%d FETCH (FLAGS (%s))", seqno, flagstr);
		}
	}
	free(entries);
	imap_reply(imap, "OK %sFETCH Completed", usinguid ? "UID " : "");
	return 0;
}

static int handle_store(struct imap_session *imap, char *s, int usinguid)
{
	char *sequences, *operation;
	int flagop;
	int silent;

	REQUIRE_ARGS(s);
	sequences = strsep(&s, " "); /* Sequence set, specified by sequence number or by UID (if usinguid) */
	operation = strsep(&s, " ");
	/* What remains are actual flags */

	if (!strcasecmp(operation, "FLAGS")) {
		flagop = 0; /* Replace */
		silent = 0;
	} else if (!strcasecmp(operation, "FLAGS.SILENT")) {
		flagop = 0;
		silent = 1;
	} else if (!strcasecmp(operation, "+FLAGS")) {
		flagop = 1; /* Append */
		silent = 0;
	} else if (!strcasecmp(operation, "+FLAGS.SILENT")) {
		flagop = 1;
		silent = 1;
	} else if (!strcasecmp(operation, "-FLAGS")) {
		flagop = -1; /* Remove */
		silent = 0;
	} else if (!strcasecmp(operation, "-FLAGS")) {
		flagop = -1; /* Remove */
		silent = 1;
	} else {
		bbs_error("Invalid STORE operation: %s\n", operation);
		imap_reply(imap, "BAD Invalid arguments");
		return 0;
	}
	process_flags(imap, s, usinguid, sequences, flagop, silent);
	return 0;
}

static int handle_create(struct imap_session *imap, char *s)
{
	char path[256];

	REQUIRE_ARGS(s);
	STRIP_QUOTES(s);

	/* Since our HIERARCHY_DELIMITER is just a ., which is nothing special in *nix, we can just blindly use it... almost. */
	if (strstr(s, "..")) { /* Don't allow path traversal UP, only DOWN */
		imap_reply(imap, "BAD Invalid mailbox name");
		return 0;
	} else if (strchr(s, '/')) { /* Don't allow our real directory delimiter */
		imap_reply(imap, "BAD Invalid mailbox name");
		return 0;
	} else if (IS_SPECIAL_NAME(s)) {
		/*! \todo We should allow this, maybe? (except for INBOX, obviously), if the appropriate attributes are going to be added */
		imap_reply(imap, "NO Can't create mailbox with special name");
		return 0;
	}

	snprintf(path, sizeof(path), "%s/.%s", mailbox_maildir(imap->mbox), s); /* maildir subdirectories start with . */
	bbs_debug(3, "IMAP client wants to create directory %s\n", path);
	if (!eaccess(path, R_OK)) {
		imap_reply(imap, "NO Mailbox already exists");
		return 0;
	}
	MAILBOX_TRYRDLOCK(imap);
	if (mkdir(path, 0700)) {
		bbs_error("mkdir(%s) failed: %s\n", path, strerror(errno));
		imap_reply(imap, "NO Mailbox creation failed");
		mailbox_unlock(imap->mbox);
		return 0;
	}
	mailbox_unlock(imap->mbox);

	/* Don't initialize the maildir itself here, that can be done at some later point. */
	imap_reply(imap, "OK CREATE completed");
	return 0;
}

static int handle_delete(struct imap_session *imap, char *s)
{
	char path[256];

	REQUIRE_ARGS(s);
	STRIP_QUOTES(s);

	if (IS_SPECIAL_NAME(s)) {
		imap_reply(imap, "NO Can't delete special mailbox");
		return 0;
	}

	snprintf(path, sizeof(path), "%s/.%s", mailbox_maildir(imap->mbox), s); /* maildir subdirectories start with . */

	if (eaccess(path, R_OK)) {
		imap_reply(imap, "NO No such mailbox with that name");
		return 0;
	}

	/* If the hierarchy really matched, it would be easier in this case, since we could
	 * just call bbs_dir_has_subdirs and reject if true (kind of, would need to exclude tmp/new/cur).
	 * We'll need to traverse the root maildir for this mailbox and see if there
	 * are any directories that are prefixed with the target directory name.
	 * i.e. any directories beginning with s., and if so, reject. */

	if (bbs_dir_has_file_prefix(mailbox_maildir(imap->mbox), s)) {
		/* From an IMAP perspective, this folder contains subfolders. Reject deletion. */
		imap_reply(imap, "NO Mailbox has inferior hierarchical names");
		return 0;
	}

	MAILBOX_TRYRDLOCK(imap);
	if (rmdir(path)) {
		bbs_error("rmdir(%s) failed: %s\n", path, strerror(errno));
	}
	mailbox_unlock(imap->mbox);
	return 0;
}

static int sub_rename(const char *path, const char *prefix, const char *newprefix)
{
	char oldpath[257];
	char newpath[257];
	struct dirent *entry, **entries;
	int res = 0;
	int files, fno = 0;
	int prefixlen = strlen(prefix);

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		} else if (entry->d_type == DT_DIR) { /* We only care about directories, not files. */
			if (!strncmp(entry->d_name, prefix, prefixlen)) {
				snprintf(oldpath, sizeof(oldpath), "%s/%s", path, entry->d_name);
				/* This folder needs to be renamed.
				 * For example, say foo is renamed to foobar
				 * Then foo.test needs to be renamed to foobar.test. */
				/* XXX Does this work correctly for multilevel subfolders? */
				snprintf(newpath, sizeof(newpath), "%s/%s%s", path, newprefix, entry->d_name + prefixlen); /* Copy everything after the original prefix back for the new filename. */
				/* Renames at this point should always succeed, since if the parent folder didn't exist, then any subfolders of it shouldn't either. */
				res = rename(oldpath, newpath);
				if (res) {
					bbs_error("rename %s -> %s failed: %s\n", oldpath, newpath, strerror(errno));
					/* This could leave things in an inconsistent state.
					 * but if this is the first failure (we didn't successfully rename anything yet)
					 * then we shouldn't have changed anything.
					 * For this reason, better to rename the subdirs before the main dir itself. */
					res = -1;
					break;
				}
			}
		}
	}

	free(entries);
	if (res < 0) {
		bbs_error("Error while reading directories (%d) - %s: %s\n", res, path, strerror(errno));
		res = -1;
	}

	return res;
}

static int handle_rename(struct imap_session *imap, char *s)
{
	char oldpath[256];
	char newpath[256];
	char *old, *new;
	int res;

	REQUIRE_ARGS(s);
	old = strsep(&s, " ");
	new = strsep(&s, " ");
	REQUIRE_ARGS(old);
	REQUIRE_ARGS(new);
	STRIP_QUOTES(old);
	STRIP_QUOTES(new);

	/* Renaming INBOX is permitted by the RFC, technically, but it just moves its messages, which isn't really rename related. */
	if (IS_SPECIAL_NAME(old) || IS_SPECIAL_NAME(new)) {
		imap_reply(imap, "NO Can't rename to/from that name");
		return 0;
	}

	snprintf(oldpath, sizeof(oldpath), "%s/.%s", mailbox_maildir(imap->mbox), old); /* maildir subdirectories start with . */
	snprintf(newpath, sizeof(newpath), "%s/.%s", mailbox_maildir(imap->mbox), new);
	if (eaccess(oldpath, R_OK)) {
		imap_reply(imap, "NO No such mailbox with that name");
		return 0;
	} else if (!eaccess(newpath, R_OK)) {
		imap_reply(imap, "NO Mailbox already exists");
		return 0;
	}

	/* Okay, for the reasons mentioned in handle_delete,
	 * this operation is truly ugly for maildir. */
	MAILBOX_TRYRDLOCK(imap);
	res = sub_rename(mailbox_maildir(imap->mbox), old, new); /* We're doing multiple renames, so to make them all atomic, surround with a RDLOCK. */
	if (!res) {
		if (rename(oldpath, newpath)) {
			bbs_error("rename %s -> %s failed: %s\n", oldpath, newpath, strerror(errno));
			imap_reply(imap, "NO System error");
		} else {
			imap_reply(imap, "OK RENAME completed");
		}
	} else {
		imap_reply(imap, "NO System error");
	}
	mailbox_unlock(imap->mbox);
	return 0;
}

static int imap_process(struct imap_session *imap, char *s)
{
	int res;
	char *command;

	imap->tag = strsep(&s, " "); /* Tag for client to identify responses to its request */
	command = strsep(&s, " ");

	if (!imap->tag || !command) {
		imap_send(imap, "BAD Missing arguments.");
		return 0;
	}

	if (!strcasecmp(command, "NOOP")) {
		imap_reply(imap, "OK NOOP completed");
	} else if (!strcasecmp(command, "LOGOUT")) {
		imap_send(imap, "BYE IMAP4 Server logging out");
		imap_reply(imap, "OK LOGOUT completed");
		return -1; /* Close connection */
	} else if (!strcasecmp(command, "CAPABILITY")) {
		/* Some clients send a CAPABILITY after login, too,
		 * even though the RFC says clients shouldn't,
		 * since capabilities don't change during sessions. */
		/* XXX AUTH=PLAIN => AUTHENTICATE, which we don't support currently. */
		imap_send(imap, "CAPABILITY " IMAP_CAPABILITIES);
		imap_reply(imap, "OK CAPABILITY completed");
	} else if (!strcasecmp(command, "LOGIN")) {
		char *user, *pass, *domain;
		user = strsep(&s, " ");
		pass = strsep(&s, " ");
		/* MUAs typically enclose these in quotes: */
		REQUIRE_ARGS(user);
		REQUIRE_ARGS(pass);
		STRIP_QUOTES(user);
		STRIP_QUOTES(pass);
		if (bbs_user_is_registered(imap->node->user)) {
			imap_reply(imap, "NO Already logged in");
			return 0;
		}
		/* Strip the domain, if present,
		 * but the domain must match our domain, if present. */
		domain = strchr(user, '@');
		if (domain) {
			*domain++ = '\0';
			if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
				imap_reply(imap, "NO Invalid username or password"); /* No such mailbox, since wrong domain! */
				return 0;
			}
		}
		res = bbs_authenticate(imap->node, user, pass);
		memset(pass, 0, strlen(pass)); /* Destroy the password from memory. */
		if (res) {
			imap_reply(imap, "NO Invalid username or password");
			return 0;
		}
		imap->mbox = mailbox_get(imap->node->user->id, NULL); /* Retrieve the mailbox for this user */
		if (!imap->mbox) {
			bbs_error("Successful authentication, but unable to retrieve mailbox for user %d\n", imap->node->user->id);
			imap_reply(imap, "BYE System error");
			return -1; /* Just disconnect, we probably won't be able to proceed anyways. */
		}
		imap_reply(imap, "OK Login completed");
	/* Past this point, must be logged in. */
	} else if (!bbs_user_is_registered(imap->node->user)) {
		imap_reply(imap, "BAD Not logged in");
	} else if (!strcasecmp(command, "SELECT")) {
		return handle_select(imap, s, 0);
	} else if (!strcasecmp(command, "EXAMINE")) {
		return handle_select(imap, s, 1);
	} else if (!strcasecmp(command, "STATUS")) { /* STATUS is like EXAMINE, but it's on a specified mailbox that is NOT the currently selected mailbox */
		REQUIRE_ARGS(s);
		if (imap->folder && !strcmp(s, imap->folder)) {
			imap_reply(imap, "NO This mailbox is currently selected");
			return 0;
		}
		return handle_select(imap, s, 2);
	} else if (!strcasecmp(command, "LIST")) {
		return handle_list(imap, s);
	} else if (!strcasecmp(command, "CREATE")) {
		return handle_create(imap, s);
	} else if (!strcasecmp(command, "DELETE")) {
		return handle_delete(imap, s);
	} else if (!strcasecmp(command, "RENAME")) {
		return handle_rename(imap, s);
	} else if (!strcasecmp(command, "CHECK")) {
		imap_reply(imap, "OK CHECK Completed"); /* Nothing we need to do now */
	} else if (!strcasecmp(command, "FETCH")) {
		return handle_fetch(imap, s, 0);
	} else if (!strcasecmp(command, "STORE")) {
		return handle_store(imap, s, 0);
	} else if (!strcasecmp(command, "UID")) {
		REQUIRE_ARGS(s);
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		if (!strcasecmp(command, "FETCH")) {
			return handle_fetch(imap, s, 1);
		} else if (!strcasecmp(command, "COPY")) {
			/*! \todo implement */
		} else if (!strcasecmp(command, "STORE")) {
			return handle_store(imap, s, 1);
		} else {
			imap_reply(imap, "BAD Invalid UID command");
		}
	} else {
		/*! \todo capabilities to support:
		 * https://www.iana.org/assignments/imap-capabilities/imap-capabilities.xml
		 * Outlook: * CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2 SASL-IR UIDPLUS MOVE ID UNSELECT CHILDREN IDLE NAMESPACE LITERAL+
		 * Outlook logged in: * CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2 SASL-IR UIDPLUS MOVE ID UNSELECT CLIENTACCESSRULES CLIENTNETWORKPRESENCELOCATION BACKENDAUTHENTICATE CHILDREN IDLE NAMESPACE LITERAL+
		 * Google: * CAPABILITY IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST CHILDREN X-GM-EXT-1 XYZZY SASL-IR AUTH=XOAUTH2 AUTH=PLAIN AUTH=PLAIN-CLIENTTOKEN AUTH=OAUTHBEARER AUTH=XOAUTH
		 * Yandex: * CAPABILITY IMAP4rev1 CHILDREN UNSELECT LITERAL+ NAMESPACE XLIST BINARY UIDPLUS ENABLE ID AUTH=PLAIN AUTH=XOAUTH2 IDLE MOVE
		 *
		 * As far as RFC 6154 goes, nobody seems to support SPECIAL-USE 
		 */

		/*! \todo add CLOSE */
		/*! \todo add COPY */
		/*! \todo add RFC 2177 IDLE - need to have a linked list of all IMAP sessions for a mailbox, and send any updates to all connected clients */

		/*! \todo handle CLOSE/EXPUNGE */
		/*! \todo add SUBSCRIBE, LSUB */
		/*! \todo add APPEND */
		/*! \todo Need to add IDLE +only allow the longer IDLE timeout (30 mins) when in an idle, time out earlier otherwise */
		/*! \todo add SEARCH */

		bbs_warning("Unsupported IMAP command: %s\n", command);
		imap_reply(imap, "BAD Command not supported.");
	}

	return 0;
}

static void handle_client(struct imap_session *imap)
{
	char buf[1001]; /* Maximum length, including CR LF, is 1000 */
	int res;
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));  

	imap_send(imap, "OK %s Service Ready", IMAP_REV);

	for (;;) {
		const char *word2;
		/* Autologout timer should not be less than 30 minutes, according to the RFC. We'll uphold that, for clients that are logged in. */
		res = bbs_fd_readline(imap->rfd, &rldata, "\r\n", bbs_user_is_registered(imap->node->user) ? MIN_MS(30) : MIN_MS(1));
		if (res < 0) {
			res += 1; /* Convert the res back to a normal one. */
			if (res == 0) {
				/* Timeout occured. */
				imap_send(imap, "BYE %s server terminating connection", IMAP_REV);
			}
			break;
		}
		word2 = strchr(buf, ' ');
		if (word2++ && !strlen_zero(word2) && !strncasecmp(word2, "LOGIN", STRLEN("LOGIN"))) {
			bbs_debug(6, "%p => <LOGIN REDACTED>\n", imap); /* Mask login to avoid logging passwords */
		} else {
			bbs_debug(6, "%p => %s\n", imap, buf);
		}
		if (imap_process(imap, buf)) {
			break;
		}
	}
}

/*! \brief Thread to handle a single IMAP/IMAPS client */
static void imap_handler(struct bbs_node *node, int secure)
{
#ifdef HAVE_OPENSSL
	SSL *ssl;
#endif
	int rfd, wfd;
	struct imap_session imap;

	/* Start TLS if we need to */
	if (secure) {
		ssl = ssl_new_accept(node->fd, &rfd, &wfd);
		if (!ssl) {
			bbs_error("Failed to create SSL\n");
			return;
		}
	} else {
		rfd = wfd = node->fd;
	}

	memset(&imap, 0, sizeof(imap));
	imap.rfd = rfd;
	imap.wfd = wfd;
	imap.node = node;

	handle_client(&imap);

#ifdef HAVE_OPENSSL
	if (secure) { /* implies ssl */
		ssl_close(ssl);
		ssl = NULL;
	}
#endif
	imap_destroy(&imap);
}

static void *__imap_handler(void *varg)
{
	struct bbs_node *node = varg;

	node->thread = pthread_self();
	bbs_node_begin(node);

	imap_handler(node, !strcmp(node->protname, "IMAPS")); /* Actually handle the message submission agent client */

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

/*! \brief Single listener thread for IMAP and/or IMAPS */
static void *imap_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener2(imap_socket, imaps_socket, "IMAP", "IMAPS", __imap_handler, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_imap.conf", 1);
	if (!cfg) {
		return 0;
	}

	/* IMAP */
	bbs_config_val_set_true(cfg, "imap", "enabled", &imap_enabled);
	bbs_config_val_set_port(cfg, "imap", "port", &imap_port);

	/* IMAPS */
	bbs_config_val_set_true(cfg, "imaps", "enabled", &imaps_enabled);
	bbs_config_val_set_port(cfg, "imaps", "port", &imaps_port);

	return 0;
}

static struct unit_tests {
	const char *name;
	int (*callback)(void);
} tests[] =
{
	{ "IMAP LIST Interpretation", test_list_interpretation },
	{ "IMAP LIST Attributes", test_build_attributes },
	{ "IMAP FETCH Item Parsing", test_parse_fetch_items },
	{ "IMAP FETCH Sequence Ranges", test_sequence_in_range },
	{ "IMAP STORE Flags Parsing", test_flags_parsing },
};

static int load_module(void)
{
	unsigned int i;

	if (load_config()) {
		return -1;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!imap_enabled && !imaps_enabled) {
		bbs_debug(3, "Neither IMAP nor IMAPS is enabled, declining to load\n");
		return -1; /* Nothing is enabled */
	}
	if (imaps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, IMAPS may not be used\n");
		return -1;
	}

	/* If we can't start the TCP listeners, decline to load */
	if (imap_enabled && bbs_make_tcp_socket(&imap_socket, imap_port)) {
		return -1;
	}
	if (imaps_enabled && bbs_make_tcp_socket(&imaps_socket, imaps_port)) {
		close_if(imap_socket);
		return -1;
	}

	if (bbs_pthread_create(&imap_listener_thread, NULL, imap_listener, NULL)) {
		bbs_error("Unable to create IMAP listener thread.\n");
		close_if(imap_socket);
		close_if(imaps_socket);
		return -1;
	}

	if (imap_enabled) {
		bbs_register_network_protocol("IMAP", imap_port);
	}
	if (imaps_enabled) {
		bbs_register_network_protocol("IMAPS", imaps_port); /* This is also for MSA */
	}
	for (i = 0; i < ARRAY_LEN(tests); i++) {
		bbs_register_test(tests[i].name, tests[i].callback);
	}
	return 0;
}

static int unload_module(void)
{
	unsigned int i;
	for (i = 0; i < ARRAY_LEN(tests); i++) {
		bbs_unregister_test(tests[i].callback);
	}
	pthread_cancel(imap_listener_thread);
	pthread_kill(imap_listener_thread, SIGURG);
	bbs_pthread_join(imap_listener_thread, NULL);
	if (imap_enabled) {
		bbs_unregister_network_protocol(imap_port);
		close_if(imap_socket);
	}
	if (imaps_enabled) {
		bbs_unregister_network_protocol(imaps_port);
		close_if(imaps_socket);
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC9051 IMAP", "mod_mail.so");
