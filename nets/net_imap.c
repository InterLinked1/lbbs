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
 * \note Supports RFC2177 IDLE
 * \note Supports RFC9208 QUOTA
 * \note Supports RFC2971 ID
 * \note Supports RFC4959 SASL-IR
 * \note Supports RFC2342 namespaces
 * \note Supports RFC4314 ACLs
 * \note Supports RFC5256 SORT
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
#include "include/mod_mimeparse.h"

/* IMAP ports */
#define DEFAULT_IMAP_PORT 143
#define DEFAULT_IMAPS_PORT 993

static int imap_port = DEFAULT_IMAP_PORT;
static int imaps_port = DEFAULT_IMAPS_PORT;

static pthread_t imap_listener_thread = -1;

static int imap_enabled = 0, imaps_enabled = 1;
static int imap_socket = -1, imaps_socket = -1;

static int allow_idle = 1;

/*! \brief Allow storage of messages up to 5MB. User can decide if that's really a good use of mail quota or not... */
#define MAX_APPEND_SIZE 5000000

static int imap_debug_level = 10;
#define imap_debug(level, fmt, ...) if (imap_debug_level >= level) { bbs_debug(level, fmt, ## __VA_ARGS__); }

#undef dprintf
#define _imap_broadcast(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); __imap_broadcast(imap, fmt, ## __VA_ARGS__);
#define _imap_reply(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); pthread_mutex_lock(&imap->lock); dprintf(imap->wfd, fmt, ## __VA_ARGS__); pthread_mutex_unlock(&imap->lock);
#define imap_send_broadcast(imap, fmt, ...) _imap_broadcast(imap, "%s " fmt "\r\n", "*", ## __VA_ARGS__)
#define imap_send(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", "*", ## __VA_ARGS__)
#define imap_reply_broadcast(imap, fmt, ...) _imap_broadcast(imap, "%s " fmt "\r\n", S_IF(imap->tag), ## __VA_ARGS__)
#define imap_reply(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", S_IF(imap->tag), ## __VA_ARGS__)

/* RFC 2086/4314 ACLs */
/*! \brief Visible in LIST, LSUB, SUBSCRIBE */
#define IMAP_ACL_LOOKUP (1 << 0)
#define IMAP_ACL_LOOKUP_LETTER 'l'

/*! \brief SELECT, STATUS */
#define IMAP_ACL_READ (1 << 1)
#define IMAP_ACL_READ_LETTER 'r'

/*! \brief SEEN persistence */
/*! \note There is no way for \Seen to not be persistent, so this is always enabled. */
#define IMAP_ACL_SEEN (1 << 2)
#define IMAP_ACL_SEEN_LETTER 's'

/*! \brief Set or clear flags other than \Seen or \Deleted via STORE, or set using APPEND/COPY */
#define IMAP_ACL_WRITE (1 << 3)
#define IMAP_ACL_WRITE_LETTER 'w'

/*! \brief Insert (APPEND, COPY) */
#define IMAP_ACL_INSERT (1 << 4)
#define IMAP_ACL_INSERT_LETTER 'i'

/*! \brief Post (send mail to submission address for mailbox), unused by IMAP4 */
#define IMAP_ACL_POST (1 << 5)
#define IMAP_ACL_POST_LETTER 'p'

/* RFC 4314 only ACLs */

/*! \brief CREATE, new mailbox RENAME */
#define IMAP_ACL_MAILBOX_CREATE (1 << 6)
#define IMAP_ACL_MAILBOX_CREATE_LETTER 'k'

/*! \brief DELETE mailbox, old mailbox DELETE */
#define IMAP_ACL_MAILBOX_DELETE (1 << 7)
#define IMAP_ACL_MAILBOX_DELETE_LETTER 'x'

/*! \brief DELETE messages (\Deleted flag via STORE, APPEND, COPY) */
#define IMAP_ACL_DELETE (1 << 8)
#define IMAP_ACL_DELETE_LETTER 't'

/*! \brief EXPUNGE, expunge as part of CLOSE */
#define IMAP_ACL_EXPUNGE (1 << 9)
#define IMAP_ACL_EXPUNGE_LETTER 'e'

/*! \brief Administer (SETACL/DELETEACL/GETACL/LISTRIGHTS) */
#define IMAP_ACL_ADMINISTER (1 << 10)
#define IMAP_ACL_ADMINISTER_LETTER 'a'

/*! \brief Obsolete ACLs from RFC 2086 */
#define IMAP_ACL_UNION_CREATE_LETTER 'c'
#define IMAP_ACL_UNION_DELETE_LETTER 'd'

/*! \brief Default ACLs for different namespaces: private = everything, other/shared = nothing */
#define IMAP_ACL_DEFAULT_PRIVATE (IMAP_ACL_LOOKUP | IMAP_ACL_READ | IMAP_ACL_SEEN | IMAP_ACL_WRITE | IMAP_ACL_INSERT | IMAP_ACL_POST | IMAP_ACL_MAILBOX_CREATE | IMAP_ACL_MAILBOX_DELETE | IMAP_ACL_DELETE | IMAP_ACL_EXPUNGE | IMAP_ACL_ADMINISTER)
#define IMAP_ACL_DEFAULT_OTHER 0
#define IMAP_ACL_DEFAULT_SHARED 0

#define PARSE_ACL_LETTER(aclflag) \
	case aclflag ## _LETTER: \
		acl |= aclflag; \
		break; \

#define WRITE_ACL_LETTER(aclflag) \
	if (acl & aclflag) { \
		*buf++ = aclflag ## _LETTER; \
	}

/*! \brief Parse IMAP ACL from string */
static int parse_acl(const char *aclstring)
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

static void generate_acl_string(int acl, char *buf, size_t len)
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

struct imap_session {
	int rfd;
	int wfd;
	char *tag;
	struct bbs_node *node;
	struct mailbox *mbox;		/* Current mailbox (mailbox as in entire mailbox, not just a mailbox folder) */
	struct mailbox *mymbox;		/* Pointer to user's private/personal mailbox. */
	char *folder;
	char *savedtag;
	/* maildir */
	char dir[256];
	char newdir[260]; /* 4 more, for /new and /cur */
	char curdir[260];
	unsigned int uidvalidity;
	unsigned int uidnext;
	int acl;					/* Cached ACL for current directory. We allowed to cache per a mailbox by the RFC. */
	/* APPEND */
	char appenddir[212];		/* APPEND directory */
	char appendtmp[260];		/* APPEND tmp name */
	char appendnew[260];		/* APPEND new name */
	char appendkeywords[27];	/* APPEND keywords (custom flags) */
	char *appenddate;			/* APPEND optional date */
	int appendflags;			/* APPEND optional flags */
	int appendfile;				/* File descriptor of current APPEND file */
	unsigned int appendsize;	/* Expected size of APPEND */
	unsigned int appendcur;		/* Bytes received so far in APPEND transfer */
	unsigned int numappendkeywords:5; /* Number of append keywords. We only need 5 bits since this cannot exceed 26. */
	unsigned int appendfail:1;
	unsigned int createdkeyword:1;	/* Whether a keyword was created in response to a STORE */
	/* Traversal flags */
	unsigned int totalnew;		/* In "new" maildir. Will be moved to "cur" when seen. */
	unsigned int totalcur;		/* In "cur" maildir. */
	unsigned int totalunseen;	/* Messages with Unseen flag (or more rather, without the Seen flag). */
	unsigned int firstunseen;	/* Oldest message that is not Seen. */
	unsigned int expungeindex;	/* Index for EXPUNGE */
	unsigned int innew:1;		/* So we can use the same callback for both new and cur */
	unsigned int readonly:1;	/* SELECT vs EXAMINE */
	unsigned int inauth:1;
	unsigned int idle:1;		/* Whether IDLE is active */
	pthread_mutex_t lock;		/* Lock for IMAP session */
	RWLIST_ENTRY(imap_session) entry;	/* Next active session */
};

static RWLIST_HEAD_STATIC(sessions, imap_session);

static int __attribute__ ((format (gnu_printf, 2, 3))) __imap_broadcast(struct imap_session *imap, const char *fmt, ...)
{
	struct imap_session *s;
	char *buf;
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	/* Write to this IMAP session first, since the client that expected a response should get it before any unsolicited replies go out. */
	pthread_mutex_lock(&imap->lock);
	dprintf(imap->wfd, "%s", buf);
	pthread_mutex_unlock(&imap->lock);

	/* Write to all IMAP sessions that share the same mailbox and current folder (imap->dir), excluding ourselves since we already went first. */
	/* Note that we do this regardless of whether or not the client is idling.
	 * This functionality actually doesn't have anything to do with IDLE.
	 * From RFC 2177, even without idle: the client MUST continue to be able to accept unsolicited untagged responses to ANY command
	 * So in theory, anything using imap_send could use imap_send_broadcast, if we wanted.
	 * EXPUNGE and EXISTS are just specifically called out in the RFC for such unsolicited responses. */
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		if (s == imap) {
			continue; /* Already did ourself first, above, don't do us again. */
		}
		if (s->mbox != imap->mbox) {
			continue; /* Different mailbox (account) */
		}
		if (strcmp(s->dir, imap->dir)) {
			continue; /* Different folders. */
		}
		/* Hey, this client is on the same exact folder right now! Send it an unsolicited, untagged response. */
		pthread_mutex_lock(&s->lock);
		dprintf(s->wfd, "%s", buf);
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);

	free(buf);
	return 0;
}

static int num_messages(const char *path)
{
	DIR *dir;
	struct dirent *entry;
	int num = 0;

	/* Order doesn't matter here, we just want the total number of messages, so fine (and faster) to use opendir instead of scandir */
	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		num++;
	}

	closedir(dir);
	return num;
}

/* All IMAP traversals must be ordered, so we can't use these functions or we'll get a ~random (at least incorrect) order */
/* Sequence numbers must strictly be in order, if they aren't, all sorts of weird stuff will happened.
 * I know this because I tried using these functions first, and it didn't really work.
 * Because scandir allocates memory for all the files in a directory up front, it could result in a lot of memory usage.
 * Technically, for this reason, may want to limit the number of messages in a single mailbox (folder) for this reason.
 */
#define opendir __Do_not_use_readdir_or_opendir_use_scandir
#define readdir __Do_not_use_readdir_or_opendir_use_scandir
#define closedir __Do_not_use_readdir_or_opendir_use_scandir

/*! \brief Callback for new messages (delivered by SMTP to the INBOX) */
static void imap_mbox_watcher(struct mailbox *mbox, const char *newfile)
{
	int numtotal = -1;
	struct imap_session *s;

	UNUSED(newfile);

	/* Notify anyone watching this mailbox, specifically the INBOX. */
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		if (s->mbox != mbox) {
			continue; /* Different mailbox (account) */
		}
		if (strcmp(s->dir, mailbox_maildir(mbox))) {
			continue; /* Different folders. */
		}
		/* Hey, this client is on the same exact folder right now! Send it an unsolicited, untagged response. */
		if (numtotal == -1) {
			/* Compute how many messages exist. */
			numtotal = num_messages(s->newdir) + num_messages(s->curdir);
			bbs_debug(4, "Calculated %d message%s in INBOX %d currently\n", numtotal, ESS(numtotal), mailbox_id(mbox));
		}
		if (numtotal < 1) { /* Calculate the number of messages "just in time", only if somebody is actually in the INBOX right now. */
			/* Should be at least 1, because this callback is triggered when we get a NEW message. So there's at least that one. */
			bbs_error("Expected at least %d message, but calculated %d?\n", 1, numtotal);
			continue; /* Don't send the client something clearly bogus */
		}
		pthread_mutex_lock(&s->lock);
		imap_debug(4, "%p <= * %d EXISTS\r\n", s, numtotal);
		dprintf(s->wfd, "* %d EXISTS\r\n", numtotal); /* Number of messages in the mailbox. */
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
}

static void imap_destroy(struct imap_session *imap)
{
	if (imap->mbox != imap->mymbox) {
		mailbox_unwatch(imap->mbox);
		imap->mbox = imap->mymbox;
		imap->mymbox = NULL;
	}
	if (imap->mbox) {
		mailbox_unwatch(imap->mbox); /* We previously started watching it, so stop watching it now. */
		imap->mbox = NULL;
	}
	close_if(imap->appendfile);
	free_if(imap->appenddate);
	/* Do not free tag, since it's stack allocated */
	free_if(imap->savedtag);
	free_if(imap->folder);
	pthread_mutex_destroy(&imap->lock);
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

#define get_uidnext(imap, directory) mailbox_get_next_uid(imap->mbox, directory, 0, &imap->uidvalidity, &imap->uidnext)

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
/* List of capabilities: https://www.iana.org/assignments/imap-capabilities/imap-capabilities.xml */
/* XXX IDLE is advertised here even if disabled (although if disabled, it won't work if a client tries to use it) */
#define IMAP_CAPABILITIES IMAP_REV " AUTH=PLAIN UNSELECT CHILDREN IDLE NAMESPACE QUOTA QUOTA=RES-STORAGE ID SASL-IR ACL SORT"
#define IMAP_FLAGS FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN " " FLAG_NAME_ANSWERED " " FLAG_NAME_DELETED " " FLAG_NAME_DRAFT
#define HIERARCHY_DELIMITER "."

/* RFC 2342 Namespaces: prefix and hierarchy delimiter */
#define PRIVATE_NAMESPACE_PREFIX ""
#define OTHER_NAMESPACE_PREFIX "Other Users"
#define SHARED_NAMESPACE_PREFIX "Shared Folders"
#define PRIVATE_NAMESPACE "((\"\" \".\"))"
#define OTHER_NAMESPACE "((\"" OTHER_NAMESPACE_PREFIX "\" \".\"))"
#define SHARED_NAMESPACE "((\"" SHARED_NAMESPACE_PREFIX "\" \".\"))"

/* Namespaces are useful for allowing users access to other mailboxes.
 * To handle this, we leverage imap_translate_dir to take namespaces and ACLs into account.
 * When a SELECT is issued by the client, the prefix for the namespace is already included,
 * and we're really none the wiser that it's in a namespace. However, we can check if it
 * starts with the prefix for a other or shared namespaces to detect this.
 * This may be necessary if the namespace is outside of the user's root maildir.
 * Currently, the 3 namespaces are identical for all users, to simplify this,
 * but in theory this need not be the case and would be simple to extend if needed.
 */

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

/* The implementation of how keywords are stored is based on how Dovecot stores keywords:
 * https://doc.dovecot.org/admin_manual/mailbox_formats/maildir/
 * We use 26 lowercase letters, to differentiate from IMAP flags (uppercase letters).
 * However, we don't a uidlist file, and we store the keywords in a separate file.
 * The implementation is handled fully in net_imap, since other modules don't care about keywords.
 */

#define MAX_KEYWORDS 26

/*! \brief Check filename for the mapping for keyword. If one does not exist and there is room ( < 26), it will be created. */
static void parse_keyword(struct imap_session *imap, const char *s, int create)
{
	char filename[266];
	char buf[32];
	FILE *fp;
	char index = 0;

	/* Many keywords start with $, but not all of them do */
	if (imap->numappendkeywords >= MAX_KEYWORDS) {
		bbs_warning("Can't store any more keywords\n");
		return;
	}

	/* Check using file in current maildir */
	snprintf(filename, sizeof(filename), "%s/.keywords", imap->dir);
	/* Open the file in read + append mode.
	 * If the file does not yet exist, it should be created.
	 * However, we need to lock if we're appending, so this whole thing must be atomic.
	 */

	mailbox_uid_lock(imap->mbox); /* We're not doing anything with the UID, but that's a global short-lived lock for the mailbox we can use (unlike mailbox_wrlock) */
	fp = fopen(filename, "a+"); /* XXX Silly to reopen this file in every loop of parse_flags_string. In practice, most messages will probably only have 1 keyword, if any. */
	if (unlikely(!!!fp)) { /* same as fp == NULL */
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
			char newindex = 'a' + index;
			fprintf(fp, "%c %s\n", newindex, s);
			imap->appendkeywords[imap->numappendkeywords++] = newindex; /* Safe, since we know we're in bounds */
			imap->createdkeyword = 1;
		}
	}

	mailbox_uid_unlock(imap->mbox);
	fclose(fp);
}

static int gen_keyword_names(struct imap_session *imap, const char *s, char *inbuf, size_t inlen)
{
	FILE *fp;
	char fbuf[32];
	char filename[266];
	char *buf = inbuf;
	int matches = 0;
	int keywordslen = 0;
	int left = inlen;

	snprintf(filename, sizeof(filename), "%s/.keywords", imap->dir);

	*buf = '\0';
	fp = fopen(filename, "r");
	if (!fp) {
		return 0;
	}

	while ((fgets(fbuf, sizeof(fbuf), fp))) {
		if (!s || strchr(s, fbuf[0])) {
			matches++;
			bbs_strterm(fbuf, '\n');
			SAFE_FAST_COND_APPEND_NOSPACE(inbuf, buf, left, 1, " %s", fbuf + 2);
		}
	}

	if (s) {
		while (*s) {
			if (islower(*s)) {
				keywordslen++;
			}
			s++;
		}

		if (keywordslen > matches) {
			bbs_warning("File has %d flags, but we only have mappings for %d of them?\n", keywordslen, matches);
		}
	}
	fclose(fp);
	return matches;
}

/*! \brief Convert named flag or keyword into a single character for maildir filename */
/*! \note If imap is not NULL, custom keywords are stored in imap->appendkeywords (size is stored in imap->numappendkeywords) */
static int parse_flags_string(struct imap_session *imap, char *s)
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
		} else if (*f == '\\') {
			bbs_warning("Failed to parse flag: %s\n", f); /* Unknown non-custom flag */
		} else if (imap) { /* else, it's a custom flag (keyword), if we have a mailbox, check the translation. */
			parse_keyword(imap, f, 1);
		}
	}
	if (imap) {
		imap->appendkeywords[imap->numappendkeywords] = '\0'; /* Null terminate the keywords buffer */
	}
	return flags;
}

/*! \param keywords[out] Pointer to beginning of keywords, if any */
static int parse_flags_letters(const char *f, const char **keywords)
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
			case 'a' ... 'z':
				if (keywords) {
					*keywords = f;
				}
				return flags; /* If we encounter keywords (custom flags), we know we're done parsing builtin flags */
			case FLAG_PASSED:
			case FLAG_REPLIED:
			default:
				bbs_warning("Unhandled flag: %c\n", *f);
		}
		f++;
	}

	return flags;
}

/*! \param keywordsbuf. Must be of size 27 */
static int parse_flags_letters_from_filename(const char *filename, int *flags, char *keywordsbuf)
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
	SAFE_FAST_COND_APPEND(fullbuf, buf, left, strchr(flagstr, FLAG_TRASHED), FLAG_NAME_DELETED);
}

static int test_flags_parsing(void)
{
	char buf[64] = FLAG_NAME_DELETED " " FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN;
	bbs_test_assert_equals(FLAG_BIT_DELETED | FLAG_BIT_FLAGGED | FLAG_BIT_SEEN, parse_flags_string(NULL, buf));
	bbs_test_assert_equals(FLAG_BIT_DRAFT | FLAG_BIT_SEEN, parse_flags_letters("DS", NULL));

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

#define REQUIRE_SELECTED(imap) \
	if (s_strlen_zero(imap->dir)) { \
		imap_reply(imap, "NO Must select a mailbox first"); \
		return 0; \
	}

#define SHIFT_OPTIONALLY_QUOTED_ARG(assign, s) \
	REQUIRE_ARGS(s); \
	if (*s == '"') { \
		s++; \
		assign = s; \
		s = strchr(s, '"'); \
		REQUIRE_ARGS(s); \
		*s++ = '\0'; \
		if (*s) { \
			s++; \
		} \
	} else { \
		assign = strsep(&s, " "); \
		STRIP_QUOTES(assign); \
	}

/*! \todo There is locking in a few places, but there probably needs to be a lot more of it.
 * POP3 WRLOCKs the entire mailbox when it starts a session,
 * and we need to ensure that we try to at least grab a RDLOCK when doing anything that
 * could potentially interfere with that. */
#define MAILBOX_TRYRDLOCK(imap) \
	if (mailbox_rdlock(imap->mbox)) { \
		imap_reply(imap, "NO Mailbox busy"); \
		return 0; \
	}

#define IMAP_NO_READONLY(imap) \
	if (imap->readonly) { \
		imap_reply(imap, "NO Mailbox is read only"); \
	}

enum mailbox_namespace {
	NAMESPACE_PRIVATE = 0,
	NAMESPACE_OTHER,
	NAMESPACE_SHARED,
};

static int load_acl_file(const char *filename, const char *matchstr, int matchlen, int *acl)
{
	char aclbuf[72];
	FILE *fp;
	int res = -1; /* If no match for this user, we still need to use the defaults. */

	fp = fopen(filename, "r");
	if (!fp) {
		return -1;
	}

	while ((fgets(aclbuf, sizeof(aclbuf), fp))) {
		char *aclstr;
		if (strncasecmp(aclbuf, matchstr, matchlen)) {
			continue;
		}
		aclstr = strchr(aclbuf, ' ');
		if (!aclstr) {
			bbs_error("Invalid ACL entry: %s\n", aclbuf);
			continue;
		}
		aclstr++;
		*acl = parse_acl(aclstr);
		res = 0;
		break;
	}
	fclose(fp);
	return res;
}

static void load_acl(struct imap_session *imap, const char *directory, enum mailbox_namespace ns, int *acl)
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
		if (!load_acl_file(fullname, matchbuf, matchlen, acl)) {
			goto done;
		}
		/* Traverse up to the .acl directory in the parent dir */
		/*! \todo Probably should not do this actually, if no .acl file in current, apply defaults immediately */
		slash = strrchr(fullname, '/');
		*slash = '\0'; /* This will always succeed, slash can never be NULL */
		slash = strrchr(fullname, '/');
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

	/* If no ACLs specified for this user, for this mailbox, go with the default for this namespace */
	if (ns == NAMESPACE_PRIVATE) {
		*acl = IMAP_ACL_DEFAULT_PRIVATE;
	} else if (ns == NAMESPACE_OTHER) {
		*acl = IMAP_ACL_DEFAULT_OTHER;
	} else {
		*acl = IMAP_ACL_DEFAULT_SHARED;
	}

done:
#ifdef DEBUG_ACL
	generate_acl_string(*acl, buf, sizeof(buf));
	bbs_debug(5, "Effective ACL for %s: %s\n", directory, buf);
#else
	return;
#endif
}

static int getacl(struct imap_session *imap, const char *directory, const char *mailbox)
{
	char fullname[256];
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
		dyn_str_append(&dynstr, appendbuf, len);
	}

	fclose(fp);

	imap_send(imap, "ACL %s%s", mailbox, S_IF(dynstr.buf));
	if (dynstr.buf) {
		free(dynstr.buf);
	}

	return 0;
}

static pthread_mutex_t acl_lock;

static int setacl(struct imap_session *imap, const char *directory, const char *mailbox, const char *user, const char *newacl)
{
	char fullname[256];
	char fullname2[256];
	char findstr[64];
	char buf[256];
	FILE *fp, *fp2;
	int userlen;
	int existed = 0;

	UNUSED(imap);
	UNUSED(mailbox);

	snprintf(fullname, sizeof(fullname), "%s/.acl", directory);
	pthread_mutex_lock(&acl_lock);
	fp = fopen(fullname, "r+"); /* Open with r+ in case we end up appending to the original file */
	if (!fp) {
		/* No existing ACLs, this is the easy case. Just write a new file and return.
		 * There is technically a race condition possible here, we're the only process using this file,
		 * but another thread could be trying to access it too. So that's why we have a lock. */
		fp = fopen(fullname, "w");
		if (!fp) {
			bbs_error("Failed to open %s for writing\n", fullname);
			pthread_mutex_unlock(&acl_lock);
			return -1;
		}
		/* XXX Should probably validate and verify this first */
		fprintf(fp, "%s %s\n", user, newacl);
		fclose(fp);
		pthread_mutex_unlock(&acl_lock);
		return 0;
	}

	/* We have to read from the current ACL file and write out the new ACL file at the same time. */
	snprintf(fullname2, sizeof(fullname2), "%s/.aclnew", directory);
	fp2 = fopen(fullname2, "w");
	if (!fp2) {
		bbs_error("Failed to open %s for writing\n", fullname2);
		pthread_mutex_unlock(&acl_lock);
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
			/* We want to replace this line */
			/* XXX Should probably validate and verify this first */
			if (newacl) { /* Copy over, unless we're deleting */
				fprintf(fp2, "%s %s\n", user, newacl);
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
			pthread_mutex_unlock(&acl_lock);
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
	pthread_mutex_unlock(&acl_lock);
	return 0;
}

/*! \brief Translate an IMAP directory path to the full path of the IMAP mailbox on disk */
static int imap_translate_dir(struct imap_session *imap, const char *directory, char *buf, size_t len, int *acl)
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
			mbox = mailbox_get(0, name);
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
			bbs_strterm(username, '.');
			userid = bbs_userid_from_username(username);
			if (!userid) {
				bbs_warning("No such user: %s\n", username);
				return -1;
			}
			remainder += strlen(username);
			/* Just this is \Select'able, it's the INBOX (INBOX isn't shown as a separate subdir for Other Users, etc.) */
			snprintf(buf, len, "%s/%d%s%s", mailbox_maildir(NULL), userid, !strlen_zero(remainder) ? "/" : "", remainder); /* Don't end in a trailing slash */
			/* Update mailbox to pointer to the right one */
			/* imap->mbox refers to the personal mailbox, not this other user's mailbox...
			 * imap->mbox needs to point to the other user's mailbox now. */
			/* Keep watching our personal mailbox, but also watch the new one. */
			mbox = mailbox_get(userid, NULL);
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

#define IMAP_HAS_ACL(acl, flag) (acl & (flag))
#define IMAP_REQUIRE_ACL(acl, flag) \
	if (!IMAP_HAS_ACL(acl, (flag))) { \
		char _aclbuf[15]; \
		generate_acl_string(acl, _aclbuf, sizeof(_aclbuf)); \
		bbs_debug(4, "User missing ACL %s (have %s)\n", #flag, _aclbuf); \
		imap_reply(imap, "NO Permission denied"); \
		return 0; \
	}

static int set_maildir(struct imap_session *imap, const char *mailbox)
{
	char dir[256];
	int acl;
	if (strlen_zero(mailbox)) {
		imap_reply(imap, "BAD Missing argument");
		return -1;
	}

	if (imap_translate_dir(imap, mailbox, dir, sizeof(dir), &acl)) {
		imap_reply(imap, "NO No such mailbox '%s'", mailbox);
		return -1;
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

static int parse_uid_from_filename(const char *filename, unsigned int *uid)
{
	char *uidstr = strstr(filename, ",U=");
	if (!uidstr) {
		return -1;
	}
	if (uidstr) {
		uidstr += STRLEN(",U=");
		if (!strlen_zero(uidstr)) {
			*uid = atoi(uidstr); /* Should stop as soon we encounter the first nonnumeric character, whether , or : */
			if (*uid <= 0) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	return 0;
}

static int on_select(const char *dir_name, const char *filename, struct imap_session *imap)
{
	char *flags;

#ifdef EXTRA_DEBUG
	imap_debug(9, "Analyzing file %s/%s (readonly: %d)\n", dir_name, filename, imap->readonly);
#endif

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
			parse_uid_from_filename(filename, &uid);
			flags++;
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

static inline unsigned int parse_size_from_filename(const char *filename, unsigned long *size)
{
	const char *sizestr = strstr(filename, ",S=");
	if (!sizestr) {
		bbs_error("Missing size in file %s\n", filename);
		return -1;
	}
	sizestr += STRLEN(",S=");
	*size = atol(sizestr);
	if (*size <= 0) {
		bbs_warning("Invalid size (%lu) for %s\n", *size, filename);
	}
	return 0;
}

static int expunge_helper(const char *dir_name, const char *filename, struct imap_session *imap, int expunge)
{
	int oldflags;
	char fullpath[256];
	unsigned long size;

	/* This is the final stage of deletions.
	 * What clients generally do when you "delete" an item is
	 * they COPY it to the Trash folder, then set the Deleted flag on the message.
	 * They fetch the flags for the message to confirm the Deleted flag is present,
	 * and then the message "disappears" from the UI. However, the message still exists.
	 * When the mail client exits, it will issue a "CLOSE" command,
	 * which will actually go ahead and remove the messages, deleting them permanently from the original folder.
	 * Of course, they're still in the Trash directory, until they're auto-deleted or removed from there
	 * using the same process.
	 */

	imap->expungeindex += 1;

#ifdef EXTRA_DEBUG
	imap_debug(10, "Analyzing file %s/%s\n", dir_name, filename);
#endif
	if (parse_flags_letters_from_filename(filename, &oldflags, NULL)) { /* Don't care about keywords */
		bbs_error("File %s is noncompliant with maildir\n", filename);
		return 0;
	}
	if (!(oldflags & FLAG_BIT_DELETED)) {
		return 0;
	}

	/* Marked as deleted. Remove message, permanently. */
	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	imap_debug(4, "Permanently removing message %s\n", fullpath);
	MAILBOX_TRYRDLOCK(imap);
	if (unlink(fullpath)) {
		bbs_error("Failed to delete %s: %s\n", fullpath, strerror(errno));
	}
	mailbox_unlock(imap->mbox);
	if (parse_size_from_filename(filename, &size)) {
		/* It's too late to stat now as a fallback, the file's gone, who knows how big it was now. */
		mailbox_invalidate_quota_cache(imap->mbox);
	} else {
		mailbox_quota_adjust_usage(imap->mbox, -size);
	}
	if (expunge) {
		imap_send_broadcast(imap, "%d EXPUNGE", imap->expungeindex); /* Send for EXPUNGE, but not CLOSE */
	}
	/* EXPUNGE indexes update as we actively expunge messages.
	 * i.e. if we were to delete all the messages in a directory,
	 * the responses might look like:
	 * 1 EXPUNGE
	 * 1 EXPUNGE
	 * 1 EXPUNGE
	 * etc...
	 *
	 * So every time we delete a message, decrement 1 so we're where we should be. */
	imap->expungeindex -= 1;
	return 0;
}

static int on_close(const char *dir_name, const char *filename, struct imap_session *imap)
{
	return expunge_helper(dir_name, filename, imap, 0);
}

static int on_expunge(const char *dir_name, const char *filename, struct imap_session *imap)
{
	return expunge_helper(dir_name, filename, imap, 1);
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
			free(entry);
			continue;
		}
		if ((res = on_file(path, entry->d_name, imap))) {
			free(entry);
			break; /* If the handler returns non-zero then stop */
		}
		free(entry);
	}
	free(entries);
	return res;
}

static int handle_select(struct imap_session *imap, char *s, int readonly)
{
	/* Mailbox can contain spaces, so don't use strsep for it if it's in quotes */
	char *mailbox;

	REQUIRE_ARGS(s);

	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s); /* The STATUS command will have additional arguments */

	/* This modifies the current maildir even for STATUS, but the STATUS command will restore the old one afterwards. */
	if (set_maildir(imap, mailbox)) { /* Note that set_maildir handles mailbox being "INBOX". It may also change the active (account) mailbox. */
		return 0;
	}
	if (!readonly) {
		static int sharedflagrights = IMAP_ACL_SEEN | IMAP_ACL_WRITE;
		readonly = IMAP_HAS_ACL(imap->acl, IMAP_ACL_INSERT | IMAP_ACL_EXPUNGE | sharedflagrights) ? 0 : 1;
	}
	if (readonly <= 1) { /* SELECT and EXAMINE should update currently selected mailbox, STATUS should not */
		REPLACE(imap->folder, mailbox);
	}
	if (readonly == 1) {
		imap->readonly = readonly;
	} else {
		imap->readonly = 0; /* In case the previously SELECTed folder was read only */
	}
	mailbox_has_activity(imap->mbox); /* Clear any activity flag since we're about to do a traversal. */
	IMAP_TRAVERSAL(imap, on_select);
	if (readonly <= 1) { /* SELECT, EXAMINE */
		char aclstr[15];
		char keywords[256] = "";
		int numkeywords = gen_keyword_names(imap, NULL, keywords, sizeof(keywords)); /* prepends a space before all of them, so this works out great */
		imap_send(imap, "FLAGS (%s%s)", IMAP_FLAGS, numkeywords ? keywords : "");
		/* Any non-standard flags are called keywords in IMAP
		 * If we don't send a PERMANENTFLAGS, the RFC says that clients should assume all flags are permanent.
		 * This works if clients are not allowed to set custom flags.
		 * If they are, then we need to send the \* in the PERMANENTFLAGS response.
		 * See: https://news.purelymail.com/posts/status/2023-04-01-security-disclosure-user-flags.html
		 * specifically:
		 * "We thought we could omit the PERMANENTFLAGS response, since the spec says that
		 * if there is no PERMANENTFLAGS response then the client should assume all flags are permanent,
		 * which is the case for Purelymail. Unfortunately this meant clients like Mozilla Thunderbird
		 * assumed they could not create any new flags since they did not see a * response."
		 *
		 * (Side note: the security incident discussed in the above post mortem was uncovered
		 *  through development of this IMAP server, in testing certain behavior of existing IMAP servers.)
		 */
		imap_send(imap, "OK [PERMANENTFLAGS (%s%s \\*)]", IMAP_FLAGS, numkeywords ? keywords : ""); /* Include \* to indicate we support IMAP keywords */
		imap_send_broadcast(imap, "%u EXISTS", imap->totalnew + imap->totalcur); /* Number of messages in the mailbox. */
		imap_send(imap, "%u RECENT", imap->totalnew); /* Number of messages with \Recent flag (maildir: new, instead of cur). */
		if (imap->firstunseen) {
			/* Both of these are supposed to be firstunseen (the first one is NOT totalunseen) */
			imap_send(imap, "OK [UNSEEN %u] Message %u is first unseen", imap->firstunseen, imap->firstunseen);
		}
		imap_send(imap, "OK [UIDVALIDITY %u] UIDs valid", imap->uidvalidity);
		/* uidnext is really the current max UID allocated. The next message will have at least UID of uidnext + 1, but it could be larger. */
		imap_send(imap, "OK [UIDNEXT %u] Predicted next UID", imap->uidnext + 1);
		generate_acl_string(imap->acl, aclstr, sizeof(aclstr));
		imap_send(imap, "OK [MYRIGHTS \"%s\"] ACL", aclstr);
		/* Some other stuff might appear here, e.g. HIGHESTMODSEQ (RFC4551) that we don't currently support. */
		/* XXX All mailboxes are READ-WRITE right now, but could be just READ-ONLY. Need to add ACL extensions for that. */
		imap_reply(imap, "OK [%s] %s completed", readonly ? "READ-ONLY" : "READ-WRITE", readonly ? "EXAMINE" : "SELECT");
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
	} else {
		bbs_assert(0);
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
	bbs_test_assert_equals(1, list_match(".Sent", "*"));
	bbs_test_assert_equals(0, list_match(".Sent", "%"));
	bbs_test_assert_equals(1, list_match(".Sent", ".S%"));

	return 0;

cleanup:
	return -1;
}

static int imap_dir_has_subfolders(const char *path, const char *prefix)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res = 0;
	int prefixlen = strlen(prefix);

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			free(entry);
			continue;
		} else if (!strncmp(entry->d_name, prefix, prefixlen)) {
			const char *rest = entry->d_name + prefixlen; /* do not add these within the strlen_zero macro! */
			/*! \todo XXX Check entire code tree for strlen_zero with + inside adding arguments. That's a bug!!! */
			if (!strlen_zero(rest)) {
				res = 1;
				free(entry);
				break;
			}
		}
		free(entry);
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

static int get_attributes(const char *parentdir, const char *mailbox)
{
	int flags = 0;

	/* Great, we've just turned this into an n^2 operation now (the downside of IMAP hierarchy being only 2 levels on disk):
	 * But HasNoChildren and HasChildren are mandatory in the RFC, and they're pretty important attributes for the client, so compute them.
	 * In reality, it shouldn't take *too* terribly long since the number of folders (all folders, recursively), is still likely to be
	 * (some kind of small) constant, not even linear, so it's sublinear * sublinear. */
	if (imap_dir_has_subfolders(parentdir, mailbox)) {
		flags |= DIR_HAS_CHILDREN;
	} else {
		flags |= DIR_NO_CHILDREN;
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

static void str_tolower(char *s)
{
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

static void list_scandir(struct imap_session *imap, const char *listscandir, int lsub, int level, enum mailbox_namespace ns,
	char *attributes, size_t attrlen, const char *reference, const char *prefix, const char *mailbox, int reflen, int skiplen)
{
	struct dirent *entry, **entries;
	int files, fno = 0;

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(listscandir, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", mailbox_maildir(imap->mbox), strerror(errno));
		return;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type == DT_DIR && (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))) { /* We only care about directories, not files. */
			int myacl, flags = 0;
			char fulldir[257];
			char mailboxbuf[256];
			char relativepath[257];
			const char *mailboxname = entry->d_name;

			if (ns != NAMESPACE_PRIVATE) { /* Skip special directories in the root maildir */
				if (!strcmp(entry->d_name, "cur") || !strcmp(entry->d_name, "new") || !strcmp(entry->d_name, "tmp") || !strcmp(entry->d_name, "mailq")) {
					goto cleanup;
				}
			}
			if (level == 0 && ns == NAMESPACE_OTHER && isdigit(*entry->d_name)) {
				if (bbs_username_from_userid(atoi(entry->d_name), mailboxbuf, sizeof(mailboxbuf))) {
					bbs_warning("No user for maildir %s\n", entry->d_name);
					goto cleanup;
				}
				str_tolower(mailboxbuf); /* Convert to all lowercase since that's the convention we use for email */
				mailboxname = mailboxbuf; /* e.g. jsmith instead of 1 */
			} else if (level == 0 && ns == NAMESPACE_SHARED && !isdigit(*entry->d_name)) {
				mailboxname = entry->d_name; /* Mailbox name stays the same, this is technically a redundant instruction */
			} else if (*entry->d_name != '.') {
				/* maildir subdirectories start with . (maildir++ standard) */
				goto cleanup;
			}
			/* This is an instance where maildir format is nice, we don't have to recurse in this subdirectory. */
			if (strncmp(mailboxname, reference, reflen)) {
#ifdef EXTRA_DEBUG
				imap_debug(10, "Directory %s doesn't start with prefix %s\n", entry->d_name, reference);
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

			if (ns == NAMESPACE_PRIVATE) {
				/* For personal, you only see the contents of your mailbox, never mailboxes themselves. */
				safe_strncpy(relativepath, entry->d_name, sizeof(relativepath)); /*! \todo Optimize for this (common case) by updating a pointer when needed, rather than copying. */
			} else if (level == 1) {
				/* Other or Shared, inside the mailbox
				 * listscandir = mailbox path
				 * mailboxname = the name of this mailbox
				 * entry->d_name = name of the mailbox folder (e.g. .Sent, .Trash, .Sub.Folder, etc.)
				 */
				snprintf(relativepath, sizeof(relativepath), ".%s%s", mailboxname, entry->d_name);
			} else {
				/* Other or Shared, in the root maildir
				 * listscandir = root maildir path
				 * prefix is NULL
				 * mailboxname = e.g. jsmith, public
				 */
				snprintf(relativepath, sizeof(relativepath), ".%s", mailboxname);
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

#ifdef EXTRA_DEBUG
			imap_debug(10, "Matching IMAP path '%s' against query '%s'\n", relativepath, mailbox + skiplen);
#endif
			if (!list_match(relativepath, mailbox + skiplen)) {
#ifdef EXTRA_DEBUG
				imap_debug(9, "IMAP path '%s' does not match against query '%s'\n", relativepath, mailbox + skiplen);
#endif
				goto cleanup;
			}

			/* If it matches, we MIGHT want to include this in the results.
			 * That depends on if we're authorized by the ACL.
			 * Generate the full directory name so we can load the ACL from it */
			snprintf(fulldir, sizeof(fulldir), "%s/%s", listscandir, entry->d_name);
			load_acl(imap, fulldir, ns, &myacl);

			/* Suppress mailbox from LIST output if user doesn't at least have IMAP_ACL_LOOKUP for this mailbox. */
			if (!IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
				char aclbuf[256] = "";
				if (myacl != 0) {
					generate_acl_string(myacl, aclbuf, sizeof(aclbuf));
				}
#ifdef DEBUG_ACL
				bbs_debug(6, "User lacks permission for %s: %s\n", fulldir, aclbuf);
#endif
				goto recurse;
			}

			if (ns != NAMESPACE_PRIVATE && !level) { /* Most LISTs will be for the private namespace, so check that case first */
				/* We can't use get_attributes for the mailbox itself, since there won't be other directories
				 * in this same directory with the maildir++ format (e.g. for mailbox public, there is .Sent folder in public, e.g. public/.Sent,
				 * but public.Sent does not exist anywhere on disk.
				 * But we know it has children, since every mailbox has Sent/Drafts/Junk/etc. so just hardcode that here: */
				flags = DIR_HAS_CHILDREN;
			} else {
				flags = get_attributes(listscandir, entry->d_name);
			}
			build_attributes_string(attributes, attrlen, flags);
			imap_send(imap, "%s (%s) \"%s\" \"%s%s%s%s\"", lsub ? "LSUB" : "LIST", attributes, HIERARCHY_DELIMITER,
				ns == NAMESPACE_SHARED ? SHARED_NAMESPACE_PREFIX HIERARCHY_DELIMITER : ns == NAMESPACE_OTHER ? OTHER_NAMESPACE_PREFIX HIERARCHY_DELIMITER : "",
				S_IF(prefix), prefix ? HIERARCHY_DELIMITER : "", *mailboxname == '.' ? mailboxname + 1 : mailboxname); /* Always send the delimiter */
recurse:
			/* User may not be authorized for some mailbox, but may be authorized for a subdirectory (e.g. not INBOX, but some subfolder)
			 * However, this is incredibly expensive as it means "Other Users" will literally traverse every user's entire maildir. */
			if (ns != NAMESPACE_PRIVATE && !level) {
				/* Recurse only the first time, since there are no more maildirs within afterwards */
				list_scandir(imap, fulldir, lsub, 1, ns, attributes, attrlen, reference, mailboxname, mailbox, reflen, skiplen);
			}
cleanup:
			; /* Needed so we can jump to the cleanup label */
		}
		free(entry);
	}
	free(entries);
}

static int handle_list(struct imap_session *imap, char *s, int lsub)
{
	char *reference, *mailbox;
	int reflen;
	char attributes[128];
	const char *listscandir;
	enum mailbox_namespace ns;
	int skiplen = 0;

	reference = strsep(&s, " ");
	mailbox = s; /* Can contain spaces, so don't use strsep first */
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
		imap_send(imap, "%s (%s %s) %s %s", lsub ? "LSUB" : "LIST", ATTR_NOSELECT, ATTR_HAS_CHILDREN, QUOTED_ROOT, EMPTY_QUOTES);
		imap_reply(imap, "OK %s completed.", lsub ? "LSUB" : "LIST");
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

	ns = NAMESPACE_PRIVATE;
	listscandir = mailbox_maildir(imap->mbox);

	bbs_debug(6, "LIST traversal for '%s' '%s' => %s%s\n", reference, S_IF(mailbox), reference, S_IF(mailbox));

	/* XXX Hack for INBOX (since it's the top level maildir folder for the user), though this feels very klunky (but it's the target of the dir traversal, so...) */
	if (strlen_zero(reference) && (strlen_zero(mailbox) || !strcmp(mailbox, "*") || !strcmp(mailbox, "%"))) {
		/* Include INBOX first before doing the rest */
		build_attributes_string(attributes, sizeof(attributes), DIR_NO_CHILDREN);
		imap_send(imap, "%s (%s) \"%s\" \"%s\"", lsub ? "LSUB" : "LIST", attributes, HIERARCHY_DELIMITER, "INBOX");
	} else if (!strcmp(mailbox, "INBOX")) {
		build_attributes_string(attributes, sizeof(attributes), DIR_NO_CHILDREN);
		imap_send(imap, "%s (%s) \"%s\" \"%s\"", lsub ? "LSUB" : "LIST", attributes, HIERARCHY_DELIMITER, "INBOX");
		/* This was just for INBOX, so nothing else can possibly match. */
		/* XXX Again, the special handling of this feels clunky here */
		imap_reply(imap, "OK %s completed.", lsub ? "LSUB" : "LIST");
		return 0;
	} else {
		/* Different namespace? (Not the private one) */
		/* Example of doing that at the bottom of this page, e.g. 0 LIST "" "#shared.*" : http://www.courier-mta.org/imap/tutorial.setup.html */
		if (STARTS_WITH(mailbox, OTHER_NAMESPACE_PREFIX)) {
			listscandir = mailbox_maildir(NULL);
			ns = NAMESPACE_OTHER;
			skiplen = STRLEN(OTHER_NAMESPACE_PREFIX);
		} else if (STARTS_WITH(mailbox, SHARED_NAMESPACE_PREFIX)) {
			listscandir = mailbox_maildir(NULL);
			ns = NAMESPACE_SHARED;
			skiplen = STRLEN(SHARED_NAMESPACE_PREFIX);
		}
	}

#ifdef EXTRA_DEBUG
	bbs_debug(6, "Namespace type: %d, dir: %s, mailbox: %s, reflen: %d, skiplen: %d\n", ns, listscandir, mailbox, reflen, skiplen);
#endif
	list_scandir(imap, listscandir, lsub, 0, ns, attributes, sizeof(attributes), reference, NULL, mailbox, reflen, skiplen); /* Recursively LIST */

	imap_reply(imap, "OK %s completed.", lsub ? "LSUB" : "LIST");
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
	char *dup;
	char *sequence, *sequences;

	dup = strdup(s);
	if (ALLOC_FAILURE(dup)) {
		return 0;
	}
	sequences = dup;

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
		free(dup);
		return 1; /* Matches */
	}
	free(dup);
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

/*! \retval 0 if not in range, UID if in range */
static inline int msg_in_range(int seqno, const char *filename, const char *sequences, int usinguid)
{
	unsigned int msguid = 0;

	if (!usinguid) {
		/* XXX UIDs aren't guaranteed to be in order (see comment below), so we can't break if seqno > max */
		if (!in_range(sequences, seqno)) {
			return 0;
		}
	}

	/* Since we use scandir, msg sequence #s should be in order of oldest to newest */

	/* Parse UID */
	if (parse_uid_from_filename(filename, &msguid)) {
		bbs_error("Unexpected UID: %u\n", msguid);
		return 0;
	}
	if (usinguid) {
		if (!in_range(sequences, msguid)) {
			return 0;
		}
	}
	return msguid;
}

#define UINTLIST_CHUNK_SIZE 32
static int uintlist_append(unsigned int **a, int *lengths, int *allocsizes, unsigned int vala)
{
	int curlen;

	if (!*a) {
		*a = malloc(UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
		if (ALLOC_FAILURE(*a)) {
			return -1;
		}
		*allocsizes = UINTLIST_CHUNK_SIZE;
	} else {
		if (*lengths >= *allocsizes) {
			unsigned int *newa = realloc(*a, *allocsizes + UINTLIST_CHUNK_SIZE * sizeof(unsigned int)); /* Increase by 32 each chunk */
			if (ALLOC_FAILURE(newa)) {
				return -1;
			}
			*allocsizes = *allocsizes + UINTLIST_CHUNK_SIZE * sizeof(unsigned int);
			*a = newa;
		}
	}

	curlen = *lengths;
	(*a)[curlen] = vala;
	*lengths = curlen + 1;
	return 0;
}

static int uintlist_append2(unsigned int **a, unsigned int **b, int *lengths, int *allocsizes, unsigned int vala, unsigned int valb)
{
	int curlen;

	if (!*a) {
		*a = malloc(UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
		if (ALLOC_FAILURE(*a)) {
			return -1;
		}
		*b = malloc(UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
		if (ALLOC_FAILURE(*b)) {
			free_if(*a);
			return -1;
		}
		*allocsizes = UINTLIST_CHUNK_SIZE;
	} else {
		if (*lengths >= *allocsizes) {
			unsigned int *newb, *newa = realloc(*a, *allocsizes + UINTLIST_CHUNK_SIZE * sizeof(unsigned int)); /* Increase by 32 each chunk */
			if (ALLOC_FAILURE(newa)) {
				return -1;
			}
			newb = realloc(*b, *allocsizes + UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
			if (ALLOC_FAILURE(newb)) {
				/* This is tricky. We expanded a but failed to expand b. Keep the smaller size for our records. */
				return -1;
			}
			*allocsizes = *allocsizes + UINTLIST_CHUNK_SIZE * sizeof(unsigned int);
			*a = newa;
			*b = newb;
		}
	}

	curlen = *lengths;
	(*a)[curlen] = vala;
	(*b)[curlen] = valb;
	*lengths = curlen + 1;
	return 0;
}
#undef UINTLIST_CHUNK_SIZE

static int copyuid_str_append(struct dyn_str *dynstr, unsigned int a, unsigned int b)
{
	char range[32];
	int len;
	if (a == b) {
		len = snprintf(range, sizeof(range), "%s%u", dynstr->used ? "," : "", a);
	} else {
		len = snprintf(range, sizeof(range), "%s%u:%u", dynstr->used ? "," : "", a, b);
	}
	return dyn_str_append(dynstr, range, len);
}

static char *gen_uintlist(unsigned int *l, int lengths)
{
	int i;
	unsigned int begin, last;
	struct dyn_str dynstr;

	if (!lengths) {
		return NULL;
	}

	memset(&dynstr, 0, sizeof(dynstr));

	last = begin = l[0];
	for (i = 1; i < lengths; i++) {
		if (l[i] != last + 1) {
			/* Last one ended a range */
			copyuid_str_append(&dynstr, begin, last);
			begin = l[i]; /* Start of next range */
		}
		last = l[i];
	}
	/* Last one */
	copyuid_str_append(&dynstr, begin, last);
	return dynstr.buf; /* This is dynamically allocated, so okay */
}

static int test_copyuid_generation(void)
{
	unsigned int *a = NULL, *b = NULL;
	char *s = NULL;
	int lengths = 0, allocsizes = 0;

	uintlist_append2(&a, &b, &lengths, &allocsizes, 1, 11);
	uintlist_append2(&a, &b, &lengths, &allocsizes, 3, 13);
	uintlist_append2(&a, &b, &lengths, &allocsizes, 4, 14);
	uintlist_append2(&a, &b, &lengths, &allocsizes, 6, 16);

	s = gen_uintlist(a, lengths);
	bbs_test_assert_str_equals(s, "1,3:4,6");
	free_if(s);

	s = gen_uintlist(b, lengths);
	bbs_test_assert_str_equals(s, "11,13:14,16");
	free_if(s);

	free_if(a);
	free_if(b);
	return 0;

cleanup:
	free_if(a);
	free_if(b);
	free_if(s);
	return -1;
}

static int handle_copy(struct imap_session *imap, char *s, int usinguid)
{
	struct dirent *entry, **entries;
	char *sequences, *newbox;
	char newboxdir[256];
	char srcfile[516];
	int files, fno = 0;
	int seqno = 0;
	int numcopies = 0;
	unsigned int *olduids = NULL, *newuids = NULL;
	int lengths = 0, allocsizes = 0;
	unsigned int uidvalidity, uidnext, uidres;
	char *olduidstr = NULL, *newuidstr = NULL;
	unsigned long quotaleft;
	int destacl;

	sequences = strsep(&s, " "); /* Messages, specified by sequence number or by UID (if usinguid) */
	REQUIRE_ARGS(sequences);
	SHIFT_OPTIONALLY_QUOTED_ARG(newbox, s);

	/* We'll be moving into the cur directory. Don't specify here, maildir_copy_msg tacks on the /cur implicitly. */
	if (imap_translate_dir(imap, newbox, newboxdir, sizeof(newboxdir), &destacl)) { /* Destination directory doesn't exist. */
		imap_reply(imap, "NO [TRYCREATE] No such mailbox");
		return 0;
	}

	quotaleft = mailbox_quota_remaining(imap->mbox);

	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_INSERT); /* Must be able to copy to dest dir */
	/* XXX Per RFC 4314, we should only copy the flags over if the user has permission to do so.
	 * Even if the user does not have permission, per the RFC we must not fail the COPY/APPEND with a NO,
	 * we just silently ignore those flags.
	 * Currently, we just always copy, as we don't parse the flags for COPY/APPEND.
	 * This comment also applies to handle_append
	 */

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		unsigned int msguid;
		struct stat st;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}
		msguid = msg_in_range(++seqno, entry->d_name, sequences, usinguid);
		if (!msguid) {
			goto cleanup;
		}

		snprintf(srcfile, sizeof(srcfile), "%s/%s", imap->curdir, entry->d_name);
		if (stat(srcfile, &st)) {
			bbs_error("stat(%s) failed: %s\n", srcfile, strerror(errno));
		} else {
			quotaleft -= st.st_size; /* Determine if we would be about to exceed our current quota. */
			if (quotaleft <= 0) {
				bbs_verb(5, "Mailbox %d has insufficient quota remaining for COPY operation\n", mailbox_id(imap->mbox));
				free(entry);
				break; /* Insufficient quota remaining */
			}
		}
		uidres = maildir_copy_msg(imap->mbox, srcfile, entry->d_name, newboxdir, &uidvalidity, &uidnext);
		if (!uidres) {
			goto cleanup;
		}
		if (!uintlist_append2(&olduids, &newuids, &lengths, &allocsizes, msguid, uidres)) {
			numcopies++;
		}
cleanup:
		free(entry);
	}
	free(entries);
	/* UIDVALIDITY of dest mailbox, src UIDs, dest UIDs (in same order as src messages) */
	if (olduids || newuids) {
		olduidstr = gen_uintlist(olduids, lengths);
		newuidstr = gen_uintlist(newuids, lengths);
		free_if(olduids);
		free_if(newuids);
	}
	if (!numcopies && quotaleft <= 0) {
		imap_send(imap, "NO [OVERQUOTA] Quota has been exceeded");
		imap_reply(imap, "NO Insufficient quota remaining");
	} else {
		imap_reply(imap, "OK [COPYUID %u %s %s] COPY completed", uidvalidity, S_IF(olduidstr), S_IF(newuidstr));
	}
	free_if(olduidstr);
	free_if(newuidstr);
	return 0;
}

static int handle_append(struct imap_session *imap, char *s)
{
	int appendsize;
	char *mailbox, *flags, *date, *size;
	unsigned long quotaleft;
	int destacl;

	/* Format is mailbox [flags] [date] message literal
	 * The message literal begins with {size} on the same line
	 * See also RFC 3502. */

	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s);
	size = strchr(s, '{');
	if (!size) {
		imap_reply(imap, "NO Missing message literal size");
		return 0;
	}
	*size++ = '\0';

	/* To properly handle the case without flags or date,
	 * e.g. APPEND "INBOX" {1290}
	 * Since we haven't called strsep yet on s since we separated the mailbox,
	 * if there's no flags or date, then *s was { prior to size++.
	 * In this case, we can skip all this:
	 */
	if (size > s + 1) {
		/* These are both optional arguments */

		/* Multiword, e.g. APPEND "INBOX" "23-Jul-2002 19:39:23 -0400" {1110}
		 * In fact, if date is present, it is guaranteed to contain spaces. */
		if (*s == '"') {
			s++;
			flags = strsep(&s, "\"");
		} else {
			flags = strsep(&s, " ");
		}

		ltrim(s);
		if (*s == '"') {
			s++;
			date = strsep(&s, "\"");
		} else {
			date = strsep(&s, " ");
		}

		if (strlen_zero(date) && !strlen_zero(flags) && strchr(flags, ' ')) {
			/* Only date, and no flags */
			date = flags;
			flags = NULL;
		}

		imap->appendflags = 0;
		free_if(imap->appenddate);

		if (flags) {
			/* Skip () */
			bbs_strterm(flags, ')');
			flags++;
			if (!strlen_zero(flags)) {
				imap->appendflags = parse_flags_string(imap, flags);
				/* imap->appendkeywords will also contain keywords as well */
			}
		}
		if (date) {
			imap->appenddate = strdup(date);
		}
	}

	STRIP_QUOTES(mailbox);
	if (imap_translate_dir(imap, mailbox, imap->appenddir, sizeof(imap->appenddir), &destacl)) { /* Destination directory doesn't exist. */
		imap_reply(imap, "NO [TRYCREATE] No such mailbox");
		return 0;
	}

	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_INSERT);

	quotaleft = mailbox_quota_remaining(imap->mbox); /* Calculate current quota remaining to determine acceptance. */

	appendsize = atoi(size); /* Read this many bytes */
	if (appendsize <= 0) {
		imap_reply(imap, "NO Invalid message literal size");
		return 0;
	} else if (appendsize >= MAX_APPEND_SIZE) {
		imap_reply(imap, "NO Message too large");
		return 0;
	} else if ((unsigned long) appendsize >= quotaleft) {
		imap_send(imap, "NO [OVERQUOTA] Quota has been exceeded");
		imap_reply(imap, "NO Insufficient quota remaining");
		return 0;
	}

	_imap_reply(imap, "+ Ready for literal data\r\n");
	imap->appendsize = appendsize; /* Bytes we expect to receive */
	imap->appendcur = 0; /* Bytes received so far */
	imap->appendfile = maildir_mktemp(imap->appenddir, imap->appendtmp, sizeof(imap->appendtmp), imap->appendnew);
	if (imap->appendfile < 0) {
		return -1;
	}
	return 0;
}

static int maildir_msg_setflags(const char *origname, const char *newflagletters)
{
	char fullfilename[524];
	char dirpath[256];
	char *tmp, *filename;

	/* Generate new filename and do the rename */
	safe_strncpy(dirpath, origname, sizeof(dirpath));
	tmp = strrchr(dirpath, '/');
	if (tmp) {
		*tmp++ = '\0';
		filename = tmp;
		bbs_strterm(filename, ':');
	} else {
		bbs_error("Invalid filename: %s\n", origname);
		return -1;
	}
	snprintf(fullfilename, sizeof(fullfilename), "%s/%s:2,%s", dirpath, filename, newflagletters);
	if (!strcmp(origname, fullfilename)) {
		return 0; /* If the flags didn't change, no point in making an unnecessary system call */
	}
	bbs_debug(4, "Renaming %s -> %s\n", origname, fullfilename);
	if (rename(origname, fullfilename)) {
		bbs_error("rename %s -> %s failed: %s\n", origname, fullfilename, strerror(errno));
		return -1;
	}
	return 0;
}

static int finish_append(struct imap_session *imap)
{
	char curdir[260];
	char newdir[260];
	char newfilename[256];
	char *filename;
	int res;
	unsigned int uidvalidity, uidnext;
	unsigned long size;

	if (imap->appendcur != imap->appendsize) {
		bbs_warning("Client wanted to append %d bytes, but sent %d?\n", imap->appendsize, imap->appendcur);
	}
	imap->appendsize = 0; /* APPEND is over now */
	close_if(imap->appendfile);
	filename = strrchr(imap->appendnew, '/');
	if (!filename) {
		bbs_error("Invalid filename: %s\n", imap->appendnew);
		imap_reply(imap, "NO Append failed");
		return 0;
	}
	filename++; /* Just the base name now */
	if (rename(imap->appendtmp, imap->appendnew)) {
		bbs_error("rename %s -> %s failed: %s\n", imap->appendtmp, imap->appendnew, strerror(errno));
		imap_reply(imap, "NO Append failed");
		return 0;
	}

	/* File has been moved from tmp to new.
	 * Now, move it to cur.
	 * This is a 2-stage rename because we don't have a function to move an arbitrary
	 * file into a mailbox folder, only one that's already in cur,
	 * and the only function that properly initializes a filename is maildir_move_new_to_cur. */
	snprintf(curdir, sizeof(curdir), "%s/cur", imap->appenddir);
	snprintf(newdir, sizeof(newdir), "%s/new", imap->appenddir);
	res = maildir_move_new_to_cur_file(imap->mbox, imap->appenddir, curdir, newdir, filename, &uidvalidity, &uidnext, newfilename, sizeof(newfilename));
	if (res < 0) {
		imap_reply(imap, "NO Append failed");
		return 0;
	}

	/* maildir_move_new_to_cur_file conveniently put the size in the filename for us,
	 * so we can just update the quota usage accordingly rather than having to invalidate it. */
	if (parse_size_from_filename(newfilename, &size)) {
		/* It's too late to stat now as a fallback, the file's gone, who knows how big it was now. */
		mailbox_invalidate_quota_cache(imap->mbox);
	} else {
		mailbox_quota_adjust_usage(imap->mbox, -size);
	}

	/* Now, apply any flags to the message... (yet a third rename, potentially) */
	if (imap->appendflags) {
		char newflagletters[53];
		/* Generate flag letters from flag bits */
		gen_flag_letters(imap->appendflags, newflagletters, sizeof(newflagletters));
		if (imap->numappendkeywords) {
			strncat(newflagletters, imap->appendkeywords, sizeof(newflagletters) - 1);
		}
		imap->appendflags = 0;
		if (maildir_msg_setflags(newfilename, newflagletters)) {
			bbs_warning("Failed to set flags for %s\n", newfilename);
		}
	}

	/* Set the internal date? Maybe not, since the original date of the message should be preserved for best user experience. */
	/*! \todo Set the file creation/modified time (strptime)? (If we do this, it shouldn't be a value returned to the client later, see note above) */
	UNUSED(imap->appenddate);

	/* APPENDUID response */
	/* Use tag from APPEND request */
	_imap_reply(imap, "%s OK [APPENDUID %u %u] APPEND completed\r\n", imap->savedtag, uidvalidity, uidnext); /* Don't add 1, this is the current message UID, not UIDNEXT */
	return 0;
}

static int process_fetch(struct imap_session *imap, int usinguid, struct fetch_request *fetchreq, const char *sequences)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int seqno = 0;
	char response[1024];
	char headers[4096] = ""; /* XXX Large enough for all headers, etc.? */
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
		unsigned int msguid;
		const char *flags;
		FILE *fp;
		char fullname[516];
		int res;
		int sendbody = 0;
		int markseen = 0;
		char *dyn = NULL;
		int unoriginal = 0;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}
		msguid = msg_in_range(++seqno, entry->d_name, sequences, usinguid);
		if (!msguid) {
			goto cleanup;
		}
		/* At this point, the message is a match. Fetch everything we're supposed to for it. */
		buf = response;
		len = sizeof(response);
		snprintf(fullname, sizeof(fullname), "%s/%s", imap->curdir, entry->d_name);

		/* We need to include the updated flags in the reply, if we're marking as seen, so check this first.
		 * However, for, reasons, we'd prefer not to rename the file while we're doing stuff in the loop body.
		 * The maildir_msg_setflags API doesn't currently provide us back with the new renamed filename.
		 * So what we do is check if we need to mark as seen, but not actually mark as seen until the END of the loop.
		 * Consequently, we have to append the seen flag to the flags response manually if needed. */
		if (fetchreq->bodyargs && !fetchreq->bodypeek) {
			markseen = 1;
		}

		if (fetchreq->flags) {
			char flagsbuf[256];
			char inflags[53];
			int custom_keywords;

			flags = strchr(entry->d_name, ':'); /* maildir flags */
			if (!flags) {
				bbs_error("Message file %s contains no flags?\n", entry->d_name);
				goto cleanup;
			}
			if (markseen && !strchr(flags, FLAG_SEEN)) {
				inflags[0] = FLAG_SEEN;
				inflags[1] = '\0';
				safe_strncpy(inflags + 1, flags, sizeof(inflags) - 1);
				flags = inflags;
				bbs_debug(6, "Appending seen flag since message wasn't already seen\n");
			}
			gen_flag_names(flags, flagsbuf, sizeof(flagsbuf));
			SAFE_FAST_COND_APPEND(response, buf, len, 1, "FLAGS (%s", flagsbuf);
			/* If there are any keywords (custom flags), include those as well */
			custom_keywords = gen_keyword_names(imap, flags, flagsbuf, sizeof(flagsbuf));
			SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, custom_keywords, "%s", flagsbuf);
			SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, 1, ")");
		}
		if (fetchreq->rfc822size) {
			unsigned long size;
			if (parse_size_from_filename(entry->d_name, &size)) {
				goto cleanup;
			}
			/* XXX With Dovecot IMAPTest, we were getting warnings that RFC822.SIZE was 2 bytes too small
			 * and BODY length was 2 bytes too large. Adding 2 fixes this warnings, but maybe
			 * the BODY is where we actually need to address this. */
			SAFE_FAST_COND_APPEND(response, buf, len, 1, "RFC822.SIZE %lu", size + 2);
		}
		/* Must include UID in response, whether requested or not (so fetchreq->uid ignored) */
		SAFE_FAST_COND_APPEND(response, buf, len, 1, "UID %u", msguid);
		if (fetchreq->bodyargs || fetchreq->bodypeek) {
			const char *bodyargs = fetchreq->bodyargs ? fetchreq->bodyargs + 5 : fetchreq->bodypeek + 10;
			if (!strcmp(bodyargs, "HEADER]")) { /* e.g. BODY.PEEK[HEADER] */
				/* Just treat it as if we got a HEADER request directly, to send all the headers. */
				unoriginal = 1;
				SAFE_FAST_COND_APPEND(response, buf, len, 1, "%s", fetchreq->bodypeek ? "BODY.PEEK[HEADER]" : "BODY[HEADER]");
				fetchreq->rfc822header = 1;
				fetchreq->bodyargs = fetchreq->bodypeek = NULL; /* Don't execute the if statement below, so that we can execute the else if */
			}
		}
		if (fetchreq->internaldate) {
			struct stat st;
			if (stat(fullname, &st)) {
				bbs_error("stat(%s) failed: %s\n", fullname, strerror(errno));
			} else {
				struct tm modtime;
				char timebuf[40];
				/* Linux doesn't really have "time created" like Windows does. Just use the modified time,
				 * and hopefully renaming doesn't change that. */
				/* Use server's local time */
				/* Example INTERNALDATE format: 08-Nov-2022 01:19:54 +0000 */
				strftime(timebuf, sizeof(timebuf), "%d-%b-%Y %H:%M:%S %z", localtime_r(&st.st_mtim.tv_sec, &modtime));
				SAFE_FAST_COND_APPEND(response, buf, len, 1, "INTERNALDATE \"%s\"", timebuf);
			}
		}
		if (fetchreq->envelope) {
			char linebuf[1001];
			int findcount;
			int started = 0;
			char *bufhdr;

			SAFE_FAST_COND_APPEND(response, buf, len, 1, "ENVELOPE (");
			/* We can't rely on the headers in the message being in the desired order.
			 * So look for each one explicitly, which means we have to double loop.
			 * Furthermore, since there could be e.g. multiple To headers,
			 * we may need to add all of them.
			 */
			fp = fopen(fullname, "r");
			if (!fp) {
				bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
				goto cleanup;
			}

#define SEEK_HEADERS(hdrname) \
	rewind(fp); \
	findcount = 0; \
	while ((fgets(linebuf, sizeof(linebuf), fp))) { \
		bbs_strterm(linebuf, '\r'); \
		bbs_strterm(linebuf, '\n'); \
		if (s_strlen_zero(linebuf)) { \
			break; \
		} \
		if (!strncasecmp(linebuf, hdrname ":", STRLEN(hdrname ":"))) { \
			findcount++; \
		} \
		if (!strncasecmp(linebuf, hdrname ":", STRLEN(hdrname ":")))

#define END_SEEK_HEADERS \
	}

/* We cannot use the ternary operator here because this is already a macro, so the format string must be a constant, not a ternary expression */
#define APPEND_BUF_OR_NIL(bufptr, cond) \
	if ((cond)) { \
		SAFE_FAST_COND_APPEND(response, buf, len, 1, "\"%s\"", bufptr); \
	} else { \
		SAFE_FAST_COND_APPEND(response, buf, len, 1, "NIL"); \
	}

#define APPEND_BUF_OR_NIL_NOSPACE(bufptr, cond) \
	if ((cond)) { \
		SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, 1, "\"%s\"", bufptr); \
	} else { \
		SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, 1, "NIL"); \
	}

#define SEEK_HEADER_SINGLE(hdrname) \
	bufhdr = NULL; \
	SEEK_HEADERS(hdrname) { \
		bufhdr = linebuf + STRLEN(hdrname) + 1; \
		ltrim(bufhdr); \
		break; \
	} \
	END_SEEK_HEADERS; \
	if (!started) { \
		APPEND_BUF_OR_NIL_NOSPACE(bufhdr, !strlen_zero(bufhdr)); /* Use the NOSPACE version since this is the first one */ \
		started = 1; \
	} else { \
		APPEND_BUF_OR_NIL(bufhdr, !strlen_zero(bufhdr)); \
	}

#define SEEK_HEADER_MULTIPLE(hdrname) \
	SEEK_HEADERS(hdrname) { \
		char *name, *user, *host; \
		char *sourceroute = NULL; /* https://stackoverflow.com/questions/30693478/imap-envelope-email-address-format/30698163#30698163 */ \
		int local; \
		bufhdr = linebuf + STRLEN(hdrname) + 1; \
		ltrim(bufhdr); \
		bbs_parse_email_address(bufhdr, &name, &user, &host, &local); \
		if (name) { \
			STRIP_QUOTES(name); \
		} \
		/* Need spaces between them but not before the first one. And again, we can't use ternary expressions so do it the verbose way. */ \
		if (findcount > 1) { \
			SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, 1, " ("); \
		} else { \
			SAFE_FAST_COND_APPEND(response, buf, len, 1, "(("); /* First one, so also add the outer one */ \
		} \
		APPEND_BUF_OR_NIL_NOSPACE(name, !strlen_zero(name)); \
		APPEND_BUF_OR_NIL(sourceroute, !strlen_zero(sourceroute)); \
		APPEND_BUF_OR_NIL(user, !strlen_zero(user)); \
		APPEND_BUF_OR_NIL(host, !strlen_zero(host)); \
		SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, 1, ")"); \
		break; \
	} \
	END_SEEK_HEADERS; \
	if (findcount) { \
		SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, 1, ")"); \
	} else { \
		SAFE_FAST_COND_APPEND(response, buf, len, 1, "NIL"); \
	}

			/* From RFC:
			 * The fields of the envelope structure are in the following order:
			 * date, subject, from, sender, reply-to, to, cc, bcc, in-reply-to, and message-id.
			 * The date, subject, in-reply-to, and message-id fields are strings.
			 * The from, sender, reply-to, to, cc, and bcc fields are parenthesized lists of address structures.
			 * An address structure is a parenthesized list that describes an electronic mail address.
			 * The fields of an address structure are in the following order: personal name,
			 * [SMTP] at-domain-list (source route), mailbox name, and host name. */

			 /* Example (formatted with line breaks for clarity): * 1 FETCH (ENVELOPE
			  *
			  * ("Tue, 8 Nov 2022 01:19:53 +0000 (UTC)"
			  * "Welcome!"
			  * (("Sender Name" NIL "sender" "example.com"))
			  * (("Sender Name" NIL "sender" "example.com"))
			  * (("Sender Name" NIL "sender" "example.com"))
			  * (("Sender Name" NIL "recipientuser" "example.org"))
			  * NIL NIL NIL "<526638975.9347.1667870393918@hostname.internal>")
			  *
			  * UID 1)
			  */
			SEEK_HEADER_SINGLE("Date");
			SEEK_HEADER_SINGLE("Subject");
			SEEK_HEADER_MULTIPLE("From");
			SEEK_HEADER_MULTIPLE("Sender");
			SEEK_HEADER_MULTIPLE("Reply-To");
			SEEK_HEADER_MULTIPLE("To");
			SEEK_HEADER_MULTIPLE("Cc");
			SEEK_HEADER_MULTIPLE("Bcc");
			SEEK_HEADER_SINGLE("In-Reply-To");
			SEEK_HEADER_SINGLE("Message-Id");
			fclose(fp);
			SAFE_FAST_COND_APPEND_NOSPACE(response, buf, len, 1, ")");
		}
		/* HEADER.FIELDS involves a multiline response, so this should be processed at the end of this loop since it appends to response.
		 * Otherwise, something else might concatenate itself on at the end and break the response. */
		if (fetchreq->bodyargs || fetchreq->bodypeek) {
			/* Can be HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT, MIME, TEXT */
			char linebuf[1001];
			char *headpos = headers;
			int headlen = sizeof(headers);
			/* e.g. BODY[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To Received)] */
			const char *bodyargs = fetchreq->bodyargs ? fetchreq->bodyargs + 5 : fetchreq->bodypeek + 10;
			if (STARTS_WITH(bodyargs, "HEADER.FIELDS") || STARTS_WITH(bodyargs, "HEADER.FIELDS.NOT")) {
				char *headerlist, *tmp;
				int inverted = 0;
				int in_match = 0;
				if (STARTS_WITH(bodyargs, "HEADER.FIELDS.NOT")) {
					inverted = 1;
				}
				multiline = 1;
				bodyargs += STRLEN("HEADER.FIELDS (");
				/* Read the file until the first CR LF CR LF (end of headers) */
				fp = fopen(fullname, "r");
				if (!fp) {
					bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
					goto cleanup;
				}
				headerlist = malloc(strlen(bodyargs) + 2); /* Add 2, 1 for NUL and 1 for : at the beginning */
				if (ALLOC_FAILURE(headerlist)) {
					goto cleanup;
				}
				headerlist[0] = ':';
				strcpy(headerlist + 1, bodyargs); /* Safe */
				tmp = headerlist + 1; /* No need to check the first byte as it's already a :, so save a CPU cycle by skipping it */
				while (*tmp) {
					if (*tmp == ' ' || *tmp == ')') {
						*tmp = ':';
					}
					tmp++;
				}
				/* The RFC says no line should be more than 1,000 octets (bytes).
				 * Most clients will wrap at 72 characters, but we shouldn't rely on this. */
				while ((fgets(linebuf, sizeof(linebuf), fp))) {
					char headername[64];
					/* fgets does store the newline, so line should end in CR LF */
					if (!strcmp(linebuf, "\r\n")) {
						break; /* End of headers */
					}
					if (isspace(linebuf[0])) { /* It's part of a previous header (mutliline header) */
						SAFE_FAST_COND_APPEND_NOSPACE(headers, headpos, headlen, in_match, "%s", linebuf); /* Append if in match */
						continue;
					}
					headername[0] = ':';
					safe_strncpy(headername + 1, linebuf, sizeof(headername) - 1); /* Don't copy the whole line. XXX This assumes that no header name is longer than 64 chars. */
					tmp = strchr(headername + 1, ':');
					if (!tmp) {
						bbs_warning("Unexpected end of headers: %s\n", linebuf);
						break;
					}
					/* Since safe_strncpy will always null terminate, it is always safe to null terminate the character after this */
					*(tmp + 1) = '\0';
					/* Only include headers that were asked for. */
					/* Note that some header names can be substrings of others, e.g. the "To" header should not match for "In-Reply-To"
					 * bodyargs contains a list of (space delimited) header names that we can match on, so we can't just use strncmp.
					 * Above, we transform the list into a : delimited list (every header has a : after it, including the last one),
					 * so NOW we can just use strstr for :NAME:
					 */
					if ((!inverted && strcasestr(headerlist, headername)) || (inverted && !strcasestr(headerlist, headername))) {
						/* I hope gcc optimizes this to not use snprintf under the hood */
						SAFE_FAST_COND_APPEND_NOSPACE(headers, headpos, headlen, 1, "%s", linebuf);
						in_match = 1;
					} else {
						in_match = 0;
					}
				}
				fclose(fp);
				free(headerlist);
				bodylen = strlen(headers); /* Can't just subtract end of headers, we'd have to keep track of bytes added on each round (which we probably should anyways) */
				/* bodyargs ends in a ')', so don't tack an additional one on afterwards */
				SAFE_FAST_COND_APPEND(response, buf, len, 1, "BODY[HEADER.FIELDS (%s", bodyargs);
			} else if (!strcmp(bodyargs, "]") || !strcmp(bodyargs, "TEXT]")) { /* Empty (e.g. BODY.PEEK[] or BODY[], or TEXT */
				multiline = 1;
				sendbody = 1;
			} else {
				/* Since it contains a closing ], add a starting one for clarity or it'll look odd. */
				bbs_warning("Unsupported BODY[] argument: [%s\n", bodyargs);
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
				goto cleanup;
			}
			/* The RFC says no line should be more than 1,000 octets (bytes).
			 * Most clients will wrap at 72 characters, but we shouldn't rely on this. */
			while ((fgets(linebuf, sizeof(linebuf), fp))) {
				/* fgets does store the newline, so line should end in CR LF */
				if (!strcmp(linebuf, "\r\n")) {
					break; /* End of headers */
				}
				/* I hope gcc optimizes this to not use snprintf under the hood */
				SAFE_FAST_COND_APPEND_NOSPACE(headers, headpos, headlen, 1, "%s", linebuf);
			}
			fclose(fp);
			bodylen = headpos - headers; /* XXX cheaper than strlen, although if truncation happened, this may be wrong (too high). */
			if (!unoriginal) {
				SAFE_FAST_COND_APPEND(response, buf, len, 1, "RFC822.HEADER");
			}
		}

		if (fetchreq->body || fetchreq->bodystructure) {
			/* BODY is BODYSTRUCTURE without extensions (which we don't send anyways, in either case) */
			/* Excellent reference for BODYSTRUCTURE: http://sgerwk.altervista.org/imapbodystructure.html */
			/* But we just use the top of the line gmime library for this task (see https://stackoverflow.com/a/18813164) */
			dyn = mime_make_bodystructure(fetchreq->bodystructure ? "BODYSTRUCTURE" : "BODY", fullname);
		}

		/* Actual body, if being sent, should be last */
		if (fetchreq->rfc822 || fetchreq->rfc822text) {
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
					goto cleanup;
				}
				fseek(fp, 0L, SEEK_END); /* Go to EOF */
				size = ftell(fp);
				rewind(fp); /* Be kind, rewind */
				if (!size) {
					bbs_warning("File size of %s is %ld bytes?\n", fullname, size);
				}
				imap_send(imap, "%d FETCH (%s%s%s %s {%ld}", seqno, S_IF(dyn), dyn ? " " : "", response, fetchreq->rfc822 ? "RFC822" : "BODY[]", size + 2); /* No close paren here, last dprintf will do that */
				/* XXX Assumes not sending headers and bodylen at same time.
				 * In reality, I think that *might* be fine because the body contains everything,
				 * and you wouldn't request just the headers and then the whole body in the same FETCH.
				 * Now if there is a request for just the body text without the headers, we might be in trouble...
				 */
				if (bodylen) {
					bbs_warning("This is not handled!\n");
				}
				offset = 0;
				/* XXX Doesn't handle partial bodies */
				pthread_mutex_lock(&imap->lock);
				res = sendfile(imap->wfd, fileno(fp), &offset, size); /* We must manually tell it the offset or it will be at the EOF, even with rewind() */
				fclose(fp);
				if (res != size) {
					bbs_error("sendfile failed (%d != %ld): %s\n", res, size, strerror(errno));
				} else {
					imap_debug(5, "Sent %d-byte body for %s\n", res, fullname);
				}
				dprintf(imap->wfd, "\r\n)\r\n"); /* And the finale (don't use imap_send for this) */
				pthread_mutex_unlock(&imap->lock);
			} else {
				/* Need to add 2 for last CR LF we tack on before ) */
				imap_send(imap, "%d FETCH (%s%s%s {%d}\r\n%s\r\n)", seqno, S_IF(dyn), dyn ? " " : "", response, bodylen + 2, headers);
			}
		} else {
			/* Number after FETCH is always a message sequence number, not UID, even if usinguid */
			imap_send(imap, "%d FETCH (%s%s%s)", seqno, S_IF(dyn), dyn ? " " : "", response); /* Single line response */
		}

		if (dyn) {
			free(dyn);
		}

		if (markseen && IMAP_HAS_ACL(imap->acl, IMAP_ACL_SEEN)) {
			int newflags;
			/* I haven't actually encountered any clients that will actually hit this path... most clients peek everything and manually mark as seen,
			 * rather than using the BODY[] item which implicitly marks as seen during processing. */
			if (parse_flags_letters_from_filename(entry->d_name, &newflags, NULL)) { /* Don't care about custom keywords */
				bbs_error("File %s is noncompliant with maildir\n", entry->d_name);
				goto cleanup;
			}
			/* If not already seen, mark as unseen */
			if (!(newflags & FLAG_BIT_SEEN)) {
				char newflagletters[256];
				bbs_debug(6, "Implicitly marking message as seen\n");
				newflags |= FLAG_BIT_SEEN;
				/* Generate flag letters from flag bits */
				gen_flag_letters(newflags, newflagletters, sizeof(newflagletters));
				maildir_msg_setflags(fullname, newflagletters);
			}
		}

cleanup:
		free(entry);
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

	if (mailbox_has_activity(imap->mbox)) {
		/* There are new messages since we last checked. */
		/* Move any new messages from new to cur so we can find them. */
		imap_debug(4, "Doing traversal again since our view of %s is stale\n", imap->dir);
		IMAP_TRAVERSAL(imap, on_select);
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

/*! \brief Modify the flags for a message */
static int process_flags(struct imap_session *imap, char *s, int usinguid, const char *sequences, int flagop, int silent)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int seqno = 0;
	int opflags = 0;
	int oldflags, flagpermsdenied = 0;

	/* Convert something like (\Deleted) into the actual flags (parse once, use for all matches) */
	/* Remove parentheses */
	if (!strlen_zero(s) && *s == '(') {
		s++;
	}
	if (!strlen_zero(s)) {
		bbs_strterm(s, ')');
	}

	opflags = parse_flags_string(imap, s);
	/* Check if user is authorized to set these flags. */
	if (opflags & FLAG_BIT_SEEN && !IMAP_HAS_ACL(imap->acl, IMAP_ACL_SEEN)) {
		bbs_debug(3, "User denied access to modify \\Seen flag\n");
		opflags &= ~FLAG_BIT_SEEN;
		flagpermsdenied++;
	}
	if (opflags & FLAG_BIT_DELETED && !IMAP_HAS_ACL(imap->acl, IMAP_ACL_DELETE)) {
		bbs_debug(3, "User denied access to modify \\Deleted flag\n");
		opflags &= ~FLAG_BIT_DELETED;
		flagpermsdenied++;
	}
	if (!IMAP_HAS_ACL(imap->acl, IMAP_ACL_WRITE)) {
		/* Cannot set any other remaining flags */
		opflags &= (opflags & (FLAG_BIT_SEEN | FLAG_BIT_DELETED)); /* Restrict to these two flags, if they are set. */
		imap->numappendkeywords = 0;
		flagpermsdenied++;
	}

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		unsigned int msguid;
		char newflagletters[53];
		char oldkeywords[27] = "";
		char newkeywords[27] = "";
		const char *keywords = newkeywords;
		int i;
		int newflags;
		int changes = 0;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}
		msguid = msg_in_range(++seqno, entry->d_name, sequences, usinguid);
		if (!msguid) {
			goto cleanup;
		}
		/* Get the message's current flags. */
		if (parse_flags_letters_from_filename(entry->d_name, &oldflags, oldkeywords)) {
			bbs_error("File %s is noncompliant with maildir\n", entry->d_name);
			goto cleanup;
		}

		/* If we wanted to microptimize, we could set flags = current flag on a match, since these must appear in order (for maildir) */

		/* Build the new flags by iterating over opflags and comparing with oldflags */
		if (flagop == 1) { /* Append */
			newflags = oldflags; /* Start with existing. */
			for (i = 0; i < NUM_FLAG_BITS; i++) {
				if (opflags & (1 << i)) {
					newflags |= (1 << i);
					changes++;
				}
			}
		} else if (flagop == -1) { /* Remove */
			newflags = oldflags; /* Start with existing. */
			for (i = 0; i < NUM_FLAG_BITS; i++) {
				if (opflags & (1 << i)) {
					newflags &= ~(1 << i);
					changes++;
				}
			}
		} else {
			newflags = opflags; /* Just replace. That was easy. */
			changes++;
		}

		if (imap->numappendkeywords) {
			char *newbuf = newkeywords;
			size_t newlen = sizeof(newkeywords);
			/* These are the keywords provided as input.
			 * oldkeywords contains the existing keywords. */
			if (flagop == 1) { /* If they're equal, we don't need to do anything */
				if (strcmp(imap->appendkeywords, oldkeywords)) {
					bbs_debug(5, "Change made to keyword: %s -> %s\n", oldkeywords, imap->appendkeywords);
					strcpy(newkeywords, oldkeywords); /* Safe */
					strncat(newkeywords, imap->appendkeywords, sizeof(newkeywords) - 1);
					changes++;
				} else if (changes) {
					keywords = oldkeywords; /* If we're going to rename the file, make sure we preserve the flags it already had. If not, no point. */
				}
			} else if (flagop == -1) {
				/* If the old flags contain any of the new flags, remove them, otherwise just copy over */
				/* Note that imap->appendkeywords is not necessarily ordered since they are as the client sent them */
				const char *c = oldkeywords;
				while (*c) {
					/* Hopefully gcc will optimize a sprintf with just %c. */
					if (!strchr(imap->appendkeywords, *c)) {
						SAFE_FAST_COND_APPEND_NOSPACE(newkeywords, newbuf, newlen, 1, "%c", *c);
					} else {
						changes++;
					}
					c++;
				}
			} else {
				/* Just replace, easy */
				if (IMAP_HAS_ACL(imap->acl, IMAP_ACL_WRITE)) {
					keywords = imap->appendkeywords;
				}
			}
		} else {
			/* Preserve existing keywords, unless we're replacing */
			keywords = flagop ? oldkeywords : imap->appendkeywords;
		}

		if (changes) {
			char oldname[516];
			/* Generate flag letters from flag bits */
			gen_flag_letters(newflags, newflagletters, sizeof(newflagletters));
			strncat(newflagletters, keywords, sizeof(newflagletters) - 1);
			snprintf(oldname, sizeof(oldname), "%s/%s", imap->curdir, entry->d_name);
			if (maildir_msg_setflags(oldname, newflagletters)) {
				goto cleanup;
			}
		} else {
			imap_debug(5, "No changes in flags for message %s/%s\n", imap->curdir, entry->d_name);
			if (flagpermsdenied) {
				/* STORE "SHOULD NOT" fail if user has rights to modify at least one flag.
				 * If we got here, this means user didn't have permissions to set any flags.
				 * We can break out of the loop at this point, because if ACLs failed for one message,
				 * they will always fail (ACLs are per mailbox, not per message).
				 */
				imap_reply(imap, "NO Permission denieds");
				free(entry);
				free(entries);
				return 0;
			}
		}

		/* Send the response if not silent */
		if (changes && !silent) {
			char flagstr[256];
			int slen;
			gen_flag_names(newflagletters, flagstr, sizeof(flagstr));
			if (keywords[0]) { /* Current keywords */
				slen = strlen(flagstr);
				gen_keyword_names(imap, keywords, flagstr + slen, sizeof(flagstr) - slen); /* Append keywords (include space before) */
			}
			if (imap->createdkeyword) {
				/* Server SHOULD send untagged response when a new keyword is created */
				char allkeywords[256] = "";
				gen_keyword_names(imap, NULL, allkeywords, sizeof(allkeywords)); /* prepends a space before all of them, so this works out great */
				imap_send(imap, "FLAGS (%s%s)", IMAP_FLAGS, allkeywords);
			}
			/*! \todo Should really broadcast this, even if silent, for anyone else watching this folder (but may need to exclude self) */
			imap_send(imap, "%d FETCH (FLAGS (%s))", seqno, flagstr);
		}
cleanup:
		free(entry);
	}
	free(entries);
	imap_reply(imap, "OK %sSTORE Completed", usinguid ? "UID " : "");
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
	} else if (!strcasecmp(operation, "-FLAGS.SILENT")) {
		flagop = -1; /* Remove */
		silent = 1;
	} else {
		bbs_error("Invalid STORE operation: %s\n", operation);
		imap_reply(imap, "BAD Invalid arguments");
		return 0;
	}
	MAILBOX_TRYRDLOCK(imap);
	process_flags(imap, s, usinguid, sequences, flagop, silent);
	mailbox_unlock(imap->mbox);
	return 0;
}

static int handle_create(struct imap_session *imap, char *s)
{
	char path[256];
	int destacl;

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

	imap_translate_dir(imap, s, path, sizeof(path), &destacl); /* Don't care about return value, since it probably doesn't exist right now and that's fine. */
	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_MAILBOX_CREATE);
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
	mailbox_quota_adjust_usage(imap->mbox, 4096);
	imap_reply(imap, "OK CREATE completed");
	return 0;
}

static int handle_delete(struct imap_session *imap, char *s)
{
	char path[256];
	int destacl;

	REQUIRE_ARGS(s);
	STRIP_QUOTES(s);

	if (IS_SPECIAL_NAME(s)) {
		imap_reply(imap, "NO Can't delete special mailbox");
		return 0;
	}

	if (imap_translate_dir(imap, s, path, sizeof(path), &destacl)) {
		imap_reply(imap, "NO No such mailbox with that name");
		return 0;
	}

	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_MAILBOX_DELETE);

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
	mailbox_quota_adjust_usage(imap->mbox, -4096);
	imap_reply(imap, "OK DELETE completed");
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
			free(entry);
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
					free(entry);
					break;
				}
			}
		}
		free(entry);
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
	int res, srcacl, destacl;

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

	if (imap_translate_dir(imap, old, oldpath, sizeof(oldpath), &srcacl)) {
		imap_reply(imap, "NO No such mailbox with that name");
		return 0;
	}
	imap_translate_dir(imap, new, newpath, sizeof(newpath), &destacl); /* Don't care about return value since if it already exists, we'll abort. */
	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_MAILBOX_CREATE);
	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_MAILBOX_DELETE);
	if (!eaccess(newpath, R_OK)) {
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

enum imap_search_type {
	IMAP_SEARCH_ALL = 0,
	IMAP_SEARCH_ANSWERED,
	IMAP_SEARCH_BCC,
	IMAP_SEARCH_BEFORE,
	IMAP_SEARCH_BODY,
	IMAP_SEARCH_CC,
	IMAP_SEARCH_DELETED,
	IMAP_SEARCH_DRAFT,
	IMAP_SEARCH_FLAGGED,
	IMAP_SEARCH_FROM,
	IMAP_SEARCH_HEADER,
	IMAP_SEARCH_KEYWORD,
	IMAP_SEARCH_LARGER,
	IMAP_SEARCH_NEW,
	IMAP_SEARCH_NOT,
	IMAP_SEARCH_OLD,
	IMAP_SEARCH_ON,
	IMAP_SEARCH_OR,
	IMAP_SEARCH_AND,
	IMAP_SEARCH_RECENT,
	IMAP_SEARCH_SEEN,
	IMAP_SEARCH_SENTBEFORE,
	IMAP_SEARCH_SENTON,
	IMAP_SEARCH_SENTSINCE,
	IMAP_SEARCH_SINCE,
	IMAP_SEARCH_SMALLER,
	IMAP_SEARCH_SUBJECT,
	IMAP_SEARCH_TEXT,
	IMAP_SEARCH_TO,
	IMAP_SEARCH_UID,
	IMAP_SEARCH_UNANSWERED,
	IMAP_SEARCH_UNDELETED,
	IMAP_SEARCH_UNDRAFT,
	IMAP_SEARCH_UNFLAGGED,
	IMAP_SEARCH_UNKEYWORD,
	IMAP_SEARCH_UNSEEN,
	IMAP_SEARCH_SEQUENCE_NUMBER_SET,
};

#ifdef DEBUG_SEARCH
static const char *imap_search_key_name(enum imap_search_type type)
{
	switch (type) {
		case IMAP_SEARCH_ALL:
			return "ALL";
		case IMAP_SEARCH_ANSWERED:
			return "ANSWERED";
		case IMAP_SEARCH_BCC:
			return "BCC";
		case IMAP_SEARCH_BEFORE:
			return "BEFORE";
		case IMAP_SEARCH_BODY:
			return "BODY";
		case IMAP_SEARCH_CC:
			return "CC";
		case IMAP_SEARCH_DELETED:
			return "DELETED";
		case IMAP_SEARCH_DRAFT:
			return "DRAFT";
		case IMAP_SEARCH_FLAGGED:
			return "FLAGGED";
		case IMAP_SEARCH_FROM:
			return "FROM";
		case IMAP_SEARCH_HEADER:
			return "HEADER";
		case IMAP_SEARCH_KEYWORD:
			return "KEYWORD";
		case IMAP_SEARCH_LARGER:
			return "LARGER";
		case IMAP_SEARCH_NEW:
			return "NEW";
		case IMAP_SEARCH_NOT:
			return "NOT";
		case IMAP_SEARCH_OLD:
			return "OLD";
		case IMAP_SEARCH_ON:
			return "ON";
		case IMAP_SEARCH_OR:
			return "OR";
		case IMAP_SEARCH_AND:
			return "AND";
		case IMAP_SEARCH_RECENT:
			return "RECENT";
		case IMAP_SEARCH_SEEN:
			return "SEEN";
		case IMAP_SEARCH_SENTBEFORE:
			return "SENTBEFORE";
		case IMAP_SEARCH_SENTON:
			return "SENTON";
		case IMAP_SEARCH_SENTSINCE:
			return "SENTSINCE";
		case IMAP_SEARCH_SINCE:
			return "SINCE";
		case IMAP_SEARCH_SMALLER:
			return "SMALLER";
		case IMAP_SEARCH_SUBJECT:
			return "SUBJECT";
		case IMAP_SEARCH_TEXT:
			return "TEXT";
		case IMAP_SEARCH_TO:
			return "TO";
		case IMAP_SEARCH_UID:
			return "UID";
		case IMAP_SEARCH_UNANSWERED:
			return "UNANSWERED";
		case IMAP_SEARCH_UNDELETED:
			return "UNDELETED";
		case IMAP_SEARCH_UNDRAFT:
			return "UNDRAFT";
		case IMAP_SEARCH_UNFLAGGED:
			return "UNFLAGGED";
		case IMAP_SEARCH_UNKEYWORD:
			return "UNKEYWORD";
		case IMAP_SEARCH_UNSEEN:
			return "UNSEEN";
		case IMAP_SEARCH_SEQUENCE_NUMBER_SET:
			return "SEQNO_SET";
		default:
			bbs_error("Invalid search key type: %d\n", type);
			return NULL;
	}
}
#endif

struct imap_search_key;

struct imap_search_key {
	enum imap_search_type type;
	union arg {
		int number;
		const char *string;
		struct imap_search_keys *keys;			/* Child key (if any) */
	} child;
	RWLIST_ENTRY(imap_search_key) entry;	/* Next key at this level */
};

RWLIST_HEAD(imap_search_keys, imap_search_key);

static struct imap_search_key *imap_search_add(struct imap_search_keys *skeys, enum imap_search_type type)
{
	struct imap_search_key *nk;

	nk = calloc(1, sizeof(*nk));
	if (ALLOC_FAILURE(nk)) {
		return NULL;
	}
	nk->type = type;
	RWLIST_INSERT_TAIL(skeys, nk, entry);
	return nk;
}

static void imap_search_free(struct imap_search_keys *skeys)
{
	struct imap_search_key *skey;

	while ((skey = RWLIST_REMOVE_HEAD(skeys, entry))) {
		if (skey->type == IMAP_SEARCH_OR || skey->type == IMAP_SEARCH_NOT) {
			imap_search_free(skey->child.keys);
			free(skey->child.keys);
		}
		free(skey);
	}
}

/* #define DEBUG_SEARCH */

#ifdef DEBUG_SEARCH
/*! \brief Dump a parsed IMAP search query structure as a hierarchical tree for debugging */
static void dump_imap_search_keys(struct imap_search_keys *skeys, struct dyn_str *str, int depth)
{
	char buf[512];
	size_t bytes;
	struct imap_search_key *skey;

	RWLIST_TRAVERSE(skeys, skey, entry) {
		/* Indent according to the recursion depth */
		bytes = snprintf(buf, sizeof(buf), "=%%= %*.s %s -> ", 3 * depth, "", imap_search_key_name(skey->type));
		dyn_str_append(str, buf, bytes);
		switch (skey->type) {
			case IMAP_SEARCH_ANSWERED:
			case IMAP_SEARCH_DELETED:
			case IMAP_SEARCH_DRAFT:
			case IMAP_SEARCH_FLAGGED:
			case IMAP_SEARCH_NEW:
			case IMAP_SEARCH_OLD:
			case IMAP_SEARCH_RECENT:
			case IMAP_SEARCH_SEEN:
			case IMAP_SEARCH_UNANSWERED:
			case IMAP_SEARCH_UNDELETED:
			case IMAP_SEARCH_UNDRAFT:
			case IMAP_SEARCH_UNFLAGGED:
			case IMAP_SEARCH_UNKEYWORD:
			case IMAP_SEARCH_UNSEEN:
				bytes = snprintf(buf, sizeof(buf), "\n");
				dyn_str_append(str, buf, bytes);
				break;
			case IMAP_SEARCH_LARGER:
			case IMAP_SEARCH_SMALLER:
			case IMAP_SEARCH_UID:
				bytes = snprintf(buf, sizeof(buf), "%d\n", skey->child.number);
				dyn_str_append(str, buf, bytes);
				break;
			case IMAP_SEARCH_BCC:
			case IMAP_SEARCH_BEFORE:
			case IMAP_SEARCH_BODY:
			case IMAP_SEARCH_CC:
			case IMAP_SEARCH_FROM:
			case IMAP_SEARCH_HEADER:
			case IMAP_SEARCH_KEYWORD:
			case IMAP_SEARCH_ON:
			case IMAP_SEARCH_SENTBEFORE:
			case IMAP_SEARCH_SENTON:
			case IMAP_SEARCH_SENTSINCE:
			case IMAP_SEARCH_SINCE:
			case IMAP_SEARCH_SUBJECT:
			case IMAP_SEARCH_TEXT:
			case IMAP_SEARCH_TO:
			case IMAP_SEARCH_SEQUENCE_NUMBER_SET:
				bytes = snprintf(buf, sizeof(buf), "%s\n", S_IF(skey->child.string));
				dyn_str_append(str, buf, bytes);
				break;
			case IMAP_SEARCH_NOT:
			case IMAP_SEARCH_OR:
			case IMAP_SEARCH_AND:
				bytes = snprintf(buf, sizeof(buf), "\n");
				dyn_str_append(str, buf, bytes);
				dump_imap_search_keys(skey->child.keys, str, depth + 1);
				break;
			case IMAP_SEARCH_ALL:
			default:
				bbs_warning("Invalid key: %d\n", skey->type);
				dyn_str_append(str, "\n", 1);
				break;
		}
	}
}
#endif

#define SEARCH_PARSE_FLAG(name) \
	else if (!strcasecmp(next, #name)) { \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (unlikely(!nk)) { \
			return -1; \
		} \
		listsize++; \
	}

#define SEARCH_PARSE_INT(name) \
	else if (!strcasecmp(next, #name)) { \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (unlikely(!nk)) { \
			return -1; \
		} \
		next = strsep(s, " "); \
		if (!next) { \
			bbs_warning("Missing numeric argument\n"); \
			return -1; \
		} \
		nk->child.number = atoi(next); \
		listsize++; \
	}

/*! \brief Parse a string argument, optionally enclosed in quotes (mandatory if the argument contains multiple words) */
#define SEARCH_PARSE_STRING(name) \
	else if (!strcasecmp(next, #name)) { \
		quoted_arg = 0; \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (!nk) { \
			return -1; \
		} \
		/* Argument can be more than one word - it's the whole quoted argument. Find it, and strip the quotes in the process. */ \
		if (!*s) { \
			bbs_warning("Missing string argument\n"); \
			return -1; \
		} \
		if (**s == '"') { \
			begin = *s + 1; /* Skip opening " */ \
			quoted_arg = 1; \
		} else { \
			begin = *s; \
		} \
		if (!*begin) { \
			bbs_warning("Empty quoted argument\n"); \
			return -1; \
		} \
		if (quoted_arg) { \
			next = strchr(begin, '"'); \
			if (!next) { \
				bbs_warning("Unterminated quoted argument\n"); \
				return -1; \
			} \
		} else { \
			next = strchr(begin, ' '); \
		} \
		if (next) { \
			*next = '\0'; \
			*s = next + 1; \
		} else { \
			*s = '\0'; \
		} \
		nk->child.string = begin; /* This is not dynamically allocated, and does not need to be freed. */ \
		listsize++; \
	}

#define SEARCH_PARSE_RECURSE(name) \
		else if (!strcasecmp(next, #name)) { \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (!nk) { \
			return -1; \
		} \
		nk->child.keys = calloc(1, sizeof(*nk->child.keys)); \
		if (!nk->child.keys) { \
			return -1; \
		} \
		listsize++; \
		if (parse_search_query(nk->child.keys, IMAP_SEARCH_ ## name, s)) { \
			return -1; \
		} \
	}

static int parse_search_query(struct imap_search_keys *skeys, enum imap_search_type parent_type, char **s)
{
	char *begin, *next = NULL;
	struct imap_search_key *nk;
	int listsize = 0;
	int quoted_arg = 0;
	int paren_count = 0;

	for (;;) {
		if (*s && **s == '(') {
			next = *s; /* Don't strsep if we are at an opening parenthesis */
		} else {
			next = strsep(s, " ");
		}
		if (!next) {
			break;
		} else if (strlen_zero(next)) {
			continue;
		}

		/* If it starts with a (, treat everything until ) as one unit */
		if (*next == '(') {
			char *subnext, *p;
			/* Can't just use strchr to find the next ), since we could have nested parentheses. Find the real end. */
			/* Perhaps more optimal might be to recurse immediately as soon as we hit another open (, and return when we hit a ) */
			for (p = next; *p; p++) {
				if (*p == '(') {
					paren_count++;
				} else if (*p == ')') {
					if (!--paren_count) {
						break;
					}
				}
			}
			if (paren_count) {
				bbs_warning("Invalid SEARCH expression: unterminated parentheses: %s\n", next);
				return -1;
			}
			*p++ = '\0';
			*s = p;
			if (strlen_zero(*s)) {
				*s = NULL;
			}
			nk = imap_search_add(skeys, IMAP_SEARCH_AND);
			if (!nk) {
				return -1;
			}
			nk->child.keys = calloc(1, sizeof(*nk->child.keys));
			if (!nk->child.keys) {
				return -1;
			}
			listsize++;
			subnext = next + 1;
			/* Recurse to parse the contents of the expression between the ( and ) */
			if (parse_search_query(nk->child.keys, IMAP_SEARCH_AND, &subnext)) {
				return -1;
			}
			goto checklistsize;
		}

		/* Need to parse two strings from this, not just one */
		if (!strcasecmp(next, "HEADER")) {
			begin = *s + 1; /* Skip opening " */
			begin = strchr(begin, '"');
			if (!begin) {
				bbs_warning("Missing end quote for HEADER arg1\n");
				return -1;
			}
			*begin++ = ' '; /* Don't null terminate, we need to be able to continue through the string. */
			begin = strchr(begin, '"');
			/* There should be a "" for empty arg2, but the quotes should still be there */
			if (!begin) {
				bbs_warning("Missing opening quote for HEADER arg2\n");
				return -1;
			}
			*begin = ' ';
		}

		if (!strcasecmp(next, "ALL")) { /* This is only first so the macros can all use else if, not because it's particularly common. */
			/* Default */
		} /* else: */
		SEARCH_PARSE_FLAG(ANSWERED)
		SEARCH_PARSE_FLAG(DELETED)
		SEARCH_PARSE_FLAG(DRAFT)
		SEARCH_PARSE_FLAG(FLAGGED)
		SEARCH_PARSE_FLAG(NEW)
		SEARCH_PARSE_FLAG(OLD)
		SEARCH_PARSE_FLAG(RECENT)
		SEARCH_PARSE_FLAG(SEEN)
		SEARCH_PARSE_FLAG(UNANSWERED)
		SEARCH_PARSE_FLAG(UNDELETED)
		SEARCH_PARSE_FLAG(UNDRAFT)
		SEARCH_PARSE_FLAG(UNFLAGGED)
		SEARCH_PARSE_FLAG(UNKEYWORD)
		SEARCH_PARSE_FLAG(UNSEEN)
		SEARCH_PARSE_INT(LARGER)
		SEARCH_PARSE_INT(SMALLER)
		SEARCH_PARSE_INT(UID)
		SEARCH_PARSE_STRING(BCC)
		SEARCH_PARSE_STRING(BEFORE)
		SEARCH_PARSE_STRING(BODY)
		SEARCH_PARSE_STRING(CC)
		SEARCH_PARSE_STRING(FROM)
		SEARCH_PARSE_STRING(HEADER)
		SEARCH_PARSE_STRING(KEYWORD)
		SEARCH_PARSE_STRING(ON)
		SEARCH_PARSE_STRING(SENTBEFORE)
		SEARCH_PARSE_STRING(SENTON)
		SEARCH_PARSE_STRING(SENTSINCE)
		SEARCH_PARSE_STRING(SINCE)
		SEARCH_PARSE_STRING(SUBJECT)
		SEARCH_PARSE_STRING(TEXT)
		SEARCH_PARSE_RECURSE(OR)
		SEARCH_PARSE_RECURSE(NOT)
		else if (isdigit(*next)) {
			/* sequence set */
			/* Not quoted, so thankfully this doesn't duplicate much code */
			nk = imap_search_add(skeys, IMAP_SEARCH_SEQUENCE_NUMBER_SET);
			if (!nk) {
				return -1;
			}
			nk->child.string = next;
			listsize++;
		} else {
			bbs_warning("Foreign IMAP search key: %s\n", next);
		}
checklistsize:
		switch (parent_type) {
			case IMAP_SEARCH_NOT:
				if (listsize == 1) {
					goto ret;
				}
				break;
			case IMAP_SEARCH_OR:
				if (listsize == 2) {
					goto ret;
				}
				break;
			default:
				break;
		}
	}

ret:
	switch (parent_type) {
		case IMAP_SEARCH_NOT:
			if (listsize != 1) {
				bbs_warning("NOT has %d children?\n", listsize);
				return -1;
			}
			break;
		case IMAP_SEARCH_OR:
			if (listsize != 2) {
				bbs_warning("OR has %d children?\n", listsize);
				return -1;
			}
			break;
		default:
			break;
	}

	return 0;
}

struct imap_search {
	const char *directory;
	const char *filename;
	const char *keywords;
	struct stat st;
	FILE *fp;
	int flags;
	int seqno;
	struct imap_session *imap;
	unsigned int new:1;
	unsigned int didstat:1;
};

static int search_message(struct imap_search *search, const char *s, int headers, int body)
{
	char linebuf[1001];
	int in_headers = 1;

	if (!search->fp) {
		char buf[512];
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename);
		search->fp = fopen(buf, "r"); /* Only open the file if needed */
		if (!search->fp) {
			bbs_error("Failed to open %s: %s\n", buf, strerror(errno));
			return -1;
		}
	} else {
		rewind(search->fp);
	}

	while ((fgets(linebuf, sizeof(linebuf), search->fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			in_headers = 0;
			if (!body) {
				break; /* End of headers */
			}
		} else if (in_headers && !headers) {
			continue;
		} else if (strcasestr(linebuf, s)) {
			return 1;
		}
	}
	return 0;
}

static int search_header(struct imap_search *search, const char *header, size_t headerlen, const char *value)
{
	char linebuf[1001];
	char *pos;

	if (!search->fp) {
		char buf[512];
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename);
		search->fp = fopen(buf, "r"); /* Only open the file if needed */
		if (!search->fp) {
			bbs_error("Failed to open %s: %s\n", buf, strerror(errno));
			return -1;
		}
	} else {
		rewind(search->fp);
	}

#ifdef DEBUG_SEARCH
	bbs_debug(8, "Searching %s header %.*s for %s\n", search->filename, (int) headerlen, header, S_IF(value));
#endif

	while ((fgets(linebuf, sizeof(linebuf), search->fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
		if (strncasecmp(linebuf, header, headerlen)) {
			continue; /* Not the right header */
		}
		pos = linebuf + headerlen;
		if (strlen_zero(value)) {
			return 1; /* Header exists (no value to search for), and that's all we care about */
		}
		if (strcasestr(pos, value)) {
			return 1;
		}
	}
	return 0;
}

static int get_header(FILE *fp, const char *header, size_t headerlen, char *buf, size_t len)
{
	char linebuf[1001];
	char *pos;

	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
		if (strncasecmp(linebuf, header, headerlen)) {
			continue; /* Not the right header */
		}
		pos = linebuf + headerlen;
		if (*pos == ':') {
			pos++;
		}
		if (*pos == ' ') {
			pos++;
		}
		safe_strncpy(buf, pos, len);
		return 0;
	}
	return -1;
}

static int parse_sent_date(const char *s, struct tm *tm)
{
	/* Multiple possible date formats:
	 * 15 Oct 2002 23:57:35 +0300
	 * Tues, 15 Oct 2002 23:57:35 +0300
	 */
	if (!strptime(s, "%a, %d %b %Y %H:%M:%S %z", tm) && !strptime(s, "%d %b %Y %H:%M:%S %z", tm)) {
		bbs_warning("Failed to parse as date: %s\n", s);
		return -1;
	}
	return 0;
}

static int search_sent_date(struct imap_search *search, struct tm *tm)
{
	char linebuf[1001];
	char *pos;

	if (!search->fp) {
		char buf[512];
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename);
		search->fp = fopen(buf, "r"); /* Only open the file if needed */
		if (!search->fp) {
			bbs_error("Failed to open %s: %s\n", buf, strerror(errno));
			return -1;
		}
	} else {
		rewind(search->fp);
	}

	while ((fgets(linebuf, sizeof(linebuf), search->fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
		if (strncasecmp(linebuf, "Date:", STRLEN("Date:"))) {
			continue; /* Not the right header */
		}
		pos = linebuf + STRLEN("Date:");
		ltrim(pos);
		bbs_strterm(pos, '\r');
		return parse_sent_date(pos, tm);
	}
	bbs_warning("Didn't find a date in message\n");
	return -1;
}

#define SEARCH_HEADER_MATCH(hdrname) \
	retval = search_header(search, hdrname ":", STRLEN(hdrname ":"), skey->child.string); \
	break;

#define SEARCH_FLAG_MATCH(flag) \
	retval = search->flags & flag ? 1 : 0; \
	break;

#define SEARCH_FLAG_NOT_MATCH(flag) \
	retval = search->flags & flag ? 0 : 1; \
	break;

#define SEARCH_STAT() \
	memset(&tm1, 0, sizeof(tm1)); \
	memset(&tm2, 0, sizeof(tm2)); \
	if (!search->didstat) { \
		char buf[512]; \
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename); \
		if (stat(buf, &search->st)) { \
			bbs_error("stat(%s) failed: %s\n", buf, strerror(errno)); \
		} else { \
			search->didstat = 1; \
		} \
	}

/* XXX For some reason, if we don't initialize both tm1 and tm2 to zero, the first search date can occasionally be wrong.
 * Not sure how it could be used uninitialized, but apparently it can be... (ditto for SEARCH_STAT above) */
#define SEARCH_DATE() \
	memset(&tm1, 0, sizeof(tm1)); \
	memset(&tm2, 0, sizeof(tm2)); \
	if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */ \
		bbs_warning("Failed to parse as date: %s\n", skey->child.string); \
		break; \
	} \
	if (search_sent_date(search, &tm1)) { /* Get from Date header */ \
		break; \
	}

#define TM_DATE_EQUAL(tm1, tm2) (tm1.tm_year == tm1.tm_year && tm1.tm_mon == tm2.tm_mon && tm1.tm_mday == tm2.tm_mday)

/*! \brief Recursively evaluate if a message matches a tree of search expressions */
static int search_keys_eval(struct imap_search_keys *skeys, enum imap_search_type type, struct imap_search *search)
{
	int retval = 1; /* True by default. */
	struct imap_search_key *skey;
	unsigned int uid;
	unsigned long size;
	const char *hdrval;
	size_t len;
	struct tm tm1, tm2;
	time_t t1, t2;

	/* Evaluate all expressions (they are all AND'ed together), stopping if we find one that's false. */
	RWLIST_TRAVERSE(skeys, skey, entry) {
		switch (skey->type) {
			case IMAP_SEARCH_ANSWERED:
				SEARCH_FLAG_MATCH(FLAG_BIT_ANSWERED);
			case IMAP_SEARCH_DELETED:
				SEARCH_FLAG_MATCH(FLAG_BIT_DELETED);
			case IMAP_SEARCH_DRAFT:
				SEARCH_FLAG_MATCH(FLAG_BIT_DRAFT);
			case IMAP_SEARCH_FLAGGED:
				SEARCH_FLAG_MATCH(FLAG_BIT_FLAGGED);
			case IMAP_SEARCH_NEW: /* Same as RECENT && UNSEEN */
				retval = search->new && !(search->flags & FLAG_BIT_SEEN);
				break;
			case IMAP_SEARCH_OLD:
				retval = !search->new;
				break;
			case IMAP_SEARCH_RECENT:
				retval = search->new;
				break;
			case IMAP_SEARCH_SEEN:
				SEARCH_FLAG_MATCH(FLAG_BIT_SEEN);
			case IMAP_SEARCH_UNANSWERED:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_ANSWERED);
			case IMAP_SEARCH_UNDELETED:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_DELETED);
			case IMAP_SEARCH_UNDRAFT:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_DELETED);
			case IMAP_SEARCH_UNFLAGGED:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_FLAGGED);
			case IMAP_SEARCH_UNKEYWORD:
				bbs_warning("UNKEYWORD is not currently supported\n");
				break;
			case IMAP_SEARCH_UNSEEN:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_SEEN);
			case IMAP_SEARCH_LARGER:
				if (!search->new) {
					/* only works for messages in cur, not new, same with subsequent parse_ function calls that use the filename */
					parse_size_from_filename(search->filename, &size);
				} else {
					SEARCH_STAT()
					size = search->st.st_size;
				}
				retval = (int) size > skey->child.number;
				break;
			case IMAP_SEARCH_SMALLER:
				if (!search->new) {
					parse_size_from_filename(search->filename, &size);
				} else {
					SEARCH_STAT()
					size = search->st.st_size;
				}
				retval = (int) size < skey->child.number;
				break;
			case IMAP_SEARCH_UID:
				if (!search->new) {
					parse_uid_from_filename(search->filename, &uid);
					retval = (int) uid == skey->child.number;
				} else {
					/* XXX messages in new don't have a UID, so by definition it can't match */
					retval = 0;
				}
				break;
			case IMAP_SEARCH_SEQUENCE_NUMBER_SET:
				retval = in_range(skey->child.string, search->seqno);
				break;
			case IMAP_SEARCH_BCC:
				SEARCH_HEADER_MATCH("Bcc");
			case IMAP_SEARCH_BODY:
				retval = search_message(search, skey->child.string, 0, 1) == 1;
				break;
			case IMAP_SEARCH_CC:
				SEARCH_HEADER_MATCH("Cc");
			case IMAP_SEARCH_FROM:
				SEARCH_HEADER_MATCH("From");
			case IMAP_SEARCH_HEADER:
				hdrval = strchr(skey->child.string, ' ');
				len = hdrval - skey->child.string;
				ltrim(hdrval);
				retval = search_header(search, skey->child.string, len, hdrval);
				break;
			case IMAP_SEARCH_KEYWORD:
				/* This is not very efficient, since we reparse the keywords for every message, but the keyword mapping is the same for everything in this mailbox. */
				parse_keyword(search->imap, skey->child.string, 0);
				/* imap->appendkeywords is now set. */
				if (search->imap->numappendkeywords != 1) {
					bbs_warning("Expected %d keyword, got %d?\n", 1, search->imap->numappendkeywords);
					break;
				}
				retval = strchr(search->keywords, search->imap->appendkeywords[0]) ? 1 : 0;
				break;
			case IMAP_SEARCH_ON: /* INTERNALDATE == match */
				SEARCH_STAT()
				if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */
					bbs_warning("Failed to parse as date: %s\n", skey->child.string);
					break;
				}
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				retval = TM_DATE_EQUAL(tm1, tm2);
				break;
			case IMAP_SEARCH_SENTBEFORE:
				SEARCH_DATE()
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				/* t1 = INTERNALDATE, t2 = threshold for search before */
				retval = difftime(t1, t2) < 0; /* If difftime is positive, tm1 > tm2 */
				break;
			case IMAP_SEARCH_SENTON:
				SEARCH_DATE()
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				retval = TM_DATE_EQUAL(tm1, tm2);
				break;
			case IMAP_SEARCH_SENTSINCE:
				SEARCH_DATE()
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				/* t1 = INTERNALDATE, t2 = threshold for search before */
				retval = difftime(t1, t2) > 0 && !TM_DATE_EQUAL(tm1, tm2); /* If difftime is positive, tm1 > tm2 */
				break;
			case IMAP_SEARCH_BEFORE: /* INTERNALDATE < */
				SEARCH_STAT()
				if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */
					bbs_warning("Failed to parse as date: %s\n", skey->child.string);
					break;
				}
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				retval = difftime(t1, t2) < 0 || TM_DATE_EQUAL(tm1, tm2);
				break;
			case IMAP_SEARCH_SINCE: /* INTERNALDATE >=, e.g. 08-Mar-2011 */
				SEARCH_STAT()
				if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */
					bbs_warning("Failed to parse as date: %s\n", skey->child.string);
					break;
				}
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				retval = difftime(t1, t2) > 0;
				break;
			case IMAP_SEARCH_SUBJECT:
				SEARCH_HEADER_MATCH("Subject");
			case IMAP_SEARCH_TEXT: /* In header or body */
				retval = search_message(search, skey->child.string, 1, 1);
				break;
			case IMAP_SEARCH_TO:
				SEARCH_HEADER_MATCH("To");
			case IMAP_SEARCH_NOT: /* 1 child, negate the result. */
				retval = !search_keys_eval(skey->child.keys, IMAP_SEARCH_NOT, search);
				break;
			case IMAP_SEARCH_OR: /* 2 children, only one of which must be true */
				retval = search_keys_eval(skey->child.keys, IMAP_SEARCH_OR, search);
				break;
			case IMAP_SEARCH_AND: /* An arbitrary number of children, all of which must be true */
				retval = search_keys_eval(skey->child.keys, IMAP_SEARCH_AND, search);
				break;
			case IMAP_SEARCH_ALL: /* Implicitly always true */
				break;
			default:
				bbs_warning("Invalid key: %d\n", skey->type);
				break;
		}
		/* Short circuit by stopping if any of the expressions turns out to be false... unless we're ORing (where we stop on the first one that's true). */
		if (type == IMAP_SEARCH_OR && retval) {
#ifdef DEBUG_SEARCH
			bbs_debug(5, "Short-circuiting since OR contains at least one true expression (%s)\n", imap_search_key_name(skey->type));
#endif
			break;
		} else if (type != IMAP_SEARCH_OR && !retval) {
#ifdef DEBUG_SEARCH
			bbs_debug(5, "Failed to match condition %s\n", imap_search_key_name(skey->type));
#endif
			break;
		}
	}
	return retval;
}

/*! \note For some reason, looping twice or using goto results in valgrind reporting a memory leak, but calling this function twice does not */
static int search_dir(struct imap_session *imap, const char *dirname, int newdir, int usinguid, struct imap_search_keys *skeys, unsigned int **a, int *lengths, int *allocsizes)
{
	int res = 0;
	int files, fno = 0;
	struct dirent *entry, **entries = NULL;
	struct imap_search search;
	unsigned int uid;
	unsigned int seqno = 0;
	char keywords[27] = "";

	files = scandir(dirname, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", dirname, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto next;
		} else if (entry->d_type != DT_REG) { /* We only care about directories, not files. */
			goto next;
		}
		seqno++;
#ifdef DEBUG_SEARCH
		bbs_debug(10, "Checking message %u: %s\n", seqno, entry->d_name);
#endif
		memset(&search, 0, sizeof(search));
		search.imap = imap;
		search.directory = dirname;
		search.filename = entry->d_name;
		search.new = newdir;
		search.seqno = seqno;
		search.keywords = keywords;
		/* Parse the flags just once in advance, since doing bit field comparisons is faster than strchr */
		if (parse_flags_letters_from_filename(search.filename, &search.flags, keywords)) {
			goto next;
		}
		if (search_keys_eval(skeys, IMAP_SEARCH_ALL, &search)) {
			/* Include in search response */
			if (usinguid) {
				parse_uid_from_filename(search.filename, &uid);
				res = uintlist_append(a, lengths, allocsizes, uid);
			} else {
				res = uintlist_append(a, lengths, allocsizes, seqno);
			}
			/* We really only need uintlist_append1, but just reuse the API used for COPY */
#ifdef DEBUG_SEARCH
			bbs_debug(5, "Including message %u (%s) in response\n", seqno, entry->d_name);
#endif
		}
		/* If we opened any resources, close them */
		if (search.fp) {
			fclose(search.fp);
		}
next:
		free(entry);
		if (unlikely(res)) {
			bbs_error("Search failed at seqno %d\n", seqno);
			break;
		}
	}
	free(entries);
	if (res < 0) {
		bbs_error("Error while reading directories (%d) - %s: %s\n", res, dirname, strerror(errno));
		res = -1;
	}
	return res;
}

/*! \retval -1 on failure, number of search results on success */
static int do_search(struct imap_session *imap, char *s, unsigned int **a, int usinguid)
{
	int lengths = 0, allocsizes = 0;
	struct imap_search_keys skeys; /* At the least the top level list itself will be stack allocated. */

	/* IMAP uses polish notation, which makes for somewhat easier parsing (can do one pass left to right) */
	/* Because of search keys like NOT, as well as being able to have multiple search keys of the same type,
	 * we can't just trivially "compile" the SEARCH query into a struct and use that for fast matching.
	 * We do in fact compile once here, but it requires a more involved parser since it can have multilevel depth.
	 * For now, we just evaluate the query left to right on every message in a mailbox folder.
	 * Note that IMAP SEARCH results should not be assumed by the client to be in any particular order.
	 * However, conventionally they are in ascending order, even though the RFC does not specify any order.
	 */

	/* Parsing example:
	 * NOT FLAGGED OR FROM 'John' FROM 'Paul'
	 * !flagged && (FROM 'John' || FROM 'Paul')
	 *
	 * Essentially, we end up at the top level with a linked list of imap_search_key structures.
	 * Each of these is ANDed together, i.e. all the keys at the top level list must be satisfied for a message to match.
	 * Within each imap_search_key in this list, we could have further keys that are themselves lists.
	 */

	memset(&skeys, 0, sizeof(skeys));
	/* If we didn't consume the entire search expression before returning, then this is invalid */
	if (parse_search_query(&skeys, IMAP_SEARCH_ALL, &s) || !strlen_zero(s)) {
		imap_search_free(&skeys);
		imap_reply(imap, "BAD Invalid search query");
		bbs_warning("Failed to parse search query\n"); /* Consumed the query in the process, but should be visible in a previous debug message */
		return -1;
	}

#ifdef DEBUG_SEARCH
	{
		memset(&dynstr, 0, sizeof(dynstr));
		dump_imap_search_keys(&skeys, &dynstr, 0);
		bbs_debug(3, "IMAP search tree:\n%s", dynstr.buf);
		free(dynstr.buf);
	}
#endif

	search_dir(imap, imap->curdir, 0, usinguid, &skeys, a, &lengths, &allocsizes);
	search_dir(imap, imap->newdir, 1, usinguid, &skeys, a, &lengths, &allocsizes);
	imap_search_free(&skeys);
	return lengths;
}

static char *uintlist_to_str(unsigned int *a, int length)
{
	int i;
	struct dyn_str dynstr;

	memset(&dynstr, 0, sizeof(dynstr));
	for (i = 0; i < length; i++) {
		char buf[15];
		int len = snprintf(buf, sizeof(buf), "%s%u", i ? " " : "", a[i]);
		dyn_str_append(&dynstr, buf, len);
	}
	return dynstr.buf;
}

static int handle_search(struct imap_session *imap, char *s, int usinguid)
{
	unsigned int *a = NULL;
	int results;

	results = do_search(imap, s, &a, usinguid);
	if (results < 0) {
		return 0;
	}

	if (results) {
		char *list = uintlist_to_str(a, results);
		imap_send(imap, "SEARCH %s", S_IF(list));
		free_if(list);
	} else {
		imap_send(imap, "SEARCH"); /* No results, but still need to send an empty untagged response */
	}

	free_if(a);
	imap_reply(imap, "OK %sSEARCH completed", usinguid ? "UID " : "");
	return 0;
}

struct imap_sort {
	struct imap_session *imap;
	struct dirent **entries;
	const char *sortexpr;
	int numfiles;
	unsigned int usinguid:1;
};

static void free_scandir_entries(struct dirent **entries, int numfiles)
{
	int fno = 0;
	struct dirent *entry;

	while (fno < numfiles && (entry = entries[fno++])) {
		free(entry);
	}
}

static int msg_to_filename(struct imap_sort *sort, unsigned int number, int usinguid, char *buf, size_t len)
{
	struct dirent *entry, **entries = sort->entries;
	int fno = 0;
	unsigned int seqno = 0;

	while (fno < sort->numfiles && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		seqno++;
		if (usinguid) {
			unsigned int uid;
			parse_uid_from_filename(entry->d_name, &uid);
			if (uid == number) {
				snprintf(buf, len, "%s/%s", sort->imap->curdir, entry->d_name);
				return 0;
			}
		} else {
			if (seqno == number) {
				snprintf(buf, len, "%s/%s", sort->imap->curdir, entry->d_name);
				return 0;
			}
		}
	}
	bbs_warning("Couldn't find match for %s %d?\n", usinguid ? "UID" : "seqno", number);
	return -1;
}

#define SKIP_STR(var, str) \
	if (STARTS_WITH(var, str)) { \
		var += STRLEN(str); \
	}

/*! \brief Skip prefixes according to RFC 5256 */
#define SKIP_PREFIXES(var) \
	for (skips = 1; !skips ;) { \
		skips = 0; \
		ltrim(a); \
		SKIP_STR(a, "Re:"); \
		SKIP_STR(a, "Fwd:"); \
	}

static int subjectcmp(const char *a, const char *b)
{
	int skips;

	SKIP_PREFIXES(a);
	SKIP_PREFIXES(b);
	return strcasecmp(a, b);
}

/*! \retval -1 if a comes before b, 1 if b comes before a, and 0 if they are equal (according to sort criteria) */
static int sort_compare(const void *aptr, const void *bptr, void *varg)
{
	const unsigned int *ap = aptr;
	const unsigned int *bp = bptr;
	const unsigned int a = *ap;
	const unsigned int b = *bp;
	struct imap_sort *sort = varg;

	char filename_a[256];
	char filename_b[256];
	char buf1[128], buf2[128];
	const char *criterion;
	int reverse = 0;
	int res;
	int hdra, hdrb;
	FILE *fpa = NULL, *fpb = NULL;
	struct tm tm1, tm2;
	time_t t1, t2;
	int diff;

	/* If sort->usinguid, then we are comparing UIDs.
	 * Otherwise, we're comparing sequence numbers. */

	/* This is a case where it would be really nice to have some kind of index
	 * of all the messages in the mailbox.
	 * Without that, we have no alternative but to open all the messages if needed.
	 * This is particularly yucky since just looking for the file involves a linear scan of the directory.
	 * Even just having an index mapping seqno/UIDs -> filenames (like dovecot has) would be useful.
	 * For now, we optimize by only calling scandir() once for the sort, and just iterating over the list
	 * each time. This is actually necessary for correctness as well, since the list of files
	 * MUST NOT CHANGE in the middle of a sort.
	 */

	if (msg_to_filename(sort, a, sort->usinguid, filename_a, sizeof(filename_a))) {
		return 0;
	} else if (msg_to_filename(sort, b, sort->usinguid, filename_b, sizeof(filename_b))) {
		return 0;
	}

	res = 0;
	memset(&tm1, 0, sizeof(tm1));
	memset(&tm2, 0, sizeof(tm2));

#define OPEN_FILE_IF_NEEDED(fp, fname) \
	if (fp) { \
		rewind(fp); \
	} else { \
		fp = fopen(fname, "r"); \
		if (!fp) { \
			bbs_error("Failed to open %s: %s\n", fname, strerror(errno)); \
			break; \
		} \
	}

#define GET_HEADERS(header) \
	OPEN_FILE_IF_NEEDED(fpa, filename_a); \
	OPEN_FILE_IF_NEEDED(fpb, filename_b); \
	hdra = get_header(fpa, header, STRLEN(header), buf1, sizeof(buf1)); \
	hdrb = get_header(fpb, header, STRLEN(header), buf2, sizeof(buf2)); \
	if (hdra && hdrb) { \
		reverse = 0; \
		continue; \
	} else if (hdra) { \
		res = 1; \
		break; \
	} else if (hdrb) { \
		res = -1; \
		break; \
	}

	/* To avoid having to duplicate the string for every single comparison,
	 * parse the string in place. */
	for (criterion = sort->sortexpr; !res && !strlen_zero(criterion); criterion = strchr(criterion, ' ')) {
		char *space;
		int len;
		if (*criterion == ' ') { /* All but first one */
			criterion++;
			if (strlen_zero(criterion)) {
				break;
			}
		}
		/* Must use STARTS_WITH (strncasecmp) since the criterion is NOT null terminated. */
		/* Break as soon as we have an unambiguous winner. */
		space = strchr(criterion, ' ');
		len = space ? (space - criterion) : (int) strlen(criterion);

#ifdef DEBUG_SORT
		bbs_debug(10, "Processing next SORT token: %.*s\n", len, criterion);
#endif

		if (STARTS_WITH(criterion, "ARRIVAL")) {
			/* INTERNALDATE *AND* time! */
			struct stat stata, statb;
			hdra = stat(filename_a, &stata);
			hdrb = stat(filename_b, &statb);
			if (hdra || hdrb) {
				res = hdra ? hdrb ? 0 : -1 : 1; /* If a date is invalid, it sorts first */
			} else {
				diff = difftime(stata.st_mtime, statb.st_mtime); /* If difftime is positive, tm1 > tm2 */
				res = diff < 0 ? 1 : diff > 0 ? -1 : 0;
			}
		} else if (STARTS_WITH(criterion, "CC")) {
			GET_HEADERS("Cc");
			res = strcasecmp(buf1, buf2);
		} else if (STARTS_WITH(criterion, "DATE")) {
			GET_HEADERS("Date");
			bbs_strterm(buf1, '\r');
			bbs_strterm(buf2, '\r');
			hdra = parse_sent_date(buf1, &tm1);
			hdrb = parse_sent_date(buf2, &tm2);
			if (hdra || hdrb) {
				res = hdra ? hdrb ? 0 : -1 : 1; /* If a date is invalid, it sorts first */
			} else {
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				diff = difftime(t1, t2); /* If difftime is positive, tm1 > tm2 */
				res = diff < 0 ? 1 : diff > 0 ? -1 : 0;
			}
		} else if (STARTS_WITH(criterion, "FROM")) {
			GET_HEADERS("From");
			res = strcasecmp(buf1, buf2);
		} else if (STARTS_WITH(criterion, "REVERSE")) {
			reverse = 1;
			continue;
		} else if (STARTS_WITH(criterion, "SIZE")) {
			long unsigned int sizea, sizeb;
			/* This is the easiest one. Everything we need is in the filename already. */
			parse_size_from_filename(filename_a, &sizea);
			parse_size_from_filename(filename_b, &sizeb);
			res = sizea < sizeb ? -1 : sizea > sizeb ? 1 : 0;
		} else if (STARTS_WITH(criterion, "SUBJECT")) {
			GET_HEADERS("Subject");
			res = subjectcmp(buf1, buf2);
		} else if (STARTS_WITH(criterion, "TO")) {
			GET_HEADERS("To");
			res = strcasecmp(buf1, buf2);
		} else {
			bbs_warning("Invalid SORT criterion: %.*s\n", len, criterion);
		}
		if (reverse && res) {
			res = -res; /* Invert if needed */
		}
		reverse = 0;
	}

	if (fpa) {
		fclose(fpa);
	}
	if (fpb) {
		fclose(fpb);
	}

	/* Final tie breaker. Pick the message with the smaller sequence number. */
	if (!res) {
		res = a < b ? -1 : a > b ? 1 : 0;
	}

#ifdef DEBUG_SORT
	bbs_debug(7, "Sort compare = %d: %s <=> %s: %s\n", res, filename_a, filename_b, sort->sortexpr);
#endif

	return res;
}

static int handle_sort(struct imap_session *imap, char *s, int usinguid)
{
	int results;
	char *sortexpr, *charset, *search;
	unsigned int *a = NULL;

	/* e.g. A283 SORT (SUBJECT REVERSE DATE) UTF-8 ALL (RFC 5256) */
	if (*s == '(') {
		sortexpr = s + 1;
		s = strchr(sortexpr, ')');
		REQUIRE_ARGS(s);
		*s = '\0';
		s++;
		REQUIRE_ARGS(s);
		s++;
		REQUIRE_ARGS(s);
	} else {
		sortexpr = strsep(&s, " ");
	}
	charset = strsep(&s, " ");
	search = s;

	REQUIRE_ARGS(charset); /* This is mandatory in the RFC, though we ignore this, apart from checking it. */
	REQUIRE_ARGS(search);

	if (strcasecmp(charset, "UTF-8") && strcasecmp(charset, "US-ASCII")) {
		imap_reply(imap, "BAD Charset not supported");
		return 0;
	}

	/* This is probably something that could be made a lot more efficient.
	 * Initially here, our concern is with simplicity and correctness,
	 * but sorting and searching could probably use lots of optimizations. */

	/* First, search for any matching messages. */
	results = do_search(imap, search, &a, usinguid);
	if (results < 0) {
		return 0;
	}

	/* Now, look at the messages matching the sort and sort only those.
	 * Consider that searching is a linear operation while sorting is logarthmic.
	 * In the ideal case, searching eliminated most messages and sorting
	 * on this filtered set will thus be much more efficient than sorting quickly, or in conjunction with searching.
	 * However, if we have something like SEARCH ALL, we are going to sort everything anyways,
	 * in which case this second pass essentially duplicates all the work done by the search, and then some.
	 */

	if (results) {
		struct imap_sort sort;
		char *list;
		memset(&sort, 0, sizeof(sort));
		sort.imap = imap;
		sort.sortexpr = sortexpr;
		sort.usinguid = usinguid;
		sort.numfiles = scandir(imap->curdir, &sort.entries, NULL, alphasort); /* cur dir only */
		if (sort.numfiles >= 0) {
			qsort_r(a, results, sizeof(unsigned int), sort_compare, &sort); /* Actually sort the results, conveniently already in an array. */
			free_scandir_entries(sort.entries, sort.numfiles);
			free(sort.entries);
		}
		list = uintlist_to_str(a, results);
		imap_send(imap, "SORT %s", S_IF(list));
		free_if(list);
	} else {
		imap_send(imap, "SORT"); /* No matches */
	}

	free_if(a);
	imap_reply(imap, "OK %sSORT completed", usinguid ? "UID " : "");
	return 0;
}

static int handle_getquota(struct imap_session *imap)
{
	unsigned int quotatotal, quotaleft, quotaused;

	quotatotal = mailbox_quota(imap->mbox);
	quotaleft = mailbox_quota_remaining(imap->mbox);
	quotaused = quotatotal - quotaleft;

	/* The RFC doesn't say this explicitly, but quota values are in KB, not bytes. */
	imap_send(imap, "QUOTA \"\" (STORAGE %u %u)", quotaused / 1024, quotatotal / 1024);
	return 0;
}

static int finish_auth(struct imap_session *imap, int auth)
{
	imap->mymbox = mailbox_get(imap->node->user->id, NULL); /* Retrieve the mailbox for this user */
	if (!imap->mymbox) {
		bbs_error("Successful authentication, but unable to retrieve mailbox for user %d\n", imap->node->user->id);
		imap_reply(imap, "BYE System error");
		return -1; /* Just disconnect, we probably won't be able to proceed anyways. */
	}
	if (auth) {
		_imap_reply(imap, "%s OK Success\r\n", imap->savedtag); /* Use tag from AUTHENTICATE request */
		free_if(imap->savedtag);
	} else {
		imap_reply(imap, "OK Login completed");
	}

	imap->mbox = imap->mymbox;
	mailbox_maildir_init(mailbox_maildir(imap->mbox)); /* Edge case: initialize if needed (necessary if user is accessing via POP before any messages ever delivered to it via SMTP) */
	mailbox_watch(imap->mbox);
	return 0;
}

static int handle_auth(struct imap_session *imap, char *s)
{
	int res;

	/* AUTH=PLAIN - got a combined encoded username/password */
	unsigned char *decoded;
	char *authorization_id, *authentication_id, *password;

	imap->inauth = 0;
	decoded = bbs_sasl_decode(s, &authorization_id, &authentication_id, &password);
	if (!decoded) {
		return -1;
	}

	/* Can't use bbs_sasl_authenticate directly since we need to strip the domain */
	bbs_strterm(authentication_id, '@');
	res = bbs_authenticate(imap->node, authentication_id, password);
	bbs_memzero(password, strlen(password)); /* Destroy the password from memory before we free it */
	free(decoded);

	/* Have a combined username and password */
	if (res) {
		imap_reply(imap, "NO Invalid username or password"); /* No such mailbox, since wrong domain! */
	} else {
		return finish_auth(imap, 1);
	}
	free_if(imap->savedtag);
	return 0;
}

static int handle_setacl(struct imap_session *imap, char *s, int delete)
{
	char buf[256];
	char *mailbox, *user, *newacl;
	int myacl;

	REQUIRE_ARGS(s);
	mailbox = strsep(&s, " ");
	user = strsep(&s, " ");
	newacl = s;
	if (delete) {
		REQUIRE_ARGS(user);
		if (newacl) {
			bbs_warning("Extraneous argument provided for DELETEACL? (%s)\n", newacl);
			newacl = NULL;
		}
	} else {
		REQUIRE_ARGS(newacl);
		STRIP_QUOTES(newacl);
	}
	STRIP_QUOTES(mailbox);
	STRIP_QUOTES(user);

	/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
	if (imap_translate_dir(imap, mailbox, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
		imap_reply(imap, "NO No such mailbox");
		return 0;
	}
	IMAP_REQUIRE_ACL(myacl, IMAP_ACL_ADMINISTER);
	if (setacl(imap, buf, mailbox, user, newacl)) {
		imap_reply(imap, "NO %s failed", delete ? "DELETEACL" : "SETACL");
	} else {
		imap_reply(imap, "OK %s complete", delete ? "DELETEACL" : "SETACL");
	}
	return 0;
}

static int imap_process(struct imap_session *imap, char *s)
{
	int res;
	char *command;

	if (imap->idle) {
		/* Command should be "DONE" */
		if (strlen_zero(s) || strcasecmp(s, "DONE")) {
			bbs_warning("Improper IDLE termination (received '%s')\n", S_IF(s));
		}
		imap->idle = 0;
		_imap_reply(imap, "%s OK IDLE terminated\r\n", imap->savedtag); /* Use tag from IDLE request */
		free_if(imap->savedtag);
		return 0;
	}

	if (imap->appendsize) {
		/* We're in the middle of an append at the moment.
		 * This is kind of like the DATA command with SMTP. */
		int dlen;

		if (imap->appendfail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		dlen = strlen(s); /* s may be empty but will not be NULL */
		bbs_std_write(imap->appendfile, s, dlen);
		bbs_std_write(imap->appendfile, "\r\n", 2);
		imap->appendcur += dlen + 2;
#ifdef EXTRA_DEBUG
		imap_debug(10, "Received %d/%d bytes of APPEND so far\n", imap->appendcur, imap->appendsize);
#endif

		if (imap->appendcur >= imap->appendsize) {
			finish_append(imap);
		}
		return 0;
	} else if (imap->inauth) {
		return handle_auth(imap, s);
	}

	if (strlen_zero(s)) {
		return 0; /* Ignore empty lines at this point (can't do this if in an APPEND) */
	}

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
		imap_send(imap, "CAPABILITY " IMAP_CAPABILITIES);
		imap_reply(imap, "OK CAPABILITY completed");
	} else if (!strcasecmp(command, "AUTHENTICATE")) {
		if (bbs_user_is_registered(imap->node->user)) {
			imap_reply(imap, "NO Already logged in");
			return 0;
		}
		/* AUTH=PLAIN => AUTHENTICATE, which is preferred to LOGIN. */
		command = strsep(&s, " ");
		if (!strcasecmp(command, "PLAIN")) {
			if (!strlen_zero(s)) {
				/* RFC 4959 SASL-IR extension */
				return handle_auth(imap, s);
			}
			_imap_reply(imap, "+\r\n");
			imap->inauth = 1;
			REPLACE(imap->savedtag, imap->tag);
		} else {
			imap_reply(imap, "NO Auth method not supported");
		}
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
		bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
		if (res) {
			imap_reply(imap, "NO Invalid username or password");
			return 0;
		}
		return finish_auth(imap, 0);
	/* Past this point, must be logged in. */
	} else if (!bbs_user_is_registered(imap->node->user)) {
		bbs_warning("'%s' command may not be used in the unauthenticated state\n", command);
		imap_reply(imap, "BAD Not logged in");
	} else if (!strcasecmp(command, "SELECT")) {
		return handle_select(imap, s, 0);
	} else if (!strcasecmp(command, "EXAMINE")) {
		return handle_select(imap, s, 1);
	} else if (!strcasecmp(command, "STATUS")) { /* STATUS is like EXAMINE, but it's on a specified mailbox that is NOT the currently selected mailbox */
		REQUIRE_ARGS(s);
		/* Need to save/restore current maildir for STATUS, so it doesn't mess up the selected mailbox, since STATUS must not modify the selected folder. */
		res = handle_select(imap, s, 2);
		if (imap->folder) {
			set_maildir(imap, imap->folder);
		}
		return res;
	} else if (!strcasecmp(command, "NAMESPACE")) {
		/* Good article for understanding namespaces: https://utcc.utoronto.ca/~cks/space/blog/sysadmin/IMAPPrefixesClientAndServer */
		imap_send(imap, "NAMESPACE %s %s %s", PRIVATE_NAMESPACE, OTHER_NAMESPACE, SHARED_NAMESPACE);
		imap_reply(imap, "NAMESPACE command completed");
	} else if (!strcasecmp(command, "LIST")) {
		return handle_list(imap, s, 0);
	} else if (!strcasecmp(command, "LSUB")) { /* Deprecated in RFC 9051 (IMAP4rev2), but clients still use it */
		/* Bit of a hack: just assume all folders are subscribed
		 * All clients share the subscription list, so clients should try to LSUB before they SUBSCRIBE to anything.
		 * For example, to check if the Sent folder is subscribed, for storing sent emails.
		 * This is because they don't know if other clients have already subscribed to these folders
		 * (and with this setup, it will appear that, indeed, some other client already has).
		 * We have stubs for SUBSCRIBE and UNSUBSCRIBE as well, but the LSUB response is actually the only important one.
		 * Since we return all folders as subscribed, clients shouldn't try to subscribe to anything.
		 */
		return handle_list(imap, s, 1);
	} else if (!strcasecmp(command, "CREATE")) {
		IMAP_NO_READONLY(imap);
		return handle_create(imap, s);
	} else if (!strcasecmp(command, "DELETE")) {
		IMAP_NO_READONLY(imap);
		return handle_delete(imap, s);
	} else if (!strcasecmp(command, "RENAME")) {
		IMAP_NO_READONLY(imap);
		return handle_rename(imap, s);
	} else if (!strcasecmp(command, "CHECK")) {
		imap_reply(imap, "OK CHECK Completed"); /* Nothing we need to do now */
	/* Selected state */
	} else if (!strcasecmp(command, "CLOSE")) {
		REQUIRE_SELECTED(imap);
		if (imap->folder && IMAP_HAS_ACL(imap->acl, IMAP_ACL_EXPUNGE)) {
			imap_traverse(imap->curdir, on_close, imap);
		}
		imap->dir[0] = imap->curdir[0] = imap->newdir[0] = '\0';
		imap_reply(imap, "OK CLOSE completed");
	} else if (!strcasecmp(command, "EXPUNGE")) {
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		IMAP_REQUIRE_ACL(imap->acl, IMAP_ACL_EXPUNGE);
		if (imap->folder) {
			imap->expungeindex = 0;
			imap_traverse(imap->curdir, on_expunge, imap);
		}
		imap_reply(imap, "OK EXPUNGE completed");
	} else if (!strcasecmp(command, "UNSELECT")) { /* Same as CLOSE, without the implicit auto-expunging */
		imap->dir[0] = imap->curdir[0] = imap->newdir[0] = '\0';
		imap_reply(imap, "OK UNSELECT completed");
	} else if (!strcasecmp(command, "FETCH")) {
		REQUIRE_SELECTED(imap);
		return handle_fetch(imap, s, 0);
	} else if (!strcasecmp(command, "COPY")) {
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		return handle_copy(imap, s, 0);
	} else if (!strcasecmp(command, "STORE")) {
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		return handle_store(imap, s, 0);
	} else if (!strcasecmp(command, "SEARCH")) {
		REQUIRE_SELECTED(imap);
		return handle_search(imap, s, 0);
	} else if (!strcasecmp(command, "SORT")) {
		REQUIRE_SELECTED(imap);
		return handle_sort(imap, s, 0);
	} else if (!strcasecmp(command, "UID")) {
		REQUIRE_SELECTED(imap);
		REQUIRE_ARGS(s);
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		if (!strcasecmp(command, "FETCH")) {
			return handle_fetch(imap, s, 1);
		} else if (!strcasecmp(command, "COPY")) {
			return handle_copy(imap, s, 1);
		} else if (!strcasecmp(command, "STORE")) {
			return handle_store(imap, s, 1);
		} else if (!strcasecmp(command, "SEARCH")) {
			return handle_search(imap, s, 1);
		} else if (!strcasecmp(command, "SORT")) {
			return handle_sort(imap, s, 1);
		} else {
			imap_reply(imap, "BAD Invalid UID command");
		}
	} else if (!strcasecmp(command, "APPEND")) {
		IMAP_NO_READONLY(imap);
		REPLACE(imap->savedtag, imap->tag);
		handle_append(imap, s);
	} else if (allow_idle && !strcasecmp(command, "IDLE")) {
		REQUIRE_SELECTED(imap);
		/* RFC 2177 IDLE */
		_imap_reply(imap, "+ idling\r\n");
		REPLACE(imap->savedtag, imap->tag);
		imap->idle = 1;
		/* Note that IDLE only applies to the currently selected mailbox (folder).
		 * Thus, in traversing all the IMAP sessions, simply sharing the same mbox isn't enough.
		 * imap->dir also needs to match (same currently selected folder).
		 *
		 * One simplification this implementation makes is that
		 * IDLE only works for the INBOX, since that's probably the only folder most people care about much. */
	} else if (!strcasecmp(command, "SETQUOTA")) {
		/* Requires QUOTASET, which we don't advertise in our capabilities, so clients shouldn't call this anyways... */
		imap_reply(imap, "NO Permission Denied"); /* Users cannot adjust their own quotas, nice try... */
	} else if (!strcasecmp(command, "GETQUOTA")) {
		/* RFC 2087 / 9208 QUOTA */
		handle_getquota(imap);
		imap_reply(imap, "OK GETQUOTA complete");
	} else if (!strcasecmp(command, "GETQUOTAROOT")) {
		imap_send(imap, "QUOTAROOT %s \"\"", s);
		handle_getquota(imap);
		imap_reply(imap, "OK GETQUOTAROOT complete");
	} else if (!strcasecmp(command, "ID")) {
		/* RFC 2971 (ID extension) */
		REQUIRE_ARGS(s); /* We don't care what the client's capabilities are (we don't make use of them), but must be some argument (e.g. NIL) */
		imap_send(imap, "ID (\"name\" \"%s.Imap4Server\" \"version\" \"%s\")", BBS_SHORTNAME, BBS_VERSION);
		imap_reply(imap, "OK ID completed");
	/* We don't store subscriptions. We just automatically treat all available folders as subscribed.
	 * Implement for the sake of completeness, even though these commands are really pointless.
	 * LSUB will return all folders, so clients *shouldn't* try to SUBSCRIBE to something, but if they do, accept it.
	 * If they try to UNSUBSCRIBE, definitely reject that. */
	} else if (!strcasecmp(command, "SUBSCRIBE")) {
		IMAP_NO_READONLY(imap);
		/* Since we don't check for mailbox existence (and everything is always subscribed anyways), no real need to check ACLs here */
		bbs_warning("Subscription attempt for %s for mailbox %d\n", S_IF(s), mailbox_id(imap->mbox));
		imap_reply(imap, "OK SUBSCRIBE completed"); /* Everything available is already subscribed anyways, so can't hurt */
	} else if (!strcasecmp(command, "UNSUBSCRIBE")) {
		IMAP_NO_READONLY(imap);
		bbs_warning("Unsubscription attempt for %s for mailbox %d\n", S_IF(s), mailbox_id(imap->mbox));
		imap_reply(imap, "NO Permission denied");
	} else if (!strcasecmp(command, "MYRIGHTS")) {
		char buf[256];
		int myacl;
		REQUIRE_ARGS(s);
		STRIP_QUOTES(s);
		/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
		if (imap_translate_dir(imap, s, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
			imap_reply(imap, "NO No such mailbox");
			return 0;
		}
		IMAP_REQUIRE_ACL(myacl, IMAP_ACL_LOOKUP | IMAP_ACL_READ | IMAP_ACL_INSERT | IMAP_ACL_MAILBOX_CREATE | IMAP_ACL_MAILBOX_DELETE | IMAP_ACL_ADMINISTER);
		generate_acl_string(myacl, buf, sizeof(buf));
		imap_send(imap, "MYRIGHTS %s %s", s, buf);
		imap_reply(imap, "OK MYRIGHTS completed");
	} else if (!strcasecmp(command, "LISTRIGHTS")) {
		char buf[256];
		char *mailbox;
		int myacl;
		REQUIRE_ARGS(s);
		mailbox = strsep(&s, " ");
		REQUIRE_ARGS(s);
		STRIP_QUOTES(mailbox);
		/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
		if (imap_translate_dir(imap, mailbox, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
			imap_reply(imap, "NO No such mailbox");
			return 0;
		}
		IMAP_REQUIRE_ACL(myacl, IMAP_ACL_ADMINISTER);
		/* First chunk is rights always granted to this user in the mailbox.
		 * Subsequent ones are rights that MAY be granted, and rights in a chunk must be granted together.
		 * No repeats allowed.
		 *
		 * Here we assume no rights always granted (empty string), and every right can be granted individually.
		 * XXX Here IMAP_ACL_UNION_CREATE_LETTER and IMAP_ACL_UNION_DELETE_LETTER are ignored.
		 */
		imap_send(imap, "LISTRIGHTS %s %s \"\" %c %c %c %c %c " "%c %c " "%c %c " "%c", mailbox, s,
			IMAP_ACL_LOOKUP_LETTER, IMAP_ACL_READ_LETTER, IMAP_ACL_SEEN_LETTER, IMAP_ACL_WRITE_LETTER, IMAP_ACL_POST_LETTER,
			IMAP_ACL_MAILBOX_CREATE_LETTER, IMAP_ACL_MAILBOX_DELETE_LETTER,
			IMAP_ACL_DELETE_LETTER, IMAP_ACL_EXPUNGE_LETTER,
			IMAP_ACL_ADMINISTER_LETTER);
		imap_reply(imap, "OK GETACL complete");
	} else if (!strcasecmp(command, "GETACL")) {
		char buf[256];
		int myacl;
		REQUIRE_ARGS(s);
		STRIP_QUOTES(s);
		/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
		if (imap_translate_dir(imap, s, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
			imap_reply(imap, "NO No such mailbox");
			return 0;
		}
		IMAP_REQUIRE_ACL(myacl, IMAP_ACL_ADMINISTER);
		getacl(imap, buf, s);
		imap_reply(imap, "OK GETACL complete");
	} else if (!strcasecmp(command, "SETACL")) {
		return handle_setacl(imap, s, 0);
	} else if (!strcasecmp(command, "DELETEACL")) {
		return handle_setacl(imap, s, 1);
	} else if (!strcasecmp(command, "TESTLOCK")) {
		/* Hold the mailbox lock for a moment. */
		/*! \note This is only used for the test suite, it is not part of any IMAP standard or intended for clients. */
		MAILBOX_TRYRDLOCK(imap);
		usleep(3500000); /* 500ms is sufficient normally, but under valgrind, we need more time */
		mailbox_unlock(imap->mbox);
		imap_reply(imap, "OK Lock test succeeded");
	} else {
		/*! \todo These commands are not currently implemented: MOVE */
		/*! \todo The following common capabilities are not currently supported: AUTH=PLAIN-CLIENTTOKEN AUTH=OAUTHBEARER AUTH=XOAUTH AUTH=XOAUTH2 UIDPLUS MOVE LITERAL+ BINARY ENABLE */
		/*! \todo Add BURL SMTP / IMAP integration (to allow message to be uploaded only once, instead of twice) */

		bbs_warning("Unsupported IMAP command: %s\n", command);
		imap_reply(imap, "BAD Command not supported.");
	}

	return 0;
}

static void handle_client(struct imap_session *imap)
{
	char buf[1001];
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
		if (imap->inauth || (word2++ && !strlen_zero(word2) && !strncasecmp(word2, "LOGIN", STRLEN("LOGIN")))) {
			bbs_debug(6, "%p => <LOGIN REDACTED>\n", imap); /* Mask login to avoid logging passwords */
		} else if (!imap->appendsize) {
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
	struct imap_session imap, *s;

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
	imap.appendfile = -1;

	pthread_mutex_init(&imap.lock, NULL);

	/* Add to session list (for IDLE) */
	RWLIST_WRLOCK(&sessions);
	RWLIST_INSERT_HEAD(&sessions, &imap, entry);
	RWLIST_UNLOCK(&sessions);

	handle_client(&imap);

	/* Remove from session list */
	RWLIST_WRLOCK(&sessions);
	s = RWLIST_REMOVE(&sessions, &imap, entry);
	RWLIST_UNLOCK(&sessions);
	if (!s) {
		bbs_error("Failed to remove IMAP session %p from session list?\n", &imap);
	}
	/* imap is stack allocated, don't free it */

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

	bbs_config_val_set_true(cfg, "general", "allowidle", &allow_idle);

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
	{ "IMAP COPYUID Generation", test_copyuid_generation },
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

	pthread_mutex_init(&acl_lock, NULL);

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
	mailbox_register_watcher(imap_mbox_watcher);
	return 0;
}

static int unload_module(void)
{
	unsigned int i;
	for (i = 0; i < ARRAY_LEN(tests); i++) {
		bbs_unregister_test(tests[i].callback);
	}
	mailbox_unregister_watcher(imap_mbox_watcher);
	bbs_pthread_cancel_kill(imap_listener_thread);
	bbs_pthread_join(imap_listener_thread, NULL);
	if (imap_enabled) {
		bbs_unregister_network_protocol(imap_port);
		close_if(imap_socket);
	}
	if (imaps_enabled) {
		bbs_unregister_network_protocol(imaps_port);
		close_if(imaps_socket);
	}
	pthread_mutex_destroy(&acl_lock);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC9051 IMAP", "mod_mail.so,mod_mimeparse.so");
