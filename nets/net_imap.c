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
 * \note Supports RFC 2177 IDLE
 * \note Supports RFC 2342 NAMESPACE
 * \note Supports RFC 4315 UIDPLUS (obsoletes RFC 2359)
 * \note Supports RFC 2971 ID
 * \note Supports RFC 3348 CHILDREN
 * \note Supports RFC 3691 UNSELECT
 * \note Supports RFC 4314 ACLs
 * \note Supports RFC 4466, 4731 SEARCH extensions
 * \note Supports RFC 4467 URLAUTH (partially) for RFC 4468 BURL
 * \note Supports RFC 4959 SASL-IR
 * \note Supports RFC 5032 WITHIN (OLDER, YOUNGER)
 * \note Supports RFC 5161 ENABLE
 * \note Supports RFC 5182 SEARCHRES
 * \note Supports RFC 5256 SORT
 * \note Supports RFC 5267 ESORT
 * \note Supports RFC 5530 Response Codes
 * \note Supports RFC 6154 SPECIAL-USE (but not CREATE-SPECIAL-USE)
 * \note Supports RFC 6851 MOVE
 * \note Supports RFC 7162 CONDSTORE (obsoletes RFC 4551)
 * \note Supports RFC 7162 QRESYNC (obsoletes RFC 5162)
 * \note Supports RFC 7889 APPENDLIMIT
 * \note Supports RFC 9208 QUOTA
 *
 * \note STARTTLS is not supported for cleartext IMAP, as proposed in RFC2595, as this guidance
 *       is obsoleted by RFC8314. Implicit TLS (IMAPS) should be preferred.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*! \todo IMAP functionality not yet implemented/supported:
 * - RFC 2088 LITERAL+ and 7888 LITERAL-
 * - RFC 3502 MULTIAPPEND - this could be potentially dangerous due to small deviations in literal sizes (see APPEND comments about Trojita)
 * - RFC 4469 CATENATE
 * - RFC 4959 SASL-IR
 * - RFC 4978 COMPRESS
 * - RFC 5255 LANGUAGE
 * - RFC 5256 THREAD
 * - RFC 5257 ANNOTATE, RFC 5464 ANNOTATE (METADATA)
 * - RFC 5258 LIST extensions (obsoletes 3348)
 * - RFC 5267 CONTEXT=SEARCH and CONTEXT=SORT
 * - RFC 5423 events and RFC 5465 NOTIFY
 * - RFC 5738 UTF8
 * - RFC 5819 LIST status
 * - RFC 5957 DISPLAYFROM/DISPLAYTO
 * - RFC 6203 FUZZY SEARCH
 * - RFC 6237 ESEARCH (MULTISEARCH)
 * - RFC 6855 UTF-8
 * - RFC 8970 PREVIEW
 * - BINARY and MULTIAPPEND extensions (RFC 3516, 4466)
 * Other capabilities: AUTH=PLAIN-CLIENTTOKEN AUTH=OAUTHBEARER AUTH=XOAUTH AUTH=XOAUTH2
 */

#define IMAP_REV "IMAP4rev1"
/* List of capabilities: https://www.iana.org/assignments/imap-capabilities/imap-capabilities.xml */
/* XXX IDLE is advertised here even if disabled (although if disabled, it won't work if a client tries to use it) */
/* XXX URLAUTH is advertised so that SMTP BURL will function in Trojita, even though we don't need URLAUTH since we have a direct trust */
#define IMAP_CAPABILITIES IMAP_REV " AUTH=PLAIN UNSELECT SPECIAL-USE XLIST CHILDREN IDLE NAMESPACE QUOTA QUOTA=RES-STORAGE ID SASL-IR ACL SORT URLAUTH ESEARCH ESORT SEARCHRES UIDPLUS APPENDLIMIT MOVE WITHIN ENABLE CONDSTORE QRESYNC"

/* Capabilities advertised by popular mail providers, for reference/comparison, both pre and post authentication:
 * - Office 365
 * Guest: IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2 SASL-IR UIDPLUS ID UNSELECT CHILDREN IDLE NAMESPACE LITERAL+
 * Auth:  IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2 SASL-IR UIDPLUS MOVE ID UNSELECT CLIENTACCESSRULES CLIENTNETWORKPRESENCELOCATION BACKENDAUTHENTICATE CHILDREN IDLE NAMESPACE LITERAL+

 * - Gmail
 * Guest: IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST CHILDREN X-GM-EXT-1 XYZZY SASL-IR AUTH=XOAUTH2 AUTH=PLAIN AUTH=PLAIN-CLIENTTOKEN AUTH=OAUTHBEARER AUTH=XOAUTH
 * Auth:  IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST CHILDREN X-GM-EXT-1 UIDPLUS COMPRESS=DEFLATE ENABLE MOVE CONDSTORE ESEARCH UTF8=ACCEPT LIST-EXTENDED LIST-STATUS LITERAL- SPECIAL-USE APPENDLIMIT=35651584

 * - Purely Mail
 * Guest: IMAP4rev1 LITERAL+ CHILDREN I18NLEVEL=1 NAMESPACE IDLE ENABLE CONDSTORE QRESYNC ANNOTATION AUTH=PLAIN SASL-IR RIGHTS= WITHIN ESEARCH ESORT SEARCHRES SORT MOVE UIDPLUS UNSELECT COMPRESSED=DEFLATE
 * Auth:  IMAP4rev1 LITERAL+ CHILDREN I18NLEVEL=1 NAMESPACE IDLE ENABLE CONDSTORE QRESYNC ANNOTATION AUTH=PLAIN SASL-IR RIGHTS= WITHIN ESEARCH ESORT SEARCHRES SORT MOVE UIDPLUS UNSELECT COMPRESSED=DEFLATE

 * - Yandex
 * Guest: IMAP4rev1 CHILDREN UNSELECT LITERAL+ NAMESPACE XLIST BINARY UIDPLUS ENABLE ID AUTH=PLAIN AUTH=XOAUTH2 IDLE MOVE
 * Auth:  IMAP4rev1 CHILDREN UNSELECT LITERAL+ NAMESPACE XLIST BINARY UIDPLUS ENABLE ID IDLE MOVE
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <dirent.h>
#include <ftw.h>
#include <poll.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/test.h"
#include "include/notify.h"
#include "include/oauth.h"
#include "include/base64.h"

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
#define _imap_reply_nolock(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); dprintf(imap->wfd, fmt, ## __VA_ARGS__);
#define _imap_reply(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); pthread_mutex_lock(&imap->lock); dprintf(imap->wfd, fmt, ## __VA_ARGS__); pthread_mutex_unlock(&imap->lock);
#define imap_send(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", "*", ## __VA_ARGS__)
#define imap_reply(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", S_IF(imap->tag), ## __VA_ARGS__)

/* RFC 2086/4314 ACLs */
/*! \brief Visible in LIST, LSUB, SUBSCRIBE */
#define IMAP_ACL_LOOKUP (1 << 0)
#define IMAP_ACL_LOOKUP_LETTER 'l'

/*! \brief SELECT, STATUS */
#define IMAP_ACL_READ (1 << 1)
#define IMAP_ACL_READ_LETTER 'r'

/*! \brief SEEN persistence */
/*! \note There is no way for Seen to not be persistent, so this is always enabled. */
#define IMAP_ACL_SEEN (1 << 2)
#define IMAP_ACL_SEEN_LETTER 's'

/*! \brief Set or clear flags other than Seen or Deleted via STORE, or set using APPEND/COPY */
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

/*! \brief DELETE messages (Deleted flag via STORE, APPEND, COPY) */
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

#define IMAP_HAS_ACL(acl, flag) (acl & (flag))
#define IMAP_REQUIRE_ACL(acl, flag) \
	if (!IMAP_HAS_ACL(acl, (flag))) { \
		char _aclbuf[15]; \
		generate_acl_string(acl, _aclbuf, sizeof(_aclbuf)); \
		bbs_debug(4, "User missing ACL %s (have %s)\n", #flag, _aclbuf); \
		imap_reply(imap, "NO [NOPERM] Permission denied"); \
		return 0; \
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
	char *folder;				/* Currently selected mailbox */
	char *activefolder;			/* Currently connected mailbox (i.e. STATUS updates this, but not folder) */
	char *savedtag;
	int pfd[2];					/* Pipe for delayed responses */
	/* maildir */
	char dir[256];
	char newdir[260]; /* 4 more, for /new and /cur */
	char curdir[260];
	char virtprefix[260];		/* Mapping prefix defined in .imapremote */
	int virtprefixlen;			/* Length of virtprefix */
	int virtcapabilities;		/* Capabilities of remote IMAP server */
	char virtdelimiter;			/* Hierarchy delimiter used by remote server */
	unsigned int uidvalidity;
	unsigned int uidnext;
	unsigned long highestmodseq;	/* Cached HIGHESTMODSEQ for current folder */
	int acl;					/* Cached ACL for current directory. We allowed to cache per a mailbox by the RFC. */
	char *savedsearch;			/* SEARCHRES */
	char *clientid;				/* Client ID */
	struct bbs_tcp_client client;	/* TCP client for virtual mailbox access on remote servers */
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
	/* Other flags */
	unsigned int savedsearchuid:1;	/* Whether the saved search consists of sequence numbers or UIDs */
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
	unsigned int virtmbox:1;	/* Currently in a virtual mailbox */
	unsigned int dnd:1;			/* Do Not Disturb: Whether client is executing a FETCH, STORE, or SEARCH command (EXPUNGE responses are not allowed) */
	unsigned int pending:1;		/* Delayed output is pending in pfd pipe */
	unsigned int alerted:2;		/* An alert has been delivered to this client */
	unsigned int condstore:1;	/* Whether a client has issue a CONDSTORE enabling command, and should be sent MODSEQ updates in untagged FETCH responses */
	unsigned int qresync:1;		/* Whether a client has enabled the QRESYNC capability */
	pthread_mutex_t lock;		/* Lock for IMAP session */
	RWLIST_ENTRY(imap_session) entry;	/* Next active session */
};

static RWLIST_HEAD_STATIC(sessions, imap_session);

static inline void reset_saved_search(struct imap_session *imap)
{
	free_if(imap->savedsearch); /* See comments about EXPUNGE in imap_expunge */
	imap->savedsearch = 0;
}

static void send_untagged_fetch(struct imap_session *imap, int seqno, unsigned int uid, unsigned long modseq, const char *newflags)
{
	struct imap_session *s;
	char normalmsg[256];
	char condstoremsg[256];
	int normallen, condlen;

	/* Prepare both types of messages.
	 * Each client currently in this same mailbox will get one message or the other,
	 * depending on its value of imap->condstore
	 */
	normallen = snprintf(normalmsg, sizeof(normalmsg), "* %d FETCH (%s)\r\n", seqno, newflags);
	condlen = snprintf(condstoremsg, sizeof(condstoremsg), "* %d FETCH (UID %u MODSEQ %lu %s)\r\n", seqno, uid, modseq, newflags); /* RFC 7162 3.2.4 */

	/*! \todo If # mailbox_watchers on the current mailbox is 1 (the entire account, not just this folder),
	 * we could probably bail out early here, since we know it's just us... */

	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		if (s == imap || s->mbox != imap->mbox || strcmp(s->dir, imap->dir)) {
			continue;
		}
		/* Hey, this client is on the same exact folder right now! Send it an unsolicited, untagged response. */
		pthread_mutex_lock(&s->lock);
		if (!s->idle) { /* We are only free to send responses whenever we want if the client is idling. */
			bbs_write(s->pfd[1], s->condstore ? condstoremsg : normalmsg, s->condstore ? condlen : normallen);
			s->pending = 1;
			imap_debug(4, "%p <= %s", s, s->condstore ? condstoremsg : normalmsg); /* Already ends in CR LF */
		} else {
			bbs_write(s->wfd, s->condstore ? condstoremsg : normalmsg, s->condstore ? condlen : normallen);
			imap_debug(4, "%p <= %s", s, s->condstore ? condstoremsg : normalmsg); /* Already ends in CR LF */
		}
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
}

/* Forward declaration */
static char *gen_uintlist(unsigned int *l, int lengths);

static void send_untagged_expunge(struct imap_session *imap, int silent, unsigned int *uid, unsigned int *seqno, int length)
{
	struct imap_session *s;
	char *str2, *str = NULL;
	int slen, slen2;
	int delay;

	/* Send VANISHED responses to any clients that enabled QRESYNC, and normal EXPUNGE responses to everyone else. */
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		/* This one also goes to ourself... unless silent */
		if (s->mbox != imap->mbox || strcmp(s->dir, imap->dir)) {
			continue;
		}
		if (s == imap && silent) {
			continue;
		}
		pthread_mutex_lock(&s->lock);
		delay = s->idle || s == imap ? 0 : 1; /* Only send immediately if in IDLE, or if it's the current client (which obviously is NOT idling) */
		if (s->qresync) { /* VANISHED */
			if (length && !str) {
				/* Don't waste time generating a VANISHED response in advance if we're not going to send it to any clients.
				 * Most clients don't even support QRESYNC, so most of the time this won't be even be useful.
				 * Do it automatically as needed if/when we encounter the first supporting client. */
				str = gen_uintlist(uid, length);
				slen = strlen(S_IF(str));
				/* Add length of * VANISHED + CR LF */
				slen2 = slen + STRLEN("* VANISHED ") + STRLEN("\r\n");
				str2 = malloc(slen2 + 1); /* For deletions of multiple sequences, this could be of any arbitrary length. Not likely, but possible. */
				if (ALLOC_SUCCESS(str2)) {
					strcpy(str2, "* VANISHED ");
					strcpy(str2 + STRLEN("* VANISHED "), str);
					strcpy(str2 + STRLEN("* VANISHED ") + slen, "\r\n");
					free(str);
					str = str2;
					slen = slen2;
				}
			}
			bbs_write(delay ? s->pfd[1] : s->wfd, str, slen);
			imap_debug(4, "%p <= %s\r\n", s, str);
		} else { /* EXPUNGE */
			int i;
			for (i = 0; i < length; i++) {
				char normalmsg[64];
				int normallen = snprintf(normalmsg, sizeof(normalmsg), "* %u EXPUNGE\r\n", seqno[i]);
				bbs_write(delay ? s->pfd[1] : s->wfd, normalmsg, normallen);
				imap_debug(4, "%p <= %s", s, normalmsg);
			}
		}
		if (delay) {
			s->pending = 1;
			reset_saved_search(s); /* Since messages were expunged, invalidate any saved search */
		}
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
	free_if(str);
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

static void free_scandir_entries(struct dirent **entries, int numfiles)
{
	int fno = 0;
	struct dirent *entry;

	while (fno < numfiles && (entry = entries[fno++])) {
		free(entry);
	}
}

static int uidsort(const struct dirent **da, const struct dirent **db)
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
		auid = atoi(a);
		buid = atoi(b);
	} else if (unlikely(failures == 1)) {
		bbs_error("Failed to parse UID for %s / %s\n", a, b);
		return 0;
	} else if (unlikely(auid == buid)) {
		bbs_error("Message UIDs are equal? (%u = %u)\n", auid, buid);
		return 0;
	}

	return auid < buid ? -1 : 1;
}

/*! \brief Find the disk filename of a message, given its sequence number or UID in a cur maildir folder */
static int imap_msg_to_filename(const char *directory, int seqno, unsigned int uid, char *buf, size_t len)
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

/* All IMAP traversals must be ordered, so we can't use these functions or we'll get a ~random (at least incorrect) order */
/* Sequence numbers must strictly be in order, if they aren't, all sorts of weird stuff will happened.
 * I know this because I tried using these functions first, and it didn't really work.
 * Because scandir allocates memory for all the files in a directory up front, it could result in a lot of memory usage.
 * Technically, for this reason, may want to limit the number of messages in a single mailbox (folder) for this reason.
 */
#define opendir __Do_not_use_readdir_or_opendir_use_scandir
#define readdir __Do_not_use_readdir_or_opendir_use_scandir
#define closedir __Do_not_use_readdir_or_opendir_use_scandir
#define alphasort __Do_not_use_alphasort_use_uidsort

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
			/* Note that we always watch our personal mailbox (s->mymbox), but the current mailbox, s->mbox,
			 * may be different.
			 * This works out as we can only send untagged responses during IDLE for the currently selected mailbox. */
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

		/* RFC 3501 Section 7: unilateral response */
		if (!s->idle) { /* We are only free to send responses whenever we want if the client is idling. */
			dprintf(s->pfd[1], "* %d EXISTS\r\n", numtotal); /* Number of messages in the mailbox. */
			imap_debug(4, "%p <= * %d EXISTS\r\n", s, numtotal);
			s->pending = 1;
			/* No need to reset saved search for new messages (only do that for EXPUNGE) */
		} else {
			dprintf(s->wfd, "* %d EXISTS\r\n", numtotal); /* Number of messages in the mailbox. */
			imap_debug(4, "%p <= * %d EXISTS\r\n", s, numtotal);
		}
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
}

static void imap_close_remote_mailbox(struct imap_session *imap)
{
	bbs_assert(imap->virtmbox == 1);
	bbs_debug(6, "Closing remote mailbox\n");
	SWRITE(imap->client.wfd, "bye LOGOUT\r\n"); /* This is optional, but be nice */
	bbs_tcp_client_cleanup(&imap->client);
	imap->virtmbox = 0;
}

static void imap_destroy(struct imap_session *imap)
{
	if (imap->virtmbox) {
		imap_close_remote_mailbox(imap);
	}
	if (imap->mbox != imap->mymbox) {
		mailbox_unwatch(imap->mbox);
		imap->mbox = imap->mymbox;
		imap->mymbox = NULL;
	}
	if (imap->mbox) {
		mailbox_unwatch(imap->mbox); /* We previously started watching it, so stop watching it now. */
		imap->mbox = NULL;
	}
	free_if(imap->savedsearch);
	close_if(imap->appendfile);
	free_if(imap->appenddate);
	/* Do not free tag, since it's stack allocated */
	free_if(imap->savedtag);
	free_if(imap->clientid);
	free_if(imap->activefolder);
	free_if(imap->folder);
	pthread_mutex_destroy(&imap->lock);
}

/*! \brief Faster than strncat, since we store our position between calls, but maintain its safety */
#define SAFE_FAST_COND_APPEND(bufstart, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, buflen, bufpos == bufstart ? fmt : " " fmt, ## __VA_ARGS__); \
		bufpos += _bytes; \
		buflen -= _bytes; \
		if ((int) buflen <= 0) { \
			bbs_warning("Buffer truncation\n"); \
			*(bufpos + buflen - 1) = '\0';  \
		} \
	}

#define SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, buflen, fmt, ## __VA_ARGS__); \
		bufpos += _bytes; \
		buflen -= _bytes; \
		if ((int) buflen <= 0) { \
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

#define IMAP_FLAGS FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN " " FLAG_NAME_ANSWERED " " FLAG_NAME_DELETED " " FLAG_NAME_DRAFT
#define HIERARCHY_DELIMITER "."
#define HIERARCHY_DELIMITER_CHAR '.'

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
static void parse_keyword(struct imap_session *imap, const char *s, const char *directory, int create)
{
	char filename[266];
	char buf[32];
	FILE *fp;
	char index = 0;

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
			char newindex = 'a' + index;
			fprintf(fp, "%c %s\n", newindex, s);
			imap->appendkeywords[imap->numappendkeywords++] = newindex; /* Safe, since we know we're in bounds */
			imap->createdkeyword = 1;
		}
	}

	mailbox_uid_unlock(imap->mbox);
	fclose(fp);
}

#define gen_keyword_names(imap, s, inbuf, inlen) __gen_keyword_names(s, inbuf, inlen, imap->dir)

static int __gen_keyword_names(const char *s, char *inbuf, size_t inlen, const char *directory)
{
	FILE *fp;
	char fbuf[32];
	char filename[266];
	char *buf = inbuf;
	int matches = 0;
	int left = inlen;
	const char *custom_start = s;

	snprintf(filename, sizeof(filename), "%s/.keywords", directory);

	*buf = '\0';
	fp = fopen(filename, "r");
	if (!fp) {
		bbs_debug(9, "maildir %s has no keywords\n", directory);
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

#define parse_flags_string(imap, s) __parse_flags_string(imap, s, imap->dir)

/*! \brief Convert named flag or keyword into a single character for maildir filename */
/*! \note If imap is not NULL, custom keywords are stored in imap->appendkeywords (size is stored in imap->numappendkeywords) */
static int __parse_flags_string(struct imap_session *imap, char *s, const char *directory)
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
			parse_keyword(imap, f, directory, 1);
		}
	}
	if (imap) {
		imap->appendkeywords[imap->numappendkeywords] = '\0'; /* Null terminate the keywords buffer */
	}
	return flags;
}

/*!
 * \param f
 * \param[out] keywords Pointer to beginning of keywords, if any
 */
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

/*!
 * \param filename
 * \param flags
 * \param keywordsbuf Must be of size 27
 */
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
	bbs_test_assert_equals(FLAG_BIT_DELETED | FLAG_BIT_FLAGGED | FLAG_BIT_SEEN, __parse_flags_string(NULL, buf, NULL));
	bbs_test_assert_equals(FLAG_BIT_DRAFT | FLAG_BIT_SEEN, parse_flags_letters("DS", NULL));

	gen_flag_letters(FLAG_BIT_FLAGGED | FLAG_BIT_SEEN, buf, sizeof(buf));
	bbs_test_assert_str_equals("FS", buf);

	gen_flag_names("FS", buf, sizeof(buf));
	bbs_test_assert_str_equals(FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN, buf);

	return 0;

cleanup:
	return -1;
}

/* Forward declaration */
static int maildir_msg_setflags(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters);

static int restrict_flags(int acl, int *flags)
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

/*!
 * \brief Translate the flags from a filename in one maildir to the flags for a different maildir (see function comments)
 * \note This function will rename the file with the adjusted flag letters
 *
 * \param imap
 * \param oldmaildir The old maildir from which flags are translated
 * \param oldfilenamefull The full path to the current filename of this message
 * \param oldfilename A base filename that contains the flags. Note this does not necessarily have to be the basename of oldfilenamefull,
 *        and with current usage, it is not. It's fine if it's stale, as long as it contains the flags accurately
 * \param newmaildir The new maildir to which flags are translated
 * \param destacl
 */
static int translate_maildir_flags(struct imap_session *imap, const char *oldmaildir, const char *oldfilenamefull, const char *oldfilename, const char *newmaildir, int destacl)
{
	char keywords[256];
	char newflagletters[53];
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

	/* Get what letters they would be in the new directory. */
	oldflags = __parse_flags_string(imap, keywords, newmaildir); /* Note: __parse_flags_string "uses up" keyword so don't attempt to print it out afterwards */

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
		strncat(newflagletters, imap->appendkeywords, sizeof(newflagletters) - 1); /* Append the keywords */
	}

	bbs_debug(5, "Flags for %s have changed to '%s' due to location/permission change\n", oldfilename, newflagletters);
	return maildir_msg_setflags(imap, 0, oldfilenamefull, newflagletters);
}

#define REQUIRE_ARGS(s) \
	if (!s || !*s) { \
		imap_reply(imap, "BAD [CLIENTBUG] Missing arguments"); \
		return 0; \
	}

#define REQUIRE_SELECTED(imap) \
	if (s_strlen_zero(imap->dir)) { \
		imap_reply(imap, "BAD [CLIENTBUG] Must select a mailbox first"); \
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
		imap_reply(imap, "NO [INUSE] Mailbox busy"); \
		return 0; \
	}

#define IMAP_NO_READONLY(imap) \
	if (imap->readonly) { \
		imap_reply(imap, "NO [NOPERM] Mailbox is read only"); \
	}

enum mailbox_namespace {
	NAMESPACE_PRIVATE = 0,
	NAMESPACE_OTHER,
	NAMESPACE_SHARED,
};

#define PARSE_ACL(var) \
	aclstr = strchr(aclbuf, ' '); \
	if (!aclstr) { \
		bbs_error("Invalid ACL entry: %s\n", aclbuf); \
		continue; \
	} \
	aclstr++; \
	var = parse_acl(aclstr);

static int load_acl_file(const char *filename, const char *matchstr, int matchlen, int *acl)
{
	char aclbuf[72];
	FILE *fp;
	int found_anyone = 0, found_authenticated = 0;
	int anyone_acl, authenticated_acl;
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
	pthread_mutex_lock(&acl_lock); /* Ordinarily, a global mutex for all SETACLs would be terrible on a large IMAP server, but fine here */
	fp = fopen(fullname, "r+"); /* Open with r+ in case we end up appending to the original file */
	if (!fp) {
		/* No existing ACLs, this is the easy case. Just write a new file and return.
		 * There is technically a race condition possible here, we're the only process using this file,
		 * but another thread could be trying to access it too. So that's why we have a lock. */
		if (action == -1) {
			bbs_debug(3, "No rights to remove - no ACL match for %s\n", user);
			return 0;
		}
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
					safe_strncpy(eff_acl + pos, newacl, sizeof(eff_acl) - pos); /* Since we know the end, can use safe_strncpy instead of strncat */
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
				return -1;
			}
			remainder += strlen(username);
			/* Just this is \Select'able, it's the INBOX (INBOX isn't shown as a separate subdir for Other Users, etc.) */
			snprintf(buf, len, "%s/%u%s%s", mailbox_maildir(NULL), userid, !strlen_zero(remainder) ? "/" : "", remainder); /* Don't end in a trailing slash */
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

/* Forward declaration */
static int load_virtual_mailbox(struct imap_session *imap, const char *path);

enum select_type {
	CMD_SELECT = 0,
	CMD_EXAMINE = 1,
	CMD_STATUS = 2,
};

static int set_maildir(struct imap_session *imap, const char *mailbox)
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
		if (imap->virtmbox) {
			imap_close_remote_mailbox(imap);
		}
		return -1;
	}

	if (imap->virtmbox) {
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

static long parse_modseq_from_filename(const char *filename, unsigned long *modseq)
{
	char *modseqstr = strstr(filename, ",M=");
	if (!modseqstr) {
		/* Don't use 0 since HIGHESTMODSEQ=0 indicates persistent mod sequences not supported (RFC 7162 Section 7) */
		*modseq = 1; /* At least since we started keeping track of MODSEQ, this file has not been modified to have it added to the filename */
		return -1;
	}
	modseqstr += STRLEN(",M=");
	if (!strlen_zero(modseqstr)) {
		*modseq = atol(modseqstr); /* Should stop as soon we encounter the first nonnumeric character, whether , or : */
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
			maildir_parse_uid_from_filename(filename, &uid);
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
	if (!*size) {
		bbs_warning("Invalid size (%lu) for %s\n", *size, filename);
	}
	return 0;
}

/* Forward declarations */
static int uintlist_append(unsigned int **a, int *lengths, int *allocsizes, unsigned int vala);
static int uintlist_append2(unsigned int **a, unsigned int **b, int *lengths, int *allocsizes, unsigned int vala, unsigned int valb);

static int imap_expunge(struct imap_session *imap, int silent)
{
	struct dirent *entry, **entries;
	int files, fno = 0;

	const char *dir_name = imap->curdir;
	const char *filename;
	int oldflags;
	char fullpath[256];
	unsigned long size;
	unsigned int uid;
	unsigned long modseq;
	unsigned int *expunged = NULL, *expungedseqs = NULL;
	int exp_lengths = 0, exp_allocsizes = 0;

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

	MAILBOX_TRYRDLOCK(imap);

	files = scandir(dir_name, &entries, NULL, uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", dir_name, strerror(errno));
		mailbox_unlock(imap->mbox);
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto next;
		}

		filename = entry->d_name;
		imap->expungeindex += 1;

#ifdef EXTRA_DEBUG
		imap_debug(10, "Analyzing file %s/%s\n", dir_name, filename);
#endif
		if (parse_flags_letters_from_filename(filename, &oldflags, NULL)) { /* Don't care about keywords */
			bbs_error("File %s is noncompliant with maildir\n", filename);
			goto next;
		}
		if (!(oldflags & FLAG_BIT_DELETED)) {
			goto next;
		}

		/* Marked as deleted. Remove message, permanently. */
		snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
		imap_debug(4, "Permanently removing message %s\n", fullpath);

		if (unlink(fullpath)) {
			bbs_error("Failed to delete %s: %s\n", fullpath, strerror(errno));
		}

		if (parse_size_from_filename(filename, &size)) {
			/* It's too late to stat now as a fallback, the file's gone, who knows how big it was now. */
			mailbox_invalidate_quota_cache(imap->mbox);
		} else {
			mailbox_quota_adjust_usage(imap->mbox, -size);
		}
		maildir_parse_uid_from_filename(filename, &uid);
		parse_modseq_from_filename(filename, &modseq);
		/* Note that the seqno gets modified during expunges, so we use expungeindex here */
		uintlist_append2(&expunged, &expungedseqs, &exp_lengths, &exp_allocsizes, uid, imap->expungeindex); /* store UID and seqno */

		/* RFC 5182 says that if we have a saved search, it MUST be updated if a message in it is expunged.
		 * That is really the correct way to do it, for now, to avoid incorrect results, we just clear any saved search (which is really not the right thing to do, either).
		 * This is done in send_untagged_expunge
		 */

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
next:
		free(entry);
	}
	free(entries);

	mailbox_unlock(imap->mbox);
	imap->highestmodseq = maildir_indicate_expunged(imap->mbox, imap->curdir, expunged, exp_lengths); /* Batch HIGHESTMODSEQ bookkeeping for EXPUNGEs */
	send_untagged_expunge(imap, silent, expunged, expungedseqs, exp_lengths); /* Send for EXPUNGE, but not CLOSE */
	free_if(expunged);
	free_if(expungedseqs);

	return 0;
}

static int imap_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, struct imap_session *imap), struct imap_session *imap)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res;

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(path, &entries, NULL, uidsort);
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
	free_scandir_entries(entries, files); /* Free all at once at the end, in case we break from the loop early */
	free(entries);
	return res;
}

/* Forward declarations */
/*! \todo Please come up with a plan to move the IMAP utility functions elsewhere, ideally to a separate file...
 * the forward declarations sprinkled throughout the file are starting to get ridiculous */
static int in_range_allocated(const char *s, int num, char *sequences);
static void generate_flag_names_full(struct imap_session *imap, const char *filename, char *bufstart, char **bufptr, int *lenptr);
static char *parensep(char **str);
static int range_to_uintlist(char *s, unsigned int **list, int *length);

/*! \note This should kind of be in mod_mail with the other modseq functions,
 * except it has dependencies on several net_imap things (uintlist_append, in_range_allocated, etc), so cleaner to just have it here */
static void maildir_get_expunged_since_modseq(struct imap_session *imap, const char *directory, unsigned long lastmodseq, char *uidrangebuf, unsigned int minuid, const char *uidrange)
{
	char modseqfile[256];
	FILE *fp;
	unsigned long modseq;
	unsigned int uid;
	int res;
	unsigned int *a = NULL;
	int lengths = 0, allocsizes = 0;

	snprintf(modseqfile, sizeof(modseqfile), "%s/../.modseqs", directory);
	fp = fopen(modseqfile, "rb");
	if (!fp) {
		bbs_error("Failed to open %s\n", modseqfile);
		return;
	}
	res = fread(&modseq, sizeof(unsigned long), 1, fp);
	if (res != 1) {
		bbs_error("Failed to read HIGHESTMODSEQ from %s\n", directory);
		fclose(fp);
		return;
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
		if (uidrange && !in_range_allocated(uidrange, uid, uidrangebuf)) {
			continue;
		}
		uintlist_append(&a, &lengths, &allocsizes, uid);
	}

	fclose(fp);

	if (lengths) {
		char *str = gen_uintlist(a, lengths);
		free(a);
		imap_send(imap, "VANISHED (EARLIER) %s", S_IF(str));
		free_if(str);
	}
}

static void do_qresync(struct imap_session *imap, unsigned long lastmodseq, const char *uidrange, char *seqrange)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	unsigned long modseq;
	unsigned int uid;
	unsigned int seqno = 0;
	unsigned int minuid = 0;
	char *uidrangebuf = NULL;

	bbs_assert(imap->qresync == 1);

	if (uidrange) {
		uidrangebuf = malloc(strlen(uidrange) + 1); /* We could use strdup, but in_range_allocated always calls strcpy, so malloc avoids unnecessary copying here */
		if (!uidrangebuf) {
			return;
		}
	}

	/* Now send any pending flag changes */
	files = scandir(imap->curdir, &entries, NULL, uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		free_if(uidrangebuf);
		return;
	}

	if (seqrange) { /* Testing note: Thunderbird does not support QRESYNC, but Trojita does */
		unsigned int *seqs = NULL, *uids = NULL;
		int seq_lengths = 0, uid_lengths = 0;
		char *uidseq, *sequences;

		uidseq = parensep(&seqrange); /* Strip the () */
		sequences = strsep(&uidseq, " "); /* Get the first half (the sequence numbers, second half is UIDs) */
		bbs_debug(7, "sequences %s <=> UIDs %s\n", sequences, uidseq);
		range_to_uintlist(sequences, &seqs, &seq_lengths);
		if (!uidseq) {
			bbs_warning("Malformed command\n");
		} else {
			range_to_uintlist(uidseq, &uids, &uid_lengths);
			if (seq_lengths != uid_lengths) {
				bbs_warning("Invalid message sequence data argument (%d != %d)\n", seq_lengths, uid_lengths);
				/* Just ignore this argument */
			} else {
				/* Run the algorithm described in RFC 7162 3.2.5.2 */
				/* Something like 1,3,5:6 1,10,15,17 - sequence numbers, then UIDs corresponding to those
				 * If based on what the client has sent, we are able to determine the client already knows about this expunge,
				 * we can skip including it in the list.
				 * Here, we determine a lowerbound on the UIDs we will consider for EXPUNGE, and pass that into
				 * maildir_get_expunged_since_modseq
				 *
				 * Note that the importance of this message sequence match data varies inversely with the completeness
				 * of the storage of modification sequences for expunged messages. This parameter is designed to account
				 * for servers expiring older expunged MODSEQs.
				 * Since we don't currently remove old expunged MODSEQs, this parameter is not as useful to us and could be ignored.
				 */
				int i = 0;
				while (fno < files && (entry = entries[fno++])) {
					if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
						continue;
					}
					seqno++;
					if (seqs[i] == seqno) {
						unsigned int realuid;
						maildir_parse_uid_from_filename(entry->d_name, &realuid);
						bbs_debug(7, "Comparing seqno %u with UID %u\n", seqs[i], uids[i]);
						if (uids[i] == realuid) {
							minuid = realuid; /* Can skip at least everything prior to this message for EXPUNGE responses */
						} else {
							break; /* No point in continuing, minuid will never get any higher */
						}
						i++;
						if (i == seq_lengths) {
							break; /* If we finish early, stop, since there are no more comparisons that can be made */
						}
					}
				}
			}
		}
		fno = 0, seqno = 0;
		free_if(seqs);
		free_if(uids);
	}

	/* First, send any expunges since last time */
	maildir_get_expunged_since_modseq(imap, imap->curdir, lastmodseq, uidrangebuf, minuid, uidrange);

	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto next;
		}
		seqno++;
		if (parse_modseq_from_filename(entry->d_name, &modseq)) {
			goto next;
		}
		if (maildir_parse_uid_from_filename(entry->d_name, &uid)) {
			goto next;
		}
		if (uidrange && !in_range_allocated(uidrange, uid, uidrangebuf)) {
			goto next;
		}
		/* seqrange is only used for EXPUNGE, not fetching flag changes */
		if (modseq > lastmodseq) {
			/* Send the flags for this message */
			char flagsbuf[256];
			char *buf = flagsbuf;
			int len = sizeof(flagsbuf);
			const char *flags;

			flags = strchr(entry->d_name, ':'); /* maildir flags */
			if (!flags) {
				bbs_error("Message file %s contains no flags?\n", entry->d_name);
				goto next;
			}
			generate_flag_names_full(imap, flags, flagsbuf, &buf, &len);
			imap_send(imap, "%u FETCH (UID %u %s) MODSEQ (%lu)", seqno, uid, flagsbuf, modseq);
		}
next:
		free(entry);
	}
	free(entries);
	free_if(uidrangebuf);
}

static void close_mailbox(struct imap_session *imap)
{
	imap->dir[0] = imap->curdir[0] = imap->newdir[0] = '\0';
}

/* ~ 2.5 MB */
#define LOW_MAILBOX_SPACE_THRESHOLD 2500000

static void low_quota_alert(struct imap_session *imap)
{
	unsigned quotaleft = mailbox_quota_remaining(imap->mbox);
	if (quotaleft < LOW_MAILBOX_SPACE_THRESHOLD) { /* Very little quota remaining */
		imap_send(imap, "OK [ALERT] Mailbox is almost full (%u KB quota remaining)\n", quotaleft / 1024);
	}
}

static int client_command_passthru(struct imap_session *imap, int fd, const char *tag, int taglen, const char *cmd, int cmdlen, int ms)
{
	int res;
	char buf[8192];
	struct pollfd pfds[2];
	int client_said_something = 0;
	struct bbs_tcp_client *client = &imap->client;

	/* We initialized bbs_readline with a NULL buffer, fix that: */
	client->rldata.buf = buf;
	client->rldata.len = sizeof(buf);

	pfds[0].fd = client->rfd;
	pfds[1].fd = fd;

	for (;;) {
		if (fd != -1) {
			res = bbs_multi_poll(pfds, 2, ms); /* If returns 1, client->rfd had activity, if 2, it was fd */
			if (res == 2) {
				char buf2[32];
				/* This is used during an IDLE. Passthru whatever we read to the client in return.
				 * We do not need actually need to parse this. If the client terminates an IDLE,
				 * then the server will respond "tag DONE" and we will detect that and exit normally.
				 * It is also true that for IDLE, the first input from the client should terminate anyways.
				 * So we check that below.
				 */
				client_said_something = 1;
				res = read(fd, buf2, sizeof(buf2));
				if (res <= 0) {
					return -1; /* Client disappeared during idle / server shutdown */
				}
				imap_debug(10, "=> %.*s", res, buf2); /* "DONE" already includes CR LF */
				res = write(client->wfd, buf2, res);
				continue;
			}
			/* If client->rfd had activity, go ahead and just call bbs_readline.
			 * The internal poll it does will be superflous, of course. */
		}
		res = bbs_readline(client->rfd, &client->rldata, "\r\n", ms);
		if (res < 0) { /* Could include remote server disconnect */
			return res;
		}
		/* Go ahead and relay it */
		bbs_write(imap->wfd, buf, res);
		SWRITE(imap->wfd, "\r\n");
#ifdef DEBUG_REMOTE_RESPONSES
		/* NEVER enable this in production because this will be a huge volume of data */
		imap_debug(10, "<= %.*s\n", res, buf);
#endif
		if (!strncmp(buf, tag, taglen)) {
			imap_debug(10, "<= %.*s\n", res, buf);
			if (STARTS_WITH(buf + taglen, "BAD")) {
				/* We did something we shouldn't have, oops */
				bbs_warning("Command '%.*s%.*s' failed\n", taglen, tag, cmdlen > 2 ? cmdlen - 2 : cmdlen, cmd); /* Don't include trailing CR LF */
			}
			break; /* That's all, folks! */
		}
		if (client_said_something) {
			bbs_warning("Client likely terminated IDLE, but loop has not exited\n");
		}
	}
	return res;
}

static int my_imap_client_login(struct bbs_tcp_client *client, struct bbs_url *url, struct imap_session *imap)
{
	return imap_client_login(client, url, imap->node->user, &imap->virtcapabilities);
}

#define imap_client_send_wait_response(imap, fd, ms, fmt, ...) __imap_client_send_wait_response(imap, fd, ms, __LINE__, fmt, ## __VA_ARGS__)

static int __attribute__ ((format (gnu_printf, 5, 6))) __imap_client_send_wait_response(struct imap_session *imap, int fd, int ms, int lineno, const char *fmt, ...)
{
	char *buf;
	int len, res;
	char tagbuf[15];
	int taglen;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	taglen = snprintf(tagbuf, sizeof(tagbuf), "%s ", imap->tag); /* Reuse the tag the client sent us, so we can just passthrough the response */

	/* XXX If the remote server disconnected on us for some reason, these operations may succeed
	 * even if no data is sent.
	 * Handled in client_command_passthru */

#if 0
	/* Somewhat redundant since there's another debug right after */
	bbs_debug(6, "Passing through command %s (line %d) to remotely mapped '%s'\n", imap->tag, lineno, imap->virtprefix);
#else
	UNUSED(lineno);
#endif
	bbs_write(imap->client.wfd, tagbuf, taglen);
	bbs_write(imap->client.wfd, buf, len);
	imap_debug(7, "=> %s%s", tagbuf, buf);
	/* Read until we get the tagged respones */
	res = client_command_passthru(imap, fd, tagbuf, taglen, buf, len, ms) <= 0;
	free(buf);
	return res;
}

static int handle_select(struct imap_session *imap, char *s, enum select_type readonly)
{
	/* Mailbox can contain spaces, so don't use strsep for it if it's in quotes */
	char *mailbox;
	int was_selected;
	unsigned long maxmodseq;
	struct mailbox *oldmbox;

	REQUIRE_ARGS(s);
	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s); /* The STATUS command will have additional arguments (and possibly SELECT, for CONDSTORE/QRESYNC) */

	was_selected = imap->dir[0] ? 1 : 0;
	oldmbox = imap->mbox;

	/* This modifies the current maildir even for STATUS, but the STATUS command will restore the old one afterwards. */
	if (set_maildir(imap, mailbox)) { /* Note that set_maildir handles mailbox being "INBOX". It may also change the active (account) mailbox. */
		return 0;
	}
	if (imap->virtmbox) {
		char *tmp, *remotename = mailbox + imap->virtprefixlen + 1;
		/* This is some other server's problem to handle.
		 * Just forward the request (after modifying the mailbox name as appropriate, to remove the prefix + following period). */
		/* Also need to adjust for hierarchy delimiter being different, potentially.
		 * Typically imap_substitute_remote_command handles this, but for SELECT we go ahead and send the name directly,
		 * so do what's needed here. The conversion logic here is a lot simpler anyways, since we know we just have
		 * a mailbox name and not an entire command to convert.
		 * XXX What if we ever want to support SELECT commands that contain more than just a mailbox?
		 */
		tmp = remotename;
		while (*tmp) {
			if (*tmp == HIERARCHY_DELIMITER_CHAR) {
				*tmp = imap->virtdelimiter;
			}
			tmp++;
		}
		if (readonly <= 1) { /* SELECT/EXAMINE */
			REPLACE(imap->folder, mailbox);
			return imap_client_send_wait_response(imap, -1, 5000, "%s \"%s\"\r\n", readonly == CMD_SELECT ? "SELECT" : "EXAMINE", remotename); /* Reconstruct the SELECT, fortunately this is not too bad */
		} else { /* STATUS */
			REPLACE(imap->activefolder, mailbox);
			return imap_client_send_wait_response(imap, -1, 5000, "STATUS \"%s\" %s\r\n", remotename, s);
		}
	}
	if (!readonly) {
		static int sharedflagrights = IMAP_ACL_SEEN | IMAP_ACL_WRITE;
		readonly = IMAP_HAS_ACL(imap->acl, IMAP_ACL_INSERT | IMAP_ACL_EXPUNGE | sharedflagrights) ? 0 : 1;
	}
	if (readonly <= 1) { /* SELECT and EXAMINE should update currently selected mailbox, STATUS should not */
		REPLACE(imap->folder, mailbox);
		reset_saved_search(imap); /* RFC 5182 2.1 */
	} else {
		/* imap->folder will still contain the currently selected mailbox.
		 * imap->activefolder will now contain the mailbox for STATUS. */
		REPLACE(imap->activefolder, mailbox);
	}
	if (readonly == CMD_EXAMINE) {
		imap->readonly = readonly;
	} else {
		imap->readonly = 0; /* In case the previously SELECTed folder was read only */
	}
	mailbox_has_activity(imap->mbox); /* Clear any activity flag since we're about to do a traversal. */
	IMAP_TRAVERSAL(imap, on_select);
	maxmodseq = maildir_max_modseq(imap->mbox, imap->curdir);
	if (readonly <= 1) { /* SELECT, EXAMINE */
		char aclstr[15];
		char keywords[256] = "";
		int condstore_just_enabled = 0;
		unsigned int lastmodseq = 0;
		char *uidrange = NULL, *seqrange = NULL;
		int numkeywords = gen_keyword_names(imap, NULL, keywords, sizeof(keywords)); /* prepends a space before all of them, so this works out great */

		if (!strlen_zero(s)) {
			if (STARTS_WITH(s, "(QRESYNC")) {
				char *qresync, *tmp;
				unsigned int lastuidvalidity;
				if (!imap->qresync) { /* RFC 7162 3.2.5 */
					imap_reply(imap, "BAD [CLIENTBUG] QRESYNC not enabled");
					return 0;
				}
				/* Something like A02 SELECT INBOX (QRESYNC (67890007 20050715194045000 41,43:211,214:541)) */
				qresync = parensep(&s);
				qresync += STRLEN("QRESYNC ");
				qresync = parensep(&qresync);
				/* Now qresync should be the inner paren contents */
				tmp = strsep(&qresync, " ");
				REQUIRE_ARGS(tmp);
				lastuidvalidity = atoi(tmp);
				tmp = strsep(&qresync, " ");
				REQUIRE_ARGS(tmp);
				lastmodseq = atoi(tmp);
				if (!strlen_zero(qresync) && *qresync != '(') { /* Trojita sends params 1, 2, and 4 but not 3 (no UID range) */
					uidrange = strsep(&qresync, " "); /* This is optional and defaults to 1:* */
				} else {
					uidrange = NULL; /* Defaults to 1:* - for efficiency's sake, use NULL instead */
				}
				if (!strlen_zero(qresync)) {
					if (*qresync == '(') {
						seqrange = qresync; /* Also optional */
					} else {
						bbs_warning("Parsing error: %s\n", qresync);
					}
				}
				/* If client's last UIDVALIDITY doesn't match ours, then ignore all this */
				if (lastuidvalidity != imap->uidvalidity) {
					bbs_verb(5, "Client's UIDVALIDITY (%u) differs from ours (%u)\n", lastuidvalidity, imap->uidvalidity);
					lastmodseq = 0;
					uidrange = NULL;
				}
			} else if (strstr(s, "CONDSTORE")) {
				if (!imap->condstore) {
					condstore_just_enabled = 1;
				}
				imap->condstore = 1; /* RFC 7162 3.1.8 */
			} else {
				/* CONDSTORE is the only known optional parameter for SELECT/EXAMINE */
				bbs_warning("Unexpected parameter: %s\n", s);
			}
		}

		if (was_selected) {
			imap_send(imap, "OK [CLOSED]"); /* RFC 7162 3.2.11, example in 3.2.5.1 */
		}

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
		 *
		 * The Purelymail email server adds an "F" after its PERMANENTFLAGS response because some clients
		 * will break if no commentary is present in the response (so a single letter suffices for this purpose).
		 * Most of the other responses already have pretty standard commentary,
		 * but that one doesn't so it's just arbitrary and as short as possible.
		 * RFC 7162 3.1.2.1 shows "LIMITED" appearing at the end of a PERMANENTFLAGS response, so we do that here,
		 * as clients are limited in how many custom flags (keywords) can be used (26 for the entire mailbox)
		 */
		imap_send(imap, "OK [PERMANENTFLAGS (%s%s \\*)] Limited", IMAP_FLAGS, numkeywords > 0 ? keywords : ""); /* Include \* to indicate we support IMAP keywords */
		imap_send(imap, "%u EXISTS", imap->totalnew + imap->totalcur); /* Number of messages in the mailbox. */
		imap_send(imap, "%u RECENT", imap->totalnew); /* Number of messages with \Recent flag (maildir: new, instead of cur). */
		if (imap->firstunseen) {
			/* Both of these are supposed to be firstunseen (the first one is NOT totalunseen) */
			imap_send(imap, "OK [UNSEEN %u] Message %u is first unseen", imap->firstunseen, imap->firstunseen);
		}
		imap_send(imap, "OK [UIDVALIDITY %u] UIDs valid", imap->uidvalidity);
		/* uidnext is really the current max UID allocated. The next message will have at least UID of uidnext + 1, but it could be larger. */
		imap_send(imap, "OK [UIDNEXT %u] Predicted next UID", imap->uidnext + 1);
		imap_send(imap, "OK [HIGHESTMODSEQ %lu] Highest", maxmodseq);
		generate_acl_string(imap->acl, aclstr, sizeof(aclstr));
		imap_send(imap, "OK [MYRIGHTS \"%s\"] ACL", aclstr);
		if (lastmodseq) {
			do_qresync(imap, lastmodseq, uidrange, seqrange);
		}
		if (oldmbox != imap->mbox) {
			/* Whenever we switch mailboxes, alert about low quota */
			low_quota_alert(imap);
		}
		imap_reply(imap, "OK [%s] %s completed%s", readonly ? "READ-ONLY" : "READ-WRITE", readonly ? "EXAMINE" : "SELECT", condstore_just_enabled ? ", CONDSTORE is now enabled" : "");
		imap->highestmodseq = maxmodseq;
	} else if (readonly == CMD_STATUS) { /* STATUS */
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
			SAFE_FAST_COND_APPEND(status_items, pos, left, strstr(s, "APPENDLIMIT"), "APPENDLIMIT %lu", mailbox_quota(imap->mbox));
			SAFE_FAST_COND_APPEND(status_items, pos, left, strstr(s, "HIGHESTMODSEQ"), "HIGHESTMODSEQ %lu", maxmodseq);
		}
		imap_send(imap, "STATUS %s (%s)", mailbox, status_items);
		imap_reply(imap, "OK STATUS completed");
	} else {
		bbs_assert(0);
	}
	return 0;
}

#define EMPTY_QUOTES "\"\""

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
	files = scandir(path, &entries, NULL, uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		} else if (!strncmp(entry->d_name, prefix, prefixlen)) {
			const char *rest = entry->d_name + prefixlen; /* do not add these within the strlen_zero macro! */
			/*! \todo XXX Check entire code tree for strlen_zero with + inside adding arguments. That's a bug!!! */
			if (!strlen_zero(rest)) {
				res = 1;
				break;
			}
		}
	}
	free_scandir_entries(entries, files);
	free(entries);
	return res;
}

#define DIR_NO_SELECT (1 << 0)
#define DIR_NO_CHILDREN (1 << 1)
#define DIR_HAS_CHILDREN (1 << 2)
#define DIR_DRAFTS (1 << 3)
#define DIR_JUNK (1 << 4)
#define DIR_SENT (1 << 5)
#define DIR_TRASH (1 << 6)

#define DIR_INBOX (1 << 7)

#define DIR_SPECIALUSE (DIR_DRAFTS | DIR_JUNK | DIR_SENT | DIR_TRASH)

#define IS_SPECIAL_NAME(s) (!strcmp(s, "INBOX") || !strcmp(s, "Drafts") || !strcmp(s, "Junk") || !strcmp(s, "Sent") || !strcmp(s, "Trash"))

#define ATTR_NOSELECT "\\Noselect"
#define ATTR_HAS_CHILDREN "\\HasChildren"
#define ATTR_NO_CHILDREN "\\HasNoChildren"
#define ATTR_DRAFTS "\\Drafts"
#define ATTR_JUNK "\\Junk"
#define ATTR_SENT "\\Sent"
#define ATTR_TRASH "\\Trash"

#define ATTR_INBOX "\\Inbox"

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
	ASSOC_ATTR(DIR_INBOX, ATTR_INBOX);

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

static void list_scandir(struct imap_session *imap, const char *listscandir, int lsub, int specialuse, int level, enum mailbox_namespace ns,
	char *attributes, size_t attrlen, const char *reference, const char *prefix, const char *mailbox, int reflen, int skiplen)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	const char *cmd = lsub == 2 ? "XLIST" : lsub ? "LSUB" : "LIST";

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(listscandir, &entries, NULL, uidsort);
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
			if (lsub == 2 && strstr(entry->d_name, "INBOX")) { /* XXX This is not the right way to detect this */
				flags |= DIR_INBOX;
			}
			build_attributes_string(attributes, attrlen, flags);
			if (!specialuse || flags & DIR_SPECIALUSE) {
				imap_send(imap, "%s (%s) \"%s\" \"%s%s%s%s\"", cmd, attributes, HIERARCHY_DELIMITER,
					ns == NAMESPACE_SHARED ? SHARED_NAMESPACE_PREFIX HIERARCHY_DELIMITER : ns == NAMESPACE_OTHER ? OTHER_NAMESPACE_PREFIX HIERARCHY_DELIMITER : "",
					S_IF(prefix), prefix ? HIERARCHY_DELIMITER : "", *mailboxname == '.' ? mailboxname + 1 : mailboxname); /* Always send the delimiter */
			}
recurse:
			/* User may not be authorized for some mailbox, but may be authorized for a subdirectory (e.g. not INBOX, but some subfolder)
			 * However, this is incredibly expensive as it means "Other Users" will literally traverse every user's entire maildir. */
			if (ns != NAMESPACE_PRIVATE && !level) {
				/* Recurse only the first time, since there are no more maildirs within afterwards */
				list_scandir(imap, fulldir, lsub, specialuse, 1, ns, attributes, attrlen, reference, mailboxname, mailbox, reflen, skiplen);
			}
cleanup:
			; /* Needed so we can jump to the cleanup label */
		}
		free(entry);
	}
	free(entries);
}

/*! \brief Mutex to prevent recursion */
static pthread_mutex_t virt_lock; /* XXX Should most definitely be per mailbox struct, not global */

static int skipn(char **str, char c, int n)
{
	int count = 0;
	char *s = *str;

	while (*s) {
		if (*s == c) {
			if (++count == n) {
				*str = s + 1;
				break;
			}
		}
		s++;
	}
	return count;
}

/*! \brief Same as skipn, but don't include spaces inside a parenthesized list */
static int skipn_noparen(char **str, char c, int n)
{
	int count = 0;
	int level = 0;
	char *s = *str;

	while (*s) {
		if (*s == '(') {
			level++;
		} else if (*s == ')') {
			level--;
		} else if (!level && *s == c) {
			if (++count == n) {
				*str = s + 1;
				break;
			}
		}
		s++;
	}
	return count;
}

static int imap_client_list(struct bbs_tcp_client *client, const char *prefix, FILE *fp)
{
	int res;

	IMAP_CLIENT_SEND(client, "a3 LIST \"\" \"*\"");

	for (;;) {
		char fullmailbox[256];
		char *p1, *p2, *attributes, *delimiter;
		res = bbs_readline(client->rfd, &client->rldata, "\r\n", 200);
		if (res < 0) {
			break;
		}
		if (STARTS_WITH(client->buf, "a3 OK")) {
			break; /* Done */
		}
		/* The responses are something like this:
		 *     * LIST () "." "Archive"
		 *     * LIST () "." "INBOX"
		 */
		/* Skip the first 2 spaces */
		p1 = client->buf;
		p2 = p1;
		if (skipn(&p2, ' ', 2) != 2) {
			bbs_warning("Invalid LIST response: %s\n", client->buf);
			continue;
		}
		if (strlen_zero(p2)) {
			bbs_warning("Unexpected LIST response: %s\n", client->buf); /* Probably screwed up now anyways */
			continue;
		}
		/* Should now be at (). But this can contain multiple words, so use parensep, not strsep */
		if (*p2 != '(') { /* guaranteed to exist since p2 would be empty otherwise */
			bbs_warning("Invalid LIST response: %s\n", p2);
			continue;
		}
		attributes = parensep(&p2);
		/* Now at "." "Archive"
		 * But not all IMAP servers use "." as their hierarchy delimiter.
		 * Gimap, for example, uses "/".
		 * So preserve the delimiter the server sends us. */
		delimiter = strsep(&p2, " ");
		STRIP_QUOTES(delimiter);
		if (strlen_zero(delimiter)) {
			bbs_warning("Invalid LIST response\n");
			continue;
		}
		if (strcmp(delimiter, ".") && strcmp(delimiter, "/")) {
			bbs_warning("Unexpected hierarchy delimiter '%s'\n", delimiter); /* Flag anything uncommon in case it's a parsing error */
			continue;
		}
		STRIP_QUOTES(p2); /* Strip quotes from mailbox name, we'll add them ourselves */
		/* Note that for real Other Users, the root folder (username) is itself selectable, and that is the INBOX.
		 * For these virtual folders, the INBOX is just a folder that appears as a sibling to other folders, e.g. Sent, Drafts, etc. */
		if (strlen_zero(attributes)) { /* If it was (), then *attributes is just the NUL terminator at this point */
			/* attributes are empty. Try to guess what they are based on folder name.
			 * This is useful as mail clients will at least use nice icons when displaying these folders: */
			if (!strcmp(p2, "Drafts")) {
				attributes = "\\Drafts";
			} else if (!strcmp(p2, "Sent")) {
				attributes = "\\Sent";
			} else if (!strcmp(p2, "Junk")) {
				attributes = "\\Junk";
			} else if (!strcmp(p2, "Trash")) {
				attributes = "\\Trash";
			} else {
				bbs_debug(8, "Mailbox '%s' has no attributes\n", p2);
			}
			/*! \todo Would be nice to say HasChildren or HasNoChildren here, too, if the server didn't say */
		}
		snprintf(fullmailbox, sizeof(fullmailbox), "%s%s%s", prefix, delimiter, p2);
		/* If the hierarchy delimiter differs from ours, then fullmailbox will contain multiple delimiters.
		 * The prefix uses ours and the remote mailbox part uses theirs.
		 * The translation happens when this gets used later. */
		fprintf(fp, "(%s) \"%s\" \"%s\"\n", attributes, delimiter, fullmailbox); /* Cache the folders so we don't have to keep hitting the server up */
		/* If this doesn't match the filter, we won't actually send it to the client, but still save it to the cache, so it's complete. */
	}

	return 0;
}

/*! \brief Whether a specific mailbox path has a virtual mapping to a mailbox on a remote server */
static int load_virtual_mailbox(struct imap_session *imap, const char *path)
{
	FILE *fp;
	int res = -1;
	char virtcachefile[256];
	char buf[256];

	if (imap->virtmbox) {
		/* Reuse the same connection if it's the same account. */
		if (!strncmp(imap->virtprefix, path, imap->virtprefixlen)) {
			bbs_debug(6, "Reusing existing connection for %s\n", path);
			return 0;
		}
		/* If it's to a different server, tear down the existing connection first. */
		imap_close_remote_mailbox(imap);
	}

	snprintf(virtcachefile, sizeof(virtcachefile), "%s/.imapremote", mailbox_maildir(imap->mymbox));
	fp = fopen(virtcachefile, "r");
	if (!fp) {
		return -1;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		char *mpath, *urlstr = buf;
		int prefixlen;
		mpath = strsep(&urlstr, "|");
		/* We are not looking for an exact match.
		 * Essentially, the user defines a "subtree" in the .imapremote file,
		 * and anything under this subtree should match.
		 * It doesn't matter if the actual desired mailbox doesn't exist on the remote server,
		 * that's not our problem, and the client will discover that when doing a SELECT.
		 */

		if (strlen_zero(urlstr)) {
			continue; /* Illegitimate */
		}

		/* Instead of doing prefixlen = strlen(mpath), we can just subtract the pointers */
		prefixlen = urlstr - mpath - 1; /* Subtract 1 for the space between. */
#if 0
		bbs_debug(3, "Comparing '%s' with %s\n", path, mpath);
#endif
		if (!strncmp(mpath, path, prefixlen)) {
			struct bbs_url url;
			char tmpbuf[1024];
			char *tmp;
			memset(&url, 0, sizeof(url));
			if (bbs_parse_url(&url, urlstr)) {
				break;
			}
			bbs_assert(!imap->virtmbox); /* Shouldn't be a client left, or it'll leak here */
			memset(&imap->client, 0, sizeof(imap->client));
			if (bbs_tcp_client_connect(&imap->client, &url, !strcmp(url.prot, "imaps"), tmpbuf, sizeof(tmpbuf))) {
				res = 1;
				break;
			}
			if (my_imap_client_login(&imap->client, &url, imap)) {
				goto cleanup;
			}
			imap->virtmbox = 1;
			safe_strncpy(imap->virtprefix, mpath, sizeof(imap->virtprefix));
			imap->virtprefixlen = prefixlen;

			/* Need to determine the hierarchy delimiter on the remote server,
			 * so that we can make replacements as needed, including for SELECT.
			 * We do store this in the .imapremote.cache file,
			 * but that's not the file we opened.
			 * It's not stored in .imapremote itself.
			 * Simplest thing is just issue: a0 LIST "" ""
			 * which will return the hierarchy delimiter and not much else.
			 * Maybe not efficient in terms of network RTT,
			 * but we only do this once, when we login and setup the connection, so not too bad.
			 */
			IMAP_CLIENT_SEND(&imap->client, "dlm LIST \"\" \"\"");
			IMAP_CLIENT_EXPECT(&imap->client, "* LIST");
			/* Parse out the hierarchy delimiter */
			tmp = strchr((&imap->client)->buf, '"');
			if (!tmp) {
				bbs_warning("Invalid LIST response: %s\n", (&imap->client)->buf);
				goto cleanup;
			}
			tmp++;
			if (strlen_zero(tmp)) {
				goto cleanup;
			}
			imap->virtdelimiter = *tmp;
			bbs_debug(6, "Remote server's hierarchy delimiter is '%c'\n", imap->virtdelimiter);
			IMAP_CLIENT_EXPECT(&imap->client, "dlm OK");

			/* Enable any capabilities enabled by the client that the server supports */
			if (imap->virtcapabilities & IMAP_CAPABILITY_ENABLE) {
				if (imap->qresync && (imap->virtcapabilities & IMAP_CAPABILITY_QRESYNC)) {
					IMAP_CLIENT_SEND(&imap->client, "cap0 ENABLE QRESYNC");
					IMAP_CLIENT_EXPECT(&imap->client, "* ENABLED QRESYNC");
					IMAP_CLIENT_EXPECT(&imap->client, "cap0 OK");
				} else if (imap->condstore && (imap->virtcapabilities & IMAP_CAPABILITY_CONDSTORE)) {
					IMAP_CLIENT_SEND(&imap->client, "cap0 ENABLE CONDSTORE");
					IMAP_CLIENT_EXPECT(&imap->client, "* ENABLED CONDSTORE");
					IMAP_CLIENT_EXPECT(&imap->client, "cap0 OK");
				}
			}

			res = 0;
			break;
cleanup:
			res = 1;
			bbs_tcp_client_cleanup(&imap->client);
			break;
		}
	}
	fclose(fp);
	return res;
}

/*! \brief Allow a LIST against mailboxes on other mail servers, configured in the .imapremote file in a user's root maildir */
/*! \note XXX Virtual mailboxes already have a meaning in some IMAP contexts, so maybe "remote mailboxes" would be a better name? */
static int list_virtual(struct imap_session *imap, const char *listscandir, int lsub, int specialuse, enum mailbox_namespace ns, const char *reference, const char *mailbox, int reflen, int skiplen)
{
	FILE *fp2;
	char virtfile[256];
	char virtcachefile[256];
	char line[256];
	int l = 0;
	struct stat st, st2;
	int forcerescan = 0;
	const char *cmd = lsub == 2 ? "XLIST" : lsub ? "LSUB" : "LIST";

	/* Folders from the proxied mailbox will need to be translated back and forth */
	if (pthread_mutex_trylock(&virt_lock)) {
		bbs_warning("Possible recursion inhibited\n");
		return -1;
	}

	snprintf(virtfile, sizeof(virtfile), "%s/.imapremote", mailbox_maildir(imap->mymbox));
	snprintf(virtcachefile, sizeof(virtcachefile), "%s/.imapremote.cache", mailbox_maildir(imap->mymbox));
	bbs_debug(3, "Checking virtual mailboxes in %s\n", virtcachefile);

	if (stat(virtfile, &st)) {
		pthread_mutex_unlock(&virt_lock);
		return -1;
	}
	if (stat(virtcachefile, &st2) || st.st_mtim.tv_sec > st2.st_mtim.tv_sec) {
		/* .imapremote has been modified since .imapremote.cache was written, or .imapremote.cache doesn't even exist yet */
		forcerescan = 1;
	}
	if (!forcerescan) {
		/* A bit non-optimal since we'll fail 2 fopens if a user isn't using virtual mailboxes */
		fp2 = fopen(virtcachefile, "r");
	}
	if (!fp2 || forcerescan) {
		FILE *fp = fopen(virtfile, "r");
		if (!fp) {
			pthread_mutex_unlock(&virt_lock);
			return -1;
		}
		fp2 = fopen(virtcachefile, "w+");
		if (!fp2) {
			fclose(fp);
			pthread_mutex_unlock(&virt_lock);
			return -1;
		}

		/* Note that we cache all the directories on all servers at once, since we truncate the file. */
		while ((fgets(line, sizeof(line), fp))) {
			char *prefix, *server;
			struct bbs_url url;
			struct bbs_tcp_client client;
			int secure = 0;
			char buf[1024]; /* Must be large enough to get all the CAPABILITYs, or bbs_readline will throw a warning about buffer exhaustion and return 0 */

			memset(&url, 0, sizeof(url));
			l++;

			server = line;
			prefix = strsep(&server, "|"); /* Use pipe in case mailbox name contains spaces */

			if (bbs_parse_url(&url, server)) {
				bbs_warning("Malformed URL on line %d: %s\n", l, server); /* Include the line number since bbs_parse_url "used up" the string */
				continue;
			}
			if (!strcmp(url.prot, "imaps")) {
				secure = 1;
			} else if (strcmp(url.prot, "imap")) {
				bbs_warning("Unsupported protocol: %s\n", url.prot);
				continue;
			}
			/* Expect a URL like imap://user:password@imap.example.com:993/mailbox */
			memset(&client, 0, sizeof(client));
			if (bbs_tcp_client_connect(&client, &url, secure, buf, sizeof(buf))) {
				continue;
			}
			if (!my_imap_client_login(&client, &url, imap)) {
				imap_client_list(&client, prefix, fp2);
			}
			bbs_tcp_client_cleanup(&client);
		}
		fclose(fp);
	}

	/* At this point, we should be able to send whatever is in the cache */

	rewind(fp2); /* Rewind cache to the beginning, in case we just wrote it */

	UNUSED(listscandir);
	UNUSED(ns);

	while ((fgets(line, sizeof(line), fp2))) {
		char relativepath[256];
		char remotedelim;
		char *tmp, *virtmboxname = relativepath;

		/* Extract the user facing mailbox path from the LIST response in the cache file */
		bbs_strterm(line, '\n'); /* Strip trailing LF */
		safe_strncpy(relativepath, line, sizeof(relativepath));
		if (skipn_noparen(&virtmboxname, ' ', 2) != 2) {
			bbs_warning("Invalid LIST response: %s\n", line); /* Garbage in the cache file */
			continue;
		}
		STRIP_QUOTES(virtmboxname);

		/* Check if it matches the LIST filters */
		if (strncmp(virtmboxname, reference, reflen)) {
			bbs_debug(8, "Virtual mailbox '%s' doesn't match reference %s\n", virtmboxname, reference);
			continue;
		}
		if (ns == NAMESPACE_OTHER) { /* XXX This seems fragile */
			virtmboxname += STRLEN(OTHER_NAMESPACE_PREFIX);
		}
		if (!list_match(virtmboxname, mailbox + skiplen)) {
			bbs_debug(8, "Virtual mailbox '%s' does not match list %s\n", virtmboxname, mailbox + skiplen);
			continue;
		}

		/* Skip "virtual folders" that people don't really want, since they duplicate other folders,
		 * in case they're not actually disabled for IMAP access online.
		 * That way the client doesn't even have a chance to learn they exist,
		 * in case it's not configured to ignore those / not synchronize them.
		 */
		tmp = strstr(virtmboxname, "[Gmail]/");
		if (tmp) {
			const char *rest = tmp + STRLEN("[Gmail]/");
			if (!strcmp(rest, "All Mail") || !strcmp(rest, "Important") || !strcmp(rest, "Starred")) {
				bbs_debug(5, "Omitting unwanted folder '%s' from listing\n", virtmboxname);
				continue;
			}
		}

		/* Matches prefix, send it */
		if (specialuse && !strstr(line, "\\")) {
			/* If it's a special use mailbox, there should be a backslash present, somewhere */
			continue;
		}
		/* If the remote server's hierarchy delimiter differs from ours,
		 * then we need to use our hierarchy delimiter locally,
		 * but translate when sending commands to the remote server.
		 *
		 * e.g. something like:
		 * (\NoSelect) "/" "Other Users.gmail.[Gmail]/Something"
		 *
		 * The first part uses our hierarchy delimiter, and the remote part could be different.
		 * Change "/" to "." (our delimiter) in the response to the client,
		 * and replace the remote's delimiter with ours wherever it appears
		 *
		 * So the above might transform to:
		 * (\NoSelect) "." "Other Users.gmail.[Gmail].Something"
		 *
		 * The great thing here is we don't need to recreate the string.
		 * We're replacing one character with another, so we can
		 * do the replacement in place.
		 */
		tmp = line;
		/* This must succeed since we did at least this much above.
		 * And you might think, this is a bit silly, why not use strsep?
		 * Ah, but strsep splits the string up, which we don't want to do. */
		skipn_noparen(&tmp, ' ', 1);
		tmp++; /* Skip opening quote */
		remotedelim = *tmp;
		*tmp = HIERARCHY_DELIMITER_CHAR;
		skipn_noparen(&tmp, ' ', 1);
		tmp++; /* Skip opening quote */
		tmp += skiplen; /* Skip our prefix to the remote */
		/* Now, do replacements where needed on the remote name */
		while (*tmp) {
			if (*tmp == remotedelim) {
				*tmp = HIERARCHY_DELIMITER_CHAR;
			}
			tmp++;
		}

		imap_send(imap, "%s %s", cmd, line);
	}
	fclose(fp2);

	pthread_mutex_unlock(&virt_lock);
	return 0;
}

static int handle_list(struct imap_session *imap, char *s, int lsub)
{
	char *reference, *mailbox;
	int reflen;
	char attributes[128];
	const char *listscandir;
	enum mailbox_namespace ns;
	int skiplen = 0;
	int specialuse = 0;
	const char *cmd = lsub == 2 ? "XLIST" : lsub ? "LSUB" : "LIST";
	int xlistflags = 0;

	reference = strsep(&s, " ");
	mailbox = s; /* Can contain spaces, so don't use strsep first */
	REQUIRE_ARGS(reference);
	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s);

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
	 * \Marked - contains messages added since last time mailbox was selected.
	 * \Unmarked - does not contain additional messages since last select.
	 *
	 * RFC 6154 SPECIAL-USE attributes (not always explicitly advertised, but this supersedes the deprecated XLIST)
	 * \All
	 * \Archive
	 * \Drafts
	 * \Flagged
	 * \Junk
	 * \Sent
	 * \Trash
	 *
	 * The XLIST command is not formally specified anywhere but basically seems to be the same thing
	 * as RFC 6154, except returning XLIST instead of LIST (obviously), and with an \Inbox attribute for the INBOX.
	 * Google says that XLIST attributes are NOT exactly the same:
	 * https://developers.google.com/gmail/imap/imap-extensions#xlist_is_deprecated
	 * Even though XLIST is deprecated, it is still needed as some clients (e.g. some versions of Microsoft Outlook)
	 * support XLIST but not SPECIAL-USE.
	 */

	/*! \todo Add support for displaying Marked and Unmarked */

	/* SPECIAL-USE specific: */
	if (!strlen_zero(s) && !strcasecmp(s, "RETURN (SPECIAL-USE)")) {
		specialuse = 1;
	}

	/* XLIST also returns \Inbox for INBOX: */
	if (lsub == 2) {
		xlistflags = DIR_INBOX;
	}

	/* A detailed reading and reading of the RFC (e.g. RFC 3501) is very handy for understanding the LIST command in its entirety. */
	if (!specialuse && strlen_zero(mailbox)) {
		/* Just return hierarchy delimiter and root name of reference */
		/* When testing other servers, the reference argument doesn't even seem to matter, I always get something like this: */
		imap_send(imap, "%s (%s %s) \"%s\" %s", cmd, ATTR_NOSELECT, ATTR_HAS_CHILDREN, HIERARCHY_DELIMITER, EMPTY_QUOTES);
		imap_reply(imap, "OK %s completed.", cmd);
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
	if (!specialuse && strlen_zero(reference) && (strlen_zero(mailbox) || !strcmp(mailbox, "*") || !strcmp(mailbox, "%"))) {
		/* Include INBOX first before doing the rest */
		build_attributes_string(attributes, sizeof(attributes), DIR_NO_CHILDREN | xlistflags);
		imap_send(imap, "%s (%s) \"%s\" \"%s\"", cmd, attributes, HIERARCHY_DELIMITER, "INBOX");
	} else if (!specialuse && !strcmp(mailbox, "INBOX")) {
		build_attributes_string(attributes, sizeof(attributes), DIR_NO_CHILDREN | xlistflags);
		imap_send(imap, "%s (%s) \"%s\" \"%s\"", cmd, attributes, HIERARCHY_DELIMITER, "INBOX");
		/* This was just for INBOX, so nothing else can possibly match. */
		/* XXX Again, the special handling of this feels clunky here */
		imap_reply(imap, "OK %s completed.", cmd);
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
	list_scandir(imap, listscandir, lsub, specialuse, 0, ns, attributes, sizeof(attributes), reference, NULL, mailbox, reflen, skiplen); /* Recursively LIST */
	list_virtual(imap, listscandir, lsub, specialuse, ns, reference, mailbox, reflen, skiplen);

	imap_reply(imap, "OK %s completed.", cmd);
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
	unsigned long changedsince;
	unsigned int envelope:1;
	unsigned int body:1;
	unsigned int bodystructure:1;
	unsigned int internaldate:1;
	unsigned int rfc822:1;
	unsigned int rfc822header:1;
	unsigned int rfc822size:1;
	unsigned int rfc822text:1;
	unsigned int uid:1;
	unsigned int modseq:1;
	unsigned int vanished:1;
};

/*! \note Direct use of this function is more efficient than in_range since we can reuse the same allocated buffer for all comparisons */
static int in_range_allocated(const char *s, int num, char *sequences)
{
	char *sequence;

	strcpy(sequences, s); /* This is safe, as it is assumed that sequences itself was strdup'd or malloc'd from s / strlen(s) + 1 previously */

	/*! \todo since atoi would stop on a , anyways, strsep isn't really necessary.
	 * We could parse the string in place, avoiding the need to allocate and copy in the first place. */

	while ((sequence = strsep(&sequences, ","))) {
		int min, max;
		char *begin = strsep(&sequence, ":");
		if (strlen_zero(begin)) {
			bbs_warning("Malformed range: %s\n", s);
			continue;
		}
		if (!strcmp(begin, "*")) {
			/* Something like just *, everything matches */
			return 1;
		}
		min = atoi(begin);
		if (num < min) {
			continue;
		}
		if (sequence) {
			if (!strcmp(sequence, "*")) { /* Something like 1:* */
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

/*! \note This is re-evaluated for every single message in the folder, which is not terribly efficient. Prefer using in_range_allocated directly. */
static int in_range(const char *s, int num)
{
	int res = 0;
	char *dup;

	dup = strdup(s);
	if (ALLOC_FAILURE(dup)) {
		return 0;
	}

	res = in_range_allocated(s, num, dup);

	free(dup);
	return res;
}

static int imap_in_range(struct imap_session *imap, const char *s, int num)
{
	if (!strcmp(s, "$")) {
		int res = 0;
		/* The caller already accounts for savedsearchuid (don't need to, and can't, do that here) */
		pthread_mutex_lock(&imap->lock); /* Lock the session to prevent somebody from freeing the savedsearch from under us */
		if (!imap->savedsearch) {
			bbs_warning("No saved search available\n");
		} else {
			res = in_range(imap->savedsearch, num);
		}
		pthread_mutex_unlock(&imap->lock);
		return res;
	}

	return in_range(s, num);
}

static int test_sequence_in_range(void)
{
	bbs_test_assert_equals(1, in_range("2:3,6", 2));
	bbs_test_assert_equals(1, in_range("2:3,6", 3));
	bbs_test_assert_equals(1, in_range("2:3,6", 6));
	bbs_test_assert_equals(0, in_range("2:3,6", 4));
	bbs_test_assert_equals(1, in_range("2:3,6,7:9", 8));
	bbs_test_assert_equals(1, in_range("1:*", 8));
	bbs_test_assert_equals(1, in_range("*", 13));
	bbs_test_assert_equals(1, in_range("1", 1));
	return 0;

cleanup:
	return -1;
}

/*! \retval 0 if not in range, UID if in range */
static int msg_in_range(int seqno, const char *filename, const char *sequences, int usinguid)
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
	if (maildir_parse_uid_from_filename(filename, &msguid)) {
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

static int imap_msg_in_range(struct imap_session *imap, int seqno, const char *filename, const char *sequences, int usinguid, int *error)
{
	int res, use_saved_search = !strcmp(sequences, "$") ? 1 : 0;

	if (use_saved_search) {
		if (!imap->savedsearch) {
			bbs_warning("Client referred to nonexistent saved search\n");
			*error = 1;
			return 0;
		}
		pthread_mutex_lock(&imap->lock); /* Prevent saved search from disappearing underneath us while we're using it */
		if (strlen_zero(imap->savedsearch)) {
			/* Empty string means nothing matches */
			pthread_mutex_unlock(&imap->lock);
			return 0;
		}
		sequences = imap->savedsearch;
		usinguid = imap->savedsearchuid; /* So that we're consistent with what the saved search actually refers to. */
	}

	res = msg_in_range(seqno, filename, sequences, usinguid);

	if (use_saved_search) {
		pthread_mutex_unlock(&imap->lock);
	}
	return res;
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
			unsigned int *newa;
			int newallocsize = *allocsizes += UINTLIST_CHUNK_SIZE; /* Don't multiply by sizeof(unsigned int), so we can directly compare with lengths */
			newa = realloc(*a, newallocsize * sizeof(unsigned int)); /* Increase by 32 each chunk */
			if (ALLOC_FAILURE(newa)) {
				return -1;
			}
			*a = newa;
			*allocsizes = newallocsize;
		}
	}

	curlen = *lengths;
#ifdef DEBUG_UINTLIST
	bbs_debug(10, "Writing to index %d/%d\n", curlen, *allocsizes);
#endif
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
			unsigned int *newb, *newa;
			int newallocsize = *allocsizes += UINTLIST_CHUNK_SIZE; /* Don't multiply by sizeof(unsigned int), so we can directly compare with lengths */
			newa = realloc(*a, newallocsize * sizeof(unsigned int)); /* Increase by 32 each chunk */
			if (ALLOC_FAILURE(newa)) {
				return -1;
			}
			newb = realloc(*b, *allocsizes + UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
			if (ALLOC_FAILURE(newb)) {
				/* This is tricky. We expanded a but failed to expand b. Keep the smaller size for our records. */
				return -1;
			}
			*allocsizes = newallocsize;
			*a = newa;
			*b = newb;
		}
	}

	curlen = *lengths;
#ifdef DEBUG_UINTLIST
	bbs_debug(10, "Writing to index %d/%d\n", curlen, *allocsizes);
#endif
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
	long quotaleft;
	int destacl;
	int error = 0;
	char newfile[256];

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

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		unsigned int msguid;
		struct stat st;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		msguid = imap_msg_in_range(imap, ++seqno, entry->d_name, sequences, usinguid, &error);
		if (!msguid) {
			continue;
		}

		snprintf(srcfile, sizeof(srcfile), "%s/%s", imap->curdir, entry->d_name);
		if (stat(srcfile, &st)) {
			bbs_error("stat(%s) failed: %s\n", srcfile, strerror(errno));
		} else {
			quotaleft -= st.st_size; /* Determine if we would be about to exceed our current quota. */
			if (quotaleft <= 0) {
				bbs_verb(5, "Mailbox %d has insufficient quota remaining for COPY operation\n", mailbox_id(imap->mbox));
				break; /* Insufficient quota remaining */
			}
		}
		uidres = maildir_copy_msg_filename(imap->mbox, srcfile, entry->d_name, newboxdir, &uidvalidity, &uidnext, newfile, sizeof(newfile));
		if (!uidres) {
			continue;
		}
		translate_maildir_flags(imap, imap->dir, newfile, entry->d_name, newboxdir, destacl);
		if (!uintlist_append2(&olduids, &newuids, &lengths, &allocsizes, msguid, uidres)) {
			numcopies++;
		}
	}
	free_scandir_entries(entries, files);
	free(entries);
	/* UIDVALIDITY of dest mailbox, src UIDs, dest UIDs (in same order as src messages) */
	if (olduids || newuids) {
		olduidstr = gen_uintlist(olduids, lengths);
		newuidstr = gen_uintlist(newuids, lengths);
		free_if(olduids);
		free_if(newuids);
	}
	if (error) {
		imap_reply(imap, "BAD Invalid saved search");
	} else if (!numcopies && quotaleft <= 0) {
		imap_reply(imap, "NO [OVERQUOTA] Insufficient quota remaining");
	} else {
		imap_reply(imap, "OK [COPYUID %u %s %s] COPY completed", uidvalidity, S_IF(olduidstr), S_IF(newuidstr));
	}
	free_if(olduidstr);
	free_if(newuidstr);
	return 0;
}

/*! \brief Basically a simpler version of handle_copy, with some expunging responses */
static int handle_move(struct imap_session *imap, char *s, int usinguid)
{
	struct dirent *entry, **entries;
	char *sequences, *newbox;
	char newboxdir[256];
	char srcfile[516];
	int files, fno = 0;
	int seqno = 0;
	unsigned int *olduids = NULL, *newuids = NULL, *expunged = NULL, *expungedseqs = NULL;
	int lengths = 0, allocsizes = 0;
	int exp_lengths = 0, exp_allocsizes = 0;
	unsigned int uidvalidity, uidnext, uidres;
	char *olduidstr = NULL, *newuidstr = NULL;
	int destacl;
	int error = 0;
	char newname[256];

	sequences = strsep(&s, " "); /* Messages, specified by sequence number or by UID (if usinguid) */
	REQUIRE_ARGS(sequences);
	SHIFT_OPTIONALLY_QUOTED_ARG(newbox, s);

	/* We'll be moving into the cur directory. Don't specify here, maildir_move_msg_filename tacks on the /cur implicitly. */
	if (imap_translate_dir(imap, newbox, newboxdir, sizeof(newboxdir), &destacl)) { /* Destination directory doesn't exist. */
		imap_reply(imap, "NO [TRYCREATE] No such mailbox");
		return 0;
	}

	IMAP_REQUIRE_ACL(imap->acl, IMAP_ACL_EXPUNGE);
	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_INSERT); /* Must be able to copy to dest dir and expunge from current dir */

	/* Since an implicit EXPUNGE is done from the current directory, we must lock the mailbox to avoid confusing POP3 clients. */
	MAILBOX_TRYRDLOCK(imap);

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		unsigned int msguid;
		unsigned long modseq;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}
		msguid = imap_msg_in_range(imap, ++seqno, entry->d_name, sequences, usinguid, &error);
		if (!msguid) {
			goto cleanup;
		}

		snprintf(srcfile, sizeof(srcfile), "%s/%s", imap->curdir, entry->d_name);
		uidres = maildir_move_msg_filename(imap->mbox, srcfile, entry->d_name, newboxdir, &uidvalidity, &uidnext, newname, sizeof(newname));
		if (!uidres) {
			goto cleanup;
		}
		/* maildir_move_msg_filename may rename the base filename, but it won't modify the flags, just the UID, so we can use the old basename for the purposes of flags. */
		translate_maildir_flags(imap, imap->dir, newname, entry->d_name, newboxdir, destacl);
		parse_modseq_from_filename(entry->d_name, &modseq);
		uintlist_append2(&olduids, &newuids, &lengths, &allocsizes, msguid, uidres);
		/* Thankfully, we are allowed to send the EXPUNGEs before the tagged response, or this would be more complicated as we would have to store a bunch of stuff temporarily.
		 * RFC 6851 3.3
		 * We still store UIDs so we can call maildir_indicate_expunged with a batch of all UIDs, for efficiency.
		 */
		uintlist_append2(&expunged, &expungedseqs, &exp_lengths, &exp_allocsizes, msguid, seqno); /* store UID and seqno */
		
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
	if (error) {
		imap_reply(imap, "BAD Invalid saved search");
	} else {
		imap_reply(imap, "OK [COPYUID %u %s %s] COPY completed", uidvalidity, S_IF(olduidstr), S_IF(newuidstr));
	}

	/* EXPUNGE untagged responses are sent in realtime (already done), just update HIGHESTMODSEQ now */
	imap->highestmodseq = maildir_indicate_expunged(imap->mbox, imap->curdir, expunged, exp_lengths);
	send_untagged_expunge(imap, 0, expunged, expungedseqs, exp_lengths);

	mailbox_unlock(imap->mbox);

	free_if(olduidstr);
	free_if(newuidstr);
	free_if(expunged);
	free_if(expungedseqs);
	return 0;
}

static int handle_append(struct imap_session *imap, char *s)
{
	int appendsize;
	char *mailbox, *flags, *size;
	unsigned long quotaleft;
	int destacl;

	/* Format is mailbox [flags] [date] message literal
	 * The message literal begins with {size} on the same line
	 * See also RFC 3502. */

	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s);
	size = strchr(s, '{');
	if (!size) {
		imap_reply(imap, "NO [CLIENTBUG] Missing message literal size");
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
		char *date;
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
		imap_reply(imap, "NO [CLIENTBUG] Invalid message literal size");
		return 0;
	} else if (appendsize >= MAX_APPEND_SIZE) {
		imap_reply(imap, "NO [LIMIT] Message too large"); /* [TOOBIG] could also be appropriate */
		return 0;
	} else if ((unsigned long) appendsize >= quotaleft) {
		imap_reply(imap, "NO [OVERQUOTA] Insufficient quota remaining");
		return 0;
	}

	_imap_reply(imap, "+ Ready for literal data\r\n"); /* Synchronizing literal response */
	imap->appendsize = appendsize; /* Bytes we expect to receive */
	imap->appendcur = 0; /* Bytes received so far */
	imap->appendfile = maildir_mktemp(imap->appenddir, imap->appendtmp, sizeof(imap->appendtmp), imap->appendnew);
	if (imap->appendfile < 0) {
		return -1;
	}
	return 0;
}

/*! \brief base filename The file name of the message file. Please do not provide the full filepath. */
static void generate_flag_names_full(struct imap_session *imap, const char *filename, char *bufstart, char **bufptr, int *lenptr)
{
	char flagsbuf[256] = "";
	int has_flags;
	int custom_keywords;

	char *buf = *bufptr;
	size_t len = *lenptr;

	if (isdigit(*filename)) { /* We have an entire filename */
		filename = strchr(filename, ':'); /* Skip everything before the flags, so we don't e.g. interpret ,S= as the Seen flag. */
		if (!filename) {
			filename = ""; /* There ain't no flags here */
		}
	} /* else, must just have the "flags" portion of the filename to begin with */

	gen_flag_names(filename, flagsbuf, sizeof(flagsbuf));
	has_flags = flagsbuf[0] ? 1 : 0;
	SAFE_FAST_COND_APPEND(bufstart, buf, len, 1, "FLAGS (%s", flagsbuf);
	/* If there are any keywords (custom flags), include those as well */
	custom_keywords = gen_keyword_names(imap, filename, flagsbuf, sizeof(flagsbuf));
	if (has_flags) {
		SAFE_FAST_COND_APPEND_NOSPACE(bufstart, buf, len, custom_keywords > 0, "%s", flagsbuf);
	} else {
		/* No leading space if there were no other flags, would be more elegantly if everything just appended to the same buffer using _NOSPACE */
		SAFE_FAST_COND_APPEND_NOSPACE(bufstart, buf, len, custom_keywords > 0, "%s", flagsbuf + 1); /* flagsbuf + 1 is safe since custom_keywords > 0 */
	}
	SAFE_FAST_COND_APPEND_NOSPACE(bufstart, buf, len, 1, ")");

	*bufptr = buf;
	*lenptr = len;
}

static int maildir_msg_setflags_modseq(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters, unsigned long *newmodseq)
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
	generate_flag_names_full(imap, newflagletters, newflags, &newbuf, &newlen);
	if (seqno) { /* Skip for merely translating flag mappings between maildirs */
		unsigned int uid;
		maildir_parse_uid_from_filename(filename, &uid);
		send_untagged_fetch(imap, seqno, uid, modseq, newflags);
	}
	return 0;
}

static int maildir_msg_setflags(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters)
{
	return maildir_msg_setflags_modseq(imap, seqno, origname, newflagletters, NULL);
}

static int maildir_msg_setflags_notify(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters)
{
	unsigned long newmodseq; /* newmodseq will be non NULL, so we'll know that we need to send out the FETCH accordingly */
	return maildir_msg_setflags_modseq(imap, seqno, origname, newflagletters, &newmodseq);
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
		/* Note: Trojita (which seems to be quite broken, but is the only client AFAIK that supports BURL, for testing)
		 * sends 2 bytes more than we expect, so if those last 2 are CR LF, can safely ignore this. */
		bbs_warning("Client wanted to append %d bytes, but sent %d?\n", imap->appendsize, imap->appendcur);
	}
	imap->appendsize = 0; /* APPEND is over now */
	close_if(imap->appendfile);
	filename = strrchr(imap->appendnew, '/');
	if (!filename) {
		bbs_error("Invalid filename: %s\n", imap->appendnew);
		imap_reply(imap, "NO [SERVERBUG] Append failed");
		return 0;
	}
	filename++; /* Just the base name now */
	if (rename(imap->appendtmp, imap->appendnew)) {
		bbs_error("rename %s -> %s failed: %s\n", imap->appendtmp, imap->appendnew, strerror(errno));
		imap_reply(imap, "NO [SERVERBUG] Append failed");
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
		imap_reply(imap, "NO [SERVERBUG] Append failed");
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
		int seqno;
		char newflagletters[53];
		/* Generate flag letters from flag bits */
		gen_flag_letters(imap->appendflags, newflagletters, sizeof(newflagletters));
		if (imap->numappendkeywords) {
			strncat(newflagletters, imap->appendkeywords, sizeof(newflagletters) - 1);
		}
		imap->appendflags = 0;
		seqno = num_messages(newdir) + num_messages(curdir); /* XXX Clunky, but compute the sequence number of this message as the # of messages in this mailbox */
		if (maildir_msg_setflags(imap, seqno, newfilename, newflagletters)) {
			bbs_warning("Failed to set flags for %s\n", newfilename);
		}
	}

	/* Set the internal date? Maybe not, since the original date of the message should be preserved for best user experience. */
	/*! \todo Set the file creation/modified time (strptime)? (If we do this, it shouldn't be a value returned to the client later, see note above) */
	UNUSED(imap->appenddate);

	/* APPENDUID response */
	/* Use tag from APPEND request */
	_imap_reply(imap, "%s OK [APPENDUID %u %u] APPEND completed\r\n", imap->savedtag, uidvalidity, uidnext); /* Don't add 1, this is the current message UID, not UIDNEXT */
	/*! \todo BUGBUG If mailbox currently selected, we SHOULD send an untagged EXISTS e.g. send_untagged_exists
	 * Even if not, we should for that particular mailbox (folder) for other clients that may be monitoring it. */
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
	int error = 0;

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}

	if (fetchreq->vanished) { /* First, send any VANISHED responses if needed */
		char *uidrangebuf = malloc(strlen(sequences) + 1);
		if (uidrangebuf) {
			/* Since VANISHED is only with UID FETCH, the sequences are in fact UID sequences, perfect! */
			maildir_get_expunged_since_modseq(imap, imap->curdir, fetchreq->changedsince, uidrangebuf, 0, sequences);
			free(uidrangebuf);
		}
	}

	while (fno < files && (entry = entries[fno++])) {
		unsigned int msguid;
		unsigned long modseq = 0;
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
		msguid = imap_msg_in_range(imap, ++seqno, entry->d_name, sequences, usinguid, &error);
		if (!msguid) {
			goto cleanup;
		}
		if (fetchreq->changedsince) {
			if (parse_modseq_from_filename(entry->d_name, &modseq)) {
				goto cleanup;
			}
			if (modseq <= fetchreq->changedsince) {
#ifdef EXTRA_DEBUG
				bbs_debug(5, "modseq %lu older than CHANGEDSINCE %lu\n", modseq, fetchreq->changedsince);
#endif
				goto cleanup; /* Older than specified CHANGEDSINCE */
			}
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
			char inflags[53];

			flags = strchr(entry->d_name, ':'); /* maildir flags */
			if (!flags) {
				bbs_error("Message file %s contains no flags?\n", entry->d_name);
				goto cleanup;
			}
			if (markseen && !strchr(flags, FLAG_SEEN)) {
				/* FYI, clients like Thunderbird do not use this: they PEEK the body and then explicitly STORE the Seen flag */
				inflags[0] = FLAG_SEEN;
				inflags[1] = '\0';
				safe_strncpy(inflags + 1, flags, sizeof(inflags) - 1);
				flags = inflags;
				bbs_debug(6, "Appending seen flag since message wasn't already seen\n");
			}
			generate_flag_names_full(imap, flags, response, &buf, &len);
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
		if (fetchreq->modseq) {
			if (!modseq) {
				/* If we didn't already compute this, do it now */
				parse_modseq_from_filename(entry->d_name, &modseq);
			}
			SAFE_FAST_COND_APPEND(response, buf, len, 1, "MODSEQ %lu", modseq);
		}
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
					if (!strcmp(linebuf, "\r\n") || !strcmp(linebuf, "\n")) { /* Some messages include only a LF at end of headers? */
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
				maildir_msg_setflags_notify(imap, seqno, fullname, newflagletters);
			}
		}

cleanup:
		free(entry);
	}
	free(entries);
	if (error) {
		imap_reply(imap, "BAD Invalid saved search");
	} else {
		imap_reply(imap, "OK %sFETCH Completed", usinguid ? "UID " : "");
	}
	return 0;
}

/*! \brief strsep-like tokenizer that returns the contents of the next substring inside parentheses (handling nested parentheses) */
static char *parensep(char **str)
{
	char *ret, *s = *str;
	int count = 0;

	if (strlen_zero(s)) {
		return NULL;
	}

	if (*s != '(') {
		if (*s == ' ') {
			s++;
		}
		if (*s != '(') {
			bbs_warning("parensep used incorrectly: %s\n", *str);
		}
	}

	while (*s) {
		if (*s == '(') {
			count++;
		} else if (*s == ')') {
			count--;
			if (count == 0) {
				*s++ = '\0';
				ret = *str + 1;
				if (*s == ' ') {
					s++;
				}
				*str = s;
				return ret;
			}
		}
		s++;
	}
	return NULL;
}

static int test_parensep(void)
{
	char buf[256];
	char *s, *left;

	strcpy(buf, "(1 (2))");
	left = buf;
	s = parensep(&left);
	bbs_test_assert_str_equals(s, "1 (2)");

	strcpy(buf, "(1 2 3) 4 5");
	left = buf;
	s = parensep(&left);
	bbs_test_assert_str_equals(s, "1 2 3");
	bbs_test_assert_str_equals(left, "4 5");

	strcpy(buf, "() \".\" \"Archive\"");
	left = buf;
	s = parensep(&left);
	bbs_test_assert_str_equals(s, "");
	bbs_test_assert_str_equals(left, "\".\" \"Archive\"");

	return 0;

cleanup:
	return -1;
}

/*! \brief Retrieve data associated with a message */
static int handle_fetch(struct imap_session *imap, char *s, int usinguid)
{
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

	/* Remove the surrounding parentheses for parsing */
	/* Because of CONDSTORE, multiple parenthesized arguments are supported,
	 * e.g. s100 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 12345)
	 * So the correct way to parse here should be to count the ( and ), adding +1 and -1 respectively,
	 * until we get back to 0, and then stop.
	 */
	items = parensep(&s);

	memset(&fetchreq, 0, sizeof(fetchreq));

	if (!strlen_zero(s)) {
		/* Another parenthesized list? (Probably CHANGEDSINCE, nothing else is supported) */
		char *arg;
		s = parensep(&s);
		while ((arg = strsep(&s, " "))) {
			if (!strcasecmp(arg, "CHANGEDSINCE")) {
				arg = strsep(&s,  " ");
				REQUIRE_ARGS(arg);
				fetchreq.changedsince = atol(arg);
				fetchreq.modseq = 1; /* RFC 7162 3.1.4.1: CHANGEDSINCE implicitly sets MODSEQ FETCH message data item */
				imap->condstore = 1;
			} else if (!strcasecmp(arg, "VANISHED")) {
				fetchreq.vanished = 1;
			} else {
				bbs_warning("Unexpected FETCH modifier: %s\n", s);
				imap_reply(imap, "BAD FETCH failed. Illegal arguments.");
				return 0;
			}
		}
		/* RFC 7162 3.2.6 */
		if (fetchreq.vanished) {
			if (!usinguid) {
				imap_reply(imap, "BAD Must use UID FETCH, not FETCH");
				return 0;
			} else if (!imap->qresync) {
				imap_reply(imap, "BAD Must enabled QRESYNC first");
				return 0;
			} else if (!fetchreq.changedsince) {
				imap_reply(imap, "BAD Must use in conjunction with CHANGEDSINCE");
				return 0;
			}
		}
		
	}

	/* Only parse the request once. */
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
		} else if (!strcmp(item, "MODSEQ")) {
			fetchreq.modseq = 1;
		/* Special macros, defined in RFC 3501. They must only be used by themselves, which makes their usage easy for us. Just expand them. */
		} else if (!strcmp(item, "ALL")) { /* FLAGS INTERNALDATE RFC822.SIZE ENVELOPE */
			fetchreq.flags = item;
			fetchreq.internaldate = 1;
			fetchreq.rfc822size = 1;
			fetchreq.envelope = 1;
			break;
		} else if (!strcmp(item, "FAST")) { /* FLAGS INTERNALDATE RFC822.SIZE */
			fetchreq.flags = item;
			fetchreq.internaldate = 1;
			fetchreq.rfc822size = 1;
			break;
		} else if (!strcmp(item, "FULL")) { /* FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY */
			fetchreq.flags = item;
			fetchreq.internaldate = 1;
			fetchreq.rfc822size = 1;
			fetchreq.envelope = 1;
			fetchreq.body = 1;
			break;
		} else {
			bbs_warning("Unsupported FETCH item: %s\n", item);
			imap_reply(imap, "BAD FETCH failed. Illegal arguments.");
			return 0;
		}
	}

	/* Process the request, for each message that matches sequence number. */
	return process_fetch(imap, usinguid, &fetchreq, sequences);
}

/*! \brief Modify the flags for a message */
static int process_flags(struct imap_session *imap, char *s, int usinguid, const char *sequences, int flagop, int silent, int do_unchangedsince, unsigned long unchangedsince)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int seqno = 0;
	int opflags = 0;
	int oldflags, flagpermsdenied = 0;
	int error = 0;
	int matches = 0;
	int was_silent = silent;

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
	flagpermsdenied = restrict_flags(imap->acl, &opflags);
	if (!IMAP_HAS_ACL(imap->acl, IMAP_ACL_WRITE)) {
		imap->numappendkeywords = 0;
	}

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}

	if (do_unchangedsince) { /* CONDSTORE support using MODSEQ */
		struct dyn_str dynstr;
		char buf[25];
		int len = 0;
		/* Check that all the desired messages have a modseq <= unchangedsince */
		memset(&dynstr, 0, sizeof(dynstr));
		while (fno < files && (entry = entries[fno++])) {
			unsigned int msguid;
			unsigned long modseq;

			if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
				continue;
			}
			msguid = imap_msg_in_range(imap, ++seqno, entry->d_name, sequences, usinguid, &error);
			if (!msguid) {
				continue;
			}
			if (parse_modseq_from_filename(entry->d_name, &modseq)) {
				continue;
			}
			/* UNCHANGEDSINCE of 0 matches no message */
			if (!unchangedsince || modseq > unchangedsince) {
				/* It's not clear from the RFC if ranges are fine or if it strictly has to be a comma-separated list,
				 * since there are no examples of consecutive messages.
				 * So we just play it safe here and make a comma-separated list */
				len = snprintf(buf, sizeof(buf), ",%u", usinguid ? msguid : (unsigned int) seqno);
				dyn_str_append(&dynstr, buf, len);
			}
		}
		seqno = fno = 0;
		if (len) { /* Failed the UNCHANGEDSINCE test. At least one message had a newer modseq */
			/* Skip 1st char since it's a comma */
			imap_reply(imap, "OK [MODIFIED %s] Conditional STORE failed", dynstr.buf + 1); /* Dunno why we reply OK instead of NO, but that's what the RFC says... */
			free_if(dynstr.buf);
			goto done;
		}
		/* We're good to proceed. */
		silent = 0; /* RFC 7162 3.1.3: An untagged FETCH MUST be sent, including MODSEQ, even if .SILENT suffix is present */
	}

	while (fno < files && (entry = entries[fno++])) {
		unsigned int msguid;
		unsigned long newmodseq = 0;
		char newflagletters[53];
		char oldkeywords[27] = "";
		char newkeywords[27] = "";
		const char *keywords = newkeywords;
		int i;
		int newflags;
		int changes = 0;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		msguid = imap_msg_in_range(imap, ++seqno, entry->d_name, sequences, usinguid, &error);
		if (!msguid) {
			continue;
		}
		matches++;
		/* Get the message's current flags. */
		if (parse_flags_letters_from_filename(entry->d_name, &oldflags, oldkeywords)) {
			bbs_error("File %s is noncompliant with maildir\n", entry->d_name);
			continue;
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
			const char *c;
			char *newbuf = newkeywords;
			size_t newlen = sizeof(newkeywords);
			/* These are the keywords provided as input.
			 * oldkeywords contains the existing keywords. */
			if (flagop == 1) { /* If they're equal, we don't need to do anything */
				if (strcmp(imap->appendkeywords, oldkeywords)) {
					int oldlen = strlen(oldkeywords);
					bbs_debug(7, "Change made to keyword: %s -> %s\n", oldkeywords, imap->appendkeywords);
					/* Merge both of them: copy over any keywords that weren't in the old one. */
					strcpy(newkeywords, oldkeywords); /* Safe */
					c = imap->appendkeywords;
					newbuf = newkeywords + oldlen;
					newlen = sizeof(newkeywords) - oldlen;
					/* XXX This eliminates duplication, but ideally they should also be sorted alphabetically between the two (e.g. merge sort) */
					while (*c) {
						if (!strchr(oldkeywords, *c)) {
							SAFE_FAST_COND_APPEND_NOSPACE(newkeywords, newbuf, newlen, 1, "%c", *c);
							changes++;
						} else {
							bbs_debug(9, "Skipping existing flag %c\n", *c);
						}
						c++;
					}
				} else if (changes) {
					keywords = oldkeywords; /* If we're going to rename the file, make sure we preserve the flags it already had. If not, no point. */
				}
			} else if (flagop == -1) {
				c = oldkeywords;
				/* If the old flags contain any of the new flags, remove them, otherwise just copy over */
				/* Note that imap->appendkeywords is not necessarily ordered since they are as the client sent them */
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
			/* RFC 3501 6.4.6: We SHOULD send an untagged FETCH when flags change from an external source (not us). This handles that: */
			if (maildir_msg_setflags_modseq(imap, seqno, oldname, newflagletters, &newmodseq)) {
				continue;
			}
		} else {
			imap_debug(5, "No changes in flags for message %s/%s\n", imap->curdir, entry->d_name);
			if (flagpermsdenied) {
				/* STORE "SHOULD NOT" fail if user has rights to modify at least one flag.
				 * If we got here, this means user didn't have permissions to set any flags.
				 * We can break out of the loop at this point, because if ACLs failed for one message,
				 * they will always fail (ACLs are per mailbox, not per message).
				 */
				imap_reply(imap, "NO [NOPERM] Permission denied");
				goto done;
			}
		}

		/* Send the response if not silent */
		if (changes && !silent) {
			char flagstr[256];
			gen_flag_names(newflagletters, flagstr, sizeof(flagstr));
			if (keywords[0]) { /* Current keywords */
				int slen = strlen(flagstr);
				/*! \todo We should not append a space before if we're at the beginning of the buffer */
				gen_keyword_names(imap, keywords, flagstr + slen, sizeof(flagstr) - slen); /* Append keywords (include space before) */
			}

			if (imap->createdkeyword) {
				/* Server SHOULD send untagged response when a new keyword is created */
				char allkeywords[256] = "";
				gen_keyword_names(imap, NULL, allkeywords, sizeof(allkeywords)); /* prepends a space before all of them, so this works out great */
				imap_send(imap, "FLAGS (%s%s)", IMAP_FLAGS, allkeywords);
			}
			/*! \todo This is repetitive, clean this up so we're not duplicating this log for UID/no UID, MODSEQ/no MODSEQ, silent/not silent */
			if (do_unchangedsince) {
				if (!newmodseq) {
					bbs_error("No MODSEQ for message %s?\n", entry->d_name); /* Old filename at this point, but should be good enough to identify it */
				}
				if (usinguid) {
					if (was_silent) {
						imap_send(imap, "%d FETCH (UID %u MODSEQ (%lu))", seqno, msguid, newmodseq);
					} else {
						imap_send(imap, "%d FETCH (UID %u MODSEQ (%lu) FLAGS (%s))", seqno, msguid, newmodseq, flagstr);
					}
				} else {
					if (was_silent) {
						imap_send(imap, "%d FETCH (MODSEQ (%lu))", seqno, newmodseq);
					} else {
						imap_send(imap, "%d FETCH (MODSEQ (%lu) FLAGS (%s))", seqno, newmodseq, flagstr);
					}
				}
			} else {
				if (usinguid) {
					imap_send(imap, "%d FETCH (UID %u FLAGS (%s))", seqno, msguid, flagstr);
				} else {
					imap_send(imap, "%d FETCH (FLAGS (%s))", seqno, flagstr);
				}
			}
		}
	}
	free_scandir_entries(entries, files);
	free(entries);

	if (!matches) {
		imap_reply(imap, "NO No messages in range");
	} else if (error) {
		imap_reply(imap, "BAD Invalid saved search");
	} else {
		imap_reply(imap, "OK %sSTORE Completed", usinguid ? "UID " : "");
	}
	return 0;

done:
	free_scandir_entries(entries, files);
	free(entries);
	return 0;
}

static int handle_store(struct imap_session *imap, char *s, int usinguid)
{
	char *sequences, *operation;
	int flagop;
	int silent;
	int do_unchangedsince = 0; /* Needed since unchangedsince is unsigned, and 0 is a valid value */
	unsigned long unchangedsince = 0;

	REQUIRE_ARGS(s);
	sequences = strsep(&s, " "); /* Sequence set, specified by sequence number or by UID (if usinguid) */
	REQUIRE_ARGS(s);

	if (*s == '(') {
		char *modifier, *tmp;
		modifier = s + 1;
		s = strchr(modifier, ')');
		REQUIRE_ARGS(s);
		*s++ = '\0';
		ltrim(s);
		tmp = strstr(modifier, "UNCHANGEDSINCE ");
		if (tmp) {
			tmp += STRLEN("UNCHANGEDSINCE ");
			if (!strlen_zero(tmp)) {
				unchangedsince = atol(tmp);
				do_unchangedsince = 1;
				imap->condstore = 1;
			}
		}
	}

	/* What remains are actual flags */
	operation = strsep(&s, " ");
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
		imap_reply(imap, "BAD [CLIENTBUG] Invalid arguments");
		return 0;
	}

	MAILBOX_TRYRDLOCK(imap);
	process_flags(imap, s, usinguid, sequences, flagop, silent, do_unchangedsince, unchangedsince);
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
		imap_reply(imap, "BAD [CANNOT] Invalid mailbox name");
		return 0;
	} else if (strchr(s, '/')) { /* Don't allow our real directory delimiter */
		imap_reply(imap, "BAD [CANNOT] Invalid mailbox name");
		return 0;
	} else if (IS_SPECIAL_NAME(s)) {
		/*! \todo We should allow this, maybe? (except for INBOX, obviously), if the appropriate attributes are going to be added */
		imap_reply(imap, "NO [CANNOT] Can't create mailbox with special name");
		return 0;
	}

	imap_translate_dir(imap, s, path, sizeof(path), &destacl); /* Don't care about return value, since it probably doesn't exist right now and that's fine. */
	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_MAILBOX_CREATE);
	bbs_debug(3, "IMAP client wants to create directory %s\n", path);
	if (!eaccess(path, R_OK)) {
		imap_reply(imap, "NO [ALREADYEXISTS] Mailbox already exists");
		return 0;
	}
	MAILBOX_TRYRDLOCK(imap);
	if (mkdir(path, 0700)) {
		bbs_error("mkdir(%s) failed: %s\n", path, strerror(errno));
		imap_reply(imap, "NO [SERVERBUG] Mailbox creation failed");
		mailbox_unlock(imap->mbox);
		return 0;
	}
	mailbox_unlock(imap->mbox);

	/* Don't initialize the maildir itself here, that can be done at some later point. */
	mailbox_quota_adjust_usage(imap->mbox, 4096);
	imap_reply(imap, "OK CREATE completed");
	return 0;
}

static int nftw_rm(const char *path, const struct stat *st, int flag, struct FTW *f)
{
	int res;

	UNUSED(st);
	UNUSED(f);

	if (flag == FTW_DP) { /* directory */
		res = rmdir(path);
	} else {
		res = unlink(path);
	}
	if (res) {
		bbs_error("Failed to remove %s: %s\n", path, strerror(errno));
	}
	return res;
}

static int recursive_rmdir(const char *path)
{
	/* can't use rmdir, since that's only good for empty directories.
	 * A maildir will NEVER be empty, so use nftw instead. */
	if (nftw(path, nftw_rm, 2, FTW_MOUNT | FTW_PHYS | FTW_DEPTH)) {
		bbs_error("nftw(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

static int handle_delete(struct imap_session *imap, char *s)
{
	char path[256];
	int destacl;

	REQUIRE_ARGS(s);
	STRIP_QUOTES(s);

	if (IS_SPECIAL_NAME(s)) {
		imap_reply(imap, "NO [CANNOT] Can't delete special mailbox");
		return 0;
	}

	if (imap_translate_dir(imap, s, path, sizeof(path), &destacl)) {
		imap_reply(imap, "NO [NONEXISTENT] No such mailbox with that name");
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
		imap_reply(imap, "NO Mailbox has inferior hierarchical names"); /* Not really a good response code we can use for this */
		return 0;
	}

	MAILBOX_TRYRDLOCK(imap);
	if (recursive_rmdir(path)) {
		mailbox_unlock(imap->mbox);
		imap_reply(imap, "NO [SERVERBUG] DELETE failed");
		return 0;
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
	files = scandir(path, &entries, NULL, uidsort);
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

	free_scandir_entries(entries, files);
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
	/* Mailbox names can have spaces */
	/*! \todo BUGBUG Technically all IMAP arguments can be in quotes, so we should always use SHIFT_OPTIONALLY_QUOTED_ARG instead of strsep(&s, " ") */
	SHIFT_OPTIONALLY_QUOTED_ARG(old, s);
	SHIFT_OPTIONALLY_QUOTED_ARG(new, s);
	REQUIRE_ARGS(old);
	REQUIRE_ARGS(new);
	STRIP_QUOTES(old);
	STRIP_QUOTES(new);

	/* Renaming INBOX is permitted by the RFC, technically, but it just moves its messages, which isn't really rename related. */
	if (IS_SPECIAL_NAME(old) || IS_SPECIAL_NAME(new)) {
		imap_reply(imap, "NO [CANNOT] Can't rename to/from that name");
		return 0;
	}

	if (imap_translate_dir(imap, old, oldpath, sizeof(oldpath), &srcacl)) {
		imap_reply(imap, "NO [NONEXISTENT] No such mailbox with that name");
		return 0;
	}
	imap_translate_dir(imap, new, newpath, sizeof(newpath), &destacl); /* Don't care about return value since if it already exists, we'll abort. */
	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_MAILBOX_CREATE);
	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_MAILBOX_DELETE);
	if (!eaccess(newpath, R_OK)) {
		imap_reply(imap, "NO [ALREADYEXISTS] Mailbox already exists");
		return 0;
	}

	/* Okay, for the reasons mentioned in handle_delete,
	 * this operation is truly ugly for maildir. */
	MAILBOX_TRYRDLOCK(imap);
	res = sub_rename(mailbox_maildir(imap->mbox), old, new); /* We're doing multiple renames, so to make them all atomic, surround with a RDLOCK. */
	if (!res) {
		if (rename(oldpath, newpath)) {
			bbs_error("rename %s -> %s failed: %s\n", oldpath, newpath, strerror(errno));
			imap_reply(imap, "NO [SERVERBUG] System error");
		} else {
			imap_reply(imap, "OK RENAME completed");
		}
	} else {
		imap_reply(imap, "NO [SERVERBUG] System error");
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
	IMAP_SEARCH_MODSEQ,
	IMAP_SEARCH_NEW,
	IMAP_SEARCH_NOT,
	IMAP_SEARCH_OLD,
	IMAP_SEARCH_OLDER,
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
	IMAP_SEARCH_YOUNGER,
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
		case IMAP_SEARCH_MODSEQ:
			return "MODSEQ";
		case IMAP_SEARCH_NEW:
			return "NEW";
		case IMAP_SEARCH_NOT:
			return "NOT";
		case IMAP_SEARCH_OLD:
			return "OLD";
		case IMAP_SEARCH_OLDER:
			return "OLDER";
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
		case IMAP_SEARCH_YOUNGER:
			return "YOUNGER";
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
		unsigned long longnumber;
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
	struct imap_search_key *skey;

	RWLIST_TRAVERSE(skeys, skey, entry) {
		/* Indent according to the recursion depth */
		size_t bytes = snprintf(buf, sizeof(buf), "=%%= %*.s %s -> ", 3 * depth, "", imap_search_key_name(skey->type));
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
			case IMAP_SEARCH_OLDER:
			case IMAP_SEARCH_YOUNGER:
				bytes = snprintf(buf, sizeof(buf), "%d\n", skey->child.number);
				dyn_str_append(str, buf, bytes);
				break;
			case IMAP_SEARCH_MODSEQ:
				bytes = snprintf(buf, sizeof(buf), "%lu\n", skey->child.longnumber);
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
			case IMAP_SEARCH_UID:
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

#define SEARCH_PARSE_LONG(name) \
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
		nk->child.longnumber = atol(next); \
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
			*s = NULL; \
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
		if (parse_search_query(imap, nk->child.keys, IMAP_SEARCH_ ## name, s)) { \
			return -1; \
		} \
	}

static int parse_search_query(struct imap_session *imap, struct imap_search_keys *skeys, enum imap_search_type parent_type, char **s)
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
			if (parse_search_query(imap, nk->child.keys, IMAP_SEARCH_AND, &subnext)) {
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
		SEARCH_PARSE_INT(OLDER)
		SEARCH_PARSE_INT(YOUNGER)
		/*! \todo BUGBUG RFC 7162 3.1.5 Technically can be something like MODSEQ "/flags/\\draft" all 620162338.
		 * We should ignore the extra info and just use the number since we don't store multiple modseqs per message,
		 * for different metadata, but currently we won't parse right if the extra stuff is present. */
		SEARCH_PARSE_LONG(MODSEQ)
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
		SEARCH_PARSE_STRING(UID)
		else if (isdigit(*next)) {
			/* sequence set */
			/* Not quoted, so thankfully this doesn't duplicate much code */
			nk = imap_search_add(skeys, IMAP_SEARCH_SEQUENCE_NUMBER_SET);
			if (!nk) {
				return -1;
			}
			nk->child.string = next;
			listsize++;
		} else if (!strcmp(next, "$")) { /* Saved search */
			nk = imap_search_add(skeys, imap->savedsearchuid ? IMAP_SEARCH_UID : IMAP_SEARCH_SEQUENCE_NUMBER_SET);
			if (!nk) {
				return -1;
			}
			nk->child.string = next; /* We store the literal '$' here, but this will get resolved in imap_in_range */
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
	int now;
	unsigned long maxmodseq;
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
	retval = (search->flags & flag) ? 1 : 0; \
	break;

#define SEARCH_FLAG_NOT_MATCH(flag) \
	retval = (search->flags & flag) ? 0 : 1; \
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
	unsigned long modseq;
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
					maildir_parse_uid_from_filename(search->filename, &uid);
					retval = imap_in_range(search->imap, skey->child.string, uid);
				} else {
					/* XXX messages in new don't have a UID, so by definition it can't match */
					retval = 0;
				}
				break;
			case IMAP_SEARCH_MODSEQ:
				if (!search->new) {
					parse_modseq_from_filename(search->filename, &modseq);
					retval = modseq >= skey->child.longnumber;
					search->maxmodseq = MAX(search->maxmodseq, modseq);
				} else {
					retval = 1; /* If it's new, by definition we don't know about it, so in the spirit of MODSEQ it should always match */
				}
				break;
			case IMAP_SEARCH_SEQUENCE_NUMBER_SET:
				retval = imap_in_range(search->imap, skey->child.string, search->seqno);
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
			case IMAP_SEARCH_UNKEYWORD:
			case IMAP_SEARCH_KEYWORD:
				/* This is not very efficient, since we reparse the keywords for every message, but the keyword mapping is the same for everything in this mailbox. */
				parse_keyword(search->imap, skey->child.string, search->imap->dir, 0);
				/* imap->appendkeywords is now set. */
				if (search->imap->numappendkeywords != 1) {
					bbs_warning("Expected %d keyword, got %d?\n", 1, search->imap->numappendkeywords);
					break;
				}
				retval = strchr(search->keywords, search->imap->appendkeywords[0]) ? 1 : 0;
				if (skey->type == IMAP_SEARCH_UNKEYWORD) {
					retval = !retval;
				}
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
			case IMAP_SEARCH_OLDER: /* like BEFORE, but with # seconds */
				SEARCH_STAT()
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = search->now;
				/* Since all INTERNALDATEs must be in the past, we expect difftime is always negative (tm1 < tm2, e.g. tm1 < now) */
				retval = difftime(t1, t2) <= -skey->child.number;
				break;
			case IMAP_SEARCH_YOUNGER: /* like SINCE, but with # seconds */
				SEARCH_STAT()
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = search->now;
				/* Since all INTERNALDATEs must be in the past, we expect difftime is always negative (tm1 < tm2, e.g. tm1 < now) */
				retval = difftime(t1, t2) >= -skey->child.number;
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
static int search_dir(struct imap_session *imap, const char *dirname, int newdir, int usinguid, struct imap_search_keys *skeys, unsigned int **a, int *lengths, int *allocsizes, int *min, int *max, unsigned long *maxmodseq)
{
	int files, fno = 0;
	struct dirent *entry, **entries = NULL;
	struct imap_search search;
	unsigned int uid;
	unsigned int seqno = 0;
	char keywords[27] = "";
	int now;

	now = time(NULL); /* Only compute this once, not for each file */

	files = scandir(dirname, &entries, NULL, uidsort);
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
		search.now = now;
		search.maxmodseq = *maxmodseq;
		/* Parse the flags just once in advance, since doing bit field comparisons is faster than strchr */
		if (parse_flags_letters_from_filename(search.filename, &search.flags, keywords)) {
			goto next;
		}
		if (search_keys_eval(skeys, IMAP_SEARCH_ALL, &search)) {
			/* Include in search response */
			if (usinguid) {
				if (maildir_parse_uid_from_filename(search.filename, &uid)) {
					continue;
				}
			} else {
				uid = seqno; /* Not really, but use the same variable for both */
			}
			uintlist_append(a, lengths, allocsizes, uid);
			if (min) {
				if (*min == -1 || (int) uid < *min) {
					*min = (int) uid;
				}
			}
			if (max) {
				if (*max == -1 || (int) uid > *max) {
					*max = (int) uid;
				}
			}
			*maxmodseq = search.maxmodseq;
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
	}
	free(entries);
	return 0;
}

/*! \retval -1 on failure, number of search results on success */
static int do_search(struct imap_session *imap, char *s, unsigned int **a, int usinguid, int *min, int *max, unsigned long *maxmodseq)
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

	/* Initialize */
	*min = -1;
	*max = -1;
	*maxmodseq = 0;

	memset(&skeys, 0, sizeof(skeys));
	/* If we didn't consume the entire search expression before returning, then this is invalid */
	if (parse_search_query(imap, &skeys, IMAP_SEARCH_ALL, &s) || !strlen_zero(s)) {
		imap_search_free(&skeys);
		imap_reply(imap, "BAD [CLIENTBUG] Invalid search query");
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

	search_dir(imap, imap->curdir, 0, usinguid, &skeys, a, &lengths, &allocsizes, min, max, maxmodseq);
	search_dir(imap, imap->newdir, 1, usinguid, &skeys, a, &lengths, &allocsizes, min, max, maxmodseq);
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

static char *uintlist_to_ranges(unsigned int *a, int length)
{
	int i;
	struct dyn_str dynstr;
	unsigned int start = 0, last, len;
	const char *prefix = "";
	char buf[15];

	memset(&dynstr, 0, sizeof(dynstr));
	if (length) {
		start = last = a[0]; /* Instead of putting an if i == 0 branch inside the loop, that will only run once, just do it beforehand */
	}
	for (i = 1; i < length; i++) {
		if (!start) {
			start = last = a[i];
		} else if (a[i] == last + 1) {
			last = a[i];
		} else {
			if (start == last) {
				len = snprintf(buf, sizeof(buf), "%s%u", prefix, last);
			} else {
				len = snprintf(buf, sizeof(buf), "%s%u:%u", prefix, start, last);
			}
			dyn_str_append(&dynstr, buf, len);
			prefix = ",";
			start = last = a[i];
		}
	}
	if (start) {
		/* last one */
		if (start == last) {
			len = snprintf(buf, sizeof(buf), "%s%u", prefix, last);
		} else {
			len = snprintf(buf, sizeof(buf), "%s%u:%u", prefix, start, last);
		}
		dyn_str_append(&dynstr, buf, len);
	}
	return dynstr.buf;
}

/*! \note This function is not safe to use for arbitrary valid IMAP sequences, e.g. *, 1:*, etc. */
static int range_to_uintlist(char *s, unsigned int **list, int *length)
{
	char *seq;
	int alloc_sizes = 0;

	while ((seq = strsep(&s, ","))) {
		int a, b;
		char *start, *end = seq;
		start = strsep(&end, ":");
		if (strlen_zero(start)) {
			bbs_warning("Invalid range\n");
			continue;
		}
		a = atoi(start);
		if (!end) {
			uintlist_append(list, length, &alloc_sizes, a);
			continue;
		}
		b = atoi(end);
		if (b - a > 100000) {
			bbs_warning("Declining to process range %d:%d (too large)\n", a, b);
			return -1; /* Don't malloc into oblivion */
		}
		for (; a <= b; a++) {
			uintlist_append(list, length, &alloc_sizes, a);
		}
	}
	return 0;
}

static int test_range_generation(void)
{
	char *ranges;
	unsigned int a[6] = { 3, 5, 2, 1, 4, 6 };
	unsigned int b[6] = { 1, 2, 3, 5, 7, 8 };
	unsigned int c[6] = { 5, 6, 7, 3, 2, 1 };

	/* Ranges must be ascending only (RFC 5267 3.2) */

	ranges = uintlist_to_ranges(a, 6);
	bbs_test_assert_str_equals(ranges, "3,5,2,1,4,6");
	free_if(ranges);

	ranges = uintlist_to_ranges(b, 6);
	bbs_test_assert_str_equals(ranges, "1:3,5,7:8");
	free_if(ranges);

	ranges = uintlist_to_ranges(c, 6);
	bbs_test_assert_str_equals(ranges, "5:7,3,2,1");
	free_if(ranges);

	return 0;

cleanup:
	return -1;
}

#define ESEARCH_ALL (1 << 0)
#define ESEARCH_COUNT (1 << 1)
#define ESEARCH_MIN (1 << 2)
#define ESEARCH_MAX (1 << 3)
#define ESEARCH_SAVE (1 << 4)

#define ESEARCH_MINMAX (ESEARCH_MIN | ESEARCH_MAX)
#define ESEARCH_STATS (ESEARCH_COUNT | ESEARCH_MIN | ESEARCH_MAX)
#define ESEARCH_RESULTS (ESEARCH_MIN | ESEARCH_MAX | ESEARCH_COUNT | ESEARCH_ALL)

#define ESEARCH_NEED_ALL(f) (f & ESEARCH_ALL || (f & ESEARCH_SAVE && !(f & ESEARCH_MINMAX)))

static int parse_search_options(char *s)
{
	int flags = 0;
	char *option;

	if (strlen_zero(s)) {
		return ESEARCH_ALL; /* for () */
	}

	while ((option = strsep(&s, " "))) {
		if (!strcmp(option, "COUNT")) {
			flags |= ESEARCH_COUNT;
		} else if (!strcmp(option, "MIN")) {
			flags |= ESEARCH_MIN;
		} else if (!strcmp(option, "MAX")) {
			flags |= ESEARCH_MAX;
		} else if (!strcmp(option, "ALL")) {
			flags |= ESEARCH_ALL;
		} else if (!strcmp(option, "SAVE")) {
			flags |= ESEARCH_SAVE;
		} else {
			bbs_warning("Unsupported ESEARCH option: %s\n", option);
		}
	}
	return flags;
}

static int parse_return_options(struct imap_session *imap, char **str, int *option_flags)
{
	char *s = *str;
	if (STARTS_WITH(s, "RETURN (")) {
		char *options;
		s += STRLEN("RETURN (");
		options = s;
		s = strchr(s, ')');
		if (!s) {
			imap_reply(imap, "BAD [CLIENTBUG] Unterminated argument");
			return -1;
		}
		*s++ = '\0';
		if (*s == ' ') {
			s++;
		}
		*str = s;
		*option_flags = parse_search_options(options);
		return 1;
	}
	*option_flags = 0;
	return 0;
}

static void esearch_response(struct imap_session *imap, int option_flags, unsigned int *a, int results, int min, int max, unsigned long maxmodseq, int usinguid)
{
	char *list = NULL;
	if (results) {
		char buf[96] = "";
		char *pos = buf;
		size_t buflen = sizeof(buf);

		if (ESEARCH_NEED_ALL(option_flags)) {
			/* For ESEARCH responses, we can send ranges, but for regular SEARCH, the RFC specifically says they are all space delimited */
			list = uintlist_to_ranges(a, results);
		}
		SAFE_FAST_COND_APPEND(buf, pos, buflen, option_flags & ESEARCH_MIN, "MIN %d", min);
		SAFE_FAST_COND_APPEND(buf, pos, buflen, option_flags & ESEARCH_MAX, "MAX %d", max);
		SAFE_FAST_COND_APPEND(buf, pos, buflen, option_flags & ESEARCH_COUNT, "COUNT %d", results);
		/* There is an exception to the RFC 7162 MODSEQ response for SEARCH/SORT,
		 * and it is outlined in RFC 4731 3.2:
		 * Basically, we return the highest MODSEQ as usual, UNLESS:
		 * - Just MIN or MAX: MODSEQ corresponds to that particular message
		 * - Only MIN and MAX (no ALL, COUNT): MODSEQ is the higher of these two messages
		 */
		if (option_flags & ESEARCH_MINMAX && !(option_flags & (ESEARCH_ALL | ESEARCH_COUNT))) {
			char filename[256];
			/* Probably faster to just lookup the message here than keep track throughout the search, just for this edge case */
			maxmodseq = 0;
			if (option_flags & ESEARCH_MIN && option_flags & ESEARCH_MAX) {
				unsigned long othermodseq;
				/* Highest of both of them */
				imap_msg_to_filename(imap->curdir, usinguid ? 0 : min, usinguid ? min : 0, filename, sizeof(filename));
				parse_modseq_from_filename(filename, &maxmodseq);
				imap_msg_to_filename(imap->curdir, usinguid ? 0 : max, usinguid ? max : 0, filename, sizeof(filename));
				parse_modseq_from_filename(filename, &othermodseq);
				maxmodseq = MAX(maxmodseq, othermodseq);
			} else {
				int target = (option_flags & ESEARCH_MIN) ? min : max;
				/* One corresponding to the particular message */
				imap_msg_to_filename(imap->curdir, usinguid ? 0 : target, usinguid ? target : 0, filename, sizeof(filename));
				parse_modseq_from_filename(filename, &maxmodseq);
			}
		}
		SAFE_FAST_COND_APPEND(buf, pos, buflen, maxmodseq, "MODSEQ %lu", maxmodseq);

		if (option_flags & ESEARCH_RESULTS) {
			imap_send(imap, "ESEARCH (TAG \"%s\")%s%s%s %s%s", imap->tag, usinguid ? " UID" : "", option_flags & ESEARCH_STATS ? " " : "", buf, list ? "ALL " : "", S_IF(list));
		}

		if (option_flags & ESEARCH_SAVE) {
			/* RFC 5182 2.4 defines what SAVE refers to if multiple options are specified. */
			free_if(imap->savedsearch);
			if (option_flags & ESEARCH_MINMAX) {
				buf[0] = '\0';
				pos = buf;
				buflen = sizeof(buf);
				SAFE_FAST_COND_APPEND(buf, pos, buflen, option_flags & ESEARCH_MIN, "%d", min);
				SAFE_FAST_COND_APPEND(buf, pos, buflen, option_flags & ESEARCH_MAX, "%d", max);
				imap->savedsearch = strdup(buf);
			} else {
				/* Implicit ALL is saved */
				imap->savedsearch = list; /* Just steal this pointer. */
				list = NULL;
			}
			/* RFC 5182 2.1 says that $ can reference message sequences or UID sequences...
			 * and furthermore, it can be stored using one and referenced using another!
			 * WHY on earth any client would do that, I don't know, but this is possible...
			 *
			 * What we have to do to account for this is that if $ is used in a UID command
			 * but savedsearchuid == 0, for the purposes of matching messages, we treat it
			 * as the non UID version.
			 * Likewise, if savedsearchuid == 1, and $ is dereferenced in a non-UID command,
			 * we have to match on UIDs, not sequence numbers.
			 */
			imap->savedsearchuid = usinguid;
		}
		free_if(list);
	} else {
		if (option_flags & ESEARCH_RESULTS) {
			imap_send(imap, "ESEARCH (TAG \"%s\") %sCOUNT 0", imap->tag, usinguid ? "UID " : ""); /* No results, but still need to send an empty untagged response */
		}
		if (option_flags & ESEARCH_SAVE) {
			REPLACE(imap->savedsearch, "");
			imap->savedsearchuid = usinguid;
		}
	}
}

static int handle_search(struct imap_session *imap, char *s, int usinguid)
{
	unsigned int *a = NULL;
	int results;
	int min, max;
	unsigned long maxmodseq;
	char *list = NULL;
	int options, option_flags;

	options = parse_return_options(imap, &s, &option_flags); /* ESEARCH */
	if (options < 0) {
		return 0;
	}

	results = do_search(imap, s, &a, usinguid, &min, &max, &maxmodseq);
	if (results < 0) {
		return 0;
	}

	if (options > 0) { /* ESEARCH */
		esearch_response(imap, option_flags, a, results, min, max, maxmodseq, usinguid);
	} else {
		if (results) {
			/* If non-empty result and MODSEQ was specified, maxmodseq will be > 0, and we'll need to append this to the response */
			list = uintlist_to_str(a, results);
			if (maxmodseq) {
				imap_send(imap, "SEARCH %s (MODSEQ %lu)", S_IF(list), maxmodseq);
			} else {
				imap_send(imap, "SEARCH %s", S_IF(list));
			}
			free_if(list);
		} else {
			imap_send(imap, "SEARCH"); /* No results, but still need to send an empty untagged response */
		}
	}

	free_if(a);
	imap_reply(imap, "OK %sSEARCH completed%s", usinguid ? "UID " : "", option_flags & ESEARCH_SAVE ? ", result saved" : "");
	return 0;
}

struct imap_sort {
	struct imap_session *imap;
	struct dirent **entries;
	const char *sortexpr;
	int numfiles;
	unsigned int usinguid:1;
};

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
			maildir_parse_uid_from_filename(entry->d_name, &uid);
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
	int options, option_flags;
	int min, max;
	unsigned long maxmodseq;

	options = parse_return_options(imap, &s, &option_flags); /* ESORT */
	if (options < 0) {
		return 0;
	}

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
		imap_reply(imap, "NO [BADCHARSET] (UTF-8 US_ASCII) Charset %s not supported", charset);
		return 0;
	}

	/* This is probably something that could be made a lot more efficient.
	 * Initially here, our concern is with simplicity and correctness,
	 * but sorting and searching could probably use lots of optimizations. */

	/* First, search for any matching messages. */
	results = do_search(imap, search, &a, usinguid, &min, &max, &maxmodseq);
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

	/* Sort if needed */
	if (options == 0 || option_flags & ESEARCH_ALL) {
		struct imap_sort sort;
		memset(&sort, 0, sizeof(sort));
		sort.imap = imap;
		sort.sortexpr = sortexpr;
		sort.usinguid = usinguid;
		sort.numfiles = scandir(imap->curdir, &sort.entries, NULL, uidsort); /* cur dir only */
		if (sort.numfiles >= 0) {
			qsort_r(a, results, sizeof(unsigned int), sort_compare, &sort); /* Actually sort the results, conveniently already in an array. */
			free_scandir_entries(sort.entries, sort.numfiles);
			free(sort.entries);
		}
	}

	if (options > 0) { /* ESORT */
		esearch_response(imap, option_flags, a, results, min, max, maxmodseq, usinguid);
	} else {
		if (results) {
			char *list;
			list = uintlist_to_str(a, results);
			if (maxmodseq) {
				imap_send(imap, "SORT %s (MODSEQ %lu)", S_IF(list), maxmodseq);
			} else {
				imap_send(imap, "SORT %s", S_IF(list));
			}
			free_if(list);
		} else {
			imap_send(imap, "SORT"); /* No matches */
		}
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

	/* XXX Most clients are going to request the capabilities immediately.
	 * As an optimization, we could save an RTT by sending them unsolicited */

	if (auth) {
		_imap_reply(imap, "%s OK Success\r\n", imap->savedtag ? imap->savedtag : imap->tag); /* Use tag from AUTHENTICATE request */
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
		if (!bbs_num_auth_providers()) {
			imap_reply(imap, "NO [UNAVAILABLE] Authentication currently unavailable");
		} else {
			imap_reply(imap, "NO [AUTHENTICATIONFAILED] Invalid username or password");
		}
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
		imap_reply(imap, "NO [NONEXISTENT] No such mailbox");
		return 0;
	}
	IMAP_REQUIRE_ACL(myacl, IMAP_ACL_ADMINISTER);
	if (setacl(imap, buf, mailbox, user, newacl)) {
		imap_reply(imap, "NO [SERVERBUG] %s failed", delete ? "DELETEACL" : "SETACL");
	} else {
		imap_reply(imap, "OK %s complete", delete ? "DELETEACL" : "SETACL");
	}
	return 0;
}

/*! \retval Number of replacements made */
static int imap_substitute_remote_command(struct imap_session *imap, char *s)
{
	char *prefix;
	int len, lenleft, replacements = 0;
	char *curpos;

	if (strlen_zero(s)) {
		bbs_debug(5, "Command is empty, nothing to substitute\n");
		return 0;
	}

	/* This function is a generic one that replaces the local name for a remote (virtually mapped)
	 * mailbox with the name of the mailbox on that system, suitable for sending to it.
	 * This means that we can passthru commands generically after modification
	 * without being concerned with the semantics/syntax of the command itself. */

	/* The remote command should always be *shorter* than the local one, because we're merely removing the prefix, wherever it may occur.
	 * This allows us to do this in place, using memmove. */
	len = strlen(s);
	curpos = s;
	while ((prefix = strstr(curpos, imap->virtprefix))) {
		char *end = prefix + imap->virtprefixlen;
		if (*end != HIERARCHY_DELIMITER_CHAR) {
			bbs_warning("Unexpected character at pos: %d\n", *end);
			continue;
		}

		/* While we're doing this, convert the hierarchy delimiter as well.
		 * This can be done in place, thankfully.
		 * Go until we get a space or an end quote, signaling the end of the mailbox name.
		 * But if the mailbox name contains spaces, then we must NOT stop there
		 * since there could be more remaining... so we should only stop on spaces
		 * if the mailbox name STARTED with a quote.
		 */
		if (imap->virtdelimiter != HIERARCHY_DELIMITER_CHAR) { /* Wouldn't hurt anything to always do, but why bother? */
			int mailbox_has_spaces;
			char *tmp = end + 1;
			if (prefix != s) { /* Bounds check: don't go past the beginning of the string */
				mailbox_has_spaces = *(prefix - 1) == '"';
			} else {
				mailbox_has_spaces = 0;
			}
			while (*tmp) {
				if (*tmp == HIERARCHY_DELIMITER_CHAR) {
					*tmp = imap->virtdelimiter;
				} else if (*tmp == '"') {
					break;
				} else if (!mailbox_has_spaces && *tmp == ' ') {
					break;
				}
				tmp++;
			}
		}

		replacements++;
		len -= imap->virtprefixlen + 1; /* plus period */
		lenleft = len - (prefix - s);
		memmove(prefix, end + 1, lenleft);
		prefix[lenleft] = '\0';
		curpos = prefix; /* Start where we left off, not at the beginning of the string */
	}
	bbs_debug(5, "Substituted remote command to: '%s'\n", s);
	return replacements;
}

static int test_remote_mailbox_substitution(void)
{
	struct imap_session imap;
	char buf[256];

	memset(&imap, 0, sizeof(imap));
	safe_strncpy(imap.virtprefix, "Other Users.foobar", sizeof(imap.virtprefix));
	imap.virtprefixlen = STRLEN("Other Users.foobar");

	safe_strncpy(buf, "a1 UID COPY 149 \"Other Users.foobar.INBOX\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&imap, buf));
	bbs_test_assert_str_equals(buf, "a1 UID COPY 149 \"INBOX\"");

	safe_strncpy(buf, "copy 149 \"Other Users.foobar.Sent\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&imap, buf));
	bbs_test_assert_str_equals(buf, "copy 149 \"Sent\"");

	/* With different remote hierarchy delimiter. */
	imap.virtdelimiter = '/';
	safe_strncpy(buf, "copy 149 \"Other Users.foobar.Sub.Folder\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&imap, buf));
	bbs_test_assert_str_equals(buf, "copy 149 \"Sub/Folder\"");

	/* Including with spaces */
	safe_strncpy(buf, "copy 149 \"Other Users.foobar.Sub.Folder with spaces.sub\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&imap, buf));
	bbs_test_assert_str_equals(buf, "copy 149 \"Sub/Folder with spaces/sub\"");

	return 0;

cleanup:
	return -1;
}

/* There must not be extra spaces between tokens. Gimap is not tolerant of them. */
#define FORWARD_VIRT_MBOX() \
	if (imap->virtmbox) { \
		return imap_client_send_wait_response(imap, -1, 5000, "%s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_UID() \
	if (imap->virtmbox) { \
		return imap_client_send_wait_response(imap, -1, 5000, "UID %s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_MODIFIED_PREFIX(count, prefix) \
	if (imap->virtmbox) { \
		replacecount = imap_substitute_remote_command(imap, s); \
		if (replacecount != count) { /* Number of replacements must be all or nothing */ \
			imap_reply(imap, "NO Cannot move/copy between home and remote servers\n"); \
			return 0; \
		} \
		return imap_client_send_wait_response(imap, -1, 5000, prefix "%s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_MODIFIED(count) FORWARD_VIRT_MBOX_MODIFIED_PREFIX(count, "")
#define FORWARD_VIRT_MBOX_MODIFIED_UID(count) FORWARD_VIRT_MBOX_MODIFIED_PREFIX(count, "UID ")

static int imap_process(struct imap_session *imap, char *s)
{
	int res, replacecount;
	char *command;

	if (imap->idle || (imap->alerted == 1 && !strcasecmp(s, "DONE"))) {
		/* IDLE for virtual mailboxes (proxied) is handled in the IDLE command itself */
		/* Thunderbird clients will still send "DONE" if we send a tagged reply during the IDLE,
		 * but Microsoft Outlook will not, so handle both cases, i.e. tolerate the redundant DONE.
		 */
		if (strlen_zero(s) || strcasecmp(s, "DONE")) { /* Command should be "DONE" */
			bbs_warning("Improper IDLE termination (received '%s')\n", S_IF(s));
		}
		imap->idle = 0;
		_imap_reply(imap, "%s OK IDLE terminated\r\n", imap->savedtag); /* Use tag from IDLE request */
		free_if(imap->savedtag);
		return 0;
	} else if (imap->alerted == 1) {
		imap->alerted = 2;
	}

	if (imap->appendsize) {
		/* We're in the middle of an append at the moment.
		 * This is kind of like the DATA command with SMTP. */
		int dlen;

		if (imap->appendfail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		dlen = strlen(s); /* s may be empty but will not be NULL */
		bbs_write(imap->appendfile, s, dlen);
		bbs_write(imap->appendfile, "\r\n", 2);
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
		imap_send(imap, "BAD [CLIENTBUG] Invalid tag"); /* There isn't a tag, so we can't do a tagged reply */
		return 0; /* Ignore empty lines at this point (can't do this if in an APPEND) */
	}

	/* IMAP clients MUST use a different tag each command, but in practice this is treated as a SHOULD. Common IMAP servers do not enforce this. */
	imap->tag = strsep(&s, " "); /* Tag for client to identify responses to its request */
	command = strsep(&s, " ");

	if (!imap->tag || !command) {
		imap_send(imap, "BAD [CLIENTBUG] Missing arguments.");
		return 0;
	}

	/* EXPUNGE responses MUST NOT be sent during FETCH, STORE, or SEARCH, or when no command is in progress (RFC 3501, 9051, and also 2180)
	 * RFC 5256 also says not allowed during SORT (but UID SORT is fine). (UID commands don't use sequence numbers)
	 * Typically, clients will issue a NOOP to get this information.
	 * The pipe allows us to decouple the EXPUNGE action from the responses sent to multi-access clients. */

	/* XXX Technically, the RFC says this should happen right before the END of the command, not at the beginning of it.
	 * e.g. RFC 5465 Section 1: "as unsolicited responses sent just before the end of a command"
	 * For simple cases like NOOP, there's no difference at all, but does it matter in other cases?
	 * It would be tricky to support the other case since each command sends its own end of command reply,
	 * and this would need to be interleaved before that as appropriate. So if it's fine to do it here, then that is much simpler.
	 *
	 * From RFC 7162 3.2.10.2, this seems to suggest that this approach is fine:
	 * A VANISHED response MUST NOT be sent when no command is in progress, nor while responding to a FETCH, STORE, or SEARCH command.
	 * This rule is necessary to prevent a loss of synchronization of message sequence numbers between the client and server.
	 * A command is not "in progress" until the complete command has been received; in particular, a command is not "in progress" during the negotiation of command continuation.
	 */

	if (imap->pending && !imap->virtmbox) { /* Not necessary to lock just to read the flag. Only if we're actually going to read data. */
		struct readline_data rldata;

		/* If it's a command during which we're not allowed to send an EXPUNGE, then don't send it now. */

		/* RFC 7162 3.2.10.2: UID FETCH, UID STORE, and UID SEARCH are different commands from FETCH, STORE, and SEARCH.
		 * A VANISHED response MAY be sent during a UID command. However, the VANISHED response MUST NOT be sent
		 * during a UID SEARCH command that contains message numbers in the search criteria.
		 *
		 * XXX Regardless of what we to do here, won't the clients sequence numbers be off anyways?
		 * We don't maintain a "client's view" of what sequences numbers are known and map to what UIDs.
		 * So what is the actual effect of "preventing loss of synchronization in this manner"???
		 */
		if (!STARTS_WITH(command, "FETCH") && !STARTS_WITH(command, "STORE") && !STARTS_WITH(command, "SEARCH") && !STARTS_WITH(command, "SORT") && (!STARTS_WITH(command, "UID") || (!strlen_zero(s) && !STARTS_WITH(s, "SEARCH")))) {
			char buf[1024]; /* Hopefully big enough for any single untagged  response. */
			pthread_mutex_lock(&imap->lock);
			bbs_readline_init(&rldata, buf, sizeof(buf));
			/* Read from the pipe until it's empty again. If there's more than one response waiting, and in particular, more than sizeof(buf), we need to read by line. */
			for (;;) {
				res = bbs_readline(imap->pfd[0], &rldata, "\r\n", 5); /* Only up to 5 ms */
				if (res < 0) {
					break;
				}
				_imap_reply_nolock(imap, "%s\r\n", buf); /* Already have lock held, and we don't know the length. Also, add CR LF back on, since bbs_readline stripped that. */
			}
			imap->pending = 0;
			pthread_mutex_unlock(&imap->lock);
		}
	}

	if (imap->activefolder && strcasecmp(command, "STATUS")) {
		/* STATUS does not change the currently selected mailbox in IMAP.
		 * However, if a client issues multiple STATUS commands for multiple
		 * mailboxes on the same remote account, we want to be able to reuse
		 * that IMAP client connection.
		 *
		 * To account for this, internally STATUS really does update the
		 * active mailbox. It will set imap->activefolder but not change
		 * imap->folder. Thus, whenever the client is done issuing STATUS
		 * commands, we'll end up inside this branch here.
		 *
		 * At THAT point, we can then replace the connection for STATUS
		 * with whatever we should have for the currently selected mailbox. */
		bbs_debug(4, "Reverting temporary STATUS override\n");
		if (imap->folder) {
			/* Since we internally changed the active mailbox, change it back to the mailbox that's still really selected.
			 * Internally, this will also close the remote if needed. */
			set_maildir(imap, imap->folder);
		} else {
			/* If no mailbox was selected when we did the STATUS, then just close the remote */
			if (imap->virtmbox) {
				imap_close_remote_mailbox(imap);
			}
		}
		FREE(imap->activefolder);
	}

	if (!strcasecmp(command, "NOOP")) {
		FORWARD_VIRT_MBOX();
		imap_reply(imap, "OK NOOP completed");
	} else if (!strcasecmp(command, "LOGOUT")) {
		imap_send(imap, "BYE IMAP4 Server logging out");
		imap_reply(imap, "OK LOGOUT completed");
		return -1; /* Close connection */
	} else if (!strcasecmp(command, "CAPABILITY")) {
		/* Some clients send a CAPABILITY after login, too,
		 * even though the RFC says clients shouldn't,
		 * since capabilities don't change during sessions.
		 * However, in practice, the capabilities exposed by many servers
		 * after authentication differ.
		 */
		imap_send(imap, "CAPABILITY " IMAP_CAPABILITIES);
		imap_reply(imap, "OK CAPABILITY completed");
	} else if (!strcasecmp(command, "AUTHENTICATE")) {
		if (bbs_user_is_registered(imap->node->user)) {
			imap_reply(imap, "NO [CLIENTBUG] Already logged in");
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
			imap_reply(imap, "NO [CANNOT] Auth method not supported");
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
			imap_reply(imap, "NO [CLIENTBUG] Already logged in");
			return 0;
		}
		/* Strip the domain, if present,
		 * but the domain must match our domain, if present. */
		domain = strchr(user, '@');
		if (domain) {
			*domain++ = '\0';
			if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
				imap_reply(imap, "NO [AUTHENTICATIONFAILED] Invalid username or password"); /* No such mailbox, since wrong domain! */
				return 0;
			}
		}
		res = bbs_authenticate(imap->node, user, pass);
		bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
		if (res) {
			if (!bbs_num_auth_providers()) {
				imap_reply(imap, "NO [UNAVAILABLE] Authentication currently unavailable");
			} else {
				imap_reply(imap, "NO [AUTHENTICATIONFAILED] Invalid username or password");
			}
			return 0;
		}
		return finish_auth(imap, 0);
	/* Past this point, must be logged in. */
	} else if (!bbs_user_is_registered(imap->node->user)) {
		bbs_warning("'%s' command may not be used in the unauthenticated state\n", command);
		imap_reply(imap, "BAD Not logged in"); /* Not necessarily a client bug, could be our fault too if we don't implement something */
	} else if (!strcasecmp(command, "SELECT")) {
		return handle_select(imap, s, CMD_SELECT);
	} else if (!strcasecmp(command, "EXAMINE")) {
		return handle_select(imap, s, CMD_EXAMINE);
	} else if (!strcasecmp(command, "STATUS")) { /* STATUS is like EXAMINE, but it's on a specified mailbox that is NOT the currently selected mailbox */
		/* Need to save/restore current maildir for STATUS, so it doesn't mess up the selected mailbox, since STATUS must not modify the selected folder.
		 * This is handled earlier in this function. */
		res = handle_select(imap, s, CMD_STATUS);
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
	} else if (!strcasecmp(command, "XLIST")) {
		return handle_list(imap, s, 2);
	} else if (!strcasecmp(command, "CREATE")) {
		/*! \todo need to modify mailbox names like select, but can then pass it on (do in the commands) */
		IMAP_NO_READONLY(imap);
		return handle_create(imap, s);
	} else if (!strcasecmp(command, "DELETE")) {
		IMAP_NO_READONLY(imap);
		return handle_delete(imap, s);
	} else if (!strcasecmp(command, "RENAME")) {
		IMAP_NO_READONLY(imap);
		return handle_rename(imap, s);
	} else if (!strcasecmp(command, "CHECK")) {
		FORWARD_VIRT_MBOX(); /* Perhaps the remote server does something with CHECK... forward it just in case */
		imap_reply(imap, "OK CHECK Completed"); /* Nothing we need to do now */
	/* Selected state */
	} else if (!strcasecmp(command, "CLOSE")) {
		FORWARD_VIRT_MBOX(); /* Send CLOSE to remote server since CLOSE = implicit expunge */
		REQUIRE_SELECTED(imap);
		if (imap->folder && IMAP_HAS_ACL(imap->acl, IMAP_ACL_EXPUNGE)) {
			imap_expunge(imap, 1);
		}
		close_mailbox(imap);
		imap_reply(imap, "OK CLOSE completed");
	} else if (!strcasecmp(command, "EXPUNGE")) {
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		IMAP_REQUIRE_ACL(imap->acl, IMAP_ACL_EXPUNGE);
		if (imap->folder) {
			imap->expungeindex = 0;
			imap_expunge(imap, 0);
			imap_reply(imap, "OK [HIGHESTMODSEQ %lu] EXPUNGE completed", imap->highestmodseq); /* imap->highestmodseq is guaranteed to be accurate here since we just set it */
		} else {
			imap_reply(imap, "OK EXPUNGE completed");
		}
	} else if (!strcasecmp(command, "UNSELECT")) { /* Same as CLOSE, without the implicit auto-expunging */
		if (imap->virtmbox) {
			imap_close_remote_mailbox(imap);
		} else {
			close_mailbox(imap);
		}
		imap_reply(imap, "OK UNSELECT completed");
	} else if (!strcasecmp(command, "FETCH")) {
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		return handle_fetch(imap, s, 0);
	} else if (!strcasecmp(command, "COPY")) {
		/* The client may think two mailboxes are on the same server, when in reality they are not.
		 * If virtual mailbox, destination must also be on that server. Otherwise, reject the operation.
		 * We would need to transparently do an APPEND otherwise (which could be done, but isn't at the moment). */
		FORWARD_VIRT_MBOX_MODIFIED(1);
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		return handle_copy(imap, s, 0);
	} else if (!strcasecmp(command, "MOVE")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX_MODIFIED(1);
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		return handle_move(imap, s, 0);
	} else if (!strcasecmp(command, "STORE")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		return handle_store(imap, s, 0);
	} else if (!strcasecmp(command, "SEARCH")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		return handle_search(imap, s, 0);
	} else if (!strcasecmp(command, "SORT")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		return handle_sort(imap, s, 0);
	} else if (!strcasecmp(command, "UID")) {
		REQUIRE_ARGS(s);
		if (!imap->virtmbox) { /* Ultimately, FORWARD_VIRT_MBOX will intercept this command, if it's valid */
			REQUIRE_SELECTED(imap);
		}
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		if (!strcasecmp(command, "FETCH")) {
			FORWARD_VIRT_MBOX_UID();
			return handle_fetch(imap, s, 1);
		} else if (!strcasecmp(command, "COPY")) {
			FORWARD_VIRT_MBOX_MODIFIED_UID(1);
			return handle_copy(imap, s, 1);
		} else if (!strcasecmp(command, "MOVE")) {
			FORWARD_VIRT_MBOX_MODIFIED_UID(1);
			return handle_move(imap, s, 1);
		} else if (!strcasecmp(command, "STORE")) {
			FORWARD_VIRT_MBOX_UID();
			return handle_store(imap, s, 1);
		} else if (!strcasecmp(command, "SEARCH")) {
			FORWARD_VIRT_MBOX_UID();
			return handle_search(imap, s, 1);
		} else if (!strcasecmp(command, "SORT")) {
			FORWARD_VIRT_MBOX_UID();
			return handle_sort(imap, s, 1);
		} else {
			imap_reply(imap, "BAD Invalid UID command");
		}
	} else if (!strcasecmp(command, "APPEND")) {
		REQUIRE_ARGS(s);
		if (imap->virtmbox) {
			/*! \todo This needs careful attention for virtual mappings */
			imap_reply(imap, "NO Operation not supported for virtual mailboxes");
			return 0;
		}
		IMAP_NO_READONLY(imap);
		REPLACE(imap->savedtag, imap->tag);
		handle_append(imap, s);
	} else if (allow_idle && !strcasecmp(command, "IDLE")) {
		if (imap->virtmbox) {
			/* IDLE for up to (just under) 30 minutes.
			 * Note that client_command_passthru will restart the timer each time there is activity,
			 * but real mail clients should terminate the IDLE when they get an untagged response
			 * and do a FETCH anyways (at least, in response to EXISTS, not EXPUNGE).
			 * Furthermore, it is NOT our responsibility to terminate the IDLE automatically after 29 minutes.
			 * It's the client's job to do that. If we get disconnected, we'll disconnect as well.
			 */
			return imap_client_send_wait_response(imap, imap->rfd, 1790000, "%s\r\n", command); /* No trailing spaces! Gimap doesn't like that */
		}
		/* XXX Outlook often tries to IDLE without selecting a mailbox, which is kind of bizarre.
		 * Technically though, RFC 2177 says IDLE is valid in either the authenticated or selected states.
		 * How it's used in the authenticated (but non-selected) state, I don't really know.
		 * For now, clients attempting that will be summarily rebuffed. */
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
		imap_reply(imap, "NO [NOPERM] Permission Denied"); /* Users cannot adjust their own quotas, nice try... */
	} else if (!strcasecmp(command, "GETQUOTA")) {
		/* RFC 2087 / 9208 QUOTA */
		handle_getquota(imap);
		imap_reply(imap, "OK GETQUOTA complete");
	} else if (!strcasecmp(command, "GETQUOTAROOT")) {
		REQUIRE_ARGS(s);
		if (imap->virtmbox) {
			if (!(imap->virtcapabilities & IMAP_CAPABILITY_QUOTA)) {
				/* Not really anything nice we can do here. There is no "default" we can provide,
				 * and since our capabilities include QUOTA, the client will think we've gone and lied to it now.
				 * Apologies, dear client. If only you knew all the tricks we were playing on you right now. */
				imap_reply(imap, "NO Quota unavailable for this mailbox");
				return 0;
			}
			/* XXX Since the remote quota will differ from ours, could this mess up the client if we don't translate the quota root? */
			FORWARD_VIRT_MBOX_MODIFIED(1);
		}
		imap_send(imap, "QUOTAROOT %s \"\"", s);
		handle_getquota(imap);
		imap_reply(imap, "OK GETQUOTAROOT complete");
	} else if (!strcasecmp(command, "ID")) {
		/* RFC 2971 (ID extension) */
		REQUIRE_ARGS(s);
		REPLACE(imap->clientid, s);
		imap_send(imap, "ID (\"name\" \"%s.Imap4Server\" \"version\" \"%s\")", BBS_SHORTNAME, BBS_VERSION);
		imap_reply(imap, "OK ID completed");
	/* We don't store subscriptions. We just automatically treat all available folders as subscribed.
	 * Implement for the sake of completeness, even though these commands are really pointless.
	 * LSUB will return all folders, so clients *shouldn't* try to SUBSCRIBE to something, but if they do, accept it.
	 * If they try to UNSUBSCRIBE, definitely reject that. */
	} else if (!strcasecmp(command, "SUBSCRIBE")) {
		IMAP_NO_READONLY(imap);
		/* Since we don't check for mailbox existence (and everything is always subscribed anyways), no real need to check ACLs here */
		bbs_debug(1, "Ignoring sbscription attempt for %s for mailbox %d\n", S_IF(s), mailbox_id(imap->mbox));
		imap_reply(imap, "OK SUBSCRIBE completed"); /* Everything available is already subscribed anyways, so can't hurt */
	} else if (!strcasecmp(command, "UNSUBSCRIBE")) {
		IMAP_NO_READONLY(imap);
		bbs_warning("Unsubscription attempt for %s for mailbox %d\n", S_IF(s), mailbox_id(imap->mbox));
		imap_reply(imap, "NO [NOPERM] Permission denied");
	} else if (!strcasecmp(command, "GENURLAUTH")) {
		char *resource, *mechanism;
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX_MODIFIED(1);
		resource = strsep(&s, " ");
		mechanism = s;
		REQUIRE_ARGS(mechanism);
		STRIP_QUOTES(resource);
		if (strcmp(mechanism, "INTERNAL")) {
			imap_reply(imap, "NO [CANNOT] Only INTERNAL mechanism allowed");
			return 0;
		}
		/* This really makes a mockery of RFC 4467.
		 * Trojita expects to be able to use GENURLAUTH
		 * to get the IMAP URL it should pass to the SMTP server.
		 * So just reflect back what it passed us; the SMTP server will know what to do with that.
		 * It's not actually going to issue any IMAP commands with it.
		 */
		 imap_send(imap, "GENURLAUTH \"%s:internal\"", resource);
		 imap_reply(imap, "OK GENURLAUTH completed");
		 /* RESETKEY and URLFETCH commands are not implemented */
	} else if (!strcasecmp(command, "MYRIGHTS")) {
		char buf[256];
		int myacl;
		REQUIRE_ARGS(s);
		if (imap->virtmbox) {
			if (!(imap->virtcapabilities & IMAP_CAPABILITY_ACL)) {
				/* Remote server doesn't support ACLs.
				 * Don't send a MYRIGHTS command since the server will reject it.
				 * Just assume everything is allowed, which is reasonable. */
				myacl = IMAP_ACL_DEFAULT_PRIVATE;
				myacl &= ~IMAP_ACL_ADMINISTER; /* If server doesn't support ACL, there is no ACL administration */
				generate_acl_string(myacl, buf, sizeof(buf));
				imap_send(imap, "MYRIGHTS %s %s", s, buf);
				imap_reply(imap, "OK MYRIGHTS completed");
				return 0;
			}
			FORWARD_VIRT_MBOX_MODIFIED(1);
		}
		STRIP_QUOTES(s);
		/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
		if (imap_translate_dir(imap, s, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
			imap_reply(imap, "NO [NONEXISTENT] No such mailbox");
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
		FORWARD_VIRT_MBOX_MODIFIED(1);
		mailbox = strsep(&s, " ");
		REQUIRE_ARGS(s);
		STRIP_QUOTES(mailbox);
		/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
		if (imap_translate_dir(imap, mailbox, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
			imap_reply(imap, "NO [NONEXISTENT] No such mailbox");
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
		FORWARD_VIRT_MBOX_MODIFIED(1);
		STRIP_QUOTES(s);
		/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
		if (imap_translate_dir(imap, s, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
			imap_reply(imap, "NO [NONEXISTENT] No such mailbox");
			return 0;
		}
		IMAP_REQUIRE_ACL(myacl, IMAP_ACL_ADMINISTER);
		getacl(imap, buf, s);
		imap_reply(imap, "OK GETACL complete");
	} else if (!strcasecmp(command, "SETACL")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX_MODIFIED(1);
		return handle_setacl(imap, s, 0);
	} else if (!strcasecmp(command, "DELETEACL")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX_MODIFIED(1);
		return handle_setacl(imap, s, 1);
	} else if (!strcasecmp(command, "ENABLE")) {
		char *cap;
		int enabled = 0;
		REQUIRE_ARGS(s);
		/*! \todo This combined with our parsing of remote server capabilities could use a more formal capabilities flag-based int */
		while ((cap = strsep(&s, " "))) {
			/* The reply only contains capabilities that were enabled just now, not any that may have already been enabled. */
			if (!strcasecmp(cap, "CONDSTORE")) {
				imap->condstore = 1;
				imap_send(imap, "ENABLED CONDSTORE");
				enabled++;
			} else if (!strcasecmp(cap, "QRESYNC")) {
				imap->condstore = 1; /* Implicitly includes CONDSTORE */
				imap->qresync = 1;
				imap_send(imap, "ENABLED QRESYNC CONDSTORE");
				enabled++;
			} else {
				bbs_warning("Unknown capability %s\n", cap);
			}
		}
		imap_reply(imap, "OK ENABLE completed."); /* Always reply OK, even if nonexistent capability. */
	} else if (!strcasecmp(command, "TESTLOCK")) {
		/* Hold the mailbox lock for a moment. */
		/*! \note This is only used for the test suite, it is not part of any IMAP standard or intended for clients. */
		MAILBOX_TRYRDLOCK(imap);
		usleep(3500000); /* 500ms is sufficient normally, but under valgrind, we need more time. Even 2500ms is not enough. */
		mailbox_unlock(imap->mbox);
		imap_reply(imap, "OK Lock test succeeded");
	} else {
		bbs_warning("Unsupported IMAP command: %s\n", command);
		imap_reply(imap, "BAD Command not supported.");
	}

	return 0;
}

static void handle_client(struct imap_session *imap)
{
	char buf[8192]; /* Buffer size suggested by RFC 7162 Section 4 */
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));

	imap_send(imap, "OK %s Service Ready", IMAP_REV);

	for (;;) {
		const char *word2;
		/* Autologout timer should not be less than 30 minutes, according to the RFC. We'll uphold that, for clients that are logged in. */
		int res = bbs_readline(imap->rfd, &rldata, "\r\n", bbs_user_is_registered(imap->node->user) ? MIN_MS(30) : MIN_MS(1));
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
	imap.client.fd = -1;
	imap.rfd = rfd;
	imap.wfd = wfd;
	imap.node = node;
	imap.appendfile = -1;

	if (pipe(imap.pfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		goto cleanup;
	}

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
	close(imap.pfd[0]);
	close(imap.pfd[1]);
	/* imap is stack allocated, don't free it */

cleanup:
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

	imap_handler(node, !strcmp(node->protname, "IMAPS"));

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
	{ "IMAP Sequence Range Generation", test_range_generation },
	{ "IMAP STORE Flags Parsing", test_flags_parsing },
	{ "IMAP COPYUID Generation", test_copyuid_generation },
	{ "IMAP Remote Mailbox Translation", test_remote_mailbox_substitution },
	{ "parensep", test_parensep },
};

static int alertmsg(unsigned int userid, const char *msg)
{
	int res = -1;
	struct imap_session *s;

	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		if (!bbs_user_is_registered(s->node->user) || s->node->user->id != userid) { /* Must be the desired user */
			continue;
		}
		pthread_mutex_lock(&s->lock);
		if (!s->idle || s->alerted) { /* Must be idling, or we can't send an untagged response now */
			pthread_mutex_unlock(&s->lock);
			continue;
		}

		/* Deliver the message using an IMAP ALERT, which MUAs (mail user agents / mail clients)
		 * are obligated to display to the user in some way (RFC 3501 7.1).
		 * In theory... */

		/* Unfortunately, in practice, it doesn't seem to be that simple...
		 * You can't just send an untagged * OK [ALERT] message to the client during an IDLE and call it a day.
		 *
		 * Thunderbird-based clients will ignore ALERTs on some commands entirely.
		 * At least these commands CAN work... SOMETIMES: ID, GETQUOTAROOT, UID FETCH, SELECT, LIST, ENABLE, CAPABILITY, NAMESPACE, LSUB
		 * However, it is not consistent. When testing, I could easily make an alert display on an initial UID FETCH,
		 * but after kicking it out of an IDLE and having it issue UID FETCH again, the alert would not display.
		 *
		 * The Thunderbird source code can be relevant here to try to understand this behavior.
		 * The relevant code is mostly unchanged since at least 52 so this applies to most Thunderbird forks as well, e.g. Interlink, Epyrus, etc.
		 *
		 * Files that have to do with ALERT:
		 * - mailnews/imap/src/nsImapServerResponseParser.cpp
		 * - mailnews/imap/src/nsImapProtocol.cpp
		 * (Search for ALERT and functions starting with AlertUser, but not ending in UsingName)
		 *
		 * RFC 3501 also backs up the theory that you SHOULD be able to send ALERTs whenever you want, and clients SHOULD display them.
		 * The Thunderbird behavior is probably wrong.
		 * Other sources that suggest you should be able to send ALERTs whenever you want:
		 * - https://mail.uni-bonn.de/Guide/IMAP.html
		 * - https://mail.uni-bonn.de/Guide/Alerts.html
		 *
		 * TL;DR It seems that we can only reliably send an ALERT when a new mailbox is selected,
		 * or initially when the client first connects and is issuing any of the commands listed in an above paragraph.
		 *
		 * So, our workaround solution, since even if this issue gets fixed, that won't fix it for the massive install base.
		 * Most things do not work, but one thing that does is we can end the IDLE session with a NO reply,
		 * which will display an alert like:
		 * "The current operation on 'Inbox' did not succeed. The mail server for account (account) : [ALERT] ...
		 *
		 * This only works if it's a tagged reply, not if it's an untagged response.
		 * This is far from ideal, but since we can't reliably generate an alert in other ways / until we figure out how,
		 * this is probably the best we can hope for.
		 *
		 * Except never mind... that only works ONCE and then never again!!!
		 *
		 * Ultimately, we can only use this mechanism ONCE for an entire connection... even if it logs back in on the same connection, that's no good.
		 * So basically use alerted to mark a "dirty bit" that means we can't use this session again.
		 *
		 * So there are major shortcomings of this mechanism in practice:
		 * - This mechanism is extremely unreliable
		 * - It only works once per connection, if at all, and then never again (MS Outlook seems to always ignore them)
		 * - Instead of sending a native ALERT in an IDLE (OK [ALERT]), it only works with NO [ALERT],
		 *   which adds the "The current operation did not succeed..." boilerplate, which is confusing to users.
		 *
		 * Overall, this mechanism has a lot of potential in theories, but since clients are very bad about displaying alerts,
		 * we can't really take advantage of this currently.
		 */

		/* RFC 2971 says we MUST NOT make operational changes or attempt to work around client bugs based on the ID.
		 * Well, RFC 3501 also says clients MUST display ALERTs to the user, so who cares about rules anyways?
		 * We have no choice but to voilate the RFC here. */

		if (!strlen_zero(s->clientid)) {
			if (strstr(s->clientid, "Outlook")) { /* MS Outlook never seems to display alerts at all */
				pthread_mutex_unlock(&s->lock);
				continue;
			}
			/* The following (Thunderbird family) clients MAY work: Thunderbird, Interlink, MailNews, Epyrus */
			/* Untested: Trojita */
		}

		s->alerted = 1;
		/* Do not send a random untagged EXISTS, e.g. * EXISTS 999999, or that will cause ~Thunderbird to ignore the ALERT */
		_imap_reply_nolock(s, "%s NO [ALERT] %s\r\n", s->savedtag, msg); /* Use tag from IDLE request. This must be a NO, not an OK. */
		s->idle = 0; /* Since we sent a tagged reply, the IDLE is technically terminated now. */
		res = 0;
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
	return res;
}

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
	pthread_mutex_init(&virt_lock, NULL);

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
	bbs_register_alerter(alertmsg, 90);
	return 0;
}

static int unload_module(void)
{
	unsigned int i;
	bbs_unregister_alerter(alertmsg);
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
	pthread_mutex_destroy(&virt_lock);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC9051 IMAP", "mod_mail.so,mod_mimeparse.so");
