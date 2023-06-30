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
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/utils.h"
#include "include/stringlist.h"

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
	size_t virtprefixlen;		/* Length of virtprefix */
	int virtcapabilities;		/* Capabilities of remote IMAP server */
	char virtdelimiter;			/* Hierarchy delimiter used by remote server */
	char *virtlist;				/* Result of LIST-STATUS command on remote IMAP server */
	int virtlisttime;			/* Time that LIST-STATUS command was run */
	struct stringlist remotemailboxes;	/* List of remote mailboxes */
	unsigned int uidvalidity;
	unsigned int uidnext;
	unsigned long highestmodseq;	/* Cached HIGHESTMODSEQ for current folder */
	int acl;					/* Cached ACL for current directory. We allowed to cache per a mailbox by the RFC. */
	char *savedsearch;			/* SEARCHRES */
	char *clientid;				/* Client ID */
	struct bbs_tcp_client client;	/* TCP client for virtual mailbox access on remote servers */
	struct readline_data *rldata;	/* Pointer to rldata used for reading input from client */
	char appendkeywords[27];	/* APPEND keywords (custom flags) */
	unsigned int numappendkeywords:5; /* Number of append keywords. We only need 5 bits since this cannot exceed 26. */
	unsigned int createdkeyword:1;	/* Whether a keyword was created in response to a STORE */
	/* Other flags */
	unsigned int savedsearchuid:1;	/* Whether the saved search consists of sequence numbers or UIDs */
	/* Traversal flags */
	unsigned int totalnew;		/* In "new" maildir. Will be moved to "cur" when seen. */
	unsigned int totalcur;		/* In "cur" maildir. */
	unsigned int totalunseen;	/* Messages with Unseen flag (or more rather, without the Seen flag). */
	unsigned long totalsize;	/* Total size of mailbox */
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

#define HIERARCHY_DELIMITER "."
#define HIERARCHY_DELIMITER_CHAR '.'

/* RFC 2342 Namespaces: prefix and hierarchy delimiter */
/* #define PRIVATE_NAMESPACE_PREFIX "" */
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

enum mailbox_namespace {
	NAMESPACE_PRIVATE = 0,
	NAMESPACE_OTHER,
	NAMESPACE_SHARED,
};

#define imap_debug(level, fmt, ...) if (imap_debug_level >= level) { bbs_debug(level, fmt, ## __VA_ARGS__); }

#ifndef IMAP_MAIN_FILE
extern int imap_debug_level;
#endif

#undef dprintf
#define _imap_reply_nolock(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); dprintf(imap->wfd, fmt, ## __VA_ARGS__);
#define _imap_reply(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); pthread_mutex_lock(&imap->lock); dprintf(imap->wfd, fmt, ## __VA_ARGS__); pthread_mutex_unlock(&imap->lock);
#define imap_send(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", "*", ## __VA_ARGS__)
#define imap_reply(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", imap->tag, ## __VA_ARGS__)

#define REQUIRE_ARGS(s) \
	if (!s || !*s) { \
		imap_reply(imap, "BAD [CLIENTBUG] Missing arguments"); \
		return 0; \
	}

/*! \brief Faster than strncat, since we store our position between calls, but maintain its safety */
#define SAFE_FAST_COND_APPEND(bufstart, bufsize, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, (size_t) buflen, bufpos == bufstart ? fmt : " " fmt, ## __VA_ARGS__); \
		bufpos += (typeof((buflen))) _bytes; \
		buflen -= (typeof((buflen))) _bytes; \
		if ((int) buflen <= 0) { \
			bbs_warning("Buffer truncation\n"); \
			*(bufstart + bufsize - 1) = '\0';  \
		} \
	}

#define SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufsize, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, (size_t) buflen, fmt, ## __VA_ARGS__); \
		bufpos += (typeof((buflen))) _bytes; \
		buflen -= (typeof((buflen))) _bytes; \
		if ((int) buflen <= 0) { \
			bbs_warning("Buffer truncation\n"); \
			*(bufstart + bufsize - 1) = '\0';  \
		} \
	}

void send_untagged_fetch(struct imap_session *imap, int seqno, unsigned int uid, unsigned long modseq, const char *newflags);

int imap_in_range(struct imap_session *imap, const char *s, int num);

unsigned int imap_msg_in_range(struct imap_session *imap, int seqno, const char *filename, const char *sequences, int usinguid, int *error);

int local_status(struct imap_session *imap, const char *mailbox, const char *items);
