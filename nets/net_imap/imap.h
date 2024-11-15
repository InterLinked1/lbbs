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

/*! \note mod_webmail also has an imap_client struct. These are not the same. */
struct imap_client {
	const char *name;			/* Same as virtprefix */
	const char *virtprefix;		/* Mapping prefix defined in .imapremote */
	struct imap_session *imap;	/* Pointer to the IMAP session that owns this connection */
	size_t virtprefixlen;		/* Length of virtprefix */
	int virtcapabilities;		/* Capabilities of remote IMAP server */
	char virtdelimiter;			/* Hierarchy delimiter used by remote server */
	char *virtlist;				/* Result of LIST-STATUS command on remote IMAP server */
	time_t created;				/* Time client was created */
	time_t virtlisttime;		/* Time that LIST-STATUS command was run */
	time_t lastactive;			/* Last active time */
	char *bgmailbox;			/* Mail for background IDLE */
	time_t idlestarted;			/* Time that IDLE started */
	int maxidlesec;				/* Max amount of time for which we can IDLE */
	unsigned int active:1;		/* Client is currently in use */
	unsigned int idling:1;		/* Idling, unattended */
	unsigned int dead:1;		/* Connection is already dead */
	RWLIST_ENTRY(imap_client) entry;
	struct bbs_tcp_client client;	/* TCP client for virtual mailbox access on remote servers */
	/*! \note Must be large enough to get all the CAPABILITYs/headers, or bbs_readline will throw a warning about buffer exhaustion and return 0 */
	char buf[8192];					/* Readline buffer */
	char data[0];
};

RWLIST_HEAD(imap_client_list, imap_client);

struct imap_notify;

struct imap_session {
	char *tag;
	struct bbs_node *node;
	struct mailbox *mbox;		/* Current mailbox (mailbox as in entire mailbox, not just a mailbox folder) */
	struct mailbox *mymbox;		/* Pointer to user's private/personal mailbox. */
	char *folder;				/* Currently selected mailbox */
	char *savedtag;
	int pfd[2];					/* Pipe for delayed responses */
	/* maildir */
	char dir[256];
	char newdir[260]; /* 4 more, for /new and /cur */
	char curdir[260];
	struct imap_client *client;			/* Current IMAP client for proxied connections to remote servers (if any) */
	struct imap_client_list clients;	/* List of all IMAP clients to remote servers */
	struct stringlist remotemailboxes;	/* List of remote mailboxes */
	unsigned int uidvalidity;
	unsigned int uidnext;
	unsigned long highestmodseq;	/* Cached HIGHESTMODSEQ for current folder */
	int acl;					/* Cached ACL for current directory. We allowed to cache per a mailbox by the RFC. */
	char *savedsearch;			/* SEARCHRES */
	char *clientid;				/* Client ID */
	struct readline_data *rldata;	/* Pointer to rldata used for reading input from client */
	char appendkeywords[27];	/* APPEND keywords (custom flags) */
	unsigned int numappendkeywords:5; /* Number of append keywords. We only need 5 bits since this cannot exceed 26. */
	unsigned int createdkeyword:1;	/* Whether a keyword was created in response to a STORE */
	/* Other flags */
	unsigned int savedsearchuid:1;	/* Whether the saved search consists of sequence numbers or UIDs */
	/* Traversal flags */
	unsigned int totalnew;		/* In "new" maildir. Will be moved to "cur" when seen. */
	unsigned int totalcur;		/* In "cur" maildir. */
	unsigned int minrecent;		/* Smallest sequence number message that is considered \Recent */
	unsigned int maxrecent;		/* Largest sequence number message that is considered \Recent (possibly redundant?) */
	unsigned int totalunseen;	/* Messages with Unseen flag (or more rather, without the Seen flag). */
	unsigned long totalsize;	/* Total size of mailbox */
	unsigned int firstunseen;	/* Oldest message that is not Seen. */
	unsigned int expungeindex;	/* Index for EXPUNGE */
	unsigned int innew:1;		/* So we can use the same callback for both new and cur */
	unsigned int readonly:1;	/* SELECT vs EXAMINE */
	unsigned int inauth:1;
	unsigned int idle:1;		/* Whether IDLE is active */
	unsigned int dnd:1;			/* Do Not Disturb: Whether client is executing a FETCH, STORE, or SEARCH command (EXPUNGE responses are not allowed) */
	unsigned int pending:1;		/* Delayed output is pending in pfd pipe */
	unsigned int expungepending:1;	/* EXPUNGE updates pending in pipe */
	unsigned int alerted:2;		/* An alert has been delivered to this client */
	unsigned int condstore:1;	/* Whether a client has issue a CONDSTORE enabling command, and should be sent MODSEQ updates in untagged FETCH responses */
	unsigned int qresync:1;		/* Whether a client has enabled the QRESYNC capability */
	struct imap_notify *notify;	/* NOTIFY events */
	bbs_mutex_t lock;		/* Lock for IMAP session */
	RWLIST_ENTRY(imap_session) entry;	/* Next active session */
};

struct imap_traversal {
	struct imap_session *imap;
	struct imap_client *client;
	struct mailbox *mbox;
	unsigned int uidvalidity;
	unsigned int uidnext;
	int acl;					/* ACL for the mailbox being traversed */
	/* Traversal flags: subset of IMAP session structure */
	unsigned int totalnew;		/* In "new" maildir. Will be moved to "cur" when seen. */
	unsigned int totalcur;		/* In "cur" maildir. */
	unsigned int minrecent;		/* Smallest sequence number message that is considered \Recent */
	unsigned int maxrecent;		/* Largest sequence number message that is considered \Recent (possibly redundant?) */
	unsigned int totalunseen;	/* Messages with Unseen flag (or more rather, without the Seen flag). */
	unsigned long totalsize;	/* Total size of mailbox */
	unsigned int firstunseen;	/* Oldest message that is not Seen. */
	unsigned int innew:1;		/* So we can use the same callback for both new and cur. Does not persist outside of traversal. */
	unsigned int readonly:1;	/* SELECT vs EXAMINE */
	/* maildir */
	char dir[256];
	char newdir[260]; /* 4 more, for /new and /cur */
	char curdir[260];
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

/*!
 * \note For use within possibly or definitely parallel jobs. This is separate to avoid overhead of checking if we know it's not parallel.
 */
#define _imap_parallel_reply(imap, fmt, ...) \
	if (imap->node->thread == pthread_self()) { \
		_imap_reply(imap, fmt, ## __VA_ARGS__); \
	} else { \
		__imap_parallel_reply(imap, fmt, ## __VA_ARGS__); \
	}

#define __imap_parallel_reply(imap, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); bbs_node_any_fd_writef(imap->node, imap->node->wfd, fmt, ## __VA_ARGS__);

#define _imap_reply_nolock_fd(imap, fd, fmt, ...) imap_debug(4, "%p <= " fmt, imap, ## __VA_ARGS__); bbs_node_fd_writef(imap->node, fd, fmt, ## __VA_ARGS__);
#define _imap_reply_nolock_fd_lognewline(imap, fd, fmt, ...) imap_debug(4, "%p <= " fmt "\r\n", imap, ## __VA_ARGS__); bbs_node_fd_writef(imap->node, fd, fmt, ## __VA_ARGS__);
#define _imap_reply_nolock(imap, fmt, ...) _imap_reply_nolock_fd(imap, imap->node->wfd, fmt, ## __VA_ARGS__);
#define _imap_reply(imap, fmt, ...) _imap_reply_nolock(imap, fmt, ## __VA_ARGS__)
#define imap_send_nocrlf(imap, fmt, ...) _imap_reply_nolock_fd_lognewline(imap, imap->node->wfd, fmt, ## __VA_ARGS__);
#define imap_send(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", "*", ## __VA_ARGS__)
#define imap_reply(imap, fmt, ...) _imap_reply(imap, "%s " fmt "\r\n", imap->tag, ## __VA_ARGS__)

#define imap_parallel_send(imap, fmt, ...) _imap_parallel_reply(imap, "%s " fmt "\r\n", "*", ## __VA_ARGS__)

#define REQUIRE_ARGS(s) \
	if (!s || !*s) { \
		imap_reply(imap, "BAD [CLIENTBUG] Missing arguments"); \
		return 0; \
	}

void send_untagged_fetch(struct imap_session *imap, int seqno, unsigned int uid, unsigned long modseq, const char *newflags);

int imap_in_range(struct imap_session *imap, const char *s, int num);

unsigned int imap_msg_in_range(struct imap_session *imap, int seqno, const char *filename, const char *sequences, int usinguid, int *error);

int local_status(struct imap_session *imap, struct imap_traversal *traversal, const char *mailbox, const char *items);
