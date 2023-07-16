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
 * \note Supports RFC 2088 LITERAL+ (for APPEND only)
 * \note Supports RFC 2177 IDLE
 * \note Supports RFC 2342 NAMESPACE
 * \note Supports RFC 4315 UIDPLUS (obsoletes RFC 2359)
 * \note Supports RFC 2971 ID
 * \note Supports RFC 3348 CHILDREN
 * \note Supports RFC 3502 MULTIAPPEND
 * \note Supports RFC 3691 UNSELECT
 * \note Supports RFC 4314 ACLs
 * \note Supports RFC 4466, 4731 SEARCH extensions
 * \note Supports RFC 4467 URLAUTH (partially) for RFC 4468 BURL
 * \note Supports RFC 4959 SASL-IR
 * \note Supports RFC 5032 WITHIN (OLDER, YOUNGER)
 * \note Supports RFC 5161 ENABLE
 * \note Supports RFC 5182 SEARCHRES
 * \note Supports RFC 5256 SORT
 * \note Supports RFC 5256 THREAD (ORDEREDSUBJECT and REFERENCES)
 * \note Supports RFC 5258 LIST-EXTENDED
 * \note Supports RFC 5267 ESORT
 * \note Supports RFC 5423 mail store events
 * \note Supports RFC 5465 NOTIFY
 * \note Supports RFC 5530 Response Codes
 * \note Supports RFC 5819 LIST-STATUS
 * \note Supports RFC 6154 SPECIAL-USE (but not CREATE-SPECIAL-USE)
 * \note Supports RFC 6851 MOVE
 * \note Supports RFC 7162 CONDSTORE (obsoletes RFC 4551)
 * \note Supports RFC 7162 QRESYNC (obsoletes RFC 5162)
 * \note Supports RFC 7889 APPENDLIMIT
 * \note Supports RFC 8437 UNAUTHENTICATE
 * \note Supports RFC 8438 STATUS=SIZE
 * \note Supports RFC 9208 QUOTA
 *
 * \note STARTTLS is not supported for cleartext IMAP, as proposed in RFC2595, as this guidance
 *       is obsoleted by RFC8314. Implicit TLS (IMAPS) should be preferred.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*! \todo IMAP functionality not yet implemented/supported:
 * - RFC 4469 CATENATE
 * - RFC 4959 SASL-IR
 * - RFC 4978 COMPRESS=DEFLATE
 * - RFC 5255 LANGUAGE
 * - RFC 5257 ANNOTATE, RFC 5464 ANNOTATE (METADATA)
 * - RFC 5258 LIST extensions (obsoletes 3348)
 * - RFC 5267 CONTEXT=SEARCH and CONTEXT=SORT
 * - RFC 5738 UTF8
 * - RFC 5957 DISPLAYFROM/DISPLAYTO
 * - RFC 6203 FUZZY SEARCH
 * - RFC 6237 ESEARCH (MULTISEARCH)
 * - RFC 6785 IMAPSIEVE
 * - RFC 6855 UTF8=ACCEPT, UTF8=ONLY
 * - RFC 7888 LITERAL-
 * - RFC 8970 PREVIEW
 * - RFC 9394 PARTIAL
 * - BINARY extensions (RFC 3516, 4466)
 * - CLIENTID: https://datatracker.ietf.org/doc/html/draft-yu-imap-client-id-10
 *             https://datatracker.ietf.org/doc/html/draft-storey-smtp-client-id-15
 * - UIDONLY: https://www.rfc-editor.org/rfc/internet-drafts/draft-ietf-extra-imap-uidonly-01.html
 * Other capabilities: AUTH=PLAIN-CLIENTTOKEN AUTH=OAUTHBEARER AUTH=XOAUTH AUTH=XOAUTH2
 */

#define IMAP_REV "IMAP4rev1"
/* List of capabilities: https://www.iana.org/assignments/imap-capabilities/imap-capabilities.xml */
/* XXX IDLE is advertised here even if disabled (although if disabled, it won't work if a client tries to use it) */
/* XXX URLAUTH is advertised so that SMTP BURL will function in Trojita, even though we don't need URLAUTH since we have a direct trust */
#define IMAP_CAPABILITIES IMAP_REV " AUTH=PLAIN UNSELECT UNAUTHENTICATE SPECIAL-USE LIST-EXTENDED LIST-STATUS XLIST CHILDREN IDLE NOTIFY NAMESPACE QUOTA QUOTA=RES-STORAGE ID SASL-IR ACL SORT THREAD=ORDEREDSUBJECT THREAD=REFERENCES URLAUTH ESEARCH ESORT SEARCHRES UIDPLUS LITERAL+ MULTIAPPEND APPENDLIMIT MOVE WITHIN ENABLE CONDSTORE QRESYNC STATUS=SIZE"

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
 *
 * Capabilities supported by Thunderbird client:
 * https://wiki.mozilla.org/MailNews:Supported_IMAP_extensions
 * https://github.com/mozilla/releases-comm-central/blob/master/mailnews/imap/src/nsImapServerResponseParser.cpp#L1880
 * AUTH=LOGIN, AUTH=PLAIN, AUTH=CRAM-MD5, AUTH=NTLM, AUTH=GSSAPI, AUTH=MSN, AUTH=EXTERNAL, AUTH=XOAUTH2,
 * STARTTLS, LOGINDISABLED, XSENDER, IMAP4, IMAP4rev1, X-NO-ATOMIC-RENAME, X-NON-HIERARCHICAL-RENAME,
 * NAMESPACE, ID, ACL, XSERVERINFO, UIDPLUS, LITERAL+, XAOL-OPTION, X-GM-EXT-1, QUOTA, LANGUAGE, IDLE,
 * CONDSTORE, ENABLE, LIST-EXTENDED, XLIST, SPECIAL-USE, COMPRESS=DEFLATE, MOVE, HIGHESTMODSEQ, CLIENTID,
 * UTF8=ACCEPT, UTF8=ONLY
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <ftw.h>
#include <poll.h>
#include <utime.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/test.h"
#include "include/notify.h"
#include "include/oauth.h"
#include "include/base64.h"
#include "include/range.h"

#include "include/mod_mail.h"

#define IMAP_MAIN_FILE
#include "nets/net_imap/imap.h"
#undef IMAP_MAIN_FILE

#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_server_acl.h"
#include "nets/net_imap/imap_server_flags.h"
#include "nets/net_imap/imap_server_list.h"
#include "nets/net_imap/imap_server_fetch.h"
#include "nets/net_imap/imap_server_search.h"
#include "nets/net_imap/imap_server_notify.h"
#include "nets/net_imap/imap_client.h"
#include "nets/net_imap/imap_client_list.h"
#include "nets/net_imap/imap_client_status.h"

int imap_debug_level = 10;

/* IMAP ports */
#define DEFAULT_IMAP_PORT 143
#define DEFAULT_IMAPS_PORT 993

static int imap_port = DEFAULT_IMAP_PORT;
static int imaps_port = DEFAULT_IMAPS_PORT;

static int imap_enabled = 0, imaps_enabled = 1;

static int allow_idle = 1;
static int idle_notify_interval = 600; /* Every 10 minutes, by default */

/*! \brief Allow storage of messages up to 25MB. User can decide if that's really a good use of mail quota or not... */
static unsigned int max_append_size = SIZE_MB(25);

/* Used extern by imap_client.c */
unsigned int maxuserproxies = 10;

#define MAX_USER_PROXIES 32

/* All IMAP traversals must be ordered, so we can't use these functions or we'll get a ~random (at least incorrect) order */
/* Sequence numbers must strictly be in order, if they aren't, all sorts of weird stuff will happened.
 * I know this because I tried using these functions first, and it didn't really work.
 * Because scandir allocates memory for all the files in a directory up front, it could result in a lot of memory usage.
 * Technically, for this reason, may want to limit the number of messages in a single mailbox (folder) for this reason.
 */
#define opendir __Do_not_use_readdir_or_opendir_use_scandir
#define readdir __Do_not_use_readdir_or_opendir_use_scandir
#define closedir __Do_not_use_readdir_or_opendir_use_scandir
#define alphasort __Do_not_use_alphasort_use_imap_uidsort
#if defined(opendir) || defined(readdir) || defined(closedir) || defined(alphasort)
/* Dummy usage for -Wunused-macros */
#endif

struct preauth_ip {
	const char *range;
	const char *username;
	RWLIST_ENTRY(preauth_ip) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(preauths, preauth_ip);

static void add_preauth_ip(const char *range, const char *username)
{
	struct preauth_ip *ip;
	size_t rangelen = strlen(range);
	size_t userlen = strlen(username);

	ip = calloc(1, sizeof(*ip) + rangelen + userlen + 2);
	if (ALLOC_FAILURE(ip)) {
		return;
	}

	strcpy(ip->data, range); /* Safe */
	ip->range = ip->data;
	strcpy(ip->data + rangelen + 1, username); /* Safe */
	ip->username = ip->data + rangelen + 1;

	RWLIST_WRLOCK(&preauths);
	RWLIST_INSERT_HEAD(&preauths, ip, entry);
	RWLIST_UNLOCK(&preauths);
}

static const char *preauth_username_match(const char *ipaddr)
{
	struct preauth_ip *ip;
	RWLIST_RDLOCK(&preauths);
	RWLIST_TRAVERSE(&preauths, ip, entry) {
		if (bbs_ip_match_ipv4(ipaddr, ip->range)) {
			bbs_debug(5, "Authorized by IP/CIDR match: %s\n", ip->range);
			RWLIST_UNLOCK(&preauths);
			return ip->username; /* Safe to return unlocked, since preauth_ip's are not cleaned up until exit. */
		}
	}
	RWLIST_UNLOCK(&preauths);
	return NULL;
}

static RWLIST_HEAD_STATIC(sessions, imap_session);

static inline void reset_saved_search(struct imap_session *imap)
{
	free_if(imap->savedsearch); /* See comments about EXPUNGE in imap_expunge */
	imap->savedsearch = 0;
}

/* We traverse cur first, since messages from new are moved to cur, and we don't want to double count them */
#define IMAP_TRAVERSAL(imap, traversal, callback, rdonly) \
	if (mailbox_rdlock(traversal->mbox)) { \
		imap_reply(imap, "NO [INUSE] Mailbox busy"); \
		return 0; \
	} \
	traversal->imap = imap; \
	traversal->readonly = rdonly; \
	traversal->totalnew = 0; \
	traversal->totalcur = 0; \
	traversal->totalsize = 0; \
	traversal->totalunseen = 0; \
	traversal->firstunseen = 0; \
	traversal->innew = 0; \
	traversal->uidvalidity = 0; \
	traversal->uidnext = 0; \
	imap_traverse(traversal->curdir, callback, traversal); \
	traversal->innew = 1; \
	traversal->minrecent = traversal->totalcur + 1; \
	imap_traverse(traversal->newdir, callback, traversal); \
	traversal->maxrecent = traversal->totalcur + traversal->totalnew; \
	if (!traversal->uidvalidity || !traversal->uidnext) { \
		mailbox_get_next_uid(traversal->mbox, traversal->imap->node, traversal->dir, 0, &traversal->uidvalidity, &traversal->uidnext); \
	} \
	mailbox_unlock(traversal->mbox);

static void set_traversal(struct imap_session *imap, struct imap_traversal *traversal)
{
	traversal->mbox = imap->mbox;
	strcpy(traversal->dir, imap->dir);
	strcpy(traversal->curdir, imap->curdir);
	strcpy(traversal->newdir, imap->newdir);
}

static void save_traversal(struct imap_session *imap, struct imap_traversal *traversal)
{
#define TRAVERSAL_PERSIST(name) imap->name = traversal->name
	TRAVERSAL_PERSIST(totalnew);
	TRAVERSAL_PERSIST(totalcur);
	TRAVERSAL_PERSIST(totalsize);
	TRAVERSAL_PERSIST(totalunseen);
	TRAVERSAL_PERSIST(innew);
	TRAVERSAL_PERSIST(uidvalidity);
	TRAVERSAL_PERSIST(uidnext);
	TRAVERSAL_PERSIST(minrecent);
	TRAVERSAL_PERSIST(maxrecent);
#undef TRAVERSAL_PERSIST
}

#define imap_send_update(imap, s, len) __imap_send_update(imap, s, len, 0, 0)
#define __imap_send_update(imap, s, len, forcenow, invalidate) __imap_send_update_log(imap, s, len, forcenow, invalidate, __LINE__)

/*! \note Must be called with imap locked */
static void __imap_send_update_log(struct imap_session *imap, const char *s, size_t len, int forcenow, int invalidate, int line)
{
	int delay = 0;

	/* We are only free to send responses whenever we want if the client is idling, or if NOTIFY SELECTED is active. */
	delay = !imap_sequence_numbers_prohibited(imap) && !imap->idle;

	/* Since we're locked in this function, we CANNOT use imap_send */
	if (delay && !forcenow) {
		imap_debug(4, "%d: %p <= %s", line, imap, s); /* Already ends in CR LF */
		bbs_write(imap->pfd[1], s, len);
		imap->pending = 1;
		if (invalidate) {
			reset_saved_search(imap); /* Since messages were expunged, invalidate any saved search */
		}
	} else {
		imap_debug(4, "%d: %p <= %s", line, imap, s); /* Already ends in CR LF */
		bbs_write(imap->wfd, s, (unsigned int) len);
	}
}

/* Forward declaration */
static int generate_status(struct imap_session *imap, const char *folder, char *buf, size_t len, const char *items);

static int generate_mailbox_name(unsigned int userid, const char *restrict maildir, char *restrict buf, size_t len)
{
	size_t rootlen, fulllen;
	unsigned int muserid;
	const char *fulldir = maildir;
	const char *rootdir = mailbox_maildir(NULL);

	rootlen = strlen(rootdir);
	fulllen = strlen(fulldir);

	if (fulllen <= rootlen) {
		bbs_error("Maildir length %lu <= root maildir length %lu?\n", fulllen, rootlen);
		return -1;
	}

	fulldir += rootlen;
	if (*fulldir == '/') {
		fulldir++;
	}

	if (strlen_zero(fulldir)) {
		bbs_error("Invalid maildir\n");
		return -1;
	}

	muserid = (unsigned int) atoi(fulldir);
	if (muserid) {
		const char *bname = basename(fulldir);
		/* User dir */
		if (muserid == userid) {
			/* It's our personal mailbox */
			if (atoi(bname)) {
				/* INBOX */
				safe_strncpy(buf, "INBOX", len);
			} else {
				/* Skip leading . for maildir++ */
				bname++; /* Skip leading . */
				safe_strncpy(buf, bname, len);
			}
		} else {
			/* Another user (Other Users) */
			char username[64];
			if (bbs_username_from_userid(muserid, username, sizeof(username))) {
				bbs_warning("No user for maildir %s\n", fulldir);
				return -1;
			}
			snprintf(buf, len, OTHER_NAMESPACE_PREFIX HIERARCHY_DELIMITER "%s.%s", username, bname);
		}
	} else {
		snprintf(buf, len, SHARED_NAMESPACE_PREFIX HIERARCHY_DELIMITER "%s", fulldir);
	}
	bbs_debug(6, "maildir %s => '%s'\n", maildir, buf);
	return 0;
}

void send_untagged_fetch(struct imap_session *imap, int seqno, unsigned int uid, unsigned long modseq, const char *newflags)
{
	struct imap_session *s;
	char normalmsg[256];
	char condstoremsg[256];
	char status_items[256];
	size_t normallen, condlen;
	int didstatus = 0;

	/* Prepare both types of messages.
	 * Each client currently in this same mailbox will get one message or the other,
	 * depending on its value of imap->condstore
	 */
	normallen = (size_t) snprintf(normalmsg, sizeof(normalmsg), "* %d FETCH (%s)\r\n", seqno, newflags);
	condlen = (size_t) snprintf(condstoremsg, sizeof(condstoremsg), "* %d FETCH (UID %u MODSEQ %lu %s)\r\n", seqno, uid, modseq, newflags); /* RFC 7162 3.2.4 */

	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		int res;
		char mboxname[256];
		if (s == imap) { /* Skip if the update was caused by the client */
			continue;
		}
		/* imap->folder is maybe not the same name for s.
		 * We convert the maildir path to the name for s, though this is a little bit roundabout.
		 * Would be easier if generate_status could accept a maildir as well instead of just a name.
		 * This also applies anywhere else generate_status is called.
		 */
		/*! \todo Ideally this would be a static mail store based callback, and then instead of imap->dir we could use e->maildir */
		generate_mailbox_name(s->node->user->id, imap->dir, mboxname, sizeof(mboxname));
		res = imap_notify_applicable(s, NULL, mboxname, imap->dir, IMAP_EVENT_FLAG_CHANGE);
		if (!res) {
			continue;
		}
		if (res == -1 && !didstatus) {
			generate_status(imap, mboxname, status_items, sizeof(status_items), "UNSEEN MESSAGES UIDVALIDITY HIGHESTMODSEQ");
			didstatus = 1;
		}
		pthread_mutex_lock(&s->lock);
		if (res == -1) { /* Not currently selected */
			char statusmsgfull[256];
			/* The same STATUS response can be used for all clients, but the mailbox name might be different */
			size_t statuslenfull = (size_t) snprintf(statusmsgfull, sizeof(statusmsgfull), "* STATUS \"%s\" (%s)\r\n", mboxname, status_items);
			imap_send_update(s, statusmsgfull, statuslenfull);
		} else { /* Currently selected */
			imap_send_update(s, s->condstore ? condstoremsg : normalmsg, s->condstore ? condlen : normallen);
		}
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
}

static void send_untagged_expunge(struct bbs_node *node, struct mailbox *mbox, const char *maildir, int silent, unsigned int *uid, unsigned int *seqno, int length)
{
	char status_items[256];
	int didstatus = 0;
	struct imap_session *s;
	char *str2, *str = NULL;
	size_t slen = 0, slen2; /* slen does not actually need to be initialized, but this avoids an erroneous -Wmaybe-uninitialized with gcc */

	if (!length) {
		return;
	}

	/* This can only happen when POP3 expunges messages, and this mailbox cannot be in use when POP3 is using the mailbox.
	 * So if seqno were ever NULL here, that would be a bug on multiple fronts. */
	bbs_assert_exists(seqno);

	/* Send VANISHED responses to any clients that enabled QRESYNC, and normal EXPUNGE responses to everyone else. */
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		int res;
		int forcenow = s->node == node; /* Echo untagged EXPUNGE to the sender in realtime, while the initiating command is running */
		char mboxname[256];
		/* This one also goes to ourself... unless silent */
		if (s->node == node && silent) {
			continue;
		}
		/* We can't pass the mailbox name into send_untagged_expunge anyways,
		 * because mailbox names might be different for different users (e.g. Other Users) */
		generate_mailbox_name(s->node->user->id, maildir, mboxname, sizeof(mboxname));
		res = imap_notify_applicable(s, mbox, mboxname, maildir, IMAP_EVENT_MESSAGE_EXPUNGE);
		if (!res) {
			continue;
		}
		if (res == -1 && !didstatus) {
			/* RFC 5465 5.3 */
			generate_status(s, mboxname, status_items, sizeof(status_items), "UIDNEXT MESSAGES HIGHESTMODSEQ");
			didstatus = 1;
		}
		pthread_mutex_lock(&s->lock);
		if (res == -1) {
			char statusmsgfull[256];
			size_t statuslenfull = (size_t) snprintf(statusmsgfull, sizeof(statusmsgfull), "* STATUS \"%s\" (%s)\r\n", mboxname, status_items);
			__imap_send_update(s, statusmsgfull, statuslenfull, forcenow, 1);
		} else {
			if (s->qresync) { /* VANISHED */
				if (!str) {
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
				__imap_send_update(s, str, slen, forcenow, 1);
			} else { /* EXPUNGE */
				int i;
				for (i = 0; i < length; i++) {
					char normalmsg[64];
					size_t normallen = (size_t) snprintf(normalmsg, sizeof(normalmsg), "* %u EXPUNGE\r\n", seqno[i]);
					__imap_send_update(s, normalmsg, normallen, forcenow, 1);
				}
			}
		}
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
	free_if(str);
}

/*! \brief Callback for sending EXISTS alerts to idling clients */
static void send_untagged_exists(struct bbs_node *node, struct mailbox *mbox, const char *maildir)
{
	char buf[256];
	char status_items[256];
	int didstatus = 0;
	size_t len = 0;
	int numrecent = -1;
	int numtotal = -1;
	struct imap_session *s;

	/* Notify anyone watching this mailbox, specifically the INBOX. */
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		int res;
		char mboxname[256];
		const char *fetchargs = NULL;

		generate_mailbox_name(s->node->user->id, maildir, mboxname, sizeof(mboxname));

		res = imap_notify_applicable_fetchargs(s, mbox, mboxname, maildir, IMAP_EVENT_MESSAGE_NEW, &fetchargs);
		if (!res) {
			continue;
		}
		if (res == 1) {
			if (numtotal == -1) { /* Calculate the number of messages "just in time", only if needed. */
				/* Compute how many messages exist. */
				numrecent = bbs_dir_num_files(s->newdir);
				numtotal = numrecent + bbs_dir_num_files(s->curdir);
				bbs_debug(4, "Calculated %d message%s in INBOX %d currently\n", numtotal, ESS(numtotal), mailbox_id(mbox));
				if (numrecent) {
					len = (size_t) snprintf(buf, sizeof(buf), "* %d EXISTS\r\n* %d RECENT\r\n", numtotal, numrecent);
				} else {
					len = (size_t) snprintf(buf, sizeof(buf), "* %d EXISTS\r\n", numtotal); /* Number of messages in the mailbox. */
				}
			}
			if (numtotal < 1) {
				/* Should be at least 1, because this callback is triggered when we get a NEW message. So there's at least that one. */
				bbs_error("Expected at least %d message, but calculated %d?\n", 1, numtotal);
				continue; /* Don't send the client something clearly bogus */
			}
		}

		if (res == -1 && !didstatus) {
			/* STATUS (RFC 5465 5.2). Also include UNSEEN since this may be unread and the client will want to know to update unread count. */
			generate_status(s, mboxname, status_items, sizeof(status_items), "UIDNEXT MESSAGES UNSEEN HIGHESTMODSEQ");
			didstatus = 1;
		}

		/* Note that we're allowed to send just a single untagged EXISTS for multiple events (RFC 5465 3.2),
		 * but we'd need to send a FETCH per matching message.
		 * Again for \Recent messages this is going to be tricky/impossible. */

		pthread_mutex_lock(&s->lock);
		/* RFC 3501 Section 7: unilateral response */
		if (res == -1) {
			char statusmsgfull[256];
			size_t statuslenfull = (size_t) snprintf(statusmsgfull, sizeof(statusmsgfull), "* STATUS \"%s\" (%s)\r\n", mboxname, status_items);
			imap_send_update(s, statusmsgfull, statuslenfull);
			pthread_mutex_unlock(&s->lock);
		} else {
			imap_send_update(s, buf, len);
			pthread_mutex_unlock(&s->lock);
			/* Unlock because send_fetch_response assumes an unlocked session.
			 * XXX Since sessions, the session technically can't disappear on us,
			 * but this does leave open the possibility of interleaved writes. */
			/* XXX Also for \Recent messages, FETCH might not work properly */
			if (fetchargs && s->node != node) { /* Never send FETCH responses to initiator of event */
				char fetchargsfull[256];
				snprintf(fetchargsfull, sizeof(fetchargsfull), "%d (%s)", numtotal, fetchargs);
				handle_fetch_full(s, fetchargsfull, 0, 0);
			}
		}
	}
	RWLIST_UNLOCK(&sessions);
}

static void send_untagged_list(struct bbs_node *node, enum mailbox_event_type type, struct mailbox *mbox, const char *maildir, const char *oldmaildir)
{
	struct imap_session *s;

	/* Notify anyone watching this mailbox, specifically the INBOX. */
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		int res;
		char buf[256];
		char olddir[256], newdir[256];
		size_t len = 0;
		const char *fetchargs = NULL;

		if (node == s->node) {
			/* RFC 5465 Section 5: avoid notifying client if this was caused by that client */
			continue;
		}

		/* Mailbox names could be different for different users, so need to do per session, not just once */
		generate_mailbox_name(s->node->user->id, maildir, newdir, sizeof(newdir));

		res = imap_notify_applicable_fetchargs(s, mbox, newdir, maildir, IMAP_EVENT_MESSAGE_NEW, &fetchargs);
		if (!res) {
			continue;
		}

		/* RFC 5465 5.4 */

		/* XXX SHOULD also include \HasChildren or \HasNoChildren */
		switch (type) {
			case EVENT_MAILBOX_CREATE:
				len = (size_t) snprintf(buf, sizeof(buf), "* LIST (\\Subscribed) \"%c\" \"%s\"\r\n", HIERARCHY_DELIMITER_CHAR, newdir);
				break;
			case EVENT_MAILBOX_DELETE:
				len = (size_t) snprintf(buf, sizeof(buf), "* LIST (\\NonExistent) \"%c\" \"%s\"\r\n", HIERARCHY_DELIMITER_CHAR, newdir);
				break;
			case EVENT_MAILBOX_RENAME:
				generate_mailbox_name(s->node->user->id, oldmaildir, olddir, sizeof(olddir));
				len = (size_t) snprintf(buf, sizeof(buf), "* LIST (\\Subscribed) \"%c\" \"%s\" (\"OLDNAME\" (\"%s\"))\r\n", HIERARCHY_DELIMITER_CHAR, newdir, olddir);
				break;
			default:
				break;
		}

		pthread_mutex_lock(&s->lock);
		imap_send_update(s, buf, len);
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
}

static void send_untagged_uidvalidity(struct mailbox *mbox, const char *maildir, unsigned int uidvalidity)
{
	char buf[256];
	size_t len;
	struct imap_session *s;

	/* This should never happen, but if the UIDVALIDITY of a mailbox changes,
	 * we MUST notify any clients currently using it.
	 * Use same format as UIDVALIDITY response to SELECT/EXAMINE (RFC 2683 3.4.3) */
	len = (size_t) snprintf(buf, sizeof(buf), "* OK [UIDVALIDITY %u] New UIDVALIDITY value!\r\n", uidvalidity);

	/* Notify anyone watching this mailbox, specifically the INBOX. */
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		if (s->mbox != mbox || strcmp(s->dir, maildir)) {
			continue;
		}

		/* If same mailbox selected, send UIDVALIDITY */
		pthread_mutex_lock(&s->lock);
		imap_send_update(s, buf, len);
		pthread_mutex_unlock(&s->lock);
	}
	RWLIST_UNLOCK(&sessions);
}

/*! \brief Callback for all mailbox events */
static void imap_mbox_watcher(struct mailbox_event *event)
{
	/* Accessing certain fields directly, e.g. event->type is okay,
	 * but resist the urge to access other internals directly.
	 * Instead, we must use the appropriate accessor methods,
	 * because if the information is not current available,
	 * it will be automatically retrieved if possible.
	 * This includes UIDVALIDITY, UIDNEXT, etc.
	 */

	switch (event->type) {
		case EVENT_MESSAGE_APPEND:
		case EVENT_MESSAGE_NEW:
			send_untagged_exists(event->node, event->mbox, event->maildir);
			break;
		case EVENT_MESSAGE_EXPUNGE:
		case EVENT_MESSAGE_EXPIRE:
			send_untagged_expunge(event->node, event->mbox, event->maildir, event->expungesilent, event->uids, event->seqnos, event->numuids);
			break;
		case EVENT_MAILBOX_CREATE:
		case EVENT_MAILBOX_DELETE:
		case EVENT_MAILBOX_RENAME:
			send_untagged_list(event->node, event->type, event->mbox, event->maildir, event->oldmaildir);
			break;
		case EVENT_MAILBOX_SUBSCRIBE:
		case EVENT_MAILBOX_UNSUBSCRIBE:
			/* We should basically do send_untagged_list,
			 * however we can ignore currently since all mailboxes are implicitly subscribed
			 * so no change occurs here. */
		/*! \todo If METADATA extension added, updates need to be sent here */
		/*! \todo ACL changes should also be taken into account.
		 * Fortunately, ACLs can be changed through the IMAP protocol which means we could get events for them.
		 * The standard mail store events don't include ACL events, but we could add events
		 * and then use those here to get updates.
		 * We need to send a LIST with \NoAccess if ACL was removed (no longer have access to a mailbox)
		 * and without \NoAccess if access is now granted (but wasn't previously). */
		case EVENT_MAILBOX_UIDVALIDITY_CHANGE:
			send_untagged_uidvalidity(event->mbox, event->maildir, mailbox_event_uidvalidity(event));
			break;
		default:
			break;
	}
}

static void imap_destroy(struct imap_session *imap)
{
	imap_shutdown_clients(imap);
	stringlist_empty(&imap->remotemailboxes);
	if (imap->mbox != imap->mymbox) {
		if (imap->mbox) {
			mailbox_unwatch(imap->mbox);
		}
		imap->mbox = imap->mymbox;
		imap->mymbox = NULL;
	}
	if (imap->mbox) {
		mailbox_unwatch(imap->mbox); /* We previously started watching it, so stop watching it now. */
		imap->mbox = NULL;
	}
	imap_notify_cleanup(imap);
	free_if(imap->savedsearch);
	/* Do not free tag, since it's stack allocated */
	free_if(imap->savedtag);
	free_if(imap->clientid);
	free_if(imap->folder);
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

#define REQUIRE_SELECTED(imap) \
	if (s_strlen_zero(imap->dir)) { \
		imap_reply(imap, "BAD [CLIENTBUG] Must select a mailbox first"); \
		return 0; \
	}

/*! \todo The quotesep function has now been added and probably should be used instead of this mess? */
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

enum select_type {
	CMD_SELECT = 0,
	CMD_EXAMINE = 1,
	CMD_STATUS = 2,
};

static int on_select(const char *dir_name, const char *filename, int seqno, void *obj)
{
	char *flags;
	char newfile[512];
	unsigned long size;
	struct imap_traversal *traversal = obj;

	UNUSED(seqno);

#ifdef EXTRA_DEBUG
	imap_debug(9, "Analyzing file %s/%s (readonly: %d)\n", dir_name, filename, traversal->readonly);
#endif

	/* RECENT is not the same as UNSEEN.
	 * In the context of maildir, RECENT refers to messages in the new directory.
	 * UNSEEN is messages that aren't read (i.e. not marked as \Seen). */

	if (traversal->innew) {
		traversal->totalnew += 1;
		traversal->totalunseen += 1; /* If it's in the new dir, it definitely can't have been seen yet. */
	} else {
		traversal->totalcur += 1;
		flags = strchr(filename, ':');
		if (!flags++) {
			bbs_error("File %s/%s is noncompliant with maildir\n", dir_name, filename);
		} else if (!strlen_zero(flags)) {
			unsigned int uid = 0;
			maildir_parse_uid_from_filename(filename, &uid);
			flags++;
			if (!strchr(flags, FLAG_SEEN)) {
				traversal->totalunseen += 1;
				/* scandir will traverse in the order files were added,
				 * which if the mailbox were read-only, would line up with the filename ordering,
				 * but otherwise there's no guarantee of this, since messages can be moved.
				 * So explicitly look for the message with the smallest UID.
				 */
				if (!traversal->firstunseen) {
					traversal->firstunseen = uid; /* If it's the first unseen message in the traversal, use that. */
				} else {
					traversal->firstunseen = MIN(traversal->firstunseen, uid); /* Otherwise, keep the lowest numbered one. */
				}
			}
			
		}
	}

	if (traversal->innew) {
		if (!traversal->readonly) {
			maildir_move_new_to_cur_file(traversal->mbox, traversal->imap->node, traversal->dir, traversal->curdir, traversal->newdir, filename, &traversal->uidvalidity, &traversal->uidnext, newfile, sizeof(newfile));
			filename = newfile;
		} else {
			/* Need to stat to get the file size the regular way since parse_size_from_filename will fail. */
			struct stat st;
			char fullname[256];
			snprintf(fullname, sizeof(fullname), "%s/%s", dir_name, filename);
			if (stat(fullname, &st)) {
				bbs_error("stat(%s) failed: %s\n", fullname, strerror(errno));
			} else {
				traversal->totalsize += (unsigned long) st.st_size;
			}
			return 0;
		}
	}

	if (!parse_size_from_filename(filename, &size)) {
		traversal->totalsize += size;
	}

	return 0;
}

static int imap_expunge(struct imap_session *imap, int silent)
{
	struct dirent *entry, **entries;
	int files, fno = 0;

	const char *dir_name = imap->curdir;
	const char *filename;
	int oldflags;
	char fullpath[516];
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

	files = scandir(dir_name, &entries, NULL, imap_uidsort);
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
			mailbox_quota_adjust_usage(imap->mbox, (int) -size);
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
		/* Decrement the highest # seqno that should be considered \Recent in this mailbox.
		 * XXX Not perfect, because if a bunch of new messages arrive post-selection,
		 * those won't be considered recent, and then if we expunge them, we'll inappropriately
		 * narrow the window of messages considered "Recent".
		 * But \Recent is most important when a client fetches the list of recent messages
		 * right when the mailbox is selected, so this probably doesn't pose a huge issue in practice... */
		imap->maxrecent--;
next:
		free(entry);
	}
	free(entries);

	mailbox_unlock(imap->mbox);
	/* Batch HIGHESTMODSEQ bookkeeping for EXPUNGEs */
	imap->highestmodseq = maildir_indicate_expunged(EVENT_MESSAGE_EXPUNGE, imap->node, imap->mbox, imap->curdir, expunged, expungedseqs, exp_lengths, silent); 
	free_if(expunged);
	free_if(expungedseqs);

	return 0;
}

static int imap_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, int seqno, void *obj), struct imap_traversal *traversal)
{
	return maildir_ordererd_traverse(path, on_file, traversal);
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
	char *expunged;

	bbs_assert(imap->qresync == 1);

	if (uidrange) {
		uidrangebuf = malloc(strlen(uidrange) + 1); /* We could use strdup, but in_range_allocated always calls strcpy, so malloc avoids unnecessary copying here */
		if (!uidrangebuf) {
			return;
		}
	}

	/* Now send any pending flag changes */
	files = scandir(imap->curdir, &entries, NULL, imap_uidsort);
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
	expunged = maildir_get_expunged_since_modseq(imap->curdir, lastmodseq, uidrangebuf, minuid, uidrange);
	imap_send(imap, "VANISHED (EARLIER) %s", S_IF(expunged));
	free_if(expunged);

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
		if (uidrange && !in_range_allocated(uidrange, (int) uid, uidrangebuf)) {
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
			generate_flag_names_full(imap, flags, flagsbuf, sizeof(flagsbuf), &buf, &len);
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
	unsigned long quotaleft = mailbox_quota_remaining(imap->mbox);
	if (quotaleft < LOW_MAILBOX_SPACE_THRESHOLD) { /* Very little quota remaining */
		imap_send(imap, "OK [ALERT] Mailbox is almost full (%lu KB quota remaining)\n", quotaleft / 1024);
	}
}

static int handle_remote_status(struct imap_client *client, char *s, const char *remotename, int wantsize, int dropsize)
{
	const char *items;

	if (dropsize) {
		s = remove_size(s);
	}
	items = parensep(&s);
	if (!items) {
		imap_reply(client->imap, "NO [CLIENTBUG] Syntax error");
		return 0;
	}

	/* However, since we told the IMAP client we support STATUS=SIZE,
	 * it's going to expect the size of the folder in the STATUS of the response.
	 * Transparently calculate the folder size the manual way behind the scenes and inform the client. */
	if (remote_status(client, remotename, items, wantsize)) {
		return -1;
	}

	imap_reply(client->imap, "OK STATUS");
	return 0;
}

static int select_examine_response(struct imap_session *imap, enum select_type readonly, char *s, unsigned long maxmodseq, int was_selected, struct mailbox *oldmbox)
{
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
			lastuidvalidity = (unsigned int) atoi(tmp);
			tmp = strsep(&qresync, " ");
			REQUIRE_ARGS(tmp);
			lastmodseq = (unsigned int) atoi(tmp);
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
		/* Best practice to always include some response text after [] */
		imap_send(imap, "OK [CLOSED] Closed"); /* RFC 7162 3.2.11, example in 3.2.5.1 */
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
	imap_send(imap, "OK [PERMANENTFLAGS (%s%s \\*)] Limited", IMAP_PERSISTENT_FLAGS, numkeywords > 0 ? keywords : ""); /* Include \* to indicate we support IMAP keywords */
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
	imap_reply(imap, "OK [%s] %s completed%s", imap->readonly ? "READ-ONLY" : "READ-WRITE", readonly == CMD_EXAMINE ? "EXAMINE" : "SELECT", condstore_just_enabled ? ", CONDSTORE is now enabled" : "");
	imap->highestmodseq = maxmodseq;
	return 0;
}

static int sharedflagrights = IMAP_ACL_SEEN | IMAP_ACL_WRITE;

static int remote_select_cb(struct imap_client *client, const char *buf, size_t len, void *cbdata)
{
	/* RFC 4551 3.1.2 says we must send a NOMODSEQ response code if this mailbox
	 * doesn't support modification sequences.
	 * For remote mailboxes, if the remote server doesn't support MODSEQ,
	 * we may need to dynamically inject a NOMODSEQ response into the SELECT/EXAMINE reply. */
	int *modseq = cbdata;

	/* Client doesn't care */
	if (!client->imap->qresync && !client->imap->condstore) {
		return 0;
	}

	/* Remote server already handles it */
	if (client->virtcapabilities & (IMAP_CAPABILITY_CONDSTORE | IMAP_CAPABILITY_QRESYNC)) {
		return 0; /* The remote server should send a HIGHESTMODSEQ or NOMODSEQ response (if compliant) */
	}

	if (!memmem(buf, len, "* ", STRLEN("* "))) {
		if (!*modseq) { /* modseq should never be 1 here, if the remote server supports CONDSTORE/QRESYNC (we'd have returned 0 above) */
			/* If we didn't get a HIGHESTMODSEQ response,
			 * we need to indicate no support at this time. */
			imap_send(client->imap, "* OK [NOMODSEQ] Unsupported");
		}
	}
	if (memmem(buf, len, "HIGHESTMODSEQ", STRLEN("HIGHESTMODSEQ"))) {
		bbs_warning("Remote server sent %.*s\n", (int) len, buf);
		*modseq = 1;
	}
	return 0;
}

/*! \brief SELECT/EXAMINE handler */
static int handle_select(struct imap_session *imap, char *s, enum select_type readonly)
{
	char *mailbox;
	int was_selected = !s_strlen_zero(imap->dir);
	unsigned long maxmodseq;
	struct imap_traversal traversal, *traversalptr = &traversal;
	struct mailbox *oldmbox = imap->mbox;

	REQUIRE_ARGS(s); /* Mailbox can contain spaces, so don't use strsep for it if it's in quotes */
	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s); /* The STATUS command will have additional arguments (and possibly SELECT, for CONDSTORE/QRESYNC) */

	/* This modifies the current maildir even for STATUS, but the STATUS command will restore the old one afterwards. */
	if (set_maildir(imap, mailbox)) { /* Note that set_maildir handles mailbox being "INBOX". It may also change the active (account) mailbox. */
		return 0;
	}
	if (imap->client) {
		int modseq = 0;
		char *remotename = remote_mailbox_name(imap->client, mailbox);
		REPLACE(imap->folder, mailbox);
		/* Reconstruct the SELECT, fortunately this is not too bad */
		return imap_client_send_wait_response_cb(imap->client, -1, 5000, remote_select_cb, &modseq, "%s \"%s\"\r\n", readonly == CMD_SELECT ? "SELECT" : "EXAMINE", remotename);
	}
	IMAP_REQUIRE_ACL(imap->acl, IMAP_ACL_READ);
	if (readonly == CMD_SELECT) {
		readonly = IMAP_HAS_ACL(imap->acl, IMAP_ACL_INSERT | IMAP_ACL_EXPUNGE | sharedflagrights) ? 0 : 1;
	}
	/* SELECT and EXAMINE should update currently selected mailbox, STATUS should not */
	REPLACE(imap->folder, mailbox);
	reset_saved_search(imap); /* RFC 5182 2.1 */

	imap->readonly = readonly == CMD_EXAMINE;
	mailbox_has_activity(imap->mbox); /* Clear any activity flag since we're about to do a traversal. */
	memset(&traversal, 0, sizeof(traversal));
	set_traversal(imap, &traversal);
	IMAP_TRAVERSAL(imap, traversalptr, on_select, imap->readonly);
	save_traversal(imap, &traversal);
	maxmodseq = maildir_max_modseq(imap->mbox, imap->curdir);
	return select_examine_response(imap, readonly, s, maxmodseq, was_selected, oldmbox);
}

static void construct_status(struct imap_session *imap, struct imap_traversal *traversal, const char *s, char *buf, size_t len, unsigned long maxmodseq)
{
	char *pos = buf;
	size_t left = len;
	unsigned int appendlimit;

	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "MESSAGES"), "MESSAGES %d", traversal->totalnew + traversal->totalcur);
	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "RECENT"), "RECENT %d", traversal->totalnew);
	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "UIDNEXT"), "UIDNEXT %d", traversal->uidnext + 1);
	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "UIDVALIDITY"), "UIDVALIDITY %d", traversal->uidvalidity);
	/* Unlike with SELECT, this is the TOTAL number of unseen messages, not merely the first one */
	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "UNSEEN"), "UNSEEN %d", traversal->totalunseen);
	appendlimit = MIN((unsigned int) mailbox_quota(imap->mbox), max_append_size);
	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "APPENDLIMIT"), "APPENDLIMIT %u", appendlimit);
	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "HIGHESTMODSEQ"), "HIGHESTMODSEQ %lu", maxmodseq);
	/* RFC 8438 STATUS=SIZE extension */
	SAFE_FAST_COND_APPEND(buf, len, pos, left, strstr(s, "SIZE"), "SIZE %lu", traversal->totalsize);
}

static int generate_status(struct imap_session *imap, const char *folder, char *buf, size_t len, const char *items)
{
	struct imap_traversal traversalstack, *traversal = &traversalstack;
	memset(&traversalstack, 0, sizeof(traversalstack));
	set_traversal(imap, &traversalstack); /* Set the traversal based on imap, not s */
	if (set_maildir_readonly(imap, &traversalstack, folder)) { /* Yes, use s session but imap->folder */
		bbs_error("Failed to set maildir for %s\n", folder);
		*buf = '\0';
		return -1;
	}

	IMAP_TRAVERSAL(imap, traversal, on_select, 1); /* Read only traversal: Do not move messages from new to cur */

	/* If CONDSTORE/QRESYNC enabled, we need at least HIGHESTMODSEQ and UIDVALIDITY.
	 * Otherwise, we need UNSEEN.
	 * Since the traversal gets all of these anyways, we may as well include everything needed for both cases. */
	construct_status(imap, traversal, items, buf, len, maildir_max_modseq(traversal->mbox, traversal->curdir));
	return 0;
}

int local_status(struct imap_session *imap, struct imap_traversal *traversal, const char *mailbox, const char *items)
{
	char status_items[84] = "";

	mailbox_has_activity(traversal->mbox); /* Clear any activity flag since we're about to do a traversal. */
	IMAP_TRAVERSAL(imap, traversal, on_select, 1); /* Read only traversal: Do not move messages from new to cur */

	if (!strlen_zero(items)) {
		construct_status(imap, traversal, items, status_items, sizeof(status_items), maildir_max_modseq(traversal->mbox, traversal->curdir));
	}
	imap_send(imap, "STATUS \"%s\" (%s)", mailbox, status_items); /* Quotes needed if mailbox name contains spaces */
	return 0;
}

/*! \brief STATUS handler, split off from handle_select for modularity */
static int handle_status(struct imap_session *imap, char *s)
{
	/* STATUS is like EXAMINE, but it's on a specified mailbox that is NOT the currently selected mailbox */
	/* Need to save/restore current maildir for STATUS, so it doesn't mess up the selected mailbox,
	 * since STATUS must not modify the selected folder.
	 * This is handled earlier in imap_process (look for "Reverting temporary STATUS override"). */
	char *mailbox;
	struct imap_traversal traversal;

	REQUIRE_ARGS(s); /* Mailbox can contain spaces, so don't use strsep for it if it's in quotes */
	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s); /* The STATUS command will have additional arguments (and possibly SELECT, for CONDSTORE/QRESYNC) */

	/* This modifies the current maildir even for STATUS, but the STATUS command will restore the old one afterwards. */
	memset(&traversal, 0, sizeof(traversal));
	set_traversal(imap, &traversal);
	if (set_maildir_readonly(imap, &traversal, mailbox)) { /* Note that set_maildir handles mailbox being "INBOX". It may also change the active (account) mailbox. */
		return 0;
	}
	if (traversal.client) {
		char *remotename = remote_mailbox_name(traversal.client, mailbox);
		int wantsize = strstr(s, "SIZE") ? 1 : 0;
		/* If the client wants SIZE but the remote server doesn't support it, we'll have to fake it by translating */
		if (wantsize && !(traversal.client->virtcapabilities & IMAP_CAPABILITY_STATUS_SIZE)) {
			return handle_remote_status(traversal.client, s, remotename, wantsize, 1);
		} else {
			/* Also use handle_remote_status instead of passthrough, because passthrough won't return the correct remote mailbox name.
			 * (It'll be the raw mailbox name on the remote server, instead of what our client thinks the name is).
			 * Also, internally, if the client doesn't support LIST-STATUS but the remote server does,
			 * we can use LIST-STATUS in our remote request and satisfy a series of client STATUS commands much more quickly
			 * than just doing pure passthrough.
			 *
			 * The only downside is the abstract STATUS translator will request all STATUS items (e.g. UIDVALIDITY, UIDNEXT, etc.)
			 * even if the client didn't ask for these. Clients must be able to tolerate getting more than they asked for,
			 * so this is not a correctness issue, just a potential performance consideration.
			 * That said, things like UIDVALIDITY and UIDNEXT should be very cheap for the server to provide anyways.
			 * So there are more benefits of doing it this way than drawbacks.
			 */
#if 1
			return handle_remote_status(traversal.client, s, remotename, wantsize, 0);
#else
			return imap_client_send_wait_response(traversal.client, -1, 5000, "STATUS \"%s\" %s\r\n", remotename, s);
#endif
		}
	}

	IMAP_REQUIRE_ACL(traversal.acl, IMAP_ACL_READ);
	local_status(imap, &traversal, mailbox, s);
	imap_reply(imap, "OK STATUS completed");
	return 0;
}

#define EMPTY_QUOTES "\"\""

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
	bbs_test_assert_equals(1, list_match("baz2", "*2")); /* RFC 5258 5.9 */
	bbs_test_assert_equals(0, list_match("baz2", "*32"));

	return 0;

cleanup:
	return -1;
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

static void list_command_destroy(struct list_command *lcmd)
{
	free_if(lcmd->mailboxes);
	free_if(lcmd->skiplens);
}

static void process_parsed_mailbox(struct list_command *lcmd, const char *s, size_t index)
{
	lcmd->mailboxes[index] = s;
	/* To allow for optimizations later, where we can skip certain process if we know these don't apply. */
	/* Example of doing that at the bottom of this page, e.g. 0 LIST "" "#shared.*" : http://www.courier-mta.org/imap/tutorial.setup.html */
	if (STARTS_WITH(s, OTHER_NAMESPACE_PREFIX)) {
		lcmd->anyother = 1;
		lcmd->skiplens[index] = STRLEN(OTHER_NAMESPACE_PREFIX);
	} else if (STARTS_WITH(s, SHARED_NAMESPACE_PREFIX)) {
		lcmd->anyshared = 1;
		lcmd->skiplens[index] = STRLEN(SHARED_NAMESPACE_PREFIX);
	} else if (list_wildcard_match(s)) { /* Is this a broad query (list everything?) */
		lcmd->anyshared = lcmd->anyother = 1;
	}
}

static int parse_list_cmd(struct imap_session *imap, struct list_command *lcmd, char *s)
{
	static char empty[] = ""; /* Static so that pointers to this buffer are valid after we return */
	char *tmp, *opt;

	/* Determine if this is an extended command (RFC 5258 LIST-EXTENDED) or normal LIST/LSUB *
	 * RFC 5258 Section 1: 3 cases to consider:
	 * 1) 1st word after command begins with (    - selection options
	 * 2) 2nd word after command begins with (    - multiple mailbox patterns
	 * 3) LIST command has more than 2 parameters - return options
	 */

	if (strlen_zero(s)) {
		return -1;
	}

	if (lcmd->cmdtype == CMD_XLIST) {
		lcmd->xlistflags = DIR_INBOX; /* XLIST also returns \Inbox for INBOX: */
	}

	/* First argument */
	if (*s == '(') {
		/* This contains selection options. */
		lcmd->extended = 1;
		tmp = parensep(&s);
		if (strlen_zero(tmp)) {
			imap_reply(imap, "BAD [CLIENTBUG] No selection options provided");
			return -1;
		}
		while ((opt = strsep(&tmp, " "))) {
			if (!strcasecmp(opt, "SUBSCRIBED")) {
				lcmd->subscribed = 1;
			} else if (!strcasecmp(opt, "REMOTE")) {
				lcmd->remote = 1;
			} else if (!strcasecmp(opt, "RECURSIVEMATCH")) {
				lcmd->recursive = 1;
			} else if (!strcasecmp(opt, "SPECIAL-USE")) {
				lcmd->specialuse = 1;
			} else {
				/* RFC 5258 Section 3: MUST respond to options we don't know about with BAD */
				imap_reply(imap, "BAD Unknown selection option %s\n", opt);
				return -1;
			}
		}
	}

	/* Reference: First or second argument, depending on if we there were selection options. */
	lcmd->reference = strsep(&s, " ");
	if (strlen_zero(lcmd->reference)) {
		imap_reply(imap, "BAD [CLIENTBUG] No mailbox pattern provided");
		return -1;
	}
	STRIP_QUOTES(lcmd->reference);

	/* Either a mailbox or list of mailbox patterns (if extended) */
	if (strlen_zero(s)) {
		imap_reply(imap, "BAD [CLIENTBUG] Missing mailbox argument");
		return -1;
	}
	if (*s == '(') {
		char *mbox;
		size_t p = 0;
		lcmd->extended = 1;
		tmp = parensep(&s);
		if (strlen_zero(tmp)) {
			imap_reply(imap, "BAD [CLIENTBUG] No mailbox patterns provided");
			return -1;
		}
		lcmd->patterns = (size_t) bbs_str_count(tmp, '"');
		if (lcmd->patterns % 2) {
			imap_reply(imap, "BAD [CLIENTBUG] Odd number of quotes in pattern list");
			return -1;
		}
		lcmd->patterns /= 2; /* 2 quotes per mailbox */
		lcmd->mailboxes = calloc(lcmd->patterns, sizeof(*lcmd->mailboxes));
		if (ALLOC_FAILURE(lcmd->mailboxes)) {
			imap_reply(imap, "NO [SERVERBUG] Allocation failure");
			return -1;
		}
		lcmd->skiplens = calloc(lcmd->patterns, sizeof(*lcmd->skiplens));
		if (ALLOC_FAILURE(lcmd->skiplens)) {
			imap_reply(imap, "NO [SERVERBUG] Allocation failure");
			return -1;
		}
		/* All mailbox names are quoted */
		while ((mbox = quotesep(&tmp))) {
			if (p > lcmd->patterns) {
				/* Avoid out of bounds */
				imap_reply(imap, "BAD [CLIENTBUG] Malformed mailbox pattern list");
				return -1;
			}
			process_parsed_mailbox(lcmd, mbox, p);
			p++;
		}
	} else {
		/* Single mailbox */
		lcmd->patterns = 1;
		lcmd->mailboxes = calloc(lcmd->patterns, sizeof(*lcmd->mailboxes));
		if (ALLOC_FAILURE(lcmd->mailboxes)) {
			imap_reply(imap, "NO [SERVERBUG] Allocation failure");
			return -1;
		}
		lcmd->skiplens = calloc(lcmd->patterns, sizeof(*lcmd->skiplens));
		if (ALLOC_FAILURE(lcmd->skiplens)) {
			imap_reply(imap, "NO [SERVERBUG] Allocation failure");
			return -1;
		}
		tmp = quotesep(&s);
		if (!tmp) {
			imap_reply(imap, "BAD [CLIENTBUG] Missing mailbox argument");
			return -1;
		}
		process_parsed_mailbox(lcmd, tmp, 0);
	}

	if (lcmd->patterns < 1) {
		imap_reply(imap, "BAD [CLIENTBUG] No mailbox patterns provided");
		return -1;
	}

	/* Return options (only for extended) */
	if (!strlen_zero(s)) {
		ltrim(s);
		if (!strlen_zero(s)) {
			if (!STARTS_WITH(s, "RETURN (")) {
				imap_reply(imap, "BAD [CLIENTBUG] Invalid return options");
				return -1;
			}
			lcmd->extended = 1;
			s += STRLEN("RETURN "); /* Want to start with ( */
			tmp = parensep(&s); /* We know that ( exists so s cannot be NULL */
			while ((opt = strsep(&tmp, " "))) {
				if (strlen_zero(opt)) {
					continue; /* Yes, we need this... */
				}
				if (!strcasecmp(opt, "SUBSCRIBED")) {
					lcmd->retsubscribed = 1;
				} else if (!strcasecmp(opt, "CHILDREN")) {
					lcmd->retchildren = 1;
				} else if (!strcasecmp(opt, "SPECIAL-USE")) {
					lcmd->retspecialuse = 1;
				} else if (!strcasecmp(opt, "STATUS")) {
					/* RFC 5819 LIST-STATUS */
					lcmd->retstatus = parensep(&tmp);
				} else {
					/* RFC 5258 Section 3: MUST respond to options we don't know about with BAD */
					imap_reply(imap, "BAD Unknown return option '%s'\n", opt);
					bbs_debug(3, "Remainder: %s\n", tmp);
					return -1;
				}
			}
		}
	}

	if (strlen_zero(lcmd->reference)) { /* Empty reference ("") means same mailbox selected using SELECT */
		/* Default to INBOX if nothing has been selected yet, since it is the root */
	} else if (!strcmp(lcmd->reference, "INBOX")) {
		lcmd->reference = empty; /* It's the root. */
	}
	lcmd->reflen = strlen(lcmd->reference);

	return 0;
}

static int handle_list(struct imap_session *imap, char *s, enum list_cmd_type cmdtype)
{
	struct list_command lcmdstack;
	struct list_command *lcmd = &lcmdstack;

	memset(&lcmdstack, 0, sizeof(lcmdstack));
	lcmd->cmdtype = cmdtype;
	lcmd->cmd = cmdtype == CMD_XLIST ? "XLIST" : cmdtype == CMD_LSUB ? "LSUB" : "LIST";

	if (parse_list_cmd(imap, &lcmdstack, s)) {
		goto cleanup;
	}

	/* Examples:
	 * LIST "" % should return all top-level folders.
	 * LIST "" * should return all folders.
	 * LIST "" S% should return all top-level folders starting with S.
	 * LIST "" S* should return all folders starting with S.
	 * Swapping these 2 arguments often results in a similar response, with subtle differences.
	 * A detailed reading and reading of the RFC (e.g. RFC 3501) is very handy for understanding the LIST command in its entirety.
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
	 *
	 * Additional attributes specified by RFC 5258:
	 * \Remote - RFC 2193 IMAP referrals (not something that we do)
	 * \Subscribed - all mailboxes are always subscribed for us
	 * \NonExistent - mailbox that doesn't exist, which can happen if subscriptions are allowed for nonexistent mailboxes.
	 *              Since we couple subscriptions to existence (1:1), this can't happen here.
	 *
	 * The XLIST command is not formally specified anywhere but basically seems to be the same thing
	 * as RFC 6154, except returning XLIST instead of LIST (obviously), and with an \Inbox attribute for the INBOX.
	 * Google says that XLIST attributes are NOT exactly the same:
	 * https://developers.google.com/gmail/imap/imap-extensions#xlist_is_deprecated
	 * Even though XLIST is deprecated, it is still needed as some clients (e.g. some versions of Microsoft Outlook)
	 * support XLIST but not SPECIAL-USE.
	 */

	if (!lcmd->specialuse && lcmd->patterns == 1 && strlen_zero(lcmd->mailboxes[0])) {
		/* This is a special case. Just return hierarchy delimiter and root name of reference */
		/* When testing other servers, the reference argument doesn't even seem to matter, I always get something like this: */
		imap_send(imap, "%s (%s %s) \"%s\" %s", lcmd->cmd, ATTR_NOSELECT, ATTR_HAS_CHILDREN, HIERARCHY_DELIMITER, EMPTY_QUOTES);
		imap_reply(imap, "OK %s completed.", lcmd->cmd);
		goto cleanup;
	}

	/* If there are subdirectories (say one level down), it doesn't even matter which side
	 * has the hierarchy delimiter: could be end of the reference or beginning of the mailbox. */

	/* In doing our traversal of the maildir, we're going to look for directories
	 * that start with reference, and then match (the/a) pattern specified by (mailbox/mailboxes).
	 * If it ends in %, that's a wildcard for the current directory.
	 * If it ends in *, that's a wildcard for all subdirectories as well.
	 *
	 * However, note that % and * can appear anywhere in the mailbox argument. And they function just like a wildcard character you'd expect.
	 * For that reason, we can't just concatenate reference and mailbox and use that as the prefix. */
#ifdef DEBUG_LIST_MATCH
	bbs_debug(6, "%s traversal rooted at '%s' (%lu pattern%s, anyshared: %d, anyother: %d)\n", lcmd->cmd, lcmd->reference, lcmd->patterns, ESS(lcmd->patterns), lcmd->anyshared, lcmd->anyother);
#endif

	/* Do 3 traversals: once each for private, shared, and other namespaces (+virtual mappings) */
	lcmd->ns = NAMESPACE_PRIVATE;
	list_scandir(imap, lcmd, 0, lcmd->reference, mailbox_maildir(imap->mbox)); /* Recursively LIST */
	/* For shared and other users, we use the root maildir since that's where the maildirs for each account are located. */
	if (lcmd->anyshared) {
		lcmd->ns = NAMESPACE_SHARED;
		list_scandir(imap, lcmd, 0, lcmd->reference, mailbox_maildir(NULL));
	}
	if (lcmd->anyother) {
		lcmd->ns = NAMESPACE_OTHER;
		list_scandir(imap, lcmd, 0, lcmd->reference, mailbox_maildir(NULL));
		/* XXX There are some assumptions made that all remote mailboxes are in the Other Users namespace,
		 * but these aren't really enforced anywhere. */
		list_virtual(imap, lcmd);
	}

	imap_reply(imap, "OK %s completed.", lcmd->cmd);

cleanup:
	list_command_destroy(&lcmdstack);
	return 0;
}

static int test_parse_fetch_items(void)
{
	char buf[72] = "FLAGS BODY[HEADER.FIELDS (DATE FROM)] INTERNALDATE BODY[]<0.2048>";
	char *item, *items = buf;

	item = fetchitem_sep(&items);
	bbs_test_assert_str_equals(item, "FLAGS");
	item = fetchitem_sep(&items);
	bbs_test_assert_str_equals(item, "BODY[HEADER.FIELDS (DATE FROM)]");
	item = fetchitem_sep(&items);
	bbs_test_assert_str_equals(item, "INTERNALDATE");
	item = fetchitem_sep(&items);
	bbs_test_assert_str_equals(item, "BODY[]<0.2048>");
	item = fetchitem_sep(&items);
	bbs_test_assert(item == NULL);
	return 0;

cleanup:
	return -1;
}

int imap_in_range(struct imap_session *imap, const char *s, int num)
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

/*! \retval 0 if not in range, UID if in range */
static unsigned int msg_in_range(int seqno, const char *filename, const char *sequences, int usinguid)
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
		if (!in_range(sequences, (int) msguid)) {
			return 0;
		}
	}
	return msguid;
}

unsigned int imap_msg_in_range(struct imap_session *imap, int seqno, const char *filename, const char *sequences, int usinguid, int *error)
{
	unsigned int res;
	int use_saved_search = !strcmp(sequences, "$") ? 1 : 0;

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

static int handle_fetch(struct imap_session *imap, char *s, int usinguid)
{
	if (mailbox_has_activity(imap->mbox)) {
		struct imap_traversal traversal, *traversalptr = &traversal;
		/* There are new messages since we last checked. */
		/* Move any new messages from new to cur so we can find them. */
		imap_debug(4, "Doing traversal again since our view of %s is stale\n", imap->dir);
		memset(&traversal, 0, sizeof(traversal));
		set_traversal(imap, &traversal);
		IMAP_TRAVERSAL(imap, traversalptr, on_select, imap->readonly);
		save_traversal(imap, &traversal);
	}
	return handle_fetch_full(imap, s, usinguid, 1);
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

	quotaleft = (long int) mailbox_quota_remaining(imap->mbox);

	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_INSERT); /* Must be able to copy to dest dir */

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, imap_uidsort);
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
		uidres = (unsigned int) maildir_copy_msg_filename(imap->mbox, imap->node, srcfile, entry->d_name, newboxdir, &uidvalidity, &uidnext, newfile, sizeof(newfile));
		if (!uidres) {
			continue;
		}
		translate_maildir_flags(imap, imap->dir, newfile, entry->d_name, newboxdir, destacl);
		if (!uintlist_append2(&olduids, &newuids, &lengths, &allocsizes, msguid, uidres)) {
			numcopies++;
		}
	}
	bbs_free_scandir_entries(entries, files);
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
		if (IMAP_HAS_ACL(imap->acl, IMAP_ACL_READ)) {
			imap_reply(imap, "OK [COPYUID %u %s %s] COPY completed", uidvalidity, S_IF(olduidstr), S_IF(newuidstr));
		} else {
			imap_reply(imap, "OK COPY completed");
		}
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
	files = scandir(imap->curdir, &entries, NULL, imap_uidsort);
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
		uidres = (unsigned int) maildir_move_msg_filename(imap->mbox, imap->node, srcfile, entry->d_name, newboxdir, &uidvalidity, &uidnext, newname, sizeof(newname));
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
		uintlist_append2(&expunged, &expungedseqs, &exp_lengths, &exp_allocsizes, msguid, (unsigned int) seqno); /* store UID and seqno */
		
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
		/* Yes, the MOVE response sends COPYUID. See RFC 6851 4.3 */
		imap_reply(imap, "OK [COPYUID %u %s %s] MOVE completed", uidvalidity, S_IF(olduidstr), S_IF(newuidstr));
	}

	/* EXPUNGE untagged responses are sent in realtime (already done), just update HIGHESTMODSEQ now */
	imap->highestmodseq = maildir_indicate_expunged(EVENT_MESSAGE_EXPUNGE, imap->node, imap->mbox, imap->curdir, expunged, expungedseqs, exp_lengths, 0);

	mailbox_unlock(imap->mbox);

	free_if(olduidstr);
	free_if(newuidstr);
	free_if(expunged);
	free_if(expungedseqs);
	return 0;
}

/*! \brief Set the INTERNALDATE of a message */
static int set_file_mtime(const char *filename, const char *appenddate)
{
	struct tm tm;
	struct stat st;
	struct utimbuf updated;

	/* e.g. 23-Jul-2002 19:39:23 -0400 */
	if (!strptime(appenddate, "%d-%b-%Y %H:%M:%S %z", &tm)) {
		bbs_error("Failed to parse date: %s\n", appenddate);
		return -1;
	}
	if (stat(filename, &st)) {
		bbs_error("stat(%s) failed: %s\n", filename, strerror(errno));
		return -1;
	}

	updated.actime = st.st_atime; /* Preserve atime */
	tm.tm_isdst = -1; /* Figure out Daylight Saving for us, or we might end up off by an hour. */
	/* Do actually use mktime, not timegm. The mtime needs to be in the server's time, even if it's not UTC. */
	updated.modtime = mktime(&tm);

	if (utime(filename, &updated)) {
		bbs_error("utime(%s) failed: %s\n", filename, strerror(errno));
		return -1;
	}
	return 0;
}

static int handle_append(struct imap_session *imap, char *s)
{
	char *mailbox;
	int destacl;
	int appends;
	char tag[48];
	char appenddir[212];		/* APPEND directory */
	unsigned int uidvalidity, uidnext;
	unsigned int *a = NULL;
	int lengths = 0, allocsizes = 0;

	/* Format is mailbox [flags] [date] message literal
	 * The message literal begins with {size} on the same line
	 * See also RFC 3502. */

	SHIFT_OPTIONALLY_QUOTED_ARG(mailbox, s);
	STRIP_QUOTES(mailbox);
	if (imap_translate_dir(imap, mailbox, appenddir, sizeof(appenddir), &destacl)) { /* Destination directory doesn't exist. */
		imap_reply(imap, "NO [TRYCREATE] No such mailbox");
		return 0;
	}

	IMAP_REQUIRE_ACL(destacl, IMAP_ACL_INSERT);

	/* APPEND will clobber the readline buffer, so save off the tag */
	safe_strncpy(tag, imap->tag, sizeof(tag));
	imap->tag = tag;

	for (appends = 0;; appends++) {
		unsigned long quotaleft;
		int appendsize, appendfile, appendflags = 0, res;
		char *flags, *sizestr;
		char *appenddate = NULL;
		int synchronizing;
		char appendtmp[260];		/* APPEND tmp name */
		char appendnew[260];		/* APPEND new name */
		char appenddatebuf[28];		/* APPEND date */
		char curdir[260];
		char newdir[260];
		char newfilename[256];
		char *filename;
		unsigned long size;
		struct mailbox_event e;

		if (appends > 0) {
			/* If it's the first line, we already read it.
			 * If it's a MULTIAPPEND, we read another line.
			 * If we read an empty line (just CR LF), then that's the end of the APPEND operation. */
			bbs_debug(7, "%d message%s appended so far, will there be more?\n", appends, ESS(appends));
			res = bbs_readline(imap->rfd, imap->rldata, "\r\n", 5000);
			if (res == 0 || res == -1) { /* either CR LF read or socket closed */
				bbs_debug(3, "%d message%s appended successfully\n", appends, ESS(appends));
				break;
			} else if (res < 0) {
				bbs_debug(3, "Client exited abruptly during APPEND?\n");
				return res;
			}
			s = imap->rldata->buf;
		}

		sizestr = strchr(s, '{');
		if (!sizestr) {
			imap_reply(imap, "NO [CLIENTBUG] Missing message literal size");
			goto cleanup2;
		}
		*sizestr++ = '\0';
		synchronizing = strchr(sizestr, '+') ? 0 : 1;

		/* To properly handle the case without flags or date,
		 * e.g. APPEND "INBOX" {1290}
		 * Since we haven't called strsep yet on s since we separated the mailbox,
		 * if there's no flags or date, then *s was { prior to size++.
		 * In this case, we can skip all this:
		 */
		if (sizestr > s + 1) {
			char *date;
			/* These are both optional arguments, so we could have 0, 1, or 2 arguments. */
			/* Multiword, e.g. APPEND "INBOX" "23-Jul-2002 19:39:23 -0400" {1110}
			 * In fact, if date is present, it is guaranteed to contain spaces. */

			/* e.g. (\Seen encrypted) "07-Jun-2023 12:02:51 -0400" */

			/* Parse flags (which are first, if present) */
			if (*s == '(') {
				/* We have flags */
				flags = parensep(&s);
				if (!strlen_zero(flags)) {
					appendflags = parse_flags_string(imap, flags);
					/* imap->appendkeywords will also contain keywords as well */
				}
			}

			/* Parse date */
			ltrim(s);
			/* XXX Seems like STRIP_QUOTES would work but that doesn't remove the trailing quote */
			if (*s == '"') {
				s++;
				date = strsep(&s, "\"");
			} else {
				date = strsep(&s, " ");
			}
			if (date) {
				safe_strncpy(appenddatebuf, date, sizeof(appenddatebuf));
				/* s is just a pointer to the readline buffer,
				 * so our call to bbs_readline_getn before we call set_file_mtime
				 * will clobber appenddate if we just do appenddate = date.
				 * Copy it locally on the stack so we don't lose it. */
				appenddate = appenddatebuf;
			}
		}

		quotaleft = mailbox_quota_remaining(imap->mbox); /* Calculate current quota remaining to determine acceptance. */
		appendsize = atoi(sizestr); /* Read this many bytes */
		if (appendsize <= 0) {
			imap_reply(imap, "NO [CLIENTBUG] Invalid message literal size");
			goto cleanup2;
		} else if ((unsigned int) appendsize >= max_append_size) {
			if (!synchronizing) {
				/* Read and ignore this many bytes, so we don't interpret all those bytes as potential commands afterwards.
				 * This is to avoid leaving the message in the buffer and trying to parse it all as IMAP commands,
				 * which would result in spamming the logs, and also present a security risk if any of the lines in the message
				 * is a potentially valid IMAP command. */
				bbs_readline_discard_n(imap->rfd, imap->rldata, SEC_MS(10), (size_t) (appendsize + 2)); /* Read the bytes + trailing CR LF and throw them away */
				bbs_debug(5, "Discarded %d bytes\n", appendsize);
				/* This is obviously wasteful of bandwidth. Client should've supported the APPENDLIMIT extension, though,
				 * so I'm not sympathetic. Get with the program already, know your limits! */
				/* The reason for not sending the NO until afterwards is to guarantee the client won't stop sending
				 * the message before we receive all of it. Even though that would save bandwidth, that would
				 * confuse our ability to parse the message properly and be certain of the client's state. */
				imap_reply(imap, "NO [LIMIT] Message too large"); /* [TOOBIG] could also be appropriate */
				continue; /* Don't disconnect the client, otherwise Thunderbird won't display the [NO] message. For MULTIAPPEND, repeat for all. */
			} else {
				imap_reply(imap, "NO [LIMIT] Message too large");
				goto cleanup;
			}
		} else if ((unsigned long) appendsize >= quotaleft) {
			if (!synchronizing) {
				bbs_readline_discard_n(imap->rfd, imap->rldata, SEC_MS(10), (size_t) (appendsize + 2));
				bbs_debug(5, "Discarded %d bytes\n", appendsize + 2);
				imap_reply(imap, "NO [OVERQUOTA] Insufficient quota remaining");
				continue;
			} else {
				imap_reply(imap, "NO [OVERQUOTA] Insufficient quota remaining");
				goto cleanup;
			}
		}

		appendfile = maildir_mktemp(appenddir, appendtmp, sizeof(appendtmp), appendnew);
		if (appendfile < 0) {
			goto cleanup2;
		}

		if (synchronizing) {
			_imap_reply(imap, "+ Ready for literal data\r\n"); /* Synchronizing literal response */
		}
		res = bbs_readline_getn(imap->rfd, appendfile, imap->rldata, 5000, (size_t) appendsize);
		if (res != appendsize) {
			bbs_warning("Client wanted to append %d bytes, but sent %d?\n", appendsize, res);
			close(appendfile);
			unlink(appendnew);
			goto cleanup2; /* Disconnect if we failed to receive the upload properly, since we're probably all screwed up now */
		}

		/* Process the upload */
		close(appendfile);
		filename = strrchr(appendnew, '/');
		if (!filename) {
			bbs_error("Invalid filename: %s\n", appendnew);
			imap_reply(imap, "NO [SERVERBUG] Append failed");
			unlink(appendnew);
			goto cleanup;
		}
		filename++; /* Just the base name now */
		if (rename(appendtmp, appendnew)) {
			bbs_error("rename %s -> %s failed: %s\n", appendtmp, appendnew, strerror(errno));
			imap_reply(imap, "NO [SERVERBUG] Append failed");
			goto cleanup;
		}

		/* File has been moved from tmp to new.
		 * Now, move it to cur.
		 * This is a 2-stage rename because we don't have a function to move an arbitrary
		 * file into a mailbox folder, only one that's already in cur,
		 * and the only function that properly initializes a filename is maildir_move_new_to_cur. */
		snprintf(curdir, sizeof(curdir), "%s/cur", appenddir);
		snprintf(newdir, sizeof(newdir), "%s/new", appenddir);
		/* RFC says the Recent flag should be set: since we're moving this to "cur" immediately, it won't be... */
		res = maildir_move_new_to_cur_file(imap->mbox, imap->node, appenddir, curdir, newdir, filename, &uidvalidity, &uidnext, newfilename, sizeof(newfilename));
		if (res < 0) {
			imap_reply(imap, "NO [SERVERBUG] Append failed");
			goto cleanup;
		}

		/* maildir_move_new_to_cur_file conveniently put the size in the filename for us,
		 * so we can just update the quota usage accordingly rather than having to invalidate it. */
		if (parse_size_from_filename(newfilename, &size)) {
			/* It's too late to stat now as a fallback, the file's gone, who knows how big it was now. */
			mailbox_invalidate_quota_cache(imap->mbox);
		} else {
			mailbox_quota_adjust_usage(imap->mbox, (int) -size);
		}

		if (!strlen_zero(appenddate)) {
			/* Maintain the INTERNALDATE of the message by using what the client gave us.
			 * Since we need the filename, do it while we still know a valid filename. */
			set_file_mtime(newfilename, appenddate);
		}

		/* Send the APPEND event before we set any flags,
		 * because the EXISTS response must go out before any flag change events. */
		uintlist_append(&a, &lengths, &allocsizes, uidnext);
		/* RFC 3501 6.3.11: We SHOULD notify the client via an untagged EXISTS. */
		mailbox_initialize_event(&e, EVENT_MESSAGE_APPEND, imap->node, imap->mbox, appenddir);
		e.uids = &uidnext;
		e.numuids = 1;
		e.uidvalidity = uidvalidity;
		e.msgsize = (size_t) size;
		mailbox_dispatch_event(&e);

		/* Now, apply any flags to the message... (yet a third rename, potentially) */
		if (appendflags) {
			int seqno;
			char newflagletters[53];
			/* Generate flag letters from flag bits */
			gen_flag_letters(appendflags, newflagletters, sizeof(newflagletters));
			if (imap->numappendkeywords) {
				strncat(newflagletters, imap->appendkeywords, sizeof(newflagletters) - 1);
			}
			seqno = bbs_dir_num_files(newdir) + bbs_dir_num_files(curdir); /* XXX Clunky, but compute the sequence number of this message as the # of messages in this mailbox */
			if (maildir_msg_setflags(imap, seqno, newfilename, newflagletters)) {
				bbs_warning("Failed to set flags for %s\n", newfilename);
			}
			bbs_debug(3, "Received %d-byte upload (flags: %s)\n", res, newflagletters);
		} else {
			bbs_debug(3, "Received %d-byte upload\n", res);
		}
		/* XXX RFC 3502 says MULTIAPPEND should be atomic, but this is not.
		 * One way to make it atomic would be, if a failure occurs,
		 * go ahead and remove all the messages accumulated in the uintlist so far.
		 * Of course, we've already dispatched notifications for those, so we'd also
		 * need to send expunge events for those at that point... and I feel like
		 * that isn't the spirit of an "atomic" operation... */
	}

	/* RFC 4315 3: if client doesn't have permission to SELECT/EXAMINE, do not send UIDPLUS response */
	if (IMAP_HAS_ACL(imap->acl, IMAP_ACL_READ)) {
		if (appends == 1) {
			/* Don't add 1, this is the current message UID, not UIDNEXT */
			imap_reply(imap, "OK [APPENDUID %u %u] APPEND completed", uidvalidity, uidnext);
		} else if (appends > 1) {
			/* MULTIAPPEND response */
			char *list = uintlist_to_ranges(a, appends);
			if (ALLOC_SUCCESS(list)) {
				imap_reply(imap, "OK [APPENDUID %u %s] APPEND completed", uidvalidity, list);
				free(list);
			} else {
				imap_reply(imap, "OK APPEND completed");
			}
		}
	} else {
		imap_reply(imap, "OK APPEND completed");
	}

cleanup:
	free_if(a);
	return 0;

cleanup2:
	free_if(a);
	return -1;
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
	unsigned int *aseen = NULL, *atrash = NULL, *aflagsset = NULL;
	int seenlength = 0, seenalloc = 0, trashlength = 0, trashalloc = 0, fslength = 0, fsalloc = 0;
	struct mailbox_event e;

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
	files = scandir(imap->curdir, &entries, NULL, imap_uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}

	if (do_unchangedsince) { /* CONDSTORE support using MODSEQ */
		struct dyn_str dynstr;
		int changed = 0;
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
				dyn_str_append_fmt(&dynstr, ",%u", usinguid ? msguid : (unsigned int) seqno);
				changed = 1;
			}
		}
		seqno = fno = 0;
		if (changed) { /* Failed the UNCHANGEDSINCE test. At least one message had a newer modseq */
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
		int newflags, changes = 0;

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
					size_t oldlen = strlen(oldkeywords);
					bbs_debug(7, "Change made to keyword: %s -> %s\n", oldkeywords, imap->appendkeywords);
					/* Merge both of them: copy over any keywords that weren't in the old one. */
					strcpy(newkeywords, oldkeywords); /* Safe */
					c = imap->appendkeywords;
					newbuf = newkeywords + oldlen;
					newlen = sizeof(newkeywords) - oldlen;
					/* XXX This eliminates duplication, but ideally they should also be sorted alphabetically between the two (e.g. merge sort) */
					while (*c) {
						if (!strchr(oldkeywords, *c)) {
							SAFE_FAST_COND_APPEND_NOSPACE(newkeywords, sizeof(newkeywords), newbuf, newlen, 1, "%c", *c);
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
						SAFE_FAST_COND_APPEND_NOSPACE(newkeywords, sizeof(newkeywords), newbuf, newlen, 1, "%c", *c);
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
		if (changes) {
			char flagstr[256];
			gen_flag_names(newflagletters, flagstr, sizeof(flagstr));
			if (keywords[0]) { /* Current keywords */
				size_t slen = strlen(flagstr);
				/*! \todo We should not append a space before if we're at the beginning of the buffer */
				gen_keyword_names(imap, keywords, flagstr + slen, sizeof(flagstr) - slen); /* Append keywords (include space before) */
			}
			if (!silent) { /* Send the response if not silent */
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

			/* Message events */
			if (flagop == 1 && newflags & FLAG_BIT_SEEN && !(oldflags & FLAG_BIT_SEEN)) {
				uintlist_append(&aseen, &seenlength, &seenalloc, msguid);
			}
			if (flagop == 1 && newflags & FLAG_BIT_DELETED && !(oldflags & FLAG_BIT_DELETED)) {
				uintlist_append(&atrash, &trashlength, &trashalloc, msguid);
			}
#if 0
			/* Ignore the seen and deleted flags for the next bit */
			newflags &= ~(FLAG_BIT_SEEN | FLAG_BIT_DELETED);
			oldflags &= ~(FLAG_BIT_SEEN | FLAG_BIT_DELETED);
			changedflags = newflags ^ oldflags;
			/* Okay, this would get us the flags that have changed for this message,
			 * but what about the keywords? We don't have any bits to easily manipulate.
			 * This isn't actually necessary. It should be fine to just use the flags that
			 * were specified for the operation, and include messages in the list as long
			 * as they were affected in some way. If changes > 0, that's already true.
			 */
#else
			/* XXX On the other hand, the below approach works for flagop == 1 or -1, but what about 0?
			 * If flags were replaced, then we could have BOTH flags that were added and removed.
			 * It's also very difficult to pick out flags that we can apply to all the messages.
			 * The flags specified are in the "added" set, but what about the removed set?
			 * Any other flag/keyword that any message in the list had?
			 * In practice, most clients don't use use a direct STORE, typically + or - to avoid clobbering,
			 * so maybe this isn't a big deal to ignore... */
#endif
			if (flagop) { /* either +1 or -1 */
				uintlist_append(&aflagsset, &fslength, &fsalloc, msguid);
			}
		}
	}
	bbs_free_scandir_entries(entries, files);
	free(entries);

	if (seenlength) {
		mailbox_initialize_event(&e, EVENT_MESSAGE_READ, imap->node, imap->mbox, imap->dir);
		e.uids = aseen;
		e.numuids = seenlength;
		mailbox_dispatch_event(&e);
		free(aseen);
	}
	if (trashlength) {
		mailbox_initialize_event(&e, EVENT_MESSAGE_TRASH, imap->node, imap->mbox, imap->dir);
		e.uids = atrash;
		e.numuids = trashlength;
		mailbox_dispatch_event(&e);
		free(atrash);
	}
	if (fslength) {
		char changedflags[256];
		char changedflagletters[32];
		gen_flag_letters(opflags, changedflagletters, sizeof(changedflagletters));
		if (imap->numappendkeywords) {
			strncat(changedflagletters, imap->appendkeywords, sizeof(changedflagletters) - 1);
		}
		gen_flag_names(changedflagletters, changedflags, sizeof(changedflags));
		if (imap->numappendkeywords) {
			size_t slen = strlen(changedflags);
			/*! \todo We should not append a space before if we're at the beginning of the buffer */
			gen_keyword_names(imap, imap->appendkeywords, changedflags + slen, sizeof(changedflags) - slen);
		}
		mailbox_initialize_event(&e, flagop < 1 ? EVENT_FLAGS_CLEAR : EVENT_FLAGS_SET, imap->node, imap->mbox, imap->dir);
		e.uids = aflagsset;
		e.numuids = fslength;
		e.flagnames = changedflags;
		mailbox_dispatch_event(&e);
		free(aflagsset);
	}

	if (!matches) {
		imap_reply(imap, "NO No messages in range");
	} else if (error) {
		imap_reply(imap, "BAD Invalid saved search");
	} else {
		imap_reply(imap, "OK %sSTORE Completed", usinguid ? "UID " : "");
	}
	return 0;

done:
	bbs_free_scandir_entries(entries, files);
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
				unchangedsince = (unsigned int) atol(tmp);
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
	mailbox_dispatch_event_basic(EVENT_MAILBOX_CREATE, imap->node, imap->mbox, path);
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

	/* RFC 2683 3.4.12: Don't allow deleting the selected mailbox. */
	if (!strcmp(imap->dir, path)) {
		imap_reply(imap, "NO May not delete currently selected mailbox");
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

	/* We're a nice server: we allow deleting non-empty mailboxes */
	MAILBOX_TRYRDLOCK(imap);
	if (recursive_rmdir(path)) {
		mailbox_unlock(imap->mbox);
		imap_reply(imap, "NO [SERVERBUG] DELETE failed");
		return 0;
	}
	mailbox_unlock(imap->mbox);
	mailbox_quota_adjust_usage(imap->mbox, -4096);
	imap_reply(imap, "OK DELETE completed");
	mailbox_dispatch_event_basic(EVENT_MAILBOX_DELETE, imap->node, imap->mbox, path);
	return 0;
}

static int sub_rename(const char *path, const char *prefix, const char *newprefix)
{
	char oldpath[257];
	char newpath[257];
	struct dirent *entry, **entries;
	int res = 0;
	int files, fno = 0;
	size_t prefixlen = strlen(prefix);

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(path, &entries, NULL, imap_uidsort);
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

	bbs_free_scandir_entries(entries, files);
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
			struct mailbox_event e;
			imap_reply(imap, "OK RENAME completed");
			mailbox_initialize_event(&e, EVENT_MAILBOX_RENAME, imap->node, imap->mbox, newpath);
			e.oldmaildir = oldpath;
			mailbox_dispatch_event(&e);
		}
	} else {
		imap_reply(imap, "NO [SERVERBUG] System error");
	}
	mailbox_unlock(imap->mbox);
	return 0;
}

static int handle_getquota(struct imap_session *imap)
{
	unsigned long quotatotal, quotaused;

	quotatotal = mailbox_quota(imap->mbox);
	quotaused = mailbox_quota_used(imap->mbox);

	/* The RFC doesn't say this explicitly, but quota values are in KB, not bytes. */
	imap_send(imap, "QUOTA \"\" (STORAGE %lu %lu)", quotaused / 1024, quotatotal / 1024);
	return 0;
}

static int finalize_auth(struct imap_session *imap)
{
	imap->mymbox = mailbox_get_by_userid(imap->node->user->id); /* Retrieve the mailbox for this user */
	if (!imap->mymbox) {
		bbs_error("Successful authentication, but unable to retrieve mailbox for user %d\n", imap->node->user->id);
		imap_reply(imap, "BYE System error");
		return -1; /* Just disconnect, we probably won't be able to proceed anyways. */
	}

	imap->mbox = imap->mymbox;
	mailbox_maildir_init(mailbox_maildir(imap->mbox)); /* Edge case: initialize if needed (necessary if user is accessing via POP before any messages ever delivered to it via SMTP) */
	mailbox_dispatch_event_basic(EVENT_LOGIN, imap->node, imap->mbox, NULL);
	mailbox_watch(imap->mbox);
	return 0;
}

static int finish_auth(struct imap_session *imap, int auth)
{
	if (finalize_auth(imap)) {
		return -1;
	}

	/* XXX Most clients are going to request the capabilities immediately.
	 * As an optimization, we could save an RTT by sending them unsolicited */

	if (auth) {
		_imap_reply(imap, "%s OK [CAPABILITY %s] Success\r\n", imap->savedtag ? imap->savedtag : imap->tag, IMAP_CAPABILITIES); /* Use tag from AUTHENTICATE request */
		free_if(imap->savedtag);
	} else {
		imap_reply(imap, "OK [CAPABILITY %s] Login completed", IMAP_CAPABILITIES);
	}
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

static int test_remote_mailbox_substitution(void)
{
	struct imap_client client;
	char buf[256];

	memset(&client, 0, sizeof(client));
	client.virtprefix = "Other Users.foobar";
	client.virtprefixlen = STRLEN("Other Users.foobar");

	safe_strncpy(buf, "a1 UID COPY 149 \"Other Users.foobar.INBOX\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&client, buf));
	bbs_test_assert_str_equals(buf, "a1 UID COPY 149 \"INBOX\"");

	safe_strncpy(buf, "copy 149 \"Other Users.foobar.Sent\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&client, buf));
	bbs_test_assert_str_equals(buf, "copy 149 \"Sent\"");

	/* With different remote hierarchy delimiter. */
	client.virtdelimiter = '/';
	safe_strncpy(buf, "copy 149 \"Other Users.foobar.Sub.Folder\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&client, buf));
	bbs_test_assert_str_equals(buf, "copy 149 \"Sub/Folder\"");

	/* Including with spaces */
	safe_strncpy(buf, "copy 149 \"Other Users.foobar.Sub.Folder with spaces.sub\"", sizeof(buf));
	bbs_test_assert_equals(1, imap_substitute_remote_command(&client, buf));
	bbs_test_assert_str_equals(buf, "copy 149 \"Sub/Folder with spaces/sub\"");

	return 0;

cleanup:
	return -1;
}

/* There must not be extra spaces between tokens. Gimap is not tolerant of them. */
#define FORWARD_VIRT_MBOX() \
	if (imap->client) { \
		return imap_client_send_wait_response(imap->client, -1, 5000, "%s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_CAPABILITY(cap) \
	if (imap->client) { \
		if (!(imap->client->virtcapabilities & (cap))) { \
			imap_reply(imap, "NO %s command not available for this mailbox", command); \
			return 0; \
		} \
		return imap_client_send_wait_response(imap->client, -1, 5000, "%s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_UID() \
	if (imap->client) { \
		return imap_client_send_wait_response(imap->client, -1, 5000, "UID %s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_UID_CAPABILITY(cap) \
	if (imap->client) { \
		if (!(imap->client->virtcapabilities & (cap))) { \
			imap_reply(imap, "NO %s command not available for this mailbox", command); \
			return 0; \
		} \
		return imap_client_send_wait_response(imap->client, -1, 5000, "UID %s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_MODIFIED_PREFIX(count, prefix) \
	if (imap->client) { \
		replacecount = imap_substitute_remote_command(imap->client, s); \
		if (replacecount != count) { /* Number of replacements must be all or nothing */ \
			imap_reply(imap, "NO Cannot move/copy between home and remote servers\n"); \
			return 0; \
		} \
		return imap_client_send_wait_response(imap->client, -1, 5000, prefix "%s%s%s\r\n", command, !strlen_zero(s) ? " " : "", S_IF(s)); \
	}

#define FORWARD_VIRT_MBOX_MODIFIED(count) FORWARD_VIRT_MBOX_MODIFIED_PREFIX(count, "")
#define FORWARD_VIRT_MBOX_MODIFIED_UID(count) FORWARD_VIRT_MBOX_MODIFIED_PREFIX(count, "UID ")

#define REQUIRE_SEQNO_ALLOWED() \
	if (imap_sequence_numbers_prohibited(imap)) { \
		imap_reply(imap, "BAD [CLIENTBUG] Sequence numbers may not be used"); \
		return 0; \
	}

static int idle_stop(struct imap_session *imap)
{
	imap->idle = 0;
	/* IDLE for virtual mailboxes (proxied) is handled in the IDLE command itself */
	_imap_reply(imap, "%s OK IDLE terminated\r\n", imap->savedtag); /* Use tag from IDLE request */
	free_if(imap->savedtag);
	return 0;
}

static int flush_updates(struct imap_session *imap, const char *command, const char *s)
{
	int res;

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

	if (imap->pending && !imap->client) { /* Not necessary to lock just to read the flag. Only if we're actually going to read data. */
		struct readline_data rldata2;

		/* If it's a command during which we're not allowed to send an EXPUNGE, then don't send it now. */

		/* RFC 7162 3.2.10.2: UID FETCH, UID STORE, and UID SEARCH are different commands from FETCH, STORE, and SEARCH.
		 * A VANISHED response MAY be sent during a UID command. However, the VANISHED response MUST NOT be sent
		 * during a UID SEARCH command that contains message numbers in the search criteria.
		 *
		 * XXX Regardless of what we to do here, won't the clients sequence numbers be off anyways?
		 * We don't maintain a "client's view" of what sequences numbers are known and map to what UIDs.
		 * So what is the actual effect of "preventing loss of synchronization in this manner"???
		 *
		 * XXX I think this should be right after the command completes, not before? (This is simpler, but technically incorrect)
		 */
		if (!STARTS_WITH(command, "FETCH") && !STARTS_WITH(command, "STORE") && !STARTS_WITH(command, "SEARCH") && !STARTS_WITH(command, "SORT") && !STARTS_WITH(command, "THREAD") && (!STARTS_WITH(command, "UID") || (!strlen_zero(s) && !STARTS_WITH(s, "SEARCH")))) {
			char buf[1024]; /* Hopefully big enough for any single untagged  response. */
			pthread_mutex_lock(&imap->lock);
			bbs_readline_init(&rldata2, buf, sizeof(buf));
			/* Read from the pipe until it's empty again. If there's more than one response waiting, and in particular, more than sizeof(buf), we need to read by line. */
			for (;;) {
				res = bbs_readline(imap->pfd[0], &rldata2, "\r\n", 5); /* Only up to 5 ms */
				if (res < 0) {
					break;
				}
				_imap_reply_nolock(imap, "%s\r\n", buf); /* Already have lock held, and we don't know the length. Also, add CR LF back on, since bbs_readline stripped that. */
			}
			imap->pending = 0;
			pthread_mutex_unlock(&imap->lock);
		}
	}
	return 0;
}

static int notify_status_cb(struct imap_client *client, const char *buf, size_t len, void *cbdata)
{
	if (len < STRLEN("* STATUS") || !STARTS_WITH(buf, "* STATUS")) {
		return 0;
	}

	UNUSED(len);
	UNUSED(cbdata);

	/* In this case, buf should be NULL terminated */

	bbs_debug(3, "Raw STATUS response: %s\n", buf);

	/* XXX Again, because only INBOX is supported for remote NOTIFY proxy */
	return imap_client_send_converted_status_response(client, "INBOX", buf);
}

static int handle_idle(struct imap_session *imap)
{
#define MAX_IDLE_MS SEC_MS(1800) /* 30 minutes */
	int idleleft = MAX_IDLE_MS;
	int res;
	int lastactivity, idlestarted;

	if (imap->client) {
		/* If not already idling on the currently selected mailbox, and can't start, abort. Otherwise, proceed as usual. */
		if (!imap->client->idling && imap_client_idle_start(imap->client)) {
			imap_reply(imap, "NO IDLE failed");
			return 0;
		}
	} else {
		REQUIRE_SELECTED(imap);
	}

	/* XXX Outlook often tries to IDLE without selecting a mailbox, which is kind of bizarre.
	 * Technically though, RFC 2177 says IDLE is valid in either the authenticated or selected states.
	 * How it's used in the authenticated (but non-selected) state, I don't really know.
	 * For now, clients attempting that will be summarily rebuffed. */

	/* RFC 2177 IDLE */
	REPLACE(imap->savedtag, imap->tag); /* We still save the tag to deal with Thunderbird bug in the other path to idle_stop */
	imap->idle = 1; /* This is used by other threads that may send the client data while it's idling. Set before sending response. */
	_imap_reply(imap, "+ idling\r\n");
	/* Note that IDLE only applies to the currently selected mailbox (folder).
	 * Thus, in traversing all the IMAP sessions, simply sharing the same mbox isn't enough.
	 * imap->dir also needs to match (same currently selected folder). */
	idlestarted = lastactivity = (int) time(NULL);
	for (;;) {
		struct imap_client *client = NULL;
		int pollms = MIN(SEC_MS(IMAP_IDLE_POLL_INTERVAL_SEC), idleleft);
		res = imap_poll(imap, pollms, &client);
		if (res < 0) {
			imap->idle = 0;
			return -1; /* Client disconnected */
		} else if (res > 0) {
			struct bbs_tcp_client *tcpclient;
			int sendstatus = 0;

			if (!client) {
				if (imap->client) {
					/* Stop idling on the selected mailbox (remote) */
					imap_client_idle_stop(imap->client);
				}
				imap_clients_renew_idle(imap); /* In case some of them are close to expiring, renew them now before returning */
				break; /* Client terminated the idle. Stop idling and return to read the next command. */
			}
			/* For remote NOTIFY: Some remote IMAP server sent us something.
			 * If it's something important, send our client an untagged STATUS for that mailbox. */
			tcpclient = &client->client;
			if (bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 100) < 0) { /* Must service the activity to satisfy poll */
				bbs_warning("Got activity on remote client connection for '%s' but failed to read line from it?\n", client->virtprefix);
				/* The remote peer probably closed the connection, and this client is now dead.
				 * We need to remove this now or poll will keep triggering for this client. */
				client->dead = 1;
				imap_client_unlink(imap, client);
				continue;
			}
			if (!client->idling) {
				/* This shouldn't happen, if we're not in IDLE, the server isn't allowed to send us unsolicited data. */
				bbs_warning("Got activity on a client that wasn't idling? (%s)\n", client->virtprefix);
				continue;
			} else if (imap->client == client) {
				/* This is the actual mailbox that is selected. Just relay anything we receive. */
				_imap_reply(imap, "%s\r\n", tcpclient->rldata.buf);
			} else {
				do {
					int seqno;
					char *s = tcpclient->rldata.buf;

					bbs_debug(4, "Received during IDLE: %s\n", tcpclient->rldata.buf);

					if (!STARTS_WITH(s, "*")) {
						bbs_warning("Unexpected data during background IDLE for '%s': %s\n", client->virtprefix, s);
						continue;
					}
					s += 2;
					if (strlen_zero(s)) {
						continue;
					}
					seqno = atoi(s);
					strsep(&s, " ");
					if (strlen_zero(s) || !seqno) {
						continue;
					}
					if (STARTS_WITH(s, "EXISTS") || STARTS_WITH(s, "EXPUNGE") || STARTS_WITH(s, "FETCH")) {
						/* In theory, client->bgmailbox contains the mailbox name so we could just
						 * construct our own STATUS response (e.g. for EXISTS, with MESSAGES),
						 * and send that.
						 * But RFC 5465 has specific requirements for what the STATUS message must contain,
						 * and that includes stuff that won't be obvious here (e.g. UIDVALIDITY, UIDNEXT, etc.)
						 * So, we're really just going to have to stop the IDLE at the end of this,
						 * get the STATUS of the mailbox, and send it back (modifying the name in the response, of course). */
						sendstatus = 1;
					}
					/* We should get at least one line, but there may be more.
					 * Poll just this fd quickly to exhaust it before returning to main poll.
					 * Wait max 500ms for further lines, e.g. FETCH. Waiting long enough
					 * helps because it avoids getting another response soon afterwards
					 * and then having to do another stop IDLE, do STATUS, start IDLE sequence for that. */
				} while (bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 500) > 0);
				if (sendstatus) {
					/* Is NOTIFY enabled for this mailbox? If not, ignore it */
					if (imap_notify_applicable(imap, NULL, client->bgmailbox, NULL, IMAP_EVENT_MESSAGE_NEW | IMAP_EVENT_MESSAGE_EXPUNGE | IMAP_EVENT_FLAG_CHANGE)) {
						/* Stop the IDLE, get the STATUS, then restart the IDLE */
						if (imap_client_idle_stop(client)) {
							continue;
						}
						/* Leave client->bgmailbox as is, since we're going to restart it momentarily */
						/* Clients SHOULD NOT issue a STATUS on the currently selected mailbox.
						 * But servers MUST be able to deal with it.
						 * However, ideally, we would store the SELECT and be able to construct what the STATUS response would be.
						 * It's reasonable to assume UIDVALIDITY will not change (though we'd get an untagged response if it did),
						 * but UIDNEXT might be less predictable, since it's not guaranteed to increase 1 by 1. */
						/* Again, bgmailbox is always an INBOX so we just hardcode that for now */
						imap_client_send_wait_response_cb_noecho(client, -1, SEC_MS(5), notify_status_cb, NULL, "STATUS \"%s\" (%s%s)\r\n", "INBOX", "MESSAGES UNSEEN UIDNEXT UIDVALIDITY", (imap->condstore || imap->qresync) && client->virtcapabilities & IMAP_CAPABILITY_CONDSTORE ? " HIGHESTMODSEQ" : ""); /* Covers all cases: MessageNew, MessageExpunge, FlagChange */
						imap_client_idle_start(client); /* Mailbox is still selected, no need to reselect */
						lastactivity = (int) time(NULL);
					} else {
						bbs_debug(7, "NOTIFY not enabled for %s, ignoring\n", client->bgmailbox);
					}
				}
			}
			imap_clients_renew_idle(imap);
		} else {
			/* Nothing yet. Send an "IDLE ping" to check in... */
			idleleft -= pollms;
			if (idleleft <= 0) {
				bbs_warning("IDLE expired without any activity\n");
				return -1; /* Disconnect the client now */
			} else {
				int now = (int) time(NULL);
				int elapsed = now - lastactivity;
				/* If we're coming up on the deadline (with a little bit of wiggle room, +/- in either direction), go ahead and do it */
				if (elapsed >= idle_notify_interval - (IMAP_IDLE_POLL_INTERVAL_SEC / 2)) {
					if (idlestarted < now - 1801) {
						/* It's been 30 minutes, so RFC 3501 now permits us to disconnect the client. */
						bbs_warning("IDLE expired\n");
						return -1;
					}
					imap_send(imap, "OK Still here");
					lastactivity = now;
				}
				imap_clients_renew_idle(imap);
			}
		}
	}
	return 0;
}

static int imap_process(struct imap_session *imap, char *s)
{
	int replacecount;
	char *command;
	int res = 0;

	if (imap->idle || (imap->alerted == 1 && !strcasecmp(s, "DONE"))) {
		/* Thunderbird clients will still send "DONE" if we send a tagged reply during the IDLE,
		 * but Microsoft Outlook will not, so handle both cases, i.e. tolerate the redundant DONE. */
		return idle_stop(imap);
	} else if (imap->alerted == 1) {
		imap->alerted = 2;
	}

	if (imap->inauth) {
		return handle_auth(imap, s);
	}

	if (strlen_zero(s)) {
		imap_send(imap, "BAD [CLIENTBUG] Invalid tag"); /* There isn't a tag, so we can't do a tagged reply */
		goto done; /* Ignore empty lines at this point (can't do this if in an APPEND) */
	}

	/* IMAP clients MUST use a different tag each command, but in practice this is treated as a SHOULD. Common IMAP servers do not enforce this. */
	imap->tag = strsep(&s, " "); /* Tag for client to identify responses to its request */
	command = strsep(&s, " ");

	if (!imap->tag || !command) {
		imap_send(imap, "BAD [CLIENTBUG] Missing arguments.");
		goto done;
	}

	flush_updates(imap, command, s);

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
			goto done;
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
			goto done;
		}
		/* Strip the domain, if present,
		 * but the domain must match our domain, if present. */
		domain = strchr(user, '@');
		if (domain) {
			*domain++ = '\0';
			if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
				imap_reply(imap, "NO [AUTHENTICATIONFAILED] Invalid username or password"); /* No such mailbox, since wrong domain! */
				goto done;
			}
		}
		res = bbs_authenticate(imap->node, user, pass);
		if (pass) {
			bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
		}
		if (res) {
			if (!bbs_num_auth_providers()) {
				imap_reply(imap, "NO [UNAVAILABLE] Authentication currently unavailable");
			} else {
				imap_reply(imap, "NO [AUTHENTICATIONFAILED] Invalid username or password");
			}
			goto done;
		}
		res = finish_auth(imap, 0);
	} else if (!strcasecmp(command, "UNAUTHENTICATE")) {
		if (!bbs_user_is_registered(imap->node->user)) {
			/* Before authentication check, because we cannot respond with a NO if this fails,
			 * we can only send an untagged BYE and disconnect.
			 * This shouldn't really happen anyways.
			 */
			imap_send(imap, "BYE Not currently logged in");
			return -1;
		}
		bbs_node_logout(imap->node);
		imap_destroy(imap);
		imap_reply(imap, "OK Logged out");
	/* Past this point, must be logged in. */
	} else if (!bbs_user_is_registered(imap->node->user)) {
		bbs_warning("'%s' command may not be used in the unauthenticated state\n", command);
		imap_reply(imap, "BAD Not logged in"); /* Not necessarily a client bug, could be our fault too if we don't implement something */
	} else if (!strcasecmp(command, "SELECT")) {
		res = handle_select(imap, s, CMD_SELECT);
	} else if (!strcasecmp(command, "EXAMINE")) {
		res = handle_select(imap, s, CMD_EXAMINE);
	} else if (!strcasecmp(command, "STATUS")) {
		res = handle_status(imap, s);
	} else if (!strcasecmp(command, "NAMESPACE")) {
		/* Good article for understanding namespaces: https://utcc.utoronto.ca/~cks/space/blog/sysadmin/IMAPPrefixesClientAndServer */
		imap_send(imap, "NAMESPACE %s %s %s", PRIVATE_NAMESPACE, OTHER_NAMESPACE, SHARED_NAMESPACE);
		imap_reply(imap, "NAMESPACE command completed");
	} else if (!strcasecmp(command, "LIST")) {
		res = handle_list(imap, s, CMD_LIST);
	} else if (!strcasecmp(command, "LSUB")) { /* Deprecated in RFC 9051 (IMAP4rev2), but clients still use it */
		/* Bit of a hack: just assume all folders are subscribed
		 * All clients share the subscription list, so clients should try to LSUB before they SUBSCRIBE to anything.
		 * For example, to check if the Sent folder is subscribed, for storing sent emails.
		 * This is because they don't know if other clients have already subscribed to these folders
		 * (and with this setup, it will appear that, indeed, some other client already has).
		 * We have stubs for SUBSCRIBE and UNSUBSCRIBE as well, but the LSUB response is actually the only important one.
		 * Since we return all folders as subscribed, clients shouldn't try to subscribe to anything.
		 */
		res = handle_list(imap, s, CMD_LSUB);
	} else if (!strcasecmp(command, "XLIST")) {
		res = handle_list(imap, s, CMD_XLIST);
	} else if (!strcasecmp(command, "CREATE")) {
		/*! \todo need to modify mailbox names like select, but can then pass it on (do in the commands) */
		IMAP_NO_READONLY(imap);
		res = handle_create(imap, s);
	} else if (!strcasecmp(command, "DELETE")) {
		IMAP_NO_READONLY(imap);
		res = handle_delete(imap, s);
	} else if (!strcasecmp(command, "RENAME")) {
		IMAP_NO_READONLY(imap);
		res = handle_rename(imap, s);
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
		if (imap->client) {
			imap_close_remote_mailbox(imap);
		} else {
			close_mailbox(imap);
		}
		imap_reply(imap, "OK UNSELECT completed");
	} else if (!strcasecmp(command, "FETCH")) {
		REQUIRE_SEQNO_ALLOWED();
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		res = handle_fetch(imap, s, 0);
	} else if (!strcasecmp(command, "COPY")) {
		REQUIRE_SEQNO_ALLOWED();
		/* The client may think two mailboxes are on the same server, when in reality they are not.
		 * If virtual mailbox, destination must also be on that server. Otherwise, reject the operation.
		 * We would need to transparently do an APPEND otherwise (which could be done, but isn't at the moment). */
		FORWARD_VIRT_MBOX_MODIFIED(1);
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		res = handle_copy(imap, s, 0);
	} else if (!strcasecmp(command, "MOVE")) {
		REQUIRE_ARGS(s);
		REQUIRE_SEQNO_ALLOWED();
		/*! \todo MOVE can be easily emulated if the remote server doesn't support it.
		 * We just do a COPY, EXPUNGE.
		 * Also note that the below check only catches if the source folder is remote,
		 * not if the destination is.
		 * But currently, either both have to be local or both have to be remote, so that's fine. */
		if (imap->client && !(imap->client->virtcapabilities & IMAP_CAPABILITY_MOVE)) {
			imap_reply(imap, "NO MOVE not supported for this mailbox");
			goto done;
		}
		FORWARD_VIRT_MBOX_MODIFIED(1);
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		res = handle_move(imap, s, 0);
	} else if (!strcasecmp(command, "STORE")) {
		REQUIRE_ARGS(s);
		REQUIRE_SEQNO_ALLOWED();
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		IMAP_NO_READONLY(imap);
		res = handle_store(imap, s, 0);
	} else if (!strcasecmp(command, "SEARCH")) {
		REQUIRE_ARGS(s);
		REQUIRE_SEQNO_ALLOWED();
		FORWARD_VIRT_MBOX();
		REQUIRE_SELECTED(imap);
		res = handle_search(imap, s, 0);
	} else if (!strcasecmp(command, "SORT")) {
		REQUIRE_ARGS(s);
		REQUIRE_SEQNO_ALLOWED();
		/*! \todo Clients will be confused if we advertise the SORT capability
		 * but the remote mailbox doesn't support it, so we have to reject a request.
		 * We could implement a "SORT" proxy where we do something like:
		 * - FETCH 1:* for all the relevant criteria (e.g. for ARRIVAL, we want INTERNALDATE)
		 * - Sort them locally
		 * - Return the result (and potentially cache it)
		 * Probably not feasible for SEARCH, because that might require requesting potentially the entire mailbox, e.g. for body search
		 * For THREAD we could do FETCH 1:* (RFC822.HEADER[References In-Reply-To])
		 */
		FORWARD_VIRT_MBOX_CAPABILITY(IMAP_CAPABILITY_SORT);
		REQUIRE_SELECTED(imap);
		res = handle_sort(imap, s, 0);
	} else if (!strcasecmp(command, "THREAD")) {
		REQUIRE_ARGS(s);
		REQUIRE_SEQNO_ALLOWED();
		FORWARD_VIRT_MBOX_CAPABILITY(IMAP_CAPABILITY_THREAD_ORDEREDSUBJECT | IMAP_CAPABILITY_THREAD_REFERENCES);
		REQUIRE_SELECTED(imap);
		res = handle_thread(imap, s, 0);
	} else if (!strcasecmp(command, "UID")) {
		REQUIRE_ARGS(s);
		if (!imap->client) { /* Ultimately, FORWARD_VIRT_MBOX will intercept this command, if it's valid */
			REQUIRE_SELECTED(imap);
		}
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		if (!strcasecmp(command, "FETCH")) {
			FORWARD_VIRT_MBOX_UID();
			res = handle_fetch(imap, s, 1);
		} else if (!strcasecmp(command, "COPY")) {
			FORWARD_VIRT_MBOX_MODIFIED_UID(1);
			res = handle_copy(imap, s, 1);
		} else if (!strcasecmp(command, "MOVE")) {
			if (imap->client && !(imap->client->virtcapabilities & IMAP_CAPABILITY_MOVE)) {
				imap_reply(imap, "NO MOVE not supported for this mailbox");
				goto done;
			}
			FORWARD_VIRT_MBOX_MODIFIED_UID(1);
			res = handle_move(imap, s, 1);
		} else if (!strcasecmp(command, "STORE")) {
			FORWARD_VIRT_MBOX_UID();
			res = handle_store(imap, s, 1);
		} else if (!strcasecmp(command, "SEARCH")) {
			FORWARD_VIRT_MBOX_UID();
			/* Should not send queued untagged updates after SEARCH or UID SEARCH,
			 * so just return immediately. */
			return handle_search(imap, s, 1);
		} else if (!strcasecmp(command, "SORT")) {
			FORWARD_VIRT_MBOX_UID_CAPABILITY(IMAP_CAPABILITY_SORT);
			res = handle_sort(imap, s, 1);
		} else if (!strcasecmp(command, "THREAD")) {
			FORWARD_VIRT_MBOX_UID_CAPABILITY(IMAP_CAPABILITY_THREAD_ORDEREDSUBJECT | IMAP_CAPABILITY_THREAD_REFERENCES);
			res = handle_thread(imap, s, 1);
		} else {
			imap_reply(imap, "BAD Invalid UID command");
		}
	} else if (!strcasecmp(command, "APPEND")) {
		REQUIRE_ARGS(s);
		if (imap->client) {
			/*! \todo This needs careful attention for virtual mappings */
			imap_reply(imap, "NO Operation not supported for virtual mailboxes");
			goto done;
		}
		IMAP_NO_READONLY(imap);
		res = handle_append(imap, s);
	} else if (allow_idle && !strcasecmp(command, "IDLE")) {
		return handle_idle(imap); /* No need to check for updates right after an IDLE */
	} else if (!strcasecmp(command, "NOTIFY")) {
		/* RFC 5465 NOTIFY */
		REQUIRE_ARGS(s);
		res = handle_notify(imap, s);
	} else if (!strcasecmp(command, "SETQUOTA")) {
		/* Requires QUOTASET, which we don't advertise in our capabilities, so clients shouldn't call this anyways... */
		imap_reply(imap, "NO [NOPERM] Permission Denied"); /* Users cannot adjust their own quotas, nice try... */
	} else if (!strcasecmp(command, "GETQUOTA")) {
		/* RFC 2087 / 9208 QUOTA */
		handle_getquota(imap);
		imap_reply(imap, "OK GETQUOTA complete");
	} else if (!strcasecmp(command, "GETQUOTAROOT")) {
		REQUIRE_ARGS(s);
		if (imap->client) {
			if (!(imap->client->virtcapabilities & IMAP_CAPABILITY_QUOTA)) {
				/* Not really anything nice we can do here. There is no "default" we can provide,
				 * and since our capabilities include QUOTA, the client will think we've gone and lied to it now.
				 * Apologies, dear client. If only you knew all the tricks we were playing on you right now. */
				imap_reply(imap, "NO Quota unavailable for this mailbox");
				goto done;
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
		char fullmaildir[256];
		int myacl;
		IMAP_NO_READONLY(imap);
		/* Since we don't check for mailbox existence (and everything is always subscribed anyways), no real need to check ACLs here */
		bbs_debug(1, "Ignoring sbscription attempt for %s for mailbox %d\n", S_IF(s), mailbox_id(imap->mbox));
		imap_reply(imap, "OK SUBSCRIBE completed"); /* Everything available is already subscribed anyways, so can't hurt */
		imap_translate_dir(imap, s, fullmaildir, sizeof(fullmaildir), &myacl);
		mailbox_dispatch_event_basic(EVENT_MAILBOX_SUBSCRIBE, imap->node, imap->mbox, fullmaildir);
	} else if (!strcasecmp(command, "UNSUBSCRIBE")) {
		char fullmaildir[256];
		int myacl;
		IMAP_NO_READONLY(imap);
		bbs_warning("Unsubscription attempt for %s for mailbox %d\n", S_IF(s), mailbox_id(imap->mbox));
		imap_reply(imap, "NO [NOPERM] Permission denied");
		imap_translate_dir(imap, s, fullmaildir, sizeof(fullmaildir), &myacl);
		mailbox_dispatch_event_basic(EVENT_MAILBOX_UNSUBSCRIBE, imap->node, imap->mbox, s);
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
			goto done;
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
		if (imap->client) {
			if (!(imap->client->virtcapabilities & IMAP_CAPABILITY_ACL)) {
				/* Remote server doesn't support ACLs.
				 * Don't send a MYRIGHTS command since the server will reject it.
				 * Just assume everything is allowed, which is reasonable. */
				myacl = IMAP_ACL_DEFAULT_PRIVATE;
				myacl &= ~IMAP_ACL_ADMINISTER; /* If server doesn't support ACL, there is no ACL administration */
				generate_acl_string(myacl, buf, sizeof(buf));
				imap_send(imap, "MYRIGHTS %s %s", s, buf);
				imap_reply(imap, "OK MYRIGHTS completed");
				goto done;
			}
			FORWARD_VIRT_MBOX_MODIFIED(1);
		}
		STRIP_QUOTES(s);
		/* If we don't have permission to list the mailbox, then we must reply with No such mailbox to avoid leaking its existence */
		if (imap_translate_dir(imap, s, buf, sizeof(buf), &myacl) || !IMAP_HAS_ACL(myacl, IMAP_ACL_LOOKUP)) {
			imap_reply(imap, "NO [NONEXISTENT] No such mailbox");
			goto done;
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
			goto done;
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
			goto done;
		}
		IMAP_REQUIRE_ACL(myacl, IMAP_ACL_ADMINISTER);
		getacl(imap, buf, s);
		imap_reply(imap, "OK GETACL complete");
	} else if (!strcasecmp(command, "SETACL")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX_MODIFIED(1);
		res = handle_setacl(imap, s, 0);
	} else if (!strcasecmp(command, "DELETEACL")) {
		REQUIRE_ARGS(s);
		FORWARD_VIRT_MBOX_MODIFIED(1);
		res = handle_setacl(imap, s, 1);
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

done:
	if (res) {
		bbs_debug(4, "%s command returned %d\n", command, res);
	} else {
		flush_updates(imap, command, NULL);
	}
	return res;
}

static void handle_client(struct imap_session *imap)
{
	char buf[8192]; /* Buffer size suggested by RFC 7162 Section 4 */
	struct readline_data rldata;
	const char *preauth_username;

	bbs_readline_init(&rldata, buf, sizeof(buf));
	imap->rldata = &rldata;

	preauth_username = preauth_username_match(imap->node->ip);
	if (preauth_username) {
		/* Resolve the username and see if we get a match. */
		struct bbs_user *user = bbs_user_from_username(preauth_username);
		if (!user) {
			bbs_warning("PREAUTH failed: no such user '%s'\n", preauth_username);
		} else {
			bbs_node_attach_user(imap->node, user);
			finalize_auth(imap);
		}
	}

	if (bbs_user_is_registered(imap->node->user)) {
		imap_send(imap, "PREAUTH [CAPABILITY %s] %s server logged in as %s", IMAP_CAPABILITIES, IMAP_REV, bbs_username(imap->node->user));
	} else {
		imap_send(imap, "OK [CAPABILITY %s] %s Service Ready", IMAP_CAPABILITIES, IMAP_REV);
	}

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
	mailbox_dispatch_event_basic(EVENT_LOGOUT, node, NULL, NULL);

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
	pthread_mutex_destroy(&imap.lock);
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

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("net_imap.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "allowidle", &allow_idle);
	bbs_config_val_set_true(cfg, "general", "idlenotifyinterval", &idle_notify_interval);
	bbs_config_val_set_uint(cfg, "general", "maxappendsize", &max_append_size);
	bbs_config_val_set_uint(cfg, "general", "maxuserproxies", &maxuserproxies);
	if (maxuserproxies > MAX_USER_PROXIES) {
		bbs_warning("Maximum maxuserproxies is %u\n", MAX_USER_PROXIES);
		maxuserproxies = MAX_USER_PROXIES;
	}

	/* IMAP */
	bbs_config_val_set_true(cfg, "imap", "enabled", &imap_enabled);
	bbs_config_val_set_port(cfg, "imap", "port", &imap_port);

	/* IMAPS */
	bbs_config_val_set_true(cfg, "imaps", "enabled", &imaps_enabled);
	bbs_config_val_set_port(cfg, "imaps", "port", &imaps_port);

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcasecmp(bbs_config_section_name(section), "preauth")) {
			struct bbs_keyval *keyval = NULL;
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_preauth_ip(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		}
	}

	return 0;
}

static struct bbs_unit_test tests[] =
{
	{ "IMAP LIST Interpretation", test_list_interpretation },
	{ "IMAP LIST Attributes", test_build_attributes },
	{ "IMAP FETCH Item Parsing", test_parse_fetch_items },
	{ "IMAP STORE Flags Parsing", test_flags_parsing },
	{ "IMAP Remote Mailbox Translation", test_remote_mailbox_substitution },
	{ "IMAP THREAD ORDEREDSUBJECT", test_thread_orderedsubject },
	{ "IMAP THREAD REFERENCES", test_thread_references },
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
	if (load_config()) {
		goto abort;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!imap_enabled && !imaps_enabled) {
		bbs_debug(3, "Neither IMAP nor IMAPS is enabled, declining to load\n");
		goto abort; /* Nothing is enabled */
	}
	if (imaps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, IMAPS may not be used\n");
		goto abort;
	}

	/* If we can't start the TCP listeners, decline to load */
	if (bbs_start_tcp_listener3(imap_enabled ? imap_port : 0, imaps_enabled ? imaps_port : 0, 0, "IMAP", "IMAPS", NULL, __imap_handler)) {
		goto abort;
	}

	bbs_register_tests(tests);
	mailbox_register_watcher(imap_mbox_watcher);
	bbs_register_alerter(alertmsg, 90);
	return 0;

abort:
	RWLIST_WRLOCK_REMOVE_ALL(&preauths, entry, free);
	return -1;
}

static int unload_module(void)
{
	bbs_unregister_alerter(alertmsg);
	bbs_unregister_tests(tests);
	mailbox_unregister_watcher(imap_mbox_watcher);
	if (imap_enabled) {
		bbs_stop_tcp_listener(imap_port);
	}
	if (imaps_enabled) {
		bbs_stop_tcp_listener(imaps_port);
	}
	RWLIST_WRLOCK_REMOVE_ALL(&preauths, entry, free);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC9051 IMAP", "mod_mail.so,mod_mimeparse.so");
