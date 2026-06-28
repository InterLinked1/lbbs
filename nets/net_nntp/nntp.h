/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief RFC 3977 Network News Transfer Protocol
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/linkedlists.h"

#define NNTP_MAX_PATH_LENGTH 1024
#define MAX_ARTICLE_GROUPS 512
#define MAX_ARTICLE_DISTRIBUTIONS 64

#define NNTP_MAX_LINE_LENGTH 512 /* RFC 3977 3.1. Includes CR LF (but not NUL) */
#define NNTP_MAX_ARG_LENGTH 497 /* RFC 3977 3.1 */
#define NNTP_BUFSIZ (NNTP_MAX_ARG_LENGTH + 1) /* For things like group names, etc. where we don't have any better official limitation to adhere to */
#define NNTP_LARGE_WILDMAT_BUFSIZ 4096

/* 2^31-1 */
#define NNTP_MAX_ARTICLE_NUMBER 2147483647

#define _nntp_send_fd(nntp, fd, fmt, ...) ({ bbs_debug(4, "%p <= " fmt, nntp, ## __VA_ARGS__); bbs_node_fd_writef(nntp->node, fd, fmt, ## __VA_ARGS__); })
#define _nntp_send(nntp, fmt, ...) ({ bbs_debug(4, "%p <= " fmt, nntp, ## __VA_ARGS__); bbs_node_fd_writef(nntp->node, nntp->node->wfd, fmt, ## __VA_ARGS__); })
#define nntp_send(nntp, code, fmt, ...) _nntp_send(nntp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

/*! \brief NNTP response codes as defined in RFC 3977 and elsewhere. */
/* Note: These are #define's instead of in an enum,
 * because we do not use it as an enum in the code,
 * and this way XSTR can be used to replace the constant with the number
 * (which is used in the tests). */
#define NNTP_INFO_HELP              100
#define NNTP_INFO_CAPABILITIES      101
#define NNTP_INFO_DATE              111
#define NNTP_OK_BANNER_POST         200
#define NNTP_OK_BANNER_NOPOST       201
#define NNTP_OK_QUIT                205
#define NNTP_OK_COMPRESS            206
#define NNTP_OK_GROUP               211
#define NNTP_OK_LIST                215
#define NNTP_OK_ARTICLE             220
#define NNTP_OK_HEAD                221
#define NNTP_OK_BODY                222
#define NNTP_OK_STAT                223
#define NNTP_OK_OVER                224
#define NNTP_OK_HDR                 225
#define NNTP_OK_NEWNEWS             230
#define NNTP_OK_NEWGROUPS           231
#define NNTP_OK_IHAVE               235
#define NNTP_OK_POST                240
#define NNTP_CONT_IHAVE             335
#define NNTP_CONT_POST              340
#define NNTP_FAIL_TERMINATING       400
#define NNTP_FAIL_WRONG_MODE        401 /* Wrong mode (e.g. not reader) */
#define NNTP_FAIL_ACTION            403 /* Internal fault, temporary problem */
#define NNTP_FAIL_BAD_GROUP         411 /* Group unknown */
#define NNTP_FAIL_NO_GROUP          412 /* Not in a newsgroup */
#define NNTP_FAIL_ARTNUM_INVALID    420 /* Current article is invalid */
#define NNTP_FAIL_NEXT              421
#define NNTP_FAIL_PREV              422
#define NNTP_FAIL_ARTNUM_NOTFOUND   423 /* Article not found (by art number) */
#define NNTP_FAIL_MSGID_NOTFOUND    430 /* Article not found (by Message-ID) */
#define NNTP_FAIL_IHAVE_REFUSE      435 /* IHAVE article not wanted */
#define NNTP_FAIL_IHAVE_DEFER       436 /* IHAVE article deferred */
#define NNTP_FAIL_IHAVE_REJECT      437 /* IHAVE article rejected */
#define NNTP_FAIL_POST_AUTH         440 /* Posting not allowed */
#define NNTP_FAIL_POST_REJECT       441 /* POST article rejected */
#define NNTP_ERR_COMMAND            500
#define NNTP_ERR_SYNTAX             501
#define NNTP_ERR_ACCESS             502
#define NNTP_ERR_UNAVAILABLE        503
#define NNTP_ERR_BASE64             504

/* Streaming extension. */
#define NNTP_OK_STREAM              203
#define NNTP_OK_CHECK               238
#define NNTP_OK_TAKETHIS            239
#define NNTP_FAIL_CHECK_DEFER       431
#define NNTP_FAIL_CHECK_REFUSE      438
#define NNTP_FAIL_TAKETHIS_REJECT   439

/* Authentication extensions */
#define NNTP_OK_AUTHINFO            281
#define NNTP_OK_SASL                283
#define NNTP_CONT_AUTHINFO          381
#define NNTP_CONT_SASL              383
#define NNTP_FAIL_AUTH_NEEDED       480
#define NNTP_FAIL_AUTHINFO_BAD      481
#define NNTP_FAIL_AUTHINFO_REJECT   482

/* Privacy extensions */
#define NNTP_CONT_STARTTLS          382
#define NNTP_FAIL_PRIVACY_NEEDED    483
#define NNTP_ERR_STARTTLS           580

/*! \brief Newsgroup metadata */
struct group_info {
	const char *name; /*!< Group name */
	int last; /*!< Last article number assigned in this group */
	int high; /*!< Reported high water mark */
	int low; /*!< Reported low water mark */
	int count; /*!< Reported article count */
	const char *status; /*!< Posting status (y/n/m/x/j/=other.group) */
	time_t created; /*!< Epoch of group creation on this server */
	const char *creator; /*!< Creator name or email */
	const char *description; /*!< Group description */
};

struct article_group {
	const char *name; /*!< The newsgroup name */
	int article_num; /*!< To be assigned when assigning the article number */
	int last; /*!< The highest numbered article previously assigned in the group */
	BBS_LIST_ENTRY(article_group) entry;
	char data[];
};

BBS_LIST_HEAD_NOLOCK(article_groups, article_group);

/*! \brief Article overview metadata */
struct article_info {
	/* As ordered for overview (fields 2-8) */
	char *subject;
	char *from;
	char *date;
	char *messageid;
	char *references;
	size_t bytes; /* This is the reported size of the article, rather than the actual size on disk (which can be larger when an article includes dot stuffed lines) */
	int lines;
	/* Optional fields */
	char *xref;
	/* Other (generally only used for processing incoming articles) */
	char *path;
	char *newsgroups;
	char *distribution;
	char *injectioninfo;
	char *injectiondate;
	char *organization;
	char *approved;
	char *control;
	char *expires;
	size_t headerslen; /* Length of headers, not including empty line separating headers/body */
	size_t prependlen;
	const char *prepend; /* Headers to prepend before all other headers, i.e. Path */
	size_t appendlen;
	const char *append; /* Headers to append after all other headers, except Xref */
	char *filepath;
	unsigned int nntp_posting_host_set:1;
	unsigned int needinjectiondate:1;
};

struct bbs_node;

enum nntp_mode {
	NNTP_MODE_TRANSIT = 0,
	NNTP_MODE_READER = 1,
};

/*! \brief NNTP client (either reader or transit) */
struct nntp_session {
	struct bbs_node *node;
	char *currentgroup;
	int currentarticle;
	char *user;
	struct article_info artinfo; /* Temporary info saved about the current article being received */
	enum nntp_mode mode;
	unsigned int inpeer_any:1; /* Whether this is an in peer authorized in at least one inpeer ACL */
	unsigned int inpeer_tlsrequired:1; /* Whether this is an in peer that is required to use TLS to deliver articles */
};

#ifndef MAIN_NNTP_FILE
extern char newsname[256];
extern char newsdir[256];
#endif

/* Article processing functions */

struct bbs_tcp_client;
struct readline_data;

void artinfo_reset(struct article_info *artinfo);

/*!
 * \brief Read an NNTP article from a TCP client
 * \param[out] artinfo Article info
 * \param[in] mode NNTP_MODE_READER or NNTP_MODE_TRANSIT
 * \param node Node if server receiving article, NULL otherwise
 * \param rldata Readline data structure if using node
 * \param tcpclient Client if acting as client receiving article from server, NULL otherwise
 * \param fp Temporary file handle
 * \param[out] artlen Article size, in bytes
 * \param[in] Article/Message ID, if expected (IHAVE/TAKETHIS)
 * \param[in] xrefslave Whether to slave article numbers off the received article's Xref header.
 * \param[out] errbuf Buffer in which an error message will be stored on failure
 * \param[in] errbuflen Size of errbuf
 * \retval 0 on success, process article
 * \retval -1 Connection closed, abort
 * \retval 1 Temporary error, reject article for now.
 * \retval 2 Permanent error (e.g. too big, malformed, etc.) Reject article.
 */
int nntp_read_article(struct article_info *artinfo, enum nntp_mode mode, struct bbs_node *node, struct readline_data *rldata, struct bbs_tcp_client *tcpclient, FILE *fp, size_t *artlen, const char *articleid, int xrefslave, char *errbuf, size_t errbuflen);

/*!
 * \brief Check article info that is available through overview
 * \retval 0 metadata okay, proceed
 * \retval -1 Article rejected/disqualified, error set in errbuf
 */
int check_article_overview(const char *subject, const char *from, const char *date, const char *messageid, const char *references, size_t bytes, int lines, const char *xref, char *errbuf, size_t errbuflen);

/*! \retval 0 on success, or 1 on duplicate or -1 for the default error code depending on mode */
int check_article(enum nntp_mode mode, struct nntp_session *nntp, struct article_info *artinfo, char *errbuf, size_t errbuflen);

void free_article_groups(struct article_groups *groups);
int article_groups_contains(struct article_groups *groups, const char *name);
int article_groups_add(struct article_groups *groups, const char *name);

int group_is_poison(const char *grp);

/*!
 * \brief Save a processed article into the spool and propagate it to peers
 * \param[in] groups NULL to autocreate from Newsgroups header
 * \param[in] artinfo
 * \param[in] srcfd File descriptor from which to read article
 * \param[in] artlen
 * \retval -1 on failure (not delivered to any groups)
 * \returns Number of groups that received the article
 * \note If artinfo->xref is already set, then its article numbers will be used instead of assigning them ourselves. The Xref header itself will be rewritten to reflect only groups carried locally.
 */
int article_create(struct article_groups *groups, struct article_info *artinfo, int srcfd, size_t artlen);

/* ACLs */
enum nntp_acl_action {
	NNTP_ACL_READ,
	NNTP_ACL_POST,
	NNTP_ACL_APPROVE,
	/* Could be extended for more granular control over operations (e.g. LIST, NEWNEWS, etc.) */
};

int allowed_by_acl_locked(struct nntp_session *nntp, const char *group, enum nntp_acl_action action);
int authorized_inpeer_for_group_locked(struct nntp_session *nntp, const char *group, enum nntp_acl_action action);

#define ACL_ALLOWED(nntp, group, action) (nntp->mode == NNTP_MODE_READER ? allowed_by_acl(nntp, group, action) : authorized_inpeer_for_group(nntp, group, action))
#define ACL_ALLOWED_LOCKED(nntp, group, action) (nntp->mode == NNTP_MODE_READER ? allowed_by_acl_locked(nntp, group, action) : authorized_inpeer_for_group_locked(nntp, group, action))

/*
 * RFC 3977 provides 3 ways of representing empty groups:
 * 1. Set high water mark to one less than the low water mark (PREFERRED)
 * 2. Set both water marks and the count to 0.
 * 3. Another option which is not even worth considering.
 *
 * INN uses method 1 in all cases (and even if a group has had articles, uses low=1 and high=0).
 *
 * With method 1, high is always less than low, but what should low be?
 * The intuitive approach is to set LOW = LAST + 1. After all, in an empty group,
 * article # LOW will never reappear again.
 * The change to INN here (https://github.com/InterNetNews/inn/issues/250) changed from this behavior
 * to effectively doing LOW = LAST, HIGH = LOW - 1, to deal with the case of overflow for NNTP_MAX_ARTICLE_NUMBER
 * However, in all other cases, it is still technically valid to do LOW = LAST + 1.
 * The low water mark would increment when you finally get to LAST=NNTP_MAX_ARTICLE_NUMBER,
 * but since the group is full at that point (and thus "done"), it's not a big deal.
 * The proposed erratum (https://www.rfc-editor.org/errata_search.php?rfc=3977&eid=1707)
 * also says that server synchronization is one reason to always do LOW = LAST rather than LOW = LAST + 1.
 * However, we don't support server synchronization, so that can safely be ignored.
 *
 * All this considered, in line with our goal of providing clients with as much "information"
 * in a response as possible, the goal here for empty groups:
 * 1. Use LOW = HIGH = 0 if a group has NEVER had articles (which is method #2, not preferred but permitted)
 * 2. Use LOW = LAST if LAST == NNTP_MAX_ARTICLE_NUMBER (new method used by INN, and preferred in RFC, only to prevent overflow for 2^31-1)
 * 3. Use LOW = LAST + 1 if LAST < NNTP_MAX_ARTICLE_NUMBER (old method used by INN, rejected by proposed erratum)
 *
 * This way, a client can tell if a group has ever had articles before as:
 * - HIGH = LOW = 0 indicates an empty group that has never had articles
 * - HIGH < LOW = LAST + 1 indicates an empty group that formerly had articles,
 *   and the low water mark is as high as is "legal"
 * - The canonical case of low=1/high=0 only applies to an empty group that only ever had 1 article total.
 *   Without step #1, this would be indistinguishable from an empty group that had never had articles.
 *   (Actually, this is not quite true; because of step #3, in this case, low=2/high=1. However, if we
 *    always set LOW = LAST rather than LAST + 1, then this WOULD be necessary to distnguish the two.)
 * - The client can't tell an empty group with LAST = NNTP_MAX_ARTICLE_NUMBER and LAST = NNTP_MAX_ARTICLE_NUMBER - 1
 *   apart, but that is the least important of all. Overall, we provide as much "information" as possible to clients
 *   way (of course, clients themselves won't behave differently, but users who see these numbers will have more insight).
 *
 * Anyways, the above describes the default behavior, true if both flags below are defined.
 * If you feel strongly that the behavior of the low water mark should be different (e.g. it should behave like INN or some other way),
 * uncomment both #define's (INN has never had the behavior of EMPTY_LOW_WATERMARK_IS_ZERO, and recent versions disable the behavior of MAXIMIZE_LOW_WATERMARK)
 * However, these settings MUST NOT BE CHANGED ON AN ACTIVE NEWS SERVER with articles already in it,
 * or you risk violating RFC 3977 by presenting a lower low water mark to a client than it has previously seen (which could happen if you disable MAXIMIZE_LOW_WATERMARK).
 */

/* In empty groups, set the low water mark to LAST + 1 instead of LAST, to maximize the low water mark as much as legally possible.
 * The RFC says to set LOW = LAST, to account for overflow, but that is only necessary in one particular edge case.
 * In all others, breaking with the RFC's recommendation allows us to provide more information. */
#define MAXIMIZE_LOW_WATERMARK

/* If a group has always been empty, return 0 for the low water mark instead of 1, as RFC 3977 prefers (but doesn't require).
 * Effectively, this is the opposite of MAXIMIZE_LOW_WATERMARK, but only when a group has never been used.
 * The advantage of this is that regardless of MAXIMIZE_LOW_WATERMARK, it makes it unambiguous that the group has always been empty, as opposed to having
 * previously had articles that all expired. However, if MAXIMIZE_LOW_WATERMARK is enabled, this is not strictly necessary.
 * At least ONE of these two options needs to be enabled for a client to be able to distinguish these two cases:
 * - an empty group which has never been used
 * - an empty group which previously had one article (which has since expired)
 * (And of the two flags, MAXIMIZE_LOW_WATERMARK is the better option to enable though having both enabled doesn't hurt.)
 */
/* #define EMPTY_LOW_WATERMARK_IS_ZERO */

#if defined(MAXIMIZE_LOW_WATERMARK) && defined(EMPTY_LOW_WATERMARK_IS_ZERO)
/* Both EMPTY_LOW_WATERMARK_IS_ZERO and MAXIMIZE_LOW_WATERMARK
 * Keep the low water mark as high as possible, but 0 if the group has never been posted to. */
#define FIX_EMPTY_GROUP_STATS(grphigh, grplow, grpcount) \
	if (!(grpcount) && (grplow)) { \
		if ((grplow) != NNTP_MAX_ARTICLE_NUMBER) { \
			(grplow) += 1; \
		} \
		(grphigh) = (grplow) - 1; \
	}
#elif defined(MAXIMIZE_LOW_WATERMARK)
/* Maximize low water mark, but low water mark is never less than 1.
 * Technically, this provides no less information than if EMPTY_LOW_WATERMARK_IS_ZERO were also defined,
 * because a group that had 1 article would have a low water mark of 2 (and high water mark of 1);
 * so if the low water mark is 1 and the high water mark is 0, the group has never been used.
 * However, unless users know what settings this server was compiled with it, users probably wouldn't know that. */
#define FIX_EMPTY_GROUP_STATS(grphigh, grplow, grpcount) \
	if (!(grpcount)) { \
		if ((grplow) != NNTP_MAX_ARTICLE_NUMBER) { \
			(grplow) += 1; \
		} \
		(grphigh) = (grplow) - 1; \
	}
#elif defined(EMPTY_LOW_WATERMARK_IS_ZERO)
/* Low water mark is 0 on initially empty group, and is 1 after article 1 deleted, rather than 2 */
#define FIX_EMPTY_GROUP_STATS(grphigh, grplow, grpcount) \
	if (!(grpcount) && (grplow)) { \
		if (!(grplow)) { \
			(grplow) += 1; \
		} \
		(grphigh) = (grplow) - 1; \
	}
#else
/* INN's current behavior: low water mark is 1 for both initially empty group and an empty group that had 1 article,
 * i.e. we maximize the low water mark ONLY when the group has never been used. */
#define FIX_EMPTY_GROUP_STATS(grphigh, grplow, grpcount) \
	if (!(grpcount)) { \
		if (!(grplow)) { \
			(grplow) += 1; \
		} \
		(grphigh) = (grplow) - 1; \
	}
#endif

/* General newsgroup management */

/* Because only group APIs that need to be accessed from the active and spool implementations
 * are available here, and we are normally locked there, only LOCKED variants should appear here: */

int group_create(const char *groupname, const char *status, const char *creator, const char *description);
int group_exists(const char *groupname);
int group_update_counts_locked(const char *groupname, int high, int low, int count);
int group_assign_article_number_locked(const char *groupname, int *restrict article_num, int *restrict last);
int group_get_stats_locked(const char *groupname, int *last, int *high, int *low, int *count);

/* Abstract spool and active file interfaces
 * At the moment, there is only one implementation of each. */

/* Active file metadata */

int active_init(void);
void active_cleanup(void);
int active_group_create(struct group_info *g);
int active_group_delete(const char *groupname);
int active_group_update(struct group_info *g, int *incrlast);
int active_group_info(const char *groupname, int *last, int *high, int *low, int *count, char *status, size_t statuslen, time_t *created, char *creator, size_t creatorlen, char *description, size_t descriplen);

enum list_category {
	LIST_INVALID = 0,
	LIST_ACTIVE = (1U << 0), /* Same as original LIST command in RFC 977 (all permitted groups): <name> <high water mark> <low water mark> <posting permitted: y/n/m> */
	LIST_COUNTS = (1U << 1), /* Same as LIST ACTIVE but with article count */
	LIST_ACTIVE_TIMES = (1U << 2), /* active.times list provides creation information: <name> <epoch time of creation> <creator, i.e. email address> */
	LIST_NEWSGROUPS = (1U << 3), /* <name> <short description about purpose of the group> (groups for which information is unavailable may be omitted, i.e. may miss groups included in LIST ACTIVE) */
	LIST_ACTIVE_ALL = (1U << 4), /* Everything in the active file */
	LIST_OVERVIEW_FMT = (1U << 5), /* format of overview file */
	LIST_HEADERS = (1U << 6), /* list headers supported for HDR */
	LIST_DISTRIB_PATS = (1U << 7), /* distrib.pats list assists clients to choose a value for the Distribution header of an article being posted. */
	LIST_DISTRIBUTIONS = (1U << 8), /* Distributions list (name and description of each distribution) */
	LIST_MODERATORS = (1U << 9), /* Moderators list */
	LIST_MOTD = (1U << 10), /* Message of the day */
	LIST_SUBSCRIPTIONS = (1U << 11), /* Subscriptions (recommended newsgroups) */
	LIST_PER_NEWSGROUP = (1U << 15), /* This LIST command is per-newsgroup */
};

/*!
 * \brief Send a LIST response to a client for a newsgroup-based category
 * \param nntp
 * \param listcat Category to send (remove LIST_PER_NEWSGROUP bitmask before calling, as it is assumed that is true if calling this function)
 * \param wildmat Optional wildmat to filter results, can be NULL
 * \retval 0 on success (response sent)
 * \retval nonzero on error (response not sent)
 */
int active_group_list(struct nntp_session *nntp, enum list_category listcat, const char *wildmat);

/*!
 * \brief Send a NEWGROUPS response to a client
 * \param nntp
 * \param newerthan Time filter - only groups newer than this time will be sent
 * \retval 0 on success (response sent)
 * \retval nonzero on error (response not sent)
 */
int active_group_list_newgroups(struct nntp_session *nntp, time_t newerthan);

/* News spool */
int spool_init(void);
void spool_cleanup(void);
int spool_group_create(const char *groupname);
int spool_group_delete(const char *groupname);
int spool_group_exists(const char *groupname);

/*!
 * \brief Send NEWNEWS response (excluding 230 response line)
 * \param nntp
 * \param wildmat Wildmat filter for groups to match
 * \param newerthan Only send articles newer than this timestamp
 * \retval 0 on success (including if no articles matched), -1 on failure
 */
int spool_newnews(struct nntp_session *nntp, const char *wildmat, time_t newerthan);

/*!
 * \brief Find the NEXT or LAST (previous) article in a newsgroup, using the spool (or its metadata)
 * \param groupname Newsgroup name
 * \param cur_artnum The current article number
 * \param[out] new_artnum The article number of the NEXT or LAST article as requested
 * \param direction +1 for NEXT, -1 for LAST
 * \param[out] msgidbuf The Message-ID of the NEXT or LAST message (will only be set on success if cur_artnum != new_artnum)
 * \param msgidlen Size of of msgidbuf
 * \retval -1 on error
 * \retval 0 on success, including if no NEXT or LAST article could be found
 *         If there was no NEXT or LAST article, new_artnum will be the same as cur_artnum
 */
int spool_group_seek(const char *groupname, int cur_artnum, int *new_artnum, int direction, char *msgidbuf, size_t msgidlen);

/*!
 * \brief Send a client a list of article numbers within the group
 * \param nntp
 * \param groupname Group name
 * \param min Minimum article number to match
 * \param max Maximum article number to match
 * \retval 0 on success (response sent to client, including trailing . on its own line)
 * \retval -1 on error (response not sent)
 * \retval 1 if group is empty (response not sent)
 */
int spool_group_list_articles(struct nntp_session *nntp, const char *groupname, int min, int max);

/*!
 * \brief Send a client matching entries from the overview database (for XOVER, OVER)
 * \param nntp
 * \param messageid Message-ID of article, if searching by message-ID
 * \param groupname Group name, required if searching by article number. May also be provided to indicate the currently selected group.
 * \param min Minimum article number to match
 * \param max Maximum article number to match
 * \retval 0 on success (response sent to client)
 * \retval -1 on error (response not sent)
 * \retval 1 if group is empty (response not sent)
 */
int spool_group_overview(struct nntp_session *nntp, const char *messageid, const char *groupname, int min, int max);

enum nntp_hdr_cmd {
	NNTP_HDR,
	NNTP_XHDR,
	NNTP_XPAT,
};

/*!
 * \brief Send a client matching entries from the overview database (for HDR/XHDR/XPAT)
 * \param nntp
 * \param field Header or metadata field to send
 * \param messageid Message-ID of article, if searching by message-ID
 * \param groupname Group name, required if searching by article number. May also be provided to indicate the currently selected group.
 * \param min Minimum article number to match
 * \param max Maximum article number to match
 * \param cmd Type of command
 * \param pattern Pattern (for XPAT)
 * \retval 0 on success (response sent to client)
 * \retval -1 on error (response not sent)
 * \retval 1 if group is empty (response not sent)
 * \retval 2 if field is invalid (response not sent)
 */
int spool_group_overview_header(struct nntp_session *nntp, const char *field, const char *messageid, const char *groupname, int min, int max, enum nntp_hdr_cmd cmd, const char *pattern);

/*!
 * \brief Send LIST OVERVIEW.FMT or LIST HEADERS response
 * \param nntp
 * \param listcat The response to send
 * \param argument The optional third argument (only used for LIST HEADERS, should be MSGID, RANGE, or NULL)
 * \retval 0
 */
int spool_overview_header_list(struct nntp_session *nntp, enum list_category listcat, const char *argument);

struct stringlist;

/*!
 * \brief Add an article to the spool for a particular group
 * \param groups List of groups to which to add the article. Caller is responsible for freeing the list's contents afterwards.
 * \param articleid The Message-ID
 * \param srcfd File descriptor from which to read article
 * \param len Length of article (number of bytes to read from srcfd). Note this included dot-stuffing characters (which should NOT be included in artinfo->bytes)
 * \retval -1 on error (not added to any groups)
 * \returns Number of groups to which the article was added. Can be 0 (in particular, if delivery to all groups failed, and a group was full, errno will be set to ERANGE)
 * \note It's possible not all items in groups will be consumed, caller should call stringlist_empty afterwards
 */
int spool_article_create(struct article_groups *groups, struct article_info *artinfo, int srcfd, size_t len);

int spool_article_delete_by_number(const char *groupname, int article_num);

/*!
 * \brief Whether a given article exists in a group
 * \param groupname
 * \param article_num
 * \retval 1 if article exists in the spool
 * \retval 0 if article doesn't exist in the spool
 */
int spool_article_exists(const char *groupname, int article_num);

/*!
 * \brief Whether any message with this Message-ID exists in any group
 * \param messageid Message-ID of article, if searching by message-ID
 * \param groupname Group name, required if searching by article number.
 * \param article_num Article number, if searching by article number
 * \retval 0 on success (article exists), -1 on error, 1 if article does not exist
 */
int spool_article_stat(struct nntp_session *nntp, const char *messageid, const char *groupname, int article_num);

/*!
 * \brief Get the (a) file path on disk to an article
 * \param groupname Article's group name
 * \param article_num Article's number within the group
 * \param[out] buf Full file path
 * \param[in] len Size of buf
 * \param[out] is_compressed Whether or not the article is compressed
 * \note This function should generally be avoided as it is usually unnecessary outside of the spool implementation to know the path to a file
 */
int spool_get_article_path(const char *groupname, int article_num, char *buf, size_t len, int *restrict is_compressed);

struct bbs_tcp_client;

/*!
 * \brief Send an article using a TCP client
 * \param tcpclient
 * \param artpath Path to the article (may or may not be compressed)
 * \retval -1 on error
 * \retval 0 if artpath does not exist
 * \returns Number of bytes written to file descriptor
 */
ssize_t spool_article_send_raw(struct bbs_tcp_client *tcpclient, const char *artpath);

/*!
 * \brief Send an article using a TCP client, except for its Xref header, if it has one
 * \param tcpclient
 * \param artpath Path to the article (may or may not be compressed)
 * \retval -1 on error
 * \retval 0 if artpath does not exist
 * \returns Number of bytes written to file descriptor
 */
ssize_t spool_article_send_raw_noxref(struct bbs_tcp_client *tcpclient, const char *artpath);

enum article_part_filter {
	SEND_HEADERS = (1 << 0),
	SEND_BODY = (1 << 1),
};

/*!
 * \brief Send part or all of an article
 * \param nntp
 * \param filter
 * \param messageid Message-ID of article, if searching by message-ID
 * \param groupname Group name, required if searching by article number. May also be provided to indicate the currently selected group.
 * \param article_num Article number, if searching by article number
 * \retval 0 on success, -1 on error, 1 if article does not exist
 */
int spool_article_send(struct nntp_session *nntp, enum article_part_filter filter, const char *messageid, const char *groupname, int article_num);

/* Wildmat pattern matching */

/*! \brief Check for match for a whole wildmat */
int uwildmat(const char *text, const char *patterns);

/*!
 * \brief Check for match for a whole wildmat, allowing poison patterns
 * \retval 1 match
 * \retval 0 doesn't match
 * \retval -1 poison match
 */
int uwildmat_poison(const char *text, const char *pattern);

/*! \brief Check for match with simple expression (neither , nor ! are special) */
int uwildmat_simple(const char *text, const char *pattern);

int test_wildmats(void);
