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

#define NNTP_MAX_PATH_LENGTH 1024

#define NNTP_MAX_LINE_LENGTH 512 /* RFC 3977 3.1. Includes CR LF (but not NUL) */
#define NNTP_MAX_ARG_LENGTH 497 /* RFC 3977 3.1 */
#define NNTP_BUFSIZ (NNTP_MAX_ARG_LENGTH + 1) /* For things like group names, etc. where we don't have any better official limitation to adhere to */

/* 2^31-1 */
#define NNTP_MAX_ARTICLE_NUMBER 2147483647

#define NNTP_MODE_TRANSIT 0
#define NNTP_MODE_READER 1

#define _nntp_send(nntp, fmt, ...) bbs_debug(4, "%p <= " fmt, nntp, ## __VA_ARGS__); bbs_node_fd_writef(nntp->node, nntp->node->wfd, fmt, ## __VA_ARGS__);
#define nntp_send(nntp, code, fmt, ...) _nntp_send(nntp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

/*! \brief Newsgroup metadata */
struct group_info {
	const char *name; /*!< Group name */
	int last; /*!< Last article number assigned in this group */
	int high; /*!< Reported high water mark */
	int low; /*!< Reported low water mark */
	int count; /*!< Reported article count */
	char status; /*!< Posting status (y/n/m) */
	time_t created; /*!< Epoch of group creation on this server */
	const char *creator; /*!< Creator name or email */
	const char *description; /*!< Group description */
};

/*! \brief Article overview metadata */
struct article_info {
	char *newsgroups;
	char *expires;
	char *subject;
	char *from;
	char *date;
	const char *messageid;
	char *references;
	size_t bytes;
	int lines;
};

struct bbs_node;

/*! \brief NNTP client (either reader or transit) */
struct nntp_session {
	struct bbs_node *node;
	char *currentgroup;
	int currentarticle;
	char *user;
	struct article_info artinfo; /* Temporary info saved about the current article being received */
	unsigned int mode:1; /* MODE (0 = transit, 1 = reader) */
	unsigned int inpeer_any:1; /* Whether this is an in peer authorized in at least one inpeer ACL */
};

#ifndef MAIN_NNTP_FILE
extern char newsdir[256];
#endif

/* ACLs */
enum nntp_acl_action {
	NNTP_ACL_READ,
	NNTP_ACL_POST,
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

int group_update_counts_locked(const char *groupname, int high, int low, int count);
int group_assign_article_number_locked(const char *groupname, int *restrict article_num);
int group_get_stats_locked(const char *groupname, int *last, int *high, int *low, int *count);

/* Abstract spool and active file interfaces
 * At the moment, there is only one implementation of each. */

/* Active file metadata */

int active_init(void);
void active_cleanup(void);
int active_group_create(struct group_info *g);
int active_group_delete(const char *groupname);
int active_group_update(const char *groupname, int *incrlast, int last, int high, int low, int count, char status, const char *description);
int active_group_info(const char *groupname, int *last, int *high, int *low, int *count, char *status, time_t *created, char *creator, size_t creatorlen, char *description, size_t descriplen);

enum list_category {
	LIST_INVALID = 0,
	LIST_ACTIVE = (1U << 0), /* Same as origina LIST command in RFC 977 (all permitted groups): <name> <high water mark> <low water mark> <posting permitted: y/n/m> */
	LIST_ACTIVE_TIMES = (1U << 1), /* active.times list provides creation information: <name> <epoch time of creation> <creator, i.e. email address> */
	LIST_NEWSGROUPS = (1U << 2), /* <name> <short description about purpose of the group> (groups for which information is unavailable may be omitted, i.e. may miss groups included in LIST ACTIVE) */
	LIST_DISTRIB_PATS = (1U << 3), /* distrib.pats list assists clients to choose a value for the Distribution header of an article being posted. */
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

/* News spool */
int spool_init(void);
void spool_cleanup(void);
int spool_group_create(const char *groupname);
int spool_group_delete(const char *groupname);
int spool_group_exists(const char *groupname);

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
 * \brief Send a client matching entries from the overview database (for XOVER, OVER)
 * \param nntp
 * \param groupname
 * \param min Minimum article number to match
 * \param max Maximum article number to match
 * \retval 0 on success (response sent to client)
 * \retval -1 on error (response not sent)
 * \retval 1 if group is empty (response not sent)
 */
int spool_group_overview(struct nntp_session *nntp, const char *groupname, int min, int max);

struct stringlist;

/*!
 * \brief Add an article to the spool for a particular group
 * \param groups List of groups to which to add the article
 * \param articleid The Message-ID
 * \param srcfd File descriptor from which to read article
 * \param len Length of article (number of bytes to read from srcfd)
 * \retval -1 on error (not added to any groups)
 * \returns Number of groups to which the article was added. Can be 0 (in particular, if delivery to all groups failed, and a group was full, errno will be set to ERANGE)
 * \note It's possible not all items in groups will be consumed, caller should call stringlist_empty afterwards
 */
int spool_article_create(struct stringlist *groups, struct article_info *artinfo, int srcfd, size_t len);

int spool_article_delete_by_number(const char *groupname, int article_num);

/*!
 * \brief Whether any message with this Message-ID exists in any group
 * \param messageid Message-ID
 * \retval 0 if no message exists
 * \retval 1 if message exists in some group
 */
int spool_article_exists(const char *messageid);

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

int test_wildmats(void);
