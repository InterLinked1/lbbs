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

/* General newsgroup management */

#define FIX_EMPTY_GROUP_STATS(grphigh, grplow, grpcount) \
	/* Fiddle the water marks for empty groups */ \
	if (!(grpcount)) { \
		if (!(grplow)) { \
			(grplow) = 1; \
		} \
		/* If the group is empty, HIGH = LOW - 1 (not LOW = HIGH + 1, as one might intuit). \
		 * This is to prevent overflow if the high water mark is the max article number. */ \
		(grphigh) = (grplow) - 1; \
	}

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
