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
 * \brief RFC 3977 Network News Transfer Protocol (NNTP)
 *
 * \note Supports RFC 4642 STARTTLS
 * \note Supports RFC 4643 AUTHINFO
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>

#include "include/stringlist.h"
#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/cli.h"
#include "include/term.h"
#include "include/test.h"

#include "include/mod_mail.h"
#include "include/mod_uuid.h"

#define MAIN_NNTP_FILE
#include "net_nntp/nntp.h"

/* NNTP ports */
/* Reading server */
#define DEFAULT_NNTP_PORT 119
#define DEFAULT_NNTPS_PORT 563
/* Transit server */
#define DEFAULT_NNSP_PORT 433

/*
 * If you are new to newsgroups (no pun intended),
 * here are a few resources to help you get started:
 *
 * - https://www.eternal-september.org/
 * - https://www.big-8.org/wiki/Newsgroup_Creation_FAQ#Can_I_propose_a_new_newsgroup_now.3F
 * - https://www.eyrie.org/~eagle/faqs/mod-pitfalls.html
 * - https://www.eyrie.org/~eagle/faqs/usenet-hier.html
 * - ftp://ftp.isc.org/pub/usenet/CONFIG/
 */

static int nntp_port = DEFAULT_NNTP_PORT;
static int nntps_port = DEFAULT_NNTPS_PORT;
static int nnsp_port = DEFAULT_NNSP_PORT;

static int nntp_enabled = 1, nntps_enabled = 1, nnsp_enabled = 1;

static bbs_rwlock_t nntp_lock;

/* General settings */
char newsdir[256] = ""; /* Non-static so other files can access it extern */
static unsigned int max_post_size = 100000; /* 100 KB should be plenty */

/* Relay in */
static int requirerelaytls = 1;

/* Relay out */
static unsigned int relayfrequency = 3600;
static unsigned int relaymaxage = 86400;

/* Reader settings */
static int require_secure_login = 0;
static int check_identity = 1;

static struct stringlist outpeers;

/* =============== Begin ACL Code =============== */

struct reader_acl {
	const char *users; /*!< Wildmat of usernames to which this ACL applies */
	const char *read; /*!< Wildmat of newsgroups for which this ACL allows read access */
	const char *post; /*!< Wildmat of newsgroups for which this ACL authorizes posting */
	int minreadpriv; /*!< Additional minimum privilege required for read access */
	int minpostpriv; /*!< Additional minimum privilege required for post access */
	struct stringlist guests; /*!< List of IPv4 CIDR ranges to which this ACL applies */
	RWLIST_ENTRY(reader_acl) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(acls, reader_acl);

static void free_acl(struct reader_acl *acl)
{
	stringlist_empty_destroy(&acl->guests);
	free(acl);
}

static int load_acl(const char *guests, const char *userswm, const char *readwm, const char *postwm, int minreadpriv, int minpostpriv)
{
	struct reader_acl *acl;
	size_t userslen, readlen, postlen;
	char *data;

	/* Because ACLs are checked frequently and there may be multiple that we need to check, for any given operation,
	 * we optimize for efficiency during runtime, i.e. we shouldn't need to copy/split strings later. */
	userslen = STRING_ALLOC_SIZE(userswm);
	readlen = STRING_ALLOC_SIZE(readwm);
	postlen = STRING_ALLOC_SIZE(postwm);

	acl = calloc(1, sizeof(*acl) + userslen + readlen + postlen);
	if (ALLOC_FAILURE(acl)) {
		return -1;
	}

	data = acl->data;
	SET_FSM_STRING_VAR(acl, data, users, userswm, userslen);
	SET_FSM_STRING_VAR(acl, data, read, readwm, readlen);
	SET_FSM_STRING_VAR(acl, data, post, postwm, postlen);

	acl->minreadpriv = minreadpriv;
	acl->minpostpriv = minpostpriv;

	stringlist_init(&acl->guests);
	if (guests) {
		stringlist_push_list(&acl->guests, guests);
	}
	RWLIST_INSERT_HEAD(&acls, acl, entry);
	return 0;
}

static inline int stringlist_contains_ip(struct stringlist *l, const char *ip)
{
	const char *s;
	struct stringitem *i = NULL;

	while ((s = stringlist_next(l, &i))) {
		if (bbs_ip_match_ipv4(ip, s)) {
			return 1;
		}
	}
	return 0;
}

/*! \brief Whether this reader ACL matches the connection */
static inline int acl_matches(struct nntp_session *nntp, struct reader_acl *acl)
{
	if (bbs_user_is_registered(nntp->node->user)) {
		/* Authenticated user, the wildmat has to match the username */
		if (acl->users) {
			return uwildmat(bbs_username(nntp->node->user), acl->users);
		} else {
			return 0; /* No authenticated users authorized by this ACL */
		}
	} else {
		/* Guest user */
		return stringlist_contains_ip(&acl->guests, nntp->node->ip); /* Okay, even if list is empty */
	}
}

/*! \brief Whether a connection is allowed to perform a certain action against a certain group */
int allowed_by_acl_locked(struct nntp_session *nntp, const char *group, enum nntp_acl_action action)
{
	struct reader_acl *acl;
	int acl_count = 0;

	RWLIST_TRAVERSE(&acls, acl, entry) {
		acl_count++;
		if (acl_matches(nntp, acl)) {
			/* ACL matches the connection, check if it allows this action */
			switch (action) {
				case NNTP_ACL_READ:
					if (acl->read && uwildmat(group, acl->read)) {
						if (!acl->minreadpriv || (bbs_user_is_registered(nntp->node->user) && nntp->node->user->priv >= acl->minreadpriv)) {
							return 1;
						}
					}
					break;
				case NNTP_ACL_POST:
					if (acl->post && uwildmat(group, acl->post)) {
						if (!acl->minpostpriv || (bbs_user_is_registered(nntp->node->user) && nntp->node->user->priv >= acl->minpostpriv)) {
							return 1;
						}
					}
					break;
			}
		}
	}

	return acl_count ? 0 : 1; /* If no ACLs are configured, actions are implicitly authorized */
}

static int allowed_by_acl(struct nntp_session *nntp, const char *group, enum nntp_acl_action action)
{
	int res;
	RWLIST_RDLOCK(&acls);
	res = allowed_by_acl_locked(nntp, group, action);
	RWLIST_UNLOCK(&acls);
	return res;
}

/*! \brief Whether guests are able to post at all without logging in */
static int guests_can_post_at_all(void)
{
	static int computed = 0;
	static int guests_can_post = 0;
	if (!computed) {
		struct reader_acl *acl;
		RWLIST_RDLOCK(&acls);
		RWLIST_TRAVERSE(&acls, acl, entry) {
			if (!stringlist_is_empty(&acl->guests) && acl->post) {
				/* Seems likely that guest users are possibly authorized to post to some newsgroups */
				guests_can_post = 1;
				break;
			}
		}
		RWLIST_UNLOCK(&acls);
		computed = 1;
	}
	return guests_can_post;
}

/* For inpeers, we use a slightly less expressive form of ACL that is equivalent to treating read and post the same (without some of the other reader ACL options)
 * In theory, we COULD have used the same ACL structure and allowed for the same configuration, but it's not quite the same use case.
 * In particular, reading clients will generally authenticate, while transit clients generally won't.
 * The actual underlying differences in ACL handling between transit and reader clients are mostly abstracted away using the ACL_ macros,
 * so if we wanted to change this in the future, it would not be super disruptive. */

/*! \brief ACL for transit peer authorized to send us articles (using IHAVE) */
enum inpeer_type {
	INPEER_IPV4,
	INPEER_HOSTNAME,
	INPEER_USERNAME,
};

struct inpeer {
	const char *identity; /*!< IPv4 address, hostname, or username */
	const char *groups; /*!< Wildmat of newsgroups for which this ACL authorizes IHAVE posting */
	enum inpeer_type type;
	RWLIST_ENTRY(inpeer) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(inpeers, inpeer);

static int add_inpeer(const char *identity, const char *groups)
{
	struct inpeer *i;
	char *data;
	size_t idlen = STRING_ALLOC_SIZE(identity);
	size_t grplen = STRING_ALLOC_SIZE(groups);

	i = calloc(1, sizeof(*i) + idlen + grplen);
	if (ALLOC_FAILURE(i)) {
		return -1;
	}

	data = i->data;
	SET_FSM_STRING_VAR(i, data, identity, identity, idlen);
	SET_FSM_STRING_VAR(i, data, groups, groups, grplen);

	/* Determine which type of peer it is now, so we don't have to determine it later */
	if (bbs_user_exists(identity)) {
		i->type = INPEER_USERNAME;
	} else {
		i->type = bbs_hostname_is_ipv4(identity) ? INPEER_IPV4 : INPEER_HOSTNAME;
	}
	RWLIST_INSERT_HEAD(&inpeers, i, entry);
	return 0;
}

static inline int inpeer_acl_matches(struct nntp_session *nntp, struct inpeer *i)
{
	switch (i->type) {
		case INPEER_IPV4:
		case INPEER_HOSTNAME:
			if (bbs_ip_match_ipv4(nntp->node->ip, i->identity)) {
				return 1;
			}
			break;
		case INPEER_USERNAME:
			if (bbs_user_is_registered(nntp->node->user) && !strcmp(bbs_username(nntp->node->user), i->identity)) {
				return 1;
			}
			break;
	}
	return 0;
}

/*! \brief Whether a transit peer is authorized for any groups (not necessarily the one of interest) */
static int authorized_inpeer_for_any_groups(struct nntp_session *nntp)
{
	struct inpeer *i;

	RWLIST_RDLOCK(&inpeers);
	RWLIST_TRAVERSE(&inpeers, i, entry) {
		if (inpeer_acl_matches(nntp, i)) {
			RWLIST_UNLOCK(&inpeers);
			return 1;
		}
	}
	RWLIST_UNLOCK(&inpeers);

	return 0;
}

/*! \brief Whether a transit peer is authorized for a specific group, e.g. for IHAVE */
int authorized_inpeer_for_group_locked(struct nntp_session *nntp, const char *group, enum nntp_acl_action action)
{
	struct inpeer *i;

	UNUSED(action); /* Assumed to be NNTP_ACL_POST, but not currently checked. In theory, the ACL mechanism could be extended to allow IHAVE but deny reading, for example. */

	RWLIST_TRAVERSE(&inpeers, i, entry) {
		if (inpeer_acl_matches(nntp, i)) {
			if (uwildmat(group, i->groups)) {
				return 1;
			}
		}
	}
	return 0;
}

static int authorized_inpeer_for_group(struct nntp_session *nntp, const char *group, enum nntp_acl_action action)
{
	int res;
	RWLIST_RDLOCK(&inpeers);
	res = authorized_inpeer_for_group_locked(nntp, group, action);
	RWLIST_UNLOCK(&inpeers);
	return res;
}

/* When a client connects, and after any authentication, we cache whether this client is authorized for any groups by an inpeer ACL.
 * This way, if not, we can easily deny IHAVE attempts without wasting resources going through the whole post process,
 * only to check ACLs for all groups in the post and find that none authorize posting. */
#define RECHECK_TRANSIT_ACL(nntp) \
	/* In case an inpeer ACL would match the user that just authenticated, recheck: */ \
	if (!nntp->inpeer_any) { /* If an ACL already matched, it won't stop matching now, no need to recheck in that case */ \
		SET_BITFIELD(nntp->inpeer_any, authorized_inpeer_for_any_groups(nntp)); \
	}

#define ACL_RDLOCK(nntp) \
	if (nntp->mode == NNTP_MODE_READER) { \
		RWLIST_RDLOCK(&acls); \
	} else { \
		RWLIST_RDLOCK(&inpeers); \
	}

#define ACL_UNLOCK(nntp) \
	if (nntp->mode == NNTP_MODE_READER) { \
		RWLIST_UNLOCK(&acls); \
	} else { \
		RWLIST_UNLOCK(&inpeers); \
	}

/* =============== End ACL Code =============== */

static void artinfo_reset(struct article_info *artinfo)
{
	free_if(artinfo->newsgroups);
	free_if(artinfo->expires);
	free_if(artinfo->subject);
	free_if(artinfo->from);
	free_if(artinfo->date);
	/* artinfo->messageid is not dynamically allocated, do not free */
	artinfo->messageid = NULL;
	free_if(artinfo->references);
	artinfo->bytes = 0;
	artinfo->lines = 0;
}

static void nntp_reset_data(struct nntp_session *nntp)
{
	artinfo_reset(&nntp->artinfo);
}

static void nntp_destroy(struct nntp_session *nntp)
{
	nntp_reset_data(nntp);
	free_if(nntp->user);
	free_if(nntp->currentgroup);
	UNUSED(nntp);
}

#define REQUIRE_ARGS(s) \
	if (strlen_zero(s)) { \
		nntp_send(nntp, 501, "Arguments required"); \
		return 0; \
	}

/* =============== Begin Group Metadata Operations =============== */

/*! \note
 * This is a very long comment, but it documents some important things to understand about how news servers have behaved historically,
 * which sets the stage for the architecture of this news server, particularly ways in which it deviates from convention.
 *
 * ----------------------------------------------------------------------------------------------------
 *
 * First, the high and low water marks, which have the following requirements per RFC 3977 6.1.1.2:
 * - the reported low water mark is the article number of the first article in the group at the moment
 * - the reported high water mark is the article number of the last article in the group at the moment
 * - empty groups may be represented these ways:
 *   1. The high water mark is one less than the low water mark, and count is 0 (preferred in RFC 3977)
 *   2. All three numbers are 0 (low, high, count)
 *   3. High water mark is >= low water mark, count may be zero or nonzero (weird case we won't consider)
 *
 * Keeping in mind:
 * - New articles may be added with article #s higher than reported high water mark when GROUP was issued
 * - Low water mark MUST be no less than in any previous response during session, and SHOULD be no less than in any previous response, ever (an invariant we maintain)
 * - Clients can use low water mark to remove all remembered information about articles with lower numbers (even when high < low)
 * - High water mark can decrease if an article is removed and increase again if reinstated or new articles arrive (and it's implied that it should decrease, by 6.1.1.2, sixth bullet)
 *
 * The above applies to client-facing response during a reader session. Then, there is also the active file, with a canonical format of <name> <high> <low> <status>:
 * - <high> = highest article number ever used in the newsgroup. This is used to ensure article numbers are never reused and monotonically increase.
 * - <low> = lowest article number in the group (same as the reported low water mark).
 *
 * While <high> as stored in the active file is generally called just that, we will henceforth refer to it as <last>.
 *
 * The distinction between <last> and the reported high water mark in theory and in practice (or lack of distinction thereof) is a possible source of confusion.
 * and a reflection of design philosophy. It is useful to understand how INN (InterNetNews) handle certain operations, to understand why we have chosen different behavior.
 * Much thanks to Russ Allbery in news.software.nntp for many of these insights:
 *
 * High water marks:
 *
 * - INN normally never decreases the high water mark (save for renumbering). For example, if the latest article is deleted, the high water mark will not decrease.
 *   - This is how most news servers have historically behaved, so the implication in RFC 3977 that servers "should" decrease the high water mark in this case is a "bug".
 *   - In practice, it has no real effect, since news readers are required to handle this situation anyways, as:
 *     - The set of articles in a group may change after GROUP due to articles being removed from the group (paraphrased from RFC 3977 6.1.1.2)
 *     - This applies to LIST ACTIVE as well (which also reports high/low water marks), and of course articles could legitimately disappear after the response before further operations.
 * - There are two ways that news servers could report the high water mark:
 *   1. Keep low/high water marks in only one place, increment the high water mark on every new article, and never decrement it because it doubles as the source of the next article number
 *   2. Keep internal "next article number" data for each group, but report the high water mark based on what articles are in the spool at the time.
 *
 * Both options are "legal" by the RFC, since clients can't definitively tell that a server did not provide the "true" high water mark.
 * #1 prioritizes performance. #2 prioritizes correctness (providing the most meaningful responses possible to a client).
 * INN, and most existing servers, use #1, for performance reasons, though #2 is arguably more correct (hence the RFC allowing this behavior, but not requiring it, to "grandfather" existing behavior).
 *
 * There are a few advantages of using behavior #2:
 * - The count of articles from LIST ACTIVE (and GROUP, etc.) will be more correct if the highest-numbered article is removed.
 *   Note the count may still be inaccurate for the more common case of articles "in the middle" missing; the count is required to be at least
 *   the number of articles available, but could be as many as <high> - <low> + 1 (and frequently estimated this way for performance).
 *
 * Low water marks:
 *
 * - The best response (providing the most information) is to increase the low water mark as much as is "legal" at any given time,
 *   i.e. if the oldest article is deleted, immediately raise the low water mark.
 *   - This allows clients to "forget" information about older articles, since the server indicates such articles will never reappear.
 *   - This should not be done if there is a possibility lower article numbers will be reinstated
 *     - In the most extreme case of "any" article can be reinstated, the low water mark can only ever be 1 (which is not very useful).
 *     - INN doesn't support article reinstation at all, so it never tries to "reserve" low water mark space.
 *
 * Article count:
 * - This is another metric about which traditional news servers (e.g. INN) are not always faithful.
 *   For performance, INN has an adjustable setting (groupexactcount) to control when it reports the true count vs. an estimate (<high> - <low> + 1) which may be wildly off.
 *
 * Active file:
 *
 * - There are several canonical files used by news servers historically, e.g.:
 *   - active (for LIST ACTIVE): <name> <high> <low> <status>, space-separated
 *   - active.times (for LIST ACTIVE.TIMES): <name> <epoch> <creator>, space-separated, sorted by group creation (thus appended to only and never rewritten)
 *   - newsgroups (for LIST NEWSGROUPS): <name> <description>, space or tab-separated
 * - Historically, these have been separate files to avoid breaking compatibility with existing files (and the commands reflect the canonical file structure)
 * - Desynchronization between some of these files has historically been a painpoint in INN
 *
 * However, we are not beholden to these formats, simply to match historical convention.
 * There are some good reasons to combine all of these (and more) into a single "extended" active file, e.g. with this format.
 * - If we are tracking <last> separately from <high> (approach #2), we need to store this additional metadata per group - and the active file is the natural place to do so.
 * - We may as well also store <count> here (for GROUP, LIST COUNT)
 * At this point, we've modified the format from the traditional <name> <high> <low> <status>, so we may as well change it completely to optimize it as much as possible:
 * - It avoids inconsistency between files - each group is defined in a single file, as opposed to having different properties in different files, which could get out of sync.
 *   - RFC 3977 states the list of groups in various LIST commands may differ, but this was more to "tolerate" existing bugs, not to condone this behavior.
 *     Ideally, the list of groups would match (i.e. "the list of groups returned by these commands SHOULD NOT differ" is the best way to interpret it now).
 * - While this would require all of the LIST commands to parse out the info they need from the line in this file (rather than sending it raw), there are advantages, too, of this approach.
 *   - Notably, in the active file, we want to zero-pad the water marks and <last> so we can make edits to them in place, without rewriting the whole file.
 *     However, if we have to parse the line anyways before sending it to a reader, we don't need to send the number zero-padded, so we can save bandwidth for LIST ACTIVE (up to 18 bytes per group).
 * - Disadvantages:
 *   - The extended active file would need to be rewritten if the description changes (or the creator, though that shouldn't really change?)
 *     This was true of .newsgroups as well, but since it was separate, that wasn't disruptive to the active file.
 *
 * Data Store:
 *
 * Historically, the active file has been a literal file (typically named .active)
 * - Flat files historically were how data was stored, so there's nothing "wrong" with using flat files - they are simpler, but may have some annoying edges.
 * - While INN still uses files, some of its functionality now leverages databases, e.g. SQLite for overview data for constant-time GROUP responses.
 * - Disadvantages of flat files:
 *   - The file needs to be rewritten if the size changes
 *   - To provide constant access to a group in the active file, some kind of hash table is needed with a file offset into the active file for each group
 *     - This needs to be recomputed if the active file is rewritten
 *     - If combining multiple metadata files into one giant active file, it will need to get rewritten under more circumstances than before
 * - Advantages of using a database for the active file (or similar files):
 *   - Schema changes are less disruptive (although since NNTP is quite stable, the set of per-group metadata is not expected to change)
 *   - We don't need to deal with parsing.
 *   - A database might be able to optimize certain prefix matches over a linear scan
 *     e.g. a wildmat match for LIST ACTIVE news.* can be translated to a SQL WHERE clause, though this may not be possible in all cases (but probably is for most common cases)
 *   - For articles, having an index on the article ID would probably allow for more efficient access to articles accessed by ID
 *
 * ----------------------------------------------------------------------------------------------------
 *
 * This news server's implementation differs from conventional news servers like INN in a few ways:
 * - We prioritize correctness of the low and high water marks and article count. We always provide faithful water marks and counts.
 * - We use a "combined" extended active file that combines what is traditionally separated into .active, .active.times, and .newsgroups.
 *   Furthermore, we explicitly track <last> separately from <high> and also keep the count (both in this same file).
 *   - This helps performance, since we can find everything we need to provide accurate water marks and counts for LIST ACTIVE in one file.
 *   - Our active file is obviously not compatible with anyone else's. There's not much reason it needs to be though, and breaking compatibility
 *     opens up many of the optimization opportunities discussed.
 *
 * Several different state changes are possible that adjust the water marks:
 *
 * 1. Group created and is initially empty. In this case, LOW=1 and HIGH=0 (indicating the group is empty).
 *    Internally, we also represent LOW=1 and LAST=0 at this point, but this property (of LOW being the next article number to assign) is NOT true once LAST > 0 (see state #4)
 * 2. Articles arrive. LOW is unchanged (since it was initialized to 1 already).
 *    For each incoming article, we check LAST in the active file, increment it by 1, and use the new value for the article number (HIGH similarly increases).
 * 3. Articles expire (and are deleted). HIGH and LAST are unchanged, but LOW increases.
 *    For example, if articles 1-10 existed and 1-5 are expired, then LOW changes from 1 to 6.
 * 4. The group becomes empty again.
 *    For example, if articles 6-10 are now deleted, LOW=10 and HIGH=9.
 *    This is the most confusing case, as it is intuitive to think that HIGH=10 and low=11 (the next article number, as in Case 1).
 *    Both seem to satisfy the high < low rule. However, RFC 3977 is very specific that in an empty group, HIGH=LOW-1, not LOW=HIGH+1.
 *    In most cases, these are the same; however, a rejected erratum to RFC 3977 clarifies this.
 *      The proposed erratum (worth a read): https://www.rfc-editor.org/errata_search.php?rfc=3977&eid=1707
 *      Fix in INN from LOW=HIGH+1 to HIGH=LOW-1: https://github.com/InterNetNews/inn/issues/250
 *    The fix here clarifies that if the highest used article number is N, report LOW=N and HIGH=N-1.
 *    This has to do with overflow, i.e. if a group fills up to 2147483647, the max allowed article ID.
 *    In order to represent this group if it were empty, HIGH=LOW-1 works but LOW=HIGH+1 does not since it causes overflow.
 *    Practically, this means if we have a single article 10, LOW=HIGH=LAST=10, but once it's deleted, LAST=10, LOW=10, and HIGH=9.
 *    However, we do not always have to do this; see the comments for FIX_EMPTY_GROUP_STATS in nntp.h.
 *
 * Other details:
 * - Currently, we use flat files, but to allow the possibility of a database backend in the future (for the good reasons described above),
 *   any implementation details involving the active file or other metadata files are sufficiently abstracted away from the core news server.
 * \todo - Currently, there is no hash table to allow for constant time access to a group in the active file (for GROUP), but this should be added.
 *
 * Metadata file formats (see also https://www.gsp.com/cgi-bin/man.cgi?topic=NEWSDB):
 *
 * $NEWSDIR/.active - "extended" active file, the master record of all newsgroups (replaces .active, .active.times, and .newsgroups in a traditional news server)
 *   <group>\t<last>\t<high>\t<low>\t<count>\t<creation epoch>\t<creator>\t<description>
 *     - We use tabs, not spaces, because <creator> could conceivably have spaces? But certainly not tabs.
 *     - The description obviously can have spaces, but shouldn't have tabs (and it's the last entry anyways)
 *     - <low>, <high>, and <count> could technically all be correctly returned without being stored, simply by scanning the spool, but this would be VERY inefficient!
 *     - <last>, <high>, <low>, and <count> are all zero-padded to 10 digits to allow for in-place edits.
 *       - When we return these on the wire to the client, we REMOVE the padding to save bandwidth.
 * $NEWSDIR/history - one line for each article received:
 *   <Message-ID>\t<history>\t<list of links to this article, in [group-name/article number] format>
 *     history has several subfields, separated by ~: <arrival epoch>~<expiry epoch from Expires header or - if no expiry given>~<optional article size in bytes>
 *     - If article expired/cancelled without being seen first, list of links and tab before it are omitted
 *     - this is used to keep track of message-IDs of articles already seen by the server
 *
 * Several different storage methods are supported by most news servers, the two most common being traditional spool and CNFS (Cyclic News File System)
 * At the moment, we only support traditional spool.
 *
 * Groups are organized into subfolders that mirror the news hierarchy, i.e. a group named misc.test would be $NEWSDIR/misc/test, not $NEWSDIR/misc.test
 *   This is simply convention in news server (as opposed to the IMAP way of having a flat directory for all mailboxes),
 *   and may have the slight advantage that certain hierarchies could be stored on a different disk (useful back in the day when disks were small).
 * This is the canonical "traditional spool" method in INN. While very human comprehensible, this method can be hard on file systems and disks,
 *   so tends to be slow for a really large server. Expiration is also expensive (lots of file system operations).
 *
 * $NEWSDIR/<group> - a directory on disk for each group. The articles on disk are usually referred to as the "spool" in news server parlance.
 * $NEWSDIR/<group>/.overview - canonically, a per-group file with one-line summaries of articles in the group (ordered by article), tab-separated
 *   <article number>\t<Subject>\t<From>\t<Date>\t<Message-ID>\t<References>\t<Bytes>\t<Lines>\t<optional headers>
 *     - Line count and References fields may be empty.
 *     - If optional headers are empty, tab after line count may be absent.
 *     - X-Ref is often included as an optional header.
 *     - This file can be quite slow for very large groups, given most clients usually only want a subset (typically the latest) messages.
 *
 * Each article itself is stored as a single file, named by number, to allow for constant time read access by article number:
 * $NEWSDIR/<group>/<article number>
 *   - If the same article appears in multiple groups, the article is symlinked rather than duplicated in the other groups
 *
 * Other common logs that should eventually be supported:
 *  control.log - log of all control messages received, whether or not they were processed, e.g.
 *    Control: newgroup foo.bar moderated
 *    Control: rmgroup misc.removed
 *  expire.log - Log of expired articles
 *  news.log - Log of articles received from transit peers: <date> <+/-> <peer hostname> <Message-ID>
 *  unwanted.log - Log of count of articles rejected for nonexistent newsgroups, by group, with most popular rejected group first
 *
 */

static int group_create(const char *groupname, char status, const char *creator, const char *description)
{
	struct group_info g;
	int res;

	bbs_rwlock_wrlock(&nntp_lock);
	if (spool_group_create(groupname)) {
		bbs_rwlock_unlock(&nntp_lock);
		return -1;
	}

	/* Explicitly initialize all the fields */
	g.name = groupname;
	g.last = 0;
	/* Initialize low water mark to 0 so we can tell an always empty group apart from a group that had 1 article which expired.
	 * Even if EMPTY_LOW_WATERMARK_IS_ZERO is not defined, we can floor the low water mark to 1 in FIX_EMPTY_GROUP_STATS. */
	g.low = 0;
	g.high = 0;
	g.count = 0;
	g.status = status;
	g.created = time(NULL);
	g.creator = creator;
	g.description = description;

	res = active_group_create(&g);
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

static int group_delete(const char *groupname)
{
	int res;

	bbs_rwlock_wrlock(&nntp_lock);
	/* Remove it from the active file first */
	res = active_group_delete(groupname);
	if (res) {
		bbs_rwlock_unlock(&nntp_lock);
		return -1;
	}

	res = spool_group_delete(groupname);
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

static int group_exists(const char *groupname)
{
	int res;

	bbs_rwlock_rdlock(&nntp_lock);
	/* For the moment, with the existing implementations,
	 * querying the tradspool for directory existence is simpler (faster?)
	 * than scanning the active file.
	 * Once we have a hash table mapping groups to offsets in the active file,
	 * adding an active_group_exists variant would probably be better. */
	res = spool_group_exists(groupname);
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

/* group_update_count needs to be called by tradspool_delete_article_single after it deletes an article,
 * but since we're already locked there, we have variants here that are already locked */
static int __group_update_locked(const char *groupname, int *incrlast, int last, int high, int low, int count, char status, const char *description)
{
	/*! \todo If status/description change, need to send control message to other servers with new status and description? */
	return active_group_update(groupname, incrlast, last, high, low, count, status, description);
}

static int __group_update(const char *groupname, int *incrlast, int last, int high, int low, int count, char status, const char *description)
{
	int res;
	bbs_rwlock_wrlock(&nntp_lock);
	res = __group_update_locked(groupname, incrlast, last, high, low, count, status, description);
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

static int group_update_status_description(const char *groupname, char status, const char *description)
{
	return __group_update(groupname, NULL, -1, -1, -1, -1, status, description);
}

int group_update_counts_locked(const char *groupname, int high, int low, int count)
{
	return __group_update_locked(groupname, NULL, -1, high, low, count, 0, NULL);
}

/*!
 * \brief Assign an article number for the next article in this group
 * \param groupname
 * \param[out] article_num Will be set to the next article number, or 0 if the group is full
 * \retval 0 on success, nonzero on error
 * \note Must be called locked
 */
int group_assign_article_number_locked(const char *groupname, int *restrict article_num)
{
	/* The active file will also increment the count for us (and low/high water marks as appropriate) when it assigns the article number */
	return __group_update_locked(groupname, article_num, -1, -1, -1, -1, 0, NULL);
}

/*!
 * \brief Delete a single article from a newsgroup by article number
 * \param groupname Newsgroup name
 * \param article_num Article number
 * \retval 0 on success, 1 on nonexistent article, -1 on system error
 */
static int group_delete_article(const char *groupname, int article_num)
{
	int res;
	bbs_rwlock_wrlock(&nntp_lock);
	res = spool_article_delete_by_number(groupname, article_num);
	bbs_rwlock_unlock(&nntp_lock);

	if (!res) {
		bbs_debug(3, "Deleted article %d in group %s\n", article_num, groupname);
	}

	return res;
}

int group_get_stats_locked(const char *groupname, int *last, int *high, int *low, int *count)
{
	int res;
	int localcount;
	if (!count) {
		count = &localcount;
	}
	res = active_group_info(groupname, last, high, low, count, NULL, NULL, NULL, 0, NULL, 0);

	FIX_EMPTY_GROUP_STATS(*high, *low, *count);
	return res;
}

/*!
 * \internal
 * \brief Get the current low and high water marks and article count of a group
 * \param[in] groupname Newsgroup name
 * \param[out] low Low water mark
 * \param[out] high High water mark
 * \param[out] count Number of articles currently in the group. Can be NULL if you don't need the count.
 * \retval 0 on success
 * \retval -1 on system error
 * \retval 1 if group not found or line was malformed
 */
static int group_get_stats(const char *groupname, int *high, int *low, int *count)
{
	int res;
	bbs_rwlock_rdlock(&nntp_lock);
	res = group_get_stats_locked(groupname, NULL, high, low, count);
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

#define VALID_POSTING_STATUS(s) (s == 'y' || s == 'n' || s == 'm')

static int valid_field(const char *s, const char *extrachars, int maxlen)
{
	int len = 0;
	if (strlen_zero(s)) {
		return 0;
	}
	while (*s) {
		/* subset of isprint, in particular TAB characters and line endings are not allowed */
		if (!isalnum(*s) && !strchr(extrachars, *s)) {
			return 0;
		}
		s++;
		len++;
	}
	if (maxlen && len > maxlen) {
		return 0;
	}
	return 1;
}

static int valid_newsgroup_name(const char *s)
{
	/* Newsgroups cannot start with numbers since the tradspool method names articles by their number,
	 * and groups can be nested within other groups. */
	return valid_field(s, ".-+", NNTP_MAX_ARG_LENGTH) && !isdigit(*s); /* The max arg length is a ridiculously long limit, but it's the only one we have */
}

/*!
 * \brief Create a newsgroup on this server (either a new group in the news network, or instantiate an existing group on this server for the first time)
 *        The directory for articles will be created, and the newsgroup metadata will be added to all necessary metadata files.
 * \param name The name of the newsgroup.
 * \param description A short description about the purpose of the group
 * \param creator Entity that created the newsgroup; may be an email address (though not necessarily, often just 'usenet' in many Usenet groups)
 * \param posting The current status of the group on this server. (y = posting allowed, n = posting not allowed, m = posts forwarded to newsgroup moderator)
 * \retval 0 Group created successfully
 * \retval 1 Group already exists
 * \retval -1 Error creating group
 */
static int newgroup(const char *name, const char *description, const char *creator, char posting)
{
	int res;

	if (strlen_zero(creator)) {
		creator = "BBS";
	}

	/* Enforce some basic sanity checks */
	/*! \todo Need to perform these checks when modifying groups as well (including in response to control messages) */
	if (!valid_newsgroup_name(name)) {
		bbs_error("Newsgroup name '%s' is invalid\n", S_IF(name));
		return -1;
	} else if (!valid_field(description, " ,.-+", NNTP_MAX_ARG_LENGTH)) {
		bbs_error("Newsgroup description '%s' is invalid\n", S_IF(description));
		return -1;
	} else if (!valid_field(creator, " ,.<>@-+", NNTP_MAX_ARG_LENGTH)) {
		bbs_error("Newsgroup creator '%s' is invalid\n", S_IF(creator));
		return -1;
	} else if (!VALID_POSTING_STATUS(posting)) {
		bbs_error("Illegal posting setting '%c'\n", posting);
		return -1;
	}

	res = group_create(name, posting, creator, description);
	if (!res) {
		bbs_verb(4, "Created newsgroup %s (%s)\n", name, description);
	}
	return 0;
}

static int cli_newgroup(struct bbs_cli_args *a)
{
	char name[128];
	char description[256];
	char creator[64];
	char posting[2];
	int res;
	ssize_t rres;

	bbs_cli_set_stdout_logging(a->fdout, 0); /* Disable logging to the terminal until we're finished (mod_sysop will reset anyways when we return) */
	bbs_buffer_input(a->fdin, 1);

	bbs_dprintf(a->fdout, "Create Newsgroup:\n");

#define PROMPT_AND_READ(var, str) \
	bbs_dprintf(a->fdout, "%s: ", str); \
	rres = bbs_poll_read(a->fdin, MIN_MS(2), var, sizeof(var) - 1); \
	if (rres <= 0) { \
		bbs_dprintf(a->fdout, "Failed to receive input, aborting\n"); \
		return -1; \
	} \
	var[rres] = '\0'; \
	if (rres > 0 && var[rres - 1] == '\n') { \
		var[rres - 1] = '\0'; \
	} \
	bbs_debug(5, "Read %s: %s\n", #var, var);

	PROMPT_AND_READ(name, "Name");
	PROMPT_AND_READ(description, "Description");
	PROMPT_AND_READ(creator, "Group Creator");
	PROMPT_AND_READ(posting, "Posting Permitted (y = yes/n = no/m = moderated)");

	res = newgroup(name, description, creator, posting[0]);
	if (res < 0) {
		bbs_dprintf(a->fdout, "Error occured creating newsgroup '%s'\n", name);
		return -1;
	} else if (res > 0) {
		bbs_dprintf(a->fdout, "Newsgroup '%s' already exists\n", name);
		return -1;
	}

	bbs_dprintf(a->fdout, "Created newsgroup %s (%s)\n", name, description);
	return 0;
}

static int cli_rmgroup(struct bbs_cli_args *a)
{
	const char *name = a->argv[2];
	int res;
	int confirmed = a->argc >= 4 && !strcmp(a->argv[3], "confirm");

	/* Since this is a very destructive action, make sure we're REALLY sure about this.
	 * Allow deletion immediately if confirmed as the next argument (useful for the tests). */
	if (!confirmed) {
		char buf[2];
		ssize_t rres;
		bbs_cli_set_stdout_logging(a->fdout, 0); /* Disable logging to the terminal until we're finished (mod_sysop will reset anyways when we return) */
		bbs_buffer_input(a->fdin, 1);
		PROMPT_AND_READ(buf, "Really delete '%s'? (y/n)");
		if (buf[0] != 'y') {
			bbs_dprintf(a->fdout, "Deletion cancelled\n");
			return 0; /* Abort */
		}
	}

	res = group_delete(name);
	if (res) {
		bbs_dprintf(a->fdout, "Error occured deleting newsgroup '%s'\n", name);
		return -1;
	}

	bbs_dprintf(a->fdout, "Deleted newsgroup %s (manually delete %s/%s)\n", name, newsdir, name);
	return 0;
}

static int cli_setpost(struct bbs_cli_args *a)
{
	/* Posting status needs to be valid and must only be one character */
	if (!VALID_POSTING_STATUS(a->argv[3][0]) || a->argv[3][1]) {
		bbs_dprintf(a->fdout, "Invalid posting status (should be y/n/m)\n");
		return -1;
	}
	/* Update posting status, don't change the low or high water marks */
	if (group_update_status_description(a->argv[2], a->argv[3][0], NULL)) {
		bbs_dprintf(a->fdout, "Failed to update group posting status\n");
		return -1;
	}
	bbs_dprintf(a->fdout, "Updated group posting status\n");
	return 0;
}

static int cli_delarticle(struct bbs_cli_args *a)
{
	const char *group = a->argv[2];
	int res;
	int article_num = atoi(a->argv[3]);

	res = group_delete_article(group, article_num);
	if (res) {
		bbs_dprintf(a->fdout, "Article %d %s\n", article_num, res == 1 ? "does not exist" : "could not be deleted");
		return -1;
	}
	bbs_dprintf(a->fdout, "Deleted article %d in group %s\n", article_num, group);
	return 0;
}

static int identity_allowed_for_posting(struct nntp_session *nntp, const char *fromaddr)
{
	char dup_addr[256];
	char *name = NULL, *user = NULL, *domain = NULL;
	unsigned int userid;

	/* While many news providers allow arbitrary email addresses to be used,
	 * we require a valid email address, unless checkidentity=no. */
	if (!check_identity) {
		return 1;
	}

	/* We can't check identity if user isn't logged in */
	if (!bbs_user_is_registered(nntp->node->user)) {
		return 0;
	}

	safe_strncpy(dup_addr, fromaddr, sizeof(dup_addr));
	if (bbs_parse_email_address(dup_addr, &name, &user, &domain)) {
		return 0;
	}
	/* Newsgroups need a full email address */
	if (!user || !domain) {
		return 0;
	}
	/* If the user is allowed to send email from this address,
	 * then we allow this identity to be used for posting to newsgroups. */
	userid = mailbox_get_userid(user, domain);
	if (!userid) {
		return 0;
	}
	return nntp->node->user && userid == nntp->node->user->id;
}

/*! \brief Final processing of POST/IHAVE */
static int do_post(struct nntp_session *nntp, const char *srcfilename, size_t postlen)
{
	char *newsgroup, *newsgroups = NULL;
	char *uuid = NULL;
	int delivered = 0;
	char articleidbuf[128];
	int total_errors = 0, permission_errors = 0;
	struct stringlist groups;
	struct article_info *artinfo = &nntp->artinfo;
	int srcfd;

	stringlist_init(&groups);

#define REQUIRE_ARTINFO_FIELD(field) \
	if (!artinfo->field) { \
		bbs_debug(1, "Missing field %s\n", #field); \
		goto cleanup; \
	}

	REQUIRE_ARTINFO_FIELD(newsgroups);
	REQUIRE_ARTINFO_FIELD(subject);
	REQUIRE_ARTINFO_FIELD(from);
	REQUIRE_ARTINFO_FIELD(date);
	if (nntp->mode == NNTP_MODE_TRANSIT) {
		REQUIRE_ARTINFO_FIELD(messageid);
		if (artinfo->messageid[0] != '<' && !bbs_str_ends_with(artinfo->messageid, ">")) {
			/* Invalid Message-ID */
			bbs_debug(1, "Invalid Message-ID '%s'\n", artinfo->messageid);
			goto cleanup;
		}
	}
	/* References header is optional, may not be present */

	/*! \todo Do further validation of fields here + group info (description, etc.) */

	if (nntp->mode == NNTP_MODE_READER) {
		/* Check the From header. */
		if (!identity_allowed_for_posting(nntp, artinfo->from)) {
			bbs_warning("Rejected NNTP post by user %d with identity %s\n", nntp->node->user ? nntp->node->user->id : 0, artinfo->from);
			nntp_send(nntp, 441, "Identity not allowed for posting");
			goto cleanup2;
		}
		uuid = bbs_uuid(); /* Use same UUID (and by extension, the same Article ID) for all newsgroups */
		if (!uuid) {
			goto cleanup;
		}
		/* We need to generate an article ID for this article, since this is its entry point into the news network */
		snprintf(articleidbuf, sizeof(articleidbuf), "<%s@%s>", uuid, bbs_hostname());
		artinfo->messageid = articleidbuf;
		/*! \todo Do we need to inject the header into the file? snprintf(msgid, sizeof(msgid), "Message-ID: <%s@%s>", uuid, bbs_hostname()); */
	} else { /* else if TRANSIT, just trust what the other end says (presumably the original server validated the identity). */
		/* Could be a race condition, maybe we didn't have the article when the client said IHAVE,
		 * but now we do (possibly from some other server). Check again. */
		if (spool_article_exists(artinfo->messageid)) {
			bbs_debug(2, "Rejecting article %s from %s (duplicate)\n", artinfo->messageid, nntp->node->ip);
			nntp_send(nntp, 435, "Duplicate");
			goto cleanup2;
		}
	}

	/* Determine the newsgroups to which we'll add this article. */
	newsgroups = artinfo->newsgroups; /* Duplicate pointer since we'll mutate it */
	ACL_RDLOCK(nntp);
	while ((newsgroup = strsep(&newsgroups, ","))) {
		/* We don't ltrim here, as newsgroups should be comma-separated, without any spaces between them */
		if (!group_exists(newsgroup)) {
			bbs_debug(3, "Newsgroup '%s' does not exist\n", newsgroup); /* Try to deliver to any other groups listed */
			total_errors++;
			continue;
		}
		if (!ACL_ALLOWED_LOCKED(nntp, newsgroup, NNTP_ACL_POST)) {
			bbs_debug(3, "ACL does not allow posting to %s\n", newsgroup);
			permission_errors++;
			total_errors++;
			continue;
		}
		if (stringlist_contains(&groups, newsgroup)) {
			bbs_debug(3, "Group '%s' is duplicated in Newsgroups list\n", newsgroup);
			total_errors++; /* The non-duplicated one may still succeed, so this doesn't necessarily mean we'll return failure */
			continue;
		}
		stringlist_push_tail(&groups, newsgroup);
	}
	ACL_UNLOCK(nntp);

	/* Actually add message to groups */
	srcfd = open(srcfilename, O_RDONLY);
	if (srcfd < 0) {
		bbs_error("Failed to open %s: %s\n", srcfilename, strerror(errno));
		goto cleanup;
	}
	bbs_rwlock_wrlock(&nntp_lock);
	delivered = spool_article_create(&groups, artinfo, srcfd, postlen);
	bbs_rwlock_unlock(&nntp_lock);
	close(srcfd);

cleanup:
	if (!delivered) {
		/* Should we instead do permanent error for transit (437), if newsgroup doesn't exist? But what if it's added later? */
		if (nntp->mode == NNTP_MODE_READER) {
			if (permission_errors && total_errors == permission_errors) {
				/* We weren't authorized to post to the group(s) */
				nntp_send(nntp, 440, "Posting not allowed");
			} else {
				nntp_send(nntp, 441, "Posting failed");
			}
		} else {
			if (permission_errors && total_errors == permission_errors) {
				nntp_send(nntp, 437, "Transfer rejected; do not retry");
			} else {
				nntp_send(nntp, 436, "Transfer failed; retry later");
			}
		}
	} else {
		/* Posting succeeded to at least one newsgroup. */
		nntp_send(nntp, nntp->mode == NNTP_MODE_READER ? 240 : 235, "Article received OK");
	}
cleanup2:
	free_if(uuid);
	free_if(newsgroups);
	stringlist_empty(&groups);
	return 0;
}

static int parse_min_max(char *s, int *min, int *max, char sep)
{
	char *tmp;

	tmp = strchr(s, sep);
	if (!tmp) {
		*min = *max = atoi(s);
		return 0;
	}
	*tmp++ = '\0';
	*min = atoi(s);
	*max = atoi(tmp);
	return 0;
}

static enum list_category parse_list_category(const char *s)
{
	if (strlen_zero(s)) {
		return LIST_ACTIVE | LIST_PER_NEWSGROUP; /* RFC 2980 2.1.2 states that "LIST ACTIVE" is the same as "LIST" (with no keyword modifier) */
	} else if (!strcasecmp(s, "ACTIVE")) {
		return LIST_ACTIVE | LIST_PER_NEWSGROUP;
	} else if (!strcasecmp(s, "ACTIVE.TIMES")) {
		return LIST_ACTIVE_TIMES | LIST_PER_NEWSGROUP;
	} else if (!strcasecmp(s, "NEWSGROUPS")) {
		return LIST_NEWSGROUPS | LIST_PER_NEWSGROUP;
	} else if (!strcasecmp(s, "DISTRIB.PATS")) {
		return LIST_DISTRIB_PATS;
	} else {
		/*! \todo Add additional categories as specified in RFC 2980 and RFC 6048 */
		bbs_warning("Unknown LIST category '%s'\n", s);
		return LIST_INVALID; /* Unknown or invalid */
	}
}

/*!
 * \internal
 * \brief Send LIST response
 * \param nntp
 * \param keyword e.g. ACTIVE
 * \param argument Optional wildmat or argument
 * \retval 0 on success
 * \retval -1 on fatal failure (disconnect)
 * \retval 1 on non-fatal failure
 */
static int handle_list(struct nntp_session *nntp, const char *keyword, const char *argument)
{
	int res = 0;
	enum list_category listcat = parse_list_category(keyword); /* If a keyword is not specified, then an argument is not present either (per syntax in RFC 3977 7.6.1.1) */

	if (listcat == LIST_INVALID) {
		nntp_send(nntp, 501, "Unknown LIST keyword");
		return 1;
	}
	if (!strlen_zero(argument) && !(listcat & LIST_PER_NEWSGROUP)) {
		/* We have an argument, but we don't consume one */
		nntp_send(nntp, 501, "This command is not newsgroup-based and does not accept an argument");
		return 1;
	}

	if (listcat & LIST_PER_NEWSGROUP) {
		listcat &= ~((unsigned int) LIST_PER_NEWSGROUP); /* Remove this flag, it is present if calling this function, and that way group_list can case directly on the category */
		ACL_RDLOCK(nntp); /* Lock the ACL list once for the whole loop so we can use the locked version of the ACL check */
		res = active_group_list(nntp, listcat, argument);
		ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, 503, "Data item not available");
			return 1;
		}
		return 0;
	} /* else, not newsgroup-based: */

	if (listcat & LIST_DISTRIB_PATS) {
		/* distrib.pats list assists clients to choose a value for the Distribution header of an article being posted.
		 * <weight> <wildmat> <value for Distribution header content>
		 * Client selects highest-weighted line with a matching wildmat. */
		/* Note: Eternal September just responds with the 2nd line here, so for now we just do that as well instead of pulling from a file: */
		nntp_send(nntp, 215, "%s", "Default distributions in form \"weight:group-pattern:distribution\"\r\n10:local.*:local");
		_nntp_send(nntp, ".\r\n");
		return 0;
	}

#if 0
	FILE *fp;
	const char *filename = NULL;
	/*! \todo no code gets here currently, but if we had files for some of these (e.g. LIST MODERATORS) we may use in the future */

	filename = NULL;
	if (!filename) {
		nntp_send(nntp, 503, "Data item not available");
		return 1;
	}

	/* Before starting a 2xx response, try opening the file if there is one, so we can abort early on failure */
	fp = fopen(filename, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
		nntp_send(nntp, 503, "Data item not available");
		return 1;
	}
	/* nntp_send(nntp, 215, "%s", resp); */
	if (fp) {
		int lineno = 0;
		char *group, buf[NNTP_MAX_LINE_LENGTH + 1];
		while ((fgets(buf, sizeof(buf), fp))) {
			bbs_term_line(line);
			/* We don't care what the rest of the line is, if the group matches, send it to the client
			 * This file isn't newsgroup-based, so no ACL checks needed. */
			_nntp_send(nntp, "%s %s\r\n", group, line);
		}
		fclose(fp);
	}
	if (res < 0) {
		return res;
	}
	_nntp_send(nntp, ".\r\n");
#endif
	return res;
}

#define REQUIRE_READER() \
	if (nntp->mode != NNTP_MODE_READER) { \
		nntp_send(nntp, 401, "MODE-READER"); \
		return 0; \
	}

#define REQUIRE_GROUP() \
	if (!nntp->currentgroup) { \
		nntp_send(nntp, 412, "No newsgroup selected"); \
		return 0; \
	}

/* articleid is only set for MODE_TRANSIT */
static int handle_post_ihave(struct nntp_session *nntp, struct readline_data *rldata, const char *articleid)
{
	char template[64];
	FILE *fp;
	int inheaders = 1;
	int postfail = 0;
	size_t postlen = 0;
	int lines = 0;
	struct article_info *artinfo = &nntp->artinfo;

	nntp_reset_data(nntp);
	strcpy(template, "/tmp/nntpXXXXXX"); /* Safe */

	fp = bbs_mkftemp(template, 0600);
	if (!fp) {
		if (nntp->mode == NNTP_MODE_READER) {
			nntp_send(nntp, 440, "Server error, posting temporarily unavailable");
		} else {
			nntp_send(nntp, 436, "Temporary server error, try again later");
		}
		return 0;
	}

	if (nntp->mode == NNTP_MODE_READER) {
		nntp_send(nntp, 340, "Input article; end with a period on its own line");
	} else {
		nntp_send(nntp, 335, "Send it; end with a period on its own line");
	}

#define SAVE_HEADER(hdrname, var) \
		if (STARTS_WITH(s, hdrname ":")) { \
			const char *hval = s + STRLEN(hdrname ":"); \
			ltrim(hval); \
			REPLACE(var, hval); \
		}

	for (;;) {
		int res;
		char *s;
		ssize_t len = bbs_node_readline(nntp->node, rldata, "\r\n", MIN_MS(5));
		if (len < 0) {
			fclose(fp);
			unlink(template);
			return -1;
		}
		s = rldata->buf;
		if (!strcmp(s, ".")) {
			fclose(fp);
			if (postfail) {
				if (nntp->mode == NNTP_MODE_TRANSIT) {
					if (inheaders || postlen >= max_post_size) {
						/* Permanent error */
						nntp_send(nntp, 437, "Transfer rejected (%s); do not retry", inheaders ? "article mismatch" : "too large");
					} else {
						nntp_send(nntp, 436, "Transfer not possible; try again later"); /* Temporary error */
					}
				} else {
					nntp_send(nntp, 441, "Posting failed%s", postlen >= max_post_size ? " (too large)" : "");
				}
				unlink(template);
				return 0;
			}
			artinfo->bytes = postlen;
			artinfo->lines = lines;
			res = do_post(nntp, template, postlen);
			unlink(template);
			return res;
		}

		if (postfail) {
			continue; /* Corruption already happened, just ignore the rest of the message for now. */
		} else if (inheaders) {
			if (!len) {
				inheaders = 0; /* Got CR LF, end of headers */
			}
			/*! \todo Need to properly parse any multi-line headers */
			else SAVE_HEADER("Newsgroups", artinfo->newsgroups)
			else SAVE_HEADER("Expires", artinfo->expires)
			else SAVE_HEADER("Subject", artinfo->subject)
			else SAVE_HEADER("From", artinfo->from)
			else SAVE_HEADER("Date", artinfo->date)
			else SAVE_HEADER("References", artinfo->references)
			else if (nntp->mode == NNTP_MODE_TRANSIT && STARTS_WITH(s, "Message-ID:")) {
				const char *hval = s + STRLEN("Message-ID:");
				ltrim(hval);
				if (!strlen_zero(hval)) {
					/* The article better be the article that the other server said it was in IHAVE */
					if (strcmp(articleid, hval)) {
						bbs_debug(1, "Article Message-ID mismatch: IHAVE=%s, Message-ID=%s\n", articleid, s);
						postfail = 1;
						continue;
					}
					artinfo->messageid = articleid;
				}
			}
		} else {
			lines++;
		}

		if ((unsigned int) (postlen + (long unsigned int) len + 2) >= max_post_size) {
			postfail = 1;
			postlen = max_post_size; /* This isn't really true, this is so we can detect that the message was too large. */
			continue;
		}

		res = bbs_append_stuffed_line_message(fp, s, (size_t) len); /* Should return len + 2, unless it was byte stuffed, in which case it'll be len + 1 */
		if (res < 0) {
			postfail = 1;
		}
		postlen += (size_t) res;
	}
}

static int nntp_process(struct nntp_session *nntp, struct readline_data *rldata, char *s)
{
	char *command = strsep(&s, " ");

	if (!strcasecmp(command, "QUIT")) {
		nntp_send(nntp, 205, "Bye!");
		return -1;
	} else if (!strcasecmp(command, "MODE")) {
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		if (!strcasecmp(command, "READER")) {
			nntp->mode = NNTP_MODE_READER;
			nntp_send(nntp, 200, "Reader mode, posting permitted");
		} else {
			bbs_error("Unknown mode: %s\n", command);
		}
	} else if (!strcasecmp(command, "CAPABILITIES")) {
		/* This is very reminiscent of the POP3 CAPABILITIES command: */
		nntp_send(nntp, 101, "Capability list:");
		_nntp_send(nntp, "VERSION 2\r\n"); /* Must be first */
		/* Don't advertise MODE-READER, just READER */
		if (!nntp->node->secure) {
			_nntp_send(nntp, "STARTTLS\r\n");
		}
		if (nntp->mode == NNTP_MODE_READER) { /* Reader mode */
			_nntp_send(nntp, "READER\r\n");
			_nntp_send(nntp, "POST\r\n");
		} else { /* Transit mode */
			_nntp_send(nntp, "IHAVE\r\n");
			_nntp_send(nntp, "MODE-READER\r\n");
		}
		_nntp_send(nntp, "LIST ACTIVE NEWSGROUPS ACTIVE.TIMES\r\n");
		_nntp_send(nntp, "XSECRET\r\n");
		if ((nntp->node->secure || !require_secure_login) && !bbs_user_is_registered(nntp->node->user)) {
			_nntp_send(nntp, "AUTHINFO USER\r\n");
			_nntp_send(nntp, "SASL PLAIN\r\n");
		}
		_nntp_send(nntp, "IMPLEMENTATION %s\r\n", BBS_SHORTNAME);
		_nntp_send(nntp, ".\r\n");
	} else if (!strcasecmp(command, "STARTTLS")) {
		if (!ssl_available()) {
			nntp_send(nntp, 580, "STARTTLS may not be used");
		} else if (!nntp->node->secure) {
			nntp_send(nntp, 382, "Ready to start TLS");
			/* RFC 4642 */
			bbs_debug(3, "Starting TLS\n");
			if (bbs_node_starttls(nntp->node)) {
				return -1; /* Just abort */
			}
			free_if(nntp->currentgroup);
			nntp->currentarticle = 0;
			bbs_readline_flush(rldata); /* Prevent STARTTLS command injection by resetting the buffer after TLS upgrade */
		} else {
			nntp_send(nntp, 502, "Already using TLS");
		}
	} else if (!strcasecmp(command, "DATE")) {
		char datestr[15];
		time_t timenow;
		struct tm nowtime;
		timenow = time(NULL);
		gmtime_r(&timenow, &nowtime);
		strftime(datestr, sizeof(datestr), "%Y%m%d%H%M%S", &nowtime); /* yyyymmddhhmmss */
		nntp_send(nntp, 111, "%s", datestr);
	} else if (!strcasecmp(command, "HELP")) {
		nntp_send(nntp, 100, "Help text follows");
		/* XXX Could add descriptions too */
		_nntp_send(nntp, "QUIT\r\n");
		_nntp_send(nntp, "MODE\r\n");
		_nntp_send(nntp, "DATE\r\n");
		_nntp_send(nntp, "HELP\r\n");
		_nntp_send(nntp, "CAPABILITIES\r\n");
		_nntp_send(nntp, "STARTTLS\r\n");
		_nntp_send(nntp, "XSECRET\r\n");
		_nntp_send(nntp, "AUTHINFO\r\n");
		_nntp_send(nntp, "USER\r\n");
		_nntp_send(nntp, "PASS\r\n");
		_nntp_send(nntp, "SASL\r\n");
		_nntp_send(nntp, "LIST, LIST.ACTIVE\r\n");
		_nntp_send(nntp, "GROUP\r\n");
		_nntp_send(nntp, "XOVER\r\n");
		_nntp_send(nntp, "HEAD\r\n");
		_nntp_send(nntp, "ARTICLE\r\n");
		_nntp_send(nntp, "BODY\r\n");
		_nntp_send(nntp, "LAST\r\n");
		_nntp_send(nntp, "NEXT\r\n");
		_nntp_send(nntp, "POST\r\n");
		_nntp_send(nntp, "IHAVE\r\n");
		_nntp_send(nntp, ".\r\n");
	} else if (!strcasecmp(command, "XSECRET")) {
		/* XSECRET appears in RFC 3977, in passing, but there is no actual documentation anywhere of it that I can find.
		 * My newsreader seems to use AUTHINFO instead, so if XSECRET/XENCRYPT are not widely used
		 * or are long deprecated, this can probably be removed. */
		int res;
		char *user, *pass, *domain;
		if (bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, 480, "Already authenticated"); /*! \todo Proper numeric response code? */
			return 0;
		}
		user = strsep(&s, " ");
		pass = s;
		REQUIRE_ARGS(user);
		REQUIRE_ARGS(pass);
		/* Strip the domain, if present,
		 * but the domain must match our domain, if present. */
		domain = strchr(user, '@');
		if (domain) {
			*domain++ = '\0';
			if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
				nntp_send(nntp, 452, "Authorization rejected"); /*! \todo right code? */
				return 0;
			}
		}
		res = bbs_authenticate(nntp->node, user, pass);
		bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
		if (res) {
			nntp_send(nntp, 452, "Authorization rejected"); /*! \todo right code? */
			return 0;
		}
		nntp_send(nntp, 290, "Password for %s accepted", user); /*! \todo Is this really the right response code? */
		RECHECK_TRANSIT_ACL(nntp);
	} else if ((nntp->node->secure || !require_secure_login) && !strcasecmp(command, "AUTHINFO")) {
		/* RFC 4643 AUTHINFO */
		/* If this command is not implemented and we send a 480,
		 * Thunderbirds will just go into a loop sending AUTH INFO commands, forever,
		 * even if AUTHINFO isn't listed as one of our capabilities.
		 * But RFC 4643 does say we MUST NOT response to an AUTHINFO with a 480, so that's probably why...
		 */
		int res;
		char *pass, *domain;

		if (bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, 502, "Already authenticated"); /*! \todo Proper numeric response code? */
			return 0;
		}

		command = strsep(&s, " ");
		if (!strcasecmp(command, "USER")) {
			free_if(nntp->user);
			REQUIRE_ARGS(s);
			nntp->user = strdup(s);
			nntp_send(nntp, 381, "Password required");
		} else if (!strcasecmp(command, "PASS")) {
			pass = s;
			if (!nntp->user) {
				nntp_send(nntp, 482, "Authentication commands issued out of sequence");
				return 0;
			}
			REQUIRE_ARGS(pass);
			/* Strip the domain, if present,
			 * but the domain must match our domain, if present. */
			domain = strchr(nntp->user, '@');
			if (domain) {
				*domain++ = '\0';
				if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
					nntp_send(nntp, 452, "Authorization rejected"); /*! \todo right code? */
					return 0;
				}
			}
			res = bbs_authenticate(nntp->node, nntp->user, pass);
			free_if(nntp->user);
			bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
			if (res) {
				nntp_send(nntp, 481, "Authentication failed");
				return 0;
			}
			nntp_send(nntp, 281, "Authentication accepted");
			RECHECK_TRANSIT_ACL(nntp);
		} else if (!strcasecmp(command, "SASL")) {
			/* RFC 4643 SASL */
			command = strsep(&s, " ");
			if (!strcasecmp(command, "PLAIN")) {
				unsigned char *decoded;
				char *authorization_id, *authentication_id, *password;

				decoded = bbs_sasl_decode(s, &authorization_id, &authentication_id, &password);
				if (!decoded) {
					return -1;
				}

				/* Can't use bbs_sasl_authenticate directly since we need to strip the domain */
				bbs_strterm(authentication_id, '@');
				res = bbs_authenticate(nntp->node, authentication_id, password);
				bbs_memzero(password, strlen(password)); /* Destroy the password from memory before we free it */
				free(decoded);

				if (res) {
					nntp_send(nntp, 481, "Authentication failed");
					return 0;
				}
				nntp_send(nntp, 281, "Authentication accepted");
				RECHECK_TRANSIT_ACL(nntp);
			} else {
				/* RFC 4643 says we MUST implement the DIGEST-MD5 mechanism, but, well, we don't. */
				nntp_send(nntp, 503, "Mechanism not recognized");
			}
		} else {
			nntp_send(nntp, 501, "Unknown AUTHINFO command");
		}
	} else if (!strcasecmp(command, "LIST")) {
		const char *keyword = strsep(&s, " ");
		if (handle_list(nntp, keyword, s) < 0) {
			return -1;
		}
	} else if (!strcasecmp(command, "GROUP")) { /* Note, this command can be used in either mode */
		int low, high, count;
		if (!group_exists(s)) {
			nntp_send(nntp, 411, "%s is unknown", s);
			return 0;
		}
		/* For future commands which require a group, we don't check read ACL since we check it here, before changing the group */
		if (!ACL_ALLOWED(nntp, s, NNTP_ACL_READ)) {
			nntp_send(nntp, 502, "Read access denied");
			return 0;
		}
		if (group_get_stats(s, &high, &low, &count)) {
			nntp_send(nntp, 403, "Error changing group");
			return 0;
		}
		REPLACE(nntp->currentgroup, s);
		nntp_send(nntp, 211, "%d %d %d %s", count, low, high, s);
		nntp->currentarticle = low;
	} else if (!strcasecmp(command, "XOVER")) {
		/* RFC 2980 XOVER */
		/* Mozilla-based clients prefer XOVER to HEAD, and will only issue a HEAD if XOVER is not available. */
		int min, max;
		REQUIRE_READER();
		REQUIRE_GROUP();
		if (!strlen_zero(s)) {
			parse_min_max(s, &min, &max, '-');
		} else {
			if (!nntp->currentarticle) {
				nntp_send(nntp, 420, "No article(s) selected");
				return 0;
			}
			min = max = nntp->currentarticle;
		}
		if (spool_group_overview(nntp, nntp->currentgroup, min, max)) {
			nntp_send(nntp, 420, "No article(s) selected");
		}
	} else if (!strcasecmp(command, "ARTICLE")) {
#define PARSE_ARTICLENUM_MSGID() \
	artnum = atoi(s); \
	if (!artnum) { \
		if (*s != '<') { \
			nntp_send(nntp, 423, "No Such Article Found"); \
			return 0; \
		} \
	}
		int artnum;
		REQUIRE_READER();
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		PARSE_ARTICLENUM_MSGID();
		/* We pass in the current group, even if searching by message ID.
		 * This way, if an article is linked in multiple groups,
		 * we can return the article number for the current group
		 * (the default is otherwise to use the first group to which the article was linked). */
		if (spool_article_send(nntp, SEND_HEADERS | SEND_BODY, artnum ? NULL : s, nntp->currentgroup, artnum)) {
			nntp_send(nntp, artnum ? 423 : 430, "No Such Article Found"); /* Only on failure, do we need to send a response here */
		} else {
			if (artnum) {
				nntp->currentarticle = artnum;
			}
		}
	} else if (!strcasecmp(command, "HEAD")) {
		int artnum;
		REQUIRE_READER();
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		PARSE_ARTICLENUM_MSGID();
		if (spool_article_send(nntp, SEND_HEADERS, artnum ? NULL : s, nntp->currentgroup, artnum)) {
			nntp_send(nntp, artnum ? 423 : 430, "No Such Article Found"); /* Only on failure, do we need to send a response here */
		} else {
			if (artnum) {
				nntp->currentarticle = artnum;
			}
		}
	} else if (!strcasecmp(command, "BODY")) {
		int artnum;
		REQUIRE_READER();
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		PARSE_ARTICLENUM_MSGID();
		if (spool_article_send(nntp, SEND_BODY, artnum ? NULL : s, nntp->currentgroup, artnum)) {
			nntp_send(nntp, artnum ? 423 : 430, "No Such Article Found"); /* Only on failure, do we need to send a response here */
		} else {
			if (artnum) {
				nntp->currentarticle = artnum;
			}
		}
	} else if (!strcasecmp(command, "LAST")) {
		int last;
		char msgid[NNTP_BUFSIZ];
		REQUIRE_READER();
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, 420, "Current article number is invalid");
			return 0;
		}
		spool_group_seek(nntp->currentgroup, nntp->currentarticle, &last, -1, msgid, sizeof(msgid));
		if (last == nntp->currentarticle) {
			nntp_send(nntp, 422, "No previous article in group");
			return 0;
		}
		nntp->currentarticle = last;
		nntp_send(nntp, 223, "%d %s", last, msgid);
	} else if (!strcasecmp(command, "NEXT")) {
		int next;
		char msgid[NNTP_BUFSIZ];
		REQUIRE_READER();
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, 420, "Current article number is invalid");
			return 0;
		}
		spool_group_seek(nntp->currentgroup, nntp->currentarticle, &next, +1, msgid, sizeof(msgid));
		if (next == nntp->currentarticle) {
			nntp_send(nntp, 421, "No next article in group");
			return 0;
		}
		nntp->currentarticle = next;
		nntp_send(nntp, 223, "%d %s", next, msgid);
	} else if (!strcasecmp(command, "POST")) {
		REQUIRE_READER();
		if (!bbs_user_is_registered(nntp->node->user) && !guests_can_post_at_all()) {
			nntp_send(nntp, 480, "Must authenticate first");
			return 0;
		}
		return handle_post_ihave(nntp, rldata, NULL);
	} else if (!strcasecmp(command, "IHAVE")) {
		char articleid[NNTP_BUFSIZ];
		if (nntp->mode != NNTP_MODE_TRANSIT) {
			nntp_send(nntp, 401, "Readers must use POST, not IHAVE");
			return 0;
		}
		/* Check if client is authorized to relay us articles. */
		if (requirerelaytls && !nntp->node->secure) {
			nntp_send(nntp, 483, "Secure connection required");
			return 0;
		}
		if (!nntp->inpeer_any) {
			bbs_warning("Sender %s/%s unauthorized to send us articles\n", bbs_username(nntp->node->user), nntp->node->ip);
			nntp_send(nntp, 500, "Not authorized to relay articles");
			return 0;
		}
		/* Group not required, the headers will say group(s) to which message should be posted. */
		REQUIRE_ARGS(s); /* Do not strip <> around Message-ID, as that is part of the Message-ID */
		/* Check if any message with this ID exists in any newsgroup. */
		if (spool_article_exists(s)) {
			nntp_send(nntp, 435, "Duplicate");
			return 0;
		}
		safe_strncpy(articleid, s, sizeof(articleid)); /* duplicate since handle_post_ihave will call bbs_readline and clobber the buffer this is in */
		return handle_post_ihave(nntp, rldata, articleid);
	} else {
		/*! \todo add:
		 * RFC 2980 extensions
		 * Also see RFC 5536
		 */
		nntp_send(nntp, 500, "Unknown command");
	}
	return 0;
}

static void handle_client(struct nntp_session *nntp)
{
	char buf[NNTP_MAX_LINE_LENGTH + 1];
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));
	/* 200 means client can post, 201 means not, but this is not a perfect distinction (see RFC) */
	nntp_send(nntp, 200, "%s Newsgroup Service Ready, posting permitted", bbs_hostname());

	SET_BITFIELD(nntp->inpeer_any, authorized_inpeer_for_any_groups(nntp)); /* Cache whether this client has an inpeer ACL */

	/* Default mode is transit mode (NNTP_MODE_TRANSIT) for mode-switching servers */
	for (;;) {
		ssize_t res = bbs_node_readline(nntp->node, &rldata, "\r\n", MIN_MS(5));
		if (res < 0) {
			/* We should NOT send any response to the client when terminating a connection due to timeout. */
			break;
		}
		if ((!strncasecmp(buf, "XSECRET", STRLEN("XSECRET")) || !strncasecmp(buf, "AUTHINFO PASS", STRLEN("AUTHINFO PASS")))) {
			/* Mask login to avoid logging passwords */
			if (*buf == 'X') {
				bbs_debug(6, "%p => XSECRET ******\n", nntp);
			} else {
				bbs_debug(6, "%p => AUTHINFO PASS ******\n", nntp);
			}
		} else {
			bbs_debug(6, "%p => %s\n", nntp, buf);
		}
		if (nntp_process(nntp, &rldata, buf)) {
			break;
		}
	}
}

/*! \brief Thread to handle a single NNTP/NNTPS client */
static void nntp_handler(struct bbs_node *node, int secure, int reader)
{
	struct nntp_session nntp;

	/* Start TLS if we need to */
	if (secure && bbs_node_starttls(node)) {
		return;
	}

	memset(&nntp, 0, sizeof(nntp));
	nntp.node = node;
	SET_BITFIELD(nntp.mode, reader);

	handle_client(&nntp);

	nntp_destroy(&nntp);
}

static void *__nntp_handler(void *varg)
{
	struct bbs_node *node = varg;

	bbs_node_net_begin(node);
	nntp_handler(node, !strcmp(node->protname, "NNTPS"), !strcmp(node->protname, "NNSP") ? NNTP_MODE_TRANSIT: NNTP_MODE_READER);
	bbs_node_exit(node);
	return NULL;
}

static struct bbs_unit_test tests[] =
{
	{ "NNTP Wildmats", test_wildmats },
};

static struct bbs_cli_entry cli_commands_nntp[] = {
	BBS_CLI_COMMAND(cli_newgroup, "news newgroup", 2, "Create a new newsgroup", NULL),
	BBS_CLI_COMMAND(cli_rmgroup, "news rmgroup", 3, "Remove a newsgroup", "news rmgroup <group> [confirm]"),
	BBS_CLI_COMMAND(cli_setpost, "news setpost", 4, "Edit posting status for a newsgroup", "news setpost <group> <y/n/m>"),
	BBS_CLI_COMMAND(cli_delarticle, "news delarticle", 4, "Delete an article", "news delarticle <group> <article number>"),
};

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

	cfg = bbs_config_load("net_nntp.conf", 1);
	if (!cfg) {
		return -1;
	}

	if (bbs_config_val_set_path(cfg, "general", "newsdir", newsdir, sizeof(newsdir))) {
		bbs_config_unlock(cfg);
		return -1;
	}

	if (active_init() || spool_init()) {
		return -1;
	}

	/* Remaining general settings */
	bbs_config_val_set_uint(cfg, "readers", "maxpostsize", &max_post_size);

	/* Reader settings */
	bbs_config_val_set_true(cfg, "readers", "requiresecurelogin", &require_secure_login);
	bbs_config_val_set_true(cfg, "readers", "checkidentity", &check_identity);

	/* NNTP */
	bbs_config_val_set_true(cfg, "nntp", "enabled", &nntp_enabled);
	bbs_config_val_set_port(cfg, "nntp", "port", &nntp_port);

	/* NNTPS */
	bbs_config_val_set_true(cfg, "nntps", "enabled", &nntps_enabled);
	bbs_config_val_set_port(cfg, "nntps", "port", &nntps_port);

	/* NNSP */
	bbs_config_val_set_true(cfg, "nnsp", "enabled", &nnsp_enabled);
	bbs_config_val_set_port(cfg, "nnsp", "port", &nnsp_port);

	bbs_config_val_set_true(cfg, "relayin", "requiretls", &requirerelaytls);

	bbs_config_val_set_uint(cfg, "relayout", "frequency", &relayfrequency);
	bbs_config_val_set_uint(cfg, "relayout", "maxage", &relaymaxage);

#define SKIP_SECTION(sectname) if (!strcasecmp(bbs_config_section_name(section), sectname)) { continue; }

	RWLIST_WRLOCK(&acls);
	RWLIST_WRLOCK(&inpeers);
	RWLIST_WRLOCK(&outpeers);
	while ((section = bbs_config_walk(cfg, section))) {
		/* Skip sections already processed above */
		SKIP_SECTION("general");
		SKIP_SECTION("readers");
		SKIP_SECTION("nntp");
		SKIP_SECTION("nntps");
		SKIP_SECTION("nnsp");
		SKIP_SECTION("relayin");
		SKIP_SECTION("relayout");
		if (!strcasecmp(bbs_config_section_name(section), "infeeds")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_inpeer(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "relayto")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				stringlist_push(&outpeers, bbs_keyval_val(keyval));
			}
		} else {
			/* The only config section type that isn't defined by the section name is user ACLs */
			const char *type = bbs_config_sect_val(section, "type");
			if (!type) {
				bbs_error("Unrecognized section name '%s' (if this is an ACL, add type=acl)\n", bbs_config_section_name(section));
			} else if (!strcasecmp(type, "acl")) {
				const char *guests = NULL, *userswm = NULL, *readwm = NULL, *postwm = NULL;
				int tmp, minreadpriv = 0, minpostpriv = 0;
				while ((keyval = bbs_config_section_walk(section, keyval))) {
					const char *key = bbs_keyval_key(keyval), *val = bbs_keyval_val(keyval);
					if (!strcasecmp(key, "type")) {
						continue;
					} else if (!strcasecmp(key, "guests")) {
						guests = val;
					} else if (!strcasecmp(key, "users")) {
						userswm = val;
					} else if (!strcasecmp(key, "read")) {
						readwm = val;
					} else if (!strcasecmp(key, "post")) {
						postwm = val;
					} else if (!strcasecmp(key, "minreadpriv")) {
						tmp = atoi(val);
						if (tmp < 0) {
							bbs_error("Invalid %s: %s\n", key, val);
						} else {
							minreadpriv = tmp;
						}
					} else if (!strcasecmp(key, "minpostpriv")) {
						tmp = atoi(val);
						if (tmp < 0) {
							bbs_error("Invalid %s: %s\n", key, val);
						} else {
							minpostpriv = tmp;
						}
					}
				}
				if (!guests && !userswm) {
					bbs_error("An ACL section must apply to at least either guests or users, ignoring [%s]\n", bbs_config_section_name(section));
					continue;
				}
				/* Create the ACL */
				load_acl(guests, userswm, readwm, postwm, minreadpriv, minpostpriv);
			} else {
				bbs_error("Unrecognized section type '%s'\n", type);
			}
		}
	}
	RWLIST_UNLOCK(&acls);
	RWLIST_UNLOCK(&inpeers);
	RWLIST_UNLOCK(&outpeers);

	bbs_config_unlock(cfg);
	return 0;
}

static void cleanup_lists(void)
{
	RWLIST_WRLOCK_REMOVE_ALL(&acls, entry, free_acl);
	RWLIST_WRLOCK_REMOVE_ALL(&inpeers, entry, free);
	stringlist_empty_destroy(&outpeers);
}

static int load_module(void)
{
	RWLIST_HEAD_INIT(&inpeers);
	stringlist_init(&outpeers);
	if (load_config()) {
		active_cleanup();
		spool_cleanup();
		return -1;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!nntp_enabled && !nntps_enabled && !nnsp_enabled) {
		bbs_debug(3, "Neither NNTP nor NNTPS nor NNSP is enabled, declining to load\n");
		goto cleanup; /* Nothing is enabled */
	}
	if (nntps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, NNTPS may not be used\n");
		goto cleanup;
	}
	if (strlen_zero(bbs_hostname())) {
		bbs_error("A BBS hostname in nodes.conf is required for newsgroup services\n");
		goto cleanup;
	}

	bbs_rwlock_init(&nntp_lock, NULL);

	bbs_register_tests(tests);
	bbs_cli_register_multiple(cli_commands_nntp);
	return bbs_start_tcp_listener3(nntp_enabled ? nntp_port : 0, nntps_enabled ? nntps_port : 0, nnsp_enabled ? nnsp_port : 0, "NNTP", "NNTPS", "NNSP", __nntp_handler);

cleanup:
	cleanup_lists();
	active_cleanup();
	spool_cleanup();
	return -1;
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_nntp);
	bbs_unregister_tests(tests);
	if (nntp_enabled) {
		bbs_stop_tcp_listener(nntp_port);
	}
	if (nntps_enabled) {
		bbs_stop_tcp_listener(nntps_port);
	}
	if (nnsp_enabled) {
		bbs_stop_tcp_listener(nnsp_port);
	}
	bbs_rwlock_destroy(&nntp_lock);
	cleanup_lists();
	active_cleanup();
	spool_cleanup();
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC3977 NNTP/NNSP", "mod_mail.so,mod_uuid.so");
