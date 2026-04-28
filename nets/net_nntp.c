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

static bbs_mutex_t nntp_lock;

/* General settings */
static char newsdir[256] = "";
static unsigned int max_post_size = 100000; /* 100 KB should be plenty */

/* News server metadata files */
static char active_file[sizeof(newsdir) + STRLEN("/active")] = ""; /* active file (used for LIST ACTIVE) */
static char active_times_file[sizeof(newsdir) + STRLEN("/active_times")] = ""; /* used for LIST ACTIVE.TIMES */
static char newsgroups_file[sizeof(newsdir) + STRLEN("/newsgroups")] = ""; /* used for LIST NEWSGROUPS */

/* Relay in */
static int requirerelaytls = 1;

/* Relay out */
static unsigned int relayfrequency = 3600;
static unsigned int relaymaxage = 86400;

/* Reader settings */
static int require_secure_login = 0;
static int check_identity = 1;

/* =============== Begin wildmat code =============== */

/*
 * Adapted from public domain code for matching wildmats written by Rich Salz in 1986 and appearing in INN 1.4
 * From: https://github.com/richsalz/wildmat/blob/main/wildmat.c
 * This version does not handle UTF-8 Unicode.
 * Minor modifications have been made for:
 * - formatting/readability
 * - parameters (e.g. accept const char *, instead of char *)
 * - safety against user input (the original assumes that inputs are valid, and they may not be). Without INVALID_PATTERN, tests would fail due to uninitialized accesses in valgrind.
 */
#define TRUE 1
#define FALSE 0
#define ABORT -1
#define INVALID_PATTERN -1 /* Bounds check on pattern, abort if invalid; checks added prior to any assumed memory accesses in original code */
#define NEGATE_CLASS '^' /* What character marks an inverted character class? */
#define OPTIMIZE_JUST_STAR /* Is "*" a common pattern? */

static int wildmat_domatch(register const char *text, register const char *p)
{
    register int last;
    register int matched;
    register int reverse;

    for ( ; *p; text++, p++) {
		if (*text == '\0' && *p != '*') {
			return ABORT;
		}
		switch (*p) {
		case '\\':
			/* Literal match with following character. */
			p++;
			if (!*p) {
				return INVALID_PATTERN;
			}
			/* FALLTHROUGH */
		default:
			if (*text != *p) {
				return FALSE;
			}
			continue;
		case '?':
			/* Match anything. */
			continue;
		case '*':
			while (*++p == '*') {
				continue; /* Consecutive stars act just like one. */
			}
			if (*p == '\0') {
				return TRUE; /* Trailing star matches everything. */
			}
			while (*text) {
				if ((matched = wildmat_domatch(text++, p)) != FALSE) {
					return matched;
				}
			}
			return ABORT;
		case '[':
			if (!p[1]) {
				return INVALID_PATTERN;
			}
			reverse = p[1] == NEGATE_CLASS ? TRUE : FALSE;
			if (reverse) {
				p++; /* Inverted character class. */
				if (!p[1]) {
					return INVALID_PATTERN;
				}
			}
			matched = FALSE;
			if (p[1] == ']' || p[1] == '-') {
				if (*++p == *text) {
					matched = TRUE;
				}
			}
			if (!*p || !p[1]) {
				return INVALID_PATTERN;
			}
			for (last = *p; *++p && *p != ']'; last = *p) {
				/* This next line requires a good C compiler. */
				if (!*p || !p[1]) {
					return INVALID_PATTERN;
				}
				if (*p == '-' && p[1] != ']' ? *text <= *++p && *text >= last : *text == *p) {
					matched = TRUE;
				}
			}
			if (!*p) {
				return INVALID_PATTERN;
			}
			if (matched == reverse) {
				return FALSE;
			}
			continue;
		}
    }

#ifdef MATCH_TAR_PATTERN
    if (*text == '/') {
		return TRUE;
	}
#endif
    return *text == '\0';
}

/*!
 * \brief Match a single wildmat pattern
 * \param text Text to check
 * \param p wildmat pattern
 * \retval 1 on match, 0 if doesn't match
 */
static int wildmat_pattern_match(const char *text, const char *p)
{
#ifdef OPTIMIZE_JUST_STAR
    if (p[0] == '*' && p[1] == '\0') {
		return TRUE;
	}
#endif
    return wildmat_domatch(text, p) == TRUE;
}

#undef TRUE
#undef FALSE
#undef ABORT
#undef INVALID_PATTERN
#undef NEGATE_CLASS
#undef OPTIMIZE_JUST_STAR
/* End public domain wildmat code */

/*! \brief Check for match for a whole wildmat */
static int wildmat(const char *text, const char *patterns)
{
	char buf[1024];
	char *p, *s = buf;
	const char *rightmostmatch = NULL;
	safe_strncpy(buf, patterns, sizeof(buf));

	/* The grammar described in RFC 3977 4.1 can be somewhat confusing, as it refers to wildmats and wildmat patterns.
	 *
	 * Wildmat patterns themselves are the single patterns that cannot contain commas.
	 * Wildmats themselves consist of 1 or more wildmat patterns (which could be as simple as the wildcard, *)
	 *
	 * RFC 3977 4.2 states that each constituent wildcard pattern is matched, and the rightmost pattern that matches is identified.
	 * If not preceded with "!", the whole wildmatch matches. Otherwise, the whole wildmat does not match.
	 *
	 * In other words, we do not match if ANY pattern matches, but only if the rightmost match is non-negated (and there is such a match). */
	while ((p = strsep(&s, ","))) {
		int match = *p == '!' ? wildmat_pattern_match(text, p + 1) : wildmat_pattern_match(text, p); /* If it's a negated pattern, we check for matching without the negation */
		if (match) {
			rightmostmatch = p;
		}
	}
	if (!rightmostmatch) {
		return 0;
	}
	return *rightmostmatch != '!'; /* If the rightmost match begins with !, not a match, otherwise the whole wildmat matches */
}

static int test_wildmats(void)
{
	/* RFC 3977 4.2 */
	bbs_test_assert_equals(1, wildmat("aaa", "a*,!*b,*c*"));
	bbs_test_assert_equals(0, wildmat("abb", "a*,!*b,*c*"));
	bbs_test_assert_equals(1, wildmat("ccb", "a*,!*b,*c*"));
	bbs_test_assert_equals(0, wildmat("xxx", "a*,!*b,*c*"));

	/* RFC 3977 4.4 */
	bbs_test_assert_equals(1, wildmat("abc", "abc")); /* The one string "abc" */
	bbs_test_assert_equals(0, wildmat("abc", "abcd"));
	bbs_test_assert_equals(1, wildmat("abc", "abc,def")); /* The two strings "abc" and "def" */
	bbs_test_assert_equals(1, wildmat("def", "abc,def"));
	bbs_test_assert_equals(0, wildmat("abc,def", "abc,def"));
#if 0
	/* wildmat_domatch doesn't support UTF-8 unicode, so this won't match at the moment: */
	bbs_test_assert_equals(0, wildmat("\xC2\xA3", "\xC2\xA3")); /* pound sterling symbol */
#endif
	bbs_test_assert_equals(1, wildmat("apple", "a*")); /* Any string that begins with "a" */
	bbs_test_assert_equals(1, wildmat("acb", "a*b")); /* Any string that begins with "a" and ends with "b" */
	bbs_test_assert_equals(0, wildmat("abc", "a*b"));
	bbs_test_assert_equals(1, wildmat("abc", "a*,*b")); /* Any string that begins with "a" or ends with "b" */
	bbs_test_assert_equals(1, wildmat("ccb", "a*,*b"));
	bbs_test_assert_equals(1, wildmat("abc", "a*,!*b")); /* Any string that begins with "a" and does not end with "b" */
	bbs_test_assert_equals(0, wildmat("ab", "a*,!*b"));
	bbs_test_assert_equals(1, wildmat("acdc", "a*,!*b,c*")); /* Any string that begins with "a" and does not end with "b", and any string that begins with "c" no matter what it ends with */
	bbs_test_assert_equals(1, wildmat("cat", "a*,!*b,c*"));
	bbs_test_assert_equals(1, wildmat("can", "a*,c*,!*b")); /* Any string that begins with "a" or "c" and does not end with "b" */
	bbs_test_assert_equals(1, wildmat("ark", "a*,c*,!*b"));
	bbs_test_assert_equals(0, wildmat("cab", "a*,c*,!*b"));
	bbs_test_assert_equals(1, wildmat("bat", "?a*")); /* Any string with "a" as its second character */
	bbs_test_assert_equals(0, wildmat("dead", "?a*"));
	bbs_test_assert_equals(1, wildmat("dead", "??a*")); /* Any string with "a" as its third character */
	bbs_test_assert_equals(1, wildmat("dead", "*a?")); /* Any string with "a" as its penultimate character */
	bbs_test_assert_equals(1, wildmat("beard", "*a??")); /* Any string with "a" as its antepenultimate character */
	bbs_test_assert_equals(0, wildmat("dead", "*a??"));

	bbs_test_assert_equals(1, wildmat("-adobe-courier-bold-o-normal--12-120-75-75-m-70-iso8859-1", "-*-*-*-*-*-*-12-*-*-*-m-*-*-*")); /* Example from wildmat.c: */
	bbs_test_assert_equals(0, wildmat("foobar", "foo[a-")); /* This example caused a crash in the original version of Rich Salz's wildmat_domatch */
	bbs_test_assert_equals(0, wildmat("foobar", "foo["));

	return 0;

cleanup:
	return -1;
}
/* =============== End wildmat code =============== */

static struct bbs_unit_test tests[] =
{
	{ "NNTP Wildmats", test_wildmats },
};

#define NNTP_MAX_LINE_LENGTH 512 /* RFC 3977 3.1. Includes CR LF (but not NUL) */
#define NNTP_MAX_ARG_LENGTH 497 /* RFC 3977 3.1 */
#define NNTP_BUFSIZE (NNTP_MAX_ARG_LENGTH + 1) /* For things like group names, etc. where we don't have any better official limitation to adhere to */

#define NNTP_MAX_PATH_LENGTH 1024

#define NNTP_MODE_TRANSIT 0
#define NNTP_MODE_READER 1

struct nntp_session {
	struct bbs_node *node;
	char *currentgroup;
	int currentarticle;
	int nextlastarticle;
	char grouppath[NNTP_MAX_PATH_LENGTH];
	char template[64];
	char *user;
	FILE *fp;
	char *newsgroups;
	char *fromheader;
	char *articleid;
	char *rxarticleid;
	unsigned int postlen;
	unsigned int mode:1;	/* MODE (0 = transit, 1 = reader) */
	unsigned int inpeer_any:1; /* Whether this is an in peer authorized in at least one inpeer ACL */
	unsigned int inpost:1;
	unsigned int inpostheaders:1;
	unsigned int postfail:1;
	unsigned int dostarttls:1;
};

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

enum nntp_acl_action {
	NNTP_ACL_READ,
	NNTP_ACL_POST,
	/* Could be extended for more granular control over operations (e.g. LIST, NEWNEWS, etc.) */
};

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
			return wildmat(bbs_username(nntp->node->user), acl->users);
		} else {
			return 0; /* No authenticated users authorized by this ACL */
		}
	} else {
		/* Guest user */
		return stringlist_contains_ip(&acl->guests, nntp->node->ip); /* Okay, even if list is empty */
	}
}

/*! \brief Whether a connection is allowed to perform a certain action against a certain group */
static int allowed_by_acl_locked(struct nntp_session *nntp, const char *group, enum nntp_acl_action action)
{
	struct reader_acl *acl;
	int acl_count = 0;

	RWLIST_TRAVERSE(&acls, acl, entry) {
		acl_count++;
		if (acl_matches(nntp, acl)) {
			/* ACL matches the connection, check if it allows this action */
			switch (action) {
				case NNTP_ACL_READ:
					if (acl->read && wildmat(group, acl->read)) {
						if (!acl->minreadpriv || (bbs_user_is_registered(nntp->node->user) && nntp->node->user->priv >= acl->minreadpriv)) {
							return 1;
						}
					}
					break;
				case NNTP_ACL_POST:
					if (acl->post && wildmat(group, acl->post)) {
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
static int authorized_inpeer_for_group_locked(struct nntp_session *nntp, const char *group, enum nntp_acl_action action)
{
	struct inpeer *i;

	UNUSED(action); /* Assumed to be NNTP_ACL_POST, but not currently checked. In theory, the ACL mechanism could be extended to allow IHAVE but deny reading, for example. */

	RWLIST_TRAVERSE(&inpeers, i, entry) {
		if (inpeer_acl_matches(nntp, i)) {
			if (wildmat(group, i->groups)) {
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

#define ACL_ALLOWED(nntp, group, action) (nntp->mode == NNTP_MODE_READER ? allowed_by_acl(nntp, group, action) : authorized_inpeer_for_group(nntp, group, action))
#define ACL_ALLOWED_LOCKED(nntp, group, action) (nntp->mode == NNTP_MODE_READER ? allowed_by_acl_locked(nntp, group, action) : authorized_inpeer_for_group_locked(nntp, group, action))

/* =============== End ACL Code =============== */

static void nntp_reset_data(struct nntp_session *nntp)
{
	free_if(nntp->newsgroups);
	if (nntp->fp) {
		fclose(nntp->fp);
		nntp->fp = NULL;
		if (unlink(nntp->template)) {
			bbs_error("Failed to delete %s: %s\n", nntp->template, strerror(errno));
		}
	}
}

static void nntp_destroy(struct nntp_session *nntp)
{
	nntp_reset_data(nntp);
	free_if(nntp->rxarticleid);
	free_if(nntp->articleid);
	free_if(nntp->fromheader);
	free_if(nntp->user);
	free_if(nntp->currentgroup);
	UNUSED(nntp);
}

#define _nntp_send(nntp, fmt, ...) bbs_debug(4, "%p <= " fmt, nntp, ## __VA_ARGS__); bbs_node_fd_writef(nntp->node, nntp->node->wfd, fmt, ## __VA_ARGS__);
#define nntp_send(nntp, code, fmt, ...) _nntp_send(nntp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

#define REQUIRE_ARGS(s) \
	if (strlen_zero(s)) { \
		nntp_send(nntp, 501, "Arguments required"); \
		return 0; \
	}

static int build_newsgroup_path(const char *name, char *buf, size_t len)
{
	errno = 0;
	if (strstr(name, "..")) { /* Reject dangerous inputs */
		return -1;
	}
	snprintf(buf, len, "%s/%s", newsdir, name);
	if (eaccess(buf, R_OK)) {
		errno = ENOENT;
		return -1; /* Doesn't exist */
	}
	return 0;
}

static int scan_newsgroup(const char *path, int *min, int *max, int *total)
{
	DIR *dir;
	struct dirent *entry;
	int fno = 0;

	*total = *min = *max = 0;

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		int articleid;
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		*total += 1;
		if (!fno++) {
			*min = *max = atoi(entry->d_name);
			continue;
		}
		articleid = atoi(entry->d_name);
		if (articleid > *max) {
			*max = articleid;
		}
		if (!*min || articleid < *min) {
			*min = articleid;
		}
	}

	closedir(dir);
	return 0;
}

/*! \brief Cache newsgroup info in a file for LIST, GROUP, etc. The generated active_file can be sent as a response to LIST ACTIVE
 * Doing this once will be much more efficient at runtime, since messages are read far more often than they are posted. */
static int scan_newsgroups(void)
{
	struct dirent *entry, **entries;
	FILE *fp;
	int fno = 0;
	int subs;
	char fullpath[1024];

	/*! \todo Calling this function to completely rewrite the active file is somewhat inefficient, especially if only a small change occured
	 * (in the least extreme case, just a single byte being changed, and no new bytes being written)
	 * An optimization by callers would be to know if the file size is staying the same and only edit the modified bytes in place. */

	/* Overwrite anything currently in the file. */
	bbs_mutex_lock(&nntp_lock);
	fp = fopen(active_file, "w");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", active_file, strerror(errno));
		bbs_mutex_unlock(&nntp_lock);
		return -1;
	}
	/* Conduct an ordered traversal of all the directories in the newsdir. */
	subs = scandir(newsdir, &entries, NULL, alphasort);
	if (subs < 0) {
		bbs_error("scandir(%s) failed: %s\n", newsdir, strerror(errno));
		fclose(fp);
		bbs_mutex_unlock(&nntp_lock);
		return -1;
	}
	while (fno < subs && (entry = entries[fno++])) {
		char groupinfo[282];
		int min, max, total;
		char perm = 'y'; /* posting allowed: y, n, m (moderated) */
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			free(entry);
			continue;
		}
		snprintf(fullpath, sizeof(fullpath), "%s/%s", newsdir, entry->d_name);
		scan_newsgroup(fullpath, &min, &max, &total);
		snprintf(groupinfo, sizeof(groupinfo), "%s %d %d %c", entry->d_name, min, max, perm);
		fprintf(fp, "%s\r\n", groupinfo);
		free(entry);
	}
	free(entries);
	fclose(fp);
	bbs_mutex_unlock(&nntp_lock);
	return 0;
}

/*! \note Must be called locked */
static int newgroup_file_insert(const char *filename, const char *name, const char *str)
{
	FILE *fp;

	/* Append to the file with the new group information.
	 * Note: In the future, we could also keep the file sorted here by more diligently rewriting it,
	 * check if it already exists in the file and abort, etc.
	 * however at the moment, we just do a dumb append.
	 * With a+, writes go to the end, but for portability, we should explicitly seek when reading. */
	UNUSED(name);

	fp = fopen(filename, "a+"); /* Append to existing or create */
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
		return -1;
	}
	fprintf(fp, "%s\r\n", str);
	fclose(fp);
	return 0;
}

/*!
 * \brief Create a newsgroup on this server (either a new group in the hierarchy, or instantiate an existing group on this server for the first time)
 *        The directory for articles will be created, and the newsgroup metadata will be added to all necessary metadata files.
 * \param name The name of the newsgroup.
 * \param description A short description about the purpose of the group
 * \param creation_time When group was created on this news server, in epoch time
 * \param creator Entity that created the newsgroup; may be an email address (though not necessarily, often just 'usenet' in many Usenet groups)
 * \param posting The current status of the group on this server. (y = posting allowed, n = posting not allowed, m = posts forwarded to newsgroup moderator)
 * \retval 0 Group created successfully
 * \retval 1 Group already exists
 * \retval -1 Error creating group
 */
static int newgroup(const char *name, const char *description, time_t creation_time, const char *creator, char posting)
{
	char groupdir[NNTP_MAX_PATH_LENGTH];
	char buf[NNTP_BUFSIZE];
	int res;

	if (strlen_zero(name) || strlen_zero(description)) {
		bbs_error("Missing mandatory fields name and/or description\n");
		return -1;
	}
	if (strlen_zero(creator)) {
		creator = "BBS";
	}
	if (posting != 'y' && posting != 'n' && posting != 'm') {
		bbs_error("Illegal posting setting '%c'\n", posting);
		return -1;
	}
	if (strchr(name, '\n') || strchr(description, '\n') || strchr(creator, '\n')) {
		bbs_error("Group metadata contains illegal value\n");
		return -1;
	}

	/* This is a ridiculously long limit, but it's the only one we have */
	if (strlen(name) > NNTP_MAX_ARG_LENGTH) {
		bbs_error("Group name '%s' is too long\n", name);
		return -1;
	}

	/* Will return -1 since it doesn't exist yet, that's fine and expected in this case.
	 * In fact, if it returns 0, it already exists and we have a problem. */
	res = build_newsgroup_path(name, groupdir, sizeof(groupdir));
	if (!res) {
		bbs_error("Directory %s already exists, please delete it and manually synchronize metadata\n", groupdir);
		return 1; /* Directory already exists? */
	}
	if (errno != ENOENT) {
		return -1; /* Something else went wrong */
	}

	bbs_mutex_lock(&nntp_lock);

	if (mkdir(groupdir, 0755)) {
		bbs_error("Failed to create %s: %s\n", groupdir, strerror(errno));
		goto abort;
	}

	/* Update the other files with what we want for this group
	 * These files create static data that does not change when articles are posted.
	 * The active file is the only one that mutates frequently, and hence it recreates itself.
	 * For that reason, the active file is sorted alphabetically, but others are not. */
	snprintf(buf, sizeof(buf), "%s %lu %s", name, creation_time, creator); /* LIST ACTIVE.TIMES format */
	res = newgroup_file_insert(active_times_file, name, buf);
	if (res) {
		goto abort;
	}

	snprintf(buf, sizeof(buf), "%s %s", name, description); /* LIST NEWSGROUPS format */
	res = newgroup_file_insert(newsgroups_file, name, buf);
	if (res) {
		goto abort;
	}

	bbs_mutex_unlock(&nntp_lock); /* Unlock before scan_newsgroups, since that locks as well */

	scan_newsgroups(); /* Last but not least, regenerate the active file */
	bbs_verb(4, "Created newsgroup %s (%s)\n", name, description);
	return 0;

abort:
	bbs_mutex_unlock(&nntp_lock);
	return -1;
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

	res = newgroup(name, description, time(NULL), creator, posting[0]);
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

static int nntp_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter),
	struct nntp_session *nntp, int msgfilter, const char *msgidfilter)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res = 0, msgno;

	/* use scandir instead of opendir/readdir, so the listing is ordered */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (!IS_MAILDIR_FILE(entry)) {
			free(entry);
			continue;
		}
		/* Filename format is ARTICLEID_MESSAGEID */
		msgno = atoi(entry->d_name); /* atoi should stop at the _ */
		if ((res = on_file(path, entry->d_name, nntp, msgno, msgfilter, msgidfilter))) {
			free(entry);
			break; /* If the handler returns non-zero then stop */
		}
		free(entry);
	}
	free(entries);
	return res;
}

static int nntp_traverse2(const char *path, int (*on_file)(const char *dir_name, const char *filename, struct nntp_session *nntp, int number), struct nntp_session *nntp, int min, int max)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res = 0;

	/* use scandir instead of opendir/readdir, so the listing is ordered */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		int msgno;
		if (!IS_MAILDIR_FILE(entry)) {
			goto cleanup;
		}
		/* Filename format is ARTICLEID_MESSAGEID */
		msgno = atoi(entry->d_name); /* atoi should stop at the _ */
		if (msgno < min || msgno > max) {
			goto cleanup;
		}
		if ((res = on_file(path, entry->d_name, nntp, msgno))) {
			free(entry);
			break; /* If the handler returns non-zero then stop */
		}
cleanup:
		free(entry);
	}
	free(entries);
	return res;
}

static int on_last(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	UNUSED(dir_name);
	UNUSED(filename);
	/* Keep going since each match is higher than the previous one. */
	if (nntp->currentarticle != number) {
		nntp->nextlastarticle = number;
	}
	return 0;
}

static int on_next(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	UNUSED(dir_name);
	UNUSED(filename);
	/* We go in order, so stop on first match */
	if (number > nntp->currentarticle) {
		nntp->nextlastarticle = number;
		return 1;
	}
	return 0;
}

static int on_find_article(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	const char *msgid = strchr(filename, '_');
	UNUSED(dir_name);
	UNUSED(number);
	if (!msgid) {
		bbs_error("Invalid filename: %s\n", filename);
		return -1;
	}
	nntp->articleid = strdup(filename); /* This callback should only execute at most once for any traversal */
	return 1;
}

/*! \brief Check if any newsgroup(s) contains an article with the specified article ID */
static int article_id_exists(const char *articleid)
{
	DIR *dir, *dir2;
	struct dirent *entry;
	char fulldir[NNTP_MAX_PATH_LENGTH + 1];
	int exists = 0;

	/* Order of newsgroup traversal doesn't matter.
	 * In fact, order of traversal within each newsgroup doesn't matter either.
	 * So use opendir instead of scandir. */

	bbs_debug(3, "Checking if article <%s> already exists\n", articleid);
	if (*articleid == '<') {
		bbs_warning("Malformed article ID: %s\n", articleid); /* Bug in calling function */
	}

	if (!(dir = opendir(newsdir))) {
		bbs_error("Error opening directory - %s: %s\n", newsdir, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		/* Check this directory */
		snprintf(fulldir, sizeof(fulldir), "%s/%s", newsdir, entry->d_name);
		dir2 = opendir(fulldir);
		if (!dir2) {
			bbs_error("Error opening directory - %s: %s\n", fulldir, strerror(errno));
			continue;
		}
		while ((entry = readdir(dir2)) != NULL) {
			if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
				continue;
			}
			if (strstr(entry->d_name, articleid)) {
				exists = 1;
				break;
			}
		}
		closedir(dir2);
		if (exists) {
			break;
		}
	}

	closedir(dir);
	return exists;
}

static char *get_article_id(struct nntp_session *nntp, int number)
{
	free_if(nntp->articleid);
	nntp_traverse2(nntp->grouppath, on_find_article, nntp, number, number);
	return nntp->articleid;
}

static int on_head(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter)
{
	FILE *fp;
	char fullpath[256 * 3];
	const char *msgid;
	char msgbuf[1001]; /* Enough for longest possible line */

	if (msgfilter && number != msgfilter) { /* Filtering by article ID? */
		return 0;
	}

	msgid = strchr(filename, '_');
	if (!msgid++) {
		bbs_error("Invalid newsgroup article filename: %s\n", filename);
		return 0;
	}
	if (msgidfilter) { /* Message filtering by msgid? */
		if (strcmp(msgidfilter, msgid)) {
			return 0;
		}
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullpath, strerror(errno));
		return 0;
	}

	nntp_send(nntp, 221, "%d <%s> Headers follow", number, msgid);
	while ((fgets(msgbuf, sizeof(msgbuf), fp))) {
		if (!strcmp(msgbuf, "\r\n")) {
			break; /* End of headers, now begin counting */
		} else if (!strcmp(msgbuf, "\n")) { /* Broken line endings */
			bbs_error("File %s using LF line endings instead of CR LF?\n", fullpath);
			break;
		}
		_nntp_send(nntp, "%s", msgbuf); /* msgbuf already includes CR LF */
	}
	fclose(fp);
	_nntp_send(nntp, ".\r\n"); /* Termination character. */
	return 1; /* Stop traversal */
}

static int on_article(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter)
{
	char fullpath[256];
	const char *msgid;

	if (msgfilter && number != msgfilter) { /* Filtering by article ID? */
		return 0;
	}

	msgid = strchr(filename, '_');
	if (!msgid++) {
		bbs_error("Invalid newsgroup article filename: %s\n", filename);
		return 0;
	}
	if (msgidfilter) { /* Message filtering by msgid? */
		if (strcmp(msgidfilter, msgid)) {
			return 0;
		}
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	nntp_send(nntp, 220, "%d <%s> Article follows", number, msgid);
	if (bbs_send_file(fullpath, nntp->node->wfd) < 0) {
		return -1; /* Just disconnect */
	}
	bbs_node_fd_writef(nntp->node, nntp->node->wfd, ".\r\n"); /* Termination character. */
	return 1; /* Stop traversal */
}

static int on_body(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter)
{
	char fullpath[256];
	char linebuf[1001];
	const char *msgid;
	FILE *fp;

	if (msgfilter && number != msgfilter) { /* Filtering by article ID? */
		return 0;
	}

	msgid = strchr(filename, '_');
	if (!msgid++) {
		bbs_error("Invalid newsgroup article filename: %s\n", filename);
		return 0;
	}
	if (msgidfilter) { /* Message filtering by msgid? */
		if (strcmp(msgidfilter, msgid)) {
			return 0;
		}
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);

	/* Read the file until the first CR LF CR LF (end of headers) */
	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullpath, strerror(errno));
		return -1;
	}
	/* Skip headers */
	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
	}
	/* This is the body */
	nntp_send(nntp, 220, "%d <%s>", number, msgid);
	/* XXX Easy, but not as efficient as calculating offset and then using sendfile... */
	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		bbs_node_fd_writef(nntp->node, nntp->node->wfd, "%s", linebuf);
	}
	fclose(fp);

	bbs_node_fd_writef(nntp->node, nntp->node->wfd, ".\r\n"); /* Termination character. */
	return 1; /* Stop traversal */
}

static int find_header(FILE *fp, const char *header, char **ptr, char *buf, size_t len)
{
	size_t hdrlen = strlen(header);

	*ptr = NULL;
	rewind(fp);

	while (fgets(buf, (int) len, fp)) {
		if (!strncasecmp(buf, header, hdrlen)) {
			char *start;
			start = buf + hdrlen;
			while (*start && isspace(*start)) { /* ltrim doesn't work here */
				start++;
			}
			bbs_term_line(start); /* CR should be sufficient, but do LF as well just in case */
			*ptr = start;
			return 0;
		}
	}
	/* Didn't find it */
	*buf = '\0';
	bbs_debug(3, "Didn't find any lines starting with '%s'\n", header);
	return -1;
}

static int on_xover(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	FILE *fp;
	char fullpath[3 * 256 + NNTP_MAX_PATH_LENGTH];
	char subjbuf[256], authorbuf[256], datebuf[256], bytecountbuf[12] = "";
	char *subject = subjbuf, *author = authorbuf, *date = datebuf, *references = NULL, *bytecount = bytecountbuf, *linecount = NULL;
	const char *msgid = NULL;
	struct stat st;

	msgid = strchr(filename, '_');
	if (!msgid++) {
		bbs_error("Invalid newsgroup article filename: %s\n", filename);
		return 0;
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);

	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("fopen(%s) failed: %s\n", fullpath, strerror(errno));
		return 0;
	}

	find_header(fp, "Subject:", &subject, subjbuf, sizeof(subjbuf));
	find_header(fp, "From:", &author, authorbuf, sizeof(authorbuf));
	find_header(fp, "Date:", &date, datebuf, sizeof(datebuf));

	fclose(fp);
	if (!stat(fullpath, &st)) {
		snprintf(bytecountbuf, sizeof(bytecountbuf), "%ld", st.st_size);
	}

	/* subject, author, date, message ID, references, byte count, line count */
	_nntp_send(nntp, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\r\n", number, S_IF(subject), S_IF(author), S_IF(date), S_IF(msgid), S_IF(references), S_IF(bytecount), S_IF(linecount));
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
static int do_post(struct nntp_session *nntp, const char *srcfilename)
{
	char *newsgroup, *newsgroups = NULL;
	char *uuid = NULL;
	int res = -1;
	int total_errors = 0, permission_errors = 0;
	int srcfd;

	if (!nntp->newsgroups) {
		goto cleanup;
	}

	if (nntp->mode == NNTP_MODE_READER) {
		/* Check the From header. */
		if (!nntp->fromheader) {
			goto cleanup;
		} else {
			const char *from = nntp->fromheader + STRLEN("From:");
			ltrim(from);
			if (!identity_allowed_for_posting(nntp, from)) {
				bbs_warning("Rejected NNTP post by user %d with identity %s\n", nntp->node->user ? nntp->node->user->id : 0, S_IF(from));
				nntp_send(nntp, 441, "Identity not allowed for posting");
				goto cleanup2;
			}
		}
		uuid = bbs_uuid(); /* Use same UUID (and by extension, the same Article ID) for all newsgroups */
		if (!uuid) {
			goto cleanup;
		}
	} else { /* else if TRANSIT, just trust what the other end says (presumably the original server validated the identity). */
		/* Could be a race condition, maybe we didn't have the article when the client said IHAVE,
		 * but now we do (possibly from some other server). Check again. */
		if (article_id_exists(nntp->rxarticleid)) {
			nntp_send(nntp, 437, "Duplicate; do not resend");
			return 0;
		}
		if (strlen_zero(nntp->rxarticleid)) {
			bbs_error("Posting article ID is invalid: %s\n", nntp->rxarticleid);
		}
	}

	/*! \todo On failure, should we keep track of Message ID to prevent duplicates on retries? But we assign the Message ID, so.... */
	/*! \todo Do we need to inject the header? snprintf(msgid, sizeof(msgid), "Message-ID: <%s@%s>", uuid, bbs_hostname()); */

	srcfd = open(srcfilename, O_RDONLY);
	if (srcfd < 0) {
		bbs_error("Failed to open %s: %s\n", srcfilename, strerror(errno));
		goto cleanup;
	}

	newsgroups = nntp->newsgroups + STRLEN("Newsgroups:"); /*! \todo FIXME This doesn't handle multiline headers, should be moved to data loop to concatenate if needed */
	ltrim(newsgroups);
	ACL_RDLOCK(nntp);
	while ((newsgroup = strsep(&newsgroups, ","))) {
		char group[NNTP_BUFSIZE];
		char filename[NNTP_MAX_PATH_LENGTH];

		int min, max, total;
		int msgno;
		int fd;

		bbs_debug(5, "Processing newsgroup %s (%s)\n", newsgroup, nntp->mode == NNTP_MODE_READER ? "READER" : "TRANSIT");
		if (build_newsgroup_path(newsgroup, group, sizeof(group))) {
			bbs_debug(3, "Newsgroup '%s' does not exist\n", newsgroup); /* Try to deliver to any other groups listed */
			total_errors++;
			continue;
		}

		if (!ACL_ALLOWED_LOCKED(nntp, newsgroup, NNTP_ACL_POST)) {
			permission_errors++;
			total_errors++;
			continue;
		}

		/* Atomically assign the new message ID. */
		bbs_mutex_lock(&nntp_lock); /* Could really just be a per-newsgroup lock, but we don't have such locks at the moment. */
		scan_newsgroup(group, &min, &max, &total);
		msgno = max + 1; /* Assign new message number, for this newsgroup. */
		/* The only way this file would already exist is if the client is posting to the same newsgroup twice.
		 * Ignore any such attempts.
		 * Check using current max UID since message would have already posted by now. */
		if (nntp->mode == NNTP_MODE_READER) {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s@%s", newsdir, newsgroup, msgno - 1, uuid, bbs_hostname());
		} else {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s", newsdir, newsgroup, msgno - 1, nntp->rxarticleid);
		}
		if (!eaccess(filename, R_OK)) {
			bbs_debug(2, "Ignoring duplicate post attempt\n");
			bbs_mutex_unlock(&nntp_lock);
			total_errors++;
			continue;
		}
		if (nntp->mode == NNTP_MODE_READER) {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s@%s", newsdir, newsgroup, msgno, uuid, bbs_hostname());
		} else {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s", newsdir, newsgroup, msgno, nntp->rxarticleid);
		}
		fd = open(filename, O_CREAT | O_WRONLY, 0600);
		if (fd < 0) {
			bbs_warning("open(%s) failed: %s\n", filename, strerror(errno));
			bbs_mutex_unlock(&nntp_lock);
			total_errors++;
			continue;
		}
		bbs_copy_file(srcfd, fd, 0, (int) nntp->postlen);
		close(fd);
		bbs_mutex_unlock(&nntp_lock);
		res = 0;
		bbs_debug(3, "Posted article %s to newsgroup %s\n", filename, newsgroup);
	}
	ACL_UNLOCK(nntp);
	close(srcfd);

cleanup:
	if (res) {
		/* Should we instead do permanent error for transit (437), if newsgroup doesn't exist? But what if it's added later? */
		if (nntp->mode == NNTP_MODE_READER) {
			if (total_errors == permission_errors) {
				/* We weren't authorized to post to the group(s) */
				nntp_send(nntp, 440, "Posting not allowed");
			} else {
				nntp_send(nntp, 441, "Posting failed");
			}
		} else {
			if (total_errors == permission_errors) {
				nntp_send(nntp, 437, "Transfer rejected; do not retry");
			} else {
				nntp_send(nntp, 436, "Transfer failed; retry later");
			}
		}
	} else {
		/* Posting succeeded to at least one newsgroup. */
		nntp_send(nntp, nntp->mode == NNTP_MODE_READER ? 240 : 235, "Article received OK");
		scan_newsgroups(); /* Rebuild the newsgroups file so that LIST responses are accurate. */
	}
cleanup2:
	free_if(uuid);
	free_if(newsgroups);
	nntp->postlen = 0;
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

struct list_info {
	const char *category; /* Category name */
	const char *resp; /* Response start text */
	const char *file; /* Filename */
	unsigned int per_newsgroup:1;
};

static struct list_info list_handlers[] =
{
	/* Similar to INN (InterNetNews), we use separate files for different purposes, to optimize responses to various LIST commands.
	 * Each file begins with the newsgroup as the first word, but subsequent words differ by file. */

	/* Same as original LIST command in RFC 977 (all newsgroups client is permitted to select using GROUP)
	 * <name> <high water mark> <low water mark> <posting permitted: y/n/m> */
	{ "ACTIVE", "Newsgroup listing follows in form \"group high low status\"", active_file, 1 }, /* Must be first in array. */

	/* active.times list provides creation information: <name> <epoch time of creation> <creator, i.e. email address> */
	{ "ACTIVE.TIMES", "Newsgroup creation times follow in form \"group time who\"", active_times_file, 1 },

	/* <name> <short description about purpose of the group> (groups for which information is unavailable may be omitted, i.e. may miss groups included in LIST ACTIVE) */
	{ "NEWSGROUPS", "Newsgroup information follows in form \"group description\"", newsgroups_file, 1 },

	/* distrib.pats list assists clients to choose a value for the Distribution header of an article being posted.
	 * <weight> <wildmat> <value for Distribution header content>
	 * Client selects highest-weighted line with a matching wildmat. */
	/* Note: Eternal September just responds with the 2nd line here, so for now we just do that as well instead of pulling from a file: */
	{ "DISTRIB.PATS", "Default distributions in form \"weight:group-pattern:distribution\"\r\n10:local.*:local", NULL, 0 },

	/*! \todo Add additional handlers as specified in RFC 2980 and RFC 6048 */
};

static struct list_info *find_list_handler(const char *keyword)
{
	size_t i;
	for (i = 0; i < ARRAY_LEN(list_handlers); i++) {
		if (!strcasecmp(keyword, list_handlers[i].category)) {
			return &list_handlers[i];
		}
	}
	return NULL;
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
	FILE *fp = NULL;
	struct list_info *lp = NULL;

	/* If a keyword is not specified, then an argument is not present either (per syntax in RFC 3977 7.6.1.1) */
	lp = !strlen_zero(keyword) ? find_list_handler(keyword) : &list_handlers[0]; /* RFC 2980 2.1.2 states that "LIST ACTIVE" is the same as "LIST" (with no keyword modifier) */
	if (!lp) {
		nntp_send(nntp, 501, "Unknown LIST keyword");
		return 1;
	}
	if (!strlen_zero(argument) && !lp->per_newsgroup) {
		/* We have an argument, but we don't consume one */
		nntp_send(nntp, 501, "This command is not newsgroup-based and does not accept an argument");
		return 1;
	}

	/* Before starting a 2xx response, try opening the file if there is one, so we can abort early on failure */
	if (lp->file) {
		fp = fopen(lp->file, "r");
		if (!fp) {
			bbs_error("Failed to open %s: %s\n", lp->file, strerror(errno));
			nntp_send(nntp, 503, "Data item not available");
			return 1;
		}
	}

	nntp_send(nntp, 215, "%s", lp->resp);
	if (fp) {
		int lineno = 0;
		char *group, buf[NNTP_MAX_LINE_LENGTH + 1];
		ACL_RDLOCK(nntp); /* Lock the ACL list once for the whole loop so we can use the locked version of the ACL check */
		while ((fgets(buf, sizeof(buf), fp))) {
			char *line = buf;
			lineno++;
#define nntp_sep(ptr) strsep(ptr, " ")
			group = nntp_sep(&line); /* The first word (prior to a space or tab) is the newsgroup. Subsequent "words" and their meaning depend on the file. */
			if (strlen_zero(line)) {
				bbs_error("Malformed line (%s:%d)\n", lp->file, lineno);
				continue;
			}
			/* Check if the group matches any filters present */
			if (argument && !wildmat(group, argument)) {
				continue; /* Didn't match wildmat */
			}
			/* Check if allowed by ACL */
			if (!ACL_ALLOWED_LOCKED(nntp, group, NNTP_ACL_READ)) {
				continue;
			}
			bbs_term_line(line);
			/* We don't care what the rest of the line is, if the group matches, send it to the client */
			_nntp_send(nntp, "%s %s\r\n", group, line);
		}
		ACL_UNLOCK(nntp);
		fclose(fp);
	}
	if (res < 0) {
		return res;
	}
	_nntp_send(nntp, ".\r\n");
	return res;
}

/*! \note Condensed equivalent of handle_list for CLI */
static int cli_list(struct bbs_cli_args *a)
{
	struct list_info *lp;
	const char *keyword = a->argv[2];
	const char *argument = a->argc >= 4 ? a->argv[3] : NULL;

	lp = find_list_handler(keyword);
	if (!lp) {
		bbs_dprintf(a->fdout, "Unknown LIST keyword\n");
		return -1;
	}
	if (argument && !lp->per_newsgroup) {
		bbs_dprintf(a->fdout, "This command does not accept a wildmat argument\n");
		return -1;
	}
	bbs_dprintf(a->fdout, "%s\n", lp->resp);
	if (lp->file) {
		char *group, buf[NNTP_MAX_LINE_LENGTH + 1];
		FILE *fp = fopen(lp->file, "r");
		if (!fp) {
			bbs_dprintf(a->fdout, "Failed to open %s: %s\n", lp->file, strerror(errno));
			return -1;
		}
		while ((fgets(buf, sizeof(buf), fp))) {
			char *line = buf;
			group = nntp_sep(&line); /* The first word (prior to a space or tab) is the newsgroup. Subsequent "words" and their meaning depend on the file. */
			if (strlen_zero(line)) {
				continue;
			} else if (argument && !wildmat(group, argument)) {
				continue;
			}
			bbs_term_line(line);
			bbs_dprintf(a->fdout, "%s\t%s\n", group, line); /* Use TAB instead of space after group for slightly better alignment in formatting */
		}
		fclose(fp);
	}
	return 0;
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

static int nntp_process(struct nntp_session *nntp, char *s, size_t len)
{
	char *command;

	if (nntp->inpost) {
		int res;
		if (!strcmp(s, ".")) {
			nntp->inpost = 0;
			if (nntp->postfail) {
				nntp->postfail = 0;
				if (nntp->mode == NNTP_MODE_TRANSIT) {
					if (nntp->inpostheaders || nntp->postlen >= max_post_size) {
						/* Permanent error */
						nntp_send(nntp, 437, "Transfer rejected (%s); do not retry", nntp->inpostheaders ? "article mismatch" : "too large");
					} else {
						nntp_send(nntp, 436, "Transfer not possible; try again later"); /* Temporary error */
					}
				} else {
					nntp_send(nntp, 441, "Posting failed%s", nntp->postlen >= max_post_size ? " (too large)" : "");
				}
				return 0;
			}
			fclose(nntp->fp);
			nntp->fp = NULL;
			res = do_post(nntp, nntp->template);
			unlink(nntp->template);
			return res;
		}

		if (nntp->postfail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		if (nntp->inpostheaders) {
			if (STARTS_WITH(s, "From:")) {
				REPLACE(nntp->fromheader, s);
			} else if (nntp->mode == NNTP_MODE_TRANSIT && STARTS_WITH(s, "Message-ID:")) {
				/* The article better be the article that the other server said it was in IHAVE */
				if (!strstr(s, nntp->rxarticleid)) { /* XXX What if it's a substring? */
					nntp->postfail = 1;
					return 0;
				}
			} else if (STARTS_WITH(s, "Newsgroups:")) {
				REPLACE(nntp->newsgroups, s);
			} else if (!len) {
				nntp->inpostheaders = 0; /* Got CR LF, end of headers */
			}
		}

		if (nntp->postlen + (unsigned int) len >= max_post_size) {
			nntp->postfail = 1;
			nntp->postlen = max_post_size; /* This isn't really true, this is so we can detect that the message was too large. */
		}

		res = bbs_append_stuffed_line_message(nntp->fp, s, (size_t) len); /* Should return len + 2, unless it was byte stuffed, in which case it'll be len + 1 */
		if (res < 0) {
			nntp->postfail = 1;
		}
		nntp->postlen += (unsigned int) res;
		return 0;
	}

	command = strsep(&s, " ");

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
			_nntp_send(nntp, "LIST ACTIVE\r\n");
		} else { /* Transit mode */
			_nntp_send(nntp, "IHAVE\r\n");
			_nntp_send(nntp, "MODE-READER\r\n");
		}
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
			nntp->dostarttls = 1;
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
		char grouppath[NNTP_BUFSIZE + 1];
		int min, max, total;
		if (build_newsgroup_path(s, grouppath, sizeof(grouppath))) {
			nntp_send(nntp, 411, "%s is unknown", s);
			return 0;
		}
		/* For future commands which require a group, we don't check read ACL since we check it here, before changing the group */
		if (!ACL_ALLOWED(nntp, s, NNTP_ACL_READ)) {
			nntp_send(nntp, 502, "Read access denied");
			return 0;
		}
		/* Must not change current group unless we succeed */
		REPLACE(nntp->currentgroup, s);
		safe_strncpy(nntp->grouppath, grouppath, sizeof(nntp->grouppath));
		scan_newsgroup(grouppath, &min, &max, &total);
		nntp_send(nntp, 211, "%d %d %d %s", total, min, max, s);
		nntp->currentarticle = min;
	} else if (!strcasecmp(command, "XOVER")) {
		/* RFC 2980 XOVER */
		/* Thunderbird-based clients prefer XOVER to HEAD, and will only issue a HEAD if XOVER is not available. */
		/* XXX For some reason, Thunderbird-based clients bork on HEAD and don't show any body (and don't ask for it),
		 * but with XOVER, no matter how complete/incomplete the response, it'll issue an ARTICLE and get the whole thing properly.
		 * Personally, I think this command is especially stupid. HEAD ought to have been sufficient enough for everyone.
		 * Either way, this really needs to work properly: */
		int min, max;

		REQUIRE_READER();
		REQUIRE_GROUP();
		if (strlen_zero(s)) {
			parse_min_max(s, &min, &max, '-');
		} else {
			if (!nntp->currentarticle) {
				nntp_send(nntp, 420, "No article(s) selected");
				return 0;
			}
			min = max = nntp->currentarticle;
		}
		nntp_send(nntp, 224, "Overview information follows");
		nntp_traverse2(nntp->grouppath, on_xover, nntp, min, max);
		_nntp_send(nntp, ".\r\n");
	} else if (!strcasecmp(command, "HEAD")) {
		int msgid;
		REQUIRE_READER();
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		msgid = atoi(s); /*! \todo BUGBUG If we're filtering by msg id (not article ID), but msg ID begins with a numeric, atoi will not return 0 */
		if (!msgid) {
			bbs_strterm(s, '>'); /* Strip <> from msgid */
			if (*s == '<') {
				s++;
			}
		}
		if (!nntp_traverse(nntp->grouppath, on_head, nntp, msgid, msgid ? NULL : s)) {
			nntp_send(nntp, msgid ? 423 : 430, "No Such Article Found");
			return 0;
		}
	} else if (!strcasecmp(command, "ARTICLE")) {
		int msgid;
		REQUIRE_READER();
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		msgid = atoi(s); /*! \todo BUGBUG If we're filtering by msg id (not article ID), but msg ID begins with a numeric, atoi will not return 0 */
		if (!msgid) {
			bbs_strterm(s, '>'); /* Strip <> from msgid */
			if (*s == '<') {
				s++;
			}
		}
		if (!nntp_traverse(nntp->grouppath, on_article, nntp, msgid, msgid ? NULL : s)) {
			nntp_send(nntp, msgid ? 423 : 430, "No Such Article Found");
			return 0;
		}
	} else if (!strcasecmp(command, "BODY")) {
		int msgid;
		REQUIRE_READER();
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		msgid = atoi(s); /*! \todo BUGBUG If we're filtering by msg id (not article ID), but msg ID begins with a numeric, atoi will not return 0 */
		if (!msgid) {
			bbs_strterm(s, '>'); /* Strip <> from msgid */
			if (*s == '<') {
				s++;
			}
		}
		if (!nntp_traverse(nntp->grouppath, on_body, nntp, msgid, msgid ? NULL : s)) {
			nntp_send(nntp, 430, "No Such Article Found");
			return 0;
		}
	} else if (!strcasecmp(command, "LAST")) {
		REQUIRE_READER();
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, 420, "Current article number is invalid");
			return 0;
		}
		/* Find the max article number less than nntp->currentarticle, if there is one. */
		nntp->nextlastarticle = 0;
		nntp_traverse2(nntp->grouppath, on_last, nntp, 1, nntp->currentarticle - 1);
		if (nntp->currentarticle == nntp->nextlastarticle) {
			nntp_send(nntp, 422, "No previous article in group");
			return 0;
		}
		if (!get_article_id(nntp, nntp->nextlastarticle)) {
			if (nntp->nextlastarticle > 0) {
				bbs_warning("Couldn't find article ID for %s #%d???\n", nntp->currentgroup, nntp->nextlastarticle);
			}
			nntp_send(nntp, 422, "No previous article in group");
			return 0;
		}
		nntp_send(nntp, 223, "%d %s", nntp->nextlastarticle, nntp->articleid);
		free_if(nntp->articleid);
	} else if (!strcasecmp(command, "NEXT")) {
		REQUIRE_READER();
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, 420, "Current article number is invalid");
			return 0;
		}
		nntp->nextlastarticle = 0;
		nntp_traverse2(nntp->grouppath, on_next, nntp, nntp->currentarticle + 1, INT_MAX);
		if (!nntp->nextlastarticle) {
			nntp_send(nntp, 421, "No next article in group");
			return 0;
		}
		if (!get_article_id(nntp, nntp->nextlastarticle)) {
			bbs_warning("Couldn't find article ID for %s #%d???\n", nntp->currentgroup, nntp->nextlastarticle);
			nntp_send(nntp, 421, "No next article in group");
			return 0;
		}
		nntp_send(nntp, 223, "%d %s", nntp->nextlastarticle, nntp->articleid);
		free_if(nntp->articleid);
	} else if (!strcasecmp(command, "POST")) {
		REQUIRE_READER();
		if (!bbs_user_is_registered(nntp->node->user) && !guests_can_post_at_all()) {
			nntp_send(nntp, 480, "Must authenticate first");
			return 0;
		}
		/* Group not required, the headers will say group(s) to which message should be posted. */
		nntp_reset_data(nntp);
		strcpy(nntp->template, "/tmp/nntpXXXXXX");
		nntp->fp = bbs_mkftemp(nntp->template, 0600);
		if (!nntp->fp) {
			nntp_send(nntp, 440, "Server error, posting temporarily unavailable");
		} else {
			nntp_send(nntp, 340, "Input article; end with a period on its own line");
			nntp->inpost = 1;
			nntp->inpostheaders = 1;
		}
	} else if (!strcasecmp(command, "IHAVE")) {
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
		REQUIRE_ARGS(s);
		/* Strip <> */
		if (*s == '<') {
			s++;
		}
		bbs_strterm(s, '>')
		REQUIRE_ARGS(s);
		/* Check if any message with this ID exists in any newsgroup. */
		if (article_id_exists(s)) {
			nntp_send(nntp, 435, "Duplicate");
			return 0;
		}
		REPLACE(nntp->rxarticleid, s);
		if (!nntp->rxarticleid) {
			nntp_send(nntp, 436, "Retry later");
			return 0;
		}
		nntp_reset_data(nntp);
		strcpy(nntp->template, "/tmp/nntpXXXXXX");
		nntp->fp = bbs_mkftemp(nntp->template, 0600);
		if (!nntp->fp) {
			nntp_send(nntp, 436, "Temporary server error, try again later");
		} else {
			nntp_send(nntp, 335, "Send it; end with a period on its own line");
			/* Reuse the POST logic */
			nntp->inpost = 1;
			nntp->inpostheaders = 1;
		}
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
	char buf[1001];
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
		if (nntp_process(nntp, buf, (size_t) res)) {
			break;
		}
		if (nntp->dostarttls) {
			/* RFC 4642 */
			bbs_debug(3, "Starting TLS\n");
			nntp->dostarttls = 0;
			if (bbs_node_starttls(nntp->node)) {
				break; /* Just abort */
			}
			free_if(nntp->currentgroup);
			nntp->currentarticle = 0;
			bbs_readline_flush(&rldata); /* Prevent STARTTLS command injection by resetting the buffer after TLS upgrade */
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

	/* Build metadata file paths */
	snprintf(active_file, sizeof(active_file), "%s/active", newsdir);
	snprintf(active_times_file, sizeof(active_times_file), "%s/active_times", newsdir);
	snprintf(newsgroups_file, sizeof(newsgroups_file), "%s/newsgroups", newsdir);

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

static struct bbs_cli_entry cli_commands_nntp[] = {
	BBS_CLI_COMMAND(cli_newgroup, "news newgroup", 2, "Create a new newsgroup", NULL),
	BBS_CLI_COMMAND(cli_list, "news list", 3, "List newsgroup info, optionally filtered", "news list <active|active.times|newsgroups> [wildmat]"),
};

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

	bbs_mutex_init(&nntp_lock, NULL);

	if (scan_newsgroups()) {
		goto cleanup;
	}

	bbs_register_tests(tests);
	bbs_cli_register_multiple(cli_commands_nntp);
	return bbs_start_tcp_listener3(nntp_enabled ? nntp_port : 0, nntps_enabled ? nntps_port : 0, nnsp_enabled ? nnsp_port : 0, "NNTP", "NNTPS", "NNSP", __nntp_handler);

cleanup:
	cleanup_lists();
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
	bbs_mutex_destroy(&nntp_lock);
	cleanup_lists();
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC3977 NNTP/NNSP", "mod_mail.so,mod_uuid.so");
