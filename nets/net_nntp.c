/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, 2026, Naveen Albert
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
 * \note Supports RFC 2980 XHDR, XOVER, XPAT
 * \note Supports RFC 3977 OVER (including MSGID)
 * \note Supports RFC 4642 STARTTLS
 * \note Supports RFC 4643 AUTHINFO
 * \note Supports RFC 4644 STREAMING
 * \note Supports RFC 6048 LIST extensions
 * \note Supports RFC 8054 COMPRESS DEFLATE
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
#include <time.h> /* use struct tm */
#include <sys/time.h> /* struct timeval for musl */

#include "include/stringlist.h"
#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/cli.h"
#include "include/term.h"
#include "include/mail.h"
#include "include/hash.h"
#include "include/base64.h"
#include "include/test.h"

#include "include/mod_mail.h"
#include "include/mod_uuid.h"

#define MAIN_NNTP_FILE
#include "net_nntp/nntp.h"
#include "net_nntp/nntp_history.h"
#include "net_nntp/nntp_feed.h"
#include "net_nntp/nntp_suck.h"

/* NNTP ports */
/* Reading server */
#define DEFAULT_NNTP_PORT 119
#define DEFAULT_NNTPS_PORT 563
/* Transit server */
#define DEFAULT_NNSP_PORT 433

#ifdef DEBUG_DISTRIBUTION
#define DIST_DEBUG(level, fmt, ...) bbs_debug(level, fmt, ## __VA_ARGS__)
#else
#define DIST_DEBUG(level, fmt, ...)
#endif

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
int nntp_unloading = 0; /* Used extern by nntp_feed_nntp.c and nntp_history.c */
void *thismodule; /* Used extern by nntp_suck.c, nntp_history.c */

static bbs_rwlock_t nntp_lock;
static FILE *newslog;
static FILE *postlog;

/* General settings */
char newsname[256] = ""; /* Our site name and path identity. Non-static so other files can access it extern */
static char newsorg[256] = ""; /* Organization */
char newsdir[256] = ""; /* Non-static so other files can access it extern */

extern size_t history_bloom_maxmem;
extern unsigned long history_bloom_maxfpinv;

/* Global settings for incoming articles */
static unsigned int max_article_size = 100000; /* ~100 KB should be plenty */
unsigned int max_groups = 100; /* used extern in nntp_suck.c */
static unsigned int max_crossposts = 10;
static unsigned int max_accept_age = 10;
unsigned int min_history = 11; /* used extern in nntp_history.c */
static unsigned int min_lines = 0;
static unsigned int max_lines = 0;
int spool_compression = 0; /* used extern in nntp_spool_trad.c */
static char poisongroups[NNTP_MAX_LINE_LENGTH];
static char poisonsites[NNTP_MAX_LINE_LENGTH];

/* Global settings for incoming articles from peers */
static int requirerelaytls = 1;
static int keepjunk = 0;
static int xref_slave = 0;

/* Reader settings */
enum injection_posting_account {
	INJECTION_POSTING_ACCOUNT_OBFUSCATED,
	INJECTION_POSTING_ACCOUNT_USERNAME,
	INJECTION_POSTING_ACCOUNT_HIDDEN,
};

static int require_secure_login = 0;
static int check_identity = 1;
static int allow_invalid = 0;
static unsigned int max_post_size = 10000; /* ~10 KB by default for reader posts */
static unsigned int max_post_groups = 25;
static enum injection_posting_account injection_add_posting_account = INJECTION_POSTING_ACCOUNT_OBFUSCATED;
static int injection_add_posting_host = 0;
static char complaints_addr[256] = "";

static struct stringlist subscriptions; /* LIST SUBSCRIPTIONS */

static char motd[NNTP_MAX_LINE_LENGTH + 1]; /* Note: This can be a multi-line message, so the protocol does not limit this to a certain size */

struct distrib_pat {
	const char *wildmat;
	const char *value;
	int weight;
	RWLIST_ENTRY(distrib_pat) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(distrib_pats, distrib_pat);

struct distribution {
	const char *name;
	const char *description;
	RWLIST_ENTRY(distribution) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(distributions, distribution);

struct moderator {
	const char *wildmat;
	const char *template; /* Submission template */
	RWLIST_ENTRY(moderator) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(moderators, moderator);

static int add_distrib_pat(const char *key)
{
	char buf[NNTP_BUFSIZ];
	struct distrib_pat *p;
	size_t wildmatlen, valuelen;
	char *weightstr, *wildmat, *value;
	int weight;

	safe_strncpy(buf, key, sizeof(buf));
	value = buf;
	weightstr = strsep(&value, ":");
	wildmat = strsep(&value, ":");

	if (strlen_zero(weightstr) || strlen_zero(wildmat)) { /* the value can be empty to signal no Distribution header should be added */
		bbs_error("Invalid distribution pattern '%s'\n", key);
		return -1;
	}

	weight = atoi(weightstr);
	if (!weight && *weightstr != '0') {
		bbs_error("Invalid distribution pattern weight '%s'\n", weightstr);
		return -1;
	}

	wildmatlen = strlen(wildmat);
	valuelen = strlen(S_IF(value));

	p = calloc(1, sizeof(*p) + wildmatlen + valuelen + 2);
	if (ALLOC_FAILURE(p)) {
		return -1;
	}
	strcpy(p->data, wildmat); /* Safe */
	p->wildmat = p->data;
	strcpy(p->data + wildmatlen + 1, S_IF(value)); /* Safe */
	p->value = p->data + wildmatlen + 1;
	p->weight = weight;
	RWLIST_INSERT_TAIL(&distrib_pats, p, entry);
	return 0;
}

static int add_distribution(const char *name, const char *description)
{
	struct distribution *d;
	size_t namelen, desclen;

	RWLIST_TRAVERSE(&distributions, d, entry) {
		if (!strcmp(d->name, name)) {
			bbs_error("Duplicate distribution '%s'\n", name);
			return -1;
		}
	}

	namelen = strlen(name);
	desclen = strlen(description);

	d = calloc(1, sizeof(*d) + namelen + desclen + 2);
	if (ALLOC_FAILURE(d)) {
		return -1;
	}
	strcpy(d->data, name); /* Safe */
	d->name = d->data;
	strcpy(d->data + namelen + 1, description); /* Safe */
	d->description = d->data + namelen + 1;
	RWLIST_INSERT_TAIL(&distributions, d, entry);
	return 0;
}

static int distribution_exists(const char *name)
{
	struct distribution *d;
	RWLIST_TRAVERSE(&distributions, d, entry) {
		if (!strcmp(d->name, name)) {
			return 1;
		}
	}
	return 0;
}

static void check_distributions(void)
{
	struct distrib_pat *p;
	/* RFC 6048 2.3.2
	 * All distributions present in distrib.pats list should also be described in the distributions list.
	 * If that is not the case, log a warning.
	 * (Note the RFC explicitly says the distributions list can describe distributions not present in distrib.pats) */
	RWLIST_TRAVERSE(&distrib_pats, p, entry) {
		if (strlen_zero(p->value)) {
			char buf[NNTP_BUFSIZ], *dist, *dists;
			safe_strncpy(buf, p->value, sizeof(buf));
			dists = buf;
			while ((dist = strsep(&dists, ","))) {
				if (!distribution_exists(p->value)) {
					/* This won't break anything, but it's good to have all the distributions we use described */
					bbs_warning("DISTRIB.PATS includes distribution '%s' which is not included in [distributions]\n", p->value);
				}
			}
		}
	}
}

static int add_moderator(const char *wildmat, const char *template)
{
	struct moderator *m;
	size_t patlen, templatelen;
	const char *tmp;

	/* First, check for invalid submission template.
	 * Per RFC 6048 2.4.2, % is not allowed to appear in the template by itself,
	 * except as part of %s, or followed by another % (in which case it is an escape).
	 *
	 * We impose no further restrictions on the submission template.
	 * While RFC 6048 2.4.3 implies that newsgroups differing in name only by . or -
	 * can't use %s in templates, this is not quite true; additionally, %s does
	 * not have to be the sole user part. */
	for (tmp = template; *tmp; tmp++) {
		if (*tmp == '%') {
			tmp++;
			if (*tmp != 's' && *tmp != '%') {
				bbs_error("Malformed moderator submission template '%s'\n", template);
				return -1;
			}
		}
	}

	patlen = strlen(wildmat);
	templatelen = strlen(template);

	m = calloc(1, sizeof(*m) + patlen + templatelen + 2);
	if (ALLOC_FAILURE(m)) {
		return -1;
	}
	strcpy(m->data, wildmat); /* Safe */
	m->wildmat = m->data;
	strcpy(m->data + patlen + 1, template); /* Safe */
	m->template = m->data + patlen + 1;
	RWLIST_INSERT_TAIL(&moderators, m, entry); /* Tail insert is especially critical here as the order of the moderators list is significant */
	return 0;
}

int group_is_poison(const char *grp)
{
	return uwildmat(grp, poisongroups);
}

enum kill_pattern_header {
	KILL_SUBJECT,
	KILL_FROM,
	KILL_MESSAGEID,
	KILL_REFERENCES,
	KILL_XREF,
	KILL_OTHER,
};

struct kill_pattern {
	enum kill_pattern_header hdr;
	const char *otherheader; /* If KILL_OTHER */
	const char *pattern;
	RWLIST_ENTRY(kill_pattern) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(kill_patterns, kill_pattern);

static enum kill_pattern_header parse_killpat_header(const char *h)
{
	if (!strcasecmp(h, "From")) {
		return KILL_FROM;
	} else if (!strcasecmp(h, "Subject")) {
		return KILL_SUBJECT;
	} else if (!strcasecmp(h, "Xref")) {
		return KILL_XREF;
	} else if (!strcasecmp(h, "Message-ID")) {
		return KILL_MESSAGEID;
	} else if (!strcasecmp(h, "References")) {
		return KILL_REFERENCES;
	}
	return KILL_OTHER;
}

static int add_killpat(const char *header, const char *pattern)
{
	struct kill_pattern *k;
	size_t patlen, hdrlen;
	char *data;
	enum kill_pattern_header pathdr = parse_killpat_header(header);

	patlen = STRING_ALLOC_SIZE(pattern);
	hdrlen = pathdr == KILL_OTHER ? STRING_ALLOC_SIZE(header) : 0;

	k = calloc(1, sizeof(*k) + patlen + hdrlen);
	if (ALLOC_FAILURE(k)) {
		return -1;
	}

	k->hdr = pathdr;

	data = k->data;
	SET_FSM_STRING_VAR(k, data, pattern, pattern, patlen);
	if (pathdr == KILL_OTHER) {
		SET_FSM_STRING_VAR(k, data, otherheader, header, hdrlen);
	}
	RWLIST_INSERT_TAIL(&kill_patterns, k, entry);
	return 0;
}

/* =============== Begin ACL Code =============== */

struct reader_acl {
	const char *users; /*!< Wildmat of usernames to which this ACL applies */
	const char *read; /*!< Wildmat of newsgroups for which this ACL allows read access */
	const char *post; /*!< Wildmat of newsgroups for which this ACL authorizes posting */
	int minreadpriv; /*!< Additional minimum privilege required for read access */
	int minpostpriv; /*!< Additional minimum privilege required for post access */
	int minapprovepriv; /*!< Additional minimum privilege required for approving articles (disabled if 0) */
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

static int load_acl(const char *guests, const char *userswm, const char *readwm, const char *postwm, int minreadpriv, int minpostpriv, int minapprovepriv)
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
	acl->minapprovepriv = minapprovepriv;

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
				case NNTP_ACL_APPROVE:
					if (acl->minapprovepriv) { /* If 0, approvals are disabled */
						if (bbs_user_is_registered(nntp->node->user) && nntp->node->user->priv >= acl->minapprovepriv) {
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

static int can_post_at_all(void)
{
	static int computed = 0;
	static int can_post = 0;
	if (!computed) {
		struct reader_acl *acl;
		RWLIST_RDLOCK(&acls);
		RWLIST_TRAVERSE(&acls, acl, entry) {
			if (acl->post) {
				can_post = 1; /* Some ACL allows somebody to post */
				break;
			}
		}
		RWLIST_UNLOCK(&acls);
		computed = 1;
	}
	return can_post;
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
	char *distribution[MAX_ARTICLE_DISTRIBUTIONS]; /* Distributions to accept/reject */
	enum inpeer_type type;
	RWLIST_ENTRY(inpeer) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(inpeers, inpeer);

/*! \brief Split up a comma-separated list into an array of strings */
static inline int split_csv_list(char *s, char **dists, int n)
{
	int i = 0;
	if (!strlen_zero(s)) {
		for (i = 0; s && i < n - 1; i++) {
			char *next;
			next = strsep(&s, ",");
			if (!next) {
				break; /* Done */
			}
			if (!strlen_zero(next)) {
				trim(next);
			}
			if (strlen_zero(next)) {
				continue;
			}
			dists[i] = next;
		}
		if (i == n - 1) { /* Filled up the list */
			bbs_error("Truncation occured (filled up list of size %d)\n", n);
			/* We could return -1, but wouldn't have much to gain by doing that... just return what we have for now */
		}
	}
	dists[i] = NULL; /* Left enough room for the sentinel NULL */
	return i;
}

/*!
 * \brief Whether any of the distributions for a site match a distribution specified in the Distribution header
 * \param dists Distributions for site
 * \param d The distribution in the header to check
 * \retval 1 on positive match, 0 if no match, -1 on negative match
 */
static inline int distribution_wanted(char **dists, const char *d)
{
	char *dist;
	int any_negated = 0; /* Behavior changes depending on whether any of the entries are negated or not */

	for (; (dist = *dists); dists++) {
		if (*dist == '!') {
			any_negated = 1;
			dist++;
			if (!strcasecmp(dist, d)) {
				DIST_DEBUG(5, "Negative match on %s\n", d);
				return 0; /* negative match */
			}
		} else {
			if (!strcasecmp(dist, d)) {
				DIST_DEBUG(5, "Positive match on %s\n", d);
				return 1; /* positive match */
			}
		}
	}

	/* If we saw any negative matches, assume they are all negated distributions and return true (case 3/4) */
	DIST_DEBUG(7, "%s (%s)\n", any_negated ? "Allowing" : "Rejecting", any_negated ? "at least one negated distribution" : "no negated distributions");
	return any_negated;
}

static inline int any_distribution_negated(char **dists)
{
	char *dist;
	for (; (dist = *dists); dists++) {
		if (*dist == '!') {
			return 1;
		}
	}
	return 0;
}

/*!
 * \brief Whether any of the distributions in an article matches against the site
 * \param site The distributions for the peer
 * \param article The distributions from the Distribution header
 * \retval 1 on positive match, 0 if no match, -1 on negative match
 */
static inline int any_distribution_wanted(char **site, char **article)
{
	if (!*site) {
		DIST_DEBUG(8, "Site has no distribution filter, allowing\n");
		return 1; /* Case 0: No distributions explicitly specified for site, so everything matches */
	} else if (!*article) {
		/* If no Distribution header, acceptance depends on whether the site has any negated distributions or not */
		return any_distribution_negated(site);
	}

	for (; *article; article++) {
		if (distribution_wanted(site, *article)) {
			return 1;
		}
	}
	return 0;
}

static int test_distributions(void)
{
	char buf[NNTP_BUFSIZ], buf2[NNTP_BUFSIZ];
	char *hdrdists[MAX_ARTICLE_DISTRIBUTIONS], *sitedists[MAX_ARTICLE_DISTRIBUTIONS];
	int distcount;

	/* Simulate these distributions being in Distribution header of article */
	strcpy(buf, "dist1a,dist2a,dist3a,dist4a,dist5b");
	distcount = split_csv_list(buf, hdrdists, ARRAY_LEN(hdrdists));
	bbs_test_assert_equals(5, distcount);

	/* Now, check if this would match against a few "sites" */
	strcpy(buf2, "!dist1a,!dist2a,!dist3a,!dist4a,!dist5b");
	distcount = split_csv_list(buf2, sitedists, ARRAY_LEN(sitedists));
	bbs_test_assert_equals(5, distcount);
	bbs_test_assert_equals(0, any_distribution_wanted(sitedists, hdrdists)); /* Site explicitly blocks all the article's distributions */

	strcpy(buf2, "!dist6a");
	distcount = split_csv_list(buf2, sitedists, ARRAY_LEN(sitedists));
	bbs_test_assert_equals(1, distcount);
	bbs_test_assert_equals(1, any_distribution_wanted(sitedists, hdrdists)); /* Site only blocks distributions, but not any of the article's, so allowed */

	strcpy(buf2, "dist1,dist2");
	distcount = split_csv_list(buf2, sitedists, ARRAY_LEN(sitedists));
	bbs_test_assert_equals(2, distcount);
	bbs_test_assert_equals(0, any_distribution_wanted(sitedists, hdrdists)); /* Site only wants select distributions, but not any of the article's, so rejected */

	strcpy(buf2, "dist1,dist2a");
	distcount = split_csv_list(buf2, sitedists, ARRAY_LEN(sitedists));
	bbs_test_assert_equals(2, distcount);
	bbs_test_assert_equals(1, any_distribution_wanted(sitedists, hdrdists)); /* Site only wants select distributions, including one of the article's, so allowed */

	/* Simulate these distributions being in Distribution header of article */
	strcpy(buf, "dist1b");
	distcount = split_csv_list(buf, hdrdists, ARRAY_LEN(hdrdists));
	bbs_test_assert_equals(1, distcount);

	/* Now, check if this would match against a few "sites" */
	strcpy(buf2, "!dist1b");
	distcount = split_csv_list(buf2, sitedists, ARRAY_LEN(sitedists));
	bbs_test_assert_equals(1, distcount);
	bbs_test_assert_equals(0, any_distribution_wanted(sitedists, hdrdists)); /* Explicitly denied */

	/* Site that only wants select distributions */
	strcpy(buf2, "dist1");
	distcount = split_csv_list(buf2, sitedists, ARRAY_LEN(sitedists));
	bbs_test_assert_equals(1, distcount);

	strcpy(buf, "");
	distcount = split_csv_list(buf, hdrdists, ARRAY_LEN(hdrdists));
	bbs_test_assert_equals(0, distcount);
	bbs_test_assert_equals(0, any_distribution_wanted(sitedists, hdrdists)); /* Not wanted, because missing Distribution header */

	/* Test site that rejects certain distributions */
	strcpy(buf2, "!dist1,!dist2");
	distcount = split_csv_list(buf2, sitedists, ARRAY_LEN(sitedists));
	bbs_test_assert_equals(2, distcount);

	strcpy(buf, "dist2");
	distcount = split_csv_list(buf, hdrdists, ARRAY_LEN(hdrdists));
	bbs_test_assert_equals(1, distcount);
	bbs_test_assert_equals(0, any_distribution_wanted(sitedists, hdrdists)); /* Distribution explicitly not wanted */

	return 0;

cleanup:
	return -1;
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

/*! \brief Whether we want any of the distributions in this article */
static int we_want_distribution(struct nntp_session *nntp, const char *distribs)
{
	struct inpeer *i;
	char *hdrdists[MAX_ARTICLE_DISTRIBUTIONS];
	char buf[NNTP_BUFSIZ];

	/* Before we start, split up the list of distributions in the header into a series of strings */
	if (!strlen_zero(distribs)) {
		safe_strncpy(buf, distribs, sizeof(buf));
		split_csv_list(buf, hdrdists, ARRAY_LEN(hdrdists));
	} else {
		hdrdists[0] = NULL;
	}

	/* We follow the same rules for Distributions as INN: https://www.eyrie.org/~eagle/software/inn/docs-2.5/newsfeeds.html
	 * This verbiage describes outgoing feeds, but this similarly applies to incoming feeds as well.
	 *
	 * 0) Default is to send all articles to all sites that subscribe to any of the groups where it has been posted
	 * If an article has a Distribution header and any distributions are specified:
	 * 1) If the Distribution: header matches any of the values in the sub-field, the article is sent.
	 * 2) If a distribution starts with an exclamation point, and it matches the Distribution: header, the article is not sent.
	 * 3) If the Distribution: header does not match any distribution in the site's entry and no negations were used, the article is not sent.
	 * 4) If the Distribution: header does not match any distribution in the site's entry and any distribution started with an exclamation point, the article is sent.
	 *    Accordingly, it is almost definitely a mistake to have a single feed that specifies distributions that start with an exclamation point along with some that don't.
	 * If an article has more than one distribution specified, then each one is handled according according to the above rules.
	 * - If any of the specified distributions indicate that the article should be sent, it is; if none do, it is not sent. In other words, the rules are used as a logical or. */

	RWLIST_RDLOCK(&inpeers);
	RWLIST_TRAVERSE(&inpeers, i, entry) {
		if (inpeer_acl_matches(nntp, i)) {
			/* Found a matching inpeer entry (most likely, there is only one, but in theory, there could be multiple) */
			if (any_distribution_wanted(i->distribution, hdrdists)) {
				break;
			}
		}
	}
	RWLIST_UNLOCK(&inpeers);
	return i ? 1 : 0;
}

static int add_inpeer(const char *identity, const char *groups)
{
	struct inpeer *i;
	char *data, *tmp;
	size_t idlen = STRING_ALLOC_SIZE(identity);
	size_t grplen = STRING_ALLOC_SIZE(groups);

	i = calloc(1, sizeof(*i) + idlen + grplen);
	if (ALLOC_FAILURE(i)) {
		return -1;
	}

	data = i->data;
	SET_FSM_STRING_VAR(i, data, identity, identity, idlen);
	tmp = data;
	SET_FSM_STRING_VAR(i, data, groups, groups, grplen);
	tmp = strchr(tmp, '/');
	if (tmp) {
		*tmp++ = '\0';
		split_csv_list(tmp, i->distribution, sizeof(i->distribution));
		if (!*i->distribution) {
			bbs_warning("Empty distribution list ('/' specified but no distributions following\n");
		}
	}

	/* Determine which type of peer it is now, so we don't have to determine it later */
	if (bbs_user_exists(identity)) {
		i->type = INPEER_USERNAME;
	} else {
		i->type = bbs_hostname_is_ipv4(identity) ? INPEER_IPV4 : INPEER_HOSTNAME;
	}
	RWLIST_INSERT_HEAD(&inpeers, i, entry);
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
/* =============== Begin Site Configs =============== */

static RWLIST_HEAD_STATIC(sites, site);

static void free_site(struct site *site)
{
	stringlist_empty(&site->exclusions);
	switch (site->type) {
		case FEED_NNTP:
			feed_nntp_cleanup_feed(site);
			break;
		default:
			__builtin_unreachable();
	}
	free(site);
}

static int parse_site_flags(struct site *site, char *flags)
{
	char *flag;
	while ((flag = strsep(&flags, ","))) {
		long sizeval;
		if (strlen_zero(flag)) {
			continue;
		}
		/*! \todo Expand this to include other options that INN offers: https://github.com/InterNetNews/inn/blob/main/doc/pod/newsfeeds.pod */
		switch (*flag) {
			case '<':
				flag++;
				sizeval = atol(flag);
				if (sizeval < 0) {
					bbs_error("Invalid max size %ld\n", sizeval);
					return -1;
				}
				site->maxsize = (size_t) sizeval;
				break;
			case '>':
				flag++;
				sizeval = atol(flag);
				if (sizeval < 0) {
					bbs_error("Invalid min size %ld\n", sizeval);
					return -1;
				}
				site->minsize = (size_t) sizeval;
				break;
			case 'A':
				/* Checks */
				flag++;
				switch (*flag) {
					case 'p':
						site->exclusionsonly = 1;
						break;
					default:
						bbs_error("Unknown site check (A) '%c'\n", *flag);
						return -1;
				}
				break;
			case 'T':
				/* Type */
				flag++;
				switch (*flag) {
					/*! \todo Add support for at least channel feeds and program feeds as well */
					case 'n':
						site->type = FEED_NNTP;
						site->feed.nntp.port = DEFAULT_NNTP_PORT;
						break;
					default:
						bbs_error("Unknown site type (T) '%c'\n", *flag);
						return -1;
				}
				break;
			case 'W':
				/* What to send */
				flag++;
				switch (*flag) {
					case 'P':
						/*! \todo Not yet implemented (would apply to channel/program feed types) */
						site->sendpath = 1;
						break;
					default:
						bbs_error("Unknown W flag '%c'\n", *flag);
						return -1;
				}
				break;
			default:
				bbs_error("Unknown site flag '%c'\n", *flag);
				return -1;
		}
	}
	return 0;
}

static int parse_feed_nntp_args(struct site *site, char *args)
{
	char *flags = strsep(&args, ":");
	if (!strlen_zero(flags)) {
		char *flag;
		int tmpint;
		while ((flag = strsep(&flags, ","))) {
			if (strlen_zero(flag)) {
				continue;
			}
#define WARN_EXTRANEOUS() \
	if (flag[1]) { \
		bbs_warning("Site %s: Stray arguments after NNTP feed flag %c: %s\n", site->name, *flag, flag + 1); \
	}
			switch (*flag) {
				case 'B':
					tmpint = atoi(flag + 1);
					if (tmpint < 1) {
						bbs_error("Site %s: invalid option for NNTP feed flag B: %s\n", site->name, flag + 1);
					} else {
						site->feed.nntp.batchsize = tmpint;
					}
					break;
				case 'C':
					site->feed.nntp.checkfirst = 1;
					WARN_EXTRANEOUS();
					break;
				case 'D':
					site->feed.nntp.compress = 1;
					WARN_EXTRANEOUS();
					break;
				case 'M':
					site->feed.nntp.modereader = 1;
					WARN_EXTRANEOUS();
					break;
				case 'P':
					site->feed.nntp.post = 1;
					WARN_EXTRANEOUS();
					break;
				case 'Q':
					site->feed.nntp.queue = 1;
					WARN_EXTRANEOUS();
					break;
				case 'S':
					site->feed.nntp.starttls = 1;
					WARN_EXTRANEOUS();
					break;
				default:
					bbs_warning("Site %s: invalid NNTP feed flag '%c'\n", site->name, *flag);
			}
		}
	}
	if (!strlen_zero(args)) {
		struct bbs_url url;
		memset(&url, 0, sizeof(url));
		if (bbs_parse_url(&url, args)) {
			bbs_error("Failed to parse feed arguments '%s'\n", args);
			return -1;
		}
		if (!strcmp(url.prot, "nntp")) {
			site->feed.nntp.secure = 0;
		} else if (!strcmp(url. prot, "nntps")) {
			site->feed.nntp.secure = 1;
		} else {
			bbs_error("Invalid protocol '%s' for NNTP\n", url.prot);
			return -1;
		}

		if (url.host) {
			REPLACE(site->feed.nntp.hostname, url.host);
		}
		if (url.user) {
			REPLACE(site->feed.nntp.username, url.user);
		}
		if (url.pass) {
			REPLACE(site->feed.nntp.password, url.pass);
		}
		if ((site->feed.nntp.username && !site->feed.nntp.password) || (!site->feed.nntp.username && site->feed.nntp.password)) {
			/* We need both a username and password for AUTHINFO so just one of them is no good */
			bbs_error("Either both username/password or neither must be specified\n");
			return -1;
		}
		if (url.port) {
			site->feed.nntp.port = url.port;
		}
	}
	bbs_mutex_init(&site->feed.nntp.lock, NULL);
	return 0;
}

static int add_site(const char *key, const char *value)
{
	struct site *site;
	char keybuf[NNTP_MAX_LINE_LENGTH];
	char valbuf[NNTP_LARGE_WILDMAT_BUFSIZ];
	char *k, *v, *data;
	char *name, *exclusions;
	char *groups, *flags, *args;
	size_t namelen, grouplen;
	char *tmp;

	safe_strncpy(keybuf, key, sizeof(keybuf));
	safe_strncpy(valbuf, value, sizeof(valbuf));
	k = keybuf;
	v = valbuf;

	name = strsep(&k, "/");
	exclusions = k;

	groups = strsep(&v, ":"); /* groups/dists */
	flags = strsep(&v, ":");
	args = v;

	if (strlen_zero(name)) {
		bbs_error("Missing site name\n");
		return -1;
	} else if (strlen_zero(groups)) {
		bbs_error("Missing site's group patterns\n");
		return -1;
	} else if (strlen_zero(flags)) {
		bbs_error("Missing site flags\n");
		return -1;
	}

	namelen = STRING_ALLOC_SIZE(name);
	grouplen = STRING_ALLOC_SIZE(groups);

	RWLIST_TRAVERSE(&sites, site, entry) {
		if (!strcmp(site->name, name)) {
			/* The same site COULD be added multiple times, but it must be named differently */
			bbs_error("Site '%s' duplicated in config, not adding\n", name);
			return -1;
		}
	}

	site = calloc(1, sizeof(*site) + namelen + grouplen);
	if (ALLOC_FAILURE(site)) {
		return -1;
	}

	if (!strlen_zero(exclusions)) {
		stringlist_push_list(&site->exclusions, exclusions);
	}

	/* Load strings */
	data = site->data;
	SET_FSM_STRING_VAR(site, data, name, name, namelen);
	tmp = data;
	SET_FSM_STRING_VAR(site, data, groups, groups, grouplen);
	tmp = strchr(tmp, '/');
	if (tmp) {
		*tmp++ = '\0';
		split_csv_list(tmp, site->dists, sizeof(site->dists));
		if (!*site->dists) {
			bbs_error("Empty distribution list ('/' specified but no distributions following\n");
			goto abort;
		}
	}

	/* Parse flags */
	if (parse_site_flags(site, flags)) {
		goto abort;
	} else if (site->type == FEED_UNKNOWN) {
		bbs_error("Feed type not configured for site '%s'\n", name);
		goto abort;
	}

	/* Parse any args, depending on feed type */
	if (!strlen_zero(args)) {
		switch (site->type) {
			case FEED_NNTP:
				if (parse_feed_nntp_args(site, args)) {
					goto abort2;
				}
				break;
			case FEED_UNKNOWN:
				__builtin_unreachable(); /* We aborted above already */
		}
	}

	RWLIST_INSERT_TAIL(&sites, site, entry);
	return 0;

abort:
	free(site);
	return -1;

abort2:
	free_site(site);
	return -1;
}

/*! \brief Send an article to a site (or at least, initiate sending) */
static int site_send(struct article_info *artinfo, struct site *site)
{
	switch (site->type) {
		case FEED_NNTP:
			return feed_nntp_send(artinfo, site);
		case FEED_UNKNOWN:
			__builtin_unreachable();
	}
	__builtin_unreachable();
}

static int site_flush(struct site *site)
{
	switch (site->type) {
		case FEED_NNTP:
			return feed_nntp_flush(site);
		case FEED_UNKNOWN:
			__builtin_unreachable();
	}
	__builtin_unreachable();
}

static int cli_feedflush(struct bbs_cli_args *a)
{
	struct site *site;
	int c = 0;
	const char *name = a->argc >= 3 ? a->argv[2] : NULL;

	RWLIST_RDLOCK(&sites);
	RWLIST_TRAVERSE(&sites, site, entry) {
		if (name && strcmp(name, site->name)) {
			continue;
		}
		if (!site_flush(site)) {
			bbs_dprintf(a->fdout, "Flushing articles for site %s\n", site->name);
			c++;
		}
	}
	RWLIST_UNLOCK(&sites);
	if (!c) {
		bbs_dprintf(a->fdout, "Could not flush articles for any sites\n"); /* Normal, if no articles are in queue */
	}
	return 0;
}

static int sites_init_feed_types(void)
{
	/* FEED_NNTP */
	if (feed_nntp_init()) {
		return -1;
	}
	return 0;
}

static void sites_cleanup_feed_types(void)
{
	feed_nntp_shutdown();
}

static int sites_init_feeds(void)
{
	struct site *site;

	RWLIST_RDLOCK(&sites);
	RWLIST_TRAVERSE(&sites, site, entry) {
		switch (site->type) {
			case FEED_NNTP:
				feed_nntp_init_feed(site);
				break;
			case FEED_UNKNOWN:
				__builtin_unreachable();
		}
	}
	RWLIST_UNLOCK(&sites);
	return 0;
}

/* Feed stats */
static bbs_rwlock_t statlock = BBS_RWLOCK_INITIALIZER;
struct site_feed_stats overallstats; /* For all sites combined */

void nntp_feed_add_stats(struct site *site, struct site_feed_stats *s)
{
	bbs_rwlock_wrlock(&statlock);

	/* This function is called by nntp_feed_nntp.c, so the site won't go away while we're using it, even though sites isn't locked here */
	if (site->type == FEED_NNTP) {
		site->feed.nntp.stats.offered += s->offered;
		site->feed.nntp.stats.accepted += s->accepted;
		site->feed.nntp.stats.refused += s->refused;
		site->feed.nntp.stats.rejected += s->rejected;
		site->feed.nntp.stats.accsize += s->accsize;
	} else {
		bbs_assert(0);
	}

	overallstats.offered += s->offered;
	overallstats.accepted += s->accepted;
	overallstats.refused += s->refused;
	overallstats.rejected += s->rejected;
	overallstats.accsize += s->accsize;

	bbs_rwlock_unlock(&statlock);
}

static inline void print_feedstats(struct bbs_cli_args *a, const char *name, int backlog, struct site_feed_stats *s)
{
	bbs_dprintf(a->fdout, "%-25s %8d %8d %8d %8d %8d %15lu\n", name, backlog, s->offered, s->accepted, s->refused, s->rejected, s->accsize);
}

static int cli_feedstats(struct bbs_cli_args *a)
{
	struct site *site;
	int c = 0, total_backlog = 0;
	const char *name = a->argc >= 3 ? a->argv[2] : NULL;

	bbs_rwlock_rdlock(&statlock);
	RWLIST_RDLOCK(&sites);
	RWLIST_TRAVERSE(&sites, site, entry) {
		if (name && strcmp(name, site->name)) {
			continue;
		}
		if (site->type != FEED_NNTP) { /* At the moment, the only feeds with stats */
			continue;
		}
		if (!c++) {
			/* Print the header */
			bbs_dprintf(a->fdout, "%-25s %8s %8s %8s %8s %8s %15s\n", "Site", "Backlog", "Offered", "Accepted", "Refused", "Rejected", "AcceptedSize");
		}
		print_feedstats(a, site->name, site->feed.nntp.backlogcount, &site->feed.nntp.stats);
		total_backlog += site->feed.nntp.backlogcount;
	}
	RWLIST_UNLOCK(&sites);
	if (c) {
		/* End with the global stats */
		print_feedstats(a, "(Overall)", total_backlog, &overallstats);
	}
	bbs_rwlock_unlock(&statlock);
	if (!c) {
		if (name) {
			/* We wanted a specific site, but didn't find it */
			bbs_dprintf(a->fdout, "No such feed site '%s'\n", name);
		} else {
			bbs_dprintf(a->fdout, "No feed sites configured\n");
		}
		return -1;
	}
	return 0;
}

/* =============== End Site Configs =============== */
/* =============== Begin Article Propagation =============== */

static int _path_contains_site(const char *path, const char *site, size_t sitelen, int posted_only)
{
	/* Parse the string in place so we don't need to make a copy, e.g. strsep(&s, "!") */
	const char *nextbang;
	for (;;) {
		size_t thissitelen;
		nextbang = strchr(path, '!');
		if (!nextbang) {
			/* This is the last site */
			return !strcasecmp(path, site);
		}

		while (*path == ' ') {
			path++; /* For multi-line Path headers, we may need to eat spaces first wherever the header wrapped */
		}

		/* Check if this is the site of interest */
		thissitelen = (size_t) (nextbang - path);
		/* If the lengths aren't equal, don't even bother comparing, can't match. */
		if (thissitelen == sitelen || (thissitelen == sitelen + 1 && path[sitelen] == ' ')) {
			/* If the Path header had to be wrapped and we are searching for a site identity at the end of a line,
			 * then a single space exists where the header folder; this is still a match. */
			if (!strncasecmp(path, site, sitelen)) {
				return 1;
			}
		}
		/* If we are checking if a site has received an article, we may want to ignore everything
		 * after .POSTED as malicious clients could falsely insert sites into the path before injection (RFC 5537 6.2) */
		if (posted_only && !strncmp(path, ".POSTED", STRLEN(".POSTED"))) { /* .POSTED could be followed by . and an FQDN/IP */
			return 0;
		}

		/* Update for the next site */
		path = nextbang + 1;
		if (strlen_zero(path)) {
			return 0; /* End of string */
		}
	}
}
#define path_contains_site(path, site) _path_contains_site(path, site, strlen(site), 1)

/*! \retval -1 for poison match, 0 if no match, 1 for positive match */
static int list_match(const char *wildmat, char **items)
{
	char *item;
	int want = 0;
	for (item = *items; (item = *items); items++) {
		int res = uwildmat_poison(item, wildmat);
		if (res == -1) {
			return -1; /* If any item is poison, then the article is poisoned for this site, even if other items would match */
		}
		if (res == 1) {
			/* Assuming there are no poison matches, this will match */
			want = 1;
		}
	}
	return want;
}

static int test_poison(void)
{
	char buf[NNTP_BUFSIZ];
	char *items[MAX_ARTICLE_GROUPS];

	strcpy(buf, "comp.test");
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(1, list_match("*,!foo.*,@*.poison,misc.poison", items));

	strcpy(buf, "foo.bar");
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(0, list_match("*,!foo.*,@*.poison,misc.poison", items));

	strcpy(buf, "foo.poison");
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(-1, list_match("*,!foo.*,@*.poison,misc.poison", items));

	strcpy(buf, "baz.poison");
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(-1, list_match("*,!foo.*,@*.poison,misc.poison", items));

	strcpy(buf, "misc.poison");
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(1, list_match("*,!foo.*,@*.poison,misc.poison", items));

	strcpy(buf, "test.foo,test.foo2");
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(1, list_match("*,@*.bina*,@*.bain*,@*.dateien*,@*.pictures*,!local*,!junk/!local", items));

	strcpy(buf, "test.foo,alt.binaries.foo,test.foo2"); /* Add a poison group, and the whole article should get poisoned for this site */
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(-1, list_match("*,@*.bina*,@*.bain*,@*.dateien*,@*.pictures*,!local*,!junk/!local", items));

	strcpy(buf, "test.foo,local.foo"); /* 1 group that would match on its own, 1 group that would not match on its own = should match */
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(1, list_match("*,@*.bina*,@*.bain*,@*.dateien*,@*.pictures*,!local*,!junk/!local", items));

	strcpy(buf, "local.foo"); /* 1 group that would match on its own, 1 group that would not match on its own = should match */
	split_csv_list(buf, items, ARRAY_LEN(items));
	bbs_test_assert_equals(0, list_match("*,@*.bina*,@*.bain*,@*.dateien*,@*.pictures*,!local*,!junk/!local", items));

	return 0;

cleanup:
	return -1;
}

static int site_wants_article(struct article_info *artinfo, char **artgrps, char **artdists, struct site *site)
{
	int res;

	/* Not wanted, if site already saw this article:
	 * We SHOULD NOT relay articles if path identity of receiving agent (or a known alias thereof)
	 * appears as a path identity, excluding within tail entry or following .POSTED (RFC 5537 3.6). */
	if (!site->exclusionsonly && path_contains_site(artinfo->path, site->name)) {
		return 0; /* Path contains site name */
	} else {
		/* Check exclusions/aliases for matches also/instead */
		struct stringitem *i = NULL;
		const char *exclusion;
		while ((exclusion = stringlist_next(&site->exclusions, &i))) {
			if (path_contains_site(artinfo->path, exclusion)) {
				return 0;
			}
		}
	}

	/* Check newsgroups */
	res = list_match(site->groups, artgrps);
	if (res != 1) {
		return 0;
	}

	/* Check distributions */
	res = any_distribution_wanted(site->dists, artdists);
	if (res != 1) {
		return 0;
	}

	/* If good so far, check for any other filters that preclude this site */
	if (site->maxsize && artinfo->bytes >= site->maxsize) {
		return 0; /* Too big for site */
	} else if (site->minsize && artinfo->bytes <= site->minsize) {
		return 0; /* Too small for site */
	}

	return 1; /* Looks like the site wants it! */
}

static int propagate_article(struct article_info *artinfo)
{
	/* Because this is all running in a single-process environment,
	 * we can't simply use the site structures like INN does.
	 * Instead, we need to keep a copy of all the sites. */
	struct site *site;
	int total = 0, sent = 0;
	char grpbuf[4 * NNTP_MAX_LINE_LENGTH], distbuf[4 * NNTP_MAX_LINE_LENGTH];
	char *artgrps[MAX_ARTICLE_GROUPS];
	char *artdists[MAX_ARTICLE_DISTRIBUTIONS];

	if (ALLOC_FAILURE(artinfo->xref)) {
		/* nntp_spool_trad duplicates the Xref value here, but no check for failure is done until now.
		 * If missing, abort in case we wanted to send Xref to a site and consequently can't. */
		return -1;
	}

	/* Parse the Newsgroups and Distribution header into a list of strings */
	safe_strncpy(grpbuf, artinfo->newsgroups, sizeof(grpbuf));
	split_csv_list(grpbuf, artgrps, ARRAY_LEN(artgrps));
	if (artinfo->distribution) {
		safe_strncpy(distbuf, artinfo->distribution, sizeof(distbuf));
		split_csv_list(distbuf, artdists, ARRAY_LEN(artdists));
	} else {
		artdists[0] = NULL;
	}

	/* First, check what sites want this article */
	RWLIST_RDLOCK(&sites);
	RWLIST_TRAVERSE(&sites, site, entry) {
		total++;
		if (site_wants_article(artinfo, artgrps, artdists, site)) {
			/* If it matches, trigger delivery of the article to this site */
			site_send(artinfo, site);
			sent++;
		}
	}
	RWLIST_UNLOCK(&sites);

	if (sent) {
		bbs_debug(3, "Propagated article %s to %d/%d site%s\n", artinfo->messageid, sent, total, ESS(total));
	}
	return 0;
}

/* =============== End Article Propagation =============== */

void artinfo_reset(struct article_info *artinfo)
{
	free_if(artinfo->filepath);

	free_if(artinfo->newsgroups);
	free_if(artinfo->distribution);
	free_if(artinfo->path);
	free_if(artinfo->organization);
	free_if(artinfo->injectioninfo);
	free_if(artinfo->injectiondate);
	free_if(artinfo->xref);
	free_if(artinfo->approved);
	free_if(artinfo->control);
	free_if(artinfo->expires);

	free_if(artinfo->subject);
	free_if(artinfo->from);
	free_if(artinfo->date);
	free_if(artinfo->messageid);
	free_if(artinfo->references);
	artinfo->bytes = 0;
	artinfo->lines = 0;

	artinfo->prepend = NULL;
	artinfo->append = NULL;
	artinfo->prependlen = 0;
	artinfo->appendlen = 0;
	artinfo->nntp_posting_host_set = 0;
	artinfo->needinjectiondate = 0;
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
}

#define REQUIRE_ARGS(s) \
	if (strlen_zero(s)) { \
		nntp_send(nntp, NNTP_ERR_SYNTAX, "Arguments required"); \
		return 0; \
	}

#define REQUIRE_NO_ARGS(s) \
	if (!strlen_zero(s)) { \
		nntp_send(nntp, NNTP_ERR_SYNTAX, "Syntax is: %s (no argument allowed)\r\n", command); \
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

int group_create(const char *groupname, const char *status, const char *creator, const char *description)
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

int group_exists(const char *groupname)
{
	int res;

	bbs_rwlock_rdlock(&nntp_lock);
	/* For the moment, with the existing implementations,
	 * querying the tradspool for directory existence is simpler (faster?)
	 * than scanning the active file.
	 * Once we have a hash table mapping groups to offsets in the active file,
	 * adding an active_group_exists variant would probably be better. */
	res = spool_group_exists(groupname);
	if (res) {
		/* There is an edge case here, groups that themselves contain other groups
		 * (since we mirror the hierarchy in the way folders are created).
		 * e.g. if we carry test.foo.bar but not test.foo, the directory test.foo
		 * will still exist, even though test.foo isn't in the active file, which is the "real" source of truth.
		 * Thus, if the directory doesn't exist, we don't carry it, but just because it does, doesn't mean we do.
		 * If an .overview file is present in the directory, then it's a real group (though we can't check that from outside nntp_spool_trad.c)
		 * If not, then we have to query the active file after all. */
		res = active_group_info(groupname, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, 0);
		res = !res ? 1 : 0;
	}
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

/* group_update_count needs to be called by tradspool_delete_article_single after it deletes an article,
 * but since we're already locked there, we have variants here that are already locked */
static int __group_update_locked(const char *groupname, int *incrlast, int last, int high, int low, int count, const char *status, const char *description)
{
	struct group_info g;

	g.name = groupname;
	g.last = last;
	g.high = high;
	g.low = low;
	g.count = count;
	g.status = status;
	g.description = description;
	/* Don't need to set created and creator, as those can't change and are just copied from the old on updates */

	return active_group_update(&g, incrlast);
	/*! \todo If status/description change, need to send control message to other servers with new status and description? */
}

static int __group_update(const char *groupname, int *incrlast, int last, int high, int low, int count, const char *status, const char *description)
{
	int res;
	bbs_rwlock_wrlock(&nntp_lock);
	res = __group_update_locked(groupname, incrlast, last, high, low, count, status, description);
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

static int group_update_status_description(const char *groupname, const char *status, const char *description)
{
	return __group_update(groupname, NULL, -1, -1, -1, -1, status, description);
}

int group_update_counts_locked(const char *groupname, int high, int low, int count)
{
	return __group_update_locked(groupname, NULL, -1, high, low, count, NULL, NULL);
}

/*!
 * \brief Assign an article number for the next article in this group
 * \param groupname
 * \param[in/out] article_num Will be set to the next article number, or 0 if the group is full. Pass in 0 to auto-assign article number or requested article number otherwise (for xrefslave)
 * \retval 0 on success, nonzero on error
 * \note Must be called locked
 */
int group_assign_article_number_locked(const char *groupname, int *restrict article_num, int *restrict last)
{
	struct group_info g;
	int res;

	g.name = groupname;
	g.last = -1;
	g.high = -1;
	g.low = -1;
	g.count = -1;
	g.status = NULL;
	g.description = NULL;

	/* The active file will also increment the count for us (and low/high water marks as appropriate) when it assigns the article number */
	res = active_group_update(&g, article_num); /* Call active_group_update directly instead of using __group_update_locked so that we can get last */
	*last = g.last;
	return res;
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
	int res = active_group_info(groupname, last, high, low, count, NULL, 0, NULL, NULL, 0, NULL, 0);
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

static int group_get_status(const char *groupname, char *status, size_t statuslen)
{
	int res;
	bbs_rwlock_rdlock(&nntp_lock);
	res = active_group_info(groupname, NULL, NULL, NULL, NULL, status, statuslen, NULL, NULL, 0, NULL, 0);
	bbs_rwlock_unlock(&nntp_lock);
	return res;
}

#define VALID_POSTING_STATUS(s) (*s == 'y' || *s == 'n' || *s == 'm' || *s == 'x' || *s == 'j' || (*s == '=' && valid_newsgroup_name(s + 1)))

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
	 * and groups can be nested within other groups.
	 * The valid characters come from RFC 5536 3.1.4 */
	return valid_field(s, ".-+_", NNTP_MAX_ARG_LENGTH) && !isdigit(*s); /* The max arg length is a ridiculously long limit, but it's the only one we have */
}

/*!
 * \brief Create a newsgroup on this server (either a new group in the news network, or instantiate an existing group on this server for the first time)
 *        The directory for articles will be created, and the newsgroup metadata will be added to all necessary metadata files.
 * \param name The name of the newsgroup.
 * \param description A short description about the purpose of the group
 * \param creator Entity that created the newsgroup; may be an email address (though not necessarily, often just 'usenet' in many Usenet groups)
 * \param status The current status of the group on this server.
 * \retval 0 Group created successfully
 * \retval 1 Group already exists
 * \retval -1 Error creating group
 */
static int newgroup(const char *name, const char *description, const char *creator, const char *status)
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
	} else if (!valid_field(description, " ,.-+()", NNTP_MAX_ARG_LENGTH)) {
		bbs_error("Newsgroup description '%s' is invalid\n", S_IF(description));
		return -1;
	} else if (!valid_field(creator, " ,.<>@-+()", NNTP_MAX_ARG_LENGTH)) {
		bbs_error("Newsgroup creator '%s' is invalid\n", S_IF(creator));
		return -1;
	} else if (!VALID_POSTING_STATUS(status)) {
		bbs_error("Illegal posting setting '%s'\n", status);
		return -1;
	}

	res = group_create(name, status, creator, description);
	if (!res) {
		bbs_verb(4, "Created newsgroup %s (%s)\n", name, description);
	}
	return 0;
}

struct group_list {
	const char *name;
	const char *description;
} builtin_groups[] =
{
	{ "control", "Various control messages (no posting)." },
	{ "control.cancel", "Cancel messages (no posting)." },
	{ "control.checkgroups", "Hierarchy check control messages (no posting)." },
	{ "control.newgroup", "Newsgroup creation control messages (no posting)." },
	{ "control.rmgroup", "Newsgroup removal control messages (no posting)." },
	{ "junk", "Unfiled articles (no posting)." },
};

static int is_builtin_group(const char *name)
{
	int i;
	for (i = 0; ARRAY_LEN(builtin_groups); i++) {
		if (!strcmp(name, builtin_groups[i].name)) {
			return 1;
		}
	}
	return 0;
}

static int init_builtin_groups(void)
{
	int res = 0;
	size_t i;
	for (i = 0; i < ARRAY_LEN(builtin_groups); i++) {
		if (!group_exists(builtin_groups[i].name)) {
			res |= newgroup(builtin_groups[i].name, builtin_groups[i].description, "BBS", "n"); /* Built-in groups do not allowed local posts */
		}
	}
	return res;
}

static int cli_newgroup(struct bbs_cli_args *a)
{
	char name[128];
	char description[256];
	char creator[64];
	char posting[128];
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

	res = newgroup(name, description, creator, posting);
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

	if (is_builtin_group(name)) {
		bbs_dprintf(a->fdout, "Can't remove '%s' (builtin group)\n", name);
		return -1;
	}

	res = group_delete(name);
	if (res) {
		bbs_dprintf(a->fdout, "Error occured deleting newsgroup '%s'\n", name);
		return -1;
	}

	bbs_dprintf(a->fdout, "Deleted newsgroup %s (manually delete %s/%s)\n", name, newsdir, name);
	return 0;
}

static int cli_setstatus(struct bbs_cli_args *a)
{
	/* Posting status needs to be valid and must only be one character */
	if (!VALID_POSTING_STATUS(a->argv[3]) || a->argv[3]) {
		bbs_dprintf(a->fdout, "Invalid posting status (should be y/n/m/x/j/=other.group)\n");
		return -1;
	}
	/* Update posting status, don't change the low or high water marks */
	if (group_update_status_description(a->argv[2], a->argv[3], NULL)) {
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

static pthread_t expire_thread;
static int expire_done = 0;

static void *do_expiration(void *varg)
{
	char *group = varg;
	int res = history_expire(group); /* OK if group is NULL */
	free_if(group);
	if (res < 0) {
		bbs_warning("Failed to expire articles\n");
	} else {
		bbs_verb(5, "Expired %d news article%s\n", res, ESS(res));
	}
	expire_done = 1;
	return NULL;
}

static int cli_expire(struct bbs_cli_args *a)
{
	const char *group = a->argv[2];
	char *varg = group ? strdup(group) : NULL;
	if (expire_thread) {
		if (!expire_done) {
			bbs_dprintf(a->fdout, "Expiration already in progress\n");
			return -1;
		}
		bbs_pthread_join(expire_thread, NULL);
	}
	if (bbs_pthread_create(&expire_thread, NULL, do_expiration, varg)) {
		free_if(varg);
		bbs_dprintf(a->fdout, "Failed to expire articles\n");
		return -1;
	}
	bbs_dprintf(a->fdout, "Started expiration task\n");
	return 0;
}

static int cli_fgexpire(struct bbs_cli_args *a)
{
	const char *group = a->argv[2];
	int res = history_expire(group); /* OK if group is NULL */
	if (res < 0) {
		bbs_dprintf(a->fdout, "Failed to expire articles\n");
		return -1;
	}
	bbs_dprintf(a->fdout, "Expired %d news article%s\n", res, ESS(res));
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

	safe_strncpy(dup_addr, fromaddr, sizeof(dup_addr));
	if (bbs_parse_email_address(dup_addr, &name, &user, &domain)) {
		return 0;
	}

	/* Newsgroups need a full email address */
	if (!user || !domain) {
		return 0;
	}

	/* If it ends in ".invalid", then this is the anonymous poster exception in RFC 5537 3.4 */
	if (allow_invalid && bbs_str_ends_with(domain, ".invalid")) {
		return 1;
	}

	/* We can't check identity if user isn't logged in */
	if (!bbs_user_is_registered(nntp->node->user)) {
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

void free_article_groups(struct article_groups *groups)
{
	struct article_group *g;
	while ((g = BBS_LIST_REMOVE_HEAD(groups, entry))) {
		free(g);
	}
}

int article_groups_contains(struct article_groups *groups, const char *name)
{
	struct article_group *g;
	BBS_LIST_TRAVERSE(groups, g, entry) {
		if (!strcasecmp(g->name, name)) {
			return 1;
		}
	}
	return 0;
}

int article_groups_add(struct article_groups *groups, const char *name)
{
	struct article_group *g = calloc(1, sizeof(*g) + strlen(name) + 1);
	if (ALLOC_FAILURE(g)) {
		return -1;
	}
	strcpy(g->data, name); /* Safe */
	g->name = g->data;
	BBS_LIST_INSERT_TAIL(groups, g, entry);
	return 0;
}

static int construct_moderator_address(const char *group, const char *template, char *buf, size_t len)
{
	do {
		if (*template == '%') {
			template++;
			if (*template == 's') {
				/* Copy the group name in place of '%s', replacing '.' with '-' */
				const char *g = group;
				while (*g) {
					if (*g == '.') {
						*buf++ = '-';
					} else {
						*buf++ = *g;
					}
					g++;
					if (unlikely(!--len)) {
						return -1;
					}
				}
				template++;
				continue;
			} /* else, should be a literal '%', we verified this when loading the config */
		}
		*buf++ = *template++;
		if (unlikely(!--len)) {
			return -1;
		}
	} while (*template);
	*buf = '\0';
	return 0;
}

static int test_moderator_templates(void)
{
	char buf[48];
	bbs_test_assert_equals(0, construct_moderator_address("test.misc", "%s@example.com", buf, sizeof(buf)));
	bbs_test_assert_str_equals("test-misc@example.com", buf);
	bbs_test_assert_equals(0, construct_moderator_address("test.misc", "test+%s@example.com", buf, sizeof(buf)));
	bbs_test_assert_str_equals("test+test-misc@example.com", buf);
	bbs_test_assert_equals(0, construct_moderator_address("test.misc", "test@example.com", buf, sizeof(buf)));
	bbs_test_assert_str_equals("test@example.com", buf);
	bbs_test_assert_equals(-1, construct_moderator_address("test.misc", "test@template.that.is.too.long.for.buffer.example.com", buf, sizeof(buf)));
	return 0;

cleanup:
	return -1;
}

static int build_moderator_address(const char *group, char *buf, size_t len)
{
	struct moderator *m;
	int res = -1;
	RWLIST_RDLOCK(&moderators);
	RWLIST_TRAVERSE(&moderators, m, entry) {
		/* First match wins */
		if (uwildmat(group, m->wildmat)) {
			res = construct_moderator_address(group, m->template, buf, len);
			break;
		}
	}
	RWLIST_UNLOCK(&moderators);
	return res;
}

static int process_moderated_group(const char *name, const char *filename)
{
	char modaddr[256];
	char template[TMPNAME_BUFSIZ];
	char buf[NNTP_MAX_LINE_LENGTH + 1];
	char sender[256];
	FILE *newfp, *artfp;
	int res = -1;

	/* First, determine the moderator address */
	if (build_moderator_address(name, modaddr, sizeof(modaddr))) {
		return -1;
	}

	/* Prepend To to the received article, and send it to the moderator, simple as that!
	 * (This is method #2 in RFC 5537 3.5.1) */
	bbs_renamable_tempname("nntpmod", template, sizeof(template));
	artfp = fopen(filename, "r");
	if (!artfp) {
		bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
		return -1;
	}
	newfp = bbs_mkftemp(template, 0600);
	if (!newfp) {
		fclose(artfp);
		return -1;
	}
	fprintf(newfp, "To: %s\r\n", modaddr);
	/* Can't use bbs_copy_file, even though it would be super-elegant here,
	 * the source article retained its dot-stuffing, and we need to unstuff it here
	 * (even though, ultimately, it may get stuffed again if it goes out SMTP) */
	while ((fgets(buf, sizeof(buf), artfp))) {
		const char *line = buf;
		if (buf[0] == '.') {
			line++;
		}
		fprintf(newfp, "%s", line); /* Includes CR LF already */
	}
	fclose(newfp);
	/* XXX We should prefer newsname, if it's a valid domain for sending email, or smtp_hostname(), should that fail;
	 * bbs_hostname() is only used here to avoid a hard dependency on net_smtp */
	snprintf(sender, sizeof(sender), "%s@%s", "moderator-submissions", bbs_hostname()); /* Construct envelope sender */
	res = bbs_mail_message(template, sender, NULL);

	fclose(artfp);
	unlink(template);
	return res;
}

static void log_article(struct nntp_session *nntp, int streaming, size_t rxbytes, const char *messageid, char code, const char *text)
{
	time_t now;
	struct timeval tvnow;
	char buf[26];

	if (unlikely(messageid == NULL)) {
		return; /* Would only happen for certain rejected posts from readers, which we don't care about so much anyways */
	}

#define LOG_REJECT '-'
#define LOG_ACCEPT '+'
#define LOG_JUNK 'j'
#define LOG_DUPLICATE 'c'
#define LOG_DEFER 'd'

#pragma GCC diagnostic ignored "-Waggregate-return"
	tvnow = bbs_tvnow();
#pragma GCC diagnostic pop

	now = time(NULL);
	ctime_r(&now, buf);
	/* No locking needed, fprintf will properly interleave writes */
	if (nntp->mode == NNTP_MODE_READER) {
		/* We log posts separately so that articles from peers and readers can be logged/rotated separately.
		 * Normally, we would expect to get a lot of articles from peers but not as many from readers,
		 * so this allows retention of reader logs longer in case we need them to figure out
		 * who posted something after an article expired.
		 *
		 * Accordingly, include authenticated user so we have a record of who posted what if needed (even after articles expire).
		 * We also include the thread ID since that is what gets logged in the logging-data parameter in Injection-Info. */
		fprintf(postlog, "%.15s.%03d %c %c %s %d %s %lu %s%s%s\n", buf + 4, (int) (tvnow.tv_usec / 1000),
			code, 'R', nntp->node->ip, bbs_gettid(),
			nntp->mode == NNTP_MODE_READER ? bbs_username(nntp->node->user) : "-",
			rxbytes, messageid, text ? " " : "", S_IF(text));
	} else {
		fprintf(newslog, "%.15s.%03d %c %c %s %d %lu %s%s%s\n", buf + 4, (int) (tvnow.tv_usec / 1000),
			code, streaming ? 'S' : 'T', nntp->node->ip, bbs_gettid(),
			rxbytes, messageid, text ? " " : "", S_IF(text));
	}
}

/*! \brief Whether a client (reader or peer) can post to a group based on its status */
static int status_allows_posting(struct nntp_session *nntp, const char *newsgroup, const char *status, char *errbuf, size_t errbuflen)
{
	/*
	 * Posting statuses, as defined by RFC 3977 and extended by RFC 6048 Section 3:
	 *
	 * Posts allowed from:
	 * y = Both
	 * n = Peers, but not readers
	 * m = Both (moderated)
	 * x = Neither (i.e. group is closed)
	 * j = Peers, but not readers
	 *     Differs from 'n' as:
	 *     - articles from peers crossposted to at least one valid group are filed only into the valid groups
	 *     - articles from peers not crossposted to any valid groups are not filed into any newsgroup, but still propagated to other peers, if appropriate
	 *       - may be filed into a catch-all group named "junk"
	 *         - if "junk" exists, it contains all posts not filed in another group, regardless of the status of "junk" (explicit posts to "junk" respect its status as usual)
	 *         - "junk" may be available to readers and often used to store articles that will be transmitted to peers
	 *         - this allows accepting articles with invalid/foreign newsgroups and filing in "junk"
	 * =other.group = Peers, but not readers; alias to another group
	 *     - groups are distinct (articles/article numbers not shared)
	 *     - posts accepted and filed into aliased group (Newsgroup header remains unchanged)
	 *     - typically used during transition between two groups (e.g. rename)
	 *     - status of alias target MUST NOT be taken into account, so aliases SHOULD NOT point to moderated groups
	 *     - aliases SHOULD NOT point to themselves or other alias groups
	 *     - alias target SHOULD exist and be visible to clients that can see original group (e.g. same permissions)
	 *
	 * "j" and "=junk" are different; if crossposting:
	 * - "j" -> article is filed in "junk" only if there are no other valid groups
	 * - "=junk" -> article is always filed in "junk", along with any other valid groups
	 */
	switch (*status) {
		case 'm': /* May need to be moderated, but continue for now */
		case 'y':
			return 1;
		case '=':
			if (nntp->mode == NNTP_MODE_TRANSIT) {
				return 1;
			}
			snprintf(errbuf, errbuflen, "The newsgroup \"%s\" has been renamed to \"%s\"", newsgroup, status + 1);
			return 0;
		case 'n':
		case 'j':
			if (nntp->mode == NNTP_MODE_TRANSIT) {
				return 1;
			}
			/* Fall through */
		case 'x':
			snprintf(errbuf, errbuflen, "Postings to \"%s\" not allowed here", newsgroup);
			return 0;
		default:
			bbs_error("Invalid status for group: '%s'\n", status);
			return 0;
	}
}

enum nntp_control_msg {
	CMSG_UNKNOWN,
	CMSG_NEWGROUP,
	CMSG_RMGROUP,
	CMSG_CHECKGROUPS,
	CMSG_CANCEL,
};

static enum nntp_control_msg parse_cmsg(const char *s)
{
	/* We use starts with here instead of strcasecmp, so that we can parse even when the string hasn't been split up into tokens yet */
	if (STARTS_WITH(s, "newgroup")) {
		return CMSG_NEWGROUP;
	} else if (STARTS_WITH(s, "rmgroup")) {
		return CMSG_RMGROUP;
	} else if (STARTS_WITH(s, "checkgroups")) {
		return CMSG_CHECKGROUPS;
	} else if (STARTS_WITH(s, "cancel")) {
		return CMSG_CANCEL;
	} else {
		return CMSG_UNKNOWN;
	}
}

static int article_too_new(struct article_info *artinfo)
{
	/* Reject any proto-articles dated too far in the future.
	 * We use Injection-Date if it is present and Date otherwise (RFC 5537 3.6)
	 * We MUST reject articles dated further than 24 hours in the future and MAY use a smaller margin than that (RFC 5537 3.5) */
	time_t cutoff = time(NULL) + 86400;
	if (artinfo->injectiondate) {
		return bbs_date_is_newer_than(artinfo->injectiondate, cutoff);
	}
	return bbs_date_is_newer_than(artinfo->date, cutoff);
}

static int article_too_old(struct article_info *artinfo)
{
	/* Reject any proto-articles dated too far in the past.
	 * We use Injection-Date if it is present and Date otherwise (RFC 5537 3.3) */
	time_t cutoff = time(NULL) - (86400 * max_accept_age);
	if (artinfo->injectiondate) {
		return bbs_date_is_older_than(artinfo->injectiondate, cutoff);
	}
	return bbs_date_is_older_than(artinfo->date, cutoff);
}

static int path_contains_poison_site(const char *path)
{
	const char *nextbang;
	if (s_strlen_zero(poisonsites)) {
		return 0; /* No poison sites configured */
	}
	for (;;) {
		size_t thissitelen;
		char sitebuf[NNTP_BUFSIZ];
		nextbang = strchr(path, '!');
		if (!nextbang) {
			/* This is the last site */
			return uwildmat(path, poisonsites);
		}

		while (*path == ' ') {
			path++; /* For multi-line Path headers, we may need to eat spaces first wherever the header wrapped */
		}

		/* Drop if poison */
		thissitelen = (size_t) (nextbang - path);
		if (thissitelen > sizeof(sitebuf) - 1) {
			return 1; /* Well, not really, but if the site name is so long it exceeds our buffer, reject it */
		}
		safe_strncpy(sitebuf, path, (size_t) (nextbang - path + 1));
		bbs_str_tolower(sitebuf);
		if (uwildmat(sitebuf, poisonsites)) {
			return 1;
		}

		/* Update for the next site */
		path = nextbang + 1;
		if (strlen_zero(path)) {
			return 0; /* End of string */
		}
	}
}

static int path_contains_posted(const char *path)
{
	const char *p;
	/* .POSTED may not be the whole site name, it may just be the beginning. Therefore, look for it, more or less, anywhere in the string. */
	for (p = path; *p; p++) {
		if (*p == '.' && !strncasecmp(p, ".POSTED", STRLEN(".POSTED"))) {
			/* Match so far. Now it needs to be end of string or followed by a character we expect */
			if (!p[7] || p[7] == '.' || p[7] == '!' || p[7] == ' ') {
				/* And finally, since p should be the beginning of the site, should've started at beginning or following ! */
				if (p == path || p[-1] == '!') {
					return 1;
				}
			}
			/* According to RFC 5537, .POSTED should only appear as the beginning of a site; nonetheless, I have seen stuff like "mysite.POSTED",
			 * so it's possible we may encounter ill-formed path elements. Treat those as posted so we reject those
			 * to avoid propagating ill-formed Path headers.
			 * We do a case-sensitive check here to avoid false positives (e.g. site ending in .posted) */
			if (!strncmp(p, ".POSTED", STRLEN(".POSTED")) && p[7] == '!') { /* we don't also require (p > path && p[-1] != '!') because we already prepended our site, so beginning of string is fine */
				bbs_client_err("Path header '%s' is non-compliant with RFC 5537\n", path);
				return -1; /* Return -1 (still nonzero) to signal a match, albeit ill-formed */
			}
		}
	}
	return 0;
}

static int already_posted(const char *path)
{
	const char *p = bbs_skipn_val(path, '!', 2);
	/* If Path header was already present, artinfo->path will actually have .POSTED in it as its second entry, since we added <site name>!.POSTED
	 * when we received the header, so we need to skip the first two entries. */
	if (!p) {
		return 0;
	}
	return path_contains_posted(p);
}

static int matches_basic_kill_pattern(const char *subject, const char *from, const char *messageid, const char *references, const char *xref, char *errbuf, size_t errbuflen)
{
	struct kill_pattern *k;

#define KILL_CASE(enumval, field, hdrname) \
	case enumval: \
		if (uwildmat_simple(field, k->pattern)) { \
			snprintf(errbuf, errbuflen, "Matches kill pattern %s: %s (%s)", hdrname, k->pattern, field); \
			goto match; \
		} \
		break;

	RWLIST_RDLOCK(&kill_patterns);
	RWLIST_TRAVERSE(&kill_patterns, k, entry) {
		switch (k->hdr) {
			KILL_CASE(KILL_SUBJECT, subject, "Subject")
			KILL_CASE(KILL_FROM, from, "From")
			KILL_CASE(KILL_MESSAGEID, messageid, "Message-ID")
			KILL_CASE(KILL_REFERENCES, references, "References")
			KILL_CASE(KILL_XREF, xref, "Xref")
			case KILL_OTHER:
				break;
		}
	}
	RWLIST_UNLOCK(&kill_patterns);
	return 0;

match:
	RWLIST_UNLOCK(&kill_patterns);
	return 1;
}

static int matches_custom_kill_pattern(struct article_info *artinfo, char *errbuf, size_t errbuflen)
{
	struct kill_pattern *k;

#define KILL_CUSTOM_CASE(field, hdrname) \
	if (artinfo->field && !strcasecmp(k->otherheader, hdrname)) { \
		if (uwildmat(artinfo->field, k->pattern)) { \
			snprintf(errbuf, errbuflen, "Matches kill pattern %s: %s (%s)", k->pattern, hdrname, artinfo->field); \
			goto match; \
		} \
	}

	RWLIST_RDLOCK(&kill_patterns);
	RWLIST_TRAVERSE(&kill_patterns, k, entry) {
		switch (k->hdr) {
			default:
				break;
			case KILL_OTHER:
				/* At the moment, these are the only other sensible headers to check that we have available */
				KILL_CUSTOM_CASE(organization, "Organization")
				else KILL_CUSTOM_CASE(distribution, "Distribution")
				else KILL_CUSTOM_CASE(injectioninfo, "Injection-Info")
				break;
		}
	}
	RWLIST_UNLOCK(&kill_patterns);
	return 0;

match:
	RWLIST_UNLOCK(&kill_patterns);
	return 1;
}

int check_article_overview(const char *subject, const char *from, const char *date, const char *messageid, const char *references, size_t bytes, int lines, const char *xref, char *errbuf, size_t errbuflen)
{
#define REQUIRE_FIELD(field) \
	if (!field) { \
		snprintf(errbuf, errbuflen, "Missing or invalid %s", #field); \
		return -1; \
	}

	/* 4 of the 6 mandatory headers according to RFC 5536 (the other 2 are not present in overview: Path, Newsgroups) */
	REQUIRE_FIELD(date);
	REQUIRE_FIELD(from);
	REQUIRE_FIELD(messageid);
	REQUIRE_FIELD(subject);

	UNUSED(references);

	/* Check size */
	if (bytes > (size_t) max_article_size) {
		snprintf(errbuf, errbuflen, "Too large (%lu > %u bytes)", bytes, max_article_size);
		return -1;
	}

	/* Check number of lines */
	if (min_lines && (unsigned int) lines < min_lines) {
		snprintf(errbuf, errbuflen, "Too few lines (%d < %u)", lines, min_lines);
		return -1;
	} else if (max_lines && (unsigned int) lines > max_lines) {
		snprintf(errbuf, errbuflen, "Too many lines (%d > %u)", lines, max_lines);
		return -1;
	}

	/* Only for sucking, if Xref is present, we can perform some checks that would normally be done with the Newsgroups header */
	if (xref) {
		char *grp, *grps;
		char xref_dup[2084];
		int xrefgroups;

		/* If we have the Xref header available in overview, count the number of newsgroups
		 * We don't query LIST OVERVIEW.FMT for the format here, but we don't really need to. */
		xrefgroups = bbs_str_count(xref, ' '); /* The hostname is first with a space following, so we don't need to add 1 to the count after */
		if (xrefgroups > (int) max_crossposts) {
			snprintf(errbuf, errbuflen, "Too many crossposts (%d > %d)", xrefgroups, max_crossposts);
			return -1;
		}

		/* Also check for poison groups here; this way if there is a match in this header, and we're sucking articles, we don't need to request the article only to discard it */
		safe_strncpy(xref_dup, xref, sizeof(xref_dup));
		grps = xref_dup;
		strsep(&grps, " "); /* Eat the news server hostname */
		while ((grp = strsep(&grps, " "))) {
			bbs_strterm(grp, ':'); /* Strip article number */
			if (group_is_poison(grp)) {
				snprintf(errbuf, errbuflen, "Contains poison group %s", grp);
				return -1;
			}
		}
	}

	/* Last, check for any kill pattern matches */
	if (matches_basic_kill_pattern(subject, from, messageid, references, xref, errbuf, errbuflen)) {
		return -1;
	}

	return 0;
}

/* RFC 5536 3.1.4 (reserved invalid groups and implementation-specific groups that MAY be used for their specific purpose or by local agreement) */
#define contains_invalid_newsgroups(s) (uwildmat(s, "example,example.*,poster,to,to.*,control,control.*,all,all.*,ctl,ctl.*,junk"))

static int check_newsgroups(const char *newsgroups, char *errbuf, size_t errbuflen)
{
	int ngrp_count;

	REQUIRE_FIELD(newsgroups);

	if (strstr(newsgroups, ",,")) {
		/* Tolerate, since we'll ignore the empty group later, but this is poor form! */
		bbs_client_err("Newsgroups header is malformed\n");
	}

	/* Crossposted too much? */
	ngrp_count = bbs_str_count(newsgroups, ',') + 1; /* Crude way of counting newsgroups (may overcount if there are consecutive commas like ,, ) */
	if (ngrp_count > (int) max_crossposts) {
		snprintf(errbuf, errbuflen, "Crossposted to too many groups (%d > %u)", ngrp_count, max_crossposts);
		return -1;
	}

	/* Ensure there are no invalid newsgroups (we already know the header is non-empty at this point)
	 * We SHOULD reject proto-articles without at least valid group or with any reserved group names (RFC 5537 3.5) */
	if (contains_invalid_newsgroups(newsgroups)) {
		snprintf(errbuf, errbuflen, "Invalid newsgroups specified");
		return -1;
	}

	return 0;
}

/*! \retval 0 on success, or 1 on duplicate or -1 for the default error code depending on mode */
int check_article(enum nntp_mode mode, struct nntp_session *nntp, struct article_info *artinfo, char *errbuf, size_t errbuflen)
{
	/* Perform basic checks that only involve data that is stored in overview.
	 * This is shared in common with the sucking logic in nntp_suck.c, which requests overview information using OVER/XOVER first,
	 * so it can efficiently exclude articles that don't meet our criteria. */
	if (check_article_overview(artinfo->subject, artinfo->from, artinfo->date, artinfo->messageid, artinfo->references, artinfo->bytes, artinfo->lines, NULL, errbuf, errbuflen)) {
		return -1;
	}

	if (check_newsgroups(artinfo->newsgroups, errbuf, errbuflen)) {
		return -1;
	}

	/* The only remaining (possibly) mandatory header that hasn't been checked yet */
	if (mode == NNTP_MODE_TRANSIT && !artinfo->path) { /* For proto-articles, we have yet to prepend this header and will do it later */
		snprintf(errbuf, errbuflen, "Missing Path");
		return -1;
	}

	/* We tolerate consecutive commas in Newsgroups but not in Distribution. */
	if (artinfo->distribution && strstr(artinfo->distribution, ",,")) {
		snprintf(errbuf, errbuflen, "Distribution header is malformed");
		return -1;
	}

	/* We reject invalid Path headers here, rather than in process_last_header,
	 * because if we had set it to NULL there, then at this point we would no longer
	 * know if the proto-article had an invalid Path header which should be rejected,
	 * or if the header was missing originally, in which case we will add it later. */
	if (artinfo->path) {
		if (path_contains_poison_site(artinfo->path)) {
			/* We log the path so that when this gets logged by log_article,
			 * the newsmaster can later determine what site caused rejection if needed.
			 * Unfortunately, uwildmat only returns whether it matched, not what caused the match,
			 * so we have to log the full header value here. */
			snprintf(errbuf, errbuflen, "Unwanted site in Path '%s'", artinfo->path);
			return -1;
		}
	}

	if (mode == NNTP_MODE_TRANSIT) {
		if (artinfo->messageid[0] != '<' && !bbs_str_ends_with(artinfo->messageid, ">")) {
			/* Invalid Message-ID */
			snprintf(errbuf, errbuflen, "Invalid Message-ID %s", artinfo->messageid);
			return -1;
		}

		/* If we limit what distributions we get from this peer, check if we want this article or not. */
		if (nntp && !we_want_distribution(nntp, artinfo->distribution)) {
			if (artinfo->distribution) {
				snprintf(errbuf, errbuflen, "Unwanted distribution \"%s\"", artinfo->distribution);
			} else {
				/* If Distribution header was not present and article was rejected for distribution,
				 * that means this site only accepts certain distributions. */
				snprintf(errbuf, errbuflen, "Unwanted, missing distribution");
			}
			return -1;
		}

		if (artinfo->control) {
			/* If it has a Control header, it's a control message.
			 * Here, we only validate that it's a known control message type and that it's approved (if required). */
			enum nntp_control_msg cmsg = parse_cmsg(artinfo->control);
			if (cmsg == CMSG_UNKNOWN) {
				snprintf(errbuf, errbuflen, "Unknown control message: %s", artinfo->control);
				return -1;
			} else if (!artinfo->approved && (cmsg == CMSG_NEWGROUP || cmsg == CMSG_RMGROUP)) {
				snprintf(errbuf, errbuflen, "Ignoring unapproved newgroup/rmgroup message");
				return -1;
			}
		}
	} else {
		/* Path is optional for proto-articles, but if present, it SHOULD NOT contain a "POSTED" diag-keyword (RFC 5537 3.4.1) */
		if (artinfo->path && already_posted(artinfo->path)) {
			snprintf(errbuf, errbuflen, "Has already been posted");
			return -1;
		}

		/* Injection-Info and Xref MUST NOT be present in proto-articles (RFC 5537 3.4.1) */
		if (artinfo->injectioninfo) {
			snprintf(errbuf, errbuflen, "Injection-Info header not allowed");
			return -1;
		}

		/* We MAY reject proto-articles that contain trace header fields, e.g. NNTP-Posting-Host,
		 * indicating injection by an agent that did not add Injection-Info/Injection-Date (RFC 5537 3.5)
		 * Currently, we only check this header but could expand this check. */
		if (artinfo->nntp_posting_host_set) {
			snprintf(errbuf, errbuflen, "Has already been posted");
			return -1;
		}

		if (artinfo->xref) {
			snprintf(errbuf, errbuflen, "Xref header not allowed");
			return -1;
		}

		if (article_too_new(artinfo)) {
			snprintf(errbuf, errbuflen, "Dated too far in future");
			return -1;
		} else if (article_too_old(artinfo)) {
			snprintf(errbuf, errbuflen, "Too old for injection");
			return -1;
		}

		/* Check the From header and reject it if it's not compliant with site policy. */
		if (!identity_allowed_for_posting(nntp, artinfo->from)) {
			bbs_notice("Rejected NNTP post by user %d with identity %s\n", nntp->node->user ? nntp->node->user->id : 0, artinfo->from);
			snprintf(errbuf, errbuflen, "Identity not allowed for posting");
			return -1;
		}

		/* Reject articles with unapproved headers users are not allowed to add. */
		if (artinfo->approved && !ACL_ALLOWED(nntp, NULL, NNTP_ACL_APPROVE)) {
			snprintf(errbuf, errbuflen, "You are not allowed to approve postings");
			return -1;
		}
		if (artinfo->control) {
			snprintf(errbuf, errbuflen, "You are not allowed to inject control messages");
			return -1;
		}
		if (STARTS_WITH(artinfo->subject, "cmsg ")) {
			/* RFC 5537 says that contrary to RFC 1036, messages merely with Subjects beginning with "cmsg" are NOT control articles,
			 * and we MAY reject such posts from users (RFC 5537 Section 5) */
			snprintf(errbuf, errbuflen, "Message ambiguous (subject begins with cmsg, missing Control header)");
			return -1;
		}
	}

	/* Check any kill patterns involving custom fields */
	if (matches_custom_kill_pattern(artinfo, errbuf, errbuflen)) {
		return -1;
	}

	/* Could be a race condition, maybe we didn't have the article when the client said CHECK/IHAVE,
	 * but now we do (possibly from some other server). Check one last time before we attempt to store it in the spool. */
	if (history_messageid_exists(artinfo->messageid)) {
		snprintf(errbuf, errbuflen, "%s is a duplicate", artinfo->messageid);
		return 1; /* Use specific response to refuse articles with IHAVE, otherwise use default */
	}

	return 0;
}

#define SET_POST_ERROR(fmt, ...) \
	bbs_debug(3, fmt "\n", ## __VA_ARGS__); \
	snprintf(errorbuf, sizeof(errorbuf), fmt, ## __VA_ARGS__); \
	total_errors++;

#define RX_REJECT(nntp, streaming) (streaming ? NNTP_FAIL_TAKETHIS_REJECT : nntp->mode == NNTP_MODE_TRANSIT ? NNTP_FAIL_IHAVE_REJECT : NNTP_FAIL_POST_REJECT)

#define nntp_rx_reply(nntp, artlen, messageid, logcode, code, msg) nntp_rx_reply_streaming(nntp, streaming, artlen, messageid, logcode, code, msg)

#define nntp_rx_reply_streaming(nntp, streaming, artlen, messageid, logcode, code, msg) \
	log_article(nntp, streaming, artlen, messageid, logcode, msg); \
	nntp_send(nntp, code, msg)

/* Send a custom error message to client (unless streaming) and do NOT include it in the log */
#define nntp_rx_reply2(nntp, artlen, messageid, logcode, code, msg) nntp_rx_reply2_streaming(nntp, streaming, artlen, messageid, logcode, code, msg)

/* Send a custom error message to client (unless streaming) but include it in the log */
#define nntp_rx_reply3(nntp, artlen, messageid, logcode, code, msg) nntp_rx_reply3_streaming(nntp, streaming, artlen, messageid, logcode, code, msg)

#define nntp_rx_reply2_streaming(nntp, streaming, artlen, messageid, logcode, code, msg) \
	log_article(nntp, streaming, artlen, messageid, logcode, ""); \
	nntp_send(nntp, code, "%s", streaming ? messageid : msg)

#define nntp_rx_reply3_streaming(nntp, streaming, artlen, messageid, logcode, code, msg) \
	log_article(nntp, streaming, artlen, messageid, logcode, msg); \
	nntp_send(nntp, code, "%s", streaming ? messageid : msg)

int article_create(struct article_groups *groups, struct article_info *artinfo, int srcfd, size_t artlen)
{
	int delivered;

	bbs_rwlock_wrlock(&nntp_lock);
	delivered = spool_article_create(groups, artinfo, srcfd, artlen); /* Assign article numbers, add Xref header, and deliver to spool */
	bbs_rwlock_unlock(&nntp_lock);

	if (delivered > 0) {
		propagate_article(artinfo);
	}

	return delivered;
}

/*! \brief Final processing of POST/IHAVE/TAKETHIS */
static int process_article(struct nntp_session *nntp, const char *srcfilename, size_t filesize, const char *articleid, int streaming)
{
	char *newsgroup, *newsgroups = NULL;
	int delivered = 0;
	char errorbuf[NNTP_MAX_LINE_LENGTH + 24] = "";
	int total_errors = 0, permission_errors = 0;
	struct article_info *artinfo = &nntp->artinfo;
	char prepend[NNTP_BUFSIZ];
	char append[NNTP_MAX_LINE_LENGTH];
	int res, srcfd;
	int temp_fail = 0; /* Have peer retry later? */
	unsigned int groupcount = 0;
	int was_junk = 0, junk_if_unfiled = 0;
	enum nntp_control_msg cmsg = CMSG_UNKNOWN;
	struct article_groups groups;

	memset(&groups, 0, sizeof(groups));

	/* Perform non-group specific checks for article and header validity. If any fail, the entire post is rejected. */
	res = check_article(nntp->mode, nntp, artinfo, errorbuf, sizeof(errorbuf));
	if (res) {
		/* errorbuf is set if we fail, send the error message now (except for TAKETHIS, where we only send Message-ID) */
		if (res == -1) {
			res = RX_REJECT(nntp, streaming); /* Use the default error for rejecting an article depending on mode (reader/transit and streaming or not) */
			nntp_rx_reply3(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_REJECT, res, errorbuf);
		} else if (res == 1) {
			res = nntp->mode == NNTP_MODE_TRANSIT && !streaming ? NNTP_FAIL_IHAVE_REFUSE : RX_REJECT(nntp, streaming); /* Duplicate */
			nntp_rx_reply2(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_DUPLICATE, res, errorbuf);
		}
		return 0;
	}

	if (artinfo->control) {
		cmsg = parse_cmsg(artinfo->control);
	}

#define PATH_TAIL ".POSTED!not-for-mail"

	/* If we don't already have a Path header, generate one. This is only the case for proto-articles from readers.
	 * It's done here because we need to prepend this header to ensure that Path is the first header. */
	if (!artinfo->path) {
		artinfo->prependlen = (size_t) snprintf(prepend, sizeof(prepend), "Path: %s!%s\r\n", newsname, PATH_TAIL);
		artinfo->prepend = prepend;
		artinfo->bytes += artinfo->prependlen; /* filesize stays unchanged because this isn't in the temp file */
		artinfo->path = strdup(prepend); /* Need this for checking paths for article propagation, as well as for sending path to channel/program feeds */
		if (ALLOC_FAILURE(artinfo->path)) {
			SET_POST_ERROR("Temporary server error");
			temp_fail = 1;
			total_errors = 1;
			goto cleanup;
		}
	}

	/* Determine the newsgroups to which we'll add this article. */
	ACL_RDLOCK(nntp);
	newsgroups = artinfo->newsgroups; /* Duplicate pointer since we'll mutate it */
	while ((newsgroup = strsep(&newsgroups, ","))) {
		char status[NNTP_BUFSIZ] = "y"; /* Default to 'y' in case it's a control message */

		ltrim(newsgroup); /* The Newsgroups header could contain spaces between groups */
		if (strlen_zero(newsgroup)) {
			continue;
		}

		/* Check if this group is poison. We need to do this first, because most likely the group isn't carried locally. */
		if (group_is_poison(newsgroup)) {
			/* If poison, this is fatal to the entire article, not just the poisoning group. Drop everything and clean up. */
			SET_POST_ERROR("Group '%s' is poison", newsgroup);
			total_errors = 1; /* This will be the error that matters, so ensure it gets used in the log message */
			ACL_UNLOCK(nntp);
			goto cleanup;
		}

		/* We don't ltrim here, as newsgroups should be comma-separated, without any spaces between them */
		if (group_get_status(newsgroup, status, sizeof(status))) {
			/* If it's a newgroup/rmgroup message, group may not exist; that's fine, continue processing since we'll change the filing group shortly */
			if (!(cmsg == CMSG_NEWGROUP || cmsg == CMSG_RMGROUP)) {
				SET_POST_ERROR("Newsgroup '%s' does not exist", newsgroup); /* Try to deliver to any other groups listed */
				continue;
			}
		}
		if (!status_allows_posting(nntp, newsgroup, status, errorbuf, sizeof(errorbuf))) {
			bbs_debug(3, "%s\n", errorbuf);
			total_errors++;
			if (nntp->mode == NNTP_MODE_TRANSIT) {
				permission_errors++; /* If a group is rejected because of status, then it should get filed into junk; for readers though, we don't consider this a permissions error */
			}
			continue;
		}
		if (!ACL_ALLOWED_LOCKED(nntp, newsgroup, NNTP_ACL_POST)) {
			SET_POST_ERROR("You are not allowed to post to %s", newsgroup);
			permission_errors++;
			continue;
		}
		if (status[0] == 'j') {
			/* If we don't end up with any valid groups, file it into junk */
			junk_if_unfiled = 1;
			continue;
		} else if (status[0] == '=') {
			/* Group is aliased to another group.
			 * This has to come after the ACL check, since we don't check the permissions for the target group, only the original one. */
			newsgroup = status + 1;
		} else if (status[0] == 'm') {
			/* If from a reader, need to send to moderator.
			 * If from peer, should already have been approved. */
			if (nntp->mode == NNTP_MODE_TRANSIT) {
				/* We MUST reject articles without an Approved header field posted to known-moderated newsgroups (RFC 5537 3.7 #5) */
				if (!artinfo->approved) {
					SET_POST_ERROR("Unapproved for \"%s\"", newsgroup);
					permission_errors++;
					continue;
				}
			} else {
				/* We forward to the moderator of the leftmost moderated group (which is the first one encountered in the loop).
				 * Even if there are other moderated (or unmoderated) groups, we stop here (RFC 5537 3.5.1).
				 * The article we send lacks the prepend/append headers (Path, Injection-Info, etc.) as these MUST NOT be sent to the moderator. */
				if (process_moderated_group(newsgroup, srcfilename)) {
					SET_POST_ERROR("Could not find moderator for group '%s'", newsgroup);
					total_errors = 1; /* This will be the error that matters, so ensure it gets used in the log message */
				} else {
					delivered = 1; /* Send success message */
				}
				ACL_UNLOCK(nntp);
				goto cleanup;
			}
		}
		if (article_groups_contains(&groups, newsgroup)) {
			bbs_debug(3, "Group '%s' is duplicated in Newsgroups list\n", newsgroup); /* Not fatal so we don't set error */
			total_errors++; /* The non-duplicated one may still succeed, so this doesn't necessarily mean we'll return failure */
			continue;
		}
		if (groupcount++ < max_post_groups || (nntp->mode == NNTP_MODE_TRANSIT && groupcount < max_groups)) {
			article_groups_add(&groups, newsgroup);
		}
	}
	ACL_UNLOCK(nntp);

	/* If the message didn't include any valid groups on this server thus far, but either:
	 * - we have a 'j' status for at least one of the attempted groups
	 * - we are configured to file all received articles w/o any nonexistent groups to junk (implicit 'j' status for articles from peers, otherwise allowed by permissions)
	 * then we go ahead and file into junk. */
	if (!groupcount && (junk_if_unfiled || (nntp->mode == NNTP_MODE_TRANSIT && keepjunk && permission_errors < total_errors))) {
		article_groups_add(&groups, "junk");
		groupcount++;
		was_junk = 1; /* We'll know later we only accepted this because it went to junk */
	}

	if (nntp->mode == NNTP_MODE_READER && groupcount > max_post_groups) {
		bbs_notice("Rejected post with %u groups (max allowed: %u)\n", groupcount, max_post_groups);
		goto cleanup;
	} else if (groupcount > max_groups) {
		bbs_notice("Rejected article with %u groups (max allowed: %u)\n", groupcount, max_groups);
		goto cleanup;
	}

	if (!groupcount) {
		goto cleanup; /* No point in proceeding if there are no groups */
	}

	if (nntp->mode == NNTP_MODE_READER) {
		char hostname[256];
		char *appendpos = append;
		size_t appendleft = sizeof(append);

		/* If Injection-Date header or both Message-ID and Date already present, MUST NOT add Injection-Date; otherwise, MUST add it (RFC 5537 3.5 #11)
		 * By the time we get to process_articles, the headers have alreay been added if they were not present, but we kept track of this in artinfo->needinjectiondate.
		 * This replaces the deprecated NNTP-Posting-Date header.
		 *
		 * It appears that INN likes to add CFWS after the date itself, e.g. (UTC) as a comment. We do NOT do this. */
		if (artinfo->needinjectiondate) {
			int datelen;
			SAFE_FAST_APPEND(append, sizeof(append), appendpos, appendleft, "Injection-Date: ");
			datelen = bbs_time_rfc822(time(NULL), append + STRLEN("Injection-Date: "), appendleft); /* Just write directly into the buffer rather than using a separate one and having to copy it */
			appendpos += (size_t) datelen;
			appendleft -= (size_t) datelen;
			SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "\r\n");
		}

		/* We MAY (and SHOULD) add an Injection-Info header identifying the source of the article and possibly other trace info (RFC 5537 3.5)
		 * We do this here instead of in process_last_header because if forwarding to moderator, we need to send off the article without
		 * added Injection-Info/Injection-Date headers (RFC 5537 3.5 #7). At this point, moderated articles have already been processed.
		 *
		 * This header replaces the deprecated NNTP-Posting-Host, X-Trace, X-Complaints-To, etc. headers */
		SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "Injection-Info: %s", newsname);
		if (injection_add_posting_account != INJECTION_POSTING_ACCOUNT_HIDDEN) {
			/* Add the authenticated user's username. RFC 5536 3.2.8 says this SHOULD be obfuscated though we allow it either way (INN does not).
			 * If obfuscation is enabled, we simply hash the username so that correlation can be maintained since we SHOULD have the same value if the same account is used. */
			if (injection_add_posting_account == INJECTION_POSTING_ACCOUNT_OBFUSCATED) {
				/* Yes, SHA1 is not as good as SHA256, but SHA256 is a bit long for this value and we are just intending to obfuscate, not provide cryptographic guarantees */
				char hash[SHA1_BUFSIZE];
				hash_sha1(bbs_username(nntp->node->user), hash);
				SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "; posting-account=\"%s\"", hash);
			} else {
				SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "; posting-account=\"%s\"", bbs_username(nntp->node->user));
			}
		}
		if (injection_add_posting_host && !bbs_get_hostname(nntp->node->ip, hostname, sizeof(hostname))) {
			SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "; posting-host=\"%s\"", hostname);
		}
		if (appendpos - append > 80) {
			/* If we added both the above parameters, wrap to the next line so the header displays more nicely.
			 * The separating ; between parameters is on the first line though. */
			SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, ";\r\n\t");
		} else {
			SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "; ");
		}
		/* This is the only parameter that we always append, since it requires no configuration and shouldn't be a privacy risk.
		 * The idea is to log something obfuscated that can later be used to reassociate to the original poster if needed.
		 * INN uses the PID, which works just as well for us as long as we use the TID since each user session gets its own thread. */
		SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "logging-data=\"%d\"", bbs_gettid());
		if (!s_strlen_zero(complaints_addr)) {
			SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "; mail-complaints-to=\"%s\"", complaints_addr);
		}
		SAFE_FAST_APPEND_NOSPACE(append, sizeof(append), appendpos, appendleft, "\r\n"); /* End the Injection-Info header */

		artinfo->appendlen = (size_t) (appendpos - append);
		artinfo->append = append;
		artinfo->bytes += artinfo->appendlen;
	}

	if (artinfo->control) {
		const char *ctlgrp;
		/* If it's a control message that's in scope, it gets filed into a special control group (RFC 5537 3.7)
		 * We processed the groups above so that we could filter out anything we don't want. */
		free_article_groups(&groups);
		groupcount = 0;
		switch (cmsg) {
			case CMSG_NEWGROUP:
				ctlgrp = "control.newgroup";
				break;
			case CMSG_RMGROUP:
				ctlgrp = "control.rmgroup";
				break;
			case CMSG_CHECKGROUPS:
				ctlgrp = "control.checkgroups";
				break;
			case CMSG_CANCEL:
				ctlgrp = "control.cancel";
				break;
			case CMSG_UNKNOWN:
				bbs_assert(0); /* Would have aborted already */
				__builtin_unreachable(); /* Suppress maybe uninitialized usage of ctlgrp */
		}
		if (!group_exists(ctlgrp)) {
			bbs_error("Control group '%s' doesn't exist, using '%s' instead\n", ctlgrp, "control");
			ctlgrp = "control";
			if (!group_exists(ctlgrp)) {
				bbs_error("Control group '%s' doesn't exist, can't file control message\n", ctlgrp);
				total_errors++;
				goto cleanup;
			}
		}
		groupcount++;
		article_groups_add(&groups, ctlgrp);
		/*! \todo No further processing of control messages is currently done yet after filing into the appropriate control group */
		/*! \todo Supersedes header likewise requires similar kind of processing (RFC 5537 3.6 #5 / 3.7 #4) */
	}

	/* Actually add message to groups */
	srcfd = open(srcfilename, O_RDONLY);
	if (srcfd < 0) {
		bbs_error("Failed to open %s: %s\n", srcfilename, strerror(errno));
		goto cleanup;
	}
	delivered = article_create(&groups, artinfo, srcfd, filesize); /* Assign article numbers, add/update Xref header, and deliver to spool */
	close(srcfd);
	if (delivered <= 0) {
		temp_fail = 1; /* If we got this far and failed, for peers, this is a temporary failure, we want them to retry deliver later */
	}

cleanup:
	free_article_groups(&groups);
	if (delivered <= 0) {
		/* Should we instead do permanent error for transit (437), if newsgroup doesn't exist? But what if it's added later? */
		if (nntp->mode == NNTP_MODE_READER) {
			if (total_errors == 1 && errorbuf[0]) {
				/* If attempted to post only to one group, use the specific error message we constructed */
				nntp_rx_reply3(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_REJECT, permission_errors ? NNTP_FAIL_POST_AUTH : NNTP_FAIL_POST_REJECT, errorbuf);
			} else if (permission_errors && total_errors == permission_errors) {
				/* We weren't authorized to post to the group(s) */
				nntp_rx_reply2(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_REJECT, NNTP_FAIL_POST_AUTH, "Posting not allowed");
			} else {
				nntp_rx_reply2(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_REJECT, NNTP_FAIL_POST_REJECT, "Posting failed");
			}
		} else {
			if (temp_fail) {
				if (streaming) {
					/* RFC 4644 2.5.2 says to defer with TAKETHIS, we MUST send a 400 response and disconnect */
					nntp_rx_reply2(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_DEFER, NNTP_FAIL_TERMINATING, "Service temporarily unavailable");
					return -1;
				}
				nntp_rx_reply2(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_DEFER, NNTP_FAIL_IHAVE_DEFER, "Transfer failed; retry later");
			} else {
				/* If multiple errors occured, use a generic error response, otherwise provide the specific message */
				if (total_errors == 1 && errorbuf[0]) {
					nntp_rx_reply3(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_REJECT, streaming ? NNTP_FAIL_TAKETHIS_REJECT : NNTP_FAIL_IHAVE_REJECT, errorbuf);
				} else {
					nntp_rx_reply2(nntp, filesize, S_OR(artinfo->messageid, articleid), LOG_REJECT, streaming ? NNTP_FAIL_TAKETHIS_REJECT : NNTP_FAIL_IHAVE_REJECT, "Transfer rejected; do not retry");
				}
			}
		}
	} else {
		/* Posting succeeded to at least one newsgroup (in which case Message-ID must be set). */
		nntp_rx_reply2(nntp, filesize, artinfo->messageid, was_junk ? LOG_JUNK : LOG_ACCEPT,
			streaming ? NNTP_OK_TAKETHIS : nntp->mode == NNTP_MODE_TRANSIT ? NNTP_OK_IHAVE : NNTP_OK_POST, "Article received OK");/* If we succeeded, propagate the article to other sites */
	}
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
	if (!*max) {
		if (!*min) {
			return 1; /* 0-0 or invalid? */
		}
		*max = NNTP_MAX_ARTICLE_NUMBER; /* e.g. 10- (all articles >= 10) */
	}
	return 0;
}

static enum list_category parse_list_category(const char *s)
{
	if (strlen_zero(s)) {
		return LIST_ACTIVE | LIST_PER_NEWSGROUP; /* RFC 2980 2.1.2 states that "LIST ACTIVE" is the same as "LIST" (with no keyword modifier) */
	} else if (!strcasecmp(s, "ACTIVE")) {
		return LIST_ACTIVE | LIST_PER_NEWSGROUP;
	} else if (!strcasecmp(s, "COUNTS")) {
		return LIST_COUNTS | LIST_PER_NEWSGROUP;
	} else if (!strcasecmp(s, "ACTIVE.TIMES")) {
		return LIST_ACTIVE_TIMES | LIST_PER_NEWSGROUP;
	} else if (!strcasecmp(s, "NEWSGROUPS")) {
		return LIST_NEWSGROUPS | LIST_PER_NEWSGROUP;
	} else if (!strcasecmp(s, "SUBSCRIPTIONS")) {
		return LIST_SUBSCRIPTIONS; /* This is newsgroup-based, but not per newsgroup since it's a hardcoded list */
	} else if (!strcasecmp(s, "OVERVIEW.FMT")) {
		return LIST_OVERVIEW_FMT;
	} else if (!strcasecmp(s, "HEADERS")) {
		return LIST_HEADERS;
	} else if (!strcasecmp(s, "DISTRIB.PATS")) {
		return LIST_DISTRIB_PATS;
	} else if (!strcasecmp(s, "DISTRIBUTIONS")) {
		return LIST_DISTRIBUTIONS;
	} else if (!strcasecmp(s, "MODERATORS")) {
		return LIST_MODERATORS;
	} else if (!strcasecmp(s, "MOTD")) {
		return LIST_MOTD;
	} else {
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
		nntp_send(nntp, NNTP_ERR_SYNTAX, "Unknown LIST keyword");
		return 1;
	}
	if (!strlen_zero(argument) && !(listcat & LIST_PER_NEWSGROUP) && !(listcat & LIST_HEADERS)) {
		/* We have an argument, but we don't consume one */
		nntp_send(nntp, NNTP_ERR_SYNTAX, "This command is not newsgroup-based and does not accept an argument");
		return 1;
	}

	if (listcat & LIST_PER_NEWSGROUP) {
		listcat &= ~((unsigned int) LIST_PER_NEWSGROUP); /* Remove this flag, it is present if calling this function, and that way group_list can case directly on the category */
		ACL_RDLOCK(nntp); /* Lock the ACL list once for the whole loop so we can use the locked version of the ACL check */
		res = active_group_list(nntp, listcat, argument);
		ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, NNTP_ERR_UNAVAILABLE, "Data item not available");
			return 1;
		}
		return 0;
	} /* else, not newsgroup-based: */

	if (listcat & (LIST_OVERVIEW_FMT | LIST_HEADERS)) {
		if (listcat & LIST_HEADERS) {
			/* With LIST_HEADERS, type is either MSGID or RANGE or NULL.
			 * Here, we only check that any provided argument is valid. */
			if (!strlen_zero(argument)) {
				if (strcasecmp(argument, "MSGID") && strcasecmp(argument, "RANGE")) {
					nntp_send(nntp, NNTP_ERR_SYNTAX, "Syntax error in argument");
					return 0;
				}
			}
		} else {
			if (!strlen_zero(argument)) {
				/* This command takes no arguments */
				nntp_send(nntp, NNTP_ERR_SYNTAX, "Unexpected wildmat or argument");
				return 0;
			}
		}
		return spool_overview_header_list(nntp, listcat, argument);
	} else if (listcat & LIST_SUBSCRIPTIONS) {
		const char *s;
		struct stringitem *i = NULL;

		nntp_send(nntp, NNTP_OK_LIST, "%s", "Recommended subscriptions in form \"group\"");
		RWLIST_RDLOCK(&subscriptions);
		while ((s = stringlist_next(&subscriptions, &i))) {
			_nntp_send(nntp, "%s\r\n", s);
		}
		RWLIST_UNLOCK(&subscriptions);
	} else if (listcat & LIST_DISTRIB_PATS) {
		struct distrib_pat *p;
		/* distrib.pats list assists clients to choose a value for the Distribution header of an article being posted.
		 * <weight> <wildmat> <value for Distribution header content>
		 * The highest-weighted line with a matching wildmat is the value that gets used. */
		nntp_send(nntp, NNTP_OK_LIST, "%s", "Default distributions in form \"weight:group-pattern:distribution\"");
		RWLIST_RDLOCK(&distrib_pats);
		RWLIST_TRAVERSE(&distrib_pats, p, entry) {
			_nntp_send(nntp, "%d:%s:%s\r\n", p->weight, p->wildmat, p->value);
		}
		RWLIST_UNLOCK(&distrib_pats);
	} else if (listcat & LIST_DISTRIBUTIONS) {
		struct distribution *d;
		nntp_send(nntp, NNTP_OK_LIST, "%s", "Default distributions in form \"distribution description\"");
		RWLIST_RDLOCK(&distributions);
		RWLIST_TRAVERSE(&distributions, d, entry) {
			_nntp_send(nntp, "%s\t%s\r\n", d->name, d->description);
		}
		RWLIST_UNLOCK(&distributions);
	} else if (listcat & LIST_MODERATORS) {
		struct moderator *m;
		nntp_send(nntp, NNTP_OK_LIST, "%s", "Newsgroup moderators in form \"group-pattern:submission-template\"");
		RWLIST_RDLOCK(&moderators);
		RWLIST_TRAVERSE(&moderators, m, entry) {
			_nntp_send(nntp, "%s:%s\r\n", m->wildmat, m->template);
		}
		RWLIST_UNLOCK(&moderators);
	} else if (listcat & LIST_MOTD) {
		if (!s_strlen_zero(motd)) {
			nntp_send(nntp, NNTP_OK_LIST, "%s", "Message of the day text in UTF-8");
			_nntp_send(nntp, "%s\r\n", motd);
		} else {
			nntp_send(nntp, NNTP_ERR_UNAVAILABLE, "No message of the day available");
			return 0;
		}
	} else {
		/* If we got here, something went wrong */
		bbs_error("Couldn't generate response for LIST %s?\n", keyword);
		return -1;
	}
	_nntp_send(nntp, ".\r\n");
	return 0;
}

#define REQUIRE_READER() \
	if (nntp->mode != NNTP_MODE_READER) { \
		nntp_send(nntp, NNTP_FAIL_WRONG_MODE, "MODE-READER"); \
		return 0; \
	}

#define REQUIRE_TRANSIT() \
	if (nntp->mode != NNTP_MODE_TRANSIT) { \
		nntp_send(nntp, NNTP_FAIL_WRONG_MODE, "Readers must use POST, not IHAVE"); \
		return 0; \
	} \
	if (requirerelaytls && !nntp->node->secure) { \
		nntp_send(nntp, NNTP_FAIL_PRIVACY_NEEDED, "Secure connection required"); \
		return 0; \
	} \
	if (!nntp->inpeer_any) { \
		bbs_notice("Sender %s/%s unauthorized to send us articles\n", bbs_username(nntp->node->user), nntp->node->ip); \
		nntp_send(nntp, NNTP_ERR_ACCESS, "Not authorized to relay articles"); \
		return 0; \
	}

#define REQUIRE_GROUP() \
	if (!nntp->currentgroup) { \
		nntp_send(nntp, NNTP_FAIL_NO_GROUP, "No newsgroup selected"); \
		return 0; \
	}

static int save_header_value(struct article_info *artinfo, char *s, char *errbuf, size_t errbuflen)
{
	char *hval;

#define SAVE_HEADER(hdrname, var) \
	if (STARTS_WITH(s, hdrname ":")) { \
		hval = s + STRLEN(hdrname ":"); \
		ltrim(hval); \
		if (unlikely(strlen_zero(hval))) { \
			bbs_client_err("Empty header '%s'?\n", hdrname); \
			/* We MAY reject articles with header fields without valid contents (RFC 5537 3.6), we just omit the header (e.g. can happen for References with no value) */ \
			return 0; \
		} \
		if (unlikely(var != NULL)) { \
			if (var == artinfo->organization) { /* Multiple Organization headers appear in practice, so tolerate duplicates */ \
				return 0; \
			} \
			snprintf(errbuf, errbuflen, "Duplicate header '%s'", hdrname); \
			return -1; /* RFC 5536 Section 3 says these headers MUST NOT occur more than once */ \
		} \
		REPLACE(var, hval); \
		if (ALLOC_FAILURE(var)) { \
			snprintf(errbuf, errbuflen, "Temporary system error"); \
			return -1; \
		} \
		hval = var; /* The logic at the end of the function to replace with space needs to operate on the saved variable */ \
	}

	/* CR LF pairs will not be present even in unfolded multi-line headers, since we appended with a space between lines.
	 * We do a few other fixups if needed at the bottom of this function. */
	SAVE_HEADER("Newsgroups", artinfo->newsgroups)
	else SAVE_HEADER("Distribution", artinfo->distribution)
	else SAVE_HEADER("Approved", artinfo->approved)
	else SAVE_HEADER("Control", artinfo->control)
	else SAVE_HEADER("Expires", artinfo->expires)
	else SAVE_HEADER("Subject", artinfo->subject)
	else SAVE_HEADER("From", artinfo->from)
	else SAVE_HEADER("Organization", artinfo->organization)
	else SAVE_HEADER("Date", artinfo->date)
	else SAVE_HEADER("References", artinfo->references)
	else SAVE_HEADER("Message-ID", artinfo->messageid)
	else SAVE_HEADER("Path", artinfo->path) /* Path is already modified in receive_article */
	else SAVE_HEADER("Injection-Info", artinfo->injectioninfo)
	else SAVE_HEADER("Injection-Date", artinfo->injectiondate)
	else SAVE_HEADER("Xref", artinfo->xref) /* Generally ignored unless slaving Xref; if from a reader, we store so we can reject the article */
	else {
		/* Don't care about value, but for certain headers, keep track that header has been set */
		if (STARTS_WITH(s, "NNTP-Posting-Host")) {
			artinfo->nntp_posting_host_set = 1;
		}
		return 0; /* Not a header of interest */
	}

	/* Fix up the header value saved in the variable, operating on it in place
	 * The only thing we need to do at this point is replace any lingering tabs or stray CR or LF with a single space.
	 * These should not be present as they are not legal, but we do this for robustness as suggested in RFC 3977 8.3.2,
	 * as the values saved in artinfo variables will eventually make their way to being stored directly in the overview file.
	 * This check is last so we don't need to do this for headers we aren't saving into a variable. */
	while (*hval) {
		if (*hval == '\t' || *hval == '\r' || *hval == '\n') {
			*hval = ' ';
		}
		hval++;
	}
	return 0;
}

/*! \brief Get the best (highest-weight) Distribution value to use from the distrib.pats list */
static int get_matching_distribution(const char *groups, char *buf, size_t len)
{
	char grpsbuf[4096];
	char *grp, *grps;
	int winning_weight = 0;
	struct distrib_pat *p, *winner = NULL;
	safe_strncpy(grpsbuf, groups, sizeof(grpsbuf));

	grps = grpsbuf;
	/* We check each newsgroup for matches, but only take the best match across all newsgroups, not per each newsgroup. */
	RWLIST_RDLOCK(&distrib_pats);
	while ((grp = strsep(&grps, ","))) {
#if 0
		/* XXX Should we check if a specified group exists before matching?
		 * It may be that a group matches a pattern in distrib.pats but isn't carried locally.
		 * Does it make sense to add distributions for such groups? */
		if (!group_exists(grp)) {
			continue;
		}
#endif
		RWLIST_TRAVERSE(&distrib_pats, p, entry) {
			/* Check the weight before the wildmat since that's faster
			 * INN uses the first match if there is a tie on weight, so likewise, we use > instead of >= */
			if (p->weight > winning_weight && uwildmat(grp, p->wildmat)) {
				winner = p;
				winning_weight = p->weight;
			}
		}
	}
	if (winner && !strlen_zero(winner->value)) {
		safe_strncpy(buf, winner->value, len);
	} else {
		winner = NULL;
	}
	RWLIST_UNLOCK(&distrib_pats);
	return winner ? 0 : 1;
}

static int is_valid_date_hdr(const char *s)
{
	struct tm tm;
	if (bbs_parse_rfc822_date(s, &tm)) {
		return 0;
	}
	return 1;
}

static int is_valid_messageid(const char *s)
{
	const char *tmp;
	if (*s != '<') {
		return 0;
	}
	tmp = strchr(s, '>');
	if (!tmp++) {
		return 0;
	}
	if (*tmp) {
		return 0;
	}
	return 1;
}

static int process_last_header(enum nntp_mode mode, struct article_info *artinfo, char *s, FILE *fp, size_t *restrict artlen, const char *articleid, char *errbuf, size_t errbuflen)
{
	int bytes;
	char hdrval[NNTP_MAX_LINE_LENGTH];

	if (save_header_value(artinfo, s, errbuf, errbuflen)) {
		return -1;
	}

	/* Before reading the body (or if there is no body?), add any final headers that we require which aren't present yet: */

#define APPEND_HDR(fp, hdrname, fmt, ...) \
	bytes = fprintf(fp, hdrname ": " fmt "\r\n", ## __VA_ARGS__); \
	*artlen += (size_t) bytes;

#define ADD_HDR(fp, field, hdrname, fmt, ...) \
	REPLACE(field, __VA_ARGS__); \
	if (ALLOC_FAILURE(field)) { \
		return -1; \
	} \
	APPEND_HDR(fp, hdrname, fmt, __VA_ARGS__); \

	/* If article did not supply a Distribution header, then we will add one automatically if appropriate (after all, client could've used DISTRIB.PATS to do it itself) */
	if (!artinfo->distribution && artinfo->newsgroups) { /* If artinfo->newsgroups isn't set, the article will get rejected anyhow (but it's not guaranteed to exist right now, so we check) */
		if (!get_matching_distribution(artinfo->newsgroups, hdrval, sizeof(hdrval))) {
			ADD_HDR(fp, artinfo->distribution, "Distribution", "%s", hdrval);
		}
	}

	if (articleid) { /* Usually if MODE_TRANSIT, but if sucking news, articleid isn't set */
		if (artinfo->messageid && strcmp(artinfo->messageid, articleid)) {
			/* The article better be the article that the other server said it was in IHAVE */
			snprintf(errbuf, errbuflen, "Message-ID mismatch: advertised %s, actually %s", articleid, s);
			return 1; /* Permanently reject message */
		}
		/* Check that header fields are valid. If not, remove the header to trigger rejection.
		 * If they're mandatory and missing, it will be rejected by check_article */
		if (artinfo->date && !is_valid_date_hdr(artinfo->date)) {
			FREE(artinfo->date);
		}
		if (artinfo->messageid && !is_valid_messageid(artinfo->messageid)) {
			FREE(artinfo->messageid);
		}
	}

	if (mode == NNTP_MODE_READER) {
		/* Certain mandatory fields are optional in proto-articles, i.e. we need to add them if they are missing (Date, Message-ID, Path).
		 * If they are present, they MUST be valid (RFC 5537 3.4.1). If we find them invalid, we REMOVE them, which will
		 * cause the proto-article to be rejected since a mandatory header will be missing. */
		if (!artinfo->injectiondate && !(artinfo->date && artinfo->messageid)) {
			/* All three of these headers are valid in proto-articles.
			 * If Injection-Date is already present, we MUST NOT add one, and if both Message-ID and Date are present,
			 * we MUST NOT add Injection-Date (RFC 5537 3.5 #11).
			 * If we decide to add one, we don't do it just yet as for some processing (e.g. moderated articles) we don't want these headers,
			 * and also we want this header to appear after some of the mandatory headers. */
			artinfo->needinjectiondate = 1;
		}
		if (artinfo->date) {
			if (!is_valid_date_hdr(artinfo->date)) {
				FREE(artinfo->date);
			}
		} else {
			bbs_time_rfc822(time(NULL), hdrval, sizeof(hdrval));
			ADD_HDR(fp, artinfo->date, "Date", "%s", hdrval);
		}
		if (artinfo->messageid) {
			if (!is_valid_messageid(artinfo->messageid)) {
				snprintf(errbuf, errbuflen, "Invalid Message-ID");
				FREE(artinfo->messageid);
			}
		} else {
			/* Didn't get a Message-ID from the reader client, construct one for the article now. */
			char *uuid = bbs_uuid(); /* Use same UUID (and by extension, the same Article ID) for all newsgroups */
			if (!uuid) {
				return -1; /* If we can't assign a Message-ID, this is fatal */
			}
			snprintf(hdrval, sizeof(hdrval), "<%s@%s>", uuid, newsname);
			free(uuid);
			ADD_HDR(fp, artinfo->messageid, "Message-ID", "%s", hdrval);
		}

		/* Either the client or the server can add the Organization header.
		 * If the client has already set it, we don't touch it. */
		if (!artinfo->organization && !s_strlen_zero(newsorg)) {
			ADD_HDR(fp, artinfo->organization, "Organization", "%s", newsorg);
		}

		/* The Path header is a special exception here.
		 * By convention, the Path header always appears at the top, and though it is typically first, we can't rely on that.
		 * Thus, as we only make a single pass over the headers when receiving an article, we won't know if the Path header
		 * is present or needs to be added until we have read all the headers (which is true at this point in the code).
		 * However, we can't directly insert a new Path header into the header here, since we are at EOH.
		 * In this case, we will insert a default Path header later when creating the article.
		 *
		 * Note however that we are just doing this for the sake of convention. There is no requirement that Path be the first header
		 * (though RFC 5537 3.5 does allow the Path header, and only the Path header, to be reordered). */
	}

	return 0;
}

static inline int article_too_large(enum nntp_mode mode, size_t bytes)
{
	return bytes >= max_article_size || (mode == NNTP_MODE_READER && bytes >= max_post_size);
}

int nntp_read_article(struct article_info *artinfo, enum nntp_mode mode, struct bbs_node *node, struct readline_data *rldata, struct bbs_tcp_client *tcpclient, FILE *fp, size_t *artlen, const char *articleid, int xrefslave, char *errbuf, size_t errbuflen)
{
	int inheaders = 1;
	int permerror = 0, postfail = 0;
	int lines = 0;
	int isxref = 0;
	char headerbuf[4096]; /* Max header size for multi-line headers, this should be plenty - this isn't email! The main culprit is probably References... */
	size_t headerleft = sizeof(headerbuf);
	char *headerpos = headerbuf;
	size_t dot_stuffed_lines = 0;

	*artlen = 0;

	for (;;) {
		int res;
		char *s;
		ssize_t len;
		if (tcpclient) {
			len = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", MIN_MS(5));
			s = tcpclient->buf;
		} else {
			len = bbs_node_readline(node, rldata, "\r\n", MIN_MS(5));
			s = rldata->buf;
		}
		if (len < 0) {
			return -1;
		}
		if (!strcmp(s, ".")) {
			break; /* End of article */
		}

		if (postfail) {
			*artlen += (size_t) len + 2; /* Keep track of the intended length, even though this message is a goner */
			continue; /* Corruption already happened, just ignore the rest of the message for now. */
		} else if (inheaders) {
			if (!len) {
				int hres;
				inheaders = 0; /* Got CR LF, end of headers */
				hres = process_last_header(mode, artinfo, headerbuf, fp, artlen, articleid, errbuf, errbuflen);
				artinfo->headerslen = *artlen; /* We are now done processing/adding headers */
				if (hres) {
					bbs_client_err("Failed to finalize headers\n");
					postfail = 1;
					permerror = hres == 1;
					continue;
				}
			} else {
				/* Another header, or continuation of one... */
				if (s[0] == ' ' || s[0] == '\t') {
					/* Continuation of previous header */
					if (headerpos == headerbuf) { /* If we skipped a header (e.g. Xref), then we don't do anything here */
						continue; /* Skipping rest of a header we don't want */
					}
					SAFE_FAST_APPEND(headerbuf, sizeof(headerbuf), headerpos, headerleft, "%s", s + 1); /* Append to existing header (skip first char, space or tab, since we already add a space) */
					if (!headerleft) {
						char *headername = headerbuf;
						bbs_strterm(headername, ':');
						snprintf(errbuf, errbuflen, "Header %s too long", headername);
						postfail = 1;
						continue;
					}
				} else {
					/* Flush any existing header */
					if (headerpos > headerbuf) {
						/* If this is a header we care about, save it into the artinfo structure with each header unfolded into a single line; otherwise ignore.
						 * Of course, all the headers are saved as is in the file, unless we explicitly skip the header. */
						if (save_header_value(artinfo, headerbuf, errbuf, errbuflen)) {
							bbs_client_err("Failed to finalize header\n");
							postfail = 1;
							continue;
						}
					}
					/* New header */
					headerbuf[0] = '\0'; /* Reset */
					headerpos = headerbuf; /* Reset */
					headerleft = sizeof(headerbuf); /* Reset */
					isxref = 0;
					if (STARTS_WITH(s, "Xref:")) {
						/* If from a peer, ignore any incoming Xref article, since we create our own rather than reuse, unless xrefslave is enabled.
						 * Readers MUST NOT send an Xref header. Therefore, we DO also process it here for readers so later we can reject proto-articles with Xref headers. */
						if (mode == NNTP_MODE_TRANSIT && !xrefslave) {
							continue;
						}
						isxref = 1;
					} else if (STARTS_WITH(s, "Path:")) {
						/* Hardly elegant, but it's easier to just prepend to this header right here and now */
						size_t pbytes;
						int wrapped = 0;
						char *restpos;
						size_t restleft;
						char *remainingpath = s + STRLEN("Path:");
						len -= (ssize_t) STRLEN("Path:");
						while (*remainingpath == ' ' || *remainingpath == '\t') {
							remainingpath++;
							len--;
						}
						/* Write the "Path" header name and our site name to the tempfile and header buffer,
						 * then the rest of what was originally in the header, making sure we keep the length up to date.
						 * If we are receiving an article from a reader, we also add .POSTED (but not not-for-mail as tail is already present).
						 *
						 * Note that we don't reject articles that already had our site name, so as to ensure that a malicious node
						 * doesn't cause us to reject articles we haven't actually yet seen.
						 *
						 * RFC 5537 allows us to append the FQDN/IP of the source to !.POSTED; we do not, to protect poster privacy. */
						SAFE_FAST_APPEND(headerbuf, sizeof(headerbuf), headerpos, headerleft, "Path: %s%s",
							newsname, mode == NNTP_MODE_READER ? "!.POSTED" : "");
						pbytes = sizeof(headerbuf) - headerleft;
						res = (int) fwrite(headerbuf, 1, pbytes, fp); /* Use headerbuf directly; since this is the first line, we know we appended to the beginning */
						if (res != (int) pbytes) {
							bbs_error("Failed to write Path prefix (%d != %lu)\n", res, pbytes);
							postfail = 1;
							continue;
						}
						*artlen += (size_t) res;
						if (len > NNTP_MAX_LINE_LENGTH - 256) {
							/* Very crude, but if the path is pretty long, then also wrap what's to come onto another line.
							 * Examples in RFC 5537 3.2.2 show that the ! then begins on the next line.
							 *
							 * Note this only goes into the article file, not into the buffers since we don't include line endings in the variables.
							 * So that artinfo->path still includes a space when the header wraps, we will include the tab below, as save_header will convert it into a space later. */
							res = (int) fwrite("\r\n", 1, STRLEN("\r\n"), fp);
							if (res != (int) STRLEN("\r\n")) {
								bbs_error("Failed to write Path prefix (%d != %lu)\n", res, pbytes);
								postfail = 1;
								continue;
							}
							*artlen += (size_t) res;
							wrapped = 1;
						}
						restpos = headerpos; /* Save beginning of where we'll write this next line: */
						restleft = headerleft;
						SAFE_FAST_APPEND_NOSPACE(headerbuf, sizeof(headerbuf), headerpos, headerleft, "%s!%s", wrapped ? "\t" : "", remainingpath);
						res = bbs_append_line_message(fp, restpos, restleft - headerleft);
						if (res < 0) {
							bbs_error("Failed to write Path suffix\n");
							postfail = 1;
							continue;
						}
						*artlen += (size_t) res;
						continue;
					}
					SAFE_FAST_APPEND(headerbuf, sizeof(headerbuf), headerpos, headerleft, "%s", s);
				}
				if (isxref) {
					continue; /* We'll save to artinfo->xref, but not to the file itself */
				}
			}
		} else {
			lines++;
			if (*s == '.') {
				dot_stuffed_lines++; /* This line is dot-stuffed, keep track so we can adjust the length */
				if (s[1] && s[1] != '.') {
					snprintf(errbuf, errbuflen, "Line %d was not dot-stuffed but should've been", lines);
					permerror = postfail = 1;
					continue;
				}
			}
		}

		/* Reject articles that significantly exceed the line length limit to avoid propagating ill-formed articles.
		 * NNTP has a command line length limit of 512, we use twice that to be more consistent with SMTP length limits,
		 * and as in practice, there are a lot of Usenet articles with lines between 512 and 1024. */
		if (len > 2 * NNTP_MAX_LINE_LENGTH - 2) {
			snprintf(errbuf, errbuflen, "Contains excessively long line (%lu > %d B)", len + 2, 2 * NNTP_MAX_LINE_LENGTH);
			permerror = postfail = 1;
			*artlen += (size_t) len + 2; /* Keep track of the intended length, even though this message is a goner */
			continue;
		}

		if (article_too_large(mode, (unsigned int) (*artlen + (long unsigned int) len + 2))) {
			snprintf(errbuf, errbuflen, "Size exceeds site size limit");
			permerror = postfail = 1;
			*artlen += (size_t) len + 2; /* Keep track of the intended length, even though this message is a goner */
			continue;
		}

		/* SMTP and NNTP both use dot-stuffing, but we do not handle them the same way.
		 * SMTP does not have a single wire format, because messages can be received/transmitted framed in multiple ways,
		 * so dot-stuffing is not always used. See:
		 * - https://dotat.at/@/2006-09-15-no-longer-simple-mail-transport-protocol.html
		 * - https://dotat.at/@/2006-09-19-how-not-to-design-an-mta-part-4-spool-file-format.html
		 *
		 * In contrast, in NNTP, messages are always framed the same way, with dot-stuffing.
		 * Therefore, stripping the leading dot here is pointless as we'd always have to add
		 * it back again when sending articles to clients; for efficiency, we leave it in,
		 * so that way we can use sendfile() without having to process the article, i.e.
		 * articles are always stored in their wire format (INN supports both storing in wire
		 * format or not, and it's enabled by default now.)
		 *
		 * This has the slight disadvantage that other processes can't look at the spool directly
		 * and receive valid articles, but this sort of thing isn't really common anymore.
		 * Other stuff can just talk NNTP if needed.
		 *
		 * The :bytes metadata item doesn't include dot-stuffing characters, so we do keep track of how many occur,
		 * so that we can calculate this correctly in tradspool_article_create(), but that's all. */
		res = bbs_append_line_message(fp, s, (size_t) len); /* Should return len + 2 */
		if (res < 0) {
			bbs_error("Failed to append line\n");
			postfail = 1;
		}
		*artlen += (size_t) res;
	}

	/* If we are slaving off Xref but don't have one, then we can't proceed */
	if (!postfail && mode == NNTP_MODE_TRANSIT && xrefslave && !artinfo->xref) {
		postfail = 1;
		snprintf(errbuf, errbuflen, "Missing Xref header");
	}

	if (postfail) {
		return permerror ? 2 : 1;
	}

	/* We handle dot-stuffing mostly transparently, i.e. the leading dots are stored in the spool
	 * so they can be efficiently served to clients without further processing.
	 * However, that means the "real" length of the file differs from the reported # of bytes.
	 * This is intended (see RFC 3977 8.1.1, :bytes is not supposed to include dot-stuffing). */
	artinfo->bytes = *artlen - dot_stuffed_lines;
	artinfo->lines = lines;
	fflush(fp);

	return 0;
}

/* articleid is only set for MODE_TRANSIT */
static int receive_article(struct nntp_session *nntp, struct readline_data *rldata, const char *articleid, int streaming)
{
	char template[TMPNAME_BUFSIZ];
	FILE *fp;
	size_t artlen;
	int res;
	char errbuf[128] = "";
	struct article_info *artinfo = &nntp->artinfo;

	nntp_reset_data(nntp);
	bbs_renamable_tempname("nntpart", template, sizeof(template));

	fp = bbs_mkftemp(template, 0600);
	if (!fp) {
		if (streaming) { /* TAKETHIS */
			nntp_rx_reply(nntp, 0, articleid, LOG_DEFER, NNTP_FAIL_TERMINATING, "Service temporarily unavailable"); /* RFC 4644 2.5.2 says to defer with TAKETHIS, we MUST send a 400 response and disconnect */
			return -1;
		} else if (nntp->mode == NNTP_MODE_READER) {
			nntp_rx_reply(nntp, 0, articleid, LOG_DEFER, NNTP_FAIL_POST_AUTH, "Server error, posting temporarily unavailable");
		} else {
			nntp_rx_reply(nntp, 0, articleid, LOG_DEFER, NNTP_FAIL_IHAVE_DEFER, "Temporary server error, try again later");
		}
		return 0;
	}

	if (!streaming) {
		if (nntp->mode == NNTP_MODE_READER) {
			nntp_send(nntp, NNTP_CONT_POST, "Input article");
		} else {
			nntp_send(nntp, NNTP_CONT_IHAVE, "Send it");
		}
	}

	res = nntp_read_article(artinfo, nntp->mode, nntp->node, rldata, NULL, fp, &artlen, articleid, xref_slave, errbuf, sizeof(errbuf));
	fclose(fp);

	if (res < 0) {
		unlink(template);
		return -1;
	} else if (res) {
		unlink(template);
		if (res == 2 || article_too_large(nntp->mode, artlen)) {
			/* Permanent error */
			if (!s_strlen_zero(errbuf)) {
				log_article(nntp, streaming, artlen, articleid, LOG_REJECT, errbuf);
				nntp_send(nntp, RX_REJECT(nntp, streaming), "%s", errbuf);
			} else {
				nntp_rx_reply(nntp, artlen, articleid, LOG_REJECT, RX_REJECT(nntp, streaming), "Transfer rejected"); /* Catch-all, but I don't think this case is possible */
			}
		} else {
			/* Temporary error */
			if (streaming) {
				if (!s_strlen_zero(errbuf)) {
					bbs_debug(4, "Transfer failed: %s\n", errbuf);
				}
				nntp_rx_reply(nntp, artlen, articleid, LOG_DEFER, NNTP_FAIL_TERMINATING, "Transfer failed; retry later");
				return -1;
			} else if (nntp->mode == NNTP_MODE_TRANSIT) {
				nntp_rx_reply(nntp, artlen, articleid, LOG_DEFER, NNTP_FAIL_IHAVE_DEFER, "Transfer not possible; retry later");
			} else {
				nntp_rx_reply(nntp, artlen, articleid, LOG_DEFER, NNTP_FAIL_POST_REJECT, "Posting failed");
			}
		}
		return 0;
	}

	res = process_article(nntp, template, artlen, articleid, streaming);
	unlink(template);
	return res;
}

/*! \brief "Work in progress" article currently being received */
struct wip_article {
	const char *msgid;
	RWLIST_ENTRY(wip_article) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(wip_articles, wip_article);

/* No more than 25 articles being delivered to us concurrently, or we start rate-limiting */
#define MAX_WIP_ARTICLES 25

static struct wip_article *wip_add(const char *articleid)
{
	struct wip_article *w;
	int wip_count;

	RWLIST_WRLOCK(&wip_articles);
	wip_count = RWLIST_SIZE(&wip_articles, w, entry);
	if (wip_count > MAX_WIP_ARTICLES) {
		bbs_notice("Deferring article delivery for (%s), already have %d in-progress articles\n", articleid, wip_count);
		return NULL;
	}
	w = calloc(1, sizeof(*w) + strlen(articleid) + 1);
	if (ALLOC_FAILURE(w)) {
		return NULL;
	}
	strcpy(w->data, articleid); /* Safe */
	w->msgid = w->data;
	RWLIST_INSERT_HEAD(&wip_articles, w, entry);
	RWLIST_UNLOCK(&wip_articles);
	return w;
}

static int is_wip_article(const char *articleid)
{
	struct wip_article *w;
	RWLIST_RDLOCK(&wip_articles);
	RWLIST_TRAVERSE(&wip_articles, w, entry) {
		if (!strcmp(articleid, w->msgid)) {
			break;
		}
	}
	RWLIST_UNLOCK(&wip_articles);
	return w ? 1 : 0;
}

static void wip_remove(struct wip_article *w)
{
	RWLIST_WRLOCK(&wip_articles);
	RWLIST_REMOVE(&wip_articles, w, entry); /* Constant time removal, because we already have a pointer to the item to remove */
	RWLIST_UNLOCK(&wip_articles);
	free(w);
}

static int handle_ihave_takethis(struct nntp_session *nntp, struct readline_data *rldata, const char *articleid, int streaming)
{
	int res;
	struct wip_article *w;

	/* Keep track that we are currently receiving this article, so if another peer offers it to us, we can defer it.
	 * Note that we already checked previously if the article exists in the spool, and a race condition is possible here,
	 * whereby two peers might CHECK if an article exists, and it isn't in the spool (or in progress),
	 * so both now begin to attempt to deliver it. However, there is no real harm in having duplicates in the in progress
	 * list; whichever finishes first will win, and the second article will be rejected. */
	w = wip_add(articleid);
	if (unlikely(w == NULL)) {
		nntp_rx_reply(nntp, 0, articleid, LOG_DEFER, NNTP_FAIL_IHAVE_DEFER, "Retry later"); /* Temporary failure */
		return 0;
	}
	res = receive_article(nntp, rldata, articleid, streaming);
	wip_remove(w);
	return res;
}

static int handle_check(struct nntp_session *nntp, const char *articleid)
{
	/* Just because it doesn't exist, doesn't necessarily mean we want it right now.
	 * If another peer is currently sending us the same article, then we should defer
	 * it from this peer until we've received it successfully. */
	if (history_messageid_exists(articleid)) {
		nntp_send(nntp, NNTP_FAIL_CHECK_REFUSE, "%s", articleid);
	} else if (is_wip_article(articleid)) {
		nntp_rx_reply2_streaming(nntp, 1, 0, articleid, LOG_DEFER, NNTP_FAIL_CHECK_DEFER, ""); /* Defer due to in-progress delivery */
	} else {
		nntp_send(nntp, NNTP_OK_CHECK, "%s", articleid);
	}
	return 0;
}

static time_t parse_datetime(const char *date, const char *hour, int utc)
{
	time_t epoch;
	struct tm tm;
	char datestr[15];
	size_t datelen = strlen(date);
	size_t timelen = strlen(hour);

	if (datelen != 6 && datelen != 8) {
		bbs_debug(3, "Invalid date '%s'\n", date);
		return -1;
	}
	if (timelen != 6) {
		bbs_debug(3, "Invalid time '%s'\n", hour);
		return -1;
	}

	/* Date, either yymmdd or yyyymmdd
	 * If we only have a 2-digit year, figure out what the first two digits should be first. */
	if (datelen == 6) {
		time_t now;
		int cur_yy, cur_yyyy, arg_yy;
		struct tm nowdate;

		/* RFC 3977 7.3.2
		 * First two digits are from current century if yy <= current year, previous century otherwise */
		now = time(NULL);
		utc ? gmtime_r(&now, &nowdate) : localtime_r(&now, &nowdate);
		cur_yyyy = nowdate.tm_year + 1900; /* Current year */
		cur_yy = cur_yyyy % 100; /* last 2 digits of the current year */
		strcpy(datestr + 2, date);
		arg_yy = 10 * (date[0] - '0') + (date[1] - '0'); /* Get user provided yy */
		if (arg_yy > cur_yy) {
			/* Previous century, e.g. arg is 95 > 26 */
			cur_yyyy -= 100;
		} /* else, current century, e.g. arg is 11 <= 26 */
		/* Faster than formatting cur_yy for printing just to get the first two digits: */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
		datestr[0] = '0' + (char) (cur_yyyy / 1000);
		datestr[1] = '0' + (char) ((cur_yyyy % 1000) / 100);
#pragma GCC diagnostic pop
	} else {
		strcpy(datestr, date); /* Safe */
	}
	strcpy(datestr + 8, hour); /* Safe */

	memset(&tm, 0, sizeof(tm));
	if (!strptime(datestr, "%Y%m%d%H%M%S", &tm)) {
		bbs_debug(3, "strptime failed for '%s'\n", datestr);
		return -1;
	}

	errno = 0;
	epoch = utc ? timegm(&tm) : mktime(&tm);
	if (epoch <= 0) {
		if (epoch == -1 && errno) {
			bbs_error("Conversion failed: %s\n", strerror(errno));
		}
	}
	bbs_debug(5, "strptime(%s) = %ld\n", datestr, epoch);
	return epoch;
}

static int test_dateparsing(void)
{
	/* Note: The 6-digit tests will need to be updated every ~100 years when the correct epoch moves forward one century */
	bbs_test_assert_long_equals(-82739L, parse_datetime("691231", "010101", 1)); /* the day before epoch 0 */
	bbs_test_assert_long_equals(946684799L, parse_datetime("991231", "235959", 1)); /* last second of 1999 */
	bbs_test_assert_long_equals(1767961859L, parse_datetime("260109", "123059", 1)); /* 2026-01-09 */
	bbs_test_assert_long_equals(1767961859L, parse_datetime("20260109", "123059", 1));
	bbs_test_assert_long_equals(17514840225L, parse_datetime("25250109", "012345", 1));
	return 0;

cleanup:
	return -1;
}

static int nntp_process(struct nntp_session *nntp, struct readline_data *rldata, char *s)
{
	char scratch[NNTP_BUFSIZ];
	char *command = strsep(&s, " ");

	if (!strcasecmp(command, "QUIT")) {
		REQUIRE_NO_ARGS(s);
		nntp_send(nntp, NNTP_OK_QUIT, "Bye!");
		return -1;
	} else if (!strcasecmp(command, "MODE")) {
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		if (!strcasecmp(command, "READER")) {
			if (!bbs_io_transform_active(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION)) { /* RFC 8054 2.2.2: MUST NOT advertise MODE-READER after compression activated */
				nntp->mode = NNTP_MODE_READER;
				nntp_send(nntp, NNTP_OK_BANNER_POST, "Reader mode, posting permitted");
			} else {
				nntp_send(nntp, NNTP_ERR_ACCESS, "MODE-READER cannot be activated after compression");
			}
		} else if (!strcasecmp(command, "STREAM")) {
			REQUIRE_NO_ARGS(s);
			nntp_send(nntp, NNTP_OK_STREAM, "Streaming permitted"); /* Not a mode change, just indicates we support streaming (RFC 4644 2.3.2) */
		} else {
			bbs_error("Unknown mode: %s\n", command);
			nntp_send(nntp, NNTP_ERR_ACCESS, "Unknown mode");
		}
	} else if (!strcasecmp(command, "CAPABILITIES")) {
		/* This is very reminiscent of the POP3 CAPABILITIES command: */
		nntp_send(nntp, NNTP_INFO_CAPABILITIES, "Capability list:");
		_nntp_send(nntp, "VERSION 2\r\n"); /* Must be first */
		_nntp_send(nntp, "IMPLEMENTATION %s\r\n", BBS_SHORTNAME);
		if (!bbs_io_transform_active(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION)) {
			if (!nntp->node->secure) {
				if (bbs_io_transformer_available(TRANSFORM_TLS_ENCRYPTION)) {
					_nntp_send(nntp, "STARTTLS\r\n");
				}
			}
			if (bbs_io_transformer_available(TRANSFORM_DEFLATE_COMPRESSION)) {
				_nntp_send(nntp, "COMPRESS DEFLATE\r\n");
			}
		}
		/* Don't advertise MODE-READER, just READER */
		if (nntp->mode == NNTP_MODE_READER) { /* Reader mode */
			_nntp_send(nntp, "READER\r\n");
			_nntp_send(nntp, "POST\r\n");
			_nntp_send(nntp, "NEWNEWS\r\n");
		} else { /* Transit mode */
			_nntp_send(nntp, "IHAVE\r\n");
			if (!bbs_io_transform_active(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION)) { /* RFC 8054 2.2.2: MUST NOT advertise MODE-READER after compression activated */
				_nntp_send(nntp, "MODE-READER\r\n");
			}
			_nntp_send(nntp, "STREAMING\r\n");
		}
		_nntp_send(nntp, "HDR\r\n");
		_nntp_send(nntp, "XPAT\r\n");
		_nntp_send(nntp, "LIST ACTIVE ACTIVE.TIMES COUNTS DISTRIB.PATS DISTRIBUTIONS HEADERS MODERATORS MOTD NEWSGROUPS OVERVIEW.FMT SUBSCRIPTIONS\r\n");
		_nntp_send(nntp, "OVER MSGID\r\n");
		_nntp_send(nntp, "XSECRET\r\n");
		if ((nntp->node->secure || !require_secure_login) && !bbs_user_is_registered(nntp->node->user)) {
			_nntp_send(nntp, "AUTHINFO USER\r\n");
			_nntp_send(nntp, "SASL PLAIN\r\n");
		}
		_nntp_send(nntp, ".\r\n");
	} else if (!strcasecmp(command, "STARTTLS")) {
		REQUIRE_NO_ARGS(s);
		if (!ssl_available()) {
			nntp_send(nntp, NNTP_ERR_STARTTLS, "STARTTLS may not be used");
		} else if (bbs_io_transform_active(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION)) {
			/* RFC 8054 2.2.2: MUST reply with 502 if STARTTLS received while compression already active */
			nntp_send(nntp, NNTP_ERR_ACCESS, "STARTTLS may not be activated after COMPRESS");
		} else if (!nntp->node->secure) {
			nntp_send(nntp, NNTP_CONT_STARTTLS, "Ready to start TLS");
			/* RFC 4642 */
			bbs_debug(3, "Starting TLS\n");
			if (bbs_node_starttls(nntp->node)) {
				return -1; /* Just abort */
			}
			free_if(nntp->currentgroup);
			nntp->currentarticle = 0;
			bbs_readline_flush(rldata); /* Prevent STARTTLS command injection by resetting the buffer after TLS upgrade */
		} else {
			nntp_send(nntp, NNTP_ERR_ACCESS, "Already using TLS");
		}
	} else if (!strcasecmp(command, "COMPRESS")) {
		REQUIRE_ARGS(s);
		if (!strcasecmp(s, "DEFLATE")) {
			if (!deflate_compression_available()) {
				nntp_send(nntp, NNTP_FAIL_ACTION, "Compression unavailable");
			} else if (bbs_io_transform_active(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION)) {
				nntp_send(nntp, NNTP_ERR_ACCESS, "DEFLATE already enabled");
			} else if (!bbs_io_transform_possible(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION)) {
				nntp_send(nntp, NNTP_FAIL_ACTION, "Can't enable compression");
			} else {
				/* Go ahead and enable it */
				int orig_wfd = nntp->node->wfd;
				int err = bbs_io_transform_setup(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION, TRANSFORM_SERVER, &nntp->node->rfd, &nntp->node->wfd, NULL);
				if (err) {
					nntp_send(nntp, NNTP_FAIL_ACTION, "Can't enable compression");
				} else {
					/* We still need to reply with an OK before compression is active.
					 * Since node->wfd has already been updated, manually write to the original file descriptor (which now sits post-compression).
					 * Normally, this would be a bad idea, since we'd intersperse uncompressed data with compressed data managed by zlib,
					 * but this should be before we've sent anything compressed. */
					_nntp_send_fd(nntp, orig_wfd, "%d Compression active\r\n", NNTP_OK_COMPRESS);
					/* XXX As with IMAP, the RFC optionally recommends flushing dictionaries at particular points, though we do not at the moment.
					 * Unlike IMAP, NNTP is less likely to encounter large uncompressible blobs (e.g. attachments).
					 * An additional suggestion is to flush the dictionary when switching between public (Usenet) and private groups/articles. */
				}
			}
		} else {
			nntp_send(nntp, NNTP_ERR_UNAVAILABLE, "Unknown compression method");
		}
	} else if (!strcasecmp(command, "DATE")) {
		char datestr[15];
		time_t timenow;
		struct tm nowtime;
		REQUIRE_NO_ARGS(s);
		timenow = time(NULL);
		gmtime_r(&timenow, &nowtime);
		strftime(datestr, sizeof(datestr), "%Y%m%d%H%M%S", &nowtime); /* yyyymmddhhmmss */
		nntp_send(nntp, NNTP_INFO_DATE, "%s", datestr);
	} else if (!strcasecmp(command, "HELP")) {
		REQUIRE_NO_ARGS(s);
		nntp_send(nntp, NNTP_INFO_HELP, "Legal commands");
		/* Alphabetically sorted list of commands: */
		_nntp_send(nntp, " ARTICLE [message-ID|number]\r\n");
		_nntp_send(nntp, " AUTHINFO USER name|PASS password\r\n");
		_nntp_send(nntp, " BODY [message-ID|number]\r\n");
		_nntp_send(nntp, " CAPABILITIES\r\n");
		if (nntp->mode == NNTP_MODE_TRANSIT) {
			_nntp_send(nntp, " CHECK message-ID\r\n");
		}
		_nntp_send(nntp, " COMPRESS DEFLATE\r\n");
		_nntp_send(nntp, " DATE\r\n");
		_nntp_send(nntp, " GROUP newsgroup\r\n");
		_nntp_send(nntp, " HDR header [message-ID|range]\r\n");
		_nntp_send(nntp, " HEAD [message-ID|number]\r\n");
		_nntp_send(nntp, " HELP\r\n");
		_nntp_send(nntp, " IHAVE message-ID\r\n");
		_nntp_send(nntp, " LAST\r\n");
		_nntp_send(nntp, " LIST [ACTIVE [wildmat]|ACTIVE.TIMES [wildmat]|COUNT [wildmat]|DISTRIB.PATS|DISTRIBUTIONS|MODERATORS|MOTD|NEWSGROUPS [wildmat]|HEADERS [MSGID|RANGE]|OVERVIEW.FMT|SUBSCRIPTIONS [wildmat]]\r\n");
		_nntp_send(nntp, " LISTGROUP [newsgroup [range]]\r\n");
		if (nntp->mode == NNTP_MODE_TRANSIT) {
			_nntp_send(nntp, " MODE READER|STREAM\r\n");
		} else {
			_nntp_send(nntp, " MODE READER\r\n");
		}
		_nntp_send(nntp, " NEWGROUPS [yy]yymmdd hhmmss [GMT]\r\n");
		_nntp_send(nntp, " NEWNEWS wildmat [yy]yymmdd hhmmss [GMT]\r\n");
		_nntp_send(nntp, " NEXT\r\n");
		_nntp_send(nntp, " OVER [range]\r\n");
		_nntp_send(nntp, " POST\r\n");
		_nntp_send(nntp, " QUIT\r\n");
		_nntp_send(nntp, " STARTTLS\r\n");
		_nntp_send(nntp, " STAT [message-ID|number]\r\n");
		if (nntp->mode == NNTP_MODE_TRANSIT) {
			_nntp_send(nntp, " TAKETHIS message-ID\r\n");
		}
		_nntp_send(nntp, " XHDR header [message-ID|range]\r\n");
		_nntp_send(nntp, " XOVER [range]\r\n");
		_nntp_send(nntp, " XPAT header message-ID|range pattern [pattern ...]\r\n");
		_nntp_send(nntp, " XSECRET username password\r\n");
		_nntp_send(nntp, ".\r\n");
	} else if (!strcasecmp(command, "XSECRET")) {
		/* XSECRET appears in RFC 3977, in passing with an example, but this is not a documented or official extension. It is not even supported by INN. */
		int res;
		char *user, *pass, *domain;

		if (!nntp->node->secure && require_secure_login) {
			nntp_send(nntp, NNTP_FAIL_PRIVACY_NEEDED, "Must STARTTLS first");
			return 0;
		} else if (bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, NNTP_ERR_ACCESS, "Already authenticated");
			return 0;
		}
		user = strsep(&s, " ");
		pass = s;
		REQUIRE_ARGS(user);
		REQUIRE_ARGS(pass);
		/* Strip the domain, if present,
		 * but the domain must match our domain, if present. */
		domain = strchr(user, '@');
#define improper_auth_hostname(domain) (strlen_zero(domain) || !(!strcasecmp(domain, newsname) || !strcasecmp(domain, bbs_hostname())))
		if (domain) {
			*domain++ = '\0';
			if (improper_auth_hostname(domain)) {
				nntp_send(nntp, NNTP_FAIL_AUTHINFO_BAD, "Authorization rejected");
				return 0;
			}
		}
		res = bbs_authenticate(nntp->node, user, pass);
		bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
		if (res) {
			nntp_send(nntp, NNTP_FAIL_AUTHINFO_BAD, "Authorization rejected"); /* XXX As this extension is not documented, I do not know what the intended response code on error was */
			return 0;
		}
		nntp_send(nntp, 290, "Password for %s accepted", user); /* XXX This is the response code in the RFC example */
		RECHECK_TRANSIT_ACL(nntp);
	} else if (!strcasecmp(command, "AUTHINFO")) {
		/* RFC 4643 AUTHINFO */
		int res;
		char *pass, *domain;

		if (!nntp->node->secure && require_secure_login) {
			nntp_send(nntp, NNTP_FAIL_PRIVACY_NEEDED, "Must STARTTLS first");
			return 0;
		} else if (bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, NNTP_ERR_ACCESS, "Already authenticated");
			return 0;
		} else if (bbs_io_transform_active(&nntp->node->trans, TRANSFORM_DEFLATE_COMPRESSION)) {
			nntp_send(nntp, NNTP_ERR_ACCESS, "AUTHINFO not allowed after COMPRESS"); /* RFC 8054 2.2.2 */
			return 0;
		}

		command = strsep(&s, " ");
		if (!strcasecmp(command, "USER")) {
			free_if(nntp->user);
			REQUIRE_ARGS(s);
			nntp->user = strdup(s);
			nntp_send(nntp, NNTP_CONT_AUTHINFO, "Password required");
		} else if (!strcasecmp(command, "PASS")) {
			pass = s;
			if (!nntp->user) {
				nntp_send(nntp, NNTP_FAIL_AUTHINFO_REJECT, "Authentication commands issued out of sequence");
				return 0;
			}
			REQUIRE_ARGS(pass);
			/* Strip the domain, if present,
			 * but the domain must match our domain, if present. */
			domain = strchr(nntp->user, '@');
			if (domain) {
				*domain++ = '\0';
				if (improper_auth_hostname(domain)) {
					nntp_send(nntp, NNTP_FAIL_AUTHINFO_BAD, "Authorization rejected");
					return 0;
				}
			}
			res = bbs_authenticate(nntp->node, nntp->user, pass);
			free_if(nntp->user);
			bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
			if (res) {
				nntp_send(nntp, NNTP_FAIL_AUTHINFO_BAD, "Authentication failed");
				return 0;
			}
			nntp_send(nntp, NNTP_OK_AUTHINFO, "Authentication accepted");
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
					nntp_send(nntp, NNTP_FAIL_AUTHINFO_BAD, "Authentication failed");
					return 0;
				}
				nntp_send(nntp, NNTP_OK_AUTHINFO, "Authentication accepted");
				RECHECK_TRANSIT_ACL(nntp);
			} else {
				/* RFC 4643 says we MUST implement the DIGEST-MD5 mechanism, but, well, we don't. */
				nntp_send(nntp, NNTP_ERR_UNAVAILABLE, "Mechanism not recognized");
			}
		} else {
			nntp_send(nntp, NNTP_ERR_SYNTAX, "Unknown AUTHINFO command");
		}
	} else if (!strcasecmp(command, "LIST")) {
		const char *keyword = strsep(&s, " ");
		if (handle_list(nntp, keyword, s) < 0) {
			return -1;
		}
	} else if (!strcasecmp(command, "GROUP")) { /* Note, this command can be used in either mode */
		int low, high, count;
		if (!group_exists(s)) {
			nntp_send(nntp, NNTP_FAIL_BAD_GROUP, "%s is unknown", s);
			return 0;
		}
		/* For future commands which require a group, we don't check read ACL since we check it here, before changing the group */
		if (!ACL_ALLOWED(nntp, s, NNTP_ACL_READ)) {
			nntp_send(nntp, NNTP_ERR_ACCESS, "Read access denied");
			return 0;
		}
		if (group_get_stats(s, &high, &low, &count)) {
			nntp_send(nntp, NNTP_FAIL_ACTION, "Error changing group");
			return 0;
		}
		REPLACE(nntp->currentgroup, s);
		nntp_send(nntp, NNTP_OK_GROUP, "%d %d %d %s", count, low, high, s);
		nntp->currentarticle = low;
	} else if (!strcasecmp(command, "LISTGROUP")) {
		int low, high, count;
		int min = 1, max = NNTP_MAX_ARTICLE_NUMBER;
		const char *groupname;
		if (!strlen_zero(s)) {
			groupname = strsep(&s, " ");
			if (!strlen_zero(s)) {
				parse_min_max(s, &min, &max, '-'); /* Even if it fails, we return an empty 211 response */
			}
		} else {
			REQUIRE_GROUP();
			groupname = nntp->currentgroup;
		}
		if (strlen_zero(groupname) || !group_exists(groupname)) {
			nntp_send(nntp, NNTP_FAIL_BAD_GROUP, "%s is unknown", groupname);
			return 0;
		}
		/* For future commands which require a group, we don't check read ACL since we check it here, before changing the group */
		if (!ACL_ALLOWED(nntp, groupname, NNTP_ACL_READ)) {
			nntp_send(nntp, NNTP_ERR_ACCESS, "Read access denied");
			return 0;
		}
		if (group_get_stats(groupname, &high, &low, &count)) {
			nntp_send(nntp, NNTP_FAIL_ACTION, "Error changing group");
			return 0;
		}
		/* If the group didn't change, no need to free/strdup.
		 * This optimization also allows us to use groupname after the REPLACE call,
		 * as if we had replaced when it wasn't necessary, groupname would no longer be valid memory. */
		if (!nntp->currentgroup || strcmp(nntp->currentgroup, groupname)) {
			REPLACE(nntp->currentgroup, groupname); /* We still change the group (as with GROUP) */
		}
		nntp_send(nntp, NNTP_OK_GROUP, "%d %d %d %s list follows", count, low, high, groupname);
		if (spool_group_list_articles(nntp, groupname, min, max)) {
			_nntp_send(nntp, ".\r\n"); /* On success, we send the trailing ., on failure we do not, so we do it here */
		}
		nntp->currentarticle = low; /* Always the first article, even if not in the provided range */
	} else if (!strcasecmp(command, "NEWGROUPS")) {
		time_t epoch;
		int res;
		char *date, *time, *gmt;
		date = strsep(&s, " ");
		time = strsep(&s, " ");
		gmt = s;
		REQUIRE_ARGS(date);
		REQUIRE_ARGS(time);
		epoch = parse_datetime(date, time, !strlen_zero(gmt) && !strcmp(gmt, "GMT"));
		if (epoch <= 0) {
			nntp_send(nntp, NNTP_ERR_SYNTAX, "Invalid time argument");
			return 0;
		}
		ACL_RDLOCK(nntp);
		res = active_group_list_newgroups(nntp, epoch);
		ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, NNTP_ERR_UNAVAILABLE, "Data item not available");
			return 0;
		}
	} else if (!strcasecmp(command, "NEWNEWS")) {
		time_t epoch;
		char *wildmat, *date, *time, *gmt;
		wildmat = strsep(&s, " ");
		date = strsep(&s, " ");
		time = strsep(&s, " ");
		gmt = s;
		REQUIRE_ARGS(wildmat);
		REQUIRE_ARGS(date);
		REQUIRE_ARGS(time);
		epoch = parse_datetime(date, time, !strlen_zero(gmt) && !strcmp(gmt, "GMT"));
		if (epoch <= 0) {
			nntp_send(nntp, NNTP_ERR_SYNTAX, "Invalid time argument");
			return 0;
		}
		nntp_send(nntp, NNTP_OK_NEWNEWS, "List of new articles by message-ID follows");
		ACL_RDLOCK(nntp);
		history_newnews(nntp, wildmat, epoch);
		ACL_UNLOCK(nntp);
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
				nntp_send(nntp, NNTP_FAIL_ARTNUM_INVALID, "No article(s) selected");
				return 0;
			}
			min = max = nntp->currentarticle;
		}
		/* ACL not needed here, since XOVER can only be used with currently selected group */
		if (spool_group_overview(nntp, NULL, nntp->currentgroup, min, max)) {
			nntp_send(nntp, NNTP_FAIL_ARTNUM_INVALID, "No article(s) selected");
		}
	} else if (!strcasecmp(command, "OVER")) {
/* If we are using a Message-ID instead of an article number, the spool will need to query ACLs for the group containing the article */
#define CMD_ACL_RDLOCK(nntp) if (msgid) { ACL_RDLOCK(nntp); }
#define CMD_ACL_UNLOCK(nntp) if (msgid) { ACL_UNLOCK(nntp); }
#define IS_MESSAGEID_RATHER_THAN_RANGE(s) (*s == '<')
		/* RFC 3977 OVER */
		int res, min = 0, max = 0;
		const char *msgid = NULL;
		REQUIRE_READER();
		if (!strlen_zero(s)) {
			if (IS_MESSAGEID_RATHER_THAN_RANGE(s)) {
				msgid = s;
			} else {
				REQUIRE_GROUP();
				if (parse_min_max(s, &min, &max, '-')) {
					nntp_send(nntp, NNTP_FAIL_ARTNUM_NOTFOUND, "Invalid range");
					return 0;
				}
			}
		} else {
			REQUIRE_GROUP();
			if (!nntp->currentarticle) {
				nntp_send(nntp, NNTP_FAIL_ARTNUM_INVALID, "Current article number is invalid");
				return 0;
			}
			min = max = nntp->currentarticle;
		}
		CMD_ACL_RDLOCK(nntp);
		res = spool_group_overview(nntp, msgid, nntp->currentgroup, min, max);
		CMD_ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, msgid ? NNTP_FAIL_MSGID_NOTFOUND : NNTP_FAIL_ARTNUM_NOTFOUND, "%s",
				msgid ? "No article with that Message-ID" : "No articles in that range");
		}
	} else if (!strcasecmp(command, "HDR") || !strcasecmp(command, "XHDR") || !strcasecmp(command, "XPAT")) {
		/* Unlike XOVER/OVER, there are very few differences between XHDR/HDR, since XHDR also supports requests using a Message-ID. Differences:
		 * - The response code number is different (221 for XHDR, 225 for HDR).
		 * - Metadata is not supported by XHDR.
		 * XPAT takes XHDR one step further by allowing for pattern(s) to be specified that must match.
		 */
		int res, min = 0, max = 0;
		char *hdr, *arg2, *pattern = NULL;
		const char *msgid = NULL;
		enum nntp_hdr_cmd cmd = command[0] == 'X' ? command[1] == 'P' ? NNTP_XPAT : NNTP_XHDR : NNTP_HDR;
		if (cmd == NNTP_HDR) {
			REQUIRE_READER(); /* XHDR and XPAT can be used by non-readers */
		}
		hdr = strsep(&s, " ");
		arg2 = strsep(&s, " ");
		pattern = s;
		REQUIRE_ARGS(hdr);
		if (!strlen_zero(arg2)) {
			if (IS_MESSAGEID_RATHER_THAN_RANGE(arg2)) {
				msgid = arg2;
			} else {
				REQUIRE_GROUP();
				if (parse_min_max(arg2, &min, &max, '-')) {
					nntp_send(nntp, NNTP_FAIL_ARTNUM_NOTFOUND, "Invalid range");
					return 0;
				}
			}
		} else {
			REQUIRE_GROUP();
			if (!nntp->currentarticle) {
				nntp_send(nntp, NNTP_FAIL_ARTNUM_INVALID, "Current article number is invalid");
				return 0;
			}
			min = max = nntp->currentarticle;
		}
		if (cmd == NNTP_XPAT) {
			REQUIRE_ARGS(s);
		}

		CMD_ACL_RDLOCK(nntp);
		res = spool_group_overview_header(nntp, hdr, msgid, nntp->currentgroup, min, max, cmd, pattern);
		CMD_ACL_UNLOCK(nntp);
		if (res) {
			if (res == 2) {
				/* We only use overview to satisfy HDR requests, so if it's not a field available in overview, we reject it */
				nntp_send(nntp, NNTP_ERR_UNAVAILABLE, "HDR not permitted on %s", hdr);
			} else {
				nntp_send(nntp, msgid ? NNTP_FAIL_MSGID_NOTFOUND : NNTP_FAIL_ARTNUM_NOTFOUND, "%s",
					msgid ? "No article with that Message-ID" : "No articles in that range");
			}
		}
	} else if (!strcasecmp(command, "ARTICLE")) {
#define PARSE_ARTICLENUM_MSGID() \
	artnum = atoi(s); \
	if (!artnum) { \
		if (!IS_MESSAGEID_RATHER_THAN_RANGE(s)) { \
			nntp_send(nntp, NNTP_FAIL_ARTNUM_NOTFOUND, "No such article"); \
			return 0; \
		} \
	}

/* Parse args for ARTICLE, HEAD, BODY, and STAT */
#define PARSE_ARTICLE_ARGS() \
	REQUIRE_READER(); \
	if (!nntp->currentgroup) { \
		REQUIRE_ARGS(s); \
	} \
	if (!strlen_zero(s)) { \
		PARSE_ARTICLENUM_MSGID(); \
		if (artnum) { /* If we specify an article number, must have a group selected */ \
			REQUIRE_GROUP(); \
		} \
	} else { /* If no arguments at all, current article (must have a group selected) */ \
		REQUIRE_GROUP(); \
		artnum = nntp->currentarticle; \
	}

/* Only difference from CMD_ACL_RDLOCK is here we check for NOT article range rather than IS Message-ID */
#define ARTICLE_ACL_RDLOCK(nntp) if (!artnum) { ACL_RDLOCK(nntp); }
#define ARTICLE_ACL_UNLOCK(nntp) if (!artnum) { ACL_UNLOCK(nntp); }

		int res, artnum;
		PARSE_ARTICLE_ARGS();
		/* We pass in the current group, even if searching by message ID.
		 * This way, if an article is linked in multiple groups,
		 * we can return the article number for the current group
		 * (the default is otherwise to use the first group to which the article was linked). */
		
		ARTICLE_ACL_RDLOCK(nntp);
		res = spool_article_send(nntp, SEND_HEADERS | SEND_BODY, artnum ? NULL : s, nntp->currentgroup, artnum);
		ARTICLE_ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, artnum ? NNTP_FAIL_ARTNUM_NOTFOUND : NNTP_FAIL_MSGID_NOTFOUND, "No such article"); /* Only on failure, do we need to send a response here */
		} else if (artnum) {
			nntp->currentarticle = artnum; /* If we explicitly specified an article number (not with Message-ID) and it exists, update current article number */
		}
	} else if (!strcasecmp(command, "HEAD")) {
		int res, artnum;
		PARSE_ARTICLE_ARGS();
		ARTICLE_ACL_RDLOCK(nntp);
		res = spool_article_send(nntp, SEND_HEADERS, artnum ? NULL : s, nntp->currentgroup, artnum);
		ARTICLE_ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, artnum ? NNTP_FAIL_ARTNUM_NOTFOUND : NNTP_FAIL_MSGID_NOTFOUND, "No such article");
		} else if (artnum) {
			nntp->currentarticle = artnum;
		}
	} else if (!strcasecmp(command, "BODY")) {
		int res, artnum;
		PARSE_ARTICLE_ARGS();
		ARTICLE_ACL_RDLOCK(nntp);
		res = spool_article_send(nntp, SEND_BODY, artnum ? NULL : s, nntp->currentgroup, artnum);
		ARTICLE_ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, artnum ? NNTP_FAIL_ARTNUM_NOTFOUND : NNTP_FAIL_MSGID_NOTFOUND, "No such article");
		} else if (artnum) {
			nntp->currentarticle = artnum;
		}
	} else if (!strcasecmp(command, "STAT")) {
		int res, artnum;
		PARSE_ARTICLE_ARGS();
		ARTICLE_ACL_RDLOCK(nntp);
		res = spool_article_stat(nntp, artnum ? NULL : s, nntp->currentgroup, artnum);
		ARTICLE_ACL_UNLOCK(nntp);
		if (res) {
			nntp_send(nntp, artnum ? NNTP_FAIL_ARTNUM_NOTFOUND : NNTP_FAIL_MSGID_NOTFOUND, "No such article");
		} else if (artnum) {
			nntp->currentarticle = artnum;
		}
	} else if (!strcasecmp(command, "LAST")) {
		int last;
		char msgid[NNTP_BUFSIZ];
		REQUIRE_READER();
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, NNTP_FAIL_ARTNUM_INVALID, "Current article number is invalid");
			return 0;
		}
		spool_group_seek(nntp->currentgroup, nntp->currentarticle, &last, -1, msgid, sizeof(msgid));
		if (last == nntp->currentarticle) {
			nntp_send(nntp, NNTP_FAIL_PREV, "No previous article in group");
			return 0;
		}
		nntp->currentarticle = last;
		nntp_send(nntp, NNTP_OK_STAT, "%d %s", last, msgid);
	} else if (!strcasecmp(command, "NEXT")) {
		int next;
		char msgid[NNTP_BUFSIZ];
		REQUIRE_READER();
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, NNTP_FAIL_ARTNUM_INVALID, "Current article number is invalid");
			return 0;
		}
		spool_group_seek(nntp->currentgroup, nntp->currentarticle, &next, +1, msgid, sizeof(msgid));
		if (next == nntp->currentarticle) {
			nntp_send(nntp, NNTP_FAIL_NEXT, "No next article in group");
			return 0;
		}
		nntp->currentarticle = next;
		nntp_send(nntp, NNTP_OK_STAT, "%d %s", next, msgid);
	} else if (!strcasecmp(command, "POST")) {
		REQUIRE_READER();
		if (!bbs_user_is_registered(nntp->node->user) && !guests_can_post_at_all()) {
			nntp_send(nntp, NNTP_FAIL_AUTH_NEEDED, "Must authenticate first");
			return 0;
		}
		return receive_article(nntp, rldata, NULL, 0);
	} else if (!strcasecmp(command, "IHAVE")) {
		REQUIRE_TRANSIT();
		REQUIRE_ARGS(s); /* Do not strip <> around Message-ID, as that is part of the Message-ID */
		if (history_messageid_exists(s)) {
			nntp_rx_reply2_streaming(nntp, 0, 0, s, LOG_DUPLICATE, NNTP_FAIL_IHAVE_REFUSE, "Duplicate");
			return 0;
		}
		safe_strncpy(scratch, s, sizeof(scratch)); /* duplicate into scratch buf since receive_article will call bbs_readline and clobber the buffer this is in */
		return handle_ihave_takethis(nntp, rldata, scratch, 0);
	} else if (!strcasecmp(command, "TAKETHIS")) {
		REQUIRE_TRANSIT();
		REQUIRE_ARGS(s);
		safe_strncpy(scratch, s, sizeof(scratch));
		return handle_ihave_takethis(nntp, rldata, scratch, 1);
	} else if (!strcasecmp(command, "CHECK")) {
		REQUIRE_TRANSIT();
		REQUIRE_ARGS(s);
		handle_check(nntp, s);
	} else {
		nntp_send(nntp, NNTP_ERR_COMMAND, "Unknown command");
	}
	return 0;
}

static void handle_client(struct nntp_session *nntp)
{
	/* This is a way more than NNTP_MAX_LINE_LENGTH, but this matches the buffer size used when sucking articles,
	 * as a lot of articles exceed the 512-byte limit. A separate limit enforces a line length limit in
	 * nntp_read_article, but a large buffer here avoids buffer exhaustion for routine articles. */
	char buf[8192];
	struct readline_data rldata;
	int posting_allowed = can_post_at_all();

	/* If we are trying to unload, reject new connections */
	if (bbs_module_is_shutting_down()) {
		nntp_send(nntp, NNTP_FAIL_TERMINATING, "Server currently unavailable");
		return;
	}

	bbs_readline_init(&rldata, buf, sizeof(buf));
	/* 200 means client can post, 201 means not, but this is not a perfect distinction (see RFC) */
	nntp_send(nntp, posting_allowed ? NNTP_OK_BANNER_POST : NNTP_OK_BANNER_NOPOST,
		"%s Newsgroup Service Ready, %s", newsname, posting_allowed ? "posting allowed" : "posting prohibited");

	SET_BITFIELD(nntp->inpeer_any, authorized_inpeer_for_any_groups(nntp)); /* Cache whether this client has an inpeer ACL */

	/* Default mode is transit mode (NNTP_MODE_TRANSIT) for mode-switching servers */
	for (;;) {
		/* The timeout length is mainly motivated by other peers keeping an idle connection open to send us article.
		 * This avoids the overhead of setting up a connection each time if articles are frequently sent.
		 * If after a few minutes, we haven't received any articles, we can probably go ahead and close it. */
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
		if (nntp->node->disconnected) {
			bbs_debug(5, "Node %d has disconnected, aborting\n", nntp->node->id);
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

	/* Connections to the default NNTP port (119) are initially transit unless MODE READER is used to switch to reader mode.
	 * The secure ports are only either reader or transit depending on the port. */
	nntp_handler(node, !strcmp(node->protname, "NNTPS"), !strcmp(node->protname, "NNTPS") ? NNTP_MODE_READER: NNTP_MODE_TRANSIT);
	bbs_node_exit(node);
	return NULL;
}

static struct bbs_unit_test tests[] =
{
	{ "NNTP Wildmats", test_wildmats },
	{ "NNTP Poison", test_poison },
	{ "NNTP Date Parsing", test_dateparsing },
	{ "NNTP Moderator Submission Templates", test_moderator_templates },
	{ "NNTP Distribution Matching", test_distributions },
};

static struct bbs_cli_entry cli_commands_nntp[] = {
	BBS_CLI_COMMAND(cli_newgroup, "news newgroup", 2, "Create a new newsgroup", NULL),
	BBS_CLI_COMMAND(cli_rmgroup, "news rmgroup", 3, "Remove a newsgroup", "news rmgroup <group> [confirm]"),
	BBS_CLI_COMMAND(cli_setstatus, "news setstatus", 4, "Edit posting status for a newsgroup", "news setstatus <group> <y/n/m>"),
	BBS_CLI_COMMAND(cli_delarticle, "news delarticle", 4, "Delete an article", "news delarticle <group> <article number>"),
	BBS_CLI_COMMAND(cli_expire, "news expire", 2, "Remove expired articles from the spool (optionally just for one group)", "news expire <group>"),
	BBS_CLI_COMMAND(cli_fgexpire, "news fgexpire", 2, "Remove expired articles from the spool (optionally just for one group), in foreground", "news expire <group>"),
	BBS_CLI_COMMAND(cli_feedflush, "news feedflush", 2, "Flush queued articles for feed(s)", "news feedflush [<site>]"),
	BBS_CLI_COMMAND(cli_feedstats, "news feedstats", 2, "Show outgoing feed stats", "news feedstats [<site>]"),
};

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	unsigned int utmp;

	cfg = bbs_config_load("net_nntp.conf", 1);
	if (!cfg) {
		return -2;
	}

	if (bbs_config_val_set_path(cfg, "general", "newsdir", newsdir, sizeof(newsdir))) {
		bbs_config_unlock(cfg);
		bbs_error("Invalid or missing newsdir in [general], declining to load\n");
		return -2;
	}

	/* These settings needed to be loaded before calling history_init() */
	if (!bbs_config_val_set_uint(cfg, "history", "bloom_maxmem", &utmp)) {
		history_bloom_maxmem = (size_t) utmp;
	}
	if (!bbs_config_val_set_uint(cfg, "history", "bloom_maxfpinv", &utmp)) {
		history_bloom_maxfpinv = utmp;
	}
	bbs_config_val_set_true(cfg, "articles", "spoolcompression", &spool_compression);

	/* Note: nntp_suckfeed_init needs to be initialized before the bulk of load_config() so the list is ready to receive items when processing the config
	 * However, it also needs to be after loading newsdir */
	if (active_init()) {
		bbs_config_unlock(cfg);
		return -2;
	} else if (spool_init()) {
		active_cleanup();
		bbs_config_unlock(cfg);
		return -2;
	} else if (history_init()) {
		active_cleanup();
		spool_init();
		bbs_config_unlock(cfg);
		return -2;
	} else if (nntp_suckfeed_init()) {
		active_cleanup();
		spool_init();
		history_cleanup();
		bbs_config_unlock(cfg);
		return -2;
	}

	/* Remaining general settings */
	if (bbs_config_val_set_str(cfg, "general", "newsname", newsname, sizeof(newsname))) {
		if (strlen_zero(bbs_hostname())) {
			bbs_config_unlock(cfg);
			bbs_error("A BBS hostname in nodes.conf or newsname in net_nntp.conf is required for newsgroup services\n");
			return -1;
		}
		safe_strncpy(newsname, bbs_hostname(), sizeof(newsname));
	}
	bbs_config_val_set_str(cfg, "general", "newsorg", newsorg, sizeof(newsorg));

	/* NNTP */
	bbs_config_val_set_true(cfg, "nntp", "enabled", &nntp_enabled);
	bbs_config_val_set_port(cfg, "nntp", "port", &nntp_port);

	/* NNTPS */
	bbs_config_val_set_true(cfg, "nntps", "enabled", &nntps_enabled);
	bbs_config_val_set_port(cfg, "nntps", "port", &nntps_port);

	/* NNSP */
	bbs_config_val_set_true(cfg, "nnsp", "enabled", &nnsp_enabled);
	bbs_config_val_set_port(cfg, "nnsp", "port", &nnsp_port);

	/* Article settings */
	bbs_config_val_set_uint(cfg, "articles", "maxsize", &max_article_size);
	if (!bbs_config_val_set_uint(cfg, "articles", "maxgroups", &max_groups)) {
		if (max_groups > MAX_ARTICLE_GROUPS) {
			bbs_warning("maxgroups %u capped at %d instead\n", max_groups, MAX_ARTICLE_GROUPS);
			max_groups = MAX_ARTICLE_GROUPS;
		}
	}
	if (!bbs_config_val_set_uint(cfg, "articles", "maxacceptage", &max_accept_age)) {
		if (max_accept_age < 3) {
			/* Rejection interval SHOULD NOT be any shorter than 72 hours (RFC 5537 3.5) */
			bbs_warning("maxacceptage '%u' invalid, floored at 3\n", max_accept_age);
			max_accept_age = 3;
		}
	}
	bbs_config_val_set_uint(cfg, "articles", "minhistory", &min_history);
	bbs_config_val_set_uint(cfg, "articles", "minlines", &min_lines);
	bbs_config_val_set_uint(cfg, "articles", "maxlines", &max_lines);

	/* Reader settings */
	bbs_config_val_set_true(cfg, "readers", "requiresecurelogin", &require_secure_login);
	bbs_config_val_set_true(cfg, "readers", "checkidentity", &check_identity);
	bbs_config_val_set_true(cfg, "readers", "allowinvalid", &allow_invalid);
	bbs_config_val_set_uint(cfg, "readers", "maxpostsize", &max_post_size);
	bbs_config_val_set_uint(cfg, "readers", "maxpostgroups", &max_post_groups);
	bbs_config_val_set_true(cfg, "readers", "postinghost", &injection_add_posting_host);
	bbs_config_val_set_str(cfg, "readers", "complaints", complaints_addr, sizeof(complaints_addr));

	bbs_config_val_set_true(cfg, "peers", "requiretls", &requirerelaytls);
	bbs_config_val_set_true(cfg, "peers", "keepjunk", &keepjunk);
	bbs_config_val_set_true(cfg, "peers", "xrefslave", &xref_slave);

#define SKIP_SECTION(sectname) if (!strcasecmp(bbs_config_section_name(section), sectname)) { continue; }

	RWLIST_WRLOCK(&acls);
	RWLIST_WRLOCK(&inpeers);
	RWLIST_WRLOCK(&sites);
	RWLIST_WRLOCK(&distributions);
	RWLIST_WRLOCK(&distrib_pats);
	RWLIST_WRLOCK(&moderators);
	RWLIST_WRLOCK(&kill_patterns);
	RWLIST_WRLOCK(&subscriptions);

	while ((section = bbs_config_walk(cfg, section))) {
		/* Skip sections already processed above */
		SKIP_SECTION("general");
		SKIP_SECTION("history");
		SKIP_SECTION("nntp");
		SKIP_SECTION("nntps");
		SKIP_SECTION("nnsp");
		SKIP_SECTION("peers");
		if (!strcasecmp(bbs_config_section_name(section), "articles")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				const char *key = bbs_keyval_key(keyval), *val = bbs_keyval_val(keyval);
				if (!strcasecmp(key, "poisongroups")) {
					safe_strncpy(poisongroups, val, sizeof(poisongroups));
				} else if (!strcasecmp(key, "poisonsites")) {
					safe_strncpy(poisonsites, val, sizeof(poisonsites));
				}
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "readers")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				const char *key = bbs_keyval_key(keyval), *val = bbs_keyval_val(keyval);
				if (!strcasecmp(key, "postingaccount")) {
					if (!strcasecmp(val, "obfuscate")) {
						injection_add_posting_account = INJECTION_POSTING_ACCOUNT_OBFUSCATED;
					} else if (S_TRUE(val)) {
						injection_add_posting_account = INJECTION_POSTING_ACCOUNT_USERNAME;
					} else {
						injection_add_posting_account = INJECTION_POSTING_ACCOUNT_HIDDEN;
					}
				}
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "motd")) {
			char *motdpos = motd;
			size_t motdleft = sizeof(motd);
			motd[0] = '\0'; /* Reset */
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				SAFE_FAST_APPEND(motd, sizeof(motd), motdpos, motdleft, "%s%s", motdpos > motd ? "\r\n" : "", bbs_keyval_val(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "subscriptions")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				if (stringlist_contains(&subscriptions, bbs_keyval_key(keyval))) {
					bbs_warning("Duplicate subscription '%s'\n", bbs_keyval_key(keyval));
				} else {
					stringlist_push(&subscriptions, bbs_keyval_key(keyval));
				}
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "distrib.pats")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_distrib_pat(bbs_keyval_key(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "distributions")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_distribution(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "moderators")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_moderator(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "incoming")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_inpeer(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "outgoing")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_site(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "kill")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				add_killpat(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		} else if (!strcasecmp(bbs_config_section_name(section), "retention")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				history_add_retention_pattern(bbs_keyval_key(keyval), bbs_keyval_val(keyval));
			}
		} else {
			/* The only config section type that isn't defined by the section name is user ACLs */
			const char *type = bbs_config_sect_val(section, "type");
			if (!type) {
				bbs_error("Unrecognized section name '%s' (add type=acl or type=suckfeed)\n", bbs_config_section_name(section));
			} else if (!strcasecmp(type, "acl")) {
				const char *guests = NULL, *userswm = NULL, *readwm = NULL, *postwm = NULL;
				int tmp, minreadpriv = 0, minpostpriv = 0, minapprovepriv = 1;
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
					} else if (!strcasecmp(key, "minapprovepriv")) {
						tmp = atoi(val);
						if (tmp < 0) {
							bbs_error("Invalid %s: %s\n", key, val);
						} else {
							minapprovepriv = tmp;
						}
					}
				}
				if (!guests && !userswm) {
					bbs_error("An ACL section must apply to at least either guests or users, ignoring [%s]\n", bbs_config_section_name(section));
					continue;
				}
				/* Create the ACL */
				load_acl(guests, userswm, readwm, postwm, minreadpriv, minpostpriv, minapprovepriv);
			} else if (!strcasecmp(type, "suckfeed")) {
				const char *server = NULL;
				const char *creator = NULL;
				int modereader = 0, starttls = 0, compress = 0;
				int autocreate = 0, xrefslave = 0;
				int maxactivity = 0, mincount = 0, minlow = 0;
				struct suck_feed *sf;
				while ((keyval = bbs_config_section_walk(section, keyval))) {
#define LOAD_NON_NEGATIVE_INT(setting) \
	else if (!strcasecmp(key, #setting)) { \
		setting = atoi(val); \
		if (setting < 0) { \
			bbs_warning("Invalid %s '%s'\n", #setting, val); \
			setting = 0; \
		} \
	}

					const char *key = bbs_keyval_key(keyval), *val = bbs_keyval_val(keyval);
					if (!strcasecmp(key, "type")) {
						continue;
					/* Suckfeed general settings */
					} else if (!strcasecmp(key, "creator")) {
						creator = val;
					} else if (!strcasecmp(key, "server")) {
						server = val;
					} else if (!strcasecmp(key, "modereader")) {
						modereader = S_TRUE(val);
					} else if (!strcasecmp(key, "starttls")) {
						starttls = S_TRUE(val);
					} else if (!strcasecmp(key, "compress")) {
						compress = S_TRUE(val);
					} else if (!strcasecmp(key, "autocreate")) {
						autocreate = S_TRUE(val);
					} else if (!strcasecmp(key, "xrefslave")) {
						xrefslave = S_TRUE(val);
					}
					/* Group filters */
					LOAD_NON_NEGATIVE_INT(maxactivity)
					LOAD_NON_NEGATIVE_INT(mincount)
					LOAD_NON_NEGATIVE_INT(minlow)
					else {
						continue; /* Everything else is a kill pattern or group pattern, skip for now */
					}
				}
				if (strlen_zero(server)) {
					bbs_error("Must specify server for suck feed %s\n", bbs_config_section_name(section));
					continue;
				}
				sf = nntp_suckfeed_create(bbs_config_section_name(section), creator, server, modereader, starttls, compress, autocreate, xrefslave, maxactivity, mincount, minlow);
				if (!sf) {
					continue;
				}
				/* If we succeeded, then load in the kill patterns and group patterns */
				while ((keyval = bbs_config_section_walk(section, keyval))) {
					const char *key = bbs_keyval_key(keyval), *val = bbs_keyval_val(keyval);
					if (!strcasecmp(key, "type") || !strcasecmp(key, "server") || !strcasecmp(key, "modereader") || !strcasecmp(key, "starttls") || !strcasecmp(key, "compress")) {
						continue; /* Skip general */
					} else if (!strcasecmp(key, "autocreate") || !strcasecmp(key, "xrefslave")) {
						continue; /* Skip general */
					} else if (!strcasecmp(key, "maxactivity") || !strcasecmp(key, "mincount") || !strcasecmp(key, "minlow")) {
						continue; /* Skip group filters */
					}
					/* Technically, we don't have the suck_feeds list locked at this point,
					 * but since we're still loading, there's no real harm yet
					 * with adding to the suck_feed without locking. Later, this would be illegal. */
					nntp_suckfeed_add_suckpat(sf, key, val); /* Group pattern */
				}
			} else {
				bbs_error("Unrecognized section type '%s'\n", type);
			}
		}
	}

	check_distributions();

	RWLIST_UNLOCK(&acls);
	RWLIST_UNLOCK(&inpeers);
	RWLIST_UNLOCK(&sites);
	RWLIST_UNLOCK(&distributions);
	RWLIST_UNLOCK(&distrib_pats);
	RWLIST_UNLOCK(&moderators);
	RWLIST_UNLOCK(&kill_patterns);
	RWLIST_UNLOCK(&subscriptions);

	bbs_config_unlock(cfg);
	return 0;
}

static void cleanup_lists(void)
{
	/* First, empty the site list, which will stop any article feeding.
	 * Then we can clean up the feed types themselves. */
	RWLIST_WRLOCK_REMOVE_ALL(&sites, entry, free_site);
	sites_cleanup_feed_types();

	nntp_suckfeed_cleanup();

	RWLIST_WRLOCK_REMOVE_ALL(&acls, entry, free_acl);
	RWLIST_WRLOCK_REMOVE_ALL(&inpeers, entry, free);
	RWLIST_WRLOCK_REMOVE_ALL(&distributions, entry, free);
	RWLIST_WRLOCK_REMOVE_ALL(&distrib_pats, entry, free);
	RWLIST_WRLOCK_REMOVE_ALL(&moderators, entry, free);
	RWLIST_WRLOCK_REMOVE_ALL(&kill_patterns, entry, free);
	stringlist_empty_destroy(&subscriptions);
}

static void cleanup_subsystems(void)
{
	active_cleanup();
	spool_cleanup();
	if (expire_thread) {
		bbs_pthread_join(expire_thread, NULL);
	}
	history_cleanup();
}

static int load_module(void)
{
	char newslogpath[512];
	char postlogpath[512];
	int res;

	thismodule = BBS_MODULE_SELF;

	RWLIST_HEAD_INIT(&acls);
	RWLIST_HEAD_INIT(&inpeers);
	RWLIST_HEAD_INIT(&sites);
	RWLIST_HEAD_INIT(&distributions);
	RWLIST_HEAD_INIT(&distrib_pats);
	RWLIST_HEAD_INIT(&moderators);
	RWLIST_HEAD_INIT(&kill_patterns);
	stringlist_init(&subscriptions);

	res = load_config();
	if (res) {
		if (res == -2) {
			return -1; /* We didn't get around to init'ing anything so just abort directly */
		}
		goto cleanup;
	}

	if (!nntp_enabled && !nntps_enabled && !nnsp_enabled) {
		bbs_debug(3, "Neither NNTP nor NNTPS nor NNSP is enabled, declining to load\n");
		goto cleanup; /* Nothing is enabled */
	}
	if (nntps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, NNTPS may not be used\n");
		goto cleanup;
	}

	bbs_rwlock_init(&nntp_lock, NULL);

	if (init_builtin_groups()) {
		bbs_rwlock_destroy(&nntp_lock);
		goto cleanup;
	}

	/* Use separately log files for reader and transit posts so the logs can be rotated/retained independently if desired
	 * (typically with higher retention for reader logs) */
	snprintf(newslogpath, sizeof(newslogpath), "%s/nntp_transit.log", bbs_log_dir());
	newslog = fopen(newslogpath, "a");
	if (!newslog) {
		bbs_error("Failed to open %s: %s\n", newslogpath, strerror(errno));
		bbs_rwlock_destroy(&nntp_lock);
		goto cleanup;
	}
	snprintf(postlogpath, sizeof(postlogpath), "%s/nntp_reader.log", bbs_log_dir());
	postlog = fopen(postlogpath, "a");
	if (!postlog) {
		bbs_error("Failed to open %s: %s\n", newslogpath, strerror(errno));
		bbs_rwlock_destroy(&nntp_lock);
		fclose(newslog);
		goto cleanup;
	}

	/* If we are good to go, initialize site feed types */
	if (sites_init_feed_types()) {
		bbs_rwlock_destroy(&nntp_lock);
		fclose(newslog);
		fclose(postlog);
		goto cleanup;
	}

	if (bbs_start_tcp_listener3(nntp_enabled ? nntp_port : 0, nntps_enabled ? nntps_port : 0, nnsp_enabled ? nnsp_port : 0, "NNTP", "NNTPS", "NNSP", __nntp_handler)) {
		bbs_rwlock_destroy(&nntp_lock);
		fclose(newslog);
		fclose(postlog);
		goto cleanup;
	}

	/* Now, kick off any feeds themselves which may need to process a queue of backlogged articles */
	sites_init_feeds();

	bbs_register_tests(tests);
	bbs_cli_register_multiple(cli_commands_nntp);
	return 0;

cleanup:
	cleanup_lists();
	cleanup_subsystems();
	return -1;
}

static int unload_module(void)
{
	nntp_unloading = 1;
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
	cleanup_lists();
	bbs_rwlock_destroy(&nntp_lock);
	cleanup_subsystems();
	fclose(newslog);
	fclose(postlog);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC3977 NNTP/NNSP", "mod_mail.so,mod_uuid.so");
