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
 * \brief NNTP suck feeds
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>

#include "include/utils.h"
#include "include/cli.h"

#include "nntp.h"
#include "nntp_history.h"
#include "nntp_bloom.h"
#include "nntp_client.h"
#include "nntp_suck.h"

/* from net_nntp.c: */
extern unsigned int max_groups;

static RWLIST_HEAD_STATIC(suck_feeds, suck_feed);
static int stop_sucking = 0;
static char suckdir[512];

/* Just to cap memory usage if server has a lot of groups (this is considerably more groups than most/all? Usenet servers carry) */
#define MAX_SUCK_GROUPS 500000

/* If downloading a large # of articles, we don't want to store an unbounded number of article numbers in memory.
 * In the worst case, that could result in an array of list of size NNTP_MAX_ARTICLE_NUMBER, too big!
 * Additionally, this is used for pipelining downloads, and we probably want to chunk those up anyways. */
#define SUCK_CHUNKSIZE 1024

/* common creator values are an email address, "usenet", "actsync", "checkgroups-update" */
#define DEFAULT_SUCK_CREATOR "sucksync"

struct upstream_group {
	const char *name;
	const char *status;
	/* Don't care about upstream creator */
	/* Don't care about upstream creation time */
	char *description;
	char disqualreason;
	int low; /* Low water mark */
	int high; /* High water mark */
	int count; /* # of articles in group */
	int lasthigh; /* Last high water mark. Used only for sucking news */
	time_t latestarticledate; /* Date epoch of latest article in group */
	RWLIST_ENTRY(upstream_group) entry;
	unsigned int excluded:1;
	unsigned int dirty:1; /* For sucking news, if group stats have changed and need to be flushed to suck file */
	char data[];
};

BBS_LIST_HEAD_NOLOCK(upstream_groups, upstream_group);

static void free_grp(struct upstream_group *grp)
{
	free_if(grp->description);
	free(grp);
}

static inline char *list_strsep(char **p)
{
	/* RFC 3977 7.6.3 says LIST ACTIVE items are separated by one OR MORE spaces... strsep will only process one space each time */
	char *ret;
	do {
		ret = strsep(p, " ");
	} while (ret && !*ret);
	return ret;
}

static int list_groups(struct nntp_client *nc, struct upstream_groups *grps, int *restrict grpcount)
{
	*grpcount = 0;

	nntp_client_send(nc, "LIST\r\n"); /* List all groups, here we go... */
	if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_LIST)) {
		return -1;
	}

	for (;;) {
		struct upstream_group *g;
		char *name, *high, *low, *status, *tmp, *data;
		size_t namelen, statuslen;
		ssize_t res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
		if (res <= 0) {
			return -1;
		}
		if (!strcmp(nc->buf, ".")) {
			break; /* That's all, folks! */
		}

		/* Parse the response */
		tmp = nc->buf;
		name = list_strsep(&tmp);
		high = list_strsep(&tmp);
		low = list_strsep(&tmp);
		status = list_strsep(&tmp);
		if (!name || !high || !low || !status || !strlen_zero(tmp)) {
			bbs_notice("Malformed LIST response line\n");
			return -1;
		}

		namelen = STRING_ALLOC_SIZE(name);
		statuslen = STRING_ALLOC_SIZE(status);

		g = calloc(1, sizeof(*g) + namelen + statuslen);
		if (ALLOC_FAILURE(g)) {
			return -1;
		}
		data = g->data;
		SET_FSM_STRING_VAR(g, data, name, name, namelen);
		SET_FSM_STRING_VAR(g, data, status, status, statuslen);
		g->high = atoi(high);
		g->low = atoi(low);
		BBS_LIST_INSERT_SORTALPHA(grps, g, entry, name); /* Keep the list sorted by name up front */

		/* Check for invalid counts AFTER inserting so cleanup is automatic if we return */
		if (g->high < 0 || g->low < 0) {
			bbs_client_err("Received invalid watermarks for group %s\n", g->name);
			return -1;
		}
		*grpcount += 1;
		if (*grpcount >= MAX_SUCK_GROUPS) { /* Prevent runaway to oblivion with an unbounded number of groups */
			bbs_warning("LIST group count has exceeded %d, aborting now\n", MAX_SUCK_GROUPS);
			return -1;
		}
	}
	return 0;
}

static struct upstream_group *find_group_after(struct upstream_group *head, const char *group)
{
	struct upstream_group *grp;
	for (grp = head; grp; grp = BBS_LIST_NEXT(grp, entry)) {
		int res = strcmp(grp->name, group);
		/* Since the list is sorted, if the element is in the list,
		 * all the items we encounter will SORT before the group we want,
		 * until we find it. */
		if (res < 0) {
			continue;
		} else if (res > 0) {
			return NULL; /* Not in list, we already went past where it would have been if present */
		} else {
			return grp; /* Found it */
		}
	}
	return NULL;
}

static struct upstream_group *find_group(struct upstream_groups *grps, const char *group, struct upstream_group *last)
{
	/* A common case is that the LIST response is sorted alphabetically, and thus we can start searching from the last group,
	 * rather than the beginning of the list. This order is not guaranteed, but is common enough it makes sense to optimize for it.
	 *
	 * In a test with 1,020 groups, this simple optimization results in only ~50-100k traversals of loop in find_group_after,
	 * versus ~12m traversals if we always use the list head (BBS_LIST_FIRST case).
	 * Overall performance may still be impacted by the relevant server response (e.g. LIST COUNTS). */
	if (last && strcmp(group, last->name) > 0) {
		return find_group_after(BBS_LIST_NEXT(last, entry), group);
	}
	return find_group_after(BBS_LIST_FIRST(grps), group);
}

static int get_descriptions(struct nntp_client *nc, struct upstream_groups *grps)
{
	struct upstream_group *lastgroup = NULL;
	nntp_client_send(nc, "LIST NEWSGROUPS\r\n");
	if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_LIST)) {
		return -1;
	}
	for (;;) {
		struct upstream_group *g;
		char *name, *description, *tmp;
		ssize_t res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
		if (res <= 0) {
			return -1;
		}
		if (!strcmp(nc->buf, ".")) {
			break; /* That's all, folks! */
		}

		/* Parse the response */
		tmp = nc->buf;
		name = tmp;
		description = strchr(tmp, '\t');
		if (!description) {
			description = strchr(tmp, ' ');
		}
		if (description) {
			*description++ = '\0';
		}
		if (!name || !description) {
			bbs_notice("Malformed LIST NEWSGROUPS response line\n");
			return -1;
		}
		g = find_group(grps, name, lastgroup);
		if (!g) {
			/* It's legal for most LIST commands to return groups that LIST ACTIVE didn't, just ignore it */
			bbs_debug(8, "LIST NEWSGROUPS included inactive group '%s'\n", name);
			continue;
		}
		lastgroup = g;
		ltrim(description); /* Trim trailing spaces */
		if (!strcmp(description, "No description.")) {
			continue; /* Well, this is a useless description, don't keep it */
		}
		g->description = strdup(description);
		if (ALLOC_FAILURE(g->description)) {
			return -1;
		}
	}
	return 0;
}

static int get_counts(struct nntp_client *nc, struct upstream_groups *grps, int ignore_missing)
{
	struct upstream_group *lastgroup = NULL;
	nntp_client_send(nc, "LIST COUNTS\r\n");
	/* XXX LIST COUNTS isn't mandatory in NNTP, but most servers should support it,
	 * if the upstream doesn't, there's no way we can efficiently do the filtering required. */
	if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_LIST)) {
		return -1;
	}
	for (;;) {
		struct upstream_group *g;
		char *name, *high, *low, *count, *status, *tmp;
		ssize_t res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
		if (res <= 0) {
			return -1;
		}
		if (!strcmp(nc->buf, ".")) {
			break; /* That's all, folks! */
		}

		/* Parse the response */
		tmp = nc->buf;
		name = list_strsep(&tmp);
		high = list_strsep(&tmp);
		low = list_strsep(&tmp);
		count = list_strsep(&tmp);
		status = list_strsep(&tmp);
		if (!name || !high || !low || !count || !status || !strlen_zero(tmp)) {
			bbs_notice("Malformed LIST COUNTS response line\n");
			return -1;
		}
		g = find_group(grps, name, lastgroup);
		if (!g) {
			if (!ignore_missing) {
				/* It's legal for most LIST commands to return groups that LIST ACTIVE didn't, just ignore it */
				bbs_debug(5, "LIST COUNTS included inactive group '%s'\n", name);
			}
			continue;
		}
		lastgroup = g;
		g->count = atoi(count);
		if (ignore_missing) {
			g->high = atoi(high);
			g->low = atoi(low);
		} /* else, we only care about counts */
		if (g->count < 0) {
			bbs_notice("Malformed group count for %s: %s\n", name, count);
			return -1;
		}
	}
	return 0;
}

static int read_hdr_response(struct nntp_client *nc, char **val)
{
	ssize_t res;
	char *artnum, *hdrval;

	res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
	if (res <= 0) {
		return -1;
	}
	hdrval = nc->buf;
	artnum = strsep(&hdrval, " ");
	if (strlen_zero(artnum)) {
		bbs_client_err("Missing article number?\n");
		return -1;
	} else if (strlen_zero(hdrval)) {
		bbs_client_err("Missing header value?\n");
		return -1;
	}
	*val = hdrval;
	return 0;
}

static int read_end_of_response(struct nntp_client *nc)
{
	ssize_t res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
	if (res <= 0) {
		return -1;
	}
	if (strcmp(nc->buf, ".")) {
		return -1;
	}
	return 0;
}

#define SKIP_LATEST_ARTICLE_CHECK(g) (g->excluded || g->latestarticledate || !g->count)

static int get_latest_articles_pass(struct nntp_client *nc, struct upstream_groups *grps)
{
	struct upstream_group *g;

	/* Most commands MAY be pipelined, so we do that to speed this up, since we need at least 2 commands per group. */
	BBS_LIST_TRAVERSE(grps, g, entry) {
		if (SKIP_LATEST_ARTICLE_CHECK(g)) {
			continue;
		}
		nntp_client_send(nc, "GROUP %s\r\n", g->name); /* This should succeed if we were able to list the group... */
		/* This COULD fail if the high water mark does not reflect the actual latest article.
		 * No need for LISTGROUP, we could use HDR Date low-high to get any existing articles' Dates at once */
		nntp_client_send(nc, "HDR Date %d\r\n", g->high);
	}
	BBS_LIST_TRAVERSE(grps, g, entry) {
		struct tm tm;
		char *date;
		int code;
		if (SKIP_LATEST_ARTICLE_CHECK(g)) {
			continue;
		}
		/* Read GROUP response */
		if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_GROUP)) {
			continue;
		}
		/* Did HDR succeed? */
		code = nntp_client_read_code(nc, SEC_MS(30));
		if (code != NNTP_OK_HDR) {
			bbs_debug(5, "Group %s: %s\n", g->name, nc->buf);
			continue; /* Could get back 423 if article not found, skip for now */
		}
		/* If OK, read HDR response */
		if (read_hdr_response(nc, &date)) {
			bbs_debug(1, "Failed to read Date header for high water article in group %s\n", g->name);
			return -1;
		}
		bbs_strterm(date, '('); /* CFWS is frequently used for human-readable time zone in Date header, trim that */
		bbs_debug(7, "Latest post in group %s: %s\n", g->name, date);
		if (bbs_parse_rfc822_date(date, &tm)) {
			return -1;
		}
		g->latestarticledate = timegm(&tm);
		if (read_end_of_response(nc)) {
			return -1;
		}
	}
	return 0;
}

static int get_latest_article_available(struct nntp_client *nc, struct upstream_group *g)
{
	int latest_article = 0;
	for (;;) {
		ssize_t res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
		if (res <= 0) {
			return -1;
		}
		if (!strcmp(nc->buf, ".")) {
			break; /* That's all, folks !*/
		}
		latest_article = atoi(nc->buf);
	}
	if (latest_article) {
		g->high = latest_article; /* Substitute in the actual high water mark */
	}
	return 0;
}

static int get_latest_articles(struct nntp_client *nc, struct upstream_groups *grps)
{
	struct upstream_group *g;

	/* The common case is that the high water mark IS the latest article in a group, so we try that first.
	 * XXX It's true that lowered number articles could have a more recent date, so this check isn't foolproof,
	 * but it would be silly to scan the whole group when this is a good enough heuristic for us. */
	if (get_latest_articles_pass(nc, grps)) {
		return -1;
	}

	/* For any groups for which the latest article was not the reported high water mark, do LISTGROUP to get the right #
	 * Do not pipeline the LISTGROUP commands in case there are a lot of groups we need to check. */
	BBS_LIST_TRAVERSE(grps, g, entry) {
		if (SKIP_LATEST_ARTICLE_CHECK(g)) {
			continue;
		}
		nntp_client_send(nc, "LISTGROUP %s\r\n", g->name);
		/* Read LISTGROUP response */
		if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_GROUP) || stop_sucking) {
			return -1;
		}
		if (get_latest_article_available(nc, g)) {
			return -1;
		}
	}

	/* Now that we used LISTGROUP to get the highest article number in each group, use that instead */
	if (get_latest_articles_pass(nc, grps)) {
		return -1;
	}

	return 0;
}

static int want_group_name(struct suck_feed *sf, const char *name)
{
	struct suck_pattern *sp;
	BBS_LIST_TRAVERSE(&sf->groups, sp, entry) {
		int res = uwildmat_poison(name, sp->pattern);
		if (res == -1) {
			return 0; /* Group is poison, don't want it */
		} else if (res == 1) {
			return 1; /* Group is wanted */
		}
	}
	return 0; /* No patterns matched either way */
}

static int explicitly_want_group(struct suck_feed *sf, const char *name)
{
	struct suck_pattern *sp;
	BBS_LIST_TRAVERSE(&sf->groups, sp, entry) {
		int res;
		if (strchr(sp->pattern, '*')) {
			size_t namelen;
			const char *s = strstr(sp->pattern, name);
			if (!s) {
				continue; /* Skip expressions with wildcards */
			}
			/* Group might be explicitly mentioned, but another pattern might have a wildcard.
			 * Check if the group we want is in the pattern. */
			namelen = strlen(name);
			if (s > sp->pattern && s[-1] != ',') {
				continue; /* Was a suffix of another group */
			}
			s += namelen;
			if (s && *s != ',') {
				continue; /* Was a prefix of another group */
			}
		}
		res = uwildmat_poison(name, sp->pattern);
		if (res == -1) {
			return 0; /* Group is poison, don't want it */
		} else if (res == 1) {
			return 1; /* Group is wanted */
		}
	}
	return 0;
}

static struct suck_pattern *get_group_pattern(struct suck_feed *sf, const char *name)
{
	struct suck_pattern *sp;
	BBS_LIST_TRAVERSE(&sf->groups, sp, entry) {
		int res = uwildmat_poison(name, sp->pattern);
		if (res == -1) {
			return NULL; /* Group is poison, don't want it */
		} else if (res == 1) {
			return sp;
		}
	}
	return NULL; /* No matching pattern, don't want group (shouldn't happen?) */
}

static void grpfilter_nonlocal(struct suck_feed *sf, int *restrict retained, struct upstream_groups *grps)
{
	struct upstream_group *g;
	UNUSED(sf);
	BBS_LIST_TRAVERSE(grps, g, entry) {
		/* This is the first exclusion so no technically need to skip groups with excluded bit set, there aren't any */
		if (!g->excluded && !group_exists(g->name)) {
			g->excluded = 1;
			g->disqualreason = 'J';
			*retained -= 1;
		}
	}
}

static void grpfilter_pattern_unwanted(struct suck_feed *sf, int *restrict retained, struct upstream_groups *grps)
{
	struct upstream_group *g;
	BBS_LIST_TRAVERSE(grps, g, entry) {
		/* Check if the group matches any patterns (poison or otherwise).
		 * The first match (poison or otherwise) gets used. */
		if (!g->excluded && !want_group_name(sf, g->name)) {
			g->excluded = 1;
			g->disqualreason = 'P';
			*retained -= 1;
		}
	}
}

static void grpfilter_pattern_explicitly_wanted(struct suck_feed *sf, int *restrict retained, struct upstream_groups *grps)
{
	struct upstream_group *g;
	BBS_LIST_TRAVERSE(grps, g, entry) {
		/* This is sort of the inverse of other filters */
		if (g->excluded && explicitly_want_group(sf, g->name)) {
			g->excluded = 0;
			g->disqualreason = '+'; /* Even though it's being kept, indicate that it was excluded, and we explicitly kept it */
			*retained += 1;
		}
	}
}

static void grpfilter_mincount(struct suck_feed *sf, int *restrict retained, struct upstream_groups *grps)
{
	struct upstream_group *g;
	BBS_LIST_TRAVERSE(grps, g, entry) {
		/* Note that many news servers do not report the actual article count, but an estimation
		 * Getting the actual article count at this point though would not be very efficient. */
		if (!g->excluded && g->count < sf->mincount) {
			g->excluded = 1;
			g->disqualreason = 'C';
			*retained -= 1;
		}
	}
}

static void grpfilter_minlow(struct suck_feed *sf, int *restrict retained, struct upstream_groups *grps)
{
	struct upstream_group *g;
	BBS_LIST_TRAVERSE(grps, g, entry) {
		if (!g->excluded && g->low < sf->minlow) {
			g->excluded = 1;
			g->disqualreason = 'L';
			*retained -= 1;
		}
	}
}

static void grpfilter_maxactivity(struct suck_feed *sf, int *restrict retained, struct upstream_groups *grps)
{
	struct upstream_group *g;
	time_t cutoff = time(NULL) - (86400 * sf->maxactivity);
	BBS_LIST_TRAVERSE(grps, g, entry) {
		if (!g->excluded && g->latestarticledate && g->latestarticledate < cutoff) {
			g->excluded = 1;
			g->disqualreason = 'A';
			*retained -= 1;
		}
	}
}

static void grpfilter_cancellations(struct suck_feed *sf, int *restrict retained, struct upstream_groups *grps)
{
	struct upstream_group *g;
	UNUSED(sf);
	BBS_LIST_TRAVERSE(grps, g, entry) {
		if (!g->excluded && !g->latestarticledate) {
			g->excluded = 1;
			g->disqualreason = 'C';
			*retained -= 1;
		}
	}
}

static void apply_filter(struct suck_feed *sf, struct upstream_groups *grps, int allgroups, int *restrict retained, const char *filtername, void (*filter)(struct suck_feed *sf, int *retained, struct upstream_groups *grps))
{
	int diff, post, pre = *retained;
	filter(sf, retained, grps);
	post = *retained;

	diff = pre - post;
	if (diff < 0) {
		diff = -diff;
	}

	bbs_verb(5, "Suck feed %s: retaining %d/%d, filtered %d by %s\n", sf->name, post, allgroups, diff, filtername);
}

static void generate_report(struct upstream_groups *grps, time_t start, int allgroups, int retained)
{
	struct upstream_group *g;
	FILE *fp;
	int overall_count = 0;
	char tmpfilepath[TMPNAME_BUFSIZ];

	bbs_tempname("nntpsuckgroups", tmpfilepath, sizeof(tmpfilepath));
	fp = bbs_mkftemp(tmpfilepath, 0600);
	if (!fp) {
		return;
	}
	BBS_LIST_TRAVERSE(grps, g, entry) {
		/* Not all groups may have a description (LIST NEWSGROUPS may be missing groups in LIST ACTIVE) */
		fprintf(fp, "%d %s %d %d %d %s %c%s%s\n", !g->excluded, g->name, g->high, g->low, g->count, g->status,
			g->disqualreason ? g->disqualreason : '-', g->description ? " " : "", S_IF(g->description));
		if (!g->excluded) {
			overall_count += g->count;
		}
	}
	fclose(fp);

	/* The overall count provided may be a bit of an overestimate, if the server reported counts were themselves estimates.
	 * However, if there are not too many holes, this should still be pretty close. */
	bbs_verb(4, "Finished sucking groups, retaining %d/%d groups (~%d article%s), report saved to %s (took %lds)\n",
		retained, allgroups, overall_count, ESS(overall_count), tmpfilepath, time(NULL) - start);
}

static int suck_client_start(struct nntp_client *nc, struct suck_feed *sf)
{
	int res = nntp_client_connect(nc, &sf->serveruri, sf->secure);
	if (res || stop_sucking) {
		goto done;
	}

	if (sf->modereader && nntp_client_mode_reader(nc)) {
		bbs_notice("MODE READER failed for %s:%d (%s), aborting\n", sf->serveruri.host, sf->serveruri.port, nc->buf);
		goto done;
	}

	res = nntp_client_capabilities(nc);
	if (res) {
		goto done;
	}

	/* Use encryption and compression if configured, then authenticate if needed */
	if (sf->starttls) {
		if (nntp_client_starttls(nc)) {
			goto done;
		}
		if ((sf->serveruri.user && (!nc->caps.authinfo_user || !nc->caps.sasl_plain)) || (sf->compress && !nc->caps.compress)) {
			res = nntp_client_capabilities(nc);
			if (res) {
				goto done;
			}
		}
	}
	if (sf->compress && nntp_client_compress(nc)) {
		goto done;
	}
	if (sf->serveruri.user && nntp_client_authenticate(nc, sf->serveruri.user, sf->serveruri.pass)) {
		goto done;
	}

	/* NEWNEWS may only be advertised after authenticating */
	res = nntp_client_capabilities(nc);
	if (res) {
		goto done;
	}

	return 0;

done:
	return -1;
}

static void suck_groups(struct suck_feed *sf)
{
	int allgroups, retained;
	time_t start;
	struct upstream_groups grps;
	struct nntp_client nc_stack, *nc = &nc_stack;

	start = time(NULL);
	BBS_LIST_HEAD_INIT(&grps);
	memset(&nc->tcpclient, 0, sizeof(struct bbs_tcp_client));

	if (suck_client_start(nc, sf)) {
		goto done;
	}

	/* We're connected. Our job is to figure out what groups we want. We do so as follows:
	 * 1) Issue LIST ACTIVE / LIST ACTIVE.TIMES / LIST NEWSGROUPS / LIST COUNTS to get all the group data we would need to recreate groups locally if necessary.
	 * 2) If autocreate=no, exclude groups that do not already exist locally
	 * 3) Exclude groups which do not match any group patterns
	 * 4) Filter groups using mincount and minlow
	 * 5) Get the age of the NEWEST article in remaining groups (e.g. Date header). If older than maxactivity, exclude group.
	 *
	 * Note that in step #1, we could combine with step #2, to avoid allocating groups that will be immediately excluded anyways.
	 * However, we load all the groups and then mark the exclusions so that we can report on all the groups with excluded/nonexcluded.
	 */
	if (list_groups(nc, &grps, &allgroups) || stop_sucking) {
		goto done;
	}
	if (get_descriptions(nc, &grps) || stop_sucking) {
		goto done;
	}
	retained = allgroups; /* Initially, all groups are considered */
	/* We have all the upstream groups. Now, start the exclusion process. */
	if (!sf->autocreate) {
		apply_filter(sf, &grps, allgroups, &retained, "nonlocal", grpfilter_nonlocal);
	}
	apply_filter(sf, &grps, allgroups, &retained, "pattern (nonmatch)", grpfilter_pattern_unwanted);
	/* Apply group filters */
	if (get_counts(nc, &grps, 0) || stop_sucking) {
		goto done;
	}
	if (sf->mincount) {
		apply_filter(sf, &grps, allgroups, &retained, "mincount", grpfilter_mincount);
	}
	if (sf->minlow) {
		apply_filter(sf, &grps, allgroups, &retained, "minlow", grpfilter_minlow);
	}
	if (sf->maxactivity) {
		/* This requires one operation for group, so it's much more expensive than the other filters */
		if (get_latest_articles(nc, &grps) || stop_sucking) {
			goto done;
		}
		apply_filter(sf, &grps, allgroups, &retained, "maxactivity", grpfilter_maxactivity);
		/* Any groups that we could not get a latest article for had all the most recent articles cancelled.
		 * Must be a spammy group, we don't want it. */
		apply_filter(sf, &grps, allgroups, &retained, "too many cancellations", grpfilter_cancellations);
	}
	/* Last of the group filters, re-include any groups we explicitly want even if they were filtered out above */
	apply_filter(sf, &grps, allgroups, &retained, "pattern (explicitly wanted)", grpfilter_pattern_explicitly_wanted);

	generate_report(&grps, start, allgroups, retained);

done:
	bbs_tcp_client_cleanup(&nc->tcpclient);
	BBS_LIST_REMOVE_ALL(&grps, entry, free_grp);
}

static inline void gen_suckfile_path(struct suck_feed *sf, char *buf, size_t len)
{
	snprintf(buf, len, "%s/%s", suckdir, sf->name);
}

static int load_suckfile(struct suck_feed *sf, struct upstream_groups *grps, time_t *lasttimestamp)
{
	FILE *fp;
	char buf[NNTP_BUFSIZ];
	int lineno = 1;
	char suckfile[sizeof(suckdir) + 32];

	gen_suckfile_path(sf, suckfile, sizeof(suckfile));
	fp = fopen(suckfile, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", suckfile, strerror(errno));
		return -1;
	}
	if (!fgets(buf, sizeof(buf), fp)) {
		bbs_error("File %s is empty\n", suckfile);
		fclose(fp);
		return -1;
	}
	*lasttimestamp = (time_t) atol(buf);
	for (; (fgets(buf, sizeof(buf), fp)); lineno++) {
		struct upstream_group *g;
		int high;
		char *grp, *hi, *tmp = buf;
		grp = strsep(&tmp, " ");
		hi = strsep(&tmp, " ");
		/* No need to trim trailing LF, atol will stop at the first non-numeric char */
		if (strlen_zero(hi)) {
			bbs_error("Suckfile %s line %d: malformed\n", suckfile, lineno);
			continue;
		}
		high = atoi(hi);
		if (high < 0) {
			bbs_error("Suckfile %s line %d: invalid metadata\n", suckfile, lineno);
			continue;
		}
		g = calloc(1, sizeof(*g) + strlen(grp) + 1);
		if (ALLOC_FAILURE(g)) {
			return -1;
		}
		strcpy(g->data, grp); /* Safe */
		g->name = g->data;
		g->lasthigh = high;
		BBS_LIST_INSERT_TAIL(grps, g, entry);
	}
	fclose(fp);
	return 0;
}

static int update_suckfile(struct suck_feed *sf, struct upstream_groups *grps, time_t started)
{
	FILE *fp;
	struct upstream_group *g;
	char suckfile[sizeof(suckdir) + 32];

	gen_suckfile_path(sf, suckfile, sizeof(suckfile));
	/* The file should be exactly the same size before/after editing */
	fp = fopen(suckfile, "r+");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", suckfile, strerror(errno));
		return -1;
	}
	fprintf(fp, "%ld\n", started);
	BBS_LIST_TRAVERSE(grps, g, entry) {
		fprintf(fp, "%s %010d\n", g->name, g->lasthigh);
	}
	fclose(fp);
	return 0;
}

static int get_recent_article_numbers(struct nntp_client *nc, int artnums[SUCK_CHUNKSIZE], int low, int high, int recent)
{
	ssize_t res;
	int i = 0, full = 0;

	for (;;) {
		int artnum;
		res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
		if (res <= 0) {
			return -1;
		}
		if (!strcmp(nc->buf, ".")) {
			break; /* That's all, folks! */
		}
		artnum = atoi(nc->buf);
		if (artnum < low) {
			continue; /* Too low */
		} else if (artnum > high) {
			continue; /* Too high */
		}
		/* If it matches so far, save it for now in the ring buffer.
		 * We'll figure out if it's recent enough later once we've read the entire response. */
		artnums[i++] = artnum;
		if (i == SUCK_CHUNKSIZE) {
			/* If we want the N most recent, then we wrap around to the beginning.
			 * Since recent <= SUCK_CHUNKSIZE, we know we won't lose any articles we want. */
			full = 1;
			i = 0;
		}
	}
	/* Since the array is not initialized, fill in any holes with 0s */
	if (!full) {
		artnums[i] = 0; /* Store 0 in first unused index to indicate "no more" */
		if (!i) {
			return 0; /* Group is empty, that's a bummer */
		}
	}
	/* We only want the most recent N articles... figure out where we start. */
	if (full) {
		/* We wrapped around, so we need to figure out where to start
		 * Say i=2 and recent=5, then we want to start at the 3rd last index, e.g. SUCK_CHUNKSIZE - (recent - i)
		 * Say i=40 and recent=5, then we want to start at 35... */
		if (recent > i) {
			return SUCK_CHUNKSIZE + i - recent;
		} else {
			return i - recent;
		}
	} else {
		/* This is the easy case. Say i=40, and recent=5, well we only want indices 35-39 */
		if (recent > i) {
			return 0; /* We're willing to accept more articles than available, take 'em all */
		} else {
			return i - recent;
		}
	}
}

struct artgroup {
	const char *group;
	int artnum;
};

struct queued_article {
	const char *msgid;
	time_t date;
	BBS_LIST_ENTRY(queued_article) entry;
	int num_xrefs;
	struct artgroup newsgroup;
	struct artgroup *xrefs;
	char data[];
};

BBS_LIST_HEAD_NOLOCK(article_queue, queued_article);

static void free_queued_article(struct queued_article *q)
{
	if (q->xrefs) {
		free(q->xrefs);
	}
	free(q);
}

static void free_queued_articles(struct article_queue *q)
{
	BBS_LIST_REMOVE_ALL(q, entry, free_queued_article);
}

static inline int xrefcmp(const struct artgroup *a_xref, int num_a, const struct artgroup *b_xref, int num_b)
{
	int i, j;
	for (i = 0; i < num_a; i++) {
		for (j = 0; j < num_b; j++) {
			if (!strcmp(a_xref[i].group, b_xref[j].group)) {
				/* They share a group in common; use the article number,
				 * e.g. if a has a lower artnum, answer is negative */
				return a_xref[i].artnum - b_xref[j].artnum;
			}
		}
	}
	return 0;
}

/*! \retval -1 if a comes before b, 1 if b comes before a, and 0 if they are equal (according to sort criteria) */
static int sort_compare(const void *aptr, const void *bptr)
{
	const struct queued_article *a = *(const struct queued_article *const *) aptr;
	const struct queued_article *b = *(const struct queued_article *const *) bptr;

	/* Preserve Xref order if possible. This ensures our order reflects the order that articles arrived to the groups upstream, irrespective of the Date header */
	if (a->num_xrefs) { /* If a->num_xrefs is > 0, then b->num_xrefs is almost guaranteed to be (since Xref is server-wide), so no need to bother checking here */
		int res = xrefcmp(a->xrefs, a->num_xrefs, b->xrefs, b->num_xrefs);
		if (res) {
			return res;
		}
	}

	/* For articles that can't be compared using Xref, use the Date header */
	if (a->date < b->date) {
		return -1;
	} else if (a->date > b->date) {
		return 1;
	} else {
		return 0;
	}
}

static int save_queued_articles(struct article_queue *q, char *template)
{
	struct queued_article *a, **artarray;
	FILE *fp;
	int count, i;

	count = BBS_LIST_SIZE(q, a, entry);
	bbs_debug(4, "Saving %d queued article%s\n", count, ESS(count));

	/* Build an array for sorting */
	artarray = malloc((long unsigned) count * sizeof(struct queued_article *));
	if (ALLOC_FAILURE(artarray)) {
		return -1;
	}
	i = 0;
	BBS_LIST_TRAVERSE(q, a, entry) {
		artarray[i++] = a;
	}

	/* Sort the messages using qsort
	 * Note that the resulting ordering only preserves relative ordering WITHIN each group.
	 * The overall ABSOLUTE ordering is not guaranteed to be consistent with the upstream article arrival order.
	 * This is because date order is not necessarily the same as upstream arrival order (due to delays
	 * in posting/injection and the lack of guarantee the Date header is accurate).
	 * There is no way in NNTP to fetch the list of articles in absolute ordering; Xref only gives us ordering within groups.
	 * Therefore, as long as relative ordering within groups is not violated, articles may still appear "out of ordering"
	 * due to articles within groups not being monotonically increasing as far as the Date header goes.
	 *
	 * There isn't a good way to work around this when doing an initial suck, but this issue can mitigated
	 * for incremental sucks by sucking frequently to minimize the variances in ordering later. */
	qsort(artarray, (size_t) count, sizeof(struct queued_article *), sort_compare);

	/* Write the ordered queue out to a list */
	bbs_tempname("nntpartsort", template, TMPNAME_BUFSIZ);
	fp = bbs_mkftemp(template, 0600);
	if (!fp) {
		free(artarray);
		return -1;
	}
	for (i = 0; i < count; i++) {
		a = artarray[i];
		/* Only the first two fields are really necessary, the time is just for debugging/analysis */
		fprintf(fp, "%s %s:%d %ld\n", a->msgid, a->newsgroup.group, a->newsgroup.artnum, a->date);
	}

	fclose(fp);
	free(artarray);
	bbs_verb(5, "Sorted %d article%s to %s, to suck articles, run 'news suckordered <suckfeed> %s' to suck articles\n", count, ESS(count), template, template);
	return 0;
}

static int queue_article(struct article_queue *q, const char *msgid, const char *group, int artnum, struct tm *tm, const char *xref)
{
	struct queued_article *a;
	char *ptr;
	int n_xref;

	/* First, check if it exists already... yes, this is very inefficient since it's a linear search */
	BBS_LIST_TRAVERSE(q, a, entry) {
		if (!strcmp(a->msgid, msgid)) {
			return 1; /* Article already exists, e.g. from another newsgroup */
		}
	}

	/* Calculate number of Xref groups */
	if (xref) {
		xref = bbs_strcnext(xref, ' '); /* Skip upstream server hostname */
	}
	n_xref = xref ? bbs_str_count(xref, ' ') + 1 : 0;

	/* Single allocation for almost everything.
	 * Technically we don't need memory for the numeric portions of the Xref header, but we do it this way to simplify the operation. */
	a = calloc(1, sizeof(*a) + strlen(msgid) + strlen(group) + 2 + strlen(S_IF(xref)) + (xref ? 1 : 0));
	if (ALLOC_FAILURE(a)) {
		return -1;
	}
	a->num_xrefs = n_xref;

	ptr = a->data;
	strcpy(ptr, msgid); /* Safe */
	a->msgid = ptr;

	ptr += strlen(msgid) + 1;

	strcpy(ptr, group); /* Safe */
	a->newsgroup.group = ptr;
	a->newsgroup.artnum = artnum;

	if (xref) {
		int xrefc = 0;
		char *xrefgrp, *xrefgrps;

		ptr += strlen(group) + 1;
		bbs_assert_exists(ptr);
		strcpy(ptr, xref); /* Safe */
		xrefgrps = ptr;

		a->xrefs = calloc(1, (sizeof(struct artgroup) * (long unsigned) n_xref));
		if (ALLOC_FAILURE(a->xrefs)) {
			free(a);
			return -1;
		}

		/* Parse Xref groups into the child struct */
		while ((xrefgrp = strsep(&xrefgrps, " "))) {
			char *colon;
			if (strlen_zero(xrefgrp)) {
				continue;
			}
			colon = strchr(xrefgrp, ':');
			if (!colon) {
				bbs_client_err("Malformed Xref header '%s' (%s)\n", xref, xrefgrp);
				free(a->xrefs);
				free(a);
				return -1;
			}
			*colon++ = '\0';
			a->xrefs[xrefc].group = xrefgrp;
			a->xrefs[xrefc].artnum = atoi(colon);
			xrefc++;
		}
	}

	a->date = timegm(tm); /* We know tm was parsed successfully at this point, so this should not fail */

	/* Insert into list */
	BBS_LIST_INSERT_HEAD(q, a, entry);

	return 0;
}

static int process_over(struct nntp_client *nc, struct suck_feed *sf, struct article_queue *q, struct upstream_group *g, int artnums[SUCK_CHUNKSIZE], int *restrict count, int *restrict skipped, int *restrict lowerbound, int *restrict upperbound)
{
	int i = 0, full = 0;

	for (;;) {
		char errbuf[128];
		long size;
		struct tm tm;
		int artnum, numlines;
		char *art, *subj, *from, *date, *msgid, *references, *bytes, *lines, *xref, *tmp;
		ssize_t res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
		if (res <= 0) {
			return -1;
		}
		if (!strcmp(nc->buf, ".")) {
			break; /* That's all, folks! */
		}
		if (full) {
			continue; /* Ignore the rest of the response */
		}
		tmp = nc->buf;
		art = strsep(&tmp, "\t");
		subj = strsep(&tmp, "\t"); /* Subject */
		from = strsep(&tmp, "\t"); /* From */
		date = strsep(&tmp, "\t"); /* Date */
		msgid = strsep(&tmp, "\t"); /* Message-ID */
		references = strsep(&tmp, "\t"); /* References */
		bytes = strsep(&tmp, "\t"); /* :bytes */
		lines = strsep(&tmp, "\t"); /* :lines */
		artnum = atoi(art);
		*upperbound = artnum;
		size = atol(bytes);
		if (strlen_zero(lines)) {
			bbs_client_err("Article %s:%d: Malformed OVER response\n", g->name, artnum);
			continue;
		}
		if (size < 0) {
			bbs_client_err("Article %s:%d: Malformed size %ld\n", g->name, artnum, size);
			continue;
		}
		numlines = atoi(lines);
		if (!strlen_zero(tmp) && STARTS_WITH(tmp, "Xref: " )) { /* XXX It might not start with the header name, LIST OVERVIEW.FMT would say for sure */
			xref = tmp += STRLEN("Xref: ");
			bbs_strterm(xref, '\t'); /* In case there are further fields */
		} else {
			xref = NULL;
		}

		/* Check global site policy */
		if (check_article_overview(subj, from, date, msgid, references, (size_t) size, numlines, xref, errbuf, sizeof(errbuf))) {
			bbs_debug(5, "Article %s:%d disqualified: %s\n", g->name, artnum, errbuf);
			goto skip;
		}

		/* As long as we have the Message-ID, we may as well check if it exists, so we don't request the article if we already have it. */
		if (history_messageid_exists(msgid)) {
			/* Sadly, if it already existed in another group, we can't just "add it" to another group now
			 * (we could link it, but the Xref header would need to get modified, and articles are immutable). */
			bbs_debug(6, "Article %s:%d disqualified: %s already exists\n", g->name, artnum, msgid);
			goto skip;
		}

		if (bbs_parse_rfc822_date(date, &tm)) {
			bbs_debug(6, "Article %s:%d disqualified: invalid date %s\n", g->name, artnum, date);
			goto skip;
		}

		/* If we're good so far, save the article number for now */
		if (i == 0) {
			*lowerbound = artnum;
		}
		artnums[i++] = artnum;
		if (i == SUCK_CHUNKSIZE) {
			full = 1;
		}
		if (sf->global_ordering) {
			res = queue_article(q, msgid, g->name, artnum, &tm, xref);
			if (res < 0) {
				return -1;
			} else if (res > 0) {
				goto skip;
			}
		}
		continue;
skip:
		*skipped += 1;
		if (i == 0) {
			/* We haven't processed any articles yet, so we know we'll never want any articles lower than this one again
			 * This way if a large suck operation is interrupt while in the middle and we've only skipped articles so far,
			 * we can at least increment our "next" pointer so we don't start at the beginning of the range next time. */
			g->lasthigh = artnum;
		}
		continue;
	}
	*count = i;
	return 0;
}

static inline int disqualify_article(int artnums[SUCK_CHUNKSIZE], int count, int artnum)
{
	int i;
	for (i = 0; i < count; i++) {
		if (artnums[i] == artnum) {
			artnums[i] = 0;
			return 0;
		}
	}
	return 1;
}

static int process_hdr(struct nntp_client *nc, struct article_queue *q, struct queued_article *qhead, struct upstream_group *g, int artnums[SUCK_CHUNKSIZE], int count, int *restrict skipped)
{
	for (;;) {
		char groupsbuf[NNTP_MAX_LINE_LENGTH];
		const char *newsgroups;
		char *grps, *grp;
		int artnum;
		ssize_t res = bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(30));
		if (res <= 0) {
			return -1;
		}
		if (!strcmp(nc->buf, ".")) {
			break; /* That's all, folks! */
		}

		artnum = atoi(nc->buf);
		newsgroups = bbs_strcnext(nc->buf, ' ');
		if (!newsgroups) {
			bbs_client_err("Article %s:%d has empty Newsgroups header?\n", g->name, artnum);
			continue;
		}
		safe_strncpy(groupsbuf, newsgroups, sizeof(groupsbuf));
		grps = groupsbuf;
		while ((grp = strsep(&grps, ","))) {
			ltrim(grp);
			if (!strlen_zero(grp)) {
				/* No, this is not an efficient implementation right (linear scan of artnums each time)
				 * However, even if we can filter out a handful of articles with poison groups from doing this,
				 * the saved bandwidth is worth it.
				 * It is probably quicker to look for poison groups than find the article in the array each time,
				 * so that's why we only scan the array if there is a match. */
				if (group_is_poison(grp)) {
					if (qhead) {
						/* We probably already added it to the list of queued articles that will be sorted, so remove it if present */
						for (; qhead; qhead = BBS_LIST_NEXT(qhead, entry)) {
							if (qhead->newsgroup.artnum == artnum) {
								BBS_LIST_REMOVE(q, qhead, entry);
								free_queued_article(qhead);
								goto skip;
							}
						}
					} else if (!disqualify_article(artnums, count, artnum)) {
						/* It only counts as another article skipped if it wasn't already disqualified */
skip:
						bbs_notice("Article %s:%d rejected: contains poison group %s\n", g->name, artnum, grp);
						*skipped += 1;
						break;
					}
				}
			}
		}
	}
	return 0;
}

/*!
 * \brief Read response to ARTICLE and try to save the article
 * \retval 0 on success
 * \retval -1 on failure (abort)
 * \retval 1 if article rejected
 */
static int save_article(struct nntp_client *nc, struct suck_feed *sf, const char *groupname, int artnum)
{
	char template[TMPNAME_BUFSIZ];
	size_t artlen = 0;
	char errbuf[NNTP_MAX_LINE_LENGTH + 24] = "";
	struct article_info artinfo;
	FILE *fp;
	int res, delivered;
	struct article_groups groups;
	unsigned int grpcount = 0;
	char *newsgroup, *newsgroups;

	memset(&artinfo, 0, sizeof(artinfo));
	memset(&groups, 0, sizeof(groups));

	bbs_renamable_tempname("nntpsuckart", template, sizeof(template));
	fp = bbs_mkftemp(template, 0600);
	if (!fp) {
		return -1;
	}

	/* Receive the full article */
	res = nntp_read_article(&artinfo, NNTP_MODE_TRANSIT, NULL, NULL, &nc->tcpclient, fp, &artlen, NULL, sf->xrefslave, errbuf, sizeof(errbuf));
	if (res) {
		fclose(fp);
		unlink(template);
		artinfo_reset(&artinfo);
		if (res < 0) {
			bbs_notice("Failed to read article %s:%d\n", groupname, artnum);
			return -1;
		} else {
			bbs_notice("Article %s:%d rejected: %s\n", groupname, artnum, errbuf); /* e.g. line length too long */
			return 1; /* Continue */
		}
	}
	res = 1; /* Reject article by default */

	/* Reject invalid or unwanted articles, e.g. missing headers, too many crossposts, etc. */
	if (check_article(NNTP_MODE_TRANSIT, NULL, &artinfo, errbuf, sizeof(errbuf))) {
		bbs_notice("Article %s:%d rejected: %s\n", groupname, artnum, errbuf);
		goto skip;
	}

	/* Process the Newsgroups headers to see which groups we want */
	newsgroups = artinfo.newsgroups; /* Duplicate pointer since we'll mutate it */
	while ((newsgroup = strsep(&newsgroups, ","))) {
		ltrim(newsgroup); /* The Newsgroups header could contain spaces between groups */
		if (strlen_zero(newsgroup)) {
			continue;
		}
		/* In theory, this should only happen if the HDR command was not supported, as we already checked for poison groups using HDR: */
		if (group_is_poison(newsgroup)) {
			bbs_notice("Article %s:%d rejected: contains poison group %s\n", groupname, artnum, newsgroup);
			goto skip;
		}
		if (want_group_name(sf, newsgroup) && group_exists(newsgroup) && !article_groups_contains(&groups, newsgroup)) {
			article_groups_add(&groups, newsgroup);
			grpcount++;
		}
	}

	if (!grpcount) {
		/* Shouldn't happen if we requested an article directly from a group (because we clearly want that group?),
		 * but maybe could happen with NEWNEWS. */
		bbs_notice("Article %s:%d rejected: contains only unwanted groups\n", groupname, artnum);
		goto skip;
	} else if (grpcount > max_groups) {
		bbs_notice("Article %s:%d rejected: contains too many groups (%u > %u)\n", groupname, artnum, grpcount, max_groups);
		goto skip;
	}

	/* If all is still well, try to save the article */
	delivered = article_create(&groups, &artinfo, fileno(fp), artlen);
	if (delivered <= 0) {
		bbs_notice("Failed to create article %s:%d\n", groupname, artnum);
	} /* nntp_spool_trad.c already logs a debug message on success, no need to log it again here */
	res = delivered > 0 ? 0 : -1;

skip:
	free_article_groups(&groups);
	fclose(fp);
	unlink(template);
	artinfo_reset(&artinfo);
	return res;
}

static int suck_articles(struct nntp_client *nc, struct suck_feed *sf, struct upstream_group *g, int artnums[SUCK_CHUNKSIZE], int count, int *restrict saved)
{
	int i, artnum, code;

	/* Pipeline all the article commands */
	for (i = 0; i < count; i++) {
		artnum = artnums[i];
		if (!artnum) {
			continue; /* Article was disqualified, don't even know what article number it is anymore, but it doesn't matter */
		}
		nntp_client_send(nc, "ARTICLE %d\r\n", artnum);
	}
	/* Read the responses back */
	for (i = 0; i < count; i++) {
		const char *artnumstr;
		int res, recv_artnum;
		artnum = artnums[i];
		if (!artnum) {
			continue; /* Article was disqualified, don't even know what article number it is anymore, but it doesn't matter */
		}
		code = nntp_client_read_code(nc, MIN_MS(5));
		if (code <= 0) {
			return -1;
		}
		if (code != NNTP_OK_ARTICLE) {
			bbs_notice("Failed to download %s:%d: %s\n", g->name, artnum, nc->buf);
			continue;
		}
		artnumstr = bbs_strcnext(nc->buf, ' ');
		if (!artnumstr) {
			bbs_client_err("Invalid response: %s\n", nc->buf);
			return -1;
		}
		recv_artnum = atoi(artnumstr);
		if (recv_artnum != artnum) {
			bbs_warning("Article mismatch, got %d, expected %d\n", recv_artnum, artnum);
			return -1;
		}
		res = save_article(nc, sf, g->name, artnum);
		if (res < 0) {
			return -1;
		} else if (!res) {
			*saved += 1;
		}
		/* Keep track that we successfully processed up through this article in case a failure happens in the middle of the article range,
		 * that way we don't needlessly request articles we already have. */
		g->lasthigh = artnum;
	}
	return 0;
}

/*! \brief Suck the latest articles for a specific group */
static int suck_group(struct nntp_client *nc, struct suck_feed *sf, struct article_queue *q, struct upstream_group *g, int *restrict total, int *restrict skipped, int *restrict saved)
{
	struct suck_pattern *sp;
	int artlow, arthigh, artrecent;
	int count;
	int artnums[SUCK_CHUNKSIZE];

	/* Find the pattern with the article filters for this group */
	sp = get_group_pattern(sf, g->name);
	if (!sp) {
		/* This can happen if groups are "poisoned" / removed in the config after the suck feed file has already been generated.
		 * Not a fatal issue, just continue, but warn so it can be removed from the file manually to reconcile. */
		bbs_warning("No pattern for suck feed %s allows group %s, skipping (remove from suck feed file if group not wanted)\n", sf->name, g->name);
		return 0;
	}

	/* If we want the N most recent articles only, we need to track that separately. */
	artlow = sp->min ? sp->min : 1;
	if (sp->recent) {
		arthigh = NNTP_MAX_ARTICLE_NUMBER;
		artrecent = sp->recent;
	} else {
		arthigh = sp->max;
		artrecent = 0;
	}

	/* We can stop if we determine we don't actually want any (more) articles for this group. */
	if (!arthigh) {
		bbs_debug(5, "Don't want any articles for %s (pattern %s, %d/%d/%d)\n", g->name, sp->pattern, sp->max, arthigh, sp->min);
		return 0;
	}
	if (g->lasthigh >= arthigh) {
		bbs_debug(5, "Don't want any higher articles for %s (max: %d)\n", g->name, arthigh);
		return 0;
	}

	/* We want to start at no less than lasthigh + 1 */
	if (g->lasthigh && artlow < g->lasthigh + 1) {
		artlow = g->lasthigh + 1; /* Not interested in articles we already saw */
	}
	if (artlow >= g->high) {
		bbs_debug(5, "No more articles available for %s (high: %d)\n", g->name, g->high);
		return 0;
	}

	/* If we want N most recent articles, figure out which article numbers are actually wanted (of what is available)
	 * We can't necessarily just subtract # recent from current high water mark, because there could be gaps in the articles available.
	 * That said, that is probably common enough we could try that first if the watermarks/count suggest there are no gaps,
	 * and only do LISTGROUP if there are actually gaps. However, this operation is only done once as part of "news suckgroups",
	 * so it's not really a big deal if it's not as efficient as possible. */
	if (artrecent) {
		int idx;
		nntp_client_send(nc, "LISTGROUP %s %d-\r\n", g->name, artlow);
		if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_GROUP)) {
			return -1;
		}
		idx = get_recent_article_numbers(nc, artnums, artlow, arthigh, artrecent);
		if (idx < 0) {
			return 0;
		}
		artlow = artnums[idx];
		if (!artlow) {
			return 0;
		}
		/* At this point we know where to start and don't have to worry about recency */
	} else {
		nntp_client_send(nc, "GROUP %s\r\n", g->name);
		if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_GROUP)) {
			return -1;
		}
	}

	if (arthigh != NNTP_MAX_ARTICLE_NUMBER) {
		bbs_verb(6, "Sucking newsgroup %s (%d-%d)\n", g->name, artlow, arthigh);
	} else {
		bbs_verb(6, "Sucking newsgroup %s (%d-)\n", g->name, artlow);
	}

	do {
		struct queued_article *lastqueued = NULL;
		int lowerbound = 0, upperbound = 0; /* can't be used uninitialized, shut gcc up */
		/* First, interrogate the metadata for articles available and filter out as many articles as we can before downloading them */
		/* If OVER capability advertised, use OVER, otherwise XOVER (since it's older) */

		/* XXX Yes, this is not very efficient, requesting "all further articles" like this when we only want the first SUCK_CHUNKSIZE articles.
		 * However, process_over also applies filtering, so we may need to scan the headers of many more than SUCK_CHUNKSIZE articles to fill the array,
		 * there's no really knowing where we'd end, even if we did a LISTGROUP in advance. */
		if (arthigh == NNTP_MAX_ARTICLE_NUMBER) {
			nntp_client_send(nc, "%sOVER %d-\r\n", nc->caps.over ? "" : "X", artlow);
		} else {
			nntp_client_send(nc, "%sOVER %d-%d\r\n", nc->caps.over ? "" : "X", artlow, arthigh);
		}
		if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_OVER)) {
			return -1;
		}

		if (sf->global_ordering) {
			lastqueued = BBS_LIST_LAST(q); /* Items are tail inserted, so any new items will be after this one, no need to search through previous items */
		}

		/* We could use XPAT for the kill patterns in a second pass, but since the headers we care about are in the OVER response anyways,
		 * it's more efficient to just do it ourselves. */
		if (process_over(nc, sf, q, g, artnums, &count, skipped, &lowerbound, &upperbound) || stop_sucking) {
			*total += count;
			return -1;
		}
		*total += count;

		if (lowerbound && upperbound) {
			/* An optimization: use HDR To ask for the Newsgroups header, since it's the only remaining header
			 * that could allow us to easily filter articles, outside of the ones already processed as part of overview headers.
			 * We know the exact bounds of the range, so use the most constrictive range possible if we filtered out articles on both sides. */
			nntp_client_send(nc, "%sHDR Newsgroups %d-%d\r\n", nc->caps.hdr ? "" : "X", lowerbound, upperbound);
			if (!nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_HDR)) {
				if (process_hdr(nc, q, lastqueued ? BBS_LIST_NEXT(lastqueued, entry) : BBS_LIST_FIRST(q), g, artnums, count, skipped) || stop_sucking) {
					return -1;
				}
			} else {
				bbs_debug(3, "HDR not supported? Got: %s\n", nc->buf);
			}
		}

		/*! \todo Use further HDR operations to filter out other headers using matches_custom_kill_pattern() prior to requesting full articles later.
		 * In particular, if we are sorting the articles first, this can improve efficiency.
		 * But we should only bother doing this if there are actually kill patterns that use the other headers. */

		/* Unless we need to sort the articles first, download any articles that haven't yet been filtered out in this batch */
		if (!sf->global_ordering) {
			if (suck_articles(nc, sf, g, artnums, count, saved) || stop_sucking) {
				return -1;
			}
		}
		g->lasthigh = upperbound; /* We successfully processed up to this article (even if it wasn't saved) */
		artlow = upperbound + 1;
	} while (count == SUCK_CHUNKSIZE && artlow <= g->high);

	bbs_verb(7, "Sucked newsgroup %s: saved %d/%d article%s\n", g->name, *saved, *total, ESS(*total));
	return 0;
}

/* Forward declaration */
static int suck_ordered(struct suck_feed *sf, struct nntp_client *nc, FILE *fp);

static void suck_news(struct suck_feed *sf)
{
	time_t start, lasttimestamp;
	struct upstream_groups grps;
	struct article_queue q;
	char template[TMPNAME_BUFSIZ];
	struct nntp_client nc_stack, *nc = &nc_stack;

	start = time(NULL);
	BBS_LIST_HEAD_INIT(&grps);
	BBS_LIST_HEAD_INIT(&q);
	memset(&nc->tcpclient, 0, sizeof(struct bbs_tcp_client));

	/* First, load all the groups we want to suck into memory */
	if (load_suckfile(sf, &grps, &lasttimestamp)) {
		goto done;
	}

	if (BBS_LIST_EMPTY(&grps)) {
		bbs_warning("No groups present for suckfeed %s\n", sf->name);
		goto done;
	}

	if (suck_client_start(nc, sf)) {
		goto done;
	}

	/* Next, store current article counts for all the groups we want.
	 * This way, we know if the current high is the same as the last high,
	 * the group has no new articles we need to suck/check. */
	if (get_counts(nc, &grps, 1) || stop_sucking) {
		goto done;
	}

	/* There are two possibly valid approaches here;
	 * We could go group by group and pull articles, or use the NEWNEWS command.
	 * A problem that exists with both NEWNEWS and a manual traversal
	 * is that for crossposted articles, the oldest article we pull for group A
	 * might be newer than other articles we pull later for other groups,
	 * yet due to saving the article from A first, it would have a lower article number.
	 *
	 * (This can be a problem with NEWNEWS since the order of returned articles is not significant,
	 *  so even doing something like NEWNEWS * 19700101 000000 GMT is not guaranteed to feed
	 *  articles to us in order. INN, for example, goes group by group, rather than using history.)
	 *
	 * Additionally, on the first traversal, NEWNEWS isn't really possible since
	 * we would be asking for every article on the server; at this point,
	 * it makes more sense to do the traversal.
	 * However, on future traversals, we will TRY to use NEWNEWS if available. */

	if (lasttimestamp && nc->caps.newnews && 0) {
		/*! \todo Possibly implement NEWNEWS support in the future */
#if 0
		char datestr[16];
		struct tm tm;
		if (likely(lasttimestamp > 90)) {
			lasttimestamp -= 90; /* Subtract > 1 minute, to ensure we don't miss articles right on the edge due to clock skew, etc. */
		}
		gmtime_r(&lasttimestamp, &tm);
		strftime(datestr, sizeof(datestr), "%Y%m%d %H%M%S", &tm); /* yyyymmdd hhmmss */
		/* Would be nice to optimize pattern based on the groups actually wanted, but this could be very long/difficult if there are a lot of entries in the file */
		nntp_client_send(nc, "NEWNEWS * %s GMT\r\n", datestr);
		/*! \todo Then do something with the response */
#endif
	} else { /* We have never sucked for this feed before */
		/* Go group by group */
		int total_processed = 0, total_skipped = 0, total_saved = 0;
		struct upstream_group *g;
		int c = 0;

		BBS_LIST_TRAVERSE(&grps, g, entry) {
			int grp_total = 0, grp_skipped = 0, grp_saved = 0;
			if (suck_group(nc, sf, &q, g, &grp_total, &grp_skipped, &grp_saved)) {
				if (sf->global_ordering) {
					/* If global ordering, don't persist processed high water mark since we didn't actually save queued articles */
					goto done;
				}
				break;
			}
			total_processed += grp_total;
			total_skipped += grp_skipped;
			total_saved += grp_saved;
			c++;
			if (stop_sucking) {
				if (sf->global_ordering) {
					goto done;
				}
				break;
			}
		}
		if (sf->global_ordering) {
			if (!stop_sucking) {
				if (BBS_LIST_EMPTY(&q)) {
					bbs_debug(1, "No new news articles available\n");
					goto done;
				}
				if (save_queued_articles(&q, template)) {
					goto done;
				}
			}
		}
		/* Note that saved + skipped != total
		 * skipped articles are not included in total, which only reflects the articles we attempted to download using "ARTICLE".
		 * If an article is rejected at that point, then it is not included in "saved", otherwise saved/total usually match.
		 * Total articles inspected is thus closer to total_processed + total_skipped. */
		bbs_verb(5, "Suck feed %s: sucked %d group%s, saved %d/%d article%s (skipped %d)\n", sf->name, c, ESS(c), total_saved, total_processed, ESS(total_processed), total_skipped);
	}

	/* Even if an error occured, at least persist the groups that got sucked successfully so we don't repeat them next time */
	if (update_suckfile(sf, &grps, start)) {
		goto done;
	}

	if (sf->global_ordering && sf->loadaftersort) {
		FILE *fp = fopen(template, "r");
		if (!fp) {
			bbs_error("Failed to open %s: %s\n", template, strerror(errno));
			goto done;
		}
		/* Reuse our existing NNTP client for the suck operation */
		if (!suck_ordered(sf, nc, fp)) { /* suck_ordered closes fp */
			bbs_delete_file(template); /* Delete temp file if we processed all articles */
		}
		/* In some cases, nc->tcpclient will be cleaned up at this point, but not always,
		 * so do it either way just in case as calling bbs_tcp_client_cleanup twice does no harm. */
	}

done:
	bbs_tcp_client_cleanup(&nc->tcpclient);
	free_queued_articles(&q);
	BBS_LIST_REMOVE_ALL(&grps, entry, free_grp);
}

static void *__suck_groups(void *varg)
{
	/* suck_feeds isn't locked, but sf can't be removed while sf->thread is set */
	struct suck_feed *sf = varg;
	suck_groups(sf);
	sf->done = 1;
	return NULL;
}

static void *__suck_news(void *varg)
{
	/* suck_feeds isn't locked, but sf can't be removed while sf->thread is set */
	struct suck_feed *sf = varg;
	suck_news(sf);
	sf->done = 1;
	return NULL;
}

static int cli_suckgroups(struct bbs_cli_args *a)
{
	struct suck_feed *sf;
	const char *name = a->argv[2];
	RWLIST_WRLOCK(&suck_feeds);
	RWLIST_TRAVERSE(&suck_feeds, sf, entry) {
		if (!strcmp(name, sf->name)) {
			/* Only one suck operation per suck feed at a time */
			if (sf->thread && sf->done) {
				/* Previous suck groups finished already, clean up the thread */
				bbs_pthread_join(sf->thread, NULL);
				sf->thread = 0;
			}
			if (sf->thread) {
				bbs_dprintf(a->fdout, "Suck operation already in progress for %s\n", sf->name);
			} else if (bbs_pthread_create(&sf->thread, NULL, __suck_groups, sf)) {
				bbs_dprintf(a->fdout, "Failed to start sucking groups for %s\n", sf->name);
			} else {
				bbs_dprintf(a->fdout, "Started sucking groups for %s\n", sf->name);
			}
			break;
		}
	}
	RWLIST_UNLOCK(&suck_feeds);
	if (!sf) {
		bbs_dprintf(a->fdout, "No such suck feed '%s'\n", name);
		return -1;
	}
	return 0;
}

static int _cli_sucknews(struct bbs_cli_args *a, int ordered, int loadaftersort)
{
	struct suck_feed *sf;
	const char *name = a->argv[2];
	RWLIST_WRLOCK(&suck_feeds);
	RWLIST_TRAVERSE(&suck_feeds, sf, entry) {
		if (!strcmp(name, sf->name)) {
			/* Only one suck operation per suck feed at a time */
			if (sf->thread && sf->done) {
				/* Previous suck groups finished already, clean up the thread */
				bbs_pthread_join(sf->thread, NULL);
				sf->thread = 0;
			}
			if (sf->thread) {
				bbs_dprintf(a->fdout, "Suck operation already in progress for %s\n", sf->name);
				break;
			}
			SET_BITFIELD(sf->global_ordering, ordered);
			SET_BITFIELD(sf->loadaftersort, loadaftersort);
			if (bbs_pthread_create(&sf->thread, NULL, __suck_news, sf)) {
				bbs_dprintf(a->fdout, "Failed to start sucking news for %s\n", sf->name);
			} else {
				bbs_dprintf(a->fdout, "Started sucking news for %s\n", sf->name);
			}
			break;
		}
	}
	RWLIST_UNLOCK(&suck_feeds);
	if (!sf) {
		bbs_dprintf(a->fdout, "No such suck feed '%s'\n", name);
		return -1;
	}
	return 0;
}

static int cli_sucknews(struct bbs_cli_args *a)
{
	return _cli_sucknews(a, 0, 0);
}

static int cli_suckorder(struct bbs_cli_args *a)
{
	return _cli_sucknews(a, 1, 0);
}

static int cli_sucknewsordered(struct bbs_cli_args *a)
{
	return _cli_sucknews(a, 1, 1);
}

/* Similar to struct artgroup, but as part of a linked list, since it's already sorted, and its contents need to be self-contained */
struct sorted_article {
	const char *msgid;
	const char *group;
	int artnum;
	BBS_LIST_ENTRY(sorted_article) entry;
	char data[];
};

BBS_LIST_HEAD_NOLOCK(sorted_articles, sorted_article);

static int save_ordered_articles(struct nntp_client *nc, struct suck_feed *sf, const char *groupname, int count, int *restrict saved)
{
	int i;
	for (i = 0; i < count; i++) {
		const char *artnumstr;
		int res, code, artnum;
		code = nntp_client_read_code(nc, MIN_MS(5));
		if (code <= 0) {
			return -1;
		}
		if (code != NNTP_OK_ARTICLE) {
			bbs_notice("Failed to download article from %s: %s\n", groupname, nc->buf);
			continue;
		}
		artnumstr = bbs_strcnext(nc->buf, ' ');
		if (!artnumstr) {
			bbs_client_err("Invalid response: %s\n", nc->buf);
			return -1;
		}
		artnum = atoi(artnumstr);
		res = save_article(nc, sf, groupname, artnum);
		if (res < 0) {
			return -1;
		} else if (!res) {
			*saved += 1;
		}
	}
	return 0;
}

/*! \brief Download a list of articles that are already sorted */
static int suck_ordered(struct suck_feed *sf, struct nntp_client *nc, FILE *fp)
{
	char buf[NNTP_MAX_LINE_LENGTH];
	struct sorted_articles articles;
	struct sorted_article *head, *lasthead;
	struct nntp_client nc_stack;
	time_t start, end;
	struct bloom_filter bf;
	int use_bloom_filter = 0, false_positives = 0, true_positives = 0, true_negatives = 0;
	int checked = 0, remaining = 0, saved = 0, pipelined = 0, lineno = 0;

	BBS_LIST_HEAD_INIT(&articles);

	/* First, build an list of the articles we want to download. Note that this whole function is idempotent,
	 * since we skip articles that have already been processed. However, this operation can become
	 * very slow as the history file and the # of articles to check grows large,
	 * because a naive "check history for each message ID" is quadratic with respect to the number of articles.
	 * For example, in one test, with ~130,000 articles in the list and ~30,000 files already downloaded,
	 * the loop below took ~465 seconds.
	 *
	 * The reason this loop exists in the first place is to avoid requesting articles we
	 * already have (which would be even slower). History could be larger than will fit
	 * in memory, so we cannot directly load the Message-IDs into memory in the general
	 * case to check for duplicates.
	 *
	 * Since the file is a list of articles to download in order, we would expect
	 * that there are first 0 or more articles in history, followed by 0 or more
	 * articles NOT in history, i.e. if and when we encounter an article that is
	 * NOT in history, it's unlikely that any further articles are in history.
	 * number of articles.
	 *
	 * However, because some articles may be rejected only when we fetch the full article,
	 * it's possible we encounter an article that WAS processed, but was rejected,
	 * and hence, there may be future articles that are in history. We don't separately
	 * store a record of refused articles, and even if we did, could not rely on that
	 * to be complete as that could grow unbounded.
	 *
	 * Taking this into account, since any articles in the list we do have are likely
	 * in order, keeping our place in the history file would speed up the simplest case
	 * where no other articles yet exist. However, this could keep history locked up
	 * for a while. (Ditto for doing one pass of the history file, and looking up
	 * each article - already pre-allocated in memory - and marking present/not present.)
	 *
	 * A Bloom filter is a good candidate for this sort of problem as we could do a linear scan
	 * of history first and then use a probabilistic data structure to check if an article is
	 * in history. However, Bloom filters tell us if a member is "probably in the set" or
	 * "definitely not in the set". However, if we get "probably in the set", we still have
	 * to check history. More useful would be "definitely in the set" or "probably not in the set",
	 * no harm in false negatives (we may request a few duplicate articles again),
	 * but we cannot have false positives (an article we thought was in the set, but wasn't,
	 * so we skipped it, and now we don't have it). Unfortunately, there is no way to do THAT.
	 *
	 * (Also, if there are a lot of articles, more bits are needed in the Bloom filter to keep
	 * false positives low; even with just 8 bits, if there are 500 million articles in history,
	 * that's already ~500 MB of RAM, which is possibly more memory than we may have available
	 * (though I would hope that large of a news server is better resourced than that...).)
	 *
	 * That said, a Bloom filter still helps, especially if we haven't downloaded most articles yet,
	 * so we do use a Bloom filter below to at least help with that case. In the above scenario
	 * of ~30,000 of ~130,000 articles being in history taking ~465 seconds with history lookups
	 * for every Message-ID, using a ~70 KB Bloom filter took only 51 seconds, about 9x faster.
	 *
	 * Of course, in the case that all articles in the file already exist,
	 * the Bloom filter won't help and will actually take slightly longer,
	 * but in most other cases there is a potentially large speedup.
	 */
	bbs_debug(2, "Cross-checking article list against history to establish outstanding downloads...\n");

	if (!history_bloom_init(&bf)) {
		use_bloom_filter = 1;
	}

	start = time(NULL);
	for (; (fgets(buf, sizeof(buf), fp)); lineno++) {
		struct sorted_article *a;
		size_t msgidlen;
		char *colon, *msgid, *groupart, *rest = buf;
		msgid = strsep(&rest, " ");
		groupart = strsep(&rest, " ");
		if (strlen_zero(msgid) || strlen_zero(groupart)) {
			bbs_warning("Malformed line in article list, line %d\n", lineno);
			continue;
		}
		colon = strchr(groupart, ':');
		if (!colon) {
			continue;
		}
		*colon++ = '\0';
		if (strlen_zero(colon)) {
			bbs_warning("Malformed line in article list, line %d\n", lineno);
			continue;
		}
		checked++;

		/* This command is idempotent, we'll skip any articles we already have */
		if (use_bloom_filter) {
			if (bloom_filter_contains(&bf, msgid, (int) strlen(msgid))) {
				/* We still need to check history to confirm it's a real match */
				if (history_messageid_exists(msgid)) {
					bbs_debug(9, "Message %s already exists, skipping\n", msgid);
					true_positives++;
					continue;
				}
				/* Good thing we checked! The Bloom filter said it was in the set, but it's not */
				false_positives++;
			} else {
				/* If it's not in the Bloom filter, it's definitely not in history, no need to scan the history file.
				 * Note that it's possible this is a false negative if the article arrived AFTER we built
				 * the Bloom filter but prior to this check. This is fairly unlikely, however,
				 * and even then, false negatives are benign because the article will get filtered out
				 * when we try to download the article anyways, so it's okay if there are a few of those. */
				true_negatives++;
			}
		} else if (history_messageid_exists(msgid)) {
			bbs_debug(9, "Message %s already exists, skipping\n", msgid);
			continue;
		}

		msgidlen = strlen(msgid);
		a = calloc(1, sizeof(*a) + msgidlen + strlen(groupart) + 2);
		if (ALLOC_FAILURE(a)) {
			bbs_warning("Malformed line in article list, line %d\n", lineno);
			fclose(fp);
			goto cleanup2;
		}
		strcpy(a->data, msgid);
		a->msgid = a->data;
		strcpy(a->data + msgidlen + 1, groupart);
		a->group = a->data + msgidlen + 1;
		a->artnum = atoi(colon);
		BBS_LIST_INSERT_TAIL(&articles, a, entry); /* Preserve order */
		if (stop_sucking) {
			fclose(fp);
			goto cleanup2;
		}
		remaining++;
	}
	fclose(fp);
	end = time(NULL);
	if (use_bloom_filter) {
		bbs_debug(2, "History Bloom filter: %d false positive%s, %d true positives, %d true negatives\n", false_positives, ESS(false_positives), true_positives, true_negatives);
		bloom_filter_destroy(&bf);
		use_bloom_filter = 0;
	}
	bbs_verb(6, "Cross-checked %d article%s against history, %d remaining to download (%lds elapsed)\n", checked, ESS(checked), remaining, end - start);

	if (BBS_LIST_EMPTY(&articles)) {
		bbs_notice("No new articles present in sorted file for %s\n", sf->name);
		return -1;
	}

	start = time(NULL);
	if (!nc) {
		nc = &nc_stack;
		memset(&nc->tcpclient, 0, sizeof(struct bbs_tcp_client));
		if (suck_client_start(nc, sf)) {
			goto cleanup;
		}
	}

	/* Now, actually download the articles, with pipelining (to the extent possible).
	 * We'll download by article number rather than message ID, since that is typically "friendlier" to news servers. */
	for (lasthead = NULL, head = BBS_LIST_FIRST(&articles); head; head = BBS_LIST_NEXT(head, entry)) {
		/* Change groups if needed */
		if (!lasthead || strcmp(lasthead->group, head->group)) {
			if (pipelined) {
				if (save_ordered_articles(nc, sf, lasthead->group, pipelined, &saved)) {
					goto cleanup;
				}
			}
			nntp_client_send(nc, "GROUP %s\r\n", head->group);
			if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_GROUP)) {
				goto cleanup;
			}
			pipelined = 0;
		}
		lasthead = head;
		/* If there are more consecutive articles in this group than the chunk size, stop eventually.
		 * It won't impact our memory usage or cause an issue for us, but at some point enough is enough. */
		if (pipelined >= SUCK_CHUNKSIZE) {
			if (save_ordered_articles(nc, sf, lasthead->group, pipelined, &saved)) {
				goto cleanup;
			}
			pipelined = 0;
		}
		nntp_client_send(nc, "ARTICLE %d\r\n", head->artnum);
		pipelined++;
		if (stop_sucking) {
			break;
		}
	}
	/* Save any final pipelined articles in the last group */
	if (pipelined) {
		if (save_ordered_articles(nc, sf, lasthead->group, pipelined, &saved) || stop_sucking) {
			goto cleanup;
		}
	}

	end = time(NULL);
	bbs_verb(5, "Suck feed %s: sucked %d article%s (%lds elapsed)\n", sf->name, saved, ESS(saved), end - start);
	BBS_LIST_REMOVE_ALL(&articles, entry, free);
	return 0;

cleanup:
	bbs_tcp_client_cleanup(&nc->tcpclient);
cleanup2:
	if (use_bloom_filter) {
		bloom_filter_destroy(&bf);
	}
	BBS_LIST_REMOVE_ALL(&articles, entry, free);
	return -1;
}

static void *__suck_ordered_articles(void *varg)
{
	/* suck_feeds isn't locked, but sf can't be removed while sf->thread is set */
	struct suck_feed *sf = varg;
	FILE *fp = sf->varg;
	suck_ordered(sf, NULL, fp);
	sf->done = 1;
	return NULL;
}

static int cli_suckordered(struct bbs_cli_args *a)
{
	struct suck_feed *sf;
	const char *name = a->argv[2];
	const char *filename = a->argv[3];

	RWLIST_WRLOCK(&suck_feeds);
	RWLIST_TRAVERSE(&suck_feeds, sf, entry) {
		if (!strcmp(name, sf->name)) {
			FILE *fp;
			/* Only one suck operation per suck feed at a time */
			if (sf->thread && sf->done) {
				/* Previous suck operation finished already, clean up the thread */
				bbs_pthread_join(sf->thread, NULL);
				sf->thread = 0;
			}
			if (sf->thread) {
				bbs_dprintf(a->fdout, "Suck operation already in progress for %s\n", sf->name);
			}
			fp = fopen(filename, "r");
			if (!fp) {
				bbs_dprintf(a->fdout, "Failed to open %s: %s\n", filename, strerror(errno));
				break;
			}
			sf->varg = fp;
			if (bbs_pthread_create(&sf->thread, NULL, __suck_ordered_articles, sf)) {
				bbs_dprintf(a->fdout, "Failed to start sucking articles for %s\n", sf->name);
				fclose(fp);
			} else {
				bbs_dprintf(a->fdout, "Started sucking articles for %s\n", sf->name);
			}
			break;
		}
	}
	RWLIST_UNLOCK(&suck_feeds);
	if (!sf) {
		bbs_dprintf(a->fdout, "No such suck feed '%s'\n", name);
		return -1;
	}
	return 0;
}

static int suck_load_groups(struct suck_feed *sf, FILE *fp)
{
	FILE *outfp;
	char suckfile[sizeof(suckdir) + 32];
	char buf[NNTP_MAX_LINE_LENGTH];
	int lineno = 1;
	const char *creator;
	int c = 0;

	/* Initialize the file that will be used to keep track of sucking for this suck feed,
	 * much the same way a normal offline NNTP client keeps tracks of articles/groups. */
	gen_suckfile_path(sf, suckfile, sizeof(suckfile));
	if (bbs_file_exists(suckfile)) {
		/* If we already loaded groups, don't overwrite unless the user really wants to */
		bbs_error("Suck file '%s' already exists. Please delete it if you want to load groups again.\n", suckfile);
		return -1;
	}

	outfp = fopen(suckfile, "w");
	if (!outfp) {
		bbs_error("Failed to open %s: %s\n", suckfile, strerror(errno));
		return -1;
	}

	/* Timestamp, for NEWNEWS. This will be exactly 10 digits wide (no 0-padded needed) until 2286, when we'll need 11 bytes, which would get us to 5138 */
	fprintf(outfp, "%010d\n", 0);

	creator = S_OR(sf->creator, DEFAULT_SUCK_CREATOR);

	for (; (fgets(buf, sizeof(buf), fp)); lineno++) {
		char *grp, *status, *tmp;
		const char *description;
		if (buf[0] != '1') {
			continue; /* If it starts with '0', it's a group that is being ignored */
		}
		tmp = buf;
		strsep(&tmp, " ");
		grp = strsep(&tmp, " ");
		strsep(&tmp, " "); /* high */
		strsep(&tmp, " "); /* low */
		strsep(&tmp, " "); /* count */
		bbs_term_line(tmp);
		status = strsep(&tmp, " "); /* status */
		strsep(&tmp, " "); /* reason for disqualification, if disqualified */
		description = tmp; /* description */
		if (strlen_zero(grp) || strlen_zero(status)) {
			bbs_warning("Malformed input file, skipping line %d\n", lineno);
			continue;
		}

		/*
		 * We store enough metadata that we can suck news periodically in an efficient manner, (space-separated):
		 * - newsgroup name
		 * - highest "processed" article number (possibly saved in the spool, or ignored if it failed our filters)
		 * As with the active file, numbers are padded to 10 digits if needed so edits can be made in place. */
		c++;
		fprintf(outfp, "%s %010d\n", grp, 0);

		/* Create the group if needed */
		if (group_exists(grp)) {
			bbs_debug(4, "Group '%s' already exists locally\n", grp);
			continue;
		}
		/* This operation is idempotent, so if we need to abort, there's no need to clean up, running a second time will only finish what's left */
		description = S_OR(description, "No description.");

		/* Technically, serving agents MUST NOT create new newsgroups simply because an unrecognized newsgroup appears (RFC 5537 3.7)
		 * However, in this case, we are explicitly configured to create such groups (so long as they match patterns specified in configuration). */
		
		if (group_create(grp, status, creator, description)) {
			bbs_error("Failed to create group %d '%s' '%s' (%s)\n", c, grp, status, S_IF(description));
		} else {
			bbs_verb(5, "Locally created newsgroup %d '%s' '%s' (%s)\n", c, grp, status, S_IF(description));
		}
	}
	fclose(outfp);
	return 0;
}

static int cli_suckload(struct bbs_cli_args *a)
{
	struct suck_feed *sf;
	const char *name = a->argv[2];
	const char *filename = a->argv[3];

	RWLIST_WRLOCK(&suck_feeds);
	RWLIST_TRAVERSE(&suck_feeds, sf, entry) {
		if (!strcmp(name, sf->name)) {
			int res;
			FILE *fp = fopen(filename, "r");
			if (!fp) {
				bbs_dprintf(a->fdout, "Failed to open %s: %s\n", filename, strerror(errno));
				break;
			}
			res = suck_load_groups(sf, fp);
			fclose(fp);
			if (res) {
				bbs_dprintf(a->fdout, "Failed to load groups from %s\n", filename);
			}
			break;
		}
	}
	RWLIST_UNLOCK(&suck_feeds);
	if (!sf) {
		bbs_dprintf(a->fdout, "No such suck feed '%s'\n", name);
		return -1;
	}
	return 0;
}

static struct bbs_cli_entry cli_commands_nntp_suck[] = {
	BBS_CLI_COMMAND(cli_suckgroups, "news suckgroups", 3, "Initialize newsgroups for a suck feed", "news suckgroups <name>"),
	BBS_CLI_COMMAND(cli_suckload, "news suckload", 4, "Create new newsgroups from the file generated by 'news suckgroups'", "news suckload <name> <filepath>"),
	BBS_CLI_COMMAND(cli_sucknews, "news sucknews", 3, "Suck news using a configured feed", "news sucknews <name>"),
	BBS_CLI_COMMAND(cli_sucknewsordered, "news sucknewsordered", 3, "Suck news in order using a configured feed", "news sucknewsordered <name>"),
	BBS_CLI_COMMAND(cli_suckorder, "news suckorder", 3, "Suck article order using a configured feed", "news suckorder <name>"),
	BBS_CLI_COMMAND(cli_suckordered, "news suckordered", 4, "Suck an ordered list of articles using a configured feed", "news suckordered <name> <filepath>"),
};

static void free_suckfeed(struct suck_feed *sf)
{
	if (sf->thread) {
		/* Tell it to stop, then wait for sucking to finish */
		if (!sf->done) {
			bbs_pthread_interrupt(sf->thread);
		}
		bbs_pthread_join(sf->thread, NULL);
		sf->thread = 0;
	}
	BBS_LIST_REMOVE_ALL(&sf->groups, entry, free);
	free(sf);
}

struct suck_feed *nntp_suckfeed_create(const char *name, const char *creator, const char *server, int modereader, int starttls, int compress, int autocreate, int xrefslave,
	int maxactivity, int mincount, int minlow)
{
	char serverbuf[1024];
	struct bbs_url url;
	struct suck_feed *sf;
	char *data;
	size_t namelen, creatorlen, hostlen, userlen, passlen;

	safe_strncpy(serverbuf, server, sizeof(serverbuf));

	memset(&url, 0, sizeof(url));
	if (bbs_parse_url(&url, serverbuf)) {
		bbs_error("Failed to parse URL '%s'\n", server);
		return NULL;
	}

	RWLIST_WRLOCK(&suck_feeds);

	RWLIST_TRAVERSE(&suck_feeds, sf, entry) {
		if (!strcmp(sf->name, name)) {
			bbs_error("Duplicate suck feed '%s'\n", name);
			RWLIST_UNLOCK(&suck_feeds);
			return NULL;
		}
	}

	namelen = STRING_ALLOC_SIZE(name);
	creatorlen = STRING_ALLOC_SIZE(creator);
	hostlen = STRING_ALLOC_SIZE(url.host);
	userlen = STRING_ALLOC_SIZE(url.user);
	passlen = STRING_ALLOC_SIZE(url.pass);

	sf = calloc(1, sizeof(*sf) + namelen + creatorlen + hostlen + userlen + passlen);
	if (ALLOC_FAILURE(sf)) {
		RWLIST_UNLOCK(&suck_feeds);
		return NULL;
	}

	data = sf->data;
	SET_FSM_STRING_VAR(sf, data, name, name, namelen);
	SET_FSM_STRING_VAR(sf, data, creator, creator, creatorlen);
	SET_FSM_STRING_VAR(sf, data, serveruri.host, url.host, hostlen);
	SET_FSM_STRING_VAR(sf, data, serveruri.user, url.user, userlen);
	SET_FSM_STRING_VAR(sf, data, serveruri.pass, url.pass, passlen);
	sf->serveruri.port = url.port;
	sf->secure = !strcasecmp(url.prot, "nntps");

	/* Server settings */
	SET_BITFIELD(sf->modereader, modereader);
	SET_BITFIELD(sf->starttls, starttls);
	SET_BITFIELD(sf->compress, compress);

	/* General */
	SET_BITFIELD(sf->autocreate, autocreate);
	SET_BITFIELD(sf->xrefslave, xrefslave);

	/* Group filters */
	sf->maxactivity = maxactivity;
	sf->mincount = mincount;
	sf->minlow = minlow;

	RWLIST_INSERT_TAIL(&suck_feeds, sf, entry);
	RWLIST_UNLOCK(&suck_feeds);
	return sf;
}

int nntp_suckfeed_add_suckpat(struct suck_feed *sf, const char *pattern, const char *args)
{
	struct suck_pattern *sp;
	size_t patlen;
	char *data;
	int min, max, recent;

	/* Parse the "args", which could be any of the following:
	 * * (all articles)
	 * 11-20 (articles 11-20 only)
	 * 11- (articles 11 and up)
	 * 11 (article 11 only)
	 * -20 (20 most recent articles)
	 */
	if (!strcmp(args, "*")) {
		min = recent = 0;
		max = NNTP_MAX_ARTICLE_NUMBER;
	} else if (!strcmp(args, "0")) {
		/* This is a special case, typically for poison entries, it means never download this group */
		min = 0;
		max = 0;
		recent = 0;
	} else {
		char argbuf[64];
		char *arg1, *arg2;
		safe_strncpy(argbuf, args, sizeof(argbuf));
		arg2 = argbuf;
		arg1 = strsep(&arg2, "-");

		if (strlen_zero(arg1)) {
			if (strlen_zero(arg2)) {
				bbs_error("Suck feed %s: Invalid suck pattern argument '%s'\n", sf->name, args);
				return -1; /* Just "-" and nothing else? */
			}
			recent = atoi(arg2);
			if (recent <= 0) {
				bbs_error("Suck feed %s: Invalid recent number of articles '%d' (%s)\n", sf->name, recent, args);
				return -1;
			}
			/* The sucking implementation requires that recent <= SUCK_CHUNKSIZE.
			 * Since SUCK_CHUNKSIZE is fairly large, it's unlikely users would
			 * specify a large value for recent, at some point you may as well suck the whole group. */
			if (recent > SUCK_CHUNKSIZE) {
				bbs_error("Suck feed %s: Recent number of articles must be <= %d (%s)\n", sf->name, SUCK_CHUNKSIZE, args);
				return -1;
			}
			min = max = 0;
		} else {
			recent = 0;
			min = atoi(arg1);
			if (min <= 0) {
				bbs_error("Suck feed %s: Invalid minimum article number '%d' (%s)\n", sf->name, min, args);
				return -1;
			}
			if (!strlen_zero(arg2)) {
				max = atoi(arg2);
				if (max <= 0) {
					bbs_error("Suck feed %s: Invalid maximum article number '%d' (%s)\n", sf->name, max, args);
					return -1;
				}
			} else {
				/* This case applies for both 11 and 11-.
				 * However, they mean different things. Check if a "-" was presently originally. */
				if (strchr(args, '-')) {
					max = NNTP_MAX_ARTICLE_NUMBER;
				} else {
					max = min;
				}
			}
		}
		if (min > NNTP_MAX_ARTICLE_NUMBER || max > NNTP_MAX_ARTICLE_NUMBER || recent > NNTP_MAX_ARTICLE_NUMBER) {
			bbs_error("Suck feed %s: Article range exceeded (%s)\n", sf->name, args);
			return -1;
		}
	}

	if (!recent && !max && !strchr(pattern, '@')) {
		bbs_warning("Pattern %s will not download articles for matching groups, should this be a poison pattern?\n", pattern);
	}

	patlen = STRING_ALLOC_SIZE(pattern);

	RWLIST_TRAVERSE(&sf->groups, sp, entry) {
		/* Quickly check for identical patterns.
		 * Different patterns that may match the same group are allowed (first one to match wins).
		 * The SAME pattern repeated twice, however, is pointless. */
		if (!strcmp(pattern, sp->pattern)) {
			bbs_error("Group pattern %s duplicated for suck feed %s\n", pattern, sf->name);
			return -1;
		}
	}

	sp = calloc(1, sizeof(*sp) + patlen);
	if (ALLOC_FAILURE(sp)) {
		return -1;
	}

	data = sp->data;
	SET_FSM_STRING_VAR(sp, data, pattern, pattern, patlen);

	sp->min = min;
	sp->max = max;
	sp->recent = recent;

	RWLIST_INSERT_TAIL(&sf->groups, sp, entry);
	bbs_debug(5, "Suck feed %s: Added suck pattern '%s' (min=%d,max=%d,recent=%d)\n", sf->name, pattern, min, max, recent);
	return 0;
}

extern void *thismodule;

int nntp_suckfeed_init(void)
{
	snprintf(suckdir, sizeof(suckdir), "%s/.suck", newsdir);
	if (bbs_ensure_directory_exists(suckdir)) {
		return -1;
	}
	RWLIST_HEAD_INIT(&suck_feeds);
	__bbs_cli_register_multiple(cli_commands_nntp_suck, ARRAY_LEN(cli_commands_nntp_suck), thismodule);
	return 0;
}

void nntp_suckfeed_cleanup(void)
{
	stop_sucking = 1;
	__bbs_cli_unregister_multiple(cli_commands_nntp_suck, ARRAY_LEN(cli_commands_nntp_suck));
	RWLIST_WRLOCK_REMOVE_ALL(&suck_feeds, entry, free_suckfeed);
}
