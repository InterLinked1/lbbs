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
 * \brief Article history
 */

#include "include/bbs.h"

#include "include/node.h"
#include "include/utils.h"
#include "include/stringlist.h"

#include "nntp.h"
#include "nntp_history.h"

/* Uncomment for additional debug messages when articles are expired */
/* #define DEBUG_EXPIRE */

extern int min_history;

/* Each thread opens a group's overview file for reading/writing, so multiple readers can operate simultaneously */
static bbs_mutex_t histlock;

static char history_file[sizeof(newsdir) + STRLEN("/history")] = "";
static FILE *histfp;

/*! \brief Group expiration settings */
struct retention_pattern {
	const char *pattern;
	double minexp;
	double defaultexp;
	double maxexp;
	RWLIST_ENTRY(retention_pattern) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(retention_patterns, retention_pattern);

static int parse_retention_period(const char *s, double *restrict val)
{
	if (strlen_zero(s)) {
		return -1;
	}
	if (!strcmp(s, "never")) {
		*val = -1;
		return 0;
	}
	*val = atof(s);
	if (*val < 0) {
		return -1;
	}
	if (*val < 0.0001 && strcmp(s, "0")) {
		return -1;
	}
	return 0;
}

int history_add_retention_pattern(const char *key, const char *value)
{
	struct retention_pattern *r;
	char valuebuf[256];
	double min = 0, defaultexp = 0, max = 0;
	char *tmp, *periods, *vbuf;

	/* This is currently only called during module loading, prior to multithreading in the module, so we don't lock here */

	RWLIST_TRAVERSE(&retention_patterns, r, entry) {
		if (!strcmp(r->pattern, key)) {
			bbs_error("Duplicate retention pattern for '%s', ignoring\n", key);
			return -1;
		}
	}

	safe_strncpy(valuebuf, value, sizeof(valuebuf));
	vbuf = valuebuf;
	periods = strsep(&vbuf, "/");
	tmp = strsep(&periods, ":");
	if (parse_retention_period(tmp, &min)) {
		bbs_error("Malformed retention directive '%s'\n", value);
		return -1;
	}
	tmp = strsep(&periods, ":");
	if (parse_retention_period(tmp, &defaultexp) || parse_retention_period(periods, &max)) {
		bbs_error("Malformed retention directive '%s'\n", value);
		return -1;
	}
	

	r = calloc(1, sizeof(*r) + strlen(key) + 1);
	if (ALLOC_FAILURE(r)) {
		return -1;
	}

	strcpy(r->data, key);
	r->pattern = r->data;

	r->minexp = min;
	r->defaultexp = defaultexp;
	r->maxexp = max;

	if (!strlen_zero(vbuf)) {
		for (; *vbuf; vbuf++) {
			switch (*vbuf) {
				/* Currently, no flags are supported */
				default:
					/* There is less harm in ignoring a retention pattern than using a malformed pattern that was not intended */
					bbs_error("Invalid retention flag '%c', ignoring retention pattern\n", *vbuf);
					free(r);
					return -1;
			}
		}
	}

	RWLIST_INSERT_TAIL(&retention_patterns, r, entry);
	return 0;
}

int history_init(void)
{
	bbs_mutex_init(&histlock, NULL);
	RWLIST_HEAD_INIT(&retention_patterns);

	snprintf(history_file, sizeof(history_file), "%s/%s", newsdir, "history");
	/* Keep the history file open for writing at runtime.
	 * We don't even need to lock for writes to it, since fprintf will ensure writes get interleaved properly. */
	histfp = fopen(history_file, "a+");
	if (!histfp) {
		bbs_error("Failed to open %s: %s\n", history_file, strerror(errno));
		return -1;
	}
	
	return 0;
}

void history_cleanup(void)
{
	/* If startup failed, we never initialized the mutexes so don't destroy them now */
	if (histfp) {
		fclose(histfp);
		histfp = NULL;
	}
	bbs_mutex_destroy(&histlock);
	RWLIST_WRLOCK_REMOVE_ALL(&retention_patterns, entry, free);
}

#define REQUIRE_HISTORY_FP(histfp) \
	if (unlikely(histfp == NULL)) { \
		bbs_mutex_unlock(&histlock); \
		bbs_error("History operation failed (history file not open)\n"); \
		return -1; \
	}

static inline int expire_article(const char *group, int artnum)
{
	/*! \note TODO FIXME This is extremely inefficient, as this involves rescanning the group's spool dir and rebuilding overview on each call
	 * Ideally, we would defer those until the end of expiration to be more efficient (one update per group of overview / recomputing watermarks) */
	return spool_article_delete_by_number(group, artnum);
}

/*! \note Must be called locked */
static inline struct retention_pattern *find_retention_pattern(const char *group)
{
	struct retention_pattern *r;
	RWLIST_TRAVERSE(&retention_patterns, r, entry) {
		if (uwildmat(group, r->pattern)) {
			return r;
		}
	}
	return NULL;
}

/* ~ val == -1, but for floating point */
#define NEVER_EXPIRE(val) (val < -0.99)

static int any_retention_patterns_remove_articles(void)
{
	struct retention_pattern *r;
	RWLIST_TRAVERSE(&retention_patterns, r, entry) {
		if (!NEVER_EXPIRE(r->minexp) || !NEVER_EXPIRE(r->defaultexp) || !NEVER_EXPIRE(r->maxexp)) {
			return 1;
		}
	}
	return 0;
}

#ifdef DEBUG_EXPIRE
#define EXPIRE_DEBUG(level, fmt, ...) bbs_debug(level, fmt, ## __VA_ARGS__)
#else
#define EXPIRE_DEBUG(level, fmt, ...)
#endif

static inline int should_expire_article(const char *group, time_t now, time_t arrival, time_t expires)
{
	time_t cutoff;
	int res;
	struct retention_pattern *r = find_retention_pattern(group);
	if (!r) {
		bbs_warning("No retention pattern applies to %s, not expiring any articles in it\n", group);
		return 0;
	}

	/* Common case is no "Expires" header */
	if (!expires) {
		if (NEVER_EXPIRE(r->defaultexp)) {
			EXPIRE_DEBUG(9, "Articles never expire in %s\n", group);
			return 0; /* Never expire */
		}
		cutoff = now - (time_t) (r->defaultexp * 86400);
		res = arrival <= cutoff;
		EXPIRE_DEBUG(9, "Retention policy says to %s for %s\n", res ? "expire" : "keep", group);
		return res;
	}

	/* Obey "Expires" header, subject to min/max constraints */

	/* Check minimum */
	if (NEVER_EXPIRE(r->minexp)) {
		EXPIRE_DEBUG(9, "Articles never expire in %s\n", group);
		return 0;
	} else {
		cutoff = now - (time_t) (r->minexp * 86400);
		if (arrival > cutoff) {
			EXPIRE_DEBUG(8, "Article not old enough yet to expire in %s, ignoring Expires header, keeping\n", group);
			return 0; /* Not old enough yet */
		}
	}

	/* Check maximum */
	if (!NEVER_EXPIRE(r->maxexp)) {
		cutoff = now - (time_t) (r->maxexp * 86400);
		if (arrival >= cutoff) {
			EXPIRE_DEBUG(8, "Article too old to keep for %s, ignoring Expires header, expiring\n", group);
			return 1; /* Too old to keep now */
		}
	}

	/* Otherwise, obey Expires header */
	res = now >= expires;
	EXPIRE_DEBUG(7, "Expires header says to %s for %s\n", res ? "expire" : "keep", group);
	return res;
}

/* Seek to the beginning of the file */
#define REWIND_HISTORY(histfp) \
	if (fseek(histfp, 0, SEEK_SET)) { \
		bbs_error("fseek failed: %s\n", strerror(errno)); \
		bbs_mutex_unlock(&histlock); \
		return -1; \
	}

int history_expire(const char *pattern)
{
	FILE *newfp;
	char buf[NNTP_BUFSIZ];
	int total_removed = 0, links_removed = 0;
	int line = 0;
	time_t history_cutoff, now;
	char template[TMPNAME_BUFSIZ];

	RWLIST_RDLOCK(&retention_patterns);
	if (!any_retention_patterns_remove_articles()) {
		bbs_notice("No retention patterns are configured, no articles will ever be expired\n");
		RWLIST_UNLOCK(&retention_patterns);
		return 0;
	}
	RWLIST_UNLOCK(&retention_patterns); /* REQUIRE_HISTORY_FP returns, so we make sure we're unlocked there */

	if (bbs_mutex_trylock(&histlock)) {
		bbs_warning("An expiration operation is already in-progress, rejecting concurrent expiration attempt\n");
		return -1;
	}

	bbs_renamable_tempname("nntp_history", template, sizeof(template));
	newfp = bbs_mkftemp(template, 0644);
	if (!newfp) {
		bbs_mutex_unlock(&histlock);
		return -1;
	}

	now = time(NULL);
	history_cutoff = now - (86400 * min_history);

	REQUIRE_HISTORY_FP(histfp);
	REWIND_HISTORY(histfp);

	RWLIST_RDLOCK(&retention_patterns);
	while ((fgets(buf, sizeof(buf), histfp))) {
		char *grp, *artnumstr, *middle, *restofline = buf;
		time_t arrival_time, expires;
		char *expires_str, *tmp, *bytes_str;
		int groups_kept = 0;
		int groups_removed = 0;
		char links[4 * NNTP_MAX_PATH_LENGTH] = "";
		char *linkspos = links;
		size_t linksleft = sizeof(links);
		char *msgid = strsep(&restofline, "\t");
		line++;
		if (unlikely(!msgid)) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}

		middle = strsep(&restofline, "\t"); /* This is the complex middle, restofline now is just the links */
		if (unlikely(strlen_zero(middle) || strlen_zero(restofline))) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}

		/* Middle is arrival~expires~len */
		tmp = strsep(&middle, "~");
		if (unlikely(!tmp)) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}
		arrival_time = *tmp == '-' ? 0 : atol(tmp);
		expires_str = strsep(&middle, "~");
		bytes_str = middle;
		if (unlikely(!expires_str || !bytes_str)) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}
		expires = atol(expires_str); /* If just '-' it will be 0, which is fine */

		if (*restofline != '\n') {
			/* Process each group in which this article appears */
			while ((artnumstr = strsep(&restofline, " "))) {
				int artnum, keep = 1;
				grp = strsep(&artnumstr, "/"); /* Parse out the group name */
				if (unlikely(!grp || strlen_zero(artnumstr))) {
					bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
					continue;
				}
				artnum = atoi(artnumstr);

				/* If we only want to expire articles in a certain group or group(s), check that first */
				if (pattern && !uwildmat(grp, pattern)) {
					goto dokeep;
				}

				if (should_expire_article(grp, now, arrival_time, expires)) {
					int res = expire_article(grp, artnum);
					if (!res) {
						keep = 0;
						links_removed++;
					}
				}
dokeep:
				if (keep) {
					groups_kept++;
					SAFE_FAST_APPEND(links, sizeof(links), linkspos, linksleft, "%s/%d", grp, artnum); /* Same as in nntp_spool_trad.c */
				} else {
					groups_removed++; /* Expiration succeded */
				}
			}
		}

		if (!groups_kept && groups_removed > 0) {
			total_removed++; /* Article was still in the spool and was deleted entirely from all group(s) containing it. */
		}

		/* Keep in history if article still exists in any groups, or if its age is less than min_history days (even if article may no longer be in any groups) */
		if (groups_kept || (min_history && (arrival_time > history_cutoff))) {
			fprintf(newfp, "%s\t%ld~%s~%s\t%s\n", msgid, arrival_time, expires_str, bytes_str, links);
		}
		if (!groups_kept || groups_removed) {
			EXPIRE_DEBUG(4, "%s %s (kept: %d, removed: %d)\n", !groups_kept && groups_removed > 0 ? "Permanently deleted" : groups_removed ? "Partially deleted" : "Keeping", msgid, groups_kept, groups_removed);
		}
	}
	RWLIST_UNLOCK(&retention_patterns);

	/* If needed, swap in the new history file and update pointers */
	fclose(newfp);
	if (total_removed > 0) {
		bbs_verb(5, "Swapping in new history file (removed %d link%s, completely removed %d article%s)\n", links_removed, ESS(links_removed), total_removed, ESS(total_removed));
		fclose(histfp);
		if (rename(template, history_file)) {
			bbs_error("Failed to rename %s -> %s: %s\n", template, history_file, strerror(errno));
			total_removed = -1;
		}
		/* Whether it's the new one or not, open the history file */
		histfp = fopen(history_file, "a+");
		if (!histfp) {
			/* This is very bad! We shouldn't crash because we check for histfp being NULL, but all future history operations will fail */
			bbs_error("Failed to open %s: %s\n", history_file, strerror(errno));
			total_removed = -1;
		}
		/* Seek back to end for appends */
		if (fseek(histfp, 0, SEEK_END)) {
			bbs_error("fseek failed: %s\n", strerror(errno));
		}
	} else {
		unlink(template); /* Discard new history file without swapping it in, nothing changed */
	}

	bbs_mutex_unlock(&histlock);
	return total_removed;
}

int history_add(const char *messageid, time_t arrival_time, time_t expires, size_t bytes, const char *links)
{
	char expiresbuf[32]; /* - indicates no expiration */

	if (expires > 0) {
		snprintf(expiresbuf, sizeof(expiresbuf), "%ld", expires);
	} else {
		strcpy(expiresbuf, "-"); /* Safe */
	}

	bbs_mutex_lock(&histlock); /* The write will be atomic, but other threads may want to read the hist file */
	REQUIRE_HISTORY_FP(histfp);
	fprintf(histfp, "%s\t%ld~%s~%lu\t%s\n", messageid, arrival_time, expiresbuf, bytes, links);
	fflush(histfp);
	bbs_mutex_unlock(&histlock);
	return 0;
}

int history_newnews(struct nntp_session *nntp, const char *wildmat, time_t newerthan)
{
	char buf[NNTP_BUFSIZ];
	int line = 0;

	bbs_mutex_lock(&histlock);
	REQUIRE_HISTORY_FP(histfp);
	REWIND_HISTORY(histfp);
	while ((fgets(buf, sizeof(buf), histfp))) {
		int sendmsg = 0;
		time_t epoch;
		char *grp, *middle, *artnumstr, *restofline = buf;
		char *msgid = strsep(&restofline, "\t");
		line++;
		if (!msgid) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}
		middle = strsep(&restofline, "\t"); /* This is the complex middle, restofline now is just the links */
		epoch = atol(middle); /* Will stop at ~ */
		/* We check the time first since that will be faster than matching the wildmat, and most of the time, we'll only want the most recent articles */
		if (epoch <= newerthan) {
			continue;
		}
		if (strlen_zero(restofline)) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}

		/* Check if the wildmat matches any of the groups containing this article */
		while ((artnumstr = strsep(&restofline, " "))) {
			grp = strsep(&artnumstr, "/"); /* Parse out the group name */
			if (!grp) {
				bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
				break;
			}
			if (!uwildmat(grp, wildmat)) {
				continue;
			}
			if (!ACL_ALLOWED_LOCKED(nntp, grp, NNTP_ACL_READ)) {
				continue;
			}
			sendmsg = 1;
			break; /* No need to check the other groups, one group is enough */
		}
		if (sendmsg) {
			_nntp_send(nntp, "%s\r\n", msgid);
		}
	}
	/* When we're done, seek back to the end of the file for appends */
	if (fseek(histfp, 0, SEEK_END)) {
		bbs_error("fseek failed: %s\n", strerror(errno));
	}
	bbs_mutex_unlock(&histlock);
	_nntp_send(nntp, ".\r\n");
	return 0;
}

int history_messageid_exists(const char *messageid)
{
	int found = 0;
	char buf[NNTP_BUFSIZ];
	int line = 0;

	bbs_mutex_lock(&histlock);
	REQUIRE_HISTORY_FP(histfp);
	REWIND_HISTORY(histfp);
	while ((fgets(buf, sizeof(buf), histfp))) {
		char *msgid, *s = buf;
		msgid = strsep(&s, "\t");
		line++;
		if (!msgid) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}
		if (!strcmp(msgid, messageid)) {
			found = 1;
			break;
		}
	}
	/* When we're done, seek back to the end of the file for appends */
	if (fseek(histfp, 0, SEEK_END)) {
		bbs_error("fseek failed: %s\n", strerror(errno));
	}
	bbs_mutex_unlock(&histlock);
	return found;
}

int history_find_article_by_messageid(const char *messageid, const char *prefgroup, char *group, size_t len, int *artnum)
{
	int found = 0;
	char buf[NNTP_BUFSIZ];
	int line = 0;

	bbs_mutex_lock(&histlock);
	REQUIRE_HISTORY_FP(histfp);
	REWIND_HISTORY(histfp);
	while ((fgets(buf, sizeof(buf), histfp))) {
		char *grp, *artnumstr, *restofline = buf;
		char *msgid = strsep(&restofline, "\t");
		line++;
		if (!msgid) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}
		if (strcmp(msgid, messageid)) {
			continue;
		}
		/* Found the article */
		strsep(&restofline, "\t"); /* This is the complex middle, restofline now is just the links */
		if (strlen_zero(restofline)) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}

		if (*restofline == '\n') {
			/* It can have no entries if the article was removed, but is still in history for a little while longer to refuse duplicates.
			 * Since we found the Message-ID, we can stop searching, but the article isn't in the spool, so it's not considered "found". */
			bbs_debug(8, "Article %s is present in history but has expired out of all groups in the spool\n", messageid);
			break;
		}

		/* If prefgroup was provided, then return that group/article number if it's present in the list of links.
		 * If we don't care (no preference), just use the first one. If we do but don't find it, we'll end up using the last one.
		 * Note we do this as a courtesy; the RFC allows 0 to be returned for the article number in any case;
		 * however, we aim to provide the article number in the current group if it actually exists there, to be as helpful as we can. */
		while ((artnumstr = strsep(&restofline, " "))) {
			grp = strsep(&artnumstr, "/"); /* Parse out the group name */
			if (!grp || !artnumstr) {
				bbs_warning("History file %s corrupted (line %d) '%s' '%s'\n", history_file, line, grp, artnumstr);
				continue;
			}
			/* If !prefgroup, we don't care, just pick the first one.
			 * If we do, we'll prefer the group if it exists in the list.
			 * If we get to the end and there weren't any matches, use the last one. */
			if (!prefgroup || !strcmp(grp, prefgroup) || strlen_zero(restofline)) {
				safe_strncpy(group, grp, len);
				*artnum = atoi(artnumstr);
				break;
			}
		}
		found = 1;
		break;
	}
	/* When we're done, seek back to the end of the file for appends */
	if (fseek(histfp, 0, SEEK_END)) {
		bbs_error("fseek failed: %s\n", strerror(errno));
	}
	bbs_mutex_unlock(&histlock);
	return found ? 0 : 1;
}
