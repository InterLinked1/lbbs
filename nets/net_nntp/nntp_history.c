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
#include "include/cli.h"
#include "include/test.h"

#include "nntp.h"
#include "nntp_history.h"
#include "nntp_bloom.h"

/* Uncomment for additional debug messages when articles are expired */
/* #define DEBUG_EXPIRE */

extern int min_history;
extern int nntp_unloading;
extern void *thismodule;

/* Both of these variables are used extern from net_nntp.c: */
/* With 50 MB, and a 1/10 false positive rate, we can handle up to 12.5 million articles. */
size_t history_bloom_maxmem = 50;

/* We start with a 1/25,000 false positive rate and worsen it if needed due to memory constraints */
unsigned long history_bloom_maxfpinv = 25000;

/* Each thread opens a group's overview file for reading/writing, so multiple readers can operate simultaneously */
static bbs_mutex_t histlock;

static char history_file[sizeof(newsdir) + STRLEN("/history")] = "";
static FILE *histfp;

#define REQUIRE_HISTORY_FP(histfp) \
	if (unlikely(histfp == NULL)) { \
		bbs_mutex_unlock(&histlock); \
		bbs_error("History operation failed (history file not open)\n"); \
		return -1; \
	}

/* Seek to the beginning of the file or abort */
#define REWIND_HISTORY(histfp) \
	if (fseek(histfp, 0, SEEK_SET)) { \
		bbs_error("fseek failed: %s\n", strerror(errno)); \
		bbs_mutex_unlock(&histlock); \
		return -1; \
	}

/* Seek to the end of the file */
#define SEEK_END_HISTORY(histfp) \
	if (fseek(histfp, 0, SEEK_END)) { \
		bbs_error("fseek failed: %s\n", strerror(errno)); \
	}

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

/* The number of iterations is kept small so that the test completes in a reasonable time when run under valgrind.
 * NUM_ITERATIONS of 4194304 takes about 5 seconds normally but almost a minute under valgrind. */
#define NUM_ITERATIONS 1572864

static inline int is_in_set(int x)
{
	/* All low number articles exist, all high number articles don't, and most in the middle do */
	if (x < (3 * (NUM_ITERATIONS / 10))) {
		return 1;
	}
	if (x > (9 * (NUM_ITERATIONS / 10))) {
		return 0;
	}
	return x % 13 ? 1 : 0;
}

static int test_bloom_filter(void)
{
	struct bloom_filter bf;
	int i;
	int false_positives = 0, true_positives = 0, true_negatives = 0;
	char buf[128];

	if (bloom_filter_autoinit(&bf, NUM_ITERATIONS)) {
		return -1;
	}

	for (i = 0; i < NUM_ITERATIONS; i++) {
		int len = snprintf(buf, sizeof(buf), "<bloom-%d@example.com>", i);
		if (is_in_set(i)) {
			bloom_filter_add(&bf, buf, len);
		}
	}

	for (i = 0; i < NUM_ITERATIONS; i++) {
		int len = snprintf(buf, sizeof(buf), "<bloom-%d@example.com>", i);
		int in_set = bloom_filter_contains(&bf, buf, len);
		if (in_set) {
			/* If Bloom filter says yes, it's probably in the set */
			if (is_in_set(i)) {
				true_positives++;
			} else {
				false_positives++;
			}
		} else {
			/* If Bloom filter says no, it must not be in the set */
			bbs_test_assert_equals(in_set, is_in_set(i));
			true_negatives++;
		}
	}
	bloom_filter_destroy(&bf);
	/* Since this is a deterministic test, we know what the results will be (Bloom filter is actually good enough to not have any false positive matches) */
	if (false_positives) {
		bbs_warning("%d false positive%s, %d true positives, %d true negatives\n", false_positives, ESS(false_positives), true_positives, true_negatives);
		goto cleanup;
	}
	bbs_debug(3, "%d false positive%s, %d true positives, %d true negatives\n", false_positives, ESS(false_positives), true_positives, true_negatives);
	return 0;

cleanup:
	bloom_filter_destroy(&bf);
	return -1;
}

static struct bbs_unit_test tests[] =
{
	{ "Bloom Filter", test_bloom_filter },
};

static int _history_bloom_init(struct bloom_filter *bf, size_t maxsize, size_t min_elements, unsigned long fp_inv, size_t *restrict actual_num_elements)
{
	char buf[NNTP_BUFSIZ];
	int res, line = 0;
	size_t hist_entries = 0;

	REQUIRE_HISTORY_FP(histfp);
	REWIND_HISTORY(histfp);
	while ((fgets(buf, sizeof(buf), histfp))) {
		hist_entries++;
	}
	if (maxsize && fp_inv) {
		size_t bytes;
		if (hist_entries < min_elements) {
			/* Don't start out too small to begin with, we'll just have to increase it immediately. */
			hist_entries = min_elements;
		}
		bytes = bloom_filter_size(hist_entries, bloom_filter_bpe(fp_inv));
		while (bytes > maxsize && fp_inv >= 20) { /* Not much point in having worse than 1/10 false positive rate */
			fp_inv /= 2;
		}
		if (bytes > maxsize) {
			bbs_debug(5, "Not building global Bloom filter (would take %lu B)\n", bytes);
			SEEK_END_HISTORY(histfp);
			return -1;
		}
		*actual_num_elements = hist_entries;
		res = bloom_filter_init(bf, hist_entries, fp_inv);
	} else {
		res = bloom_filter_autoinit(bf, hist_entries);
	}
	if (res) {
		SEEK_END_HISTORY(histfp);
		return -1;
	}
	REWIND_HISTORY(histfp);
	while ((fgets(buf, sizeof(buf), histfp))) {
		char *msgid, *s = buf;
		msgid = strsep(&s, "\t");
		line++;
		if (!msgid) {
			bbs_warning("History file %s corrupted (line %d)\n", history_file, line);
			continue;
		}
		bloom_filter_add(bf, msgid, (int) strlen(msgid));
	}
	/* When we're done, seek back to the end of the file for appends */
	SEEK_END_HISTORY(histfp);
	return 0;
}

int history_bloom_init(struct bloom_filter *bf)
{
	int res;
	size_t n; /* Unused */
	bbs_mutex_lock(&histlock);
	res = _history_bloom_init(bf, 0, 0, 0, &n);
	bbs_mutex_unlock(&histlock);
	return res;
}

static struct hist_bloom_data {
	struct bloom_filter filter;
	size_t cursize;
	size_t max_elements;
	unsigned int false_positives;
	unsigned int true_positives;
	unsigned int true_negatives;
	unsigned int available:1;
} hist_bloom;

/* All these helper functions are assumed to be called with histlock held */
static void hist_bloom_destroy(void)
{
	if (hist_bloom.available) {
		hist_bloom.available = 0;
		bloom_filter_destroy(&hist_bloom.filter);
	}
}

static int hist_bloom_create(void)
{
	size_t n, next_size;

	if (!history_bloom_maxmem) {
		return -1; /* Bloom filter disabled */
	}

	/* Start out with a minimum # of elements of 4096, so that we don't have to recreate the Bloom filter
	 * several times just in the first few thousand articles. */
	if (_history_bloom_init(&hist_bloom.filter, SIZE_MB(history_bloom_maxmem), 4096, history_bloom_maxfpinv, &n)) {
		return -1;
	}
	hist_bloom.available = 1;
	hist_bloom.cursize = n;

	/* Since we initially allocate this Bloom filter based on the number of articles that
	 * were present in history at startup, over time the filter will perform worse and worse
	 * as more articles are added. At some point, we'll want to recreate the filter entirely
	 * using a larger number of bits to ensure the effective false positive rate doesn't
	 * get too bad, keeping in mind:
	 * - We want to avoid doing this too often
	 * - We want to avoid this if increasing the filter size would hit a memory limit (either history_bloom_maxmem or allocation failure)
	 *   Makes sense to try to create the new filter first and then swap out on success.
	 *
	 * Here we calculate the # of elements at which we should consider recreating the filter anew.
	 * For small numbers of articles, we double the size of the filter to avoid recreating it too often.
	 * Once we have a sufficiently large number of articles, we grow by only 1.5x since we can grow more slowly.
	 */
	hist_bloom.max_elements = (n > 512000 ? 3 / 2 : 2) * n;

	/* This isn't how much space the next Bloom filter would actually use, but the worst case scenario,
	 * since we'll increase the error rate if we would run out of size, up to a point.
	 * If we know we wouldn't be allowed to allocate that much memory, then there's no point in trying.
	 * If even at that point, we'd still use too much memory, then this is as big a Bloom filter
	 * as we can use, so we'll just have to deal with it. */
	next_size = bloom_filter_size(hist_bloom.max_elements, bloom_filter_bpe(10UL));
	if (next_size > SIZE_MB(history_bloom_maxmem)) {
		bbs_debug(1, "Bloom filter cannot be further increased in the future (to %lu elements, would need %lu B)\n", hist_bloom.max_elements, next_size);
		hist_bloom.max_elements = 0;
	}

	return 0;
}

static int hist_bloom_reset(void)
{
	hist_bloom_destroy();
	return hist_bloom_create();
}

static inline void hist_bloom_add(const char *messageid)
{
	if (hist_bloom.available) {
		bloom_filter_add(&hist_bloom.filter, messageid, (int) strlen(messageid));
	}
	if (hist_bloom.max_elements && hist_bloom.filter.count > hist_bloom.max_elements) {
		/* We create the new filter in such a way that we always have a filter afterwards;
		 * even if we fail to create the new filter, we'll still have the old one. */
		struct bloom_filter old;
		memcpy(&old, &hist_bloom.filter, sizeof(old));
		if (hist_bloom_create()) {
			/* Failed to create new filter, restore the old one */
			bbs_warning("Couldn't enlarge Bloom filter, keeping the old one\n");
			memcpy(&hist_bloom.filter, &old, sizeof(hist_bloom.filter));
		} else {
			/* We succeeded, finish the swap out */
			bloom_filter_destroy(&old);
		}
	}
}

#define hist_bloom_check(messageid) (bloom_filter_contains(&hist_bloom.filter, messageid, (int) strlen(messageid)))

static int cli_news_bloom_stats(struct bbs_cli_args *a)
{
	int calc_fp;
	if (!hist_bloom.available) {
		bbs_dprintf(a->fdout, "No global Bloom filter currently in use\n");
		return 0;
	}
	/* Technically we should rdlock here, but we only have a mutex, so skip it */
	if (hist_bloom.false_positives + hist_bloom.true_positives) {
		calc_fp = (int) (100.0 * (hist_bloom.false_positives / (1.0 * hist_bloom.false_positives + hist_bloom.true_positives + hist_bloom.true_negatives)));
	} else {
		calc_fp = 0;
	}
	bbs_dprintf(a->fdout, "%-15s %15lu\n", "# Elements", hist_bloom.filter.count); /* This is how many messages are in the history file */
	bbs_dprintf(a->fdout, "%-15s %15lu\n", "Alloc Elements", hist_bloom.cursize); /* This was the # of elements used to create the Bloom filter */
	bbs_dprintf(a->fdout, "%-15s %15lu\n", "Recreate Thresh", hist_bloom.max_elements); /* Threshold at which we should build a new Bloom filter */
	bbs_dprintf(a->fdout, "%-15s %15lu\n", "# Bits", hist_bloom.filter.nbits);
	bbs_dprintf(a->fdout, "%-15s %15u\n", "# Hashes", hist_bloom.filter.nhashes);
	bbs_dprintf(a->fdout, "%-15s %15d%%\n", "False Pos. Rate", calc_fp);
	bbs_dprintf(a->fdout, "%-15s %15u\n", "False Positives", hist_bloom.false_positives);
	bbs_dprintf(a->fdout, "%-15s %15u\n", "True Positives", hist_bloom.true_positives);
	bbs_dprintf(a->fdout, "%-15s %15u\n", "True Negatives", hist_bloom.true_negatives);
	/* By definition, a Bloom filter has no false negatives */
	return 0;
}

static int cli_news_bloom_size(struct bbs_cli_args *a)
{
	size_t bytes;
	ssize_t n = atol(a->argv[3]);
	long fp_inv = atol(a->argv[4]);

	if (n < 0) {
		bbs_dprintf(a->fdout, "Invalid number of elements: %s\n", a->argv[3]);
		return -1;
	} else if (fp_inv < 0) {
		bbs_dprintf(a->fdout, "Invalid reciproval false positive ratio: %s\n", a->argv[4]);
		return -1;
	}

	bytes = bloom_filter_size((size_t) n, bloom_filter_bpe((unsigned long) fp_inv));
	bbs_dprintf(a->fdout, "Bloom filter size for %ld elements, 1/%ld f.p.: %lu B\n", n, fp_inv, bytes);
	return 0;
}

static struct bbs_cli_entry cli_commands_nntp_history[] = {
	BBS_CLI_COMMAND(cli_news_bloom_stats, "news bloom stats", 3, "Display global history Bloom filter stats", NULL),
	BBS_CLI_COMMAND(cli_news_bloom_size, "news bloom size", 5, "Compute size required for Bloom filter based on article count and false positives", "news bloom size <num> <fp_inv>"),
};

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

	/* Initialize a Bloom filter to use for history check operations.
	 * Certain operations will use their own, larger Bloom filters; this one serves as a stopgap.
	 * Since it will remain allocated persistently, we don't want it to be too large,
	 * and we accept a higher false positive rate.
	 *
	 * We keep the Bloom filter up to date with all new articles, so we can definitively
	 * say that if the Bloom filter returns false, the article is not in history.
	 *
	 * Ideally, we have a false positive rate of at least 1/1,000, but
	 * we even with a rate as bad as 1/10, in the case of checking whether
	 * to accept an article offered by a peer, there's a good chance it
	 * will be a true negative so the Bloom filter still avoids a history traversal. */
	hist_bloom_create(); /* We can proceed even if this fails */

	__bbs_cli_register_multiple(cli_commands_nntp_history, ARRAY_LEN(cli_commands_nntp_history), thismodule);
	__bbs_register_tests(tests, ARRAY_LEN(tests), thismodule);
	return 0;
}

void history_cleanup(void)
{
	/* If startup failed, we never initialized the mutexes so don't destroy them now */
	if (histfp) {
		fclose(histfp);
		histfp = NULL;
	}

	__bbs_unregister_tests(tests, ARRAY_LEN(tests));
	bbs_cli_unregister_multiple(cli_commands_nntp_history);

	/* Lock and unlock to ensure that all expire operations have finished */
	bbs_mutex_lock(&histlock);
	hist_bloom_destroy();
	bbs_mutex_unlock(&histlock);

	bbs_mutex_destroy(&histlock);
	RWLIST_WRLOCK_REMOVE_ALL(&retention_patterns, entry, free);
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
		if (arrival <= cutoff) {
			EXPIRE_DEBUG(8, "Article too old to keep for %s, ignoring Expires header, expiring\n", group);
			return 1; /* Too old to keep now */
		}
	}

	/* Otherwise, obey Expires header */
	res = now >= expires;
	EXPIRE_DEBUG(7, "Expires header says to %s for %s\n", res ? "expire" : "keep", group);
	return res;
}

int history_expire(const char *pattern)
{
	FILE *newfp, *expirefp;
	char buf[NNTP_BUFSIZ];
	int total_removed = 0, links_removed = 0;
	int line = 0;
	int error = 0;
	time_t history_cutoff, now;
	char template[TMPNAME_BUFSIZ];
	char expirelogfile[NNTP_MAX_PATH_LENGTH];

	snprintf(expirelogfile, sizeof(expirelogfile), "%s/%s", bbs_log_dir(), "nntp_expire.log");

	RWLIST_RDLOCK(&retention_patterns);
	if (!any_retention_patterns_remove_articles()) {
		bbs_notice("No retention patterns are configured, no articles will ever be expired\n");
		RWLIST_UNLOCK(&retention_patterns);
		return 0;
	}
	RWLIST_UNLOCK(&retention_patterns); /* REQUIRE_HISTORY_FP returns, so we make sure we're unlocked there */

	if (bbs_mutex_trylock(&histlock)) {
		bbs_notice("An expiration operation is already in-progress, rejecting concurrent expiration attempt\n");
		return -1;
	}

	if (nntp_unloading) {
		bbs_mutex_unlock(&histlock);
		bbs_notice("Module unload is pending, not starting article expiration\n");
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

	expirefp = fopen(expirelogfile, "a");
	if (!expirefp) {
		bbs_error("Failed to append to %s: %s\n", expirelogfile, strerror(errno));
		fclose(newfp);
		unlink(template);
		bbs_mutex_unlock(&histlock);
		return -1;
	}

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
		char *msgid;

		line++;

		msgid = strsep(&restofline, "\t");
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
					/* If we successfully expired it, or the article is no longer present in the spool, treat as expired */
					if (!res || !spool_article_exists(grp, artnum)) {
						keep = 0;
						links_removed++;
						EXPIRE_DEBUG(6, "Expiring %s:%d\n", grp, artnum);
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
		} else {
			/* If article is now being completely removed from history, add it to the expire log, the final vestige of this article's transient existence! */
			fprintf(expirefp, "%s\t%ld~%s~%s~%ld\n", msgid, arrival_time, expires_str, bytes_str, now); /* Also include time of expiration at end */
		}
		if (!groups_kept || groups_removed) {
			/* "Keeping" means the article is kept in history for now, now that we're keeping the article (it's already gone) */
			EXPIRE_DEBUG(4, "%s %s (kept: %d, removed: %d)\n", !groups_kept && groups_removed > 0 ? "Permanently deleted" : groups_removed ? "Partially deleted" : "Keeping", msgid, groups_kept, groups_removed);
		}

		/* If we are unloading, skip all further expiration checks and just copy the remainder of the original history file to the new one.
		 * This way we can stop ~immediately if finishing expiration would take a long time. */
		if (nntp_unloading) {
			bbs_debug(4, "Aborting remaining expiration checks\n");

			if (!total_removed) {
				/* No changes have been made yet, we can just keep the original file */
				break;
			}
			if (bbs_copy_rest_of_file(histfp, newfp)) {
				error = 1; /* If we failed to append the remainder of the file, don't discard the original history file */
			}
			break;
		}
	}
	RWLIST_UNLOCK(&retention_patterns);

	/* If needed, swap in the new history file and update pointers */
	fclose(expirefp);
	fclose(newfp);
	if (total_removed > 0 && !error) {
		bbs_verb(5, "Swapping in new history file (removed %d link%s, completely removed %d article%s)\n", links_removed, ESS(links_removed), total_removed, ESS(total_removed));
		fclose(histfp);
		if (bbs_rename(template, history_file)) {
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
		SEEK_END_HISTORY(histfp);
	} else {
		unlink(template); /* Discard new history file without swapping it in, nothing changed */
	}

	/* Since a bunch of articles may have been removed from history, rebuild the Bloom filter for existence checks */
	hist_bloom_reset();

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
	hist_bloom_add(messageid);
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
	SEEK_END_HISTORY(histfp);
	bbs_mutex_unlock(&histlock);
	_nntp_send(nntp, ".\r\n");
	return 0;
}

static int history_messageid_exists_with_bloom_filter(const char *messageid, int check_bloom_filter)
{
	int found = 0;
	char buf[NNTP_BUFSIZ];
	int line = 0;

	bbs_mutex_lock(&histlock);
	if (check_bloom_filter && hist_bloom.available) {
		if (!hist_bloom_check(messageid)) {
			hist_bloom.true_negatives++;
			bbs_mutex_unlock(&histlock);
			return 0; /* Well, that was easy */
		}
	}
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
	SEEK_END_HISTORY(histfp);
	if (check_bloom_filter && hist_bloom.available) {
		if (found) {
			hist_bloom.true_positives++;
		} else {
			hist_bloom.false_positives++;
		}
	}
	bbs_mutex_unlock(&histlock);
	return found;
}

int history_messageid_exists(const char *messageid)
{
	/* By default, use the Bloom filter to speed up existence checks for nonexistent articles. */
	return history_messageid_exists_with_bloom_filter(messageid, 1);
}

int history_messageid_exists_rawscan(const char *messageid)
{
	/* For tasks that already use their own Bloom filter, checking a second (and likely inferior) Bloom filter is redundant */
	return history_messageid_exists_with_bloom_filter(messageid, 0);
}

int history_find_article_by_messageid(struct nntp_session *nntp, const char *messageid, const char *prefgroup, char *group, size_t len, int *artnum)
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
			/* It's possible the user is authorized for only some (or none) of the groups in which this article was posted,
			 * so skip ineligible groups. */
			if (!ACL_ALLOWED_LOCKED(nntp, grp, NNTP_ACL_READ)) {
				continue;
			}
			/* If !prefgroup, we don't care, just pick the first one.
			 * If we do, we'll prefer the group if it exists in the list.
			 * If we get to the end and there weren't any matches, use the last one. */
			if (!prefgroup || !strcmp(grp, prefgroup) || strlen_zero(restofline)) {
				safe_strncpy(group, grp, len);
				*artnum = atoi(artnumstr);
				found = 1;
				break;
			}
		}
		break;
	}
	/* When we're done, seek back to the end of the file for appends */
	SEEK_END_HISTORY(histfp);
	bbs_mutex_unlock(&histlock);
	return found ? 0 : 1;
}
