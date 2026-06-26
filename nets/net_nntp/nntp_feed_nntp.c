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
 * \brief Simple embedded NNTP feeder
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <sys/time.h> /* struct timeval for musl */

#include "include/module.h" /* use bbs_module_is_shutting_down */
#include "include/utils.h"
#include "include/node.h" /* use bbs_sendfile */

#include "nntp.h"
#include "nntp_feed.h"
#include "nntp_client.h"

/* This is an approximation - not exactly obeyed - max # of articles to ever send using a single connection before closing/reopening */
#define MAX_ARTICLES_PER_CONNECTION 120000

extern unsigned int feed_timeout;

static char backlogdir[512];
static FILE *logfp;

extern int nntp_unloading;

int feed_nntp_init(void)
{
	char logpath[512];
	snprintf(backlogdir, sizeof(backlogdir), "%s/.backlog", newsdir);
	if (bbs_ensure_directory_exists(backlogdir)) {
		return -1;
	}
	snprintf(logpath, sizeof(logpath), "%s/%s", bbs_log_dir(), "nntp_feed.log");
	logfp = fopen(logpath, "a");
	if (!logfp) {
		bbs_error("Failed to open %s: %s\n", logpath, strerror(errno));
		return -1;
	}
	return 0;
}

void feed_nntp_shutdown(void)
{
	if (logfp) {
		fclose(logfp);
	}
}

struct site_article {
	const char *messageid;
	const char *filepath;
	RWLIST_ENTRY(site_article) entry;
	size_t size;
	unsigned int offered:1;
	unsigned int refused:1;
	unsigned int rejected:1;
	unsigned int accepted:1;
	unsigned int deferred:1;
	unsigned int requeued:1;
	unsigned int missing:1;
	unsigned int skip:1;
	char data[];
};

BBS_LIST_HEAD_NOLOCK(site_articles, site_article);

static int backlog_filename(struct site *site, char *buf, size_t len)
{
	return snprintf(buf, len, "%s/%s", backlogdir, site->name);
}

static FILE *open_backlog(struct site *site, const char *mode)
{
	char feedfile[sizeof(backlogdir) + 32];
	FILE *fp;
	backlog_filename(site, feedfile, sizeof(feedfile));
	fp = fopen(feedfile, mode);
	if (!fp) {
		return NULL;
	}
	return fp;
}

static inline void log_fed_article(struct nntp_client *nc, struct site *site, struct site_article *art)
{
	char c = art->accepted ? '+' : art->rejected ? '-' : art->refused ? 'R' : art->missing ? 'M' : art->deferred ? 'D' : '*';
	int exception = c == '*';
	time_t now;
	struct timeval tvnow;
	char buf[26];

	now = time(NULL);
	ctime_r(&now, buf);

#pragma GCC diagnostic ignored "-Waggregate-return"
	tvnow = bbs_tvnow();
#pragma GCC diagnostic pop

	/* If the article was neither accepted nor refused, not explicitly deferred, log the full response */
	fprintf(logfp, "%.15s.%03d %c %s %s%s%s\n", buf + 4, (int) (tvnow.tv_usec / 1000), c, site->name, art->messageid, exception ? " " : "", exception ? nc->buf : "");
}

static int can_feed_article(struct site_article *art, struct site *site)
{
	if (!bbs_file_exists(art->filepath)) {
		/* Well, this is awkward... but better than offering an article we can't actually send.
		 * Article must've expired or been deleted while it was backlogged for this site. */
		bbs_notice("Article file %s no longer exists in the spool, can't send it to site %s!\n", art->messageid, site->name);
		art->missing = 1;
		return 0;
	}
	return 1;
}

/*! \brief Send a single article using POST (presumably via a reader connection) */
static int send_article_post(struct nntp_client *nc, struct site *site, struct site_article *art)
{
	int res;
	ssize_t wres;

	if (!can_feed_article(art, site)) {
		return 0; /* Still try to send the rest */
	}

	nntp_client_send(nc, "POST\r\n");
	res = nntp_client_expect_code(nc, SEC_MS(30), NNTP_CONT_POST);
	if (res) {
		return -1; /* If we can't POST this article, we won't be able to post any others eithers */
	}
	art->offered = 1;

	/* In order to use POST, we need to convert the article back into a compliant proto-article.
	 * As such, we need to parse the headers to omit those which MUST NOT be included in proto-articles,
	 * as we now need to behave like a compliant posting agent according to RFC 5537.
	 *
	 * Luckily, we don't need to ADD any headers, since proto-articles have strictly weaker requirements
	 * for headers than injected articles. */
	wres = spool_article_send_raw_noxref(&nc->tcpclient, art->filepath);
	if (wres <= 0) {
		return -1;
	}

	art->size = (size_t) wres;
	nntp_client_send(nc, ".\r\n");
	res = nntp_client_read_code(nc, MIN_MS(10));
	if (res < 0) {
		return -1;
	}
	switch (res) {
		case NNTP_FAIL_POST_REJECT:
			art->rejected = 1;
			log_fed_article(nc, site, art);
			break;
		case NNTP_OK_POST:
			art->accepted = 1;
			log_fed_article(nc, site, art);
			break;
		default:
			bbs_client_err("Unexpected response to POST: %s\n", nc->buf);
			return -1;
	}
	return 0;
}

/*! \brief Send a single article using IHAVE (for peers that don't support streaming) */
static int send_article_ihave(struct nntp_client *nc, struct site *site, struct site_article *art)
{
	int res;
	ssize_t sent;

	/* Whether it's more optimal to open the article before or after offering it depends on whether it's more likely the article will be accepted or rejected.
	 * If acceptance is likely, it's better to open upfront so we can bail if the article is no longer in spool for some reason.
	 * If refusal is likely, it's better to wait to avoid the overhead of opening the article only to be refused.
	 * To compromise, we go ahead and check for existence up front, opening if requested. */

	if (!can_feed_article(art, site)) {
		return 0; /* Still try to send the rest */
	}

	nntp_client_send(nc, "IHAVE %s\r\n", art->messageid);
	art->offered = 1;
	res = nntp_client_read_code(nc, MIN_MS(1));
	if (res <= 0) {
		return res ? res : -1; /* If an empty line is returned, for whatever reason (invalid), just abort */
	}
	switch (res) {
		case NNTP_FAIL_IHAVE_REFUSE: /* Site doesn't want it */
			art->refused = 1;
			return 0;
		case NNTP_FAIL_IHAVE_DEFER:
			art->deferred = 1;
			return 0;
		case NNTP_CONT_IHAVE:
			break;
		default:
			bbs_client_err("Unexpected response to IHAVE: %s\n", nc->buf);
			return -1;
	}

	/* Go ahead and send it.
	 * We don't need to worry about dot-stuffing, since the articles in the spool are stored in wire format.
	 * We MAY delete the Xref header when sending, but peers will usually ignore that anyways,
	 * and some peers may want it if configured to slave off our Xref header. */
	sent = spool_article_send_raw(&nc->tcpclient, art->filepath);
	if (sent <= 0) {
		/* Not good. We offered the article, the server accepted, and now we can't oblige.
		 * The only thing we can do now is disconnect. */
		return -1;
	}
	art->size = (size_t) sent;

	nntp_client_send(nc, ".\r\n");
	res = nntp_client_read_code(nc, MIN_MS(10));
	if (res < 0) {
		return -1;
	}
	switch (res) {
		case NNTP_FAIL_IHAVE_REJECT:
			art->rejected = 1;
			log_fed_article(nc, site, art);
			break;
		case NNTP_FAIL_IHAVE_DEFER:
			art->deferred = 1;
			log_fed_article(nc, site, art);
			break;
		case NNTP_OK_IHAVE:
			art->accepted = 1;
			log_fed_article(nc, site, art);
			break;
		default:
			bbs_client_err("Unexpected response to IHAVE: %s\n", nc->buf);
			return -1;
	}
	return 0;
}

static int takethis(struct nntp_client *nc, struct site *site, struct site_article *art)
{
	ssize_t wres;

	if (!can_feed_article(art, site)) {
		return 1; /* Can't send article, not in spool anymore? But this is not fatal */
	}

	nntp_client_send(nc, "TAKETHIS %s\r\n", art->messageid);
	if (!site->feed.nntp.checkfirst) {
		art->offered = 1; /* If we didn't send CHECK, then count it as offered now */
	}
	wres = spool_article_send_raw(&nc->tcpclient, art->filepath);
	if (wres <= 0) {
		/* If we couldn't send the article for any reason, we need to abort, since we already sent TAKETHIS */
		return -1;
	}
	art->size = (size_t) wres;
	nntp_client_send(nc, ".\r\n"); /* End of article */
	/* We are pipelining TAKETHIS, so we don't read the responses just yet */
	return 0;
}

/*! \brief Send a batch of articles using streaming */
static int send_articles_streaming(struct nntp_client *nc, struct site *site, struct site_article **head, int maxsend)
{
	struct site_article *art, *first = *head;
	int c, res;

	if (site->feed.nntp.checkfirst) {
		/* Send all the CHECK commands up front, so we can pipeline them. Afterwards, we'll read all the responses. */
		for (c = 0, art = first; art && c < maxsend; c++, art = BBS_LIST_NEXT(art, entry)) {
			art->offered = 1;
			nntp_client_send(nc, "CHECK %s\r\n", art->messageid);
		}

		/* Now, read the responses back. They should be in the same order as we sent the commands */
		for (c = 0, art = first; art && c < maxsend; c++, art = BBS_LIST_NEXT(art, entry)) {
			const char *messageid;
			res = nntp_client_read(nc, MIN_MS(5));
			if (res <= 0) {
				return -1;
			}
			bbs_term_line(nc->buf); /* Strip LF from message ID */
			messageid = bbs_strcnext(nc->buf, ' ');
			if (!messageid) {
				bbs_client_err("Unexpected CHECK response: '%s'\n", nc->buf);
				return -1;
			}
			if (strcmp(messageid, art->messageid)) {
				bbs_client_err("Article ID mismatch in CHECK response, expected '%s', got '%s'\n", art->messageid, messageid);
				return -1;
			}
			res = atoi(nc->buf); /* Parse the code */
			switch (res) {
				case NNTP_FAIL_CHECK_REFUSE:
					art->refused = 1;
					log_fed_article(nc, site, art);
					break;
				case NNTP_FAIL_CHECK_DEFER:
					art->deferred = 1;
					log_fed_article(nc, site, art);
					break;
				case NNTP_OK_CHECK:
					break; /* We don't mark anything just yet if CHECK came back OK */
				default:
					bbs_client_err("Unexpected CHECK response: '%s'\n", nc->buf);
					return -1;
			}
			if (site->feed.nntp.wantexit) {
				return -1;
			}
		}
	}

	/* Send the articles, using TAKETHIS */
	for (c = 0, art = first; art && c < maxsend; c++, art = BBS_LIST_NEXT(art, entry)) {
		if (site->feed.nntp.wantexit || art->refused || art->deferred) {
			art->skip = 1;
			continue; /* Don't send any more articles, but do read the responses to the ones we've sent so far */
		}
		if (takethis(nc, site, art) < 0) {
			break;
		}
	}

	/* Finally, read the responses to TAKETHIS */
	for (c = 0, art = first; art && c < maxsend; c++, art = BBS_LIST_NEXT(art, entry)) {
		const char *messageid;
		if (art->skip) {
			break; /* If we aborted TAKETHIS above, then there are no more responses to read now */
		}
		res = nntp_client_read(nc, MIN_MS(15)); /* Since articles are large, we are very patient here, all the pipelined writes could take a long time on a slow link */
		if (res <= 0) {
			return -1;
		}
		bbs_term_line(nc->buf); /* Strip LF from message ID */
		res = atoi(nc->buf); /* Parse the code */
		if (res != NNTP_FAIL_TAKETHIS_REJECT && res != NNTP_FAIL_TERMINATING && res != NNTP_OK_TAKETHIS) {
			/* Probably a 4xx or 5xx error */
			bbs_notice("TAKETHIS failed: %s\n", nc->buf);
			return -1;
		}
		messageid = bbs_strcnext(nc->buf, ' ');
		if (!messageid) {
			bbs_client_err("Unexpected TAKETHIS response: '%s'\n", nc->buf);
			return -1;
		}
		if (strcmp(messageid, art->messageid)) {
			bbs_client_err("Article ID mismatch in TAKETHIS response, expected '%s', got '%s'\n", art->messageid, messageid);
			return -1;
		}
		switch (res) {
			case NNTP_FAIL_TAKETHIS_REJECT:
				art->rejected = 1;
				log_fed_article(nc, site, art);
				break;
			case NNTP_FAIL_TERMINATING:
				/* Disconnecting is the only way to defer articles with TAKETHIS, so we handle it but don't treat as officially deferred for stats */
				art->requeued = 1;
				log_fed_article(nc, site, art);
				break;
			case NNTP_OK_TAKETHIS:
				art->accepted = 1;
				log_fed_article(nc, site, art);
				break;
			default:
				log_fed_article(nc, site, art);
				bbs_client_err("Unexpected TAKETHIS response: '%s'\n", nc->buf);
				return -1;
		}
	}
	*head = art; /* Save the first unprocessed article for the next batch */
	return 0;
}

static struct site_article *find_article(struct site_articles *articles, const char *messageid)
{
	struct site_article *art;
	BBS_LIST_TRAVERSE(articles, art, entry) {
		if (!strcmp(art->messageid, messageid)) {
			return art;
		}
	}
	return NULL;
}

/*! \note Must be called locked */
static int merge_backlog(struct site *site, struct site_articles *articles, int remaining)
{
	FILE *fp;
	char buf[NNTP_MAX_LINE_LENGTH];
	char backlogpath[sizeof(backlogdir) + 32];
	struct site_article *art;
	char tmpfilepath[TMPNAME_BUFSIZ];

	/* We can prune articles from the backlog.
	 * This is the common case; in most cases, if we are able to connect to a peer at all,
	 * most articles will be either accepted or refused/rejected, i.e. most of the file can get thrown away. */

	bbs_renamable_tempname("nntpfeedtmp", tmpfilepath, sizeof(tmpfilepath));
	fp = bbs_mkftemp(tmpfilepath, 0600);
	if (!fp) {
		return -1;
	}

	if (!site->feed.nntp.fp) {
		site->feed.nntp.fp = open_backlog(site, "r"); /* only need to read old file if not already open */
		if (!site->feed.nntp.fp) {
			return -1;
		}
	} else {
		if (fseek(site->feed.nntp.fp, SEEK_SET, 0)) { /* Rewind to beginning */
			bbs_error("fseek failed: %s\n", strerror(errno));
			return -1;
		}
	}

	/* Iterate over the old file and build a new backlog file, not including the entries that were accepted/rejected */
	art = BBS_LIST_FIRST(articles);
	while ((fgets(buf, sizeof(buf), site->feed.nntp.fp))) {
		char *tmp;
		const char *messageid;
		tmp = strchr(buf, '\n');
		if (tmp) {
			*tmp = '\0'; /* Strip LF for processing, add it back if we need to backlog again */
		}
		messageid = bbs_strcnext(buf, ' ');
		if (strlen_zero(messageid)) {
			bbs_error("Malformed line in backlog file for site %s\n", site->name);
			continue;
		}
		if (strcmp(messageid, art->messageid)) {
			/* Since we pulled the first N matches out of the file, and only one thread processes the backlog, we should match the first N lines in the file too.
			 * This is odd. */
			art = find_article(articles, messageid);
			if (art) {
				bbs_warning("Article %s reordered in backlog?\n", messageid);
			} else {
				/* Something invalid was in the backlog or it somehow disappeared? */
				bbs_warning("Article %s disappeared from backlog after processing?\n", messageid);
				continue;
			}
		}
		if (art->accepted || art->refused || art->rejected || art->missing) {
			if (!--remaining) {
				break;
			}
		} else {
			/* Need to copy article to new backlog to retry later
			 * Note that the original order is preserved, i.e. deferred articles do not go to the end but their original position. */
			size_t buflen;
			if (tmp) {
				*tmp = '\n'; /* Restore the LF so we can use fwrite instead of fprintf */
			}
			buflen = strlen(buf);
			if (fwrite(buf, 1, buflen, fp) != buflen) {
				/* If we can't write for whatever reason, abort now. We don't want to miss carrying anything over and drop articles */
				bbs_error("fwrite(%s) failed: %s\n", tmpfilepath, strerror(errno));
				fseek(site->feed.nntp.fp, SEEK_END, 0); /* Rewind back to end before leaving */
				bbs_delete_file(tmpfilepath);
				return -1;
			}
		}
		art = BBS_LIST_NEXT(art, entry);
	}
	/* Anything left, just copy over - we could use bbs_copy_file to be more efficient,
	 * but since this is probably just a handful of articles that showed up while we were processing
	 * backlog, shouldn't make much difference. */
	while ((fgets(buf, sizeof(buf), site->feed.nntp.fp))) {
		fwrite(buf, 1, strlen(buf), fp);
	}
	fclose(fp); /* Close new file */
	fclose(site->feed.nntp.fp); /* Close old file */
	backlog_filename(site, backlogpath, sizeof(backlogpath));
	if (remaining) {
		bbs_warning("%d article%s processed no longer in backlog for %s?\n", remaining, ESS(remaining), site->name);
	}
	if (bbs_rename(tmpfilepath, backlogpath)) {
		bbs_delete_file(tmpfilepath);
		site->feed.nntp.fp = open_backlog(site, "a+"); /* Reopen for appending at end regardless */
		return -1;
	}
	site->feed.nntp.fp = open_backlog(site, "a+"); /* Now writers can start appending again */
	return 0;
}

struct feed_stats {
	int accepted;
	int refused;
	int rejected;
	int deferred;
	int requeued;
	int missing;
	int unattempted;
	int offered;
	int total;
	size_t accsize;
};

static void process_sent_articles(struct site *site, struct site_articles *articles, struct feed_stats *fs)
{
	struct site_article *art;
	int res = 0;
	int total_eliminated = 0;
	struct site_feed_stats aggstats;

	memset(&aggstats, 0, sizeof(aggstats));

	/* Note that the feed stats may already have values from previous batches sent using this same connection
	 * Therefore we only add to these values, rather than replacing them. */
	BBS_LIST_TRAVERSE(articles, art, entry) {
		if (art->refused) {
			aggstats.refused++;
		} else if (art->rejected) {
			aggstats.rejected++;
		} else if (art->accepted) {
			aggstats.accepted++;
			aggstats.accsize += art->size;
		} else if (art->deferred) {
			fs->deferred++;
		} else if (art->requeued) {
			fs->requeued++; /* Functionally equivalent to deferred, e.g. TAKETHIS responded with a 400 and closed the connection */
		} else if (art->missing) {
			fs->missing++;
		} else {
			fs->unattempted++; /* We had it in the list, but never attempted to send the article */
		}
		fs->total++;
		if (art->offered) {
			aggstats.offered++;
		}
		if (art->accepted || art->refused || art->rejected || art->missing) {
			total_eliminated++;
		}
	}

	/* We use values only from this round as otherwise we would add the same values again potentially if using the fs values */
	nntp_feed_add_stats(site, &aggstats);

	fs->offered += aggstats.offered;
	fs->accepted += aggstats.accepted;
	fs->refused += aggstats.refused;
	fs->rejected += aggstats.rejected;
	fs->accsize += aggstats.accsize;

	if (total_eliminated) {
		bbs_mutex_lock(&site->feed.nntp.lock);
		res = merge_backlog(site, articles, total_eliminated);
		if (!res) {
			/* Reduce backlogcount by the # of entries removed from the backlog file */
			site->feed.nntp.backlogcount -= total_eliminated;
			bbs_debug(3, "Removed %d article%s from backlog for %s\n", total_eliminated, ESS(total_eliminated), site->name);
		}
		bbs_mutex_unlock(&site->feed.nntp.lock);
	}
}

/*!
 * \brief Try to send all the backlogged/queued articles to the remote site
 * \param site
 * \retval 0 finished for now, idle for a bit and try to send more articles later
 * \retval -1 disconnect for now
 */
static int send_articles(struct nntp_client *nc, struct site *site, struct feed_stats *feedstats)
{
	struct site_articles articles;
	struct site_article *art;
	int lineno = 1;
	int count = 0;
	int res;
	char buf[NNTP_MAX_LINE_LENGTH];

	BBS_LIST_HEAD_INIT(&articles);

	/* The nice thing about NNTP is that there is no real harm in sending a duplicate article; the site will simply reject it.
	 * For that reason, the way we process articles is in each "pass", we load a list of articles that we want to send. Then we try to send them (using streaming if possible).
	 * We keep track of which articles were sent successfully, which were rejected, and which need to be retried.
	 * Finally, we remove the successes and the permanent rejections from the queued file.
	 * If for some reason we don't get to the last part (e.g. a crash), no real harm done because it's impossible
	 * for articles already in the backlog file to get removed if they haven't been sent. */
	bbs_mutex_lock(&site->feed.nntp.lock);
	/* Use the existing file handle, we only need it for a moment so we won't hold up writers too long */
	if (bbs_assertion_failed(site->feed.nntp.fp != NULL)) {
		/* This shouldn't happen... in both the init case and the normal NNTP thread append case,
		 * the file handle is open by this point. */
		bbs_mutex_unlock(&site->feed.nntp.lock);
		return -1;
	}
	/* Seek to beginning to start reading */
	if (fseek(site->feed.nntp.fp, 0, SEEK_SET) < 0) {
		bbs_error("fseek failed: %s\n", strerror(errno));
		bbs_mutex_unlock(&site->feed.nntp.lock);
		return -1;
	}
	for (;(fgets(buf, sizeof(buf), site->feed.nntp.fp)); lineno++) {
		char *filepath, *messageid = buf;
		size_t filepathlen;
		bbs_term_line(buf); /* Strip trailing LF from message ID */
		filepath = strsep(&messageid, " ");
		if (strlen_zero(filepath) || strlen_zero(messageid) || messageid[0] != '<') {
			bbs_error("Malformed line in backlog file for site %s, line %d\n", site->name, lineno);
			continue;
		}
		filepathlen = strlen(filepath);
		/* We don't immediately check here if the article exists in the spool.
		 * If not streaming, we check before offering each article.
		 * For streaming, we only check for articles requested following CHECK,
		 * so we can avoid needing to check for existence in most cases. */
		art = calloc(1, sizeof(*art) + filepathlen + strlen(messageid) + 2);
		if (ALLOC_FAILURE(art)) {
			continue;
		}
		strcpy(art->data, filepath); /* Safe */
		art->filepath = art->data;
		strcpy(art->data + filepathlen + 1, messageid); /* Safe */
		art->messageid = art->data + filepathlen + 1;
		BBS_LIST_INSERT_TAIL(&articles, art, entry); /* Preserve the order articles were added to the backlog */
		count++;
	}
	/* Should be at end of file now, which is where we want to leave it so writers can append in the meantime */
	bbs_mutex_unlock(&site->feed.nntp.lock);

	/* Now, try to send the articles */
	if (site->feed.nntp.post) {
		/* Reinject the article using a reader connection with POST.
		 * This can incur a greater risk of loops/duplicates.
		 * It's not really the way that articles are intended to be fed to peers,
		 * but is supported for small sites that may not have peering. */
		BBS_LIST_TRAVERSE(&articles, art, entry) {
			res = send_article_post(nc, site, art);
			if (res || site->feed.nntp.wantexit) {
				break;
			}
		}
	} else if (nc->caps.streaming) {
		struct site_article *head = BBS_LIST_FIRST(&articles);
		if (site->feed.nntp.batchsize && count > site->feed.nntp.batchsize) {
			/* We don't want to pipeline a zillion articles at once, break it up into batches.
			 * We keep the linked list intact, but adjust the head we pass into send_articles_streaming,
			 * along with a max # of articles to send for that batch. */
			do {
				res = send_articles_streaming(nc, site, &head, site->feed.nntp.batchsize);
				if (res) {
					goto done;
				}
				count -= site->feed.nntp.batchsize;
			} while (count > site->feed.nntp.batchsize);
			if (count) {
				res = send_articles_streaming(nc, site, &head, count);
			}
		} else {
			res = send_articles_streaming(nc, site, &head, count);
		}
	} else {
		BBS_LIST_TRAVERSE(&articles, art, entry) {
			res = send_article_ihave(nc, site, art);
			if (res || site->feed.nntp.wantexit) {
				break;
			}
		}
	}

	/* Even if the server disconnected part way through, we may still have sent some articles.
	 * Remove any sent articles that were either accepted/rejected from our backlog. */
done:
	process_sent_articles(site, &articles, feedstats);
	BBS_LIST_REMOVE_ALL(&articles, entry, free);
	return res;
}

static int wait_for_more_articles(struct nntp_client *nc, struct site *site)
{
	site->feed.nntp.waiting = 1;
	/* XXX There is a small chance that a writing thread could signal us here, after setting flag but before sleeping */
	bbs_tcp_client_safe_sleep(&nc->tcpclient, (int) feed_timeout); /* Wait this long for more articles, then close the connection. */
	site->feed.nntp.waiting = 0;

	/* If we got interrupted, check if there are more articles to deliver */
	if (site->feed.nntp.processmore) {
		return 0;
	}
	/* Anything else, we should abort */
	if (site->feed.nntp.wantexit) {
		bbs_debug(3, "NNTP feeder thread for %s told to exit\n", site->name);
	}
	return -1;
}

/*! \brief The thread that handle feeding articles to a site via NNTP. At the moment, only one thread/connection per site is supported. */
static void feed_thread(struct site *site)
{
	int res, spooled;
	struct feed_stats fs;
	time_t elapsed, start;
	struct bbs_url url;
	struct nntp_client nc_stack, *nc = &nc_stack;

	memset(&nc->tcpclient, 0, sizeof(struct bbs_tcp_client));
	memset(&url, 0, sizeof(url));
	url.port = site->feed.nntp.port;

	start = time(NULL);

	/* If we have an explicit hostname, use that.
	 * Otherwise, if any exclusions are specified, use the first exclusion.
	 * Otherwise, use the site name (assume it's the hostname, since it's probably the site's path identity) */
	url.host = site->feed.nntp.hostname;
	if (!url.host) {
		url.host = stringlist_peek(&site->exclusions);
		if (!url.host) {
			url.host = site->name;
		}
	}

	/* We're not really "waiting" here, but connect() can take some time,
	 * so allow ourselves to be interrupted here if we want to shut down feeding.
	 * This scenario actually occurs in test_nntp_transit, speeding the test up so we don't need to wait 30 seconds. */
	site->feed.nntp.waiting = 1;
	res = nntp_client_connect(nc, &url, site->feed.nntp.secure);
	site->feed.nntp.waiting = 0;
	if (res || site->feed.nntp.wantexit) {
		goto done;
	}

	if (site->feed.nntp.modereader && nntp_client_mode_reader(nc)) {
		bbs_client_err("MODE READER failed for %s (%s), aborting\n", site->name, nc->buf);
		goto done;
	}

	res = nntp_client_capabilities(nc);
	if (res) {
		goto done;
	}

	/* Use encryption and compression if configured */
	if (site->feed.nntp.starttls) {
		if (nntp_client_starttls(nc)) {
			goto done;
		}
		/* Following STARTTLS, the capabilities may change, so check again. Particularly important as AUTHINFO may require encryption.
		 * If further actions would depend on these capabilities, ask for them again. */
		if ((site->feed.nntp.username && (!nc->caps.authinfo_user || !nc->caps.sasl_plain)) || (site->feed.nntp.compress && !nc->caps.compress)) {
			res = nntp_client_capabilities(nc);
			if (res) {
				goto done;
			}
		}
	}
	if (site->feed.nntp.compress) {
		if (nntp_client_compress(nc)) {
			goto done;
		}
		/* Capabilities probably won't change after activating compression alone (aside from COMPRESS DEFLATE no longer being advertised maybe, which is no longer relevant anyways) */
	}

	/* If we need to authenticate, do that next */
	if (site->feed.nntp.username && nntp_client_authenticate(nc, site->feed.nntp.username, site->feed.nntp.password)) {
		goto done;
	}

	/* We are only here if there is at least one article in the queue to send.
	 * After we have sent it, we may keep the connection open for a bit,
	 * in case we have another article to send soon. */
	memset(&fs, 0, sizeof(fs));
	for (;;) {
		site->feed.nntp.processmore = 0;
		if (site->feed.nntp.wantexit || send_articles(nc, site, &fs)) {
			break;
		}
		/* This isn't a strict upper limit; in any given call to send_articles, we could exceed this;
		 * if, however, we've determine we've exceeded this, close the connection and open a new one,
		 * so that we refresh even busy connections periodically. (A new one will probably get opened soon.) */
		if (site->feed.nntp.wantexit || fs.total > MAX_ARTICLES_PER_CONNECTION) {
			break;
		}
		if (site->feed.nntp.processmore) {
			continue; /* There are already more articles to process */
		}
		/* Sleep for a little bit, in case there are more articles to process shortly */
		if (!feed_timeout || wait_for_more_articles(nc, site)) {
			break;
		}
	}

	/* Log feed stats when we close the connection.
	 * Similar to the log message document in INN's infeed: https://github.com/InterNetNews/inn/blob/master/doc/pod/innfeed.pod
	 * We don't log rejsize because for articles which are refused by IHAVE or CHECK, we never open the article or check its size. */
	spooled = fs.unattempted + fs.deferred + fs.requeued;
	elapsed = time(NULL) - start;
	bbs_notice("%s checkpoint: seconds %ld offered %d accepted %d refused %d rejected %d deferred %d requeued %d missing %d accsize %lu spooled %d\n",
		site->name, elapsed, fs.offered, fs.accepted, fs.refused, fs.rejected, fs.deferred, fs.requeued, fs.missing, fs.accsize, spooled);

done:
	/* If we failed to establish the connection at all, we don't bother logging the above as it would just be all 0s */
	bbs_tcp_client_cleanup(&nc->tcpclient);
}

static void *__feed_thread(void *varg)
{
	struct site *site = varg;
	bbs_debug(4, "Launched feeder thread for site %s\n", site->name);
	feed_thread(site);
	site->feed.nntp.thread_done = 1;
	return NULL;
}

static FILE *site_has_queued_articles(struct site *site)
{
	char buf[NNTP_MAX_LINE_LENGTH];
	FILE *fp = open_backlog(site, "r+"); /* Don't create the file if it doesn't already exist */
	if (!fp) {
		return NULL; /* If backlog file doesn't exist, then no queued articles */
	}
	fseek(fp, 0, SEEK_SET); /* according fseek(3), when using a+ mode, the read offset is not specified by POSIX, so explicitly seek to beginning */
	while ((fgets(buf, sizeof(buf), fp))) {
		if (strchr(buf, '<')) { /* Found a message ID somewhere */
			site->feed.nntp.backlogcount++;
		}
	}
	/* Now at EOF */
	return fp;
}

static int spawn_feed_thread(struct site *site)
{
	/* Launch a thread to process articles for this feed.
	 * Note that after we return and unlock the sites list, this thread
	 * will have a reference to sites when the list is not locked.
	 * However, we ensure that whenever removing site from the list,
	 * we join the thread, so site can't disappear on us. */
	if (bbs_pthread_create(&site->feed.nntp.thread, NULL, __feed_thread, site)) {
		return -1;
	}
	return 0;
}

int feed_nntp_init_feed(struct site *site)
{
	bbs_mutex_lock(&site->feed.nntp.lock);
	site->feed.nntp.fp = site_has_queued_articles(site);
	if (!site->feed.nntp.fp) {
		bbs_mutex_unlock(&site->feed.nntp.lock);
		return 0;
	}
	/* If there are articles in queue, launch a thread now to process them, unless 'Q' flag is set.
	 * We already opened the file handle and can reuse that now. */
	if (!site->feed.nntp.queue && spawn_feed_thread(site)) {
		bbs_mutex_unlock(&site->feed.nntp.lock);
		return -1;
	}
	bbs_mutex_unlock(&site->feed.nntp.lock);
	return 0;
}

void feed_nntp_cleanup_feed(struct site *site)
{
	bbs_mutex_lock(&site->feed.nntp.lock);

	if (site->feed.nntp.thread) {
		site->feed.nntp.wantexit = 1;
		if (!site->feed.nntp.thread_done && site->feed.nntp.waiting) { /* Don't interrupt unless thread is waiting or we may interrupt a transmission, let it end gracefully */
			bbs_pthread_interrupt(site->feed.nntp.thread);
		}
		/* Release the lock to wait or we'll deadlock when the feeder thread calls merge_backlog upon exit.
		 * (It needs the mutex to ensure no further articles are written to the backlog simultaneously.)
		 * feed_nntp_cleanup_feed can only be called once, so we're not worried about concurrency right here either. */
		bbs_mutex_unlock(&site->feed.nntp.lock);
		bbs_pthread_join(site->feed.nntp.thread, NULL);
		bbs_mutex_lock(&site->feed.nntp.lock);
	}
	if (site->feed.nntp.fp) {
		fclose(site->feed.nntp.fp);
		site->feed.nntp.fp = NULL;
	}
	free_if(site->feed.nntp.hostname);
	free_if(site->feed.nntp.username);
	free_if(site->feed.nntp.password);

	bbs_mutex_unlock(&site->feed.nntp.lock);
	bbs_mutex_destroy(&site->feed.nntp.lock);
	/* don't need to free site itself here */
}

static inline void cleanup_old_feed_thread(struct site *site)
{
	if (site->feed.nntp.thread && site->feed.nntp.thread_done) {
		bbs_pthread_join(site->feed.nntp.thread, NULL); /* Since thread exited, this will complete immediately */
		/* Reset for the next thread: */
		site->feed.nntp.thread = 0;
		site->feed.nntp.thread_done = 0;
	}
}

int feed_nntp_send(struct article_info *artinfo, struct site *site)
{
	/* So as not to block the client thread here, we do a minimal
	 * number of things here before handing things off to another thread.
	 * The most important thing is to log the article info somewhere persistent;
	 * this way, even if we exit/reload/crash, etc. before the article can
	 * be sent, it will get retried later. */

	bbs_mutex_lock(&site->feed.nntp.lock);
	if (!site->feed.nntp.fp) {
		site->feed.nntp.fp = open_backlog(site, "a+"); /* we'll also read from the file from the feeder thread */
		if (!site->feed.nntp.fp) {
			/* Well, this is bad. This article is getting dropped and may not reach the site. */
			bbs_error("Failed to append to backlog for %s: %s\n", site->name, strerror(errno));
			bbs_mutex_unlock(&site->feed.nntp.lock);
			return -1;
		}
	}

	/* This is the same format (more or less) used by INN, so we use it too */
	fprintf(site->feed.nntp.fp, "%s %s\n", artinfo->filepath, artinfo->messageid);
	fflush(site->feed.nntp.fp); /* Flush file so the reader can see this */
	site->feed.nntp.backlogcount++;
	site->feed.nntp.processmore = 1;

	/* If there was a previous thread that exited, reap it before spawning a new one */
	cleanup_old_feed_thread(site);

	if (!nntp_unloading && !site->feed.nntp.queue) { /* If 'Q' flag set, we only queue articles during propagation but don't actually send them immediately */
		if (site->feed.nntp.thread) {
			if (site->feed.nntp.waiting) {
				/* Interrupt the thread to wake it up */
				bbs_pthread_interrupt(site->feed.nntp.thread);
			}
		} else {
			if (spawn_feed_thread(site)) {
				bbs_mutex_unlock(&site->feed.nntp.lock);
				return -1;
			}
		}
	}
	bbs_mutex_unlock(&site->feed.nntp.lock);
	return 0;
}

int feed_nntp_flush(struct site *site)
{
	bbs_mutex_lock(&site->feed.nntp.lock);
	cleanup_old_feed_thread(site);
	if (!site->feed.nntp.backlogcount) {
		/* There are no articles to flush, don't bother spawning a thread to connect and do nothing */
		bbs_mutex_unlock(&site->feed.nntp.lock);
		return 1;
	}
	if (!nntp_unloading) { /* We were explicitly told to flush, so 'Q' flag is ignored */
		if (site->feed.nntp.thread) {
			if (site->feed.nntp.waiting) {
				/* Interrupt the thread to wake it up */
				bbs_pthread_interrupt(site->feed.nntp.thread);
			}
		} else {
			if (spawn_feed_thread(site)) {
				bbs_mutex_unlock(&site->feed.nntp.lock);
				return -1;
			}
		}
	}
	bbs_mutex_unlock(&site->feed.nntp.lock);
	return 0;
}
