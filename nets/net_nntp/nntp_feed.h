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
 * \brief NNTP feeds
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/stringlist.h"

struct article_info;
struct site;

enum feed_type {
	FEED_UNKNOWN,
	FEED_NNTP,
};

struct site_feed_stats {
	int offered;
	int accepted;
	int refused;
	int rejected;
	size_t accsize;
};

/*! \brief A site as configured in [outgoing] */
struct site {
	const char *name; /*!< Site name */
	struct stringlist exclusions; /*!< Additional path identity exclusions */
	const char *groups; /*!< Groups to send (or not), including poison patterns */
	char *dists[MAX_ARTICLE_DISTRIBUTIONS]; /*!< Distributions to send (or not), including poison patterns */
	enum feed_type type; /*!< Feed type */
	/* Flags */
	size_t maxsize; /*!< Maximum article size to send */
	size_t minsize; /*!< Minimum article size to send */
	/* Checks */
	unsigned int exclusionsonly:1; /*!< Ap: only check exclusions against path identities */
	/* What to send */
	unsigned int sendpath:1; /*!< WP: send Path header */
	union {
		/* For FEED_NNTP */
		struct {
			bbs_mutex_t lock;
			FILE *fp; /*!< File to which articles to feed are written */
			pthread_t thread; /*!< Feeder thread */
			char *hostname; /*!< NNTP hostname for feeding */
			char *username; /*!< NNTP username to authenticate to peer */
			char *password; /*!< NNTP password to authenticate to peer */
			int port; /*!< NNTP port */
			int backlogcount; /*!< Number of outstanding articles to send to this peer */
			int batchsize; /*!< Max batch size for streaming */
			unsigned int checkfirst:1; /*!< CHECK before TAKETHIS */
			unsigned int compress:1; /*!< Use COMPRESS DEFLATE */
			unsigned int modereader:1; /*!< Send MODE READER */
			unsigned int post:1; /*!< POST using a reader account */
			unsigned int queue:1; /*!< Queue articles until flushed */
			unsigned int starttls:1; /*!< Use STARTTLS */
			unsigned int secure:1; /*!< Implicit TLS */
			/* Internal */
			unsigned int processmore:1; /*!< More articles to process */
			unsigned int waiting:1; /*!< Waiting for articles */
			unsigned int wantexit:1; /*!< Want thread to exit */
			unsigned int thread_done:1; /*!< Thread done running */
			struct site_feed_stats stats;
		} nntp;
	} feed;
	/* Other */
	RWLIST_ENTRY(site) entry;
	char data[];
};

void nntp_feed_add_stats(struct site *site, struct site_feed_stats *s);

/* NNTP feed type */
int feed_nntp_init(void);
void feed_nntp_shutdown(void);
int feed_nntp_init_feed(struct site *site);
void feed_nntp_cleanup_feed(struct site *site);
int feed_nntp_send(struct article_info *artinfo, struct site *site);
int feed_nntp_flush(struct site *site);
