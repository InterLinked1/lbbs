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

struct suck_pattern {
	const char *pattern;
	int min;
	int max;
	int recent;
	RWLIST_ENTRY(suck_pattern) entry;
	char data[];
};

BBS_LIST_HEAD_NOLOCK(suck_patterns, suck_pattern);

struct suck_feed {
	const char *name;
	const char *creator;
	pthread_t thread;
	struct suck_patterns patterns;
	struct bbs_url serveruri;
	unsigned int global_ordering:1; /* Internal flag for CLI command */
	unsigned int loadaftersort:1; /* Internal flag for CLI command */
	unsigned int secure:1;
	unsigned int modereader:1;
	unsigned int starttls:1;
	unsigned int compress:1;
	unsigned int done:1;
	unsigned int autocreate:1;
	unsigned int xrefslave:1;

	/* Group filters */
	int maxactivity;
	int mincount;
	int minlow;

	void *varg; /* Internal */

	struct suck_patterns groups;
	RWLIST_ENTRY(suck_feed) entry;
	char data[];
};

struct suck_feed *nntp_suckfeed_create(const char *name, const char *creator, const char *server, int modereader, int starttls, int compress, int autocreate, int xrefslave,
	int maxactivity, int mincount, int minlow);
int nntp_suckfeed_add_suckpat(struct suck_feed *sf, const char *pattern, const char *args);
int nntp_suckfeed_init(void);
void nntp_suckfeed_cleanup(void);
