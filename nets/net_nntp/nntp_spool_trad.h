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
 * \brief Traditional file-based spool implementation
 */

struct stringlist;

int tradspool_init(void);
void tradspool_cleanup(void);
int tradspool_group_create(const char *groupname);
int tradspool_group_delete(const char *groupname);
int tradspool_group_exists(const char *groupname);
int tradspool_newnews(struct nntp_session *nntp, const char *wildmat, time_t newerthan);
int tradspool_group_seek(const char *groupname, int cur_artnum, int *new_artnum, int direction, char *msgidbuf, size_t msgidlen);
int tradspool_group_list_articles(struct nntp_session *nntp, const char *groupname, int min, int max);
int tradspool_group_overview(struct nntp_session *nntp, const char *messageid, const char *groupname, int min, int max);
int tradspool_group_overview_header(struct nntp_session *nntp, const char *field, const char *messageid, const char *groupname, int min, int max);
int tradspool_overview_header_list(struct nntp_session *nntp, enum list_category listcat, const char *argument);
int tradspool_article_create(struct article_groups *groups, struct article_info *artinfo, int srcfd, size_t len);
int tradspool_article_delete_by_number(const char *groupname, int article_num);
int tradspool_article_exists(const char *messageid);
int tradspool_article_stat(struct nntp_session *nntp, const char *messageid, const char *groupname, int article_num);
int tradspool_article_send(struct nntp_session *nntp, enum article_part_filter filter, const char *messageid, const char *groupname, int article_num);
