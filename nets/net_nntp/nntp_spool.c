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
 * \brief Abstract spool interface
 */

#include "include/bbs.h"

#include "nntp.h"
#include "nntp_spool_trad.h"

int spool_init(void)
{
	return tradspool_init();
}

void spool_cleanup(void)
{
	return tradspool_cleanup();
}

int spool_group_create(const char *groupname)
{
	return tradspool_group_create(groupname);
}

int spool_group_delete(const char *groupname)
{
	return tradspool_group_delete(groupname);
}

int spool_group_exists(const char *groupname)
{
	return tradspool_group_exists(groupname);
}

int spool_group_seek(const char *groupname, int cur_artnum, int *new_artnum, int direction, char *msgidbuf, size_t msgidlen)
{
	return tradspool_group_seek(groupname, cur_artnum, new_artnum, direction, msgidbuf, msgidlen);
}

int spool_group_list_articles(struct nntp_session *nntp, const char *groupname, int min, int max)
{
	return tradspool_group_list_articles(nntp, groupname, min, max);
}

int spool_group_overview(struct nntp_session *nntp, const char *messageid, const char *groupname, int min, int max)
{
	return tradspool_group_overview(nntp, messageid, groupname, min, max);
}

int spool_article_create(struct article_groups *groups, struct article_info *artinfo, int srcfd, size_t len)
{
	return tradspool_article_create(groups, artinfo, srcfd, len);
}

int spool_article_delete_by_number(const char *groupname, int article_num)
{
	return tradspool_article_delete_by_number(groupname, article_num);
}

int spool_article_exists(const char *messageid)
{
	return tradspool_article_exists(messageid);
}

int spool_article_stat(struct nntp_session *nntp, const char *messageid, const char *groupname, int article_num)
{
	return tradspool_article_stat(nntp, messageid, groupname, article_num);
}

int spool_article_send(struct nntp_session *nntp, enum article_part_filter filter, const char *messageid, const char *groupname, int article_num)
{
	return tradspool_article_send(nntp, filter, messageid, groupname, article_num);
}
