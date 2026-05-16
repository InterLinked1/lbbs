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
 * \brief Abstract active group metadata interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "nntp.h"
#include "nntp_active_file.h"

int active_init(void)
{
	return active_file_init();
}

void active_cleanup(void)
{
	active_file_cleanup();
}

int active_group_create(struct group_info *g)
{
	return active_file_group_create(g);
}

int active_group_delete(const char *groupname)
{
	return active_file_group_delete(groupname);
}

int active_group_update(const char *groupname, int *incrlast, int last, int high, int low, int count, const char *status, const char *description)
{
	return active_file_group_update(groupname, incrlast, last, high, low, count, status, description);
}

int active_group_info(const char *groupname, int *last, int *high, int *low, int *count, char *status, size_t statuslen, time_t *created, char *creator, size_t creatorlen, char *description, size_t descriplen)
{
	return active_file_group_info(groupname, last, high, low, count, status, statuslen, created, creator, creatorlen, description, descriplen);
}

int active_group_list(struct nntp_session *nntp, enum list_category listcat, const char *wildmat)
{
	return active_file_group_list(nntp, listcat, wildmat);
}

int active_group_list_newgroups(struct nntp_session *nntp, time_t newerthan)
{
	return active_file_group_list_newgroups(nntp, newerthan);
}
