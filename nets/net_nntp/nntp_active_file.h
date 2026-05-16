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
 * \brief Active group metadata file implementation
 */

int active_file_init(void);
void active_file_cleanup(void);
int active_file_group_create(struct group_info *g);
int active_file_group_delete(const char *groupname);
int active_file_group_update(const char *groupname, int *incrlast, int last, int high, int low, int count, const char *status, const char *description);
int active_file_group_info(const char *groupname, int *last, int *high, int *low, int *count, char *status, size_t statuslen, time_t *created, char *creator, size_t creatorlen, char *description, size_t descriplen);
int active_file_group_list(struct nntp_session *nntp, enum list_category listcat, const char *wildmat);
int active_file_group_list_newgroups(struct nntp_session *nntp, time_t newerthan);
