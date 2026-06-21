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

int history_init(void);
void history_cleanup(void);

int history_add_retention_pattern(const char *key, const char *value);

/*!
 * \brief Add a received article to history
 * \param messageid The article's Message-ID
 * \param arrival_time The UNIX timestamp when the article arrived (should be ~now)
 * \param expires The UNIX timestamp of the Expires header value, or 0 if article did not contain an Expires header
 * \param bytes Number of bytes in article
 * \param links A space-separated list of group/article numbers ('/' delimited) in which the article is linked in the spool
 */
int history_add(const char *messageid, time_t arrival_time, time_t expires, size_t bytes, const char *links);

/*!
 * \brief Expire any articles which ought no longer to be retained
 * \param pattern Optionally, only remove expired articles from specified group(s)
 * \retval -1 on error
 * \returns Number of expired articles removed
 * \note This will involve spool/overview operations as well
 */
int history_expire(const char *pattern);

/*! \brief Generate the NEWNEWS response */
int history_newnews(struct nntp_session *nntp, const char *wildmat, time_t newerthan);

/*!
 * \brief Whether a message ID exists in history
 * \param messageid
 * \retval 1 Message-ID is in history
 * \retval 0 Message-ID is not (or no longer) in history
 * \note This will return 1 for expired articles still in history but no longer in any groups in the spool, so such articles can be properly refused
 */
int history_messageid_exists(const char *messageid);

/*!
 * \brief Find an article by Message-ID
 * \param nntp
 * \param[in] messageid Message-ID used for searching
 * \param[in] prefgroup The currently selected group, if one is selected. If the article exists in this group, returned info will be based on this group.
 * \param[out] group Some group which contains this article, if found. If the article exists in prefgroup, this will be prefgroup.
 * \param[in] len Size of group
 * \param[out] artnum The article number in group
 * \retval 0 on success
 * \retval -1 on error
 * \retval 1 no such article found (or user not authorized to access it)
 * \note This will return 0 for message IDs present in history if the associated article is no longer present in any groups
 */
int history_find_article_by_messageid(struct nntp_session *nntp, const char *messageid, const char *prefgroup, char *group, size_t len, int *artnum);
