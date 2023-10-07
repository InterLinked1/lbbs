/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief BBS user groups
 *
 */

/*!
 * \brief Check whether a group contains a user
 * \param group Name of group
 * \param user Username
 * \retval 1 if in group, 0 if not in group or group does not exist
 */
int bbs_group_contains_user(const char *group, const char *user);

/*! \brief Clean up groups */
int bbs_groups_cleanup(void);

/*! \brief Initialize groups */
int bbs_groups_init(void);
