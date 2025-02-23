/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief UUID support
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*!
 * \brief Generate a UUID (universally unique identifier), all lowercase
 * \return UUID on success, NULL on failure
 */
char *bbs_uuid(void);
