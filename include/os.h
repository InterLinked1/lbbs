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
 * \brief OS details
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*! \brief Get OS name and version */
const char *bbs_get_osver(void);

/*! \brief Initialize OS name and version */
int bbs_init_os_info(void);

/*!
 * \brief Get the number of free bytes available on the system
 * \return Number of free bytes
 * \return -1 on failure
 * \note This will only check the root partition (/)
 */
long bbs_disk_bytes_free(void);
