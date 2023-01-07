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
 * \brief Command History
 *
 */

/*!
 * \brief Reset the history index to the most recent element
 * \retval 0 on success, -1 on failure
 */
int bbs_history_reset(void);

/*!
 * \brief Retrieves the next oldest history entry, updating index
 * \returns History entry, NULL if no such index
 */
const char *bbs_history_older(void);

/*!
 * \brief Retrieves the next most recent history entry, updating index
 * \returns History entry, NULL if no such index
 */
const char *bbs_history_newer(void);

/*!
 * \brief Add a string to history
 * \retval 0 on success, -1 on failure
 */
int bbs_history_add(const char *s);

/*!
 * \brief Shut down history
 * \retval 0
 */
int bbs_history_shutdown(void);

/*!
 * \brief Initialize history
 * \retval 0
 * \note If bbs_history_shutdown is called, this is safe to call again.
 * \warning This history interface is global, so only one module should really be using it.
 */
int bbs_history_init(void);
