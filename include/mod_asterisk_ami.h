/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Asterisk Manager Interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*!
 * \brief Get the global AMI session
 * \return NULL if no AMI session active
 * \return ami session
 */
struct ami_session *bbs_ami_session(void);

int __bbs_ami_callback_register(int (*callback)(struct ami_event *event, const char *eventname), void *mod);

/*!
 * \brief Register an AMI callback
 * \param callback Callback function to execute on AMI events
 * \retval 0 on success, -1 on failure
 */
#define bbs_ami_callback_register(callback) __bbs_ami_callback_register(callback, BBS_MODULE_SELF)

/*!
 * \brief Unregister an AMI callback previously registered using bbs_ami_callback_register
 * \param callback
 * \retval 0 on success, -1 on failure
 */
int bbs_ami_callback_unregister(int (*callback)(struct ami_event *event, const char *eventname));
