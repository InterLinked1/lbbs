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
 * \brief Asterisk Queue Position System
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

struct queue_call_handle {
	/* Agent info */
	struct bbs_node *node;	/*!< Node of agent handling call */
	int agentid;			/*!< ID of agent handling call */
	/* Call info */
	int id;					/*!< Queue call ID */
	const char *queuetitle;	/*!< Queue title */
	const char *channel;	/*!< Channel name */
	int ani2;				/*!< ANI II */
	unsigned long ani;		/*!< ANI */
	unsigned long dnis;		/*!< DNIS */
	const char *cnam;		/*!< CNAM */
};

int __bbs_queue_call_handler_register(const char *name, int (*handler)(struct queue_call_handle *qch), void *mod);

/*!
 * \brief Register a queue call handler
 * \param name Name of handler to register
 * \retval 0 on success, -1 on failure
 */
#define bbs_queue_call_handler_register(name, handler) __bbs_queue_call_handler_register(name, handler, BBS_MODULE_SELF)

/*!
 * \brief Unregister a queue call handler
 * \param name Name of registered handler
 * \retval 0 on success, -1 on failure
 */
int bbs_queue_call_handler_unregister(const char *name);
