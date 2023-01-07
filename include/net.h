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
 * \brief Network Protocols
 *
 */

/*! \brief Register network protocol */
int bbs_register_network_protocol(const char *name, unsigned int port);

/*! \brief Unregister network protocol */
int bbs_unregister_network_protocol(unsigned int port);

/*! \brief List all registered network protocols */
int bbs_list_network_protocols(int fd);
