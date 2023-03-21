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
 * \brief Network Protocols
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/linkedlists.h"
#include "include/net.h"

struct net_prot {
	unsigned int port;
	RWLIST_ENTRY(net_prot) entry;
	char name[0];
};

static RWLIST_HEAD_STATIC(prots, net_prot);

int bbs_register_network_protocol(const char *name, unsigned int port)
{
	struct net_prot *prot;

	RWLIST_WRLOCK(&prots);
	prot = calloc(1, sizeof(*prot) + strlen(name) + 1);
	if (!prot) {
		RWLIST_UNLOCK(&prots);
		return -1;
	}

	prot->port = port;
	strcpy(prot->name, name); /* Safe */

	/* Insert in order of port */
	RWLIST_INSERT_SORTED(&prots, prot, entry, port);
	RWLIST_UNLOCK(&prots);
	bbs_verb(5, "Registered %s protocol on port %u\n", name, port);
	return 0;
}

int bbs_unregister_network_protocol(unsigned int port)
{
	struct net_prot *prot;

	prot = RWLIST_WRLOCK_REMOVE_BY_FIELD(&prots, port, port, entry);
	if (!prot) {
		bbs_warning("Failed to unregister protocol on port %u: not found\n", port);
	} else {
		free(prot);
	}

	return 0;
}

int bbs_list_network_protocols(int fd)
{
	int i = 0;
	struct net_prot *prot;

	RWLIST_RDLOCK(&prots);
	RWLIST_TRAVERSE(&prots, prot, entry) {
		if (!i++) {
			bbs_dprintf(fd, "%5s %s\n", "Port", "Protocol");
		}
		bbs_dprintf(fd, "%5d %s\n", prot->port, prot->name);
	}
	RWLIST_UNLOCK(&prots);

	if (!i) {
		/* Technically could happen, but such a BBS would be somewhat useless... */
		bbs_debug(3, "No network protocols registered?\n");
	}

	return 0;
}

int bbs_protocol_port(const char *name)
{
	int port = 0;
	struct net_prot *prot;

	RWLIST_RDLOCK(&prots);
	RWLIST_TRAVERSE(&prots, prot, entry) {
		if (!strcmp(name, prot->name)) {
			port = prot->port;
			break;
		}
	}
	RWLIST_UNLOCK(&prots);

	return port;
}
