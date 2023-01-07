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
 * \brief Linked list of strings
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h> /* use free, calloc */
#include <string.h>

#include "include/linkedlists.h"
#include "include/stringlist.h"

/*! \brief Opaque structure for a single string in a stringlist */
struct stringitem {
	RWLIST_ENTRY(stringitem) entry;
	/* Use a FSM, so we can do 1 allocation per item, rather than 2.
	 * Must be last, since it's a flexible struct member */
	char s[0];
};

int stringlist_contains(struct stringlist *list, const char *s)
{
	struct stringitem *i;
	RWLIST_RDLOCK(list);
	RWLIST_TRAVERSE(list, i, entry) {
		if (!strcmp(i->s, s)) {
			break;
		}
	}
	RWLIST_UNLOCK(list);
	return i ? 1 : 0;
}

void stringlist_empty(struct stringlist *list)
{
	struct stringitem *i;
	RWLIST_WRLOCK(list);
	while ((i = RWLIST_REMOVE_HEAD(list, entry))) {
		free(i);
	}
	RWLIST_UNLOCK(list);
}

int stringlist_push(struct stringlist *list, const char *s)
{
	struct stringitem *i = calloc(1, sizeof(*i) + strlen(s) + 1);
	if (!i) {
		bbs_error("calloc failed\n");
		return -1;
	}
	strcpy(i->s, s); /* Safe */
	RWLIST_INSERT_HEAD(list, i, entry);
	return 0;
}
