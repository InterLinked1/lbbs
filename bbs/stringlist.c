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
	char *s; /* Avoid a FSM, so that we can return the separately allocated string to the caller in stringlist_pop */
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
		free(i->s);
		free(i);
	}
	RWLIST_UNLOCK(list);
}

char *stringlist_pop(struct stringlist *list)
{
	struct stringitem *i;
	char *s;

	i = RWLIST_REMOVE_HEAD(list, entry);
	if (!i) {
		return NULL; /* Nothing left */
	}
	s = i->s;
	free(i); /* Free the stringitem, but not the string itself. Caller's job to do that, once done with it. */
	return s;
}

int stringlist_push(struct stringlist *list, const char *s)
{
	struct stringitem *i;
	char *sdup = strdup(s);

	if (!sdup) {
		bbs_error("strdup failed\n");
		return -1;
	}

	i = calloc(1, sizeof(*i));
	if (!i) {
		bbs_error("calloc failed\n");
		free(sdup);
		return -1;
	}
	i->s = sdup;
	RWLIST_INSERT_HEAD(list, i, entry);
	return 0;
}
