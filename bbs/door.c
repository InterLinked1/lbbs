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
 * \brief BBS doors
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/door.h"
#include "include/linkedlists.h"
#include "include/module.h"

struct bbs_door {
	/*! Door function */
	int (*execute)(DOOR_PARAMS);
	/*! Module registering the door */
	struct bbs_module *module;
	/* Next entry */
	RWLIST_ENTRY(bbs_door) entry;
	/*! The name of the door. */
	char name[0];
};

static RWLIST_HEAD_STATIC(doors, bbs_door);

/*! \note door list must be RDLOCKed */
static struct bbs_door *find_door(const char *name)
{
	struct bbs_door *door;

	RWLIST_TRAVERSE(&doors, door, entry) {
		if (!strcmp(door->name, name)) {
			break;
		}
	}
	return door;
}

int bbs_unregister_door(const char *name)
{
	struct bbs_door *door;

	RWLIST_WRLOCK(&doors);
	RWLIST_TRAVERSE_SAFE_BEGIN(&doors, door, entry) {
		if (!strcmp(door->name, name)) {
			RWLIST_REMOVE_CURRENT(entry);
			/* Destroy the door */
			free(door);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&doors);

	if (!door) {
		bbs_warning("Failed to unregister door '%s': not found\n", name);
	}

	return door ? 0 : -1;
}

int __bbs_register_door(const char *name, int (*execute)(DOOR_PARAMS), void *mod)
{
	struct bbs_door *door;
	int length, res = -1;

	RWLIST_WRLOCK(&doors);
	door = find_door(name);
	if (door) {
		bbs_warning("Door '%s' is already registered\n", name);
		goto cleanup;
	}
	/* It doesn't already exist, we're good. */
	length = sizeof(*door) + strlen(name) + 1;
	door = calloc(1, length);
	if (!door) {
		goto cleanup;
	}
	strcpy(door->name, name); /* Safe */
	door->execute = execute;
	door->module = mod;
	res = 0;
	RWLIST_INSERT_TAIL(&doors, door, entry);
	bbs_verb(4, "Registered door '%s'\n", door->name);

cleanup:
	RWLIST_UNLOCK(&doors);
	return res;
}

int bbs_list_doors(int fd)
{
	int c = 0;
	struct bbs_door *door;

	RWLIST_RDLOCK(&doors);
	RWLIST_TRAVERSE(&doors, door, entry) {
		/* Doors can't be unregistered by modules without a WRLOCK being obtained.
		 * Since we're holding a RDLOCK, it's safe to go ahead and print the module name. */
		bbs_dprintf(fd, "%3d => %-15s (%s)\n", ++c, door->name, bbs_module_name(door->module));
	}
	RWLIST_UNLOCK(&doors);
	bbs_dprintf(fd, "%d door%s registered\n", c, ESS(c));
	return 0;
}

int bbs_door_exec(struct bbs_node *node, const char *name, const char *args)
{
	int res;
	struct bbs_door *door;

	RWLIST_RDLOCK(&doors);
	door = find_door(name);

	if (!door) {
		RWLIST_UNLOCK(&doors);
		bbs_warning("Door not found: '%s'\n", name);
		return 0; /* Don't disconnect the node */
	}

	/* Ref module before unlocking */
	bbs_module_ref(door->module);
	RWLIST_UNLOCK(&doors);
	res = door->execute(node, args);
	bbs_module_unref(door->module);
	return res;
}
