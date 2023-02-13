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
 * \brief BBS menu handlers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/handler.h"
#include "include/linkedlists.h"
#include "include/module.h"
#include "include/variables.h"

struct menu_handler {
	/*! Menu handler function */
	int (*execute)(struct bbs_node *node, char *args);
	/*! Whether this menu handler requires arguments */
	unsigned int needargs:1;
	/*! Module registering the menu handler */
	struct bbs_module *module;
	/* Next entry */
	RWLIST_ENTRY(menu_handler) entry;
	/*! The name of the menu handler. */
	char name[0];
};

static RWLIST_HEAD_STATIC(handlers, menu_handler);

/*! \note handler list must be RDLOCKed */
static struct menu_handler *find_handler(const char *name)
{
	struct menu_handler *handler;

	RWLIST_TRAVERSE(&handlers, handler, entry) {
		if (!strcmp(handler->name, name)) {
			break;
		}
	}
	return handler;
}

int bbs_unregister_menu_handler(const char *name)
{
	struct menu_handler *handler;

	RWLIST_WRLOCK(&handlers);
	RWLIST_TRAVERSE_SAFE_BEGIN(&handlers, handler, entry) {
		if (!strcmp(handler->name, name)) {
			RWLIST_REMOVE_CURRENT(entry);
			/* Destroy the handler */
			free(handler);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&handlers);

	if (!handler) {
		bbs_warning("Failed to unregister handler '%s': not found\n", name);
	}

	return handler ? 0 : -1;
}

int __bbs_register_menu_handler(const char *name, int (*execute)(struct bbs_node *node, char *args), int needargs, void *mod)
{
	struct menu_handler *handler;
	int length, res = -1;

	RWLIST_WRLOCK(&handlers);
	handler = find_handler(name);
	if (handler) {
		bbs_warning("Handler '%s' is already registered\n", name);
		goto cleanup;
	}
	/* It doesn't already exist, we're good. */
	length = sizeof(*handler) + strlen(name) + 1;
	handler = calloc(1, length);
	if (!handler) {
		goto cleanup;
	}
	strcpy(handler->name, name); /* Safe */
	handler->execute = execute;
	handler->needargs = needargs;
	handler->module = mod;
	res = 0;
	RWLIST_INSERT_TAIL(&handlers, handler, entry);
	bbs_verb(4, "Registered handler '%s'\n", handler->name);

cleanup:
	RWLIST_UNLOCK(&handlers);
	return res;
}

int bbs_list_menu_handlers(int fd)
{
	int c = 0;
	struct menu_handler *handler;

	RWLIST_RDLOCK(&handlers);
	RWLIST_TRAVERSE(&handlers, handler, entry) {
		/* Handlers can't be unregistered by modules without a WRLOCK being obtained.
		 * Since we're holding a RDLOCK, it's safe to go ahead and print the module name. */
		bbs_dprintf(fd, "%3d => %-15s (%s)\n", ++c, handler->name, bbs_module_name(handler->module));
	}
	RWLIST_UNLOCK(&handlers);
	bbs_dprintf(fd, "%d menu handler%s registered\n", c, ESS(c));
	return 0;
}

int menu_handler_exists(const char *name, int *needargs)
{
	struct menu_handler *handler;

	if (!strcmp(name, "menu")) {
		/* This is a special case, because it's hardcoded into menu.c, not an actual handler. */
		if (needargs) {
			*needargs = 1;
		}
		return 1;
	}

	RWLIST_RDLOCK(&handlers);
	handler = find_handler(name);
	if (handler && needargs) {
		*needargs = handler->needargs;
	}
	RWLIST_UNLOCK(&handlers);
	return handler ? 1 : 0;
}

int menu_handler_exec(struct bbs_node *node, const char *name, char *args)
{
	int res;
	char subargs[384]; /* XXX This is arbitrary */
	struct menu_handler *handler;

	RWLIST_RDLOCK(&handlers);
	handler = find_handler(name);

	if (!handler) {
		RWLIST_UNLOCK(&handlers);
		bbs_warning("No menu handler found for: '%s'\n", name);
		return 0; /* Don't disconnect the node */
	}

	if (handler->needargs && strlen_zero(args)) {
		RWLIST_UNLOCK(&handlers);
		bbs_warning("Menu handler '%s' requires arguments\n", name);
		return 0; /* Don't disconnect the node */
	}

	/* Ref module before unlocking. The module unload function is what unregisters the handler, but module.c will decline to unload it due to positive use count. */
	bbs_module_ref(handler->module);
	RWLIST_UNLOCK(&handlers);
	if (args) {
		bbs_substitute_vars(node, args, subargs, sizeof(subargs));
	}
	bbs_debug(5, "Executing menu handler %s (%s)\n", name, args ? subargs : ""); /* Yes, this looks backwards but this is right. If no args, pass NULL */
	res = handler->execute(node, args ? subargs : NULL); /* Yes, this looks backwards but this is right. If no args, pass NULL */
	bbs_debug(5, "Menu handler %s returned %d\n", name, res);
	bbs_module_unref(handler->module);
	return res;
}
