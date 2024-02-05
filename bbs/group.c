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
 * \brief BBS user groups
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/config.h"
#include "include/linkedlists.h"
#include "include/stringlist.h"
#include "include/cli.h"
#include "include/group.h"
#include "include/reload.h"

/* Currently, groups must be defined statically in groups.conf.
 * If this becomes a hindrance, this could be dynamized. */

struct bbs_group {
	const char *name;
	struct stringlist users;
	RWLIST_ENTRY(bbs_group) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(groups, bbs_group);

static void group_free(struct bbs_group *group)
{
	stringlist_empty_destroy(&group->users);
	free(group);
}

static int cli_groups(struct bbs_cli_args *a)
{
	struct bbs_group *g;

	RWLIST_RDLOCK(&groups);
	RWLIST_TRAVERSE(&groups, g, entry) {
		bbs_dprintf(a->fdout, "%s\n", g->name);
	}
	RWLIST_UNLOCK(&groups);
	return 0;
}

/*! \brief Must be called locked */
static struct bbs_group *find_group(const char *name)
{
	struct bbs_group *g;

	RWLIST_TRAVERSE(&groups, g, entry) {
		if (!strcmp(g->name, name)) {
			return g;
		}
	}
	return NULL;
}

int bbs_group_contains_user(const char *group, const char *user)
{
	struct bbs_group *g;
	int contains;

	RWLIST_RDLOCK(&groups);
	g = find_group(group);
	if (!g) {
		RWLIST_UNLOCK(&groups);
		return 0;
	}
	contains = stringlist_case_contains(&g->users, user);
	RWLIST_UNLOCK(&groups);
	return contains;
}

static int cli_group(struct bbs_cli_args *a)
{
	const char *s;
	struct bbs_group *g;
	struct stringitem *i = NULL;

	RWLIST_RDLOCK(&groups);
	g = find_group(a->argv[1]);
	if (!g) {
		RWLIST_UNLOCK(&groups);
		bbs_dprintf(a->fdout, "Group '%s' does not exist\n", a->argv[1]);
		return -1;
	}
	while ((s = stringlist_next(&g->users, &i))) {
		bbs_dprintf(a->fdout, "%s\n", s);
	}
	RWLIST_UNLOCK(&groups);
	return 0;
}

static int load_groups(void)
{
	struct bbs_group *g;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("groups.conf", 1);

	if (!cfg) {
		return 0; /* No custom groups defined */
	}

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Reserved */
		}
		g = calloc(1, sizeof(*g) + strlen(bbs_config_section_name(section)) + 1);
		if (ALLOC_FAILURE(g)) {
			continue;
		}
		strcpy(g->data, bbs_config_section_name(section)); /* Safe */
		g->name = g->data;
		stringlist_init(&g->users);
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval);

			/* Alternately, we could resolve usernames to user IDs, but we'd have to do that after startup has finished,
			 * since we need the auth module to map all the usernames to IDs.
			 * This will take up slightly more storage but is probably more convenient for listing groups as well. */
			stringlist_push(&g->users, key);
		}
		RWLIST_INSERT_TAIL(&groups, g, entry);
	}
	bbs_config_free(cfg); /* No longer needed */
	return 0;
}

/*! \todo Should use a generic system-wide reload mechanism */
static int reload_groups(int fd)
{
	RWLIST_WRLOCK(&groups);
	RWLIST_REMOVE_ALL(&groups, entry, group_free);
	load_groups();
	RWLIST_UNLOCK(&groups);
	bbs_dprintf(fd, "Reloaded groups\n");
	return 0;
}

static struct bbs_cli_entry cli_commands_groups[] = {
	BBS_CLI_COMMAND(cli_groups, "groups", 1, "List user groups", NULL),
	BBS_CLI_COMMAND(cli_group, "group", 2, "List members of a user group", "group <name>"),
};

/*! \todo Currently groups cannot be reloaded, but it might make sense here (and in several other places) to allow this, using some builtin functionality */
static int load_config(void)
{
	RWLIST_WRLOCK(&groups);
	load_groups();
	RWLIST_UNLOCK(&groups);
	return 0;
}

int bbs_groups_cleanup(void)
{
	RWLIST_REMOVE_ALL(&groups, entry, group_free);
	bbs_cli_unregister_multiple(cli_commands_groups);
	return 0;
}

int bbs_groups_init(void)
{
	load_config();
	bbs_register_reload_handler("groups", "Reload BBS user groups", reload_groups);
	bbs_cli_register_multiple(cli_commands_groups);
	return 0;
}
