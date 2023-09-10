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
 * \brief Sysop CLI commands
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/string.h"
#include "include/cli.h"

struct cli_cmd {
	struct bbs_cli_entry *e;
	void *mod;
	size_t cmdlen;
	RWLIST_ENTRY(cli_cmd) entry;
};

static RWLIST_HEAD_STATIC(cmds, cli_cmd);

/*!
 * \brief Find a CLI command
 * \param s The string, which must begin with the command name (e.g. may contain just the command name or a full command, with arguments)
 * \note Must be called locked
 * \return CLI command if match found, NULL if no match found
 */
static struct cli_cmd *find_cli_cmd(const char *s)
{
	struct cli_cmd *c;

	RWLIST_TRAVERSE(&cmds, c, entry) {
		if (!strncasecmp(s, c->e->command, c->cmdlen)) {
			const char *next = c->e->command + c->cmdlen;
			const char *next2 = s + c->cmdlen;
			if ((*next == '\0' || *next == ' ') && (*next2 == '\0' || *next2 == ' ')) { /* It must be a full word match */
				return c;
			}
		}
	}

	return NULL;
}

static int __cli_register_locked(struct bbs_cli_entry *e, struct bbs_module *mod)
{
	struct cli_cmd *c;

	c = find_cli_cmd(e->command);
	if (c) {
		bbs_warning("CLI command '%s' is already registered as '%s'\n", e->command, c->e->command);
		return -1;
	}

	c = calloc(1, sizeof(*c));
	if (ALLOC_FAILURE(c)) {
		return -1;
	}

	c->e = e;
	c->mod = mod;
	c->cmdlen = strlen(c->e->command);
	RWLIST_INSERT_SORTALPHA(&cmds, c, entry, e->command);
	return 0;
}

int __bbs_cli_register(struct bbs_cli_entry *e, struct bbs_module *mod)
{
	int res;

	RWLIST_WRLOCK(&cmds);
	res = __cli_register_locked(e, mod);
	RWLIST_UNLOCK(&cmds);

	return res;
}

int __bbs_cli_register_multiple(struct bbs_cli_entry *e, size_t len, struct bbs_module *mod)
{
	size_t i;
	int res = 0;

	RWLIST_WRLOCK(&cmds);
	for (i = 0; i < len; i++) {
		res |= __cli_register_locked(e + i, mod);
	}
	RWLIST_UNLOCK(&cmds);

	return res;
}

static int cli_unregister_locked(struct bbs_cli_entry *e)
{
	struct cli_cmd *c;

	RWLIST_TRAVERSE_SAFE_BEGIN(&cmds, c, entry) {
		if (c->e == e) {
			/* Module should be prevented from unloading commands that are in use. */
			RWLIST_REMOVE_CURRENT(entry);
			free(c);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;

	if (!c) {
		bbs_warning("CLI command '%s' not registered?\n", e->command);
		return -1;
	}

	return 0;
}

int bbs_cli_unregister(struct bbs_cli_entry *e)
{
	int res;

	RWLIST_WRLOCK(&cmds);
	res = cli_unregister_locked(e);
	RWLIST_UNLOCK(&cmds);

	return res;
}

int __bbs_cli_unregister_multiple(struct bbs_cli_entry *e, size_t len)
{
	size_t i;
	int res = 0;

	RWLIST_WRLOCK(&cmds);
	for (i = 0; i < len; i++) {
		res |= cli_unregister_locked(e + i);
	}
	RWLIST_UNLOCK(&cmds);

	return res;
}

int bbs_cli_unregister_remaining(void)
{
	struct cli_cmd *c;
	int removed = 0;
	bbs_assert(bbs_is_shutting_down());
	RWLIST_WRLOCK(&cmds);
	while ((c = RWLIST_REMOVE_HEAD(&cmds, entry))) {
		if (c->mod) {
			bbs_error("Command %s still registered at shutdown\n", c->e->command);
		}
		free(c);
		removed++;
	}
	RWLIST_UNLOCK(&cmds);
	bbs_debug(1, "%d remaining CLI command%s unregistered\n", removed, ESS(removed));
	return 0;
}

#define MAX_CLI_ARGUMENTS 32

int bbs_cli_exec(int fdin, int fdout, const char *s)
{
	struct cli_cmd *c;
	char cmddup[1024];
	const char *argv[MAX_CLI_ARGUMENTS + 1]; /* Leave remove for NULL sentinel */
	char *next, *dup;
	int res, argc = 0;

	if (strlen_zero(s)) {
		errno = EINVAL;
		return -1;
	}

	/* Before we split it up, find the command to use */
	RWLIST_RDLOCK(&cmds); /* Make sure the command isn't removed before we increase its refcount (which will then ensure it isn't removed) */
	c = find_cli_cmd(s);
	if (!c) {
		RWLIST_UNLOCK(&cmds);
		bbs_debug(1, "No matching CLI command for '%s'\n", s); /* Not a warning, user could fat finger a typo */
		errno = ENOENT;
		return -1;
	}

	if (c->mod) { /* If it's not part of the core, bump the ref count */
		bbs_module_ref(c->mod);
	}
	RWLIST_UNLOCK(&cmds);

	safe_strncpy(cmddup, s, sizeof(cmddup));
	dup = cmddup;
	while ((next = strsep(&dup, " "))) {
		if (strlen_zero(next)) {
			continue;
		}
		argv[argc++] = next;
		if (argc == MAX_CLI_ARGUMENTS) {
			break;
		}
	}

	argv[argc] = NULL; /* This value should never be read by CLI commands, but in convention with argv, NULL terminate anyways */

	if (argc < c->e->minargc) {
		bbs_dprintf(fdout, "Not enough arguments. Usage: %s\n", S_OR(c->e->usage, c->e->command));
		res = -1;
	} else {
		struct bbs_cli_args a;
		a.fdin = fdin;
		a.fdout = fdout;
		a.argc = argc;
		a.argv = argv;
		a.command = s;
		res = c->e->handler(&a);
		if (res) {
			bbs_debug(2, "Command '%s' returned %d\n", s, res);
		}
	}
	if (c->mod) {
		bbs_module_unref(c->mod);
	}
	return res;
}

static int cli_help(struct bbs_cli_args *a)
{
	struct cli_cmd *c;

	RWLIST_RDLOCK(&cmds);
	RWLIST_TRAVERSE(&cmds, c, entry) {
		/* Since commands begin with a '/', prefix that */
		bbs_dprintf(a->fdout, "/%-35s - %s\n", S_OR(c->e->usage, c->e->command), c->e->description);
	}
	RWLIST_UNLOCK(&cmds);

	return 0;
}

static struct bbs_cli_entry cli_commands_core[] = {
	BBS_CLI_COMMAND(cli_help, "help", 1, "List available commands", NULL),
};

int bbs_cli_load(void)
{
	return bbs_cli_register_multiple(cli_commands_core);
}
