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
 * \brief Core menu handlers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h> /* use tolower */

#include "include/module.h"
#include "include/node.h"
#include "include/term.h"
#include "include/handler.h"
#include "include/door.h"
#include "include/system.h"
#include "include/editor.h"

static int fastquit_handler(struct bbs_node *node, char *args)
{
	UNUSED(node);
	UNUSED(args);
	return -3; /* Use -3 to differentiate from -1 for fatal I/O */
}

static int quit_handler(struct bbs_node *node, char *args)
{
	char opt;

	UNUSED(node);
	UNUSED(args);

	bbs_node_writef(node, "%s\rAre you sure you want to quit? [YN]%s", COLOR(COLOR_RED), COLOR_RESET);
	opt = bbs_node_tread(node, SEC_MS(30));
	if (opt <= 0) {
		return opt;
	} else if (tolower(opt) == 'y') {
		return fastquit_handler(node, args);
	}
	/* else, user changed mind / cancelled */
	bbs_node_clear_line(node);
	return 0;
}

static int return_handler(struct bbs_node *node, char *args)
{
	if (node->menustack == 1) {
		/* This is the top-level menu. Returning will quit, effectively. */
		return quit_handler(node, args); /* If this is the last stack frame, treat "return" same as "quit" */
	}
	return -2; /* Return -2 to exit menu loop but really return 0 */
}

static int door_handler(struct bbs_node *node, char *args)
{
	char *doorargs, *doorname = args;

	bbs_assert_exists(args); /* We registered with needargs, so args should never be NULL */

	doorargs = strchr(doorname, ':');
	if (doorargs) {
		*doorargs++ = '\0';
	}
	/* Execute a door */
	return bbs_door_exec(node, doorname, doorargs);
}

/*! \brief Execute a system command / program */
static int __exec_handler(struct bbs_node *node, char *args, int isolated)
{
	int res;
	char *argv[32]; /* 32 arguments ought to be enough for anybody. */

	bbs_assert_exists(args); /* We registered with needargs, so args should never be NULL */

	/* Parse a string (delimiting on spaces) into arguments for argv */
	res = bbs_argv_from_str(argv, ARRAY_LEN(argv), args);
	if (res < 1 || res >= (int) ARRAY_LEN(argv)) { /* Failure or truncation */
		return 0; /* Don't execute if we failed parsing */
	}

	bbs_node_clear_screen(node);
	bbs_node_buffer(node); /* Assume that exec'd processes will want the terminal to be buffered: in canonical mode with echo on. */
	if (isolated) {
		res = bbs_execvp_isolated(node, argv[0], argv); /* Prog name is simply argv[0]. */
	} else {
		res = bbs_execvp(node, argv[0], argv); /* Prog name is simply argv[0]. */
	}
	if (res < 0) {
		return res;
	}
	/* This "hack" could maybe be in menu.c, but so far I think we only absolutely need it here. */
	if (!node->active) {
		/* Hack because we return 0 from bbs_execvp if the child process was killed.
		 *
		 * Generally speaking, most bbs I/O functions return -1 if we should stop the node,
		 * due to some kind of I/O function (poll, read, write) returning -1.
		 * bbs_execvp is different (it returns the exit code of the child process).
		 * Because we pass I/O control to the child PID (it becomes the session leader and controlling process for the terminal)
		 * we don't really know much about why the child returned.
		 *
		 * In the case of a node shutdown, we haven't yet closed any file descriptors
		 * when we kill the child, so our only indication to bail is that node->active == 0.
		 *
		 * This ensure that just because the program is killed, we don't disconnect the node.
		 * However, returning -1 worked well when the child was killed due to an active node shutdown.
		 * Compromise by detecting that here and changing res to -1.
		 *
		 * If we don't, then bbs_node_wait_key will just trigger an assertion because the slavefd will be -1 already.
		 */
		return -1;
	}
	/* Who knows what this external program did. Prompt the user for confirmation before returning to menu. */
	/* bbs_node_wait_key's unbuffer ill always succeed, regardless of actual current state, because as far as the BBS is concerned, we're buffered */
	return bbs_node_wait_key(node, MIN_MS(2));
}

/*! \brief Execute a system command / program */
static int exec_handler(struct bbs_node *node, char *args)
{
	return __exec_handler(node, args, 0);
}

/*! \brief Execute a system command / program in an isolated environment */
static int iso_exec_handler(struct bbs_node *node, char *args)
{
	return __exec_handler(node, args, 1);
}

static int file_handler(struct bbs_node *node, char *args)
{
	return bbs_node_term_browse(node, args);
}

static struct menu_handlers {
	const char *name;
	int (*handler)(struct bbs_node *node, char *args);
	int needargs;
} handlers[] =
{
	{ "fastquit", fastquit_handler, 0 },
	{ "quit", quit_handler, 0 },
	{ "return", return_handler, 0 },
	{ "door", door_handler, 1 },
	{ "exec", exec_handler, 1 },
	{ "isoexec", iso_exec_handler, 1 },
	{ "file", file_handler, 1 },
};

static int unload_module(void)
{
	int res = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_LEN(handlers); i++) {
		res |= bbs_unregister_menu_handler(handlers[i].name);
	}
	return res;
}

static int load_module(void)
{
	int res = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_LEN(handlers); i++) {
		res |= bbs_register_menu_handler(handlers[i].name, handlers[i].handler, handlers[i].needargs);
	}
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_STANDARD("Builtin Menu Handlers");
