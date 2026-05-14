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
 * \brief Command history
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h> /* use free */
#include <string.h> /* use strcmp */
#include <histedit.h>
#include <readline/history.h>

#include "include/module.h"
#include "include/utils.h"

#include "include/mod_history.h"

#define MAX_HISTORY_ENTRIES 25

/* #define DEBUG_HISTORY */

static int hist_added = 0;

/*
 * This is a loose wrapper around the GNU libreadline history library.
 * Because this library can only be used once per process, this is
 * basically a global history, intended to be used for the sysop console.
 */

int bbs_history_reset(void)
{
	int pos, len = history_length; /* Set to length, rather than index of length - 1, because we'll call bbs_history_older which calls previous_history */
	if (!hist_added) {
		return 0; /* Nothing to reset */
	}
#ifdef DEBUG_HISTORY
	bbs_debug(5, "Setting history index to %d\n", len);
#endif
	pos = history_set_pos(len); /* Return to the very end */
	if (!pos) {
		/* history_set_pos returns 0 on error */
		bbs_error("history_set_pos failed: current length is %d\n", history_length);
	}
	return 0;
}

const char *bbs_history_older(void)
{
	/* We don't use current_history() at all */
	HIST_ENTRY *h = previous_history();
	if (!h) {
#ifdef DEBUG_HISTORY
		bbs_debug(5, "No older history available\n");
#endif
		return NULL;
	}
	/* Where_history is 0-indexed, but history_length is # total, so 0/N... N-1/N... so add +1 so both are 1-indexed. */
#ifdef DEBUG_HISTORY
	bbs_debug(5, "Now at history index %d/%d\n", where_history() + 1, history_length);
#endif
	return (const char*) h->line;
}

const char *bbs_history_newer(void)
{
	HIST_ENTRY *h = next_history();
	if (!h) {
#ifdef DEBUG_HISTORY
		bbs_debug(5, "No newer history available\n");
#endif
		return NULL;
	}
	bbs_debug(5, "Now at history index %d/%d\n", where_history() + 1, history_length);
	return (const char*) h->line;
}

int bbs_history_add(const char *s)
{
	if (!bbs_str_isprint(s)) {
		/* Avoid weird things getting added to history (e.g. things with escape sequences, etc.) */
		bbs_debug(4, "String is not printable, not adding to history\n");
		return -1;
	}
	if (hist_added) {
		/* Don't add this to history if it's the same as the last one, to avoid pointless duplication
		 * This is a better user experience, and uses less memory. */
		HIST_ENTRY *h = history_get(history_length); /* Get most recent entry. 1-indexed. */
		if (!h) {
			bbs_error("No history at index %d?\n", history_length);
		} else if (!strcmp(s, h->line)) {
#ifdef DEBUG_HISTORY
			bbs_debug(5, "Not adding to history, identical to most recent addition\n");
#endif
			return 0;
		}
	}
	hist_added++;
	add_history(s);
	bbs_history_reset(); /* Update current position to the end upon append */
	return 0;
}

static int unload_module(void)
{
	/* Free all the history.
	 * Currently we don't save it to disk. I'm not sure persisting it between sessions would really be that useful. */

	clear_history(); /* Don't forget this or we'll leak memory. This is appropriate because we never added any private data, so this will properly free history entries. */

	/* libreadline is sloppy and never actually frees the history list itself.
	 * Once allocated through add_history, the list sticks around forever.
	 * Manually do so to avoid this memory leak (albeit a constant-size one with respect to history usage). */
	if (hist_added) {
		/* This is only safe to call once, which is why bbs_history_shutdown is called by the core during shutdown, not when mod_sysop unloads. */
		free(history_list()); /* Directly free the list. This is safe only because we called clear_history first so the list contains no allocations. */
	}

	hist_added = 0;
	return 0;
}

static int load_module(void)
{
	using_history(); /* This is safe to call multiple times (i.e. module is reloaded) */
	stifle_history(MAX_HISTORY_ENTRIES); /* Prevent history list from running away to oblivion */
	return 0;
}

BBS_MODULE_INFO_FLAGS("Command History", MODFLAG_GLOBAL_SYMBOLS);
