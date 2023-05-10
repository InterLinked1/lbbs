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
 * \brief BBS menus
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h> /* use isalnum */
#include <math.h> /* use ceil */

#include "include/menu.h"
#include "include/config.h"
#include "include/linkedlists.h"
#include "include/node.h"
#include "include/user.h"
#include "include/term.h"
#include "include/handler.h"
#include "include/variables.h"
#include "include/utils.h"
#include "include/startup.h"

static int case_sensitive = 0;

struct bbs_menu_item {
	char opt;
	char *action;
	char *name;
	unsigned int minpriv;
	/* Next entry */
	RWLIST_ENTRY(bbs_menu_item) entry;
};

RWLIST_HEAD(bbs_menuitems, bbs_menu_item);

struct bbs_menu {
	char *name;				/*!< Name of menu section e.g. [menu] */
	char *title;			/*!< Menu title */
	char *subtitle;			/*!< Menu subtitle */
	char *display;			/*!< Menu display, if manual rather than automatic */
	/* List of menu items */
	struct bbs_menuitems menuitems;
	/* Next entry */
	RWLIST_ENTRY(bbs_menu) entry;
};

static RWLIST_HEAD_STATIC(menus, bbs_menu);

static void menuitem_free(struct bbs_menu_item *menuitem)
{
	free_if(menuitem->name);
	free_if(menuitem->action);
	free(menuitem);
}

static void menu_free(struct bbs_menu *menu)
{
	bbs_debug(5, "Destroying menu %s\n", menu->name);
	RWLIST_REMOVE_ALL(&menu->menuitems, entry, menuitem_free);
	free_if(menu->title);
	free_if(menu->subtitle);
	free_if(menu->display);
	free(menu->name);
	free(menu);
}

void bbs_free_menus(void)
{
	RWLIST_REMOVE_ALL(&menus, entry, menu_free);
}

static int menu_item_link(struct bbs_menu *menu, struct bbs_menu_item *menuitem)
{
	int exists = 0;
	struct bbs_menu_item *i;

	RWLIST_TRAVERSE(&menu->menuitems, i, entry) {
		/* If !case_sensitive, then these will both be uppercase */
		if (i->opt == menuitem->opt) {
			exists = 1;
			break;
		}
	}
	if (exists) {
		bbs_warning("Duplicate menu item for option '%c', not adding\n", menuitem->opt);
		menuitem_free(menuitem); /* Destroy the menu item before returning */
		return -1;
	}

	RWLIST_INSERT_TAIL(&menu->menuitems, menuitem, entry);
	return 0;
}

static int menu_link(struct bbs_menu *menu)
{
	int exists = 0;
	struct bbs_menu *m;

	RWLIST_TRAVERSE(&menus, m, entry) {
		if (!strcmp(menu->name, m->name)) {
			exists = 1;
			break;
		}
	}
	if (exists) {
		bbs_warning("Duplicate menu with name '%s', not adding\n", menu->name);
		menu_free(menu); /* Destroy the menu before returning */
		return -1;
	}

	RWLIST_INSERT_TAIL(&menus, menu, entry);
	return 0;
}

static struct bbs_menu_item *find_menuitem(struct bbs_menu *menu, char opt)
{
	struct bbs_menu_item *menuitem;

	RWLIST_TRAVERSE(&menu->menuitems, menuitem, entry) {
		if (menuitem->opt == opt) {
			break;
		}
	}
	return menuitem;
}

/*! \brief Must be called with menus list lock held */
static struct bbs_menu *find_menu(const char *menuname)
{
	struct bbs_menu *menu;

	RWLIST_TRAVERSE(&menus, menu, entry) {
		if (!strcasecmp(menu->name, menuname)) {
			break;
		}
	}
	return menu;
}

int bbs_dump_menu(int fd, const char *menuname)
{
	int c = 0;
	struct bbs_menu *menu;
	struct bbs_menu_item *menuitem;

	RWLIST_RDLOCK(&menus);
	menu = find_menu(menuname);
	if (!menu) {
		RWLIST_UNLOCK(&menus);
		bbs_warning("No such menu: %s\n", menuname);
		return -1;
	}

	bbs_dprintf(fd, "=== %s ===\n", menu->name);
	bbs_dprintf(fd, "Title: %s\n", S_IF(menu->title));
	bbs_dprintf(fd, "Subtitle: %s\n", S_IF(menu->subtitle));
	bbs_dprintf(fd, "Dynamically Generated: %s\n", BBS_YN(menu->display == NULL));
	bbs_dprintf(fd, "\n");

	RWLIST_TRAVERSE(&menu->menuitems, menuitem, entry) {
		c++;
		bbs_dprintf(fd, "  %c =>\n", menuitem->opt);
		bbs_dprintf(fd, "    Action:    %s\n", menuitem->action);
		bbs_dprintf(fd, "    Name:      %s\n", menuitem->name);
		/* There's so many random modifiers, only print ones that apply to any given menu item */
		if (menuitem->minpriv) {
			bbs_dprintf(fd, "    Min Priv:  %d\n", menuitem->minpriv);
		}
	}

	bbs_dprintf(fd, "Menu contains %d item%s\n", c, ESS(c));

	RWLIST_UNLOCK(&menus);
	return 0;
}

int bbs_dump_menus(int fd)
{
	int c = 0;
	struct bbs_menu *menu;

	bbs_dprintf(fd, "%4s    %-15s %4s %-7s %s\n", "#", "Name", "Opts", "Dynamic", "Title");

	RWLIST_RDLOCK(&menus);
	RWLIST_TRAVERSE(&menus, menu, entry) {
		struct bbs_menu_item *mi;
		int numopts = RWLIST_SIZE(&menu->menuitems, mi, entry);
		bbs_dprintf(fd, "%4d => %-15s %4d %-7s %s\n", ++c, menu->name, numopts, BBS_YN(menu->display == NULL), S_IF(menu->title));
	}
	RWLIST_UNLOCK(&menus);
	bbs_dprintf(fd, "%d total menu%s\n", c, ESS(c));
	bbs_dprintf(fd, "Options Case Sensitive: %s\n", BBS_YN(case_sensitive));
	return 0;
}

#define MENUITEM_NOT_APPLICABLE(node, menuitem) (node && node->user && node->user->priv < (int) menuitem->minpriv)

#define DEBUG_MENU_DRAW

static unsigned int print_header(struct bbs_node *node, const char *s, const char *color, char *buf, size_t len)
{
	unsigned int plen;
	unsigned int rows_used = 1;
	/* Manually substitute any variables, since we don't substitute until the menu handler is called */
	bbs_substitute_vars(node, s, buf, len);
	bbs_node_writef(node, "%s%s\n", color, buf);
	/* Check for exceeding dimensions */
	plen = (unsigned int) bbs_printable_strlen(buf);
	bbs_debug(6, "plen: %u, cols: %u\n", plen, node->cols);
	if (!NODE_IS_TDD(node) && node->cols && plen > node->cols) {
		unsigned int real_rows = plen + (node->cols - 1) / node->cols; /* avoid ceil() */
		bbs_warning("Menu title length (%d) exceeds node %d's terminal width (%dx%d), actually occupies %d rows\n", plen, node->id, node->cols, node->rows, real_rows);
		rows_used += (real_rows - 1); /* Add additional rows it actually took up */
	}
	return rows_used;
}

static int print_menu_title(struct bbs_node *node, struct bbs_menu *menu)
{
	char sub_name[256];
	print_header(node, menu->title, COLOR(COLOR_PRIMARY), sub_name, sizeof(sub_name));
	return 0;
}

/*! \brief Build and display menu to a node */
/*! \note Must be called with RDLOCK on menu list */
static int display_menu(struct bbs_node *node, struct bbs_menu *menu, char *restrict buf, size_t len)
{
	int numopts;
	int i = 0;
	char sub_name[64];
	char sub_full[96];
	int longest = 0;
	unsigned int rows_used = 0;
	unsigned int numcols = 1;
	unsigned int outcol = 1;
	struct bbs_menu_item *menuitem;

	NEG_RETURN(bbs_node_clear_screen(node)); /* Clear screen for each menu. */

	numopts = RWLIST_SIZE(&menu->menuitems, menuitem, entry);
	bbs_debug(2, "Menu has %d total option%s\n", numopts, ESS(numopts));

	if (!strlen_zero(menu->title)) { /* Menu has a title, print it */
		rows_used += print_header(node, menu->title, COLOR(COLOR_PRIMARY), sub_name, sizeof(sub_name));
	}
	if (!NODE_IS_TDD(node) && !strlen_zero(menu->subtitle)) { /* Menu has a subtitle, print it, unless it's a TDD, in which case skip it */
		rows_used += print_header(node, menu->subtitle, COLOR(COLOR_SECONDARY), sub_name, sizeof(sub_name));
	}
	if (!strlen_zero(menu->title) || !strlen_zero(menu->subtitle)) {
		/* If either title or subtitle, add additional empty line for visual separation from the options */
		bbs_node_writef(node, "\n");
		rows_used++;
	}

	/* First, find the length of the longest option name. Even for TDDs, we still need the count of options from here. */
	RWLIST_TRAVERSE(&menu->menuitems, menuitem, entry) {
		int slen;
		if (MENUITEM_NOT_APPLICABLE(node, menuitem)) {
			bbs_debug(6, "Skipping item '%c' as not applicable to node %d\n", menuitem->opt, node->id);
			continue;
		}
		/* We have to substitute here, because the length could (probably will) change when we substitute, and we want the real length we'll print */
		/* Manually substitute any variables, since we don't substitute until the menu handler is called */
		bbs_substitute_vars(node, menuitem->name, sub_name, sizeof(sub_name));
		slen = bbs_printable_strlen(sub_name); /* We must use bbs_printable_strlen to get the real # of cols occupied, because this could contain escape sequences (e.g. color formatting) */
		longest = MAX(slen, longest);
		i++; /* Count how many options we're actually going to output */
		/* This bit here is to fill the options buffer, it doesn't have anything to do with drawing the screen */
		*buf++ = menuitem->opt;
		if (--len <= 1) {
			bbs_error("Ran out of room in buffer\n");
			break;
		}
	}
	*buf = '\0'; /* Null terminate options buffer */

	if (!strlen_zero(menu->display)) {
		/* menus.conf tells us what to draw to the screen. */
		char disp[2 * 1920]; /* An 80x24 screen is 1920, so twice that ought to be plenty. Avoid using strlen(menu->display) for gcc -Wstack-protector */
		bbs_substitute_vars(node, menu->display, disp, sizeof(disp));
		bbs_node_writef(node, "%s\n", disp); /* Add LF after last line */
		bbs_node_reset_color(node);
		return 0;
	}

#ifdef DEBUG_MENU_DRAW
	bbs_debug(7, "Longest substituted item available in menu '%s' has length %d\n", menu->name, longest);
#endif

	/* Too wide? */
	longest += 5; /* Add 1 for the option itself and the 2 separating spaces, plus 2 spaces dividing inbetween groups */
	/* Things are definitely going to be too long for a TDD. But TDDs can scroll! Either way, ignore them here. */
	if (!NODE_IS_TDD(node) && node->cols && (unsigned int) longest > node->cols) {
		/* The option name won't even fit on 1 line. There is no way to print it nicely. This is bad. Maybe your names are too long? */
		/* We don't know which option here it was (we could keep track, but eh, why bother?) */
		bbs_warning("Menu '%s' contains option too long to fit on a single line for node %d (%dx%d)\n", menu->name, node->id, node->cols, node->rows);
	}

	/* Some basic heuristics to figure out the best way to draw the screen with all the options
	 * so that they all fit on the screen (if possible) and look nice, based on the node's terminal size.
	 * XXX Expand this to include more things over time, to accomodate more types of menus and terminal sizes, as we test.
	 */

	/* Compute how many column groups of options will fit on the screen, using the length of the longest option as an upperbound */
	if (node->cols) {
		/* # of groups of options in their own columns.
		 * This doesn't mean # columns in terms of dimensions, it's columns of options, not columns of pixels */
		numcols = node->cols / (unsigned int) longest; /* Integer division will naturally floor the result, which is what we want here anyways. Round down. */
		if (!numcols) {
			numcols = 1; /* We already emitted a warning about this scenario about (too long for single line) */
		}
	} /* else default to just a single col, since the terminal size is unknown */

	if (!NODE_IS_TDD(node) && node->rows && i > (int) (numcols * (node->rows - rows_used))) {
		/* There's so many options that they're not all going to fit on the screen */
		bbs_warning("Not all options for menu '%s' (%d total options) will not fit for node %d (%dx%d)\n", menu->name, i, node->id, node->cols, node->rows);
	}

	if (!NODE_IS_TDD(node)) {
		RWLIST_TRAVERSE(&menu->menuitems, menuitem, entry) {
			int real_len;
			int byte_len;
			int chunk_len;
			if (MENUITEM_NOT_APPLICABLE(node, menuitem)) {
				bbs_debug(6, "Skipping item '%c' as not applicable to node %d\n", menuitem->opt, node->id);
				continue;
			}
			/* Manually substitute any variables, since we don't substitute until the menu handler is called */
			bbs_substitute_vars(node, menuitem->name, sub_name, sizeof(sub_name));

			/* Resist the urge to directly snprintf the whole chunk into a buffer and then format that using %.*s.
			 * It won't work because the string includes non-printable characters, and *.*s doesn't care about printable length, it cares about bytes.
			 * For our purposes, the color formatting doesn't count towards the length, so we ignore those.
			 * We'll manually compute the printable length.
			 */
			real_len = (outcol > 1 ? 2 : 0) + 1 + 2 + bbs_printable_strlen(sub_name); /* Use bbs_printable_strlen, since the option name could contain formatting, e.g. escape sequences */
			byte_len = snprintf(sub_full, sizeof(sub_full), "%s%s%c  %s%s", outcol > 1 ? "  " : "", COLOR(COLOR_PRIMARY), menuitem->opt, COLOR(COLOR_SECONDARY), sub_name);
			/* real_len is going to be smaller than byte_len because of the colors not being counted.
			 * In order to format with the desired printable length, we need to add the difference between these to the target.
			 * i.e. desired = longest + (byte_len - real_len) */
			if (real_len > longest) {
				/* Something is wrong with our calculations. This shouldn't happen. The item name is going to get truncated, which is really bad. */
				bbs_error("Needed %d characters to display option '%c', but we only have %d?\n", real_len, menuitem->opt, longest);
			}
			chunk_len = longest + (byte_len - real_len); /* In theory, byte_len - real_len should be constant for ALL menu items */
			bbs_node_writef(node, "%-*s", chunk_len, sub_full);
#ifdef DEBUG_MENU_DRAW
			bbs_debug(7, "Displaying option '%c' in row group %d, col group %d, total size %d bytes (%d cols)\n", menuitem->opt, rows_used, outcol, chunk_len, longest);
#endif
			if (++outcol > numcols) {
				/* End of what we can fit on this line. Move to a new line */
				bbs_node_writef(node, "\n");
				outcol = 1; /* Yes, this is a 1-indexed variable */
				rows_used++;
			}
		}
		if (outcol > 1) {
			/* We're in the middle of the screen. Final newline so the cursor is now at the beginning of a line */
			bbs_node_writef(node, "\n");
			outcol = 1;
			rows_used++;
		}
		bbs_node_reset_color(node); /* We didn't reset the color after each item, for efficiency. Now that we're all done, reset it. */
		bbs_debug(6, "Built full menu with %d option%s in %d row group%s, %d col group%s for %dx%d terminal\n",
			i, ESS(i), rows_used, ESS(rows_used), numcols, ESS(numcols), node->cols, node->rows);
		if (i > numopts) {
			/* It's not necessarily going to be equal, if some options weren't applicable, but it should never be greater than */
			bbs_error("Built full menu with %d option%s, but menu '%s' contains %d?\n", i, ESS(i), menu->name, numopts);
		}
	} else {
		/* TDDs only have one row, and we just want to list the options as concisely as possible, with no formatting.
		 * If we do it the normal way, then there'll be a bunch of additional whitespace from aligning everything in column groups. */
		RWLIST_TRAVERSE(&menu->menuitems, menuitem, entry) {
			if (MENUITEM_NOT_APPLICABLE(node, menuitem)) {
				bbs_debug(6, "Skipping item '%c' as not applicable to node %d\n", menuitem->opt, node->id);
				continue;
			}
			/* Manually substitute any variables, since we don't substitute until the menu handler is called */
			bbs_substitute_vars(node, menuitem->name, sub_name, sizeof(sub_name));
			snprintf(sub_full, sizeof(sub_full), "%s%s%c  %s%s", outcol > 1 ? "  " : "", COLOR(COLOR_PRIMARY), menuitem->opt, COLOR(COLOR_SECONDARY), sub_name);
			bbs_node_writef(node, " %s ", sub_full);
		}
		bbs_debug(6, "Built compact menu with %d option%s for %dx%d terminal\n", i, ESS(i), node->cols, node->rows);
	}

	return 0;
}

static int build_options(struct bbs_node *node, struct bbs_menu *menu, char *restrict buf, size_t len)
{
	struct bbs_menu_item *menuitem;

	RWLIST_TRAVERSE(&menu->menuitems, menuitem, entry) {
		if (MENUITEM_NOT_APPLICABLE(node, menuitem)) {
			continue;
		}
		*buf++ = menuitem->opt;
		if (--len <= 1) {
			bbs_error("Ran out of room in buffer\n");
			break;
		}
	}
	*buf = '\0'; /* Null terminate */
	return 0;
}

static int valid_menusequence(const char *restrict s)
{
	while (*s) {
		if (!isalnum(*s)) {
			bbs_debug(6, "Invalid in menu sequence: %d\n", *s);
			return 0;
		}
		s++;
	}
	return 1;
}

/*!
 * \brief Run the BBS on a node
 * \param node node
 * \param menuname Name of menu to run
 * \param stack Current stack count
 * \param optreq Option request string
 */
static int bbs_menu_run(struct bbs_node *node, const char *menuname, int stack, const char *optreq)
{
	int res;
	char opt = 0;
	struct bbs_menu *menu;
	struct bbs_menu_item *menuitem;
	char options[64]; /* No menu will ever have more than this many options... */
	char menusequence[BBS_MAX_MENUSTACK + 1]; /* No point in reading more options than we can recuse */
	int neederror = 0;
	int forcedrawmenu = 0;

	/* Ensure we're within the stack limit */
	if (++stack > BBS_MAX_MENUSTACK) {
		bbs_error("Node %d has exceeded menu stack size (%d), trying to access '%s'\n", node->id, BBS_MAX_MENUSTACK, menuname);
		return 0; /* Do nothing, "return" immediately to previous (calling) menu */
	}

	/* The reason we store this on the node is the return menu handler needs it,
	 * and that's in a menu handler callback now, not hardcoded into this function.
	 * Aside from this, there is no other reason. */
	node->menustack = stack;

	/* Grab a RDLOCK on the menu list. We might hold this for a while...
	 * it's okay since it's a RDLOCK. The only thing this holds up is
	 * operations that modify the menulist, which is good since we don't
	 * want menus changing from underneath us while we're using them...
	 */
	RWLIST_RDLOCK(&menus);
	/* Find the menu */
	menu = find_menu(menuname);
	if (!menu) {
		RWLIST_UNLOCK(&menus);
		bbs_warning("Menu '%s' (requested by node %d) does not exist!\n", menuname, node->id);
		return 0; /* Do nothing, "return" immediately to previous (calling) menu */
	}

	bbs_assert(!strcasecmp(menuname, menu->name));

	/* Wait for a selection */
	for (;;) {
		node->menu = menu->name; /* As long as we're in the menu, it can't be destroyed and this is safe. */
		node->menuitem = NULL;
		node->inmenu = 1;
		if (strlen_zero(optreq)) {
			bbs_verb(5, "Node %d executing menu(%d) '%s'\n", node->id, stack, node->menu);
			if (!opt) {
				/* Draw the menu */
				if (!NODE_IS_TDD(node) || forcedrawmenu) {
					forcedrawmenu = 0;
					display_menu(node, menu, options, sizeof(options));
					if (neederror) {
						/* We chose an invalid option before the menu was displayed (for skip menu nav) */
						neederror = 0;
						bbs_node_writef(node, "\r%sInvalid option!%s", COLOR(COLOR_RED), COLOR_RESET);
					}
				} else {
					/* For TDDs, don't draw the menu initially,
					 * as it's much faster if the user already knows
					 * the desired option to not have to wait for
					 * a printout of all the options.
					 * Simply inform the user how to get the option list.
					 */
					bbs_node_clear_screen(node); /* Won't have any effect for real TDDs, call this just in case */
					/* Don't draw the whole menu, just print the title initially so we know which menu we're on. */
					print_menu_title(node, menu); /* Make a function call, because we don't want to allocate a buffer on THIS stack. */
					bbs_node_writef(node, "Opt (SPACE for list): \n");
					build_options(node, menu, options, sizeof(options)); /* Since we didn't display the menu, get the option list */
				}
			}
			/* Wait for user to choose an option from the menu */
			bbs_node_unbuffer(node); /* Unbuffer input and disable echo, so we can read a single-char selection */
			opt = bbs_node_tread(node, (int) bbs_idle_ms());
			if (opt <= 0) {
				RWLIST_UNLOCK(&menus);
				return opt;
			} else if (opt == 21) {
				opt = 0;
				continue; /* Redraw the menu */
			}
		} else {
			bbs_debug(5, "Node %d bypassing menu(%d) '%s' with option '%c' (full string: %s)\n", node->id, stack, menuname, *optreq, optreq);
			opt = *optreq;
			build_options(node, menu, options, sizeof(options)); /* Since we didn't display the menu, get the option list */
		}

		if (!case_sensitive) {
			opt = (char) toupper(opt);
		}

		/* We can quickly check if this was a valid selection. If the option chosen isn't valid, try again. */
		if (opt == '/') {
			/* Allow "jumping" through menus all at once. */
			bbs_node_writef(node, COLOR_RESET "/"); /* Since echo was off, print it out manually. */
			bbs_node_buffer(node);
			res = bbs_node_readline(node, SEC_MS(30), menusequence, sizeof(menusequence) - 1);
			if (res <= 0) {
				RWLIST_UNLOCK(&menus);
				return opt;
			}
			menusequence[res] = '\0'; /* Null terminate */
			bbs_node_unbuffer(node);

			/* Everything in the sequence must be alphanumeric: either a letter or number */
			if (!valid_menusequence(menusequence)) {
				bbs_node_writef(node, "%sInvalid skip menu sequence%s\n", COLOR(COLOR_RED), COLOR_RESET);
				continue;
			}

			/* All right, let's roll. */
			optreq = menusequence;
			opt = menusequence[0];
			if (!case_sensitive) {
				opt = (char) toupper(opt);
			}
		} else if (opt == ' ') {
			/* Force redraw the menu (or maybe, for TDDs, draw it for the first time) */
			optreq = NULL;
			opt = 0;
			forcedrawmenu = 1;
			bbs_debug(3, "Requesting force menu draw/redraw\n");
			continue;
		} else if (!strchr(options, opt)) {
			bbs_debug(3, "Node %d chose option '%c', but this is not a valid option for menu '%s'\n", node->id, opt, menuname);
			/* Leave opt != 0 so that we don't display the menu again */
			if (optreq) {
				/* If we were doing skip menu navigation, DO display the menu again since we didn't see it before. */
				opt = 0; /* This will clear the screen, so no point in printing an error message here, really... */
				neederror = 1; /* Display the error message once we redraw the screen */
			} else {
				bbs_node_clear_line(node);
				bbs_node_writef(node, "\r%sInvalid option!%s", COLOR(COLOR_RED), COLOR_RESET);
			}
			optreq = NULL; /* If were doing skip menu navigation, stop now since we hit a dead end. */
			continue; /* We must continue and not proceed. */
		}

		/* Got a valid option. */
		bbs_verb(5, "Node %d selected option '%c' at menu(%d) '%s'\n", node->id, opt, stack, menuname);
		/* Hey, guess what, we're still holding a RDLOCK on the menu. See what this option is for. */
		/* We don't need to call MENUITEM_NOT_APPLICABLE here to check if it applies, it wouldn't be in the options buffer if it wasn't */
		menuitem = find_menuitem(menu, opt);
		bbs_assert_exists(menuitem); /* It was in the menu and the menu hasn't changed, it better exist. */
		if (unlikely(!menuitem)) {
			return -1;
		}
		node->menuitem = menuitem->name;

		opt = 0; /* Got a valid option, display the menu again next round */

		/* Initially, when I started writing this file, all the handlers were just hardcoded into a giant else if !strcmp mess here.
		 * Now we have handler.c to clean this up and allow the handlers to be compartmentalized.
		 * Only the menu handler for "menu" itself remains hardcoded in here, since
		 * we need to be able to recurse efficiently with arguments that other handlers don't (and shouldn't) get. */
		if (STARTS_WITH(menuitem->action, "menu:")) {
			/* Execute another menu, recursively */
			res = bbs_menu_run(node, menuitem->action + 5, stack, optreq ? optreq + 1 : NULL);
		} else {
			char *handler, *args;
			/* At this point in the function, we're done with the options buffer, and if we need it again, we'll fill it again.
			 * So, reuse that buffer since we're in a recursive function, and we really want to avoid stack allocations if possible. */
			safe_strncpy(options, menuitem->action, sizeof(options));
			handler = options;
			args = strchr(handler, ':');
			if (args) {
				*args++ = '\0'; /* We just want the name of the menu handler to use. */
			}
			/* Not that args is char, not const char, so handlers can parse the args in place. That's fine, we don't need the data back. */
			node->inmenu = 0;
			res = menu_handler_exec(node, handler, args);
			node->inmenu = 1;
		}
		/* Intercept -3 and -2 return values from "return" */
		if (res == -3) { /* Quit */
			/* Keep returning -3 until we get to the top-level menu (stack == 1). Only then do we return from the menu system completely and exit normally. */
			if (stack == 1) {
				res = 0;
			}
			break;
		} else if (res == -2) { /* Return */
			res = 0;
			break;
		} else if (res == -1) { /* Immediate abort */
			break;
		}
		optreq = NULL; /* Any argument we had or may have had this round is "used up" now, i.e. don't repeat the option after it returns */
	}

	RWLIST_UNLOCK(&menus);
	node->menustack = stack - 1; /* When we return from the last (top level) menu, we'll set menustack back to 0 */
	if (stack == 1) {
		node->inmenu = 0; /* If stack > 1, we're going to return to a previous menu. If this is the last one, actually set to 0. */
	}
	return res;
}

int bbs_node_menuexec(struct bbs_node *node)
{
	return bbs_menu_run(node, DEFAULT_MENU, 0, NULL);
}

static int load_config(int reload)
{
	struct bbs_menu *menu;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("menus.conf", 1);

	if (!cfg) {
		bbs_warning("File 'menus.conf' is missing: BBS has no execution plan\n");
		return 0; /* Really should abort, since a BBS with no menus is kinda useless. But not strictly necessary for many black box tests. */
	}

	bbs_config_val_set_true(cfg, "general", "case", &case_sensitive);

	if (reload) {
		if (RWLIST_TRYWRLOCK(&menus)) {
			bbs_warning("Menus currently in use. Kick all nodes and try again.\n");
			return -1;
		}
		/* Destroy all existing menus */
		RWLIST_REMOVE_ALL(&menus, entry, menu_free);
	} else {
		RWLIST_WRLOCK(&menus);
	}

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Not a menu section, skip */
		}
		menu = calloc(1, sizeof(*menu));
		if (ALLOC_FAILURE(menu)) {
			continue;
		}
		menu->name = strdup(bbs_config_section_name(section));
		if (ALLOC_FAILURE(menu->name)) {
			free(menu);
			continue;
		}
#ifdef DEBUG_MENU_PARSING
		bbs_debug(3, "Parsing menu: %s\n", bbs_config_section_name(section));
#endif
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
#ifdef DEBUG_MENU_PARSING
			bbs_debug(7, "Parsing menu directive %s=%s\n", key, value);
#endif
			if (!strcasecmp(key, "title")) {
				REPLACE(menu->title, value);
			} else if (!strcasecmp(key, "subtitle")) {
				REPLACE(menu->subtitle, value);
			} else if (!strcasecmp(key, "display")) {
				if (menu->display) {
					size_t slen = strlen(menu->display);
					char *s = realloc(menu->display, slen + strlen(value) + 2); /* LF + NUL */
					if (ALLOC_FAILURE(s)) {
						bbs_error("Failed to append menu line '%s' due to realloc error\n", value);
					} else {
						menu->display = s;
						menu->display[slen] = '\n'; /* Next display= line is for the next line */
						strcpy(menu->display + slen + 1, value); /* Safe */
					}
				} else {
					menu->display = strdup(value);
				}
			} else {
#define menuopt_allowed(c) (isalnum(c) || c == '?')
				/* Add menu item */
				char *tmporig, *tmp, *s;
				struct bbs_menu_item *menuitem;
				if (strlen(key) != 1) {
					bbs_warning("'%s' cannot be used as a menu option (too long)\n", key);
					continue;
				} else if (!menuopt_allowed(*key)) {
					bbs_warning("'%s' cannot be used as a menu option (non-alphanumeric, and not ?)\n", key);
					continue;
				}
				menuitem = calloc(1, sizeof(*menuitem));
				if (ALLOC_FAILURE(menuitem)) {
					continue;
				}
				tmporig = tmp = strdup(value); /* Avoid strdupa, we're in a loop */
				if (ALLOC_FAILURE(tmp)) {
					free(menuitem);
					continue;
				}
				menuitem->opt = *key; /* It's only a single letter */
				if (!case_sensitive) {
					menuitem->opt = (char) toupper(menuitem->opt); /* If not case sensitive, store internally as uppercase */
				}
				/* First one is always the menu item action. */
				s = strsep(&tmp, "|");
				if (strlen_zero(s)) {
					menuitem_free(menuitem);
					free(tmporig);
					continue;
				}

				menuitem->action = strdup(s);
				/* Second one is always the friendly name. */
				s = strsep(&tmp, "|");
				if (strlen_zero(s)) {
					bbs_warning("Missing | (menu item '%s' has no name, ignoring)\n", menuitem->action);
					menuitem_free(menuitem);
					free(tmporig);
					continue;
				}
				menuitem->name = strdup(s);
				/* These are mandatory */
				if (!menuitem->opt || !menuitem->action || ALLOC_FAILURE(menuitem->name)) {
					menuitem_free(menuitem);
					free(tmporig);
					continue;
				}
				/* Now, process any optional modifiers */
				while ((s = strsep(&tmp, "|"))) {
					char *k = strsep(&s, "=");
					/* Process a bunch of key=value pairs. k is now the key, s is now the value */
					if (strlen_zero(k) || strlen_zero(s)) {
						bbs_warning("Invalid menu item modifier: %s=%s\n", S_IF(k), S_IF(s));
						continue;
					}
					if (!strcasecmp(k, "minpriv")) {
						menuitem->minpriv = (unsigned int) atoi(s);
					} else {
						bbs_warning("Unrecognized menu item modifier '%s'\n", k);
					}
				}
				free(tmporig);
				menu_item_link(menu, menuitem);
			}
		}
		menu_link(menu);
	}

	/* Some sanity checks are in menu_sanity_check,
	 * but there are also some things we're able to check now.
	 * Some other things could also be checked here, but if they require a full traversal,
	 * wait until menu_sanity_check to do them.
	 */

	/* Ensure that a 'main' menu exists, the entry point to the BBS */
	if (!find_menu(DEFAULT_MENU)) {
		RWLIST_UNLOCK(&menus);
		bbs_error("No 'main' menu exists\n");
		return -1;
	}

	RWLIST_UNLOCK(&menus);
	return 0;
}

/*! \brief Do some sanity checks on what we registered from menus.conf */
static int check_menus(void)
{
	struct bbs_menu *menu;
	struct bbs_menu_item *menuitem;
	int exists, needargs;
	char handler_name[32];
	char *args;

	RWLIST_RDLOCK(&menus);
	RWLIST_TRAVERSE(&menus, menu, entry) {
		int egress_possible = 0;
		RWLIST_RDLOCK(&menu->menuitems);
		RWLIST_TRAVERSE(&menu->menuitems, menuitem, entry) {
			if (!menuitem->action) {
				bbs_warning("No action defined for menu item %s => %c\n", menu->name, menuitem->opt);
				continue;
			}
			/* Check if it's a valid menu action (at least a validly formatted one) */
			safe_strncpy(handler_name, menuitem->action, sizeof(handler_name)); /* Truncation is okay, we just need up to the first : */
			args = strchr(handler_name, ':');
			if (args) {
				*args++ = '\0';
			}
			/* Verify menu handlers exist for anything specified, and if they need arguments, they exist
			 * Warnings will also be thrown at runtime, but this functions as more of a "load time" / "compile time" check,
			 * so we can notify about issues with menu items in advance of them being used.
			 */
			exists = menu_handler_exists(handler_name, &needargs);
			/* There is no need to substitute variables here. */
			if (!exists) {
				bbs_warning("No menu handler exists for '%s' (%s => %c: %s)\n", handler_name, menu->name, menuitem->opt, menuitem->action);
			} else if (needargs && strlen_zero(args)) {
				bbs_warning("Menu handler '%s' requires arguments, missing for %s => %c: %s\n", handler_name, menu->name, menuitem->opt, menuitem->action);
			} else {
				/* XXX I don't fully like that these handlers are hardcoded here like this, but this is fine for now */
				if (!egress_possible && (!strcmp(menuitem->action, "quit") || !strcmp(menuitem->action, "forcequit") || !strcmp(menuitem->action, "return"))) {
					egress_possible = 1;
				} else if (!strcmp(handler_name, "menu")) {
					/* If it's a menu, make the menu it references actually exists. */
					if (!find_menu(args)) {
						bbs_warning("Menu '%s' referenced by %s => %c does not exist\n", args, menu->name, menuitem->opt);
					}
				}
			}
		}
		RWLIST_UNLOCK(&menu->menuitems);
		if (!egress_possible) {
			/* This will strand any users that access this menu */
			bbs_warning("Menu %s contains no way to exit or return from it\n", menu->name);
		}
	}
	RWLIST_UNLOCK(&menus);
	return 0;
}

int bbs_load_menus(int reload)
{
	int res;
	res = load_config(reload);
	if (reload) {
		check_menus(); /* Reload, so we can just directly execute the sanity checks now */
	} else {
		/* We're just starting the BBS now.
		 * We can't check the sanity of menus.conf until all modules have registered,
		 * since menu handlers aren't yet registered right now, so we have to wait to verify them.
		 * Register a callback. */
		bbs_register_startup_callback(check_menus);
	}
	return res;
}
