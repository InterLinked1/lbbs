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

#include "include/menu.h"
#include "include/ansi.h"
#include "include/config.h"
#include "include/linkedlists.h"
#include "include/node.h"
#include "include/user.h"
#include "include/group.h"
#include "include/term.h"
#include "include/handler.h"
#include "include/variables.h"
#include "include/utils.h"
#include "include/startup.h"
#include "include/cli.h"
#include "include/reload.h"

static int case_sensitive = 0;

#define MAX_MENU_NAME_LENGTH 64
#define MAX_MENUITEM_NAME_LENGTH 64

struct bbs_menu_item {
	char opt;
	const char *action;
	const char *name;
	const char *group;
	unsigned int minpriv;
	/* Next entry */
	RWLIST_ENTRY(bbs_menu_item) entry;
	char data[];
};

RWLIST_HEAD(bbs_menuitems, bbs_menu_item);

struct bbs_menu {
	const char *name;			/*!< Name of menu section e.g. [menu] */
	const char *title;			/*!< Menu title */
	const char *subtitle;		/*!< Menu subtitle */
	const char *artfile;		/*!< Menu art file (e.g. ANSI art) */
	const char *display;		/*!< Menu display, if manual rather than automatic */
	/* List of menu items */
	struct bbs_menuitems menuitems;
	/* Next entry */
	RWLIST_ENTRY(bbs_menu) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(menus, bbs_menu);

static void menuitem_free(struct bbs_menu_item *menuitem)
{
	free(menuitem);
}

static void menu_free(struct bbs_menu *menu)
{
	bbs_debug(5, "Destroying menu %s\n", menu->name);
	RWLIST_REMOVE_ALL(&menu->menuitems, entry, menuitem_free);
	RWLIST_HEAD_DESTROY(&menu->menuitems);
	free(menu);
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

	bbs_verb(5, "Added menu item '%c => %s' to menu '%s'\n", menuitem->opt, menuitem->name, menu->name);
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

static int bbs_dump_menu(int fd, const char *menuname)
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
	bbs_dprintf(fd, "Art File: %s\n", S_IF(menu->artfile));
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
		if (menuitem->group) {
			bbs_dprintf(fd, "    Group Required: %s\n", menuitem->group);
		}
	}

	bbs_dprintf(fd, "Menu contains %d item%s\n", c, ESS(c));

	RWLIST_UNLOCK(&menus);
	return 0;
}

/*! \brief Print menu list */
static int bbs_dump_menus(int fd)
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

#define MENUITEM_NOT_APPLICABLE(node, menuitem) (!node || !node->user || (node->user->priv < (int) menuitem->minpriv || (menuitem->group && !bbs_group_contains_user(menuitem->group, bbs_username(node->user)))))

#define DEBUG_MENU_DRAW

static unsigned int print_header(struct bbs_node *node, const char *s, const char *color, char *buf, size_t len)
{
	unsigned int plen;
	unsigned int rows_used = 1;
	/* Manually substitute any variables, since we don't substitute until the menu handler is called */
	bbs_node_substitute_vars(node, s, buf, len);
	bbs_node_writef(node, "%s%s\n", color, buf);
	/* Check for exceeding dimensions */
	plen = (unsigned int) bbs_printable_strlen(buf);
	bbs_debug(6, "plen: %u, cols: %u\n", plen, node->cols);
	if (!NODE_IS_TDD(node) && node->cols && plen > node->cols) {
		unsigned int real_rows = (plen + (node->cols - 1)) / node->cols; /* avoid ceil() */
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
		bbs_node_substitute_vars(node, menuitem->name, sub_name, sizeof(sub_name));
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
		bbs_node_substitute_vars(node, menu->display, disp, sizeof(disp));
		bbs_node_writef(node, "%s\n", disp); /* Add LF after last line */
		bbs_node_reset_color(node);
		return 0;
	}

#ifdef DEBUG_MENU_DRAW
	bbs_debug(8, "Longest substituted item available in menu '%s' has length %d\n", menu->name, longest);
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
			bbs_node_substitute_vars(node, menuitem->name, sub_name, sizeof(sub_name));

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
			if (node->ansi) {
				int jump_len;
				/* Instead of space padding menu items, use ANSI escape sequences to jump where needed.
				 * This makes a big difference on slow connections (e.g. 300, 1200 bps), since otherwise we're sending a byte for every space,
				 * whereas jumping around reduces the size of the menu download.
				 * Normally, bbs_node_ansi_write (called by bbs_node_write as appropriate) will also handle this automatically,
				 * but this is the canonical application for this type of optimization, and we may as well avoid
				 * prematurely adding a lot of spaces and then skipping them right away. In other places, it's not as simple.
				 */
				bbs_node_write(node, sub_full, (size_t) byte_len);
				jump_len = longest - real_len; /* We need to jump forward this many spaces */
				if (jump_len) {
					/* This will be 0 for the longest option.
					 * An escape sequence to move forward 0 characters is obviously useless and unnecessary.
					 * Furthermore, it's also wrong, as 0 will be treated as 1 and thus add an extra column. */
					bbs_node_writef(node, "\e[%dC", jump_len); /* Cursor forward N characters */
				}
			} else {
				/* This is guaranteed to be correct, but results in more bytes being sent on the wire */
				bbs_node_writef(node, "%-*s", chunk_len, sub_full);
			}
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
			bbs_node_substitute_vars(node, menuitem->name, sub_name, sizeof(sub_name));
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

static int menu_set_title(struct bbs_node *node, const char *name)
{
	char sub_name[64];
	char stripped[64];
	int strippedlen;

	/* We could have something like ${TERM_COLOR_RED}Option Name${COLOR_RESET}
	 * We need to substitute variables and then strip any ANSI sequences,
	 * before using that for the terminal title. */
	bbs_node_substitute_vars(node, name, sub_name, sizeof(sub_name));
	bbs_ansi_strip(sub_name, strlen(sub_name), stripped, sizeof(stripped), &strippedlen);
	return bbs_node_set_term_title(node, stripped);
}

/*!
 * \brief Run the BBS on a node
 * \param node node
 * \param menuname Name of menu to run
 * \param menuitemname
 * \param stack Current stack count
 * \param optreq Option request string
 * \param scratchbuf Scratch buffer space, of size SCRATCH_BUF_SIZE
 */
static int bbs_menu_run(struct bbs_node *node, const char *menuname, const char *menuitemname, int stack, const char *optreq, char *restrict scratchbuf)
{
	int res;
	int opt = 0;
	struct bbs_menu *menu;
	struct bbs_menu_item *menuitem;
	char options[64]; /* No menu will ever have more than this many options... */
	char menusequence[BBS_MAX_MENUSTACK + 1]; /* No point in reading more options than we can use */
	char submenuitemname[MAX_MENUITEM_NAME_LENGTH];
	int neederror = 0;
	int forcedrawmenu = 0;
	unsigned int origrows, origcols;

	origrows = node->rows;
	origcols = node->cols;

	/* Ensure we're within the stack limit */
	if (++stack > BBS_MAX_MENUSTACK) {
		bbs_error("Node %d has exceeded menu stack size (%d), trying to access '%s'\n", node->id, BBS_MAX_MENUSTACK, menuname);
		return 0; /* Do nothing, "return" immediately to previous (calling) menu */
	}

	/* The reason we store this on the node is the return menu handler needs it,
	 * and that's in a menu handler callback now, not hardcoded into this function.
	 * Aside from this, there is no other reason. */
	node->menustack = stack;

	/* Grab a RDLOCK on the menu list. However, to allow for menus to be reloaded while nodes,
	 * are active in the menu system, we unlock menus while waiting for or executing a selection. */
	RWLIST_RDLOCK(&menus);
	/* Find the menu */
	menu = find_menu(menuname);
	if (!menu) {
		RWLIST_UNLOCK(&menus);
		bbs_warning("Menu '%s' (requested by node %d) does not exist!\n", menuname, node->id);
		return 0; /* Do nothing, "return" immediately to previous (calling) menu */
	}

	bbs_assert(!strcasecmp(menuname, menu->name));

	if (menu->artfile && node->ansi) {
		bbs_debug(4, "Displaying ANSI art: %s\n", menu->artfile);
		bbs_node_clear_screen(node);
		/* Menu has an ANSI art file, display it, but only the first time we run this menu. */
		if (bbs_send_file(menu->artfile, node->slavefd) <= 0) {
			RWLIST_UNLOCK(&menus);
			return -1;
		}
		/* Pause momentarily, or the user won't really see the ANSI art.
		 * ANSI art can take a long time at slow speeds, so be tolerant of that. */
		if (bbs_node_wait_key(node, MIN_MS(7)) < 0) {
			RWLIST_UNLOCK(&menus);
			return -1;
		}
	}

	/* Wait for a selection */
	/* menus must be RDLOCK'd at the beginning of the loop */
	for (;;) {
		if (!menu) {
			/* During this loop, we unlock menus to minimize the amount of time for which menus is locked.
			 * When we do this, we set menu to NULL, since that pointer is no longer necessarily valid.
			 * Thus, when we loop again (now that menus is locked again),
			 * we may need to find menu again. */
			menu = find_menu(menuname);
			if (!menu) {
				RWLIST_UNLOCK(&menus);
				bbs_warning("Menu '%s' (executed by node %d) no longer exists!\n", menuname, node->id);
				return 0;
			}
		}
		node->menu = menuname;
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
						bbs_node_writef(node, "\r%sInvalid option!%s", COLOR(TERM_COLOR_RED), COLOR_RESET);
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

			/* Don't hold a lock on the menus while we're just waiting for input. */
			menu = NULL; /* menu is no longer valid memory necessarily since menus can change when unlocked. */
			RWLIST_UNLOCK(&menus);

			/* Wait for user to choose an option from the menu */
			bbs_node_unbuffer(node); /* Unbuffer input and disable echo, so we can read a single-char selection */
			opt = bbs_node_tread(node, (int) bbs_idle_ms());
			if (opt <= 0) {
				return opt;
			} else if (opt == 21) {
				opt = 0;
				RWLIST_RDLOCK(&menus);
				continue; /* Redraw the menu */
			}
		} else {
			bbs_debug(5, "Node %d bypassing menu(%d) '%s' with option '%c' (full string: %s)\n", node->id, stack, menuname, *optreq, optreq);
			opt = *optreq;
			build_options(node, menu, options, sizeof(options)); /* Since we didn't display the menu, get the option list */
			menu = NULL;
			RWLIST_UNLOCK(&menus);
		}

		if (!case_sensitive) {
			opt = (char) toupper(opt);
		}

		/* We can quickly check if this was a valid selection. If the option chosen isn't valid, try again. */
		if (opt == '/') {
			/* Allow "jumping" through menus all at once. */
			bbs_node_writef(node, COLOR_RESET "/"); /* Since echo was off, print it out manually. */
			bbs_node_buffer(node);
			res = bbs_node_read_line(node, SEC_MS(30), menusequence, sizeof(menusequence) - 1);
			if (res <= 0) {
				RWLIST_UNLOCK(&menus);
				return opt;
			}
			menusequence[res] = '\0'; /* Null terminate */
			bbs_node_unbuffer(node);

			if (res == 1 && menusequence[0] == 0) {
				/* User pressed / and then pressed ENTER. Logically, this should do nothing. */
				optreq = NULL;
				opt = 0;
				RWLIST_RDLOCK(&menus);
				continue;
			}

			/* Everything in the sequence must be alphanumeric: either a letter or number */
			if (!valid_menusequence(menusequence)) {
				bbs_node_writef(node, "%sInvalid skip menu sequence%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET);
				RWLIST_RDLOCK(&menus);
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
			RWLIST_RDLOCK(&menus);
			continue;
		} else if (!strchr(options, opt)) {
			if (node->cols != origcols || node->rows != origrows) {
				/* Menu needs a redraw, the input we got was spoofed
				 * on the PTY master to make us wake up and redraw it.
				 * Don't emit a warning about invalid selection. */
				origcols = node->cols;
				origrows = node->rows;
				opt = 0;
				forcedrawmenu = 1;
				bbs_debug(3, "Completely redrawing menu due to change in screen size\n");
			} else {
				bbs_debug(3, "Node %d chose option '%c', but this is not a valid option for menu '%s'\n", node->id, opt, menuname);
				/* Leave opt != 0 so that we don't display the menu again */
				if (optreq) {
					/* If we were doing skip menu navigation, DO display the menu again since we didn't see it before. */
					opt = 0; /* This will clear the screen, so no point in printing an error message here, really... */
					neederror = 1; /* Display the error message once we redraw the screen */
				} else {
					bbs_node_clear_line(node);
					bbs_node_writef(node, "\r%sInvalid option!%s", COLOR(TERM_COLOR_RED), COLOR_RESET);
				}
			}
			optreq = NULL; /* If were doing skip menu navigation, stop now since we hit a dead end. */
			RWLIST_RDLOCK(&menus);
			continue; /* We must continue and not proceed. */
		}

		/* Got a valid option. */
		bbs_verb(5, "Node %d selected option '%c' at menu(%d) '%s'\n", node->id, opt, stack, menuname);
		RWLIST_RDLOCK(&menus);
		/* Look for the menu again since menus can change when unlocked;
		 * if reloaded, the old menu is definitely no longer a valid pointer. */
		menu = find_menu(menuname);
		if (!menu) {
			RWLIST_UNLOCK(&menus);
			/* Menu was removed while a node was running it.
			 * This is the price we pay for allowing menus to be reloaded (at least partially) during menu execution. */
			bbs_warning("Menu '%s' (executed by node %d) no longer exists!\n", menuname, node->id);
			return 0; /* Do nothing, "return" immediately to previous (calling) menu */
		}

		/* We don't need to call MENUITEM_NOT_APPLICABLE here to check if it applies, it wouldn't be in the options buffer if it wasn't */
		menuitem = find_menuitem(menu, (char) opt);
		/* It was in the menu and the menu hasn't changed, it better exist. */
		if (!menuitem) {
			bbs_warning("Could not find option '%c' in menu '%s'\n", opt, menu->name);
			optreq = NULL;
			opt = 0;
			continue; /* Display menu again */
		}

		opt = 0; /* Got a valid option, display the menu again next round */

		safe_strncpy(submenuitemname, menuitem->name, sizeof(submenuitemname));
		node->menuitem = submenuitemname;

		/* Set the title to the option name */
		/* XXX Because things like "quit" and "back" are technically options,
		 * the option name (e.g. "Back") will be displayed as the title temporarily.
		 * It will almost immediately return, and then unwind the menu stack as much as is needed,
		 * during which time the title will not be further overwritten.
		 * Eventually, the BBS will exit or a new title will be overwritten,
		 * but users may notice this temporarily, and that's what's going on.
		 * It might be nice to not do this, but that would require breaking menu handler abstraction
		 * and poking into the option to see what it does, which I don't want to do... */
		menu_set_title(node, menuitem->name);

		/* Initially, when I started writing this file, all the handlers were just hardcoded into a giant else if !strcmp mess here.
		 * Now we have handler.c to clean this up and allow the handlers to be compartmentalized.
		 * Only the menu handler for "menu" itself remains hardcoded in here, since
		 * we need to be able to recurse efficiently with arguments that other handlers don't (and shouldn't) get. */
		if (STARTS_WITH(menuitem->action, "menu:")) {
			/* Execute another menu, recursively */

			/* We need to duplicate the new menu name and item name on each stack frame,
			 * since we need to be able to use them even after calling another menu and returning from it.
			 * If it was a common buffer for all stack frames, it could be overwritten by the time we return,
			 * if that menu also recursed to another menu. */
			char submenuname[MAX_MENU_NAME_LENGTH];
			safe_strncpy(submenuname, menuitem->action + 5, sizeof(submenuname));
			menu = NULL; /* Can't dereference after unlocking */
			menuitem = NULL;
			RWLIST_UNLOCK(&menus);

			res = bbs_menu_run(node, submenuname, submenuitemname, stack, optreq ? optreq + 1 : NULL, scratchbuf);
		} else {
#define SCRATCH_BUF_SIZE 256
			char *handler, *args;
			/* We need a buffer that is sufficiently long enough to avoid truncation, so use the scratch buffer. */
			safe_strncpy(scratchbuf, menuitem->action, SCRATCH_BUF_SIZE);
			menu = NULL; /* Can't dereference after unlocking */
			menuitem = NULL;
			RWLIST_UNLOCK(&menus);
			if (strlen(scratchbuf) >= SCRATCH_BUF_SIZE - 1) {
				bbs_warning("Truncation occurred copying menu item arguments into buffer of size %d\n", SCRATCH_BUF_SIZE);
			}
			handler = scratchbuf;
			args = strchr(handler, ':');
			if (args) {
				*args++ = '\0'; /* We just want the name of the menu handler to use. */
			}
			/* Not that args is char, not const char, so handlers can parse the args in place. That's fine, we don't need the data back. */
			node->inmenu = 0;
			res = menu_handler_exec(node, handler, args);
			node->inmenu = 1;
		}

		/* If another thread interrupted the node while it was executing a handler, -1 will get returned (probably by poll(2)).
		 * This is handy, since the -1 return value should cleanly make the handler exit at that point, since it thinks the node is gone.
		 * However, the node didn't really exit, we just wanted to interrupt it to get it out of the handler, so correct the return value now. */
		if (bbs_node_interrupted(node)) {
			bbs_node_interrupt_clear(node);
			/* Drain any input received, in case poll was interrupt and there's data available,
			 * to avoid using user input to interact with the menus. */
			bbs_debug(2, "Flushing interrupted input\n");
			bbs_node_unbuffer(node); /* Unbuffer input, so we can properly flush it */
			bbs_node_flush_input(node);
			bbs_node_buffer(node);
			res = 0; /* Either 0 or -3 could make sense */
		}

		bbs_node_lock(node);
		node->menu = node->menuitem = NULL;
		bbs_node_unlock(node);

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

		if (!NODE_IS_TDD(node)) {
			/* Restore previous terminal title */
			bbs_node_restore_term_title(node); /* Pop the current title */
			if (!strlen_zero(menuitemname)) {
				/* If this is not the top-level menu, then the menu was chosen via an option that had a name for the menu.
				 * Use that name here since that's the most logical name to display. */
				menu_set_title(node, menuitemname);
			} else {
				/* In case popping the title just resets to the very original title (probably the hostname),
				 * explicitly set the BBS name as the title, since that's what's set initially and
				 * displayed the first time a user accesses the root menu (so use that from here on out). */
				bbs_node_set_term_title(node, bbs_name());
			}
		}
		RWLIST_RDLOCK(&menus); /* Lock before going round again */
	}

	node->menustack = stack - 1; /* When we return from the last (top level) menu, we'll set menustack back to 0 */
	if (stack == 1) {
		node->inmenu = 0; /* If stack > 1, we're going to return to a previous menu. If this is the last one, actually set to 0. */
	}
	return res;
}

int bbs_node_menuexec(struct bbs_node *node)
{
	/* Declare just once rather than on each stack frame, since bbs_menu_run recurses a lot.
	 * This allows us to save (BBS_MAX_MENUSTACK - 1) * SCRATCH_BUF_SIZE bytes of stack space. */
	char scratchbuf[SCRATCH_BUF_SIZE];
	return bbs_menu_run(node, DEFAULT_MENU, NULL, 0, NULL, scratchbuf);
}

static int load_config(int reload)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("menus.conf", 1);

	if (!cfg) {
		bbs_warning("File 'menus.conf' is missing: BBS has no execution plan\n");
		return 0; /* Really should abort, since a BBS with no menus is kinda useless. But not strictly necessary for many black box tests. */
	}

	bbs_config_val_set_true(cfg, "general", "case", &case_sensitive);

	if (reload) {
		if (RWLIST_TRYWRLOCK(&menus)) { /* This is a holdover from when we used to hold a read lock while menus were running. Shouldn't happen much anymore. */
			bbs_warning("Menus currently in use. Please try again later.\n");
			bbs_config_unlock(cfg);
			return -1;
		}
		/* Destroy all existing menus */
		RWLIST_REMOVE_ALL(&menus, entry, menu_free);
	} else {
		RWLIST_WRLOCK(&menus);
	}

	while ((section = bbs_config_walk(cfg, section))) {
		const char *menuname = NULL, *title = NULL, *subtitle = NULL, *artfile = NULL;
		char *tmpdisplay = NULL;
		struct bbs_menu *menu = NULL;
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Not a menu section, skip */
		}
		menuname = bbs_config_section_name(section);
#ifdef DEBUG_MENU_PARSING
		bbs_debug(3, "Parsing menu: %s\n", bbs_config_section_name(section));
#endif
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
#ifdef DEBUG_MENU_PARSING
			bbs_debug(7, "Parsing menu directive %s=%s\n", key, value);
#endif
			if (!strcasecmp(key, "title")) {
				title = value;
			} else if (!strcasecmp(key, "subtitle")) {
				subtitle = value;
			} else if (!strcasecmp(key, "artfile")) {
				artfile = value;
				if (!bbs_file_exists(artfile)) {
					/* Continue, because it may exist later, but warn about this
					 * so it can be fixed if needed. */
					bbs_warning("Art file '%s' does not currently exist\n", artfile);
				}
			} else if (!strcasecmp(key, "display")) {
				if (tmpdisplay) {
					size_t slen = strlen(tmpdisplay);
					char *s = realloc(tmpdisplay, slen + strlen(value) + 2); /* LF + NUL */
					if (ALLOC_FAILURE(s)) {
						bbs_error("Failed to append menu line '%s' due to realloc error\n", value);
					} else {
						tmpdisplay = s;
						tmpdisplay[slen] = '\n'; /* Next display= line is for the next line */
						strcpy(tmpdisplay + slen + 1, value); /* Safe */
					}
				} else {
					tmpdisplay = strdup(value);
				}
			} else {
#define menuopt_allowed(c) (isalnum(c) || c == '?')
				/* Add menu item */
				char *tmporig, *tmp, *s;
				struct bbs_menu_item *menuitem;
				size_t actionlen, namelen, grouplen;
				char *data;
				unsigned int minpriv = 0;
				char opt;
				const char *action = NULL, *name = NULL, *group = NULL;

				if (!menu) {
					size_t menunamelen, titlelen, subtitlelen, artfilelen, displaylen;

					menunamelen = STRING_ALLOC_SIZE(menuname);
					titlelen = STRING_ALLOC_SIZE(title);
					subtitlelen = STRING_ALLOC_SIZE(subtitle);
					artfilelen = STRING_ALLOC_SIZE(artfile);
					displaylen = STRING_ALLOC_SIZE(tmpdisplay);

					if (menunamelen >= MAX_MENU_NAME_LENGTH) {
						bbs_error("Menu name '%s' is too long (%lu >= %d)\n", menuname, menunamelen, MAX_MENU_NAME_LENGTH);
						goto nextmenu;
					}

					/* Allocate menu when we reach the first item */
					menu = calloc(1, sizeof(*menu) + menunamelen + titlelen + subtitlelen + artfilelen + displaylen);
					if (ALLOC_FAILURE(menu)) {
						goto nextmenu; /* Can't just break or continue since we're in the inner loop */
					}

					RWLIST_HEAD_INIT(&menu->menuitems);
					data = menu->data;
					SET_FSM_STRING_VAR(menu, data, name, menuname, menunamelen);
					SET_FSM_STRING_VAR(menu, data, title, title, titlelen);
					SET_FSM_STRING_VAR(menu, data, subtitle, subtitle, subtitlelen);
					SET_FSM_STRING_VAR(menu, data, artfile, artfile, artfilelen);
					SET_FSM_STRING_VAR(menu, data, display, tmpdisplay, displaylen);
				}

				if (strlen(key) != 1) {
					bbs_warning("'%s' cannot be used as a menu option (too long)\n", key);
					continue;
				} else if (!menuopt_allowed(*key)) {
					bbs_warning("'%s' cannot be used as a menu option (non-alphanumeric, and not ?)\n", key);
					continue;
				}

				opt = *key; /* It's only a single letter */
				if (!case_sensitive) {
					opt = (char) toupper(opt); /* If not case sensitive, store internally as uppercase */
				}

				tmporig = tmp = strdup(value); /* Avoid strdupa, we're in a loop */
				if (ALLOC_FAILURE(tmp)) {
					continue;
				}

				/* First one is always the menu item action. */
				action = strsep(&tmp, "|");
				if (strlen_zero(action)) { /* Mandatory */
					free(tmporig);
					continue;
				}

				/* Second one is always the friendly name. */
				name = strsep(&tmp, "|");
				if (strlen_zero(name)) { /* Mandatory */
					bbs_warning("Missing | (menu item '%s' has no name, ignoring)\n", action);
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
						minpriv = (unsigned int) atoi(s);
					} else if (!strcasecmp(k, "requiregroup")) {
						group = s;
					} else {
						bbs_warning("Unrecognized menu item modifier '%s'\n", k);
					}
				}

				actionlen = STRING_ALLOC_SIZE(action);
				namelen = STRING_ALLOC_SIZE(name);
				grouplen = STRING_ALLOC_SIZE(group);

				if (namelen >= MAX_MENUITEM_NAME_LENGTH) {
					bbs_error("Menu item name '%s' is too long (%lu >= %d)\n", name, namelen, MAX_MENUITEM_NAME_LENGTH);
					free(tmporig);
					continue;
				}

				/* Allocate menu when we reach the first item */
				menuitem = calloc(1, sizeof(*menuitem) + actionlen + namelen + grouplen);
				if (ALLOC_FAILURE(menuitem)) {
					free(tmporig);
					continue;
				}

				data = menuitem->data;
				SET_FSM_STRING_VAR(menuitem, data, action, action, actionlen);
				SET_FSM_STRING_VAR(menuitem, data, name, name, namelen);
				SET_FSM_STRING_VAR(menuitem, data, group, group, grouplen);
				menuitem->opt = opt; /* It's only a single letter */
				menuitem->minpriv = minpriv;

				menu_item_link(menu, menuitem);
				free(tmporig);
			}
		}
		menu_link(menu);
nextmenu:
		free_if(tmpdisplay);
	}

	bbs_config_unlock(cfg);

	/* Some sanity checks are in menu_sanity_check,
	 * but there are also some things we're able to check now.
	 * Some other things could also be checked here, but if they require a full traversal,
	 * wait until menu_sanity_check to do them. */

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
				if (!egress_possible && (!strcmp(menuitem->action, "quit") || !strcmp(menuitem->action, "fastquit") || !strcmp(menuitem->action, "return"))) {
					egress_possible = 1;
				} else if (!strcmp(handler_name, "menu")) {
					/* If it's a menu, make sure the menu it references actually exists. */
					if (strlen_zero(args)) {
						bbs_warning("Menu item 'menu' requires an argument\n");
					} else if (!find_menu(args)) {
						bbs_warning("Menu '%s' referenced by %s => %c does not exist\n", args, menu->name, menuitem->opt);
					}
				}
			}
		}
		RWLIST_UNLOCK(&menu->menuitems);
		if (!egress_possible) {
			/* This will strand any users that access this menu */
			bbs_warning("Menu '%s' contains no way to exit or return from it\n", menu->name);
		}
	}
	RWLIST_UNLOCK(&menus);
	return 0;
}

static int reload_menus(int fd)
{
	int res = bbs_load_menus(1);
	if (!res) {
		bbs_dprintf(fd, "Reloaded menus\n");
	}
	return res;
}

static int cli_menus(struct bbs_cli_args *a)
{
	return bbs_dump_menus(a->fdout);
}

static int cli_menu(struct bbs_cli_args *a)
{
	return bbs_dump_menu(a->fdout, a->argv[1]);
}

static struct bbs_cli_entry cli_commands_menu[] = {
	BBS_CLI_COMMAND(cli_menus, "menus", 1, "List all menus", NULL),
	BBS_CLI_COMMAND(cli_menu, "menu", 2, "Dump a menu", "menu <name>"),
};

int bbs_load_menus(int reload)
{
	int res;
	res = load_config(reload);

	/* We can't check the sanity of menus.conf until all modules have registered,
	 * since menu handlers aren't yet registered right now, so we have to wait to verify them. */
	bbs_run_when_started(check_menus, STARTUP_PRIORITY_DEFAULT);

	if (!reload) {
		bbs_register_reload_handler("menus", "Reload BBS menus", reload_menus);
		res |= bbs_cli_register_multiple(cli_commands_menu);
	}
	return res;
}

void bbs_free_menus(void)
{
	bbs_cli_unregister_multiple(cli_commands_menu);
	RWLIST_REMOVE_ALL(&menus, entry, menu_free);
}
