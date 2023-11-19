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
 * \brief Graphical text menus
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <curses.h>
#include <menu.h>
#include <unistd.h>
#include <wait.h>

#include "include/module.h"
#include "include/node.h"
#include "include/term.h"

#include "include/mod_ncurses.h"

void bbs_ncurses_menu_init(struct bbs_ncurses_menu *menu)
{
	menu->title = NULL;
	menu->subtitle = NULL;
	menu->num_options = 0;
	menu->keybindings = menu->keybind;
	/* Don't bother initializing the options array */
}

void bbs_ncurses_menu_destroy(struct bbs_ncurses_menu *menu)
{
	int i;
	for (i = 0; i < menu->num_options; i++) {
		free(menu->options[i]);
		free_if(menu->optvals[i]);
	}
	/* Don't free menu itself, it's stack allocated */
}

void bbs_ncurses_menu_set_title(struct bbs_ncurses_menu *menu, const char *title)
{
	menu->title = title;
}

void bbs_ncurses_menu_set_subtitle(struct bbs_ncurses_menu *menu, const char *subtitle)
{
	menu->subtitle = subtitle;
}

void bbs_ncurses_menu_disable_keybindings(struct bbs_ncurses_menu *menu)
{
	menu->keybindings = NULL;
}

int bbs_ncurses_menu_addopt(struct bbs_ncurses_menu *menu, char key, const char *opt, const char *value)
{
	if (menu->num_options >= MAX_NCURSES_MENU_OPTIONS) {
		bbs_warning("Maximum number of options (%d) reached for menu\n", menu->num_options);
		return -1;
	}
	/* We pass in 0 for no key binding, but to avoid null terminating the buffer,
	 * we silently change that to a space, which is internally used to indicate no binding. */
	menu->keybind[menu->num_options] = key ? key : ' ';
	menu->options[menu->num_options] = strdup(opt);
	bbs_debug(6, "Added menu option %d with key binding '%c'\n", menu->num_options, key ? key : ' ');
	menu->optvals[menu->num_options] = !strlen_zero(value) ? strdup(value) : NULL;
	menu->num_options++;
	return 0;
}

const char *bbs_ncurses_menu_getopt_name(struct bbs_ncurses_menu *menu, int index)
{
	if (!IN_BOUNDS(index, 0, menu->num_options - 1)) {
		bbs_warning("Index %d is out of bounds for this menu\n", index);
		return NULL;
	}
	return menu->options[index];
}

char bbs_ncurses_menu_getopt_key(struct bbs_ncurses_menu *menu, int index)
{
	if (!IN_BOUNDS(index, 0, menu->num_options - 1)) {
		bbs_warning("Index %d is out of bounds for this menu\n", index);
		return 0;
	}
	if (!menu->keybindings) {
		return 0;
	}
	return menu->keybind[index]; /* If keybindings isn't NULL, it's equivalent to keybind */
}

char bbs_ncurses_menu_getopt_selection(struct bbs_node *node, struct bbs_ncurses_menu *menu)
{
	int res;

	res = bbs_ncurses_menu_getopt(node, menu);
	if (res < 0) {
		return 0;
	}

	return bbs_ncurses_menu_getopt_key(menu, res);
}

#define MENU_WIDTH 76
#define MENU_PAGE_NUM_OPTIONS 10

enum print_pos {
	PRINT_MIDDLE = 0,
	PRINT_LEFT,
};

#define print_in_middle(win, starty, startx, width, string, color) __print_pos(win, starty, startx, width, string, color, PRINT_MIDDLE)
#define print_left(win, starty, startx, width, string, color) __print_pos(win, starty, startx, width, string, color, PRINT_LEFT)

static void __print_pos(WINDOW *win, int starty, int startx, int width, const char *string, chtype color, enum print_pos print_pos)
{
	int length, x, y;
	double temp;

	if (!win) {
		win = stdscr;
	}
	getyx(win, y, x);
	if (startx != 0) {
		x = startx;
	}
	if (starty != 0) {
		y = starty;
	}
	if (width == 0) {
		width = MENU_WIDTH;
	}

	length = (int) strlen(string);
	temp = (1.0 * width - length) / 2;
	x = startx + (int) temp;
	wattron(win, color);
	switch (print_pos) {
		case PRINT_MIDDLE:
			mvwprintw(win, y, x, "%s", string);
			break;
		case PRINT_LEFT:
			mvwprintw(win, y, 2, "%s", string);
			break;
	}
	wattroff(win, color);
	refresh();
}

static int run_menu(const char *title, const char *subtitle, int num_choices, ITEM **options, const char *optkeys)
{
	char *curpos;
	int c, offset, selected_item;
	ITEM *selection;
	MENU *menu;
	WINDOW *win;
	int show_subtitle = !strlen_zero(subtitle) ? 1 : 0;

	/* Create menu */
	menu = new_menu(options);

	/* Create window for menu */
	win = newwin(MENU_PAGE_NUM_OPTIONS + 5, MENU_WIDTH, 2, 2);
	keypad(win, TRUE);

	/* Set main window and sub window */
	set_menu_win(menu, win);
	set_menu_sub(menu, derwin(win, MENU_PAGE_NUM_OPTIONS, MENU_WIDTH - 2, 3 + show_subtitle, 1));
	set_menu_format(menu, MENU_PAGE_NUM_OPTIONS, 1);
	set_menu_mark(menu, " * "); /* Set "selected" item string */

	/* Print a border around the main window and print a title */
	wborder(win, '|', '|', '-', '-', '/', '\\', '\\', '/'); /* relying on the default ACS macros (perhaps using box) doesn't always work properly */
	print_in_middle(win, 1, 0, MENU_WIDTH, title, COLOR_PAIR(1));

	/* This will print left-aligned text on the same line as the title, which could be useful but not what we want here... */
	if (show_subtitle) {
		print_left(win, 1 + show_subtitle, 0, MENU_WIDTH, subtitle, COLOR_PAIR(2));
	}
	mvwaddch(win, 2 + show_subtitle, 0, '|');
	mvwhline(win, 2 + show_subtitle, 1, '-', MENU_WIDTH - 2);
	mvwaddch(win, 2 + show_subtitle, MENU_WIDTH - 1, '|');
	mvprintw(LINES - 2, 0, "ESC to exit");

	refresh();

	/* Post the menu */
	post_menu(menu);
	wrefresh(win);

	for (;;) { /* Loop until we get an ESCAPE */
		c = wgetch(win);
		if (c == ERR) {
			selected_item = -1;
			goto quit;
		}
		switch (c) {
		case 27: /* Break on ESCAPE */
			selected_item = -1;
			goto quit;
		case 10: /* Break on ENTER */
		case KEY_ENTER: /* Break on ENTER */
			goto postmenu;
		case KEY_DOWN:
			menu_driver(menu, REQ_DOWN_ITEM);
			break;
		case KEY_UP:
			menu_driver(menu, REQ_UP_ITEM);
			break;
		case 'n':
		case KEY_NPAGE:
			menu_driver(menu, REQ_SCR_DPAGE);
			break;
		case 'k':
		case KEY_PPAGE:
			menu_driver(menu, REQ_SCR_UPAGE);
			break;
		case KEY_HOME:
			menu_driver(menu, REQ_FIRST_ITEM);
			break;
		case KEY_END:
			menu_driver(menu, REQ_LAST_ITEM);
			break;
		default:
			if (optkeys) {
				curpos = strchr(optkeys, c);
				if (curpos && c != ' ') { /* Space indicates no key binding */
					offset = (int) (curpos - optkeys); /* Calculate index in string */
					if (offset < num_choices) {
						/* Allow for optstrings like "abcdefg..." that might be longer than the available options.
						 * Prevent indexing out of bounds by just ignoring if it's not within bounds. */
						set_current_item(menu, options[offset]);
						goto postmenu;
					}
				} else if (c == 'q' && !strchr(optkeys, 'q')) {
					/* option string, but it doesn't contain 'q', so treat that as an exit */
					selected_item = -1;
					goto quit;
				}
			} else { /* have a default 'q' binding for quit */
				if (c == 'q') {
					selected_item = -1;
					goto quit;
				}
			}
			break; /* Do nothing */
		}
		wrefresh(win);
	}

postmenu:
	selection = current_item(menu);
	selected_item = item_index(selection);

quit:
	/* Unpost and free all memory taken up */
	unpost_menu(menu);
	free_menu(menu);

	return selected_item;
}

static int ncurses_menu(struct bbs_ncurses_menu *menu)
{
	int i, selected_item;
	ITEM **options;

	/* Initialize curses */
	initscr();
	start_color();
	cbreak(); /* Unlike raw, allow CTRL codes */
	noecho();
	keypad(stdscr, TRUE);
	init_pair(1, COLOR_MAGENTA, COLOR_BLACK);
	init_pair(2, COLOR_GREEN, COLOR_BLACK);
	curs_set(0); /* Disable cursor */

	/* Yes, you need to allocate N+1, or you get segfaults with 3 menu items... */
	options = calloc((size_t) menu->num_options + 1, sizeof(ITEM *));
	/* Create items */
	for (i = 0; i < menu->num_options; i++) {
		/* Even though we can mutate menu independent of the parent, don't.
		 * This way, we can avoid having to do copy on write altogether. */
		options[i] = new_item(menu->options[i], menu->optvals[i] ? menu->optvals[i] : "");
		if (strlen_zero(menu->options[i])) {
			bbs_warning("Option %d is empty\n", i);
		}
	}

	selected_item = run_menu(menu->title, menu->subtitle, menu->num_options, options, menu->keybind);
	for (i = 0; i < menu->num_options; i++) {
		free_item(options[i]);
	}
	free(options);
	endwin();
	return selected_item;
}

int bbs_ncurses_menu_getopt(struct bbs_node *node, struct bbs_ncurses_menu *menu)
{
	int pfd[2];
	int res;
	ssize_t rres;
	char c;

	/* Null terminate before running for strchr */
	menu->keybind[menu->num_options] = '\0';

	if (menu->num_options <= 0) {
		bbs_warning("Menu has %d options?\n", menu->num_options);
		return -1;
	}

	bbs_debug(3, "Executing menu with %d option%s\n", menu->num_options, ESS(menu->num_options));

	/* ncurses is not threadsafe.
	 * There is a threadsafe version, but it's not very robust,
	 * not recommended, and it's almost certainly not the version
	 * of ncurses present on this system.
	 * Rather than requiring that this version be present, at the risk
	 * of messing up everything else on the system,
	 * work around this by forking and running ncurses in a separate process.
	 * To do this, we fork, and then construct the menu there, passing
	 * the return value back using a pipe.
	 */

	if (pipe(pfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	}

	bbs_node_unbuffer(node); /* Make sure our PTY is unbuffered for ncurses */
	bbs_node_flush_input(node);

	res = fork();
	if (res < 0) {
		bbs_error("fork failed: %s\n", strerror(errno));
		return -1;
	} else if (!res) {
		/* We now have our own copy of menu, to do with as we please.
		 * We don't even have to marshall the menu into argv and exec. */
		bbs_set_stdout_logging(0); /* Don't log to the child process's STDOUT. */
		close(pfd[0]); /* Close read end */

		/* ncurses expects to use STDIN and STDOUT by default.
		 * Tie these to the node, just like in system.c. */
		dup2(node->slavefd, STDIN_FILENO);
		dup2(node->slavefd, STDOUT_FILENO);
		close(STDERR_FILENO);

		/* The environment (in particular, the TERM variable) isn't set properly
		 * at this point for ncurses (it may be, incidentally, if the BBS is running in the foreground,
		 * started from a terminal, but in general, it may be running daemonized.)
		 * We could therefore set the TERM variable here if we have it available on the node. */

		res = ncurses_menu(menu);
		c = (char) res;
		if (write(pfd[1], &c, 1) != 1) {
			_exit(errno);
		}
		close(pfd[1]);
		_exit(0);
	}

	/* Wait for completion. */
	node->childpid = res;
	close(pfd[1]); /* Close write end */
	if (waitpid(res, NULL, 0) < 0) {
		bbs_error("waitpid failed: %s\n", strerror(errno));
		close(pfd[0]);
		return -1;
	}
	node->childpid = 0;
	rres = read(pfd[0], &c, 1);
	close(pfd[0]);
	if (rres != 1) {
		bbs_error("Failed to read result: %s\n", strerror(errno));
		return -1;
	}
	res = c;
	bbs_debug(3, "Menu return value: %d\n", res);
	return res;
}

static int load_module(void)
{
	return 0;
}

static int unload_module(void)
{
	return 0;
}

BBS_MODULE_INFO_FLAGS("ncurses", MODFLAG_GLOBAL_SYMBOLS);
