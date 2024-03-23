/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Simple file manager for viewing and downloading files via X/Y/ZMODEM
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define _GNU_SOURCE 1

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <wait.h>

#include <sys/stat.h>

#include <ncurses.h>
#include <menu.h>

/* Cleaner output, but less efficient, since the screen is redrawn completely after ZMODEM operations: */
#define SUSPEND_NCURSES_WHILE_ZMODEM_RUNNING

/* No user servicable parts below this */

/*! \note Currently, this program only supports ZMODEM, not X/YMODEM. */
static char modemtype = 'Z';

static int allow_downloads = 0;
static int allow_uploads = 0;

#define PROGNAME "filemgr"
#define PROG_VERSION "0.0.1"
#define PROG_COPYRIGHT "Copyright (C) 2024 Naveen Albert"

static WINDOW *header, *footer, *win;
static char scratchbuf[1024];
static int really_started = 0;

static int keep_footer = 0;

#define SET_FOOTER(fmt, ...) { \
	snprintf(scratchbuf, sizeof(scratchbuf), fmt, ## __VA_ARGS__); \
	__set_footer(scratchbuf); \
	keep_footer = 1; \
}

#define ERROR(fmt, ...) { \
	if (really_started) { \
		SET_FOOTER(fmt, ## __VA_ARGS__); \
		flash(); \
		beep(); \
		doupdate(); \
	} else { \
		endwin(); \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} \
}

static void __set_footer(const char *s)
{
	wmove(footer, 0, 0);
	wclrtoeol(footer); /* Clear line */
	mvwaddstr(footer, 0, 0, s);
	wnoutrefresh(footer);
}

static char dtypec(int c)
{
	switch (c & S_IFMT) {
		case S_IFBLK: return 'B';
		case S_IFCHR: return 'C';
		case S_IFDIR: return 'D';
		case S_IFIFO: return 'P';
		case S_IFLNK: return 'L';
		case S_IFREG: return 'F';
		case S_IFSOCK: return 'S';
		default: return '?';
	}
	__builtin_unreachable();
}

static void format_size(size_t size, char *buf, size_t len)
{
	if (size < 1024) {
		snprintf(buf, len, "%lu B", size);
		return;
	}

	size += (1024 / 2) + 1; /* Round up */
	size /= 1024;
	if (size < 1024) {
		snprintf(buf, len, "%lu K", size);
		return;
	}

	size += (1024 / 2) + 1; /* Round up */
	size /= 1024;
	if (size < 1024) {
		snprintf(buf, len, "%lu M", size);
		return;
	}

	size += (1024 / 2) + 1; /* Round up */
	size /= 1024;
	if (size < 1024) {
		snprintf(buf, len, "%lu G", size);
		return;
	}

	size += (1024 / 2) + 1; /* Round up */
	size /= 1024;
	if (size < 1024) {
		snprintf(buf, len, "%lu T", size);
		return;
	}
	strcpy(buf, "?????"); /* Safe */
}

static void format_date(time_t t, char *buf, size_t len)
{
	struct tm tm;
	localtime_r(&t, &tm);
	strftime(buf, len, "%b %e %H:%M %Y", &tm);
}

static int exec_helper(char *const argv[])
{
	pid_t pid;
	int res = -1;
	int wstatus;

	pid = fork();
	if (pid < 0) {
		ERROR("fork: %s", strerror(errno));
		return -1;
	} else if (!pid) {
		execvp(argv[0], argv);
		_exit(errno);
	}
	waitpid(pid, &wstatus, 0);
	if (WIFEXITED(wstatus)) {
		if (WEXITSTATUS(wstatus) == 0) {
			res = 0;
		} else {
			if (WEXITSTATUS(wstatus) == ENOENT) {
				ERROR("%s not installed!", argv[0]);
			} else {
				ERROR("execvp: %s", strerror(errno));
			}
			res = -1;
		}
	}
	return res;
}

static int download_file(const char *filename)
{
	const char *prog = modemtype == 'X' ? "sx" : modemtype == 'Y' ? "sy" : "sz";
	char *const argv[] = { (char*) prog, "-b", (char*) filename, NULL };
	return exec_helper(argv);
}

static int upload_file(void)
{
	const char *prog = modemtype == 'X' ? "rx" : modemtype == 'Y' ? "ry" : "rz";
	char *const argv[] = { (char*) prog, "-b", NULL };
	return exec_helper(argv);
}

static int create_directory(void)
{
	char filename[128] = "";
	char *buf = filename;
	size_t left = sizeof(filename);

	for (;;) {
		int c;
		SET_FOOTER("New directory: %s", filename);
		doupdate();
		c = getch();
		switch (c) {
		case ERR:
			return -1;
		case 27: /* ESCAPE */
			SET_FOOTER("Operation cancelled");
			return 1;
		/* Not allowed in filenames by Linux */
		case '/':
		case 0:
			beep();
			break;
		case '\n':
			/* Ignore LF since do we did nonl(), this will double up with CR otherwise */
			continue;
		case '\r':
		case KEY_ENTER:
			goto done;
		case KEY_BACKSPACE:
			if (buf > filename) {
				buf--;
				*buf = '\0';
				left++;
			} else {
				beep();
			}
			break;
		default:
			if (!isprint(c)) {
				beep();
				break;
			}
			*buf++ = c;
			*buf = '\0';
			left--;
			if (left <= 1) {
				SET_FOOTER("Directory name too long!");
				return 1;
			}
		}
	}

done:
	if (mkdir(filename, 0755)) {
		SET_FOOTER("Error: %s", strerror(errno));
		return 1;
	} else {
		SET_FOOTER("Directory created!");
		return 0;
	}
}

#ifndef SUSPEND_NCURSES_WHILE_ZMODEM_RUNNING
static void menu_fixup(MENU *menu, WINDOW *window, int numfiles)
{
	int x, y;
	ITEM *selection = current_item(menu);
	int index = item_index(selection);

	/* In some terminals an artifact will be leftover at the end (binary on the line from the ZMODEM protocol).
	 * Ideally, we could use wredrawln to force ncurses to redraw the current line,
	 * but this doesn't work since its idea of where the cursor is on the screen is now wrong.
	 *
	 * As a hacky workaround, move to another row and come back, if possible,
	 * since the highlighting changes cause the row to be redrawn properly.
	 * However, try not to move the page if we're at the first or last visible item.
	 *
	 * The below is probably NOT the best way to do this, more efficient code would be better...
	 */
	getyx(window, y, x);
	if (index > 0) {
		/* Go up and then back down */
		if (y > 0) {
			menu_driver(menu, REQ_UP_ITEM);
			wnoutrefresh(window);
			doupdate();
			menu_driver(menu, REQ_DOWN_ITEM);
		} else {
			menu_driver(menu, REQ_SCR_UPAGE);
			wnoutrefresh(window);
			doupdate();
			menu_driver(menu, REQ_SCR_DPAGE);
		}
	}
	if (index < numfiles - 1) {
		/* Go down and then back up */
		if (y < LINES - 3) {
			menu_driver(menu, REQ_DOWN_ITEM);
			wnoutrefresh(window);
			doupdate();
			menu_driver(menu, REQ_UP_ITEM);
		} else {
			menu_driver(menu, REQ_SCR_DPAGE);
			wnoutrefresh(window);
			SET_FOOTER("%s", " "); /* first letter of footer also needs to get updated to make that redraw properly */
			doupdate();
			menu_driver(menu, REQ_SCR_UPAGE);
		}
	} else { /* index == numfiles - 1 */
		if (y < LINES - 3) {
			wredrawln(window, y, 2);
		}
	}
	(void) x;
}
#endif /* SUSPEND_NCURSES_WHILE_ZMODEM_RUNNING */

/*!
 * \brief Display a directory. Nothing fancy like mc, just a single pane showing files and directories.
 * \retval 0 to run again immediately, 1 to redraw windows, -1 on error, -2 to quit
 */
static int display_directory(void)
{
	struct dirent **entries, *entry;
	ITEM **items, *selection;
	MENU *menu;
	char **displays;
	int i, numfiles;
	int width;
	int res = 3; /* Default value that means keep looping */

	numfiles = scandir(".", &entries, NULL, alphasort);
	if (numfiles < 0) {
		ERROR("scandir: %s", strerror(errno));
		return -1;
	}
	/* Add menu entries */
	displays = calloc(numfiles, sizeof(char *));
	if (!displays) {
		ERROR("calloc");
		return -1; /* Leaks, but exiting */
	}
	items = calloc(numfiles + 1, sizeof(ITEM*));
	if (!items) {
		ERROR("calloc");
		return -1; /* Leaks, but exiting */
	}
	width = COLS - (1 + 1 + 2 + 5 + 2 + 17);
	for (i = 0; i < numfiles; i++) {
		struct stat st;
		char size[21];
		char date[26];
		char dtype;
		/* Show filename, size, and modify time */
		if (lstat(entries[i]->d_name, &st)) {
			ERROR("lstat: %s", strerror(errno));
			return -1;
		}
		format_size(st.st_size, size, sizeof(size));
		format_date(st.st_mtime, date, sizeof(date));
		dtype = dtypec(st.st_mode);
		/* Make this take up the entire screen */
		/* 24, not 25, for date, since we don't want the newline at the end */
		if (asprintf(&displays[i], "%c %-*.*s  %5s  %17s", dtype, width, width, entries[i]->d_name, size, date) < 0) {
			ERROR("asprintf");
			return -1;
		}
		items[i] = new_item(displays[i], "");
		if (!items[i]) {
			ERROR("new_item: %s - %s", displays[i], strerror(errno));
			return -1;
		}
		set_item_userptr(items[i], entries[i]); /* Store dirent as callback data */
	}
	items[numfiles] = NULL; /* Array must be NULL terminated */

	/* Create menu */
	menu = new_menu(items);
	if (!menu) {
		return -1; /* Leaks, but exiting */
	}
	set_menu_win(menu, win);
	/* We can't seem to use wbkgd here to set the colors, so do that manually for each item instead. */
	set_menu_sub(menu, derwin(win, LINES - 2, COLS, 0, 0));
	set_menu_format(menu, LINES - 2, 1); /* rows, cols (of options) */
	set_menu_mark(menu, ""); /* No need for a mark, whatever's selected is already highlighted */

	/* Display, and input loop */
	post_menu(menu);
	wnoutrefresh(win);
	doupdate();

#define LOAD_CURRENT() \
	selection = current_item(menu); \
	entry = item_userptr(selection); \
	if (entry->d_type == DT_UNKNOWN) { \
		struct stat st; \
		if (lstat(entry->d_name, &st)) { \
			ERROR("lstat: %s", strerror(errno)); \
			break; \
		} \
		is_dir = S_ISDIR(st.st_mode); \
	} else if (entry->d_type == DT_DIR) { \
		is_dir = 1; \
	} else if (entry->d_type != DT_REG) { \
		ERROR("Unknown dtype: %d", entry->d_type); \
		break; \
	}

	really_started = 1;
	for (;;) {
		int delres;
		int is_dir = 0; /* avoid uninitialized warning */
		int c = getch();
		keep_footer = 0;
		switch (c) {
		case ERR:
			res = -1;
			break;
		case KEY_RESIZE:
			res = 1;
			break;
		case 'q':
		case 'Q':
			res = -2;
			break;
		case KEY_UP:
			menu_driver(menu, REQ_UP_ITEM);
			break;
		case KEY_DOWN:
			menu_driver(menu, REQ_DOWN_ITEM);
			break;
		case KEY_PPAGE:
			menu_driver(menu, REQ_SCR_UPAGE);
			break;
		case KEY_NPAGE:
			menu_driver(menu, REQ_SCR_DPAGE);
			break;
		case KEY_HOME:
			menu_driver(menu, REQ_FIRST_ITEM);
			break;
		case KEY_END:
			menu_driver(menu, REQ_LAST_ITEM);
			break;
		case ' ': /* SPACE */
			/* Create new directory */
			if (!allow_uploads) {
				ERROR("Directory creation disabled");
				break;
			}
			res = create_directory();
			if (res > 0) {
				res = 3; /* Reset and continue */
			} /* else if res < 0, abort, and if 0, menus needs recreate/redraw since we created a new inode in this directory */
			break;
		case KEY_DC: /* DELETE */
			if (!allow_uploads) {
				ERROR("Deletion disabled");
				break;
			}
			LOAD_CURRENT();
			SET_FOOTER("%s - permanently delete? (y/n) ", entry->d_name);
			doupdate();
			c = getch();
			if (c == 'y' || c == 'Y') {
				if (unlink(entry->d_name)) {
					SET_FOOTER("%s - deletion failed: %s", entry->d_name, strerror(errno));
				} else {
					SET_FOOTER("%s - deleted!", entry->d_name);
					res = 0; /* Redraw folder */
				}
			} else {
				SET_FOOTER("%s - deletion cancelled", entry->d_name);
			}
			if (is_dir) {
				/* If the directory is empty, allow it to be deleted.
				 * If not, that is pretty dangerous, and the system
				 * call will fail anyways, so that functions as a safeguard already. */
				delres = rmdir(entry->d_name);
			} else {
				delres = unlink(entry->d_name);
			}
			if (delres) {
				SET_FOOTER("%s - deletion failed: %s", entry->d_name, strerror(errno));
			} else {
				SET_FOOTER("%s - deleted!", entry->d_name);
				res = 0; /* Redraw folder */
			}
			break;
		case '\n':
			/* Ignore LF since do we did nonl(), this will double up with CR otherwise */
			continue;
		case '\r':
		case KEY_ENTER:
			/* Select current entry */
			LOAD_CURRENT();
			if (is_dir) {
				/* cd to this dir */
				chdir(entry->d_name);
				res = 0;
			} else {
				/* It's a file, download it */
				if (allow_downloads) {
					int dres;
					SET_FOOTER("%s - downloading via %cMODEM...", entry->d_name, modemtype);
					doupdate();
#ifdef SUSPEND_NCURSES_WHILE_ZMODEM_RUNNING
					endwin(); /* Disable ncurses while ZMODEM is running */
#endif
					dres = download_file(entry->d_name);
#ifndef SUSPEND_NCURSES_WHILE_ZMODEM_RUNNING
					menu_fixup(menu, win, numfiles);
#endif
					/* Draw footer after in case the last row mangled it */
					if (!dres) {
						SET_FOOTER("%s - downloaded!", entry->d_name);
					}
				} else {
					ERROR("File download not permitted");
				}
			}
			break;
		case 331: /* INSERT */
		case 64: /* Also INSERT? */
			if (allow_uploads) {
				int ures;
				SET_FOOTER("Uploading via %cMODEM... please wait", modemtype);
				doupdate();
#ifdef SUSPEND_NCURSES_WHILE_ZMODEM_RUNNING
				endwin(); /* Disable ncurses while ZMODEM is running */
#endif
				ures = upload_file();
#ifndef SUSPEND_NCURSES_WHILE_ZMODEM_RUNNING
				/* Tested with SyncTERM, for both downloads and uploads,
				 * menu_fixup is usually able to take care of artifacts,
				 * at least eventually (after ZMODEM itself is completed).
				 * I've noticed it can be a bit trickier for uploads, e.g.
				 * if you press INSERT to initiate a transfer and then ESC immediately,
				 * which will cause the terminal to get "stuck"; using ALT+U or ALT+D
				 * to attempt another ZMODEM operation will eventually fix this.
				 *
				 * A couple artifacts are still left with uploads that disappear with navigation.
				 *
				 * Downloads are smoother; and in fact using ALT+D to download a file
				 * works fine. ALT+U to upload a file does not, since we don't support
				 * the client telling us it wants to upload a file, so the user will
				 * need to press INS to do that. */
				menu_fixup(menu, win, numfiles);
#endif
				if (!ures) {
					SET_FOOTER("File uploaded!");
					res = 0; /* Redraw folder since it contains new files */
				} else {
					SET_FOOTER("Upload failed or cancelled");
				}
			} else {
				ERROR("File upload not permitted");
			}
			break;
		/* Jump to listings that start with the typed letter */
		case 'a' ... 'p':
		case 'r' ... 'z': /* Exclude q */
		case 'A' ... 'P':
		case 'R' ... 'Z':
			for (i = 0; i < numfiles; i++) {
				int cmp = entries[i]->d_name[0] == c;
				if (cmp) {
					/* Found a match */
					set_current_item(menu, items[i]);
					SET_FOOTER("Jumped to '%c'", c);
					break;
				}
			}
			break;
		default:
			beep();
#ifdef DEBUG_KEY_VALUES
			SET_FOOTER("No binding for %d", c);
			break;
#endif
			continue; /* Ignored */
		}
		if (res != 3) {
			break;
		}
		/* Show currently selected file in the status bar */
		selection = current_item(menu);
		entry = item_userptr(selection);
		if (!keep_footer) {
			SET_FOOTER("%s", entry->d_name);
		}
		wnoutrefresh(win);
		doupdate();
	}

	/* Clean up */
	unpost_menu(menu);
	free_menu(menu);
	for (i = 0; i < numfiles; i++) {
		free_item(items[i]);
		free(entries[i]);
		free(displays[i]);
	}
	free(entries);
	return res;
}

static int filemgr(void)
{
	int res;

	initscr();
	cbreak();
	nonl();
    noecho();
	keypad(stdscr, TRUE); /* Enable keypad for function key interpretation (escape sequences) */
	curs_set(0); /* Disable cursor */
	start_color(); /* Enable colors */

	init_pair(1, COLOR_WHITE, COLOR_BLACK);
	init_pair(2, COLOR_CYAN, COLOR_BLUE);

	clear();
	doupdate();

	do {
		header = newwin(1, COLS, 0, 0); /* Top */
		if (!header) {
			return -1;
		}
		footer = newwin(1, COLS, LINES - 1, 0); /* Bottom */
		if (!footer) {
			delwin(header);
			return -1;
		}
		win = newwin(LINES - 2, COLS, 1, 0); /* Main window, in middle */
		wbkgd(header, COLOR_PAIR(2));
		wbkgd(footer, COLOR_PAIR(2));

		refresh();

		/* Set up header */
		mvwaddstr(header, 0, 0, PROGNAME);
		wnoutrefresh(header);

		/* Set up footer */
		if (allow_uploads) {
			SET_FOOTER("%s", allow_downloads ? "INS to upload, ENTER to download via ZMODEM, SP to create directory" : "INS to upload via ZMODEM, downloads disabled, SP to create directory");
		} else {
			SET_FOOTER("%s", allow_downloads ? "Press ENTER to download via ZMODEM" : "Downloads/uploads disabled");
		}

		/* Returning after each call ensures
		 * the stack depth never gets too deep,
		 * regardless of level of recursion on file system. */
		do {
			res = display_directory();
		} while (!res);

		delwin(header);
		delwin(footer);
		delwin(win);
	} while (res > 0);
	return res == -1 ? -1 : 0;
}

static void show_help(void)
{
	printf(PROGNAME " -- simple orthodox file manager\n");
	printf("\n");
	printf("Usage: filemgr   [-opts[modifiers]]\n");
	printf("  -d             Also allow file downloads via ZMODEM\n");
	printf("  -l             Logfile to use for runtime logging\n");
	printf("  -u             Also allow file uploads via ZMODEM\n");
	printf("  -V             Display program version and exit\n");
	printf("  -?             Display this help and exit\n");
	printf("\n");
}

static int load_config(int argc, char *argv[])
{
	int c;
	static const char *opts = "dhuV?";

	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 'd':
			allow_downloads = 1;
			break;
		case 'h':
		case '?':
			show_help();
			return 1;
		case 'u':
			allow_uploads = 1;
			break;
		case 'V':
			fprintf(stderr, PROGNAME " " PROG_VERSION " " PROG_COPYRIGHT "\n");
			return 1;
		default:
			break;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int res;

	if (load_config(argc, argv)) {
		return -1;
	}

	res = filemgr();

	endwin();
	return res;
}
