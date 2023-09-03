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
 * \brief Terminal editor: editor, paging, navigation, etc.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h> /* use isspace (for rtrim) */
#include <math.h>

#include "include/node.h"
#include "include/term.h"
#include "include/editor.h"
#include "include/utils.h" /* use bbs_str_count */

int bbs_line_editor(struct bbs_node *node, const char *restrict instr, char *restrict buf, size_t len)
{
	char *tmp, *ptr = buf;
	int otherdata = 0, nlflag = 0;

	bbs_node_clear_screen(node);
	bbs_node_writef(node, "%s%s LINE EDITOR - %sENTER 2x to process/abort%s\n", COLOR(COLOR_PRIMARY), BBS_SHORTNAME, COLOR(COLOR_SECONDARY), COLOR_RESET);
	if (instr) {
		bbs_node_writef(node, "%s%s%s\n", COLOR(COLOR_WHITE), instr, COLOR_RESET);
	}

	for (;;) {
		char c;
		bbs_node_buffer(node);
		/* Read until we get 2 newlines */
		for (;;) {
			size_t res = (size_t) bbs_node_readline(node, MIN_MS(5), ptr, len);
			if (res <= 0) {
				return -1;
			}
			res = strlen(ptr); /* Use length of string, not raw bytes of input read */
			if (res == 0) {
				nlflag++;
			} else {
				nlflag = 0;
				otherdata++;
			}
			ptr += res;
			len -= res;
			if (len <= 2) { /* Room for LF and NUL */
				/* Truncation */
				bbs_node_writef(node, "%sBuffer is full, aborting%s\n", COLOR(COLOR_RED), COLOR_RESET);
				NEG_RETURN(bbs_node_wait_key(node, MIN_MS(2)));
				return 0;
			}
			*ptr = '\n';
			ptr += 1;
			len -= 1;
			*ptr = '\0';
			/* In most cases, users will finish typing a sentence and hit ENTER.
			 * i.e. Every readline ends in a LF.
			 * However, we only care about cases where all we got was an ENTER, and that was it.
			 * The edge case is if the user presses ENTER immediately, without typing anything else.
			 * In this case, one fewer ENTER will be required, and the editor would quit after only one ENTER.
			 * To prevent this, we only abort when nlflag is 1, if the user has previously input other data.
			 */
			if (nlflag == 2 || (nlflag == 1 && otherdata)) {
				break;
			}
		}
		/* This loop should run nflag + 1 times */
		do {
			/* Rewind the buffer slightly, null terminating the extra newline */
			*ptr-- = '\0';
			len++;
		} while (nlflag--);
		bbs_debug(3, "Line editing finished: %s\n", buf);
		bbs_node_writef(node, "%sProcess? [YNC]%s\n", COLOR(COLOR_RED), COLOR_RESET);
		bbs_node_unbuffer(node);
		c = bbs_node_tread(node, MIN_MS(1));
		if (c <= 0) {
			return -1; /* if tpoll/tread return 0, we return -1 */
		} else if (tolower(c) == 'y') {
			break;
		} else if (tolower(c) != 'c') {
			bbs_node_writef(node, "%sAborted%s\n", COLOR(COLOR_RED), COLOR_RESET);
			return 1;
		}
		ptr = strchr(buf, '\0'); /* Since we called rtrim, find the end of the buffer so far as we're concerned. */
		/* len will be smaller than it really is now, which is fine (as long as it's not bigger) */
	}

	tmp = buf; /* rtrim wants a pointer */
	rtrim(tmp); /* Trim all trailing whitespace */
	return 0;
}

/* #define DEBUG_PAGING */

#define PAGE_COLS(node) (node->cols ? node->cols : 80)
#define PAGE_ROWS(node) (node->rows ? node->rows : 24)

int bbs_pager(struct bbs_node *node, struct pager_info *pginfo, int ms, const char *restrict s, size_t len)
{
	/* Retrieve the terminal dimensions each time, because they could change at any time */
	unsigned int eff_width = PAGE_COLS(node);
	/* Subtract 1 each for header + footer, if present, plus our own footer */
	unsigned int eff_height = PAGE_ROWS(node) - (pginfo->header ? 1 : 0) - (pginfo->footer ? 1 : 0) - 1;

	if (!pginfo->line) {
		/* First invocation! Clear the screen and switch to non-canonical mode (with echo off). */
		NEG_RETURN(bbs_node_clear_screen(node));
		NEG_RETURN(bbs_node_reset_color(node));
		bbs_node_unbuffer(node);

		/* Print any header */
		if (pginfo->header) {
			/* If it has a newline, don't add another one */
			NEG_RETURN(bbs_node_writef(node, strchr(pginfo->header, '\n') ? "%s" : "%s\n", pginfo->header));
		}
		pginfo->want = eff_height; /* Start by printing the effective height number of rows */
	}
	/* Do we have lines pending to spill out to the screen? */
#ifdef DEBUG_PAGING
	bbs_debug(10, "Paged line[%d]: %s\n", len, s);
#endif
	if (pginfo->want > 0 && s) {
		int ends_in_newline;
		int newlines, lines_eff = 1;
		newlines = bbs_str_count(s, '\n');
		ends_in_newline = s[len - 1] == '\n' ? 1 : 0;
		if (newlines) {
			/* The LF isn't necessarily at the end of the line, this could mean there are multiple lines of input. */
			newlines -= ends_in_newline; /* If on of the LFs is at the end, it doesn't count (so long as we be sure not to print out own LF at the end) */
			if (newlines) {
				/* If more than 1 LF, then the caller has really violated the contract of the pager. ONE LINE AT A TIME! */
				bbs_warning("Input line contains line feeds! Please fix this!\n");
				/* Manually compensate. Add the number of unaccounted LFs. */
				lines_eff += newlines;
			}
		}
		if (len > eff_width) {
			/* The line is longer than the terminal width, so if we just spill it out as is, it will wrap automatically.
			 * That's fine, but we need to know how many rows this will actually use up on the user's terminal. */
			int actual_lines = (int) (len + (eff_width - 1) / eff_width); /* Round up, without using the ceil function to avoid expensive floating point division */
			lines_eff += (actual_lines - 1); /* Subtract 1 because actual_lines includes the first line, so don't double count that. */
		}
		/* If this will cause us to exceed what we're allowed, stop now. */
		if (lines_eff > (int) pginfo->want) {
			bbs_warning("Stopping paging early, as %d effective rows exceeds %ld permitted\n", lines_eff, pginfo->want);
			pginfo->want = 0; /* Reset */
			/* Continue to paging part of the function */
		} else {
			/* Print out a chunk */
			pginfo->line += lines_eff; /* Increment our effective line count */
			/* If we didn't actually know the real terminal size (node->cols == node->rows == 0),
			 * then we actually need to force wrapping at 80 columns, since there's
			 * no guarantee this is the real width. We just assumed it by default.
			 * Otherwise, on wide terminals, we may take up fewer lines on the screen than we thought we used.
			 */
			if (len > 80 && !node->cols) {
				size_t left = len;
				/* Write 80 characters at a time */
				while (left > 80) {
					NEG_RETURN(bbs_node_writef(node, "%.*s\n", 80, s));
					s += 80; /* Advance to next row of output */
					left -= 80;
				}
				/* At least 1 character remains */
			}
#ifdef DEBUG_PAGING
			bbs_debug(10, "[%d/%d] row %d (want %d): lines_eff: %d, extra LFs: %d, ends in LF: %d\n",
					eff_width, eff_height, pginfo->line, pginfo->want, lines_eff, newlines, ends_in_newline);
#endif
			if (s) {
				if ((len == 1 && *s == '\n') || (len == 2 && !strcmp(s, "\r\n"))) {
#ifdef DEBUG_PAGING
					bbs_debug(10, "Just an empty line\n");
#endif
					s = "\r \n"; /* Replace empty line with a space, then go on to the next line, to properly cover up the press : symbol */
				} else if (*s == '\t') {
					NEG_RETURN(bbs_node_writef(node, "\r \r")); /* Tabs don't erase the :, do so manually */
				}
				NEG_RETURN(bbs_node_writef(node, ends_in_newline ? "%s" : "%s\n", s)); /* Print the line */
			}
			if (pginfo->want) {
				pginfo->want -= (size_t) lines_eff; /* We're printing out this many rows, that we no longer owe */
			}
			/* Can't just write all the lines in a for loop, bbs_pager only gets 1 line at a time */
			if (pginfo->want) {
				return 0; /* Keep going, display the next line immediately. */
			} /* else, continue to paging */
		}
	}

	/* XXX pager_info.footer is currently ignored and not used. Should we draw a footer on the : prompt line? */

	/* Actual paging is now required. */
	for (;;) {
		int res;
		char buf[5];
		NEG_RETURN(bbs_node_writef(node, s ? ":" : "EOF:")); /* Input prompt */
		res = bbs_node_poll_read(node, ms, buf, 5); /* Any key shouldn't be more than 5 characters (some keys involve escape sequences) */
		if (res >= 0) {
			NEG_RETURN(bbs_node_writef(node, "\r")); /* Overwrite : */
			/* If the next line is just a newline, then we won't actually end up "deleting" the : in this manner.
			 * To workaround that, we could write "\r \r" which would space over the : and then go back to the beginning of the line again.
			 * However, to be more efficient, since most lines won't be empty, we can simply detect empty lines and do this only then.
			 */
		}
		if (res < 0) {
			return res;
		} else if (!res) {
			return 1; /* Timeout */
		}
		/* These options are similar to those used by more(1) and less(1) */
		switch (buf[0]) {
			case '\n': /* ENTER = 1 more line */
				pginfo->want++;
				break;
			case ' ': /* SPACE = 1 entire page */
				pginfo->want += eff_height;
				break;
			case 'q': /* Quit */
			case 'Q':
				return 2;
			case 'g': /* Jump to end of file */
			case 'G':
				pginfo->want += 999999; /* Hopefully we don't encounter any files this long, let alone INT_MAX lines long */
				break;
			default: /* Ignore */
				NEG_RETURN(bbs_node_ring_bell(node));
				continue; /* Continue the for loop */
		}
		if (!s) { /* Wait for explicit quit */
			NEG_RETURN(bbs_node_ring_bell(node));
			continue; /* Continue the for loop */
		}
		break;
	}
	return 0;
}

int bbs_node_term_browse(struct bbs_node *node, const char *filename)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t nbytes;
	struct pager_info pginfo;
	int res = 0;

	fp = fopen(filename, "r");
	if (!fp) {
		bbs_error("File does not exist: %s\n", filename);
		return -1;
	}

	memset(&pginfo, 0, sizeof(pginfo));
	pginfo.header = "Browse File";

	while ((nbytes = getline(&line, &len, fp)) != -1) {
#ifdef DEBUG_PAGING
		bbs_debug(8, "Read line(%zu): %s\n", nbytes, line);
#endif
		res = bbs_pager(node, &pginfo, MIN_MS(5), line, (size_t) nbytes);
		if (res) {
			break; /* Stop if anything exceptional happens */
		}
	}
	fclose(fp);
	if (line) {
		free(line); /* Free the last line */
	}
	if (!res) {
		res = bbs_pager(node, &pginfo, MIN_MS(5), NULL, 0);
	}
	return res < 0 ? -1 : 0;
}
