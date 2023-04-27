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
 * \brief SIGWINCH demo program
 *
 * \note This program is used to test the window resizing functionality of the BBS.
 *       It serves no other useful purpose.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>

static int last_sig = 0;

static void sigwinch_handler(int sig)
{
	last_sig = sig;
	return; /* Don't even log here, printf isn't safe in a signal handler */
}

#define print_winsize(ws) printf("Window size is %d cols and %d rows (x: %d, y: %d)\n", ws.ws_col, ws.ws_row, ws.ws_xpixel, ws.ws_ypixel)

int main(int argc, char *argv[])
{
	struct winsize winp;

	/* Not used */
	(void) argc;
	(void) argv;

	signal(SIGWINCH, sigwinch_handler); /* Set up the signal handler */
	printf("Waiting for SIGWINCH... press ^C to exit.\n");

	/* Get current window size */
	if (ioctl(0, TIOCGWINSZ, &winp)) {
		fprintf(stderr, "%d: ioctl failed: %s\n", __LINE__, strerror(errno));
	}
	print_winsize(winp);

	/* Loop until we get a SIGINT (^C) */
	for (;;) {
		pause();
		if (last_sig == SIGWINCH) {
			/* Get new window size */
			if (ioctl(0, TIOCGWINSZ, &winp)) {
				fprintf(stderr, "%d: ioctl failed: %s\n", __LINE__, strerror(errno));
			}
			print_winsize(winp);
		} else {
			printf("Got some non-SIGWINCH signal?\n");
		}
	}
	return 0;
}
