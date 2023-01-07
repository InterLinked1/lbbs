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
 * \brief Utilities
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/module.h"
#include "include/node.h"
#include "include/term.h"
#include "include/user.h"
#include "include/door.h"
#include "include/system.h"

/*! \brief Calculator utility */
static int calc_exec(struct bbs_node *node, const char *args)
{
	int res = -1;
	int stdin[2], stdout[2];
	char buf[128]; /* How long are math equations really going to be? */

	UNUSED(args);

	if (eaccess("/usr/bin/bc", R_OK)) {
		/* If bc isn't available, can't proceed */
		bbs_error("/usr/bin/bc not found\n");
		return 0;
	}

#if 0
	/* Just use the bc shell */
	char *argv[3] = { "bc", "-q", NULL }; /* -q = quiet: disable initial banner */
	return bbs_execvpe(node, "bc", argv);
#endif

	/* Create a pipe for passing input and output to/from bc */
	if (pipe(stdin)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return 0;
	} else if (pipe(stdout)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		/* Log first, since close may change errno */
		close(stdin[0]);
		close(stdin[1]);
		return 0;
	}

	bbs_buffer(node);
	bbs_writef(node, "\r");
	for (;;) {
		char *argv[3] = { "bc", "-q", NULL }; /* -q = quiet: disable initial banner */
		bbs_writef(node, "EQ> ");
		res = bbs_readline(node, MIN_MS(5), buf, sizeof(buf) - 2);
		if (res <= 0) {
			res = -1;
			break;
		}
		/* Allow quit... kind of important */
		if (s_strlen_zero(buf) || !strcasecmp(buf, "quit")) {
			res = 0;
			break;
		}
		res = strlen(buf);
		buf[res++] = '\n'; /* bc must get a LF to terminate command */
		buf[res++] = '\0';
		/* This is basically echo "scale=3; $buf" | bc
		 * Except, we don't massively open ourselves up to shell injection from user input. */
		if (SWRITE(stdin[1], "scale=3; ") < 0) {
			bbs_error("write failed: %s\n", strerror(errno));
			continue;
		} else if (write(stdin[1], buf, strlen(buf)) < 0) {
			bbs_error("write failed: %s\n", strerror(errno));
			continue;
		}
		/* In theory, this shouldn't be necessary, but for some reason,
		 * bc thinks we're interactive STDIN, and it'll wait forever for a quit command,
		 * just like in an interactive session.
		 * So in addition to LF, send it quit LF to make sure we don't hang. */
		if (SWRITE(stdin[1], "quit\n") < 0) {
			bbs_error("write failed: %s\n", strerror(errno));
			continue;
		}
		res = bbs_execvpe_fd_headless(node, stdin[0], stdout[1], "bc", argv);
		if (res) {
			bbs_writef(node, "Execution Error\n");
			continue;
		}
		/* Read into the buffer */
		if (bbs_std_poll(stdout[0], 0) == 0) {
			bbs_warning("No data in pipe?\n");
			bbs_writef(node, "Execution Error\n");
			continue;
		}
		res = read(stdout[0], buf, sizeof(buf) - 1);
		if (res <= 0) {
			bbs_error("read returned %d\n", res);
			res = 0;
			break;
		}
		buf[res] = '\0';
		/* Show the answer */
		bbs_debug(5, "Read '%s' from stdout pipe\n", buf);
		if (STARTS_WITH(buf, "(standard_in)")) { /* Syntax error or some other thingamajig */
			bbs_writef(node, "Syntax Error\n");
			continue;
		}
		bbs_writef(node, "%s", buf);
	}
	close(stdin[0]);
	close(stdin[1]);
	close(stdout[0]);
	close(stdout[1]);
	return res;
}

static int load_module(void)
{
	return bbs_register_door("calc", calc_exec);
}

static int unload_module(void)
{
	return bbs_unregister_door("calc");
}

BBS_MODULE_INFO_STANDARD("Utilities");
