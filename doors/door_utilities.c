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
#include <ctype.h>

#include "include/module.h"
#include "include/node.h"
#include "include/term.h"
#include "include/user.h"
#include "include/door.h"
#include "include/system.h"
#include "include/editor.h"

#include "include/mod_curl.h"

/*! \brief Calculator utility */
static int calc_exec(struct bbs_node *node, const char *args)
{
	int res = -1;
	int stdin[2], stdout[2];
	char buf[128]; /* How long are math equations really going to be? */

	UNUSED(args);

	if (eaccess("/usr/bin/bc", X_OK)) {
		/* If bc isn't available, can't proceed */
		bbs_error("/usr/bin/bc not found\n");
		return 0;
	}

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

	bbs_node_buffer(node);
	bbs_node_writef(node, "\r");
	for (;;) {
		struct bbs_exec_params x;
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
		char *argv[3] = { "bc", "-q", NULL }; /* -q = quiet: disable initial banner */
		bbs_node_writef(node, "EQ> ");
		res = bbs_node_read_line(node, MIN_MS(5), buf, sizeof(buf) - 2);
		if (res <= 0) {
			res = -1;
			break;
		}
		/* Allow quit... kind of important */
		if (s_strlen_zero(buf) || !strcasecmp(buf, "quit")) {
			res = 0;
			break;
		}
		res = (int) strlen(buf);
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
		EXEC_PARAMS_INIT_FD(x, stdin[0], stdout[1]);
		res = bbs_execvp(node, &x, "bc", argv);
#pragma GCC diagnostic pop
		if (res) {
			bbs_node_writef(node, "Execution Error\n");
			continue;
		}
		/* Read into the buffer */
		if (bbs_poll(stdout[0], 0) == 0) {
			bbs_warning("No data in pipe?\n");
			bbs_node_writef(node, "Execution Error\n");
			continue;
		}
		res = (int) read(stdout[0], buf, sizeof(buf) - 1);
		if (res <= 0) {
			bbs_error("read returned %d\n", res);
			res = 0;
			break;
		}
		buf[res] = '\0';
		/* Show the answer */
		bbs_debug(5, "Read '%s' from stdout pipe\n", buf);
		if (STARTS_WITH(buf, "(standard_in)")) { /* Syntax error or some other thingamajig */
			bbs_node_writef(node, "Syntax Error\n");
			continue;
		}
		bbs_node_writef(node, "%s", buf);
	}
	close(stdin[0]);
	close(stdin[1]);
	close(stdout[0]);
	close(stdout[1]);
	return res;
}

/*! \brief Dictionary utility */
static int dict_exec(struct bbs_node *node, const char *args)
{
	int res = -1;
	char buf[56]; /* Long enough for the longest word (reasonably) */

	UNUSED(args);

	bbs_node_clear_screen(node); /* Didn't really want to, but the pager will clear the screen anyways so this is consistent with that */

	bbs_node_writef(node, "\r");
	for (;;) {
		char url[256];
		struct pager_info pginfo;
		struct bbs_curl c = {
			.forcefail = 1,
		};

		bbs_node_buffer(node); /* The pager will disable buffering (including echo), so do this each loop */
		bbs_node_writef(node, "DICT> ");
		res = bbs_node_read_line(node, MIN_MS(5), buf, sizeof(buf) - 2);
		if (res <= 0) {
			res = -1;
			break;
		}
		res = 0;
		if (s_strlen_zero(buf)) { /* No empty words */
			continue;
		}
		/* Allow quit... kind of important */
		if (!strcasecmp(buf, "quit")) {
			res = 0;
			break;
		}

		/* Use the DICT protocol (RFC 2229) to look up the word. */
		memset(&c, 0, sizeof(c));
		snprintf(url, sizeof(url), "dict://dict.org/d:%s", buf);
		c.url = url;

		if (!bbs_curl_get(&c)) { /* This isn't an HTTP GET request, technically, but this works just fine for this */
			char *line, *resp = c.response;
			if (strlen_zero(resp)) {
				bbs_debug(2, "No response for '%s'?\n", buf);
				continue;
			}
			memset(&pginfo, 0, sizeof(pginfo));
			pginfo.header = NULL; /* No header is necessary, the output will repeat the word at the beginning */
			while ((line = strsep(&resp, "\n"))) {
				/* Just skip the first few lines, and the last - anything starting with a response code. (super primitive, but it works):
				 * 220 dict.dict.org dictd 1.12.1/rf on Linux 4.19.0-10-amd64 <auth.mime> <128117509.2275.1657921565@dict.dict.org>
				 * 250 ok
				 * 150 1 definitions retrieved
				 * 151 "hamburger" wn "WordNet (r) 3.0 (2006)"
				 * .....
				 * 250 ok [d/m/c = 1/0/16; 0.000r 0.000u 0.000s]
				 * 221 bye [d/m/c = 0/0/0; 0.000r 0.000u 0.000s]
				 */
				if (isdigit(*line) && isdigit(*(line + 1)) && isdigit(*(line + 2)) && isspace(*(line + 3))) {
					continue;
				}
				if (STARTS_WITH(line, ".\r")) {
					break; /* End of response */
				}
#define USE_PAGING
#ifdef USE_PAGING
				res = bbs_pager(node, &pginfo, MIN_MS(5), line, strlen(line));
				if (res) {
					break; /* Stop if anything exceptional happens */
				}
#else
				bbs_node_writef(node, "%s\n", line);
#endif
			}
			bbs_curl_free(&c);
			res = res < 0 ? -1 : 0;
		}
	}
	return res;
}

static int unload_module(void)
{
	bbs_unregister_door("calc");
	bbs_unregister_door("dict");
	return 0;
}

static int load_module(void)
{
	int res = 0;
	BBS_REQUIRE_EXTERNAL_PROGRAM("bc");
	res |= bbs_register_door("calc", calc_exec);
	res |= bbs_register_door("dict", dict_exec);
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_DEPENDENT("Utilities", "mod_curl.so");
