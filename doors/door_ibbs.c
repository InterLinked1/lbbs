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
 * \brief Telnet BBS Guide listing
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <unistd.h> /* use R_OK */

#include "include/module.h"
#include "include/node.h"
#include "include/door.h"
#include "include/term.h"
#include "include/curl.h"
#include "include/system.h"
#include "include/editor.h"

static int ibbs_exec(struct bbs_node *node, const char *args)
{
	time_t now;
    struct tm nowdate;
	char mmyy[5];
	char tmpzip[20];
	char mon[5];
	char listfile[48];

	UNUSED(args);

	now = time(NULL);
    localtime_r(&now, &nowdate);
#pragma GCC diagnostic ignored "-Wformat-y2k"
	strftime(mmyy, sizeof(mmyy), "%m%y", &nowdate); /* 2-digit month, 2-digit year */
	strftime(mon, sizeof(mon), "%b", &nowdate); /* For the target filename. The full listing is in full_Mon_Yr.txt */
#pragma GCC diagnostic pop

	snprintf(tmpzip, sizeof(tmpzip), "/tmp/ibbs%s.zip", mmyy);
	snprintf(listfile, sizeof(listfile), "/tmp/full_%s_%s.txt", mon, mmyy + 2);

	if (access(listfile, R_OK)) {
		char *const argv[] = { "unzip", tmpzip, "-d", "/tmp", NULL };
		if (access(tmpzip, R_OK)) {
			char url[54];
			struct bbs_curl c = {
				.url = url,
				.forcefail = 1,
			};
			/* File doesn't already exist. Download it. */
			snprintf(url, sizeof(url), "https://www.telnetbbsguide.com/bbslist/ibbs%s.zip", mmyy);
			if (bbs_curl_get_file(&c, tmpzip)) {
				return 0; /* Don't return -1 or the node will abort */
			}
			bbs_curl_free(&c); /* Technically, since we wrote to a file, there's nothing to free, but for consistency... */
		} /* else, ZIP already exists */

		/* Extract the files in the ZIP into the /tmp directory.
		 * Even though we have a handle to the node, pass NULL for node since we don't need to link STDIN/STDOUT to the unzip command.
		 * We just need it to execute, and this is more efficient (and safer!) than using system()
		 */
		if (bbs_execvpe_headless(node, "unzip", argv)) {
			return 0; /* Don't return -1 or the node will abort */
		} 
	} /* else, file already exists */

	return bbs_node_term_browse(node, listfile);
}

static int load_module(void)
{
	return bbs_register_door("telnetbbsguide", ibbs_exec);
}

static int unload_module(void)
{
	return bbs_unregister_door("telnetbbsguide");
}

BBS_MODULE_INFO_STANDARD("Telnet BBS Guide");
