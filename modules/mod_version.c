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
 * \brief Version Update Notifications
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>

#include "include/module.h"
#include "include/utils.h"

#include "include/mod_curl.h"

#define BBS_VERSION_SOURCE_FILE "https://raw.githubusercontent.com/InterLinked1/lbbs/master/include/version.h"

static pthread_t periodic_thread = 0;
static int nags = 0;

/*! \note Function name is intentionally brief to avoid looking messy in the console */
static void checkver(void)
{
	int major = -1, minor = -1, patch = -1;
	char *line, *lines;
	struct bbs_curl c = {
		.url = BBS_VERSION_SOURCE_FILE,
		.forcefail = 1,
	};

	if (bbs_curl_get(&c)) {
		return;
	}
	lines = c.response;
	while ((line = strsep(&lines, "\n"))) {
		if (!strncmp(line, "#define BBS_MAJOR_VERSION ", 26)) {
			line += 26;
			if (!strlen_zero(line)) {
				major = atoi(line);
			}
		} else if (!strncmp(line, "#define BBS_MINOR_VERSION ", 26)) {
			line += 26;
			if (!strlen_zero(line)) {
				minor = atoi(line);
			}
		} else if (!strncmp(line, "#define BBS_PATCH_VERSION ", 26)) {
			line += 26;
			if (!strlen_zero(line)) {
				patch = atoi(line);
			}
		}
	}
	bbs_curl_free(&c);

	if (major == -1 || minor == -1 || patch == -1) {
		bbs_warning("Failed to check current upstream BBS version (parsed %d.%d.%d)\n", major, minor, patch);
		return;
	}

	/* Only notify if upstream version is newer. If it's the same or older, don't care. */
	if (major > BBS_MAJOR_VERSION) {
		bbs_notice("A new major release of %s is available (%d.%d.%d available, currently running %s)\n", BBS_SHORTNAME, major, minor, patch, BBS_VERSION);
	} else if (minor > BBS_MINOR_VERSION && major >= BBS_MAJOR_VERSION) {
		bbs_notice("A new minor release of %s is available (%d.%d.%d available, currently running %s)\n", BBS_SHORTNAME, major, minor, patch, BBS_VERSION);
	} else if (patch > BBS_PATCH_VERSION && major >= BBS_MAJOR_VERSION && minor >= BBS_MINOR_VERSION) {
		bbs_notice("A new patch release of %s is available (%d.%d.%d available, currently running %s)\n", BBS_SHORTNAME, major, minor, patch, BBS_VERSION);
	} else {
		bbs_debug(1, "Upstream release %d.%d.%d <= ours (%s)\n", major, minor, patch, BBS_VERSION);
		return;
	}
	nags++;
}

static void *periodic_tasks(void *unused)
{
	UNUSED(unused);
	/*! \todo BUGBUG FIXME Shorter than a few seconds will cause test failure due to curl being active when cancelled?
	 * Would be better to have a function like bbs_waitfor_ms_or_shutdown()
	 * that can just return after some amount of time, or if the BBS is shutting down,
	 * and then we can wouldn't need to cancel it.
	 */
	usleep(5000000);
	for (;;) {
		/* Check if a newer version of the BBS is available */
		/* Only check once a day. */
		bbs_pthread_disable_cancel();
		checkver();
		bbs_pthread_enable_cancel();
		sleep(60 * 60 * 24); /* use sleep instead of usleep since the argument to usleep would overflow an int */
	}
	return NULL;
}

static int unload_module(void)
{
	bbs_pthread_cancel_kill(periodic_thread);
	bbs_pthread_join(periodic_thread, NULL);
	return 0;
}

static int load_module(void)
{
	return bbs_pthread_create(&periodic_thread, NULL, periodic_tasks, NULL);
}

BBS_MODULE_INFO_DEPENDENT("Version Update Notifications", "mod_curl.so");
