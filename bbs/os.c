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
 * \brief OS details
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h> /* use snprintf */
#include <string.h> /* use strerror */
#include <sys/utsname.h> /* use uname */

#include "include/os.h"

static char osver[96];

const char *bbs_get_osver(void)
{
	return osver;
}

int bbs_init_os_info(void)
{
	long unsigned int res;
	struct utsname buf;

	if (uname(&buf)) {
		bbs_error("uname: %s\n", strerror(errno));
		return -1;
	}

	res = snprintf(osver, sizeof(osver), "%s %s", buf.sysname, buf.release);
	if (res >= sizeof(osver)) {
		bbs_error("Truncation occured when trying to write %ld bytes\n", res);
		return -1;
	}
	bbs_debug(5, "OS info: %s\n", osver);
	return 0;
}
