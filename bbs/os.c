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
#include <sys/statvfs.h> /* use statvfs */

#include "include/os.h"

static char osver[96];

const char *bbs_get_osver(void)
{
	return osver;
}

int bbs_init_os_info(void)
{
	int res;
	struct utsname buf;

	if (uname(&buf)) {
		bbs_error("uname: %s\n", strerror(errno));
		return -1;
	}

	res = snprintf(osver, sizeof(osver), "%s %s", buf.sysname, buf.release);
	if (res >= (int) sizeof(osver)) {
		bbs_error("Truncation occured when trying to write %d bytes\n", res);
		return -1;
	}
	bbs_debug(5, "OS info: %s\n", osver);
	return 0;
}

long bbs_disk_bytes_free(void)
{
	struct statvfs stat;
	const char *path = "/"; /* Root partition */

	if (statvfs(path, &stat)) {
		bbs_error("statvfs failed: %s\n", strerror(errno));
		return -1;
	}

	return (long) (stat.f_bsize * stat.f_bavail); /* Return number of free bytes */
}
