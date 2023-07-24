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
 * \brief Protocol-agnostic file transfer settings
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/config.h"
#include "include/transfer.h"
#include "include/node.h" /* for node->user */
#include "include/user.h"
#include "include/utils.h"

static char rootdir[84];
static int rootlen;
static int privs[5];
static int access_priv, download_priv, upload_priv, delete_priv, newdir_priv;
static int idletimeout;
static int max_upload_size;

const char *bbs_transfer_rootdir(void)
{
	return rootdir;
}

int bbs_transfer_timeout(void)
{
	return idletimeout;
}

int bbs_transfer_max_upload_size(void)
{
	return max_upload_size;
}

int bbs_transfer_operation_allowed(struct bbs_node *node, int operation, const char *diskpath)
{
	int required_priv;

	bbs_assert(IN_BOUNDS(operation, 0, (int) ARRAY_LEN(privs)));

	if (!strlen_zero(diskpath)) {
		char homedir[256];
		int len;
		/* If the operation is being done to something inside the user's home directory, it is ALWAYS allowed.
		 * i.e. even if a user cannot normally delete files in the transfer root, users can do whatever
		 * they like inside their home directories. */
		len = snprintf(homedir, sizeof(homedir), "%s/home/%d", bbs_transfer_rootdir(), bbs_user_is_registered(node->user) ? node->user->id : 0);
		if (!strncmp(diskpath, homedir, (size_t) len)) {
			bbs_debug(6, "Operation implicitly authorized since it's in the user's home directory\n");
			return 1;
		}
	}

	required_priv = privs[operation];
	return bbs_user_priv(node->user) >= required_priv;
}

int transfer_make_longname(const char *file, struct stat *st, char *buf, size_t len, int ftp)
{
	char ctimebuf[26]; /* 26 bytes is enough per ctime(3) */
	char *modtime;
	char *p = buf;
	mode_t mode = st->st_mode;

	/* Need 10 bytes for rwx, 10 bytes for first snprintf, 26-4 for ctime + filename */

	/* Directory? */
	*p++ = (mode & S_IFMT) == S_IFDIR ? 'd' : '-';

	/* User */
	*p++ = mode & 0400 ? 'r' : '-';
	*p++ = mode & 0200 ? 'w' : '-';
	*p++ = mode & 0100 ? mode & S_ISUID ? 's' : 'x' : '-';

	/* Group */
	*p++ = mode & 040 ? 'r' : '-';
	*p++ = mode & 020 ? 'w' : '-';
	*p++ = mode & 010 ? 'x' : '-';

	/* Other */
	*p++ = mode & 04 ? 'r' : '-';
	*p++ = mode & 02 ? 'w' : '-';
	*p++ = mode & 01 ? 'x' : '-';

	*p++ = ' ';

	p += snprintf(p, len - (size_t) (p - buf), "%3d %d %d %d", (int) st->st_nlink, (int) st->st_uid, (int) st->st_gid, (int) st->st_size);
	if (ftp) {
		struct tm tm;
		/* Times should be in UTC */
		gmtime_r(&st->st_mtime, &tm);
		modtime = asctime_r(&tm, ctimebuf);
	} else {
		modtime = ctime_r(&st->st_mtime, ctimebuf); /* ctime_r assumes ctimebuf is at least 26, there is no length argument. */
	}
	modtime += 4; /* Skip short day of week */
	bbs_strterm(modtime, '\n'); /* Strip trailing LF */
	if (ftp) {
		char *colon;
		/* For FTP, we don't want the seconds or FileZilla will treat part of the date as the filename. */
		colon = strrchr(modtime, ':');
		if (colon) {
			*colon = '\0';
		}
	}
	return snprintf(p, len - (size_t) (p - buf), " %s %s", modtime, file);
}

int bbs_transfer_home_dir(struct bbs_node *node, char *buf, size_t len)
{
	if (!bbs_user_is_registered(node->user)) {
		return -1;
	}
	if (!rootlen) {
		bbs_debug(3, "No transfer root directory is configured\n");
		return -1;
	}
	snprintf(buf, len, "%s/home/%d", rootdir, node->user->id);
	return bbs_ensure_directory_exists(buf);
}

/*! \note This implementation assumes the userpath is always a subset of the diskpath */
const char *bbs_transfer_get_user_path(struct bbs_node *node, const char *diskpath)
{
	const char *userpath = diskpath + rootlen;

	UNUSED(node); /* Might be used in the future, e.g. for home directories? */

	/* This isn't solely just to ensure that nothing funny is going on.
	 * If diskpath is shorter than rootdir for whatever reason,
	 * then userpath points to invalid memory, and we must not access it. */
	if (strncmp(diskpath, rootdir, (size_t) rootlen)) {
		bbs_warning("Disk path '%s' is outside of transfer root '%s'\n", diskpath, rootdir);
		return NULL;
	}

	userpath = S_OR(userpath, "/"); /* Corner case: for root, we need to manually add the / back */
	bbs_debug(5, "Client path is '%s'\n", userpath);
	return userpath;
}

/*! \note query and buf are probably aliased from the original parent call */
static int __transfer_set_path(struct bbs_node *node, const char *function, const char *query, const char *fullpath, char *buf, size_t len, int require_existence)
{
	const char *userpath = bbs_transfer_get_user_path(node, fullpath);
	/* If it's a home directory, dynamically create it if needed, since we can't expect that to exist automatically. */
	if (bbs_user_is_registered(node->user) && STARTS_WITH(userpath, "/home")) {
		char myhomedir[256];
		/* When accessing /home, or the user's home directory directly, if the user's home directory doesn't exist, create it. */
		snprintf(myhomedir, sizeof(myhomedir), "%s/%d", fullpath, node->user->id);
		if (!strcmp(userpath, "/home") || STARTS_WITH(fullpath, myhomedir)) {
			if (eaccess(myhomedir, R_OK)) {
				if (mkdir(myhomedir, 0600)) {
					bbs_error("mkdir(%s) failed: %s\n", myhomedir, strerror(errno));
				} else {
					bbs_verb(5, "Auto created home directory %s\n", myhomedir);
				}
			}
		}
	}

	/* Deny requests to navigate into other people's home directories. */
	if (STARTS_WITH(userpath, "/home") && strlen(userpath) > STRLEN("/home")) {
		const char *homedir = strchr(userpath + 1, '/');
		if (likely(homedir != NULL)) { /* If length is longer than /home, there should be another / */
			unsigned int user = (unsigned int) atoi(S_IF(homedir + 1));
			if (user && (!bbs_user_is_registered(node->user) || user != node->user->id)) {
				/* This is also hit when doing a directory listing, so this doesn't necessarily indicate user malfeasance */
				bbs_debug(3, "User not authorized for location: %s\n", fullpath);
				errno = EPERM;
				return -1;
			}
		}
	}

	if (require_existence && !bbs_file_exists(fullpath)) {
		bbs_debug(5, "Path %s does not exist\n", fullpath);
		errno = ENOENT;
		return -1; /* Doesn't exist, don't change the path. */
	} else if (strstr(fullpath, "..")) {
		bbs_warning("Attempt to access unsafe path '%s'\n", fullpath);
		errno = EPERM;
		return -1;
	}
	bbs_debug(3, "%s(%s) => '%s'\n", function, query, fullpath);
	safe_strncpy(buf, fullpath, len);
	return 0;
}

int __bbs_transfer_set_disk_path_absolute(struct bbs_node *node, const char *userpath, char *buf, size_t len, int mustexist)
{
	/*! \note Once home directory support is added, if trying to access another user's home directory, we should return EPERM (not ENOENT) */
	UNUSED(node); /* Might be used in the future, e.g. for home directories? */

	if (userpath && (strlen_zero(userpath) || !strcmp(userpath, ".") || !strcmp(userpath, "/"))) {
		safe_strncpy(buf, rootdir, len); /* The rootdir must exist. Well, if it doesn't, then nothing will work anyways. */
	} else {
		char tmp[256];
		int pathlen = !strlen_zero(userpath) ? (int) strlen(userpath) : 0;
		snprintf(tmp, sizeof(tmp), "%s%s", rootdir, S_IF(userpath));
		if (pathlen > 3) {
			/* e.g. for foobar/.. we want /.. */
			const char *end = userpath + pathlen - 3;
			if (!strcmp(end, "/..")) {
				/* SFTP will use /.. at the end of a path to go up one directory (~CDUP in FTP).
				 * Detect that and call bbs_transfer_set_disk_path_up when that happens. */
				return bbs_transfer_set_disk_path_up(node, tmp, buf, len);
			}
		}
		return __transfer_set_path(node, "disk_path_absolute", userpath, tmp, buf, len, mustexist);
	}
	return 0;
}

int __bbs_transfer_set_disk_path_relative(struct bbs_node *node, const char *current, const char *userpath, char *buf, size_t len, int mustexist)
{
	char tmp[256];
	const char *lastslash;
	int addslash = 1;

	UNUSED(node); /* Might be used in the future, e.g. for home directories? */

	/* If directory does not start with a /, then it's relative to the current directory.
	 * If it does, then it's absolute. */
	if (!strlen_zero(userpath) && *userpath == '/') {
		return __bbs_transfer_set_disk_path_absolute(node, userpath, buf, len, mustexist);
	}
	/* userpath will not begin with a / so we'll want to insert one there normally.
	 * However, if current ends in a slash, then we don't want to insert or we'll have a duplicate //
	 * Additionally, if current begins with a slash, then we should strip it to avoid a duplicate // there.
	 */
	lastslash = strrchr(current, '/');
	if (lastslash && !*(lastslash + 1)) {
		addslash = 0;
	}
	snprintf(tmp, sizeof(tmp), "%s/%s%s%s", rootdir, *current == '/' ? current + 1 : current, addslash ? "/" : "", S_IF(userpath));
	return __transfer_set_path(node, "disk_path_relative", userpath, tmp, buf, len, mustexist);
}

int bbs_transfer_set_disk_path_up(struct bbs_node *node, const char *diskpath, char *buf, size_t len)
{
	char tmp[256];
	char *end;

	UNUSED(node); /* Might be used in the future, e.g. for home directories? */

	/* Note that diskpath and buf might be the same pointer.
	 * We do not use diskpath at any point after buf is modified,
	 * so this is fine.
	 * In other words, these pointers could NOT be __restrict'ed,
	 * since they may alias! */

	safe_strncpy(tmp, diskpath, sizeof(tmp));
	end = strrchr(tmp, '/');
	if (!end) {
		bbs_error("Path '%s' contains no slashes?\n", diskpath);
		return -1;
	}
	*end++ = '\0';
	/* If the / is at the end, it doesn't count. Same with if /.. is at the end. */
	if (!*end || (!strlen_zero(end) && !strcmp(end, ".."))) {
		bbs_debug(7, "That didn't count, terminating the previous slash too: %s\n", tmp);
		end = strrchr(tmp, '/');
	}

	/* If the previous directory were just '/', then removing the last / could result
	 * in an empty string remaining.
	 * However, that would only happen if the transfer rootdir were actually / on disk,
	 * and hopefully nobody is too stupid to do that. */
	if (!end) {
		bbs_error("Path '%s' contains no slashes?\n", diskpath);
		return -1;
	}
	*end = '\0';

	bbs_debug(7, "final: %s\n", tmp);

	/* We must not allow anyone to escape out of the transfer directory! */
	if ((int) strlen(tmp) < rootlen) {
		bbs_warning("Attempt to navigate outside of rootdir: %s\n", tmp);
		return -1;
	}

	return __transfer_set_path(node, "disk_path_up", diskpath, tmp, buf, len, 0); /* Parent guaranteed to exist, so don't verify that it does, that's unnecessary. */
}

int bbs_transfer_available(void)
{
	return rootlen ? 1 : 0;
}

int bbs_transfer_config_load(void)
{
	char homedir[256];
	struct bbs_config *cfg = bbs_config_load("transfers.conf", 1); /* Load cached version, since multiple transfer protocols may use this config */

	if (!cfg) {
		return 0; /* Transfers will be disabled, but don't abort startup. */
	}

	idletimeout = 60000;
	max_upload_size = 10 * 1024 * 1024; /* 10 MB */
	if (!bbs_config_val_set_int(cfg, "transfers", "timeout", &idletimeout)) {
		idletimeout *= 1000; /* convert s to ms */
	}
	if (bbs_config_val_set_path(cfg, "transfers", "rootdir", rootdir, sizeof(rootdir))) { /* Must explicitly specify */
		bbs_error("No rootdir specified, transfers will be disabled\n");
		return 0; /* Transfers will be disabled, but don't abort startup. */
	}
	/* Auto create the root home dir if it doesn't exist already. */
	snprintf(homedir, sizeof(homedir), "%s/%s", rootdir, "home");
	if (eaccess(homedir, R_OK) && mkdir(homedir, 0600)) {
		bbs_error("mkdir(%s) failed: %s\n", homedir, strerror(errno));
		return -1;
	}

	bbs_config_val_set_int(cfg, "transfers", "maxuploadsize", &max_upload_size);
	rootlen = (int) strlen(rootdir);

	access_priv = 0;
	download_priv = 0;
	upload_priv = 1;
	delete_priv = 2;
	newdir_priv = 2;
	
	bbs_config_val_set_int(cfg, "privs", "access", &privs[TRANSFER_ACCESS]);
	bbs_config_val_set_int(cfg, "privs", "download", &privs[TRANSFER_DOWNLOAD]);
	bbs_config_val_set_int(cfg, "privs", "upload", &privs[TRANSFER_UPLOAD]);
	bbs_config_val_set_int(cfg, "privs", "delete", &privs[TRANSFER_NEWDIR]);
	bbs_config_val_set_int(cfg, "privs", "newdirs", &privs[TRANSFER_DESTRUCTIVE]);

	return 0;
}
