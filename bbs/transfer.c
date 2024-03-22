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
#include "include/system.h"

/*!
 * \note One thing I did not like about the original transfer implementation
 * is that the user-facing file paths must be a suffix of a path on disk;
 * in particular, for home directories, the user saw /home/$USERID,
 * instead of /home/$USERNAME, which is not very user-friendly,
 * and also leaks abstraction some, since users should not really
 * be concerned with their user IDs, which are more of an implementation detail.
 *
 * While it would be elegant to make use of namespaces and mounts,
 * we're running within the main BBS process, so we can't really
 * do stuff like that. Most FTP servers just chroot themselves,
 * so they don't really have to worry about converting back and forth
 * like that.
 *
 * So, we settle for just having some logic to convert between
 * /home/$USERNAME/stuff <-> /home/$USERID/stuff as needed.
 *
 * To restore the original behavior, undef FRIENDLY_PATHS
 * (though not sure why you'd want to do that, and that may break stuff!)
 *
 * Because it is necessary to have the public files not be in a prefix
 * of the home directory, those files are located at
 * /home/public <-> /home/0
 */

/* Display usernames in home directory paths instead of raw user IDs */
#define FRIENDLY_PATHS

static char rootdir[84];
static char publichomedir[92];
static char homedirtemplate[256];

static size_t rootlen;
static size_t publichomedirlen;

static int show_all_home_dirs = 0;

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

size_t bbs_transfer_max_upload_size(void)
{
	return (size_t) max_upload_size;
}

#define PATH_STARTS_WITH(p, s) (!strncmp(p, s, STRLEN(s)))

int bbs_transfer_show_all_home_dirs(void)
{
	return show_all_home_dirs;
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
		/* If it's not in the public home directory, then access denied! */
		if (strncmp(diskpath, publichomedir, publichomedirlen)) {
			len = snprintf(homedir, sizeof(homedir), "%s/home", bbs_transfer_rootdir());
			if (!strncmp(diskpath, homedir, (size_t) len)) {
				if (!bbs_transfer_show_all_home_dirs() || (operation == TRANSFER_UPLOAD || operation == TRANSFER_NEWDIR || operation == TRANSFER_DESTRUCTIVE)) {
					/* If not inside the user's home directory, reject the request.
					 * Logic elsewhere prevents accesing other users' home directories,
					 * but this is needed here to ensure that:
					 * - Users cannot delete other home directories
					 * - Users cannot delete the root /home/ directory (and everyone's home directories!)
					 * - Users cannot create directories inside the root /home/ directory
					 */
					bbs_debug(2, "Operation %d rejected for '%s', since it modifies or displays /home (root home directory)\n", operation, diskpath);
					return 0;
				}
			}
		}
	}

	required_priv = privs[operation];
	bbs_debug(9, "Operation %d allowed for '%s'\n", operation, diskpath);
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

	/*! \note The uid/gid are not meaningful to users.
	 * It would be better to use the BBS username, particularly for a user's own files;
	 * however, there aren't user accounts on the system itself for each user,
	 * so we don't have a way to store that in the file attributes.
	 *
	 * In the meantime, we may want to just output 0 for both uid and gid,
	 * instead of outputting the actual values...
	 */

#ifdef OUTPUT_REAL_UIDS_GIDS
	p += snprintf(p, len - (size_t) (p - buf), "%3d %d %d %d", (int) st->st_nlink, (int) st->st_uid, (int) st->st_gid, (int) st->st_size);
#else
	p += snprintf(p, len - (size_t) (p - buf), "%3d %d %d %d", 0, 0, (int) st->st_gid, (int) st->st_size);
#endif
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

static int recursive_copy(const char *srcfiles, const char *dest)
{
	/* It can probably do a better job than we can */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored "-Wcast-qual"
	/* no clobber, just in case it already existed (which it shouldn't, but just supposing),
	 * we don't want to overwrite all the user's existing files. */
	char *const argv[] = { "cp", "-r", "-n", (char*) srcfiles, (char*) dest, NULL };
#pragma GCC diagnostic pop
	return bbs_execvp(NULL, argv[0], argv);
}

int bbs_transfer_home_dir(unsigned int userid, char *buf, size_t len)
{
	if (!rootlen) {
		bbs_debug(3, "No transfer root directory is configured\n");
		return -1;
	}
	snprintf(buf, len, "%s/home/%d", rootdir, userid);
	if (eaccess(buf, R_OK | X_OK)) {
		char srcfiles[258];
		if (bbs_ensure_directory_exists(buf)) { /* Autocreate directory structure */
			return -1;
		}
		/* We just created the user's home directory.
		 * Copy the template files in. */
		if (userid > 0 && !s_strlen_zero(homedirtemplate)) {
			bbs_verb(5, "Initializing home directory %s from template directory %s\n", buf, homedirtemplate);
			/* It's kind of weird, to copy the contents OF a directory,
			 * when the destination already exists, you have to use ., not * */
			snprintf(srcfiles, sizeof(srcfiles), "%s/.", homedirtemplate);
			recursive_copy(srcfiles, buf);
		}
	}
	return 0;
}

int bbs_transfer_home_dir_cd(struct bbs_node *node, char *buf, size_t len)
{
	if (!bbs_user_is_registered(node->user)) {
		return -1;
	}
	/* Initialize if needed */
	return bbs_transfer_home_dir(node->user->id, buf, len);
}

int bbs_transfer_home_dir_init(struct bbs_node *node)
{
	char homedir[256];
	/* It might seem funny that the "initialize" logic
	 * uses the cd logic internally, but this is because
	 * the only real concept of "current directory"
	 * is whatever path is stored in the directory buffer
	 * of the network protocol driver handling the transfers
	 * (e.g. net_ftp).
	 *
	 * To initialize, we simply pass in a buffer that is discarded. */
	return bbs_transfer_home_dir_cd(node, homedir, sizeof(homedir));
}

int bbs_transfer_set_default_dir(struct bbs_node *node, char *buf, size_t len)
{
	if (bbs_transfer_home_dir_cd(node, buf, len)) {
		/* Must not be authenticated, just use the transfer root */
		safe_strncpy(buf, bbs_transfer_rootdir(), len);
	}
	bbs_verb(4, "Setting current directory to '%s'\n", buf);
	return 0;
}

int bbs_transfer_home_config_dir(unsigned int userid, char *buf, size_t len)
{
	if (bbs_transfer_home_dir(userid, buf, len)) {
		return -1;
	}
	/* XDG Base Directory Specification says user config files should go in ~/.config,
	 * so we use the same convention here
	 * $XDG_CONFIG_HOME
	 * https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
	 *
	 * Some user-related things, like Sieve/MailScript rules, still go in other places,
	 * like the user's maildir.
	 */
	snprintf(buf, len, "%s/home/%d/.config", rootdir, userid);
	return bbs_ensure_directory_exists(buf);
}

int bbs_transfer_home_config_subdir(unsigned int userid, const char *dir, char *buf, size_t len)
{
	/* Do not autocreate home directory, or any parent directories, or anything else */
	snprintf(buf, len, "%s/home/%d/%s", rootdir, userid, dir);
	return 0;
}

int bbs_transfer_home_config_file(unsigned int userid, const char *name, char *buf, size_t len)
{
	if (bbs_transfer_home_config_dir(userid, buf, len)) {
		return -1;
	}
	snprintf(buf, len, "%s/home/%d/.config/%s", rootdir, userid, name);
	return !bbs_file_exists(buf);
}

int bbs_transfer_get_user_path(struct bbs_node *node, const char *diskpath, char *buf, size_t len)
{
	const char *userpath = diskpath + rootlen;
	const char *p;
	char *origbuf = buf;

	UNUSED(node);

	*buf = '\0';

	/* This isn't solely just to ensure that nothing funny is going on.
	 * If diskpath is shorter than rootdir for whatever reason,
	 * then userpath points to invalid memory, and we must not access it. */
	if (strncmp(diskpath, rootdir, rootlen)) {
		bbs_error("Disk path '%s' is outside of transfer root '%s'\n", diskpath, rootdir);
		return -1;
	}

#ifdef FRIENDLY_PATHS
	if (PATH_STARTS_WITH(userpath, "/home/")) {
		int bytes;
		const char *tmp;
		p = userpath + STRLEN("/home/");
		bytes = snprintf(buf, len, "/home/");
		if (bytes >= (int) len) {
			return -1;
		}
		buf += bytes;
		len -= (size_t) bytes;
		if (!strlen_zero(p)) {
			int userid = atoi(p);
			if (userid < 0) {
				bbs_error("No user with user ID %d", userid);
				return -1;
			}
			if (userid == 0) {
				bytes = snprintf(buf, len, "public");
			} else {
				bbs_lowercase_username_from_userid((unsigned int) userid, buf, len);
				bytes = (int) strlen(buf);
			}
			buf += bytes;
			len -= (size_t) bytes;
			/* Anything after the home directory path */
			tmp = strchr(p, '/');
			if (tmp) {
				safe_strncpy(buf, tmp, len);
			}
		}
	} else
#endif
	{
		/* This assumes userpath is always a subset of the diskpath */
		p = S_OR(userpath, "/"); /* Corner case: for root, we need to manually add the / back */
		bbs_debug(5, "Client path is '%s'\n", p);
		safe_strncpy(buf, p, len);
	}
	bbs_debug(2, "Translated disk path '%s' -> user path '%s'\n", diskpath, origbuf);
	return 0;
}

/*!
 * \brief "Change directories" by constructing a new file path
 * \param node
 * \param function Name of calling function, for logging purposes
 * \param query User-facing directory query, for logging purposes
 * \param fullpath The new full disk path
 * \param[out] buf
 * \param len
 * \param require_existence Return error (ENOENT) if path does not exist already
 * \retval 0 on success ("directory changed", i.e. copied to buf)
 * \retval -1 on error, with errno set appropriately
 * \note query and buf are probably aliased from the original parent call (e.g. for bbs_transfer_set_disk_path_up)
 */
static int __transfer_set_path(struct bbs_node *node, const char *function, const char *query, const char *fullpath, char *buf, size_t len, int require_existence)
{
	const char *p = fullpath + rootlen; /* Skip root prefix */

	if (strncmp(fullpath, rootdir, rootlen)) {
		bbs_error("Requested directory is outside of transfer root: %s\n", fullpath);
		return -1;
	}

	if (PATH_STARTS_WITH(p, "/home")) {
		char homedir[256] = "";
		/* Make sure our home directory exists, in case it doesn't already, since we want it to show in the directory listing. */
		if (bbs_user_is_registered(node->user)) {
			bbs_transfer_home_dir_cd(node, homedir, sizeof(homedir));
		}

		/* Only allow accesses to the user's own home directory, or the public home directory, not anyone else's. */
		p += STRLEN("/home");
		if (!strlen_zero(p)) {
			p++; /* Skips /home/ */
			if (!strlen_zero(p)) {
				if (strncasecmp(fullpath, publichomedir, publichomedirlen)) {
					/* This is also hit when doing a directory listing, so this doesn't necessarily indicate user malfeasance.
					 * This will also have the effect of hiding directories a user is not authorized to access. */
					if (!bbs_user_is_registered(node->user)) {
						bbs_debug(3, "User not authorized for location(%s): %s (home dir: %s)\n", function, fullpath, homedir);
						errno = EPERM;
						return -1;
					}
					if (strncasecmp(fullpath, homedir, strlen(homedir))) {
						bbs_debug(3, "User not authorized for location(%s): %s (home dir: %s)\n", function, fullpath, homedir);
						errno = EPERM;
						return -1;
					}
					p = fullpath + strlen(homedir);
					if (*p && *p != '/') {
						/* Say we have /home/11... our home dir is /home/1,
						 * but that shouldn't count as a prefix of /home/11.
						 * It needs to be either just /home/11, or home/11/ followed by more stuff. */
						bbs_debug(3, "User not authorized for location(%s): %s (home dir: %s)\n", function, fullpath, homedir);
						errno = EPERM;
						return -1;
					}
				}
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

/*!
 * \brief Append the user part of the path to form a full disk path (this allows taking a user path argument and using it construct a full disk path)
 * \param userpath User path
 * \param[out] buf
 * \param len. Size of buf. Please try to make it larger than any buffers used in userspace modules.
 * \note This function works, almost surprisingly, but it's rather hard to follow. Possible improvement would be more logically easy to follow code,
 *       even if that means we do more copying to make it more readable.
 */
static int append_userpath_to_diskpath(const char *userpath, const char *olduserpath, char *buf, size_t len)
{
	unsigned int userid;
	int tmplen;
	char username[256];
	char *tmporig = buf;
	const char *p;

	/* In case we don't append anything */
	*buf = '\0';

	/* If olduserpath is empty, we're concatenating for an absolute path,
	 * so /home/ would be at the beginning of userpath, if present.
	 *
	 * For relative paths, we may have a non-empty olduserpath,
	 * in which case we need to process that first.
	 * Remember, we stripped the leading / from it, if there was one. */
	if (!strlen_zero(olduserpath)) {
		if (*olduserpath != '/') {
			/* If no slash to start, add one */
			bbs_debug(8, "Didn't begin with slash, adding one\n");
			*buf++ = '/';
			len--;
		} else {
			*buf++ = '/';
			len--;
			olduserpath++;
		}
		if (PATH_STARTS_WITH(olduserpath, "home/")) {
			p = olduserpath + STRLEN("home/");
			if (!strlen_zero(p)) {
				bbs_strncpy_until(username, p, sizeof(username), '/');
				if (!strcmp(username, "public")) {
					userid = 0;
				} else {
					userid = bbs_userid_from_username(username);
					if (userid < 1) {
						bbs_debug(1, "No such username '%s'\n", username);
						return -1;
					}
				}
				/* else, replace it, we don't care about permissions here */
				tmplen = snprintf(buf, len, "home/%u", userid);
				olduserpath += STRLEN("home/");
				olduserpath = strchr(olduserpath, '/'); /* Skip user and go to remainder, if any */
				if (tmplen >= (int) len) {
					bbs_error("Truncation occured\n");
					return -1;
				}
				buf += tmplen;
				len -= (size_t) tmplen;
				bbs_debug(8, "Translated username %s to user ID %u\n", username, userid);
			}
		}
	}
	if (!strlen_zero(olduserpath)) {
		tmplen = snprintf(buf, len, "%s", olduserpath);
		buf += tmplen;
		len -= (size_t) tmplen;
	}

	if (len <= 1) {
		bbs_error("Buffer exhausted\n");
		return -1;
	}

	if (buf > tmporig + 1) { /* Did we add anything so far? */
		/* If it didn't end in a slash, add one before continuing */
		const char *lastslash = strrchr(tmporig, '/');
		if (!lastslash || *(lastslash + 1)) {
			/* What we got doesn't end in a slash, so add one at the end,
			 * before adding more stuff (which presumably does NOT begin
			 * with a slash). */
			bbs_debug(8, "Doesn't end in a slash, adding one\n");
			*buf++ = '/';
			len--;
		}
		*buf = '\0';
	}

	*buf = '\0'; /* If the last thing we did was assign to *buf++, it may not be NUL terminated right now */

	/* Second thing to append and translate */
	if (!strlen_zero(userpath)) {
		p = userpath;
		if (!olduserpath && PATH_STARTS_WITH(userpath, "/home/")) {
			p += STRLEN("/home/");
			tmplen = snprintf(buf, len, "/home/");
			buf += tmplen;
			len -= (size_t) tmplen;
		}
		/* In this case, also ignore if ends in "/.", we'll remove that below. This only applies to SFTP. */
		if (!strlen_zero(p) && !strcmp(tmporig, "/home/") && strcmp(p, ".")) { /* If all we've got so far is /home/, what follows must be the username that needs conversion to a user ID */
			bbs_strncpy_until(username, p, sizeof(username), '/');
			if (!strcmp(username, "public")) {
				userid = 0;
			} else {
				userid = bbs_userid_from_username(username);
				if (userid < 1) {
					bbs_debug(1, "No such username '%s'\n", username);
					return -1;
				}
			}
			/* else, replace it, we don't care about permissions here */
			tmplen = snprintf(buf, len, "%u", userid);
			p = strchr(p, '/'); /* Skip user and go to remainder, if any */
			if (tmplen >= (int) len) {
				bbs_error("Truncation occured\n");
				return -1;
			}
			buf += tmplen;
			len -= (size_t) tmplen;
			bbs_debug(8, "Translated username %s to user ID %u\n", username, userid);
		}
		if (!strlen_zero(p)) {
			/* Copy anything left */
			safe_strncpy(buf, p, len);
			buf += strlen(p);
			len -= strlen(p);
		}
	}

	if (len <= 1) {
		bbs_error("Buffer exhausted\n");
		return -1;
	}

	if (buf > tmporig + 1 && *(buf - 1) == '.' && *(buf - 2) == '/') {
		/* If there's a trailing /. (from SFTP), remove that,
		 * since that will cause issues and is the same path without that bit. */
		bbs_debug(8, "Removing trailing '/.' from path\n");
		buf -= 2;
		len += 2;
	}

	 /* If the last thing we did was assign to *buf++, it may not be NUL terminated anymore, fix that.
	  * Keep this in mind if debugging by dumping out intermediate values above! */
	*buf = '\0';
	return 0;
}

int __bbs_transfer_set_disk_path_absolute(struct bbs_node *node, const char *userpath, char *buf, size_t len, int mustexist)
{
	if (userpath && (strlen_zero(userpath) || !strcmp(userpath, ".") || !strcmp(userpath, "/"))) {
		safe_strncpy(buf, rootdir, len); /* The rootdir must exist. Well, if it doesn't, then nothing will work anyways. */
	} else {
		char tmp[512];
		int pathlen = !strlen_zero(userpath) ? (int) strlen(userpath) : 0;
		int tmplen = snprintf(tmp, sizeof(tmp), "%s", rootdir);
		if (append_userpath_to_diskpath(userpath, NULL, tmp + tmplen, sizeof(tmp) - (size_t) tmplen)) {
			errno = ENOENT; /* Just pick something */
			return -1;
		}
		if (pathlen > 3) { /* Special case... check for go up one directory */
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
	char tmp[512];
	int tmplen;

	bbs_debug(3, "Relative path request: current '%s', differential '%s'\n", current, userpath);

	/* If directory does not start with a /, then it's relative to the current directory.
	 * If it does, then it's absolute. */
	if (!strlen_zero(userpath) && *userpath == '/') {
		return __bbs_transfer_set_disk_path_absolute(node, userpath, buf, len, mustexist);
	}

	tmplen = snprintf(tmp, sizeof(tmp), "%s", rootdir);
	if (append_userpath_to_diskpath(userpath, current, tmp + tmplen, sizeof(tmp) - (size_t) tmplen)) {
		errno = ENOENT; /* Just pick something */
		return -1;
	}
	bbs_debug(3, "Relative path request: current '%s', differential '%s' -> '%s'\n", current, userpath, tmp);
	return __transfer_set_path(node, "disk_path_relative", userpath, tmp, buf, len, mustexist);
}

int bbs_transfer_set_disk_path_up(struct bbs_node *node, const char *diskpath, char *buf, size_t len)
{
	char tmp[256];
	char *end;

	/* Note that diskpath and buf might be the same pointer.
	 * We do not use diskpath at any point after buf is modified,
	 * so this is fine.
	 * In other words, these pointers could NOT be __restrict'ed,
	 * since they may alias! */

	safe_strncpy(tmp, diskpath, sizeof(tmp));
	end = strrchr(tmp, '/');
	if (!end) {
		bbs_error("Path '%s' contains no slashes?\n", diskpath);
		errno = ENOENT;
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
		errno = ENOENT;
		return -1;
	}
	*end = '\0';

	bbs_debug(7, "final: %s\n", tmp);

	/* We must not allow anyone to escape out of the transfer directory! */
	if (strlen(tmp) < rootlen) {
		bbs_warning("Attempt to navigate outside of rootdir: %s\n", tmp);
		errno = ENOENT;
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
	if (bbs_ensure_directory_exists(homedir)) {
		return -1;
	}

	/* Template dir */
	if (bbs_config_val_set_path(cfg, "transfers", "homedirtemplate", homedirtemplate, sizeof(homedirtemplate))) {
		homedirtemplate[0] = '\0';
	}

	bbs_config_val_set_true(cfg, "transfers", "show_all_home_dirs", &show_all_home_dirs);
	bbs_config_val_set_int(cfg, "transfers", "maxuploadsize", &max_upload_size);
	rootlen = strlen(rootdir);

	bbs_transfer_home_dir(0, publichomedir, sizeof(publichomedir));
	publichomedirlen = strlen(publichomedir);
	bbs_assert(publichomedirlen > rootlen);

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
