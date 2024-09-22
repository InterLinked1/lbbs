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
 * \brief RFC5804 ManageSieve protocol
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/user.h"
#include "include/auth.h"
#include "include/mail.h"

#include "include/mod_mail.h"

/* ManageSieve TCP port */
#define DEFAULT_SIEVE_PORT 4190 

static int sieve_port = DEFAULT_SIEVE_PORT;

struct sieve_session {
	int rfd;
	int wfd;
	struct bbs_node *node;
	struct mailbox *mbox;
	FILE *fp;
	char *scriptname;
	char template[32];
	long unsigned int quotaleft;
	unsigned int uploadsofar;
	unsigned int uploadexpected;
	unsigned int dostarttls:1;
};

static void sieve_cleanup(struct sieve_session *sieve)
{
	free_if(sieve->scriptname);
	if (sieve->fp) {
		fclose(sieve->fp);
		sieve->fp = NULL;
		unlink(sieve->template);
	}
}

#define sieve_send(sieve, fmt, ...) bbs_node_fd_writef(sieve->node, sieve->wfd, fmt "\r\n", ## __VA_ARGS__); bbs_debug(5, "%p <= " fmt "\n", sieve, ## __VA_ARGS__);

static int handle_capability(struct sieve_session *sieve)
{
	/* Send capabilities immediately */
	char *caps = sieve_get_capabilities();
	if (!caps) {
		bbs_warning("No Sieve capabilities available\n");
		return -1;
	}
	sieve_send(sieve, "\"SIEVE\" \"%s\"", caps);
	free(caps);
	sieve_send(sieve, "\"VERSION\" \"1.0\"");
	if (!sieve->node->secure) {
		sieve_send(sieve, "\"STARTTLS\"");
	}
	sieve_send(sieve, "\"SASL\" \"PLAIN\"");
	sieve_send(sieve, "\"IMPLEMENTATION\" \"%s %s\"", BBS_SHORTNAME, BBS_VERSION);
	sieve_send(sieve, "OK");
	return 0;
}

#define REQUIRE_ARGS(s) if (strlen_zero(s)) { sieve_send(sieve, "BAD Missing argument"); return 0; }
#define REQUIRE_AUTH() if (!bbs_user_is_registered(sieve->node->user)) { sieve_send(sieve, "NO Not logged in"); return 0; }

#define SHIFT_OPTIONALLY_QUOTED_ARG(assign, s) \
	REQUIRE_ARGS(s); \
	if (*s == '"') { \
		s++; \
		assign = s; \
		s = strchr(s, '"'); \
		REQUIRE_ARGS(s); \
		*s++ = '\0'; \
		if (*s) { \
			s++; \
		} \
	} else { \
		assign = strsep(&s, " "); \
		STRIP_QUOTES(assign); \
	}

static int sieve_script_name_to_path_noexist(struct sieve_session *sieve, const char *s, char *buf, size_t len)
{
	if (strstr(s, "..")) {
		return -1;
	}
	snprintf(buf, len, "%s/%s.sieve", mailbox_maildir(sieve->mbox), s);
	return 0;
}

static int sieve_script_name_to_path(struct sieve_session *sieve, const char *s, char *buf, size_t len)
{
	if (strstr(s, "..")) {
		return -1;
	}
	snprintf(buf, len, "%s/%s.sieve", mailbox_maildir(sieve->mbox), s);
	if (!bbs_file_exists(buf)) {
		return 1;
	}
	return 0;
}

static int putscript_helper(struct sieve_session *sieve, char *s, int put)
{
	char *name = NULL; /* Can't be used uninitialized, but make gcc happy */
	char *literal;
	unsigned int bytes;
	char putpath[256];
	REQUIRE_AUTH();
	REQUIRE_ARGS(s);
	if (put) {
		SHIFT_OPTIONALLY_QUOTED_ARG(name, s);
		REQUIRE_ARGS(s);
	}
	literal = s;
	if (*literal != '{') {
		bbs_error("Unexpected token: %s\n", literal);
		sieve_send(sieve, "BAD Invalid");
		return 0;
	}
	literal++;
	bytes = (unsigned int) atoi(literal);
	if (!bytes) {
		sieve_send(sieve, "BAD \"Invalid length\"");
		return 0;
	}
	if (put && sieve_script_name_to_path_noexist(sieve, name, putpath, sizeof(putpath))) {
		sieve_send(sieve, "NO \"Invalid name\"\n");
		return 0;
	}
	/* A non-synchronizing litereal is used for ManageSieve
	 * (also possible with IMAP, but not required for a server to support that).
	 * This means the input follows, and in fact may already be in the readline
	 * buffer. */
	strcpy(sieve->template, "/tmp/sieveputXXXXXX");
	sieve->fp = bbs_mkftemp(sieve->template, 0600);
	sieve->uploadexpected = bytes + 2; /* Add 2 for the final CR LF */
	sieve->uploadsofar = 0;
	sieve->quotaleft = mailbox_quota_remaining(sieve->mbox);
	if (put) {
		sieve->scriptname = strdup(putpath);
	}
	if (!sieve->fp) {
		sieve_send(sieve, "BAD \"Server error\"");
	}
	return 0;
}

static int sieve_process(struct sieve_session *sieve, char *s)
{
	char *command;

	if (sieve->fp) {
		char *errormsg = NULL;
		/* Just finished a file upload. */
		fclose(sieve->fp);
		sieve->fp = NULL;
		/* Check its validity */
		if (sieve_validate_script(sieve->template, sieve->mbox, &errormsg)) {
			sieve_send(sieve, "NO \"%s\"", S_IF(errormsg));
			unlink(sieve->template);
		} else {
			/* If we're good to go, rename the file if we have a target. */
			if (sieve->scriptname) { /* PUTSCRIPT (but not CHECKSCRIPT) */
				if (rename(sieve->template, sieve->scriptname)) {
					bbs_error("rename %s -> %s failed\n", sieve->template, sieve->scriptname);
					sieve_send(sieve, "NO \"Server error\"");
					goto doneupload;
				}
			}
			sieve_send(sieve, "OK");
		}
doneupload:
		free_if(errormsg);
		free_if(sieve->scriptname);
		return 0;
	}

	command = strsep(&s, " ");

	if (!strcasecmp(command, "CAPABILITY")) {
		return handle_capability(sieve);
	} else if (!strcasecmp(command, "AUTHENTICATE")) {
		if (bbs_user_is_registered(sieve->node->user)) {
			sieve_send(sieve, "NO Already logged in");
			return 0;
		}
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		REQUIRE_ARGS(s);
		STRIP_QUOTES(command);
		if (!strcasecmp(command, "PLAIN")) {
			int res;
			unsigned char *decoded;
			char *authorization_id, *authentication_id, *password;

			STRIP_QUOTES(s);
			decoded = bbs_sasl_decode(s, &authorization_id, &authentication_id, &password);
			if (!decoded) {
				sieve_send(sieve, "NO Authentication failed");
				return -1;
			}

			/* Can't use bbs_sasl_authenticate directly since we need to strip the domain */
			bbs_strterm(authentication_id, '@');
			res = bbs_authenticate(sieve->node, authentication_id, password);
			bbs_memzero(password, strlen(password)); /* Destroy the password from memory before we free it */
			free(decoded);

			if (res) {
				sieve_send(sieve, "NO Authentication failed");
			} else {
				sieve->mbox = mailbox_get_by_userid(sieve->node->user->id);
				sieve_send(sieve, "OK");
			}
		} else {
			sieve_send(sieve, "NO Unsupported auth method");
		}
	} else if (!strcasecmp(command, "STARTTLS")) {
		sieve_send(sieve, "OK");
		sieve->dostarttls = 1;
	} else if (!strcasecmp(command, "NOOP")) {
		sieve_send(sieve, "OK \"NOOP completed\"");
	} else if (!strcasecmp(command, "UNAUTHENTICATE")) {
		if (!bbs_user_is_registered(sieve->node->user)) {
			sieve_send(sieve, "NO Must be authenticated");
			return 0;
		}
		bbs_node_logout(sieve->node);
		sieve_send(sieve, "OK");
	} else if (!strcasecmp(command, "LOGOUT")) {
		sieve_send(sieve, "OK");
		return -1;
	} else if (!strcasecmp(command, "HAVESPACE")) {
		unsigned int scriptsize;
		command = strsep(&s, " ");
		REQUIRE_AUTH();
		REQUIRE_ARGS(command);
		s = strsep(&s, " "); /* Ignore the script name */
		REQUIRE_ARGS(s);
		scriptsize = (unsigned int) atoi(s);
		if (mailbox_quota_remaining(sieve->mbox) < scriptsize) {
			sieve_send(sieve, "NO (QUOTA/MAXSIZE) \"Quota exceeded\"");
		} else {
			sieve_send(sieve, "OK");
		}
	} else if (!strcasecmp(command, "LISTSCRIPTS")) {
		DIR *dir;
		char activescript[256];
		char activescriptpath[PATH_MAX];
		struct dirent *entry;
		const char *activebase = NULL;
		ssize_t res;

		REQUIRE_AUTH();
		if (!(dir = opendir(mailbox_maildir(sieve->mbox)))) {
			bbs_error("Error opening directory - %s: %s\n", mailbox_maildir(sieve->mbox), strerror(errno));
			return -1;
		}

		snprintf(activescript, sizeof(activescript), "%s/.sieve", mailbox_maildir(sieve->mbox));
		res = readlink(activescript, activescriptpath, sizeof(activescriptpath) - 1);
		if (res > 0 && res < (ssize_t) sizeof(activescriptpath) - 1) { /* There is an active script (symlink exists) */
			activescriptpath[res] = '\0'; /* readlink does not NULL terminate */
			activebase = strrchr(activescriptpath, '/');
			if (activebase) {
				activebase++;
			}
		}

		while ((entry = readdir(dir)) != NULL) {
			char *end;
			int active;
			if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
				continue;
			}
			end = strstr(entry->d_name, ".sieve"); /* Look for files ending in .sieve extension */
			if (!end) {
				continue;
			}
			if (*(end + STRLEN(".sieve"))) {
				/* It contains .sieve but there's something after that? */
				continue;
			}
			/* Don't include the .sieve suffix, by printing only the name part length */
			active = activebase && !strcmp(activebase, entry->d_name);
			sieve_send(sieve, "\"%.*s\"%s", (int) (end - entry->d_name), entry->d_name, active ? " ACTIVE" : "");
		}

		closedir(dir);
		sieve_send(sieve, "OK");
	} else if (!strcasecmp(command, "SETACTIVE")) {
		char activescript[256];
		char activescriptpath[PATH_MAX];
		REQUIRE_AUTH();
		REQUIRE_ARGS(s);
		STRIP_QUOTES(s);
		snprintf(activescript, sizeof(activescript), "%s/.sieve", mailbox_maildir(sieve->mbox));
		unlink(activescript); /* Remove existing active script if needed. */
		if (!strlen_zero(s)) {
			if (sieve_script_name_to_path(sieve, s, activescriptpath, sizeof(activescriptpath))) {
				sieve_send(sieve, "NO (NONEXISTENT) \"There is no script by that name\"");
			} else {
				/* make the symlink */
				if (symlink(activescriptpath, activescript)) { /* Make activescript symlink to activescriptpath */
					bbs_error("symlink failed: %s\n", strerror(errno));
					sieve_send(sieve, "NO Server error");
				} else {
					sieve_send(sieve, "OK");
				}
			}
		} else { /* Just set no script as active */
			sieve_send(sieve, "OK");
		}
	} else if (!strcasecmp(command, "DELETESCRIPT")) {
		char activescript[256];
		char activescriptpath[PATH_MAX];
		char targetscript[PATH_MAX];
		REQUIRE_AUTH();
		REQUIRE_ARGS(s);
		STRIP_QUOTES(s);
		if (sieve_script_name_to_path(sieve, s, targetscript, sizeof(targetscript))) {
			sieve_send(sieve, "NO (NONEXISTENT) \"No such script\"");
		} else {
			ssize_t res;
			/* Cannot delete an active script */
			snprintf(activescript, sizeof(activescript), "%s/.sieve", mailbox_maildir(sieve->mbox));
			res = readlink(activescript, activescriptpath, sizeof(activescriptpath) - 1);
			if (res > 0 && res < (ssize_t) sizeof(activescriptpath) - 1) {
				activescriptpath[res] = '\0';
				if (!strcmp(activescriptpath, targetscript)) {
					sieve_send(sieve, "NO (ACTIVE) \"You may not delete an active script\"");
					return 0;
				}
			}
			unlink(targetscript);
			sieve_send(sieve, "OK");
		}
	} else if (!strcasecmp(command, "RENAMESCRIPT")) {
		char *old, *new;
		char oldscript[256];
		char newscript[256];
		char activescript[PATH_MAX];
		REQUIRE_AUTH();
		REQUIRE_ARGS(s);
		SHIFT_OPTIONALLY_QUOTED_ARG(old, s);
		REQUIRE_ARGS(s);
		SHIFT_OPTIONALLY_QUOTED_ARG(new, s);
		if (sieve_script_name_to_path(sieve, old, oldscript, sizeof(oldscript))) {
			sieve_send(sieve, "NO (NONEXISTENT) \"No such script\"");
		} else if (!sieve_script_name_to_path_noexist(sieve, new, newscript, sizeof(newscript))) {
			sieve_send(sieve, "NO (ALREADYEXISTS) \"Already a script by that name\"");
		} else {
			/* If this is the active script, we need to also recreate the symlink,
			 * since the symlink references the name, not the inode. */
			snprintf(activescript, sizeof(activescript), "%s/.sieve", mailbox_maildir(sieve->mbox));
			if (rename(oldscript, newscript)) {
				bbs_error("rename %s -> %s failed: %s\n", oldscript, newscript, strerror(errno));
				sieve_send(sieve, "NO \"Server error\"");
			} else if (!strcmp(activescript, oldscript)) {
				bbs_debug(5, "Rename target is currently the active script, adjusting symlink\n");
				unlink(activescript);
				if (symlink(activescript, newscript)) {
					bbs_error("symlink failed: %s\n", strerror(errno));
				}
				sieve_send(sieve, "OK");
			}
		}
	} else if (!strcasecmp(command, "GETSCRIPT")) {
		char path[256];
		char buf[1001];
		FILE *fp;
		long int size;
		REQUIRE_AUTH();
		REQUIRE_ARGS(s);
		STRIP_QUOTES(s);
		if (sieve_script_name_to_path(sieve, s, path, sizeof(path))) {
			sieve_send(sieve, "NO (NONEXISTENT) No such script\n");
			return 0;
		}
		fp = fopen(path, "r");
		if (!fp) {
			sieve_send(sieve, "NO (NONEXISTENT) No such script\n");
			return 0;
		}
		fseek(fp, 0L, SEEK_END);
		size = ftell(fp);
		rewind(fp);
		sieve_send(sieve, "{%ld}", size);
		size = 0;
		while ((fgets(buf, sizeof(buf), fp))) {
			size_t len = strlen(buf);
			size += bbs_write(sieve->wfd, buf, (unsigned int) len);
		}
		fclose(fp);
		bbs_debug(5, "Sent %ld-byte script\n", size);
		sieve_send(sieve, ""); /* The RFC suggests this, and the Thunderbird Sieve editor extension wants to see an empty line after the script */
		sieve_send(sieve, "OK");
	} else if (!strcasecmp(command, "PUTSCRIPT")) {
		return putscript_helper(sieve, s, 1);
	} else if (!strcasecmp(command, "CHECKSCRIPT")) {
		return putscript_helper(sieve, s, 0);
	} else {
		bbs_warning("Unhandled command '%s'\n", command);
		sieve_send(sieve, "BAD Unrecognized command");
	}
	return 0;
}

static void handle_client(struct sieve_session *sieve)
{
	char buf[1001]; /* Maximum length, including CR LF, is 1000 */
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));
	if (handle_capability(sieve)) { /* Send capabilities immediately, unsolicited */
		return;
	}

	for (;;) {
		ssize_t res = bbs_readline(sieve->rfd, &rldata, "\r\n", 300000); /* Must be at least 30 minutes per RFC 5804, though that seems excessive */
		if (res < 0) {
			break;
		}
		if (sieve->fp) { /* Uploading a file */
			sieve->uploadsofar += (unsigned int) res + 2; /* Add the CR LF back */
			if (sieve->scriptname && sieve->uploadsofar > sieve->quotaleft) { /* Only check quota for PUTSCRIPT, but not CHECKSCRIPT */
				sieve_send(sieve, "NO (QUOTA/MAXSIZE) Quota exceeded");
				break; /* Extreme, but it's highly unlikely anyone would exceed email quota by uploading a Sieve script... come on, folks. */
			}
			fwrite(buf, sizeof(char), (size_t) res, sieve->fp); /* Append */
			if (sieve->uploadsofar >= sieve->uploadexpected) {
				if (sieve->uploadsofar > sieve->uploadexpected) { /* We already added 2 for the final CR LF so should never be more than */
					bbs_warning("Received %u/%u byte upload\n", sieve->uploadsofar, sieve->uploadexpected);
				} else {
					bbs_debug(5, "Received %u/%u byte upload\n", sieve->uploadsofar, sieve->uploadexpected);
				}
			} else {
				fwrite("\r\n", sizeof(char), STRLEN("\r\n"), sieve->fp); /* Don't do it the very last time or we'll have an extra CR LF */
				continue;
			}
		} else {
			bbs_debug(6, "%p => %s\n", sieve, buf);
		}
		if (sieve_process(sieve, buf)) {
			break;
		}
		if (sieve->dostarttls) { /* RFC3207 STARTTLS */
			bbs_debug(3, "Starting TLS\n");
			sieve->dostarttls = 0;
			if (bbs_node_starttls(sieve->node)) {
				break; /* Just abort */
			}
			bbs_readline_flush(&rldata); /* Prevent STARTTLS command injection by resetting the buffer after TLS upgrade */
			if (handle_capability(sieve)) { /* Must reissue after STARTTLS */
				return;
			}
		}
	}
}

static void *__sieve_handler(void *varg)
{
	struct bbs_node *node = varg;
	struct sieve_session sieve;

	bbs_node_net_begin(node);

	memset(&sieve, 0, sizeof(sieve));
	sieve.rfd = sieve.wfd = node->fd;
	sieve.node = node;

	handle_client(&sieve);

	sieve_cleanup(&sieve);

	bbs_node_exit(node);
	return NULL;
}

static int load_module(void)
{
	return bbs_start_tcp_listener(sieve_port, "ManageSieve", __sieve_handler);
}

static int unload_module(void)
{
	bbs_stop_tcp_listener(sieve_port);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC5804 ManageSieve", "mod_mail.so");
