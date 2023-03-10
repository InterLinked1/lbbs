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
 * \brief SFTP (Secure File Transfer Protocol) server
 *        Not to be confused in any way with RFC 913 Simple File Transfer Protocol!
 *
 * \note This module also depends on the net_ssh.conf config file.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <pthread.h>
#include <signal.h> /* use pthread_kill */

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

/* SFTP */
#define WITH_SERVER
#include <libssh/sftp.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/auth.h"
#include "include/pty.h" /* use bbs_openpty */
#include "include/term.h" /* use bbs_fd_unbuffer_input */
#include "include/utils.h"
#include "include/config.h"
#include "include/net.h"
#include "include/transfer.h"

static pthread_t sftp_listener_thread;

#define KEYS_FOLDER "/etc/ssh/"

static int sftp_port;
/* Key loading defaults */
static int load_key_rsa = 1;
static int load_key_dsa = 0;
static int load_key_ecdsa = 1;

static ssh_bind sshbind = NULL;

/*
 * There is no RFC officially for SFTP.
 * Version 3, working draft 2 is what we want: https://www.sftp.net/spec/draft-ietf-secsh-filexfer-02.txt
 */

/*!
 * \note Ideally, SSH and SFTP can operate on the same port since SFTP runs on top of SSH.
 * The way this module is designed now, it operates its own SSH listener which must run on a different port.
 * The main reason for this was to decouple the two since the SSH module uses an event-driven architecture
 * whereas the SFTP module was written more simply just for SFTP operations.
 * (Surprisingly, very little code is duplicated between net_ssh and net_sftp because of this.)
 * In some ways, this is a constraint, but in others it's also more flexible.
 * However, if this turns out to be a major limitation, then we should migrate to using only a single listener.
 */

/*! \brief Returns 1 on success, 0 on failure (!!!) */
/*! \note from net_ssh */
static int bind_key(enum ssh_bind_options_e opt, const char *filename)
{
	if (eaccess(filename, R_OK)) {
		bbs_warning("Can't access key %s - missing or not readable?\n", filename);
		return 0;
	}
	ssh_bind_options_set(sshbind, opt, KEYS_FOLDER "ssh_host_rsa_key");
	return 1;
}

/*! \note from net_ssh */
static int start_ssh(void)
{
	int keys = 0;

	sshbind = ssh_bind_new();
	if (!sshbind) {
		bbs_error("ssh_bind_new failed\n");
		return -1;
	}

	/* Set default keys */
	if (load_key_rsa) {
		keys += bind_key(SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
	}
	if (load_key_dsa) {
		keys += bind_key(SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
	}
	if (load_key_ecdsa) {
		keys += bind_key(SSH_BIND_OPTIONS_ECDSAKEY, KEYS_FOLDER "ssh_host_ecdsa_key");
	}

	if (!keys) {
		bbs_error("Failed to configure listener, unable to bind any SSH keys\n");
		/* May need to do e.g. chown <BBS run username> /etc/ssh/ssh_host_rsa_key */
		return -1;
	}

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &sftp_port); /* Set the SSH bind port */
	if (ssh_bind_listen(sshbind) < 0) {
		bbs_error("%s\n", ssh_get_error(sshbind));
		ssh_bind_free(sshbind);
		sshbind = NULL;
		return -1;
	}

	return 0;
}

static int do_auth(struct bbs_node *node, ssh_session session)
{
	int res = -1;
	ssh_message message;

	while (res) {
		message = ssh_message_get(session);
		if (!message) {
			return -1;
		}
		switch (ssh_message_type(message)) {
			case SSH_REQUEST_AUTH:
				switch (ssh_message_subtype(message)) {
					case SSH_AUTH_METHOD_PASSWORD:
						if (!bbs_authenticate(node, ssh_message_auth_user(message), ssh_message_auth_password(message))) {
							ssh_message_auth_reply_success(message, 0);
						}
						res = 0; /* Whether successful or not, we stop. Only one attempt for SFTP. */
						break;
					default:
						ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
						ssh_message_reply_default(message);
						break;
				}
				break;
			default:
				ssh_message_reply_default(message);
		}
		ssh_message_free(message);
	}

	return res;
}

static ssh_channel get_sftp_channel(ssh_session session)
{
	ssh_channel chan = NULL;
	ssh_message message;

	while (!chan) {
		message = ssh_message_get(session);
		if (!message) {
			return NULL;
		}
		switch (ssh_message_type(message)) {
			case SSH_REQUEST_CHANNEL_OPEN:
				if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
					chan = ssh_message_channel_request_open_reply_accept(message);
					bbs_debug(3, "Channel open requested\n");
					break;
				}
				/* Fall through */
			default:
				bbs_debug(5, "Skipping message %d\n", ssh_message_type(message));
				ssh_message_reply_default(message);
		}
		ssh_message_free(message);
	}

	for (;;) {
		message = ssh_message_get(session);
		if (!message) {
			return NULL;
		}
		switch (ssh_message_type(message)) {
			case SSH_REQUEST_CHANNEL:
				if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SUBSYSTEM) {
					const char *subtype = ssh_message_channel_request_subsystem(message);
					if (!strcmp(subtype, "sftp")) {
						ssh_message_channel_request_reply_success(message);
						ssh_message_free(message);
						return chan;
					}
					bbs_error("Unsupported subsystem: %s\n", subtype);
					break;
				}
				/* Fall through */
			default:
				bbs_debug(5, "Skipping message %d\n", ssh_message_type(message));
				ssh_message_reply_default(message);
		}
		ssh_message_free(message);
	}

	bbs_assert(0);
	return NULL;
}

static int handle_errno(sftp_client_message msg)
{
	bbs_debug(3, "errno: %s\n", strerror(errno));
	switch (errno) {
		case EPERM:
		case EACCES:
			return sftp_reply_status(msg, SSH_FX_PERMISSION_DENIED, "Permission denied");
		case ENOENT:
			return sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, "No such file or directory"); /* Also SSH_FX_NO_SUCH_PATH */
		case ENOTDIR:
			return sftp_reply_status(msg, SSH_FX_FAILURE, "Not a directory");
		case EEXIST:
			return sftp_reply_status(msg, SSH_FX_FILE_ALREADY_EXISTS, "File already exists");
		default:
			return sftp_reply_status(msg, SSH_FX_FAILURE, NULL);
	}
}

#define TYPE_DIR 0
#define TYPE_FILE 1

struct sftp_info {
	int offset;
	char *name;			/*!< Client's filename */
	char *realpath;		/*!< Actual server path */
	DIR *dir;
	FILE *file;
	unsigned int type:1;
};

static struct sftp_info *alloc_sftp_info(void)
{
	struct sftp_info *h = calloc(1, sizeof(*h));
	if (!h) {
		bbs_error("calloc failed\n");
		return NULL;
	}
	h->offset = 0;
	return h;
}

static sftp_attributes attr_from_stat(struct stat *st)
{
	sftp_attributes attr = calloc(1, sizeof(*attr));

	if (!attr) {
		bbs_error("calloc failed\n");
		return NULL;
	}

	attr->size = st->st_size;
	attr->uid = st->st_uid;
	attr->gid = st->st_gid;
	attr->permissions = st->st_mode;
	attr->atime = st->st_atime;
	attr->mtime = st->st_mtime;
	attr->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;

    return attr;
}

static int make_longname(const char *file, struct stat *st, char *buf, size_t len)
{
	char ctimebuf[26]; /* 26 bytes is enough per ctime(3) */
	char *modtime;
	char *p = buf;
	int mode = st->st_mode;

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

	p += snprintf(p, len - (p - buf), "%3d %d %d %d", (int) st->st_nlink, (int) st->st_uid, (int) st->st_gid, (int) st->st_size);
	modtime = ctime_r(&st->st_mtime, ctimebuf); /* ctime_r assumes ctimebuf is at least 26, there is no length argument. */
	modtime += 4; /* Skip short day of week */
	bbs_strterm(modtime, '\n'); /* Strip trailing LF */
	snprintf(p, len - (p - buf), " %s %s", modtime, file);
	return 0;
}

static const char *sftp_get_client_message_type_name(uint8_t i)
{
	switch (i) {
		case SSH_FXP_INIT: return "INIT";
		case SSH_FXP_VERSION: return "VERSION";
		case SSH_FXP_OPEN: return "OPEN";
		case SSH_FXP_CLOSE: return "CLOSE";
		case SSH_FXP_READ: return "READ";
		case SSH_FXP_WRITE: return "WRITE";
		case SSH_FXP_LSTAT: return "LSTAT";
		case SSH_FXP_FSTAT: return "FSTAT";
		case SSH_FXP_SETSTAT: return "SETSTAT";
		case SSH_FXP_FSETSTAT: return "FSETSTAT";
		case SSH_FXP_OPENDIR: return "OPENDIR";
		case SSH_FXP_READDIR: return "READDIR";
		case SSH_FXP_REMOVE: return "REMOVE";
		case SSH_FXP_MKDIR: return "MKDIR";
		case SSH_FXP_RMDIR: return "RMDIR";
		case SSH_FXP_REALPATH: return "REALPATH";
		case SSH_FXP_STAT: return "STAT";
		case SSH_FXP_RENAME: return "RENAME";
		case SSH_FXP_READLINK: return "READLINK";
		case SSH_FXP_SYMLINK: return "SYMLINK";
		case SSH_FXP_STATUS: return "STATUS";
		case SSH_FXP_HANDLE: return "HANDLE";
		case SSH_FXP_DATA: return "DATA";
		case SSH_FXP_NAME: return "NAME";
		case SSH_FXP_ATTRS: return "ATTRS";
		case SSH_FXP_EXTENDED: return "EXTENDED";
		case SSH_FXP_EXTENDED_REPLY: return "return EXTENDED_REPLY";
		default:
			bbs_error("Unknown message type: %d\n", i);
			return NULL;
	}
}

static int sftp_io_flags(int sflags)
{
	int flags = 0;
	if (sflags & SSH_FXF_READ) {
		flags |= O_RDONLY;
	}
	if (sflags & SSH_FXF_WRITE) {
		flags |= O_WRONLY;
	}
	if (sflags & SSH_FXF_APPEND) {
		flags |= O_APPEND;
	}
	if (sflags & SSH_FXF_TRUNC) {
		flags |= O_TRUNC;
	}
	if (sflags & SSH_FXF_EXCL) {
		flags |= O_EXCL;
	}
	if (sflags & SSH_FXF_CREAT) {
		flags |= O_CREAT;
	}
	return flags;
}

static const char *fopen_flags(int flags)
{
	switch (flags & (O_RDONLY | O_WRONLY | O_APPEND | O_TRUNC)) {
		case O_RDONLY:
			return "r";
		case O_WRONLY | O_RDONLY:
			return "r+";
		case O_WRONLY | O_TRUNC:
			return "w";
		case O_WRONLY | O_RDONLY | O_APPEND:
			return "a+";
		default:
			switch (flags & (O_RDONLY | O_WRONLY)) {
				case O_RDONLY:
					return "r";
				case O_WRONLY:
					return "w";
			}
	}
	return "r"; /* Default */
}

static int handle_readdir(sftp_client_message msg)
{
	sftp_attributes attr;
	struct dirent *dir;
	struct stat st;
	int eof = 0;
	char file[1024];
	char longname[PATH_MAX];
	int i = 0;
	struct sftp_info *info = sftp_handle(msg->sftp, msg->handle);

	if (!info || info->type != TYPE_DIR) {
		sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "Invalid handle");
		return -1;
	}

	while (!eof) {
		dir = readdir(info->dir);
		if (!dir) {
			eof = 1;
			break;
		}
		i++;
		/* Avoid double slash // at beginning when in the root directory */
		bbs_debug(4, "Have %s/%s\n", !strcmp(info->name, "/") ? "" : info->name, dir->d_name);
		snprintf(file, sizeof(file), "%s/%s/%s", bbs_transfer_rootdir(), info->name, dir->d_name);
		if (lstat(file, &st)) {
			bbs_error("lstat failed: %s\n", strerror(errno));
            continue;
        }
		attr = attr_from_stat(&st);
		if (!attr) {
			continue;
		}
		make_longname(dir->d_name, &st, longname, sizeof(longname));
		sftp_reply_names_add(msg, dir->d_name, longname, attr);
		sftp_attributes_free(attr);
	}

	if (!i && eof) { /* No files */
		sftp_reply_status(msg, SSH_FX_EOF, NULL);
		return 0;
	}
	sftp_reply_names(msg);
	return 0;
}

static int handle_read(sftp_client_message msg)
{
	void *data;
	int r;
	uint32_t len = msg->len; /* Maximum number of bytes to read */
	struct sftp_info *info = sftp_handle(msg->sftp, msg->handle);

	if (!info || info->type != TYPE_FILE) {
		sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "Invalid handle");
		return -1;
	} else if (len < 1) {
		sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "Insufficient length");
		return -1;
	}

	/* Avoid MIN macro due to different signedness */
	if (len > (2 << 15)) {
		len = 2 << 15; /* Cap at 32768, so we don't malloc ourselves into oblivion... */
		bbs_debug(5, "Capping len at %d (down from %d)\n", len, msg->len);
	}

	data = malloc(len);
	if (!data) {
		sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "Allocation failed");
		return -1;
	}

	if (fseeko(info->file, msg->offset, SEEK_SET)) {
		bbs_error("fseeko failed: %s\n", strerror(errno));
		sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "Offset failed");
		free(data);
		return -1;
	}

	r = fread(data, 1, len, info->file);
	bbs_debug(7, "read %d bytes (len: %d)\n", r, len);
	/* XXX For some reason, we get 128 of these after the EOF, before we stop getting READ messages (???) (At least with FileZilla).
	 * Still works but probably not right */
	if (r <= 0) {
		if (feof(info->file)) {
			bbs_debug(4, "File transfer has completed\n");
			sftp_reply_status(msg, SSH_FX_EOF, "EOF");
		} else {
			handle_errno(msg);
		}
	} else {
		sftp_reply_data(msg, data, r);
	}
	/* Do not respond with an OK here */
	free(data);
	return 0;
}

static int handle_write(sftp_client_message msg)
{
	int r;
	uint32_t len;
	struct sftp_info *info = sftp_handle(msg->sftp, msg->handle);

	if (!info || info->type != TYPE_FILE) {
		sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "Invalid handle");
        return -1;
	}
	len = string_len(msg->data);
	if (fseeko(info->file, msg->offset, SEEK_SET)) {
		bbs_error("fseeko failed: %s\n", strerror(errno));
		sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "Offset failed");
		return -1;
	}
	do {
		r = fwrite(string_data(msg->data), 1, len, info->file);
		if (r <= 0 && len > 0) {
			handle_errno(msg);
			return -1;
		}
		len -= r;
	} while (len > 0);
	sftp_reply_status(msg, SSH_FX_OK, NULL);
	return 0;
}

#define STDLIB_SYSCALL(func, ...) \
	if (func(__VA_ARGS__)) { \
		handle_errno(msg); \
	} else { \
		sftp_reply_status(msg, SSH_FX_OK, NULL); \
	}

#define SFTP_ENSURE_TRUE(func, node) \
	if (!func(node)) { \
		errno = EACCES; \
		handle_errno(msg); \
		break; \
	}

/* Duplicate code from libssh if needed since sftp_server_free isn't available in older versions */
#ifndef HAVE_SFTP_SERVER_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

struct sftp_ext_struct {
	uint32_t count;
	char **name;
	char **data;
};

static void sftp_ext_free(sftp_ext ext)
{
	size_t i;

	if (ext == NULL) {
		return;
	}

	if (ext->count > 0) {
		if (ext->name != NULL) {
			for (i = 0; i < ext->count; i++) {
				SAFE_FREE(ext->name[i]);
			}
			SAFE_FREE(ext->name);
		}

		if (ext->data != NULL) {
			for (i = 0; i < ext->count; i++) {
				SAFE_FREE(ext->data[i]);
			}
			SAFE_FREE(ext->data);
		}
	}

	SAFE_FREE(ext);
}

static void sftp_message_free(sftp_message msg)
{
	if (msg == NULL) {
		return;
	}

	SSH_BUFFER_FREE(msg->payload);
	SAFE_FREE(msg);
}

/*!
 * \brief sftp_server_free from libssh's sftp.c (unmodified)
 * \note Licensed under the GNU Lesser GPL
 * \note This was only added to libssh in commit cc536377f9711d9883678efe4fcf4cb6449c3b1a
 *       LIBSFTP_VERSION is 3 both before/after this commit, so unfortunately
 *       we don't have any good way of detecting whether or not this function
 *       exists in the version of libssh installed.
 *       Therefore, we just duplicate the function here to guarantee its availability.
 */
static void sftp_server_free(sftp_session sftp)
{
	sftp_request_queue ptr;

	if (sftp == NULL) {
		return;
	}

	ptr = sftp->queue;
	while(ptr) {
		sftp_request_queue old;
		sftp_message_free(ptr->message);
		old = ptr->next;
		SAFE_FREE(ptr);
		ptr = old;
	}

	SAFE_FREE(sftp->handles);
	SSH_BUFFER_FREE(sftp->read_packet->payload);
	SAFE_FREE(sftp->read_packet);

	sftp_ext_free(sftp->ext);

	SAFE_FREE(sftp);
}
#endif

static int do_sftp(struct bbs_node *node, ssh_session session, ssh_channel channel)
{
	char buf[PATH_MAX], mypath[PATH_MAX];
	sftp_session sftp;
	int res;
	FILE *fp;
	int fd;
	DIR *dir;
	struct sftp_info *info;
	ssh_string handle;
	struct stat st;
	sftp_attributes attr;

	bbs_debug(3, "Starting SFTP session on node %d\n", node->id);

	sftp = sftp_server_new(session, channel);
	if (!sftp) {
		bbs_error("Failed to create SFTP session\n");
		return SSH_ERROR;
	}
	res = sftp_server_init(sftp); /* Initialize SFTP server */
	if (res) {
		bbs_error("sftp_server_init failed: %d\n", sftp_get_error(sftp));
		goto cleanup;
	}

	for (;;) {
		sftp_client_message msg;
#if 0
		/*! \todo BUGBUG FIXME For some reason, this doesn't work (probably can't poll directly on the fd, see if there's a libssh API to do this) */
		int pres = bbs_std_poll(node->fd, bbs_transfer_timeout());
		if (pres <= 0) {
			bbs_debug(3, "poll returned %d, terminating SFTP session\n", pres);
			break;
		}
#endif
		msg = sftp_get_client_message(sftp); /* This will block, so if we want a timeout, we need to do it beforehand */
		if (!msg) {
			break;
		}
		if (msg->filename && (!strcmp(msg->filename, ".") || !strcmp(msg->filename, "/"))) {
			safe_strncpy(mypath, bbs_transfer_rootdir(), sizeof(mypath));
		} else {
			snprintf(mypath, sizeof(mypath), "%s%s", bbs_transfer_rootdir(), S_IF(msg->filename));
		}
		bbs_debug(5, "Got SFTP client message %2d (%8s), client path: %s => server path: %s\n", msg->type, sftp_get_client_message_type_name(msg->type), msg->filename, mypath);
		switch (msg->type) {
			case SFTP_REALPATH:
				if (!realpath(mypath, buf)) { /* returns NULL on failure */
					bbs_debug(5, "Path '%s' not found: %s\n", mypath, strerror(errno));
					errno = ENOENT;
					handle_errno(msg);
				} else {
					const char *client_realpath = buf + strlen(bbs_transfer_rootdir());
					/* Corner case: for root, we need to manually add the / back */
					bbs_debug(3, "Real client path is '%s'\n", S_OR(client_realpath, "/"));
					sftp_reply_name(msg, S_OR(client_realpath, "/"), NULL); /* Skip root dir */
				}
				break;
			case SFTP_OPENDIR:
				dir = opendir(mypath);
				if (!dir) {
					handle_errno(msg);
				} else if (!(info = alloc_sftp_info())) {
					handle_errno(msg);
				} else {
					info->dir = dir;
					info->type = TYPE_DIR;
					info->name = strdup(msg->filename);
					info->realpath = strdup(mypath);
					handle = sftp_handle_alloc(msg->sftp, info);
					sftp_reply_handle(msg, handle);
					free(handle);
					handle = NULL;
				}
				break;
			case SFTP_OPEN:
				fd = open(mypath, sftp_io_flags(msg->flags), msg->attr->permissions);
				if (fd < 0) {
					handle_errno(msg);
				} else {
					fp = fdopen(fd, fopen_flags(sftp_io_flags(msg->flags)));
					if (!(info = alloc_sftp_info())) {
						handle_errno(msg);
						close(fd); /* Do this after so we don't mess up errno */
					} else {
						info->type = TYPE_FILE;
						info->file = fp;
						info->name = strdup(msg->filename);
						info->realpath = strdup(mypath);
						handle = sftp_handle_alloc(msg->sftp, info);
						sftp_reply_handle(msg, handle);
						free(handle);
						handle = NULL;
					}
				}
				break;
			case SFTP_STAT:
				/* Fall through */
			case SFTP_LSTAT:
				if ((msg->type == SFTP_STAT && stat(mypath, &st)) || (msg->type == SFTP_LSTAT && lstat(mypath, &st))) {
					handle_errno(msg);
				} else {
					attr = attr_from_stat(&st);
					sftp_reply_attr(msg, attr);
					sftp_attributes_free(attr);
				}
				break;
			case SFTP_CLOSE:
				info = sftp_handle(msg->sftp, msg->handle);
				if (!info) {
					sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "Invalid handle");
				} else {
					sftp_handle_remove(msg->sftp, info);
					info->type == TYPE_DIR ? closedir(info->dir) : fclose(info->file);
					free_if(info->name);
					free_if(info->realpath);
					free(info);
					sftp_reply_status(msg, SSH_FX_OK, NULL);
				}
				break;
			case SFTP_READDIR:
				handle_readdir(msg);
				break;
			case SFTP_READ:
				SFTP_ENSURE_TRUE(bbs_transfer_canread, node);
				handle_read(msg);
				break;
			case SFTP_WRITE:
				SFTP_ENSURE_TRUE(bbs_transfer_canwrite, node);
				handle_write(msg);
				break;
			case SFTP_REMOVE:
				SFTP_ENSURE_TRUE(bbs_transfer_candelete, node);
				STDLIB_SYSCALL(unlink, mypath);
				break;
			case SFTP_MKDIR:
				SFTP_ENSURE_TRUE(bbs_transfer_canmkdir, node);
				STDLIB_SYSCALL(mkdir, mypath, 0600);
				break;
			case SFTP_RMDIR:
				SFTP_ENSURE_TRUE(bbs_transfer_candelete, node);
				STDLIB_SYSCALL(rmdir, mypath);
				break;
			case SFTP_RENAME:
				SFTP_ENSURE_TRUE(bbs_transfer_candelete, node);
				{
					const char *newpath;
					char realnewpath[PATH_MAX];
					newpath = sftp_client_message_get_data(msg); /* According to sftp.h, rename() newpath is here */
					snprintf(realnewpath, sizeof(realnewpath), "%s%s", bbs_transfer_rootdir(), newpath);
					if (!eaccess(realnewpath, R_OK)) { /* If target already exists, it's a no go */
						errno = EEXIST;
						handle_errno(msg);
					} else {
						bbs_debug(5, "Renaming %s => %s\n", mypath, realnewpath);
						STDLIB_SYSCALL(rename, mypath, realnewpath);
					}
				}
				break;
			case SFTP_SETSTAT:
			case SFTP_FSETSTAT:
				/* XXX Not implemented, don't allow users to change permissions on the system */
				errno = EPERM;
				handle_errno(msg);
				break;
			case SFTP_FSTAT:
			case SFTP_READLINK:
			case SFTP_SYMLINK:
				/* Not implemented */
			default:
				bbs_error("Unhandled SFTP client operation: %d (%s)\n", msg->type, sftp_get_client_message_type_name(msg->type));
				sftp_reply_status(msg, SSH_FX_OP_UNSUPPORTED, "Unsupported operation");
		}
		sftp_client_message_free(msg);
	}

	/*! \todo BUGBUG FIXME XXX Need to implicitly close anything that's open to prevent resource leaks (don't trust the client to clean up) */

cleanup:
	sftp_server_free(sftp);
	return SSH_ERROR;
}

static void handle_session(struct bbs_node *node, ssh_session session)
{
	ssh_channel channel;
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		bbs_error("%s\n", ssh_get_error(session));
		return;
	}

	if (do_auth(node, session)) {
		bbs_debug(3, "Authentication aborted\n");
		return;
	} else if (!node->user) {
		return; /* Authentication failed */
	}

	if (!bbs_transfer_canaccess(node)) {
		bbs_verb(3, "Node %d is not allowed file transfer access\n", node->id);
		return;
	}

	channel = get_sftp_channel(session);
	if (!channel) {
		bbs_debug(3, "Channel setup aborted\n");
		return;
	}

	do_sftp(node, session, channel);
	bbs_debug(3, "Terminating SSH session\n");

	/* Goodbye */
	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
}

/*! \note from net_ssh */
static int save_remote_ip(ssh_session session, struct bbs_node *node, char *buf, size_t len)
{
	socket_t sfd;
	struct sockaddr tmp;
	struct sockaddr_in *sock;
	socklen_t socklen = sizeof(tmp);

	sfd = ssh_get_fd(session); /* Get fd of the connection */
	if (getpeername(sfd, &tmp, &socklen)) {
		bbs_error("getpeername: %s\n", strerror(errno));
		return -1;
	}

	sock = (struct sockaddr_in *) &tmp;
	if (node) {
		return bbs_save_remote_ip(sock, node);
	} else if (buf) {
		return bbs_get_remote_ip(sock, buf, len);
	} else {
		return -1;
	}
}

static void *ssh_connection(void *varg)
{
	ssh_session session = varg;
	struct bbs_node *node = bbs_node_request(ssh_get_fd(session), "SFTP");

	if (node) {
		save_remote_ip(session, node, NULL, 0);
		node->thread = pthread_self();
		bbs_node_begin(node);
		handle_session(node, session); /* This is the custom node handler, essentially */
		bbs_debug(3, "Node %d has ended its SFTP session\n", node->id);
		bbs_node_exit(node); /* node is no longer a valid reference */
	}

	ssh_disconnect(session);
	ssh_free(session);
	return NULL;
}

static ssh_session pending_session = NULL;

static void *ssh_listener(void *unused)
{
	ssh_session session; /* This is actually a pointer, even though it doesn't look like one. */

	UNUSED(unused);

	for (;;) {
		static pthread_t sftp_thread;
		pending_session = session = ssh_new();
		if (!session) {
			bbs_error("Failed to allocate SSH session\n");
			continue;
		}
		/* Blocks until there is a new incoming connection. */
		if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
			bbs_error("%s\n", ssh_get_error(sshbind));
			continue;
		}
		/* Spawn a thread to handle this SFTP connection. */
		if (bbs_pthread_create_detached(&sftp_thread, NULL, ssh_connection, session)) {
			ssh_disconnect(session);
			ssh_free(session);
			continue;
		}
	}
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	if (bbs_transfer_config_load()) {
		return -1;
	}

	cfg = bbs_config_load("net_ssh.conf", 1); /* Use cached version if available */
	if (!cfg) {
		return -1;
	}

	bbs_config_val_set_true(cfg, "keys", "rsa", &load_key_rsa);
	bbs_config_val_set_true(cfg, "keys", "dsa", &load_key_dsa);
	bbs_config_val_set_true(cfg, "keys", "ecdsa", &load_key_ecdsa);

	sftp_port = -1;
	if (bbs_config_val_set_port(cfg, "sftp", "port", &sftp_port)) {
		bbs_error("No SFTP port specified in net_ssh.conf, declining to load\n");
		return -1;
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	if (ssh_init() != SSH_OK) { /* Init SSH library */
		bbs_error("libssh ssh_init failed\n");
		return -1;
	}
	if (start_ssh()) {
		goto cleanup;
	}
	if (bbs_pthread_create(&sftp_listener_thread, NULL, ssh_listener, NULL)) {
		bbs_error("Unable to create SFTP listener thread.\n");
		goto cleanup;
	}
	bbs_register_network_protocol("SFTP", sftp_port);
	return 0;

cleanup:
	ssh_finalize(); /* Clean up SSH library */
	return -1;
}

static int unload_module(void)
{
	if (!sshbind) {
		bbs_error("SSH socket already closed at unload?\n");
		return 0;
	}
	bbs_unregister_network_protocol(sftp_port);
	bbs_debug(3, "Cleaning up libssh\n");
	pthread_cancel(sftp_listener_thread);
	pthread_kill(sftp_listener_thread, SIGURG);
	bbs_pthread_join(sftp_listener_thread, NULL);
	/* Since the ssh_listener thread was cancelled, most likely in ssh_bind_accept,
	 * but it already called ssh_new, we need to free the session that never got assigned. */
	if (pending_session) {
		ssh_free(pending_session);
		pending_session = NULL;
	}
	ssh_bind_free(sshbind);
	ssh_finalize(); /* Clean up SSH library */
	return 0;
}

BBS_MODULE_INFO_STANDARD("SFTP (Secure File Transfer Protocol)");
