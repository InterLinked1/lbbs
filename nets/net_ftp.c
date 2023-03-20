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
 * \brief FTP (File Transfer Protocol) server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h> /* use pthread_kill */
#include <sys/sendfile.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/config.h"
#include "include/net.h"
#include "include/auth.h"
#include "include/system.h"
#include "include/transfer.h"

static int ftp_socket = -1; /*!< TCP Socket for allowing incoming network connections */
static pthread_t ftp_thread;
static int minport, maxport;

/*! \brief Default FTP port is 21 */
#define DEFAULT_FTP_PORT 21

static int ftp_port = DEFAULT_FTP_PORT;

/*! \note Uses a statement expression so that we can also log all FTP responses */
#define ftp_write(node, code, fmt, ...) ({ bbs_debug(5, "FTP <= %d " fmt, code, ## __VA_ARGS__); bbs_std_writef(node->fd, "%d " fmt, code, ## __VA_ARGS__); })
#define ftp_poll(node, ms) bbs_std_poll(node->fd, ms)
#define ftp_read(node, buf, size) read(node->fd, buf, size)
#define IO_ABORT(res) if (res <= 0) { goto cleanup; }

/*! \note Not sure if accessing parent directories is an issue with all functions, but just in case */
#define UNSAFE_FILEPATH(path) strstr(path, "..")

#define FTP_UPDATE_DIR(dir) safe_strncpy(ftpdir, dir, sizeof(ftpdir)); snprintf(fulldir, sizeof(fulldir), "%s%s", bbs_transfer_rootdir(), ftpdir); bbs_debug(5, "Updated FTP directory to %s\n", ftpdir)
#define REQUIRE_PASV_FD() \
	if (pasv_fd == -1) { \
		res = ftp_write(node, 501, "Invalid command sequence\r\n"); \
		IO_ABORT(res); \
		continue; \
	}

#define MIN_FTP_PRIV(priv) \
	if (!bbs_transfer_operation_allowed(node, priv)) { \
		res = ftp_write(node, 450, "Insufficient privileges for operation\n"); \
		IO_ABORT(res); \
		continue; \
	}

static int ftp_pasv_new(int *sockfd)
{
	int sfd;
	int res = -1, port;
	int attempts_left = MIN((maxport - minport), 250);

	/* There are some security issues with passive mode.
	 * http://cr.yp.to/ftp/security.html
	 *
	 * To mitigate, we:
	 * 1) Choose ports randomly from the allowed range.
	 * 2) Only allow the originally connecting IP (even though this violates RFC 943, technically)
	 */

	/* XXX Should be randomized for better */
	while (res && attempts_left-- > 0) {
		port = bbs_rand(minport, maxport); /* It would be better if we didn't retry previously attempted ports, but this should be good enough */
		/* XXX Could globally keep track of ports currently in use within this module, if the traffic ever becomes high enough, rather than attempting bind() directly */
		res = bbs_make_tcp_socket(&sfd, port); /* bind() will fail if the port is already in use */
		if (res) {
			bbs_debug(7, "Couldn't bind to port %d\n", port);
		}
	}

	if (res) {
		bbs_warning("Couldn't allocate port for passive mode data connection\n");
		return -1;
	}

	*sockfd = sfd;
	return port;
}

static int ftp_put(struct bbs_node *node, int *pasv_fd_ptr, const char *fulldir, const char *file, const char *flags)
{
	int res;
	char fullfile[386];
	char buf[512];
	FILE *fp;
	int x, bytes = 0;

	if (!bbs_transfer_canwrite(node)) {
		return ftp_write(node, 450, "File uploads denied for user\n");
	}

	snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, file);
	if (UNSAFE_FILEPATH(file)) {
		return ftp_write(node, 450, "File \"%s\" not allowed\n", file);
	}

	/* Overwriting is basically deleting and then writing, unless we're appending */
	if (!bbs_transfer_candelete(node) && strcmp(flags, "a") && !eaccess(fullfile, R_OK)) {
		return ftp_write(node, 450, "File \"%s\" already exists and may not be overwritten\n", file);
	}

	fp = fopen(fullfile, flags);
	if (!fp) {
		return ftp_write(node, 451, "File \"%s\" not created\n", file);
	}

	/* Accept file upload */
	for (;;) {
		res = bbs_std_poll(*pasv_fd_ptr, 2000);
		if (res <= 0) {
			res = -1;
			bbs_warning("File transfer stalled, aborting\n");
			break;
		}
		res = read(*pasv_fd_ptr, buf, sizeof(buf));
		if (res <= 0) {
			res = 0; /* End of transfer */
			break;
		}
		x = fprintf(fp, "%.*s", res, buf);
		if (x != res) {
			bbs_warning("Wanted to write %d bytes but only wrote %d\n", res, x);
			res = -1;
			break;
		}
		bytes += x;
	}

	fclose(fp);
	close_if(*pasv_fd_ptr); /* Close connection when done. This is the EOF that signals the client that the file transfer has completed. */
	if (res == -1) {
		res = ftp_write(node, 451, "File transfer failed\r\n");
	} else {
		res = ftp_write(node, 226, "File transfer successful, put %d bytes\r\n", bytes);
	}
	return res;
}

static void *ftp_handler(void *varg)
{
	char buf[512];
	char username[64] = "";
	char ftpdir[256] = ""; /* FTP relative directory */
	char fulldir[256];
	char *command, *rest, *next;
	int res;
	struct bbs_node *node = varg;
	int invalids = 0;
	int pasv_port, pasv_fd = -1;
	char our_ip[48];
	char rename_from[256] = "";
	char type = 'A'; /* Default is ASCII */

	/* This thread is running instead of the normal node handler thread */
	/* Remember, no pseudoterminal is allocated for this node! Can NOT use normal bbs_ I/O functions. */
	bbs_node_begin(node);

	if (bbs_get_local_ip(our_ip, sizeof(our_ip))) { /* Determine it just once, now */
		goto cleanup;
	}

	/* FTP uses CR LF line endings (but that's what you expected, right?) */
	res = ftp_write(node, 220, "Welcome to %s FTP\r\n", bbs_name()); /* Send welcome message */
	IO_ABORT(res);

	FTP_UPDATE_DIR("/"); /* Must be called whenever ftpdir is updated (rootdir doesn't change) */

	for (;;) {
		res = ftp_poll(node, node->user ? bbs_transfer_timeout() : 15000); /* After some number of seconds of inactivity, a client times out */
		if (res <= 0) {
			break;
		}
		res = ftp_read(node, buf, sizeof(buf) - 1);
		if (res <= 0) {
			break;
		}
		if (res > 2 && buf[res - 1] == '\n') { /* Strip trailing CR LF */
			buf[res - 1] = '\0';
			if (buf[res - 2] == '\r') {
				buf[res - 2] = '\0';
			}
		} else {
			res = ftp_write(node, 501, "Invalid command\r\n"); /* Very small chance read returned an incomplete command. Just try again. */
			IO_ABORT(res);
			continue;
		}
		if (!STARTS_WITH(buf, "PASS ")) {
			bbs_debug(3, "FTP => %s\n", buf);
		} else {
			bbs_debug(3, "FTP => PASS %s\n", "<REDACTED>");
		}
		rest = buf;
		command = strsep(&rest, " ");

		/* RFC 959 says commands are not case sensitive */

		/* Access Control */
		if (!strcasecmp(command, "USER")) {
			next = rest;
			safe_strncpy(username, next, sizeof(username));
			res = ftp_write(node, 331, "User name okay, need password\r\n");
		} else if (!strcasecmp(command, "PASS")) {
			next = rest;
			if (s_strlen_zero(username)) { /* Never got a username first */
				res = ftp_write(node, 503, "Bad sequence of commands\r\n");
			} else if (strlen_zero(next)) { /* No password */
				res = ftp_write(node, 501, "Invalid command syntax\r\n");
			} else {
				/* Try to authenticate. */
				res = bbs_authenticate(node, username, next);
				memset(buf, 0, sizeof(buf)); /* Overwrite (zero out) the plain text password from memory */
				username[0] = '\0'; /* Delete the username too so it's not preset if we reauthenticate */
				if (res) {
					invalids++;
					if (invalids > 1) {
						res = ftp_write(node, 421, "Invalid username or password, closing control connection\r\n");
						break; /* Close connection */
					} else {
						res = ftp_write(node, 430, "Invalid username or password\r\n");
					}
				} else {
					MIN_FTP_PRIV(TRANSFER_ACCESS);
					res = ftp_write(node, 230, "Login successful\r\n"); /* If ACCT needed, reply 332 instead */
				}
			}
		} else if (!strcasecmp(command, "ACCT")) {
			res = ftp_write(node, 202, "Command Not Implemented, Superflous\r\n"); /* Not needed */
		} else if (!strcasecmp(command, "REIN")) { /* Reinitialize */
			if (node->user) {
				bbs_node_logout(node);
				res = ftp_write(node, 220, "Welcome to %s FTP\r\n", bbs_name()); /* Send welcome message */
			} else {
				res = ftp_write(node, 421, "Not currently logged in, closing control connection\r\n");
				break;
			}
		} else if (!strcasecmp(command, "QUIT")) { /* Log out and quit */
			res = ftp_write(node, 231, "Goodbye\r\n");
			break;
		} else if (!strcasecmp(command, "AUTH")) {
			/* AUTH TLS / AUTH SSL = RFC2228 opportunistic encryption */
			res = ftp_write(node, 502, "Command Not Implemented\r\n"); /* Legitimate w/o authentication, but not supported currently */
		} else if (!node->user) {
			/* All subsequent commands require authentication */
			bbs_warning("Node %d issued FTP %s without authentication\n", node->id, command);
			res = ftp_write(node, 530, "Not Logged In\r\n");
			if (res <= 0) {
				break;
			}
			continue;
		} else if (!strcasecmp(command, "CWD")) { /* Change working directory */
			char newdir[sizeof(fulldir) + 1];
			bbs_debug(7, "Current FTP dir is '%s' and request is '%s'\n", ftpdir, rest);
			if (*rest == '/') {
				snprintf(newdir, sizeof(newdir), "%s%s", bbs_transfer_rootdir(), rest);
			} else {
				snprintf(newdir, sizeof(newdir), "%s%s/%s", bbs_transfer_rootdir(), ftpdir, rest); /* Relative to current directory */
			}
			bbs_debug(5, "Checking if directory exists: %s\n", newdir);
			if (eaccess(newdir, R_OK) || UNSAFE_FILEPATH(rest)) {
				res = ftp_write(node, 431, "No such directory %s\r\n", rest);
			} else {
				if (*rest == '/') {
					FTP_UPDATE_DIR(rest); /* Absolute */
				} else {
					snprintf(newdir, sizeof(newdir), "%s/%s", ftpdir, rest);
					FTP_UPDATE_DIR(newdir); /* Relative */
				}
				res = ftp_write(node, 250, "CWD successful. \"%s\" is current directory.\r\n", ftpdir);
			}
		} else if (!strcasecmp(command, "CDUP")) { /* Change to parent directory */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "SMNT")) { /* Structure Mount */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		/* Transfer Parameters */
		} else if (!strcasecmp(command, "PORT")) { /* Active Mode: Data Port */
			/* We only allow PASV (passive mode), not active mode */
			/* RFC 959 says that PORT is within the minimum implementation,
			 * so this FTP module is not technically fully RFC 959 compliant.
			 * Don't care that much about that, active mode is useless in the 21st century. */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "PASV") || !strcasecmp(command, "EPSV")) { /* Passive Mode */
			int h1, h2, h3, h4, p1, p2;
			int tmpfd;
			close_if(pasv_fd); /* In case there was an existing data channel open (but there shouldn't be...) */
			pasv_port = ftp_pasv_new(&pasv_fd);
			if (pasv_port < 0) {
				res = ftp_write(node, 425, "Failed to enter passive mode, closing control connection\r\n");
				break; /* Just give up if this failed */
			}
			/* Format is h1,h2,h3,h4,p1,p2.
			 * h1-h4 is the IP.
			 * PORT = p1*256 + p2
			 * https://www.serv-u.com/resources/tutorial/225-226-227-230-ftp-response-codes
			 *
			 * The IP is actually ignored in many cases today by the client,
			 * since if the server is behind NAT, the IP won't be meaningful to the client.
			 * It will use the port we provide, but just use the IP of the original connection
			 */

			/* Handle it in this thread, rather than launching another thread,
			 * since we really only need to handle one socket at a time. */

			if (!strcasecmp(command, "EPSV")) { /* RFC2428 Extended Passive Mode, only need the port. IPv4 and IPv6 supported. */
				res = ftp_write(node, 227, "Entering Extended Passive Mode (|||%d|)\r\n", pasv_port);
			} else {
				/* Yes, PASV only supports IPv4 */
				char *cur, *left;
				char myip[48];
				safe_strncpy(myip, our_ip, sizeof(myip));
				left = myip;
				cur = strsep(&left, ".");
				h1 = atoi(S_IF(cur));
				cur = strsep(&left, ".");
				h2 = atoi(S_IF(cur));
				cur = strsep(&left, ".");
				h3 = atoi(S_IF(cur));
				h4 = atoi(S_IF(left));
				if (!h1 || !h4) {
					/* Octets 2 and 3 could be 0, but octets 1 and 4 should not be */
					bbs_error("IP address parsing error: %s = %d,%d,%d,%d\n", our_ip, h1, h2, h3, h4);
					res = ftp_write(node, 425, "Failed to enter passive mode, closing control connection\r\n");
					break; /* Just give up if this failed */
				}
				p1 = pasv_port / 256;
				p2 = pasv_port - (p1 * 256);
				res = ftp_write(node, 227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n", h1, h2, h3, h4, p1, p2);
			}
			tmpfd = bbs_timed_accept(pasv_fd, 3500, node->ip); /* Wait 3.5 seconds for a connection from the same client (at least at the same IP) */
			if (tmpfd < 0) {
				/* Client didn't connect in time */
				bbs_warning("Client failed to open passive mode port %d in time\n", pasv_port);
			}
			/* Replace listener socket file descriptor with the accept()'d one */
			close(pasv_fd);
			pasv_fd = tmpfd;
			if (tmpfd != -1) {
				bbs_debug(5, "Client has joined the data channel on port %d\n", pasv_port);
			} else {
				break;
			}
		} else if (!strcasecmp(command, "TYPE")) { /* Representation Type */
			next = rest;
			if (!next) {
				res = ftp_write(node, 429, "Invalid type, disconnecting\r\n");
				break;
			}
			switch (*next) {
				case 'A': /* ASCII */
				case 'I': /* Image (binary) */
					type = *next;
					res = ftp_write(node, 200, "Type set to %c\r\n", type);
					break;
				default:
					res = ftp_write(node, 429, "Invalid type, disconnecting\r\n");
					break;
			}
		} else if (!strcasecmp(command, "STRU")) { /* File Structure */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "MODE")) { /* Transfer Mode */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		/* Service Commands */
		} else if (!strcasecmp(command, "RETR")) { /* Download file from server */
			char fullfile[386];
			snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, rest);
			MIN_FTP_PRIV(TRANSFER_DOWNLOAD);
			if (eaccess(fullfile, R_OK) || UNSAFE_FILEPATH(rest)) {
				res = ftp_write(node, 450, "File \"%s\" does not exist\n", rest);
			} else {
				struct stat filestat;
				FILE *fp;
				REQUIRE_PASV_FD();
				fp = fopen(fullfile, "rb");
				if (!fp) {
					res = ftp_write(node, 450, "File \"%s\" does not exist\n", rest);
					IO_ABORT(res);
					continue;
				}
				if (stat(fullfile, &filestat)) {
					bbs_warning("stat failed: %s\n", strerror(errno));
					res = ftp_write(node, 450, "File \"%s\" does not exist\n", rest);
					IO_ABORT(res);
					fclose(fp);
					continue;
				}
				if (type != 'I') { /* Binary transfer */
					/* ASCII transfers are usually just a mess anyways, always do a binary transfer */
					bbs_warning("Transfer type is '%c', but doing binary transfer anyways\n", type);
				}
				res = sendfile(pasv_fd, fileno(fp), NULL, filestat.st_size); /* More convenient and efficient than manually relaying using read/write */
				fclose(fp);
				close_if(pasv_fd); /* Close connection when done. This is the EOF that signals the client that the file transfer has completed. */
				if (res != filestat.st_size) {
					bbs_error("File transfer failed: %s\n", strerror(errno));
					res = ftp_write(node, 451, "File transfer failed\r\n");
				} else {
					res = ftp_write(node, 226, "File transfer successful\r\n");
				}
			}
		} else if (!strcasecmp(command, "STOR")) { /* Upload file to server */
			REQUIRE_PASV_FD();
			res = ftp_put(node, &pasv_fd, fulldir, rest, "w"); /* STOR will truncate */
		} else if (!strcasecmp(command, "STOU")) { /* Store unique: no clobber */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "APPE")) { /* Append (with create) */
			REQUIRE_PASV_FD();
			res = ftp_put(node, &pasv_fd, fulldir, rest, "a");
		} else if (!strcasecmp(command, "ALLO")) { /* Allocate */
			res = ftp_write(node, 202, "Command Not Relevant\r\n"); /* Ignore, don't need */
		} else if (!strcasecmp(command, "DELE")) { /* Delete */
			char fullfile[386];
			MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE);
			snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, rest);
			if (eaccess(fullfile, R_OK) || UNSAFE_FILEPATH(rest)) {
				res = ftp_write(node, 450, "File \"%s\" does not exist\n", rest);
			} else {
				if (unlink(fullfile)) {
					bbs_error("unlink failed: %s\n", strerror(errno));
					res = ftp_write(node, 451, "File deletion failed\r\n");
				} else {
					res = ftp_write(node, 226, "File deletion successful\r\n");
				}
			}
		} else if (!strcasecmp(command, "REST")) { /* Restart */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "RNFR")) { /* Rename From */
			char fullfile[386];
			MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE);
			rename_from[0] = '\0'; /* In case we issue a successful RNFR, then issue a failed one (nonexistent target), then try to rename, that should fail, so always reset */
			snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, rest);
			if (eaccess(fullfile, R_OK) || UNSAFE_FILEPATH(rest)) {
				res = ftp_write(node, 450, "File \"%s\" does not exist\n", rest);
			} else {
				safe_strncpy(rename_from, rest, sizeof(rename_from)); /* Save the target name */
				res = ftp_write(node, 226, "Filename accepted\r\n");
			}
		} else if (!strcasecmp(command, "RNTO")) { /* Rename To */
			char fullfile[596];
			char newfullfile[596];
			MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE);
			snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, rename_from);
			snprintf(newfullfile, sizeof(newfullfile), "%s/%s", fulldir, rest);
			if (s_strlen_zero(rename_from)) {
				res = ftp_write(node, 503, "Bad sequence of commands\r\n");
			} else if (eaccess(fullfile, R_OK) || UNSAFE_FILEPATH(rename_from)) {
				res = ftp_write(node, 450, "File \"%s\" does not exist\n", rename_from);
			} else if (!eaccess(newfullfile, R_OK)) {
				res = ftp_write(node, 450, "File \"%s\" already exists\n", rest);
			} else {
				if (rename(fullfile, newfullfile)) {
					res = ftp_write(node, 450, "Failed to rename \"%s\"\n", rename_from);
				} else {
					res = ftp_write(node, 226, "File renamed to \"%s\"\r\n", rest);
				}
			}
			rename_from[0] = '\0'; /* Can't be reused */
		} else if (!strcasecmp(command, "ABOR")) { /* Abort */
			/* This is technically unreachable/unexecutable, since we use a single thread currently
			 * for both the control and data channels.
			 * But if this was usable, this is what it would do: */
			REQUIRE_PASV_FD();
			/* Close data connection, which should cause the data I/O to abort */
			shutdown(pasv_fd, SHUT_RDWR); /* Don't close pasv_fd here, the actual control connection will do so. */
			res = ftp_write(node, 226, "Closed data connection\r\n");
		} else if (!strcasecmp(command, "RMD")) { /* Remove Directory */
			char fullfile[386];
			MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE);
			snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, rest);
			if (eaccess(fullfile, R_OK)) {
				res = ftp_write(node, 450, "\"%s\" does not exist\n", rest);
			} else {
				if (rmdir(fullfile)) {
					bbs_warning("rmdir failed: %s\n", strerror(errno));
					res = ftp_write(node, 451, "\"%s\" could not be deleted\n", rest);
				} else {
					res = ftp_write(node, 250, "\"%s/%s\" directory deleted.\r\n", ftpdir, rest);
				}
			}
		} else if (!strcasecmp(command, "MKD")) { /* Make Directory */
			char fullfile[386];
			MIN_FTP_PRIV(TRANSFER_NEWDIR);
			snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, rest);
			if (!eaccess(fullfile, R_OK)) {
				res = ftp_write(node, 450, "\"%s\" already exists\n", rest);
			} else {
				if (mkdir(fullfile, 0600)) {
					bbs_warning("mkdir failed: %s\n", strerror(errno));
					res = ftp_write(node, 451, "\"%s\" could not be created\n", rest);
				} else {
					res = ftp_write(node, 250, "\"%s/%s\" directory created.\r\n", ftpdir, rest);
				}
			}
		} else if (!strcasecmp(command, "PWD")) { /* Print Working Directory */
			res = ftp_write(node, 257, "\"%s\" is current directory.\r\n", ftpdir);
		} else if (!strcasecmp(command, "LIST")) { /* List files */
			/*! \todo BUGBUG FIXME XXX ls uses local timestamps, needs to be UTC. Also reveals local usernames. This should be generated directly, not exec'ed out to ls. */
			char *argv[4] = { "ls", "-l", fulldir, NULL };
			REQUIRE_PASV_FD();
			res = ftp_write(node, 125, "Listing follows for %s\r\n", ftpdir);
			bbs_debug(5, "Generating listing for %s\n", fulldir); /* Client should not know what fulldir is */
			/* The list itself goes over the data connection */
			/* According to the FTP standard itself, the LIST response
			 * is for humans, not for machines to parse.
			 * In practice, we need it to be parseable for FTP clients
			 * to know what files exist.
			 * See:
			 * - RFC 3659
			 * - https://files.stairways.com/other/ftp-list-specs-info.txt
			 * - http://cr.yp.to/ftp/list/binls.html
			 *
			 * Should be something like:
			 * -rw-r--r-- 1 owner group           213 Aug 26 16:31 README
			 */
			res = bbs_execvp_fd_headless(node, -1, pasv_fd, "/bin/ls", argv); /* Just use ls, since that's the right format */
			if (res) { /* Listing failed, just disconnect */
				break;
			}
			close_if(pasv_fd); /* Close connection when done */
			res = ftp_write(node, 226, "Action successful\r\n");
		} else if (!strcasecmp(command, "NLST")) { /* Name list */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "SYST")) { /* System */
			res = ftp_write(node, 215, "UNIX emulated by %s\r\n", BBS_SHORTNAME);
		} else if (!strcasecmp(command, "STAT")) { /* Status */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "HELP")) { /* Help */
			/* We use the control connection */
			/* It may be desirable to allow HELP prior to USER, but RFC 959 does not say this is mandatory. */
			if (strlen_zero(rest)) {
				/* List all available commands at this site */
				res = ftp_write(node, 211, "USER PASS QUIT CWD PASV EPSV TYPE RETR STOR APPE DELE RNFR RNTO RMD MKD PWD LIST SYST HELP NOOP\r\n");
			} else {
				res = ftp_write(node, 502, "Command Not Implemented\r\n"); /* 214 reply if we have help for a specific command */
			}
		} else if (!strcasecmp(command, "NOOP")) { /* No Op */
			res = ftp_write(node, 200, "OK\r\n");
		} else {
			bbs_warning("Unimplemented FTP command: %s (%s %s)\n", command, command, S_IF(rest)); /* Show the full command as well */
			res = ftp_write(node, 502, "Command Not Implemented\r\n");
		}
		if (res <= 0) {
			break;
		}
	}

cleanup:
	close_if(pasv_fd);
	bbs_node_exit(node);
	return NULL;
}

static void *ftp_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener(ftp_socket, "FTP", ftp_handler, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	if (bbs_transfer_config_load()) {
		return -1;
	}

	cfg = bbs_config_load("net_ftp.conf", 0);
	if (!cfg) {
		return -1; /* Decline to load if there is no config. */
	}

	ftp_port = DEFAULT_FTP_PORT;
	bbs_config_val_set_port(cfg, "ftp", "port", &ftp_port);

	minport = 10000;
	maxport = 20000;
	bbs_config_val_set_port(cfg, "pasv", "minport", &minport);
	bbs_config_val_set_port(cfg, "pasv", "maxport", &maxport);

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	/* If we can't start the TCP listener, decline to load */
	if (bbs_make_tcp_socket(&ftp_socket, ftp_port)) {
		return -1;
	}
	bbs_assert(ftp_socket >= 0);
	if (bbs_pthread_create(&ftp_thread, NULL, ftp_listener, NULL)) {
		close(ftp_socket);
		ftp_socket = -1;
		return -1;
	}
	bbs_register_network_protocol("FTP", ftp_port);
	return 0;
}

static int unload_module(void)
{
	if (ftp_socket > -1) {
		bbs_unregister_network_protocol(ftp_port);
		close(ftp_socket);
		ftp_socket = -1;
		pthread_cancel(ftp_thread);
		pthread_kill(ftp_thread, SIGURG);
		bbs_pthread_join(ftp_thread, NULL);
	} else {
		bbs_error("FTP socket already closed at unload?\n");
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC959 File Transfer Protocol");
