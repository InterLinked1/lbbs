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
 * \note Supports RFC 4217 FTPS
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/config.h"
#include "include/auth.h"
#include "include/system.h"
#include "include/transfer.h"
#include "include/tls.h"

static int minport, maxport;

/*! \brief Default FTP port is 21 */
#define DEFAULT_FTP_PORT 21

#define DEFAULT_FTPS_PORT 990

static int ftp_port = DEFAULT_FTP_PORT;
static int ftps_port = DEFAULT_FTPS_PORT;

static int ftps_enabled = 0;

static int require_reuse = 0;

/*! \note Uses a statement expression so that we can also log all FTP responses */
#define ftp_write(ftp, code, fmt, ...) ({ bbs_debug(5, "FTP <= %d " fmt, code, ## __VA_ARGS__); bbs_writef(ftp->wfd, "%d " fmt, code, ## __VA_ARGS__); })
#define ftp_write0(ftp, code, fmt, ...) ({ bbs_debug(5, "FTP <= %d-" fmt, code, ## __VA_ARGS__); bbs_writef(ftp->wfd, "%d-" fmt, code, ## __VA_ARGS__); })
#define ftp_write_raw(ftp, fmt, ...) ({ bbs_debug(5, "FTP <= " fmt, ## __VA_ARGS__); bbs_writef(ftp->wfd, fmt, ## __VA_ARGS__); })
#define ftp_write_raw2(ftp, fmt, ...) ({ bbs_debug(5, "FTP <= " fmt, ## __VA_ARGS__); bbs_writef(ftp->wfd2, fmt, ## __VA_ARGS__); })
#define IO_ABORT(res) if (res <= 0) { goto cleanup; }

#define REQUIRE_PASV_FD() \
	if (pasv_fd == -1) { \
		res = ftp_write(ftp, 501, "Invalid command sequence\r\n"); \
		IO_ABORT(res); \
		continue; \
	}

#define MIN_FTP_PRIV(priv, fullpath) \
	if (!bbs_transfer_operation_allowed(node, priv, fullpath)) { \
		res = ftp_write(ftp, 450, "Insufficient privileges for operation\n"); \
		IO_ABORT(res); \
		continue; \
	}

struct ftp_session {
	/* Control */
	int rfd;
	int wfd;
	/* Data */
	int rfd2;
	int wfd2;
	int protbufsize;
	struct bbs_node *node;
	unsigned int securedata:1;
	unsigned int gotpbsz:1;
};

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

#define DATA_INIT() ({ \
	int __data_res = 0; \
	ftp->rfd2 = ftp->wfd2 = pasv_fd; \
	if (ftp->securedata) { \
		bbs_debug(3, "Setting up TLS on data channel\n"); \
		ssl2 = ssl_new_accept(ftp->node, pasv_fd, &ftp->rfd2, &ftp->wfd2); \
		if (!ssl2) { \
			bbs_error("Failed to create SSL\n"); \
			__data_res = -1; \
		} else if (require_reuse && !SSL_session_reused(ssl2)) { \
			bbs_warning("TLS session was not reused\n"); \
			ssl_close(ssl2); \
			ssl2 = NULL; \
			ftp->rfd2 = ftp->wfd2 = -1; \
			__data_res = -1; \
		} \
	} \
	__data_res; \
})

#define DATA_DONE(fp, fd) \
	if (fp) { \
		fclose(fp); \
	} \
	if (ssl2) { \
		ssl_close(ssl2); \
		ssl2 = NULL; \
	} \
	close_if(fd); /* Close connection when done. This is the EOF that signals the client that the file transfer has completed. */ \
	ftp->rfd2 = ftp->wfd2 = -1;

static ssize_t ftp_put(struct ftp_session *ftp, int *pasvfdptr, const char *fulldir, const char *file, const char *flags)
{
	ssize_t res = 0;
	char fullfile[386];
	char buf[512];
	FILE *fp;
	int x = 0, bytes = 0;
	SSL *ssl2 = NULL;
	int pasv_fd = *pasvfdptr;
	int maxuploadsize = bbs_transfer_max_upload_size();

	if (!bbs_transfer_canwrite(ftp->node, fulldir)) {
		return ftp_write(ftp, 450, "File uploads denied for user\n");
	}

	bbs_transfer_home_dir_init(ftp->node);
	if (bbs_transfer_set_disk_path_relative_nocheck(ftp->node, bbs_transfer_get_user_path(ftp->node, fulldir), file, fullfile, sizeof(fullfile))) {
		return ftp_write(ftp, 450, "File \"%s\" not allowed\n", file);
	}

	/* Overwriting is basically deleting and then writing, unless we're appending */
	if (!bbs_transfer_candelete(ftp->node, fulldir) && strcmp(flags, "a") && bbs_file_exists(fullfile)) {
		return ftp_write(ftp, 450, "File \"%s\" already exists and may not be overwritten\n", file);
	}

	fp = fopen(fullfile, flags);
	if (!fp) {
		return ftp_write(ftp, 451, "File \"%s\" not created\n", file);
	}

	/* Accept file upload */
	ftp_write(ftp, 150, "Proceed with data\r\n");
	if (DATA_INIT()) {
		fclose(fp);
		return -1;
	}
	for (;;) {
		res = bbs_poll(ftp->rfd2, 2000);
		if (res < 0) {
			res = 0;
			break; /* Client will close connection for EOF */
		} else if (res <= 0) {
			res = -1;
			bbs_warning("File transfer stalled, aborting\n");
			break;
		}
		res = read(ftp->rfd2, buf, sizeof(buf));
		if (res <= 0) {
			res = 0; /* End of transfer */
			break;
		}
		if (bytes + x > maxuploadsize) {
			bbs_warning("File upload aborted (too large)\n");
			res = -1;
			break;
		}
		x = fprintf(fp, "%.*s", (int) res, buf);
		if (x != res) {
			bbs_warning("Wanted to write %lu bytes but only wrote %d\n", res, x);
			res = -1;
			break;
		}
		bytes += x;
	}
	DATA_DONE(fp, *pasvfdptr);
	if (res == -1) {
		/* Can't use ternary operator here */
		if (bytes + x > maxuploadsize) {
			res = ftp_write(ftp, 451, "File too large\r\n");
		} else {
			res = ftp_write(ftp, 451, "File transfer failed\r\n");
		}
	} else {
		res = ftp_write(ftp, 226, "File transfer successful, put %d bytes\r\n", bytes);
	}
	return res;
}

static void *ftp_handler(void *varg)
{
	char buf[512];
	char username[64] = "";
	char fulldir[256];	/* Path on disk */
	char *command, *rest, *next;
	ssize_t res;
	struct bbs_node *node = varg;
	int invalids = 0;
	int pasv_port, pasv_fd = -1;
	char our_ip[48];
	char rename_from[256] = "";
	char type = 'A'; /* Default is ASCII */
	struct readline_data rldata;
	struct ftp_session ftpstack, *ftp;
	SSL *ssl = NULL, *ssl2 = NULL;

	/* This thread is running instead of the normal node handler thread */
	/* Remember, no pseudoterminal is allocated for this node! Can NOT use normal bbs_ I/O functions. */
	bbs_node_begin(node);

	if (bbs_get_local_ip(our_ip, sizeof(our_ip))) { /* Determine it just once, now */
		goto cleanup;
	}

	memset(&ftpstack, 0, sizeof(ftpstack));
	ftp = &ftpstack;
	ftp->node = node;

	/* Start TLS if we need to */
	if (!strcmp(node->protname, "FTPS")) {
		ssl = ssl_node_new_accept(node, &ftp->rfd, &ftp->wfd);
		if (!ssl) {
			goto cleanup;
		}
	} else {
		ftp->rfd = ftp->wfd = node->fd;
	}

	/* FTP uses CR LF line endings (but that's what you expected, right?) */
	res = ftp_write(ftp, 220, "Welcome to %s FTP\r\n", bbs_name()); /* Send welcome message */
	IO_ABORT(res);

	/* Initialize our directory to the transfer root */
	safe_strncpy(fulldir, bbs_transfer_rootdir(), sizeof(fulldir));

	bbs_readline_init(&rldata, buf, sizeof(buf));

	for (;;) {
		next = NULL;
		res = bbs_readline(ftp->rfd, &rldata, "\r\n", node->user ? bbs_transfer_timeout() : 15000); /* After some number of seconds of inactivity, a client times out */
		if (res <= 0) {
			break;
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
			res = ftp_write(ftp, 331, "User name okay, need password\r\n");
		} else if (!strcasecmp(command, "PASS")) {
			next = rest;
			if (s_strlen_zero(username)) { /* Never got a username first */
				res = ftp_write(ftp, 503, "Bad sequence of commands\r\n");
			} else if (strlen_zero(next)) { /* No password */
				res = ftp_write(ftp, 501, "Invalid command syntax\r\n");
			} else {
				/* Try to authenticate. */
				res = bbs_authenticate(node, username, next);
				bbs_memzero(buf, sizeof(buf)); /* Overwrite (zero out) the plain text password from memory */
				username[0] = '\0'; /* Delete the username too so it's not preset if we reauthenticate */
				if (res) {
					invalids++;
					if (invalids > 1) {
						res = ftp_write(ftp, 421, "Invalid username or password, closing control connection\r\n");
						break; /* Close connection */
					} else {
						res = ftp_write(ftp, 430, "Invalid username or password\r\n");
					}
				} else {
					MIN_FTP_PRIV(TRANSFER_ACCESS, NULL);
					res = ftp_write(ftp, 230, "Login successful\r\n"); /* If ACCT needed, reply 332 instead */
				}
			}
		} else if (!strcasecmp(command, "ACCT")) {
			res = ftp_write(ftp, 202, "Command Not Implemented, Superflous\r\n"); /* Not needed */
		} else if (!strcasecmp(command, "REIN")) { /* Reinitialize */
			if (ssl) {
				break; /* Can't go back to unencrypted, just disconnect. */
			}
			if (node->user) {
				bbs_node_logout(node);
				ftp->securedata = 0;
				res = ftp_write(ftp, 220, "Welcome to %s FTP\r\n", bbs_name()); /* Send welcome message */
			} else {
				res = ftp_write(ftp, 421, "Not currently logged in, closing control connection\r\n");
				break;
			}
		} else if (!strcasecmp(command, "QUIT")) { /* Log out and quit */
			res = ftp_write(ftp, 231, "Goodbye\r\n");
			break;
		} else if (!strcasecmp(command, "FEAT")) {
			res = ftp_write0(ftp, 211, "Extensions supported\r\n");
			res = ftp_write_raw(ftp, " AUTH TLS\r\n");
			res = ftp_write_raw(ftp, " PBSZ\r\n");
			res = ftp_write_raw(ftp, " PROT\r\n");
			res = ftp_write_raw(ftp, " MDTM\r\n");
			res = ftp_write(ftp, 211, "END\r\n");
		} else if (!strcasecmp(command, "AUTH") && !strlen_zero(rest) && !strcasecmp(rest, "TLS")) {
			/* AUTH TLS / AUTH SSL = RFC2228 opportunistic encryption */
			if (!ssl && ssl_available()) {
				res = ftp_write(ftp, 234, "Begin TLS negotiation\r\n");
				ssl = ssl_node_new_accept(node, &ftp->rfd, &ftp->wfd);
				if (!ssl) {
					bbs_error("Failed to create SSL\n");
					break; /* Just abort */
				}
				/* Must reauthorize */
				if (node->user) {
					bbs_node_logout(node);
				}
			} else {
				res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
			}
		} else if (!strcasecmp(command, "CCC")) { /* Clear Control Channel */
			if (ssl) {
				/* We don't support reverting back from encrypted to unencrypted */
				res = ftp_write(ftp, 534, "Connection may not be downgraded\r\n");
			} else {
				res = ftp_write(ftp, 533, "Connection is not encrypted\r\n");
			}
		} else if (!node->user) {
			/* All subsequent commands require authentication */
			bbs_warning("Node %d issued FTP %s without authentication\n", node->id, command);
			res = ftp_write(ftp, 530, "Not Logged In\r\n");
		} else if (!strcasecmp(command, "CWD")) { /* Change working directory */
			if (bbs_transfer_set_disk_path_relative(node, bbs_transfer_get_user_path(node, fulldir), rest, fulldir, sizeof(fulldir))) {
				res = ftp_write(ftp, 431, "No such directory %s\r\n", rest);
			} else {
				res = ftp_write(ftp, 250, "CWD successful. \"%s\" is current directory.\r\n", bbs_transfer_get_user_path(node, fulldir));
			}
		} else if (!strcasecmp(command, "CDUP")) { /* Change to parent directory */
			if (bbs_transfer_set_disk_path_up(node, fulldir, fulldir, sizeof(fulldir))) {
				res = ftp_write(ftp, 431, "Can't move up directories\r\n");
			} else {
				res = ftp_write(ftp, 250, "CDUP successful. \"%s\" is current directory.\r\n", bbs_transfer_get_user_path(node, fulldir));
			}
		} else if (!strcasecmp(command, "SMNT")) { /* Structure Mount */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		/* Transfer Parameters */
		} else if (!strcasecmp(command, "PBSZ")) { /* Protection Buffer Size */
			int tmp;
			if (strlen_zero(rest)) {
				bbs_warning("Missing PBSZ argument\n");
				break;
			}
			tmp = atoi(rest);
			if (tmp < 0 || tmp > (2^32)) { /* 0 is allowed by RFC 4217 */
				res = ftp_write(ftp, 501, "Argument not valid\r\n");
				continue;
			}
			if (!ssl) {
				res = ftp_write(ftp, 503, "Security data exchange not completed\r\n");
				continue;
			}
			ftp->protbufsize = MIN(tmp, 0); /* XXX Right value from OpenSSL? Most clients will use "0" anyways, so... */
			ftp->gotpbsz = 1;
			res = ftp_write(ftp, 200, "PBSZ=%d\r\n", ftp->protbufsize);
		} else if (!strcasecmp(command, "PROT")) { /* Set Encryption for Data Connection */
			if (strlen_zero(rest)) {
				bbs_warning("Missing PROT argument\n");
				break;
			}
			if (!ftp->gotpbsz) { /* By extension, this connection must also be encrypted for this to be true */
				res = ftp_write(ftp, 503, "PBSZ first\r\n");
				continue;
			}
			switch (*rest) {
				case 'C': /* Clear */
					ftp->securedata = 0;
					res = ftp_write(ftp, 200, "Data will not be encrypted\r\n");
					break;
				case 'P': /* Private */
					ftp->securedata = 1;
					res = ftp_write(ftp, 200, "Data will be encrypted\r\n");
					break;
				case 'S': /* Safe */
				case 'E': /* Confidential */
				default:
					bbs_warning("Invalid PROT argument: %c\n", *rest);
					break;
			}
		} else if (!strcasecmp(command, "PORT")) { /* Active Mode: Data Port */
			/* We only allow PASV (passive mode), not active mode */
			/* RFC 959 says that PORT is within the minimum implementation,
			 * so this FTP module is not technically fully RFC 959 compliant.
			 * Don't care that much about that, active mode is useless in the 21st century. */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "PASV") || !strcasecmp(command, "EPSV")) { /* Passive Mode */
			int tmpfd;
			close_if(pasv_fd); /* In case there was an existing data channel open (but there shouldn't be...) */
			if (ssl2) {
				ssl_close(ssl2);
				ssl2 = NULL;
			}
			pasv_port = ftp_pasv_new(&pasv_fd);
			if (pasv_port < 0) {
				res = ftp_write(ftp, 425, "Failed to enter passive mode, closing control connection\r\n");
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
				res = ftp_write(ftp, 227, "Entering Extended Passive Mode (|||%d|)\r\n", pasv_port);
			} else {
				int h1, h2, h3, h4, p1, p2;
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
				if (!h1) {
					/* Octets 2, 3, and 4 could be 0, but octet 1 should not be */
					bbs_error("IP address parsing error: %s = %d,%d,%d,%d\n", our_ip, h1, h2, h3, h4);
					res = ftp_write(ftp, 425, "Failed to enter passive mode, closing control connection\r\n");
					break; /* Just give up if this failed */
				}
				p1 = pasv_port / 256;
				p2 = pasv_port - (p1 * 256);
				res = ftp_write(ftp, 227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n", h1, h2, h3, h4, p1, p2);
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
				res = ftp_write(ftp, 429, "Invalid type, disconnecting\r\n");
				break;
			}
			switch (*next) {
				case 'A': /* ASCII */
				case 'I': /* Image (binary) */
					type = *next;
					res = ftp_write(ftp, 200, "Type set to %c\r\n", type);
					break;
				default:
					res = ftp_write(ftp, 429, "Invalid type, disconnecting\r\n");
					break;
			}
		} else if (!strcasecmp(command, "STRU")) { /* File Structure */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "MODE")) { /* Transfer Mode */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		/* Service Commands */
		} else if (!strcasecmp(command, "RETR")) { /* Download file from server */
			char fullfile[386];
			if (bbs_transfer_set_disk_path_relative(node, bbs_transfer_get_user_path(node, fulldir), rest, fullfile, sizeof(fullfile))) {
				res = ftp_write(ftp, 450, "File \"%s\" does not exist\n", rest);
			} else {
				struct stat filestat;
				FILE *fp;
				MIN_FTP_PRIV(TRANSFER_DOWNLOAD, fullfile);
				REQUIRE_PASV_FD();
				fp = fopen(fullfile, "rb");
				if (!fp) {
					res = ftp_write(ftp, 450, "File \"%s\" does not exist\n", rest);
					IO_ABORT(res);
					continue;
				}
				if (stat(fullfile, &filestat)) {
					bbs_warning("stat failed: %s\n", strerror(errno));
					res = ftp_write(ftp, 450, "File \"%s\" does not exist\n", rest);
					IO_ABORT(res);
					fclose(fp);
					continue;
				}
				if (type != 'I') { /* Binary transfer */
					/* ASCII transfers are usually just a mess anyways, always do a binary transfer */
					bbs_warning("Transfer type is '%c', but doing binary transfer anyways\n", type);
				}
				ftp_write(ftp, 150, "Proceeding with data\r\n");
				if (DATA_INIT()) {
					break;
				}
				res = (int) bbs_sendfile(ftp->wfd2, fileno(fp), NULL, (size_t) filestat.st_size); /* More convenient and efficient than manually relaying using read/write */
				DATA_DONE(fp, pasv_fd);
				if (res != filestat.st_size) {
					bbs_error("File transfer failed: %s\n", strerror(errno));
					res = ftp_write(ftp, 451, "File transfer failed\r\n");
				} else {
					res = ftp_write(ftp, 226, "File transfer successful\r\n");
				}
			}
		} else if (!strcasecmp(command, "LIST")) { /* List files */
			struct dirent *dir;
			struct stat st;
			char file[1024];
			char longname[PATH_MAX];
			DIR *mydir;
			int len;
			const char *userpath = bbs_transfer_get_user_path(node, fulldir);

			REQUIRE_PASV_FD();
			res = ftp_write(ftp, 125, "Listing follows for %s\r\n", userpath);
			if (DATA_INIT()) {
				break;
			}
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
			mydir = opendir(fulldir);
			while ((dir = readdir(mydir))) { /* XXX This is not thread safe */
				if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) {
					continue;
				}
				/* Could do bbs_transfer_set_disk_path_relative(node, info->name, dir->d_name, file, sizeof(file)); but it's not really necessary here */
				snprintf(file, sizeof(file), "%s/%s/%s", bbs_transfer_rootdir(), userpath, dir->d_name);
				if (bbs_transfer_set_disk_path_relative(node, userpath, dir->d_name, file, sizeof(file))) { /* Will fail for other people's home directories, which is fine, hide in listing */
					continue;
				}
				if (lstat(file, &st)) {
					bbs_error("lstat failed: %s\n", strerror(errno));
					continue;
				}
				len = transfer_make_longname(dir->d_name, &st, longname, sizeof(longname), 1);
				ftp_write_raw2(ftp, "%s\r\n", longname);
				if (len) {
				}
			}
			closedir(mydir);
			DATA_DONE(NULL, pasv_fd);
			res = ftp_write(ftp, 226, "Action successful\r\n");
		} else if (!strcasecmp(command, "MDTM")) { /* File Modification Time - RFC 3659 */
			/* CoreFTP also attempts to send MDTM to send the modification time of an uploaded file,
			 * but that should be MFMT, not MDTM. */
			char fullfile[512];
			struct stat st;
			if (strlen_zero(next)) {
				break;
			}
			snprintf(fullfile, sizeof(fullfile), "%s/%s", fulldir, rest);
			if (stat(fullfile, &st)) {
				res = ftp_write(ftp, 550, "No such file\r\n");
			} else {
				struct tm modtime;
				char timebuf[35];
				localtime_r(&st.st_mtim.tv_sec, &modtime);
				strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", &modtime);
				res = ftp_write(ftp, 213, "%s\r\n", timebuf);
			}
		} else if (!strcasecmp(command, "STOR")) { /* Upload file to server */
			REQUIRE_PASV_FD();
			res = ftp_put(ftp, &pasv_fd, fulldir, rest, "w"); /* STOR will truncate */
			close_if(pasv_fd); /* Close connection when done. This is the EOF that signals the client that the file transfer has completed. */
			ftp->rfd2 = ftp->wfd2 = -1;
		} else if (!strcasecmp(command, "STOU")) { /* Store unique: no clobber */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "APPE")) { /* Append (with create) */
			REQUIRE_PASV_FD();
			res = ftp_put(ftp, &pasv_fd, fulldir, rest, "a");
			close_if(pasv_fd); /* Close connection when done. This is the EOF that signals the client that the file transfer has completed. */
		} else if (!strcasecmp(command, "ALLO")) { /* Allocate */
			res = ftp_write(ftp, 202, "Command Not Relevant\r\n"); /* Ignore, don't need */
		} else if (!strcasecmp(command, "DELE")) { /* Delete */
			char fullfile[386];
			if (bbs_transfer_set_disk_path_relative(node, bbs_transfer_get_user_path(node, fulldir), rest, fullfile, sizeof(fullfile))) {
				res = ftp_write(ftp, 450, "File \"%s\" does not exist\n", rest);
			} else {
				MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE, fullfile);
				if (unlink(fullfile)) {
					bbs_error("unlink failed: %s\n", strerror(errno));
					res = ftp_write(ftp, 451, "File deletion failed\r\n");
				} else {
					res = ftp_write(ftp, 226, "File deletion successful\r\n");
				}
			}
		} else if (!strcasecmp(command, "REST")) { /* Restart */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "RNFR")) { /* Rename From */
			char fullfile[386];
			rename_from[0] = '\0'; /* In case we issue a successful RNFR, then issue a failed one (nonexistent target), then try to rename, that should fail, so always reset */
			/* The rename from target has to exist, so using set_disk_path is okay (since that verifies the path exists) */
			if (bbs_transfer_set_disk_path_relative(node, bbs_transfer_get_user_path(node, fulldir), rest, fullfile, sizeof(fullfile))) {
				res = ftp_write(ftp, 450, "File \"%s\" does not exist\n", rest);
			} else {
				MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE, fullfile);
				safe_strncpy(rename_from, rest, sizeof(rename_from)); /* Save the target name */
				res = ftp_write(ftp, 226, "Filename accepted\r\n");
			}
		} else if (!strcasecmp(command, "RNTO")) { /* Rename To */
			char fullfile[596];
			char newfullfile[596];
			if (s_strlen_zero(rename_from)) {
				res = ftp_write(ftp, 503, "Bad sequence of commands\r\n");
			} else if (bbs_transfer_set_disk_path_relative(node, bbs_transfer_get_user_path(node, fulldir), rename_from, fullfile, sizeof(fullfile))) {
				res = ftp_write(ftp, 450, "File \"%s\" does not exist\n", rename_from);
			/* Use bbs_transfer_set_disk_file_relative since we don't want to require that the target file exists (in fact, it must not) */
			} else if (bbs_transfer_set_disk_path_relative_nocheck(node, bbs_transfer_get_user_path(node, fulldir), rest, newfullfile, sizeof(newfullfile))) {
				res = ftp_write(ftp, 450, "File \"%s\" cannot be the new target\n", rest);
			} else if (bbs_file_exists(newfullfile)) {
				res = ftp_write(ftp, 450, "File \"%s\" already exists\n", rest);
			} else {
				MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE, fullfile);
				if (rename(fullfile, newfullfile)) {
					res = ftp_write(ftp, 450, "Failed to rename \"%s\"\n", rename_from);
				} else {
					res = ftp_write(ftp, 226, "File renamed to \"%s\"\r\n", rest);
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
			res = ftp_write(ftp, 226, "Closed data connection\r\n");
		} else if (!strcasecmp(command, "RMD")) { /* Remove Directory */
			char fullfile[386];
			if (bbs_transfer_set_disk_path_relative(node, bbs_transfer_get_user_path(node, fulldir), rest, fullfile, sizeof(fullfile))) {
				res = ftp_write(ftp, 450, "\"%s\" does not exist\n", rest);
			} else {
				MIN_FTP_PRIV(TRANSFER_DESTRUCTIVE, fullfile);
				if (rmdir(fullfile)) {
					bbs_warning("rmdir failed: %s\n", strerror(errno));
					res = ftp_write(ftp, 451, "\"%s\" could not be deleted\n", rest);
				} else {
					res = ftp_write(ftp, 250, "\"%s/%s\" directory deleted.\r\n", bbs_transfer_get_user_path(node, fullfile), rest);
				}
			}
		} else if (!strcasecmp(command, "MKD")) { /* Make Directory */
			char fullfile[386];
			if (bbs_transfer_set_disk_path_relative_nocheck(node, bbs_transfer_get_user_path(node, fulldir), rest, fullfile, sizeof(fullfile))) {
				res = ftp_write(ftp, 450, "\"%s\" already exists\n", rest);
			} else if (bbs_file_exists(fullfile)) {
				res = ftp_write(ftp, 450, "\"%s\" already exists\n", rest);
			} else {
				MIN_FTP_PRIV(TRANSFER_NEWDIR, fullfile);
				if (mkdir(fullfile, 0600)) {
					bbs_warning("mkdir failed: %s\n", strerror(errno));
					res = ftp_write(ftp, 451, "\"%s\" could not be created\n", rest);
				} else {
					res = ftp_write(ftp, 250, "\"%s/%s\" directory created.\r\n", bbs_transfer_get_user_path(node, fullfile), rest);
				}
			}
		} else if (!strcasecmp(command, "PWD")) { /* Print Working Directory */
			res = ftp_write(ftp, 257, "\"%s\" is current directory.\r\n", bbs_transfer_get_user_path(node, fulldir));
		} else if (!strcasecmp(command, "NLST")) { /* Name list */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "SYST")) { /* System */
			res = ftp_write(ftp, 215, "UNIX emulated by %s\r\n", BBS_SHORTNAME);
		} else if (!strcasecmp(command, "STAT")) { /* Status */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		} else if (!strcasecmp(command, "HELP")) { /* Help */
			/* We use the control connection */
			/* It may be desirable to allow HELP prior to USER, but RFC 959 does not say this is mandatory. */
			if (strlen_zero(rest)) {
				/* List all available commands at this site */
				res = ftp_write(ftp, 211, "USER PASS AUTH FEAT PBSZ PROT CCC QUIT CWD PASV EPSV TYPE RETR STOR APPE DELE RNFR RNTO RMD MKD PWD LIST SYST HELP NOOP\r\n");
			} else {
				res = ftp_write(ftp, 502, "Command Not Implemented\r\n"); /* 214 reply if we have help for a specific command */
			}
		} else if (!strcasecmp(command, "NOOP")) { /* No Op */
			res = ftp_write(ftp, 200, "OK\r\n");
		} else {
			bbs_warning("Unimplemented FTP command: %s (%s %s)\n", command, command, S_IF(rest)); /* Show the full command as well */
			res = ftp_write(ftp, 502, "Command Not Implemented\r\n");
		}
		if (res <= 0) {
			break;
		}
	}

cleanup:
	close_if(pasv_fd);
	if (ssl2) {
		ssl_close(ssl2);
		ssl2 = NULL;
	}
	if (ssl) {
		ssl_close(ssl);
		ssl = NULL;
	}
	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	if (!bbs_transfer_available()) {
		bbs_error("Transfers are disabled\n");
		return -1;
	}

	cfg = bbs_config_load("net_ftp.conf", 0);
	if (!cfg) {
		return -1; /* Decline to load if there is no config. */
	}

	ftp_port = DEFAULT_FTP_PORT;
	bbs_config_val_set_port(cfg, "ftp", "port", &ftp_port);

	ftps_port = DEFAULT_FTPS_PORT;
	bbs_config_val_set_true(cfg, "ftps", "enabled", &ftps_enabled);
	bbs_config_val_set_port(cfg, "ftps", "port", &ftps_port);
	bbs_config_val_set_true(cfg, "ftps", "requirereuse", &require_reuse);

	minport = 10000;
	maxport = 20000;
	bbs_config_val_set_port(cfg, "pasv", "minport", &minport);
	bbs_config_val_set_port(cfg, "pasv", "maxport", &maxport);

	if (ftps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, FTPS may not be used\n");
		return -1;
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	/* If we can't start the TCP listener, decline to load */
	return bbs_start_tcp_listener3(ftp_port, ftps_enabled ? ftps_port : 0, 0, "FTP", "FTPS", NULL, ftp_handler);
}

static int unload_module(void)
{
	bbs_stop_tcp_listener(ftp_port);
	if (ftps_enabled) {
		bbs_stop_tcp_listener(ftps_port);
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC959 File Transfer Protocol");
