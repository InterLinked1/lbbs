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
 * \brief SSH (Secure Shell) and SFTP (Secure File Transfer Protocol) server
 *
 * \note Supports RFC 4251 architecture
 * \note Supports RFC 4252 authentication
 * \note Supports RFC 4253 protocol
 * \note Supports RFC 4254 protocol
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <signal.h> /* use pthread_kill */
#include <sys/ioctl.h> /* use winsize */
#include <limits.h> /* use PATH_MAX */

/*
 * The SSH driver has dependencies on libssh and libcrypto.
 * Parts of this module based on https://github.com/xbmc/libssh/blob/master/examples/ssh_server_fork.c
 */
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

/* SFTP */
#define WITH_SERVER
#include <libssh/sftp.h>
#include <dirent.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/auth.h"
#include "include/pty.h" /* use bbs_openpty */
#include "include/term.h" /* use bbs_unbuffer_input */
#include "include/utils.h"
#include "include/config.h"
#include "include/net.h"
#include "include/transfer.h"
#include "include/event.h"

static pthread_t ssh_listener_thread;

/*! \brief Default SSH port is 22 */
#define DEFAULT_SSH_PORT 22

#define KEYS_FOLDER "/etc/ssh/"

/*
 * There is no RFC officially for SFTP.
 * Version 3, working draft 2 is what we want: https://www.sftp.net/spec/draft-ietf-secsh-filexfer-02.txt
 */

static int ssh_port = DEFAULT_SSH_PORT;
static int allow_sftp = 1;

/* Key loading defaults */
static int load_key_rsa = 1;
static int load_key_dsa = 0;
static int load_key_ecdsa = 1;
static int load_key_ed25519 = 1;

static ssh_bind sshbind = NULL;

/*! \brief Returns 1 on success, 0 on failure (!!!) */
static int bind_key(enum ssh_bind_options_e opt, const char *filename)
{
	if (eaccess(filename, R_OK)) {
		bbs_warning("Can't access key %s - missing or not readable?\n", filename);
		return 0;
	}
	return ssh_bind_options_set(sshbind, opt, KEYS_FOLDER "ssh_host_rsa_key") ? 0 : 1;
}

static int start_ssh(void)
{
	int keys = 0;

	sshbind = ssh_bind_new();
	if (!sshbind) {
		bbs_error("ssh_bind_new failed\n");
		return -1;
	}

	/* Set default keys
	 * Note that all these SSH_BIND_OPTIONS enum values are aliases to SSH_BIND_OPTIONS_HOSTKEY */
	if (load_key_rsa) {
		bbs_debug(2, "Binding RSA key\n");
		keys += bind_key(SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
	}
	if (load_key_dsa) {
		bbs_debug(2, "Binding DSA key\n");
		keys += bind_key(SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
	}
	if (load_key_ecdsa) {
		bbs_debug(2, "Binding ECDSA key\n");
		keys += bind_key(SSH_BIND_OPTIONS_ECDSAKEY, KEYS_FOLDER "ssh_host_ecdsa_key");
	}
	if (load_key_ed25519) {
		bbs_debug(2, "Binding ED25519 key\n");
		keys += bind_key(SSH_BIND_OPTIONS_HOSTKEY, KEYS_FOLDER "ssh_host_ed25519_key");
	}

	if (!keys) {
		bbs_error("Failed to configure listener, unable to bind any SSH keys\n");
		/* May need to do e.g. chown <BBS run username> /etc/ssh/ssh_host_rsa_key */
		ssh_bind_free(sshbind);
		sshbind = NULL;
		return -1;
	}

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &ssh_port); /* Set the SSH bind port */
	if (ssh_bind_listen(sshbind) < 0) {
		bbs_error("%s\n", ssh_get_error(sshbind));
		ssh_bind_free(sshbind);
		sshbind = NULL;
		return -1;
	}
	bbs_verb(7, "SSH listener started using %d key%s\n", keys, ESS(keys));
	return 0;
}

/* A userdata struct for channel. */
struct channel_data_struct {
	/* BBS node */
	struct bbs_node *node;
	/* BBS user pointer */
	struct bbs_user **user;
	/* BBS node thread */
	pthread_t nodethread;
	/* pid of the child thread the channel will spawn. */
	pid_t pid;
	/* For PTY allocation */
	socket_t pty_master;
	socket_t pty_slave;
	/* For communication with the child thread. */
	socket_t child_stdin;
	socket_t child_stdout;
	/* Only used for subsystem and exec requests. */
	socket_t child_stderr;
	/* Event which is used to poll the above descriptors. */
	ssh_event event;
	/* Terminal size struct. */
	struct winsize *winsize;
	/* Flags */
	unsigned int closed:1;
	unsigned int userattached:1;
	unsigned int addedfdwatch:1;
	unsigned int sftp:1;	/*!< SFTP connection */
};

/* A userdata struct for session. */
struct session_data_struct {
	/* BBS user pointer */
	struct bbs_user **user;
	/* Pointer to the channel the session will allocate. */
	ssh_channel channel;
	int auth_attempts;
	unsigned int authenticated:1;
	unsigned int dead:1;
};

static ssh_channel channel_open(ssh_session session, void *userdata)
{
	struct session_data_struct *sdata = userdata;
	sdata->channel = ssh_channel_new(session);
	return sdata->channel;
}

/*! \brief Called when data is available from the client for the server */
static int data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
	struct channel_data_struct *cdata = userdata;

	UNUSED(session);
	UNUSED(channel);
	UNUSED(is_stderr);

	if (len == 0 || !cdata->node) {
		return 0;
	}

	/* child_stdin = pty_master (relay data from client to PTY master) */
	return (int) write(cdata->child_stdin, (char *) data, len);
}

/*! \brief Called if the client closes the connection */
static void close_callback(ssh_session session, ssh_channel channel, void *userdata)
{
	struct channel_data_struct *cdata = userdata;

	UNUSED(session);
	UNUSED(channel);
	UNUSED(userdata);
	bbs_debug(3, "Client has closed the SSH session\n");
	cdata->closed = 1;
}

static int save_remote_ip(ssh_session session, struct bbs_node *node, char *buf, size_t len)
{
	socket_t sfd;
	struct sockaddr tmp;
	struct sockaddr_in *sock;
	socklen_t socklen = sizeof(tmp);

	sfd = ssh_get_fd(session); /* Get fd of the connection */
	if (sfd < 0) {
		bbs_error("No file descriptor available for SSH session\n");
		return -1;
	}
	if (getpeername(sfd, &tmp, &socklen)) {
		bbs_error("getpeername(%d): %s\n", sfd, strerror(errno));
		return -1;
	}

	sock = (struct sockaddr_in *) &tmp;
	if (node) {
		node->sfd = sfd; /* Save actual network file descriptor for this node */
		return bbs_save_remote_ip(sock, node);
	} else if (buf) {
		return bbs_get_remote_ip(sock, buf, len);
	} else {
		return -1;
	}
}

/*! \brief Called when data is available from PTY master */
static int process_stdout(socket_t fd, int revents, void *userdata)
{
	int n = -1;
	struct session_data_struct *sdata = userdata;
	ssh_channel channel = sdata->channel;

	if (channel != NULL && (revents & POLLIN) != 0) {
#define BUF_SIZE 1048576
		char buf[BUF_SIZE];
#undef BUF_SIZE
		n = (int) read(fd, buf, sizeof(buf));
		if (n > 0) {
			/* Relay data from PTY master to the client */
			ssh_channel_write(channel, buf, (uint32_t) n);
		} else {
			bbs_debug(3, "len: %d\n", n);
		}
	} else {
#ifdef EXTRA_DEBUG
		bbs_debug(3, "channel: %p, events: %s\n", channel, poll_revent_name(revents));
#endif
		if (revents & POLLHUP) {
			sdata->dead = 1;
		}
	}
	return n;
}

static void auth_fail(ssh_session session, const char *username)
{
	struct bbs_event event;

	/* auth.c won't trigger the EVENT_NODE_LOGIN_FAILED event,
	 * since that requires a node. Do it manually. */
	memset(&event, 0, sizeof(event));
	event.type = EVENT_NODE_LOGIN_FAILED;
	if (save_remote_ip(session, NULL, event.ipaddr, sizeof(event.ipaddr))) {
		return;
	}
	if (!strlen_zero(username)) {
		safe_strncpy(event.username, username, sizeof(event.username));
	}
	bbs_event_broadcast(&event);
}

static void request_fail(const char *ip, enum bbs_event_type type)
{
	struct bbs_event event;

	/* Don't have a node, so need to dispatch manually */
	memset(&event, 0, sizeof(event));
	event.type = type;
	safe_strncpy(event.ipaddr, ip, sizeof(event.ipaddr));
	bbs_event_broadcast(&event);
}

static int auth_none(ssh_session session, const char *user, void *userdata)
{
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;

	bbs_debug(3, "Anonymous authentication for user '%s'\n", user);

	/* SSH clients first attempt to use "none" method to probe supports methods,
	 * so the most compatible thing to do is respond with success only if the
	 * requested username does not exist, and to otherwise remove 'none'
	 * from the list of supported auth methods.
	 * This is probably why RFC 4252 5.2 says servers MUST NOT list 'none' as a supported method.
	 */
	if (!strlen_zero(user) && bbs_user_exists(user)) {
		bbs_debug(2, "Requested user exists, disabling anonymous login\n");
		ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
		return SSH_AUTH_DENIED;
	}

	/* We're not calling bbs_authenticate or bbs_user_authenticatehere,
	 * the user still has to authenticate for real (but will do so interactively)
	 * ... this is the "normal" way of logging in for a BBS, like with Telnet/RLogin, etc.
	 */
	sdata->authenticated = 1;
	return SSH_AUTH_SUCCESS;
}

static int auth_password(ssh_session session, const char *user, const char *pass, void *userdata)
{
	struct bbs_user *bbsuser;
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;

	UNUSED(session);

	bbs_debug(3, "Password authentication attempt for user '%s'\n", S_IF(user));

	/* We can't use bbs_authenticate because node doesn't exist yet
	 * It's not even allocated until pty_request is called...
	 * and we need the PTY file descriptor at that time,
	 * so we can't create it now either.
	 * Instead, create the user now and attach it
	 * to the node when we create the PTY.
	 */

	if (strlen_zero(user) || strlen_zero(pass)) {
		bbs_debug(1, "Empty SSH username or password\n");
		goto fail;
	}

	if (!*sdata->user) { /* First attempt? Allocate a user. */
		bbsuser = bbs_user_request();
		if (!bbsuser) {
			return SSH_AUTH_DENIED;
		}
		*sdata->user = bbsuser;
	}

	if (!bbs_user_authenticate(*sdata->user, user, pass)) {
		sdata->authenticated = 1;
		return SSH_AUTH_SUCCESS;
	}

fail:
	auth_fail(session, user);

	sdata->auth_attempts++;
	return SSH_AUTH_DENIED;
}

static struct bbs_user *auth_by_pubkey(const char *user, struct ssh_key_struct *pubkey)
{
	struct bbs_user *bbsuser;
	char keyfile[256];
	unsigned int userid;
	int res;
	ssh_key key = NULL;

	/* Check for match. */
	bbs_debug(4, "SSH public key authentication attempt by %s\n", user);

	if (strlen_zero(bbs_transfer_rootdir())) {
		bbs_debug(2, "Transfers are disabled, public key authentication is not possible\n");
		return NULL;
	}

	userid = bbs_userid_from_username(user);
	if (!userid) {
		bbs_auth("Public key authentication failed for '%s' (no such user)\n", user);
		return NULL;
	}
	snprintf(keyfile, sizeof(keyfile), "%s/home/%u/ssh.pub", bbs_transfer_rootdir(), userid);
	if (!bbs_file_exists(keyfile)) {
		bbs_auth("Public key authentication failed for '%s' (no public key for user)\n", user);
		return NULL;
	}

	/* Actually check if key is a match. */
	res = ssh_pki_import_pubkey_file(keyfile, &key);
	/* libssh is a little finicky about formats. Keypairs generated by ssh-keygen work well.
	 * puttygen could be hit or miss. */
	if (res != SSH_OK || !key) {
		bbs_warning("Unable to import public key %s\n", keyfile);
		return NULL;
	}
	res = ssh_key_cmp(key, pubkey, SSH_KEY_CMP_PUBLIC);
	ssh_key_free(key);
	if (res) {
		return NULL;
	}

	bbsuser = bbs_user_from_userid(userid); /* XXX This doesn't update the last login timestamp */
	if (!bbsuser) {
		return NULL;
	}

	bbs_auth("Public key authentication succeeded for '%s'\n", user);
	return bbsuser;
}

static int auth_pubkey(ssh_session session, const char *user, struct ssh_key_struct *pubkey, char signature_state, void *userdata)
{
	struct bbs_user *bbsuser;
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;

	UNUSED(session);

	/* First stage: allow it to proceed */
	if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
		return SSH_AUTH_SUCCESS;
	}

	sdata->auth_attempts++;

	/* Second stage: must be valid */
	if (signature_state != SSH_PUBLICKEY_STATE_VALID) {
		return SSH_AUTH_DENIED;
	}

	bbsuser = auth_by_pubkey(user, pubkey);
	if (!bbsuser) {
		auth_fail(session, user);
		return SSH_AUTH_DENIED;
	}

	*sdata->user = bbsuser;
	sdata->authenticated = 1;
	return SSH_AUTH_SUCCESS;
}

static int get_session_sockaddr(ssh_session session, struct sockaddr *restrict saddr, struct sockaddr_in **restrict sinaddr, int *restrict sfd)
{
	socklen_t socklen = sizeof(struct sockaddr);

	*sfd = ssh_get_fd(session); /* Get fd of the connection */
	if (*sfd < 0) {
		bbs_error("No file descriptor available for SSH session\n");
		return -1;
	}
	if (getpeername(*sfd, saddr, &socklen)) {
		bbs_error("getpeername(%d): %s\n", *sfd, strerror(errno));
		return -1;
	}

	*sinaddr = (struct sockaddr_in *) saddr;
	return 0;
}

static int pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;
	struct sockaddr saddr;
	struct sockaddr_in *sinaddr;
	int sfd;

	UNUSED(channel);

	cdata->winsize->ws_row = (short unsigned int) rows;
	cdata->winsize->ws_col = (short unsigned int) cols;

	/* These are ignored at present, as they're not that important and don't even seem to get sent by some clients. */
	cdata->winsize->ws_xpixel = (short unsigned int) px;
	cdata->winsize->ws_ypixel = (short unsigned int) py;

	/* Yes, we're launching a separate PTY here.
	 * In theory, we could probably get by with just the PTY in pty.c.
	 * However, we can't just utilize the actual network socket file descriptor
	 * as node->fd for SSH, because, unlike Telnet and RLogin, we're not just
	 * reading and writing raw data, we need to encrypt and decrypt, and
	 * libssh does this for us.
	 *
	 * So, another way to do this might be to create a pipe here
	 * and connect one end of the pipe to the BBS node as node->fd.
	 * But another dedicated PTY ought to work fine too, even if a bit heavyhanded.
	 *
	 * XXX Or maybe the above is not really true. Revisit this later, once we have time for mindless optimizations.
	 */
	if (bbs_openpty(&cdata->pty_master, &cdata->pty_slave, NULL, NULL, cdata->winsize) != 0) {
		bbs_error("Failed to openpty\n");
		return SSH_ERROR;
	}

	/* Disable canonical mode and echo on this PTY slave, since these are set on the node's PTY. */
	bbs_unbuffer_input(cdata->pty_slave, 0);

	/* Make the master side raw, to pass everything unaltered to the "real" PTY, which is the node PTY */
	bbs_term_makeraw(cdata->pty_master);

	if (get_session_sockaddr(session, &saddr, &sinaddr, &sfd)) {
		return -1;
	}

	/* node->fd will be the slave from the above PTY */
	cdata->node = bbs_node_request(cdata->pty_slave, "SSH", sinaddr, sfd);
	if (!cdata->node) {
		return SSH_ERROR;
	}
	REPLACE(cdata->node->term, term);
	/* Attach the user that we set earlier.
	 * If we didn't set one, it's still NULL, so fine either way. */
	if (!bbs_node_attach_user(cdata->node, *cdata->user)) {
		cdata->userattached = 1;
	}
	bbs_node_update_winsize(cdata->node, cols, rows);
	return SSH_OK;
}

static int pty_resize(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

	UNUSED(session);
	UNUSED(channel);

	cdata->winsize->ws_row = (short unsigned int) rows;
	cdata->winsize->ws_col = (short unsigned int) cols;

	/* These are ignored at present, as they're not that important and don't even seem to get sent by some clients. */
	cdata->winsize->ws_xpixel = (short unsigned int) px;
	cdata->winsize->ws_ypixel = (short unsigned int) py;

	/* Resist the urge to directly send a SIGWINCH signal here.
	 * bbs_node_update_winsize will do that if needed. */
	if (cdata->node && !bbs_node_update_winsize(cdata->node, cols, rows)) {
		/* Unlike the Telnet module, we can easily update this out of band... nice! */
		return SSH_OK;
	}
	return SSH_ERROR;
}

static int shell_request(ssh_session session, ssh_channel channel, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;
	struct bbs_node *node = cdata->node;

	UNUSED(session);
	UNUSED(channel);

	bbs_debug(3, "SSH shell requested\n");

	if (cdata->pid > 0) {
		return SSH_ERROR;
	}

	if (cdata->pty_master == -1 || cdata->pty_slave == -1) {
		/* Client requested a shell without a pty */
		bbs_error("Client requested SSH shell without a PTY?\n");
		return SSH_ERROR;
	} else if (!node) {
		bbs_warning("No node exists for SSH connection, declining shell\n");
		return SSH_ERROR;
	}
	cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
	/* Run the BBS on this node */
	/* Unlike other network drivers, the SSH module creates the
	 * node thread normally (not detached), so that handle_session
	 * can join the thread (and know if it has exited)
	 */
	node->skipjoin = 1; /* handle_session will join the node thread, bbs_node_shutdown should not */
	if (bbs_pthread_create(&node->thread, NULL, bbs_node_handler, node)) {
		bbs_node_unlink(node);
		cdata->node = NULL;
		return SSH_ERROR;
	}
	cdata->nodethread = node->thread;
	bbs_debug(3, "Node thread is %lu\n", (unsigned long) cdata->nodethread);
	return SSH_OK;
}

static int do_sftp(struct bbs_node *node, ssh_session session, ssh_channel channel);

static int subsystem_request(ssh_session session, ssh_channel channel, const char *subsystem, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;
	struct sockaddr saddr;
	struct sockaddr_in *sinaddr;
	int sfd;

	UNUSED(channel);

	if (cdata->node) {
		bbs_error("Node already exists?\n");
		return SSH_ERROR;
	}

	if (!strcmp(subsystem, "sftp")) {
		if (!allow_sftp) {
			bbs_verb(4, "SFTP subsystem request rejected (disabled)\n");
			return SSH_ERROR;
		}

		if (!cdata->user) {
			bbs_warning("Rejecting unauthenticated SFTP access\n");
			return SSH_ERROR;
		}

		if (get_session_sockaddr(session, &saddr, &sinaddr, &sfd)) {
			return -1;
		}

		cdata->node = bbs_node_request(ssh_get_fd(session), "SFTP", sinaddr, sfd);
		if (!cdata->node) {
			return SSH_ERROR;
		}
		/* Attach the user that we set earlier.
		 * If we didn't set one, it's still NULL, so fine either way. */
		if (!bbs_node_attach_user(cdata->node, *cdata->user)) {
			cdata->userattached = 1;
		}
		bbs_debug(3, "Starting SFTP session on node %d\n", cdata->node->id);
		cdata->sftp = 1;
        return SSH_OK;
    }

	bbs_error("Unsupported subsystem: %s\n", subsystem);
    return SSH_ERROR;
}

/*! \note Works only for threads that are NOT detached */
static int thread_has_exited(pthread_t thread)
{
	int res = pthread_kill(thread, 0);
	/* res is the error number, errno is not set */
	if (!res) {
		return 0;
	}
	if (res == ESRCH) {
		return 1;
	}
	/* Unexpected return value */
	bbs_warning("pthread_kill(%lu) = %d (%s)\n", (unsigned long) thread, res, strerror(res));
	return 0;
}

static void bad_ssh_conn(const char *ipaddr)
{
	struct bbs_event event;

	/* These connections are not likely to be legitimate, so log them. We don't have a node, so manually dispatch an event */
	memset(&event, 0, sizeof(event));
	event.type = EVENT_NODE_SHORT_SESSION; /* Always consider it short, if it never set up a PTY */
	safe_strncpy(event.protname, "SSH", sizeof(event.protname));
	safe_strncpy(event.ipaddr, ipaddr, sizeof(event.ipaddr));
	bbs_event_broadcast(&event);
}

static void handle_session(ssh_event event, ssh_session session)
{
	char ipaddr[64];
	int n;
	int node_started = 0;
	int stdoutfd;
	int is_sftp = 0;
	int res;
	long int timeout; /* in seconds */
	/* We set the user when we have access to the session userdata,
	 * but we need to attach it the node when we have access to the
	 * channel userdata.
	 * So store a pointer to the actual user data on both.
	 */
	struct bbs_user *user = NULL;

	/* Structure for storing the pty size. */
	struct winsize wsize = {
		.ws_row = 0,
		.ws_col = 0,
		.ws_xpixel = 0,
		.ws_ypixel = 0
	};

	/* Our struct holding information about the channel. */
	struct channel_data_struct cdata = {
		.node = NULL,
		.user = &user,
		.pid = 0,
		.pty_master = -1,
		.pty_slave = -1,
		.child_stdin = -1,
		.child_stdout = -1,
		.child_stderr = -1,
		.event = NULL,
		.winsize = &wsize,
		.closed = 0,
		.userattached = 0,
	};

	/* Our struct holding information about the session. */
	struct session_data_struct sdata = {
		.user = &user,
		.channel = NULL,
		.auth_attempts = 0,
		.authenticated = 0,
		.dead = 0,
	};

	struct ssh_channel_callbacks_struct channel_cb = {
		.userdata = &cdata,
		.channel_pty_request_function = pty_request, /* When client requests a PTY */
		.channel_pty_window_change_function = pty_resize, /* When client requests a window change */
		.channel_shell_request_function = shell_request, /* When client requests a shell */
		.channel_data_function = data_function, /* When data is available from STDIN */
		.channel_close_function = close_callback, /* When client closes connection */
		/* We don't need these callbacks.
		 * We're a BBS, not a full SSH server that provides all the functionality of one.
		 * There are many more callbacks we don't need, that aren't all explicitly listed here as not being needed.
		 */
		.channel_exec_request_function = NULL, /* When client requests a command execution. Not needed. */
		.channel_subsystem_request_function = subsystem_request, /* When client requests a subsystem, e.g. SFTP. */
	};

	struct ssh_server_callbacks_struct server_cb = {
		.userdata = &sdata,
		.auth_none_function = auth_none,
		.auth_password_function = auth_password,
		.auth_pubkey_function = auth_pubkey,
		.channel_open_request_session_function = channel_open,
	};

	/* Get the IP of the connecting user now, in case authentication never succeeds
	 * and we never store the IP. */
	save_remote_ip(session, NULL, ipaddr, sizeof(ipaddr));
	bbs_auth("Accepting new SSH connection from %s\n", ipaddr);

	/*
	 * Unlike Telnet and RLogin, the closest you can get with SSH to disabling protocol-level authentication
	 * is to allow any username, with no password. This is what SSH_AUTH_METHOD_NONE is.
	 * Clients will need to provide a username, but they'll be able to connect without getting a password prompt,
	 * as long as the provided username doesn't exist. This is necessary since many clients (PuTTY, FileZilla, etc.)
	 * will first use 'none' to determine what auth methods are supported. If the requested user exists,
	 * we then need to remove SSH_AUTH_METHOD_NONE as a supported method and return failure to
	 * make the client authenticate with one of the other methods. For SSH terminal access,
	 * this is not necessary; we could just connect anonymously at first and have the user log in during the session,
	 * but this is necessary for SFTP since the login has to happen up front.
	 *
	 * SyncTERM, bizarrely, doesn't seem to support anonymous authentication, but it will work with password authentication.
	 * So it's okay to support both, it's just that if a client supports anonymous auth, it will always use that it seems,
	 * with no way to use password auth (at least, without using a client like SyncTERM that doesn't support anonymous auth).
	 * This could be because Synchronet BBS will login you immediately when connecting via SSH (as opposed to providing a login page),
	 * so maybe SBBS just decided to force this kind of login style for SSH.
	 *
	 * TL;DR:
	 * SyncTERM doesn't support SSH_AUTH_METHOD_NONE (PuTTY/KiTTY do, and will force this method if available)
	 * PuTTY/KiTTY don't support SSH_AUTH_METHOD_INTERACTIVE (SyncTERM does)
	 */
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_NONE | SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE);

	ssh_callbacks_init(&server_cb);
	ssh_callbacks_init(&channel_cb);
	ssh_set_server_callbacks(session, &server_cb);

	timeout = 60; /* Max 60 seconds until logged in */
	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

	/* If a client connects and just does nothing, it might just block here forever.
	 * The timeout above is to address that. */

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		/* This isn't our fault, it's the clients, and since this is typical of
		 * spammy connections, log it as a debug message. */
		bbs_debug(1, "Fatal key exchange error: %s\n", ssh_get_error(session));
		request_fail(ipaddr, EVENT_NODE_ENCRYPTION_FAILED);
		return;
	}
	if (ssh_event_add_session(event, session) != SSH_OK) {
		bbs_error("Couldn't add session to event\n");
		return;
	}

	/* Wait for authentication to happen. */
	n = 0;
	while (sdata.authenticated == 0 || sdata.channel == NULL) {
		/* If the user has used up all attempts, or if he hasn't been able to
		 * authenticate in 10 seconds (n * 100ms), disconnect. */
		if (sdata.auth_attempts >= 3 || n++ >= 100) {
			return;
		}

		if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
			/* If client disconnects during login stage, this could happen.
			 * Hence, it's not an error, as it's not our fault. */
			bbs_debug(1, "%s\n", ssh_get_error(session));
			request_fail(ipaddr, EVENT_NODE_BAD_REQUEST);
			return;
		}
	}

	/* If we get here, it was a successful authentication (from an SSH protocol perspective) */
	ssh_set_channel_callbacks(sdata.channel, &channel_cb);
	bbs_debug(3, "Authentication has succeeded\n");

	/* Increase the timeout now that the connection is established */
	timeout = 3600; /* 1 hour */
	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

	/* Session is now running. Wait for it to finish. */
	do {
		int pollres = ssh_event_dopoll(event, cdata.node ? -1 : MIN_MS(60));
		if (pollres == SSH_ERROR) {
			bbs_debug(1, "ssh_event_dopoll returned error, closing SSH channel\n");
			ssh_channel_close(sdata.channel);
			break;
		} else if (pollres) { /* Don't print out otherwise, there'll be an event for every key */
			bbs_debug(5, "SSH pollres: %d\n", pollres);
		}
		/* If child thread's stdout/stderr has been registered with the event,
		 * or the child thread hasn't started yet, continue. */
		if (sdata.dead) {
			bbs_debug(3, "Server has closed PTY, exiting\n");
			break;
		}
		if (cdata.event != NULL) {
#ifdef EXTRA_DEBUG
			bbs_debug(8, "No SSH event (pollres: %d)\n", pollres);
#endif
			/* The BBS node thread (in this module) is not detached, so we can check its status. */
			/* XXX This is kind of a hacky kludge (though it does work).
			 * It would be much better (and more efficient)
			 * to get notified if the PTY slave is closed (since the node cleanup function
			 * closes node->fd, which is the slave end of the PTY created in this module.
			 * Then we could set a flag to terminate, rather than calling pthread_kill periodically
			 * to check if the thread has finished or not. */
			if (cdata.closed) {
				bbs_debug(3, "Client disconnected\n");
				/* When we close the PTY master, that'll signal the node to die */
				break;
			}
			if (node_started && !cdata.sftp) {
				if (!cdata.nodethread) {
					/* Happens in the case that we get (and reject) an anonymous SFTP connection */
					bbs_warning("No node thread, disconnecting\n");
					break;
				} else if (thread_has_exited(cdata.nodethread)) {
					/* The node started but disappeared, i.e. server disconnected the node.
					 * Time for us to die. */
					bbs_debug(3, "Node thread has now exited\n");
					break;
				}
			}
			continue;
		} else if (!cdata.node) {
			bbs_debug(3, "No BBS node\n");
			continue;
		}
		bbs_assert(!node_started);
		/* Executed only once, once the child thread starts. */
		cdata.event = event;
		node_started = 1;

		if (cdata.sftp) {
			is_sftp = 1;
			if (cdata.node) {
				if (!bbs_user_is_registered(cdata.node->user)) {
					/* Anonymous SFTP access is technically allowed,
					 * as is anonymous FTP access. */
					bbs_debug(3, "SFTP user is not yet authenticated\n");
					if (!bbs_transfer_operation_allowed(cdata.node, TRANSFER_ACCESS, NULL)) {
						bbs_debug(3, "Anonymous access not allowed, rejecting\n");
						break;
					}
				}
				do_sftp(cdata.node, session, sdata.channel);
			} else {
				bbs_warning("Rejecting anonymous SFTP access\n");
			}
		} else {
			/* If stdout valid, add stdout to be monitored by the poll event. */
			/* Skip stderr, the BBS doesn't use it, since we're not launching a shell. */
			if (cdata.child_stdout != -1 && !cdata.addedfdwatch) {
				if (ssh_event_add_fd(event, cdata.child_stdout, POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL, process_stdout, &sdata) != SSH_OK) {
					bbs_error("Failed to register stdout to poll context\n");
					ssh_channel_close(sdata.channel);
				} else {
					cdata.addedfdwatch = 1;
				}
			} else {
				bbs_error("No stdout available?\n");
			}
		}
	} while (ssh_channel_is_open(sdata.channel));

	bbs_debug(3, "Terminating SSH session\n");
	if (user && !cdata.userattached) {
		/* If we had password auth attempts but never succeeded,
		 * we never created the PTY and attached the user to a node.
		 * Clean up the user. */
		bbs_debug(5, "Destroying user that was never attached to a node\n");
		bbs_user_destroy(user);
		user = NULL;
	}

	if (cdata.pty_master == -1 && !(cdata.node && !strcmp(cdata.node->protname, "SFTP"))) {
		bbs_auth("SSH connection from %s did not have a PTY at shutdown\n", ipaddr);
		bad_ssh_conn(ipaddr);
	}

	close_if(cdata.pty_master);
	close_if(cdata.child_stdin);
	stdoutfd = cdata.child_stdout;
	close_if(cdata.child_stdout);

	if (cdata.nodethread) {
		bbs_pthread_join(cdata.nodethread, NULL);
	}

	/* Remove the descriptors from the polling context, since they are now closed, they will always trigger during the poll calls */
	if (stdoutfd != -1 && ssh_event_remove_fd(event, stdoutfd) != SSH_OK) {
		bbs_error("Failed to free SSH event fd\n");
	}

	if (cdata.node && is_sftp) {
		bbs_node_exit(cdata.node);
	}

#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* ssh_channel_get_exit_status, string_len, string_data */
	/* Goodbye */
	ssh_channel_set_blocking(sdata.channel, 0); /* Set nonblocking, to avoid ssh_channel_close hanging */
	/* Try to cleanly end the connection */
	res = ssh_channel_send_eof(sdata.channel);
	if (res == SSH_ERROR) {
		int code = ssh_channel_get_exit_status(sdata.channel);
		bbs_error("SSH session ended uncleanly with code %d\n", code);
	}
	if (ssh_channel_is_open(sdata.channel) && !ssh_channel_is_eof(sdata.channel)) {
		/* Try to end the connection cleanly, if we can, but don't wait forever for that.
		 * Sometimes SSH sessions can also be stale, in which case we won't get an EOF
		 * (or anythiing else) from that client when we force disconnect it.
		 * Setting SO_KEEPALIVE could help slightly but doesn't eliminate this possibility. */
		char buf[512];
		int eof_waitcount = 0;
		bbs_debug(3, "Channel not EOF yet\n");
		do {
			res = ssh_channel_read(sdata.channel, buf, sizeof(buf), 0);
			if (res == SSH_ERROR) {
				int code = ssh_channel_get_exit_status(sdata.channel);
				bbs_error("SSH session ended uncleanly with code %d\n", code);
				break;
			} else if (res == SSH_EOF) {
				bbs_debug(3, "Received EOF\n");
				break;
			} else if (res) {
				bbs_debug(3, "Received %d byte%s\n", res, ESS(res));
			} else {
				bbs_debug(5, "Channel still not EOF yet\n");
			}
			if (++eof_waitcount > 200) {
				bbs_warning("SSH client still hasn't disconnected cleanly, forcibly disconnecting...\n");
				break;
			}
			usleep(250000); /* Avoid tight loop */
		} while (ssh_channel_is_open(sdata.channel) && !ssh_channel_is_eof(sdata.channel));
	}
	ssh_channel_close(sdata.channel); /* In some cases, this may be the 2nd time calling this, but shouldn't hurt */
	ssh_channel_free(sdata.channel);
}

/* === SFTP functions === */
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
	struct bbs_node *node;
	unsigned int type:1;
	unsigned int homedir:1;
};

static struct sftp_info *alloc_sftp_info(void)
{
	struct sftp_info *h = calloc(1, sizeof(*h));
	if (ALLOC_SUCCESS(h)) {
		h->offset = 0;
	}
	return h;
}

static sftp_attributes attr_from_stat(struct stat *st)
{
	sftp_attributes attr = calloc(1, sizeof(*attr));

	if (ALLOC_FAILURE(attr)) {
		return NULL;
	}

	attr->size = (uint64_t) st->st_size;
	attr->uid = (uint32_t) st->st_uid;
	attr->gid = st->st_gid;
	attr->permissions = st->st_mode;
	attr->atime = (uint32_t) st->st_atime;
	attr->mtime = (uint32_t) st->st_mtime;
	attr->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;

    return attr;
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

#define SFTP_IO_WRITE(f) (f & (SSH_FXF_WRITE | SSH_FXF_APPEND | SSH_FXF_TRUNC | SSH_FXF_EXCL | SSH_FXF_CREAT))

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

/*! \brief Single iteration of readdir callback */
static int handle_readdir(struct bbs_node *node, sftp_client_message msg)
{
	sftp_attributes attr;
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
		char usernamebuf[256];
		int userid;
		const char *user_folder_name;
		struct dirent *dir = readdir(info->dir); /* readdir is thread safe per directory stream in glibc */
		if (!dir) {
			eof = 1;
			break;
		}
		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) {
			continue;
		}
		/* Avoid double slash // at beginning when in the root directory */
		bbs_debug(4, "Have %s/%s\n", !strcmp(info->name, "/") ? "" : info->name, dir->d_name);
		/* Could do bbs_transfer_set_disk_path_relative(node, info->name, dir->d_name, file, sizeof(file)); but it's not really necessary here */
		snprintf(file, sizeof(file), "%s/%s", info->realpath, dir->d_name);
		if (info->homedir) {
			userid = atoi(dir->d_name);
			if (userid == 0) {
				strcpy(usernamebuf, "public"); /* Safe */
			} else {
				if (bbs_lowercase_username_from_userid((unsigned int) userid, usernamebuf, sizeof(usernamebuf))) {
					strcpy(usernamebuf, "");
				}
			}
		}
		user_folder_name = info->homedir ? usernamebuf : dir->d_name;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
		/* gcc complains userid could be used uninitialized with -Og */
		if (info->homedir && userid > 0 && !bbs_transfer_show_all_home_dirs()) {
#pragma GCC diagnostic pop
			char resolvbuf[256];
			if (bbs_transfer_set_disk_path_relative(node, info->name, user_folder_name, resolvbuf, sizeof(resolvbuf))) { /* Will fail for other people's home directories, which is fine, hide in listing */
				continue;
			}
		}
		if (lstat(file, &st)) {
			bbs_error("lstat(%s) failed: %s\n", file, strerror(errno));
			continue;
		}
		attr = attr_from_stat(&st);
		if (!attr) {
			continue;
		}
		i++;
		transfer_make_longname(user_folder_name, &st, longname, sizeof(longname), 0);
		sftp_reply_names_add(msg, user_folder_name, longname, attr);
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
	size_t r;
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
	if (ALLOC_FAILURE(data)) {
		sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "Allocation failed");
		return -1;
	}

	if (fseeko(info->file, (off_t) msg->offset, SEEK_SET)) {
		bbs_error("fseeko failed: %s\n", strerror(errno));
		sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "Offset failed");
		free(data);
		return -1;
	}

	r = fread(data, 1, len, info->file);
	bbs_debug(7, "read %lu bytes (len: %d)\n", r, len);
	/* XXX For some reason, we get 128 of these after the EOF, before we stop getting READ messages (???) (At least with FileZilla).
	 * Still works but probably not right */
	if (r <= 0) {
		if (feof(info->file)) {
			char userpath[256];
			struct bbs_file_transfer_event event;
			bbs_debug(4, "File transfer has completed\n");
			sftp_reply_status(msg, SSH_FX_EOF, "EOF");
			bbs_transfer_get_user_path(info->node, info->realpath, userpath, sizeof(userpath));
			event.userpath = userpath;
			event.diskpath = info->realpath;
			bbs_event_dispatch_custom(info->node, EVENT_FILE_DOWNLOAD_COMPLETE, &event);
		} else {
			handle_errno(msg);
		}
	} else {
		sftp_reply_data(msg, data, (int) r);
	}
	/* Do not respond with an OK here */
	free(data);
	return 0;
}

static int handle_write(sftp_client_message msg)
{
	size_t len;
	size_t maxuploadsize;
	struct sftp_info *info = sftp_handle(msg->sftp, msg->handle);

	/*! \todo Add support for limiting max file size upload according to bbs_transfer_max_upload_size */

	if (!info || info->type != TYPE_FILE) {
		sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "Invalid handle");
		return -1;
	}
	len = string_len(msg->data);
	if (fseeko(info->file, (off_t) msg->offset, SEEK_SET)) {
		bbs_error("fseeko failed: %s\n", strerror(errno));
		sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "Offset failed");
		return -1;
	}
	maxuploadsize = bbs_transfer_max_upload_size();
	do {
		size_t r;
		if ((size_t) ftell(info->file) + len >= maxuploadsize) {
			bbs_warning("File upload aborted (too large)\n");
			sftp_reply_status(msg, SSH_FX_BAD_MESSAGE, "File too large");
			return -1;
		}
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
#pragma GCC diagnostic pop

#define STDLIB_SYSCALL(func, ...) \
	if (func(__VA_ARGS__)) { \
		handle_errno(msg); \
	} else { \
		sftp_reply_status(msg, SSH_FX_OK, NULL); \
	}

#define SFTP_ENSURE_TRUE2(func, node, mypath) \
	if (!func(node, mypath)) { \
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
	if (ext == NULL) {
		return;
	}

	if (ext->count > 0) {
		size_t i;
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

#define CANONICALIZE_PATHS() \
	/* Clients are supposed to call REALPATH so that the server can canonicalize the actual path on disk.
	 * We just assume that's been done afterwards... */ \
	if (!realpath(mypath, buf)) { /* returns NULL on failure */ \
		bbs_debug(5, "Path '%s' not found: %s\n", mypath, strerror(errno)); \
		handle_errno(msg); \
		break; \
	} \
	bbs_debug(3, "realpath(%s) -> %s\n", mypath, buf); \
	safe_strncpy(mypath, buf, sizeof(mypath)); /* Replace mypath so we can use either */ \
	bbs_transfer_get_user_path(node, buf, userpath, sizeof(userpath)); \

#define SFTP_MAKE_PATH() \
	bbs_debug(3, "MAKE PATH(%s) '%s'\n", mypath, msg->filename); \
	bbs_transfer_get_user_path(node, mypath, userpath, sizeof(userpath)); \
	if (bbs_transfer_set_disk_path_relative(node, userpath, msg->filename, mypath, sizeof(mypath))) { \
		handle_errno(msg); \
		break; \
	} \
	CANONICALIZE_PATHS();

#define SFTP_MAKE_PATH_NOCHECK() \
	bbs_transfer_get_user_path(node, mypath, userpath, sizeof(userpath)); \
	if (bbs_transfer_set_disk_path_relative_nocheck(node, userpath, msg->filename, mypath, sizeof(mypath))) { \
		handle_errno(msg); \
		break; \
	} \
	CANONICALIZE_PATHS();

static void sftp_free_info(struct sftp_info *info)
{
	if (info->type == TYPE_DIR) {
		closedir(info->dir);
	} else {
		fclose(info->file);
	}
	free_if(info->name);
	free_if(info->realpath);
	free(info);
}

static int do_sftp(struct bbs_node *node, ssh_session session, ssh_channel channel)
{
	char mypath[PATH_MAX] = ""; /* Real disk path */
	char buf[PATH_MAX]; /* for realpath */
	sftp_session sftp;
	int res;
	FILE *fp = NULL;
	int fd;
	DIR *dir = NULL;
	struct sftp_info *info = NULL;
	ssh_string handle;
	struct stat st;
	sftp_attributes attr;

	bbs_debug(3, "Starting SFTP session on node %d\n", node->id);

	sftp = sftp_server_new(session, channel);
	if (!sftp) {
		bbs_error("Failed to create SFTP session\n");
		return SSH_ERROR;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	res = sftp_server_init(sftp); /* Initialize SFTP server */
	if (res) {
		bbs_error("sftp_server_init failed: %d\n", sftp_get_error(sftp));
		goto cleanup;
	}
#pragma GCC diagnostic pop

	bbs_transfer_set_default_dir(node, mypath, sizeof(mypath));
	for (;;) {
		char userpath[256];
		sftp_client_message msg;
		int pres = ssh_channel_poll_timeout(channel, bbs_transfer_timeout(), 0);
		if (pres <= 0) {
			bbs_debug(3, "ssh_channel_poll_timeout returned %d, terminating SFTP session\n", pres);
			break;
		}
		msg = sftp_get_client_message(sftp); /* This will block, so if we want a timeout, we need to do it beforehand */
		if (!msg) {
			break;
		}
		/* Since some operations can be for paths that may not exist currently, always use the _nocheck variant.
		 * For operations that require the path to exist, they will fail anyways on the system call. */
		bbs_debug(5, "Got SFTP client message %2d (%8s), client path: %s\n", msg->type, sftp_get_client_message_type_name(msg->type), msg->filename);
		switch (msg->type) {
			case SFTP_REALPATH:
				SFTP_MAKE_PATH();
				sftp_reply_name(msg, userpath, NULL); /* Skip root dir */
				break;
			case SFTP_OPENDIR:
				SFTP_MAKE_PATH();
				dir = opendir(mypath);
				if (!dir) {
					handle_errno(msg);
				} else if (!(info = alloc_sftp_info())) {
					handle_errno(msg);
					closedir(dir); /* Do this after so we don't mess up errno */
					dir = NULL;
				} else {
					info->dir = dir;
					info->type = TYPE_DIR;
					info->name = strdup(msg->filename);
					info->realpath = strdup(buf);
					info->node = node;
					bbs_transfer_get_user_path(node, buf, userpath, sizeof(userpath));
					info->homedir = !strcmp(userpath, "/home") || !strcmp(userpath, "/home/"); /* Are we listing all the home directories? */
					bbs_debug(4, "Opened user directory '%s' (home dir: %d)\n", userpath, info->homedir);
					handle = sftp_handle_alloc(msg->sftp, info);
					sftp_reply_handle(msg, handle);
					free(handle);
					handle = NULL;
				}
				break;
			case SFTP_OPEN:
				SFTP_MAKE_PATH_NOCHECK(); /* Might be opening a file that doesn't currently exist */
				fd = open(mypath, sftp_io_flags((int) msg->flags), msg->attr->permissions);
				if (fd < 0) {
					handle_errno(msg);
				} else {
					fp = fdopen(fd, fopen_flags(sftp_io_flags((int) msg->flags)));
					if (!(info = alloc_sftp_info())) {
						handle_errno(msg);
						close(fd); /* Do this after so we don't mess up errno */
					} else {
						struct bbs_file_transfer_event event;
						info->type = TYPE_FILE;
						info->file = fp;
						info->name = strdup(msg->filename);
						info->realpath = strdup(buf);
						info->node = node;
						handle = sftp_handle_alloc(msg->sftp, info);
						sftp_reply_handle(msg, handle);
						free(handle);
						handle = NULL;

						bbs_transfer_get_user_path(node, buf, userpath, sizeof(userpath));
						event.userpath = userpath;
						event.diskpath = buf;
						bbs_event_dispatch_custom(node, SFTP_IO_WRITE(msg->flags) ? EVENT_FILE_UPLOAD_START : EVENT_FILE_DOWNLOAD_START, &event);
					}
				}
				break;
			case SFTP_STAT:
				/* Fall through */
			case SFTP_LSTAT:
				SFTP_MAKE_PATH();
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
					if (info->type != TYPE_DIR) {
						if (SFTP_IO_WRITE(msg->flags)) { /* For downloads, we already dispatched an event */
							long int pos;
							struct bbs_file_transfer_event event;
							bbs_transfer_get_user_path(node, buf, userpath, sizeof(userpath));
							event.userpath = userpath;
							event.diskpath = buf;
							fseek(info->file, 0, SEEK_END); /* Should be at end, already, but just in case */
							pos = ftell(info->file);
							event.size = (size_t) pos;
							bbs_event_dispatch_custom(node, EVENT_FILE_UPLOAD_COMPLETE, &event);
						}
					}
					sftp_handle_remove(msg->sftp, info);
					sftp_free_info(info);
					/* These are all pointers of different types,
					 * so we can't assign them all to NULL on the same line: */
					dir = NULL;
					fp = NULL;
					info = NULL;
					sftp_reply_status(msg, SSH_FX_OK, NULL);
				}
				break;
			case SFTP_READDIR:
				handle_readdir(node, msg);
				break;
			case SFTP_READ:
				SFTP_ENSURE_TRUE2(bbs_transfer_canread, node, mypath);
				handle_read(msg);
				break;
			case SFTP_WRITE:
				SFTP_ENSURE_TRUE2(bbs_transfer_canwrite, node, mypath);
				handle_write(msg);
				break;
			case SFTP_REMOVE:
				SFTP_MAKE_PATH();
				SFTP_ENSURE_TRUE2(bbs_transfer_candelete, node, mypath);
				STDLIB_SYSCALL(unlink, mypath);
				break;
			case SFTP_MKDIR:
				SFTP_MAKE_PATH_NOCHECK();
				SFTP_ENSURE_TRUE2(bbs_transfer_canmkdir, node, mypath);
				STDLIB_SYSCALL(mkdir, mypath, 0700); /* Make directory executable, or we won't be able to create files int */
				break;
			case SFTP_RMDIR:
				SFTP_MAKE_PATH();
				SFTP_ENSURE_TRUE2(bbs_transfer_candelete, node, mypath);
				STDLIB_SYSCALL(rmdir, mypath);
				break;
			case SFTP_RENAME:
				{
					const char *newpath;
					char realnewpath[PATH_MAX];
					newpath = sftp_client_message_get_data(msg); /* According to sftp.h, rename() newpath is here */
					SFTP_MAKE_PATH();
					SFTP_ENSURE_TRUE2(bbs_transfer_candelete, node, mypath);
					if (bbs_transfer_set_disk_path_absolute_nocheck(node, newpath, realnewpath, sizeof(realnewpath))) {
						handle_errno(msg);
						break;
					}
					if (bbs_file_exists(realnewpath)) { /* If target already exists, it's a no go */
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

cleanup:
	/* Good clients should clean up normally themselves,
	 * but malicious ones shouldn't force us to leak resources. */
	if (info) {
		bbs_debug(7, "Closing info still open at SFTP session end\n");
		sftp_free_info(info);
		info = NULL;
	}
	if (fp) {
		bbs_debug(7, "Closing file still open at SFTP session end\n");
		fclose(fp);
	}
	if (dir) {
		bbs_debug(7, "Closing directory still open at SFTP session end\n");
		closedir(dir);
	}
	sftp_server_free(sftp);
	return SSH_ERROR;
}

static void *ssh_connection(void *varg)
{
	ssh_session session = varg;
	ssh_event event;

	/* Bump the ref count since, unlike other network comm drivers,
	 * we can be "in use" even while there's not a node allocated
	 * and actively using the module, e.g. pre-authentication.
	 * This is safe since this thread is detached, i.e. all the code
	 * in this function will be executed, the thread is not going
	 * to get cancelled in the middle.
	 *
	 * This way, an explicit attempt to unload this module
	 * will fail (be declined) while it's in use, whether we've
	 * allocated a node (which also refs/unrefs the module), or not.
	 */
	bbs_module_ref(BBS_MODULE_SELF, 1);
	event = ssh_event_new();
	if (!event) {
		bbs_error("Could not create SSH polling context\n");
	} else {
		/* Blocks until the SSH session ends by either
		 * this server thread or client disconnecting. */
		handle_session(event, session);
		ssh_event_free(event);
	}

	ssh_disconnect(session);
	ssh_free(session);
	bbs_module_unref(BBS_MODULE_SELF, 1);
	return NULL;
}

static ssh_session pending_session = NULL;

static void *ssh_listener(void *unused)
{
	ssh_session session; /* This is actually a pointer, even though it doesn't look like one. */

	UNUSED(unused);

	for (;;) {
		static pthread_t ssh_thread;
		pending_session = session = ssh_new();
		if (ALLOC_FAILURE(session)) {
			bbs_error("Failed to allocate SSH session\n");
			continue;
		}

		/* Blocks until there is a new incoming connection. */
		if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
			bbs_pthread_disable_cancel();
			bbs_error("%s\n", ssh_get_error(sshbind));
			bbs_pthread_enable_cancel();
			continue;
		}
		bbs_pthread_disable_cancel();
		/* Spawn a thread to handle this SSH connection. */
		if (bbs_pthread_create_detached(&ssh_thread, NULL, ssh_connection, session)) {
			ssh_disconnect(session);
			ssh_free(session);
			continue;
		}
		bbs_pthread_enable_cancel();
	}
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("net_ssh.conf", 1);

	if (!cfg) {
		/* Assume defaults if we failed to load the config (e.g. file doesn't exist). */
		return 0;
	}

	ssh_port = DEFAULT_SSH_PORT;
	bbs_config_val_set_port(cfg, "ssh", "port", &ssh_port);

	bbs_config_val_set_true(cfg, "sftp", "enabled", &allow_sftp);

	bbs_config_val_set_true(cfg, "keys", "rsa", &load_key_rsa);
	bbs_config_val_set_true(cfg, "keys", "dsa", &load_key_dsa);
	bbs_config_val_set_true(cfg, "keys", "ecdsa", &load_key_ecdsa);
	bbs_config_val_set_true(cfg, "keys", "ed25519", &load_key_ed25519);

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
	if (bbs_pthread_create(&ssh_listener_thread, NULL, ssh_listener, NULL)) {
		bbs_error("Unable to create SSH listener thread.\n");
		goto cleanup;
	}
	bbs_register_network_protocol("SSH", (unsigned int) ssh_port);
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
	bbs_unregister_network_protocol((unsigned int) ssh_port);
	bbs_debug(3, "Cleaning up libssh\n");
	bbs_pthread_cancel_kill(ssh_listener_thread);
	bbs_pthread_join(ssh_listener_thread, NULL);
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

BBS_MODULE_INFO_STANDARD("RFC4253 SSH (Secure Shell) and SFTP (Secure File Transfer Protocol)");
