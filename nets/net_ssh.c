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
 * \brief SSH (Secure Shell)
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
#include <pthread.h>
#include <signal.h> /* use pthread_kill */
#include <sys/ioctl.h> /* use winsize */

/*
 * The SSH comm driver has dependencies on libssh and libcrypto.
 * Parts of this module based on https://github.com/jeroen/libssh/blob/master/examples/ssh_server_fork.c
 */
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

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

static pthread_t ssh_listener_thread;

/*! \brief Default SSH port is 22 */
#define DEFAULT_SSH_PORT 22

#define KEYS_FOLDER "/etc/ssh/"

/* This mainly exists so that I can test public key authentication with PuTTY/KiTTY.
 * If anonymous authentication is possible, then they will force you to use that instead.
 * So, if you're a developer using PuTTY/KiTTY to test public key auth, comment this out.
 * Otherwise, make sure this is defined to have all authentication options be available.
 */
#define ALLOW_ANON_AUTH

static int ssh_port = DEFAULT_SSH_PORT;
/* Key loading defaults */
static int load_key_rsa = 1;
static int load_key_dsa = 0;
static int load_key_ecdsa = 1;

static ssh_bind sshbind = NULL;

/*! \brief Returns 1 on success, 0 on failure (!!!) */
static int bind_key(enum ssh_bind_options_e opt, const char *filename)
{
	if (eaccess(filename, R_OK)) {
		bbs_warning("Can't access key %s - missing or not readable?\n", filename);
		return 0;
	}
	ssh_bind_options_set(sshbind, opt, KEYS_FOLDER "ssh_host_rsa_key");
	return 1;
}

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

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &ssh_port); /* Set the SSH bind port */
	if (ssh_bind_listen(sshbind) < 0) {
		bbs_error("%s\n", ssh_get_error(sshbind));
		ssh_bind_free(sshbind);
		sshbind = NULL;
		return -1;
	}
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
	/* pid of the child process the channel will spawn. */
	pid_t pid;
	/* For PTY allocation */
	socket_t pty_master;
	socket_t pty_slave;
	/* For communication with the child process. */
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
};

/* A userdata struct for session. */
struct session_data_struct {
	/* BBS user pointer */
	struct bbs_user **user;
	/* Pointer to the channel the session will allocate. */
	ssh_channel channel;
	int auth_attempts;
	int authenticated;
};

static ssh_channel channel_open(ssh_session session, void *userdata)
{
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;
	sdata->channel = ssh_channel_new(session);
	return sdata->channel;
}

/*! \brief Called when data is available from the client for the server */
static int data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

	UNUSED(session);
	UNUSED(channel);
	UNUSED(is_stderr);

	if (len == 0 || !cdata->node) {
		return 0;
	}

	/* child_stdin = pty_master (relay data from client to PTY master) */
	return write(cdata->child_stdin, (char *) data, len);
}

/*! \brief Called if the client closes the connection */
static void close_callback(ssh_session session, ssh_channel channel, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

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

/*! \brief Called when data is available from PTY master */
static int process_stdout(socket_t fd, int revents, void *userdata)
{
	int n = -1;
	ssh_channel channel = (ssh_channel) userdata;

	if (channel != NULL && (revents & POLLIN) != 0) {
#define BUF_SIZE 1048576
		char buf[BUF_SIZE];
#undef BUF_SIZE
		n = read(fd, buf, sizeof(buf));
		if (n > 0) {
			/* Relay data from PTY master to the client */
			ssh_channel_write(channel, buf, n);
		} else {
			bbs_debug(3, "len: %d\n", n);
		}
	}
	return n;
}

#ifdef ALLOW_ANON_AUTH
static int auth_none(ssh_session session, const char *user, void *userdata)
{
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;

	bbs_debug(3, "Anonymous authentication for user '%s'\n", user);

	UNUSED(user);
	UNUSED(session);

	/* We're not calling bbs_authenticate or bbs_user_authenticatehere,
	 * the user still has to authenticate for real (but will do so interactively)
	 * ... this is the "normal" way of logging in for a BBS, like with Telnet/RLogin, etc.
	 */
	sdata->authenticated = 1;
	return SSH_AUTH_SUCCESS;
}
#endif

static int auth_password(ssh_session session, const char *user, const char *pass, void *userdata)
{
	struct bbs_user *bbsuser;
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;

	UNUSED(session);

	bbs_debug(3, "Password authentication attempt for user '%s'\n", user);

	/* We can't use bbs_authenticate because node doesn't exist yet
	 * It's not even allocated until pty_request is called...
	 * and we need the PTY file descriptor at that time,
	 * so we can't create it now either.
	 * Instead, create the user now and attach it
	 * to the node when we create the PTY.
	 */

	if (strlen_zero(user) || strlen_zero(pass)) {
		sdata->auth_attempts++;
		return SSH_AUTH_DENIED;
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
		return SSH_AUTH_DENIED;
	}

	*sdata->user = bbsuser;
	sdata->authenticated = 1;
	return SSH_AUTH_SUCCESS;
}

static int pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

	UNUSED(session);
	UNUSED(channel);
	UNUSED(term);

	cdata->winsize->ws_row = rows;
	cdata->winsize->ws_col = cols;

	/* These are ignored at present, as they're not that important and don't even seem to get sent by some clients. */
	cdata->winsize->ws_xpixel = px;
	cdata->winsize->ws_ypixel = py;

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
	bbs_fd_unbuffer_input(cdata->pty_slave, 0);

	/* Make the master side raw, to pass everything unaltered to the "real" PTY, which is the node PTY */
	bbs_term_makeraw(cdata->pty_master);

	/* node->fd will be the slave from the above PTY */
	cdata->node = bbs_node_request(cdata->pty_slave, "SSH");
	if (!cdata->node) {
		return SSH_ERROR;
	}
	/* Attach the user that we set earlier.
	 * If we didn't set one, it's still NULL, so fine either way. */
	if (!bbs_node_attach_user(cdata->node, *cdata->user)) {
		cdata->userattached = 1;
	}
	save_remote_ip(session, cdata->node, NULL, 0);
	bbs_node_update_winsize(cdata->node, cols, rows);
	return SSH_OK;
}

static int pty_resize(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata)
{
	struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

	UNUSED(session);
	UNUSED(channel);

	cdata->winsize->ws_row = rows;
	cdata->winsize->ws_col = cols;

	/* These are ignored at present, as they're not that important and don't even seem to get sent by some clients. */
	cdata->winsize->ws_xpixel = px;
	cdata->winsize->ws_ypixel = py;

	/* Resist the urge to directly send a SIGWINCH signal here.
	 * bbs_node_update_winsize will do that if needed. */
	if (cdata->node) {
		/* Unlike the Telnet module, we can easily update this out of band... nice! */
		bbs_node_update_winsize(cdata->node, cols, rows);
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
	}
	cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
	/* Run the BBS on this node */
	/* Unlike other network drivers, the SSH module creates the
	 * node thread normally (not detached), so that handle_session
	 * can join the thread (and know if it has exited)
	 */
	if (bbs_pthread_create(&node->thread, NULL, bbs_node_handler, node)) {
		bbs_node_unlink(node);
		cdata->node = NULL;
		return SSH_ERROR;
	}
	node->skipjoin = 1; /* handle_session will join the node thread, bbs_node_shutdown should not */
	cdata->nodethread = node->thread;
	bbs_debug(3, "Node thread is %lu\n", cdata->nodethread);
	return SSH_OK;
}

/*! \note Works only for threads that are NOT detached */
static inline int thread_has_exited(pthread_t thread)
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
	bbs_warning("pthread_kill(%lu) = %d (%s)\n", thread, res, strerror(res));
	return 0;
}

static void handle_session(ssh_event event, ssh_session session)
{
	int n;
	int node_started = 0;
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
		.authenticated = 0
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
		.channel_subsystem_request_function = NULL, /* When client requests a subsystem, e.g. SFTP. Not needed */
	};

	struct ssh_server_callbacks_struct server_cb = {
		.userdata = &sdata,
#ifdef ALLOW_ANON_AUTH
		.auth_none_function = auth_none,
#endif
		.auth_password_function = auth_password,
		.auth_pubkey_function = auth_pubkey,
		.channel_open_request_session_function = channel_open,
	};

	/*
	 * Unlike Telnet and RLogin, the closest you can get with SSH to disabling protocol-level authentication
	 * is to allow any username, with no password. This is what SSH_AUTH_METHOD_NONE is.
	 * Clients will need to provide a username, but they'll be able to connect without getting a password prompt.
	 * Even if they specify a password, it will be ignored and anonymous authentication will be used,
	 * (at least, this is how PuTTY/KiTTY + libssh seems to work).
	 * SyncTERM, bizarrely, doesn't seem to support anonymous authentication, but it will work with password authentication.
	 * So it's okay to support both, it's just that if a client supports anonymous auth, it will always use that it seems,
	 * with no way to use password auth (at least, without using a client like SyncTERM that doesn't support anonymous auth).
	 * This could be because Synchronet BBS will login you immediately when connecting via SSH (as opposed to providing a login page),
	 * so maybe SBBS just decided to force this kind of login style for SSH.
	 *
	 * This is just how it seems to be. I would think it would make sense for PuTTY/KiTTY to disable anonymous auth
	 * if a password is specified IN ADVANCE (in the connection settings, not interactively), so that you could use both modes
	 * with a single client. Neither the behavior of PuTTY/KITTY nor SyncTERM makes much sense to me in this regard.
	 *
	 * TL;DR:
	 * SyncTERM doesn't support SSH_AUTH_METHOD_NONE (PuTTY/KiTTY do, and will force this method if available)
	 * PuTTY/KiTTY don't support SSH_AUTH_METHOD_INTERACTIVE (SyncTERM does)
	 */
#ifdef ALLOW_ANON_AUTH
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_NONE | SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE);
#else
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
#endif

	ssh_callbacks_init(&server_cb);
	ssh_callbacks_init(&channel_cb);
	ssh_set_server_callbacks(session, &server_cb);

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		bbs_error("%s\n", ssh_get_error(session));
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
		if (sdata.auth_attempts >= 3 || n >= 100) {
			return;
		}

		if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
			/* If client disconnects during login stage, this could happen.
			 * Hence, it's a warning, not an error, as it's not our fault. */
			bbs_warning("%s\n", ssh_get_error(session));
			return;
		}
		n++;
	}

	/* If we get here, it was a successful authentication (from an SSH protocol perspective) */
	ssh_set_channel_callbacks(sdata.channel, &channel_cb);
	bbs_debug(3, "Authentication has succeeded\n");

	/* Session is now running. Wait for it to finish. */
	do {
		int pollres = ssh_event_dopoll(event, -1);
		if (pollres == SSH_ERROR) {
			bbs_debug(1, "ssh_event_dopoll returned error, closing SSH channel\n");
			ssh_channel_close(sdata.channel);
			break;
		}
		/* If child thread's stdout/stderr has been registered with the event,
		 * or the child thread hasn't started yet, continue. */
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
			if (node_started && thread_has_exited(cdata.nodethread)) {
				/* The node started but disappeared, i.e. server disconnected the node.
				 * Time for us to die. */
				bbs_debug(3, "Node thread has now exited\n");
				break;
			}
			continue;
		} else if (!cdata.node) {
			bbs_debug(3, "No BBS node\n");
			continue;
		} else if (node_started) {
			bbs_error("Shouldn't happen\n");
			bbs_assert(0);
		}
		/* Executed only once, once the child thread starts. */
		cdata.event = event;
		node_started = 1;
		/* If stdout valid, add stdout to be monitored by the poll event. */
		/* Skip stderr, the BBS doesn't use it, since we're not launching a shell. */
		if (cdata.child_stdout != -1) {
			if (ssh_event_add_fd(event, cdata.child_stdout, POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL, process_stdout, sdata.channel) != SSH_OK) {
				bbs_error("Failed to register stdout to poll context\n");
				ssh_channel_close(sdata.channel);
			}
		} else {
			bbs_error("No stdout available?\n");
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
	close_if(cdata.pty_master);
	close_if(cdata.child_stdin);
	close_if(cdata.child_stdout);

	if (cdata.nodethread) {
		bbs_pthread_join(cdata.nodethread, NULL);
	}

	/* Remove the descriptors from the polling context, since they are now closed, they will always trigger during the poll calls */
	ssh_event_remove_fd(event, cdata.child_stdout);

	/* Goodbye */
	ssh_channel_send_eof(sdata.channel);
	ssh_channel_close(sdata.channel);
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
	bbs_module_ref(BBS_MODULE_SELF);
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
	bbs_module_unref(BBS_MODULE_SELF);
	return NULL;
}

static ssh_session pending_session = NULL;

static void *ssh_listener(void *unused)
{
	char ipaddr[64];
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
			bbs_error("%s\n", ssh_get_error(sshbind));
			continue;
		}
		/* Get the IP of the connecting user now, in case authentication never succeeds
		 * and we never store the IP. */
		save_remote_ip(session, NULL, ipaddr, sizeof(ipaddr));
		bbs_auth("Accepting new SSH connection from %s\n", ipaddr);
		/* Spawn a thread to handle this SSH connection. */
		if (bbs_pthread_create_detached(&ssh_thread, NULL, ssh_connection, session)) {
			ssh_disconnect(session);
			ssh_free(session);
			continue;
		}
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

	bbs_config_val_set_true(cfg, "keys", "rsa", &load_key_rsa);
	bbs_config_val_set_true(cfg, "keys", "dsa", &load_key_dsa);
	bbs_config_val_set_true(cfg, "keys", "ecdsa", &load_key_ecdsa);

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
	bbs_register_network_protocol("SSH", ssh_port);
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
	bbs_unregister_network_protocol(ssh_port);
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

BBS_MODULE_INFO_STANDARD("RFC4253 SSH (Secure Shell)");
