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
 * \brief Asterisk Manager Interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <cami/cami.h>

#define MIN_VERSION_REQUIRED SEMVER_VERSION(0,4,0)
#if !defined(CAMI_VERSION_MAJOR)
#error "libcami version too old"
#elif SEMVER_VERSION(CAMI_VERSION_MAJOR, CAMI_VERSION_MINOR, CAMI_VERSION_PATCH) < MIN_VERSION_REQUIRED
#pragma message "libcami version " XSTR(CAMI_VERSION_MAJOR) "." XSTR(CAMI_VERSION_MINOR) "." XSTR(CAMI_VERSION_PATCH) " too old"
#endif

#include "include/module.h"
#include "include/startup.h"
#include "include/config.h"
#include "include/alertpipe.h"
#include "include/linkedlists.h"
#include "include/cli.h"
#include "include/node.h"
#include "include/utils.h"

#include "include/mod_asterisk_ami.h"

struct ami_callback {
	int (*callback)(struct ami_event *event, const char *eventname);
	void *mod;
	RWLIST_ENTRY(ami_callback) entry;
};

static RWLIST_HEAD_STATIC(callbacks, ami_callback);

struct bbs_ami_session {
	struct ami_session *session;
	int logfd;
	unsigned int loglevel;
	unsigned int asterisk_up:1;
	unsigned int reconnecting:1;
	unsigned int post_reconnect:1;
	unsigned int dead:1;
	unsigned int loggedin:1;
	unsigned int authfailure:1;	/* Credentials rejected */
	unsigned int tls:1;	/* Connection configured for TLS encryption */
	int port;	/* AMI port */
	/* These next 4 fields are only used for encrypted connections: */
	int fd;
	int rfd;
	int wfd;
	struct bbs_io_transformations trans;
	pthread_t amithread;
	RWLIST_ENTRY(bbs_ami_session) entry;
	/* Connection information */
	const char *name; /* Session name */
	char hostname[256]; /* AMI hostname */
	char username[64]; /* AMI username */
	char password[92]; /* AMI password */
	char logfile[512]; /* AMI log file */
	char data[];
};

static RWLIST_HEAD_STATIC(sessions, bbs_ami_session);

/*! \note Must be called locked */
static struct bbs_ami_session *find_named_session(const char *name)
{
	struct bbs_ami_session *ami;
	RWLIST_TRAVERSE(&sessions, ami, entry) {
		if (!name) {
			return ami; /* If there is no name, then the default session is the first session (we do a tail insert so it'll be at the head) */
		}
		if (!strcasecmp(name, ami->name)) {
			return ami;
		}
	}
	if (name) {
		bbs_warning("Couldn't find named AMI session '%s'\n", name);
	} else {
		bbs_warning("Couldn't find any AMI session\n");
	}
	return NULL;
}

static int wait_for_reconnect_finish(struct bbs_ami_session *ami)
{
	int i;
	/* Wait up to 5 seconds for reconnect to finish, otherwise reject.
	 * This reduces the number of requests that need to be outright rejected during a reconnect.
	 * Additionally, it ensures module reloads go smoothly; mod_asterisk_queues
	 * makes an AMI query when it loads after startup, and will decline to load if it cannot do it.
	 * Since it may take a second for clients to finish starting up, we queue for a few seconds. */
	bbs_debug(3, "Queuing AMI action until reconnect finishes\n");
	for (i = 0; i < 100; i++) {
		RWLIST_UNLOCK(&sessions); /* Release lock while waiting */
		usleep(50000); /* Wait 50 ms at a time */
		RWLIST_RDLOCK(&sessions);
		if (!ami->reconnecting) {
			/* We are no longer reconnecting, woo hoo! */
			bbs_debug(3, "Unqueued AMI action, reconnect finished\n");
			return 0;
		}
	}
	bbs_warning("Rejecting AMI action, active reconnect in progress\n");
	return -1; /* Failed */
}

static int wait_for_session_creation(struct bbs_ami_session *ami)
{
	int i;
	/* Similar to above, but wait for session creation, in case the module just loaded. */
	bbs_debug(3, "Waiting for AMI session to start\n");
	for (i = 0; i < 200; i++) {
		RWLIST_UNLOCK(&sessions); /* Release lock while waiting */
		usleep(50000); /* Wait 50 ms at a time */
		RWLIST_RDLOCK(&sessions);
		if (ami->session && ami->loggedin) {
			/* We are no longer reconnecting, woo hoo! */
			bbs_debug(3, "Unqueued AMI action, session created\n");
			return 0;
		}
	}
	bbs_warning("Rejecting AMI action, no manager session active\n");
	return -1; /* Failed */
}

/* If we're in the middle of a reconnect, we can't do anything
 * Queue momentarily, in case the connection comes back up soon; that way, the request
 * is simply delayed, not rejected (we unlock the list,
 * sleep a little bit, then relock and check, with a timeout). */
#define RECONNECT_CHECKS() \
	if (ami->reconnecting) { \
		if (wait_for_reconnect_finish(ami)) { \
			goto cleanup; \
		} \
	} \
	if (!ami->session) { \
		if (wait_for_session_creation(ami)) { \
			goto cleanup; \
		} \
	}

/* Start with a { so that we have our own scope for declaring the ami variable */
#define AMI_SESSION_CALL_START() { \
	struct bbs_ami_session *ami; \
	RWLIST_RDLOCK(&sessions); \
	ami = find_named_session(session_name); \
	if (!ami) { \
		goto cleanup; \
	} \
	RECONNECT_CHECKS();

/* Use this variant if you promise you won't try to access ami->session */
#define AMI_SESSION_CALL_START_SESSIONLESS() { \
	struct bbs_ami_session *ami; \
	RWLIST_RDLOCK(&sessions); \
	ami = find_named_session(session_name); \
	if (!ami) { \
		goto cleanup; \
	}

#define AMI_SESSION_CALL_END() } \
cleanup: \
	RWLIST_UNLOCK(&sessions);

struct ami_response * __attribute__ ((format (printf, 3, 4))) bbs_ami_action(const char *session_name, const char *action, const char *fmt, ...)
{
	struct ami_response *resp = NULL;
	va_list ap;

	/* This is a wrapper around libcami's ami_action to ensure safety.
	 * We can't directly expose ami_session to other modules, because it could be NULL.
	 * They could do a NULL check, but that would be a TOCTOU race condition.
	 * We need to guarantee that the session will remain valid while it's being used.
	 *
	 * Hence, we need our own wrapper for each CAMI function we want to use.
	 *
	 * If each module had its own independent AMI session (as it used to), we wouldn't
	 * have this problem.
	 *
	 * Here, we keep the sessions list locked, to ensure that ami_session can't become
	 * NULL while we're using it (in case of a reconnect). */

	AMI_SESSION_CALL_START();
	va_start(ap, fmt);
	resp = ami_action_va(ami->session, action, fmt, ap); /* Use ami_action_va, to avoid an additional vasprintf allocation */
	va_end(ap);
	AMI_SESSION_CALL_END();

	return resp;
}

int bbs_ami_action_setvar(const char *session_name, const char *variable, const char *value, const char *channel)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_setvar(ami->session, variable, value, channel);
	AMI_SESSION_CALL_END();

	return res;
}

int bbs_ami_action_getvar_buf(const char *session_name, const char *variable, const char *channel, char *buf, size_t len)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_getvar_buf(ami->session, variable, channel, buf, len);
	AMI_SESSION_CALL_END();

	return res;
}

int bbs_ami_action_response_result(const char *session_name, struct ami_response *resp)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_response_result(ami->session, resp);
	AMI_SESSION_CALL_END();

	return res;
}

char *bbs_ami_action_getvar(const char *session_name, const char *variable, const char *channel)
{
	char *var = NULL;

	AMI_SESSION_CALL_START();
	var = ami_action_getvar(ami->session, variable, channel);
	AMI_SESSION_CALL_END();

	return var;
}

int bbs_ami_action_redirect(const char *session_name, const char *channel, const char *context, const char *exten, const char *priority)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_redirect(ami->session, channel, context, exten, priority);
	AMI_SESSION_CALL_END();

	return res;
}

int bbs_ami_softmodem_get_callerid(struct bbs_node *node, char *numberbuf, size_t num_len, char *namebuf, size_t name_len)
{
	int i;
	const char *number = NULL, *name = NULL;
	struct ami_response *resp;

	*numberbuf = '\0';
	*namebuf = '\0';

	/*
	 * The sender is not sent as part of the payload itself via TCP.
	 * We need to query the phone system for the caller's number/name.
	 * If the Asterisk softmodem is being used, we need to figure this out from Asterisk.
	 *
	 * We can correlate the sessions because on our end, we know the TCP port number on the client side,
	 * as opened by the Softmodem application. The Softmodem application can therefore save this
	 * information on the channel, and we can look for a channel that has the correct port number saved.
	 *
	 * If we cannot determine the caller information, the application can reject the connection.
	 * In that sense, it also functions as a partial security check, since it requires the connecting port
	 * to be used by the softmodem (though the IP address itself is not checked here).
	 */

	/* XXX Only the default session is supported by this function - should this be extended to allow session name to be passed in?
	 * The thing is, even if multiple Asterisk systems were pointed at the BBS, we wouldn't inherently know
	 * from which server the connection originated. (Unless the public/private IP makes it unambiguous,
	 * but this is not guaranteed to be the case, since the IP/hostname we use to connect to the Asterisk server
	 * may not be the same one that we see for incoming connections, although in most cases, it probably would be.)
	 *
	 * If we don't know for sure which server sent the call to us, in theory, there could be multiple
	 * connections on the same remote port on two different servers, so we can't even necessarily
	 * query them all.
	 *
	 * Regardless, there isn't much point in exposing the session name option to dependent modules, since
	 * they would have to determine, based on the incoming IP, which session name to use.
	 * In that case, we may as well do that here, if we decide to add multi-session support in the future,
	 * i.e. based on node->ip, determine which AMI session corresponds to the connection, and then
	 * use that here. So whether or not we add multi-session support, not much point in adding the session name
	 * as a parameter to this function, since callers won't know or won't care. */
	resp = bbs_ami_action(NULL, "SoftmodemSessions", "Port:%u", node->rport);
	if (!resp || !resp->success) {
		bbs_warning("Failed to get caller info\n");
		if (resp) {
			ami_resp_free(resp);
		}
		return -1;
	}

	/* Since we applied a filter for only port node->rport, we'll only get back one session, at most */
	for (i = 1; i < resp->size - 1; i++) {
		struct ami_event *e = resp->events[i];
		const char *event = ami_keyvalue(e, "Event");
		if (!strcmp(event, "SoftmodemSession")) {
			number = ami_keyvalue(e, "CallerIDNumber");
			name = ami_keyvalue(e, "CallerIDName");
			break;
		}
	}
	bbs_debug(5, "Softmodem caller: %s (%s)\n", S_IF(number), S_IF(name));
	if (strlen_zero(number)) {
		safe_strncpy(numberbuf, number, num_len);
	}
	if (!strlen_zero(name)) {
		safe_strncpy(namebuf, name, name_len);
	}
	ami_resp_free(resp);
	return 0;
}

static void set_ami_status(struct bbs_ami_session *ami, int up)
{
	SET_BITFIELD(ami->asterisk_up, up);
	bbs_debug(3, "Asterisk Manager Interface is now %s\n", up ? "UP" : "DOWN");
}

/*! \brief Callback function executing asynchronously when new events are available */
static void ami_callback(struct ami_session *session, struct ami_event *event)
{
	struct ami_callback *cb;
	int do_reload = 0;
	const char *eventname;
	struct bbs_ami_session *ami = ami_get_callback_data(session);

	if (bbs_module_is_shutting_down()) {
		ami_event_free(event);
		return; /* If we're unloading, don't care */
	}

	eventname = ami_keyvalue(event, "Event");
	bbs_assert_exists(eventname);

	if (unlikely(!strcmp(eventname, "FullyBooted"))) {
		/* We get this when Asterisk starts, but also when we connect, so if Asterisk is already running, we're still good.
		 * However, I've seen that sometimes, e.g. when Asterisk restarts, we get the FullyBooted event,
		 * but the AMI connection is dead after that. So, just to make sure it's really working,
		 * send a dummy action and make sure we get a response. */
		if (ami->post_reconnect) {
			/* This is one of the few commands that will probably work,
			 * regardless of the permissions for this manager user. */
			struct ami_response *resp = ami_action(ami->session, "ListCommands", "");
			if (!resp) {
				bbs_error("Failed to get response to 'ListCommands' sanity check\n");
				/* We're probably screwed up at this point.
				 * The only thing we could do is a hard unload/load
				 * of the module. */
				do_reload = 1;
				goto cleanup;
			}
			ami_resp_free(resp);
			bbs_debug(2, "AMI reconnect sanity check succeeded\n");
			ami->post_reconnect = 0;
		}
		set_ami_status(ami, 1);
		goto cleanup; /* No need to forward this event to listeners. */
	}

	RWLIST_RDLOCK(&callbacks);
	RWLIST_TRAVERSE(&callbacks, cb, entry) {
		int res;
		/* Dispatch AMI event to each subscribed callback function */
		bbs_module_ref(cb->mod, 1);
		res = cb->callback(event, eventname);
		bbs_module_unref(cb->mod, 1);
		/* If callback returns 0, that means it handled it non-exclusively.
		 * If callback returns -1, that means it's not handling it.
		 * If callback returns 1, abort callback handling. */
		if (res == 1) {
			break;
		}
	}
	RWLIST_UNLOCK(&callbacks);

cleanup:
	ami_event_free(event); /* Free event when done with it */
	if (do_reload) {
		bbs_request_module_unload("mod_asterisk_ami", 1);
	}
}

static int ami_alert_pipe[2] = { -1, -1 };

int __bbs_ami_callback_register(int (*callback)(struct ami_event *event, const char *eventname), void *mod)
{
	struct ami_callback *cb;

	cb = calloc(1, sizeof(*cb));
	if (ALLOC_FAILURE(cb)) {
		return -1;
	}

	cb->callback = callback;
	cb->mod = mod;

	bbs_alertpipe_write(ami_alert_pipe);

	RWLIST_WRLOCK(&callbacks);
	RWLIST_INSERT_HEAD(&callbacks, cb, entry);
	RWLIST_UNLOCK(&callbacks);

	return 0;
}

int bbs_ami_callback_unregister(int (*callback)(struct ami_event *event, const char *eventname))
{
	struct ami_callback *cb;

	/* If ami_disconnect_callback is currently running,
	 * we need to interrupt it in order to be able to
	 * successfully WRLOCK the list. */
	bbs_alertpipe_write(ami_alert_pipe);

	RWLIST_WRLOCK(&callbacks);
	cb = RWLIST_REMOVE_BY_FIELD(&callbacks, callback, callback, entry);
	RWLIST_UNLOCK(&callbacks);

	if (!cb) {
		bbs_error("Tried to unregister unregistered callback %p\n", callback);
		return -1;
	} else {
		free(cb);
	}
	return 0;
}

static int cli_ami_loglevel(struct bbs_cli_args *a)
{
	const char *session_name = a->argv[2];
	int oldlevel = -1, newlevel = atoi(a->argv[3]);
	if (newlevel < 0 || newlevel > 10) {
		bbs_dprintf(a->fdout, "Invalid log level: %d\n", newlevel);
		return -1;
	}

	AMI_SESSION_CALL_START_SESSIONLESS();
	oldlevel = ami_set_debug_level(ami->session, newlevel);
	AMI_SESSION_CALL_END();

	if (oldlevel == -1) {
		bbs_dprintf(a->fdout, "No such AMI session '%s'\n", session_name);
		return -1;
	}
	bbs_dprintf(a->fdout, "Updated log level from %d to %d\n", oldlevel, newlevel);
	return 0;
}

static int cli_ami_status(struct bbs_cli_args *a)
{
	struct bbs_ami_session *ami;
	bbs_dprintf(a->fdout, "%-20s %6s %s\n", "Name", "Status", "Server");
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, ami, entry) {
		char hostport[512];
		snprintf(hostport, sizeof(hostport), "%s://%s:%d", ami->tls ? "tls" : "tcp", ami->hostname, ami->port);
		bbs_dprintf(a->fdout, "%-20s %6s %s\n", ami->name, hostport, ami->asterisk_up ? "UP" : "DOWN");
	}
	RWLIST_UNLOCK(&sessions);
	return 0;
}

static struct bbs_cli_entry cli_commands_ami[] = {
	BBS_CLI_COMMAND(cli_ami_loglevel, "ami loglevel", 4, "Set CAMI (AMI library) log level", "ami loglevel <session> <newlevel>"),
	BBS_CLI_COMMAND(cli_ami_status, "ami status", 2, "View AMI (Asterisk Manager Interface) connection statuses", NULL),
};

static int start_ami_client(struct bbs_ami_session *ami, int reconnect);

static void cleanup_ami(struct bbs_ami_session *ami)
{
	bbs_debug(5, "Cleaning up AMI session (session: %p, TLS: %d, dead: %d)\n", ami->session, ami->tls, ami->dead);

	if (ami->session) {
		ami_disconnect(ami->session);
		ami_destroy(ami->session);
		ami->session = NULL;
	}

	/* We only need to close file descriptors for encrypted sessions */
	if (ami->tls) {
		bbs_io_shutdown(&ami->trans, &ami->rfd, &ami->wfd);
		bbs_io_session_unregister(&ami->trans);
		memset(&ami->trans, 0, sizeof(ami->trans));
		close_if(ami->fd);
	}

	ami->dead = 1;
}

static void ami_disconnect_callback(struct ami_session *session)
{
	struct bbs_ami_session *ami = ami_get_callback_data(session);
	int sleep_ms = 500;

	if (ami->reconnecting) {
		bbs_debug(3, "Ignoring, reconnect already in progress\n");
		return;
	}

	set_ami_status(ami, 0);
	bbs_notice("Asterisk Manager Interface connection lost\n");

	if (bbs_module_is_shutting_down()) {
		return; /* If we're unloading, don't care */
	}
	if (ami->authfailure) {
		bbs_debug(5, "Not reconnecting since login was rejected\n");
		/* We don't call cleanup_ami(ami) on login failure, since ami is still being used at the time,
		 * so clean it up here. */
		cleanup_ami(ami);
		return;
	}

	/* Write lock, since nobody can be accessing the AMI session while we're recreating it */
	ami->reconnecting = 1;

	/* Perhaps Asterisk restarted (or crashed).
	 * Try to reconnect if it comes back up. */
	RWLIST_RDLOCK(&sessions);
	for (;;) {
		int res;
		cleanup_ami(ami);
		res = start_ami_client(ami, 1);
		if (!res) {
			bbs_verb(4, "Asterisk Manager Interface connection re-established\n");
			ami->post_reconnect = 1;
			/* No need to call set_ami_status(ami, 1) here,
			 * when we reconnect, we'll get a FullyBooted event
			 * which will do this. */
			break;
		}
		bbs_debug(3, "Waiting %d ms to retry AMI connection...\n", sleep_ms);
		if (bbs_alertpipe_poll(ami_alert_pipe, sleep_ms)) {
			bbs_alertpipe_read(ami_alert_pipe);
			bbs_debug(3, "AMI reconnect interrupted\n");
			if (bbs_module_is_shutting_down()) {
				bbs_debug(3, "Aborting reconnect\n");
				break;
			}
			/* Interrupted, but not unloading.
			 * Probably something else that needs to grab a list lock.
			 * Suspend the retry for a moment. */
			usleep(1000); /* Force the CPU to suspend this thread */
		}
		if (sleep_ms < 64000) { /* Exponential backoff, up to 64 seconds */
			sleep_ms *= 2;
		}
	}
	RWLIST_UNLOCK(&sessions);
	ami->reconnecting = 0;
}

static int starttls(struct bbs_ami_session *ami)
{
	int res;
	if (!bbs_io_transformer_available(TRANSFORM_TLS_ENCRYPTION)) {
		bbs_error("Can't set up encrypted AMI connection, TLS transformer unavailable\n");
		return 1;
	}
	res = bbs_io_transform_setup(&ami->trans, TRANSFORM_TLS_ENCRYPTION, TRANSFORM_CLIENT, &ami->rfd, &ami->wfd, ami->hostname);
	if (res) {
		return res;
	}
	bbs_io_session_register(&ami->trans, TRANSFORM_SESSION_TCPCLIENT, ami); /* last arg is typically a bbs_tcp_client, but it's void*, so we can pass whatever we like */
	return 0;
}

static int start_ami_client(struct bbs_ami_session *ami, int reconnect)
{
	struct ami_session *s;
	int port = ami->port;

	/* We should have cleaned up any previous session already.
	 * If not, we'll overwrite it and leak memory. */
	bbs_assert(!ami->session);

	if (reconnect) {
		ami->fd = ami->rfd = ami->wfd = -1; /* Reset if needed */
		ami->loggedin = 0;
		ami->dead = 0;
	}

	bbs_debug(4, "Attempting to start AMI client %s://%s:%d\n", ami->tls ? "tls" : "tcp", ami->hostname, ami->port);

	if (ami->tls) {
		/* If it's an encrypted connection, we set up encryption ourselves and pass
		 * normal file descriptors off to libcami. */
		if (!port) {
			port = 5039; /* Default port for encrypted AMI sessions is 5039 */
		}
		ami->fd = bbs_tcp_connect(ami->hostname, port);
		if (ami->fd == -1) {
			bbs_error("AMI connection failed to %s:%d\n", ami->hostname, port);
			return -1;
		}
		ami->rfd = ami->wfd = ami->fd;
		/* Set up TLS encryption */
		if (starttls(ami)) {
			bbs_error("Failed to set up TLS encryption for connection\n");
			cleanup_ami(ami);
			return -1;
		}
		/* Now, link the session with libcami */
		s = ami_session_from_fd(ami->rfd, ami->wfd, ami_callback, ami_disconnect_callback);
	} else {
		s = ami_connect(ami->hostname, 0, ami_callback, ami_disconnect_callback);
	}

	if (!s) {
		bbs_error("AMI session setup failed for %s\n", ami->hostname);
		cleanup_ami(ami);
		return -1;
	}

	ami_set_debug(s, ami->logfd);
	ami_set_debug_level(s, (int) ami->loglevel);
	ami_set_callback_data(s, ami);
	ami->session = s;

	/* After it's connected, log in */
	if (ami_action_login(s, ami->username, ami->password)) {
		ami->authfailure = 1; /* Don't retry if credentials were rejected */
		bbs_error("AMI login failed for user %s@%s\n", ami->username, ami->hostname);
		return -1;
	}
	ami->loggedin = 1;
	return 0;
}

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_config *cfg;

	cfg = bbs_config_load("mod_asterisk_ami.conf", 1);
	if (!cfg) {
		return -1;
	}

	RWLIST_WRLOCK(&sessions);
	while ((section = bbs_config_walk(cfg, section))) {
		struct bbs_ami_session *ami;
		struct bbs_keyval *keyval = NULL;

		ami = calloc(1, sizeof(*ami) + strlen(bbs_config_section_name(section)) + 1);
		if (ALLOC_FAILURE(ami)) {
			continue;
		}
		ami->fd = ami->rfd = ami->wfd = ami->logfd = -1; /* Initialize all file descriptors to "none" */

		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcasecmp(key, "hostname")) {
				safe_strncpy(ami->hostname, value, sizeof(ami->hostname));
			} else if (!strcasecmp(key, "username")) {
				safe_strncpy(ami->username, value, sizeof(ami->username));
			} else if (!strcasecmp(key, "password")) {
				safe_strncpy(ami->password, value, sizeof(ami->password));
			} else if (!strcasecmp(key, "logfile")) {
				safe_strncpy(ami->logfile, value, sizeof(ami->logfile));
			} else if (!strcasecmp(key, "loglevel")) {
				ami->loglevel = (unsigned int) atoi(value);
				if (ami->loglevel > 10) {
					bbs_warning("AMI log level must be between 0 and 10\n");
					ami->loglevel = 10;
				}
			} else if (!strcasecmp(key, "port")) {
				/* Not very efficient, but the set_port variant only exists for top-level */
				bbs_config_val_set_port(cfg, bbs_config_section_name(section), "port", &ami->port); /* Optional, defaults to 0 (default) */
			} else if (!strcasecmp(key, "encryption")) {
				int tls = 0;
				/* Not very efficient, but the set_true variant only exists for top-level */
				bbs_config_val_set_true(cfg, bbs_config_section_name(section), "encryption", &tls);  /* Optional, defaults to 0 */
				SET_BITFIELD(ami->tls, tls);
			} else {
				bbs_warning("Unknown directive: %s\n", key);
			}
		}
		if (s_strlen_zero(ami->hostname) || s_strlen_zero(ami->username) || s_strlen_zero(ami->password)) {
			bbs_error("Missing mandatory settings, not creating AMI session '%s'\n", bbs_config_section_name(section));
			free(ami);
			continue;
		}
		strcpy(ami->data, bbs_config_section_name(section)); /* Safe */
		ami->name = ami->data;
		RWLIST_INSERT_TAIL(&sessions, ami, entry);
	}
	RWLIST_UNLOCK(&sessions);

	/* Purge the config from memory now, since it contains a password.
	 * The password is still stored in the module while it's running, but at least it's once less place. */
	bbs_config_unlock(cfg);
	bbs_config_free(cfg);
	return 0;
}

static void *ami_thread(void *varg)
{
	struct bbs_ami_session *ami = varg;
	start_ami_client(ami, 0);
	return NULL;
}

static int start_ami_clients(void)
{
	struct bbs_ami_session *ami;
	RWLIST_WRLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, ami, entry) {
		if (!s_strlen_zero(ami->logfile)) {
			ami->logfd = open(ami->logfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
			if (ami->logfd == -1) {
				bbs_error("Failed to open %s for AMI logging: %s\n", ami->logfile, strerror(errno));
			}
		}
		/* We launch a separate thread to launch each session.
		 * This is because if login fails, the disconnect callback is triggered,
		 * which can lead to deadlock as that will try to lock the session list,
		 * but we already have it locked here.
		 * More importantly, the disconnect callback will retry forever with backoff,
		 * so each session really needs its own thread so we can start them all now. */
		bbs_pthread_create(&ami->amithread, NULL, ami_thread, ami);
	}
	RWLIST_UNLOCK(&sessions);
	return 0;
}

static void cleanup_session(struct bbs_ami_session *ami)
{
	cleanup_ami(ami);
	if (ami->amithread) {
		bbs_pthread_interrupt(ami->amithread);
		bbs_pthread_join(ami->amithread, NULL);
	}
	close_if(ami->logfd);
	free(ami);
}

static void cleanup_sessions(void)
{
	RWLIST_WRLOCK_REMOVE_ALL(&sessions, entry, cleanup_session);
}

static int load_module(void)
{
	if (bbs_alertpipe_create(ami_alert_pipe)) {
		return -1;
	}

	if (load_config()) {
		cleanup_sessions();
		bbs_alertpipe_close(ami_alert_pipe);
		return -1;
	} else if (RWLIST_EMPTY(&sessions)) {
		bbs_notice("No AMI sessions defined in mod_asterisk_ami.conf, declining to load\n");
		cleanup_sessions();
		bbs_alertpipe_close(ami_alert_pipe);
		return -1;
	}

	bbs_run_when_started(start_ami_clients, STARTUP_PRIORITY_DEPENDENT);

	bbs_cli_register_multiple(cli_commands_ami);
	return 0;
}

static int unload_module(void)
{
	/* If ami_disconnect_callback is currently being executed by some thread, get rid of it. */
	bbs_alertpipe_write(ami_alert_pipe); /* Wake up anything waiting in ami_disconnect_callback */

	/* Ensure that nobody has the callbacks list locked. */
	RWLIST_WRLOCK(&callbacks);
	RWLIST_UNLOCK(&callbacks);

	cleanup_sessions();
	bbs_cli_unregister_multiple(cli_commands_ami);
	bbs_alertpipe_close(ami_alert_pipe);
	return 0;
}

BBS_MODULE_INFO_FLAGS("Asterisk Manager Interface", MODFLAG_GLOBAL_SYMBOLS);
