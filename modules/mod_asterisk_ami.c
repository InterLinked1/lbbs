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

#define MIN_VERSION_REQUIRED SEMVER_VERSION(0,3,0)
#if !defined(CAMI_VERSION_MAJOR)
#error "libcami version too old"
#elif SEMVER_VERSION(CAMI_VERSION_MAJOR, CAMI_VERSION_MINOR, CAMI_VERSION_PATCH) < MIN_VERSION_REQUIRED
#pragma message "libcami version " XSTR(CAMI_VERSION_MAJOR) "." XSTR(CAMI_VERSION_MINOR) "." XSTR(CAMI_VERSION_PATCH) " too old"
#endif

#include "include/module.h"
#include "include/config.h"
#include "include/alertpipe.h"
#include "include/linkedlists.h"
#include "include/cli.h"
#include "include/node.h"
#include "include/utils.h"

#include "include/mod_asterisk_ami.h"

static int asterisk_up = 0;
static int post_reconnect = 0;
static struct ami_session *ami_session = NULL;

struct ami_callback {
	int (*callback)(struct ami_event *event, const char *eventname);
	void *mod;
	RWLIST_ENTRY(ami_callback) entry;
};

static RWLIST_HEAD_STATIC(callbacks, ami_callback);

static int reconnecting = 0;

/* If we're in the middle of a reconnect, we can't do anything
 * We could also implement some logic here to queue momentarily,
 * in case the connection comes back up soon; that way, the request
 * is simply delayed, not rejected (we'd need to unlock the list,
 * sleep a little bit, then relock and check, with a timeout). */
#define RECONNECT_CHECKS() \
	UNUSED(session); \
	if (reconnecting) { \
		bbs_warning("Rejecting AMI action during active reconnect\n"); \
		goto cleanup; \
	} else if (!ami_session) { \
		bbs_warning("Rejecting AMI action - no manager session active\n"); \
		goto cleanup; \
	}

#define AMI_SESSION_CALL_START() \
	RWLIST_RDLOCK(&callbacks); \
	RECONNECT_CHECKS();

#define AMI_SESSION_CALL_END() \
cleanup: \
	RWLIST_UNLOCK(&callbacks);

struct ami_response * __attribute__ ((format (printf, 3, 4))) bbs_ami_action(const char *session, const char *action, const char *fmt, ...)
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
	 * Here, we keep the callbacks list locked, to ensure that ami_session can't become
	 * NULL while we're using it (in case of a reconnect). */

	AMI_SESSION_CALL_START();
	va_start(ap, fmt);
	resp = ami_action_va(ami_session, action, fmt, ap); /* Use ami_action_va, to avoid an additional vasprintf allocation */
	va_end(ap);
	AMI_SESSION_CALL_END();

	return resp;
}

int bbs_ami_action_setvar(const char *session, const char *variable, const char *value, const char *channel)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_setvar(ami_session, variable, value, channel);
	AMI_SESSION_CALL_END();

	return res;
}

int bbs_ami_action_getvar_buf(const char *session, const char *variable, const char *channel, char *buf, size_t len)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_getvar_buf(ami_session, variable, channel, buf, len);
	AMI_SESSION_CALL_END();

	return res;
}

int bbs_ami_action_response_result(const char *session, struct ami_response *resp)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_response_result(ami_session, resp);
	AMI_SESSION_CALL_END();

	return res;
}

char *bbs_ami_action_getvar(const char *session, const char *variable, const char *channel)
{
	char *var = NULL;

	AMI_SESSION_CALL_START();
	var = ami_action_getvar(ami_session, variable, channel);
	AMI_SESSION_CALL_END();

	return var;
}

int bbs_ami_action_redirect(const char *session, const char *channel, const char *context, const char *exten, const char *priority)
{
	int res = -1;

	AMI_SESSION_CALL_START();
	res = ami_action_redirect(ami_session, channel, context, exten, priority);
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

static void set_ami_status(int up)
{
	asterisk_up = up;
	bbs_debug(3, "Asterisk Manager Interface is now %s\n", up ? "UP" : "DOWN");
}

/*! \brief Callback function executing asynchronously when new events are available */
static void ami_callback(struct ami_session *ami, struct ami_event *event)
{
	struct ami_callback *cb;
	int do_reload = 0;
	const char *eventname;

	UNUSED(ami);

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
		if (post_reconnect) {
			/* This is one of the few commands that will probably work,
			 * regardless of the permissions for this manager user. */
			struct ami_response *resp = ami_action(ami, "ListCommands", "");
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
			post_reconnect = 0;
		}
		set_ami_status(1);
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

static int ami_log_fd = -1;

static int cli_ami_loglevel(struct bbs_cli_args *a)
{
	int newlevel = atoi(a->argv[2]);
	if (newlevel < 0 || newlevel > 10) {
		bbs_dprintf(a->fdout, "Invalid log level: %d\n", newlevel);
		return -1;
	}
	ami_set_debug_level(ami_session, newlevel);
	return 0;
}

static int cli_ami_status(struct bbs_cli_args *a)
{
	bbs_dprintf(a->fdout, "Asterisk Manager Interface status: %s\n", asterisk_up ? "UP" : "DOWN");
	return 0;
}

static struct bbs_cli_entry cli_commands_ami[] = {
	BBS_CLI_COMMAND(cli_ami_loglevel, "ami loglevel", 3, "Set CAMI (AMI library) log level", "ami loglevel <newlevel>"),
	BBS_CLI_COMMAND(cli_ami_status, "ami status", 2, "View Asterisk Manager Interface connection status", NULL),
};

static int load_config(int open_logfile);

static void cleanup_ami(void)
{
	struct ami_session *s = ami_session;
	ami_session = NULL;
	if (s) {
		ami_disconnect(s);
		ami_destroy(s);
	}
	close_if(ami_log_fd);
}

static void ami_disconnect_callback(struct ami_session *ami)
{
	int sleep_ms = 500;

	UNUSED(ami);

	set_ami_status(0);
	bbs_warning("Asterisk Manager Interface connection lost\n");

	if (bbs_module_is_shutting_down()) {
		return; /* If we're unloading, don't care */
	}

	/* Write lock, since nobody can be accessing the global AMI session while we're recreating it */
	reconnecting = 1;
	RWLIST_WRLOCK(&callbacks);
	cleanup_ami();
	/* Perhaps Asterisk restarted (or crashed).
	 * Try to reconnect if it comes back up. */
	for (;;) {
		int res;
		res = load_config(0);
		if (!res) {
			bbs_verb(4, "Asterisk Manager Interface connection re-established\n");
			post_reconnect = 1;
			/* No need to call set_ami_status(1) here,
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
			RWLIST_UNLOCK(&callbacks);
			usleep(10); /* Enough to cause the CPU to suspend this thread, and allow something else to grab a WRLOCK */
			RWLIST_WRLOCK(&callbacks);
		}
		if (sleep_ms < 64000) { /* Exponential backoff, up to 64 seconds */
			sleep_ms *= 2;
		}
	}
	RWLIST_UNLOCK(&callbacks);
	reconnecting = 0;
}

static int load_config(int open_logfile)
{
	int res = 0;
	struct bbs_config *cfg;
	char hostname[256];
	char username[64];
	char password[92] = ""; /* Avoid uninitialized memory access if it wasn't set */
	char logfile[512];
	unsigned int loglevel = 0;

	cfg = bbs_config_load("mod_asterisk_ami.conf", 1);
	if (!cfg) {
		return -1;
	}

	res |= bbs_config_val_set_str(cfg, "ami", "hostname", hostname, sizeof(hostname));
	res |= bbs_config_val_set_str(cfg, "ami", "username", username, sizeof(username));
	res |= bbs_config_val_set_str(cfg, "ami", "password", password, sizeof(password));

	if (open_logfile && !bbs_config_val_set_str(cfg, "logging", "logfile", logfile, sizeof(logfile))) {
		ami_log_fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (ami_log_fd != -1) {
			bbs_config_val_set_uint(cfg, "logging", "loglevel", &loglevel);
			if (loglevel > 10) {
				bbs_warning("Maximum AMI debug level is 10\n");
				loglevel = 10;
			}
		} else {
			bbs_error("Failed to open %s for AMI logging: %s\n", logfile, strerror(errno));
		}
	}

	if (!res) {
		struct ami_session *s = ami_connect(hostname, 0, ami_callback, ami_disconnect_callback);
		if (!s) {
			bbs_error("AMI connection failed to %s\n", hostname);
			res = -1;
			goto cleanup;
		}
		ami_set_debug(s, ami_log_fd);
		ami_set_debug_level(s, (int) loglevel);
		if (ami_action_login(s, username, password)) {
			bbs_error("AMI login failed for user %s@%s\n", username, hostname);
			ami_disconnect(s);
			res = -1;
		} else {
			ami_session = s;
		}
	}

cleanup:
	/* Fully purge the password from memory */
	bbs_memzero(password, strlen(password));
	bbs_config_unlock(cfg);
	bbs_config_free(cfg);
	return res;
}

static int load_module(void)
{
	if (bbs_alertpipe_create(ami_alert_pipe)) {
		return -1;
	}
	if (load_config(1)) {
		close_if(ami_log_fd);
		bbs_alertpipe_close(ami_alert_pipe);
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_ami);
	return 0;
}

static int unload_module(void)
{
	/* If ami_disconnect_callback is currently being executed by some thread,
	 * get rid of it. */
	bbs_alertpipe_write(ami_alert_pipe); /* Wake up anything waiting in ami_disconnect_callback */

	/* If anything was in the body of ami_disconnect_callback,
	 * it had the list locked. If we can lock the list, that means they're gone. */
	do {
		bbs_debug(3, "Attempting to lock callback list to ensure safe unload\n");
		RWLIST_WRLOCK(&callbacks);
		RWLIST_UNLOCK(&callbacks);
	} while (reconnecting);

	bbs_cli_unregister_multiple(cli_commands_ami);
	cleanup_ami();
	bbs_alertpipe_close(ami_alert_pipe);
	return 0;
}

BBS_MODULE_INFO_FLAGS("Asterisk Manager Interface", MODFLAG_GLOBAL_SYMBOLS);
