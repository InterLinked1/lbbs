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
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <cami/cami.h>

#define MIN_VERSION_REQUIRED SEMVER_VERSION(0,2,0)
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

struct ami_session *bbs_ami_session(void)
{
	return ami_session;
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

static int reconnecting = 0;

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

	reconnecting = 1;
	RWLIST_RDLOCK(&callbacks);
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
