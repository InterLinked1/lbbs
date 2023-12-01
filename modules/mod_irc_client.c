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
 * \brief IRC client
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/linkedlists.h"
#include "include/utils.h"
#include "include/config.h"
#include "include/startup.h"
#include "include/system.h"
#include "include/auth.h"
#include "include/cli.h"

#include <lirc/irc.h>
#include <lirc/numerics.h>

#include "include/mod_irc_client.h"

#define MIN_VERSION_REQUIRED SEMVER_VERSION(0,2,0)
#if SEMVER_VERSION(LIRC_VERSION_MAJOR, LIRC_VERSION_MINOR, LIRC_VERSION_PATCH) < MIN_VERSION_REQUIRED
#error "lirc version too old"
#endif

struct bbs_irc_client {
	RWLIST_ENTRY(bbs_irc_client) entry; 		/* Next client */
	struct irc_client *client;			/* IRC client */
	pthread_t thread;					/* Thread for relay */
	char *msgscript;					/* Message handler hook script (e.g. for bot actions) */
	unsigned int log:1;					/* Log to log file */
	unsigned int callbacks:1;			/* Execute callbacks for messages received by this client */
	FILE *logfile;						/* Log file */
	char name[0];						/* Unique client name */
};

static RWLIST_HEAD_STATIC(irc_clients, bbs_irc_client);

struct irc_msg_callback {
	void (*msg_cb)(const char *clientname, enum irc_callback_msg_type type, const char *channel, const char *prefix, int ctcp, const char *msg);
	void (*numeric_cb)(const char *clientname, const char *prefix, int numeric, const char *msg);
	void *mod;
	RWLIST_ENTRY(irc_msg_callback) entry;
};

static RWLIST_HEAD_STATIC(msg_callbacks, irc_msg_callback); /* Container for all message callbacks */

int __bbs_irc_client_msg_callback_register(void (*msg_cb)(const char *clientname, enum irc_callback_msg_type type, const char *channel, const char *prefix, int ctcp, const char *msg), void (*numeric_cb)(const char *clientname, const char *prefix, int numeric, const char *msg), void *mod)
{
	struct irc_msg_callback *cb;

	RWLIST_WRLOCK(&msg_callbacks);
	RWLIST_TRAVERSE(&msg_callbacks, cb, entry) {
		if (msg_cb == cb->msg_cb) {
			break;
		}
	}
	if (cb) {
		bbs_error("Callback %p is already registered\n", msg_cb);
		RWLIST_UNLOCK(&msg_callbacks);
		return -1;
	}
	cb = calloc(1, sizeof(*cb));
	if (ALLOC_FAILURE(cb)) {
		RWLIST_UNLOCK(&msg_callbacks);
		return -1;
	}
	cb->msg_cb = msg_cb;
	cb->numeric_cb = numeric_cb;
	cb->mod = mod;
	RWLIST_INSERT_HEAD(&msg_callbacks, cb, entry);
	RWLIST_UNLOCK(&msg_callbacks);
	return 0;
}

/* No need for a separate cleanup function since this module cannot be unloaded until all relays have unregistered */

int bbs_irc_client_msg_callback_unregister(void (*msg_cb)(const char *clientname, enum irc_callback_msg_type type, const char *channel, const char *prefix, int ctcp, const char *msg))
{
	struct irc_msg_callback *cb;

	cb = RWLIST_WRLOCK_REMOVE_BY_FIELD(&msg_callbacks, msg_cb, msg_cb, entry);
	if (cb) {
		free(cb);
	} else {
		bbs_error("Callback %p was not previously registered\n", msg_cb);
		return -1;
	}
	return 0;
}

static void __client_log(enum irc_log_level level, int sublevel, const char *file, int line, const char *func, const char *msg)
{
	/* Log messages already have a newline, don't add another one */
	switch (level) {
		case IRC_LOG_ERR:
			__bbs_log(LOG_ERROR, 0, file, line, func, "%s", msg);
			break;
		case IRC_LOG_WARN:
			__bbs_log(LOG_WARNING, 0, file, line, func, "%s", msg);
			break;
		case IRC_LOG_INFO:
			__bbs_log(LOG_NOTICE, 0, file, line, func, "%s", msg);
			break;
		case IRC_LOG_DEBUG:
			__bbs_log(LOG_DEBUG, sublevel, file, line, func, "%s", msg);
			break;
	}
}

int bbs_irc_client_exists(const char *clientname)
{
	struct bbs_irc_client *c;

	RWLIST_RDLOCK(&irc_clients);
	RWLIST_TRAVERSE(&irc_clients, c, entry) {
		if (!strcmp(c->name, clientname)) {
			break;
		}
	}
	RWLIST_UNLOCK(&irc_clients);
	return c ? 1 : 0;
}

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_irc_client.conf", 1);

	if (!cfg) {
		bbs_error("File 'mod_irc_client.conf' is missing: IRC client declining to start\n");
		return -1; /* Abort, if we have no users, we can't start */
	}

	RWLIST_WRLOCK(&irc_clients);
	while ((section = bbs_config_walk(cfg, section))) {
		struct bbs_irc_client *client;
		int flags = 0;
		struct irc_client *ircl;
		char *msgscript = NULL;
		const char *hostname, *username, *password, *autojoin;
		unsigned int port = 0;
		int tls = 0, tlsverify = 0, sasl = 0, logfile = 0, callbacks = 1;
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Skip [general] */
		}
		/* It's a client section */
		if (strchr(bbs_config_section_name(section), ' ')) {
			bbs_error("Config section name '%s' contains illegal spaces\n", bbs_config_section_name(section));
			continue; /* Client names will get used in IRC relays, and IRC doesn't permit spaces in nicknames */
		}
		hostname = bbs_config_sect_val(section, "hostname");
		username = bbs_config_sect_val(section, "username");
		password = bbs_config_sect_val(section, "password");
		autojoin = bbs_config_sect_val(section, "autojoin");
		/* XXX This is not efficient, there should be versions that take section directly */
		bbs_config_val_set_uint(cfg, bbs_config_section_name(section), "port", &port);
		bbs_config_val_set_true(cfg, bbs_config_section_name(section), "tls", &tls);
		bbs_config_val_set_true(cfg, bbs_config_section_name(section), "tlsverify", &tlsverify);
		bbs_config_val_set_true(cfg, bbs_config_section_name(section), "sasl", &sasl);
		bbs_config_val_set_true(cfg, bbs_config_section_name(section), "logfile", &logfile);
		bbs_config_val_set_true(cfg, bbs_config_section_name(section), "callbacks", &callbacks);
		bbs_config_val_set_dstr(cfg, bbs_config_section_name(section), "msgscript", &msgscript);

		client = calloc(1, sizeof(*client) + strlen(bbs_config_section_name(section)) + 1);
		if (ALLOC_FAILURE(client)) {
			free_if(msgscript);
			continue;
		}

		strcpy(client->name, bbs_config_section_name(section)); /* Safe */
		ircl = irc_client_new(hostname, port, username, password);
		if (!ircl) {
			free(client);
			free_if(msgscript);
			continue;
		}
		irc_client_autojoin(ircl, autojoin);
		if (tls) {
			flags |= IRC_CLIENT_USE_TLS;
		}
		if (tlsverify) {
			flags |= IRC_CLIENT_VERIFY_SERVER;
		}
		if (sasl) {
			flags |= IRC_CLIENT_USE_SASL;
		}
		irc_client_set_flags(ircl, flags);
		client->client = ircl;
		SET_BITFIELD(client->log, logfile);
		SET_BITFIELD(client->callbacks, callbacks);
		client->msgscript = msgscript;
		/* Go ahead and warn now if it doesn't exist. Set it either way, as it could be fixed during runtime. */
		if (client->msgscript && access(client->msgscript, X_OK)) {
			bbs_warning("File %s does not exist or is not executable\n", client->msgscript);
		}
		bbs_debug(4, "Created IRC client '%s'\n", client->name);
		RWLIST_INSERT_TAIL(&irc_clients, client, entry); /* Tail insert so first client is always first */
	}
	RWLIST_UNLOCK(&irc_clients);
	return 0;
}

static void client_free(struct bbs_irc_client *client)
{
	if (client->msgscript) {
		free(client->msgscript);
	}
	free(client);
}

/* Forward declaration */
static void *client_relay(void *varg);

static int start_irc_clients(void)
{
	struct bbs_irc_client *client;
	int started = 0;

	RWLIST_WRLOCK(&irc_clients);
	RWLIST_TRAVERSE_SAFE_BEGIN(&irc_clients, client, entry) {
		int res = irc_client_connect(client->client); /* Actually connect */
		if (!res) {
			res = irc_client_login(client->client); /* Authenticate */
		}
		if (!res && !irc_client_connected(client->client)) {
			bbs_error("Attempted to start client '%s', but disconnected prematurely?\n", client->name);
			res = -1;
		}
		if (res) {
			/* Connection failed? Remove it */
			bbs_error("Failed to start IRC client '%s'\n", client->name);
			irc_client_destroy(client->client);
			RWLIST_REMOVE_CURRENT(entry);
			client_free(client);
		} else {
			started++;
			/* Now, start the event loop to receive messages from the server */
			if (bbs_pthread_create(&client->thread, NULL, client_relay, (void*) client)) {
				return -1;
			}
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&irc_clients);
	if (started) {
		bbs_verb(4, "Started %d IRC client%s\n", started, ESS(started));
	}
	return 0;
}

enum relay_flags {
	RELAY_TO_IRC = (1 << 0),
	RELAY_FROM_IRC = (1 << 1),
};

static enum irc_callback_msg_type callback_msg_type(enum irc_msg_type type)
{
	switch (type) {
		case IRC_CMD_PRIVMSG:
			return CMD_PRIVMSG;
		case IRC_CMD_NOTICE:
			return CMD_NOTICE;
		case IRC_CMD_PING:
			return CMD_PING;
		case IRC_CMD_JOIN:
			return CMD_JOIN;
		case IRC_CMD_PART:
			return CMD_PART;
		case IRC_CMD_QUIT:
			return CMD_QUIT;
		case IRC_CMD_KICK:
			return CMD_KICK;
		case IRC_CMD_NICK:
			return CMD_NICK;
		case IRC_CMD_MODE:
			return CMD_MODE;
		case IRC_CMD_TOPIC:
			return CMD_TOPIC;
		case IRC_UNPARSED:
		case IRC_NUMERIC: /* Numerics have their own callback, so doesn't apply here */
		case IRC_CMD_ERROR:
		case IRC_CMD_OTHER:
		default: /* In case more enum values are added */
			return CMD_UNSUPPORTED;
	}
}

static const char *callback_msg_type_name(enum irc_callback_msg_type type)
{
	switch (type) {
		case CMD_PRIVMSG:
			return "PRIVMSG";
		case CMD_NOTICE:
			return "NOTICE";
		case CMD_PING:
			return "PING";
		case CMD_JOIN:
			return "JOIN";
		case CMD_PART:
			return "PART";
		case CMD_QUIT:
			return "QUIT";
		case CMD_KICK:
			return "KICK";
		case CMD_NICK:
			return "NICK";
		case CMD_MODE:
			return "MODE";
		case CMD_TOPIC:
			return "TOPIC";
		case CMD_UNSUPPORTED:
			return "UNSUPPORTED";
	}
	return NULL;
}

#define msg_relay_to_local(client, msg) msg_relay(client, RELAY_FROM_IRC, irc_msg_type(msg), irc_msg_channel(msg), irc_msg_prefix(msg), irc_msg_is_ctcp(msg), irc_msg_body(msg), strlen(S_IF(irc_msg_body(msg))))

static int msg_relay(struct bbs_irc_client *client, enum relay_flags flags, enum irc_msg_type type, const char *channel, const char *prefix, int ctcp, const char *body, size_t len)
{
	int res = 0;
	const char *scope = flags & RELAY_TO_IRC ? flags & RELAY_FROM_IRC ? "to/from" : "to" : "from";
	enum irc_callback_msg_type cb_type = callback_msg_type(type);
	bbs_debug(7, "Broadcasting %s %s client %s, channel %s, prefix %s, CTCP: %d, length %lu: %.*s\n", callback_msg_type_name(cb_type), scope, client->name, channel, prefix, ctcp, len, (int) len, body);

	if (len > 512) {
		bbs_warning("%lu-byte message is too long to send to IRC\n", len);
		return -1;
	}

	/* Relay the message to everyone */
	RWLIST_RDLOCK(&irc_clients); /* XXX Really just need to lock *this* client to prevent it from being removed, not all of them */
	if (flags & RELAY_TO_IRC) {
		res = irc_client_msg(client->client, channel, body); /* Actually send to IRC */
	}
	if (flags & RELAY_FROM_IRC) { /* Only execute callback on messages received *FROM* IRC client, not messages *TO* it. */
		if (client->callbacks) {
			struct irc_msg_callback *cb;
			RWLIST_RDLOCK(&msg_callbacks);
			RWLIST_TRAVERSE(&msg_callbacks, cb, entry) {
				bbs_module_ref(cb->mod, 1);
				cb->msg_cb(client->name, cb_type, channel, prefix, ctcp, body);
				bbs_module_unref(cb->mod, 1);
			}
			RWLIST_UNLOCK(&msg_callbacks);
		}
	}
	RWLIST_UNLOCK(&irc_clients);
	return res;
}

static void __bot_handler(struct bbs_irc_client *client, enum relay_flags flags, const char *channel, const char *prefix, int ctcp, const char *msg)
{
	/* If fromirc, then it's a message from IRC.
	 * Otherwise, it's a message to IRC, sent from a BBS user.
	 * They're both PRIVMSGs, it's just the direction.
	 *
	 * The nomenclature here is a bit misleading: even if !fromirc,
	 * it could be from IRC, e.g. the local IRC network,
	 * but it's injected using bbs_irc_client_msg, as opposed to being
	 * received from an IRC client. */
	int fromirc = flags & RELAY_FROM_IRC ? 1 : 0;
	int lines = 0;
	struct readline_data rldata;
	char buf[IRC_MAX_MSG_LEN + 1]; /* Luckily, we are bounded by the max length of an IRC message anyways */
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	char *argv[6] = { (char*) client->msgscript, fromirc ? "1" : "0", (char*) channel, (char*) prefix, (char*) msg, NULL };
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
	int res;
	int stdout[2];

	if (strlen_zero(client->msgscript)) {
		return;
	} else if (access(client->msgscript, X_OK)) {
		bbs_error("File %s does not exist or is not executable\n", client->msgscript); /* If not caught by now, this is fatal for script execution */
		return;
	} else if (pipe(stdout)) { /* Create a pipe for receiving output. */
		bbs_error("pipe failed: %s\n", strerror(errno)); /* Log first, since close may change errno */
		return;
	}

	/* Invoke the script synchronously.
	 *
	 * Before someone criticizes this as having a lot of overhead, private messages in IRC channels
	 * aren't something that occur frequently enough for this to be an issue, generally speaking.
	 * Several forks a minute is fine. Several forks a second, maybe that would not be so fine.
	 *
	 * Also, even if this blocks for some reason, this thread can be killed using pthread_cancel during unload.
	 * The nice thing about this being a separate script is it can be updated while the BBS is running,
	 * and it doesn't matter what language it's using. A little flavor of CGI :)
	 */

	bbs_readline_init(&rldata, buf, sizeof(buf));
	res = bbs_execvp_fd(NULL, -1, stdout[1], client->msgscript, argv); /* No STDIN, only STDOUT */
	bbs_debug(5, "Script '%s' returned %d\n", client->msgscript, res);
	if (res) {
		goto cleanup; /* Ignore non-zero return values */
	} else if (bbs_poll(stdout[0], 0) == 0) {
		bbs_debug(4, "No data in script's STDOUT pipe\n"); /* Not necessarily an issue, the script could have returned 0 but printed nothing */
	}

	/* If there's output in the pipe, send it to the channel */
	/* Use reliable readline in case there are multiple lines. We don't need to worry about partial reads since writing is done,
	 * but we don't want to process more than one line at the same time. */
	for (;;) { /* Shouldn't have to wait very long, output should be in the pipe ready to read by time process exits */
		ssize_t bytes;
		char *dest, *line = buf;
		/* First word of output is the target channel or username.
		 * In most cases, this will be the same, but for example,
		 * we might want to message the sender privately, rather than
		 * posting to the channel publicly.
		 * Or maybe we should post to a different channel.
		 * The possibilities are endless!
		 */

		bytes = bbs_readline(stdout[0], &rldata, "\n", 10);
		if (bytes < 0) {
			/* The last line doesn't have to be NULL terminated, if there's data pending, just process what we got last */
			if ((bytes = readline_bytes_available(&rldata, 0)) <= 0) {
				if (!lines) { /* bbs_poll returned positive previously, so how can this be? */
					bbs_warning("Failed to read any script output data\n");
				}
				break;
			}
		}
		if (!bytes) {
			continue; /* Ignore empty lines */
		}

		dest = strsep(&line, " ");
		if (strlen_zero(line)) {
			bbs_warning("Script output contained a target but no message, ignoring\n");
			continue;
		}

		/* XXX system.c dups STDOUT and STDERR to the same fd, so
		 * if there is STDERR output here, we'll process it just the same,
		 * even though it should really be ignored. */

		bbs_debug(4, "Sending to %s: %s\n", dest, line);

		/* Relay the message to wherever it should go */
		bbs_strterm(line, '\r');
		/* Can't be over 512 characters since that's as large as the buffer is anyways. (We ignore anything over that) */
		if (!strcmp(channel, dest)) {
			/* It's going back to the same channel. Send it to everyone. */
			/*! \note RELAY_FROM_IRC was removed from the mask here, since that would
			 * relay the message to the other side (e.g. the local IRC network channel)
			 * improperly impersonated, i.e. the message posted by the bot would appear
			 * to be posted by the person to whom the bot was responding.
			 * Upon further though, it really doesn't make sense to relay bot responses
			 * in the other direction anyways, hence this simpler (and more correct) behavior. */
			msg_relay(client, RELAY_TO_IRC, IRC_CMD_PRIVMSG, dest, prefix, ctcp, line, strlen(line));
		} else { /* It's going to a different channel, or to a user. */
			/* Call irc_client_msg directly, and don't relay it to local users.
			 * Note that according to the IRC specs, PRIVMSG may solicit automated replies
			 * whereas NOTICE may not (and NOTICE is indeed ignored for bot handling).
			 * We reply using a PRIVMSG rather than a NOTICE because in practice,
			 * NOTICEs are also more disruptive.
			 */
			irc_client_msg(client->client, dest, line);
		}
		lines++;
	}

cleanup:
	close(stdout[0]);
	close(stdout[1]);
}

/*! \brief Optional hook for bots for user messages and PRIVMSGs from channel */
static void bot_handler(struct bbs_irc_client *client, struct irc_msg *msg, enum relay_flags flags)
{
	return __bot_handler(client, flags, irc_msg_channel(msg), irc_msg_prefix(msg), irc_msg_is_ctcp(msg), irc_msg_body(msg));
}

static void handle_ctcp(struct bbs_irc_client *client, struct irc_client *ircl, struct irc_msg *msg)
{
	enum irc_ctcp_type ctcp = irc_msg_ctcp_type(msg);

	/* CTCP command: known extended data = ACTION, VERSION, TIME, PING, DCC, SED, etc. */
	/* Remember: CTCP requests use PRIVMSG, responses use NOTICE! */

	if (irc_msg_type(msg) != IRC_CMD_PRIVMSG) {
		/* Ignore NOTICE (reply) */
		return;
	}

	switch (ctcp) {
	case CTCP_ACTION: /* /me, /describe */
		/* At this time, the only CTCP command that we pass through to callbacks is ACTION. */
		msg_relay_to_local(client, msg);
		bot_handler(client, msg, RELAY_FROM_IRC);
		break;
	case CTCP_VERSION:
		irc_client_ctcp_reply(ircl, irc_msg_prefix(msg), ctcp, BBS_SHORTNAME " / LIRC " XSTR(LIRC_MAJOR_VERSION) "." XSTR(LIRC_MINOR_VERSION) "." XSTR(LIRC_PATCH_VERSION));
		break;
	case CTCP_PING:
		irc_client_ctcp_reply(ircl, irc_msg_prefix(msg), ctcp, irc_msg_body(msg)); /* Reply with the data that was sent */
		break;
	case CTCP_TIME:
		{
			char timebuf[32];
			time_t nowtime;
			struct tm nowdate;

			nowtime = time(NULL);
			localtime_r(&nowtime, &nowdate);
			strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M:%S %P %Z", &nowdate);
			irc_client_ctcp_reply(ircl, irc_msg_prefix(msg), ctcp, timebuf);
		}
		break;
	default:
		bbs_warning("Unhandled CTCP extended data type: %s\n", irc_ctcp_name(irc_msg_ctcp_type(msg)));
	}
}

static void handle_irc_msg(void *data, struct irc_msg *msg)
{
	struct bbs_irc_client *client = data;

	switch (irc_msg_type(msg)) {
	case IRC_NUMERIC:
		/* Just ignore all these */
		switch (irc_msg_numeric(msg)) {
		/* Needed by mod_irc_relay: */
		case RPL_WHOISUSER:
		case RPL_WHOISSERVER:
		case RPL_ENDOFWHO:
		case RPL_WHOISIDLE:
		case RPL_ENDOFWHOIS:
		case RPL_WHOISCHANNELS:
		case RPL_WHOWAS_TIME:
		case RPL_WHOREPLY:
		case RPL_NAMREPLY:
		case RPL_ENDOFNAMES:
		case RPL_WHOISSECURE:
		/* XXX Missing any numeric for WHO, WHOIS, NAMES replies? */
			if (client->callbacks) {
				struct irc_msg_callback *cb;
				/* Reconstruct the raw response */
				RWLIST_RDLOCK(&msg_callbacks);
				RWLIST_TRAVERSE(&msg_callbacks, cb, entry) {
					if (cb->numeric_cb) {
						bbs_module_ref(cb->mod, 2);
						cb->numeric_cb(client->name, irc_msg_prefix(msg), irc_msg_numeric(msg), irc_msg_body(msg));
						bbs_module_unref(cb->mod, 2);
					}
				}
				RWLIST_UNLOCK(&msg_callbacks);
			}
			break;
		default:
			bbs_debug(5, "Got numeric: prefix: %s, num: %d, body: %s\n", irc_msg_prefix(msg), irc_msg_numeric(msg), irc_msg_body(msg));
		}
		return;
	case IRC_CMD_PRIVMSG:
	case IRC_CMD_NOTICE:
		bbs_strterm(irc_msg_prefix(msg), '!'); /* Strip everything except the nickname from the prefix */
		if (irc_msg_is_ctcp(msg) && !irc_parse_msg_ctcp(msg)) {
			handle_ctcp(client, client->client, msg); /* handle_ctcp also calls bot_handler */
		} else {
			msg_relay_to_local(client, msg);

			/* Only run the bot handler after we've forwarded the event to consumer modules.
			 * Otherwise, a bot response could be received before the message to which it's responding. */
			if (irc_msg_type(msg) == IRC_CMD_PRIVMSG) {
				/* Bots can only reply to PRIVMSG, not NOTICE, to prevent loops */
				bot_handler(client, msg, RELAY_FROM_IRC);
			}
		}
		break;
	case IRC_CMD_PING:
		irc_client_pong(client->client, msg);
		break;
	case IRC_CMD_JOIN:
	case IRC_CMD_PART:
	case IRC_CMD_QUIT:
	case IRC_CMD_KICK:
	case IRC_CMD_NICK:
	case IRC_CMD_MODE:
	case IRC_CMD_TOPIC:
		/* Pass on intact to the consumer modules.
		 * We do no formatting of messages here. */
		msg_relay_to_local(client, msg);
		break;
	case IRC_CMD_ERROR:
		bbs_warning("Received error from IRC client %s: %s\n", client->name, irc_msg_body(msg));
		/* Ignore, do not forward errors to consumer modules */
		break;
	case IRC_CMD_OTHER:
	case IRC_UNPARSED:
	default:
		bbs_warning("Unhandled command: prefix: %s, command: %s, body: %s\n", irc_msg_prefix(msg), irc_msg_command(msg), irc_msg_body(msg));
		/* Don't pass on */
	}
}

static void *client_relay(void *varg)
{
	struct bbs_irc_client *client = varg;
	char logfile[256];

	snprintf(logfile, sizeof(logfile), "%s/irc_%s.txt", BBS_LOG_DIR, client->name);

	if (client->log) {
		client->logfile = fopen(logfile, "a"); /* Create or append */
		if (!client->logfile) {
			bbs_error("Failed to open log file %s: %s\n", logfile, strerror(errno));
			return NULL;
		}
	}

	irc_loop(client->client, client->logfile, handle_irc_msg, client);

	bbs_debug(3, "IRC client '%s' thread has exited\n", client->name);
	return NULL;
}

int __attribute__ ((format (gnu_printf, 2, 3))) bbs_irc_client_send(const char *clientname, const char *fmt, ...)
{
	struct bbs_irc_client *client;
	char buf[IRC_MAX_MSG_LEN + 1];
	int res, len;
	va_list ap;

	RWLIST_RDLOCK(&irc_clients);
	RWLIST_TRAVERSE(&irc_clients, client, entry) {
		if (!clientname) {
			break; /* Just use the first one (default) */
		}
		if (!strcasecmp(client->name, clientname)) {
			break;
		}
	}
	if (!client) {
		bbs_warning("IRC client %s doesn't exist\n", S_IF(clientname));
		RWLIST_UNLOCK(&irc_clients);
		return -1;
	}

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len >= (int) sizeof(buf)) {
		bbs_warning("Truncation occured trying to send %d-byte IRC message\n", len);
		RWLIST_UNLOCK(&irc_clients);
		return -1;
	}

	/* Directly send raw message to IRC (don't relay locally) */
	res = irc_send(client->client, "%s", buf);

	RWLIST_UNLOCK(&irc_clients);
	return res;
}

int __attribute__ ((format (gnu_printf, 4, 5))) bbs_irc_client_msg(const char *clientname, const char *channel, const char *prefix, const char *fmt, ...)
{
	struct bbs_irc_client *client;
	char buf[IRC_MAX_MSG_LEN + 1];
	int res, len;
	va_list ap;

	RWLIST_RDLOCK(&irc_clients);
	RWLIST_TRAVERSE(&irc_clients, client, entry) {
		if (!clientname) {
			break; /* Just use the first one (default) */
		}
		if (!strcasecmp(client->name, clientname)) {
			break;
		}
	}
	if (!client) {
		bbs_warning("IRC client %s doesn't exist\n", S_IF(clientname));
		RWLIST_UNLOCK(&irc_clients);
		return -1;
	}

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len >= (int) sizeof(buf)) {
		bbs_warning("Truncation occured trying to format %d-byte IRC message\n", len);
		RWLIST_UNLOCK(&irc_clients);
		return -1;
	}

	/* Send to IRC (and relay to anything local) */

	/*! \todo FIXME Should also include RELAY_FROM_IRC,
	 * but if we're sending a message from the local IRC network to an IRC channel,
	 * we shouldn't also process it as if it were originally received from IRC,
	 * which is what would happen now.
	 * Omitting this for now is more correct, but means messages from the local IRC server
	 * will get relayed to other actual IRC channels but not to door_irc, for example.
	 * Might work if we skip the sending module? Or maybe not??? */

	res = msg_relay(client, RELAY_TO_IRC, IRC_CMD_PRIVMSG, channel, prefix, 0, buf, (size_t) len); /* No prefix */

	RWLIST_UNLOCK(&irc_clients);
	return res;
}

static int cli_irc_irc_clients(struct bbs_cli_args *a)
{
	struct bbs_irc_client *c;

	bbs_dprintf(a->fdout, "%-20s %6s %3s %9s %-15s %s\n", "Name", "Status", "Log", "Callbacks", "Thread", "BotMsgScript");
	RWLIST_RDLOCK(&irc_clients);
	RWLIST_TRAVERSE(&irc_clients, c, entry) {
		bbs_dprintf(a->fdout, "%-20s %6s %3s %9s %15lu %s\n", c->name, irc_client_connected(c->client) ? "Online" : "Offline", BBS_YN(c->log), BBS_YN(c->callbacks), c->thread, S_IF(c->msgscript));
	}
	RWLIST_UNLOCK(&irc_clients);
	return 0;
}

static struct bbs_cli_entry cli_commands_irc[] = {
	BBS_CLI_COMMAND(cli_irc_irc_clients, "irc irc_clients", 2, "List all IRC irc_clients", NULL),
};

static int unload_module(void)
{
	struct bbs_irc_client *client;

	RWLIST_WRLOCK(&irc_clients);
	bbs_debug(3, "Removing %d IRC irc_clients\n", RWLIST_SIZE(&irc_clients, client, entry));
	while ((client = RWLIST_REMOVE_HEAD(&irc_clients, entry))) {
		irc_disconnect(client->client);
		bbs_pthread_join(client->thread, NULL);
		irc_client_destroy(client->client);
		if (client->logfile) {
			fclose(client->logfile);
		}
		bbs_debug(4, "Destroying IRC client %s\n", client->name);
		client_free(client);
	}
	RWLIST_UNLOCK(&irc_clients);

	bbs_cli_unregister_multiple(cli_commands_irc);
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	irc_log_callback(__client_log); /* Set up logging */
	bbs_run_when_started(start_irc_clients, STARTUP_PRIORITY_DEPENDENT);
	bbs_cli_register_multiple(cli_commands_irc);
	return 0;
}

BBS_MODULE_INFO_FLAGS("Internet Relay Chat Client", MODFLAG_GLOBAL_SYMBOLS);
