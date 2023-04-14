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
#include <sys/time.h> /* use gettimeofday */

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/door.h"
#include "include/term.h"
#include "include/linkedlists.h"
#include "include/utils.h"
#include "include/config.h"
#include "include/startup.h"
#include "include/system.h"
#include "include/auth.h"

#include "include/door_irc.h"

#include "lirc/irc.h"

static int unloading = 0;

struct participant {
	struct bbs_node *node;
	struct client *client;				/* Reference to the underlying client */
	const char *channel;				/* Channel */
	int chatpipe[2];					/* Pipe to store data */
	RWLIST_ENTRY(participant) entry;	/* Next participant */
};

RWLIST_HEAD(participants, participant);

struct client {
	RWLIST_ENTRY(client) entry; 		/* Next client */
	struct participants participants; 	/* List of participants */
	struct irc_client *client;			/* IRC client */
	pthread_t thread;					/* Thread for relay */
	char *msgscript;					/* Message handler hook script (e.g. for bot actions) */
	unsigned int log:1;					/* Log to log file */
	unsigned int callbacks:1;			/* Execute callbacks for messages received by this client */
	FILE *logfile;						/* Log file */
	char name[0];						/* Unique client name */
};

RWLIST_HEAD_STATIC(clients, client);

struct irc_msg_callback {
	void (*msg_cb)(const char *clientname, const char *channel, const char *msg);
	void (*numeric_cb)(const char *clientname, const char *prefix, int numeric, const char *msg);
	void *mod;
	RWLIST_ENTRY(irc_msg_callback) entry;
};

static RWLIST_HEAD_STATIC(msg_callbacks, irc_msg_callback); /* Container for all message callbacks */

/* Export global symbols for these 3 functions */

int bbs_irc_client_msg_callback_register(void (*msg_cb)(const char *clientname, const char *channel, const char *msg), void (*numeric_cb)(const char *clientname, const char *prefix, int numeric, const char *msg), void *mod)
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
	bbs_module_ref(BBS_MODULE_SELF); /* Bump our module ref count */
	RWLIST_UNLOCK(&msg_callbacks);
	return 0;
}

/* No need for a separate cleanup function since this module cannot be unloaded until all relays have unregistered */

int bbs_irc_client_msg_callback_unregister(void (*msg_cb)(const char *clientname, const char *channel, const char *msg))
{
	struct irc_msg_callback *cb;

	cb = RWLIST_WRLOCK_REMOVE_BY_FIELD(&msg_callbacks, msg_cb, msg_cb, entry);
	if (cb) {
		free(cb);
		bbs_module_unref(BBS_MODULE_SELF); /* And decrement the module ref count back again */
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

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_config *cfg = bbs_config_load("door_irc.conf", 1);

	if (!cfg) {
		bbs_error("File 'door_irc.conf' is missing: IRC client declining to start\n");
		return -1; /* Abort, if we have no users, we can't start */
	}

	RWLIST_WRLOCK(&clients);
	while ((section = bbs_config_walk(cfg, section))) {
		struct client *client;
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
			bbs_warning("Config section name '%s' contains spaces, please avoid this\n", bbs_config_section_name(section));
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
			continue;
		}
		strcpy(client->name, bbs_config_section_name(section)); /* Safe */
		ircl = irc_client_new(hostname, port, username, password);
		if (!ircl) {
			free(client);
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
		client->log = logfile;
		client->callbacks = callbacks;
		client->msgscript = msgscript;
		/* Go ahead and warn now if it doesn't exist. Set it either way, as it could be fixed during runtime. */
		if (client->msgscript && access(client->msgscript, X_OK)) {
			bbs_warning("File %s does not exist or is not executable\n", client->msgscript);
		}
		RWLIST_INSERT_TAIL(&clients, client, entry); /* Tail insert so first client is always first */
	}
	RWLIST_UNLOCK(&clients);
	return 0;
}

static void client_free(struct client *client)
{
	if (client->msgscript) {
		free(client->msgscript);
	}
	free(client);
}

/* Forward declaration */
static void *client_relay(void *varg);

static int start_clients(void)
{
	struct client *client;
	int started = 0;

	RWLIST_WRLOCK(&clients);
	RWLIST_TRAVERSE_SAFE_BEGIN(&clients, client, entry) {
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
	RWLIST_UNLOCK(&clients);
	if (started) {
		bbs_verb(4, "Started %d IRC client%s\n", started, ESS(started));
	}
	return 0;
}

static void leave_client(struct client *client, struct participant *participant)
{
	struct participant *p;

	/* Lock the entire list first */
	RWLIST_WRLOCK(&clients);
	if (unloading) {
		RWLIST_UNLOCK(&clients);
		/* If the module is being unloaded, the client no longer exists.
		 * The participant list has also been freed. Just free ourselves and get out of here. */
		free(participant);
		return;
	}
	RWLIST_WRLOCK(&client->participants);
	p = RWLIST_REMOVE(&client->participants, participant, entry);
	if (p) {
		/* Close the pipe */
		close(p->chatpipe[0]);
		close(p->chatpipe[1]);
		/* Free */
		free(p);
	} else {
		bbs_error("Failed to remove participant %p (node %d) from client %s?\n", participant, participant->node->id, client->name);
	}
	RWLIST_UNLOCK(&client->participants);
	RWLIST_UNLOCK(&clients);
}

static struct participant *join_client(struct bbs_node *node, const char *name)
{
	struct participant *p;
	struct client *client;

	RWLIST_WRLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!strcasecmp(client->name, name)) {
			break;
		}
	}
	if (!client) {
		bbs_error("IRC client %s doesn't exist\n", name);
		return NULL;
	}
	/* Okay, we have the client. Add the newcomer to it. */
	p = calloc(1, sizeof(*p));
	if (ALLOC_FAILURE(p)) {
		RWLIST_UNLOCK(&clients);
		return NULL;
	}
	p->node = node;
	p->client = client;
	if (pipe(p->chatpipe)) {
		bbs_error("Failed to create pipe\n");
		free(p);
		RWLIST_UNLOCK(&clients);
		return NULL;
	}
	RWLIST_INSERT_HEAD(&client->participants, p, entry);
	RWLIST_UNLOCK(&clients);
	return p;
}

/* Forward declarations */
static int __attribute__ ((format (gnu_printf, 5, 6))) _chat_send(struct client *client, struct participant *sender, const char *channel, int dorelay, const char *fmt, ...);
static int __chat_send(struct client *client, struct participant *sender, const char *channel, int dorelay, const char *msg, int len);

/*! \brief Optional hook for bots for user messages and PRIVMSGs from channel */
static void bot_handler(struct client *client, int fromirc, const char *channel, const char *sender, const char *body)
{
	char *line, *dest, *outmsg;
	char buf[IRC_MAX_MSG_LEN + 1];
	char *argv[6] = { (char*) client->msgscript, fromirc ? "1" : "0", (char*) channel, (char*) sender, (char*) body, NULL };
	int res;
	int stdout[2];

	/* If fromirc, then it's a message from IRC.
	 * Otherwise, it's a message to IRC, sent from a BBS user.
	 * They're both PRIVMSGs, it's just the direction.
	 */

	if (strlen_zero(client->msgscript)) {
		return;
	}
	if (access(client->msgscript, X_OK)) {
		bbs_error("File %s does not exist or is not executable\n", client->msgscript); /* If not caught by now, this is fatal for script execution */
		return;
	}

	/* Create a pipe for receiving output. */
	if (pipe(stdout)) {
		bbs_error("pipe failed: %s\n", strerror(errno)); /* Log first, since close may change errno */
		return;
	}

	/* Invoke the script synchronously.
	 *
	 * Before some criticizes this as having a lot of overhead, private messages in IRC channels
	 * aren't something that occurs frequently enough for this to be an issue, generally speaking.
	 * Several forks a minute is fine. Several forks a second, maybe that would not be so fine.
	 *
	 * Also, even if this blocks for some reason, this thread can be killed using pthread_cancel during unload.
	 * The nice thing about this being a separate script is it can be updated while the BBS is running,
	 * and it doesn't matter what language it's using. A little flavor of CGI :)
	 */

	res = bbs_execvp_fd(NULL, -1, stdout[1], client->msgscript, argv); /* No STDIN, only STDOUT */
	bbs_debug(5, "Script '%s' returned %d\n", client->msgscript, res);
	if (res) {
		goto cleanup; /* Ignore non-zero return values */
	}

	/* If there's output in the pipe, send it to the channel */
	/* Poll first, in case there's no data in the pipe or this would block. */
	if (bbs_std_poll(stdout[0], 0) == 0) {
		bbs_debug(4, "No data in script's STDOUT pipe\n"); /* Not necessarily an issue, the script could have returned 0 but printed nothing */
		goto cleanup;
	}
	res = read(stdout[0], buf, sizeof(buf) - 1); /* Luckily, we are bounded by the max length of an IRC message anyways */
	if (res <= 0) {
		bbs_error("read returned %d\n", res);
		goto cleanup;
	}
	buf[res] = '\0';
	outmsg = buf;

	if (strlen_zero(outmsg)) {
		goto cleanup; /* Output is empty. Do nothing. */
	}

	/* First word of output is the target channel or username.
	 * In most cases, this will be the same, but for example,
	 * we might want to message the sender privately, rather than
	 * posting to the channel publicly.
	 * Or maybe we should post to a different channel.
	 * The possibilities are endless!
	 */
	dest = strsep(&outmsg, " ");
	if (strlen_zero(outmsg)) {
		bbs_warning("Script output contained a target but no message, ignoring\n");
		goto cleanup;
	}

	bbs_debug(4, "Sending to %s: %s\n", dest, outmsg);

	/* Relay the message to wherever it should go */
	while ((line = strsep(&outmsg, "\n"))) { /* If response contains multiple lines, we need to send multiple messages */
		char *cr = strchr(line, '\r');
		if (cr) {
			*cr = '\0';
		}
		/* Can't be over 512 characters since that's as large as the buffer is anyways. (We ignore anything over that) */
		if (!strcmp(channel, dest)) {
			/* It's going back to the same channel. Send it to everyone. */
			__chat_send(client, NULL, dest, 1, line, strlen(line));
		} else {
			/* It's going to a different channel, or to a user. */
			/* Call irc_client_msg directly, and don't relay it to local users.
			 * Note that according to the IRC specs, PRIVMSG may solicit automated replies
			 * whereas NOTICE may not (and NOTICE is indeed ignored for bot handling).
			 * We reply using a PRIVMSG rather than a NOTICE because in practice,
			 * NOTICEs are also more disruptive.
			 */
			irc_client_msg(client->client, dest, line); /* XXX This only works for targeting IRC users, not local BBS users */
		}
	}

cleanup:
	close(stdout[0]);
	close(stdout[1]);
	return;
}

#define relay_to_local(client, channel, fmt, ...) _chat_send(client, NULL, channel, 0, fmt, __VA_ARGS__)

static void handle_ctcp(struct client *client, struct irc_client *ircl, const char *channel, struct bbs_node *node, struct irc_msg *msg, char *body)
{
	/* CTCP command: known extended data = ACTION, VERSION, TIME, PING, DCC, SED, etc. */
	/* Remember: CTCP requests use PRIVMSG, responses use NOTICE! */
	char *tmp, *ctcp_name;
	enum irc_ctcp ctcp;

	body++; /* Skip leading \001 */
	if (!*body) {
		bbs_error("Nothing after \\001?\n");
		return;
	}
	/* Don't print the trailing \001 */
	tmp = strchr(body, 0x01);
	if (tmp) {
		*tmp = '\0';
	} else {
		bbs_error("Couldn't find trailing \\001?\n");
	}

	ctcp_name = strsep(&body, " ");

	tmp = strchr(msg->prefix, '!');
	if (tmp) {
		*tmp = '\0'; /* Strip everything except the nickname from the prefix */
	}

	ctcp = irc_ctcp_from_string(ctcp_name);
	if (ctcp < 0) {
		bbs_error("Unsupported CTCP extended data type: %s\n", ctcp_name);
		return;
	}

	if (!strcmp(msg->command, "PRIVMSG")) {
		switch (ctcp) {
		case CTCP_ACTION: /* /me, /describe */
			if (client) {
				relay_to_local(client, channel, "[ACTION] <%s> %s\n", msg->prefix, body);
				bot_handler(client, 1, channel, msg->prefix, body);
			} else {
				bbs_writef(node, "[ACTION] <%s> %s\n", msg->prefix, body);
			}
			break;
		case CTCP_VERSION:
			irc_client_ctcp_reply(ircl, msg->prefix, ctcp, BBS_SHORTNAME " / LIRC 0.1.0");
			break;
		case CTCP_PING:
			irc_client_ctcp_reply(ircl, msg->prefix, ctcp, body); /* Reply with the data that was sent */
			break;
		case CTCP_TIME:
			{
				char timebuf[32];
				time_t nowtime;
				struct tm nowdate;

				nowtime = time(NULL);
				localtime_r(&nowtime, &nowdate);
				strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M:%S %P %Z", &nowdate);
				irc_client_ctcp_reply(ircl, msg->prefix, ctcp, timebuf);
			}
			break;
		default:
			bbs_warning("Unhandled CTCP extended data type: %s\n", ctcp_name);
		}
	} else { /* NOTICE (reply) */
		/* Ignore */
	}
}

static void handle_irc_msg(struct client *client, struct irc_msg *msg)
{
	if (msg->numeric) {
		/* Just ignore all these */
		switch (msg->numeric) {
		/* Needed by mod_relay_irc: */
		case 311:
		case 312:
		case 315:
		case 317:
		case 318:
		case 319:
		case 330:
		case 352:
		case 353:
		case 366:
		case 671:
		/* XXX Missing any numeric for WHO, WHOIS, NAMES replies? */
			if (client->callbacks) {
				struct irc_msg_callback *cb;
				/* Reconstruct the raw response */
				RWLIST_RDLOCK(&msg_callbacks);
				RWLIST_TRAVERSE(&msg_callbacks, cb, entry) {
					if (cb->numeric_cb) {
						bbs_module_ref(cb->mod);
						cb->numeric_cb(client->name, msg->prefix, msg->numeric, msg->body);
						bbs_module_unref(cb->mod);
					}
				}
				RWLIST_UNLOCK(&msg_callbacks);
			}
			break;
		default:
			bbs_debug(5, "Got numeric: prefix: %s, num: %d, body: %s\n", msg->prefix, msg->numeric, msg->body);
		}
		return;
	}
	/* else, it's a command */
	if (!msg->command) {
		assert(0);
	}
	if (!strcmp(msg->command, "PRIVMSG") || !strcmp(msg->command, "NOTICE")) { /* This is intentionally first, as it's the most common one. */
		/* NOTICE is same as PRIVMSG, but should never be acknowledged (replied to), to prevent loops, e.g. for use with bots. */
		char *channel, *body = msg->body;

		/* Format of msg->body here is CHANNEL :BODY */
		channel = strsep(&body, " ");
		body++; /* Skip : */

		if (*body == 0x01) { /* sscanf stripped off the leading : */
			handle_ctcp(client, client->client, channel, NULL, msg, body);
		} else {
			char *tmp = strchr(msg->prefix, '!');
			if (tmp) {
				*tmp = '\0'; /* Strip everything except the nickname from the prefix */
			}
			relay_to_local(client, channel, "<%s> %s\n", msg->prefix, body);
			if (!strcmp(msg->command, "PRIVMSG")) {
				bot_handler(client, 1, channel, msg->prefix, body);
			}
		}
	} else if (!strcmp(msg->command, "PING")) {
		/* Reply with the same data that it sent us (some servers may actually require that) */
		int sres = irc_send(client->client, "PONG :%s", msg->body ? msg->body + 1 : ""); /* If there's a body, skip the : and bounce the rest back */
		if (sres) {
			return;
		}
	} else if (!strcmp(msg->command, "JOIN")) {
		relay_to_local(client, msg->body, "%s has %sjoined%s\n", msg->prefix, COLOR(COLOR_GREEN), COLOR_RESET);
	} else if (!strcmp(msg->command, "PART")) {
		relay_to_local(client, msg->body, "%s has %sleft%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
	} else if (!strcmp(msg->command, "QUIT")) {
		relay_to_local(client, msg->body, "%s has %squit%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
	} else if (!strcmp(msg->command, "KICK")) {
		relay_to_local(client, msg->body, "%s has been %skicked%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
	} else if (!strcmp(msg->command, "NICK")) {
		relay_to_local(client, NULL, "%s is %snow known as%s %s\n", msg->prefix, COLOR(COLOR_CYAN), COLOR_RESET, msg->body);
	} else if (!strcmp(msg->command, "MODE")) {
		/* Ignore */
	} else if (!strcmp(msg->command, "ERROR")) {
		/* Ignore, do not send errors to users */
	} else if (!strcmp(msg->command, "TOPIC")) {
		/* Ignore */
	} else {
		bbs_warning("Unhandled command: prefix: %s, command: %s, body: %s\n", msg->prefix, msg->command, msg->body);
	}
}

static void *client_relay(void *varg)
{
	struct client *client = varg;
	/* Thread will get killed on shutdown */

	int res = 0;
	char readbuf[IRC_MAX_MSG_LEN + 1];
	struct irc_msg msg;
	char *prevbuf, *mybuf = readbuf;
	int prevlen, mylen = sizeof(readbuf) - 1;
	char *start, *eom;
	int rounds;
	char logfile[256];

	snprintf(logfile, sizeof(logfile), "%s/irc_%s.txt", BBS_LOG_DIR, client->name);

	if (client->log) {
		client->logfile = fopen(logfile, "a"); /* Create or append */
		if (!client->logfile) {
			bbs_error("Failed to open log file %s: %s\n", logfile, strerror(errno));
			return NULL;
		}
	}

	start = readbuf;
	for (;;) {
begin:
		rounds = 0;
		if (mylen <= 1) {
			/* IRC max message is 512, but we could have received multiple messages in one read() */
			char *a;
			/* Shift current message to beginning of the whole buffer */
			for (a = readbuf; *start; a++, start++) {
				*a = *start;
			}
			*a = '\0';
			mybuf = a;
			mylen = sizeof(readbuf) - 1 - (mybuf - readbuf);
			start = readbuf;
			if (mylen <= 1) { /* Couldn't shift, whole buffer was full */
				/* Could happen but this would not be valid. Abort read and reset. */
				bbs_error("Buffer truncation!\n");
				start = readbuf;
				mybuf = readbuf;
				mylen = sizeof(readbuf) - 1;
			}
		}
		/* Wait for data from server */
		if (res != sizeof(readbuf) - 1) {
			/* XXX We don't poll if we read() into an entirely full buffer and there's still more data to read.
			 * poll() won't return until there's even more data (but it feels like it should). */
			res = irc_poll(client->client, -1, -1);
			if (res <= 0) {
				break;
			}
		}
		prevbuf = mybuf;
		prevlen = mylen;
		res = irc_read(client->client, mybuf, mylen);
		if (res <= 0) {
			break;
		}

		mybuf[res] = '\0'; /* Safe */
		do {
			eom = strstr(mybuf, "\r\n");
			if (!eom) {
				/* read returned incomplete message */
				mybuf = prevbuf + res;
				mylen = prevlen - res;
				goto begin; /* In a double loop, can't continue */
			}

			/* Got more than one message? */
			if (*(eom + 2)) {
				*(eom + 1) = '\0'; /* Null terminate before the next message starts */
			}

			memset(&msg, 0, sizeof(msg));
			if (client->logfile) {
				fprintf(client->logfile, "%s\n", start); /* Append to log file */
			}
			if (!irc_parse_msg(&msg, start)) {
				handle_irc_msg(client, &msg);
			}

			mylen -= (eom + 2 - mybuf);
			start = mybuf = eom + 2;
			rounds++;
		} while (mybuf && *mybuf);

		start = mybuf = readbuf; /* Reset to beginning */
		mylen = sizeof(readbuf) - 1;
	}

	bbs_debug(3, "IRC client '%s' thread has exited\n", client->name);
	return NULL;
}

static int __chat_send(struct client *client, struct participant *sender, const char *channel, int dorelay, const char *msg, int len)
{
	time_t now;
	struct tm sendtime;
	char datestr[18];
	int timelen;
	struct participant *p;

	/* Calculate the current time once, for everyone, using the server's time (sorry if participants are in different time zones) */
	now = time(NULL);
	localtime_r(&now, &sendtime);
	/* So, %P is lowercase and %p is uppercase. Just consult your local strftime(3) man page if you don't believe me. Good grief. */
	strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime); /* mm-dd hh:mm:ssPP + space at end (before message) = 17 chars */
	timelen = strlen(datestr); /* Should be 17 */
	bbs_assert(timelen == 17);

	/* If sender is set, it's safe to use even with no locks, because the sender is a calling function of this one */
	if (sender) {
		bbs_debug(7, "Broadcasting to %s,%s (except node %d): %s%.*s\n", client->name, channel, sender->node->id, datestr, len, msg);
	} else {
		bbs_debug(7, "Broadcasting to %s,%s: %s%.*s\n", client->name, channel, datestr, len, msg);
	}

	/* Relay the message to everyone */
	RWLIST_RDLOCK(&client->participants);
	if (dorelay) {
		irc_client_msg(client->client, channel, msg); /* Actually send to IRC */
	} else {
		if (client->callbacks) {
			struct irc_msg_callback *cb;
			/* Only execute callback on messages received *FROM* IRC client, not messages *TO* it. */
			RWLIST_RDLOCK(&msg_callbacks);
			RWLIST_TRAVERSE(&msg_callbacks, cb, entry) {
				bbs_module_ref(cb->mod);
				cb->msg_cb(client->name, channel, msg);
				bbs_module_unref(cb->mod);
			}
			RWLIST_UNLOCK(&msg_callbacks);
		}
	}
	RWLIST_TRAVERSE(&client->participants, p, entry) {
		int res;
		/* We're intentionally relaying to other BBS nodes ourselves, separately from IRC, rather than
		 * just enabling echo on the IRC client and letting that bounce back for other participants.
		 * This is because we don't want our own messages to echo back to ourselves,
		 * and rather than parse messages to figure out if we should ignore something we just sent,
		 * it's easier to not have to ignore anything in the first place (at least for this purpose, still need to do channel filtering) */
		if (p == sender) {
			continue; /* Don't send a sender's message back to him/herself */
		}
		/* XXX Restricts users to a single channel, currently */
		if (!strlen_zero(channel) && strcmp(p->channel, channel)) {
			continue; /* Channel filter doesn't match for this participant */
		}
		if (!NODE_IS_TDD(p->node)) {
			write(p->chatpipe[1], datestr, timelen); /* Don't send timestamps to TDDs, for brevity */
		}
		res = write(p->chatpipe[1], msg, len);
		if (res <= 0) {
			bbs_error("write failed: %s\n", strerror(errno));
			continue; /* Even if one send fails, don't fail all of them */
		}
	}
	RWLIST_UNLOCK(&client->participants);
	return 0;
}

#define chat_send(client, sender, channel, fmt, ...) _chat_send(client, sender, channel, 1, fmt, __VA_ARGS__)

/*! \param sender If NULL, the message will be sent to the sender, if specified, the message will not be sent to this participant */
static int __attribute__ ((format (gnu_printf, 5, 6))) _chat_send(struct client *client, struct participant *sender, const char *channel, int dorelay, const char *fmt, ...)
{
	char *buf;
	int res, len;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* No format specifiers in the format string, just do it directly to avoid an unnecessary allocation. */
		return __chat_send(client, sender, channel, dorelay, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	res = __chat_send(client, sender, channel, dorelay, buf, len);
	free(buf);
	return res;
}

int __attribute__ ((format (gnu_printf, 2, 3))) bbs_irc_client_send(const char *clientname, const char *fmt, ...)
{
	struct client *client;
	char *buf;
	int res, len;
	va_list ap;

	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!clientname) {
			break; /* Just use the first one (default) */
		}
		if (!strcasecmp(client->name, clientname)) {
			break;
		}
	}
	if (!client) {
		bbs_warning("IRC client %s doesn't exist\n", S_IF(clientname));
		RWLIST_UNLOCK(&clients);
		return -1;
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		RWLIST_UNLOCK(&clients);
		return -1;
	}

	/* Directly send raw message to IRC (don't relay locally) */
	res = irc_send(client->client, "%s", buf);
	RWLIST_UNLOCK(&clients);
	free(buf);
	return res;
}

int __attribute__ ((format (gnu_printf, 3, 4))) bbs_irc_client_msg(const char *clientname, const char *channel, const char *fmt, ...)
{
	struct client *client;
	char *buf;
	int res, len;
	va_list ap;

	RWLIST_RDLOCK(&clients);
	RWLIST_TRAVERSE(&clients, client, entry) {
		if (!clientname) {
			break; /* Just use the first one (default) */
		}
		if (!strcasecmp(client->name, clientname)) {
			break;
		}
	}
	if (!client) {
		bbs_warning("IRC client %s doesn't exist\n", S_IF(clientname));
		RWLIST_UNLOCK(&clients);
		return -1;
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		RWLIST_UNLOCK(&clients);
		return -1;
	}

	/* Send to IRC */
	res = __chat_send(client, NULL, channel, 1, buf, len);
	RWLIST_UNLOCK(&clients);
	free(buf);
	return res;
}

static int participant_relay(struct bbs_node *node, struct participant *p, const char *channel)
{
	char buf[384];
	char buf2[sizeof(buf)];
	int res;
	struct client *c = p->client;

	/* Join the channel */
	bbs_clear_screen(node);
	chat_send(c, NULL, channel, "%s@%d has joined %s\n", bbs_username(node->user), p->node->id, channel);

	bbs_unbuffer(node); /* Unbuffer so we can receive keys immediately. Otherwise, might print a message while user is typing */

	for (;;) {
		/* We need to poll both the node as well as the participant (chat) pipe */
		res = bbs_poll2(node, SEC_MS(10), p->chatpipe[0]);
		if (res < 0) {
			break;
		} else if (res == 1) {
			/* Node has activity: Typed something */
			res = bbs_read(node, buf, 1);
			if (res <= 0) {
				break;
			}
			res = 0;
			if (buf[0] == '\n') { /* User just pressed ENTER. Um, okay. */
				continue;
			}
			bbs_writef(node, "%c", buf[0]);
			/* Now, buffer input */
			/* XXX The user will be able to use terminal line editing, except for the first char */
			/* XXX ESC should cancel */
			/* XXX All this would be handled once we have a terminal line editor that works with unbuffered input */
			bbs_buffer(node);
			res = bbs_poll_read(node, MIN_MS(3), buf + 1, sizeof(buf) - 2); /* Leave the first char in the buffer alone, -1 for null termination, and -1 for the first char */
			if (res <= 0) {
				bbs_debug(3, "bbs_poll_read returned %d\n", res);
				if (res == 0) {
					/* User started a message, but didn't finish before timeout */
					bbs_writef(node, "\n*** TIMEOUT ***\n");
					bbs_flush_input(node); /* Discard any pending input */
					continue;
				}
				break;
			}
			res++; /* Add 1, since we read 1 char prior to the last read */
			buf[res] = '\0'; /* Now we can use strcasecmp, et al. */

			bbs_str_process_backspaces(buf, buf2, sizeof(buf2));

			/* strcasecmp will fail because the buffer has a LF at the end. Use strncasecmp, so anything starting with /help or /quit will technically match too */
			if (STARTS_WITH(buf2, "/quit")) {
				break; /* Quit */
			}
			bbs_unbuffer(node);
			chat_send(c, p, channel, "<%s@%d> %s", bbs_username(node->user), node->id, buf2); /* buf2 already contains a newline from the user pressing ENTER, so don't add another one */
			bot_handler(c, 0, channel, bbs_username(node->user), buf2);
		} else if (res == 2) {
			/* Pipe has activity: Received a message */
			res = 0;
			res = read(p->chatpipe[0], buf, sizeof(buf) - 1);
			if (res <= 0) {
				break;
			}
			buf[res] = '\0'; /* Safe */
			/* Don't add a trailing LF, the sent message should already had one. */
			if (bbs_writef(node, "%.*s", res, buf) < 0) {
				res = -1;
				break;
			}
			/* Since we null terminated the buffer, we can safely use strstr */
			if (strcasestr(buf, bbs_username(node->user))) {
				bbs_debug(3, "Message contains '%s', alerting user\n", bbs_username(node->user));
				/* If the message contains our username, ring the bell.
				 * (Most IRC clients also do this for mentions.) */
				if (bbs_ring_bell(node) < 0) {
					res = -1;
					break;
				}
			}
		}
	}

	chat_send(c, NULL, channel, "%s@%d has left %s\n", bbs_username(node->user), node->id, channel);
	return res;
}

/*! \note channel could be char* and that would be fine, but we don't need to modify it, so const char* works */
static int irc_single_client(struct bbs_node *node, char *constring, const char *channel)
{
	struct irc_client *ircl;
	int res;
	int port = 0; /* Default */
	int secure = 0;
	int flags = 0;
	struct readline_data rldata;
	char usernamebuf[24];
	char passwordbuf[64];
	char buf[2048];
	char *username, *password, *hostname, *portstr;

	/* Parse the arguments.
	 * Format is:
	 * irc:// or ircs://username[:password]@hostname[:port] */
	if (STARTS_WITH(constring, "ircs://")) {
		secure = 1;
		constring += STRLEN("ircs://");
	} else {
		constring += STRLEN("irc://"); /* This is the only other thing it could be */
	}

	portstr = constring;
	password = strsep(&portstr, "@");
	username = strsep(&password, ":");
	hostname = strsep(&portstr, ":");
	if (!strlen_zero(portstr)) {
		port = atoi(portstr);
	}

	if (strlen_zero(hostname)) {
		bbs_warning("Missing IRC hostname\n");
		return 0;
	}

	bbs_clear_screen(node);
	bbs_writef(node, "Connecting to IRC...\n");

	/* We get our own client, all to ourself! */
	if (strlen_zero(username)) {
		bbs_writef(node, "Enter username: ");
		NONPOS_RETURN(bbs_readline(node, MIN_MS(1), usernamebuf, sizeof(usernamebuf))); /* Returning -1 anyways, no need to re-enable echo */
		username = usernamebuf;
		if (strlen_zero(username)) {
			bbs_writef(node, "No username received. Connection aborted.\n");
			NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));
			return 0;
		}
	}
	if (!strlen_zero(password) && !strcmp(password, "*")) {
		if (bbs_user_is_registered(node->user) && !bbs_user_temp_authorization_token(node->user, passwordbuf, sizeof(passwordbuf))) {
			password = passwordbuf;
		} else {
			password = NULL;
		}
	}
	if (strlen_zero(password)) {
		/* Don't know the password.
		 * For connections from a BBS node to the BBS IRC server,
		 * user will probably have to re-enter his/her password here manually,
		 * since we don't have any way of authenticating to the IRC server otherwise.
		 * Kind of clunky, admittedly, in the future we could add a more seamless
		 * mechanism that would allow the IRC server to auto-authenticate connections
		 * like this perhaps (e.g. if username and password are empty).
		 *
		 * Complication is that we don't actually know this connection is to the local
		 * IRC server, it could be to any arbitrary server, so this is at least generic:
		 */
		bbs_echo_off(node); /* Don't display password */
		bbs_writef(node, "Enter password for %s: ", username);
		NONPOS_RETURN(bbs_readline(node, MIN_MS(1), passwordbuf, sizeof(passwordbuf))); /* Returning -1 anyways, no need to re-enable echo */
		/* Hopefully the password is right... only get one shot!
		 * In theory, if we knew the connection was to our own IRC server,
		 * we could actually call bbs_user_authentication here with a dummy user
		 * to check the password, and if it's okay, proceed since we know that
		 * the IRC server will then accept it.
		 */
		bbs_echo_on(node);
		password = passwordbuf;
		if (strlen_zero(password)) {
			bbs_writef(node, "\nNo password received. Connection aborted.\n");
			NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));
			return 0;
		}
	}

	/* Somehow, it actually works that the same user can log into IRC twice
	 * e.g. once directly to IRC and once through here.
	 * Obviously the full masks are different in these cases. */

	ircl = irc_client_new(hostname, port, username, password);
	if (!ircl) {
		return 0;
	}

	irc_client_autojoin(ircl, channel);
	if (secure) {
		flags |= IRC_CLIENT_USE_TLS;
		/* Require SASL if using TLS, but don't do it otherwise,
		 * since the IRC URI doesn't indicate whether to use SASL or not.
		 * If a server requires SASL, however, it's reasonable to expect that
		 * it supports TLS, so just pair them together. */
		flags |= IRC_CLIENT_USE_SASL;
	}
	irc_client_set_flags(ircl, flags);

	res = irc_client_connect(ircl); /* Actually connect */
	if (!res) {
		res = irc_client_login(ircl); /* Authenticate */
	}
	if (res || !irc_client_connected(ircl)) {
		bbs_writef(node, "Connection failed.\n");
		bbs_wait_key(node, SEC_MS(75));
		goto cleanup;
	}

	/* Instead of spawning a client_relay thread with a pseudo client and running an event loop,
	 * handle the connection in the current thread.
	 * This does complicate things just a little bit, as can be seen below.
	 * There are several inefficiencies in the loop that could be optimized.
	 */
	bbs_readline_init(&rldata, buf, sizeof(buf)); /* XXX Should probably use a bbs_readline in client_relay as well, to simplify message parsing */
	bbs_clear_screen(node);
	bbs_buffer(node);
	for (;;) {
		time_t now;
		struct tm sendtime;
		char datestr[18] = "";

		/* XXX Known issue: If a message is received while a user is typing,
		 * the message from IRC is printed out immediately and the user continues typing on the next line.
		 * Not super ideal, but since the node is buffered here, we can't easily fix this without unbuffering
		 * the first character and then buffering the rest, and not printing during that time
		 * (this is what door_irc and door_chat do for the shared clients normally).
		 */

		/* Client is buffered, so if poll returns, that means we have a full message from it */
		res = irc_poll(ircl, -1, node->slavefd); /* Wait for either something from the server or from the client */
		if (res <= 0) {
			break;
		}

		/* XXX This is embarassing. irc_poll returns 1 if poll() returned for either fd, but doesn't tell us which fd.
		 * We should update that API to return 1 for fd 0 and 2 for fd 1, just like in socket.c.
		 * Seriously... we are calling poll() 3 times here for every loop!!!
		 * - Once in irc_poll
		 * - bbs_poll and possibly irc_poll again, with timeout of 0.
		 * - Finally in bbs_fd_readline (fortunately, we don't call irc_poll the 2nd time in this case, so it's always 3 times, never 4)
		 *
		 * In the meantime, we manually poll again with no timeout to see if it was the client that has activity. */
		if (bbs_poll(node, 0) > 0) {
			char clientbuf[512]; /* Use a separate buf so that bbs_fd_readline gets its own buf for the server reads */

			/* No need to use a fancy bbs_readline struct, since we can reasonably expect to get 1 full line at a time, nothing more, nothing less */
			res = bbs_readline(node, 0, clientbuf, sizeof(clientbuf) - 1);
			if (res <= 0) {
				bbs_warning("bbs_fd_readline returned %d\n", res);
				break;
			}
			clientbuf[res] = '\0'; /* Safe */
			bbs_strterm(clientbuf, '\r'); /* If we did get a CR, strip it */

			/* Parse the user's message. Note this isn't IRC syntax, it's just STDIN input.
			 * Unless the user typed /quit, we can basically just build a message and send it to the channel. */
			if (!strcasecmp(clientbuf, "/quit")) {
				break;
			}
			irc_client_msg(ircl, channel, clientbuf); /* Actually send to IRC */

			/* Make our timestamp */
			if (!NODE_IS_TDD(node)) {
				now = time(NULL);
				localtime_r(&now, &sendtime);
				strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime);
			}

			bbs_writef(node, "%s<%s> %s\n", datestr, irc_client_username(ircl), clientbuf); /* Echo the user's own message */
		} else if (irc_poll(ircl, 0, -1) > 0) { /* Must've been the server. */
			char tmpbuf[2048];
			int ready;
			/* bbs_fd_readline internally will call poll(), but we already polled inside irc_poll,
			 * and then poll() again to see which file descriptor had activity,
			 * so just pass 0 as poll should always return > 0 anyways, immediately,
			 * since we haven't read any data yet to quell the poll. */

			/* Another clunky thing. Need to get data using irc_read, but we want to buffer it using a bbs_readline struct.
			 * So relay using a pipe.
			 */
			res = irc_read(ircl, tmpbuf, sizeof(tmpbuf));
			res = bbs_fd_readline_append(&rldata, "\r\n", tmpbuf, res, &ready);
			if (!ready) {
				continue;
			}
			do {
				struct irc_msg msg_stack, *msg = &msg_stack;
				if (res < 0) {
					res += 1; /* Convert the res back to a normal one. */
					if (res == 0) {
						/* No data to read. This shouldn't happen if irc_poll returned > 0 */
						bbs_warning("bbs_fd_readline returned %d\n", res - 1); /* And subtract 1 again to match what it actually returned before we added 1 */
					}
					goto cleanup;
				}
				/* Parse message from server */
				memset(&msg_stack, 0, sizeof(msg_stack));
				if (!irc_parse_msg(&msg_stack, buf)) {
					/* Condensed version of what handle_irc_msg does */
					if (msg->numeric) {
						bbs_writef(node, "%s %d %s\n", NODE_IS_TDD(node) ? "" : S_IF(msg->prefix), msg->numeric, msg->body);
					} else {
						bbs_assert_exists(msg->command);
						if (!strcmp(msg->command, "PRIVMSG") || !strcmp(msg->command, "NOTICE")) { /* This is intentionally first, as it's the most common one. */
							/* NOTICE is same as PRIVMSG, but should never be acknowledged (replied to), to prevent loops, e.g. for use with bots. */
							char *channel_name, *body = msg->body;

							/* Format of msg->body here is CHANNEL :BODY */
							channel_name = strsep(&body, " ");
							body++; /* Skip : */
							if (*body == 0x01) { /* sscanf stripped off the leading : */
								handle_ctcp(NULL, ircl, channel_name, node, msg, body);
							} else {
								char *tmp = strchr(msg->prefix, '!');
								if (tmp) {
									*tmp = '\0'; /* Strip everything except the nickname from the prefix */
								}
								if (!NODE_IS_TDD(node)) {
									now = time(NULL);
									localtime_r(&now, &sendtime);
									strftime(datestr, sizeof(datestr), "%m-%d %I:%M:%S%P ", &sendtime);
								}
								bbs_writef(node, "%s<%s> %s\n", datestr, msg->prefix, body);
							}
						} else if (!strcmp(msg->command, "PING")) {
							/* Reply with the same data that it sent us (some servers may actually require that) */
							int sres = irc_send(ircl, "PONG :%s", msg->body ? msg->body + 1 : ""); /* If there's a body, skip the : and bounce the rest back */
							if (sres) {
								return 0;
							}
						} else if (!strcmp(msg->command, "JOIN")) {
							bbs_writef(node, "%s has %sjoined%s\n", msg->prefix, COLOR(COLOR_GREEN), COLOR_RESET);
						} else if (!strcmp(msg->command, "PART")) {
							bbs_writef(node, "%s has %sleft%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
						} else if (!strcmp(msg->command, "QUIT")) {
							bbs_writef(node, "%s has %squit%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
						} else if (!strcmp(msg->command, "KICK")) {
							bbs_writef(node, "%s has been %skicked%s\n", msg->prefix, COLOR(COLOR_RED), COLOR_RESET);
						} else if (!strcmp(msg->command, "NICK")) {
							bbs_writef(node, "%s is %snow known as%s %s\n", msg->prefix, COLOR(COLOR_CYAN), COLOR_RESET, msg->body);
						} else if (!strcmp(msg->command, "MODE")) {
							/* Ignore */
						} else if (!strcmp(msg->command, "ERROR")) {
							/* Ignore, do not send errors to users */
						} else if (!strcmp(msg->command, "TOPIC")) {
							bbs_writef(node, "Topic is now %s\n", msg->body);
						} else {
							bbs_warning("Unhandled command: prefix: %s, command: %s, body: %s\n", msg->prefix, msg->command, msg->body);
						}
					}
				}

				/* Okay, now because bbs_fd_readline might have read MULTIPLE lines from the server,
				 * call it again to make sure there isn't any further input.
				 * We use a timeout of 0, because if there isn't another message ready already,
				 * then we should just go back to the outer poll.
				 */
				res = bbs_fd_readline(node->slavefd, &rldata, "\r\n", 0);
			} while (res > 0);
		} else { /* Shouldn't happen */
			bbs_warning("irc_poll returned activity, but neither client nor server has pending data?\n");
		}
	}

cleanup:
	irc_client_destroy(ircl);
	return 0;
}

static int irc_client_exec(struct bbs_node *node, const char *args)
{
	char buf[84];
	char *channel, *client;
	struct participant *p;
	int res;

	if (strlen_zero(args)) {
		bbs_error("Must specify a client name to use (syntax: client,channel)\n");
		return 0; /* Don't disconnect the node */
	}

	safe_strncpy(buf, args, sizeof(buf));
	channel = buf;
	client = strsep(&channel, ",");

	if (strlen_zero(channel) || strlen_zero(client)) {
		bbs_error("Must specify a client and channel (syntax: client,channel)\n");
		return 0;
	}

	/* Join via a dedicated connection, dynamically. Especially useful if trying to join the local BBS IRC server,
	 * since then we can have a 1:1 connection for each client. */
	if (STARTS_WITH(client, "irc://") || STARTS_WITH(client, "ircs://")) {
		return irc_single_client(node, client, channel);
	}

	/* Join via a preconstructed client. */
	p = join_client(node, client);
	if (!p) {
		return 0;
	}

	p->channel = channel;
	res = participant_relay(node, p, channel);
	leave_client(p->client, p);
	return res;
}

static int unload_module(void)
{
	struct client *client;

	RWLIST_WRLOCK(&clients);
	unloading = 1;

	while ((client = RWLIST_REMOVE_HEAD(&clients, entry))) {
		struct participant *p;
		irc_client_destroy(client->client);
		/* If there are any clients still connected, boot them */
		while ((p = RWLIST_REMOVE_HEAD(&client->participants, entry))) {
			/* XXX Because the usecount will be positive if clients are being used, the handling to remove participants may be kind of moot */
			/* Remove from list, but don't actually free the participant itself. Each node will do that as it leaves. */
			close(p->chatpipe[1]); /* Close write end of pipe to kick the node from the client */
			p->chatpipe[1] = -1;
		}
		pthread_cancel(client->thread); /* Kill the relay thread for this client, if it hasn't already exited by now. */
		bbs_pthread_join(client->thread, NULL);
		if (client->logfile) {
			fclose(client->logfile);
		}
		client_free(client);
	}
	RWLIST_UNLOCK(&clients);

	return bbs_unregister_door("irc");
}

static int load_module(void)
{
	int res;

	if (load_config()) {
		return -1;
	}
	irc_log_callback(__client_log); /* Set up logging */
	res = bbs_register_door("irc", irc_client_exec);
	if (!res) {
		/* Start the clients now, unless the BBS is still starting */
		if (bbs_is_fully_started()) {
			start_clients();
		} else {
			bbs_register_startup_callback(start_clients);
		}
	}
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_FLAGS("Internet Relay Chat Client", MODFLAG_GLOBAL_SYMBOLS);
