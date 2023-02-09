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
 * \brief ChanServ (Channel Services) for integrated IRC Server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "include/mod_mysql.h"

#include "include/config.h"
#include "include/module.h"
#include "include/utils.h"

#include "include/net_irc.h"

/*
 * This is a separate module for two important reasons.
 * One is that modularity is just good in general, for maintainability.
 * More importantly, we may want to reload ChanServ without disrupting the IRC server itself.
 * It thus also follows that this module is dependent on net_irc, and not the other way around:
 * this allows us to unload/reload THIS module without having to unload net_irc.
 *
 * Note that unlike net_irc, which has no persistent storage,
 * many operations of ChanServ are backed by persistent storage (MySQL/MariaDB database)
 */

static char buf_dbhostname[32] = "";
static char buf_dbusername[32] = "";
static char buf_dbpassword[32] = "";
static char buf_dbname[32];

struct chanserv_subcmd {
	const char *name;
	const char *description;
	const char *help;
};

struct chanserv_cmd {
	const char *name;
	void (*handler)(const char *username, char *msg);
	struct chanserv_subcmd *subcmds;
	int subcmdslen;
	const char *description;
	const char *help;
};

#define chanserv_notice(recipient, fmt, ...) chanserv_send("NOTICE %s :" fmt, recipient, ## __VA_ARGS__)

static int __attribute__ ((format (gnu_printf, 1, 2))) chanserv_send(const char *fmt, ...)
{
	char *buf;
	int len, res = 0;
	char *crlf;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		bbs_error("vasprintf failure\n");
		return -1;
	}

	crlf = strstr(buf, "\r\n");
	if (crlf) {
		bbs_warning("ChanServ should not add a trailing CR LF\n");
		*crlf = '\0';
	}

	bbs_debug(5, "<= %s\n", buf);
	res |= chanserv_exec(buf);
	free(buf);
	return res;
}

/*! \retval 0 on success (result rows), -1 on failure, 1 if no results */
#pragma GCC diagnostic ignored "-Wstack-protector"
static int sql_fetch_strings(const char *username, const char *channel, void cb(const char *username, const char *strfields[]), const char *fmt, const char *sql)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int mysqlres;
	int res = -1;
	unsigned int i;
	const unsigned int num_fields = strlen(fmt);

	/* XXX Query should only have one parameter (one ?) */

	mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		goto cleanup;
	}

	if (sql_prep_bind_exec(stmt, sql, "s", channel)) {
		return -1;
	} else {
		/* Indented a block since we need num_fields */
		MYSQL_BIND results[num_fields]; /* should be equal to number of selected cols */
		unsigned long int lengths[num_fields]; /* Only needed for string result fields */
		int bind_ints[num_fields];
		char *bind_strings[num_fields];
		my_bool bind_null[num_fields];
		char strfields[num_fields][64]; /* Hopefully enough for anything we want */
#pragma GCC diagnostic pop

		memset(results, 0, sizeof(results));
		memset(lengths, 0, sizeof(lengths));
		memset(bind_strings, 0, sizeof(bind_strings));

		/* Set stack-allocated string fields */
		for (i = 0; i < num_fields; i++) {
			bind_strings[i] = strfields[i];
			lengths[i] = sizeof(strfields[i]) - 1;
		}

		if (sql_bind_result(stmt, fmt, results, lengths, bind_ints, bind_strings, NULL, bind_null)) {
			return res;
		}

		while (MYSQL_NEXT_ROW(stmt)) {
			cb(username, (const char **) bind_strings); /* Only call on success */
			res = 0;
		}
	}

	if (res != 0) {
		res = 1;
	}

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
	return res;
}

#pragma GCC diagnostic ignored "-Wstack-protector"
static int fetch_channel_owner(MYSQL_STMT *stmt, const char *channel, char *buf, size_t len)
{
	char sql[184];
	int mysqlres;
	/* SQL SELECT */
	const char *fmt = "s";
	int res = -1;
	const unsigned int num_fields = strlen(fmt);

	*buf = '\0';

	snprintf(sql, sizeof(sql), "SELECT founder FROM %s.channels WHERE name = ? LIMIT 1", buf_dbname);

	if (sql_prep_bind_exec(stmt, sql, "s", channel)) {
		return -1;
	} else {
		/* Indented a block since we need num_fields */
		MYSQL_BIND results[num_fields]; /* should be equal to number of selected cols */
		unsigned long int lengths[num_fields]; /* Only needed for string result fields */
		int bind_ints[num_fields];
		char *bind_strings[num_fields];
		my_bool bind_null[num_fields];
		MYSQL_TIME bind_dates[num_fields];
#pragma GCC diagnostic pop

		memset(results, 0, sizeof(results));
		memset(lengths, 0, sizeof(lengths));
		memset(bind_strings, 0, sizeof(bind_strings));

		if (sql_bind_result(stmt, fmt, results, lengths, bind_ints, bind_strings, bind_dates, bind_null)) {
			goto stmtcleanup;
		}

		while (MYSQL_NEXT_ROW(stmt)) {
			char *founder;

			/* Must allocate string results before attempting to use them */
			if (sql_alloc_bind_strings(stmt, fmt, results, lengths, bind_strings)) { /* Needs to be called if we don't use sql_string_prep in advance for all strings. */
				break; /* If we fail for some reason, don't crash attempting to access NULL strings */
			} else if (sql_fetch_columns(bind_ints, NULL, bind_strings, bind_dates, bind_null, fmt, &founder)) { /* We have no longs, so NULL is fine */
				break;
			}

			bbs_debug(3, "Founder of %s is %s\n", channel, founder);
			safe_strncpy(buf, founder, len);
			sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Call inside the while loop, since strings only need to be freed per row */
			res = 0;
		}

stmtcleanup:
		sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Won't hurt anything, clean up in case we break from the loop */
	}

	return res;
}

static int channel_set_flag(const char *username, const char *channel, const char *column, int enabled)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	char sql[184];
	char existingfounder[64];
	int res = -1;
	const char *types = "s";

	snprintf(sql, sizeof(sql), "UPDATE channels SET %s = %d WHERE name = ?", column, enabled ? 1 : 0);

	mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		chanserv_notice(username, "ChanServ failure - please contact an IRC operator.");
		goto cleanup;
	}

	/* Must be authorized to make the change */
	if (!fetch_channel_owner(stmt, channel, existingfounder, sizeof(existingfounder))) {
		/* Channel is already registered with ChanServ */
		if (strcmp(existingfounder, username)) {
			chanserv_notice(username, "You are not authorized to perform this operation.");
			goto cleanup;
		}
	} else {
		chanserv_notice(username, "%s is not registered.", channel);
		goto cleanup;
	}

	/* XXX Don't change if there is no change.
	 * e.g. The GUARD flag is already set for channel #channel / The GUARD flag is not set for channel #channel. */

	if (sql_prep_bind_exec(stmt, sql, types, "")) { /* Bind parameters and execute */
		chanserv_notice(username, "ChanServ failure - please contact an IRC operator.");
		goto cleanup;
	}
	res = 0;

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
	return res;
}

#if 0
static int update_colval(const char *username, const char *channel, const char *column, const char *value)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	char sql[184];
	char existingfounder[64];
	int res = -1;
	const char *types = "ss";

	snprintf(sql, sizeof(sql), "UPDATE %s.channels SET %s = ? WHERE name = ?", column, buf_dbname);

	mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		chanserv_notice(founder, "ChanServ failure - please contact an IRC operator.");
		goto cleanup;
	}

	/* Must be authorized to make the change */
	if (!fetch_channel_owner(stmt, channel, existingfounder, sizeof(existingfounder))) {
		/* Channel is already registered with ChanServ */
		if (strcmp(existingfounder, username)) {
			chanserv_notice(username, "You are not authorized to perform this operation.");
			goto cleanup;
		}
	}

	/* Try to register it. This is still atomic, since INSERT will fail if the channel already exists. */
	if (sql_prep_bind_exec(stmt, sql, types, value, channel)) { /* Bind parameters and execute */
		chanserv_notice(founder, "ChanServ failure - please contact an IRC operator.");
		goto cleanup;
	}
	res = 0;

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
	return res;
}
#endif

static void chanserv_init(void)
{
	/* Join any channels with GUARD enabled */
	/*! \todo */
	/*! \todo and on demand when flag set */
	/*! \todo chanserv can't be kicked from channels */
}

static int do_register(const char *channel, const char *founder)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	char sql[184];
	char existingfounder[64];
	int res = -1;
	const char *types = "ss";

	snprintf(sql, sizeof(sql), "INSERT INTO %s.channels (name, founder) VALUES (?, ?)", buf_dbname);

	mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		chanserv_notice(founder, "Failed to register %s - please contact an IRC operator.", channel);
		goto cleanup;
	}

	if (!fetch_channel_owner(stmt, channel, existingfounder, sizeof(existingfounder))) {
		/* Channel is already registered with ChanServ */
		chanserv_notice(founder, "%s is already registered to %s", channel, founder);
		goto cleanup;
	}

	/* Try to register it. This is still atomic, since INSERT will fail if the channel already exists. */
	if (sql_prep_bind_exec(stmt, sql, types, channel, founder)) { /* Bind parameters and execute */
		chanserv_notice(founder, "Failed to register %s - please contact an IRC operator.", channel);
		goto cleanup;
	}
	res = 0;

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
	return res;
}

static void chanserv_register(const char *username, char *msg)
{
	const char *channel = msg;
	enum channel_user_modes modes;

	if (strlen_zero(channel)) {
		chanserv_notice(username, "Insufficient parameters for REGISTER.");
		chanserv_notice(username, "To register a channel: REGISTER <#channel>");
		return;
	}

	/* Must be a channel operator to register. */
	modes = irc_get_channel_member_modes(channel, username); /* We could issue a NAMES or some other command to determine this (probably what real ChanServ bots do), but this is more direct */
	if (!(modes & CHANNEL_USER_MODE_OP)) {
		chanserv_notice(username, "You must be a channel operator in %s in order to register it.", channel);
		return;
	}

	if (!do_register(channel, username)) {
		chanserv_notice(username, "%s is now registered to %s", channel, username);
		/* The %s namespace is managed by the %s project (channel, org) */
	}
}

/*! \brief Called on successful queries for INFO commands */
static void info_cb(const char *username, const char *fields[])
{
	/* Array length is what we expect it to be. Be careful! */
	chanserv_notice(username, "Information on %s:", fields[0]);
	chanserv_notice(username, "Founder  : %s", fields[1]);
	chanserv_notice(username, "Registered  : %s", fields[2]);
}

static void chanserv_info(const char *username, char *msg)
{
	int res;
	if (strlen_zero(msg)) {
		chanserv_notice(username, "Insufficient parameters for INFO.");
		chanserv_notice(username, "Syntax: INFO <#channel>");
		return;
	}
	/* XXX %b format doesn't seem to work? */
	res = sql_fetch_strings(username, msg, info_cb, "sss", "SELECT name, founder, DATE_FORMAT(registered, '%b %e %H:%i:%S %Y') AS date FROM channels WHERE name = ?");
	if (res == -1) {
		chanserv_notice(username, "ChanServ could not fulfill your request. Please contact an IRC operator.");
	} else if (res == 1) {
		chanserv_notice(username, "%s is not registered.", msg);
	}
}

static struct chanserv_subcmd chanserv_set_cmds[] =
{
	{ "GUARD", "Sets whether or not services will inhabit the channel.", "SET GUARD allows you to have ChanServ join your channel.\r\nSyntax: SET <#channel> GUARD ON|OFF" },
};

static void chanserv_set(const char *username, char *msg)
{
	char *channel, *setting, *params;

	if (strlen_zero(msg)) {
		chanserv_notice(username, "Insufficient parameters for SET.");
		chanserv_notice(username, "Syntax: SET <#channel> <setting> [parameters]");
		return;
	}
	channel = strsep(&msg, " ");
	setting = strsep(&msg, " ");
	params = msg;
	if (!params) {
		chanserv_notice(username, "Insufficient parameters for SET.");
		chanserv_notice(username, "Syntax: SET <#channel> <setting> [parameters]");
		return;
	}

	if (!strcasecmp(setting, "GUARD")) {
		int enabled = S_TRUE(params);
		if (!channel_set_flag(username, channel, "guard", enabled)) {
			chanserv_notice(username, "The GUARD flag has been %s for channel %s", enabled ? "set" : "removed", channel);
			/*! \todo Actually add or remove ChanServ from channel in question */
		}
	} else {
		chanserv_notice(username, "Invalid ChanServ SET subcommand.");
		chanserv_notice(username, "Use /msg ChanServ HELP SET for a ChanServ SET subcommand listing.");
	}
}

/* Forward declaration, since chanserv_help references chanserv_cmds */
static void chanserv_help(const char *username, char *msg);

static struct chanserv_cmd chanserv_cmds[] =
{
	{ "HELP", chanserv_help, NULL, 0, "Displays contextual help information.", "HELP displays help information on all commands in services.\r\n"
		"Syntax: HELP <command> [parameters]" },
	{ "INFO", chanserv_info, NULL, 0, "Displays information on registrations.", "INFO displays channel information such as registration time, flags, and other details.\r\n"
		"Syntax: INFO <#channel>" },
	{ "REGISTER", chanserv_register, NULL, 0, "Registers a channel.", "REGISTER allows you to register a channel so that you have better control.\r\n"
		"Registration allows you to maintain a channel access list and other functions that are normally provided by IRC bots.\r\n"
		"Syntax: REGISTER <#channel>" },
	{ "SET", chanserv_set, chanserv_set_cmds, ARRAY_LEN(chanserv_set_cmds), "Sets various control flags.",
		"SET allows you to set various control flags for channels that change the way certain operations are performed on them.\r\n"
		"Syntax: SET <#channel> <setting> [parameters]" },
};

static void send_help(const char *username, const char *cmd, const char *subcmd, const char *s)
{
	char *line, *lines, *linesdup;
	chanserv_notice(username, "Help for %s%s%s:", cmd, subcmd ? " " : "", S_IF(subcmd));
	lines = linesdup = strdup(s);
	if (!lines) {
		return;
	}
	/* We shouldn't send CR LF here, but do allow it to be used as a separator,
	 * which will send multiple messages under the hood. */
	while ((line = strsep(&lines, "\r\n"))) {
		if (strlen_zero(line)) {
			continue; /* Skip blank lines. IRC doesn't allow empty messages (and just whitespace isn't allowed, either) */
		}
		chanserv_notice(username, "%s", line);
	}
	free(linesdup);
}

static void chanserv_help(const char *username, char *msg)
{
	long unsigned int x;
	chanserv_notice(username, "***** ChanServ Help *****");
	if (!strlen_zero(msg)) {
		char *cmd, *subcmd = msg;
		cmd = strsep(&subcmd, " ");
		for (x = 0; x < ARRAY_LEN(chanserv_cmds); x++) {
			if (!strcasecmp(chanserv_cmds[x].name, cmd)) {
				int j;
				if (!strlen_zero(subcmd) && chanserv_cmds[x].subcmds) {
					for (j = 0; j < chanserv_cmds[x].subcmdslen; j++) {
						if (!strcasecmp(chanserv_cmds[x].subcmds[j].name, subcmd)) {
							send_help(username, chanserv_cmds[x].name, chanserv_cmds[x].subcmds[j].name, chanserv_cmds[x].subcmds[j].help);
							goto done; /* In a double loop */
						}
					}
				} else {
					send_help(username, chanserv_cmds[x].name, NULL, chanserv_cmds[x].help);
					if (chanserv_cmds[x].subcmds) {
						chanserv_notice(username, "The following subcommands are available:");
						for (j = 0; j < chanserv_cmds[x].subcmdslen; j++) {
							chanserv_notice(username, "%-15s %s", chanserv_cmds[x].subcmds[j].name, chanserv_cmds[x].subcmds[j].description);
						}
						chanserv_notice(username, "For more information on a ChanServ %s subcommand, type:", chanserv_cmds[x].name);
						chanserv_notice(username, "/msg ChanServ HELP %s <subcommand>", chanserv_cmds[x].name);
					}
					break;
				}
			}
		}
done:
		/* Command wasn't found */
		if (x >= ARRAY_LEN(chanserv_cmds)) {
			chanserv_notice(username, "No such command %s.", msg);
		}
	} else {
		/* I guess we can't send blank lines since we can't send CR LFs... */
		chanserv_notice(username, "ChanServ gives normal users the ability to maintain control");
		chanserv_notice(username, "of a channel, without the need of a bot. Channel takeovers are");
		chanserv_notice(username, "virtually impossible when a channel is registered with ChanServ.");
		chanserv_notice(username, "The following commands are available:");
		for (x = 0; x < ARRAY_LEN(chanserv_cmds); x++) {
			/* Spacing won't be consistent since not all graphical (maybe not most) IRC clients don't use monospace fonts */
			chanserv_notice(username, "%-15s %s", chanserv_cmds[x].name, chanserv_cmds[x].description);
		}
		chanserv_notice(username, "For more information on a ChanServ command, type:");
		chanserv_notice(username, "/msg ChanServ HELP <command>");
	}
	chanserv_notice(username, "***** End of Help *****");
}

/*! \brief Handle PRIVMSGs from users trying to use ChanServ */
static void process_privmsg(const char *username, char *msg)
{
	long unsigned int x;
	char *command;
	/* We can expect that this is well-formatted or the PRIVMSG would have been rejected. */
	/* We can also expect that username is really authorized, since users can't PRIVMSG ChanServ without being logged in,
	 * and we don't allow nick changes in net_irc */
	bbs_debug(8, "=> %s: %s\n", username, msg); /* Log the message before we start mangling it */

	command = strsep(&msg, " ");
	/* Messages are close to the IRC protocol, but must NOT end in CR LF since the hook into net_irc is after CR LF is stripped */
	for (x = 0; x < ARRAY_LEN(chanserv_cmds); x++) {
		if (!strcasecmp(chanserv_cmds[x].name, command)) {
			chanserv_cmds[x].handler(username, msg);
			break;
		}
	}

	/* Command wasn't found */
	if (x >= ARRAY_LEN(chanserv_cmds)) {
		chanserv_notice(username, "Invalid ChanServ command.");
		chanserv_notice(username, "	Use /msg ChanServ HELP for a ChanServ command listing.");
	}
}

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("mod_chanserv.conf", 1);

	if (!cfg) {
		bbs_error("mod_chanserv.conf is missing, module will decline to load\n");
		return -1;
	}

	bbs_config_val_set_str(cfg, "db", "hostname", buf_dbhostname, sizeof(buf_dbhostname));
	bbs_config_val_set_str(cfg, "db", "username", buf_dbusername, sizeof(buf_dbusername));
	bbs_config_val_set_str(cfg, "db", "password", buf_dbpassword, sizeof(buf_dbpassword));
	if (bbs_config_val_set_str(cfg, "db", "database", buf_dbname, sizeof(buf_dbname))) { /* This is optional but highly recommended. */
		bbs_error("No database name specified in mod_chanserv.conf\n");
		return -1;
	}

	bbs_config_free(cfg); /* Destroy the config now, rather than waiting until shutdown, since it will NEVER be used again for anything. */
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	if (irc_chanserv_register(process_privmsg, BBS_MODULE_SELF)) {
		return -1;
	}
	chanserv_init();
	return 0;
}

static int unload_module(void)
{
	irc_chanserv_unregister(process_privmsg);
	return 0;
}

BBS_MODULE_INFO_STANDARD("ChanServ for IRC");
