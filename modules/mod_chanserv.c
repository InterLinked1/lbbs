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
static int sql_fetch_strings(const char *username, const char *channel, void cb(const char *username, const char *strfields[], int row, void *data), void *data, const char *fmt, const char *sql)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int mysqlres;
	int res = -1;
	unsigned int i;
	const unsigned int num_fields = strlen(fmt);

	if (strlen_zero(channel)) {
		bbs_error("Channel is NULL or empty?\n");
		return -1;
	}

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
		int rownum = 0;
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
			cb(username, (const char **) bind_strings, rownum++, data); /* Only call on success */
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

/*! \retval 0 on success (result rows), -1 on failure, 1 if no results */
#pragma GCC diagnostic ignored "-Wstack-protector"
static int sql_fetch_strings2(const char *username, const char *channel, const char *nickname, void cb(const char *username, const char *strfields[], int row, void *data), void *data, const char *fmt, const char *sql)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int mysqlres;
	int res = -1;
	unsigned int i;
	const unsigned int num_fields = strlen(fmt);

	if (strlen_zero(channel)) {
		bbs_error("Channel is NULL or empty?\n");
		return -1;
	}

	/* XXX Query should only have 2 parameter (two ?s) */

	mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		goto cleanup;
	}

	if (sql_prep_bind_exec(stmt, sql, "ss", channel, nickname)) {
		return -1;
	} else {
		/* Indented a block since we need num_fields */
		MYSQL_BIND results[num_fields]; /* should be equal to number of selected cols */
		unsigned long int lengths[num_fields]; /* Only needed for string result fields */
		int bind_ints[num_fields];
		char *bind_strings[num_fields];
		my_bool bind_null[num_fields];
		char strfields[num_fields][64]; /* Hopefully enough for anything we want */
		int rownum = 0;
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
			cb(username, (const char **) bind_strings, rownum++, data); /* Only call on success */
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

/*! \todo Since multiple users can have the F flag in a channel, we should really be comparing with that, than using the original founder exclusively */
#pragma GCC diagnostic ignored "-Wstack-protector"
static int get_channel_colval(MYSQL_STMT *stmt, const char *channel, const char *column, char *buf, size_t len)
{
	char sql[184];
	int mysqlres;
	/* SQL SELECT */
	const char *fmt = "s";
	int res = -1;
	const unsigned int num_fields = strlen(fmt);

	*buf = '\0';

	snprintf(sql, sizeof(sql), "SELECT %s FROM %s.channels WHERE name = ? LIMIT 1", column, buf_dbname);

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
			char *colval;

			/* Must allocate string results before attempting to use them */
			if (sql_alloc_bind_strings(stmt, fmt, results, lengths, bind_strings)) { /* Needs to be called if we don't use sql_string_prep in advance for all strings. */
				break; /* If we fail for some reason, don't crash attempting to access NULL strings */
			} else if (sql_fetch_columns(bind_ints, NULL, bind_strings, bind_dates, bind_null, fmt, &colval)) { /* We have no longs, so NULL is fine */
				break;
			}
			if (colval) {
				safe_strncpy(buf, colval, len);
			}
			sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Call inside the while loop, since strings only need to be freed per row */
			res = 0;
		}

stmtcleanup:
		sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Won't hurt anything, clean up in case we break from the loop */
	}

	return res;
}

static int fetch_channel_owner(MYSQL_STMT *stmt, const char *channel, char *buf, size_t len)
{
	return get_channel_colval(stmt, channel, "founder", buf, len);
}

static int channel_get_entrymsg(MYSQL_STMT *stmt, const char *channel, char *buf, size_t len)
{
	int res = -1;
	int connlocal = 0;
	MYSQL *mysql = NULL;

	if (!stmt) {
		connlocal = 1;
		mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
		stmt = mysql_stmt_init(mysql);
		if (!stmt) {
			goto cleanup;
		}
	}
	res = get_channel_colval(stmt, channel, "entrymsg", buf, len);
	if (!connlocal) {
		return res;
	}

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
	return res;
}

static int channel_unauthorized(const char *channel, const char *username, enum channel_user_modes mode)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	char existingfounder[64];
	int res = -1;

	mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
	if (!mysql) {
		return 0;
	}
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		chanserv_notice(username, "ChanServ failure - please contact an IRC operator.");
		goto cleanup;
	}

	/* Must be authorized to make the change */
	if (!fetch_channel_owner(stmt, channel, existingfounder, sizeof(existingfounder))) {
		res = 1; /* Channel exists, but may not be authorized */
		/* Channel is already registered with ChanServ */
		if (!strcmp(existingfounder, username)) {
			res = 0; /* Authorized */
		}
		/* XXX Need other checks here, depending on authorized for what. */
		/* XXX e.g. anyone with the +F flag is authorized. */
		UNUSED(mode);
	}

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
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

	if (sql_prep_bind_exec(stmt, sql, types, channel)) { /* Bind parameters and execute */
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

static int channel_userflags_set(const char *username, const char *channel, const char *nickname, char flag, int enabled)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	const char *sql;
	char existingfounder[64];
	char flagbuf[2] = { flag, '\0' };
	int res = -1;
	const char *types = "sss";

	if (enabled) {
		sql = "INSERT INTO channel_flags (channel, nickname, flag) VALUES (?, ?, ?)";
	} else {
		sql = "DELETE FROM channel_flags WHERE channel = ? AND nickname = ? AND flag = ?";
	}

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
	 * e.g. Channel access to #channel for jsmith unchanged.
	 * BUGBUG Right now we don't do this and sql_prep_bind_exec will fail due to duplicate entry.
	 */
	if (sql_prep_bind_exec(stmt, sql, types, channel, nickname, flagbuf)) { /* Bind parameters and execute */
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

static int update_colval(const char *username, const char *channel, const char *column, const char *value)
{
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	char sql[184];
	char existingfounder[64];
	int res = -1;
	int mres;

	if (value) {
		snprintf(sql, sizeof(sql), "UPDATE channels SET %s = ? WHERE name = ?", column);
	} else {
		snprintf(sql, sizeof(sql), "UPDATE channels SET %s = NULL WHERE name = ?", column);
	}

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
	}

	if (value) {
		const char *types = "ss";
		mres = sql_prep_bind_exec(stmt, sql, types, value, channel);
	} else {
		const char *types = "s";
		mres = sql_prep_bind_exec(stmt, sql, types, channel);
	}

	/* Try to register it. This is still atomic, since INSERT will fail if the channel already exists. */
	if (mres) { /* Bind parameters and execute */
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
		channel_userflags_set(username, channel, username, 'F', 1); /* Founder flag */
	}
}

/*! \brief Called on successful queries for INFO commands */
static void info_cb(const char *username, const char *fields[], int row, void *data)
{
	/* Array length is what we expect it to be. Be careful! */
	chanserv_notice(username, "Information on %s:", fields[0]);
	chanserv_notice(username, "Founder  : %s", fields[1]);
	chanserv_notice(username, "Registered  : %s", fields[2]);
	if (fields[3]) {
		chanserv_notice(username, "Mode lock  : %s", fields[3]);
	}
	if (fields[4]) {
		chanserv_notice(username, "Entrymsg  : %s", fields[4]);
	}
	chanserv_notice(username, "Flags  :%s%s", fields[5], fields[6]);
	UNUSED(row);
	UNUSED(data);
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
	res = sql_fetch_strings(username, msg, info_cb, NULL, "sssssss", "SELECT name, founder, DATE_FORMAT(registered, '%b %e %H:%i:%S %Y') AS date, modelock, entrymsg, IF(guard = 1, ' GUARD ', '') AS guardflag, IF(keeptopic = 1, ' KEEPTOPIC ', '') AS keeptopicflag FROM channels WHERE name = ?");
	if (res == -1) {
		chanserv_notice(username, "ChanServ could not fulfill your request. Please contact an IRC operator.");
	} else if (res == 1) {
		chanserv_notice(username, "%s is not registered.", msg);
	}
}

static struct chanserv_subcmd chanserv_set_cmds[] =
{
	{ "ENTRYMSG", "Sets the channel entry message.", "SET ENTRYMSG allows you to change or set a message sent to all users joining the channel.\r\n" "Syntax: SET <#channel> ENTRYMSG [message]" },
	{ "GUARD", "Sets whether or not services will inhabit the channel.", "SET GUARD allows you to have ChanServ join your channel.\r\nSyntax: SET <#channel> GUARD ON|OFF" },
	{ "MLOCK", "Sets channel mode lock.", "MLOCK (or \"mode lock\") allows you to enforce a set of modes on a channel." },
	{ "KEEPTOPIC", "Enables topic retention.", "SET KEEPTOPIC enables restoration of the old topic after the channel has become empty.\r\nIn some cases, it may revert topic changes after services outages, so it is\r\nnot recommended to turn this on if your channel tends to never empty." }
};

#define REQUIRE_SET_PARAMS() \
	if (!params) { \
		chanserv_notice(username, "Insufficient parameters for SET."); \
		chanserv_notice(username, "Syntax: SET <#channel> <setting> [parameters]"); \
		return; \
	}

static void chanserv_set(const char *username, char *msg)
{
	char *channel, *setting, *params;
	int enabled;

	if (strlen_zero(msg)) {
		chanserv_notice(username, "Insufficient parameters for SET.");
		chanserv_notice(username, "Syntax: SET <#channel> <setting> [parameters]");
		return;
	}
	channel = strsep(&msg, " ");
	setting = strsep(&msg, " ");
	params = msg;

	if (!strcasecmp(setting, "ENTRYMSG")) {
		/* XXX 3 cases:
		 * The entry message for #channel has been cleared.
		 * The entry message for #channel was not set.
		 * The entry message for #channel has been set to <params>. */
		if (!update_colval(username, channel, "entrymsg", S_OR(params, NULL))) { /* Use explicit NULL if empty */
			if (!strlen_zero(params)) {
				chanserv_notice(username, "The entry message for %s has been set to %s.", channel, S_OR(params, NULL));
			} else {
				chanserv_notice(username, "The entry message for %s has been cleared.", channel);
			}
		}
	} else if (!strcasecmp(setting, "GUARD")) {
		REQUIRE_SET_PARAMS();
		enabled = S_TRUE(params);
		if (!channel_set_flag(username, channel, "guard", enabled)) {
			chanserv_notice(username, "The GUARD flag has been %s for channel %s", enabled ? "set" : "removed", channel);
			/* Actually join or leave the channel */
			if (enabled) {
				chanserv_send("JOIN %s", channel);
			} else {
				chanserv_send("PART %s", channel);
			}
		}
	} else if (!strcasecmp(setting, "KEEPTOPIC")) {
		REQUIRE_SET_PARAMS();
		enabled = S_TRUE(params);
		if (!channel_set_flag(username, channel, "keeptopic", enabled)) {
			chanserv_notice(username, "The KEEPTOPIC flag has been %s for channel %s", enabled ? "set" : "removed", channel);
			/* Actually update our copy of the topic */
			if (enabled) {
				const char *topic = irc_channel_topic(channel);
				if (!strlen_zero(topic)) {
					update_colval(username, channel, "topic", topic);
				}
			} else {
				update_colval(username, channel, "topic", NULL);
			}
		}
	} else if (!strcasecmp(setting, "MLOCK")) {
		/* 2 cases:
		 * The MLOCK for #channel has been set to <params>
		 * The MLOCK for #channel has been removed. */
		if (!update_colval(username, channel, "modelock", S_OR(params, NULL))) { /* Use explicit NULL if empty */
			if (!strlen_zero(params)) {
				chanserv_notice(username, "The MLOCK for %s has been set to %s.", channel, params);
			} else {
				chanserv_notice(username, "The MLOCK for %s has been cleared.", channel);
			}
			/*! \todo XXX MLOCK is actually supposed to enforce the modes in the MLOCK at all times, not just on channel recreate.
			 * Therefore, sending these modes now is a start, but net_irc also needs to prevent any modes in the mlock from being unset. */
			if (!strlen_zero(params)) {
				chanserv_send("MODE %s %s", channel, params);
			} /* else, leave any existing modes intact if MLOCK if removed. */
		}
	} else {
		chanserv_notice(username, "Invalid ChanServ SET subcommand.");
		chanserv_notice(username, "Use /msg ChanServ HELP SET for a ChanServ SET subcommand listing.");
	}
}

static void flag_view_cb(const char *username, const char *fields[], int row, void *data)
{
	if (data) { /* Means we filtered to a single user only */
		chanserv_notice(username, "Flags for %s in %s are +%s", fields[1], fields[0], fields[2]);
		return;
	}
	if (!row) {
		chanserv_notice(username, "Entry        Nickname        Flags");
	}
	chanserv_notice(username, "%d    %s     +%s", row + 1, fields[1], fields[2]);
}

static void chanserv_flags(const char *username, char *msg)
{
	char *channel, *nickname, *flags;

	if (strlen_zero(msg)) {
		chanserv_notice(username, "	Insufficient parameters for FLAGS.");
		chanserv_notice(username, "Syntax: FLAGS <channel> [target] [flags]");
		return;
	}
	channel = strsep(&msg, " ");
	nickname = strsep(&msg, " ");
	flags = msg;

	/* If a channel exists, there should always be at least one entry in channel_flags for it, so no results ~ channel not registered */

	if (!nickname) { /* Just view existing flags */
		int res = sql_fetch_strings(username, channel, flag_view_cb, NULL, "sss", "SELECT channel, nickname, GROUP_CONCAT(flag ORDER BY flag '' SEPARATOR '') AS flags FROM channel_flags WHERE channel = ? GROUP BY channel, nickname");
		if (res == -1) {
			chanserv_notice(username, "ChanServ could not fulfill your request. Please contact an IRC operator.");
		} else if (res == 1) {
			chanserv_notice(username, "%s is not registered.", channel);
		} else {
			chanserv_notice(username, "End of %s FLAGS listing.", channel);
		}
	} else if (strlen_zero(flags)) { /* View flags for a single user */
		int res = sql_fetch_strings2(username, channel, nickname, flag_view_cb, nickname, "sss", "SELECT channel, nickname, GROUP_CONCAT(flag ORDER BY flag  SEPARATOR '') AS flags FROM channel_flags WHERE channel = ? AND nickname = ? GROUP BY channel, nickname");
		if (res == -1) {
			chanserv_notice(username, "ChanServ could not fulfill your request. Please contact an IRC operator.");
		} else if (res == 1) {
			chanserv_notice(username, "%s is not registered.", channel);
		}
	} else { /* Modify flags */
		int res = -1, enabled = *flags++ == '+' ? 1 : 0;
		char validflags[64] = "";
		int left = sizeof(validflags) - 1;
		int attempted = 0;
		char *flagptr = validflags;
		while (*flags) {
			/*! \todo People who are operators (but not the/a founder),
			 * should be able to add the +O flag for themselves. */
			if (strchr("FOV", *flags)) { /* Valid flag? */
				attempted++;
				res = channel_userflags_set(username, channel, nickname, *flags, enabled);
				if (!res && --left > 1) { /* Cheaper than strncat, works with a char (instead of a string), and buffer safe */
					*flagptr++ = *flags;
				}
			} /* else, invalid flag, ignore */
			flags++;
		}
		*flagptr = '\0';
		if (!s_strlen_zero(validflags)) {
			chanserv_notice(username, "Flags %c%s were set on %s in %s", enabled ? '+' : '-', msg + 1, nickname, channel);
		} else if (!attempted) { /* Never actually called channel_userflags_set */
			chanserv_notice(username, "No valid flags given, use /msg ChanServ HELP FLAGS for a list");
		}
	}
}

static void chanserv_chan_user_mode(const char *username, enum channel_user_modes mode, int set, char *msg)
{
	int res;
	const char *channel, *nickname;

	if (strlen_zero(msg)) {
		chanserv_notice(username, "	Insufficient parameters for %s.", mode & CHANNEL_USER_MODE_OP ? "OP" : "VOICE");
		chanserv_notice(username, "Syntax: %s <#channel> [nickname] [...]", mode & CHANNEL_USER_MODE_OP ? "OP" : "VOICE");
		return;
	}
	channel = strsep(&msg, " ");
	nickname = strsep(&msg, " ");

	if (strlen_zero(nickname)) {
		nickname = username;
	}

	/* Must be authorized to make the change */
	res = channel_unauthorized(channel, username, CHANNEL_USER_MODE_OP);
	if (res > 0) {
		/* Channel is already registered with ChanServ */
		chanserv_notice(username, "You are not authorized to perform this operation.");
		return;
	} else if (res < 0) {
		chanserv_notice(username, "%s is not registered.", channel);
		return;
	}

	/* This is not persistent, it's just a one time thing... e.g. can use +O flag on user for persistence. */
	chanserv_send("MODE %s %c%c %s", channel, set ? '+' : '-', mode & CHANNEL_USER_MODE_OP ? 'o' : 'v', nickname);
}

static void chanserv_op(const char *username, char *msg)
{
	return chanserv_chan_user_mode(username, CHANNEL_USER_MODE_OP, 1, msg);
}

static void chanserv_deop(const char *username, char *msg)
{
	return chanserv_chan_user_mode(username, CHANNEL_USER_MODE_OP, 0, msg);
}

static void chanserv_voice(const char *username, char *msg)
{
	return chanserv_chan_user_mode(username, CHANNEL_USER_MODE_VOICE, 1, msg);
}

static void chanserv_devoice(const char *username, char *msg)
{
	return chanserv_chan_user_mode(username, CHANNEL_USER_MODE_VOICE, 0, msg);
}

/* Forward declaration, since chanserv_help references chanserv_cmds */
static void chanserv_help(const char *username, char *msg);

static struct chanserv_cmd chanserv_cmds[] =
{
	{ "DEOP", chanserv_deop, NULL, 0, "Removes channel ops from a user.", "These commands perform status mode changes on a channel.\r\n"
		"If the last parameter is omitted the action is performed on the person requesting the command.\r\n"
		"Syntax: DEOP <#channel> [nickname]" },
	{ "DEVOICE", chanserv_devoice, NULL, 0, "Removes channel voice from a user.", "These commands perform status mode changes on a channel.\r\n"
		"If the last parameter is omitted the action is performed on the person requesting the command.\r\n"
		"Syntax: DEVOICE <#channel> [nickname]" },
	{ "FLAGS", chanserv_flags, NULL, 0, "Manipulates specific permissions on a channel.", "The FLAGS command allows for the granting/removal of channel privileges on a more specific, non-generalized level.\r\n"
		"It supports nicknames as targets.\r\n"
		"When only the channel argument is given, a listing of permissions granted to users will be displayed.\r\n"
		"Syntax: FLAGS <#channel>\r\n"
		"Syntax: FLAGS <#channel> [nickname]\r\n"
		"Permissions:\r\n"
		"+F - Grants full founder access.\r\n"
		"+O - Enables automatic op.\r\n"
		"+V - Enables automatic voice."
		},
	{ "HELP", chanserv_help, NULL, 0, "Displays contextual help information.", "HELP displays help information on all commands in services.\r\n"
		"Syntax: HELP <command> [parameters]" },
	{ "INFO", chanserv_info, NULL, 0, "Displays information on registrations.", "INFO displays channel information such as registration time, flags, and other details.\r\n"
		"Syntax: INFO <#channel>" },
	{ "OP", chanserv_op, NULL, 0, "Gives channel ops to a user.", "These commands perform status mode changes on a channel.\r\n"
		"If the last parameter is omitted the action is performed on the person requesting the command.\r\n"
		"Syntax: OP <#channel> [nickname]" },
	{ "REGISTER", chanserv_register, NULL, 0, "Registers a channel.", "REGISTER allows you to register a channel so that you have better control.\r\n"
		"Registration allows you to maintain a channel access list and other functions that are normally provided by IRC bots.\r\n"
		"Syntax: REGISTER <#channel>" },
	{ "SET", chanserv_set, chanserv_set_cmds, ARRAY_LEN(chanserv_set_cmds), "Sets various control flags.",
		"SET allows you to set various control flags for channels that change the way certain operations are performed on them.\r\n"
		"Syntax: SET <#channel> <setting> [parameters]" },
	{ "VOICE", chanserv_voice, NULL, 0, "Gives channel voice to a user.", "These commands perform status mode changes on a channel.\r\n"
		"If the last parameter is omitted the action is performed on the person requesting the command.\r\n"
		"Syntax: VOICE <#channel> [nickname]" }
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

static void join_flags_cb(const char *username, const char *fields[], int row, void *data)
{
	const char *channel = fields[0];
	const char *nickname = fields[1];
	const char *flags = fields[2];

	UNUSED(username);
	UNUSED(row);
	UNUSED(data);

	bbs_debug(3, "FLAGS for %s in %s are +%s\n", nickname, channel, flags);
	if (strchr(flags, 'O')) { /* Auto-op the user */
		if (strchr(flags, 'F')) { /* Also make a founder */
			chanserv_send("MODE %s +oq %s", channel, nickname);
		} else {
			chanserv_send("MODE %s +q %s", channel, nickname);
		}
	}
	if (strchr(flags, 'V')) { /* Auto-voice the user */
		chanserv_send("MODE %s +v %s", channel, nickname);
	}
}

/*! \brief Respond to channel events, such as JOIN, TOPIC change, etc. */
static void event_cb(const char *cmd, const char *channel, const char *username, const char *data)
{
	bbs_debug(3, "%s %s (%s): %s\n", cmd, channel, username, S_IF(data));

	/* Case-sensitive comparisons fine here */
	if (!strcmp(cmd, "JOIN")) {
		char entrymsg[256] = "";
		sql_fetch_strings2(username, channel, username, join_flags_cb, (char*) username, "sss", "SELECT channel, nickname, GROUP_CONCAT(flag ORDER BY flag '' SEPARATOR '') AS flags FROM channel_flags WHERE channel = ? AND nickname = ? GROUP BY channel, nickname");
		if (!channel_get_entrymsg(NULL, channel, entrymsg, sizeof(entrymsg)) && !s_strlen_zero(entrymsg)) {
			/* Channel has an entry message. Send it to the newcomer. */
			chanserv_notice(username, "[%s] %s", channel, entrymsg);
		}
	} else if (!strcmp(cmd, "TOPIC")) {
		/* If KEEPTOPIC enabled, remember the topic */
		/*! \todo ONLY if KEEPTOPIC enabled, remember the topic */
		/*! \todo Only do this when we're first creating the channel... not each time mod_chanserv is reloaded (disruptive to members of the channel) */
		update_colval(username, channel, "topic", !strlen_zero(data) ? data : NULL); /* Kind of an inverted S_IF here */
	}
}

#pragma GCC diagnostic ignored "-Wstack-protector"
static void chanserv_init(void)
{
	const char *sql = "SELECT name, topic, modelock, guard, keeptopic FROM channels WHERE guard > ?";
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int mysqlres;
	/* SQL SELECT */
	const char *fmt = "sssii";
	const unsigned int num_fields = strlen(fmt);

	mysql = sql_connect_db(buf_dbhostname, buf_dbusername, buf_dbpassword, buf_dbname);
	if (!mysql) {
		return;
	}

	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		goto cleanup;
	}

	/* XXX We should really have a sql_exec function, but since we don't currently, just bind a dummy argument that will cause the query to return all records */
	if (sql_prep_bind_exec(stmt, sql, "i", 0)) {
		goto cleanup;
	} else {
		/* Indented a block since we need num_fields */
		MYSQL_BIND results[num_fields]; /* should be equal to number of selected cols */
		unsigned long int lengths[num_fields]; /* Only needed for string result fields */
		int bind_ints[num_fields];
		char *bind_strings[num_fields];
		my_bool bind_null[num_fields];
		MYSQL_TIME bind_dates[num_fields];
		int rownum = 0;
#pragma GCC diagnostic pop

		memset(results, 0, sizeof(results));
		memset(lengths, 0, sizeof(lengths));
		memset(bind_strings, 0, sizeof(bind_strings));

		if (sql_bind_result(stmt, fmt, results, lengths, bind_ints, bind_strings, bind_dates, bind_null)) {
			goto stmtcleanup;
		}

		while (MYSQL_NEXT_ROW(stmt)) {
			int guard, keeptopic;
			char *channame, *topic, *mlock;

			/* Must allocate string results before attempting to use them */
			if (sql_alloc_bind_strings(stmt, fmt, results, lengths, bind_strings)) { /* Needs to be called if we don't use sql_string_prep in advance for all strings. */
				break; /* If we fail for some reason, don't crash attempting to access NULL strings */
			} else if (sql_fetch_columns(bind_ints, NULL, bind_strings, bind_dates, bind_null, fmt, &channame, &topic, &mlock, &guard, &keeptopic)) { /* We have no longs, so NULL is fine */
				break;
			}

			bbs_debug(3, "Processing channel %s\n", channame);
			/* Join any channels with GUARD enabled */
			if (guard) {
				bbs_debug(4, "Joining channel %s\n", channame);
				chanserv_send("JOIN %s", channame);
			}
			/* XXX These will only work when guard is enabled? Reconcile this... */
			/* Set channel modes from MLOCK */
			if (!strlen_zero(mlock)) {
				chanserv_send("MODE %s %s", channame, mlock);
			}
			if (keeptopic && !strlen_zero(topic)) { /* These should both be true or both be false, but just in case, check both */
				chanserv_send("TOPIC %s :%s", channame, topic);
			}

			rownum++;
			sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Call inside the while loop, since strings only need to be freed per row */
		}

		bbs_debug(3, "Processed %d channel%s\n", rownum, ESS(rownum));

stmtcleanup:
		sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Won't hurt anything, clean up in case we break from the loop */
		mysql_stmt_close(stmt);
	}

cleanup:
	mysql_close(mysql);
	return;
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
	if (irc_chanserv_register(process_privmsg, event_cb, BBS_MODULE_SELF)) {
		return -1;
	}
	chanserv_init();
	return 0;
}

static int unload_module(void)
{
	/* We don't currently leave any channels that we're currently in.
	 * This may be desirable (not to), as if we reload the module,
	 * it won't cause ChanServ to leave and immediately join the channel:
	 * it'll be completely transparent to any channels that have ChanServ in them (due to GUARD ON) */
	irc_chanserv_unregister(process_privmsg);
	return 0;
}

BBS_MODULE_INFO_STANDARD("ChanServ for IRC");
