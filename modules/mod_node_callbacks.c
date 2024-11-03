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
 * \brief Node callbacks
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/module.h"
#include "include/node.h"
#include "include/user.h"
#include "include/event.h"
#include "include/notify.h"
#include "include/utils.h"
#include "include/variables.h"
#include "include/os.h" /* use bbs_get_osver */

static int interactive_start(struct bbs_node *node)
{
	char timebuf[29];

	if (!NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_node_clear_screen(node));
		NEG_RETURN(bbs_node_writef(node, "%s %d.%d.%d  %s\n\n", BBS_TAGLINE, BBS_MAJOR_VERSION, BBS_MINOR_VERSION, BBS_PATCH_VERSION, BBS_COPYRIGHT));
		bbs_node_safe_sleep(node, 150);
		NEG_RETURN(bbs_node_writef(node, COLOR(COLOR_PRIMARY)));
	} else {
		/* Print some spaces as TDD carrier starts up, so we don't clip the beginning of output,
		 * and because the TDD could be in FIGS mode and this gives it a chance to get into LTRS mode. */
		NEG_RETURN(bbs_node_writef(node, "%10s", ""));
		/* Since the server will keep going until we block (hit a key),
		 * sleep explicitly as it will take some for the TDD to print the output anyways.
		 * This will allow the sysop to begin spying on the node here and catch the next output.
		 * Really, mainly to help with testing and debugging. */
		bbs_node_safe_sleep(node, 2500);
		NEG_RETURN(bbs_node_writef(node, "%s %d.%d.%d  %s\n\n", BBS_SHORTNAME, BBS_MAJOR_VERSION, BBS_MINOR_VERSION, BBS_PATCH_VERSION, BBS_COPYRIGHT_SHORT));
	}

	NEG_RETURN(bbs_node_writef(node, "%s\n", bbs_name())); /* Print BBS name */

	if (!NODE_IS_TDD(node)) {
		char speed[NODE_SPEED_BUFSIZ_LARGE];
		if (!s_strlen_zero(bbs_tagline())) {
			NEG_RETURN(bbs_node_writef(node, "%s\n\n", bbs_tagline())); /* Print BBS tagline */
		}
		bbs_time_friendly_now(timebuf, sizeof(timebuf));

		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", COLOR(TERM_COLOR_WHITE), "CLIENT", COLOR(COLOR_SECONDARY), "CONN", COLOR(COLOR_PRIMARY), node->protname));
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "ADDR", COLOR(COLOR_PRIMARY), node->ip));
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%dx%d %s\n", "", "", COLOR(COLOR_SECONDARY), "TERM", COLOR(COLOR_PRIMARY), node->cols, node->rows, node->ansi ? "ANSI" : ""));

		bbs_node_format_speed(node, speed, sizeof(speed));
		/* We use "LINK" instead of "SPEED" since it's 4 characters */
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "LINK", COLOR(COLOR_PRIMARY), speed));

		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", COLOR(TERM_COLOR_WHITE), "SERVER", COLOR(COLOR_SECONDARY), "NAME", COLOR(TERM_COLOR_WHITE), bbs_name()));
		if (!s_strlen_zero(bbs_hostname())) {
			NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "ADDR", COLOR(COLOR_PRIMARY), bbs_hostname()));
		}
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%d %s(of %s%d%s) - %s%s\n", "", "", COLOR(COLOR_SECONDARY), "NODE", COLOR(COLOR_PRIMARY),
			node->id, COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), bbs_maxnodes(), COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), bbs_get_osver()));
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "TIME", COLOR(COLOR_PRIMARY), timebuf));
		if (!s_strlen_zero(bbs_hostname())) {
			NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "ADMN", COLOR(COLOR_PRIMARY), bbs_sysop()));
		}
	} else {
		bbs_time_friendly_short_now(timebuf, sizeof(timebuf)); /* Use condensed date for TDDs */
		NEG_RETURN(bbs_node_writef(node, "Node %d - %s\n", node->id, timebuf));
	}

	bbs_node_safe_sleep(node, 300);

	NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
	return 0;
}

static inline ssize_t print_birthday_banner(struct bbs_node *node)
{
	return bbs_node_writef(node,
		"\n"
		"%s%c%s%c%s%c%s%c%s%c "
		"%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s%c "
		"%s%c%s%c "
		"%s%c%s%c%s%c"
		"\n"
		"%s%c%s%c%s%c%s%c%s%c "
		"%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s%c "
		"%s%c%s%c "
		"%s%c%s%c%s%c"
		"%s%c%s%c%s%c\n"
		,
		COLOR(TERM_COLOR_RED), 'H',
		COLOR(TERM_COLOR_BLUE), 'a',
		COLOR(TERM_COLOR_GREEN), 'p',
		COLOR(TERM_COLOR_WHITE), 'p',
		COLOR(TERM_COLOR_CYAN), 'y',
		COLOR(TERM_COLOR_RED), 'B',
		COLOR(TERM_COLOR_WHITE), 'i',
		COLOR(TERM_COLOR_RED), 'r',
		COLOR(TERM_COLOR_GREEN), 't',
		COLOR(TERM_COLOR_BLUE), 'h',
		COLOR(TERM_COLOR_CYAN), 'd',
		COLOR(TERM_COLOR_RED), 'a',
		COLOR(TERM_COLOR_WHITE), 'y',
		COLOR(TERM_COLOR_BLUE), 't',
		COLOR(TERM_COLOR_RED), 'o',
		COLOR(TERM_COLOR_GREEN), 'y',
		COLOR(TERM_COLOR_BLUE), 'o',
		COLOR(TERM_COLOR_CYAN), 'u',
		/* Second line, different colors */
		COLOR(TERM_COLOR_RED), 'H',
		COLOR(TERM_COLOR_WHITE), 'a',
		COLOR(TERM_COLOR_BLUE), 'p',
		COLOR(TERM_COLOR_RED), 'p',
		COLOR(TERM_COLOR_GREEN), 'y',
		COLOR(TERM_COLOR_BLUE), 'B',
		COLOR(TERM_COLOR_GREEN), 'i',
		COLOR(TERM_COLOR_RED), 'r',
		COLOR(TERM_COLOR_WHITE), 't',
		COLOR(TERM_COLOR_GREEN), 'h',
		COLOR(TERM_COLOR_RED), 'd',
		COLOR(TERM_COLOR_CYAN), 'a',
		COLOR(TERM_COLOR_BLUE), 'y',
		COLOR(TERM_COLOR_GREEN), 't',
		COLOR(TERM_COLOR_RED), 'o',
		COLOR(TERM_COLOR_WHITE), 'y',
		COLOR(TERM_COLOR_CYAN), 'o',
		COLOR(TERM_COLOR_RED), 'u',
		COLOR(TERM_COLOR_GREEN), '.',
		COLOR(TERM_COLOR_BLUE), '.',
		COLOR(TERM_COLOR_CYAN), '.'
		);
}

static int interactive_splash(struct bbs_node *node)
{
	node->menu = "welcome"; /* Not really a menu, but it's a page and we should give it a name */
	NEG_RETURN(bbs_node_clear_screen(node));

#if 0
	NEG_RETURN(bbs_node_writef(node, "%sLast few callers:\n\n", COLOR(COLOR_PRIMARY)));
	/*! \todo Finish this: need to be able to retrieve past authentication info, e.g. from DB */
#endif

	/* System stats */
	if (!NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_node_writef(node, "%s%-20s: %s%s\n", COLOR(COLOR_SECONDARY), "System", COLOR(COLOR_PRIMARY), bbs_name()));
		NEG_RETURN(bbs_node_writef(node, "%s%6s%s %4u%9s%s: %s%s\n", COLOR(COLOR_SECONDARY), "User #", COLOR(COLOR_PRIMARY), node->user->id, "", COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), bbs_username(node->user)));
	} else {
		/* Omit the # sign since TDDs display # as $ */
		NEG_RETURN(bbs_node_writef(node, "User %d - %s\n", node->user->id, bbs_username(node->user)));
	}

	/*! \todo Add more stats here, e.g. num logins today, since started, lifetime, etc. */

	if (bbs_starttime() > (int) bbs_min_uptime_threshold()) {
		char timebuf[24];
		time_t now = time(NULL);
		print_time_elapsed(bbs_starttime(), now, timebuf, sizeof(timebuf)); /* Formatting for timebuf (11 chars) should be enough for 11 years uptime, I think that's good enough */
		if (!NODE_IS_TDD(node)) {
			char daysbuf[36];
			print_days_elapsed(bbs_starttime(), now, daysbuf, sizeof(daysbuf));
			NEG_RETURN(bbs_node_writef(node, "%s%6s%s %2s%-11s%s: %s%s\n", COLOR(COLOR_SECONDARY), "Uptime", COLOR(COLOR_PRIMARY), "", timebuf, COLOR(COLOR_SECONDARY), COLOR(COLOR_PRIMARY), daysbuf));
		} else {
			NEG_RETURN(bbs_node_writef(node, "Uptime %s\n", timebuf)); /* Only print the condensed uptime */
		}
	}

#if 0
	/*! \todo Finish these and make them work */
	NEG_RETURN(bbs_node_writef(node, "%s%-20s: %s%5d %s%-9s%s%6d%s%s\n", COLOR(COLOR_SECONDARY), "Logons Today", COLOR(COLOR_PRIMARY), 1, COLOR(COLOR_SECONDARY), "(Max ", COLOR(COLOR_PRIMARY), 22, COLOR(COLOR_SECONDARY), ")"));
	NEG_RETURN(bbs_node_writef(node, "%s%-20s: %s%5d %s%-9s%s%6d%s%s\n", COLOR(COLOR_SECONDARY), "Time on Today", COLOR(COLOR_PRIMARY), 26, COLOR(COLOR_SECONDARY), "(Max ", COLOR(COLOR_PRIMARY), 86, COLOR(COLOR_SECONDARY), ")"));
	NEG_RETURN(bbs_node_writef(node, "%s%-20s: %s%5d %s%-9s%s%6d%s%s\n", COLOR(COLOR_SECONDARY), "Mail Waiting", COLOR(COLOR_PRIMARY), 0, COLOR(COLOR_SECONDARY), "(Unread ", COLOR(COLOR_PRIMARY), 0, COLOR(COLOR_SECONDARY), ")"));
#endif

	if (!s_strlen_zero(bbs_sysop()) && !NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_node_writef(node, "%s%-20s: %s%s\n", COLOR(COLOR_SECONDARY), "Sysop is", COLOR(COLOR_PRIMARY), bbs_sysop()));
	}

	NEG_RETURN(bbs_node_writef(node, "\n")); /* Separation before next section */
	if (!NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_node_statuses(node, NULL));
	}

	/* If it's the caller's birthday, throw some confetti... */
	if (!NODE_IS_TDD(node) && node->user->dob) {
		struct tm tm;
		time_t now;
		int month = node->user->dob->tm_mon;
		int date = node->user->dob->tm_mday;
		now = time(NULL);
		localtime_r(&now, &tm);
		if (tm.tm_mon == month && tm.tm_mday == date) {
			bbs_debug(3, "Today is %s's birthday!\n", bbs_username(node->user));
			print_birthday_banner(node);
		}
	}

	NEG_RETURN(bbs_node_wait_key(node, MIN_MS(2)));
	return 0;
}

static int interactive_login(struct bbs_node *node)
{
	/* Make some basic variables available that can be used in menus.conf scripting
	 * For example, something in the menu could say Welcome ${BBS_USERNAME}! */
	bbs_node_var_set_fmt(node, "BBS_NODENUM", "%d", node->id);
	bbs_node_var_set_fmt(node, "BBS_USERID", "%d", node->user->id);
	bbs_node_var_set_fmt(node, "BBS_USERPRIV", "%d", node->user->priv);
	bbs_node_var_set(node, "BBS_USERNAME", bbs_username(node->user));
	bbs_user_init_vars(node); /* Set any custom variables for this user */

	/*! \todo Notify user's friends that s/he's logged on now */
	/*! \todo Notify the sysop (sysop console), via BELL, that a new user has logged in, if and only if the sysop console is idle */

	NEG_RETURN(bbs_node_writef(node, COLOR_RESET "\r\n"));

	/* Should be authenticated by now (either as a user or continuing as guest) */
	bbs_assert(bbs_node_logged_in(node));

	/* Display welcome updates and alerts */
	if (interactive_splash(node)) {
		bbs_debug(5, "Exiting\n");
		return -1;
	}

	return 0;
}

static int event_cb(struct bbs_event *event)
{
	const struct bbs_file_transfer_event *tevent;

	switch (event->type) {
		case EVENT_USER_REGISTRATION:
			/* Relatively speaking, it's a pretty big deal whenever a new user registers.
			 * Notify the sysop. */
			bbs_sysop_email(NULL, "New User Registration", "Greetings, sysop,\r\n\tA new user, %s (#%d), just registered on your BBS from IP %s.",
				event->username, event->userid, event->ipaddr);
			/*! \todo Also send the user a new user greeting, to his/her BBS email account? (need to add API to/with net_smtp) */
			return 1;
		case EVENT_NODE_INTERACTIVE_START:
			/* Since events callbacks are executed synchronously,
			 * we can interact with the node directly here. */
			if (interactive_start(event->node)) {
				/* Only the highest return value is kept,
				 * so we should return 1, not -1 */
				return 1;
			}
			break;
		case EVENT_NODE_INTERACTIVE_LOGIN:
			if (interactive_login(event->node)) {
				return 1;
			}
			break;
		case EVENT_FILE_DOWNLOAD_COMPLETE:
			/*! \todo In the future, add support here for download/upload quotas,
			 * where uploading file increases allowance and downloading consumes that.
			 * We'll need to check before DOWNLOAD_START to ensure we have sufficient balance. */
			tevent = event->cdata;
			bbs_verb(5, "User %s downloaded %s (%lu bytes)\n", S_OR(event->username, "<Guest>"), tevent->diskpath, tevent->size);
			return 1;
		case EVENT_FILE_UPLOAD_COMPLETE:
			tevent = event->cdata;
			bbs_verb(5, "User %s uploaded %s (%lu bytes)\n", S_OR(event->username, "<Guest>"), tevent->diskpath, tevent->size);
			/*! \brief In addition to updating balance as described above,
			 * we may want to do something more, like dispatch a "new file notification",
			 * since uploads are a lot more significant than downloads. */
			return 1;
		default:
			return 0;
	}
	return 0;
}

static int load_module(void)
{
	return bbs_register_event_consumer(event_cb);
}

static int unload_module(void)
{
	return bbs_unregister_event_consumer(event_cb);
}

BBS_MODULE_INFO_STANDARD("Node Callbacks");
