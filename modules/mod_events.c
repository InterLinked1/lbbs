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
 * \brief Event callbacks
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/user.h"
#include "include/event.h"
#include "include/notify.h"
#include "include/system.h"
#include "include/linkedlists.h"
#include "include/stringlist.h"
#include "include/utils.h" /* use bbs_str_isprint */
#include "include/cli.h"
#include "include/variables.h"
#include "include/os.h" /* use bbs_get_osver */

/* Don't ban private IP addresses, under any circumstances */
#define IGNORE_LOCAL_NETS

/*! \brief Whitelisted IP addresses */
struct stringlist ip_whitelist;

struct ip_block {
	struct in_addr addr;		/* IP address */
	time_t epoch;				/* Epoch time of last auth failure */
	struct timeval lastfail;	/* Granular time of last auth failure */
	unsigned int authfails;		/* Total number of auth fails */
	unsigned int authhits;		/* Total number of uncompleted connections (never logged in) */
	unsigned int quickfails;	/* Total number of auth fails in succession */
	unsigned int quickhits;		/* Total number of hits in succession */
	unsigned int banned:1;		/* Whether this has been blocked */
	RWLIST_ENTRY(ip_block) entry;
};

static RWLIST_HEAD_STATIC(ipblocks, ip_block);

/* Maximum number of IPs to keep track of. This must be limited, because this could be unbounded. */
#define MAX_BAD_IPS 100

/* If no hits in 2 hours, purge it */
#define GOOD_NEIGHBOR_SEC 7200

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
static void ban_ip(const char *addr)
{
	int res;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	char *ipaddr = (char*) addr;

	if (is_root()) {
		char *argv[] = { "/usr/sbin/iptables", "-A", "INPUT", "-s", ipaddr, "-j", "DROP", NULL };
		res = bbs_execvp_fd(NULL, -1, -1, "/usr/sbin/iptables", argv);
	} else {
		/* There's no guarantee that the BBS user is in the sudoers file for this command, or even that sudo is installed,
		 * but this is the only way it could even work, so give it a try. */
		char *argv[] = { "/usr/bin/sudo", "-n", "/usr/sbin/iptables", "-A", "INPUT", "-s", ipaddr, "-j", "DROP", NULL };
		res = bbs_execvp_fd(NULL, -1, -1, "/usr/bin/sudo", argv);
	}
	if (res) {
		bbs_warning("Failed to block %s using iptables: %s\n", ipaddr, strerror(res));
	} else {
		bbs_auth("Blocked IP address %s (too many failed connections)\n", ipaddr);
	}
}
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop

static void process_bad_ip(struct in_addr *addr, const char *straddr, const char *username, enum bbs_event_type type)
{
	int c = 0;
	struct ip_block *ip, *oldest_offender = NULL;
	struct timeval nowtime;
	time_t now, nowthresh;
	unsigned long diff;
	time_t least_recent_offend_time = 0;
	int repeat_offender, do_ban;

	now = time(NULL);
	nowthresh = now - GOOD_NEIGHBOR_SEC;
	gettimeofday(&nowtime, NULL);

	RWLIST_WRLOCK(&ipblocks);
	RWLIST_TRAVERSE_SAFE_BEGIN(&ipblocks, ip, entry) {
		int purge = 0;
		c++;
		/* Purge any IPs that haven't had a hit in some amount of time */
		if (ip->epoch < nowthresh) {
			purge = 1;
		}
		if (purge) {
			/* It's been long enough we can purge this guy. */
			RWLIST_REMOVE_CURRENT(entry);
			free(ip);
			continue;
		}
		if (!memcmp(&ip->addr, addr, sizeof(struct in_addr))) {
			break; /* Found it, repeat offender */
		}
		if (!oldest_offender || ip->epoch < least_recent_offend_time) {
			least_recent_offend_time = ip->epoch;
			oldest_offender = ip;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;

	if (c >= MAX_BAD_IPS) {
		RWLIST_REMOVE(&ipblocks, oldest_offender, entry); /* Capacity is full, purge the oldest offender to make room for newer ones */
		free(oldest_offender);
	}

	repeat_offender = ip ? 1 : 0;
	if (!ip) {
		ip = calloc(1, sizeof(*ip));
		if (ALLOC_FAILURE(ip)) {
			RWLIST_UNLOCK(&ipblocks);
			return; /* Not much we can do */
		}
		memcpy(&ip->addr, addr, sizeof(ip->addr));
	} else {
		time_t secsince = now - ip->epoch;
		/* If it's been at least 30 seconds since the last offense, reset quickhits to 0. */
		if (secsince > 30) {
			ip->quickhits = 0;
		}
		/* If it's been at least 5 minutes since the last offense, reset authhits to 0. */
		if (secsince > 300) {
			ip->authhits = 0;
		}
	}

	/* Treat failed logins much more severely than short sessions */
	if (type == EVENT_NODE_LOGIN_FAILED || type == EVENT_NODE_BAD_REQUEST || type == EVENT_NODE_ENCRYPTION_FAILED) {
		int bad_username = 0;
		if (!strlen_zero(username)) {
			bad_username = !strcmp(username, "root") || !strcmp(username, "shell") || !strcmp(username, "system") || !bbs_str_isprint(username);
		}
		ip->authfails++;
		if (bad_username || type == EVENT_NODE_ENCRYPTION_FAILED) { /* 99% sure this is spam, expedite the block */
			ip->authfails += 4;
		}
	} else {
		ip->authhits++;
	}
	if (repeat_offender) {
		diff = (unsigned long) (nowtime.tv_sec - ip->lastfail.tv_sec) * 1000000 + (unsigned long) (nowtime.tv_usec - ip->lastfail.tv_usec);
		if (diff < 200000) {
			/* Less than 200 ms since the last hit. Almost certainly automated scanning. */
			if (type == EVENT_NODE_LOGIN_FAILED || type == EVENT_NODE_BAD_REQUEST || type == EVENT_NODE_ENCRYPTION_FAILED) {
				ip->quickfails++;
			} else {
				ip->quickhits++;
			}
		}
		bbs_debug(2, "IP address %s blacklist score: %d/%d/%d/%d (last offense: %" TIME_T_FMT "s/%luus ago\n", straddr, ip->authfails, ip->authhits, ip->quickfails, ip->quickhits, now - ip->epoch, diff);
	} else {
		bbs_debug(2, "IP address %s blacklist score: %d/%d/%d/%d (first offense)\n", straddr, ip->authfails, ip->authhits, ip->quickfails, ip->quickhits);
	}
	ip->epoch = now;
	memcpy(&ip->lastfail, &nowtime, sizeof(ip->lastfail));

	if (!repeat_offender) {
		RWLIST_INSERT_HEAD(&ipblocks, ip, entry);
	}

	/* These thresholds are specifically intended to be tolerant of email client "autoconfiguration",
	 * which may probe the SMTP, POP3, and IMAP server all in a split second.
	 * For example, a single "autoconfiguration" brings the score to 0/6/0/5 after one attempt and 0/12/0/10 after two.
	 * If you keep running autoconfig, it will still block you eventually, but this should grant some leeway.
	 */
	do_ban = (ip->authfails >= 10 || ip->authhits >= 50 || ip->quickfails >= 2 || ip->quickhits >= 15) && !ip->banned;
	if (do_ban) {
		/* If we get a flurry of connects, it suffices to block once,
		 * otherwise we're just wasting resources. */
		ip->banned = 1;
	}
	RWLIST_UNLOCK(&ipblocks);

	if (do_ban) {
		ban_ip(straddr); /* Make the system call after unlocking the list */
	}
}

static int cli_ips(struct bbs_cli_args *a)
{
	struct ip_block *ip;
	time_t now = time(NULL);

	bbs_dprintf(a->fdout, "%-55s %13s %11s %11s %11s %11s\n", "Address", "Last Fail (s)", "Auth Fails", "Auth Hits", "Quick Fails", "Quick Hits");
	RWLIST_RDLOCK(&ipblocks);
	RWLIST_TRAVERSE(&ipblocks, ip, entry) {
		char buf[56];
		time_t ago;
		if (!inet_ntop(AF_INET, &ip->addr, buf, (socklen_t) sizeof(buf))) { /* XXX Assumes IPv4 */
			bbs_error("Failed to get IP address: %s\n", strerror(errno));
			continue;
		}
		ago = now - ip->epoch;
		bbs_dprintf(a->fdout, "%-55s %13" TIME_T_FMT " %11d %11d %11d %11d\n", buf, ago, ip->authfails, ip->authhits, ip->quickfails, ip->quickhits);
	}
	RWLIST_UNLOCK(&ipblocks);
	return 0;
}

static int ip_whitelisted(const char *ip)
{
	const char *s;
	struct stringitem *i = NULL;

	while ((s = stringlist_next(&ip_whitelist, &i))) {
		if (bbs_ip_match_ipv4(ip, s)) {
			return 1;
		}
	}
	return 0;
}

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

		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", COLOR(COLOR_WHITE), "CLIENT", COLOR(COLOR_SECONDARY), "CONN", COLOR(COLOR_PRIMARY), node->protname));
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "ADDR", COLOR(COLOR_PRIMARY), node->ip));
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%dx%d %s\n", "", "", COLOR(COLOR_SECONDARY), "TERM", COLOR(COLOR_PRIMARY), node->cols, node->rows, node->ansi ? "ANSI" : ""));

		bbs_node_format_speed(node, speed, sizeof(speed));
		/* We use "LINK" instead of "SPEED" since it's 4 characters */
		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", "", "", COLOR(COLOR_SECONDARY), "LINK", COLOR(COLOR_PRIMARY), speed));

		NEG_RETURN(bbs_node_writef(node, "%s%6s %s%s: %s%s\n", COLOR(COLOR_WHITE), "SERVER", COLOR(COLOR_SECONDARY), "NAME", COLOR(COLOR_WHITE), bbs_name()));
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
		COLOR(COLOR_RED), 'H',
		COLOR(COLOR_BLUE), 'a',
		COLOR(COLOR_GREEN), 'p',
		COLOR(COLOR_WHITE), 'p',
		COLOR(COLOR_CYAN), 'y',
		COLOR(COLOR_RED), 'B',
		COLOR(COLOR_WHITE), 'i',
		COLOR(COLOR_RED), 'r',
		COLOR(COLOR_GREEN), 't',
		COLOR(COLOR_BLUE), 'h',
		COLOR(COLOR_CYAN), 'd',
		COLOR(COLOR_RED), 'a',
		COLOR(COLOR_WHITE), 'y',
		COLOR(COLOR_BLUE), 't',
		COLOR(COLOR_RED), 'o',
		COLOR(COLOR_GREEN), 'y',
		COLOR(COLOR_BLUE), 'o',
		COLOR(COLOR_CYAN), 'u',
		/* Second line, different colors */
		COLOR(COLOR_RED), 'H',
		COLOR(COLOR_WHITE), 'a',
		COLOR(COLOR_BLUE), 'p',
		COLOR(COLOR_RED), 'p',
		COLOR(COLOR_GREEN), 'y',
		COLOR(COLOR_BLUE), 'B',
		COLOR(COLOR_GREEN), 'i',
		COLOR(COLOR_RED), 'r',
		COLOR(COLOR_WHITE), 't',
		COLOR(COLOR_GREEN), 'h',
		COLOR(COLOR_RED), 'd',
		COLOR(COLOR_CYAN), 'a',
		COLOR(COLOR_BLUE), 'y',
		COLOR(COLOR_GREEN), 't',
		COLOR(COLOR_RED), 'o',
		COLOR(COLOR_WHITE), 'y',
		COLOR(COLOR_CYAN), 'o',
		COLOR(COLOR_RED), 'u',
		COLOR(COLOR_GREEN), '.',
		COLOR(COLOR_BLUE), '.',
		COLOR(COLOR_CYAN), '.'
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
	struct sockaddr_in sa;

	switch (event->type) {
		case EVENT_NODE_LOGIN_FAILED:
		case EVENT_NODE_SHORT_SESSION:
		case EVENT_NODE_BAD_REQUEST:
		case EVENT_NODE_ENCRYPTION_FAILED:
			if (strlen_zero(event->ipaddr)) {
				bbs_error("Missing IP address\n");
				return -1;
			}
			if (!strcmp(event->ipaddr, "127.0.0.1")) {
				return 1; /* Ignore localhost */
			}
#ifdef IGNORE_LOCAL_NETS
			if (STARTS_WITH(event->ipaddr, "10.") || STARTS_WITH(event->ipaddr, "192.168")) {
				return 1; /* Ignore private CIDR ranges (at least Class A and C, since Class B is 172.16-172.31) */
			}
#endif
			if (ip_whitelisted(event->ipaddr)) {
				return 1; /* Ignore event if IP is whitelisted */
			}
			/*! \todo IPs are currently stored as strings throughout the BBS (e.g. node->ipaddr). We should store them as an struct in_addr instead for efficiency. */
			/*! \todo Some protocols probably need to be exempted from this, e.g. Finger, Gopher, HTTP (to some extent), etc.
			 * For HTTP, if the request is bad, we should send an event, but if it's a successful request, then it's okay. */
			if (!inet_pton(AF_INET, event->ipaddr, &(sa.sin_addr))) {
				bbs_error("Invalid IP address: %s\n", event->ipaddr); /* Bug somewhere else */
				return -1;
			}
			process_bad_ip(&sa.sin_addr, event->ipaddr,	event->username, event->type);
			return 1;
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
		default:
			return 0;
	}
	return 0;
}

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("mod_events.conf", 1);
	if (!cfg) {
		return 0;
	}

	/* IP whitelist */
	while ((section = bbs_config_walk(cfg, section))) {
		struct bbs_keyval *keyval = NULL;
		if (strcmp(bbs_config_section_name(section), "whitelist")) {
			continue; /* Not the whitelist section */
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval);
			if (!stringlist_contains(&ip_whitelist, key)) {
				stringlist_push(&ip_whitelist, key);
				bbs_verb(5, "Whitelisted IP/CIDR %s\n", key);
			}
		}
	}

	return 0;
}

static struct bbs_cli_entry cli_commands_events[] = {
	BBS_CLI_COMMAND(cli_ips, "ips", 1, "List flagged IP addresses", NULL),
};

static int load_module(void)
{
	RWLIST_HEAD_INIT(&ip_whitelist);

	if (load_config()) {
		stringlist_empty_destroy(&ip_whitelist);
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_events);
	return bbs_register_event_consumer(event_cb);
}

static int unload_module(void)
{
	int res = bbs_unregister_event_consumer(event_cb);
	bbs_cli_unregister_multiple(cli_commands_events);
	RWLIST_WRLOCK_REMOVE_ALL(&ipblocks, entry, free);
	stringlist_empty_destroy(&ip_whitelist);
	return res;
}

BBS_MODULE_INFO_STANDARD("Core Event Handlers");
