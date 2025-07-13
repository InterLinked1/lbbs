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
 * \brief fail2ban-like IP banner
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
#include "include/system.h"
#include "include/linkedlists.h"
#include "include/stringlist.h"
#include "include/utils.h" /* use bbs_str_isprint */
#include "include/cli.h"
#include "include/variables.h"

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
	struct bbs_exec_params x;
	int res;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	char *ipaddr = (char*) addr;

	EXEC_PARAMS_INIT_FD(x, -1, -1);
	if (is_root()) {
		char *argv[] = { "/usr/sbin/iptables", "-A", "INPUT", "-s", ipaddr, "-j", "DROP", NULL };
		res = bbs_execvp(NULL, &x, "/usr/sbin/iptables", argv);
	} else {
		/* There's no guarantee that the BBS user is in the sudoers file for this command, or even that sudo is installed,
		 * but this is the only way it could even work, so give it a try. */
		char *argv[] = { "/usr/bin/sudo", "-n", "/usr/sbin/iptables", "-A", "INPUT", "-s", ipaddr, "-j", "DROP", NULL };
		res = bbs_execvp(NULL, &x, "/usr/bin/sudo", argv);
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
		bbs_debug(2, "IP address %s blacklist score: %d/%d/%d/%d (last offense: %" TIME_T_FMT "s/%luus ago)\n", straddr, ip->authfails, ip->authhits, ip->quickfails, ip->quickhits, now - ip->epoch, diff);
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

static int event_cb(struct bbs_event *event)
{
	struct bbs_node *node;
	struct sockaddr_in sa;
	time_t now;

	switch (event->type) {
		case EVENT_NODE_SHUTDOWN:
			/* Whenever a node disconnects, determine if this was an illegitimate connection */
			node = event->node;
			if (event->userid || bbs_is_shutting_down()) {
				break; /* If a user logged in successfully, or we're shutting down, not a bad request */
			}
			now = time(NULL);
			if (!bbs_assertion_failed(node != NULL) && now >= node->created + 5) {
				break; /* Node was created more than 5 seconds ago, not a short session */
			}
			if (!strcmp(event->protname, "HTTP") || !strcmp(event->protname, "HTTPS") || !strcmp(event->protname, "Gopher")) {
				/* These protocols typically involve short sessions by their nature. Don't penalize them. */
				break;
			}
			/* Fall through */
		case EVENT_NODE_LOGIN_FAILED:
		case EVENT_NODE_BAD_REQUEST:
		case EVENT_NODE_ENCRYPTION_FAILED:
			if (strlen_zero(event->ipaddr)) {
				bbs_error("Missing IP address\n");
				return -1;
			}
			if (bbs_is_loopback_ipv4(event->ipaddr)) {
				return 1; /* Ignore localhost */
			}
#ifdef IGNORE_LOCAL_NETS
			if (bbs_ip_is_private_ipv4(event->ipaddr)) {
				return 1; /* Ignore private CIDR ranges */
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
		default:
			return 0;
	}
	return 0;
}

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("mod_ip_blocker.conf", 1);
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

	bbs_config_unlock(cfg);
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

BBS_MODULE_INFO_STANDARD("Malicious IP Blocker");
