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
#include "include/node.h"
#include "include/event.h"
#include "include/notify.h"
#include "include/system.h"
#include "include/linkedlists.h"

/* Don't ban private IP addresses, under any circumstances */
#define IGNORE_LOCAL_NETS

struct ip_block {
	struct in_addr addr;		/* IP address */
	int epoch;				/* Epoch time of last auth failure */
	struct timeval lastfail;	/* Granular time of last auth failure */
	unsigned int authfails;		/* Total number of auth fails */
	unsigned int authhits;		/* Total number of uncompleted connections (never logged in) */
	unsigned int quickfails;	/* Total number of auth fails in succession */
	unsigned int quickhits;		/* Total number of hits in succession */
	RWLIST_ENTRY(ip_block) entry;
};

static RWLIST_HEAD_STATIC(ipblocks, ip_block);

/* Maximum number of IPs to keep track of. This must be limited, because this could be unbounded. */
#define MAX_BAD_IPS 100

/* If no hits in 2 hours, purge it */
#define GOOD_NEIGHBOR_SEC 7200

static void ban_ip(const char *addr)
{
	int res;
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

static void process_bad_ip(struct in_addr *addr, const char *straddr, int authfail)
{
	int c = 0;
	struct ip_block *ip, *oldest_offender = NULL;
	struct timeval nowtime;
	int now, nowthresh;
	unsigned long diff;
	int least_recent_offend_time = 0;
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
		int secsince = now - ip->epoch;
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
	if (authfail) {
		ip->authfails++;
	} else {
		ip->authhits++;
	}
	if (repeat_offender) {
		diff = (nowtime.tv_sec - ip->lastfail.tv_sec) * 1000000 + nowtime.tv_usec - ip->lastfail.tv_usec;
		if (diff < 200000) {
			/* Less than 200 ms since the last hit. Almost certainly automated scanning. */
			if (authfail) {
				ip->quickfails++;
			} else {
				ip->quickhits++;
			}
		}
		bbs_debug(2, "IP address %s blacklist score: %d/%d/%d/%d (last offense: %ds/%luus ago\n", straddr, ip->authfails, ip->authhits, ip->quickfails, ip->quickhits, now - ip->epoch, diff);
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
	do_ban = ip->authfails >= 10 || ip->authhits >= 50 || ip->quickfails >= 2 || ip->quickhits >= 15;
	RWLIST_UNLOCK(&ipblocks);

	if (do_ban) {
		ban_ip(straddr); /* Make the system call after unlocking the list */
	}
}

static int event_cb(struct bbs_event *event)
{
	struct sockaddr_in sa;

	switch (event->type) {
		case EVENT_NODE_LOGIN_FAILED:
		case EVENT_NODE_SHORT_SESSION:
			if (!strcmp(event->ipaddr, "127.0.0.1")) {
				return 1; /* Ignore localhost */
			}
#ifdef IGNORE_LOCAL_NETS
			if (STARTS_WITH(event->ipaddr, "10.") || STARTS_WITH(event->ipaddr, "192.168")) {
				return 1; /* Ignore private CIDR ranges (at least Class A and C, since Class B is 172.16-172.31) */
			}
#endif
			/*! \todo IPs are currently stored as strings throughout the BBS (e.g. node->ipaddr). We should store them as an struct in_addr instead for efficiency. */
			/*! \todo Some protocols probably need to be exempted from this, e.g. Finger, Gopher, HTTP (to some extent), etc.
			 * For HTTP, if the request is bad, we should send an event, but if it's a successful request, then it's okay. */
			inet_pton(AF_INET, event->ipaddr, &(sa.sin_addr));
			process_bad_ip(&sa.sin_addr, event->ipaddr, event->type == EVENT_NODE_LOGIN_FAILED);
			return 1;
		case EVENT_USER_REGISTRATION:
			/* Relatively speaking, it's a pretty big deal whenever a new user registers.
			 * Notify the sysop. */
			bbs_sysop_email(NULL, "New User Registration", "Greetings, sysop,\r\n\tA new user, %s (#%d), just registered on your BBS from IP %s.",
				event->username, event->userid, event->ipaddr);
			/*! \todo Also send the user a new user greeting, to his/her BBS email account? (need to add API to/with net_smtp) */
			return 1;
		default:
			return 0;
	}
}

static int load_module(void)
{
	return bbs_register_event_consumer(event_cb);
}

static int unload_module(void)
{
	int res = bbs_unregister_event_consumer(event_cb);
	RWLIST_WRLOCK_REMOVE_ALL(&ipblocks, entry, free);
	return res;
}

BBS_MODULE_INFO_STANDARD("Core Event Handlers");
