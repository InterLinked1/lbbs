/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief RFC 6647 Email Greylisting
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/stringlist.h"
#include "include/transfer.h"
#include "include/node.h"
#include "include/user.h" /* use bbs_user_is_registered */
#include "include/utils.h" /* use bbs_ip_is_private_ipv4 */
#include "include/config.h"
#include "include/cli.h"

#include "include/net_smtp.h"

/* Defaults */
static unsigned int min_spamscore = 2;
static unsigned int min_failcount = 1;

static int skipped_messages = 0;
static int lifetime_safe_senders = 0;
static int lifetime_greylisted_messages = 0;
static int lifetime_expired = 0;

struct safe_sender {
	time_t added;
	time_t last_used;
	RWLIST_ENTRY(safe_sender) entry;
	char srcip[];
};

#define GREYLIST_MIN_AGE 180 /* Require at least 3 minutes to pass before we will allow a greylisted message to be accepted */
#define GREYLIST_MAX_AGE 86500 /* Beyond just over one day, expire a pending greylist, a legitimate server would've retried by now */
#define SAFE_SENDER_MAX_AGE (10 * 86400) /* Allow greylisting to be bypassed for 10 days */

/* "Database" of known senders that we have previously accepted.
 * This is not persisted, and doesn't need to be, since
 * the SMTP landscape is constantly evolving.
 *
 * safe_senders is potentially somewhat of a misnomer...
 * if the server is really good, we'd never have greylisted it at all...
 * it's only because it triggered some alarm bells already that we did.
 * So these could well be potentially spammy servers that we've accepted
 * because they complied with our greylisting request. */
static RWLIST_HEAD_STATIC(safe_senders, safe_sender);

static int is_safe_sender(struct smtp_msg_process *mproc)
{
	struct safe_sender *s, *match = NULL;
	time_t now = time(NULL);
	time_t exp_time = now - SAFE_SENDER_MAX_AGE;
	RWLIST_WRLOCK(&safe_senders);
	RWLIST_TRAVERSE_SAFE_BEGIN(&safe_senders, s, entry) {
		if (s->added < exp_time) {
			RWLIST_REMOVE_CURRENT(entry);
			free(s);
			continue;
		}
		/* Don't break, continue and prune the list */
		if (!strcmp(s->srcip, smtp_node(mproc->smtp)->ip)) {
			if (match) {
				bbs_warning("Duplicate safe sender detected for IP address %s\n", s->srcip);
				RWLIST_REMOVE_CURRENT(entry);
				free(s);
				continue;
			}
			match = s;
			match->last_used = now;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&safe_senders);
	return match ? 1 : 0;
}

static void add_safe_sender(struct smtp_msg_process *mproc)
{
	const char *srcip = smtp_node(mproc->smtp)->ip;
	struct safe_sender *s = calloc(1, sizeof(*s) + strlen(srcip) + 1);
	if (ALLOC_FAILURE(s)) {
		return;
	}
	strcpy(s->srcip, srcip); /* Safe */
	s->added = time(NULL);
	RWLIST_WRLOCK(&safe_senders);
	RWLIST_INSERT_HEAD(&safe_senders, s, entry);
	lifetime_safe_senders++;
	RWLIST_UNLOCK(&safe_senders);
}

/* DATA-based greylisting */
struct greylisted_msg {
	const char *srcip;
	const char *mailfrom;
	const char *firstrecipient;
	const char *messageid;
	unsigned int failcount;
	int spamscore;
	time_t added;
	RWLIST_ENTRY(greylisted_msg) entry;
	char data[]; /* Flexible struct member for all string allocations */
};

/*!
 * \note We only WRLOCK this list, never RDLOCK it,
 * so in theory the list could just use a mutex. */
static RWLIST_HEAD_STATIC(greylisted_messages, greylisted_msg);

static const char *first_recipient(struct smtp_msg_process *mproc)
{
	struct stringitem *i = NULL;
	return stringlist_next(smtp_recipients(mproc->smtp), &i);
}

static void greylist_add(struct smtp_msg_process *mproc, int spamscore)
{
	struct greylisted_msg *g;
	const char *srcip, *mailfrom, *firstrecip, *messageid;
	size_t srciplen, mailfromlen, firstreciplen, messageidlen;
	char *data;

	srcip = smtp_node(mproc->smtp)->ip;
	mailfrom = smtp_from(mproc->smtp);
	firstrecip = first_recipient(mproc);
	messageid = smtp_messageid(mproc->smtp);

	srciplen = strlen(srcip) + 1;
	mailfromlen = strlen(mailfrom) + 1;
	firstreciplen = strlen(firstrecip) + 1;
	messageidlen = messageid ? strlen(messageid) + 1 : 0;

	g = calloc(1, sizeof(*g) + srciplen + mailfromlen + firstreciplen + messageidlen);
	if (ALLOC_FAILURE(g)) {
		return;
	}
	data = g->data;
	SET_FSM_STRING_VAR(g, data, srcip, srcip, srciplen);
	SET_FSM_STRING_VAR(g, data, mailfrom, mailfrom, mailfromlen);
	SET_FSM_STRING_VAR(g, data, firstrecipient, firstrecip, firstreciplen);
	SET_FSM_STRING_VAR(g, data, messageid, messageid, messageidlen);

	g->added = time(NULL);
	g->failcount = smtp_failure_count(mproc->smtp);
	g->spamscore = spamscore;

	RWLIST_INSERT_HEAD(&greylisted_messages, g, entry); /* Add to head, so newest attempts are first */
	lifetime_greylisted_messages++;
}

static struct greylisted_msg *get_greylisted_msg(struct smtp_msg_process *mproc, int spamscore)
{
	struct greylisted_msg *g, *msg = NULL;
	time_t now, exptime;
	unsigned int failcount;
	const char *mailfrom, *messageid, *firstrecip;

	firstrecip = first_recipient(mproc);
	mailfrom = smtp_from(mproc->smtp);
	messageid = smtp_messageid(mproc->smtp);
	failcount = smtp_failure_count(mproc->smtp);
	now = time(NULL);
	exptime = now - GREYLIST_MAX_AGE;

	/* It is important here to reduce false negatives, i.e. not detecting
	 * a message has already been greylisted when it really has.
	 * This could result in a loop of a message being retried.
	 * RFC 6647 recommands using a tuple of source IP, MAIL FROM,
	 * and the first recipient. We also save the message ID,
	 * and a few other properties to make identifying matches easier. */

	/* First pass attempts to find the exact message that was greylisted,
	 * not just a message from the same server. */
	RWLIST_TRAVERSE_SAFE_BEGIN(&greylisted_messages, g, entry) {
		/* Is the record already too old?
		 * Legitimate MTAs will retry within maybe a minute to perhaps a few hours
		 * or even a day at most. Beyond that, any attempts should be discarded. */
		if (g->added < exptime) {
			/* Purge it */
			RWLIST_REMOVE_CURRENT(entry);
			lifetime_expired++;
			free(g);
			continue; /* In practice, once we hit one expired record, everything else in the list is also expired, due to the head insert */
		}

		/* The fail count should be the same, given that the sender will
		 * retry delivery the exact same way each time. */
		if (g->failcount != failcount || g->spamscore != spamscore) {
			continue;
		}

		/* Not from the same IP address.
		 * Note that for larger mailers, the source IP address might not always be the same,
		 * so this can sometimes result in false negatives.
		 * We handle that in the second pass. */
		if (strcmp(g->srcip, smtp_node(mproc->smtp)->ip)) {
			continue; /* Not from the same IP address. */
		} else if (g->mailfrom && mailfrom && strcmp(g->mailfrom, mailfrom)) {
			continue; /* Different MAIL FROM address. Could also be different in some cases, if VERP is in use, though that's unlikely... */
		} else if (strcmp(g->firstrecipient, firstrecip)) {
			continue; /* Different first recipient. In theory, they could be in a different order, though unlikely... */
		} else if (g->messageid && messageid && strcmp(g->messageid, messageid)) {
			continue;
		}
		/* Don't break from the list even on a match. Iterate until the end to purge all stale entries. */
		if (msg) {
			bbs_warning("Greylisted message located more than once in list?\n");
			RWLIST_REMOVE_CURRENT(entry);
			free(g);
		} else {
			msg = g;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (msg) {
		return msg; /* Return the matched message */
	}
	/* Couldn't find a strict match. Do another pass where we're a little bit more lenient. */
	RWLIST_TRAVERSE(&greylisted_messages, g, entry) { /* Not removing anything from the list anymore, no need for safe traversal */
		int matches = 0;
		/* Instead of AND'ing all the requirements, we now look for 3 out of 4. */
		matches += !strcmp(g->srcip, smtp_node(mproc->smtp)->ip) ? 1 : 0;
		matches += g->mailfrom ? (!strlen_zero(mailfrom) && !strcmp(g->mailfrom, mailfrom) ? 1 : 0) : strlen_zero(mailfrom);
		matches += !strcmp(g->firstrecipient, firstrecip) ? 1 : 0;
		matches += g->messageid ? (!strlen_zero(messageid) && !strcmp(g->messageid, messageid) ? 1 : 0) : strlen_zero(messageid);
		if (matches >= 3) {
			/* Okay, good enough. If it turns out this was actually for a different message,
			 * that means there's another match in the list that could match for the other message,
			 * so it works out. */
			break;
		}
		/* Remember... it might not be in the list! That's okay, don't be more lenient than 3 out of 4. */
	}
	return g;
}

static int get_spam_score(struct smtp_msg_process *mproc)
{
	char headerval[1001];
	const char *header = "X-Spam-Score";
	size_t headerlen = STRLEN("X-Spam-Score");

	if (!bbs_module_running("mod_spamassassin")) {
		/* If SpamAssassin isn't running, then we won't encounter the X-Spam-Score header.
		 * (If we do, for some reason, then it was illegitimately added by the sender).
		 *
		 * We wouldn't need to this check if mod_spamassassin was a dependency
		 * of this module, but it's not strictly a dependency. */
		bbs_debug(2, "mod_spamassassin is not loaded, can't check spam score\n");
		return 0;
	}

	/* There isn't any standard API provided by net_smtp to retrieve a header value,
	 * message processors have to do it themselves :(
	 */
	if (!mproc->fp) {
		mproc->fp = fopen(mproc->datafile, "r");
		if (!mproc->fp) {
			bbs_error("fopen(%s) failed: %s\n", mproc->datafile, strerror(errno));
			return 0;
		}
	} else {
		rewind(mproc->fp);
	}

	/* No need to clean up mproc->fp so we can return without cleaning up anything */
	while ((fgets(headerval, sizeof(headerval), mproc->fp))) {
		char *start;
		if (!strcmp(headerval, "\r\n")) {
			return 0; /* End of headers, didn't find an X-Spam-Score header */
		}
		if (strncasecmp(headerval, header, headerlen)) {
			continue; /* It's not the right header. */
		}
		start = headerval + headerlen;
		if (*start != ':') {
			continue; /* Prefix of another header, I guess. Not actually the right header. */
		}
		start++;
		if (*start == ' ') {
			start++;
		}
		if (strlen_zero(start)) {
			bbs_warning("X-Spam-Score header value is empty?\n");
			return 0;
		}
		return atoi(start);
	}
	return 0;
}

static int processor(struct smtp_msg_process *mproc)
{
	struct greylisted_msg *g;
	time_t now;
	int spamscore;

	if (smtp_is_exempt_relay(mproc->smtp)) {
		/* We don't greylist outbound mail, only inbound mail from the Internet.
		 * Technically, this check is a subset of bbs_ip_is_private_ipv4 below,
		 * which ignores all private IPs. However, this is a flag check,
		 * as opposed to parsing the IP address, so in a potentially common case,
		 * this is much quicker to check now. */
		return 0;
	} else if (!mproc->smtp || !smtp_node(mproc->smtp)) {
		/* Things like DSNs will hit this path.
		 * Regardless, greylisting only makes sender when we have a live sender on the wire. */
		return 0;
	} else if (bbs_user_is_registered(smtp_node(mproc->smtp)->user)) {
		bbs_warning("Authenticated session?\n");
		return 0;
	}

	/* Unlike mod_smtp_recipient_monitor, where the bulk of work is done holding a WRLOCK.
	 * that is unacceptable here, because we are looking at incoming mail,
	 * which has much greater throughput than mail submissions.
	 * Therefore, we do some checks on the message first, before deciding if we should even continue. */
	if (smtp_failure_count(mproc->smtp) < min_failcount) {
		skipped_messages++;
		return 0;
	} else if (bbs_ip_is_private_ipv4(smtp_node(mproc->smtp)->ip)) { /* This check is done later in the sequence, since it's more expensive than the others */
		return 0; /* No point in greylisting if it's from a private IP */
	}

	/* Check the X-Spam-Score header to get its spam score.
	 * Unlike conventional greylisting mechanisms, since this is written for smaller environments,
	 * we do spam analysis first and use that to make a more intelligent and more informed decision
	 * about whether to greylist at all. */
	spamscore = min_spamscore ? get_spam_score(mproc) : 0; /* If min_spamscore is 0, we don't actually care about the spam score */
	if (spamscore < (int) min_spamscore) {
		skipped_messages++;
		bbs_debug(3, "Spam score (%d) is less than minimum for greylisting consideration (%d)\n", spamscore, (int) min_spamscore);
		return 0;
	}

	/* Okay, at this point, we have already aborted if we're confident
	 * that the message isn't potentially spam. This should be most
	 * legitimate messages, so now we're okay to grab the WRLOCK...
	 * it's not as big a deal if we're only bottlenecking the potential junk. */

	/* First, check if it's in our list of safe senders. */
	if (is_safe_sender(mproc)) {
		skipped_messages++;
		bbs_debug(4, "Message received from previously greylisted server, now a safe sender, accepting\n");
		return 0;
	}

	now = time(NULL);

	/* Check if this message was already greylisted */
	RWLIST_WRLOCK(&greylisted_messages);
	g = get_greylisted_msg(mproc, spamscore);
	if (g) {
		/* We don't want to allow a sender to just retry immediately... some amount of time needs to pass,
		 * so the sender is forced to queue the message and reattempt delivery later.
		 * A lot of spammers don't bother maintaining a queue. */
		if (g->added > now - GREYLIST_MIN_AGE) {
			RWLIST_UNLOCK(&greylisted_messages);
			bbs_debug(4, "Too soon since message was greylisted, deferring again\n");
			bbs_smtp_log(4, mproc->smtp, "Greylisting message from <%s>, too soon: %s/%s/%s/%u/%d\n", /* Log the full tuple used for greylisting analysis */
				smtp_from(mproc->smtp), smtp_node(mproc->smtp)->ip, smtp_messageid(mproc->smtp), first_recipient(mproc), smtp_failure_count(mproc->smtp), spamscore);
			smtp_reply_nostatus(mproc->smtp, 421, "Message greylisted, retry delivery later");
			return -1; /* Reject again, for now */
		} else {
			/* Okay, it passed the test!
			 * Add to safe_senders list. */
			bbs_debug(4, "Message was previously greylisted (%ld s ago), now releasing\n", now - g->added);
			add_safe_sender(mproc);
			RWLIST_REMOVE(&greylisted_messages, g, entry);
			free(g);
			RWLIST_UNLOCK(&greylisted_messages);
			return 0;
		}
	}
	/* We haven't seen this message before (though we may have seen this sender before) */
	greylist_add(mproc, spamscore);
	RWLIST_UNLOCK(&greylisted_messages);

	/* Instead of setting mproc->bounce and mproc->drop to 1, we reply directly and return -1. */
	bbs_debug(4, "Greylisting message (temporary deferral)\n");
	bbs_smtp_log(4, mproc->smtp, "Greylisting message from <%s>: %s/%s/%s/%u/%d\n", /* Log the full tuple used for greylisting analysis */
		smtp_from(mproc->smtp), smtp_node(mproc->smtp)->ip, smtp_messageid(mproc->smtp), first_recipient(mproc), smtp_failure_count(mproc->smtp), spamscore);
	smtp_reply_nostatus(mproc->smtp, 421, "Message greylisted, retry delivery later");
	return -1; /* Reject the message, for now */
}

static int cli_greylisted_messages(struct bbs_cli_args *a)
{
	struct greylisted_msg *g;
	int c = 0;

	bbs_dprintf(a->fdout, "%-20s %15s %-25s %-35s %s\n", "Greylist Time", "IP Address", "MAIL FROM", "RCPT TO #1", "Message-ID");
	RWLIST_RDLOCK(&greylisted_messages);
	RWLIST_TRAVERSE(&greylisted_messages, g, entry) {
		char greylisted_date[32];
		struct tm tm;
		localtime_r(&g->added, &tm);
		strftime(greylisted_date, sizeof(greylisted_date), "%a, %d %b %H:%M:%S", &tm);
		bbs_dprintf(a->fdout, "%-20s %15s %-25s %-35s %s\n",
			greylisted_date, g->srcip, S_OR(g->mailfrom, "<>"), g->firstrecipient, g->messageid);
		c++;
	}
	RWLIST_UNLOCK(&greylisted_messages);
	bbs_dprintf(a->fdout, "%d message%s currently greylisted (%d ever greylisted [%d expired], %d skipped)\n",
		c, ESS(c), lifetime_greylisted_messages, lifetime_expired, skipped_messages);
	return 0;
}

static int cli_greylisted_senders(struct bbs_cli_args *a)
{
	struct safe_sender *s;
	int c = 0;

	bbs_dprintf(a->fdout, "%-21s %-21s %s\n", "Added", "Last Used", "Source IP Address");
	RWLIST_RDLOCK(&safe_senders);
	RWLIST_TRAVERSE(&safe_senders, s, entry) {
		char added[32];
		char last_used[32];
		struct tm tm;
		localtime_r(&s->added, &tm);
		strftime(added, sizeof(added), "%a, %d %b %H:%M:%S", &tm);
		localtime_r(&s->last_used, &tm);
		strftime(last_used, sizeof(last_used), "%a, %d %b %H:%M:%S", &tm);
		bbs_dprintf(a->fdout, "%-21s %-21s %s\n", added, last_used, s->srcip);
		c++;
	}
	RWLIST_UNLOCK(&safe_senders);
	bbs_dprintf(a->fdout, "%d sender%s currently whitelisted (%d ever whitelisted)\n", c, ESS(c), lifetime_safe_senders);
	return 0;
}

static struct bbs_cli_entry cli_commands_greylisting[] = {
	BBS_CLI_COMMAND(cli_greylisted_messages, "greylisted messages", 2, "List currently greylisted messages", NULL),
	BBS_CLI_COMMAND(cli_greylisted_senders, "greylisted senders", 2, "List safe senders (previously greylisted)", NULL),
};

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("mod_smtp_greylisting.conf", 1);
	if (!cfg) {
		return -1;
	}

	bbs_config_val_set_uint(cfg, "general", "min_failcount", &min_failcount);
	bbs_config_val_set_uint(cfg, "general", "min_spamscore", &min_spamscore);
	return 0;
}

struct smtp_message_processor proc = {
	.callback = processor,
	.dir = SMTP_DIRECTION_IN, /* Only applies to incoming mail */
	.scope = SMTP_SCOPE_COMBINED, /* This is for the message as a whole, not instances of its delivery */
	/* We want to do this on the first pass, before a user's mailbox rules even run.
	 * Greylist typically takes precedence over most other handling.
	 * This is still after DATA and after SpamAssassin has run, so we're good. */
	.iteration = FILTER_BEFORE_MAILBOX,
};

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	if (smtp_register_processor(&proc)) {
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_greylisting);
	return 0;
}

static int unload_module(void)
{
	int res;
	bbs_cli_unregister_multiple(cli_commands_greylisting);
	res = smtp_unregister_processor(&proc);
	RWLIST_WRLOCK_REMOVE_ALL(&greylisted_messages, entry, free);
	RWLIST_WRLOCK_REMOVE_ALL(&safe_senders, entry, free);
	return res;
}

BBS_MODULE_INFO_DEPENDENT("RFC6647 Message Greylisting", "net_smtp.so");
