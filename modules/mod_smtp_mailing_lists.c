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
 * \brief Electronic Mailing Lists
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/user.h"
#include "include/auth.h" /* use bbs_user_list */
#include "include/utils.h"
#include "include/stringlist.h"
#include "include/linkedlists.h"
#include "include/cli.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"

enum reply_behavior {
	REPLY_LIST = (1 << 0),
	REPLY_SENDER = (1 << 1),
};

struct mailing_list {
	/* Reflector address properties */
	const char *user;
	const char *domain;
	const char *name;
	const char *tag;
	const char *footer;
	/* Properties */
	struct stringlist recipients;	/*!< Recipients */
	struct stringlist senders;		/*!< Authorized senders */
	RWLIST_ENTRY(mailing_list) entry;
	/* Attributes */
	enum reply_behavior replyto;	/*!< Reply-To behavior */
	size_t maxsize;					/*!< Maximum permitted posting size */
	unsigned int archive:1;			/*!< Archive? */
	unsigned int ptonly:1;			/*!< Plain text only? */
	unsigned int samesenders:1;		/*!< Senders same as recipients? */
	char data[];
};

static RWLIST_HEAD_STATIC(lists, mailing_list);

static void list_free(struct mailing_list *l)
{
	stringlist_empty(&l->recipients);
	stringlist_empty(&l->senders);
	free(l);
}

/*! \note lists must be locked */
static int add_list(struct mailing_list *list)
{
	struct mailing_list *l;

	RWLIST_TRAVERSE(&lists, l, entry) {
		if (!strcmp(l->user, list->user)) {
			if (!l->domain || (list->domain && !strcmp(l->domain, list->domain))) {
				bbs_warning("List already defined: %s%s%s\n", l->user, l->domain ? "@" : "", S_IF(l->domain));
				return -1;
			}
		}
	}
	RWLIST_INSERT_HEAD(&lists, list, entry);
	bbs_debug(3, "Added list mapping %s%s%s\n", list->user, list->domain ? "@" : "", S_IF(list->domain));
	return 0;
}

static struct mailing_list *find_list(const char *user, const char *domain)
{
	struct mailing_list *l;

	RWLIST_TRAVERSE(&lists, l, entry) {
		if (!strcmp(l->user, user)) {
			if (!l->domain) { /* If l->domain is NULL, that means it's unqualified, and always matches. */
				break;
			} else if (domain && !strcmp(l->domain, domain)) { /* l->domain must match domain */
				break;
			} else if (!domain && !strcmp(l->domain, bbs_hostname())) { /* Empty domain matches the primary hostname */
				break;
			}
		}
	}
	return l;
}

/*! \brief Is this a message to a mailing list? */
static int exists(struct smtp_session *smtp, struct smtp_response *resp, const char *address, const char *user, const char *domain, int fromlocal, int tolocal)
{
	char name[256];
	char *addr, *subaddr;
	struct mailing_list *l;

	UNUSED(address);
	UNUSED(fromlocal);

	if (!tolocal) {
		return 0;
	}

	safe_strncpy(name, user, sizeof(name));
	subaddr = name;
	addr = strsep(&subaddr, "+");

	l = find_list(addr, domain);
	if (!l) {
		return 0;
	}

	if (l->maxsize && smtp_message_estimated_size(smtp) && smtp_message_estimated_size(smtp) > l->maxsize) {
		/* If the client told us in advance how large the message will be,
		 * and we already know it's going to be too large, reject it now and save the client some bandwidth. */
		smtp_abort(resp, 552, 5.3.4, "Message too large");
		return -1;
	}

	/* We do not validate whether a user has permission to send anything to this list at this time.
	 * That's only done when the full message is received, since that's when we'll have stuff like
	 * SPF, DKIM, ARC, DMARC, etc. */

	if (strlen_zero(subaddr)) { /* It's the reflector address */
		return 1;
	} else if (!strcmp(subaddr, "subscribe") || !strcmp(subaddr, "unsubscribe") || !strcmp(subaddr, "owner") || !strcmp(subaddr, "help") || STARTS_WITH(subaddr, "bounce")) {
		return 1;
	}
	return -1; /* List exists, but subaddress is not valid */
}

static int sender_authorized(struct mailing_list *l, struct smtp_session *smtp, const char *from)
{
	struct stringlist *s;

	bbs_debug(4, "Checking if %s has permission to post to %s%s%s\n", from, l->user, l->domain ? "@" : "", S_IF(l->domain));

	s = l->samesenders ? &l->recipients : &l->senders;

	if (bbs_user_is_registered(smtp_node(smtp)->user)) {
		if (stringlist_contains(s, "*")) {
			bbs_debug(6, "Message authorized via local user membership\n");
			return 1;
		} else if (stringlist_contains(s, bbs_username(smtp_node(smtp)->user))) {
			bbs_debug(6, "Message authorized via explicit local mapping\n");
			return 1;
		}
	}
	if (stringlist_contains(s, from)) {
		bbs_debug(6, "Message authorized via explicit generic mapping\n");
		return 1;
	}
	/* Somewhat of an edge case. If the list is empty, that means everyone is authorized */
	if (stringlist_is_empty(s)) {
		bbs_debug(6, "Message authorized via empty authorized sender membership\n");
		return 1;
	}
	return 0;
}

#define LIST_RESERVED_HEADER(s) (STARTS_WITH(s, "Reply-To") || STARTS_WITH(s, "Sender:") || STARTS_WITH(s, "List-") || STARTS_WITH(s, "Mailing-List:"))

static int add_list_headers(struct mailing_list *l, FILE *fp, const char *from)
{
	int nreply = 0;
	const char *rdomain = S_OR(l->domain, bbs_hostname()); /* Reflector domain */

	/* Add list headers */

	/* If sent to a mailing list (or more rather, any of the recipients was a mailing list), indicate bulk precedence.
	 * Discouraged by RFC 2076, but this is common practice nonetheless.
	 * Nonetheless, mailing list software is not consistent.
	 * Yahoo Groups used "bulk", mailman uses "list", and groups.io uses "Bulk". */
	fprintf(fp, "Precedence: %s\r\n", "bulk");

	fprintf(fp, "Sender: <%s@%s>\r\n", l->user, rdomain); /* groups.io and Yahoo just use the reflector address; mailman does "user" <user-bounces@domain> */

	/* Many RFC 2369 headers */
	fprintf(fp, "List-Id: <%s@%s>\r\n", l->user, rdomain); /* RFC 2919; "" for groups.io and Yahoo Groups; mailman does "list name" <reflector> */
	fprintf(fp, "List-Subscribe: <%s+%s@%s>\r\n", l->user, "subscribe", rdomain); /* groups.io uses +subscribe, mailman uses -request ...?subject=subscribe */
	fprintf(fp, "List-Unsubscribe: <mailto:%s+%s@%s>\r\n", l->user, "unsubscribe", rdomain);
	/* Skip List-Archive header, this isn't accessible to users */
	fprintf(fp, "List-Post: <mailto:%s@%s>\r\n", l->user, rdomain); /* mailman includes this */
	fprintf(fp, "List-Help: <mailto:%s+%s@%s>\r\n", l->user, "help", rdomain); /* groups.io uses +help, mailman uses -request ...?subject=help */
	fprintf(fp, "List-Owner: <mailto:%s+%s@%s>\r\n", l->user, "owner", rdomain);
	/* Yahoo Groups also added a "Mailing-List: list reflector; contact owner" header */
	fprintf(fp, "Delivered-To: mailing list %s@%s\r\n", l->user, rdomain); /* Yahoo Groups and groups.io do this (loop avoidance) */

	/* mailman adds an Errors-To header, but this is mostly deprecated; bounces will go to the envelope address */

	/* Reply-To behavior */
	fprintf(fp, "Reply-To: ");
	if (l->replyto & REPLY_LIST) {
		fprintf(fp, "%s%s%s<%s@%s>\r\n", l->name ? "\"" : "", S_IF(l->name), l->name ? "\" " : "", l->user, rdomain);
		nreply++;
	}
	if (l->replyto & REPLY_SENDER) {
		fprintf(fp, "%s%s\r\n", nreply ? "," : "", from);
		nreply++;
	}
	if (!nreply) {
		bbs_warning("No reply targets for list?\n");
		return -1;
	}
	return 0;
}

/*!
 * \brief Generate the RFC822 message that will be sent to list members by transforming what the poster sent
 * \param l
 * \param fp FILE handle to which the generated message will be written
 * \retval 0 on success, -1 on failure
 */
static int listify(struct mailing_list *l, struct smtp_response *resp, FILE *fp, int srcfd, size_t origlen)
{
	ssize_t res;
	int consumed = 0;
	int body_bytes;
	int got_subject = 0;
	char buf[1001]; /* Max length of SMTP line */
	struct readline_data rldata;
	char delivered_hdr[256];
	char from_hdr[256] = "";
	int skipping = 0;

	snprintf(delivered_hdr, sizeof(delivered_hdr), "Delivered-To: mailing list %s@%s", l->user, S_OR(l->domain, bbs_hostname()));

	bbs_readline_init(&rldata, buf, sizeof(buf));
	for (;;) { /* Need to read headers line by line */
		res = bbs_readline(srcfd, &rldata, "\r\n", 0); /* We already have the entire message, so no timeout is necessary */
		if (res < 0) {
			bbs_warning("Encountered EOF before EOH?\n");
			return -1;
		}
		/* Actual bytes consumed from srcfd should be res + 2 (CR LF) */
		consumed += (int) res + 2;
		if (!res) {
			/* We're not done writing *our* headers, so don't end the headers just yet */
			break; /* EOH (end of headers) */
		}
		/* Analyze the header received */
		if (skipping && isspace(buf[0])) {
			continue;
		}
		skipping = 0;
		if (l->tag && STARTS_WITH(buf, "Subject:")) {
			char subjectbuf[256];
			int has_prefix = 0;
			char *tmp, *firstword, *subjectcopy = subjectbuf;
			const char *subject = buf + STRLEN("Subject:");
			if (strlen_zero(subject)) {
				skipping = 1;
				continue; /* Subject header but no value? */
			}
			ltrim(subject);
			safe_strncpy(subjectbuf, subject, sizeof(subjectbuf));
			firstword = strsep(&subjectcopy, " ");
			/* Ignore Re:, Fwd:, Fw:, and such prefixes. In fact, just ignore all prefixes. */
			tmp = strchr(firstword, ':');
			if (tmp && !*++tmp) { /* Ends in : */
				has_prefix = 1;
			} else if (!strcmp(l->tag, firstword)) {
				has_prefix = 1;
			}
			got_subject = 1;
			if (has_prefix) {
				fprintf(fp, "%s\r\n", buf);
			} else {
				fprintf(fp, "Subject: [%s] %s\r\n", l->tag, subject); /* Prepend tag in front of original subject */
			}
			skipping = 1; /* Ignore multiline subjects... seriously, something is wrong then */
		} else if (LIST_RESERVED_HEADER(buf)) {
			skipping = 1; /* Skip, and don't butcher multiline headers while doing so */
		} else if (!strcmp(buf, delivered_hdr)) {
			/* If there's a loop that's reposting to the mailing list again, stop it */
			bbs_warning("Detected possible loop in mailing list post, aborting\n");
			smtp_abort(resp, 550, 5.4.6, "Routing loop detected");
			return -1;
		} else if (STARTS_WITH(buf, "From:")) {
			const char *from = buf + STRLEN("From:");
			if (!strlen_zero(from)) {
				fprintf(fp, "From:%s\r\n", from); /* Use the original From header */
				safe_strncpy(from_hdr, from, sizeof(from_hdr));
			}
		} else {
			fprintf(fp, "%s\r\n", buf); /* Just copy it over */
		}
	}
	if (s_strlen_zero(from_hdr)) {
		bbs_warning("Message has no 'From' header?\n");
		return -1;
	}
	if (!got_subject && l->tag) {
		fprintf(fp, "Subject: [%s]\r\n", l->tag); /* This is probably still an awkward solution. I don't really have a good idea for this. */
	}
	if (add_list_headers(l, fp, from_hdr)) {
		return -1;
	}

	/* Now, add the message body */
	fprintf(fp, "\r\n"); /* Finish headers */
	fflush(fp);
	body_bytes = (int) origlen - consumed;
	res = bbs_copy_file(srcfd, fileno(fp), consumed, body_bytes);
	if (res != body_bytes) {
		bbs_error("Failed to write %d bytes, only wrote %lu\n", body_bytes, res);
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	if (l->footer) {
		/* XXX Assumes no encoding, and may not work for multipart messages? */
		fprintf(fp, "\r\n\r\n\r\n");
		fprintf(fp, "-=-=-=-=-=-=-=-=-=-=-=-\r\n");
		fprintf(fp, "%s\r\n", l->footer);
		fprintf(fp, "-=-=-=-=-=-=-=-=-=-=-=-\r\n");
	}

	return 0;
}

/*! \brief Whether delivery to this recipient is local (as opposed to external) */
static int deliver_locally(const char *addr)
{
	int local;
	char address[256];
	char *user, *domain;

	if (!strchr(addr, '@')) {
		/* If there's no domain, it must be local, we can't route it anywhere else */
		return 1;
	}

	if ((size_t) snprintf(address, sizeof(address), "<%s>", addr) >= sizeof(address)) {
		/* If buffer truncation occurs, it's not one of our addresses since we don't allow stuff this long */
		return 0;
	}

	if (bbs_parse_email_address(address, NULL, &user, &domain)) {
		return 0; /* Fail safe to "NO" since there must not be false positives */
	}
	local = mail_domain_is_local(domain);
	/* Don't actually need to call mailbox_get_by_name here,
	 * knowing if the domain is local or not is enough to know
	 * if this recipient is local or external, which is all that matters.
	 * We don't care, at this point, whether or not this recipient actually exists. */
	return local;
}

static int list_post_message(struct mailing_list *l, const char *msgfile, size_t msglen)
{
	const char *s;
	struct stringlist local;
	struct stringitem *i = NULL;
	int localcount = 0, manuallocalcount = 0, extcount = 0;
	char mailfrom[265];

	memset(&local, 0, sizeof(local));

	/* XXX net_smtp should be able to process recipients without popping and removing them,
	 * that might allow us to avoid allocating/freeing unnecessarily */

	/* We could do VERP (variable envelope return path) by using a unique MAIL FROM for every recipient,
	 * but that would require N SMTP transactions instead of potentially as few as 1 (though still O(n) if they're all external).
	 * See: https://en.wikipedia.org/wiki/Variable_envelope_return_path#Disadvantages
	 * To get the best of both worlds, for any local users, we use a single SMTP transaction, since we trust our own bounces,
	 * and for external users, we can use VERP, since due to queuing, there's already 1 transaction per external recipient anyways. */

	while ((s = stringlist_next(&l->recipients, &i))) { /* This list is read only, we must not modify it */
		char full[256];
		if (!strcmp(s, "*")) {
			/* Expands to all active local users */
			/* We'll deliver a copy to every user that actually has an active mailbox at the moment.
			 * In other words, if there are 50 users on the BBS, but only 15 have mailbox directories,
			 * we'll only deliver 15, to avoid the hassle of creating mailboxes for users that may
			 * not check them anyways. */
			struct bbs_user **users = bbs_user_list();
			if (users) {
				struct bbs_user *bbsuser;
				int index = 0;
				while ((bbsuser = users[index++])) {
					char maildir[256];
					snprintf(maildir, sizeof(maildir), "%s/%d", mailbox_maildir(NULL), bbsuser->id);
					if (eaccess(maildir, R_OK)) {
						continue; /* User doesn't have a mailbox, skip */
					}
					snprintf(full, sizeof(full), "<%s>", bbs_username(bbsuser));
					/* No need to check for duplicates if * is all we've processed so far */
					if (!manuallocalcount || !stringlist_contains(&local, full)) {
						stringlist_push(&local, full);
					}
					localcount++;
				}
				bbs_user_list_destroy(users);
			} else {
				bbs_error("Failed to fetch user list\n");
			}
			/* Don't break from the loop just yet: list may contain external users too (in other words, may expand to more than just '*') */
		} else if (deliver_locally(s)) {
			/* deliver_locally should be comprehensive.
			 * It's important to catch all local recipients here,
			 * because we want to weed out duplicates (e.g. if a recipient
			 * is specified multiple times, or different addresses resolve
			 * to the same catch-all address). Any given mailbox only
			 * needs to receive one copy of this message from this transaction. */
			snprintf(full, sizeof(full), "<%s>", s);
			if (!stringlist_contains(&local, full)) {
				stringlist_push(&local, full);
			}
			localcount++;
			manuallocalcount++;
		} else {
			/* This won't block since external mail is queued and delivered in a separate thread.
			 * Easier to do it now so we don't have to have another intermediate step of saving the external addresses,
			 * and we have to use a unique bounce address for each delivery anyways.
			 */
			struct stringlist external;
			char replaced[256];
			memset(&external, 0, sizeof(external));
			snprintf(full, sizeof(full), "<%s>", s);
			if (stringlist_contains(&external, full)) {
				continue;
			}
			stringlist_push(&external, full);
			safe_strncpy(replaced, s, sizeof(replaced));
			bbs_strreplace(replaced, '@', '=');
			snprintf(mailfrom, sizeof(mailfrom), "%s@%s+bounce=%s", l->user, S_OR(l->domain, bbs_hostname()), replaced); /* No <> */
			smtp_inject(mailfrom, &external, msgfile, msglen); /* Deliver to the external recipient */
			extcount++;
		}
	}

	/* If there are any local recipients, deliver to them all at once */
	if (localcount) {
		snprintf(mailfrom, sizeof(mailfrom), "%s@%s+bounce", l->user, S_OR(l->domain, bbs_hostname())); /* No <> */
		smtp_inject(mailfrom, &local, msgfile, msglen);
	}

	bbs_debug(2, "Delivered post to %d local user%s (%d explicitly) and %d external user%s\n",
		localcount, ESS(localcount), manuallocalcount, extcount, ESS(extcount));
	if (localcount + extcount == 0) {
		bbs_warning("Mailing list %s@%s has no recipients?\n", l->user, S_OR(l->domain, bbs_hostname()));
	}
	return 0;
}

static int archive_list_msg(const char *listname, int srcfd, size_t msglen)
{
	char listsdir[256];
	char listdir[512];
	int fd, res;
	char tmpfile[256], newfile[256];

	/* Archive a copy of the message sent to this mailing list. */
	snprintf(listsdir, sizeof(listsdir), "%s/lists", mailbox_maildir(NULL));
	if (eaccess(listsdir, R_OK)) {
		if (mkdir(listsdir, 0700)) {
			bbs_error("mkdir(%s) failed: %s\n", listsdir, strerror(errno));
			return -1;
		}
	}

	snprintf(listdir, sizeof(listdir), "%s/%s", listsdir, listname);
	if (eaccess(listdir, R_OK)) {
		if (mkdir(listdir, 0700)) {
			bbs_error("mkdir(%s) failed: %s\n", listdir, strerror(errno));
			return -1;
		}
	}

	/* This isn't really a mailbox, but just use the maildir functions for convenience. */
	if (mailbox_maildir_init(listdir)) {
		return -1;
	}

	fd = maildir_mktemp(listdir, tmpfile, sizeof(tmpfile), newfile);
	if (fd < 0) {
		return -1;
	}

	/* Write the entire body of the message. */
	res = bbs_copy_file(srcfd, fd, 0, (int) msglen);
	if (res != (int) msglen) {
		bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", msglen, tmpfile, res);
		close(fd);
		return -1;
	}

	close(fd);
	if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		return -1;
	}

	bbs_debug(7, "Archived list message to %s\n", newfile);
	return 0;
}

static int blast_exploder(struct smtp_session *smtp, struct smtp_response *resp, const char *from, const char *recipient, const char *user, const char *domain, int fromlocal, int tolocal, int srcfd, size_t datalen, void **freedata)
{
	char name[256];
	char *addr, *subaddr;
	struct mailing_list *l;

	UNUSED(recipient);
	UNUSED(freedata);

	if (!tolocal) {
		return 0;
	}

	safe_strncpy(name, user, sizeof(name));
	subaddr = name;
	addr = strsep(&subaddr, "+");

	l = find_list(addr, domain);
	if (!l) {
		return 0;
	}

	/* First, validate what permissions the sending user has for this list */
	if (!sender_authorized(l, smtp, from)) {
		bbs_auth("Unauthorized attempt to post to list %s by %s (%s) (fromlocal: %d)\n",
			user, from, fromlocal ? bbs_username(smtp_node(smtp)->user) : "", fromlocal);
		smtp_abort(resp, 550, 5.7.2, "You are not authorized to post to this list");
		return -1;
	}

	if (l->maxsize && datalen > l->maxsize) {
		char *errmsg; /* Can't stack allocate this, since we need it after we return */
		asprintf(&errmsg, "Message too large (maximum size permitted is %lu bytes)", l->maxsize);
		*freedata = errmsg;
		smtp_abort(resp, 552, 5.3.4, errmsg);
		return -1;
	}

	if (l->ptonly && smtp_message_content_type(smtp) && !STARTS_WITH(smtp_message_content_type(smtp), "text/plain")) {
		smtp_abort(resp, 550, 5.6.3, "Only plain text emails permitted to this mailing list");
		return -1;
	}

	if (strlen_zero(subaddr)) { /* It's the reflector address */
		char tmpattach[256] = "/tmp/lbbsmailXXXXXX";
		int res;
		size_t msglen;
		FILE *fp = bbs_mkftemp(tmpattach, 0600);
		if (!fp) {
			/* Local error in processing */
			return -1;
		}
		res = listify(l, resp, fp, srcfd, datalen);

		if (res) {
			fclose(fp);
			bbs_delete_file(tmpattach);
			/* XXX Should probably set a custom error here (list did not accept the message for some policy reason) */
			return -1;
		}

		msglen = (size_t) ftell(fp);
		fclose(fp);

		res = list_post_message(l, tmpattach, msglen);
		if (l->archive) {
			char listname[256];
			int fd = open(tmpattach, O_RDONLY);
			if (fd == -1) {
				bbs_error("open(%s) failed: %s\n", tmpattach, strerror(errno));
			} else {
				snprintf(listname, sizeof(listname), "%s%s%s", l->user, l->domain ? "@" : "", S_IF(l->domain));
				/* XXX This is a wee bit silly... we're about to delete the file, yet we copy it all into another file, rather than renaming... */
				archive_list_msg(listname, fd, msglen);
				close(fd);
			}
		}
		bbs_delete_file(tmpattach);
		return 1;
	} else if (!strcmp(subaddr, "subscribe") || !strcmp(subaddr, "unsubscribe") || !strcmp(subaddr, "owner") || !strcmp(subaddr, "help")) {
		return -1; /*! \todo Future expansion to support these */
	} else if (STARTS_WITH(subaddr, "bounce")) {
		/* Somebody's copy bounced. If VERP was used, we might even know whose! */
		bbs_warning("Bounce received (%s)\n", subaddr + STRLEN("bounce"));
	}
	return -1; /* List exists, but subaddress is not valid */
}

struct smtp_delivery_agent exploder = {
	.exists = exists,
	.deliver = blast_exploder,
};

static int cli_mailing_lists(struct bbs_cli_args *a)
{
	struct mailing_list *l;

	RWLIST_TRAVERSE(&lists, l, entry) {
		bbs_dprintf(a->fdout, "%s%s%s\n", l->user, l->domain ? "@" : "", S_IF(l->domain));
	}
	return 0;
}

static int cli_mailing_list(struct bbs_cli_args *a)
{
	struct mailing_list *l;
	struct stringlist *r;
	struct stringitem *i = NULL;
	const char *s;

	l = find_list(a->argv[2], a->argc >= 4 ? a->argv[3] : NULL);
	if (!l) {
		bbs_dprintf(a->fdout, "No such list: %s%s%s\n", a->argv[2], a->argc >= 4 ? "@" : "", a->argc >= 4 ? a->argv[3] : "");
		return 0;
	}

	/* XXX Could also show other config properties */

	/* Dump recipients and allowed senders */
	r = l->samesenders ? &l->recipients : &l->senders;
	bbs_dprintf(a->fdout, "Recipients:\n");
	while ((s = stringlist_next(&l->recipients, &i))) {
		bbs_dprintf(a->fdout, " - %s\n", s);
	}
	bbs_dprintf(a->fdout, "Authorized Senders: %s\n", stringlist_is_empty(r) ? "All Registered Users" : l->samesenders ? "Same As Recipients" : "");
	if (!l->samesenders) {
		while ((s = stringlist_next(r, &i))) {
			bbs_dprintf(a->fdout, " - %s\n", s);
		}
	}

	return 0;
}

static struct bbs_cli_entry cli_commands_smtp_mailing_lists[] = {
	BBS_CLI_COMMAND(cli_mailing_lists, "smtp lists", 2, "Enumerate mailing lists", NULL),
	BBS_CLI_COMMAND(cli_mailing_list, "smtp list", 3, "Show details of a mailing list", "smtp list <user> [<domain>]"),
};

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

	cfg = bbs_config_load("mod_smtp_mailing_lists.conf", 1);
	if (!cfg) {
		return -1;
	}

	RWLIST_WRLOCK(&lists);
	while ((section = bbs_config_walk(cfg, section))) {
		struct mailing_list *l;
		char namebuf[256];
		int samesenders = 0, ptonly = 0, archive = 1;
		size_t maxsize = 0;
		enum reply_behavior replyto = REPLY_LIST;
		const char *recipients = NULL, *senders = NULL;
		const char *user = NULL, *name = NULL, *tag = NULL, *footer = NULL;
		char *domain;
		const char *reflector = bbs_config_section_name(section);
		size_t userlen, domainlen, namelen, taglen, footerlen;
		char *data;
		if (!strcmp(reflector, "general")) {
			continue;
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcmp(key, "recipients")) {
				recipients = value;
			} else if (!strcmp(key, "senders")) {
				senders = value;
			} else if (!strcmp(key, "samesenders")) {
				samesenders = S_TRUE(value);
			} else if (!strcmp(key, "ptonly")) {
				ptonly = S_TRUE(value);
			} else if (!strcmp(key, "archive")) {
				archive = S_TRUE(value);
			} else if (!strcmp(key, "maxsize")) {
				maxsize = (size_t) atol(value);
			} else if (!strcmp(key, "tag")) {
				tag = value;
			} else if (!strcmp(key, "replyto")) {
				if (!strcmp(key, "list")) {
					replyto = REPLY_LIST;
				} else if (!strcmp(key, "sender")) {
					replyto = REPLY_SENDER;
				} else if (!strcmp(key, "both")) {
					replyto = REPLY_LIST | REPLY_SENDER;
				}
			} else {
				bbs_warning("Unknown setting '%s'\n", key);
			}
		}
		if (samesenders) {
			senders = recipients;
		}

		safe_strncpy(namebuf, reflector, sizeof(namebuf));
		domain = namebuf;
		user = strsep(&domain, "@");

		userlen = STRING_ALLOC_SIZE(user);
		domainlen = STRING_ALLOC_SIZE(domain);
		namelen = STRING_ALLOC_SIZE(name);
		taglen = STRING_ALLOC_SIZE(tag);
		footerlen = STRING_ALLOC_SIZE(footer);

		l = calloc(1, sizeof(*l) + userlen + domainlen + namelen + taglen + footerlen);
		if (ALLOC_FAILURE(l)) {
			continue;
		}
		SET_BITFIELD(l->ptonly, ptonly);
		SET_BITFIELD(l->samesenders, samesenders);
		SET_BITFIELD(l->archive, archive);
		l->maxsize = maxsize;
		l->replyto = replyto;
		if (!strlen_zero(recipients)) {
			stringlist_push_list(&l->recipients, recipients);
		}
		if (!strlen_zero(senders)) {
			stringlist_push_list(&l->senders, senders);
		}
		data = l->data;
		SET_FSM_STRING_VAR(l, data, user, user, userlen);
		SET_FSM_STRING_VAR(l, data, domain, domain, domainlen);
		SET_FSM_STRING_VAR(l, data, name, name, namelen);
		SET_FSM_STRING_VAR(l, data, tag, tag, taglen);
		SET_FSM_STRING_VAR(l, data, footer, footer, footerlen);
		if (add_list(l)) {
			list_free(l);
		}
	}
	RWLIST_UNLOCK(&lists);
	/* No further locking is needed because the list is not in use while this module is reffed,
	 * and if it's not, it's safe to unload. */
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_smtp_mailing_lists);
	return smtp_register_delivery_handler(&exploder, 5); /* Takes priority over individual user mailboxes */
}

static int unload_module(void)
{
	int res = smtp_unregister_delivery_agent(&exploder);
	bbs_cli_unregister_multiple(cli_commands_smtp_mailing_lists);
	RWLIST_WRLOCK_REMOVE_ALL(&lists, entry, list_free);
	return res;
}

BBS_MODULE_INFO_DEPENDENT("Electronic Mailing Lists", "net_smtp.so");
