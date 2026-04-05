/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Paging/SMTP Integration
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>

#include "include/module.h"
#include "include/paging.h"
#include "include/mail.h"
#include "include/user.h"
#include "include/utils.h"

#include "include/net_smtp.h"

/* If a page doesn't have a subject and gets relayed to email, give it a generic subject ("New Page")
 * This probably makes the most sense, since it avoids subjectless emails if a page was submitted
 * without a subject - useful since pages may appear in a mailbox among other emails,
 * and this clearly identifies it as a page (and nobody likes subjectless emails).
 *
 * However, if this ends up going out to a physical pager at some point, then it will include
 * the dummy subject "New Page", which is NOT ideal since that's just a waste of characters - it's obvious!
 *
 * We have to pick one behavior and stick with it, since we don't really know where the page is going from here.
 * There are pros and cons, but this seems most logical, since usually email-submitted pages will have a subject anyways,
 * so this only affects pages submitted via TAP/IXO or SNPP, if SUBJ was not used.
 * Comment it out if you disagree. */
#define ALWAYS_HAVE_A_SUBJECT

/*! \brief Send page via SMTP */
static int page_single(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	char emailuser[128];
	char fromaddr[256];
	const char *subj, *msg, *from;
	int res;

	UNUSED(meta);

	if (!strlen_zero(data->callerid) && strchr(data->callerid, '@')) {
		/* If we already have an email address, simply use that */

		/*! \todo FIXME There is a slight problem here.
		 * This callback will get used when dropping a carbon copy of a page in a local user's mailbox,
		 * or if relaying it elsewhere.
		 * Even if the page did arrive by email, we are not forwarding it as is,
		 * but reconstructing it entirely, so if the sender is not local,
		 * neither SPF nor DKIM will pass.
		 * The correct thing to do would be set the From header like we are doing,
		 * but always use a new MAIL FROM envelope sender that is local, i.e. always use page-sender when we remail it.
		 *
		 * (This would also avoid us setting the Sender header to the same as the From header as bbs_mail does,
		 *  which is not really appropriate in this case.)
		 *
		 * This would entail using bbs_mail_message where we can pass in a mailfrom and full RFC822 message,
		 * as opposed to the simpler bbs_mail API. */
		from = data->callerid;
	} else {
		snprintf(fromaddr, sizeof(fromaddr), "%s <%s@%s>", S_OR(data->callerid, "Page Sender"), "page-sender", smtp_hostname()); /* Since we depend on net_smtp, we can ask it for the best hostname to use */
		from = fromaddr;
	}
	snprintf(emailuser, sizeof(emailuser), "%s%s%s", recipient->pagerid, data->gateway ? "@" : "", S_IF(data->gateway));

	if (data->subject) {
		subj = data->subject;
	} else {
		/* Note we do NOT have a branch here for !data->subject && data->callerid.
		 * This is deliberate; the From header will already contain the sender's identity,
		 * so there is no reason to include it in the subject.
		 * In the worst case, if it ends up going out via another protocol, i.e. to a physical pager,
		 * then the payload would contain the sender's identity twice. */
#ifdef ALWAYS_HAVE_A_SUBJECT
		subj = "New Page";
#else
		subj = NULL;
#endif
	}

	/* Even though this module has an explicit dependency on net_smtp,
	 * meaning we know net_smtp will be the mail provider,
	 * use the abstracted mail interface, for its simplicity. */
	msg = S_OR(data->body, data->message);
	res = bbs_mail(1, emailuser, from, NULL, subj, S_IF(msg));
	if (res) {
		errno = EAGAIN;
		return -1;
	}
	return 0;
}

static int is_pageable(const char *s)
{
	enum pager_type type;
	if (bbs_user_exists(s)) {
		return 1;
	}
	if (bbs_pager_exists(s, &type, 0)) {
		return 1;
	}
	return 0;
}

static int exists(struct smtp_session *smtp, struct smtp_response *resp, const char *address, const char *user, const char *domain, int fromlocal, int tolocal)
{
	UNUSED(smtp);
	UNUSED(resp);
	UNUSED(address);
	UNUSED(fromlocal);

	/* Note that we do not check the domain,
	 * so page-username [at] any domain for which we receive mail locally
	 * will be accepted and processed.
	 * This is because with certain aliases, users may want to use different domains,
	 * e.g. page-alice@a.example.com, page-bob@b.example.com, etc. */

	if (tolocal && !strlen_zero(domain)) {
		/* format is page-username@hostname */
		char usercopy[64];
		char *basepart, *userpart = usercopy;
		safe_strncpy(usercopy, user, sizeof(usercopy));
		basepart = strsep(&userpart, "-");
		if (!strcasecmp(basepart, "page") && !strlen_zero(userpart)) {
			if (is_pageable(userpart)) {
				return 1;
			}
			smtp_abort(resp, 550, 5.1.1, "No such mailbox");
			return -1;
		}
	}
	return 0;
}

/*! \brief Receive page via SMTP */
static int receive_emailed_page(struct smtp_session *smtp, struct smtp_response *resp, const char *from, const char *recipient, const char *user, const char *domain, int fromlocal, int srcfd, size_t datalen, void **freedata)
{
	int res = -1;
	int mres;
	char usercopy[64];
	char *basepart, *userpart;
	FILE *fp;
	char buf[SMTP_MAX_BUFSIZE];
	char subject[SMTP_MAX_BUFSIZE] = "";
	char fromhdr[SMTP_MAX_BUFSIZE] = "";
	int newfd;
	struct dyn_str dstr;
	struct bbs_paging_recipient recip;
	struct bbs_paging_data data;
	struct bbs_paging_message_metadata meta;

	UNUSED(from);
	UNUSED(recipient);
	UNUSED(datalen);
	UNUSED(fromlocal);
	UNUSED(freedata);

	if (strlen_zero(domain)) {
		return 0; /* Not for us */
	}
	userpart = usercopy;
	safe_strncpy(usercopy, user, sizeof(usercopy));
	basepart = strsep(&userpart, "-");
	if (strcasecmp(basepart, "page") || strlen_zero(userpart) || !is_pageable(userpart)) {
		return 0; /* Not for us */
	}

	newfd = dup(srcfd);
	if (newfd < 0) {
		bbs_error("Failed to dup file descriptor %d: %s\n", srcfd, strerror(errno));
		smtp_abort(resp, 452, 4.3.1, "Temporary system error");
		return -1;
	}
	fp = fdopen(newfd, "r");
	if (!fp) {
		bbs_error("Failed to open file descriptor %d: %s\n", newfd, strerror(errno));
		smtp_abort(resp, 452, 4.3.1, "Temporary system error");
		return -1;
	}
	/* Parse any needed headers */
	while ((fgets(buf, sizeof(buf), fp))) {
		char *tmp = buf;
		if (STARTS_WITH(tmp, "Subject:")) {
			tmp += STRLEN("Subject:");
			ltrim(tmp);
			if (!strlen_zero(tmp)) {
				bbs_strncpy_until(subject, tmp, sizeof(subject), '\r');
			}
		} else if (STARTS_WITH(tmp, "From:")) {
			tmp += STRLEN("From:");
			ltrim(tmp);
			if (!strlen_zero(tmp)) {
				bbs_strncpy_until(fromhdr, tmp, sizeof(fromhdr), '\r');
			}
		} else if (STARTS_WITH(tmp, "Content-Type:")) {
			tmp += STRLEN("Content-Type:");
			ltrim(tmp);
			if (!strlen_zero(tmp)) {
				bbs_term_line(tmp);
				if (!strcasestr(tmp, "text/plain")) {
					/* No HTML or multipart messages! */
					smtp_abort(resp, 550, 5.7.1, "Only plain text replies accepted at this address");
					goto abort;
				}
			}
		} else if (!strcmp(tmp, "\r\n")) {
			break; /* EOH */
		}
	}

	/* Now, parse the body, which is just plain text. */
	memset(&dstr, 0, sizeof(dstr));
	while ((fgets(buf, sizeof(buf), fp))) {
		dyn_str_append(&dstr, buf, strlen(buf)); /* fgets will return the CR LF */
	}

	memset(&recip, 0, sizeof(recip));
	recip.pagerid = userpart;
	memset(&data, 0, sizeof(data));
	data.body = dstr.buf;
	data.node = smtp_node(smtp);
	/* If the page arrived via email, preserve the Subject and From header,
	 * if we relay the page out via a method that supports these. */
	if (!s_strlen_zero(subject)) {
		data.subject = subject;
	}
	if (!s_strlen_zero(fromhdr)) {
		data.callerid = fromhdr;
	}
	memset(&meta, 0, sizeof(meta));
	mres = bbs_page_single(&recip, &data, &meta);

	if (mres) {
		switch (errno) {
			case ENOENT:
				smtp_abort(resp, 550, 5.7.1, "Invalid Pager ID"); /* Shouldn't happen if exists returned 1, but here for completeness */
				goto abort2;
			case EAGAIN:
			case ECHILD:
				smtp_abort(resp, 451, 4.0.0, "Temporary delivery failure");
				break;
			case EACCES:
				smtp_abort(resp, 550, 5.2.0, "Pager is restricted"); /* Pager requires a PIN (not supported by SMTP gateway) */
				break;
			case EINVAL:
				smtp_abort(resp, 550, 5.1.1, "Illegal Pager ID");
				break;
			case EDOM:
				smtp_abort(resp, 550, 5.2.0, "Tone-only pager, no message allowed");
				break;
			case ERANGE:
				smtp_abort(resp, 550, 5.2.0, "Numeric paging only, no alphabetic characters allowed");
				break;
			case EMSGSIZE:
				smtp_abort(resp, 550, 5.6.0, "Long message rejected, exceeds max character length");
				break;
			case EDQUOT:
				smtp_abort(resp, 550, 5.7.0, "Message quota temporarily exceeded");
				break;
			default:
				smtp_abort(resp, 550, 5.7.0, "Other Failure");
		}
	} else {
		res = 1; /* Delivery succeeded */
	}

abort2:
	free_if(dstr.buf);
abort:
	fclose(fp);
	return res;
}

struct smtp_delivery_agent page_submission = {
	.type = SMTP_DELIVERY_AGENT_LOCAL,
	.exists = exists,
	.deliver = receive_emailed_page,
};

struct bbs_paging_callbacks paging_callbacks = {
	.page_single = page_single, /* mod_paging only calls the other modules with one recipient per invocation, so no point implementing page_multiple */
};

static int load_module(void)
{
	smtp_register_delivery_handler(&page_submission, 9); /* Priority needs to be more urgent than mod_smtp_delivery_local */
	return bbs_register_paging_provider(&paging_callbacks, 5, PAGING_PROT_SMTP);
}

static int unload_module(void)
{
	smtp_unregister_delivery_agent(&page_submission);
	bbs_unregister_paging_provider(&paging_callbacks);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("SNPP Paging Client", "net_smtp.so");
