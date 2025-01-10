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
 * \brief Local mail delivery agent
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <time.h>

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/user.h"
#include "include/net.h"
#include "include/mail.h"
#include "include/utils.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"

static int minpriv_relay_in = 0;
static int notify_external_firstmsg = 1;

static int exists(struct smtp_session *smtp, struct smtp_response *resp, const char *address, const char *user, const char *domain, int fromlocal, int tolocal)
{
	struct mailbox *mbox;

	UNUSED(smtp);
	UNUSED(address);

	if (!tolocal) {
		return 0;
	}

	mbox = mailbox_get_by_name(user, domain);
	if (!mbox) {
		return 0;
	}
	/* Mailbox exists, great! */
	if (!fromlocal && minpriv_relay_in) {
		int userpriv = bbs_user_priv_from_userid((unsigned int) mailbox_id(mbox));
		if (userpriv < minpriv_relay_in) {
			smtp_abort(resp, 550, 5.1.1, "User unauthorized to receive external mail");
			return -1;
		}
	}
	/* It's a submission of outgoing mail, do no further validation here. */
	return 1;
}

static void notify_firstmsg(struct mailbox *mbox)
{
	char newdir[256];

	snprintf(newdir, sizeof(newdir), "%s/new", mailbox_maildir(mbox));
	if (eaccess(newdir, R_OK)) {
		struct bbs_user *user;
		const char *email;
		char popstr[32] = "", imapstr[32] = "";
		int port_imap, port_pop3;
		/* Doesn't exist yet. So this is the first message for the user. */
		/* Send a message to the user's off-net address. */
		user = bbs_user_from_userid((unsigned int) mailbox_id(mbox));
		if (!user) {
			bbs_error("Couldn't find any user for mailbox %d?\n", mailbox_id(mbox));
			return;
		}
		email = bbs_user_email(user);
		if (strlen_zero(email)) {
			goto cleanup; /* No email? Forget about it */
		}
		port_imap = bbs_protocol_port("IMAPS");
		port_pop3 = bbs_protocol_port("POP3S");
		if (port_imap) {
			snprintf(imapstr, sizeof(imapstr), "IMAP: %d (TLS)\r\n", port_imap);
		} else {
			port_imap = bbs_protocol_port("IMAP");
			if (port_imap) {
				snprintf(imapstr, sizeof(imapstr), "IMAP: %d (plaintext)\r\n", port_imap);
			}
		}
		if (port_pop3) {
			snprintf(popstr, sizeof(popstr), "POP3: %d (TLS)\r\n", port_pop3);
		} else {
			port_pop3 = bbs_protocol_port("POP3");
			if (port_pop3) {
				snprintf(popstr, sizeof(popstr), "POP3: %d (plaintext)\r\n", port_pop3);
			}
		}
		if (!port_pop3 && !port_imap) {
			bbs_warning("No message retrieval protocols are currently enabled, user cannot retrieve mail\n");
			return;
		}
		bbs_debug(3, "Notifying %s via %s since this is the first message delivered to this user\n", bbs_username(user), email);
		bbs_mail_fmt(1, email, NULL, NULL, "You Have Mail",
			"Hello, %s\r\n\tYou just received your first email in your BBS email account.\r\n"
			"To check your messages, you can connect your mail client client to %s.\r\n"
			"== Connection Details: ==\r\n"
			"%s"
			"%s"
			,bbs_username(user), bbs_hostname(), imapstr, popstr);
cleanup:
		bbs_user_destroy(user);
	}
}

/*!
 * \brief Save a message to a maildir folder
 * \param smtp SMTP session
 * \param[out] resp Custom failure response to send
 * \param mbox Mailbox to which message is being appended
 * \param mproc
 * \param recipient Recipient address (incoming), NULL for saving copies of sent messages (outgoing)
 * \param srcfd Source file descriptor containing message
 * \param datalen Length of message
 * \param[out] newfilebuf Saved filename
 * \param len Length of newfilebuf
 * \retval 0 on success, nonzero on error
 */
/*! \todo Can smtp be NULL to this function? If so, we have a problem */
static int appendmsg(struct smtp_session *smtp, struct smtp_response *resp, struct mailbox *mbox, struct smtp_msg_process *mproc, const char *recipient, int srcfd, size_t datalen, char *newfilebuf, size_t len)
{
	char tmpfile[256];
	char newfile[sizeof(tmpfile)];
	int fd, res;
	unsigned long quotaleft;

	/* Enforce mail quota for message delivery. We check this after callbacks,
	 * since maybe the callback opted to drop the message, or relay it,
	 * or do something to the message that can succeed even with insufficient quota to save it. */
	quotaleft = mailbox_quota_remaining(mbox);
	bbs_debug(5, "Mailbox %d has %lu bytes quota remaining (need %lu)\n", mailbox_id(mbox), quotaleft, datalen);
	if (quotaleft < datalen) {
		/* Mailbox is full, insufficient quota remaining for this message. */
		mailbox_notify_quota_exceeded(smtp_node(smtp), mbox);
		smtp_abort(resp, 452, 4.2.2, "The mailbox you've tried to reach is full (over quota)"); /* Quota might be available later */
		return -1;
	}

	if (mproc->newdir) {
		char newdir[512];
		/* Doesn't account for INBOX, but fileinto INBOX would be redundant, since it's already going there by default. */
		snprintf(newdir, sizeof(newdir), "%s/.%s", mailbox_maildir(mbox), mproc->newdir);
		free_if(mproc->newdir);
		if (eaccess(newdir, R_OK)) {
			bbs_warning("maildir %s does not exist. Defaulting to INBOX\n", newdir);
			fd = maildir_mktemp(mailbox_maildir(mbox), tmpfile, sizeof(tmpfile), newfile);
		} else {
			fd = maildir_mktemp(newdir, tmpfile, sizeof(tmpfile), newfile);
		}
	} else {
		fd = maildir_mktemp(mailbox_maildir(mbox), tmpfile, sizeof(tmpfile), newfile);
	}

	if (fd < 0) {
		return -1;
	}

	if (recipient) { /* For incoming messages, but not for saving copies of outgoing messages */
		struct smtp_filter_data filterdata;
		memset(&filterdata, 0, sizeof(filterdata));
		filterdata.smtp = smtp;
		filterdata.recipient = recipient;
		filterdata.inputfd = srcfd;
		filterdata.size = datalen;
		filterdata.outputfd = fd;
		smtp_run_filters(&filterdata, smtp_is_message_submission(smtp) ? SMTP_DIRECTION_SUBMIT : SMTP_DIRECTION_IN);
	}

	/* Write the entire body of the message. */
	res = bbs_copy_file(srcfd, fd, 0, (int) datalen);
	close(fd);
	if (res != (int) datalen) {
		bbs_error("Failed to write %lu bytes to %s, only wrote %d\n", datalen, tmpfile, res);
		return -1;
	}

	if (rename(tmpfile, newfile)) {
		bbs_error("rename %s -> %s failed: %s\n", tmpfile, newfile, strerror(errno));
		return -1;
	} else {
		char maildir[256];
		/* Because the notification is delivered before we actually return success to the sending client,
		 * this can result in the somewhat strange experience of receiving an email sent to yourself
		 * before it seems that the email has been fully sent.
		 * This is just a side effect of processing the email completely synchronously (if delivered locally).
		 * "Real" mail servers typically queue the message to decouple it. We just deliver it immediately.
		 */
		bbs_debug(6, "Delivered message to %s\n", newfile);
		if (newfilebuf) {
			safe_strncpy(newfilebuf, newfile, len);
		}
		safe_strncpy(maildir, newfile, sizeof(maildir));
		maildir_extract_from_filename(maildir); /* Strip everything beneath the maildir */
		mailbox_notify_new_message(smtp_node(smtp), mbox, maildir, newfile, datalen);
	}
	return 0;
}

static int do_local_delivery(struct smtp_session *smtp, struct smtp_response *resp, const char *from, const char *recipient, const char *user, const char *domain, int fromlocal, int tolocal, int srcfd, size_t datalen, void **freedata)
{
	struct mailbox *mbox;
	struct smtp_msg_process mproc;
	struct smtp_response tmpresp; /* Dummy that gets thrown away, if needed */
	int res;

	UNUSED(from);
	UNUSED(fromlocal);

	if (!tolocal) {
		return 0; /* Not for us */
	}

	mbox = mailbox_get_by_name(user, domain);
	if (!mbox) {
		/* We should've caught this before. */
		bbs_warning("Mailbox '%s' does not exist locally\n", user);
		return -1;
	}

	/* .Drafts, .Sent, .Trash etc. are auto-created by mailbox_get if needed.
	 * However, new, cur, and tmp aren't created until we called mailbox_maildir_init.
	 * So if they don't exist right now, this is a mailbox whose maildir we just created.
	 * In other words, this is the first message this user has ever received. */
	if (notify_external_firstmsg) {
		notify_firstmsg(mbox);
	}

	/* No need to get a mailbox lock, really. */
	if (mailbox_maildir_init(mailbox_maildir(mbox))) {
		return -1;
	}

	res = smtp_run_delivery_callbacks(smtp, &mproc, mbox, &resp, SMTP_DIRECTION_IN, SMTP_SCOPE_INDIVIDUAL, recipient, datalen, freedata);
	if (res) {
		return res;
	}
	if (!resp) {
		resp = &tmpresp; /* We already set the error, don't allow appendmsg to override it if we're not going to drop immediately */
	}

	return appendmsg(smtp, resp, mbox, &mproc, recipient, srcfd, datalen, NULL, 0) ? -1 : 1;
}

/*! \brief Upload a copy of the message to a remote IMAP server */
static int upload_file(struct smtp_session *smtp, struct smtp_msg_process *mproc, int srcfd, size_t datalen)
{
	struct bbs_tcp_client client;
	struct bbs_url url;
	char tmpbuf[1024];
	int imapcaps;
	off_t offset = 0;
	ssize_t res;

	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));
	if (bbs_parse_url(&url, mproc->newdir) || strlen_zero(url.resource) || bbs_tcp_client_connect(&client, &url, !strcmp(url.prot, "imaps"), tmpbuf, sizeof(tmpbuf))) {
		return -1;
	}

	if (imap_client_login(&client, &url, smtp_node(smtp)->user, &imapcaps)) {
		bbs_debug(3, "IMAP login fail!\n");
		goto cleanup;
	}

	if (imapcaps & IMAP_CAPABILITY_LITERAL_PLUS) {
		/* Avoid an RTT if possible by using a non-synchronizing literal */
		IMAP_CLIENT_SEND(&client, "a2 APPEND \"%s\" (\\Seen) {%lu+}", url.resource, datalen);
	} else {
		IMAP_CLIENT_SEND(&client, "a2 APPEND \"%s\" (\\Seen) {%lu}", url.resource, datalen);
		IMAP_CLIENT_EXPECT(&client, "+");
	}

	res = bbs_sendfile(client.wfd, srcfd, &offset, datalen); /* Don't use bbs_copy_file, the target is a pipe/socket, not a file */
	if (res != (ssize_t) datalen) {
		bbs_warning("Wanted to upload %lu bytes but only uploaded %ld? (%s)\n", datalen, res, strerror(errno));
		goto cleanup;
	}
	IMAP_CLIENT_SEND(&client, ""); /* CR LF to finish */
	IMAP_CLIENT_EXPECT(&client, "a2 OK");
	IMAP_CLIENT_SEND(&client, "a3 LOGOUT");
	bbs_tcp_client_cleanup(&client);
	return 0;

cleanup:
	bbs_debug(5, "Remote IMAP login to %s:%d failed\n", url.host, url.port);
	bbs_tcp_client_cleanup(&client);
	return -1;
}

static int save_copy(struct smtp_session *smtp, struct smtp_msg_process *mproc, int srcfd, size_t datalen, char *newfile, size_t newfilelen)
{
	int res;
	if (STARTS_WITH(mproc->newdir, "imap://") || STARTS_WITH(mproc->newdir, "imaps://")) {
		res = upload_file(smtp, mproc, srcfd, datalen); /* Connect to some remote IMAP server and APPEND the message */
		FREE(mproc->newdir);
	} else {
		struct smtp_response resp; /* Collect any error from appendmsg but ignore/discard */
		struct mailbox *mbox = mailbox_get_by_userid(smtp_node(smtp)->user->id);
		res = appendmsg(smtp, &resp, mbox, mproc, NULL, srcfd, datalen, newfile, newfilelen); /* Save the Sent message locally */
		/* appendmsg frees mproc.newdir */
		if (res) {
			newfile[0] = '\0';
		}
	}
	return res;
}

struct smtp_delivery_agent lda = {
	.exists = exists,
	.deliver = do_local_delivery,
	.save_copy = save_copy,
};

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_smtp.conf", 1);
	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "notifyextfirstmsg", &notify_external_firstmsg);
	bbs_config_val_set_true(cfg, "privs", "relayin", &minpriv_relay_in);
	return 0;
}

static int load_module(void)
{
	load_config();
	return smtp_register_delivery_handler(&lda, 10);
}

static int unload_module(void)
{
	return smtp_unregister_delivery_agent(&lda);
}

BBS_MODULE_INFO_DEPENDENT("E-Mail Local Delivery Agent", "net_smtp.so");
