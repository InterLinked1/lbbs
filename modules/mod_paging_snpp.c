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
 * \brief RFC 1861 SNPP Paging Client
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/module.h"
#include "include/paging.h"
#include "include/utils.h"

static int snpp_code_to_errno(const char *command, int code, const char *msg)
{
	if (strlen(msg) > 4) {
		msg += 4; /* Skip past numeric code and space */
	}
	/* Here, we basically reverse the error codes in net_snpp and turn them back into the errno value
	 * Because some SNPP error codes are used for different types of errors,
	 * we try to use the error number if we can, and words in the error message if needed
	 * in order to discriminate different error conditions.
	 *
	 * Of course, not all SNPP servers are guaranteed to use the same numeric codes we do,
	 * and/or they may use different human-readable messages,
	 * so this is a best effort type of endeavor. */
	if (!strncmp(command, "PAGE", 4)) {
		switch (code) {
			case 421: return ECHILD;
			case 554: return EAGAIN;
			case 500: return ENOSYS;
			case 950: return ENETDOWN;
			case 750: return ENOTCONN; /* Use instead of ECOMM, which is not POSIX and thus not defined on FreeBSD */
			case 550:
				if (strstr(msg, "2WAY")) {
					return EPROTOTYPE; /* Not 2WAY */
				}
				return ENOENT; /* e.g. pager doesn't exist */
			default: break;
		}
	} else if (!strncmp(command, "SEND", 4)) {
		switch (code) {
			case 421:
				if (strstr(msg, "Quota")) {
					return EDQUOT;
				}
				return ECHILD;
			case 554:
				if (strstr(msg, "PIN")) {
					return EACCES; /* PIN required */
				}
				if (strstr(msg, "Tone")) {
					return EDOM;
				}
				if (strstr(msg, "Numeric")) {
					return ERANGE;
				}
				if (strstr(msg, "Long")) {
					return EMSGSIZE;
				}
				return EAGAIN;
			case 500: return ENOSYS;
			case 550:
				if (strstr(msg, "2WAY")) {
					return EPROTOTYPE;
				}
				return ENOENT; /* e.g. pager doesn't exist */
		}
	} else if (!strncmp(command, "PING", 4)) {
		switch (code) {
			case 421: return ECHILD;
			case 500: return ENOSYS;
			case 821: return EIDRM;
			case 750: return ENETDOWN;
			case 920: return ENOTCONN;
			case 550:
				if (strstr(msg, "2WAY")) {
					return ENOTTY;
				}
				if (strstr(msg, "Illegal")) {
					return EINVAL;
				}
				return ENOENT; /* e.g. pager doesn't exist */
			default: break;
		}
	} else if (!strncmp(command, "MSTA", 4)) {
		switch (code) {
			case 421: return ECHILD;
			case 500: return ENOSYS;
			case 550: return EINVAL;
			case 780: return ETIMEDOUT;
			default: break;
		}
	} else if (!strncmp(command, "KTAG", 4)) {
		switch (code) {
			case 421: return ECHILD;
			case 550: return EINVAL;
			default: break;
		}
	}
	/* Any other command not specifically handled */
	switch (code) {
		case 550: return EINVAL;
		default: break;
	}
	bbs_warning("Unhandled SNPP response for %s: %d %s\n", command, code, msg);
	return 0;
}

static int page_single(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	struct bbs_tcp_client client_stack;
	struct bbs_tcp_client *client = &client_stack;
	struct bbs_url url;
	char buf[1024];
	ssize_t res;
	int saved_errno = 0;
	int starttls_supported = 0, subj_supported = 0, call_supported;

	if (!data->gateway) {
		bbs_error("Gateway was not set\n");
		return -1;
	}

	/* Set up the TCP connection to the target. */
	memset(&url, 0, sizeof(url));
	memset(&client_stack, 0, sizeof(client_stack));
	url.host = data->gateway;
	url.port = 444; /* SNPP port */
	if (bbs_tcp_client_connect(client, &url, 0, buf, sizeof(buf))) {
		errno = EAGAIN;
		return -1;
	}

#define COMMAND_SEND_EXPECT(expect, cmd, fmt, ...) \
	bbs_debug(3, "=> " fmt "\n", ## __VA_ARGS__); \
	bbs_tcp_client_send(client, fmt "\r\n", ## __VA_ARGS__); \
	res = bbs_readline(client->rfd, &client->rldata, "\r\n", SEC_MS(5)); \
	if (res < 0) { \
		goto cleanup; \
	} \
	bbs_debug(3, "<= %s\n", client->buf); \
	if (!STARTS_WITH(client->buf, #expect)) { \
		saved_errno = snpp_code_to_errno(cmd, atoi(client->buf), client->buf); \
		bbs_debug(3, "Unexpected SNPP response: %s\n", client->buf); \
		goto cleanup; \
	}

#define COMMAND_SEND_EXPECT_NONFATAL(expect, cmd, fmt, ...) \
	bbs_debug(3, "=> " fmt "\n", ## __VA_ARGS__); \
	bbs_tcp_client_send(client, fmt "\r\n", ## __VA_ARGS__); \
	res = bbs_readline(client->rfd, &client->rldata, "\r\n", SEC_MS(5)); \
	if (res >= 0) { \
	bbs_debug(3, "<= %s\n", client->buf); \
		if (!STARTS_WITH(client->buf, #expect)) { \
			saved_errno = snpp_code_to_errno(cmd, atoi(client->buf), client->buf); \
			bbs_debug(3, "Unexpected SNPP response: %s\n", client->buf); \
		} \
	}

	bbs_tcp_client_expect(client, "\r\n", 1, SEC_MS(5), "220"); /* Wait for banner */

	/* Find out what commands are supported */
	bbs_debug(3, "=> HELP\n");
	bbs_tcp_client_send(client, "HELP\r\n");
	for (;;) {
		res = bbs_readline(client->rfd, &client->rldata, "\r\n", SEC_MS(5));
		if (res < 0) {
			goto cleanup;
		}
		bbs_debug(3, "<= %s\n", client->buf);
		if (strstr(client->buf, "SUBJ")) {
			subj_supported = 1;
		}
		if (strstr(client->buf, "CALL")) {
			call_supported = 1;
		}
		if (strstr(client->buf, "STARTTLS")) {
			starttls_supported = 1;
		}
		if (strstr(client->buf, "250")) {
			break; /* End of help */
		}
	}

	/* If we are connecting over the public Internet, and the server supports STARTTLS, encrypt the connection.
	 * This is an unofficial extension to SNPP, supported at the very least by this software
	 * (commercial paging providers won't support it, so email or even TAP/IXO should be used if
	 *  encrypted delivery is required to a commercial paging provider.) */
	if (starttls_supported && !bbs_address_nonpublic(data->gateway)) {
		COMMAND_SEND_EXPECT(220, "STARTTLS", "STARTTLS");
		if (bbs_tcp_client_starttls(client, data->gateway)) {
			goto cleanup;
		}
		bbs_tcp_client_expect(client, "\r\n", 1, SEC_MS(5), "220"); /* Wait for banner again, like in SMTP */
	}

	if (data->twoway) {
		COMMAND_SEND_EXPECT(250, "2WAY", "2WAY");
	}

	/* Any per-recipient modifiers */
	if (recipient->parameters.level_set) {
		COMMAND_SEND_EXPECT(250, "LEVE", "LEVE %d", recipient->parameters.level);
	}
	if (recipient->parameters.coverage_set) {
		COMMAND_SEND_EXPECT(250, "COVE", "COVE %d", recipient->parameters.coverage);
	}
	if (recipient->parameters.holduntil) {
		struct tm tm;
		char timebuf[32];
		/* YYMMDDHHMMSS +T format, e.g. 950925143501 +0700 */
		memset(&tm, 0, sizeof(tm));
		if (localtime_r(&recipient->parameters.holduntil, &tm)) {
			strftime(timebuf, sizeof(timebuf), "%y%02m%02d%H%M%S %z", &tm);
			COMMAND_SEND_EXPECT(250, "HOLD", "HOLD %s", timebuf);
		}
	}
	if (recipient->parameters.alert) {
		COMMAND_SEND_EXPECT(250, "ALER", "ALER %d", recipient->parameters.alert ? 1 : 0);
	}

	if (recipient->pin) {
		COMMAND_SEND_EXPECT(250, "PAGE", "PAGE %s %s", recipient->pagerid, recipient->pin);
	} else {
		COMMAND_SEND_EXPECT(250, "PAGE", "PAGE %s", recipient->pagerid);
	}

	/* Message options */
	if (data->noqueue) {
		COMMAND_SEND_EXPECT(250, "NOQUEUE", "NOQUEUE");
	}
	if (data->readack) {
		COMMAND_SEND_EXPECT(250, "ACKR", "ACKR");
	}

	/* Not every server supports SUBJ and CALL (for example, Spok does not)
	 * If not, we'll have to stuff them into the body.
	 * If supported, great! Use the dedicated commands so that they are cleanly
	 * available to the receiver, useful if we are transmitting via SNPP,
	 * but the receiver is going to relay via SMTP. If SUBJ/CALL are supported,
	 * the receiver can use those for the From and Subject headers.
	 * If we stuff them in the body here, then all the metadata will be stuck
	 * in the body of the email, which is not ideal. */
	if (subj_supported && data->subject) {
		COMMAND_SEND_EXPECT(250, "SUBJ", "SUBJ %s", data->subject);
	}
	if (call_supported && data->callerid) {
		char clidbuf[256];
		const char *clid = data->callerid;
		char *tmp;
		/* data->callerid could be either a telephone number or an email address.
		 * If it's an email address and it's in "Name <email>" format, pluck out just the email address, without the name.
		 * We don't include the <> themselves, to keep it as small as possible.
		 * This matches how Spok formats email addresses in pages. */
		if (strchr(clid, '<') && strchr(clid, '>')) {
			safe_strncpy(clidbuf, data->callerid, sizeof(clidbuf));
			tmp = strchr(clidbuf, '<'); /* Must exist, we checked */
			tmp++;
			clid = tmp;
			bbs_strterm(tmp, '>');
		}
		COMMAND_SEND_EXPECT(250, "CALL", "CALL %s", clid);
	}

	/* Message body */
	if (data->body || (!subj_supported && data->subject) || (!call_supported && data->callerid)) {
		char clidbuf[256];
		const char *clid = data->callerid;
		const char *msg = S_OR(data->body, data->message);
		/* If we have a name, pluck out just the email */
		if ((!call_supported && clid) && strchr(clid, '<') && strchr(clid, '>')) {
			char *tmp;
			safe_strncpy(clidbuf, data->callerid, sizeof(clidbuf));
			tmp = strchr(clidbuf, '<'); /* Must exist, we checked */
			tmp++;
			clid = tmp;
			bbs_strterm(tmp, '>');
		}
		COMMAND_SEND_EXPECT(354, "DATA", "DATA");
		if (!subj_supported && data->subject) {
			if (!call_supported && !strlen_zero(clid)) {
				/* This is the format Spok uses when sending pages arriving via SMTP to a pager: */
				COMMAND_SEND_EXPECT(250, "DATA", "From: %s\r\nSubject: %s - %s\r\n.", clid, data->subject, msg);
			} else {
				COMMAND_SEND_EXPECT(250, "DATA", "Subject: %s - %s\r\n.", data->subject, msg);
			}
		} else if (!call_supported && !strlen_zero(clid)) {
			COMMAND_SEND_EXPECT(250, "DATA", "From: %s\r\n%s\r\n.", clid, msg);
		} else {
			/* Note: If sending email to Spok, they will still include Subject: - body... in the message,
			 * even if no subject was provided in the email message. We don't do that here. */
			COMMAND_SEND_EXPECT(250, "DATA", "%s\r\n.", msg);
		}
	} else if (data->message) {
		COMMAND_SEND_EXPECT(250, "MESS", "MESS %s", data->message);
	} else {
		/* In SNPP, the message payload is mandatory, even though for tone-only pagers, there is no message payload.
		 * So just send something short and generic, it's arbitrary. */
		COMMAND_SEND_EXPECT(250, "MESS", "MESS %s", "New Page");
	}
	bbs_debug(3, "=> SEND\n");
	bbs_tcp_client_send(client, "SEND\r\n");
	res = bbs_readline(client->rfd, &client->rldata, "\r\n", SEC_MS(30)); /* Wait longer, in case SEND triggers a synchronous operation */
	if (res < 0) {
		goto cleanup;
	}
	bbs_debug(3, "<= %s\n", client->buf);
	if (!STARTS_WITH(client->buf, "250")) {
		int code = atoi(client->buf);
		if (code != 250 && code < 800) {
			saved_errno = snpp_code_to_errno("SEND", code, client->buf);
			bbs_debug(3, "Unexpected SNPP response: %s\n", client->buf);
			goto cleanup;
		}
	}
	COMMAND_SEND_EXPECT(221, "QUIT", "QUIT");
	bbs_tcp_client_cleanup(client);
	meta->status |= PAGE_DELIVERED;
	return 0;

cleanup:
	COMMAND_SEND_EXPECT_NONFATAL(221, "QUIT", "QUIT"); /* If it fails, don't end up in a loop by going to cleanup */
	bbs_tcp_client_cleanup(client);
	errno = saved_errno ? saved_errno : EAGAIN;
	return -1;
}

struct bbs_paging_callbacks paging_callbacks = {
	.page_single = page_single, /* mod_paging only calls the other modules with one recipient per invocation, so no point implementing page_multiple */
};

static int load_module(void)
{
	return bbs_register_paging_provider(&paging_callbacks, 5, PAGING_PROT_SNPP);
}

static int unload_module(void)
{
	bbs_unregister_paging_provider(&paging_callbacks);
	return 0;
}

BBS_MODULE_INFO_STANDARD("SNPP Paging Client");
