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
 * \brief TDD Message Protocol
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <ctype.h> /* use isspace for ltrim */

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/user.h"
#include "include/paging.h"

#include "include/mod_asterisk_ami.h"

#define MAX_TMP_MSG_LEN 512

static int tmp_port = 0; /* No default */
static int tmps_port = 0; /* No default */

/*
 * TDD (Telecommunications Device for the Deaf) Message Protocol
 *
 * Currently an unofficial protocol, not standardized in any RFC
 *
 * This is a simplified variant of the Message Send Protocol (MSP) and TAP/IXO protocols,
 * a shorter message protocol, if you will.
 *
 * It is intended to be used indirectly by TDD devices calling
 * and the Asterisk softmodem proxying such connections to this TCP port.
 * Therefore, this TCP port does not need to be publicly accessible,
 * only accessible to the Asterisk server.
 *
 * The message prompt is defined as '> ', indicating the user may send a payload.
 * The payload format is defined as:
 *
 * "<RECIPIENT> SP <BODY> [CR]LF
 *
 * The sender is extracted out of band from the phone system, if possible.
 * The actual delivery method (email, page, etc.) is left undefined by this
 * specification, but in this implementation, is sent as an ephemeral alert
 * and/or asynchronous message (e.g. email) to the recipient, if found.
 *
 * The CR is optional, and if sent, is deleted; just LF is needed to terminate the
 * message, to maximize compatibility.
 *
 * This protocol is server sends first. An optional message be sent initially,
 * but the client should not send any payload until receiving the prompt.
 *
 * After a payload is received, a short human-consumable response is sent,
 * and if no fatal errors have occured, another prompt is provided to allow
 * another message to be sent.
 *
 * This protocol is not intended for machine-to-machine communication and is
 * strictly intended for interactive use by humans, from TDD devices.
 *
 * This protocol provides no means for authentication or for a sender to indicate
 * his identity (aside from the Caller ID, which may be extracted from the phone
 * system). If the sender wishes to convey his identity, it should be explicitly
 * included in the message itself.
 *
 * To quit, the user simply hangs up the TDD phone connection, which will terminate
 * the proxied TCP connection. If the user hangs up in the middle of a message
 * that has not been sent by pressing ENTER, any in-progress message is discarded.
 *
 * Security implications:
 * The TCP port used by the system does not need to be publicly accessible,
 * to ensure any uses of this protocol are via an approved modem connection.
 * This allows the phone system to handle screening of calls, if needed,
 * since the TDD Message Protocol does no authentication or verification of its own.
 *
 */

struct tmp_session {
	struct bbs_node *node;
	size_t bytes_written;
};

static ssize_t read_msg(struct bbs_node *node, char *restrict buf, size_t len)
{
	ssize_t bytes = 0;
	char *bufptr = buf;
	size_t left = len;

	for (;;) {
		char *next = bufptr;
		ssize_t res = bbs_poll(node->fd, MIN_MS(1)); /* Wait 1 minute for input */
		if (res <= 0) {
			return -1;
		}
		res = read(node->rfd, bufptr, left);
		if (res < 0) {
			bbs_error("read failed: %s\n", strerror(errno));
			return -1;
		} else if (!res) {
			return -1;
		}
		bytes += res;
		bufptr += res;
		left -= (size_t) res;
		if (left <= 0) {
			bbs_warning("TMP message too long, buffer exhausted\n");
			return -1;
		}
		/* We've gotten the entire payload once we've gotten a LF */
		while (res--) {
			if (*next++ == '\n') {
				/* Got the entire message */
				*next = '\0';
				if (next > buf && *(next - 1) == '\r') {
					*(next - 1) = '\0';
				}
				return bytes;
			}
		}
	}
}

static int tmp_response(struct tmp_session *tmp, const char *s, size_t len)
{
	ssize_t wres;
	bbs_debug(3, "TMP response <= %.*s\n", (int) len, s);
	wres = bbs_node_fd_write(tmp->node, tmp->node->wfd, s, len);
	if (wres > 0) {
		tmp->bytes_written += (size_t) wres;
	}
	return 0;
}

/* Pad message with trailing spaces to ensure it comes through clearly in its entirety */
#define TMP_RESPONSE(tmp, s) tmp_response(tmp, "  " s "  ", STRLEN("  " s "  "))

static int handle_msg(struct tmp_session *tmp, char *buf, const char *number, const char *name)
{
	int res;
	struct bbs_paging_recipient recip;
	struct bbs_paging_data data;
	struct bbs_paging_message_metadata meta;
	char *recipient, *body = buf;

	ltrim(body);
	bbs_strterm(body, '\r'); /* We'll get a CR when the TDD user presses RETURN */

	recipient = strsep(&body, " ");

	/* Keep all responses short so they can be sent succintly on a 45.45 TDD connection */
	if (strlen_zero(recipient)) {
		TMP_RESPONSE(tmp, "Missing recipient");
		return 0;
	} else if (strlen_zero(body)) {
		TMP_RESPONSE(tmp, "Missing message");
		return 0;
	}

	bbs_debug(3, "CallerNumber: %s, CallerName: %s, Recipient: %s, Body: %s\n", S_IF(number), S_IF(name), recipient, body);

	/* Marshal our arguments into the paging structures (there ain't much here, though!) */
	memset(&recip, 0, sizeof(recip));
	recip.pagerid = recipient; /* Page by username */
	memset(&data, 0, sizeof(data));
	data.body = body;
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	data.callerid = (char*) number; /* This isn't allocated, so we don't need to free it later */
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
	data.node = tmp->node;

	res = bbs_page_single(&recip, &data, &meta);

	if (res) {
		switch (errno) {
			case ENOENT:
				TMP_RESPONSE(tmp, "Invalid Pager ID");
				break;
			case EAGAIN:
			case ECHILD:
				TMP_RESPONSE(tmp, "Temp failure, retry later");
				break;
			case EACCES: /* PIN required (only supported by SNPP) */
				TMP_RESPONSE(tmp, "Pager is restricted");
				break;
			case EINVAL:
				TMP_RESPONSE(tmp, "Illegal Pager ID");
				break;
			case EDOM:
				TMP_RESPONSE(tmp, "Tone-only pager");
				break;
			case ERANGE:
				TMP_RESPONSE(tmp, "Numeric paging only");
				break;
			case EMSGSIZE:
				TMP_RESPONSE(tmp, "Long message rejected");
				break;
			case EDQUOT:
				TMP_RESPONSE(tmp, "Message quota exceeded");
				break;
			default:
				TMP_RESPONSE(tmp, "Other Failure");
		}
	} else {
		if (!(meta.status & PAGE_DELIVERED)) {
			TMP_RESPONSE(tmp, "Page Accepted, Deferred Delivery");
		} else {
			TMP_RESPONSE(tmp, "Page Accepted");
		}
	}
	return 0;
}

#define MESSAGE_PROMPT(tmp) TMP_RESPONSE(tmp, ">")

static int __tmp_handler(struct tmp_session *tmp)
{
	char buf[MAX_TMP_MSG_LEN + 1];
	char number[16], name[16];

	/* Start TLS if we need to */
	if (!strcmp(tmp->node->protname, "TMPS") && bbs_node_starttls(tmp->node)) {
		return -1;
	}

	if (bbs_ami_softmodem_get_callerid(tmp->node, NULL, 0, number, sizeof(number), name, sizeof(name))) {
		return -1;
	}

	for (;;) {
		ssize_t res;
		MESSAGE_PROMPT(tmp);
		res = read_msg(tmp->node, buf, sizeof(buf));
		if (res < 0) {
			break;
		}
		if (handle_msg(tmp, buf, number, name)) {
			bbs_debug(4, "Failed to handle TMP message\n");
			break;
		}
		/* If all is well, allow the client to send another message. */
	}
	return -1;
}

static void *tmp_handler(void *varg)
{
	struct tmp_session tmp;
	struct bbs_node *node = varg;

	memset(&tmp, 0, sizeof(tmp));
	tmp.node = node;

	bbs_node_net_begin(node);
	__tmp_handler(&tmp);
	if (tmp.bytes_written > STRLEN("  >  ")) {
		/* Wait for any pending TDD transmission to finish sending before exiting,
		 * or softmodem may terminate prematurely before all data has been written out.
		 * However, if the client connected and we never wrote anything out,
		 * no need to wait here. */
		bbs_node_safe_sleep(node, SEC_MS((int) tmp.bytes_written / 9)); /* Wait time here is a likely upper bound, may need less time */
	}
	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	int res;
	struct bbs_config *cfg = bbs_config_load("net_tmp.conf", 0);

	if (!cfg) {
		return 0;
	}

	res = bbs_config_val_set_port(cfg, "general", "port", &tmp_port) && bbs_config_val_set_port(cfg, "general", "secureport", &tmps_port); /* At least one required */
	bbs_config_unlock(cfg);
	return res;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	return bbs_start_tcp_listener2(tmp_port, tmps_port, "TMP", "TMPS", tmp_handler);
}

static int unload_module(void)
{
	if (tmp_port) {
		bbs_stop_tcp_listener(tmp_port);
	}
	if (tmps_port) {
		bbs_stop_tcp_listener(tmps_port);
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("TDD Message Protocol", "mod_asterisk_ami.so");
