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
 * \brief RFC 1312 Message Send Protocol
 *
 * \note Supersedes RFC 1159
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/user.h"
#include "include/notify.h"
#include "include/net_irc.h"

#define DEFAULT_MSP_PORT 18
#define MAX_MSP_MSG_LEN 512

static int msp_tcp_port = DEFAULT_MSP_PORT;
static int msp_udp_port = DEFAULT_MSP_PORT;

static pthread_t udp_thread;
static int udp_socket = -1;
static int unloading = 0;

struct msp {
	struct bbs_node *node;	/* Node (TCP only) */
	struct sockaddr_in *in;	/* sockaddr (UDP only) */
	socklen_t slen;			/* sockaddr len (UDP only) */
	unsigned int version:1; /* 0 = 'A', 1 = 'B' */
	const char *recip;
	const char *recipterm;
	const char *message;
	/* Only in version 2 of the protocol: */
	const char *sender;
	const char *senderterm;
	const char *cookie;
	const char *signature;
};

/*!
 * \brief Variant of strsep that delimits on NULL, with bounds check
 * \param[out] var Variable corresponding to next token to parse
 * \param buf Current buffer, which will be updated to the remaining portion after the current token
 * \param len Amount remaining in buf, which will be updated after buf is parsed
 * \retval 0 on success, -1 on failure
 */
static int strnsep(const char **restrict var, char **restrict buf, size_t *restrict len)
{
	char *s;

	if (*len <= 0) {
		bbs_error("Buffer exhausted\n");
		return -1;
	} else if (!*buf) {
		bbs_error("Nothing left in buffer to parse\n");
		return -1;
	}

	*var = s = *buf;

	for (;;) {
		*len -= 1;
		if (*s == '\0') {
			/* Since the NUL is already in the buffer, *var is already NUL terminated */
			*buf = s + 1;
			if (!*len) {
				*buf = NULL; /* There is nothing more to read, that's the end of the buffer */
			}
			bbs_debug(4, "Parsed token '%s'\n", *var);
			return 0;
		}
		if (!*len) {
			bbs_error("Exhausted buffer before successfully parsing another token (got '%.*s')\n", (int) (s - *buf), *buf);
			return -1;
		}
		s++;
	}
}

static int parse_msp(struct msp *restrict msp, char *restrict buf, size_t len)
{
	char version;
	char *tmp = buf;

	/* Since the payload contains NULs, we need to know how long it is. */

	version = *tmp++;
	len--;
	if (version == 'B') {
		msp->version = 1;
	} else if (version != 'A') {
		bbs_warning("Invalid MSP protocol version\n");
		return -1;
	}

	if (strnsep(&msp->recip, &tmp, &len)) {
		bbs_warning("Failed to parse recipient\n");
		return -1;
	}
	if (strnsep(&msp->recipterm, &tmp, &len)) {
		bbs_warning("Failed to parse recipient terminal\n");
		return -1;
	}
	if (strnsep(&msp->message, &tmp, &len)) {
		bbs_warning("Failed to parse message\n");
		return -1;
	}

	if (!msp->version) {
		/* Finished parsing a version 1 payload */
		return 0;
	}

	if (strnsep(&msp->sender, &tmp, &len)) {
		bbs_warning("Failed to parse sender\n");
		return -1;
	}
	if (strnsep(&msp->senderterm, &tmp, &len)) {
		bbs_warning("Failed to parse sender terminal\n");
		return -1;
	}
	if (strnsep(&msp->cookie, &tmp, &len)) {
		bbs_warning("Failed to parse cookie\n");
		return -1;
	}
	if (strnsep(&msp->signature, &tmp, &len)) {
		bbs_warning("Failed to parse signature\n");
		return -1;
	}

	/* Finished parsing version 2 payload */
	return 0;
}

/*! \brief Read message into buffer for TCP handler */
static ssize_t read_msg(struct msp *restrict msp, char *restrict buf, size_t len, int rfd)
{
	int got_version = 0;
	int nulls_wanted;
	ssize_t bytes = 0;
	char *bufptr = buf;
	size_t left = len;

	for (;;) {
		char *next = bufptr;
		ssize_t res = bbs_poll(rfd, MIN_MS(1));
		if (res <= 0) {
			return -1;
		}
		res = read(rfd, bufptr, left);
		if (res < 0) {
			bbs_error("read failed: %s\n", strerror(errno));
			return -1;
		} else if (!res) {
			if (got_version) {
				bbs_debug(3, "Client disconnected mid-message, with %d part%s remaining\n", nulls_wanted, ESS(nulls_wanted));
			}
			return -1;
		}
		bytes += res;
		bufptr += res;
		left -= (size_t) res;
		if (left <= 0) {
			bbs_warning("MSP message too long, buffer exhausted\n");
			return -1;
		}
		if (!got_version) {
			if (buf[0] != 'A' && buf[0] != 'B') {
				/* If we don't get a valid protocol version,
				 * don't even bother reading the rest. */
				bbs_warning("Invalid MSP protocol version: '%c'\n", buf[0]);
				return -1;
			}
			msp->version = buf[0] == 'B';
			got_version = 1;
			nulls_wanted = msp->version ? 7 : 3;
		}
		/* Keep track of how many NULs we've gotten, so we know when we've gotten an entire message */
		while (res--) {
			if (*next++ == '\0') {
				if (!--nulls_wanted) {
					/* Got the entire message */
					return bytes;
				}
			}
		}
	}
}

static int msp_response(struct msp *restrict msp, const char *s, size_t len)
{
	bbs_debug(3, "MSP response <= %.*s\n", (int) len, s);
	if (msp->node) {
		bbs_node_fd_write(msp->node, msp->node->fd, s, len);
	} else {
		ssize_t res = sendto(udp_socket, s, len, 0, msp->in, msp->slen);
		if (res <= 0) {
			bbs_error("sendto failed: %s\n", strerror(errno));
		}
	}
	return 0;
}

/* Include NUL terminator, since that's part of the message */
#define MSP_ERROR(msp, s) msp_response(msp, "-" s, STRLEN("-" s) + 1)

static int handle_msp(struct msp *restrict msp, const char *ip)
{
	char msgbuf[512];
	int res;

	bbs_verb(4, "Handling Message Send Protocol version %d message\n", msp->version ? 2 : 1);

#ifdef EXTRA_DEBUG
	bbs_debug(4, "MSP message version %d:\n"
		"\tRecip: %s\n"
		"\tRecipTerm: %s\n"
		"\tMessage: %s\n"
		"\tSender: %s\n"
		"\tSenderTerm: %s\n"
		"\tCookie: %s\n"
		"\tSignature: %s\n",
		msp->version ? 2 : 1, S_IF(msp->recip), S_IF(msp->recipterm), S_IF(msp->message),
		S_IF(msp->sender), S_IF(msp->senderterm), S_IF(msp->cookie), S_IF(msp->signature));
#endif

	if (strlen_zero(msp->message)) {
		MSP_ERROR(msp, "Empty message");
		return -1;
	}

	/* Only printable characters allowed. */
	if (!bbs_str_isprint(msp->message)) {
		MSP_ERROR(msp, "Invalid characters");
		return -1;
	}

	/* While we successfully parse version 1 messages, where sender is empty,
	 * we are now obligated to process these, and we do not. */
	if (strlen_zero(msp->sender)) {
		MSP_ERROR(msp, "Empty sender");
		return -1;
	}

	/* The following are presently ignored:
	 * recipterm
	 * senderterm
	 * cookie
	 * signature
	 */

	if (strlen_zero(msp->recip)) {
		/* Not directed to any particular user.
		 * We're allowed to deliver "to any user", but just reject it... */
		MSP_ERROR(msp, "This system does not deliver messages without a recipient");
		return -1;
	} else {
		/* Directed to a particular user (or channel). */
		if (!isalpha(*msp->recip)) {
			/* Begins with a non-numeric character.
			 * Assume it's the name of an IRC channel. */
			res = irc_relay_send(msp->recip, CHANNEL_USER_MODE_NONE, "MSP", msp->sender, NULL, msp->message, NULL);
			if (res) {
				MSP_ERROR(msp, "Channel does not exist");
				return -1;
			}
		} else {
			unsigned int userid = bbs_userid_from_username(msp->recip);
			if (!userid) {
				MSP_ERROR(msp, "No such user");
				return -1;
			}
			snprintf(msgbuf, sizeof(msgbuf), "%s@%s: %s", msp->sender, ip, msp->message);
			res = bbs_alert_user(userid, DELIVERY_EPHEMERAL, "%s", msgbuf);
			if (res) {
				MSP_ERROR(msp, "User not online");
				return -1;
			}
		}
	}

	/* Responses include + or -, an optional description, and a final NUL */
	msp_response(msp, "+", 2);
	return 0;
}

static void *msp_tcp_handler(void *varg)
{
	char buf[MAX_MSP_MSG_LEN + 1];
	struct bbs_node *node = varg;

	bbs_node_net_begin(node);
	for (;;) {
		struct msp msp;
		ssize_t res;
		memset(&msp, 0, sizeof(msp));

		/* Read the message first without parsing it,
		 * so we can have a common parser for both TCP and UDP. */
		res = read_msg(&msp, buf, sizeof(buf), node->fd);
		if (res < 0) {
			break;
		}
		if (parse_msp(&msp, buf, (size_t) res)) {
			bbs_debug(4, "Failed to parse MSP payload\n");
			break;
		}
		/* We got a valid message */
		msp.node = node;
		if (handle_msp(&msp, node->ip)) {
			bbs_debug(4, "Failed to handle MSP message\n");
			break;
		}
		/* If all is well, allow the client to continue. */
	}
	bbs_node_exit(node);

	return NULL;
}

static void *msp_udp_listener(void *varg)
{
	struct pollfd pfd;

	UNUSED(varg);
	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = udp_socket;
	pfd.events = POLLIN;
	for (;;) {
		char ipaddr[55];
		struct msp msp;
		struct sockaddr_in srcaddr;
		socklen_t slen = sizeof(struct sockaddr_in);
		char buf[MAX_MSP_MSG_LEN + 1];
		ssize_t res;
		pfd.revents = 0;
		res = poll(&pfd, 1, -1);
		if (res <= 0) {
			bbs_debug(3, "poll returned %ld: %s\n", res, strerror(errno));
			break;
		}
		if (unloading) {
			break;
		}
		res = recvfrom(udp_socket, buf, sizeof(buf), 0, (struct sockaddr*) &srcaddr, &slen);
		if (res <= 0) {
			bbs_error("recvfrom returned %ld: %s\n", res, strerror(errno));
			break;
		}
		bbs_get_remote_ip(&srcaddr, ipaddr, sizeof(ipaddr));
		bbs_auth("Received new Message Send Protocol message from %s\n", ipaddr);
		memset(&msp, 0, sizeof(msp));
		msp.in = &srcaddr;
		msp.slen = slen;
		/* Single thread for all incoming UDP connections,
		 * since it won't take very long to service requests. */
		if (parse_msp(&msp, buf, (size_t) res)) {
			bbs_debug(4, "Failed to parse MSP payload\n");
		} else if (handle_msp(&msp, ipaddr)) {
			bbs_debug(4, "Failed to handle MSP message\n");
		}
	}
	return NULL;
}

static const char *ip = NULL, *interface = NULL;

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("net_msp.conf", 0);

	if (!cfg) {
		return 0;
	}

	/* We don't destroy the config after we return, so it's okay that we have a constant reference to it directly */
	ip = bbs_config_val(cfg, "udp", "ip");
	interface = bbs_config_val(cfg, "udp", "interface");

	return bbs_config_val_set_port(cfg, "ports", "tcp", &msp_tcp_port) && bbs_config_val_set_port(cfg, "ports", "udp", &msp_udp_port);
}

static int load_module(void)
{
	int res = 0;

	if (load_config()) {
		return -1;
	}

	if (msp_tcp_port) {
		res = bbs_start_tcp_listener(msp_tcp_port, "MSP", msp_tcp_handler);
	}
	if (!res && msp_udp_port) {
		/* Be extra careful about the interfaces to which we bind,
		 * since the source IP of UDP messages can be spoofed,
		 * and we won't be able to tell. */
		res = bbs_make_udp_socket(&udp_socket, msp_udp_port, ip, interface);
		if (!res) {
			res = bbs_pthread_create(&udp_thread, NULL, msp_udp_listener, NULL);
		}
		if (res) {
			bbs_stop_tcp_listener(msp_tcp_port);
		}
	}
	return res;
}

static int unload_module(void)
{
	if (msp_tcp_port) {
		bbs_stop_tcp_listener(msp_tcp_port);
	}
	if (msp_udp_port) {
		unloading = 1;
		bbs_socket_close(&udp_socket);
		bbs_pthread_join(udp_thread, NULL);
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC1312 Message Send Protocol", "net_irc.so");
