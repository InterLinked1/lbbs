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
 * \brief Simple NNTP client
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/utils.h"

#include "nntp.h"
#include "nntp_client.h"

static void back_off(int *restrict attempts, int max_attempts)
{
	int timeout = 0;
	switch (*attempts) {
		case 0:
			timeout = 30;
			break;
		case 1:
			timeout = 60;
			break;
		case 2:
			timeout = 120;
			break;
		case 3:
			timeout = 240;
			break;
		case 4:
			timeout = 600;
			break;
		case 5:
			timeout = 1200;
			break;
		case 6:
			timeout = 3600;
			break;
		case 7:
			timeout = 7200;
			break;
		case 8:
			timeout = 14400;
			break;
		case 9:
			timeout = 28800;
			break;
		case 10:
			timeout = 43200;
			break;
		default:
			timeout = 86400;
	}
	*attempts += 1;
	if ((*attempts >= max_attempts) || bbs_safe_sleep(SEC_MS(timeout))) {
		*attempts = -1; /* Abort (probably BBS shutdown) */
	}
}

int nntp_client_connect_retry(struct nntp_client *nc, struct bbs_url *url, int secure, int max_attempts)
{
	int res, attempts, code;
	nc->url = url; /* Save pointer to URL so we can log hostname later in log messages if needed */
	/* Establish a connection to the site and make sure we can send articles */
	for (attempts = 0 ; attempts != -1 ; back_off(&attempts, max_attempts)) {
		res = bbs_tcp_client_connect(&nc->tcpclient, url, secure, nc->buf, sizeof(nc->buf));
		/* If we fail now, it's possible the connection could succeed later;
		 * we should periodically retry. */
		if (res) {
			continue;
		}
		res = nntp_client_expect(nc, SEC_MS(30), "20"); /* Looking for 200 or 201 response */
		if (res) {
			bbs_tcp_client_cleanup(&nc->tcpclient);
			continue;
		} else if (!(code = atoi(nc->buf)) || !(code == NNTP_OK_BANNER_POST || code == NNTP_OK_BANNER_NOPOST)) {
			bbs_client_err("NNTP connection failed (%s), aborting\n", nc->buf);
			bbs_tcp_client_cleanup(&nc->tcpclient);
			continue;
		}
		break;
	}
	return attempts == -1 ? -1 : 0;
}

int nntp_client_connect(struct nntp_client *nc, struct bbs_url *url, int secure)
{
	return nntp_client_connect_retry(nc, url, secure, 1);
}

int nntp_client_read(struct nntp_client *nc, int timeout)
{
	return (int) bbs_readline(nc->tcpclient.rfd, &nc->tcpclient.rldata, "\r\n", SEC_MS(timeout));
}

int nntp_client_read_code(struct nntp_client *nc, int timeout)
{
	ssize_t res = nntp_client_read(nc, timeout);
	if (res <= 0) {
		return (int) res;
	}
	return atoi(nc->buf);
}

int nntp_client_capabilities(struct nntp_client *nc)
{
	int res;

	/* Check the CAPABILITIES for things of interest:
	 * - Whether STARTTLS is supported
	 * - Whether AUTHINFO is supported
	 * - Whether STREAMING is supported
	 *
	 * In particular, for the latter, this alleviates the need to try MODE STREAM to check for streaming support,
	 * so it's not a waste of RTT. */

	memset(&nc->caps, 0, sizeof(struct nntp_capabilities));

	nntp_client_send(nc, "CAPABILITIES\r\n");
	res = nntp_client_expect_code(nc, SEC_MS(30), NNTP_INFO_CAPABILITIES);
	if (res) {
		return -1;
	}
	for (;;) {
		ssize_t rres = nntp_client_read(nc, 30);
		if (rres < 0) {
			return -1;
		}
		/* Capabilities are case-insensitive */
		if (!strcmp(nc->buf, ".")) {
			break;
		} else if (!strcasecmp(nc->buf, "VERSION 2")) {
			nc->caps.version2 = 1;
		} else if (STARTS_WITH(nc->buf, "IMPLEMENTATION")) {
			continue; /* Don't care */
		} else if (!strcasecmp(nc->buf, "STARTTLS")) {
			nc->caps.starttls = 1;
		} else if (!strcasecmp(nc->buf, "COMPRESS DEFLATE")) {
			nc->caps.compress = 1;
		} else if (!strcasecmp(nc->buf, "READER")) {
			nc->caps.reader = 1;
		} else if (!strcasecmp(nc->buf, "NEWNEWS")) {
			nc->caps.newnews = 1;
		} else if (!strcasecmp(nc->buf, "POST")) {
			nc->caps.post = 1;
		} else if (!strcasecmp(nc->buf, "IHAVE")) {
			nc->caps.ihave = 1;
		} else if (!strcasecmp(nc->buf, "MODE-READER")) {
			nc->caps.modereader = 1;
		} else if (!strcasecmp(nc->buf, "STREAMING")) {
			nc->caps.streaming = 1;
		} else if (!strcasecmp(nc->buf, "HDR")) {
			nc->caps.hdr = 1;
		} else if (!strcasecmp(nc->buf, "XPAT")) {
			nc->caps.xpat = 1;
		} else if (!strcasecmp(nc->buf, "AUTHINFO USER")) {
			nc->caps.authinfo_user = 1;
		} else if (!strcasecmp(nc->buf, "SASL PLAIN")) {
			nc->caps.sasl_plain = 1;
		} else if (STARTS_WITH(nc->buf, "OVER")) {
			nc->caps.over = 1;
			if (strstr(nc->buf, "MSGID")) {
				nc->caps.overmsgid = 1;
			}
		} else if (STARTS_WITH(nc->buf, "LIST")) {
			char *l, *listcaps = nc->buf + STRLEN("LIST");
			while ((l = strsep(&listcaps, " "))) {
				if (strlen_zero(l)) {
					continue;
				} else if (!strcasecmp(l, "ACTIVE")) {
					nc->caps.listcaps |= LIST_ACTIVE;
				} else if (!strcasecmp(l, "ACTIVE.TIMES")) {
					nc->caps.listcaps |= LIST_ACTIVE_TIMES;
				} else if (!strcasecmp(l, "COUNTS")) {
					nc->caps.listcaps |= LIST_COUNTS;
				} else if (!strcasecmp(l, "DISTRIB.PATS")) {
					nc->caps.listcaps |= LIST_DISTRIB_PATS;
				} else if (!strcasecmp(l, "DISTRIBUTIONS")) {
					nc->caps.listcaps |= LIST_DISTRIBUTIONS;
				} else if (!strcasecmp(l, "HEADERS")) {
					nc->caps.listcaps |= LIST_HEADERS;
				} else if (!strcasecmp(l, "MODERATORS")) {
					nc->caps.listcaps |= LIST_MODERATORS;
				} else if (!strcasecmp(l, "MOTD")) {
					nc->caps.listcaps |= LIST_NEWSGROUPS;
				} else if (!strcasecmp(l, "OVERVIEW.FMT")) {
					nc->caps.listcaps |= LIST_OVERVIEW_FMT;
				} else if (!strcasecmp(l, "SUBSCRIPTIONS")) {
					nc->caps.listcaps |= LIST_SUBSCRIPTIONS;
				}
			}
		} else if (!strcasecmp(nc->buf, "ETRN")) {
			continue; /* Don't care */
		} else if (!strcasecmp(nc->buf, "XSECRET")) {
			continue; /* Don't care */
		} else {
			bbs_client_err("Unexpected capability '%s'\n", nc->buf);
		}
	}
	return 0;
}

int nntp_client_mode_reader(struct nntp_client *nc)
{
	int res, code;
	nntp_client_send(nc, "MODE READER\r\n");
	res = nntp_client_expect(nc, SEC_MS(30), "20"); /* Looking for 200 or 201 response */
	if (res || !(code = atoi(nc->buf)) || !(code == NNTP_OK_BANNER_POST || code == NNTP_OK_BANNER_NOPOST)) {
		bbs_notice("MODE READER failed for %s (%s), aborting\n", nc->url->host, nc->buf);
		return -1;
	}
	return 0;
}

int nntp_client_starttls(struct nntp_client *nc)
{
	if (!bbs_io_transformer_available(TRANSFORM_TLS_ENCRYPTION)) {
		bbs_notice("STARTTLS required for %s, but unavailable, aborting\n", nc->url->host);
		return -1;
	} else if (!nc->caps.starttls) {
		bbs_notice("STARTTLS not offered by %s, aborting\n", nc->url->host);
		return -1;
	}
	nntp_client_send(nc, "STARTTLS\r\n");
	if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_CONT_STARTTLS)) {
		return -1;
	}
	if (bbs_tcp_client_starttls(&nc->tcpclient, nc->url->host)) {
		return -1;
	}
	return 0;
}

int nntp_client_compress(struct nntp_client *nc)
{
	if (!bbs_io_transformer_available(TRANSFORM_DEFLATE_COMPRESSION)) {
		bbs_notice("Compression required for %s, but unavailable, aborting\n", nc->url->host);
		return -1;
	} else if (!nc->caps.compress) {
		bbs_notice("COMPRESS DEFLATE not offered by %s, aborting\n", nc->url->host);
		return -1;
	}
	nntp_client_send(nc, "COMPRESS DEFLATE\r\n");
	if (nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_COMPRESS)) {
		return -1;
	}
	if (bbs_tcp_client_compress(&nc->tcpclient)) {
		return -1;
	}
	return 0;
}

int nntp_client_authenticate(struct nntp_client *nc, const char *username, const char *password)
{
	int res;
	if (nc->caps.sasl_plain) { /* Prefer SASL if available to save a RTT */
		char *saslstr = bbs_sasl_encode(username, username, password);
		if (!saslstr) {
			return -1;
		}
		nntp_client_send(nc, "AUTHINFO SASL PLAIN %s\r\n", saslstr);
		free(saslstr);
		res = nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_AUTHINFO);
		if (res) {
			return -1;
		}
	} else if (nc->caps.authinfo_user) {
		nntp_client_send(nc, "AUTHINFO USER %s\r\n", username);
		res = nntp_client_expect_code(nc, SEC_MS(30), NNTP_CONT_AUTHINFO);
		if (res) {
			return -1;
		}
		nntp_client_send(nc, "AUTHINFO PASS %s\r\n", password);
		res = nntp_client_expect_code(nc, SEC_MS(30), NNTP_OK_AUTHINFO);
		if (res) {
			return -1;
		}
	} else {
		bbs_notice("No mutual authentication methods supported by %s\n", nc->url->host);
		return -1;
	}
	return 0;
}
