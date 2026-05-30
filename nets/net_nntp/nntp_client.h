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

struct nntp_capabilities {
	unsigned int version2:1;
	unsigned int starttls:1;
	unsigned int compress:1;
	unsigned int reader:1;
	unsigned int newnews:1;
	unsigned int post:1;
	unsigned int ihave:1;
	unsigned int modereader:1;
	unsigned int streaming:1;
	unsigned int hdr:1;
	unsigned int over:1;
	unsigned int overmsgid:1;
	unsigned int xpat:1;
	unsigned int authinfo_user:1;
	unsigned int sasl_plain:1;
	enum list_category listcaps;
};

struct nntp_client {
	struct bbs_tcp_client tcpclient;
	struct nntp_capabilities caps;
	struct bbs_url *url;
	char buf[8192]; /* Large for leniency when sucking articles */
};

#define nntp_client_send(nc, fmt, ...) \
	bbs_tcp_client_send(&(nc)->tcpclient, fmt, ## __VA_ARGS__); \
	bbs_debug(7, "<= " fmt, ## __VA_ARGS__); \

#define nntp_client_expect(nc, timeout, str) bbs_tcp_client_expect(&(nc)->tcpclient, "\r\n", 1, timeout, str)

#define nntp_client_expect_code(nc, timeout, code) ({ \
	int _x = bbs_tcp_client_expect(&(nc)->tcpclient, "\r\n", 1, timeout, XSTR(code)); \
	if (_x < 0) { \
		bbs_client_err("Expected %s, got %s\n", XSTR(code), nc->buf); \
	} \
	_x; \
})

int nntp_client_connect(struct nntp_client *nc, struct bbs_url *url, int secure);
int nntp_client_read(struct nntp_client *nc, int timeout);
int nntp_client_read_code(struct nntp_client *nc, int timeout);
int nntp_client_capabilities(struct nntp_client *nc);
int nntp_client_mode_reader(struct nntp_client *nc);
int nntp_client_starttls(struct nntp_client *nc);
int nntp_client_compress(struct nntp_client *nc);
int nntp_client_authenticate(struct nntp_client *nc, const char *username, const char *password);
