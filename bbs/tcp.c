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
 * \brief High-level TCP client
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdarg.h>

#include "include/utils.h"
#include "include/node.h"

void bbs_tcp_client_cleanup(struct bbs_tcp_client *client)
{
	bbs_io_teardown_all_transformers(&client->trans);
	bbs_io_session_unregister(&client->trans);
	close_if(client->fd);
}

static int starttls(struct bbs_tcp_client *client, const char *snihostname)
{
	if (!bbs_io_transformer_available(TRANSFORM_TLS_ENCRYPTION)) {
		return 1;
	}

	return bbs_io_transform_setup(&client->trans, TRANSFORM_TLS_ENCRYPTION, TRANSFORM_CLIENT, &client->rfd, &client->wfd, snihostname);
}

int bbs_tcp_client_connect(struct bbs_tcp_client *client, struct bbs_url *url, int secure, char *buf, size_t len)
{
	client->fd = bbs_tcp_connect(url->host, url->port);
	if (client->fd < 0) {
		return -1;
	}
	client->wfd = client->rfd = client->fd;
	SET_BITFIELD(client->secure, secure);
	client->buf = buf;
	client->len = len;
	if (client->secure) {
		if (starttls(client, url->host)) {
			bbs_debug(3, "Failed to set up TLS\n");
			close_if(client->fd);
			return -1;
		}
		bbs_debug(5, "Implicit TLS completed\n");
	}
	bbs_readline_init(&client->rldata, client->buf, client->len);
	bbs_io_session_register(&client->trans, TRANSFORM_SESSION_TCPCLIENT, client);
	return 0;
}

int bbs_tcp_client_starttls(struct bbs_tcp_client *client, const char *hostname)
{
	bbs_assert(!client->secure);

	if (starttls(client, hostname)) {
		bbs_warning("Failed to do STARTTLS\n");
		return -1;
	}
	bbs_readline_flush(&client->rldata); /* Prevent STARTTLS response injection by resetting the buffer after TLS upgrade */
	return 0;
}

ssize_t __attribute__ ((format (gnu_printf, 2, 3))) bbs_tcp_client_send(struct bbs_tcp_client *client, const char *fmt, ...)
{
	char *buf;
	int len;
	ssize_t res;
	va_list ap;

	if (!strchr(fmt, '%')) {
		return bbs_write(client->wfd, fmt, strlen(fmt));
	}

	/* Do not use vdprintf, I have not had good experiences with that... */
	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	res = bbs_write(client->wfd, buf, (size_t) len);
	free(buf);
	return res;
}

int bbs_tcp_client_expect(struct bbs_tcp_client *client, const char *delim, int attempts, int ms, const char *str)
{
	while (attempts-- > 0) {
		ssize_t res = bbs_readline(client->rfd, &client->rldata, delim, ms);
		if (res < 0) {
			bbs_debug(3, "bbs_readline returned %ld\n", res);
			bbs_readline_print_reset(&client->rldata);
			return -1;
		}
		bbs_debug(7, "<= %s\n", client->buf);
		if (strstr(client->buf, str)) {
			return 0;
		}
	}
	bbs_warning("Missing expected response (%s), got: %s\n", str, client->buf);
	return 1;
}
