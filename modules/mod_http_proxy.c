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
 * \brief HTTP Forward Proxy Server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <poll.h>

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/utils.h"

/* Needed for mod_http.h */
#include "include/linkedlists.h"
#include "include/variables.h"

#include "include/stringlist.h"

#include "include/mod_http.h"

/* The way http_proxy_client is used is almost identical to smtp_relay_host in net_smtp */
struct http_proxy_client {
	const char *source;
	struct stringlist domains;
	RWLIST_ENTRY(http_proxy_client) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(proxy_clients, http_proxy_client);

static void add_proxy_client(const char *source, const char *domains)
{
	struct http_proxy_client *c;

	if (STARTS_WITH(source, "0.0.0.0")) {
		/* If someone wants to shoot him/herself in the foot, at least provide a warning */
		bbs_notice("This server is configured as an open proxy and may be abused!\n");
	}

	c = calloc(1, sizeof(*c) + strlen(source) + 1);
	if (ALLOC_FAILURE(c)) {
		return;
	}

	strcpy(c->data, source); /* Safe */
	c->source = c->data;
	stringlist_push_list(&c->domains, domains);

	/* Head insert, so later entries override earlier ones, in case multiple match */
	RWLIST_INSERT_HEAD(&proxy_clients, c, entry);
}

static void proxy_client_free(struct http_proxy_client *c)
{
	stringlist_empty(&c->domains);
	free(c);
}

static int proxy_client_authorized(const char *srcip, const char *hostname)
{
	struct http_proxy_client *c;

	RWLIST_RDLOCK(&proxy_clients);
	RWLIST_TRAVERSE(&proxy_clients, c, entry) {
		if (bbs_ip_match_ipv4(srcip, c->source)) {
			/* Just needs to be allowed by one matching entry, or wildcard allow. */
			if (stringlist_contains(&c->domains, hostname) || stringlist_contains(&c->domains, "*")) {
				RWLIST_UNLOCK(&proxy_clients);
				return 1;
			}
		}
	}
	RWLIST_UNLOCK(&proxy_clients);
	return 0;
}

/*! \brief Whether or not a header may be forwarded if via proxy
 * \param h Header name
 * \retval 1 OK to forward
 * \retval 0 Must not be forwarded
 */
static int proxy_header_forwardable(const char *h)
{
	if (!strcasecmp(h, "Proxy-Connection")) {
		return 0;
	}
	return 1;
}

static int proxy_forward_headers(struct http_session *http, struct bbs_tcp_client *client)
{
	/* Replay the request headers, omitting Proxy-Connection.
	 * Some proxies also add other identifying headers like X-Forwarded-For here. */
	struct bbs_var *v = NULL; /* Iterate from beginning */
	const char *key, *val;
	int sent = 0;
	struct bbs_vars *headers = &http->req->headers;

	/* Write the initial request line */
	if (bbs_writef(client->wfd, "%s %s %s\r\n", http_method_name(http->req->method), http->req->uri, http_version_name(http->req->version)) < 0) {
		bbs_debug(2, "Failed to write request line to proxy target\n");
		return -1;
	}

	/* Just blindly relay all the headers the client sent,
	 * unless we're explicitly not supposed to send certain headers. */
	while ((val = bbs_varlist_next(headers, &v, &key))) {
		if (!proxy_header_forwardable(key)) {
			continue;
		}
		/* XXX Do something specific for Connection / Keep-Alive headers,
		 * to handle persistence via proxy? */
		if (bbs_writef(client->wfd, "%s: %s\r\n", key, val) < 0) {
			bbs_debug(2, "Failed to write header %s to proxy target\n", key);
		} else {
			sent++;
		}
	}
	if (SWRITE(client->wfd, "\r\n") < 0) { /* EOH */
		return -1;
	}
	bbs_debug(3, "Forward proxied %d header%s\n", sent, ESS(sent));
	return 0;
}

static int proxy_relay(struct http_session *http, struct bbs_tcp_client *client, char *restrict buf, size_t len)
{
	struct pollfd pfds[2];

	memset(pfds, 0, sizeof(pfds));
	pfds[0].fd = client->rfd;
	pfds[0].events = POLLIN;
	pfds[1].fd = http->node->rfd;
	pfds[1].events = POLLIN;

	if (!(http->req->method & HTTP_METHOD_CONNECT)) {
		/* For HTTP requests with a body (not using CONNECT),
		 * part of the body may still be in the readline buffer,
		 * and we need to flush the buffer to the proxy server.
		 * Afterwards, we can just relay directly. */
		size_t bytes = (size_t) readline_bytes_available(http->rldata, 1);
		if (bytes > 0) {
			bbs_debug(3, "Flushing %lu-byte body via proxy\n", bytes);
			if (bbs_write(client->wfd, http->buf, bytes) < 0) {
				return -1;
			}
		}
	}

	bbs_debug(3, "Proxying 2 file descriptors (%d/%d) on node %d\n", pfds[0].fd, pfds[1].fd, http->node->id);
	for (;;) {
		ssize_t res;
		pfds[0].revents = pfds[1].revents = 0;
		res = poll(pfds, 2, -1);
		if (res <= 0) {
			/* If either side disconnects, terminate the proxy session. */
			bbs_debug(3, "Proxy session terminating on node %d (poll returned %ld)\n", http->node->id, res);
			break;
		}
		if (pfds[0].revents) {
			/* Data from server towards proxy client */
			res = read(client->rfd, buf, len);
			if (res <= 0) {
				bbs_debug(3, "Proxy session terminating on node %d (read returned %ld: %s)\n", http->node->id, res, strerror(errno));
				break;
			}
			if (bbs_write(http->node->wfd, buf, (size_t) res) < 0) {
				bbs_debug(3, "Proxy session terminating on node %d (write returned %ld)\n", http->node->id, res);
				break;
			}
		} else if (pfds[1].revents) {
			/* Data from proxy client towards server. */
			res = read(http->node->rfd, buf, len);
			if (res <= 0) {
				bbs_debug(3, "Proxy session terminating on node %d (read returned %ld: %s)\n", http->node->id, res, strerror(errno));
				break;
			}
			if (bbs_write(client->wfd, buf, (size_t) res) < 0) {
				bbs_debug(3, "Proxy session terminating on node %d (write returned %ld)\n", http->node->id, res);
				break;
			}
		}
	}

	return -1;
}

static enum http_response_code proxy_handler(struct http_session *http)
{
	char buf[BUFSIZ];
	struct bbs_url url;
	struct bbs_tcp_client client;
	char hostbuf[512];
	const char *host;
	unsigned int port;

	port = http->req->hostport;
	if (port == 0 && !(http->req->method & HTTP_METHOD_CONNECT)) {
		/* No port was specified explicitly, use the default for the protocol (However, in CONNECT, it must be specified explicitly) */
		port = http->secure ? 443 : 80;
	}

	/* Want the host without the port attached */
	if (http->req->method & HTTP_METHOD_CONNECT) {
		if (strlen_zero(http->req->host)) {
			bbs_warning("CONNECT request missing hostname\n");
			return HTTP_BAD_REQUEST;
		}
		bbs_strncpy_until(hostbuf, http->req->host, sizeof(hostbuf), ':'); /* Strip : */
		host = hostbuf;
	} else {
		host = http->req->host;
	}

	/* Determine if the client is authorized to be proxying at all. */
	if (!proxy_client_authorized(http->node->ip, host)) {
		bbs_debug(2, "Client %s is not authorized to proxy to %s:%u\n", http->node->ip, host, port);
		return HTTP_UNAUTHORIZED;
	}

	/* If we're tunneling, only allow connections to ports 80 and 443, to avoid proxying arbitrary protocols. */
	if (http->req->method & HTTP_METHOD_CONNECT && (port != 80 && port != 443)) {
		bbs_debug(2, "Rejecting proxy request to nonstandard HTTP/HTTPS port %u\n", port);
		return HTTP_FORBIDDEN;
	}

	bbs_debug(5, "Client %s is authorized to proxy traffic to %s:%u\n", http->node->ip, host, port);

	/* Set up the TCP connection to the target. */
	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));
	url.host = host;
	url.port = (int) port;
	/* Never set up TLS (even for HTTPS over CONNECT), since the proxy client is responsible for doing that.
	 * We'll be oblivious to the juicy details of what they're saying to each other. */
	if (bbs_tcp_client_connect(&client, &url, 0, buf, sizeof(buf))) {
		bbs_debug(3, "Could not get connect to proxy destination %s:%u\n", host, port);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	if (http->req->method & HTTP_METHOD_CONNECT) {
		/* For CONNECT, this is it, we can just send 200 OK now and then relay everything hereafter. */
		http->res->code = HTTP_OK; /* Hasn't been set using the higher-level functions, so set manually */
		http_send_response_status(http, HTTP_OK);
		NODE_SWRITE(http->node, http->wfd, "\r\n"); /* CR LF to indicate end of headers */
	} else {
		if (proxy_forward_headers(http, &client)) {
			bbs_warning("Failed to forward headers to proxy destination %s:%u\n", host, port);
			return HTTP_BAD_GATEWAY;
		}
	}

	proxy_relay(http, &client, buf, sizeof(buf));
	bbs_tcp_client_cleanup(&client);
	return -2; /* Disconnect now */
}

static unsigned short int proxy_port = 0; /* Check default port at runtime. Can't use http_get_default_http_port without also depending on net_http first to set that */

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("mod_http_proxy.conf", 0);
	if (!cfg) {
		return -1; /* Decline to load if there is no config. */
	}

	/* Read in the authorized proxy clients and authorized destinations */
	while ((section = bbs_config_walk(cfg, section))) {
		struct bbs_keyval *keyval = NULL;
		const char *key, *val;

		if (!strcmp(bbs_config_section_name(section), "clients")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				key = bbs_keyval_key(keyval);
				val = bbs_keyval_val(keyval);
				add_proxy_client(key, val);
			}
		} else if (strcasecmp(bbs_config_section_name(section), "general")) {
			bbs_warning("Invalid section name '%s'\n", bbs_config_section_name(section));
		}
	}

	return 0;
}

static int unload_module(void)
{
	int res = http_unregister_proxy_handler(proxy_handler);
	RWLIST_WRLOCK_REMOVE_ALL(&proxy_clients, entry, proxy_client_free);
	return res;
}

static int load_module(void)
{
	if (load_config() || http_register_proxy_handler(proxy_port,
		HTTP_METHOD_HEAD | HTTP_METHOD_GET | HTTP_METHOD_POST | HTTP_METHOD_PUT | HTTP_METHOD_DELETE | HTTP_METHOD_CONNECT,
		proxy_handler)) {
		RWLIST_WRLOCK_REMOVE_ALL(&proxy_clients, entry, proxy_client_free);
		return -1;
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("HTTP Forward Proxy Server", "mod_http.so");
