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
 * \brief RFC 6455 WebSocket Server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <pthread.h>

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/tls.h"

/* Needed for mod_http.h */
#include "include/linkedlists.h"
#include "include/variables.h"

#include "include/mod_http.h"
#include "include/net_ws.h"

#include <wss.h> /* libwss */

static int http_port = 0, https_port = 0;
static int ws_port = 0, wss_port = 0;

static void ws_log(int level, int len, const char *file, const char *function, int line, const char *buf)
{
	/*! \todo should be a version of __bbs_log that doesn't call asprintf, for efficiency (accepts # bytes) */
	switch (level) {
		case WS_LOG_ERROR:
			__bbs_log(LOG_ERROR, 0, file, line, function, "%.*s", len, buf);
			break;
		case WS_LOG_WARNING:
			__bbs_log(LOG_WARNING, 0, file, line, function, "%.*s", len, buf);
			break;
		case WS_LOG_DEBUG:
		default:
			__bbs_log(LOG_DEBUG, level - WS_LOG_DEBUG + 1, file, line, function, "%.*s", len, buf);
	}
}

struct ws_session {
	struct wss_client *client;	/*!< libwss WebSocket client */
	struct bbs_node *node;		/*!< BBS node */
	struct http_session *http;	/*!< HTTP session */
	pthread_mutex_t lock;		/*!< Session lock for serializing writing */
	void *data;					/*!< Module specific user data */
};

struct ws_route {
	const char *uri;
	int (*on_open)(struct ws_session *ws);
	int (*on_close)(struct ws_session *ws, void *data);
	int (*on_text_message)(struct ws_session *ws, void *data, const char *buf, size_t len);
	RWLIST_ENTRY(ws_route) entry;
	void *mod;
	char data[0];
};

static RWLIST_HEAD_STATIC(routes, ws_route);

int __websocket_route_register(const char *uri, int (on_open)(struct ws_session *ws), int (on_close)(struct ws_session *ws, void *data), int (on_text_message)(struct ws_session *ws, void *data, const char *buf, size_t len), void *mod)
{
	struct ws_route *route;

	RWLIST_WRLOCK(&routes);
	RWLIST_TRAVERSE(&routes, route, entry) {
		if (!strcmp(uri, route->uri)) {
			bbs_error("WebSocket route '%s' already registered\n", route->uri);
			RWLIST_UNLOCK(&routes);
			return -1;
		}
	}
	route = calloc(1, sizeof(*route) + strlen(uri) + 1);
	if (ALLOC_FAILURE(route)) {
		RWLIST_UNLOCK(&routes);
		return -1;
	}
	route->mod = mod;
	route->on_open = on_open;
	route->on_close = on_close;
	route->on_text_message = on_text_message;
	strcpy(route->data, uri); /* Safe */
	route->uri = route->data;

	RWLIST_INSERT_HEAD(&routes, route, entry);
	RWLIST_UNLOCK(&routes);
	return 0;
}

int websocket_route_unregister(const char *uri)
{
	struct ws_route *route;

	RWLIST_WRLOCK(&routes);
	RWLIST_TRAVERSE_SAFE_BEGIN(&routes, route, entry) {
		if (!strcmp(route->uri, uri)) {
			RWLIST_REMOVE_CURRENT(entry);
			free(route);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&routes);
	if (!route) {
		bbs_error("WebSocket route '%s' was not registered?\n", uri);
		return -1;
	}
	return 0;
}

static struct ws_route *find_route(const char *uri)
{
	struct ws_route *route;

	RWLIST_RDLOCK(&routes);
	RWLIST_TRAVERSE(&routes, route, entry) {
		if (!strcmp(uri, route->uri)) {
			break;
		}
	}
	if (route) {
		bbs_module_ref(route->mod);
	}
	RWLIST_UNLOCK(&routes);
	return route;
}

void websocket_attach_user_data(struct ws_session *ws, void *data)
{
	ws->data = data;
}

void websocket_sendtext(struct ws_session *ws, const char *buf, size_t len)
{
	pthread_mutex_lock(&ws->lock);
	wss_write(ws->client, WS_OPCODE_TEXT, buf, len);
	pthread_mutex_unlock(&ws->lock);
}

/*! \note The details of the underlying WebSocket library are intentionally abstracted away here.
 * WebSocket applications just deal with the net_ws module, the net_ws module deals with
 * the WebSocket library that actually speaks the WebSocket protocol on the wire. */
static void ws_handler(struct bbs_node *node, struct http_session *http, int rfd, int wfd)
{
	struct ws_session ws;
	struct ws_route *route;
	struct wss_client *client;
	int res;
	int want_ping = 0;
	char ping_data[15];
	//struct pollfd pfd;

	/* no memset needed, directly initialize all values */
	ws.node = node;
	ws.http = http;
	ws.data = NULL;

	bbs_verb(5, "Handling WebSocket client on node %d to %s\n", node->id, http->req->uri);

	route = find_route(http->req->uri);
	if (!route) {
		bbs_warning("Rejecting WebSocket connection for '%s' (no such WebSocket route)\n", http->req->uri);
		return; /* Get lost, dude */
	}

	client = wss_client_new(&ws, rfd, wfd);
	if (!client) {
		bbs_error("Failed to create WebSocket client\n");
		return;
	}
	ws.client = client; /* Needed as part of structure so it can be accessed in websocket_sendtext */

	pthread_mutex_init(&ws.lock, NULL);

	if (route->on_open && route->on_open(&ws)) {
		return;
	}

	for (;;) {
		/*! \todo IMAP: poll imap client fd, as well as websocket client fd - could use readline on the IMAP side. */
		res = wss_read(client, SEC_MS(55), 0);
		if (res < 0) {
			bbs_debug(3, "Failed to read WebSocket frame\n");
			if (wss_error_code(client)) {
				wss_close(client, wss_error_code(client));
			} else {
				wss_close(client, WS_CLOSE_PROTOCOL_ERROR);
			}
			break;
		} else if (!res) {
			int framelen;
			/* Send a ping if we haven't heard anything in a while */
			if (++want_ping > 1) {
				/* Already had a ping outstanding that wasn't ponged. Disconnect. */
				bbs_debug(3, "Still haven't received ping reply, disconnecting client\n");
				break;
			}
			/* Use current timestamp as our ping data */
			framelen = snprintf(ping_data, sizeof(ping_data), "%ld", time(NULL));
			wss_write(client, WS_OPCODE_PING, ping_data, (size_t) framelen);
		} else {
			struct wss_frame *frame = wss_client_frame(client);
			bbs_debug(1, "WebSocket '%s' frame received\n", wss_frame_name(frame));
			switch (wss_frame_opcode(frame)) {
				case WS_OPCODE_TEXT:
					if (route->on_text_message && route->on_text_message(&ws, ws.data, wss_frame_payload(frame), wss_frame_payload_length(frame))) {
						wss_frame_destroy(frame);
						goto done; /* Can't break out of loop from within switch */
					}
					break;
				case WS_OPCODE_BINARY:
					/* Do something... */
					bbs_warning("Ignoring received binary frame\n");
					break;
				case WS_OPCODE_CLOSE:
					/* Close the connection and break */
					bbs_debug(2, "Client closed WebSocket connection (code %d)\n", wss_close_code(frame));
					wss_close(client, WS_CLOSE_NORMAL);
					wss_frame_destroy(frame);
					goto done; /* Can't break out of loop from within switch */
				case WS_OPCODE_PING:
					/* Reply in kind with a pong containing the same payload */
					wss_write(client, WS_OPCODE_PONG, wss_frame_payload(frame), wss_frame_payload_length(frame));
					break;
				case WS_OPCODE_PONG:
					/* Confirm receipt of a previous ping, or ignore if unexpected */
					if (wss_frame_payload_length(frame) && !strcmp(ping_data, wss_frame_payload(frame))) {
						want_ping = 0;
					} else {
						bbs_debug(5, "Ignoring unexpected PONG\n");
					}
					break;
				default:
					bbs_warning("Unexpected WS opcode %d?\n", wss_frame_opcode(frame));
			}
			wss_frame_destroy(frame);
		}
	}

done:
	if (client) {
		if (route->on_close) {
			route->on_close(&ws, ws.data);
		}
		wss_client_destroy(client);
		pthread_mutex_destroy(&ws.lock);
	}
	bbs_module_unref(route->mod);
}

static void ws_direct_handler(struct bbs_node *node, int secure)
{
	SSL *ssl = NULL;
	int res;

	/* needed for HTTP structure */
	char buf[1024];
	struct readline_data rldata;
	struct http_session http;

	memset(&http, 0, sizeof(http));
	http.node = node;
	http.rldata = &rldata;
	http.req = &http.reqstack;
	http.res = &http.resstack;
	SET_BITFIELD(http.secure, secure);

	/* Start TLS if we need to */
	if (secure) {
		ssl = ssl_new_accept(node->fd, &http.rfd, &http.wfd);
		if (!ssl) {
			return; /* Disconnect. */
		}
	} else {
		http.rfd = http.wfd = node->fd;
	}

	/* If this is a direct connection, either the client connected directly to us,
	 * or we went through a reverse proxy, which is going to relay the headers forward to us.
	 * Either way, we still need to perform the websocket handshake (most likely upgrading from HTTP 1.1).
	 * Read the headers and pay attention only to the ones that we care about. */

	/* XXX How do we know this is actually an HTTP request coming in, in the first place, not a direct WS connection from the get go? */

	bbs_readline_init(&rldata, buf, sizeof(buf));
	res = http_parse_request(&http, buf); /* This will, among other things, load any cookies in the request, so we can identify the client. */
	if (res) {
		goto cleanup; /* Just disconnect, don't even bother sending a response */
	}

	bbs_debug(4, "Ready to begin WebSocket handshake\n");
	if (!http_websocket_upgrade_requested(&http)) {
		bbs_debug(3, "Not a WebSocket client?\n"); /* Probably just rando TCP traffic hitting this port. Drop it. */
		goto cleanup;
	} else if (http_websocket_handshake(&http)) {
		goto cleanup; /* WebSocket handshake failed */
	}

	/* Handshake succeeded! Okay, we're done with the HTTP stuff now. It's just websockets from here on out. */
	ws_handler(node, &http, http.rfd, http.wfd);

cleanup:
	if (ssl) {
		ssl_close(ssl);
		ssl = NULL;
	}
}

static enum http_response_code ws_proxy_handler(struct http_session *http)
{
	/* If this is a reverse proxied connection through the web server, upgrade it first,
	 * then hand it off to the websocket server. */
	if (!http_websocket_upgrade_requested(http) || http_websocket_handshake(http)) {
		return HTTP_BAD_REQUEST;
	}
	/* This is now a websocket connection, speaking the websocket protocol. */
	ws_handler(http->node, http, http->rfd, http->wfd);
	/* Return back to the web server, which will simply terminate the connection */
	return http->res->code;
}

static void *__ws_handler(void *varg)
{
	struct bbs_node *node = varg;

	node->thread = pthread_self();
	bbs_node_begin(node);

	ws_direct_handler(node, !strcmp(node->protname, "WSS"));

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_http.conf", 0);
	if (cfg) {
		int http_enabled = 0, https_enabled = 0;
		bbs_config_val_set_true(cfg, "http", "enabled", &http_enabled);
		if (http_enabled) {
			bbs_config_val_set_port(cfg, "http", "port", &http_port);
		}
		bbs_config_val_set_true(cfg, "https", "enabled", &https_enabled);
		if (https_enabled) {
			bbs_config_val_set_port(cfg, "https", "port", &https_port);
		}
	}
	cfg = bbs_config_load("net_ws.conf", 0);
	if (cfg) {
		bbs_config_val_set_port(cfg, "ws", "port", &ws_port);
		bbs_config_val_set_port(cfg, "wss", "port", &wss_port);
	}
	return 0;
}

static int unload_module(void)
{
	http_unregister_route(ws_proxy_handler);
	if (ws_port) {
		bbs_stop_tcp_listener(ws_port);
	}
	if (wss_port) {
		bbs_stop_tcp_listener(wss_port);
	}
	return 0;
}

static int load_module(void)
{
	int res = 0;
	if (load_config()) {
		return -1;
	}
	wss_set_logger(ws_log);
	wss_set_log_level(WS_LOG_DEBUG + 5);
	/* Register reverse proxy routes if needed */

	/* XXX Need to register all routes? */
	if (http_port) {
		res |= http_register_insecure_route("/ws", (unsigned short int) http_port, NULL, HTTP_METHOD_GET, ws_proxy_handler);
	}
	if (https_port) {
		res |= http_register_secure_route("/ws", (unsigned short int) http_port, NULL, HTTP_METHOD_GET, ws_proxy_handler);
	}
	if (res) {
		return unload_module();
	}
	/* Register listener(s) to accept WebSocket connections directly, e.g. from another reverse proxy (e.g. Apache HTTP server) */
	res = bbs_start_tcp_listener3(ws_port ? ws_port : 0, wss_port ? wss_port : 0, 0, "WS", "WSS", NULL, __ws_handler);
	return res ? unload_module() : res;
}

BBS_MODULE_INFO_FLAGS_DEPENDENT("WebSocket Server", MODFLAG_GLOBAL_SYMBOLS, "mod_http.so");
