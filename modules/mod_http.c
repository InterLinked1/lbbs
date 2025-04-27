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
 * \brief Hypertext Transfer Protocol (HTTP 1.1) Web Server
 *
 * \note Supports both HTTP and RFC 2818 Secure HTTP (HTTPS)
 * \note Supports RFC 3875 Common Gateway Interface
 * \note Supports RFC 7233 Range requests
 * \note Supports RFC 7235, 7617 Basic Authentication
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <poll.h>
#include <sys/socket.h>
#include <signal.h>
#include <magic.h>
#include <sys/wait.h>
#include <limits.h> /* use PATH_MAX */

#include "include/module.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/system.h"
#include "include/linkedlists.h"
#include "include/variables.h"
#include "include/base64.h"
#include "include/hash.h"
#include "include/crypt.h"
#include "include/event.h"
#include "include/cli.h"
#include "include/callback.h"

#include "include/mod_http.h"

#define SERVER_NAME BBS_TAGLINE " " BBS_VERSION " Web Server"

#define DEFAULT_MIME_TYPE "application/octet-stream"

#define STRPTIME_FMT "%a, %d %b %Y %T %Z"
#define STRFTIME_FMT "%a, %d %b %Y %T %Z"

#define MAX_REQUEST_HEADERS 100
#define MAX_REQUEST_HEADER_LENGTH 2048
#define MAX_URI_LENGTH 1024
#define MAX_HTTP_REQUEST_SIZE 8192
#define MAX_HTTP_UPLOAD_SIZE SIZE_MB(20)

#define http_debug(level, fmt, ...) bbs_debug(level, fmt, ## __VA_ARGS__)

const char *http_method_name(enum http_method method)
{
	switch (method) {
		case HTTP_METHOD_OPTIONS:
			return "OPTIONS";
		case HTTP_METHOD_HEAD:
			return "HEAD";
		case HTTP_METHOD_GET:
			return "GET";
		case HTTP_METHOD_POST:
			return "POST";
		case HTTP_METHOD_PUT:
			return "PUT";
		case HTTP_METHOD_DELETE:
			return "DELETE";
		case HTTP_METHOD_TRACE:
			return "TRACE";
		case HTTP_METHOD_CONNECT:
			return "CONNECT";
		case HTTP_METHOD_UNDEF:
		default:
			return NULL;
	}
}

struct http_route {
	const char *prefix;
	const char *hostname;
	unsigned short int port;
	enum http_method methods;
	enum http_response_code (*handler)(struct http_session *http);
	void *mod;	/*!< Registering module */
	size_t prefixlen; /*!< Length of prefix */
	unsigned int usecount;
	unsigned int secure:1;
	bbs_mutex_t lock;
	RWLIST_ENTRY(http_route) entry;
	char data[];
};

struct http_listener {
	unsigned short int port;
	unsigned int usecount;
	unsigned int secure:1;
	RWLIST_ENTRY(http_listener) entry;
};

#define SESSION_ID_LENGTH 48

struct session {
	char sessid[SESSION_ID_LENGTH + 1];	/*!< Session ID (may change) */
	struct bbs_vars vars;				/*!< Session variables */
	time_t created;						/*!< Session creation time */
	RWLIST_ENTRY(session) entry;		/*!< Next session */
	unsigned int usecount;				/*!< Number of clients using this session */
	unsigned int secure:1;				/*!< Session only used securely? */
};

static RWLIST_HEAD_STATIC(listeners, http_listener);
static RWLIST_HEAD_STATIC(routes, http_route);
static RWLIST_HEAD_STATIC(sessions, session);

BBS_SINGULAR_CALLBACK_DECLARE(proxy_handler, enum http_response_code, struct http_session *http);
/* Extra information for the callback that isn't handled by the regular singular callback interface: */
static unsigned short int proxy_port = 0;
static enum http_method proxy_methods = HTTP_METHOD_UNDEF;

/* == HTTP output I/O wrappers == */

/*! \brief Actually write data to the HTTP client (potentially abstracted by TLS) */
static ssize_t __http_direct_write(struct http_session *http, const char *buf, size_t len)
{
	return bbs_node_fd_write(http->node, http->node->wfd, buf, len);
}

/*! \brief sendfile wrapper for HTTP clients */
static inline ssize_t http_sendfile(struct http_session *http, int in_fd, off_t *offset, size_t count)
{
	return bbs_sendfile(http->node->wfd, in_fd, offset, count);
}

static ssize_t __attribute__ ((format (gnu_printf, 2, 3))) __http_direct_writef(struct http_session *http, const char *fmt, ...)
{
	char sbuf[2048];
	char *buf = NULL;
	int dynamic = 0;
	int len;
	ssize_t res;
	va_list ap;

	/* Try using a stack allocated buffer first, since most of the time, it will fit */
	va_start(ap, fmt);
	len = vsnprintf(sbuf, sizeof(sbuf), fmt, ap);
	va_end(ap);

	if ((size_t) len >= sizeof(sbuf) - 1) {
		/* Truncation occured */
		va_start(ap, fmt);
		len = vasprintf(&buf, fmt, ap);
		va_end(ap);
		if (len < 0) {
			return -1;
		}
		dynamic = 1;
	} else {
		buf = sbuf;
	}

	res = __http_direct_write(http, buf, (size_t) len);
	if (dynamic) {
		free(buf);
	}
	return res;
}

/* == End output I/O wrappers == */

/* Statement expression to return nonzero on I/O failure */
#define http_send_header(http, fmt, ...) ({ \
	int _x = 0; \
	http_debug(5, "<= " fmt, ## __VA_ARGS__); \
	if (__http_direct_writef(http, fmt, ## __VA_ARGS__) < 0) { \
		_x = -1; \
	} \
	_x; \
})

#define HTTP_SEND_HEADER(http, fmt, ...) if (http_send_header(http, fmt, ## __VA_ARGS__)) { return -1; }

static const char *http_response_code_name(enum http_response_code code)
{
	switch (code) {
		case HTTP_CONTINUE: return "Continue";
		case HTTP_SWITCHING_PROTOCOLS: return "Switching Protocols";
		case HTTP_OK: return "OK";
		case HTTP_CREATED: return "Created";
		case HTTP_NO_CONTENT: return "No Content";
		case HTTP_PARTIAL_CONTENT: return "Partial Content";
		case HTTP_REDIRECT_PERMANENT: return "Moved Permanently";
		case HTTP_REDIRECT_FOUND: return "Found";
		case HTTP_NOT_MODIFIED_SINCE: return "Not Modified";
		case HTTP_REDIRECT_TEMPORARY: return "Temporary Redirect";
		case HTTP_BAD_REQUEST: return "Bad Request";
		case HTTP_UNAUTHORIZED: return "Unauthorized";
		case HTTP_FORBIDDEN: return "Forbidden";
		case HTTP_NOT_FOUND: return "Not Found";
		case HTTP_NOT_ALLOWED: return "Not Allowed";
		case HTTP_REQUEST_TIMEOUT: return "Request Timeout";
		case HTTP_GONE: return "Gone";
		case HTTP_CONTENT_TOO_LARGE: return "Content Too Large";
		case HTTP_URI_TOO_LONG: return "URI Too Long";
		case HTTP_RANGE_UNAVAILABLE: return "Range Not Satisfiable";
		case HTTP_EXPECTATION_FAILED: return "Expectation Failed";
		case HTTP_IM_A_TEAPOT: return "I'm a teapot";
		case HTTP_TOO_MANY_REQUESTS: return "Too Many Requests";
		case HTTP_REQUEST_HEADERS_TOO_LARGE: return "Request Header Fields Too Large";
		case HTTP_INTERNAL_SERVER_ERROR: return "Internal Server Error";
		case HTTP_NOT_IMPLEMENTED: return "Not Implemented";
		case HTTP_BAD_GATEWAY: return "Bad Gateway";
		case HTTP_SERVICE_UNAVAILABLE: return "Service Unavailable";
		case HTTP_GATEWAY_TIMEOUT: return "Gateway Timeout";
		case HTTP_VERSION_NOT_SUPPORTED: return "Version Not Supported";
		/* No default */
	}
	return "";
}

void http_send_response_status(struct http_session *http, enum http_response_code code)
{
	bbs_assert(!http->res->sentheaders);
	http->res->sentheaders = 1;
	http_send_header(http, "HTTP/1.1 %u %s\r\n", code, http_response_code_name(code));
}

static int http_send_headers(struct http_session *http)
{
	const char *key;
	char *value;
	enum http_response_code code = http->res->code ? http->res->code : HTTP_OK;

	http_send_response_status(http, code);

	/* Note: Headers sent here via http_send_header are not intended to be set by applications,
	 * since they would be duped in the header list, and not override what is sent here. */
	HTTP_SEND_HEADER(http, "Server: %s\r\n", SERVER_NAME);

	if (http->req->method & HTTP_VERSION_1_1_OR_NEWER) {
		struct tm tm;
		time_t now;
		char datestr[30];
		now = time(NULL);
		localtime_r(&now, &tm);
		strftime(datestr, sizeof(datestr), "%a, %d %b %Y %T %Z", &tm);
		HTTP_SEND_HEADER(http, "Date: %s\r\n", datestr);
	}

	if (http->res->contentlength) {
		HTTP_SEND_HEADER(http, "Content-Length: %lu\r\n", http->res->contentlength);
		http->res->chunked = 0;
	} else if (http->res->chunked) {
		HTTP_SEND_HEADER(http, "Transfer-Encoding: chunked\r\n");
#if 0
	/* Not needed, as it's legitimate to have 0-length bodies.
	 * Applications will disable keepalive if needed. */
	} else {
		/* A Content-Length was not sent in advance,
		 * and we're not using chunked transfer encoding,
		 * so the client won't have any other way of knowing when the response is completed.
		 * We'll have to close the connection to indicate so, i.e. this connection is now "dirty". */
		if (http->req->keepalive) {
			bbs_debug(6, "Cannot keep this connection alive, not chunked and length not known in advance\n");
			http->req->keepalive = 0;
		}
#endif
	}

	/* Include Connection header, except for websocket upgrades, which already have one */
	if ((http->req->method & HTTP_VERSION_1_1_OR_NEWER) && http->res->code != HTTP_SWITCHING_PROTOCOLS) {
		HTTP_SEND_HEADER(http, "Connection: %s\r\n", http->req->keepalive ? "keep-alive" : "close");
	}

	if (http->req->keepalive) {
		HTTP_SEND_HEADER(http, "Keep-Alive: timeout=%d, max=%d\r\n", 1, 1000);
	}

	/* variables are tail inserted, so iterating from the head is appropriate and preserves order */
	while ((key = bbs_vars_peek_head(&http->res->headers, &value))) {
		HTTP_SEND_HEADER(http, "%s: %s\r\n", key, value);
		bbs_vars_remove_first(&http->res->headers);
	}
	NODE_SWRITE(http->node, http->node->wfd, "\r\n"); /* CR LF to indicate end of headers */
	return 0;
}

int http_set_header(struct http_session *http, const char *header, const char *value)
{
	return bbs_varlist_append(&http->res->headers, header, value); /* Add or replace header */
}

enum http_response_code http_redirect_https(struct http_session *http, int port)
{
	char full_url[PATH_MAX];
	char host[256];

	/* This function must not be called if we're already secure, or we'll just end up in a loop, redirecting to ourself. */
	bbs_assert(!http->secure);

	/* The current host might already include a port, so strip it if so */
	safe_strncpy(host, S_OR(http->req->host, bbs_hostname()), sizeof(host));
	bbs_strterm(host, ':');
	if (port != 443) {
		snprintf(full_url, sizeof(full_url), "https://%s:%d%s", host, port, http->req->uri);
	} else {
		snprintf(full_url, sizeof(full_url), "https://%s%s", host, http->req->uri);
	}
	http_redirect(http, HTTP_REDIRECT_PERMANENT, full_url);
	return HTTP_REDIRECT_PERMANENT;
}

void http_enable_hsts(struct http_session *http, unsigned int maxage)
{
	char buf[256];
	snprintf(buf, sizeof(buf), "max-age=%u; includeSubDomains; preload", maxage);
	http_set_header(http, "Strict-Transport-Security", buf);
}

int http_redirect(struct http_session *http, enum http_response_code code, const char *location)
{
	switch (code) {
		case HTTP_REDIRECT_PERMANENT:
		case HTTP_REDIRECT_FOUND:
		case HTTP_REDIRECT_TEMPORARY:
			break;
		default:
			bbs_warning("Invalid redirect response code (%u)\n", code);
			return -1;
	}
	http->res->code = code;
	if (location) {
		http_set_header(http, "Location", location);
	}
	return 0;
}

static int __http_write(struct http_session *http, const char *buf, size_t len)
{
	/* If headers have not yet been sent yet, send em */
	if (!http->res->sentheaders && http_send_headers(http)) {
		return -1;
	}

	if (__http_direct_write(http, buf, len) < 0) {
		return -1;
	}
	http->res->sentbytes += len;
	return 0;
}

static int send_chunk(struct http_session *http, const char *buf, size_t len)
{
	/* If headers have not yet been sent yet, send em */
	if (!http->res->sentheaders && http_send_headers(http)) {
		return -1;
	}

	HTTP_SEND_HEADER(http, "%x\r\n", (unsigned int) len); /* Doesn't count towards body length, so don't use __http_write */
	if (__http_write(http, buf, len)) {
		return -1;
	}
	return __http_direct_write(http, "\r\n", STRLEN("\r\n")) < 0 ? -1 : 0; /* Doesn't count towards length */
}

static void flush_buffer(struct http_session *http, int final)
{
	if (!http->res->chunkedbytes) {
#ifdef DEBUG_HTTP_WRITE
		http_debug(9, "Nothing in buffer to flush\n");
#endif
		return; /* Nothing to flush */
	}

	if (final && !http->res->contentlength && !http->res->sentheaders && !http->res->sentbytes) {
		/* The entire response got chunked in the buffer (for small pages less than the buffer size).
		 * Rather than actually using chunked transfer encoding,
		 * since we now know the length of the response (even though we didn't initially),
		 * just send a regular response with a content length */
		bbs_debug(5, "Chunked transfer not needed, full length now known to be %lu\n", http->res->chunkedbytes);
		http->res->contentlength = http->res->chunkedbytes;
		http->res->chunked = 0;
		__http_write(http, http->res->chunkbuf, http->res->chunkedbytes);
		return;
	}

	if (!http->res->chunked) {
#ifdef DEBUG_HTTP_WRITE
		http_debug(9, "Response not chunked, nothing to flush\n");
#endif
		return; /* Not a chunked transfer */
	}

#ifdef DEBUG_HTTP_WRITE
	http_debug(9, "Flushing out %lu bytes\n", http->res->chunkedbytes);
#endif

	/* Send chunk */
	send_chunk(http, http->res->chunkbuf, http->res->chunkedbytes);
	/* Reset */
	http->res->chunkedleft = sizeof(http->res->chunkbuf);
	http->res->chunkedbytes = 0;
	if (final) {
		__http_direct_write(http, "0\r\n", STRLEN("0\r\n")); /* This is the beginning of the end. Optional footers may follow. */
		/* If we wanted to send optional footers, we could do so here. But we don't. */
		__http_direct_write(http, "\r\n", STRLEN("\r\n")); /* Very end of chunked transfer */
	}
}

void http_write(struct http_session *http, const char *buf, size_t len)
{
	if (!http->res->chunked) {
		/* Not chunked, just flush out immediately. */
#ifdef DEBUG_HTTP_WRITE
		http_debug(9, "Flushing out %lu bytes immediately\n", len);
#endif
		__http_write(http, buf, len);
		return;
	}

	/* Chunked transfer, buffer it and send it in chunks, automatically. */
	if (len > http->res->chunkedleft) {
		if (http->res->chunkedbytes) {
			/* Not enough room. Flush the buffer first. */
			flush_buffer(http, 0);
		}
		if (len > http->res->chunkedleft) {
			/* Still not enough room, this chunk is larger than the entire buffer! Flush it out immediately. */
			bbs_debug(4, "Chunk length %lu exceeds buffer size %lu!\n", len, http->res->chunkedleft);
			send_chunk(http, buf, len);
			return;
		}
	}

	/* There is room in the buffer. Stash it there for now. */
#ifdef DEBUG_HTTP_WRITE
	http_debug(9, "Buffering %lu bytes\n", len);
#endif
	memcpy(http->res->chunkbuf + http->res->chunkedbytes, buf, len);
	http->res->chunkedbytes += len;
	http->res->chunkedleft -= len;
}

int http_writef(struct http_session *http, const char *fmt, ...)
{
	char *buf;
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len == -1) {
		return -1;
	}

	http_write(http, buf, (size_t) len);
	free(buf);
	return len;
}

const char *http_version_name(enum http_version version)
{
	switch (version) {
		case HTTP_VERSION_0_9:
			return "HTTP/0.9";
		case HTTP_VERSION_1_0:
			return "HTTP/1.0";
		case HTTP_VERSION_1_1:
			return "HTTP/1.1";
		case HTTP_VERSION_2:
			return "HTTP/2";
		case HTTP_VERSION_3:
			return "HTTP/3";
		default:
			return "";
	}
}

static void log_response(struct http_session *http)
{
	const char *referer = http_request_header(http, "Referer");
	const char *useragent = http_request_header(http, "User-Agent");
	/*! \todo XXX Also log to a dedicated log file */
	bbs_debug(3, "\"%s %s %s\" %d %lu \"%s\" \"%s\"\n",
		http_method_name(http->req->method), http->req->uri, http_version_name(http->req->version),
		http->res->code, http->res->sentbytes, S_IF(referer), S_IF(useragent));
}

static int builtin_response(struct http_session *http)
{
	const char *title = NULL, *description = NULL;

	title = http_response_code_name(http->res->code);

	switch (http->res->code) {
		/* Some verbiage borrowed from Apache HTTP server: https://github.com/apache/httpd/tree/trunk/docs/error */
		case HTTP_NOT_MODIFIED_SINCE:
			break; /* No need for a body */
		case HTTP_BAD_REQUEST:
			description = "Your browser sent a request the server could not understand.";
			break;
		case HTTP_UNAUTHORIZED:
			description = "Additional authentication required to access this resource.";
			break;
		case HTTP_FORBIDDEN:
			description = "You don't have permission to access this resource.";
			break;
		case HTTP_NOT_FOUND:
			description = "The requested URL was not found on this server.";
			break;
		case HTTP_NOT_ALLOWED:
			description = "Method not allowed for the requested URL.";
			break;
		case HTTP_CONTENT_TOO_LARGE:
			description = "The data volume exceeds the capacity limit.";
			break;
		case HTTP_INTERNAL_SERVER_ERROR:
			description = "The server encountered an internal error and was unable to complete your request.";
			break;
		case HTTP_NOT_IMPLEMENTED:
			description = "The server does not support the action requested by the browser.";
			break;
		case HTTP_VERSION_NOT_SUPPORTED:
			description = "The server does not support the HTTP version of your browser.";
			break;
		default:
			return -1;
	}

	if (title && description) {
		http_set_header(http, "Content-Type", "text/html");
	}

	if (http->res->code == HTTP_UNAUTHORIZED && !http->req->username) {
		/* If not already authenticated, ask the user to */
		bbs_debug(3, "Asking for additional authorization\n");
		http_set_header(http, "WWW-Authenticate", "Basic realm=\"bbs\"");
	}

	/* Headers are automatically sent if needed when we try to write, e.g. http_writef */
	if (title && description) {
		http_writef(http, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n");
		http_writef(http, "<html><head><title>%d %s</title></head>\r\n", http->res->code, title);
		http_writef(http, "<h1>%s</h1>\r\n", title);
		http_writef(http, "<p>%s</p>\r\n", description);
		http_writef(http, "<hr><address>%s</address></body></html>", SERVER_NAME);
	}
	return 0;
}

static void postfield_free(struct post_field *p)
{
	free_if(p->buffer);
	if (p->filename) {
		unlink(p->tmpfile);
	}
	free(p);
}

static void session_free(struct session *sess)
{
	/* It's assumed that all clients have been kicked at this point
	 * and are not using the session. */
	bbs_vars_destroy(&sess->vars);
	free(sess);
}

static void session_decref(struct session *sess)
{
	RWLIST_WRLOCK(&sessions);
	--sess->usecount;
	/* Don't remove it if the use count hits 0 (think about it: that would be stupid) */
	RWLIST_UNLOCK(&sessions);
}

static void http_request_cleanup(struct http_request *req)
{
	free_if(req->uri);
	free_if(req->urihost);
	free_if(req->username);
	bbs_vars_destroy(&req->headers); /* In case headers were never sent? */
	bbs_vars_destroy(&req->cookies);
	bbs_vars_destroy(&req->queryparams);
	if (req->session) {
		session_decref(req->session);
	}
	RWLIST_REMOVE_ALL(&req->postfields, entry, postfield_free);
	RWLIST_HEAD_DESTROY(&req->postfields);
	free_if(req->body);
}

static void http_response_cleanup(struct http_response *res)
{
	bbs_vars_destroy(&res->headers);
}

void http_session_cleanup(struct http_session *http)
{
	http_request_cleanup(http->req);
	http_response_cleanup(http->res);
}

static int parse_request_line(struct http_session *restrict http, char *s)
{
	char *tmp;

	tmp = strsep(&s, " ");

	if (strlen_zero(tmp)) {
		return HTTP_BAD_REQUEST;
	}

	/* HTTP method (case-sensitive) */
	if (!strcmp(tmp, "GET")) {
		http->req->method = HTTP_METHOD_GET; /* Most common first */
	} else if (!strcmp(tmp, "HEAD")) {
		http->req->method = HTTP_METHOD_HEAD;
	} else if (!strcmp(tmp, "OPTIONS")) {
		http->req->method = HTTP_METHOD_OPTIONS;
	} else if (!strcmp(tmp, "POST")) {
		http->req->method = HTTP_METHOD_POST;
	} else if (!strcmp(tmp, "PUT")) {
		http->req->method = HTTP_METHOD_PUT;
	} else if (!strcmp(tmp, "DELETE")) {
		http->req->method = HTTP_METHOD_DELETE;
	} else if (!strcmp(tmp, "TRACE")) {
		http->req->method = HTTP_METHOD_TRACE;
	} else if (!strcmp(tmp, "CONNECT")) {
		http->req->method = HTTP_METHOD_CONNECT;
	} else {
		bbs_warning("Unknown HTTP request method: %s\n", bbs_str_isprint(tmp) ? tmp : "(non-printable)");
		return HTTP_NOT_IMPLEMENTED;
	}

	/* Request URI */
	tmp = strsep(&s, " ");
	if (strlen_zero(tmp)) {
		return HTTP_BAD_REQUEST;
	}
	if (!strstr(tmp, "://")) {
		if (strlen(tmp) > MAX_URI_LENGTH) {
			return HTTP_URI_TOO_LONG;
		}
		http->req->uri = strdup(tmp);
		http->req->querystring = strchr(http->req->uri, '?');
		if (http->req->querystring) {
			http->req->querystring++;
		}
	} else {
		char *uri;
		/* Ooh, an absolute URL. Uncommon but could happen.
		 * (One common use case is with HTTP proxying.)
		 * Parse out the hostname and the URI from this. */
		if (STARTS_WITH(tmp, "http://")) {
			tmp += STRLEN("http://");
		} else if (STARTS_WITH(tmp, "https://")) {
			tmp += STRLEN("https://");
		} else {
			bbs_warning("Unsupported protocol in request: %s\n", tmp);
			return HTTP_BAD_REQUEST;
		}
		if (!*tmp) {
			return HTTP_BAD_REQUEST;
		}
		uri = strchr(tmp, '/');
		if (!uri) {
			return HTTP_BAD_REQUEST;
		}
		http->req->uri = strdup(uri);
		*uri = '\0';
		http->req->urihost = strdup(tmp);
		http->req->host = http->req->urihost;
		http->req->absolute = 1;
	}
	if (ALLOC_FAILURE(http->req->uri)) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* HTTP version (case-sensitive) */
	if (strlen_zero(s)) {
		return HTTP_BAD_REQUEST;
	}
	if (!strcmp(s, "HTTP/1.1")) {
		http->req->version = HTTP_VERSION_1_1;
	} else if (!strcmp(s, "HTTP/1.0")) {
		http->req->version = HTTP_VERSION_1_0;
	} else if (!strcmp(s, "HTTP/2")) {
		http->req->version = HTTP_VERSION_2;
	} else if (!strcmp(s, "HTTP/3")) {
		http->req->version = HTTP_VERSION_3;
	} else if (!strcmp(s, "HTTP/0.9")) {
		http->req->version = HTTP_VERSION_0_9;
	} else {
		return HTTP_VERSION_NOT_SUPPORTED;
	}

	return 0;
}

static int process_headers(struct http_session *http)
{
	const char *value;

	/* Host header */
	value = http_request_header(http, "Host");
	if (value) {
		const char *portstr = strchr(value, ':');
		http->req->host = value;
		if (portstr) {
			portstr++;
			if (strlen_zero(portstr)) {
				bbs_warning("Malformed host: %s\n", value);
			} else {
				http->req->hostport = (unsigned int) atoi(portstr);
				if (http->req->hostport != http->node->port && !(http->req->method & HTTP_METHOD_CONNECT) && !http->req->absolute) {
					/* For proxy connections, the port could be anything arbitrary,
					 * but otherwise, it's not legitimate and we should reject it. */
					bbs_warning("Host port %u does not match actual port %u\n", http->req->hostport, http->node->port);
					return HTTP_BAD_REQUEST;
				}
			}
		}
	} else {
		if (http->req->method & HTTP_VERSION_1_1) {
			/* The Host request header is mandatory in HTTP 1.1. */
			bbs_warning("HTTP 1.1 client missing Host header\n");
			return HTTP_BAD_REQUEST;
		}
	}

	/* Keep alive */
	if (http->req->method & HTTP_VERSION_1_1_OR_NEWER) {
		value = http_request_header(http, "Connection");
		if (value) {
			http->req->keepalive = !strcasecmp(value, "close") || !strcasecmp(value, "retry-after") ? 0 : 1;
		} else {
			http->req->keepalive = 1; /* If header not present, it's enabled by default */
		}
		/* We will try to buffer responses so we can take advantage of keep alive. */
		http->res->chunked = http->req->keepalive;
	} else {
		http->req->keepalive = 0;
	}

	/* Expect */
	value = http_request_header(http, "Expect");
	if (value) {
		http->req->expect100 = strstr(value, "100-continue") ? 1 : 0;
	}

	/* Upgrade Insecure */
	value = http_request_header(http, "Upgrade-Insecure-Requests");
	if (value && atoi(value) == 1) {
		SET_BITFIELD(http->req->httpsupgrade, atoi(value));
	}

	/* Content-Length */
	value = http_request_header(http, "Content-Length");
	if (value) {
		http->req->contentlength = (size_t) atol(value);
	}

	/* Transfer-Encoding */
	value = http_request_header(http, "Transfer-Encoding");
	if (value) {
		if (!strcasecmp(value, "chunked")) {
			http->req->chunked = 1;
		} else if (!strcasecmp(value, "identity")) {
			/* Default */
		} else {
			bbs_warning("Unsupported Transfer-Encoding: %s\n", value);
			return HTTP_NOT_IMPLEMENTED; /* RFC 2616, 3.6: respond with 501 for any transfer encodings we don't support */
		}
	}

	/* Authorization */
	value = http_request_header(http, "Authorization");
	if (value) {
		char tmpbuf[256];
		char *tmp, *dup = tmpbuf;
		int outlen;
		safe_strncpy(tmpbuf, value, sizeof(tmpbuf));
		tmp = strsep(&dup, " ");
		if (!strcmp(tmp, "Basic")) {
			unsigned char *decoded = base64_decode((unsigned char*) tmpbuf, (int) strlen(value), &outlen);
			if (decoded) {
				char *username, *password = (char*) decoded;
				username = strsep(&password, ":");

				/* Always set, even if incorrect password, so we know that we attempted Basic Auth */
				REPLACE(http->req->username, username);
				if (bbs_authenticate(http->node, username, password)) {
					bbs_auth("Basic authentication attempt failed for %s\n", username);
				}
				/* Destroy the password before freeing it */
				bbs_memzero(decoded, (size_t) outlen);
				free(decoded);
			}
		}
	}

	/* If-Modified-Since */
	if (http->req->method & (HTTP_METHOD_GET | HTTP_METHOD_OPTIONS)) {
		value = http_request_header(http, "If-Modified-Since");
		if (value) {
			if (strptime(value, STRPTIME_FMT, &http->req->modsince) != NULL) { /* Returns NULL on failure */
				http->req->ifmodsince = 1;
			} else {
				bbs_warning("Failed to parse If-Modified-Since: %s\n", value);
			}
		}
	}

	/* Cookie */
	value = http_request_header(http, "Cookie");
	if (value) {
		char *cookies = strdup(value);
		if (ALLOC_SUCCESS(cookies)) {
			char *cookie, *dup = cookies;
			while ((cookie = strsep(&dup, ";"))) {
				char *name, *val = cookie;
				name = strsep(&val, "=");
				if (strlen_zero(name) || strlen_zero(val)) {
					bbs_warning("Invalid cookie: %s\n", cookie);
					continue;
				}
				STRIP_QUOTES(name);
				STRIP_QUOTES(value);
				ltrim(name); /* If we got multiple cookies, there is a space after the ; */
				bbs_debug(4, "Cookie: %s => %s\n", name, val);
				bbs_varlist_append(&http->req->cookies, name, val);
			}
			free(cookies);
		}
	}

	return 0;
}

int http_is_proxy_request(struct http_session *http)
{
	/* There are two ways that clients establish proxy connections.
	 *
	 * A. The traditional way is to connect to a proxy (often on its own dedicated port)
	 * and simply make the request. The server then replays the request to the target,
	 * and relays the response. Regular methods, e.g. GET, POST, etc. are used.
	 *
	 * B. Another method, specified in RFC 7231 4.3.6, and always used for HTTPS, is to use the CONNECT method
	 * to the proxy server, establish a tunnel to the destination, and then set up
	 * TLS and make the actual HTTP requests on top of that.
	 * A client *could* do this for plain HTTP requests as well, but in practice
	 * most don't, unless you tell them to (e.g. cURL with the -p option, in addition to -x)
	 * Because the client could, theoretically, request connection to any arbitrary TCP port,
	 * servers generally restrict the connection to port 443 (and maybe 80) only.
	 *
	 * A. GET http://example.com/file.html HTTP/1.1
	 * B. CONNECT example.com:443 HTTP/1.1
	 *
	 * We support both, for maximum compatibility. For CONNECT requests, it's obvious
	 * that it's a proxy, but in the first case, it's not as clear cut if we're not
	 * running on a port dedicated for the proxy. There are two telltale signs:
	 * - Using an absolute URL in the request header (e.g. http://example.com).
	 *   This is mandatory for proxy connections, but does not necessarily
	 *   indicate a proxy connection (even if uncommon, otherwise)
	 * - Presence of the Proxy-Connection header. In contrast, this is a sure confirmation,
	 *   but I'm not 100% sure this header will always be present, though it does seem
	 *   fairly reliable, between cURL and browsers, and seems to be the only thing
	 *   that CAN actually identify it as a proxy request.
	 *   Obviously, this header should not be passed forward when replaying the request.
	 */
	return http->req->method & HTTP_METHOD_CONNECT || (http->req->absolute && http_request_header(http, "Proxy-Connection"));
}

int http_websocket_upgrade_requested(struct http_session *http)
{
	const char *value;
	value = http_request_header(http, "Connection");
	if (!strlen_zero(value) && !strcasecmp(value, "Upgrade")) { /* Connection header value is case-insensitive (RFC 7230 6.1) */
		value = http_request_header(http, "Upgrade");
		if (!strlen_zero(value) && !strcasecmp(value, "WebSocket")) {
			return 1;
		}
	}
	return 0;
}

int http_websocket_handshake(struct http_session *http)
{
	/* Set-WebSocket-Accept response is derived from Sec-WebSocket-Key request header */
	const char *versionstr, *key;
	int version;

	if (!(http->req->version & HTTP_VERSION_1_1_OR_NEWER)) {
		bbs_warning("HTTP version incompatible with websockets\n");
		return -1;
	}

	if (!(http->req->method & HTTP_METHOD_GET)) {
		bbs_warning("Websocket upgrades must use GET request\n");
		return -1;
	}

	versionstr = http_request_header(http, "Sec-WebSocket-Version");
	if (!versionstr) {
		bbs_warning("Websocket version not included in client request\n");
		return -1;
	}
	/* Version numbers found here: https://www.iana.org/assignments/websocket/websocket.xhtml#version-number */
	version = atoi(versionstr);
	if (version != 13 && !strstr(versionstr, "13")) { /* In case client specified multiple, e.g. 7, 13 */
		http_set_header(http, "Sec-Websocket-Version", "13"); /* Tell the client what we support */
		return -1;
	}

	key = http_request_header(http, "Sec-WebSocket-Key");
	if (key) { /* This is optional, only if the client wants to */
		char concatenation[256];
		char hash[SHA1_LEN];
		int outlen;
		char *response;
		/* Compute the challenge response to include in our response. */
#define WS_UPGRADE_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" /* RFC 6455 1.3 */
		if (snprintf(concatenation, sizeof(concatenation), "%s%s", key, WS_UPGRADE_GUID) >= (int) sizeof(concatenation)) {
#undef WS_UPGRADE_GUID
			bbs_warning("Buffer truncation during handshake\n"); /* sizeof(concatenation) too small, or malicious request */
			return -1;
		}
		hash_sha1_bytes(concatenation, hash);
		response = base64_encode(hash, SHA1_LEN, &outlen);
		if (!response) {
			bbs_warning("base64 encoding failed\n");
			return -1;
		}
		http_set_header(http, "Sec-WebSocket-Accept", response);
		free(response);
	}

	/* If we got this far, http_websocket_upgrade_requested(http) should be true,
	 * there isn't any need to verify that here. */

	http->res->code = HTTP_SWITCHING_PROTOCOLS;
	http_set_header(http, "Upgrade", "websocket");
	http_set_header(http, "Connection", "Upgrade");

	/* There isn't any data to send for the 101 response. Just flush headers out. */
	http->res->chunked = 0; /* Not a chunked response, turn that off. */
	http->req->keepalive = 0; /* No keep alive */
	http_send_headers(http);

	/* At this point, the application is good to proceed,
	 * e.g. hand the connection off to a websocket server. */
	return 0;
}

static unsigned int atoh(const char *restrict s)
{
	/* There is no actual atoh function in the standard library, apparently? */
	return (unsigned int) strtoul(s, NULL, 16);
}

/*! \retval 0 on success, -1 on failure, 1 on body too large */
static int read_body(struct http_session *http, char *buf, int discard)
{
	/* Parse the body, if any.
	 *
	 * The actual upload (message body) is handled in 2 ways, based on Transfer-Encoding:
	 * - Content-Length
	 * - Chunked transfer encoding. This takes precedence over Content-Length.
	 *
	 * Then, once we have the entity body (decoding from chunked transfer encoding if necessary),
	 * the data is parsed, in 3 possible formats, per the Content-Type/Content-Encoding:
	 * - application/x-www-form-urlencoded
	 * - multipart/form-data
	 * - text/plain
	 *
	 * See also RFC 2616 4.4
	 */

	bbs_assert(!http->req->parsedbody);
	http->req->parsedbody = 1;

	/* XXX I don't really like that we always read the entire POST body into memory first,
	 * even if it's a multipart file upload and we'll store most of it in temp files.
	 * This will not scale for very large uploads. */

	if (http->req->chunked) {
		struct dyn_str dynstr;
		size_t bytes = 0;
		memset(&dynstr, 0, sizeof(dynstr));
		for (;;) {
			/* Determine how large the next chunk is */
			unsigned int chunksize;
			ssize_t res = bbs_node_readline(http->node, http->rldata, "\r\n", SEC_MS(10));
			if (res <= 0) {
				free_if(dynstr.buf);
				bbs_warning("Failed to read all or part of chunked upload?\n");
				return -1;
			}
			chunksize = atoh(buf); /* atoh will stop at the semicolon, if there even is one */
			if (chunksize == 0 && buf[0] == '0') { /* Not just atoh failure, but actually read 0 */
				/* That was the last chunk */
				break;
			}
			if (discard) {
				bbs_readline_discard_n(http->node->rfd, http->rldata, SEC_MS(10), chunksize + 2); /* Read the bytes + trailing CR LF and throw them away */
			} else {
				bbs_readline_getn_dynstr(http->node->rfd, &dynstr, http->rldata, SEC_MS(10), chunksize);
				bytes += (size_t) chunksize;
				if (bytes >= MAX_HTTP_UPLOAD_SIZE) {
					bbs_warning("Partial content length %lu is too large\n", http->req->contentlength);
					free_if(dynstr.buf);
					return 1;
				}
				/* Read and skip the trailing CR and LF after the chunk */
				if (bbs_readline_getn_dynstr(http->node->rfd, &dynstr, http->rldata, SEC_MS(1), 2) != 2) {
					free_if(dynstr.buf);
					return -1;
				}
				if (strcmp(buf, "\r\n")) {
					bbs_warning("Expected CR LF trailer, got 0x%02hhX, 0x%02hhX?\n", (unsigned char) buf[0], (unsigned char) buf[1]);
					free_if(dynstr.buf);
					return -1;
				}
			}
		}

		http->req->contentlength = bytes;
		http->req->body = (unsigned char*) dynstr.buf;

		/* Read and discard any trailer entity-header lines, indicated by a blank line. */
		for (;;) {
			ssize_t res = bbs_node_readline(http->node, http->rldata, "\r\n", SEC_MS(5));
			if (res < 0) {
				return -1; /* At this point, http->req->body is cleaned up on exit so we don't need to free it here */
			} else if (res == 0) {
				break;
			}
		}
	} else if (http->req->contentlength) {
		if (http->req->contentlength > MAX_HTTP_UPLOAD_SIZE) {
			/* Too large */
			bbs_warning("Content length %lu is too large\n", http->req->contentlength);
			return 1;
		}
		if (discard) {
			/* Read the data but don't bother saving it.
			 * We only do this so we can keep the connection alive. Otherwise we'd have to close it if we don't read the entire request. */
			bbs_readline_discard_n(http->node->rfd, http->rldata, SEC_MS(10), http->req->contentlength); /* Read the bytes and throw them away */
		} else {
			http->req->body = (unsigned char*) bbs_readline_getn_str(http->node->rfd, http->rldata, SEC_MS(10), http->req->contentlength);
			if (!http->req->body) {
				return -1;
			}
		}
		/* That was easy. */
	} /* else, there is no body */

	return 0;
}

static int push_post_param(struct http_session *http, const char *name, const char *ctype, const char *filename, unsigned char *buffer, size_t len)
{
	struct post_field *p;
	size_t namelen, ctypelen, filenamelen;

	if (strlen_zero(name)) {
		bbs_warning("%lu-byte POST field missing name\n", len);
		return -1;
	}

	namelen = strlen(name) + 1;
	ctypelen = ctype ? strlen(ctype) + 1 : 0;
	filenamelen = filename ? strlen(filename) + 1 : 0;

	p = calloc(1, sizeof(*p) + namelen + ctypelen + filenamelen);
	if (ALLOC_FAILURE(p)) {
		return -1;
	}

	strcpy(p->data, name); /* Safe */
	p->name = p->data;
	if (filename) {
		strcpy(p->data + namelen, filename);
		p->filename = p->data + namelen;
	}
	if (ctype) {
		strcpy(p->data + namelen + filenamelen, ctype);
		p->type = p->data + namelen + filenamelen;
	}

	p->length = len;

	RWLIST_INSERT_TAIL(&http->req->postfields, p, entry);

	if (filename) {
		int fd;
		/* Write the buffer into a temp file, and save the name of the temp file. */
		strcpy(p->tmpfile, "/tmp/uploadXXXXXX");
		fd = mkstemp(p->tmpfile);
		if (fd < 0) {
			bbs_error("Failed to create temporary file %s: %s\n", p->tmpfile, strerror(errno));
			return -1; /* p will be freed on cleanup */
		}
		bbs_write(fd, (const char*) buffer, len);
		close(fd);
	} else {
		p->buffer = memdup(buffer, len);
		if (ALLOC_FAILURE(p->buffer)) {
			return -1;
		}
	}

	return 0;
}

struct post_field *http_post_param(struct http_session *http, const char *name)
{
	struct post_field *p;
	RWLIST_TRAVERSE(&http->req->postfields, p, entry) {
		if (!strcmp(p->name, name)) {
			break;
		}
	}
	return p;
}

static void parse_url_encoded_params(struct http_session *http, enum http_method method, char *s)
{
	char *param;
	char empty[] = "";
	while ((param = strsep(&s, "&"))) {
		char *key = strsep(&param, "=");
		/* URL decode these in place */
		if (param) {
			bbs_url_decode(param);
		} else {
			param = empty;
		}
		bbs_url_decode(key);
		/* XXX PHP will support repeats (multiple values for the same key)
		 * if the key name ends in []. Perhaps we could do something like that, too? */
		if (method & HTTP_METHOD_GET) {
			bbs_varlist_append(&http->req->queryparams, key, param);
		} else if (method & HTTP_METHOD_POST) {
			push_post_param(http, key, NULL, NULL, (unsigned char*) param, strlen(param) + 1); /* Add NUL */
		}
	}
}

const char *http_query_param(struct http_session *http, const char *name)
{
	return bbs_var_find(&http->req->queryparams, name);
}

static int parse_multipart_part(struct http_session *http, char *s, size_t len)
{
	char *header;
	const char *name = NULL, *filename = NULL, *type = NULL;

	/* Read the headers first. */
	while ((header = strsep(&s, "\r\n"))) {
		char *headername;
		size_t headerlen;
		if (strlen_zero(header)) {
			len -= 1; /* This makes the math work out... strsep weirdness */
			if (len >= 2 && !strncmp(s, "\r\n", 2)) { /* Final CR LF for end of multipart headers. Needed because... strsep weirdness */
				len -= 2;
				s += 2;
			}
			break; /* End of headers, everything that remains is the body. */
		}
		if (!s) {
			bbs_warning("Unexpected end of multipart headers\n");
			return -1;
		}
		headerlen = (size_t) (s - header); /* Faster than strlen, includes CR LF bytes */
		len -= headerlen;
		http_debug(5, "=> %s\n", header);
		headername = strsep(&header, ":");
		if (!header) {
			bbs_warning("%s header is empty\n", headername);
			continue;
		}
		ltrim(header);
		if (!strcasecmp(headername, "Content-Disposition")) {
			char *k, *v;
			if (!STARTS_WITH(header, "form-data")) {
				bbs_warning("Unknown content disposition: %s\n", header);
				return -1;
			}
			header += STRLEN("form-data");
			if (*header == ';') {
				header++;
			}
			ltrim(header);
			if (strlen_zero(header)) {
				continue;
			}
			while ((v = strsep(&header, ";"))) {
				k = strsep(&v, "=");
				if (strlen_zero(v)) {
					continue;
				}
				ltrim(k);
				STRIP_QUOTES(v);
				if (!strcasecmp(k, "name")) {
					name = v;
				} else if (!strcasecmp(k, "filename")) {
					filename = v;
				} else {
					bbs_warning("Unknown content disposition field: %s\n", k);
				}
			}
		} else if (!strcasecmp(headername, "Content-Type")) {
			/* XXX could have a ;charset */
			type = header;
		} else if (!strcasecmp(headername, "Content-Transfer-Encoding")) {
			/* Deprecated, ignore */
		} else {
			bbs_warning("Invalid multipart header: %s\n", headername);
			/* Ignore */
		}
	}
	http_debug(5, "=> %lu-byte multipart body (%s)\n", len, name);
	/* We can't store in a variable even if it's not a file, because binary data could be present. */
#ifdef DEBUG_UPLOADS
	bbs_dump_mem((unsigned char*) s, len);
#endif
	return push_post_param(http, name, type, filename, (unsigned char*) s, len);
}

static int parse_multipart(struct http_session *http, const char *content_type)
{
	size_t boundarylen;
	size_t bodyleft = http->req->contentlength;
	unsigned char *start, *bodypos = http->req->body;
	int res = -1;
	const char *boundary = strchr(content_type, '='); /* ; boundary= */
	if (!boundary) {
		bbs_warning("No boundary provided in content type\n");
		return -1;
	}
	boundary++;
	if (!*boundary) {
		bbs_warning("Empty boundary\n");
		return -1;
	}
	/* Note that the actual boundary where it appears in the data will be prefixed
	 * with 2 more dashes. See RFC 7578 4.1 */
	boundarylen = strlen(boundary);

	/* We already have the entire POST body loaded into a buffer.
	 * We can just scan the string.
	 * We may NOT use string functions like strstr since the body can contain binary data. */

	/* The first boundarylen + 2 bytes should be -- and the boundary. */
	if (strncmp((char*) bodypos, "--", 2) || strncmp((char*) bodypos + 2, boundary, boundarylen)) {
		bbs_warning("POST body (size %lu) does not begin with boundary? (%02x %02x)\n", bodyleft, bodypos[0], bodypos[1]);
		goto cleanup;
	}
	/* +2 for leading -- and +2 for CR LF afterwards */
	start = bodypos = bodypos + 2 + boundarylen; /* Beginning of first data */
	bodyleft -= boundarylen + 2;
	if (strncmp((char*) bodypos, "\r\n", 2)) {
		bbs_warning("Boundary not followed by CR LF?\n");
		goto cleanup;
	}
	start = bodypos = bodypos + 2;
	bodyleft -= 2;
	while (bodyleft > 0) {
		size_t length;
		unsigned char *nextboundary; /* Don't make this const, because start = bodypos line will complain about a const to non-const conversion */
		/* Find the end of this data. */
		nextboundary = memmem(bodypos, bodyleft, boundary, boundarylen);
		if (!nextboundary) {
			bbs_warning("Encountered premature end of multipart body?\n");
#ifdef DEBUG_UPLOADS
			bbs_dump_mem(bodypos, bodyleft);
#endif
			break;
		}
		if (nextboundary < http->req->body + 4) {
			/* Needs to be prefixed with CR LF --, so this can't be it. */
			bodypos += 4;
			bodyleft -= 4;
			continue;
		}
		if (strncmp((const char*) nextboundary - 4, "\r\n--", 4)) {
			/* It's actually not the boundary, since it wasn't preceded by those 4 characters. */
			bodypos += boundarylen;
			bodyleft -= boundarylen;
		}

		/* Okay, we found a valid boundary, with something after it. */
		length = (size_t) (nextboundary - 4 - start);
		bbs_debug(3, "Found multipart part of length %lu\n", length);
		if (parse_multipart_part(http, (char*) start, length)) {
			break;
		}

		/* Ready for next part */
		bodyleft += (size_t) (bodypos - start);
		bodyleft -= (size_t) (length + boundarylen + 4);
		start = bodypos = (nextboundary + boundarylen);

		if (!strncmp((const char*) nextboundary + boundarylen, "--", 2)) {
			/* The last boundary has 2 dashes after it, instead of CR LF */
			if (bodyleft != 2) {
				bbs_warning("%lu bytes left at end of POST body?\n", bodyleft);
			}
			res = 0;
			break;
		}

		if (bodyleft < 2) {
			bbs_warning("No CR LF after boundary? (%lu bytes left)\n", bodyleft);
			break;
		} else if (strncmp((char*) bodypos, "\r\n", 2)) {
			bbs_warning("Expected CR LF after boundary? (%02x %02x)\n", bodypos[0], bodypos[1]);
			break;
		}
		bodyleft -= 2;
		start = bodypos = bodypos + 2;
	}

	return res;

cleanup:
	FREE(http->req->body);
	return res;
}

static int parse_body(struct http_session *http)
{
	const char *content_type;

	if (!http->req->body) {
		return 0; /* No body to parse */
	}

	content_type = http_request_header(http, "Content-Type");
	if (!content_type || !strcasecmp(content_type, "application/x-www-form-urlencoded")) {
		/* Default is url encoded if not specified */
		parse_url_encoded_params(http, HTTP_METHOD_POST, (char*) http->req->body);
		FREE(http->req->body);
	} else if (STARTS_WITH(content_type, "multipart/form-data")) {
		parse_multipart(http, content_type);
	} else if (!strcasecmp(content_type, "text/plain")) {
		bbs_warning("The text/plain content type should be avoided!\n");
		return -1;
	} else {
		bbs_warning("Unsupported Content-Type: %s\n", content_type);
		return -1;
	}
	return 0;
}

static int parse_uri(struct http_session *http)
{
	char *q = strchr(http->req->uri, '?');
	if (!q) {
		return 0;
	}
	q++;
	if (!*q) {
		return 0;
	}
	q = strdup(q);
	if (ALLOC_FAILURE(q)) {
		return -1;
	}
	bbs_strterm(q, '#');
	parse_url_encoded_params(http, HTTP_METHOD_GET, q);
	free(q);
	return 0;
}

const char *http_request_header(struct http_session *http, const char *header)
{
	return bbs_var_find_case(&http->req->headers, header);
}

const char *http_get_cookie(struct http_session *http, const char *cookie)
{
	return bbs_var_find(&http->req->cookies, cookie);
}

int http_set_cookie(struct http_session *http, const char *name, const char *value, int secure, int maxage)
{
	char cookiebuf[1024];
	int len;

	/*
	 * Cookie attributes are ; separated:
	 * Domain= Top-level domain to which cookie will be sent (including subdomains). Default is only current domain.
	 * Expires= Date at which cookie will expire.
	 * HttpOnly Forbid JavaScript access.
	 * Max-Age= Number of seconds until cookie expiration. <= 0 will expire immediately.
	 * Partitioned
	 * Path= Required URL prefix for cookie to be sent
	 * SameSite=[Strict|Lax|None] Cross-site request control
	 * Secure HTTPS-only
	 */
	len = snprintf(cookiebuf, sizeof(cookiebuf), "%s=%s; HttpOnly; SameSite=Strict%s", name, value, secure ? "; Secure" : "");
	if (maxage) {
		snprintf(cookiebuf + len, sizeof(cookiebuf) - (size_t) len, "; Max-Age=%d", maxage);
	}

	/*! \todo FIXME Because http_set_header uses variables, this only allows a max of 1 cookie to be set
	 * We should store cookies in variables internally in the response, then write them out into a header
	 * when we actually send headers. */
	if (bbs_var_find_case(&http->res->headers, "Set-Cookie")) {
		bbs_warning("A cookie has already been set, and multiple cookies are not currently supported\n");
		return -1;
	}
	return http_set_header(http, "Set-Cookie", cookiebuf);
}

/* Could prefix with __Secure if it should be accessible only secure */
static char session_cookie_name[] = "HTTPSESSID";
static char session_cookie_name_secure[] = "__Secure-HTTPSESSID";
static int session_duration = 7200; /* 2 hours */

static struct session *http_session_find(const char *sessid)
{
	struct session *sess;
	time_t expired_threshold = time(NULL) - (time_t) session_duration;

	RWLIST_WRLOCK(&sessions);
	/* First, purge any expired sessions that aren't in use */
	RWLIST_TRAVERSE_SAFE_BEGIN(&sessions, sess, entry) {
		if (!sess->usecount && sess->created < expired_threshold) {
			bbs_debug(4, "Purging session %s (too old)\n", sess->sessid);
			RWLIST_REMOVE_CURRENT(entry);
			free(sess);
		}
	}
	RWLIST_TRAVERSE_SAFE_END;

	/* Now, look up the session. It's still not valid if it's expired. */
	RWLIST_TRAVERSE(&sessions, sess, entry) {
		if (!strcmp(sessid, sess->sessid)) {
			if (sess->created >= expired_threshold) {
				sess->usecount++;
				break;
			}
		}
	}
	RWLIST_UNLOCK(&sessions);
	if (!sess) {
		/* Since sessions are stored entirely in memory, and are not persisted to disk,
		 * likely from a previous instance of the BBS. */
		bbs_debug(5, "No session found with session ID: %s\n", sessid);
	}
	return sess;
}

static struct session *http_session_set(struct http_session *http, int secure, int update)
{
	struct session *sess;
	char sessid[SESSION_ID_LENGTH];

	if (bbs_rand_alnum(sessid, sizeof(sessid))) {
		return NULL;
	}

	RWLIST_WRLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, sess, entry) {
		if (!strcmp(sessid, sess->sessid)) {
			break;
		}
	}
	if (sess) {
		RWLIST_UNLOCK(&sessions);
		bbs_error("Created duplicate session ID %s?\n", sessid);
		return NULL;
	}

	if (update) {
		/* Find the existing session. */
		RWLIST_TRAVERSE(&sessions, sess, entry) {
			if (sess == http->req->session) {
				break;
			}
		}
#if 1
		if (!sess) {
			RWLIST_UNLOCK(&sessions);
			bbs_error("Can't update session (no session currently exists)\n");
			return NULL;
		}
#endif
	}
	if (!sess) {
		sess = calloc(1, sizeof(*sess));
		if (ALLOC_FAILURE(sess)) {
			RWLIST_UNLOCK(&sessions);
			return NULL;
		}
		bbs_varlist_init(&sess->vars);
	}

	strcpy(sess->sessid, sessid); /* Safe */

	if (!update) {
		RWLIST_INSERT_HEAD(&sessions, sess, entry);
		sess->usecount += 1;
		SET_BITFIELD(sess->secure, secure);
		sess->created = time(NULL);
	}
	RWLIST_UNLOCK(&sessions);

	/* Send a cookie to the client */
	http_set_cookie(http, secure ? session_cookie_name_secure : session_cookie_name, sessid, secure, session_duration);

	return sess; /* refcounted, so safe to return */
}

/*! \brief Create a new session */
static struct session *http_session_new(struct http_session *http, int secure)
{
	return http_session_set(http, secure, 0);
}

int http_session_regenerate(struct http_session *http)
{
	struct session *sess = http->req->session;
	if (!sess) {
		bbs_error("Can't regenerate session (no existing session)\n");
		return -1;
	}
	return http_session_set(http, sess->secure, 1) ? 0 : -1;
}

int http_session_destroy(struct http_session *http)
{
	struct session *sess = http->req->session;
	if (!sess) {
		bbs_warning("No session available to destroy\n");
		return -1;
	}
	RWLIST_WRLOCK(&sessions);
	sess->usecount--;
	http->req->session = NULL;
	sess->created = -1; /* Too old to ever be valid again. It'll get cleaned up when possible. Maybe now! */
	if (!sess->usecount) {
		struct session *s;
		RWLIST_TRAVERSE_SAFE_BEGIN(&sessions, s, entry) {
			if (sess == s) {
				RWLIST_REMOVE_CURRENT(entry);
				session_free(s);
				break;
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
		if (!s) {
			bbs_warning("Couldn't find session in session list?\n");
		}
	} else {
		bbs_debug(3, "Session invalidated, but can't be removed yet (still has usecount %d)\n", sess->usecount);
	}
	RWLIST_UNLOCK(&sessions);
	return 0;
}

int http_session_start(struct http_session *http, int secure)
{
	const char *cookie;
	struct session *sess = NULL;

	cookie = secure ? http_get_cookie(http, session_cookie_name_secure) : http_get_cookie(http, session_cookie_name);
	if (cookie) {
		sess = http_session_find(cookie);
	}
	if (!sess) {
		if (cookie) {
			bbs_verb(5, "Client had an expired session, starting a new session\n");
		} else {
			bbs_verb(5, "Client did not send a session cookie, starting a new session\n");
		}
		sess = http_session_new(http, secure);
	}
	http->req->session = sess;
	if (!sess) {
		bbs_warning("Failed to create or find session\n");
		return -1;
	}
	return 0;
}

const char *http_session_var(struct http_session *http, const char *name)
{
	struct session *sess = http->req->session;
	if (!sess) {
		bbs_warning("No session is currently active\n");
		return NULL;
	}
	return bbs_var_find(&sess->vars, name);
}

int http_session_set_var(struct http_session *http, const char *name, const char *value)
{
	struct session *sess = http->req->session;
	if (!sess) {
		bbs_warning("No session is currently active\n");
		return -1;
	}
	return bbs_varlist_append(&sess->vars, name, value); /* Add or replace session var */
}

static struct http_route *find_route(unsigned short int port, const char *hostname, const char *uri, enum http_method method, int *methodmismatch, unsigned short int *secureport)
{
	struct http_route *route = NULL, *r, *secureroute = NULL;
	struct http_route *defaultroute = NULL;
	char *host = NULL;

	if (!strlen_zero(hostname)) {
		host = strdup(hostname);
		if (ALLOC_FAILURE(host)) {
			return NULL;
		}
		bbs_strterm(host, ':'); /* Ignore port */
	}

	RWLIST_RDLOCK(&routes);
	RWLIST_TRAVERSE(&routes, r, entry) {
		if (r->hostname && host && strcmp(r->hostname, host)) {
#ifdef DEBUG_ROUTING
			bbs_debug(5, "Different host: %s != %s\n", host, r->hostname);
#endif
			continue; /* Different virtualhost */
		}
		if (!r->prefix) {
			if (port == r->port) {
				defaultroute = r;
			}
#ifdef DEBUG_ROUTING
			bbs_debug(5, "Skipping default route for now\n");
#endif
			continue; /* Prefer a more specific match, if available. */
		}
		if (strncmp(uri, r->prefix, r->prefixlen)) {
#ifdef DEBUG_ROUTING
			bbs_debug(5, "Prefix '%s' does not match\n", r->prefix);
#endif
			continue; /* Prefix doesn't match the request URI */
		}
		if (!(r->methods & method)) {
			*methodmismatch = 1;
#ifdef DEBUG_ROUTING
			bbs_debug(5, "Prefix %s matches, but method mismatch\n", r->prefix);
#endif
			continue; /* Wrong method */
		}
#ifdef DEBUG_ROUTING
		bbs_debug(5, "Found candidate route for %s\n", r->prefix);
#endif
		/* The route sufficiently matches */
		if (secureport && r->secure) {
			secureroute = r;
		}
		if (!route && port == r->port) { /* Use the first match */
			route = r;
		}
		/* Break as soon as we have the route we want,
		 * and the secureroute (which may or may not be the same),
		 * if secureport is desired (used for HTTPS upgrades) */
		if (route && (!secureport || secureroute)) {
			break;
		}
	}
	if (!route && defaultroute && defaultroute->methods & method) {
		bbs_debug(7, "Using default route %p\n", defaultroute);
		bbs_assert(defaultroute->prefix == NULL);
		route = defaultroute;
	}
	if (route) {
		*methodmismatch = 0;
		bbs_mutex_lock(&route->lock);
		route->usecount++;
		bbs_mutex_unlock(&route->lock);
		bbs_module_ref(route->mod, 1);
	} else {
		bbs_debug(3, "No matching route for '%s' and no default route!\n", uri);
	}
	RWLIST_UNLOCK(&routes);

	free_if(host);
	return route;
}

static void route_unref(struct http_route *route)
{
	bbs_module_unref(route->mod, 1);
	bbs_mutex_lock(&route->lock);
	route->usecount--;
	bbs_mutex_unlock(&route->lock);
}

int http_parse_request(struct http_session *http, char *buf)
{
	ssize_t res;
	size_t requestsize;
	size_t headerlen = 0;

	memset(&http->reqstack, 0, sizeof(http->reqstack));
	/* XXX This also memset's http->res->chunkbuf, which is unnecessary */
	memset(&http->resstack, 0, sizeof(http->resstack));

	RWLIST_HEAD_INIT(&http->reqstack.headers);
	RWLIST_HEAD_INIT(&http->reqstack.cookies);
	RWLIST_HEAD_INIT(&http->reqstack.queryparams);
	RWLIST_HEAD_INIT(&http->reqstack.postfields);

	RWLIST_HEAD_INIT(&http->resstack.headers);

	/* Initialize */
	http->res->chunkedleft = sizeof(http->res->chunkbuf);

	/* Particular consideration has been made of items discussed here: https://www.jmarshall.com/easy/http/ */

	/* Read and parse the request line */
	res = bbs_node_readline(http->node, http->rldata, "\r\n", SEC_MS(15));
	if (res <= 0) {
		http->req->keepalive = 0;
		http->res->code = HTTP_REQUEST_TIMEOUT;
		return -2;
	}
	requestsize = (size_t) res + 2; /* Plus CR LF */
	http_debug(5, "=> %s\n", buf);
	res = parse_request_line(http, buf);
	if (res) {
		/* Unknown HTTP method, probably not even a legitimate HTTP request.
		 * Send an HTTP error and close the connection. */
		http->res->code = res;
		builtin_response(http);
		bbs_event_dispatch(http->node, EVENT_NODE_BAD_REQUEST);
		return -1;
	}

	/* Read and store headers */
	for (;;) {
		char *tmp;
		res = bbs_node_readline(http->node, http->rldata, "\r\n", MIN_MS(1));
		if (res < 0) {
			/* Client disconnected without sending request headers */
			bbs_event_dispatch(http->node, EVENT_NODE_BAD_REQUEST);
			return -1;
		} else if (res == 0) { /* CR LF = end of headers */
			break;
		}
		http_debug(5, "=> %s\n", buf);
		requestsize += (size_t) res + 2; /* Plus CR LF */
		if (requestsize > MAX_HTTP_REQUEST_SIZE) {
			bbs_warning("HTTP request is too large (%lu+)\n", requestsize);
			return HTTP_CONTENT_TOO_LARGE;
		}
		if (isspace(buf[0])) {
			/* Continuation of previous header. Append data to previous line */
			if (!headerlen) {
				bbs_warning("Header continuation with no/empty header?\n");
				return -1;
			}
			headerlen += (size_t) res;
			if (headerlen > MAX_REQUEST_HEADER_LENGTH) {
				bbs_warning("Header is too long (%lu+)\n", headerlen);
				return HTTP_REQUEST_HEADERS_TOO_LARGE;
			}
			bbs_varlist_last_var_append(&http->req->headers, buf + 1); /* Skip first space */
		} else {
			char *s = buf;
			tmp = strsep(&s, ":");
			if (!s) {
				return -1;
			}
			*s++ = '\0';
			ltrim(s); /* Trim leading whitespace between : and actual header value */
			if (++http->req->numheaders > MAX_REQUEST_HEADERS) {
				bbs_warning("Maximum number of request headers exceeded\n"); /* Somebody's being ridiculous */
				return -1;
			}
			headerlen = (size_t) res;
			if (headerlen > MAX_REQUEST_HEADER_LENGTH) {
				bbs_warning("Header is too long (%lu+)\n", headerlen);
				return HTTP_REQUEST_HEADERS_TOO_LARGE;
			}
			bbs_varlist_append(&http->req->headers, tmp, s);
		}
	}

	/* Parse any GET parameters */
	if (parse_uri(http)) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Valid (and safe) path? */
	if (strlen_zero(http->req->uri) || strstr(http->req->uri, "..")) {
		/* We could use realpath, but this just isn't a valid web path */
		return HTTP_FORBIDDEN;
	}

	return process_headers(http);
}

/*! \retval -1 if connection should be closed (-2 if immediately), 0 on success, positive response code to send a default error message */
static int http_handle_request(struct http_session *http, char *buf)
{
	int res, methodmismatch = 0;
	struct http_route *route;
	enum http_response_code code;
	unsigned short int secureport = 0;

	res = http_parse_request(http, buf);
	if (res) {
		return res;
	}

	/* RFC 9110 7.6.2
	 * For OPTIONS and TRACE requests, if a Max-Forwards header is provided,
	 * we MUST NOT forward the request if its value is 0,
	 * and MUST decrement it otherwise (or set it to the local max supported Max-Forwards)
	 * We MAY ignore Max-Forwards for other methods, but don't have to, either...
	 * Currently, we don't forward requests (outside of the CONNECT proxy support),
	 * but we handle this anyways. */
	if (http->req->method & (HTTP_METHOD_OPTIONS | HTTP_METHOD_TRACE)) {
		const char *maxforwards = http_request_header(http, "Max-Forwards");
		if (!strlen_zero(maxforwards)) {
			int maxfwds = atoi(maxforwards);
			if (maxfwds) {
				char newmaxforwards[16];
				snprintf(newmaxforwards, sizeof(newmaxforwards), "%d", --maxfwds);
				/* BUGBUG This will only work if the case matches (e.g. request received
				 * was case-sensitively 'Max-Forwards'. If not, we will end up creating
				 * a new header with the canonical casing, and leave the old one intact... ouch.
				 * Leaving this unfixed for now, but it forwarding is ever added and this matters,
				 * we will need to be able to update headers case-insensitively, to be compatible
				 * with modifying existing headers as received. */
				http_set_header(http, "Max-Forwards", newmaxforwards);
			} else {
				/* Currently, there is nothing that checks this,
				 * but if OPTIONS and TRACE were to be implemented and in a way that supported forwarding,
				 * they would need to obey this. */
				http->req->noforward = 1;
			}
		}
	}

	/* Proxy requests really need to be handled before doing anything else, since they're fairly low level.
	 * We don't want to read or process the body.
	 * We don't care what the request is for,
	 * and we don't want to use any of the regular routes. */
	if (http_is_proxy_request(http)) {
		/* Pass it off to the proxy handler, if one exists.
		 * Otherwise, just reject it as unauthorized. */
		if (!proxy_port && http_get_default_http_port() > 0) {
			proxy_port = (unsigned short int) http_get_default_http_port();
		}
		if (http->node->port != proxy_port) {
			bbs_debug(3, "Node port %u does not match proxy port %u\n", http->node->port, proxy_port);
		} else if (!(proxy_methods & http->req->method)) {
			bbs_debug(3, "Proxy handler does not support %s\n", http_method_name(http->req->method));
		} else {
			if (!bbs_singular_callback_execute_pre(&proxy_handler)) {
				bbs_debug(4, "Passing %s proxy request for %s to proxy handler\n", http_method_name(http->req->method), http->req->uri);
				code = BBS_SINGULAR_CALLBACK_EXECUTE(proxy_handler)(http);
				bbs_singular_callback_execute_post(&proxy_handler);
				return code;
			}
			bbs_event_dispatch(http->node, EVENT_NODE_BAD_REQUEST); /* Likely spam traffic. */
			return HTTP_UNAUTHORIZED;
		}
		/* Fall through and treat as non proxy request */
	}

	/* Search for a matching route, before processing the body. */
	route = find_route(http->node->port, http->req->host, http->req->uri, http->req->method, &methodmismatch, http->req->httpsupgrade ? &secureport : NULL);
	if (!http->secure && http->req->httpsupgrade && secureport && secureport != http->node->port) {
		/* Upgrade to the HTTPS version of this page */
		return http_redirect_https(http, secureport);
	}
	if (!route) {
		if (methodmismatch) {
			bbs_debug(7, "No matching method for %s %s (%u) %s\n", http_method_name(http->req->method), http->req->host, http->node->port, http->req->uri);
			return HTTP_NOT_ALLOWED;
		} else {
			bbs_debug(7, "No matching route for %s %s (%u) %s\n", http_method_name(http->req->method), http->req->host, http->node->port, http->req->uri);
			return HTTP_NOT_FOUND; /* No matching route. How sad. */
		}
	}

	/* Done processing headers and URL. Move on to the body, if needed. */
	if (http->req->version & HTTP_VERSION_1_1_OR_NEWER && http->req->method & (HTTP_METHOD_POST | HTTP_METHOD_PUT)) {
		if (http->req->contentlength > MAX_HTTP_UPLOAD_SIZE) {
			/* Too large */
			route_unref(route);
			return HTTP_CONTENT_TOO_LARGE;
		}
		/* Send a 100 Continue intermediate response if we're good so far. */
		http->res->sent100 = 1;
		HTTP_SEND_HEADER(http, "HTTP/1.1 100 Continue\r\n");
		__http_direct_write(http, "\r\n", STRLEN("\r\n"));
		/* XXX If libcurl gets a 100 followed by a 404, it will be very unhappy (it will hang forever). */
	}

	/* Read and store the POST (or PUT) body */
	res = read_body(http, buf, 0);
	if (res) {
		if (res == 1) {
			route_unref(route);
			return HTTP_CONTENT_TOO_LARGE;
		}
		http->req->keepalive = 0; /* If we failed to read the body, we may not have parsed all of it. */
		goto abort;
	}
	if (http->rldata->leftover) {
		if (http->req->version & (HTTP_VERSION_0_9 | HTTP_VERSION_1_0)) {
			/* Since these versions don't support persistent connections,
			 * there should never be any data left after we've read the body. */
			bbs_warning("%lu bytes leftover?\n", http->rldata->leftover);
		} else {
			bbs_debug(3, "%lu bytes leftover\n", http->rldata->leftover);
		}
	}
	/* Parse POST body */
	if (parse_body(http)) {
		http->req->keepalive = 0; /* If we failed to parse the body, we may not have parsed all of it. */
		goto abort;
	}

	/* Run route handler, to abstractly serve the actual static or dynamic content. */
	code = route->handler(http);
	if (code > 0) {
		if (http->res->code > 0 && http->res->code != (unsigned int) code) {
			/* Possible programming error: set code and returned something else? */
			bbs_warning("Actual HTTP response code is %u, but returned %d?\n", http->res->code, code);
		}
		http->res->code = code;
	}
	route_unref(route);

	return http->req->keepalive ? 0 : -1; /* If keep alive not supported/enabled, kill the connection anyways */

abort:
	route_unref(route);
	return HTTP_BAD_REQUEST;
}

/*! \brief Thread to handle a single HTTP/HTTPS client */
static void http_handler(struct bbs_node *node, int secure)
{
	int res;
	char buf[MAX_HTTP_REQUEST_SIZE];
	struct readline_data rldata;
	struct http_session http;

	memset(&http, 0, sizeof(http));
	http.node = node;
	http.rldata = &rldata;
	http.req = &http.reqstack;
	http.res = &http.resstack;
	SET_BITFIELD(http.secure, secure);

	/* Start TLS if we need to */
	if (secure && bbs_node_starttls(node)) {
		return; /* Disconnect. */
	}

	bbs_readline_init(&rldata, buf, sizeof(buf));
	http.buf = buf;

	do {
		res = http_handle_request(&http, buf);
		if (res > 0) {
			http.res->code = res;
		} else if (res == -2) {
			/* Timeout occured when waiting for request (possible and likely with persistent connections) */
			break;
		}
		if (http.req->keepalive && !http.req->parsedbody && (!http.req->expect100 || http.res->sent100)) {
			/* We can still reuse the connection, but we need to discard any body we may have received.
			 * Unless, if client sent Expect: 100-continue and we have NOT sent a 100 continue,
			 * then there is no body as the client never sent it. */
			read_body(&http, buf, 1);
		}
		/* Send a builtin error response if no other data has been sent (or buffered to be sent). */
		if (!http.res->sentheaders && !http.res->sentbytes && !http.res->chunkedbytes) {
			builtin_response(&http);
		}
		flush_buffer(&http, 1); /* For (possibly) chunked responses, flush anything that might still be in the buffer */
		if (!http.res->sentheaders) {
			/* Send an empty response if needed. Must do this AFTER calling flush_buffer, as we only do this if no output was sent. */
			if (!http.res->code) {
				http.res->code = HTTP_OK;
			}
			http.res->chunked = 0; /* There's no body, definitely no need to use chunked transfer encoding */
			if (http_send_headers(&http)) {
				res = -1;
			}
		}
		if (http.res->contentlength && http.res->sentbytes != http.res->contentlength) {
			bbs_warning("Meant to send %lu bytes, but actually sent %lu?\n", http.res->contentlength, http.res->sentbytes);
		}
		log_response(&http);
		if (http.res->code == HTTP_BAD_REQUEST) {
			/* This is almost certainly an illegitimate request. */
			bbs_event_dispatch(http.node, EVENT_NODE_BAD_REQUEST);
		} else if (http.res->code == HTTP_NOT_FOUND && strcmp(http.req->uri, "/favicon.ico")) {
			/* Penalize 404s since this is likely bots scanning.
			 * Exempt favicon.ico since Chromium browsers request this automatically. */
			bbs_event_dispatch(http.node, EVENT_NODE_BAD_REQUEST);
		}
		http_session_cleanup(&http);
	} while (res >= 0 && http.req->keepalive);
}

/*! \brief 80 columns of spaces */
#define SPACE_STRING "                                                                                "

static int dir_listing(const char *dir_name, const char *filename, int dir, void *obj)
{
	struct stat st;
	struct http_session *http = obj;
	char fullpath[256];
	char timebuf[30];
	char sizebuf[15]; /* This has to be at least this large to avoid snprintf truncation warnings, but the space allotted for printing this is actually less than this */
	struct tm modtime;
	int paddinglen;
	int bytes;
	char prefix;
	double kb, mb;
	char *tmp;

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);

	if (stat(fullpath, &st)) {
		bbs_error("stat failed (%s): %s\n", fullpath, strerror(errno));
		return -1;
	}
	gmtime_r(&st.st_mtim.tv_sec, &modtime); /* Times are always in GMT (UTC) */
	if (!strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", &modtime)) { /* returns 0 on failure, o/w number of bytes written */
		bbs_error("strftime failed\n"); /* errno is not set according to strftime(3) man page */
		return -1;
	}

	paddinglen = 80 - (int) strlen(filename);
	bytes = (int) st.st_size;
	mb = 1.0 * bytes / (1024 * 1024);

	if (mb >= 1) {
		if (mb >= 1024) {
			double gb = 1.0 * bytes / (1024 * 1024 * 1024);
			snprintf(sizebuf, sizeof(sizebuf), "%.1fG", gb);
			prefix = 'G';
		} else {
			snprintf(sizebuf, sizeof(sizebuf), "%.1fM", mb);
			prefix = 'M';
		}
	} else if ((kb = 1.0 * bytes / 1024) >= 1) {
		snprintf(sizebuf, sizeof(sizebuf), "%.1fK", kb);
		prefix = 'K';
	} else {
		snprintf(sizebuf, sizeof(sizebuf), "%dB", bytes);
		prefix = '\0';
	}
	/* g format character is like f, expect don't print decimal places if they are 0. Unfortunately, it loses precision.
	 * If the number after the decimal point is 0, manually fix that up here and remove it. */
	tmp = strchr(sizebuf, '.');
	if (tmp && *(tmp + 1) == '0') {
		/* Easier (and faster) than doing memmove and other tricks */
		*tmp = prefix;
		*(tmp + 1) = '\0';
	}
	/* We need at least 7 characters for the size: potentially 4 numbers + period + decimal digit + suffix */
	http_writef(http, "<a href='%s%s%s'>%s</a>%.*s <span>%s</span> <span style='text-align: right;'>%8s</span><br>\r\n",
		http->req->uri, filename, dir ? "/" : "", filename, paddinglen, SPACE_STRING, timebuf, sizebuf);
	return 0;
}

static enum http_response_code http_dirlist(struct http_session *http, const char *dirname)
{
	/* strlen_zero doesn't like + 1 being passed in with its argument. Must be a pointer with no calculations. */
	/*! \todo XXX BUGBUG Check the rest of the BBS for strlen_zero calls with calculations - these will not work! */
	const char *suburi = http->req->uri + 1;
	/* Dump the directory */
	bbs_debug(5, "Neither index.html nor index.htm exists, producing a directory listing for %s\n", dirname);
	http_writef(http, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">");
	http_writef(http, "<html><head><title>Index of %s</title></head>\r\n", http->req->uri);
	http_writef(http, "<body><h1>Index of %s</h1>\r\n", http->req->uri);
	http_writef(http, "<pre>");
	http_writef(http, "<b>%-80s</b> <b>%-16s</b> <b>%8s</b>\n", "Name", "Last modified", "Size");
	http_writef(http, "<hr>");
	if (!strlen_zero(suburi) && strchr(suburi + 1, '/')) {
		/* If we're in a subdirectory, provide link to go up one level */
		http_writef(http, "<a href='%s%s%s'>%s</a>%.*s <span>%s</span> <span style='text-align: right;'>%8s</span><br>\r\n",
			http->req->uri, "..", "/", "Parent Directory", 80 - (int) STRLEN("Parent Directory"), SPACE_STRING, "", "");
	}
	bbs_dir_traverse_items(dirname, dir_listing, http); /* Dump the directory */
	http_writef(http, "<hr></pre></body></html>");
	return HTTP_OK;
}

#undef SPACE_STRING

static int translate_dir_to_file(const char *docroot, const char *uri, int ends_in_slash, struct stat *stptr, char *buf, size_t len, const char *suffix)
{
	char filename[PATH_MAX];
	struct stat st;
	snprintf(filename, sizeof(filename), "%s%s%s%s", docroot, uri, ends_in_slash ? "" : "/", suffix);
	if (!stat(filename, &st)) {
		safe_strncpy(buf, filename, len);
		memcpy(stptr, &st, sizeof(struct stat));
		return 0;
	}
	return -1;
}

static int mime_type(const char *filename, char *buf, size_t len)
{
	const char *mime;
	magic_t magic;
	char *ext;

	magic = magic_open(MAGIC_MIME_TYPE);
	if (!magic) {
		bbs_error("magic_open failed: %s\n", strerror(errno));
		return -1;
	}
	magic_load(magic, NULL);
	magic_compile(magic, NULL);
	mime = magic_file(magic, filename);
	if (mime) {
		safe_strncpy(buf, mime, len);
	} else {
		bbs_warning("Could not determine MIME type of %s\n", filename);
		*buf = '\0';
	}
	magic_close(magic);

	bbs_debug(7, "magic mimetype(%s): %s\n", filename, buf);

	/* Some basic checks that we need to do */
	ext = strrchr(filename, '.');
	if (!ext || !(++ext)) {
		return 0; /* No further way to intuit */
	}
	if (!strcmp(buf, "text/plain")) {
		/* libmagic is not going to figure out most text-based files
		 * correctly, it's more intended for binary files.
		 * Apache also uses its own database prior to falling back to libmagic. */
		if (!strcmp(ext, "html")) {
			safe_strncpy(buf, "text/html", len);
		} else if (!strcmp(ext, "css")) {
			safe_strncpy(buf, "text/css", len);
		}
	} else if (!mime) {
		safe_strncpy(buf, DEFAULT_MIME_TYPE, len);
	}

	return 0;
}

static long int range_parse(char *range, long int size, long int *a, long int *b)
{
	int contains_dash;
	char *start, *end = range;

	/* First character could be negative, that's not the a-b separator, that's negative a */
	if (*range == '-') {
		/* A manual strsep, basically */
		start = end;
		end = strrchr(start, '-'); /* Will never return NULL */
		bbs_assert_exists(end);
		contains_dash = end != range ? 1 : 0;
		if (contains_dash) {
			*end++ = '\0';
		}
	} else {
		contains_dash = strchr(end, '-') ? 1 : 0;
		start = strsep(&end, "-");
	}
	if (strlen_zero(start)) {
		bbs_warning("No start for range?\n");
		return -1; /* Malformed request? */
	}
	*a = atoi(start);

	/* Convert negative offsets */
	if (*a < 0) {
		*a = size + *a; /* a is negative, so size + a is really size - (-a) */
	}
	if (strlen_zero(end)) {
		if (contains_dash) {
			*b = size - 1; /* Until end of file */
		} else {
			*b = *a; /* Single byte */
		}
	} else {
		*b = atoi(end);
		if (*b < 0) {
			*b = size + *b;
		}
	}
	return *b - *a + 1; /* Number of bytes */
}

enum http_response_code http_static(struct http_session *http, const char *filename, struct stat *st)
{
	struct tm modtime;
	int fd = -1;
	off_t offset;
	ssize_t written;
	char timebuf[30];
	char mimetype[64];
	const char *ranges;
	char rangebuf[256];
	int rangeparts = 0;
	size_t rangebytes = 0;
	long int a, b;
	struct stat st2;

	if (!st) {
		if (stat(filename, &st2)) {
			bbs_error("stat(%s) failed: %s\n", filename, strerror(errno));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		st = &st2;
	}

	/* Only GET and HEAD are supported for static files, nothing dynamic. */
	if (!(http->req->method & (HTTP_METHOD_GET | HTTP_METHOD_HEAD))) {
		return HTTP_NOT_ALLOWED;
	}

	memset(&modtime, 0, sizeof(modtime));
	gmtime_r(&st->st_mtim.tv_sec, &modtime); /* Times are always in GMT (UTC) */

	/* If-Modified-Since is actually useful for static files! */
	if (http->req->ifmodsince) {
		struct tm nowtime;
		time_t timenow, timemod, timemodsince;

		memset(&nowtime, 0, sizeof(nowtime));
		timenow = time(NULL);
		gmtime_r(&timenow, &nowtime);

		timemod = mktime(&modtime); /* mktime is thread safe */
		timemodsince = mktime(&http->req->modsince);
		if (difftime(timemod, timemodsince) <= 0) { /* If difftime > 0, then arg1 > arg2, so if it's <=, we should respond with a 304 Not Modified. */
			/* Client sent If-Modified-Since and file hasn't been modified since then */
			return HTTP_NOT_MODIFIED_SINCE;
		}
	}

	/* Caching headers */
	if (!strftime(timebuf, sizeof(timebuf), STRFTIME_FMT, &modtime)) { /* returns 0 on failure, o/w number of bytes written */
		bbs_error("strftime failed\n"); /* errno is not set according to strftime(3) man page */
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	http_set_header(http, "Last-Modified", timebuf);
	http_set_header(http, "Cache-Control", "must-revalidate, max-age=60"); /* Use Cache-Control instead of Expires */
	http_set_header(http, "Accept-Ranges", "bytes"); /* Advertise RFC 7233 bytes range support */

	ranges = http_request_header(http, "Range");
	if (ranges) {
		if (!STARTS_WITH(ranges, "bytes=")) {
			ranges = NULL;
			bbs_warning("Unsupported Range header value: %s\n", ranges);
		} else {
			/* Calculate the ranges */
			size_t overhead = 0;
			char bytes_list[48];
			char *range, *rangelist = rangebuf;
			/* Calculate the number of parts (and bytes) to transfer */
			safe_strncpy(rangebuf, ranges + STRLEN("bytes="), sizeof(rangebuf));
			while ((range = strsep(&rangelist, ","))) {
				long int thisrangebytes;
				thisrangebytes = range_parse(range, st->st_size, &a, &b);
				if (thisrangebytes == -1) {
					return HTTP_RANGE_UNAVAILABLE;
				}
				if (a > st->st_size || b > st->st_size) { /* Requesting range encompassing bytes beyond the file size */
					return HTTP_RANGE_UNAVAILABLE;
				}
				rangeparts++;
				rangebytes += (size_t) thisrangebytes;
				/* Assume rangeparts > 1 so we don't need to make another pass over the ranges if true.
				 * Calculate overhead of the multipart headers.
				 * THIS MUST BE DONE EXACTLY THE SAME WAY THE HEADERS ARE ACTUALLY GENERATED AT THE BOTTOM OF THIS FUNCTION!
				 */
				overhead += STRLEN("--" RANGE_SEPARATOR "\r\n"); /* XXX What if RANGE_SEPARATOR appears in the content? */
				overhead += STRLEN("Content-Range: ");
				overhead += (size_t) snprintf(bytes_list, sizeof(bytes_list), "bytes %ld-%ld", a, b);
				overhead += STRLEN("\r\n\r\n"); /* Content-Range CR LF, plus CR LF for end of headers */
				overhead += STRLEN("\r\n"); /* Plus CR LF after the part itself. */
				/* Could also send Content-Type header (and add to overhead length) */
			}
			overhead += STRLEN("--" RANGE_SEPARATOR "--");
			if (rangeparts == 1) {
				/* Just a single range */
				overhead = 0;
				snprintf(bytes_list, sizeof(bytes_list), "bytes %ld-%ld", a, b);
				http_set_header(http, "Content-Range", bytes_list);
				/* Could also send Content-Type header */
			} else if (rangebytes + overhead > (size_t) st->st_size) {
				/* The number of bytes sent in range chunks is greater than if we were to just send the entire file. */
				bbs_warning("Refusing to satisfy Range request: transferring entire file singularly would be more efficient (%ld bytes vs %lu+%lu)\n", st->st_size, rangebytes, overhead);
				ranges = NULL;
			} else if (rangeparts > 1) {
				/* Already calculated the overhead. Just set the content type */
				http_set_header(http, "Content-Type", "multipart/byteranges; boundary=" RANGE_SEPARATOR);
			} else { /* ranges == 0 */
				bbs_warning("Range request failed to parse into ranges?\n");
				ranges = NULL;
			}
			http->res->contentlength = rangebytes + overhead;
		}
	}

	/* Size is already known, no need to lseek */
	if (!ranges) {
		http->res->contentlength = (size_t) st->st_size;
		offset = 0;
	}
	
	/* Set Content Type based on MIME type, unless we already set it for multipart/byteranges */
	if ((!ranges || rangeparts <= 1) && !mime_type(filename, mimetype, sizeof(mimetype))) {
		http_set_header(http, "Content-Type", mimetype);
	}

	/* We must set the response code, if needed, before headers are sent out */
	http->res->code = ranges ? HTTP_PARTIAL_CONTENT : HTTP_OK;

	/* All right, actually dump the file */
	if (!(http->req->method & HTTP_METHOD_HEAD)) {
		fd = open(filename, O_RDONLY, 0600);
		if (fd < 0) {
			bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	/* Logic here is basically that in __http_write, but as a wrapper around sendfile instead of bbs_write */
	if (http->res->sentheaders) {
		bbs_warning("Headers have already been sent?\n");
		close_if(fd);
		return HTTP_INTERNAL_SERVER_ERROR;
	} else {
		http_send_headers(http);
	}

	/* Past this point, the return value is kind of meaningless since we already sent the headers. Always return http->res->code */

	/* Bail out now for HEAD requests */
	if (http->req->method & HTTP_METHOD_HEAD) {
		/* We never opened fd, no need to close it */
		return http->res->code;
	}

	/* Since we already sent headers, if a failure occurs, we must disable persistence (keep alive) and abort */
	if (ranges) {
		if (rangeparts == 1) {
			offset = a;
			written = http_sendfile(http, fd, &offset, rangebytes);
			close(fd);
			if (written != (ssize_t) rangebytes) {
				http->req->keepalive = 0;
			}
			http->res->sentbytes += (size_t) rangebytes;
		} else { /* rangeparts > 1 */
			char *range, *rangelist = rangebuf;
			safe_strncpy(rangebuf, ranges + STRLEN("bytes="), sizeof(rangebuf));
			while ((range = strsep(&rangelist, ","))) {
				long int thisrangebytes = range_parse(range, st->st_size, &a, &b);
				bbs_assert(thisrangebytes != -1); /* It succeeded before already, why would it fail now? */
				http_writef(http, "--%s\r\n", RANGE_SEPARATOR);
				http_writef(http, "Content-Range: bytes %ld-%ld\r\n", a, b);
				http_writef(http, "\r\n");
				offset = a;
				bbs_debug(5, "Sending %ld-byte range beginning at offset %lu\n", thisrangebytes, offset);
				written = http_sendfile(http, fd, &offset, (size_t) thisrangebytes);
				if (written != (ssize_t) thisrangebytes) {
					close(fd);
					http->req->keepalive = 0;
					return http->res->code;
				}
				http->res->sentbytes += (size_t) thisrangebytes;
				http_writef(http, "\r\n"); /* After part itself */
			}
			close(fd);
			http_writef(http, "--%s--", RANGE_SEPARATOR); /* Final multipart boundary */
		}
	} else {
		written = http_sendfile(http, fd, &offset, (size_t) st->st_size);
		close(fd);
		if (written != (ssize_t) st->st_size) {
			http->req->keepalive = 0;
		}
		http->res->sentbytes += (size_t) st->st_size;
	}

	return http->res->code;
}

static int cgi_run(struct http_session *http, const char *filename, char *const envp[])
{
	int res = -1;
	int stdin[2], stdout[2];
	pid_t child_pid;
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	char *const argv[2] = { (char*) filename, NULL };
#pragma GCC diagnostic pop /* -Wcast-qual */
#pragma GCC diagnostic pop /* -Wdiscarded-qualifiers */

	/* Because we need to run our own logic while the child is running,
	 * fork and wait on the child directly here, rather than using BBS exec APIs.
	 * It's just easier in this case. */

	/* Create pipes for the CGI's STDIN and STDOUT */
	if (pipe(stdin)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	} else if (pipe(stdout)) {
		PIPE_CLOSE(stdin);
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	}

	child_pid = fork(); /* fork has an implicit SIGCHLD */
	if (child_pid == -1) {
		bbs_error("fork failed: %s\n", strerror(errno));
		goto cleanup;
	}

	if (child_pid == 0) {
		int i;
		/* Disable and reset signal handlers */
		signal(SIGWINCH, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		/* Close all file descriptors except the pipes */
		for (i = 3; i < 1024; i++) {
			if (i != stdin[0] && i != stdout[1]) {
				close(i);
			}
		}
		/* Set STDIN and STDOUT */
		dup2(stdin[0], STDIN_FILENO);
		dup2(stdout[1], STDOUT_FILENO);
		/* Ignore STDERR_FILENO - that shouldn't go to the HTTP client, at least, maybe to the BBS log? */
		/* Execute the CGI script */
#ifdef __FreeBSD__
		/* See comments about execvpe on FreeBSD in bbs/system.c */
		bbs_error("execvpe is not supported on FreeBSD\n");
		UNUSED(envp);
		res = execvp(filename, argv);
#else
		res = execvpe(filename, argv, envp);
#endif
		_exit(errno);
	} else {
		char buf[1024];
		int status;
		ssize_t bytes;
		size_t total_bytes = 0;
		int headers = 0, got_headers = 0;
		int pollms = SEC_MS(20); /* Effectively, lower bounds the maximum amount of time a CGI script is allowed to execute */
		struct readline_data rldata;

		/* Close the ends we don't need, or we won't get an EOF on the STDOUT pipe when the child dies. */
		close_if(stdin[0]);
		close_if(stdout[1]);

		/* If there's a body, feed it on STDIN */
		/* XXX The reason we don't free req->body after parsing the body is so we can feed the raw body to CGIs
		 * In the case of CGIs, that means parsing the body itself was unnecessary.
		 * The way it is now is a bit simpler for HTTP applications, as everything is always already ready to go,
		 * but it would be more efficient if individual route handlers called the body parser if/as needed. */
		if (http->req->body) {
			bbs_write(stdin[1], (char*) http->req->body, http->req->contentlength);
		}

		bbs_readline_init(&rldata, buf, sizeof(buf));
		/* Parent: wait for CGI script to finish, and process its STDOUT all the meanwhile */

		/* The CGI script is expected to send headers, a newline, and then the HTTP body.
		 * This means until we get a blank line, we're parsing headers, not the actual body.
		 *
		 * Note that because the pipe will close and wake up poll(),
		 * we don't need to explicitly monitor for child exit.
		 * We can just call waitpid when we're finished.
		 */
		bbs_verb(5, "Executing CGI %s\n", filename);
		for (;;) {
			char *hdr, *val;
			/* Use only LF as a delimiter since, unlike HTTP, these can be CR LF or just LF delimited. */
			bytes = bbs_readline(stdout[0], &rldata, "\n", SEC_MS(30)); /* Wait up to 30 seconds for the CGI script to send headers */
			if (bytes < 0) {
				bbs_debug(4, "readline returned %lu before end of headers\n", bytes);
				goto cleanup;
			}
			if (bytes == 0 || (bytes == 1 && buf[0] == '\r')) {
				/* End of headers */
				got_headers = 1;
				break;
			}
			bbs_strterm(buf, '\r'); /* If CR is present, get rid of it */
			val = buf;
			hdr = strsep(&val, ":");
			if (!val) {
				bbs_warning("CGI script emitted header '%s' with no value (line length %lu)?\n", hdr, bytes);
				goto cleanup;
			}
			ltrim(val);
			http_set_header(http, hdr, val);
			headers++;
		}
		if (!got_headers) {
			bbs_warning("CGI script did not signal end of headers before response body\n");
		}
		/* Now, send the body.
		 * Note that some (or all) of it may be sitting in the readline buffer. */
		bytes = readline_bytes_available(&rldata, 1);
		if (bytes > 0) {
			http_write(http, buf, (size_t) bytes);
			total_bytes += (size_t) bytes;
		}
		/* Read from the pipe until it closes
		 * We're done with rldata, so we can reuse buf. */
		for (;;) {
			int pres;
			pres = bbs_poll(stdout[0], pollms);
			if (pres < 0) {
				break;
			} else if (pres == 0) {
				bbs_warning("CGI script %s possibly stalled?\n", filename);
				goto cleanup;
			}
			bytes = read(stdout[0], buf, sizeof(buf));
			if (bytes < 0) {
				bbs_error("read failed: %s\n", strerror(errno));
			} else if (bytes == 0) {
				break;
			}
			http_write(http, buf, (size_t) bytes);
			total_bytes += (size_t) bytes;
		}
		/* CGI is done executing */
		bbs_debug(5, "CGI script finished, wrote %d header%s, %lu-byte body\n", headers, ESS(headers), total_bytes);
		if (!headers && !total_bytes) {
			bbs_warning("CGI script output was empty (no headers and no body)\n");
			/* In this case, we never called http_write,
			 * so we haven't thus far caused anything to be returned for the response.
			 * Thus, 200 OK headers will be sent automatically,
			 * but the default keepalive behavior will cause us to hang, so explicitly disable that. */
			http->req->keepalive = 0;
		}
		if (waitpid(child_pid, &status, 0) == -1) { /* This should return immediately since child exited (pipe closed) */
			bbs_error("waitpid failed: %s\n", strerror(errno));
			goto cleanup;
		}
		if (WIFEXITED(status)) { /* Child terminated normally */
			res = WEXITSTATUS(status);
			bbs_debug(5, "Process %d (%s) exited, status %d\n", child_pid, filename, res);
		} else {
			bbs_warning("Child process %d didn't exit normally?\n", child_pid);
		}
	}

cleanup:
	PIPE_CLOSE(stdin);
	PIPE_CLOSE(stdout);
	return res;
}

static void cgi_delenv(char *envp[])
{
	int i = 0;
	char *s = envp[i];
	while (s) {
		free(s);
		s = envp[++i];
	}
}

static int __attribute__ ((format (gnu_printf, 5, 6))) __cgi_setenv(char *envp[], size_t envlen, int *envnum, const char *key, const char *fmt, ...)
{
	char *buf;
	va_list ap;
	int len;
	int i;

	if (*envnum >= (int) envlen) {
		bbs_warning("Failed to set environment variable %s (envp array is full)\n", key);
		return -1;
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len == -1) {
		return -1;
	}

	/* I'm sure there's a clever way to do the next few lines in a single line or two in C,
	 * but it's not occuring to me right now... */
	i = *envnum;
	envp[i++] = buf;
	*envnum = i;
	http_debug(6, "Setting CGI env var %2d: %s\n", i, buf); /* after i++ means this is naturally 1-indexed */

	/* Don't free here, envp needs this */
	return 0;
}

#define cgi_setenv(key, fmt, ...) __cgi_setenv(envp, len, &envnum, key, "%s=" fmt, key, __VA_ARGS__)
#define cgi_setenvif(key, fmt, var) if (var) { cgi_setenv(key, fmt, var); }
#define cgi_setenvif_hdr(key, fmt, hdr) { \
	const char *_hdrval = http_request_header(http, hdr); \
	if (_hdrval) { cgi_setenv(key, fmt, _hdrval); } \
}

static int cgi_set_envp(struct http_session *http, const char *filename, const char *docroot, char *envp[], size_t len)
{
	int envnum = 0;

	envp[envnum] = NULL;

	/* RFC 3875 Request Meta-Variables */
	if (http_request_header(http, "Authorization")) {
		cgi_setenv("AUTH_TYPE", "%s", "BASIC");
	}
	cgi_setenvif("CONTENT_LENGTH", "%lu", http->req->contentlength);
	cgi_setenvif_hdr("CONTENT_TYPE", "%s", "Content-Type");
	cgi_setenv("GATEWAY_INTERFACE", "%s", "1.1");
	cgi_setenv("PATH_INFO", "%s", http->req->uri);
	cgi_setenv("PATH_TRANSLATED", "%s", filename);
	cgi_setenvif("QUERY_STRING", "%s", http->req->querystring);
	cgi_setenv("REMOTE_ADDR", "%s", http->node->ip);
	/* Skip REMOTE_HOST, we don't have the FQDN of the client, seriously? Just use REMOTE_ADDR */
	/* Skip REMOTE_IDENT, RFC 1413 identification protocol */
	cgi_setenvif("REMOTE_USER", "%s", http->req->username);
	cgi_setenv("REQUEST_METHOD", "%s", http_method_name(http->req->method));
	cgi_setenv("SCRIPT_NAME", "%s", bbs_basename(filename));
	cgi_setenvif("SERVER_NAME", "%s", http->req->host);
	cgi_setenv("SERVER_PORT", "%d", http->node->port);
	cgi_setenv("SERVER_PROTOCOL", "%s", "HTTP/1.1");
	cgi_setenv("SERVER_SOFTWARE", "%s", SERVER_NAME); /* This one only, we could put the arg directly in fmt, but I don't want to ## __VA_ARGS__ just for this one */

	/* Add some stuff not explicitly specified in RFC 3875, some of this is PHP-inspired */
	cgi_setenvif("DOCUMENT_ROOT", "%s", docroot);
	cgi_setenvif("HTTPS", "%d", http->secure);
	/* List of (some common) HTTP headers */
	cgi_setenvif_hdr("HTTP_ACCEPT", "%s", "Accept");
	cgi_setenvif_hdr("HTTP_ACCEPT_CHARSET", "%s", "Accept-Charset");
	cgi_setenvif_hdr("HTTP_ACCEPT_ENCODING", "%s", "Accept-Encoding");
	cgi_setenvif_hdr("HTTP_ACCEPT_LANGUAGE", "%s", "Accept-Language");
	cgi_setenvif_hdr("HTTP_FORWARDED", "%s", "Forwarded");
	cgi_setenvif_hdr("HTTP_HOST", "%s", "Host");
	cgi_setenvif_hdr("HTTP_PROXY_AUTHORIZATION", "%s", "Proxy-Authorization");
	cgi_setenvif_hdr("HTTP_USER_AGENT", "%s", "User-Agent");

	envp[envnum] = NULL;
	return 0;
}

enum http_response_code http_cgi(struct http_session *http, const char *filename, const char *docroot)
{
	char *envp[32];

	if (http->req->method & HTTP_METHOD_HEAD) {
		return HTTP_NOT_ALLOWED; /* Can't do HEAD requests for CGI scripts. No guarantee those are idempotent. */
	}

	if (cgi_set_envp(http, filename, docroot, envp, ARRAY_LEN(envp))) {
		cgi_delenv(envp);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* See also: https://www.jmarshall.com/easy/cgi/ */
	if (cgi_run(http, filename, envp)) {
		cgi_delenv(envp);
		return HTTP_BAD_GATEWAY; /* Consider the CGI a gateway that has failed us */
	} else {
		cgi_delenv(envp);
		return HTTP_OK;
	}
}

enum http_response_code http_serve_static_or_cgi(struct http_session *http, const char *uri, const char *docroot, int dirlist, int cgi, const char *cgiext)
{
	char filename[PATH_MAX];
	struct stat st;
	int ends_in_slash;

	/* First, check if such a file exists on disk, corresponding to the URI portion.
	 * e.g. if uri == /index.html, see if docroot/index.html exists. */
	snprintf(filename, sizeof(filename), "%s%s", docroot, uri);
	bbs_strterm(filename, '?'); /* Don't include query string when looking up URL */
	if (stat(filename, &st)) {
		if (cgiext) {
			snprintf(filename, sizeof(filename), "%s%s%s", docroot, uri, cgiext);
		}
		if (stat(filename, &st) || S_ISDIR(st.st_mode)) { /* Doesn't count if we added a file extension implicitly and that's a directory */
			return HTTP_NOT_FOUND; /* File does not exist */
		}
	}
	/* Okay, so it exists! But is it a file or a directory?
	 * If the latter, we need to find a default file. */
	ends_in_slash = uri[strlen(uri) - 1] == '/';
	if (S_ISDIR(st.st_mode)) {
		if (!ends_in_slash) {
			/* Redirect to the canonical form of a directory path, with a slash at the end. */
			snprintf(filename, sizeof(filename), "%s/", http->req->uri);
			http_redirect(http, HTTP_REDIRECT_FOUND, filename);
			return HTTP_REDIRECT_FOUND;
		}
		if (translate_dir_to_file(docroot, uri, ends_in_slash, &st, filename, sizeof(filename), "index.html")
			&& translate_dir_to_file(docroot, uri, ends_in_slash, &st, filename, sizeof(filename), "index.htm")
			&& (!cgiext || translate_dir_to_file(docroot, uri, ends_in_slash, &st, filename, sizeof(filename), cgiext))) {
			/* We could not translate to a file, we are stuck with a directory.
			 * If we are allowed to provide a directory listing, do so. */
			return dirlist ? http_dirlist(http, filename) : HTTP_FORBIDDEN;
		}
	}
	if (!S_ISREG(st.st_mode)) {
		bbs_warning("%s is not a regular file?\n", filename);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	/* Okay, we have a file to serve or execute.
	 * See if we can execute it (CGI), otherwise just serve the file.
	 * We allow any executable file to be executed using CGI,
	 * no need to be in a special cgi-bin directory (which isn't special for this web server)
	 */
	if (cgi && !eaccess(filename, X_OK)) {
		return http_cgi(http, filename, docroot);
	} else {
		return http_static(http, filename, &st);
	}
}

static void *__http_handler(void *varg)
{
	struct bbs_node *node = varg;

	bbs_node_net_begin(node);
	http_handler(node, !strcmp(node->protname, "HTTPS") ? 1 : 0); /* Actually handle the HTTP/HTTPS client */
	bbs_node_exit(node);
	return NULL;
}

/*! \note routes must be locked when calling */
static int ref_listener(unsigned short int port, unsigned int secure)
{
	struct http_listener *listener;

	/* No need to WRLOCK listeners. routes is already WRLOCK'ed */
	RWLIST_TRAVERSE(&listeners, listener, entry) {
		if (port == listener->port) {
			if (secure != listener->secure) {
				bbs_error("Port %u is already a %s port\n", port, listener->secure ? "secure" : "insecure");
				return -1;
			}
			break;
		}
	}
	if (!listener) {
		listener = calloc(1, sizeof(*listener));
		if (ALLOC_FAILURE(listener)) {
			return -1;
		}
		listener->port = port;
		SET_BITFIELD(listener->secure, secure);
		bbs_start_tcp_listener(port, secure ? "HTTPS" : "HTTP", __http_handler);
		RWLIST_INSERT_HEAD(&listeners, listener, entry);
	}
	listener->usecount++;
	return (int) listener->usecount;
}

/*! \note routes must be locked when calling */
static void unref_listener(unsigned short int port)
{
	struct http_listener *listener;

	/* No need to WRLOCK listeners. routes is already WRLOCK'ed */
	RWLIST_TRAVERSE_SAFE_BEGIN(&listeners, listener, entry) {
		if (port == listener->port) {
			if (!--listener->usecount) { /* No routes are using this listener anymore. */
				RWLIST_REMOVE_CURRENT(entry);
				bbs_stop_tcp_listener(port);
				free(listener);
			}
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (!listener) {
		bbs_error("Trying to unreference nonexistent listener for port %u?\n", port);
		return;
	}
}

static int http_default_port = -1;
static int https_default_port = -1;

void http_set_default_http_port(int port)
{
	http_default_port = port;
}

void http_set_default_https_port(int port)
{
	https_default_port = port;
}

int http_get_default_http_port(void)
{
	return http_default_port;
}

int http_get_default_https_port(void)
{
	return https_default_port;
}

int __http_register_route(const char *hostname, unsigned short int port, unsigned int secure, const char *prefix, enum http_method methods, enum http_response_code (*handler)(struct http_session *http), void *mod)
{
	size_t hostlen, prefixlen;
	struct http_route *route;

	prefixlen = strlen(S_IF(prefix));

	RWLIST_WRLOCK(&routes);
	RWLIST_TRAVERSE(&routes, route, entry) {
		if (route->port == port && route->methods == methods) {
			/* XXX This is far from comprehensive */
			if ((hostname && route->hostname && !strcmp(hostname, route->hostname)) || (!hostname && !route->hostname)) {
				if ((prefix && route->prefix && (!strncmp(prefix, route->prefix, prefixlen) || !strncmp(route->prefix, prefix, prefixlen))) || (!prefix && !route->prefix)) {
					bbs_error("Route already registered for host %s, prefix %s\n", route->hostname, route->prefix);
					RWLIST_UNLOCK(&routes);
					return -1;
				}
			}
		}
	}

	/* Create or reuse an (effectively reference counted) listener */
	if (ref_listener(port, secure) < 1) {
		RWLIST_UNLOCK(&routes);
		return -1;
	}

	hostlen = hostname ? strlen(hostname) + 1 : 0;
	prefixlen = prefix ? strlen((const char*) prefix) + 1 : 0;
	route = calloc(1, sizeof(*route) + hostlen + prefixlen);
	if (ALLOC_FAILURE(route)) {
		unref_listener(port);
		RWLIST_UNLOCK(&routes);
		return -1;
	}

	if (hostname) {
		strcpy(route->data, hostname);
		route->hostname = route->data;
	}
	if (prefix) {
		strcpy(route->data + hostlen, (const char*) prefix);
		route->prefix = route->data + hostlen;
		route->prefixlen = prefixlen - 1; /* Subtract the 1 we added for NUL */
	}

	route->port = port;
	route->methods = methods;
	route->handler = handler;
	route->mod = mod;
	bbs_mutex_init(&route->lock, NULL);
	SET_BITFIELD(route->secure, secure);
	RWLIST_INSERT_HEAD(&routes, route, entry);
	RWLIST_UNLOCK(&routes);
	return 0;
}

int http_unregister_route(enum http_response_code (*handler)(struct http_session *http))
{
	struct http_route *route;
	int removed = 0;

	RWLIST_WRLOCK(&routes);
	RWLIST_TRAVERSE_SAFE_BEGIN(&routes, route, entry) {
		if (route->handler == handler) {
			bbs_mutex_lock(&route->lock);
			/* Not very elegant, but mainly needed for mod_test_http,
			 * since the "client" will try to unregister the route as soon as it's done,
			 * but the server may still be using the route.
			 * Don't actually remove it until the server is done with it,
			 * or we'll end up with race conditions, use after free, etc. */
			while (route->usecount > 0) {
				bbs_mutex_unlock(&route->lock);
				usleep(10000);
				bbs_mutex_lock(&route->lock);
			}
			unref_listener(route->port);
			RWLIST_REMOVE_CURRENT(entry);
			bbs_mutex_unlock(&route->lock);
			bbs_mutex_destroy(&route->lock);
			free(route);
			/* Don't break, because the route could be registered multiple times (e.g. HTTP and HTTPS)
			 * If we also accepted a port number, that should be unique and we could break. */
			removed++;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&routes);
	return removed ? 0 : -1;
}

int __http_register_proxy_handler(unsigned short int port, enum http_method methods, enum http_response_code (*handler)(struct http_session *http), void *mod)
{
	int res = bbs_singular_callback_register(&proxy_handler, handler, mod);
	if (!res) {
		/* Not 100% perfect, since we're no longer holding the lock, but probably fine */
		proxy_port = port;
		proxy_methods = methods;
	}
	return res;
}

int http_unregister_proxy_handler(enum http_response_code (*handler)(struct http_session *http))
{
	int res = bbs_singular_callback_unregister(&proxy_handler, handler);
	if (!res) {
		proxy_port = 0;
		proxy_methods = HTTP_METHOD_UNDEF;
	}
	return res;
}

static int cli_http_routes(struct bbs_cli_args *a)
{
	struct http_route *r;

	bbs_dprintf(a->fdout, "%-30s %-30s %5s %6s %7s %s\n", "Prefix", "Hostname", "Port", "Secure", "Use Cnt", "Module");
	RWLIST_RDLOCK(&routes);
	RWLIST_TRAVERSE(&routes, r, entry) {
		bbs_dprintf(a->fdout, "%-30s %-30s %5u %6s %7u %s\n", S_IF(r->prefix), S_IF(r->hostname), r->port, BBS_YN(r->secure), r->usecount, bbs_module_name(r->mod));
	}
	RWLIST_UNLOCK(&routes);
	return 0;
}

static int cli_http_sessions(struct bbs_cli_args *a)
{
	struct session *s;

	bbs_dprintf(a->fdout, "%-48s %s\n", "Session ID", "Use Count");
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, s, entry) {
		bbs_dprintf(a->fdout, "%-48s %u\n", s->sessid, s->usecount);
	}
	RWLIST_UNLOCK(&sessions);
	return 0;
}

static struct bbs_cli_entry cli_commands_http[] = {
	BBS_CLI_COMMAND(cli_http_routes, "http routes", 2, "List HTTP routes", NULL),
	BBS_CLI_COMMAND(cli_http_sessions, "http sessions", 2, "List HTTP sessions", NULL),
};

static int unload_module(void)
{
	/* Remove any lingering sessions */
	RWLIST_WRLOCK_REMOVE_ALL(&sessions, entry, session_free);
	bbs_cli_unregister_multiple(cli_commands_http);
	bbs_singular_callback_destroy(&proxy_handler);
	return 0;
}

static int load_module(void)
{
	if (bbs_cli_register_multiple(cli_commands_http)) {
		unload_module();
		return -1;
	}
	return 0;
}

BBS_MODULE_INFO_FLAGS("RFC2616 HTTP 1.1 Web Server Engine", MODFLAG_GLOBAL_SYMBOLS);
