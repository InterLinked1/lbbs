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
#include <string.h>
#include <unistd.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <poll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <sys/sendfile.h>
#include <magic.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/system.h"
#include "include/linkedlists.h"
#include "include/base64.h"

#define SERVER_NAME BBS_TAGLINE " " BBS_VERSION " Web Server"

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443

#define DEFAULT_MIME_TYPE "application/octet-stream"

#define STRPTIME_FMT "%a, %d %b %Y %T %Z"
#define STRFTIME_FMT "%a, %d %b %Y %T %Z"

static int http_port = DEFAULT_HTTP_PORT;
static int https_port = DEFAULT_HTTPS_PORT;

static pthread_t http_listener_thread = -1;
static char http_docroot[256] = "";

static int http_enabled = 0, https_enabled = 0;
static int cgi = 0;
static int authonly = 0;
static int http_socket = -1, https_socket = -1;

/* These functions are not safe to use */
#undef read
#undef write

#define MAX_HTTP_REQUEST_SIZE 8192

enum http_method {
	HTTP_UNDEF = 0,
	HTTP_OPTIONS,
	HTTP_HEAD,
	HTTP_GET,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
};

static const char *http_method_name(enum http_method method)
{
	switch (method) {
		case HTTP_OPTIONS:
			return "OPTIONS";
		case HTTP_HEAD:
			return "HEAD";
		case HTTP_GET:
			return "GET";
		case HTTP_POST:
			return "POST";
		case HTTP_PUT:
			return "PUT";
		case HTTP_DELETE:
			return "DELETE";
		case HTTP_UNDEF:
		default:
			return NULL;
	}
}

struct http_req {
	struct bbs_node *node;
	int rfd;
	int wfd;
#ifdef HAVE_OPENSSL
	SSL *ssl;
#endif

	/* Response */
	unsigned int responsecode;
	unsigned int responselen;

	/* Request */
	enum http_method method;
	double version;
	unsigned int length;

	char *host;
	char *path;
	const char *file;
	char *query;
	char *useragent;
	char *referer; /* Sic */
	char *contenttype;
	char *remoteuser; /* Basic Auth username */
	char *range;

	struct tm modsince; /* If-Modified-Since */

	/* Request Flags */
	unsigned int dir:1;				/* Request is for a directory */
	unsigned int secure:1;			/* HTTPS? */
	unsigned int keepalive:1;		/* Connection: keep-alive */
	unsigned int upgradeinsecure:1;	/* Upgrade-Insecure-Requests: 1 */
	unsigned int ifmodsince:1;		/* If we got a valid If-Modified-Since request header */
};

/* Allow dprintf to be used */
#undef dprintf

#define HTTP_NOT_MODIFIED_SINCE 304
#define HTTP_BAD_REQUEST 400
#define HTTP_UNAUTHORIZED 401
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_NOT_ALLOWED 405
#define HTTP_INTERNAL_SERVER_ERROR 500
#define HTTP_NOT_IMPLEMENTED 501
#define HTTP_VERSION_NOT_SUPPORTED 505

static int send_response(struct http_req *req, int code)
{
	const char *title = NULL, *description = NULL;

	req->responsecode = code;

	switch (code) {
		/* Some verbiage borrowed from Apache HTTP server: https://github.com/apache/httpd/tree/trunk/docs/error */
		case HTTP_NOT_MODIFIED_SINCE:
			break; /* No need for a body */
		case HTTP_BAD_REQUEST:
			title = "Bad Request";
			description = "Your browser sent a request the server could not understand.";
			break;
		case HTTP_UNAUTHORIZED:
			title = "Unauthorized";
			description = "Additional authentication required to access this resource.";
			break;
		case HTTP_FORBIDDEN:
			title = "Forbidden";
			description = "You don't have permission to access this resource.";
			break;
		case HTTP_NOT_FOUND:
			title = "Not Found";
			description = "The requested URL was not found on this server.";
			break;
		case HTTP_NOT_ALLOWED:
			title = "Not Allowed";
			description = "Method not allowed for the requested URL.";
			break;
		case HTTP_INTERNAL_SERVER_ERROR:
			title = "Internal Server Error";
			description = "The server encountered an internal error and was unable to complete your request.";
			break;
		case HTTP_NOT_IMPLEMENTED:
			title = "Not Implemented";
			description = "The server does not support the action requested by the browser.";
			break;
		case HTTP_VERSION_NOT_SUPPORTED:
			title = "Version Not Supported";
			description = "The server does not support the HTTP version of your browser.";
			break;
		default:
			return -1;
	}

	dprintf(req->wfd, "HTTP/1.1 %d%s%s\r\n", code, title ? " " : "", S_IF(title));
	dprintf(req->wfd, "Server: %s\r\n", SERVER_NAME);
	if (title && description) {
		dprintf(req->wfd, "Content-Type: text/html\r\n");
	}
	dprintf(req->wfd, "Connection: %s\r\n", req->keepalive ? "keep-alive" : "close"); /* HTTP 1.0 compatibility, assumed default in 1.1+ */
	if (code == HTTP_UNAUTHORIZED && !req->remoteuser) {
		/* If not already authenticated, ask the user to */
		bbs_debug(3, "Asking for additional authorization\n");
		dprintf(req->wfd, "WWW-Authenticate: Basic realm=\"bbs\"\r\n");
	}
	dprintf(req->wfd, "\r\n"); /* End the response headers */
	if (title && description) {
		dprintf(req->wfd, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n");
		dprintf(req->wfd, "<html><head><title>%d %s</title></head>\r\n", code, title);
		dprintf(req->wfd, "<h1>%s</h1>\r\n", title);
		dprintf(req->wfd, "<p>%s</p>\r\n", description);
		dprintf(req->wfd, "<hr><address>%s</address></body></html>", SERVER_NAME);
	}
	return 0;
}

/*! \brief If client sends a header twice, don't leak memory. */
#define HEADER_DUP(var) \
	free_if(var); \
	var = strdup(value);

static inline int parse_header(struct http_req *req, char *s)
{
	char *tmp, *query, *header, *value = s;

	header = strsep(&value, ":");

	if (req->method == HTTP_UNDEF) {
		/* First line of the request */
		tmp = strsep(&header, " ");
		if (!strcasecmp(tmp, "GET")) {
			req->method = HTTP_GET; /* Most common first */
		} else if (!strcasecmp(tmp, "HEAD")) {
			req->method = HTTP_HEAD;
		} else if (!strcasecmp(tmp, "OPTIONS")) {
			req->method = HTTP_OPTIONS;
		} else if (!strcasecmp(tmp, "POST")) {
			req->method = HTTP_POST;
		} else if (!strcasecmp(tmp, "PUT")) {
			req->method = HTTP_PUT;
		} else if (!strcasecmp(tmp, "DELETE")) {
			req->method = HTTP_DELETE;
		} else {
			if (!strcasecmp(tmp, "CONNECT")) {
				bbs_debug(3, "Unsupported HTTP method: %s\n", tmp);
			} else {
				bbs_warning("Unknown HTTP request method: %s\n", bbs_str_isprint(tmp) ? tmp : "(non-printable)");
			}
			return HTTP_NOT_IMPLEMENTED;
		}
		tmp = strsep(&header, " ");
		if (!tmp) {
			return HTTP_BAD_REQUEST; /* Missing path */
		}
		query = tmp;
		tmp = strsep(&query, "?");
		req->path = strdup(tmp);
		tmp = strrchr(req->path, '/');
		if (strlen_zero(tmp) || strlen_zero(tmp + 1)) {
			/* The / was the last character in the path.
			 * This implies the default document in this location. */
			req->dir = 1;
		} else {
			req->dir = 0;
		}

		if (query && !strlen_zero(++query)) {
			req->query = strdup(query);
		}

		tmp = strsep(&header, "/"); /* Skip HTTP/ */
		if (!header) {
			return HTTP_VERSION_NOT_SUPPORTED; /* Missing HTTP version */
		}
		req->version = atof(header);
		if (req->version >= 1.1) {
			req->keepalive = 1; /* keep alive assumed for 1.1+ */
		}
		return 0;
	} else if (!value) {
		bbs_warning("Header '%s' has no value?\n", header);
		return HTTP_BAD_REQUEST;
	} else if (*value == ' ') {
		value++; /* This is all we need to do, no need to call ltrim */
	}

	if (!strcasecmp(header, "Host")) {
		HEADER_DUP(req->host);
	} else if (!strcasecmp(header, "Connection")) {
		req->keepalive = !strcasecmp(value, "close") || !strcasecmp(value, "retry-after") ? 0 : 1;
	} else if (!strcasecmp(header, "Pragma")) {
		/* Deprecated header: only HTTP 1.0 */
	} else if (!strcasecmp(header, "Cache-Control")) {
		/* HTTP 1.1 header that replaced Pragma: Ignore, because we're not a proxy server or CDN */
	} else if (!strcasecmp(header, "Upgrade-Insecure-Requests")) {
		req->upgradeinsecure = atoi(value);
	} else if (!strcasecmp(header, "User-Agent")) {
		HEADER_DUP(req->useragent);
	} else if (!strcasecmp(header, "Accept") || !strcasecmp(header, "Accept-Encoding") || !strcasecmp(header, "Accept-Language")) {
		/* Ignore */
	} else if (!strcasecmp(header, "Content-Length")) {
		req->length = atoi(value);
	} else if (!strcasecmp(header, "Content-Type")) {
		HEADER_DUP(req->contenttype);
	} else if (!strcasecmp(header, "Referer")) {
		HEADER_DUP(req->referer);
	} else if (!strcasecmp(header, "Authorization")) {
		int outlen;
		tmp = strsep(&value, " ");
		if (!strcmp(tmp, "Basic")) {
			unsigned char *decoded = base64_decode((unsigned char*) value, strlen(value), &outlen);
			if (decoded) {
				char *username, *password = (char*) decoded;
				username = strsep(&password, ":");

				/* Always set, even if incorrect password, so we know that we attempted Basic Auth */
				REPLACE(req->remoteuser, username);
				bbs_authenticate(req->node, username, password);
				/* Destroy the password before freeing it */
				bbs_memzero(decoded, outlen);
				free(decoded);
			}
		}
	} else if (!strcasecmp(header, "If-Modified-Since")) {
		if (req->method == HTTP_GET || req->method == HTTP_OPTIONS) {
			if (strptime(value, STRPTIME_FMT, &req->modsince) != NULL) { /* Returns NULL on failure */
				req->ifmodsince = 1;
			} else {
				bbs_warning("Failed to parse If-Modified-Since: %s\n", value);
			}
		}
	} else if (!strcasecmp(header, "Range")) {
		HEADER_DUP(req->range);
	} else if (!strcasecmp(header, "DNT")) {
		/* Do Not Track header: ignore, we don't track people anyways */
	} else if (!strcasecmp(header, "X-Forwarded-For") || !strcasecmp(header, " X-Forwarded-Proto")) {
		/* Ignore these headers, don't care */
	} else {
		bbs_warning("Unhandled HTTP header: %s (%s)\n", header, S_IF(value)); /* This is fine, maybe bad on us, but the client didn't do anything wrong */
	}
	return 0;
}

static void http_req_destroy(struct http_req *req)
{
	free_if(req->host);
	free_if(req->path);
	free_if(req->query);
	free_if(req->useragent);
	free_if(req->referer);
	free_if(req->contenttype);
	free_if(req->range);
}

/* Apache style log message */
#define LOG_REQ() bbs_debug(3, "\"%s %s HTTP/%1.1f\" %d %d \"%s\" \"%s\"\n", http_method_name(req.method), req.path, req.version, req.responsecode, req.responselen, S_IF(req.referer), S_IF(req.useragent));

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
	if (!strcmp(buf, "text/plain") && !strcmp(ext, "html")) {
		safe_strncpy(buf, "text/html", len);
	}

	return 0;
}

static int __attribute__ ((format (gnu_printf, 3, 4))) __cgi_setenv(char *envp[], int *envnum, const char *fmt, ...)
{
	char *buf;
	va_list ap;
	int len;
	int i;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len == -1) {
		return -1;
	}

	/* I'm sure there's a clever way to do the next 3 lines in a single line in C, but it's not occuring to me right now... */
	i = *envnum;
	envp[i++] = buf;
	*envnum = i;
	/* Don't free here, envp needs this */
	return 0;
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

#define cgi_setenv(key, fmt, ...) __cgi_setenv(envp, &envnum, "%s=" fmt, key, __VA_ARGS__)
#define cgi_setenvif(key, fmt, var) if (var) { cgi_setenv(key, fmt, var); }

/*! \brief RFC 3875 Common Gateway Interface */
static int run_cgi(struct http_req *req, const char *filename)
{
	int res;
	int envnum = 0;
	char *const argv[2] = { (char*) filename, NULL };
	char *envp[32];

	/* RFC 3875 Request Meta-Variables */
	if (req->remoteuser) {
		cgi_setenv("AUTH_TYPE", "%s", "Basic");
	}
	cgi_setenvif("CONTENT_LENGTH", "%d", req->length);
	cgi_setenvif("CONTENT_TYPE", "%s", req->contenttype);
	cgi_setenv("GATEWAY_INTERFACE", "%s", "1.1");
	cgi_setenv("PATH_INFO", "%s", req->path);
	cgi_setenv("PATH_TRANSLATED", "%s", filename); /* XXX Same as SCRIPT_NAME, in this simple CGI implementation? */
	cgi_setenvif("QUERY_STRING", "%s", req->query);
	cgi_setenv("REMOTE_ADDR", "%s", req->node->ip);
	/* Skip REMOTE_HOST, we don't have the FQDN of the client, seriously? */
	/* Skip REMOTE_IDENT, RFC 1413 identification protocol */
	cgi_setenvif("REMOTE_USER", "%s", req->remoteuser);
	cgi_setenv("REQUEST_METHOD", "%s", http_method_name(req->method));
	cgi_setenv("SCRIPT_NAME", "%s", filename);
	cgi_setenvif("SERVER_NAME", "%s", req->host);
	cgi_setenv("SERVER_PORT", "%d", req->secure ? https_port : http_port);
	cgi_setenv("SERVER_PROTOCOL", "%s", "HTTP/1.1");
	cgi_setenv("SERVER_SOFTWARE", "%s", SERVER_NAME); /* This one only, we could put the arg directly in fmt, but I don't want to ## __VA_ARGS__ just for this one */

	/* Add some stuff not explicitly specified in RFC 3875, some of this is PHP-inspired */
	cgi_setenv("DOCUMENT_ROOT", "%s", http_docroot);
	cgi_setenvif("HTTPS", "%d", req->secure);
	cgi_setenvif("HTTP_USER_AGENT", "%s", req->useragent);

	envp[envnum++] = NULL;
	bbs_assert(envnum < (int) ARRAY_LEN(envp)); /* If envp is not NULL-terminated, we'll crash anyways. And if this happens, we probably wrote into invalid memory already... */
	bbs_debug(3, "Spawning CGI %s with %d environment variables\n", filename, envnum);

	/* CGI script only gets STDOUT, and no STDIN */
	/* If the CGI script prints headers, we need to be sure not to stamp on them. */
	dprintf(req->wfd, "HTTP/1.1 %d %s\r\n", 200, "OK");
	dprintf(req->wfd, "Server: %s\r\n", SERVER_NAME);
	dprintf(req->wfd, "Connection: %s\r\n", req->keepalive ? "keep-alive" : "close"); /* HTTP 1.0 compatibility, assumed default in 1.1+ */
	if (req->keepalive) {
		dprintf(req->wfd, "Keep-Alive: timeout=%d, max=%d\r\n", 1, 1000);
	}
	req->responsecode = 200;
	dprintf(req->wfd, "\r\n"); /* End the response headers */
	/* XXX What if the CGI script wants to add its own headers?
	 * What if wants to reply with a non-200 response?
	 * We'd have to use a pipe to check the STDOUT from the CGI script,
	 * and if it's adding headers, not trample on them,
	 * and at the same time add anything it doesn't. */

	/* The CGI protocol says the CGI script gets the body on STDIN...
	 * Okay... less work for us, then! */
	res = bbs_execvpe_fd_headless(req->node, req->rfd, req->wfd, filename, argv, envp);
	/* XXX Ideally if the CGI script failed to execute, we would return a 500 error here.
	 * But we really have no idea if the script failed or not. Even if it returns nonzero
	 * when it exits, we don't know if started writing to STDOUT before that, in which
	 * case it wouldn't make sense to send response headers anymore.
	 * Not to mention we already sent a 200 OK, so... yeah... I hope your CGI script works. */
	cgi_delenv(envp);
	return res;
}

static int range_parse(char *range, int size, int *a, int *b)
{
	int contains_dash;
	char *start, *end = range;

	/* First character could be negative, that's not the a-b separator, that's negative a */
	if (*range == '-') {
		/* A manual strsep, basically */
		start = end;
		end = strrchr(start, '-'); /* Will never return NULL */
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

static inline int path_file_exists(const char *dir, const char *file)
{
	char buf[256];
	snprintf(buf, sizeof(buf), "%s%s", dir, file);
	return bbs_file_exists(buf);
}

/*! \brief 80 columns of spaces */
#define SPACE_STRING "                                                                                "

static int dir_listing(const char *dir_name, const char *filename, int dir, void *obj)
{
	struct stat st;
	struct http_req *req = obj;
	char fullpath[256];
	char timebuf[30];
	char sizebuf[15]; /* This has to be at least this large to avoid snprintf truncation warnings, but the space allotted for printing this is actually less than this */
	struct tm modtime;
	int paddinglen;
	int bytes;
	char prefix;
	double kb, mb;
	char *tmp;
	const char *parent = dir_name + strlen(http_docroot);

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);

	if (stat(fullpath, &st)) {
		bbs_error("stat failed (%s): %s\n", fullpath, strerror(errno));
		return -1;
	}
	gmtime_r(&st.st_mtim.tv_sec, &modtime); /* Times are always in GMT (UTC) */
	if (strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", &modtime) <= 0) { /* returns 0 on failure, o/w number of bytes written */
		bbs_error("strftime failed\n"); /* errno is not set according to strftime(3) man page */
		return -1;
	}

	paddinglen = 80 - strlen(filename);
	bytes = st.st_size;
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
	dprintf(req->wfd, "<a href='%s/%s%s'>%s</a>%.*s <span>%s</span> <span style='text-align: right;'>%8s</span><br>\r\n", parent, filename, dir ? "/" : "", filename, paddinglen, SPACE_STRING, timebuf, sizebuf);
	return 0;
}

/*! \brief Thread to handle a single HTTP/HTTPS client */
static void http_handler(struct bbs_node *node, int secure)
{
#ifdef HAVE_OPENSSL
	SSL *ssl;
#endif
	int res;
	char buf[MAX_HTTP_REQUEST_SIZE];
	struct readline_data rldata;
	struct http_req req;
	char fullpath[PATH_MAX];
	int nreq;
	int rfd, wfd;

	memset(&req, 0, sizeof(req));
	req.node = node;
	req.method = HTTP_UNDEF;

	/* Start TLS if we need to */
	if (secure) {
		ssl = ssl_new_accept(node->fd, &rfd, &wfd);
		if (!ssl) {
			return; /* Disconnect. */
		}
		req.ssl = ssl;
		req.rfd = rfd;
		req.wfd = wfd;
	} else {
		rfd = wfd = req.rfd = req.wfd = node->fd;
	}

	bbs_readline_init(&rldata, buf, sizeof(buf));

	for (nreq = 0;; nreq++) {
		FILE *fp;
		int size, complete = 0;
		char mime[64];
		char timebuf[30];
		off_t offset;
		struct stat st;
		struct tm nowtime, modtime;
		time_t timenow;
		int rangeparts = 0;

		/* For keep alive, it can take a non-zero time for the next request to arrive */
		if (bbs_std_poll(req.rfd, 1000) <= 0) { /* Do this here so we don't double log for successive requests on the same connection. */
			bbs_debug(3, "Client timed out, closing connection\n");
			break;
		}
		if (nreq) {
			if (req.keepalive) {
				/* From the previous request */
				LOG_REQ();
				http_req_destroy(&req); /* Free anything dynamic from the last request handled, so we don't leak memory from previous requests */
				req.node = node;
				req.method = HTTP_UNDEF;
				req.rfd = rfd;
				req.wfd = wfd;
#ifdef HAVE_OPENSSL
				req.ssl = ssl;
#endif
			} else {
				break; /* Client doesn't support persistent connections, stop */
			}
		}
		req.secure = secure;

		for (;;) {
			res = bbs_fd_readline(req.rfd, &rldata, "\r\n", MIN_MS(1));
			if (s_strlen_zero(buf)) { /* End of request headers */
				complete = 1;
				break;
			}
			bbs_debug(8, "Parsing header: %s\n", buf);
			res = parse_header(&req, buf);
			if (res > 0) {
				send_response(&req, res);
				goto cleanup; /* Can't break, we're in a double loop */
			}
		}

		/* It's safe to either break (same as goto cleanup) or continue in this loop, at any point.
		 * break will stop processing requests, continue will move to the next one if keep alive is supported. */

		if (!complete) {
			if (req.method == HTTP_UNDEF) {
				bbs_debug(5, "Client closed HTTP connection\n"); /* EOF before receiving any data */
				break;
			}
			bbs_warning("Incomplete HTTP request?\n");
			send_response(&req, HTTP_BAD_REQUEST);
			break; /* Stop now */
		}

		/* Valid HTTP version? */
		if (req.version < 0.9 || req.version > 1.1) {
			bbs_warning("HTTP version %f not supported\n", req.version);
			send_response(&req, HTTP_VERSION_NOT_SUPPORTED);
			goto cleanup;
		}

		/* Valid (and safe) path? */
		if (strlen_zero(req.path) || strstr(req.path, "..")) {
			/* We could use realpath, but this just isn't a valid web path */
			send_response(&req, HTTP_FORBIDDEN);
			break;
		}

		/* RFC 7235 Basic Authentication */
		if (authonly && !bbs_user_is_registered(req.node->user)) {
			send_response(&req, HTTP_UNAUTHORIZED);
			continue;
		}

		/* If the path exists but it's a directory, check for a default document to use */
		snprintf(fullpath, sizeof(fullpath), "%s%s", http_docroot, req.path);
		req.file = NULL;
		/* Directory root (not necessarily the root directory, but of some directory) */
		if (!eaccess(fullpath, F_OK)) {
			if (stat(fullpath, &st)) {
				bbs_error("stat failed for %s: %s\n", fullpath, strerror(errno));
				send_response(&req, HTTP_INTERNAL_SERVER_ERROR); /* How can eaccess succeed but stat fail? */
				break;
			}
			/* If index.html or index.htm exists in the current directory, use that.
			 * Otherwise, display the directory. */
			snprintf(fullpath, sizeof(fullpath), "%s%s", http_docroot, req.path);
			if (path_file_exists(fullpath, "index.html")) {
				bbs_debug(3, "%s%s exists\n", fullpath, req.path);
				req.file = "index.html";
			} else if (path_file_exists(fullpath, "index.htm")) {
				req.file = "index.htm";
			}
		}

		bbs_debug(3, "%s || %s || %s\n", http_docroot, req.path, req.file);

		/* File exists? */
		snprintf(fullpath, sizeof(fullpath), "%s%s%s", http_docroot, req.path, S_IF(req.file));
		bbs_debug(6, "Full path: %s\n", fullpath);
		if (!bbs_file_exists(fullpath)) { /* It doesn't even exist. */
			send_response(&req, HTTP_NOT_FOUND);
			continue;
		} else if (eaccess(fullpath, R_OK)) { /* It exists, but it's not readable by the BBS user */
			send_response(&req, HTTP_FORBIDDEN);
			continue;
		}

		/* stat again, fullpath could have changed */
		memset(&st, 0, sizeof(st));
		if (stat(fullpath, &st)) {
			bbs_error("stat failed for %s: %s\n", fullpath, strerror(errno));
			send_response(&req, HTTP_INTERNAL_SERVER_ERROR); /* How can eaccess succeed but stat fail? */
			break;
		}

		if (S_ISREG(st.st_mode) && !eaccess(fullpath, X_OK)) { /* File is executable (directories may be executable, ignore those) */
			if (!cgi) {
				bbs_warning("File '%s' is executable, but CGI is disabled. For security reasons, this request is blocked.\n", fullpath);
				send_response(&req, HTTP_FORBIDDEN);
				continue;
			}
			run_cgi(&req, fullpath); /* Run a dynamic script or binary */
			continue;
		} else if (S_ISDIR(st.st_mode)) {
			/* Dump the directory */
			bbs_debug(5, "Neither index.html nor index.htm exists, producing a directory listing\n");
			req.responsecode = 200;
			dprintf(req.wfd, "HTTP/1.1 %d %s\r\n", req.responsecode, "OK");
			dprintf(req.wfd, "Server: %s\r\n", SERVER_NAME);
			dprintf(req.wfd, "Connection: %s\r\n", "close"); /* No content length, we don't know what it'll be */
			dprintf(req.wfd, "\r\n");  /* End of response headers */
			dprintf(req.wfd, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">");
			dprintf(req.wfd, "<html><head><title>Index of %s</title></head>\r\n", req.path);
			dprintf(req.wfd, "<body><h1>Index of %s</h1>\r\n", req.path);
			dprintf(req.wfd, "<pre>");
			dprintf(req.wfd, "<b>%-80s</b> <b>%-16s</b> <b>%-8s</b>\n", "Name", "Last modified", "Size");
			dprintf(req.wfd, "<hr>");
			bbs_dir_traverse_items(fullpath, dir_listing, &req); /* Dump the directory */
			dprintf(req.wfd, "<hr></pre></body></html>");
			/* Close the connection, since we didn't send a Content-Length.
			 * Generally speaking, not ideal, but it works fine in this case,
			 * and it's not really a big deal since we don't expect the client to send any extra requests
			 * (the auto-generated webpage doesn't reference any other resources). */
			break;
		} else if (!S_ISREG(st.st_mode)) {
			bbs_warning("'%s' is not a file or directory, ignoring\n", fullpath);
			send_response(&req, HTTP_FORBIDDEN);
			continue;
		}

		/* At this point, we're serving a static file. Only GET and HEAD are supported, nothing dynamic. */
		if (req.method != HTTP_GET && req.method != HTTP_HEAD) {
			send_response(&req, HTTP_NOT_ALLOWED);
			continue;
		}

		memset(&nowtime, 0, sizeof(nowtime));
		memset(&modtime, 0, sizeof(modtime));

		timenow = time(NULL);
		gmtime_r(&timenow, &nowtime);
		gmtime_r(&st.st_mtim.tv_sec, &modtime); /* Times are always in GMT (UTC) */

		if (req.ifmodsince) {
			time_t timemod, timemodsince;
			timemod = mktime(&modtime); /* mktime is thread safe */
			timemodsince = mktime(&req.modsince);
#if 0
			bbs_debug(3, "%lu, %lu = difftime: %f\n", timemod, timemodsince, difftime(timemod, timemodsince));
#endif
			if (difftime(timemod, timemodsince) <= 0) { /* If difftime > 0, then arg1 > arg2, so if it's <=, we should respond with a 304 Not Modified. */
				/* If client sent If-Modified-Since and file hasn't been modified since then */
				send_response(&req, HTTP_NOT_MODIFIED_SINCE); /* How can eaccess succeed but stat fail? */
				continue;
			}
		}

		/* Okay, actually dump the static file */
		fp = fopen(fullpath, "rb");
		if (!fp) {
			send_response(&req, HTTP_INTERNAL_SERVER_ERROR);
			break;
		}
		fseek(fp, 0L, SEEK_END); /* Go to EOF */
		size = ftell(fp);
		rewind(fp); /* Be kind, rewind */

		/* Assume it's a 200 OK by default */
		req.responsecode = 200;
		req.responselen = size;

		if (req.range) { /* Range header, override */
			if (STARTS_WITH(req.range, "bytes=")) {
				req.responsecode = 206;
			} else {
				free(req.range); /* Just ignore it */
			}
		}

		/* Actually good to go */
		dprintf(req.wfd, "HTTP/1.1 %d %s\r\n", req.responsecode, req.responsecode == 206 ? "Partial Content" : "OK");
		dprintf(req.wfd, "Server: %s\r\n", SERVER_NAME);
		dprintf(req.wfd, "Connection: %s\r\n", req.keepalive ? "keep-alive" : "close"); /* HTTP 1.0 compatibility, assumed default in 1.1+ */
		if (req.keepalive) {
			dprintf(req.wfd, "Keep-Alive: timeout=%d, max=%d\r\n", 1, 1000);
		}

		/* Caching headers */
		if (strftime(timebuf, sizeof(timebuf), STRFTIME_FMT, &modtime) <= 0) { /* returns 0 on failure, o/w number of bytes written */
			bbs_error("strftime failed\n"); /* errno is not set according to strftime(3) man page */
			send_response(&req, HTTP_INTERNAL_SERVER_ERROR);
			break;
		}
		dprintf(req.wfd, "Last-Modified: %s\r\n", timebuf);
		dprintf(req.wfd, "Cache-Control: must-revalidate, max-age=%d\r\n", 60); /* Use Cache-Control instead of Expires */
		dprintf(req.wfd, "Accept-Ranges: bytes\r\n"); /* Advertise RFC 7233 bytes range support */

#define RANGE_SEPARATOR "THIS_STRING_SEPARATES"
		if (req.responsecode == 206) {
			/* Calculate the ranges */
			int rangebytes = 0;
			char rangebuf[256];
			char *range, *ranges = rangebuf;
			/* Calculate the number of parts to transfer */
			safe_strncpy(rangebuf, req.range + STRLEN("bytes="), sizeof(rangebuf));
			while ((range = strsep(&ranges, ","))) {
				int thisrangebytes;
				int a, b;
				thisrangebytes = range_parse(range, size, &a, &b);
				if (thisrangebytes == -1) {
					continue;
				}
				rangeparts++;
				rangebytes += thisrangebytes;
			}
			/* Calculate the real length */
			safe_strncpy(rangebuf, req.range + STRLEN("bytes="), sizeof(rangebuf));
			if (rangeparts > 1) {
				dprintf(req.wfd, "Content-Type: multipart/byteranges; boundary=%s\r\n", RANGE_SEPARATOR);
			} else if (rangeparts == 1) {
				rangebytes = 0;
				while ((range = strsep(&ranges, ","))) {
					int thisrangebytes;
					int a, b;
					thisrangebytes = range_parse(range, size, &a, &b);
					if (thisrangebytes == -1) {
						continue;
					}
					dprintf(req.wfd, rangebytes > 0 ? "/" : "Content-Range: bytes ");
					dprintf(req.wfd, "%d", a);
					if (b != a) {
						dprintf(req.wfd, "-%d", b);
					}
					rangebytes += thisrangebytes;
				}
				dprintf(req.wfd, "\r\n"); /* End this header */
			} else {
				break; /* Invalid */
			}
			req.responselen = rangebytes;
		} else if (!mime_type(fullpath, mime, sizeof(mime))) {
			dprintf(req.wfd, "Content-Type: %s\r\n", mime);
		}
		dprintf(req.wfd, "Content-Length: %d\r\n", req.responselen);
		dprintf(req.wfd, "\r\n"); /* End the response headers */

		if (req.method == HTTP_HEAD) {
			/* Don't actually send the body */
			fclose(fp);
			continue;
		}

		bbs_debug(3, "Sending file '%s' (%d bytes)\n", fullpath, size);

		if (req.range) {
			/* Calculate the ranges */
			int rangebytes = 0;
			char rangebuf[256];
			char *range, *ranges = rangebuf;
			/* Calculate the real length */
			safe_strncpy(rangebuf, req.range + STRLEN("bytes="), sizeof(rangebuf));
			while ((range = strsep(&ranges, ","))) {
				int thisrangebytes;
				int a, b;
				thisrangebytes = range_parse(range, size, &a, &b);
				if (thisrangebytes == -1) {
					continue;
				}

				if (rangeparts > 1) {
					dprintf(req.wfd, "--%s\r\n", RANGE_SEPARATOR);
					dprintf(req.wfd, "Content-Range: bytes ");
					dprintf(req.wfd, "%d", a);
					if (b != a) {
						dprintf(req.wfd, "-%d", b);
					}
					rangebytes += thisrangebytes;
				}

				/* Send this chunk */
				offset = a;
				size = thisrangebytes;
				res = sendfile(req.wfd, fileno(fp), &offset, size);
				if (res != size) {
					bbs_error("sendfile failed for range (%d != %d): %s\n", res, size, strerror(errno));
					break; /* This is fatal, just bail immediately. The client will know the request failed since the response body won't match the response headers. */
				}
			}
		} else {
			offset = 0;
			res = sendfile(req.wfd, fileno(fp), &offset, size); /* We must manually tell it the offset or it will be at the EOF, even with rewind() */
			if (res != size) {
				bbs_error("sendfile failed (%d): %s\n", res, strerror(errno));
				break; /* This is fatal, just bail immediately */
			}
		}
		fclose(fp);
	}

cleanup:
	/* From the last request */
	if (req.method != HTTP_UNDEF) {
		LOG_REQ();
		http_req_destroy(&req);
	}

#ifdef HAVE_OPENSSL
	if (secure) { /* implies ssl */
		ssl_close(ssl);
		ssl = NULL;
	}
#endif
}

static void *__http_handler(void *varg)
{
	struct bbs_node *node = varg;

	node->thread = pthread_self();
	bbs_node_begin(node);

	http_handler(node, !strcmp(node->protname, "HTTPS") ? 1 : 0); /* Actually handle the HTTP/HTTPS client */

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

/*! \brief Single listener thread for HTTP and/or HTTPS */
static void *http_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener2(http_socket, https_socket, "HTTP", "HTTPS", __http_handler, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_http.conf", 0);
	if (!cfg) {
		return -1; /* Decline to load if there is no config. */
	}

	/* General */
	if (bbs_config_val_set_path(cfg, "general", "docroot", http_docroot, sizeof(http_docroot))) {
		return -1;
	}
	bbs_config_val_set_true(cfg, "general", "cgi", &cgi); /* Allow Common Gateway Interface? */
	bbs_config_val_set_true(cfg, "general", "authonly", &authonly);

	/* HTTP */
	bbs_config_val_set_true(cfg, "http", "enabled", &http_enabled);
	bbs_config_val_set_port(cfg, "http", "port", &http_port);

	/* HTTPS */
	bbs_config_val_set_true(cfg, "https", "enabled", &https_enabled);
	bbs_config_val_set_port(cfg, "https", "port", &https_port);

	if (!http_enabled && !https_enabled) {
		return -1; /* Nothing is enabled. */
	}

	if (https_enabled && !ssl_available()) {
		bbs_error("TLS is not available, HTTPS may not be used\n");
		return -1;
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}

	/* If we can't start the TCP listeners, decline to load */
	if (http_enabled && bbs_make_tcp_socket(&http_socket, http_port)) {
		return -1;
	}
	/* If we get this far, and HTTPS is enabled, we're allowed to use it. */
	if (https_enabled && bbs_make_tcp_socket(&https_socket, https_port)) {
		close_if(http_socket);
		return -1;
	}

	if (bbs_pthread_create(&http_listener_thread, NULL, http_listener, NULL)) {
		bbs_error("Unable to create HTTP listener thread.\n");
		close_if(http_socket);
		close_if(https_socket);
		return -1;
	}

	if (http_enabled) {
		bbs_register_network_protocol("HTTP", http_port);
	}
	if (https_enabled) {
		bbs_register_network_protocol("HTTPS", https_port);
	}
	return 0;
}

static int unload_module(void)
{
	pthread_cancel(http_listener_thread);
	pthread_kill(http_listener_thread, SIGURG);
	bbs_pthread_join(http_listener_thread, NULL);
	if (http_enabled) {
		close_if(http_socket);
		bbs_unregister_network_protocol(http_port);
	}
	if (https_enabled) {
		close_if(https_socket);
		bbs_unregister_network_protocol(https_port);
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC2616 HTTP 1.1 Web Server");
