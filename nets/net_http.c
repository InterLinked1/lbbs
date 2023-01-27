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

#define HAVE_OPENSSL

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For hashing: */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/system.h"
#include "include/linkedlists.h"

#define SERVER_NAME BBS_TAGLINE " " BBS_VERSION " Web Server"

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443

#define STRPTIME_FMT "%a, %d %b %Y %T %Z"
#define STRFTIME_FMT "%a, %d %b %Y %T %Z"

static int http_port = DEFAULT_HTTP_PORT;
static int https_port = DEFAULT_HTTPS_PORT;

static pthread_t http_listener_thread = -1;
static char http_docroot[256] = "";
static char ssl_cert[256] = "";
static char ssl_key[256] = "";

static int http_enabled = 0, https_enabled = 0;
static int cgi = 0;
static int authonly = 0;
static int http_socket = -1, https_socket = -1;

/* Basic Authentication performance optimizations.
 * Calling bbs_authenticate on every HTTP request using Basic Authentication is extremely slow.
 * To speed this up, if an authentication is *successful*, we will hash the
 * the password using a fast (but not as secure) one-way hash function
 * and store the username along with this hash in a linked list.
 * Then, on future requests, we can check if the username is in the linked list and, if so,
 * hash the password and see if we get a match.
 * If we do, then we can go ahead and authenticate without actually calling the slow crypt_r.
 * To prevent these hashes from building up in memory, we'll limit the number of hashes
 * we retain to a small number, since this is only relevant for immediate session reuse,
 * and stale hashes can safely be purged.
 *
 * Obviously, using cookies is more robust, but we're trying to keep it simple here.
 */

struct http_user {
	const char *username;
	const char *pwhash;
	RWLIST_ENTRY(http_user) entry;
	char data[0];
};

static RWLIST_HEAD_STATIC(users, http_user);

#define SHA256_BUFSIZE 65

static void hash_sha256(const char *s, char buf[SHA256_BUFSIZE])
{
	int i;
    unsigned char hash[SHA256_DIGEST_LENGTH];

	/* We already use OpenSSL, just use that */
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, s, strlen(s));
    SHA256_Final(hash, &sha256);

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
#undef sprintf
        sprintf(buf + (i * 2), "%02x", hash[i]); /* Safe */
    }
    buf[SHA256_BUFSIZE - 1] = '\0';
}

static void http_user_cache_purge(void)
{
	struct http_user *user;
	while ((user = RWLIST_REMOVE_HEAD(&users, entry))) {
		free(user);
	}
}

static int http_user_cache_add(const char *username, const char *password)
{
	int i = 0;
	char sha256[SHA256_BUFSIZE];
	int usernamelen, sha256len;
	struct http_user *user, *last;

	RWLIST_WRLOCK(&users);
	RWLIST_TRAVERSE(&users, user, entry) {
		i++;
		if (!strcasecmp(user->username, username)) {
			break;
		}
		last = user;
	}
	if (user) {
		/* User already exists */
		bbs_warning("User '%s' already exists in user list?\n", username); /* Shouldn't be calling this function in this case */
		RWLIST_UNLOCK(&users);
		return -1;
	}

	bbs_debug(5, "Currently have %d cached user%s\n", i, ESS(i));

	/* It's a new user we need to add. */
	if (i >= 10) {
		/* If we're at capacity, remove the oldest item from the list to prevent this from growing to oblivion. */
		RWLIST_TRAVERSE_SAFE_BEGIN(&users, user, entry) {
			if (user == last) { /* It's the last one */
				RWLIST_REMOVE_CURRENT(entry);
				free(user);
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
	}

	usernamelen = strlen(username);
	hash_sha256(password, sha256);
	sha256len = strlen(sha256); /* length should be 64 */
	if (sha256len != SHA256_BUFSIZE - 1) {
		bbs_warning("SHA256 result has length %d?\n", sha256len);
	}

	/* Push new user into the queue. */
	user = calloc(1, sizeof(*user) + usernamelen + sha256len + 2); /* Plus 2 NUL terminators */
	if (!user) {
		bbs_error("calloc failed\n");
		return -1;
		RWLIST_UNLOCK(&users);
	}

	user->username = user->data;
	strcpy(user->data, username);
	user->pwhash = user->data + usernamelen + 1;
	strcpy(user->data + usernamelen + 1, sha256);

	RWLIST_INSERT_HEAD(&users, user, entry); /* Insert at beginning of list for fastest access */
	RWLIST_UNLOCK(&users);
	return 0;
}

static int http_user_cache_check(const char *username, const char *password)
{
	struct http_user *user;
	int match = 0;

	RWLIST_RDLOCK(&users);
	RWLIST_TRAVERSE(&users, user, entry) {
		if (!strcasecmp(user->username, username)) {
			break;
		}
	}
	if (user) {
		char sha256[SHA256_BUFSIZE];
		hash_sha256(password, sha256);
		if (!strcmp(sha256, user->pwhash)) {
			match = 1;
		}
	} /* else, not found in cache */
	RWLIST_UNLOCK(&users);
	return match;
}

#ifdef HAVE_OPENSSL
SSL_CTX *ssl_ctx = NULL;
#endif

/*! \todo is there an OpenSSL function for this? */
static const char *ssl_strerror(int err)
{
	switch (err) {
	case SSL_ERROR_NONE:
		return "SSL_ERROR_NONE";
	case SSL_ERROR_ZERO_RETURN:
		return "SSL_ERROR_ZERO_RETURN";
	case SSL_ERROR_WANT_READ:
		return "SSL_ERROR_WANT_READ";
	case SSL_ERROR_WANT_WRITE:
		return "SSL_ERROR_WANT_WRITE";
	case SSL_ERROR_WANT_CONNECT:
		return "SSL_ERROR_WANT_CONNECT";
	case SSL_ERROR_WANT_ACCEPT:
		return "SSL_ERROR_WANT_ACCEPT";
	case SSL_ERROR_WANT_X509_LOOKUP:
		return "SSL_ERROR_WANT_X509_LOOKUP";
	case SSL_ERROR_SYSCALL:
		return "SSL_ERROR_SYSCALL";
	case SSL_ERROR_SSL:
		return "SSL_ERROR_SSL";
	default:
		break;
	}
	return "Undefined";
}

static int ssl_server_init(void)
{
#ifdef HAVE_OPENSSL
	const SSL_METHOD *method;

	method = TLS_server_method(); /* Server method, not client method! */
	ssl_ctx = SSL_CTX_new(method);

	if (!ssl_ctx) {
		bbs_error("Failed to create SSL context\n");
		return -1;
	}

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL); /* Server is not verifying the client, the client will verify the server */

	if (SSL_CTX_use_certificate_file(ssl_ctx, ssl_cert, SSL_FILETYPE_PEM) <= 0) {
        bbs_error("Could not load certificate file %s: %s\n", ssl_cert, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_key, SSL_FILETYPE_PEM) <= 0) {
        bbs_error("Could not load private key file %s: %s\n", ssl_key, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        bbs_error("Private key does not match public certificate\n");
        return -1;
    }

	return 0;
#else
	return -1; /* Won't happen */
#endif
}

static void ssl_server_shutdown(void)
{
#ifdef HAVE_OPENSSL
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
#endif
}

/* Helper macros to automatically handle writing/reading with SSL */
#ifdef HAVE_SSL_RECV
#define my_recv(ssl, fd, buf, len, flags) (ssl ? SSL_recv(ssl, buf, len, flags) : recv(fd, buf, len, flags)
#endif
#define my_read(ssl, fd, buf, len) (ssl ? SSL_read(ssl, buf, len) : read(fd, buf, len))
#define my_write(ssl, fd, buf, len) (ssl ? SSL_write(ssl, buf, len) : write(fd, buf, len))
#define my_readline(ssl, fd, buf, len) SSL_readline(ssl, buf, len)

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

/*! \todo move to base64.c? */
static const unsigned char decoding_table[256] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,
0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*! \note Modified and amalgamated from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c/64856489 */
static unsigned char *base64_decode(const unsigned char *data, int input_length, int *outlen)
{
	int i, j;
	int output_length;
	unsigned char *decoded_data;

	if (input_length % 4 != 0) {
		return NULL;
	}

	output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') {
		(output_length)--;
	}
	if (data[input_length - 2] == '=') {
		(output_length)--;
	}

	decoded_data = (unsigned char*) malloc(output_length + 1);
	if (!decoded_data) {
		return NULL;
	}

	for (i = 0, j = 0; i < input_length;) {
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

		if (j < output_length) {
			decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		}
		if (j < output_length) {
			decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		}
		if (j < output_length) {
			decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
		}
	}

	*outlen = output_length;
	decoded_data[output_length] = '\0';
	return decoded_data;
}

/*! \brief If client sends a header twice, don't leak memory. */
#define HEADER_DUP(var) \
	free_if(var); \
	var = strdup(value);

static inline int parse_header(struct http_req *req, char *s)
{
	char *tmp, *query, *header, *value = s;

	bbs_strterm(s, '\r');
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
			bbs_warning("Unknown HTTP request method: %s\n", tmp);
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
		if (!*(tmp + 1)) {
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
				free_if(req->remoteuser);
				req->remoteuser = strdup(username);

				if (http_user_cache_check(username, password)) {
					/* Manually attach a user to this node.
					 * This won't update last_login, but that's probably fine, since this is cached. */
					if (req->node->user) {
						bbs_user_destroy(req->node->user);
					}
					req->node->user = bbs_user_info_by_username(username);
					bbs_debug(3, "User reauthenticated as %s using cache\n", username);
				} else if (!bbs_authenticate(req->node, username, password)) {
					http_user_cache_add(username, password); /* Successful auth? Cache it */
				}
				/* Destroy the password before freeing it */
				memset(decoded, 0, outlen);
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
	safe_strncpy(buf, mime, len);
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
	if (eaccess(buf, F_OK)) { /* It doesn't even exist. */
		return 0;
	}
	return 1;
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
	FILE *clientfp;
	struct http_req req;
	char fullpath[PATH_MAX];
	int nreq;
	int rfd, wfd;

	memset(&req, 0, sizeof(req));
	req.node = node;
	req.method = HTTP_UNDEF;

	/* Start TLS if we need to */
	if (secure) {
#ifdef HAVE_OPENSSL
		ssl = SSL_new(ssl_ctx);
		if (!ssl) {
			bbs_error("Failed to create SSL\n");
			return;
		}
		SSL_set_fd(ssl, node->fd);
		res = SSL_accept(ssl);
		if (res != 1) {
			int sslerr = SSL_get_error(ssl, res);
			bbs_error("SSL error %d: %d (%s = %s)\n", res, sslerr, ssl_strerror(sslerr), ERR_error_string(ERR_get_error(), NULL));
			goto cleanup; /* Disconnect. */
		}
		req.ssl = ssl;
		rfd = req.rfd = SSL_get_rfd(ssl);
		wfd = req.wfd = SSL_get_wfd(ssl);
#else
		bbs_assert(0); /* Can't happen */
#endif
	} else {
		rfd = wfd = req.rfd = req.wfd = node->fd;
	}

	clientfp = fdopen(req.rfd, "r");
	if (!clientfp) {
		bbs_error("fdopen failed: %s\n", strerror(errno));
		goto cleanup;
	}

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

		/* Start processing headers... yes, this limits on LF, but the CR should immediately precede it. */
		while ((fgets(buf, sizeof(buf), clientfp))) {
#if 0
			bbs_debug(10, "Got: %s", buf); /* Don't add another LF */
#endif
			if (!strcmp(buf, "\r\n")) { /* End of request headers */
				complete = 1;
				break;
			}
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
		if (strstr(req.path, "..")) {
			/* We could use realpath, but this just isn't a valid web path */
			send_response(&req, HTTP_FORBIDDEN);
			continue;
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
		if (eaccess(fullpath, F_OK)) { /* It doesn't even exist. */
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

	if (clientfp) {
		fclose(clientfp);
	}
#ifdef HAVE_OPENSSL
	if (secure) { /* implies ssl */
		SSL_free(ssl);
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
	/* Avoid using the bbs_tcp_listener function, even though it's convenient,
	 * because HTTP requests are stateless, and bbs_tcp_listener would
	 * create and destroy a node for every single HTTP request. */

	struct sockaddr_in sinaddr;
	socklen_t len;
	int sfd, res;
	struct pollfd pfds[2];
	int nfds = 0;
	struct bbs_node *node;
	char new_ip[56];

	UNUSED(unused);

	if (http_socket != -1) {
		pfds[nfds].fd = http_socket;
		pfds[nfds].events = POLLIN;
		nfds++;
	}
	if (https_socket != -1) {
		pfds[nfds].fd = https_socket;
		pfds[nfds].events = POLLIN;
		nfds++;
	}

	bbs_assert(nfds); /* Why would we have spawned a listener if we're not listening? */
	bbs_debug(1, "Started HTTP/HTTPS listener thread\n");

	for (;;) {
		int secure;
		res = poll(pfds, nfds, -1); /* Wait forever for an incoming connection. */
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (pfds[0].revents) {
			len = sizeof(sinaddr);
			sfd = accept(pfds[0].fd, (struct sockaddr *) &sinaddr, &len);
			bbs_get_remote_ip(&sinaddr, new_ip, sizeof(new_ip));
			bbs_debug(1, "Accepting new %s connection from %s\n", pfds[0].fd == http_socket ? "HTTP" : "HTTPS", new_ip);
			secure = pfds[0].fd == https_socket;
		} else if (pfds[1].revents) {
			len = sizeof(sinaddr);
			sfd = accept(pfds[1].fd, (struct sockaddr *) &sinaddr, &len);
			bbs_get_remote_ip(&sinaddr, new_ip, sizeof(new_ip));
			bbs_debug(1, "Accepting new %s connection from %s\n", pfds[1].fd == http_socket ? "HTTP" : "HTTPS", new_ip); /* Must be HTTPS, technically */
			secure = pfds[1].fd == https_socket;
		} else {
			bbs_error("No revents?\n");
			continue; /* Shouldn't happen? */
		}
		if (sfd < 0) {
			if (errno != EINTR) {
				bbs_warning("accept returned %d: %s\n", sfd, strerror(errno));
				break;
			}
			continue;
		}

		node = bbs_node_request(sfd, secure ? "HTTPS" : "HTTP");
		if (!node) {
			close(sfd);
		} else if (bbs_save_remote_ip(&sinaddr, node)) {
			bbs_node_unlink(node);
		} else if (bbs_pthread_create_detached(&node->thread, NULL, __http_handler, node)) { /* Run the BBS on this node */
			bbs_node_unlink(node);
		}
	}
	/* Normally, we never get here, as pthread_cancel snuffs out the thread ungracefully */
	bbs_warning("HTTP/HTTPS listener thread exiting abnormally\n");
	return NULL;
}

static int load_config(void)
{
	char *tmp;
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_http.conf", 0);
	if (!cfg) {
		return -1; /* Decline to load if there is no config. */
	}

	/* General */
	bbs_config_val_set_str(cfg, "general", "docroot", http_docroot, sizeof(http_docroot));
	bbs_config_val_set_true(cfg, "general", "cgi", &cgi); /* Allow Common Gateway Interface? */
	bbs_config_val_set_true(cfg, "general", "authonly", &authonly);
	/* Must not contain trailing slash */
	tmp = strrchr(http_docroot, '/');
	if (tmp && !*(tmp + 1)) {
		*tmp = '\0';
	}

	/* HTTP */
	bbs_config_val_set_true(cfg, "http", "enabled", &http_enabled);
	bbs_config_val_set_port(cfg, "http", "port", &http_port);

	/* HTTPS */
	bbs_config_val_set_true(cfg, "https", "enabled", &https_enabled);
	bbs_config_val_set_port(cfg, "https", "port", &https_port);
	bbs_config_val_set_str(cfg, "https", "cert", ssl_cert, sizeof(ssl_cert));
	bbs_config_val_set_str(cfg, "https", "key", ssl_key, sizeof(ssl_key));

	if (eaccess(http_docroot, R_OK)) {
		bbs_error("Document root %s does not exist\n", http_docroot);
		return -1;
	}

	if (https_port) {
#ifndef HAVE_OPENSSL
		bbs_error("HTTP module was compiled without OpenSSL, HTTPS may not be used\n");
		return -1;
#else
		if (s_strlen_zero(ssl_cert) || s_strlen_zero(ssl_key)) {
			bbs_error("An SSL certificate and private key must be provided to use HTTPS\n");
			return -1;
		}
#endif
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
	if (https_enabled && bbs_make_tcp_socket(&https_socket, https_port)) {
		close_if(http_socket);
		return -1;
	}

	if (https_enabled) {
		if (ssl_server_init()) {
			close_if(http_socket);
			close_if(https_socket);
			return -1;
		}
	}

	if (bbs_pthread_create(&http_listener_thread, NULL, http_listener, NULL)) {
		bbs_error("Unable to create HTTP listener thread.\n");
		close_if(http_socket);
		close_if(https_socket);
		ssl_server_shutdown();
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
		bbs_unregister_network_protocol(http_port);
	}
	if (https_enabled) {
		bbs_unregister_network_protocol(https_port);
		ssl_server_shutdown();
	}
	http_user_cache_purge();
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC2616 HTTP 1.1 Web Server");
