/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief HTTP Server
 *
 */

#define RANGE_SEPARATOR "THIS_STRING_SEPARATES"

enum http_method {
	HTTP_METHOD_UNDEF = 0,
	HTTP_METHOD_OPTIONS = (1 << 0),
	HTTP_METHOD_HEAD = (1 << 1),
	HTTP_METHOD_GET = (1 << 2),
	HTTP_METHOD_POST = (1 << 3),
	HTTP_METHOD_PUT = (1 << 4),
	HTTP_METHOD_DELETE = (1 << 5),
	HTTP_METHOD_TRACE = (1 << 6),
	HTTP_METHOD_CONNECT = (1 << 7),
};

enum http_version {
	HTTP_VERSION_UNKNOWN = 0,
	HTTP_VERSION_0_9 = (1 << 0),
	HTTP_VERSION_1_0 = (1 << 1),
	HTTP_VERSION_1_1 = (1 << 2),
	HTTP_VERSION_2 = (1 << 3),
	HTTP_VERSION_3 = (1 << 4),
};

#define HTTP_VERSION_1_1_OR_NEWER (HTTP_VERSION_1_1 | HTTP_VERSION_2 | HTTP_VERSION_3)

enum http_response_code {
	/* Not all defined HTTP response codes are present here,
	 * only those relevant or possibly relevant to this implementation. */
	HTTP_CONTINUE = 100,
	HTTP_SWITCHING_PROTOCOLS = 101,
	HTTP_OK = 200,
	HTTP_CREATED = 201,
	HTTP_NO_CONTENT = 204,
	HTTP_PARTIAL_CONTENT = 206,
	HTTP_REDIRECT_PERMANENT = 301,
	HTTP_REDIRECT_FOUND = 302,
	HTTP_NOT_MODIFIED_SINCE = 304,
	HTTP_REDIRECT_TEMPORARY = 307,
	HTTP_BAD_REQUEST = 400,
	HTTP_UNAUTHORIZED = 401,
	HTTP_FORBIDDEN = 403,
	HTTP_NOT_FOUND = 404,
	HTTP_NOT_ALLOWED = 405,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_GONE = 410,
	HTTP_CONTENT_TOO_LARGE = 413,
	HTTP_URI_TOO_LONG = 414,
	HTTP_RANGE_UNAVAILABLE = 416,
	HTTP_EXPECTATION_FAILED = 417,
	HTTP_IM_A_TEAPOT = 418,
	HTTP_TOO_MANY_REQUESTS = 429,
	HTTP_REQUEST_HEADERS_TOO_LARGE = 431,
	HTTP_INTERNAL_SERVER_ERROR = 500,
	HTTP_NOT_IMPLEMENTED = 501,
	HTTP_BAD_GATEWAY = 502,
	HTTP_SERVICE_UNAVAILABLE = 503,
	HTTP_GATEWAY_TIMEOUT = 504,
	HTTP_VERSION_NOT_SUPPORTED = 505,
};

struct post_field {
	const char *name;		/* Name of POST field */
	const char *type;		/* Content-Type, if available */
	const char *filename;	/* For files, name of file */
	unsigned char *buffer;	/* For non files */
	char tmpfile[128];		/* For files, path to tmp file */
	size_t length;			/* Length of data */
	RWLIST_ENTRY(post_field) entry;
	char data[];
};

RWLIST_HEAD(post_fields, post_field);

struct session;

struct http_request {
	enum http_method method;
	enum http_version version;
	size_t contentlength;
	char *urihost;
	char *uri;
	struct bbs_vars headers;
	struct bbs_vars cookies;
	struct bbs_vars queryparams;	/*!< Query parameters in the GET URI */
	struct post_fields postfields;	/*!< Parameters in the POST body */
	struct session *session;
	char *username;			/*!< Basic Authentication username (not necessarily authenticated, check http->node->user for that) */
	unsigned char *body;
	struct tm modsince;
	int numheaders;
	/* Pointers to allocated data */
	const char *host;
	const char *querystring;
	/* Flags */
	unsigned int keepalive:1;
	unsigned int ifmodsince:1;
	unsigned int httpsupgrade:1;
	unsigned int chunked:1;		/*!< Request uses chunked transfer encoding */
	unsigned int expect100:1;	/*!< Expecting 100-continue */
	unsigned int parsedbody:1;
};

struct http_response {
	enum http_response_code code;
	size_t contentlength;
	size_t sentbytes;
	struct bbs_vars headers;
	char chunkbuf[BUFSIZ];
	size_t chunkedbytes;		/*!< Bytes chunked in buffer */
	size_t chunkedleft;			/*!< Space left in buffer */
	/* Flags */
	unsigned int sentheaders:1;
	unsigned int sent100:1;		/*!< Sent 100 continue */
	unsigned int chunked:1;		/*!< Response uses chunked transfer encoding */
};

struct http_session {
	struct http_request *req;
	struct http_response *res;
	struct http_request reqstack;
	struct http_response resstack;
	struct bbs_node *node;
	struct readline_data *rldata;
	int rfd;
	int wfd;
	unsigned int secure:1;
};

/*!
 * \brief Parse an HTTP request that is pending on an http_session's node's file descriptor
 * \note Do not use this function directly unless needed; this is primarily internal and only used externally by net_wss.
 * \retval 0 on success, -1 or HTTP status code on failure
 */
int http_parse_request(struct http_session *http, char *buf);

/*!
 * \brief Free an HTTP request's contents
 * \note Do not use this function directly unless needed; this is primarily internal and only used externally by net_wss.
 */
void http_request_cleanup(struct http_request *req);

/*!
 * \brief Set an HTTP response header
 * \param http
 * \param header Header name. If a header has already been set, it will be replaced.
 * \param value Header value
 * \retval 0 on success, -1 on failure
 */
int http_set_header(struct http_session *http, const char *header, const char *value);

/*!
 * \brief Redirect an HTTP request to the HTTPS version of the site
 * \param http
 * \param port HTTPS port for the application
 * \retval HTTP response code to return
 * \warning This function must NOT be called for HTTPS requests, or it will send the client into a redirect loop
 */
enum http_response_code http_redirect_https(struct http_session *http, int port);

/*!
 * \brief Send a Strict-Transport-Security header to instruct the client to use HSTS
 * \param http
 * \param maxage Seconds for max-age attribute (should be greater than 0)
 */
void http_enable_hsts(struct http_session *http, unsigned int maxage);

/*!
 * \brief Redirect an HTTP client to a new location
 * \param http
 * \param code Redirect response code
 * \param location Redirect URI
 * \retval 0 on success, -1 on failure
 */ 
int http_redirect(struct http_session *http, enum http_response_code code, const char *location);

/*!
 * \brief Write bytes of an HTTP response body
 * \param http
 * \param buf
 * \param len Number of bytes to write
 */
void http_write(struct http_session *http, const char *buf, size_t len);

/*! \brief Same as http_write, but accept printf-style arguments */
int __attribute__ ((format (gnu_printf, 2, 3))) http_writef(struct http_session *http, const char *fmt, ...);

/*!
 * \brief Get an HTTP request header, if it exists
 * \param http
 * \param header
 * \return Header value, or NULL if header not present
 */
const char *http_request_header(struct http_session *http, const char *header);

/*!
 * \brief Get an HTTP cookie, if it exists
 * \param http
 * \param cookie Name of cookie
 * \return Cookie value, or NULL if cookie not foun
 */
const char *http_get_cookie(struct http_session *http, const char *cookie);

/*!
 * \brief Set an HTTP cookie
 * \param http
 * \param name Cookie name
 * \param value Cookie value
 * \param secure Whether the cookie will only be accessible on secure connections
 * \param maxage Number of seconds for which cookie should be valid
 */
int http_set_cookie(struct http_session *http, const char *name, const char *value, int secure, int maxage);

/*! \brief Regenerate Session ID (to prevent session fixation) */
int http_session_regenerate(struct http_session *http);

/*! \brief Destroy (end) a session */
int http_session_destroy(struct http_session *http);

/*!
 * \brief Start a session
 * \param http
 * \param secure Whether the session should only be accessible for secure connections
 * \retval 0 on success, -1 on failure
 */
int http_session_start(struct http_session *http, int secure);

/*!
 * \brief Get a session variable
 * \param http
 * \param name Name of session variable
 * \return NULL it no session or variable not found
 * \return Session variable
 * \warning The returned variable is not protected
 */
const char *http_session_var(struct http_session *http, const char *name);

/*!
 * \brief Set a session variable
 * \param http
 * \param name Name of session variable
 * \param value
 * \retval 0 on success, -1 on failure
 */
int http_session_set_var(struct http_session *http, const char *name, const char *value);

/*! \brief Whether a websocket upgrade was requested by the client */
int http_websocket_upgrade_requested(struct http_session *http);

/*!
 * \brief Complete a websocket handshake with the client
 * \retval 0 if connection was successfully upgraded
 * \retval -1 if handshake failed (connection should be aborted by the application by returning HTTP_BAD_REQUEST)
 */
int http_websocket_handshake(struct http_session *http);

/*!
 * \brief Get an HTTP POST field, if it exists
 * \param http
 * \param name Name of POST field
 * \return POST field, or NULL if not found
 */
struct post_field *http_post_param(struct http_session *http, const char *name);

/*!
 * \brief Serve a single, static file
 * \param http
 * \param Full path to file to serve
 * \param st stat structure if available already, NULL otherwise
 * \return HTTP response code
 * \note Avoid using this function directly if possible. Use http_serve_static_or_cgi instead.
 */
enum http_response_code http_static(struct http_session *http, const char *filename, struct stat *st);

/*!
 * \brief Execute a CGI script
 * \param http
 * \param Full path to file to serve
 * \param docroot Document root
 * \return HTTP response code
 * \note Avoid using this function directly if possible. Use http_serve_static_or_cgi instead.
 */
enum http_response_code http_cgi(struct http_session *http, const char *filename, const char *docroot);

/*!
 * \brief Serve static files or CGI content
 * \param http
 * \param uri Relative portion of URI to use to find files.
 * \param docroot Document root from which to serve static files. NULL for no static file serving.
 * \param dirlist Display directory contents (listing) if a directory is requested (equivalent to Options +Indexes in Apache HTTP server)
 * \param cgi Allow executable (CGI) content serving
 * \param cgiext Optional default extension to apply for serving CGI content (e.g. .php)
 * \return HTTP response code
 */
enum http_response_code http_serve_static_or_cgi(struct http_session *http, const char *uri, const char *docroot, int dirlist, int cgi, const char *cgiext);

/*!
 * \brief Set the default HTTP application port
 * \param port Non-negative default port for HTTP, or -1 if not configured
 */
void http_set_default_http_port(int port);

/*!
 * \brief Set the default HTTPS application port
 * \param port Non-negative default port for HTTPS, or -1 if not configured
 */
void http_set_default_https_port(int port);

/*!
 * \brief Get the default HTTP application port
 * \retval HTTP application port, or -1 if not configured
 * \note Modules that use this function must explicitly have a dependency on net_http (the module that sets these ports)
 */
int http_get_default_http_port(void);

/*!
 * \brief Get the default HTTPS application port
 * \retval HTTPS application port, or -1 if not configured
 * \note Modules that use this function must explicitly have a dependency on net_http (the module that sets these ports)
 */
int http_get_default_https_port(void);

#define http_register_insecure_route(hostname, port, prefix, methods, handler) http_register_route(hostname, port, 0, prefix, methods, handler)
#define http_register_secure_route(hostname, port, prefix, methods, handler) http_register_route(hostname, port, 1, prefix, methods, handler)
#define http_register_route(hostname, port, secure, prefix, methods, handler) __http_register_route(hostname, port, secure, prefix, methods, handler, BBS_MODULE_SELF)

/*!
 * \brief Register an HTTP route
 * \param hostname Hostname. NULL for all/any hosts.
 * \param port Port number
 * \param secure Whether this is an HTTPS port or not
 * \param prefix The URI prefix that must match. If NULL, this will be used as the default route (e.g. serve static files)
 * \param methods Mask of matching HTTP methods
 * \param handler Callback function to handle the route
 * \param mod Handle to registering module */
int __http_register_route(const char *hostname, unsigned short int port, unsigned int secure, const char *prefix, enum http_method methods, enum http_response_code (*handler)(struct http_session *http), void *mod);

/*! \brief Unregister a route previously registered using __http_register_route */
int http_unregister_route(enum http_response_code (*handler)(struct http_session *http));
