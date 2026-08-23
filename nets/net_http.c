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

#include <limits.h> /* use PATH_MAX */

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/transfer.h"

/* Needed for mod_http.h */
#include "include/linkedlists.h"
#include "include/variables.h"

#include "include/mod_http.h"

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443

static int http_port = DEFAULT_HTTP_PORT;
static int https_port = DEFAULT_HTTPS_PORT;

static char http_docroot[256] = "";

static int http_enabled = 0, https_enabled = 0;
static int allow_cgi = 0;
static int authonly = 0;
static int forcehttps;
static unsigned int hsts_max_age = 0;
static int forcesessions = 0;

/*! \brief Serve static files in users' home directories' public_html directories */
static enum http_response_code home_dir_handler(struct http_session *http)
{
	char tmpbuf[64];
	char user_home_dir[PATH_MAX];
	unsigned int userid;
	const char *uri;
	const char *slash, *username;

	if (!http->secure && forcehttps) {
		return http_redirect_https(http, https_port);
	}
	if (http->secure && hsts_max_age) {
		http_enable_hsts(http, hsts_max_age);
	}
	if (forcesessions && http_session_start(http, 0)) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	username = http->req->uri + STRLEN("/~"); /* Guaranteed to be at least length 2 */
	if (strlen_zero(username)) {
		return HTTP_NOT_FOUND;
	}
	if (authonly && !bbs_user_is_registered(http->node->user)) {
		return HTTP_UNAUTHORIZED;
	}
	slash = strchr(username, '/');
	if (slash) {
		size_t bytes = (size_t) (slash - username);
		if (bytes < 1 || bytes >= sizeof(tmpbuf)) {
			return HTTP_NOT_FOUND; /* Don't overrun the buffer. Real usernames aren't this long anyways. */
		}
		/* Copy portion to next / (but not including the /), which will give us the username part of the URL
		 * This avoids copying the rest of the URL, which we don't care about here. */
		memcpy(tmpbuf, username, bytes);
		tmpbuf[bytes] = '\0';
		username = tmpbuf;
	}
	userid = bbs_userid_from_username(username);
	if (!userid) {
		bbs_debug(6, "No such user '%s'\n", username);
		return HTTP_NOT_FOUND;
	}
	if (bbs_transfer_home_config_subdir(userid, "public_html", user_home_dir, sizeof(user_home_dir))) {
		return HTTP_INTERNAL_SERVER_ERROR; /* Will still return 0 if directory does not exist, so this is a serious error */
	}
	uri = http->req->uri + STRLEN("/~") + strlen(username);
	return http_serve_static_or_cgi(http, uri, user_home_dir, 1, 0, NULL); /* Serve only static files (no CGI) */
}

/*! \brief Serve static files and CGI scripts in the configured docroot */
static enum http_response_code default_handler(struct http_session *http)
{
	if (!http->secure && forcehttps) {
		return http_redirect_https(http, https_port);
	}
	if (http->secure && hsts_max_age) {
		http_enable_hsts(http, hsts_max_age);
	}
	if (forcesessions && http_session_start(http, 0)) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (authonly && !bbs_user_is_registered(http->node->user)) {
		return HTTP_UNAUTHORIZED;
	}
	return http_serve_static_or_cgi(http, http->req->uri, http_docroot, 1, allow_cgi, NULL); /* Serve content corresponding to entire URI portion */
}

struct virtualhost {
	const char *hostname;
	const char *docroot;
	unsigned short int port;
	unsigned int hsts_max_age;
	unsigned int tls:1;
	unsigned int dirlist:1;
	unsigned int cgi:1;
	unsigned int authonly:1;
	unsigned int forcesessions:1;
	RWLIST_ENTRY(virtualhost) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(virtualhosts, virtualhost);

/*! \brief Serve static files and CGI scripts in the configured virtualhost docroot */
static enum http_response_code virtualhost_handler(struct http_session *http, void *cbdata)
{
	struct virtualhost *v = cbdata;
	if (v->tls && v->hsts_max_age) {
		http_enable_hsts(http, v->hsts_max_age);
	}
	if (v->forcesessions && http_session_start(http, 0)) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (v->authonly && !bbs_user_is_registered(http->node->user)) {
		return HTTP_UNAUTHORIZED;
	}
	return http_serve_static_or_cgi(http, http->req->uri, v->docroot, v->dirlist, v->cgi, NULL); /* Serve content corresponding to entire URI portion */
}

static int register_virtualhost(struct virtualhost *v)
{
	return http_register_virtualhost(v->hostname, v->port, v->tls, NULL, HTTP_METHOD_HEAD | HTTP_METHOD_GET | HTTP_METHOD_POST, virtualhost_handler, v);
}

static int add_virtualhost(const char *host, const char *docroot, unsigned int hsts, int tls, int dirlist, int cgi, int v_authonly, int v_forcesessions)
{
	struct virtualhost *v, *v2;
	const char *colon;
	size_t hostlen;

	if (!docroot) {
		bbs_error("Missing docroot for virtualhost %s\n", host);
	}

	hostlen = strlen(host);
	v = calloc(1, sizeof(*v) + hostlen + strlen(docroot) + 2);
	if (ALLOC_FAILURE(v)) {
		return -1;
	}
	bbs_strncpy_until(v->data, host, hostlen, ':');
	v->hostname = v->data;

	strcpy(v->data + hostlen + 1, docroot); /* Safe */
	v->docroot = v->data + hostlen + 1;

	colon = strchr(host, ':');
	if (colon) {
		colon++;
		v->port = (unsigned short int) atoi(colon);
	} else {
		v->port = 0;
	}
	v->hsts_max_age = hsts;
	SET_BITFIELD(v->tls, tls);
	SET_BITFIELD(v->dirlist, dirlist);
	SET_BITFIELD(v->cgi, cgi);
	SET_BITFIELD(v->authonly, v_authonly);
	SET_BITFIELD(v->forcesessions, v_forcesessions);
	RWLIST_TRAVERSE(&virtualhosts, v2, entry) {
		if (v->port == v2->port && !strcasecmp(v->hostname, v2->hostname)) {
			bbs_error("Duplicate virtualhost %s\n", host);
			free(v);
			return -1;
		}
	}
	RWLIST_INSERT_TAIL(&virtualhosts, v, entry);
	return 0;
}

static void remove_virtualhost(struct virtualhost *v)
{
	http_unregister_virtualhost(v);
	free(v);
}

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	forcehttps = ssl_available(); /* Default depends on whether TLS is available. */

	cfg = bbs_config_load("net_http.conf", 0);
	if (!cfg) {
		return -1; /* Decline to load if there is no config. */
	}

	/* General */
	if (bbs_config_val_set_path(cfg, "general", "docroot", http_docroot, sizeof(http_docroot))) {
		bbs_warning("No document root is specified, web server will be disabled\n");
		bbs_config_unlock(cfg);
		return -1;
	}
	bbs_config_val_set_true(cfg, "general", "cgi", &allow_cgi); /* Allow Common Gateway Interface? */
	bbs_config_val_set_true(cfg, "general", "authonly", &authonly);
	bbs_config_val_set_true(cfg, "general", "forcehttps", &forcehttps);
	bbs_config_val_set_uint(cfg, "general", "hsts", &hsts_max_age);
	bbs_config_val_set_true(cfg, "general", "forcesessions", &forcesessions);

	/* HTTP */
	bbs_config_val_set_true(cfg, "http", "enabled", &http_enabled);
	bbs_config_val_set_port(cfg, "http", "port", &http_port);

	/* HTTPS */
	bbs_config_val_set_true(cfg, "https", "enabled", &https_enabled);
	bbs_config_val_set_port(cfg, "https", "port", &https_port);

	if (!https_enabled) {
		forcehttps = 0;
	}

	if (!http_enabled && !https_enabled) {
		bbs_warning("Neither HTTP nor HTTPS is enabled, web server will be disabled\n");
		bbs_config_unlock(cfg);
		return -1; /* Nothing is enabled. */
	}

	if (https_enabled && !ssl_available()) {
		bbs_error("TLS is not available, HTTPS may not be used\n");
		bbs_config_unlock(cfg);
		return -1;
	}

	RWLIST_WRLOCK(&virtualhosts);
	while ((section = bbs_config_walk(cfg, section))) {
		if (strchr(bbs_config_section_name(section), ':')) {
			struct bbs_keyval *keyval = NULL;
			const char *docroot = NULL;
			int tls = 0, dirlist = 0, cgi = 0, v_authonly = 0, v_forcesessions = 0;
			unsigned int hsts = 0;
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				if (!strcasecmp(bbs_keyval_key(keyval), "docroot")) {
					docroot = bbs_keyval_val(keyval);
				} else if (!strcasecmp(bbs_keyval_key(keyval), "hsts")) {
					hsts = (unsigned int) atoi(bbs_keyval_val(keyval));
				} else if (!strcasecmp(bbs_keyval_key(keyval), "tls")) {
					tls = S_TRUE(bbs_keyval_val(keyval));
				} else if (!strcasecmp(bbs_keyval_key(keyval), "dirlist")) {
					dirlist = S_TRUE(bbs_keyval_val(keyval));
				} else if (!strcasecmp(bbs_keyval_key(keyval), "cgi")) {
					cgi = S_TRUE(bbs_keyval_val(keyval));
				} else if (!strcasecmp(bbs_keyval_key(keyval), "authonly")) {
					v_authonly = S_TRUE(bbs_keyval_val(keyval));
				} else if (!strcasecmp(bbs_keyval_key(keyval), "forcesessions")) {
					v_forcesessions = S_TRUE(bbs_keyval_val(keyval));
				} else {
					bbs_error("Invalid virtualhost setting '%s'\n", bbs_keyval_key(keyval));
				}
			}
			add_virtualhost(bbs_config_section_name(section), docroot, hsts, tls, dirlist, cgi, v_authonly, v_forcesessions);
		}
	}
	RWLIST_UNLOCK(&virtualhosts);

	bbs_config_unlock(cfg);
	return 0;
}

static int unload_module(void)
{
	RWLIST_WRLOCK_REMOVE_ALL(&virtualhosts, entry, remove_virtualhost);
	http_unregister_route(default_handler);
	http_unregister_route(home_dir_handler);
	http_set_default_http_port(-1);
	http_set_default_https_port(-1);
	return 0;
}

static int load_module(void)
{
	int res = 0;
	if (load_config()) {
		return -1;
	}
	if (http_enabled) {
		res |= http_register_insecure_route(NULL, (unsigned short int) http_port, NULL, HTTP_METHOD_HEAD | HTTP_METHOD_GET | HTTP_METHOD_POST, default_handler);
		res |= http_register_insecure_route(NULL, (unsigned short int) http_port, "/~", HTTP_METHOD_HEAD | HTTP_METHOD_GET, home_dir_handler);
		http_set_default_http_port(http_port);
	}
	if (https_enabled) {
		res |= http_register_secure_route(NULL, (unsigned short int) https_port, NULL, HTTP_METHOD_HEAD | HTTP_METHOD_GET | HTTP_METHOD_POST, default_handler);
		res |= http_register_secure_route(NULL, (unsigned short int) https_port, "/~", HTTP_METHOD_HEAD | HTTP_METHOD_GET, home_dir_handler);
		http_set_default_https_port(https_port);
	}
	if (!res) {
		struct virtualhost *v;
		RWLIST_RDLOCK(&virtualhosts);
		RWLIST_TRAVERSE(&virtualhosts, v, entry) {
			register_virtualhost(v);
		}
		RWLIST_UNLOCK(&virtualhosts);
	}
	return res ? unload_module() : res;
}

BBS_MODULE_INFO_DEPENDENT("HTTP Web Server", "mod_http.so");
