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
 * \brief WebSocket Webmail Backend Server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <ctype.h>

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/user.h"
#include "include/utils.h"
#include "include/json.h"
#include "include/base64.h"

#include "include/net_ws.h"

#include <libetpan/libetpan.h>

#define IDLE_REFRESH_EXISTS (1 << 0)
#define IDLE_REFRESH_EXPUNGE (1 << 1)
#define IDLE_REFRESH_FETCH (1 << 2)
#define IDLE_REFRESH_STATUS (1 << 3)

struct imap_client {
	struct mailimap *imap;
	struct ws_session *ws;
	int imapfd;			/* File descriptor, important for polling an idle connection */
	time_t idlestart;	/* Time that IDLE started, to avoid timing out */
	int idlerefresh;	/* Reasons for refreshing page listing during IDLE */
	/* Cache */
	int page;
	int pagesize;
	int start;
	int end;
	/* Cached */
	char *mailbox;		/* Current mailbox name */
	uint32_t messages;	/* Cached number of messages in selected mailbox */
	uint32_t uid;		/* Current message UID */
	/* Flags */
	unsigned int authenticated:1;	/* Logged in yet? */
	unsigned int canidle:1;
	unsigned int idling:1;
	unsigned int has_move:1;
	unsigned int has_sort:1;
	unsigned int has_thread:1;
	unsigned int has_status_size:1;
	unsigned int has_list_status:1;
	unsigned int has_notify:1;
	/* Sorting */
	char *sort;
	char *filter;
};

static unsigned int webmail_log_level = 0;
static FILE *webmail_log_fp = NULL;
static pthread_mutex_t loglock = PTHREAD_MUTEX_INITIALIZER;

static void __attribute__ ((format (gnu_printf, 3, 4))) webmail_log(int level, struct imap_client *client, const char *fmt, ...);

static void webmail_log(int level, struct imap_client *client, const char *fmt, ...)
{
	va_list ap;
	char datestr[20];
	time_t lognow;
	struct tm logdate;
	struct timeval now;

	if (!webmail_log_fp || (unsigned int) level > webmail_log_level) { /* This is static to this file, so we can't do this in a macro. */
		return;
	}

#pragma GCC diagnostic ignored "-Waggregate-return"
	now = bbs_tvnow();
#pragma GCC diagnostic pop
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);

	pthread_mutex_lock(&loglock);
	fprintf(webmail_log_fp, "[%s.%03d] %p: ", datestr, (int) now.tv_usec / 1000, client);

	va_start(ap, fmt);
	vfprintf(webmail_log_fp, fmt, ap);
	va_end(ap);

	pthread_mutex_unlock(&loglock);
	fflush(webmail_log_fp);
}

static void libetpan_log(mailimap *session, int log_type, const char *str, size_t size, void *context)
{
	UNUSED(session);
	UNUSED(context); /* this is a imap_client */

	if (!size) {
		/* Sometimes log messages from libetpan have length 0... ? */
		return;
	}

	switch (log_type) {
		case MAILSTREAM_LOG_TYPE_ERROR_PARSE:
		case MAILSTREAM_LOG_TYPE_ERROR_RECEIVED:
		case MAILSTREAM_LOG_TYPE_ERROR_SENT:
			bbs_warning("[%lu] %.*s", size, (int) size, str); /* Already ends in newline */
		case MAILSTREAM_LOG_TYPE_INFO_RECEIVED:
		case MAILSTREAM_LOG_TYPE_INFO_SENT:
		case MAILSTREAM_LOG_TYPE_DATA_RECEIVED:
		case MAILSTREAM_LOG_TYPE_DATA_SENT:
			break;
		case MAILSTREAM_LOG_TYPE_DATA_SENT_PRIVATE:
			/* Never log */
			break;
	}
}

#define MAILIMAP_ERROR(r) (r != MAILIMAP_NO_ERROR && r != MAILIMAP_NO_ERROR_AUTHENTICATED && r != MAILIMAP_NO_ERROR_NON_AUTHENTICATED)

static int json_send(struct ws_session *ws, json_t *root)
{
	int res = -1;
	char *s = json_dumps(root, 0);
	json_decref(root);
	if (s) {
		size_t len = strlen(s);
		res = websocket_sendtext(ws, s, len);
		free(s);
	} else {
		bbs_warning("Failed to dump JSON string: was it allocated?\n");
	}
	return res;
}

static void client_clear_status(struct ws_session *ws)
{
	/* XXX In theory, we could just send a fixed string here, no need to use jansson at all for this. */
	json_t *json = json_object();
	if (!json) {
		return;
	}
	json_object_set_new(json, "response", json_string("status")); /* Lowercase, to indicate it's not IMAP protocol related */
	json_object_set_new(json, "status", json_string(""));
	json_send(ws, json);
}

#define client_set_status(ws, fmt, ...) __client_set_status(ws, 0, fmt, ## __VA_ARGS__)
#define client_set_error(ws, fmt, ...) __client_set_status(ws, 1, fmt, ## __VA_ARGS__)

static void __attribute__ ((format (gnu_printf, 3, 4))) __client_set_status(struct ws_session *ws, int fatal, const char *fmt, ...)
{
	/* A fixed buffer of this size should be plenty for status messages.
	 * If it weren't for the JSON, this whole thing would involve 0 allocations! */
	char buf[256];
	va_list ap;
	json_t *json;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	bbs_debug(5, "New status: %s\n", buf);

	json = json_object();
	if (!json) {
		return;
	}
	json_object_set_new(json, "response", json_string("status")); /* Lowercase, to indicate it's not IMAP protocol related */
	json_object_set_new(json, "error", json_boolean(fatal));
	json_object_set_new(json, "msg", json_string(buf));
	json_send(ws, json);
}

static char *find_mailbox_response_line(char *restrict s, const char *cmd, const char *mb, int *skiplenptr)
{
	char *tmp;
	int skiplen;
	char findbuf[64];
	skiplen = snprintf(findbuf, sizeof(findbuf), "* %s \"%s\" (", cmd, mb);
	tmp = strstr(s, findbuf);
	if (!tmp && !strchr(mb, ' ')) { /* If not found, try the unquoted version */
		skiplen = snprintf(findbuf, sizeof(findbuf), "* %s %s (", cmd, mb);
		tmp = strstr(s, findbuf);
	}
	*skiplenptr = skiplen;
	return tmp;
}

static int client_status_basic(mailimap *imap, const char *mbox, uint32_t *unseen, uint32_t *total)
{
	int res = 0;
	struct mailimap_status_att_list *att_list;
	struct mailimap_mailbox_data_status *status;
	clistiter *cur;

	att_list = mailimap_status_att_list_new_empty();
	if (!att_list) {
		return -1;
	}
	if (unseen) {
		res = mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_UNSEEN);
	}
	if (total) {
		res = mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_MESSAGES);
	}

	if (res) {
		bbs_warning("Failed to add message: %s\n", maildriver_strerror(res));
		goto cleanup;
	}
	res = mailimap_status(imap, mbox, att_list, &status);

	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("STATUS failed: %s\n", maildriver_strerror(res));
		goto cleanup;
	}
	res = 0;

	for (cur = clist_begin(status->st_info_list); cur; cur = clist_next(cur)) {
		struct mailimap_status_info *status_info = clist_content(cur);
		switch (status_info->st_att) {
			case MAILIMAP_STATUS_ATT_UNSEEN:
				if (unseen) {
					*unseen = status_info->st_value;
				}
				break;
			case MAILIMAP_STATUS_ATT_MESSAGES:
				if (total) {
					*total = status_info->st_value;
				}
				break;
			default:
				break;
		}
	}
	mailimap_mailbox_data_status_free(status);

cleanup:
	mailimap_status_att_list_free(att_list);
	return res;
}

static void parse_status(struct imap_client *client, json_t *folder, char *restrict tmp, uint32_t *messages, int expect)
{
	char *str;
	uint32_t num;

	if (strlen_zero(tmp)) {
		bbs_warning("Malformed STATUS response\n");
		return;
	}

	str = strstr(tmp, "MESSAGES ");
	if (str) {
		str += STRLEN("MESSAGES ");
		if (!strlen_zero(str)) {
			num = (uint32_t) atol(str);
			*messages = num;
			json_object_set_new(folder, "messages", json_integer(num));
		}
	} else if (expect) {
		bbs_warning("Failed to parse MESSAGES\n");
	}
	str = strstr(tmp, "RECENT ");
	if (str) {
		str += STRLEN("RECENT ");
		if (!strlen_zero(str)) {
			num = (uint32_t) atol(str);
			json_object_set_new(folder, "recent", json_integer(num));
		}
	} else if (expect) {
		bbs_warning("Failed to parse RECENT\n");
	}
	str = strstr(tmp, "UNSEEN ");
	if (str) {
		str += STRLEN("UNSEEN ");
		if (!strlen_zero(str)) {
			num = (uint32_t) atol(str);
			json_object_set_new(folder, "unseen", json_integer(num));
		}
	} else if (expect) {
		bbs_warning("Failed to parse UNSEEN\n");
	}
	if (client->has_status_size) {
		str = strstr(tmp, "SIZE ");
		if (str) {
			str += STRLEN("SIZE ");
			if (!strlen_zero(str)) {
				num = (uint32_t) atol(str);
				json_object_set_new(folder, "size", json_integer(num));
			}
		} else if (expect) {
			bbs_warning("Failed to parse SIZE\n");
		}
	}
}

static int client_status_command(struct imap_client *client, struct mailimap *imap, const char *mbox, json_t *folder, uint32_t *messages, char *listresp)
{
	int res = 0;
	struct mailimap_status_att_list *att_list;
	struct mailimap_mailbox_data_status *status;
	clistiter *cur;

	if (listresp) {
		char *tmp;
		int skiplen;
		/* See if we can get what we want from the log message. */
		tmp = find_mailbox_response_line(listresp, "STATUS", mbox, &skiplen);
		if (!tmp) {
			bbs_warning("No STATUS response for mailbox '%s'\n", mbox);
			/* Manually ask for it now, as usual */
		} else {
			/* Parse what we want from the STATUS response.
			 * Normally not a great idea, but STATUS responses are easy to parse. */
			tmp += skiplen;
			parse_status(client, folder, tmp, messages, 1);
			/* Look at all the time we saved! Profit and return */
			return 0;
		}
	}

	att_list = mailimap_status_att_list_new_empty();
	if (!att_list) {
		return -1;
	}
	/* Want total (MESSAGES) and unseen (UNSEEN).
	 * Also SIZE (if RFC 8438 supported).
	 * Don't care about RECENT as much but, eh, why not? */
	res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_MESSAGES);
	if (folder) {
		res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_RECENT);
		res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_UNSEEN);
		if (client->has_status_size) {
			res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_SIZE);
		}
	}

	if (res) {
		bbs_warning("Failed to add message: %s\n", maildriver_strerror(res));
		goto cleanup;
	}
	client_set_status(client->ws, "Querying status of %s", mbox);
	res = mailimap_status(imap, mbox, att_list, &status);

	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("STATUS failed: %s\n", maildriver_strerror(res));
		goto cleanup;
	}
	res = 0;

	for (cur = clist_begin(status->st_info_list); cur; cur = clist_next(cur)) {
		struct mailimap_extension_data *st_ext_data;
		struct mailimap_status_info *status_info = clist_content(cur);
		switch (status_info->st_att) {
			case MAILIMAP_STATUS_ATT_MESSAGES:
				*messages = status_info->st_value;
				json_object_set_new(folder, "messages", json_integer(status_info->st_value));
				break;
			case MAILIMAP_STATUS_ATT_RECENT:
				json_object_set_new(folder, "recent", json_integer(status_info->st_value));
				break;
			case MAILIMAP_STATUS_ATT_UNSEEN:
				json_object_set_new(folder, "unseen", json_integer(status_info->st_value));
				break;
			case MAILIMAP_STATUS_ATT_UIDNEXT:
			case MAILIMAP_STATUS_ATT_UIDVALIDITY:
			case MAILIMAP_STATUS_ATT_HIGHESTMODSEQ:
				break;
			case MAILIMAP_STATUS_ATT_SIZE:
				json_object_set_new(folder, "size", json_integer(status_info->st_value));
				break;
			case MAILIMAP_STATUS_ATT_EXTENSION:
				st_ext_data = status_info->st_ext_data;
				bbs_debug(7, "STATUS extension data - %d / %p\n", st_ext_data->ext_type, st_ext_data->ext_data);
				break;
		}
	}
	mailimap_mailbox_data_status_free(status);

cleanup:
	mailimap_status_att_list_free(att_list);
	return res;
}

static void send_status_update(struct imap_client *client, const char *mbox, char *restrict data)
{
	json_t *json;
	uint32_t messages;

	json = json_object();
	if (!json) {
		return;
	}

	json_object_set_new(json, "response", json_string("STATUS"));
	json_object_set_new(json, "name", json_string(mbox));
	json_object_set_new(json, "recent", json_boolean(1));
	parse_status(client, json, data, &messages, 0);
	json_send(client->ws, json);
}

static int load_capabilities(struct imap_client *client, int authenticated)
{
	json_t *json, *jsoncaps, *jsonauthcaps;
	struct mailimap_capability_data *capdata;
	clistiter *cur;
	int res;
	struct mailimap *imap = client->imap;

	res = mailimap_capability(imap, &capdata);
	if (MAILIMAP_ERROR(res)) {
		return -1;
	}

	json = json_object();
	if (!json) {
		mailimap_capability_data_free(capdata);
		return -1;
	}
	jsoncaps = json_array();
	if (!jsoncaps) {
		mailimap_capability_data_free(capdata);
		json_decref(json);
		return -1;
	}
	json_object_set_new(json, "response", json_string("CAPABILITY"));
	json_object_set_new(json, "capabilities", jsoncaps);
	jsonauthcaps = json_array();
	if (!jsonauthcaps) {
		mailimap_capability_data_free(capdata);
		json_decref(json);
		return -1;
	}

	for (cur = clist_begin(capdata->cap_list); cur; cur = clist_next(cur)) {
		struct mailimap_capability *cap = clist_content(cur);
		if (cap->cap_type == MAILIMAP_CAPABILITY_AUTH_TYPE) {
			if (strlen_zero(cap->cap_data.cap_auth_type)) {
				bbs_warning("Skipping empty capability\n");
				continue;
			}
			json_array_append_new(jsonauthcaps, json_string(cap->cap_data.cap_auth_type));
		} else { /* MAILIMAP_CAPABILITY_NAME */
			if (strlen_zero(cap->cap_data.cap_name)) {
				continue;
			}
			json_array_append_new(jsoncaps, json_string(cap->cap_data.cap_name));
		}
	}
	json_object_set_new(json, "authcapabilities", jsonauthcaps);

	if (json_send(client->ws, json)) {
		return -1;
	}
	json = NULL;

	/* Now that we've called mailimap_capability, libetpan is aware of what capabilities are available. */
	mailimap_capability_data_free(capdata);

	if (!authenticated) {
		/* Don't care yet. Often new capabilities are announced once authenticated,
		 * so don't bother asking yet. */
		return 0;
	}

	if (mailimap_has_id(imap)) {
#if 0
		/* This dynamically allocates a lot of memory unnecessarily, and it has a memory leak, so avoid it and do it ourself. */
		char *server = NULL, *server_ver = NULL;
		res = mailimap_id_basic(imap, "wssmail via LBBS (libetpan)", BBS_VERSION, &server, &server_ver);
		if (!MAILIMAP_ERROR(res)) {
			free_if(server);
			free_if(server_ver);
		}
#else
		res = mailimap_custom_command(imap, "ID (\"name\" \"wssmail via LBBS (libetpan)\" \"version\" \"" BBS_VERSION "\")");
#endif
	}

	SET_BITFIELD(client->canidle, mailimap_has_idle(imap));
	SET_BITFIELD(client->has_move, mailimap_has_extension(imap, "MOVE"));
	SET_BITFIELD(client->has_sort, mailimap_has_sort(imap));
	SET_BITFIELD(client->has_thread, mailimap_has_extension(imap, "THREAD=REFERENCES"));
	SET_BITFIELD(client->has_status_size, mailimap_has_extension(imap, "STATUS=SIZE"));
	SET_BITFIELD(client->has_list_status, mailimap_has_extension(imap, "LIST-STATUS"));
	SET_BITFIELD(client->has_notify, mailimap_has_extension(imap, "NOTIFY"));
	return 0;
}

#define CLIENT_REQUIRE_VAR(name) \
	if (!name) { \
		bbs_warning("Missing required variable '%s'\n", #name); \
		return -1; \
	}

static int client_imap_login(struct ws_session *ws, struct imap_client *client, struct mailimap *imap, const char *password)
{
	int res;
	int outlen;
	char *decoded_password;
	const char *username;

	username = websocket_query_param(ws, "username"); /* Without Remember Me, passed directly over WebSocket during connection setup */
	if (!username) {
		username = websocket_cookie_val(ws, "wssmail_webmail", "username"); /* In cookie */
	}
	if (!username) {
		username = websocket_session_data_string(ws, "username"); /* If using sessions (deprecated) */
	}

	CLIENT_REQUIRE_VAR(username);
	webmail_log(2, client, "=> LOGIN %s\n", username);

	/* Decode the password. The only reason the client base64 encodes it is for obfuscation, not for security.
	 * This is fundamentally not very secure, but there's not much else we can do since we need to be able
	 * to send the plain text password to the IMAP server. */
	decoded_password = (char*) base64_decode((unsigned const char*) password, (int) strlen(password), &outlen);
	CLIENT_REQUIRE_VAR(decoded_password);
	res = mailimap_login(imap, username, decoded_password);
	free(decoded_password);

	if (MAILIMAP_ERROR(res)) {
		bbs_warning("Failed to login to IMAP server as %s\n", username);
		client_set_error(ws, "IMAP server login failed");
		return -1;
	}

	client_set_status(client->ws, "Successfully logged in as %s", username);

	/* Request capabilities again, since, in practice, they often change once authenticated */
	if (load_capabilities(client, 1)) {
		return -1;
	}
	client->authenticated = 1;
	/* Regardless of whether a mailbox is selected and is idling, we
	 * need to do something at least every 30 minutes, or the IMAP server will disconnect us. */
	client->imapfd = mailimap_idle_get_fd(imap);
	websocket_set_custom_poll_fd(ws, client->imapfd, SEC_MS(1740)); /* Just under 30 minutes */
	/* Don't start IDLING yet. No mailbox is yet selected. */
	return 0;
}

static int client_imap_init(struct ws_session *ws, struct imap_client *client)
{
	struct mailimap *imap;
	int res;
	const char *hostname;
	uint16_t port;
	int secure;
	int explicit = 0;

	hostname = websocket_query_param(ws, "server");
	if (hostname) { /* If server explicitly specified in the WebSocket URI, use that */
		const char *tmp = websocket_query_param(ws, "port");
		if (strlen_zero(tmp)) {
			bbs_error("Missing query parameter 'port'\n");
			return -1;
		}
		port = (uint16_t) atoi(tmp);
		tmp = websocket_query_param(ws, "secure");
		if (strlen_zero(tmp)) {
			bbs_error("Missing query parameter 'secure'\n");
			return -1;
		}
		secure = S_TRUE(tmp);
		explicit = 1;
	} else { /* Else, hopefully we can get it from the cookie the client sent. It's HttpOnly, so the client (in JavaScript) can't even access it. */
		/* Keep in mind the session is the only way to send data from the frontend to the backend.
		 * Even if it's direct, we can't POST data since WebSocket upgrades must be GET requests.
		 * So the data would already have to be somewhere. */
		hostname = websocket_session_data_string(ws, "server");
		port = (uint16_t) websocket_session_data_number(ws, "port");
		secure = websocket_session_data_number(ws, "secure");
	}

	CLIENT_REQUIRE_VAR(hostname);
	CLIENT_REQUIRE_VAR(port);
#undef CLIENT_REQUIRE_VAR

	client_set_status(ws, "Connecting %s (%s) to %s:%u", secure ? "securely" : "insecurely", explicit ? "explicitly" : "implicitly", hostname, port);

	imap = mailimap_new(0, NULL);
	if (!imap) {
		bbs_error("Failed to create IMAP session\n");
		return -1;
	}

	client->imap = imap;

	mailimap_set_logger(imap, libetpan_log, client);
	mailimap_set_timeout(imap, 10); /* If the IMAP server hasn't responded by now, I doubt it ever will */
	if (secure) {
		res = mailimap_ssl_connect(imap, hostname, port);
	} else {
		res = mailimap_socket_connect(imap, hostname, port);
	}
	if (MAILIMAP_ERROR(res)) {
		bbs_warning("Failed to establish IMAP session to %s:%d (%s)\n", hostname, port, maildriver_strerror(res));
		client_set_error(ws, "IMAP server connection failed");
		goto cleanup;
	}

	bbs_debug(5, "Connection established to %s:%u\n", hostname, port);

	/* Timeout needs to be sufficiently large... e.g. FETCH 1:* (SIZE) can take quite a few seconds on large mailboxes. */
	mailimap_set_timeout(imap, 60); /* If the IMAP server hasn't responded by now, I doubt it ever will */

	if (load_capabilities(client, 0)) {
		goto cleanup;
	}

	return 0;

cleanup:
	mailimap_free(imap);
	client->imap = NULL;
	return -1;
}

static uint32_t fetch_size(struct mailimap_msg_att *msg_att)
{
	clistiter *cur;

	for (cur = clist_begin(msg_att->att_list); cur; cur = clist_next(cur)) {
		struct mailimap_msg_att_item *item = clist_content(cur);
		if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC && item->att_data.att_static->att_type == MAILIMAP_MSG_ATT_RFC822_SIZE) {
			return item->att_data.att_static->att_data.att_rfc822_size;
		}
	}
	bbs_warning("Size not present?\n");
	return 0;
}

struct list_status_cb {
	struct imap_client *client;
	struct dyn_str *dynstr;
};

static void list_status_logger(mailstream *imap_stream, int log_type, const char *str, size_t size, void *context)
{
	/* This is a hack due to the limitations of libetpan.
	 * It is very tricky to be able to send an arbitrary command and be able to read the raw response from it.
	 * Ideally, libetpan would populate a list of STATUS, but it only does this for one mailbox,
	 * so with LIST-STATUS, the status returned would just be that of the last mailbox for which an untagged STATUS
	 * was received. This doesn't help us at all.
	 *
	 * Instead, we use this logger callback as a callback to be able to receive the raw data received.
	 * We'll analyze any STATUS lines that appear here, store the info we want from it,
	 * and then use that later.
	 * The LIST response is still parsed as usual in mailimap_list_status.
	 * We still let libetpan handle parsing the LIST responses and we only manually parse the STATUS responses.
	 */

	struct list_status_cb *cb = context;
	struct imap_client *client = cb->client;
	struct dyn_str *dynstr = cb->dynstr;

	UNUSED(imap_stream);

	if (!size || log_type != MAILSTREAM_LOG_TYPE_DATA_RECEIVED) {
#ifdef DEBUG_LIST_STATUS
		bbs_debug(3, "Skipping %d: %.*s\n", log_type, (int) size, str);
#endif
		return;
	}

#ifdef DEBUG_LIST_STATUS
	bbs_debug(3, "Log callback %d: %.*s\n", log_type, (int) size, str);
#endif

	/* Can be broken up across multiple log callback calls, so append to a dynstr */
	bbs_debug(6, "Log callback of %lu bytes for LIST-STATUS\n", size);
	/* Since this can take quite a bit of time, send an update here */
	if (size > STRLEN("* STATUS ") && STARTS_WITH(str, "* STATUS ")) {
		const char *mb = str + STRLEN("* STATUS ");
		size_t maxlen = size - STRLEN("* STATUS ");
		if (maxlen > 1) {
			const char *end = memchr(mb + 1, *mb == '"' ? '"' : ' ', maxlen);
			size_t mblen = end ? (size_t) (end - mb) : maxlen;
			if (*mb == '"') {
				mb++;
				mblen--;
			}
			client_set_status(client->ws, "Queried status of %.*s", (int) mblen, mb);
		}
	}
	dyn_str_append(dynstr, str, size);
}

/*! \brief Basically mailimap_list, but sending a custom command */
static int mailimap_list_status(mailimap *session, clist **list_result)
{
	struct mailimap_response *response;
	int r;
	int error_code;

#define LIST_STATUS_CMD "LIST \"\" \"*\" RETURN (STATUS (MESSAGES RECENT UNSEEN SIZE))\r\n"
/* RFC 5258 Sec 4: Technically, if the server supports LIST-EXTENDED and we don't ask for CHILDREN explicitly,
 * it's not obligated to return these attributes */
#define LIST_STATUS_CHILDREN_CMD "LIST \"\" \"*\" RETURN (CHILDREN STATUS (MESSAGES RECENT UNSEEN SIZE))\r\n"

	if ((session->imap_state != MAILIMAP_STATE_AUTHENTICATED) && (session->imap_state != MAILIMAP_STATE_SELECTED)) {
		return MAILIMAP_ERROR_BAD_STATE;
	}
	r = mailimap_send_current_tag(session);
	if (r != MAILIMAP_NO_ERROR) {
		return r;
	}

	/* XXX mailimap_send_crlf and mailimap_send_custom_command aren't public */
	if (mailimap_has_extension(session, "LIST-EXTENDED")) {
		r = (int) mailstream_write(session->imap_stream, LIST_STATUS_CHILDREN_CMD, STRLEN(LIST_STATUS_CHILDREN_CMD));
		if (r != STRLEN(LIST_STATUS_CHILDREN_CMD)) {
			return MAILIMAP_ERROR_STREAM;
		}
	} else {
		r = (int) mailstream_write(session->imap_stream, LIST_STATUS_CMD, STRLEN(LIST_STATUS_CMD));
		if (r != STRLEN(LIST_STATUS_CMD)) {
			return MAILIMAP_ERROR_STREAM;
		}
	}

	if (mailstream_flush(session->imap_stream) == -1) {
		return MAILIMAP_ERROR_STREAM;
	}
	if (mailimap_read_line(session) == NULL) {
		return MAILIMAP_ERROR_STREAM;
	}
	r = mailimap_parse_response(session, &response);
	if (r != MAILIMAP_NO_ERROR) {
		return r;
	}

	*list_result = session->imap_response_info->rsp_mailbox_list;
	session->imap_response_info->rsp_mailbox_list = NULL;

	/* session->imap_response only contains the last line (e.g. LIST completed) */
	error_code = response->rsp_resp_done->rsp_data.rsp_tagged->rsp_cond_state->rsp_type;
	mailimap_response_free(response);

	switch (error_code) {
		case MAILIMAP_RESP_COND_STATE_OK:
			return MAILIMAP_NO_ERROR;
		default:
			return MAILIMAP_ERROR_LIST;
	}
}

static int client_list_command(struct imap_client *client, struct mailimap *imap, json_t *json, char *delim, int details)
{
	int res;
	char delimiter = 0;
	clist *imap_list;
	clistiter *cur;
	int needunselect = 0;
	char *listresp = NULL;
	int numother = 0;

	/* There are a few different scenarios here, depending on supported extensions:
	 * LIST-STATUS     STATUS=SIZE        # commands Approach
	 *     No              No             2N + 1     LIST, STATUS for each folder, FETCH 1:* to compute size for each folder
	 *     Yes             No             N + 1      Extended LIST command, FETCH 1:* to compute size for each folder
	 *     No              Yes            N + 1      LIST, STATUS-SIZE for each folder
	 *     Yes             Yes            1          LIST-STATUS=SIZE
	 *
	 * For a non-pipelined client, the # of commands also is proportional to the total RTT of all commands in the operation.
	 *
	 * Assuming the IMAP server is net_imap, it supports both and will optimize aggregation for remote mailboxes.
	 *
	 * Obviously, a server that supports both LIST-STATUS and STATUS=SIZE is the holy grail of IMAP servers, and we should take advantage of that.
	 */

	client_set_status(client->ws, "Querying folder list");
	webmail_log(2, client, "=> LIST\n");

	/* XXX First, we should do a LIST "" "" to get the namespace names, e.g. Other Users and Shared Folders,
	 * rather than just assuming that's what they're called. */

	if (details && client->has_list_status && client->has_status_size) {
		struct list_status_cb cb;
		struct dyn_str dynstr;
		cb.dynstr = &dynstr;
		cb.client = client;
		memset(&dynstr, 0, sizeof(dynstr));
		/* Fundamentally, libetpan does not support LIST-STATUS.
		 * It did not support STATUS=SIZE either, but it was easy to patch it support that
		 * (and mod_webmail requires such a patched version of libetpan).
		 * Rather than trying to kludge libetpan to support LIST-STATUS,
		 * it's easier to just send it the command we want and parse it ourselves. */
		bbs_debug(4, "Nice, both LIST-STATUS and STATUS=SIZE are supported!\n"); /* Somebody please give the poor IMAP server a pay raise */
		mailstream_set_logger(imap->imap_stream, list_status_logger, &cb);
		res = mailimap_list_status(imap, &imap_list);
		mailstream_set_logger(imap->imap_stream, NULL, NULL);
		listresp = dynstr.buf;
	} else {
		res = mailimap_list(imap, "", "*", &imap_list);
	}
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("%s\n", maildriver_strerror(res));
		free_if(listresp);
		return -1;
	}
	if (!clist_begin(imap_list)) {
		bbs_warning("List is empty?\n");
		free_if(listresp);
		return -1;
	}

	for (cur = clist_begin(imap_list); cur; cur = clist_next(cur)) {
		json_t *folder, *flagsarr;
		const char *name;
		int noselect = 0;
		uint32_t total = 0;
		struct mailimap_mailbox_list *mb_list = clist_content(cur);
		struct mailimap_mbx_list_flags *flags = mb_list->mb_flag;
		delimiter = mb_list->mb_delimiter;
		name = mb_list->mb_name;

		/* Append to JSON array */
		folder = json_object();
		if (!folder) {
			continue;
		}

		if (client->has_notify && !strncmp(name, "Other Users.", STRLEN("Other Users."))) {
			numother++;
		}

		json_object_set_new(folder, "name", json_string(name));
		flagsarr = json_array();
		json_object_set_new(folder, "flags", flagsarr);
		if (flags) {
			clistiter *cur2;
			if (flags->mbf_type == MAILIMAP_MBX_LIST_FLAGS_SFLAG) {
				switch (flags->mbf_sflag) {
					case MAILIMAP_MBX_LIST_SFLAG_MARKED:
						json_array_append_new(flagsarr, json_string("Marked"));
						break;
					case MAILIMAP_MBX_LIST_SFLAG_UNMARKED:
						json_array_append_new(flagsarr, json_string("Unmarked"));
						break;
					case MAILIMAP_MBX_LIST_SFLAG_NOSELECT:
						json_array_append_new(flagsarr, json_string("NoSelect"));
						noselect = 1;
						break;
				}
			}
			for (cur2 = clist_begin(flags->mbf_oflags); cur2; cur2 = clist_next(cur2)) {
				struct mailimap_mbx_list_oflag *oflag = clist_content(cur2);
				switch (oflag->of_type) {
					case MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS:
						json_array_append_new(flagsarr, json_string("NoInferiors"));
						break;
					case MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT:
						/* These don't include any backslashes, so don't in the other ones above either: */
						json_array_append_new(flagsarr, json_string(oflag->of_flag_ext));
						if (!strcasecmp(oflag->of_flag_ext, "NonExistent")) {
							noselect = 1;
						}
						break;
				}
			}
		}
		json_array_append_new(json, folder);
		webmail_log(4, client, "<= LIST %s\n", name);
		if (!details || noselect) {
			continue;
		}

		/* STATUS: ideally we could get all the details we want from a single STATUS command. */
		if (!client_status_command(client, imap, name, folder, &total, listresp)) {
			if (!client->has_status_size) { /* Lacks RFC 8438 support */
				uint32_t size = 0;
				if (total > 0) {
					/* Do it the manual way. */
					struct mailimap_fetch_type *fetch_type;
					struct mailimap_fetch_att *fetch_att;
					clist *fetch_result;
					struct mailimap_set *set = mailimap_set_new_interval(1, 0); /* fetch in interval 1:* */

					bbs_debug(2, "IMAP server does not support RFC 8438. Manually calculating mailbox size for %s\n", name);
					client_set_status(client->ws, "Calculating size of %s", name);
					/* Must EXAMINE mailbox */
					res = mailimap_examine(imap, name);
					if (res != MAILIMAP_NO_ERROR) {
						bbs_warning("Failed to EXAMINE mailbox '%s'\n", name);
					} else {
						fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
						fetch_att = mailimap_fetch_att_new_rfc822_size();
						mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);
						res = mailimap_fetch(imap, set, fetch_type, &fetch_result);
						if (res != MAILIMAP_NO_ERROR) {
							bbs_error("Failed to calculate size of mailbox %s: %s\n", name, maildriver_strerror(res));
						} else {
							clistiter *cur2;
							/* Iterate over each message size */
							for (cur2 = clist_begin(fetch_result); cur2; cur2 = clist_next(cur2)) {
								struct mailimap_msg_att *msg_att = clist_content(cur2);
								size += fetch_size(msg_att);
							}
							mailimap_fetch_list_free(fetch_result);
							mailimap_fetch_type_free(fetch_type);
						}
						/* UNSELECT the mailbox, since we weren't supposed to do this.
						 * XXX If a mailbox was previously selected, after we're done with all this,
						 * reselect that one. */
						needunselect = 1;
					}
					mailimap_set_free(set);
				}
				json_object_set_new(folder, "size", json_integer(size));
				if (imap->imap_selection_info) {
					json_object_set_new(folder, "uidvalidity", json_integer(imap->imap_selection_info->sel_uidvalidity));
					json_object_set_new(folder, "uidnext", json_integer(imap->imap_selection_info->sel_uidnext));
				}
			}
		}
	}

	if (client->has_notify) { /* Construct the NOTIFY command */
		char cmd[2048];
		struct dyn_str dynstr;
		int otherinboxonly = numother > 10;

		/* If the NOTIFY capability is supported, we'll use it to keep on top of updates to other mailboxes
		 * (not just the currently selected one).
		 * We can use the personal selector to get updates to all mailboxes in the personal namespace.
		 * This will leave mailboxes in the "Other Users" and "Shared Folders" namespaces... we could name
		 * them all individually (there's no patterns allowed in the NOTIFY command), but if there's a large
		 * number of mailboxes, this might be too much (and the server could reject the command).
		 *
		 * This is most true for Shared Folders, however; Other Users should be relatively bounded in size.
		 *
		 * So our final approach is:
		 * - Personal namespace: subscribe all
		 * - Other Users namespace:
		 *  |- If < OTHER_USERS_WATCHALL_THRESHOLD total folders:
		 *    - subscribe all (entire subtree)
		 *     Else, only subscribe to all the "INBOX" or "Inbox" folders we encounter.
		 * - Shared Folders namespace:
		 *  - Subscribe to all the "INBOX" or "Inbox" folders we encounter.
		 */

#define OTHER_USERS_WATCHALL_THRESHOLD 25

		memset(&dynstr, 0, sizeof(dynstr));
		if (numother > OTHER_USERS_WATCHALL_THRESHOLD) {
			for (cur = clist_begin(imap_list); cur; cur = clist_next(cur)) {
				struct mailimap_mailbox_list *mb_list = clist_content(cur);
				const char *name = mb_list->mb_name;
				if (!strncmp(name, "Other Users.", STRLEN("Other Users."))) {
					if (otherinboxonly && !strcasestr(name, "INBOX")) {
						continue;
					}
				} else if (!strncmp(name, "Shared Folders.", STRLEN("Shared Folders."))) {
					if (!strcasestr(name, "INBOX")) {
						continue;
					}
				} else {
					continue; /* Personal namespace */
				}
				dyn_str_append(&dynstr, " \"", STRLEN(" \""));
				dyn_str_append(&dynstr, name, strlen(name));
				dyn_str_append(&dynstr, "\"", STRLEN("\""));
			}
		}

		/* We just want notifications when something happens, having an untagged FETCH sent to us isn't that important.
		 * We can wake up and do some work if really needed. */
		if (dynstr.buf) {
			snprintf(cmd, sizeof(cmd), "NOTIFY SET (SELECTED-DELAYED (MessageNew MessageExpunge FlagChange)) %s(personal (MessageNew MessageExpunge)) (mailboxes%s (MessageNew MessageExpunge))",
				numother <= OTHER_USERS_WATCHALL_THRESHOLD ? "(subtree \"Other Users\" (MessageNew MessageExpunge FlagChange))" : "",
				dynstr.buf);
			FREE(dynstr.buf);
		} else {
			snprintf(cmd, sizeof(cmd), "NOTIFY SET (SELECTED-DELAYED (MessageNew MessageExpunge FlagChange)) (personal (MessageNew MessageExpunge))%s", numother ? " (subtree \"Other Users\" (MessageNew MessageExpunge))" : "");
		}
		res = mailimap_custom_command(imap, cmd);
		if (MAILIMAP_ERROR(res)) {
			bbs_warning("NOTIFY SET failed\n");
		}
	}

	free_if(listresp);
	mailimap_list_result_free(imap_list);
	client_clear_status(client->ws);

	if (needunselect) {
		/* UNSELECT itself is an extension. Only do if supported. */
		if (mailimap_has_extension(imap, "UNSELECT")) {
			res = mailimap_custom_command(imap, "UNSELECT");
			if (MAILIMAP_ERROR(res)) {
				bbs_warning("UNSELECT failed\n");
			}
		} else {
			bbs_debug(4, "No way to unselect mailbox...\n");
			/* It's fine, the current mailbox won't be used until some mailbox is selected anyways... */
		}
	}

	if (!delimiter) {
		bbs_warning("Invalid delimiter: no mailboxes available?\n");
		return -1;
	}

	bbs_debug(3, "Hierarchy delimiter is '%c'\n", delimiter);
	delim[0] = delimiter;
	delim[1] = '\0';
	return 0;
}

static void list_response(struct ws_session *ws, struct imap_client *client, struct mailimap *imap)
{
	char delim[2];
	json_t *root, *arr;

	/* If the server does not support LIST-STATUS, then do a preliminary LIST,
	 * because afterwards, we'll have to fall back to issuing a STATUS for
	 * every mailbox, and this can take quite some time. Therefore, the preliminary
	 * LIST at least allows displaying the mailbox names in the client, even
	 * though there are no details for any of them and the interface isn't usable yet.
	 *
	 * If the LIST-STATUS extension is supported, we're going to get all
	 * the responses much more quickly, and it's probably okay to just do
	 * the single detailed LIST, which saves time overall by avoiding redundancy,
	 * at the expense of the folder pane taking a little longer to display anything. */

	if (!client->has_list_status) {
		root = json_object();
		if (!root) {
			bbs_error("Failed to create JSON root\n");
			return;
		}
		arr = json_array();
		json_object_set_new(root, "response", json_string("LIST"));
		json_object_set_new(root, "data", arr);

		if (client_list_command(client, imap, arr, delim, 0)) {
			goto cleanup;
		}

		json_object_set_new(root, "delimiter", json_string(delim));
		json_send(ws, root);

		/* We just sent a list of folder names.
		 * Now, send the full details, in a second response since this will take a second.
		 * This allows the UI to be more responsive for the user. */
	}

	root = json_object();
	if (!root) {
		bbs_error("Failed to create JSON root\n");
		return;
	}
	arr = json_array();
	json_object_set_new(root, "response", json_string("LIST"));
	json_object_set_new(root, "data", arr);

	if (client_list_command(client, imap, arr, delim, 1)) {
		goto cleanup;
	}
	json_object_set_new(root, "delimiter", json_string(delim));
	json_send(ws, root);
	return;

cleanup:
	json_decref(root);
}

static int client_imap_select(struct ws_session *ws, struct imap_client *client, struct mailimap *imap, const char *name)
{
	json_t *root, *flags;
	clistiter *cur;
	int res;
	uint32_t num_unseen = 0;

	/* For some reason, the SELECT response can't give you the number of unread messages.
	 * We need to explicitly ask for the STATUS to get that.
	 * Do so and send it along because that will help the frontend.
	 * What could pose a problem is that with IMAP, you are not SUPPOSED to
	 * issue a STATUS for the currently selected mailbox.
	 * Personally, I think this is stupid, since there's no other way to get this information,
	 * and so what if you want that for the currently selected mailbox?
	 * We therefore ask for the STATUS before doing the SELECT, to maximize compatibility with
	 * servers that may adhere to such a dumb limitation, but that won't help if this mailbox
	 * was already selected anyways, and we're merely reselecting it.
	 */
	res = client_status_basic(imap, name, &num_unseen, NULL);
	if (res != MAILIMAP_NO_ERROR) {
		return -1;
	}

	webmail_log(2, client, "=> SELECT %s\n", name);
	res = mailimap_select(imap, name);
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("SELECT '%s' failed: %s\n", name, maildriver_strerror(res));
		return -1;
	}

	root = json_object();
	if (!root) {
		return -1;
	}

	json_object_set_new(root, "response", json_string("SELECT"));
	json_object_set_new(root, "folder", json_string(name));
	json_object_set_new(root, "uidnext", json_integer(imap->imap_selection_info->sel_uidnext));
	json_object_set_new(root, "uidvalidity", json_integer(imap->imap_selection_info->sel_uidvalidity));
	json_object_set_new(root, "readonly", json_boolean(imap->imap_selection_info->sel_perm == MAILIMAP_MAILBOX_READONLY));
	json_object_set_new(root, "exists", json_integer(imap->imap_selection_info->sel_exists));
	json_object_set_new(root, "recent", json_integer(imap->imap_selection_info->sel_recent));

	json_object_set_new(root, "unseen", json_integer(num_unseen));

	client->messages = imap->imap_selection_info->sel_exists;
	REPLACE(client->mailbox, name);

	flags = json_array();
	json_object_set_new(root, "flags", flags);

	/* Iterate over each message size */
	for (cur = clist_begin(imap->imap_selection_info->sel_perm_flags); cur; cur = clist_next(cur)) {
		struct mailimap_flag_perm *perm_flag = clist_content(cur);
		switch (perm_flag->fl_type) {
			case MAILIMAP_FLAG_PERM_FLAG:
				switch (perm_flag->fl_flag->fl_type) {
					case MAILIMAP_FLAG_ANSWERED:
						json_array_append_new(flags, json_string("\\Answered"));
						break;
					case MAILIMAP_FLAG_FLAGGED:
						json_array_append_new(flags, json_string("\\Flagged"));
						break;
					case MAILIMAP_FLAG_DELETED:
						json_array_append_new(flags, json_string("\\Deleted"));
						break;
					case MAILIMAP_FLAG_SEEN:
						json_array_append_new(flags, json_string("\\Seen"));
						break;
					case MAILIMAP_FLAG_DRAFT:
						json_array_append_new(flags, json_string("\\Draft"));
						break;
					case MAILIMAP_FLAG_KEYWORD:
						json_array_append_new(flags, json_string(perm_flag->fl_flag->fl_data.fl_keyword));
						break;
					case MAILIMAP_FLAG_EXTENSION:
						json_array_append_new(flags, json_string(perm_flag->fl_flag->fl_data.fl_extension));
						break;
				}
				break;
			case MAILIMAP_FLAG_PERM_ALL:
				json_object_set_new(flags, "folder", json_string("\\All")); /* XXX \All is not a flag, this means "all"... */
				break;
		}
	}

	if (json_send(ws, root)) {
		return -1;
	}
	return 0;
}

static void append_quota(json_t *root, struct imap_client *client)
{
	int res;
	clistiter *cur;

	if (mailimap_has_quota(client->imap)) {
		struct mailimap_quota_complete_data *quotaroot_complete = NULL;
		res = mailimap_quota_getquotaroot(client->imap, client->mailbox, &quotaroot_complete);
		if (!MAILIMAP_ERROR(res)) {
			int sentquota = 0;
			for (cur = clist_begin(quotaroot_complete->quota_list); cur; cur = clist_next(cur)) {
				struct mailimap_quota_quota_data *qd = clist_content(cur);
				clistiter *cur2;
				for (cur2 = clist_begin(qd->quota_list); cur2; cur2 = clist_next(cur2)) {
					struct mailimap_quota_quota_resource *qr = clist_content(cur2);
					bbs_debug(3, "Mailbox '%s', usage %u, limit %u\n", quotaroot_complete->quotaroot_data->mailbox, qr->usage, qr->limit);
					if (!sentquota++) { /* Only send the first one */
						json_object_set_new(root, "quota", json_integer(qr->limit));
						json_object_set_new(root, "quotaused", json_integer(qr->usage));
					}
				}
			}
			mailimap_quota_complete_data_free(quotaroot_complete);
		}
	} else {
		bbs_debug(3, "Server does not support quota\n");
	}
}

static void __append_datetime(json_t *json, const char *field, struct tm *tm)
{
	time_t epoch;
	long int offset;

	offset = tm->tm_gmtoff; /* timegm will reset this, save it first */

	/* tm->tm_isdst is not relevant, because we're using UTC offsets, so Daylight Saving thankfully doesn't matter */

	/* We need to subtract the offset (in s) from UTC to actually get the right epoch */
	epoch = timegm(tm) - offset; /* All times need to be given out in UTC */
	/* Send the epoch time, and the client can display it in
	 * its local timezone / preferred format without us needing to know. */
#ifdef DEBUG_DATETIME
	bbs_debug(5, "Parsed datetime -> epoch %ld (had offset %ld)\n", epoch, offset);
#endif
	if (epoch < 0) { /* It should never be negative... */
		bbs_warning("Date parsed to %ld? (%ld/%ld)\n", epoch, offset, timegm(tm));
		return;
	}
	json_object_set_new(json, field, json_integer(epoch));
}

static void append_datetime(json_t *json, const char *field, const char *buf)
{
	struct tm tm;

	memset(&tm, 0, sizeof(tm)); /* so that fields not set by strptime are still zeroed */

	if (!strptime(buf, "%Y-%m-%d %H:%M:%S %z", &tm)) {
		bbs_warning("Failed to parse INTERNALDATE %s?\n", buf);
	} else {
		__append_datetime(json, field, &tm);
	}
}

static void append_internaldate(json_t *json, struct mailimap_date_time *dt)
{
	char buf[40];
	snprintf(buf, sizeof(buf), "%4d-%02d-%02d %02d:%02d:%02d %c%04d",
		dt->dt_year, dt->dt_month, dt->dt_day, dt->dt_hour, dt->dt_min, dt->dt_sec,
	dt->dt_zone < 0 ? '-' : '+', dt->dt_zone < 0 ? -dt->dt_zone : dt->dt_zone); /* -/+ followed by abs value for formatting */
	return append_datetime(json, "received", buf);
}

#define EXTRA_CHECKS

static char *mime_header_decode(const char *s)
{
	size_t cur_token;
	int encoded = 0;
	size_t len;
	char *decoded = NULL;
#ifdef EXTRA_CHECKS
	int removed;
#endif

	/* Decode header per RFC 2047 */
	/* See also: https://github.com/dinhvh/libetpan/issues/24 */

	if (strlen_zero(s)) {
		return NULL;
	}
	if (strstr(s, "=?")) {
		encoded = strcasestr(s, "?Q?") || strcasestr(s, "?B?");
	}
	if (!encoded) {
		/* XXX Interpret as UTF-8 */
		return NULL;
	}
	cur_token = 0;
	/* Decode any RFC 2047 encoded words */

	mailmime_encoded_phrase_parse("iso-8859-1", s, strlen(s), &cur_token, "utf-8", &decoded);
	if (!decoded) {
		bbs_warning("Failed to decode MIME header\n");
		return NULL;
	}

#ifdef EXTRA_CHECKS
	/* XXX Hack: Some of the encoded strings can have weird artifacts in them when decoded.
	 * e.g.:
	 * =?windows-1252?Q?foo=AE_bonus?= =?windows-1252?Q?_bar=3F?=
	 * turns into
	 * foo<unprintable> bonus bar?
	 *
	 * Possibly a bug with mailmime_encoded_phrase_parse, not really sure.
	 *
	 * We shouldn't have to do this, but json_object_set_new will fail if we're not UTF-8 compliant.
	 * So remove any such characters if there are any.
	 *
	 * UPDATE: This is probably because char was signed and these were negative values.
	 * Since this should be unsigned, I am not sure this is a problem anymore.
	 */
	len = strlen(decoded);
	removed = bbs_utf8_remove_invalid((unsigned char*) decoded, &len);
	if (removed) {
		bbs_warning("%d unprintable character%s removed\n", removed, ESS(removed));
	}
#endif

	return decoded;
}

static void append_header_single(json_t *restrict json, int *importance, int fetchlist, json_t *to, json_t *cc, const char *hdrname, char *restrict hdrval)
{
	/* This is one of the headers we wanted.
	 * FETCHLIST: Date, Subject, From, Cc, To, X-Priority, Importance, X-MSMail-Priority, or Priority.
	 * FETCH: We get all headers, ignore any we don't want.
	 * In addition to FETCHLIST ones, we also look at User-Agent.
	 * From is the only one we expect multiple of (possibly). */

	if (!strcasecmp(hdrname, "X-Priority")) {
		*importance = atoi(hdrval); /* It'll stop where it should, this just works! */
	} else if (!strcasecmp(hdrname, "Importance") || !strcasecmp(hdrname, "X-MSMail-Priority")) {
		if (!strcasecmp(hdrval, "high")) {
			*importance = 1;
		} else if (!strcasecmp(hdrval, "low")) {
			*importance = 5;
		} else {
			*importance = 3;
		}
	} else if (!strcasecmp(hdrname, "Priority")) {
		if (!strcasecmp(hdrval, "Urgent")) {
			*importance = 1;
		} else if (!strcasecmp(hdrval, "Non-Urgent")) {
			*importance = 5;
		} else {
			*importance = 3;
		}
	} else {
		if (fetchlist) {
			char *decoded = mime_header_decode(hdrval);
			if (decoded) {
				bbs_debug(5, "Decoded %s: %s => %s\n", hdrname, hdrval, decoded);
				hdrval = decoded;
			}
			if (!strcasecmp(hdrname, "From")) {
				json_object_set_new(json, "from", json_string(hdrval));
			} else if (!strcasecmp(hdrname, "To")) {
				/* XXX Multiple recipients can be specified in (or split across) header lines,
				 * and the frontend assumes that each recipient is in its own line, currently,
				 * so recipients can be truncated for FETCHLIST (but won't be for regular FETCH) */
				json_array_append_new(to, json_string(hdrval));
			} else if (!strcasecmp(hdrname, "Cc")) {
				json_array_append_new(cc, json_string(hdrval));
			} else if (!strcasecmp(hdrname, "Subject")) {
				json_object_set_new(json, "subject", json_string(hdrval));
			} else if (!strcasecmp(hdrname, "Date")) {
				struct tm sent;
				memset(&sent, 0, sizeof(sent));
				if (!bbs_parse_rfc822_date(hdrval, &sent)) {
					__append_datetime(json, "sent", &sent);
				}
			} else { /* else, there shouldn't be anything unaccounted for, since we only fetched specific headers of interest */
				bbs_warning("Unanticipated header: %s\n", hdrname);
			}
			free_if(decoded);
		} else {
			/* Only care about these headers when fetching a full message.
			 * The ones in the fetchlist branch are taken care of for us by the MIME parsing stuff. */
			if (!strcasecmp(hdrname, "User-Agent")) {
				json_object_set_new(json, "useragent", json_string(hdrval));
			}
			/* Ignore Content-Type and Content-Transfer-Encoding headers here.
			 * If it's multipart/alternative, that doesn't really tell us what
			 * we're actually sending to the client (which may be the plain text or HTML component, just depending
			 * on what the client wants and what's available).
			 * When parsing the MIME stuff we'll send what we're actually sending. */
		}
	}
}

static void append_header_meta(json_t *restrict json, char *headers, int fetchlist)
{
	int importance = 0;
	char *header, *prevheadername = NULL, *prevval = NULL;
	struct dyn_str dynstr;
	json_t *to = json_array();
	json_t *cc = json_array();

	json_object_set_new(json, "to", to);
	json_object_set_new(json, "cc", cc);

	memset(&dynstr, 0, sizeof(dynstr));

	/* The reason this loop looks more complicated than it needs to be is to properly
	 * handle headers that extend across multiple lines.
	 * This isn't that uncommon (e.g. References), and it really must work correctly. */
	while ((header = strsep(&headers, "\n"))) {
		char *hdrname, *hdrval = header;

		bbs_strterm(header, '\r');
		if (strlen_zero(header)) {
			break; /* End of headers */
		}

		if (isspace(header[0])) {
			/* Continuation of previous header */
			if (!prevval) {
				bbs_warning("No previous header to continue?\n");
				continue;
			}
			dyn_str_append(&dynstr, prevval, strlen(prevval));
			prevval = header;
		} else {
			/* If we had a previous multiline header, flush it */
			if (dynstr.buf) {
				dyn_str_append(&dynstr, prevval, strlen(prevval));
				append_header_single(json, &importance, fetchlist, to, cc, prevheadername, dynstr.buf);
				free(dynstr.buf);
				memset(&dynstr, 0, sizeof(dynstr));
			} else if (prevval) {
				append_header_single(json, &importance, fetchlist, to, cc, prevheadername, prevval);
			}
			/* New header */
			hdrname = strsep(&hdrval, ":");
			prevheadername = hdrname;
			if (!strlen_zero(hdrval)) {
				ltrim(hdrval);
			}
			prevval = hdrval;
		}
	}

	/* If we had a previous multiline header, flush it */
	if (dynstr.buf) {
		dyn_str_append(&dynstr, prevval, strlen(prevval));
		append_header_single(json, &importance, fetchlist, to, cc, prevheadername, dynstr.buf);
		free(dynstr.buf);
	} else if (prevval) {
		append_header_single(json, &importance, fetchlist, to, cc, prevheadername, prevval);
	}

	if (importance) {
		json_object_set_new(json, "priority", json_integer(importance));
	}
}

/*! \brief XXX Basically mailimap_status / mailimap_sort, but with support for using search keys libetpan does not support
 * That said, it does not support all the search keys, just a subset of ones we care about. Hence, fuller, not full. */
static int mailimap_search_sort_fuller(mailimap *session, const char *sortkey, const char *searchkey, clist **outlist)
{
	char cmd[256];
	size_t cmdlen;
	struct mailimap_response *response;
	int r;
	int error_code;
	clistiter *cur = NULL;
	clist *sort_result = NULL;

	if ((session->imap_state != MAILIMAP_STATE_AUTHENTICATED) && (session->imap_state != MAILIMAP_STATE_SELECTED)) {
		return MAILIMAP_ERROR_BAD_STATE;
	}
	r = mailimap_send_current_tag(session);
	if (r != MAILIMAP_NO_ERROR) {
		return r;
	}

	/* XXX mailimap_send_crlf and mailimap_send_custom_command aren't public */
	if (sortkey) {
		cmdlen = (size_t) snprintf(cmd, sizeof(cmd), "SORT (%s) UTF-8 %s\r\n", sortkey, searchkey);
	} else {
		cmdlen = (size_t) snprintf(cmd, sizeof(cmd), "SEARCH %s\r\n", searchkey);
	}

	r = (int) mailstream_write(session->imap_stream, cmd, cmdlen);
	if (r != (int) cmdlen) {
		return MAILIMAP_ERROR_STREAM;
	}

	if (mailstream_flush(session->imap_stream) == -1) {
		return MAILIMAP_ERROR_STREAM;
	}
	if (mailimap_read_line(session) == NULL) {
		return MAILIMAP_ERROR_STREAM;
	}
	r = mailimap_parse_response(session, &response);
	if (r != MAILIMAP_NO_ERROR) {
		return r;
	}

	for (cur = clist_begin(session->imap_response_info->rsp_extension_list); cur; cur = clist_next(cur)) {
		struct mailimap_extension_data *ext_data = clist_content(cur);
		if (ext_data->ext_extension->ext_id == MAILIMAP_EXTENSION_SORT) {
			if (sortkey && !sort_result) {
				sort_result = ext_data->ext_data;
				ext_data->ext_data = NULL;
				ext_data->ext_type = -1;
			}
		}
		mailimap_extension_data_free(ext_data);
	}
	clist_free(session->imap_response_info->rsp_extension_list);
	session->imap_response_info->rsp_extension_list = NULL;

	if (!sort_result) {
		sort_result = session->imap_response_info->rsp_search_result;
		session->imap_response_info->rsp_search_result = NULL;
	}

	/* session->imap_response only contains the last line (e.g. LIST completed) */
	error_code = response->rsp_resp_done->rsp_data.rsp_tagged->rsp_cond_state->rsp_type;
	mailimap_response_free(response);
	*outlist = sort_result;

	switch (error_code) {
		case MAILIMAP_RESP_COND_STATE_OK:
			return MAILIMAP_NO_ERROR;
		default:
			return MAILIMAP_ERROR_LIST;
	}
}

#define LIBETPAN_SEARCH_KEYS_BROKEN_ABI 1

static struct mailimap_search_key *mailimap_search_key_new_type(int sk_type)
{
  return mailimap_search_key_new(sk_type, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL);
}

static clist *sortall(struct imap_client *client, const char *sort, const char *search, int *searched, int *sorted)
{
	int res = -1;
	clist *list = NULL;

	if (LIBETPAN_SEARCH_KEYS_BROKEN_ABI) {
		if (sort) {
			/* Yes, these seem flipped. See comment below. */
			if (!strcmp(sort, "sent-desc")) {
				sort = "DATE";
			} else if (!strcmp(sort, "sent-asc")) {
				sort = "REVERSE DATE";
			} else if (!strcmp(sort, "received-desc")) {
				sort = "ARRIVAL";
			} else if (!strcmp(sort, "received-asc")) {
				sort = "REVERSE ARRIVAL";
			} else if (!strcmp(sort, "size-desc")) {
				sort = "SIZE";
			} else if (!strcmp(sort, "size-asc")) {
				sort = "REVERSE SIZE";
			} else if (!strcmp(sort, "subject-asc")) {
				sort = "REVERSE SUBJECT";
			} else if (!strcmp(sort, "subject-desc")) {
				sort = "SUBJECT";
			} else if (!strcmp(sort, "from-asc")) {
				sort = "REVERSE FROM";
			} else if (!strcmp(sort, "from-desc")) {
				sort = "FROM";
			} else if (!strcmp(sort, "to-asc")) {
				sort = "REVERSE TO";
			} else if (!strcmp(sort, "to-desc")) {
				sort = "TO";
			} else {
				bbs_warning("Unsupported sort criteria: '%s'\n", sort);
			}
		}
		if (search) {
			if (!strcmp(search, "recent")) {
				search = "RECENT";
			} else if (!strcmp(search, "unseen")) {
				search = "UNSEEN";
			} else {
				bbs_warning("Unsupported search criteria: '%s'\n", search);
			}
		}
		*sorted = *searched = 0;
		res = mailimap_search_sort_fuller(client->imap, sort, search, &list);
	} else {
		struct mailimap_sort_key *sortkey = NULL;
		struct mailimap_search_key *searchkey = NULL;
		if (sort) {
			/* These seem backwards because, in a way, they are.
			 * The pagination logic is written to expect the "first" result on the last page and show the "last"
			 * result at the beginning, so that on an unsorted mailbox, the latest results show up on the first page.
			 * Therefore, we flip all the orderings here, e.g. to sort in descending order, we really ask the server
			 * to do an ascending sort, so that when the last results are used for the first page, the largest items
			 * show up there, making it feel like a descending sort. */
			if (!strcmp(sort, "sent-desc")) {
				sortkey = mailimap_sort_key_new_date(0);
			} else if (!strcmp(sort, "sent-asc")) {
				sortkey = mailimap_sort_key_new_date(1);
			} else if (!strcmp(sort, "received-desc")) {
				sortkey = mailimap_sort_key_new_arrival(0);
			} else if (!strcmp(sort, "received-asc")) {
				sortkey = mailimap_sort_key_new_arrival(1);
			} else if (!strcmp(sort, "size-desc")) {
				sortkey = mailimap_sort_key_new_size(0);
			} else if (!strcmp(sort, "size-asc")) {
				sortkey = mailimap_sort_key_new_size(1);
			} else if (!strcmp(sort, "subject-asc")) {
				sortkey = mailimap_sort_key_new_subject(1);
			} else if (!strcmp(sort, "subject-desc")) {
				sortkey = mailimap_sort_key_new_subject(0);
			} else if (!strcmp(sort, "from-asc")) {
				sortkey = mailimap_sort_key_new_from(1);
			} else if (!strcmp(sort, "from-desc")) {
				sortkey = mailimap_sort_key_new_from(0);
			} else if (!strcmp(sort, "to-asc")) {
				sortkey = mailimap_sort_key_new_to(1);
			} else if (!strcmp(sort, "to-desc")) {
				sortkey = mailimap_sort_key_new_to(0);
			} else {
				bbs_warning("Unsupported sort criteria: '%s'\n", sort);
			}
			if (!sortkey) {
				return NULL;
			}
		}

		if (search) {
			if (!strcmp(search, "recent")) {
				/* XXX LIBETPAN_SEARCH_KEYS_BROKEN_ABI. Something is not right here.
				 * For some reason, when this is actually sent, RECENT becomes ON and UNSEEN becomes UNFLAGGED.
				 * ON is 1 before RECENT and UNFLAGGED is 2 before UNSEEN, so this almost seems like
				 * some kind of ordering/ABI issue, even though that doesn't seem to fit.
				 * Not only is that wrong, but it will almost certainly lead to a crash.
				 * The code seems to be correct and it seems to work this way in other projects,
				 * so I'm not entirely sure what the issue is here. For now, we build the command manually.
				 */
				searchkey = mailimap_search_key_new_type(MAIL_SEARCH_KEY_RECENT);
			} else if (!strcmp(search, "unseen")) {
				searchkey = mailimap_search_key_new_type(MAIL_SEARCH_KEY_UNSEEN);
			} else {
				bbs_warning("Unsupported search criteria: '%s'\n", search);
			}
		} else {
			searchkey = mailimap_search_key_new_all();
		}
		if (!searchkey) {
			if (sortkey) {
				mailimap_sort_key_free(sortkey);
			}
			return NULL;
		}

		if (sortkey) {
			res = mailimap_sort(client->imap, "UTF-8", sortkey, searchkey, &list);
			mailimap_sort_key_free(sortkey);
			*sorted = 1;
			*searched = 0;
		} else {
			res = mailimap_search(client->imap, "UTF-8", searchkey, &list);
			*sorted = 0;
			*searched = 1;
		}
		mailimap_search_key_free(searchkey);
	}

	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("%s failed: %s\n", *sorted ? "SORT" : "SEARCH", maildriver_strerror(res));
		/* Wish there was an easy way to get the actual tagged NO response, so we could pass that on.
		 * If SORT failed, it's probably beacuse it's not supported for this mailbox.
		 * SEARCH is part of the base specification so it's always supported.
		 * (the scenario being the server itself supports it but perhaps a proxied mailbox doesn't) */
		if (*sorted) {
			client_set_error(client->ws, "Sort failed or not supported for this mailbox");
		}
	}
	return list;
}

static int contains_attachments_1part(struct mailimap_body_type_1part *type_1part)
{
	struct mailimap_body_fld_dsp *disp;

	/* Using the logic here:
	 * https://stackoverflow.com/questions/28366248/imap-best-way-to-detect-the-presence-of-an-attachment-in-a-message/28368829#28368829
	 *
	 * "Parse the BODYSTRUCTURE and if test each bodypart. If its content-type is multipart, it's not an attachment.
	 * If its content-type is text, then you have to look at its content-disposition, which may be either inline or attachment.
	 * If it has another content-type, then it is an attachment."
	 */
	switch (type_1part->bd_type) {
		case MAILIMAP_BODY_TYPE_1PART_BASIC:
#ifdef DEBUG_ATTACHMENTS
			bbs_debug(6, "1-part basic\n");
#endif
			/* It's an attachment */
			return 1;
		case MAILIMAP_BODY_TYPE_1PART_MSG:
#ifdef DEBUG_ATTACHMENTS
			bbs_debug(6, "1-part msg\n");
#endif
			break;
		case MAILIMAP_BODY_TYPE_1PART_TEXT:
			/* It could be an attachment, depending on the disposition */
			disp = type_1part->bd_ext_1part->bd_disposition;
			if (disp) {
#ifdef DEBUG_ATTACHMENTS
				bbs_debug(6, "1-part text: %s\n", disp->dsp_type);
#endif
				if (!strcasecmp(disp->dsp_type, "attachment")) {
					return 1;
				}
			} else {
#ifdef DEBUG_ATTACHMENTS
				bbs_debug(6, "1-part text\n");
#endif
			}
			break;
	}
	return 0;
}

static int contains_attachments(struct mailimap_body *imap_body);

static int contains_attachments_mpart(struct mailimap_body_type_mpart *p)
{
	clistiter *cur;
#ifdef DEBUG_ATTACHMENTS
	bbs_debug(6, "mpart - %s\n", p->bd_media_subtype);
#endif
	for (cur = clist_begin(p->bd_list); cur; cur = clist_next(cur)) {
		struct mailimap_body *imap_body = clist_content(cur);
		if (contains_attachments(imap_body)) {
			return 1;
		}
	}
	return 0;
}

static int contains_attachments(struct mailimap_body *imap_body)
{
	switch (imap_body->bd_type) {
		case MAILIMAP_BODY_1PART:
			if (contains_attachments_1part(imap_body->bd_data.bd_body_1part)) {
				return 1;
			}
			break;
		case MAILIMAP_BODY_MPART:
			if (contains_attachments_mpart(imap_body->bd_data.bd_body_mpart)) {
				return 1;
			}
			break;
		default:
			break;
	}
	return 0;
}

static void fetchlist_single(struct mailimap_msg_att *msg_att, json_t *arr)
{
	json_t *msgitem;
	clistiter *cur2;

	msgitem = json_object();
	if (!msgitem) {
		return;
	}
	json_array_append_new(arr, msgitem);
	json_object_set_new(msgitem, "seqno", json_integer(msg_att->att_number));

	for (cur2 = clist_begin(msg_att->att_list); cur2; cur2 = clist_next(cur2)) {
		struct mailimap_msg_att_item *item = clist_content(cur2);
		if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC) {
			struct mailimap_msg_att_body_section *msg_att_body_section;
			struct mailimap_body *imap_body;
			char headersbuf[8192]; /* Should be large enough for most email headers */
			switch (item->att_data.att_static->att_type) {
				case MAILIMAP_MSG_ATT_UID:
					json_object_set_new(msgitem, "uid", json_integer(item->att_data.att_static->att_data.att_uid));
					break;
				case MAILIMAP_MSG_ATT_INTERNALDATE:
					append_internaldate(msgitem, item->att_data.att_static->att_data.att_internal_date);
					break;
				case MAILIMAP_MSG_ATT_RFC822_SIZE:
					json_object_set_new(msgitem, "size", json_integer(item->att_data.att_static->att_data.att_rfc822_size));
					break;
				case MAILIMAP_MSG_ATT_BODY_SECTION:
					msg_att_body_section = item->att_data.att_static->att_data.att_body_section;
					/* Manual hacky workaround */
					/* Seems calling mailmime_parse and fetch_mime_recurse here is pointless
					 * since we still have to do append_header_meta on those fields anyways,
					 * or they don't show up. Can't just parse headers into mailmime_parse. */
					safe_strncpy(headersbuf, msg_att_body_section->sec_body_part, sizeof(headersbuf));
					append_header_meta(msgitem, headersbuf, 1);
					break;
				case MAILIMAP_MSG_ATT_BODYSTRUCTURE:
					imap_body = item->att_data.att_static->att_data.att_bodystructure;
					json_object_set_new(msgitem, "attachments", json_boolean(contains_attachments(imap_body)));
					break;
				case MAILIMAP_MSG_ATT_RFC822_HEADER:
				case MAILIMAP_MSG_ATT_ENVELOPE:
				case MAILIMAP_MSG_ATT_RFC822_TEXT:
				case MAILIMAP_MSG_ATT_BODY:
				default:
					bbs_warning("Unhandled FETCH response item\n");
					break;
			}
		} else {
			struct mailimap_msg_att_dynamic *dynamic = item->att_data.att_dyn;
			clistiter *dcur;
			json_t *flagsarr = json_array();
			json_object_set_new(msgitem, "flags", flagsarr);
			if (dynamic && dynamic->att_list) {
				for (dcur = clist_begin(dynamic->att_list); dcur; dcur = clist_next(dcur)) {
					struct mailimap_flag_fetch *flag = clist_content(dcur);
					switch (flag->fl_type) {
						case MAILIMAP_FLAG_FETCH_RECENT:
							json_array_append_new(flagsarr, json_string("\\Recent"));
							break;
						case MAILIMAP_FLAG_FETCH_OTHER:
							switch (flag->fl_flag->fl_type) {
								case MAILIMAP_FLAG_ANSWERED:
									json_array_append_new(flagsarr, json_string("\\Answered"));
									break;
								case MAILIMAP_FLAG_FLAGGED:
									json_array_append_new(flagsarr, json_string("\\Flagged"));
									break;
								case MAILIMAP_FLAG_DELETED:
									json_array_append_new(flagsarr, json_string("\\Deleted"));
									break;
								case MAILIMAP_FLAG_SEEN:
									json_array_append_new(flagsarr, json_string("\\Seen"));
									break;
								case MAILIMAP_FLAG_DRAFT:
									json_array_append_new(flagsarr, json_string("\\Draft"));
									break;
								case MAILIMAP_FLAG_KEYWORD:
									json_array_append_new(flagsarr, json_string(flag->fl_flag->fl_data.fl_keyword));
									break;
								case MAILIMAP_FLAG_EXTENSION:
									json_array_append_new(flagsarr, json_string(flag->fl_flag->fl_data.fl_extension));
									break;
							}
							break;
					}
				}
			}
		}
	}
}

static int fetchlist(struct ws_session *ws, struct imap_client *client, const char *reason, int start, int end, int page, int pagesize, int numpages, const char *sort, const char *filter)
{
	int expected, res, c = 0;
	struct mailimap_set *set = NULL;
	struct mailimap_fetch_type *fetch_type = NULL;
	struct mailimap_fetch_att *fetch_att = NULL;
	clist *fetch_result = NULL;
	clistiter *cur, *cur2;
	clist *hdrlist;
	char *headername = NULL;
	struct mailimap_header_list *imap_hdrlist;
	struct mailimap_section *section;
	json_t *root = NULL, *arr;
	int added = 0;

	/* start to end is inclusive */
	expected = end - start + 1;
	bbs_debug(3, "Fetching message listing %d:%d (page %d of %d), sort: %s, filter: %s\n", start, end, page, numpages, S_IF(sort), S_IF(filter));
	webmail_log(4, client, "<= FETCHLIST %d:%d (page %d of %d), sort: %s, filter: %s\n", start, end, page, numpages, S_IF(sort), S_IF(filter));

	/* Fetch: UID, flags, size, from, to, subject, internaldate,
	 * +with attributes: priority headers, contains attachments */
	if (sort && !client->has_sort) {
		bbs_debug(3, "Can't sort, sort not available\n");
		client_set_status(ws, "Your IMAP server does not support SORT");
		sort = NULL; /* If server doesn't support sort, we can't sort */
	}
	/* Thankfully, SEARCH is not an extension, it should be supported by all IMAP servers */
	if (sort || filter) {
		int index = 1;
		int searchlist, sortlist;
		/*! \todo Cache this between FETCHLIST calls */
		clist *sorted = sortall(client, sort, filter, &searchlist, &sortlist); /* This could be somewhat slow, since we have sort the ENTIRE mailbox every time */
		if (!sorted) {
			return -1;
		}
		set = mailimap_set_new_empty();
		if (!set) {
			if (sortlist) {
				mailimap_sort_result_free(sorted);
			} else if (searchlist) {
				mailimap_search_result_free(sorted);
			}
			return -1;
		}
		if (filter) {
			/* Since # messages is not client->messages, we need to paginate accordingly. */
			int total = clist_count(sorted);
			/* The # pages could be different since # of results could be anything */
			numpages = (total + (pagesize - 1)) / pagesize; /* avoid ceil() */
			bbs_debug(5, "Total # messages: %d, # pages: %d, requested page: %d\n", total, numpages, page);
			if (page > numpages) {
				bbs_debug(3, "Capping page to %d\n", numpages);
				page = numpages;
			}
			/* Recalculate */
			start = total - (pagesize * page) + 1;
			if (start < 1) {
				start = 1;
			}
			end = start + (pagesize - 1);
		}
		for (cur = clist_begin(sorted); cur; index++, cur = clist_next(cur)) {
			uint32_t *seqno;
			if (index < start) {
				continue;
			}
			seqno = clist_content(cur);
			res = mailimap_set_add_single(set, *seqno);
			added++;
			if (res != MAILIMAP_NO_ERROR) {
				bbs_error("Failed to add sorted seqno to list: %u\n", *seqno);
				if (sortlist) {
					mailimap_sort_result_free(sorted);
				} else if (searchlist) {
					mailimap_search_result_free(sorted);
				}
				return -1;
			}
			if (index >= end) {
				break;
			}
		}
		bbs_debug(6, "SEARCH/SORT matched %d result%s\n", added, ESS(added));
		if (sortlist) {
			mailimap_sort_result_free(sorted);
		} else if (searchlist) {
			mailimap_search_result_free(sorted);
		}
	} else {
		set = mailimap_set_new_interval((uint32_t) start, (uint32_t) end);
		added = (end - start + 1);
	}

	client->start = start;
	client->end = end;

	/* In the case of a filter, there might not be anything */
	if (added) {
		fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();

		/* UID */
		fetch_att = mailimap_fetch_att_new_uid();
		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_flags()); /* Flags */
		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_internaldate()); /* INTERNALDATE */
		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_rfc822_size()); /* Size */
		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_bodystructure()); /* BODYSTRUCTURE (for attachments) */

		/* Headers */
		hdrlist = clist_new();
		if (!hdrlist) {
			mailimap_set_free(set);
			mailimap_fetch_att_free(fetch_att);
			return -1;
		}

#define FETCH_HEADER(name) \
	headername = strdup(name); \
	res = clist_append(hdrlist, headername); \
	if (!hdrlist) { \
		goto cleanup; \
	}

		FETCH_HEADER("Date");
		FETCH_HEADER("Subject");
		FETCH_HEADER("From");
		FETCH_HEADER("To");
		FETCH_HEADER("X-Priority");
		FETCH_HEADER("Importance");
		FETCH_HEADER("X-MSMail-Priority");
		FETCH_HEADER("Priority");

		imap_hdrlist = mailimap_header_list_new(hdrlist);
		section = mailimap_section_new_header_fields(imap_hdrlist);
		if (!section) {
			goto cleanup2;
		}
		fetch_att = mailimap_fetch_att_new_body_peek_section(section);
		if (!fetch_att) {
			goto cleanup2;
		}
		res = mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);
		if (MAILIMAP_ERROR(res)) {
			goto cleanup;
		}
		fetch_att = NULL;

		/* Fetch! By sequence number, not UID. */
		res = mailimap_fetch(client->imap, set, fetch_type, &fetch_result);
		mailimap_fetch_type_free(fetch_type);
		/* Don't go to cleanup past this point, so no need to set fetch_type/set to NULL */
		if (MAILIMAP_ERROR(res)) {
			bbs_warning("FETCH failed: %s\n", maildriver_strerror(res));
			/* fetch_result and everything that went into it is already freed */
			mailimap_set_free(set);
			return -1;
		}
	}

	root = json_object();
	if (!root) {
		if (fetch_result) {
			mailimap_fetch_list_free(fetch_result);
		}
		mailimap_set_free(set);
		return -1;
	}

	json_object_set_new(root, "response", json_string("FETCHLIST"));
	json_object_set_new(root, "cause", json_string(reason));
	json_object_set_new(root, "mailbox", json_string(client->mailbox));
	json_object_set_new(root, "page", json_integer(page));
	json_object_set_new(root, "numpages", json_integer(numpages));

	arr = json_array();
	json_object_set_new(root, "data", arr);

	if (!added) {
		/* If we filtered, there might not be any results */
		goto finalize;
	}

	if (sort) {
		/* We need to add the messages in the order of the SORT response.
		 * This is O(n^2), unfortunately (although the # of messages for FETCHLIST
		 * should be relatively small, certainly not N).
		 * We can't use qsort directly to sort the messages first and then do a linear scan,
		 * because it's in the custom clist (linked list).
		 * XXX We could however create an array of pointers and sort the pointers... */
		clist *set_list = set->set_list;
		for (cur2 = clist_begin(set_list); cur2; cur2 = clist_next(cur2)) {
			struct mailimap_set_item *item = clist_content(cur2);
			/* This is the nice thing about using a single set item for every message
			 * when we sort, even if we could use a range. It makes this step easier,
			 * since item->set_first == item->set_last */
			uint32_t seqno = item->set_first;
			bbs_assert(item->set_first == item->set_last);
			/* Look for this message in the linked list of FETCH responses,
			 * since they could be in any order.
			 * Worst case we have to do a linear scan for every message. */
			for (cur = clist_begin(fetch_result); cur; cur = clist_next(cur)) {
				struct mailimap_msg_att *msg_att = clist_content(cur);
				if (msg_att->att_number != seqno) {
					continue;
				}
				fetchlist_single(msg_att, arr);
				seqno = 0;
				c++;
				break;
			}
			if (seqno) {
				/* This shouldn't happened. The message was in the SORT response,
				 * and barring some awesome race condition, if we FETCH it,
				 * then it should be in the response as well.
				 * Regardless, we're still adding messages in the proper order.
				 */
				bbs_warning("No FETCH response for seqno %u?\n", seqno);
			}
		}
	} else {
		/* Not sorted. Order doesn't matter. */
		for (cur = clist_begin(fetch_result); cur; cur = clist_next(cur)) {
			struct mailimap_msg_att *msg_att = clist_content(cur);
			fetchlist_single(msg_att, arr);
			c++;
		}
	}

	/* The messages are in ascending order here.
	 * They are displayed newest first in the the webmail client,
	 * but we let frontend JavaScript reverse this JSON array,
	 * since jansson doesn't have a function to reverse arrays? */

	if (c != expected && !filter) { /* If we filtered, there might be fewer results than expected? */
		bbs_warning("Expected to fetch %d (%d:%d) messages but only fetched %d?\n", expected, start, end, c);
	}

	mailimap_fetch_list_free(fetch_result);

finalize:
	mailimap_set_free(set);

	/* XXX Should this be done only for SELECT, not each FETCHLIST? */
	append_quota(root, client);

	json_send(ws, root);
	return 0;

cleanup:
	mailimap_set_free(set);
	free_if(headername);
	/* Doesn't compile: clist_foreach(hdrlist, (clist_func) free, NULL); */
	for (cur = clist_begin(hdrlist); cur; cur = clist_next(cur)) {
		headername = clist_content(cur);
		free(headername);
	}
	clist_free(hdrlist);

	if (fetch_att) {
		mailimap_fetch_att_free(fetch_att);
	}
	if (fetch_type) {
		mailimap_fetch_type_free(fetch_type);
	}
	json_decref(root);
	return -1;

cleanup2:
	mailimap_set_free(set);
	mailimap_header_list_free(imap_hdrlist);
	if (fetch_att) {
		mailimap_fetch_att_free(fetch_att);
	}
	if (fetch_type) {
		mailimap_fetch_type_free(fetch_type);
	}
	json_decref(root);
	return -1;
}

static int handle_fetchlist(struct ws_session *ws, struct imap_client *client, const char *reason, int page, int pagesize, const char *sort, const char *filter)
{
	uint32_t total;
	int numpages, start, end;
	const char *oldsort = client->sort;
	const char *oldfilter = client->filter;

	if (page < 1) {
		page = 1;
	}
	if (pagesize < 1) {
		pagesize = 25;
	}

	/* Cache */
	client->page = page;
	client->pagesize = pagesize;
	client->uid = 0;
	if (!(client->sort && sort && !strcmp(sort, client->sort))) { /* Don't free and strdup if the string is the same */
		free_if(client->sort);
		if (sort && (sort == oldsort || strcmp(sort, "none"))) { /* If sort is aliased with what client->sort was, it's invalid, so duplicate */
			client->sort = strdup(sort);
		}
	}
	if (!(client->filter && filter && !strcmp(filter, client->filter))) {
		free_if(client->filter);
		if (filter && (filter == oldfilter || strcmp(filter, "none"))) {
			client->filter = strdup(filter);
		}
	}

	/* A mailbox MUST be currently selected here */
	total = client->messages;
	if (!total) {
		json_t *root = json_object();
		bbs_debug(5, "Mailbox is empty, no listing to provide\n");
		if (root) {
			/* Send an empty list to refresh the current mailbox to empty */
			json_object_set_new(root, "response", json_string("FETCHLIST"));
			json_object_set_new(root, "cause", json_string(reason));
			json_object_set_new(root, "mailbox", json_string(client->mailbox));
			json_object_set_new(root, "page", json_integer(page));
			json_object_set_new(root, "numpages", json_integer(1));
			json_object_set_new(root, "data", json_array());
			json_send(ws, root);
		}
		return 0;
	}

	/* Calculate pagination */
	/* Logically, numpages = ceil(total / pagesize) */
	numpages = ((int) total + (pagesize - 1)) / pagesize; /* avoid ceil() */
	start = (int) total - (pagesize * page) + 1;
	if (start < 1) {
		start = 1;
	}
	end = start + (pagesize - 1);
	if (end < 1) {
		end = 0; /* But we must not pass 1:0 to libetpan, or that will turn into 1:* */
		return -1;
	} else if (end > (int) total) {
		end = (int) total; /* End can't be beyond the max # of messages */
	}
	return fetchlist(ws, client, reason, start, end, page, pagesize, numpages, client->sort, client->filter);
}

static void fetch_mime_recurse_single(const char **body, size_t *len, struct mailmime_data *data)
{
	switch (data->dt_type) {
		case MAILMIME_DATA_TEXT:
			bbs_debug(7, "data : %lu bytes\n", data->dt_data.dt_text.dt_length);
			*body = data->dt_data.dt_text.dt_data;
			*len = data->dt_data.dt_text.dt_length;
			break;
		case MAILMIME_DATA_FILE:
			bbs_debug(7, "data (file) : %s\n", data->dt_data.dt_filename);
			break;
	}
}

static void append_recipients(json_t *recipients, struct mailimf_address_list *addr_list)
{
	clistiter *cur;
	struct mailimf_mailbox *mb;
	char addrbuf[256];

	for (cur = clist_begin(addr_list->ad_list); cur; cur = clist_next(cur)) {
		char *decoded;
		const char *name;
		struct mailimf_address *addr = clist_content(cur);
		switch (addr->ad_type) {
			case MAILIMF_ADDRESS_GROUP:
				bbs_debug(5, "Group address?\n");
				break;
			case MAILIMF_ADDRESS_MAILBOX:
				mb = addr->ad_data.ad_mailbox;
				decoded = mb->mb_display_name ? mime_header_decode(mb->mb_display_name) : NULL;
				name = decoded ? decoded : mb->mb_display_name;
				snprintf(addrbuf, sizeof(addrbuf), "%s%s<%s>", S_IF(name), !strlen_zero(name) ? " " : "", mb->mb_addr_spec);
				json_array_append_new(recipients, json_string(addrbuf));
				free_if(decoded);
				break;
		}
	}
}

static int fetch_mime_recurse(json_t *root, json_t *attachments, struct mailmime *mime, int level, int *bodyencoding, const char **body, size_t *len, int html)
{
	struct mailmime_fields *fields;
	struct mailmime_content *content_type;
	int text_plain = 0, text_html = 0;
	int pt_flowed = 0;
	int is_attachment = 0;
	int encoding;
	clistiter *cur;
	clist *parameters;

	level++;

	switch (mime->mm_type) {
		case MAILMIME_SINGLE:
			bbs_debug(3, "Single part\n");
			break;
		case MAILMIME_MULTIPLE:
			bbs_debug(3, "Multipart\n");
			break;
		case MAILMIME_MESSAGE:
			bbs_debug(3, "Message\n");
			break;
	}

	fields = mime->mm_mime_fields;

	/* https://sourceforge.net/p/libetpan/mailman/libetpan-users/thread/etPan.442f9a32.136d1751.1f41%40utopia/
	 * To get the HTML body from MIME structure:
	 * - display multipart/mixed in the given order
	 * - display multipart/parallel in any order
	 * - display one sub-part of the multipart/alternative (for example, if there is an HTML part, display it)
	 */

	content_type = mime->mm_content_type;
	/* We care about the encoding, mainly for quoted-printable Content-Transfer-Encoding.
	 * format=flowed is in the Content-Type, and we don't deal with that here, the frontend does. */
	encoding = fields ? mailmime_transfer_encoding_get(fields) : MAILMIME_MECHANISM_8BIT;
	parameters = content_type->ct_parameters;
	switch (content_type->ct_type->tp_type) {
		case MAILMIME_TYPE_DISCRETE_TYPE:
			switch (content_type->ct_type->tp_data.tp_discrete_type->dt_type) {
				case MAILMIME_DISCRETE_TYPE_TEXT:
					bbs_debug(7, "[%d] text/%s\n", level, content_type->ct_subtype);
					if (!strcasecmp(content_type->ct_subtype, "plain")) {
						text_plain = 1;
					} else if (!strcasecmp(content_type->ct_subtype, "html")) {
						text_html = 1;
					}
					break;
				case MAILMIME_DISCRETE_TYPE_IMAGE:
					bbs_debug(7, "[%d] image/%s\n", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_AUDIO:
					bbs_debug(7, "[%d] audio/%s\n", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_VIDEO:
					bbs_debug(7, "[%d] video/%s\n", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_APPLICATION:
					bbs_debug(7, "[%d] application/%s\n", level, content_type->ct_subtype);
					if (!strcmp(content_type->ct_subtype, "octet-stream")) {
						is_attachment = 1;
					}
					break;
				case MAILMIME_DISCRETE_TYPE_EXTENSION:
					bbs_debug(7, "[%d] %s/%s\n", level, content_type->ct_type->tp_data.tp_discrete_type->dt_extension, content_type->ct_subtype);
					break;
			}
			break;
		case MAILMIME_TYPE_COMPOSITE_TYPE:
			switch (content_type->ct_type->tp_data.tp_composite_type->ct_type) {
				case MAILMIME_COMPOSITE_TYPE_MESSAGE:
					bbs_debug(7, "[%d] message/%s\n", level, content_type->ct_subtype);
					break;
				case MAILMIME_COMPOSITE_TYPE_MULTIPART:
					bbs_debug(7, "[%d] multipart/%s\n", level, content_type->ct_subtype);
					if (!strcasecmp(content_type->ct_subtype, "alternative")) {
						text_html = 1;
					}
					break;
				case MAILMIME_COMPOSITE_TYPE_EXTENSION:
					bbs_debug(7, "[%d] %s/%s\n", level, content_type->ct_type->tp_data.tp_composite_type->ct_token, content_type->ct_subtype);
					break;
			}
	}

	for (cur = clist_begin(parameters); cur; cur = clist_next(cur)) {
		struct mailmime_parameter *param = clist_content(cur);
		bbs_debug(7, ";%s=%s\n", param->pa_name, param->pa_value);
		if (text_plain && !strcmp(param->pa_name, "format")) {
			if (!strcmp(param->pa_value, "flowed")) {
				pt_flowed = 1;
			}
		} else if (!strcmp(param->pa_name, "name")) {
			json_t *attach = json_object();
			is_attachment = 1;
			/* If it's an attachment, add the name (and size) to the list */
			if (attach) {
				const char *body2;
				size_t len2 = 0;
				json_array_append_new(attachments, attach);
				json_object_set_new(attach, "name", json_string(param->pa_value));
				/* Get the size of the attachment by reusing fetch_mime_recurse_single for that purpose. */
				if (mime->mm_type == MAILMIME_SINGLE) {
					fetch_mime_recurse_single(&body2, &len2, mime->mm_data.mm_single);
					if (len2) {
						json_object_set_new(attach, "size", json_integer((json_int_t) len2));
					}
				}
			}
		}
	}

	switch (mime->mm_type) {
		case MAILMIME_SINGLE:
			/* The goal here is to not show attachments in an email,
			 * e.g.:
			 * - message/rfc822
			 * |- multipart/mixed
			 *   |- text/plain (body)
			 *   |- text/plain (attachment)
			 *
			 * We can't just stop when we find the message body,
			 * because we also need to process attachments to list them.
			 * But we need to be aware that anything after the body must be an attachment, not the body. */
			if (!is_attachment) { /* Haven't yet found the message body */
				if (html && text_html) {
					fetch_mime_recurse_single(body, len, mime->mm_data.mm_single);
					if (body && len) {
						bbs_debug(7, "Using text/html part\n");
						json_object_set_new(root, "contenttype", json_string("text/html"));
					}
					*bodyencoding = encoding;
				} else if (!*bodyencoding && text_plain) {
					fetch_mime_recurse_single(body, len, mime->mm_data.mm_single);
					if (body && len) {
						bbs_debug(7, "Using text/plain part\n");
						json_object_set_new(root, "contenttype", json_string(pt_flowed ? "text/plain; format=flowed" : "text/plain"));
					}
					*bodyencoding = encoding;
				}
			}
			break;
		case MAILMIME_MULTIPLE:
			for (cur = clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur; cur = clist_next(cur)) {
				fetch_mime_recurse(root, attachments, clist_content(cur), level, bodyencoding, body, len, html);
			}
			break;
		case MAILMIME_MESSAGE:
			/* A message could have multiple Subject, etc. headers if it contains an RFC 822 message
			 * as an attachment, e.g. a non-delivery report. In that case, the first one we encounter
			 * is the real one, and everything else afterwards should be ignored. */
#define json_set_header(root, name, value) \
	if (!json_object_string_value(root, name)) { \
		json_object_set_new(root, name, value); \
	}

			if (mime->mm_data.mm_message.mm_fields) {
				/* Use the MIME decoded headers to both handle decoding and so we don't have to parse headers ourselves */
				if (clist_begin(mime->mm_data.mm_message.mm_fields->fld_list)) {
					struct mailimf_fields *mffields = mime->mm_data.mm_message.mm_fields;
					json_t *to, *cc, *replyto;
					to = json_array();
					cc = json_array();
					replyto = json_array();
					json_set_header(root, "to", to);
					json_set_header(root, "cc", cc);
					json_set_header(root, "replyto", replyto);
					for (cur = clist_begin(mffields->fld_list); cur; cur = clist_next(cur)) {
						clistiter *fcur;
						struct mailimf_subject *subject;
						struct mailimf_orig_date *orig_date;
						struct mailimf_date_time *dt;
						char buf[40];
						char *decoded;
						const char *name;
						struct mailimf_field *f = clist_content(cur);
						switch (f->fld_type) {
							case MAILIMF_FIELD_ORIG_DATE:
								orig_date = f->fld_data.fld_orig_date;
								dt = orig_date->dt_date_time;
								snprintf(buf, sizeof(buf), "%4d-%02d-%02d %02d:%02d:%02d %c%04d",
									dt->dt_year, dt->dt_month, dt->dt_day, dt->dt_hour, dt->dt_min, dt->dt_sec,
									dt->dt_zone < 0 ? '-' : '+', dt->dt_zone < 0 ? -dt->dt_zone : dt->dt_zone);
								append_datetime(root, "sent", buf);
								break;
							case MAILIMF_FIELD_FROM:
								/* libetpan allows for multiple, but basically all emails have at max 1 From address */
								fcur = clist_begin(f->fld_data.fld_from->frm_mb_list->mb_list);
								if (fcur) {
									char frombuf[256];
									struct mailimf_mailbox *mb = clist_content(fcur);
									decoded = mb->mb_display_name ? mime_header_decode(mb->mb_display_name) : NULL;
									name = decoded ? decoded : mb->mb_display_name;
									snprintf(frombuf, sizeof(frombuf), "%s%s<%s>", S_IF(name), !strlen_zero(name) ? " " : "", mb->mb_addr_spec);
									bbs_debug(6, "From: %s\n", frombuf);
									json_set_header(root, "from", json_string(frombuf));
									free_if(decoded);
								}
								break;
							case MAILIMF_FIELD_REPLY_TO:
								append_recipients(to, f->fld_data.fld_reply_to->rt_addr_list);
								break;
							case MAILIMF_FIELD_TO:
								append_recipients(to, f->fld_data.fld_to->to_addr_list);
								break;
							case MAILIMF_FIELD_CC:
								append_recipients(to, f->fld_data.fld_cc->cc_addr_list);
								break;
							case MAILIMF_FIELD_SUBJECT:
								subject = f->fld_data.fld_subject;
								decoded = subject ? mime_header_decode(subject->sbj_value) : NULL;
								name = decoded ? decoded : subject ? subject->sbj_value : NULL;
								bbs_debug(5, "Subject: %s\n", name);
								json_set_header(root, "subject", json_string(name));
								free_if(decoded);
								break;
							case MAILIMF_FIELD_MESSAGE_ID:
								bbs_debug(5, "Message-ID: %s\n", f->fld_data.fld_message_id->mid_value);
								json_set_header(root, "messageid", json_string(f->fld_data.fld_message_id->mid_value));
								break;
							/* Skip Reply-To and References here, we just want the raw versions for FETCH,
							 * not the parsed versions, and we don't need them for FETCHLIST */
							default:
								/* Ignore others */
								break;
						}
					}
				}
				if (mime->mm_data.mm_message.mm_msg_mime) {
					fetch_mime_recurse(root, attachments, mime->mm_data.mm_message.mm_msg_mime, level, bodyencoding, body, len, html);
				}
			}
			break;
	}

	return 0;
}

static int fetch_mime(json_t *root, int html, const char *msg_body, size_t msg_size, int expect_body)
{
	int res;
	size_t current_index = 0; /* This must be initialized */
	struct mailmime *mime;
	const char *body = NULL;
	size_t len = 0;
	int encoding = 0;
	json_t *attachments = json_array();

	if (!attachments) {
		return -1;
	}

	json_object_set_new(root, "attachments", attachments);

	res = mailmime_parse(msg_body, msg_size, &current_index, &mime);
	if (res != MAILIMF_NO_ERROR) {
		return -1;
	}

	fetch_mime_recurse(root, attachments, mime, 0, &encoding, &body, &len, html);
	bbs_debug(7, "FETCH result: want HTML=%d, bodylen=%lu\n", html, len);
	if (body && len) {
		size_t idx = 0;
		char *result;
		size_t resultlen;
		/* Decode the body if needed. */
		switch (encoding) {
			case MAILMIME_MECHANISM_BASE64:
				bbs_debug(7, "Base64 encoded\n");
				break;
			case MAILMIME_MECHANISM_QUOTED_PRINTABLE:
				bbs_debug(7, "Quoted printable encoded\n");
				break;
			case MAILMIME_MECHANISM_7BIT:
				bbs_debug(7, "7-bit encoded\n");
				break;
			case MAILMIME_MECHANISM_8BIT:
				bbs_debug(7, "8-bit encoded\n");
				break;
			case MAILMIME_MECHANISM_BINARY:
				bbs_debug(7, "Binary encoded\n");
				break;
		}
		res = mailmime_part_parse(body, len, &idx, encoding, &result, &resultlen);
		if (MAILIMAP_ERROR(res)) {
			json_object_set_new(root, "body", json_stringn(body, len));
		} else {
			json_t *jsonbody = NULL;
			char *d_body = result;
			char *decoded = NULL;

			/* 7-bit and 8-bit don't need any special handling.
			 * Quoted printable needs to be decoded appropriately (below).
			 * Base64 is (in practice) only used for attachments, not the actual message content.
			 * Similar for binary, if that's even used at all. */
			if (encoding == MAILMIME_MECHANISM_QUOTED_PRINTABLE) {
				size_t qlen = 0;
#if 0
				size_t index;
				/* This doesn't work: */
				int dres = mailmime_quoted_printable_body_parse(result, resultlen, &index, &decoded, &qlen, 0);
				if (dres == MAILIMAP_NO_ERROR && decoded) {
#else
				decoded = strndup(body, len);
				/* We pass in 0 to bbs_quoted_printable_decode since bbs_utf8_remove_invalid handles invalid UTF-8 more robustly,
				 * so all invalid character removal is done in the second pass. */
				if (ALLOC_SUCCESS(decoded) && !bbs_quoted_printable_decode(decoded, &qlen, 0)) { /* Need to operate on original body, mailmime_part_parse removes quoted printable stuff */
#endif
					bbs_debug(3, "Translated quoted-printable body of length %lu to body of length %lu\n", resultlen, qlen);
					jsonbody = json_stringn(decoded, qlen);
#ifdef EXTRA_CHECKS
					if (!jsonbody) {
						bbs_utf8_remove_invalid((unsigned char*) decoded, &qlen);
						jsonbody = json_stringn(decoded, qlen);
					}
#endif
					if (!jsonbody) {
						bbs_warning("Failed to encode decoded quoted-printable body %p (%lu) as JSON\n", d_body, qlen);
						/* Just encode the non-decoded version... will be incomplete (missing quoted-printable stuff) but mostly faithful */
					} else {
						resultlen = qlen;
						d_body = decoded;
					}
				} else {
					bbs_warning("Could not decode quoted printable body?\n");
				}
			}
			/*! \todo Support RFC 2392 inline cid: links */
			if (!jsonbody) {
				jsonbody = json_stringn(d_body, resultlen);
			}
			if (!jsonbody) {
#ifdef EXTRA_CHECKS
				bbs_utf8_remove_invalid((unsigned char*) d_body, &resultlen);
				jsonbody = json_stringn(d_body, resultlen);
#endif
				if (!jsonbody) {
					bbs_warning("Failed to encode body %p (%lu) as JSON\n", d_body, resultlen);
				} else {
					bbs_warning("Message body is not valid UTF-8 and has been converted with omissions\n");
				}
			}
			json_object_set_new(root, "body", jsonbody);
			mailmime_decoded_part_free(result);
			free_if(decoded);
		}
	} else {
		if (expect_body) {
			bbs_warning("Failed to determine a suitable body for message?\n");
		}
	}
	mailmime_free(mime);
	return body ? 0 : -1;
}

static void send_preview(struct ws_session *ws, struct imap_client *client, uint32_t seqno)
{
	int res;
	struct mailimap_set *set;
	struct mailimap_fetch_type *fetch_type;
	struct mailimap_fetch_att *fetch_att;
	clist *fetch_result = NULL;
	clistiter *cur;
	struct mailimap_msg_att *msg_att;
	json_t *root = NULL;

	root = json_object();
	if (!root) {
		bbs_error("Failed to allocate JSON object\n");
		return;
	}

	set = mailimap_set_new_single(seqno);
	fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();

	if (!fetch_type) {
		return;
	}

	fetch_att = mailimap_fetch_att_new_uid();
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

	/* Do NOT automark as seen */
	fetch_att = mailimap_fetch_att_new_rfc822_header();
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

	/* No need to get INTERNALDATE, because that would be right now */

	/* Fetch by sequence number */
	res = mailimap_fetch(client->imap, set, fetch_type, &fetch_result);
	if (MAILIMAP_ERROR(res)) {
		bbs_warning("FETCH failed: %s\n", maildriver_strerror(res));
		fetch_result = NULL;
		goto cleanup;
	}

	json_object_set_new(root, "response", json_string("EXISTS"));

	cur = clist_begin(fetch_result);
	msg_att = clist_content(cur);
	if (!msg_att) {
		goto cleanup;
	}
	for (cur = clist_begin(msg_att->att_list); cur ; cur = clist_next(cur)) {
		struct mailimap_msg_att_item *item = clist_content(cur);
		if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC) {
			size_t msg_size;
			char *msg_body;
			char *eoh;
			switch (item->att_data.att_static->att_type) {
				case MAILIMAP_MSG_ATT_UID:
					json_object_set_new(root, "uid", json_integer(item->att_data.att_static->att_data.att_uid));
					break;
				case MAILIMAP_MSG_ATT_RFC822_HEADER:
					/* These are just the headers, not the whole body */
					msg_body = item->att_data.att_static->att_data.att_rfc822_header.att_content;
					msg_size = item->att_data.att_static->att_data.att_rfc822_header.att_length;
					eoh = memmem(msg_body, msg_size, "\r\n\r\n", STRLEN("\r\n\r\n")); /* Find end of headers */
					if (eoh) {
						size_t headerlen = (size_t) (eoh - msg_body);
						char *dupheaders = memdup(msg_body, headerlen);
						if (ALLOC_SUCCESS(dupheaders)) {
							append_header_meta(root, dupheaders, 0);
							free(dupheaders);
						}
					}
					fetch_mime(root, 0, msg_body, msg_size, 0);
					break;
				default:
					bbs_warning("Unhandled type\n");
			}
		}
	}

	if (!json_object_int_value(root, "uid")) {
		bbs_warning("Message %u missing UID\n", seqno);
	}

	json_send(ws, root);
	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	mailimap_fetch_list_free(fetch_result);
	return;

cleanup:
	bbs_debug(3, "Preview failed\n");
	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	if (fetch_result) {
		mailimap_fetch_list_free(fetch_result);
	}
	json_decref(root);
}

static int handle_fetch(struct ws_session *ws, struct imap_client *client, uint32_t uid, int html, int raw)
{
	int res;
	struct mailimap_set *set;
	struct mailimap_fetch_type *fetch_type;
	struct mailimap_fetch_att *fetch_att;
	clist *fetch_result = NULL;
	clistiter *cur;
	struct mailimap_section *section;
	struct mailimap_msg_att *msg_att;
	json_t *root = NULL, *attachments;

	webmail_log(1, client, "=> FETCH %u (%s)\n", uid, raw ? "raw" : html ? "html" : "plaintext");

	if (!uid) {
		bbs_warning("Invalid UID: %u\n", uid);
		return -1;
	}

	root = json_object();
	if (!root) {
		return -1;
	}

/* Automatically mark selected messages as Seen. This is typically expected behavior. */
#define AUTO_MARK_SEEN

	set = mailimap_set_new_single(uid);
	fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
	fetch_att = mailimap_fetch_att_new_internaldate();
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);
	section = mailimap_section_new(NULL);
#ifdef AUTO_MARK_SEEN
	fetch_att = mailimap_fetch_att_new_body_section(section);
#else
	fetch_att = mailimap_fetch_att_new_body_peek_section(section);
#endif
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

	/* Fetch by UID */
	res = mailimap_uid_fetch(client->imap, set, fetch_type, &fetch_result);
	if (MAILIMAP_ERROR(res)) {
		bbs_warning("FETCH failed: %s\n", maildriver_strerror(res));
		goto cleanup;
	}

	json_object_set_new(root, "response", json_string("FETCH"));
	attachments = json_array();
	json_object_set_new(root, "attachments", attachments);

	/* There's only one message, no need to have a for loop: */
	cur = clist_begin(fetch_result);
	msg_att = clist_content(cur);
	if (!msg_att) {
		goto cleanup;
	}
	for (cur = clist_begin(msg_att->att_list); cur ; cur = clist_next(cur)) {
		struct mailimap_msg_att_item *item = clist_content(cur);
		if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC) {
			size_t msg_size;
			char *msg_body;
			char *eoh;
			switch (item->att_data.att_static->att_type) {
				case MAILIMAP_MSG_ATT_UID:
					json_object_set_new(root, "uid", json_integer(item->att_data.att_static->att_data.att_uid));
					break;
				case MAILIMAP_MSG_ATT_INTERNALDATE:
					append_internaldate(root, item->att_data.att_static->att_data.att_internal_date);
					break;
				case MAILIMAP_MSG_ATT_BODY_SECTION:
					msg_size = item->att_data.att_static->att_data.att_body_section->sec_length;
					msg_body = item->att_data.att_static->att_data.att_body_section->sec_body_part;
					eoh = memmem(msg_body, msg_size, "\r\n\r\n", STRLEN("\r\n\r\n")); /* Find end of headers */
					if (eoh) {
						size_t headerlen = (size_t) (eoh - msg_body);
						char *dupheaders = memdup(msg_body, headerlen);
						if (ALLOC_SUCCESS(dupheaders)) {
							append_header_meta(root, dupheaders, 0);
							free(dupheaders);
						}
					}
					if (raw) {
						json_object_set_new(root, "body", json_stringn(msg_body, msg_size)); /* We know how large it is, so just use the size */
					} else {
						fetch_mime(root, html, msg_body, msg_size, 1);
					}
					break;
				default:
					bbs_warning("Unhandled type\n");
			}
		}
	}

	client->uid = uid;

	if (!json_object_int_value(root, "uid")) {
		bbs_warning("Message %u missing UID\n", uid);
	}
	if (!json_object_string_value(root, "body")) {
		bbs_warning("Message %u missing body\n", uid);
	}

	json_send(ws, root);
	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	mailimap_fetch_list_free(fetch_result);
	return 0;

cleanup:
	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	if (fetch_result) {
		mailimap_fetch_list_free(fetch_result);
	}
	json_decref(root);
	return -1;
}

static struct mailimap_set *uidset(json_t *uids)
{
	size_t i;
	struct mailimap_set *set;

	if (json_is_string(uids) && json_string_value(uids)) {
		if (!strcmp(json_string_value(uids), "1:*")) {
			/* All messages in mailbox */
			set = mailimap_set_new_interval(1, 0);
			webmail_log(3, NULL, "=> UID 1:*\n");
			return set;
		} else {
			/* Must use an array for everything else */
			bbs_warning("Invalid UID set: %s\n", json_string_value(uids));
			return NULL;
		}
	}

	if (!uids || !json_is_array(uids) || !json_array_size(uids)) {
		bbs_warning("No UIDs provided\n");
		return NULL;
	}

	set = mailimap_set_new_empty();
	if (!set) {
		return NULL;
	}
	for (i = 0; i < json_array_size(uids); i++) {
		int res;
		json_int_t uid;
		json_t *j = json_array_get(uids, i);
		uid = json_integer_value(j);
		if (uid < 1) {
			bbs_warning("Invalid UID: %llu\n", uid);
			continue;
		}
		webmail_log(3, NULL, "=> UID %llu\n", uid);
		res = mailimap_set_add_single(set, (uint32_t) uid);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("Failed to add UID %lld to list\n", uid);
		}
	}
	return set;
}

static int __handle_store(struct imap_client *client, int sign, struct mailimap_set *set, struct mailimap_flag_list *flag_list)
{
	int res;
	struct mailimap_store_att_flags *att_flags;

	if (sign > 0) {
		att_flags = mailimap_store_att_flags_new_add_flags_silent(flag_list);
	} else {
		att_flags = mailimap_store_att_flags_new_remove_flags_silent(flag_list);
	}
	if (!att_flags) {
		goto cleanup;
	}

	res = mailimap_uid_store(client->imap, set, att_flags);
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("UID STORE failed: %s\n", maildriver_strerror(res));
	}
	/* Regardless of whether it failed or not, we're done */
	mailimap_store_att_flags_free(att_flags);
	mailimap_set_free(set);
	return 0;

cleanup:
	mailimap_flag_list_free(flag_list);
	mailimap_set_free(set);
	return -1;
}

/*!
 * \brief Add or remove an arbitrary flag from a message.
 * \param client
 * \param sign 1 to store flag, -1 to remove flag
 * \param uids
 * \param flagname
 */
static int handle_store(struct imap_client *client, int sign, json_t *uids, const char *flagname)
{
	int res;
	struct mailimap_flag_list *flag_list;
	struct mailimap_flag *flag;
	struct mailimap_set *set;
	char *keyword = NULL;

	webmail_log(1, client, "=> STORE %c%s\n", sign ? '+' : '-', flagname);

	set = uidset(uids);
	if (!set) {
		return -1;
	}

	flag_list = mailimap_flag_list_new_empty();
	if (!strcasecmp(flagname, "\\Seen")) {
		flag = mailimap_flag_new_seen();
	} else if (!strcasecmp(flagname, "\\Deleted")) {
		flag = mailimap_flag_new_deleted();
	} else if (!strcasecmp(flagname, "\\Flagged")) {
		flag = mailimap_flag_new_flagged();
	} else if (!strcasecmp(flagname, "\\Answered")) {
		flag = mailimap_flag_new_answered();
	} else {
		keyword = strdup(flagname);
		flag = mailimap_flag_new_flag_keyword(keyword);
	}
	res = mailimap_flag_list_add(flag_list, flag);
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("LIST add failed: %s\n", maildriver_strerror(res));
		mailimap_flag_free(flag);
		mailimap_flag_list_free(flag_list);
		mailimap_set_free(set);
		free_if(keyword);
		return -1;
	}

	return __handle_store(client, sign, set, flag_list);
}

/*!
 * \brief Add or remove the \Seen flag from a message.
 * \param client
 * \param uid
 * \param sign 1 to store flag, -1 to remove flag
 */
#define handle_store_seen(client, sign, uids) handle_store(client, sign, uids, "\\Seen")

#define handle_store_deleted(client, uids) handle_store(client, +1, uids, "\\Deleted")

#define handle_store_flagged(client, sign, uids) handle_store(client, sign, uids, "\\Flagged")

static int handle_move(struct imap_client *client, json_t *uids, const char *newmbox)
{
	int res;
	struct mailimap_set *set;

	webmail_log(1, client, "=> MOVE %s\n", newmbox);

	set = uidset(uids);
	if (!set) {
		return -1;
	}

	if (client->has_move) {
		res = mailimap_uid_move(client->imap, set, newmbox);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("UID MOVE failed: %s\n", maildriver_strerror(res));
		}
	} else {
		/* You're kidding me... right? */
		res = mailimap_uid_copy(client->imap, set, newmbox);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("UID COPY failed: %s\n", maildriver_strerror(res));
		} else {
			handle_store_deleted(client, uids);
			/* XXX Should we do an EXPUNGE automatically? It could be dangerous! */
		}
	}
	if (res == MAILIMAP_NO_ERROR) {
		uint32_t newcount;
		if (json_is_array(uids) && client->messages >= json_array_size(uids)) {
			newcount = client->messages - (uint32_t) json_array_size(uids);
		} else {
			newcount = 0; /* It was a 1:* operation */
			/* Issue a NOOP, for some reason whenever we IDLE after a folder gets completely emptied,
			 * libetpan isn't able to parse the "+ idling" confirmation if we just go right into that,
			 * seemingly due to the parser not being in the right state. This gets things back in sync. */
			res = mailimap_noop(client->imap);
			if (res != MAILIMAP_NO_ERROR) {
				bbs_warning("IMAP NOOP failed: %s\n", maildriver_strerror(res));
			}
		}
		bbs_debug(5, "Updated folder count from %u to %u\n", client->messages, newcount);
		client->messages = newcount;
	}
	mailimap_set_free(set);
	return res; /* libetpan defines MAILIMAP_NO_ERROR as 0, so we're good */
}

static int handle_copy(struct imap_client *client, json_t *uids, const char *newmbox)
{
	int res;
	struct mailimap_set *set;

	webmail_log(1, client, "=> COPY %s\n", newmbox);

	set = uidset(uids);
	if (!set) {
		return -1;
	}

	res = mailimap_uid_copy(client->imap, set, newmbox);
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("UID COPY failed: %s\n", maildriver_strerror(res));
		return -1;
	}
	mailimap_set_free(set);
	return 0;
}

static int handle_append(struct imap_client *client, const char *message, size_t size, const char *date, const char *flags)
{
	int res;
	size_t realsize;

	webmail_log(1, client, "=> APPEND {%lu} \"%s\" \"%s\"\n", size, S_IF(date), S_IF(flags));

	if (strlen_zero(message)) {
		bbs_warning("Empty APPEND message?\n");
		return -1;
	}
	realsize = strlen(message);
	if (realsize != size) { /* Some people say trust but verify. Here, we don't trust and verify. */
		bbs_warning("Purported size is %lu, but actual size is %lu?\n", size, realsize);
		size = realsize;
	}

	if (date || flags) {
		bbs_error("APPEND with size/date not currently supported\n");
		/*! \todo Support flags/date */
	}
	res = mailimap_append_simple(client->imap, client->mailbox, message, size);
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("APPEND failed: %s\n", maildriver_strerror(res));
		return -1;
	} else {
		client->messages++; /* Manually update count */
	}
	return 0;
}

#define REFRESH_LISTING(reason) handle_fetchlist(ws, client, reason, client->page, client->pagesize, client->sort, client->filter)

static int idle_stop(struct ws_session *ws, struct imap_client *client)
{
	UNUSED(ws); /* Formerly used to adjust net_ws timeout, not currently used */
	if (client->idling) {
		int res;
		bbs_debug(5, "Stopping IDLE\n");
		webmail_log(7, client, "=> IDLE STOP\n");
		res = mailimap_idle_done(client->imap);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("Failed to stop IDLE: %s\n", maildriver_strerror(res));
			return -1;
		}
		client->idling = 0;
	}
	return 0;
}

static int idle_start(struct ws_session *ws, struct imap_client *client)
{
	UNUSED(ws); /* Formerly used to adjust net_ws timeout, not currently used */
	if (client->canidle && !client->idling) { /* Don't IDLE again if already idling... */
		int res;
		bbs_debug(5, "Starting IDLE...\n");
		webmail_log(7, client, "=> IDLE START\n");
		res = mailimap_idle(client->imap);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("Failed to start IDLE: %s\n", maildriver_strerror(res));
			return -1;
		} else {
			client->idlestart = time(NULL);
			client->idling = 1;
		}
	}
	return 0;
}

static void idle_continue(struct imap_client *client)
{
	time_t left, elapsed;
	time_t now = time(NULL);

	bbs_assert(client->idling);
	bbs_assert(client->imapfd != -1);

	/* If the IMAP server sent an "* OK Still here",
	 * then we're just going to continue idling.
	 * However, there are 2 important things to keep in mind here:
	 *
	 * In total, the IDLE should end before 30 minutes from when we started idling.
	 * If we just continue without updating any state, it'd be 30 minutes
	 * without hearing anything from the server, which is NOT the same thing,
	 * and will possibly lead to a connection timeout in the case that the
	 * server keeps sending us "* OK Still here" and nothing else within that 30 minutes.
	 */

	elapsed = now - client->idlestart;
	left = 1740 - elapsed; /* Don't do math inside the SEC_MS macro. It won't work properly. */
	bbs_debug(9, "IDLE time remaining: %" TIME_T_FMT " s (%" TIME_T_FMT " s elapsed)\n", left, elapsed);
}

static int process_idle(struct imap_client *client, char *s)
{
	char *tmp;
	int seqno;

	if (strlen_zero(s)) {
		bbs_warning("Empty IDLE response\n");
		return -1;
	}

	bbs_debug(3, "IDLE data: %s", s); /* Already ends in LF */
	webmail_log(3, client, "<= %s\n", s);

	if (!STARTS_WITH(s, "* ")) {
		bbs_warning("Unexpected IDLE response (not untagged): %s\n", s);
		return -1;
	}
	tmp = s + 2;
	if (strlen_zero(tmp)) {
		bbs_warning("Partial IDLE response: %s\n", s);
		return -1;
	}

	if (STARTS_WITH(tmp, "OK Still here")) {
		idle_continue(client); /* Ignore */
	} else if (STARTS_WITH(tmp, "STATUS")) {
		char *mbname;
		client->idlerefresh |= IDLE_REFRESH_STATUS;
		tmp += STRLEN("STATUS");
		if (strlen_zero(tmp)) {
			bbs_warning("Incomplete STATUS response\n");
			return -1;
		}
		ltrim(tmp);
		mbname = quotesep(&tmp); /* Get the mailbox name where the update occured. */
		if (!mbname) {
			return -1;
		}
		/* Send the STATUS info to the frontend. */
		send_status_update(client, mbname, tmp);
	} else {
		seqno = atoi(tmp); /* It'll stop where it needs to */
		tmp = strchr(tmp, ' '); /* Skip the sequence number */
		if (!strlen_zero(tmp)) {
			tmp++;
		}
		if (strlen_zero(tmp)) {
			bbs_warning("Invalid IDLE data: %s\n", s);
			return -1;
		}

		/* What we do next depends on what the untagged response is */
		if (STARTS_WITH(tmp, "EXISTS")) {
			uint32_t previewseqno = (uint32_t) seqno;
			client->messages = previewseqno; /* Update number of messages in this mailbox */
			client->idlerefresh |= IDLE_REFRESH_EXISTS;
		} else if (STARTS_WITH(tmp, "EXPUNGE")) {
			if (client->messages) {
				client->messages--; /* Assume we lost one */
				/* Always refresh: even if it wasn't visible, this has shifted the number of messages,
				 * and perhaps the number of pages has now changed. */
				client->idlerefresh |= IDLE_REFRESH_EXPUNGE;
			} else {
				bbs_warning("EXPUNGE on empty mailbox?\n");
				return -1;
			}
		} else if (STARTS_WITH(tmp, "FETCH")) {
			/* This is most likely an update in flags.
			 * If the message in question is visible on the current page,
			 * refresh the current message listing.
			 * Otherwise, ignore it, since it's not visible anyways. */
			if (seqno >= client->start && seqno <= client->end) {
				client->idlerefresh |= IDLE_REFRESH_FETCH;
			} else {
				bbs_debug(6, "Ignoring FETCH update since not visible on current page\n");
			}
		} else {
			bbs_debug(3, "Ignoring IDLE data: %s\n", s);
		}
	}
	return 0;
}

static int on_poll_activity(struct ws_session *ws, void *data)
{
	struct imap_client *client = data;
	char *idledata;
	int res = 0;

	if (!client->authenticated) {
		bbs_warning("Poll activity prior to being authenticated?\n");
		return -1;
	}

	if (!client->idling) {
		/* If there was activity (as opposed to a timeout) and we're not idling,
		 * this likely indicates the IMAP server disconnected on us. */
		if (bbs_socket_pending_shutdown(client->imapfd)) {
			bbs_debug(3, "Remote IMAP server appears to have disconnected\n");
			return -1;
		}
		bbs_debug(5, "Not currently idling, ignoring...\n");
		idle_stop(ws, client);
		return idle_start(ws, client);
	} else if (strlen_zero(client->mailbox)) {
		bbs_error("Client mailbox not set?\n");
		idle_stop(ws, client);
		return idle_start(ws, client);
	}

	/* IDLE activity! */
	bbs_debug(5, "IDLE activity detected...\n");
	client->idlerefresh = 0;
	idledata = mailimap_read_line(client->imap);
	if (!idledata) {
		/* Check if the remote IMAP server may have disconnected us */
		if (bbs_socket_pending_shutdown(client->imapfd)) {
			bbs_debug(3, "Remote IMAP server appears to have disconnected\n");
			client->idling = 0; /* No need to send a DONE during cleanup, if the server is already gone */
			return -1;
		}
		bbs_error("IDLE activity, but no data?\n");
		idle_stop(ws, client);
		return idle_start(ws, client);
	}
	do {
		res |= process_idle(client, idledata); /* Process a single line of data received during an IDLE */
		/* mailimap_read_line will block, so we need to ensure that we break if there's no more data to read.
		 * We can't use poll, because multiple lines may be in the internal buffer already.
		 * Timeouts don't help either, since libetpan doesn't use them for this call.
		 * Checking the stream buffer length works, but if we're too quick, we might not have read it all yet,
		 * which is why we also need to poll for a little bit, in case there are other untagged messages on the way.
		 * Would be nice if there was something like mailimap_lines_available(), but there isn't...
		 */
		if ((client->imap->imap_stream && client->imap->imap_stream->read_buffer_len) || bbs_poll(client->imapfd, 100) > 0) {
			idledata = mailimap_read_line(client->imap);
		} else {
			break;
		}
	} while (idledata && !res);

	if (res) {
		if (idle_stop(ws, client)) {
			bbs_warning("Failed to stop IDLE, terminating webmail session\n");
		}
	}

	client->idlerefresh &= ~IDLE_REFRESH_STATUS; /* This doesn't count for needing a page refresh */
	if (client->idlerefresh) { /* If there were multiple lines in the IDLE update, batch any updates up and send a single refresh */
		int r = client->idlerefresh;
		const char *reason = r & IDLE_REFRESH_EXISTS ? "EXISTS" : r & IDLE_REFRESH_FETCH ? "FETCH" : r & IDLE_REFRESH_EXPUNGE ? "EXPUNGE" : "";
		/* In our case, since we're webmail, we can cheat a little and just refresh the current listing.
		 * The nice thing is this handles both EXISTS and EXPUNGE responses just fine. */
		idle_stop(ws, client);
		REFRESH_LISTING(reason);
		if (r & IDLE_REFRESH_EXISTS) {
			/* Send the metadata for message with this sequence number as an unsolicited EXISTS.
			 * It's probably this message, assuming there's only 1 more message.
			 * (In the unlikely case there's more than one, we wouldn't want to show multiple notifications anyways, just one suffices.)
			 * Do NOT automark as seen. This is not a FETCH. */
			send_preview(ws, client, client->messages);
		}
		client->idlerefresh = 0;
	}

	/* That's all, resume idling if we stopped */
	return idle_start(ws, client);
}

static int on_poll_timeout(struct ws_session *ws, void *data)
{
	struct imap_client *client = data;

	if (!client->authenticated) {
		return -1;
	}

	if (client->idling) {
		/* Just restart the IDLE before it times out */
		idle_stop(ws, client);
		idle_start(ws, client);
	} else {
		/* Prevent IMAP connection timeout by sending a NOOP to the server, since we're not idling. */
		int res = mailimap_noop(client->imap);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("IMAP NOOP failed: %s\n", maildriver_strerror(res));
		}
	}

	return 0;
}

#define SEND_STATUS_IF_NEEDED(refresh) \
	if (!res && json_is_string(json_object_get(root, "uids")) && json_string_value(json_object_get(root, "uids")) && !strcmp(json_string_value(json_object_get(root, "uids")), "1:*")) { \
		send_status(client); \
		if (refresh) { \
			REFRESH_LISTING(command); \
		} \
	}

static int send_status(struct imap_client *client)
{
	uint32_t total = 0;
	json_t *root;

	root = json_object();
	if (!root) {
		return -1;
	}

	json_object_set_new(root, "response", json_string("STATUS"));
	json_object_set_new(root, "name", json_string(client->mailbox));
	json_object_set_new(root, "recent", json_boolean(0));

	/* Frontend will handle toggling unread/read visibility,
	 * and updating folder counts,
	 * unless this is a 1:* operation, in which case it doesn't have enough information
	 * to do that on its own. */
	if (client_status_command(client, client->imap, client->mailbox, root, &total, NULL)) {
		/* If server supports RFC 8438, we'll also update the size as part of this. If not, size will remain stale
		 * (doesn't matter for SEEN/UNSEEN though) */
		json_decref(root);
		return -1;
	}

	client_set_status(client->ws, "%s", ""); /* Clear "Querying status of..." message */
	return json_send(client->ws, root);
}

static int on_text_message(struct ws_session *ws, void *data, const char *buf, size_t len)
{
	json_t *root;
	json_error_t error;
	const char *command;
	int res = -1;
	struct imap_client *client = data;

	if (strlen_zero(buf)) {
		bbs_warning("Empty message received from client?\n");
		return -1;
	}

	if (client->authenticated) {
		idle_stop(ws, client);
	}

	root = json_loads(buf, 0, &error);
	if (!root) {
		bbs_warning("Failed to parse client text payload of length %lu (line %d, %s): %s\n", len, error.line, error.text, buf);
		return -1;
	}

	command = json_object_string_value(root, "command");
	if (!command) {
		bbs_warning("Missing command\n");
		goto cleanup;
	}

	bbs_debug(4, "Processing %s command '%s'\n", client->authenticated ? "authenticated" : "unauthenticated", command);

	if (!client->authenticated) {
		if (!strcmp(command, "LOGIN")) {
			res = client_imap_login(ws, client, client->imap, json_object_string_value(root, "password"));
			if (!res) {
				json_t *root2;
				/* Send an AUTHENTICATED response immediately, since the LIST response will take a moment,
				 * and we want the UI to immediately reflect the fact that we're authenticated */
				root2 = json_object();
				if (!root2) {
					bbs_error("Failed to create JSON root\n");
					goto cleanup;
				}
				json_object_set_new(root2, "response", json_string("AUTHENTICATED"));
				json_send(ws, root2);

				/* Send unsolicited LIST response once authenticated */
				list_response(ws, client, client->imap);
			}
		} else {
			bbs_warning("Command unknown: %s\n", command);
		}
		return res;
	}

	if (!strcmp(command, "LIST")) {
		list_response(ws, client, client->imap); /* Not currently used by the frontend, but sure, allow it to ask for an updated LIST later. */
	} else if (!strcmp(command, "SELECT")) {
		if (client_imap_select(ws, client, client->imap, json_object_string_value(root, "folder"))) {
			goto cleanup;
		}
		/* Send an unsolicited list of messages (implicitly fetch the first page). */
		res = handle_fetchlist(ws, client, command, 1, json_object_int_value(root, "pagesize"), json_object_string_value(root, "sort"), json_object_string_value(root, "filter"));
	} else if (!strcmp(command, "FETCHLIST")) {
		res = handle_fetchlist(ws, client, command, json_object_int_value(root, "page"), json_object_int_value(root, "pagesize"), json_object_string_value(root, "sort"), json_object_string_value(root, "filter"));
	} else if (client->mailbox) {
		/* SELECTed state only */
		if (!strcmp(command, "FETCH")) {
			res = handle_fetch(ws, client, (uint32_t) json_object_int_value(root, "uid"), json_object_bool_value(root, "html"), json_object_bool_value(root, "raw"));
		} else if (!strcmp(command, "UNSEEN")) {
			res = handle_store_seen(client, -1, json_object_get(root, "uids"));
			SEND_STATUS_IF_NEEDED(1);
		} else if (!strcmp(command, "SEEN")) {
			res = handle_store_seen(client, +1, json_object_get(root, "uids"));
			SEND_STATUS_IF_NEEDED(1);
		} else if (!strcmp(command, "UNFLAG")) {
			res = handle_store_flagged(client, -1, json_object_get(root, "uids"));
			REFRESH_LISTING("UNFLAG");
		} else if (!strcmp(command, "FLAG")) {
			res = handle_store_flagged(client, +1, json_object_get(root, "uids"));
			REFRESH_LISTING("FLAG");
		} else if (!strcmp(command, "DELETE")) {
			res = handle_store_deleted(client, json_object_get(root, "uids"));
			/* In theory, the frontend could handle marking messages as Deleted locally,
			 * without us sending a refreshed message listing.
			 * However, it is possible that the message list has actually changed in other ways.
			 * For example, Outlook.com will actually expunge the message when something
			 * in the Trash is marked as deleted.
			 * (An untagged EXPUNGE is sent when this happens; however, we can only
			 * process untagged messages when we're idling, so we'll miss that here
			 * as we're not expecting). libetpan would need to support callbacks for
			 * all untagged responses for us to be able to receive this.
			 * For this reason, it is not only okay to refresh the listing, we must do so
			 * in order to display it properly. The frontend cannot accurately guess
			 * what the IMAP server did.
			 */
			REFRESH_LISTING("DELETE");
		} else if (!strcmp(command, "EXPUNGE")) {
			webmail_log(1, client, "=> EXPUNGE\n");
			res = mailimap_expunge(client->imap);
			if (res != MAILIMAP_NO_ERROR) {
				bbs_error("EXPUNGE failed: %s\n", strerror(errno));
			} else {
				/* XXX We don't know how many messages were expunged since we're not currently able to
				 * receive all the IDLE data.
				 * Thus, explicitly ask for the # of messages in the currently selected mailboxes.
				 * Again, this is something clients SHOULD NOT do, but we kind of have to... */
				uint32_t num_total = 0;
				res = client_status_basic(client->imap, client->mailbox, NULL, &num_total);
				client->messages = num_total;
				REFRESH_LISTING("EXPUNGE");
			}
		} else if (!strcmp(command, "MOVE")) {
			res = handle_move(client, json_object_get(root, "uids"), json_object_string_value(root, "folder"));
			if (!res) {
				/* Problem here is libetpan flushes all existing pending output when issuing a command.
				 * This includes NOOP and IDLE, so if there's an untagged * EXISTS already waiting for us, we'll never see it.
				 * We could just poll and call readline, since there SHOULD be an untagged * EXISTS,
				 * but we don't know how many, so that gets very tricky.
				 *
				 * So, just assume that the number of messages in the mailbox has decreased by how many messages
				 * were moved, and update our count and then refresh (handle_move does the calculation)
				 * This of course assumes we won't ever see the corresponding EXPUNGE responses for these messages (but since we won't, it works)
				 */
				REFRESH_LISTING("MOVE");
			}
		} else if (!strcmp(command, "COPY")) {
			res = handle_copy(client, json_object_get(root, "uids"), json_object_string_value(root, "folder"));
			REFRESH_LISTING("COPY");
		} else if (!strcmp(command, "APPEND")) {
			res = handle_append(client, json_object_string_value(root, "message"), (size_t) json_object_number_value(root, "size"), json_object_string_value(root, "date"), json_object_string_value(root, "flags"));
			REFRESH_LISTING("APPEND");
		} else {
			bbs_warning("Command unknown: %s\n", command);
		}
	} else {
		bbs_warning("Command unknown or invalid in current state: %s\n", command);
	}

	if (res) {
		/* This is more of an error, but only a temporary one */
		bbs_warning("%s operation failed\n", command);
		client_set_status(client->ws, "%s operation failed", command);
	}

	if (client->mailbox) {
		idle_start(ws, client);
	}
	res = 0;

cleanup:
	json_decref(root);
	return res;
}

static int on_open(struct ws_session *ws)
{
	struct imap_client *client;

	client = calloc(1, sizeof(*client)); /* Unfortunately, we can't stack allocate this */
	if (ALLOC_FAILURE(client)) {
		return -1;
	}

	client->imapfd = -1;
	client->ws = ws;
	websocket_attach_user_data(ws, client);
	if (client_imap_init(ws, client)) {
		goto done;
	}

	websocket_set_custom_poll_fd(ws, client->imapfd, SEC_MS(60)); /* Give the user a minute to authenticate */
	webmail_log(2, client, "New session established\n");
	return 0;

done:
	FREE(client);
	return -1;
}

static int on_close(struct ws_session *ws, void *data)
{
	struct imap_client *client = data;

	idle_stop(ws, client);
	mailimap_logout(client->imap);
	mailimap_free(client->imap); /* Must exist, or we would have rejected in on_open */
	free_if(client->mailbox);
	free_if(client->sort);
	free_if(client->filter);
	free(client);
	return 0;
}

struct ws_callbacks callbacks = {
	.on_open = on_open,
	.on_close = on_close,
	.on_text_message = on_text_message,
	.on_poll_activity = on_poll_activity,
	.on_poll_timeout = on_poll_timeout,
};

static int load_config(void)
{
	char webmail_log_file[256];
	struct bbs_config *cfg;

	cfg = bbs_config_load("mod_webmail.conf", 1);
	if (!cfg) {
		return 0;
	}

	if (!bbs_config_val_set_str(cfg, "logging", "logfile", webmail_log_file, sizeof(webmail_log_file))) {
		webmail_log_fp = fopen(webmail_log_file, "a");
		if (!webmail_log_fp) {
			bbs_error("Failed to open SMTP log file for appending: %s\n", webmail_log_file);
		}
		bbs_config_val_set_uint(cfg, "logging", "loglevel", &webmail_log_level);
	}

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	return websocket_route_register("/webmail", &callbacks);
}

static int unload_module(void)
{
	if (webmail_log_fp) {
		fclose(webmail_log_fp);
	}
	return websocket_route_unregister("/webmail");
}

/* Note that net_ws itself depends on mod_http as well */
BBS_MODULE_INFO_DEPENDENT("Webmail Server", "net_ws.so");
