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

#include "include/net_ws.h"

#include <libetpan/libetpan.h>

struct imap_client {
	struct mailimap *imap;
	int imapfd;			/* File descriptor, important for polling an idle connection */
	int idlestart;		/* Time that IDLE started, to avoid timing out */
	/* Cache */
	int page;
	int pagesize;
	/* Cached */
	char *mailbox;		/* Current mailbox name */
	uint32_t messages;	/* Cached number of messages in selected mailbox */
	uint32_t uid;		/* Current message UID */
	/* Flags */
	unsigned int canidle:1;
	unsigned int idling:1;
	unsigned int has_move:1;
	unsigned int has_sort:1;
	unsigned int has_thread:1;
	unsigned int has_status_size:1;
	unsigned int has_list_status:1;
	/* Sorting */
	char *sort;
};

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

static int client_status_command(struct imap_client *client, struct mailimap *imap, const char *mbox, json_t *folder, uint32_t *messages, char *listresp)
{
	int res = 0;
	struct mailimap_status_att_list *att_list;
	struct mailimap_mailbox_data_status *status;
	clistiter *cur;

	if (listresp) {
		char *tmp;
		char findbuf[64];
		int skiplen;
		/* See if we can get what we want from the log message. */
		skiplen = snprintf(findbuf, sizeof(findbuf), "* STATUS \"%s\" (", mbox);
		tmp = strstr(listresp, findbuf);
		if (!tmp && !strchr(mbox, ' ')) { /* If not found, try the unquoted version */
			skiplen = snprintf(findbuf, sizeof(findbuf), "* STATUS %s (", mbox);
			tmp = strstr(listresp, findbuf);
		}
		if (!tmp) {
			bbs_warning("No STATUS response for mailbox '%s'\n", mbox);
			/* Manually ask for it now, as usual */
		} else {
			/* Parse what we want from the STATUS response.
			 * Normally not a great idea, but STATUS responses are easy to parse. */
			char *str;
			uint32_t num;
			tmp += skiplen;
			if (strlen_zero(tmp)) {
				bbs_warning("Malformed STATUS response\n");
			} else {
				str = strstr(tmp, "MESSAGES ");
				if (str) {
					str += STRLEN("MESSAGES ");
					if (!strlen_zero(str)) {
						num = (uint32_t) atol(str);
						*messages = num;
						json_object_set_new(folder, "messages", json_integer(num));
					}
				}
				if (!str) {
					bbs_warning("Failed to parse MESSAGES\n");
				}
				str = strstr(tmp, "RECENT ");
				if (str) {
					str += STRLEN("RECENT ");
					if (!strlen_zero(str)) {
						num = (uint32_t) atol(str);
						json_object_set_new(folder, "recent", json_integer(num));
					}
				}
				if (!str) {
					bbs_warning("Failed to parse RECENT\n");
				}
				str = strstr(tmp, "UNSEEN ");
				if (str) {
					str += STRLEN("UNSEEN ");
					if (!strlen_zero(str)) {
						num = (uint32_t) atol(str);
						json_object_set_new(folder, "unseen", json_integer(num));
					}
				}
				if (!str) {
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
					}
					if (!str) {
						bbs_warning("Failed to parse SIZE\n");
					}
				}
			}
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

static int json_send(struct ws_session *ws, json_t *root)
{
	char *s = json_dumps(root, 0);
	if (s) {
		size_t len = strlen(s);
		websocket_sendtext(ws, s, len);
		free(s);
	} else {
		bbs_warning("Failed to dump JSON string: was it allocated?\n");
	}
	json_decref(root);
	return s ? 0 : -1;
}

#define CLIENT_REQUIRE_VAR(name) \
	if (!name) { \
		bbs_warning("Missing required session variable '%s'\n", #name); \
		return -1; \
	}

static int client_imap_init(struct ws_session *ws, struct imap_client *client, struct mailimap **data)
{
	struct mailimap *imap;
	int res;
	time_t timeout;
	struct mailimap_capability_data *capdata;

	/* Keep in mind the session is the only way to send data from the frontend to the backend.
	 * Even if it's direct, we can't POST data since WebSocket upgrades must be GET requests.
	 * So the data would already have to be somewhere. */
	const char *hostname = websocket_session_data_string(ws, "server");
	uint16_t port = (uint16_t) websocket_session_data_number(ws, "port");
	int secure = websocket_session_data_number(ws, "secure");
	const char *username = websocket_session_data_string(ws, "username");
	const char *password = websocket_session_data_string(ws, "password");

	CLIENT_REQUIRE_VAR(hostname);
	CLIENT_REQUIRE_VAR(port);
	CLIENT_REQUIRE_VAR(username);
	CLIENT_REQUIRE_VAR(password);
#undef CLIENT_REQUIRE_VAR

	imap = mailimap_new(0, NULL);
	if (!imap) {
		bbs_error("Failed to create IMAP session\n");
		return -1;
	}

	mailimap_set_logger(imap, libetpan_log, client);
	timeout = mailimap_get_timeout(imap);
	/* Timeout needs to be sufficiently large... e.g. FETCH 1:* (SIZE) can take quite a few seconds on large mailboxes. */
	mailimap_set_timeout(imap, 25); /* If the IMAP server hasn't responded by now, I doubt it ever will */
	if (secure) {
		res = mailimap_ssl_connect(imap, hostname, port);
	} else {
		res = mailimap_socket_connect(imap, hostname, port);
	}
	if (MAILIMAP_ERROR(res)) {
		bbs_warning("Failed to establish IMAP session to %s:%d\n", hostname, port);
		goto cleanup;
	}
	mailimap_set_timeout(imap, timeout); /* Reset once logged in */
	res = mailimap_login(imap, username, password);
	if (MAILIMAP_ERROR(res)) {
		bbs_warning("Failed to login to IMAP server as %s\n", username);
		goto cleanup;
	}
	res = mailimap_capability(imap, &capdata);
	if (!MAILIMAP_ERROR(res)) {
		/* We don't ourselves directly care about the capabilities (at least right now)
		 * This will just make libetpan aware of them, so functions like mailimap_has_extension
		 * and mailimap_has_quota return correct and meaningful values.
		 * Otherwise, if the server doesn't send unsolicited CAPABILITY responses (and most don't),
		 * these will all be defaulted to false. */
		mailimap_capability_data_free(capdata); /* This is wasteful of libetpan to duplicate the caps for us to immediately free them... but this is the API */
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
	*data = imap;
	return 0;

cleanup:
	mailimap_free(imap);
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

	struct dyn_str *dynstr = context;

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

	if (details && client->has_list_status && client->has_status_size) {
		struct dyn_str dynstr;
		memset(&dynstr, 0, sizeof(dynstr));
		/* Fundamentally, libetpan does not support LIST-STATUS.
		 * It did not support STATUS=SIZE either, but it was easy to patch it support that
		 * (and mod_webmail requires such a patched version of libetpan).
		 * Rather than trying to kludge libetpan to support LIST-STATUS,
		 * it's easier to just send it the command we want and parse it ourselves.
		 *
		 * XXX Since I don't know how to read/write directly using libetpan's connection,
		 * we open up a 2nd IMAP connection here for the LIST-STATUS operation.
		 * The time savings from doing a single LIST-STATUS command over N STATUS commands
		 * is worth the overhead in setting up a separate connection. */
		bbs_debug(4, "Nice, both LIST-STATUS and STATUS=SIZE are supported!\n"); /* Somebody please give the poor IMAP server a pay raise */
		mailstream_set_logger(imap->imap_stream, list_status_logger, &dynstr);
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
						break;
				}
			}
		}
		json_array_append_new(json, folder);
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
					/* Must SELECT mailbox */
					res = mailimap_select(imap, name);
					if (res != MAILIMAP_NO_ERROR) {
						bbs_warning("Failed to SELECT mailbox '%s'\n", name);
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

	free_if(listresp);
	mailimap_list_result_free(imap_list);

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
	json_t *root = json_object();
	json_t *arr;

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
	 * This allows the UI to be more responsive for the user.
	 */
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
	int res = mailimap_select(imap, name);
	if (res != MAILIMAP_NO_ERROR) {
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
	bbs_debug(5, "Parsed datetime -> epoch %lu (had offset %ld)\n", epoch, offset);
#endif
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

static char *mime_header_decode(const char *s)
{
	size_t cur_token;
	int encoded = 0;
	char *decoded = NULL;

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
#define DEST_CHARSET "iso-8859-1"
	mailmime_encoded_phrase_parse(DEST_CHARSET, s, strlen(s), &cur_token, DEST_CHARSET, &decoded);
	if (!decoded) {
		bbs_warning("Failed to decode MIME header\n");
	}
	return decoded;
}

static void append_header_single(json_t *restrict json, int *importance, int fetchlist, json_t *to, json_t *cc, const char *hdrname, const char *hdrval)
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
				json_array_append_new(to, json_string(hdrval));
			} else if (!strcasecmp(hdrname, "Cc")) {
				json_array_append_new(cc, json_string(hdrval));
			} else if (!strcasecmp(hdrname, "Subject")) {
				json_object_set_new(json, "subject", json_string(hdrval));
			} else if (!strcasecmp(hdrname, "Date")) {
				struct tm sent;
				/* from parse_sent_date in net_imap: */
				if (!strptime(hdrval, "%a, %d %b %Y %H:%M:%S %z", &sent) && !strptime(hdrval, "%d %b %Y %H:%M:%S %z", &sent)) {
					bbs_warning("Failed to parse as date: %s\n", hdrval);
				}
				__append_datetime(json, "sent", &sent);
			} /* else, there shouldn't be anything unaccounted for, since we only fetched specific headers of interest */
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
			hdrname = prevheadername;
			dyn_str_append(&dynstr, prevval, strlen(prevval));
			prevval = header;
		} else {
			/* If we had a previous multiline header, flush it */
			if (dynstr.buf) {
				dyn_str_append(&dynstr, prevval, strlen(prevval));
				append_header_single(json, &importance, fetchlist, to, cc, prevheadername, dynstr.buf);
				free(dynstr.buf);
				memset(&dynstr, 0, sizeof(dynstr));
			}
			/* New header */
			hdrname = strsep(&hdrval, ":");
			prevheadername = hdrname;
			prevval = hdrval;
		}

		if (!strlen_zero(hdrval)) {
			ltrim(hdrval);
			bbs_strterm(hdrval, '\r');
			append_header_single(json, &importance, fetchlist, to, cc, hdrname, hdrval);
		}
		hdrname = hdrval = NULL;
	}

	/* If we had a previous multiline header, flush it */
	if (dynstr.buf) {
		dyn_str_append(&dynstr, prevval, strlen(prevval));
		append_header_single(json, &importance, fetchlist, to, cc, prevheadername, dynstr.buf);
		free(dynstr.buf);
	}

	if (importance) {
		json_object_set_new(json, "priority", json_integer(importance));
	}
}

static clist *sortall(struct imap_client *client, const char *sort)
{
	int res = -1;
	clist *list = NULL;
	struct mailimap_sort_key *key = NULL;
	struct mailimap_search_key *searchkey = NULL;

	/* These seem backwards because, in a way, they are.
	 * The pagination logic is written to expect the "first" result on the last page and show the "last"
	 * result at the beginning, so that on an unsorted mailbox, the latest results show up on the first page.
	 * Therefore, we flip all the orderings here, e.g. to sort in descending order, we really ask the server
	 * to do an ascending sort, so that when the last results are used for the first page, the largest items
	 * show up there, making it feel like a descending sort. */
	if (!strcmp(sort, "sent-desc")) {
		key = mailimap_sort_key_new_date(0);
	} else if (!strcmp(sort, "sent-asc")) {
		key = mailimap_sort_key_new_date(1);
	} else if (!strcmp(sort, "received-desc")) {
		key = mailimap_sort_key_new_arrival(0);
	} else if (!strcmp(sort, "received-asc")) {
		key = mailimap_sort_key_new_arrival(1);
	} else if (!strcmp(sort, "size-desc")) {
		key = mailimap_sort_key_new_size(0);
	} else if (!strcmp(sort, "size-asc")) {
		key = mailimap_sort_key_new_size(1);
	} else if (!strcmp(sort, "subject-asc")) {
		key = mailimap_sort_key_new_subject(1);
	} else if (!strcmp(sort, "subject-desc")) {
		key = mailimap_sort_key_new_subject(0);
	} else if (!strcmp(sort, "from-asc")) {
		key = mailimap_sort_key_new_from(1);
	} else if (!strcmp(sort, "from-desc")) {
		key = mailimap_sort_key_new_from(0);
	} else if (!strcmp(sort, "to-asc")) {
		key = mailimap_sort_key_new_to(1);
	} else if (!strcmp(sort, "to-desc")) {
		key = mailimap_sort_key_new_to(0);
	} else {
		bbs_warning("Unsupported sort criteria: '%s'\n", sort);
	}
	if (!key) {
		return NULL;
	}

	searchkey = mailimap_search_key_new_all();
	if (!searchkey) {
		mailimap_sort_key_free(key);
		return NULL;
	}

	res = mailimap_sort(client->imap, "UTF-8", key, searchkey, &list);
	mailimap_search_key_free(searchkey);
	mailimap_sort_key_free(key);
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("SORT failed: %s\n", maildriver_strerror(res));
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
				bbs_debug(6, "1-part text\n");
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

static void fetchlist(struct ws_session *ws, struct imap_client *client, const char *reason, int start, int end, int page, int numpages, const char *sort)
{
	int expected, res, c = 0;
	struct mailimap_set *set = NULL;
	struct mailimap_fetch_type *fetch_type = NULL;
	struct mailimap_fetch_att *fetch_att = NULL;
	clist *fetch_result;
	clistiter *cur;
	clist *hdrlist;
	char *headername = NULL;
	struct mailimap_header_list *imap_hdrlist;
	struct mailimap_section *section;
	json_t *root = NULL, *arr;

	/* start to end is inclusive */
	expected = end - start + 1;
	bbs_debug(3, "Fetching message listing %d:%d (page %d of %d)\n", start, end, page, numpages);

	/* Fetch: UID, flags, size, from, to, subject, internaldate,
	 * +with attributes: priority headers, contains attachments */
	if (sort && client->has_sort) {
		int index = 1;
		/*! \todo Cache this between FETCHLIST calls */
		clist *sorted = sortall(client, sort); /* This could be somewhat slow, since we have sort the ENTIRE mailbox every time */
		if (!sorted) {
			return;
		}
		set = mailimap_set_new_empty();
		if (!set) {
			mailimap_sort_result_free(sorted);
			return;
		}
		for (cur = clist_begin(sorted); cur; index++, cur = clist_next(cur)) {
			uint32_t *seqno;
			if (index < start) {
				continue;
			}
			seqno = clist_content(cur);
			res = mailimap_set_add_single(set, *seqno);
			if (res != MAILIMAP_NO_ERROR) {
				bbs_error("Failed to add sorted seqno to list: %u\n", *seqno);
				mailimap_sort_result_free(sorted);
				return;
			}
			if (index >= end) {
				break;
			}
		}
		mailimap_sort_result_free(sorted);
	} else {
		set = mailimap_set_new_interval((uint32_t) start, (uint32_t) end);
	}

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
		return;
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
	mailimap_set_free(set);
	/* Don't go to cleanup past this point, so no need to set fetch_type/set to NULL */
	if (MAILIMAP_ERROR(res)) {
		bbs_warning("FETCH failed: %s\n", maildriver_strerror(res));
		/* fetch_result and everything that went into it is already freed */
		return;
	}

	root = json_object();
	if (!root) {
		mailimap_fetch_list_free(fetch_result);
		return;
	}

	json_object_set_new(root, "response", json_string("FETCHLIST"));
	json_object_set_new(root, "cause", json_string(reason));
	json_object_set_new(root, "mailbox", json_string(client->mailbox));
	json_object_set_new(root, "page", json_integer(page));
	json_object_set_new(root, "numpages", json_integer(numpages));

	arr = json_array();
	json_object_set_new(root, "data", arr);

	for (cur = clist_begin(fetch_result); cur; cur = clist_next(cur)) {
		json_t *msgitem;
		clistiter *cur2;
		struct mailimap_msg_att *msg_att = clist_content(cur);

		msgitem = json_object();
		if (!msgitem) {
			continue;
		}
		json_array_append_new(arr, msgitem);
		json_object_set_new(msgitem, "seqno", json_integer(msg_att->att_number));

		for (cur2 = clist_begin(msg_att->att_list); cur2; cur2 = clist_next(cur2)) {
			struct mailimap_msg_att_item *item = clist_content(cur2);
			if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC) {
				struct mailimap_msg_att_body_section *msg_att_body_section;
				struct mailimap_body *imap_body;
				char headersbuf[2048];
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
#ifdef EXTRA_DEBUG
						bbs_debug(5, "Matching headers: %s\n", msg_att_body_section->sec_body_part);
#endif
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
								bbs_debug(5, "Recent\n");
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
		c++;
	}

	/* The messages are in ascending order here.
	 * They are displayed newest first in the the webmail client,
	 * but we let frontend JavaScript reverse this JSON array,
	 * since jansson doesn't have a function to reverse arrays? */

	if (c != expected) {
		bbs_warning("Expected to fetch %d (%d:%d) messages but only fetched %d?\n", expected, start, end, c);
	}

	/* XXX Should this be done only for SELECT, not each FETCHLIST? */
	append_quota(root, client);

	mailimap_fetch_list_free(fetch_result);
	json_send(ws, root);
	return;

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
	return;

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
}

static void handle_fetchlist(struct ws_session *ws, struct imap_client *client, const char *reason, int page, int pagesize, const char *sort)
{
	uint32_t total;
	int numpages, start, end;
	const char *oldsort = client->sort;

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

	/* A mailbox MUST be currently selected here */
	total = client->messages;
	if (!total) {
		bbs_debug(5, "Mailbox is empty, no listing to provide\n");
		return;
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
		return;
	} else if (end > (int) total) {
		end = (int) total; /* End can't be beyond the max # of messages */
	}
	return fetchlist(ws, client, reason, start, end, page, numpages, client->sort);
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
			if (mime->mm_data.mm_message.mm_fields) {
				/* Use the MIME decoded headers to both handle decoding and so we don't have to parse headers ourselves */
				if (clist_begin(mime->mm_data.mm_message.mm_fields->fld_list)) {
					struct mailimf_fields *mffields = mime->mm_data.mm_message.mm_fields;
					json_t *to, *cc, *replyto;
					to = json_array();
					cc = json_array();
					replyto = json_array();
					json_object_set_new(root, "to", to);
					json_object_set_new(root, "cc", cc);
					json_object_set_new(root, "replyto", replyto);
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
									json_object_set_new(root, "from", json_string(frombuf));
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
								name = decoded ? decoded : subject->sbj_value;
								bbs_debug(5, "Subject: %s\n", name);
								json_object_set_new(root, "subject", json_string(name));
								free_if(decoded);
								break;
							case MAILIMF_FIELD_MESSAGE_ID:
								bbs_debug(5, "Message-ID: %s\n", f->fld_data.fld_message_id->mid_value);
								json_object_set_new(root, "messageid", json_string(f->fld_data.fld_message_id->mid_value));
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
			json_object_set_new(root, "body", json_stringn(result, resultlen));
			mailmime_decoded_part_free(result);
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
			//struct mailimap_msg_att_body_section *msg_att_body_section;
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
	bbs_debug(3, "preview failed\n");
	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	if (fetch_result) {
		mailimap_fetch_list_free(fetch_result);
	}
	json_decref(root);
}

static void handle_fetch(struct ws_session *ws, struct imap_client *client, uint32_t uid, int html, int raw)
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

	if (!uid) {
		bbs_warning("Invalid UID: %u\n", uid);
		return;
	}

	root = json_object();
	if (!root) {
		return;
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
			//struct mailimap_msg_att_body_section *msg_att_body_section;
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
	return;

cleanup:
	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	if (fetch_result) {
		mailimap_fetch_list_free(fetch_result);
	}
	json_decref(root);
}

static struct mailimap_set *uidset(json_t *uids)
{
	size_t i;
	struct mailimap_set *set = mailimap_set_new_empty();
	if (!set) {
		return NULL;
	}
	for (i = 0; i < json_array_size(uids); i++) {
		int res;
		json_int_t uid;
		json_t *j = json_array_get(uids, i);
		uid = json_integer_value(j);
		if (uid < 1) {
			bbs_warning("Invalid UID: %lld\n", uid);
			continue;
		}
		res = mailimap_set_add_single(set, (uint32_t) uid);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("Failed to add UID %lld to list\n", uid);
		}
	}
	return set;
}

static void __handle_store(struct imap_client *client, int sign, struct mailimap_set *set, struct mailimap_flag_list *flag_list)
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
	return;

cleanup:
	mailimap_flag_list_free(flag_list);
	mailimap_set_free(set);
}

/*!
 * \brief Add or remove an arbitrary flag from a message.
 * \param client
 * \param uid
 * \param sign 1 to store flag, -1 to remove flag
 */
static void handle_store(struct imap_client *client, int sign, json_t *uids, const char *flagname)
{
	int res;
	struct mailimap_flag_list *flag_list;
	struct mailimap_flag *flag;
	struct mailimap_set *set;
	char *keyword = NULL;

	if (!uids || !json_array_size(uids)) {
		bbs_warning("No UIDs provided\n");
		return;
	}

	set = uidset(uids);
	if (!set) {
		return;
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
		return;
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

static void handle_move(struct imap_client *client, json_t *uids, const char *newmbox)
{
	int res;
	struct mailimap_set *set;

	if (!uids || !json_array_size(uids)) {
		bbs_warning("No UIDs provided\n");
		return;
	}

	set = uidset(uids);
	if (!set) {
		return;
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
	if (res == MAILIMAP_NO_ERROR && client->messages >= json_array_size(uids)) {
		uint32_t newcount = client->messages - (uint32_t) json_array_size(uids);
		bbs_debug(5, "Updated folder count from %u to %u\n", client->messages, newcount);
		client->messages = newcount;
	}
	mailimap_set_free(set);
}

static void handle_copy(struct imap_client *client, json_t *uids, const char *newmbox)
{
	int res;
	struct mailimap_set *set;

	if (!uids || !json_array_size(uids)) {
		bbs_warning("No UIDs provided\n");
		return;
	}

	set = uidset(uids);
	if (!set) {
		return;
	}

	res = mailimap_uid_copy(client->imap, set, newmbox);
	if (res != MAILIMAP_NO_ERROR) {
		bbs_warning("UID COPY failed: %s\n", maildriver_strerror(res));
	}
	mailimap_set_free(set);
}

static void handle_append(struct imap_client *client, const char *message, size_t size, const char *date, const char *flags)
{
	int res;
	size_t realsize;

	if (strlen_zero(message)) {
		bbs_warning("Empty APPEND message?\n");
		return;
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
	} else {
		client->messages++; /* Manually update count */
	}
}

#define REFRESH_LISTING(reason) handle_fetchlist(ws, client, reason, client->page, client->pagesize, client->sort)

static void idle_stop(struct ws_session *ws, struct imap_client *client)
{
	if (client->idling) {
		int res;
		bbs_debug(5, "Stopping IDLE\n");
		res = mailimap_idle_done(client->imap);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("Failed to stop IDLE: %s\n", maildriver_strerror(res));
			client->idling = 0;
			/* net_ws will convert -1 to the maximum allowed poll time */
			websocket_set_custom_poll_fd(ws, -1, -1);
		}
	}
}

static void idle_start(struct ws_session *ws, struct imap_client *client)
{
	if (client->canidle) {
		int res;
		bbs_debug(5, "Starting IDLE...\n");
		res = mailimap_idle(client->imap);
		if (res != MAILIMAP_NO_ERROR) {
			bbs_warning("Failed to start IDLE: %s\n", maildriver_strerror(res));
		} else {
			client->idlestart = (int) time(NULL);
			client->imapfd = mailimap_idle_get_fd(client->imap);
			client->idling = 1;
			websocket_set_custom_poll_fd(ws, client->imapfd, SEC_MS(1740)); /* Just under 30 minutes */
		}
	}
}

static void idle_continue(struct imap_client *client)
{
	int left, elapsed, now = (int) time(NULL);

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
	bbs_debug(9, "IDLE time remaining: %d s (%d s elapsed)\n", left, elapsed);
}

static int on_poll_activity(struct ws_session *ws, void *data)
{
	const char *reason = NULL;
	struct imap_client *client = data;
	uint32_t previewseqno = 0;
	char *idledata;
	int ends_in_crlf;

	if (!client->idling) {
		bbs_debug(7, "IDLE not active, ignoring...\n");
		return 0;
	} else if (strlen_zero(client->mailbox)) {
		bbs_error("Client mailbox not set?\n");
		return 0;
	}

	/* IDLE activity! */
	idledata = mailimap_read_line(client->imap);
	ends_in_crlf = !strlen_zero(idledata) ? strchr(idledata, '\n') ? 1 : 0 : 0;
	bbs_debug(3, "IDLE activity detected: %s%s", idledata, ends_in_crlf ? "" : "\n");
	if (STARTS_WITH(idledata, "* ")) {
		char *tmp = idledata + 2;
		if (!strlen_zero(tmp)) {
			int seqno;
			if (STARTS_WITH(tmp, "OK Still here")) {
				idle_continue(client);
				return 0; /* Ignore */
			}
			seqno = atoi(tmp); /* It'll stop where it needs to */
			tmp = strchr(tmp, ' '); /* Skip the sequence number */
			if (!strlen_zero(tmp)) {
				tmp++;
			}
			if (!strlen_zero(tmp)) {
				if (STARTS_WITH(tmp, "EXISTS")) {
					reason = "EXISTS";
					previewseqno = (uint32_t) seqno;
					client->messages = previewseqno; /* Update number of messages in this mailbox */
				} else if (STARTS_WITH(tmp, "EXPUNGE")) {
					reason = "EXPUNGE";
					if (client->messages) {
						client->messages--; /* Assume we lost one */
					} else {
						bbs_warning("EXPUNGE on empty mailbox?\n");
					}
				} else if (STARTS_WITH(tmp, "FETCH")) {
					/* XXX Not currently used */
				}
			}
		}
	}
	if (!reason) {
		bbs_warning("Unhandled IDLE response: %s%s", idledata, ends_in_crlf ? "" : "\n");
		idle_continue(client);
		return 0; /* No need to start the IDLE again, we never stopped it */
	}
	idle_stop(ws, client);

	/* In our case, since we're webmail, we can cheat a little and just refresh the current listing.
	 * The nice thing is this handles both EXISTS and EXPUNGE responses just fine. */

	/* Send the update and restart the IDLE */
	REFRESH_LISTING(reason);

	if (previewseqno) {
		/* Send the metadata for message with this sequence number as an unsolicited EXISTS.
		 * It's probably this message, assuming there's only 1 more message.
		 * (In the unlikely case there's more than one, we wouldn't want to show multiple notifications anyways, just one suffices.)
		 * Do NOT automark as seen. This is not a FETCH. */
		send_preview(ws, client, previewseqno);
	}

	idle_start(ws, client);
	return 0;
}

static int on_poll_timeout(struct ws_session *ws, void *data)
{
	struct imap_client *client = data;

	if (client->idling) {
		/* Just restart the IDLE before it times out */
		idle_stop(ws, client);
		idle_start(ws, client);
	}

	return 0;
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

	idle_stop(ws, client);

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

	bbs_debug(4, "Processing command '%s'\n", command);

	if (!strcmp(command, "SELECT")) {
		if (client_imap_select(ws, client, client->imap, json_object_string_value(root, "folder"))) {
			goto cleanup;
		}
		/* Send an unsolicited list of messages (implicitly fetch the first page). */
		handle_fetchlist(ws, client, command, 1, json_object_int_value(root, "pagesize"), json_object_string_value(root, "sort"));
	} else if (!strcmp(command, "FETCHLIST")) {
		handle_fetchlist(ws, client, command, json_object_int_value(root, "page"), json_object_int_value(root, "pagesize"), json_object_string_value(root, "sort"));
	} else if (client->mailbox) {
		/* SELECTed state only */
		if (!strcmp(command, "FETCH")) {
			handle_fetch(ws, client, (uint32_t) json_object_int_value(root, "uid"), json_object_bool_value(root, "html"), json_object_bool_value(root, "raw"));
		} else if (!strcmp(command, "UNSEEN")) {
			handle_store_seen(client, -1, json_object_get(root, "uids"));
			/* Frontend will handle toggling unread/read visibility and updating folder counts */
		} else if (!strcmp(command, "SEEN")) {
			handle_store_seen(client, +1, json_object_get(root, "uids"));
			/* Frontend will handle toggling unread/read visibility and updating folder counts */
		} else if (!strcmp(command, "DELETE")) {
			handle_store_deleted(client, json_object_get(root, "uids"));
			REFRESH_LISTING("DELETE"); /* XXX Frontend can easily handle marking it as Deleted on its end, and should */
		} else if (!strcmp(command, "EXPUNGE")) {
			/* XXX We need to get an updated total message count now, as ours is out of date,
			 * and we don't easily know how many messages were expunged (same problem discussed in "MOVE" below) */
			res = mailimap_expunge(client->imap);
			if (res != MAILIMAP_NO_ERROR) {
				bbs_error("EXPUNGE failed: %s\n", strerror(errno));
			} else {
				REFRESH_LISTING("EXPUNGE");
			}
		} else if (!strcmp(command, "MOVE")) {
			handle_move(client, json_object_get(root, "uids"), json_object_string_value(root, "folder"));
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
		} else if (!strcmp(command, "COPY")) {
			handle_copy(client, json_object_get(root, "uids"), json_object_string_value(root, "folder"));
			REFRESH_LISTING("COPY");
		} else if (!strcmp(command, "APPEND")) {
			handle_append(client, json_object_string_value(root, "message"), (size_t) json_object_number_value(root, "size"), json_object_string_value(root, "date"), json_object_string_value(root, "flags"));
			REFRESH_LISTING("APPEND");
		} else {
			bbs_warning("Command unknown: %s\n", command);
		}
	} else {
		bbs_warning("Command unknown or invalid in current state: %s\n", command);
	}

	/*! \todo XXX Improvement: Only start idling if we've been inactive for at least a few seconds...
	 * We could do that by setting a short poll timeout, not IDLING, if it expires without
	 * anything happening, start idling then. */
	idle_start(ws, client);
	res = 0;

cleanup:
	json_decref(root);
	return res;
}

static int on_open(struct ws_session *ws)
{
	struct imap_client *client;
	struct mailimap *imap = NULL;

	client = calloc(1, sizeof(*client)); /* Unfortunately, we can't stack allocate this */
	if (ALLOC_FAILURE(client)) {
		return -1;
	}

	websocket_attach_user_data(ws, client);
	if (client_imap_init(ws, client, &imap)) {
		goto done;
	}
	list_response(ws, client, imap);
	client->imap = imap;
	/* Don't start IDLING yet. No mailbox is yet selected. */
	return 0;

done:
	if (imap) {
		mailimap_free(imap);
	}
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

static int load_module(void)
{
	return websocket_route_register("/webmail", &callbacks);
}

static int unload_module(void)
{
	return websocket_route_unregister("/webmail");
}

/* Note that net_ws itself depends on mod_http as well */
BBS_MODULE_INFO_DEPENDENT("Webmail Server", "net_ws.so");
