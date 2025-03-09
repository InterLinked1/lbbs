/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Webmail Backend Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <wss.h> /* libwss */

#define WEBMAIL_WS_PORT 8143

static int pre(void)
{
	test_preload_module("mod_mail.so");
	test_preload_module("mod_http.so");
	test_preload_module("mod_mimeparse.so");
	test_preload_module("net_smtp.so");
	test_load_module("mod_smtp_delivery_local.so");
	test_load_module("net_imap.so");
	test_load_module("net_http.so");
	test_load_module("net_ws.so");
	test_load_module("mod_mail_events.so");
	test_load_module("mod_webmail.so");

	TEST_ADD_CONFIG("mod_mail.conf");
	TEST_ADD_CONFIG("net_smtp.conf");
	TEST_ADD_CONFIG("net_imap.conf");
	TEST_ADD_CONFIG("net_http.conf");
	TEST_ADD_CONFIG("net_ws.conf");
	TEST_ADD_CONFIG("mod_mail_events.conf");

	TEST_RESET_MKDIR(TEST_MAIL_DIR);
	TEST_MKDIR(TEST_WWW_DIR); /* Make directory if it doesn't exist already. We just need it to exist for net_http to load. */
	return 0;
}

static int send_message(int client1)
{
	char date[42], subject[32];
	static int send_count = 0;

	if (!send_count++) {
		CLIENT_EXPECT_EVENTUALLY(client1, "220 ");
		SWRITE(client1, "EHLO " TEST_EXTERNAL_DOMAIN ENDL);
		CLIENT_EXPECT_EVENTUALLY(client1, "250 "); /* "250 " since there may be multiple "250-" responses preceding it */
	} else {
		SWRITE(client1, "RSET" ENDL);
		CLIENT_EXPECT(client1, "250");
	}

	SWRITE(client1, "MAIL FROM:<" TEST_EMAIL_EXTERNAL ">\r\n");
	CLIENT_EXPECT(client1, "250");
	SWRITE(client1, "RCPT TO:<" TEST_EMAIL ">\r\n");
	CLIENT_EXPECT(client1, "250");
	SWRITE(client1, "DATA\r\n");
	CLIENT_EXPECT(client1, "354");

	/* Different dates for sorting messages */
	snprintf(date, sizeof(date), "Date: Sun, 1 Jan 2023 01:01:%02d -0700" ENDL, 59 - send_count % 59);
	write(client1, date, strlen(date));

	SWRITE(client1, "From: " TEST_EMAIL_EXTERNAL ENDL);
	snprintf(subject, sizeof(subject), "Subject: Message %d" ENDL, send_count);
	write(client1, subject, strlen(subject));

	bbs_debug(5, "Delivering message with '01:01:%02d' and subject 'Message %d'\n", 59 - send_count % 59, send_count);

	SWRITE(client1, "To: " TEST_EMAIL ENDL);
	SWRITE(client1, "Content-Type: text/plain" ENDL);
	SWRITE(client1, ENDL);
	SWRITE(client1, "This is a test email message." ENDL);
	SWRITE(client1, "." ENDL); /* EOM */
	CLIENT_EXPECT(client1, "250");
	return 0;

cleanup:
	return -1;
}

static void ws_logger(int level, int len, const char *file, const char *function, int line, const char *buf)
{
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

static int ws_expect(struct wss_client *ws, int tries, const char *str, int line)
{
	int attempts = tries;
	while (tries--) {
		struct wss_frame *frame;
		int res = wss_read(ws, SEC_MS(5), 1);
		if (res < 0) {
			bbs_error("Failed to read WebSocket frame at line %d\n", line);
			return -1;
		}
		frame = wss_client_frame(ws);
		if (!frame) {
			bbs_error("Failed to parse WebSocket frame at line %d\n", line);
			return -1;
		}
		if (wss_frame_opcode(frame) != WS_OPCODE_TEXT) {
			wss_frame_destroy(frame);
			continue;
		}
#define WS_FRAME_PREVIEW_LEN 250
		if (strstr(wss_frame_payload(frame), str)) {
			if (wss_frame_payload_length(frame) > WS_FRAME_PREVIEW_LEN) {
				bbs_debug(3, "Received expected payload for line %d: '%." XSTR(WS_FRAME_PREVIEW_LEN) "s'...\n", line, wss_frame_payload(frame));
			} else {
				bbs_debug(3, "Received expected payload for line %d: '%s'\n", line, wss_frame_payload(frame));
			}
			wss_frame_destroy(frame);
			return 0;
		}
		bbs_debug(5, "Ignoring text frame: '%s'\n", wss_frame_payload(frame));
		wss_frame_destroy(frame);
	}

	bbs_error("Failed to receive text '%s' after %d attempts at line %d\n", str, attempts, line);
	return -1;
}

static int finish_handshake(int fd)
{
	char buf[512];
	int res = 0;

	/* We have to be careful here. wss_client_new will want to start
	 * handling the connection at the precise instant the WebSocket handshake
	 * ends. However, since the session begins immediately after the upgrade
	 * response, we could easily read part of that and mess up the WebSocket
	 * parser. So dance around that by only reading minimally until the end
	 * of the upgrade. */

	/* test.c subtracts 1 from the buffer size for NUL terminator, so add 1 here for that so we can exactly fit entire lines at a time */
	res |= test_client_expect_eventually_buf(fd, SEC_MS(1), "HTTP/1.1 101 Switching Protocols\r\n", __LINE__, buf, 1 + STRLEN("HTTP/1.1 101 Switching Protocols\r\n"));
	res |= test_client_expect_eventually_buf(fd, SEC_MS(1), "Web Server\r\n", __LINE__, buf, 1 + STRLEN("Server: Lightweight BBS For Linux 0.0.0 Web Server\r\n"));
	/* The timezone could end in 'T' for local (EST/EDT/PST/PDT, etc.) or it could be UTC... so for that reason, we look at just the front for this one, rather than the end. */
	res |= test_client_expect_eventually_buf(fd, SEC_MS(1), "Date: ", __LINE__, buf, 1 + STRLEN("Date: Sun, 01 Jan 1900 12:12:12 UTC\r\n"));
	res |= test_client_expect_eventually_buf(fd, SEC_MS(1), "Upgrade: websocket\r\n", __LINE__, buf, 1 + STRLEN("Upgrade: websocket\r\n"));
	res |= test_client_expect_eventually_buf(fd, SEC_MS(1), "Connection: Upgrade\r\n", __LINE__, buf, 1 + STRLEN("Connection: Upgrade\r\n"));
	res |= test_client_expect_eventually_buf(fd, SEC_MS(1), "\r\n", __LINE__, buf, 1 + STRLEN("\r\n"));
	return res;
}

static int send_messages(void)
{
	int clientfd = -1;
	int res = 0;
	int num_messages = 25;

	clientfd = test_make_socket(25);
	REQUIRE_FD(clientfd);

	while (num_messages--) {
		res |= send_message(clientfd);
	}

	close(clientfd);
	return res;
}

static int run(void)
{
	int clientfd = -1;
	struct wss_client *ws = NULL;
	int res = -1;

	if (send_messages()) {
		goto cleanup;
	}

	clientfd = test_make_socket(WEBMAIL_WS_PORT);
	REQUIRE_FD(clientfd);

	/* Start WebSocket connection */
	SWRITE(clientfd, "GET /webmail?server=localhost&port=143&secure=0&username=" TEST_USER " HTTP/1.1" ENDL);
	SWRITE(clientfd, "Host: localhost:" XSTR(WEBMAIL_WS_PORT) ENDL);
	SWRITE(clientfd, "Connection: upgrade" ENDL);
	SWRITE(clientfd, "Origin: http://localhost" ENDL);
	SWRITE(clientfd, "Upgrade: WebSocket" ENDL);
	/* For simplicity, no Sec-WebSocket-Key */
	SWRITE(clientfd, "Sec-WebSocket-Version: 13" ENDL);
	SWRITE(clientfd, ENDL); /* End of headers */

	if (finish_handshake(clientfd)) {
		goto cleanup;
	}

	ws = wss_client_new(NULL, clientfd, clientfd);
	if (!ws) {
		goto cleanup;
	}
	wss_set_client_type(ws, WS_CLIENT);
	wss_set_logger(ws_logger);
	wss_set_log_level(WS_LOG_DEBUG + 3);

#define WS_WRITE(ws, payload) \
	res = wss_write(ws, WS_OPCODE_TEXT, payload, STRLEN(payload)); \
	if (res < 0) { \
		bbs_error("Failed to write WebSocket frame\n"); \
		goto cleanup; \
	}

#define WS_EXPECT(ws, tries, str) \
	res = ws_expect(ws, tries, str, __LINE__); \
	if (res) { \
		goto cleanup; \
	}

	/* Server response as soon as session starts */
	WS_EXPECT(ws, 1, "Connecting insecurely (explicitly) to ");

	/* We could use libjansson for JSON encoding/decoding,
	 * but we don't need to do anything super complicated so we can keep it simple and efficient.
	 * Note that in many of the WS_EXPECT calls, we just look at the beginning of
	 * the JSON payload, so the JSON string is not complete (and thus not valid). */

	WS_EXPECT(ws, 1, "{\"response\": \"CAPABILITY\", \"capabilities\": [\"IMAP4rev1");

	/* Login */
	WS_WRITE(ws, "{\"command\": \"LOGIN\", \"password\": \"" TEST_PASS_BASE64 "\"}");
	/* We don't need to worry about reading line by line, since the library does that for us, we can reliably look at messages frame by frame */
	WS_EXPECT(ws, 1, "{\"response\": \"status\", \"error\": false");
	WS_EXPECT(ws, 1, "{\"response\": \"CAPABILITY\", \"capabilities\": [\"IMAP4rev1");
	WS_EXPECT(ws, 1, "{\"response\": \"AUTHENTICATED\"}");

	/* SELECT */
	WS_WRITE(ws, "{\"command\": \"SELECT\", \"folder\": \"INBOX\"}");
	WS_EXPECT(ws, 50, "{\"response\": \"SELECT\""); /* Just the beginning. Also ignore the STATUS for each mailbox. */
	WS_EXPECT(ws, 1, "{\"response\": \"status\", \"error\": false");
	WS_EXPECT(ws, 1, "{\"response\": \"FETCHLIST\", \"cause\": \"SELECT\""); /* Server automatically sends us a FETCHLIST response without us asking */

	/* FETCHLIST, with sorting and filtering */
	WS_WRITE(ws, "{\"command\": \"FETCHLIST\", \"page\": 1, \"pagesize\": 15, \"sort\": \"sent-desc\", \"filter\": \"unseen\"}");
	WS_EXPECT(ws, 1, "{\"response\": \"FETCHLIST\", \"cause\": \"FETCHLIST\"");

	/* MOVE something to the Trash */
	WS_WRITE(ws, "{\"command\": \"MOVE\", \"folder\": \"Trash\", \"uids\": [4, 7]}");
	WS_EXPECT(ws, 1, "{\"response\": \"FETCHLIST\", \"cause\": \"MOVE\"");

	/* SELECT */
	WS_WRITE(ws, "{\"command\": \"SELECT\", \"folder\": \"Trash\"}");
	WS_EXPECT(ws, 1, "{\"response\": \"SELECT\""); /* Just the beginning */
	WS_EXPECT(ws, 1, "{\"response\": \"status\", \"error\": false");
	WS_EXPECT(ws, 1, "{\"response\": \"FETCHLIST\", \"cause\": \"SELECT\""); /* Server automatically sends us a FETCHLIST response without us asking */

	/* FETCHLIST, with a slightly different sort/filter */
	WS_WRITE(ws, "{\"command\": \"FETCHLIST\", \"page\": 1, \"pagesize\": 5, \"sort\": \"sent-asc\", \"filter\": \"recent\"}");
	WS_EXPECT(ws, 1, "{\"response\": \"FETCHLIST\", \"cause\": \"FETCHLIST\", \"mailbox\": \"Trash\"");

	/* FETCH a message */
	WS_WRITE(ws, "{\"command\": \"FETCH\", \"uid\": 1}");
	WS_EXPECT(ws, 1, "{\"response\": \"FETCH\", \"uid\": 1");

	wss_close(ws, WS_CLOSE_NORMAL);
	res = 0;

cleanup:
	if (ws) {
		wss_client_destroy(ws);
	}
	close_if(clientfd);
	return res;
}

TEST_MODULE_INFO_STANDARD("Webmail Backend Tests");
