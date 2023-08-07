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
 * \brief HTTP Unit Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/test.h"
#include "include/utils.h"
#include "include/curl.h"

#include "include/node.h" /* use bbs_write */

/* Needed for mod_http.h */
#include "include/linkedlists.h"
#include "include/variables.h"

#include "include/mod_http.h"

/* Use a port for testing that is unlikely to be used by anything else.
 * So definitely not 8000, 8080, or anything like that. */
#define DEFAULT_TEST_HTTP_PORT 58280

struct http_route_uri {
	const char *host;
	unsigned short int port;
	const char *prefix;
	enum http_method methods;
	enum http_response_code (*handler)(struct http_session *http);
};

static int register_uris(struct http_route_uri *uris, size_t len)
{
	size_t i;
	int res = 0;

	for (i = 0; i < len; i++) {
		int mres = http_register_insecure_route(uris[i].host, uris[i].port, uris[i].prefix, uris[i].methods, uris[i].handler);
		if (mres) {
			bbs_warning("Failed to register route %s\n", uris[i].prefix);
		}
		res |= mres;
	}
	usleep(1000); /* Wait for TCP multilistener thread to be listening on the new socket(s), to avoid connection reset if we connect before listener is ready to accept */
	return res;
}

static void unregister_uris(struct http_route_uri *uris, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		http_unregister_route(uris[i].handler);
	}
}

static enum http_response_code get_basic(struct http_session *http)
{
	http_writef(http, "<h1>Hello world</h1>");
	return HTTP_OK;
}

static enum http_response_code get_code_404(struct http_session *http)
{
	UNUSED(http);
	return HTTP_NOT_FOUND;
}

static enum http_response_code get_code_404_content(struct http_session *http)
{
	http->res->code = HTTP_NOT_FOUND;
	http_writef(http, "<p>Unfortunately, we could not find that page.</p>");
	return http->res->code;
}

static int test_http_get_basic(void)
{
	int mres, res = -1;
	char url[84];
	struct bbs_curl c = {
		.url = url,
		.forcefail = 0,
	};

	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/test", HTTP_METHOD_GET, get_basic },
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/notfound", HTTP_METHOD_GET, get_code_404 },
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/notfound2", HTTP_METHOD_GET, get_code_404_content },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	snprintf(url, sizeof(url), "http://127.0.0.1:%u/test", DEFAULT_TEST_HTTP_PORT);
	bbs_test_assert_equals(0, bbs_curl_get(&c));
	bbs_test_assert_equals(200, c.http_code);
	bbs_test_assert_str_exists_equals(c.response, "<h1>Hello world</h1>");

	bbs_curl_free(&c);

	/* Unsupported method */
	bbs_test_assert_equals(0, bbs_curl_post(&c));
	bbs_test_assert_equals(405, c.http_code);
	bbs_test_assert_str_exists_contains(c.response, "Method not allowed");

	bbs_curl_free(&c);

	snprintf(url, sizeof(url), "http://127.0.0.1:%u/notfound", DEFAULT_TEST_HTTP_PORT);
	bbs_test_assert_equals(0, bbs_curl_get(&c));
	bbs_test_assert_equals(404, c.http_code);
	bbs_test_assert_str_exists_contains(c.response, "not found"); /* Default 404 body */

	bbs_curl_free(&c);

	snprintf(url, sizeof(url), "http://127.0.0.1:%u/notfound2", DEFAULT_TEST_HTTP_PORT);
	bbs_test_assert_equals(0, bbs_curl_get(&c));
	bbs_test_assert_equals(404, c.http_code);
	bbs_test_assert_str_exists_contains(c.response, "<p>Unfortunately, we could not find that page.</p>"); /* Default 404 body */

	res = 0;

cleanup:
	bbs_curl_free(&c);
	unregister_uris(tests, ARRAY_LEN(tests));
	return res;
}

static enum http_response_code post_basic(struct http_session *http)
{
	if (http->req->method & HTTP_METHOD_GET) {
		http_writef(http, "<h1>Hello world</h1>");
	} else {
		http_writef(http, "<h1>Hello there</h1>");
	}
	return HTTP_OK;
}

static enum http_response_code post_upload(struct http_session *http)
{
	struct post_field *id = http_post_param(http, "id");
	struct post_field *secret = http_post_param(http, "secret");
	struct post_field *option = http_post_param(http, "option");

	bbs_test_assert_exists(id);
	bbs_test_assert_exists(secret);
	bbs_test_assert_exists(option);

	bbs_test_assert_mem_equals(id->buffer, "123", 3);
	bbs_test_assert_mem_equals(secret->buffer, "456", 3);
	bbs_test_assert_mem_equals(option->buffer, "789 0", 3);

	return HTTP_OK;

cleanup:
	return HTTP_INTERNAL_SERVER_ERROR;
}

static int test_http_post_basic(void)
{
	int mres, res = -1;
	char url[84];
	char postdata[256] = "";
	struct bbs_curl c = {
		.url = url,
		.postfields = postdata,
		.forcefail = 0,
	};

	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/test", HTTP_METHOD_GET | HTTP_METHOD_POST, post_basic },
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/upload", HTTP_METHOD_POST, post_upload },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	snprintf(url, sizeof(url), "http://127.0.0.1:%u/test", DEFAULT_TEST_HTTP_PORT);
	bbs_test_assert_equals(0, bbs_curl_get(&c));
	bbs_test_assert_equals(200, c.http_code);
	bbs_test_assert_str_exists_equals(c.response, "<h1>Hello world</h1>");

	bbs_curl_free(&c);

	bbs_test_assert_equals(0, bbs_curl_post(&c));
	bbs_test_assert_equals(200, c.http_code);
	bbs_test_assert_str_exists_equals(c.response, "<h1>Hello there</h1>");

	bbs_curl_free(&c);

	strcpy(postdata, "id=123&secret=456&option=789%200"); /* url encoded POST fields need to be decoded too! */
	bbs_test_assert_equals(0, bbs_curl_post(&c));
	bbs_test_assert_equals(200, c.http_code);

	res = 0;

cleanup:
	bbs_curl_free(&c);
	unregister_uris(tests, ARRAY_LEN(tests));
	return res;
}

static void generate_deterministic_binary_data(char *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		buf[i] = (char) (i % 26);
	}
}

#define BINARY_BUF_SIZE 512

static enum http_response_code post_binary_upload(struct http_session *http)
{
	char buf[BINARY_BUF_SIZE];
	struct post_field *data = http_post_param(http, "data");
	struct post_field *data2 = http_post_param(http, "data2");

	generate_deterministic_binary_data(buf, sizeof(buf));

	bbs_test_assert_exists(data);
	bbs_test_assert_exists(data2);
	bbs_test_assert_exists(data->buffer);
	bbs_test_assert_exists(data2->buffer);
	bbs_test_assert_size_equals(data->length, sizeof(buf));
	bbs_test_assert_size_equals(data->length, sizeof(buf));

	bbs_test_assert_mem_equals(data->buffer, buf, sizeof(buf));
	bbs_test_assert_mem_equals(data2->buffer, buf, sizeof(buf));

	return HTTP_OK;

cleanup:
	return HTTP_INTERNAL_SERVER_ERROR;
}

static enum http_response_code post_file_upload(struct http_session *http)
{
	char buf[BINARY_BUF_SIZE];
	char fbuf[BINARY_BUF_SIZE];
	FILE *fp = NULL;
	size_t size;
	struct post_field *data = http_post_param(http, "data");
	struct post_field *data2 = http_post_param(http, "data2");

	generate_deterministic_binary_data(buf, sizeof(buf));

	bbs_test_assert_exists(data);
	bbs_test_assert_exists(data2);
	bbs_test_assert_null(data->buffer);
	bbs_test_assert_null(data2->buffer);
	bbs_test_assert_size_equals(data->length, sizeof(buf));
	bbs_test_assert_size_equals(data->length, sizeof(buf));

	fp = fopen(data->tmpfile, "rb");
	bbs_test_assert_exists(fp);
	fseek(fp, 0, SEEK_END);
	size = (size_t) ftell(fp);
	rewind(fp); /* Be kind, rewind. */
	bbs_test_assert_size_equals(data->length, size);
	size = fread(fbuf, 1, sizeof(fbuf), fp);
	bbs_test_assert_size_equals(size, sizeof(fbuf));
	bbs_test_assert_mem_equals(fbuf, buf, sizeof(buf));
	fclose(fp);

	fp = fopen(data2->tmpfile, "rb");
	bbs_test_assert_exists(fp);
	fseek(fp, 0, SEEK_END);
	size = (size_t) ftell(fp);
	rewind(fp); /* Be kind, rewind. */
	bbs_test_assert_size_equals(data2->length, size);
	size = fread(fbuf, 1, sizeof(fbuf), fp);
	bbs_test_assert_size_equals(size, sizeof(fbuf));
	bbs_test_assert_mem_equals(fbuf, buf, sizeof(buf));
	fclose(fp);

	return HTTP_OK;

cleanup:
	if (fp) {
		fclose(fp);
	}
	return HTTP_INTERNAL_SERVER_ERROR;
}

/* No need to bother checking the return value of write. If it failed, the tests will also fail anyways. */
#pragma GCC diagnostic ignored "-Wunused-result"

static int test_http_post_multipart_basic(void)
{
	int mres, res = -1;
	char sendbuf[BINARY_BUF_SIZE];
	char buf[256];
	char urlstr[84];
	struct bbs_url url;
	struct bbs_tcp_client client;
	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/upload", HTTP_METHOD_POST, post_binary_upload },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));

	/* localhost might try ::1 before 127.0.0.1, so be explicit here: */
	snprintf(urlstr, sizeof(urlstr), "http://127.0.0.1:%u", DEFAULT_TEST_HTTP_PORT);
	mres = bbs_parse_url(&url, urlstr);
	bbs_test_assert_equals(mres, 0);
	mres = bbs_tcp_client_connect(&client, &url, 0, buf, sizeof(buf));
	bbs_test_assert_equals(mres, 0);

	/* Do not use bbs_tcp_client_send, that will add trailing NULs */
	SWRITE(client.wfd,
		"POST /upload HTTP/1.1\r\n"
		"Host: localhost:58280\r\n" /* Can't use STR/XSTR because that adds a NUL in the middle */
		"Content-Length: 1255\r\n" /* BINARY_BUF_SIZE + BINARY_BUF_SIZE + 231 */
		"Expect: 100-continue\r\n"
		"Content-Type: multipart/form-data; boundary=------------------------d74496d66958873e\r\n"
		"\r\n");

	mres = bbs_tcp_client_expect(&client, "\r\n", 1, SEC_MS(1), "100 Continue");
	bbs_test_assert_equals(mres, 0);

	generate_deterministic_binary_data(sendbuf, sizeof(sendbuf));

	SWRITE(client.wfd,
		"--------------------------d74496d66958873e\r\n"
		"Content-Disposition: form-data; name=\"data\"\r\n"
		"\r\n"); /* Length 91 */
	bbs_write(client.wfd, sendbuf, sizeof(sendbuf));
	SWRITE(client.wfd, "\r\n"); /* End of this part (length 2) */
	/* Send another (identical) chunk */
	SWRITE(client.wfd,
		"--------------------------d74496d66958873e\r\n"
		"Content-Disposition: form-data; name=\"data2\"\r\n"
		"\r\n"); /* Length 92 */
	bbs_write(client.wfd, sendbuf, sizeof(sendbuf));
	SWRITE(client.wfd, "\r\n"); /* End of this part (length 2) */
	SWRITE(client.wfd, "--------------------------d74496d66958873e--"); /* Length 44. No CR LF follows the last boundary. */

	mres = bbs_tcp_client_expect(&client, "\r\n", 2, SEC_MS(1), "HTTP/1.1 200"); /* 2 attempts, first will fail because it's the empty line after 100 continue */
	bbs_test_assert_equals(mres, 0);

	res = 0;

cleanup:
	bbs_tcp_client_cleanup(&client);
	unregister_uris(tests, ARRAY_LEN(tests));
	return res;
}

static int test_http_post_file_upload(void)
{
	int mres, res = -1;
	char sendbuf[BINARY_BUF_SIZE];
	char buf[256];
	char urlstr[84];
	struct bbs_url url;
	struct bbs_tcp_client client;
	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/fileupload", HTTP_METHOD_POST, post_file_upload },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));

	/* localhost might try ::1 before 127.0.0.1, so be explicit here: */
	snprintf(urlstr, sizeof(urlstr), "http://127.0.0.1:%u", DEFAULT_TEST_HTTP_PORT);
	mres = bbs_parse_url(&url, urlstr);
	bbs_test_assert_equals(mres, 0);
	mres = bbs_tcp_client_connect(&client, &url, 0, buf, sizeof(buf));
	bbs_test_assert_equals(mres, 0);

	/* Do not use bbs_tcp_client_send, that will add trailing NULs */
	SWRITE(client.wfd,
		"POST /fileupload HTTP/1.1\r\n"
		"Host: localhost:58280\r\n" /* Can't use STR/XSTR because that adds a NUL in the middle */
		"Content-Length: 1288\r\n" /* BINARY_BUF_SIZE + BINARY_BUF_SIZE + 231 + 33 =  */
		"Expect: 100-continue\r\n"
		"Content-Type: multipart/form-data; boundary=------------------------d74496d66958873e\r\n"
		"\r\n");

	mres = bbs_tcp_client_expect(&client, "\r\n", 1, SEC_MS(1), "100 Continue");
	bbs_test_assert_equals(mres, 0);

	generate_deterministic_binary_data(sendbuf, sizeof(sendbuf));

	SWRITE(client.wfd,
		"--------------------------d74496d66958873e\r\n"
		"Content-Disposition: form-data; name=\"data\"; filename=\"foo\"\r\n"
		"\r\n"); /* Length 91 + 16 = 107 */
	bbs_write(client.wfd, sendbuf, sizeof(sendbuf));
	SWRITE(client.wfd, "\r\n"); /* End of this part (length 2) */
	/* Send another (identical) chunk */
	SWRITE(client.wfd,
		"--------------------------d74496d66958873e\r\n"
		"Content-Disposition: form-data; name=\"data2\"; filename=\"foo2\"\r\n"
		"\r\n"); /* Length 92 + 17 = 109 */
	bbs_write(client.wfd, sendbuf, sizeof(sendbuf));
	SWRITE(client.wfd, "\r\n"); /* End of this part (length 2) */
	SWRITE(client.wfd, "--------------------------d74496d66958873e--"); /* Length 44. No CR LF follows the last boundary. */

	mres = bbs_tcp_client_expect(&client, "\r\n", 2, SEC_MS(1), "HTTP/1.1 200"); /* 2 attempts, first will fail because it's the empty line after 100 continue */
	bbs_test_assert_equals(mres, 0);

	res = 0;

cleanup:
	bbs_tcp_client_cleanup(&client);
	unregister_uris(tests, ARRAY_LEN(tests));
	return res;
}

static enum http_response_code post_header_continue(struct http_session *http)
{
	size_t expected = 12;
	bbs_test_assert_size_equals(http->req->contentlength, expected);
	return HTTP_OK;

cleanup:
	return HTTP_INTERNAL_SERVER_ERROR;
}

static int test_http_header_continuation(void)
{
	int mres, res = -1;
	char buf[256];
	char urlstr[84];
	struct bbs_url url;
	struct bbs_tcp_client client;
	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/headers", HTTP_METHOD_POST, post_header_continue },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));

	/* localhost might try ::1 before 127.0.0.1, so be explicit here: */
	snprintf(urlstr, sizeof(urlstr), "http://127.0.0.1:%u", DEFAULT_TEST_HTTP_PORT);
	mres = bbs_parse_url(&url, urlstr);
	bbs_test_assert_equals(mres, 0);
	mres = bbs_tcp_client_connect(&client, &url, 0, buf, sizeof(buf));
	bbs_test_assert_equals(mres, 0);

	SWRITE(client.wfd,
		"POST /headers HTTP/1.1\r\n"
		"Host: localhost:58280\r\n" /* Can't use STR/XSTR because that adds a NUL in the middle */
		"Content-Length: 1\r\n"
		" 2\r\n"
		"\r\n");

	mres = bbs_tcp_client_expect(&client, "\r\n", 1, SEC_MS(1), "100 Continue");
	bbs_test_assert_equals(mres, 0);

	SWRITE(client.wfd, "test=test123"); /* 12 bytes */

	mres = bbs_tcp_client_expect(&client, "\r\n", 2, SEC_MS(1), "HTTP/1.1 200"); /* 2 attempts, first will fail because it's the empty line after 100 continue */
	bbs_test_assert_equals(mres, 0);

	res = 0;

cleanup:
	bbs_tcp_client_cleanup(&client);
	unregister_uris(tests, ARRAY_LEN(tests));
	return res;
}

static char range_tmpfile[84] = "";

static enum http_response_code range_test(struct http_session *http)
{
	/* Regardless of what the request was for, serve this specific file: */
	if (s_strlen_zero(range_tmpfile)) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return http_static(http, range_tmpfile, NULL);
}

static int test_http_range_single(void)
{
	int mres, res = -1;
	char url[84];
	char ranges[84];
	struct bbs_curl c = {
		.url = url,
		.forcefail = 0,
		.ranges = ranges,
	};

	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/range", HTTP_METHOD_GET, range_test },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	/* Could add locking to make test execution immune to concurrent race conditions */
	if (s_strlen_zero(range_tmpfile)) {
		FILE *fp;
		int i;
		strcpy(range_tmpfile, "/tmp/rangeXXXXXX");
		fp = bbs_mkftemp(range_tmpfile, 0600);
		if (!fp) {
			goto cleanup;
		}
		for (i = 0; i < 10; i++) {
			fprintf(fp, "abcdefghijklmnopqrstuvwxyz");
		}
		fclose(fp);
	}

	snprintf(url, sizeof(url), "http://127.0.0.1:%u/range", DEFAULT_TEST_HTTP_PORT);
	strcpy(ranges, "8-12");
	bbs_test_assert_equals(0, bbs_curl_get(&c));
	bbs_test_assert_equals(206, c.http_code);
	bbs_test_assert_str_exists_equals(c.response, "ijklm");

	bbs_curl_free(&c);

	res = 0;

cleanup:
	bbs_curl_free(&c);
	unregister_uris(tests, ARRAY_LEN(tests));
	if (!s_strlen_zero(range_tmpfile)) {
		unlink(range_tmpfile);
		range_tmpfile[0] = '\0';
	}
	return res;
}

static int test_http_range_multiple(void)
{
	int mres, res = -1;
	char url[84];
	char ranges[84];
	struct bbs_curl c = {
		.url = url,
		.forcefail = 0,
		.ranges = ranges,
	};

	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/range", HTTP_METHOD_GET, range_test },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	/* Could add locking to make test execution immune to concurrent race conditions */
	if (s_strlen_zero(range_tmpfile)) {
		FILE *fp;
		int i;
		strcpy(range_tmpfile, "/tmp/rangeXXXXXX");
		fp = bbs_mkftemp(range_tmpfile, 0600);
		if (!fp) {
			goto cleanup;
		}
		for (i = 0; i < 10; i++) {
			fprintf(fp, "abcdefghijklmnopqrstuvwxyz");
		}
		fclose(fp);
	}

	snprintf(url, sizeof(url), "http://127.0.0.1:%u/range", DEFAULT_TEST_HTTP_PORT);
	strcpy(ranges, "8-12,15-17");
	bbs_test_assert_equals(0, bbs_curl_get(&c));
	bbs_test_assert_equals(206, c.http_code);
	/* cURL will include the multipart headers in the response body. */
	bbs_test_assert_str_exists_equals(c.response,
		"--" RANGE_SEPARATOR "\r\n"
		"Content-Range: bytes 8-12\r\n"
		"\r\n"
		"ijklm"
		"\r\n"
		"--" RANGE_SEPARATOR "\r\n"
		"Content-Range: bytes 15-17\r\n"
		"\r\n"
		"pqr"
		"\r\n"
		"--" RANGE_SEPARATOR "--");

	bbs_curl_free(&c);

	res = 0;

cleanup:
	bbs_curl_free(&c);
	unregister_uris(tests, ARRAY_LEN(tests));
	if (!s_strlen_zero(range_tmpfile)) {
		unlink(range_tmpfile);
		range_tmpfile[0] = '\0';
	}
	return res;
}

static enum http_response_code websocket_server_upgrade(struct http_session *http)
{
	bbs_test_assert_equals(http_websocket_upgrade_requested(http), 1);
	bbs_test_assert_equals(http_websocket_handshake(http), 0);
	return http->res->code;

cleanup:
	return HTTP_INTERNAL_SERVER_ERROR;
}

static int test_http_websocket_upgrade(void)
{
	int mres, res = -1;
	char buf[256];
	char urlstr[84];
	struct bbs_url url;
	struct bbs_tcp_client client;
	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/ws", HTTP_METHOD_GET, websocket_server_upgrade },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));

	/* localhost might try ::1 before 127.0.0.1, so be explicit here: */
	snprintf(urlstr, sizeof(urlstr), "http://127.0.0.1:%u", DEFAULT_TEST_HTTP_PORT);
	mres = bbs_parse_url(&url, urlstr);
	bbs_test_assert_equals(mres, 0);
	mres = bbs_tcp_client_connect(&client, &url, 0, buf, sizeof(buf));
	bbs_test_assert_equals(mres, 0);

	/* Example from https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers */
	SWRITE(client.wfd,
		"GET /ws HTTP/1.1\r\n"
		"Host: localhost:58280\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"\r\n");

	mres = bbs_tcp_client_expect(&client, "\r\n", 1, SEC_MS(1), "101 Switching Protocols");
	bbs_test_assert_equals(mres, 0);

	mres = bbs_tcp_client_expect(&client, "\r\n", 10, SEC_MS(1), "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="); /* By the time headers are all received, should get */
	bbs_test_assert_equals(mres, 0);

	res = 0;

cleanup:
	bbs_tcp_client_cleanup(&client);
	unregister_uris(tests, ARRAY_LEN(tests));
	return res;
}

static enum http_response_code set_session(struct http_session *http)
{
	bbs_test_assert_equals(0, http_session_start(http, 0));
	bbs_test_assert_equals(0, http_session_set_var(http, "foo", "bar"));
	bbs_test_assert_str_exists_equals(http_session_var(http, "foo"), "bar"); /* We just set it, it better still be there */

	return HTTP_OK;

cleanup:
	return HTTP_INTERNAL_SERVER_ERROR;
}

static enum http_response_code get_session(struct http_session *http)
{
	bbs_test_assert_equals(0, http_session_start(http, 0));
	/* Completely separate HTTP request. Session var should still be there. */
	bbs_test_assert_str_exists_equals(http_session_var(http, "foo"), "bar");

	return HTTP_OK;

cleanup:
	return HTTP_INTERNAL_SERVER_ERROR;
}

static int test_http_session(void)
{
	int mres, res = -1;
	char buf[256];
	char urlstr[84];
	struct bbs_url url;
	struct bbs_tcp_client client;

	struct http_route_uri tests[] = {
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/sessionset", HTTP_METHOD_GET, set_session },
		{ NULL, DEFAULT_TEST_HTTP_PORT, "/sessionget", HTTP_METHOD_GET, get_session },
	};
	mres = register_uris(tests, ARRAY_LEN(tests));
	bbs_test_assert_equals(mres, 0);

	memset(&url, 0, sizeof(url));
	memset(&client, 0, sizeof(client));

	/* localhost might try ::1 before 127.0.0.1, so be explicit here: */
	snprintf(urlstr, sizeof(urlstr), "http://127.0.0.1:%u", DEFAULT_TEST_HTTP_PORT);
	mres = bbs_parse_url(&url, urlstr);
	bbs_test_assert_equals(mres, 0);
	mres = bbs_tcp_client_connect(&client, &url, 0, buf, sizeof(buf));
	bbs_test_assert_equals(mres, 0);

	/* We make the HTTP requests manually, instead of using bbs_curl_get,
	 * because the BBS's libcurl interface doesn't support cookies currently,
	 * and honestly, probably doesn't need to since that wouldn't be useful
	 * for much else. */

	SWRITE(client.wfd,
		"GET /sessionset HTTP/1.1\r\n"
		"Host: localhost:58280\r\n"
		"\r\n");

	mres = bbs_tcp_client_expect(&client, "\r\n", 1, SEC_MS(1), "200 OK");
	bbs_test_assert_equals(mres, 0);

	mres = bbs_tcp_client_expect(&client, "\r\n", 10, SEC_MS(1), "Set-Cookie:"); /* By the time headers are all received, should get */
	bbs_test_assert_equals(mres, 0);

	/* Extract the cookie from the buf */
	bbs_strterm(buf, ';'); /* Don't echo the attributes back */
	bbs_debug(3, "Cookie => %s\n", buf);

	/* Close the connection so that we have a separate HTTP client on the server side */
	bbs_tcp_client_cleanup(&client);
	mres = bbs_tcp_client_connect(&client, &url, 0, buf, sizeof(buf));
	bbs_test_assert_equals(mres, 0);

	/* Send the cookie back */
	SWRITE(client.wfd,
		"GET /sessionget HTTP/1.1\r\n"
		"Host: localhost:58280\r\n");
	write(client.wfd, buf + 4, strlen(buf + 4));
	SWRITE(client.wfd, "\r\n\r\n");

	mres = bbs_tcp_client_expect(&client, "\r\n", 1, SEC_MS(1), "200 OK");
	bbs_test_assert_equals(mres, 0);

	res = 0;

cleanup:
	bbs_tcp_client_cleanup(&client);
	unregister_uris(tests, ARRAY_LEN(tests));
	return res;
}

static struct bbs_unit_test tests[] =
{
	{ "HTTP GET Basic", test_http_get_basic },
	{ "HTTP POST Basic", test_http_post_basic },
	{ "HTTP POST Multipart Basic", test_http_post_multipart_basic },
	{ "HTTP POST File Upload", test_http_post_file_upload },
	{ "HTTP Header Continuation", test_http_header_continuation },
	{ "HTTP GET Range Single", test_http_range_single },
	{ "HTTP GET Range Multiple", test_http_range_multiple },
	{ "HTTP Websocket Upgrade", test_http_websocket_upgrade },
	{ "HTTP Sessions", test_http_session },
};

static int unload_module(void)
{
	return bbs_unregister_tests(tests);
}

static int load_module(void)
{
	int res = bbs_register_tests(tests);
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_DEPENDENT("HTTP Unit Tests", "mod_http.so");
