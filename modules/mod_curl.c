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
 * \brief cURL
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h> /* use strdup */

#include <curl/curl.h>

#include "include/module.h"

#include "include/mod_curl.h"

#define BBS_CURL_USER_AGENT STRCAT(STRCAT(BBS_NAME, " "), BBS_VERSION)

void bbs_curl_free(struct bbs_curl *c)
{
	free_if(c->response);
	/* Don't actually free c, it's probably stack allocated! */
}

struct curl_response_data {
	char *str;
	size_t len;
};

#define MAX_CURL_DOWNLOAD_SIZE 10000000 /* 10 MB */

/*!
 * \brief cURL response data callback function
 * \returns Number of bytes on success, 0 on failure
 */
static size_t WriteMemoryCallback(void *restrict ptr, size_t size, size_t nmemb, void *restrict data)
{
	register size_t realsize = size * nmemb;
	struct curl_response_data *respdata = data;
	char *newbuf, *orig_buf = respdata->str;

	bbs_assert_exists(respdata);

	/* Prevent a huge download from using up all our memory */
	if (respdata->len + size > MAX_CURL_DOWNLOAD_SIZE) {
		bbs_warning("Partial download size %ld exceeded maximum allowed\n", respdata->len + size);
		return 0;
	}

	/* XXX Not for binary data */
	if (respdata->len) {
#ifdef EXTRA_DEBUG
		bbs_debug(9, "curl response continued with %ld + %ld\n", respdata->len, realsize);
#endif
		newbuf = realloc(respdata->str, respdata->len + realsize + 1); /* Add null terminator */
		if (ALLOC_FAILURE(newbuf)) {
			FREE(respdata->str);
			return 0; /* Fail */
		}
		respdata->str = newbuf;
		memcpy(respdata->str + respdata->len, ptr, realsize); /* strncpy okay here, but since bbs.h blocks it, use memcpy */
		*(respdata->str + respdata->len + realsize) = '\0'; /* Null terminate the string */
	} else {
#ifdef EXTRA_DEBUG
		bbs_debug(9, "curl response started with %ld\n", realsize);
#endif
		/* Don't use memdup, since the last byte doesn't exist in the source */
		respdata->str = malloc(realsize + 1); /* Add null terminator */
		if (ALLOC_SUCCESS(respdata->str)) {
			memcpy(respdata->str, ptr, realsize);
			*(respdata->str + realsize) = '\0'; /* Null terminate, for ease if it's a string */
		}
	}

	if (!respdata->str) {
		if (orig_buf) {
			free(orig_buf);
			respdata->str = NULL; /* Can't use FREE() here */
		}
		return 0; /* Fail */
	}

	respdata->len += realsize;
#ifdef EXTRA_DEBUG
	bbs_debug(8, "curl response now %ld bytes\n", respdata->len);
#endif
	return realsize;
}

static int curl_common_setup(CURL **curl_ptr, const char *url)
{
	CURL *curl;

	if (strlen_zero(url)) {
		bbs_warning("URL is empty!\n");
		return -1;
	}

	curl = curl_easy_init();
	if (!curl) {
		bbs_warning("curl_easy_init failed\n");
		return -1;
	}

	*curl_ptr = curl;

	/* see https://curl.se/libcurl/c/ for documentation */

	/* curl_easy_setopt: https://curl.se/libcurl/c/curl_easy_setopt.html */
	if (curl_easy_setopt(curl, CURLOPT_USERAGENT, BBS_CURL_USER_AGENT)) {
		bbs_warning("Failed to set cURL user agent\n");
		goto cleanup;
	}
	if (curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1)) {
		bbs_warning("Failed to set cURL option NOSIGNAL\n");
		goto cleanup;
	}
	if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20)) { /* Max 20 seconds */
		bbs_warning("Failed to set cURL timeout\n");
		goto cleanup;
	}
	if (curl_easy_setopt(curl, CURLOPT_URL, url)) {
		bbs_warning("Failed to set cURL option CURLOPT_URL\n");
		goto cleanup;
	}
	return 0;

cleanup:
	curl_easy_cleanup(curl);
	return -1;
}

#ifdef DEBUG_CURL
static int curl_debug(CURL *handle, curl_infotype type, char *data, size_t size, void *clientp)
{
	switch (type) {
		case CURLINFO_TEXT:
			bbs_debug(5, "== %.*s", (int) size, data);
			break;
		/* XXX Not binary safe, could use bbs_dump_mem instead: */
		case CURLINFO_HEADER_OUT:
			bbs_debug(5, "=> Send header %.*s", (int) size, data);
			break;
		case CURLINFO_DATA_OUT:
			bbs_debug(5, "=> Send data %.*s", (int) size, data);
			break;
		case CURLINFO_SSL_DATA_OUT:
			bbs_debug(5, "=> Send SSL data %.*s", (int) size, data);
			break;
		case CURLINFO_HEADER_IN:
			bbs_debug(5, "=> Recv header %.*s", (int) size, data);
			break;
		case CURLINFO_DATA_IN:
			bbs_debug(5, "=> Recv data %.*s", (int) size, data);
			break;
		case CURLINFO_SSL_DATA_IN:
			bbs_debug(5, "=> Recv SSL data %.*s", (int) size, data);
			break;
		default:
			bbs_debug(5, "-- %.*s", (int) size, data);
			break;
			UNUSED(handle);
			UNUSED(clientp);
	}

	return 0;
}
#endif

static int curl_common_run(CURL *curl, struct bbs_curl *c, FILE *fp)
{
	int res, cres = -1;
	struct curl_response_data response;
	long http_code;

	memset(&response, 0, sizeof(response));

	if (fp) {
		/* Write response body to a file */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
		if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp)) {
			bbs_warning("Failed to set cURL opt CURLOPT_WRITEDATA\n");
			return -1;
		}
	} else {
		/* Write response body to an allocated string */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response)) {
			bbs_warning("Failed to set cURL WRITEDATA\n");
		}
	}
	if (c->cookies) {
		curl_easy_setopt(curl, CURLOPT_COOKIE, c->cookies);
	}
	if (!strlen_zero(c->ranges)) {
		curl_easy_setopt(curl, CURLOPT_RANGE, c->ranges);
	}
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); /* Follow redirects */
#ifdef DEBUG_CURL
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
	res = curl_easy_perform(curl);

	c->response = NULL;

	if (res != CURLE_OK) {
		bbs_warning("curl_easy_perform() failed for %s: %s\n", c->url, curl_easy_strerror(res));
		if (response.len && response.str) {
			free_if(response.str); /* Free response if we're not going to return it */
		}
	} else {
		int failed;
		/* Some of this code assumes HTTP, but is really generic to other protocols, too */
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (fp) {
			/* We're already at the end of the file, so we can get the file size
			 * just from the current position. */
			long int sz = ftell(fp);
			bbs_debug(4, "CURL Response Code: %ld - %ld bytes (%s)\n", http_code, sz, c->url);
		} else {
			bbs_debug(4, "CURL Response Code: %ld - %ld bytes (%s)\n", http_code, response.len, c->url);
		}
		c->http_code = (int) http_code;
		failed = STARTS_WITH(c->url, "http") ? !HTTP_RESPONSE_SUCCESS(http_code) : http_code != 0;
		if (c->forcefail && failed) {
			bbs_debug(4, "Response failed, freeing response (length %ld)\n", response.len);
			free_if(response.str); /* Free response if we're not going to return it */
		} else {
			if (response.len) {
				bbs_assert_exists(response.str);
				c->response = response.str; /* Caller is now responsible for freeing this when done */
			} else {
				/* We don't want to read response and get garbage, so make it null terminated */
				c->response = strdup(""); /* This way, response is never NULL */
			}
			cres = 0;
		}
	}

	curl_easy_cleanup(curl);
	return cres;
}

int bbs_curl_get(struct bbs_curl *c)
{
	CURL *curl = NULL; /* Dummy initialization to make gcc happy... we'll do the real initialization in curl_common_setup */

	if (curl_common_setup(&curl, c->url)) {
		return -1;
	}

	bbs_debug(5, "cURL GET: %s\n", c->url);
	return curl_common_run(curl, c, NULL);
}

int bbs_curl_get_file(struct bbs_curl *c, const char *filename)
{
	int res;
	FILE *fp;
	CURL *curl = NULL; /* Dummy initialization to make gcc happy... we'll do the real initialization in curl_common_setup */

	fp = fopen(filename, "wb");
	if (!fp) {
		bbs_error("Failed to open file for writing: %s\n", filename);
		return -1;
	}

	if (curl_common_setup(&curl, c->url)) {
		fclose(fp);
		return -1;
	}

	bbs_debug(5, "cURL GET: %s -> %s\n", c->url, filename);
	res = curl_common_run(curl, c, fp);

	fclose(fp);
	return res;
}

int bbs_curl_post(struct bbs_curl *c)
{
	CURL *curl = NULL;

	if (curl_common_setup(&curl, c->url)) {
		return -1;
	}
	if (curl_easy_setopt(curl, CURLOPT_POST, 1)) {
		bbs_warning("Failed to set cURL option CURLOPT_POST\n");
	}
	if (c->postfields) {
		if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, c->postfields)) {
			bbs_warning("Failed to set POST fields\n");
		}
	} else {
		bbs_debug(5, "No post fields in CURL POST... interesting...\n"); /* Not necessarily wrong, but strange... */
	}

	bbs_debug(5, "cURL POST: %s\n", c->url);
	return curl_common_run(curl, c, NULL);
}

#ifdef EXTRA_TESTS
static int test_curl_failure(void)
{
	int res;
	struct bbs_curl c = {
		.url = "https://httpstat.us/400", /* Faster than https://httpbin.org/status/400 */
		.forcefail = 1,
	};

	/* This test implicitly passes if it does not cause a segfault */
	res = bbs_curl_get(&c);
	bbs_test_assert_equals(-1, res);

	bbs_curl_free(&c);
	return 0;

cleanup:
	bbs_curl_free(&c);
	return -1;
}

static struct bbs_unit_test tests[] =
{
	{ "cURL Failure", test_curl_failure },
};
#endif

static int unload_module(void)
{
	/* XXX Memory leak: https://curl-library.cool.haxx.narkive.com/e2XublwY/memory-leak-detected-by-valgrind
	 * This is suppressed in valgrind.supp. */
	curl_global_cleanup();
	return 0;
}

static int load_module(void)
{
	curl_global_init(CURL_GLOBAL_ALL);
	return 0;
}

BBS_MODULE_INFO_FLAGS("cURL Support", MODFLAG_GLOBAL_SYMBOLS);
