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

#include "include/curl.h"

#define BBS_CURL_USER_AGENT STRCAT(STRCAT(BBS_NAME, " "), BBS_VERSION)

int bbs_curl_shutdown(void)
{
	/* XXX Memory leak: https://curl-library.cool.haxx.narkive.com/e2XublwY/memory-leak-detected-by-valgrind
	 * This is suppressed in valgrind.supp. */
	curl_global_cleanup();
	return 0;
}

int bbs_curl_init(void)
{
	curl_global_init(CURL_GLOBAL_ALL);
	return 0;
}

void bbs_curl_free(struct bbs_curl *c)
{
	if (c->response) {
		free(c->response);
	}
	/* Don't actually free c, it's probably stack allocated! */
}

struct curl_response_data {
	char *str;
	char *resp;	/* XXX This is a total hack. For some reason str is NULL when we get back to main func so dup the pointer */
	size_t len;
};

#define MAX_CURL_DOWNLOAD_SIZE 10000000 /* 10 MB */

static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
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
		bbs_debug(9, "curl response continued with %ld + %ld\n", respdata->len, realsize);
		newbuf = realloc(respdata->str, respdata->len + realsize + 1); /* Add null terminator */
		if (ALLOC_FAILURE(newbuf)) {
			FREE(respdata->str);
			return 0; /* Fail */
		}
		respdata->str = newbuf;
		memcpy(respdata->str + respdata->len, ptr, realsize); /* strncpy okay here, but since bbs.h blocks it, use memcpy */
		*(respdata->str + respdata->len + realsize) = '\0'; /* Null terminate the string */
	} else {
		bbs_debug(9, "curl response started with %ld\n", realsize);
		respdata->str = strndup(ptr, realsize + 1); /* Add null terminator */
		if (ALLOC_SUCCESS(respdata->str)) {
			*(respdata->str + realsize) = '\0'; /* Null terminate the string */
		}
	}

	if (!respdata->str) {
		if (orig_buf) {
			free(orig_buf);
			respdata->str = NULL; /* Can't use FREE() here */
		}
		return 0; /* Fail */
	}

	respdata->resp = respdata->str; /* XXX Hack: Dup the pointer because for some reason response.str is NULL in curl_common_run? */
	respdata->len += realsize;
	bbs_debug(8, "curl response now %ld bytes\n", respdata->len);
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
	curl_easy_setopt(curl, CURLOPT_USERAGENT, BBS_CURL_USER_AGENT);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20); /* Max 20 seconds */

	curl_easy_setopt(curl, CURLOPT_URL, url);
	return 0;
}

static int curl_common_run(CURL *curl, struct bbs_curl *c, FILE *fp)
{
	int res, cres = -1;
	struct curl_response_data response;
	int http_code;

	memset(&response, 0, sizeof(response));

	if (fp) {
		/* Write response body to a file */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	} else {
		/* Write response body to an allocated string */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	}
	res = curl_easy_perform(curl);

	c->response = NULL;

	if (res != CURLE_OK) {
		bbs_warning("curl_easy_perform() failed for %s: %s\n", c->url, curl_easy_strerror(res));
		if (response.len && response.str) {
			response.str = response.resp;
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
			bbs_debug(4, "CURL Response Code: %d - %ld bytes (%s)\n", http_code, sz, c->url);
		} else {
			bbs_debug(4, "CURL Response Code: %d - %ld bytes (%s)\n", http_code, response.len, c->url);
		}
		c->http_code = http_code;
		failed = STARTS_WITH(c->url, "http") ? !HTTP_RESPONSE_SUCCESS(http_code) : http_code != 0;
		if (c->forcefail && failed) {
			bbs_debug(4, "Response failed, freeing response (length %ld)\n", response.len);
			response.str = response.resp;
			free_if(response.str); /* Free response if we're not going to return it */
		} else {
			if (response.len) {
				if (!response.str && response.resp) {
					bbs_debug(3, "Strange, str was NULL but resp was not?\n"); /* XXX See comments above */
					response.str = response.resp;
				} else {
					response.str = response.resp; /* XXX Do it anyways, since response.str can be an invalid reference at this point */
				}
				if (!response.str) {
					bbs_warning("Response string is NULL?\n");
				} else {
					c->response = response.str; /* Caller is now responsible for freeing this when done */
				}
			} else {
				/* We don't want to read response and get garbage, so make it null terminated */
				c->response = strdup(""); /* This way, response is never NULL */
			}
			cres = 0;
			if (!c->response) {
				bbs_warning("c->response was still NULL?\n");
				c->response = strdup(""); /* Guarantee to caller that response will always be non-NULL */
			}
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
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	if (c->postfields) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, c->postfields);
	} else {
		bbs_debug(5, "No post fields in CURL POST... interesting...\n"); /* Not necessarily wrong, but strange... */
	}

	bbs_debug(5, "cURL POST: %s\n", c->url);
	return curl_common_run(curl, c, NULL);
}
