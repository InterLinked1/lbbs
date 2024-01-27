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
 * \brief Unit Tests
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>

#include "include/module.h"
#include "include/test.h"
#include "include/variables.h"
#include "include/ansi.h"
#include "include/utils.h"
#include "include/curl.h"

static int test_parensep(void)
{
	char buf[256];
	char *s, *left;

	strcpy(buf, "(1 (2))");
	left = buf;
	s = parensep(&left);
	bbs_test_assert_str_equals(s, "1 (2)");

	strcpy(buf, "(1 2 3) 4 5");
	left = buf;
	s = parensep(&left);
	bbs_test_assert_str_equals(s, "1 2 3");
	bbs_test_assert_str_equals(left, "4 5");

	strcpy(buf, "() \".\" \"Archive\"");
	left = buf;
	s = parensep(&left);
	bbs_test_assert_str_equals(s, "");
	bbs_test_assert_str_equals(left, "\".\" \"Archive\"");

	return 0;

cleanup:
	return -1;
}

static int test_quotesep(void)
{
	char buf[256];
	char *s, *left;

	strcpy(buf, "\"foo bar\" \"foo2 bar2\"");
	left = buf;
	s = quotesep(&left);
	bbs_test_assert_str_equals(s, "foo bar");
	s = quotesep(&left);
	bbs_test_assert_str_equals(s, "foo2 bar2");
	s = quotesep(&left);
	bbs_test_assert_null(s);

	strcpy(buf, "\"*\" \"%\"");
	left = buf;
	s = quotesep(&left);
	bbs_test_assert_str_equals(s, "*");
	s = quotesep(&left);
	bbs_test_assert_str_equals(s, "%");
	s = quotesep(&left);
	bbs_test_assert_null(s);

	return 0;

cleanup:
	return -1;
}

static int test_substitution(void)
{
	int res = -1;
	char buffer[256];
	/* Use BBS_TEST_ prefixed test vars so we don't conflict with anything */
	const char *orig = "Hello ${BBS_TEST_testvar}";
	const char *novars = "Hello there!";

	bbs_node_var_set(NULL, "BBS_TEST_testvar", "world");
	bbs_node_substitute_vars(NULL, orig, buffer, sizeof(buffer));
	bbs_test_assert_str_equals(buffer, "Hello world");

	/* Now reuse the buffer */
	bbs_node_var_set(NULL, "BBS_TEST_testvar", "!");
	bbs_node_substitute_vars(NULL, orig, buffer, sizeof(buffer));
	bbs_test_assert_str_equals(buffer, "Hello !");

	/* Substitution with no variables */
	bbs_node_substitute_vars(NULL, novars, buffer, sizeof(buffer));
	bbs_test_assert_str_equals(buffer, novars);

	res = 0; /* All passed */

cleanup:
	/* Clean up the mess we made */
	bbs_node_var_set(NULL, "BBS_TEST_testvar", NULL); /* Clean up the dummy global we made */
	return res;
}

static int test_safe_print(void)
{
	int res = -1;
	char buf[12];
	const char *s = "\tabc\n";

	bbs_test_assert(!bbs_str_safe_print(s, buf, sizeof(buf)));
	bbs_test_assert_str_equals(buf, "<9>abc<10>");
	return 0;

cleanup:
	return res;
}

static int test_printable_strlen(void)
{
	int res = -1;
	const char *s = COLOR(COLOR_GREEN) "abc";
	const char *s2 = COLOR(COLOR_RED) "test" COLOR_RESET;

	bbs_test_assert_equals(bbs_printable_strlen(s), 3);
	bbs_test_assert_equals(bbs_printable_strlen(s2), 4);
	return 0;

cleanup:
	return res;
}

static int test_ansi_strip(void)
{
	int res = -1;
	int outlen;
	const char *s = COLOR(COLOR_GREEN) " abc";
	const char *s2 = COLOR_RESET COLOR(COLOR_GREEN) "abc 123 " COLOR(COLOR_RED) "456" COLOR_RESET;
	const char *s3 = TERM_CLEAR;
	char outbuf[32];

	bbs_test_assert_equals(0, bbs_ansi_strip(s, strlen(s), outbuf, sizeof(outbuf), &outlen));
	bbs_test_assert_equals(4, outlen);
	bbs_test_assert_str_equals(outbuf, " abc");

	bbs_test_assert_equals(0, bbs_ansi_strip(s2, strlen(s2), outbuf, sizeof(outbuf), NULL));
	bbs_test_assert_str_equals(outbuf, "abc 123 456");

	bbs_test_assert_equals(0, bbs_ansi_strip(s3, strlen(s3), outbuf, sizeof(outbuf), &outlen));
	bbs_test_assert_equals(0, outlen);
	bbs_test_assert_str_equals(outbuf, "");

	return 0;

cleanup:
	return res;
}

static int test_backspace_processing(void)
{
	int res = -1;
	const char *s = "Ted" "\b" "st";
	const char *s2 = "\b\b" " Ted" "\b" "st";
	char outbuf[32];

	bbs_test_assert_equals(0, bbs_str_process_backspaces(s, outbuf, sizeof(outbuf)));
	bbs_test_assert_str_equals(outbuf, "Test");

	/* Make sure leading backspaces are ignored */
	bbs_test_assert_equals(0, bbs_str_process_backspaces(s2, outbuf, sizeof(outbuf)));
	bbs_test_assert_str_equals(outbuf, " Test");

	return 0;

cleanup:
	return res;
}

static int test_strcpy_nospaces(void)
{
	int res = -1;
	const char *s = "a string with spaces";
	char outbuf[32];

	bbs_test_assert_equals(0, bbs_strcpy_nospaces(s, outbuf, sizeof(outbuf)));
	bbs_test_assert_str_equals(outbuf, "astringwithspaces");

	return 0;

cleanup:
	return res;
}

static int test_str_ends_with(void)
{
	bbs_test_assert_equals(1, bbs_str_ends_with("big string with substring", "substring"));
	bbs_test_assert_equals(1, bbs_str_ends_with("substring", "substring"));
	bbs_test_assert_equals(0, bbs_str_ends_with("string", "substring"));

	return 0;

cleanup:
	return -1;
}

static int test_str_remove_substring(void)
{
	char buf[256];

	strcpy(buf, "a1 STATUS (RECENT MESSAGES)\r\n");
	bbs_str_remove_substring(buf, " SIZE", STRLEN(" SIZE"));
	bbs_test_assert_str_equals(buf, "a1 STATUS (RECENT MESSAGES)\r\n");

	strcpy(buf, "a1 STATUS (RECENT MESSAGES SIZE)\r\n");
	bbs_str_remove_substring(buf, " SIZE", STRLEN(" SIZE"));
	bbs_test_assert_str_equals(buf, "a1 STATUS (RECENT MESSAGES)\r\n");

	return 0;

cleanup:
	return -1;
}

static int test_lf_crlf(void)
{
	char buf[256];
	char *out = NULL;

	strcpy(buf, "a1\na2\na3\n");
	bbs_test_assert_equals(3, bbs_str_contains_bare_lf(buf));
	out = bbs_str_bare_lf_to_crlf(buf);
	if (!out) {
		goto cleanup;
	}
	bbs_test_assert_str_equals(out, "a1\r\na2\r\na3\r\n");
	free(out);

	return 0;

cleanup:
	free_if(out);
	return -1;
}

/* No need to bother checking the return value of write. If it failed, the tests will also fail anyways. */
#pragma GCC diagnostic ignored "-Wunused-result"

static int test_readline_helper(void)
{
	int mres, res = -1;
	char buf[256];
	int pfd[2];
	struct readline_data rldata;

	if (pipe(pfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	}

	bbs_readline_init(&rldata, buf, sizeof(buf));

	SWRITE(pfd[1], "abcd\r\nefg");
	mres = (int) bbs_readline(pfd[0], &rldata, "\r\n", 1000);
	bbs_test_assert_equals(4, mres);
	bbs_test_assert_str_equals(buf, "abcd");
	SWRITE(pfd[1], "hi\r\nj");
	mres = (int) bbs_readline(pfd[0], &rldata, "\r\n", 1000);
	bbs_test_assert_equals(5, mres);
	bbs_test_assert_str_equals(buf, "efghi");
	SWRITE(pfd[1], "k\r\nlmno\r\npqrs\r\n");
	mres = (int) bbs_readline(pfd[0], &rldata, "\r\n", 1000);
	bbs_test_assert_equals(2, mres);
	bbs_test_assert_str_equals(buf, "jk");
	mres = (int) bbs_readline(pfd[0], &rldata, "\r\n", 1000);
	bbs_test_assert_equals(4, mres);
	bbs_test_assert_str_equals(buf, "lmno");
	mres = (int) bbs_readline(pfd[0], &rldata, "\r\n", 1000);
	bbs_test_assert_equals(4, mres);
	bbs_test_assert_str_equals(buf, "pqrs");
	SWRITE(pfd[1], "tuv\r\n");
	mres = (int) bbs_readline(pfd[0], &rldata, "\r\n", 1000);
	bbs_test_assert_equals(3, mres);
	bbs_test_assert_str_equals(buf, "tuv");
	SWRITE(pfd[1], "wxyz\r\n");
	mres = (int) bbs_readline(pfd[0], &rldata, "\r\n", 1000);
	bbs_test_assert_equals(4, mres);
	bbs_test_assert_str_equals(buf, "wxyz");

	res = 0;

cleanup:
	close(pfd[0]);
	close(pfd[1]);
	return res;
}

static int test_readline_append(void)
{
	int mres;
	char inbuf[256];
	char buf[256];
	struct readline_data rldata;
	int len, ready;

	bbs_readline_init(&rldata, buf, sizeof(buf));

#undef sprintf
	len = sprintf(inbuf, "Test1\nTest2\nTe");
	mres = (int) bbs_readline_append(&rldata, "\n", inbuf, (size_t) len, &ready);
	bbs_test_assert_equals(len, mres);
	bbs_test_assert_equals(1, ready);
	bbs_test_assert_str_equals(buf, "Test1");

	inbuf[0] = '\0';
	mres = (int) bbs_readline_append(&rldata, "\n", inbuf, 0, &ready);
	bbs_test_assert_equals(0, mres);
	bbs_test_assert_equals(1, ready);
	bbs_test_assert_str_equals(buf, "Test2");

	inbuf[0] = '\0';
	mres = (int) bbs_readline_append(&rldata, "\n", inbuf, 0, &ready);
	bbs_test_assert_equals(0, mres);
	bbs_test_assert_equals(0, ready);
	bbs_test_assert_str_equals(buf, "Te");

	len = sprintf(inbuf, "st3\nTest4\n");
	mres = (int) bbs_readline_append(&rldata, "\n", inbuf, (size_t) len, &ready);
	bbs_test_assert_equals(len, mres);
	bbs_test_assert_equals(1, ready);
	bbs_test_assert_str_equals(buf, "Test3");

	inbuf[0] = '\0';
	mres = (int) bbs_readline_append(&rldata, "\n", inbuf, 0, &ready);
	bbs_test_assert_equals(0, mres);
	bbs_test_assert_equals(1, ready);
	bbs_test_assert_str_equals(buf, "Test4");

	return 0;

cleanup:
	return -1;
}

static int test_readline_getn(void)
{
	int res = -1;
	int mres;
	char buf[256];
	char buf2[256];
	int pfd[2], pfd2[2];
	struct readline_data rldata;

	if (pipe(pfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	} else if (pipe(pfd2)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		goto cleanup;
	}

	bbs_readline_init(&rldata, buf, sizeof(buf));

	SWRITE(pfd[1], "abcd\r\nefg");
	mres = (int) bbs_readline_getn(pfd[0], pfd2[1], &rldata, 1000, 3);
	bbs_test_assert_equals(3, mres);
	mres = (int) read(pfd2[0], buf2, sizeof(buf2));
	bbs_test_assert_equals(3, mres);
	buf2[mres] = '\0'; /* Returned string is not NUL-terminated so do that for strcmp */
	bbs_test_assert_str_equals(buf2, "abc");

	mres = (int) bbs_readline_getn(pfd[0], pfd2[1], &rldata, 1000, 4);
	bbs_test_assert_equals(4, mres);
	mres = (int) read(pfd2[0], buf2, sizeof(buf2));
	bbs_test_assert_equals(4, mres);
	buf2[mres] = '\0'; /* Returned string is not NUL-terminated so do that for strcmp */
	bbs_test_assert_str_equals(buf2, "d\r\ne");

	SWRITE(pfd[1], "foobar");
	mres = (int) bbs_readline_getn(pfd[0], pfd2[1], &rldata, 1000, 8);
	bbs_test_assert_equals(8, mres);
	mres = (int) read(pfd2[0], buf2, sizeof(buf2));
	bbs_test_assert_equals(8, mres);
	buf2[mres] = '\0'; /* Returned string is not NUL-terminated so do that for strcmp */
	bbs_test_assert_str_equals(buf2, "fgfoobar");

	res = 0;

cleanup:
	close_if(pfd[0]);
	close_if(pfd[1]);
	close_if(pfd2[0]);
	close_if(pfd2[1]);
	return res;
}

static int test_readline_boundary(void)
{
	int res = -1;
	int mres;
	char buf[256];
	int pfd[2], pfd2[2];
	struct readline_data rldata;
	struct dyn_str dynstr;

	if (pipe(pfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	} else if (pipe(pfd2)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&dynstr, 0, sizeof(dynstr));
	bbs_readline_init(&rldata, buf, sizeof(buf));

	bbs_readline_set_boundary(&rldata, "--seperator--");

	SWRITE(pfd[1], "abcdefg--seperator--hijklmno");
	mres = (int) bbs_readline_get_until(pfd[0], &dynstr, &rldata, 1000, 4096);
	bbs_test_assert_equals(0, mres);
	bbs_test_assert_str_exists_equals(dynstr.buf, "abcdefg");
	bbs_test_assert_str_equals(buf, "hijklmno");

	dyn_str_reset(&dynstr);

	SWRITE(pfd[1], "p--seperator--qrstuv");
	mres = (int) bbs_readline_get_until(pfd[0], &dynstr, &rldata, 1000, 4096);
	bbs_test_assert_equals(0, mres);
	bbs_test_assert_str_exists_equals(dynstr.buf, "hijklmnop");
	bbs_test_assert_str_equals(buf, "qrstuv");

	dyn_str_reset(&dynstr);

	SWRITE(pfd[1], "wxyz--seperator--");
	mres = (int) bbs_readline_get_until(pfd[0], &dynstr, &rldata, 1000, 4096);
	bbs_test_assert_equals(0, mres);
	bbs_test_assert_str_exists_equals(dynstr.buf, "qrstuvwxyz");

	dyn_str_reset(&dynstr);

	res = 0;

cleanup:
	free_if(dynstr.buf);
	close_if(pfd[0]);
	close_if(pfd[1]);
	close_if(pfd2[0]);
	close_if(pfd2[1]);
	return res;
}

static int test_sasl_decode(void)
{
	int res = -1;
	unsigned char *decoded = NULL;
	char *authorization, *authentication, *password;
	const char *s = "amlsbGVzAGppbGxlcwBzZXNhbWU="; /* Example from https://ircv3.net/specs/extensions/sasl-3.1 */

	decoded = bbs_sasl_decode(s, &authorization, &authentication, &password);
	bbs_test_assert(decoded != NULL);
	bbs_test_assert_str_equals(authorization, "jilles");
	bbs_test_assert_str_equals(authentication, "jilles");
	bbs_test_assert_str_equals(password, "sesame");

	res = 0;

cleanup:
	free_if(decoded);
	return res;
}

static int test_cidr_ipv4(void)
{
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("1.1.1.1", "1.1.1.1/32"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("1.0.0.0", "1.0.0.0/32"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("1.0.0.1", "1.0.0.1/24"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("192.168.1.1", "192.168.1.1/32"));
	bbs_test_assert_equals(0, bbs_cidr_match_ipv4("192.168.1.1", "192.168.1.2/32"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("192.168.1.1", "192.168.1.0/24"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("192.168.1.1", "192.168.1.0/16"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("192.168.1.1", "192.168.1.0/8"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("192.168.1.1", "0.0.0.0/0"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("192.168.1.1", "192.0.0.0/8"));
	bbs_test_assert_equals(0, bbs_cidr_match_ipv4("192.168.1.1", "192.168.2.0/24"));
	bbs_test_assert_equals(1, bbs_cidr_match_ipv4("192.168.1.1", "192.168.2.0/16"));

	return 0;

cleanup:
	return -1;
}

static int test_ipv4_detection(void)
{
	bbs_test_assert_equals(1, bbs_hostname_is_ipv4("1.1.1.1"));
	bbs_test_assert_equals(0, bbs_hostname_is_ipv4("example.com"));
	bbs_test_assert_equals(1, bbs_hostname_is_ipv4("1.2.3.4"));
	bbs_test_assert_equals(1, bbs_hostname_is_ipv4("192.168.1.1"));
	bbs_test_assert_equals(1, bbs_hostname_is_ipv4("10.2.3.4"));

	return 0;

cleanup:
	return -1;
}

static int test_url_parsing(void)
{
	int res = -1;
	char buf[84];
	struct bbs_url url;

	snprintf(buf, sizeof(buf), "imap://username:password@imap.example.com:993/mailbox");
	memset(&url, 0, sizeof(url));
	bbs_test_assert_equals(0, bbs_parse_url(&url, buf));
	bbs_test_assert_str_exists_equals(url.prot, "imap");
	bbs_test_assert_str_exists_equals(url.user, "username");
	bbs_test_assert_str_exists_equals(url.pass, "password");
	bbs_test_assert_str_exists_equals(url.host, "imap.example.com");
	bbs_test_assert_equals(url.port, 993);
	bbs_test_assert_str_exists_equals(url.resource, "mailbox");

	snprintf(buf, sizeof(buf), "imap://username@imap.example.com");
	memset(&url, 0, sizeof(url));
	bbs_test_assert_equals(0, bbs_parse_url(&url, buf));
	bbs_test_assert_str_exists_equals(url.prot, "imap");
	bbs_test_assert_str_exists_equals(url.user, "username");
	bbs_test_assert_null(url.pass);
	bbs_test_assert_str_exists_equals(url.host, "imap.example.com");
	bbs_test_assert_equals(url.port, 0);
	bbs_test_assert_null(url.resource);

	snprintf(buf, sizeof(buf), "imap://imap.example.com");
	memset(&url, 0, sizeof(url));
	bbs_test_assert_equals(0, bbs_parse_url(&url, buf));
	bbs_test_assert_str_exists_equals(url.prot, "imap");
	bbs_test_assert_null(url.user);
	bbs_test_assert_null(url.pass);
	bbs_test_assert_str_exists_equals(url.host, "imap.example.com");
	bbs_test_assert_equals(url.port, 0);
	bbs_test_assert_null(url.resource);

	snprintf(buf, sizeof(buf), "imap://user@domain:password@imap.example.com");
	memset(&url, 0, sizeof(url));
	bbs_test_assert_equals(0, bbs_parse_url(&url, buf));
	bbs_test_assert_str_exists_equals(url.prot, "imap");
	bbs_test_assert_str_exists_equals(url.user, "user@domain");
	bbs_test_assert_str_exists_equals(url.pass, "password");
	bbs_test_assert_str_exists_equals(url.host, "imap.example.com");
	bbs_test_assert_equals(url.port, 0);
	bbs_test_assert_null(url.resource);

	res = 0;

cleanup:
	return res;
}

static int test_url_decoding(void)
{
	char buf[256];

	strcpy(buf, "http://example.com/test?foo=bar&test=two+words&foo2=%20%28%29");
	bbs_url_decode(buf);
	bbs_test_assert_str_equals(buf, "http://example.com/test?foo=bar&test=two words&foo2= ()");

	return 0;

cleanup:
	return -1;
}

static int test_quoted_printable_decode(void)
{
	char buf[256];
	char ref[256];
	size_t len;
	int res;

	strcpy(buf, "one=20two=20three=20four=92five=\r\n six");
	res = bbs_quoted_printable_decode(buf, &len, 1);
	bbs_test_assert_equals(res, 0);
	bbs_test_assert_str_equals(buf, "one two three fourfive six");

	strcpy(buf, "one=20two=20three=20four=92five=\r\n six");
	res = bbs_quoted_printable_decode(buf, &len, 0);
	bbs_test_assert_equals(res, 0);
	snprintf(ref, sizeof(ref), "one two three four%cfive six", 0x92);
	bbs_test_assert_str_equals(buf, ref);

	return 0;

cleanup:
	return -1;
}

static int test_utf8_remove_invalid(void)
{
	char buf[256];
	size_t len;
	int res;

	len = (size_t) snprintf(buf, sizeof(buf), "one two three four%cfive six", 0x92);
	res = bbs_utf8_remove_invalid((unsigned char*) buf, &len);
	bbs_test_assert_equals(res, 1);
	bbs_test_assert_str_equals(buf, "one two three fourfive six");

	return 0;

cleanup:
	return -1;
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
#endif

static struct bbs_unit_test tests[] =
{
	{ "parensep", test_parensep },
	{ "quotesep", test_quotesep },
	{ "Variable Substitution", test_substitution },
	{ "Safe Print", test_safe_print },
	{ "Printable String Length", test_printable_strlen },
	{ "ANSI Stripping", test_ansi_strip },
	{ "Backspace Processing", test_backspace_processing },
	{ "String Copy w/o Spaces", test_strcpy_nospaces },
	{ "String Ends With", test_str_ends_with },
	{ "String Remove Substring", test_str_remove_substring },
	{ "LF to CR LF Conversion", test_lf_crlf },
	{ "Readline Helper", test_readline_helper },
	{ "Readline Append", test_readline_append },
	{ "Readline getn", test_readline_getn },
	{ "Readline Boundary", test_readline_boundary },
	{ "SASL Decoding", test_sasl_decode },
	{ "IPv4 CIDR Range Matching", test_cidr_ipv4 },
	{ "IPv4 Address Detection", test_ipv4_detection },
	{ "URL Parsing", test_url_parsing },
	{ "URL Decoding", test_url_decoding },
	{ "Quoted Printable Decode", test_quoted_printable_decode },
	{ "UTF8 Remove Invalid", test_utf8_remove_invalid },
#ifdef EXTRA_TESTS
	{ "cURL Failure", test_curl_failure },
#endif
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

BBS_MODULE_INFO_STANDARD("Unit Tests");
