/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Wildmat pattern matching
 */

#include "include/bbs.h"

#include "include/utils.h"
#include "include/test.h"

#include "nntp.h"

/*
 * Adapted from public domain code for matching wildmats written by Rich Salz in 1986 and appearing in INN 1.4
 * From: https://github.com/richsalz/wildmat/blob/main/wildmat.c
 * This version does not handle UTF-8 Unicode.
 * Minor modifications have been made for:
 * - formatting/readability
 * - parameters (e.g. accept const char *, instead of char *)
 * - safety against user input (the original assumes that inputs are valid, and they may not be). Without INVALID_PATTERN, tests would fail due to uninitialized accesses in valgrind.
 */
#define TRUE 1
#define FALSE 0
#define ABORT -1
#define INVALID_PATTERN -1 /* Bounds check on pattern, abort if invalid; checks added prior to any assumed memory accesses in original code */
#define NEGATE_CLASS '^' /* What character marks an inverted character class? */
#define OPTIMIZE_JUST_STAR /* Is "*" a common pattern? */

static int match_pattern(register const char *text, register const char *p)
{
    register int last;
    register int matched;
    register int reverse;

    for ( ; *p; text++, p++) {
		if (*text == '\0' && *p != '*') {
			return ABORT;
		}
		switch (*p) {
		case '\\':
			/* Literal match with following character. */
			p++;
			if (!*p) {
				return INVALID_PATTERN;
			}
			/* FALLTHROUGH */
		default:
			if (*text != *p) {
				return FALSE;
			}
			continue;
		case '?':
			/* Match anything. */
			continue;
		case '*':
			while (*++p == '*') {
				continue; /* Consecutive stars act just like one. */
			}
			if (*p == '\0') {
				return TRUE; /* Trailing star matches everything. */
			}
			while (*text) {
				if ((matched = match_pattern(text++, p)) != FALSE) {
					return matched;
				}
			}
			return ABORT;
		case '[':
			if (!p[1]) {
				return INVALID_PATTERN;
			}
			reverse = p[1] == NEGATE_CLASS ? TRUE : FALSE;
			if (reverse) {
				p++; /* Inverted character class. */
				if (!p[1]) {
					return INVALID_PATTERN;
				}
			}
			matched = FALSE;
			if (p[1] == ']' || p[1] == '-') {
				if (*++p == *text) {
					matched = TRUE;
				}
			}
			if (!*p || !p[1]) {
				return INVALID_PATTERN;
			}
			for (last = *p; *++p && *p != ']'; last = *p) {
				/* This next line requires a good C compiler. */
				if (!*p || !p[1]) {
					return INVALID_PATTERN;
				}
				if (*p == '-' && p[1] != ']' ? *text <= *++p && *text >= last : *text == *p) {
					matched = TRUE;
				}
			}
			if (!*p) {
				return INVALID_PATTERN;
			}
			if (matched == reverse) {
				return FALSE;
			}
			continue;
		}
    }

#ifdef MATCH_TAR_PATTERN
    if (*text == '/') {
		return TRUE;
	}
#endif
    return *text == '\0';
}

/*!
 * \brief Match a single wildmat pattern
 * \param text Text to check
 * \param p wildmat pattern
 * \retval 1 on match, 0 if doesn't match
 */
static int wildmat_pattern_match(const char *text, const char *p)
{
#ifdef OPTIMIZE_JUST_STAR
    if (p[0] == '*' && p[1] == '\0') {
		return TRUE;
	}
#endif
    return match_pattern(text, p) == TRUE;
}

#undef FALSE
#undef ABORT
#undef INVALID_PATTERN
#undef NEGATE_CLASS
#undef OPTIMIZE_JUST_STAR
/* End public domain wildmat code */

/*! \brief Check for match for a whole wildmat */
static int match_expr(const char *text, const char *patterns, int allow_poison)
{
	char buf[1024];
	char *p, *s = buf;
	int match = 0, poisoned = 0;

	safe_strncpy(buf, patterns, sizeof(buf));

	/* The grammar described in RFC 3977 4.1 can be somewhat confusing, as it refers to wildmats and wildmat patterns.
	 *
	 * Wildmat patterns themselves are the single patterns that cannot contain commas.
	 * Wildmats themselves consist of 1 or more wildmat patterns (which could be as simple as the wildcard, *)
	 *
	 * RFC 3977 4.2 states that each constituent wildcard pattern is matched, and the rightmost pattern that matches is identified.
	 * If not preceded with "!", the whole wildmatch matches. Otherwise, the whole wildmat does not match.
	 *
	 * "Poison patterns" are a later enhancement whereby patterns beginning with @ instead of ! will "poison" a pattern,
	 * i.e. a poison match will cause the whole pattern to not match. Normally, if at least one group in a list of newsgroups
	 * matches, an article is processed, but a poison match would cause the whole article to not be processed (accepted/sent), i.e.
	 * crossposting to a group that would trigger a poison match "poisons" the whole article.
	 * The poison entry still has to be the last one to match for poison logic to apply.
	 *
	 * At the moment, we do not natively support UTF-8 in the wildmat code.
	 *
	 * In other words, we do not match if ANY pattern matches, but only if the rightmost match is non-negated (and there is such a match). */
	while ((p = strsep(&s, ","))) {
		int reverse, poison = 0;
		if (allow_poison) {
			poison = *p == '@';
		}
		reverse = *p == '!' || poison;
		if (reverse) {
			p++;
		}

		/* Optimization: If the pattern can't change the result, don't bother checking this pattern */
		if (match == !reverse && poison == poisoned) {
			continue;
		}

		if (match_pattern(text, p) == TRUE) {
			poisoned = poison;
			match = !reverse;
		}
	}
	if (poisoned) {
		return -1;
	}
	return match;
}
#undef TRUE

int uwildmat(const char *text, const char *pattern)
{
	return match_expr(text, pattern, 0);
}

int uwildmat_poison(const char *text, const char *pattern)
{
	return match_expr(text, pattern, 1);
}

int uwildmat_simple(const char *text, const char *pattern)
{
	return wildmat_pattern_match(text, pattern);
}

int test_wildmats(void)
{
	/* RFC 3977 4.2 */
	bbs_test_assert_equals(1, uwildmat("aaa", "a*,!*b,*c*"));
	bbs_test_assert_equals(0, uwildmat("abb", "a*,!*b,*c*"));
	bbs_test_assert_equals(1, uwildmat("ccb", "a*,!*b,*c*"));
	bbs_test_assert_equals(0, uwildmat("xxx", "a*,!*b,*c*"));

	/* RFC 3977 4.4 */
	bbs_test_assert_equals(1, uwildmat("abc", "abc")); /* The one string "abc" */
	bbs_test_assert_equals(0, uwildmat("abc", "abcd"));
	bbs_test_assert_equals(1, uwildmat("abc", "abc,def")); /* The two strings "abc" and "def" */
	bbs_test_assert_equals(1, uwildmat("def", "abc,def"));
	bbs_test_assert_equals(0, uwildmat("abc,def", "abc,def"));
#if 0
	/* wildmat_domatch doesn't support UTF-8 unicode, so this won't match at the moment: */
	bbs_test_assert_equals(0, uwildmat("\xC2\xA3", "\xC2\xA3")); /* pound sterling symbol */
#endif
	bbs_test_assert_equals(1, uwildmat("apple", "a*")); /* Any string that begins with "a" */
	bbs_test_assert_equals(1, uwildmat("acb", "a*b")); /* Any string that begins with "a" and ends with "b" */
	bbs_test_assert_equals(0, uwildmat("abc", "a*b"));
	bbs_test_assert_equals(1, uwildmat("abc", "a*,*b")); /* Any string that begins with "a" or ends with "b" */
	bbs_test_assert_equals(1, uwildmat("ccb", "a*,*b"));
	bbs_test_assert_equals(1, uwildmat("abc", "a*,!*b")); /* Any string that begins with "a" and does not end with "b" */
	bbs_test_assert_equals(0, uwildmat("ab", "a*,!*b"));
	bbs_test_assert_equals(1, uwildmat("acdc", "a*,!*b,c*")); /* Any string that begins with "a" and does not end with "b", and any string that begins with "c" no matter what it ends with */
	bbs_test_assert_equals(1, uwildmat("cat", "a*,!*b,c*"));
	bbs_test_assert_equals(1, uwildmat("can", "a*,c*,!*b")); /* Any string that begins with "a" or "c" and does not end with "b" */
	bbs_test_assert_equals(1, uwildmat("ark", "a*,c*,!*b"));
	bbs_test_assert_equals(0, uwildmat("cab", "a*,c*,!*b"));
	bbs_test_assert_equals(1, uwildmat("bat", "?a*")); /* Any string with "a" as its second character */
	bbs_test_assert_equals(0, uwildmat("dead", "?a*"));
	bbs_test_assert_equals(1, uwildmat("dead", "??a*")); /* Any string with "a" as its third character */
	bbs_test_assert_equals(1, uwildmat("dead", "*a?")); /* Any string with "a" as its penultimate character */
	bbs_test_assert_equals(1, uwildmat("beard", "*a??")); /* Any string with "a" as its antepenultimate character */
	bbs_test_assert_equals(0, uwildmat("dead", "*a??"));

	bbs_test_assert_equals(1, uwildmat("-adobe-courier-bold-o-normal--12-120-75-75-m-70-iso8859-1", "-*-*-*-*-*-*-12-*-*-*-m-*-*-*")); /* Example from wildmat.c: */
	bbs_test_assert_equals(0, uwildmat("foobar", "foo[a-")); /* This example caused a crash in the original version of Rich Salz's match_pattern */
	bbs_test_assert_equals(0, uwildmat("foobar", "foo["));

	bbs_test_assert_equals(1, uwildmat_simple("!aaabbb", "!a*b*"));

	bbs_test_assert_equals(0, uwildmat_poison("foo.bar", "foo.*,!foo.bar,@*.poison"));
	bbs_test_assert_equals(-1, uwildmat_poison("foo.poison", "*,@f*,@*.poison"));
	bbs_test_assert_equals(1, uwildmat_poison("foo.poison", "*,@f*,@*.poison,*"));

	return 0;

cleanup:
	return -1;
}
