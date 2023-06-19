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
 * \brief String utility functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h> /* use isprint, isspace */

#include "include/string.h"

int bbs_printable_strlen(const char *restrict s)
{
	int c = 0;
	while (*s) {
		if (*s == 27) {
			/* Escape sequences include printable characters, so we need to process them as an entire unit */
			if (*(s + 1) == '[') {
				/* Control Sequence Introducer: Begins an (ANSI) escape sequence.
				 * These are variable length, ugh...
				 * XXX This is far from complete, in fact it's close to incomplete.
				 * Because bbs_printable_strlen is mainly used to deal with color,
				 * that's the main thing we handle here.
				 */
				if (*(s + 2) == '1' && *(s + 3) == ';' && isdigit(*(s + 4)) && isdigit(*(s + 5)) && *(s + 6) == 'm') {
					/* Color */
					s += 7; /* Skip the whole escape sequence */
					continue;
				}
			}
		} else if (isprint(*s)) {
			s++;
			c++;
		} else if (*s == '\t') {
			/* Oh boy. This is impossible to say. It depends on WHERE the tab is on the page. We have no context here. */
			/* Fortunately, this shouldn't happen. The automatic menu screen generator doesn't use tabs.
			 * Users may use tabs if they manually make the screen using display= in menus.conf,
			 * but in that case, we don't call print_strlen on that. */
			bbs_warning("Printable string length calculation may be inaccurate: string contains TAB\n");
			s++;
			c += 4; /* Assume 4 characters, but this is kinda arbitrary. But for the purposes we care about, overestimate is safer than underestimate. */
		} else {
			s++; /* Some other non printable thing, just ignore it */
		}
	}
	return c;
}

int bbs_str_process_backspaces(const char *restrict s, char *restrict buf, size_t len)
{
	int i = 0;
	while (*s) {
		if (len <= 1) {
			bbs_error("Truncation occured\n");
			return -1;
		}
		if (*s == 8 || *s == 127) { /* BACKSPACE or DELETE character */
			if (i > 0) {
				*--buf = '\0';
				len++;
				i--;
			} /* else, ignore backspaces at beginning of line */
			s++;
		} else {
			*buf++ = *s++;
			i++;
			len--;
		}
	}
	*buf = '\0';
	return 0;
}

int bbs_str_safe_print(const char *restrict s, char *restrict buf, size_t len)
{
	char ascii_num[7];

	while (*s) {
		if (len <= 1) {
			bbs_error("Truncation occurred when building string\n");
			return -1;
		}
		/* isprint doesn't include LF, but we don't want to.
		 * It does include TAB, which we don't want either. */
		if (isprint(*s) && *s != '\t') {
			*buf = *s; /* Just copy */
			buf++;
			len--;
		} else {
			/* Make a representation */
			size_t replen = (size_t) snprintf(ascii_num, sizeof(ascii_num), "<%d>", *s);
			if (replen >= len - 1) {
				bbs_error("Truncation occurred when building string\n");
				return -1;
			}
			safe_strncpy(buf, ascii_num, len - 1);
			buf += replen;
			len -= replen;
		}
		s++;
	}
	*buf = '\0';
	return 0;
}

void bbs_dump_string(const char *restrict s)
{
	char buf[1024];
	char *pos = buf;
	int len = sizeof(buf) - 4;

	while (*s) {
		if (len <= 6) {
			break;
		}
		if (isprint(*s)) {
			*pos++ = *s;
			len--;
		} else {
			if (*s == '\r') {
				strcpy(pos, "<CR>"); /* Safe */
				pos += 4;
				len -= 4;
			} else if (*s == '\n') {
				strcpy(pos, "<LF>");
				pos += 4;
				len -= 4;
			} else {
				int b = snprintf(pos, (size_t) len, "<%d>", *s);
				pos += b;
				len -= b;
			}
		}
		s++;
	}

	*pos = '\0';
	bbs_debug(8, "String Dump: '%s'\n", buf);
}

void bbs_dump_mem(unsigned const char *restrict s, size_t len)
{
	size_t i;
	unsigned int start;
	char buf[3 * 16 + 1] = "";
	char ascii[16 + 1] = "";
	if (ALLOC_FAILURE(buf)) {
		return;
	}
	start = 0;
	for (i = 0; i < len; i++) {
		int pos = (int) (i % 16);
#undef sprintf
		if (pos) {
			sprintf(buf + pos * 3 - 1, " %02x", s[i]);
		} else {
			sprintf(buf + pos * 3, "%02x", s[i]);
		}
		if (isprint(s[i])) {
			ascii[pos] = (char) s[i];
		} else {
			ascii[pos] = '.';
		}
		if (pos == 15) {
			/* Flush */
			ascii[16] = '\0';
			bbs_debug(3, "%04x %-47s | %s\n", start, buf, ascii);
			ascii[0] = buf[0] = '\0';
			start = (unsigned int) (i + 1);
		}
	}
	if (i % 16) {
		ascii[i % 16] = '\0';
		bbs_debug(3, "%04x %-47s | %s\n", start, buf, ascii);
	}
}

int bbs_str_count(const char *restrict s, char c)
{
	int count = 0;
	while (*s) {
		if (*s == c) {
			count++;
		}
		s++;
	}
	return count;
}

int bbs_strncount(const char *restrict s, size_t len, char c)
{
	size_t i;
	int count = 0;
	for (i = 0; i < len; i++) {
		if (s[i] == c) {
			count++;
		}
	}
	return count;
}

int bbs_term_line(char *restrict c)
{
	int len = 0;

	/* More efficient than calling:
	 * bbs_strterm(linebuf, '\r');
	 * bbs_strterm(linebuf, '\n');
	 * in succession.
	 * Plus this returns the new string length for free. */

	while (*c) {
		if (*c == '\r' || *c == '\n') {
			*c = '\0';
			break;
		}
		len++;
		c++;
	}
	return len;
}

/* XXX Have to pass -Wno-null-dereference to the linker for this function with -flto */
void safe_strncpy(char *restrict dst, const char *restrict src, size_t size)
{
	while (*src && size) {
		*dst++ = *src++;
		size--;
	}
	if (unlikely(!size)) {
		dst--;
	}
	*dst = '\0';
}

int bbs_strcpy_nospaces(const char *restrict s, char *restrict buf, size_t len)
{
	/* Copy the username, not including spaces */
	while (*s && --len > 1) {
		if (isprint(*s) && !isspace(*s)) {
			*buf++ = *s;
		}
		s++;
	}
	*buf = '\0'; /* Null terminate */
	return len > 1 ? 0 : -1;
}

void bbs_str_remove_substring(char *restrict s, const char *word, size_t wordlen)
{
	char *dst = s;
	while (*s) {
		if (!strncmp(s, word, wordlen)) {
			/* Skip over it */
			s += wordlen;
		} else {
			*dst++ = *s++;
		}
	}
	*dst = '\0';
}

void bbs_strreplace(char *restrict s, char find, char repl)
{
	while (*s) {
		if (*s == find) {
			*s = repl;
		}
		s++;
	}
}

int bbs_str_isprint(const char *restrict s)
{
	while (*s) {
		/* isprint doesn't include LF */
		if (!isprint(*s) && !isspace(*s)) {
			bbs_debug(3, "Character %d is not printable\n", *s);
			return 0;
		}
		s++;
	}
	return 1;
}

int bbs_str_anyprint(const char *restrict s)
{
	while (*s) {
		if (isprint(*s) && !isspace(*s)) {
			return 1;
		}
		s++;
	}
	return 0;
}

void str_tolower(char *restrict s)
{
	while (*s) {
		*s = (char) tolower(*s);
		s++;
	}
}

int skipn(char **str, char c, int n)
{
	int count = 0;
	char *s = *str;

	while (*s) {
		if (*s == c) {
			if (++count == n) {
				*str = s + 1;
				break;
			}
		}
		s++;
	}
	return count;
}

int skipn_noparen(char **str, char c, int n)
{
	int count = 0;
	int level = 0;
	char *s = *str;

	while (*s) {
		if (*s == '(') {
			level++;
		} else if (*s == ')') {
			level--;
		} else if (!level && *s == c) {
			if (++count == n) {
				*str = s + 1;
				break;
			}
		}
		s++;
	}
	return count;
}

char *parensep(char **str)
{
	char *ret, *s = *str;
	int count = 0;

	if (strlen_zero(s)) {
		return NULL;
	}

	if (*s != '(') {
		if (*s == ' ') {
			s++;
		}
		if (*s != '(') {
			bbs_warning("parensep used incorrectly: %s\n", *str);
		}
	}

	while (*s) {
		if (*s == '(') {
			count++;
		} else if (*s == ')') {
			count--;
			if (count == 0) {
				*s++ = '\0';
				ret = *str + 1;
				if (*s == ' ') {
					s++;
				}
				*str = s;
				return ret;
			}
		}
		s++;
	}
	return NULL;
}

char *quotesep(char **str)
{
	char *ret, *s = *str;

	if (strlen_zero(s)) {
		return NULL;
	}

	if (*s != '"' && *s == ' ') {
		s++;
	}

	if (*s != '"') {
		return strsep(str, " "); /* If not in quotes, then just return the next word as usual */
	}
	if (!*(s + 1)) {
		bbs_warning("Malformed string (quotes not terminated)\n");
		return NULL;
	}
	ret = s + 1;
	s = strchr(s + 1, '"');
	if (!s) {
		bbs_warning("Unterminated quotes\n");
		return NULL;
	}

	*s++ = '\0';
	*str = s;
	return ret;
}
