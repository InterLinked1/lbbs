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

#undef strlcat
#include <bsd/string.h>

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

void __bbs_dump_string(const char *restrict s, const char *file, const char *func, int line)
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
	__bbs_log(LOG_DEBUG, 8, file, line, func, "String Dump: '%s'\n", buf);
}

void bbs_dump_mem(unsigned const char *restrict s, size_t len)
{
	size_t i;
	unsigned int start;
	char buf[3 * 16 + 1] = "";
	char ascii[16 + 1] = "";

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

const char *bbs_strcnext(const char *restrict s, char c)
{
	const char *tmp = strchr(s, c);
	if (!tmp) {
		return NULL;
	}
	tmp++;
	if (strlen_zero(tmp)) {
		return NULL;
	}
	return tmp;
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

void bbs_strncpy_until(char *restrict dst, const char *restrict src, size_t size, char term)
{
	/* Copy the username, not including spaces */
	while (*src && *src != term && size) {
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

size_t bbs_append_string(char *restrict dst, const char *src, size_t len)
{
	return strlcat(dst, src, len); /* Requires -lbsd */
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

int bbs_quoted_printable_decode(char *restrict s, size_t *restrict len, int printonly)
{
	char *d = s;
	size_t index = 0;
	*len = 0;
	while (*s) {
		if (*s == '=') {
			unsigned int hex;
			s++;
			index++;
			if (!*s) {
				bbs_warning("Invalid quoted-printable sequence (abruptly terminated)\n");
				return -1;
			}
			if (*s == '\r') {
				/* Soft line break (since we must wrap by pos 76) */
				s++;
				index++;
				if (*s != '\n') {
					bbs_warning("Invalid quoted-printable sequence (CR not followed by LF)\n");
					return -1;
				}
			} else {
				char hexcode[3];
				hexcode[0] = *s;
				s++;
				index++;
				if (!*s) {
					bbs_warning("Invalid quoted-printable sequence (abruptly terminated)\n");
					return -1;
				}
				hexcode[1] = *s;
				hexcode[2] = '\0';
				if (sscanf(hexcode, "%x", &hex) != 1) {
					bbs_warning("Failed to decode %s\n", hexcode);
				}
				if (!printonly || isprint((char) hex)) { /* XXX isprint check only works for single-byte UTF-8 characters */
					*d++ = (char) hex;
					*len += 1;
					bbs_debug(5, "Decoded quoted printable[%lu] %s -> %d (%c)\n", index, hexcode, hex, hex);
				} else {
					/* Don't add invalid UTF-8 characters in the first place */
					bbs_warning("Invalid quoted printable[%lu] %s -> %d (%c)\n", index, hexcode, hex, hex);
				}
			}
			s++;
			index++;
		} else {
			if (*s <= 32 && !isspace(*s)) {
				bbs_warning("Illegal quoted-printable character: %d\n", *s);
				return -1;
			}
			*d++ = *s++;
			index++;
			*len += 1;
		}
	}
	*d = '\0';
	return 0;
}

/*
 * BEGIN THIRD PARTY CODE
 *
 * Copyright (c) 2008-2010 Björn Höhrmann <bjoern@hoehrmann.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * See http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ for details.
 */

#define UTF8_ACCEPT 0
#define UTF8_REJECT 12

static const uint8_t utf8d[] = {
	/* The first part of the table maps bytes to character classes that
	 * to reduce the size of the transition table and create bitmasks. */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,

	/* The second part is a transition table that maps a combination
	 * of a state of the automaton and a character class to a state. */
	0,12,24,36,60,96,84,12,12,12,48,72, 12,12,12,12,12,12,12,12,12,12,12,12,
	12, 0,12,12,12,12,12, 0,12, 0,12,12, 12,24,12,12,12,12,12,24,12,24,12,12,
	12,12,12,12,12,12,12,24,12,12,12,12, 12,24,12,12,12,12,12,12,12,24,12,12,
	12,12,12,12,12,12,12,36,12,36,12,12, 12,36,12,12,12,12,12,36,12,36,12,12,
	12,36,12,12,12,12,12,12,12,12,12,12,
};

static inline uint32_t decode(uint32_t *state, uint32_t byte)
{
	uint32_t type = utf8d[byte];
	*state = utf8d[256 + *state + type];
	return *state;
}
/* END THIRD PARTY CODE */

int bbs_utf8_remove_invalid(unsigned char *restrict s, size_t *restrict len)
{
	int i = 0;
	unsigned char *start, *first = s;
	unsigned char *d = s;
	uint32_t state = UTF8_ACCEPT;

	start = s;
	while (*s) {
		uint32_t res = decode(&state, (uint8_t) *s);
		if (res == UTF8_REJECT) {
			size_t utflen;
			/* There is U+FFFD for "invalid/unknown" UTF-8 character (question mark ? icon), but this requires 3 bytes,
			 * so we can't do an in place replacement without possibly running out of space.
			 * We just remove invalid characters without replacement. */
			utflen = (size_t) (s - start); /* Length of invalid UTF-8 character, in bytes */
			*len -= utflen;
			d -= (utflen - 1);
			bbs_debug(1, "Invalid UTF-8 sequence(%d) (%X...) encountered (position %ld)\n",
				(int) utflen, *(start + 1), s - first);
			/* Start the next chunk fresh */
			s++;
			i++;
			state = UTF8_ACCEPT;
			start = s;
		} else {
			if (res == UTF8_ACCEPT) {
				start = s;
			}
			*d++ = *s++;
		}
	}
	if (i) {
		bbs_warning("%d invalid UTF-8 sequence%s removed\n", i, ESS(i));
	}
	*d = '\0';
	return i;
}
