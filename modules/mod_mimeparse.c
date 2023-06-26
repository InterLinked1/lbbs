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
 * \brief MIME Parser Supplements for IMAP Server
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gmime/gmime.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "include/module.h"
#include "include/utils.h" /* use bbs_str_count */

#include "include/mod_mimeparse.h"

/*! \note This code is based on gmime's imap-example.c,
 * which is licensed under GPLv2.
 *
 * Some major changes have been made, namely:
 * - build the body structure in a dynamic string, rather than writing to a file
 * - performance optimizations by avoiding unnecessary allocations
 * - elimination of duplicated code
 * - memory leaks fixed
 * - BODYSTRUCTURE response formatting fixes. The sample in gmime cannot be used as is.
 *   This has been improved through adjustments from RFC 3501 BODYSTRUCTURE
 *   and cross-referencing with other IMAP servers.
 */

static char *escape_string(const char *string)
{
	const char *inptr;
	GString *str;

	str = g_string_new("");

	inptr = string;

	while (*inptr) {
		const char *start = inptr;
		while (*inptr && *inptr != '"') {
			inptr++;
		}

		g_string_append_len(str, start, inptr - start);
		if (*inptr == '"') {
			g_string_append(str, "\\\"");
			inptr++;
		}
	}

	return g_string_free(str, FALSE);
}

static void write_part_bodystructure(GMimeObject *part, GString *gs)
{
	GMimeContentType *content_type;
	GMimeParamList *params;
	const char *subtype;
	GMimeParam *param;
	GMimeContentDisposition *disposition = NULL;
	int i, n;

	g_string_append_c(gs, '(');

	if (GMIME_IS_MULTIPART(part)) {
		GMimeMultipart *multipart = (GMimeMultipart *) part;

		n = g_mime_multipart_get_count(multipart);
		for (i = 0; i < n; i++) {
			GMimeObject *subpart = g_mime_multipart_get_part(multipart, i);
			write_part_bodystructure(subpart, gs);
		}
	}

	/* Body type */
	content_type = g_mime_object_get_content_type(part);
	if (!GMIME_IS_MULTIPART(part)) {
		g_string_append_printf(gs, "\"%s\" ", g_mime_content_type_get_media_type(content_type));
	} else {
		g_string_append(gs, " "); /* Don't include "multipart" if it's multipart */
	}

	/* Body subtype */
	if ((subtype = g_mime_content_type_get_media_subtype(content_type))) {
		g_string_append_printf(gs, "\"%s\" ", subtype);
	} else {
		g_string_append(gs, "\"\"");
	}

	/* Content-Type params */
	params = g_mime_content_type_get_parameters(content_type);
	if ((n = g_mime_param_list_length(params)) > 0) {
		g_string_append_c(gs, '(');
		for (i = 0; i < n; i++) {
			if (i > 0) {
				g_string_append_c(gs, ' ');
			}
			param = g_mime_param_list_get_parameter_at(params, i);
			g_string_append_printf(gs, "\"%s\" \"%s\"", g_mime_param_get_name(param), g_mime_param_get_value(param));	
		}
		g_string_append(gs, ") ");
	} else {
		g_string_append(gs, "NIL ");
	}

	if (GMIME_IS_MULTIPART(part)) {
		/* Already did it */
	} else if (GMIME_IS_MESSAGE_PART(part)) {
		GMimeMessage *message;
		const char *str;
		char *nstring;

		message = GMIME_MESSAGE_PART(part)->message;

		/* print envelope */
		g_string_append_c(gs, '(');

		str = g_mime_object_get_header((GMimeObject *) message, "Date");
		g_string_append_printf(gs, "\"%s\" ", str);

#define MIME_HEADER(name) \
	if ((str = g_mime_object_get_header((GMimeObject *) message, name))) { \
		nstring = escape_string(str); \
		g_string_append_printf(gs, "\"%s\" ", nstring); \
		g_free(nstring); \
	} else { \
		g_string_append_printf(gs, "\"%s\" ", ""); \
	} \

		MIME_HEADER("Subject");
		MIME_HEADER("From");
		MIME_HEADER("Sender");
		MIME_HEADER("Reply-To");
		MIME_HEADER("To");
		MIME_HEADER("Cc");
		MIME_HEADER("Bcc"); /* Should this even exist? */
		MIME_HEADER("In-Reply-To");

#undef MIME_HEADER

		/* Body parameter parenthesized list */
		if ((str = g_mime_message_get_message_id(message))) {
			nstring = escape_string(str);
			g_string_append_printf(gs, "\"%s\"", nstring);
			g_free(nstring);
		} else {
			g_string_append_printf(gs, "\"%s\"", "");
		}

		g_string_append(gs, ") ");

		/* print body */
		write_part_bodystructure((GMimeObject *) message->mime_part, gs);
	} else if (GMIME_IS_PART(part)) {
		disposition = g_mime_object_get_content_disposition(part); /* Save for later */

		/* Body ID and body description */
		g_string_append(gs, "NIL NIL ");

		/* Body encoding */
		switch (g_mime_part_get_content_encoding((GMimePart *) part)) {
		case GMIME_CONTENT_ENCODING_7BIT:
			g_string_append(gs, "\"7BIT\"");
			break;
		case GMIME_CONTENT_ENCODING_8BIT:
			g_string_append(gs, "\"8BIT\"");
			break;
		case GMIME_CONTENT_ENCODING_BINARY:
			g_string_append(gs, "\"BINARY\"");
			break;
		case GMIME_CONTENT_ENCODING_BASE64:
			g_string_append(gs, "\"BASE64\"");
			break;
		case GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE:
			g_string_append(gs, "\"QUOTED-PRINTABLE\"");
			break;
		case GMIME_CONTENT_ENCODING_UUENCODE:
			g_string_append(gs, "\"X-UUENCODE\"");
			break;
		default:
			g_string_append(gs, "NIL");
		}
	}

	/* Body size */
	if (!GMIME_IS_MULTIPART(part)) {
		/* Body size */
		GMimeStream *stream;
		ssize_t bodysize;
		size_t newlines = 0;
		char *s;

		/* Use a null stream since we don't actually care about the content, only its length (and # of newlines) */
		stream = g_mime_stream_null_new();
		if (GMIME_IS_TEXT_PART(part)) {
			g_mime_stream_null_set_count_newlines((GMimeStreamNull*) stream, TRUE);
		}
		bodysize = g_mime_object_write_to_stream((GMimeObject*) part, NULL, stream);
		if (bodysize == -1) {
			bbs_error("Failed to write part to GMime stream\n");
		} else {
			newlines = ((GMimeStreamNull*) stream)->newlines; /* no accessor method, but this is # of newlines */
		}

		/* bodysize here includes the headers for the MIME part too, but we only want
		 * the body here, so subtract that out */
		s = g_mime_object_get_headers((GMimeObject*) part, NULL);
		if (s) {
			/* We only want the body length, so subtract the length of the headers */
			size_t headerslen, headerlines;
			headerslen = strlen(s);
			headerlines = (size_t) bbs_str_count(s, '\n'); /* Ends in newline, so need to add 1 */
#ifdef EXTRA_DEBUG
			bbs_debug(5, "Entire part: %ld bytes, %lu lines / Headers: %lu bytes, %lu lines\n", bodysize, newlines, headerslen, headerlines);
#endif
			if (headerslen > (size_t) bodysize) {
				bbs_error("%ld bytes total, but header is %lu bytes?\n", bodysize, headerslen);
			} else {
				bodysize -= (ssize_t) headerslen;
			}
			if (bodysize > 2) { /* End of headers CR LF CR LF. One of the newlines is included, the other is not. */
				bodysize -= 2;
			}
			if (GMIME_IS_TEXT_PART(part)) {
				if (headerlines >= newlines) {
					bbs_error("%lu lines total (%ld bytes), but header has %lu lines?\n", newlines, bodysize, headerlines);
				} else {
					newlines -= headerlines;
				}
				if (newlines > 0) {
					newlines--; /* For CR LF for end of headers */
				}
			}
			g_free(s);
		}
		g_object_unref(stream);

		g_string_append_printf(gs, " %ld", bodysize); /* Number of bytes in part */
		/* XXX MESSAGE/RFC822 is also specifically called out in the RFC, but not handled here yet */
		if (!strcasecmp(g_mime_content_type_get_media_type(content_type), "TEXT")) {
			g_string_append_printf(gs, " %lu", newlines); /* Number of newlines in part */
		}
		g_string_append(gs, " NIL"); /* Non-multipart extension data: body MD5 */
	}

	if (disposition) {
		/* This is kind of a continuation of the previous block.
		 * Since this is an extension, it absolutely must come after the NIL for body MD5 */
		g_string_append(gs, " (");
		g_string_append_printf(gs, "\"%s\" ", g_mime_content_disposition_get_disposition(disposition));

		params = g_mime_content_disposition_get_parameters(disposition);
		if ((n = g_mime_param_list_length(params)) > 0) {
			g_string_append_c(gs, '(');
			for (i = 0; i < n; i++) {
				if (i > 0) {
					g_string_append_c(gs, ' ');
				}
				param = g_mime_param_list_get_parameter_at(params, i);
				g_string_append_printf(gs, "\"%s\" \"%s\"", g_mime_param_get_name(param), g_mime_param_get_value(param));
			}
			g_string_append(gs, ")");
		} else {
			g_string_append(gs, "NIL");
		}
		g_string_append(gs, ")");
	}

	g_string_append_c(gs, ')');
}

char *mime_make_bodystructure(const char *itemname, const char *file)
{
	GMimeFormat format = GMIME_FORMAT_MESSAGE;
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;
	GString *str;
	gchar *result;
	int fd;

	fd = open(file, O_RDONLY, 0);
	if (fd < 0) {
		bbs_error("Failed to open %s: %s\n", file, strerror(errno));
		return NULL;
	}

	stream = g_mime_stream_fs_new(fd);
	parser = g_mime_parser_new_with_stream(stream);
	g_mime_parser_set_persist_stream(parser, FALSE);
	g_mime_parser_set_format(parser, format);
	g_object_unref(stream);

	message = g_mime_parser_construct_message(parser, NULL);

	g_object_unref(parser);
	close(fd);

	if (!message) {
		bbs_error("Failed to parse message as MIME\n");
		return NULL;
	}

	str = g_string_new("");
	g_string_append_printf(str, "%s ", itemname);
	write_part_bodystructure(message->mime_part, str);
	result = g_string_free(str, FALSE); /* Free the g_string but not the buffer */
	g_object_unref(message);
	return result; /* gchar is just a typedef for char, so this returns a char */
}

static int load_module(void)
{
	g_mime_init();
	/* Use CR LF for email messages, not LF, or our calculations for body size will be off */
	g_mime_format_options_set_newline_format(g_mime_format_options_get_default(), GMIME_NEWLINE_FORMAT_DOS);
	return 0;
}

static int unload_module(void)
{
	/* This doesn't free everything (possibly lost leaks in valgrind . See:
	 * Q: https://mail.gnome.org/archives/gmime-devel-list/2012-November/msg00000.html
	 * A: https://mail.gnome.org/archives/gmime-devel-list/2012-November/msg00001.html
	 */
	g_mime_shutdown();
	return 0;
}

BBS_MODULE_INFO_FLAGS("IMAP MIME Parser", MODFLAG_GLOBAL_SYMBOLS);
