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

/* XXX Not sure why this is necessary, but it is... */
#define BBS_LOCK_WRAPPERS_NOWARN

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

static void add_envelope(GMimeMessage *message, GString *gs)
{
	char *nstring;
	const char *str = g_mime_object_get_header((GMimeObject *) message, "Date");
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
}

static void write_part_bodystructure(GMimeObject *part, GString *gs, int level)
{
	GMimeContentType *content_type;
	GMimeParamList *params;
	const char *subtype;
	GMimeParam *param;
	GMimeContentDisposition *disposition = NULL;
	int i, n;
	int rfc822;

	if (level++ > 100) {
		bbs_error("Maximum BODYSTRUCTURE recursion reached\n");
		return;
	}

	g_string_append_c(gs, '(');

	if (GMIME_IS_MULTIPART(part)) {
		GMimeMultipart *multipart = (GMimeMultipart *) part;

		n = g_mime_multipart_get_count(multipart);
		for (i = 0; i < n; i++) {
			GMimeObject *subpart = g_mime_multipart_get_part(multipart, i);
			write_part_bodystructure(subpart, gs, level);
		}
	}

	/* Body type */
	content_type = g_mime_object_get_content_type(part);
	subtype = g_mime_content_type_get_media_subtype(content_type);

	rfc822 = !strcasecmp(g_mime_content_type_get_media_type(content_type), "message") && subtype && !strcasecmp(subtype, "rfc822");

	if (!GMIME_IS_MULTIPART(part)) {
		g_string_append_printf(gs, "\"%s\" ", g_mime_content_type_get_media_type(content_type));
	} else {
		g_string_append(gs, " "); /* Don't include "multipart" if it's multipart */
	}

	/* Body subtype */
	if (subtype) {
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
	} else if (GMIME_IS_MESSAGE_PART(part) && !rfc822) {
		GMimeMessage *message;
		const char *str;
		char *nstring;

		message = GMIME_MESSAGE_PART(part)->message;

		g_string_append_c(gs, '(');

		/* print envelope */
		add_envelope(message, gs);

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
		write_part_bodystructure((GMimeObject *) message->mime_part, gs, level);
	} else if (GMIME_IS_PART(part)) {
		const char *contentid;
		disposition = g_mime_object_get_content_disposition(part); /* Save for later */

		/* Body ID and body description */
		contentid = g_mime_object_get_content_id((GMimeObject *) part);
		if (contentid) {
			/* Body ID would be (quoted) contents of Content-ID header, if there is one */
			g_string_append_printf(gs, "\"<%s>\" NIL ", contentid);
		} else {
			g_string_append(gs, "NIL NIL ");
		}

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
	} else if (rfc822) {
		/* Body ID and body description */
		g_string_append(gs, "NIL NIL ");

		/* This is not a part, so we can't do the above (though maybe there's a different function?)
		 * It's either 7-bit or 8-bit, just make it work for now: */
		g_string_append(gs, "NIL"); /* XXX Not sure if it's 7-bit or 8-bit, can't use g_mime_part_get_content_encoding */
	}

	/* Body size */
	if (!GMIME_IS_MULTIPART(part)) { /* Includes RFC822 message */
		/* Body size */
		GMimeStream *stream;
		ssize_t bodysize;
		size_t newlines = 0;
		char *s;

		/* Use a null stream since we don't actually care about the content, only its length (and # of newlines) */
		stream = g_mime_stream_null_new();
		if (GMIME_IS_TEXT_PART(part) || rfc822) {
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
			if (GMIME_IS_TEXT_PART(part) || rfc822) {
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

		if (rfc822) {
			/* Envelope structure, body structure */
			GMimeMessage *message = GMIME_MESSAGE_PART(part)->message;
			g_string_append(gs, " (");
#if 0
			add_envelope(message, gs);
#else
			/* libetpan chokes on the envelope we send here, and I know this works, so just send NILs for now, for compatibility.
			 * I've seen other IMAP servers do this, so maybe there's a good reason for that.
			 * (I suspect it probably has to do with not properly handling certain characters, e.g. parentheses)
			 * libetpan also has this issue with parsing FLAGS/PERMANENTFLAGS. */
			g_string_append(gs, "NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL");
#endif
			g_string_append_c(gs, ')');
			write_part_bodystructure((GMimeObject *) message->mime_part, gs, level);
		}

		if (rfc822 || !strcasecmp(g_mime_content_type_get_media_type(content_type), "TEXT")) {
			g_string_append_printf(gs, " %lu", newlines); /* Number of newlines in part */
		}
		g_string_append(gs, " NIL"); /* Non-multipart extension data: body MD5 */
	}

	/* Extensions */
	if (!rfc822 && disposition) {
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

static GMimeMessage *mk_mime(const char *file)
{
	GMimeFormat format = GMIME_FORMAT_MESSAGE;
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;
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
	bbs_mark_closed(fd); /* g_object_unref closed our file descriptor for us */

	if (!message) {
		bbs_error("Failed to parse message %s as MIME\n", file);
	}

	return message;
}

/* Opaque structure for MIME message, so other modules can reuse this for multiple operations */
struct bbs_mime_message {
	GMimeMessage *message;
};

struct bbs_mime_message *bbs_mime_message_parse(const char *filename)
{
	struct bbs_mime_message *mime = malloc(sizeof(*mime));
	if (ALLOC_FAILURE(mime)) {
		return NULL;
	}
	mime->message = mk_mime(filename);
	return mime;
}

void bbs_mime_message_destroy(struct bbs_mime_message *mime)
{
	g_object_unref(mime->message);
	free(mime);
}

char *bbs_mime_make_bodystructure(struct bbs_mime_message *mime)
{
	GMimeMessage *message = mime->message;
	GString *str;
	gchar *result;
#ifdef CHECK_VALIDITY
	int p = 0;
	int in_quoted = 0;
	char *s;
#endif

	str = g_string_new("");
	write_part_bodystructure(message->mime_part, str, 0);

#ifdef CHECK_VALIDITY
	/* Ensure the result is well parenthesized */
	s = str->str;
	while (*s) {
		if (in_quoted) {
			if (*s == '\\') {
				/* Next " is escaped, don't count that */
				if (*(s + 1)) {
					s++;
				}
			} else if (*s == '"') {
				in_quoted = 0;
			}
		} else {
			if (*s == '(') {
				p++;
			} else if (*s == ')') {
				p--;
			} else if (*s == '"') {
				in_quoted = 1;
			}
		}
		s++;
	}

	if (p != 0) {
		bbs_warning("BODYSTRUCTURE is malformed, parentheses score was %d\n", p);
		/* If there are unterminated parentheses, we can fix that easily. Too many is not handled here.
		 * This should never happen anyways. */
		while (p-- > 0) {
			g_string_append(str, ")");
		}
	}
#endif

	result = g_string_free(str, FALSE); /* Free the g_string but not the buffer */
	return result; /* gchar is just a typedef for char, so this returns a char */
}

#if SEMVER_VERSION(GMIME_MAJOR_VERSION, GMIME_MINOR_VERSION, GMIME_MICRO_VERSION) < SEMVER_VERSION(3, 2, 8)
/* This function was only added in gmime commit 3efc24a6cdc88198e11e43f23e03e32f12b13bd8,
 * so older packages of the library don't have it. Define it manually for those cases. */
static ssize_t g_mime_object_write_content_to_stream(GMimeObject *object, GMimeFormatOptions *options, GMimeStream *stream)
{
	g_return_val_if_fail (GMIME_IS_OBJECT (object), -1);
	g_return_val_if_fail (GMIME_IS_STREAM (stream), -1);

	return GMIME_OBJECT_GET_CLASS(object)->write_to_stream(object, options, TRUE, stream);
}
#endif

static void write_part(GMimeObject *part, GMimeStream *stream, enum mime_part_filter filter)
{
	char *buf;
	GMimeMessage *message;
	GMimeContentType *content_type;
	const char *subtype;
	GMimeFormatOptions *format = g_mime_format_options_get_default();

#define IS_RFC822(part) (!strcasecmp(g_mime_content_type_get_media_type(content_type), "message") && subtype && !strcasecmp(subtype, "rfc822"))

	content_type = g_mime_object_get_content_type(part);
	subtype = g_mime_content_type_get_media_subtype(content_type);

	switch (filter) {
	case MIME_PART_FILTER_TEXT:
		/* If the type is message/rfc822, proceed. If not, illegal (just return empty). */
		if (!IS_RFC822(part)) {
			bbs_debug(1, "Ignoring request for TEXT, since its type is %s/%s\n", g_mime_content_type_get_media_type(content_type), S_IF(subtype));
			return;
		}
		/* Might be a more elegant way to do this with gmime, but not sure what it is at the moment.
		 * For now, return the whole thing, and later strip out the headers. */
		/* Fall through */
	case MIME_PART_FILTER_ALL:
		if (g_mime_object_write_content_to_stream((GMimeObject *) part, format, stream) == -1) {
			bbs_warning("Failed to write part to stream\n");
		}
		break;
	case MIME_PART_FILTER_MIME:
		/* XXX In theory, since we get a string, we could return this directly,
		 * rather than adding to a stream and then allocating another string.
		 * However, the stream allows us to be a little more abstract here. */
		buf = g_mime_object_get_headers(part, format);
		if (!strlen_zero(buf)) {
			g_mime_stream_printf(stream, "%s\r\n", buf); /* Need to include end of headers */
		}
		g_free(buf);
		break;
	case MIME_PART_FILTER_HEADERS:
		/* If the type is message/rfc822, proceed. If not, illegal (just return empty). */
		if (!IS_RFC822(part)) {
			bbs_debug(1, "Ignoring request for HEADERS, since its type is %s/%s\n", g_mime_content_type_get_media_type(content_type), S_IF(subtype));
			return;
		}
		/* XXX Same thing here about returning a string directly */
		message = g_mime_message_part_get_message((GMimeMessagePart *) part);
		buf = g_mime_object_get_headers((GMimeObject *) message, format);
		if (!strlen_zero(buf)) {
			g_mime_stream_printf(stream, "%s\r\n", buf); /* Need to include end of headers */
		}
		g_free(buf);
		break;
	}
}

/*! * \brief Get the contents of a MIME part by part number */
static int get_part(GMimeMessage *message, GMimeStream *mem, const char *spec, enum mime_part_filter filter)
{
	GMimePartIter *iter;
	GMimeObject *part;

	iter = g_mime_part_iter_new((GMimeObject *) message);
	if (!g_mime_part_iter_is_valid(iter)) {
		bbs_warning("Part iteration is invalid\n");
		g_mime_part_iter_free(iter);
		return -1;
	}
	if (!g_mime_part_iter_jump_to(iter, spec)) {
		bbs_warning("Failed to fetch part number %s\n", spec);
		g_mime_part_iter_free(iter);
		return -1;
	}

	part = g_mime_part_iter_get_current(iter);
	write_part(part, mem, filter);
	g_mime_part_iter_free(iter);
	return 0;
}

char *bbs_mime_get_part(struct bbs_mime_message *mime, const char *spec, size_t *restrict outlen, enum mime_part_filter filter)
{
	GMimeMessage *message = mime->message;
	GMimeStream *mem;
	GByteArray *buffer;
	char *buf;
	unsigned char *bufdata;
	size_t buflen;

	mem = g_mime_stream_mem_new();
	if (!mem) {
		bbs_error("Failed to allocate stream buffer\n");
		return NULL;
	}

	if (get_part(message, mem, spec, filter)) {
		g_object_unref(mem);
		return NULL;
	}

	buffer = g_mime_stream_mem_get_byte_array((GMimeStreamMem *) mem);

	if (filter == MIME_PART_FILTER_TEXT) {
		char *eoh;
		size_t diff;
		/* Now we have to pay the piper... skip past the headers. */
		eoh = memmem(buffer->data, buffer->len, "\r\n\r\n", STRLEN("\r\n\r\n"));
		if (!eoh) {
			bbs_debug(3, "Message has no body, just headers, if that...\n");
			g_object_unref(mem);
			return NULL;
		}
		diff = (size_t) (eoh - (char*) buffer->data);
		diff += STRLEN("\r\n\r\n");
		bufdata = buffer->data + diff;
		buflen = buffer->len - diff;
	} else {
		bufdata = buffer->data;
		buflen = buffer->len;
	}

	buf = malloc(buflen + 1);
	if (ALLOC_FAILURE(buf)) {
		g_object_unref(mem);
		return NULL;
	}
	memcpy(buf, bufdata, buflen);
	buf[buflen] = '\0';
	*outlen = buflen;
	g_object_unref(mem);

	return buf; /* gchar is just a typedef for char, so this returns a char */
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
	/* This doesn't free everything (possibly lost leaks in valgrind). See:
	 * Q: https://mail.gnome.org/archives/gmime-devel-list/2012-November/msg00000.html
	 * A: https://mail.gnome.org/archives/gmime-devel-list/2012-November/msg00001.html
	 */
	g_mime_shutdown();
	return 0;
}

BBS_MODULE_INFO_FLAGS("IMAP MIME Parser", MODFLAG_GLOBAL_SYMBOLS);
