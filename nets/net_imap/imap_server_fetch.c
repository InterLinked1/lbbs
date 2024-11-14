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
 * \brief IMAP Server FETCH
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>
#include <dirent.h>

#include "include/node.h"

#include "include/mod_mail.h"
#include "include/mod_mimeparse.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_server_acl.h"
#include "nets/net_imap/imap_server_flags.h"
#include "nets/net_imap/imap_server_fetch.h"

/* Series of process_fetch helper functions for process_fetch.
 * Some of these might seem silly, but they are all only used once, so gcc should inline them anyways.
 * process_fetch was getting too big and overwhelming to work on so that's the main reason for compartmentalizing these. */

static int process_fetch_flags(struct imap_session *imap, const char *filename, int markseen, int recent, char *response, size_t responselen, char **buf, int *len)
{
	char inflags[53];
	int c = 0;
	const char *flags = strchr(filename, ':'); /* maildir flags */
	if (!flags) {
		bbs_error("Message file %s contains no flags?\n", filename);
		return -1;
	}
	if (markseen && !strchr(flags, FLAG_SEEN)) {
		/* FYI, clients like Thunderbird do not use this: they PEEK the body and then explicitly STORE the Seen flag */
		inflags[c++] = FLAG_SEEN;
		bbs_debug(6, "Appending seen flag since message wasn't already seen\n");
	}
	if (recent) {
		/* Add the phony maildir filename character for Recent, so it can get printed in the response */
		inflags[c++] = FLAG_RECENT;
	}
	if (c) {
		inflags[c] = '\0';
		safe_strncpy(inflags + c, flags, sizeof(inflags) - (size_t) c);
		flags = inflags;
	}
	generate_flag_names_full(imap, flags, response, responselen, buf, len);
	return 0;
}

static int process_fetch_size(const char *filename, char *response, size_t responselen, char **buf, int *len)
{
	unsigned long size;
	if (parse_size_from_filename(filename, &size)) {
		return -1;
	}
	SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "RFC822.SIZE %lu", size);
	return 0;
}

static int process_fetch_modseq(const char *filename, char *response, size_t responselen, char **buf, int *len, unsigned long *modseq)
{
	if (!*modseq) {
		/* If we didn't already compute this, do it now */
		if (parse_modseq_from_filename(filename, modseq)) {
			return -1;
		}
	}
	SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "MODSEQ %lu", *modseq);
	return 0;
}

static int process_fetch_internaldate(const char *fullname, char *response, size_t responselen, char **buf, int *len)
{
	struct stat st;
	struct tm modtime;
	char timebuf[40];

	if (stat(fullname, &st)) {
		bbs_error("stat(%s) failed: %s\n", fullname, strerror(errno));
		return -1;
	}

	/* Linux doesn't really have "time created" like Windows does. Just use the modified time,
	 * and hopefully renaming doesn't change that. */
	/* Use server's local time */
	/* Example INTERNALDATE format: 08-Nov-2022 01:19:54 +0000 */
	strftime(timebuf, sizeof(timebuf), "%d-%b-%Y %H:%M:%S %z", localtime_r(&st.st_mtim.tv_sec, &modtime));
	SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "INTERNALDATE \"%s\"", timebuf);
	return 0;
}

static int process_fetch_envelope(const char *fullname, char *response, size_t responselen, char **buf, int *len)
{
	char linebuf[1001];
	int findcount;
	int started = 0;
	char *bufhdr;
	FILE *fp;

	/* We can't rely on the headers in the message being in the desired order.
	 * So look for each one explicitly, which means we have to double loop.
	 * Furthermore, since there could be e.g. multiple To headers,
	 * we may need to add all of them.
	 */
	fp = fopen(fullname, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
		return -1;
	}

	SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "ENVELOPE (");

#define SEEK_HEADERS(hdrname) \
	rewind(fp); \
	findcount = 0; \
	while ((fgets(linebuf, sizeof(linebuf), fp))) { \
		bbs_term_line(linebuf); \
		if (s_strlen_zero(linebuf)) { \
			break; \
		} \
		if (!strncasecmp(linebuf, hdrname ":", STRLEN(hdrname ":"))) { \
			findcount++; \
		} \
		if (!strncasecmp(linebuf, hdrname ":", STRLEN(hdrname ":")))

#define END_SEEK_HEADERS \
	}

/* We cannot use the ternary operator here because this is already a macro, so the format string must be a constant, not a ternary expression */
#define APPEND_BUF_OR_NIL(bufptr, cond) \
	if ((cond)) { \
		SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "\"%s\"", bufptr); \
	} else { \
		SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "NIL"); \
	}

#define APPEND_BUF_OR_NIL_NOSPACE(bufptr, cond) \
	if ((cond)) { \
		SAFE_FAST_COND_APPEND_NOSPACE(response, responselen, *buf, *len, 1, "\"%s\"", bufptr); \
	} else { \
		SAFE_FAST_COND_APPEND_NOSPACE(response, responselen, *buf, *len, 1, "NIL"); \
	}

#define SEEK_HEADER_SINGLE(hdrname) \
	bufhdr = NULL; \
	SEEK_HEADERS(hdrname) { \
		bufhdr = linebuf + STRLEN(hdrname) + 1; \
		ltrim(bufhdr); \
		break; \
	} \
	END_SEEK_HEADERS; \
	if (!started) { \
		APPEND_BUF_OR_NIL_NOSPACE(bufhdr, !strlen_zero(bufhdr)); /* Use the NOSPACE version since this is the first one */ \
		started = 1; \
	} else { \
		APPEND_BUF_OR_NIL(bufhdr, !strlen_zero(bufhdr)); \
	}

#define SEEK_HEADER_MULTIPLE(hdrname) \
	SEEK_HEADERS(hdrname) { \
		char *name, *user, *host; \
		char *sourceroute = NULL; /* https://stackoverflow.com/questions/30693478/imap-envelope-email-address-format/30698163#30698163 */ \
		bufhdr = linebuf + STRLEN(hdrname) + 1; \
		ltrim(bufhdr); \
		bbs_parse_email_address(bufhdr, &name, &user, &host); \
		if (name) { \
			STRIP_QUOTES(name); \
		} \
		/* Need spaces between them but not before the first one. And again, we can't use ternary expressions so do it the verbose way. */ \
		if (findcount > 1) { \
			SAFE_FAST_COND_APPEND_NOSPACE(response, responselen, *buf, *len, 1, " ("); \
		} else { \
			SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "(("); /* First one, so also add the outer one */ \
		} \
		APPEND_BUF_OR_NIL_NOSPACE(name, !strlen_zero(name)); \
		APPEND_BUF_OR_NIL(sourceroute, !strlen_zero(sourceroute)); \
		APPEND_BUF_OR_NIL(user, !strlen_zero(user)); \
		APPEND_BUF_OR_NIL(host, !strlen_zero(host)); \
		SAFE_FAST_COND_APPEND_NOSPACE(response, responselen, *buf, *len, 1, ")"); \
		break; \
	} \
	END_SEEK_HEADERS; \
	if (findcount) { \
		SAFE_FAST_COND_APPEND_NOSPACE(response, responselen, *buf, *len, 1, ")"); \
	} else { \
		SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "NIL"); \
	}

	/* From RFC:
	 * The fields of the envelope structure are in the following order:
	 * date, subject, from, sender, reply-to, to, cc, bcc, in-reply-to, and message-id.
	 * The date, subject, in-reply-to, and message-id fields are strings.
	 * The from, sender, reply-to, to, cc, and bcc fields are parenthesized lists of address structures.
	 * An address structure is a parenthesized list that describes an electronic mail address.
	 * The fields of an address structure are in the following order: personal name,
	 * [SMTP] at-domain-list (source route), mailbox name, and host name. */

	 /* Example (formatted with line breaks for clarity): * 1 FETCH (ENVELOPE
	  *
	  * ("Tue, 8 Nov 2022 01:19:53 +0000 (UTC)"
	  * "Welcome!"
	  * (("Sender Name" NIL "sender" "example.com"))
	  * (("Sender Name" NIL "sender" "example.com"))
	  * (("Sender Name" NIL "sender" "example.com"))
	  * (("Sender Name" NIL "recipientuser" "example.org"))
	  * NIL NIL NIL "<526638975.9347.1667870393918@hostname.internal>")
	  *
	  * UID 1)
	  */
	SEEK_HEADER_SINGLE("Date");
	SEEK_HEADER_SINGLE("Subject");
	SEEK_HEADER_MULTIPLE("From");
	SEEK_HEADER_MULTIPLE("Sender");
	SEEK_HEADER_MULTIPLE("Reply-To");
	SEEK_HEADER_MULTIPLE("To");
	SEEK_HEADER_MULTIPLE("Cc");
	SEEK_HEADER_MULTIPLE("Bcc");
	SEEK_HEADER_SINGLE("In-Reply-To");
	SEEK_HEADER_SINGLE("Message-Id");
	fclose(fp);
	SAFE_FAST_COND_APPEND_NOSPACE(response, responselen, *buf, *len, 1, ")");
	return 0;
}

/*! \brief Adjust send offset and size based on partial data request */
static void adjust_send_offset(struct fetch_body_request *fbr, off_t *restrict offset, size_t *restrict sendsize)
{
	int realskip = 0;
	if (fbr->substart != -1) {
		/* sendsize is currently how many bytes are left.
		 * So for this offset to work,
		 * fbr->substart must be at most sendsize, and we
		 * reduce sendsize by fbr->substart bytes. */
		realskip = MIN(fbr->substart, (int) *sendsize);
		*offset += realskip;
		*sendsize -= (size_t) realskip;
	}
	if (fbr->sublength != -1) {
		/* fbr->sublength is an upperbound on the number of bytes to send */
		*sendsize = MIN((size_t) fbr->sublength, *sendsize); /* Can be at most sendsize. */
	}
}

#define send_headers(imap, fbr, itemname, fp, fullname) send_filtered_headers(imap, fbr, itemname, fp, fullname, NULL, 0)

static int send_filtered_headers(struct imap_session *imap, struct fetch_body_request *fbr, const char *itemname, FILE **restrict fp, const char *fullname, const char *headerlist, int filter)
{
	char headersbuf[8192];
	size_t headersbuflen = sizeof(headersbuf);
	char *buf = headersbuf;
	size_t len = headersbuflen;
	char linebuf[1001];
	char listbuf[4096];
	int inside_match = filter ? 0 : 1;
	size_t headerslen;
	char *sendstart;
	size_t sendsize;

	if (filter) {
		size_t headerlistlen;
		if (filter == 1) {
			headerlist += STRLEN("HEADER.FIELDS (");
		} else { /* filter == -1 */
			headerlist += STRLEN("HEADER.FIELDS.NOT (");
		}
		/* stpcpy would be useful here, to copy and compute length in one pass... */
		headerlistlen = strlen(headerlist);
		if (headerlistlen >= sizeof(listbuf) - 2) {
			bbs_error("List of desired headers is too long (%lu)\n", headerlistlen);
		}
		/* Well, now that we checked the length explicitly, strcpy is safe */
		strcpy(listbuf + 1, headerlist); /* Safe */
		/* Replace all the spaces with colons, so they match the format in the message */
		listbuf[0] = ':'; /* Also start with : so we can search for :$HEADERNAME: in the buffer */
		bbs_strreplace(listbuf + 1, ' ', ':');
		/* Also need to replace the trailing ) with : to match the last header.
		 * Rather than a manual loop on both ' ' and ')', it's more efficient to just replace the last one. */
		if (headerlistlen > 0) {
			/* Normally, we'd subtract 1, but we copied into the buffer starting at position 1, so it cancels out */
			listbuf[headerlistlen] = ':';
		}
	}

	/* Read the file until the first CR LF CR LF (end of headers) */
	if (!*fp) {
		*fp = fopen(fullname, "r");
		if (!*fp) {
			bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
			return -1;
		}
	} else {
		rewind(*fp);
	}

	/* The RFC says no line should be more than 1,000 octets (bytes).
	 * Most clients will wrap at 72 characters, but we shouldn't rely on this. */
	while ((fgets(linebuf, sizeof(linebuf), *fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n") || !strcmp(linebuf, "\n")) { /* Some messages include only a LF at end of headers? */
			break; /* End of headers */
		}
		if (filter) {
			/* I have seen headers as crazy long as this:
			 * X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp */
#define MAX_HEADER_NAME_LENGTH 72
			char headername[MAX_HEADER_NAME_LENGTH];
			if (!isspace(linebuf[0])) { /* Continuation of multiline header */
				char *tmp;
				headername[0] = ':';
				safe_strncpy(headername + 1, linebuf, sizeof(headername) - 1);
				tmp = strchr(headername + 1, ':');
				if (!tmp) {
					bbs_warning("Unexpected end of headers: %s\n", linebuf);
					break;
				}
				/* Since safe_strncpy will always null terminate,
				 * it is always safe to null terminate the character after this
				 * (if there wasn't room in the buffer, the character wouldn't be here) */
				*(tmp + 1) = '\0';
				/* Only include headers that were asked for. */
				/* Note that some header names can be substrings of others, e.g. the "To" header should not match for "In-Reply-To"
				 * headerlist contains a list of (space delimited) header names that we can match on, so we can't just use strncmp.
				 * Above, we transform the list into a : delimited list (every header has a : before/after it, including the last one),
				 * so NOW we can just use strstr for :$HEADERNAME:
				 */
				inside_match = (filter == 1 && strcasestr(listbuf, headername)) || (filter == -1 && !strcasestr(listbuf, headername));
			} /* else, append if in match (fall through... will only append if inside_match in macro) */
		}
		/* I hope gcc optimizes this to not use snprintf under the hood */
		SAFE_FAST_COND_APPEND_NOSPACE(headersbuf, headersbuflen, buf, len, inside_match, "%s", linebuf);
	}
	SAFE_FAST_COND_APPEND_NOSPACE(headersbuf, headersbuflen, buf, len, 1, "\r\n"); /* Include CR LF after */
	headerslen = (size_t) (buf - headersbuf);

	/* Leading space, since this is not the first item in the response */
	sendstart = headersbuf;
	sendsize = headerslen;
	if (fbr && fbr->substart != -1) {
		off_t offset = 0;
		bbs_debug(3, "Orig input(%ld): %s\n", sendsize, sendstart);
		adjust_send_offset(fbr, &offset, &sendsize);
		sendstart += offset;
		_imap_reply(imap, " %s<%ld> {%lu}\r\n%s", itemname, offset, sendsize, sendstart);
	} else {
		_imap_reply(imap, " %s {%lu}\r\n%s", itemname, sendsize, sendstart);
	}
	return 0;
}

/* See RFC 3501 6.4.5. */
enum partspec_suffix {
	PARTSPEC_ENTIRE = 0,
	PARTSPEC_MIME,
	PARTSPEC_TEXT,
	PARTSPEC_HEADER,
	PARTSPEC_HEADER_FIELDS,
	PARTSPEC_HEADER_FIELDS_NOT,
};

/*! \brief Similar to send_filtered_headers, but operating on a string rather than a file */
static char *filter_headers_string(char *headers, const char *filter, size_t *restrict partlen, enum partspec_suffix suffix)
{
	char headersbuf[8192]; /* Hopefully, all headers fit in here */
	size_t headerslen = sizeof(headersbuf);
	char *pos = headersbuf;
	size_t left = headerslen;
	char *header;
	int in_match = 0;

	/* Skip to first header name */
	while (*filter && *filter != '(') {
		filter++;
	}
	if (*filter == '(') {
		filter++;
	}

	/* Thankfully, this string is no longer needed afterwards, so we can modify it using strsep for easy parsing */
	while ((header = strsep(&headers, "\r\n"))) {
		if (strlen_zero(header)) { /* Yes, this is necessary... for some reason, every other strsep returns an empty string */
			continue;
		}
		if (suffix == PARTSPEC_HEADER || suffix == PARTSPEC_MIME) {
			in_match = 1;
		} else if (isspace(header[0])) {
			if (!in_match) {
				continue;
			}
		} else {
			char *colon = strchr(header, ':');
			if (!colon) {
				/* Huh? Header name not followed by colon??? */
				continue;
			}
			/* Case-insensitively look for the entire word from header, up to but not including colon.
			 * So that we can use strstr, temporarily augment the colon. */
			*colon = '\0';

			if (strcasestr(filter, header)) {
				/* This doesn't necessarily mean there's match. There are several possible match types:
				 * '(FIRSTHEADER '
				 * '(ONLYHEADER)'
				 * ' MIDDLEHEADER '
				 * ' LASTHEADER)'
				 *
				 * So, we need to do some further checks to be sure.
				 * There is a more efficient way to do this here, but given if we've hit this path,
				 * it's almost always a match anyways, it's not really increasing the runtime (ignoring constants).
				 */
				char filterdup[8192];
				char *fheader, *fheaders;

				bbs_strncpy_until(filterdup, S_IF(filter), sizeof(filterdup), ')'); /* Ignoring opening ( and closing ) */
				fheaders = filterdup;
				/* Now it's space-delimited */
				while ((fheader = strsep(&fheaders, " "))) {
					if (!strcasecmp(header, fheader)) {
						break;
					}
				}
				if (fheader) {
					/* Yes, an exact match for the header was found */
					in_match = suffix == PARTSPEC_HEADER_FIELDS;
				} else {
					in_match = suffix == PARTSPEC_HEADER_FIELDS_NOT;
				}
			} else {
				/* No, header was not found. */
				in_match = suffix == PARTSPEC_HEADER_FIELDS_NOT;
			}

			*colon = ':'; /* Restore */
		}
		/* If it's a match, include it */
		/* Readd CR LF since strsep removed it. But if it's a multiline continuation of a header, don't add CR LF */
		SAFE_FAST_COND_APPEND_NOSPACE(headersbuf, headerslen, pos, left, in_match, "%s%s", pos > headersbuf && !isspace(header[0]) ? "\r\n" : "", header);
	}
	SAFE_FAST_COND_APPEND_NOSPACE(headersbuf, headerslen, pos, left, pos > headersbuf, "\r\n"); /* Line ending for last header, if there was one */
	/* RFC 3501 6.4.5
	 * Subsetting does not exclude the [RFC-2822] delimiting blank line between the header and the body;
	 * the blank line is included in all header fetches, except in the case of a message which has no body and no blank line.
	 *
	 * XXX We assume a body is always present, but technically this should be contingent upon having a body (if we knew that here) */
	SAFE_FAST_COND_APPEND_NOSPACE(headersbuf, headerslen, pos, left, 1, "\r\n");
	/* Now, should have the length */
	*partlen = (size_t) (pos - headersbuf);
	return strndup(headersbuf, *partlen);
}

/*!
 * \brief Parse a part specifier, as defined in RFC 3501 6.4.5
 * \param[out] buf Just the part number prefix of the part specifier
 * \param[in] len Size of buf
 * \param[in] Entire part specifier to parse
 */
static enum partspec_suffix parse_part_spec(char *restrict buf, size_t len, const char *input)
{
	enum partspec_suffix suffix = PARTSPEC_ENTIRE;
	char *tmp;

	safe_strncpy(buf, input, len);

	/* It's either going to be just a part number,
	 * or it's going to have .MIME, .HEADER, or .TEXT (or .HEADER.FIELDS or .HEADER.FIELDS.NOT)
	 * all of which (except .MIME) are only valid for message/rfc822 subparts.
	 * We want to pass just the part number for spec, if there is a modifier.
	 *
	 * Can't use strrchr, since HEADER.FIELDS and HEADER.FIELDS.NOT include commas.
	 * Can't do "ends with str" either, since HEADER.FIELDS and HEADER.FIELDS.NOT take arguments.
	 * Most reliable way is keep parsing the string until we hit something not numeric or a period. */

	tmp = buf;
	while (*tmp && (isdigit(*tmp) || *tmp == '.')) {
		tmp++;
	}

	if (*tmp && tmp > buf) {
		/* We ran out of the numeric portion, terminate here to split the string */
		*(tmp - 1) = '\0';
	}

	if (!strlen_zero(tmp)) {
		if (!strcasecmp(tmp, "MIME")) {
			*tmp = '\0';
			suffix = PARTSPEC_MIME;
		} else if (!strcasecmp(tmp, "TEXT")) {
			*tmp = '\0';
			suffix = PARTSPEC_TEXT;
		} else if (!strcasecmp(tmp, "HEADER")) {
			*tmp = '\0';
			suffix = PARTSPEC_HEADER;
		/* This must be first, since HEADER.FIELDS.NOT also starts with HEADER.FIELDS */
		} else if (STARTS_WITH(tmp, "HEADER.FIELDS.NOT")) {
			*tmp = '\0';
			suffix = PARTSPEC_HEADER_FIELDS_NOT;
		} else if (STARTS_WITH(tmp, "HEADER.FIELDS")) {
			*tmp = '\0';
			suffix = PARTSPEC_HEADER_FIELDS;
		} else if (!strcmp(tmp, ".")) {
			bbs_warning("Malformed part specifier: %s\n", input);
		} else {
			if (!isdigit(*tmp)) {
				bbs_warning("Unknown part specifier: %s\n", input);
			}
		}
	}

	return suffix;
}

/*!
 * \brief Get offset into file at which body starts (after skipping headers)
 * \note This function assumes fp is positioned at beginning of file
 * \return offset at which the body starts
 */
static long int compute_body_offset(FILE *fp)
{
	char linebuf[1001];

	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			/* End of headers... we are now positioned at start of body */
			return ftell(fp);
		}
	}
	return ftell(fp); /* Message has no body? */
}

#define BOTH 0
#define HEADERS_ONLY 1
#define BODY_ONLY 2

/*! \brief Send only the body (no headers) */
static ssize_t send_message(struct imap_session *imap, struct fetch_body_request *fbr, const char *item, FILE **restrict fp, size_t *restrict size, const char *fullname, int sendmask)
{
	size_t sendsize;
	off_t offset = 0;

	if (!*fp) {
		*fp = fopen(fullname, "r");
		if (!*fp) {
			bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
			return -1;
		}
	}
	if (!*size) {
		/* First time, compute size of message */
		fseek(*fp, 0L, SEEK_END); /* EOF */
		*size = (size_t) ftell(*fp);
		rewind(*fp); /* Be kind, rewind */
		if (!*size) {
			bbs_warning("File size of %s is %ld bytes?\n", fullname, *size);
		}
		bbs_debug(3, "File size of %s is %ld\n", fullname, *size);
	}

	if (sendmask == BODY_ONLY) {
		offset = compute_body_offset(*fp);
		sendsize = *size - (size_t) offset;
	} else if (sendmask == HEADERS_ONLY) {
		offset = compute_body_offset(*fp);
		sendsize = (size_t) offset;
	} else {
		sendsize = *size;
	}

	if (fbr && fbr->substart != -1) {
		adjust_send_offset(fbr, &offset, &sendsize);
		/* Format is described in RFC 3501 7.4.2: BODY[<section>]<<origin octet>>
		 * We only include the starting octet, not the length.
		 * Client must assume truncation may have occured. */
		_imap_reply(imap, " %s<%ld> {%ld}\r\n", item, offset, sendsize);
	} else {
		_imap_reply(imap, " %s {%ld}\r\n", item, sendsize);
	}

	/* We must manually tell it the offset or it will be at the EOF, even with rewind() */
	return bbs_sendfile(imap->node->wfd, fileno(*fp), &offset, sendsize);
}

static int send_part(struct imap_session *imap, struct fetch_body_request *fbr, struct bbs_mime_message **restrict mime, const char *fullname)
{
	char *part, *partstart;
	size_t partlen = 0;
	char partnumber[128];
	enum partspec_suffix suffix;
	enum mime_part_filter filter;
	char *tmp;

	/* Part specification, which could be just a part number, but not necessarily, e.g.
	 * 1, 2, 2.1, 2.1.MIME are all valid.
	 *
	 * RFC 3501 6.4.5 sums it up concisely:
	 *
	 * The HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT, and TEXT part
	 * specifiers can be the sole part specifier or can be prefixed by
	 * one or more numeric part specifiers, provided that the numeric
	 * part specifier refers to a part of type MESSAGE/RFC822.  The
	 * MIME part specifier MUST be prefixed by one or more numeric
	 * part specifiers.
	 *
	 * In other words, keep the following 4 things in mind:
	 * - MIME only needs to be handled in this code block, not as a bodyarg by itself.
	 * - Any part spec can end in .MIME
	 * - Any message/rfc822 subpart can end in .HEADER, .TEXT (as shown in the RFC 3501 6.4.5 example),
	 *   as well as .HEADER.FIELDS (header1 header2 ...), .HEADER.FIELDS.NOT (header 1 header2 ...).
	 * - A request for just HEADER, TEXT, HEADER.FIELDS, or HEADER.FIELDS.NOT is already handled
	 *   as a bodyarg by itself, here we just need to handle these as a suffix of a part number.
	 */
	suffix = parse_part_spec(partnumber, sizeof(partnumber), fbr->bodyarg);
	if (!*mime) {
		*mime = bbs_mime_message_parse(fullname);
		if (!*mime) {
			return -1;
		}
	}

	/* We'll handle HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT, and TEXT (all the message/rfc822 specific stuff)
	 * here in net_imap, since that's not really in the scope of what mod_mimeparse is for.
	 * However, MIME is something that mod_mimeparse is well-equipped to do for us already,
	 * and since it's so small compared to an entire part, it'd be kind of wasteful to allocate the whole thing
	 * when we don't need all of that.
	 * As such, if the part specifier is only for .MIME, then filter appropriately to get just that. */
	switch (suffix) {
		case PARTSPEC_ENTIRE:
			filter = MIME_PART_FILTER_ALL;
			break;
		case PARTSPEC_MIME:
			filter = MIME_PART_FILTER_MIME;
			break;
		case PARTSPEC_HEADER:
		case PARTSPEC_HEADER_FIELDS:
		case PARTSPEC_HEADER_FIELDS_NOT:
			/* These part specifiers are only legal if the subpart is of type message/rfc822 */
			filter = MIME_PART_FILTER_HEADERS;
			break;
		case PARTSPEC_TEXT:
			/* This part specifier is only legal if the subpart is of type message/rfc822 */
			filter = MIME_PART_FILTER_TEXT;
			break;
	}

	part = bbs_mime_get_part(*mime, partnumber, &partlen, filter);
	if (!part) {
		_imap_reply(imap, " %s[%s] {0}\r\n", "BODY", fbr->bodyarg);
		return 0;
	}

	switch (suffix) {
		case PARTSPEC_HEADER:
			/* Remove the trailing line endings from HEADER response */
			tmp = part + partlen - 1;
			while (tmp > part && (*tmp == '\r' || *tmp == '\n')) {
				*tmp-- = '\0';
				partlen--;
			}
			/* Use filter_headers_string to properly combine multiline headers onto a single line for response. */
			/* Fall through. */
		case PARTSPEC_MIME: /* Force multiline header continuations onto the same line */
		case PARTSPEC_HEADER_FIELDS:
		case PARTSPEC_HEADER_FIELDS_NOT:
			/* Some post-processing is now required, since we need
			 * to eliminate any headers that don't match the filter in fbr->bodyarg
			 * While we do already have code to look for HEADER.FIELDS and HEADER.FIELDS.NOT
			 * in the entire message, that operates by scanning over a file,
			 * while here we need to scan over a string. So similar logic to send_filtered_headers, but separate function. */
			tmp = filter_headers_string(part, fbr->bodyarg, &partlen, suffix);
			/* Swap it out */
			free(part);
			part = tmp;
			break;
		case PARTSPEC_TEXT:
		case PARTSPEC_ENTIRE:
			/* No post-processing required */
			break;
	}

	partstart = part;
	if (fbr->substart != -1) {
		off_t offset = 0;
		adjust_send_offset(fbr, &offset, &partlen);
		partstart += offset;
		_imap_reply(imap, " %s[%s]<%ld> {%ld}\r\n", "BODY", fbr->bodyarg, offset, partlen);
	} else {
		_imap_reply(imap, " %s[%s] {%ld}\r\n", "BODY", fbr->bodyarg, partlen);
	}

	if (!strlen_zero(partstart)) {
		bbs_node_fd_write(imap->node, imap->node->wfd, partstart, partlen);
	}

	free(part);
	return 0;
}

/*!
 * \brief Finalize and send the FETCH response
 * \note Most simple items are already prepared prior to calling this function.
 *       Anything to do with fetch_body_request or the body itself is handled here.
 * \param imap
 * \param fetchreq
 * \param seqno Sequence number of the message
 * \param fullname Full path to message file
 * \param[in] response Argument 1 to SAFE_FAST_COND_APPEND. Actual entire buffer.
 * \param[in] responselen Argument 2 to SAFE_FAST_COND_APPEND. Total size of buffer.
 * \param[in] buf Argument 3 to SAFE_FAST_COND_APPEND. Current buffer head for next write.
 * \param[in] len Argument 4 to SAFE_FAST_COND_APPEND. Amount of buffer remaining.
 */
static int process_fetch_finalize(struct imap_session *imap, struct fetch_request *fetchreq, int seqno, const char *fullname, char *response, size_t responselen, char **buf, int *len)
{
	struct fetch_body_request *fbr;
	FILE *fp = NULL;
	size_t size = 0;
	int res = 0;
	struct bbs_mime_message *mime = NULL; /* For BODYSTRUCTURE/BODY[]/BODY.PEEK[] operations that need the MIME message */

	/* There are a few important things to keep in mind in this function:
	 *
	 * 1. response is a large (but not infinite) temporary buffer that can be used to build up most (but not all)
	 *    of the FETCH response.
	 *    It's explicitly NOT suitable for large, variable responses, like the body or any part of the body.
	 *
	 * 2. It is desirable, to the extent that is easily possible, to minimize the number of system calls
	 *    that write to the connection, both to reduce system call overhead and also to reduce the total
	 *    number of packets sent.
	 *    Because it is often easier to write directly to the node (especially when impractical to use the fixed-size buffer),
	 *    we employ TCP_CORK to temporarily "hold" the data in the kernel and unbuffer it all at once.
	 *    TCP_CORK will keep data in the kernel until a full packet of data is present or we manually remove it.
	 *
	 * 3. The IMAP session must remain locked atomically throughout the entire function.
	 *    We thus must take care to avoid functions that lock the session for us.
	 *
	 * 4. imap_send must be avoided, since it adds CR LF and logs the entire payload.
	 *    We do sometimes use imap_send_nocrlf or _imap_reply, if we want to log it, but anytime we send a potentially long payload,
	 *    this MUST NOT be logged (and thus, we use bbs_node_fd_write instead).
	 *
	 * 5. It isn't obvious from reading the RFC, but BODY.PEEK is only used in client commands. It is not used in server responses.
	 *    We always reply with BODY[... even when the client sent BODY.PEEK[...
	 */

#define CLEANUP_IF_NULL(x) if (!x) { res = -1; goto cleanup; }

	bbs_mutex_lock(&imap->lock);
	bbs_node_cork(imap->node, 1); /* Cork the TCP session */

	/* Do as much as possible before we even start the reply, to minimize number of writes */
	if (fetchreq->rfc822header) {
		send_headers(imap, NULL, "RFC822.HEADER", &fp, fullname);
	}
	if (fetchreq->body || fetchreq->bodystructure) {
		char *bodystructure;
		/* BODY is BODYSTRUCTURE without extensions (which we don't send anyways, in either case) */
		/* Excellent reference for BODYSTRUCTURE: http://sgerwk.altervista.org/imapbodystructure.html */
		if (!mime) {
			mime = bbs_mime_message_parse(fullname);
			CLEANUP_IF_NULL(mime);
		}
		bodystructure = bbs_mime_make_bodystructure(mime);
		if (!strlen_zero(bodystructure)) {
			SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "%s %s", fetchreq->bodystructure ? "BODYSTRUCTURE" : "BODY", bodystructure);
			free(bodystructure);
		}
	}

	imap_send_nocrlf(imap, /* Start the IMAP response, and ensure no CR LF is automatically added. */
		"* %d " /* Number after FETCH is always a message sequence number, not UID, even if usinguid */
		"FETCH (%s", seqno, response); /* No closing paren, we do that at the very end */

	/* Now, send anything that could be a large, variable amount of data.
	 * All of these will use a format literal / multiline response */
	if (fetchreq->rfc822) { /* Same as BODY[] */
		send_message(imap, NULL, "RFC822", &fp, &size, fullname, BOTH);
	}
	if (fetchreq->rfc822header) {
		send_message(imap, NULL, "RFC822.HEADER", &fp, &size, fullname, HEADERS_ONLY);
	}
	if (fetchreq->rfc822text) { /* Same as BODY[TEXT] */
		send_message(imap, NULL, "RFC822.TEXT", &fp, &size, fullname, BODY_ONLY);
	}
	RWLIST_TRAVERSE(&fetchreq->bodyfetches, fbr, entry) {
		if (strlen_zero(fbr->bodyarg)) { /* Empty (e.g. BODY.PEEK[] or BODY[] */
			send_message(imap, fbr, "BODY[]", &fp, &size, fullname, BOTH);
		} else if (!strcasecmp(fbr->bodyarg, "TEXT")) {
			send_message(imap, fbr, "BODY[TEXT]", &fp, &size, fullname, BODY_ONLY);
		} else if (isdigit(*fbr->bodyarg)) {
			int part_number = atoi(fbr->bodyarg);
			if (part_number == 0) {
				/* BODY[0] (or BODY.PEEK[0]) = ([RFC-822] header of the message) MULTIPART/MIXED
				 * Thunderbird-based clients may fall back to this if they are unsatisfied with
				 * the response to a request for BODY.PEEK[HEADER]
				 * This usage was obsoleted in IMAP4rev1, RFC 2060 Appendix B.10:
				 * "Body part number 0 has been obsoleted."
				 * We have to go back to RFC 1730 6.4.5, IMAP4, to get the definition of this.
				 *
				 * In practice, when I've seen this fallback happen, it usually means
				 * the client didn't like our original response to BODY.PEEK[HEADER],
				 * and since we just do the same thing here, it's unlikely to like that either.
				 * This phenomenon is thus probably symptomatic of a bug somewhere...
				 * for that reason, log a warning here for now.
				 *
				 * Furthermore, most IMAP servers don't seem to support this with IMAP4rev1
				 * (after all, it isn't in the IMAPrev1 spec). Most of them treat it as a bad command.
				 */
				bbs_warning("Requesting headers using part number 0 was obsoleted in IMAP4rev1\n");
				send_message(imap, fbr, "BODY[0]", &fp, &size, fullname, HEADERS_ONLY);
			} else {
				if (send_part(imap, fbr, &mime, fullname)) {
					res = -1;
					goto cleanup;
				}
			}
		/* If sending all headers, we don't need to combine multiline headers onto a single line,
		 * pure passthrough works correctly.
		 * Surprisingly, this seems to be true for HEADER.FIELDS and HEADER.FIELDS.NOT too (at this level).
		 * For subparts (within send_part), it's different. */
		} else if (!strcasecmp(fbr->bodyarg, "HEADER")) { /* e.g. BODY.PEEK[HEADER] */
			send_headers(imap, fbr, "BODY[HEADER]", &fp, fullname);
		} else if (STARTS_WITH(fbr->bodyarg, "HEADER.FIELDS")) {
			char itemname[1024];
			snprintf(itemname, sizeof(itemname), "%s[%s]", "BODY", fbr->bodyarg);
			send_filtered_headers(imap, fbr, itemname, &fp, fullname, fbr->bodyarg, 1);
		} else if (STARTS_WITH(fbr->bodyarg, "HEADER.FIELDS.NOT")) {
			char itemname[1024];
			snprintf(itemname, sizeof(itemname), "%s[%s]", "BODY", fbr->bodyarg);
			send_filtered_headers(imap, fbr, itemname, &fp, fullname, fbr->bodyarg, -1);
		} else {
			bbs_warning("Unknown FETCH BODY item: %s\n", fbr->bodyarg);
		}
	}

	if (bbs_node_fd_writef(imap->node, imap->node->wfd, ")\r\n") < 0) { /* And the finale (don't use imap_send for this either) */
		res = -1;
	}

cleanup:
	bbs_node_cork(imap->node, 0); /* Uncork the node, to ensure data is fully written */
	if (mime) {
		bbs_mime_message_destroy(mime);
	}
	if (fp) {
		fclose(fp);
	}
	bbs_mutex_unlock(&imap->lock);
	return res;
}

/*! \brief Get beginning of keyword letters in a filename, if present */
static const char *keywords_start(const char *restrict filename)
{
	const char *flagstr = strchr(filename, ':');
	if (!flagstr++) {
		return NULL;
	}
	/* Skip 2, before flags */
	while (*flagstr == '2' || *flagstr == ',') {
		flagstr++;
	}
	while (isupper(*flagstr)) {
		flagstr++;
	}
	return flagstr;
}

static int mark_seen(struct imap_session *imap, int seqno, const char *fullname, const char *filename)
{
	int newflags;
	/* I haven't actually encountered many clients that will actually hit this path...
	 * most clients peek everything and then explicitly mark as seen,
	 * rather than using the BODY[] item which implicitly marks as seen during processing.
	 * Seems to be a common safety precaution to avoid implicitly marking something as read if some client or server side issue crops up.
	 */
	if (parse_flags_letters_from_filename(filename, &newflags, NULL)) { /* Don't care about custom keywords */
		bbs_error("File %s is noncompliant with maildir\n", filename);
		return -1;
	}

	/* If not already seen, mark as unseen */
	if (!(newflags & FLAG_BIT_SEEN)) {
		char newflagletters[256];
		const char *keywords;
		bbs_debug(6, "Implicitly marking message as seen\n");
		newflags |= FLAG_BIT_SEEN;
		/* Generate flag letters from flag bits */
		gen_flag_letters(newflags, newflagletters, sizeof(newflagletters));

		/* No point in parsing the existing keywords only to convert them back and append.
		 * Just copy over from filename directly. */
		keywords = keywords_start(filename);

		if (!strlen_zero(keywords)) {
			bbs_append_string(newflagletters, keywords, sizeof(newflagletters) - 1);
		}
		maildir_msg_setflags_notify(imap, seqno, fullname, newflagletters);
	}
	return 0;
}

static int process_fetch(struct imap_session *imap, int usinguid, struct fetch_request *fetchreq, const char *sequences, int tagged)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int seqno = 0;
	int error = 0;
	int fetched = 0;

	/* use scandir instead of opendir/readdir since we need ordering, even for message sequence numbers */
	files = scandir(imap->curdir, &entries, NULL, imap_uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", imap->curdir, strerror(errno));
		return -1;
	}

	if (fetchreq->vanished) { /* First, send any VANISHED responses if needed */
		char *uidrangebuf = malloc(strlen(sequences) + 1);
		if (uidrangebuf) {
			/* Since VANISHED is only with UID FETCH, the sequences are in fact UID sequences, perfect! */
			char *expunged = maildir_get_expunged_since_modseq(imap->curdir, fetchreq->changedsince, uidrangebuf, 0, sequences);
			free(uidrangebuf);
			imap_send(imap, "VANISHED (EARLIER) %s", S_IF(expunged));
			free_if(expunged);
		}
	}

	while (fno < files && (entry = entries[fno++])) {
		char response[8192];
		char *buf = response;
		int len = sizeof(response);
		unsigned int msguid;
		unsigned long modseq = 0;
		char fullname[516];
		int markseen, recent;

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}
		msguid = imap_msg_in_range(imap, ++seqno, entry->d_name, sequences, usinguid, &error);
		if (!msguid) {
			goto cleanup;
		}
		if (fetchreq->changedsince) {
			if (parse_modseq_from_filename(entry->d_name, &modseq)) {
				goto cleanup;
			}
			if (modseq <= fetchreq->changedsince) {
#ifdef EXTRA_DEBUG
				bbs_debug(5, "modseq %lu older than CHANGEDSINCE %lu\n", modseq, fetchreq->changedsince);
#endif
				goto cleanup; /* Older than specified CHANGEDSINCE */
			}
		}
		/* At this point, the message is a match. Fetch everything we're supposed to for it. */
		snprintf(fullname, sizeof(fullname), "%s/%s", imap->curdir, entry->d_name);

		/* Must include UID in response, whether requested or not (so fetchreq->uid ignored) */
		SAFE_FAST_COND_APPEND(response, sizeof(response), buf, len, 1, "UID %u", msguid);

		/* We need to include the updated flags in the reply, if we're marking as seen, so check this first.
		 * However, for, reasons, we'd prefer not to rename the file while we're doing stuff in the loop body.
		 * The maildir_msg_setflags API doesn't currently provide us back with the new renamed filename.
		 * So what we do is check if we need to mark as seen, but not actually mark as seen until the END of the loop.
		 * Consequently, we have to append the seen flag to the flags response manually if needed. */
		markseen = fetchreq->nopeek || fetchreq->rfc822text;

		/* We don't store the \Recent flag anywhere, it's a computed flag.
		 * \Recent corresponds to messages that were in the new directory (as opposed to cur)
		 * at the time that the mailbox was selected (EXAMINE and STATUS do not move messages out of new, so \Recent is unchanged by these).
		 * When we do the traversal, we note the lowest # sequence numbered message that was in the new directory,
		 * as well as the highest.
		 * Then later, when we do a FETCH, we can send the \Recent flag if the sequence number of the message falls in this window.
		 * However, I think after a message is fetched, a message should no longer really be considered "Recent".
		 * However, this implementation would consider the messages that were recent at selection-time recent
		 * until the mailbox is re-selected.
		 * Only one client should consider a message Recent, since subsequent clients will not find these messages in
		 * the new dir at selection time. So it does still mostly work as expected, and the RFC also says if we're not
		 * sure if a message is recent, to consider it recent, so there is nothing definitively wrong with the approach taken here.
		 * Importantly, messages that were not Recent at the time the mailbox was selected will never be considered Recent.
		 */
		recent = (unsigned int) seqno >= imap->minrecent && (unsigned int) seqno <= imap->maxrecent;
		if (fetchreq->flags && process_fetch_flags(imap, entry->d_name, markseen, recent, response, sizeof(response), &buf, &len)) {
			goto cleanup;
		}
		if (fetchreq->rfc822size && process_fetch_size(entry->d_name, response, sizeof(response), &buf, &len)) {
			goto cleanup;
		}
		if (fetchreq->modseq && process_fetch_modseq(entry->d_name, response, sizeof(response), &buf, &len, &modseq)) {
			goto cleanup;
		}
		if (fetchreq->internaldate && process_fetch_internaldate(fullname, response, sizeof(response), &buf, &len)) {
			goto cleanup;
		}
		if (fetchreq->envelope && process_fetch_envelope(fullname, response, sizeof(response), &buf, &len)) {
			goto cleanup;
		}

		/* Handle the header/body stuff and actually send the response. */
		if (process_fetch_finalize(imap, fetchreq, seqno, fullname, response, sizeof(response), &buf, &len)) {
			goto cleanup;
		}
		if (markseen && IMAP_HAS_ACL(imap->acl, IMAP_ACL_SEEN)) {
			mark_seen(imap, seqno, fullname, entry->d_name); /* No need to goto cleanup if we fail, we do anyways */
		}

		fetched++;

cleanup:
		free(entry);
	}
	free(entries);
	if (!fetched) {
		bbs_debug(6, "FETCH command did not return any matching results\n");
	}
	if (tagged) {
		if (error) {
			imap_reply(imap, "BAD Invalid saved search");
		} else {
			imap_reply(imap, "OK %sFETCH Completed", usinguid ? "UID " : "");
		}
	}
	return 0;
}

static int parse_body_tail(struct fetch_body_request *fbr, char *s)
{
	char *tmp;

	if (strlen_zero(s)) {
		return -1;
	}
	tmp = strchr(s, ']');
	if (!tmp) {
		return -1;
	}
	*tmp++ = '\0';
	if (!strlen_zero(tmp)) { /* Something like <0.2048> is leftover. */
		char *a, *b;
		if (*tmp++ != '<') {
			return -1;
		}
		b = tmp;
		a = strsep(&b, ".");
		if (strlen_zero(a)) {
			return -1;
		}
		fbr->substart = atoi(a); /* Can be 0 (to start from the beginning) */
		if (fbr->substart < 0) {
			return -1;
		}
		if (!strlen_zero(b)) {
			/* This is the maximum number of octets desired */
			fbr->sublength = atol(b); /* cannot be 0 (or negative) */
			if (fbr->sublength <= 0) {
				return -1;
			}
		} else {
			fbr->sublength = -1;
		}
	}
	return 0;
}

/*! \note Only non-static so net_imap.c can unit test this */
char *fetchitem_sep(char **s)
{
	int in_bracket = 0;
	/* Can't use strsep, since a single token could be multiple words. */
	char *cur, *begin = *s;

	if (!*s) {
		return NULL;
	}

	cur = begin;
	while (*cur) {
		if (*cur == '[') {
			in_bracket = 1;
		} else if (*cur == ']') {
			if (in_bracket) {
				in_bracket = 0;
				/* Keep going, there might be <> components afterwards
				 * e.g. BODY[]<0.2048> */
			} else {
				bbs_warning("Malformed FETCH request item string: %s\n", *s);
			}
		} else if (*cur == ' ') {
			if (!in_bracket) {
				break; /* Found the end */
			}
		}
		cur++;
	}

	*s = *cur ? cur + 1 : cur; /* If we got to the end, next item will be NULL, otherwise eat the space */
	if (*cur) {
		*cur = '\0'; /* Null terminate the previous string here */
	}

	if (strlen_zero(begin)) {
		return NULL; /* Empty string = nothing left */
	}

	return begin;
}

int handle_fetch_full(struct imap_session *imap, char *s, int usinguid, int tagged)
{
	char *sequences;
	char *items, *item;
	struct fetch_request fetchreq;
	struct fetch_body_request *fbr;
	int res = 0;

	REQUIRE_ARGS(s);
	sequences = strsep(&s, " "); /* Messages, specified by sequence number or by UID (if usinguid) */
	REQUIRE_ARGS(s); /* What remains are the items to select */

	/* Could be sequence numbers/UIDs, or '$' for saved search */
	if (strlen_zero(sequences) || (!atoi(sequences) && strcmp(sequences, "$"))) {
		imap_reply(imap, "BAD Missing message numbers");
		return 0;
	}

	/* Remove the surrounding parentheses for parsing */
	/* Because of CONDSTORE, multiple parenthesized arguments are supported,
	 * e.g. s100 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 12345)
	 * So the correct way to parse here should be to count the ( and ), adding +1 and -1 respectively,
	 * until we get back to 0, and then stop.
	 */
	if (*s == '(') {
		items = parensep(&s);
	} else {
		items = s; /* Parentheses optional for just a single item */
		s = NULL;
	}

	memset(&fetchreq, 0, sizeof(fetchreq));

	if (!strlen_zero(s)) {
		/* Another parenthesized list? (Probably CHANGEDSINCE, nothing else is supported) */
		char *arg;
		s = parensep(&s);
		while ((arg = strsep(&s, " "))) {
			if (!strcasecmp(arg, "CHANGEDSINCE")) {
				arg = strsep(&s,  " ");
				REQUIRE_ARGS(arg);
				fetchreq.changedsince = (unsigned long) atol(arg);
				fetchreq.modseq = 1; /* RFC 7162 3.1.4.1: CHANGEDSINCE implicitly sets MODSEQ FETCH message data item */
				imap->condstore = 1;
			} else if (!strcasecmp(arg, "VANISHED")) {
				fetchreq.vanished = 1;
			} else {
				bbs_warning("Unexpected FETCH modifier: %s\n", s);
				imap_reply(imap, "BAD FETCH failed. Illegal arguments.");
				goto cleanup;
			}
		}
		/* RFC 7162 3.2.6 */
		if (fetchreq.vanished) {
			if (!usinguid) {
				imap_reply(imap, "BAD Must use UID FETCH, not FETCH");
				goto cleanup;
			} else if (!imap->qresync) {
				imap_reply(imap, "BAD Must enabled QRESYNC first");
				goto cleanup;
			} else if (!fetchreq.changedsince) {
				imap_reply(imap, "BAD Must use in conjunction with CHANGEDSINCE");
				goto cleanup;
			}
		}
		
	}

	/* Only parse the request once. */
	while ((item = fetchitem_sep(&items))) {
		char *tmp;
		if (!strcmp(item, "BODY")) {
			/* Same as BODYSTRUCTURE, basically */
			fetchreq.body = 1;
		} else if (!strcmp(item, "BODYSTRUCTURE")) {
			fetchreq.bodystructure = 1;
		} else if (STARTS_WITH(item, "BODY[") || STARTS_WITH(item, "BODY.PEEK[")) {
			/* Leave just the contents inside the [] */
			fbr = calloc(1, sizeof(*fbr));
			if (ALLOC_FAILURE(fbr)) {
				res = -1;
				goto cleanup;
			}
			if (STARTS_WITH(item, "BODY.PEEK[")) {
				fbr->peek = 1;
			} else {
				fetchreq.nopeek = 1;
			}
			tmp = item + (fbr->peek ? STRLEN("BODY.PEEK[") : STRLEN("BODY["));
			fbr->substart = -1; /* Initialize to -1 */
			if (parse_body_tail(fbr, tmp)) {
				bbs_warning("Failed to parse partial fetch directive: %s\n", tmp);
				res = -1;
				free(fbr);
				goto cleanup;
			}
			fbr->bodyarg = tmp; /* Make assignment after, since this is a const char */
			RWLIST_INSERT_TAIL(&fetchreq.bodyfetches, fbr, entry);
		} else if (!strcmp(item, "ENVELOPE")) {
			fetchreq.envelope = 1;
		} else if (!strcmp(item, "FLAGS")) {
			fetchreq.flags = item;
		} else if (!strcmp(item, "INTERNALDATE")) {
			fetchreq.internaldate = 1;
		} else if (!strcmp(item, "RFC822")) { /* Technically deprecated nowadays, in favor of BODY[], but clients still use it */
			/* Same as BODY[], basically */
			fetchreq.rfc822 = 1;
		} else if (!strcmp(item, "RFC822.HEADER")) {
			/* Same as BODY.PEEK[HEADER], basically */
			fetchreq.rfc822header = 1;
		} else if (!strcmp(item, "RFC822.SIZE")) {
			fetchreq.rfc822size = 1;
		} else if (!strcmp(item, "RFC822.TEXT")) {
			/* Same as BODY[TEXT], basically */
			fetchreq.rfc822text = 1;
		} else if (!strcmp(item, "UID")) {
			fetchreq.uid = 1;
		} else if (!strcmp(item, "MODSEQ")) {
			fetchreq.modseq = 1;
		/* Special macros, defined in RFC 3501. They must only be used by themselves, which makes their usage easy for us. Just expand them. */
		} else if (!strcmp(item, "ALL")) { /* FLAGS INTERNALDATE RFC822.SIZE ENVELOPE */
			fetchreq.flags = item;
			fetchreq.internaldate = 1;
			fetchreq.rfc822size = 1;
			fetchreq.envelope = 1;
			break;
		} else if (!strcmp(item, "FAST")) { /* FLAGS INTERNALDATE RFC822.SIZE */
			fetchreq.flags = item;
			fetchreq.internaldate = 1;
			fetchreq.rfc822size = 1;
			break;
		} else if (!strcmp(item, "FULL")) { /* FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY */
			fetchreq.flags = item;
			fetchreq.internaldate = 1;
			fetchreq.rfc822size = 1;
			fetchreq.envelope = 1;
			fetchreq.body = 1;
			break;
		} else {
			bbs_warning("Unsupported FETCH item: %s\n", item);
			imap_reply(imap, "BAD FETCH failed. Illegal arguments.");
			goto cleanup;
		}
	}

	/* Process the request, for each message that matches sequence number. */
	res = process_fetch(imap, usinguid, &fetchreq, sequences, tagged);

cleanup:
	while ((fbr = RWLIST_REMOVE_HEAD(&fetchreq.bodyfetches, entry))) {
		free(fbr);
	}
	return res;
}
