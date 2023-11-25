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

static int process_fetch_rfc822header(const char *fullname, char *response, size_t responselen, char **buf, int *len,
	char *headers, size_t headerslen, int unoriginal, size_t *bodylen)
{
	FILE *fp;
	char linebuf[1001];
	char *headpos = headers;
	size_t headlen = headerslen;

	/* Read the file until the first CR LF CR LF (end of headers) */
	fp = fopen(fullname, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
		return -1;
	}
	/* The RFC says no line should be more than 1,000 octets (bytes).
	 * Most clients will wrap at 72 characters, but we shouldn't rely on this. */
	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
		/* I hope gcc optimizes this to not use snprintf under the hood */
		SAFE_FAST_COND_APPEND_NOSPACE(headers, headerslen, headpos, headlen, 1, "%s", linebuf);
	}
	fclose(fp);
	*bodylen = (size_t) (headpos - headers); /* XXX cheaper than strlen, although if truncation happened, this may be wrong (too high). */
	if (!unoriginal) {
		SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "RFC822.HEADER");
	}
	return 0;
}

static int process_fetch_finalize(struct imap_session *imap, struct fetch_request *fetchreq, int seqno, const char *fullname, char *response, size_t responselen, char **buf, int *len)
{
	char headers[10000] = ""; /* XXX Large enough for all headers, etc.? Better might be sendfile, no buffering */
	char rangebuf[32] = "";
	int multiline = 0;
	size_t bodylen = 0;
	int sendbody = 0;
	int skipheaders = 0;
	int unoriginal = 0; /* BODY[HEADER] or BODY.PEEK[HEADER], rather than RFC822.HEADER, and the type has already been appended to the buffer. */
	FILE *fp = NULL;
	char *dyn = NULL;
	/* For BODY and BODY.PEEK: */
	int peek = fetchreq->bodypeek ? 1 : 0; /* NOT whether we are peeking the message, this is purely if it's BODY.PEEK vs. BODY */
	int body = fetchreq->bodyargs || fetchreq->bodypeek; /* One of BODY or BODY.PEEK ? */
	const char *bodyargs = peek ? fetchreq->bodypeek : fetchreq->bodyargs;

	/* BODY or BODY.PEEK (RFC 3501 6.4.5)
	 * format is BODY[section]<partial>
	 * section = 0+ part specifiers:
	 * - HEADER: all headers
	 * - HEADER.FIELDS: only the specified headers
	 * - HEADER.FIELDS.NOT: only those headers that don't match the provided list
	 * - MIME: MIME header for this part
	 * - TEXT: body (not including headers)
	 * - If empty, it's the entire message (including headers)
	 * partial = substring in a.b format (a = position of first octet, b = max # of octets to fetch)
	 * - Note: BODY[]<0.2048> of a 1500-octet message will be returned as BODY[]<0>, not BODY[]
	 * - Substrings should be supported for HEADER.FIELDS and HEADER.FIELDS.NOT too!
	 */

	/* HEADER.FIELDS involves a multiline response, so this should be processed at the end of this loop since it appends to response.
	 * Otherwise, something else might concatenate itself on at the end and break the response. */
	if (body) {
		/* Can be HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT, MIME, TEXT */
		char linebuf[1001];
		char *headpos = headers;
		int headlen = sizeof(headers);

		if (!strcmp(bodyargs, "HEADER")) { /* e.g. BODY.PEEK[HEADER] */
			/* Just treat it as if we got a HEADER request directly, to send all the headers. */
			unoriginal = 1;
			SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, 1, "%s", peek ? "BODY.PEEK[HEADER]" : "BODY[HEADER]");
			fetchreq->rfc822header = 1;
			fetchreq->bodyargs = fetchreq->bodypeek = NULL; /* Don't execute the if statement below, so that we can execute the else if */
		} else if (STARTS_WITH(bodyargs, "HEADER.FIELDS") || STARTS_WITH(bodyargs, "HEADER.FIELDS.NOT")) {
			/* e.g. BODY[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To Received)] */
			char *headerlist, *tmp;
			int inverted = 0;
			int in_match = 0;
			multiline = 1;
			if (STARTS_WITH(bodyargs, "HEADER.FIELDS.NOT")) {
				inverted = 1;
				bodyargs += STRLEN("HEADER.FIELDS.NOT (");
			} else {
				bodyargs += STRLEN("HEADER.FIELDS (");
			}
			/* Read the file until the first CR LF CR LF (end of headers) */
			fp = fopen(fullname, "r");
			if (!fp) {
				bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
				return -1;
			}
			headerlist = malloc(strlen(bodyargs) + 2); /* Add 2, 1 for NUL and 1 for : at the beginning */
			if (ALLOC_FAILURE(headerlist)) {
				fclose(fp);
				return -1;
			}
			headerlist[0] = ':';
			strcpy(headerlist + 1, bodyargs); /* Safe */
			tmp = headerlist + 1; /* No need to check the first byte as it's already a :, so save a CPU cycle by skipping it */
			while (*tmp) {
				if (*tmp == ' ' || *tmp == ')') {
					*tmp = ':';
				}
				tmp++;
			}
			/* The RFC says no line should be more than 1,000 octets (bytes).
			 * Most clients will wrap at 72 characters, but we shouldn't rely on this. */
#define MAX_HEADER_NAME_LENGTH 72
			while ((fgets(linebuf, sizeof(linebuf), fp))) {
				/* I have seen headers as crazy long as this:
				 * X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp */
				char headername[MAX_HEADER_NAME_LENGTH];
				/* fgets does store the newline, so line should end in CR LF */
				if (!strcmp(linebuf, "\r\n") || !strcmp(linebuf, "\n")) { /* Some messages include only a LF at end of headers? */
					break; /* End of headers */
				}
				if (isspace(linebuf[0])) { /* It's part of a previous header (mutliline header) */
					SAFE_FAST_COND_APPEND_NOSPACE(headers, sizeof(headers), headpos, headlen, in_match, "%s", linebuf); /* Append if in match */
					continue;
				}
				headername[0] = ':';
				safe_strncpy(headername + 1, linebuf, sizeof(headername) - 1); /* Don't copy the whole line. XXX This assumes that no header name is longer than MAX_HEADER_NAME_LENGTH chars. */
				tmp = strchr(headername + 1, ':');
				if (!tmp) {
					bbs_warning("Unexpected end of headers: %s\n", linebuf);
					break;
				}
				/* Since safe_strncpy will always null terminate, it is always safe to null terminate the character after this */
				*(tmp + 1) = '\0';
				/* Only include headers that were asked for. */
				/* Note that some header names can be substrings of others, e.g. the "To" header should not match for "In-Reply-To"
				 * bodyargs contains a list of (space delimited) header names that we can match on, so we can't just use strncmp.
				 * Above, we transform the list into a : delimited list (every header has a : after it, including the last one),
				 * so NOW we can just use strstr for :NAME:
				 */
				if ((!inverted && strcasestr(headerlist, headername)) || (inverted && !strcasestr(headerlist, headername))) {
					/* I hope gcc optimizes this to not use snprintf under the hood */
					SAFE_FAST_COND_APPEND_NOSPACE(headers, sizeof(headers), headpos, headlen, 1, "%s", linebuf);
					in_match = 1;
				} else {
					in_match = 0;
				}
			}
			fclose(fp);
			free(headerlist);
			bodylen = strlen(headers); /* Can't just subtract end of headers, we'd have to keep track of bytes added on each round (which we probably should anyways) */

			/* bodyargs ends in a ')', so don't tack an additional one on afterwards */
			/* Here, the condition will only be true for one or the other: */
			SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, !inverted, "BODY[HEADER.FIELDS (%s]", bodyargs);
			SAFE_FAST_COND_APPEND(response, responselen, *buf, *len, inverted, "BODY[HEADER.FIELDS.NOT (%s]", bodyargs);
		} else if (!strcmp(bodyargs, "TEXT")) { /* Empty (e.g. BODY.PEEK[] or BODY[], or TEXT */
			multiline = 1;
			sendbody = 1;
			skipheaders = 1;
		} else if (!strcmp(bodyargs, "MIME")) {
			bbs_error("MIME is currently unsupported!\n"); /*! \todo Support it */
		} else if (!strcmp(bodyargs, "")) { /* Empty (e.g. BODY.PEEK[] or BODY[], or TEXT */
			multiline = 1;
			sendbody = 1;
		} else {
			bbs_warning("Invalid BODY argument: %s\n", bodyargs);
		}
	}
	if (fetchreq->rfc822header) { /* not a else if, because it could have just been set true. */
		multiline = 1;
		if (process_fetch_rfc822header(fullname, response, responselen, buf, len, headers, sizeof(headers), unoriginal, &bodylen)) {
			return -1;
		}
	}

	/* Actual body, if being sent, should be last */
	if (fetchreq->rfc822 || fetchreq->rfc822text) {
		multiline = 1;
		sendbody = 1;
	}

	if (fetchreq->body || fetchreq->bodystructure) {
		/* BODY is BODYSTRUCTURE without extensions (which we don't send anyways, in either case) */
		/* Excellent reference for BODYSTRUCTURE: http://sgerwk.altervista.org/imapbodystructure.html */
		/* But we just use the top of the line gmime library for this task (see https://stackoverflow.com/a/18813164) */
		dyn = mime_make_bodystructure(fetchreq->bodystructure ? "BODYSTRUCTURE" : "BODY", fullname);
	}

	if (multiline) {
		/* {D} tells client this is a multiline response, with D more bytes remaining */
		long size, fullsize;
		skipheaders |= (fetchreq->rfc822text && !fetchreq->rfc822); /* Other conditions in which we skip sending headers */
		if (sendbody) {
			ssize_t res;
			char resptype[48];
			off_t offset;
			fp = fopen(fullname, "r");
			if (!fp) {
				bbs_error("Failed to open %s: %s\n", fullname, strerror(errno));
				return -1;
			}
			fseek(fp, 0L, SEEK_END); /* Go to EOF */
			fullsize = size = ftell(fp);
			rewind(fp); /* Be kind, rewind */
			if (!size) {
				bbs_warning("File size of %s is %ld bytes?\n", fullname, size);
			}

			/* XXX Assumes not sending headers and bodylen at same time.
			 * In reality, I think that *might* be fine because the body contains everything,
			 * and you wouldn't request just the headers and then the whole body in the same FETCH. */
			if (bodylen) {
				bbs_error("Can't send body and headers simultaneously!\n");
			}
			offset = 0;
			if (skipheaders) { /* Only body. No headers. */
				char linebuf[1001];
				/* XXX Refactor so we can just get the offset to body start via function call */
				while ((fgets(linebuf, sizeof(linebuf), fp))) {
					/* fgets does store the newline, so line should end in CR LF */
					offset += (off_t) strlen(linebuf); /* strlen includes CR LF already */
					if (!strcmp(linebuf, "\r\n")) {
						break; /* End of headers */
					}
				}
				size -= offset;
			}

			if (fetchreq->sublength) {
				int realskip = 0;
				if (fetchreq->substart) {
					/* size is currently how many bytes are left.
					 * So for this offset to work,
					 * fetchreq->substart must be at most size, and we
					 * reduce size by fetchreq->substart bytes. */
					realskip = MIN(fetchreq->substart, (int) size);
					offset += realskip;
					size -= realskip;
				}
				size = MIN(fetchreq->sublength, size); /* Can be at most size. */
				/* Format is described in RFC 3501 7.4.2: BODY[<section>]<<origin octet>>
				 * We only include the starting octet, not the length.
				 * Client must assume truncation may have occured. */
				snprintf(rangebuf, sizeof(rangebuf), "<%d>", realskip);
			}

			/* If request used RFC822, use that. If it used BODY, use BODY */
			snprintf(resptype, sizeof(resptype), "%s%s", fetchreq->rfc822 ? "RFC822" : fetchreq->rfc822text ? "RFC822.TEXT" : skipheaders ? "BODY[TEXT]" : "BODY[]", rangebuf);

			imap_send(imap, "%d FETCH (%s%s%s %s {%ld}", seqno, S_IF(dyn), dyn ? " " : "", response, resptype, size); /* No close paren here, last write will do that */

			pthread_mutex_lock(&imap->lock);
			res = bbs_sendfile(imap->wfd, fileno(fp), &offset, (size_t) size); /* We must manually tell it the offset or it will be at the EOF, even with rewind() */
			bbs_node_fd_writef(imap->node, imap->wfd, ")\r\n"); /* And the finale (don't use imap_send for this) */
			pthread_mutex_unlock(&imap->lock);

			fclose(fp);
			if (res == (ssize_t) size) {
				imap_debug(5, "Sent %ld/%ld-byte body for %s\n", res, fullsize, fullname); /* either partial or entire body */
			}
		} else {
			const char *headersptr = headers;
			if (fetchreq->sublength) {
				int realskip = 0;
				if (fetchreq->substart) {
					realskip = MIN(fetchreq->substart, (int) bodylen);
					headersptr += realskip;
					bodylen -= (size_t) realskip;
				}
				bodylen = MIN((size_t) fetchreq->sublength, bodylen);
				snprintf(rangebuf, sizeof(rangebuf), "<%d>", realskip);
			}
			imap_send(imap, "%d FETCH (%s%s%s%s {%lu}\r\n%s)", seqno, S_IF(dyn), dyn ? " " : "", response, rangebuf, bodylen, headersptr);
		}
	} else {
		/* Number after FETCH is always a message sequence number, not UID, even if usinguid */
		imap_send(imap, "%d FETCH (%s%s%s)", seqno, S_IF(dyn), dyn ? " " : "", response); /* Single line response */
	}

	free_if(dyn);
	return 0;
}

/*! \brief Get beginning of keyword letters in a filename, if present */
static const char *keywords_start(const char *restrict filename)
{
	const char *flagstr = strchr(filename, ':');
	if (!flagstr++) {
		return NULL;
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
		char response[1024];
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
		markseen = (fetchreq->bodyargs && !fetchreq->bodypeek) || fetchreq->rfc822text;

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

static int parse_body_tail(struct fetch_request *fetchreq, char *s)
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
		if (strlen_zero(a) || strlen_zero(b)) {
			return -1;
		}
		fetchreq->substart = atoi(a); /* Can be 0 (to start from the beginning) */
		if (fetchreq->substart < 0) {
			return -1;
		}
		fetchreq->sublength = atol(b); /* cannot be 0 (or negative) */
		if (fetchreq->sublength <= 0) {
			return -1;
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

	REQUIRE_ARGS(s);
	sequences = strsep(&s, " "); /* Messages, specified by sequence number or by UID (if usinguid) */
	REQUIRE_ARGS(s); /* What remains are the items to select */

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
				return 0;
			}
		}
		/* RFC 7162 3.2.6 */
		if (fetchreq.vanished) {
			if (!usinguid) {
				imap_reply(imap, "BAD Must use UID FETCH, not FETCH");
				return 0;
			} else if (!imap->qresync) {
				imap_reply(imap, "BAD Must enabled QRESYNC first");
				return 0;
			} else if (!fetchreq.changedsince) {
				imap_reply(imap, "BAD Must use in conjunction with CHANGEDSINCE");
				return 0;
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
		} else if (STARTS_WITH(item, "BODY[")) {
			/* Leave just the contents inside the [] */
			tmp = item + STRLEN("BODY[");
			if (parse_body_tail(&fetchreq, tmp)) {
				return -1;
			}
			fetchreq.bodyargs = tmp; /* Make assignment after, since this is a const char */
		} else if (STARTS_WITH(item, "BODY.PEEK[")) {
			tmp = item + STRLEN("BODY.PEEK[");
			if (parse_body_tail(&fetchreq, tmp)) {
				return -1;
			}
			fetchreq.bodypeek = tmp;
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
			return 0;
		}
	}

	/* Process the request, for each message that matches sequence number. */
	return process_fetch(imap, usinguid, &fetchreq, sequences, tagged);
}
