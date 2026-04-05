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
 * \brief Telocator Alphanumeric Protocol (TAP), Version 1.8
 *
 * \note Sometimes known as IXO
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <stdarg.h>
#include <ctype.h> /* use isspace for rtrim */

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/keys.h"
#include "include/user.h"
#include "include/paging.h"
#include "include/stringlist.h"
#include "include/test.h"

#include "include/mod_asterisk_ami.h"

/* Uncomment to improve reliability with poor-quality phone lines (e.g. VoIP)
 * Note that this is still kind of a work in progress, and should help a little,
 * but may not be enough if the connection is bad enough. */
#define SUPPORT_LOW_QUALITY_PHONE_CONNECTIONS

/* Uncomment to debug messaging with hex dumps */
/* #define DEBUG_TAP */

#define MAX_CHECKSUM_FAILURES_PER_TRANSACTION 3
#define MAX_PAGES_PER_SESSION 10
#define MAX_SESSION_SECS 180
#define MAX_FIELDS 16

/* This is a TAP protocol limit, not a paging provider limit.
 * The paging provider may have a stricter limit. */
#define MAX_MESSAGE_LENGTH 768

/* Define this to automatically truncate long messages and send them,
 * rather than reject messages that are too long. */
/* #define AUTO_TRUNCATE */

static int tap_port = 0; /* No default */
static int taps_port = 0; /* No default */

static char session_name_buf[64] = "";
static const char *ami_session = NULL; /* Default is NULL (the default/first session in mod_asterisk_ami.conf) */
static char dial_context[80] = ""; /* This size matches AST_MAX_CONTEXT from Asterisk */
static char softmodem_args[128] = "";

/*
 * Security implications:
 * The TCP port used by the system does not need to be publicly accessible,
 * to ensure any uses of this protocol are via an approved modem connection.
 * This allows the phone system to handle screening of calls, if needed.
 */

struct tap_session {
	struct bbs_node *node;
	struct readline_data rldata;
	time_t started;
	unsigned int num_pages_sent; 	/*!< Number of num_pages_sent transactions */
	unsigned int outgoing:1;		/*!< Outgoing session (rather than incoming) */
};

#ifdef DEBUG_TAP
#define tap_write_and_log(line, func, tap, dirstr, s, len) ({ \
	__bbs_log(LOG_DEBUG, 3, __FILE__, line, func, "TAP %s %.*s\n", dirstr, (int) len, s); \
	bbs_dump_mem((unsigned const char*) s, (size_t) len); \
	bbs_node_fd_write(tap->node, tap->node->wfd, s, len) < 0 ? -1 : 0; \
})
#else
#define tap_write_and_log(line, func, tap, dirstr, s, len) ({ \
	__bbs_log(LOG_DEBUG, 3, __FILE__, line, func, "TAP %s %.*s\n", dirstr, (int) len, s); \
	bbs_node_fd_write(tap->node, tap->node->wfd, s, len) < 0 ? -1 : 0; \
})
#endif

#define tap_write(tap, s, len) tap_write_and_log(__LINE__, __func__, tap, "response <=", s, len)

static int __attribute__ ((format (gnu_printf, 5, 6))) tap_writef(int line, const char *func, struct tap_session *tap, const char *dirstr, const char *fmt, ...)
{
	char buf[256];
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return tap_write_and_log(line, func, tap, dirstr, buf, (size_t) len);
}

#define TAP_SEND(tap, s) if (tap_write(tap, s, STRLEN(s)) < 0) { goto cleanup; }

/* The code + optional message (which can be multi-line, CR separated) comprise a message sequence */
/* Do not include trailing CR in message, if provided, we add it here */
#define TAP_REPLY(tap, code, message, disp) if (tap_writef(__LINE__, __func__, tap, "response <=", "%d%s%s\r%s", code, !strlen_zero(message) ? " " : "", message, disp) < 0) { goto cleanup; }
#define TAP_OUTGOING_SEND(tap, str) if (tap_writef(__LINE__, __func__, tap, "=>", "%s", str) < 0) { goto cleanup; }
#define TAP_OUTGOING_SEND_FMT(tap, fmt, ...) if (tap_writef(__LINE__, __func__, tap, "=>", fmt, ## __VA_ARGS__) < 0) { goto cleanup; }

#define CHAR_STX '\002'
#define CHAR_ETX '\003'
#define CHAR_EOT '\004'
#define CHAR_ETB '\027'
#define CHAR_SUB '\032'
#define CHAR_US '\037'

/*! \brief OK, continue */
#define RESPONSE_OK "\006\r" /* ACK CR */
#define NO_CR_RESPONSE_OK "\006"

/*! \brief Resend */
#define RESPONSE_SEND_AGAIN "\025\r" /* NAK CR */
#define NO_CR_RESPONSE_SEND_AGAIN "\025"

/*! \brief Abandon current transaction and continue */
#define RESPONSE_ABANDON "\036\r" /* RS CR */
#define NO_CR_RESPONSE_ABANDON "\036"

/*! \brief Begin disconnect */
#define RESPONSE_DISCONNECT "\033\004\r" /* ESC EOT CR */
#define NO_CR_RESPONSE_DISCONNECT "\033\004"

#define TIMER_T1 2
#define TIMER_T2 1
#define TIMER_T3 10
#define TIMER_T4 4
#define TIMER_T5 8

#define RETRY_N1 3
/* RETRY_N2 is 3, but not used in this implementation */
#define RETRY_N3 3

#define READ_LINE(tap, timer, retries) \
	res = read_with_retries(tap, timer, retries); \
	if (res < 0) { \
		goto abort; \
	}

#define read_with_retries(tap, timer, retries) __read_with_retries(__LINE__, __func__, tap, "\r", timer, retries)
#define read_with_retries_delim(tap, timer, retries, delim) __read_with_retries(__LINE__, __func__, tap, delim, timer, retries)

/*!
 * \internal
 * \retval -2 if bbs_node_readline returned -2 or -3 (fatal error)
 * \retval -1 Full line not read (delimiter not encountered)
 * \returns Number of bytes in line, as returned by bbs_node_readline
 */
static int __read_with_retries(int line, const char *func, struct tap_session *tap, const char *delim, int timeout, int retries_allowed)
{
	int retries;
	for (retries = 0; retries < retries_allowed; retries++) {
		ssize_t res = __bbs_node_readline(__FILE__, line, func, tap->node, &tap->rldata, delim, SEC_MS(timeout));
		if (res < -1) {
			return -2;
		}
		if (res == -1) {
			__bbs_log(LOG_DEBUG, 2, __FILE__, line, func, "Attempt %d/%d: No input received from TAP %s\n", retries + 1, retries_allowed, tap->outgoing ? "terminal" : "entry device");
			continue;
		}
#ifdef DEBUG_TAP
		bbs_dump_mem((unsigned const char*) tap->rldata.buf, (size_t) res);
#endif
		return (int) res;
	}
	if (retries_allowed > 1) {
		__bbs_log(LOG_DEBUG, 2, __FILE__, line, func, "Max retries (%d) exceeded\n", retries_allowed);
	}
	return -1;
}

/*! \brief Whether this field is incomplete (to be continued in the next block) */
static int is_partial_field(const char *s, int len)
{
	const char *us;

	if (len < 4) {
		/* If the line we read was less than 4 characters,
		 * then it must be a complete field, because if the field
		 * continued in the next block, we'd need at least <US> <CHECKSUM> */
		return 0;
	}
	us = s + len - 4;
	if (*us != CHAR_US) {
		return 0; /* Can't be a partial field if US isn't in this position */
	}
	if (len > 4 && *(us - 1) == CHAR_SUB) {
		/* We found US, but it's preceded by SUB, so it's "escaped" (a form of byte stuffing, if you will).
		 * That means, it's not a real US, and therefore it can't be a partial field. */
		return 0;
	}
	return 1;
}

static int contains_illegal_chars(const unsigned char *s, int len)
{
	int i;
	for (i = 0; i < len; i++, s++) {
		/* The spec allows control characters < x20 with control transparency, but we specifically
		 * disallow NUL from being in messages to avoid complications with C strings. */
		if (!*s || *s > 0x7F) {
			bbs_debug(3, "Detected illegal character %d at line[%d]\n", *s, i);
			return 1;
		}
	}
	return 0;
}

static int arithmetic_sum(const char *s)
{
	int c = 0;
	while (*s) {
		c += *s++;
	}
	return c;
}

static int arithmetic_sum_len(const char *s, int len)
{
	int i, c = 0;
	for (i = 0; i < len; i++) {
		c += *s++;
	}
	return c;
}

/* CR isn't present in the string, but we need to include it in the checksum */
#define arithmetic_sum_cr(s) (arithmetic_sum(s) + '\r')

#define CHECKSUM_BUFSIZ 4

static void calc_checksum(int sum, char *restrict checksum)
{
	/* Null terminate the checksum buffer before starting, since we fill the buffer in starting at the end */
	checksum += 3;
	*checksum-- = '\0';

	/* Numeric checksum is least 12 bits of the arithmetic sum of all 7-bit values preceding in block */
	/* Next, each 4 bits gets added to 48 (0x30) to become an ASCII character */
	/* This is based on the BASIC reference in the specification */
	*checksum-- = (char) (48 + sum - (sum / 16) * 16);
	sum /= 16;
	*checksum-- = (char) (48 + sum - (sum / 16) * 16);
	sum /= 16;
	*checksum = (char) (48 + sum - (sum / 16) * 16);
}

static int test_checksum(void)
{
	/* This example comes from the TAP spec */
	char checksum[CHECKSUM_BUFSIZ];
	int sum;

	sum = 0;
	sum += arithmetic_sum_cr("\002123"); /* <ETX> 123 <CR> */
	sum += arithmetic_sum_cr("ABC"); /* ABC <CR> */
	sum += CHAR_ETX;
	bbs_test_assert_equals(sum, 379);
	calc_checksum(sum, checksum);
	bbs_test_assert_str_equals(checksum, "17;");

	return 0;

cleanup:
	return -1;
}

static char *combine_fields_to_string(struct stringlist *fields)
{
	struct dyn_str dstr;
	char *s;

	memset(&dstr, 0, sizeof(dstr));
	while ((s = stringlist_pop(fields))) {
		dyn_str_append_fmt(&dstr, "%s\r\n", S_IF(s));
	}
	return dstr.buf;
}

static int process_page(struct tap_session *tap, struct stringlist *messages, const char *number)
{
	int res = -1;
	struct bbs_paging_recipient recip;
	struct bbs_paging_data data;
	struct bbs_paging_message_metadata meta;
	char *pagerid = NULL, *body = NULL;
	size_t msglen;
	int truncated = 0;

	/* Typically, the recipient is in field 1, and the message is any subsequent fields */
	pagerid = stringlist_pop(messages);
	if (strlen_zero(pagerid)) {
		/* No pager ID? */
		TAP_REPLY(tap, 515, "Missing pager ID", RESPONSE_ABANDON);
		return -1;
	}
	if (stringlist_is_empty(messages)) {
		/* Got a pager ID but no message? */
		TAP_REPLY(tap, 515, "Missing body", RESPONSE_ABANDON);
		return -1;
	}

	if (stringlist_size(messages) > 1) {
		body = combine_fields_to_string(messages); /* Concatenate whatever fields remain together */
		/* Fields can be empty (e.g. for tone only paging) */
		if (!strlen_zero(body) && !strcmp(body, "\r\n")) {
			free(body);
			body = NULL;
		}
	} else {
		char *str;
		size_t oldlen;
		/* This is the common case, and considerably more efficient */
		body = stringlist_pop(messages);
		/* We just need to add CR LF at the end */
		oldlen = strlen(body);
		str = realloc(body, oldlen + 3); /* CR LF NUL */
		if (str) {
			strcpy(str + oldlen, "\r\n"); /* Safe */
		} else {
			free(body);
			TAP_REPLY(tap, 512, "Temporary system error", RESPONSE_SEND_AGAIN);
			return -1;
		}
		body = str;
	}

	bbs_debug(6, "Pager ID '%s', body '%s'\n", pagerid, S_IF(body));

	msglen = strlen(S_IF(body));
#ifdef AUTO_TRUNCATE
	if (msglen > MAX_MESSAGE_LENGTH) {
		body[msglen] = '\0'; /* Chop it off right at the limit */
		msglen = MAX_MESSAGE_LENGTH;
		truncated = 1;
	}
#endif
	if (msglen > MAX_MESSAGE_LENGTH) {
		TAP_REPLY(tap, 517, XSTR(MAX_MESSAGE_LENGTH) " character maximum, message rejected", RESPONSE_ABANDON);
		goto cleanup;
	}

	/* Marshal our arguments into the paging structures (there ain't much here, though!) */
	memset(&recip, 0, sizeof(recip));
	recip.pagerid = pagerid;
	memset(&data, 0, sizeof(data));
	data.body = body;
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	data.callerid = (char*) number; /* This isn't allocated, so we don't need to free it later */
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
	data.node = tap->node;

	res = bbs_page_single(&recip, &data, &meta);

	if (res) {
		switch (errno) {
			case ENOENT:
				TAP_REPLY(tap, 511, "Invalid Pager ID", RESPONSE_ABANDON);
				break;
			case EAGAIN:
			case ECHILD:
				TAP_REPLY(tap, 512, "Temporary delivery failure, retry later", RESPONSE_ABANDON);
				break;
			case EACCES: /* Pager requires a PIN, which TAP 1.8 does not support (but SNPP does) */
				TAP_REPLY(tap, 513, "Pager is restricted", RESPONSE_ABANDON);
				break;
			case EINVAL:
				TAP_REPLY(tap, 510, "Illegal Pager ID", RESPONSE_ABANDON);
				break;
			case EDOM:
				TAP_REPLY(tap, 504, "Tone-only pager, no message allowed", RESPONSE_ABANDON);
				break;
			case ERANGE:
				TAP_REPLY(tap, 505, "Numeric paging only, no alphabetic characters allowed", RESPONSE_ABANDON);
				break;
			case EMSGSIZE:
				TAP_REPLY(tap, 513, "Long message rejected, exceeds max character length", RESPONSE_ABANDON);
				break;
			case EDQUOT:
				TAP_REPLY(tap, 516, "Message quota temporarily exceeded", RESPONSE_ABANDON);
				break;
			default:
				TAP_REPLY(tap, 512, "Other Failure", RESPONSE_ABANDON);
		}
	} else {
		if (truncated) {
			TAP_REPLY(tap, 214, XSTR(MAX_MESSAGE_LENGTH) " character max, message truncated and sent", RESPONSE_OK);
		} else {
			if (!(meta.status & PAGE_DELIVERED)) {
				TAP_REPLY(tap, 213, "Message Accepted, Deferred Delivery", RESPONSE_OK);
			} else {
				TAP_REPLY(tap, 211, "Page Accepted", RESPONSE_OK);
			}
		}
	}
	res = 0;

cleanup:
	/* Free after so we don't mess with errno */
	free_if(pagerid);
	free_if(data.body);
	return res;
}

static int validate_password(struct tap_session *tap, const char *password)
{
	/* We don't require passwords, we don't even know who this is, so it would be difficult to know what passwords to accept.
	 * However, abort if we receive an overly long password (that is possibly the message instead, by mistake). */
	if (!strlen_zero(password)) {
		if (strlen(password) > 16) {
			TAP_REPLY(tap, 509, "Invalid password", RESPONSE_DISCONNECT);
			return -1;
		}
		bbs_debug(5, "Ignoring password '%s'\n", password);
	}
	return 0;

cleanup:
	return -1;
}

static void undo_control_transparency(char *s)
{
	char *o = s;

	while (*s) {
		if (*s == 0x1A) { /* SUB */
			s++;
			if (!*s) {
				break;
			}
			*o++ = (char) ((*s++) - 0x40);
		} else {
			*o++ = *s++;
		}
	}
	*o = '\0';
}

/*!
 * \internal
 * \brief Receive a single transaction
 * \param tap
 * \param number Caller ID number
 * \retval 0 if transaction finished, proceed
 * \retval -1 on fatal error or if EOT received, go ahead and disconnect
 */
static int receive_transaction(struct tap_session *tap, const char *number)
{
	struct stringlist messages, blockmessages;
	int started_block = 0;
	int corrupted = 0, abandon = 0;
	int num_checksum_failures = 0, num_format_errors = 0;
	int running_sum = 0;
	int partial_len = 0;
	char *partial_str = NULL;
	int field_num = 1;
	int retval = -1;

	/* A "block" is up to 256 chars (250 info chars,  3 control chars, 3-char checksum)
	 * A block carries one transaction (one set of fields 1... N) OR a portion of one transaction.
	 * Blocks begin with STX and end with a checksum + CR.
	 * Fields may be any length, and may be continued in succeeding blocks.
	 * No limit is imposed by the protocol on the number of transactions, fields, or blocks;
	 * however, systems may impose these limits.
	 *
	 * Any character <= DEL (x7F) may be included.
	 * Characters < x20 must be indicated using control transparency
	 *   The control byte is converted -> SUB (x1A) + (char + x40)
	 *
	 * Each field ends with CR.
	 * Block termination character immediately preceding checksum:
	 *   - ETX: transaction (fields 1...N) ends in this block
	 *   - ETB: transaction continued into next block, but last field is complete
	 *   - US = field continues in next block (and consequently, no CR prior to checksum)
	 *
	 * e.g.
	 *
	 * <STX>
	 * Field 1 <CR>
	 * Field 2 <CR>
	 * ...
	 * Field L <US> <CHECKSUM> <CR>
	 *
	 * <STX>
	 * Field L cont. <CR>
	 * Field M <CR>
	 * <ETB> <CHECKSUM> <CR>
	 *
	 * <STX>
	 * Field N <CR>
	 * ...
	 * Field X <CR>
	 * <ETX> <CHECKSUM> <CR>
	 */

	stringlist_init(&messages);
	stringlist_init(&blockmessages);

	/* Read all the blocks, saving all the fields into a string list */
	for (;;) {
		const char *line;
		int res;
		if (field_num > MAX_FIELDS) {
			/* All right, this is getting ridiculous.
			 * Too long, go ahead and disconnect. */
			TAP_REPLY(tap, 506, "Too many fields received", RESPONSE_DISCONNECT);
			break;
		}
		res = read_with_retries(tap, TIMER_T4, 1);
		if (res < 0) {
			corrupted = 1;
			if (res == -1) { /* if -2, already disconnected, if -1, just timed out */
				TAP_REPLY(tap, 501, "Timeout", RESPONSE_DISCONNECT);
			}
			break;
		}
		line = tap->rldata.buf;
		if (!started_block) {
			if (res == 1 && line[0] == CHAR_EOT) {
				/* End of transmission, no more remaining */
				TAP_REPLY(tap, 115, "Goodbye", RESPONSE_DISCONNECT);
				break;
			}
			if (line[0] != CHAR_STX) {
				bbs_dump_string(line);
				TAP_REPLY(tap, 502, "Unexpected start of transaction", RESPONSE_SEND_AGAIN);
				break;
			}
			if (tap->num_pages_sent > MAX_PAGES_PER_SESSION) {
				TAP_REPLY(tap, 112, "Session expired", RESPONSE_DISCONNECT);
				break;
			} else if (time(NULL) - tap->started > MAX_SESSION_SECS) {
				TAP_REPLY(tap, 113, "Session expired", RESPONSE_DISCONNECT);
				break;
			}
			if (line[0] != '\0') {
				/* Don't index into possibly uninitialized memory if we got an
				 * empty field at the start of a block, for whatever reason. */
				line++;
				res--;
				running_sum += CHAR_STX; /* Since we incremented line, we won't include this later, add it now */
			}
			started_block = 1;
		}
		if (!corrupted && contains_illegal_chars((const unsigned char*) line, res)) {
			corrupted = 1;
		}

#define CHECK_CHECKSUM(calculated, received) \
	if (strcmp(checksum, received)) { \
		bbs_warning("Checksum mismatch: '%s' != '%s'\n", received, checksum); \
		checksum_error = 1; \
	}

		if (line[0] == CHAR_ETX || line[0] == CHAR_ETB) {
			int checksum_error = 0;
			char checksum[CHECKSUM_BUFSIZ];
			/* End of transmission or end of block */
			bbs_debug(3, "Received end of %s\n", line[0] == CHAR_ETX ? "transmission" : "block");
			running_sum += line[0]; /* ETB or ETX is the last byte included in the checksum */
			if (res != 4) {
				bbs_warning("Received end of %s, but line length is %d?\n", line[0] == CHAR_ETX ? "transmission" : "block", res);
				corrupted = 1;
				break;
			}
			if (!corrupted) { /* If it's already known to be corrupted, don't bother, we stopped calculating the running sum anyways, so we can't */
				calc_checksum(running_sum, checksum);
				/* Checksum is the next 3 characters */
				CHECK_CHECKSUM(checksum, line + 1);
			}
			if (line[0] == CHAR_ETX) {
				/* If we're at the end of the transmission, there should be no partial field lingering */
				if (partial_str) {
					bbs_warning("Received unterminated field?\n");
					corrupted = 1;
					FREE(partial_str);
				}
			}
			if (checksum_error) {
				if (num_checksum_failures++ > MAX_CHECKSUM_FAILURES_PER_TRANSACTION) {
					TAP_REPLY(tap, 503, "Excessive checkum errors", RESPONSE_DISCONNECT);
					break;
				} else {
					TAP_REPLY(tap, 514, "Checksum error", RESPONSE_SEND_AGAIN);
				}
			} else if (corrupted) {
				if (num_format_errors++ > MAX_CHECKSUM_FAILURES_PER_TRANSACTION) {
					TAP_REPLY(tap, 506, "Excessive invalid pages", RESPONSE_DISCONNECT);
					break;
				} else {
					TAP_REPLY(tap, 515, "Format error", RESPONSE_SEND_AGAIN);
				}
			} else {
				if (line[0] == CHAR_ETB) {
					TAP_REPLY(tap, 211, "Accepted", RESPONSE_OK); /* XXX Right response if just one block for partial transaction? */
				} else {
					stringlist_merge(&messages, &blockmessages); /* Merge the last block in, and now we have the full message */
					if (!process_page(tap, &messages, number)) { /* process_page replies with the response */
						tap->num_pages_sent++;
					}
				}
			}
			if (line[0] == CHAR_ETB) {
				/* End of Block. Reset some variables for the next block. */
				running_sum = 0;
				if (corrupted || abandon) {
					stringlist_empty(&blockmessages); /* Discard all fields received for this block */
				} else {
					/* If this block was received completely,
					 * then we can move the fields from our
					 * temporary list to the main one. */
					stringlist_merge(&messages, &blockmessages);
				}
				/* If corrupted, ask sender to resend last block.
				 * Otherwise, if we need to abandon, inform sender of failure but move to next transmission (system rule violated) */
				continue;
			} else {
				bbs_debug(3, "Transmission completed\n");
				retval = 0;
				break; /* We're done with this entire transmission */
			}
		}
		if (corrupted || abandon) {
			/* If we're corrupted or going to abandon this transaction, ignore everything else we receive until end of transmission */
			bbs_debug(4, "Ignoring received line (corrupted=%d, abandon=%d)\n", corrupted, abandon);
			continue;
		}

		/* Read a single field (which may be empty)
		 * In most cases, each line that we read corresponds to a field.
		 * For fields that span multiple blocks, however,
		 * we also have the <US> <CHECKSUM> at the end.
		 * So, first, we need to determine if this is a complete field or not. */
		if (is_partial_field(line, res)) {
			int checksum_error = 0;
			char checksum[CHECKSUM_BUFSIZ];
			int plen;
			const char *datastr = line;

			/* If it's a partial field, save what we have so far until we have the full thing. */
			bbs_debug(7, "Received partial field (to be continued in next block)\n");

			/* The checksum is the entire line up to the checksum (so including <US>)
			 * CR isn't present in the output so we go up to last 3. */
			running_sum += arithmetic_sum_len(line, res - 3); /* A ... <US> CHK1 CHK2 CHK3 <CR> */

			calc_checksum(running_sum, checksum);
			/* Checksum is the last 3 characters (CR wasn't returned so last 3 is the checksum) */
			CHECK_CHECKSUM(checksum, line + res - 3);

			if (checksum_error) {
				if (num_checksum_failures++ > MAX_CHECKSUM_FAILURES_PER_TRANSACTION) {
					TAP_REPLY(tap, 503, "Excessive checkum errors", RESPONSE_DISCONNECT);
					break;
				} else {
					TAP_REPLY(tap, 514, "Checksum error", RESPONSE_SEND_AGAIN);
				}
			} else if (corrupted) {
				if (num_format_errors++ > MAX_CHECKSUM_FAILURES_PER_TRANSACTION) {
					TAP_REPLY(tap, 506, "Excessive invalid pages", RESPONSE_DISCONNECT);
					break;
				} else {
					TAP_REPLY(tap, 515, "Format error", RESPONSE_SEND_AGAIN);
				}
			} else {
				TAP_REPLY(tap, 211, "Accepted, Continue", RESPONSE_OK);
			}

			/* End of Block. Reset some variables for the next block. */
			running_sum = 0;

			if (corrupted || abandon) {
				stringlist_empty(&blockmessages); /* Discard all fields received for this block */
				continue;
			}

			/* If it's a partial field, save what we have so far until we have the full thing. */
			plen = res - 4; /* We exclude <US> and the checksum */
			if (line[0] == CHAR_STX) {
				plen--;
				datastr++;
			}
			if (partial_str) {
				/* We already read a partial field, i.e. this is a field that
				 * spans not just 2, but at least 3 or more blocks. */
				char *newstr = realloc(partial_str, (size_t) (partial_len + plen + 1)); /* Old + new + NUL */
				if (ALLOC_FAILURE(newstr)) {
					corrupted = 1;
				} else {
					memcpy(newstr + partial_len, datastr, (size_t) plen); /* Don't use strcpy since we don't want to copy the checksum */
					partial_str = newstr;
					partial_len += plen;
					partial_str[partial_len] = '\0';
				}
			} else {
				partial_str = strndup(datastr, (size_t) plen);
				if (ALLOC_FAILURE(partial_str)) {
					corrupted = 1;
				} else {
					partial_len = plen;
				}
			}
		} else {
			int plen = res;
			const char *datastr = line;
			/* We received the end of the field. */
			running_sum += arithmetic_sum_cr(line); /* We know it contains no NULs or we would've treated it as corrupted */
			if (line[0] == CHAR_STX) {
				plen--;
				datastr++;
			}
			if (partial_str) {
				char *newstr = realloc(partial_str, (size_t) (partial_len + plen + 1)); /* Old + new + NUL */
				if (ALLOC_FAILURE(newstr)) {
					corrupted = 1;
				} else {
					strcpy(newstr + partial_len, datastr); /* Safe */
					partial_str = newstr;
					partial_len += plen;
				}
				/* Now we have the entire field in one string (appended through multiple blocks) */
				undo_control_transparency(partial_str);
				bbs_debug(3, "Field %d: '%s'\n", field_num, partial_str);
				if (stringlist_push_tail_allocated(&blockmessages, partial_str)) {
					corrupted = 1;
					free(partial_str);
				} /* else, on success, the string list is now responsible for freeing it later */
				partial_str = NULL;
			} else {
				char tbuf[257];
				safe_strncpy(tbuf, datastr, sizeof(tbuf));
				undo_control_transparency(tbuf);
				bbs_debug(3, "Field %d: '%s'\n", field_num, tbuf);
				if (stringlist_push_tail(&blockmessages, tbuf)) {
					corrupted = 1;
				}
			}
			field_num++;
		}
	}

cleanup:
	if (partial_str) {
		bbs_warning("Received unterminated field?\n");
		bbs_dump_string(partial_str);
		corrupted = 1;
		FREE(partial_str);
	}

	stringlist_empty_destroy(&blockmessages);
	stringlist_empty_destroy(&messages);
	return retval;
}

static int run_incoming(struct tap_session *tap, const char *number)
{
	char buf[257]; /* Block size is limited to 256, so we'll never need more than that much space at a time */
	const char *password;
	int res, retries;

	/* Step 1: TAP entry device dials TAP terminal (us)
	 * Step 2: Carrier handshake. */

#ifdef DEBUG_TAP
	memset(buf, 0, sizeof(buf)); /* Zero buffer out for debugging in case we print its contents */
#endif
	bbs_readline_init(&tap->rldata, buf, sizeof(buf));

	/* Step 3: The entry device needs to send a CR */
#ifdef SUPPORT_LOW_QUALITY_PHONE_CONNECTIONS
	/* Since this is the first exchange, we are significantly more generous in # of retries here than the spec, to reduce chances of failed synchronization */
	READ_LINE(tap, TIMER_T1 + 3, RETRY_N1 + 2);
#else
	READ_LINE(tap, TIMER_T1, RETRY_N1);
#endif

	/* Step 4: Send ID= within t2 seconds of receiving CR */
	TAP_SEND(tap, "ID=");

	/* Wait for response to ID= */
	for (retries = 0;; retries++) {
		READ_LINE(tap, TIMER_T5, RETRY_N3);
		if (buf[0] != KEY_ESC) { /* Manual Operation */
			/* Step 5M: As long as we get a non-null sequence followed by CR, it's good.
			 * However, we don't support manual mode. */
#ifdef DEBUG_TAP
			/* Sometimes (usually only with poorer quality connections) we end up in this call path and it's not clear why: */
			bbs_dump_mem((unsigned const char*) buf, sizeof(buf));
#endif
#ifdef SUPPORT_LOW_QUALITY_PHONE_CONNECTIONS
			if (retries < 3) {
				if (retries > 1) {
					/* Didn't get what we were looking for, try asking again... */
					TAP_SEND(tap, "ID=");
				}
				continue;
			}
#endif
			TAP_REPLY(tap, 507, "Manual mode not supported", RESPONSE_DISCONNECT);
			goto done;
		}
		break;
	}

	/* Automatic Mode */
	/* Step 5A: Get desired paging service */
	/* SST
	 * SS = paging service, and is 'PG' if sending pager ID + message
	 * T = type of terminal or device sending the message
	 *      1 = only supported value for all devices
	 *      7, 8, 9 = reserved for user-specific devices */
	if (res < 4) {
		TAP_REPLY(tap, 507, "Incorrect login sequence", RESPONSE_DISCONNECT);
		goto done;
	} else if (strncmp(buf + 1, "PG", 2)) {
		TAP_REPLY(tap, 508, "Unsupported service", RESPONSE_DISCONNECT);
		goto done;
	} else if (buf[3] != '1') {
		TAP_REPLY(tap, 508, "Unsupported category", RESPONSE_DISCONNECT);
		goto done;
	}
	/* Optional 6-character alphanumeric password, then CR
	 * Currently, passwords are not supported, so just ignore if one is received.
	 * (Even for pagers with a PIN, this password is for TAP terminal access,
	 *  not for access to a specific pager.)
	 * If an incorrect login sequence is received (typically <ESC>PG1<CR>,
	 * we MAY response with ID= to require retransmission (but we just abort). */
	password = buf + 4;
	if (validate_password(tap, password)) {
		goto done;
	}

	/* Step 6: Accept Login, send within t3 seconds of Step 5 */
	TAP_REPLY(tap, 110, "1.8", RESPONSE_OK); /* TAP version 1.8 */

	/* A message sequence is a series of short messages separated by CR's. A CR always follows a message sequence.
	 * Each message in a message sequence has a 3-digit response code + <SP> prepended to human friendly text. */

	/* Step 6a: Paging terminal (us) MAY insert a message sequence */

	/* Step 7: Send message go ahead, within t3 seconds of Step 6 */
	TAP_SEND(tap, "\033[p\r"); /* ESC [p CR */

	/* Step 8: Receive transaction (within t4 seconds of a response) */
	do {
		res = receive_transaction(tap, number);
	} while (!res);

done:
	bbs_node_safe_sleep(tap->node, SEC_MS(10)); /* Wait for any pending TAP transmission to finish sending before exiting, or softmodem will exit */
	return 0; /* We already responded */

abort: /* Label used if READ_LINE aborts */
	/* If res == -2, error occured (likely user disconnect). If res == -1, timeout occured. */
	if (res == -1) {
		TAP_REPLY(tap, 501, "Timeout", RESPONSE_DISCONNECT);
		bbs_node_safe_sleep(tap->node, SEC_MS(10)); /* Wait for any pending TAP transmission to finish sending before exiting, or softmodem will exit */
	}
cleanup:
	return -1;
}

struct outgoing_call {
	struct bbs_paging_recipient *recipient;
	struct bbs_paging_data *data;
	struct bbs_paging_message_metadata *meta;
	unsigned int outgoing_id;
	RWLIST_ENTRY(outgoing_call) entry;
	unsigned int connected:1;
	unsigned int done:1;
	unsigned int success:1;
};

static RWLIST_HEAD_STATIC(outgoing_calls, outgoing_call);

static void do_control_transparency(char *out, const char *in)
{
	while (*in) {
		if (*in < 0x20) {
			/* Needs control transparency */
			*out++ = 0x1A; /* SUB */
			*out++ = (char) ((*in++) + 0x40);
		} else {
			*out++ = *in++;
		}
	}
	*out = '\0';
}

static int test_control_transparency(void)
{
	char inbuf[256], outbuf[2 * sizeof(inbuf) + 1];

	strcpy(inbuf, "Test\032M\032JTest");
	bbs_dump_string(inbuf);
	undo_control_transparency(inbuf);
	bbs_dump_string(inbuf);
	bbs_test_assert_str_equals(inbuf, "Test\r\nTest");
	do_control_transparency(outbuf, inbuf); /* inbuf = actual payload, outbuf = transparent payload */
	bbs_dump_string(inbuf);
	bbs_dump_string(outbuf);
	bbs_test_assert_str_equals(outbuf, "Test\032M\032JTest"); /* What we started with */

	return 0;

cleanup:
	return -1;
}

/* Reset info bytes to 249, not counting STX itself, since this is only for the info chars */
#define START_BLOCK(tap) \
	TAP_OUTGOING_SEND_FMT(tap, "%c", CHAR_STX); \
	running_sum = CHAR_STX; \
	infobytesleft = 249;

#define TX_FIELD(tap, fmt, ...) \
	len = snprintf(buf, sizeof(buf), fmt, ## __VA_ARGS__); \
	TAP_OUTGOING_SEND_FMT(tap, "%s\r", buf); \
	infobytesleft -= len; \
	running_sum += arithmetic_sum_cr(buf); /* CR is included in checksum, but arithmetic_sum_cr adds that for us */

#define TX_PARTIAL_FIELD(tap, fmt, ...) \
	len = snprintf(buf, sizeof(buf), fmt, ## __VA_ARGS__); \
	TAP_OUTGOING_SEND_FMT(tap, "%.*s\037", len, buf); \
	running_sum += arithmetic_sum(buf) + '\037';

static int send_transaction(struct tap_session *tap, struct outgoing_call *o)
{
	char buf[257];
	char checksum[CHECKSUM_BUFSIZ];
	int len;
	int res;
	int infobytesleft = 0; /* Initialize once here, since START_BLOCK calls TX_FIELD before initializing infobytesleft */
	int running_sum = 0; /* Initialize once here, since START_BLOCK calls TX_FIELD before initializing running_sum */
	int blockno = 1;
	char *bodydup = NULL;
	const char *pagerid = o->recipient->pagerid; /* Field 1 */
	const char *body = S_OR(o->data->body, o->data->message); /* Field 2 (if present) */

	/* We need to handle control transparency, which may involve adding bytes, giving us a size of 2N in the worst case */
	if (body) {
		char *tmp;
		/* The spec recommends eliminating trailing spaces to conserve "over-the-air" transmission time, particularly relevant for email-originated pages */
		ltrim(body); /* body is const, unlike bodydup, so do the ltrim separately, also to avoid adjusting bodydup, since we need to free it later */
		bodydup = malloc(2 * strlen(body) + 1);
		if (ALLOC_FAILURE(bodydup)) {
			return -1;
		}
		do_control_transparency(bodydup, body);
		rtrim(bodydup);

		/* Spaces will be trimmed, but CR and LF are subject to control transparently, so won't be affected by trim operations
		 * Manually trim them. */
		tmp = bodydup;
		while (*tmp) {
			tmp++;
		}
		while (tmp > bodydup + 2 && tmp[-2] == 0x1A && (tmp[-1] == 'M' || tmp[-1] == 'J')) {
			tmp[-2] = '\0';
			tmp -= 2;
		}

		body = bodydup;
	}

	/* This is more or less a simplified and inverted version of receive_transaction
	 * We only have 1 or 2 fields, but if the payload is longer than 250 info chars,
	 * we may need to split up field 2 across multiple blocks */

	/* A reminder, for convenience:
	 *
	 * <STX>
	 * Field 1 <CR>
	 * Field 2 <CR>
	 * ...
	 * Field L <US> <CHECKSUM> <CR>
	 *
	 * <STX>
	 * Field L cont. <CR>
	 * Field M <CR>
	 * <ETB> <CHECKSUM> <CR>
	 *
	 * <STX>
	 * Field N <CR>
	 * ...
	 * Field X <CR>
	 * <ETX> <CHECKSUM> <CR>
	 */

	START_BLOCK(tap); /* Start block 1 */
	TX_FIELD(tap, "%s", pagerid); /* Send field 1 */
	/* Now, we begin field 2 (if we have a body)
	 * It may need to be split across multiple fields */
	if (!strlen_zero(body)) {
		int bodyleft = (int) strlen(body);
		while (bodyleft > infobytesleft) {
			/* Multiple blocks still required, this will not be the last one */
			TX_PARTIAL_FIELD(tap, "%.*s", infobytesleft, body);

			/* On a 7E2 connection at 300 baud, each byte requires 9 bits,
			 * so that's about 33 1/3 bytes per second.
			 * We need to be mindful that it will take some time to
			 * transmit, possibly up to around ~8 seconds per block,
			 * and since timer T3 is only 10 seconds, we need to
			 * wait for transmission to ~finish before starting the timer.
			 * Polling for the amount of time transmission will take
			 * (or until there is activity pending) will accomplish that. */
			bbs_poll(tap->node->rfd, 30 * len); /* ~30ms per byte (if anything, we want to be under since we don't want to delay anything) */

			calc_checksum(running_sum, checksum);
			TAP_OUTGOING_SEND_FMT(tap, "%s\r", checksum); /* Very end of block */

			/* Verify that the block was received successfully */
			READ_LINE(tap, TIMER_T3, 1);
			/* As of TAP 1.6, a message sequence is required here, but
			 * since it's optional in older versions, be prepared to not have it here. */
			if (!strchr(tap->rldata.buf, KEY_ESC)) {
				bbs_debug(4, "<= %s\n", tap->rldata.buf);
				READ_LINE(tap, TIMER_T3, 1); /* Now, read the final response */
			}
			if (strstr(tap->rldata.buf, NO_CR_RESPONSE_SEND_AGAIN)) {
				bbs_debug(3, "Block %d needs to be retransmitted\n", blockno);
				/* Retry the previous block */
				START_BLOCK(tap);
				if (blockno == 1) {
					TX_FIELD(tap, "%s", pagerid); /* Resend field 1 */
				}
				continue;
			} else if (strstr(tap->rldata.buf, NO_CR_RESPONSE_OK)) {
				bbs_debug(3, "Block %d transmitted successfully\n", blockno);
			} else if (strstr(tap->rldata.buf, NO_CR_RESPONSE_ABANDON)) {
				bbs_debug(3, "Block %d failed, transaction abandoned\n", blockno);
				goto err;
			} else {
				bbs_warning("Invalid response to block %d\n", blockno);
				bbs_dump_string(tap->rldata.buf);
				goto err;
			}

			/* Move to the next block */
			blockno++;
			body += infobytesleft;
			bodyleft -= infobytesleft;
			START_BLOCK(tap);
		}

		for (;;) {
			if (bodyleft > 0) {
				TX_FIELD(tap, "%s", body); /* End of field, in last block */
				bbs_poll(tap->node->rfd, 30 * len); /* ~30ms per byte */
			}

			/* End the last block */
			running_sum += CHAR_ETX; /* Last char in checksum */
			calc_checksum(running_sum, checksum);
			TAP_OUTGOING_SEND_FMT(tap, "%c%s\r", CHAR_ETX, checksum); /* Very end of last block */

			/* Read the final response */
			READ_LINE(tap, TIMER_T3, 1);
			/* As of TAP 1.6, a message sequence is required here, but
			 * since it's optional in older versions, be prepared to not have it here. */
			if (!strchr(tap->rldata.buf, KEY_ESC)) {
				bbs_debug(4, "<= %s\n", tap->rldata.buf);
				READ_LINE(tap, TIMER_T3, 1); /* Now, read the final response */
			}
			/* Technically, the spec says if we don't get a response within t3 seconds, we may resend the transaction up to n2 (3) times;
			 * however, we don't bother with that and assume if we get no response that a fatal failure has occured with the connection */
			if (strstr(tap->rldata.buf, NO_CR_RESPONSE_SEND_AGAIN)) {
				bbs_debug(3, "Block %d needs to be retransmitted\n", blockno);
				/* Retry the last block */
				START_BLOCK(tap);
				if (blockno == 1) {
					TX_FIELD(tap, "%s", pagerid); /* Resend field 1 */
				}
				continue;
			}
			break;
		}
	} else {
		for (;;) {
			/* End the last block */
			running_sum += CHAR_ETX; /* Last char in checksum */
			calc_checksum(running_sum, checksum);
			TAP_OUTGOING_SEND_FMT(tap, "%s\r", checksum); /* Very end of last block */

			/* Read the final response */
			READ_LINE(tap, TIMER_T3, 1);
			if (!strchr(tap->rldata.buf, KEY_ESC)) {
				bbs_debug(4, "<= %s\n", tap->rldata.buf);
				READ_LINE(tap, TIMER_T3, 1); /* Now, read the final response */
			}
			if (strstr(tap->rldata.buf, NO_CR_RESPONSE_SEND_AGAIN)) {
				bbs_debug(3, "Block %d needs to be retransmitted\n", blockno);
				/* Retry the last block */
				START_BLOCK(tap);
				TX_FIELD(tap, "%s", pagerid); /* Send field 1 */
				continue;
			}
			break;
		}
	}

	/* NAK is processed in each individual branch above,
	 * we can process both ACK and RS here: */
	free_if(bodydup);
	if (strstr(tap->rldata.buf, NO_CR_RESPONSE_OK)) {
		bbs_debug(3, "Block %d transmitted successfully, end of transaction\n", blockno);
		return 0;
	} else if (strstr(tap->rldata.buf, NO_CR_RESPONSE_ABANDON)) {
		bbs_debug(3, "Block %d failed, transaction abandoned\n", blockno);
		return 1;
	}  else {
		bbs_warning("Invalid response to block %d\n", blockno);
		bbs_dump_string(tap->rldata.buf);
		return -1;
	}

abort:
	bbs_debug(4, "Read aborted\n");
err:
cleanup:
	free_if(bodydup);
	return -1;
}

static int run_outgoing(struct tap_session *tap, unsigned int outgoing_id)
{
	char buf[257]; /* Max block size is 256 */
	struct outgoing_call *o;
	int res, tres;
	int retries;
	int i;

	/* Actually send the page using the TAP/IXO protocol */
	RWLIST_WRLOCK(&outgoing_calls);
	RWLIST_TRAVERSE(&outgoing_calls, o, entry) {
		if (o->outgoing_id == outgoing_id) {
			o->connected = 1;
			break;
		}
	}
	RWLIST_UNLOCK(&outgoing_calls);

	if (!o) {
		bbs_warning("Connected call with outgoing ID %u not found in call list?\n", outgoing_id);
		return -1;
	}

	/* This is just the reverse of run_tap; we act as the client to send data and read responses
	 * When reading responses, we need to ensure we use the NO_CR_ versions of strings,
	 * since bbs_readline won't return the trailing CR. */
	bbs_readline_init(&tap->rldata, buf, sizeof(buf));

	for (i = 0; i < 20; i++) {
		/* Step 3: The entry device needs to send a CR */
		TAP_OUTGOING_SEND(tap, "\r");

		/* The connection comes back in as soon as a call originates,
		 * but for analog lines, we may not have accurate supervision.
		 * Wait up to 60 seconds for any data. */
		if (bbs_poll(tap->node->rfd, SEC_MS(3))) {
			bbs_debug(6, "Data received back from terminal, advancing to Step 4\n");
			break;
		}
	}

#define TAP_EXPECT_RETRIES(tap, timer, attempts, str) \
	retries = attempts; \
	for (;;) { \
		READ_LINE(tap, timer, attempts); \
		bbs_dump_string(tap->rldata.buf); \
		if (!strstr(tap->rldata.buf, str)) { \
			if (--retries) { \
				continue; \
			} \
			bbs_warning("Failed to receive '%s'\n", str); \
			goto abort; \
		} \
		break; \
	}

	/* Step 4: Receive ID= within t2 seconds of sending CR
	 * ID= is not CR-terminated, so we can't use TAP_EXPECT here.
	 *
	 * We also want to continue sending CR until we get the ID= response,
	 * since the carrier may not have come up yet, so it's possible
	 * the TAP terminal missed our earlier CRs.
	 * For that reason, we retry here for much longer than the spec advises. */
	for (retries = 0; retries < 10; retries++) {
		if (retries) {
			TAP_OUTGOING_SEND(tap, "\r");
		}
		res = read_with_retries_delim(tap, 2 * TIMER_T2, 1, "="); /* Since ID= is not CR-terminated, this is a hack to use bbs_readline to read "ID=" */
		if (res < -1) {
			goto abort;
		} else if (res == -1) {
			TAP_OUTGOING_SEND(tap, "\r");
			continue;
		}
		bbs_dump_string(tap->rldata.buf);
		if (strstr(tap->rldata.buf, "ID")) {
			break;
		}
#ifdef SUPPORT_LOW_QUALITY_PHONE_CONNECTIONS
		/* On poorer quality phone connections, we might have missed it */
		bbs_debug(4, "Didn't get 'ID=' but got '%s=', proceeding anyways\n", tap->rldata.buf);
		break;
#endif
	}
	if (retries == 10) {
		bbs_warning("Failed to receive 'ID='\n");
		goto abort;
	}

	/* Step 5A: Send response to ID= */
	TAP_OUTGOING_SEND_FMT(tap, "%cPG1\r", KEY_ESC); /* <ESC>PG1<CR> */

	/* Step 6: Login Accepted? */
	/* This could be a multi-line response, so we may need to read a few times for the ACK,
	 * and we just expect <ACK> without the CR, since that gets eaten by bbs_readline
	 *
	 * The spec says we are supposed to use TIMER_T3 here; however, we use a shorter
	 * timer with more retries, allowing us to inspect the buffer,
	 * in case the terminal sent ID= again (in which case we need to repeat Step 5A). */
#ifdef SUPPORT_LOW_QUALITY_PHONE_CONNECTIONS
	for (retries = 0; retries < 5; retries++) {
		/* Here, we force bbs_readline to return immediately 200 ms after the last bytes received,
		 * even though the initial timeout for first read is longer. */
		tap->rldata.posttimeout = 200; /* 300 ms should mean that data has stopped, at 300 baud */
		res = read_with_retries(tap, 2, 1);
		tap->rldata.posttimeout = 0;
		if (res < -1) {
			goto abort;
		} else if (res == -1) {
			/* No poll input, i.e. haven't received a full "line" yet (ending in CR)
			 * However, check if we've received any data at all.
			 * In particular, we may have gotten "ID=" again. */
			int avail = readline_bytes_available(&tap->rldata, 0);
			if (avail >= 3) {
				if (strstr(tap->rldata.buf, "ID=")) {
					bbs_debug(3, "Resending identification\n");
					TAP_OUTGOING_SEND_FMT(tap, "%cPG1\r", KEY_ESC);
					/* Discard all the data received so far */
					bbs_readline_discard_n(tap->node->rfd, &tap->rldata, 1, (size_t) avail);
					continue;
				}
			}
		} else if (res > 0) {
			bbs_dump_string(tap->rldata.buf);
			if (strstr(tap->rldata.buf, NO_CR_RESPONSE_OK)) {
				break;
			}
		} /* else, if 0 (which is invalid in TAP/IXO at this point), continue */
	}
	if (retries == 5) {
		bbs_warning("Failed to receive login acceptance\n");
		goto abort;
	}
#else
	TAP_EXPECT_RETRIES(tap, TIMER_T3, 1, NO_CR_RESPONSE_OK);
#endif

	/* Step 6a: Optional message sequence between steps 6 and 7
	 * Step 7: Message go ahead - as in Step 6, we expect excluding the CR */
	TAP_EXPECT_RETRIES(tap, TIMER_T3, 3, "\033[p");

	tres = send_transaction(tap, o); /* Step 8: Send transaction */

	/*! \todo Since setting up a TAP session is time-consuming, if there are multiple pages queued for this TAP terminal, deliver them all now
	 * Also note that at the time we begin this transaction, we may not have known about a page that has been queued since then,
	 * so we should do the check now if there is anything else we can deliver (and the queued page should wait for us here rather than start new attempt) */

	if (tres >= 0) {
		int res2 = 0;
		/* Received ACK or RS to last block sent */
		TAP_OUTGOING_SEND_FMT(tap, "%c\r", CHAR_EOT); /* Step 9: protocol disconnect sequence */
		for (;;) {
			/* Not all TAP terminals will send further data at this point,
			 * some may immediately disconnect, e.g. Spok.
			 * For that reason, we don't use READ_LINE, as that will goto abort directly,
			 * and we want to treat "no further data" as success as well. */
			res = read_with_retries(tap, 5, 1);
			if (res < 0) {
				bbs_debug(5, "TAP/IXO server disconnected immediately\n");
				break;
			}
			if (strstr(tap->rldata.buf, NO_CR_RESPONSE_DISCONNECT)) {
				/* Paging terminal disconnect sequence */
				bbs_debug(5, "TAP/IXO server disconnecting normally\n");
				break;
			} else if (strstr(tap->rldata.buf, NO_CR_RESPONSE_ABANDON)) {
				bbs_debug(3, "Transaction transmitted successfully, but rejected afterwards\n");
				res2 = -1;
			} else {
				/* Some other (optional) message sequence */
				bbs_debug(3, "<= %s\n", tap->rldata.buf);
			}
		}
		if (!tres && !res2) {
			o->success = 1;
		}
	}

abort:
cleanup:
	RWLIST_WRLOCK(&outgoing_calls);
	o->done = 1;
	RWLIST_UNLOCK(&outgoing_calls);
	return 0;
}

static int wait_outgoing(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta, unsigned int outgoing_id)
{
	struct outgoing_call o_stack, *o = &o_stack;
	time_t start;

	/* At this point, we made the origination request and are waiting for the call to kick off the Softmodem connection back to the BBS.
	 * Wait for that to happen (or time out). */
	memset(&o_stack, 0, sizeof(o_stack));
	o->recipient = recipient;
	o->data = data;
	o->meta = meta;
	o->outgoing_id = outgoing_id;

	/* This thread fully owns o, we insert it into the list and remove it later, nobody else will steal it from us.
	 * run_outgoing thread will lock the list when making changes to its fields. */
	RWLIST_WRLOCK(&outgoing_calls);
	RWLIST_INSERT_HEAD(&outgoing_calls, o, entry);
	RWLIST_UNLOCK(&outgoing_calls);

	/* Now, wait for the request to connect, or time out */
#define ORIGINATE_TIMEOUT 45 /* In Asterisk, this is 30, but we'll give some extra time for the modem setup and any other processing */
	start = time(NULL);
	do {
		usleep(1000000); /* 1 sec */
		if (bbs_is_shutting_down()) {
			break;
		}
		if (o->connected) {
			break;
		}
	} while (time(NULL) < start + ORIGINATE_TIMEOUT);

	/* Check if the call answered and actually established a Softmodem connection back to the BBS */
	RWLIST_WRLOCK(&outgoing_calls);
	if (!o->connected) {
		/* The call never connected, give up now */
		RWLIST_REMOVE(&outgoing_calls, o, entry);
		RWLIST_UNLOCK(&outgoing_calls);
		bbs_debug(2, "Outgoing TAP/IXO call never connected, aborting attempt\n");
		errno = EAGAIN;
		return -1;
	}
	RWLIST_UNLOCK(&outgoing_calls);

	/* Now, run_outgoing will be using o until it sets o->done to 1,
	 * so as long as !o->done, we need to wait for the other thread. */
	/* XXX Could use a cond variable to notify this thread more efficiently */
	for (;;) {
		usleep(1000000); /* 1 sec */
		if (bbs_is_shutting_down()) {
			break;
		}
		RWLIST_WRLOCK(&outgoing_calls);
		if (o->done) {
			RWLIST_REMOVE(&outgoing_calls, o, entry);
			RWLIST_UNLOCK(&outgoing_calls);
			if (o->success) {
				bbs_debug(2, "Outgoing TAP/IXO call completed, transmission successful\n");
				return 0;
			} else {
				bbs_debug(2, "Outgoing TAP/IXO call connected, transmission failed\n");
				errno = EAGAIN;
				return -1;
			}
		}
		RWLIST_UNLOCK(&outgoing_calls);
	}
	RWLIST_WRLOCK(&outgoing_calls);
	RWLIST_REMOVE(&outgoing_calls, o, entry);
	RWLIST_UNLOCK(&outgoing_calls);
	errno = EAGAIN;
	return -1;
}

static int __tap_handler(struct bbs_node *node)
{
	struct tap_session tap;
	char number[16], name[16];
	char channel[80];
	char varbuf[32];

	/* Start TLS if we need to */
	if (!strcmp(node->protname, "TAPS") && bbs_node_starttls(node)) {
		return -1;
	}

	/* If the connection didn't come through Asterisk, then it's not legitimate, drop it */
	if (bbs_ami_softmodem_get_callerid(node, channel, sizeof(channel), number, sizeof(number), name, sizeof(name))) {
		return -1;
	}

	memset(&tap, 0, sizeof(tap));
	tap.node = node;
	tap.started = time(NULL);

	if (!bbs_ami_action_getvar_buf(ami_session, "BBS_TAP_IXO_OUTGOING", channel, varbuf, sizeof(varbuf))) {
		/* Step 2: Carrier handshake.
		 * If the variable exists and is set, then it's an outgoing connection */
		int outgoing_id = atoi(varbuf);
		if (outgoing_id <= 0) {
			bbs_warning("Invalid value for BBS_TAP_IXO_OUTGOING: %s\n", varbuf);
			return -1;
		}
		tap.outgoing = 1;
		bbs_debug(4, "Starting outgoing TAP session\n");
		return run_outgoing(&tap, (unsigned int) outgoing_id);
	} else {
		bbs_debug(4, "Starting incoming TAP session\n");
		return run_incoming(&tap, number);
	}
}

static void *tap_handler(void *varg)
{
	struct bbs_node *node = varg;
	bbs_node_net_begin(node);
	__tap_handler(node);
	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	int res;
	struct bbs_config *cfg = bbs_config_load("net_tap.conf", 1);

	if (!cfg) {
		return -1;
	}

	res = bbs_config_val_set_port(cfg, "general", "port", &tap_port) && bbs_config_val_set_port(cfg, "general", "secureport", &taps_port); /* At least one required */

	if (!bbs_config_val_set_str(cfg, "outbound", "amisession", session_name_buf, sizeof(session_name_buf))) {
		ami_session = session_name_buf;
	}
	bbs_config_val_set_str(cfg, "outbound", "dial_context", dial_context, sizeof(dial_context));
	bbs_config_val_set_str(cfg, "outbound", "softmodem_args", softmodem_args, sizeof(softmodem_args));

	bbs_config_unlock(cfg);
	return res;
}

static int invalid_body(unsigned const char *s)
{
	while (*s) {
		if (*s > 0x7F) {
			return 1;
		}
		s++;
	}
	return 0;
}

/*! \brief Send page via TAP/IXO */
static int page_single(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	char dialstr[128];
	static unsigned int outgoing_id = 1;
	unsigned int my_id;
	int res;
	const char *body = S_OR(data->body, data->message);

	if (invalid_body((unsigned const char*) body)) {
		bbs_warning("Message contains illegal characters for TAP/IXO: %s\n", body);
		errno = EMSGSIZE; /* Not fully accurate, the message is illegal, not too long */
		return -1;
	}

	/* Unlike mod_paging_snpp and mod_paging_smtp, the handler for sending outbound pages via TAP/IXO
	 * is embedded into the protocol handler. This is because the way we accomplish this
	 * is by telling Asterisk to establish a normal inbound TCP connection to the TAP port,
	 * at which point we'll detect it's for the outbound call and take over.
	 * Putting the callback here means we don't need to listen on a separate TCP port. */

	/* We know dial_context is non-empty since we don't register the callback if it is
	 * Local channel optimization must be prevented if we are calling a dialplan application like Softmodem directly (won't matter if calling a real device, like DAHDI) */
	snprintf(dialstr, sizeof(dialstr), "Local/%s@%s/n", data->gateway, dial_context); /* Dial string to dial the TAP/IXO gateway */

	/* Step 1: TAP entry device (us) dials TAP terminal
	 *
	 * Normally, the Softmodem call looks something like: Softmodem(127.0.0.1,4827,v(Bell103)led(7))
	 * The main difference here is we add the 'f' option to make this an originating modem, rather than answering.
	 * The actual arguments we take from the config file, but we append 'f' unconditionally;
	 * it's required for originating mode, and it does no harm if the config already included it. */
	my_id = bbs_atomic_fetchadd_int(&outgoing_id, +1); /* Monotonically increasing ID to correlate the incoming session with this request */
	res = bbs_ami_action_response_result(ami_session, bbs_ami_action(ami_session, "Originate",
		"Channel:%s\r\nApplication:Softmodem\r\nData:%sf\r\nAsync:1\r\nTimeout:%d\r\nVariable:%s=%u",
		dialstr, softmodem_args, SEC_MS(ORIGINATE_TIMEOUT), "BBS_TAP_IXO_OUTGOING", my_id));
	if (res) {
		bbs_error("Failed to originate outgoing Softmodem call\n")
		errno = EAGAIN;
		return -1;
	}

	return wait_outgoing(recipient, data, meta, my_id);
}

struct bbs_paging_callbacks paging_callbacks = {
	.page_single = page_single,
};

static struct bbs_unit_test tests[] =
{
	{ "TAP Checksum Calculation", test_checksum },
	{ "TAP Control Transparency", test_control_transparency },
};

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	bbs_register_tests(tests);
	if (!s_strlen_zero(dial_context)) { /* If the outbound context hasn't been configured, no point in registering the provider */
		bbs_register_paging_provider(&paging_callbacks, 5, PAGING_PROT_TAP_IXO);
	}
	return bbs_start_tcp_listener2(tap_port, taps_port, "TAP", "TAPS", tap_handler);
}

static int unload_module(void)
{
	bbs_unregister_tests(tests);
	if (!s_strlen_zero(dial_context)) {
		bbs_unregister_paging_provider(&paging_callbacks);
	}
	if (tap_port) {
		bbs_stop_tcp_listener(tap_port);
	}
	if (taps_port) {
		bbs_stop_tcp_listener(taps_port);
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("TAP/IXO Paging Protocol", "mod_asterisk_ami.so");
