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
 * \brief IMAP Server SEARCH, SORT, THREAD
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>
#include <search.h>

#include "include/node.h"
#include "include/test.h"
#include "include/range.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_server_flags.h"
#include "nets/net_imap/imap_server_search.h"

enum imap_search_type {
	IMAP_SEARCH_ALL = 0,
	IMAP_SEARCH_ANSWERED,
	IMAP_SEARCH_BCC,
	IMAP_SEARCH_BEFORE,
	IMAP_SEARCH_BODY,
	IMAP_SEARCH_CC,
	IMAP_SEARCH_DELETED,
	IMAP_SEARCH_DRAFT,
	IMAP_SEARCH_FLAGGED,
	IMAP_SEARCH_FROM,
	IMAP_SEARCH_HEADER,
	IMAP_SEARCH_KEYWORD,
	IMAP_SEARCH_LARGER,
	IMAP_SEARCH_MODSEQ,
	IMAP_SEARCH_NEW,
	IMAP_SEARCH_NOT,
	IMAP_SEARCH_OLD,
	IMAP_SEARCH_OLDER,
	IMAP_SEARCH_ON,
	IMAP_SEARCH_OR,
	IMAP_SEARCH_AND,
	IMAP_SEARCH_RECENT,
	IMAP_SEARCH_SEEN,
	IMAP_SEARCH_SENTBEFORE,
	IMAP_SEARCH_SENTON,
	IMAP_SEARCH_SENTSINCE,
	IMAP_SEARCH_SINCE,
	IMAP_SEARCH_SMALLER,
	IMAP_SEARCH_SUBJECT,
	IMAP_SEARCH_TEXT,
	IMAP_SEARCH_TO,
	IMAP_SEARCH_UID,
	IMAP_SEARCH_UNANSWERED,
	IMAP_SEARCH_UNDELETED,
	IMAP_SEARCH_UNDRAFT,
	IMAP_SEARCH_UNFLAGGED,
	IMAP_SEARCH_UNKEYWORD,
	IMAP_SEARCH_UNSEEN,
	IMAP_SEARCH_YOUNGER,
	IMAP_SEARCH_SEQUENCE_NUMBER_SET,
};

#ifdef DEBUG_SEARCH
static const char *imap_search_key_name(enum imap_search_type type)
{
	switch (type) {
		case IMAP_SEARCH_ALL:
			return "ALL";
		case IMAP_SEARCH_ANSWERED:
			return "ANSWERED";
		case IMAP_SEARCH_BCC:
			return "BCC";
		case IMAP_SEARCH_BEFORE:
			return "BEFORE";
		case IMAP_SEARCH_BODY:
			return "BODY";
		case IMAP_SEARCH_CC:
			return "CC";
		case IMAP_SEARCH_DELETED:
			return "DELETED";
		case IMAP_SEARCH_DRAFT:
			return "DRAFT";
		case IMAP_SEARCH_FLAGGED:
			return "FLAGGED";
		case IMAP_SEARCH_FROM:
			return "FROM";
		case IMAP_SEARCH_HEADER:
			return "HEADER";
		case IMAP_SEARCH_KEYWORD:
			return "KEYWORD";
		case IMAP_SEARCH_LARGER:
			return "LARGER";
		case IMAP_SEARCH_MODSEQ:
			return "MODSEQ";
		case IMAP_SEARCH_NEW:
			return "NEW";
		case IMAP_SEARCH_NOT:
			return "NOT";
		case IMAP_SEARCH_OLD:
			return "OLD";
		case IMAP_SEARCH_OLDER:
			return "OLDER";
		case IMAP_SEARCH_ON:
			return "ON";
		case IMAP_SEARCH_OR:
			return "OR";
		case IMAP_SEARCH_AND:
			return "AND";
		case IMAP_SEARCH_RECENT:
			return "RECENT";
		case IMAP_SEARCH_SEEN:
			return "SEEN";
		case IMAP_SEARCH_SENTBEFORE:
			return "SENTBEFORE";
		case IMAP_SEARCH_SENTON:
			return "SENTON";
		case IMAP_SEARCH_SENTSINCE:
			return "SENTSINCE";
		case IMAP_SEARCH_SINCE:
			return "SINCE";
		case IMAP_SEARCH_SMALLER:
			return "SMALLER";
		case IMAP_SEARCH_SUBJECT:
			return "SUBJECT";
		case IMAP_SEARCH_TEXT:
			return "TEXT";
		case IMAP_SEARCH_TO:
			return "TO";
		case IMAP_SEARCH_UID:
			return "UID";
		case IMAP_SEARCH_UNANSWERED:
			return "UNANSWERED";
		case IMAP_SEARCH_UNDELETED:
			return "UNDELETED";
		case IMAP_SEARCH_UNDRAFT:
			return "UNDRAFT";
		case IMAP_SEARCH_UNFLAGGED:
			return "UNFLAGGED";
		case IMAP_SEARCH_UNKEYWORD:
			return "UNKEYWORD";
		case IMAP_SEARCH_UNSEEN:
			return "UNSEEN";
		case IMAP_SEARCH_YOUNGER:
			return "YOUNGER";
		case IMAP_SEARCH_SEQUENCE_NUMBER_SET:
			return "SEQNO_SET";
		default:
			bbs_error("Invalid search key type: %d\n", type);
			return NULL;
	}
}
#endif

struct imap_search_key;

struct imap_search_key {
	enum imap_search_type type;
	union arg {
		int number;
		unsigned long longnumber;
		const char *string;
		struct imap_search_keys *keys;			/* Child key (if any) */
	} child;
	RWLIST_ENTRY(imap_search_key) entry;	/* Next key at this level */
};

RWLIST_HEAD(imap_search_keys, imap_search_key);

static struct imap_search_key *imap_search_add(struct imap_search_keys *skeys, enum imap_search_type type)
{
	struct imap_search_key *nk;

	nk = calloc(1, sizeof(*nk));
	if (ALLOC_FAILURE(nk)) {
		return NULL;
	}
	nk->type = type;
	RWLIST_INSERT_TAIL(skeys, nk, entry);
	return nk;
}

static void imap_search_free(struct imap_search_keys *skeys)
{
	struct imap_search_key *skey;

	while ((skey = RWLIST_REMOVE_HEAD(skeys, entry))) {
		if (skey->type == IMAP_SEARCH_OR || skey->type == IMAP_SEARCH_NOT) {
			imap_search_free(skey->child.keys);
			free(skey->child.keys);
		}
		free(skey);
	}
}

/* #define DEBUG_SEARCH */

#ifdef DEBUG_SEARCH
/*! \brief Dump a parsed IMAP search query structure as a hierarchical tree for debugging */
static void dump_imap_search_keys(struct imap_search_keys *skeys, struct dyn_str *str, int depth)
{
	struct imap_search_key *skey;

	RWLIST_TRAVERSE(skeys, skey, entry) {
		/* Indent according to the recursion depth */
		dyn_str_append_fmt(str, "=%%= %*.s %s -> ", 3 * depth, "", imap_search_key_name(skey->type));
		switch (skey->type) {
			case IMAP_SEARCH_ANSWERED:
			case IMAP_SEARCH_DELETED:
			case IMAP_SEARCH_DRAFT:
			case IMAP_SEARCH_FLAGGED:
			case IMAP_SEARCH_NEW:
			case IMAP_SEARCH_OLD:
			case IMAP_SEARCH_RECENT:
			case IMAP_SEARCH_SEEN:
			case IMAP_SEARCH_UNANSWERED:
			case IMAP_SEARCH_UNDELETED:
			case IMAP_SEARCH_UNDRAFT:
			case IMAP_SEARCH_UNFLAGGED:
			case IMAP_SEARCH_UNKEYWORD:
			case IMAP_SEARCH_UNSEEN:
				dyn_str_append_fmt(str, "\n", 1);
				break;
			case IMAP_SEARCH_LARGER:
			case IMAP_SEARCH_SMALLER:
			case IMAP_SEARCH_OLDER:
			case IMAP_SEARCH_YOUNGER:
				dyn_str_append_fmt(str, "%d\n", skey->child.number);
				break;
			case IMAP_SEARCH_MODSEQ:
				dyn_str_append_fmt(str, "%lu\n", skey->child.longnumber);
				break;
			case IMAP_SEARCH_BCC:
			case IMAP_SEARCH_BEFORE:
			case IMAP_SEARCH_BODY:
			case IMAP_SEARCH_CC:
			case IMAP_SEARCH_FROM:
			case IMAP_SEARCH_HEADER:
			case IMAP_SEARCH_KEYWORD:
			case IMAP_SEARCH_ON:
			case IMAP_SEARCH_SENTBEFORE:
			case IMAP_SEARCH_SENTON:
			case IMAP_SEARCH_SENTSINCE:
			case IMAP_SEARCH_SINCE:
			case IMAP_SEARCH_SUBJECT:
			case IMAP_SEARCH_TEXT:
			case IMAP_SEARCH_TO:
			case IMAP_SEARCH_SEQUENCE_NUMBER_SET:
			case IMAP_SEARCH_UID:
				dyn_str_append_fmt(str, "%s\n", S_IF(skey->child.string));
				break;
			case IMAP_SEARCH_NOT:
			case IMAP_SEARCH_OR:
			case IMAP_SEARCH_AND:
				dyn_str_append(str, "\n", 1);
				dump_imap_search_keys(skey->child.keys, str, depth + 1);
				break;
			case IMAP_SEARCH_ALL:
			default:
				bbs_warning("Invalid key: %d\n", skey->type);
				dyn_str_append(str, "\n", 1);
				break;
		}
	}
}
#endif

#define SEARCH_PARSE_FLAG(name) \
	else if (!strcasecmp(next, #name)) { \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (unlikely(!nk)) { \
			return -1; \
		} \
		listsize++; \
	}

#define SEARCH_PARSE_INT(name) \
	else if (!strcasecmp(next, #name)) { \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (unlikely(!nk)) { \
			return -1; \
		} \
		next = strsep(s, " "); \
		if (!next) { \
			bbs_warning("Missing numeric argument\n"); \
			return -1; \
		} \
		nk->child.number = atoi(next); \
		listsize++; \
	}

#define SEARCH_PARSE_LONG(name) \
	else if (!strcasecmp(next, #name)) { \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (unlikely(!nk)) { \
			return -1; \
		} \
		next = strsep(s, " "); \
		if (!next) { \
			bbs_warning("Missing numeric argument\n"); \
			return -1; \
		} \
		nk->child.longnumber = (unsigned long) atol(next); \
		listsize++; \
	}

/*! \brief Parse a string argument, optionally enclosed in quotes (mandatory if the argument contains multiple words) */
#define SEARCH_PARSE_STRING(name) \
	else if (!strcasecmp(next, #name)) { \
		quoted_arg = 0; \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (!nk) { \
			return -1; \
		} \
		/* Argument can be more than one word - it's the whole quoted argument. Find it, and strip the quotes in the process. */ \
		if (!*s) { \
			bbs_warning("Missing string argument\n"); \
			return -1; \
		} \
		if (**s == '"') { \
			begin = *s + 1; /* Skip opening " */ \
			quoted_arg = 1; \
		} else { \
			begin = *s; \
		} \
		if (!*begin) { \
			bbs_warning("Empty quoted argument\n"); \
			return -1; \
		} \
		if (quoted_arg) { \
			next = strchr(begin, '"'); \
			if (!next) { \
				bbs_warning("Unterminated quoted argument\n"); \
				return -1; \
			} \
		} else { \
			next = strchr(begin, ' '); \
		} \
		if (next) { \
			*next = '\0'; \
			*s = next + 1; \
		} else { \
			*s = NULL; \
		} \
		nk->child.string = begin; /* This is not dynamically allocated, and does not need to be freed. */ \
		listsize++; \
	}

#define SEARCH_PARSE_RECURSE(name) \
		else if (!strcasecmp(next, #name)) { \
		nk = imap_search_add(skeys, IMAP_SEARCH_ ## name); \
		if (!nk) { \
			return -1; \
		} \
		nk->child.keys = calloc(1, sizeof(*nk->child.keys)); \
		if (!nk->child.keys) { \
			return -1; \
		} \
		listsize++; \
		if (parse_search_query(imap, nk->child.keys, IMAP_SEARCH_ ## name, s)) { \
			return -1; \
		} \
	}

static int parse_search_query(struct imap_session *imap, struct imap_search_keys *skeys, enum imap_search_type parent_type, char **s)
{
	char *begin, *next = NULL;
	struct imap_search_key *nk;
	int listsize = 0;
	int quoted_arg = 0;
	int paren_count = 0;

	for (;;) {
		if (*s && **s == '(') {
			next = *s; /* Don't strsep if we are at an opening parenthesis */
		} else {
			next = strsep(s, " ");
		}
		if (!next) {
			break;
		} else if (strlen_zero(next)) {
			continue;
		}

		/* If it starts with a (, treat everything until ) as one unit */
		if (*next == '(') {
			char *subnext, *p;
			/* Can't just use strchr to find the next ), since we could have nested parentheses. Find the real end. */
			/* Perhaps more optimal might be to recurse immediately as soon as we hit another open (, and return when we hit a ) */
			for (p = next; *p; p++) {
				if (*p == '(') {
					paren_count++;
				} else if (*p == ')') {
					if (!--paren_count) {
						break;
					}
				}
			}
			if (paren_count) {
				bbs_warning("Invalid SEARCH expression: unterminated parentheses: %s\n", next);
				return -1;
			}
			*p++ = '\0';
			*s = p;
			if (strlen_zero(*s)) {
				*s = NULL;
			}
			nk = imap_search_add(skeys, IMAP_SEARCH_AND);
			if (!nk) {
				return -1;
			}
			nk->child.keys = calloc(1, sizeof(*nk->child.keys));
			if (!nk->child.keys) {
				return -1;
			}
			listsize++;
			subnext = next + 1;
			/* Recurse to parse the contents of the expression between the ( and ) */
			if (parse_search_query(imap, nk->child.keys, IMAP_SEARCH_AND, &subnext)) {
				return -1;
			}
			goto checklistsize;
		}

		/* Need to parse two strings from this, not just one */
		if (!strcasecmp(next, "HEADER")) {
			begin = *s + 1; /* Skip opening " */
			begin = strchr(begin, '"');
			if (!begin) {
				bbs_warning("Missing end quote for HEADER arg1\n");
				return -1;
			}
			*begin++ = ' '; /* Don't null terminate, we need to be able to continue through the string. */
			begin = strchr(begin, '"');
			/* There should be a "" for empty arg2, but the quotes should still be there */
			if (!begin) {
				bbs_warning("Missing opening quote for HEADER arg2\n");
				return -1;
			}
			*begin = ' ';
		}

		if (!strcasecmp(next, "ALL")) { /* This is only first so the macros can all use else if, not because it's particularly common. */
			/* Default */
		} /* else: */
		SEARCH_PARSE_FLAG(ANSWERED)
		SEARCH_PARSE_FLAG(DELETED)
		SEARCH_PARSE_FLAG(DRAFT)
		SEARCH_PARSE_FLAG(FLAGGED)
		SEARCH_PARSE_FLAG(NEW)
		SEARCH_PARSE_FLAG(OLD)
		SEARCH_PARSE_FLAG(RECENT)
		SEARCH_PARSE_FLAG(SEEN)
		SEARCH_PARSE_FLAG(UNANSWERED)
		SEARCH_PARSE_FLAG(UNDELETED)
		SEARCH_PARSE_FLAG(UNDRAFT)
		SEARCH_PARSE_FLAG(UNFLAGGED)
		SEARCH_PARSE_FLAG(UNSEEN)
		SEARCH_PARSE_INT(LARGER)
		SEARCH_PARSE_INT(SMALLER)
		SEARCH_PARSE_INT(OLDER)
		SEARCH_PARSE_INT(YOUNGER)
		/*! \todo BUGBUG RFC 7162 3.1.5 Technically can be something like MODSEQ "/flags/\\draft" all 620162338.
		 * We should ignore the extra info and just use the number since we don't store multiple modseqs per message,
		 * for different metadata, but currently we won't parse right if the extra stuff is present. */
		SEARCH_PARSE_LONG(MODSEQ)
		SEARCH_PARSE_STRING(BCC)
		SEARCH_PARSE_STRING(BEFORE)
		SEARCH_PARSE_STRING(BODY)
		SEARCH_PARSE_STRING(CC)
		SEARCH_PARSE_STRING(FROM)
		SEARCH_PARSE_STRING(HEADER)
		SEARCH_PARSE_STRING(KEYWORD)
		SEARCH_PARSE_STRING(UNKEYWORD)
		SEARCH_PARSE_STRING(ON)
		SEARCH_PARSE_STRING(SENTBEFORE)
		SEARCH_PARSE_STRING(SENTON)
		SEARCH_PARSE_STRING(SENTSINCE)
		SEARCH_PARSE_STRING(SINCE)
		SEARCH_PARSE_STRING(SUBJECT)
		SEARCH_PARSE_STRING(TEXT)
		SEARCH_PARSE_RECURSE(OR)
		SEARCH_PARSE_RECURSE(NOT)
		SEARCH_PARSE_STRING(UID)
		else if (isdigit(*next)) {
			/* sequence set */
			/* Not quoted, so thankfully this doesn't duplicate much code */
			nk = imap_search_add(skeys, IMAP_SEARCH_SEQUENCE_NUMBER_SET);
			if (!nk) {
				return -1;
			}
			nk->child.string = next;
			listsize++;
		} else if (!strcmp(next, "$")) { /* Saved search */
			nk = imap_search_add(skeys, imap->savedsearchuid ? IMAP_SEARCH_UID : IMAP_SEARCH_SEQUENCE_NUMBER_SET);
			if (!nk) {
				return -1;
			}
			nk->child.string = next; /* We store the literal '$' here, but this will get resolved in imap_in_range */
			listsize++;
		} else {
			bbs_warning("Foreign IMAP search key: %s\n", next);
			return -1;
		}
checklistsize:
		switch (parent_type) {
			case IMAP_SEARCH_NOT:
				if (listsize == 1) {
					goto ret;
				}
				break;
			case IMAP_SEARCH_OR:
				if (listsize == 2) {
					goto ret;
				}
				break;
			default:
				break;
		}
	}

ret:
	switch (parent_type) {
		case IMAP_SEARCH_NOT:
			if (listsize != 1) {
				bbs_warning("NOT has %d children?\n", listsize);
				return -1;
			}
			break;
		case IMAP_SEARCH_OR:
			if (listsize != 2) {
				bbs_warning("OR has %d children?\n", listsize);
				return -1;
			}
			break;
		default:
			break;
	}

	return 0;
}

struct imap_search {
	const char *directory;
	const char *filename;
	const char *keywords;
	struct stat st;
	FILE *fp;
	int flags;
	int seqno;
	int now;
	unsigned long maxmodseq;
	struct imap_session *imap;
	unsigned int new:1;
	unsigned int didstat:1;
};

static int search_message(struct imap_search *search, const char *s, int headers, int body)
{
	char linebuf[1001];
	int in_headers = 1;

	if (!search->fp) {
		char buf[512];
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename);
		search->fp = fopen(buf, "r"); /* Only open the file if needed */
		if (!search->fp) {
			bbs_error("Failed to open %s: %s\n", buf, strerror(errno));
			return -1;
		}
	} else {
		rewind(search->fp);
	}

	while ((fgets(linebuf, sizeof(linebuf), search->fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			in_headers = 0;
			if (!body) {
				break; /* End of headers */
			}
		} else if (in_headers && !headers) {
			continue;
		} else if (strcasestr(linebuf, s)) {
			return 1;
		}
	}
	return 0;
}

static int search_header(struct imap_search *search, const char *header, size_t headerlen, const char *value)
{
	char linebuf[1001];
	char *pos;

	if (!search->fp) {
		char buf[512];
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename);
		search->fp = fopen(buf, "r"); /* Only open the file if needed */
		if (!search->fp) {
			bbs_error("Failed to open %s: %s\n", buf, strerror(errno));
			return -1;
		}
	} else {
		rewind(search->fp);
	}

#ifdef DEBUG_SEARCH
	bbs_debug(8, "Searching %s header %.*s for %s\n", search->filename, (int) headerlen, header, S_IF(value));
#endif

	while ((fgets(linebuf, sizeof(linebuf), search->fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
		if (strncasecmp(linebuf, header, headerlen)) {
			continue; /* Not the right header */
		}
		pos = linebuf + headerlen;
		if (strlen_zero(value)) {
			return 1; /* Header exists (no value to search for), and that's all we care about */
		}
		if (strcasestr(pos, value)) {
			return 1;
		}
	}
	return 0;
}

static int get_header(FILE *fp, const char *header, size_t headerlen, char *buf, size_t len)
{
	char linebuf[1001];
	char *pos;

	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
		if (strncasecmp(linebuf, header, headerlen)) {
			continue; /* Not the right header */
		}
		pos = linebuf + headerlen;
		if (*pos == ':') {
			pos++;
		}
		if (*pos == ' ') {
			pos++;
		}
		safe_strncpy(buf, pos, len);
		return 0;
	}
	return -1;
}

static int search_sent_date(struct imap_search *search, struct tm *tm)
{
	char linebuf[1001];
	char *pos;

	if (!search->fp) {
		char buf[512];
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename);
		search->fp = fopen(buf, "r"); /* Only open the file if needed */
		if (!search->fp) {
			bbs_error("Failed to open %s: %s\n", buf, strerror(errno));
			return -1;
		}
	} else {
		rewind(search->fp);
	}

	while ((fgets(linebuf, sizeof(linebuf), search->fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
		if (strncasecmp(linebuf, "Date:", STRLEN("Date:"))) {
			continue; /* Not the right header */
		}
		pos = linebuf + STRLEN("Date:");
		ltrim(pos);
		bbs_strterm(pos, '\r');
		return bbs_parse_rfc822_date(pos, tm);
	}
	bbs_warning("Didn't find a date in message\n");
	return -1;
}

#define SEARCH_HEADER_MATCH(hdrname) \
	retval = search_header(search, hdrname ":", STRLEN(hdrname ":"), skey->child.string); \
	break;

#define SEARCH_FLAG_MATCH(flag) \
	retval = (search->flags & flag); \
	break;

#define SEARCH_FLAG_NOT_MATCH(flag) \
	retval = !(search->flags & flag); \
	break;

#define SEARCH_STAT() \
	memset(&tm1, 0, sizeof(tm1)); \
	memset(&tm2, 0, sizeof(tm2)); \
	if (!search->didstat) { \
		char buf[512]; \
		snprintf(buf, sizeof(buf), "%s/%s", search->directory, search->filename); \
		if (stat(buf, &search->st)) { \
			bbs_error("stat(%s) failed: %s\n", buf, strerror(errno)); \
		} else { \
			search->didstat = 1; \
		} \
	}

/* XXX For some reason, if we don't initialize both tm1 and tm2 to zero, the first search date can occasionally be wrong.
 * Not sure how it could be used uninitialized, but apparently it can be... (ditto for SEARCH_STAT above) */
#define SEARCH_DATE() \
	memset(&tm1, 0, sizeof(tm1)); \
	memset(&tm2, 0, sizeof(tm2)); \
	if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */ \
		bbs_warning("Failed to parse as date: %s\n", skey->child.string); \
		break; \
	} \
	if (search_sent_date(search, &tm1)) { /* Get from Date header */ \
		break; \
	}

#define TM_DATE_EQUAL(tm1, tm2) (tm1.tm_year == tm1.tm_year && tm1.tm_mon == tm2.tm_mon && tm1.tm_mday == tm2.tm_mday)

/*! \brief Recursively evaluate if a message matches a tree of search expressions */
static int search_keys_eval(struct imap_search_keys *skeys, enum imap_search_type type, struct imap_search *search)
{
	int retval = 1; /* True by default. */
	struct imap_search_key *skey;
	unsigned int uid;
	unsigned long modseq;
	unsigned long size;
	const char *hdrval;
	size_t len;
	struct tm tm1, tm2;
	time_t t1, t2;

	/* Evaluate all expressions (they are all AND'ed together), stopping if we find one that's false. */
	RWLIST_TRAVERSE(skeys, skey, entry) {
		switch (skey->type) {
			case IMAP_SEARCH_ANSWERED:
				SEARCH_FLAG_MATCH(FLAG_BIT_ANSWERED);
			case IMAP_SEARCH_DELETED:
				SEARCH_FLAG_MATCH(FLAG_BIT_DELETED);
			case IMAP_SEARCH_DRAFT:
				SEARCH_FLAG_MATCH(FLAG_BIT_DRAFT);
			case IMAP_SEARCH_FLAGGED:
				SEARCH_FLAG_MATCH(FLAG_BIT_FLAGGED);
			case IMAP_SEARCH_NEW: /* Same as RECENT && UNSEEN */
				retval = search->new && !(search->flags & FLAG_BIT_SEEN);
				break;
			case IMAP_SEARCH_OLD:
				retval = !search->new;
				break;
			case IMAP_SEARCH_RECENT:
				retval = search->new;
				break;
			case IMAP_SEARCH_SEEN:
				SEARCH_FLAG_MATCH(FLAG_BIT_SEEN);
			case IMAP_SEARCH_UNANSWERED:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_ANSWERED);
			case IMAP_SEARCH_UNDELETED:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_DELETED);
			case IMAP_SEARCH_UNDRAFT:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_DELETED);
			case IMAP_SEARCH_UNFLAGGED:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_FLAGGED);
			case IMAP_SEARCH_UNSEEN:
				SEARCH_FLAG_NOT_MATCH(FLAG_BIT_SEEN);
			case IMAP_SEARCH_LARGER:
				if (!search->new) {
					/* only works for messages in cur, not new, same with subsequent parse_ function calls that use the filename */
					parse_size_from_filename(search->filename, &size);
				} else {
					SEARCH_STAT()
					size = (unsigned long) search->st.st_size;
				}
				retval = (int) size > skey->child.number;
				break;
			case IMAP_SEARCH_SMALLER:
				if (!search->new) {
					parse_size_from_filename(search->filename, &size);
				} else {
					SEARCH_STAT()
					size = (unsigned long) search->st.st_size;
				}
				retval = (int) size < skey->child.number;
				break;
			case IMAP_SEARCH_UID:
				if (!search->new) {
					maildir_parse_uid_from_filename(search->filename, &uid);
					retval = imap_in_range(search->imap, skey->child.string, (int) uid);
				} else {
					/* XXX messages in new don't have a UID, so by definition it can't match */
					retval = 0;
				}
				break;
			case IMAP_SEARCH_MODSEQ:
				if (!search->new) {
					parse_modseq_from_filename(search->filename, &modseq);
					retval = modseq >= skey->child.longnumber;
					search->maxmodseq = MAX(search->maxmodseq, modseq);
				} else {
					retval = 1; /* If it's new, by definition we don't know about it, so in the spirit of MODSEQ it should always match */
				}
				break;
			case IMAP_SEARCH_SEQUENCE_NUMBER_SET:
				retval = imap_in_range(search->imap, skey->child.string, search->seqno);
				break;
			case IMAP_SEARCH_BCC:
				SEARCH_HEADER_MATCH("Bcc");
			case IMAP_SEARCH_BODY:
				retval = search_message(search, skey->child.string, 0, 1) == 1;
				break;
			case IMAP_SEARCH_CC:
				SEARCH_HEADER_MATCH("Cc");
			case IMAP_SEARCH_FROM:
				SEARCH_HEADER_MATCH("From");
			case IMAP_SEARCH_HEADER:
				hdrval = strchr(skey->child.string, ' ');
				len = (size_t) (hdrval - skey->child.string);
				ltrim(hdrval);
				retval = search_header(search, skey->child.string, len, hdrval);
				break;
			case IMAP_SEARCH_UNKEYWORD:
			case IMAP_SEARCH_KEYWORD:
				/* This is not very efficient, since we reparse the keywords for every message, but the keyword mapping is the same for everything in this mailbox. */
				if (strlen_zero(skey->child.string)) {
					bbs_warning("No keyword?\n");
					break;
				}
				parse_keyword(search->imap, skey->child.string, search->imap->dir, 0);
				/* imap->appendkeywords is now set. */
				if (search->imap->numappendkeywords != 1) {
					bbs_warning("Expected %d keyword, got %d? (%s)\n", 1, search->imap->numappendkeywords, skey->child.string);
					break;
				}
				retval = strchr(search->keywords, search->imap->appendkeywords[0]) ? 1 : 0;
				if (skey->type == IMAP_SEARCH_UNKEYWORD) {
					retval = !retval;
				}
				break;
			case IMAP_SEARCH_ON: /* INTERNALDATE == match */
				SEARCH_STAT()
				if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */
					bbs_warning("Failed to parse as date: %s\n", skey->child.string);
					break;
				}
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				retval = TM_DATE_EQUAL(tm1, tm2);
				break;
			case IMAP_SEARCH_SENTBEFORE:
				SEARCH_DATE()
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				/* t1 = INTERNALDATE, t2 = threshold for search before */
				retval = difftime(t1, t2) < 0; /* If difftime is positive, tm1 > tm2 */
				break;
			case IMAP_SEARCH_SENTON:
				SEARCH_DATE()
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				retval = TM_DATE_EQUAL(tm1, tm2);
				break;
			case IMAP_SEARCH_SENTSINCE:
				SEARCH_DATE()
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				/* t1 = INTERNALDATE, t2 = threshold for search before */
				retval = difftime(t1, t2) > 0 && !TM_DATE_EQUAL(tm1, tm2); /* If difftime is positive, tm1 > tm2 */
				break;
			case IMAP_SEARCH_BEFORE: /* INTERNALDATE < */
				SEARCH_STAT()
				if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */
					bbs_warning("Failed to parse as date: %s\n", skey->child.string);
					break;
				}
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				retval = difftime(t1, t2) < 0 || TM_DATE_EQUAL(tm1, tm2);
				break;
			case IMAP_SEARCH_SINCE: /* INTERNALDATE >=, e.g. 08-Mar-2011 */
				SEARCH_STAT()
				if (!strptime(skey->child.string, "%d-%b-%Y", &tm2)) { /* We currently parse the date each time needed. */
					bbs_warning("Failed to parse as date: %s\n", skey->child.string);
					break;
				}
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				retval = difftime(t1, t2) > 0;
				break;
			case IMAP_SEARCH_OLDER: /* like BEFORE, but with # seconds */
				SEARCH_STAT()
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = search->now;
				/* Since all INTERNALDATEs must be in the past, we expect difftime is always negative (tm1 < tm2, e.g. tm1 < now) */
				retval = difftime(t1, t2) <= -skey->child.number;
				break;
			case IMAP_SEARCH_YOUNGER: /* like SINCE, but with # seconds */
				SEARCH_STAT()
				localtime_r(&search->st.st_mtim.tv_sec, &tm1);
				t1 = mktime(&tm1);
				t2 = search->now;
				/* Since all INTERNALDATEs must be in the past, we expect difftime is always negative (tm1 < tm2, e.g. tm1 < now) */
				retval = difftime(t1, t2) >= -skey->child.number;
				break;
			case IMAP_SEARCH_SUBJECT:
				SEARCH_HEADER_MATCH("Subject");
			case IMAP_SEARCH_TEXT: /* In header or body */
				retval = search_message(search, skey->child.string, 1, 1);
				break;
			case IMAP_SEARCH_TO:
				SEARCH_HEADER_MATCH("To");
			case IMAP_SEARCH_NOT: /* 1 child, negate the result. */
				retval = !search_keys_eval(skey->child.keys, IMAP_SEARCH_NOT, search);
				break;
			case IMAP_SEARCH_OR: /* 2 children, only one of which must be true */
				retval = search_keys_eval(skey->child.keys, IMAP_SEARCH_OR, search);
				break;
			case IMAP_SEARCH_AND: /* An arbitrary number of children, all of which must be true */
				retval = search_keys_eval(skey->child.keys, IMAP_SEARCH_AND, search);
				break;
			case IMAP_SEARCH_ALL: /* Implicitly always true */
				break;
			default:
				bbs_warning("Invalid key: %d\n", skey->type);
				break;
		}
		/* Short circuit by stopping if any of the expressions turns out to be false... unless we're ORing (where we stop on the first one that's true). */
		if (type == IMAP_SEARCH_OR && retval) {
#ifdef DEBUG_SEARCH
			bbs_debug(5, "Short-circuiting since OR contains at least one true expression (%s)\n", imap_search_key_name(skey->type));
#endif
			break;
		} else if (type != IMAP_SEARCH_OR && !retval) {
#ifdef DEBUG_SEARCH
			bbs_debug(5, "Failed to match condition %s\n", imap_search_key_name(skey->type));
#endif
			break;
		}
	}
	return retval;
}

/*! \note For some reason, looping twice or using goto results in valgrind reporting a memory leak, but calling this function twice does not */
static int search_dir(struct imap_session *imap, const char *dirname, int newdir, int usinguid, struct imap_search_keys *skeys, unsigned int **a, int *lengths, int *allocsizes, int *min, int *max, unsigned long *maxmodseq)
{
	int files, fno = 0;
	struct dirent *entry, **entries = NULL;
	struct imap_search search;
	unsigned int uid;
	unsigned int seqno = 0;
	char keywords[27] = "";
	int now;

	now = (int) time(NULL); /* Only compute this once, not for each file */

	files = scandir(dirname, &entries, NULL, imap_uidsort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", dirname, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto next;
		} else if (entry->d_type != DT_REG) { /* We only care about directories, not files. */
			goto next;
		}
		seqno++;
#ifdef DEBUG_SEARCH
		bbs_debug(10, "Checking message %u: %s\n", seqno, entry->d_name);
#endif
		memset(&search, 0, sizeof(search));
		search.imap = imap;
		search.directory = dirname;
		search.filename = entry->d_name;
		SET_BITFIELD(search.new, newdir);
		search.seqno = (int) seqno;
		search.keywords = keywords;
		search.now = now;
		search.maxmodseq = *maxmodseq;
		/* Parse the flags just once in advance, since doing bit field comparisons is faster than strchr */
		if (parse_flags_letters_from_filename(search.filename, &search.flags, keywords)) {
			goto next;
		}
		if (search_keys_eval(skeys, IMAP_SEARCH_ALL, &search)) {
			/* Include in search response */
			if (usinguid) {
				if (maildir_parse_uid_from_filename(search.filename, &uid)) {
					continue;
				}
			} else {
				uid = seqno; /* Not really, but use the same variable for both */
			}
			uintlist_append(a, lengths, allocsizes, uid);
			if (min) {
				if (*min == -1 || (int) uid < *min) {
					*min = (int) uid;
				}
			}
			if (max) {
				if (*max == -1 || (int) uid > *max) {
					*max = (int) uid;
				}
			}
			*maxmodseq = search.maxmodseq;
			/* We really only need uintlist_append1, but just reuse the API used for COPY */
#ifdef DEBUG_SEARCH
			bbs_debug(5, "Including message %u (%s) in response\n", seqno, entry->d_name);
#endif
		}
		/* If we opened any resources, close them */
		if (search.fp) {
			fclose(search.fp);
		}
next:
		free(entry);
	}
	free(entries);
	return 0;
}

/*! \retval -1 on failure, number of search results on success */
static int do_search(struct imap_session *imap, char *s, unsigned int **a, int usinguid, int *min, int *max, unsigned long *maxmodseq)
{
	int lengths = 0, allocsizes = 0;
	struct imap_search_keys skeys; /* At the least the top level list itself will be stack allocated. */

	/* IMAP uses polish notation, which makes for somewhat easier parsing (can do one pass left to right) */
	/* Because of search keys like NOT, as well as being able to have multiple search keys of the same type,
	 * we can't just trivially "compile" the SEARCH query into a struct and use that for fast matching.
	 * We do in fact compile once here, but it requires a more involved parser since it can have multilevel depth.
	 * For now, we just evaluate the query left to right on every message in a mailbox folder.
	 * Note that IMAP SEARCH results should not be assumed by the client to be in any particular order.
	 * However, conventionally they are in ascending order, even though the RFC does not specify any order.
	 */

	/* Parsing example:
	 * NOT FLAGGED OR FROM 'John' FROM 'Paul'
	 * !flagged && (FROM 'John' || FROM 'Paul')
	 *
	 * Essentially, we end up at the top level with a linked list of imap_search_key structures.
	 * Each of these is ANDed together, i.e. all the keys at the top level list must be satisfied for a message to match.
	 * Within each imap_search_key in this list, we could have further keys that are themselves lists.
	 */

	/* Initialize */
	*min = -1;
	*max = -1;
	*maxmodseq = 0;

	memset(&skeys, 0, sizeof(skeys));
	/* If we didn't consume the entire search expression before returning, then this is invalid */
	if (parse_search_query(imap, &skeys, IMAP_SEARCH_ALL, &s) || !strlen_zero(s)) {
		imap_search_free(&skeys);
		imap_reply(imap, "BAD [CLIENTBUG] Invalid search query");
		bbs_warning("Failed to parse search query\n"); /* Consumed the query in the process, but should be visible in a previous debug message */
		return -1;
	}

#ifdef DEBUG_SEARCH
	{
		struct dyn_str dynstr;
		memset(&dynstr, 0, sizeof(dynstr));
		dump_imap_search_keys(&skeys, &dynstr, 0);
		bbs_debug(3, "IMAP search tree:\n%s", dynstr.buf);
		free(dynstr.buf);
	}
#endif

	search_dir(imap, imap->curdir, 0, usinguid, &skeys, a, &lengths, &allocsizes, min, max, maxmodseq);
	search_dir(imap, imap->newdir, 1, usinguid, &skeys, a, &lengths, &allocsizes, min, max, maxmodseq);
	imap_search_free(&skeys);
	return lengths;
}

#define ESEARCH_ALL (1 << 0)
#define ESEARCH_COUNT (1 << 1)
#define ESEARCH_MIN (1 << 2)
#define ESEARCH_MAX (1 << 3)
#define ESEARCH_SAVE (1 << 4)

#define ESEARCH_MINMAX (ESEARCH_MIN | ESEARCH_MAX)
#define ESEARCH_STATS (ESEARCH_COUNT | ESEARCH_MIN | ESEARCH_MAX)
#define ESEARCH_RESULTS (ESEARCH_MIN | ESEARCH_MAX | ESEARCH_COUNT | ESEARCH_ALL)

#define ESEARCH_NEED_ALL(f) (f & ESEARCH_ALL || (f & ESEARCH_SAVE && !(f & ESEARCH_MINMAX)))

static int parse_search_options(char *s)
{
	int flags = 0;
	char *option;

	if (strlen_zero(s)) {
		return ESEARCH_ALL; /* for () */
	}

	while ((option = strsep(&s, " "))) {
		if (!strcmp(option, "COUNT")) {
			flags |= ESEARCH_COUNT;
		} else if (!strcmp(option, "MIN")) {
			flags |= ESEARCH_MIN;
		} else if (!strcmp(option, "MAX")) {
			flags |= ESEARCH_MAX;
		} else if (!strcmp(option, "ALL")) {
			flags |= ESEARCH_ALL;
		} else if (!strcmp(option, "SAVE")) {
			flags |= ESEARCH_SAVE;
		} else {
			bbs_warning("Unsupported ESEARCH option: %s\n", option);
		}
	}
	return flags;
}

static int parse_return_options(struct imap_session *imap, char **str, int *option_flags)
{
	char *s = *str;
	if (STARTS_WITH(s, "RETURN (")) {
		char *options;
		s += STRLEN("RETURN (");
		options = s;
		s = strchr(s, ')');
		if (!s) {
			imap_reply(imap, "BAD [CLIENTBUG] Unterminated argument");
			return -1;
		}
		*s++ = '\0';
		if (*s == ' ') {
			s++;
		}
		*str = s;
		*option_flags = parse_search_options(options);
		return 1;
	}
	*option_flags = 0;
	return 0;
}

static void esearch_response(struct imap_session *imap, int option_flags, unsigned int *a, int results, int min, int max, unsigned long maxmodseq, int usinguid)
{
	char *list = NULL;
	if (results) {
		char buf[96] = "";
		char *pos = buf;
		size_t buflen = sizeof(buf);

		if (ESEARCH_NEED_ALL(option_flags)) {
			/* For ESEARCH responses, we can send ranges, but for regular SEARCH, the RFC specifically says they are all space delimited */
			list = uintlist_to_ranges(a, results);
		}
		SAFE_FAST_COND_APPEND(buf, sizeof(buf), pos, buflen, option_flags & ESEARCH_MIN, "MIN %d", min);
		SAFE_FAST_COND_APPEND(buf, sizeof(buf), pos, buflen, option_flags & ESEARCH_MAX, "MAX %d", max);
		SAFE_FAST_COND_APPEND(buf, sizeof(buf), pos, buflen, option_flags & ESEARCH_COUNT, "COUNT %d", results);
		/* There is an exception to the RFC 7162 MODSEQ response for SEARCH/SORT,
		 * and it is outlined in RFC 4731 3.2:
		 * Basically, we return the highest MODSEQ as usual, UNLESS:
		 * - Just MIN or MAX: MODSEQ corresponds to that particular message
		 * - Only MIN and MAX (no ALL, COUNT): MODSEQ is the higher of these two messages
		 */
		if (option_flags & ESEARCH_MINMAX && !(option_flags & (ESEARCH_ALL | ESEARCH_COUNT))) {
			char filename[256];
			/* Probably faster to just lookup the message here than keep track throughout the search, just for this edge case */
			maxmodseq = 0;
			if (option_flags & ESEARCH_MIN && option_flags & ESEARCH_MAX) {
				unsigned long othermodseq;
				/* Highest of both of them */
				imap_msg_to_filename(imap->curdir, usinguid ? 0 : min, usinguid ? (unsigned int) min : 0, filename, sizeof(filename));
				parse_modseq_from_filename(filename, &maxmodseq);
				imap_msg_to_filename(imap->curdir, usinguid ? 0 : max, usinguid ? (unsigned int) max : 0, filename, sizeof(filename));
				parse_modseq_from_filename(filename, &othermodseq);
				maxmodseq = MAX(maxmodseq, othermodseq);
			} else {
				int target = (option_flags & ESEARCH_MIN) ? min : max;
				/* One corresponding to the particular message */
				imap_msg_to_filename(imap->curdir, usinguid ? 0 : target, usinguid ? (unsigned int) target : 0, filename, sizeof(filename));
				parse_modseq_from_filename(filename, &maxmodseq);
			}
		}
		SAFE_FAST_COND_APPEND(buf, sizeof(buf), pos, buflen, maxmodseq, "MODSEQ %lu", maxmodseq);

		if (option_flags & ESEARCH_RESULTS) {
			imap_send(imap, "ESEARCH (TAG \"%s\")%s%s%s %s%s", imap->tag, usinguid ? " UID" : "", option_flags & ESEARCH_STATS ? " " : "", buf, list ? "ALL " : "", S_IF(list));
		}

		if (option_flags & ESEARCH_SAVE) {
			/* RFC 5182 2.4 defines what SAVE refers to if multiple options are specified. */
			free_if(imap->savedsearch);
			if (option_flags & ESEARCH_MINMAX) {
				buf[0] = '\0';
				pos = buf;
				buflen = sizeof(buf);
				SAFE_FAST_COND_APPEND(buf, sizeof(buf), pos, buflen, option_flags & ESEARCH_MIN, "%d", min);
				SAFE_FAST_COND_APPEND(buf, sizeof(buf), pos, buflen, option_flags & ESEARCH_MAX, "%d", max);
				imap->savedsearch = strdup(buf);
			} else {
				/* Implicit ALL is saved */
				imap->savedsearch = list; /* Just steal this pointer. */
				list = NULL;
			}
			/* RFC 5182 2.1 says that $ can reference message sequences or UID sequences...
			 * and furthermore, it can be stored using one and referenced using another!
			 * WHY on earth any client would do that, I don't know, but this is possible...
			 *
			 * What we have to do to account for this is that if $ is used in a UID command
			 * but savedsearchuid == 0, for the purposes of matching messages, we treat it
			 * as the non UID version.
			 * Likewise, if savedsearchuid == 1, and $ is dereferenced in a non-UID command,
			 * we have to match on UIDs, not sequence numbers.
			 */
			SET_BITFIELD(imap->savedsearchuid, usinguid);
		}
		free_if(list);
	} else {
		if (option_flags & ESEARCH_RESULTS) {
			imap_send(imap, "ESEARCH (TAG \"%s\") %sCOUNT 0", imap->tag, usinguid ? "UID " : ""); /* No results, but still need to send an empty untagged response */
		}
		if (option_flags & ESEARCH_SAVE) {
			REPLACE(imap->savedsearch, "");
			SET_BITFIELD(imap->savedsearchuid, usinguid);
		}
	}
}

int handle_search(struct imap_session *imap, char *s, int usinguid)
{
	unsigned int *a = NULL;
	int results;
	int min, max;
	unsigned long maxmodseq;
	char *list = NULL;
	int options, option_flags;

	options = parse_return_options(imap, &s, &option_flags); /* ESEARCH */
	if (options < 0) {
		return 0;
	}

	results = do_search(imap, s, &a, usinguid, &min, &max, &maxmodseq);
	if (results < 0) {
		return 0;
	}

	if (options > 0) { /* ESEARCH */
		esearch_response(imap, option_flags, a, results, min, max, maxmodseq, usinguid);
	} else {
		if (results) {
			/* If non-empty result and MODSEQ was specified, maxmodseq will be > 0, and we'll need to append this to the response */
			list = uintlist_to_str(a, results);
			if (maxmodseq) {
				imap_send(imap, "SEARCH %s (MODSEQ %lu)", S_IF(list), maxmodseq);
			} else {
				imap_send(imap, "SEARCH %s", S_IF(list));
			}
			free_if(list);
		} else {
			imap_send(imap, "SEARCH"); /* No results, but still need to send an empty untagged response */
		}
	}

	free_if(a);
	imap_reply(imap, "OK %sSEARCH completed%s", usinguid ? "UID " : "", option_flags & ESEARCH_SAVE ? ", result saved" : "");
	return 0;
}

struct imap_sort {
	struct imap_session *imap;
	struct dirent **entries;
	const char *sortexpr;
	int numfiles;
	unsigned int usinguid:1;
};

static int msg_to_filename(struct imap_sort *sort, unsigned int number, int usinguid, char *buf, size_t len)
{
	struct dirent *entry, **entries = sort->entries;
	int fno = 0;
	unsigned int seqno = 0;

	while (fno < sort->numfiles && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		seqno++;
		if (usinguid) {
			unsigned int uid;
			maildir_parse_uid_from_filename(entry->d_name, &uid);
			if (uid == number) {
				snprintf(buf, len, "%s/%s", sort->imap->curdir, entry->d_name);
				return 0;
			}
		} else {
			if (seqno == number) {
				snprintf(buf, len, "%s/%s", sort->imap->curdir, entry->d_name);
				return 0;
			}
		}
	}
	bbs_warning("Couldn't find match for %s %d?\n", usinguid ? "UID" : "seqno", number);
	return -1;
}

#define SKIP_STR(var, str) \
	if (STARTS_WITH(var, str)) { \
		var += STRLEN(str); \
	}

/*! \brief Skip prefixes according to RFC 5256 */
#define SKIP_PREFIXES(var) \
	for (skips = 1; !skips ;) { \
		skips = 0; \
		ltrim(a); \
		SKIP_STR(a, "Re:"); \
		SKIP_STR(a, "Fwd:"); \
	}

static int subjectcmp(const char *a, const char *b)
{
	int skips;

	/* Deal with empty subjects */
	if (strlen_zero(a)) {
		return -1;
	} else if (strlen_zero(b)) {
		return 1;
	}

	SKIP_PREFIXES(a);
	SKIP_PREFIXES(b);
	return strcasecmp(a, b);
}

/*! \retval -1 if a comes before b, 1 if b comes before a, and 0 if they are equal (according to sort criteria) */
static int sort_compare(const void *aptr, const void *bptr, void *varg)
{
	const unsigned int *ap = aptr;
	const unsigned int *bp = bptr;
	const unsigned int a = *ap;
	const unsigned int b = *bp;
	struct imap_sort *sort = varg;

	char filename_a[516];
	char filename_b[516];
	char buf1[128], buf2[128];
	const char *criterion;
	int reverse = 0;
	int res;
	int hdra, hdrb;
	FILE *fpa = NULL, *fpb = NULL;
	struct tm tm1, tm2;
	time_t t1, t2;
	long int diff;

	/* If sort->usinguid, then we are comparing UIDs.
	 * Otherwise, we're comparing sequence numbers. */

	/* This is a case where it would be really nice to have some kind of index
	 * of all the messages in the mailbox.
	 * Without that, we have no alternative but to open all the messages if needed.
	 * This is particularly yucky since just looking for the file involves a linear scan of the directory.
	 * Even just having an index mapping seqno/UIDs -> filenames (like dovecot has) would be useful.
	 * For now, we optimize by only calling scandir() once for the sort, and just iterating over the list
	 * each time. This is actually necessary for correctness as well, since the list of files
	 * MUST NOT CHANGE in the middle of a sort.
	 */

	if (msg_to_filename(sort, a, sort->usinguid, filename_a, sizeof(filename_a))) {
		return 0;
	} else if (msg_to_filename(sort, b, sort->usinguid, filename_b, sizeof(filename_b))) {
		return 0;
	}

	res = 0;
	memset(&tm1, 0, sizeof(tm1));
	memset(&tm2, 0, sizeof(tm2));

#define OPEN_FILE_IF_NEEDED(fp, fname) \
	if (fp) { \
		rewind(fp); \
	} else { \
		fp = fopen(fname, "r"); \
		if (!fp) { \
			bbs_error("Failed to open %s: %s\n", fname, strerror(errno)); \
			break; \
		} \
	}

#define GET_HEADERS(header) \
	OPEN_FILE_IF_NEEDED(fpa, filename_a); \
	OPEN_FILE_IF_NEEDED(fpb, filename_b); \
	hdra = get_header(fpa, header, STRLEN(header), buf1, sizeof(buf1)); \
	hdrb = get_header(fpb, header, STRLEN(header), buf2, sizeof(buf2)); \
	if (hdra && hdrb) { \
		reverse = 0; \
		continue; \
	} else if (hdra) { \
		res = 1; \
		break; \
	} else if (hdrb) { \
		res = -1; \
		break; \
	}

	/* To avoid having to duplicate the string for every single comparison,
	 * parse the string in place. */
	for (criterion = sort->sortexpr; !res && !strlen_zero(criterion); criterion = strchr(criterion, ' ')) {
		char *space;
		int len;
		if (*criterion == ' ') { /* All but first one */
			criterion++;
			if (strlen_zero(criterion)) {
				break;
			}
		}
		/* Must use STARTS_WITH (strncasecmp) since the criterion is NOT null terminated. */
		/* Break as soon as we have an unambiguous winner. */
		space = strchr(criterion, ' ');
		len = space ? (int) (space - criterion) : (int) strlen(criterion);

#ifdef DEBUG_SORT
		bbs_debug(10, "Processing next SORT token: %.*s\n", len, criterion);
#endif

		if (STARTS_WITH(criterion, "ARRIVAL")) {
			/* INTERNALDATE *AND* time! */
			struct stat stata, statb;
			hdra = stat(filename_a, &stata);
			hdrb = stat(filename_b, &statb);
			if (hdra || hdrb) {
				res = hdra ? hdrb ? 0 : -1 : 1; /* If a date is invalid, it sorts first */
			} else {
				diff = (long int) difftime(stata.st_mtime, statb.st_mtime); /* If difftime is positive, tm1 > tm2 */
				res = diff > 0 ? 1 : diff < 0 ? -1 : 0;
			}
		} else if (STARTS_WITH(criterion, "CC")) {
			GET_HEADERS("Cc");
			res = strcasecmp(buf1, buf2);
		} else if (STARTS_WITH(criterion, "DATE")) {
			GET_HEADERS("Date");
			bbs_strterm(buf1, '\r');
			bbs_strterm(buf2, '\r');
			hdra = bbs_parse_rfc822_date(buf1, &tm1);
			hdrb = bbs_parse_rfc822_date(buf2, &tm2);
			if (hdra || hdrb) {
				res = hdra ? hdrb ? 0 : -1 : 1; /* If a date is invalid, it sorts first */
			} else {
				t1 = mktime(&tm1);
				t2 = mktime(&tm2);
				diff = (long int) difftime(t1, t2); /* If difftime is positive, tm1 > tm2 */
				res = diff > 0 ? 1 : diff < 0 ? -1 : 0;
			}
		} else if (STARTS_WITH(criterion, "FROM")) {
			GET_HEADERS("From");
			res = strcasecmp(buf1, buf2);
		} else if (STARTS_WITH(criterion, "REVERSE")) {
			reverse = 1;
			continue;
		} else if (STARTS_WITH(criterion, "SIZE")) {
			long unsigned int sizea, sizeb;
			/* This is the easiest one. Everything we need is in the filename already. */
			parse_size_from_filename(filename_a, &sizea);
			parse_size_from_filename(filename_b, &sizeb);
			res = sizea < sizeb ? -1 : sizea > sizeb ? 1 : 0;
		} else if (STARTS_WITH(criterion, "SUBJECT")) {
			GET_HEADERS("Subject");
			res = subjectcmp(buf1, buf2);
		} else if (STARTS_WITH(criterion, "TO")) {
			GET_HEADERS("To");
			res = strcasecmp(buf1, buf2);
		} else {
			bbs_warning("Invalid SORT criterion: %.*s\n", len, criterion);
		}
		if (reverse && res) {
			res = -res; /* Invert if needed */
		}
		reverse = 0;
	}

	if (fpa) {
		fclose(fpa);
	}
	if (fpb) {
		fclose(fpb);
	}

	/* Final tie breaker. Pick the message with the smaller sequence number. */
	if (!res) {
		res = a < b ? -1 : a > b ? 1 : 0;
	}

#ifdef DEBUG_SORT
	bbs_debug(7, "Sort compare = %d: %s <=> %s: %s\n", res, filename_a, filename_b, sort->sortexpr);
#endif

	return res;
}

int handle_sort(struct imap_session *imap, char *s, int usinguid)
{
	int results;
	char *sortexpr, *charset, *search;
	unsigned int *a = NULL;
	int options, option_flags;
	int min, max;
	unsigned long maxmodseq;

	options = parse_return_options(imap, &s, &option_flags); /* ESORT */
	if (options < 0) {
		return 0;
	}

	/* e.g. A283 SORT (SUBJECT REVERSE DATE) UTF-8 ALL (RFC 5256) */
	if (*s == '(') {
		sortexpr = s + 1;
		s = strchr(sortexpr, ')');
		REQUIRE_ARGS(s);
		*s = '\0';
		s++;
		REQUIRE_ARGS(s);
		s++;
		REQUIRE_ARGS(s);
	} else {
		sortexpr = strsep(&s, " ");
	}
	charset = strsep(&s, " ");
	search = s;

	REQUIRE_ARGS(charset); /* This is mandatory in the RFC, though we ignore this, apart from checking it. */
	REQUIRE_ARGS(search);

	if (strcasecmp(charset, "UTF-8") && strcasecmp(charset, "US-ASCII")) {
		imap_reply(imap, "NO [BADCHARSET] (UTF-8 US_ASCII) Charset %s not supported", charset);
		return 0;
	}

	/* This is probably something that could be made a lot more efficient.
	 * Initially here, our concern is with simplicity and correctness,
	 * but sorting and searching could probably use lots of optimizations. */

	/* First, search for any matching messages. */
	results = do_search(imap, search, &a, usinguid, &min, &max, &maxmodseq);
	if (results < 0) {
		return 0;
	}

	/* Now, look at the messages matching the sort and sort only those.
	 * Consider that searching is a linear operation while sorting is logarthmic.
	 * In the ideal case, searching eliminated most messages and sorting
	 * on this filtered set will thus be much more efficient than sorting quickly, or in conjunction with searching.
	 * However, if we have something like SEARCH ALL, we are going to sort everything anyways,
	 * in which case this second pass essentially duplicates all the work done by the search, and then some.
	 */

	/* Sort if needed */
	if (options == 0 || option_flags & ESEARCH_ALL) {
		struct imap_sort sort;
		memset(&sort, 0, sizeof(sort));
		sort.imap = imap;
		sort.sortexpr = sortexpr;
		SET_BITFIELD(sort.usinguid, usinguid);
		sort.numfiles = scandir(imap->curdir, &sort.entries, NULL, imap_uidsort); /* cur dir only */
		if (sort.numfiles >= 0) {
			qsort_r(a, (size_t) results, sizeof(unsigned int), sort_compare, &sort); /* Actually sort the results, conveniently already in an array. */
			bbs_free_scandir_entries(sort.entries, sort.numfiles);
			free(sort.entries);
		}
	}

	if (options > 0) { /* ESORT */
		esearch_response(imap, option_flags, a, results, min, max, maxmodseq, usinguid);
	} else {
		if (results) {
			char *list;
			list = uintlist_to_str(a, results);
			if (maxmodseq) {
				imap_send(imap, "SORT %s (MODSEQ %lu)", S_IF(list), maxmodseq);
			} else {
				imap_send(imap, "SORT %s", S_IF(list));
			}
			free_if(list);
		} else {
			imap_send(imap, "SORT"); /* No matches */
		}
	}

	free_if(a);
	imap_reply(imap, "OK %sSORT completed", usinguid ? "UID " : "");
	return 0;
}

/* == Threading == */

enum thread_algorithm {
	THREAD_ALG_ORDERED_SUBJECT,
	THREAD_ALG_REFERENCES,
};

struct thread_message {
	unsigned int id;
	struct tm sent;
	char *references;
	char *msgid;
	struct thread_message *parent;
	struct thread_message *child;
	/* Use fixed size buffers, to reduce the number of allocations, to avoid excessive memory fragmentation */
	char subject[128];
	char inreplyto[128];
};

static void free_thread_messages(struct thread_message *msgs, size_t length)
{
	size_t i;
	for (i = 0; i < length; i++) {
		free_if(msgs[i].msgid);
		free_if(msgs[i].references);
	}
	free(msgs);
}

static int populate_thread_data(struct imap_session *imap, struct thread_message *msgs, unsigned int *a, int length, int usinguid)
{
	char filename[256];
	int i;
	struct imap_sort sort;

	/* We're not going to sort anything here. We just need a sort structure to use the msg_to_filename API.
	 * We obviously don't want to call scandir or opendir for each message. */
	memset(&sort, 0, sizeof(sort));
	sort.imap = imap;
	sort.numfiles = scandir(imap->curdir, &sort.entries, NULL, imap_uidsort); /* cur dir only */
	if (sort.numfiles < 0) {
		return -1;
	}

	for (i = 0; i < length; i++) {
		char linebuf[1024];
		struct dyn_str dynstr;
		int gotinfo = 0, in_ref = 0;
		FILE *fp;

		memset(&dynstr, 0, sizeof(dynstr));

		if (msg_to_filename(&sort, a[i], usinguid, filename, sizeof(filename))) {
			continue;
		}

		/* Retrieve anything from the message that may be useful in trying to thread it during the algorithm.
		 * After this, we never peek inside the message again. */
		fp = fopen(filename, "r");
		if (!fp) {
			continue;
		}
		while ((fgets(linebuf, sizeof(linebuf), fp))) {
			/* fgets does store the newline, so line should end in CR LF */
			if (in_ref) {
				if (linebuf[0] == ' ') {
					/* Already starts with a space, conveniently, so we can just go ahead and append immediately. */
					int len = bbs_term_line(linebuf);
					dyn_str_append(&dynstr, linebuf, (size_t) len);
					continue;
				} else {
					in_ref = 0;
					gotinfo++;
				}
			}
			if (gotinfo == 5 || !strcmp(linebuf, "\r\n")) {
				break; /* End of headers, or got everything we need already, whichever comes first. */
			}
			if (STARTS_WITH(linebuf, "Date:")) {
				char *s = linebuf + STRLEN("Date:");
				ltrim(s);
				bbs_term_line(s);
				bbs_parse_rfc822_date(s, &msgs[i].sent);
				gotinfo++;
			} else if (STARTS_WITH(linebuf, "In-Reply-To:")) {
				char *s = linebuf + STRLEN("In-Reply-To:");
				ltrim(s);
				bbs_term_line(s);
				safe_strncpy(msgs[i].inreplyto, s, sizeof(msgs[i].inreplyto));
				gotinfo++;
			} else if (STARTS_WITH(linebuf, "Subject:")) {
				char *s = linebuf + STRLEN("Subject:");
				ltrim(s);
				bbs_term_line(s);
				/* Don't normalize subject here. subjectcmp will handle that when needed. */
				safe_strncpy(msgs[i].subject, s, sizeof(msgs[i].subject));
				gotinfo++;
			} else if (STARTS_WITH(linebuf, "Message-ID:")) {
				char *s = linebuf + STRLEN("Message-ID:");
				ltrim(s);
				bbs_term_line(s);
				REPLACE(msgs[i].msgid, s);
				gotinfo++;
			} else if (STARTS_WITH(linebuf, "References:")) {
				/* The References header may consist of many lines, since it can contain many lines.
				 * The other headers we expect to only be one line so can handle more simply. */
				char *s = linebuf + STRLEN("References:");
				int len;
				ltrim(s);
				len = bbs_term_line(s);
				dyn_str_append(&dynstr, s, (size_t) len);
				in_ref = 1;
			}
		}
		fclose(fp);
		/* We already allocated References... may as well just use that. */
		msgs[i].references = dynstr.buf;
		msgs[i].id = a[i];
	}

	bbs_free_scandir_entries(sort.entries, sort.numfiles);
	free(sort.entries);
	return 0;
}

#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
static int thread_ordered_subject_compare(const void *aptr, const void *bptr)
{
	const struct thread_message *a = aptr;
	const struct thread_message *b = bptr;
	int res;

	res = subjectcmp(a->subject, b->subject);
	if (!res) {
		/* Subjects match. Use date as a tiebreaker. */
		int t1, t2;
		long diff;
		struct thread_message *ac = (struct thread_message*) a, *bc = (struct thread_message*) b; /* discard const pointer for mktime */
		t1 = (int) mktime(&ac->sent);
		t2 = (int) mktime(&bc->sent);
		diff = (long int) difftime(t1, t2); /* If difftime is positive, tm1 > tm2 */
		res = diff < 0 ? -1 : diff > 0 ? 1 : 0;
	}
	return res;
}
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop

/*! \note This struct uses a doubly linked list to keep track of all messages in a flat hierarchy, but internally there is also a hierarchy for threads */
struct thread_messageid {
	struct thread_messageid *llnext;	/* Next item in linked list. Must be first for <search.h>. */
	struct thread_messageid *llprev;	/* Previous item in linked list. Must be second for <search.h>. */
	const char *msgid;					/* Message ID */
	struct thread_messageid *parent;	/* Parent */
	struct thread_messageid *children;	/* First child in the thread (all children can be obtained by traversing the next point on children) */
	struct thread_messageid *next; 		/* Next sibling in the thread */
	struct tm *sent;
	unsigned int id;					/* ID (sequence number or UID) */
	unsigned int dummy:1;				/* Dummy message created by the threading algorithm? */
	char data[0];
};

static struct thread_messageid *find_thread_msgid_any(struct thread_messageid *msgids, const char *msgid)
{
	struct thread_messageid *t = msgids;

	while (t) { /* Check all of them. Don't care about parent/child relationships. */
		if (!strcmp(msgid, t->msgid)) { /* Message ID comparisons are case sensitive */
			return t;
		}
		t = t->llnext;
	}
	return NULL;
}

/*! \brief Same as find_thread_msgid_related, but faster if target pointer already known since we can do pointer comparisons */
static struct thread_messageid *find_thread_msgid_related_ptr(struct thread_messageid *a, struct thread_messageid *b)
{
	struct thread_messageid *t;

	/* Check all our children */
	if (a->children) {
		t = find_thread_msgid_related_ptr(a->children, b);
		if (t) {
			return t;
		}
	}

	/* Check all our siblings */
	t = a;
	while (t) {
		if (a == b) {
			return t;
		}
		t = t->next;
	}
	return NULL;
}

static struct thread_messageid *push_threadmsgid(struct thread_messageid *msgids, const char *msgid, int dummy)
{
	struct thread_messageid *curmsg;

	curmsg = calloc(1, sizeof(*curmsg) + strlen(msgid) + 1);
	if (ALLOC_FAILURE(curmsg)) {
		return NULL;
	}
	strcpy(curmsg->data, msgid); /* Safe */
	curmsg->msgid = curmsg->data;
	SET_BITFIELD(curmsg->dummy, dummy);

	/* Insert (head insert) */
	insque(curmsg, msgids);
	return curmsg;
}

/*! \todo XXX Combine this function with the above */
static struct thread_messageid *append_threadmsgid(struct thread_messageid *prev, const char *msgid)
{
	struct thread_messageid *curmsg;

	curmsg = calloc(1, sizeof(*curmsg) + strlen(msgid) + 1);
	if (ALLOC_FAILURE(curmsg)) {
		return NULL;
	}
	strcpy(curmsg->data, msgid); /* Safe */
	curmsg->msgid = curmsg->data;
	curmsg->dummy = 0;

	/* Insert (tail insert) */
	insque(curmsg, prev);
	return curmsg;
}

static void free_thread_msgids(struct thread_messageid *msgids)
{
	struct thread_messageid *t = msgids;
	t = t->llnext; /* Skip t itself, since it's stack allocated and it's the dummy root. */
	while (t) {
		struct thread_messageid *cur = t;
		t = t->llnext;
		free(cur);
	}
}

#ifdef DEBUG_THREADING
static char spaces[] = "                                                                        ";

#define MAX_THREAD_DEPTH 128

static int __dump_thread(struct thread_messageid *msgids, int level, unsigned int maxcount)
{
	struct thread_messageid *t;
	int c = 0;

	if (!msgids) {
		bbs_debug(7, "Nothing at this level\n");
		return 0;
	}

	/* Iterate over everything at this level. */
	t = msgids;
#if 0
	bbs_debug(8, "Thread root: %s - children: %d\n", t->msgid, msgids->children ? 1 : 0);
#endif
	while (t) {
		static char buf[100];
		char date[21] = "";
		const char *msgid = bbs_str_isprint(t->msgid) ? t->msgid : "(unprintable)";
		if (t->sent) {
			strftime(date, sizeof(date), "%d %b %Y %H:%M:%S", t->sent);
		}
		snprintf(buf, sizeof(buf), "%.*s%s %s", level, spaces, level ? "|-" : "", msgid);
		bbs_debug(5, "%20s [%2d%c] %s [%d] %p\n", date, level, t->children ? '+' : ' ', buf, t->id, t);
		c++;
		/* If there's a bug in our threading logic and we have a loop, don't keep going forever */
		if (level > (int) maxcount) {
			bbs_error("Folder only has %d messages, but we've recursed to level %d?\n", maxcount, level);
			break;
		} else if (level > MAX_THREAD_DEPTH) {
			/* Very deep threads are possible... but probably not super common. Either way, avoid stack overflow. */
			bbs_warning("Reached maximum thread depth exceed (%d), aborting\n", maxcount);
			break;
		}
		/* Iterate over children, if any. */
		if (t->children) {
			c += __dump_thread(t->children, level + 1, maxcount);
		}
		t = t->next;
	}

	return c;
}

static void dump_thread_msgids(struct thread_messageid *msgids, unsigned int maxcount)
{
	struct thread_messageid *t;
	int d = 0, c = 0;

	t = msgids;
	t = msgids->llnext; /* Skip the dummy root */
	while (t) {
		c++;
		/* Recursively dump anything that doesn't have a parent (since these are the top level of a thread)
		 * and they will handle all their children. */
		if (!t->parent) {
			d += __dump_thread(t, 0, maxcount);
		}
		t = t->llnext;
	}
	if (c != d) {
		/* If not all messages are reachable from the root, we've corrupted the pointers somewhere. */
		bbs_error("%d total messages, but only %d reachable in threads?\n", c, d);
	} else {
		bbs_debug(5, "%d total messages, %d reachable in threads\n", c, d);
	}
}
#endif /* DEBUG_THREADING */

static void thread_link_parent_child(struct thread_messageid *parent, struct thread_messageid *child)
{
	struct thread_messageid *tmp;

	/* If message already has a parent, don't change the existing link */
	if (child->parent) {
#ifdef DEBUG_THREADING
		if (child->parent != parent) {
			bbs_debug(3, "Message %s already has another parent (%s)\n", child->msgid, child->parent->msgid);
		}
#endif
		return;
	}

	/* Don't create a link if that would introduce a loop. */

	/* Make sure that parent is not already a descendant of child,
	 * and that child is not already a parent of parent. */
	if (parent == child) {
		bbs_warning("Parent and child are the same?\n");
		return;
	}
	if (parent->parent == child) { /* If this happens, something is probably seriously whacked up */
		bbs_warning("Message %s is already the parent of %s???\n", child->msgid, parent->msgid);
		return;
	}

	/* Recursively search the child for parent. If we find parent, bail out. */
	if (find_thread_msgid_related_ptr(child, parent)) {
		bbs_warning("Message %s is already a descendant of %s, cannot also be a parent!\n", parent->msgid, child->msgid);
		return;
	}

#ifdef DEBUG_THREADING
	bbs_debug(5, "%s is now the parent of %s\n", parent->msgid, child->msgid);
#endif

	/* Make parent the parent of child */
	child->parent = parent;

	tmp = parent->children;

	/* Unlike JWZ's and the RFC algorithms, we maintain order here by inserting into the proper location.
	 * This is expected to be near constant time, since typically any particular message isn't likely to have
	 * many direct children: in a proper thread, each child has one child, and so forth...
	 * So we shouldn't have to make too many comparisons here.
	 *
	 * The advantage of doing it this way is that Step 6 of the algorithm is already done for us here,
	 * as long as we don't later perturb the ordering.
	 */
	if (tmp) {
		/* Insert at the right place to maintain order.
		 * Earlier messages come first.
		 * So insert it into the list whenever we're newer than, or reach the end of the list. */
		struct thread_messageid *prev = NULL;
		time_t t1 = child->sent ? mktime(child->sent) : 0;
		while (tmp) {
			time_t t2;
			long diff;
			t2 = tmp->sent ? mktime(tmp->sent) : 0;
			diff = (long int) difftime(t1, t2);
			if (diff < 0) {
				break;
			}
			prev = tmp;
			tmp = tmp->next;
		}
		/* Insert after the previous one (inbetween its successor) */
		if (prev) {
			child->next = prev->next;
			prev->next = child;
		} else {
			/* Insert at head of list (it's first) */
			child->next = parent->children;
			parent->children = child;
		}
	} else {
		parent->children = child;
	}
}

/*! \brief RFC 5256 REFERENCES algorithm Steps 1/2 */
static int thread_references_step1(struct thread_messageid *tmsgids, struct thread_message *msgs, int length)
{
	int i;

	tmsgids->msgid = "0"; /* This is the root. Won't match anything */
	insque(tmsgids, NULL); /* Linear list initialization - see insque(3) */

	/* Ensure we have a unique Message ID for every message */
	for (i = 0; i < length; i++) {
		struct thread_messageid *curmsg;
		/* If no Message ID present, assign a new one.
		 * All valid Message IDs probably have an '@' symbol so just use the index if unavailable. */
		if (!msgs[i].msgid) {
			bbs_debug(3, "Message %d (ID %d) does not have a Message-ID\n", i, msgs[i].id);
			if (asprintf(&msgs[i].msgid, "%d", i) < 0) {
				return -1;
			}
		}
		/* If the message does not have a unique Message ID (already exists),
		 * then treat it as if it didn't have one. */
		curmsg = find_thread_msgid_any(tmsgids, msgs[i].msgid);
		if (curmsg) {
			bbs_debug(3, "Message %d (ID %d) has a duplicate Message-ID: %s\n", i, msgs[i].id, msgs[i].msgid);
			if (asprintf(&msgs[i].msgid, "%d", i) < 0) {
				return -1;
			}
		}
		/* Now, create the thread_messageid for this message. */
		curmsg = push_threadmsgid(tmsgids, msgs[i].msgid, 0);
		if (ALLOC_SUCCESS(curmsg)) {
			curmsg->sent = &msgs[i].sent;
			curmsg->id = msgs[i].id;
		}
	}

	/* Create all the parent/child relationships between messages. */
	for (i = 0; i < length; i++) {
		char *refdup, *refs, *ref;
		struct thread_messageid *curmsg, *parentmsg = NULL, *childmsg = NULL;
		int j = 0;

		if (strlen_zero(msgs[i].references)) {
#ifdef DEBUG_THREADING
			bbs_debug(8, "Message %d (ID %d) %s does not reference any message\n", i, msgs[i].id, msgs[i].msgid); /* First in its thread, or the only one */
#endif
			continue; /* Message has no references */
		}

		refdup = strdup(msgs[i].references);
		if (ALLOC_FAILURE(refdup)) {
			continue;
		}
		refs = refdup;
		while ((ref = strsep(&refs, " "))) {
			j++;
			parentmsg = childmsg; /* Whatever was the child last round is now the parent, since we go older to newer */
			childmsg = find_thread_msgid_any(tmsgids, ref);
			/* If no message can be found with a given Message ID, create a dummy message with this ID.
			 * For example, we only have part of a thread and are referencing older messages not included in this set. */
			if (!childmsg) { /* It could not exist since the first part only creates Message IDs for messages, not the messages they reference. */
#ifdef DEBUG_THREADING
				bbs_debug(5, "Creating dummy message for Message-ID %s\n", ref);
#endif
				childmsg = push_threadmsgid(tmsgids, ref, 1);
				if (ALLOC_FAILURE(childmsg)) {
					free(refdup);
					return -1;
				}
			}
			if (j == 1) { /* First one */
				/* We won't have a parentmsg at this point */
				continue;
			}
			thread_link_parent_child(parentmsg, childmsg);
		}

		/* Create a parent/child link between the last reference and ourself. */
		if (childmsg) {
			curmsg = find_thread_msgid_any(tmsgids, msgs[i].msgid);
			bbs_assert_exists(curmsg); /* We created the message earlier, so it MUST exist in the list. */
			thread_link_parent_child(childmsg, curmsg);
		}
		free(refdup);
	}

	/* Parentless threads are automatically children of the dummy root, so nothing special needs to be done for Step 2. */

	return 0;
}

static void thread_remove(struct thread_messageid *t)
{
	/* Removing is not just as simple as calling remque;
	 * that takes care of the llnext/llprev pointers,
	 * but not the parent/child relationships that are affected. */

	remque(t); /* Remove from linked list */

	if (t->children) {
		struct thread_messageid *cur;

		/* Promote dummy messages with children (shift up),
		 * UNLESS doing so would make them children of the root...
		 * UNLESS there is only 1 child (in which case, do)
		 *
		 * (If you think hard about threading for a minute, this will make perfect sense)
		 *
		 * Basically, we only skip if t is a descendant of the root (no parent),
		 * and there is more than 1 child at this level. Otherwise, we prune.
		 */

		cur = t->children;
		if (t->parent) {
			struct thread_messageid *next;
			bbs_debug(5, "Pruning dummy message with children: %s\n", t->msgid);
			/* Make the children all belong to our parent.
			 * Insert each child into the list one by one, so as not to perturb the ordering (earliest first) */
			while (cur) {
				next = cur->next; /* thread_link_parent_child could change the next pointer, save it */
				cur->parent = NULL; /* Wipe the parent, since we won't be it anymore, so we can successfully reassign it a new parent. */
				thread_link_parent_child(t->parent, cur); /* All right, the new parent has adopted this child */
				cur = next;
			}
		} else {
			/* The thread being removed is a child of the dummy root.
			 * We should only have one child. Make it a direct child of the dummy root. */
			if (t->next) { /* XXX Possibly incomplete? This assumes we're the first child, but what if we're not? */
				bbs_warning("We have a sibling?\n");
			} else {
				if (t->children->next) {
					/* Make the oldest child the new parent (we know it's the earliest message in the thread), and shift the other children up. */
					struct thread_messageid *newparent = cur; /* Since we maintain order throughout, this should be the oldest child. */
					newparent->parent = NULL;
					newparent->children = t->children->next;
					newparent->next = NULL;
					cur = newparent->children;
					bbs_debug(5, "Pruning dummy message with multiple children (dummy is a child of the root): %s\n", t->msgid);
					/* XXX This is supposedly the case where we don't do anything in the algorithm, but I feel like we have to do something.
					 * e.g. if we have:
					 * - dummy
					 * |- message 1
					 * |- message 2
					 *
					 * Thunderbird clients will, if dummy is deleted, change this to:
					 * - message 1
					 * |- message 2
					 *
					 * Even though message 1 ISN'T the parent of message 2, it's a sibling.
					 * But really, what other sane thing is there to do? We need to have something at the first level.
					 * Somebody has to be promoted, even if none of them wants to be.
					 */
					while (cur) {
						/* Manually correct all the parent pointers, less overhead than calling thread_link_parent_child */
						cur->parent = newparent;
						cur = cur->next;
					}
				} else {
					bbs_debug(5, "Pruning dummy message with only 1 child: %s\n", t->msgid);
					/* XXX Loop unnecessary? Since only one child */
					while (cur) {
						cur->parent = NULL; /* This is all that needs to be done to become a child of the dummy root */
						cur = cur->next;
					}
				}
			}
		}
	} else {
		bbs_debug(5, "Pruning dummy message with no children: %s\n", t->msgid);
	}

	if (t->parent) {
		struct thread_messageid *next, *prev = NULL;
		/* Remove ourselves from the parent's child list. */
		bbs_assert_exists(t->parent->children); /* If we have a parent, our parent must have children. */
		next = t->parent->children;
		bbs_debug(5, "Pruning ourselves from our parent's children: %s\n", t->msgid);
		while (next) {
			if (next == t) {
				/* Found ourself. Remove ourselves from inbetween the previous and next child. */
				if (prev) {
					prev->next = next->next;
				} else {
					t->parent->children = next->next;
				}
				break;
			}
			prev = next;
			next = prev->next;
		}
		if (!next) {
			bbs_warning("Didn't find ourself (%s) in parent's (%s) list of children?\n", t->msgid, t->parent->msgid);
		}
	}

	free(t);
}

/*! \brief RFC 5256 REFERENCES algorithm Step 3 */
static int thread_references_step3(struct thread_messageid *msgids, unsigned int maxcount)
{
	struct thread_messageid *t;

#ifdef DEBUG_THREADING
	dump_thread_msgids(msgids, maxcount);
#else
	UNUSED(maxcount);
#endif

	/* Prune dummy messages */
	t = msgids->llnext; /* Skip the dummy root */
	while (t) {
		struct thread_messageid *next = t->llnext; /* Since we could free t within the loop */
		/* Traverse each thread under the root, recursively. */
		if (t->dummy) {
			if (t->next) {
				/* This will probably mess up our algorithm (at least our implementation of it) */
				bbs_warning("Dummy message %s has thread-level siblings?\n", t->msgid);
			}
			thread_remove(t);
		}
		t = next;
	}

	return 0;
}

#define FIND_EARLIEST_CHILD_DATE(x, var) \
	c = x->children; \
	bbs_assert_exists(c); \
	var = 0; \
	while (c) { \
		time_t tmp = c->sent ? mktime(c->sent) : 0; \
		if (!var || tmp < var) { \
			var = tmp; /* Time is earlier, use this one */ \
		} \
		c = c->next; \
	}

#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
static int thread_toplevel_datesort(const void *aptr, const void *bptr)
{
	struct thread_messageid **ap = (struct thread_messageid **) aptr;
	struct thread_messageid **bp = (struct thread_messageid **) bptr;
	struct thread_messageid *a = (struct thread_messageid*) *ap;
	struct thread_messageid *b = (struct thread_messageid*) *bp;
	struct thread_messageid *c;
	time_t t1, t2;
	long int diff;
	int res;

	/* We only want to sort messages under the root. */
	bbs_assert(!a->parent && !b->parent); /* We shouldn't be comparing things that aren't children of the root */

	/* Both of the messages are under the root.
	 * If one of the messages is a dummy, though, use the earliest date of the children (and there must be at least one child) */
	if (a->dummy) {
		FIND_EARLIEST_CHILD_DATE(a, t1);
	} else {
		t1 = mktime(a->sent);
	}
	if (b->dummy) {
		FIND_EARLIEST_CHILD_DATE(b, t2);
	} else {
		t2 = mktime(b->sent);
	}

	diff = (long int) difftime(t1, t2); /* If difftime is positive, tm1 > tm2 */
	if (!t1 || !t2 || diff == INT_MIN) {
		bbs_warning("%s: %ld, %s: %ld, diff: %ld\n", a->msgid, t1, b->msgid, t2, diff);
	}
	res = diff < 0 ? -1 : diff > 0 ? 1 : 0; /* This is inverted from other operations so we can get earlier dates sorted first */
	if (!res) {
		/* If dates are the same, use order in mailbox as the tiebreaker. */
		res = a->id < b->id ? -1 : a->id > b->id ? 1 : 0;
		bbs_assert(res != 0 || (a->id == 0 && b->id == 0));
	}
#if defined(DEBUG_THREADING) && defined(DEBUG_SORT)
	bbs_debug(10, "%s %s %s (%ld)\n", a->msgid, res ? res == 1 ? ">" : "<" : "=", b->msgid, diff);
#endif
	return res;
}
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop

static int thread_references_step4(struct thread_messageid *msgids, int *lengthptr)
{
	int i, length = 0;
	struct thread_messageid **msgptrs, *next;

	*lengthptr = 0;

	/* Sort messages under the root (top-level siblings only) by sent date.
	 * For dummy messages, sort children by sort date and then use the first child for the top-level sort.
	 *
	 * XXX Not sure why we would sort the children though, which is n*log(n), when we could do a linear scan for the min (linear time).
	 * Forget performance, it's way simpler to do that, too.
	 */

	/* Complicating things here is the fact that we have a linked list, not an array,
	 * so we can't just pass msgids right into qsort, as the list pointers themselves need to be updated.
	 * To work around that, here we allocate an array of pointers for all the message IDs.
	 * We can sort the array of pointers, and then use the sorted array to rearrange the linked list.
	 * Kind of clunky, but works until we come up with a better method...
	 */

	/* First, calculate the size of the list.
	 * We can't use the length parameter provided to step 1 since that's the number of messages,
	 * not the size of the references list (since there could be dummies now) */

	next = msgids->llnext; /* Skip dummy root, don't include it in the count. */
	while (next) {
		if (!next->parent) {
			/* Skip anything that's not a direct child of the dummy root, to avoid unnecessary qsort callback calls.
			 * These are the only ones that needed to be sorted. */
			length++;
		}
		if (!next->dummy) {
			*lengthptr += 1; /* Count the number of non-dummy messages */
		}
		next = next->llnext;
	}

	if (length <= 1) {
		bbs_debug(8, "Only %d child, no sorting is necessary\n", length);
		return 0;
	}

	msgptrs = calloc((size_t) length, sizeof(struct thread_messageid*)); /* Skip dummy root */
	if (ALLOC_FAILURE(msgptrs)) {
		return -1;
	}

	/* Copy the list pointers to the array */
	next = msgids->llnext; /* Skip dummy root */
	i = 0;
	while (next) {
		/*! \todo XXX To optimize for performance instead of correctness, if i == length, we can break the loop, since there are no more. */
		if (!next->parent) {
			bbs_assert(i < length); /* Shouldn't be out of bounds if we calculated the length correctly */
			msgptrs[i++] = next;
		}
		next = next->llnext;
	}

	qsort(msgptrs, (size_t) length, sizeof(struct thread_messageid**), thread_toplevel_datesort);

	/* Okay, now we have a sorted array of pointers, go ahead and update the linked list. */
#if defined(DEBUG_THREADING) && 0
	for (i = 0; i < length; i++) {
		char date[21] = "";
		if (msgptrs[i]->sent) {
			strftime(date, sizeof(date), "%d %b %Y %H:%M:%S", msgptrs[i]->sent);
		}
		bbs_debug(3, "Child %d: %20s - %s\n", i, date, msgptrs[i]->msgid);
	}
#endif

	/* Now the msgptrs array is sorted from oldest to newest, as far as the threads themselves should be ordered. */
	/* To fix the ordering of the linked list, remove all the top-level children from the linked list,
	 * and then re-insert them in such a way that they are in the proper order. */
	for (i = 0; i < length; i++) {
		remque(msgptrs[i]); /* Remove from list, but do not delete the element. We are going to reinsert it. */
	}
	i = 0;
	insque(msgptrs[i], msgids); /* First child goes after root */
	for (i = 1; i < length; i++) {
		insque(msgptrs[i], msgptrs[i - 1]); /* Each other child goes after the previous one */
	}

	free(msgptrs);
	return 0;
}

static void thread_generate_list_recurse(struct dyn_str *dynstr, struct thread_messageid *msgids, int level)
{
	int multiple;
	struct thread_messageid *next = msgids;

	if (!msgids) {
		return;
	}

	/* These are all of the threads at this level. */
	multiple = next->next || level == 0 ? 1 : 0; /* Root threads always need parentheses, otherwise add only if needed */
	while (next) {
		
		if (next->id) { /* Skip messages with no ID, since they were not among the originally provided messages */
			if (multiple) {
				dyn_str_append(dynstr, "(", 1);
			}
			dyn_str_append_fmt(dynstr, "%d%s", next->id, next->children ? " " : "");
			thread_generate_list_recurse(dynstr, next->children, level + 1);
			if (multiple) {
				dyn_str_append(dynstr, ") ", 1);
			}
		} else {
			thread_generate_list_recurse(dynstr, next->children, level + 1);
		}
		
		next = next->next;
	}
}

static char *thread_generate_list(struct thread_messageid *msgids, unsigned int maxcount)
{
	struct dyn_str dynstr;
	struct thread_messageid *next;

	memset(&dynstr, 0, sizeof(dynstr));

#ifdef DEBUG_THREADING
	dump_thread_msgids(msgids, maxcount);
#else
	UNUSED(maxcount);
#endif

	next = msgids->llnext; /* Skip dummy root */
	while (next) {
		/* Process top level children here, and recurse */
		if (!next->parent) {
			/* Each one of these is its own thread. The recursive step will handle the descendants of the thread. */
			thread_generate_list_recurse(&dynstr, next, 0);
		}
		next = next->llnext;
	}

#ifdef DEBUG_THREADING
	bbs_debug(3, "%s\n", dynstr.buf);
#endif

	if (dynstr.buf && strstr(dynstr.buf, "((")) { /* Invalid syntax that will result in missing messages, something has gone wrong */
		bbs_warning("Corrupted thread list: %s\n", dynstr.buf);
	}

	return dynstr.buf;
}

static int thread_orderedsubject(struct thread_messageid *tmsgids, struct thread_message *msgs, int length)
{
	int i;
	struct thread_messageid *next, *lastmsg, *parent = NULL;
	char *lastsubject = NULL;
	int outlen;

	tmsgids->msgid = "0"; /* This is the root. Won't match anything */
	insque(tmsgids, NULL); /* Linear list initialization - see insque(3) */

	/* Poor man's threading. Sort by subject, then date, then thread by subject.
	 * Rather than bothering with sorting a, we just sort msgs directly,
	 * since it will immediately have the info needed to make the comparison decision. */
	qsort(msgs, (size_t) length, sizeof(struct thread_message), thread_ordered_subject_compare); /* Actually sort the results, conveniently already in an array. */

	/* Load all the messages - simplified version of REFERENCES algorithm step 1.
	 * Note that we're already sorted by subject here. */
	lastmsg = tmsgids;
	for (i = 0; i < length; i++) {
		struct thread_messageid *curmsg;
		if (!msgs[i].msgid) {
			bbs_debug(3, "Message %d does not have a Message-ID\n", i);
			if (asprintf(&msgs[i].msgid, "%d", i) < 0) {
				return -1;
			}
		}
		curmsg = append_threadmsgid(lastmsg, msgs[i].msgid); /* Tail insert to preserve order with array */
		if (ALLOC_FAILURE(curmsg)) {
			return -1;
		}
		curmsg->sent = &msgs[i].sent;
		curmsg->id = msgs[i].id;
		lastmsg = curmsg;
	}

	/* Traverse the list we just built and create the parent/child relationships.
	 * Note that the list order follows the array order from above. */
	next = tmsgids->llnext; /* Skip dummy root */
	i = 0;
	while (next) {
		/* Parent is simply the first one for each subject */
		bbs_assert(next->id == msgs[i].id); /* If this isn't true, then we're threading the wrong messages */
		if (i && lastsubject && !subjectcmp(msgs[i].subject, lastsubject)) {
			/* Same subject as last one */
			thread_link_parent_child(parent, next);
		} else {
			/* First thread, or new subject */
			parent = next;
			lastsubject = msgs[i].subject;
#ifdef DEBUG_THREADING
			bbs_debug(8, "Next subject: %s (%s)\n", lastsubject, msgs[i].msgid);
#endif
		}
		lastsubject = msgs[i].subject;
		next = next->llnext;
		i++;
	}

	/* Sorting is same as Step 4 of the REFERENCES algorithm */
	thread_references_step4(tmsgids, &outlen);

	/* Something to note about the ordering here is that the Date header is used (i.e. the SENT time, not the RECEIVED time)
	 * Thus, messages without a Sent time will appear all the way at the beginning.
	 * Probably reasonable...
	 */

	return 0;
}

int test_thread_orderedsubject(void)
{
	int res = -1, mres;
	struct thread_message *msgs;
	struct thread_messageid tmsgids;
	time_t now = (int) time(NULL);
	unsigned int i;
	char date[34];
	const size_t num_msgs = 20;
	char *list = NULL;

	memset(&tmsgids, 0, sizeof(tmsgids));

	msgs = calloc(num_msgs, sizeof(struct thread_message));
	if (ALLOC_FAILURE(msgs)) {
		goto cleanup;
	}
	/* A bunch of messages in one thread, one after the other */
	for (i = 0; i < 5; i++) {
		msgs[i].id = i + 1;
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_sec = (int) i; /* So they're not exactly the same */
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Test Subject");
	}
	/* Messages that are the only one in their conversation */
	for (; i < 8; i++) {
		msgs[i].id = i + 1;
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_sec = (int) i; /* So they're not exactly the same */
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Test Subject %d", i);
	}
	msgs[i].id = i + 1;
	snprintf(date, sizeof(date), "Tues, 2 Jan 2001 14:14:14 -0300");
	bbs_parse_rfc822_date(date, &msgs[i].sent); /* XXX Currently fails, so date will be first of all of them */
	msgs[i].sent.tm_sec = (int) i; /* So they're not exactly the same */
	i++;
	for (; i < 11; i++) {
		msgs[i].id = i + 1;
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_sec = (int) i; /* So they're not exactly the same */
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Test Subject %d", i);
	}

	for (; i < num_msgs; i++) {
		msgs[i].id = i + 1;
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_sec = (int) i; /* So they're not exactly the same */
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Re: Some Subject");
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
	}

	mres = thread_orderedsubject(&tmsgids, msgs, (int) num_msgs);
	bbs_test_assert_equals(0, mres);
	list = thread_generate_list(&tmsgids, i);
	bbs_test_assert(list != NULL);
	bbs_test_assert_str_equals(list, "(9)(1 (2)(3)(4)(5))(6)(7)(8)(10)(11)(12 (13)(14)(15)(16)(17)(18)(19)(20))");
	res = 0;

cleanup:
	free_if(list);
	free_thread_msgids(&tmsgids);
	free_thread_messages(msgs, num_msgs);
	return res;
}

int test_thread_references(void)
{
	int res = -1, mres;
	struct thread_message *msgs;
	struct thread_messageid tmsgids;
	time_t now = (int) time(NULL);
	unsigned int i;
	int outlen;
	char date[34];
	const size_t num_msgs = 20;
	char *list = NULL;

	memset(&tmsgids, 0, sizeof(tmsgids));

	msgs = calloc(num_msgs, sizeof(struct thread_message));
	if (ALLOC_FAILURE(msgs)) {
		goto cleanup;
	}
	/* A bunch of messages in one thread, one after the other */
	for (i = 0; i < 5; i++) {
		msgs[i].id = i + 1;
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_year -= 2;
		if (asprintf(&msgs[i].references, "<msg%d@localhost>", i) < 0) {
			goto cleanup;
		}
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Test Subject");
		snprintf(msgs[i].inreplyto, sizeof(msgs[i].inreplyto), "<msg%d@localhost>", i);
	}
	/* Messages that are the only one in their conversation */
	for (; i < 8; i++) {
		msgs[i].id = i + 1;
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_year -= (int) (i * 2 - (i % 2) * 5); /* Mix it up though */
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Test Subject %d", i);
	}
	/* 8 doesn't have a Message-ID, just to throw us off */
	msgs[i].id = i + 1;
	snprintf(date, sizeof(date), "Tues, 2 Jan 2001 14:14:14 -0300");
	bbs_parse_rfc822_date(date, &msgs[i].sent); /* XXX Currently fails, so date will be first of all of them */
	snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Message with no Msg-ID");
	i++;
	for (; i < 11; i++) {
		msgs[i].id = i + 1;
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_year -= 1;
		msgs[i].sent.tm_min = (int) i;
		if (asprintf(&msgs[i].references, "<nonexistent%d@localhost>", i) < 0) { /* Reference a nonexistent message */
			goto cleanup;
		}
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Test Subject %d", i);
	}

	/* Thread where they all reference their ancestors */
	for (; i < num_msgs; i++) {
		char references[384] = "";
		char *refbuf = references;
		int refleft = sizeof(references);
		int j;
		int parent = (int) i;

		/* For variety, make some messages in the thread be siblings.
		 * i.e. there will be messages with 2 children, rather than every message having 1 children. */
		if (parent % 2) {
			parent--;
		}

		/* Reference all prior conversations, as a proper MUA should. */
		for (j = 10; j < parent; j++) {
			SAFE_FAST_COND_APPEND(references, sizeof(references), refbuf, refleft, 1, "<msg%d@localhost>", j);
		}
		msgs[i].id = i + 1;
		msgs[i].references = strdup(references);
		localtime_r(&now, &msgs[i].sent);
		msgs[i].sent.tm_sec = (int) i; /* So they're not exactly the same */
		snprintf(msgs[i].subject, sizeof(msgs[i].subject), "Re: Some Subject");
		if (asprintf(&msgs[i].msgid, "<msg%d@localhost>", i + 1) < 0) {
			goto cleanup;
		}
		snprintf(msgs[i].inreplyto, sizeof(msgs[i].inreplyto), "<msg%d@localhost>", parent);
	}

	mres = thread_references_step1(&tmsgids, msgs, (int) num_msgs);
	bbs_test_assert_equals(0, mres);
	mres = thread_references_step3(&tmsgids, i);
	bbs_test_assert_equals(0, mres);
	mres = thread_references_step4(&tmsgids, &outlen);
	bbs_test_assert_equals(0, mres);
	list = thread_generate_list(&tmsgids, i);
	bbs_test_assert(list != NULL);
	bbs_test_assert_str_equals(list, "(9)(7)(8)(6)(1 2 3 4 5)(10)(11 (12)(13 (15 (17 (19)(20))(18))(16))(14))");
	res = 0;

cleanup:
	free_if(list);
	free_thread_msgids(&tmsgids);
	free_thread_messages(msgs, num_msgs);
	return res;
}

static int do_threading(struct imap_session *imap, unsigned int *a, size_t length, int usinguid, enum thread_algorithm algo)
{
	char *list;
	struct thread_messageid tmsgids;
	struct thread_message *msgs = calloc(length, sizeof(struct thread_message));

	if (ALLOC_FAILURE(msgs)) {
		return -1;
	}

	/* Populate the thread structures with the content needed for either algorithm */
	if (populate_thread_data(imap, msgs, a, (int) length, usinguid)) {
		free(msgs); /* Haven't allocated anything else yet */
		bbs_warning("Failed to populate thread data\n");
		return -1;
	}

	memset(&tmsgids, 0, sizeof(tmsgids));

	if (algo == THREAD_ALG_ORDERED_SUBJECT) {
		thread_orderedsubject(&tmsgids, msgs, (int) length);
	} else { /* REFERENCES */
		int outlen;
		/* RFC 5256 REFERENCES algorithm.
		 * Also a good writeup by the original author of the algorithm, here: https://www.jwz.org/doc/threading.html */
		thread_references_step1(&tmsgids, msgs, (int) length); /* Steps 1, 2, and 6 */
		thread_references_step3(&tmsgids, imap->totalcur + imap->totalnew);
		thread_references_step4(&tmsgids, &outlen);
		/* We skip step 5 of the algorithm.
		 * I consider this part "optional", since nowadays all compliant MUAs should be setting the References header,
		 * and combining based on subject may group unrelated threads with the same subject erroneously,
		 * and this is probably worse than the marginal benefit of grouping together potentially related messages.
		 * I am aware there are a few such broken clients out there (e.g. Outlook 2003, SurgeWeb) that do not support threading,
		 * but to my knowledge, clients e.g. Thunderbird-based ones, do not do Step 5 either, anyways.
		 * JWZ would say this is cutting corners, just like Netscape 4.0, but this really makes more sense this way, to me.
		 */
		if (outlen != (int) length) { /* Note that even if this is false, that doesn't necessarily mean the result was correct. */
			bbs_warning("Got %lu messages as input, but only threaded %d?\n", length, outlen);
		}
	}

	/* At this point, threads are sorted. All we need to do now is generate the list. */
	list = thread_generate_list(&tmsgids, imap->totalcur + imap->totalnew);
	free_thread_msgids(&tmsgids);
	imap_send(imap, "THREAD %s", S_IF(list));
	free_if(list);

	/* Destroy thread structures */
	free_thread_messages(msgs, length);
	return 0;
}

int handle_thread(struct imap_session *imap, char *s, int usinguid)
{
	int results;
	char *charset, *search;
	enum thread_algorithm algo;
	unsigned int *a = NULL;
	int min, max;
	unsigned long maxmodseq;
	char *tmp;

	/* e.g. A283 THREAD ORDEREDSUBJECT UTF-8 SINCE 5-MAR-2000 */

	REQUIRE_ARGS(s);
	tmp = strsep(&s, " ");
	if (!strcasecmp(tmp, "REFERENCES")) {
		algo = THREAD_ALG_REFERENCES;
	} else if (!strcasecmp(tmp, "ORDEREDSUBJECT")) {
		algo = THREAD_ALG_ORDERED_SUBJECT;
	} else {
		imap_reply(imap, "BAD Invalid threading algorithm");
		return 0;
	}

	charset = strsep(&s, " ");
	REQUIRE_ARGS(charset); /* This is mandatory in the RFC, though we ignore this, apart from checking it. */
	search = s;
	REQUIRE_ARGS(search);

	if (strcasecmp(charset, "UTF-8") && strcasecmp(charset, "US-ASCII")) {
		imap_reply(imap, "NO [BADCHARSET] (UTF-8 US_ASCII) Charset %s not supported", charset);
		return 0;
	}

	/* First, search for any matching messages. */
	results = do_search(imap, search, &a, usinguid, &min, &max, &maxmodseq);
	if (results < 0) {
		return 0;
	}

	if (results) {
		/* Now, thread the messages. This is much more complicating than normal sorting,
		 * particularly for the REFERENCES algorithm. */
		do_threading(imap, a, (size_t) results, usinguid, algo);
	}

	free_if(a);
	imap_reply(imap, "OK %sTHREAD completed", usinguid ? "UID " : "");
	return 0;
}
