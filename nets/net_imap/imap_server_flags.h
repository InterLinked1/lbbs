/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief IMAP Server Flags and Keywords
 *
 */

#define FLAG_BIT_FLAGGED (1 << 0)
#define FLAG_BIT_SEEN (1 << 1)
#define FLAG_BIT_ANSWERED (1 << 2)
#define FLAG_BIT_DELETED (1 << 3)
#define FLAG_BIT_DRAFT (1 << 4)
/* This flag is special, since it is not explicitly stored at all, it is purely computed, and cannot be set by clients */
#define FLAG_BIT_RECENT (1 << 5)
/*! \note Must be the number of FLAG_BIT macros */
#define NUM_FLAG_BITS 6

#define FLAG_NAME_FLAGGED "\\Flagged"
#define FLAG_NAME_SEEN "\\Seen"
#define FLAG_NAME_ANSWERED "\\Answered"
#define FLAG_NAME_DELETED "\\Deleted"
#define FLAG_NAME_DRAFT "\\Draft"
#define FLAG_NAME_RECENT "\\Recent"

#define IMAP_PERSISTENT_FLAGS FLAG_NAME_FLAGGED " " FLAG_NAME_SEEN " " FLAG_NAME_ANSWERED " " FLAG_NAME_DELETED " " FLAG_NAME_DRAFT
#define IMAP_FLAGS IMAP_PERSISTENT_FLAGS " " FLAG_NAME_RECENT

/* maildir flags, that appear in a single string and must appear in ASCII order: https://cr.yp.to/proto/maildir.html */
#define FLAG_DRAFT 'D'
#define FLAG_FLAGGED 'F'
#define FLAG_PASSED 'P'
#define FLAG_REPLIED 'R'
#define FLAG_SEEN 'S'
#define FLAG_TRASHED 'T'
#define FLAG_RECENT 'U' /* This is a phony flag, it never goes in the maildir filename, it's just for ease of printing flag names */

#define SET_LETTER_IF_FLAG(flag, letter) \
	if (flags & flag) { \
		*buf++ = letter; \
	}

/* The implementation of how keywords are stored is based on how Dovecot stores keywords:
 * https://doc.dovecot.org/admin_manual/mailbox_formats/maildir/
 * We use 26 lowercase letters, to differentiate from IMAP flags (uppercase letters).
 * However, we don't a uidlist file, and we store the keywords in a separate file.
 * The implementation is handled fully in net_imap, since other modules don't care about keywords.
 */

#define MAX_KEYWORDS 26

/*! \brief Check filename for the mapping for keyword. If one does not exist and there is room ( < 26), it will be created. */
void parse_keyword(struct imap_session *imap, const char *s, const char *directory, int create);

#define gen_keyword_names(imap, s, inbuf, inlen) __gen_keyword_names(s, inbuf, inlen, imap->dir)

int __gen_keyword_names(const char *s, char *inbuf, size_t inlen, const char *directory);

#define parse_flags_string(imap, s) __parse_flags_string(imap, s, imap->dir)

/*! \brief Convert named flag or keyword into a single character for maildir filename */
/*! \note If imap is not NULL, custom keywords are stored in imap->appendkeywords (size is stored in imap->numappendkeywords) */
int __parse_flags_string(struct imap_session *imap, char *s, const char *directory);

/*!
 * \param f
 * \param[out] keywords Pointer to beginning of keywords, if any
 */
int parse_flags_letters(const char *restrict f, const char **keywords);

/*!
 * \param filename
 * \param flags
 * \param keywordsbuf Must be of size 27
 */
int parse_flags_letters_from_filename(const char *filename, int *flags, char *keywordsbuf);

void gen_flag_letters(int flags, char *buf, size_t len);

void gen_flag_names(const char *flagstr, char *fullbuf, size_t len);

int restrict_flags(int acl, int *flags);

/*!
 * \brief Translate the flags from a filename in one maildir to the flags for a different maildir (see function comments)
 * \note This function will rename the file with the adjusted flag letters
 *
 * \param imap
 * \param oldmaildir The old maildir from which flags are translated
 * \param oldfilenamefull The full path to the current filename of this message
 * \param oldfilename A base filename that contains the flags. Note this does not necessarily have to be the basename of oldfilenamefull,
 *        and with current usage, it is not. It's fine if it's stale, as long as it contains the flags accurately
 * \param newmaildir The new maildir to which flags are translated
 * \param destacl
 */
int translate_maildir_flags(struct imap_session *imap, const char *oldmaildir, const char *oldfilenamefull, const char *oldfilename, const char *newmaildir, int destacl);

/*! \brief base filename The file name of the message file. Please do not provide the full filepath. */
void generate_flag_names_full(struct imap_session *imap, const char *filename, char *bufstart, size_t bufsize, char **bufptr, int *lenptr);

int maildir_msg_setflags_modseq(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters, unsigned long *newmodseq);

int maildir_msg_setflags(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters);

int maildir_msg_setflags_notify(struct imap_session *imap, int seqno, const char *origname, const char *newflagletters);
