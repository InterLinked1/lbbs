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
 * \brief IMAP Server ACLs (Access Control List)
 *
 */

/* RFC 2086/4314 ACLs */
/*! \brief Visible in LIST, LSUB, SUBSCRIBE */
#define IMAP_ACL_LOOKUP (1 << 0)
#define IMAP_ACL_LOOKUP_LETTER 'l'

/*! \brief SELECT, STATUS */
#define IMAP_ACL_READ (1 << 1)
#define IMAP_ACL_READ_LETTER 'r'

/*! \brief SEEN persistence */
/*! \note There is no way for Seen to not be persistent, so this is always enabled. */
#define IMAP_ACL_SEEN (1 << 2)
#define IMAP_ACL_SEEN_LETTER 's'

/*! \brief Set or clear flags other than Seen or Deleted via STORE, or set using APPEND/COPY */
#define IMAP_ACL_WRITE (1 << 3)
#define IMAP_ACL_WRITE_LETTER 'w'

/*! \brief Insert (APPEND, COPY) */
#define IMAP_ACL_INSERT (1 << 4)
#define IMAP_ACL_INSERT_LETTER 'i'

/*! \brief Post (send mail to submission address for mailbox), unused by IMAP4 */
#define IMAP_ACL_POST (1 << 5)
#define IMAP_ACL_POST_LETTER 'p'

/* RFC 4314 only ACLs */

/*! \brief CREATE, new mailbox RENAME */
#define IMAP_ACL_MAILBOX_CREATE (1 << 6)
#define IMAP_ACL_MAILBOX_CREATE_LETTER 'k'

/*! \brief DELETE mailbox, old mailbox DELETE */
#define IMAP_ACL_MAILBOX_DELETE (1 << 7)
#define IMAP_ACL_MAILBOX_DELETE_LETTER 'x'

/*! \brief DELETE messages (Deleted flag via STORE, APPEND, COPY) */
#define IMAP_ACL_DELETE (1 << 8)
#define IMAP_ACL_DELETE_LETTER 't'

/*! \brief EXPUNGE, expunge as part of CLOSE */
#define IMAP_ACL_EXPUNGE (1 << 9)
#define IMAP_ACL_EXPUNGE_LETTER 'e'

/*! \brief Administer (SETACL/DELETEACL/GETACL/LISTRIGHTS) */
#define IMAP_ACL_ADMINISTER (1 << 10)
#define IMAP_ACL_ADMINISTER_LETTER 'a'

/*! \brief Obsolete ACLs from RFC 2086 */
#define IMAP_ACL_UNION_CREATE_LETTER 'c'
#define IMAP_ACL_UNION_DELETE_LETTER 'd'

/*! \brief Default ACLs for different namespaces: private = everything, other/shared = nothing */
#define IMAP_ACL_DEFAULT_PRIVATE (IMAP_ACL_LOOKUP | IMAP_ACL_READ | IMAP_ACL_SEEN | IMAP_ACL_WRITE | IMAP_ACL_INSERT | IMAP_ACL_POST | IMAP_ACL_MAILBOX_CREATE | IMAP_ACL_MAILBOX_DELETE | IMAP_ACL_DELETE | IMAP_ACL_EXPUNGE | IMAP_ACL_ADMINISTER)
#define IMAP_ACL_DEFAULT_OTHER 0
#define IMAP_ACL_DEFAULT_SHARED 0

#define PARSE_ACL_LETTER(aclflag) \
	case aclflag ## _LETTER: \
		acl |= aclflag; \
		break; \

#define WRITE_ACL_LETTER(aclflag) \
	if (acl & aclflag) { \
		*buf++ = aclflag ## _LETTER; \
	}

#define IMAP_HAS_ACL(acl, flag) (acl & (flag))
#define IMAP_REQUIRE_ACL_RETURN(acl, flag, ret) \
	if (!IMAP_HAS_ACL(acl, (flag))) { \
		char _aclbuf[15]; \
		generate_acl_string(acl, _aclbuf, sizeof(_aclbuf)); \
		bbs_debug(4, "User missing ACL %s (have %s)\n", #flag, _aclbuf); \
		imap_reply(imap, "NO [NOPERM] Permission denied"); \
		return ret; \
	}
#define IMAP_REQUIRE_ACL(acl, flag) IMAP_REQUIRE_ACL_RETURN(acl, flag, 0)

/*! \brief Parse IMAP ACL from string */
int parse_acl(const char *aclstring);

void generate_acl_string(int acl, char *buf, size_t len);

void load_acl(struct imap_session *imap, const char *directory, enum mailbox_namespace ns, int *acl);

int getacl(struct imap_session *imap, const char *directory, const char *mailbox);

int setacl(struct imap_session *imap, const char *directory, const char *mailbox, const char *user, const char *newacl);
