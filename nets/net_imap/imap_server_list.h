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
 * \brief IMAP Server LIST
 *
 */

#define DIR_NO_SELECT (1 << 0)
#define DIR_NO_CHILDREN (1 << 1)
#define DIR_HAS_CHILDREN (1 << 2)
#define DIR_DRAFTS (1 << 3)
#define DIR_JUNK (1 << 4)
#define DIR_SENT (1 << 5)
#define DIR_TRASH (1 << 6)

#define DIR_INBOX (1 << 7)
#define DIR_SUBSCRIBED (1 << 8)

#define DIR_MARKED (1 << 9)
#define DIR_UNMARKED (1 << 10)

#define DIR_SPECIALUSE (DIR_DRAFTS | DIR_JUNK | DIR_SENT | DIR_TRASH)

#define IS_SPECIAL_NAME(s) (!strcmp(s, "INBOX") || !strcmp(s, "Drafts") || !strcmp(s, "Junk") || !strcmp(s, "Sent") || !strcmp(s, "Trash"))

#define ATTR_NOSELECT "\\Noselect"
#define ATTR_HAS_CHILDREN "\\HasChildren"
#define ATTR_NO_CHILDREN "\\HasNoChildren"
#define ATTR_DRAFTS "\\Drafts"
#define ATTR_JUNK "\\Junk"
#define ATTR_SENT "\\Sent"
#define ATTR_TRASH "\\Trash"

#define ATTR_INBOX "\\Inbox"
#define ATTR_SUBSCRIBED "\\Subscribed"

#define ATTR_MARKED "\\Marked"
#define ATTR_UNMARKED "\\Unmarked"

#define ASSOC_ATTR(flag, string) SAFE_FAST_COND_APPEND(buf, len, pos, left, (attrs & flag), string)

enum list_cmd_type {
	CMD_LIST,
	CMD_LSUB,
	CMD_XLIST,
};

struct list_command {
	enum list_cmd_type cmdtype;
	const char *cmd;
	/* Mailbox patterns */
	char *reference;
	size_t patterns;			/*!< Number of mailboxes in pattern */
	const char **mailboxes;		/*!< List of mailbox patterns */
	int *skiplens;				/*!< List of skip lengths */
	/* Selection options */
	unsigned int subscribed:1;	/*!< RFC 5258 SUBSCRIBED selection option - mailboxes to which we're subscribed. */
	unsigned int remote:1;		/*!< RFC 5258 REMOTE selection option - mailboxes using RFC 2193 mailbox referrals (N/A for us) */
	unsigned int recursive:1;	/*!< RFC 5258 RECRUSIVEMATCH selection option */
	unsigned int specialuse:1;	/*!< RFC 6154 SPECIAL-USE LIST extension */
	/* Return options */
	unsigned int retsubscribed:1;	/*!< SUBSCRIBED return option */
	unsigned int retchildren:1;		/*!< CHILDREN return option */
	unsigned int retspecialuse:1;	/*!< SPECIAL-USE (RFC 6154) */
	const char *retstatus;			/*!< STATUS return option (RFC 5819 LIST-STATUS extension) */
	/* Internal */
	unsigned int extended:1;	/*!< EXTENDED list command? */
	unsigned int anyother:1;	/*!< Any mailboxes in Other Users namespace? */
	unsigned int anyshared:1;	/*!< Any mailboxes in Shared Folders namespace? */
	int xlistflags;				/*!< Whether or not to also return \Inbox */
	enum mailbox_namespace ns;
	size_t reflen;
};

/*! \brief Determine if the interpreted result of the LIST arguments matches a directory in the maildir */
int list_match(const char *dirname, const char *query);

void build_attributes_string(char *buf, size_t len, int attrs);

#define list_wildcard_match(mailbox) (strlen_zero(lcmd->reference) && (strlen_zero(mailbox) || !strcmp(mailbox, "*") || !strcmp(mailbox, "%")))

#define list_mailbox_pattern_matches_inbox_single(mailbox) (list_wildcard_match(mailbox) || !strcmp(mailbox, "INBOX"))

int list_mailbox_pattern_matches(struct list_command *lcmd, const char *dirname);

int list_scandir(struct imap_session *imap, struct list_command *lcmd, int level, const char *prefix, const char *listscandir);
