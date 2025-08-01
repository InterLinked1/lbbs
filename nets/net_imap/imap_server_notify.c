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
 * \brief IMAP Server NOTIFY (RFC 5465)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>

#include "include/node.h"
#include "include/linkedlists.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h" /* includes stringlist.h already */
#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_server_acl.h"
#include "nets/net_imap/imap_server_list.h"
#include "nets/net_imap/imap_server_notify.h"
#include "nets/net_imap/imap_client.h"

/* #define DEBUG_NOTIFY */

enum notify_mailbox_specifier {
	/* Selected mailbox (overrides everything else) */
	/* Only one of either SELECTED or SELECTED_DELAYED may exist for the entire NOTIFY command */
	NOTIFY_SELECTED = 0,		/*!< Currently selected mailbox, immediate */
	NOTIFY_SELECTED_DELAYED,	/*!< Currently selected mailbox, during an allowed command (e.g. NOOP, IDLE) */
	/* Non-selected mailboxes */
	NOTIFY_PERSONAL,			/*!< Any selectable mailbox in the personal namespace */
	NOTIFY_INBOXES,				/*!< Any selectable mailbox in the personal namespace to which an MDA may deliver messages, i.e. just INBOX for us */
	NOTIFY_SUBSCRIBED,			/*!< All mailboxes subscribed to by the user */
	NOTIFY_SUBTREE,				/*!< Specified mailbox(es) and all selected mailboxes subordinate to it */
	NOTIFY_MAILBOXES,			/*!< Specified mailbox(es). No wildcard expansion. */
};

/*! \brief A single watch */
struct notify_watch {
	enum notify_mailbox_specifier spec;		/*!< Mailbox specifier */
	enum mailbox_event_type events;			/*!< Events */
	unsigned int none:1;					/*!< NONE */
	const char *fetchargs;
	RWLIST_ENTRY(notify_watch) entry;
	struct stringlist mbnames;
	char data[];
};

RWLIST_HEAD(notify_watchlist, notify_watch);

struct imap_notify {
	struct notify_watchlist watchlist;		/*!< Event groups */
	unsigned int none:1;					/*!< NOTIFY NONE */
	unsigned int nomsn:1;					/*!< SELECTED active (message sequence numbers cannot be used) */
	unsigned int nonpersonal:1;				/*!< Any non personal namespace mailboxes? */
};

static void watch_free(struct notify_watch *w)
{
	stringlist_empty_destroy(&w->mbnames);
	free(w);
}

static void notify_destroy(struct imap_notify *notify)
{
	notify->none = 0;
	notify->nomsn = 0;
	RWLIST_WRLOCK_REMOVE_ALL(&notify->watchlist, entry, watch_free);
}

void imap_notify_cleanup(struct imap_session *imap)
{
	if (imap->notify) {
		notify_destroy(imap->notify);
		RWLIST_HEAD_DESTROY(&imap->notify->watchlist);
		FREE(imap->notify);
	}
}

int imap_sequence_numbers_prohibited(struct imap_session *imap)
{
	if (!imap->notify) {
		return 0;
	}
	return imap->notify->nomsn;
}

/*! \note Must be called locked, and it's assumed imap->notify is non-NULL */
static struct notify_watch *notify_get_match(struct imap_session *imap, const char *name)
{
	struct imap_notify *notify = imap->notify;
	struct notify_watch *w;
	int selected;

	/* Currently selected folder is treated specially */
	selected = imap->folder && !strcmp(name, imap->folder);
#ifdef DEBUG_NOTIFY
	bbs_debug(3, "Currently selected mailbox selected match: %d (%s|%s)\n", selected, name, imap->folder);
#endif

	RWLIST_TRAVERSE(&notify->watchlist, w, entry) {
		/* Only SELECTED and NOTIFY_SELECTED_DELAYED match the currently selected mailbox */
		if (selected) {
			if (w->spec != NOTIFY_SELECTED && w->spec != NOTIFY_SELECTED_DELAYED) {
				continue;
			}
		} else {
			if (w->spec == NOTIFY_SELECTED || w->spec == NOTIFY_SELECTED_DELAYED) {
				continue;
			}
			if (w->spec == NOTIFY_PERSONAL && (STARTS_WITH(name, OTHER_NAMESPACE_PREFIX) || STARTS_WITH(name, SHARED_NAMESPACE_PREFIX))) {
				continue; /* Not in personal namespace */
			}
			/* These checks specifically are case-insensitive. So Inbox is treated the same as INBOX, etc.
			 * Most IMAP servers are case-insensitive when it comes to mailbox names,
			 * although this IMAP server is not, since they map directly to a directory structure. */
			if (w->spec == NOTIFY_MAILBOXES && !stringlist_case_contains(&w->mbnames, name)) {
				continue;
			}
			if (w->spec == NOTIFY_SUBTREE) {
				/* If name is not fully prefixed by anything in w->mbnames, it's not a match */
				const char *s;
				struct stringitem *i = NULL;
				RWLIST_RDLOCK(&w->mbnames);
				while ((s = stringlist_next(&w->mbnames, &i))) {
					if (!strncasecmp(name, s, strlen(s))) {
						RWLIST_UNLOCK(&w->mbnames);
						return w;
					}
				}
				RWLIST_UNLOCK(&w->mbnames);
			}
		}
		/* RFC 5465 seems somewhat vague on which match to use if more than one specifier matches a mailbox.
		 * We just use the first one for simplicity (so a client should provide the most specific matches first if multiple could match). */
		if (w) {
			break;
		}
	}
	return w;
}

#define DEFAULT_EVENTS (IMAP_EVENT_MESSAGE_NEW | IMAP_EVENT_MESSAGE_EXPUNGE | IMAP_EVENT_FLAG_CHANGE)

int imap_notify_applicable(struct imap_session *imap, struct mailbox *mbox, const char *folder, const char *maildir, enum mailbox_event_type e)
{
	return imap_notify_applicable_fetchargs(imap, mbox, folder, maildir, e, NULL);
}

#ifdef DEBUG_NOTIFY
static void dump_events_str(enum mailbox_event_type events)
{
#define DUMP_EVENT(e) if (events & e) { bbs_debug(3, "Event present: %s\n", #e); }
	DUMP_EVENT(EVENT_MESSAGE_APPEND);
	DUMP_EVENT(EVENT_MESSAGE_EXPIRE);
	DUMP_EVENT(EVENT_MESSAGE_EXPUNGE);
	DUMP_EVENT(EVENT_MESSAGE_NEW);
	DUMP_EVENT(EVENT_QUOTA_EXCEED);
	DUMP_EVENT(EVENT_QUOTA_WITHIN);
	DUMP_EVENT(EVENT_QUOTA_CHANGE);
	DUMP_EVENT(EVENT_MESSAGE_READ);
	DUMP_EVENT(EVENT_MESSAGE_TRASH);
	DUMP_EVENT(EVENT_FLAGS_SET);
	DUMP_EVENT(EVENT_FLAGS_CLEAR);
	DUMP_EVENT(EVENT_LOGIN);
	DUMP_EVENT(EVENT_LOGOUT);
	DUMP_EVENT(EVENT_MAILBOX_CREATE);
	DUMP_EVENT(EVENT_MAILBOX_DELETE);
	DUMP_EVENT(EVENT_MAILBOX_RENAME);
	DUMP_EVENT(EVENT_MAILBOX_SUBSCRIBE);
	DUMP_EVENT(EVENT_MAILBOX_UNSUBSCRIBE);
	DUMP_EVENT(EVENT_METADATA_CHANGE);
	DUMP_EVENT(EVENT_SERVER_METADATA_CHANGE);
	DUMP_EVENT(EVENT_ANNOTATION_CHANGE);
	DUMP_EVENT(EVENT_MAILBOX_UIDVALIDITY_CHANGE);
#undef DUMP_EVENT
}
#endif

/* This comparison compares the actual mailbox names to see if the folder name here matches.
 * This covers any personal mailbox folders, as well as remote/proxied mailbox folders. */
#define FOLDER_NAME_MATCHES(imap, folder) (imap->folder && !strcmp(folder, imap->folder))

/* If the client never used the NOTIFY command, imap->notify is NULL, and in this case it's okay to not have a maildir
 * Additionally, in handle_idle when checking if a remote mailbox with activity is applicable, maildir will be NULL. */
#define MAILDIR_PATHS_MATCH(imap, maildir) (maildir && !strcmp(maildir, imap->dir))

/* This comparison compares the maildirs involved by their directory paths on disk.
 * This covers shared mailboxes or other users' mailboxes, since the name for different users may differ.
 * However, we need to be careful to explicitly NOT match if we are actively using a remote/proxied folder,
 * since that isn't using the maildir at the moment (in other words, the maildir path here is stale,
 * because we didn't update it when we selected the remote folder).
 * XXX We should probably also clear out imap->dir when selecting remote folders as well. */
#define MAILDIRS_MATCH(imap, maildir) (!imap->client && MAILDIR_PATHS_MATCH(imap, maildir))

int imap_notify_applicable_fetchargs(struct imap_session *imap, struct mailbox *mbox, const char *folder, const char *maildir, enum mailbox_event_type e, const char **fetchargs)
{
	if (!imap->notify) {
		/* Basically, is it the same mailbox that's selected? */
		bbs_assert_exists(folder);
		/* If the client never used the NOTIFY command, imap->notify is NULL, and in this case it's okay to not have a maildir */
		return (imap->mbox == mbox && FOLDER_NAME_MATCHES(imap, folder)) || MAILDIRS_MATCH(imap, maildir);
	} else {
		struct imap_notify *notify = imap->notify;
		struct notify_watch *w;
		enum mailbox_event_type events;
		int selected_a = folder && FOLDER_NAME_MATCHES(imap, folder);
		int selected_b = !s_strlen_zero(imap->dir) && MAILDIRS_MATCH(imap, maildir);
		int selected = selected_a || selected_b;

		if (notify->none) {
			return 0;
		}

		RWLIST_RDLOCK(&notify->watchlist);
		w = notify_get_match(imap, folder);
		if (w) {
			if (w->none) {
				events = 0; /* NOTIFY SET... NONE */
			} else {
				events = w->events;
				if (fetchargs) {
					*fetchargs = w->fetchargs;
				}
			}
		} else {
			/* By default, no events for non-selected mailboxes */
			events = selected ? DEFAULT_EVENTS : 0;
		}
#ifdef DEBUG_NOTIFY
		bbs_debug(3, "'%s'|'%s', '%s'|'%s' (remote client: %d), mailbox selected: %d [%d/%d], spec: %d, event match: %d\n",
			folder, imap->folder, maildir, imap->dir, imap->client ? 1 : 0, selected, selected_a, selected_b, w->spec, events & e ? 1 : 0);
		dump_events_str(events);
#endif
		RWLIST_UNLOCK(&notify->watchlist);
		if (events & e) {
			return selected ? 1 : -1;
		}
		return 0;
	}
}

static struct imap_notify *notify_get(struct imap_session *imap)
{
	if (!imap->notify) {
		imap->notify = calloc(1, sizeof(*imap->notify));
		if (ALLOC_SUCCESS(imap->notify)) {
			RWLIST_HEAD_INIT(&imap->notify->watchlist);
		}
	}
	return imap->notify;
}

static int parse_specifier(enum notify_mailbox_specifier *restrict spec, char *s)
{
	if (!strcasecmp(s, "SELECTED")) {
		*spec = NOTIFY_SELECTED;
	} else if (!strcasecmp(s, "SELECTED-DELAYED")) {
		*spec = NOTIFY_SELECTED_DELAYED;
	} else if (!strcasecmp(s, "personal")) {
		*spec = NOTIFY_PERSONAL;
	} else if (!strcasecmp(s, "inboxes")) {
		*spec = NOTIFY_INBOXES;
	} else if (!strcasecmp(s, "subtree")) {
		*spec = NOTIFY_SUBTREE;
	} else if (!strcasecmp(s, "mailboxes")) {
		*spec = NOTIFY_MAILBOXES;
	} else {
		bbs_warning("Invalid mailbox specifier '%s'\n", s);
		return -1;
	}
	return 0;
}

static int mailbox_watchable(struct imap_session *imap, char *s)
{
	char fullmaildir[256];
	int myacl;

	/* 1. If not an existing mailbox, MUST ignore it */
	if (imap_translate_dir(imap, s, fullmaildir, sizeof(fullmaildir), &myacl)) {
		/* If it's a prefix, allow it: */
		if (STARTS_WITH(s, OTHER_NAMESPACE_PREFIX) || STARTS_WITH(s, SHARED_NAMESPACE_PREFIX)) {
			return 1;
		}
		/* Maybe it's a remote mapping? In which case, allow it */
		if (mailbox_remotely_mapped(imap, s)) {
			return 1;
		}
		bbs_debug(1, "Mailbox '%s' does not exist and is not remotely mapped\n", s);
		return 0;
	}
	/* If can't LIST, MUST ignore it */
	if (!(myacl & IMAP_ACL_LOOKUP)) {
		bbs_debug(1, "Insufficient ACLs for mailbox '%s'\n", s);
		return 0;
	}
	/* If we don't have other required rights, must send untagged LIST with \NoAccess attribute.
	 * Pretty much boils down to the read right for all events... */
	if (!(myacl & IMAP_ACL_READ)) {
		imap_send(imap, "LIST \"%s\" \"%s\"", "\\NoAccess", s);
		return 0;
	}
	return 1;
}

/*! \retval 0 on failure, 1 if watch added */
static int add_watch(struct imap_session *imap, struct imap_notify *notify, char *s)
{
	struct notify_watch *w;
	char *specname;
	int none = 0;
	enum notify_mailbox_specifier spec;
	enum mailbox_event_type events = 0;
	struct stringlist mbnames;
	char *fetchargs = NULL;

	stringlist_init(&mbnames);

	/* e.g.
	 * selected MessageNew (uid body.peek[header.fields (from to subject)]) MessageExpunge
	 *
	 * NOTE: The above appears in RFC 5465 3.1.
	 * However, this appears to violate the RFC 5234 Augmented Backhaus-Naur Form (ABNF)
	 * given for the NOTIFY command in Section 8, as
	 * events should either be NONE or parenthesized.
	 * Therefore, I find it logical to believe it should be:
	 *
	 * selected (MessageNew (uid body.peek[header.fields (from to subject)]) MessageExpunge)
	 *
	 * mailboxes INBOX (Messagenew messageExpunge)
	 * personal (MessageNew FlagChange MessageExpunge)
	 * mailboxes foobar NONE
	 */

	specname = strsep(&s, " ");
	if (strlen_zero(specname)) {
		bbs_warning("Missing specification name\n");
		return 0;
	}
	if (parse_specifier(&spec, specname)) {
		return 0;
	}

	if (spec == NOTIFY_SUBTREE || spec == NOTIFY_MAILBOXES) {
		int watchable = 0;
		/* 1 or more mailbox names follow.
		 * Don't forget, they could be quoted.
		 * And strchr(s, '(')) isn't robust if the mailbox name contains parentheses. */
		while (!strlen_zero(s) && strcasecmp(s, "NONE") && *s != '(') {
			/* We've got another mailbox name */
			char *mbname = quotesep(&s);
			/* Evaluate the mailbox name now, even before pushing into the stringlist */
			if (!mailbox_watchable(imap, mbname)) {
				bbs_warning("Mailbox '%s' is not watchable\n", mbname);
				continue;
			}
			watchable++;
			/* No need to recurse on children for NOTIFY_SUBTREE */
			stringlist_push(&mbnames, mbname);
			if (STARTS_WITH(mbname, OTHER_NAMESPACE_PREFIX) || STARTS_WITH(mbname, SHARED_NAMESPACE_PREFIX)) {
				notify->nonpersonal = 1;
			}
		}
		if (!watchable) {
			return 0;
		}
	}

	if (strlen_zero(s)) {
		bbs_warning("Incomplete event\n");
		return 0;
	}

	/* Okay, next is either NONE or a parenthesized list of event names */
	if (!strcasecmp(s, "NONE")) {
		none = 1;
	} else if (*s != '(') {
		bbs_warning("Unexpected token: %s\n", s);
	} else {
		char *e, *eventstr;
		eventstr = parensep(&s);
		while ((e = strsep(&eventstr, " "))) {
			/* Parse the events. Some might be followed by a parenthesized list. */
			if (!strcasecmp(e, "FlagChange")) {
				events |= IMAP_EVENT_FLAG_CHANGE;
			} else if (!strcasecmp(e, "MessageNew")) {
				events |= IMAP_EVENT_MESSAGE_NEW;
				if (!strlen_zero(eventstr) && *eventstr == '(') {
					/* Parenthesized list as argument. Only for MessageNew? */
					fetchargs = parensep(&eventstr);
				}
			} else if (!strcasecmp(e, "MessageExpunge")) {
				events |= IMAP_EVENT_MESSAGE_EXPUNGE;
			} else if (!strcasecmp(e, "MailboxName")) {
				events |= IMAP_EVENT_MAILBOX_NAME;
			} else if (!strcasecmp(e, "SubscriptionChange")) {
				events |= IMAP_EVENT_SUBSCRIPTION_CHANGE;
#if 0 /*! \todo Remove once these IMAP extensions are supported */
			} else if (!strcasecmp(e, "AnnotationChange")) {
				events |= IMAP_EVENT_ANNOTATION_CHANGE;
			} else if (!strcasecmp(e, "MailboxMetadataChange")) {
				events |= IMAP_EVENT_MAILBOX_METADATA_CHANGE;
			} else if (!strcasecmp(e, "ServerMetadataChange")) {
				events |= IMAP_EVENT_SERVER_METADATA_CHANGE;
#endif
			} else {
				bbs_warning("Unknown event: '%s'\n", e);
				imap_reply(imap, "NO [BADEVENT] Supported events: FlagChange, MessageNew, MessageExpunge, MailboxName, SubscriptionChange");
				return -1;
			}
		}
		/* RFC 5465 Section 5: New and Expunge must be specified together, and FlagChange and AnnotationChange require New/Expunge. */
		if (events & IMAP_EVENT_MESSAGE_EXPUNGE && !(events & IMAP_EVENT_MESSAGE_NEW)) {
			imap_reply(imap, "BAD [CLIENTBUG] Improper event combination");
			return -1;
		} else if (events & IMAP_EVENT_MESSAGE_NEW && !(events & IMAP_EVENT_MESSAGE_EXPUNGE)) {
			imap_reply(imap, "BAD [CLIENTBUG] Improper event combination");
			return -1;
		} else if (events & (IMAP_EVENT_ANNOTATION_CHANGE | IMAP_EVENT_FLAG_CHANGE) && !(events & IMAP_EVENT_MESSAGE_NEW)) {
			imap_reply(imap, "BAD [CLIENTBUG] Improper event combination");
			return -1;
		}
	}

	w = calloc(1, sizeof(*w) + (fetchargs ? strlen(fetchargs) + 1 : 0));
	if (ALLOC_FAILURE(w)) {
		stringlist_empty_destroy(&mbnames);
		return 0;
	}

	if (spec == NOTIFY_SELECTED) {
		notify->nomsn = 1; /* Message sequence numbers cannot be used */
	}
	w->spec = spec;
	w->events = events;
#ifdef DEBUG_NOTIFY
	bbs_debug(3, "Adding NOTIFY watch for spec %d, events:\n", spec);
	dump_events_str(w->events);
#endif
	SET_BITFIELD(w->none, none);
	if (fetchargs) {
		strcpy(w->data, fetchargs); /* Safe */
		w->fetchargs = w->data;
	}

	/* The stringlist itself contains dynamically allocated pointers.
	 * It's therefore fine to copy the list head itself. */
	memcpy(&w->mbnames, &mbnames, sizeof(w->mbnames));

	RWLIST_INSERT_TAIL(&notify->watchlist, w, entry);
	return 1;
}

static int notify_list_cb(struct imap_session *imap, struct list_command *lcmd, const char *name, void *data)
{
	char fullname[256];
	struct imap_notify *notify = data;
	struct notify_watch *w;

	if (imap->folder && !strcmp(name, imap->folder)) {
		return 0; /* No STATUS for currently selected mailbox */
	}

	if (lcmd->ns == NAMESPACE_OTHER || lcmd->ns == NAMESPACE_SHARED) {
		if (lcmd->ns == NAMESPACE_OTHER) {
			snprintf(fullname, sizeof(fullname), OTHER_NAMESPACE_PREFIX HIERARCHY_DELIMITER "%s", name);
		} else if (lcmd->ns == NAMESPACE_SHARED) {
			snprintf(fullname, sizeof(fullname), SHARED_NAMESPACE_PREFIX HIERARCHY_DELIMITER "%s", name);
		}
		if (strstr(fullname, "..")) {
			bbs_warning("Unexpected folder: '%s' (maildir path '%s' is invalid)\n", name, fullname);
			bbs_soft_assert(!strstr(fullname, "..")); /* If this happens, something got malformed */
		}
		name = fullname;
	}

	RWLIST_RDLOCK(&notify->watchlist);
	w = notify_get_match(imap, name);
	if (w && (w->spec != NOTIFY_SELECTED && w->spec != NOTIFY_SELECTED_DELAYED)) { /* No STATUS for selected mailbox */
		const char *s;
		struct imap_traversal traversal;
		/* If MessageNew: MESSAGES, UIDNEXT, UIDVALIDITY
		 * If MessageExpunge: MESSAGES
		 * If AnnotationChange, FlagChange and CONDSTORE/QRESYNC supported (by us, so true): UIDVALIDITY, HIGHESTMODSEQ
		 *
		 * RFC 5465 Section 5: New and Expunge must be specified together, and FlagChange and AnnotationChange require New/Expunge.
		 */
		if (w->spec & (IMAP_EVENT_MESSAGE_NEW | IMAP_EVENT_MESSAGE_EXPUNGE)) {
			if (w->spec & (IMAP_EVENT_ANNOTATION_CHANGE | IMAP_EVENT_FLAG_CHANGE)) {
				s = "MESSAGES UIDNEXT UIDVALIDITY HIGHESTMODSEQ";
			} else {
				s = "MESSAGES UIDNEXT UIDVALIDITY";
			}
			memset(&traversal, 0, sizeof(traversal));
			if (set_maildir_readonly(imap, &traversal, name)) {
				bbs_error("Failed to set maildir for %s\n", name);
			} else {
				local_status(imap, &traversal, name, s); /* We know this folder is local, not remote */
			}
		} /* else, no STATUS needed */
	} else {
		bbs_debug(6, "Skipping NOTIFY STATUS for %s\n", name);
	}
	RWLIST_UNLOCK(&notify->watchlist);
	return 0;
}

/* If the client is being ridiculous, don't put up with it */
#define MAX_NOTIFY_EVENT_GROUPS 50

int handle_notify(struct imap_session *imap, char *s)
{
	struct imap_notify *notify;
	char *ws;
	int sendstatus = 0;
	int added = 0;

	if (!strcasecmp(s, "NONE")) {
		/* Not interested in receiving any events at all.
		 * Destroy all existing watches. */
		notify = notify_get(imap);
		if (!notify) {
			imap_reply(imap, "NO [SERVERBUG] Allocation failure");
			return -1;
		}
		notify->none = 1;
		imap_reply(imap, "OK NOTIFY done");
		return 0;
	} else if (!STARTS_WITH(s, "SET ")) {
		imap_reply(imap, "BAD [CLIENTBUG] Invalid NOTIFY command");
		return 0;
	}

	s += STRLEN("SET ");

	/* SET: replace previous watchlist with new watchlist */
	if (strlen_zero(s)) {
		imap_reply(imap, "NO [CLIENTBUG] Incomplete NOTIFY command");
		return 0;
	}

	if (STARTS_WITH(s, "STATUS ")) {
		sendstatus = 1;
		s += STRLEN("STATUS ");
		if (strlen_zero(s)) {
			imap_reply(imap, "NO [CLIENTBUG] Incomplete NOTIFY command");
			return 0;
		}
	}

	/* Destroy any previous watchlist */
	notify = notify_get(imap);
	if (!notify) {
		imap_reply(imap, "NO [SERVERBUG] Allocation failure");
		return -1;
	}
	notify->none = 0;
	notify_destroy(notify);

	RWLIST_WRLOCK(&notify->watchlist);

	/* They're each parenthesized */
	while ((ws = parensep(&s))) {
		int res;
		res = add_watch(imap, notify, ws);
		if (res < 0) {
			RWLIST_UNLOCK(&notify->watchlist);
			return 0;
		}
		added += res;
	}

	if (!added) {
		imap_reply(imap, "NO Specified mailboxes not accessible");
		/* No change */
		RWLIST_UNLOCK(&notify->watchlist);
		return 0;
	} else if (added > MAX_NOTIFY_EVENT_GROUPS) {
		imap_reply(imap, "NO [NOTIFICATIONOVERFLOW] Too many event groups");
		notify_destroy(notify);
		notify->none = 1; /* Behave as if we got a NOTIFY NONE */
		RWLIST_UNLOCK(&notify->watchlist);
		return 0;
	}
	RWLIST_UNLOCK(&notify->watchlist);

	if (sendstatus) {
		/* Iterate over all the watches and send a STATUS response
		 * for any mailbox that matches.
		 * This is basically like doing a LIST-STATUS, except we only want the STATUS responses, not the LIST responses. */
		struct list_command lcmd;

		memset(&lcmd, 0, sizeof(lcmd));
		lcmd.ns = NAMESPACE_PRIVATE;
		list_iterate(imap, &lcmd, 0, "", mailbox_maildir(imap->mbox), notify_list_cb, notify);
		if (notify->nonpersonal) {
			lcmd.ns = NAMESPACE_SHARED;
			list_iterate(imap, &lcmd, 0, "", mailbox_maildir(NULL), notify_list_cb, notify);
			lcmd.ns = NAMESPACE_OTHER;
			list_iterate(imap, &lcmd, 0, "", mailbox_maildir(NULL), notify_list_cb, notify);
		}
		/* XXX FIXME What about remote mailboxes??? */
	}

	imap_reply(imap, "OK NOTIFY done");
	return 0;
}
