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
 * \brief Local Paging Handler
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>

#include "include/module.h"
#include "include/config.h"
#include "include/cli.h"
#include "include/node.h"
#include "include/term.h"
#include "include/paging.h"
#include "include/crypt.h"
#include "include/user.h"
#include "include/transfer.h"
#include "include/notify.h"
#include "include/variables.h"
#include "include/system.h"
#include "include/ratelimit.h"
#include "include/stringlist.h"
#include "include/utils.h"

static unsigned int maxmsglen = 256; /* Default */
static char all_externalcmd[512] = "";
static pthread_t queue_thread = 0;
static int unloading = 0;

/* Use a more aggressive queuing interval than SMTP, given the urgency of pages */
#define QUEUE_SLEEP_INTERVAL_SEC 60

/* Keep retrying pages in queue no longer than 1 day and 1 hour (which may seem long, but it's much shorter than SMTP)
 * We don't want it too short either; SNPP's "EXPT" command accepts an argument in hours */
#define QUEUE_MAX_RETRY_SEC 90000

static const char *pager_type_name(enum pager_type type)
{
	switch (type & (PAGER_TONE_ONLY | PAGER_NUMERIC | PAGER_ALPHANUMERIC)) {
		case PAGER_TONE_ONLY: return "Tone Only";
		case PAGER_NUMERIC: return "Numeric";
		case PAGER_ALPHANUMERIC: return "Alphanumeric";
		default: return "?";
	}
	__builtin_unreachable();
}

struct pager_endpoint {
	const char *pagerid;				/*!< Pager ID */
	const char *pin;					/*!< Optional: PIN */
	enum pager_type type;				/*!< Pager type */
	struct bbs_rate_limit ratelimit;	/*!< Rate limiting structure */
	/* User only */
	unsigned int userid;				/*!< Optional: User ID associated with this pager ID */
	unsigned int sendirc:1;				/*!< Attempt delivery via IRC */
	unsigned int retries:1;				/*!< Whether to retry if we can't deliver it immediately (similar to !NOQUEUE in SNPP, but set at the endpoint level) */
	const char *snpp;					/*!< Attempt delivery to this SNPP destination */
	const char *snppid;					/*!< SNPP pager ID override */
	const char *snpppin;				/*!< SNPP pin */
	const char *email;					/*!< Attempt delivery to this email destination */
	const char *emailuser;				/*!< SMTP email user part override */
	const char *tap;					/*!< Attempt delivery to this TAP/IXO destination */
	const char *tapuser;				/*!< TAP/IXO pager ID override */
	const char *externalcmd;			/*!< External command to run */
	RWLIST_ENTRY(pager_endpoint) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(endpoints, pager_endpoint);

struct paging_alias_target {
	struct pager_endpoint *endpoint;
	RWLIST_ENTRY(paging_alias_target) entry;
};

RWLIST_HEAD(paging_alias_targets, paging_alias_target);

/*! \brief Paging alias pointing to one or more real endpoints */
struct paging_alias {
	const char *pagerid;
	const char *pin;
	/* Note: Aliases do not have an inherent type, but are the superset of the capabilities of their targets.
	 * Aliases are never two-way since these are 1:many */
	enum pager_type type;
	struct paging_alias_targets targets;
	RWLIST_ENTRY(paging_alias) entry;
	char data[];
};

/* Note, we lock endpoints equivalently, in lieu of locking the aliases list */
static RWLIST_HEAD_STATIC(aliases, paging_alias);

static void free_alias(struct paging_alias *a)
{
	RWLIST_REMOVE_ALL(&a->targets, entry, free);
	free(a);
}

/*! \brief Whether pager ID is valid format (currently, we require it to be alphanumeric, or somebody's username) */
#define valid_pagerid(s) (bbs_str_fully_alphanumeric(s) || bbs_user_exists(s))

/*! \note Must be called with endpoints locked */
static struct pager_endpoint *find_endpoint(const char *pagerid, int match_wildcard)
{
	struct pager_endpoint *e, *u = NULL;
	unsigned int userid = 0;
	int could_be_username = !bbs_str_fully_alphanumeric(pagerid) && strcmp(pagerid, "*");
	if (could_be_username) {
		userid = bbs_userid_from_username(pagerid);
	}
	RWLIST_TRAVERSE(&endpoints, e, entry) {
		if (!strcasecmp(e->pagerid, pagerid)) {
			return e;
		}
		if (match_wildcard) {
			/* Note this logic depends on tail insert when we add endpoints, i.e. default will be first during traversal */
			if (e->userid && userid == e->userid && !u) {
				bbs_debug(7, "Resolved pager ID %s to username match\n", pagerid);
				u = e; /* Use a user's first endpoint as the default match for paging by username if we can't find an explicit one */
			}
			if (!u && !strcmp(e->pagerid, "*")) {
				bbs_debug(6, "Resolved pager ID %s to wildcard match\n", pagerid);
				return e; /* Wildcard match is at the end, so if we get here, it's the strictest possible match */
			}
		}
	}
	return u;
}

#define resolve_endpoint(pagerid) find_endpoint(pagerid, 1)
#define find_exact_endpoint(pagerid) find_endpoint(pagerid, 0)

static struct paging_alias *resolve_alias(const char *pagerid)
{
	struct paging_alias *a;
	RWLIST_TRAVERSE(&aliases, a, entry) {
		if (!strcasecmp(a->pagerid, pagerid)) {
			return a;
		}
		if (!strcmp(a->pagerid, "*")) {
			bbs_debug(6, "Resolved paging alias %s to wildcard match\n", pagerid);
			return a; /* Wildcard match is at the end, so if we get here, it's the strictest possible match */
		}
	}
	return NULL;
}

static enum pager_type min_pager_requirement(const char *s)
{
	enum pager_type reqtypes = PAGER_TONE_ONLY;
	/* Scan the message to determine what's required */
	if (strlen_zero(s)) {
		return PAGER_TONE_ONLY; /* Anything will do */
	}
	while (*s) {
		if (isdigit(*s)) {
			reqtypes |= PAGER_NUMERIC;
		} else {
			reqtypes |= PAGER_ALPHANUMERIC;
		}
		s++;
	}
	return reqtypes;
}

static int pager_exists(const char *pagerid, enum pager_type *type, enum pager_requirements req)
{
	/* Note: net_snpp uses this callback, but not net_tap */
	struct pager_endpoint *e;
	struct paging_alias *a = NULL;

	if (req & PAGER_REQ_TWOWAY) {
		/*! \todo FIXME We don't currently support two-way paging, so just reject the request entirely.
		 * ENETDOWN and ENOTCONN not currently used here. */
		errno = EPROTOTYPE;
		return -1;
	}

	RWLIST_RDLOCK(&endpoints);
	e = resolve_endpoint(pagerid);
	if (e) {
		*type  = e->type;
	} else {
		a = resolve_alias(pagerid);
		if (a) {
			/* If an alias expands to multiple targets, it cannot be used for a 2WAY transaction, that would make no sense */
			if (req & PAGER_REQ_TWOWAY) {
				struct paging_alias_target *t;
				if (RWLIST_SIZE(&a->targets, t, entry) > 1) {
					RWLIST_UNLOCK(&endpoints);
					errno = EPROTOTYPE;
					return -1;
				}
			}
			*type = a->type; /* Type is the superset of its target types */
		}
	}
	RWLIST_UNLOCK(&endpoints);
	return e || a ? 1 : 0;
}

static int pager_ping(const char *pagerid, char *buf, size_t len)
{
	struct pager_endpoint *e;

	if (!valid_pagerid(pagerid)) {
		errno = EINVAL;
		return -1;
	}

	RWLIST_RDLOCK(&endpoints);

	/* Does the endpoint exist? */
	e = resolve_endpoint(pagerid);
	if (!e)	{
		RWLIST_UNLOCK(&endpoints);
		errno = ENOENT;
		return -1;
	}
	if (e->userid && e->sendirc) {
		if (strlen_zero(e->externalcmd) && strlen_zero(e->snpp) && strlen_zero(e->email) && strlen_zero(e->tap)) {
			/* If user is currently online on IRC, treat as "online" for paging purposes */
			if (bbs_node_user_count(e->userid, "net_irc") > 0) {
				RWLIST_UNLOCK(&endpoints);
				errno = EIDRM; /* We have no actual location information, so just return EIDRM, like the default */
				return -1;
			} else {
				/* User only pageable via IRC, and not currently on IRC */
				RWLIST_UNLOCK(&endpoints);
				/* We use ENETDOWN instead of ENONET (which has a more appropriate description)
				 * since ENONET isn't POSIX and thus isn't defined on FreeBSD */
				errno = ENETDOWN;
				return -1;
			}
		}
	}
	RWLIST_UNLOCK(&endpoints);

	/* Two-way paging not currently supported, and we certainly don't support geolocation of pagers,
	 * so just say no info available. */
	UNUSED(buf);
	UNUSED(len);
	errno = EIDRM;
	return -1;
}

enum queue_methods {
	/* IRC and externalcmd do not get queued, they are only tried the first time in a blocking manner */
	QUEUE_SNPP = (1 << 0),
	QUEUE_SMTP = (1 << 1),
	QUEUE_TAP = (1 << 2),
};

#define QUEUE_ALL (QUEUE_SNPP | QUEUE_SMTP | QUEUE_TAP)

/*! \brief Queued page to a single recipient - currently, the entire queue is stored only in memory, since we don't expect messages to be stored long */
struct queued_page {
	const char *pagerid;
	const char *pin;
	struct pager_endpoint *e;			/*!< Pointer to endpoint associated with this recipient */
	struct bbs_paging_options parameters;
	struct bbs_paging_message_metadata meta;
	struct bbs_paging_data data;
	enum queue_methods methods;
	char *response;						/*!< Allocated response, which will be provided to caller via a const pointer. Cleaned up when we free ourselves. */
	time_t added;						/*!< Time added to queue */
	time_t lastretry;					/*!< Last retry time */
	time_t finalresponseread;			/*!< First time that a final 88x response was read by a client (0 if never). If set, we can expire more quickly */
	int numretries;						/*!< Number of retries */
	pthread_t owner;
	RWLIST_ENTRY(queued_page) entry;
	unsigned int sent:1;				/*!< Message sent, do not reattempt */
	unsigned int expired:1;
	unsigned int inprogress:1;			/*!< Whether a dedicated thread is currently attempting delivery of this message for the first time */
	char fsmdata[];
};

static RWLIST_HEAD_STATIC(queued_pages, queued_page);

static void free_queued_page(struct queued_page *q)
{
	if (q->owner) {
		bbs_pthread_join(q->owner, NULL);
	}
	bbs_paging_data_free_contents(&q->data);
	free_if(q->response);
	free(q);
}

/*! \note Must be called locked */
static struct queued_page *find_queued_page(const char *msgtag)
{
	struct queued_page *q;
	RWLIST_TRAVERSE(&queued_pages, q, entry) {
		if (!strcmp(q->meta.msgtag, msgtag)) {
			return q;
		}
	}
	return NULL;
}

/* Forward declaration */
static int deliver_queued_message(struct queued_page *q);

static void *handle_queued_transaction(void *varg)
{
	struct queued_page *q = varg;
	deliver_queued_message(q);
	q->lastretry = time(NULL); /* Start counting from when the last attempt finished, not when it started */
	q->inprogress = 0; /* Indicate that we're done, and wait for the periodic queue thread to reap the thread eventually */
	return NULL;
}

/*! \brief Exponential backoff */
static int next_retry_time(int n)
{
	switch (n) {
		case 0:
			/* Fall through */
		case 1: return 30;
		case 2: return 60;
		case 3: return 120;
		case 4: return 180;
		case 5: return 300;
		case 6: return 600;
		case 7: return 1200;
		case 8: return 1800;
		case 9: return 3600;
		case 10: return 7200;
		case 11: return 14400;
		case 12: return 21600;
		case 13: return 43200;
		case 14:
		default:
			return 86400;
	}
}

static void *periodic_queue_thread(void *unused)
{
	UNUSED(unused);

	for (;;) {
		struct queued_page *q;
		int wait_sec = QUEUE_SLEEP_INTERVAL_SEC;
		time_t now = time(NULL);

		/* XXX If unloading, the main thread has queued_pages WRLOCK'd when trying to join this thread,
		 * so don't try to grab the lock or we'll deadlock. */
		if (unloading) {
			break;
		}

		/* Inspect everything in queue, and flag messages to deliver.
		 * However, don't attempt them with the lock held.
		 * We do it this way to avoid locking the list for a non-trivial amount of time,
		 * to ensure that queue_page is able to insert new items into the list without waiting, for the initial send. */
		RWLIST_RDLOCK(&queued_pages); /* We don't delete anything from queue here, so RDLOCK is fine */
		RWLIST_TRAVERSE(&queued_pages, q, entry) {
			if (q->inprogress) {
				continue; /* Not ours to mess with, yet */
			} else if (q->owner) {
				/* The owner exited, join it.
				 * The only other path that joins thread has a WRLOCK, and there's only one instance of this thread, so we won't conflict */
				bbs_pthread_join(q->owner, NULL);
				q->owner = 0;
			}
			if (q->expired) {
				continue; /* Nope, it's expired */
			}
			if (q->sent) {
				continue; /* Delivery was already attempted and succeeded or failed; we don't try again */
			}
			if (q->meta.status & PAGE_DELIVERED) {
				continue; /* We delivered it already */
			}
			if (q->parameters.holduntil && q->parameters.holduntil > now) {
				continue; /* Can't send it yet */
			}
			if (q->added < now - QUEUE_MAX_RETRY_SEC) {
				bbs_debug(4, "Page %s has expired in queue\n", q->meta.msgtag);
				q->expired = 1;
				continue;
			}
			if (q->added + next_retry_time(q->numretries) > now) {
				continue; /* Too soon */
			}
			/* Create a new thread, so we can attempt multiple in parallel, if needed */
			bbs_debug(6, "Retrying delivery of page %s\n", q->meta.msgtag);
			q->numretries++;
			q->inprogress = 1;
			bbs_pthread_create(&q->owner, NULL, handle_queued_transaction, q);
		}
		RWLIST_UNLOCK(&queued_pages);

		/* Calculate how long until the earliest retry in the queue to be attempted
		 * This esp. matters for messages that should be held for delivery until a certain time has passed.
		 * The edge case here is messages that get added to the queue while we are sleeping, between intervals.
		 * When adding a message to queue, we'll get interrupted if we need to recalculate. */
		RWLIST_WRLOCK(&queued_pages);
		RWLIST_TRAVERSE_SAFE_BEGIN(&queued_pages, q, entry) {
			int prune = 0;
			/* Prune any dead items */
			if (q->finalresponseread && q->finalresponseread < now - 60) {
				/* If a final 88x response was read by a client more than 60 seconds ago,
				 * we can delete it. */
				prune = 1;
			} else if ((q->expired || q->sent) && q->meta.timestamp < now - 3600) {
				/* It expired more than an hour ago, get rid of it */
				prune = 1;
			} else if (q->meta.status & PAGE_DELIVERED) {
				/* If it's delivered, we need to be careful.
				 * If we're waiting for a reply, we should keep it in queue longer.
				 * If not, we can get rid of it more quickly. */
				if (q->meta.status & (PAGE_AWAITING_READACK | PAGE_READ | PAGE_AWAITING_REPLY | PAGE_REPLY_RECEIVED)) {
					prune = q->meta.timestamp < now - 86400;
				} else {
					prune = q->meta.timestamp < now - 3600;
				}
			}

			if (prune) {
				bbs_debug(6, "Purging page %s\n", q->meta.msgtag);
				RWLIST_REMOVE_CURRENT(entry);
				free_queued_page(q);
				continue;
			}
			if (q->parameters.holduntil) {
				time_t diff = q->parameters.holduntil - now;
				if (diff < 0) {
					diff = 0;
				}
				wait_sec = MIN(wait_sec, (int) diff); /* Use the shortest wait needed to satisfy everyone */
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
		RWLIST_UNLOCK(&queued_pages);

		if (!wait_sec) {
			continue; /* No need to wait, there is at least one message that needs to be delivered now */
		} else if (unloading) {
			break;
		}

		if (bbs_safe_sleep_interrupt(SEC_MS(wait_sec))) { /* Don't use usleep, as the SIGURG signal doesn't succeed in interrupting it */
			bbs_debug(8, "Periodic queue thread interrupted\n");
			if (unloading) {
				break;
			}
			break;
		}
	}
	return NULL;
}

static void update_timestamp(struct queued_page *q, time_t now)
{
	q->meta.timestamp = now;
}

static char *duplicate_with_trailing_cr_lf_if_needed(const char *s, int must_end_in_crlf)
{
	/* Add CR LF to the end if needed, with just one allocation */
	if (must_end_in_crlf && !strlen_zero(s) && !bbs_str_ends_with(s, "\r\n")) {
		char *newstr;
		size_t origlen = strlen(s);

		bbs_debug(6, "Appending CR LF to end of message for RFC822 compliance\n");

		newstr = malloc(origlen + 3); /* CR LF NUL */
		if (ALLOC_SUCCESS(newstr)) {
			memcpy(newstr, s, origlen);
			strcpy(newstr + origlen, "\r\n"); /* Safe */
		}
		return newstr;
	} else {
		return strdup_if(s);
	}
}

/*! \brief Queue a page for future asynchronous delivery */
static struct queued_page *queue_page(struct pager_endpoint *e, struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta, enum queue_methods methods)
{
	struct queued_page *q;
	size_t pageridlen, pinlen;
	time_t now;
	char *fsmdata;

	pageridlen = STRING_ALLOC_SIZE(recipient->pagerid);
	pinlen = STRING_ALLOC_SIZE(recipient->pin);

	q = calloc(1, sizeof(*q) + pageridlen + pinlen);
	if (ALLOC_FAILURE(q)) {
		return NULL;
	}
	fsmdata = q->fsmdata;

	/* Save the recipient info */
	SET_FSM_STRING_VAR(q, fsmdata, pagerid, recipient->pagerid, pageridlen);
	SET_FSM_STRING_VAR(q, fsmdata, pin, recipient->pin, pinlen);

	/* Save the parameters */
	memcpy(&q->parameters, &recipient->parameters, sizeof(struct bbs_paging_options));

	/* Save the message metadata */
	strcpy(q->meta.msgtag, meta->msgtag); /* Safe */
	strcpy(q->meta.passcode, meta->passcode); /* Safe */

	/* Copy over data, and reallocate any of its dynamic members */
	memcpy(&q->data, data, sizeof(struct bbs_paging_data));

	/* If the body doesn't end in CR LF, we need to add it or DKIM signing will fail */
	q->data.message = duplicate_with_trailing_cr_lf_if_needed(data->message, methods & QUEUE_SMTP);
	q->data.body = duplicate_with_trailing_cr_lf_if_needed(data->body, methods & QUEUE_SMTP);

	q->data.subject = strdup_if(data->subject);
	q->data.callerid = strdup_if(data->callerid);
	q->data.node = NULL;

	q->e = e;
	q->methods = methods;
	q->meta.status = 0;
	if (q->data.readack) {
		/* Note, readacks and read receipts are not currently supported, so this currently does nothing */
		q->meta.status |= PAGE_AWAITING_READACK;
	}
	now = time(NULL);
	q->added = now;
	update_timestamp(q, now);

	/* Insert into the list so we can find it later.
	 * Lock BEFORE launching the new thread, to ensure
	 * that when the new thread acquires the lock, the item is present. */
	RWLIST_WRLOCK(&queued_pages);

	if (methods) {
		/* Create a new thread to attempt it immediately (but asynchronously).
		 * This way, multiple queued pages can be attempted simultaneously, if needed.
		 * We indicate that it's in progress so the periodic queue thread doesn't try to handle it at the same time. */
		q->inprogress = 1;
		if (bbs_pthread_create(&q->owner, NULL, handle_queued_transaction, q)) {
			RWLIST_UNLOCK(&queued_pages);
			free(q);
			return NULL;
		}

		/* This is an unlikely, but possible, edge case.
		 * If we are inserting an item whose delivery should be held,
		 * but for a duration that could be before the next time the queue might run,
		 * wake it up now to force it to recalculate it when it will run next. */
		if (q->parameters.holduntil && q->parameters.holduntil < now + QUEUE_SLEEP_INTERVAL_SEC) {
			bbs_pthread_interrupt(queue_thread);
		}
	}

	RWLIST_INSERT_TAIL(&queued_pages, q, entry); /* This way, most recent pages are at bottom of "paging queue" CLI output */
	RWLIST_UNLOCK(&queued_pages);
	return q;
}

static int run_external_cmd(struct bbs_paging_data *data, unsigned int userid, const char *cmd)
{
	char subbuf[1024];
	char *argv[32];
	char *s;
	int argc;
	int res;
	struct bbs_exec_params x;

	bbs_node_substitute_vars(data->node, cmd, subbuf, sizeof(subbuf));
	s = subbuf;

	argc = bbs_argv_from_str(argv, ARRAY_LEN(argv), s); /* Parse string into argv */
	if (argc < 1 || argc > (int) ARRAY_LEN(argv)) {
		bbs_error("Too many arguments in '%s'\n", cmd);
		return -1;
	}

	EXEC_PARAMS_INIT_HEADLESS(x);
	x.exectimeout = 60; /* Kill after one minute */
	if (userid) {
		/* Run in container if user-provided command */
		x.isolated = 1;
		x.user = bbs_user_from_userid(userid);
	}

	res = bbs_execvp(data->node, &x, argv[0], argv); /* Directly return the exit code */

	if (x.user) {
		bbs_user_destroy(x.user); /* Destroy the temporary user we created for execution */
	}
	return res;
}

/*!
 * \brief Try to deliver the page the first time, during a transaction (future attempts while in queue only do a subset of these tasks)
 * \note Must be called with endpoints locked
 */
static int deliver_page(struct pager_endpoint *e, struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	char combined[2048];
	const char *singlemsg = NULL;
	int sent = 0, received = 0;
	int res = -1, saved_errno = 0;
	enum queue_methods methods = 0;
	const char *msgbody = S_OR(data->body, data->message); /* Only one or the other is used */

	/* If the message has a hold for this recipient, check if we can deliver it yet.
	 * If not, add it to queue and return immediately. */
	if (recipient->parameters.holduntil) {
		time_t now = time(NULL);
		if (recipient->parameters.holduntil > now) {
			/* Add to queue */
			methods |= QUEUE_ALL;
			goto queue;
		}
	}

	/* First, if we can only send a single string (e.g. POCSAG, IRC, etc.), generate the combined string.
	 * Keep in mind, we may have a message body, even if this pager doesn't accept certain types of messages. */
	if (e->type & PAGER_ALPHANUMERIC) {
		if (!strlen_zero(msgbody)) {
			snprintf(combined, sizeof(combined),
				"%s%s%s"
				"%s%s%s"
				"%s",
				/* Spok POCSAG pages use the format:
				 * Email: "From <email> Subject: subj - Message"
				 * Phone: Message
				 */
				S_COR(data->callerid, "From: ", ""), S_IF(data->callerid), S_COR(data->callerid, " ", ""),
				S_COR(data->subject, "Subject: ", ""), S_IF(data->subject), S_COR(data->subject, " - ", ""),
				S_IF(msgbody));
			singlemsg = combined;
		} else {
			if (!strlen_zero(data->callerid)) {
				snprintf(combined, sizeof(combined), "New Page Received From %s", data->callerid);
				singlemsg = combined;
			} /* else, there is nothing meaningful we can send */
		}
	} else if (e->type & PAGER_NUMERIC) {
		if (!strlen_zero(data->body) || !strlen_zero(data->message)) {
			if (bbs_str_fully_numeric(msgbody)) {
				singlemsg = msgbody;
			} else {
				singlemsg = NULL; /* If message isn't fully numeric, don't send the message to this recipient */
			}
		} /* else, nothing to send */
	} /* else, must be PAGER_TONE_ONLY, nothing to send */

	/* Note: If we are going to pass on the message to this endpoint, it needs to comply with its type (alpha/numeric/tone-only)
	 * However, depending on the delivery method (e.g. IRC, SNPP, etc.) we may not have those limitations,
	 * and can substitute a generic string in if our payload would be empty. */

	/* Attempt to deliver immediately, and if we can't, add it to queue */

	/* It's a personal paging endpoint */
	if (e->userid) {
		/* If user is online on IRC, try to send a message there, using the alerting APIs */
		if (e->sendirc) {
			bbs_debug(6, "Paging user %u via IRC/IMAP\n", e->userid);
			res = bbs_alert_user(e->userid, DELIVERY_EPHEMERAL, "%s", S_OR(singlemsg, "New Page Received"));
			if (!res) {
				sent++;
				received++;
				/* This is unique in that even if we succeed, we still continue to deliver using a "real" method,
				 * e.g. SNPP, SMTP, or TAP/IXO. */
			} else {
				/* User was not online.
				 * This is a bit of a weird case. In SNPP, if a pager is not online,
				 * the transaction is rejected at "PAGE", not at "SEND".
				 * It's always possible the user went offline inbetween,
				 * and if IRC is the only configured method, then respond with temporary failure. */
				bbs_debug(5, "Can't alert user %u (not currently online)\n", e->userid);
				saved_errno = EAGAIN;
				res = -1;
			}
		}
	}

	if (e->snpp) {
		/* Attempt SNPP relay in real time.
		 * If it fails with a temporary error (but not a permanent error), we queue it for later. */
		struct bbs_paging_data protdata;
		struct bbs_paging_recipient protrecip = {
			.parameters = recipient->parameters,
		};
		struct bbs_paging_message_metadata metadata;

		memset(&metadata, 0, sizeof(metadata)); /* We need our own local metadata, since page_single overwrites the msgtag */
		memcpy(&protdata, data, sizeof(struct bbs_paging_data));
		protdata.prot = PAGING_PROT_SNPP; /* Have the SNPP module handle this */
		protdata.gateway = e->snpp;
		protrecip.pagerid = S_OR(e->snppid, recipient->pagerid);
		protrecip.pin = e->snpppin;
		res = bbs_page_single(&protrecip, &protdata, &metadata);
		if (res) {
			saved_errno = errno;
			if (saved_errno == EAGAIN) {
				if (!data->noqueue && e->retries) {
					methods |= QUEUE_SNPP; /* Sure, we can try again later (unless NOQUEUE is set via SNPP or !retries is set in the endpoint config) */
				}
			} /* else, any other error is fatal */
		} else {
			sent++;
		}
	}
	if (e->email) {
		/* Since email involves queuing anyways, there is no point in not queuing it here */
		methods |= QUEUE_SMTP;
	}
	if (e->tap) {
		/* TAP takes a non-trivial amount of time to send a transaction,
		 * so don't block the connection while we're waiting.
		 * Instead, add it to the queue and send it asynchronously. */
		methods |= QUEUE_TAP;
	}

	/* Since the user-provided commands could take a moment to run, we execute these last,
	 * after getting the page out via IRC/SNPP, if possible. */
	if (!s_strlen_zero(all_externalcmd) || e->externalcmd) {
		bbs_node_var_set(data->node, "PAGENUMBER", recipient->pagerid);
		bbs_node_var_set(data->node, "PAGESUBJECT", data->subject); /* Okay if NULL */
		bbs_node_var_set(data->node, "PAGEMESSAGE", msgbody); /* Okay if NULL */
		if (!s_strlen_zero(all_externalcmd)) {
			res = run_external_cmd(data, 0, all_externalcmd);
			if (!res) {
				sent++;
			} else {
				/* Only use the error code from system-wide command execution if we don't already have one.
				 * If we do, it's more relevant and we'll use the one we already have instead. */
				if (!saved_errno) {
					saved_errno = res;
				}
				res = -1;
			}
		}
		if (e->externalcmd) {
			res = run_external_cmd(data, e->userid, e->externalcmd);
			if (!res) {
				sent++;
			} else {
				saved_errno = res;
				res = -1;
			}
		}
	}

	/* If we need to queue the message for one or more protocols, do so */
queue:
	if (methods) {
		bbs_debug(4, "Queuing page %s (SNPP: %s, SMTP: %s, TAP: %s)\n", meta->msgtag,
			BBS_YESNO(methods & QUEUE_SNPP), BBS_YESNO(methods & QUEUE_SMTP), BBS_YESNO(methods & QUEUE_TAP));
		if (!queue_page(e, recipient, data, meta, methods)) {
			errno = EAGAIN;
			return -1;
		}
		sent++; /* Count it as sent, but not as received */
	} else {
		/* If not queued, delivery was attempted and already succeeded or failed;
		 * store the meta data in the queue list, where it will eventually get reaped.
		 * We do this for all pages, even those that aren't 2WAY pages, so that
		 * their status can be checked later (e.g. using MSTA).
		 * Since some non-2WAY pages will get queued anyways (e.g. email delivery, TAP/IXO),
		 * it makes sense that we store all of them in the list regardless
		 * so that we can check the status regardless of delivery mechanism. */
		struct queued_page *q = queue_page(e, recipient, data, meta, 0);
		if (q) {
			update_timestamp(q, time(NULL));
			q->sent = 1; /* We should not attempt delivery again; separate from q->expired, because delivery attempts didn't expire, they finished */
			if (received) {
				q->meta.status |= PAGE_DELIVERED;
			}
		}
	}

	/* Based on where we relayed the page, take the "best" outcome that we got and use that for the response. */
	if (received) {
		/* If we know it was received, then we can say with confidence the page was delivered. */
		meta->timestamp = time(NULL);
		meta->status |= PAGE_DELIVERED;
	} else if (sent) {
		meta->timestamp = time(NULL);
	} else {
		/* Uh oh, we failed to send it on via any methods and couldn't queue it.
		 * Since we must have at least one delivery method enabled,
		 * res should be -1 here (we must have attempted all configured methods and failed at all of them),
		 * and errno should be set appropriately already. */
		meta->timestamp = time(NULL);
		bbs_assert(res != 0);
		errno = saved_errno;
		return -1;
	}
	return 0;
}

static const char *page_strerror(int errno_arg)
{
	switch (errno_arg) {
		case ENXIO: return "Desired paging protocol unavailable";
		case ENOENT: return "No such pager ID";
		case EAGAIN: return "Temporary delivery failure";
		case ECHILD: return "No paging providers registered";
		case ENOSYS: return "Command not implemented";
		case EACCES: return "Correct PIN not provided";
		case EINVAL: return "Illegal pager ID format";
		case EDOM: return "Tone-only pager, no message allowed";
		case ERANGE: return "Numeric paging only";
		case EMSGSIZE: return "Long message rejected";
		case EDQUOT: return "Message quota temporarily exceeded";
	}
	bbs_warning("Unhandled error: %d (%s)\n", errno_arg, strerror(errno));
	return "Unknown Error";
}

/*! \brief (Re)attempt delivery of a single message in queue */
static int deliver_queued_message(struct queued_page *q)
{
	int sent = 0, received = 0;
	int res = -1, saved_errno = 0;
	struct bbs_paging_data protdata;
	struct bbs_paging_recipient protrecip = {
		.parameters = q->parameters,
	};
	struct bbs_paging_message_metadata metadata;

	memset(&metadata, 0, sizeof(metadata)); /* We need our own local metadata, since page_single overwrites the msgtag */
	memcpy(&protdata, &q->data, sizeof(struct bbs_paging_data));

#define PAGE_TRY_METHOD(field, flag, protocol, pageridnum, pagerpassword, gw) \
	if (q->e->field && (q->methods & flag)) { \
		bbs_debug(4, "Attempting subdelivery for %s using %s\n", q->meta.msgtag, #protocol); \
		protdata.prot = protocol; \
		protdata.gateway = gw; \
		protrecip.pagerid = pageridnum; \
		protrecip.pin = pagerpassword; \
		res = bbs_page_single(&protrecip, &protdata, &metadata); \
		if (res) { \
			saved_errno = errno; \
			bbs_notice("Page subdelivery for %s using %s failed (%s)\n", q->meta.msgtag, #protocol + STRLEN("PAGING_PROT_"), page_strerror(saved_errno)); \
		} else { \
			sent++; \
		} \
	}

	/*! \todo For some methods, esp. TAP/IXO, if we have multiple pages queued using a particular gateway,
	 * it would be optimal to send them all during one session to avoid connection setup for each page.
	 * The current queuing logic is per-page only, without respect to the gateway used. */
	PAGE_TRY_METHOD(snpp, QUEUE_SNPP, PAGING_PROT_SNPP, S_OR(q->e->snppid, q->pagerid), q->e->snpppin, q->e->snpp);
	PAGE_TRY_METHOD(email, QUEUE_SMTP, PAGING_PROT_SMTP, S_OR(q->e->emailuser, q->pagerid), NULL, q->e->email);
	PAGE_TRY_METHOD(tap, QUEUE_TAP, PAGING_PROT_TAP_IXO, S_OR(q->e->tapuser, q->pagerid), NULL, q->e->tap);

	if (q->data.noqueue || !q->e->retries) {
		q->expired = 1; /* If NOQUEUE is set, or we should not retry, then after one attempt, we stop */
		update_timestamp(q, time(NULL));
	}

	/* If we already set a "good" status, don't backtrack */
	if (received || q->meta.status & PAGE_DELIVERED) {
		if (q->meta.status != PAGE_DELIVERED) {
			update_timestamp(q, time(NULL));
			q->meta.status |= PAGE_DELIVERED;
		}
		q->sent = 1; /* Sent, do not retry again */
	} else if (sent) { /* Still not delivered */
		update_timestamp(q, time(NULL));
		q->sent = 1; /* Sent, do not retry again */
	} else {
		update_timestamp(q, time(NULL));
		bbs_assert(res != 0);
		errno = saved_errno;
		return -1;
	}
	return 0;
}

static int page_single(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta);

static int page_multiple(struct bbs_paging_recipients *recipients, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	int res = -1;
	struct bbs_paging_recipient *r;

	/*! \todo An optimization would be if there are multiple recipients destined for the same gateway,
	 * dispatch them in one go (i.e. one phone call, one SNPP transaction) for efficiency.
	 * Though that might be easier to accomplish leaving this intact,
	 * and modifying queuing logic such that external SNPP and TAP/IXO deliveries
	 * get added to queue, which we process after the entire transaction is over,
	 * grouping together messages going to the same gateway or terminal. */
	RWLIST_TRAVERSE(recipients, r, entry) {
		int mres = page_single(r, data, meta);
		if (!mres) {
			res = 0;
		}
	}
	return res;
}

static int deliver_to_alias(struct bbs_paging_recipient *aliasrecipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta, struct paging_alias *a)
{
	struct bbs_paging_recipients recipients;
	struct paging_alias_target *t;
	int res, saved_errno;

	/* All aliases expand to real endpoints, so there's only one level of indirection here.
	 *
	 * Unfortunately, we can't dirctly pass in &a->targets as the list of recipients,
	 * we need to make a new linked list with all the recipients reallocated.
	 *
	 * We could have a persistent copy of recipients, but since parameters can differ,
	 * we would have to keep the alias locked to prevent concurrency issues,
	 * so we might as well just make a new one each time. */
	RWLIST_HEAD_INIT(&recipients);
	RWLIST_TRAVERSE(&a->targets, t, entry) {
		struct bbs_paging_recipient *r;
		struct pager_endpoint *e = t->endpoint;
		size_t pageridlen = strlen(e->pagerid);
		r = calloc(1, sizeof(*r) + pageridlen + 1 + (e->pin ? strlen(e->pin) + 1 : 0));
		if (ALLOC_FAILURE(r)) {
			continue;
		}
		strcpy(r->data, e->pagerid); /* Safe */
		r->pagerid = r->data;
		if (e->pin) {
			strcpy(r->data + pageridlen + 1, e->pin); /* Safe */
			r->pin = r->data + pageridlen + 1;
		}
		memcpy(&r->parameters, &aliasrecipient->parameters, sizeof(struct bbs_paging_options)); /* Use same parameters for all recipients */
		RWLIST_INSERT_HEAD(&recipients, r, entry);
	}

	/* Now, start a new paging transaction with all of the alias's targets.
	 * Since this transaction contains only "real" recipients, it won't lead to recursion.
	 *
	 * One thing to be mindful of is the message tag. When paging a single recipient,
	 * there is a 1:1 relationship with the message tag that gets provided (for MSTA in SNPP).
	 * In SNPP, if paging multiple recipients, a single message tag is returned.
	 * As the code is currently written, this is the message tag of the last recipient processed,
	 * since page_single generates a new message tag each execution.
	 * With that logic, aliases behave the same way (if it's a 1:1 alias, the returned message
	 * tag is what you'd expect and want) - if it expands to multiple targets, the returned
	 * message tag corresponds to the last recipient processed.
	 * So at present, if you want the message tag for each recipient, you'd have to send to each recipient individually. */

	/*! \todo Can 2WAY in SNPP be used with multiple PAGE recipients? RFC doesn't specify. If not, that tightens up some of these loose behaviors.
	 * Unclear how message tags are really supposed to work in SNPP if multiple recipients are provided for a message.
	 *
	 * Spok's SNPP server seems to take a lot of shortcuts, reusing the pager ID for the message tag,
	 * with sequentially increasing (across all users) passcodes, and just returning 556 Unknown status for MSTA.
	 * They also accept one-way recipients for 2WAY transactions, with no distinction made when sending. */
	res = page_multiple(&recipients, data, meta);
	saved_errno = errno; /* Save errno to preserve it until we return, in case we returned nonzero */

	/* Free the recipients we allocated for the expansion */
	RWLIST_REMOVE_ALL(&recipients, entry, free);

	errno = saved_errno;
	return res;
}

/* Note: errno must be set AFTER unlocking the list since these calls may change errno */
#define UNLOCK_RETURN_WITH_ERRNO(err) \
	RWLIST_UNLOCK(&endpoints); \
	errno = err; \
	return -1;

static int page_single(struct bbs_paging_recipient *recipient, struct bbs_paging_data *data, struct bbs_paging_message_metadata *meta)
{
	struct pager_endpoint *e;
	enum pager_type minreq;
	const char *msgbody;
	size_t msglen;
	int res, saved_errno;

	if (!valid_pagerid(recipient->pagerid)) {
		/* SNPP does not require pager IDs to be numeric, and neither do we */
		errno = EINVAL;
		return -1;
	}

	RWLIST_RDLOCK(&endpoints);
	e = resolve_endpoint(recipient->pagerid);

	/* Does the pager exist? */
	if (!e) {
		/* Not a valid endpoint, but it might be an alias */
		struct paging_alias *a = resolve_alias(recipient->pagerid);
		if (!a) {
			bbs_debug(4, "No pager endpoint or alias matching '%s'\n", recipient->pagerid);
			UNLOCK_RETURN_WITH_ERRNO(ENOENT);
		}
		/* It exists as an alias.
		 * This is a bit of an interesting case,
		 * much like a mailing list, we explode the alias into all of its targets. */
		if (a->pin && strcmp(recipient->pin, a->pin)) {
			UNLOCK_RETURN_WITH_ERRNO(EACCES);
		}
		res = deliver_to_alias(recipient, data, meta, a);
		saved_errno = errno;
		RWLIST_UNLOCK(&endpoints);
		errno = saved_errno;
		return res;
	}

	/* If a PIN is required for this pager, and we don't have the right PIN, reject it */
	if (e->pin && strcmp(recipient->pin, e->pin)) {
		UNLOCK_RETURN_WITH_ERRNO(EACCES);
	}

	/* If we need numeric or alphanumeric paging, ensure we're compatible */
	msgbody = S_OR(data->body, data->message);
	minreq = min_pager_requirement(msgbody);
	if (minreq & PAGER_ALPHANUMERIC) {
		enum pager_type type = e->type;
		if (!(type & PAGER_ALPHANUMERIC)) {
			bbs_debug(5, "Pager %s is %s (incompatible)\n", e->pagerid, pager_type_name(e->type));
			UNLOCK_RETURN_WITH_ERRNO(type & PAGER_NUMERIC ? ERANGE : EDOM);
		}
	} else if (minreq & PAGER_NUMERIC) {
		enum pager_type type = e->type;
		if (!(type & PAGER_NUMERIC)) {
			bbs_debug(5, "Pager %s is %s (incompatible)\n", e->pagerid, pager_type_name(e->type));
			UNLOCK_RETURN_WITH_ERRNO(EDOM);
		}
	}
	/* If we need two-way paging, ensure we're capable */
	if (data->twoway) {
		if (!(e->type & PAGER_TWOWAY)) {
			/* We don't currently support two-way paging (see pager_exists) */
			/* Since we don't support two-way paging, we should never hit this branch.
			 * Only SNPP supports two-way paging and if pager_exists fails (it would),
			 * the recipient never gets added.
			 * So we don't need to specially set errno here, the generic error is fine */
			UNLOCK_RETURN_WITH_ERRNO(0);
		}
	}

	/* If there are length restrictions, ensure the message isn't too long */
	msglen = strlen(S_IF(msgbody));
	if (maxmsglen && (msglen > maxmsglen)) {
		bbs_debug(7, "Page length (%lu) too long (max length is %u)\n", msglen, maxmsglen);
		UNLOCK_RETURN_WITH_ERRNO(EMSGSIZE);
	}

	/* Rate limit exceeded? */
	if (bbs_rate_limit_exceeded(&e->ratelimit)) {
		UNLOCK_RETURN_WITH_ERRNO(EDQUOT);
	}

	/* At this point, the message seems valid, so we can go ahead and try to deliver it.
	 * Come up with a message tag and PIN for this transaction */
	if (bbs_rand_alnum(meta->msgtag, PAGE_MESSAGE_TAG_LENGTH + 1) || bbs_rand_alnum(meta->passcode, PAGE_MESSAGE_PASSCODE_LENGTH + 1)) {
		UNLOCK_RETURN_WITH_ERRNO(EAGAIN);
	}

	bbs_debug(4, "Attempting delivery of %s to paging recipient %s (IRC: %s, cmd: %s, SNPP: %s, SMTP: %s, TAP: %s)\n", meta->msgtag, recipient->pagerid,
		BBS_YESNO(e->sendirc), BBS_YESNO(e->externalcmd), BBS_YESNO(e->snpp), BBS_YESNO(e->email), BBS_YESNO(e->tap));

	/* Go ahead and try to deliver it */
	res = deliver_page(e, recipient, data, meta);
	saved_errno = errno;
	RWLIST_UNLOCK(&endpoints);
	errno = saved_errno;
	return res;
}

static int cli_endpoints(struct bbs_cli_args *a)
{
	struct pager_endpoint *e;
	int c = 0;

	bbs_dprintf(a->fdout, "%-11s %-8s %-12s %2s %16s %4s %4s %4s %4s %3s\n", "Pager ID", "PIN", "Type", "2W", "User", "IRC", "SNPP", "SMTP", "TAP", "Ext");
	RWLIST_RDLOCK(&endpoints);
	RWLIST_TRAVERSE(&endpoints, e, entry) {
		char username[64] = "-";
		if (e->userid) {
			bbs_username_from_userid(e->userid, username, sizeof(username));
		}
		bbs_dprintf(a->fdout, "%-11s %-8s %-12s %2s %16s %4s %4s %4s %4s %3s\n", e->pagerid, S_IF(e->pin), pager_type_name(e->type), BBS_YN(e->type & PAGER_TWOWAY), username,
			e->sendirc ? "*" : "-", S_COR(e->snpp, "*", "-"), S_COR(e->email, "*", "-"), S_COR(e->tap, "*", "-"), S_COR(e->externalcmd, "*", "-"));
		c++;
	}
	RWLIST_UNLOCK(&endpoints);
	bbs_dprintf(a->fdout, "%d paging endpoint%s configured\n", c, ESS(c));
	return 0;
}

static int cli_endpoint(struct bbs_cli_args *a)
{
	struct pager_endpoint *e;

	RWLIST_RDLOCK(&endpoints);
	e = resolve_endpoint(a->argv[2]);
	if (e) {
		char username[64] = "-";
		if (e->userid) {
			bbs_username_from_userid(e->userid, username, sizeof(username));
		}
		bbs_dprintf(a->fdout, "Pager ID:  %s\n", e->pagerid);
		bbs_dprintf(a->fdout, "PIN:       %s\n", S_IF(e->pin));
		bbs_dprintf(a->fdout, "Type:      %s\n", pager_type_name(e->type));
		bbs_dprintf(a->fdout, "Retries:   %s\n", BBS_YESNO(e->retries));
		bbs_dprintf(a->fdout, "Two-Way:   %s\n", BBS_YESNO(e->type & PAGER_TWOWAY));
		bbs_dprintf(a->fdout, "User:      %s\n", username);
		bbs_dprintf(a->fdout, "IRC Alert: %s\n", BBS_YESNO(e->sendirc));
		bbs_dprintf(a->fdout, "SNPP GW:   %s\n", S_IF(e->snpp));
		bbs_dprintf(a->fdout, "SNPP ID:   %s\n", S_IF(e->snppid));
		bbs_dprintf(a->fdout, "SNPP PIN:  %s\n", S_IF(e->snpppin));
		bbs_dprintf(a->fdout, "SMTP GW:   %s\n", S_IF(e->email));
		bbs_dprintf(a->fdout, "SMTP User: %s\n", S_IF(e->emailuser));
		bbs_dprintf(a->fdout, "TAP GW:    %s\n", S_IF(e->tap));
		bbs_dprintf(a->fdout, "TAP ID:    %s\n", S_IF(e->tapuser));
		bbs_dprintf(a->fdout, "Ext Cmd:   %s\n", S_IF(e->externalcmd));
	} else {
		bbs_dprintf(a->fdout, "No such paging endpoint '%s'\n", a->argv[2]);
	}
	RWLIST_UNLOCK(&endpoints);
	return 0;
}

static int cli_aliases(struct bbs_cli_args *a)
{
	struct paging_alias *alias;
	int c = 0;

	bbs_dprintf(a->fdout, "%-11s %8s %12s %s\n", "Pager ID", "PIN", "Type", "# Targets");
	RWLIST_RDLOCK(&endpoints); /* We don't use the aliases lock */
	RWLIST_TRAVERSE(&aliases, alias, entry) {
		struct paging_alias_target *t;
		bbs_dprintf(a->fdout, "%-11s %8s %12s %d\n", alias->pagerid, S_IF(alias->pin), pager_type_name(alias->type), RWLIST_SIZE(&alias->targets, t, entry));
		c++;
	}
	RWLIST_UNLOCK(&endpoints);
	bbs_dprintf(a->fdout, "%d paging alias%s configured\n", c, ESS(c));
	return 0;
}

static int cli_alias(struct bbs_cli_args *a)
{
	struct paging_alias *alias;
	int c = 0;

	RWLIST_RDLOCK(&endpoints); /* We don't use the aliases lock */
	alias = resolve_alias(a->argv[2]);
	if (alias) {
		struct paging_alias_target *t;
		bbs_dprintf(a->fdout, "Pager ID:  %s\n", alias->pagerid);
		bbs_dprintf(a->fdout, "PIN:       %s\n", alias->pin);
		bbs_dprintf(a->fdout, "Type:      %s\n", pager_type_name(alias->type));
		bbs_dprintf(a->fdout, "Targets:\n");
		RWLIST_TRAVERSE(&alias->targets, t, entry) {
			bbs_dprintf(a->fdout, "%3d --> %s\n", ++c, t->endpoint->pagerid);
		}
		bbs_dprintf(a->fdout, "%d target%s defined for this alias\n", c, ESS(c));
	} else {
		bbs_dprintf(a->fdout, "No such paging alias '%s'\n", a->argv[2]);
	}
	RWLIST_UNLOCK(&endpoints);
	return 0;
}

static const char *status_str(enum bbs_paging_message_delivery_status status)
{
	if (!(status & PAGE_DELIVERED)) {
		return "Queued/Sent";
	} else { /* PAGE_DELIVERED */
		if (status & PAGE_REPLY_RECEIVED) { /* Reply received (and obviously it's read */
			if (status & PAGE_REPLY_RECEIVED_MC) {
				return "MC Reply Received";
			} else { /* PAGE_REPLY_RECEIVED_TEXT */
				return "Reply Received";
			}
		} else if (status & PAGE_READ) {
			if (status & PAGE_AWAITING_REPLY) {
				return "Read, Awaiting Reply";
			} else {
				return "Read";
			}
		} else { /* PAGE_AWAITING_READACK */
			if (status & PAGE_AWAITING_READACK) {
				return "Delivered, Awaiting Ack";
			} else if (status & PAGE_AWAITING_REPLY) {
				return "Delivered, Awaiting Reply";
			} else {
				return "Delivered";
			}
		}
	}
}

static int cli_queue(struct bbs_cli_args *a)
{
	struct queued_page *q;
	int c = 0;

	bbs_dprintf(a->fdout, "%*s %.*s %-15s %7s %4s %3s %*s %s\n", PAGE_MESSAGE_TAG_LENGTH, "Message Tag", PAGE_MESSAGE_PASSCODE_LENGTH, "Passcode",
		"Pager ID", "Retries", "Sent", "Exp", PAGING_TIMESTAMP_LENGTH, "Timestamp", "Status");
	RWLIST_RDLOCK(&queued_pages);
	RWLIST_TRAVERSE(&queued_pages, q, entry) {
		char timestampbuf[PAGING_TIMESTAMP_LENGTH] = "";
		bbs_paging_timestamp(q->meta.timestamp, timestampbuf, sizeof(timestampbuf));
		bbs_dprintf(a->fdout, "%.*s %.*s %-15s %7d %4s %3s %*s %s\n", PAGE_MESSAGE_TAG_LENGTH, q->meta.msgtag, PAGE_MESSAGE_PASSCODE_LENGTH, q->meta.passcode,
			q->pagerid, q->numretries, q->sent ? "*" : "", q->expired ? "*" : "", PAGING_TIMESTAMP_LENGTH, timestampbuf, status_str(q->meta.status));
		c++;
	}
	RWLIST_UNLOCK(&queued_pages);
	bbs_dprintf(a->fdout, "%d page%s queued for delivery\n", c, ESS(c));
	return 0;
}

static void create_timestamp(time_t t, char *buf, size_t len)
{
	struct tm tm;

	if (!t) {
		*buf = '\0';
		return;
	}

	/* Timestamp is something like 2000-01-01 00:00:00 -0400 */
	localtime_r(&t, &tm);
	strftime(buf, len, "%Y-%02m-%02d %H:%M:%S %z", &tm);
}

static void option_value(int value, int value_set, char *buf, size_t len)
{
	if (!value_set) {
		snprintf(buf, len, "-");
		return;
	}
	snprintf(buf, len, "%d", value);
}

static int cli_message(struct bbs_cli_args *a)
{
	struct queued_page *q;
	const char *msgtag = a->argv[2];

	RWLIST_RDLOCK(&queued_pages);
	q = find_queued_page(msgtag);
	if (q) {
		char tbuf[26];
		bbs_dprintf(a->fdout, "=== Page: %s ===\n", q->meta.msgtag);
		bbs_dprintf(a->fdout, "Message Tag: %s\n", q->meta.msgtag);
		bbs_dprintf(a->fdout, "Passcode:    %s\n", q->meta.passcode);
		bbs_dprintf(a->fdout, "Status:      %s\n", status_str(q->meta.status));
		bbs_dprintf(a->fdout, "Response:    %s\n", S_IF(q->meta.response));
		create_timestamp(q->meta.timestamp, tbuf, sizeof(tbuf));
		bbs_dprintf(a->fdout, "Timestamp:   %s\n", tbuf);
		bbs_dprintf(a->fdout, "Sent:        %s\n", BBS_YESNO(q->sent));
		bbs_dprintf(a->fdout, "In Progress: %s\n", BBS_YESNO(q->inprogress));
		bbs_dprintf(a->fdout, "Expired:     %s\n", BBS_YESNO(q->expired));
		create_timestamp(q->added, tbuf, sizeof(tbuf));
		bbs_dprintf(a->fdout, "Queued:      %s\n", tbuf);
		bbs_dprintf(a->fdout, "Num Retries: %d\n", q->numretries);
		create_timestamp(q->lastretry, tbuf, sizeof(tbuf));
		bbs_dprintf(a->fdout, "Last Retry:  %s\n", tbuf);
		create_timestamp(q->finalresponseread, tbuf, sizeof(tbuf));
		bbs_dprintf(a->fdout, "Resp Read:   %s\n", tbuf);
#if defined(__linux__) && defined(__GLIBC__)
		bbs_dprintf(a->fdout, "Thread:      %lu\n", q->owner);
#endif
		bbs_dprintf(a->fdout, "--- Destination ---\n");
		bbs_dprintf(a->fdout, "Pager ID:    %s\n", q->pagerid);
		bbs_dprintf(a->fdout, "Pager PIN:   %s\n", S_IF(q->pin));
		bbs_dprintf(a->fdout, "SNPP Queued: %s\n", BBS_YESNO(q->methods & QUEUE_SNPP));
		bbs_dprintf(a->fdout, "SMTP Queued: %s\n", BBS_YESNO(q->methods & QUEUE_SMTP));
		bbs_dprintf(a->fdout, "TAP Queued:  %s\n", BBS_YESNO(q->methods & QUEUE_TAP));
		bbs_dprintf(a->fdout, "Gateway:     %s\n", S_IF(q->data.gateway));
		bbs_dprintf(a->fdout, "--- Delivery Options ---\n");
		option_value(q->parameters.level, q->parameters.level_set, tbuf, sizeof(tbuf));
		bbs_dprintf(a->fdout, "Level:       %s\n", tbuf);
		option_value(q->parameters.coverage, q->parameters.coverage_set, tbuf, sizeof(tbuf));
		bbs_dprintf(a->fdout, "Coverage:    %s\n", tbuf);
		bbs_dprintf(a->fdout, "Alert:       %s\n", BBS_YESNO(q->parameters.alert));
		create_timestamp(q->parameters.holduntil, tbuf, sizeof(tbuf));
		bbs_dprintf(a->fdout, "Hold Until:  %s\n", tbuf);
		bbs_dprintf(a->fdout, "--- Payload Data ---\n");
		bbs_dprintf(a->fdout, "2-Way:       %s\n", BBS_YESNO(q->data.twoway));
		bbs_dprintf(a->fdout, "No Queue:    %s\n", BBS_YESNO(q->data.noqueue));
		bbs_dprintf(a->fdout, "ReadAck:     %s\n", BBS_YESNO(q->data.readack));
		bbs_dprintf(a->fdout, "Caller ID:   %s\n", S_IF(q->data.callerid));
		bbs_dprintf(a->fdout, "Subject:     %s\n", S_IF(q->data.subject));
		bbs_dprintf(a->fdout, "Message:     %s\n", S_OR(q->data.body, q->data.message));
	}
	RWLIST_UNLOCK(&queued_pages);

	if (!q) {
		bbs_dprintf(a->fdout, "No such page with msgtag '%s'\n", msgtag);
		return -1;
	}
	return 0;
}

static int cli_purge(struct bbs_cli_args *a)
{
	struct queued_page *q;
	const char *msgtag = a->argv[2];

	RWLIST_WRLOCK(&queued_pages);
	if (!strcmp(msgtag, "ALL")) {
		int purged = 0, expired = 0, total = 0;
		RWLIST_TRAVERSE_SAFE_BEGIN(&queued_pages, q, entry) {
			total++;
			if (q->inprogress) {
				q->expired = 1;
				expired++;
			} else {
				RWLIST_REMOVE_CURRENT(entry);
				free_queued_page(q);
				purged++;
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
		bbs_dprintf(a->fdout, "Purged %d/%d page%s, expired %d\n", purged, total, ESS(total), expired);
	} else {
		q = find_queued_page(msgtag);
		if (q) {
			if (q->inprogress) {
				/* We can't remove it if a thread is using it, so just prevent all further delivery attempts */
				bbs_dprintf(a->fdout, "Can't actively purge %s (in progress), expiring instead\n", msgtag);
				q->expired = 1;
			} else {
				RWLIST_REMOVE(&queued_pages, q, entry);
				bbs_dprintf(a->fdout, "Purged page %s\n", q->meta.msgtag);
				free_queued_page(q);
			}
		}
		if (!q) {
			bbs_dprintf(a->fdout, "No such page with msgtag '%s'\n", msgtag);
		}
	}
	RWLIST_UNLOCK(&queued_pages);
	return 0;
}

static int cli_page(struct bbs_cli_args *a)
{
	ssize_t res;
	char message[1024];
	enum pager_type type;
	struct bbs_paging_recipient recip;
	struct bbs_paging_data data;
	struct bbs_paging_message_metadata meta;
	const char *pagerid = a->argv[1];

	if (a->argc > 2) {
		bbs_dprintf(a->fdout, "Too many arguments (page body is entered separately)\n");
		return -1;
	}

	if (!bbs_pager_exists(pagerid, &type, 0)) {
		bbs_dprintf(a->fdout, "Can't send page to '%s', no such endpoint\n", pagerid);
		return -1;
	}

	/* If it's valid, use the BBS APIs to send the page (which should call back into this module) */
	bbs_cli_set_stdout_logging(a->fdout, 0); /* Disable logging to the terminal until we're finished (mod_sysop will reset anyways when we return) */
	bbs_buffer_input(a->fdin, 1);
	bbs_dprintf(a->fdout, "\nMessage: ");

	res = bbs_poll_read(a->fdin, MIN_MS(2), message, sizeof(message) - 1);
	if (res <= 0) {
		bbs_dprintf(a->fdout, "Failed to read message from user, aborting\n");
		return -1;
	}
	message[res] = '\0';
	memset(&recip, 0, sizeof(recip));
	recip.pagerid = pagerid;
	memset(&data, 0, sizeof(data));
	data.message = message;

	/* For SMTP, we need to ensure there is no trailing bare LF (not part of a CR LF pair) */
	bbs_strterm(message, '\n');

	bbs_cli_set_stdout_logging(a->fdout, 1); /* Re-enable so we can see what happens when we try sending the page */
	if (page_single(&recip, &data, &meta)) {
		bbs_dprintf(a->fdout, "Page failed to send: %s\n", page_strerror(errno));
	} else {
		bbs_dprintf(a->fdout, "Page sent or queued (%s %s)\n", meta.msgtag, meta.passcode);
	}
	return 0;
}

static int page_status(struct bbs_paging_message_metadata *meta)
{
	struct queued_page *q;

	RWLIST_RDLOCK(&queued_pages);
	q = find_queued_page(meta->msgtag);
	if (!q) {
		/* Doesn't exist */
		RWLIST_UNLOCK(&queued_pages);
		errno = EINVAL;
		return -1;
	} else if (strcmp(meta->passcode, q->meta.passcode)) {
		/* Wrong passcode */
		RWLIST_UNLOCK(&queued_pages);
		errno = EACCES;
		return -1;
	} else if (q->expired) {
		/* Expired prior to delivery */
		RWLIST_UNLOCK(&queued_pages);
		/* We use ETIMEDOUT instead of ETIME (which as a more appropriate description)
		 * since the latter is not POSIX and is thus unavailable on FreeBSD. */
		errno = ETIMEDOUT;
		return -1;
	}

	/* Update the caller's view of the status */
	meta->status = q->meta.status;
	meta->timestamp = q->meta.timestamp;
	if (!q->finalresponseread && meta->status & PAGE_DELIVERED) {
		q->finalresponseread = time(NULL);
	}

	RWLIST_UNLOCK(&queued_pages);
	return 0;
}

static int page_expire(struct bbs_paging_message_metadata *meta)
{
	struct queued_page *q;

	RWLIST_WRLOCK(&queued_pages); /* Since we remove on success, WRLOCK */
	q = find_queued_page(meta->msgtag);
	if (!q) {
		/* Doesn't exist */
		RWLIST_UNLOCK(&queued_pages);
		errno = EINVAL;
		return -1;
	} else if (strcmp(meta->passcode, q->meta.passcode)) {
		/* Wrong passcode */
		RWLIST_UNLOCK(&queued_pages);
		errno = EACCES;
		return -1;
	}

	meta->status = q->meta.status;
	meta->timestamp = q->meta.timestamp;

	/* Remove it */
	RWLIST_REMOVE(&queued_pages, q, entry);
	free_queued_page(q);

	RWLIST_UNLOCK(&queued_pages);
	return 0;
}

static struct pager_endpoint *add_endpoint(const char *pagerid, const char *pin, const char *snpp, const char *snppid, const char *snpppin,
	const char *email, const char *emailuser, const char *tap, const char *tapuser, const char *externalcmd)
{
	struct pager_endpoint *e;
	char *data;
	size_t pageridlen, pinlen, snpplen, snppidlen, snpppinlen, emaillen, emailuserlen, taplen, tapuserlen, externalcmdlen;

	pageridlen = STRING_ALLOC_SIZE(pagerid);
	pinlen = STRING_ALLOC_SIZE(pin);
	snpplen = STRING_ALLOC_SIZE(snpp);
	snppidlen = STRING_ALLOC_SIZE(snppid);
	snpppinlen = STRING_ALLOC_SIZE(snpppin);
	emaillen = STRING_ALLOC_SIZE(email);
	emailuserlen = STRING_ALLOC_SIZE(emailuser);
	taplen = STRING_ALLOC_SIZE(tap);
	tapuserlen = STRING_ALLOC_SIZE(tapuser);
	externalcmdlen = STRING_ALLOC_SIZE(externalcmd);
	e = calloc(1, sizeof(*e) + pageridlen + pinlen + snpplen + snppidlen + snpppinlen + emaillen + emailuserlen + taplen + tapuserlen + externalcmdlen);
	if (ALLOC_FAILURE(e)) {
		return NULL;
	}

	data = e->data;
	SET_FSM_STRING_VAR(e, data, pagerid, pagerid, pageridlen);
	SET_FSM_STRING_VAR(e, data, pin, pin, pinlen);
	SET_FSM_STRING_VAR(e, data, snpp, snpp, snpplen);
	SET_FSM_STRING_VAR(e, data, snppid, snppid, snppidlen);
	SET_FSM_STRING_VAR(e, data, snpppin, snpppin, snpppinlen);
	SET_FSM_STRING_VAR(e, data, email, email, emaillen);
	SET_FSM_STRING_VAR(e, data, emailuser, emailuser, emailuserlen);
	SET_FSM_STRING_VAR(e, data, tap, tap, taplen);
	SET_FSM_STRING_VAR(e, data, tapuser, tapuser, tapuserlen);
	SET_FSM_STRING_VAR(e, data, externalcmd, externalcmd, externalcmdlen);

	bbs_rate_limit_init(&e->ratelimit, SEC_MS(30), 5); /* No more than 5 messages per 30 seconds (we don't want to risk legitimate messages getting dropped) */
	e->type = PAGER_ALPHANUMERIC; /* Default, may be overridden */

	bbs_debug(5, "Added paging endpoint '%s'\n", pagerid);

	/* Default ("*") will be moved to the end after all endpoints are loaded */
	RWLIST_INSERT_TAIL(&endpoints, e, entry);
	return e;
}

/* The default argument if there is no delimiter in all these cases is on the right-hand side, which complicates the parsing */
#define PARSE_SNPP(snpp, snppid, snpppin) \
	snpppin = strsep(&snpp, "@"); \
	if (!snpp) { \
		snpp = snpppin; \
		snppid = snpppin = NULL; \
	} else { \
		snppid = strsep(&snpppin, ":"); \
	}

#define PARSE_EMAIL(email, emailuser) \
	emailuser = strsep(&email, "@"); \
	if (!email) { \
		email = emailuser; \
		emailuser = NULL; \
	}

#define PARSE_TAP_IXO(tap, tapuser) \
	tapuser = strsep(&tap, "@"); \
	if (!tap) { \
		tap = tapuser; \
		tapuser = NULL; \
	}

static int add_gateway(char *key, char *val)
{
	char *pagerid, *pin;
	char *snpp, *email, *tap;
	char *snppid, *snpppin;
	char *emailuser;
	char *tapuser;

	/* Format is pagerid[:pin] = [[SNPP pager ID[:PIN]@]SNPP hostname],[[SMTP pager user@]SMTP hostname],[[TAP/IXO pager ID@]TAP/IXO pager terminal number]
	 * If pager ID is '*', this indicates the default gateway */
	pin = key;
	pagerid = strsep(&pin, ":");

	tap = val;
	snpp = strsep(&tap, ",");
	email = strsep(&tap, ",");

	PARSE_SNPP(snpp, snppid, snpppin);
	PARSE_EMAIL(email, emailuser);
	PARSE_TAP_IXO(tap, tapuser);

	if (strlen_zero(pagerid)) {
		bbs_error("Pager ID must be non-empty\n");
		return -1;
	}
	if (!valid_pagerid(pagerid) && strcmp(pagerid, "*")) {
		bbs_error("Pager ID '%s' must be alphanumeric or '*'\n", pagerid);
		return -1;
	}
	if (s_strlen_zero(all_externalcmd) && strlen_zero(snpp) && strlen_zero(email) && strlen_zero(tap)) {
		bbs_error("At least one delivery method for %s must be configured (SNPP, SMTP, TAP/IXO, or external command)\n", pagerid);
		return -1;
	}

	if (find_exact_endpoint(pagerid)) {
		bbs_warning("Pager ID '%s' already registered, skipping duplicate gateway\n", pagerid);
		return -1;
	}
	return add_endpoint(pagerid, pin, snpp, snppid, snpppin, email, emailuser, tap, tapuser, NULL) ? 0 : -1;
}

static int add_alias(const char *pagerid, const char *pin, char *targets)
{
	struct paging_alias_target *t;
	struct pager_endpoint *e;
	char *target;
	struct paging_alias *a;
	enum pager_type supertype;
	size_t pageridlen, pinlen;
	char *data;

	if (!valid_pagerid(pagerid) && strcmp(pagerid, "*")) {
		bbs_error("Pager ID '%s' must be alphanumeric or '*'\n", pagerid);
		return -1;
	}
	if (find_exact_endpoint(pagerid)) {
		bbs_warning("Can't add alias '%s', a paging endpoint with that ID already exists\n", pagerid);
		return -1;
	}
	RWLIST_TRAVERSE(&aliases, a, entry) {
		if (!strcmp(a->pagerid, pagerid)) {
			bbs_warning("Alias '%s' already exists\n", pagerid);
			return -1;
		}
	}

	pageridlen = STRING_ALLOC_SIZE(pagerid);
	pinlen = STRING_ALLOC_SIZE(pin);

	a = calloc(1, sizeof(*a) + pageridlen + pinlen);
	if (ALLOC_FAILURE(a)) {
		return -1;
	}
	data = a->data;
	SET_FSM_STRING_VAR(a, data, pagerid, pagerid, pageridlen);
	SET_FSM_STRING_VAR(a, data, pin, pin, pinlen);
	RWLIST_HEAD_INIT(&a->targets);

	while ((target = strsep(&targets, ","))) {
		if (strlen_zero(target)) {
			continue;
		}
		e = find_exact_endpoint(target);
		if (!e) {
			bbs_warning("Can't make '%s' a target of alias '%s', it's not a valid endpoint\n", target, pagerid);
			continue;
		}
		t = calloc(1, sizeof(*t));
		if (ALLOC_FAILURE(t)) {
			continue;
		}
		t->endpoint = e;
		RWLIST_INSERT_HEAD(&a->targets, t, entry);
	}
	if (RWLIST_EMPTY(&a->targets)) {
		bbs_warning("Can't add alias '%s', it has no valid targets\n", pagerid);
		free(a);
		return -1;
	}

	/* The alias's type is a superset of the types of its targets.
	 * Calculate it now so we don't need to recompute later. */
	supertype = 0;
	RWLIST_TRAVERSE(&a->targets, t, entry) {
		supertype |= t->endpoint->type;
	}
	if (supertype & PAGER_ALPHANUMERIC) {
		a->type = PAGER_ALPHANUMERIC;
	} else if (supertype & PAGER_NUMERIC) {
		a->type = PAGER_NUMERIC;
	} else {
		a->type = PAGER_TONE_ONLY;
	}

	if (!strcmp(pagerid, "*")) {
		RWLIST_INSERT_TAIL(&aliases, a, entry);
	} else {
		RWLIST_INSERT_HEAD(&aliases, a, entry);
	}
	return 0;
}

static int delegation_authorized(struct bbs_config_section *delegated, unsigned int userid, const char *pagerid)
{
	unsigned int d_userid;
	struct bbs_keyval *keyval = NULL;
	/* Start at the beginning of [delegated] and see if there are any entries delegating this pager ID to this user */
	while ((keyval = bbs_config_section_walk(delegated, keyval))) {
		if (strcmp(pagerid, bbs_keyval_key(keyval))) {
			continue;
		}
		/* There is a delegation for this pager ID... is it for us? */
		d_userid = bbs_userid_from_username(bbs_keyval_val(keyval));
		return d_userid == userid;
	}

	d_userid = bbs_userid_from_username(pagerid);
	if (d_userid == userid) {
		/* The user is implicitly delegated the endpoint corresponding to his or her username */
		return 1;
	}

	return 0; /* No delegation for this user or any other */
}

static int load_user_config(struct bbs_config_section *delegated, const char *filename, unsigned int userid)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg;

	cfg = bbs_config_load(filename, 1);
	if (!cfg) {
		return -1; /* File should exist, so this shouldn't happen... */
	}

	while ((section = bbs_config_walk(cfg, section))) {
		struct pager_endpoint *e;
		const char *pin = NULL;
		enum pager_type type = PAGER_ALPHANUMERIC;
		int sendirc = 0;
		char snppbuf[1024], emailbuf[1024], tapbuf[1024];
		char *snpp = NULL, *snppid = NULL, *snpppin = NULL;
		char *email = NULL, *emailuser = NULL;
		char *tap = NULL, *tapuser = NULL;
		const char *externalcmd = NULL;
		int retries = 1;
		const char *pagerid = bbs_config_section_name(section);
		/* Before processing anything, check if we are delegated this pager ID */
		if (!delegation_authorized(delegated, userid, pagerid)) {
			bbs_user_config_log(userid, cfg, LOG_ERROR, LOG_NOTICE, "User not delegated pager ID %s, not loading\n", pagerid);
			continue;
		}
		/* It can't already exist, either */
		e = find_exact_endpoint(pagerid);
		if (e) {
			bbs_user_config_log(userid, cfg, LOG_ERROR, LOG_NOTICE, "Endpoint %s already configured, not loadng endpoint %s\n", e->pagerid, pagerid);
			continue;
		}
		if (!valid_pagerid(pagerid) && strcmp(pagerid, "*")) {
			bbs_user_config_log(userid, cfg, LOG_ERROR, LOG_NOTICE, "Pager ID '%s' must be alphanumeric or '*'\n", pagerid);
			continue;
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval);
			const char *val = bbs_keyval_val(keyval);
			if (!strcasecmp(key, "pin")) {
				pin = val;
			} else if (!strcasecmp(key, "messages")) {
				/* Default is alphanumeric, but this can be overridden */
				if (!strcasecmp(val, "alpha")) {
					type = PAGER_ALPHANUMERIC;
				} else if (!strcasecmp(val, "numeric")) {
					type = PAGER_NUMERIC;
				} else if (!strcasecmp(val, "none")) {
					type = PAGER_TONE_ONLY;
				} else {
					bbs_user_config_log(userid, cfg, LOG_WARNING, LOG_NOTICE, "Invalid 'messages' option '%s'\n", val);
				}
			} else if (!strcasecmp(key, "irc")) {
				sendirc = S_TRUE(val);
			} else if (!strcasecmp(key, "snpp")) {
				safe_strncpy(snppbuf, val, sizeof(snppbuf));
				snpp = snppbuf;
				PARSE_SNPP(snpp, snppid, snpppin);
				if (strlen_zero(snpp)) {
					bbs_user_config_log(userid, cfg, LOG_WARNING, LOG_NOTICE, "SNPP endpoint '%s' is missing SNPP gateway\n", val);
				}
			} else if (!strcasecmp(key, "email")) {
				safe_strncpy(emailbuf, val, sizeof(emailbuf));
				email = emailbuf;
				PARSE_EMAIL(email, emailuser);
				if (strlen_zero(email)) {
					bbs_user_config_log(userid, cfg, LOG_WARNING, LOG_NOTICE, "Email endpoint '%s' is missing SMTP gateway\n", val);
				}
			} else if (!strcasecmp(key, "tap")) {
				safe_strncpy(tapbuf, val, sizeof(tapbuf));
				tap = tapbuf;
				PARSE_TAP_IXO(tap, tapuser);
				if (strlen_zero(tap)) {
					bbs_user_config_log(userid, cfg, LOG_WARNING, LOG_NOTICE, "TAP endpoint '%s' is missing TAP terminal number\n", val);
				}
			} else if (!strcasecmp(key, "externalcmd")) {
				externalcmd = val;
			} else if (!strcasecmp(key, "retries")) {
				retries = S_TRUE(val);
			} else {
				bbs_user_config_log(userid, cfg, LOG_ERROR, LOG_NOTICE, "Invalid delivery method '%s'\n", key);
			}
		}
		if (!sendirc && strlen_zero(externalcmd) && strlen_zero(snpp) && strlen_zero(email) && strlen_zero(tap)) {
			bbs_user_config_log(userid, cfg, LOG_ERROR, LOG_NOTICE, "At least one delivery method for %s must be configured (IRC, SNPP, SMTP, TAP/IXO, or external command)\n", pagerid);
			continue;
		}
		/* Now, try to load it */
		e = add_endpoint(pagerid, pin, snpp, snppid, snpppin, email, emailuser, tap, tapuser, externalcmd);
		if (!e) {
			continue;
		}
		/* Add user only stuff */
		e->userid = userid;
		e->type = type;
		SET_BITFIELD(e->sendirc, sendirc);
		SET_BITFIELD(e->retries, retries);
	}

	bbs_config_unlock(cfg);
	return 0;
}

static int load_user_endpoints(const char *dir_name, const char *filename, void *obj)
{
	unsigned int userid;
	char fullpath[1024];
	struct bbs_config_section *delegated = obj;

	snprintf(fullpath, sizeof(fullpath), "%s/%s/.config/.paging", dir_name, filename);

	/* At this point, we already know the file exists. */
	userid = (unsigned int) atoi(filename);
	return load_user_config(delegated, fullpath, userid);
}

static int load_delegated_endpoints(struct bbs_config_section *delegated)
{
	/*! \todo As with mod_irc_bouncer, delegated endpoints are only processed when the module loads,
	 * so it won't pick up changes made by users while module is running */
	struct bbs_transfer_traversal t = {
		.filename = ".config/.paging",
		.callback = load_user_endpoints,
		.obj = delegated,
	};
	if (bbs_transfer_traverse_home_directories(&t)) {
		return -1;
	}
	return 0;
}

static int load_config(void)
{
	struct pager_endpoint *e;
	struct bbs_config_section *section = NULL;
	struct bbs_config *cfg = bbs_config_load("mod_paging.conf", 1);

	if (!cfg) {
		return -1;
	}

	bbs_config_val_set_str(cfg, "general", "externalcmd", all_externalcmd, sizeof(all_externalcmd));
	bbs_config_val_set_uint(cfg, "general", "maxmsglen", &maxmsglen);

	RWLIST_WRLOCK(&endpoints);
	/* Stage 1: Load gateways */
	while ((section = bbs_config_walk(cfg, section))) {
		char keybuf[1024], valbuf[1024];
		struct bbs_keyval *keyval = NULL;
		if (!strcmp(bbs_config_section_name(section), "gateways")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				safe_strncpy(keybuf, bbs_keyval_key(keyval), sizeof(keybuf));
				safe_strncpy(valbuf, bbs_keyval_val(keyval), sizeof(valbuf));
				add_gateway(keybuf, valbuf);
			}
		} else if (!strcmp(bbs_config_section_name(section), "delegations")) {
			continue;
		} else if (!strcmp(bbs_config_section_name(section), "aliases")) {
			continue;
		} else if (!strcmp(bbs_config_section_name(section), "email")) {
			continue; /* mod_paging_smtp uses this */
		} else if (strcmp(bbs_config_section_name(section), "general")) {
			/* Only in Stage 1 do we emit warnings about foreign section names, to avoid duplicate warnings */
			bbs_warning("Invalid section name '%s'\n", bbs_config_section_name(section));
		}
	}

	/* Stage 2: Parse user configs for delegated endpoints */
	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "delegations")) {
			load_delegated_endpoints(section);
			break;
		}
	}

	/* Stage 3: Process aliases last, since they will save references to endpoints */
	while ((section = bbs_config_walk(cfg, section))) {
		char keybuf[1024], valbuf[8192]; /* Could be a lot of targets */
		struct bbs_keyval *keyval = NULL;
		if (!strcmp(bbs_config_section_name(section), "aliases")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				char *pagerid, *pin;
				safe_strncpy(keybuf, bbs_keyval_key(keyval), sizeof(keybuf));
				safe_strncpy(valbuf, bbs_keyval_val(keyval), sizeof(valbuf));
				pin = keybuf;
				pagerid = strsep(&pin, ":");
				add_alias(pagerid, pin, valbuf);
			}
		}
	}

	/* Stage 4: Move default endpoint, if present, to end of list */
	RWLIST_TRAVERSE_SAFE_BEGIN(&endpoints, e, entry) {
		if (!strcmp(e->pagerid, "*")) {
			RWLIST_REMOVE_CURRENT(entry);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (e) {
		/* Re-insert the default endpoint at the very end so it will be last during a traversal */
		RWLIST_INSERT_TAIL(&endpoints, e, entry);
	}

	RWLIST_UNLOCK(&endpoints);
	bbs_config_unlock(cfg);
	return 0;
}

struct bbs_paging_callbacks paging_callbacks = {
	.pager_exists = pager_exists,
	.pager_ping = pager_ping,
	.page_single = page_single,
	.page_multiple = page_multiple,
	.page_status = page_status,
	.page_expire = page_expire,
};

static struct bbs_cli_entry cli_commands_paging[] = {
	BBS_CLI_COMMAND(cli_endpoints, "paging endpoints", 2, "List gateway and delegated paging endpoints", NULL),
	BBS_CLI_COMMAND(cli_endpoint, "paging endpoint", 3, "Show configuration for a paging endpoint", "paging endpoint <pager ID>"),
	BBS_CLI_COMMAND(cli_aliases, "paging aliases", 2, "List paging aliases", NULL),
	BBS_CLI_COMMAND(cli_alias, "paging alias", 3, "Show configuration and targets for a paging alias", "paging alias <pager ID>"),
	BBS_CLI_COMMAND(cli_queue, "paging queue", 2, "List messages in paging queue and their status", NULL),
	BBS_CLI_COMMAND(cli_message, "paging message", 3, "Show information about a queued page", "paging message <msgtag>"),
	BBS_CLI_COMMAND(cli_purge, "paging purge", 3, "Show information about a queued page", "paging purge <msgtag|ALL>"),
	BBS_CLI_COMMAND(cli_page, "page", 2, "Send a simple page to a paging endpoint. Message is read on STDIN.", "page <pager ID>"),
};

static int unload_module(void)
{
	unloading = 1;

	bbs_unregister_paging_provider(&paging_callbacks);
	bbs_cli_unregister_multiple(cli_commands_paging);

	/* Clean up the queue first */
	RWLIST_WRLOCK(&queued_pages);
	bbs_pthread_interrupt(queue_thread); /* Since list is locked, queue_thread won't be doing anything important */
	bbs_pthread_join(queue_thread, NULL);
	RWLIST_REMOVE_ALL(&queued_pages, entry, free_queued_page);
	RWLIST_UNLOCK(&queued_pages);

	RWLIST_WRLOCK(&endpoints);
	RWLIST_REMOVE_ALL(&aliases, entry, free_alias); /* Aliases must be freed first since they reference endpoints */
	RWLIST_REMOVE_ALL(&endpoints, entry, free);
	RWLIST_UNLOCK(&endpoints);

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	if (bbs_pthread_create(&queue_thread, NULL, periodic_queue_thread, NULL)) {
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_paging);
	if (bbs_register_paging_provider(&paging_callbacks, 1, PAGING_PROT_DEFAULT)) { /* Register with highest priority */
		usleep(100); /* XXX Delay needed for bbs_pthread_interrupt to work */
		unload_module();
		return -1;
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("General Paging Handler");
