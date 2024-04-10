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
 * \brief IMAP Client LIST
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/node.h"
#include "include/parallel.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_client.h"
#include "nets/net_imap/imap_server_list.h"
#include "nets/net_imap/imap_client_list.h"
#include "nets/net_imap/imap_client_status.h" /* use remove_size */

extern unsigned int maxuserproxies;

static int remote_list(struct imap_client *client, struct list_command *lcmd, const char *prefix)
{
	char *s;
	struct stringlist matchedmailboxes;
	struct imap_session *imap = client->imap;
	struct bbs_tcp_client *tcpclient = &client->client;
	int caps = client->virtcapabilities;
	const char *subprefix;
	ssize_t res;

	stringlist_init(&matchedmailboxes);

	/* Don't send LIST-STATUS here, even if the remote server supports it,
	 * because imap_client_status.c is responsible for STATUS and LIST-STATUS
	 * And even if we have something to limit the scope of the search,
	 * since LIST could contain multiple patterns, we really need to use list_mailbox_pattern_matches
	 * to check that, since the mailbox names are different remotely so we can't just easily pass through the LIST arguments.
	 */
	if (caps & IMAP_CAPABILITY_LIST_EXTENDED) {
		/* RFC 5258 Sec 4: Technically, if the server supports LIST-EXTENDED and we don't ask for CHILDREN explicitly,
		 * it's not obligated to return these attributes. Ditto for SPECIAL-USE. */
		if (caps & IMAP_CAPABILITY_SPECIAL_USE) {
			IMAP_CLIENT_SEND(tcpclient, "a3 LIST \"\" \"*\" RETURN (CHILDREN SPECIAL-USE)");
		} else {
			IMAP_CLIENT_SEND(tcpclient, "a3 LIST \"\" \"*\" RETURN (CHILDREN)");
		}
	} else {
		IMAP_CLIENT_SEND(tcpclient, "a3 LIST \"\" \"*\"");
	}

	for (;;) {
		char fullmailbox[256];
		char *p1, *p2, *delimiter;
		const char *attributes, *virtmboxname;
		res = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 200);
		if (res < 0) {
			break;
		}
		if (STARTS_WITH(tcpclient->buf, "a3 OK")) {
			break; /* Done */
		}
		/* The responses are something like this:
		 *     * LIST () "." "Archive"
		 *     * LIST () "." "INBOX"
		 */
		/* Skip the first 2 spaces */
		p1 = tcpclient->buf;
		p2 = p1;
		if (skipn(&p2, ' ', 2) != 2) {
			bbs_warning("Invalid LIST response: %s\n", tcpclient->buf);
			continue;
		}
		if (strlen_zero(p2)) {
			bbs_warning("Unexpected LIST response: %s\n", tcpclient->buf); /* Probably screwed up now anyways */
			continue;
		}
		/* Should now be at (). But this can contain multiple words, so use parensep, not strsep */
		if (*p2 != '(') { /* guaranteed to exist since p2 would be empty otherwise */
			bbs_warning("Invalid LIST response: %s\n", p2);
			continue;
		}
		attributes = parensep(&p2);
		/* Now at "." "Archive"
		 * But not all IMAP servers use "." as their hierarchy delimiter.
		 * Gimap, for example, uses "/".
		 * So preserve the delimiter the server sends us. */
		delimiter = strsep(&p2, " ");
		STRIP_QUOTES(delimiter);
		if (strlen_zero(delimiter)) {
			bbs_warning("Invalid LIST response\n");
			continue;
		}
		/* . is the most common. Gmail uses / and Yandex uses | */
		if (strcmp(delimiter, ".") && strcmp(delimiter, "/") && strcmp(delimiter, "|")) {
			bbs_warning("Unexpected hierarchy delimiter '%s' (remainder: %s)\n", delimiter, p2); /* Flag anything uncommon in case it's a parsing error */
		}
		STRIP_QUOTES(p2); /* Strip quotes from mailbox name, we'll add them ourselves */
		/* Note that for real Other Users, the root folder (username) is itself selectable, and that is the INBOX.
		 * For these virtual folders, the INBOX is just a folder that appears as a sibling to other folders, e.g. Sent, Drafts, etc. */
		if (strlen_zero(attributes)) { /* If it was (), then *attributes is just the NUL terminator at this point */
			/* attributes are empty. Try to guess what they are based on folder name.
			 * This is useful as mail clients will at least use nice icons when displaying these folders: */
			if (!strcmp(p2, "Drafts")) {
				attributes = "\\Drafts";
			} else if (!strcmp(p2, "Sent")) {
				attributes = "\\Sent";
			} else if (!strcmp(p2, "Junk")) {
				attributes = "\\Junk";
			} else if (!strcmp(p2, "Trash")) {
				attributes = "\\Trash";
			} else {
				bbs_debug(8, "Mailbox '%s' has no attributes\n", p2);
			}
			if (!strlen_zero(attributes)) {
				bbs_debug(3, "Remote IMAP server does not support SPECIAL-USE, adding heuristically\n");
			}
			/*! \todo Would be nice to say HasChildren or HasNoChildren here, too, if the server didn't say */
		}
		/*! \todo FIXME Not everything implemented in list_scandir_single is implemented here.
		 * e.g. XLIST, adding \\Subscribed.
		 * Ideally, we'd have common code for that, but there we construct the flags,
		 * and here we basically do passthrough from whatever the server told us.
		 * In particular, if lcmd->retsubscribed, we should append \\Subscribed.
		 *
		 * - We should also tack on \HasChildren or \HasNoChildren based on the folders received.
		 * - We should also tack on \Marked or \Unmarked based on whether there are new messages that haven't been seen yet.
		 *   Determining if this is the case might be a little bit tricky.
		 *   An easy case that should result in no false negatives is if the cached STATUS response has changed or not.
		 *   (Of course, that means we'll have to do the STATUS *before* returning the LIST response, and even if we're not doing LIST-STATUS)
		 */
		if (lcmd->specialuse && !strlen_zero(attributes)) {
			if (strstr(attributes, "\\Drafts") || strstr(attributes, "\\Sent") || strstr(attributes, "\\Junk") || strstr(attributes, "\\Trash")) {
				bbs_debug(7, "Ignoring SPECIAL-USE mailbox\n");
				continue;
			}
		}

		snprintf(fullmailbox, sizeof(fullmailbox), "%s%s%s", prefix, delimiter, p2);
		/* If the remote server's hierarchy delimiter differs from ours,
		 * then we need to use our hierarchy delimiter locally,
		 * but translate when sending commands to the remote server. */
		bbs_strreplace(fullmailbox, client->virtdelimiter, HIERARCHY_DELIMITER_CHAR);

		/* Check if it matches the LIST filters */
		if (strncmp(fullmailbox, lcmd->reference, lcmd->reflen)) {
			bbs_debug(8, "Virtual mailbox '%s' doesn't match reference %s\n", fullmailbox, lcmd->reference);
			continue;
		}

		/* Need to do specifically for remote mailboxes, we can't just add a fixed skiplen (could be multiple patterns) */
		virtmboxname = fullmailbox;
		if (STARTS_WITH(virtmboxname, OTHER_NAMESPACE_PREFIX)) {
			virtmboxname += STRLEN(OTHER_NAMESPACE_PREFIX);
		} else if (STARTS_WITH(virtmboxname, SHARED_NAMESPACE_PREFIX)) {
			virtmboxname += STRLEN(SHARED_NAMESPACE_PREFIX);
		}
		if (!list_mailbox_pattern_matches(lcmd, virtmboxname)) {
			bbs_debug(8, "Virtual mailbox '%s' does not match any list pattern\n", virtmboxname);
			continue;
		}
		if (STARTS_WITH(p2, "[Gmail]/")) {
			/* Skip "virtual folders" that people don't really want, since they duplicate other folders,
			 * in case they're not actually disabled for IMAP access online.
			 * That way the client doesn't even have a chance to learn they exist,
			 * in case it's not configured to ignore those / not synchronize them.
			 */
			const char *rest = p2 + STRLEN("[Gmail]/");
			if (!strcmp(rest, "All Mail") || !strcmp(rest, "Important") || !strcmp(rest, "Starred")) {
				bbs_debug(5, "Omitting unwanted folder '%s' from listing\n", p2);
				continue;
			}
		}

		/* Matches prefix, send it (but send our hierarchy delimiter, not remote delimiter) */
		imap_parallel_send(imap, "%s (%s) \"%c\" \"%s\"", lcmd->cmd, attributes, HIERARCHY_DELIMITER_CHAR, fullmailbox);

#define MAILBOX_SELECTABLE(flags) (strlen_zero(attributes) || (!strcasestr(flags, "\\NonExistent") && !strcasestr(flags, "\\NoSelect")))
		/* Handle LIST-STATUS and STATUS=SIZE for remote mailboxes. */
		if (lcmd->retstatus && MAILBOX_SELECTABLE(attributes)) { /* Don't call STATUS on a NoSelect mailbox */
			/* Keep track of mailboxes that match */
			stringlist_push(&matchedmailboxes, p2);
		}
	}

	/* Skip Other Users. (Other Users already skipped at this point, so skip the delimiter) */
	subprefix = prefix;
	if (STARTS_WITH(subprefix, OTHER_NAMESPACE_PREFIX)) {
		subprefix += STRLEN(OTHER_NAMESPACE_PREFIX) + 1;
	} else if (STARTS_WITH(subprefix, SHARED_NAMESPACE_PREFIX)) {
		subprefix += STRLEN(SHARED_NAMESPACE_PREFIX) + 1;
	}
	/* Keep track of parent mailbox names that are remote */
	stringlist_push(&imap->remotemailboxes, subprefix);

	/* Now that the LIST response is finished, if we're doing LIST-STATUS, get the STATUS of any mailboxes that matched.
	 * imap_client_status.c will send a LIST-STATUS to the remote end and cache that if needed,
	 * but we don't have to worry about the details of that here.
	 *
	 * Because we're popping them off in reverse order, the STATUS responses
	 * will be in the reverse order of the LIST responses. There's nothing wrong with that,
	 * since clients can't expect any particular order, though it is admittedly a bit weird.
	 */
	while ((s = stringlist_pop(&matchedmailboxes))) {
		char statuscmd[84];
		const char *items = lcmd->retstatus;
		int want_size = strstr(items, "SIZE") ? 1 : 0;
		/* We also need to remove SIZE from items if it's not supported by the remote */
		if (want_size && !(caps & IMAP_CAPABILITY_STATUS_SIZE)) {
			safe_strncpy(statuscmd, items, sizeof(statuscmd));
			items = remove_size(statuscmd);
		}

		/* Always use remote_status, never direct passthrough, to avoid sending a tagged OK response each time */
		remote_status(client, s, items, want_size);
		free(s);
	}

	stringlist_destroy(&matchedmailboxes);
	imap_client_idle_notify(client); /* Don't need the client anymore for now... */
	return 0;
}

struct remote_list_info {
	struct list_command *lcmd;
	const char *prefix;
	struct imap_session *imap;
	char *server;
	char data[];
};

static void remote_list_destroy(void *data)
{
	struct remote_list_info *r = data;
	if (!strlen_zero(r->server)) {
		bbs_memzero(r->server, strlen(r->server)); /* Contains password */
	}
	free(r->server);
	free(r);
}

static void *remote_list_dup(void *data)
{
	size_t prefixlen;
	struct remote_list_info *r, *orig = data;

	prefixlen = strlen(orig->prefix);

	r = calloc(1, sizeof(*r) + prefixlen + 1);
	if (ALLOC_FAILURE(r)) {
		return NULL;
	}
	strcpy(r->data, orig->prefix); /* Safe */
	r->prefix = r->data;
	r->lcmd = orig->lcmd;
	r->imap = orig->imap;

	/* Allocate this separately, so that we can destroy it securely */
	r->server = strdup(orig->server);
	if (ALLOC_FAILURE(r->server)) {
		free(r);
		return NULL;
	}
	return r;
}

static int remote_list_cb(void *data)
{
	int res;
	struct remote_list_info *r = data;
	struct imap_client *client = imap_client_get_by_url_parallel(r->imap, r->prefix, r->server);
	bbs_memzero(r->server, strlen(r->server)); /* Contains password */

	if (!client) {
		bbs_error("Failed to get client for %s\n", r->prefix);
		return -1;
	}

	/* Marshall arguments and execute */
	res = remote_list(client, r->lcmd, r->prefix);
	client->active = 0; /* Mark client as no longer being used, so if we need to make room for a new client during the parallel job, we can kick this one */
	return res;
}

static int remote_list_parallel(struct bbs_parallel *p, const char *restrict prefix, struct list_command *lcmd, struct imap_session *imap, const char *server)
{
	struct remote_list_info rinfo; /* No memset needed */

	rinfo.lcmd = lcmd;
	rinfo.prefix = prefix;
	rinfo.imap = imap;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	/* This variable will not be modified, but since the dynamic version allocates and frees it, the type cannot be const */
	rinfo.server = (char*) server;
#pragma GCC diagnostic pop
	return bbs_parallel_schedule_task(p, prefix, &rinfo, remote_list_cb, remote_list_dup, remote_list_destroy);
}

/*! \brief Mutex to prevent recursion */
static bbs_mutex_t virt_lock = BBS_MUTEX_INITIALIZER; /* XXX Should most definitely be per mailbox struct, not global */

int list_virtual(struct imap_session *imap, struct list_command *lcmd)
{
	FILE *fp;
	char virtfile[256];
	char line[256];
	int l = 0;
	struct bbs_parallel p;

	/* Folders from the proxied mailbox will need to be translated back and forth */
	if (bbs_mutex_trylock(&virt_lock)) {
		bbs_warning("Possible recursion inhibited\n");
		return -1;
	}

	if (imap_client_mapping_file(imap, virtfile, sizeof(virtfile))) {
		bbs_mutex_unlock(&virt_lock);
		return -1;
	}
	bbs_debug(3, "Checking virtual mailboxes in %s\n", virtfile);

	/* It turns out that we can't just send the cached LIST response from when we first built the cache file,
	 * because the assumption that mailbox attributes do not change is wrong.
	 * In particular, the \Marked and \Unmarked attributes could change at any time,
	 * and there is no way to determine if they have without actually asking the server.
	 * Therefore, we need to do a live LIST command for every remote server, every time.
	 *
	 * So the approach here is to issue one LIST per remote server,
	 * and if we're doing a LIST-STATUS, we can also do that for all received mailboxes, at the same time.
	 *
	 * For now, we still keep a cached folder list, but that isn't used anymore at the moment,
	 * and .imapremote.cache could possibly be removed in the future if there's no good use case for it. */
	fp = fopen(virtfile, "r");
	if (!fp) {
		bbs_mutex_unlock(&virt_lock);
		return -1;
	}

	stringlist_empty(&imap->remotemailboxes);
	bbs_parallel_init(&p, 2, maxuserproxies);

	/* Note that we cache all the directories on all servers at once, since we truncate the file. */
	while ((fgets(line, sizeof(line), fp))) {
		char *prefix, *server;

		l++;
		server = line;
		prefix = strsep(&server, "|"); /* Use pipe in case mailbox name contains spaces */
		if (!strncmp(prefix, "#", 1)) {
			continue; /* Skip commented lines */
		}

		/* We don't actually create the client here,
		 * since TCP and IMAP setup time takes a while,
		 * we do it inside the job itself! */
		remote_list_parallel(&p, prefix, lcmd, imap, server);
	}
	fclose(fp);

	bbs_parallel_join(&p);
	bbs_mutex_unlock(&virt_lock);
	return 0;
}
