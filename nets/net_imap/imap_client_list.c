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

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_server_maildir.h"
#include "nets/net_imap/imap_client.h"
#include "nets/net_imap/imap_server_list.h"
#include "nets/net_imap/imap_client_list.h"
#include "nets/net_imap/imap_client_status.h" /* use remove_size */

/*! \brief Mutex to prevent recursion */
static pthread_mutex_t virt_lock = PTHREAD_MUTEX_INITIALIZER; /* XXX Should most definitely be per mailbox struct, not global */

static int imap_client_list(struct bbs_tcp_client *client, int caps, const char *prefix, FILE *fp)
{
	int res;

	if (caps & IMAP_CAPABILITY_LIST_EXTENDED) {
		/* RFC 5258 Sec 4: Technically, if the server supports LIST-EXTENDED and we don't ask for CHILDREN explicitly,
		 * it's not obligated to return these attributes. Ditto for SPECIAL-USE. */
		if (caps & IMAP_CAPABILITY_SPECIAL_USE) {
			IMAP_CLIENT_SEND(client, "a3 LIST \"\" \"*\" RETURN (CHILDREN SPECIAL-USE)");
		} else {
			IMAP_CLIENT_SEND(client, "a3 LIST \"\" \"*\" RETURN (CHILDREN)");
		}
	} else {
		IMAP_CLIENT_SEND(client, "a3 LIST \"\" \"*\"");
	}

	for (;;) {
		char fullmailbox[256];
		char *p1, *p2, *delimiter;
		const char *attributes;
		res = bbs_readline(client->rfd, &client->rldata, "\r\n", 200);
		if (res < 0) {
			break;
		}
		if (STARTS_WITH(client->buf, "a3 OK")) {
			break; /* Done */
		}
		/* The responses are something like this:
		 *     * LIST () "." "Archive"
		 *     * LIST () "." "INBOX"
		 */
		/* Skip the first 2 spaces */
		p1 = client->buf;
		p2 = p1;
		if (skipn(&p2, ' ', 2) != 2) {
			bbs_warning("Invalid LIST response: %s\n", client->buf);
			continue;
		}
		if (strlen_zero(p2)) {
			bbs_warning("Unexpected LIST response: %s\n", client->buf); /* Probably screwed up now anyways */
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
			/*! \todo Would be nice to say HasChildren or HasNoChildren here, too, if the server didn't say */
		}
		snprintf(fullmailbox, sizeof(fullmailbox), "%s%s%s", prefix, delimiter, p2);
		/* If the hierarchy delimiter differs from ours, then fullmailbox will contain multiple delimiters.
		 * The prefix uses ours and the remote mailbox part uses theirs.
		 * The translation happens when this gets used later. */
		fprintf(fp, "(%s) \"%s\" \"%s\"\n", attributes, delimiter, fullmailbox); /* Cache the folders so we don't have to keep hitting the server up */
		/* If this doesn't match the filter, we won't actually send it to the client, but still save it to the cache, so it's complete. */
	}

	return 0;
}

int list_virtual(struct imap_session *imap, struct list_command *lcmd)
{
	FILE *fp2;
	char virtfile[256];
	char virtcachefile[256];
	char line[256];
	int l = 0;
	struct stat st, st2;
	int forcerescan = 0;

	/* Folders from the proxied mailbox will need to be translated back and forth */
	if (pthread_mutex_trylock(&virt_lock)) {
		bbs_warning("Possible recursion inhibited\n");
		return -1;
	}

	snprintf(virtfile, sizeof(virtfile), "%s/.imapremote", mailbox_maildir(imap->mymbox));
	snprintf(virtcachefile, sizeof(virtcachefile), "%s/.imapremote.cache", mailbox_maildir(imap->mymbox));
	bbs_debug(3, "Checking virtual mailboxes in %s\n", virtcachefile);

	if (stat(virtfile, &st)) {
		pthread_mutex_unlock(&virt_lock);
		return -1;
	}
	if (stat(virtcachefile, &st2) || st.st_mtim.tv_sec > st2.st_mtim.tv_sec) {
		/* .imapremote has been modified since .imapremote.cache was written, or .imapremote.cache doesn't even exist yet */
		bbs_debug(4, "Control file has changed since cache file was last rebuilt, need to rebuild again\n");
		forcerescan = 1;
	}
	if (!forcerescan) {
		/* A bit non-optimal since we'll fail 2 fopens if a user isn't using virtual mailboxes */
		fp2 = fopen(virtcachefile, "r");
	}

#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
	/* gcc thinks fp2 can be used uninitialized here. If it is, the conditional will short circuit, so it can't be. */
	if (forcerescan || !fp2) {
#pragma GCC diagnostic pop /* -Wcast-qual */
		FILE *fp = fopen(virtfile, "r");
		if (!fp) {
			pthread_mutex_unlock(&virt_lock);
			return -1;
		}
		fp2 = fopen(virtcachefile, "w+");
		if (!fp2) {
			fclose(fp);
			pthread_mutex_unlock(&virt_lock);
			return -1;
		}

		/* Note that we cache all the directories on all servers at once, since we truncate the file. */
		while ((fgets(line, sizeof(line), fp))) {
			char *prefix, *server;
			struct bbs_url url;
			struct bbs_tcp_client client;
			int secure = 0;
			char buf[1024]; /* Must be large enough to get all the CAPABILITYs, or bbs_readline will throw a warning about buffer exhaustion and return 0 */

			l++;
			server = line;
			prefix = strsep(&server, "|"); /* Use pipe in case mailbox name contains spaces */
			if (!strncmp(prefix, "# ", 2)) {
				continue; /* Skip commented lines */
			}

			memset(&url, 0, sizeof(url));
			if (bbs_parse_url(&url, server)) {
				bbs_warning("Malformed URL on line %d: %s\n", l, server); /* Include the line number since bbs_parse_url "used up" the string */
				continue;
			}
			if (!strcmp(url.prot, "imaps")) {
				secure = 1;
			} else if (strcmp(url.prot, "imap")) {
				bbs_warning("Unsupported protocol: %s\n", url.prot);
				continue;
			}
			/* Expect a URL like imap://user:password@imap.example.com:993/mailbox */
			memset(&client, 0, sizeof(client));
			if (bbs_tcp_client_connect(&client, &url, secure, buf, sizeof(buf))) {
				continue;
			}
			if (!my_imap_client_login(&client, &url, imap)) {
				imap_client_list(&client, imap->virtcapabilities, prefix, fp2);
			}
			bbs_tcp_client_cleanup(&client);
		}
		fclose(fp);
		rewind(fp2); /* Rewind cache to the beginning, in case we just wrote it */
	}

	/* At this point, we should be able to send whatever is in the cache */

	stringlist_empty(&imap->remotemailboxes);
	while ((fgets(line, sizeof(line), fp2))) {
		char relativepath[256];
		char remotedelim;
		const char *virtmboxaccount;
		char *tmp, *fullmboxname, *virtmboxname = relativepath;

		/* Extract the user facing mailbox path from the LIST response in the cache file */
		bbs_strterm(line, '\n'); /* Strip trailing LF */
		safe_strncpy(relativepath, line, sizeof(relativepath));
		if (skipn_noparen(&virtmboxname, ' ', 2) != 2) {
			bbs_warning("Invalid LIST response: %s\n", line); /* Garbage in the cache file */
			continue;
		}
		STRIP_QUOTES(virtmboxname);

		/* Check if it matches the LIST filters */
		if (strncmp(virtmboxname, lcmd->reference, lcmd->reflen)) {
			bbs_debug(8, "Virtual mailbox '%s' doesn't match reference %s\n", virtmboxname, lcmd->reference);
			continue;
		}

		fullmboxname = virtmboxname;

		/* Need to do specifically for remote mailboxes, we can't just add a fixed skiplen (could be multiple patterns) */
		if (STARTS_WITH(virtmboxname, OTHER_NAMESPACE_PREFIX)) {
			virtmboxname += STRLEN(OTHER_NAMESPACE_PREFIX);
		} else if (STARTS_WITH(virtmboxname, SHARED_NAMESPACE_PREFIX)) {
			virtmboxname += STRLEN(SHARED_NAMESPACE_PREFIX);
		}
		if (!list_mailbox_pattern_matches(lcmd, virtmboxname)) {
			bbs_debug(8, "Virtual mailbox '%s' does not match any list pattern\n", virtmboxname);
			continue;
		}

		/* Skip "virtual folders" that people don't really want, since they duplicate other folders,
		 * in case they're not actually disabled for IMAP access online.
		 * That way the client doesn't even have a chance to learn they exist,
		 * in case it's not configured to ignore those / not synchronize them.
		 */
		tmp = strstr(virtmboxname, "[Gmail]/");
		if (tmp) {
			const char *rest = tmp + STRLEN("[Gmail]/");
			if (!strcmp(rest, "All Mail") || !strcmp(rest, "Important") || !strcmp(rest, "Starred")) {
				bbs_debug(5, "Omitting unwanted folder '%s' from listing\n", virtmboxname);
				continue;
			}
		}

		/* Matches prefix, send it */
		if (lcmd->specialuse && !strstr(line, "\\")) {
			/* If it's a special use mailbox, there should be a backslash present, somewhere */
			continue;
		}

		/*! \todo FIXME Not everything implemented in list_scandir_single is implemented here.
		 * e.g. XLIST, adding \\Subscribed.
		 * Ideally, we'd have common code for that, but there we construct the flags,
		 * and here we basically do passthrough from whatever the server told us.
		 * In particular, if lcmd->retsubscribed, we should append \\Subscribed.
		 */

		/* If the remote server's hierarchy delimiter differs from ours,
		 * then we need to use our hierarchy delimiter locally,
		 * but translate when sending commands to the remote server.
		 *
		 * e.g. something like:
		 * (\NoSelect) "/" "Other Users.gmail.[Gmail]/Something"
		 *
		 * The first part uses our hierarchy delimiter, and the remote part could be different.
		 * Change "/" to "." (our delimiter) in the response to the client,
		 * and replace the remote's delimiter with ours wherever it appears
		 *
		 * So the above might transform to:
		 * (\NoSelect) "." "Other Users.gmail.[Gmail].Something"
		 *
		 * The great thing here is we don't need to recreate the string.
		 * We're replacing one character with another, so we can
		 * do the replacement in place.
		 */
		tmp = line;
		/* This must succeed since we did at least this much above.
		 * And you might think, this is a bit silly, why not use strsep?
		 * Ah, but strsep splits the string up, which we don't want to do. */
		skipn_noparen(&tmp, ' ', 1);
		tmp++; /* Skip opening quote */
		remotedelim = *tmp;
		*tmp = HIERARCHY_DELIMITER_CHAR;
		skipn_noparen(&tmp, ' ', 1);
		tmp++; /* Skip opening quote */

		/* Now, do replacements where needed on the remote name */
		while (*tmp) {
			if (*tmp == remotedelim) {
				*tmp = HIERARCHY_DELIMITER_CHAR;
			}
			tmp++;
		}

		imap_send(imap, "%s %s", lcmd->cmd, line);
		virtmboxaccount = virtmboxname + 1; /* Skip Other Users. (Other Users already skipped at this point, so skip the delimiter) */

#define MAILBOX_SELECTABLE(flags) (!strcasestr(flags, "\\NonExistent") && !strcasestr(flags, "\\NoSelect"))

		/* Handle LIST-STATUS and STATUS=SIZE for remote mailboxes. */
		if (lcmd->retstatus && MAILBOX_SELECTABLE(line)) { /* Don't call STATUS on a NoSelect mailbox */
			/* Replace the remote hierarchy delimiter with our own, solely for set_maildir. */
			bbs_strreplace(fullmboxname, remotedelim, HIERARCHY_DELIMITER_CHAR);
			/* Use fullmboxname, for full mailbox name (from our perspective), NOT virtmboxname */
			if (set_maildir(imap, fullmboxname)) {
				bbs_error("Failed to set maildir for mailbox '%s'\n", fullmboxname);
			} else if (!imap->virtmbox) {
				/* We know we called set_maildir for a remote mailbox, so it should always be remote */
				bbs_warning("No virtual/remote mailbox active?\n");
			} else {
				/* remote_mailbox_name may modify fullmboxname (if the hierarchy delimiters differ)
				 * This is fine since the only further use is below when pushing to the stringlish,
				 * but we strip all hierarchy delimiters before doing that anyways. */
				char statuscmd[84];
				const char *items = lcmd->retstatus;
				char *remotename = remote_mailbox_name(imap, fullmboxname); /* Convert local delimiter (back) to remote */
				int want_size = strstr(lcmd->retstatus, "SIZE") ? 1 : 0;
				REPLACE(imap->activefolder, fullmboxname);

				/* We also need to remove SIZE from lcmd->retstatus if it's not supported by the remote */
				if (want_size && !(imap->virtcapabilities & IMAP_CAPABILITY_STATUS_SIZE)) {
					safe_strncpy(statuscmd, lcmd->retstatus, sizeof(statuscmd));
					items = remove_size(statuscmd);
				}

				/* Always use remote_status, never direct passthrough, to avoid sending a tagged OK response each time */
				remote_status(imap, remotename, items, want_size);
			}
			/* Most of it is already in the remote format... convert it all so bbs_strterm will stop at the right spot */
			bbs_strreplace(fullmboxname, HIERARCHY_DELIMITER_CHAR, remotedelim);
		}

		bbs_strterm(virtmboxaccount, remotedelim); /* Just the account portion, so we can use stringlist_contains later */

		/* Keep track of parent mailboxe names that are remote */
		if (!stringlist_contains(&imap->remotemailboxes, virtmboxaccount)) {
			stringlist_push(&imap->remotemailboxes, virtmboxaccount);
		}
	}
	fclose(fp2);

	pthread_mutex_unlock(&virt_lock);
	return 0;
}
