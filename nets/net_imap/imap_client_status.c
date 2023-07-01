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
 * \brief Remote IMAP STATUS
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <poll.h>

#include "include/node.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_client.h"
#include "nets/net_imap/imap_client_status.h"

char *remove_size(char *restrict s)
{
	/* This IMAP server supports STATUS=SIZE, but if the remote one doesn't,
	 * we have to remove it from the STATUS command before passing it through,
	 * since unsupporting IMAP servers may reject the command otherwise. */
	if (strstr(s, " SIZE ")) {
		/* If we just check "SIZE" and there's a space on both sides, there'd be 2 spaces left, instead of just 1 */
		bbs_str_remove_substring(s, " SIZE", STRLEN(" SIZE"));
	} else if (strstr(s, " SIZE")) {
		/* Similar reason. Not all IMAP servers are tolerant of stray spaces. */
		bbs_str_remove_substring(s, " SIZE", STRLEN(" SIZE"));
	} else if (strstr(s, "SIZE ")) {
		/* Ditto, although this case is extremely unlikely. */
		bbs_str_remove_substring(s, "SIZE ", STRLEN("SIZE "));
	} else {
		bbs_str_remove_substring(s, "SIZE", STRLEN("SIZE"));
	}
	return s;
}

static FILE *status_size_cache_file_load(struct imap_client *client, const char *remotename, int write)
{
	char cache_dir[256];
	char cache_file_name[534];
	int cachedirlen;
	FILE *fp;
	struct imap_session *imap = client->imap;

	/* Put them in a subdirectory of the maildir, so it doesn't clutter up the maildir.
	 * The name just has to NOT start with the hierarchy delimiter (or it would be a maildir) */
	cachedirlen = snprintf(cache_dir, sizeof(cache_dir), "%s/__cache", mailbox_maildir(imap->mymbox));
	if (write && eaccess(cache_dir, R_OK) && mkdir(cache_dir, 0700)) {
		bbs_error("mkdir(%s) failed: %s\n", cache_dir, strerror(errno));
	}
	snprintf(cache_file_name, sizeof(cache_file_name), "%s/.imapremote.size.%s.%s", cache_dir, client->virtprefix, remotename);
	/* Replace the remote delimiter with a period.
	 * The actual character in this case isn't super important,
	 * and it doesn't need to be our local delimiter (which is just a coincidence).
	 * It just needs to be deterministic and make this path unique on the filesystem,
	 * and it can't be / as that would indicate a subdirectory.
	 * Period is just a good choice, for the same reason it's a good choice for the maildir++ delimiter. */
	bbs_strreplace(cache_file_name + cachedirlen + 1, client->virtdelimiter, '.');
	fp = fopen(cache_file_name, write ? "w" : "r");
	if (!fp) {
		if (write) {
			bbs_error("fopen(%s) failed: %s\n", cache_file_name, strerror(errno));
		}
		return NULL;
	}
	return fp;
}

static int status_size_cache_fetch(struct imap_client *client, const char *remotename, const char *remote_status_resp, size_t *mb_size)
{
	char buf[256];
	size_t curlen;
	FILE *fp;
	char *tmp;

	fp = status_size_cache_file_load(client, remotename, 0);
	if (!fp) {
		bbs_debug(9, "Cache file does not exist\n");
		return -1; /* Not an error, just the cache file didn't exist (probably the first time) */
	}
	fgets(buf, sizeof(buf), fp);
	fclose(fp);

	curlen = strlen(remote_status_resp);

	/* We subtract 2 as the last characters won't match.
	 * In the raw response from the server, we'll have a ) at the end for end of response,
	 * but in the cached version, we appended the SIZE so there'll be a space there e.g. " SIZE XXX" */
	if (strncmp(remote_status_resp, buf, curlen - 2)) {
		bbs_debug(6, "Cached size is outdated ('%.*s' !~= '%.*s')\n", (int) (curlen - 2), remote_status_resp, (int) (curlen - 2), buf);
		return -1;
	}

	/* Reuse the SIZE from last time */
	tmp = strstr(buf + curlen - 2, "SIZE ");
	if (!tmp) {
		bbs_warning("Cache file missing size?\n");
	}
	tmp += STRLEN("SIZE ");
	if (strlen_zero(tmp)) {
		bbs_warning("Cache file missing size?\n");
		return -1;
	}
	*mb_size = (size_t) atol(tmp);
	return 0;
}

static void status_size_cache_update(struct imap_client *client, const char *remotename, const char *remote_status_resp)
{
	FILE *fp = status_size_cache_file_load(client, remotename, 1);

	/* Using a separate file for every single remote folder is... not very efficient.
	 * But it's very easy to deal with, much easier than using a single file for all remote boxes,
	 * especially if some require changes and some don't.
	 * And to put it in perspective, it might add a few ms of overhead per mailbox (at most),
	 * whereas the caching itself is potentially saving seconds, so the bar is already very low, so to speak,
	 * and this is very easy to reason about and should be bug-free.
	 */
	if (!fp) {
		return;
	}
	fprintf(fp, "%s\n", remote_status_resp);
	fclose(fp);
}

static int cache_remote_list_status(struct imap_client *client, const char *rtag, size_t taglen)
{
	int res;
	struct dyn_str dynstr;
	int i;
	struct bbs_tcp_client *tcpclient = &client->client;
	char *buf = tcpclient->rldata.buf;

	free_if(client->virtlist);
	memset(&dynstr, 0, sizeof(dynstr));

	client->virtlisttime = (int) time(NULL);

	for (i = 0; ; i++) {
		res = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 10000);
		if (res <= 0) {
			bbs_warning("IMAP timeout from LIST-STATUS - remote server issue?\n");
			free_if(dynstr.buf);
			return -1;
		}
		if (!strncmp(buf, rtag, taglen)) {
			bbs_debug(3, "End of LIST-STATUS response: %s\n", buf);
			break;
		}
		/* Only save STATUS lines */
		if (STARTS_WITH(buf, "* LIST")) {
			continue;
		} else if (!STARTS_WITH(buf, "* STATUS")) {
			bbs_warning("Unexpected LIST-STATUS response: %s\n", buf);
			continue;
		}
		if (i) {
			dyn_str_append(&dynstr, "\n", STRLEN("\n"));
		}
		dyn_str_append(&dynstr, tcpclient->rldata.buf, (size_t) res);
	}
	client->virtlist = dynstr.buf;
	return 0;
}

static int remote_status_cached(struct imap_client *client, const char *mb, char *buf, size_t len)
{
	char *tmp, *end;
	size_t statuslen;
	char findstr[128];

	snprintf(findstr, sizeof(findstr), "* STATUS \"%s\"", mb);
	tmp = strstr(client->virtlist, findstr);
	if (!tmp && !strchr(mb, ' ')) { /* Retry, without quotes, if the mailbox name has no spaces */
		snprintf(findstr, sizeof(findstr), "* STATUS \"%s\"", mb);
		tmp = strstr(client->virtlist, findstr);
	}
	if (!tmp) {
		bbs_warning("Cached LIST-STATUS response missing response for '%s'\n", mb);
		return -1;
	}
	end = strchr(tmp, '\n');
	if (end) {
		statuslen = (size_t) (end - tmp);
	} else {
		statuslen = strlen(tmp);
	}
	safe_strncpy(buf, tmp, MIN(len, statuslen + 1));
	bbs_debug(3, "Cached LIST-STATUS for '%s': %s\n", mb, buf);
	return 0;
}

int remote_status(struct imap_client *client, const char *remotename, const char *items, int size)
{
	char buf[1024];
	char converted[256];
	char remote_status_resp[1024];
	char rtag[64];
	size_t taglen;
	int len, res;
	char *tmp;
	struct imap_session *imap = client->imap;
	struct bbs_tcp_client *tcpclient = &client->client;
	const char *tag = client->imap->tag;
	const char *add1, *add2, *add3;
	int issue_status = 1;

	tcpclient->rldata.buf = buf;
	tcpclient->rldata.len = sizeof(buf);

	/* In order for caching of SIZE to be reliable, we must invalidate it whenever anything
	 * in the original STATUS response, including UIDNEXT/UIDVALIDITY. These are needed to
	 * reliably detect changes to the mailbox (e.g. if a message is added and delete,
	 * with MESSAGES/UNSEEN/RECENT alone, those might not change, but SIZE would probably
	 * change if the added message is different from the deleted message.
	 * In this case though, UIDNEXT and UIDVALIDITY would both change.
	 * Likewise, UIDVALIDITY and UIDNEXT alone are NOT sufficient, because if a message is deleted,
	 * UIDNEXT and UIDVALIDITY do not change (but MESSAGES will).
	 * TL;DR - to detect changes, we need all three of MESSAGES, UIDNEXT, and UIDVALIDITY.
	 *
	 * Even if the client did not request them, if the remote does not support STATUS=SIZE,
	 * request these (if not already requested).
	 * These will also get returned in the response (even if the client didn't ask for them),
	 * but that's not really an issue, since it's getting more than what it asked for.
	 */
	add1 = !(client->virtcapabilities & IMAP_CAPABILITY_STATUS_SIZE) && !strstr(items, "UIDNEXT") ? " UIDNEXT" : "";
	add2 = !(client->virtcapabilities & IMAP_CAPABILITY_STATUS_SIZE) && !strstr(items, "UIDVALIDITY") ? " UIDVALIDITY" : "";
	add3 = !(client->virtcapabilities & IMAP_CAPABILITY_STATUS_SIZE) && !strstr(items, "MESSAGES") ? " MESSAGES" : "";

	/* XXX The tag sent to the remote end will be the same for every single mailbox (for LIST-STATUS)
	 * Since we're not pipelining these that's fine (and even if we were, it wouldn't be ambiguous
	 * since the response contains the mailbox name), but this is certainly not a "proper" thing to do... */
	taglen = (size_t) snprintf(rtag, sizeof(rtag), "A.%s.1 OK", tag);

	/* If the remote server supports LIST-STATUS, do that (once), rather than doing a STATUS on each mailbox there
	 * Cache the results locally and reuse that for the same virtual mailbox. */
	if (client->virtlist && client->virtlisttime < (int) time(NULL) - 10) {
		/* If the cached LIST-STATUS response is more than 10 seconds old, consider it stale.
		 * The use case here is for replying to a LIST-STATUS query or a client querying STATUS
		 * of every mailbox in succession, if these are spread out the statuses could have changed since. */
		bbs_debug(8, "Cached LIST-STATUS response is stale, purging\n");
		free_if(client->virtlist);
	}
	if (!client->virtlist && client->virtcapabilities & IMAP_CAPABILITY_LIST_STATUS) { /* Try LIST-STATUS if it's the first mailbox */
		len = snprintf(buf, sizeof(buf), "A.%s.1 LIST \"\" \"*\" RETURN (STATUS (%s%s%s%s))\r\n", tag, items, add1, add2, add3);
		imap_debug(3, "=> %.*s", len, buf);
		bbs_write(tcpclient->wfd, buf, (size_t) len);
		cache_remote_list_status(client, rtag, taglen);
	}
	if (client->virtlist) {
		if (!remote_status_cached(client, remotename, remote_status_resp, sizeof(remote_status_resp))) {
			bbs_debug(8, "Reusing cached LIST-STATUS response for '%s'\n", remotename);
			issue_status = 0;
		}
	}

	if (issue_status) {
		/* XXX Same tag is reused here, so we expect the same prefix (rtag) */
		len = snprintf(buf, sizeof(buf), "A.%s.1 STATUS \"%s\" (%s%s%s%s)\r\n", tag, remotename, items, add1, add2, add3);
		imap_debug(3, "=> %.*s", len, buf);
		bbs_write(tcpclient->wfd, buf, (size_t) len);
		res = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 5000);
		if (res <= 0) {
			return -1;
		}
		if (!STARTS_WITH(buf, "* STATUS ")) {
			bbs_warning("Unexpected response: %s\n", buf);
			return -1;
		}
		safe_strncpy(remote_status_resp, buf, sizeof(remote_status_resp)); /* Save the STATUS response from the server */
		res = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 5000);
		if (res <= 0) {
			return -1;
		}
		if (strncasecmp(buf, rtag, taglen)) {
			bbs_warning("Unexpected response: %s (doesn't start with %.*s)\n", buf, (int) taglen, rtag);
			return -1;
		}
	}

	/*
	 * The other optimization is caching the SIZE for servers that don't support STATUS=SIZE.
	 * After each invocation of this function, we store the STATUS response received from the server.
	 * If it is identical to the cached version, we know that SIZE must be the same, without issuing a FETCH 1:* (which is slow!)
	 * To be 100% reliable, we include MESSAGES, UIDNEXT, and UIDVALIDITY in the STATUS query,
	 * even if the client didn't ask for them (should be okay to respond with them regardless anyways).
	 * In this case, we still have the overhead of doing STATUS for each folder, but that's peanuts compared to FETCH 1:*
	 */

	if (size && !strstr(remote_status_resp, "SIZE ")) { /* If we want SIZE and the server didn't send it, calculate it. */
		size_t mb_size = 0;
		int cached = 0;
		/* Check the cache to see if we've already done a FETCH 1:* before and if the mailbox has changed since.
		 * If not, the SIZE will be the same as last time, and we can just return that.
		 * This is an EXTREMELY IMPORTANT optimization, because this operation can take a VERY long time on large mailboxes.
		 * It can easily take a couple to several seconds - a rule of thumb might be 1 second per 10,000 messages.
		 * It's a lot of data being received, a lot of calculations, and probably even more work for the poor IMAP server to compute.
		 * Multiply this by a lot of mailboxes, and this can literally save time on the order of a minute.
		 * (And given webmail clients are probably the most interested in SIZE, since they have no persistent state between sessions,
		 *  speed matters the most there and nobody wants to wait a minute for a webmail client to load.)
		 */
		if (!status_size_cache_fetch(client, remotename, remote_status_resp, &mb_size)) {
			cached = 1;
			bbs_debug(5, "Reusing previously cached SIZE: %lu\n", mb_size);
		} else if (!strstr(remote_status_resp, "MESSAGES 0")) { /* If we know the folder is empty, we know SIZE is 0 without asking */
			/* EXAMINE it so it's read only */
			/* XXX This will reuse imap->tag for the tag here... which isn't ideal but should be accepted.
			 * Since we're not pipelining our commands, it doesn't really matter anyways. */
			res = imap_client_send_wait_response_noecho(client, -1, 5000, "%s \"%s\"\r\n", "EXAMINE", remotename);
			if (res) {
				return res;
			}

			/* Need to reinitialize again since client_command_passthru modifies this */
			tcpclient->rldata.buf = buf;
			tcpclient->rldata.len = sizeof(buf);

			/* imap->tag gets reused multiple times for different commands here...
			 * something we SHOULD not do but servers are supposed to (MUST) tolerate. */
			taglen = strlen(tag);
			bbs_write(tcpclient->wfd, tag, taglen);
			SWRITE(tcpclient->wfd, " FETCH 1:* (RFC822.SIZE)\r\n");
			imap_debug(3, "=> %s FETCH 1:* (RFC822.SIZE)\n", tag);
			for (;;) {
				const char *sizestr;
				res = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 10000);
				if (res <= 0) {
					bbs_warning("IMAP timeout from FETCH 1:* (RFC822.SIZE) - remote server issue?\n");
					return -1;
				}
				if (!strncmp(buf, tag, taglen)) {
					bbs_debug(3, "End of FETCH response: %s\n", buf);
					break;
				}
				/* Should get a response like this: * 48 FETCH (RFC822.SIZE 548) */
				sizestr = strstr(buf, "RFC822.SIZE ");
				if (!sizestr) {
					bbs_warning("Unexpected response line: %s\n", buf);
					continue;
				}
				sizestr = sizestr + STRLEN("RFC822.SIZE ");
				if (strlen_zero(sizestr)) {
					bbs_warning("Server sent empty size: %s\n", buf);
					continue;
				}
				mb_size += (size_t) atoi(sizestr);
			}
		} /* else, if no messages, assume size is 0 */

		/* Modify the originally returned response to include the SIZE attribute */
		/* Find LAST instance, since we can't assume there's only one pair of parentheses, the mailbox name could contain parentheses */
		tmp = strrchr(remote_status_resp, ')');
		if (!tmp) {
			return -1;
		}
		*tmp = '\0';
		snprintf(tmp, sizeof(remote_status_resp) - (size_t) (tmp - remote_status_resp), " SIZE %lu)", mb_size);

		if (!cached) {
			/* Cache all of this for next time, so we don't have to issue a FETCH 1:* (which can be VERY slow)
			 * unless the mailbox has been modified in some way. */
			status_size_cache_update(client, remotename, remote_status_resp);
		}
	}

	/* Replace remote mailbox name with our name for it.
	 * To do this, insert imap->virtprefix before the mailbox name.
	 * In practice, easier to just reconstruct the STATUS as needed. */
	tmp = strrchr(remote_status_resp, '('); /* Again, look for the last ( since the mailbox name could contain it */

	safe_strncpy(converted, remotename, sizeof(converted));
	bbs_strreplace(converted, client->virtdelimiter, HIERARCHY_DELIMITER_CHAR); /* Convert remote delimiter back to local for client response */

	imap_send(imap, "STATUS \"%s%c%s\" %s", client->virtprefix, HIERARCHY_DELIMITER_CHAR, converted, tmp); /* Send the modified response */
	return 0;
}
