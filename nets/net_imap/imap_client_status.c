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
#include "include/kvs.h"

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

static size_t status_size_cache_key_name(struct imap_client *client, const char *remotename, char *buf, size_t len)
{
	char prefix[32];
	int keylen;
	struct imap_session *imap = client->imap;

	/* We need a unique prefix based on the mailbox.
	 * All mailboxes either have an ID or have a name. */
	if (mailbox_uniqueid(imap->mymbox, prefix, sizeof(prefix))) {
		return 0;
	}

	keylen = snprintf(buf, len, "net_imap.%s.status.%s.%s", prefix, client->virtprefix, remotename);

	/* Replace the remote delimiter with a period.
	 * The actual character in this case isn't super important,
	 * and it doesn't need to be our local delimiter (which is just a coincidence).
	 * It just needs to be deterministic and make this path unique,
	 * and it can't be / as that would indicate a subdirectory (if KVS store is backed by disk).
	 * Period is just a good choice, for the same reason it's a good choice for the maildir++ delimiter.
	 *
	 * Technically this step isn't necessary, but doing it ensures that if the remote hierarchy delimiter
	 * every changes, that is transparent here.
	 */
	bbs_strreplace(buf, client->virtdelimiter, '.');
	return (size_t) keylen;
}

static void status_size_cache_update(struct imap_client *client, const char *remotename, const char *remote_status_resp)
{
	char key[256];
	size_t keylen;

	keylen = status_size_cache_key_name(client, remotename, key, sizeof(key));
	if (keylen) {
		bbs_kvs_put(key, keylen, remote_status_resp, strlen(remote_status_resp));
	}
}

static int status_size_cache_fetch(struct imap_client *client, const char *remotename, size_t *mb_size, char *buf, size_t len)
{
	char key[256];
	size_t keylen;
	char *tmp;

	keylen = status_size_cache_key_name(client, remotename, key, sizeof(key));
	if (!keylen) {
		return -1;
	}
	if (bbs_kvs_get(key, keylen, buf, len, NULL)) {
		bbs_debug(9, "Cache file does not exist\n");
		return -1; /* Not an error, just the cache file didn't exist (probably the first time) */
	}

	/* Reuse the SIZE from last time */
	tmp = strstr(buf, "SIZE ");
	if (!tmp) {
		bbs_warning("Cache file missing size?\n");
		return -1;
	}
	tmp += STRLEN("SIZE ");
	if (strlen_zero(tmp)) {
		bbs_warning("Cache file missing size?\n");
		return -1;
	}
	*mb_size = (size_t) atol(tmp);
	return 0;
}

static int status_size_fetch_all(struct imap_client *client, const char *tag, size_t *mb_size)
{
	int res;
	size_t taglen;
	struct bbs_tcp_client *tcpclient = &client->client;
	char *buf = tcpclient->rldata.buf;

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

	return 0;
}

#define parse_status_item(full, keyword, result) __parse_status_item(full, keyword, STRLEN(keyword), result)

static int __parse_status_item(const char *full, const char *keyword, size_t keywordlen, int *result)
{
	const char *tmp = strstr(full, keyword);
	if (!tmp) {
		return -1;
	}
	tmp += keywordlen;
	if (*tmp++ != ' ') {
		return -1;
	}
	if (strlen_zero(tmp)) {
		return -1;
	}
	*result = atoi(tmp);
	return 0;
}

static int status_size_fetch_incremental(struct imap_client *client, const char *tag, size_t *mb_size, const char *old, const char *new)
{
	char cmd[64];
	size_t cmdlen;
	int res;
	size_t taglen;
	struct bbs_tcp_client *tcpclient = &client->client;
	char *buf = tcpclient->rldata.buf;
	int oldv, newv;
	int oldmessages, newmessages, oldnext, newnext;
	int netincrease, added, expunged;
	int received;

	/* Compare MESSAGES and UIDNEXT from the old and new responses */
	if (parse_status_item(old, "UIDVALIDITY", &oldv) || parse_status_item(new, "UIDVALIDITY", &newv)) {
		bbs_warning("UIDVALIDITY parsing error\n");
		return -1;
	}
	if (oldv != newv) {
		bbs_verb(4, "Remote UIDVALIDITY changed from %d to %d\n", oldv, newv);
		return -1;
	}
	if (parse_status_item(old, "MESSAGES", &oldmessages) || parse_status_item(new, "MESSAGES", &newmessages)) {
		bbs_warning("MESSAGES parsing error\n");
		return -1;
	}
	if (parse_status_item(old, "UIDNEXT", &oldnext) || parse_status_item(new, "UIDNEXT", &newnext)) {
		bbs_warning("UIDNEXT parsing error\n");
		return -1;
	}

	/* If UIDNEXT increased more, some messages were expunged.
	 * If MESSAGES increased more... well, technically this should not be possible
	 * (it would imply messages were added without increasing UIDNEXT), but in this IMAP server,
	 * we do a read only traversal to compute STATUS and the \Recent messages aren't yet assigned a UID...
	 * a compliant IMAP server might not have this issue, though).
	 *
	 * If UIDNEXT stayed the same, but MESSAGES decreased, then messages were expunged.
	 *
	 * Examples:
	 * Added = new UIDNEXT - old UIDNEXT (assuming this increments by 1, which is a reasonable assumption, though not guaranteed by the RFC)
	 * Net Increase = new MESSAGES - old MESSAGES
	 * Expunged = calculate indirectly:
	 * -Expunged + Added = (new MESSAGES - old MESSAGES)
	 * => -Expunged = Net Increase - added
	 * => Expunged = Added - Net Increase
	 *
	 *     --- OLD ---      --- NEW ---   - Net +/-  - Added - Expunged - Useful? (can we do an incremental fetch?)
	 * MESSAGES UIDNEXT MESSAGES UIDNEXT
	 *    25      75      20      75          -5         0        5       No
	 *    25      75      20      80          -5         5       10       No
	 *    25      75      25      80           0         5        5       No
	 *    25      75      26      80           1         5        4       No
	 *    25      75      30      80           5         5        0       Yes (do an incremental FETCH)
	 *    25      75      25      75           0         0        0       Yes (but this is a simpler case, just reuse)
	 *
	 *
	 * In all cases, when the Expunged count is 0, that's when we can use this shortcut.
	 */
	netincrease = newmessages - oldmessages;
	added = newnext - oldnext;
	expunged = added - netincrease;

	if (expunged > 0) {
		bbs_debug(7, "Messages have been expunged (MESSAGES %d -> %d, UIDNEXT %d -> %d)\n", oldmessages, newmessages, oldnext, newnext);
		return -1;
	} else if (expunged < 0) {
		bbs_warning("%d messages expunged? (MESSAGES %d -> %d, UIDNEXT %d -> %d)\n", expunged, oldmessages, newmessages, oldnext, newnext);
		return -1;
	}

	/* We can do an incremental fetch! */
	bbs_debug(7, "No messages expunged since last time, %d added (MESSAGES %d -> %d, UIDNEXT %d -> %d)\n", added, oldmessages, newmessages, oldnext, newnext);

	/* imap->tag gets reused multiple times for different commands here...
	 * something we SHOULD not do but servers are supposed to (MUST) tolerate. */
	taglen = strlen(tag);

	cmdlen = (size_t) snprintf(cmd, sizeof(cmd), "%s UID FETCH %d:* (RFC822.SIZE)\r\n", tag, oldnext);
	bbs_write(tcpclient->wfd, cmd, cmdlen);
	imap_debug(3, "=> %s", cmd);

	for (received = 0;;) {
		const char *sizestr;
		res = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", 5000);
		if (res <= 0) {
			bbs_warning("IMAP timeout from UID FETCH (RFC822.SIZE) - remote server issue?\n");
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
		received++;
	}

	if (received != added) {
		bbs_warning("Expected to get %d message sizes, but got %d?\n", added, received);
		return -1;
	}

	return 0;
}

static int append_size_item(struct imap_client *client, const char *remotename, const char *remote_status_resp, const char *tag)
{
	size_t curlen;
	char buf[256];
	size_t mb_size = 0;
	int cached = 0;
	char *tmp;

	/* Check the cache to see if we've already done a FETCH 1:* before and if the mailbox has changed since.
	 * If not, the SIZE will be the same as last time, and we can just return that.
	 * This is an EXTREMELY IMPORTANT optimization, because this operation can take a VERY long time on large mailboxes.
	 * It can easily take a couple to several seconds - a rule of thumb might be 1 second per 10,000 messages.
	 * It's a lot of data being received, a lot of calculations, and probably even more work for the poor IMAP server to compute.
	 * Multiply this by a lot of mailboxes, and this can literally save time on the order of a minute.
	 * (And given webmail clients are probably the most interested in SIZE, since they have no persistent state between sessions,
	 *  speed matters the most there and nobody wants to wait a minute for a webmail client to load.)
	 */

	/* Get the STATUS response and size from last time */
	if (status_size_cache_fetch(client, remotename, &mb_size, buf, sizeof(buf))) {
		return -1;
	}

	curlen = strlen(remote_status_resp);

	/* We subtract 2 as the last characters won't match.
	 * In the raw response from the server, we'll have a ) at the end for end of response,
	 * but in the cached version, we appended the SIZE so there'll be a space there e.g. " SIZE XXX" */
	if (!strncmp(remote_status_resp, buf, curlen - 2)) {
		/* The STATUS response is completely the same as last time, so we can just reuse the SIZE directly. */
		cached = 1;
	} else if (strstr(remote_status_resp, "MESSAGES 0")) {
		/* If there are no messages, SIZE must be 0 */
	} else {
		/* EXAMINE it so it's read only */
		/* XXX This will reuse imap->tag for the tag here... which isn't ideal but should be accepted.
		 * Since we're not pipelining our commands, it doesn't really matter anyways. */
		int res = imap_client_send_wait_response_noecho(client, -1, 5000, "%s \"%s\"\r\n", "EXAMINE", remotename);
		if (res) {
			return res;
		}

		/* Okay, so the mailbox has changed since last time... but don't just go right to FETCH 1:* just yet.
		 * Check if we can calculate the size incrementally. This should be possible when, compared with the cached response:
		 * - new messages have been added to the mailbox
		 * - no messages have been expunged from the mailbox
		 *
		 * If this is the case, we can simply fetch all messages by UID starting with the *old* UIDNEXT.
		 * e.g. (simplified example:)
		 *
		 * OLD: * STATUS "INBOX" (MESSAGES 2000 UIDNEXT 2085 SIZE 974605)
		 * NEW: * STATUS "INBOX" (MESSAGES 2003 UIDNEXT 2088 ?????????)
		 *
		 * In the above case, we can just do UID FETCH 2085:* instead of doing FETCH 1:*,
		 * which means we only need to fetch 3 messages, not 2003.
		 *
		 * This case occurs when MESSAGES and UIDNEXT have increased by the same amount.
		 *
		 * If any messages were expunged, we CANNOT optimize, because we don't know which messages were removed.
		 * However, if the mailbox change was purely additive, we can then simply add the difference to the old size.
		 *
		 * In the grand scheme of things, this optimization is probably even more important than the one above,
		 * which can only be used when the mailbox has not changed at all. It's much more likely that messages
		 * have been added (though probably not as likely as some messages having also or only been expunged).
		 *
		 * This is an optimization on multiple fronts, for example, FETCH 1:* on a message of ~75,000 messages:
		 * - takes about 10 seconds
		 * - involves sending 2.5 MB of FETCH responses
		 * - involves 75,000 calculations (at the macro level)
		 *... regardless of how many messages were actually added (even just 1!).
		 *
		 * This optimization doesn't help with all cases, or even most of them, but it should help some,
		 * particularly for non-INBOX "filing"/"archive" mailboxes which generally only increase in size over time.
		 */

		/* Can we calculate the size incrementally? */
		if (status_size_fetch_incremental(client, tag, &mb_size, buf, remote_status_resp)) { /* Add to what we already had */
			/* If not, resort to FETCH 1:* fallback as last resort */
			mb_size = 0;
			if (status_size_fetch_all(client, tag, &mb_size)) {
				return -1;
			}
		}
	}

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
	return 0;
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
			bbs_warning("IMAP timeout (res: %d) from LIST-STATUS - remote server issue?\n", res);
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
	char remote_status_resp[1024];
	char rtag[64];
	size_t taglen;
	int len, res;
	char *buf;
	char cmd[1024];
	struct bbs_tcp_client *tcpclient = &client->client;
	const char *tag = client->imap->tag;
	const char *add1, *add2, *add3;
	int issue_status = 1;

	/* In order for caching of SIZE to be reliable, we must invalidate it whenever anything
	 * in the original STATUS response changes, including UIDNEXT/UIDVALIDITY. These are needed to
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
	buf = client->buf;
	if (!client->virtlist && client->virtcapabilities & IMAP_CAPABILITY_LIST_STATUS) { /* Try LIST-STATUS if it's the first mailbox */
		len = snprintf(cmd, sizeof(cmd), "A.%s.1 LIST \"\" \"*\" RETURN (STATUS (%s%s%s%s))\r\n", tag, items, add1, add2, add3);
		imap_debug(3, "=> %.*s", len, cmd);
		bbs_write(tcpclient->wfd, cmd, (size_t) len);
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
		len = snprintf(cmd, sizeof(cmd), "A.%s.1 STATUS \"%s\" (%s%s%s%s)\r\n", tag, remotename, items, add1, add2, add3);
		imap_debug(3, "=> %.*s", len, cmd);
		bbs_write(tcpclient->wfd, cmd, (size_t) len);
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
		res = append_size_item(client, remotename, remote_status_resp, tag);
		if (res) {
			return res;
		}
	}

	return imap_client_send_converted_status_response(client, remotename, remote_status_resp);
}

int imap_client_send_converted_status_response(struct imap_client *client, const char *remotename, const char *response)
{
	char converted[256];
	char *tmp;
	struct imap_session *imap = client->imap;

	/* Replace remote mailbox name with our name for it.
	 * To do this, insert imap->virtprefix before the mailbox name.
	 * In practice, easier to just reconstruct the STATUS as needed. */
	tmp = strrchr(response, '('); /* Again, look for the last ( since the mailbox name could contain it */

	safe_strncpy(converted, remotename, sizeof(converted));
	bbs_strreplace(converted, client->virtdelimiter, HIERARCHY_DELIMITER_CHAR); /* Convert remote delimiter back to local for client response */

	imap_send(imap, "STATUS \"%s%c%s\" %s", client->virtprefix, HIERARCHY_DELIMITER_CHAR, converted, tmp); /* Send the modified response */

	return 0;
}
