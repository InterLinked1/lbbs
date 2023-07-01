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
 * \brief Simple Proxied IMAP Client
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <poll.h>

#include "include/node.h"

#include "include/mod_mail.h"

#include "nets/net_imap/imap.h"
#include "nets/net_imap/imap_client.h"

extern unsigned int maxuserproxies;

/*! \note Must be called locked */
static void client_link(struct imap_session *imap, struct imap_client *client)
{
	client->imap = imap;
	RWLIST_INSERT_TAIL(&imap->clients, client, entry);
}

static void client_destroy(struct imap_client *client)
{
	bbs_debug(5, "Destroying IMAP client %s\n", client->name);
	SWRITE(client->client.wfd, "bye LOGOUT\r\n"); /* This is optional, but be nice */
	bbs_tcp_client_cleanup(&client->client);
	free_if(client->virtlist);
	free(client);
}

static void client_unlink(struct imap_session *imap, struct imap_client *client)
{
	struct imap_client *c;

	RWLIST_WRLOCK(&imap->clients);
	c = RWLIST_REMOVE(&imap->clients, client, entry);
	RWLIST_UNLOCK(&imap->clients);

	if (c) {
		client_destroy(c);
	} else {
		bbs_error("Failed to unlink client %s\n", client->name);
	}
}

void imap_shutdown_clients(struct imap_session *imap)
{
	imap->client = NULL;
	RWLIST_WRLOCK_REMOVE_ALL(&imap->clients, entry, client_destroy);
}

/* XXX We may want to keep the connection alive, and just mark it as no longer the active one (e.g. imap->client = NULL) */
void imap_close_remote_mailbox(struct imap_session *imap)
{
	struct imap_client *client = imap->client;
	if (!client) {
		bbs_warning("Not currently a foreground outbound client connection\n");
		return;
	}
	/* Mark this connection as no longer active */
	imap->client = NULL;
	/* We ideally want to keep the connection alive for faster reuse if needed later. */
	if (maxuserproxies <= 1) {
		client_unlink(imap, client);
	}
}

static struct imap_client *client_new(const char *name)
{
	size_t len = strlen(name);
	struct imap_client *client;

	client = calloc(1, sizeof(*client) + len + 1);
	if (ALLOC_FAILURE(client)) {
		return client;
	}

	strcpy(client->data, name); /* Safe */
	client->virtprefix = client->name = client->data;
	client->virtprefixlen = len;
	client->client.fd = -1;
	return client;
}

/*! \brief Find or create the appropriate IMAP client session */
static struct imap_client *imap_client_get(struct imap_session *imap, const char *name, int *new)
{
	unsigned int current = 0;
	struct imap_client *client;

	if (!maxuserproxies) {
		bbs_warning("IMAP client proxy functionality is disabled\n");
		return NULL;
	}

	RWLIST_WRLOCK(&imap->clients);
	RWLIST_TRAVERSE_SAFE_BEGIN(&imap->clients, client, entry) {
		current++;
		if (!strcmp(name, client->name)) {
			*new = 0;
			bbs_debug(5, "Reusing existing client connection for %s\n", name);
			/* Make sure this connection is still live.
			 * If it was idle long enough, the remote IMAP server may have timed us out
			 * and closed the connection, in which case we need to close this and make a new one.
			 */
			/* We explicitly use fd, not rfd, in case it's using TLS, so we can
			 * query the actual TCP socket, not a pipe within the BBS,
			 * (which isn't serviced if it's not being used). */
			if (bbs_socket_pending_shutdown(client->client.fd)) {
				bbs_verb(4, "Proxied connection for %s has been closed by the remote peer, reopening\n", name);
				RWLIST_REMOVE_CURRENT(entry);
				client_destroy(client);
				client = NULL;
			}
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (!client) {
		while (current >= maxuserproxies) {
			/* We'll need to disconnect a connection in order to make room for this one. */
			bbs_debug(3, "Need to free up some client connections to make room for new connection\n");
			client = RWLIST_REMOVE_HEAD(&imap->clients, entry);
			bbs_assert_exists(client);
			client_destroy(client);
			current--;
		}
		client = client_new(name);
		if (ALLOC_FAILURE(client)) {
			RWLIST_UNLOCK(&imap->clients);
			return NULL;
		}
		/* We have to do this again, because the URL pointers are specific to the allocated memory */
		client_link(imap, client);
		*new = 1;
		bbs_debug(5, "Set up new client connection for %s\n", name);
	}
	RWLIST_UNLOCK(&imap->clients);

	return client;
}

static int my_imap_client_login(struct imap_client *client, struct bbs_url *url)
{
	struct bbs_tcp_client *tcpclient = &client->client;
	return imap_client_login(tcpclient, url, client->imap->node->user, &client->virtcapabilities);
}

struct imap_client *imap_client_get_by_url(struct imap_session *imap, const char *name, char *restrict urlstr)
{
	struct imap_client *client;
	struct bbs_url url;
	int secure, new;
	char *tmp;
	char buf[1024]; /* Must be large enough to get all the CAPABILITYs, or bbs_readline will throw a warning about buffer exhaustion and return 0 */

	memset(&url, 0, sizeof(url));
	if (bbs_parse_url(&url, urlstr)) {
		return NULL;
	} else if (!strcmp(url.prot, "imaps")) {
		secure = 1;
	} else if (strcmp(url.prot, "imap")) {
		bbs_warning("Unsupported protocol: %s\n", url.prot);
		return NULL;
	}

	client = imap_client_get(imap, name, &new);
	if (!client) {
		return NULL;
	} else if (!new) {
		/* XXX Maybe check to see if the connection is still alive/active?
		 * And if not, just fall through here and try to reconnect
		 * For example, we could issue a "NOOP" here to see if that works.
		 */
		return client;
	}

	/* Expect a URL like imap://user:password@imap.example.com:993/mailbox */
	memset(&client->client, 0, sizeof(client->client));
	if (bbs_tcp_client_connect(&client->client, &url, secure, buf, sizeof(buf))) {
		goto cleanup;
	}
	if (my_imap_client_login(client, &url)) {
		goto cleanup;
	}

	/* Need to determine the hierarchy delimiter on the remote server,
	 * so that we can make replacements as needed, including for SELECT.
	 * We do store this in the .imapremote.cache file,
	 * but that's not the file we opened.
	 * It's not stored in .imapremote itself.
	 * Simplest thing is just issue: a0 LIST "" ""
	 * which will return the hierarchy delimiter and not much else.
	 * Maybe not efficient in terms of network RTT,
	 * but we only do this once, when we login and setup the connection, so not too bad.
	 */
	IMAP_CLIENT_SEND(&client->client, "dlm LIST \"\" \"\"");
	IMAP_CLIENT_EXPECT(&client->client, "* LIST");
	/* Parse out the hierarchy delimiter */
	tmp = strchr(buf, '"');
	if (!tmp) {
		bbs_warning("Invalid LIST response: %s\n", buf);
		goto cleanup;
	}
	tmp++;
	if (strlen_zero(tmp)) {
		goto cleanup;
	}
	client->virtdelimiter = *tmp;
	bbs_debug(6, "Remote server's hierarchy delimiter is '%c'\n", client->virtdelimiter);
	IMAP_CLIENT_EXPECT(&client->client, "dlm OK");

	/* Enable any capabilities enabled by the client that the server supports */
	if (client->virtcapabilities & IMAP_CAPABILITY_ENABLE) {
		if (imap->qresync && (client->virtcapabilities & IMAP_CAPABILITY_QRESYNC)) {
			IMAP_CLIENT_SEND(&client->client, "cap0 ENABLE QRESYNC");
			IMAP_CLIENT_EXPECT(&client->client, "* ENABLED QRESYNC");
			IMAP_CLIENT_EXPECT(&client->client, "cap0 OK");
		} else if (imap->condstore && (client->virtcapabilities & IMAP_CAPABILITY_CONDSTORE)) {
			IMAP_CLIENT_SEND(&client->client, "cap0 ENABLE CONDSTORE");
			IMAP_CLIENT_EXPECT(&client->client, "* ENABLED CONDSTORE");
			IMAP_CLIENT_EXPECT(&client->client, "cap0 OK");
		}
	}

	return client;

cleanup:
	client_unlink(imap, client);
	return NULL;
}

static int client_command_passthru(struct imap_client *client, int fd, const char *tag, int taglen, const char *cmd, int cmdlen, int ms, int echo)
{
	int res;
	char buf[8192];
	struct pollfd pfds[2];
	int client_said_something = 0;
	struct imap_session *imap = client->imap;
	struct bbs_tcp_client *tcpclient = &client->client;

	/* We initialized bbs_readline with a NULL buffer, fix that: */
	tcpclient->rldata.buf = buf;
	tcpclient->rldata.len = sizeof(buf);

	pfds[0].fd = tcpclient->rfd;
	pfds[1].fd = fd;

	for (;;) {
		if (fd != -1) {
			res = bbs_multi_poll(pfds, 2, ms); /* If returns 1, client->rfd had activity, if 2, it was fd */
			if (res == 2) {
				char buf2[32];
				/* This is used during an IDLE. Passthru whatever we read to the client in return.
				 * We do not need actually need to parse this. If the client terminates an IDLE,
				 * then the server will respond "tag DONE" and we will detect that and exit normally.
				 * It is also true that for IDLE, the first input from the client should terminate anyways.
				 * So we check that below.
				 */
				client_said_something = 1;
				res = (int) read(fd, buf2, sizeof(buf2));
				if (res <= 0) {
					return -1; /* Client disappeared during idle / server shutdown */
				}
				imap_debug(10, "=> %.*s", res, buf2); /* "DONE" already includes CR LF */
				res = (int) write(tcpclient->wfd, buf2, (size_t) res);
				continue;
			}
			/* If client->rfd had activity, go ahead and just call bbs_readline.
			 * The internal poll it does will be superflous, of course. */
		}
		res = bbs_readline(tcpclient->rfd, &tcpclient->rldata, "\r\n", ms);
		if (res < 0) { /* Could include remote server disconnect */
			return res;
		}
		if (echo) {
			/* Go ahead and relay it */
			bbs_write(imap->wfd, buf, (unsigned int) res);
			SWRITE(imap->wfd, "\r\n");
		}
#ifdef DEBUG_REMOTE_RESPONSES
		/* NEVER enable this in production because this will be a huge volume of data */
		imap_debug(10, "<= %.*s\n", res, buf);
#endif
		if (!strncmp(buf, tag, (size_t) taglen)) {
			imap_debug(10, "<= %.*s\n", res, buf);
			if (STARTS_WITH(buf + taglen, "BAD")) {
				/* We did something we shouldn't have, oops */
				bbs_warning("Command '%.*s%.*s' failed: %s\n", taglen, tag, cmdlen > 2 ? cmdlen - 2 : cmdlen, cmd, buf); /* Don't include trailing CR LF */
			}
			break; /* That's all, folks! */
		}
		if (client_said_something) {
			bbs_warning("Client likely terminated IDLE, but loop has not exited\n");
		}
	}
	return res;
}

int __attribute__ ((format (gnu_printf, 6, 7))) __imap_client_send_wait_response(struct imap_client *client, int fd, int ms, int echo, int lineno, const char *fmt, ...)
{
	char *buf;
	int len, res;
	char tagbuf[15];
	int taglen;
	va_list ap;
	const char *tag = client->imap->tag;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	taglen = snprintf(tagbuf, sizeof(tagbuf), "%s ", tag); /* Reuse the tag the client sent us, so we can just passthrough the response */

	/* XXX If the remote server disconnected on us for some reason, these operations may succeed
	 * even if no data is sent.
	 * Handled in client_command_passthru */

#if 0
	/* Somewhat redundant since there's another debug right after */
	bbs_debug(6, "Passing through command %s (line %d) to remotely mapped '%s'\n", tag, lineno, client->virtprefix);
#else
	UNUSED(lineno);
#endif
	bbs_write(client->client.wfd, tagbuf, (unsigned int) taglen);
	bbs_write(client->client.wfd, buf, (unsigned int) len);
	imap_debug(7, "=> %s%s", tagbuf, buf);
	/* Read until we get the tagged respones */
	res = client_command_passthru(client, fd, tagbuf, taglen, buf, len, ms, echo) <= 0;
	free(buf);
	return res;
}

int imap_substitute_remote_command(struct imap_client *client, char *s)
{
	char *prefix;
	int len, lenleft, replacements = 0;
	char *curpos;

	if (strlen_zero(s)) {
		bbs_debug(5, "Command is empty, nothing to substitute\n");
		return 0;
	}

	/* This function is a generic one that replaces the local name for a remote (virtually mapped)
	 * mailbox with the name of the mailbox on that system, suitable for sending to it.
	 * This means that we can passthru commands generically after modification
	 * without being concerned with the semantics/syntax of the command itself. */

	/* The remote command should always be *shorter* than the local one, because we're merely removing the prefix, wherever it may occur.
	 * This allows us to do this in place, using memmove. */
	len = (int) strlen(s);
	curpos = s;
	while ((prefix = strstr(curpos, client->virtprefix))) {
		char *end = prefix + client->virtprefixlen;
		if (*end != HIERARCHY_DELIMITER_CHAR) {
			bbs_warning("Unexpected character at pos: %d\n", *end);
			continue;
		}

		/* While we're doing this, convert the hierarchy delimiter as well.
		 * This can be done in place, thankfully.
		 * Go until we get a space or an end quote, signaling the end of the mailbox name.
		 * But if the mailbox name contains spaces, then we must NOT stop there
		 * since there could be more remaining... so we should only stop on spaces
		 * if the mailbox name STARTED with a quote.
		 */
		if (client->virtdelimiter != HIERARCHY_DELIMITER_CHAR) { /* Wouldn't hurt anything to always do, but why bother? */
			int mailbox_has_spaces;
			char *tmp = end + 1;
			if (prefix != s) { /* Bounds check: don't go past the beginning of the string */
				mailbox_has_spaces = *(prefix - 1) == '"';
			} else {
				mailbox_has_spaces = 0;
			}
			while (*tmp) {
				if (*tmp == HIERARCHY_DELIMITER_CHAR) {
					*tmp = client->virtdelimiter;
				} else if (*tmp == '"') {
					break;
				} else if (!mailbox_has_spaces && *tmp == ' ') {
					break;
				}
				tmp++;
			}
		}

		replacements++;
		len -= (int) client->virtprefixlen + 1; /* plus period */
		lenleft = len - (int) (prefix - s);
		memmove(prefix, end + 1, (size_t) lenleft);
		prefix[lenleft] = '\0';
		curpos = prefix; /* Start where we left off, not at the beginning of the string */
	}
	bbs_debug(5, "Substituted remote command to: '%s'\n", s);
	return replacements;
}

struct imap_client *load_virtual_mailbox(struct imap_session *imap, const char *path, int *exists)
{
	FILE *fp;
	char virtcachefile[256];
	char buf[256];

	if (imap->client) {
		/* Reuse the same connection if it's the same account. */
		if (!strncmp(imap->client->virtprefix, path, imap->client->virtprefixlen)) {
			bbs_debug(5, "Reusing existing active connection for %s\n", path);
			*exists = 1;
			return imap->client;
		}
		/* An optimization here is if the remote server supports the UNAUTHENTICATE capability,
		 * we can reuse the connection instead of establishing a new one
		 * (if it's the same server (hostname), but different user/account)
		 * Unfortunately, no major providers support the UNAUTHENTICATE extension,
		 * so this wouldn't help much at the moment, but would be nice to some day (assuming support exists).
		 * Also, now that we support concurrent connections, there'd be no reason to do this,
		 * since we'd have to keep logging out and back in. Just use a new connection.
		 */
		imap_close_remote_mailbox(imap);
	}

	*exists = 0;
	snprintf(virtcachefile, sizeof(virtcachefile), "%s/.imapremote", mailbox_maildir(imap->mymbox));
	fp = fopen(virtcachefile, "r");
	if (!fp) {
		return NULL;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		char *mpath, *urlstr = buf;
		size_t prefixlen;
		mpath = strsep(&urlstr, "|");
		/* We are not looking for an exact match.
		 * Essentially, the user defines a "subtree" in the .imapremote file,
		 * and anything under this subtree should match.
		 * It doesn't matter if the actual desired mailbox doesn't exist on the remote server,
		 * that's not our problem, and the client will discover that when doing a SELECT.
		 */

		if (strlen_zero(urlstr)) {
			continue; /* Illegitimate */
		}

		/* Instead of doing prefixlen = strlen(mpath), we can just subtract the pointers */
		prefixlen = (size_t) (urlstr - mpath - 1); /* Subtract 1 for the space between. */
		if (!strncmp(mpath, path, prefixlen)) {
			struct imap_client *client = imap_client_get_by_url(imap, mpath, urlstr);
			*exists = 1;
			bbs_memzero(urlstr, strlen(urlstr)); /* Contains password */
			if (!client) {
				break;
			}
			fclose(fp);
			return client;
		}
	}
	fclose(fp);
	return NULL;
}

char *remote_mailbox_name(struct imap_client *client, char *restrict mailbox)
{
	char *tmp, *remotename = mailbox + client->virtprefixlen + 1;
	/* This is some other server's problem to handle.
	 * Just forward the request (after modifying the mailbox name as appropriate, to remove the prefix + following period). */
	/* Also need to adjust for hierarchy delimiter being different, potentially.
	 * Typically imap_substitute_remote_command handles this, but for SELECT we go ahead and send the name directly,
	 * so do what's needed here. The conversion logic here is a lot simpler anyways, since we know we just have
	 * a mailbox name and not an entire command to convert.
	 * XXX What if we ever want to support SELECT commands that contain more than just a mailbox?
	 */
	tmp = mailbox + client->virtprefixlen + 1;
	while (*tmp) {
		if (*tmp == HIERARCHY_DELIMITER_CHAR) {
			*tmp = client->virtdelimiter;
		}
		tmp++;
	}
	return remotename;
}
