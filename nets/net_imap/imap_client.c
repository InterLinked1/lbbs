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
#include "include/user.h"
#include "include/transfer.h"

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
	if (!client->dead) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
		SWRITE(client->client.wfd, "bye LOGOUT\r\n"); /* This is optional, but be nice */
#pragma GCC diagnostic pop
	}
	bbs_tcp_client_cleanup(&client->client);
	free_if(client->virtlist);
	free_if(client->bgmailbox);
	free(client);
}

void imap_client_unlink(struct imap_session *imap, struct imap_client *client)
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

int imap_poll(struct imap_session *imap, int ms, struct imap_client **clientout)
{
	struct pollfd *pfds;
	nfds_t numfds;
	int res = -1;
	struct imap_client *client;

	*clientout = NULL;

	/* Poll the IMAP session and all clients */
	RWLIST_RDLOCK(&imap->clients); /* Okay to read lock, nobody else is using this for the duration of this function */
	numfds = (nfds_t) RWLIST_SIZE(&imap->clients, client, entry);
	numfds++; /* Plus the main session itself (our client) */

	bbs_debug(5, "Polling %lu fd%s for IMAP session %p (for %ds)\n", numfds, ESS(numfds), imap, ms / 1000);

	if (numfds == 1) {
		/* No remote clients, just the main client */
		RWLIST_UNLOCK(&imap->clients);
		return bbs_poll(imap->rfd, ms);
	}

	pfds = calloc(numfds, sizeof(*pfds));
	if (ALLOC_FAILURE(pfds)) {
		goto cleanup;
	}

	for (;;) {
		int pres, i = 0;
		pfds[i].events = POLLIN;
		pfds[i].revents = 0;
		pfds[i].fd = imap->rfd;
		RWLIST_TRAVERSE(&imap->clients, client, entry) {
			i++;
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
			pfds[i].fd = client->client.rfd;
		}
		pres = poll(pfds, numfds, ms);
		if (pres < 0) {
			if (errno == EINTR) {
				continue;
			}
			bbs_warning("poll failed: %s\n", strerror(errno));
			break;
		} else if (pres == 0) {
			res = 0;
			break;
		}
		/* Something got activity! Time to service it. */
		res = 1;
		i = 0;
		if (pfds[i].revents) {
			bbs_debug(8, "IMAP poll returned %d for main IMAP client\n", pres);
			break;
		}
		RWLIST_TRAVERSE(&imap->clients, client, entry) {
			i++;
			if (pfds[i].revents) {
				*clientout = client;
				bbs_debug(8, "IMAP poll returned %d for remote IMAP client %s\n", pres, client->virtprefix);
				goto cleanup; /* Can't break in double loop */
			}
		}
	}

cleanup:
	free(pfds);
	RWLIST_UNLOCK(&imap->clients);
	return res;
}

int imap_client_idle_start(struct imap_client *client)
{
	/* Now, IDLE on it so we get updates for that mailbox */
	if (SWRITE(client->client.wfd, "idle IDLE\r\n") < 0) {
		return -1;
	}
	if (bbs_tcp_client_expect(&client->client, "\r\n", 1, SEC_MS(3), "+")) {
		bbs_warning("Failed to start IDLE\n");
		return -1;
	}
	client->idling = 1;
	client->idlestarted = (int) time(NULL);
	return 0;
}

int imap_client_idle_stop(struct imap_client *client)
{
	if (SWRITE(client->client.wfd, "DONE\r\n") < 0) {
		return -1;
	}
	/* There could be some untagged updates sent that we're just seeing now, be tolerant of receiving a few of those */
	if (bbs_tcp_client_expect(&client->client, "\r\n", 10, SEC_MS(3), "idle OK")) { /* tagged OK response */
		bbs_warning("Failed to terminate IDLE for %s\n", client->virtprefix);
		return -1;
	}
	client->idling = 0;
	return 0;
}

int imap_clients_next_idle_expiration(struct imap_session *imap)
{
	int min_maxage = 0;
	struct imap_client *client;
	int now = (int) time(NULL);

	/* Renew all the IDLEs on remote servers, periodically,
	 * to keep the IMAP connection alive. */

	RWLIST_RDLOCK(&imap->clients);
	RWLIST_TRAVERSE(&imap->clients, client, entry) {
		int maxage;
		if (!client->idling) {
			continue;
		}
		/* This is when the connection may be terminated.
		 * We need to renew the connection BEFORE then. */
		maxage = client->idlestarted + client->maxidlesec;
		if (!min_maxage || maxage < min_maxage) {
			min_maxage = maxage;
		}
	}
	RWLIST_UNLOCK(&imap->clients);
	if (min_maxage) {
		min_maxage = min_maxage - now;
		if (min_maxage < 0) {
			bbs_warning("Next expiration is in the past? (%ds ago)\n", min_maxage);
		}
	}
	return min_maxage;
}

void imap_clients_renew_idle(struct imap_session *imap)
{
	struct imap_client *client;
	int now = (int) time(NULL);

	/* Renew all the IDLEs on remote servers, periodically,
	 * to keep the IMAP connection alive. */

	RWLIST_WRLOCK(&imap->clients);
	RWLIST_TRAVERSE_SAFE_BEGIN(&imap->clients, client, entry) {
		int maxage;
		if (!client->idling) {
			continue;
		}
		/* This is when the connection may be terminated.
		 * We need to renew the connection BEFORE then. */
		maxage = client->idlestarted + client->maxidlesec;
		/* If we're not going to call this function to check for renewals before it's due to expire, renew it now */
		if (maxage < now + 15) { /* Add a little bit of wiggle room */
			int age = now - client->idlestarted;
			bbs_debug(4, "Client '%s' needs to renew IDLE (%d/%d s elapsed)...\n", client->virtprefix, age, client->maxidlesec);
			if (imap_client_idle_stop(client) || imap_client_idle_start(client)) {
				client->dead = 1;
				if (imap->client != client) {
					RWLIST_REMOVE_CURRENT(entry);
					client_destroy(client);
				}
				continue;
			}
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&imap->clients);
}

void imap_client_idle_notify(struct imap_client *client)
{
	char mailbox[128];

	if (client->idling) {
		bbs_warning("Already idling on %s?\n", client->virtprefix);
		return;
	}

	bbs_debug(6, "Checking if we should background IDLE for %s...\n", client->virtprefix);

	/* Even if NOTIFY is not enabled by the client currently,
	 * the client may enable it in the future.
	 * Therefore, just because !client->imap->notify doesn't mean we shouldn't bother. */

	/* To emulate NOTIFY support (in a way) for remote mailboxes,
	 * what we can do is, if the client has expressed interest
	 * in being notified of updates to a folder on this server,
	 * do an IDLE on that folder in the background.
	 * (This will only work for one folder at a time, so the INBOX
	 * takes precedence if more than one folder is specified.)
	 * Then, if we detect an update while our client is idling,
	 * we can read the update and then do a STATUS if necessary
	 * and pass that to our client. This way, it more or less
	 * feels like a native NOTIFY to our client, although it only
	 * works on only one remote folder on each server. In practice,
	 * this limitation may be fine as usually only the INBOX is worth watching.
	 *
	 * XXX Also, we could also do a direct NOTIFY downstream to the remote server,
	 * if supported, but almost no providers support NOTIFY anyways,
	 * whereas IDLE is pretty universal so this fallback is more important. */
	if (!(client->virtcapabilities & IMAP_CAPABILITY_IDLE)) {
		bbs_warning("Remote IMAP server does not support IDLE, lame...\n");
		return;
	}

	/* XXX Currently we are hardcoded to just monitor the INBOX.
	 * Not really much else we can do without either:
	 * a) The remote server also supporting NOTIFY (fat chance)
	 * b) Opening a separate TCP connection for every single mailbox and idling on it (yikes!)
	 */

	/* Determine what mailbox we'll monitor remotely.
	 * XXX Currently just hardcoded to prefer the INBOX. */
	snprintf(mailbox, sizeof(mailbox), "%s%c%s", client->virtprefix, HIERARCHY_DELIMITER_CHAR, "INBOX");

	/* Do not check if NOTIFY is enabled using imap_notify_applicable.
	 * The client might not have enabled NOTIFY yet,
	 * and this may not be safe to call if imap->notify is NULL.
	 * We check if NOTIFY applies to this mailbox inside handle_idle itself. */

	/* First, select the mailbox for which we want NOTIFY updates.
	 * Use EXAMINE as that should hopefully preserve \Recent flags too. */
	if (imap_client_send_wait_response_noecho(client, -1, SEC_MS(5), "EXAMINE \"%s\"\r\n", "INBOX")) { /* remote name */
		bbs_warning("Failed to EXAMINE '%s'\n", mailbox);
	}

	/* Now, IDLE on it so we get updates for that mailbox */
	if (!imap_client_idle_start(client)) {
		bbs_debug(5, "Set up background IDLE for '%s'\n", mailbox);
		REPLACE(client->bgmailbox, mailbox);
	}
}

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
		imap_client_unlink(imap, client);
	} else {
		imap_client_idle_notify(client);
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

static ssize_t client_command_passthru(struct imap_client *client, int fd, const char *tag, int taglen, const char *cmd, int cmdlen, int ms, int echo, int (*cb)(struct imap_client *client, const char *buf, size_t len, void *cbdata), void *cbdata)
{
	ssize_t res;
	struct pollfd pfds[2];
	int client_said_something = 0;
	int c = 0;
	struct imap_session *imap = client->imap;
	struct bbs_tcp_client *tcpclient = &client->client;

	pfds[0].fd = tcpclient->rfd;
	pfds[1].fd = fd;

	for (;;) {
		int cbres = 0;
		char *buf = client->buf;
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
				imap_debug(10, "=> %.*s", (int) res, buf2); /* "DONE" already includes CR LF */
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
		if (cb) {
			cbres = cb(client, buf, (size_t) res, cbdata);
			if (cbres < 0) {
				res = -1;
				break;
			}
		}
		if (echo) {
			/* Go ahead and relay it */
			if (res > 0) { /* If it was just an empty line, don't bother calling write() with 0 bytes */
				bbs_write(imap->wfd, buf, (unsigned int) res);
			}
			if (SWRITE(imap->wfd, "\r\n") < 0) {
				res = -1;
				break;
			}
		}
#ifdef DEBUG_REMOTE_RESPONSES
		/* NEVER enable this in production because this will be a huge volume of data */
		imap_debug(10, "<= %.*s\n", (int) res, buf);
#else
		if (c++ < 15 && res > 2 && !strncmp(buf, "* ", STRLEN("* "))) {
			imap_debug(7, "<= %.*s\n", (int) res, buf);
		}
#endif
		if (!strncmp(buf, tag, (size_t) taglen)) {
			imap_debug(10, "<= %.*s\n", (int) res, buf);
			if (STARTS_WITH(buf + taglen, "BAD")) {
				/* We did something we shouldn't have, oops */
				bbs_warning("Command '%.*s%.*s' failed: %s\n", taglen, tag, cmdlen > 2 ? cmdlen - 2 : cmdlen, cmd, buf); /* Don't include trailing CR LF */
			}
			client->lastactive = (int) time(NULL); /* Successfully just got data from remote server */
			break; /* That's all, folks! */
		}
		if (client_said_something) {
			bbs_warning("Client likely terminated IDLE, but loop has not exited\n");
		}
	}
	return res;
}

ssize_t __imap_client_send_log(struct imap_client *client, int log, const char *fmt, ...)
{
	char buf[1024]; /* IMAP commands shouldn't be longer than this anyways */
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len >= (int) sizeof(buf)) {
		bbs_warning("Truncation occured writing %d bytes to buffer of size %lu\n", len, sizeof(buf));
		return -1;
	}

	if (log) {
		bbs_debug(3, "%p => %.*s", client, len, buf);
	}

	return bbs_write(client->client.wfd, buf, (size_t) len);
}

int __imap_client_send_wait_response(struct imap_client *client, int fd, int ms, int echo, int lineno, int (*cb)(struct imap_client *client, const char *buf, size_t len, void *cbdata), void *cbdata, const char *fmt, ...)
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
	res = client_command_passthru(client, fd, tagbuf, taglen, buf, len, ms, echo, cb, cbdata) <= 0;
	free(buf);
	return res;
}

/*!
 * \brief Check to ensure a connection is still alive
 * \retval 0 if still alive, -1 if not
 */
static int imap_client_keepalive_check(struct imap_client *client)
{
	struct bbs_tcp_client *tcpclient = &client->client;
	int res = imap_client_send_wait_response_noecho(client, -1, SEC_MS(2), "NOOP\r\n"); /* Yeah, this will result in tag reuse... */
	if (res) {
		bbs_warning("Reuse keepalive check failed\n");
		return -1;
	}
	if (bbs_socket_pending_shutdown(tcpclient->fd)) {
		bbs_verb(4, "Proxied connection for %s has been closed by the remote peer\n", client->name);
		return -1;
	}
	return 0; /* Seems to still be alive and well */
}

static int connection_stale(struct imap_client *client)
{
	int now;
	struct bbs_tcp_client *tcpclient = &client->client;

	/* If it's running an IDLE in the background, stop it */
	if (client->idling) {
		if (imap_client_idle_stop(client)) {
			return -1;
		}
		bbs_debug(5, "Successfully stopped background IDLE on client, reusing\n");
		return 0;
	}

	/* Make sure this connection is still live.
	 * If it was idle long enough, the remote IMAP server may have timed us out
	 * and closed the connection, in which case we need to close this and make a new one.
	 * Even if we weren't idling very long, the server could have closed the connection
	 * at any point for any reason.
	 */

	/* We explicitly use fd, not rfd, in case it's using TLS, so we can
	 * query the actual TCP socket, not a pipe within the BBS,
	 * (which isn't serviced if it's not being used). */
	if (bbs_socket_pending_shutdown(tcpclient->fd)) {
		bbs_verb(4, "Proxied connection for %s has been closed by the remote peer, reconnecting\n", client->name);
		return -1;
	}

	/* It could still be the case that this socket is no longer usable, because as soon as try to use it,
	 * it will disconnect on us. So explicitly send a NOOP and see if we get a response.
	 * Because this check adds an additional RTT, only do this if we haven't heard from the server super recently.
	 * If we have, then this is just unnecessary. */
	now = (int) time(NULL);
	if (now < client->lastactive + 10) {
		bbs_debug(5, "Received output from remote server within last 10 seconds, fast reuse\n");
		return 0; /* Should be okay to reuse without doing an explicit keep alive check */
	}
	return imap_client_keepalive_check(client);
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
			if (connection_stale(client)) {
				RWLIST_REMOVE_CURRENT(entry);
				client->dead = 1;
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
	char *tmp, *buf;

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
		return client;
	}

	/* Expect a URL like imap://user:password@imap.example.com:993/mailbox */
	memset(&client->client, 0, sizeof(client->client));
	if (bbs_tcp_client_connect(&client->client, &url, secure, client->buf, sizeof(client->buf))) {
		goto cleanup;
	}
	if (my_imap_client_login(client, &url)) {
		goto cleanup;
	}

	/* Need to determine the hierarchy delimiter on the remote server,
	 * so that we can make replacements as needed, including for SELECT.
	 * This is not stored in .imapremote itself.
	 * Simplest thing is just issue: a0 LIST "" ""
	 * which will return the hierarchy delimiter and not much else.
	 * Maybe not efficient in terms of network RTT,
	 * but we only do this once, when we login and setup the connection, so not too bad.
	 */
	IMAP_CLIENT_SEND(&client->client, "dlm LIST \"\" \"\"");
	IMAP_CLIENT_EXPECT(&client->client, "* LIST");
	/* Parse out the hierarchy delimiter */
	buf = client->buf;
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

	/* Yandex explicitly violates RFC 3501 5.4, which
	 * specifies inactivity timers MUST be at least 30 minutes.
	 * With Yandex, if a mailbox is not selected, it'll
	 * disconnect you after about 2 minutes and 45 seconds.
	 *
	 * In theory, this should not be an issue as it's transparent
	 * to the user: if the connection is dead the next time we need it,
	 * we can just make a new one. It just worsens performance,
	 * and means users won't receive IDLE/NOTIFY notifications for those accounts,
	 * so it's good to keep alive if possible...
	 */
	if (!strcmp(url.host, "imap.yandex.com")) {
		client->maxidlesec = 120; /* 2 minutes */
	} else {
		client->maxidlesec = 1800; /* 30 minutes */
	}

	client->lastactive = (int) time(NULL); /* Mark as active since we just successfully did I/O with it */
	return client;

cleanup:
	imap_client_unlink(imap, client);
	return NULL;
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

int imap_client_mapping_file(struct imap_session *imap, char *buf, size_t len)
{
	return bbs_transfer_home_config_file(imap->node->user->id, ".imapremote", buf, len);
}

static struct imap_client *__load_virtual_mailbox(struct imap_session *imap, const char *path, int *exists, int load, int prefixonly)
{
	FILE *fp;
	char virtcachefile[256];
	char buf[256];
	size_t pathlen;

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
	}

	if (prefixonly) {
		pathlen = strlen(path);
	}

	*exists = 0;
	if (imap_client_mapping_file(imap, virtcachefile, sizeof(virtcachefile))) {
		return NULL;
	}
	fp = fopen(virtcachefile, "r");
	if (!fp) {
		return NULL;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		char *mpath, *urlstr = buf;
		size_t prefixlen, urlstrlen;
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
		urlstrlen = strlen(urlstr);
		if (prefixonly && !strncmp(path, mpath, pathlen)) {
			fclose(fp);
			*exists = 1;
			return NULL;
		}
		if (!strncmp(mpath, path, prefixlen)) {
			struct imap_client *client = NULL;

			/* XXX This is most strange.
			 * This shouldn't matter, but if this fclose occurs AFTER imap_client_get_by_url,
			 * and we end up recreating the client (because it's stale, connection timed out, etc.)
			 * it will mess up the new client's TCP connection, and the next time we try to use the
			 * socket, we'll get a POLLHUP.
			 * i.e. before fclose it works perfectly fine, and after fclose, the socket returns POLLHUP.
			 * Mind you, this is a shiny, brand new socket that we just created and successfully read from and wrote to!
			 * This is pretty obvious code smell, but valgrind doesn't pick anything up,
			 * and in theory we can do an fclose immediately too, so this works fine,
			 * I'm not just not satisfied that I can't explain why we need to do this here.
			 */
			fclose(fp);

			*exists = 1;
			if (load) {
				client = imap_client_get_by_url(imap, mpath, urlstr);
			}
			bbs_memzero(urlstr, urlstrlen); /* Contains password */
			return client;
		} else {
			bbs_memzero(urlstr, urlstrlen); /* Contains password */
		}
	}
	fclose(fp);
	return NULL;
}

struct imap_client *load_virtual_mailbox(struct imap_session *imap, const char *path, int *exists)
{
	return __load_virtual_mailbox(imap, path, exists, 1, 0);
}

int mailbox_remotely_mapped(struct imap_session *imap, const char *path)
{
	int exists = 0;
	__load_virtual_mailbox(imap, path, &exists, 0, 1);
	return exists;
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
