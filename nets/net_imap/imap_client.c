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

void imap_close_remote_mailbox(struct imap_session *imap)
{
	bbs_assert(imap->virtmbox == 1);
	bbs_debug(6, "Closing remote mailbox\n");
	SWRITE(imap->client.wfd, "bye LOGOUT\r\n"); /* This is optional, but be nice */
	bbs_tcp_client_cleanup(&imap->client);
	imap->virtmbox = 0;
}

static int client_command_passthru(struct imap_session *imap, int fd, const char *tag, int taglen, const char *cmd, int cmdlen, int ms, int echo)
{
	int res;
	char buf[8192];
	struct pollfd pfds[2];
	int client_said_something = 0;
	struct bbs_tcp_client *client = &imap->client;

	/* We initialized bbs_readline with a NULL buffer, fix that: */
	client->rldata.buf = buf;
	client->rldata.len = sizeof(buf);

	pfds[0].fd = client->rfd;
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
				res = (int) write(client->wfd, buf2, (size_t) res);
				continue;
			}
			/* If client->rfd had activity, go ahead and just call bbs_readline.
			 * The internal poll it does will be superflous, of course. */
		}
		res = bbs_readline(client->rfd, &client->rldata, "\r\n", ms);
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

int my_imap_client_login(struct bbs_tcp_client *client, struct bbs_url *url, struct imap_session *imap)
{
	return imap_client_login(client, url, imap->node->user, &imap->virtcapabilities);
}

int __attribute__ ((format (gnu_printf, 6, 7))) __imap_client_send_wait_response(struct imap_session *imap, int fd, int ms, int echo, int lineno, const char *fmt, ...)
{
	char *buf;
	int len, res;
	char tagbuf[15];
	int taglen;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	taglen = snprintf(tagbuf, sizeof(tagbuf), "%s ", imap->tag); /* Reuse the tag the client sent us, so we can just passthrough the response */

	/* XXX If the remote server disconnected on us for some reason, these operations may succeed
	 * even if no data is sent.
	 * Handled in client_command_passthru */

#if 0
	/* Somewhat redundant since there's another debug right after */
	bbs_debug(6, "Passing through command %s (line %d) to remotely mapped '%s'\n", imap->tag, lineno, imap->virtprefix);
#else
	UNUSED(lineno);
#endif
	bbs_write(imap->client.wfd, tagbuf, (unsigned int) taglen);
	bbs_write(imap->client.wfd, buf, (unsigned int) len);
	imap_debug(7, "=> %s%s", tagbuf, buf);
	/* Read until we get the tagged respones */
	res = client_command_passthru(imap, fd, tagbuf, taglen, buf, len, ms, echo) <= 0;
	free(buf);
	return res;
}

int imap_substitute_remote_command(struct imap_session *imap, char *s)
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
	while ((prefix = strstr(curpos, imap->virtprefix))) {
		char *end = prefix + imap->virtprefixlen;
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
		if (imap->virtdelimiter != HIERARCHY_DELIMITER_CHAR) { /* Wouldn't hurt anything to always do, but why bother? */
			int mailbox_has_spaces;
			char *tmp = end + 1;
			if (prefix != s) { /* Bounds check: don't go past the beginning of the string */
				mailbox_has_spaces = *(prefix - 1) == '"';
			} else {
				mailbox_has_spaces = 0;
			}
			while (*tmp) {
				if (*tmp == HIERARCHY_DELIMITER_CHAR) {
					*tmp = imap->virtdelimiter;
				} else if (*tmp == '"') {
					break;
				} else if (!mailbox_has_spaces && *tmp == ' ') {
					break;
				}
				tmp++;
			}
		}

		replacements++;
		len -= (int) imap->virtprefixlen + 1; /* plus period */
		lenleft = len - (int) (prefix - s);
		memmove(prefix, end + 1, (size_t) lenleft);
		prefix[lenleft] = '\0';
		curpos = prefix; /* Start where we left off, not at the beginning of the string */
	}
	bbs_debug(5, "Substituted remote command to: '%s'\n", s);
	return replacements;
}

int load_virtual_mailbox(struct imap_session *imap, const char *path)
{
	FILE *fp;
	int res = -1;
	char virtcachefile[256];
	char buf[256];

	if (imap->virtmbox) {
		/* Reuse the same connection if it's the same account. */
		if (!strncmp(imap->virtprefix, path, imap->virtprefixlen)) {
			bbs_debug(6, "Reusing existing connection for %s\n", path);
			return 0;
		}
		/* If it's to a different server, tear down the existing connection first. */
		/* XXX An optimization here is if the remote server supports the UNAUTHENTICATE capability,
		 * we can reuse the connection instead of tearing it down and building a new one
		 * (if it's the same server (hostname), but different user/account)
		 * Unfortunately, no major providers support the UNAUTHENTICATE extension,
		 * so this wouldn't help much at the moment, but would be nice to some day (assuming support exists). */
		imap_close_remote_mailbox(imap);
	}

	free_if(imap->virtlist); /* Any cached LIST-STATUS response is no longer relevant */

	snprintf(virtcachefile, sizeof(virtcachefile), "%s/.imapremote", mailbox_maildir(imap->mymbox));
	fp = fopen(virtcachefile, "r");
	if (!fp) {
		return -1;
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
			struct bbs_url url;
			char tmpbuf[1024];
			char *tmp;
			memset(&url, 0, sizeof(url));
			if (bbs_parse_url(&url, urlstr)) {
				break;
			}
			bbs_assert(!imap->virtmbox); /* Shouldn't be a client left, or it'll leak here */
			memset(&imap->client, 0, sizeof(imap->client));
			if (bbs_tcp_client_connect(&imap->client, &url, !strcmp(url.prot, "imaps"), tmpbuf, sizeof(tmpbuf))) {
				res = 1;
				break;
			}
			if (my_imap_client_login(&imap->client, &url, imap)) {
				goto cleanup;
			}
			imap->virtmbox = 1;
			safe_strncpy(imap->virtprefix, mpath, sizeof(imap->virtprefix));
			imap->virtprefixlen = prefixlen;

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
			IMAP_CLIENT_SEND(&imap->client, "dlm LIST \"\" \"\"");
			IMAP_CLIENT_EXPECT(&imap->client, "* LIST");
			/* Parse out the hierarchy delimiter */
			tmp = strchr((&imap->client)->buf, '"');
			if (!tmp) {
				bbs_warning("Invalid LIST response: %s\n", (&imap->client)->buf);
				goto cleanup;
			}
			tmp++;
			if (strlen_zero(tmp)) {
				goto cleanup;
			}
			imap->virtdelimiter = *tmp;
			bbs_debug(6, "Remote server's hierarchy delimiter is '%c'\n", imap->virtdelimiter);
			IMAP_CLIENT_EXPECT(&imap->client, "dlm OK");

			/* Enable any capabilities enabled by the client that the server supports */
			if (imap->virtcapabilities & IMAP_CAPABILITY_ENABLE) {
				if (imap->qresync && (imap->virtcapabilities & IMAP_CAPABILITY_QRESYNC)) {
					IMAP_CLIENT_SEND(&imap->client, "cap0 ENABLE QRESYNC");
					IMAP_CLIENT_EXPECT(&imap->client, "* ENABLED QRESYNC");
					IMAP_CLIENT_EXPECT(&imap->client, "cap0 OK");
				} else if (imap->condstore && (imap->virtcapabilities & IMAP_CAPABILITY_CONDSTORE)) {
					IMAP_CLIENT_SEND(&imap->client, "cap0 ENABLE CONDSTORE");
					IMAP_CLIENT_EXPECT(&imap->client, "* ENABLED CONDSTORE");
					IMAP_CLIENT_EXPECT(&imap->client, "cap0 OK");
				}
			}

			res = 0;
			break;
cleanup:
			res = 1;
			bbs_tcp_client_cleanup(&imap->client);
			break;
		}
	}
	fclose(fp);
	return res;
}

char *remote_mailbox_name(struct imap_session *imap, char *restrict mailbox)
{
	char *tmp, *remotename = mailbox + imap->virtprefixlen + 1;
	/* This is some other server's problem to handle.
	 * Just forward the request (after modifying the mailbox name as appropriate, to remove the prefix + following period). */
	/* Also need to adjust for hierarchy delimiter being different, potentially.
	 * Typically imap_substitute_remote_command handles this, but for SELECT we go ahead and send the name directly,
	 * so do what's needed here. The conversion logic here is a lot simpler anyways, since we know we just have
	 * a mailbox name and not an entire command to convert.
	 * XXX What if we ever want to support SELECT commands that contain more than just a mailbox?
	 */
	tmp = mailbox + imap->virtprefixlen + 1;
	while (*tmp) {
		if (*tmp == HIERARCHY_DELIMITER_CHAR) {
			*tmp = imap->virtdelimiter;
		}
		tmp++;
	}
	return remotename;
}
