/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023-2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Transport Layer Security (TLS)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <poll.h>

#include <openssl/opensslv.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "include/module.h"
#include "include/node.h"
#include "include/linkedlists.h"
#include "include/config.h"
#include "include/alertpipe.h"
#include "include/utils.h"
#include "include/event.h"
#include "include/cli.h"
#include "include/reload.h"

/* This path is configurable, since it varies by distro.
 * e.g. See: https://go.dev/src/crypto/x509/root_linux.go */
static char root_certs[84] = "/etc/ssl/certs/ca-certificates.crt";
static char ssl_cert[256] = "";
static char ssl_key[256] = "";

static SSL_CTX *ssl_ctx = NULL;

static int ssl_is_available = 0;
static int ssl_shutting_down = 0;

static bbs_mutex_t *lock_cs = NULL;
static long *lock_count = NULL;

static void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
#ifdef DEBUG_TLS_LOCKING
	bbs_debug(3,"mode=%s lock=%s %s:%d\n", (mode & CRYPTO_LOCK) ? "l" : "u", (type & CRYPTO_READ) ? "r" : "w", file, line);
#else
	UNUSED(file);
	UNUSED(line);
#endif
	if (mode & CRYPTO_LOCK) {
		bbs_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		bbs_mutex_unlock(&(lock_cs[type]));
	}
}

static int lock_init(void)
{
	int i;
	/* OpenSSL crypto/threads/mttest.c */
	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(bbs_mutex_t));
	if (ALLOC_FAILURE(lock_cs)) {
		return -1;
	}
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	if (ALLOC_FAILURE(lock_count)) {
		OPENSSL_free(lock_cs);
		return -1;
	}
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		bbs_mutex_init(&(lock_cs[i]), NULL);
	}
	CRYPTO_set_locking_callback(pthreads_locking_callback);
	if (0) {
		/* XXX FIXME For some reason, CRYPTO_set_locking_callback doesn't count as using pthreads_locking_callback,
		 * so we have this dummy usage that the compiler will optimize out. Something else is probably not right... */
		pthreads_locking_callback(0, 0, NULL, 0);
	}
	return 0;
}

static void lock_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		bbs_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
}

struct sni {
	const char *hostname;		/*!< SNI hostname */
	SSL_CTX *ctx;
	RWLIST_ENTRY(sni) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(sni_certs, sni);

/*! \note Must be called with WRLOCK held */
static void sni_push(const char *hostname, SSL_CTX *ctx)
{
	struct sni *sni;
	size_t hostlen = strlen(hostname);
	sni = calloc(1, sizeof(*sni) + hostlen + 1);
	if (ALLOC_FAILURE(sni)) {
		return;
	}
	sni->ctx = ctx;
	strcpy(sni->data, hostname); /* Safe */
	sni->hostname = sni->data;
	RWLIST_INSERT_HEAD(&sni_certs, sni, entry);
	bbs_verb(5, "Added TLS certificate for %s\n", hostname);
}

/*! \note Must be called with WRLOCK held */
static void sni_free(struct sni *sni)
{
	SSL_CTX_free(sni->ctx);
	free(sni);
}

/*! \todo is there an OpenSSL function for this? */
static const char *ssl_strerror(int err)
{
	switch (err) {
	case SSL_ERROR_NONE:
		return "SSL_ERROR_NONE";
	case SSL_ERROR_ZERO_RETURN:
		return "SSL_ERROR_ZERO_RETURN";
	case SSL_ERROR_WANT_READ:
		return "SSL_ERROR_WANT_READ";
	case SSL_ERROR_WANT_WRITE:
		return "SSL_ERROR_WANT_WRITE";
	case SSL_ERROR_WANT_CONNECT:
		return "SSL_ERROR_WANT_CONNECT";
	case SSL_ERROR_WANT_ACCEPT:
		return "SSL_ERROR_WANT_ACCEPT";
	case SSL_ERROR_WANT_X509_LOOKUP:
		return "SSL_ERROR_WANT_X509_LOOKUP";
	case SSL_ERROR_SYSCALL:
		return "SSL_ERROR_SYSCALL";
	case SSL_ERROR_SSL:
		return "SSL_ERROR_SSL";
	default:
		break;
	}
	return "Undefined";
}

struct ssl_fd {
	SSL *ssl;
	int fd;
	int readpipe[2];
	int writepipe[2];
	unsigned int dead:1;
	unsigned int client:1;
	RWLIST_ENTRY(ssl_fd) entry;
};

static RWLIST_HEAD_STATIC(sslfds, ssl_fd);

static int ssl_alert_pipe[2] = { -1, -1 };

static int ssl_register_fd(SSL *ssl, int fd, int *rfd, int *wfd, int client)
{
	struct ssl_fd *sfd;

	if (ssl_alert_pipe[0] == -1) {
		bbs_error("Cannot register SSL fd: no alertpipe available\n");
		return -1;
	}

	RWLIST_WRLOCK(&sslfds);
	RWLIST_TRAVERSE(&sslfds, sfd, entry) {
		if (ssl == sfd->ssl) {
			break;
		}
	}
	if (sfd) {
		bbs_error("SSL fd %d already registered?\n", fd);
		RWLIST_UNLOCK(&sslfds);
		return -1;
	}
	sfd = calloc(1, sizeof(*sfd));
	if (ALLOC_FAILURE(sfd)) {
		RWLIST_UNLOCK(&sslfds);
		return -1;
	}
	sfd->ssl = ssl;
	sfd->fd = fd;
	if (pipe(sfd->readpipe)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		free(sfd);
		RWLIST_UNLOCK(&sslfds);
		return -1;
	} else if (pipe(sfd->writepipe)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		PIPE_CLOSE(sfd->readpipe);
		free(sfd);
		RWLIST_UNLOCK(&sslfds);
		return -1;
	}
	*rfd = sfd->readpipe[0];
	*wfd = sfd->writepipe[1];

	bbs_unblock_fd(sfd->readpipe[1]); /* Make sure write(readpipe, ...) doesn't block */

	SET_BITFIELD(sfd->client, client);

	RWLIST_INSERT_HEAD(&sslfds, sfd, entry);
	RWLIST_UNLOCK(&sslfds);
	bbs_alertpipe_write(ssl_alert_pipe); /* Notify I/O thread that we added an fd */
	return 0;
}

static void ssl_fd_free(struct ssl_fd *sfd)
{
	PIPE_CLOSE(sfd->readpipe);
	PIPE_CLOSE(sfd->writepipe);
	free(sfd);
}

static int needcreate = 1; /* Whether the list of TLS sessions is stale and needs to be rebuilt */
static int defer_rebuild = 0; /* Whether to defer the next rebuild of the session list */

/*! \note It's possible it might not be in the list, because the owner thread has already called ssl_unregister_fd,
 * in which case there's no need to do anything. */
#define MARK_DEAD(s) { \
	struct ssl_fd *sfd_traverse = sfd; /* Don't modify sfd in place or it would be NULL after traversal */ \
	RWLIST_TRAVERSE(&sslfds, sfd_traverse, entry) { \
		if (sfd_traverse->ssl == s) { \
			if (sfd_traverse->dead) { /* Shouldn't happen since we rebuild traversal list after MARK_DEAD */ \
				bbs_warning("SSL connection %p already marked as dead?\n", sfd_traverse->ssl); \
			} \
			sfd_traverse->dead = 1; \
			bbs_debug(5, "SSL connection %p now marked as dead\n", sfd_traverse->ssl); \
			break; \
		} \
	} \
}

static int ssl_unregister_fd(SSL *ssl)
{
	struct ssl_fd *sfd;

	RWLIST_WRLOCK(&sslfds);
	sfd = RWLIST_REMOVE_BY_FIELD(&sslfds, ssl, ssl, entry);
	if (sfd) {
		/* Any list of SSL sessions is now stale, since it
		 * could potentially include the session we just removed. */
		MARK_DEAD(ssl);
		needcreate = 1;
		defer_rebuild = 1;
	}
	RWLIST_UNLOCK(&sslfds);
	if (sfd) {
		ssl_fd_free(sfd);
		bbs_alertpipe_write(ssl_alert_pipe); /* Notify I/O thread that we removed a fd, although it'll probably detect this anyways. */
		return 0;
	}
	bbs_warning("Couldn't unregister SSL session for %p?\n", ssl);
	return -1;
}

static void ssl_cleanup_fds(void)
{
	struct ssl_fd *sfd;
	int c = 0;

	RWLIST_WRLOCK(&sslfds);
	while ((sfd = RWLIST_REMOVE_HEAD(&sslfds, entry))) {
		ssl_fd_free(sfd);
		c++;
	}
	needcreate = 1;
	RWLIST_UNLOCK(&sslfds);
	if (c) {
		bbs_warning("Forcibly removed %d SSL file descriptor%s\n", c, ESS(c));
	}
}

static pthread_t ssl_thread;

/*! \brief Dump TLS sessions */
static int cli_tls(struct bbs_cli_args *a)
{
	int i = 0;
	int x = 0;
	struct ssl_fd *sfd;

	RWLIST_RDLOCK(&sslfds);
	RWLIST_TRAVERSE(&sslfds, sfd, entry) {
		int readpipe, writepipe;
		i++;
		x++;
		readpipe = sfd->readpipe[1]; /* Write end of read pipe */
		i++;
		writepipe = sfd->writepipe[0];
		if (i == 2) { /* First one, print header */
			bbs_dprintf(a->fdout, "%3s %4s %6s %16s %16s %-10s %-7s\n", "#", "Type", "Status", "SFD", "SSL", "Indices", "FDs");
		}
		bbs_dprintf(a->fdout, "%3d %4s %6s %16p %16p [%3d/%3d] %3d / %3d\n", x, sfd->client ? "C" : "S", sfd->dead ? "Dead" : "Alive", sfd, sfd->ssl, i - 1, (i - 1) / 2, readpipe, writepipe);
	}
	RWLIST_UNLOCK(&sslfds);
	bbs_dprintf(a->fdout, "Polling %d file descriptor%s (%d connection%s)\n", i + 1, ESS(i + 1), i / 2, ESS(i / 2));
	return 0;
}

struct deferred_write {
	const char *buf;
	size_t len;
	SSL *ssl;
	int wfd;
	RWLIST_ENTRY(deferred_write) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(deferred_writes, deferred_write);

/* Note:
 * Many frequent TLS-level warnings or errors have been made debug messages here,
 * because they happen frequently due to client issues.
 * Most of the time, we're not really concerned with these since there's nothing we can do about that. */

/*! \brief Single thread to handle I/O for all TLS connections (which are mainly buffered in chunks anyways) */
static void *ssl_io_thread(void *unused)
{
	struct ssl_fd *sfd;
	int res;
	struct pollfd *pfds = NULL; /* Will dynamically allocate */
	int *readpipes = NULL;
	SSL **ssl_list = NULL;
	/* We use int instead of nfds_t here,
	 * since we print these out, and nfds_t is signed on some platforms (e.g. Linux)
	 * and unsigned on others (e.g. FreeBSD), so we can't portably print them. */
	int i, prevfds = 0, oldnumfds = 0, numfds = 0, numssl = 0;
	char buf[8192];
	int pending;
	int inovertime = 0, overtime = 0, num_deferred_writes = 0;
#define MAX_DEFERRED_REBUILDS 12
	int max_deferred_rebuilds = MAX_DEFERRED_REBUILDS; /* Maximum number of rebuilds that can be deferred before we rebuild no matter what */
	char err_msg[1024];

	UNUSED(unused);

	SSL_load_error_strings();

	/* Only recreate pfds when we read from the alertpipe, otherwise, it's the same file descriptors the next round */
	for (;;) {
		if (needcreate) {
			/* Because some types of connections involve many TLS sessions (e.g. a mail session with client proxies to many other servers),
			 * when the parent connection gets torn down, we could have many TLS connections all being torn down at once.
			 * Naively, we might rebuild the TLS session list as each one is torn down, all within ms of each other,
			 * but this is clearly inefficient.
			 * As an optimization, before rebuilding the list, wait a few ms for something else to happen. */
			int numdead = 0;
			if (ssl_shutting_down) {
				bbs_debug(4, "SSL I/O thread has been instructed to exit\n");
				break; /* We're shutting down. */
			}
			while (defer_rebuild) {
				defer_rebuild = 0; /* Not protected by lock, but that's okay */
				if (!max_deferred_rebuilds--) {
					max_deferred_rebuilds = MAX_DEFERRED_REBUILDS;
					bbs_debug(8, "Maximum deferred rebuilds reached, rebuilding immediately\n");
					break;
				}
				bbs_debug(8, "Temporarily deferring rebuild of TLS session list\n");
				/* If another session needs servicing, ideally we should stop waiting and handle it immediately.
				 * However, polling with the existing pfds here won't be accurate,
				 * since the session that ended originally still has activity on it.
				 * We could update the poll list so it's accurate, but that is precisely the work we are trying to avoid here.
				 * So just sleep for a very short period of time that is unlikely to disrupt any active sessions. */
				if (bbs_safe_sleep(2)) { /* Wait 2 ms */
					break;
				}
			}
			bbs_debug(8, "Rebuilding TLS session list\n");
			needcreate = 0;
			free_if(pfds);
			free_if(ssl_list);
			free_if(readpipes);
			RWLIST_RDLOCK(&sslfds);
			oldnumfds = numfds;
			numssl = RWLIST_SIZE(&sslfds, sfd, entry);
			numfds = 2 * numssl + 1; /* Times 2, one for read and write. Add 1 for alertpipe */
			pfds = calloc((size_t) numfds, sizeof(*pfds));
			if (ALLOC_FAILURE(pfds)) {
				RWLIST_UNLOCK(&sslfds);
				break;
			}
			ssl_list = calloc((size_t) numssl, sizeof(SSL *));
			if (ALLOC_FAILURE(ssl_list)) {
				free_if(pfds);
				RWLIST_UNLOCK(&sslfds);
				break;
			}
			readpipes = calloc((size_t) numssl, sizeof(int));
			if (ALLOC_FAILURE(readpipes)) {
				free_if(pfds);
				free_if(ssl_list);
				RWLIST_UNLOCK(&sslfds);
				break;
			}
			i = 0;
			pfds[i].fd = ssl_alert_pipe[0];
			pfds[i].events = POLLIN;
			RWLIST_TRAVERSE(&sslfds, sfd, entry) {
				i++;
				ssl_list[i / 2] = sfd->ssl;
				readpipes[i / 2] = sfd->readpipe[1]; /* Write end of read pipe */
				if (sfd->dead) { /* Don't read from dead connections */
					numdead++;
					/* Don't care about any events for this connection, it's dead.
					 * We're going to leave it in the linked list until the consumer removes it, but that may not happen immediately. */
					readpipes[i / 2] = -2; /* Indicate this SSL is dead, don't read from it. */
					/* We cannot merely do pfds[i].events = 0 to ignore this fd: 0 implicitly includes POLLHUP, POLLERR, and POLLNVAL.
					 * Another option might be closing some file descriptors as soon as they become dead,
					 * rather than waiting until ssl_fd_free. */
					pfds[i].events = 0;
					pfds[i].fd = -1; /* This does not trigger a POLLNVAL, negative fds are ignored by poll (see poll(2)) */
					bbs_debug(7, "Skipping dead SSL read connection %p at index %d / %d (fd: %d/%d)\n", sfd->ssl, i, i / 2, sfd->fd, sfd->writepipe[0]);
				} else {
					pfds[i].fd = sfd->fd;
					pfds[i].events = POLLIN | POLLPRI | POLLERR | POLLNVAL;
				}
				i++;
				/*! \todo In some cases, we are still seeing an infinite loop of poll constantly returning activity on a dead connection.
				 * I think this happens because even though we use -1 above, we still use the actual writepipe read fd here.
				 * While we can't set this to -1 because of the comment below, in certain cases it may make sense to close this and use -1.
				 * For now, more logging of the actual file descriptor number has been added so this theory can be confirmed. */
				pfds[i].fd = sfd->writepipe[0];
				/* If it's dead, we still need to read from the writepipe and discard,
				 * or otherwise it might block a writing thread */
				pfds[i].events = POLLIN | POLLPRI | POLLERR | POLLNVAL;
			}
			RWLIST_UNLOCK(&sslfds);
			if (numfds != prevfds) {
				char tmpbuf[20] = "";
				if (numdead) {
					snprintf(tmpbuf, sizeof(tmpbuf), ", %d dead", numdead);
				}
				bbs_debug(7, "SSL I/O thread now polling %d -> %d fd%s (%d connection%s%s)\n", oldnumfds, numfds, ESS(numfds), numssl, ESS(numssl), tmpbuf);
			} else {
				bbs_debug(7, "SSL I/O thread still polling %d fd%s\n", numfds, ESS(numfds));
			}
			prevfds = numfds;
		}
		for (i = 0; i < numfds; i++) {
			pfds[i].revents = 0;
		}
		res = 0;
		if (!overtime) {
			res = poll(pfds, (nfds_t) numfds, -1);
			if (res <= 0) {
				if (res == -1 && errno == EINTR) {
					continue;
				}
				bbs_warning("poll returned %d (%s)\n", res, res == -1 ? strerror(errno) : "");
				break;
			}
			inovertime = 0;
		} else {
#ifdef DEBUG_TLS
			bbs_debug(6, "%d TLS connection%s in overtime\n", overtime, ESS(overtime));
#endif
			res = overtime;
			inovertime = 1;
		}
		RWLIST_RDLOCK(&sslfds);
		/* Now that we've acquired the lock, check if any sessions are stale.
		 * If so, we need to rebuild the list before iterating again,
		 * to avoid using sessions that were removed and may now be freed. */
		if (needcreate) {
			RWLIST_UNLOCK(&sslfds);
			bbs_debug(4, "TLS session list has become stale since loop iteration began, rebuilding again...\n");
			continue;
		}
		if (num_deferred_writes) {
			struct deferred_write *d;
			/* First, establish that any pending deferred writes belong to an SSL session that still exists.
			 * If it got destroyed, than we should just discard it. */
			if (RWLIST_EMPTY(&deferred_writes)) {
				bbs_error("No deferred writes, but thought we had %d?\n", num_deferred_writes);
				num_deferred_writes = 0;
			}
			RWLIST_TRAVERSE_SAFE_BEGIN(&deferred_writes, d, entry) {
				int match = 0;
				ssize_t wres;
				for (i = 0; i < numssl; i++) {
					if (d->ssl == ssl_list[i]) {
						match = 1;
						break;
					}
				}
				if (!match) {
					bbs_warning("Discarding deferred write of %lu bytes, associated TLS session %p no longer exists\n", d->len, d->ssl);
					RWLIST_REMOVE_CURRENT(entry);
					free(d);
					num_deferred_writes--;
					continue;
				}
				/* Attempt the deferred write again.
				 * Since it already got deferred once, don't wait very long, just 100 ms per attempt. */
				wres = bbs_timed_write(d->wfd, d->buf, d->len, 100);
				if (wres < 0) {
					MARK_DEAD(d->ssl);
					needcreate = 1;
					RWLIST_REMOVE_CURRENT(entry);
					free(d);
					num_deferred_writes--;
					continue;
				} else if (!wres) {
					bbs_debug(3, "Deferred write of %lu bytes couldn't yet be serviced\n", d->len);
					continue;
				}
				/* If we encounter another partial write, just adjust the offsets, no need to reallocate */
				d->buf += wres;
				d->len -= (size_t) wres;
				if (!d->len) {
					bbs_debug(3, "Successfully wrote deferred write of %ld bytes\n", wres);
					RWLIST_REMOVE_CURRENT(entry);
					free(d);
					num_deferred_writes--;
				} else {
					bbs_debug(3, "Deferred write reduced to %lu bytes\n", d->len);
				}
			}
			RWLIST_TRAVERSE_SAFE_END;
			/* If we have another reason to go through the loop below, then we can,
			 * but most likely res == 0 here, and we'll just skip the traversal. */
		}
		for (i = 0; res > 0 && i < numfds; i++) {
			int ores;
			ssize_t wres;
			if (!inovertime) {
				if (pfds[i].revents == 0) {
					continue;
				}
				res--; /* Processed one event. Break the loop as soon as there are no more, to avoid traversing all like with select(). */
			}
			if (!inovertime && pfds[i].revents != POLLIN) { /* Something exceptional happened, probably something going away */
				if (pfds[i].revents & (POLLNVAL | POLLHUP)) {
					SSL *ssl = ssl_list[i / 2];
					bbs_debug(5, "Skipping SSL %p at index %d / %d = %s (fd %d)\n", ssl, i, i/2, poll_revent_name(pfds[i].revents), pfds[i].fd);
					MARK_DEAD(ssl);
					needcreate = 1;
					continue; /* Don't try to read(), that would fail */
				} else {
					bbs_debug(5, "SSL %p at index %d / %d = %s\n", ssl_list[i / 2], i, i/2, poll_revent_name(pfds[i].revents));
				}
			}
			if (!inovertime && i == 0) {
				bbs_alertpipe_read(ssl_alert_pipe);
				needcreate = 1;
				break; /* Skip everything else, in case something no longer exists */
			} else if (i % 2 == 1) { /* sfd->fd has activity */
				/* Read from socket using SSL_read and write to readpipe */
				SSL *ssl = ssl_list[i / 2];
				int readpipe = readpipes[i / 2];
				if (num_deferred_writes) {
					/* Make sure we don't read any new data from this connection as long as there is data
					 * we already read that still needs to be written to the other side. */
					struct deferred_write *d;
					RWLIST_TRAVERSE(&deferred_writes, d, entry) {
						if (d->ssl == ssl) {
							break;
						}
					}
					if (d) {
						bbs_debug(3, "Skipping active SSL connection at index %d / %d, deferred write still pending on it\n", i, i/2);
						continue;
					}
				}
				if (readpipe == -2) {
					/* Don't bother trying to call SSL_read again, we'll just get the error we got last time (SYSCALL or ZERO_RETURN)
					 * However, this shouldn't even happen anymore, because when we rebuild the poll structure,
					 * we explicitly mark the dead connections as "don't poll". */
					bbs_warning("Skipping dead SSL connection at index %d / %d\n", i, i/2);
					continue;
				} else if (inovertime) {
					pending = SSL_pending(ssl);
					if (pending <= 0) {
						continue;
					}
#ifdef DEBUG_TLS
					bbs_debug(10, "Reading from SSL connection in overtime with %d bytes pending\n", pending);
#endif
					res--; /* Processed an overtime event */
					overtime--;
				}
				/* This will not block, since we unblocked the file descriptor prior to registration.
				 * This is important because we're holding a RDLOCK on the list, which prevents other
				 * stuff from getting added, and this is a single thread for all TLS I/O, so if
				 * we block here for any reason, that is really, really, really, really bad.
				 * This loop must finish as quickly as possible.*/
				ores = SSL_read(ssl, buf, sizeof(buf));
				if (ores <= 0) {
					int err = SSL_get_error(ssl, ores);
					switch (err) {
						case SSL_ERROR_NONE:
						case SSL_ERROR_WANT_READ:
							bbs_debug(10, "SSL_read for %p returned %d (%s)\n", ssl, ores, ssl_strerror(err));
							continue; /* Move on to other connections, come back to this one later */
						case SSL_ERROR_SYSCALL:
						case SSL_ERROR_ZERO_RETURN:
						case SSL_ERROR_SSL:
							if (err == SSL_ERROR_SSL) {
								unsigned long err_err = ERR_get_error();
								ERR_error_string_n(err_err, err_msg, sizeof(err_msg));
								bbs_debug(1, "TLS error: %s\n", err_msg);
							}
							/* This socket is done for, do not retry to read more data,
							 * e.g. client has closed the connection but server has yet to close its end, and we're in the middle */
							MARK_DEAD(ssl);
							/* Fall through */
						default:
							break;
					}
					bbs_debug(6, "SSL_read for %p returned %d (%s)\n", ssl, ores, ssl_strerror(err));
					/* Socket closed the connection, pass it on. */
					close(readpipe);
					needcreate = 1;
					continue;
				}
				/* This could block, and we also need to retry partial writes, as above with partial reads, hence bbs_write APIs instead of write. */
				wres = bbs_timed_write(readpipe, buf, (size_t) ores, 750);
				if (wres == -1) {
					MARK_DEAD(ssl);
					needcreate = 1;
					continue;
				} else if (wres != ores) {
					struct deferred_write *d;
					char *bytes_start;
					size_t bytes_left;
					/* If we can't make regular progress fairly quickly,
					 * then we should move on and come back to this later.
					 * Otherwise, we can encounter a form of deadlock,
					 * where one TLS session is blocked and attempts to
					 * wait for it to be writable block other sessions. */
					bytes_start = buf + wres;
					bytes_left = (size_t) (ores - wres);
					/* Don't abuse the overtime counter, this is a different scenario */
					bbs_debug(3, "Wanted to write %d bytes but wrote %ld (%lu remaining)\n", ores, wres, bytes_left);
					/* Save it for later... */
					d = malloc(sizeof(*d) + bytes_left);
					if (ALLOC_FAILURE(d)) {
						/* Well, this is bad. Not much we can do besides give up... */
						MARK_DEAD(ssl);
						needcreate = 1;
						continue;
					}
					memcpy(d->data, bytes_start, bytes_left);
					d->buf = d->data;
					d->len = bytes_left;
					d->ssl = ssl;
					d->wfd = readpipe;
					RWLIST_NEXT(d, entry) = NULL;
					/* No need to lock/unlock deferred_writes list, nobody uses it but this thread */
					num_deferred_writes++;
					RWLIST_INSERT_TAIL(&deferred_writes, d, entry);
					bbs_debug(3, "Deferred write of %lu bytes from session %p (now %d total deferred write%s)\n", bytes_left, ssl, num_deferred_writes, ESS(num_deferred_writes));
					continue;
				}
				/* We're polling the raw socket file descriptor,
				 * but reading from ssl. Therefore, it's possible
				 * that's polling the socket would return 0,
				 * because we can't keep up with reading the decrypted data,
				 * and thus everything is already buffered in the OpenSSL BIO.
				 * Explicitly check, because we'll need to read again
				 * if that's the case, since there's data available to relay
				 * even though poll() doesn't think there is anymore. */
				pending = SSL_pending(ssl);
				if (pending > 0) {
#ifdef DEBUG_TLS
					bbs_debug(6, "SSL %p has %d pending bytes\n", ssl, pending);
#endif
					overtime++;
				}
			} else if (!overtime) { /* sfd->writepipe has activity */
				int write_attempts = 0;
				int readpipe = readpipes[(i - 1) / 2]; /* If SSL connection is dead, can't write to it either */
				/* Read from writepipe and relay to socket using SSL_write */
				SSL *ssl = ssl_list[(i - 1) / 2];
				ores = (int) read(pfds[i].fd, buf, sizeof(buf));
				if (ores <= 0) {
					bbs_debug(3, "read returned %d on fd %d: %s\n", ores, pfds[i].fd, strerror(errno));
					/* Application closed the connection,
					 * but it will close the node fd (socket) so we don't need to close here. */
					MARK_DEAD(ssl); /* What we can do now though is mark it as dead */
					needcreate = 1; /* Rebuild the iterator so we don't repeatedly try reading from a dead connection */
					continue;
				}
				if (readpipe == -2) {
					/* If the SSL connection is known to be dead, we know we can't write to it, don't try.
					 * We still read the data to avoid causing writes to the pipe to block, but we basically throw it away. */
					bbs_warning("Can't write to dead SSL connection %p, discarding %d bytes\n", ssl, ores);
					continue;
				}
				do {
					/* If we're sending a large amount of data from the BBS to a TLS socket,
					 * it is probable that SSL_write will return -1 (SSL_ERROR_WANT_WRITE).
					 * In this case, we need to be prepared to keep retrying the write. */
					wres = SSL_write(ssl, buf, ores);
					if (wres != ores) {
						if (wres <= 0) {
							int err = SSL_get_error(ssl, (int) wres);
							switch (err) {
								case SSL_ERROR_WANT_WRITE:
									/* We are supposed to retry with the same arguments,
									 * we cannot just come back and try this again later,
									 * since the buffer is shared amongst all TLS users,
									 * we cannot store this for later.
									 * It may not be a great idea to retry again because this may hold
									 * other connections up, and no single SSL connection must be allowed to hog
									 * the thread.
									 * We COULD malloc dup the # of bytes in the buffer (and store how many)
									 * and check for such a buffer on previous visits to this item in the loop.
									 * We certainly SHOULD do this if this turns out to be a major issue,
									 * i.e. more than just tens or a couple hunderd milliseconds.
									 * This is definitely a downside of using a single thread for all TLS relaying.
									 */
									if (!write_attempts++) { /* Log the first time. Debug, not warning, since this could happen legitimately */
										bbs_debug(4, "SSL_write returned %ld (%s)\n", wres, ssl_strerror(err));
									}
									if (write_attempts < 3000) {
										/* Don't make the loop super tight, it'll probably take several hunderd/thousand us anyways,
										 * and we don't need to service I/O in realtime.
										 * Don't make it super loose either, we have other work we need to get on with. */
										usleep(500);
										continue;
									}
									/* This is more than a second without making any progress, abort. */
									bbs_error("Max SSL_write retries (%d) exceeded\n", write_attempts);
									MARK_DEAD(ssl);
									needcreate = 1;
									break;
								case SSL_ERROR_SYSCALL:
								case SSL_ERROR_ZERO_RETURN:
								case SSL_ERROR_SSL:
									ERR_error_string_n(ERR_get_error(), err_msg, sizeof(err_msg));
									bbs_warning("TLS error: wanted to write %d bytes to %p but wrote %ld? (%s)\n", ores, ssl, wres, err_msg);
									/* Fall through */
								case SSL_ERROR_NONE:
									/* This socket is done for, do not retry to read more data,
									 * e.g. client has closed the connection but server has yet to close its end, and we're in the middle */
									MARK_DEAD(ssl);
									needcreate = 1;
									/* Fall through */
								default:
									break;
							}
							bbs_debug(6, "SSL_write returned %ld (%s)\n", wres, ssl_strerror(err));
							break;
						} else {
							/* Reset any time we are able to make progress. */
							write_attempts = 0;
						}
					}
				} while (wres != ores);
				if (write_attempts) {
					bbs_debug(4, "SSL_write succeeded after %d retries\n", write_attempts);
				}
			}
		}
		RWLIST_UNLOCK(&sslfds);
	}
	free_if(pfds);
	free_if(ssl_list);
	free_if(readpipes);
	return NULL;
}

static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
	/* OpenSSL apps/s_server.c */

	/* This is supposedly threadsafe due to CRYPTO_set_locking_callback */
	struct sni *sni;
	const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

	UNUSED(ad);
	UNUSED(arg);

	if (strlen_zero(servername)) { /* Client that doesn't support SNI? */
		bbs_debug(4, "No server name in TLS handshake - client doesn't support SNI?\n");
		return SSL_TLSEXT_ERR_OK;
	}

	RWLIST_RDLOCK(&sni_certs);
	RWLIST_TRAVERSE(&sni_certs, sni, entry) {
		if (!strcasecmp(servername, sni->hostname)) { /* Hostnames are not case sensitive */
			SSL_set_SSL_CTX(s, sni->ctx);
			break;
		}
	}
	RWLIST_UNLOCK(&sni_certs);

	if (sni) {
		bbs_debug(1, "Switching server context due to SNI: %s\n", servername);
	} else {
		bbs_debug(1, "No certificate match for %s, aborting SNI\n", servername);
	}
	return SSL_TLSEXT_ERR_OK;
}

static bbs_rwlock_t ssl_cert_lock = BBS_RWLOCK_INITIALIZER;

static SSL *ssl_new_accept(int fd, int *rfd, int *wfd)
{
	int res;
	int readfd, writefd;
	int attempts = 0;
	SSL *ssl;

	if (!ssl_is_available) {
		return NULL;
	}

	if (rfd && wfd && bbs_unblock_fd(fd)) { /* Make the TLS reads from the client nonblocking */
		return NULL;
	}

	/* No need to call SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER) - this is the default */

	bbs_rwlock_rdlock(&ssl_cert_lock);
	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		bbs_rwlock_unlock(&ssl_cert_lock);
		bbs_error("Failed to create SSL\n");
		return NULL;
	}
	SSL_set_fd(ssl, fd);
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION); /* Minimum TLS 1.0 */
	SSL_CTX_set_tlsext_servername_callback(ssl_ctx, ssl_servername_cb);

accept:
	res = SSL_accept(ssl);
	if (res != 1) {
		int sslerr = SSL_get_error(ssl, res);
		if (sslerr == SSL_ERROR_WANT_READ) {
			if (++attempts > 3000) { /* 3 seconds */
				bbs_rwlock_unlock(&ssl_cert_lock);
				bbs_warning("SSL_accept timed out\n");
				SSL_free(ssl);
				return NULL;
			}
			usleep(1000);
			goto accept; /* This just works out to be cleaner than using any kind of loop here */
		}
		bbs_rwlock_unlock(&ssl_cert_lock);
		bbs_debug(1, "SSL error %d: %d (%s = %s)\n", res, sslerr, ssl_strerror(sslerr), ERR_error_string(ERR_get_error(), NULL));
		SSL_free(ssl);
		return NULL;
	}
	bbs_rwlock_unlock(&ssl_cert_lock);

	readfd = SSL_get_rfd(ssl);
	writefd = SSL_get_wfd(ssl);
	if (readfd != writefd || readfd != fd) {
		bbs_warning("File descriptor mismatch: %d/%d/%d\n", fd, readfd, writefd);
	}

	if (rfd && wfd) {
		if (ssl_register_fd(ssl, fd, rfd, wfd, 0)) {
			SSL_free(ssl);
			return NULL;
		}
	}

	if (SSL_session_reused(ssl)) {
		bbs_debug(5, "SSL session was reused for this connection\n");
	}

	bbs_debug(3, "TLS handshake completed %p (%s)\n", ssl, SSL_get_version(ssl));
	return ssl;
}

static SSL *ssl_client_new(int fd, int *rfd, int *wfd, const char *snihostname)
{
	SSL *ssl;
	SSL_CTX *ctx;
	X509 *server_cert;
	long verify_result;
	char *str;

	if (rfd && wfd && bbs_unblock_fd(fd)) { /* Make the TLS reads from the client nonblocking */
		return NULL;
	}

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		bbs_error("Failed to setup new SSL context\n");
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION); /* Only use TLS, disable compression */
	ssl = SSL_new(ctx);
	if (!ssl) {
		bbs_error("Failed to create new SSL\n");
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (SSL_set_fd(ssl, fd) != 1) {
		bbs_error("Failed to connect SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto sslcleanup;
	}

	/* Attempt to verify the server's TLS certificate.
	 * If we don't do this, verify_result won't be set properly later on. */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);
	if (SSL_CTX_load_verify_locations(ctx, root_certs, NULL) != 1) {
		bbs_error("Failed to load root certs from %s: %s\n", root_certs, ERR_error_string(ERR_get_error(), NULL));
		goto sslcleanup;
	}

	/* SNI (Server Name Indication) tells the server which host we want.
	 * Some servers may host multiple hosts at the same IP,
	 * and won't send us a TLS certificate if we don't provide the SNI.
	 * Either way, we should always send SNI if possible. */
	if (!strlen_zero(snihostname)) {
		if (SSL_set_tlsext_host_name(ssl, snihostname) != 1) {
			bbs_warning("Failed to set SNI for TLS connection\n");
		}
	} else {
		bbs_warning("No SNI provided, server may be unable to provide us its certificate!\n");
	}

connect:
	if (SSL_connect(ssl) == -1) {
		int sslerr = SSL_get_error(ssl, -1);
		if (sslerr == SSL_ERROR_WANT_READ) {
			usleep(1000);
			goto connect;
		}
		bbs_debug(4, "SSL error: %s\n", ssl_strerror(sslerr));
		bbs_error("Failed to connect SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto sslcleanup;
	}
	/* Verify cert */
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
	server_cert = SSL_get1_peer_certificate(ssl);
#else
	server_cert = SSL_get_peer_certificate(ssl);
#endif
	if (!server_cert) {
		bbs_error("Failed to get peer certificate\n");
		goto sslcleanup;
	}
	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	if (!str) {
		bbs_error("Failed to get peer certificate\n");
		goto sslcleanup;
	}
	bbs_debug(8, "TLS SN: %s\n", str);
	OPENSSL_free(str);
	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	if (!str) {
		bbs_error("Failed to get peer certificate\n");
		goto sslcleanup;
	}
	bbs_debug(8, "TLS Issuer: %s\n", str);
	OPENSSL_free(str);
	X509_free(server_cert);
	verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		bbs_warning("SSL verify failed: %ld (%s)\n", verify_result, X509_verify_cert_error_string(verify_result));
		goto sslcleanup;
	} else {
		bbs_debug(4, "TLS verification successful %p\n", ssl);
	}

	SSL_CTX_free(ctx);
	if (rfd && wfd) {
		if (ssl_register_fd(ssl, fd, rfd, wfd, 1)) {
			SSL_free(ssl);
			return NULL;
		}
	}
	return ssl;

sslcleanup:
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	ctx = NULL;
	ssl = NULL;
	return NULL;
}

static int ssl_close(SSL *ssl)
{
	int sres, res = ssl_unregister_fd(ssl);
	sres = SSL_shutdown(ssl);
	if (sres < 0) {
		int err = SSL_get_error(ssl, sres);
		bbs_debug(1, "SSL shutdown failed %p: %s\n", ssl, ssl_strerror(err));
	} else if (!sres) {
		/* We sent a close notify, but haven't received one from the peer.
		 * To be properly conformant, a client should send us a close notify,
		 * but not every client will, and we don't really care if we get one or not,
		 * so we just continue, rather than calling SSL_read to wait for proper shutdown
		 * to finish. */
		bbs_debug(5, "Exiting without receiving close notify from peer\n");
	} /* else, if sres == 1, shutdown completed successfully. */
	SSL_free(ssl);
	return res;
}

static int validate_cert(SSL_CTX *ctx, const char *cert)
{
	const ASN1_TIME *created, *expires;
	int res;
	int cdays = 0, csecs = 0, edays = 0, esecs = 0;
	X509 *x509 = SSL_CTX_get0_certificate(ctx);

	if (!cert) {
		bbs_error("Failed to load X509 certificate for %s\n", cert);
		return 0;
	}

	created = X509_getm_notBefore(x509);
	expires = X509_getm_notAfter(x509);

	res = ASN1_TIME_diff(&cdays, &csecs, NULL, created);
	if (!res) {
		bbs_warning("Failed to determine expiration time of %s\n", cert);
		return 0;
	}
	res = ASN1_TIME_diff(&edays, &esecs, NULL, expires);
	if (!res) {
		bbs_warning("Failed to determine expiration time of %s\n", cert);
		return 0;
	}

	cdays = -cdays;
	csecs = -csecs;

	bbs_debug(1, "Certificate created %d day%s, %d second%s ago, expires %d day%s, %d second%s from now\n", cdays, ESS(cdays), csecs, ESS(csecs), edays, ESS(edays), esecs, ESS(esecs));

	if (cdays < 0) {
		bbs_error("TLS certificate %s is not valid until %d day%s, %d second%s from now\n", cert, -cdays, ESS(cdays), -csecs, ESS(csecs));
		return 1;
	}

	if (edays < 0 || (edays == 0 && esecs < 0)) {
		/* Crikey, SOMEBODY forgot to renew the certificates */
		bbs_error("TLS certificate %s expired %d day%s, %d second%s ago\n", cert, -edays, ESS(edays), -esecs, ESS(esecs));
		return 1;
	} else if (edays < 1) {
		bbs_warning("TLS certificate %s will expire in %d seconds\n", cert, esecs);
	}
	return 0;
}

static SSL_CTX *tls_ctx_create(const char *cert, const char *key)
{
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		bbs_error("Failed to create SSL context\n");
		return NULL;
	}

	/* Disabling compression is a best practice to avoid attacks such as CRIME.
	 * However, another reason we explicitly do so is to avoid conflicting with explicit compression,
	 * such as DEFLATE. This cannot be enabled at the same time that compression is already enabled
	 * at the TLS layer, so disabling it here ensures that attempts to enable explicit compression
	 * don't need to worry about TLS compression already being enabled. */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION); /* Only use TLS, disable compression */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); /* Server is not verifying the client, the client will verify the server */

	if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0) {
		bbs_error("Could not load certificate file %s: %s\n", cert, ERR_error_string(ERR_get_error(), NULL));
		SSL_CTX_free(ctx);
		return NULL;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		bbs_error("Could not load private key file %s: %s\n", key, ERR_error_string(ERR_get_error(), NULL));
		SSL_CTX_free(ctx);
		return NULL;
	}
	if (SSL_CTX_check_private_key(ctx) != 1) {
		bbs_error("Private key %s does not match public certificate %s\n", key, cert);
		SSL_CTX_free(ctx);
		return NULL;
	}
	if (validate_cert(ctx, cert)) {
		SSL_CTX_free(ctx);
		return NULL;
	}
	return ctx;
}

static int ssl_load_config(int reload)
{
	int res = 0;
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

	cfg = bbs_config_load("tls.conf", 0);

	if (!cfg) {
		if (!reload) {
			bbs_warning("SSL/TLS will be unavailable since tls.conf is missing\n");
		}
		return -1; /* Impossible to do TLS server stuff if we don't know what the server key/cert are */
	}

	bbs_config_val_set_str(cfg, "tls", "rootcerts", root_certs, sizeof(root_certs)); /* Has a sane default that will work on Debian systems */
	/* If not specified in the config, warn if the default file doesn't exist on this system. */
	if (!bbs_file_exists(root_certs)) {
		bbs_warning("Root certs file '%s' does not exist; specify explicitly in tls.conf\n", root_certs);
	}
	res |= bbs_config_val_set_str(cfg, "tls", "cert", ssl_cert, sizeof(ssl_cert));
	res |= bbs_config_val_set_str(cfg, "tls", "key", ssl_key, sizeof(ssl_key));

	if (res || s_strlen_zero(ssl_cert) || s_strlen_zero(ssl_key)) {
		bbs_warning("An SSL certificate and private key must be provided to enable TLS server functionality\n");
		/* We can still be a client, but not a server */
		return -1;
	}

	ssl_ctx = tls_ctx_create(ssl_cert, ssl_key);
	if (!ssl_ctx) {
		return -1;
	}
	bbs_verb(5, "Added default TLS certificate\n");

	RWLIST_WRLOCK(&sni_certs);
	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "tls")) {
			continue; /* Already processed */
		} else if (!strcmp(bbs_config_section_name(section), "sni")) {
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				char certbuf[512];
				char *cert, *key;
				SSL_CTX *ctx;
				const char *value = bbs_keyval_val(keyval);

				if (bbs_hostname_is_ipv4(bbs_keyval_val(keyval))) {
					bbs_error("SNI is only supported for hostnames, not IP addresses (e.g. %s)\n", bbs_keyval_val(keyval));
					continue;
				}
				safe_strncpy(certbuf, value, sizeof(certbuf));
				key = certbuf;
				cert = strsep(&key, ":");

				if (strlen_zero(cert)) {
					bbs_error("TLS certificate for '%s' not specified\n", bbs_keyval_key(keyval));
					continue;
				} else if (strlen_zero(key)) {
					bbs_error("TLS private key for '%s' not specified\n", bbs_keyval_key(keyval));
					continue;
				}
				ctx = tls_ctx_create(cert, key);
				if (!ctx) {
					continue;
				}
				sni_push(bbs_keyval_key(keyval), ctx);
			}
		} else {
			bbs_error("Invalid section '%s', ignoring\n", bbs_config_section_name(section));
		}
	}
	RWLIST_UNLOCK(&sni_certs);

	bbs_config_free(cfg);
	return res;
}

static int tls_cleanup(void)
{
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
	RWLIST_WRLOCK_REMOVE_ALL(&sni_certs, entry, sni_free);
	return 0;
}

static int thread_launched = 0;
static int locks_initialized = 0;

/*! \brief Limited support for reloading configuration (e.g. new certificates) */
static int tlsreload(int fd)
{
	struct ssl_fd *sfd;

	if (!locks_initialized) {
		bbs_dprintf(fd, "TLS may only be reloaded if it initialized during startup. Completely unload and load (/reload) the TLS module to load new configuration.\n");
		return -1;
	}

	bbs_rwlock_rdlock(&ssl_cert_lock);

	/* Currently, we only keep one reference for each ctx.
	 * If we reference counted them using SSL_CTX_up_ref, then we could call SSL_CTX_free for each connection,
	 * and this would allow us to leave an existing ctx associated with a connection and trust it'll get cleaned up properly.
	 * For now, we require that no connections are using any context, e.g. we cannot have any clients to reload,
	 * so admittedly this reload functionality is not as powerful as it could be.
	 *
	 * Alternately, if we're not going to add reference counting, instead of destroying the ctx's now,
	 * we could add them to a free list and do it at shutdown. But this will result in a growing leak over time,
	 * if there are lots of reloads.
	 */

	RWLIST_WRLOCK(&sslfds);
	RWLIST_TRAVERSE(&sslfds, sfd, entry) {
		if (sfd->client) {
			continue; /* Clients are fine, they don't use any permanent ctx, they just make their own temporarily during the connection. */
		} else if (sfd->dead) {
			continue; /* If it's dead, I guess it's not coming back to life... */
		}
		break;
	}
	if (sfd) { /* At least server session exists */
		bbs_dprintf(fd, "TLS may not be reloaded while any server sessions are in use. Kick any TLS sessions and try again.\n");
		RWLIST_UNLOCK(&sslfds);
		bbs_rwlock_unlock(&ssl_cert_lock);
		return -1;
	}

	ssl_is_available = 0; /* Ensure any new connections are rejected until we're done reloading. */
	RWLIST_UNLOCK(&sslfds); /* tls_cleanup will lock the list again, so unlock it for now. XXX It's a different lock though, so could unlock after? */

	tls_cleanup();

	if (ssl_load_config(1)) {
		bbs_rwlock_unlock(&ssl_cert_lock);
		bbs_debug(5, "Failed to reload TLS configuration, TLS server will now be disabled.\n");
		return -1;
	}

	ssl_is_available = 1;
	bbs_rwlock_unlock(&ssl_cert_lock);

	bbs_dprintf(fd, "Reloaded TLS configuration\n");
	return 0;
}

static int cli_tlsreload(struct bbs_cli_args *a)
{
	return tlsreload(a->fdout);
}

static struct bbs_cli_entry cli_commands_tls[] = {
	BBS_CLI_COMMAND(cli_tls, "tls", 1, "List all TLS sessions", NULL),
	BBS_CLI_COMMAND(cli_tlsreload, "tlsreload", 1, "Reload TLS certificates and configuration", NULL),
};

static int setup_ssl_io(void)
{
	if (bbs_alertpipe_create(ssl_alert_pipe)) {
		return -1;
	}
	if (bbs_pthread_create(&ssl_thread, NULL, ssl_io_thread, NULL)) {
		return -1;
	}
	thread_launched = 1;
	return 0;
}

static int ssl_server_init(void)
{
	bbs_cli_register_multiple(cli_commands_tls);
	if (setup_ssl_io()) { /* Even if we can't be a TLS server, we can still be a TLS client. */
		return -1;
	}

	if (ssl_load_config(0)) {
		bbs_debug(5, "TLS server will not be available\n");
	} else {
		ssl_is_available = 1;
	}
	if (lock_init()) {
		bbs_error("lock_init failed, TLS disabled\n");
		return -1;
	}

	locks_initialized = 1;
	return 0;
}

static void ssl_server_shutdown(void)
{
	ssl_is_available = 0;
	ssl_shutting_down = 1;

	tls_cleanup();

	bbs_cli_unregister_multiple(cli_commands_tls);

	/* Do not use pthread_cancel, let the thread clean up */
	if (thread_launched) {
		bbs_alertpipe_write(ssl_alert_pipe); /* Tell thread to exit */
		bbs_pthread_join(ssl_thread, NULL);
	}
	bbs_alertpipe_close(ssl_alert_pipe);
	ssl_cleanup_fds();
	if (locks_initialized) {
		lock_cleanup();
	}
}

/* I/O transformation callback functions */

static int setup(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg)
{
	SSL *ssl = NULL;
	int fd = *rfd;

	/* For TLS, these must match since OpenSSL takes a file descriptor for setup (which is expected to be a socket, or something like that, same fd for read/write) */
	if (*rfd != *wfd) {
		bbs_error("rfd != wfd (%d != %d)\n", *rfd, *wfd);
		return -1;
	}

	if (dir & TRANSFORM_SERVER) {
		if (!ssl_is_available) {
			bbs_error("Declining TLS setup\n"); /* Shouldn't happen since we didn't register the SERVER I/O callback... */
			return -1;
		}
		ssl = ssl_new_accept(fd, rfd, wfd);
	} else if (dir & TRANSFORM_CLIENT) {
		const char *snihostname = arg;
		ssl = ssl_client_new(fd, rfd, wfd, snihostname);
	}

	if (!ssl) {
		return -1;
	}

	*data = ssl; /* Store as transform callback data */
	return 0;
}

static void cleanup(struct bbs_io_transformation *tran)
{
	SSL *ssl = tran->data;
	bbs_assert_exists(ssl);
	ssl_close(ssl);
}

static int query(struct bbs_io_transformation *tran, int query, void *data)
{
	SSL *ssl = tran->data;
	int *result = data;

	switch (query) {
	case TRANSFORM_QUERY_TLS_REUSE:
		*result = SSL_session_reused(ssl);
		break;
	default:
		bbs_warning("Unknown query type: %d\n", query);
		return -1;
	}
	return 0;
}

static int load_module(void)
{
	if (ssl_server_init()) {
		bbs_error("Failed to initialize TLS\n");
		ssl_server_shutdown();
		return -1;
	}
	/* If we loaded server configuration, allow TLS as both server/client. Otherwise, just client. */
	if (bbs_io_transformer_register("TLS", setup, query, cleanup, TRANSFORM_TLS_ENCRYPTION, ssl_is_available ? TRANSFORM_SERVER_CLIENT_TX_RX : (TRANSFORM_CLIENT_TX | TRANSFORM_CLIENT_RX))) {
		ssl_server_shutdown();
		return -1;
	}
	return 0;
}

static int unload_module(void)
{
	bbs_io_transformer_unregister("TLS");

	/* This module should be reffed for each I/O transformation using it,
	 * but also double check to be sure. */
	RWLIST_WRLOCK(&sslfds);
	if (!RWLIST_EMPTY(&sslfds)) {
		RWLIST_UNLOCK(&sslfds);
		bbs_warning("TLS connections are still active, declining to unload\n");
		return -1;
	}
	RWLIST_UNLOCK(&sslfds);

	ssl_server_shutdown();
	return 0;
}

/* Since most network modules will use ssl_available() to check for TLS availability
 * when they load, we should be loaded before any of them are: */
BBS_MODULE_INFO_FLAGS("TLS (Transport Layer Security)", MODFLAG_ALWAYS_PRELOAD);
