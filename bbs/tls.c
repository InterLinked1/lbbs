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
 * \brief Transport Layer Security (TLS)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <string.h>
#include <poll.h>

#include "include/tls.h"

/* For hashing: */
#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/alertpipe.h"
#include "include/utils.h"

static char ssl_cert[256] = "";
static char ssl_key[256] = "";

#ifdef HAVE_OPENSSL
SSL_CTX *ssl_ctx = NULL;
#endif

static int ssl_is_available = 0;
static int ssl_shutting_down = 0;

int hash_sha256(const char *s, char buf[SHA256_BUFSIZE])
{
#ifdef HAVE_OPENSSL
	int i;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	/* We already use OpenSSL, just use that */
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, s, strlen(s));
	SHA256_Final(hash, &sha256);

	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
#undef sprintf
		sprintf(buf + (i * 2), "%02x", hash[i]); /* Safe */
	}
	buf[SHA256_BUFSIZE - 1] = '\0';
	return 0;
#else
	UNUSED(s);
	UNUSED(buf);
	UNUSED(len);
	return -1;
#endif
}

/*! \todo is there an OpenSSL function for this? */
const char *ssl_strerror(int err)
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
	RWLIST_ENTRY(ssl_fd) entry;
};

static RWLIST_HEAD_STATIC(sslfds, ssl_fd);

static int ssl_alert_pipe[2] = { -1, -1 };

static int ssl_register_fd(SSL *ssl, int fd, int *rfd, int *wfd)
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
		close(sfd->readpipe[0]);
		close(sfd->readpipe[1]);
		free(sfd);
		RWLIST_UNLOCK(&sslfds);
		return -1;
	}
	*rfd = sfd->readpipe[0];
	*wfd = sfd->writepipe[1];

	RWLIST_INSERT_HEAD(&sslfds, sfd, entry);
	RWLIST_UNLOCK(&sslfds);
	bbs_alertpipe_write(ssl_alert_pipe); /* Notify I/O thread that we added an fd */
	return 0;
}

static void ssl_fd_free(struct ssl_fd *sfd)
{
	close(sfd->readpipe[1]);
	close(sfd->readpipe[0]);
	close(sfd->writepipe[1]);
	close(sfd->writepipe[0]);
	free(sfd);
}

static int ssl_unregister_fd(SSL *ssl)
{
	struct ssl_fd *sfd;

	sfd = RWLIST_WRLOCK_REMOVE_BY_FIELD(&sslfds, ssl, ssl, entry);
	if (sfd) {
		ssl_fd_free(sfd);
		bbs_alertpipe_write(ssl_alert_pipe); /* Notify I/O thread that we removed a fd, although it'll probably detect this anyways. */
		return 0;
	}
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
	RWLIST_UNLOCK(&sslfds);
	if (c) {
		bbs_warning("Forcibly removed %d SSL file descriptor%s\n", c, ESS(c));
	}
}

static pthread_t ssl_thread;

/*! \brief Single thread to handle I/O for all TLS connections (which are mainly buffered in chunks anyways) */
static void *ssl_io_thread(void *unused)
{
	struct ssl_fd *sfd;
	int i, res;
	struct pollfd *pfds = NULL; /* Will dynamically allocate */
	int *readpipes = NULL;
	SSL **ssl_list = NULL;
	int prevfds = 0;
	int numfds = 0;
	int numssl = 0;
	int needcreate = 1;
	char buf[2048];
	int pending;
	int inovertime = 0, overtime = 0;

	UNUSED(unused);

	/* Only recreate pfds when we read from the alertpipe, otherwise, it's the same file descriptors the next round */
	for (;;) {
		if (needcreate) {
			int numdead = 0;
			if (ssl_shutting_down) {
				bbs_debug(4, "SSL I/O thread has been instructed to exit\n");
				break; /* We're shutting down. */
			}
			needcreate = 0;
			free_if(pfds);
			free_if(ssl_list);
			free_if(readpipes);
			RWLIST_RDLOCK(&sslfds);
			numssl = RWLIST_SIZE(&sslfds, sfd, entry);
			numfds = 2 * numssl + 1; /* Times 2, one for read and write. Add 1 for alertpipe */
			pfds = calloc(numfds, sizeof(*pfds));
			if (ALLOC_FAILURE(pfds)) {
				RWLIST_UNLOCK(&sslfds);
				break;
			}
			ssl_list = calloc(numssl, sizeof(SSL *));
			if (ALLOC_FAILURE(ssl_list)) {
				free(pfds);
				RWLIST_UNLOCK(&sslfds);
				break;
			}
			readpipes = calloc(numssl, sizeof(int));
			if (ALLOC_FAILURE(readpipes)) {
				free(pfds);
				free(ssl_list);
				RWLIST_UNLOCK(&sslfds);
				break;
			}
			i = 0;
			pfds[i].fd = ssl_alert_pipe[0];
			pfds[i].events = POLLIN;
			i++;
			RWLIST_TRAVERSE(&sslfds, sfd, entry) {
				ssl_list[i / 2] = sfd->ssl;
				readpipes[i / 2] = sfd->readpipe[1]; /* Write end of read pipe */
				if (sfd->dead) {
					readpipes[i / 2] = -2; /* Indicate this SSL is dead, don't read from it. */
				}
				pfds[i].fd = sfd->fd;
				pfds[i].events = POLLIN;
				i++;
				pfds[i].fd = sfd->writepipe[0];
				pfds[i].events = POLLIN;
				i++;
				if (sfd->dead) {
					numdead++;
				}
			}
			RWLIST_UNLOCK(&sslfds);
			if (numfds != prevfds) {
				char tmpbuf[20] = "";
				if (numdead) {
					snprintf(tmpbuf, sizeof(tmpbuf), " (%d dead)", numdead);
				}
				bbs_debug(7, "SSL I/O thread now polling %d fd%s%s\n", numfds, ESS(numfds), tmpbuf);
			}
			prevfds = numfds;
		}
		for (i = 0; i < numfds; i++) {
			pfds[i].revents = 0;
		}
		if (!overtime) {
			res = poll(pfds, numfds, -1);
			if (res <= 0) {
				if (res == -1 && errno == EINTR) {
					continue;
				}
				bbs_warning("poll returned %d (%s)\n", res, res == -1 ? strerror(errno) : "");
				break;
			}
			inovertime = 0;
		} else {
			bbs_debug(6, "%d TLS connection%s in overtime\n", overtime, ESS(overtime));
			res = overtime;
			inovertime = 1;
		}
		RWLIST_RDLOCK(&sslfds);
		for (i = 0; res > 0 && i < numfds; i++) {
			int ores, wres;
			if (!inovertime) {
				if (pfds[i].revents == 0) {
					continue;
				}
				res--; /* Processed one event. Break the loop as soon as there are no more, to avoid traversing all like with select(). */
			}
			if (!inovertime && pfds[i].revents != POLLIN) { /* Something exceptional happened, probably something going away */
				bbs_debug(3, "SSL at index %d / %d = %s\n", i, i/2, poll_revent_name(pfds[i].revents));
			}
			if (!inovertime && i == 0) {
				bbs_alertpipe_read(ssl_alert_pipe);
				needcreate = 1;
				break; /* Skip everything else, in case something no longer exists */
			} else if (i % 2 == 1) { /* sfd->fd has activity */
				/* Read from socket using SSL_read and write to readpipe */
				SSL *ssl = ssl_list[i / 2];
				int readpipe = readpipes[i / 2];
				if (readpipe == -2) {
					/* Don't bother trying to call SSL_read again, we'll just get the error we got last time (SYSCALL or ZERO_RETURN) */
					bbs_debug(10, "Skipping dead SSL connection\n"); /* This may spam the debug logs until whatever is using this SSL fd cleans it up */
					continue;
				} else if (inovertime) {
					pending = SSL_pending(ssl);
					if (pending <= 0) {
						continue;
					}
					bbs_debug(10, "Reading from SSL connection in overtime with %d bytes pending\n", pending);
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
							bbs_debug(10, "SSL_read returned %d (%s)\n", ores, ssl_strerror(err));
							continue;
						case SSL_ERROR_SYSCALL:
						case SSL_ERROR_ZERO_RETURN:
							/* This socket is done for, do not retry to read more data, e.g. client has closed the connection but server has yet to close its end, and we're in the middle */
							RWLIST_TRAVERSE(&sslfds, sfd, entry) {
								if (sfd->ssl == ssl) {
									sfd->dead = 1;
									break;
								}
							}
							/* Fall through */
						default:
							break;
					}
					bbs_debug(6, "SSL_read returned %d (%s)\n", ores, ssl_strerror(err));
					/* Socket closed the connection, pass it on. */
					close(readpipe);
					needcreate = 1;
					continue;
				}
				wres = write(readpipe, buf, ores);
				if (wres != ores) {
					bbs_error("Wanted to write %d bytes but wrote %d?\n", ores, wres);
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
					bbs_debug(6, "SSL %p has %d pending bytes\n", ssl, pending);
					overtime++;
				}
			} else if (!overtime) { /* sfd->writepipe has activity */
				/* Read from writepipe and relay to socket using SSL_write */
				SSL *ssl = ssl_list[(i - 1) / 2];
				ores = read(pfds[i].fd, buf, sizeof(buf));
				if (ores <= 0) {
					bbs_debug(3, "read returned %d\n", ores);
					/* Application closed the connection,
					 * but it will close the node fd (socket) so we don't need to close here. */
					continue;
				}
				wres = SSL_write(ssl, buf, ores);
				if (wres != ores) {
					bbs_error("Wanted to write %d bytes but wrote %d?\n", ores, wres);
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

SSL *ssl_new_accept(int fd, int *rfd, int *wfd)
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

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		bbs_error("Failed to create SSL\n");
		return NULL;
	}
	SSL_set_fd(ssl, fd);
accept:
	res = SSL_accept(ssl);
	if (res != 1) {
		int sslerr = SSL_get_error(ssl, res);
		if (sslerr == SSL_ERROR_WANT_READ) {
			if (++attempts > 3000) { /* 3 seconds */
				bbs_warning("SSL_accept timed out\n");
				SSL_free(ssl);
				return NULL;
			}
			usleep(1000);
			goto accept; /* This just works out to be cleaner than using any kind of loop here */
		}
		bbs_error("SSL error %d: %d (%s = %s)\n", res, sslerr, ssl_strerror(sslerr), ERR_error_string(ERR_get_error(), NULL));
		SSL_free(ssl);
		return NULL;
	}
	readfd = SSL_get_rfd(ssl);
	writefd = SSL_get_wfd(ssl);
	if (readfd != writefd || readfd != fd) {
		bbs_warning("File descriptor mismatch: %d/%d/%d\n", fd, readfd, writefd);
	}

	if (rfd && wfd) {
		if (ssl_register_fd(ssl, fd, rfd, wfd)) {
			SSL_free(ssl);
			return NULL;
		}
	}

	if (SSL_session_reused(ssl)) {
		bbs_debug(5, "SSL session was reused for this connection\n");
	}

	return ssl;
}

SSL *ssl_client_new(int fd, int *rfd, int *wfd)
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
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); /* Only use TLS */
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
	server_cert = SSL_get_peer_certificate(ssl);
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
	str = X509_NAME_oneline(X509_get_issuer_name (server_cert), 0, 0);
	if (!str) {
		bbs_error("Failed to get peer certificate\n");
		goto sslcleanup;
	}
	bbs_debug(8, "TLS Issuer: %s\n", str);
	OPENSSL_free(str);
	X509_free(server_cert);
	verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		/* XXX Verification always fails, so do debug for now, rather than warning log */
		bbs_debug(1, "SSL verify failed: %ld (%s)\n", verify_result, X509_verify_cert_error_string(verify_result));
	} else {
		bbs_debug(4, "TLS verification successful\n");
	}

	SSL_CTX_free(ctx);
	if (rfd && wfd) {
		if (ssl_register_fd(ssl, fd, rfd, wfd)) {
			SSL_free(ssl);
			return NULL;
		}
	}
	return ssl;

sslcleanup:
#ifdef HAVE_OPENSSL
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	ctx = NULL;
	ssl = NULL;
#endif
	return NULL;
}

int ssl_close(SSL *ssl)
{
	int res = ssl_unregister_fd(ssl);
	SSL_free(ssl);
	return res;
}

int ssl_available(void)
{
	return ssl_is_available;
}

static int ssl_load_config(void)
{
	int res = 0;
	struct bbs_config *cfg;

	cfg = bbs_config_load("tls.conf", 0);

	if (!cfg) {
		bbs_warning("SSL/TLS will be unavailable since tls.conf is missing\n");
		return -1; /* Impossible to do TLS server stuff if we don't know what the server key/cert are */
	}

	res |= bbs_config_val_set_str(cfg, "tls", "cert", ssl_cert, sizeof(ssl_cert));
	res |= bbs_config_val_set_str(cfg, "tls", "key", ssl_key, sizeof(ssl_key));

	if (!res && (s_strlen_zero(ssl_cert) || s_strlen_zero(ssl_key))) {
		bbs_error("An SSL certificate and private key must be provided to use TLS\n");
		return -1;
	}

	bbs_config_free(cfg);
	return res;
}

static int setup_ssl_io(void)
{
	if (bbs_alertpipe_create(ssl_alert_pipe)) {
		return -1;
	}
	if (bbs_pthread_create(&ssl_thread, NULL, ssl_io_thread, NULL)) {
		return -1;
	}
	return 0;
}

int ssl_server_init(void)
{
#ifdef HAVE_OPENSSL
	const SSL_METHOD *method;

	setup_ssl_io(); /* Even if we can't be a TLS server, we can still be a TLS client. */

	if (ssl_load_config()) {
		return -1;
	}

	method = TLS_server_method(); /* Server method, not client method! */
	ssl_ctx = SSL_CTX_new(method);

	if (!ssl_ctx) {
		bbs_error("Failed to create SSL context\n");
		return -1;
	}

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL); /* Server is not verifying the client, the client will verify the server */

	if (SSL_CTX_use_certificate_file(ssl_ctx, ssl_cert, SSL_FILETYPE_PEM) <= 0) {
		bbs_error("Could not load certificate file %s: %s\n", ssl_cert, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_key, SSL_FILETYPE_PEM) <= 0) {
		bbs_error("Could not load private key file %s: %s\n", ssl_key, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		bbs_error("Private key does not match public certificate\n");
		return -1;
	}

	ssl_is_available = 1;

	return 0;
#else
	bbs_error("BBS compiled without OpenSSL support?\n");
	return -1; /* Won't happen */
#endif
}

void ssl_server_shutdown(void)
{
	ssl_is_available = 0;
	ssl_shutting_down = 1;
#ifdef HAVE_OPENSSL
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
	/* Do not use pthread_cancel, let the thread clean up */
	bbs_alertpipe_write(ssl_alert_pipe); /* Tell thread to exit */
	bbs_pthread_join(ssl_thread, NULL);
	bbs_alertpipe_close(ssl_alert_pipe);
	ssl_cleanup_fds();
#endif
}
