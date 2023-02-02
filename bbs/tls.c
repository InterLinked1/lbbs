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
	RWLIST_ENTRY(ssl_fd) entry;
};

static RWLIST_HEAD_STATIC(sslfds, ssl_fd);

static int ssl_alert_pipe[2] = { -1, -1 };

static int ssl_register_fd(SSL *ssl, int fd, int *rfd, int *wfd)
{
	struct ssl_fd *sfd;

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
	if (!sfd) {
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

	RWLIST_WRLOCK(&sslfds);
	RWLIST_TRAVERSE_SAFE_BEGIN(&sslfds, sfd, entry) {
		if (ssl == sfd->ssl) {
			RWLIST_REMOVE_CURRENT(entry);
			ssl_fd_free(sfd);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&sslfds);
	if (sfd) {
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
	int i, res, ores, wres;
	struct pollfd *pfds = NULL; /* Will dynamically allocate */
	int *readpipes = NULL;
	SSL **ssl_list = NULL;
	int numfds = 0;
	int numssl = 0;
	int needcreate = 1;
	char buf[2048];

	UNUSED(unused);

	/* Only recreate pfds when we read from the alertpipe, otherwise, it's the same file descriptors the next round */
	for (;;) {
		if (needcreate) {
			if (!ssl_is_available) {
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
			if (!pfds) {
				RWLIST_UNLOCK(&sslfds);
				bbs_error("calloc failed\n");
				break;
			}
			ssl_list = calloc(numssl, sizeof(SSL *));
			if (!ssl_list) {
				free(pfds);
				RWLIST_UNLOCK(&sslfds);
				bbs_error("calloc failed\n");
				break;
			}
			readpipes = calloc(numssl, sizeof(int));
			if (!readpipes) {
				free(pfds);
				free(ssl_list);
				RWLIST_UNLOCK(&sslfds);
				bbs_error("calloc failed\n");
				break;
			}
			i = 0;
			pfds[i].fd = ssl_alert_pipe[0];
			pfds[i].events = POLLIN;
			i++;
			RWLIST_TRAVERSE(&sslfds, sfd, entry) {
				ssl_list[i / 2] = sfd->ssl;
				readpipes[i / 2] = sfd->readpipe[1]; /* Write end of read pipe */
				pfds[i].fd = sfd->fd;
				pfds[i].events = POLLIN;
				i++;
				pfds[i].fd = sfd->writepipe[0];
				pfds[i].events = POLLIN;
				i++;
			}
			RWLIST_UNLOCK(&sslfds);
			bbs_debug(7, "SSL I/O thread now polling %d fd%s\n", numfds, ESS(numfds));
		}
		for (i = 0; i < numfds; i++) {
			pfds[i].revents = 0;
		}
		res = poll(pfds, numfds, -1);
		if (res <= 0) {
			bbs_warning("poll returned %d\n", res);
			break;
		}
		bbs_debug(8, "poll returned %d\n", res);
		for (i = 0; res > 0 && i < numfds; i++) {
			if (pfds[i].revents == 0) {
				continue;
			}
			res--; /* Processed one event. Break the loop as soon as there are no more, to avoid traversing all like with select(). */
			if (pfds[i].revents != POLLIN) { /* Something exceptional happened, probably something going away */
				bbs_debug(3, "SSL at index %d / %d = %s\n", i, i/2, poll_revent_name(pfds[i].revents));
			}
			if (i == 0) {
				bbs_alertpipe_read(ssl_alert_pipe);
				needcreate = 1;
			} else if (i % 2 == 1) { /* sfd->fd has activity */
				/* Read from socket using SSL_read and write to readpipe */
				SSL *ssl = ssl_list[i / 2];
				int readpipe = readpipes[i / 2];
				ores = SSL_read(ssl, buf, sizeof(buf));
				if (ores <= 0) {
					bbs_debug(3, "SSL_read returned %d\n", ores);
					continue;
				}
				wres = write(readpipe, buf, ores);
				if (wres != ores) {
					bbs_error("Wanted to write %d bytes but wrote %d?\n", ores, wres);
				}
			} else { /* sfd->writepipe has activity */
				/* Read from writepipe and relay to socket using SSL_write */
				SSL *ssl = ssl_list[(i - 1) / 2];
				ores = read(pfds[i].fd, buf, sizeof(buf));
				if (ores <= 0) {
					bbs_debug(3, "read returned %d\n", ores);
					continue;
				}
				wres = SSL_write(ssl, buf, ores);
				if (wres != ores) {
					bbs_error("Wanted to write %d bytes but wrote %d?\n", ores, wres);
				}
			}
		}
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
	SSL *ssl;

	if (!ssl_is_available) {
		return NULL;
	}

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		bbs_error("Failed to create SSL\n");
		return NULL;
	}
	SSL_set_fd(ssl, fd);
	res = SSL_accept(ssl);
	if (res != 1) {
		int sslerr = SSL_get_error(ssl, res);
		bbs_error("SSL error %d: %d (%s = %s)\n", res, sslerr, ssl_strerror(sslerr), ERR_error_string(ERR_get_error(), NULL));
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

	return ssl;
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
		return -1; /* Impossible to do TLS if we don't know what the server key/cert are */
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

int ssl_server_init(void)
{
#ifdef HAVE_OPENSSL
	const SSL_METHOD *method;

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

	if (bbs_alertpipe_create(ssl_alert_pipe)) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		return -1;
	}
	ssl_is_available = 1;
	if (bbs_pthread_create(&ssl_thread, NULL, ssl_io_thread, NULL)) {
		bbs_error("Failed to create thread for TLS I/O\n");
		ssl_is_available = 0;
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		bbs_alertpipe_close(ssl_alert_pipe);
		return -1;
	}

	return 0;
#else
	bbs_error("BBS compiled with OpenSSL support?\n");
	return -1; /* Won't happen */
#endif
}

void ssl_server_shutdown(void)
{
	ssl_is_available = 0;
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
