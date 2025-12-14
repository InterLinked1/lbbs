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

static bbs_rwlock_t ssl_cert_lock = BBS_RWLOCK_INITIALIZER;

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
	const char *certfile;		/*!< Certificate file */
	const char *keyfile;		/*!< Private key file */
	SSL_CTX *ctx;
	RWLIST_ENTRY(sni) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(sni_certs, sni);

/*! \note Must be called with WRLOCK held */
static void sni_push(const char *hostname, SSL_CTX *ctx, const char *filenames)
{
	struct sni *sni;
	char *tmp;
	size_t hostlen = strlen(hostname);
	size_t filelen = strlen(filenames);
	sni = calloc(1, sizeof(*sni) + hostlen + filelen + 2);
	if (ALLOC_FAILURE(sni)) {
		return;
	}
	sni->ctx = ctx;
	strcpy(sni->data, hostname); /* Safe */
	sni->hostname = sni->data;
	tmp = sni->data + hostlen + 1;
	strcpy(tmp, filenames);
	sni->keyfile = tmp;
	sni->certfile = strsep(&tmp, ":");
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

struct tls_client {
	SSL *ssl;
	int fd;
	int readpipe[2];
	int writepipe[2];
	unsigned int client:1; /* If we are a TLS client instead of a TLS server */
	pthread_t thread;
	RWLIST_ENTRY(tls_client) entry;
};

static RWLIST_HEAD_STATIC(tls_clients, tls_client);

static void poll_init(void *varg, int *restrict fd0, int *restrict fd1)
{
	struct tls_client *t = varg;
	*fd0 = t->fd; /* BBS application read: Network socket */
	*fd1 = t->writepipe[0]; /* BBS application write: Read end of write pipe (i.e. read unencrypted data from BBS application) */
}

static int io_read_pending(void *varg)
{
	struct tls_client *t = varg;
	/* A previous SSL operation may have read in some data that is buffered,
	 * and polling the file descriptor won't detect that, since there
	 * isn't actually any new data available on the network socket itself. */
	if (SSL_has_pending(t->ssl)) {
		int pending = SSL_pending(t->ssl);
		bbs_debug(9, "SSL %p has %d pending bytes, servicing immediately\n", t->ssl, pending);
		return pending;
	}
	return 0;
}

/*! \brief Read data from the network, decrypt it, and provide it to the application */
static ssize_t io_read(void *varg)
{
	char input[BUFSIZ];
	struct tls_client *t = varg;
	ssize_t res = SSL_read(t->ssl, input, sizeof(input));
	if (res <= 0) {
		int sslerr = SSL_get_error(t->ssl, (int) res);
		if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
			bbs_debug(9, "SSL_read returned %ld: %s\n", res, ssl_strerror(sslerr));
			return 1; /* Pretend like we did something, so io.c won't terminate the session, even though nothing happened, since we want to poll again */
		}
		bbs_debug(4, "SSL_read returned %ld: %s\n", res, ssl_strerror(sslerr));
		return 0; /* Network socket closed */
	}
	return bbs_write(t->readpipe[1], input, (size_t) res); /* Write end of read pipe (i.e. write unencrypted data to BBS application) */
}

#define LOG_SSL_ERROR(sslerr, descr) { \
	if (sslerr == SSL_ERROR_SSL) { \
		char errbuf[512]; \
		unsigned long err = ERR_get_error(); \
		bbs_warning("%s: %s - %s\n", descr, ssl_strerror(sslerr), ERR_error_string(err, errbuf)); \
	} else { \
		bbs_warning("%s: %s\n", descr, ssl_strerror(sslerr)); \
	} \
}

/*! \brief Read data from the application to encrypt for the network */
static ssize_t io_write(void *varg)
{
	char input[BUFSIZ];
	int attempts = 0;
	struct tls_client *t = varg;
	ssize_t res, bytes = read(t->writepipe[0], input, sizeof(input));
	if (bytes <= 0) {
		bbs_debug(4, "read returned %ld\n", bytes);
		/* BBS is shutting this transformation down (in cleanup() callback).
		 * The cleanup() callback closes t->writepipe[1], and once we've
		 * read everything left to be written, read will return 0 here. */
		return bytes;
	}

#define MAX_SSL_WRITE_SEC 180

	/* Encrypt it */
	/* OpenSSL doesn't do partial writes, so we don't worry about those here. */
sslwrite:
	res = SSL_write(t->ssl, input, (int) bytes);
	if (res <= 0) {
		int sslerr = SSL_get_error(t->ssl, (int) res);
		bbs_debug(9, "SSL_write returned %ld: %s\n", res, ssl_strerror(sslerr));
		if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
			if (attempts++ < MAX_SSL_WRITE_SEC + 7) { /* Retry sufficiently, with not quite exponential backoff, long enough to accomodate dial-up connections */
				usleep(attempts > 10 ? 1000000 : attempts > 5 ? 500000 : 100000); /* If a write fails, wait a little bit before retrying, there are probably buffers that need to be flushed out */
				goto sslwrite; /* Retry exactly the same write again */
			}
			bbs_warning("SSL_write timed out after %d seconds\n", MAX_SSL_WRITE_SEC);
			return -1; /* Since we failed to write, abort the connection */
		} else {
			LOG_SSL_ERROR(sslerr, "SSL_write failed");
		}
		return res;
	}
	if (attempts > 0) {
		bbs_debug(8, "SSL_write succeeded after %d %s\n", attempts, attempts == 1 ? "retry" : "retries");
	}
	return res;
}

static void io_finalize(void *varg)
{
	struct tls_client *t = varg;
	/* Don't close both sides of the pipe, because the consumers may still be using the other end of the pipes.
	 * They don't belong to us anymore and are somebody else's responsibility to close. */
	close_if(t->readpipe[1]); /* Nothing more to write towards the application, close the write end of BBS application read */
	close_if(t->writepipe[0]); /* Nothing more to write towards the network, close read end of BBS application write */
}

static struct tls_client *ssl_launch(SSL *ssl, int fd, int *rfd, int *wfd, int client)
{
	struct tls_client *t;

	t = calloc(1, sizeof(*t));
	if (ALLOC_FAILURE(t)) {
		return NULL;
	}
	t->ssl = ssl;
	t->fd = fd;
	if (pipe(t->readpipe)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		free(t);
		return NULL;
	} else if (pipe(t->writepipe)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		PIPE_CLOSE(t->readpipe);
		free(t);
		return NULL;
	}

	SET_BITFIELD(t->client, client);

	RWLIST_WRLOCK(&tls_clients);
	RWLIST_INSERT_HEAD(&tls_clients, t, entry);
	RWLIST_UNLOCK(&tls_clients);

	*rfd = t->readpipe[0];
	*wfd = t->writepipe[1];
	return t;
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

static void ssl_init(SSL *ssl)
{
	/* SSL_read() in libssl can block if the file descriptor is blocking (stuck on libc_read)
	 * Even though each TLS session has its own thread, this can still cause issues as
	 * the thread will never get cleaned up, and other if any locks are held by the thread
	 * during this I/O, those will never be released.
	 *
	 * For this reason, we put the file descriptor in nonblocking mode,
	 * even though that makes our life slightly harder.
	 *
	 * We need to do this from the beginning, since even SSL_accept can block. */
	bbs_unblock_fd(SSL_get_fd(ssl));
}

static struct tls_client *ssl_new_accept(int fd, int *rfd, int *wfd)
{
	struct tls_client *t;
	int res;
	SSL *ssl;
	int tries = 0;

	if (!ssl_is_available) {
		return NULL;
	}

	bbs_rwlock_rdlock(&ssl_cert_lock);
	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		bbs_rwlock_unlock(&ssl_cert_lock);
		bbs_error("Failed to create SSL\n");
		return NULL;
	}
	SSL_set_fd(ssl, fd);
	ssl_init(ssl);
	SSL_CTX_set_tlsext_servername_callback(ssl_ctx, ssl_servername_cb);

sslaccept:
	res = SSL_accept(ssl);
	if (res != 1) {
		int sslerr = SSL_get_error(ssl, res);
		if (sslerr == SSL_ERROR_WANT_READ) {
			if (tries++ < 3000) { /* Retry up to 3 seconds */
				usleep(1000);
				goto sslaccept;
			}
			bbs_debug(1, "SSL_accept timed out: (%s = %s)\n", ssl_strerror(sslerr), ERR_error_string(ERR_get_error(), NULL));
		} else {
			bbs_debug(1, "SSL error %d: %d (%s = %s)\n", res, sslerr, ssl_strerror(sslerr), ERR_error_string(ERR_get_error(), NULL));
		}
		SSL_free(ssl);
		bbs_rwlock_unlock(&ssl_cert_lock);
		return NULL;
	}

	bbs_debug(3, "TLS handshake completed %p (%s%s)\n", ssl, SSL_get_version(ssl), SSL_session_reused(ssl) ? ", session reused" : "");

	t = ssl_launch(ssl, fd, rfd, wfd, 0);
	if (!t) {
		SSL_free(ssl);
		bbs_rwlock_unlock(&ssl_cert_lock);
		return NULL;
	}
	bbs_rwlock_unlock(&ssl_cert_lock);
	return t;
}

/*! \brief Common CTX initialization for servers and clients */
static void tls_common_ctx_init(SSL_CTX *ctx)
{
	/* Disabling compression is a best practice to avoid attacks such as CRIME.
	 * However, another reason we explicitly do so is to avoid conflicting with explicit compression,
	 * such as DEFLATE. This cannot be enabled at the same time that compression is already enabled
	 * at the TLS layer, so disabling it here ensures that attempts to enable explicit compression
	 * don't need to worry about TLS compression already being enabled. */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION); /* Only use TLS, disable compression */

	/* No need to call SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER) - this is the default */
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION); /* Minimum TLS 1.0 */
	/* No maximum set, so TLS 1.0, 1.1, 1.2, and 1.3 are supported */
}

static struct tls_client *ssl_client_new(int fd, int *rfd, int *wfd, const char *snihostname)
{
	struct tls_client *t;
	SSL *ssl;
	SSL_CTX *ctx;
	X509 *server_cert;
	long verify_result;
	char *str;
	int attempts = 0;

	OpenSSL_add_ssl_algorithms();
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		bbs_error("Failed to setup new SSL context\n");
		return NULL;
	}
	tls_common_ctx_init(ctx);
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

	ssl_init(ssl);

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

sslconnect:
	if (SSL_connect(ssl) == -1) {
		int sslerr = SSL_get_error(ssl, -1);
		if (sslerr == SSL_ERROR_WANT_READ && attempts++ < 3000) { /* Retry up to 3 seconds */
			usleep(1000);
			goto sslconnect;
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
	t = ssl_launch(ssl, fd, rfd, wfd, 1);
	if (!t) {
		SSL_free(ssl);
		return NULL;
	}
	return t;

sslcleanup:
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	ctx = NULL;
	ssl = NULL;
	return NULL;
}

static int ssl_close(struct tls_client *t)
{
	SSL *ssl = t->ssl;
	int err, sres, status, fd;

	/* Sanity check.
	 * Verify that the file descriptor for this session has not been closed yet.
	 * If it has, then something went wrong, and this is likely the cause of other TLS issues. */
	fd = SSL_get_fd(ssl);
	bbs_soft_assert(bbs_fd_valid(fd));

	RWLIST_WRLOCK(&tls_clients);
	RWLIST_REMOVE(&tls_clients, t, entry);
	RWLIST_UNLOCK(&tls_clients);

	/* At this point, the only file descriptor remaining that hasn't been cleaned up yet is t->readpipe[0].
	 * That is left to the application to close, since it may still be currently reading data out of its end of the pipe. */

#define SHUTDOWN_STATUS(s) (s & SSL_RECEIVED_SHUTDOWN ? s & SSL_SENT_SHUTDOWN ? "sent/received" : "received" : "none")
	status = SSL_get_shutdown(ssl);
	bbs_debug(6, "Shutdown status is %s (fd %d)\n", SHUTDOWN_STATUS(status), fd);

	sres = SSL_shutdown(ssl);
	if (sres == 1) {
		status = SSL_get_shutdown(ssl);
		bbs_debug(5, "Bidirectional SSL shutdown completed (%s)\n", SHUTDOWN_STATUS(status));
	} else if (sres == 0 || SSL_get_error(ssl, sres) == SSL_ERROR_WANT_READ) {
		int retried = 0;
		status = SSL_get_shutdown(ssl);
		bbs_debug(6, "Shutdown status is %s (fd %d)\n", SHUTDOWN_STATUS(status), fd);

		/* The second call to SSL_shutdown or other OpenSSL functions at this point
		 * can sometimes hang (blocked on read internally) if file descriptor is blocking,
		 * but we are nonblocking the entire session so don't need to unblock again. */

shutdown2:
		/* Unidirectional shutdown has completed. Historically, it would be okay to clean up now,
		 * although we could try for a bidirectional shutdown as well by calling SSL_shutdown again
		 * (and with nonblocking SSL's, potentially multiple times if SSL_ERROR_WANT_READ).
		 * However, with TLS 1.3, this is critical, particularly for sessions where data
		 * is only written in one direction.
		 *
		 * See https://github.com/openssl/openssl/issues/7948
		 */
		sres = SSL_shutdown(ssl);
		if (sres == 1) {
			status = SSL_get_shutdown(ssl);
			bbs_debug(5, "Bidirectional SSL shutdown completed (%s)\n", SHUTDOWN_STATUS(status));
		} else {
			err = SSL_get_error(ssl, sres);
			if (err == SSL_ERROR_WANT_READ && bbs_poll(fd, SEC_MS(2)) > 0 && !retried++) {
				goto shutdown2; /* Retry once */
			}
			/* Not necessarily our fault. The other side may not have sent the close notify. */
			bbs_debug(1, "Bidirectional SSL shutdown failed %p: %s\n", ssl, ssl_strerror(err));
		}
	} else {
		err = SSL_get_error(ssl, sres);
		bbs_debug(1, "SSL shutdown failed %p: %s\n", ssl, ssl_strerror(err));
		bbs_assert(sres == -1);
	}

	SSL_free(ssl);
	free(t);
	return 0;
}

static int validate_cert(SSL_CTX *ctx, const char *cert)
{
	const ASN1_TIME *created, *expires;
	int res;
	int cdays = 0, csecs = 0, edays = 0, esecs = 0;
	X509 *x509 = SSL_CTX_get0_certificate(ctx);

	if (!x509) {
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

static SSL_CTX *tls_server_ctx_create(const char *cert, const char *key)
{
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		bbs_error("Failed to create SSL context\n");
		return NULL;
	}

	tls_common_ctx_init(ctx);
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
			bbs_warning("SSL/TLS server will be unavailable since tls.conf is missing\n");
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
		bbs_config_unlock(cfg);
		return -1;
	}

	ssl_ctx = tls_server_ctx_create(ssl_cert, ssl_key);
	if (!ssl_ctx) {
		bbs_config_unlock(cfg);
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
				const char *hostname = bbs_keyval_key(keyval);
				const char *filenames = bbs_keyval_val(keyval);

				if (bbs_hostname_is_ipv4(hostname)) {
					bbs_error("SNI is only supported for hostnames, not IP addresses (e.g. %s)\n", hostname);
					continue;
				}
				safe_strncpy(certbuf, filenames, sizeof(certbuf));
				key = certbuf;
				cert = strsep(&key, ":");

				if (strlen_zero(cert)) {
					bbs_error("TLS certificate for '%s' not specified\n", hostname);
					continue;
				} else if (strlen_zero(key)) {
					bbs_error("TLS private key for '%s' not specified\n", hostname);
					continue;
				}
				ctx = tls_server_ctx_create(cert, key);
				if (!ctx) {
					continue;
				}
				sni_push(hostname, ctx, filenames);
			}
		} else {
			bbs_error("Invalid section '%s', ignoring\n", bbs_config_section_name(section));
		}
	}
	RWLIST_UNLOCK(&sni_certs);

	bbs_config_unlock(cfg);
	bbs_config_free(cfg);
	return res;
}

static void print_cert_info(int fd, const char *hostname, SSL_CTX *ctx, const char *certfile, const char *keyfile)
{
	const ASN1_TIME *created, *expires;
	struct tm createdtm, exptm, mtm;
	char cdate[17], edate[17], mdate[17];
	struct stat st;
	int res;
	X509 *x509 = SSL_CTX_get0_certificate(ctx); /* We know this will succeed or the cert wouldn't be loaded */

	hostname = S_OR(hostname, "(Default)");

	created = X509_getm_notBefore(x509);
	expires = X509_getm_notAfter(x509);

	memset(&createdtm, 0, sizeof(createdtm));
	memset(&exptm, 0, sizeof(exptm));
	memset(&mtm, 0, sizeof(mtm));

	if (stat(certfile, &st)) {
		bbs_error("stat(%s) failed: %s\n", certfile, strerror(errno));
	}
	localtime_r(&st.st_mtim.tv_sec, &mtm);

	res = ASN1_TIME_to_tm(created, &createdtm);
	if (!res) { /* 0 = error, 1 = success */
		bbs_warning("Time conversion failed\n");
	}
	res = ASN1_TIME_to_tm(expires, &exptm);
	if (!res) { /* 0 = error, 1 = success */
		bbs_warning("Time conversion failed\n");
	}

	strftime(cdate, sizeof(cdate), "%Y-%m-%d %H:%M", &createdtm);
	strftime(edate, sizeof(edate), "%Y-%m-%d %H:%M", &exptm);
	strftime(mdate, sizeof(mdate), "%Y-%m-%d %H:%M", &mtm);

	bbs_dprintf(fd, "%-20s %-16s %-16s %-16s %s:%s\n", hostname, mdate, cdate, edate, certfile, keyfile);
}

static int cli_tlscerts(struct bbs_cli_args *a)
{
	struct sni *s;

	if (!ssl_is_available) {
		bbs_dprintf(a->fdout, "No server certificates are configured\n");
		return -1;
	}

	bbs_dprintf(a->fdout, "%-20s %-16s %-16s %-16s %s\n", "Hostname", "Modified", "Issued", "Expires", "Cert:Key Files");

	/* Default cert */
	print_cert_info(a->fdout, NULL, ssl_ctx, ssl_cert, ssl_key);

	RWLIST_RDLOCK(&sni_certs);
	RWLIST_TRAVERSE(&sni_certs, s, entry) {
		print_cert_info(a->fdout, s->hostname, s->ctx, s->certfile, s->keyfile);
	}
	RWLIST_UNLOCK(&sni_certs);
	return 0;
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

static int locks_initialized = 0;

/*! \brief Limited support for reloading configuration (e.g. new certificates) */
static int tlsreload(int fd)
{
	struct tls_client *t;

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

	RWLIST_WRLOCK(&tls_clients);
	RWLIST_TRAVERSE(&tls_clients, t, entry) {
		if (t->client) {
			continue; /* Clients are fine, they don't use any permanent ctx, they just make their own temporarily during the connection. */
		}
		break;
	}
	if (t) { /* At least server session exists */
		bbs_dprintf(fd, "TLS may not be reloaded while any server sessions are in use. Kick any TLS sessions and try again.\n");
		RWLIST_UNLOCK(&tls_clients);
		bbs_rwlock_unlock(&ssl_cert_lock);
		return -1;
	}

	ssl_is_available = 0; /* Ensure any new connections are rejected until we're done reloading. */
	RWLIST_UNLOCK(&tls_clients); /* tls_cleanup will lock the list again, so unlock it for now. XXX It's a different lock though, so could unlock after? */

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

/*! \brief Dump TLS sessions */
static int cli_tls(struct bbs_cli_args *a)
{
	int i = 0;
	int x = 0;
	struct tls_client *t;

	RWLIST_RDLOCK(&tls_clients);
	RWLIST_TRAVERSE(&tls_clients, t, entry) {
		int readpipe, writepipe;
		i++;
		x++;
		readpipe = t->readpipe[1]; /* Write end of read pipe */
		i++;
		writepipe = t->writepipe[0];
		if (i == 2) { /* First one, print header */
			bbs_dprintf(a->fdout, "%3s %4s %16s %16s %-10s %-7s\n", "#", "Type", "TLS", "SSL", "Indices", "FDs");
		}
		bbs_dprintf(a->fdout, "%3d %4s %16p %16p [%3d/%3d] %3d / %3d\n", x, t->client ? "C" : "S", t, t->ssl, i - 1, (i - 1) / 2, readpipe, writepipe);
	}
	RWLIST_UNLOCK(&tls_clients);
	bbs_dprintf(a->fdout, "Polling %d file descriptor%s (%d connection%s)\n", i + 1, ESS(i + 1), i / 2, ESS(i / 2));
	return 0;
}

static int cli_tlsreload(struct bbs_cli_args *a)
{
	return tlsreload(a->fdout);
}

static struct bbs_cli_entry cli_commands_tls[] = {
	BBS_CLI_COMMAND(cli_tls, "tls", 1, "List all TLS sessions", NULL),
	BBS_CLI_COMMAND(cli_tlsreload, "tlsreload", 1, "Reload TLS certificates and configuration", NULL),
	BBS_CLI_COMMAND(cli_tlscerts, "tlscerts", 1, "List TLS certificate configuration", NULL),
};

static int ssl_server_init(void)
{
	bbs_cli_register_multiple(cli_commands_tls);

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

	if (locks_initialized) {
		lock_cleanup();
	}
}

static int setup(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg)
{
	struct tls_client *t;
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
		t = ssl_new_accept(fd, rfd, wfd);
	} else if (dir & TRANSFORM_CLIENT) {
		const char *snihostname = arg;
		t = ssl_client_new(fd, rfd, wfd, snihostname);
	} else {
		/* Can't happen */
		bbs_error("Invalid direction\n");
		return -1;
	}

	if (!t) {
		return -1;
	}

	*data = t; /* Store as transform callback data */
	return 0;
}

static void cleanup(struct bbs_io_transformation *tran)
{
	struct tls_client *t = tran->data;
	bbs_assert_exists(t);
	ssl_close(t);
}

static int query(struct bbs_io_transformation *tran, int query, void *data)
{
	struct tls_client *t = tran->data;
	int *result = data;

	switch (query) {
	case TRANSFORM_QUERY_TLS_REUSE:
		*result = SSL_session_reused(t->ssl);
		break;
	default:
		bbs_warning("Unknown query type: %d\n", query);
		return -1;
	}
	return 0;
}

static struct bbs_io_transformer_functions funcs = {
	.setup = setup,
	.query = query,
	.poll_init = poll_init,
	.io_read_pending = io_read_pending,
	.io_read = io_read,
	.io_write = io_write,
	.io_finalize = io_finalize,
	.cleanup = cleanup,
};

static int load_module(void)
{
	if (ssl_server_init()) {
		bbs_error("Failed to initialize TLS\n");
		ssl_server_shutdown();
		return -1;
	}
	/* If we loaded server configuration, allow TLS as both server/client. Otherwise, just client. */
	if (bbs_io_transformer_register("TLS", &funcs, TRANSFORM_TLS_ENCRYPTION, ssl_is_available ? TRANSFORM_SERVER_CLIENT_TX_RX : (TRANSFORM_CLIENT_TX | TRANSFORM_CLIENT_RX))) {
		ssl_server_shutdown();
		return -1;
	}
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	return 0;
}

static int unload_module(void)
{
	bbs_io_transformer_unregister("TLS");

	/* This module should be reffed for each I/O transformation using it,
	 * but also double check to be sure. */
	RWLIST_WRLOCK(&tls_clients);
	if (!RWLIST_EMPTY(&tls_clients)) {
		RWLIST_UNLOCK(&tls_clients);
		bbs_warning("TLS connections are still active, declining to unload\n");
		return -1;
	}
	RWLIST_UNLOCK(&tls_clients);

	ssl_server_shutdown();
	return 0;
}

/* Since most network modules will use ssl_available() to check for TLS availability
 * when they load, we should be loaded before any of them are: */
BBS_MODULE_INFO_FLAGS("TLS (Transport Layer Security)", MODFLAG_ALWAYS_PRELOAD);
