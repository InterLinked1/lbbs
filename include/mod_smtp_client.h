/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023-2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief SMTP client
 *
 * \note This is a somewhat low-level SMTP client, which mainly abstracts the process
 *       of connecting to an SMTP server. It does not operate at the level of
 *       "sending a message" or things like that. Other modules build on top of this to do that.
 *       This is one layer high level than the bbs_tcp_client, but still lower than an application layer.
 *
 */

#define SMTP_EXPECT(smtpclient, ms, str) \
	res = bbs_tcp_client_expect(&(smtpclient)->client, "\r\n", 1, ms, str); \
	if (res) { bbs_warning("Expected '%s', returned %d, got: %s\n", str, res, (smtpclient)->client.rldata.buf); goto cleanup; } else { bbs_debug(9, "Found '%s': %s\n", str, (smtpclient)->client.rldata.buf); }

#define bbs_smtp_client_send(smtpclient, fmt, ...) bbs_tcp_client_send(&(smtpclient)->client, fmt, ## __VA_ARGS__); bbs_debug(3, " => " fmt, ## __VA_ARGS__);

#define SMTP_CAPABILITY_STARTTLS (1 << 0)
#define SMTP_CAPABILITY_PIPELINING (1 << 1)
#define SMTP_CAPABILITY_8BITMIME (1 << 2)
#define SMTP_CAPABILITY_ENHANCEDSTATUSCODES (1 << 3)
#define SMTP_CAPABILITY_ETRN (1 << 4)
#define SMTP_CAPABILITY_AUTH_LOGIN (1 << 5)
#define SMTP_CAPABILITY_AUTH_PLAIN (1 << 6)
#define SMTP_CAPABILITY_AUTH_XOAUTH2 (1 << 7)

struct bbs_smtp_client {
	struct bbs_tcp_client client;
	struct bbs_url url;
	const char *helohost;	/*!< Hostname to use for HELO/EHLO */
	const char *hostname;	/*!< Hostname of remote SMTP server */
	int caps;				/*!< Capabilities supported by remote SMTP server */
	int maxsendsize;		/*!< Maximum size of messages accepted by remote SMTP server */
	unsigned int secure:1;	/*!< Connection is secure */
};

/*!
 * \brief Initialize and connect to a remote SMTP server
 * \param[out] smtpclient
 * \param helohost Hostname to use for HELO/EHLO. Must remain valid pointer for duration of SMTP client session.
 * \param hostname Server hostname. Must remain valid pointer for duration of SMTP client session.
 * \param port Server port
 * \param secure Whether to use implicit TLS
 * \param buf Readline buffer to use
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 */
int bbs_smtp_client_connect(struct bbs_smtp_client *smtpclient, const char *helohost, const char *hostname, int port, int secure, char *buf, size_t len);

/*! \brief Await a final SMTP response code */
int bbs_smtp_client_expect_final(struct bbs_smtp_client *restrict smtpclient, int ms, const char *code, size_t codelen);

#define SMTP_CLIENT_EXPECT_FINAL(smtpclient, ms, code) if ((res = bbs_smtp_client_expect_final(smtpclient, ms, code, STRLEN(code)))) { goto cleanup; }

/*!
 * \brief Handshake with an SMTP server, parsing its advertised capabilities
 * \param smtpclient
 * \param Whether to require a secure connection (e.g. STARTTLS)
 */
int bbs_smtp_client_handshake(struct bbs_smtp_client *restrict smtpclient, int require_secure);

/*!
 * \brief Perform STARTTLS on an SMTP connection (explicit TLS)
 * \param smtpclient
 * \retval 0 on success
 * \retval -1 STARTTLS unavailable, connection already encrypted, or TLS failure
 */
int bbs_smtp_client_starttls(struct bbs_smtp_client *restrict smtpclient);

/*!
 * \brief Destroy an SMTP client
 * \param smtpclient
 */
void bbs_smtp_client_destroy(struct bbs_smtp_client *restrict smtpclient);
