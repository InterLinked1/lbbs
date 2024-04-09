/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief High-level TCP client
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/io.h"

struct bbs_url;

struct bbs_tcp_client {
	char *buf;
	size_t len;
	struct readline_data rldata;
	int fd;
	int rfd;
	int wfd;
	struct bbs_io_transformations trans; /*!< I/O transformations */
	unsigned int secure:1;
};

/*! \brief Clean up a TCP client */
void bbs_tcp_client_cleanup(struct bbs_tcp_client *client);

/*!
 * \brief Establish a TCP client connection to a server
 * \param[out] client This is filled in, but memset this to 0 first.
 * \param url Server address
 * \param secure Whether to use implicit TLS when establishing the connection
 * \param buf Buffer for readline operations
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 */
int bbs_tcp_client_connect(struct bbs_tcp_client *client, struct bbs_url *url, int secure, char *buf, size_t len);

/*!
 * \brief Perform STARTTLS on a TCP client
 * \param client
 * \param hostname
 * \retval 0 on success, -1 on failure
 * \note The readline buffer is reset on success to prevent response injection attacks
 */
int bbs_tcp_client_starttls(struct bbs_tcp_client *client, const char *hostname);

/*!
 * \brief Send data on a TCP client connection
 * \param client
 * \param fmt printf-style format string
 * \retval same as write
 */
ssize_t bbs_tcp_client_send(struct bbs_tcp_client *client, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3))) ;

/*!
 * \brief Expect a response containing a substring on a TCP connection
 * \param client
 * \param delim Delimiter to use for readline operations (CR LF is typical)
 * \param attempts Maximum number of responses (typically lines) that will be parsed. Typically 1.
 * \param ms argument to poll()
 * \param str Substring to expect
 * \retval 0 on success (substring contained in response), -1 on failure, 1 if max attempts reached
 */
int bbs_tcp_client_expect(struct bbs_tcp_client *client, const char *delim, int attempts, int ms, const char *str);
