/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief ANSI helpers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define FMT_EXPECT(fmt, ...) \
	sprintf(tmpbuf, fmt, ## __VA_ARGS__); \
	CLIENT_EXPECT_EVENTUALLY(clientfd, tmpbuf);

#define FMT_SEND(fmt, ...) \
	bytes = sprintf(tmpbuf, fmt, ## __VA_ARGS__); \
	write(clientfd, tmpbuf, (size_t) bytes);

#define SEND_CURSOR_POS(n, m) \
	bytes = sprintf(tmpbuf, "\e[%d;%dR", n, m); \
	write(clientfd, tmpbuf, (size_t) bytes);

int test_ansi_handshake(int clientfd);
