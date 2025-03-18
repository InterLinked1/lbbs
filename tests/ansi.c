/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief ANSI helpers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "ansi.h"

#include <stdio.h>

int test_ansi_handshake(int clientfd)
{
	static char tmpbuf[64];
	int bytes;

	FMT_EXPECT(TERM_CURSOR_POS_QUERY);
	SEND_CURSOR_POS(3, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_RESET_LINE */
	SEND_CURSOR_POS(6, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_UP_ONE_LINE */
	SEND_CURSOR_POS(5, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_COLOR_GREEN */
	SEND_CURSOR_POS(5, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_TITLE_FMT */
	SEND_CURSOR_POS(5, 1);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_CURSOR_POS_SET_FMT */
	SEND_CURSOR_POS(4, 6);
	FMT_EXPECT(TERM_CURSOR_POS_QUERY); /* After TERM_CLEAR */
	SEND_CURSOR_POS(1, 1);

	return 0;

cleanup:
	return -1;
}
