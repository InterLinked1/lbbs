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
 * \brief Alertpipe
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <unistd.h>
#include <string.h>
#include <sys/eventfd.h> /* use eventfd */
#include <stdint.h> /* use uint64_t */
#include <fcntl.h> /* use O_NONBLOCK */
#include <poll.h>

#include "include/alertpipe.h"

ssize_t bbs_alertpipe_write(int alert_pipe[2])
{
	uint64_t tmp = 1;
	bbs_assert(alert_pipe[1] != -1);
	return write(alert_pipe[1], &tmp, sizeof(tmp)) != sizeof(tmp);
}

int bbs_alertpipe_read(int alert_pipe[2])
{
	uint64_t tmp;

	bbs_assert(alert_pipe[0] != -1);
	if (read(alert_pipe[0], &tmp, sizeof(tmp)) < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			bbs_error("read() failed: %s\n", strerror(errno));
			return -1;
		}
	}

	return 0;
}

int bbs_alertpipe_create(int alert_pipe[2])
{
	/* Prefer eventfd to pipe since it's more efficient (only 1 fd needed, rather than 2) */
	int fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
	if (fd > -1) {
		alert_pipe[0] = alert_pipe[1] = fd;
		return 0;
	}
	bbs_warning("Failed to create alert pipe with eventfd(), falling back to pipe(): %s\n", strerror(errno));
	bbs_alertpipe_clear(alert_pipe);
	if (pipe2(alert_pipe, O_NONBLOCK)) {
		bbs_error("Failed to create alert pipe: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_alertpipe_close(int alert_pipe[2])
{
	if (alert_pipe[0] == -1 && alert_pipe[1] == -1) {
		bbs_error("Alert pipe is already closed\n");
		return -1;
	}
	if (alert_pipe[0] == alert_pipe[1]) {
		/* eventfd */
		close_if(alert_pipe[0]);
	} else {
		/* pipe2 */
		close_if(alert_pipe[0]);
		close_if(alert_pipe[1]);
	}
	bbs_alertpipe_clear(alert_pipe);
	return 0;
}

int bbs_alertpipe_poll(int alert_pipe[2], int ms)
{
	int res;
	for (;;) {
		struct pollfd pfd = { alert_pipe[0], POLLIN, 0 };
		res = poll(&pfd, 1, ms);
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (pfd.revents) {
			return 1;
		}
	}
	return res;
}
