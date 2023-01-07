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
 * \brief Socket functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <arpa/inet.h> /* use inet_ntop */
#include <poll.h>

/* #define DEBUG_TEXT_IO */

#ifdef DEBUG_TEXT_IO
#include <ctype.h>
#endif

/* Generic socket functions are in utils.h */
#include "include/utils.h"
/* Most node specific functions are in node.h */
#include "include/node.h"

#include "include/term.h" /* use bbs_unbuffer */

int bbs_make_tcp_socket(int *sock, int port)
{
	struct sockaddr_in sinaddr; /* Internet socket */
	const int enable = 1;

	*sock = socket(AF_INET, SOCK_STREAM, 0);
	if (*sock < 0) {
		bbs_error("Unable to create TCP socket: %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		bbs_error("Unable to create setsockopt: %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
		bbs_error("Unable to create setsockopt: %s\n", strerror(errno));
		return -1;
	}
	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr.s_addr=INADDR_ANY;
	sinaddr.sin_port = htons(port); /* Public TCP port on which to listen */

	if (bind(*sock, (struct sockaddr *)&sinaddr, sizeof(sinaddr))) {
		bbs_error("Unable to bind TCP socket to port %d: %s\n", port, strerror(errno));
		close(*sock);
		*sock = -1;
		return -1;
	}
	if (listen(*sock, 2) < 0) {
		bbs_error("Unable to listen on TCP socket on port %d: %s\n", port, strerror(errno));
		close(*sock);
		*sock = -1;
		return -1;
	}
	bbs_debug(1, "Started %s listener on port %d\n", "TCP", port);
	return 0;
}

void bbs_tcp_comm_listener(int socket, const char *name, int (*handshake)(struct bbs_node *node), void *module)
{
	struct sockaddr_in sinaddr;
	socklen_t len;
	int sfd, res;
	struct pollfd pfd;
	struct bbs_node *node;

	pfd.fd = socket;
	pfd.events = POLLIN;

	bbs_debug(1, "Started %s listener thread\n", name);

	for (;;) {
		res = poll(&pfd, 1, -1); /* Wait forever for an incoming connection. */
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (pfd.revents) {
			bbs_debug(1, "Accepting new %s connection\n", name);
			len = sizeof(sinaddr);
			sfd = accept(socket, (struct sockaddr *) &sinaddr, &len);
		} else {
			continue; /* Shouldn't happen? */
		}
		if (sfd < 0) {
			if (errno != EINTR) {
				bbs_warning("accept returned %d: %s\n", sfd, strerror(errno));
				break;
			}
			continue;
		}

		node = __bbs_node_request(sfd, name, module);
		if (!node) {
			close(sfd);
			continue;
		}
		if (bbs_save_remote_ip(&sinaddr, node)) {
			bbs_node_unlink(node);
			continue;
		}
		if (handshake(node)) {
			bbs_node_unlink(node);
			continue;
		}

		/* Run the BBS on this node */
		if (bbs_pthread_create_detached(&node->thread, NULL, bbs_node_handler, node)) {
			bbs_node_unlink(node);
			continue;
		}
	}
	/* Normally, we never get here, as pthread_cancel snuffs out the thread ungracefully */
	bbs_warning("%s listener thread exiting abnormally\n", name);
}

int bbs_get_remote_ip(struct sockaddr_in *sinaddr, char *buf, size_t len)
{
	struct in_addr ip_addr = sinaddr->sin_addr;
	inet_ntop(AF_INET, &ip_addr, buf, len);
	return 0;
}

int bbs_save_remote_ip(struct sockaddr_in *sinaddr, struct bbs_node *node)
{
	char addrstr[64];

	bbs_get_remote_ip(sinaddr, addrstr, sizeof(addrstr));
	node->ip = strdup(addrstr);
	if (!node->ip) {
		bbs_error("Failed to duplicate IP address '%s'\n", addrstr);
		return -1;
	}
	return 0;
}

const char *poll_revent_name(int revents)
{
	if (revents & POLLIN) {
		return "POLLIN";
	} else if (revents & POLLPRI) {
		return "POLLPRI";
	} else if (revents & POLLOUT) {
		return "POLLOUT";
	} else if (revents & POLLRDHUP) {
		return "POLLRDHUP";
	} else if (revents & POLLERR) {
		return "POLLERR";
	} else if (revents & POLLHUP) {
		return "POLLHUP";
	} else if (revents & POLLNVAL) {
		return "POLLNVAL";
	}
	bbs_assert(0);
	return NULL;
}

/* XXX This duplicates code, we should combine core logic of bbs_std_poll and bbs_poll */
int bbs_std_poll(int fd, int ms)
{
	struct pollfd pfd;
	int res;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	for (;;) {
		res = poll(&pfd, 1, ms);
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (res > 0) {
			if (!pfd.revents) {
				bbs_error("poll returned %d but no revents?\n", res);
			} else if (!(pfd.revents & POLLIN)) {
				if (pfd.revents & BBS_POLL_QUIT) {
					bbs_debug(1, "poll returned %d but got %s?\n", res, poll_revent_name(pfd.revents));
					res = -1; /* override to -1 since fd is closed */
					break;
				}
				bbs_error("poll returned %d but got %s?\n", res, poll_revent_name(pfd.revents));
			}
			break;
		}
		break;
	}
	bbs_debug(10, "poll returned %d\n", res);
	return res;
}

/* XXX For INTERNAL_POLL_THRESHOLD stuff, if ms == -1, instead of asserting, just set ms to INT_MAX or loop forever, internally */

/* XXX bbs_poll should really use bbs_multi_poll internally to avoid duplicating code. Might be a tiny performance hit? */
static int bbs_multi_poll(struct pollfd pfds[], int numfds, int ms)
{
	int i, res;

	/* Finish initializing pfds (hopefully the caller set the fds!) */
	for (i = 0; i < numfds; i++) {
		pfds[i].events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
		pfds[i].revents = 0;
	}

	for (;;) {
		/* XXX If the pty master thread closes the slavefd,
		 * we won't see that until the poll expires, for some reason,
		 * at which point it will return 1, with POLLNVAL.
		 * To speed this up, if ms is larger than some threshold (say 15 seconds),
		 * do a loop with 1 poll call every 15 seconds up to the ms timer.
		 * Of course, more optimal would be to figure out how to get poll to return
		 * immediately when the slavefd has been closed.
		 * For now, this is a good compromise.
		 */

/* A smaller threshold means less time for stale connections to persist.
 * However, this comes at the cost of efficiency.
 * So we pick something that's small enough for a good user experience,
 * (allows dead nodes to be reaped relatively quickly)
 * but large enough to be adequately efficient.
 */
#define INTERNAL_POLL_THRESHOLD SEC_MS(15)
		if (ms > INTERNAL_POLL_THRESHOLD) {
			int msleft = ms;
			for (;;) {
				res = poll(pfds, numfds, MIN(msleft, INTERNAL_POLL_THRESHOLD));
				if (res == 0 && msleft > INTERNAL_POLL_THRESHOLD) {
					msleft -= INTERNAL_POLL_THRESHOLD;
#ifdef EXTRA_DEBUG
					bbs_debug(10, "Internal poll elapsed with no activity, %d ms left (will poll(%d))\n", msleft, MIN(msleft, INTERNAL_POLL_THRESHOLD));
#endif
					continue; /* Call poll again */
				} /* else, something happened, fall through */
				break;
			}
		} else {
			res = poll(pfds, numfds, ms);
		}
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (res > 0) {
			/* Check all the polled fds to see what happened */
			for (i = 0; i < numfds; i++) {
				if (pfds[i].revents) {
					res = i + 1; /* Return 1-indexed pfd with activity */
#ifdef EXTRA_DEBUG
					bbs_debug(10, "Got revent %s on pfds[%d]\n", poll_revent_name(pfds[i].revents), i);
#endif
					if (!(pfds[i].revents & POLLIN)) {
						if (pfds[i].revents & BBS_POLL_QUIT) {
							bbs_debug(1, "poll returned %d but got %s\n", res, poll_revent_name(pfds[i].revents));
							res = -1; /* override to -1 since fd is closed */
							break;
						}
						bbs_error("poll returned %d but got %s?\n", res, poll_revent_name(pfds[i].revents));
					}
					break;
				}
			}
			break;
		}
		break;
	}
#ifdef EXTRA_DEBUG
	bbs_debug(10, "multipoll returned %d on pfd %d\n", res, i);
#endif
	return res;
}

/*! \note fd is the last arg in case in the future, we want to expand this to accept variadic args of fds */
int bbs_poll2(struct bbs_node *node, int ms, int fd)
{
	struct pollfd pfds[2];

	bbs_assert(node->fd != -1);

	/* Watch for data written from the master end of the PTY to the slave end. */
	/* The lock/unlock to get node->slavefd here is a little silly. It just makes helgrind happy. */
	bbs_node_lock(node);
	pfds[0].fd = node->slavefd;
	bbs_node_unlock(node);
	pfds[1].fd = fd;

	return bbs_multi_poll(pfds, 2, ms);
}

int bbs_poll(struct bbs_node *node, int ms)
{
	struct pollfd pfd;
	int res;

	bbs_assert(node->fd != -1);

	/* We should never be polling indefinitely for a BBS node. */
	bbs_assert(ms >= 0);

	/* Watch for data written from the master end of the PTY to the slave end. */
	/* The lock/unlock to get node->slavefd here is a little silly. It just makes helgrind happy. */
	bbs_node_lock(node);
	pfd.fd = node->slavefd;
	bbs_node_unlock(node);
	pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	for (;;) {
		/* XXX If the pty master thread closes the slavefd,
		 * we won't see that until the poll expires, for some reason,
		 * at which point it will return 1, with POLLNVAL.
		 * To speed this up, if ms is larger than some threshold (say 15 seconds),
		 * do a loop with 1 poll call every 15 seconds up to the ms timer.
		 * Of course, more optimal would be to figure out how to get poll to return
		 * immediately when the slavefd has been closed.
		 * For now, this is a good compromise.
		 */

/* A smaller threshold means less time for stale connections to persist.
 * However, this comes at the cost of efficiency.
 * So we pick something that's small enough for a good user experience,
 * (allows dead nodes to be reaped relatively quickly)
 * but large enough to be adequately efficient.
 */
#define INTERNAL_POLL_THRESHOLD SEC_MS(15)
		if (ms > INTERNAL_POLL_THRESHOLD) {
			int msleft = ms;
			for (;;) {
				res = poll(&pfd, 1, MIN(msleft, INTERNAL_POLL_THRESHOLD));
				if (res == 0 && msleft > INTERNAL_POLL_THRESHOLD) {
					msleft -= INTERNAL_POLL_THRESHOLD;
#if 0
					bbs_debug(10, "Internal poll elapsed with no activity, %d ms left (will poll(%d))\n", msleft, MIN(msleft, INTERNAL_POLL_THRESHOLD));
#endif
					continue; /* Call poll again */
				} /* else, something happened, fall through */
				break;
			}
		} else {
			res = poll(&pfd, 1, ms);
		}
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (res > 0) {
			if (!pfd.revents) {
				bbs_error("Node %d: poll returned %d but no revents?\n", node->id, res);
			} else if (!(pfd.revents & POLLIN)) {
				if (pfd.revents & BBS_POLL_QUIT) {
					bbs_debug(1, "Node %d: poll returned %d but got %s\n", node->id, res, poll_revent_name(pfd.revents));
					res = -1; /* override to -1 since fd is closed */
					break;
				}
				bbs_error("Node %d: poll returned %d but got %s?\n", node->id, res, poll_revent_name(pfd.revents));
			}
			break;
		}
		break;
	}
	bbs_debug(10, "Node %d: poll returned %d\n", node->id, res);
	return res;
}

int bbs_tpoll(struct bbs_node *node, int ms)
{
	int everwarned = 0, warned = 0, res = 0;
	int wasbuffered = node->buffered; /* We could be buffered or unbuffered, with echo or without */
	int hadecho = node->echo;
	int pollms = ms;
	int attempts = 0;

	bbs_assert(ms > 0); /* There would be no reason to use bbs_tpoll over bbs_poll unless ms > 0. */

	/* If the poll is long enough, we do a preliminary poll first.
	 * If this poll expires, give the user a warning that s/he's about to be disconnected.
	 * Then, if the next poll expires, actually disconnect.
	 */

/*! \brief If doing a warning, how long before disconnect we should warn. */
#define MIN_WARNING_MS SEC_MS(30)

/*! \brief Minimum amount of poll time (ms) for which we should even bother doing a warning.
 * Polls shorter than this will expire with no warning.
 * Should be at least twice the warning time, or the warning would be triggered before even half the poll is done, which makes no sense.
 */
#define MIN_POLL_MS_FOR_WARNING 2 * MIN_WARNING_MS

	for (;;) {
		if (++attempts > 1) {
			bbs_debug(6, "tpoll iteration %d (%d ms)\n", attempts, pollms);
		}
		ms = pollms;
		warned = 0;
		if (ms >= MIN_POLL_MS_FOR_WARNING) {
			/* Wait until there's MIN_WARNING_MS ms left. */
			res = bbs_poll(node, ms - MIN_WARNING_MS);
			if (!res) {
				bbs_debug(8, "Node %d has been inactive for %d ms, warning\n", node->id, ms - MIN_WARNING_MS);
				bbs_verb(5, "Node %d is at imminent risk of timing out\n", node->id);
				if (everwarned) {
					/* If already warned, don't keep adding more new lines. */
					bbs_clear_line(node);
					NEG_RETURN(bbs_writef(node, "\r"));
				} else {
					/* Don't begin with \r because we may not necessarily want to erase current line. */
					/* On the contrary, start with a LF for safety, since bbs_wait_key for example doesn't end in LF.
					 * Finally, don't end with a LF. */
					NEG_RETURN(bbs_writef(node, "\n"));
				}
				NEG_RETURN(bbs_writef(node, "%sAre you still there? []%s", COLOR(COLOR_RED), COLOR_RESET));
				/* Ring the bell to get the user's attention. */
				NEG_RETURN(bbs_ring_bell(node));
				ms = MIN_WARNING_MS;
				everwarned = warned = 1;
				/* If wasbuffered, then we don't actually know if the next bbs_poll returned 1
				 * because the user started typing and stopped before hitting ENTER (and the timer went off),
				 * or because the user responded to the "Are you still there?".
				 * As a result, we need to check if the buffer has data when we put
				 * the terminal into noncanonical mode, before polling, so we know which of the 2 cases is true.
				 *
				 * We don't actually need to call poll with 0 to check, we can just flush the buffer here,
				 * as well as below. This guarantees that the next bbs_poll won't return immediately
				 * because of data that was present in the buffer prior to the warning, simply
				 * because we changed to noncanonical mode.
				 */
				bbs_unbuffer(node); /* Non-canonical mode for warning response, no echo */
				NEG_RETURN(bbs_flush_input(node));
			}
		}

		/* This is the first poll if <= MIN_POLL_MS_FOR_WARNING, and possibly if >. */
		if (!res) {
			res = bbs_poll(node, ms);
			if (res > 0 && warned) {
				/* This was a response to the "Are you still there?" prompt, not whatever the BBS was doing.
				 * Flush the response to ignore everything pending in the input buffer.
				 * (If we were in canonical mode, there could be more than 1 byte to flush.)
				 */
				NEG_RETURN(bbs_flush_input(node));
				/* Ate response, now start over */
				if (wasbuffered) {
					bbs_clear_line(node); /* Erase prompt */
					NEG_RETURN(bbs_writef(node, "\r"));
					bbs_buffer_input(node, hadecho); /* Canonical mode, same echo */
				}
				continue; /* Start the poll over again, now that the user confirmed s/he's still there */
			} else if (!res && warned && wasbuffered) {
				bbs_buffer_input(node, hadecho); /* Restore before continuing */
			}
		}
		break;
	}

	if (ms && res == 0) {
		/* Write directly to the socket fd instead of using the PTY fd,
		 * because otherwise the node might shut everything down before
		 * the PTY master thread has time to relay it to the socket fd.
		 *
		 * Note that because we're writing directly to the socket fd,
		 * we must do CR LF, not just LF.
		 */
		SWRITE(node->fd, COLOR_RESET "\r\nYou've been inactive too long.\r\n");
		bbs_verb(4, "Node %d timed out due to inactivity\n", node->id);
	}
	return res;
}

int bbs_read(struct bbs_node *node, char *buf, size_t len)
{
	int res;

	bbs_assert(node->slavefd != -1);

	bbs_node_lock(node);
	res = read(node->slavefd, buf, len);
	bbs_node_unlock(node);
	if (res <= 0) {
		bbs_debug(5, "Node %d: read returned %d\n", node->id, res);
	}

	if (res == 1) {
		bbs_debug(10, "Node %d: read %d byte (%d)\n", node->id, res, *buf);
	} else {
		bbs_debug(10, "Node %d: read %d bytes\n", node->id, res);
	}
	return res;
}

int bbs_poll_read(struct bbs_node *node, int ms, char *buf, size_t len)
{
	int res = bbs_poll(node, ms);
	if (res <= 0) {
		return res;
	}
	res = bbs_read(node, buf, len);
	return res;
}

int bbs_fd_poll_read(int fd, int ms, char *buf, size_t len)
{
	int res = bbs_std_poll(fd, ms);
	if (res <= 0) {
		return res;
	}
	res = read(fd, buf, len);
	return res;
}

static char bbs_fd_tread(int fd, int ms)
{
	char res;

	bbs_assert(ms > 0); /* There would be no reason to use bbs_tpoll over bbs_poll unless ms > 0. */
	res = bbs_std_poll(fd, ms);

	if (res > 0) {
		char buf[1];
		res = read(fd, buf, sizeof(buf));
		if (res <= 0) {
			return res;
		}
		return buf[0]; /* Return the char that was read */
	}
	return res;
}

char bbs_tread(struct bbs_node *node, int ms)
{
	char res;

	bbs_assert(ms > 0); /* There would be no reason to use bbs_tpoll over bbs_poll unless ms > 0. */
	res = bbs_tpoll(node, ms);

	if (res > 0) {
		char buf[1];
		res = bbs_read(node, buf, sizeof(buf));
		if (res <= 0) {
			return res;
		}
		return buf[0]; /* Return the char that was read */
	}
	return res;
}

/*!
 * \retval -1 node disconnected
 * \retval 0 ESC (just the ESC key, no escape sequence)
 * \retval positive escape sequence code
 */
static int __bbs_read_escseq(struct bbs_node *node, int fd)
{
	/* We can't just declare a variable pointing to the right function to use, since their arguments are of different types (node vs int). Use a macro instead. */
#define bbs_proper_tread(node, fd, ms) node ? bbs_tread(node, ms) : bbs_fd_tread(fd, ms)

	char c1, c2, c3;
	/* We already read ESC (27). Try to read further characters. */
	c1 = bbs_proper_tread(node, fd, 10); /* 10ms ought to be more than enough. We should really get everything at once. */
	if (c1 <= 0) {
		return c1 < 0 ? c1 : KEY_ESC;
	}
	switch (c1) {
		case 91:
			c2 = bbs_proper_tread(node, fd, 10);
			if (c2 <= 0) {
				return c2;
			}
			switch (c2) {
				case 49:
					c3 = bbs_proper_tread(node, fd, 10);
					if (c3 <= 0) {
						return c3 < 0 ? c3 : KEY_HOME;
					}
					switch (c3) {
						/* F function keys */
						case 49 ... 53:
							return KEY_F(1 + c3 - 49); /* F1 to F5 */
						/* 54 is skipped */
						case 55 ... 57:
							return KEY_F(6 + c3 - 55); /* F6 to F8 */
						default:
							bbs_debug(3, "Unhandled escape sequence: %d %d\n", c1, c2);
							break;
					}
					break;
				case 50:
					c3 = bbs_proper_tread(node, fd, 2);
					if (c3 <= 0) {
						return c3 < 0 ? c3 : KEY_IC; /* INSERT */
					}
					switch (c3) {
						case 48 ... 49:
							return KEY_F(9 + c3 - 48); /* F9 to F10 */
						/* Skip 50 */
						case 51 ... 52:
							return KEY_F(11 + c3 - 51); /* F11 to F12 */
						default:
							bbs_debug(3, "Unhandled escape sequence: %d %d\n", c1, c2);
							break;
					}
					break;
				case 51:
					return KEY_DC; /* DELETE */
				case 52:
					return KEY_END;
				case 53:
					return KEY_PPAGE; /* PG UP */
				case 54:
					return KEY_NPAGE; /* PG DOWN */
				case 65:
					return KEY_UP;
				case 66:
					return KEY_DOWN;
				case 67:
					return KEY_RIGHT;
				case 68:
					return KEY_LEFT;
				default:
					bbs_debug(3, "Unhandled escape sequence: %d %d\n", c1, c2);
					break;
			}
			break;
		default:
			bbs_debug(3, "Unhandled escape sequence: %d\n", c1);
			break;
	}
	return 0;
#undef bbs_proper_tread
}

int bbs_fd_read_escseq(int fd)
{
	int res = __bbs_read_escseq(NULL, fd);
	if (res > 0) {
		bbs_debug(5, "Escape sequence converted to %d\n", res);
	}
	return res;
}

int bbs_read_escseq(struct bbs_node *node)
{
	int res = __bbs_read_escseq(node, -1);
	return res;
}

int bbs_readline(struct bbs_node *node, int ms, char *buf, size_t len)
{
#ifdef DEBUG_TEXT_IO
	int i;
#endif
	int res;
	int bytes_read = 0;
	char *startbuf = buf;
	char *term = NULL;
	char *nterm = 0;
	int keep_trying = 0;

	bbs_assert(node->slavefd != -1);

	/* Do not call bbs_buffer(node) here,
	 * calling functions should do that if needed.
	 * This allows to read with echo on or off (e.g. passwords),
	 * we don't know what's appropriate here. */

	for (;;) {
		if (keep_trying) {
			res = bbs_poll(node, 5);
			if (res == 0) {
				/* It's okay, we were just checking to see if there was more input,
				 * (remember we set ms to be very small)
				 * if there's not, proceed with what we got. */
				break;
			}
		} else {
			res = bbs_tpoll(node, ms);
		}
		if (res <= 0) {
			bbs_debug(10, "Node %d: poll returned %d\n", node->id, res);
			return res;
		}
		res = read(node->slavefd, buf, len);
		if (res <= 0) {
			bbs_debug(10, "Node %d: read returned %d\n", node->id, res);
			return res;
		}
		nterm = memchr(buf, '\0', res);
		/* Telnet may send CR NUL or CR LF, so check CR first, then LF.
		 * To make things even more confusing, Windows Telnet and SyncTERM seem to send LF LF.
		 * (Though it could be the PTY line discipline converting things that results in this)
		 * We want to be able to handle CR (NUL), CR LF, LF LF, and LF successfully.
		 * If we see either CR or LF, terminate the buffer there.
		 */

		/*! \todo BUGBUG Still lots of inconsistencies.
		 * On Windows Telnet and in SyncTERM, we get extra lines inbetween carriage returns.
		 * In PuTTY with Telnet, there are ^@'s at the beginning of lines after this function returns.
		 */
		if (!term) { /* In the case where we poll again for a few ms (below), this will be true, don't do this again. */
			term = memchr(buf, '\r', res); /* There is no strnchr function. Use memchr. */
			if (!term) {
				term = memchr(buf, '\n', res);
			}
		}
		buf += res;
		len -= res;
		bytes_read += res;
#ifdef DEBUG_TEXT_IO
		for (i = 0; i < bytes_read; i++) {
			bbs_debug(10, "read[%d] %d / '%c'\n", i, startbuf[i], isprint(startbuf[i]) ? startbuf[i] : ' ');
		}
#endif
		if (nterm || term || len <= 0) {
			/* Remove any line ending from input. */
			if (term) {
				*term = '\0';
			}
			if (!nterm && term) {
				bbs_debug(2, "Received CR and/or LF from client, but no NUL?\n");
				/* The NUL could be trailing and we might read it next time.
				 * Or maybe there won't be a NUL, certain client+protocols seem to send one, some don't.
				 * If we do get one, we should get the NUL before returning. If we're not going to get one,
				 * then it's probably no biggie.
				 * Poll again for a brief period of time (<5 ms) in case more input is going to be available shortly.
				 */
				keep_trying = 1;
				continue;
			}
			break;
		}
	}

	if (*startbuf == '\0') {
		/* This isn't an issue per se in and of itself,
		 * but probably an irregularity in reading input above. */
		bbs_warning("First character received was NUL?\n"); /* XXX seems to happen if user just presses ENTER immediately */
	}

	bbs_debug(10, "Node %d: read(%d) %.*s\n", node->id, bytes_read, bytes_read, startbuf);
	return bytes_read;
}

int bbs_get_response(struct bbs_node *node, int qlen, const char *q, int pollms, char *buf, int len, int *tries, int minlen, const char *reqchars)
{
	int res;
	int attempt = 1;
	const char *c;

	for (; *tries > 0; *tries -= 1, attempt++) { /* Retries here count less than retries of the main loop */
		if (attempt > 1) {
			bbs_debug(4, "Attempt #%d to get response for question\n", attempt);
		}
		if (qlen) {
			NONPOS_RETURN(bbs_writef(node, "%-*s", qlen, q));
		} else {
			NONPOS_RETURN(bbs_writef(node, "%s", q));
		}
		res = bbs_readline(node, pollms, buf, len);
		/* bbs_readline returns the number of bytes read.
		 * However, in most cases, we'll want to subtract 1, because we null terminated the new line read as input.
		 * Therefore, we can approximate the strlen with res - 1 (so long as res > 0)
		 */
		if (res < 0) {
			return res;
		} else if (res == 0) {
			/* bbs_readline uses bbs_tpoll, so if the tpoll times out (returns 0), then we must return,
			 * as we already printed out "You've been inactive too long" at this point. */
			return -1; /* -1, not 0, we're already due for disconnect. */
		} else if (strlen_zero(buf)) {
			NONPOS_RETURN(bbs_writef(node, "%sPlease try again.%s\n", COLOR(COLOR_RED), COLOR(COLOR_WHITE)));
			continue; /* Empty responses not allowed. Try again, eventually we'll hit max attempts */
		} if (res - 1 < minlen) {
			NONPOS_RETURN(bbs_writef(node, "%sInadequate response, please try again.%s\n", COLOR(COLOR_RED), COLOR(COLOR_WHITE)));
			continue; /* Too short */
		} else if (res - 1 >= len) {
			NONPOS_RETURN(bbs_writef(node, "%sResponse is too long, please try again.%s\n", COLOR(COLOR_RED), COLOR(COLOR_WHITE)));
			continue;
		} else if (!bbs_str_isprint(buf)) {
			/* Contains nonprintable characters. Reject. */
			NONPOS_RETURN(bbs_writef(node, "%sResponse contains invalid characters, please try again.%s\n", COLOR(COLOR_RED), COLOR(COLOR_WHITE)));
			continue;
		}
		if (reqchars) {
			for (c = reqchars; *c; c++) {
				if (!strchr(buf, *c)) {
					NONPOS_RETURN(bbs_writef(node, "%sInadequate response, please try again.%s\n", COLOR(COLOR_RED), COLOR(COLOR_WHITE)));
					/* We're in a double loop, we want to continue the outer loop */
					goto continueloop; /* Missing required chars */
				}
			}
		}
		break;
continueloop:
		continue;
	}
	if (*tries <= 0) {
		bbs_debug(5, "Max attempts reached, disconnecting\n");
		return 1;
	}
	return 0;
}

#ifdef DEBUG_TEXT_IO
static void print_printable(char *s, int len)
{
	int i;

	for (i = 0; i < len; i++, s++) {
		char c = *s;
		if (c < 0) {
			c += 256;
		}
		if (isprint(c)) {
			bbs_debug(10, "STR[%d] => %d (%c)\n", i, c, c);
		} else {
			bbs_debug(10, "STR[%d] => %d\n", i, c);
		}
	}
}
#endif

int bbs_std_flush_input(int fd)
{
	char buf[64];
	int res;

	for (;;) {
		/* Poll and read again and again until poll says there's no input waiting. */
		res = bbs_std_poll(fd, 0);
		if (res <= 0) {
			break;
		}
		res = read(fd, buf, sizeof(buf));
		if (res <= 0) {
			break;
		}
		bbs_debug(5, "Flushed %d bytes\n", res);
#ifdef DEBUG_TEXT_IO
		print_printable(buf, res);
#endif
	}
	return res;
}

int bbs_flush_input(struct bbs_node *node)
{
	char buf[64];
	int res;

	for (;;) {
		/* Poll and read again and again until poll says there's no input waiting. */
		res = bbs_poll(node, 0);
		if (res <= 0) {
			break;
		}
		res = bbs_read(node, buf, sizeof(buf));
		if (res <= 0) {
			break;
		}
		bbs_debug(5, "Flushed %d byte%s\n", res, ESS(res));
#ifdef DEBUG_TEXT_IO
		print_printable(buf, res);
#endif
	}
	return res;
}

int bbs_write(struct bbs_node *node, const char *buf, unsigned int len)
{
	int res;
	unsigned int written = 0;
	bbs_assert(node->slavefd != -1);
	for (;;) {
		/* So helgrind doesn't complain about data race if node is shut down
		 * and slavefd closed during write */
		bbs_node_lock(node);
		res = write(node->slavefd, buf, len);
		bbs_node_unlock(node);
		if (res <= 0) {
			bbs_debug(5, "Node %d: write returned %d\n", node->id, res);
			return res;
		}
		buf += res;
		written += res;
		len -= res;
		if (len <= 0) {
			break;
		}
	}
	return written;
}

int __attribute__ ((format (gnu_printf, 2, 3))) bbs_writef(struct bbs_node *node, const char *fmt, ...)
{
	char *buf;
	int len, res;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* If the format string doesn't contain any %'s, there are no variadic arguments.
		 * Just write it directly, to avoid allocating memory unnecessarily. */
		return bbs_write(node, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		bbs_error("vasprintf failure\n");
		return -1;
	}

	res = bbs_write(node, buf, len);
	free(buf);
	return res;
}

int bbs_clear_screen(struct bbs_node *node)
{
	return bbs_write(node, TERM_CLEAR, STRLEN(TERM_CLEAR));
}

int bbs_clear_line(struct bbs_node *node)
{
	return bbs_write(node, TERM_RESET_LINE, STRLEN(TERM_RESET_LINE));
}

int bbs_reset_color(struct bbs_node *node)
{
	return bbs_write(node, COLOR_RESET, STRLEN(COLOR_RESET));
}

int bbs_draw_line(struct bbs_node *node, char c)
{
	int i, cols = node->cols ? node->cols : 80; /* Assume 80x24 if not available */
	char buf[384]; /* Avoid cols + 2 for gcc -Wstack-protector */

	if (cols + 2 >= (int) (sizeof(buf) - 1)) {
		bbs_warning("Truncation occured of line for node with %d cols\n", node->cols);
		/* Not fatal */
	}

	for (i = 0; i < cols; i++) {
		buf[i] = c;
	}
	buf[i++] = '\n'; /* New line */
	buf[i] = '\0';
	/* Write all at once */
	return bbs_write(node, buf, cols + 1); /* No need to actually write the NUL, just through the LF */
}

int bbs_ring_bell(struct bbs_node *node)
{
	/* This function should be sparingly used. Users are annoyed if the bell goes off all the time.
	 * So log every time it's used. */
	bbs_debug(7, "Ringing bell for node %d\n", node->id);
	return bbs_write(node, TERM_BELL, STRLEN(TERM_BELL));
}

#define HIT_KEY_PROMPT "Hit a key, any key..."

int bbs_wait_key(struct bbs_node *node, int ms)
{
	bbs_debug(6, "Waiting %d ms for any input\n", ms);
	NEG_RETURN(bbs_unbuffer(node));
	NEG_RETURN(bbs_flush_input(node)); /* Discard anything that may be pending so bbs_tpoll doesn't return immediately. */
	NEG_RETURN(bbs_writef(node, "\r\n%s%s%s", COLOR(COLOR_RED), "[" HIT_KEY_PROMPT "]", COLOR_RESET));

	/* Wait up to ms for any key, doesn't matter what key so discard input if/when received. */
	if (bbs_tpoll(node, ms) <= 0 || bbs_flush_input(node) < 0) {
		return -1;
	}
	return 0;
}
