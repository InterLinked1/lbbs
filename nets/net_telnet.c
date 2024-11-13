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
 * \brief Telnet and TTY/TDD network driver
 *
 * \note Supports RFC 857 Echo
 * \note Supports RFC 858 Suppress Go Ahead
 * \note Supports RFC 1073 Window Size
 * \note Supports RFC 1079 Terminal Speed
 * \note Supports RFC 1091 Terminal Type
 * \note Supports RFC 1116 Line Mode (disabling only)
 * \note Supports RFC 1143 Q Method of Option Negotiation
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */

/* Expose the telcmds and telopts string arrays */
#define TELCMDS
#define TELOPTS
#include "arpa/telnet.h"

#include "include/module.h"
#include "include/node.h"
#include "include/pty.h" /* use bbs_pty_allocate */
#include "include/utils.h"
#include "include/config.h"
#include "include/net.h"

static int telnet_socket = -1, telnets_socket = -1, tty_socket = -1, ttys_socket = -1; /*!< TCP Socket for allowing incoming network connections */
static pthread_t telnet_thread, telnets_thread, tty_thread;

/*! \brief Telnet port is 23 */
#define DEFAULT_TELNET_PORT 23

/*! \brief TELNETS (Telnet over TLS) port is 992 */
#define DEFAULT_TELNETS_PORT 992

static int telnet_port = DEFAULT_TELNET_PORT;
static int telnets_port = DEFAULT_TELNETS_PORT;
static int telnets_enabled = 0;
static int tty_port = 0, ttys_port = 0; /* Disabled by default */

static int telnet_send_command(int fd, unsigned char cmd, unsigned char opt)
{
	unsigned char ctl[] = {IAC, cmd, opt};
	ssize_t res = write(fd, ctl, ARRAY_LEN(ctl));
	if (res <= 0) {
		if (errno != EPIPE) { /* Ignore if client just closed connection immediately */
			bbs_error("Failed to write to Telnet connection: %s\n", strerror(errno));
		}
	} else {
		/* telcmds[0] is EOF (236), so normalize the index to 236 */
		/* telopts[0] is simply 0, so no modification needed */
		bbs_debug(5, "Sent Telnet command: %s %s %s\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt]);
	}
	return res <= 0 ? -1 : 0;
}

static int telnet_send_command6(int fd, unsigned char cmd, unsigned char opt, unsigned char opt2, unsigned char opt3, unsigned char opt4)
{
	unsigned char ctl[] = {IAC, cmd, opt, opt2, opt3, opt4};
	ssize_t res = write(fd, ctl, ARRAY_LEN(ctl));
	if (res <= 0) {
		if (errno != EPIPE) { /* Ignore if client just closed connection immediately */
			bbs_error("Failed to write to Telnet connection: %s\n", strerror(errno));
		}
	} else {
		/* telcmds[0] is EOF (236), so normalize the index to 236 */
		/* telopts[0] is simply 0, so no modification needed */
		bbs_debug(5, "Sent Telnet command: %s %s %s %s %s %s\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt], telopts[opt2], telcmds[opt3 - xEOF], telcmds[opt4 - xEOF]);
	}
	return res <= 0 ? -1 : 0;
}

static int telnet_read_command(int fd, unsigned char *buf, size_t len)
{
	ssize_t res = bbs_poll(fd, 300); /* qodem needs a bit more time to respond to certain requests */
	if (res < 0) {
		bbs_debug(4, "poll returned %ld: %s\n", res, strerror(errno));
		return (int) res;
	} else if (!res) {
		bbs_debug(4, "poll returned 0\n");
		return 0;
	}
	res = read(fd, buf, len - 1);
	/* Process the command */
	if (res <= 0) {
		bbs_debug(4, "read returned %ld: %s\n", res, strerror(errno));
		return (int) res;
	} else if (res >= 3) {
		int a, b, c;
		buf[res] = '\0'; /* Don't read uninitialized memory later */
		if (buf[0] != IAC) {
			/* Got something that wasn't the beginning of a telnet command */
			bbs_debug(3, "Read %d %d %d, aborting handshake\n", buf[0], buf[1], buf[2])
			return 0;
		}
		/* Don't let the client make us index out of bounds */
		if (!TELCMD_OK(buf[0]) || !TELCMD_OK(buf[1])) {
			bbs_warning("Got out of bounds command: %d %d %d\n", buf[0], buf[1], buf[2]);
			return 0;
		}
		if (!TELOPT_OK(buf[2])) {
			bbs_warning("Got out of bounds option: %d %d %d\n", buf[0], buf[1], buf[2]);
			return 0;
		}
		a = buf[0] - xEOF; /* We know this is IAC */
		b = buf[1] - xEOF;
		c = buf[2];
		bbs_assert(telcmds[a] != NULL);
		bbs_assert(telcmds[b] != NULL);
		bbs_assert(telopts[c] != NULL);
		bbs_debug(3, "Received Telnet command %s %s %s\n", telcmds[a], telcmds[b], telopts[c]);
		return (int) res;
	} else {
		bbs_warning("Read %ld bytes, not enough to do anything with, discarding\n", res);
		return 0;
	}
}

/* RFC 1143 Q Method for Option Negotiation (Section 7) */
/* All options are disabled by default, so it is intentional that NO has value 0 for initialization purposes */
enum option_state {
	NO = 0,
	WANTNO,
	WANTYES,
	YES,
};

/* Queue bit if option state is WANTNO or WANTYES */
enum queue_state {
	EMPTY = 0, /* Also NONE in RFC 1143 */
	OPPOSITE,
};

static const char *option_state_name(enum option_state s)
{
	switch (s) {
		case NO:
			return "NO";
		case WANTNO:
			return "WANTNO";
		case WANTYES:
			return "WANTYES";
		case YES:
			return "YES";
	}
	__builtin_unreachable();
}

static const char *queue_state_name(enum queue_state s)
{
	switch (s) {
		case EMPTY:
			return "EMPTY";
		case OPPOSITE:
			return "OPPOSITE";
	}
	__builtin_unreachable();
}

struct telnet_settings {
	struct {
		enum option_state us:2;
		enum queue_state usq:1;
		enum option_state him:2;
		enum queue_state himq:1;
	} options[NTELOPTS + 1];
	unsigned int rcv_noecho:1;
};

#define telnet_process_command(node, settings, buf, len, res) __telnet_process_command(node, settings, buf, len, res, depth + 1)

/* IAC SE frequently indicates the end of a client's response for a command */
static const unsigned char RESPONSE_FINALE[] = { IAC, SE };
#define RESPONSE_FINALE_LEN 2

/* Forward declaration */
static int __telnet_process_command(struct bbs_node *node, struct telnet_settings *settings, unsigned char *buf, size_t len, int res, int depth);

static int telnet_process_command_additional(struct bbs_node *node, struct telnet_settings *settings, unsigned char *buf, size_t len, int res, int depth)
{
	if (!TELCMD_OK(buf[0]) || !TELCMD_OK(buf[1])) {
		bbs_warning("Got out of bounds command: %d %d %d\n", buf[0], buf[1], buf[2]);
		return 0;
	}
	if (!TELOPT_OK(buf[2])) {
		bbs_warning("Got out of bounds option: %d %d %d\n", buf[0], buf[1], buf[2]);
		return 0;
	}
	bbs_debug(3, "Processing additional Telnet command %s %s %s\n", telcmds[*buf - xEOF], telcmds[*(buf + 1) - xEOF], telopts[*(buf + 2)]);
	return telnet_process_command(node, settings, buf, len, res);
}

static int telnet_option_send(struct bbs_node *node, struct telnet_settings *settings, unsigned char cmd, unsigned char opt)
{
	int res;

	if (cmd == WILL || cmd == WONT || cmd == DO || cmd == DONT) {
		bbs_debug(6, "him: %s, himq: %s, us: %s, usq: %s\n",
			option_state_name(settings->options[opt].him), queue_state_name(settings->options[opt].himq),
			option_state_name(settings->options[opt].us), queue_state_name(settings->options[opt].usq));
	}

	switch (cmd) {
	case DO:
		/* Ask client to enable */
		switch (settings->options[opt].him) {
		case NO:
			/* him=WANTYES, send DO. */
			settings->options[opt].him = WANTYES;
			res = telnet_send_command(node->wfd, DO, opt);
			if (res) {
				return -1;
			}
			break;
		case YES:
			/* Error: Already enabled. */
			bbs_warning("Trying to send %s %s %s, but option already enabled?\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt]);
			break;
		case WANTNO:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* Error: Cannot initiate new request in the middle of negotiation (no queuing of requests). */
				bbs_warning("Can't initiate new request in middle of option negotiation\n");
				break;
			case OPPOSITE:
				/* Error: Already queued an enable request. */
				bbs_warning("Already queued an enable request\n");
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* Error: Already negotiating for enable. */
				bbs_debug(1, "Already neogitiating for enable\n");
				break;
			case OPPOSITE:
				/* himq=EMPTY */
				settings->options[opt].himq = EMPTY;
				break;
			}
			break;
		}
		break;
	case DONT:
		/* Ask client to disable */
		switch (settings->options[opt].him) {
		case NO:
			/* Error: Already disabled. */
			bbs_warning("Trying to send DONT, but option already disabled?\n");
			break;
		case YES:
			/* him=WANTNO, send DONT */
			settings->options[opt].him = WANTNO;
			res = telnet_send_command(node->wfd, DONT, opt);
			if (res) {
				return -1;
			}
			break;
		case WANTNO:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* Error: Already negotiating for disable. */
				bbs_debug(1, "Already negotiating for disable\n");
				break;
			case OPPOSITE:
				/* himq=EMPTY */
				settings->options[opt].himq = EMPTY;
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* Error: Cannot initiate new request in the middle of negotiation. */
				bbs_warning("Can't initiate new request in the middle of option negotiation\n");
				break;
			case OPPOSITE:
				/* Error: Already queued a disable request. */
				bbs_warning("Already queued a disable request\n");
				break;
			}
			break;
		}
		break;
	/* The next two cases are symmetrical:
	 * We handle the option on our side by the same procedures, with DO-WILL, DONT-WONT, him-us, himq-usq swapped. */
	case WILL:
		/* Confirm we will enable */
		switch (settings->options[opt].us) {
		case NO:
			settings->options[opt].us = WANTYES;
			res = telnet_send_command(node->wfd, WILL, opt);
			if (res) {
				return -1;
			}
			break;
		case YES:
			bbs_warning("Trying to send WILL, but option already enabled?\n");
			break;
		case WANTNO:
			switch (settings->options[opt].usq) {
			case EMPTY:
				bbs_warning("Can't initiate new request %s %s %s in the middle of option negotiation\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt]);
				break;
			case OPPOSITE:
				bbs_warning("Already queued an enable request\n");
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].usq) {
			case EMPTY:
				bbs_debug(1, "Already neogitiating for enable\n");
				break;
			case OPPOSITE:
				settings->options[opt].usq = EMPTY;
				break;
			}
			break;
		}
		break;
	case WONT:
		/* Negative acknowledgment, we will not enable this option */
		switch (settings->options[opt].us) {
		case NO:
			bbs_warning("Trying to send %s %s %s, but option already disabled?\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt]);
			break;
		case YES:
			settings->options[opt].us = WANTNO;
			res = telnet_send_command(node->wfd, WONT, opt);
			if (res) {
				return -1;
			}
			break;
		case WANTNO:
			switch (settings->options[opt].usq) {
			case EMPTY:
				bbs_debug(1, "Already negotiating for disable\n");
				break;
			case OPPOSITE:
				settings->options[opt].usq = EMPTY;
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].usq) {
			case EMPTY:
				bbs_warning("Can't initiate new request %s %s %s in the middle of option negotiation\n", telcmds[IAC - xEOF], telcmds[cmd - xEOF], telopts[opt]);
				break;
			case OPPOSITE:
				bbs_warning("Already queued a disable request\n");
				break;
			}
			break;
		}
		break;
	default:
		__builtin_unreachable();
	}
	return 0;
}

#define handle_option_will(node, settings, cmd, opt) __handle_option_will(node, settings, cmd, opt, buf, len, depth)

/*!
 * \brief Whether we mutually agree to enable an option
 * \retval 1 if option is supported, 0 if option not supported
 */
static int option_supported(struct bbs_node *node, unsigned char cmd, unsigned char opt)
{
	bbs_assert(cmd == WILL);

	switch (opt) {
	case TELOPT_NAWS:
		if (node->dimensions) {
			/* If we already got the dimensions, we don't want them again.
			 * If logic is added to process commands during a session and receive window size updates,
			 * this condition would need to be refined, but it would still be the case that we don't
			 * care to receive this more than once during initial negotiation. */
			bbs_debug(3, "Ignoring offer to send window dimensions since we already have them\n");
			return 0; /* Reject, and we will send DONT */
		}
		/* Fall through */
	case TELOPT_ECHO:
	case TELOPT_TSPEED:
	case TELOPT_TTYPE:
		/* Yes, please enable */
		return 1;
	default:
		bbs_debug(3, "Option %s is not supported\n", telopts[opt]);
		break;
	}
	return 0;
}

/*! \brief Handler for when an option has been enabled */
static int __handle_option_will(struct bbs_node *node, struct telnet_settings *settings, unsigned char cmd, unsigned char opt, unsigned char *buf, size_t len, int depth)
{
	int res;

	bbs_assert(cmd == WILL);

	switch (opt) {
	case TELOPT_ECHO:
		settings->rcv_noecho = 1;
		bbs_debug(3, "Client acknowledged local echo disable\n");
		return 0;
	case TELOPT_NAWS:
		/* Read terminal dimensions, coming up next */
		res = telnet_read_command(node->rfd, buf, len);
		if (res > 0) {
			res = telnet_process_command(node, settings, buf, len, res);
		} else if (res < 0) {
			return res;
		} else {
			/* Even after we send IAC DO NAWS and we receive IAC WILL NAWS from the client,
			 * SyncTERM doesn't seem to do IAC SB NAWS unless we repeat our IAC DO NAWS once more. */
			bbs_debug(3, "Failed to receive terminal dimensions, even though client offered to send it?\n");
			/* Temporarily violate RFC 1143, manually fiddle the state bits so we can resend the request */
			settings->options[opt].him = NO;
			if (telnet_option_send(node, settings, DO, opt)) {
				return -1;
			}
			res = telnet_read_command(node->rfd, buf, len);
			if (res > 0) {
				res = telnet_process_command(node, settings, buf, len, res);
			}
		}
		return 0;
	case TELOPT_TSPEED:
		/* Client supports sending terminal speed */
		if (telnet_send_command6(node->wfd, SB, TELOPT_TSPEED, TELQUAL_SEND, IAC, SE)) {
			return -1;
		}
		return 0;
	case TELOPT_TTYPE:
		/* Client supports sending terminal type */
		if (telnet_send_command6(node->wfd, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE)) {
			return -1;
		}
		return 0;
	default:
		bbs_debug(3, "No handler for option %s\n", telopts[opt]);
		break;
	}
	return 1;
}

static int __telnet_process_command(struct bbs_node *node, struct telnet_settings *settings, unsigned char *buf, size_t len, int res, int depth)
{
	unsigned char cmd = buf[1], opt = buf[2];

	if (depth > 4) {
		/* Prevent infinite recursion if the client replies with the same thing that triggered another command */
		bbs_warning("Exceeded command stack depth %d\n", depth);
		return 0;
	}

	bbs_assert(res >= 3);
	if (cmd == WILL || cmd == WONT || cmd == DO || cmd == DONT) {
		bbs_debug(6, "him: %s, himq: %s, us: %s, usq: %s\n",
			option_state_name(settings->options[opt].him), queue_state_name(settings->options[opt].himq),
			option_state_name(settings->options[opt].us), queue_state_name(settings->options[opt].usq));
	}

	/* Implemented as per RFC 1143. */
	switch (cmd) {
	case WILL:
		/* Client offered to enable an option. */
		switch (settings->options[opt].him) {
		case NO:
			/* If we agree that he should enable, him=YES, send DO; otherwise, send DONT. */
			if (!option_supported(node, cmd, opt)) {
				res = telnet_send_command(node->wfd, DONT, opt);
			} else {
				settings->options[opt].him = YES;
				res = telnet_send_command(node->wfd, DO, opt);
				handle_option_will(node, settings, cmd, opt); /* Post-processing for when option is enabled */
			}
			if (res) {
				return -1;
			}
			break;
		case YES:
			/* Ignore */
			bbs_debug(6, "Ignoring WILL since option already enabled\n");
			break;
		case WANTNO:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* Error. DONT answered by WILL. him=NO */
				bbs_warning("DONT answered by WILL?\n");
				settings->options[opt].him = NO;
				break;
			case OPPOSITE:
				/* Error. DONT answered by WILL. him=YES, himq=EMPTY */
				bbs_warning("DONT answered by WILL?\n");
				settings->options[opt].him = YES;
				settings->options[opt].himq = EMPTY;
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* him=YES */
				settings->options[opt].him = YES;
				handle_option_will(node, settings, cmd, opt); /* Post-processing for when option is enabled */
				break;
			case OPPOSITE:
				/* him=WANTNO, himq=EMPTY, send DONT */
				settings->options[opt].him = WANTNO;
				settings->options[opt].himq = EMPTY;
				res = telnet_send_command(node->wfd, DONT, opt);
				if (res) {
					return -1;
				}
				break;
			}
			break;
		}
		break;
	case WONT:
		/* Client informed us it will not enable an option. */
		switch (settings->options[opt].him) {
		case NO:
			/* Ignore. */
			bbs_debug(6, "Ignoring WONT since option already disabled\n");
			break;
		case YES:
			/* him=NO, send DONT */
			settings->options[opt].him = NO;
			res = telnet_send_command(node->wfd, DONT, opt);
			if (res) {
				return -1;
			}
			break;
		case WANTNO:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* him=NO */
				settings->options[opt].him = NO;
				break;
			case OPPOSITE:
				/* him=WANTYES, himq=NONE, send DO */
				settings->options[opt].him = WANTYES;
				settings->options[opt].himq = EMPTY;
				res = telnet_send_command(node->wfd, DO, opt);
				if (res) {
					return -1;
				}
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].himq) {
			case EMPTY:
				/* him=NO */
				settings->options[opt].him = NO;
				break;
			case OPPOSITE:
				/* him=NO, himq=NONE */
				/* Here we don't have to generate another request because we've been "refused into" the correct state anyway. */
				settings->options[opt].him = NO;
				settings->options[opt].himq = EMPTY;
				break;
			}
			break;
		}
		break;
	/* The next two cases are symmetrical:
	 * We handle the option on our side by the same procedures, with DO-WILL, DONT-WONT, him-us, himq-usq swapped. */
	case DO:
		/* Client told us to enable an option. */
		switch (settings->options[opt].us) {
		case NO:
			/* There are no options that we support enabling on the SERVER side...
			 * they are all on the client (we are, after all, a server).
			 * So always use the failure case here, symmetrically from above. */
			if (1) {
				res = telnet_send_command(node->wfd, WONT, opt);
			} else {
				settings->options[opt].us = YES;
				res = telnet_send_command(node->wfd, WILL, opt);
			}
			if (res) {
				return -1;
			}
			break;
		case YES:
			/* Ignore */
			bbs_debug(6, "Ignoring DO since option already enabled\n");
			break;
		case WANTNO:
			switch (settings->options[opt].usq) {
			case EMPTY:
				bbs_warning("WONT answered by DO?\n");
				settings->options[opt].us = NO;
				break;
			case OPPOSITE:
				bbs_warning("WONT answered by DO?\n");
				settings->options[opt].us = YES;
				settings->options[opt].usq = EMPTY;
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].usq) {
			case EMPTY:
				settings->options[opt].us = YES;
				break;
			case OPPOSITE:
				settings->options[opt].us = WANTNO;
				settings->options[opt].usq = EMPTY;
				res = telnet_send_command(node->wfd, WONT, opt);
				if (res) {
					return -1;
				}
				break;
			}
			break;
		}
		break;
	case DONT:
		/* Client told us to not enable an option. */
		switch (settings->options[opt].us) {
		case NO:
			bbs_debug(6, "Ignoring DONT since option already disabled\n");
			break;
		case YES:
			/* him=NO, send DONT */
			settings->options[opt].us = NO;
			res = telnet_send_command(node->wfd, WONT, opt);
			if (res) {
				return -1;
			}
			break;
		case WANTNO:
			switch (settings->options[opt].usq) {
			case EMPTY:
				settings->options[opt].us = NO;
				break;
			case OPPOSITE:
				settings->options[opt].us = WANTYES;
				settings->options[opt].usq = EMPTY;
				res = telnet_send_command(node->wfd, WILL, opt);
				if (res) {
					return -1;
				}
				break;
			}
			break;
		case WANTYES:
			switch (settings->options[opt].usq) {
			case EMPTY:
				settings->options[opt].us = NO;
				break;
			case OPPOSITE:
				settings->options[opt].us = NO;
				settings->options[opt].usq = EMPTY;
				break;
			}
			break;
		}
		break;
	case SB:
		switch (opt) {
		case TELOPT_NAWS:
			/* Get the window size
			 * IAC SB NAWS WIDTH[1] WIDTH[0] HEIGHT[1] HEIGHT[0] IAC SE
			 * According to RFC 1073, there are 2 bytes for the width and the height each,
			 * to support clients with a window height/width of up to 65536 rows/cols.
			 * I'm sorry, there's no way there are any clients with screens that large.
			 * Here's what these bytes would look for a standard 80x24 terminal:
			 * 0 80 0 24 255 240
			 * So we can simply ignore WIDTH[1] and HEIGHT[1] altogether.
			 */
			if (res >= 9) {
				bbs_debug(7, "Got %d %d %d %d %d %d\n", buf[3], buf[4], buf[5], buf[6], buf[7], buf[8]);
				bbs_node_update_winsize(node, buf[4], buf[6]);
			} else {
				bbs_warning("Received window subnegotiation, but only got %d bytes?\n", res);
			}

			/* XXX Now, tell the client not to send window updates
			 * Because we're going to step out of the way and all socket I/O is going to
			 * go right into the PTY master, we won't be able to intercept future Telnet
			 * commands, so if a window update is sent, we won't be able to process it.
			 * It would probably be better to add an intermediate layer here to handle that
			 * (similar to what the SSH module does).
			 * Or, the PTY thread could handle telnet commands (beginning with IAC),
			 * if node->protname == "Telnet", but that would break the abstraction
			 * that the BBS has from the communications protocol.
			 *
			 * Either way, for now, we don't support window updates.
			 */
			if (telnet_send_command(node->wfd, DONT, TELOPT_NAWS)) {
				return -1;
			}
			res = telnet_read_command(node->rfd, buf, len);
			if (res > 0) {
				res = telnet_process_command(node, settings, buf, len, res);
			}
			return 1;
		case TELOPT_TTYPE:
			if (buf[3] == TELQUAL_IS && res >= 6) {
				/* With SyncTERM, if we resend IAC DO NAWS (as we now do above, since for some reason it needs to be prompted to),
				 * SyncTERM will send the term type, followed by IAC SE IAC WILL TELOPT_NAWS.
				 * The IAC SE is the trailer to the response, but the IAC WILL TELOPT_NAWS (offering to send window dimensions)
				 * throws the accounting below off. It's also a bit odd, given we already received the dimensions
				 * and then send IAC DONT NAWS (and received IAC WONT NAWS) in response.
				 * That said, while odd, it is certainly legitimate to receive multiple commands in a single call to read()
				 * like this, and we need to parse appropriately. Specifically,
				 * rather than assuming IAC SE is at the end of whatever we just read, we need to actually look for IAC SE and stop there.
				 *
				 * Note that this doesn't actually happen anymore, since in telnet_handshake,
				 * we move asking for terminal type to BEFORE asking for dimensions,
				 * to avoid the extra exchange in the first place. */
				size_t length, cmdlen, nextlen;
				unsigned char *termtype;
				unsigned char *end;
				termtype = buf + 4; /* First 4 bytes are command, and last two are IAC SE (IAC SB TERMINAL TYPE <term type> IAC SE) */
				end = memmem(termtype, (size_t) res, RESPONSE_FINALE, RESPONSE_FINALE_LEN);
				if (!end) {
					bbs_warning("Received command response does not send in IAC SE\n");
					bbs_dump_mem(buf, (size_t) res);
					return -1;
				}
				/* IAC SB TTYPE IS syncterm IAC SE   IAC WILL NAWS */
				cmdlen = (size_t) (end - buf) + RESPONSE_FINALE_LEN;
				length = cmdlen - 6; /* Subtract 4 for command (IAC SB TERMINAL TYPE IS) and 2 for trailer (IAC SE) */
				bbs_debug(3, "Terminal type is %.*s\n", (int) length, termtype);
				*end = '\0'; /* Replace IAC with NUL for strdup since we don't need it anymore */
				REPLACE(node->term, (char*) termtype);
				/* If there is anything leftover, thanks to recursion, we can easily process a second command received */
				nextlen = (size_t) res - cmdlen;
				if (nextlen > 0) {
					buf += cmdlen;
					len -= cmdlen;
					res = telnet_process_command_additional(node, settings, buf, len, (int) nextlen, depth);
				}
			} else {
				bbs_debug(3, "Ignoring unhandled response %d %d %d\n", buf[0], buf[1], buf[2]);
			}
			break;
		case TELOPT_TSPEED:
			if (buf[3] == TELQUAL_IS && res >= 3) {
				bbs_debug(3, "Terminal speed is %.*s\n", (int) res - 6, buf + 4); /* First 4 bytes are command, and last two are IAC SE */
				if (res - 6 < (int) len - 1) {
					memmove(buf, buf + 4, (size_t) res - 6);
					buf[res - 6] = '\0';
					node->reportedbps = (unsigned int) atoi((char*) buf);
				}
			} else {
				bbs_debug(3, "Ignoring unhandled response %d %d %d\n", buf[0], buf[1], buf[2]);
			}
			break;
		default:
			bbs_debug(3, "Ignoring unhandled response %d %d %d\n", buf[0], buf[1], buf[2]);
		}
		break;
	default:
		bbs_debug(3, "Ignoring unhandled response %d %d %d\n", buf[0], buf[1], buf[2]);
	}

	return 1;
}

static int read_and_process_command(struct bbs_node *node, struct telnet_settings *settings, unsigned char *buf, size_t len)
{
	int depth = 0;
	int res = telnet_read_command(node->rfd, buf, len);
	if (res > 0) {
		res = telnet_process_command(node, settings, buf, len, res);
	}
	return res;
}

static int telnet_handshake(struct bbs_node *node)
{
	int res;
	struct telnet_settings settings;
	unsigned char buf[32];

	memset(&settings, 0, sizeof(settings));

	/* RFC 857 Disable Telnet echo or we'll get double echo when slave echo is on and single echo when it's off. */

	/* http://www.verycomputer.com/174_d636f401932e1db5_1.htm
	 * If using telnet as a TCP client, this will properly disable echo.
	 * This is necessary, in addition to actually setting the termios as normal.
	 * If you are using netcat, make sure to disable canonical mode and echo when launching
	 * netcat, i.e.: stty -icanon -echo && nc 127.0.0.1 23
	 *
	 * Might seem backwards to do WILL echo to turn local echo off, but think of it as
	 * us saying that WE'LL do the echoing so local echo, please stop. */
	if (telnet_option_send(node, &settings, WILL, TELOPT_ECHO)) {
		return -1;
	}

	/* Send the following to disable line buffering and make the terminal "uncooked" from a Telnet perspective.
	 * In particular, this is needed to get PuTTY to work properly, since it will assume cooked by default. */
	if (telnet_option_send(node, &settings, WILL, TELOPT_SGA)) { /* Suppress Go Ahead */
		return -1;
	}
#if 0
	/* All Telnet options are disabled by default, so there is no need to explicitly send WONT LINEMODE */
	if (telnet_option_send(node, &settings, WONT, TELOPT_LINEMODE)) { /* Disable line mode */
		return -1;
	}
#endif

	/* Read anything the client sends upon connect, if anything.
	 * For example, some clients, like SyncTERM, will acknowledge everything with a response,
	 * while others, like PuTTY, will not. */
	do {
		res = read_and_process_command(node, &settings, buf, sizeof(buf));
	} while (res > 0);
	if (res < 0) {
		return -1;
	}

	bbs_debug(8, "Finished processing commands received at connection time\n");

	/* RFC 1091 Terminal Type */
	if (telnet_option_send(node, &settings, DO, TELOPT_TTYPE)) {
		return -1;
	}
	res = read_and_process_command(node, &settings, buf, sizeof(buf));
	if (res < 0) {
		return res;
	}

	/* This is not an issue for real Telnet clients, but test_terminals is not a real Telnet client,
	 * it is preprogrammed to look for output in a consistent order. Because we move on to sending NAWS
	 * immediately after sending IAC SB TERMINAL TYPE, we will have to be able to process the end of the TERMINAL TYPE
	 * negotiation in the NAWS block (or TSPEED, technically, if node->dimensions is already set here, but it
	 * won't be in the test, and since this doesn't matter for actual clients, that is not relevant here).
	 * So the only needed workaround is to call read_and_process_command again if we haven't yet gotten the dimensions.
	 *
	 * There are two scenarios:
	 * 1. In the read_and_process_command after TELOPT_NAWS, we read both IAC SB TERMINAL TYPE and the NAWS response.
	 *    Both are processed and we're still synchronized with no additional effort.
	 *
	 * XXX Note that not all command handlers are written to elegantly
	 * handle receiving multiple responses at once (though the TERMINAL TYPE handler is).
	 * This should be generic so that we could successfully handle multiple commands
	 * at any stage. An easy way would be using bbs_readline with IAC SE as the delimiter when needed.
	 *
	 * 2. In the read_and_process_command after TELOPT_NAWS, we happen to read the IAC SB TERMINAL TYPE.
	 *    Now, node->dimensions is still 0, and we will call read_and_process_command again to read the NAWS response.
	 */

	/* RFC 1073 Request window size */
	if (!node->dimensions) {
		if (telnet_option_send(node, &settings, DO, TELOPT_NAWS)) {
			return -1;
		}
		res = read_and_process_command(node, &settings, buf, sizeof(buf));
		if (res < 0) {
			return res;
		}
		/* This is the solution to the issue described in the long comment above.
		 * This should only be needed for test_terminals (specifically the qodem, Telnet case),
		 * but this is not "incorrect" to do when interacting with real clients, either.
		 * Here, if we have not yet received a response (still WANTYES), that means in
		 * the read_and_process_command block above, we only processed the IAC SB TERMINAL TYPE
		 * response from the block above, rather than the NAWS response we intended to.
		 * So actually go ahead and process it here.
		 *
		 * Sometimes, this does result in a delay, usually for clients with certain "quirks",
		 * but much of the time we try this, we do actually catch a response that was simply delayed,
		 * or arrived in a subsequent packet. Only downsides of doing this are the additional delay
		 * when the client chooses not to respond for some reason, and not pipelining the TSPEED option,
		 * which would otherwise be a reasonable thing to do when dealing only with actual clients.
		 * This is purely to keep the test suite synchronized. */
		if (!node->dimensions && settings.options[TELOPT_NAWS].him == WANTYES) {
			bbs_debug(3, "Haven't yet received response to NAWS option inquiry, waiting for it...\n");
			res = read_and_process_command(node, &settings, buf, sizeof(buf));
			if (res < 0) {
				return res;
			}
		}
	}

	/* RFC 1079 Terminal Speed */
	if (telnet_option_send(node, &settings, DO, TELOPT_TSPEED)) {
		return -1;
	}
	res = read_and_process_command(node, &settings, buf, sizeof(buf));
	if (res < 0) {
		return res;
	}

	if (!settings.rcv_noecho) {
		bbs_debug(3, "Request to enable ECHO not yet acknowledged, retrying\n");
		/* Temporarily break with RFC 1143, and manually fiddle some bits to force the request to send */
		settings.options[TELOPT_ECHO].us = YES;
		if (telnet_option_send(node, &settings, WONT, TELOPT_ECHO)) {
			return -1;
		}
		settings.options[TELOPT_ECHO].us = NO;
		if (telnet_option_send(node, &settings, WILL, TELOPT_ECHO)) {
			return -1;
		}
	}

	/* Read anything leftover, if anything */
	do {
		res = read_and_process_command(node, &settings, buf, sizeof(buf));
	} while (res > 0);
	if (res < 0) {
		return -1;
	}

	return 0;
}

static int tty_handshake(struct bbs_node *node)
{
	/* Not really a handshake, just use this as a callback to set a few things */
	node->ansi = 0; /* TDDs don't support ANSI escape sequences, disable them */
	/* Assume standard TDD screen size */
	node->cols = NUM_TDD_COLS;
	node->rows = 1;
	/* Note that because we don't actually call telnet_handshake,
	 * as we assume an actual TDD is on the other end of the connection,
	 * things like echo and input buffering which require Telnet commands
	 * will not be sent, so using a telnet client with the TTY port
	 * will be completely unsuitable. */
	return 0;
}

static void *telnet_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_comm_listener(telnet_socket, "TELNET", telnet_handshake, BBS_MODULE_SELF);
	return NULL;
}

/* A quick way to test this is simply: openssl s_client -port 992
 * However, I think s_client is cookied / canonical,
 * so input isn't flushed to the server until you hit ENTER locally.
 * Additionally, output that shouldn't be echoed obviously is.
 * A proper TELNETS client probably doesn't have this issue.
 * (And no, -nbio doesn't help with input buffering either)
 */
static void *telnets_handler(void *varg)
{
	struct bbs_node *node = varg;

	/* Yikes... a TELNETS client needs 3 threads:
	 * the network thread, the PTY thread,
	 * and the actual application thread.
	 * Please don't implement proper Telnet support
	 * as another intermediary layer that looks for 255 bytes,
	 * and add yet a fourth thread! */
	/* Set up TLS, then do the handshake, then proceed as normal. */
	if (bbs_node_starttls(node)) {
		bbs_node_exit(node); /* Since we're not calling bbs_node_handler, we're responsible for manually cleaning the node up */
		return NULL;
	}

	if (!telnet_handshake(node)) {
		bbs_node_handler(node); /* Run the normal node handler */
	} else {
		bbs_node_exit(node); /* Manual cleanup */
	}

	return NULL;
}

static void *tty_handler(void *varg)
{
	struct bbs_node *node = varg;

	if (!strcmp(node->protname, "TDDS")) {
		/* Use TDD for both secure and plaintext TDD. Used in NODE_IS_TDD macro. */
		node->protname = "TDD";
		bbs_debug(5, "Connection accepted on secure TTY port\n");
		if (bbs_node_starttls(node)) {
			bbs_node_exit(node);
			return NULL;
		}
	}

	tty_handshake(node);
	bbs_node_handler(node); /* Run the normal node handler */

	return NULL;
}

static void *telnets_listener(void *unused)
{
	UNUSED(unused);
	/* We need to start TLS before doing the application-level handshake, so use the generic TCP listener for TELNETS */
	bbs_tcp_listener(telnets_socket, "TELNETS", telnets_handler, BBS_MODULE_SELF);
	return NULL;
}

static void *tty_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener2(tty_socket, ttys_socket, "TDD", "TDDS", tty_handler, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("net_telnet.conf", 1);

	if (!cfg) {
		/* Assume defaults if we failed to load the config (e.g. file doesn't exist). */
		return 0;
	}

	telnet_port = DEFAULT_TELNET_PORT;
	bbs_config_val_set_port(cfg, "telnet", "port", &telnet_port);

	telnets_port = DEFAULT_TELNETS_PORT;
	bbs_config_val_set_port(cfg, "telnets", "port", &telnets_port);
	bbs_config_val_set_true(cfg, "telnets", "enabled", &telnets_enabled);

	if (telnets_enabled && !ssl_available()) {
		bbs_error("TLS is not available, TELNETS cannot be used\n");
		return -1;
	}

	tty_port = ttys_port = 0; /* Disabled by default */
	bbs_config_val_set_port(cfg, "telnet", "ttyport", &tty_port);
	bbs_config_val_set_port(cfg, "telnets", "ttyport", &ttys_port);

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	/* If we can't start the TCP listener, decline to load */
	if (bbs_make_tcp_socket(&telnet_socket, telnet_port)) {
		return -1;
	}
	if (telnets_enabled && bbs_make_tcp_socket(&telnets_socket, telnets_port)) {
		close(telnet_socket);
		return -1;
	}
	bbs_assert(telnet_socket >= 0);
	if (bbs_pthread_create(&telnet_thread, NULL, telnet_listener, NULL)) {
		close(telnet_socket);
		close_if(telnets_socket);
		telnet_socket = -1;
		return -1;
	}
	if (telnets_enabled && bbs_pthread_create(&telnets_thread, NULL, telnets_listener, NULL)) {
		close_if(telnets_socket);
		bbs_socket_thread_shutdown(&telnet_socket, telnet_thread);
		return -1;
	}
	if (tty_port || ttys_port) {
		if (tty_port) {
			if (bbs_make_tcp_socket(&tty_socket, tty_port)) {
				return -1;
			}
		}
		if (ttys_port) {
			if (bbs_make_tcp_socket(&ttys_socket, ttys_port)) {
				close_if(tty_socket);
				return -1;
			}
		}
		if (bbs_pthread_create(&tty_thread, NULL, tty_listener, NULL)) {
			bbs_socket_thread_shutdown(&telnet_socket, telnet_thread);
			if (telnets_enabled) {
				bbs_socket_thread_shutdown(&telnets_socket, telnets_thread);
			}
			close_if(tty_socket);
			close_if(ttys_socket);
			return -1;
		}
	}
	bbs_register_network_protocol("TELNET", (unsigned int) telnet_port);
	if (telnets_enabled) {
		bbs_register_network_protocol("TELNETS", (unsigned int) telnets_port);
	}
	return 0;
}

static int unload_module(void)
{
	if (tty_socket > -1 || ttys_socket > -1) {
		if (tty_socket != -1) {
			bbs_socket_close(&tty_socket);
		}
		if (ttys_socket != -1) {
			bbs_socket_close(&ttys_socket);
		}
		bbs_pthread_join(tty_thread, NULL);
	}
	if (telnet_socket > -1) {
		bbs_unregister_network_protocol((unsigned int) telnet_port);
		if (telnets_socket > -1) {
			bbs_unregister_network_protocol((unsigned int) telnets_port);
		}
		bbs_socket_thread_shutdown(&telnet_socket, telnet_thread);
		if (telnets_enabled) {
			bbs_socket_thread_shutdown(&telnets_socket, telnets_thread);
		}
	} else {
		bbs_error("Telnet socket already closed at unload?\n");
	}
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC854 Telnet and TTY/TDD");
