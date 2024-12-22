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
 * \brief Pseudoterminals
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

/* Uncomment this to generate a log message for every chunk of data received
 * by the client, logging the number of bytes. Mainly useful for debugging
 * PTY-layer stuff, shouldn't be used in production. */
/* #define DEBUG_PTY */

/* Uncomment this to dump all input received for a log, so we can see exactly
 * what was sent by client at the application layer (so minus encryption and all that).
 * The files created are temporary and may not be named uniquely.
 * This is not intended to ever be used in production, it is primarily for manually capturing
 * the sequences of data sent by certain terminal clients so we can encode them in tests.
 * This is different from tcpdump, which could capture, say, raw SSH encryption data,
 * which is not useful for this - we just want the unencrypted protocol-layer data, such
 * as escape sequences, line endings, etc. */
/* #define DUMP_PTY_INPUT */

#ifdef DUMP_PTY_INPUT
/* Define the directory in which the log file will be created.
 * Must include a trailing slash and should begin with a leading slash for absolute path.
 * Leave empty to create log file in current directory in which the BBS is running. */
#define DUMP_DIRECTORY ""
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <sys/ioctl.h> /* use winsize */
#include <signal.h> /* use kill */

#ifdef DEBUG_PTY
#include <ctype.h>
#endif

/* Can you believe it?
 * #include <pty.h>
 * is not necessary!
 * (It's for the old BSD ptys)
 */

#include "include/node.h"
#include "include/pty.h"
#include "include/term.h"
#include "include/ansi.h"
#include "include/alertpipe.h"
#include "include/utils.h" /* use bbs_pthread_create */

/*!
 * \brief Roughly equivalent to BSD openpty, but use the POSIX (UNIX 98) functions
 * \param amaster Will be set to the fd of the master side of the PTY
 * \param slavename Buffer that will contain slave name
 * \param slen Size of ptsname buffer
 * \retval 0 on success, -1 on failure
 */
static int posix_openpty(int *amaster, char *slavename, size_t slen)
{
	int master_fd;
	master_fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (master_fd == -1) {
		bbs_error("posix_openpt failed: %s\n", strerror(errno));
		return -1;
	}
	if (grantpt(master_fd)) { /* Grant access to slave */
		/* Note: for non-forked, main BBS process and spawn process should run as the same user */
		bbs_error("grantpt failed: %s\n", strerror(errno));
		close(master_fd);
		return -1;
	}
	if (unlockpt(master_fd)) { /* Unlock slave */
		bbs_error("unlockpt failed: %s\n", strerror(errno));
		close(master_fd);
		return -1;
	}
	if (ptsname_r(master_fd, slavename, slen)) { /* Get slave name, and use the thread safe version of ptsname */
		bbs_error("ptsname_r failed: %s\n", strerror(errno));
		close(master_fd);
		return -1;
	}
	/* No need to check for truncation: ptsname_r will return -1 (ERANGE) in that case. */
	*amaster = master_fd; /* All is well. */

	return 0;
}

int bbs_openpty(int *amaster, int *aslave, char *name, const struct termios *termp, const struct winsize *winp)
{
	char slavename[48];
	/* Assume the buffer is size 48 */
	int slave, res;

	res = posix_openpty(amaster, slavename, sizeof(slavename));
	if (res < 0) {
		return -1;
	}
	if (!res && name) {
		/* XXX Note this is not actually safe. We have no idea how big the name buffer is. Just hope for the best.
		 * The one module that calls this function currently (the SSH network driver) passes NULL
		 * for name, so this is theoretical at this point anyways. Since we're setting aslave with the slave fd,
		 * callers generally shouldn't need to know or care what the slave name is.
		 */
		safe_strncpy(name, slavename, sizeof(slavename));
	}

	/* Open the slave here and just return the file descriptor of the slave,
	 * rather than returning its name and making the caller open the slave. */
	slave = open(slavename, O_RDWR);
	if (slave == -1) {
		return -1;
	}
	*aslave = slave;

	/* Set slave TTY attributes */
	if (termp && tcsetattr(slave, TCSANOW, termp)) {
		bbs_error("tcsetattr failed: %s\n", strerror(errno));
		close(slave);
		return -1;
	}

	/* Set slave window size */
	if (winp && ioctl(slave, TIOCSWINSZ, winp) == -1) {
		bbs_error("ioctl failed: %s\n", strerror(errno));
		close(slave);
		return -1;
	}

	return 0;
}

struct pty_fds {
	int amaster;
	int fd;
};

static void *pty_master_fd(void *varg)
{
	struct pty_fds *ptyfds = varg;
	struct pollfd fds[2];
	char buf[4096]; /* According to termios(3) man page, the canonical mode buffer of the PTY is 4096, so this should always be large enough */
	ssize_t bytes_read, bytes_wrote;

	/* Save relevant fields. */
	fds[0].fd = ptyfds->fd;
	fds[1].fd = ptyfds->amaster;
	fds[0].events = fds[1].events = POLLIN | POLLPRI | POLLERR | POLLNVAL;
	free(ptyfds);

	bbs_debug(10, "Starting generic PTY master for %d <=> %d\n", fds[1].fd, fds[0].fd);

	/* We don't need to call tty_set_raw on any file descriptor. */

	/* Relay data between master and slave */
	for (;;) {
		int pres;
		fds[0].revents = fds[1].revents = 0;
		pres = poll(fds, 2, -1);
		pthread_testcancel();
		if (pres < 0) {
			if (errno != EINTR) {
				bbs_error("poll returned %d: %s\n", pres, strerror(errno));
				break;
			}
			continue;
		}
		if (fds[0].revents & POLLIN) { /* Got input on socket -> pty */
			bytes_read = read(fds[0].fd, buf, sizeof(buf));
			if (bytes_read <= 0) {
				close(fds[1].fd); /* Close the other side */
				close(fds[0].fd); /* Close our side, since nobody else will */
				break; /* We'll read 0 bytes upon disconnect */
			}
			bytes_wrote = write(fds[1].fd, buf, (size_t) bytes_read);
			if (bytes_wrote != bytes_read) {
				bbs_error("Expected to write %ld bytes, only wrote %ld (%s)\n", bytes_read, bytes_wrote, strerror(errno));
				if (bytes_wrote == -1) {
					close(fds[1].fd);
					close(fds[0].fd);
					break;
				}
			}
		} else if (fds[1].revents & POLLIN) { /* Got input from pty -> socket */
			bytes_read = read(fds[1].fd, buf, sizeof(buf) - 1);
			if (bytes_read <= 0) {
				bbs_debug(10, "pty master read returned %ld (%s)\n", bytes_read, strerror(errno));
				close(fds[0].fd); /* Close the other side */
				close(fds[1].fd); /* Close our side, since nobody else will */
				break; /* We'll read 0 bytes upon disconnect */
			}
			bytes_wrote = write(fds[0].fd, buf, (size_t) bytes_read);
			if (bytes_wrote != bytes_read) {
				bbs_error("Expected to write %ld bytes, only wrote %ld (%s)\n", bytes_read, bytes_wrote, strerror(errno));
				if (bytes_wrote == -1) {
					close(fds[1].fd);
					close(fds[0].fd);
					break;
				}
			}
		} else {
			break;
		}
	}

	bbs_debug(10, "PTY master exiting for %d <=> %d\n", fds[1].fd, fds[0].fd);
	return NULL;
}

int __bbs_spawn_pty_master(int fd, int *amaster)
{
	pthread_t masterthread;
	struct pty_fds *ptyfds;
	int aslave;

	if (bbs_openpty(amaster, &aslave, NULL, NULL, NULL) != 0) {
		bbs_error("Failed to openpty\n");
		return -1;
	}
	bbs_unbuffer_input(aslave, 0); /* Disable canonical mode and echo on this PTY slave */
	bbs_term_makeraw(*amaster); /* Make the master side raw */

	ptyfds = calloc(1, sizeof(*ptyfds));
	if (ALLOC_FAILURE(ptyfds)) {
		return -1;
	}
	ptyfds->amaster = *amaster;
	ptyfds->fd = fd;
	if (bbs_pthread_create_detached(&masterthread, NULL, pty_master_fd, ptyfds)) {
		free(ptyfds);
		return -1;
	}
	return aslave;
}

int bbs_spawn_pty_master(int fd)
{
	int amaster = -1; /* Not needed, but initialize to make old versions of gcc happy */
	return __bbs_spawn_pty_master(fd, &amaster);
}

int bbs_pty_allocate(struct bbs_node *node)
{
	/* We store the slavename on the node struct, but
	 * technically this isn't necessary since it's only used in this function. */
	if (posix_openpty(&node->amaster, node->slavename, sizeof(node->slavename))) {
		return -1;
	}

	/* Launch a PTY master thread to relay data between network socket and PTY master. */
	if (bbs_pthread_create(&node->ptythread, NULL, pty_master, node)) {
		return -1;
	}
#ifdef __linux__
	bbs_debug(8, "PTY thread %lu allocated for node %u\n", node->ptythread, node->id);
#endif

	/* We are the PTY slave */
	node->slavefd = open(node->slavename, O_RDWR);
	if (node->slavefd == -1) {
		return -1;
	}

	bbs_assert(isatty(node->amaster));
	bbs_assert(isatty(node->slavefd));

	/* Assume TTY will be in canonical mode with echo enabled to start. */
	node->echo = 1;
	node->buffered = 1;

	return 0;
}

int bbs_node_spy(int fdin, int fdout, unsigned int nodenum)
{
	int spy_alert_pipe[2] = { -1, -1 };
	struct bbs_node *node;
	int fgconsole;

	fgconsole = fdout == STDOUT_FILENO; /* foreground console if using STDIN/STDOUT */
	/* There can only be 1 foreground console, so there's no possibility
	 * of race conditions here, only one thread could ever have fgconsole be true. */
	if (fgconsole && bbs_alertpipe_create(spy_alert_pipe)) {
		return -1;
	}

	node = bbs_node_get(nodenum); /* This returns node locked */
	if (!node) {
		bbs_dprintf(fdout, "No such node: %u\n", nodenum);
		if (fgconsole) {
			bbs_alertpipe_close(spy_alert_pipe);
		}
		return 0;
	}

	if (!NODE_HAS_PTY(node)) {
		bbs_dprintf(fdout, "Node %d does not have a PTY attached (protocol: %s)\n", node->id, node->protname);
		bbs_node_unlock(node);
		if (fgconsole) {
			bbs_alertpipe_close(spy_alert_pipe);
		}
		return 0;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	/* Clear the screen to start. */
	SWRITE(fdout, COLOR_RESET); /* Reset color too, just in case */
	SWRITE(fdout, TERM_CLEAR);
#pragma GCC diagnostic pop

	bbs_node_pty_lock(node);
	node->spy = 1;
	node->spyfd = fdout;
	node->spyfdin = fdin;
	if (fgconsole) {
		bbs_sigint_set_alertpipe(spy_alert_pipe);
	}
	bbs_unbuffer_input(fdin, 0); /* Unbuffer input, so that sysop can type on the node's TTY in real time, not just flushed after line breaks. */
	bbs_node_pty_unlock(node);
	bbs_node_unlock(node); /* We're done with the node. */

	bbs_verb(3, "Spying begun on node %d\n", nodenum);

	/* pty_master is responsible for our input and output as long as we're spying.
	 *
	 * Another way of potentially doing this would be to read from spyfdin in this thread
	 * and relay that to the amaster fd, but I think pty_master thread is better off
	 * dealing with the PTY file descriptors all on its own, without interference.
	 * The way it is now, all the I/O is handled in that thread.
	 *
	 * So, just wait indefinitely for ^C to stop spying.
	 * Except, we only get signals from ^C on the foreground console.
	 */
	if (fgconsole) {
		if (bbs_alertpipe_poll(spy_alert_pipe, -1) > 0) {
			bbs_alertpipe_read(spy_alert_pipe);
		}
		/* Restore the original handler for ^C */
		bbs_sigint_set_alertpipe(NULL); /* Unsubscribe, restore default SIGINT handling */
		bbs_alertpipe_close(spy_alert_pipe);

		/* Reset the terminal. */
		bbs_buffer_input(fdin, 1); /* Rebuffer input */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
		SWRITE(fdout, COLOR_RESET);
		SWRITE(fdout, TERM_CLEAR);
#pragma GCC diagnostic pop
	} else {
		int res;
		struct pollfd pfd;
		pfd.fd = fdin;
		pfd.events = POLLIN;
		/* If remote console, and the sysop quits using ^C,
		 * that will just quit the remote console.
		 * That's fine. For foreground consoles, we explicitly intercept ^C
		 * because otherwise it would pass through and terminate the BBS.
		 * For remote consoles, it's fine if ^C terminates the remote console,
		 * the sysop can just open it again.
		 * Therefore, all we really need to do here is just wait indefinitely
		 * for fdin/fdout (which are sockets) to close. */
		do {
			pfd.revents = 0;
			res = poll(&pfd, 1, -1); /* Use poll directly instead of just bbs_poll, so that we know what event we get */
			/* Careful! poll will return 1 when the remote console disconnects, not -1. Use the revents to figure out what really happened. */
			if (res == 1 && pfd.revents & BBS_POLL_QUIT) {
				break;
			}
		} while (res >= 0); /* poll should not return 0, since we passed -1 for ms */
		/* Remote console socket is now closed.
		 * Because it's closed from rsysop towards the BBS, we can't reset the terminal here. */
	}

	/* Log this message after the screen was cleared, as the sysop will likely see it,
	 * and this serves as a visual indication that spying has really stopped. */
	bbs_verb(3, "Spying stopped on node %d\n", nodenum);

	node = bbs_node_get(nodenum);
	if (!node) {
		bbs_debug(3, "Node %d disappeared while we were spying on it\n", nodenum);
		return 0;
	}
	node->spy = 0;
	node->spyfd = -1;
	node->spyfdin = -1;
	bbs_node_unlock(node); /* We're done with the node. */
	return 0;
}

/*! \brief Emulated speed control for non-serial file descriptors */
static ssize_t slow_write(struct pollfd *restrict pfds, int fd, int fd2, ssize_t sofar, char **restrict buf, size_t *restrict len, unsigned int sleepus, int *restrict input)
{
	size_t c;
	ssize_t total_bytes = sofar;

	/* This function exists because it is not possible to use termios
	 * to set the speed of non-serial terminals.
	 * In other words, you can't do this:
	 *
	 * struct termios slow;
	 * tcgetattr(STDOUT_FILENO, &slow);
	 * cfsetispeed(&slow, B300);
	 * cfsetospeed(&slow, B1200);
	 * tcsetattr(STDOUT_FILENO, TCSANOW, &slow);
	 *
	 * These calls will all succeed, but they don't have any effect, unless STDOUT_FILENO
	 * is a file descriptor for a serial terminal. So, none of this works with Internet Protocol.
	 * This is actually pretty useless for that.
	 *
	 * So, we have to get a little creative. Hence, this is why the slow_write function exists.
	 * There may be other ways of achieving similar things,
	 * e.g. see https://unix.stackexchange.com/questions/669232/how-to-throttle-bandwidth-of-ssh-connection
	 *
	 * However, even though methods such as proxying sessions through pv(1) may be more efficient,
	 * these are not as flexible since you cannot change the speed on the fly during a session,
	 * which we want to be able to do.
	 */

	/* Write entire buffer one character at a time, with appropriate delay inbetween.
	 * Downside of doing it this way is that it's not very efficient (e.g. CPU usage) */

	/* XXX Another downside, since PTY master is one thread for both PTY input and output,
	 * this function will take time, which means we can't receive any INPUT
	 * while we're writing output, until we're all done writing all the output.
	 * We should have a way to interrupt output from the terminal, e.g. if this is taking too long.
	 */

	for (c = 0; *len; c++) {
		ssize_t res, res2 = 0;
		if (c) {
			usleep(sleepus); /* delay in us between each character for I/O */
			/* Sleep for a fixed time rather than polling, because if we were to
			 * receive and process input, then the output speed would get thrown off. */
			if (poll(pfds, 1, 0) > 0) { /* This is not very efficient, but it's the best we can do with poll. */
				*input = 1;
				return total_bytes;
			}
		}
		res = write(fd, *buf, 1);
		if (fd2 != -1) {
			res2 = write(fd2, *buf, 1);
		}
		if (res <= 0 || (fd2 != -1 && res2 <= 0)) {
			return res;
		}
		total_bytes++; /* res must be 1 here */
		(*buf)++;
		(*len)--;
	}
	return total_bytes;
}

static void trigger_node_disconnect(struct bbs_node *node)
{
	/* Client disconnected.
	 * Do not lock the node, because if a shutdown of the node is ongoing,
	 * the node is already locked, and the lock will not be released
	 * until it's ready to be freed.
	 * If that's the case, then it'll wait until this thread has joined,
	 * so in practice there should not be any concurrency issues here (in that particular scenario)... */

	/* Close the slave, this will cause bbs_node_poll, bbs_node_read, bbs_node_write, etc. to return -1.
	 * That will cause the node to exit and it will subsequently join this thread. */
	if (node->slavefd != -1) {
		/* XXX If something else is closing it now, possible race condition here */
		bbs_socket_close(&node->slavefd);
	}
	/* bbs_node_poll will wait for ms to expire (so if ms == -1, very bad!!!)
	 * You'd think poll would get a POLLHUP immediately... but nope! Not sure why.
	 * Need to find a way to make this immediate.
	 * In the meantime, the node threads will exit eventually, just not immediately.
	 */
	/* Resist the urge to also close node->fd here.
	 * Just wait for cleanup to happen, and we'll close node->fd there in due course. */

	/* If there's a child process running for this node, then this might not be sufficient.
	 * Go ahead and make it exit. */
	bbs_node_kill_child(node);
}

/* According to termios(3) man page, the canonical mode buffer of the PTY is 4096, so this should always be large enough */
#define PTY_BUFFER_SIZE 4096

void *pty_master(void *varg)
{
	struct bbs_node *node = varg;
	int pres = 0; /* gcc thinks it can be used uninitialized? */
	struct pollfd fds[3];
	char readbuf[PTY_BUFFER_SIZE];
	char writebuf[PTY_BUFFER_SIZE];
	char strippedbuf[PTY_BUFFER_SIZE];
	ssize_t bytes_read, bytes_wrote;
	nfds_t numfds = 0; /* gcc thinks it can be used uninitialized? */
	/* Expanded scope for slow_write */
	ssize_t last_bytes_read = 0;
	ssize_t lastbyteswrote = 0;
	char *relaybuf = NULL;
	unsigned int speed = 0;
	int is_telnet, is_tdd;
	enum {
		TDD_OTHER,
		TDD_CR,
		TDD_CRLF,
		TDD_CRLFCR,
	} tdd_receive_state = TDD_OTHER;
#ifdef DUMP_PTY_INPUT
	char filename[256];
	FILE *fp;
#endif

	/* Save relevant fields. */
	unsigned int nodeid;
	int amaster, rfd, wfd;
	int ansi = 0; /* gcc thinks it can be used uninitialized? */

	/* Not that these are expected to change, but it makes helgrind happy */
	bbs_node_lock(node);
	nodeid = node->id;
	amaster = node->amaster;
	rfd = node->rfd;
	wfd = node->wfd;
	bbs_node_unlock(node);

	bbs_debug(10, "Starting PTY master for node %d: %d => %s\n", nodeid, amaster, node->slavename);

	/* We don't need to call tty_set_raw on any file descriptor. */

	/* If the node gets shut down,
	 * then node is no longer valid memory to access,
	 * so save what we need from it (above)
	 * and use our local copies of the file descriptor numbers instead.
	 *
	 * Since a shutdown closes the file descriptors, we only
	 * need to close amaster in this thread if we exit due to our own volition,
	 * and since we never do that, we don't need to.
	 */

	is_telnet = STARTS_WITH(node->protname, "TELNET"); /* TELNET or TELNETS */
	is_tdd = NODE_IS_TDD(node);

#ifdef DUMP_PTY_INPUT
	snprintf(filename, sizeof(filename), "%s%s_pty_input_%d", DUMP_DIRECTORY, BBS_SHORTNAME, node->lifetimeid);
	fp = fopen(filename, "wb");
	if (!fp) {
		bbs_error("Failed to open PTY input file for writing: %s\n", strerror(errno));
		return NULL;
	}
#endif

	/* Relay data between terminal (socket side) and pty master */
	for (;;) {
		int spy = 0, spyfdout = -1;
		int spyfdin = -1; /* Doesn't need to be initialized here since it's only used if spy == 1, but gcc isn't smart enough to realize that */

		if (node->slow_bytes_left) {
			goto finishoutput;
		}

		fds[0].fd = rfd;
		fds[1].fd = amaster;
		fds[0].events = fds[1].events = POLLIN | BBS_POLL_QUIT;
		fds[0].revents = fds[1].revents = 0;
		numfds = 2;
		/* Don't try to acquire the regular node lock since that would deadlock during a shutdown. */
		bbs_node_pty_lock(node);
		ansi = node->ansi; /* Check each time since this can be toggled during node runtime */
		speed = node->speed;
		spy = node->spy;
		if (spy) {
			/* You might think that a limitation of this is that we only check this at the begining of
			 * each poll loop here, i.e. if the sysop attaches to a node mid-poll,
			 * then the spying won't take effect until the next loop.
			 * But if we're mid-poll, nothing's happening, silly!
			 * As soon as something happens, we'll loop again. Remember that we're reading char by char,
			 * so effectively as soon as there is a single character of input or output,
			 * spying should take effect here.
			 */
			fds[2].fd = node->spyfdin;
			fds[2].events = POLLIN;
			fds[2].revents = 0;
			numfds++;
			/* "Cache" these on this thread's stack so we don't have to grab the node lock.
			 * This is updated each loop so it won't get stale. */
			spyfdin = node->spyfdin;
			spyfdout = node->spyfd;
		}
		bbs_node_pty_unlock(node);

		pres = poll(fds, numfds, -1);
		pthread_testcancel();
		if (pres < 0) {
			if (errno != EINTR) {
				bbs_error("poll returned %d: %s\n", pres, strerror(errno));
			}
			continue;
		}

gotinput:
		if (fds[0].revents & POLLIN) { /* Got input on socket -> pty */
			char *buf = readbuf;
			bytes_read = read(rfd, readbuf, sizeof(readbuf));
			if (bytes_read <= 0) {
				bbs_debug(10, "socket read returned %ld\n", bytes_read);
				/* If the PTY master exits, need to get rid of the node. This should do the trick. */
				trigger_node_disconnect(node);
				break; /* We'll read 0 bytes upon disconnect */
			}
#ifdef DEBUG_PTY
			if (isprint(*buf)) {
				bbs_debug(10, "Node %d: master->slave(%ld): %.*s (%d %d)\n", nodeid, bytes_read, (int) bytes_read, buf, *buf, bytes_read > 1 ? *(buf + 1) : -1);
			} else {
				bbs_debug(10, "Node %d: master->slave(%ld): (%d %d)\n", nodeid, bytes_read, *buf, bytes_read > 1 ? *(buf + 1) : -1);
			}
#endif
#ifdef DUMP_PTY_INPUT
			/* This can include binary data, so use fwrite: */
			fwrite(buf, 1, (size_t) bytes_read, fp);
#endif
			if (is_telnet && bytes_read == 2 && *buf == '\r' && *(buf + 1) == '\0') { /* Probably faster than strncmp, and performance really matters here */
				/* The sequence CR NUL is used in telnet to indicate a CR not followed by LF (see RFC 854).
				 * Technically it is supposed to be used both ways, but we don't do that for output.
				 * However, we do need to handle it properly for input.
				 *
				 * XXX This is Telnet protocol specific logic, so ideally it would be in net_telnet
				 * and not in the BBS core at all. However, that would require processing all
				 * receive data in net_telnet before getting here. Eventually, we SHOULD do that,
				 * as part of also being able to handle window resizing and such during a session,
				 * but until then, that logic is most naturally handled here.
				 * If/when this logic is moved to net_telnet, it should also be more robust,
				 * i.e. every byte should be analyzed no matter where the CR NUL sequence may fall
				 * across received data (and same for any Telnet escape sequences). */
				bbs_debug(9, "Got CR NUL, translating to CR for slave\n");
				bytes_read = 1; /* Just ignore the NUL. It's not part of the application data so shouldn't be passed down the pseudoterminal. */
			}
			if (is_tdd && bytes_read == 1) { /* With TDD, each character is sent one at a time due to the slow speed of 45/50 baud */
				/* XXX As above, this is TDD-specific logic which ideally would be in net_telnet */
				switch (*buf) {
					case '\r':
						if (tdd_receive_state == TDD_CRLF) {
							/* TDDs seem to send CR LF CR when you hit RETURN, rather than CR LF as specified in V.18.
							 * At least, my Superprint 4425 does.
							 * Since Bauduot code will be sent to us byte by byte, that means on 3 separate
							 * reads from the PTY master, we'll read CR, then LF, then CR.
							 * First, we'll end up emulating CR LF when we see the CR.
							 * Next, we'll end up ignoring the LF due to the emulated CR LF.
							 * Finally, we need to ignore the trailing CR completely.
							 */
							tdd_receive_state = TDD_CRLFCR;
						} else if (tdd_receive_state == TDD_OTHER) {
							tdd_receive_state = TDD_CR;
						} else {
							tdd_receive_state = TDD_OTHER;
						}
						break;
					case '\n':
						tdd_receive_state = tdd_receive_state == TDD_CR ? TDD_CRLF : TDD_OTHER;
						break;
					default:
						*buf = bbs_node_input_translate(node, *buf); /* Translate characters if needed for a TDD */
						tdd_receive_state = TDD_OTHER;
				}
				if (tdd_receive_state != TDD_OTHER) {
					if (tdd_receive_state != TDD_CRLFCR) {
						/* If we're in the middle of reading a CR LF CR sequence, don't do anything yet */
						continue;
					}
					/* Got a complete CR LF CR line sequence.
					 * Just treat it as a single CR (like most terminals send),
					 * so we process it as a single "ENTER" */
					bbs_debug(9, "Treating CR LF CR as a single CR for TDD compatibility\n");
					bytes_read = 1;
				}
			}

			if (bytes_read == 1 && *buf >= 1 && *buf <= 26) {
				char sigchar = (char) ('A' - 1 + *buf);
				/* Received byte corresponds to CTRL + [A through Z],
				 * commonly interpreted to send a signal to the foreground process group.
				 * XXX Technically, there's no guarantee that such a byte would arrive by itself (bytes_read == 1),
				 * but in practice that's generally how it is, if a user did it. */
				if (node->childpid) {
					/*
					 * Initially, we had code here to inspect the ASCII character received (e.g. ETX in ASCII, or 3)
					 * and manually generate the corresponding signal ourselves (e.g. SIGINT).
					 * This is completely redundant and totally unnecessary, and this code has been removed.
					 *
					 * The TTY line discipline is normally responsible for interpreting bytes as signals (e.g. 3 for ^C),
					 * and sending the corresponding signal (e.g. SIGINT) to the foreground process group of the terminal.
					 * Pseudoterminals will, by default, allow the kernel to inspect these and automatically send
					 * the appropriate signal to the foreground process group. There is a call to tcsetpgrp in system.c,
					 * after a child process has forked (but prior to exec) to set the terminal foreground process group.
					 *
					 * The ISIG flag for tcgetattr's c_lflag controls whether or not the kernel will "interpret"
					 * these signals for the PTY, as is done by default typically. Simply leaving this enabled
					 * is sufficient to ensure that the child process gets a SIGINT when a ^C is received. There
					 * is certainly no need to inspect the byte here and manually generate a signal ourselves.
					 *
					 * However, when executing an external program like ssh, for example, it may not be desirable
					 * to allow signals to be handled by the kernel for the PTY. If you're running a program in
					 * a remote SSH session, for example, a ^C should pass through to the remote host, without having
					 * any effect on this system, to allow the remote host to interpret the ^C and send a SIGINT to
					 * its running program. In this case, we want ISIG to be unset.
					 *
					 * In practice, calling tty_disable_signal_handling after set_controlling_term
					 * doesn't seem to make much difference... behavior is as desired whether or not we do that.
					 * It makes sense that ssh would probably disable signal handling on its own,
					 * but programs also exit on their own when receiving input. Calling that function
					 * would probably allowing FORCING programs to exit in certain cases, like
					 * if it's running in raw mode and not exiting gracefully, but terminals don't
					 * account for that sort of thing and neither should we.
					 */
					bbs_debug(10, "Received ^%c, forwarding it to child process\n", sigchar);
				} else {
					/* Now, if we're not executing a child process, things are very different.
					 * In this case, it actually makes sense to do some processing of these signals ourselves, too,
					 * since we'll need to implement custom logic to handle these.
					 * For example, ^C and ^Z here currently cancel any pending output... the kernel
					 * can't help us with that since all this logic is in userspace, in the BBS. */
					switch (*buf) {
						case 3: /* ^C */
						case 26: /* ^Z. The PAUSE/BREAK key typically maps to this, so that's why this is included. */
							node->slow_bytes_left = 0;
							/* Cancel any pending terminal output. This allows users to abort
							 * a large amount of output, particularly with emulated baud rate.
							 * This is a very simple implementation since this is easily done
							 * in the PTY master thread; a more elaborate implementation could
							 * involve setting a flag here to break out of whatever the BBS is
							 * currently in the middle of doing (though most applications should
							 * provide their own mechanism of doing this). But it could be handy
							 * to allow ^C to break out of the door module that might be executing,
							 * in case its input handling is buggy in some way.
							 */
							bbs_debug(3, "Received ^%c, cancelling pending output\n", sigchar);
							break;
						default:
							bbs_debug(3, "Received ^%c, forwarding it\n", sigchar);
					}
					/* If there's no child process, then there's not much reason to relay
					 * this byte through the pseudoterminal, but it doesn't do any harm, either.
					 * For example, if we had some binary terminal logic implemented within the BBS
					 * (not as an external program), we might actually want to receive all the bytes.
					 * So, just relay everything through no matter what. */
				}
			}

			/* We only slow output, not input, so don't use slow_write here, regardless of the speed */
			bytes_wrote = bbs_write(amaster, buf, (size_t) bytes_read);
			/* Don't relay user input to sysop for spying here. If we're supposed to, it'll get echoed back in the output. */
			if (bytes_wrote != bytes_read) {
				bbs_error("Expected to write %ld bytes, only wrote %ld\n", bytes_read, bytes_wrote);
				break;
			}
		} else if (fds[1].revents & POLLIN) { /* Got input from pty -> socket */
			relaybuf = writebuf;

			if (node->slow_bytes_left) {
				goto finishoutput;
			}

			bytes_read = read(amaster, writebuf, sizeof(writebuf) - 1);
			if (bytes_read <= 0) {
				bbs_debug(10, "pty master read returned %ld (%s)\n", bytes_read, strerror(errno));
				break; /* We'll read 0 bytes upon disconnect */
			}
#ifdef DEBUG_PTY
			/* We're not generally concerned with what we're sending (server -> client),
			 * we're usually trying to debug what we're receiving (client -> server),
			 * so this is disabled unless absolutely needed, even with DEBUG_PTY.
			 */
#if 0
			bbs_debug(10, "Node %u: slave->master(%d): %.*s\n", nodeid, bytes_read, bytes_read, writebuf);
#endif
#endif /* DEBUG_PTY */
			if (!ansi) {
				int strippedlen;
				/* Strip ANSI escape sequences from output for terminal, e.g. TTY/TDD */
				writebuf[bytes_read] = '\0'; /* NUL terminate for bbs_ansi_strip */
				/*! \todo XXX This should always get smaller... so couldn't this be done in place? */
				if (!bbs_ansi_strip(writebuf, (size_t) bytes_read, strippedbuf, sizeof(strippedbuf), &strippedlen)) {
					if (strippedlen == 0) {
						bbs_debug(9, "Reduced all %lu bytes to nothing after stripping escape sequences\n", bytes_read);
						/* There is nothing to write, don't even bother calling bbs_write,
						 * since we shouldn't call write with 0 bytes. */
						continue;
					}
					bytes_read = strippedlen;
					relaybuf = strippedbuf;
				} /* else, failed to strip, just write the original data (possibly containing ANSI escape sequences) */
			}
			if (speed) {
				/* Slow write to both real socket and spying fd simultaneously */
				int input;
				last_bytes_read = bytes_read;
				node->slow_bytes_left = (size_t) bytes_read;

				lastbyteswrote = 0;
finishoutput:
				input = 0;
				/* This might seem redundant (we just did the reverse), but is necessary if we just jump here,
				 * otherwise, bytes_read won't have the right value below */
				bytes_read = last_bytes_read;
				bytes_wrote = slow_write(fds, wfd, spyfdout, lastbyteswrote, &relaybuf, &node->slow_bytes_left, speed, &input);
				if (input && bytes_wrote >= 0) {
					/* goto is usually used judiciously in the BBS.
					 * This is an exception, this function is a mess, and we should clean this up.
					 * Here, we're interrupting writing output halfway through so we can read and write input,
					 * then return back to writing the output where we left off. */
					lastbyteswrote = bytes_wrote;
					goto gotinput;
				}
				node->slow_bytes_left = 0;
			} else {
				bytes_wrote = bbs_write(wfd, relaybuf, (size_t) bytes_read);
				if (spy && bytes_wrote == bytes_read) {
					bytes_wrote = bbs_write(spyfdout, relaybuf, (size_t) bytes_read);
				}
			}
			if (bytes_wrote != bytes_read) {
				bbs_error("Expected to write %ld bytes, only wrote %ld\n", bytes_read, bytes_wrote);
			}
		} else if (numfds == 3 && fds[2].revents & POLLIN) { /* Got input from sysop (node spying) -> pty */
			char *buf = readbuf;
			bytes_read = read(spyfdin, readbuf, sizeof(readbuf));
			if (bytes_read <= 0) {
				bbs_debug(10, "pty spy_in read returned %ld (%s)\n", bytes_read, strerror(errno));
				continue; /* We'll read 0 bytes upon disconnect */
			}
#ifdef DEBUG_PTY
			if (isprint(*buf)) {
				bbs_debug(10, "Node %d: spy_in->slave(%ld): %.*s (%d %d)\n", nodeid, bytes_read, (int) bytes_read, buf, *buf, bytes_read > 1 ? *(buf + 1) : -1);
			} else {
				bbs_debug(10, "Node %d: spy_in->slave(%ld): (%d %d)\n", nodeid, bytes_read, *buf, bytes_read > 1 ? *(buf + 1) : -1);
			}
#endif
			if (bytes_read == 2 && *buf == '\r' && *(buf + 1) == '\0') { /* Probably faster than strncmp, and performance really matters here */
				/* This is needed for PuTTY/KiTTY. SyncTERM/Windows Telnet don't need this, since they do CR LF,
				 * but according to RFC 854, CR NUL is also valid for Telnet and so we handle that here.
				 * An important reason for that is if the slave fd is in canonical mode, then the buffer won't
				 * get flushed until there's a LF, so we must do this here to flush output to the slave immediately.
				 */
				bbs_debug(9, "Got CR NUL, translating to CR LF for slave\n");
				*(buf + 1) = '\n';
			}
			if (spy) {
				/* Spoof sysop input (spy) to system.
				 * One great thing about the way we're doing this: notice that we're not using TIOCSTI, which requires CAP_SYS_ADMIN (see man terminal(7)) */
				bytes_wrote = write(amaster, buf, (size_t) bytes_read);
				if (bytes_wrote != bytes_read) {
					bbs_error("Expected to write %ld bytes, only wrote %ld\n", bytes_read, bytes_wrote);
					break;
				}
			} else {
				bbs_warning("Got spy input for node %d, but not a spy target?\n", nodeid);
			}
		} else {
			int x = fds[0].revents ? 0 : fds[1].revents ? 1 : numfds == 3 ? 2 : -1;
			bbs_assert(x >= 0);
			bbs_debug(4, "poll returned %d (revent[%d] = %s)\n", pres, x, poll_revent_name(fds[x].revents));
			if (fds[0].revents & BBS_POLL_QUIT || fds[1].revents & BBS_POLL_QUIT) {
				bbs_debug(2, "PTY %s closed the connection\n", x == 0 ? "master (client)" : "slave (server)");
				if (x == 0) {
					trigger_node_disconnect(node);
				} /* else, slave closed, i.e. node shutdown is probably already ongoing, we don't need to do anything further */
				break;
			}
			bbs_error("poll returned %d (revent %s), but no POLLIN?\n", pres, poll_revent_name(fds[x].revents));
		}
	}

#ifdef DUMP_PTY_INPUT
	fflush(fp);
	fclose(fp);
#endif

	bbs_debug(9, "PTY master exiting for node %d\n", nodeid);
	return NULL;
}
