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

/* #define DEBUG_PTY */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <pthread.h>
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

int bbs_spawn_pty_master(int fd)
{
	pthread_t masterthread;
	struct pty_fds *ptyfds;
	int aslave, amaster;

	if (bbs_openpty(&amaster, &aslave, NULL, NULL, NULL) != 0) {
		bbs_error("Failed to openpty\n");
		return -1;
	}
	bbs_unbuffer_input(aslave, 0); /* Disable canonical mode and echo on this PTY slave */
	bbs_term_makeraw(amaster); /* Make the master side raw */

	ptyfds = calloc(1, sizeof(*ptyfds));
	if (ALLOC_FAILURE(ptyfds)) {
		return -1;
	}
	ptyfds->amaster = amaster;
	ptyfds->fd = fd;
	if (bbs_pthread_create_detached(&masterthread, NULL, pty_master_fd, ptyfds)) {
		free(ptyfds);
		return -1;
	}
	return aslave;
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

	/* We are the PTY slave */
	node->slavefd = open(node->slavename, O_RDWR);
	if (node->slavefd == -1) {
		return -1;
	}

	bbs_assert(isatty(node->amaster));
	bbs_assert(isatty(node->slavefd));
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
		return 0;
	}

	if (!NODE_HAS_PTY(node)) {
		bbs_dprintf(fdout, "Node %d does not have a PTY attached (protocol: %s)\n", node->id, node->protname);
		bbs_node_unlock(node);
		return 0;
	}

	/* Clear the screen to start. */
	SWRITE(fdout, COLOR_RESET); /* Reset color too, just in case */
	SWRITE(fdout, TERM_CLEAR);

	bbs_node_pty_lock(node);
	node->spy = 1;
	node->spyfd = fdout;
	node->spyfdin = fdin;
	if (fgconsole) {
		bbs_sigint_set_alertpipe(spy_alert_pipe);
	}
	bbs_unbuffer_input(fdin, 0); /* Unbuffer input, so that sysop can type on the node's TTY in real time, not just flushed after line breaks. */
	bbs_node_pty_lock(node);
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
		if (bbs_alertpipe_poll(spy_alert_pipe) > 0) {
			bbs_alertpipe_read(spy_alert_pipe);
		}
		/* Restore the original handler for ^C */
		bbs_sigint_set_alertpipe(NULL); /* Unsubscribe, restore default SIGINT handling */
		bbs_alertpipe_close(spy_alert_pipe);

		/* Reset the terminal. */
		bbs_buffer_input(fdin, 1); /* Rebuffer input */
		SWRITE(fdout, COLOR_RESET);
		SWRITE(fdout, TERM_CLEAR);
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
		/* Remote console socket is now closed */
	}

	/* Log this message after the screen was cleared, as the sysop will likely see it,
	 * and this serves as a visual indication that spying has really stopped. */
	bbs_verb(3, "Spying stopped on node %d\n", nodenum);

	node = bbs_node_get(nodenum);
	if (!node) {
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
	bbs_node_lock(node);
	/* Client disconnected */
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

	bbs_node_unlock(node);
}

/* According to termios(3) man page, the canonical mode buffer of the PTY is 4096, so this should always be large enough */
#define PTY_BUFFER_SIZE 4096

void *pty_master(void *varg)
{
	struct bbs_node *node = varg;
	int pres;
	struct pollfd fds[3];
	char readbuf[PTY_BUFFER_SIZE];
	char writebuf[PTY_BUFFER_SIZE];
	char strippedbuf[PTY_BUFFER_SIZE];
	ssize_t bytes_read, bytes_wrote;
	long unsigned int numfds;
	int emulated_crlf = 0, just_did_emulated_crlf = 0;
	/* Expanded scope for slow_write */
	size_t slow_bytes_left = 0;
	ssize_t last_bytes_read = 0;
	ssize_t lastbyteswrote = 0;
	char *relaybuf = NULL;
	unsigned int speed = 0;

	/* Save relevant fields. */
	unsigned int nodeid;
	int amaster, rfd, wfd, ansi;

	/* Not that these are expected to change, but it makes helgrind happy */
	bbs_node_lock(node);
	nodeid = node->id;
	amaster = node->amaster;
	rfd = node->rfd;
	wfd = node->wfd;
	ansi = node->ansi;
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

	/* Relay data between terminal (socket side) and pty master */
	for (;;) {
		int spy = 0, spyfdin, spyfdout = -1;

		if (slow_bytes_left) {
			goto finishoutput;
		}

		fds[0].fd = rfd;
		fds[1].fd = amaster;
		fds[0].events = fds[1].events = POLLIN;
		fds[0].revents = fds[1].revents = 0;
		numfds = 2;
		/* Don't try to acquire the regular node lock since that would deadlock during a shutdown. */
		bbs_node_pty_lock(node);
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
			if (bytes_read == 2 && *buf == '\r' && *(buf + 1) == '\0') { /* Probably faster than strncmp, and performance really matters here */
				/* This is needed for PuTTY/KiTTY. SyncTERM/Windows Telnet don't need this, since they do CR LF,
				 * but according to RFC 854, CR NUL is also valid for Telnet and so we handle that here.
				 * An important reason for that is if the slave fd is in canonical mode, then the buffer won't
				 * get flushed until there's a LF, so we must do this here to flush output to the slave immediately.
				 */
				bbs_debug(9, "Got CR NUL, translating to CR LF for slave\n");
				*(buf + 1) = '\n';
				emulated_crlf = 0;
				just_did_emulated_crlf = 0;
			} else if (bytes_read == 1 && *buf == '\r') {
				/* RLogin clients (at least SyncTERM) seem to do this.
				 * This can also happen with Telnet, so always convert,
				 * and if we happen to get a LF next, ignore it. */
				/* XXX Technically, very small chance we might've read LF on the next poll/read,
				 * but they most likely would arrive together, if there was one,
				 * since they'd be transmitted at the same time. */
				if (just_did_emulated_crlf) {
					/* TDDs seem to send CR LF CR when you hit RETURN, rather than CR LF as specified in V.18.
					 * At least, mine does.
					 * Since Bauduot code will be sent to us byte by byte, that means on 3 separate
					 * reads from the PTY master, we'll read CR, then LF, then CR.
					 * First, we'll end up emulating CR LF when we see the CR.
					 * Next, we'll end up ignoring the LF due to the emulated CR LF.
					 * Finally, we need to ignore the trailing CR completely.
					 */
					bbs_debug(7, "Ignoring spurious CR, since we just emulated CR LF\n");
					emulated_crlf = 0;
					just_did_emulated_crlf = 0;
				} else {
					bbs_debug(9, "Got CR, translating to CR LF for slave\n");
					*(buf + 1) = '\n'; /* We must have a LF for input to work in canonical mode! */
					bytes_read = 2;
					emulated_crlf = 1;
					just_did_emulated_crlf = 0;
				}
			} else if (bytes_read == 1 && *buf == '\n' && emulated_crlf) {
				/* The last thing we read was just a CR, and that was it. We treated it as a CR LF, so ignore the LF now. */
				emulated_crlf = 0;
				just_did_emulated_crlf = 1;
				bbs_debug(7, "Ignoring LF due to previous emulated CR LF\n");
				continue;
			} else {
				if (bytes_read == 1 && NODE_IS_TDD(node)) {
					*buf = bbs_node_input_translate(node, *buf); /* Translate characters if needed for a TDD */
				}
				emulated_crlf = just_did_emulated_crlf = 0;
			}
			/* We only slow output, not input, so don't use slow_write here, regardless of the speed */
			bytes_wrote = bbs_write(amaster, buf, (size_t) bytes_read);
			/* Don't relay user input to sysop for spying here. If we're supposed to, it'll get echoed back in the output. */
			if (bytes_wrote != bytes_read) {
				bbs_error("Expected to write %ld bytes, only wrote %ld\n", bytes_read, bytes_wrote);
				return NULL;
			}
			if (bytes_read == 1 && *buf >= 1 && *buf <= 26) {
				/* In general, we should not intercept messages between 1 and 26 (^A through ^Z).
				 * They'll pass through fine to children on their own, i.e. ^D, etc. do what you'd expect.
				 * Handle ^C explicitly here though in case in the future we want to things when we *don't* have a child,
				 * and because we need to actually generate SIGINT, not write ^C as input (which happens otherwise).
				 * All other CTRL keys can just pass through directly.
				 */
				/* 3 = ETX (^C / SIGINT) */
				if (node->childpid && *buf == 3) {
					/* If executing a child process, also pass SIGINT on, in addition to writing it to the PTY slave */
#if 0
					/* Never mind, this doesn't work (even when run as root)
					 * Possibly because it's been disabled due to being a "security risk",
					 * e.g. https://undeadly.org/cgi?action=article;sid=20170701132619
					 * But that only happened on BSD, not Linux, so dunno...
					 */
					char c = 1; /* termios.c_cc[VINTR] */
					if (ioctl(amaster, TIOCSTI, &c)) {
						bbs_error("TIOCSTI failed: %s\n", strerror(errno));
					}
#endif
					/* This does work. It sends a SIGINT to the child process,
					 * just as if you hit ^C in a shell session.
					 * How it handles it is up to the child process.
					 * It may not necessarily exit. That's okay.
					 *
					 * That said, I feel like this is not some of my best work here...
					 * it just feels hacky to manually detect ETX (decimal 3 ASCI)
					 * and intercept it like this to send the signal.
					 * We should make this work in a more elegant manner, this is
					 * just the first thing I tried that seems to work properly.
					 *
					 * On the flip side, maybe this is a good way to handle it.
					 * The PTY doesn't know if there's a child PID or not.
					 * However, we do (by checking node->childpid).
					 * This way, we can also use ^C within the BBS itself,
					 * depending on certain things, i.e. we can make it
					 * cause a module or door to abort, by writing to the node pipe or something
					 * and returning -1.
					 */
					bbs_debug(3, "Sending SIGINT to process %d\n", node->childpid);
					bbs_assert(node->childpid != getpid());
					if (kill(node->childpid, SIGINT)) {
						bbs_error("SIGINT failed: %s\n", strerror(errno));
					}
				} else {
					switch (*buf) {
						case 3: /* ^C */
						case 26: /* ^Z. The PAUSE/BREAK key typically maps to this, so that's why this is included. */
							slow_bytes_left = 0;
							/* Cancel any pending terminal output. This allows users to abort
							 * a large amount of output, particularly with emulated baud rate. */
							bbs_debug(3, "Received ^%c, cancelling pending output\n", 'A' - 1 + *buf);
							break;
						default:
							/* XXX In the future, could be used by the BBS to do certain things too */
							bbs_debug(3, "Ignoring ^%c and not forwarding it\n", 'A' - 1 + *buf);
					}
					continue;
				}
			}
		} else if (fds[1].revents & POLLIN) { /* Got input from pty -> socket */
			relaybuf = writebuf;

			if (slow_bytes_left) {
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
				if (!bbs_ansi_strip(writebuf, (int) bytes_read, strippedbuf, sizeof(strippedbuf), &strippedlen)) {
					bytes_read = strippedlen;
					relaybuf = strippedbuf;
				} /* else, failed to strip, just write the original data (possibly containing ANSI escape sequences) */
			}
			if (speed) {
				/* Slow write to both real socket and spying fd simultaneously */
				int input;
				last_bytes_read = bytes_read;
				slow_bytes_left = (size_t) bytes_read;

				lastbyteswrote = 0;
finishoutput:
				input = 0;
				/* This might seem redundant (we just did the reverse), but is necessary if we just jump here,
				 * otherwise, bytes_read won't have the right value below */
				bytes_read = last_bytes_read;
				bytes_wrote = slow_write(fds, wfd, spyfdout, lastbyteswrote, &relaybuf, &slow_bytes_left, speed, &input);
				if (input && bytes_wrote >= 0) {
					/* goto is usually used judiciously in the BBS.
					 * This is an exception, this function is a mess, and we should clean this up.
					 * Here, we're interrupting writing output halfway through so we can read and write input,
					 * then return back to writing the output where we left off. */
					lastbyteswrote = bytes_wrote;
					goto gotinput;
				}
				slow_bytes_left = 0;
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
				break; /* We'll read 0 bytes upon disconnect */
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
					return NULL;
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

	bbs_debug(9, "PTY master exiting for node %d\n", nodeid);
	return NULL;
}
