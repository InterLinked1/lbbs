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
 * \brief Sysop console
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h> /* use isprint */
#include <poll.h>
#include <sys/un.h>	/* use struct sockaddr_un */

#include "include/node.h"
#include "include/pty.h"
#include "include/module.h"
#include "include/term.h"
#include "include/mail.h"
#include "include/utils.h" /* use bbs_dump_threads */
#include "include/startup.h"
#include "include/alertpipe.h"
#include "include/cli.h"

#include "include/mod_history.h"

extern int option_nofork;

#define my_set_stdout_logging(fd, setting) if (console->interactive) { bbs_cli_set_stdout_logging(fd, setting); }

/* Since we now support remote consoles, bbs_printf is not logical to use in this module */
#ifdef bbs_printf
#undef bbs_printf
#endif
#define bbs_printf __Do_not_use_bbs_printf_use_bbs_dprintf
/* Use the macro to suppress unused macro warning with -Wunused-macros */
#ifdef bbs_printf
#endif

static int console_alertpipe[2];
static int unloading = 0;

static void show_copyright(int fd, int footer)
{
	bbs_dprintf(fd,
	BBS_TAGLINE ", " BBS_COPYRIGHT "\n"
	BBS_SHORTNAME " comes with ABSOLUTELY NO WARRANTY; for details type '/warranty'\n"
	"This is free software, and you are welcome to redistribute it\n"
	"under certain conditions; type '/copyright' for details.\n");
	if (footer) {
		bbs_dprintf(fd, "====================================================================\n");
	}
}

static void show_license(int fd)
{
	bbs_dprintf(fd,
	BBS_SHORTNAME " is free software; you can redistribute it and/or modify\n"
	"it under the terms of the GNU General Public License version 2 as\n"
	"published by the Free Software Foundation.\n\n"
	"This program also contains components licensed under other licenses.\n"
	"They include:\n\n"
	"This program is distributed in the hope that it will be useful,\n"
	"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
	"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
	"GNU General Public License for more details.\n\n"
	"You should have received a copy of the GNU General Public License\n"
	"along with this program; if not, write to the Free Software\n"
	"Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n");
}

static void show_warranty(int fd)
{
	bbs_dprintf(fd, "                            NO WARRANTY\n"
	"BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY\n"
	"FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN\n"
	"OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES\n"
	"PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED\n"
	"OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF\n"
	"MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS\n"
	"TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE\n"
	"PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,\n"
	"REPAIR OR CORRECTION.\n\n"
	"IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING\n"
	"WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR\n"
	"REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,\n"
	"INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING\n"
	"OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED\n"
	"TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY\n"
	"YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER\n"
	"PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE\n"
	"POSSIBILITY OF SUCH DAMAGES.\n");
}

/* Not defined as an enum, since we store this as 1 bit in the struct anyways */
#define CONSOLE_FOREGROUND 0
#define CONSOLE_REMOTE 1

struct sysop_console {
	int sfd;
	int fdin;
	int fdout;
	int amaster; /* PTY master fd for this console */
	pthread_t thread;
	pthread_t ptythread; /* PTY relay thread for remote consoles */
	unsigned int remote:1;
	unsigned int dead:1;
	unsigned int log:1;
	unsigned int tty:1;
	unsigned int interactive:1;
	RWLIST_ENTRY(sysop_console) entry;
};

/*
 * For the test suite, none of the consoles launched are using pseudoterminals,
 * so they're not actually real TTYs.
 * In other words, the foreground console immediately exits in the tests,
 * but that's fine, since we only use it for the log output. In those cases,
 * we don't set up a terminal in the first place.
 *
 * For remote consoles, we want to be able to service those even if they are not TTYs,
 * first and foremost because test_sysop needs a functioning console.
 * But if they aren't a TTY (which would really only happen in tests, not real usage),
 * avoid TTY-specific function calls like tcgetattr, etc. */
#define CONSOLE_HAS_TTY(c) (c->tty)

static RWLIST_HEAD_STATIC(consoles, sysop_console);

static int cli_testemail(struct bbs_cli_args *a)
{
	const char *recipient = a->argc >= 2 ? a->argv[1] : NULL; /* Default to sysop */
	return bbs_mail(0, recipient, NULL, NULL, "Test Email",
		"This is a test message generated automatically by the LBBS bulletin board system.\r\n"
		"You may be receiving this to test deliverability to your address after a previous delivery failure.\r\n"
		"If you have any questions, please contact your sysop directly; please, do not respond to this message.\r\n"
		"\t--LBBS\r\n"); /* Email should end with CR LF */
}

static int cli_mtrim(struct bbs_cli_args *a)
{
	size_t released = bbs_malloc_trim();
	bbs_dprintf(a->fdout, "%lu bytes released\n", released);
	return 0;
}

static int cli_assert(struct bbs_cli_args *a)
{
	/* Development testing only: this command is not listed */
	char *tmp = NULL;
	UNUSED(a);
	bbs_assert_exists(tmp);
	return 0;
}

static int cli_copyright(struct bbs_cli_args *a)
{
	show_copyright(a->fdout, 0);
	return 0;
}

static int cli_license(struct bbs_cli_args *a)
{
	show_license(a->fdout);
	return 0;
}

static int cli_warranty(struct bbs_cli_args *a)
{
	show_warranty(a->fdout);
	return 0;
}

static int cli_fdclose(struct bbs_cli_args *a)
{
	int fd = atoi(a->argv[1]);
	if (shutdown(fd, SHUT_RDWR)) {
		bbs_dprintf(a->fdout, "Shutdown failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int sysop_command(struct sysop_console *console, const char *s)
{
	int res;

	my_set_stdout_logging(console->fdout, console->log);
	res = bbs_cli_exec(console->fdin, console->fdout, s);
	my_set_stdout_logging(console->fdout, console->log); /* Reset, in case a CLI command changed it */

	if (res == ENOENT) {
		bbs_dprintf(console->fdout, "ERROR: Invalid command: '%s'. Press '?' for help.\n", s);
	}

	return res;
}

static void console_close_fds(struct sysop_console *console)
{
	if (console->fdin != console->fdout) { /* will be the same for foreground console */
		close_if(console->fdin);
	}
	if (console->fdout != console->sfd) { /* will be the same for a non-interactive session with no PTY */
		close_if(console->fdout);
	}
	close_if(console->sfd);
}

static void console_cleanup(struct sysop_console *console)
{
	bbs_assert(console->remote);
	RWLIST_WRLOCK(&consoles);
	RWLIST_REMOVE(&consoles, console, entry);
	bbs_assert_exists(console);

	/* Must do before console_close_fds since that sets fd to -1 */
	if (console->interactive) {
		bbs_remove_logging_fd(console->fdout);
	}

	/* Interrupt PTY thread to force poll() to exit */
	if (console->interactive) {
		if (console->ptythread) {
			bbs_pthread_interrupt(console->ptythread);
		}
		/* Finally, join the PTY thread.
		 * We don't do this before console_close_fds, since closed file descriptors
		 * is the signal that ptythread uses to exit. Otherwise, it'd just hang.
		 *
		 * However, interrupt is not guaranteed to actually cause the thread to exit (rare but possible),
		 * and since we don't set a flag the thread can check to exit, it could still hang indefinitely.
		 * So, wait politely for a bit, but on the off-chance things go south, close the file descriptors anyways. */
		if (bbs_pthread_timedjoin(console->ptythread, NULL, SEC_MS(2))) {
			bbs_warning("Sysop console PTY thread hasn't exited yet, forcibly closing its file descriptors\n");
			console_close_fds(console);
			/* Okay, now the thread should definitely exit of its own volition */
			bbs_pthread_join(console->ptythread, NULL);
		} else {
			console_close_fds(console);
		}

		/* Clean up the master side of the PTY. The slave is already closed. */
		close_if(console->amaster);
	} else { /* remote command execution won't have a PTY */
		console_close_fds(console);
	}

	/* console->thread is detached, so we don't join it */
	free(console);
	RWLIST_UNLOCK(&consoles);
}

static void print_time(int fdout)
{
	char timebuf[40];
	time_t now;
	struct tm nowdate;

	now = time(NULL);
	localtime_r(&now, &nowdate);
	strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M:%S %P %Z", &nowdate);
	bbs_dprintf(fdout, "%s\n", timebuf);
}

static void load_hist_command(struct sysop_console *console, const char **s)
{
	my_set_stdout_logging(console->fdout, 0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
	bbs_dprintf(console->fdout, TERM_RESET_LINE "\r/%s", *s);
}

static void edit_hist_command(struct sysop_console *console, const char **s)
{
	/* This addresses the desire to be able to modify commands in history to run a new command.
	 * This is complicated by the fact that commands are read in buffered mode,
	 * while most of the rest of console operation is unbuffered.
	 *
	 * To allow editing a command from history using e.g. backspace,
	 * we use a clever trick.
	 * If we start editing a command by hitting the BACKSPACE / DEL key,
	 * then we write the command from history into the PTY master fd,
	 * which will go through the pseudoterminal just as if the user
	 * had manually typed this.
	 * Then the buffered editing facilities can be used,
	 * and we can just read the edited command from the slave as usual.
	 * Only caveat is that ESC can no longer be used to cancel inputting a command.
	 * Once you start editing the command, you commit to running SOMETHING...
	 * What we can do is detect ESC in the ran command and ignore it if ESC is present. */
	if (console->amaster != -1 && *s) {
		/* Foreground console doesn't have a PTY created,
		 * since it doesn't need one. Downside is we can't inject
		 * a command this way. */
		size_t cmdlen = strlen(*s);
		if (cmdlen <= 1) {
			/* Not much point then */
			return;
		}

		/* First, clear the current line before we overwrite on it */
		if (SWRITE(console->fdout, TERM_RESET_LINE "\r") == -1) {
			return;
		}

		if (CONSOLE_HAS_TTY(console)) {
			bbs_buffer_input(console->fdin, 1); /* We're currently unbuffered, we need to buffer first. */
		}
		bbs_writef(console->fdout, "/"); /* The / isn't actually buffered, buffering starts after, so just print */
		bbs_writef(console->amaster, "%.*s", (int) (cmdlen - 1), *s);  /* Write onto the master to spoof the user typing this, minus the last char since user hit backspace */
		*s = NULL; /* Pretend this is real input, not history browsing anymore */
	}
}

static void *sysop_handler(void *varg)
{
	char buf[1];
	char cmdbuf[256];
	int res;
	struct pollfd pfds[2];
	char titlebuf[84];
	int sysopfdin, sysopfdout;
	const char *histentry;
	int modified_hist = 0;
	int executed_command = 0;
	struct sysop_console *console = varg;

	sysopfdin = console->fdin;
	sysopfdout = console->fdout;

	console->log = 1; /* Logging to console enabled by default */
	if (console->remote && console->interactive) {
		bbs_add_logging_fd(sysopfdout);
	}

	/* Keep it short but descriptive, for a user to differentiate sysop consoles on multiple systems, as well as foreground vs remote. */
	snprintf(titlebuf, sizeof(titlebuf), "%s%s%s", console->remote ? "Sysop" : "LBBS", S_COR(bbs_hostname(), "@", ""), S_IF(bbs_hostname()));
	bbs_dprintf(sysopfdout, TERM_TITLE_FMT, titlebuf);

	if (console->interactive && !CONSOLE_HAS_TTY(console)) {
		/* Generally speaking, the console will be a TTY, if using the rsysop program.
		 * However, in test_sysop, the connection doesn't use a PTY and so it doesn't appear to us as a TTY.
		 * That's fine, but we need to take care to skip any calls that are TTY-specific. */
		bbs_debug(3, "%s console (%d/%d) is not a TTY\n", console->remote ? "Remote" : "Foreground", sysopfdin, sysopfdout);
	}

	/* Disable input buffering so we can read a character as soon as it's typed */
	if (CONSOLE_HAS_TTY(console) && bbs_unbuffer_input(sysopfdin, 0)) {
		bbs_error("Failed to unbuffer fd %d, sysop console %d/%d will be unavailable\n", sysopfdin, sysopfdin, sysopfdout);
		/* If this fails, the foreground console is just not going to work properly.
		 * For example, supervisorctl doesn't seem to have a TTY/PTY available.
		 * Just use screen or tmux? */
		goto cleanup;
	}

	pfds[0].fd = sysopfdin;
	pfds[0].events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	pfds[1].fd = console_alertpipe[0];
	pfds[1].events = POLLIN;

	if (console->interactive && (console->remote || bbs_is_fully_started())) {
		/* For foreground console, if BBS is still starting,
		 * we already registered a startup callback to show copyright later. */
		show_copyright(sysopfdout, 1);
	}

	histentry = NULL; /* initiailization must be after pthread_cleanup_push to avoid "variable might be clobbered" warning */
	while (!console->dead) {
		if (!console->interactive && executed_command++) {
			break; /* Only one loop iteration for single command executions */
		}
		pfds[0].revents = pfds[1].revents = 0;
		res = poll(pfds, 2, -1);
		if (console->dead) {
			bbs_debug(3, "Console %d/%d has been instructed to exit\n", sysopfdin, sysopfdout);
			break;
		}
		if (res < 0) {
			if (errno != EINTR) {
				bbs_debug(3, "poll returned %d: %s\n", res, strerror(errno));
				break;
			}
			continue;
		}
		if (pfds[1].revents) {
			my_set_stdout_logging(sysopfdout, console->log);
			if (CONSOLE_HAS_TTY(console)) {
				bbs_buffer_input(sysopfdin, 1);
			}
			break;
		} else if (pfds[0].revents & POLLIN) {
			ssize_t bytes_read = read(sysopfdin, buf, sizeof(buf));
			if (bytes_read <= 0) {
				my_set_stdout_logging(sysopfdout, 0); /* The console has disconnected, so don't attempt to log to it anymore, it will fail. */
				bbs_debug(5, "read returned %ld\n", bytes_read);
				break;
			}
			switch (tolower(buf[0])) {
				case '?':
				case 'h':
					bbs_dprintf(sysopfdout, " == Quick Commands ==\n");
					bbs_dprintf(sysopfdout, "? - Show help\n");
					bbs_dprintf(sysopfdout, "c - Clear screen\n");
					bbs_dprintf(sysopfdout, "h - Show help\n");
					bbs_dprintf(sysopfdout, "l - Enable/disable logging to this console\n");
					bbs_dprintf(sysopfdout, "n - List active nodes\n");
					bbs_dprintf(sysopfdout, "q - Shut down the BBS (with confirmation)\n");
					bbs_dprintf(sysopfdout, "s - Show BBS system status\n");
					bbs_dprintf(sysopfdout, "t - Show BBS system time\n");
					bbs_dprintf(sysopfdout, "u - Show list of users\n");
					bbs_dprintf(sysopfdout, "UP -> Previous command\n");
					bbs_dprintf(sysopfdout, "DN -> More recent command\n");
					bbs_cli_exec(sysopfdin, sysopfdout, "help");
					break;
				case 'c':
					bbs_dprintf(sysopfdout, TERM_CLEAR); /* TERM_CLEAR doesn't end in a newline, so normally, flush output, but bbs_printf does this for us. */
					bbs_dprintf(sysopfdout, TERM_CLEAR_SCROLLBACK); /* Clear scrollback buffer */
					break;
				case 'l':
					SET_BITFIELD(console->log, !console->log); /* Save the new log setting */
					my_set_stdout_logging(sysopfdout, console->log); /* Make it take effect immediately */
					bbs_dprintf(sysopfdout, "Logging is now %s for %s console\n", console->log ? "enabled" : "disabled", console->remote ? "this remote" : "the foreground");
					break;
				case 'n':
					bbs_cli_exec(sysopfdin, sysopfdout, "nodes");
					break;
				case 's':
					bbs_view_settings(sysopfdout);
					break;
				case 't':
					print_time(sysopfdout);
					break;
				case 'u':
					bbs_cli_exec(sysopfdin, sysopfdout, "users");
					break;
				case 'q':
					{
						int do_quit = 0;
						my_set_stdout_logging(sysopfdout, 0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
						bbs_dprintf(sysopfdout, "\n%sReally shut down the BBS? [YN] %s", COLOR(TERM_COLOR_RED), COLOR_RESET);
						res = poll(pfds, console->remote ? 1 : 2, 10000);
						if (res < 0) {
							if (errno != EINTR) {
								bbs_error("poll returned %d: %s\n", res, strerror(errno));
							}
						} else if (res == 0) {
							bbs_dprintf(sysopfdout, "\nShutdown attempt expired\n");
						} else if (pfds[1].revents) {
							/* alertpipe had activity in the meantime */
							my_set_stdout_logging(sysopfdout, console->log);
							if (CONSOLE_HAS_TTY(console)) {
								bbs_buffer_input(sysopfdin, 1);
							}
							goto cleanup;
						} else {
							bytes_read = read(sysopfdin, buf, 1);
							if (bytes_read <= 0) {
								bbs_debug(5, "read returned %ld\n", bytes_read);
							} else if (buf[0] == 'y' || buf[0] == 'Y') {
								do_quit = 1;
							}
						}
						bbs_dprintf(sysopfdout, "\n");
						if (do_quit) {
							bbs_cli_exec(sysopfdin, sysopfdout, "shutdown");
						}
					}
					break;
				case KEY_ESC:
					res = bbs_read_escseq(sysopfdin);
					switch (res) {
						case KEY_UP:
							histentry = bbs_history_older();
							if (histentry) {
								load_hist_command(console, &histentry);
							}
							break;
						case KEY_DOWN:
							histentry = bbs_history_newer();
							if (histentry) {
								load_hist_command(console, &histentry);
							}
							break;
						case KEY_ESC:
							bbs_history_reset();
							histentry = NULL;
							my_set_stdout_logging(sysopfdout, console->log); /* If running in foreground, re-enable STDOUT logging */
							bbs_dprintf(sysopfdout, "\n"); /* Print new line since we had history on the line */
							break;
						case KEY_BACKSPACE:
							goto backsp;
						default:
							/* Ignore */
							break;
					}
					break;
				case '\n':
					if (histentry) {
						bbs_dprintf(sysopfdout, "\n"); /* Print new line since we had history on the line */
						safe_strncpy(cmdbuf, histentry, sizeof(cmdbuf));
						bbs_history_add(cmdbuf);
						bbs_history_reset();
						histentry = NULL;
						my_set_stdout_logging(sysopfdout, 0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
						if (CONSOLE_HAS_TTY(console)) {
							bbs_buffer_input(sysopfdin, 1);
						}
						res = sysop_command(console, cmdbuf);
						if (CONSOLE_HAS_TTY(console)) {
							bbs_unbuffer_input(sysopfdin, 0);
						}
						my_set_stdout_logging(sysopfdout, console->log); /* If running in foreground, re-enable STDOUT logging */
					} else {
						bbs_dprintf(sysopfdout, "\n"); /* Print newline for convenience */
					}
					break;
				case '/':
					if (console->interactive) {
						bbs_dprintf(sysopfdout, "/");
					}
awaitcmd:
					my_set_stdout_logging(sysopfdout, 0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
					/* One downside of this approach is if the user hits UP to retrieve a command from history,
					 * we're not yet in "edit move", so the user can't start typing to append to it.
					 * However, BACKSPACE will enter edit mode, after which characters can be appended. */
					if (CONSOLE_HAS_TTY(console)) {
						bbs_buffer_input(sysopfdin, 1);
					}
					res = poll(pfds, console->remote ? 1 : 2, 300000);
					if (res < 0) {
						if (errno != EINTR) {
							bbs_error("poll returned %d: %s\n", res, strerror(errno));
						}
					} else if (res == 0) {
						bbs_dprintf(sysopfdout, "\nCommand expired\n");
					} else if (pfds[1].revents) {
						my_set_stdout_logging(sysopfdout, console->log);
						if (CONSOLE_HAS_TTY(console)) {
							bbs_buffer_input(sysopfdin, 1);
						}
						goto cleanup;
					} else {
						bytes_read = read(sysopfdin, cmdbuf, sizeof(cmdbuf) - 1);
						if (bytes_read <= 0) {
							bbs_debug(5, "read returned %ld\n", bytes_read);
						} else {
							cmdbuf[bytes_read] = '\0'; /* Safe, since size - 1 above */
							bbs_term_line(cmdbuf);
							/* Save in history */
							bbs_history_add(cmdbuf);
							res = sysop_command(console, cmdbuf);
						}
					}
					if (CONSOLE_HAS_TTY(console)) {
						bbs_unbuffer_input(sysopfdin, 0);
					}
					my_set_stdout_logging(sysopfdout, console->log); /* If running in foreground, re-enable STDOUT logging */
					break;
				case 127: /* Forward delete, but many terminal emulators send this for backspace */
backsp:
					if (histentry) {
						edit_hist_command(console, &histentry);
						modified_hist = 1;
						goto awaitcmd;
					}
					/* Fall through */
				default:
					if (isprint(buf[0])) {
						bbs_debug(5, "Received character %d (%c) on sysop console\n", buf[0], buf[0]);
					} else {
						bbs_debug(5, "Received character %d on sysop console\n", buf[0]);
					}
					if (modified_hist) {
						modified_hist = 0;
						/* Once we hit backspace and start modifying a previous command,
						 * there is no way to escape from it.
						 * ESC also doesn't end up in the buffer,
						 * so we can't tell if ESC was pressed or not.
						 * However, we can delete the entire command by backing up until the /,
						 * then hit ENTER, and nothing will try to execute.
						 * Also, we need to manually print a newline. */
						bbs_dprintf(sysopfdout, "\n");
					}
					bbs_dprintf(sysopfdout, "Invalid command '%c'. Press '?' for help.\n", isprint(buf[0]) ? buf[0] : ' ');
					break;
			}
		} else {
			if (!(pfds[0].revents & BBS_POLL_QUIT)) {
				bbs_error("poll returned %d, but no POLLIN?\n", res);
			}
			break;
		}
	}

cleanup:
	bbs_debug(2, "Sysop console (fd %d/%d) thread exiting\n", sysopfdin, sysopfdout);
	if (console->remote) {
		console_cleanup(console);
	}
	return NULL;
}

static void *sysop_pty_master(void *varg)
{
	struct sysop_console *console = varg;
	struct pollfd fds[2];
	char buf[4096]; /* According to termios(3) man page, the canonical mode buffer of the PTY is 4096, so this should always be large enough */
	ssize_t bytes_read, bytes_wrote;

	fds[0].fd = console->sfd;
	fds[1].fd = console->amaster;
	fds[0].events = fds[1].events = POLLIN | POLLPRI | POLLERR | POLLNVAL;

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
			} else {
				bbs_debug(6, "poll returned %d: %s\n", pres, strerror(errno));
			}
			break; /* Break even on EINTR, so that bbs_pthread_interrupt can force us to exit */
		}
		if (fds[0].revents & POLLIN) { /* Got input on socket -> pty */
			/*! \todo We are just copying bytes from one fd to another here.
			 * Use copy_file_range or something that can do an in-kernel copy? */
			bytes_read = read(fds[0].fd, buf, sizeof(buf));
			if (bytes_read <= 0) {
				bbs_debug(7, "read returned %ld\n", bytes_read);
				break; /* We'll read 0 bytes upon disconnect */
			}
			bytes_wrote = write(fds[1].fd, buf, (size_t) bytes_read);
			if (bytes_wrote != bytes_read) {
				bbs_error("Expected to write %ld bytes, only wrote %ld (%s)\n", bytes_read, bytes_wrote, strerror(errno));
				if (bytes_wrote == -1) {
					break;
				}
			}
		} else if (fds[1].revents & POLLIN) { /* Got input from pty -> socket */
			bytes_read = read(fds[1].fd, buf, sizeof(buf) - 1);
			if (bytes_read <= 0) {
				bbs_debug(10, "pty master read returned %ld (%s)\n", bytes_read, strerror(errno));
				break; /* We'll read 0 bytes upon disconnect */
			}
			bytes_wrote = write(fds[0].fd, buf, (size_t) bytes_read);
			if (bytes_wrote != bytes_read) {
				bbs_error("Expected to write %ld bytes, only wrote %ld (%s)\n", bytes_read, bytes_wrote, strerror(errno));
				if (bytes_wrote == -1) {
					break;
				}
			}
		} else {
			/* Something else happened that should effect a disconnect. */
			bbs_debug(10, "Exceptional activity returned from poll: %s/%s\n", poll_revent_name(fds[0].revents), poll_revent_name(fds[1].revents));
			break;
		}
	}

	bbs_debug(10, "PTY master exiting for %d <=> %d\n", fds[1].fd, fds[0].fd);
	/* We need to close the file descriptors for closes from the network to be detected by sysop_handler thread. */
	close_if(console->sfd);
	close_if(console->amaster);
	return NULL;
}

/*!
 * \brief Create and spawn a generic PTY master relay for the console session
 * \param console
 * \note This thread will continue until either file descriptor closes. It should NOT be created detached.
 * \retval -1 on failure, slave file descriptor on success
 */
static int spawn_pty_master(struct sysop_console *console)
{
	int aslave;

	if (bbs_openpty(&console->amaster, &aslave, NULL, NULL, NULL) != 0) {
		bbs_error("Failed to openpty\n");
		return -1;
	}
	bbs_unbuffer_input(aslave, 0); /* Disable canonical mode and echo on this PTY slave */
	bbs_term_makeraw(console->amaster); /* Make the master side raw */

	/* Don't create the thread detached, because if nobody waits to join it,
	 * the BBS could finish shutting down before we return. */
	if (bbs_pthread_create(&console->ptythread, NULL, sysop_pty_master, console)) {
		return -1;
	}
	return aslave;
}

/*!
 * \brief Launch sysop console
 * \param remote 1 for remote console, 0 for foreground console
 * \param sfd Socket file descriptor
 * \param 0 if console was successfully launched, -1 on failure
 */
static int launch_sysop_console(int remote, int sfd)
{
	int res = 0;
	int skip_pty = 0;
	struct sysop_console *console;

	if (!remote && !isatty(sfd)) {
		/* See comment for CONSOLE_HAS_TTY macro */
		bbs_debug(3, "Foreground console is not a terminal, not allocating console\n");
		/* No file descriptors or thread to clean up since threads are only for remotes */
		return -1;
	}

	console = calloc(1, sizeof(*console));
	if (ALLOC_FAILURE(console)) {
		if (remote) {
			close(sfd); /* This is the only one open right now */
		}
		return -1;
	}

	console->sfd = sfd; /* Socket file descriptor */
	console->interactive = 1; /* All consoles are interactive except for command executions */
	SET_BITFIELD(console->remote, remote);

	if (remote) {
		/* XXX Hack job!
		 * For command execution via rsysop, we don't want to launch a PTY (we don't need one) or display the usual banner (clutter).
		 * The only way I can seem to distinguish the two automatically is that command executions will send
		 * the data immediately, so POLLIN is already triggered here. */
		if (bbs_poll(sfd, 0) == 1) {
			skip_pty = 1;
		}
	}

	if (!remote) {
		console->amaster = -1;
		console->fdin = STDIN_FILENO;
		console->fdout = STDOUT_FILENO;
		console->tty = 1; /* If it weren't, we would have aborted at the top of this function */
	} else {
		if (skip_pty) {
			console->fdin = sfd;
			console->fdout = sfd;
			console->interactive = 0;
			console->tty = 0;
		} else {
			int aslave;
			/* Now, we need to create a pseudoterminal for the UNIX socket, the sysop thread needs a PTY.
			 * aslave and amaster are overridden here with the real values to use. */
			aslave = spawn_pty_master(console); /* Only needed for remote consoles. The foreground console doesn't have a separate thread. */
			if (aslave == -1) {
				close(sfd);
				return -1;
			}
			console->fdin = aslave; /* PTY */
			console->fdout = aslave;
			SET_BITFIELD(console->tty, isatty(aslave));
		}
	}

	RWLIST_WRLOCK(&consoles);
	/* Note there is no SIGINT handler for remote consoles,
	 * so ^C will just exit the remote console without killing the BBS. */
	if (remote) {
		if (CONSOLE_HAS_TTY(console)) {
			bbs_unbuffer_input(console->fdin, 0); /* Disable canonical mode and echo on this PTY slave */
			bbs_dprintf(console->fdout, TERM_CLEAR); /* Clear the screen on connect */
		}
		/* We create the thread detached since there isn't anything to join consoles at runtime
		 * when they disconnect. However, the console itself is removed from the linked list at that point,
		 * so there are no resource leaks while running. All consoles must be cleaned up
		 * prior to the module being able to unload. */
		res = bbs_pthread_create_detached(&console->thread, NULL, sysop_handler, console);
	} else {
		res = bbs_pthread_create(&console->thread, NULL, sysop_handler, console);
	}
	if (res) {
		bbs_error("Failed to create %s sysop thread for %d/%d\n", remote ? "remote" : "foreground", console->fdin, console->fdout);
		console_close_fds(console);
		if (console->ptythread) {
			bbs_pthread_join(console->ptythread, NULL);
		}
		free(console);
	}
	RWLIST_INSERT_TAIL(&consoles, console, entry);
	RWLIST_UNLOCK(&consoles);
	return res;
}

static int uds_socket = -1; /*!< UDS socket for allowing incoming local UNIX connections */
static pthread_t uds_thread;

static void *remote_sysop_listener(void *unused)
{
	struct sockaddr_un sunaddr;
	socklen_t len;
	int sfd;
	struct pollfd pfd;

	UNUSED(unused);

	pfd.fd = uds_socket;
	pfd.events = POLLIN;

	for (;;) {
		int res = poll(&pfd, 1, -1); /* Wait forever for an incoming connection. */
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (!pfd.revents) {
			continue; /* Shouldn't happen? */
		}
		if (unloading) {
			break;
		}
		len = sizeof(sunaddr);
		sfd = accept(uds_socket, (struct sockaddr *) &sunaddr, &len);
		if (sfd < 0) {
			if (errno != EINTR) {
				bbs_debug(1, "accept returned %d: %s\n", sfd, strerror(errno));
				break;
			}
			continue;
		}
		bbs_verb(4, "Accepting new remote sysop connection\n");
		launch_sysop_console(CONSOLE_REMOTE, sfd); /* Launch sysop console for this connection */
	}
	return NULL;
}

static int cli_consoles(struct bbs_cli_args *a)
{
	struct sysop_console *console;

	bbs_dprintf(a->fdout, "%1s %4s %4s %3s %4s %3s %s\n", "R", "IN", "OUT", "TTY", "Dead", "Log", "Thread");
	RWLIST_RDLOCK(&consoles);
	RWLIST_TRAVERSE(&consoles, console, entry) {
		bbs_dprintf(a->fdout, "%1s %4d %4d %3s %4s %3s %16lu\n", console->remote ? "*" : "", console->fdin, console->fdout, console->tty ? "*" : "", BBS_YN(console->dead), BBS_YN(console->log), (unsigned long) console->thread);
	}
	RWLIST_UNLOCK(&consoles);

	return 0;
}

static struct bbs_cli_entry cli_commands_sysop[] = {
	BBS_CLI_COMMAND(cli_consoles, "consoles", 1, "List all sysop console sessions", NULL),
	/* General */
	BBS_CLI_COMMAND(cli_testemail, "testemail", 1, "Send test email to a recipient (default: sysop)", "testemail <address>"),
	BBS_CLI_COMMAND(cli_mtrim, "mtrim", 1, "Manually release free memory at the top of the heap", NULL),
	BBS_CLI_COMMAND(cli_assert, "assert", 1, "Manually trigger an assertion (WARNING: May abort BBS)", NULL),
	BBS_CLI_COMMAND(cli_copyright, "copyright", 1, "Show copyright notice", NULL),
	BBS_CLI_COMMAND(cli_license, "license", 1, "Show license notice", NULL),
	BBS_CLI_COMMAND(cli_warranty, "warranty", 1, "Show warranty notice", NULL),
	BBS_CLI_COMMAND(cli_fdclose, "fdclose", 2, "Manually close a file descriptor associated with a socket", "fdclose <fd>"),
};

static int unload_module(void)
{
	struct sysop_console *console;

	bbs_cli_unregister_multiple(cli_commands_sysop);
	unloading = 1;
	bbs_alertpipe_write(console_alertpipe);

	if (uds_socket != -1) {
		bbs_socket_thread_shutdown(&uds_socket, uds_thread);
		unlink(BBS_SYSOP_SOCKET);
	}

	/* Close all the consoles. */
	RWLIST_RDLOCK(&consoles);
	RWLIST_TRAVERSE_SAFE_BEGIN(&consoles, console, entry) {
		bbs_debug(3, "Instructing %s sysop console %p (%d/%d) to exit\n", console->remote ? "remote" : "foreground", console, console->fdin, console->fdout);
		console->dead = 1;
		if (console->remote) {
			/* Should cause the console thread to exit */
			bbs_pthread_interrupt(console->thread);
			/* Don't close any file descriptors here.
			 * sysop_handler does that by calling console_cleanup() when it cleans up.
			 * We don't do any cleanup here apart from nudging the thread to exit,
			 * if it happens to still be active at this point. */
		} else {
			RWLIST_REMOVE_CURRENT(entry);
			bbs_pthread_join(console->thread, NULL);
			free(console);
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&consoles);

	bbs_alertpipe_read(console_alertpipe);
	bbs_alertpipe_close(console_alertpipe);

	/* This is not pretty, but need to wait until the list is empty - console threads are detached so we have nothing to join,
	 * and we can't make them non-detached because console threads can exit on their own, without anyone to join them. */
	for (;;) {
		int remaining = 0;
		bbs_debug(3, "Waiting for all sysop consoles to exit\n");
		RWLIST_RDLOCK(&consoles);
		RWLIST_TRAVERSE(&consoles, console, entry) {
			if (console->fdin == -1 && console->fdout == -1) {
				/* This means the remote console has been shut down, but its thread has not yet exited. */
				bbs_warning("Stale %s console %p still registered?\n", console->remote ? "remote" : "foreground", console);
			} else {
				bbs_debug(3, "%s console %p (%d/%d) is still registered\n", console->remote ? "Remote" : "Foreground", console, console->fdin, console->fdout);
			}
			remaining++;
		}
		RWLIST_UNLOCK(&consoles);
		if (!remaining) {
			break;
		}
		usleep(100000);
	}

	return 0;
}

static int show_copyright_fg(void)
{
	show_copyright(STDOUT_FILENO, 1);
	return 0;
}

static int load_module(void)
{
	if (bbs_alertpipe_create(console_alertpipe)) {
		return -1;
	}
	if (option_nofork) {
		launch_sysop_console(CONSOLE_FOREGROUND, STDIN_FILENO);
	} else {
		bbs_debug(3, "BBS not started with foreground console, declining to load foreground sysop console\n");
	}

#pragma GCC diagnostic ignored "-Wsign-conversion"
	/* Start a thread to allow remote sysop console connections */
	if (bbs_make_unix_socket(&uds_socket, BBS_SYSOP_SOCKET, "0600", -1, -1) || bbs_pthread_create(&uds_thread, NULL, remote_sysop_listener, NULL)) {
		if (!option_nofork) {
			/* Nothing major to clean up, we didn't create a foreground console, and the remote handler failed */
			return -1; /* Only fatal if daemonized, since otherwise there would be no sysop consoles at all */
		}
	}
#pragma GCC diagnostic pop

	if (!bbs_is_fully_started() && option_nofork) {
		bbs_register_startup_callback(show_copyright_fg, STARTUP_PRIORITY_DEFAULT);
	}

	bbs_cli_register_multiple(cli_commands_sysop);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("Sysop Console", "mod_history.so");
