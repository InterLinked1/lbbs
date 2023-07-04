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
#include <pthread.h>
#include <sys/un.h>	/* use struct sockaddr_un */

#include "include/node.h"
#include "include/pty.h"
#include "include/module.h"
#include "include/term.h"
#include "include/menu.h"
#include "include/variables.h"
#include "include/handler.h"
#include "include/door.h"
#include "include/net.h"
#include "include/mail.h"
#include "include/test.h"
#include "include/history.h"
#include "include/utils.h" /* use bbs_dump_threads */
#include "include/auth.h" /* use bbs_list_auth_providers */
#include "include/user.h" /* use bbs_user_dump */
#include "include/notify.h"
#include "include/startup.h"

extern int option_nofork;

#define my_set_stdout_logging(fdout, setting) if (fdout == STDOUT_FILENO) { bbs_set_stdout_logging(setting); } else { bbs_set_fd_logging(fdout, setting); }

/* Since we now support remote consoles, bbs_printf is not logical to use in this module */
#ifdef bbs_printf
#undef bbs_printf
#endif
#define bbs_printf __Do_not_use_bbs_printf_use_bbs_dprintf
/* Use the macro to suppress unused macro warning with -Wunused-macros */
#ifdef bbs_printf
#endif

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

static int sysop_command(int fdin, int fdout, const char *s)
{
	int res = 0;
	static char file_without_ext[] = __FILE__;

	/* This only has an effect the first time */
	bbs_strterm(file_without_ext, '.'); /* There's no macro like __FILE__ w/o ext, so this is what we gotta do. */

	if (!strcmp(s, "halt")) {
		bbs_request_shutdown(-1);
	} else if (!strcmp(s, "shutdown")) {
		bbs_request_shutdown(0);
	} else if (!strcmp(s, "restart")) {
		bbs_request_shutdown(1);
	} else if (STARTS_WITH(s, "load ")) {
		s += STRLEN("load ");
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		res = bbs_module_load(s);
	} else if (STARTS_WITH(s, "waitload ")) {
		struct pollfd pfd;
		s += STRLEN("waitload ");
		ENSURE_STRLEN(s);
		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = fdin;
		pfd.events = POLLIN;
		/* Since the terminal is in canonical mode, we need a newline for poll() to wake up.
		 * That's fine, just say so. */
		/* XXX Should check that s is at least a valid module, otherwise it will never load
		 * Also, if it's already loaded, we shouldn't wait at all. */
		if (!bbs_module_exists(s)) {
			bbs_dprintf(fdout, "Module '%s' does not exist\n", s);
		} else if (bbs_module_running(s)) {
			bbs_dprintf(fdout, "Module '%s' is already running\n", s);
		} else {
			/* Technically, a small race condition is possible here.
			 * The module might not be running when we check above
			 * but be running before we call bbs_module_load.
			 * In that case, we'd just sit here. Very unlikely though,
			 * and not really possible unless the user is manipulating modules.
			 */
			bbs_dprintf(fdout, "Waiting until module '%s' loads. Press ENTER to cancel retry: ", s); /* No newline */
			do {
				res = bbs_module_load(s);
				/* Allow the call to be interrupted. */
			} while (res && poll(&pfd, 1, 500) == 0);
			if (res) {
				bbs_dprintf(fdout, TERM_RESET_LINE "Load retry cancelled\n");
			} else {
				bbs_dprintf(fdout, TERM_RESET_LINE "Module loaded\n");
			}
		}
	} else if (STARTS_WITH(s, "unload ")) {
		s += STRLEN("unload ");
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		if (!strncasecmp(s, file_without_ext, strlen(file_without_ext))) {
			bbs_request_module_unload(s, 0);
		} else {
			res = bbs_module_unload(s);
		}
	} else if (STARTS_WITH(s, "reload ")) {
		s += STRLEN("reload ");
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		if (!strncasecmp(s, file_without_ext, strlen(file_without_ext))) {
			bbs_request_module_unload(s, 1);
		} else {
			res = bbs_module_reload(s, 0);
		}
	} else if (STARTS_WITH(s, "qreload ")) {
		s += STRLEN("qreload ");
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		/* Nothing increments the ref count of this module (mod_sysop) currently,
		 * so reloads will always succeed anyways, not get queued */
		if (!strncasecmp(s, file_without_ext, strlen(file_without_ext))) {
			bbs_request_module_unload(s, 1);
		} else {
			res = bbs_module_reload(s, 1);
		}
	} else if (STARTS_WITH(s, "verbose ")) {
		s += STRLEN("verbose ");
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_set_verbose(atoi(s));
	} else if (STARTS_WITH(s, "debug ")) {
		s += STRLEN("debug ");
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_set_debug(atoi(s));
	} else if (!strcmp(s, "variables")) {
		bbs_node_vars_dump(fdout, NULL);
	} else if (!strcmp(s, "menureload")) {
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_load_menus(1);
	} else if (!strcmp(s, "menus")) {
		bbs_dump_menus(fdout);
	} else if (!strcmp(s, "menuhandlers")) {
		bbs_list_menu_handlers(fdout);
	} else if (STARTS_WITH(s, "menu ")) {
		s += 5;
		ENSURE_STRLEN(s);
		bbs_dump_menu(fdout, s);
	} else if (!strcmp(s, "doors")) {
		bbs_list_doors(fdout);
	} else if (!strcmp(s, "modules")) {
		bbs_list_modules(fdout);
	} else if (!strcmp(s, "nets")) {
		bbs_list_network_protocols(fdout);
	} else if (!strcmp(s, "authproviders")) {
		bbs_list_auth_providers(fdout);
	} else if (!strcmp(s, "threads")) {
		bbs_dump_threads(fdout);
	} else if (!strcmp(s, "fds")) {
		bbs_fd_dump(fdout);
	} else if (STARTS_WITH(s, "kick ")) {
		s += 5;
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_node_shutdown_node((unsigned int) atoi(s));
	} else if (!strcmp(s, "kickall")) {
		my_set_stdout_logging(fdout, 1);
		bbs_node_shutdown_all(0);
	} else if (STARTS_WITH(s, "node ")) {
		s += 5;
		ENSURE_STRLEN(s);
		bbs_node_info(fdout, (unsigned int) atoi(s));
	} else if (STARTS_WITH(s, "user ")) {
		s += 5;
		ENSURE_STRLEN(s);
		if (bbs_user_dump(fdout, s, 10)) {
			bbs_dprintf(fdout, "No such user '%s'\n", s);
		}
	} else if (STARTS_WITH(s, "spy ")) {
		s += 4;
		ENSURE_STRLEN(s);
		bbs_node_spy(fdin, fdout, (unsigned int) atoi(s));
	} else if (STARTS_WITH(s, "alert ")) {
		char *dup = strdup(S_IF(s + STRLEN("alert ")));
		if (ALLOC_SUCCESS(dup)) {
			unsigned int userid;
			char *username, *msg = dup;
			username = strsep(&msg, " ");
			userid = bbs_userid_from_username(username);
			if (userid) {
				if (bbs_alert_user(userid, DELIVERY_EPHEMERAL, "%s", msg)) {
					bbs_dprintf(fdout, "Failed to deliver message\n");
				} else {
					bbs_dprintf(fdout, "Message delivered\n");
				}
			} else {
				bbs_dprintf(fdout, "No such user '%s'\n", username);
			}
			free(dup);
		}
	} else if (!strcmp(s, "runtests")) {
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_run_tests(fdout);
	} else if (STARTS_WITH(s, "runtest ")) {
		s += STRLEN("runtest ");
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_run_test(fdout, s);
	} else if (!strcmp(s, "testemail")) {
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_mail(0, NULL, NULL, NULL, "Test Email", "This is a test email.\r\n\t--LBBS");
	} else if (!strcmp(s, "assert")) {
		/* Development testing only: this command is not listed */
		char *tmp = NULL;
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_assert_exists(tmp);
	} else if (!strcmp(s, "copyright")) {
		show_copyright(fdout, 0);
	} else if (!strcmp(s, "license")) {
		show_license(fdout);
	} else if (!strcmp(s, "warranty")) {
		show_warranty(fdout);
	} else {
		res = -1;
		bbs_dprintf(fdout, "ERROR: Invalid command: '%s'. Press '?' for help.\n", s);
	}
	return res;
}

struct sysop_console {
	int sfd;
	int fdin;
	int fdout;
	pthread_t thread;
	unsigned int remote:1;
	unsigned int dead:1;
	RWLIST_ENTRY(sysop_console) entry;
};

static RWLIST_HEAD_STATIC(consoles, sysop_console);

static void console_cleanup(struct sysop_console *console)
{
	RWLIST_WRLOCK(&consoles);
	RWLIST_REMOVE(&consoles, console, entry);
	if (console->remote) {
		/* If unloading, these have already been closed */
		if (!console->dead) {
			bbs_remove_logging_fd(console->fdout);
			bbs_socket_close(&console->fdin);
			bbs_socket_close(&console->fdout);
			bbs_socket_close(&console->sfd);
		}
	}
	free(console);
	RWLIST_UNLOCK(&consoles);
}

static void print_time(int fdout)
{
	char timebuf[40];
	time_t now;
	struct tm nowdate;

	now = (int) time(NULL);
	localtime_r(&now, &nowdate);
	strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M:%S %P %Z", &nowdate);
	bbs_dprintf(fdout, "%s\n", timebuf);
}

static void *sysop_handler(void *varg)
{
	char buf[1];
	char cmdbuf[256];
	int res;
	struct pollfd pfd;
	int sysopfdin, sysopfdout;
	const char *histentry;
	struct sysop_console *console = varg;

	sysopfdin = console->fdin;
	sysopfdout = console->fdout;

	if (console->remote) {
		bbs_add_logging_fd(sysopfdout);
	}

	bbs_dprintf(sysopfdout, TERM_TITLE_FMT, "Sysop Console");

	/* Disable input buffering so we can read a character as soon as it's typed */
	if (bbs_unbuffer_input(sysopfdin, 0)) {
		bbs_error("Failed to unbuffer fd %d, sysop console will be unavailable\n", sysopfdin);
		/* If this fails, the foreground console is just not going to work properly.
		 * For example, supervisorctl doesn't seem to have a TTY/PTY available.
		 * Just use screen or tmux? */
		goto cleanup;
	}

	pfd.fd = sysopfdin;
	pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	show_copyright(sysopfdout, 1);

	histentry = NULL; /* initiailization must be after pthread_cleanup_push to avoid "variable might be clobbered" warning */
	for (;;) {
		pfd.revents = 0;
		res = poll(&pfd, 1, -1);
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_debug(3, "poll returned %d: %s\n", res, strerror(errno));
				break;
			}
			continue;
		}
		if (pfd.revents & POLLIN) {
			ssize_t bytes_read = read(sysopfdin, buf, sizeof(buf));
			if (bytes_read <= 0) {
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
					bbs_dprintf(sysopfdout, "n - List active nodes\n");
					bbs_dprintf(sysopfdout, "q - Shut down the BBS (with confirmation)\n");
					bbs_dprintf(sysopfdout, "s - Show BBS system status\n");
					bbs_dprintf(sysopfdout, "t - Show BBS system time\n");
					bbs_dprintf(sysopfdout, "u - Show list of users\n");
					bbs_dprintf(sysopfdout, "UP -> Previous command\n");
					bbs_dprintf(sysopfdout, "DN -> More recent command\n");
					bbs_dprintf(sysopfdout, " == Sysoping ==\n");
					bbs_dprintf(sysopfdout, "/kickall            - Kick all connected nodes\n");
					bbs_dprintf(sysopfdout, "/kick <nodenum>     - Kick specified node\n");
					bbs_dprintf(sysopfdout, "/node <nodenum>     - View information about a node\n");
					bbs_dprintf(sysopfdout, "/user <username>    - View information about a user\n");
					bbs_dprintf(sysopfdout, "/spy <nodenum>      - Spy on a node (^C to stop)\n");
					bbs_dprintf(sysopfdout, "/alert <user> <msg> - Send a message to a user\n");
					bbs_dprintf(sysopfdout, "/menureload         - Reload menus\n");
					bbs_dprintf(sysopfdout, " == Operational ==\n");
					bbs_dprintf(sysopfdout, "/debug <level>      - Set debug level\n");
					bbs_dprintf(sysopfdout, "/verbose <level>    - Set verbose level\n");
					bbs_dprintf(sysopfdout, "/variables          - List all global variables\n");
					bbs_dprintf(sysopfdout, "/menu <name>        - Dump a menu\n");
					bbs_dprintf(sysopfdout, "/menus              - View list of menus\n");
					bbs_dprintf(sysopfdout, "/menuhandlers       - View list of menu handlers\n");
					bbs_dprintf(sysopfdout, "/doors              - View list of doors\n");
					bbs_dprintf(sysopfdout, "/modules            - View list of loaded modules\n");
					bbs_dprintf(sysopfdout, "/nets               - View list of network protocols\n");
					bbs_dprintf(sysopfdout, "/authproviders      - View list of registered auth providers\n");
					bbs_dprintf(sysopfdout, " == Licensing == \n");
					bbs_dprintf(sysopfdout, "/copyright          - Show copyright notice\n");
					bbs_dprintf(sysopfdout, "/license            - Show license notice\n");
					bbs_dprintf(sysopfdout, "/warranty           - Show warranty notice\n");
					bbs_dprintf(sysopfdout, " == Development & Debugging == \n");
					bbs_dprintf(sysopfdout, "/threads            - View list of active registered threads\n");
					bbs_dprintf(sysopfdout, "/fds                - View list of open file descriptors\n");
					bbs_dprintf(sysopfdout, "/runtests           - Run all unit tests\n");
					bbs_dprintf(sysopfdout, "/runtest <test>     - Run a specific unit test\n");
					bbs_dprintf(sysopfdout, "/testemail          - Send a test email to the sysop\n");
					bbs_dprintf(sysopfdout, " == Administrative ==\n");
					bbs_dprintf(sysopfdout, "/load <module>      - Load dynamic module\n");
					bbs_dprintf(sysopfdout, "/waitload <module>  - Keep retrying load of dynamic module until it succeeds\n");
					bbs_dprintf(sysopfdout, "/unload <module>    - Unload dynamic module\n");
					bbs_dprintf(sysopfdout, "/reload <module>    - Unload and load dynamic module\n");
					bbs_dprintf(sysopfdout, "/qreload <module>   - Unload and load dynamic module, queuing if necessary\n");
					bbs_dprintf(sysopfdout, "/halt               - Immediately (uncleanly) halt the BBS (DANGER!)\n");
					bbs_dprintf(sysopfdout, "/shutdown (^C)      - Shut down the BBS (no confirmation)\n");
					bbs_dprintf(sysopfdout, "/restart            - Restart the BBS\n");
					break;
				case 'c':
					bbs_dprintf(sysopfdout, TERM_CLEAR); /* TERM_CLEAR doesn't end in a newline, so normally, flush output, but bbs_printf does this for us. */
					break;
				case 'n':
					bbs_nodes_print(sysopfdout);
					break;
				case 's':
					bbs_view_settings(sysopfdout);
					break;
				case 't':
					print_time(sysopfdout);
					break;
				case 'u':
					bbs_users_dump(sysopfdout, 10);
					break;
				case 'q':
					{
						int do_quit = 0;
						my_set_stdout_logging(sysopfdout, 0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
						bbs_dprintf(sysopfdout, "\n%sReally shut down the BBS? [YN] %s", COLOR(COLOR_RED), COLOR_RESET);
						res = poll(&pfd, 1, 10000);
						if (res < 0) {
							if (errno != EINTR) {
								bbs_error("poll returned %d: %s\n", res, strerror(errno));
							}
						} else if (res == 0) {
							bbs_dprintf(sysopfdout, "\nShutdown attempt expired\n");
						} else {
							bytes_read = read(sysopfdin, buf, 1);
							if (bytes_read <= 0) {
								bbs_debug(5, "read returned %ld\n", bytes_read);
							} else if (buf[0] == 'y' || buf[0] == 'Y') {
								do_quit = 1;
							}
						}
						bbs_dprintf(sysopfdout, "\n");
						my_set_stdout_logging(sysopfdout, 1); /* If running in foreground, re-enable STDOUT logging */
						if (do_quit) {
							bbs_request_shutdown(0);
						}
					}
					break;
				case KEY_ESC:
					res = bbs_read_escseq(sysopfdin);
					switch (res) {
						case KEY_UP:
							histentry = bbs_history_older();
							if (histentry) {
								bbs_dprintf(sysopfdout, "\r/%s", histentry);
							}
							break;
						case KEY_DOWN:
							histentry = bbs_history_newer();
							if (histentry) {
								bbs_dprintf(sysopfdout, "\r/%s", histentry);
							}
							break;
						case KEY_ESC:
							bbs_history_reset();
							histentry = NULL;
							break;
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
						bbs_buffer_input(sysopfdin, 1);
						res = sysop_command(sysopfdin, sysopfdout, cmdbuf);
						bbs_unbuffer_input(sysopfdin, 0);
						my_set_stdout_logging(sysopfdout, 1); /* If running in foreground, re-enable STDOUT logging */
					} else {
						bbs_dprintf(sysopfdout, "\n"); /* Print newline for convenience */
					}
					break;
				case '/':
					bbs_dprintf(sysopfdout, "/");
					my_set_stdout_logging(sysopfdout, 0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
					bbs_buffer_input(sysopfdin, 1);
					res = poll(&pfd, 1, 300000);
					if (res < 0) {
						if (errno != EINTR) {
							bbs_error("poll returned %d: %s\n", res, strerror(errno));
						}
					} else if (res == 0) {
						bbs_dprintf(sysopfdout, "\nCommand expired\n");
					} else {
						bytes_read = read(sysopfdin, cmdbuf, sizeof(cmdbuf) - 1);
						if (bytes_read <= 0) {
							bbs_debug(5, "read returned %ld\n", bytes_read);
						} else {
							cmdbuf[bytes_read] = '\0'; /* Safe, since size - 1 above */
							bbs_term_line(cmdbuf);
							/* Save in history */
							bbs_history_add(cmdbuf);
							res = sysop_command(sysopfdin, sysopfdout, cmdbuf);
						}
					}
					bbs_unbuffer_input(sysopfdin, 0);
					my_set_stdout_logging(sysopfdout, 1); /* If running in foreground, re-enable STDOUT logging */
					break;
				default:
					if (isprint(buf[0])) {
						bbs_debug(5, "Received character %d (%c) on sysop console\n", buf[0], buf[0]);
					} else {
						bbs_debug(5, "Received character %d on sysop console\n", buf[0]);
					}
					bbs_dprintf(sysopfdout, "Invalid command '%c'. Press '?' for help.\n", isprint(buf[0]) ? buf[0] : ' ');
					break;
			}
		} else {
			if (!(pfd.revents & BBS_POLL_QUIT)) {
				bbs_error("poll returned %d, but no POLLIN?\n", res);
			}
			break;
		}
	}

cleanup:
	bbs_debug(2, "Sysop console %d/%d thread exiting\n", sysopfdin, sysopfdout);
	console_cleanup(console);
	return NULL;
}

static int launch_sysop_console(int remote, int sfd, int fdin, int fdout)
{
	int res = 0;
	struct sysop_console *console;

	console = calloc(1, sizeof(*console));
	if (ALLOC_FAILURE(console)) {
		return -1;
	}

	console->sfd = sfd; /* Socket file descriptor */
	console->fdin = fdin; /* PTY */
	console->fdout = fdout;
	SET_BITFIELD(console->remote, remote);

	RWLIST_WRLOCK(&consoles);
	RWLIST_INSERT_HEAD(&consoles, console, entry);
	/* Note there is no SIGINT handler for remote consoles,
	 * so ^C will just exit the remote console without killing the BBS. */
	if (bbs_pthread_create_detached(&console->thread, NULL, sysop_handler, console)) {
		bbs_error("Failed to create %s sysop thread for %d/%d\n", remote ? "remote" : "foreground", fdin, fdout);
		RWLIST_REMOVE(&consoles, console, entry);
		free(console);
		res = -1;
	}
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
		int aslave;
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
		/* Now, we need to create a pseudoterminal for the UNIX socket, the sysop thread needs a PTY. */
		aslave = bbs_spawn_pty_master(sfd);
		if (aslave == -1) {
			close(sfd);
			continue;
		}
		bbs_unbuffer_input(aslave, 0); /* Disable canonical mode and echo on this PTY slave */
		bbs_dprintf(aslave, TERM_CLEAR); /* Clear the screen on connect */
		launch_sysop_console(1, sfd, aslave, aslave); /* Launch sysop console for this connection */
	}
	return NULL;
}

#define BBS_SYSOP_SOCKET DIRCAT(DIRCAT("/var/run", BBS_NAME), "sysop.sock")

static int unload_module(void)
{
	struct sysop_console *console;

	unloading = 1;

	if (uds_socket != -1) {
		bbs_socket_thread_shutdown(&uds_socket, uds_thread);
		unlink(BBS_SYSOP_SOCKET);
	}

	/* Close all the consoles. */
	RWLIST_RDLOCK(&consoles);
	RWLIST_TRAVERSE_SAFE_BEGIN(&consoles, console, entry) {
		bbs_debug(3, "Instructing %s sysop console %d/%d to exit\n", console->remote ? "remote" : "foreground", console->fdin, console->fdout);
		console->dead = 1;
		if (console->remote) {
			bbs_remove_logging_fd(console->fdout); /* Must do before bbs_socket_close since that sets fd to -1 */
			/* Should cause the console thread to exit */
			bbs_socket_close(&console->fdout);
			bbs_socket_close(&console->fdin);
			bbs_socket_close(&console->sfd);
		} else {
			bbs_buffer_input(console->fdin, 1); /* Be nice: re-enable canonical mode and echo to leave the TTY in a sane state. */
			/* A bit difficult to avoid pthread_cancel here since shutdowns can be initiated in this module.
			 * Use caution if trying to improve this. */
			bbs_pthread_cancel_kill(console->thread);
			RWLIST_REMOVE_CURRENT(entry);
			free(console);
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&consoles);

	/* This is not pretty, but need to wait until the list is empty - console threads are detached so we have nothing to join,
	 * and we can't make them non-detached because console threads can exit on their own, without anyone to join them. */
	for (;;) {
		int empty;
		bbs_debug(3, "Waiting for all sysop consoles to exit\n");
		RWLIST_RDLOCK(&consoles);
		empty = RWLIST_EMPTY(&consoles);
		RWLIST_UNLOCK(&consoles);
		if (empty) {
			break;
		}
		usleep(10000);
	}

	bbs_history_shutdown();
	return 0;
}

static int show_copyright_fg(void)
{
	show_copyright(STDOUT_FILENO, 1);
	return 0;
}

static int load_module(void)
{
	bbs_history_init();

	if (option_nofork) {
		launch_sysop_console(0, STDIN_FILENO, STDIN_FILENO, STDOUT_FILENO);
	} else {
		bbs_debug(3, "BBS not started with foreground console, declining to load foreground sysop console\n");
	}

#pragma GCC diagnostic ignored "-Wsign-conversion"
	/* Start a thread to allow remote sysop console connections */
	if (bbs_make_unix_socket(&uds_socket, BBS_SYSOP_SOCKET, "0600", -1, -1) || bbs_pthread_create(&uds_thread, NULL, remote_sysop_listener, NULL)) {
		if (!option_nofork) {
			/* Nothing to clean up, we didn't create a foreground console, and the remote handler failed */
			return -1; /* Only fatal if daemonized, since otherwise there would be no sysop consoles at all */
		}
	}
#pragma GCC diagnostic pop

	if (!bbs_is_fully_started() && option_nofork) {
		bbs_register_startup_callback(show_copyright_fg);
	}

	return 0;
}

BBS_MODULE_INFO_STANDARD("Sysop Console");
