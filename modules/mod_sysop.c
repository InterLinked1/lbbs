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

extern int option_nofork;

static pthread_t sysop_thread = -1;

#define my_set_stdout_logging(fdout, setting) if (fdout == STDOUT_FILENO) { bbs_set_stdout_logging(setting); } else { bbs_set_fd_logging(fdout, setting); }

/* Since we now support remote consoles, bbs_printf is not logical to use in this module */
#ifdef bbs_printf
#undef bbs_printf
#endif
#define bbs_printf __Do_not_use_bbs_printf_use_bbs_dprintf

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
		s += 5;
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		res = bbs_module_load(s);
	} else if (STARTS_WITH(s, "unload ")) {
		s += 7;
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		if (!strncasecmp(s, file_without_ext, strlen(file_without_ext))) {
			bbs_request_module_unload(s, 0);
		} else {
			res = bbs_module_unload(s);
		}
	} else if (STARTS_WITH(s, "reload ")) {
		s += 7;
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		if (!strncasecmp(s, file_without_ext, strlen(file_without_ext))) {
			bbs_request_module_unload(s, 1);
		} else {
			res = bbs_module_reload(s, 0);
		}
	} else if (STARTS_WITH(s, "qreload ")) {
		s += 8;
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
		s += 8;
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_set_verbose(atoi(s));
	} else if (STARTS_WITH(s, "debug ")) {
		s += 6;
		ENSURE_STRLEN(s);
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_set_debug(atoi(s));
	} else if (!strcmp(s, "variables")) {
		bbs_vars_dump(fdout, NULL);
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
		bbs_node_shutdown_node(atoi(s));
	} else if (!strcmp(s, "kickall")) {
		my_set_stdout_logging(fdout, 1);
		bbs_node_shutdown_all(0);
	} else if (STARTS_WITH(s, "node ")) {
		s += 5;
		ENSURE_STRLEN(s);
		bbs_node_info(fdout, atoi(s));
	} else if (STARTS_WITH(s, "user ")) {
		s += 5;
		ENSURE_STRLEN(s);
		if (bbs_user_dump(fdout, s, 10)) {
			bbs_dprintf(fdout, "No such user '%s'\n", s);
		}
	} else if (STARTS_WITH(s, "spy ")) {
		s += 4;
		ENSURE_STRLEN(s);
		bbs_node_spy(fdin, fdout, atoi(s));
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
	} else if (!strcmp(s, "testemail")) {
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_mail(0, NULL, NULL, NULL, "Test Email", "This is a test email.\r\n\t--LBBS");
	} else if (!strcmp(s, "assert")) {
		/* Development testing only: this command is not listed */
		char *tmp = NULL;
		my_set_stdout_logging(fdout, 1); /* We want to be able to see the logging */
		bbs_assert_exists(tmp);
	} else {
		res = -1;
		bbs_dprintf(fdout, "ERROR: Invalid command: '%s'. Press '?' for help.\n", s);
	}
	return res;
}

struct sysop_fd {
	int fdin;
	int fdout;
};

static void rsysop_cleanup(void *varg)
{
	struct sysop_fd *fds = varg;
	if (fds->fdin != STDIN_FILENO) {
		bbs_remove_logging_fd(fds->fdout);
		close(fds->fdin);
	}
	free(fds);
}

static void *sysop_handler(void *varg)
{
	char buf[1];
	char cmdbuf[256];
	int res;
	struct pollfd pfd;
	const char *histentry = NULL;
	int sysopfdin, sysopfdout;
	struct sysop_fd *fds = varg;

	sysopfdin = fds->fdin;
	sysopfdout = fds->fdout;

	pthread_cleanup_push(rsysop_cleanup, fds); /* When remote console exits or is killed, close PTY slave */
	if (sysopfdout != STDOUT_FILENO) {
		bbs_add_logging_fd(sysopfdout);
	}

	bbs_dprintf(sysopfdout, TERM_TITLE_FMT, "Sysop Console");

	/* Disable input buffering so we can read a character as soon as it's typed */
	if (bbs_fd_unbuffer_input(sysopfdin, 0)) {
		bbs_error("Failed to unbuffer fd %d, sysop console will be unavailable\n", sysopfdin);
		/* If this fails, the foreground console is just not going to work properly.
		 * For example, supervisorctl doesn't seem to have a TTY/PTY available.
		 * Just use screen or tmux? */
		goto cleanup;
	}

	pfd.fd = sysopfdin;
	pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	for (;;) {
		pfd.revents = 0;
		res = poll(&pfd, 1, -1);
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_error("poll returned %d: %s\n", res, strerror(errno));
				break;
			}
			continue;
		}
		if (pfd.revents & POLLIN) {
			int bytes_read = read(sysopfdin, buf, sizeof(buf));
			if (bytes_read <= 0) {
				bbs_debug(5, "read returned %d\n", bytes_read);
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
					bbs_dprintf(sysopfdout, " == Development & Debugging == \n");
					bbs_dprintf(sysopfdout, "/threads            - View list of active registered threads\n");
					bbs_dprintf(sysopfdout, "/fds                - View list of open file descriptors\n");
					bbs_dprintf(sysopfdout, "/runtests           - Run all unit tests\n");
					bbs_dprintf(sysopfdout, "/testemail          - Send a test email to the sysop\n");
					bbs_dprintf(sysopfdout, " == Administrative ==\n");
					bbs_dprintf(sysopfdout, "/load <module>      - Load dynamic module\n");
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
								bbs_debug(5, "read returned %d\n", bytes_read);
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
					res = bbs_fd_read_escseq(sysopfdin);
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
						bbs_fd_buffer_input(sysopfdin, 1);
						res = sysop_command(sysopfdin, sysopfdout, cmdbuf);
						bbs_fd_unbuffer_input(sysopfdin, 0);
						my_set_stdout_logging(sysopfdout, 1); /* If running in foreground, re-enable STDOUT logging */
					} else {
						bbs_dprintf(sysopfdout, "\n"); /* Print newline for convenience */
					}
					break;
				case '/':
					bbs_dprintf(sysopfdout, "/");
					my_set_stdout_logging(sysopfdout, 0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
					bbs_fd_buffer_input(sysopfdin, 1);
					res = poll(&pfd, 1, 30000);
					if (res < 0) {
						if (errno != EINTR) {
							bbs_error("poll returned %d: %s\n", res, strerror(errno));
						}
					} else if (res == 0) {
						bbs_dprintf(sysopfdout, "\nCommand expired\n");
					} else {
						bytes_read = read(sysopfdin, cmdbuf, sizeof(cmdbuf) - 1);
						if (bytes_read <= 0) {
							bbs_debug(5, "read returned %d\n", bytes_read);
						} else {
							cmdbuf[bytes_read] = '\0'; /* Safe, since size - 1 above */
							bbs_strterm(cmdbuf, '\r');
							bbs_strterm(cmdbuf, '\n');
							/* Save in history */
							bbs_history_add(cmdbuf);
							res = sysop_command(sysopfdin, sysopfdout, cmdbuf);
						}
					}
					bbs_fd_unbuffer_input(sysopfdin, 0);
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
			bbs_error("poll returned %d, but no POLLIN?\n", res);
			if (pfd.revents & BBS_POLL_QUIT) {
				break;
			}
			break;
		}
	}

cleanup:
	pthread_cleanup_pop(1);
	return NULL;
}

static int launch_sysop_console(int remote, int fdin, int fdout)
{
	struct sysop_fd *fds;

	fds = calloc(1, sizeof(*fds));
	if (ALLOC_FAILURE(fds)) {
		return -1;
	}

	fds->fdin = fdin;
	fds->fdout = fdout;

	if (remote) {
		pthread_t rthread;
		/* Remote console. Make it detached so we don't have to keep track of it and join it later. */
		/* Note there is no SIGINT handler for remote consoles,
		 * so ^C will just exit the remote console without killing the BBS.
		 */
		if (bbs_pthread_create_detached_killable(&rthread, NULL, sysop_handler, fds)) {
			bbs_error("Failed to create remote sysop thread for %d/%d\n", fdin, fdout);
			free(fds);
			return -1;
		}
	} else {
		/* This is the foreground sysop console */
		if (bbs_pthread_create(&sysop_thread, NULL, sysop_handler, fds)) {
			bbs_error("Failed to create foreground sysop thread for %d/%d\n", fdin, fdout);
			free(fds);
			return -1;
		}
	}
	return 0;
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
		if (pfd.revents) {
			bbs_verb(4, "Accepting new remote sysop connection\n");
			len = sizeof(sunaddr);
			sfd = accept(uds_socket, (struct sockaddr *) &sunaddr, &len);
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
		/* Now, we need to create a pseudoterminal for the UNIX socket, the sysop thread needs a PTY. */
		aslave = bbs_spawn_pty_master(sfd);
		if (aslave == -1) {
			close(sfd);
			continue;
		}
		bbs_fd_unbuffer_input(aslave, 0); /* Disable canonical mode and echo on this PTY slave */
		bbs_dprintf(aslave, TERM_CLEAR); /* Clear the screen on connect */
		launch_sysop_console(1, aslave, aslave); /* Launch sysop console for this connection */
	}
	/* Normally, we never get here, as pthread_cancel snuffs out the thread ungracefully */
	bbs_warning("Remote sysop console listener thread exiting abnormally\n");
	return NULL;
}

#define BBS_SYSOP_SOCKET DIRCAT(DIRCAT("/var/run", BBS_NAME), "sysop.sock")

static int unload_module(void)
{
	/* This module may have created detached threads that will never exit of their own volition.
	 * Kill them now. */
	bbs_thread_cancel_killable();

	if (uds_socket != -1) {
		close(uds_socket);
		uds_socket = -1;
		bbs_pthread_cancel_kill(uds_thread);
		bbs_pthread_join(uds_thread, NULL);
		unlink(BBS_SYSOP_SOCKET);
	}
	if (sysop_thread != (long unsigned int) -1) {
		bbs_debug(3, "Waiting for sysop thread to exit\n");
		bbs_pthread_cancel_kill(sysop_thread);
		bbs_pthread_join(sysop_thread, NULL);
		if (option_nofork) {
			bbs_fd_buffer_input(STDIN_FILENO, 1); /* Be nice: re-enable canonical mode and echo to leave the TTY in a sane state. */
		}
		bbs_debug(2, "Sysop thread has exited\n");
	}
	bbs_history_shutdown();
	return 0;
}

static int load_module(void)
{
	bbs_history_init();

	if (option_nofork) {
		launch_sysop_console(0, STDIN_FILENO, STDOUT_FILENO);
	} else {
		bbs_debug(3, "BBS not started with foreground console, declining to load foreground sysop console\n");
	}

	/* Start a thread to allow remote sysop console connections */
	if (bbs_make_unix_socket(&uds_socket, BBS_SYSOP_SOCKET, "0600", -1, -1) || bbs_pthread_create(&uds_thread, NULL, remote_sysop_listener, NULL)) {
		if (!option_nofork) {
			/* Nothing to clean up, we didn't create a foreground console, and the remote handler failed */
			return -1; /* Only fatal if daemonized, since otherwise there would be no sysop consoles at all */
		}
	}

	return 0;
}

BBS_MODULE_INFO_STANDARD("Sysop Console");
