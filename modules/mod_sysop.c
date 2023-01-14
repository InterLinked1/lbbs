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
#include <signal.h> /* use pthread_kill */

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

extern int option_nofork;

static pthread_t sysop_thread = -1;

static int sysop_command(int fd, const char *s)
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
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		res = bbs_module_load(s);
	} else if (STARTS_WITH(s, "unload ")) {
		s += 7;
		ENSURE_STRLEN(s);
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		if (!strncasecmp(s, file_without_ext, strlen(file_without_ext))) {
			bbs_request_module_unload(s, 0);
		} else {
			res = bbs_module_unload(s);
		}
	} else if (STARTS_WITH(s, "reload ")) {
		s += 7;
		ENSURE_STRLEN(s);
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		if (!strncasecmp(s, file_without_ext, strlen(file_without_ext))) {
			bbs_request_module_unload(s, 1);
		} else {
			res = bbs_module_reload(s, 0);
		}
	} else if (STARTS_WITH(s, "qreload ")) {
		s += 8;
		ENSURE_STRLEN(s);
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
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
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		bbs_set_verbose(atoi(s));
	} else if (STARTS_WITH(s, "debug ")) {
		s += 6;
		ENSURE_STRLEN(s);
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		bbs_set_debug(atoi(s));
	} else if (!strcmp(s, "variables")) {
		bbs_vars_dump(fd, NULL);
	} else if (!strcmp(s, "menureload")) {
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		bbs_load_menus(1);
	} else if (!strcmp(s, "menus")) {
		bbs_dump_menus(fd);
	} else if (!strcmp(s, "menuhandlers")) {
		bbs_list_menu_handlers(fd);
	} else if (STARTS_WITH(s, "menu ")) {
		s += 5;
		ENSURE_STRLEN(s);
		bbs_dump_menu(fd, s);
	} else if (!strcmp(s, "doors")) {
		bbs_list_doors(fd);
	} else if (!strcmp(s, "modules")) {
		bbs_list_modules(fd);
	} else if (!strcmp(s, "modules")) {
		bbs_list_modules(fd);
	} else if (!strcmp(s, "nets")) {
		bbs_list_network_protocols(fd);
	} else if (!strcmp(s, "authproviders")) {
		bbs_list_auth_providers(fd);
	} else if (!strcmp(s, "threads")) {
		bbs_dump_threads(fd);
	} else if (!strcmp(s, "fds")) {
		bbs_fd_dump(fd);
	} else if (STARTS_WITH(s, "kick ")) {
		s += 5;
		ENSURE_STRLEN(s);
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		bbs_node_shutdown_node(atoi(s));
	} else if (!strcmp(s, "kickall")) {
		bbs_node_shutdown_all(0);
	} else if (STARTS_WITH(s, "node ")) {
		s += 5;
		ENSURE_STRLEN(s);
		bbs_node_info(fd, atoi(s));
	} else if (STARTS_WITH(s, "spy ")) {
		s += 4;
		ENSURE_STRLEN(s);
		/* We know that fd == STDOUT_FILENO (it's also STDIN_FILENO, so we could also just specify fd for both args) */
		bbs_node_spy(STDIN_FILENO, fd, atoi(s));
	} else if (!strcmp(s, "runtests")) {
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		bbs_run_tests(fd);
	} else if (!strcmp(s, "testemail")) {
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		bbs_mail(0, NULL, NULL, NULL, "Test Email", "This is a test email.\r\n\t--LBBS");
	} else if (!strcmp(s, "assert")) {
		/* Development testing only: this command is not listed */
		char *tmp = NULL;
		bbs_set_stdout_logging(1); /* We want to be able to see the logging */
		bbs_assert_exists(tmp);
	} else {
		res = -1;
		bbs_dprintf(fd, "ERROR: Invalid command: '%s'. Press '?' for help.\n", s);
	}
	return res;
}

static void *sysop_handler(void *varg)
{
	char buf[1];
	char cmdbuf[256];
	int res;
	struct pollfd pfd;
	const char *histentry = NULL;

	UNUSED(varg);

	bbs_printf(TERM_TITLE_FMT, "Sysop Console");

	for (;;) {
		pfd.fd = STDIN_FILENO;
		pfd.events = POLLIN;
		pfd.revents = 0;

		res = poll(&pfd, 1, -1);
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_error("poll returned %d: %s\n", res, strerror(errno));
			}
			continue;
		}
		if (pfd.revents & POLLIN) {
			int bytes_read = read(STDIN_FILENO, buf, sizeof(buf));
			if (bytes_read <= 0) {
				bbs_debug(5, "read returned %d\n", bytes_read);
				break;
			}
			switch (tolower(buf[0])) {
				case '?':
				case 'h':
					bbs_printf(" == Quick Commands ==\n");
					bbs_printf("? - Show help\n");
					bbs_printf("c - Clear screen\n");
					bbs_printf("h - Show help\n");
					bbs_printf("n - List active nodes\n");
					bbs_printf("q - Shut down the BBS (with confirmation)\n");
					bbs_printf("s - Show BBS system status\n");
					bbs_printf("UP -> Previous command\n");
					bbs_printf("DN -> More recent command\n");
					bbs_printf(" == Sysoping ==\n");
					bbs_printf("/kickall          - Kick all connected nodes\n");
					bbs_printf("/kick <nodenum>   - Kick specified node\n");
					bbs_printf("/node <nodenum>   - View information about a node\n");
					bbs_printf("/spy <nodenum>    - Spy on a node (^C to stop)\n");
					bbs_printf("/menureload       - Reload menus\n");
					bbs_printf(" == Operational ==\n");
					bbs_printf("/debug <level>    - Set debug level\n");
					bbs_printf("/verbose <level>  - Set verbose level\n");
					bbs_printf("/variables        - List all global variables\n");
					bbs_printf("/menu <name>      - Dump a menu\n");
					bbs_printf("/menus            - View list of menus\n");
					bbs_printf("/menuhandlers     - View list of menu handlers\n");
					bbs_printf("/doors            - View list of doors\n");
					bbs_printf("/modules          - View list of loaded modules\n");
					bbs_printf("/nets             - View list of network protocols\n");
					bbs_printf("/authproviders    - View list of registered auth providers\n");
					bbs_printf(" == Development & Debugging == \n");
					bbs_printf("/threads          - View list of active registered threads\n");
					bbs_printf("/fds              - View list of open file descriptors\n");
					bbs_printf("/runtests         - Run all unit tests\n");
					bbs_printf("/testemail        - Send a test email to the sysop\n");
					bbs_printf(" == Administrative ==\n");
					bbs_printf("/load <module>    - Load dynamic module\n");
					bbs_printf("/unload <module>  - Unload dynamic module\n");
					bbs_printf("/reload <module>  - Unload and load dynamic module\n");
					bbs_printf("/qreload <module> - Unload and load dynamic module, queuing if necessary\n");
					bbs_printf("/halt             - Immediately (uncleanly) halt the BBS (DANGER!)\n");
					bbs_printf("/shutdown (^C)    - Shut down the BBS (no confirmation)\n");
					bbs_printf("/restart          - Restart the BBS\n");
					break;
				case 'c':
					bbs_printf(TERM_CLEAR); /* TERM_CLEAR doesn't end in a newline, so normally, flush output, but bbs_printf does this for us. */
					break;
				case 'n':
					bbs_nodes_print(STDOUT_FILENO);
					break;
				case 's':
					bbs_view_settings(STDOUT_FILENO);
					break;
				case 'q':
					{
						int do_quit = 0;
						bbs_set_stdout_logging(0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
						bbs_printf("\n%sReally shut down the BBS? [YN] %s", COLOR(COLOR_RED), COLOR_RESET);
						res = poll(&pfd, 1, 10000);
						if (res < 0) {
							if (errno != EINTR) {
								bbs_error("poll returned %d: %s\n", res, strerror(errno));
							}
						} else if (res == 0) {
							bbs_printf("\nShutdown attempt expired\n");
						} else {
							bytes_read = read(STDIN_FILENO, buf, 1);
							if (bytes_read <= 0) {
								bbs_debug(5, "read returned %d\n", bytes_read);
							} else if (buf[0] == 'y' || buf[0] == 'Y') {
								do_quit = 1;
							}
						}
						bbs_printf("\n");
						bbs_set_stdout_logging(1); /* If running in foreground, re-enable STDOUT logging */
						if (do_quit) {
							bbs_request_shutdown(0);
						}
					}
					break;
				case KEY_ESC:
					res = bbs_fd_read_escseq(STDIN_FILENO);
					switch (res) {
						case KEY_UP:
							histentry = bbs_history_older();
							if (histentry) {
								bbs_printf("\r/%s", histentry);
							}
							break;
						case KEY_DOWN:
							histentry = bbs_history_newer();
							if (histentry) {
								bbs_printf("\r/%s", histentry);
							}
							break;
						case KEY_ESC:
							bbs_history_reset();
							break;
						default:
							/* Ignore */
							break;
					}
					break;
				case '\n':
					if (histentry) {
						bbs_printf("\n"); /* Print new line since we had history on the line */
						safe_strncpy(cmdbuf, histentry, sizeof(cmdbuf));
						bbs_history_add(cmdbuf);
						bbs_set_stdout_logging(0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
						bbs_fd_buffer_input(STDIN_FILENO, 1);
						res = sysop_command(STDOUT_FILENO, cmdbuf);
						bbs_fd_unbuffer_input(STDIN_FILENO, 0);
						bbs_set_stdout_logging(1); /* If running in foreground, re-enable STDOUT logging */
					} else {
						bbs_printf("\n"); /* Print newline for convenience */
					}
					break;
				case '/':
					bbs_printf("/");
					bbs_set_stdout_logging(0); /* Disable logging so other stuff isn't trying to write to STDOUT at the same time. */
					bbs_fd_buffer_input(STDIN_FILENO, 1);
					res = poll(&pfd, 1, 30000);
					if (res < 0) {
						if (errno != EINTR) {
							bbs_error("poll returned %d: %s\n", res, strerror(errno));
						}
					} else if (res == 0) {
						bbs_printf("\nCommand expired\n");
					} else {
						bytes_read = read(STDIN_FILENO, cmdbuf, sizeof(cmdbuf) - 1);
						if (bytes_read <= 0) {
							bbs_debug(5, "read returned %d\n", bytes_read);
						} else {
							cmdbuf[bytes_read] = '\0'; /* Safe, since size - 1 above */
							bbs_strterm(cmdbuf, '\r');
							bbs_strterm(cmdbuf, '\n');
							/* Save in history */
							bbs_history_add(cmdbuf);
							res = sysop_command(STDOUT_FILENO, cmdbuf);
						}
					}
					bbs_fd_unbuffer_input(STDIN_FILENO, 0);
					bbs_set_stdout_logging(1); /* If running in foreground, re-enable STDOUT logging */
					break;
				default:
					if (isprint(buf[0])) {
						bbs_debug(5, "Received character %d (%c) on sysop console\n", buf[0], buf[0]);
					} else {
						bbs_debug(5, "Received character %d on sysop console\n", buf[0]);
					}
					bbs_printf("Invalid command '%c'. Press '?' for help.\n", isprint(buf[0]) ? buf[0] : ' ');
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

	return NULL;
}

static int load_module(void)
{
	if (!option_nofork) {
		bbs_debug(3, "BBS not started with foreground console, declining to load sysop console\n");
		return -1;
	}
	/* Disable input buffering so we can read a character as soon as it's typed */
	if (bbs_fd_unbuffer_input(STDIN_FILENO, 0)) {
		bbs_error("Failed to unbuffer STDIN, sysop console will be unavailable\n");
		/* If this fails, the console is just not going to work properly.
		 * For example, supervisorctl doesn't seem to have a TTY/PTY available.
		 * Just use screen or tmux? */
		return -1;
	}
	if (bbs_pthread_create(&sysop_thread, NULL, sysop_handler, NULL)) {
		bbs_fd_buffer_input(STDIN_FILENO, 1); /* Restore the terminal. */
		bbs_error("Failed to create sysop thread\n");
		return -1;
	}
	bbs_history_init();
	return 0;
}

static int unload_module(void)
{
	bbs_debug(3, "Waiting for sysop thread to exit\n");
	bbs_assert(sysop_thread != (pthread_t) -1);
	pthread_cancel(sysop_thread);
	pthread_kill(sysop_thread, SIGURG);
	bbs_pthread_join(sysop_thread, NULL);
	bbs_fd_buffer_input(STDIN_FILENO, 1); /* Be nice: re-enable canonical mode and echo to leave the TTY in a sane state. */
	bbs_debug(2, "Sysop thread has exited\n");
	bbs_history_shutdown();
	return 0;
}

BBS_MODULE_INFO_STANDARD("Sysop Console");
