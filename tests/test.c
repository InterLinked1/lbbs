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
 * \brief Black Box Testing Framework
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "test.h"
#include "email.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <dlfcn.h>
#include <dirent.h>
#include <time.h>
#include <getopt.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h> /* use getpwnam */
#include <limits.h> /* use PATH_MAX */

#include "include/readline.h"

static int option_debug = 0;
static int option_debug_bbs = 0;
static char option_debug_bbs_str[12] = "-";
static int option_errorcheck = 0;
static int option_helgrind = 0;
static int option_strace = 0;
static int option_gen_supp = 0;
static int option_exit_failure = 0;
static const char *testfilter = NULL;

int startup_run_unit_tests;

/* Log file for BBS STDOUT output (empty after execution???)
 * Note: Normal BBS file logging is still done to the normal BBS log files. */
#define TEST_LOGFILE "/tmp/test_lbbs.log"

/* Log file for valgrind output */
#define VALGRIND_LOGFILE TEST_ROOT_DIR "/valgrind.log"

#define STRACE_LOGFILE TEST_ROOT_DIR "/strace.log"

/* There values are fairly conservative (longer than they needed to be in most cases).
 * However, occasionally if something takes longer, we don't want the test to fail
 * just because we jumped the gun too soon. */

/* How long to wait for the BBS to start fully */
#define STARTUP_TIMEOUT 25

/* Maximum amount of time for any single test duration */
#define TEST_TIMEOUT 180

/* How long to wait for BBS to exit after a test. */
#define SHUTDOWN_TIMEOUT 15

static const char *loglevel2str(enum bbs_log_level level)
{
	switch (level) {
		case LOG_ERROR:
			return COLOR(TERM_COLOR_RED) "  ERROR" COLOR_RESET;
		case LOG_WARNING:
			return COLOR(TERM_COLOR_RED) "WARNING" COLOR_RESET;
		case LOG_DEBUG:
			return COLOR(TERM_COLOR_GREEN) "  DEBUG" COLOR_RESET;
		default:
			break;
	}
	__builtin_unreachable();
}

/*! \brief Minimal implementation of __bbs_log, so we can use the same interface */
void __attribute__ ((format (gnu_printf, 6, 7))) __bbs_log(enum bbs_log_level loglevel, int level, const char *file, int lineno, const char *func, const char *fmt, ...)
{
	char *buf;
	int len;
	va_list ap;
	time_t lognow;
	struct tm logdate;
	struct timeval now;
	char datestr[20];

	switch (loglevel) {
		case LOG_DEBUG:
			if (level > option_debug) {
				return;
			}
			break;
		case LOG_VERBOSE:
			assert(0);
			break;
		default:
			break;
	}

	gettimeofday(&now, NULL);
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		fprintf(stderr, "ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	} else {
		char *fullbuf;
		int bytes;
		int need_reset = 0;

		need_reset = strchr(buf, 27) ? 1 : 0; /* If contains ESC, this could contain a color escape sequence. Reset afterwards. */

		bytes = asprintf(&fullbuf, "[%s.%03d] %s: %s:%d %s: %s%s", datestr, (int) now.tv_usec / 1000, loglevel2str(loglevel), file, lineno, func, buf, need_reset ? COLOR_RESET : "");
		if (bytes < 0) {
			fprintf(stderr, "ERROR: Logging vasprintf failure\n"); /* Can't use bbs_log functions! */
			fprintf(stderr, "%s", buf); /* Just put what we had */
		} else {
			fprintf(stderr, "%s", fullbuf);
			free(fullbuf);
		}
		free(buf);
	}

	return;
}

static int parse_options(int argc, char *argv[])
{
	static const char *getopt_settings = "?dDeglst:x";
	int c;

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case '?':
		case 'h':
			fprintf(stderr, "-?     Show this help and exit.\n");
			fprintf(stderr, "-d     Increase debug level. At least level 1 need for BBS log output (except debug, controlled by -D, separately)\n");
			fprintf(stderr, "-D     Increase BBS debug level. Must have at least one -d to get BBS logging output.\n");
			fprintf(stderr, "-e     Run the BBS under valgrind to check for errors and warnings.\n");
			fprintf(stderr, "-g     Also generate valgrind suppressions for the valgrind report.\n");
			fprintf(stderr, "-h     Show this help and exit.\n");
			fprintf(stderr, "-h     Run the BBS under helgrind to check for locking errors.\n");
			fprintf(stderr, "-s     Run the BBS under strace\n");
			fprintf(stderr, "-t     Run a specific named test. Include the test_ prefix but not the .so suffix.\n");
			fprintf(stderr, "-x     Exit on the first failure.\n");
			return -1;
		case 'd':
			if (option_debug == MAX_DEBUG) {
				fprintf(stderr, "Maximum debug level is %d\n", MAX_DEBUG);
				return -1;
			}
			option_debug++;
			break;
		case 'D':
		if (option_debug_bbs == MAX_DEBUG) {
				fprintf(stderr, "Maximum BBS debug level is %d\n", MAX_DEBUG);
				return -1;
			}
			option_debug_bbs++;
			strcat(option_debug_bbs_str, "d"); /* Safe */
			break;
		case 'e':
			option_errorcheck = 1;
			break;
		case 'g':
			option_gen_supp = 1;
			break;
		case 'l':
			option_errorcheck = 1;
			option_helgrind = 1;
			break;
		case 's':
			option_strace = 1;
			break;
		case 't':
			testfilter = optarg;
			break;
		case 'x':
			option_exit_failure = 1;
			break;
		}
	}
	if ((option_errorcheck || option_helgrind) && option_strace) {
		fprintf(stderr, "-e/-l and -s options are mutually exclusive\n");
		return -1;
	}
	return 0;
}

int test_dir_file_count(const char *directory)
{
	int count = 0;
	DIR *dir;
	struct dirent *entry;

	if (!(dir = opendir(directory))) {
		bbs_debug(1, "Error opening directory - %s: %s\n", directory, strerror(errno));
		return -1;
	}
	while ((entry = readdir(dir))) {
		/* Look for any test_*.so files in the directory in which the tests were compiled. */
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		count++;
	}
	closedir(dir);
	return count;
}

int test_make_socket(int port)
{
	struct sockaddr_in sinaddr; /* Internet socket */
	int sock;
	socklen_t len;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		bbs_error("Unable to create TCP socket: %s\n", strerror(errno));
		return -1;
	}
	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sinaddr.sin_port = htons((uint16_t) port);

	/* XXX connect() should not block */

	len = sizeof(sinaddr);
	if (connect(sock, (struct sockaddr *) &sinaddr, len) < 0) {
		bbs_error("Unable to connect to TCP port %d: %s\n", port, strerror(errno));
		close(sock);
		return -1;
	}
	bbs_debug(1, "Connected to %s port %d\n", "TCP", port);
	return sock;
}

int test_client_drain(int fd, int ms)
{
	struct pollfd pfd;
	char buf[4096];
	ssize_t drained = 0;

	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
	assert(pfd.fd != -1);

	for (;;) {
		ssize_t res;
		pfd.revents = 0;
		res = poll(&pfd, 1, ms);
		if (res < 0) {
			return -1;
		} else if (!res) {
			break;
		} else {
			res = read(fd, buf, sizeof(buf) - 1);
			if (res <= 0) {
				bbs_debug(1, "read returned %ld\n", res);
				break;
			} else {
				buf[res] = '\0';
				bbs_debug(8, "Flushed: %s", buf); /* There's probably already a CR LF, don't add to it */
				drained += res;
			}
		}
	}
	bbs_debug(5, "Flushed %ld bytes from fd %d\n", drained, fd);
	return 0;
}

int test_client_expect(int fd, int ms, const char *s, int line)
{
	char buf[4096];
	return test_client_expect_buf(fd, ms, s, line, buf, sizeof(buf));
}

int test_client_expect_buf(int fd, int ms, const char *s, int line, char *buf, size_t len)
{
	int res;
	struct pollfd pfd;

	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	assert(pfd.fd != -1);

	res = poll(&pfd, 1, ms);
	if (res < 0) {
		return -1;
	}
	if (res > 0 && pfd.revents) {
		ssize_t bytes;
		bytes = read(fd, buf, len - 1);
		if (bytes <= 0) {
			bbs_warning("Failed to receive expected output at line %d: %s (read returned %ld) - %s\n", line, s, bytes, strerror(errno));
			return -1;
		}
		buf[bytes] = '\0'; /* Safe */
		if (!strstr(buf, s)) {
			bbs_warning("Failed to receive expected output at line %d: %s (got %s)\n", line, s, buf);
			return -1;
		}
		bbs_debug(10, "Contains output expected at line %d: %s", line, buf); /* Probably already ends in LF */
		return 0;
	}
	bbs_warning("Failed to receive expected output at line %d: %s\n", line, s);
	return -1;
}

int test_client_expect_eventually(int fd, int ms, const char *restrict s, int line)
{
	char buf[4096];
	return test_client_expect_eventually_buf(fd, ms, s, line, buf, sizeof(buf));
}

int test_client_expect_eventually_buf(int fd, int ms, const char *restrict s, int line, char *restrict buf, size_t len)
{
	struct pollfd pfd;

	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = fd;
	pfd.events = POLLIN;
	assert(pfd.fd != -1);

	for (;;) {
		int res;
		pfd.revents = 0;
		res = poll(&pfd, 1, ms);
		if (res < 0) {
			return -1;
		} else if (!res) {
			break;
		}
		if (res > 0 && pfd.revents) {
			ssize_t bytes;
			bytes = read(fd, buf, len - 1);
			if (bytes <= 0) {
				bbs_warning("Failed to receive expected output at line %d: %s (read returned %ld)\n", line, s, bytes);
				return -1;
			}
			buf[bytes] = '\0'; /* Safe */
			/* Probably ends in LF, so skip one here */
			bbs_debug(10, "Analyzing output(%d): %s", line, buf); /* Particularly under valgrind, we'll end up reading individual lines more than chunks, so using CLIENT_DRAIN is especially important */
			/* XXX Should use bbs_readline_append for reliability */
			if (strstr(buf, s)) {
				return 0;
			}
		}
	}
	bbs_warning("Failed to receive expected output at line %d: %s\n", line, s);
	return -1;
}

static void get_live_backtrace(void)
{
	/* Don't try to use gdb if we're already stracing.
	 * Can't do multiple ptraces. */
	if (!option_strace) {
		if (option_errorcheck) {
			system("vgdb v.info scheduler");
		} else {
			/* Before we kill the BBS, dump the current threads to output,
			 * so we can see what was going on in the postmortem. */
			system("../scripts/bbs_dumper.sh livedump && cat full.txt");
		}
	}
}

static int bbs_shutting_down = 0;
static int do_abort = 0;
static int bbspfd[2] = { -1 , -1 };
static int notifypfd[2] = { -1, -1 };
static pthread_t bbs_io_thread = 0;
static const char *bbs_expect_str = NULL;

/* used extern */
int test_autorun = 1;
int rand_alloc_fails = 0;

static int soft_assertions_failed = 0;

static char expectbuf[4096];
static struct readline_data rldata;

static int startup_run_unit_tests_started = 0;

static void *io_relay(void *varg)
{
	char buf[1024];
	int logfd;
	int *pipefd = varg;
	int ready;
	int found;
	char c = '\n';

	logfd = open(TEST_LOGFILE, O_CREAT | O_TRUNC, 0600);
	if (logfd < 0) {
		bbs_error("open failed: %s\n", strerror(errno));
		return NULL;
	}

	for (;;) {
		ssize_t res;
		res = read(pipefd[0], buf, sizeof(buf) - 1);
		if (res <= 0) {
			bbs_debug(4, "read returned %ld\n", res);
			close(logfd);
			return NULL;
		}
		write(logfd, buf, (size_t) res);
		if (option_debug) {
			write(STDERR_FILENO, buf, (size_t) res);
		}
		buf[res] = '\0';
		if (strstr(buf, "Failed soft assertion")) {
			soft_assertions_failed++;
		}
		if (bbs_expect_str) {
			int rounds = 0;
			bbs_readline_append(&rldata, "\n", buf, (size_t) res, &ready);
			/* Check if the line contains the expected output.
			 * If we read multiple lines, loop until there's not a full line left in the buffer. */
			while (ready && bbs_expect_str) { /* Check bbs_expect_str again as it could be set NULL once we get a match */
				found = strstr(expectbuf, bbs_expect_str) ? 1 : 0;
				if (found) {
					if (write(notifypfd[1], &c, 1) != 1) { /* Signal notify waiter */
						bbs_error("write failed: %s\n", strerror(errno));
					}
					if (startup_run_unit_tests && startup_run_unit_tests_started == 0) {
						/* First call to io_relay is always to detect BBS being fully started. */
						startup_run_unit_tests_started = 1;
						/* To prevent a race condition where the BBS unit tests all pass before
						 * test_unit has a chance to call test_bbs_expect with "100%",
						 * stall intentionally until we know we're good to proceed. */
					}
				}
				/* Don't append, just shift the buffer and check if we can read immediately. */
				bbs_readline_append(&rldata, "\n", NULL, 0, &ready);
				rounds++;
			}
			if (startup_run_unit_tests_started == 1) {
				bbs_debug(5, "Stalling until expect reactivated\n");
				while (startup_run_unit_tests_started == 1) {
					usleep(500);
				}
				bbs_debug(5, "Ending stall due to expect reactivation\n");
			}
		} else if (bbs_shutting_down) {
			/* Look for stalled shutdown... we have to do it in this thread,
			 * since the main thread is blocked on the alarm() call. */
			if (strstr(buf, "Skipping unload of ") && strstr(buf, " on pass 27")) {
				/* At this point, something is likely "stuck".
				 * The BBS won't trigger this itself, but we should get a backtrace of the
				 * running process to see what's up. */
				get_live_backtrace();
			}
		}
		if (rand_alloc_fails && strstr(expectbuf, "Simulated allocation failure")) {
			rand_alloc_fails++;
		}
	}
	close(logfd);
	return NULL;
}

int test_bbs_expect(const char *s, int ms)
{
	int res;
	struct pollfd pfd;

	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = notifypfd[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	assert(pfd.fd != -1);

	expectbuf[0] = '\0';
	bbs_readline_init(&rldata, expectbuf, sizeof(expectbuf));
	bbs_expect_str = s;
	if (startup_run_unit_tests_started == 1) {
		startup_run_unit_tests_started = 2;
	}
	res = poll(&pfd, 1, ms);
	bbs_expect_str = NULL;
	if (do_abort || res < 0) {
		bbs_debug(5, "poll returned %d\n", res);
		return -1;
	}
	if (res > 0 && pfd.revents) {
		char c;
		ssize_t rres = read(notifypfd[0], &c, 1);
		if (rres < 1) {
			bbs_warning("read returned %lu: %s\n", rres, strerror(errno));
		}
		return 0;
	}
	bbs_warning("Failed to receive expected output: %s (got: %s)\n", s, expectbuf);
	return -1;
}

static pid_t current_child = 0;
static pid_t mysql_child = 0; /* We never wait on the child since we let it run for remaining tests if/once started, but it will exit with SIGCHLD once we do */

#define MYSQL_DATA_DIR DIRCAT(TEST_MYSQL_DIR, "data")
#define MYSQL_PID_FILE DIRCAT(TEST_MYSQL_DIR, "mysqld.pid")
#define MYSQL_LOG_FILE DIRCAT(TEST_MYSQL_DIR, "mysql.log")
#define MYSQL_ERROR_LOG DIRCAT(TEST_MYSQL_DIR, "error.log")
#define MYSQL_SOCKET DIRCAT(TEST_MYSQL_DIR, "mysqld.sock")
#define MYSQL_PORT 3307
#define MYSQL_PASSWORD "P@ssw0rdUShouldChAngE!"

static int reset_database(void)
{
	/* Seed the database:
	 * Use the right path depending on current directory. */
	if (!eaccess("scripts/dbcreate.sql", R_OK)) {
		/* running from source root */
		if (system("mysql --socket=" MYSQL_SOCKET " < scripts/dbcreate.sql")) {
			bbs_error("Failed to seed database: %s\n", strerror(errno));
			return -1;
		}
	} else if (!eaccess("../scripts/dbcreate.sql", R_OK)) {
		/* running from tests subdir? */
		if (system("mysql --socket=" MYSQL_SOCKET " < ../scripts/dbcreate.sql")) {
			bbs_error("Failed to seed database: %s\n", strerror(errno));
			return -1;
		}
	} else {
		bbs_error("Can't find path to scripts/dbcreate.sql\n");
		return -1;
	}

	return 0;
}

#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored "-Wsign-conversion"
static int mysql_spawn(void)
{
	int attempts = 25;
	struct passwd *pwd;
	/* The MySQL daemon is launched in such a manner that,
	 * even if there are already MySQL databases on this machine,
	 * we isolate the data and daemon from the typical running configuration,
	 * so we can easily manipulate it and avoid touching any real databases. */
	char *argv[] = {
		"mysqld",
		"--datadir=" MYSQL_DATA_DIR,
		"--pid-file=" MYSQL_PID_FILE,
		"--general_log_file=" MYSQL_LOG_FILE,
		"--log-error=" MYSQL_ERROR_LOG,
		"--socket=" MYSQL_SOCKET,
		"--port=" XSTR(MYSQL_PORT),
		"--user=mysql",
		NULL
	};

	/* We require a database, and it isn't running yet, start it */
	bbs_debug(2, "Starting MySQL database daemon\n");

	/* Since we are just starting, initialize fresh */
	TEST_RESET_MKDIR(TEST_MYSQL_DIR);
	TEST_MKDIR(MYSQL_DATA_DIR);

	/* The mysql user exist from installing MySQL as a service */
	pwd = getpwnam("mysql"); /* Not thread-safe, but we don't need that */
	if (!pwd) {
		bbs_error("getpwnam failed: %s\n", strerror(errno));
		return -1;
	}

	if (chown(TEST_MYSQL_DIR, pwd->pw_uid, -1)) {
		bbs_error("chown(%s) failed: %s\n", TEST_MYSQL_DIR, strerror(errno));
		return -1;
	}
	if (chown(MYSQL_DATA_DIR, pwd->pw_uid, -1)) {
		bbs_error("chown(%s) failed: %s\n", TEST_MYSQL_DIR, strerror(errno));
		return -1;
	}

	/* First, initialize the temporary DB: */
	if (system("mysql_install_db --skip-test-db --user=mysql --ldata=" MYSQL_DATA_DIR " > /dev/null")) { /* Yuck... but why reinvent the wheel? */
		bbs_error("Failed to initialize database\n");
		return -1;
	}

	mysql_child = fork();
	if (mysql_child < 0) {
		bbs_error("fork failed: %s\n", strerror(errno));
		return -1;
	} else if (!mysql_child) {
		execvp(argv[0], argv); /* Try again now, and it better work this time */
		_exit(errno);
	}

	/* Wait a moment for the database to start. MYSQL_SOCKET and MYSQL_PID_FILE will both exist while it's running. */
	bbs_debug(2, "MySQL database has started on PID %d\n", mysql_child);
	do {
		if (!eaccess(MYSQL_PID_FILE, R_OK) && !eaccess(MYSQL_SOCKET, R_OK)) {
			bbs_debug(2, "MySQL database has initialized on PID %d\n", mysql_child);
			if (system("mysql --socket=" MYSQL_SOCKET " -e \"CREATE USER 'bbs'@'localhost' IDENTIFIED BY '" MYSQL_PASSWORD "'\"")) {
				bbs_error("Failed to create user: %s\n", strerror(errno));
				return -1;
			}
			if (reset_database()) {
				return -1;
			}
			return 0;
		}
		usleep(100000);
	} while (attempts--);

	bbs_error("Failed to start mysqld\n");
	system("cat " MYSQL_ERROR_LOG);
	return -1;
}

static int test_bbs_spawn(const char *directory)
{
	pid_t child;
	char **argv = NULL;
	char *argv_normal[] = {
		LBBS_BINARY,
		/* Begin options */
		"-b", /* Force reuse bind ports */
		"-c", /* Don't daemonize */
		"-C", (char*) directory, /* Custom config directory */
		"-g", /* Dump core on crash */
		"-vvvvvvvvv", /* Very verbose */
		startup_run_unit_tests ? "-T" : "-v", /* If not, add an option that won't do anything */
		option_debug_bbs ? option_debug_bbs_str : NULL, /* Lotsa debug... maybe */
		NULL
	};
	char *argv_strace[] = {
		"strace",
		"--decode-fds=path",
		"--follow-forks",
		"-o",
		STRACE_LOGFILE,
		LBBS_BINARY,
		/* Begin options */
		"-b", /* Force reuse bind ports */
		"-c", /* Don't daemonize */
		"-C", (char*) directory, /* Custom config directory */
		"-g", /* Dump core on crash */
		"-vvvvvvvvv", /* Very verbose */
		rand_alloc_fails ? "-A" : "-v", /* If not, add an option that won't do anything */
		startup_run_unit_tests ? "-T" : "-v", /* If not, add an option that won't do anything */
		option_debug_bbs ? option_debug_bbs_str : NULL, /* Lotsa debug... maybe */
		NULL
	};
	char *argv_error_check[] = {
		/* There are 3 things that are really helpful about running tests under valgrind:
		 * 1) Can catch errors, warnings, and other issues, in general, which is always good.
		 * 2) The test framework executes extremely quickly, and interacts with the BBS much faster
		 *    than a normal user would. So this stress tests the BBS and potentially exposes issues
		 *    that would not be uncovered in normal executions of either the BBS / under valgrind alone.
		 * 3) The speed of execution is slower under valgrind, which can challenge assumptions made
		 *    (esp. timing related ones) and intolerant tests (or services) may cause test failures
		 *    if these are not taken into account.
		 *
		 * Ideally, to be comprehensive, the tests should be run normally (without valgrind)
		 * as well as under valgrind, and both executions should pass.
		 */
		"valgrind",
#ifdef HAVE_VALGRIND_SHOW_ERROR_LIST
		"--show-error-list=yes",
#endif
		"--keep-debuginfo=yes",
		option_helgrind ? "--tool=helgrind" : "--leak-check=full",
		"--track-fds=yes",
		option_helgrind ? "--tool=helgrind" : "--track-origins=yes",
		option_helgrind ? "--tool=helgrind" : "--show-leak-kinds=all",
		"--suppressions=../valgrind.supp", /* Move up one directory from tests, since that's where this file is */
		/* =yes is not suitable for non-interactive usage: https://valgrind.org/docs/manual/manual-core.html#manual-core.suppress */
		option_gen_supp ? "--gen-suppressions=all" : "--gen-suppressions=no",
		option_helgrind ? "--tool=helgrind" : "--log-file=" VALGRIND_LOGFILE,
		option_helgrind ? "--tool=helgrind" : "--tool=memcheck",
		LBBS_BINARY,
		/* Begin options */
		"-b", /* Force reuse bind ports */
		"-c", /* Don't daemonize */
		"-C", (char*) directory, /* Custom config directory */
		"-g", /* Dump core on crash */
		"-vvvvvvvvv", /* Very verbose */
		rand_alloc_fails ? "-A" : "-v", /* If not, add an option that won't do anything */
		startup_run_unit_tests ? "-T" : "-v", /* If not, add an option that won't do anything */
		option_debug_bbs ? option_debug_bbs_str : NULL, /* Lotsa debug... maybe */
		NULL
	};
	argv = option_errorcheck ? argv_error_check : option_strace ? argv_strace : argv_normal;

	if (pipe(bbspfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	}
	if (pipe(notifypfd)) {
		bbs_error("pipe failed: %s\n", strerror(errno));
		return -1;
	}

	child = fork();
	if (child < 0) {
		bbs_error("fork failed: %s\n", strerror(errno));
		return -1;
	} else if (child == 0) {
		int i;
		close_if(notifypfd[0]);
		close_if(notifypfd[1]);
		close_if(bbspfd[0]); /* Close read end */
		/* Close all file descriptors that might still be open */
		for (i = STDERR_FILENO + 1; i < 1024; i++) {
			if (i != bbspfd[1]) {
				close(i);
			}
		}
		if (dup2(bbspfd[1], STDOUT_FILENO) < 0) {
			bbs_error("dup2(%d) failed: %s\n", bbspfd[1], strerror(errno));
			_exit(errno);
		} else if (dup2(bbspfd[1], STDERR_FILENO) < 0) {
			bbs_error("dup2(%d) failed: %s\n", bbspfd[1], strerror(errno));
			_exit(errno);
		}
		close(STDIN_FILENO); /* Don't accept input */
		close(bbspfd[1]); /* We already dup2'd, we don't need a duplicate or it will result in valgrind complaining about a fd leak (typically of fd 4) */
		execvp(argv[0], argv); /* use execvp instead of execv for option_errorcheck, so we don't have to specify valgrind path */
		bbs_error("execv failed: %s\n", strerror(errno));
		_exit(errno);
	}
	/* Start a thread to handle the output from the BBS process */
	pthread_create(&bbs_io_thread, NULL, io_relay, bbspfd);
	current_child = child;
	return child;
}
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop

static void close_pipes(void)
{
	close_if(bbspfd[0]);
	close_if(bbspfd[1]);
	close_if(notifypfd[0]);
	close_if(notifypfd[1]);
}

static void sigint_handler(int sig)
{
	(void) sig;
	do_abort++;
	if (do_abort > 1 && current_child > 0) {
		/* We already asked nicely. Be a bit more forceful now. */
		kill(current_child, SIGQUIT);
	}
	close_pipes();
}

static const struct test_module_info *testmod;

static int total_pass = 0;
static int total_fail = 0;

FILE *modulefp;

int test_preload_module(const char *module)
{
	if (!modulefp) {
		bbs_error("Can't call this function now\n");
		return -1;
	}
	fprintf(modulefp, "preload=%s\r\n", module);
	return 0;
}

int test_load_module(const char *module)
{
	if (!modulefp) {
		bbs_error("Can't call this function now\n");
		return -1;
	}
	fprintf(modulefp, "load=%s\r\n", module);
	return 0;
}

static int option_autoload_all;
static int option_use_mysql;

void test_autoload_all(void)
{
	option_autoload_all = 1;
}

void test_use_mysql(void)
{
	option_use_mysql = 1;
}

static int reset_test_configs(void)
{
	if (eaccess(TEST_CONFIG_DIR, R_OK)) { /* Create the config directory, if it doesn't exist. */
		if (mkdir(TEST_CONFIG_DIR, 0600)) {
			bbs_error("mkdir(%s) failed: %s\n", TEST_CONFIG_DIR, strerror(errno));
			return -1;
		}
	} else { /* If it does, remove anything currently in it so we start fresh. */
		/* Yuck, but why reinvent the wheel? */
		if (system("rm " TEST_CONFIG_DIR "/*.conf")) {
			bbs_error("Failed to delete files: %s\n", strerror(errno));
		}
	}
	return 0;
}

static int analyze_valgrind(void)
{
	int res = 0;
	char buf[1024];
	int got_segv = 0, fds_open = 0, num_bytes_lost = 0, num_errors = 0, num_false_positives = 0;
	int in_heap_summary = 0, in_error_summary = 0;

	FILE *fp = fopen(VALGRIND_LOGFILE, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", VALGRIND_LOGFILE, strerror(errno));
		return -1;
	}

	while ((fgets(buf, sizeof(buf), fp))) {
		/*! \todo BUGBUG atoi will stop when it sees commas, so for example 8,192 bytes lost is reported as 8 bytes lost
		 * This isn't super high priority to fix at the moment since any number of bytes lost is bad and should be fixed. */
		const char *s;
		if (!num_bytes_lost && (s = strstr(buf, "definitely lost: "))) {
			s += STRLEN("definitely lost: ");
			num_bytes_lost = atoi(s);
		} else if (!num_errors && (s = strstr(buf, "ERROR SUMMARY: "))) {
			/* This includes things like conditional jump on uninitialized value, invalid writes, etc. */
			s += STRLEN("ERROR SUMMARY: ");
			/* This prints out twice, so skip the 2nd one */
			num_errors = atoi(s);
			in_error_summary = 1;
		} else if (!fds_open && (s = strstr(buf, "FILE DESCRIPTORS: "))) {
			s += STRLEN("FILE DESCRIPTORS: ");
			fds_open = atoi(s);
		} else if (!got_segv && (s = strstr(buf, "Process terminating with default action of signal 6 (SIGABRT)"))) {
			/* If we trigger an assertion in the BBS, we'll abort rather than segfault, but we should treat this the same */
			got_segv = 1;
		} else if (!in_heap_summary && (s = strstr(buf, "HEAP SUMMARY:"))) {
			in_heap_summary = 1;
		} else if (in_heap_summary && (s = strstr(buf, "LEAK SUMMARY:"))) {
			if (got_segv && option_debug < 5) {
				fprintf(stderr, "== Memory leak details omitted. See %s for full log.\n", VALGRIND_LOGFILE);
			}
			in_heap_summary = 0;
		} else if (in_error_summary && strstr(buf, "File descriptor ") && strstr(buf, " was closed already")) {
			/* XXX On some distros (non-Debian), at least valgrind 3.24.0 is reporting
			 * the file descriptor for the IRC connection in test_unit (which isn't even part of the tests,
			 * mod_irc_client just establishes a connection to net_irc with its default configuration)
			 * is closed twice.
			 * However, with both FD_LOGFILE file in fd.c enabled and running the same test under strace,
			 * there is no evidence that this file descriptor is closed twice, so this seems like a bug in valgrind
			 * with --trace-fds=yes.
			 * In any case, we ignore these particular errors for now until we figure out what's going on.
			 *
			 * test_autoload has also been added as a more targeted test for this strange behavior,
			 * since it won't run any tests (which is just noise for this problem) but will still autoload everything,
			 * likewise triggering that same IRC connect.
			 */
			num_false_positives++;
		}
		if (option_debug > 2) { /* Most any level of debug gets valgrind report printout */
			if (!got_segv || !in_heap_summary || option_debug > 5) { /* Skip memory leak details if we segfaulted, since those are probably caused by the segfault and output will be HUGE */
				if (!strstr(buf, "used_suppression:") || option_debug > 6) {
					fprintf(stderr, "%s", buf); /* Don't add LF since buffer already contains one */
				}
			}
		}
	}
	fclose(fp);

	/* Print everything out at the end, in case the valgrind log output is long */
	if (got_segv) {
		/* There should already be a core file anyways, but if not for some reason, make sure the test fails */
		bbs_error("Segmentation fault or abortion during execution\n");
	}
/* STDIN, STDOUT, STDERR */
#define FDS_OPEN_EXPECTED 3
	if (fds_open > FDS_OPEN_EXPECTED) {
		bbs_error("%d file descriptors open at shutdown (expected %d)\n", fds_open, FDS_OPEN_EXPECTED);
	}
	if (num_bytes_lost) {
		bbs_error("Memory leak: %d bytes definitely lost\n", num_bytes_lost); /* # of bytes lost will never be singular, I guarantee you */
	}
	if (num_errors) {
		if (num_false_positives == num_errors) {
			bbs_warning("%d error%s during execution, but they were all false positives\n", num_errors, ESS(num_errors));
			num_errors = 0;
		} else {
			bbs_error("%d error%s during execution (%d ignored)\n", num_errors, ESS(num_errors), num_false_positives);
		}
	}

#ifndef HAVE_VALGRIND_SHOW_ERROR_LIST
	bbs_debug(1, "--show-error-list / -s support was not detected in the build system\n");
#endif

	res |= got_segv || num_errors || num_bytes_lost || fds_open > FDS_OPEN_EXPECTED;
	return res;
}

static void send_signal(pid_t pid, int sig)
{
	if (!pid) {
		return;
	}
	switch (sig) {
	case SIGTERM:
		bbs_debug(3, "Sending SIGTERM to process %lu\n", (unsigned long) pid);
		break;
	case SIGKILL:
		bbs_debug(3, "Sending SIGKILL to process %lu\n", (unsigned long) pid);
		break;
	default:
		bbs_error("Unhandled signal: %d\n", sig);
		return;
	}
	kill(pid, sig);
}

static pid_t bbs_pid(pid_t childpid)
{
	/* Since SIGINT requires confirmation, we have to pause briefly before sending a second SIGINT.
	 * Just use SIGTERM since the BBS processes that immediately after receiving one. */
	if (option_strace) {
		char pidbuf[256];
		long pid;
		/* If the BBS is running under strace, then childpid is the PID of strace, not the BBS.
		 * Read the actual PID from the pid file. */
		FILE *fp = fopen(BBS_PID_FILE, "r");
		if (!fp) {
			bbs_error("Can't send signal to BBS, its PID is unknown!\n");
			return 0;
		}
		fgets(pidbuf, sizeof(pidbuf), fp);
		fclose(fp);
		pid = (long int) atol(pidbuf);
		bbs_debug(5, "BBS PID is %ld, not %ld\n", pid, (long int) childpid);
		childpid = (pid_t) pid;
		if (!childpid) {
			bbs_error("Couldn't parse pid file: %s\n", pidbuf);
		}
	}
	return childpid;
}

static void stop_bbs_pid(pid_t childpid)
{
	bbs_shutting_down = 1;
	send_signal(bbs_pid(childpid), SIGTERM); /* Ask it to exit nicely. */
}

static void *stop_stuck_bbs(void *unused)
{
	UNUSED(unused);

	bbs_debug(3, "BBS hasn't yet shut down?\n");

	if (!current_child) {
		return NULL; /* Maybe it just exited */
	}

	get_live_backtrace();

	if (current_child) {
		send_signal(bbs_pid(current_child), SIGTERM);
		send_signal(bbs_pid(current_child), SIGKILL);
		/* Now, the main thread should be unblocked from continuing since waitpid will return */
	}
	return NULL;
}

static void sigalrm_handler(int sig)
{
	pthread_t child;
	pthread_attr_t attr;

	UNUSED(sig);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&child, &attr, stop_stuck_bbs, NULL); /* Not signal safe, but better than doing all that in the current thread */
}

static int run_test(const char *filename, int multiple)
{
	int res = 0;
	void *lib;

	bbs_shutting_down = 0;
	soft_assertions_failed = 0;
	send_count = 0; /* Reset email send count between tests */
	bbs_debug(3, "Planning to run test %s\n", filename);
	total_fail++; /* Increment for now in case we abort early */

	testmod = NULL;
	lib = dlopen(filename, RTLD_NOW | RTLD_LOCAL);
	if (!lib) {
		const char *dlerror_msg = S_IF(dlerror());
		bbs_error("Error loading '%s': %s\n", filename, dlerror_msg);
		return -1;
	}

	if (!testmod) {
		bbs_error("Test module didn't register itself?\n");
		res = -1;
	} else if (!testmod->run) {
		bbs_error("Test module contains no test function?\n");
		res = -1;
	} else {
		struct timeval start, end;
		int64_t sec_dif, usec_dif, tot_dif;
		int core_before = 0;
		pid_t childpid = -1;
		if (eaccess(TEST_ROOT_DIR, R_OK) && mkdir(TEST_ROOT_DIR, 0700)) {
			bbs_error("Failed to create %s: %s\n", TEST_ROOT_DIR, strerror(errno));
			res = -1;
			goto cleanup;
		}
		if (reset_test_configs()) { /* Reset before each test */
			res = -1;
			goto cleanup;
		}
		option_autoload_all = option_use_mysql = rand_alloc_fails = 0;
		test_autorun = 1;
		startup_run_unit_tests = 0;
		if (testmod->pre) {
			char modfilename[256];
			snprintf(modfilename, sizeof(modfilename), "%s/%s", TEST_CONFIG_DIR, "modules.conf");
			modulefp = fopen(modfilename, "w");
			if (!modulefp) {
				bbs_error("fopen(%s) failed: %s\n", modfilename, strerror(errno));
				res = -1;
				goto cleanup;
			}
			fprintf(modulefp, "[general]\r\nautoload=no\r\n\r\n[modules]\r\n");
			test_load_module("mod_auth_static.so"); /* Always load this module */
			res = testmod->pre();
			if (res) {
				goto cleanup;
			}
			if (option_autoload_all) {
				/* Truncate file and start again. Most tests don't use this.
				 * There's not really a great way to truncate a file that's already open, so just close it and start again. */
				fclose(modulefp);
				modulefp = fopen(modfilename, "w");
				if (!modulefp) {
					bbs_error("fopen(%s) failed: %s\n", modfilename, strerror(errno));
					res = -1;
					goto cleanup;
				}
				fprintf(modulefp, "[general]\r\nautoload=yes\r\n\r\n[modules]\r\n");
			}
			fclose(modulefp);
			/* Set up basic configs that most, if not all, tests will need. */
			modulefp = fopen(TEST_CONFIG_DIR "/nodes.conf", "w");
			if (modulefp) {
				fprintf(modulefp, "[bbs]\r\nhostname=%s\r\n", TEST_HOSTNAME);
				fprintf(modulefp, "[nodes]\r\naskdimensions=no\r\n"); /* Only needed for test_menus */
				fclose(modulefp);
			}
			modulefp = fopen(TEST_CONFIG_DIR "/mod_auth_static.conf", "w");
			if (modulefp) {
				fprintf(modulefp, "[users]\r\n%s=%s\r\n", TEST_USER, TEST_HASH);
				fprintf(modulefp, "%s=%s\r\n", TEST_USER2, TEST_HASH2);
				fprintf(modulefp, "%s=%s\r\n", TEST_USER3, TEST_HASH3);
				fprintf(modulefp, "%s=%s\r\n", TEST_USER4, TEST_HASH4);
				fclose(modulefp);
			}
			if (option_autoload_all) {
				if (system("cp " TEST_CONFIGS_SRC_DIR "/*.conf " TEST_CONFIG_DIR)) {
					bbs_error("Failed to copy files: %s\n", strerror(errno));
				}
			}
		}
		/* If we're running all the tests, skip those that should only be run standalone */
		if (multiple && !test_autorun) {
			bbs_debug(2, "Skipping test %s\n", testmod->name);
			total_fail--;
			goto cleanup;
		}
		if (option_use_mysql && !mysql_child && mysql_spawn()) {
			res = -1;
			goto cleanup;
		}
		gettimeofday(&start, NULL);
		if (!res) {
			core_before = eaccess("core", R_OK) ? 0 : 1;
			childpid = test_bbs_spawn(TEST_CONFIG_DIR);
			if (childpid < 0) {
				res = -1;
				goto cleanup;
			}
			bbs_debug(3, "Spawned child process %d (%s)\n", childpid, option_errorcheck ? "valgrind" : option_strace ? "strace" : "lbbs");
			/* Wait for the BBS to fully start */
			/* XXX If we could receive this event outside of the BBS process, that would be more elegant */
			res = test_bbs_expect("BBS is fully started", SEC_MS(STARTUP_TIMEOUT));
			usleep(25000); /* In case a test exits immediately, let spawned threads spawn before we exit */
			if (!res) {
				bbs_debug(3, "BBS fully started on process %d\n", childpid);
				alarm(TEST_TIMEOUT); /* If test hangs, don't wait forever */
				res = testmod->run();
				alarm(0); /* Cancel any pending alarm */
				bbs_debug(3, "Test '%s' returned %d\n", filename, res);
				usleep(25000); /* Allow the poor BBS time for catching its breath. At least test_irc under valgrind seems to need this. */
			} else {
				bbs_warning("BBS didn't complete startup?\n");
			}
			gettimeofday(&end, NULL);
			if (childpid != -1) {
				int wstatus;
				stop_bbs_pid(childpid);
				/* If shutdown gets stuck, don't sit around waiting forever. */
				alarm(SHUTDOWN_TIMEOUT);
				waitpid(childpid, &wstatus, 0); /* Wait for child to exit */
				if (!alarm(0)) { /* Cancel any pending alarm */
					bbs_error("BBS did not shut down in a timely manner, possible deadlock?\n");
					res = -1; /* Automatic fail, since shutdown was not clean */
				}
				current_child = 0;
				bbs_debug(3, "Child process %d has exited\n", childpid);
				if (WIFSIGNALED(wstatus)) { /* Child terminated by signal (probably SIGSEGV?) */
					bbs_error("Process %d (%s) killed, signal %s\n", childpid, filename, bbs_signal_name(WTERMSIG(wstatus)));
				}
			}
			bbs_debug(3, "Test %s return code so far is %d\n", filename, res);
		} else {
			memcpy(&end, &start, sizeof(end));
		}
		close_pipes(); /* This needs to be done before we join bbs_io_thread or it won't exit */
		if (bbs_io_thread) {
			pthread_join(bbs_io_thread, NULL);
			bbs_io_thread = 0;
		}
		sec_dif = (int64_t)(end.tv_sec - start.tv_sec) * 1000;
		usec_dif = (1000000 + end.tv_usec - start.tv_usec) / 1000 - 1000;
		tot_dif = sec_dif + usec_dif;
		if (option_errorcheck) {
			int vres;
			/* Check valgrind.log report for potential issues. */
			vres = analyze_valgrind();
			res |= vres;
			if (vres) {
				bbs_error("valgrind checks failed\n");
			}
		}
		/* We called chdir before we spawned the BBS, so the core dump should be in the current directory if there is one. */
		if (!core_before && !eaccess(XSTR(TEST_DIR) "/core", R_OK)) {
			bbs_error("BBS dumped a core during test %s...\n", testmod->name);
			res = -1; /* Segfaults are never good... automatic test fail. */
		}
		if (rand_alloc_fails) {
			bbs_debug(1, "%d simulated allocation failure%s\n", rand_alloc_fails - 1, ESS(rand_alloc_fails - 1));
		}
		if (soft_assertions_failed) {
			/* These don't cause a crash, so we wouldn't implicitly fail due to one, but these should still cause test failure. */
			bbs_debug(1, "%d soft assertion%s failed\n", soft_assertions_failed, ESS(soft_assertions_failed));
			res = -1;
		}
		if (res) {
			fprintf(stderr, "== Test %sFAILED%s: %5lums %-20s %s\n", COLOR(COLOR_FAILURE), COLOR_RESET, tot_dif, testmod->name, testmod->description);
		} else {
			fprintf(stderr, "== Test %sPASSED%s: %5lums %-20s %s\n", COLOR(COLOR_SUCCESS), COLOR_RESET, tot_dif, testmod->name, testmod->description);
			total_pass++;
			total_fail--; /* We didn't actually fail so undo that bit */
		}
	}

cleanup:
	dlclose(lib);
	if (testmod) {
		bbs_warning("Test module still registered?\n");
	}
	return res;
}

void test_module_register(const struct test_module_info *info)
{
	testmod = info;
	return;
}

void test_module_unregister(const struct test_module_info *info)
{
	UNUSED(info);
	testmod = NULL;
	return;
}

static void stop_bbs(void)
{
	/* Don't use kill since that only works if we were started as the same user. */
	struct stat st;
	FILE *f;
	long file_pid = 0;
	char procpath[PATH_MAX];

	/* Get current value from PID file */
	f = fopen(BBS_PID_FILE, "r");
	if (!f) {
		bbs_debug(5, "PID file %s does not exist\n", BBS_PID_FILE);
		return; /* PID file doesn't exist? No way to tell. */
	}
	if (fscanf(f, "%ld", &file_pid) == EOF) {
		bbs_debug(5, "PID file %s does not contain a PID\n", BBS_PID_FILE);
		return;
	}
	fclose(f);
	if (!file_pid) {
		bbs_warning("Failed to parse PID from %s\n", BBS_PID_FILE);
		return;
	}

	/* Check if such a process is running */
	snprintf(procpath, sizeof(procpath), "/proc/%ld", file_pid);
	if (stat(procpath, &st) == -1 && errno == ENOENT) {
		/* Process doesn't exist */
		bbs_debug(5, "Process %ld no longer exists\n", file_pid);
		return;
	}
	stop_bbs_pid((pid_t) file_pid);
	usleep(1500000);
	/* If it's still running, then forcibly kill it. */
	if (stat(procpath, &st) == -1 && errno == ENOENT) {
		bbs_debug(5, "Gently killed existing BBS process %ld\n", file_pid);
		return;
	}
	kill((pid_t) file_pid, SIGKILL);
	bbs_warning("Forcibly killed existing BBS process %ld\n", file_pid);
	return;
}

int main(int argc, char *argv[])
{
	int res = 0;
	int total;
	char fullpath[512];

	if (parse_options(argc, argv)) {
		return -1;
	}

	stop_bbs(); /* If the BBS is already running, stop it. */
	signal(SIGINT, sigint_handler); /* Catch SIGINT since cleanup could be very messy */
	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE to avoid exiting on failed write to pipe */
	signal(SIGALRM, sigalrm_handler);

	bbs_debug(1, "Looking for tests in %s\n", XSTR(TEST_DIR));
	if (chdir(XSTR(TEST_DIR))) {
		bbs_error("chdir(%s) failed: %s\n", XSTR(TEST_DIR), strerror(errno));
	}

	if (testfilter) { /* Single test */
		snprintf(fullpath, sizeof(fullpath), "%s/%s.so", XSTR(TEST_DIR), testfilter);
		if (eaccess(fullpath, R_OK)) {
			fprintf(stderr, "No such file: %s\n", fullpath);
			return -1;
		}
		fprintf(stderr, "Running test: %s\n", testfilter);
		res |= run_test(fullpath, 0);
	} else { /* Run all tests */
		DIR *dir;
		struct dirent *entry;
		if (!(dir = opendir(XSTR(TEST_DIR)))) {
			bbs_error("Error opening directory - %s: %s\n", XSTR(TEST_DIR), strerror(errno));
			return errno;
		}
		fprintf(stderr, "Running all tests\n");
		while ((entry = readdir(dir))) {
			/* Look for any test_*.so files in the directory in which the tests were compiled. */
			if (entry->d_type != DT_REG || !STARTS_WITH(entry->d_name, "test_") || !strstr(entry->d_name, ".so")) {
				continue;
			}
			snprintf(fullpath, sizeof(fullpath), "%s/%s", XSTR(TEST_DIR), entry->d_name);
			res |= run_test(fullpath, 1);
			if (do_abort || (option_exit_failure && res)) {
				break;
			}
		}
		closedir(dir);
	}

	if (mysql_child) {
		if (kill(mysql_child, SIGTERM)) {
			bbs_error("Failed to stop MySQL: %s\n", strerror(errno));
		} else {
			bbs_debug(5, "Sent SIGTERM to MySQL process %d\n", mysql_child);
		}
	}

	sigint_handler(SIGINT); /* Restore terminal on exit */
	bbs_debug(1, "Test Framework exiting (%d)\n", res);
	if (res) {
		fprintf(stderr, "%d test%s %sFAILED%s\n", total_fail, ESS(total_fail), COLOR(TERM_COLOR_RED), COLOR_RESET);
	}
	total = total_pass + total_fail;
	fprintf(stderr, "%d/%d test%s passed\n", total_pass, total, ESS(total));
	return res;
}
