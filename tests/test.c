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

#include "include/readline.h"

static int option_debug = 0;
static int option_debug_bbs = 0;
static char option_debug_bbs_str[12] = "-";
static int option_errorcheck = 0;
static int option_gen_supp = 0;
static int option_exit_failure = 0;
static const char *testfilter = NULL;

int startup_run_unit_tests;

#define VALGRIND_LOGFILE "/tmp/test_lbbs/valgrind.log"

static const char *loglevel2str(enum bbs_log_level level)
{
	switch (level) {
		case LOG_ERROR:
			return COLOR(COLOR_RED) "  ERROR" COLOR_RESET;
		case LOG_WARNING:
			return COLOR(COLOR_RED) "WARNING" COLOR_RESET;
		case LOG_DEBUG:
			return COLOR(COLOR_GREEN) "  DEBUG" COLOR_RESET;
		default:
			break;
	}
	assert(0);
	return NULL;
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
	lognow = (int) time(NULL);
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
	static const char *getopt_settings = "?dDegt:x";
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
		case 't':
			testfilter = optarg;
			break;
		case 'x':
			option_exit_failure = 1;
			break;
		}
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
			bbs_debug(10, "Analyzing output: %s", buf); /* Particularly under valgrind, we'll end up reading individual lines more than chunks, so using CLIENT_DRAIN is especially important */
			/* XXX Should use bbs_readline_append for reliability */
			if (strstr(buf, s)) {
				return 0;
			}
		}
	}
	bbs_warning("Failed to receive expected output at line %d: %s\n", line, s);
	return -1;
}

static int do_abort = 0;
static int bbspfd[2] = { -1 , -1 };
static int notifypfd[2] = { -1, -1 };
static pthread_t bbs_io_thread = 0;
static const char *bbs_expect_str = NULL;

/* used extern */
int test_autorun = 1;
int rand_alloc_fails = 0;

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

	logfd = open("/tmp/test_lbbs.log", O_CREAT | O_TRUNC, 0600);
	if (logfd < 0) {
		bbs_error("open failed: %s\n", strerror(errno));
		return NULL;
	}

	for (;;) {
		ssize_t res;
		res = read(pipefd[0], buf, sizeof(buf) - 1);
		if (res <= 0) {
			bbs_debug(4, "read returned %ld\n", res);
			return NULL;
		}
		write(logfd, buf, (size_t) res);
		if (option_debug) {
			write(STDERR_FILENO, buf, (size_t) res);
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
		read(notifypfd[0], &c, 1);
		return 0;
	}
	bbs_warning("Failed to receive expected output: %s (got: %s)\n", s, expectbuf);
	return -1;
}

#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
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
		"--show-error-list=yes",
		"--keep-debuginfo=yes",
		"--leak-check=full",
		"--track-fds=yes",
		"--track-origins=yes",
		"--show-leak-kinds=all",
		"--suppressions=../valgrind.supp", /* Move up one directory from tests, since that's where this file is */
		/* =yes is not suitable for non-interactive usage: https://valgrind.org/docs/manual/manual-core.html#manual-core.suppress */
		option_gen_supp ? "--gen-suppressions=all" : "--gen-suppressions=no",
		"--log-file=" VALGRIND_LOGFILE,
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
	argv = option_errorcheck ? argv_error_check : argv_normal;

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
		execvp(option_errorcheck ? "valgrind" : LBBS_BINARY, argv); /* use execvp instead of execv for option_errorcheck, so we don't have to specify valgrind path */
		bbs_error("execv failed: %s\n", strerror(errno));
		_exit(errno);
	}
	/* Start a thread to handle the output from the BBS process */
	pthread_create(&bbs_io_thread, NULL, io_relay, bbspfd);
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
	do_abort = 1;
	/* The nice thing about the spawned BBS is that it's a child process,
	 * so when we exit, it'll automatically receive a SIGCHLD.
	 * We don't explicitly need to terminate it here. */
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

void test_autoload_all(void)
{
	option_autoload_all = 1;
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
		system("rm " TEST_CONFIG_DIR "/*.conf");
	}
	return 0;
}

static int analyze_valgrind(void)
{
	int res = 0;
	char buf[1024];
	int got_segv = 0, fds_open = 0, num_bytes_lost = 0, num_errors = 0;
	int in_heap_summary = 0;

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
/* STDIN, STDOUT, STDERR, +1 */
#define FDS_OPEN_EXPECTED 4
	if (fds_open > FDS_OPEN_EXPECTED) {
		bbs_error("%d file descriptors open at shutdown (expected %d)\n", fds_open, FDS_OPEN_EXPECTED);
	}
	if (num_bytes_lost) {
		bbs_error("Memory leak: %d bytes definitely lost\n", num_bytes_lost); /* # of bytes lost will never be singular, I guarantee you */
	}
	if (num_errors) {
		bbs_error("%d error%s during execution\n", num_errors, ESS(num_errors));
	}

	res |= got_segv || num_errors || num_bytes_lost || fds_open > FDS_OPEN_EXPECTED;
	return res;
}

static int run_test(const char *filename, int multiple)
{
	int res = 0;
	void *lib;

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
		option_autoload_all = rand_alloc_fails = 0;
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
				fclose(modulefp);
			}
			modulefp = fopen(TEST_CONFIG_DIR "/mod_auth_static.conf", "w");
			if (modulefp) {
				fprintf(modulefp, "[users]\r\n%s=%s\r\n", TEST_USER, TEST_HASH);
				fprintf(modulefp, "[users]\r\n%s=%s\r\n", TEST_USER2, TEST_HASH2);
				fclose(modulefp);
			}
			if (option_autoload_all) {
				system("cp *.conf " TEST_CONFIG_DIR);
			}
		}
		/* If we're running all the tests, skip those that should only be run standalone */
		if (multiple && !test_autorun) {
			bbs_debug(2, "Skipping test %s\n", testmod->name);
			total_fail--;
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
			bbs_debug(3, "Spawned child process %d\n", childpid);
			/* Wait for the BBS to fully start */
			/* XXX If we could receive this event outside of the BBS process, that would be more elegant */
			res = test_bbs_expect("BBS is fully started", SEC_MS(15));
			usleep(25000); /* In case a test exits immediately, let spawned threads spawn before we exit */
			if (!res) {
				bbs_debug(3, "BBS fully started on process %d\n", childpid);
				res = testmod->run();
				bbs_debug(3, "Test '%s' returned %d\n", filename, res);
				usleep(25000); /* Allow the poor BBS time for catching its breath. At least test_irc under valgrind seems to need this. */
			}
			gettimeofday(&end, NULL);
			if (childpid != -1) {
				int wstatus;
				kill(childpid, SIGINT); /* Ask it to exit nicely. */
				waitpid(childpid, &wstatus, 0); /* Wait for child to exit */
				bbs_debug(3, "Child process %d has exited\n", childpid);
			}
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
			/* Check valgrind.log report for potential issues. */
			res |= analyze_valgrind();
		}
		/* We called chdir before we spawned the BBS, so the core dump should be in the current directory if there is one. */
		if (!core_before && !eaccess("core", R_OK)) {
			bbs_error("BBS dumped a core during test %s...\n", testmod->name);
			res = -1; /* Segfaults are never good... automatic test fail. */
		}
		if (rand_alloc_fails) {
			bbs_debug(1, "%d simulated allocation failure%s\n", rand_alloc_fails - 1, ESS(rand_alloc_fails - 1));
		}
		if (res) {
			fprintf(stderr, "== Test %sFAILED%s: %5lums %-20s %s\n", COLOR(COLOR_RED), COLOR_RESET, tot_dif, testmod->name, testmod->description);
		} else {
			fprintf(stderr, "== Test %sPASSED%s: %5lums %-20s %s\n", COLOR(COLOR_GREEN), COLOR_RESET, tot_dif, testmod->name, testmod->description);
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
	fscanf(f, "%ld", &file_pid);
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
	kill((pid_t) file_pid, SIGINT); /* Ask it to exit nicely. */
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

	bbs_debug(1, "Looking for tests in %s\n", XSTR(TEST_DIR));
	chdir(XSTR(TEST_DIR));

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

	sigint_handler(SIGINT); /* Restore terminal on exit */
	bbs_debug(1, "Test Framework exiting (%d)\n", res);
	if (res) {
		fprintf(stderr, "%d test%s %sFAILED%s\n", total_fail, ESS(total_fail), COLOR(COLOR_RED), COLOR_RESET);
	}
	total = total_pass + total_fail;
	fprintf(stderr, "%d/%d test%s passed\n", total_pass, total, ESS(total));
	return res;
}
