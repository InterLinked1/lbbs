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

/*!
 * \mainpage LBBS -- The Lightweight Bulletin Board System
 *
 * \section copyright Copyright and Author
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief Top level source file for LBBS.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define BBS_MAIN_FILE

#include "include/bbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h> /* use mkdir */
#include <sys/types.h> /* use getpid */
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h> /* use O_NONBLOCK */
#include <limits.h> /* use PATH_MAX */
#include <libgen.h> /* use dirname */

#ifdef __linux__
#include <sys/prctl.h> /* use prctl */
#include <sys/capability.h>
#include <linux/capability.h>
#endif

#include <sys/resource.h> /* use rlimit */
#include <grp.h> /* use getgrnam */
#include <pwd.h> /* use getpwnam */
#include <sys/ioctl.h>

#include "include/module.h" /* use load_modules */
#include "include/reload.h"
#include "include/alertpipe.h"
#include "include/os.h"
#include "include/system.h"
#include "include/config.h"
#include "include/menu.h"
#include "include/mail.h"
#include "include/auth.h" /* use bbs_num_auth_providers */
#include "include/utils.h" /* use print_time_elapsed, print_days_elapsed */
#include "include/node.h"
#include "include/user.h"
#include "include/group.h"
#include "include/variables.h"
#include "include/startup.h"
#include "include/event.h"
#include "include/test.h"
#include "include/transfer.h"
#include "include/cli.h"
#include "include/handler.h"
#include "include/net.h"
#include "include/door.h"

static char *_argv[256];

/* Immutable */
int option_dumpcore = 0; /* extern in bbs.h for backtrace */
int option_nofork = 0; /* run in foreground instead of daemonizing */
int option_rebind = 0; /* used extern in socket.c */
int option_rand_alloc_failures = 0; /* used extern in alloc.c */
static int option_run_unit_tests = 0; /* run unit tests on startup */

/* Mutable during runtime */
int option_debug = 0;
int option_verbose = 0;
int max_logfile_debug_level = MAX_DEBUG;

char *rungroup = NULL, *runuser = NULL, *config_dir = NULL;

static pid_t bbs_pid;

static time_t bbs_start_time;

enum shutdown_type {
	SHUTDOWN_NORMAL = 0,
	SHUTDOWN_RESTART,
	SHUTDOWN_HALT,
};

static int sig_alert_pipe[2] = { -1, -1 };
static int abort_startup = 0;
static int want_shutdown = 0;
static int shutting_down = 0;
static enum shutdown_type shutdown_type = SHUTDOWN_NORMAL;

static bbs_mutex_t sig_lock;

/*! \brief Save original args for restart */
static void saveopts(int argc, char *argv[])
{
	int x;
	
	/* Remember original args for restart */
	if (argc > (int) ARRAY_LEN(_argv) - 1) {
		fprintf(stderr, "Truncating argument size to %d\n", (int) ARRAY_LEN(_argv) - 1);
		argc = ARRAY_LEN(_argv) - 1;
	}
	for (x = 0; x < argc; x++) {
		_argv[x] = argv[x];
	}
	_argv[x] = NULL;
}

static int set_cwd(void)
{
	char dir[PATH_MAX];

	if (!getcwd(dir, sizeof(dir)) || eaccess(dir, R_OK | X_OK | F_OK)) {
		fprintf(stderr, "Unable to access the running directory (%s). Changing to '/' for compatibility.\n", strerror(errno));
		/* If we cannot access the CWD, then we couldn't dump core anyway,
		 * so chdir("/") won't break anything. */
		if (chdir("/")) {
			/* chdir(/) should never fail, so this ends up being a no-op */
			fprintf(stderr, "chdir(\"/\") failed?!! %s\n", strerror(errno));
			return -1;
		}
	} else if (!option_nofork && !option_dumpcore) {
		/* Backgrounding, but no cores, so chdir won't break anything. */
		if (chdir("/")) {
			fprintf(stderr, "Unable to chdir(\"/\") ?!! %s\n", strerror(errno));
			return -1;
		}
	}

	return 0;
}

static int get_core_file_pattern(char *buf, size_t len)
{
	FILE *fp = fopen("/proc/sys/kernel/core_pattern", "r");
	if (!fp) {
		bbs_warning("Failed to open %s: %s\n", "/proc/sys/kernel/core_pattern", strerror(errno));
		return -1;
	}
	if (!fgets(buf, (int) len, fp)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	bbs_strterm(buf, '\n');
	return 0;
}

static void startup_checks(void)
{
	char corefile[PATH_MAX];

	/* Wherever we end up, if we can't write to the current directory, we may not be able to dump a core. */
	if (!get_core_file_pattern(corefile, sizeof(corefile))) {
		/* Get parent */
		const char *corefiledir = dirname(corefile);
		if (corefiledir && !strcmp(corefiledir, ".")) {
			/* If the core would get dumped in the current running directory, get its absolute path */
			if (!getcwd(corefile, sizeof(corefile))) {
				return;
			}
			corefiledir = corefile;
		}
		if (corefiledir && eaccess(corefiledir, R_OK | W_OK | X_OK | F_OK)) {
			/* Common fixes if a core isn't getting dumped:
			 * - Run 'ulimit -c unlimited'
			 * - Ensure the BBS run user has write permissions to the running directory of the BBS. */
			bbs_warning("Core file directory '%s' is not writable by BBS user %s - change the rundir or its permissions or adjust the core pattern!\n", corefiledir, S_IF(runuser));
		}
	}
}

static void check_cap(int isroot)
{
#ifdef __linux__
	cap_t caps;
	cap_value_t cap;
	cap_flag_value_t flag;

#define cap_err(fmt, ...) if (isroot) { fprintf(stderr, fmt, ## __VA_ARGS__); } else { bbs_error(fmt, ## __VA_ARGS__); }

/* #define DEBUG_CAPS */

#ifdef DEBUG_CAPS
	char *txt_caps;
#endif

	/* if isroot, it's before dropping privileges, we can set caps and we can NOT use bbs_log.
	 * if !isroot, it's after dropping privileges, we can only read, but we can log normally. */

	caps = cap_get_proc();
	if (!caps) {
		cap_err("Failed to get process capabilities: %s\n", strerror(errno));
		return;
	}

	/* Check if we have CAP_NET_BIND_SERVICE. If we don't, we can't bind to privileged ports */
	cap = CAP_NET_BIND_SERVICE;
	if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &flag)) {
		cap_err("Failed to get process capabilities: %s\n", strerror(errno));
		goto cleanup;
	}
	if (flag != CAP_SET) {
		/* Typically < 1024, but could be different per system.
		 * Can run sysctl -a | grep "net.ipv4.ip_unprivileged_port_start" to see where privileged ports start. */
		if (isroot) {
			fprintf(stderr, "Process lacks CAP_NET_BIND_SERVICE capability and may not be able to bind to privileged ports\n");
		} else {
			bbs_warning("Process lacks CAP_NET_BIND_SERVICE capability and may not be able to bind to privileged ports.\n");
			bbs_warning("Consider granting privileges to UID %d to bind on any necessary ports, or use nonprivileged ports.\n", getuid()); /* By this point, we've dropped privileges and check UID directly */
		}
	}

	if (isroot) {
#if 0
		/* Sadly, this doesn't actually work. Users will need to manually rectify this issue.
		 * setcap cap_net_bind_service=ep /usr/sbin/lbbs doesn't seem to work either for me.
		 * To change min nonpriv port: sysctl net.ipv4.ip_unprivileged_port_start=513
		 * To persist this change: sysctl -w net.ipv4.ip_unprivileged_port_start=513
		 * authbind sounds theoretically nice but may have issues with multithreaded programs (like the BBS), not recommended.
		 */
		/* While we're root, before we drop privileges, grant CAP_NET_BIND_SERVICE */
		cap_value_t cap_list[1];
		cap_list[0] = CAP_NET_BIND_SERVICE;
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
			cap_err("Failed to set process capabilities flags: %s\n", strerror(errno));
			goto cleanup;
		}
		if (cap_set_proc(caps)) {
			cap_err("Failed to set process capabilities: %s\n", strerror(errno));
			goto cleanup;
		}
#else
		/* XXX Possible future improvement: determine what ports we need to bind to (from all network drivers),
		 * then automatically run sysctl net.ipv4.ip_unprivileged_port_start=MINPORT to grant temporarily.
		 * This must be an optional, disabled-by-default setting in bbs.conf, due to the inherent security risks. */
#endif
	}

#ifdef DEBUG_CAPS
	txt_caps = cap_to_text(caps, NULL);
	if (!txt_caps) {
		cap_err("Failed to get process capabilities as text: %s\n", strerror(errno));
		return;
	}
	if (isroot) {
		fprintf(stderr, "Current process capabilities (+set): %s\n", txt_caps);
	} else {
		bbs_debug(3, "Current process capabilities (+set): %s\n", txt_caps);
	}
	cap_free(txt_caps);
#endif

cleanup:
	if (cap_free(caps) == -1) {
		cap_err("Failed to free process capabilities: %s\n", strerror(errno));
	}
#else
	UNUSED(isroot);
	bbs_debug(3, "Capabilities not supported\n");
#endif /* __linux__ */
}

#pragma GCC diagnostic ignored "-Wsign-conversion"
static int run_init(int argc, char *argv[])
{
	struct rlimit limits;
	int isroot = is_root();
	bbs_pid = getpid();

	if (option_dumpcore) {
		memset(&limits, 0, sizeof(limits));
		limits.rlim_cur = RLIM_INFINITY;
		limits.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &limits)) {
			fprintf(stderr, "Unable to disable core size resource limit: %s\n", strerror(errno));
			return -1;
		}
	}

	if (getrlimit(RLIMIT_NOFILE, &limits)) {
		fprintf(stderr, "Unable to check file descriptor limit: %s\n", strerror(errno));
		return -1;
	}

	/* It's common on some platforms to clear /var/run at boot.  Create the
	 * socket file directory before we drop privileges. */
	if (mkdir(BBS_RUN_DIR, 0755)) {
		if (errno != EEXIST) {
			fprintf(stderr, "Unable to create socket file directory (%s)\n", strerror(errno));
			return -1;
		}
	}

	if (isroot && rungroup) {
		struct group *gr = getgrnam(rungroup);
		if (!gr) {
			fprintf(stderr, "No such group '%s'!\n", rungroup);
			return -1;
		}
		if (chown(BBS_RUN_DIR, -1, gr->gr_gid)) {
			fprintf(stderr, "Unable to chgrp run directory to %d (%s)\n", (int) gr->gr_gid, rungroup);
			return -1;
		}
		if (setgid(gr->gr_gid)) {
			fprintf(stderr, "Unable to setgid to %d (%s)\n", (int) gr->gr_gid, rungroup);
			return -1;
		}
		if (setgroups(0, NULL)) {
			fprintf(stderr, "Unable to drop unneeded groups\n");
			return -1;
		}
	}

	if (runuser) {
		struct passwd *pw;
		pw = getpwnam(runuser);
		if (!pw) {
			fprintf(stderr, "No such user '%s'!\n", runuser);
			return -1;
		}
		if (chown(BBS_RUN_DIR, pw->pw_uid, -1)) {
			if (eaccess(BBS_RUN_DIR, X_OK)) { /* If we don't already have the right permissions, then that's an issue */
				fprintf(stderr, "Unable to chown run directory to %d (%s)\n", (int) pw->pw_uid, runuser);
				return -1;
			}
		}
		if (eaccess(BBS_LOG_DIR, R_OK)) {
			if (mkdir(BBS_LOG_DIR, 0744)) { /* Directory must be executable to be able to create files in it */
				fprintf(stderr, "Unable to create log directory: %s\n", strerror(errno));
				return -1;
			}
		}
		if (chown(BBS_LOG_DIR, pw->pw_uid, -1)) {
			fprintf(stderr, "Unable to chown log directory to %d (%s)\n", (int) pw->pw_uid, runuser);
			return -1;
		}
		if (!isroot && pw->pw_uid != geteuid()) {
			fprintf(stderr, "BBS started as nonroot, but runuser '%s' requested.\n", runuser);
			return -1;
		}
		if (!rungroup) {
			if (setgid(pw->pw_gid)) {
				fprintf(stderr, "Unable to setgid to %d!\n", (int) pw->pw_gid);
				return -1;
			}
			if (isroot && initgroups(pw->pw_name, pw->pw_gid)) {
				fprintf(stderr, "Unable to init groups for '%s'\n", runuser);
				return -1;
			}
		}
		check_cap(1);
		if (setuid(pw->pw_uid)) {
			fprintf(stderr, "Unable to setuid to %d (%s)\n", (int) pw->pw_uid, runuser);
			return -1;
		}
	}

	if (!is_root() && option_dumpcore) {
#ifdef __linux__
		if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
			fprintf(stderr, "Unable to set the process for core dumps after changing to a non-root user. %s\n", strerror(errno));
			return -1;
		}
#endif /* __linux__ */
	}

	if (set_cwd()) {
		return -1;
	}

	saveopts(argc, argv);
	return 0;
}
#pragma GCC diagnostic pop

time_t bbs_starttime(void)
{
	return bbs_start_time;
}

const char *bbs_config_dir(void)
{
	if (strlen_zero(config_dir)) {
		return BBS_CONFIG_DIR;
	}
	return config_dir;
}

int bbs_view_settings(int fd)
{
	char timebuf[24];
	char daysbuf[36];
	char corefile[PATH_MAX] = "";
	char curdir[PATH_MAX];
	time_t now;

	now = time(NULL);
	print_time_elapsed(bbs_start_time, now, timebuf, sizeof(timebuf));
	print_days_elapsed(bbs_start_time, now, daysbuf, sizeof(daysbuf));

	get_core_file_pattern(corefile, sizeof(corefile));
	if (!getcwd(curdir, sizeof(curdir))) {
		curdir[0] = '\0';
	}

#define VIEW_FMT_D  "%-12s: %d\n"
#define VIEW_FMT_U  "%-12s: %u\n"
#define VIEW_FMT_S  "%-12s: %s\n"
#define VIEW_FMT_SS "%-12s: %s (%s)\n"
	bbs_dprintf(fd, VIEW_FMT_S, "Host", bbs_hostname());
	bbs_dprintf(fd, VIEW_FMT_D, "PID", getpid());
	bbs_dprintf(fd, VIEW_FMT_D, "Verbose", option_verbose);
	bbs_dprintf(fd, VIEW_FMT_D, "Debug", option_debug);
	bbs_dprintf(fd, VIEW_FMT_S, "Config Dir", bbs_config_dir());
	bbs_dprintf(fd, VIEW_FMT_S, "Run User", S_IF(runuser));
	bbs_dprintf(fd, VIEW_FMT_S, "Run Group", S_IF(rungroup));
	bbs_dprintf(fd, VIEW_FMT_S, "Dump Core", BBS_YN(option_dumpcore));
	bbs_dprintf(fd, VIEW_FMT_S, "Core File", corefile);
	bbs_dprintf(fd, VIEW_FMT_S, "Current Dir", curdir);
	bbs_dprintf(fd, VIEW_FMT_S, "Daemonized", BBS_YN(!option_nofork));
	bbs_dprintf(fd, VIEW_FMT_SS, "BBS Uptime", timebuf, daysbuf);
	bbs_dprintf(fd, VIEW_FMT_U, "Active Nodes", bbs_node_count());
#undef VIEW_FMT_SS
#undef VIEW_FMT_S
#undef VIEW_FMT_U
#undef VIEW_FMT_D
	return 0;
}

static void show_help(void)
{
	/* It is safe to use printf here since we aren't yet multithreaded */
	printf("  -A        Randomly fail allocations periodically (DO NOT USE IN PRODUCTION)\n");
	printf("  -b        Always force rebind to busy ports\n");
	printf("  -c        Do not fork daemon\n");
	printf("  -C        Specify alternate configuration directory\n");
	printf("  -d        Increase debug level\n");
	printf("  -g        Dump core on crash\n");
	printf("  -G        Specify run group\n");
	printf("  -h        Display this help and exit\n");
	printf("  -T        Run unit tests on startup\n");
	printf("  -U        Specify run user\n");
	printf("  -v        Increase verbosity level\n");
	printf("  -V        Display version number and exit\n");
	printf("  -?        Display this help and exit\n");
}

static const char *getopt_settings = "?AbcC:dG:ghTU:Vv";

static int parse_options_pre(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case 'C':
			/* Affects what config we load in load_config, so do before that */
			REPLACE(config_dir, optarg);
			break;
		case 'V':
			fprintf(stderr, BBS_TAGLINE " " BBS_VERSION "\n");
			return -1;
		default:
			break; /* Ignore for now, everything else handled in parse_options */
		}
	}
	return 0;
}

static int parse_options(int argc, char *argv[])
{
	int c;

	optind = 1; /* Reset from parse_options_pre */
	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case '?':
		case 'h':
			show_help();
			return -1;
		case 'A':
			option_rand_alloc_failures = 1;
			break;
		case 'b':
			option_rebind = 1;
			break;
		case 'c':
			option_nofork = 1;
			break;
		case 'C':
			break; /* Already processed in parse_options_pre, skip */
		case 'd':
			if (option_debug == MAX_DEBUG) {
				fprintf(stderr, "Maximum debug level is %d\n", MAX_DEBUG);
				if (!config_dir) {
					return -1;
				}
			} else {
				option_debug++;
			}
			break;
		case 'g':
			option_dumpcore = 1;
			break;
		case 'G':
			REPLACE(rungroup, optarg); /* If specified by config, override */
			break;
		case 'T':
			option_run_unit_tests = 1;
			break;
		case 'U':
			REPLACE(runuser, optarg); /* If specified by config, override */
			break;
		case 'v':
			if (option_verbose == MAX_VERBOSE) {
				fprintf(stderr, "Maximum verbose level is %d\n", MAX_VERBOSE);
				if (!config_dir) {
					return -1;
				}
			} else {
				option_verbose++;
			}
			break;
		}
	}
	return 0;
}

static void free_options(void)
{
	free_if(runuser);
	free_if(rungroup);
	free_if(config_dir);
}

/* Whether we successfully started the BBS */
static int fully_started = 0;

/* used extern by logger.c */
int shutdown_finished = 0;

int bbs_is_fully_started(void)
{
	return fully_started;
}

int bbs_abort_startup(void)
{
	return abort_startup;
}

int bbs_is_shutting_down(void)
{
	return shutting_down;
}

static void cleanup(void)
{
	/* Close alertpipe */
	bbs_alertpipe_close(sig_alert_pipe);

	/* Shutdown logging last. */
	if (shutdown_type == SHUTDOWN_RESTART) {
		bbs_verb(2, "BBS is now restarting on PID %d\n", bbs_pid);
	} else {
		bbs_verb(2, "Finalizing shutdown\n");
	}
	bbs_thread_cleanup();
	bbs_log_close();
	free_options();
	if (fully_started) {
		/* Don't remove the PID file if we didn't successfully start.
		 * The main thing this addresses is if we tried to start and the BBS was already running.
		 * In that case, we'll abort, and we shouldn't remove the PID file because the already-running
		 * instance of the BBS created the PID file, not us, and it will remove it when it exits,
		 * so we should just leave it alone. */
		unlink(BBS_PID_FILE); /* Remove PID file. This is necessary for restart to succeed. */
	}
	shutdown_finished = 1;
	if (shutdown_type == SHUTDOWN_RESTART) {
		int i, saved_errno;
		/* Mark all file descriptors for closing on exec */
		for (i = 3; i < 32768; i++) {
			fcntl(i, F_SETFD, FD_CLOEXEC);
		}
		/* Note that exec preserves PIDs: the restarted BBS will have the same PID as the old one,
		 * although if daemonized, the PID will immediately change. */
		execvp(_argv[0], _argv);
		/* If we get here, that means we failed to restart... */
		saved_errno = errno;
		bbs_log_init(option_nofork); /* Reopen logging channel so we can record this */
		bbs_error("Failed to restart: %s\n", strerror(saved_errno));
		bbs_log_close();
		/* Go ahead and just exit, since we failed to restart */
	}
}

static void bbs_shutdown(void)
{
	bbs_mutex_lock(&sig_lock);
	if (shutting_down) {
		bbs_mutex_unlock(&sig_lock);
		bbs_error("Active shutdown already in progress\n");
		return;
	}
	shutting_down = 1;
	bbs_event_dispatch(NULL, EVENT_SHUTDOWN);
	if (shutdown_type == SHUTDOWN_HALT) {
		bbs_warning("Halting BBS\n");
		/* Fast exit (halt), don't clean up */
		exit(EXIT_FAILURE);
	}
	bbs_verb(2, "Shutting down BBS\n");
	bbs_node_shutdown_all(shutting_down);

	/* Let go of the lock in case a module
	 * tries to perform some action that locks sig_lock,
	 * which would lead to deadlock. */
	bbs_mutex_unlock(&sig_lock);
	unload_modules();
	bbs_mutex_lock(&sig_lock);

	login_cache_cleanup(); /* Clean up any remaining cached logins */
	username_cache_flush(); /* Clean up any cached username mappings */
	bbs_free_menus(); /* Clean up menus */
	bbs_groups_cleanup();
	bbs_cleanup_auth();
	bbs_configs_free_all(); /* Clean up any remaining configs that modules didn't. */
	bbs_vars_cleanup();
	bbs_cli_unregister_remaining();
	tcp_listener_cleanup();
	bbs_fd_shutdown();
	bbs_mutex_unlock(&sig_lock); /* Don't release the lock until the very end */
	bbs_mutex_destroy(&sig_lock);
	cleanup();
}

static int *sigint_alert_pipe = NULL;

void bbs_sigint_set_alertpipe(int p[2])
{
	sigint_alert_pipe = p;
}

static time_t last_shutdown_attempt = 0;

static void __sigint_handler(int num)
{
	time_t now;

	if (getpid() != bbs_pid) {
		/* __sigint_handler triggered from child process before it was removed in system.c (race condition). Just abort.
		 * Remember, must NEVER call bbs_log within a child, it will deadlock waiting for the log lock. */
		return;
	}

	if (!fully_started) {
		/* This typically happens when something blcoks startup, e.g. binding to a port already in use, with force bind.
		 * To properly handle this, whatever is doing whatever it is should be prepared to abort if needed. */
		bbs_debug(3, "SIGINT received prior to BBS being fully started\n");
		abort_startup = 1;
	}

	/* If somebody is subscribed to the SIGINT handler, dispatch it to them and ignore it. */
	/* XXX Currently we allow 1 external subscriber at a time. In theory if we wanted more than one possible,
	 * we could maintain a linked list of subscribers, but that seems like overkill right now,
	 * especially since we're inside a signal handler. */
	if (sigint_alert_pipe) {
		bbs_debug(2, "Got SIGINT with subscriber, skipping built-in handling\n"); /* XXX not safe */
		if (bbs_alertpipe_write(sigint_alert_pipe) < 0) {
			/* Don't use BBS log functions within a signal handler */
			if (option_nofork) {
				fprintf(stderr, "%s: write() failed: %s\n", __func__, strerror(errno));
			}
		}
		/* XXX Should we go ahead and automatically remove the subscriber? (set sigint_alert_pipe to NULL?)
		 * Right now we rely on the subscriber to do this manually. If someone forgets, this could be bad. */
		 return;
	}
	now = time(NULL);

	/* Prompt for confirmation with SIGINT.
	 * No confirmation for SIGTERM. */
	if (num == SIGINT) {
		if (!last_shutdown_attempt || last_shutdown_attempt < now - 10) {
			/* ^C in a remote console just exits the console, while
			 * ^C in the foreground console terminates the BBS.
			 * It is easy to forget which console you are in and
			 * accidentally kill the entire BBS when you just meant to exit the console.
			 * Try to prevent this from happening by asking if that's what the sysop really wants. */
			last_shutdown_attempt = now;
			if (!strlen_zero(bbs_hostname())) {
				printf("\n%sReally shut down the BBS on %s? Press ^C again within 10s to confirm.%s\n", COLOR(TERM_COLOR_RED), bbs_hostname(), COLOR_RESET); /* XXX technically not safe to use in signal handler */
			} else {
				printf("\n%sReally shut down the BBS? Press ^C again within 10s to confirm.%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET); /* XXX technically not safe to use in signal handler */
			}
			return;
		}
		bbs_debug(2, "Got SIGINT, requesting shutdown\n"); /* XXX technically not safe to use in signal handler */
	}

	want_shutdown = 1;
	if (bbs_alertpipe_write(sig_alert_pipe) < 0) {
		/* Don't use BBS log functions within a signal handler */
		if (option_nofork) {
			fprintf(stderr, "%s: write() failed: %s\n", __func__, strerror(errno));
		}
	}
}

static struct sigaction sigint_handler = {
	.sa_handler = __sigint_handler,
};

/*! \brief Log any SIGWINCHes received */
static void __sigwinch_handler(int num)
{
	struct winsize ws;

	UNUSED(num);

	memset(&ws, 0, sizeof(ws));

	if (getpid() != bbs_pid) {
		/* __sigwinch_handler triggered from child process before it was removed in system.c (race condition). Just abort.
		 * Remember, must NEVER call bbs_log within a child, it will deadlock waiting for the log lock. */
		return;
	}

	/*
	 * We could get a SIGWINCH for a few reasons, but mainly:
	 * 1) Foreground console (STDIN) is running and was resized. This is okay.
	 * 2) The BBS made an TIOCSWINSZ ioctl call improperly,
	 *    i.e. to the wrong PTY file descriptor or when it shouldn't have.
	 *    This is not okay. It means that a node resizing its terminal
	 *    resulted in this process getting a SIGWINCH, which means if there is
	 *    a foreground console, when we exit, the terminal dimensions for the sysop
	 *    will be the dimensions of the node that resized its terminal. Whoops!
	 */

	/* XXX Calling bbs_log is not really safe to do in a signal handler */
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws)) {
		bbs_error("ioctl failed: %s\n", strerror(errno));
	}
	if (option_nofork) {
		bbs_debug(3, "Caught SIGWINCH: %d cols and %d rows (x: %d, y: %d)\n", ws.ws_col, ws.ws_row, ws.ws_xpixel, ws.ws_ypixel);
	} else {
		/* We got a SIGWINCH with no foreground terminal? (If this happens, it's bad, see note above) */
		bbs_warning("Caught SIGWINCH: %d cols and %d rows (x: %d, y: %d)\n", ws.ws_col, ws.ws_row, ws.ws_xpixel, ws.ws_ypixel);
	}
}

static struct sigaction sigwinch_handler = {
	.sa_handler = __sigwinch_handler,
};

static void __sig_catch_and_release_handler(int num)
{
	bbs_debug(3, "Received signal %d (%s)\n", num, bbs_signal_name(num));
}

static struct sigaction sig_catch_and_release_handler = {
	.sa_handler = __sig_catch_and_release_handler,
};

static void __sigusr2_handler(int num)
{
	UNUSED(num);

	/* Execute reload handlers */
#define ALL_RELOAD_HANDLER_INDICATOR "*"
	bbs_request_module_unload(ALL_RELOAD_HANDLER_INDICATOR, 1); /* The 2nd argument doesn't matter in this case */
}

static struct sigaction sigusr2_handler = {
	.sa_handler = __sigusr2_handler,
};

/*!
 * \brief Request BBS shutdown
 * \param type
 * \retval 0 on success, -1 on failure
 */
static int bbs_request_shutdown(enum shutdown_type type)
{
	bbs_debug(5, "Requesting shutdown\n");
	bbs_mutex_lock(&sig_lock);
	shutdown_type = type;
	want_shutdown = 1;
	if (bbs_alertpipe_write(sig_alert_pipe)) {
		bbs_error("write() failed: %s\n", strerror(errno));
		bbs_mutex_unlock(&sig_lock);
		return -1;
	}
	bbs_mutex_unlock(&sig_lock);
	return 0;
}

static char task_modulename[64] = "";
static int task_reload;

void bbs_request_module_unload(const char *name, int reload)
{
	bbs_mutex_lock(&sig_lock);
	task_reload = reload;
	/* If we're unloading the sysop module, name won't be
	 * valid memory once we unload it. */
	safe_strncpy(task_modulename, name, sizeof(task_modulename));
	if (bbs_alertpipe_write(sig_alert_pipe)) {
		bbs_error("write() failed: %s\n", strerror(errno));
	}
	bbs_mutex_unlock(&sig_lock);
}

int bbs_safe_sleep(int ms)
{
	bbs_soft_assert(ms > 0);
	if (bbs_is_shutting_down()) {
		/* If we are already shutting down,
		 * immediately return activity,
		 * as the alertpipe would have already triggered. */
		bbs_debug(3, "Shutdown already in progress\n");
		return 1;
	}
	return bbs_poll(sig_alert_pipe[0], ms);
}

int bbs_safe_sleep_interrupt(int ms)
{
	bbs_soft_assert(ms > 0);
	if (bbs_is_shutting_down()) {
		/* If we are already shutting down,
		 * immediately return activity,
		 * as the alertpipe would have already triggered. */
		bbs_debug(3, "Shutdown already in progress\n");
		return 1;
	}
	return bbs_poll_interrupt(sig_alert_pipe[0], ms);
}

static int cli_halt(struct bbs_cli_args *a)
{
	UNUSED(a);
	return bbs_request_shutdown(SHUTDOWN_HALT);
}

static int cli_shutdown(struct bbs_cli_args *a)
{
	UNUSED(a);
	return bbs_request_shutdown(SHUTDOWN_NORMAL);
}

static int cli_restart(struct bbs_cli_args *a)
{
	UNUSED(a);
	return bbs_request_shutdown(SHUTDOWN_RESTART);
}

static struct bbs_cli_entry cli_commands_bbs[] = {
	BBS_CLI_COMMAND(cli_shutdown, "shutdown", 1, "Shut down the BBS (no confirmation). Also ^C", NULL),
	BBS_CLI_COMMAND(cli_restart, "restart", 1, "Restart the BBS", NULL),
	BBS_CLI_COMMAND(cli_halt, "halt", 1, "Immediately (uncleanly) halt the BBS (DANGER!)", NULL),
};

static void *monitor_sig_flags(void *unused)
{
	UNUSED(unused);

	for (;;) {
		if (bbs_alertpipe_poll(sig_alert_pipe, -1) <= 0) {
			break;
		}
		bbs_mutex_lock(&sig_lock);
		bbs_alertpipe_read(sig_alert_pipe);
		if (task_modulename[0]) {
			if (!strcmp(task_modulename, ALL_RELOAD_HANDLER_INDICATOR)) {
				/* Reload configuration
				 * Note: This does NOT reload all modules,
				 * it only executes all registered reload handlers
				 * to reload the configuration in those modules. */
				bbs_debug(1, "Asynchronously executing all reload handlers\n");
				bbs_reload(NULL, -1);
			} else {
				/* Reload a specific module */
				bbs_debug(1, "Asynchronously %s module '%s'\n", task_reload ? "reloading" : "unloading", task_modulename);
				task_reload ? bbs_module_reload(task_modulename, 0) : bbs_module_unload(task_modulename);
			}
			task_modulename[0] = '\0';
			bbs_mutex_unlock(&sig_lock);
		} else if (want_shutdown) {
			bbs_mutex_unlock(&sig_lock);
			bbs_debug(1, "Shutdown requested\n");
			bbs_shutdown();
			break;
		} else {
			/* Shouldn't ever happen... */
			bbs_mutex_unlock(&sig_lock);
			bbs_warning("Received unactionable activity on sig alert pipe?\n");
		}
	}

	/* Restore previous terminal title */
	printf(TERM_TITLE_RESTORE_FMT);
	fflush(stdout);
	return NULL;
}

static void bbs_atexit(void)
{
	/* Detect unclean exit */
	if (!shutting_down) {
		/* Logger is still up, we never shut down */
		bbs_error("BBS quit unexpectedly, without shutdown requested\n");
	}
	if (option_nofork) {
		/* If shutting_down is TRUE, logger has been shut down, can't use any BBS logging functions */
		printf("BBS has exited\n");
	}
}

static long bbs_is_running(void)
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
		return 0; /* PID file doesn't exist? No way to tell. */
	}
	if (fscanf(f, "%ld", &file_pid) == EOF) {
		bbs_debug(5, "PID file %s does not contain a PID\n", BBS_PID_FILE);
		fclose(f);
		return 0;
	}
	fclose(f);
	if (!file_pid) {
		bbs_warning("Failed to parse PID from %s\n", BBS_PID_FILE);
		return 0;
	}

	/* Check if such a process is running */
	snprintf(procpath, sizeof(procpath), "/proc/%ld", file_pid);
	if (stat(procpath, &st) == -1 && errno == ENOENT) {
		/* Process doesn't exist */
		bbs_debug(5, "Process %ld no longer exists\n", file_pid);
		return 0;
	}
	return file_pid;
}

/*! \brief Blindly write the PID file */
static int write_pid(void)
{
	FILE *f;

	unlink(BBS_PID_FILE);
	f = fopen(BBS_PID_FILE, "w");
	if (!f) {
		bbs_error("Unable to open pid file '%s': %s\n", BBS_PID_FILE, strerror(errno));
		return -1;
	}
	fprintf(f, "%ld\n", (long) bbs_pid);
	fclose(f);
	return 0;
}

static int load_config(void)
{
	int tmp;
	struct bbs_config *cfg = bbs_config_load("bbs.conf", 0);

	/* No reload handler is registered for bbs.conf settings,
	 * since these settings won't have any impact after
	 * the BBS is started (technically, we could set the
	 * dumpcore setting later, but it's not worth it). */

	if (!cfg) {
		return 0;
	}

	/* Run user/group */
	bbs_config_val_set_dstr(cfg, "run", "user", &runuser);
	bbs_config_val_set_dstr(cfg, "run", "group", &rungroup);
	bbs_config_val_set_true(cfg, "run", "dumpcore", &option_dumpcore);

	/* Logger options */
	if (!bbs_config_val_set_int(cfg, "logger", "verbose", &tmp)) {
		bbs_set_verbose(tmp);
		fprintf(stderr, "Verbose level set to %d\n", tmp);
	}
	if (!bbs_config_val_set_int(cfg, "logger", "debug", &tmp)) {
		bbs_set_debug(tmp);
		fprintf(stderr, "Debug level set to %d\n", tmp);
	}
	if (!bbs_config_val_set_int(cfg, "logger", "logfile_debug", &tmp)) {
		max_logfile_debug_level = tmp;
		fprintf(stderr, "Max log file debug level set to %d\n", max_logfile_debug_level);
	}

	return 0;
}

static struct sigaction ignore_sig_handler = {
	.sa_handler = SIG_IGN,
};

static void set_signals(void)
{
	/* Use sigaction instead of signal, since it's the more modern and well-behaving API: */
	sigaction(SIGINT, &sigint_handler, NULL);
	sigaction(SIGTERM, &sigint_handler, NULL); /* Almost identical handling, but without a confirmation */
	if (!option_nofork || !isatty(STDOUT_FILENO)) {
		/* SIGHUP is conventionally used by daemon processes to reload their configuration,
		 * since they don't typically need to deal with TTYs closing.
		 *
		 * If the BBS is run with a foreground console though, then it may make sense to
		 * allow SIGHUP to be processed per its prescribed meaning and terminate the BBS.
		 *
		 * However, not all instances of the BBS running in the foreground mean that
		 * we should process SIGHUP. For example, under systemd, the BBS is run in the
		 * foreground (not daemonized), but we won't have a TTY available,
		 * so it doesn't make sense to process SIGHUP in this case, either.
		 *
		 * For both of these scenarios, we explicitly ignore SIGHUP using SIG_IGN.
		 * Note that installing SIG_IGN (via &ignore_sig_handler) is critically important here.
		 * Per sigaction(2), on execve, handled signals are reset to the default,
		 * while ignored signals are left unchanged.
		 *
		 * Using SIG_IGN for SIGHUP avoids an issue with BBS restarts where
		 * as soon as we execvp to restart, the BBS is killed with a SIGHUP signal.
		 * Previously, this would occur sporadically (and only when the BBS is daemonized).
		 * (stracing the BBS prior to the restart would make this happen consistently.)
		 * With SIG_IGN, the signal is reliably ignored, including across restarts.
		 *
		 * Because we ignore SIGHUP, in some cases even while running as a service,
		 * we can't use SIGHUP for its alternate conventional use of triggering a reload.
		 * Instead, we use SIGUSR2 for that. This allows us to safely ignore SIGHUP
		 * when we don't need to receive it from a foreground console disconnect.
		 */
		sigaction(SIGHUP, &ignore_sig_handler, NULL);
	}
	sigaction(SIGWINCH, &sigwinch_handler, NULL);
	sigaction(SIGURG, &sig_catch_and_release_handler, NULL);

	/* By default, if we use pthread_kill to try to send SIGUSR1 to a thread,
	 * it will terminate the entire BBS.
	 * Installing this dummy signal handler that does nothing prevents that,
	 * but still allows system calls to be interrupted, as desired. */
	sigaction(SIGUSR1, &sig_catch_and_release_handler, NULL);

	sigaction(SIGUSR2, &sigusr2_handler, NULL); /* Used for reload, since SIGHUP is ignored */
	sigaction(SIGPIPE, &ignore_sig_handler, NULL);
}

/*!
 * \brief Called for fatal startup errors.
 * If starting daemon, bbs_log messages wouldn't go to STDOUT/STDERR, do so explicitly so something is output.
 */
#define startup_error(fmt, ...) \
	bbs_error(fmt, __VA_ARGS__); \
	if (!option_nofork) { \
		fprintf(stderr, fmt, __VA_ARGS__); \
	}

int main(int argc, char *argv[])
{
	if (parse_options_pre(argc, argv) || load_config() || parse_options(argc, argv) || run_init(argc, argv) || bbs_log_init(option_nofork)) {
		free_options();
		exit(EXIT_FAILURE);
	}

	if (!config_dir) {
		long current_pid;
		/* If BBS already running, don't start another one. */
		if ((current_pid = bbs_is_running())) {
			startup_error("BBS already running on PID %ld. Use rsysop for remote sysop console.\n", current_pid);
			cleanup();
			exit(EXIT_FAILURE);
		}
	}

	/* This needs to remain as high up in the initial start up as possible.
	 * daemon causes a fork to occur, which has all sorts of unintended
	 * consequences for things that interact with threads. This call *must*
	 * occur before anything spawns or manipulates thread related primitives. */
	bbs_debug(1, "Starting BBS on PID %d\n", bbs_pid);
	if (!option_nofork && daemon(1, 0) < 0) {
		startup_error("daemon() failed: %s\n", strerror(errno));
		cleanup();
		exit(EXIT_FAILURE);
	}

	/* At this point everything has been forked successfully,
	 * and we have determined that the BBS isn't already running.
	 * We are now multi-thread safe. */

	bbs_pid = getpid(); /* If we daemonized, the PID changed. */
	if (write_pid()) {
		bbs_shutdown();
		exit(EXIT_FAILURE);
	}

	bbs_debug(1, "Initializing BBS on PID %d, running as user '%s' and group '%s', using '%s'\n", bbs_pid, S_IF(runuser), S_IF(rungroup), bbs_config_dir());
	bbs_start_time = time(NULL);

	if (argc > 0 && !strstr(argv[0], BBS_NAME)) {
		/* argv[0] is typically the program name, by convention.
		 * If it's something else, then that is certainly odd.
		 * Caller might mean to be running the BBS under something else (e.g. valgrind) */
		bbs_warning("LBBS argv[0] is %s - did you mean to execute a different program?\n", S_IF(argv[0]));
	}

	/* Seed the random number generators */
	srand((unsigned int) time(NULL));
	srandom((unsigned int) time(NULL));

	/* Initialize alert pipe before installing any signal handlers. */
	bbs_mutex_init(&sig_lock, NULL);
	if (bbs_alertpipe_create(sig_alert_pipe)) {
		bbs_shutdown();
		exit(EXIT_FAILURE);
	}
	set_signals();

#define CHECK_INIT(x) if ((x)) { bbs_shutdown(); exit(EXIT_FAILURE); }

	bbs_verb(1, "Initializing BBS\n");
	CHECK_INIT(atexit(bbs_atexit));
	CHECK_INIT(bbs_cli_load());
	CHECK_INIT(bbs_cli_register_multiple(cli_commands_bbs));
	CHECK_INIT(bbs_init_os_info());
	CHECK_INIT(bbs_fd_init());
	CHECK_INIT(bbs_vars_init());
	CHECK_INIT(bbs_init_threads());
	CHECK_INIT(bbs_init_system());
	CHECK_INIT(bbs_transfer_config_load());
	CHECK_INIT(bbs_mail_init());
	CHECK_INIT(bbs_init_auth());
	CHECK_INIT(bbs_groups_init());
	CHECK_INIT(bbs_load_menus(0));
	CHECK_INIT(bbs_init_menu_handlers());
	CHECK_INIT(bbs_load_nodes());
	/* Most of these here are purely registering sysop CLI commands */
	CHECK_INIT(bbs_io_init());
	CHECK_INIT(bbs_init_nets());
	CHECK_INIT(bbs_init_doors());
	CHECK_INIT(bbs_init_tests());

	if (!is_root()) {
		check_cap(0); /* Check before modules load, which may try to bind to privileged ports. */
	}
	CHECK_INIT(load_modules());

#ifdef SILLY_OPTIMIZATIONS
	/* Many modules (and the core) don't free their configs, and if a module never rereads the config,
	 * this memory is sitting around for no reason. Free all the configs after startup finishes,
	 * any rereads will require a new parse the first time, but after that, it will linger around.
	 * This is a minor optimization to free a small amount of memory that may never be needed again.
	 * XXX config.c returns configs (not locked) to modules, reference counting should be utilized
	 * to prevent destroying a config that may be in use (previously not an issue, since only done at shutdown)
	 * Ideally, if modules did this themselves (explicitly destroyed the config), that would be race free.
	 */
	bbs_configs_free_all();
#endif

	fully_started = 1;
	bbs_verb(1, "%s\n", COLOR(COLOR_SUCCESS) "BBS is fully started" COLOR_RESET);
	bbs_event_dispatch(NULL, EVENT_STARTUP);
	startup_checks(); /* Static stuff in this file, doesn't use a startup callback */

	/* Run any callbacks registered during startup, now that we're fully started. */
	bbs_run_startup_callbacks();

	/* Release excess memory used by startup */
	bbs_malloc_trim();

	if (is_root() && !runuser) {
		bbs_warning("BBS is running as root. This may compromise the security of your system.\n");
	}

	if (option_run_unit_tests) {
		bbs_run_tests(STDOUT_FILENO);
	}

	/* Stall until a quit signal is given */
	monitor_sig_flags(NULL);
	return 0;
}
