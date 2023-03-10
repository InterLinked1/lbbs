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
#include <linux/limits.h> /* use PATH_MAX */
#include <sys/resource.h> /* use rlimit */
#include <sys/prctl.h> /* use prctl */
#include <grp.h> /* use getgrnam */
#include <pwd.h> /* use getpwnam */
#include <sys/ioctl.h>
#include <sys/capability.h>
#include <linux/capability.h>

#include "include/module.h" /* use load_modules */
#include "include/alertpipe.h"
#include "include/os.h"
#include "include/config.h"
#include "include/menu.h"
#include "include/mail.h"
#include "include/curl.h"
#include "include/auth.h" /* use bbs_num_auth_providers */
#include "include/utils.h" /* use print_time_elapsed, print_days_elapsed */
#include "include/node.h"
#include "include/variables.h"
#include "include/startup.h"
#include "include/tls.h"
#include "include/event.h"

static char *_argv[256];

/* Immutable */
int option_dumpcore = 0; /* extern in bbs.h for backtrace */
int option_nofork = 0;

/* Mutable during runtime */
int option_debug = 0;
int option_verbose = 0;

char *rungroup = NULL, *runuser = NULL, *config_dir = NULL;

static pid_t bbs_pid;

static int bbs_start_time;

static int sig_alert_pipe[2] = { -1, -1 };
static int shutting_down = 0;
static int shutdown_restart = 0;

static pthread_mutex_t sig_lock;

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
		fprintf(stderr, "Unable to access the running directory (%s).  Changing to '/' for compatibility.\n", strerror(errno));
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

static void check_cap(int isroot)
{
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
			fprintf(stderr, "Process lacks CAP_NET_BIND_SERVICE capability and will not be able to bind to privileged ports\n");
		} else {
			bbs_warning("Process lacks CAP_NET_BIND_SERVICE capability and will not be able to bind to privileged ports.\n");
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
		return;
	}
	return;
}

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
			fprintf(stderr, "Unable to chown run directory to %d (%s)\n", (int) pw->pw_uid, runuser);
			return -1;
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
		if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
			fprintf(stderr, "Unable to set the process for core dumps after changing to a non-root user. %s\n", strerror(errno));
			return -1;
		}
	}

	if (set_cwd()) {
		return -1;
	}

	saveopts(argc, argv);
	return 0;
}

int bbs_starttime(void)
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
	int now;

	now = time(NULL);
	print_time_elapsed(bbs_start_time, now, timebuf, sizeof(timebuf));
	print_days_elapsed(bbs_start_time, now, daysbuf, sizeof(daysbuf));

#define VIEW_FMT_D  "%-12s: %d\n"
#define VIEW_FMT_U  "%-12s: %u\n"
#define VIEW_FMT_S  "%-12s: %s\n"
#define VIEW_FMT_SS "%-12s: %s (%s)\n"
	bbs_dprintf(fd, VIEW_FMT_D, "PID", getpid());
	bbs_dprintf(fd, VIEW_FMT_D, "Verbose", option_verbose);
	bbs_dprintf(fd, VIEW_FMT_D, "Debug", option_debug);
	bbs_dprintf(fd, VIEW_FMT_S, "Config Dir", bbs_config_dir());
	bbs_dprintf(fd, VIEW_FMT_S, "Run User", S_IF(runuser));
	bbs_dprintf(fd, VIEW_FMT_S, "Run Group", S_IF(rungroup));
	bbs_dprintf(fd, VIEW_FMT_S, "Dump Core", BBS_YN(option_dumpcore));
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
	printf("  -c        Do not fork daemon\n");
	printf("  -C        Specify alternate configuration directory\n");
	printf("  -g        Dump core on crash\n");
	printf("  -G        Specify run group\n");
	printf("  -g        Dump core on crash\n");
	printf("  -h        Display this help and exit\n");
	printf("  -U        Specify run user\n");
	printf("  -V        Display version number and exit\n");
	printf("  -?        Display this help and exit\n");
}

static const char *getopt_settings = "?cC:dG:ghU:v";

static int parse_options_pre(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case 'C':
			/* Affects what config we load in load_config, so do before that */
			free_if(config_dir);
			config_dir = strdup(optarg);
			break;
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
			free_if(rungroup); /* If specified by config, override */
			rungroup = strdup(optarg);
			break;
		case 'U':
			free_if(runuser); /* If specified by config, override */
			runuser = strdup(optarg);
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

int bbs_is_shutting_down(void)
{
	return shutting_down;
}

static void cleanup(void)
{
	/* Close alertpipe */
	bbs_alertpipe_close(sig_alert_pipe);

	/* Shutdown logging last. */
	if (shutdown_restart) {
		bbs_verb(2, "BBS is now restarting\n");
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
	if (shutdown_restart) {
		int i;
		/* Mark all file descriptors for closing on exec */
		for (i = 3; i < 32768; i++) {
			fcntl(i, F_SETFD, FD_CLOEXEC);
		}
		/* Note that exec preserves PIDs: the restarted BBS will have the same PID as the old one. */
		execvp(_argv[0], _argv);
	}
}

static void bbs_shutdown(void)
{
	pthread_mutex_lock(&sig_lock);
	if (shutting_down) {
		pthread_mutex_unlock(&sig_lock);
		bbs_error("Active shutdown already in progress\n");
		return;
	}
	shutting_down = 1;
	bbs_event_dispatch(NULL, EVENT_SHUTDOWN);
	if (shutdown_restart == -1) {
		bbs_warning("Halting BBS\n");
		/* Fast exit (halt), don't clean up */
		exit(EXIT_FAILURE);
	}
	bbs_verb(2, "Shutting down BBS\n");
	bbs_node_shutdown_all(shutting_down);
	unload_modules();
	bbs_curl_shutdown(); /* Clean up cURL */
	ssl_server_shutdown(); /* Shut down SSL/TLS */
	login_cache_cleanup(); /* Clean up any remaining cached logins */
	bbs_free_menus(); /* Clean up menus */
	bbs_configs_free_all(); /* Clean up any remaining configs that modules didn't. */
	bbs_vars_cleanup();
	pthread_mutex_unlock(&sig_lock); /* Don't release the lock until the very end */
	pthread_mutex_destroy(&sig_lock);
	cleanup();
}

static struct sigaction ignore_sig_handler = {
	.sa_handler = SIG_IGN,
};

static int *sigint_alert_pipe = NULL;

void bbs_sigint_set_alertpipe(int p[2])
{
	sigint_alert_pipe = p;
}

static void __sigint_handler(int num)
{
	UNUSED(num);

	if (getpid() != bbs_pid) {
		/* __sigint_handler triggered from child process before it was removed in system.c (race condition). Just abort.
		 * Remember, must NEVER call bbs_log within a child, it will deadlock waiting for the log lock. */
		return;
	}

	/* If somebody is subscribed to the SIGINT handler, dispatch it to them and ignore it. */
	/* XXX Currently we allow 1 external subscriber at a time. In theory if we wanted more than one possible,
	 * we could maintain a linked list of subscribers, but that seems like overkill right now,
	 * especially since we're inside a signal handler. */
	if (sigint_alert_pipe) {
		bbs_debug(2, "Got SIGINT with subscriber, skipping built-in handling\n"); /* XXX not safe */
		if (bbs_alertpipe_write(sigint_alert_pipe)) {
			/* Don't use BBS log functions within a signal handler */
			if (option_nofork) {
				fprintf(stderr, "%s: write() failed: %s\n", __FUNCTION__, strerror(errno));
			}
		}
		/* XXX Should we go ahead and automatically remove the subscriber? (set sigint_alert_pipe to NULL?)
		 * Right now we rely on the subscriber to do this manually. If someone forgets, this could be bad. */
	} else if (bbs_alertpipe_write(sig_alert_pipe)) {
		bbs_debug(2, "Got SIGINT, requesting shutdown\n"); /* XXX not safe */
		/* Don't use BBS log functions within a signal handler */
		if (option_nofork) {
			fprintf(stderr, "%s: write() failed: %s\n", __FUNCTION__, strerror(errno));
		}
	}
}

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

void bbs_request_shutdown(int restart)
{
	bbs_debug(5, "Requesting shutdown\n");
	pthread_mutex_lock(&sig_lock);
	shutdown_restart = restart;
	if (bbs_alertpipe_write(sig_alert_pipe)) {
		bbs_error("write() failed: %s\n", strerror(errno));
	}
	pthread_mutex_unlock(&sig_lock);
}

static char task_modulename[64] = "";
static int task_reload;

void bbs_request_module_unload(const char *name, int reload)
{
	pthread_mutex_lock(&sig_lock);
	task_reload = reload;
	/* If we're unloading the sysop module, name won't be
	 * valid memory once we unload it. */
	safe_strncpy(task_modulename, name, sizeof(task_modulename));
	if (bbs_alertpipe_write(sig_alert_pipe)) {
		bbs_error("write() failed: %s\n", strerror(errno));
	}
	pthread_mutex_unlock(&sig_lock);
}

static void *monitor_sig_flags(void *unused)
{
	UNUSED(unused);

	for (;;) {
		if (bbs_alertpipe_poll(sig_alert_pipe) <= 0) {
			break;
		}
		pthread_mutex_lock(&sig_lock);
		bbs_alertpipe_read(sig_alert_pipe);
		if (task_modulename[0]) {
			bbs_debug(1, "Asynchronously %s module '%s'\n", task_reload ? "reloading" : "unloading", task_modulename);
			task_reload ? bbs_module_reload(task_modulename, 0) : bbs_module_unload(task_modulename);
			task_modulename[0] = '\0';
			pthread_mutex_unlock(&sig_lock);
		} else {
			pthread_mutex_unlock(&sig_lock);
			bbs_debug(1, "Shutdown requested\n");
			bbs_shutdown();
			break;
		}
	}

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
	fscanf(f, "%ld", &file_pid);
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
	const char *val;
	struct bbs_config *cfg = bbs_config_load("bbs.conf", 0);

	if (!cfg) {
		return 0;
	}

	/* Run user/group */
	val = bbs_config_val(cfg, "run", "user");
	if (!strlen_zero(val)) {
		runuser = strdup(val);
	}
	val = bbs_config_val(cfg, "run", "group");
	if (!strlen_zero(val)) {
		rungroup = strdup(val);
	}
	val = bbs_config_val(cfg, "run", "dumpcore");
	if (!strlen_zero(val)) {
		option_dumpcore = S_TRUE(val);
	}

	/* Logger options */
	val = bbs_config_val(cfg, "logger", "verbose");
	if (!strlen_zero(val)) {
		bbs_set_verbose(atoi(val));
		fprintf(stderr, "Verbose level set to %d\n", atoi(val));
	}
	val = bbs_config_val(cfg, "logger", "debug");
	if (!strlen_zero(val)) {
		bbs_set_debug(atoi(val));
		fprintf(stderr, "Debug level set to %d\n", atoi(val));
	}

	return 0;
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
	long current_pid;

	if (parse_options_pre(argc, argv) || load_config() || parse_options(argc, argv) || run_init(argc, argv) || bbs_log_init(option_nofork)) {
		free_options();
		exit(EXIT_FAILURE);
	}

	if (!config_dir) {
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

	bbs_debug(1, "Starting BBS on PID %d, running as user '%s' and group '%s', using '%s'\n", bbs_pid, S_IF(runuser), S_IF(rungroup), bbs_config_dir());
	bbs_start_time = time(NULL);

	/* Seed the random number generators */
	srand(time(NULL));
	srandom(time(NULL));

	/* Initialize alert pipe before installing any signal handlers. */
	pthread_mutex_init(&sig_lock, NULL);
	if (bbs_alertpipe_create(sig_alert_pipe)) {
		bbs_shutdown();
		exit(EXIT_FAILURE);
	}
	signal(SIGINT, __sigint_handler);
	signal(SIGTERM, __sigint_handler);
	signal(SIGWINCH, __sigwinch_handler);
	sigaction(SIGPIPE, &ignore_sig_handler, NULL);

#define CHECK_INIT(x) if ((x)) { bbs_shutdown(); exit(EXIT_FAILURE); }

	bbs_verb(1, "Initializing BBS\n");
	CHECK_INIT(atexit(bbs_atexit));
	CHECK_INIT(bbs_init_os_info());
	CHECK_INIT(bbs_vars_init());
	CHECK_INIT(bbs_mail_init());
	CHECK_INIT(bbs_load_menus(0));
	CHECK_INIT(bbs_load_nodes());

	ssl_server_init(); /* If this fails for some reason, that's okay. Other failures will ensue, but this is not fatal. */

	CHECK_INIT(bbs_curl_init());
	if (!is_root()) {
		check_cap(0); /* Check before modules load, which may try to bind to privileged ports. */
	}
	CHECK_INIT(load_modules());

	fully_started = 1;
	bbs_verb(1, "%s\n", COLOR(COLOR_SUCCESS) "BBS is fully started" COLOR_RESET);
	bbs_event_dispatch(NULL, EVENT_STARTUP);

	/* Run any callbacks registered during startup, now that we're fully started. */
	bbs_run_startup_callbacks();

	if (!bbs_num_auth_providers()) {
		bbs_warning("There are no auth providers currently registered. User login will fail.\n");
	}
	if (is_root() && !runuser) {
		bbs_warning("BBS is running as root. This may compromise the security of your system.\n");
	}

	/* Stall until a quit signal is given */
	monitor_sig_flags(NULL);
	return 0;
}
