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
 * \brief Isolated root environment (e.g. container)
 *
 * This sample program demonstrates how to execute a "container"
 * in a separate namespace.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <sched.h> /* use clone */
#include <syscall.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sched.h>

#ifndef pivot_root
#define pivot_root(new, old) syscall(SYS_pivot_root, new, old)
#endif

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];
static int map_pipe[2];

static int update_map(const char *mapping, const char *map_file, int map_len)
{
	int fd;

	fd = open(map_file, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open(%s) failed: %s\n", map_file, strerror(errno));
		return -1;
	}
	if (write(fd, mapping, map_len) != map_len) {
		fprintf(stderr, "write failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int proc_setgroups_write(pid_t pid, const char *str, int str_len)
{
	char setgroups_path[PATH_MAX];
	int fd;

	snprintf(setgroups_path, sizeof(setgroups_path), "/proc/%ld/setgroups", (long) pid);
	fd = open(setgroups_path, O_RDWR);
	if (fd < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "open failed: %s\n", strerror(errno));
			return -1;
		}
		return 0;
	}

	if (write(fd, str, str_len) != str_len) {
		fprintf(stderr, "write failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static const char *hostname = "container";

static int child_exec(void *varg)
{
	char c;
	int res;
	struct utsname uts;
	char *argv[] = { "/bin/bash", NULL };

	(void) varg;

	/* Wait until parent has updated mappings. */
	close(map_pipe[1]);
	res = read(map_pipe[0], &c, 1);
	if (res != 0) {
		fprintf(stderr, "read returned %d? (%s)\n", res, strerror(errno));
		exit(errno);
	}

	/* Change hostname in child's UTS namespace */
	if (sethostname(hostname, strlen(hostname)) < 0) {
		fprintf(stderr, "sethostname failed: %s\n", strerror(errno));
		exit(errno);
	}

	if (uname(&uts) < 0) {
		fprintf(stderr, "uname failed: %s\n", strerror(errno));
		exit(errno);
	}

	fprintf(stderr, "PID = %d, PPID = %d, hostname = %s\n", getpid(), getppid(), uts.nodename);

	/* Set mount points */
	if (mount("./rootfs", "./rootfs", "bind", MS_BIND | MS_REC, "")) {
		fprintf(stderr, "mount failed: %s\n", strerror(errno));
		exit(errno);
	}

	/* If ./rootfs/.old doesn't yet exist, create it in the rootfs */
	if (eaccess("./rootfs/.old", R_OK) && mkdir("./rootfs/.old", 0700)) {
		fprintf(stderr, "mkdir failed: %s\n", strerror(errno));
		exit(errno);
	}

	if (pivot_root("./rootfs", "./rootfs/.old")) {
		fprintf(stderr, "pivot_root failed: %s\n", strerror(errno));
		exit(errno);
	}
	if (mount("proc", "/proc", "proc", 0, NULL)) {
		fprintf(stderr, "mount failed: %s\n", strerror(errno));
		exit(errno);
	}

	chdir("/"); /* Change to new root since we changed it */

	if (umount2("/.old", MNT_DETACH)) {
		fprintf(stderr, "umount2 failed: %s\n", strerror(errno));
		exit(errno);
	}

	execvp(argv[0], argv);
	fprintf(stderr, "exec failed: %s\n", strerror(errno));
	exit(errno);
}

static int setup_namespace(pid_t pid)
{
	char map_buf[100];
	char map_path[PATH_MAX];
	char *uid_map = map_buf, *gid_map = map_buf;
	int map_len;

	snprintf(map_path, sizeof(map_path), "/proc/%d/uid_map", pid);
	map_len = snprintf(map_buf, sizeof(map_buf), "0 %ld 1", (long) getuid());
	if (update_map(uid_map, map_path, map_len)) {
		return -1;
	}

	proc_setgroups_write(pid, "deny", strlen("deny"));

	snprintf(map_path, sizeof(map_path), "/proc/%d/gid_map", pid);
	map_len = snprintf(map_buf, sizeof(map_buf), "0 %ld 1", (long) getgid());
    if (update_map(gid_map, map_path, map_len)) {
		return -1;
	}

	close(map_pipe[1]); /* Close write end of pipe, to signal that UID/GID maps have been updated. */
	close(map_pipe[0]);
	return 0;
}

int main(int argc, char *argv[])
{
	pid_t child;

	(void) argc;
	(void) argv;

	if (pipe(map_pipe)) {
		fprintf(stderr, "pipe failed: %s\n", strerror(errno));
		return -1;
	}

	child = clone(child_exec, child_stack + STACK_SIZE,
		SIGCHLD | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWUSER,
		argv);
	if (child < 0) {
		fprintf(stderr, "clone failed: %s\n", strerror(errno));
		exit(errno);
	}

	/* Only the parent gets here */
	fprintf(stderr, "Starting on PID %d\n", child);

	if (setup_namespace(child)) {
		exit(EXIT_FAILURE);
	}

	if (waitpid(child, NULL, 0) < 0) {
		fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Process %d has exited\n", child);
	return 0;
}
