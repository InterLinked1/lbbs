#!/bin/sh

set -e

# $1 = optional, specific test to run
TEST=$1

# Execute all of the tests, and if a core is dumped,
# process it and cat the backtrace. Useful for CI tests,
# so we can see what happened during a run.

# Note: This script assumes a Debian-based system

# Process core dump, if there was one
handle_failure() {
	if [ -f tests/core ]; then
		# Found a core dump? Process it
		scripts/bbs_dumper.sh postdump tests/core
		cat full.txt
	fi
	# which may not be installed, so don't check if valgrind is installed.
	# Instead, we can use existence of log file
	if [ -f /tmp/test_lbbs/valgrind.log ]; then
		# Dumping the log file here is redundant, since test.c itself already did that
		valgrind --version
	fi
	if [ -f /var/log/lbbs/fd.log ]; then
		printf "Displaying fd log\n"
		cat /var/log/lbbs/fd.log
		# If we are debugging file descriptors for some reason, also give it a whirl under strace
		if [ "$TEST" != "" ]; then
			tests/test -t$TEST -ddddddddd -DDDDDDDDDD -x -s
			printf "Displaying strace log\n"
			cat /tmp/test_lbbs/strace.log
		fi
	fi
	exit 1 # If tests exited nonzero, we need to actually return nonzero as well
}

install_valgrind() {
	# It's possible which won't be installed, in which case this will always fail.
	# Worst case, we run the command to install valgrind even if it's already installed.
	if which "valgrind" > /dev/null; then
		return
	fi
	PACKAGES="valgrind strace"
	# Assume the package manager has already been updated if needed.
	OS=$( uname -s )
	OS_DIST_INFO="(lsb_release -ds || cat /etc/*release || uname -om ) 2>/dev/null | head -n1 | cut -d'=' -f2"
	OS_DIST_INFO=$(eval "$OS_DIST_INFO" | tr -d '"')
	if [ -f /etc/debian_version ]; then
		apt-get install -y $PACKAGES
	elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
		dnf install -y $PACKAGES
	elif [ "$OS_DIST_INFO" = "SLES" ] || [ "$OS_DIST_INFO" = "openSUSE Tumbleweed" ]; then
		zypper install --no-confirm $PACKAGES
	elif [ -r /etc/arch-release ]; then
		pacman -Sy --noconfirm $PACKAGES
		export DEBUGINFOD_URLS="https://debuginfod.archlinux.org"
	elif [ -r /etc/alpine-release ]; then
		apk add $PACKAGES
	elif [ "$OS" = "FreeBSD" ]; then
		pkg install -y $PACKAGES
	else
		printf "Could not automatically install valgrind (unsupported distro?)\n" "$OS" >&2 # to stderr
		return
	fi
	# If we just installed valgrind, go ahead and rebuild test.c
	# This is because test.c was built before valgrind existed,
	# and thus it wasn't built with support for the -s option, even if it's supported
	# with the version we just installed
	touch tests/test.c
	make tests
}

if [ "$TEST" = "" ]; then # run all tests
	# First, do one pass without -e, in case there's a failure, it'll be caught much more quickly
	tests/test -dddddddddd -DDDDDDDDDD -x || handle_failure
	# If all good so far, repeat but under valgrind
	install_valgrind
	tests/test -dddddddddd -DDDDDDDDDD -ex || handle_failure
else
	# If we are only running a specific test, don't bother with the first pass, just run directly with the -e option (valgrind)
	install_valgrind
	tests/test -t$TEST -ddddddddd -DDDDDDDDDD -ex || handle_failure
fi

valgrind --version

if [ "$IGNORE_LIBBFD_MEMORY_LEAK_BUGS" != "1" ]; then
	# Primarily intended for test_unit, since this includes the backtrace test in mod_test_backtrace:
	# If this rule was used in a suppression, the test itself will pass since that is an exception,
	# but that means we have a buggy version of libbfd.
	! grep "BACKTRACE_libbfd_bfd_elf_find_nearest_line" /tmp/test_lbbs/valgrind.log
else
	# Inspect if it happened, but don't fail if it didn't leak (which would only show if test_unit was the last test run, anyways)
	grep "BACKTRACE_libbfd_bfd_elf_find_nearest_line" /tmp/test_lbbs/valgrind.log || :
fi
