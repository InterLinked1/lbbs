#!/bin/sh

set -e

# $1 = optional, specific test to run

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
		cat /tmp/test_lbbs/valgrind.log
		valgrind --version
	fi
	exit 1 # If tests exited nonzero, we need to actually return nonzero as well
}

install_valgrind() {
	# It's possible which won't be installed, in which case this will always fail.
	# Worst case, we run the command to install valgrind even if it's already installed.
	if which "valgrind" > /dev/null; then
		return
	fi
	# Assume the package manager has already been updated if needed.
	OS=$( uname -s )
	OS_DIST_INFO="(lsb_release -ds || cat /etc/*release || uname -om ) 2>/dev/null | head -n1 | cut -d'=' -f2"
	OS_DIST_INFO=$(eval "$OS_DIST_INFO" | tr -d '"')
	if [ -f /etc/debian_version ]; then
		apt-get install -y valgrind
	elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
		dnf install -y valgrind
	elif [ "$OS_DIST_INFO" = "SLES" ] || [ "$OS_DIST_INFO" = "openSUSE Tumbleweed" ]; then
		zypper install --no-confirm valgrind
	elif [ -r /etc/arch-release ]; then
		pacman -Sy --noconfirm valgrind
		export DEBUGINFOD_URLS="https://debuginfod.archlinux.org"
	elif [ -r /etc/alpine-release ]; then
		apk add valgrind
		apk upgrade --available musl
	elif [ "$OS" = "FreeBSD" ]; then
		pkg install -y valgrind
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

if [ "$1" = "" ]; then # run all tests
	tests/test -ddddddddd -DDDDDDDDDD -x || handle_failure
	install_valgrind
	tests/test -ddddddddd -DDDDDDDDDD -ex || handle_failure
else
	# If we are only running a specific test, don't bother with the first pass, just run directly with the -e option (valgrind)
	install_valgrind
	tests/test -t$1 -ddddddddd -DDDDDDDDDD -ex || handle_failure
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
