#!/bin/sh

set -e

# Execute all of the tests, and if a core is dumped,
# process it and cat the backtrace. Useful for CI tests,
# so we can see what happened during a run.

# Note: This script assumes a Debian-based system

# Process core dump, if there was one
handle_failure() {
	# Only continue if there was a core dump
	[ -f tests/core ]
	# Found a core dump? Process it
	scripts/bbs_dumper.sh postdump tests/core
	cat full.txt
	exit 1 # Segfaults resulting a core dump always cause failure
}

tests/test -ddddddddd -DDDDDDDDDD -x || handle_failure
apt-get install -y valgrind
tests/test -ddddddddd -DDDDDDDDDD -ex || handle_failure
