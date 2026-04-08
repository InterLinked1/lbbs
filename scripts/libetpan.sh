#!/bin/sh

# This script is used to compile libetpan from source,
# with modifications that are required for LBBS and other software.

set -e

cd /usr/local/src
if [ ! -d libetpan ]; then
	git clone --depth 1 --recursive --shallow-submodule https://github.com/dinhvh/libetpan.git
	cd libetpan
else
	cd libetpan
	git stash
	git pull
	# make clean isn't valid if the directory already exists,
	# but the Makefile hasn't yet been generated
	make clean || git reset --hard origin/master
fi

# Slipstream patches needed for LBBS net_imap functionality
wget "https://github.com/dinhvh/libetpan/commit/5ea630e6482422ffa2e26b9afe5fb47a9eb673a2.diff"
wget "https://github.com/dinhvh/libetpan/commit/4226610e3dc19f58345ae7c5146fa8cf249ca97b.patch"
git apply "5ea630e6482422ffa2e26b9afe5fb47a9eb673a2.diff" # IMAP STATUS=SIZE
git apply "4226610e3dc19f58345ae7c5146fa8cf249ca97b.patch" # SMTP AUTH

# Slipstream other bug fixes, since libetpan is not currently being maintained upstream
# Don't you just love unmaintained open source software?
wget "https://patch-diff.githubusercontent.com/raw/dinhvh/libetpan/pull/447.diff"
git apply 447.diff

./autogen.sh --with-poll > /dev/null || ./autogen.sh --with-poll

ostype=$( uname -o )
printf "OSTYPE: %s\n" "$ostype"
MAKE=make
if [ "$ostype" = "FreeBSD" ]; then
	printf "FreeBSD detected\n"
	MAKE=gmake
fi

# libetpan's compilation is quite verbose, and full of warnings we can't do anything about since it's not being maintained
# Suppress most output unless something goes wrong
$MAKE -j$(nproc) >/dev/null 2>&1 || $MAKE # Quiet, but show errors on failure
$MAKE install
