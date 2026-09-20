#!/bin/sh

# This script is used to compile libetpan from source

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

./autogen.sh --with-poll > /dev/null || ./autogen.sh --with-poll

ostype=$( uname -o )
printf "OSTYPE: %s\n" "$ostype"
MAKE=make
if [ "$ostype" = "FreeBSD" ]; then
	printf "FreeBSD detected\n"
	MAKE=gmake
fi

# libetpan's compilation is quite verbose, and full of warnings we can't do anything about
# Suppress most output unless something goes wrong
$MAKE -j$(nproc) >/dev/null 2>&1 || $MAKE # Quiet, but show errors on failure
$MAKE install
