#!/bin/sh

# This script is used to compile libsieve from source

set -e

cd /usr/local/src
if [ ! -d libsieve ]; then
	git clone --depth 1 https://github.com/InterLinked1/libsieve
	cd libsieve
else
	cd libsieve
	git stash
	git pull
	# make clean isn't valid if the directory already exists,
	# but the Makefile hasn't yet been generated
	make clean || git reset --hard origin/maintenance
fi

autoreconf -i
./configure

ostype=$( uname -o )
printf "OSTYPE: %s\n" "$ostype"
MAKE=make
if [ "$ostype" = "FreeBSD" ]; then
	printf "FreeBSD detected\n"
	MAKE=gmake
fi

$MAKE -j$(nproc) >/dev/null 2>&1 || $MAKE # Quiet, but show errors on failure
$MAKE install
