#!/bin/sh

# Install libdiscord as a shared library

set -e

cd /usr/local/src
if [ ! -d concord ]; then
	git clone https://github.com/cogmasters/concord.git
	cd concord
else
	cd concord
	git stash
	git pull
fi
printf "Compiling libdiscord\n"
CFLAGS="-fPIC" make shared
make install
ldconfig
