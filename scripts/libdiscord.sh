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
	make clean
fi
# Use the dev branch for latest bug fixes
git checkout dev
printf "Compiling libdiscord\n"
CFLAGS="-fPIC" make shared
make install
ldconfig
