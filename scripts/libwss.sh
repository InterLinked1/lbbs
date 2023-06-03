#!/bin/sh

set -e
cd /usr/local/src
if [ ! -d libwss ]; then
	git clone https://github.com/InterLinked1/libwss.git
	cd libwss
else
	cd libwss
	git stash
	git pull
fi
printf "Compiling libwss\n"
make
make install
