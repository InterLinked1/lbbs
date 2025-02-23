#!/bin/sh

set -e

OS=$( uname -s )
MAKE=make
if [ "$OS" = "FreeBSD" ]; then
	MAKE=gmake
fi

cd /usr/local/src
if [ ! -d evergreen ]; then
	git clone https://github.com/InterLinked1/evergreen.git
	cd evergreen
else
	cd evergreen
	git stash
	git pull
fi
$MAKE
$MAKE install
