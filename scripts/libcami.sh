#!/bin/sh

set -e
cd /usr/local/src
if [ ! -d cami ]; then
	git clone https://github.com/InterLinked1/cami.git
	cd cami
else
	cd cami
	git stash
	git pull
fi
ostype=$( uname -o )
printf "OSTYPE: %s\n" "$ostype"
MAKE=make
if [ "$ostype" = "FreeBSD" ]; then
	printf "FreeBSD detected\n"
	MAKE=gmake
fi
$MAKE library
$MAKE install
