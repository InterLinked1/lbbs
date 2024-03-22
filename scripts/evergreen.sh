#!/bin/sh

set -e
cd /usr/local/src
if [ ! -d evergreen ]; then
	git clone https://github.com/InterLinked1/evergreen.git
	cd evergreen
else
	cd evergreen
	git stash
	git pull
fi
make
make install
