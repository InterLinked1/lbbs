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
make
make install
