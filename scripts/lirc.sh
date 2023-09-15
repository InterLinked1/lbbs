#!/bin/sh

# Install lirc as a shared library

set -e

cd /usr/local/src
if [ ! -d lirc ]; then
	git clone https://github.com/InterLinked1/lirc.git
	cd lirc
else
	cd lirc
	git stash
	git pull
fi
printf "Compiling lirc\n"
make library
make install
