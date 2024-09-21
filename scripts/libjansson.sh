#!/bin/sh

set -e
cd /usr/local/src
wget http://digip.org/jansson/releases/jansson-2.13.1.tar.gz
tar -xvzf jansson-2.13.1.tar.gz
cd jansson-2.13.1
./configure
make
make install
