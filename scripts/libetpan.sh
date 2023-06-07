#!/bin/sh
cd /usr/local/src
git clone https://github.com/dinhvh/libetpan.git
cd libetpan
./autogen.sh --with-poll
make
make install