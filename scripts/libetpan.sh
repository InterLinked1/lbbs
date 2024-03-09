#!/bin/sh

# This script is used to compile libetpan from source,
# with modifications that are required for LBBS and other software.

set -e

cd /usr/local/src
if [ ! -d libetpan ]; then
	git clone https://github.com/dinhvh/libetpan.git
	cd libetpan
else
	cd libetpan
	git stash
	git pull
	make clean
fi
wget "https://github.com/dinhvh/libetpan/commit/5ea630e6482422ffa2e26b9afe5fb47a9eb673a2.diff"
wget "https://github.com/dinhvh/libetpan/commit/4226610e3dc19f58345ae7c5146fa8cf249ca97b.patch"
git apply "5ea630e6482422ffa2e26b9afe5fb47a9eb673a2.diff" # IMAP STATUS=SIZE
git apply "4226610e3dc19f58345ae7c5146fa8cf249ca97b.patch" # SMTP AUTH
./autogen.sh --with-poll
make
make install
