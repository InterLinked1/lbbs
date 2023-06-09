#!/bin/sh

# This script can be used to compile libetpan from source.
# However, as of this writing, the package version also suffices.

cd /usr/local/src
git clone https://github.com/dinhvh/libetpan.git
cd libetpan
wget "https://github.com/dinhvh/libetpan/commit/5ea630e6482422ffa2e26b9afe5fb47a9eb673a2.diff"
git apply "5ea630e6482422ffa2e26b9afe5fb47a9eb673a2.diff"
./autogen.sh --with-poll
make
make install