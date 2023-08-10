#!/bin/sh

cd /usr/local/src
if [ -d OpenARC ]; then
	cd OpenARC
	git stash
	git pull
else
	git clone https://github.com/trusteddomainproject/OpenARC.git
	cd OpenARC
fi
git checkout develop # master branch is behind
# https://github.com/trusteddomainproject/OpenARC/issues/118
aclocal && autoconf && autoreconf --install && automake --add-missing && ./configure && make all
make install
