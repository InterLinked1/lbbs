#!/bin/sh

# Install experimental Debian package (unlikely to work):
# add-apt-repository "deb http://ftp.debian.org/debian experimental main contrib non-free"
# apt-get update
# apt-get -t experimental install libopenarc-dev

# If that fails, try compiling from source, which should actually work
#if [ $? -ne 0 ]; then
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
	apt-get install -yy make automake pkg-config libtool m4 libbsd-dev libssl-dev libmilter-dev
	aclocal && autoconf && autoreconf --install && automake --add-missing && ./configure && make all
	make install
#fi
