#!/bin/sh

# Install libdiscord as a shared library

set -e

# libcurl 7.86.0 or higher is required
curlv=$( curl-config --version | cut -d' ' -f2 | tr -d '\n' )
if [ $? -eq 0 ]; then
	printf "$curlv\n7.86.0" | sort -V | head -n1 | grep -qF 7.86.0 && ret=$? || ret=$? # capture failure since we have set -e
	if [ $ret -ne 0 ]; then
		printf "libcurl $curlv (< 7.86.0) is currently installed, need to build from source\n"
		CURL_SRC_VER="8.13.0"
	else
		printf "libcurl $curlv (>= 7.86.0) is currently installed, package okay\n"
	fi
else
	printf "libcurl is not currently installed?\n"
	CURL_SRC_VER="8.13.0"
fi

if [ "$CURL_SRC_VER" != "" ]; then
	# Based on https://github.com/Cogmasters/concord/commit/04027977b6e1fe06e2d1ff589edb425223197046
	cd /usr/local/src
	if [ -f curl-${CURL_SRC_VER}.tar.gz ]; then
		rm curl-${CURL_SRC_VER}.tar.gz
	fi
	wget https://curl.se/download/curl-${CURL_SRC_VER}.tar.gz
	tar -xzf curl-${CURL_SRC_VER}.tar.gz
	# libpsl doesn't seem to be available on all distros (e.g. Rocky Linux 8.9)
	# https://daniel.haxx.se/blog/2024/01/10/psl-in-curl/
	cd curl-${CURL_SRC_VER} && ./configure --with-openssl --enable-websockets --without-libpsl
	make -j$(nproc)
	make install
	ldconfig
fi

cd /usr/local/src
if [ ! -d concord ]; then
	git clone https://github.com/cogmasters/concord.git
	cd concord
else
	cd concord
	git stash
	git pull
	make clean
fi
# Use the dev branch for latest bug fixes
git checkout dev
printf "Compiling libdiscord\n"
CFLAGS="-fPIC" make shared
make install
if [ -f /etc/alpine-release ]; then
	ldconfig /etc/ld.so.conf.d
else
	ldconfig
fi
