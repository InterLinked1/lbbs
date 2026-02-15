#!/bin/sh

# Install libdiscord as a shared library

set -e

# libcurl 8.7.1 or higher is required
mincurlver="8.7.1"
# libcurl 8.18.0 requires OpenSSL 3.0.0, which older systems (e.g. Debian 10/11) will not have, so use 8.17.0 for now since it's good enough anyways
LATEST_CURL_VERSION="8.17.0"

# If on Debian, it may make sense to try to get a suitably up-to-date libcurl from Debian backports first
# This way, we don't need to fight between an older system package and a newer version compiled from source
if [ -d /etc/apt/sources.list ]; then
	# libcurl 8.7.1 or higher is required
	curlv=$( curl-config --version | cut -d' ' -f2 | tr -d '\n' )
	if [ $? -eq 0 ]; then
		printf "$curlv\n$mincurlver" | sort -V | head -n1 | grep -qF $mincurlver && ret=$? || ret=$? # capture failure since we have set -e
		if [ $ret -ne 0 ]; then
			# Installed package is too old, see if backports are available
			if apt-get install -t bookworm-backports; then
				printf "Attempting to install newer version of libcurl from backports (stable version is too old)\n"
				# Without -y, so that the user has to confirm this operation:
				apt-get install -t bookworm-backports curl libcurl4
			else
				printf "libcurl $curlv (< $mincurlver) is currently installed, need to build from source (backports not enabled on this system)\n"
			fi
		fi
	fi
fi

curlv=$( curl-config --version | cut -d' ' -f2 | tr -d '\n' )
if [ $? -eq 0 ]; then
	printf "$curlv\n$mincurlver" | sort -V | head -n1 | grep -qF $mincurlver && ret=$? || ret=$? # capture failure since we have set -e
	if [ $ret -ne 0 ]; then
		printf "libcurl $curlv (< $mincurlver) is currently installed, need to build from source\n"
		CURL_SRC_VER="$LATEST_CURL_VERSION"
	else
		if [ "$FORCE_CURL_REBUILD" = "1" ]; then
			printf "libcurl $curlv (>= $mincurlver) is currently installed, package okay but rebuilding anyways\n"
			CURL_SRC_VER="$LATEST_CURL_VERSION"
		else
			printf "libcurl $curlv (>= $mincurlver) is currently installed, package okay (pass 'FORCE_CURL_REBUILD=1' to rebuild anyways)\n"
		fi
	fi
else
	printf "libcurl is not currently installed?\n"
	CURL_SRC_VER="$LATEST_CURL_VERSION"
fi

if [ "$CURL_SRC_VER" != "" ] || [ "$FORCE_CURL_REBUILD" = "1" ]; then
	# Based on https://github.com/Cogmasters/concord/commit/04027977b6e1fe06e2d1ff589edb425223197046
	cd /usr/local/src
	if [ -f curl-${CURL_SRC_VER}.tar.gz ]; then
		rm curl-${CURL_SRC_VER}.tar.gz
	fi
	wget -q https://curl.se/download/curl-${CURL_SRC_VER}.tar.gz
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
	# Use the dev branch for latest bug fixes
	git checkout dev
else
	cd concord
	git stash
	git checkout dev # need to ensure we're on a branch for git pull to work
	git pull
	make clean
fi

printf "Compiling libdiscord\n"
CFLAGS="-fPIC" make shared -j$(nproc)
make install
if [ -f /etc/alpine-release ]; then
	ldconfig /etc/ld.so.conf.d
else
	ldconfig
fi
