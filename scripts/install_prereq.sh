#/bin/sh

set -e

# == Packages
# Debian: apt-get
# Fedora: yum/dnf (RPM)
# openSUSE/SLES: zypper
# FreeBSD: pkg

# -- Core --

# Minimal build essentials: git, make/gcc
PACKAGES_DEBIAN="git build-essential make"
PACKAGES_FEDORA="git gcc wget"
PACKAGES_SUSE="git-core gcc make"
PACKAGES_FREEBSD="git gcc gmake"

# autotools, used by libopenarc, libetpan
PACKAGES_DEBIAN="$PACKAGES_DEBIAN automake pkg-config libtool m4"
PACKAGES_FEDORA="$PACKAGES_FEDORA autoconf libtool"
PACKAGES_SUSE="$PACKAGES_SUSE automake libtool"

PACKAGES_DEBIAN="$PACKAGES_DEBIAN libncurses-dev" # ncurses
PACKAGES_DEBIAN="$PACKAGES_DEBIAN ncurses-base ncurses-term" # full/extended terminal definitions
PACKAGES_FEDORA="$PACKAGES_FEDORA ncurses-devel"
PACKAGES_SUSE="$PACKAGES_SUSE ncurses-devel"

PACKAGES_DEBIAN="$PACKAGES_DEBIAN libcrypt-dev" # crypt_r

# <curl/curl.h> - cURL, OpenSSL variant
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libcurl4-openssl-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libcurl-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libcurl-devel"

# <bfd.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN binutils-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA binutils-devel"
PACKAGES_SUSE="$PACKAGES_SUSE binutils-devel"

# <sys/capability.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libcap-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libcap-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libcap-devel"

# <uuid/uuid.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libuuid1 uuid-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libuuid-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libuuid-devel"

# <bsd/string.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libbsd-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libbsd-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libbsd-devel"

# sz, rz programs for ZMODEM transfers
PACKAGES_DEBIAN="$PACKAGES_DEBIAN lrzsz"
PACKAGES_FEDORA="$PACKAGES_FEDORA lrzsz"
PACKAGES_SUSE="$PACKAGES_SUSE lrzsz"

# <histedit.h>, <readline/history.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libedit-dev libreadline-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libedit-devel readline-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libedit-devel readline-devel"

# hash.c, io_tls: OpenSSL
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libssl-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA openssl-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libopenssl-devel"

# io_compress: zlib
PACKAGES_DEBIAN="$PACKAGES_DEBIAN zlib1g-dev"

# libssh (net_ssh)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libssh-dev"
# net_ssh, which requires objdump to test for symbol existence... thanks a lot, libssh
PACKAGES_DEBIAN="$PACKAGES_DEBIAN binutils" # objdump
PACKAGES_FEDORA="$PACKAGES_FEDORA libssh-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libssh-devel"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD libssh"

# MariaDB (MySQL) dev headers (mod_mysql, mod_mysql_auth)
# mariadb-server is also required to run a local DBMS, but this is not
# required for either compilation or operation.
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libmariadb-dev libmariadb-dev-compat"
PACKAGES_FEDORA="$PACKAGES_FEDORA mariadb-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libmariadb-devel"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD mariadb106-client"

# LMDB (mod_lmdb)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN liblmdb-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA lmdb-devel"
# MISSING: SUSE package
PACKAGES_FREEBSD="$PACKAGES_FREEBSD lmdb"

# <magic.h> (mod_http)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libmagic-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA file-devel"
PACKAGES_SUSE="$PACKAGES_SUSE file-devel"

# OpenDKIM (mod_smtp_filter_dkim)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libopendkim-dev"

# mod_oauth
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libjansson-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA jansson-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libjansson-devel"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD jansson"

# mod_mimeparse
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libglib2.0-dev libgmime-3.0-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA glib2-devel"
PACKAGES_SUSE="$PACKAGES_SUSE glib2-devel gmime-devel"

# mod_smtp_filter_arc
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libmilter-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA sendmail-milter-devel"

# mod_smtp_filter_spf
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libspf2-dev"
# MISSING: RPM package

# mod_smtp_filter_dmarc
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libopendmarc-dev"
# MISSING: RPM package

# mod_sieve
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libsieve2-dev"
# MISSING: RPM package

# mod_webmail (libetpan)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN autoconf"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD autoconf"

# Soft dependencies
# used for bc (executed by 'calc' in door_utils)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN bc"

# used for cal (included in menus.conf sample)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN ncal"

# Actually install required packages
OS=$( uname -s )
if [ -f /etc/os-release ]; then
	. /etc/os-release # Source the variables
fi
if [ -f /etc/debian_version ]; then
	apt-get update
	apt-get install -y $PACKAGES_DEBIAN
elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
	dnf install -y $PACKAGES_FEDORA
elif [ "$ID_LIKE" = "suse" ]; then
	zypper install --no-confirm $PACKAGES_SUSE
elif [ "$OS" = "FreeBSD" ]; then
	pkg update -f
	pkg install -y $PACKAGES_FREEBSD
else
	printf "Could not install %s packages (unsupported distro?)\n" "$OS" >&2 # to stderr
	exit 1
fi

# == Source Install

# libcami (mod_asterisk_ami)
scripts/libcami.sh

# lirc (mod_irc_client)
scripts/lirc.sh

# libdiscord (mod_discord)
scripts/libdiscord.sh

# libwss (net_ws)
scripts/libwss.sh

# libetpan (mod_webmail): the package no longer suffices, since we patch the source.
#PACKAGES_DEBIAN="$PACKAGES_DEBIAN libetpan-dev"
scripts/libetpan.sh

# evergreen (door_evergreen)
scripts/evergreen.sh

# mod_slack (also depends on libwss)
scripts/libslackrtm.sh

# mod_smtp_filter_arc
scripts/libopenarc.sh

# doxygen only:
#PACKAGES_DEBIAN="$PACKAGES_DEBIAN doxygen graphviz"
