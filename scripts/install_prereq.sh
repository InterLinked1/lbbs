#/bin/sh

set -e

# == Packages
# Debian: apt-get
# Fedora: yum/dnf (RPM)
# openSUSE/SLES: zypper
# FreeBSD: pkg

# -- Core --

# Minimal build essentials: git, make/gcc
PACKAGES_DEBIAN="git gcc make wget build-essential"
PACKAGES_FEDORA="git gcc make wget"
PACKAGES_SUSE="git-core gcc make wget gawk"
PACKAGES_ARCH="git gcc make wget"
PACKAGES_FREEBSD="git gcc gmake wget"

# autotools, used by libopenarc, libetpan
PACKAGES_DEBIAN="$PACKAGES_DEBIAN autoconf automake pkg-config libtool m4"
PACKAGES_FEDORA="$PACKAGES_FEDORA autoconf automake pkg-config libtool m4"
PACKAGES_SUSE="$PACKAGES_SUSE autoconf automake pkg-config libtool m4"
PACKAGES_ARCH="$PACKAGES_ARCH autoconf automake pkg-config libtool m4"

PACKAGES_DEBIAN="$PACKAGES_DEBIAN libncurses-dev" # ncurses
PACKAGES_DEBIAN="$PACKAGES_DEBIAN ncurses-base ncurses-term" # full/extended terminal definitions
PACKAGES_FEDORA="$PACKAGES_FEDORA ncurses-devel"
PACKAGES_SUSE="$PACKAGES_SUSE ncurses-devel"
PACKAGES_ARCH="$PACKAGES_ARCH ncurses"

# <curl/curl.h> - cURL, OpenSSL variant
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libcurl4-openssl-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libcurl-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libcurl-devel"
PACKAGES_ARCH="$PACKAGES_ARCH curl"

# <bfd.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN binutils-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA binutils-devel"
PACKAGES_SUSE="$PACKAGES_SUSE binutils-devel"
PACKAGES_ARCH="$PACKAGES_ARCH binutils"

# <sys/capability.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libcap-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libcap-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libcap-devel"
PACKAGES_ARCH="$PACKAGES_ARCH libcap"

# <uuid/uuid.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libuuid1 uuid-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libuuid-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libuuid-devel"
PACKAGES_ARCH="$PACKAGES_ARCH util-linux-libs"

# sz, rz programs for ZMODEM transfers
PACKAGES_DEBIAN="$PACKAGES_DEBIAN lrzsz"
PACKAGES_FEDORA="$PACKAGES_FEDORA lrzsz"
PACKAGES_SUSE="$PACKAGES_SUSE lrzsz"
PACKAGES_ARCH="$PACKAGES_ARCH lrzsz"

# hash.c, io_tls: OpenSSL
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libssl-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA openssl-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libopenssl-devel"
PACKAGES_ARCH="$PACKAGES_ARCH openssl"

# Red Hat identical to Fedora so far
PACKAGES_RHEL="$PACKAGES_FEDORA"

# <histedit.h>, <readline/history.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libedit-dev libreadline-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libedit-devel readline-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libedit-devel readline-devel"
PACKAGES_ARCH="$PACKAGES_ARCH libedit readline"

# <bsd/string.h>
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libbsd-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA libbsd-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libbsd-devel"
PACKAGES_ARCH="$PACKAGES_ARCH libbsd"

# io_compress: zlib
PACKAGES_DEBIAN="$PACKAGES_DEBIAN zlib1g-dev"

# libssh (net_ssh)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libssh-dev"
# net_ssh, which requires objdump to test for symbol existence... thanks a lot, libssh
PACKAGES_DEBIAN="$PACKAGES_DEBIAN binutils" # objdump
PACKAGES_FEDORA="$PACKAGES_FEDORA libssh-devel"
PACKAGES_RHEL="$PACKAGES_RHEL libssh-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libssh-devel"
PACKAGES_ARCH="$PACKAGES_ARCH libssh"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD libssh"

# MariaDB (MySQL) dev headers (mod_mysql, mod_mysql_auth)
# mariadb-server is also required to run a local DBMS, but this is not
# required for either compilation or operation.
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libmariadb-dev libmariadb-dev-compat"
PACKAGES_FEDORA="$PACKAGES_FEDORA mariadb-devel"
# MISSING: mysql-devel for RHEL?
PACKAGES_SUSE="$PACKAGES_SUSE libmariadb-devel"
PACKAGES_ARCH="$PACKAGES_ARCH mariadb-libs"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD mariadb106-client"

# LMDB (mod_lmdb)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN liblmdb-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA lmdb-devel"
# MISSING: SUSE package
PACKAGES_ARCH="$PACKAGES_ARCH lmdb"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD lmdb"

# <magic.h> (mod_http)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libmagic-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA file-devel"
PACKAGES_SUSE="$PACKAGES_SUSE file-devel"
PACKAGES_ARCH="$PACKAGES_ARCH file"

# OpenDKIM (mod_smtp_filter_dkim)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libopendkim-dev"
PACKAGES_ARCH="$PACKAGES_ARCH opendkim"

# mod_oauth
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libjansson-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA jansson-devel"
PACKAGES_SUSE="$PACKAGES_SUSE libjansson-devel"
PACKAGES_ARCH="$PACKAGES_ARCH jansson"
PACKAGES_FREEBSD="$PACKAGES_FREEBSD jansson"

# mod_mimeparse
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libglib2.0-dev libgmime-3.0-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA glib2-devel gmime30-devel"
PACKAGES_RHEL="$PACKAGES_RHEL glib2-devel"
PACKAGES_SUSE="$PACKAGES_SUSE glib2-devel gmime-devel"
PACKAGES_ARCH="$PACKAGES_ARCH glib2 gmime3"

# mod_smtp_filter_arc
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libmilter-dev"
PACKAGES_FEDORA="$PACKAGES_FEDORA sendmail-milter-devel"

# mod_smtp_filter_spf
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libspf2-dev"
# MISSING: RPM package
PACKAGES_ARCH="$PACKAGES_ARCH libspf2"

# mod_smtp_filter_dmarc
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libopendmarc-dev"
# MISSING: RPM package
PACKAGES_SUSE="$PACKAGES_SUSE sendmail-devel"
# opendmarc is available for Arch, but tries to install something that can satisfy smtp-server, so don't

# mod_sieve
PACKAGES_DEBIAN="$PACKAGES_DEBIAN libsieve2-dev"
# MISSING: RPM package
# MISSING: Arch package

# Soft dependencies
# used for bc (executed by 'calc' in door_utils)
PACKAGES_DEBIAN="$PACKAGES_DEBIAN bc"

# Actually install required packages
OS=$( uname -s )
OS_DIST_INFO="(lsb_release -ds || cat /etc/*release || uname -om ) 2>/dev/null | head -n1 | cut -d'=' -f2"
OS_DIST_INFO=$(eval "$OS_DIST_INFO" | tr -d '"')

printf "OS type: %s\n" "$OS_DIST_INFO"

if [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
	# If environment variables not set, use sane defaults
	if [ "$INSTALL_LIBETPAN" = "" ]; then
		printf "libetpan does not build successfully on Fedora-based distros... auto-disabling... pass INSTALL_LIBETPAN=1 to override\n"
		INSTALL_LIBETPAN=0
	fi
fi

if [ -f /etc/debian_version ]; then
	DEBIAN_VERSION=$( lsb_release -a | grep "Release:" | xargs | cut -d' ' -f2 )
	if [ $DEBIAN_VERSION -ge 11 ]; then
		# Not available in Debian 10
		PACKAGES_DEBIAN="$PACKAGES_DEBIAN libcrypt-dev" # crypt_r
		# used for cal (included in menus.conf sample)
		PACKAGES_DEBIAN="$PACKAGES_DEBIAN ncal"
	fi
	apt-get update
	apt-get install -y $PACKAGES_DEBIAN
# Fedora check must come first, since confusingly, both Fedora and RHEL/Rocky Linux have /etc/redhat-release
elif [ -f /etc/fedora-release ]; then
	dnf update -y
	dnf install -y $PACKAGES_FEDORA
elif [ -f /etc/redhat-release ]; then
	dnf update -y
	# libbsd is only available through EPEL (Extra Packages for Enterprise Linux)
	# And epel is only available through the extras repo... which may not be available.
	# Talk about dependency hell...
	majversion=$( cat /etc/redhat-release | cut -d'(' -f1 | awk '{print $(NF)}' | cut -d'.' -f1 ) # lsb_release not present by default
	dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$majversion.noarch.rpm"
	if [ "$OS_DIST_INFO" = "Rocky Linux release 8.9 (Green Obsidian)" ]; then
		dnf --enablerepo=devel install -y libedit-devel
	else
		PACKAGES_RHEL="$PACKAGES_RHEL libedit-devel"
	fi
	PACKAGES_RHEL="$PACKAGES_RHEL readline-devel libbsd-devel"
	dnf install -y $PACKAGES_RHEL
elif [ "$OS_DIST_INFO" = "SLES" ] || [ "$OS_DIST_INFO" = "openSUSE Tumbleweed" ]; then
	zypper update -y
	zypper install --no-confirm $PACKAGES_SUSE
elif [ -r /etc/arch-release ]; then
	pacman -Syu --noconfirm
	pacman -Sy --noconfirm $PACKAGES_ARCH
elif [ "$OS" = "FreeBSD" ]; then
	if [ ! -d /usr/local/src ]; then
		mkdir /usr/local/src
	fi
	pkg update -f
	pkg install -y $PACKAGES_FREEBSD
else
	printf "Could not install %s packages (unsupported distro?)\n" "$OS" >&2 # to stderr
	exit 1
fi

# == Source Install

# For some reason, jansson doesn't seem to get installed properly for Fedora-based distros in the CI
if [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
	if [ ! -f /usr/include/jansson.h ]; then
		printf "Hmm, it appears <jansson.h> is not available?\n"
		# Fall back to compiling it from source
		scripts/libjansson.sh
	fi
fi

# libcami (mod_asterisk_ami)
scripts/libcami.sh

# lirc (mod_irc_client)
scripts/lirc.sh

# libdiscord (mod_discord)
scripts/libdiscord.sh

# libwss (net_ws)
scripts/libwss.sh

# libetpan fails to build successfully on Fedora-based distros,
# so need to be able to skip that for now using an env var.
if [ "$INSTALL_LIBETPAN" != "0" ]; then
	# libetpan (mod_webmail): the package no longer suffices, since we patch the source.
	#PACKAGES_DEBIAN="$PACKAGES_DEBIAN libetpan-dev"
	scripts/libetpan.sh

	# evergreen (door_evergreen)
	scripts/evergreen.sh
fi

# mod_slack (also depends on libwss)
scripts/libslackrtm.sh

# mod_smtp_filter_arc
# milter pre-req can be hard to satisfy, so can be disabled using an env var
if [ "$INSTALL_LIBOPENARC" != "0" ]; then
	scripts/libopenarc.sh
fi

# doxygen only: env var required to enable
if [ "$INCLUDE_DOXYGEN" = "1" ]; then
	PACKAGES_DEBIAN="$PACKAGES_DEBIAN doxygen graphviz"
fi
