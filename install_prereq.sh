#/bin/sh

# Update
apt-get update

# Install pre-reqs
apt-get install -y build-essential # make
apt-get install -y libncurses-dev # ncurses
apt-get install -y libcrypt-dev # crypt_r
apt-get install -y libcurl4-openssl-dev # <curl/curl.h> - cURL, OpenSSL variant
apt-get install -y binutils-dev # <bfd.h>
apt-get install -y libcap-dev # <sys/capability.h>
apt-get install -y libedit-dev # <histedit.h>
apt-get install -y libuuid1 uuid-dev # <uuid/uuid.h>
apt-get install -y libreadline-dev # <readline/history.h>

# net_ssh
apt-get install -y libssh-dev # libssh

# net_ssh, which requires objdump to test for symbol existence... thanks a lot, libssh
apt-get install -y binutils # binutils, for objdump

# mod_mysql, mod_mysql_auth
apt-get install -y libmariadb-dev libmariadb-dev-compat # MariaDB (MySQL) dev headers

# mod_lmdb
apt-get install -y liblmdb-dev

# mod_http
apt-get install -y libmagic-dev

# mod_smtp_filter_dkim
apt-get install -y libopendkim-dev

# mod_smtp_filter_dmarc
apt-get install -y libopendmarc-dev

# mod_smtp_filter_spf
apt-get install -y libspf2-dev

# mod_mimeparse
apt-get install -y libglib2.0-dev libgmime-3.0-dev

# mod_oauth
apt-get install -y libjansson-dev

# mod_sieve
apt-get install -y libsieve2-dev

# libdiscord (mod_discord)
scripts/concord.sh

# libwss (net_ws)
scripts/libwss.sh

# mod_slack (also depends on libwss)
scripts/libslackrtm.sh

# libetpan (mod_webmail): the package no longer suffices, since we patch the source.
# apt-get install -y libetpan-dev
apt-get install -y automake libtool
scripts/libetpan.sh

# doxygen only:
# apt-get install -y doxygen graphviz
