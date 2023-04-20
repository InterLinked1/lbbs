#/bin/sh

# Update
apt-get update

# Install pre-reqs
apt-get install -y libncurses-dev # ncurses
apt-get install -y libcrypt-dev # crypt_r
apt-get install -y libcurl4-openssl-dev # <curl/curl.h> - cURL, OpenSSL variant
apt-get install -y binutils-dev # <bfd.h>
apt-get install -y libcap-dev # <sys/capability.h>
apt-get install -y libedit-dev # <histedit.h>
apt-get install -y libuuid1 uuid-dev # <uuid/uuid.h>
apt-get install -y libreadline-dev # <readline/history.h>

# net_ssh and net_sftp
apt-get install -y libssh-dev # libssh

# net_sftp, which requires objdump to test for symbol existence... thanks a lot, libssh
apt-get install -y binutils # binutils, for objdump

# mod_mysql, mod_mysql_auth
apt-get install -y libmariadb-dev libmariadb-dev-compat # MariaDB (MySQL) dev headers

# net_http
apt-get install -y libmagic-dev

# net_smtp
apt-get install -y libspf2-dev

# mod_mimeparse
apt-get install -y libglib2.0-dev libgmime-3.0-dev

# mod_sieve
apt-get install -y libsieve2-dev

# libdiscord
scripts/concord.sh

# doxygen only:
# apt-get install -y doxygen graphviz
