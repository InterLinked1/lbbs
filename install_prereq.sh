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

# sock_ssh
apt-get install -y libssh-dev # libssh

# mod_mysql_auth
apt-get install -y libmariadb-dev libmariadb-dev-compat # MariaDB (MySQL) dev headers

# net_http
apt-get install -y libmagic-dev

# doxygen only:
# apt-get install -y doxygen graphviz
