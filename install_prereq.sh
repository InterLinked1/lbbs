#/bin/sh

# Install pre-reqs

apt-get install -y libncurses-dev # ncurses
apt-get install -y libcrypt-dev # crypt_r
apt-get install -y binutils-dev # bfd.h

# sock_ssh
apt-get install -y libssh-dev # libssh

# mod_mysql_auth
apt-get install -y libmariadb-dev libmariadb-dev-compat # MariaDB (MySQL) dev headers
