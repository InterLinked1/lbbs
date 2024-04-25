#!/bin/sh
# BBS Setup Guide for Debian 11/12

# This is a high-level sample script that can be used to fully set up a Linux server for running LBBS.
# This is NOT a fully unattended script, some commands (e.g. mysql_secure_installation) are interactive.

# If you currently have Debian 11, but want to upgrade to Debian 12:
# sed -i 's/bullseye/bookworm/g' /etc/apt/source-list
# apt-get update && apt-get upgrade && apt-get dist-upgrade && reboot

apt-get -y update
apt-get -y upgrade

apt-get -y install git

# Change sshd port to something non-standard, e.g. 22 to 22222, so the BBS's SSH server can run on 22
# Debian 12: If you have an RSA public key and your public key is denied, see: https://unix.stackexchange.com/questions/721606/ssh-server-gives-userauth-pubkey-key-type-ssh-rsa-not-in-pubkeyacceptedalgorit
# echo "PubkeyAcceptedAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 22222/' /etc/ssh/sshd_config
service ssh restart

# Create a non-root user for the BBS:
adduser -c "BBS" bbs --disabled-password --shell /usr/sbin/nologin --gecos ""

# Install MariaDB: https://www.digitalocean.com/community/tutorials/how-to-install-mariadb-on-debian-11
apt-get -y install mariadb-server
mysql_secure_installation

# Install a terminfo file for syncterm, which is not present by default
if [ -d /etc/terminfo ] && [ ! -f /etc/terminfo/s/syncterm ]; then
	cd /tmp
	wget https://gitlab.synchro.net/main/sbbs/-/raw/master/install/termcap -O /tmp/syncterm_terminfo
	sed -i 's/ansi-bbs/syncterm/' /tmp/syncterm_terminfo
	tic -s syncterm_terminfo
fi

# Change these passwords! (create admin account for sysop use, and a BBS account for LBBS to use)

# mariadb
# GRANT ALL ON *.* TO 'admin'@'localhost' IDENTIFIED BY 'password' WITH GRANT OPTION;
# CREATE USER 'bbs'@'localhost' IDENTIFIED BY 'anotherpassword';
# FLUSH PRIVILEGES;
# exit

# Install the BBS
cd /usr/local/src
git clone https://github.com/InterLinked1/lbbs.git
cd lbbs
./scripts/install_prereq.sh
make modconfig
make
make tests
make install

# Let the BBS bind to privileged ports:
setcap CAP_NET_BIND_SERVICE=+eip /usr/sbin/lbbs

# Set up the databases. This ensures any new tables are added even if not present on a previous system.
mariadb < scripts/dbcreate.sql

# To backup/export the BBS's DBs from another machine (e.g. migrating BBS between servers), export data (but not schema):
# mysqldump --no-create-db --no-create-info --databases bbs irc > bbsdb.sql
#
# Import the dump onto the new system
# mariadb < bbsdb.sql

# Create all the default directories that are used in the sample configs
# These directories are not created automatically by the makefile

# files root (transfers.conf)
mkdir -p /home/bbs/files
chown -R bbs:bbs /home/bbs/files

# maildir (mod_mail.comf)
mkdir -p /home/bbs/maildir
chown -R bbs:bbs /home/bbs/maildir

# docroot (net_http.conf), also used as gopher root by default in net_gopher.conf
mkdir -p /home/bbs/www
chown -R bbs:bbs /home/bbs/www

# newsdir (net_nntp.conf)
mkdir -p /home/bbs/newsgroups
chown -R bbs:bbs /home/bbs/newsgroups

# Set up the rootfs for containers
cd /var/lib/lbbs && /usr/local/src/lbbs/scripts/gen_rootfs.sh && chown -R root:root /var/lib/lbbs/rootfs/
