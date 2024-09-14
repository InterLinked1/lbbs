#!/bin/sh

# Simple Setup Wizard
# This script complements server_setup.sh (and is meant to be run after that)

# WARNING: This is somewhat experimental, and does not configure all (or even most) available settings.
# It is only intended to assist with some very rudimentary basic setup.
# Refer to each config file for full configuration.

if ! which "dialog" > /dev/null; then
	apt-get install -y dialog
fi

BBS_USER=""
BBS_HOST=""
MYSQL_HOST=""
MYSQL_USER=""
MYSQL_PASS=""
MAILDIR=""
NEWSDIR=""
DOCROOT=""

if [ ! -d /etc/lbbs ]; then
	if [ -f scripts/setup_wizard.sh ]; then # We're in the BBS source directory
		printf "Installing sample configs to /etc/lbbs\n"
		make samples
	else
		printf "ERROR: /etc/lbbs/ does not exist yet. Run make samples from the source directory, then rerun wizard.\n"
		exit 1
	fi
fi

reset
clear

printf "\n"

BBS_USER=$(dialog --nocancel --inputbox "What user do you want to run LBBS under?" 20 60 "bbs" 2>&1 >/dev/tty)
BBS_HOST=$(dialog --nocancel --inputbox "Primary hostname for BBS?" 20 60 "bbs.example.com" 2>&1 >/dev/tty)
MYSQL_HOST=$(dialog --nocancel --inputbox "Database hostname?" 20 60 "localhost" 2>&1 >/dev/tty)
MYSQL_USER=$(dialog --nocancel --inputbox "Database username?" 20 60 "bbs" 2>&1 >/dev/tty)
MYSQL_PASS=$(dialog --nocancel --inputbox "Database password?" 20 60 "" 2>&1 >/dev/tty)
MAILDIR=$(dialog --nocancel --inputbox "maildir for storing email" 20 60 "/home/$BBS_USER/maildir" 2>&1 >/dev/tty)
NEWSDIR=$(dialog --nocancel --inputbox "newsdir for storing news" 20 60 "/home/$BBS_USER/newsgroups" 2>&1 >/dev/tty)
DOCROOT=$(dialog --nocancel --inputbox "Webserver docroot" 20 60 "/home/$BBS_USER/www" 2>&1 >/dev/tty)

reset # In case dialog messed up the terminal

printf "%s\n" "----------- Confirm Settings -----------"
printf "%-20s %s\n" "BBS User/Group:" "$BBS_USER"
printf "%-20s %s\n" "BBS Hostname:" "$BBS_HOST"
printf "%-20s %s\n" "MySQL Hostname:" "$MYSQL_HOST"
printf "%-20s %s\n" "MySQL Username:" "$MYSQL_USER"
printf "%-20s %s\n" "MySQL Password:" "$MYSQL_PASS"
printf "%-20s %s\n" "Maildir:" "$MAILDIR"
printf "%-20s %s\n" "Newsdir:" "$NEWSDIR"
printf "%-20s %s\n" "Docroot:" "$DOCROOT"

printf "\nPress ENTER to confirm changes, ^C to abort: " >&2
read -r option

printf "Applying changes...\n"

# Run User/Group
id -u "$BBS_USER"
if [ $? -ne 0 ]; then
	# We want a home directory, but not a shell
	adduser -c "BBS" "$BBS_USER" --disabled-password --shell /usr/sbin/nologin --gecos ""
	printf "Created user %s\n" "$BBS_USER"
else
	printf "Using existing user %s\n" "$BBS_USER"
fi
sed -i "s/;user = bbs/user = $BBS_USER/" /etc/lbbs/bbs.conf
sed -i "s/;group = bbs/group = $BBS_USER/" /etc/lbbs/bbs.conf

chown -R "$BBS_USER" /var/log/lbbs
if ! which "sudo" > /dev/null; then
	apt-get install -y sudo
fi
echo "$BBS_USER ALL=(ALL:ALL) NOPASSWD:/usr/sbin/iptables" > /etc/sudoers.d/bbs-iptables

# Hostname
sed -i "s/hostname=bbs.example.com/hostname=$BBS_HOST/" /etc/lbbs/nodes.conf

# MySQL DB
sed -i "s/hostname=localhost/hostname=$MYSQL_HOST/" /etc/lbbs/mod_auth_mysql.conf
sed -i "s/username=bbs/username=$MYSQL_USER/" /etc/lbbs/mod_auth_mysql.conf
sed -i "s/password=P@ssw0rdUShouldChAngE!/password=$MYSQL_PASS/" /etc/lbbs/mod_auth_mysql.conf

chown -R "$BBS_USER" /etc/ssh/

mkdir -p "$MAILDIR"
chown -R "$BBS_USER" "$MAILDIR"
chgrp -R "$BBS_USER" "$MAILDIR"
sed -i "s|maildir=/home/bbs/maildir|maildir=$MAILDIR|" /etc/lbbs/mod_mail.conf

mkdir -p "$NEWSDIR"
chown -R "$BBS_USER" "$NEWSDIR"
chgrp -R "$BBS_USER" "$NEWSDIR"
sed -i "s|newsdir=/home/bbs/newsgroups|newsdir=$NEWSDIR|" /etc/lbbs/net_nntp.conf

mkdir -p "$DOCROOT"
chown -R "$BBS_USER" "$DOCROOT"
chgrp -R "$BBS_USER" "$DOCROOT"
sed -i "s|;docroot=/home/bbs/www|docroot=$DOCROOT|" /etc/lbbs/net_http.conf
sed -i "s/;enabled=yes/enabled=yes/" /etc/lbbs/net_http.conf

# Core dump permissions
if [ -f scripts/setup_wizard.sh ]; then # We're in the BBS source directory
	chown -R "$BBS_USER" .
fi
ulimit -c unlimited

printf "Basic setup wizard completed. Review your configs in /etc/lbbs/\n"
