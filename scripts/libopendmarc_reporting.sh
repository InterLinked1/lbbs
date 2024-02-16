#!/bin/sh

# libopendmarc_reporting.sh
# Set up the DMARC reporting database and scripts
# to process reporting logs from mod_smtp_filter_dmarc

set -e

# Install prereqs for perl scripts
apt-get install -y libswitch-perl libdbd-mysql-perl
export PERL_MM_USE_DEFAULT=1
cpan JSON

# Build OpenDMARC from source to compile the reports scripts,
# but don't install it, since we already installed the package.

cd /usr/local/src
git clone https://github.com/trusteddomainproject/OpenDMARC.git
cd OpenDMARC
aclocal && autoconf && autoreconf --install && automake --add-missing && ./configure

# Build, but don't install everything, just the reports
make
cd reports

# Get hostname to use, since default reporting address is postmaster@, which is unsuitable
BBS_HOSTNAME=$( grep "hostname" /etc/lbbs/nodes.conf | cut -d'=' -f2 | cut -d' ' -f1 | tr -d '\n' )
printf "Autodetected SMTP hostname: %s\n", "$BBS_HOSTNAME"

# The opendmarc-reports perl script uses the system hostname for HELO/EHLO
# If this isn't a FQDN, then some MTAs might not like that if they check the HELO hostname.
hostname | grep -F "."
if [ $? -ne 0 ]; then
	printf "System hostname is not a FQDN: "
	hostname
	# Since it's not a FQDN, replace hostfqdn() in the reporting script with $BBS_HOSTNAME
	# so we use the right HELO (to avoid updating the system hostname just for this)
	printf "Modifying opendmarc-reports script to use hardcoded hostname '%s' instead - you will need to change this if your hostname changes!\n" $BBS_HOSTNAME
	sed -i "s/hostfqdn()/\"$BBS_HOSTNAME\"/" opendmarc-reports.in
fi

# Install the reporting scripts
make install

# Set up the database

# You should ideally change the password in the scripts,
# but worst case it's a local user so it probably doesn't matter anyways.
# The opendmarc scripts use opendmarc as the default so change it to that.
sed -i 's/changeme/opendmarc/' db/schema.mysql
sed -i 's/-- CREATE/CREATE/' db/schema.mysql
sed -i 's/-- GRANT/GRANT/' db/schema.mysql

# Script is broken by default: https://github.com/trusteddomainproject/OpenDMARC/issues/184
sed -i 's/1970-01-01 00:00:00/1970-01-01 00:00:01/' db/schema.mysql

mariadb < db/schema.mysql

# Script should now be able to run and connect to the DB using the script defaults
# opendmarc-import is used to read messages from a log file and put them in the DB
# opendmarc-importstats is the wrapper around opendmarc-import, to be called from cron
# opendmarc-reports is used to actually generate and send reports
# opendmarc-expire is used to periodically expire old data that is no longer needed

# The following scripts need to be called automatically (via cron),
# but do a test run first and make sure all is well.
# Helps if you send a test email prior to running these, so you can see something.

opendmarc-expire --verbose

# Import from log file into database
# This will rotate /var/tmp/dmarc.dat, and mod_smtp_filter_dmarc will subsequently reopen the file
# so that future logging goes to a fresh log file.
# (The opendmarc milter opens the file each time, so it doesn't need to check)

# This script will call opendmarc-import just using the program name, so it needs to be installed to be in PATH.
# If this fails, it will also fail at runtime.
opendmarc-importstats

# Process database and send reports. Since --test will generate funky named XML files, cd to /tmp first.
cd /tmp
opendmarc-reports --test --verbose --verbose --verbose

# Go ahead and add everything to crontab.
# Assuming this machine is in UTC, reports should go out at midnight every night.

# We need to manually set a PATH for the script, since opendmarc-importstats calls opendmarc-import,
# and that will fail if PATH is not set, rotating the file, but not importing it, basically discarding the log.
# Since we include /usr/local/bin explicitly in the PATH for the job, we can omit the full path to the other commands.
# The other directories in path are needed for mv and ls, other programs called by opendmarc-importstats
# Spawning a subshell doesn't seem to work in crontab for grouping commands for redirection, so
# we just spawn /bin/sh for compatibility, so we can append all output to a log file easily.

(crontab -l ; echo "0 0 * * * PATH=/usr/bin:/usr/local/bin:/usr/local/sbin /bin/sh -c 'opendmarc-importstats && opendmarc-reports --verbose --verbose --verbose --report-org=${BBS_HOSTNAME} --report-email=dmarc-noreply@${BBS_HOSTNAME} && opendmarc-expire' >> /var/log/lbbs/dmarcrua.log 2>&1") | sort - | uniq - | crontab -
