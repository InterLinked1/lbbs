#!/bin/sh

# Basic script to backup all of LBBS's important data
# Desgigned to be a simple, easy script to back everything
# up into a single tarball.

# Note that this script is not recommended for systems
# with lots of data, since you will likely want to apply
# different backup policies for different types of data
# (e.g. email vs config files, etc.)
# If you really want to back up EVERYTHING, then this
# script may be useful to you.

# The config parsing is not particularly robust,
# since we aren't parsing the INI configs, so complicated
# configs may perturb the results. Use at your own risk.

# This script assumes directories do not contain spaces.

# This script is written for POSIX sh, so some things would
# be easier if bashisms were allowed, bear with me :)

# Get all the relevant paths from the LBBS config files
BBS_CONFIG_DIR=/etc/lbbs
BBS_LOG_DIR=/var/log/lbbs # not backed up by default, due to large size, but could be added to the backup list if you want it

# Determine the BBS runuser

# $1 = file, $2 = section (currently ignored), $3 = key
get_config_value() {
	if [ -f "$BBS_CONFIG_DIR/$1" ]; then
		# We filter semicolon (comment begin) early in this process,
		# because we need to handle semicolon at the beginning of the line (in which case we should ignore the line entirely)
		# as well as commenting out a description for an active setting (in which case we just strip the comment).
		# This has to be done before the = filter, since if we take what's on the right of that, we could miss the leading semicolon.
		val=$( grep -e "$3=" -e "$3 =" $BBS_CONFIG_DIR/$1 | cut -d';' -f1 | cut -d'=' -f2 | xargs | tr -d '\n' )
		printf "%s" "$val"
	fi
}

# transfers.conf
BBS_FILES_ROOT=$( get_config_value "transfers.conf" "transfers" "rootdir" )
BBS_HOMEDIR_TEMPLATE=$( get_config_value "transfers.conf" "transfers" "homedirtemplate" )

# system.conf
BBS_CONTAINER_TEMPLATE=$( get_config_value "system.conf" "container" "templatedir" )

# mod_lmdb.conf
LMDB_DIR="/var/lib/lbbs/lmdb" # currently hardcoded into the module, not configurable

# mod_mail.conf
BBS_MAILDIR=$( get_config_value "mod_mail.conf" "general" "maildir" )

# net_http.conf
BBS_HTTP_ROOT=$( get_config_value "net_http.conf" "general" "docroot" )

# net_gopher.conf
BBS_GOPHER_ROOT=$( get_config_value "net_gopher.conf" "gopher" "root" )

# net_nntp.conf
BBS_NNTP_DIR=$( get_config_value "net_nntp.conf" "general" "newsdir" )

# If there any additional directories to back up,
# include them in this string:
# The string should end with a space

DIRS="$BBS_CONFIG_DIR $BBS_FILES_ROOT $BBS_HOMEDIR_TEMPLATE $BBS_CONTAINER_TEMPLATE $LMDB_DIR $BBS_MAILDIR $BBS_HTTP_ROOT $BBS_GOPHER_ROOT $BBS_NNTP_DIR"

DIRS=$( printf "%s" "$DIRS" | tr -s " " | xargs ) # squash multiple whitespace to avoid turning it into multiple newlines below
DIRS="$DIRS " # end with whitespace for last directory

# Get the "minimum spanning set" of these directories

# First, print out all the directories
printf "$DIRS" | tr ' ' '\n' | while read DIR; do
	printf "  + %s\n" "$DIR"
done

# Eliminate any directories that don't exist

eliminate_nonexistent() {
	# Normally, when pipelining, any modifications made in the loop (since it's at the end of the pipeline) won't persist after the loop
	# So we call this as a function and echo the result so the parent can see it
	printf "$DIRS" | tr ' ' '\n' | while read DIR; do
		if [ ! -d "$DIR" ]; then
			# Don't include in result, so print to STDERR
			printf "Directory does not exist: %s\n" "$DIR" >&2
		else
			printf "%s " "$DIR"
		fi
	done
}

DIRS=$( eliminate_nonexistent )
printf " * Existing Directories:  %s\n" "$DIRS" # space added for alignment with below

# $1 = directory to check if it's a subdirectory of any other directory
eliminate_subdirectory_check() {
	# Here, we print negative matches (e.g. if we print something, we should omit that directory)
	printf "$DIRS" | tr ' ' '\n' | while read DIR; do
		case $DIR in
			"$1") ;; # If it's the same, it's itself, so that doesn't count
			"$1"*) printf "%s " "$DIR"; printf " - Directory %s is a subdirectory of %s, discarding\n" "$DIR" "$1" >&2 ;; # We do not want to back up anything twice, so discard
			*) :
		esac
	done
}

eliminate_subdirectories_check() {
	printf "$DIRS" | tr ' ' '\n' | while read DIR; do
		SKIPDIR=$( eliminate_subdirectory_check "$DIR" )
		if [ "$SKIPDIR" = "" ]; then
			# If it's not a subdirectory, print it
			printf "%s " "$DIR"
		fi
	done
}

DIRS=$( eliminate_subdirectories_check )
printf " * Top-level Directories: %s\n" "$DIRS"

# Eliminate trailing space
DIRS=$( printf "%s" "$DIRS" | xargs )

FILES=""

# Backup databases
BACKUP_DBS=""

# Only backup the database if it's on the same server. If it's not local, skip it.
if which "mysql" > /dev/null; then
	ALL_DBS=$( mysql -N -e "show databases like '%';" )
fi

# $1 = database to check
database_exists() {
	# We can't use <<< since that's a Bashism
	printf "%s" "$ALL_DBS" | grep "$1" > /dev/null # DB names are surrounded by spaces in the mysql output, so include those for safety
	if [ $? -eq 0 ]; then
		# If it exists, output it
		printf "%s " "$1"
	fi
}

BBS_DBS="bbs irc opendmarc "

check_databases_exist() {
	printf "$BBS_DBS" | tr ' ' '\n' | while read DB; do
		database_exists "$DB"
	done
}

if [ "$ALL_DBS" != "" ]; then
	BACKUP_DBS=$( check_databases_exist )
	printf " - Databases: %s\n" "$BACKUP_DBS"

	if [ "$BACKUP_DBS" != "" ]; then
		# Dump the BBS database(s)
		# Not all databases may exist on all systems, so detect if a database is present and only then add it to the list
		printf " ! %s\n" "mysqldump -h localhost --databases $BACKUP_DBS > /tmp/bbsdb.sql" # Print executed command
		mysqldump -h localhost --databases $BACKUP_DBS > /tmp/bbsdb.sql
		if [ "$FILES" != "" ]; then
			FILES="$FILES /tmp/bbsdb.sql"
		else
			FILES="/tmp/bbsdb.sql"
		fi
	fi
fi

# Now, go ahead and actually tarball everything up
TAR_NAME="lbbs_$(date +"%Y%m%d_%H%M%S").tar.gz"
printf " ! %s\n" "tar cvzf $TAR_NAME $DIRS $FILES" # Print executed command
# This will contain a lot of files, don't list them all
tar cvzf $TAR_NAME $DIRS $FILES >/dev/null 2>&1 # suppress "tar: Removing leading `/' from member names"
printf "Backed up to tarball %s in current directory\n" "$TAR_NAME"
ls -lh "$TAR_NAME"
