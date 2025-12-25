#/bin/sh

# bbs_dumper
# (C) Copyright 2023 Naveen Albert

# $1 = REQUIRED Sub-command to run: pid|threads|term|quit|postdump|livedump|gdb
# $2 = OPTIONAL For postdump command, custom path to core file. Default is 'core' in current directory.
# For backtraces, the full backtrace is saved to full.txt in the current directory

ps -aux | grep "lbbs" | grep -v "strace" | grep -v "grep" | grep -v "mysqld"

bbspid=`cat /var/run/lbbs/bbs.pid`
printf "BBS PID: %d\n" $bbspid

install_gdb() {
	# Assume the package manager has already been updated if needed.
	OS=$( uname -s )
	OS_DIST_INFO="(lsb_release -ds || cat /etc/*release || uname -om ) 2>/dev/null | head -n1 | cut -d'=' -f2"
	OS_DIST_INFO=$(eval "$OS_DIST_INFO" | tr -d '"')
	if [ -f /etc/debian_version ]; then
		apt-get install -y gdb
	elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
		dnf install -y gdb
	elif [ "$OS_DIST_INFO" = "SLES" ] || [ "$OS_DIST_INFO" = "openSUSE Tumbleweed" ]; then
		zypper install --no-confirm gdb
	elif [ -r /etc/arch-release ]; then
		pacman -Sy --noconfirm gdb
		export DEBUGINFOD_URLS="https://debuginfod.archlinux.org"
	elif [ -r /etc/alpine-release ]; then
		apk add gdb
	elif [ "$OS" = "FreeBSD" ]; then
		pkg install -y gdb
	else
		printf "Could not automatically install gdb (unsupported distro?)\n" "$OS" >&2 # to stderr
		return
	fi
}

ensure_gdb_installed() {
	# For some reason, using which is not sufficient and will lead to things like: /usr/bin/gdb does not support python
	# That's because gdb isn't really installed.
	# Use a technique aside from which/path/binary detection to see if we find something we expect:
	helplines=`gdb --help 2> /dev/null | grep "GDB manual" | wc -l`
	if [ "$helplines" != "1" ]; then
		printf "GDB does not appear to be currently installed, trying to install it now...\n"
		install_gdb
	fi
}

if [ "$1" = "pid" ]; then
	echo $bbspid
elif [ "$1" = "threads" ]; then
	ps -o pid,lwp,pcpu,pmem,comm,cmd -L $bbspid
elif [ "$1" = "term" ]; then
	kill -9 $bbspid
elif [ "$1" = "quit" ]; then
	kill -3 $bbspid
elif [ "$1" = "postdump" ]; then
	ensure_gdb_installed
	if [ "$2" != "" ]; then
		CORE_FILE=$2
	else
		CORE_FILE=core
	fi
	gdb /usr/sbin/lbbs "$CORE_FILE" -ex "thread apply all bt full" -ex "quit" > full.txt
	# gdb can return nonzero even if it succeeded, so don't check the return code
	if [ -f full.txt ]; then
		printf "Backtrace saved to full.txt\n"
	else
		printf "Failed to obtain backtrace\n"
	fi
elif [ "$1" = "livedump" ]; then
	ensure_gdb_installed
	gdb /usr/sbin/lbbs --batch -q -p $bbspid -ex 'thread apply all bt full' -ex 'quit' > full.txt
	if [ -f full.txt ]; then
		printf "Backtrace saved to full.txt\n"
	else
		printf "Failed to obtain backtrace\n"
	fi
elif [ "$1" = "gdb" ]; then
	ensure_gdb_installed
	exec gdb /usr/sbin/lbbs -p $bbspid
else
	echo "Invalid command!"
	exit 1
fi
