#/bin/sh

# bbs_dumper
# (C) Copyright 2023 Naveen Albert

# $1 = REQUIRED Sub-command to run: pid|threads|term|quit|postdump|livedump|gdb
# $2 = OPTIONAL For postdump command, custom path to core file. Default is 'core' in current directory.
# For backtraces, the full backtrace is saved to full.txt in the current directory

ps -aux | grep "lbbs" | grep -v "grep"

bbspid=`cat /var/run/lbbs/bbs.pid`
printf "BBS PID: %d\n" $bbspid

ensure_gdb_installed() {
	# For some reason, using which is not sufficient and will lead to things like: /usr/bin/gdb does not support python
	# That's because gdb isn't really installed.
	# Use a technique aside from which/path/binary detection to see if we find something we expect:
	helplines=`gdb --help | grep "GDB manual" | wc -l`
	if [ "$helplines" != "1" ]; then
		printf "GDB does not appear to be currently installed, trying to install it now...\n"
		apt-get install -y gdb
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
	printf "Backtrace saved to full.txt\n"
elif [ "$1" = "livedump" ]; then
	ensure_gdb_installed
	gdb /usr/sbin/lbbs --batch -q -p $bbspid -ex 'thread apply all bt full' -ex 'quit' > full.txt
	printf "Backtrace saved to full.txt\n"
elif [ "$1" = "gdb" ]; then
	ensure_gdb_installed
	exec gdb /usr/sbin/lbbs -p $bbspid
else
	echo "Invalid command!"
	exit 1
fi
