#/bin/sh

# bbs_dumper
# (C) Copyright 2023 Naveen Albert

ps -aux | grep "lbbs" | grep -v "grep"

bbspid=`cat /var/run/lbbs/bbs.pid`
printf "BBS PID: %d\n" $bbspid

if [ "$1" = "pid" ]; then
	echo $bbspid
elif [ "$1" = "term" ]; then
	kill -9 $bbspid
elif [ "$1" = "quit" ]; then
	kill -3 $bbspid
elif [ "$1" = "postdump" ]; then
	gdb /usr/sbin/lbbs core -ex "thread apply all bt full" -ex "quit" > full.txt
	printf "Backtrace saved to full.txt\n"
elif [ "$1" = "livedump" ]; then
	gdb --batch -q -p $bbspid -ex 'thread apply all bt full' -ex 'quit' > full.txt
	printf "Backtrace saved to full.txt\n"
else
	echo "Invalid command!"
	exit 1
fi
