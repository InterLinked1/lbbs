#!/bin/sh

if ! which valgrind > /dev/null; then
	printf "valgrind is not installed on your system\n"
	exit 1
fi

VALGRIND_VERSION_MAJOR=`valgrind --version | cut -d'-' -f2 | cut -d'.' -f1`
VALGRIND_VERSION_MINOR=`valgrind --version | cut -d'-' -f2 | cut -d'.' -f2`

printf "Valgrind version: %s.%d\n" "$VALGRIND_VERSION_MAJOR" "$VALGRIND_VERSION_MINOR"

if [ $VALGRIND_VERSION_MAJOR -ge 3 ] && [ $VALGRIND_VERSION_MINOR -ge 15 ]; then
	printf "Newer version of valgrind detected\n"
	VALGRIND="valgrind --show-error-list=yes --keep-debuginfo=yes"
else
	printf "Older version of valgrind detected\n"
	VALGRIND="valgrind --keep-debuginfo=yes"
fi

if [ "$1" = "valgrindfg" ]; then
	exec $VALGRIND --leak-check=full --track-fds=yes --track-origins=yes --show-leak-kinds=all --child-silent-after-fork=yes --suppressions=valgrind.supp /usr/sbin/$EXE -cb
elif [ "$1" = "valgrind" ]; then
	exec $VALGRIND --leak-check=full --track-fds=yes --track-origins=yes --show-leak-kinds=all --child-silent-after-fork=yes --suppressions=valgrind.supp --log-fd=9 /usr/sbin/$EXE -cb 9>valgrind.txt
elif [ "$1" = "valgrindsupp" ]; then
	exec $VALGRIND --leak-check=full --track-fds=yes --track-origins=yes --show-leak-kinds=all --child-silent-after-fork=yes --suppressions=valgrind.supp --gen-suppressions=all --log-fd=9 /usr/sbin/$EXE -cb 9>valgrind.txt
elif [ "$1" = "helgrind" ]; then
	$VALGRIND --tool=helgrind /usr/sbin/$EXE -c
else
	printf "Invalid valgrind target\n"
fi
