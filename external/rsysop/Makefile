#
# Remote Sysop Console
#
# Copyright (C) 2023, Naveen Albert
#

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wmaybe-uninitialized -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wnull-dereference -Wformat=2 -Wshadow -Wsizeof-pointer-memaccess -std=gnu99 -pthread -O0 -g -Wstack-protector -fno-omit-frame-pointer -fwrapv -D_FORTIFY_SOURCE=2
EXE		= rsysop
RM		= rm -f
INSTALL = install

all: rsysop.o
	$(CC) $(CFLAGS) -o $(EXE) *.o

%.o : %.c
	$(CC) $(CFLAGS) -c $^

install : all
	$(INSTALL) -m 755 $(EXE) /var/lib/lbbs/external/$(EXE)

clean :
	$(RM) *.i *.o $(EXE)

.PHONY: all
.PHONY: install
.PHONY: clean
