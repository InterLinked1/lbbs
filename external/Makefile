# External programs, not part of the BBS itself

SRCS := $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
EXES = $(patsubst %.o,%,$(OBJS))
OBJS_NOFILEMGR = $(filter-out filemgr.o,$(OBJS))
EXES_NOFLEMGR = $(patsubst %.o,%,$(OBJS_NOFILEMGR))

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wmaybe-uninitialized -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wnull-dereference -Wformat=2 -Wshadow -Wsizeof-pointer-memaccess -std=gnu99 -pthread -O3 -g -Wstack-protector -Wno-unused-result -fno-omit-frame-pointer -fwrapv -D_FORTIFY_SOURCE=2
RM		= rm -f
INSTALL = install
NCURSES_FLAGS=$(shell pkg-config --cflags ncurses)

ARCH = $(shell uname -m)
CFLAGS += -DBBS_LINUX_ARCH=$(ARCH)

all: $(EXES)

$(EXES_NOFLEMGR): %: %.o
	@echo "  [LD] $@.o -> $@"
	$(CC) $(CFLAGS) -o $@ $@.o

filemgr: filemgr.o
	@echo "  [LD] $@.o -> $@"
	$(CC) $(CFLAGS) -o $@ $@.o -lmenu -lncurses

%.o : %.c
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -c $^

filemgr.o : filemgr.c
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) $(NCURSES_FLAGS) -c $^

install : all
	@for i in $(EXES); do \
		echo " -> Installing external program $${i}"; \
		$(INSTALL) -m 755 $${i} /var/lib/lbbs/external/; \
	done

clean :
	$(RM) *.i *.o $(EXES)

.PHONY: all
.PHONY: install
.PHONY: clean
