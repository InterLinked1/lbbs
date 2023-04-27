# External programs, not part of the BBS itself

SRCS := $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
EXES = $(patsubst %.o,%,$(OBJS))

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wmaybe-uninitialized -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wnull-dereference -Wformat=2 -Wshadow -Wsizeof-pointer-memaccess -std=gnu99 -pthread -O0 -g -Wstack-protector -fno-omit-frame-pointer -fwrapv -D_FORTIFY_SOURCE=2
RM		= rm -f
INSTALL = install

all: $(EXES)

# XXX: This is not quite right, as it recreates all binaries whenever an object file needs to be recreated.
# What we really want to do is have each EXE depend on its corresponding OBJ file (with .o extension)
$(EXES): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $@.o

%.o : %.c
	$(CC) $(CFLAGS) -c $^

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
