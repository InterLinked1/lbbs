
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

# Since we don't use autoconf:
SFTP_SERVER_FREE_EXISTS = $(shell objdump -T /usr/lib/x86_64-linux-gnu/libssh.so /lib/x86_64-linux-gnu/libssh.so /usr/lib64/libssh.so 2>&1 | grep "sftp_server_free" | wc -l)

ifneq ($(SFTP_SERVER_FREE_EXISTS),0)
	CFLAGS += -DHAVE_SFTP_SERVER_FREE
endif

all: $(MOD_SO)

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) -c $<

%.so : %.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^

IMAP_SRC = $(wildcard net_imap/*.c)
IMAP_OBJ = $(patsubst %.c,%.o,$(IMAP_SRC))

# XXX if nets/net_imap/imap.h is modified, only net_imap.c is automatically recompiled,
# not any nets/net_imap/*.c source files that include it
# XXX If using -j[>1], some files in net_imap/ are recompiled multiple times (parallel build bug)

# Subdirectory with components for net_imap
net_imap/%.o: $(IMAP_SRC)
	@+$(SUBMAKE) --no-builtin-rules -C net_imap $(basename $(notdir $@)).o

net_imap.so : net_imap.o $(IMAP_OBJ)
	@echo "  [LD] $< $(IMAP_OBJ) -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $<).so $(IMAP_OBJ) $<

# SSHLIB=$(pkg-config --libs libssh)
net_ssh.so : net_ssh.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lssh

net_ws.so : net_ws.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lwss

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: all
.PHONY: net_imap
