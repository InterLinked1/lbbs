
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

# Since we don't use autoconf:
ARCH = $(shell uname -m)
SFTP_SERVER_FREE_EXISTS = $(shell objdump -T /usr/lib/$(ARCH)-linux-gnu/libssh.so /lib/$(ARCH)-linux-gnu/libssh.so /usr/lib64/libssh.so 2>&1 | grep "sftp_server_free" | wc -l)

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

# This target ensures that any nets/net_imap/*.c source files including header files in nets/net_imap/
# also get recompiled if needed. Otherwise, only net_imap.c gets recompiled, which can lead
# to ABI issues if structs are modified and "make clean" isn't run between builds.
imap_subtargets:
	@+$(SUBMAKE) --no-builtin-rules -C net_imap all

# Subdirectory with components for net_imap
# Since imap_subtargets ensures that any object files in the subdirectory are recompiled if needed,
# no recompiling should be done as a result of having $(IMAP_SRC) as a dependency for the this target.
# Also note that even though imap_subtargets is a dependency for all object files in the subdirectory,
# it will only get called once.
net_imap/%.o: imap_subtargets $(IMAP_SRC)
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
.PHONY: imap_subtargets
