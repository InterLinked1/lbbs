
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

# SSHLIB=$(pkg-config --libs libssh)
SSHLIB=-lssh

# Since we don't use autoconf:
SFTP_SERVER_FREE_EXISTS = $(shell objdump -T /usr/lib/x86_64-linux-gnu/libssh.so /lib/x86_64-linux-gnu/libssh.so /usr/lib64/libssh.so 2>&1 | grep "sftp_server_free" | wc -l)

ifneq ($(SFTP_SERVER_FREE_EXISTS),0)
	CFLAGS += -DHAVE_SFTP_SERVER_FREE
endif

all: $(MOD_SO)
	@echo "== Compiling nets"

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) -c $<

%.so : %.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^

IMAP_SRC = $(wildcard net_imap/*.c)
IMAP_OBJ = $(patsubst %.c,%.o,$(IMAP_SRC))

# Subdirectory with components for net_imap
net_imap:
	@echo " +--------- make $@ ---------+"
	$(SUBMAKE) --no-builtin-rules -C $@ all

net_imap.so : net_imap.o net_imap
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $<).so $(IMAP_OBJ) $<

net_ssh.so : net_ssh.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ $(SSHLIB)

net_ws.so : net_ws.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lwss

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: all
.PHONY: net_imap
