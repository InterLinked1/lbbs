
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)

INCLUDE_FILES := $(wildcard ../include/*.h)

# the include directory is in the parent
INC = -I..

# SSHLIB=$(pkg-config --libs libssh)
SSHLIB=-lssh

SFTP_SERVER_FREE_EXISTS = $(shell objdump -T /lib/x86_64-linux-gnu/libssh.so | grep "sftp_server_free" | wc -l)

ifeq ($(SFTP_SERVER_FREE_EXISTS),1)
	CFLAGS += -DHAVE_SFTP_SERVER_FREE
endif

all: $(MOD_SO)
	@echo "== Compiling nets"

%.o : %.c
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $^)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $^)_self $(INC) -c $^

%.so : %.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^

net_ssh.so : net_ssh.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ $(SSHLIB)

net_sftp.so : net_sftp.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ $(SSHLIB)

net_http.so : net_http.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lmagic

.PHONY: all
