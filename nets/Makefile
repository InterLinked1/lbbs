
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)

INCLUDE_FILES := $(wildcard ../include/*.h)

# the include directory is in the parent
INC = -I..

# SSHLIB=$(pkg-config --libs libssh)
SSHLIB=-lssh

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

.PHONY: all
