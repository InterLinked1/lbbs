
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)

INCLUDE_FILES := $(wildcard ../include/*.h)

# the include directory is in the parent
INC = -I..

all: $(MOD_SO)
	@echo "== Compiling doors"

%.o : %.c
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $^)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $^)_self $(INC) -c $^

%.so : %.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^

irc.o : lirc/irc.c
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC $(INC) -c $^

lirc :
	@if [ ! -d lirc ]; then\
		git clone https://github.com/InterLinked1/lirc.git lirc;\
	fi

door_irc.so : lirc door_irc.o irc.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o door_irc.so door_irc.o irc.o -lssl -lcrypto

.PHONY: lirc
.PHONY: all
