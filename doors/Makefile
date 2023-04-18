
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

all: $(MOD_SO)
	@echo "== Compiling doors"

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) -c $<

%.so : %.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^

irc.o : lirc/irc.c
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC $(INC) -c $^

# Target executed only if lirc directory doesn't exist (since it's not PHONY)
lirc :
	@if [ ! -d lirc ]; then\
		git clone https://github.com/InterLinked1/lirc.git lirc;\
	fi

door_irc.so : lirc door_irc.o irc.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o door_irc.so door_irc.o irc.o -lssl -lcrypto

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: all
