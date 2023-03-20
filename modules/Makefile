
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)

INCLUDE_FILES := $(wildcard ../include/*.h)

# the include directory is in the parent
INC = -I..

GMIME_FLAGS=$(shell pkg-config --cflags glib-2.0 gmime-3.0)
GMIME_LIBS=$(shell pkg-config --libs glib-2.0 gmime-3.0)
MYSQL_LIBS := $(shell mysql_config --libs)

all: $(MOD_SO)
	@echo "== Compiling modules"

%.o : %.c
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $^)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $^)_self $(INC) -c $^

mod_mimeparse.o : mod_mimeparse.c
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $^)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $^)_self $(GMIME_FLAGS) $(INC) -c $^

%.so : %.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^

mod_discord.so : mod_discord.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -ldiscord

mod_mimeparse.so : mod_mimeparse.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ $(GMIME_LIBS)

mod_mysql.so : mod_mysql.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ $(MYSQL_LIBS)

.PHONY: concord
.PHONY: all
