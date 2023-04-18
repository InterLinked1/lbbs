
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

GMIME_FLAGS=$(shell pkg-config --cflags glib-2.0 gmime-3.0)
GMIME_LIBS=$(shell pkg-config --libs glib-2.0 gmime-3.0)
MYSQL_LIBS := $(shell mysql_config --libs)

all: $(MOD_SO)
	@echo "== Compiling modules"

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) -c $<
	touch $@

mod_mimeparse.o : mod_mimeparse.c mod_mimeparse.d
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self $(GMIME_FLAGS) -MMD -MP $(INC) -c $<

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

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: concord
.PHONY: all
