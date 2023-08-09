
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

GMIME_FLAGS=$(shell pkg-config --cflags glib-2.0 gmime-3.0)
GMIME_LIBS=$(shell pkg-config --libs glib-2.0 gmime-3.0)
MYSQL_LIBS := $(shell mysql_config --libs)

ETPANCFLAGS=-I/usr/local/include
ETPANLDDFLAGS=-lssl -lcrypto -ldb-5.3 -lz -L/usr/local/lib -Wl,-rpath=/usr/local/lib/ -letpan

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

mod_http.so : mod_http.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lmagic

mod_lmdb.so : mod_lmdb.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -llmdb

mod_mimeparse.so : mod_mimeparse.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ $(GMIME_LIBS)

mod_mysql.so : mod_mysql.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ $(MYSQL_LIBS)

mod_oauth.so : mod_oauth.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -ljansson

mod_sieve.so : mod_sieve.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lsieve

mod_slack.so : mod_slack.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lslackrtm

mod_smtp_delivery_external.so : mod_smtp_delivery_external.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lresolv

mod_smtp_filter_arc.so : mod_smtp_filter_arc.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -L/usr/local/lib -Wl,-rpath -Wl,/usr/local/lib -lopenarc

mod_smtp_filter_dkim.so : mod_smtp_filter_dkim.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lopendkim

mod_smtp_filter_dmarc.so : mod_smtp_filter_dmarc.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lopendmarc

mod_smtp_filter_spf.so : mod_smtp_filter_spf.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -lspf2

mod_webmail.o : mod_webmail.c mod_webmail.d
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -funsigned-char -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) $(ETPANCFLAGS) -c $<

mod_webmail.so : mod_webmail.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^ -ljansson $(ETPANLDDFLAGS)

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: all
