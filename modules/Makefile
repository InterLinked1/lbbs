
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

NCURSES_FLAGS=$(shell pkg-config --cflags ncurses)
GMIME_FLAGS := $(shell pkg-config --cflags glib-2.0 gmime-3.0)
# On Fedora, pkg-config returns  -I/usr/include/libassuan2, which may not even exist and isn't needed
GMIME_FLAGS := $(filter-out -I/usr/include/libassuan2%,$(GMIME_FLAGS))
GMIME_LIBS=$(shell pkg-config --libs glib-2.0 gmime-3.0)
MYSQL_LIBS := $(shell mysql_config --libs)

ETPANCFLAGS=-I/usr/local/include

all: $(MOD_SO)

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) -c $<
	touch $@

mod_curl.so : mod_curl.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lcurl

mod_history.so : mod_history.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lreadline

mod_mimeparse.o : mod_mimeparse.c mod_mimeparse.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self $(GMIME_FLAGS) -Wno-inline -MMD -MP $(INC) -c $<

mod_ncurses.o : mod_ncurses.c mod_ncurses.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self $(NCURSES_FLAGS) -MMD -MP $(INC) -c $<

mod_webmail.o : mod_webmail.c mod_webmail.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -funsigned-char -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) $(ETPANCFLAGS) -c $<

%.so : %.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^

mod_asterisk_ami.so : mod_asterisk_ami.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lcami

mod_asterisk_queues.so : mod_asterisk_queues.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lcami

mod_discord.so : mod_discord.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -ldiscord

mod_http.so : mod_http.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lmagic

mod_irc_client.so : mod_irc_client.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lirc

mod_lmdb.so : mod_lmdb.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -llmdb

mod_mimeparse.so : mod_mimeparse.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ $(GMIME_LIBS)

mod_mysql.so : mod_mysql.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ $(MYSQL_LIBS)

mod_ncurses.so : mod_ncurses.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lmenu -lncurses

mod_oauth.so : mod_oauth.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -ljansson

mod_operator.so : mod_operator.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -ljansson

mod_sieve.so : mod_sieve.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lsieve

mod_slack.so : mod_slack.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lslackrtm

mod_smtp_delivery_external.so : mod_smtp_delivery_external.o
	@echo "  [LD] $^ -> $@"
ifeq ($(UNAME_S),FreeBSD)
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^
else
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lresolv
endif

mod_smtp_filter_arc.so : mod_smtp_filter_arc.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -L/usr/local/lib -Wl,-rpath -Wl,/usr/local/lib -lopenarc

mod_smtp_filter_dkim.so : mod_smtp_filter_dkim.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lopendkim

mod_smtp_filter_dmarc.so : mod_smtp_filter_dmarc.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lopendmarc

mod_smtp_filter_spf.so : mod_smtp_filter_spf.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lspf2

mod_systemd.so : mod_systemd.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lsystemd

mod_uuid.so : mod_uuid.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -luuid

mod_webmail.so : mod_webmail.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -L/usr/local/lib -Wl,-rpath=/usr/local/lib/ -ljansson -lssl -lcrypto -lz -letpan

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: all
