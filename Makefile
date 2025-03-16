#
# LBBS -- The Lightweight Bulletin Board System
#
# Top level Makefile
#
# Copyright (C) 2023, Naveen Albert
#
# Naveen Albert <bbs@phreaknet.org>
#

BBSTOPDIR:=$(subst $(space),\$(space),$(CURDIR))

export BBSTOPDIR		# Top level dir, used in subdirs' Makefiles

GCCVERSION = $(shell gcc --version | grep ^gcc | sed 's/^.* //g')
GCCVERSIONGTEQ8 := $(shell expr `gcc -dumpversion | cut -f1 -d.` \>= 8)
ALPINE_LINUX := $(shell ls /etc/alpine-release 2>/dev/null | wc -l)

CC		= gcc

CFLAGS += -Wall -Werror -Wunused -Wextra -Wparentheses -Wconversion -Wdangling-else -Waggregate-return -Wchar-subscripts -Wdouble-promotion -Wmissing-include-dirs -Wuninitialized -Wunknown-pragmas -Wstrict-overflow -Wmissing-format-attribute -Wnull-dereference -Warray-bounds=1 -Wduplicated-branches -Wduplicated-cond -Wtrampolines -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wundef -Wunused-macros -Wcast-qual -Wcast-align -Wwrite-strings -Wunused-result -Wjump-misses-init -Wlogical-op -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wpacked -Wnested-externs -Winline -Wdisabled-optimization -Wstack-protector -std=gnu99 -pthread -g -fno-omit-frame-pointer -fstrict-aliasing -fdelete-null-pointer-checks -fwrapv

ifeq "$(NO_OPTIMIZE)" "1"
CFLAGS += -O0
else
CFLAGS += -O3
endif

CORE_LDFLAGS = -pthread -Wl,--export-dynamic
MOD_LDFLAGS = -shared -fPIC

ifeq "$(ADDRESS_SANITIZER)" "1"
CFLAGS += -fsanitize=address
CORE_LDFLAGS += -fsanitize=address
MOD_LDFLAGS += -fsanitize=address
else
CFLAGS += -D_FORTIFY_SOURCE=2
endif

# -z lazy is needed for Alpine Linux: https://www.openwall.com/lists/musl/2019/12/11/16
ifeq ($(ALPINE_LINUX),1)
MOD_LDFLAGS += -Wl,-z lazy
endif

# -Wstringop-truncation only in gcc 8.0 and later
ifeq "$(GCCVERSIONGTEQ4)" "1"
	CFLAGS += -Wstringop-truncation
endif

EXE		= lbbs
PREFIX	= /usr/local
BINDIR	= $(PREFIX)/bin
RM		= rm -f
LN		= ln
INSTALL = install
UNAME_S := $(shell uname -s)

# Uncomment this to see all build commands instead of 'quiet' output
#NOISY_BUILD=yes

MOD_SUBDIR:=doors io modules nets
SUBDIRS:=$(MOD_SUBDIR)
SUBDIRS_INSTALL:=$(SUBDIRS:%=%-install)
SUBDIRS_CLEAN:=$(SUBDIRS:%=%-clean)

ifneq ($(PRINT_DIR)$(NOISY_BUILD),)
SUBMAKE:=$(MAKE)
else
SUBMAKE:=$(MAKE) --quiet --no-print-directory
endif

MOD_SUBDIR_CFLAGS="-I$(BBSTOPDIR)/include"

# MODULE_PREFIX:=mod
MAIN_SOURCES := $(wildcard *.c) $(cami/wildcard *.c)
INCLUDE_FILES := $(wildcard include/*.h)
MAIN_OBJ = $(MAIN_SOURCES:.c=.o)

SILENT_BUILD_PREFIX := @

# ALL_C_MODS+=$(foreach p,$(MOD_SUBDIR)/$(MODULE_PREFIX),$(patsubst %.c,%.so,$(wildcard $(p)_*.c)))

export CC
export CFLAGS
export CORE_LDFLAGS
export MOD_LDFLAGS
export EXE

export ALPINE_LINUX

export UNAME_S
export SUBMAKE

# Run sub targets in parallel, but don't run top-level targets in parallel
.NOTPARALLEL:

# This is the first target, so it's the default for just "make":
all : bbs $(MOD_SUBDIR) external
	@echo " +--------- LBBS has been compiled ---------+"
	@echo " You may now install it by running make install"

bbs : $(MAIN_OBJ)
	@+$(SUBMAKE) --no-builtin-rules -C $@ all

$(MOD_SUBDIR):
	@+$(SUBMAKE) --no-builtin-rules -C $@ all

external tests :
	@+$(SUBMAKE) --no-builtin-rules -C $@ all

# Make only modcheck, but not any of the other external programs
modcheckrule :
	@+$(SUBMAKE) --no-builtin-rules -C external modman

modcheck : modcheckrule
	@external/modman -t

modconfig : modcheckrule
	@external/modman -d

clean :
	$(RM) bbs/$(EXE) bbs/*.d bbs/*.i bbs/*.o
	$(RM) include/*.gch
	$(SUBMAKE) --no-builtin-rules -C external clean
	@for i in $(MOD_SUBDIR) tests; do \
		$(RM) $${i}/*.d $${i}/*.i $${i}/*.o $${i}/*.so; \
	done
	$(RM) tests/test
	$(RM) -r doors/lirc
	$(RM) doxygen.log
	$(RM) -r doc/html
	$(RM) -r doc/latex

moduninstall:
	$(RM) /usr/lib/lbbs/modules/*.so

uninstall : moduninstall
	$(RM) /var/lib/lbbs/external/*
	$(RM) /usr/local/sbin/rsysop
	$(RM) /usr/sbin/$(EXE)

bininstall: bbs
	$(INSTALL) -m 755 bbs/$(EXE) "/usr/sbin/lbbs"

modinstall: $(MOD_SUBDIR)
	@if [ ! -d /usr/lib/lbbs ]; then\
		mkdir /usr/lib/lbbs;\
	fi
	@if [ ! -d /usr/lib/lbbs/modules ]; then\
		mkdir /usr/lib/lbbs/modules;\
	fi
	@echo "Installing modules to /usr/lib/lbbs/modules"
	@for i in $(MOD_SUBDIR); do \
		echo " -> Installing modules in $${i}"; \
		$(INSTALL) -m 755 $${i}/*.so /usr/lib/lbbs/modules; \
		find /usr/lib/lbbs/modules -size 0 -delete; \
	done

extinstall:
	@if [ ! -d /var/lib ]; then\
		mkdir /var/lib;\
	fi
	@if [ ! -d /var/lib/lbbs ]; then\
		mkdir /var/lib/lbbs;\
	fi
	@if [ ! -d /var/lib/lbbs/external ]; then\
		mkdir /var/lib/lbbs/external;\
	fi
	@+$(SUBMAKE) --no-builtin-rules -C external install
	@find /var/lib/lbbs/external -size 0 -delete; \
	ln -s -f /var/lib/lbbs/external/rsysop /usr/local/sbin/rsysop

scripts :
	@if [ ! -d /var/lib/lbbs ]; then\
		mkdir /var/lib/lbbs;\
	fi
	@if [ ! -d /var/lib/lbbs/scripts ]; then\
		mkdir /var/lib/lbbs/scripts;\
	fi
	cp scripts/*.sh /var/lib/lbbs/scripts
	cp scripts/*.sql /var/lib/lbbs/scripts
# On FreeBSD, cp -n returns 1 if it already exists, ignore that
	cp -n scripts/*.php /var/lib/lbbs/scripts || :
	chmod +x /var/lib/lbbs/scripts/*

templates :
	@if [ ! -d /var/lib/lbbs ]; then\
		mkdir /var/lib/lbbs;\
	fi
	@if [ ! -d /var/lib/lbbs/templates ]; then\
		mkdir /var/lib/lbbs/templates;\
	fi
	@if [ ! -d /var/lib/lbbs/templates/.config ]; then\
		mkdir /var/lib/lbbs/templates/.config;\
	fi
	cp -r -n configs/templates/. /var/lib/lbbs/templates/.config

install : all bininstall modinstall extinstall scripts
	@echo " +--- LBBS and associated modules have been installed ---+"

samples : templates
	@if [ ! -d /etc/lbbs ]; then\
		mkdir /etc/lbbs;\
	fi
	cp -n configs/*.conf /etc/lbbs

# Don't allow the service to be installed if the module couldn't be built
service : modules/mod_systemd.so
	$(INSTALL) -m 644 configs/lbbs.service "/etc/systemd/system/lbbs.service"
	systemctl enable lbbs.service
	# Even if the BBS is already running, this will return 0
	systemctl start lbbs

doxygen :
# apt-get install -y doxygen graphviz
	doxygen Doxyfile.in

valgrindfg :
	@scripts/valgrind.sh "valgrindfg"

valgrind :
	@scripts/valgrind.sh "valgrind"

valgrindsupp :
	@scripts/valgrind.sh "valgrindsupp"

helgrind :
	@scripts/valgrind.sh "helgrind"

.PHONY: all
.PHONY: bbs
.PHONY: $(MOD_SUBDIR)
.PHONY: external
.PHONY: modcheckrule
.PHONY: modcheck
.PHONE: modconfig
.PHONY: tests
.PHONY: scripts
.PHONY: clean
.PHONY: install
.PHONY: samples
.PHONY: doxygen
.PHONY: valgrindfg
.PHONY: valgrind
.PHONY: valgrindsupp
.PHONY: helgrind
