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

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wparentheses -Wconversion -Wdangling-else -Waggregate-return -Wchar-subscripts -Wdouble-promotion -Wmissing-include-dirs -Wuninitialized -Wunknown-pragmas -Wstrict-overflow -Wmissing-format-attribute -Wnull-dereference -Warray-bounds=1 -Wduplicated-branches -Wduplicated-cond -Wtrampolines -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wundef -Wunused-macros -Wcast-qual -Wcast-align -Wwrite-strings -Wunused-result -Wjump-misses-init -Wlogical-op -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wpacked -Wnested-externs -Winline -Wdisabled-optimization -Wstack-protector -std=gnu99 -pthread -O3 -g -fno-omit-frame-pointer -fstrict-aliasing -fdelete-null-pointer-checks -fwrapv -D_FORTIFY_SOURCE=2

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

export UNAME_S

LIBS	= -lrt -lm -ldl

# -lcrypto needed for SHA1_Init in hash.c
LIBS += -lcrypt -lcrypto -lcurl -lreadline -luuid -rdynamic

# -lbfd and friends
# On SUSE, the remaining libraries are needed to link successfully
# However, on other platforms they are generally not, and -liberty is likely to cause issues
# Furthermore, some of the other libraries are also needed, if present, or possibly even missing
LIBS += -lbfd
LIBERTY_CHECK = $(shell gcc -liberty 2>&1 | grep "cannot find" | wc -l )
LSFRAME_CHECK = $(shell gcc -lsframe 2>&1 | grep "cannot find" | wc -l )
ifneq ($(LIBERTY_CHECK),1)
LIBS += -liberty -lz -lopcodes
endif
ifneq ($(LSFRAME_CHECK),1)
LIBS += -lsframe
endif

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
LIBS += -lbsd -lcap
endif

ifeq ($(UNAME_S),FreeBSD)
LIBS += -lexecinfo -lintl
endif

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

export EXE
export LIBS

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

uninstall :
	$(RM) /var/lib/lbbs/external/*
	$(RM) /usr/local/sbin/rsysop
	$(RM) /usr/lib/lbbs/modules/*.so
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
	cp -n scripts/* /var/lib/lbbs/scripts
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
