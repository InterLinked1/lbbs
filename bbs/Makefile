
MAIN_SRC := $(wildcard *.c)
MAIN_OBJ = $(MAIN_SRC:.c=.o)
DEPENDS := $(patsubst %.c,%.d,$(MAIN_SRC))

# the include directory is in the parent
INC = -I..

LIBS	= -lrt -lm -ldl -lcrypt -rdynamic

# -lcrypto needed for SHA1_Init in hash.c
# XXX Would be nice to move hash.c out into a module (mod_hash)
# The only users of hash.h are mod_http and auth.c, one call each.
LIBS += -lcrypto

# -lbfd and friends
# On SUSE, the remaining libraries are needed to link successfully
# However, on other platforms they are generally not, and -liberty is likely to cause issues
# Furthermore, some of the other libraries are also needed, if present, but must not be specified if not
# On FreeBSD, there is leading whitespace, so also trim for good measure
LIBS += -lbfd
LIBERTY_CHECK = $(shell gcc -liberty 2>&1 | grep "cannot find" | wc -l | tr -d ' ' )
LZSTD_CHECK = $(shell gcc -lzstd 2>&1 | grep "cannot find" | wc -l | tr -d ' ' )
LSFRAME_CHECK = $(shell gcc -lsframe 2>&1 | grep "cannot find" | wc -l | tr -d ' ' )
ifneq ($(LIBERTY_CHECK),1)
LIBS += -liberty -lz -lopcodes
endif
ifneq ($(LZSTD_CHECK),1)
LIBS += -lzstd
endif
ifneq ($(LSFRAME_CHECK),1)
LIBS += -lsframe
endif

ifeq ($(ALPINE_LINUX),1)
LIBS += -lcap
else ifeq ($(UNAME_S),Linux)
LIBS += -lbsd -lcap
endif

ifeq ($(UNAME_S),FreeBSD)
LIBS += -lexecinfo -lintl
else ifeq ($(ALPINE_LINUX),1)
LIBS += -lexecinfo
endif

# musl doesn't support dlclose (it's just a noop), so we can only dlopen modules once
# See: https://wiki.musl-libc.org/functional-differences-from-glibc.html#Unloading_libraries
ifeq ($(ALPINE_LINUX),1)
CFLAGS += -DDLOPEN_ONLY_ONCE
endif

all: $(EXE)

$(EXE) : $(MAIN_OBJ)
	@echo "  [LD] $^ -> $@"
	$(CC) -pthread -Wl,--export-dynamic -o $(EXE) *.o $(LIBS)

-include $(DEPENDS)

# Empty target so that if the .d file doesn't already exist, the %.d dependency is implicitly satisfied.
$(DEPENDS):

%.o : %.c %.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -DBBS_IN_CORE -MMD -MP $(INC) -c $<

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: bbs
