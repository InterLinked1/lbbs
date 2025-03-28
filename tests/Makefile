
MOD_SRC := $(wildcard test_*.c)
MOD_SO := $(MOD_SRC:.c=.so)
ALL_SRC := $(wildcard *.c)
MAIN_SRC := $(filter-out $(MOD_SRC),$(ALL_SRC))
MAIN_OBJ = $(MAIN_SRC:.c=.o)

TEST_EXE := test

INCLUDE_FILES := $(wildcard ../include/*.h)

# the include directory is in the parent
INC = -I..

TEST_LDFLAGS = -shared -fPIC

# Older versions of valgrind do not have the --show-error-list option
VALGRIND_VERSION_MM := $(shell valgrind --version 2> /dev/null | cut -d'-' -f2 | cut -d'.' -f1-2)
ifdef VALGRIND_VERSION_MM
ifeq ($(shell expr $(VALGRIND_VERSION_MM) \>= 3.15), 1)
EXTRA_FLAGS := -DHAVE_VALGRIND_SHOW_ERROR_LIST
endif
endif

all: $(TEST_EXE) $(MOD_SO)

# This is for all files in the binary, except readline.c
# A more specific rule matches all of the module files.
%.o : %.c
	@echo "  [LD] $^ -> $@"
	$(CC) $(CFLAGS) -Wno-unused-result -DTEST_IN_CORE -DTEST_DIR=$(CURDIR) $(EXTRA_FLAGS) $(INC) -c $^

readline.o : ../bbs/readline.c
	cp ../bbs/readline.c .
	$(CC) $(CFLAGS) -fPIC -DTEST_MODULE=\"$(basename $^)\" -DTEST_MODULE_SELF_SYM=__internal_$(basename $^)_self $(INC) -c $^

$(TEST_EXE) : $(MAIN_OBJ) readline.o
	$(CC) $(CFLAGS) -Wl,--export-dynamic -o $(TEST_EXE) $^ -ldl -lpthread -lssl -lcrypto -lz

test_%.o : test_%.c
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -Wno-unused-result -fPIC -DTEST_MODULE=\"$(basename $^)\" -DTEST_MODULE_SELF_SYM=__internal_$(basename $^)_self $(INC) -c $^

test_%.so : test_%.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(TEST_LDFLAGS) -o $(basename $^).so $^

test_sftp.so : test_sftp.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(TEST_LDFLAGS) -o $(basename $^).so $^ -lssh

test_ssh.so : test_ssh.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(TEST_LDFLAGS) -o $(basename $^).so $^ -lssh

test_webmail.so : test_webmail.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(TEST_LDFLAGS) -o $(basename $^).so $^ -lwss

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
# For tests, mainly needed to ensure the .so target isn't rebuilt when a dummy target created by modman is encountered.
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: all
