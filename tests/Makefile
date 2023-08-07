
MOD_SRC := $(wildcard test_*.c)
MOD_SO := $(MOD_SRC:.c=.so)

TEST_EXE := test

INCLUDE_FILES := $(wildcard ../include/*.h)

# the include directory is in the parent
INC = -I..

all: $(TEST_EXE) $(MOD_SO)

%.o : %.c
	@echo "== Compiling $@"
	$(CC) $(CFLAGS) -Wno-unused-result -fPIC -DTEST_MODULE=\"$(basename $^)\" -DTEST_MODULE_SELF_SYM=__internal_$(basename $^)_self $(INC) -c $^

readline.o : ../bbs/readline.c
	cp ../bbs/readline.c .
	$(CC) $(CFLAGS) -fPIC -DTEST_MODULE=\"$(basename $^)\" -DTEST_MODULE_SELF_SYM=__internal_$(basename $^)_self $(INC) -c $^

test.o : test.c
	@echo "== Linking $@"
	$(CC) $(CFLAGS) -DTEST_IN_CORE -DTEST_DIR=$(CURDIR) $(INC) -c $^

$(TEST_EXE) : test.o readline.o
	$(CC) $(CFLAGS) -Wl,--export-dynamic -o $(TEST_EXE) *.o -ldl -lpthread

%.so : %.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(basename $^).so $^

.PHONY: all
