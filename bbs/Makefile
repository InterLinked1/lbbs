
MAIN_SRC := $(wildcard *.c)
MAIN_OBJ = $(MAIN_SRC:.c=.o)

INCLUDE_FILES := $(wildcard ../include/*.h)

# the include directory is in the parent
INC = -I..

all: $(MAIN_OBJ)
	@echo "== Linking $@"
	$(CC) $(CFLAGS) -Wl,--export-dynamic -o $(EXE) *.o $(LIBS)

%.o : %.c
	@echo "== Compiling bbs/$@"
	$(CC) $(CFLAGS) -DBBS_IN_CORE $(INC) -c $^

.PHONY: bbs
