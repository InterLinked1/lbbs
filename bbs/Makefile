
MAIN_SRC := $(wildcard *.c)
MAIN_OBJ = $(MAIN_SRC:.c=.o)
DEPENDS := $(patsubst %.c,%.d,$(MAIN_SRC))

# the include directory is in the parent
INC = -I..

all: $(EXE)

$(EXE) : $(MAIN_OBJ)
	@echo "  [LD] $^ -> $@"
	$(CC) $(CFLAGS) -Wl,--export-dynamic -o $(EXE) *.o $(LIBS)

-include $(DEPENDS)

# Empty target so that if the .d file doesn't already exist, the %.d dependency is implicitly satisfied.
$(DEPENDS):

%.o : %.c %.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -DBBS_IN_CORE -MMD -MP $(INC) -c $<

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: bbs
