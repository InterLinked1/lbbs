
IMAP_SRC := $(wildcard *.c)
IMAP_OBJ = $(IMAP_SRC:.c=.o)
DEPENDS := $(patsubst %.c,%.d,$(IMAP_SRC))

# the include directory is in the parent's parent
INC = -I../..

all: $(MOD_SO)

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE_SUBFILE -MMD -MP $(INC) -c $<

all: $(IMAP_OBJ)

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(IMAP_SRC))

.PHONY: all
