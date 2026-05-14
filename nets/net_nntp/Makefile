
NNTP_SRC := $(wildcard *.c)
NNTP_OBJ = $(NNTP_SRC:.c=.o)
DEPENDS := $(patsubst %.c,%.d,$(NNTP_SRC))

# the include directory is in the parent's parent
INC = -I../..

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE_SUBFILE -MMD -MP $(INC) -c $<

all: $(NNTP_OBJ)

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(NNTP_SRC))

.PHONY: all
