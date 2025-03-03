
MOD_SRC := $(wildcard *.c)
MOD_SO := $(MOD_SRC:.c=.so)
DEPENDS := $(patsubst %.c,%.d,$(MOD_SRC))

# the include directory is in the parent
INC = -I..

all: $(MOD_SO)

-include $(DEPENDS)

$(DEPENDS):

%.o : %.c %.d
	@echo "  [CC] $< -> $@"
	$(CC) $(CFLAGS) -fPIC -DBBS_MODULE=\"$(basename $<)\" -DBBS_MODULE_SELF_SYM=__internal_$(basename $<)_self -MMD -MP $(INC) -c $<

%.so : %.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^

io_compress.so : io_compress.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lz

io_tls.so : io_tls.o
	@echo "  [LD] $^ -> $@"
	$(CC) $(MOD_LDFLAGS) -o $(basename $^).so $^ -lssl -lcrypto

# Don't automatically remove intermediate .o files, to prevent unnecessary recompilations
.SECONDARY: $(patsubst %.c,%.o,$(MOD_SRC))

.PHONY: all
